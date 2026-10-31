// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_runtime.h"

#include <elf.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <new>
#include <mutex>
#include <utility>
#include <unordered_map>
#include <unordered_map>

#include "dynarmic/interface/A64/a64.h"
#include "dynarmic/interface/A64/config.h"
#include "translation/a64_guest_host_calls.h"
#include "translation/a64_guest_jni.h"
#include "translation/a64_guest_memory.h"
#include "translation/a64_guest_tls.h"
#include "translation/a64_linux_syscalls.h"

namespace mocktail::translation {
namespace {

using DynarmicAddress = Dynarmic::A64::VAddr;
constexpr std::uint32_t kA64BreakpointInstruction = 0xD4200000U;
constexpr std::uint64_t kDlopenHandleBase = 0x444C4F50454E0000ULL;
constexpr std::size_t kMaximumDlfcnStringBytes = 4096;
constexpr std::size_t kMaximumDlErrorBytes = 1024;
constexpr std::uint64_t kRtldLazy = 0x1;
constexpr std::uint64_t kRtldNow = 0x2;
constexpr std::uint64_t kRtldNoLoad = 0x4;
constexpr std::uint64_t kRtldGlobal = 0x100;
constexpr std::uint64_t kRtldNodelete = 0x1000;

bool AddOverflows(std::uint64_t left, std::uint64_t right) noexcept {
  return right > std::numeric_limits<std::uint64_t>::max() - left;
}

bool ReadLittleEndian(A64GuestMemory& memory, std::uint64_t address,
                      std::uint8_t* bytes, std::size_t length) {
  return memory.Read(address, bytes, length);
}

bool WriteLittleEndian(A64GuestMemory& memory, std::uint64_t address,
                       const std::uint8_t* bytes, std::size_t length) {
  return memory.Write(address, bytes, length);
}

bool ReadBoundedGuestCString(A64GuestMemory& memory, std::uint64_t address,
                             std::size_t maximum, std::string* value,
                             std::string* error) {
  auto fail = [&](const char* message) {
    if (error != nullptr) *error = message;
    return false;
  };
  if (address == 0 || value == nullptr || maximum == 0) {
    return fail("guest C-string address/output/limit is invalid");
  }
  value->clear();
  for (std::size_t offset = 0; offset < maximum; ++offset) {
    if (offset > std::numeric_limits<std::uint64_t>::max() - address) {
      return fail("guest C-string address overflows");
    }
    char ch = '\0';
    if (!memory.Read(address + offset, &ch, sizeof(ch))) {
      return fail("guest C-string points outside readable guest memory");
    }
    if (ch == '\0') {
      if (error != nullptr) error->clear();
      return true;
    }
    value->push_back(ch);
  }
  return fail("guest C-string exceeds the configured length limit");
}

bool ParseJniTypeDescriptor(const std::string& descriptor,
                            std::size_t* cursor,
                            bool allow_void) noexcept {
  if (cursor == nullptr || *cursor >= descriptor.size()) return false;
  bool is_array = false;
  while (*cursor < descriptor.size() && descriptor[*cursor] == '[') {
    is_array = true;
    ++*cursor;
  }
  if (*cursor >= descriptor.size()) return false;

  const char type = descriptor[*cursor];
  if (type == 'L') {
    const auto class_start = ++*cursor;
    while (*cursor < descriptor.size() && descriptor[*cursor] != ';') {
      if (descriptor[*cursor] == '[' || descriptor[*cursor] == '.') return false;
      ++*cursor;
    }
    if (*cursor == class_start || *cursor >= descriptor.size()) return false;
    ++*cursor;
    return true;
  }

  switch (type) {
    case 'Z': case 'B': case 'C': case 'S': case 'I':
    case 'J': case 'F': case 'D':
      ++*cursor;
      return true;
    case 'V':
      if (allow_void && !is_array) {
        ++*cursor;
        return true;
      }
      return false;
    default:
      return false;
  }
}

bool CountJniParameterTypes(const std::string& signature,
                            std::size_t* parameter_count,
                            std::string* error,
                            std::vector<char>* parameter_types = nullptr) {
  auto fail = [&](const char* message) {
    if (error != nullptr) *error = message;
    return false;
  };
  if (parameter_count == nullptr || signature.empty() ||
      signature.front() != '(') {
    return fail("invalid JNI method descriptor");
  }
  std::size_t cursor = 1;
  std::size_t count = 0;
  if (parameter_types != nullptr) parameter_types->clear();
  while (cursor < signature.size() && signature[cursor] != ')') {
    const auto type_start = cursor;
    if (!ParseJniTypeDescriptor(signature, &cursor, false)) {
      return fail("invalid JNI parameter type descriptor");
    }
    if (parameter_types != nullptr) {
      char type = signature[type_start];
      if (type == '[') type = 'L';  // Arrays are object references in JNI.
      parameter_types->push_back(type);
    }
    ++count;
    // JNI's two implicit parameters consume X0/X1, leaving six Java
    // arguments in X2-X7. Additional arguments are valid AAPCS64 parameters
    // and are passed on the guest stack by CallRegisteredJniNative.
    constexpr std::size_t kMaximumJniArguments = 262;
    if (count > kMaximumJniArguments) {
      return fail("JNI method descriptor exceeds the 262-argument limit");
    }
  }
  if (cursor >= signature.size() || signature[cursor] != ')') {
    return fail("JNI method descriptor is missing ')'");
  }
  ++cursor;
  if (!ParseJniTypeDescriptor(signature, &cursor, true) ||
      cursor != signature.size()) {
    return fail("invalid JNI return type descriptor");
  }
  *parameter_count = count;
  if (error != nullptr) error->clear();
  return true;
}

}  // namespace

class A64GuestRuntime::Impl final {
 public:
  explicit Impl(A64GuestRuntimeOptions options)
      : options_(std::move(options)),
        memory_(options_.max_guest_memory_bytes),
        tls_runtime_(memory_, options_.max_tls_bytes),
        host_calls_(memory_),
        syscalls_(memory_) {
    if (options_.enable_jni_bridge) {
      jni_bridge_ = std::make_unique<A64GuestJniBridge>(
          memory_, host_calls_, options_.jni_available_classes);
    }
  }

  ~Impl() {
    if (main_thread_tls_.valid()) {
      std::string ignored;
      static_cast<void>(tls_runtime_.DestroyThread(&main_thread_tls_, &ignored));
    }
  }

  class Callbacks final : public Dynarmic::A64::UserCallbacks {
   public:
    explicit Callbacks(Impl& owner) : owner_(owner) {}

    void Attach(Dynarmic::A64::Jit* jit) noexcept { jit_ = jit; }

    void BeginRun(std::uint64_t budget, bool require_return) {
      run_start_ticks_ = total_ticks_;
      instruction_budget_ = budget;
      return_required_ = require_return;
      saw_return_trap_ = false;
      guest_exit_ = false;
      exit_status_ = 0;
      failure_.clear();
      if (jit_ != nullptr) jit_->ClearHalt();
    }

    bool saw_return_trap() const noexcept { return saw_return_trap_; }
    bool guest_exit() const noexcept { return guest_exit_; }
    std::uint32_t exit_status() const noexcept { return exit_status_; }
    const std::string& failure() const noexcept { return failure_; }
    std::uint64_t ticks_used() const noexcept {
      return total_ticks_ - run_start_ticks_;
    }

    std::optional<std::uint32_t> MemoryReadCode(
        DynarmicAddress address) override {
      std::uint8_t bytes[4]{};
      if (!owner_.memory_.ReadExecutable(address, bytes, sizeof(bytes))) {
        Fail("guest instruction fetch outside executable memory");
        return std::nullopt;
      }
      return static_cast<std::uint32_t>(bytes[0]) |
             (static_cast<std::uint32_t>(bytes[1]) << 8U) |
             (static_cast<std::uint32_t>(bytes[2]) << 16U) |
             (static_cast<std::uint32_t>(bytes[3]) << 24U);
    }

    std::uint8_t MemoryRead8(DynarmicAddress address) override {
      std::uint8_t value = 0;
      if (!ReadLittleEndian(owner_.memory_, address, &value, sizeof(value))) {
        Fail("guest read outside readable mapped memory");
      }
      return value;
    }

    std::uint16_t MemoryRead16(DynarmicAddress address) override {
      std::uint8_t bytes[2]{};
      if (!ReadLittleEndian(owner_.memory_, address, bytes, sizeof(bytes))) {
        Fail("guest 16-bit read outside readable mapped memory");
        return 0;
      }
      return static_cast<std::uint16_t>(bytes[0]) |
             (static_cast<std::uint16_t>(bytes[1]) << 8U);
    }

    std::uint32_t MemoryRead32(DynarmicAddress address) override {
      std::uint8_t bytes[4]{};
      if (!ReadLittleEndian(owner_.memory_, address, bytes, sizeof(bytes))) {
        Fail("guest 32-bit read outside readable mapped memory");
        return 0;
      }
      return static_cast<std::uint32_t>(bytes[0]) |
             (static_cast<std::uint32_t>(bytes[1]) << 8U) |
             (static_cast<std::uint32_t>(bytes[2]) << 16U) |
             (static_cast<std::uint32_t>(bytes[3]) << 24U);
    }

    std::uint64_t MemoryRead64(DynarmicAddress address) override {
      std::uint8_t bytes[8]{};
      if (!ReadLittleEndian(owner_.memory_, address, bytes, sizeof(bytes))) {
        Fail("guest 64-bit read outside readable mapped memory");
        return 0;
      }
      std::uint64_t value = 0;
      for (std::size_t index = 0; index < sizeof(bytes); ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
      }
      return value;
    }

    Dynarmic::A64::Vector MemoryRead128(
        DynarmicAddress address) override {
      return {MemoryRead64(address), MemoryRead64(address + 8)};
    }

    void MemoryWrite8(DynarmicAddress address,
                      std::uint8_t value) override {
      if (!WriteLittleEndian(owner_.memory_, address, &value, sizeof(value))) {
        Fail("guest write outside writable mapped memory");
      }
    }

    void MemoryWrite16(DynarmicAddress address,
                       std::uint16_t value) override {
      const std::uint8_t bytes[] = {
          static_cast<std::uint8_t>(value),
          static_cast<std::uint8_t>(value >> 8U),
      };
      if (!WriteLittleEndian(owner_.memory_, address, bytes, sizeof(bytes))) {
        Fail("guest 16-bit write outside writable mapped memory");
      }
    }

    void MemoryWrite32(DynarmicAddress address,
                       std::uint32_t value) override {
      const std::uint8_t bytes[] = {
          static_cast<std::uint8_t>(value),
          static_cast<std::uint8_t>(value >> 8U),
          static_cast<std::uint8_t>(value >> 16U),
          static_cast<std::uint8_t>(value >> 24U),
      };
      if (!WriteLittleEndian(owner_.memory_, address, bytes, sizeof(bytes))) {
        Fail("guest 32-bit write outside writable mapped memory");
      }
    }

    void MemoryWrite64(DynarmicAddress address,
                       std::uint64_t value) override {
      std::uint8_t bytes[8]{};
      for (std::size_t index = 0; index < sizeof(bytes); ++index) {
        bytes[index] = static_cast<std::uint8_t>(value >> (index * 8U));
      }
      if (!WriteLittleEndian(owner_.memory_, address, bytes, sizeof(bytes))) {
        Fail("guest 64-bit write outside writable mapped memory");
      }
    }

    void MemoryWrite128(DynarmicAddress address,
                        Dynarmic::A64::Vector value) override {
      MemoryWrite64(address, value[0]);
      MemoryWrite64(address + 8, value[1]);
    }

    void InterpreterFallback(DynarmicAddress, std::size_t) override {
      Fail("Dynarmic requested interpreter fallback for guest code");
    }

    void CallSVC(std::uint32_t immediate) override {
      if (jit_ == nullptr) {
        Fail("Dynarmic invoked SVC before the guest JIT was attached");
        return;
      }

      if (owner_.host_calls_.HandlesSvc(immediate)) {
        A64GuestHostCalls::Arguments arguments{};
        for (std::size_t index = 0; index < arguments.size(); ++index) {
          arguments[index] = jit_->GetRegister(index);
        }
        const auto result =
            owner_.host_calls_.DispatchSvc(immediate, arguments);
        if (!result.success) {
          Fail("guest host call failed: " + result.error);
          return;
        }
        jit_->SetRegister(0, result.value);
        return;
      }

      if (immediate != 0) {
        // Linux AArch64 syscalls use SVC #0. Other immediates have no
        // implicit meaning in this runtime.
        jit_->SetRegister(
            0, static_cast<std::uint64_t>(
                   -static_cast<std::int64_t>(38)));  // -ENOSYS
        return;
      }

      const std::array<std::uint64_t, 6> arguments{
          jit_->GetRegister(0), jit_->GetRegister(1), jit_->GetRegister(2),
          jit_->GetRegister(3), jit_->GetRegister(4), jit_->GetRegister(5)};
      const auto result =
          owner_.syscalls_.Dispatch(jit_->GetRegister(8), arguments);
      jit_->SetRegister(0, result.value);
      if (result.should_exit) {
        guest_exit_ = true;
        exit_status_ = result.exit_status;
        Stop();
      }
    }

    void ExceptionRaised(DynarmicAddress address,
                         Dynarmic::A64::Exception exception) override {
      if (exception == Dynarmic::A64::Exception::Breakpoint) {
        if (address == owner_.options_.return_trap_address && return_required_) {
          saw_return_trap_ = true;
        } else {
          Fail("guest hit BRK instead of returning through X30");
        }
        Stop();
        return;
      }
      Fail("unexpected AArch64 guest CPU exception");
    }

    void AddTicks(std::uint64_t ticks) override {
      if (AddOverflows(total_ticks_, ticks)) {
        Fail("guest instruction counter overflowed");
        return;
      }
      total_ticks_ += ticks;
      if (ticks_used() >= instruction_budget_) {
        Fail("guest instruction budget exhausted");
      }
    }

    std::uint64_t GetTicksRemaining() override {
      const auto used = ticks_used();
      return used >= instruction_budget_ ? 0 : instruction_budget_ - used;
    }

    std::uint64_t GetCNTPCT() override { return total_ticks_; }

   private:
    void Fail(std::string message) {
      if (failure_.empty()) failure_ = std::move(message);
      Stop();
    }

    void Stop() {
      if (jit_ != nullptr) jit_->HaltExecution();
    }

    Impl& owner_;
    Dynarmic::A64::Jit* jit_ = nullptr;
    std::uint64_t total_ticks_ = 0;
    std::uint64_t run_start_ticks_ = 0;
    std::uint64_t instruction_budget_ = 1;
    bool return_required_ = true;
    bool saw_return_trap_ = false;
    bool guest_exit_ = false;
    std::uint32_t exit_status_ = 0;
    std::string failure_;
  };

  void SetDlError(std::string message) {
    if (message.size() > kMaximumDlErrorBytes) {
      message.resize(kMaximumDlErrorBytes);
    }
    dl_error_ = std::move(message);
    dl_error_pending_ = true;
  }

  A64HostCallResult GuestDlopen(const A64GuestHostCalls::Arguments& arguments) {
    if (!modules_ || modules_->modules.empty()) {
      SetDlError("dlopen called before the guest module set was loaded");
      return {true, 0, {}};
    }
    const auto flags = arguments[1];
    constexpr std::uint64_t kAllowedFlags =
        kRtldLazy | kRtldNow | kRtldNoLoad | kRtldGlobal | kRtldNodelete;
    const auto mode = flags & (kRtldLazy | kRtldNow);
    if ((flags & ~kAllowedFlags) != 0 ||
        (mode != kRtldLazy && mode != kRtldNow)) {
      SetDlError("dlopen received unsupported flags");
      return {true, 0, {}};
    }

    std::size_t module_index = modules_->root_index;
    if (arguments[0] != 0) {
      std::string filename;
      std::string diagnostic;
      if (!ReadBoundedGuestCString(memory_, arguments[0],
                                   kMaximumDlfcnStringBytes,
                                   &filename, &diagnostic) ||
          filename.empty()) {
        SetDlError(diagnostic.empty() ? "dlopen filename is empty"
                                      : diagnostic);
        return {true, 0, {}};
      }
      const auto* module = modules_->FindModule(filename);
      if (module == nullptr) {
        SetDlError("dlopen only supports preloaded guest modules; unavailable: " +
                   filename);
        return {true, 0, {}};
      }
      module_index = static_cast<std::size_t>(module - modules_->modules.data());
    }
    if (module_index >= modules_->modules.size()) {
      SetDlError("dlopen resolved an invalid guest module index");
      return {true, 0, {}};
    }

    // Opaque guest integer handles; loaded images remain mapped for this runtime.
    const auto handle = kDlopenHandleBase + module_index + 1U;
    dl_handles_[handle] = module_index;
    return {true, handle, {}};
  }

  std::optional<std::uint64_t> ResolveDlsymFromRoots(
      const std::vector<std::size_t>& roots, const std::string& name,
      std::string* error) const {
    auto fail = [&](const std::string& message)
        -> std::optional<std::uint64_t> {
      if (error != nullptr) *error = message;
      return std::nullopt;
    };
    if (!modules_) return fail("dlsym called before loading guest modules");

    std::vector<std::size_t> pending;
    std::vector<bool> visited(modules_->modules.size(), false);
    pending.reserve(modules_->modules.size());
    for (const auto root : roots) {
      if (root >= modules_->modules.size()) {
        return fail("dlsym received an invalid guest module handle");
      }
      pending.push_back(root);
    }

    for (std::size_t cursor = 0; cursor < pending.size(); ++cursor) {
      const auto index = pending[cursor];
      if (visited[index]) continue;
      visited[index] = true;
      const auto& module = modules_->modules[index];
      for (const auto& symbol : module.image.exported_symbols) {
        if (symbol.name != name ||
            (!symbol.version.empty() && symbol.version_hidden)) {
          continue;
        }
        if (symbol.type == STT_TLS) {
          return fail("dlsym of TLS symbols is unsupported by the static-TLS prototype");
        }
        if (symbol.type == STT_GNU_IFUNC) {
          return fail("dlsym of GNU IFUNC symbols is unsupported");
        }
        if (symbol.guest_address == 0) {
          return fail("dlsym found a symbol without a guest address");
        }
        if (error != nullptr) error->clear();
        return symbol.guest_address;
      }

      // Handle-based lookup traverses only this module's preloaded DT_NEEDED closure.
      for (const auto& dependency : module.image.dependencies) {
        const auto* dependency_module = modules_->FindModule(dependency);
        if (dependency_module == nullptr) continue;
        const auto dependency_index = static_cast<std::size_t>(
            dependency_module - modules_->modules.data());
        if (dependency_index < modules_->modules.size() &&
            !visited[dependency_index]) {
          pending.push_back(dependency_index);
        }
      }
    }
    return fail("dlsym could not find guest symbol: " + name);
  }

  A64HostCallResult GuestDlsym(const A64GuestHostCalls::Arguments& arguments) {
    if (!modules_) {
      SetDlError("dlsym called before the guest module set was loaded");
      return {true, 0, {}};
    }
    std::string name;
    std::string diagnostic;
    if (!ReadBoundedGuestCString(memory_, arguments[1],
                                 kMaximumDlfcnStringBytes,
                                 &name, &diagnostic) || name.empty()) {
      SetDlError(diagnostic.empty() ? "dlsym symbol name is empty" : diagnostic);
      return {true, 0, {}};
    }

    std::vector<std::size_t> roots;
    if (arguments[0] == 0) {
      // RTLD_DEFAULT searches the whole initial namespace.
      roots.reserve(modules_->modules.size());
      if (modules_->root_index < modules_->modules.size()) {
        roots.push_back(modules_->root_index);
      }
      for (std::size_t index = 0; index < modules_->modules.size(); ++index) {
        if (index != modules_->root_index) roots.push_back(index);
      }
    } else {
      const auto handle = dl_handles_.find(arguments[0]);
      if (handle == dl_handles_.end()) {
        SetDlError("dlsym received an invalid handle (RTLD_NEXT is unsupported)");
        return {true, 0, {}};
      }
      roots.push_back(handle->second);
    }

    const auto symbol = ResolveDlsymFromRoots(roots, name, &diagnostic);
    if (!symbol) {
      SetDlError(diagnostic.empty() ? "dlsym could not resolve guest symbol"
                                    : diagnostic);
      return {true, 0, {}};
    }
    return {true, *symbol, {}};
  }

  std::optional<std::uint64_t> GuestDlfcnString(
      const std::string& value, std::string* error) {
    auto fail = [&](const std::string& message)
        -> std::optional<std::uint64_t> {
      if (error != nullptr) *error = message;
      return std::nullopt;
    };
    if (value.size() + 1U > kMaximumDlfcnStringBytes) {
      return fail("libdl guest string exceeds the configured length limit");
    }
    const auto found = dl_guest_strings_.find(value);
    if (found != dl_guest_strings_.end()) {
      if (error != nullptr) error->clear();
      return found->second;
    }
    if (dl_guest_strings_.size() >= 1024U) {
      return fail("libdl guest string cache reached its bounded entry limit");
    }

    constexpr std::uint64_t kPageMask =
        A64GuestMemory::kPageSize - 1U;
    const auto requested_size =
        static_cast<std::uint64_t>(value.size() + 1U);
    // The string length is already bounded above, so this rounding cannot
    // overflow and never exceeds two guest pages.
    const auto mapped_size =
        (requested_size + kPageMask) & ~kPageMask;
    std::uint64_t address = 0;
    std::string diagnostic;
    if (!memory_.MapAnywhere(
            value.size() + 1U,
            A64GuestMemory::kRead | A64GuestMemory::kWrite,
            &address, &diagnostic)) {
      return fail("cannot allocate guest string for libdl result: " +
                  diagnostic);
    }
    if (!memory_.Write(address, value.c_str(), value.size() + 1U)) {
      static_cast<void>(memory_.Unmap(address, mapped_size));
      return fail("cannot initialize guest string for libdl result");
    }
    try {
      const auto inserted = dl_guest_strings_.emplace(value, address);
      if (!inserted.second) {
        static_cast<void>(memory_.Unmap(address, mapped_size));
        address = inserted.first->second;
      }
    } catch (const std::bad_alloc&) {
      static_cast<void>(memory_.Unmap(address, mapped_size));
      return fail("not enough host memory to retain libdl guest strings");
    }
    if (error != nullptr) error->clear();
    return address;
  }

  A64HostCallResult GuestDladdr(
      const A64GuestHostCalls::Arguments& arguments) {
    struct GuestDlInfo final {
      std::uint64_t filename = 0;
      std::uint64_t base = 0;
      std::uint64_t symbol_name = 0;
      std::uint64_t symbol_address = 0;
    };

    const auto requested_address = arguments[0];
    const auto output_address = arguments[1];
    if (!modules_ || requested_address == 0 || output_address == 0) {
      SetDlError("dladdr requires a loaded guest image, address, and output");
      return {true, 0, {}};
    }

    const A64GuestModule* owner = nullptr;
    const A64LoadSegment* containing_segment = nullptr;
    for (const auto& module : modules_->modules) {
      for (const auto& segment : module.image.segments) {
        if (requested_address >= segment.guest_address &&
            requested_address - segment.guest_address < segment.bytes.size()) {
          owner = &module;
          containing_segment = &segment;
          break;
        }
      }
      if (owner != nullptr) break;
    }
    if (owner == nullptr || containing_segment == nullptr) {
      // POSIX dladdr reports a normal lookup miss with 0 and does not fabricate
      // metadata for an arbitrary guest pointer.
      return {true, 0, {}};
    }

    const A64ExportedSymbol* nearest_symbol = nullptr;
    for (const auto& symbol : owner->image.exported_symbols) {
      if (symbol.guest_address == 0 ||
          symbol.guest_address > requested_address ||
          symbol.type == STT_TLS || symbol.type == STT_GNU_IFUNC ||
          symbol.version_hidden ||
          symbol.guest_address < containing_segment->guest_address ||
          symbol.guest_address - containing_segment->guest_address >=
              containing_segment->bytes.size()) {
        continue;
      }
      if (nearest_symbol == nullptr ||
          symbol.guest_address > nearest_symbol->guest_address) {
        nearest_symbol = &symbol;
      }
    }

    std::string diagnostic;
    const auto filename = GuestDlfcnString(owner->source_name, &diagnostic);
    if (!filename) {
      SetDlError("dladdr failed to allocate image name: " + diagnostic);
      return {true, 0, {}};
    }

    GuestDlInfo information{};
    information.filename = *filename;
    information.base = owner->image.base_address;
    if (nearest_symbol != nullptr) {
      const auto symbol_name =
          GuestDlfcnString(nearest_symbol->name, &diagnostic);
      if (!symbol_name) {
        SetDlError("dladdr failed to allocate symbol name: " + diagnostic);
        return {true, 0, {}};
      }
      information.symbol_name = *symbol_name;
      information.symbol_address = nearest_symbol->guest_address;
    }

    if (!memory_.Write(output_address, &information, sizeof(information))) {
      SetDlError("dladdr output does not point to writable guest memory");
      return {true, 0, {}};
    }
    return {true, 1, {}};
  }

  A64HostCallResult GuestDlclose(
      const A64GuestHostCalls::Arguments& arguments) {
    if (dl_handles_.find(arguments[0]) == dl_handles_.end()) {
      SetDlError("dlclose received an invalid guest module handle");
      return {true, static_cast<std::uint64_t>(-1LL), {}};
    }
    // The closure is preloaded into a fixed address space. dlclose is a safe
    // no-op instead of unmapping code that other guest modules may still call.
    return {true, 0, {}};
  }

  A64HostCallResult GuestDlerror() {
    if (!dl_error_pending_) return {true, 0, {}};
    if (dl_error_buffer_address_ == 0) {
      std::string diagnostic;
      if (!memory_.MapAnywhere(
              A64GuestMemory::kPageSize,
              A64GuestMemory::kRead | A64GuestMemory::kWrite,
              &dl_error_buffer_address_, &diagnostic)) {
        return {true, 0, {}};
      }
    }
    const auto length = std::min(dl_error_.size(), kMaximumDlErrorBytes);
    if (!memory_.Write(dl_error_buffer_address_, dl_error_.c_str(), length + 1U)) {
      return {true, 0, {}};
    }
    dl_error_pending_ = false;
    return {true, dl_error_buffer_address_, {}};
  }

  bool RegisterAndroidSystemProperties(std::string* error) {
    constexpr std::size_t kMaximumPropertyNameBytes = 128;
    constexpr std::size_t kPropertyValueMax = 92;  // Includes the NUL byte.
    auto fail = [&](const std::string& message) {
      if (error != nullptr) *error = message;
      return false;
    };

    for (const auto& item : options_.android_system_properties) {
      if (item.first.empty() ||
          item.first.size() >= kMaximumPropertyNameBytes ||
          item.second.size() >= kPropertyValueMax ||
          item.first.find('\0') != std::string::npos ||
          item.second.find('\0') != std::string::npos) {
        return fail("synthetic Android property name/value is invalid or too long");
      }
    }

    if (!host_calls_.Register(
        "__system_property_get", "libc.so", "",
        [this](const A64GuestHostCalls::Arguments& arguments)
            -> A64HostCallResult {
          std::string property_name;
          std::string diagnostic;
          if (!ReadBoundedGuestCString(
                  memory_, arguments[0], 128, &property_name, &diagnostic)) {
            static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
            return {true, 0, {}};
          }
          if (arguments[1] == 0) {
            static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
            return {true, 0, {}};
          }

          std::string value;
          const auto found = options_.android_system_properties.find(property_name);
          if (found != options_.android_system_properties.end()) {
            value = found->second;
          }
          if (value.size() >= kPropertyValueMax ||
              !memory_.Write(arguments[1], value.c_str(), value.size() + 1U)) {
            static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
            return {true, 0, {}};
          }
          return {true, static_cast<std::uint64_t>(value.size()), {}};
        },
        error)) {
      return false;
    }

    auto register_one = [this, error](
        const char* name, A64GuestHostCalls::Handler handler) {
      return host_calls_.Register(name, "libc.so", "", std::move(handler),
                                  error);
    };

    if (!register_one("__system_property_find", [this](
            const A64GuestHostCalls::Arguments& arguments)
            -> A64HostCallResult {
          std::string property_name;
          std::string diagnostic;
          if (!ReadBoundedGuestCString(
                  memory_, arguments[0], 128, &property_name, &diagnostic)) {
            static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
            return {true, 0, {}};
          }
          if (options_.android_system_properties.find(property_name) ==
              options_.android_system_properties.end()) {
            return {true, 0, {}};
          }

          std::lock_guard<std::mutex> lock(android_property_mutex_);
          const auto existing = android_property_handles_.find(property_name);
          if (existing != android_property_handles_.end()) {
            return {true, existing->second, {}};
          }
          if (next_android_property_handle_ >
              std::numeric_limits<std::uint64_t>::max() - 16U) {
            static_cast<void>(host_calls_.SetGuestErrno(ENOMEM));
            return {true, 0, {}};
          }
          const auto handle = next_android_property_handle_;
          try {
            android_property_handles_.emplace(property_name, handle);
            try {
              android_property_names_.emplace(handle, property_name);
            } catch (...) {
              android_property_handles_.erase(property_name);
              throw;
            }
          } catch (const std::bad_alloc&) {
            static_cast<void>(host_calls_.SetGuestErrno(ENOMEM));
            return {true, 0, {}};
          }
          next_android_property_handle_ += 16U;
          return {true, handle, {}};
        })) {
      return false;
    }

    if (!register_one("__system_property_read", [this](
            const A64GuestHostCalls::Arguments& arguments)
            -> A64HostCallResult {
          std::string property_name;
          {
            std::lock_guard<std::mutex> lock(android_property_mutex_);
            const auto found = android_property_names_.find(arguments[0]);
            if (found == android_property_names_.end()) {
              static_cast<void>(host_calls_.SetGuestErrno(EINVAL));
              return {true, static_cast<std::uint64_t>(-1LL), {}};
            }
            property_name = found->second;
          }
          if (arguments[1] == 0 || arguments[2] == 0) {
            static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
            return {true, static_cast<std::uint64_t>(-1LL), {}};
          }
          const auto found = options_.android_system_properties.find(property_name);
          if (found == options_.android_system_properties.end()) {
            static_cast<void>(host_calls_.SetGuestErrno(EINVAL));
            return {true, static_cast<std::uint64_t>(-1LL), {}};
          }
          const std::string& value = found->second;
          if (!memory_.Write(arguments[1], property_name.c_str(),
                             property_name.size() + 1U) ||
              !memory_.Write(arguments[2], value.c_str(), value.size() + 1U)) {
            static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
            return {true, static_cast<std::uint64_t>(-1LL), {}};
          }
          return {true, static_cast<std::uint64_t>(value.size()), {}};
        })) {
      return false;
    }

    if (!register_one("__system_property_serial", [this](
            const A64GuestHostCalls::Arguments& arguments)
            -> A64HostCallResult {
          std::lock_guard<std::mutex> lock(android_property_mutex_);
          if (android_property_names_.find(arguments[0]) ==
              android_property_names_.end()) {
            static_cast<void>(host_calls_.SetGuestErrno(EINVAL));
            return {true, 0, {}};
          }
          // The configured profile is immutable for one runtime instance.
          return {true, 1, {}};
        })) {
      return false;
    }

    if (!register_one("__system_property_area_serial", [](
            const A64GuestHostCalls::Arguments&) -> A64HostCallResult {
          // The profile cannot change while a guest runtime is loaded.
          return {true, 1, {}};
        })) {
      return false;
    }

    return true;
  }

  bool RegisterGuestAuxiliaryVector(std::string* error) {
    return host_calls_.Register(
        "getauxval", "libc.so", "",
        [this](const A64GuestHostCalls::Arguments& arguments)
            -> A64HostCallResult {
          // A conservative baseline: AArch64 FP and ASIMD are available to
          // translated code. Do not advertise optional ISA extensions unless
          // the guest translator explicitly enables them.
          switch (arguments[0]) {
            case 6:   // AT_PAGESZ
              return {true, A64GuestMemory::kPageSize, {}};
            case 11:  // AT_UID
            case 12:  // AT_EUID
            case 13:  // AT_GID
            case 14:  // AT_EGID
              return {true, 10000, {}};
            case 15: {  // AT_PLATFORM
              std::string diagnostic;
              const auto platform =
                  GuestDlfcnString("aarch64", &diagnostic);
              if (!platform) {
                static_cast<void>(host_calls_.SetGuestErrno(ENOMEM));
                return {true, 0, {}};
              }
              return {true, *platform, {}};
            }
            case 16:  // AT_HWCAP: HWCAP_FP | HWCAP_ASIMD
              return {true, 0x3, {}};
            case 17:  // AT_CLKTCK
              return {true, 100, {}};
            case 23:  // AT_SECURE
              return {true, 0, {}};
            case 25: {  // AT_RANDOM: 16 random bytes in guest memory.
              if (guest_auxv_random_address_ == 0) {
                std::string diagnostic;
                if (!memory_.MapAnywhere(
                        16U, A64GuestMemory::kRead | A64GuestMemory::kWrite,
                        &guest_auxv_random_address_, &diagnostic)) {
                  static_cast<void>(host_calls_.SetGuestErrno(ENOMEM));
                  return {true, 0, {}};
                }
                const std::array<std::uint64_t, 6> random_arguments{
                    guest_auxv_random_address_, 16U, 0, 0, 0, 0};
                const auto result = syscalls_.Dispatch(
                    A64LinuxSyscalls::kGetRandom, random_arguments);
                if (result.value != 16U) {
                  static_cast<void>(memory_.Unmap(
                      guest_auxv_random_address_,
                      A64GuestMemory::kPageSize));
                  guest_auxv_random_address_ = 0;
                  static_cast<void>(host_calls_.SetGuestErrno(EIO));
                  return {true, 0, {}};
                }
              }
              return {true, guest_auxv_random_address_, {}};
            }
            case 26:  // AT_HWCAP2: no optional extensions are advertised.
              return {true, 0, {}};
            case 31: {  // AT_EXECFN
              std::string diagnostic;
              const auto executable =
                  GuestDlfcnString("mocktail-android-guest", &diagnostic);
              if (!executable) {
                static_cast<void>(host_calls_.SetGuestErrno(ENOMEM));
                return {true, 0, {}};
              }
              return {true, *executable, {}};
            }
            default:
              static_cast<void>(host_calls_.SetGuestErrno(ENOENT));
              return {true, 0, {}};
          }
        },
        error);
  }

  bool RegisterAndroidPlatformApi(std::string* error) {
    return host_calls_.Register(
        "android_get_device_api_level", "libandroid.so", "",
        [this](const A64GuestHostCalls::Arguments&) -> A64HostCallResult {
          const auto found =
              options_.android_system_properties.find("ro.build.version.sdk");
          if (found == options_.android_system_properties.end() ||
              found->second.empty()) {
            static_cast<void>(host_calls_.SetGuestErrno(ENOENT));
            return {true, 0, {}};
          }
          // Parse the configured SDK without allowing signs, suffixes or
          // overflow to turn a malformed profile into a host-side integer.
          std::uint32_t api_level = 0;
          for (const char character : found->second) {
            if (character < '0' || character > '9') {
              static_cast<void>(host_calls_.SetGuestErrno(EINVAL));
              return {true, 0, {}};
            }
            const auto digit = static_cast<std::uint32_t>(character - '0');
            if (api_level >
                (static_cast<std::uint32_t>(
                     std::numeric_limits<std::int32_t>::max()) - digit) /
                    10U) {
              static_cast<void>(host_calls_.SetGuestErrno(EINVAL));
              return {true, 0, {}};
            }
            api_level = api_level * 10U + digit;
          }
          return {true, api_level, {}};
        },
        error);
  }




  bool RegisterAndroidNativeWindowApi(std::string* error) {
    auto register_one = [this, error](
        const char* name, A64GuestHostCalls::Handler handler) {
      return host_calls_.Register(name, "libandroid.so", "",
                                  std::move(handler), error);
    };
    if (!register_one("ANativeWindow_fromSurface",
        [](const A64GuestHostCalls::Arguments&) {
          // A probe has no Android Activity/Surface or host renderer window.
          // Return null rather than fabricating a window-shaped pointer.
          return A64HostCallResult{true, 0, {}};
        })) return false;
    if (!register_one("ANativeWindow_acquire",
        [](const A64GuestHostCalls::Arguments&) {
          return A64HostCallResult{true, 0, {}};
        })) return false;
    if (!register_one("ANativeWindow_release",
        [](const A64GuestHostCalls::Arguments&) {
          return A64HostCallResult{true, 0, {}};
        })) return false;
    const char* const unsupported_window_apis[] = {
        "ANativeWindow_setBuffersGeometry",
        "ANativeWindow_lock",
        "ANativeWindow_unlockAndPost",
    };
    for (const auto* name : unsupported_window_apis) {
      if (!register_one(name, [this](const A64GuestHostCalls::Arguments&) {
            static_cast<void>(host_calls_.SetGuestErrno(ENODEV));
            return A64HostCallResult{
                true, static_cast<std::uint64_t>(-1LL), {}};
          })) return false;
    }
    const char* query_apis[] = {
        "ANativeWindow_getWidth",
        "ANativeWindow_getHeight",
        "ANativeWindow_getFormat",
    };
    for (const auto* name : query_apis) {
      if (!register_one(name, [](const A64GuestHostCalls::Arguments&) {
            // Null is the only window handle supplied by this headless probe.
            return A64HostCallResult{true, 0, {}};
          })) return false;
    }
    if (error != nullptr) error->clear();
    return true;
  }


  bool RegisterAndroidBitmapApi(std::string* error) {
    auto register_one = [this, error](
        const char* name, A64GuestHostCalls::Handler handler) {
      return host_calls_.Register(name, "libjnigraphics.so", "",
                                  std::move(handler), error);
    };
    const char* bitmap_apis[] = {
        "AndroidBitmap_getInfo",
        "AndroidBitmap_lockPixels",
        "AndroidBitmap_unlockPixels",
    };
    for (const auto* name : bitmap_apis) {
      if (!register_one(name, [this](const A64GuestHostCalls::Arguments&) {
            // The guest JNI bridge has no ART Bitmap object or pixel backing.
            // Return ANDROID_BITMAP_RESULT_BAD_PARAMETER rather than exposing
            // host memory or claiming that a Java Bitmap was locked.
            static_cast<void>(host_calls_.SetGuestErrno(ENOTSUP));
            return A64HostCallResult{
                true, static_cast<std::uint64_t>(-1LL), {}};
          })) return false;
    }
    if (error != nullptr) error->clear();
    return true;
  }

  bool RegisterAndroidLooperApi(std::string* error) {
    constexpr std::uint64_t kLooperHandle = 0x414C4F4F50455231ULL;
    constexpr int kAllowNonCallbacks = 1;
    constexpr int kPollWake = -1;
    constexpr int kPollTimeout = -3;
    constexpr int kPollError = -4;
    auto register_one = [this, error](
        const char* name, A64GuestHostCalls::Handler handler) {
      return host_calls_.Register(name, "libandroid.so", "",
                                  std::move(handler), error);
    };

    if (!register_one("ALooper_prepare",
        [this](const A64GuestHostCalls::Arguments& args)
            -> A64HostCallResult {
          if (guest_looper_) return {true, kLooperHandle, {}};
          auto looper = std::make_unique<GuestLooper>();
          looper->allow_non_callbacks =
              (static_cast<int>(args[0]) & kAllowNonCallbacks) != 0;
          looper->epoll_fd = ::epoll_create1(EPOLL_CLOEXEC);
          if (looper->epoll_fd < 0) {
            static_cast<void>(host_calls_.SetGuestErrno(errno));
            return {true, 0, {}};
          }
          looper->wake_fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
          if (looper->wake_fd < 0) {
            static_cast<void>(host_calls_.SetGuestErrno(errno));
            return {true, 0, {}};
          }
          epoll_event wake_event{};
          wake_event.events = EPOLLIN;
          wake_event.data.u64 = 0;
          if (::epoll_ctl(looper->epoll_fd, EPOLL_CTL_ADD, looper->wake_fd,
                          &wake_event) != 0) {
            static_cast<void>(host_calls_.SetGuestErrno(errno));
            return {true, 0, {}};
          }
          guest_looper_ = std::move(looper);
          return {true, kLooperHandle, {}};
        })) return false;

    if (!register_one("ALooper_forThread",
        [this](const A64GuestHostCalls::Arguments&) {
          return A64HostCallResult{
              true, guest_looper_ ? kLooperHandle : 0, {}};
        })) return false;

    if (!register_one("ALooper_acquire",
        [this](const A64GuestHostCalls::Arguments& args) {
          if (args[0] == kLooperHandle && guest_looper_) {
            std::scoped_lock lock(guest_looper_->mutex);
            if (guest_looper_->references <
                std::numeric_limits<std::uint32_t>::max()) {
              ++guest_looper_->references;
            }
          }
          return A64HostCallResult{true, 0, {}};
        })) return false;

    if (!register_one("ALooper_release",
        [this](const A64GuestHostCalls::Arguments& args) {
          if (args[0] == kLooperHandle && guest_looper_) {
            bool destroy = false;
            {
              std::scoped_lock lock(guest_looper_->mutex);
              if (guest_looper_->references > 0) {
                destroy = --guest_looper_->references == 0;
              }
            }
            if (destroy) guest_looper_.reset();
          }
          return A64HostCallResult{true, 0, {}};
        })) return false;

    if (!register_one("ALooper_wake",
        [this](const A64GuestHostCalls::Arguments& args) {
          if (args[0] == kLooperHandle && guest_looper_) {
            const std::uint64_t one = 1;
            const auto result =
                ::write(guest_looper_->wake_fd, &one, sizeof(one));
            if (result < 0 && errno != EAGAIN) {
              static_cast<void>(host_calls_.SetGuestErrno(errno));
            }
          }
          return A64HostCallResult{true, 0, {}};
        })) return false;

    if (!register_one("ALooper_isPolling",
        [this](const A64GuestHostCalls::Arguments& args) {
          return A64HostCallResult{
              true, args[0] == kLooperHandle && guest_looper_ &&
                            guest_looper_->polling.load(
                                std::memory_order_acquire)
                        ? 1U : 0U,
              {}};
        })) return false;

    if (!register_one("ALooper_addFd",
        [this](const A64GuestHostCalls::Arguments& args)
            -> A64HostCallResult {
          if (args[0] != kLooperHandle || !guest_looper_ ||
              args[1] > static_cast<std::uint64_t>(
                           std::numeric_limits<int>::max()) ||
              args[3] > static_cast<std::uint64_t>(
                           std::numeric_limits<int>::max()) ||
              args[4] != 0 || !guest_looper_->allow_non_callbacks ||
              static_cast<std::int32_t>(args[2]) < 0) {
            static_cast<void>(host_calls_.SetGuestErrno(EINVAL));
            return {true, static_cast<std::uint64_t>(-1LL), {}};
          }
          const int fd = static_cast<int>(args[1]);
          const int ident = static_cast<int>(args[2]);
          const int requested_events = static_cast<int>(args[3]);
          std::uint32_t epoll_events = 0;
          if ((requested_events & 1) != 0) epoll_events |= EPOLLIN;
          if ((requested_events & 2) != 0) epoll_events |= EPOLLOUT;
          epoll_event event{};
          event.events = epoll_events;
          event.data.u64 = static_cast<std::uint64_t>(fd) + 1U;
          std::scoped_lock lock(guest_looper_->mutex);
          const bool exists =
              guest_looper_->registrations.find(fd) !=
              guest_looper_->registrations.end();
          if (::epoll_ctl(guest_looper_->epoll_fd,
                          exists ? EPOLL_CTL_MOD : EPOLL_CTL_ADD,
                          fd, &event) != 0) {
            static_cast<void>(host_calls_.SetGuestErrno(errno));
            return {true, static_cast<std::uint64_t>(-1LL), {}};
          }
          guest_looper_->registrations.insert_or_assign(
              fd, GuestLooper::Registration{
                      ident, requested_events, args[5]});
          return {true, 1, {}};
        })) return false;

    if (!register_one("ALooper_removeFd",
        [this](const A64GuestHostCalls::Arguments& args)
            -> A64HostCallResult {
          if (args[0] != kLooperHandle || !guest_looper_ ||
              args[1] > static_cast<std::uint64_t>(
                           std::numeric_limits<int>::max())) {
            static_cast<void>(host_calls_.SetGuestErrno(EINVAL));
            return {true, static_cast<std::uint64_t>(-1LL), {}};
          }
          const int fd = static_cast<int>(args[1]);
          std::scoped_lock lock(guest_looper_->mutex);
          const auto found = guest_looper_->registrations.find(fd);
          if (found == guest_looper_->registrations.end()) {
            return {true, 0, {}};
          }
          if (::epoll_ctl(guest_looper_->epoll_fd, EPOLL_CTL_DEL, fd,
                          nullptr) != 0 && errno != ENOENT && errno != EBADF) {
            static_cast<void>(host_calls_.SetGuestErrno(errno));
            return {true, static_cast<std::uint64_t>(-1LL), {}};
          }
          guest_looper_->registrations.erase(found);
          return {true, 1, {}};
        })) return false;

    auto poll_once = [this, kPollWake, kPollTimeout, kPollError](
        const A64GuestHostCalls::Arguments& args) -> A64HostCallResult {
      if (!guest_looper_) {
        return {true, static_cast<std::uint64_t>(
                          static_cast<std::int64_t>(kPollError)), {}};
      }
      const auto timeout = static_cast<std::int32_t>(args[0]);
      if (timeout < -1) {
        static_cast<void>(host_calls_.SetGuestErrno(EINVAL));
        return {true, static_cast<std::uint64_t>(
                          static_cast<std::int64_t>(kPollError)), {}};
      }
      auto clear_output = [this](std::uint64_t address, const void* value,
                                 std::size_t size) {
        return address == 0 || memory_.Write(address, value, size);
      };
      const std::int32_t zero = 0;
      const std::uint64_t null_data = 0;
      if (!clear_output(args[1], &zero, sizeof(zero)) ||
          !clear_output(args[2], &zero, sizeof(zero)) ||
          !clear_output(args[3], &null_data, sizeof(null_data))) {
        static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
        return {true, static_cast<std::uint64_t>(
                          static_cast<std::int64_t>(kPollError)), {}};
      }

      std::array<epoll_event, 32> events{};
      guest_looper_->polling.store(true, std::memory_order_release);
      const int ready = ::epoll_wait(guest_looper_->epoll_fd, events.data(),
                                     static_cast<int>(events.size()), timeout);
      const int wait_error = errno;
      guest_looper_->polling.store(false, std::memory_order_release);
      if (ready == 0) {
        return {true, static_cast<std::uint64_t>(
                          static_cast<std::int64_t>(kPollTimeout)), {}};
      }
      if (ready < 0) {
        static_cast<void>(host_calls_.SetGuestErrno(wait_error));
        return {true, static_cast<std::uint64_t>(
                          static_cast<std::int64_t>(kPollError)), {}};
      }
      for (int index = 0; index < ready; ++index) {
        if (events[index].data.u64 == 0) {
          std::uint64_t drained = 0;
          while (::read(guest_looper_->wake_fd, &drained,
                        sizeof(drained)) > 0) {}
          return {true, static_cast<std::uint64_t>(
                            static_cast<std::int64_t>(kPollWake)), {}};
        }
        const auto fd_value = events[index].data.u64 - 1U;
        if (fd_value > static_cast<std::uint64_t>(
                           std::numeric_limits<int>::max())) continue;
        const int fd = static_cast<int>(fd_value);
        GuestLooper::Registration registration{};
        {
          std::scoped_lock lock(guest_looper_->mutex);
          const auto found = guest_looper_->registrations.find(fd);
          if (found == guest_looper_->registrations.end()) continue;
          registration = found->second;
        }
        std::int32_t guest_fd = fd;
        std::int32_t guest_events = 0;
        if ((events[index].events & (EPOLLIN | EPOLLPRI)) != 0) guest_events |= 1;
        if ((events[index].events & EPOLLOUT) != 0) guest_events |= 2;
        if ((events[index].events & EPOLLERR) != 0) guest_events |= 4;
        if ((events[index].events & (EPOLLHUP | EPOLLRDHUP)) != 0) guest_events |= 8;
        if (!clear_output(args[1], &guest_fd, sizeof(guest_fd)) ||
            !clear_output(args[2], &guest_events, sizeof(guest_events)) ||
            !clear_output(args[3], &registration.data,
                          sizeof(registration.data))) {
          static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
          return {true, static_cast<std::uint64_t>(
                            static_cast<std::int64_t>(kPollError)), {}};
        }
        return {true, static_cast<std::uint64_t>(
                          static_cast<std::int64_t>(registration.ident)), {}};
      }
      return {true, static_cast<std::uint64_t>(
                        static_cast<std::int64_t>(kPollTimeout)), {}};
    };
    if (!register_one("ALooper_pollOnce", poll_once)) return false;
    if (!register_one("ALooper_pollAll", poll_once)) return false;

    if (error != nullptr) error->clear();
    return true;
  }

  bool RegisterAndroidAssetApi(std::string* error) {
    constexpr std::uint64_t kAssetManagerHandle = 0x41535345544D4752ULL;
    constexpr std::size_t kMaximumAssetBytes = 64U * 1024U * 1024U;
    constexpr std::size_t kMaximumOpenAssets = 4096U;
    auto register_one = [this, error](
        const char* name, A64GuestHostCalls::Handler handler) {
      return host_calls_.Register(name, "libandroid.so", "",
                                  std::move(handler), error);
    };

    if (!register_one("AAssetManager_fromJava",
        [](const A64GuestHostCalls::Arguments&) {
          // Java AssetManager is represented by a runtime-owned opaque token.
          // It is never dereferenced as a host pointer.
          return A64HostCallResult{true, kAssetManagerHandle, {}};
        })) return false;

    if (!register_one("AAssetManager_open",
        [this, kAssetManagerHandle](const A64GuestHostCalls::Arguments& args)
            -> A64HostCallResult {
          if (args[0] != kAssetManagerHandle ||
              options_.android_asset_root.empty()) {
            return {true, 0, {}};
          }
          std::string requested;
          std::string diagnostic;
          if (!ReadBoundedGuestCString(memory_, args[1], 4096,
                                       &requested, &diagnostic)) {
            static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
            return {true, 0, {}};
          }
          auto strip_prefix = [&requested](const char* prefix) {
            const std::string value(prefix);
            if (requested.compare(0, value.size(), value) == 0) {
              requested.erase(0, value.size());
              return true;
            }
            return false;
          };
          if (!strip_prefix("file:///android_asset/") &&
              !strip_prefix("rbxasset://")) {
            // Plain NDK asset paths are relative to the assets directory.
          }
          if (requested.compare(0, 7, "assets/") == 0) {
            requested.erase(0, 7);
          }
          const std::filesystem::path relative(requested);
          if (requested.empty() || relative.is_absolute()) {
            return {true, 0, {}};
          }
          for (const auto& component : relative) {
            if (component == ".." || component == "." || component.empty()) {
              return {true, 0, {}};
            }
          }
          std::error_code ec;
          const auto root = std::filesystem::canonical(
              options_.android_asset_root, ec);
          if (ec || !std::filesystem::is_directory(root, ec) || ec) {
            return {true, 0, {}};
          }
          const auto path = std::filesystem::canonical(root / relative, ec);
          if (ec || !std::filesystem::is_regular_file(path, ec) || ec) {
            return {true, 0, {}};
          }
          auto root_it = root.begin();
          auto path_it = path.begin();
          for (; root_it != root.end() && path_it != path.end();
               ++root_it, ++path_it) {
            if (*root_it != *path_it) return {true, 0, {}};
          }
          if (root_it != root.end()) return {true, 0, {}};

          std::ifstream input(path, std::ios::binary | std::ios::ate);
          if (!input) return {true, 0, {}};
          const auto end = static_cast<std::streamoff>(input.tellg());
          if (end < 0 || static_cast<std::uint64_t>(end) >
                             kMaximumAssetBytes) {
            static_cast<void>(host_calls_.SetGuestErrno(EFBIG));
            return {true, 0, {}};
          }
          GuestAsset asset;
          asset.bytes.resize(static_cast<std::size_t>(end));
          input.seekg(0, std::ios::beg);
          if (!asset.bytes.empty()) {
            input.read(reinterpret_cast<char*>(asset.bytes.data()),
                       static_cast<std::streamsize>(asset.bytes.size()));
            if (!input || static_cast<std::size_t>(input.gcount()) !=
                              asset.bytes.size()) {
              return {true, 0, {}};
            }
          }
          if (guest_assets_.size() >= kMaximumOpenAssets) {
            static_cast<void>(host_calls_.SetGuestErrno(EMFILE));
            return {true, 0, {}};
          }
          constexpr std::size_t kMaximumOpenAssetBytes =
              256U * 1024U * 1024U;
          if (asset.bytes.size() >
              kMaximumOpenAssetBytes - guest_asset_bytes_) {
            static_cast<void>(host_calls_.SetGuestErrno(ENOMEM));
            return {true, 0, {}};
          }
          guest_asset_bytes_ += asset.bytes.size();
          const std::uint64_t handle = next_guest_asset_handle_++;
          guest_assets_.emplace(handle, std::move(asset));
          return {true, handle, {}};
        })) return false;

    if (!register_one("AAsset_close",
        [this](const A64GuestHostCalls::Arguments& args)
            -> A64HostCallResult {
          const auto found = guest_assets_.find(args[0]);
          if (found == guest_assets_.end()) return {true, 0, {}};
          if (found->second.guest_buffer != 0) {
            std::string diagnostic;
            const auto allocation_size =
                std::max<std::size_t>(found->second.bytes.size(), 1U);
            if (!memory_.Unmap(found->second.guest_buffer, allocation_size,
                               &diagnostic)) {
              return {false, 0, "cannot release guest AAsset buffer: " +
                                    diagnostic};
            }
          }
          guest_asset_bytes_ -= found->second.bytes.size();
          guest_assets_.erase(found);
          return {true, 0, {}};
        })) return false;

    if (!register_one("AAsset_getLength",
        [this](const A64GuestHostCalls::Arguments& args) {
          const auto found = guest_assets_.find(args[0]);
          return A64HostCallResult{
              true, found == guest_assets_.end()
                        ? 0 : static_cast<std::uint64_t>(found->second.bytes.size()),
              {}};
        })) return false;
    if (!register_one("AAsset_getLength64",
        [this](const A64GuestHostCalls::Arguments& args) {
          const auto found = guest_assets_.find(args[0]);
          return A64HostCallResult{
              true, found == guest_assets_.end()
                        ? 0 : static_cast<std::uint64_t>(found->second.bytes.size()),
              {}};
        })) return false;
    if (!register_one("AAsset_getRemainingLength",
        [this](const A64GuestHostCalls::Arguments& args) {
          const auto found = guest_assets_.find(args[0]);
          if (found == guest_assets_.end()) return A64HostCallResult{true, 0, {}};
          const auto& asset = found->second;
          return A64HostCallResult{
              true, static_cast<std::uint64_t>(
                        asset.bytes.size() - asset.offset), {}};
        })) return false;
    if (!register_one("AAsset_getRemainingLength64",
        [this](const A64GuestHostCalls::Arguments& args) {
          const auto found = guest_assets_.find(args[0]);
          if (found == guest_assets_.end()) return A64HostCallResult{true, 0, {}};
          const auto& asset = found->second;
          return A64HostCallResult{
              true, static_cast<std::uint64_t>(
                        asset.bytes.size() - asset.offset), {}};
        })) return false;

    if (!register_one("AAsset_getBuffer",
        [this](const A64GuestHostCalls::Arguments& args)
            -> A64HostCallResult {
          auto found = guest_assets_.find(args[0]);
          if (found == guest_assets_.end()) return {true, 0, {}};
          auto& asset = found->second;
          if (asset.guest_buffer == 0) {
            const auto allocation_size =
                std::max<std::size_t>(asset.bytes.size(), 1U);
            std::string diagnostic;
            if (!memory_.MapAnywhere(
                    allocation_size,
                    A64GuestMemory::kRead | A64GuestMemory::kWrite,
                    &asset.guest_buffer, &diagnostic)) {
              return {false, 0, "cannot map guest AAsset buffer: " + diagnostic};
            }
            if (!asset.bytes.empty() &&
                !memory_.Write(asset.guest_buffer, asset.bytes.data(),
                               asset.bytes.size())) {
              std::string ignored;
              static_cast<void>(memory_.Unmap(asset.guest_buffer,
                                               allocation_size, &ignored));
              asset.guest_buffer = 0;
              return {false, 0, "cannot copy AAsset bytes into guest memory"};
            }
            if (!memory_.Protect(asset.guest_buffer, allocation_size,
                                 A64GuestMemory::kRead, &diagnostic)) {
              std::string ignored;
              static_cast<void>(memory_.Unmap(asset.guest_buffer,
                                               allocation_size, &ignored));
              asset.guest_buffer = 0;
              return {false, 0, "cannot protect guest AAsset buffer: " +
                                    diagnostic};
            }
          }
          return {true, asset.guest_buffer, {}};
        })) return false;

    if (!register_one("AAsset_read",
        [this](const A64GuestHostCalls::Arguments& args)
            -> A64HostCallResult {
          auto found = guest_assets_.find(args[0]);
          if (found == guest_assets_.end() || args[1] == 0) return {true, static_cast<std::uint64_t>(-1LL), {}};
          auto& asset = found->second;
          const auto remaining = asset.bytes.size() - asset.offset;
          const auto count = std::min<std::uint64_t>(
              args[2], std::min<std::size_t>(
                           remaining, A64GuestHostCalls::kMaximumTransferBytes));
          if (count != 0 &&
              !memory_.Write(args[1], asset.bytes.data() + asset.offset,
                             static_cast<std::size_t>(count))) {
            static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
            return {true, static_cast<std::uint64_t>(-1LL), {}};
          }
          asset.offset += static_cast<std::size_t>(count);
          return {true, count, {}};
        })) return false;

    if (!register_one("AAsset_seek",
        [this](const A64GuestHostCalls::Arguments& args)
            -> A64HostCallResult {
          auto found = guest_assets_.find(args[0]);
          if (found == guest_assets_.end()) return {true, static_cast<std::uint64_t>(-1LL), {}};
          auto& asset = found->second;
          const auto offset = static_cast<std::int64_t>(args[1]);
          std::int64_t base = 0;
          if (args[2] == 1) {
            base = static_cast<std::int64_t>(asset.offset);
          } else if (args[2] == 2) {
            base = static_cast<std::int64_t>(asset.bytes.size());
          } else if (args[2] != 0) {
            static_cast<void>(host_calls_.SetGuestErrno(EINVAL));
            return {true, static_cast<std::uint64_t>(-1LL), {}};
          }
          if ((offset > 0 && base > std::numeric_limits<std::int64_t>::max() - offset) ||
              (offset < 0 && base < std::numeric_limits<std::int64_t>::min() - offset) ||
              base + offset < 0) {
            static_cast<void>(host_calls_.SetGuestErrno(EINVAL));
            return {true, static_cast<std::uint64_t>(-1LL), {}};
          }
          asset.offset = std::min<std::size_t>(
              static_cast<std::size_t>(base + offset), asset.bytes.size());
          return {true, static_cast<std::uint64_t>(asset.offset), {}};
        })) return false;

    if (!register_one("AConfiguration_new",
        [this](const A64GuestHostCalls::Arguments&) {
          const auto handle = next_configuration_handle_++;
          configurations_.insert(handle);
          return A64HostCallResult{true, handle, {}};
        })) return false;
    if (!register_one("AConfiguration_delete",
        [this](const A64GuestHostCalls::Arguments& args) {
          configurations_.erase(args[0]);
          return A64HostCallResult{true, 0, {}};
        })) return false;
    if (!register_one("AConfiguration_fromAssetManager",
        [](const A64GuestHostCalls::Arguments&) {
          // The synthetic configuration profile is already selected by the
          // runtime options; the manager token carries no additional state.
          return A64HostCallResult{true, 0, {}};
        })) return false;
    if (!register_one("AConfiguration_getLanguage",
        [this](const A64GuestHostCalls::Arguments& args) {
          if (configurations_.count(args[0]) != 0 && args[1] != 0) {
            const char language[] = {'e', 'n', '\0'};
            if (!memory_.Write(args[1], language, sizeof(language))) {
              static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
            }
          }
          return A64HostCallResult{true, 0, {}};
        })) return false;
    if (!register_one("AConfiguration_getCountry",
        [this](const A64GuestHostCalls::Arguments& args) {
          if (configurations_.count(args[0]) != 0 && args[1] != 0) {
            const char country[] = {'U', 'S', '\0'};
            if (!memory_.Write(args[1], country, sizeof(country))) {
              static_cast<void>(host_calls_.SetGuestErrno(EFAULT));
            }
          }
          return A64HostCallResult{true, 0, {}};
        })) return false;
    const std::pair<const char*, std::uint64_t> configuration_values[] = {
        {"AConfiguration_getScreenSize", 2},
        {"AConfiguration_getScreenWidthDp", 360},
        {"AConfiguration_getScreenHeightDp", 640},
        {"AConfiguration_getNavHidden", 1},
    };
    for (const auto& item : configuration_values) {
      if (!register_one(item.first,
          [this, value = item.second](const A64GuestHostCalls::Arguments& args) {
            return A64HostCallResult{
                true, configurations_.count(args[0]) != 0 ? value : 0U, {}};
          })) return false;
    }
    if (error != nullptr) error->clear();
    return true;
  }

  bool RegisterAndroidMediaNdkApi(std::string* error) {
    auto fail = [error](const std::string& message) {
      if (error != nullptr) *error = message;
      return false;
    };
    auto register_one = [this, error](
        const char* name, A64GuestHostCalls::Handler handler) {
      return host_calls_.Register(name, "libmediandk.so", "",
                                  std::move(handler), error);
    };

    if (!register_one("AMediaFormat_new",
        [this](const A64GuestHostCalls::Arguments&) -> A64HostCallResult {
          std::uint64_t address = 0;
          std::string diagnostic;
          if (!memory_.MapAnywhere(
                  128, A64GuestMemory::kRead | A64GuestMemory::kWrite,
                  &address, &diagnostic)) {
            return {false, 0, "failed to allocate AMediaFormat placeholder: " +
                                  diagnostic};
          }
          const std::array<std::uint8_t, 128> zeroed{};
          if (!memory_.Write(address, zeroed.data(), zeroed.size())) {
            return {false, 0, "failed to initialize AMediaFormat placeholder"};
          }
          return {true, address, {}};
        })) return false;
    if (!register_one("AMediaFormat_delete",
        [](const A64GuestHostCalls::Arguments&) {
          // Placeholder objects are kept for the one-shot probe lifetime.
          return A64HostCallResult{true, 0, {}};
        })) return false;
    if (!register_one("AMediaFormat_toString",
        [](const A64GuestHostCalls::Arguments&) {
          return A64HostCallResult{true, 0, {}};
        })) return false;

    struct MediaFormatKey {
      const char* symbol;
      const char* value;
    };
    constexpr MediaFormatKey kMediaFormatKeys[] = {
        {"AMEDIAFORMAT_KEY_AAC_PROFILE", "aac-profile"},
        {"AMEDIAFORMAT_KEY_BIT_RATE", "bitrate"},
        {"AMEDIAFORMAT_KEY_BITRATE_MODE", "bitrate-mode"},
        {"AMEDIAFORMAT_KEY_CHANNEL_COUNT", "channel-count"},
        {"AMEDIAFORMAT_KEY_COLOR_FORMAT", "color-format"},
        {"AMEDIAFORMAT_KEY_COLOR_RANGE", "color-range"},
        {"AMEDIAFORMAT_KEY_COLOR_STANDARD", "color-standard"},
        {"AMEDIAFORMAT_KEY_COLOR_TRANSFER", "color-transfer"},
        {"AMEDIAFORMAT_KEY_COMPLEXITY", "complexity"},
        {"AMEDIAFORMAT_KEY_CROP_BOTTOM", "crop-bottom"},
        {"AMEDIAFORMAT_KEY_CROP_LEFT", "crop-left"},
        {"AMEDIAFORMAT_KEY_CROP_RIGHT", "crop-right"},
        {"AMEDIAFORMAT_KEY_CROP_TOP", "crop-top"},
        {"AMEDIAFORMAT_KEY_CSD_0", "csd-0"},
        {"AMEDIAFORMAT_KEY_CSD_1", "csd-1"},
        {"AMEDIAFORMAT_KEY_CSD_2", "csd-2"},
        {"AMEDIAFORMAT_KEY_DISPLAY_HEIGHT", "display-height"},
        {"AMEDIAFORMAT_KEY_DISPLAY_WIDTH", "display-width"},
        {"AMEDIAFORMAT_KEY_DURATION", "durationUs"},
        {"AMEDIAFORMAT_KEY_ENCODER_DELAY", "encoder-delay"},
        {"AMEDIAFORMAT_KEY_ENCODER_PADDING", "encoder-padding"},
        {"AMEDIAFORMAT_KEY_FLAC_COMPRESSION_LEVEL", "flac-compression-level"},
        {"AMEDIAFORMAT_KEY_FRAME_RATE", "frame-rate"},
        {"AMEDIAFORMAT_KEY_HDR_STATIC_INFO", "hdr-static-info"},
        {"AMEDIAFORMAT_KEY_HEIGHT", "height"},
        {"AMEDIAFORMAT_KEY_INTRA_REFRESH_PERIOD", "intra-refresh-period"},
        {"AMEDIAFORMAT_KEY_IS_ADTS", "is-adts"},
        {"AMEDIAFORMAT_KEY_IS_AUTOSELECT", "is-autoselect"},
        {"AMEDIAFORMAT_KEY_IS_DEFAULT", "is-default"},
        {"AMEDIAFORMAT_KEY_IS_FORCED_SUBTITLE", "is-forced-subtitle"},
        {"AMEDIAFORMAT_KEY_I_FRAME_INTERVAL", "i-frame-interval"},
        {"AMEDIAFORMAT_KEY_LANGUAGE", "language"},
        {"AMEDIAFORMAT_KEY_LEVEL", "level"},
        {"AMEDIAFORMAT_KEY_MAX_B_FRAMES", "max-bframes"},
        {"AMEDIAFORMAT_KEY_MAX_FPS_TO_ENCODER", "max-fps-to-encoder"},
        {"AMEDIAFORMAT_KEY_MAX_HEIGHT", "max-height"},
        {"AMEDIAFORMAT_KEY_MAX_INPUT_SIZE", "max-input-size"},
        {"AMEDIAFORMAT_KEY_MAX_PTS_GAP_TO_ENCODER", "max-pts-gap-to-encoder"},
        {"AMEDIAFORMAT_KEY_MAX_WIDTH", "max-width"},
        {"AMEDIAFORMAT_KEY_MIME", "mime"},
        {"AMEDIAFORMAT_KEY_OPERATING_RATE", "operating-rate"},
        {"AMEDIAFORMAT_KEY_PCM_ENCODING", "pcm-encoding"},
        {"AMEDIAFORMAT_KEY_PROFILE", "profile"},
        {"AMEDIAFORMAT_KEY_PRIORITY", "priority"},
        {"AMEDIAFORMAT_KEY_PUSH_BLANK_BUFFERS_ON_STOP",
         "push-blank-buffers-on-shutdown"},
        {"AMEDIAFORMAT_KEY_QUALITY", "quality"},
        {"AMEDIAFORMAT_KEY_REPEAT_PREVIOUS_FRAME_AFTER",
         "repeat-previous-frame-after"},
        {"AMEDIAFORMAT_KEY_ROTATION", "rotation-degrees"},
        {"AMEDIAFORMAT_KEY_SAMPLE_RATE", "sample-rate"},
        {"AMEDIAFORMAT_KEY_SLICE_HEIGHT", "slice-height"},
        {"AMEDIAFORMAT_KEY_STRIDE", "stride"},
        {"AMEDIAFORMAT_KEY_TEMPORAL_LAYERING", "ts-schema"},
        {"AMEDIAFORMAT_KEY_WIDTH", "width"},
    };
    std::size_t key_storage_size = 0;
    for (const auto& key : kMediaFormatKeys) {
      key_storage_size += std::strlen(key.value) + 1;
    }
    std::uint64_t key_storage_address = 0;
    std::string key_storage_error;
    if (!memory_.MapAnywhere(
            key_storage_size,
            A64GuestMemory::kRead | A64GuestMemory::kWrite,
            &key_storage_address, &key_storage_error)) {
      return fail("failed to allocate guest AMediaFormat key strings: " +
                  key_storage_error);
    }
    auto key_address = key_storage_address;
    for (const auto& key : kMediaFormatKeys) {
      const auto key_size = std::strlen(key.value) + 1;
      if (!memory_.Write(key_address, key.value, key_size)) {
        return fail("failed to write guest AMediaFormat key string");
      }
      if (!host_calls_.RegisterDataSymbol(
              key.symbol, "libmediandk.so", "", key_address, error)) {
        return false;
      }
      key_address += key_size;
    }

    // These setters are void in the NDK ABI. Getters return false because the
    // prototype does not yet maintain a typed AMediaFormat key/value store.
    const char* const void_apis[] = {
        "AMediaFormat_setInt32", "AMediaFormat_setInt64",
        "AMediaFormat_setFloat", "AMediaFormat_setDouble",
        "AMediaFormat_setSize", "AMediaFormat_setString",
        "AMediaFormat_setBuffer", "AMediaFormat_setRect"};
    for (const auto* name : void_apis) {
      if (!register_one(name, [](const A64GuestHostCalls::Arguments&) {
            return A64HostCallResult{true, 0, {}};
          })) return false;
    }
    const char* const getter_apis[] = {
        "AMediaFormat_getInt32", "AMediaFormat_getInt64",
        "AMediaFormat_getFloat", "AMediaFormat_getDouble",
        "AMediaFormat_getSize", "AMediaFormat_getString",
        "AMediaFormat_getBuffer", "AMediaFormat_getRect"};
    for (const auto* name : getter_apis) {
      if (!register_one(name, [](const A64GuestHostCalls::Arguments&) {
            return A64HostCallResult{true, 0, {}};
          })) return false;
    }
    if (error != nullptr) error->clear();
    return true;
  }

  bool RegisterAndroidLoggingApi(std::string* error) {
    auto register_one = [this, error](
        const char* name, A64GuestHostCalls::Handler handler) {
      return host_calls_.Register(name, "liblog.so", "", std::move(handler),
                                  error);
    };

    auto read_log_fields = [this](
        std::uint64_t tag_address, std::uint64_t message_address,
        std::string* tag, std::string* message,
        std::string* diagnostic) {
      if (!ReadBoundedGuestCString(memory_, tag_address, 128, tag,
                                   diagnostic)) {
        return false;
      }
      if (!ReadBoundedGuestCString(memory_, message_address, 4096, message,
                                   diagnostic)) {
        return false;
      }
      return true;
    };

    auto emit_log = [](int priority, const std::string& tag,
                       const std::string& message, int buffer_id) {
      // Only guest-owned strings cross this boundary. Keep one physical host
      // line per log record so guest newlines cannot forge log prefixes.
      const char* priority_name = "UNKNOWN";
      switch (priority) {
        case 1: priority_name = "DEFAULT"; break;
        case 2: priority_name = "VERBOSE"; break;
        case 3: priority_name = "DEBUG"; break;
        case 4: priority_name = "INFO"; break;
        case 5: priority_name = "WARN"; break;
        case 6: priority_name = "ERROR"; break;
        case 7: priority_name = "FATAL"; break;
        case 8: priority_name = "SILENT"; break;
        default: break;
      }
      std::clog << "[Android guest " << priority_name;
      if (buffer_id >= 0) std::clog << " buffer=" << buffer_id;
      std::clog << "][" << tag << "] ";
      for (const char character : message) {
        if (character == '\n') {
          std::clog << "\\n";
        } else if (character == '\r') {
          std::clog << "\\r";
        } else {
          std::clog << character;
        }
      }
      std::clog << '\n';
    };

    if (!register_one("__android_log_write",
        [read_log_fields, emit_log](
            const A64GuestHostCalls::Arguments& arguments) {
          const auto priority = static_cast<std::int32_t>(arguments[0]);
          if (priority < 0 || priority > 8) return A64HostCallResult{true, 0, {}};
          std::string tag, message, diagnostic;
          if (!read_log_fields(arguments[1], arguments[2], &tag, &message,
                               &diagnostic)) {
            return A64HostCallResult{
                false, 0, "invalid guest pointers passed to __android_log_write: " +
                              diagnostic};
          }
          emit_log(priority, tag, message, -1);
          return A64HostCallResult{true, 1, {}};
        })) return false;

    if (!register_one("__android_log_buf_write",
        [read_log_fields, emit_log](
            const A64GuestHostCalls::Arguments& arguments) {
          const auto buffer_id = static_cast<std::int32_t>(arguments[0]);
          const auto priority = static_cast<std::int32_t>(arguments[1]);
          if (buffer_id < 0 || priority < 0 || priority > 8) {
            return A64HostCallResult{true, 0, {}};
          }
          std::string tag, message, diagnostic;
          if (!read_log_fields(arguments[2], arguments[3], &tag, &message,
                               &diagnostic)) {
            return A64HostCallResult{
                false, 0, "invalid guest pointers passed to __android_log_buf_write: " +
                              diagnostic};
          }
          emit_log(priority, tag, message, buffer_id);
          return A64HostCallResult{true, 1, {}};
        })) return false;

    if (!register_one("__android_log_print",
        [read_log_fields, emit_log](
            const A64GuestHostCalls::Arguments& arguments) {
          const auto priority = static_cast<std::int32_t>(arguments[0]);
          if (priority < 0 || priority > 8) return A64HostCallResult{true, 0, {}};
          std::string tag, format, diagnostic;
          if (!read_log_fields(arguments[1], arguments[2], &tag, &format,
                               &diagnostic)) {
            return A64HostCallResult{
                false, 0, "invalid guest pointers passed to __android_log_print: " +
                              diagnostic};
          }
          // Varargs are not formatted yet; retain the bounded format string.
          emit_log(priority, tag, format, -1);
          return A64HostCallResult{true, format.size(), {}};
        })) return false;

    if (!register_one("__android_log_is_loggable",
        [this](const A64GuestHostCalls::Arguments& arguments) {
          const auto priority = static_cast<std::int32_t>(arguments[0]);
          const auto default_priority = static_cast<std::int32_t>(arguments[2]);
          if (priority < 0 || priority > 8 ||
              default_priority < 0 || default_priority > 8 ||
              priority == 8 || default_priority == 8) {
            return A64HostCallResult{true, 0, {}};
          }
          // Validate a provided tag even though per-tag property overrides
          // aren't emulated yet. A null tag uses only the caller's fallback.
          if (arguments[1] != 0) {
            std::string tag, message, diagnostic;
            if (!ReadBoundedGuestCString(memory_, arguments[1], 128, &tag,
                                         &diagnostic)) {
              return A64HostCallResult{
                  false, 0, "invalid tag passed to __android_log_is_loggable: " +
                                diagnostic};
            }
          }
          const auto effective_priority =
              priority <= 1 ? default_priority : priority;
          return A64HostCallResult{
              true, effective_priority >= default_priority ? 1U : 0U, {}};
        })) return false;

    return true;
  }

  bool RegisterGuestSingleThreadSynchronizationApi(std::string* error) {
    auto register_one = [this, error](
        const char* name, A64GuestHostCalls::Handler handler) {
      return host_calls_.Register(name, "libc.so", "", std::move(handler),
                                  error);
    };
    auto valid_object = [this](std::uint64_t address) {
      std::uint8_t byte = 0;
      return address != 0 && memory_.Read(address, &byte, sizeof(byte));
    };
    auto initialize_object = [this](std::uint64_t address) {
      const std::uint64_t initial_state = 0;
      return address != 0 &&
             memory_.Write(address, &initial_state, sizeof(initial_state));
    };

    // No guest pthreads are created yet. These operations only make the
    // single active guest context able to pass through basic lock-protected
    // initialization code. They do not provide mutual exclusion across host
    // threads, condition-variable waits, or a pthread scheduler.
    auto lock_noop = [valid_object](
        const A64GuestHostCalls::Arguments& arguments) {
      return A64HostCallResult{
          true, valid_object(arguments[0]) ? 0U : EINVAL, {}};
    };
    auto init_noop = [initialize_object](
        const A64GuestHostCalls::Arguments& arguments) {
      return A64HostCallResult{
          true, initialize_object(arguments[0]) ? 0U : EINVAL, {}};
    };

    const struct {
      const char* name;
      A64GuestHostCalls::Handler handler;
    } object_initializers[] = {
        {"pthread_mutex_init", init_noop},
        {"pthread_rwlock_init", init_noop},
        {"pthread_spin_init", init_noop},
    };
    for (const auto& item : object_initializers) {
      if (!register_one(item.name, item.handler)) return false;
    }

    const char* const object_noops[] = {
        "pthread_mutex_destroy", "pthread_mutex_lock",
        "pthread_mutex_trylock", "pthread_mutex_timedlock",
        "pthread_mutex_unlock", "pthread_rwlock_destroy",
        "pthread_rwlock_rdlock", "pthread_rwlock_tryrdlock",
        "pthread_rwlock_wrlock", "pthread_rwlock_trywrlock",
        "pthread_rwlock_unlock", "pthread_spin_destroy",
        "pthread_spin_lock", "pthread_spin_trylock",
        "pthread_spin_unlock", "pthread_mutex_consistent",
    };
    for (const auto* name : object_noops) {
      if (!register_one(name, lock_noop)) return false;
    }

    if (!register_one("pthread_self", [](
            const A64GuestHostCalls::Arguments&) {
          // An opaque, canonical guest pointer-like identifier. It is not a
          // host pthread_t and must not be dereferenced by guest code.
          return A64HostCallResult{true, 0x6000000010ULL, {}};
        })) {
      return false;
    }
    if (!register_one("pthread_equal", [](
            const A64GuestHostCalls::Arguments& arguments) {
          return A64HostCallResult{
              true, arguments[0] == arguments[1] ? 1U : 0U, {}};
        })) {
      return false;
    }
    return true;
  }

  bool RegisterGuestCxxGuardApi(std::string* error) {
    auto register_one = [this, error](
        const char* name, const char* provider,
        A64GuestHostCalls::Handler handler) {
      return host_calls_.Register(name, provider, "", std::move(handler),
                                  error);
    };

    auto acquire = [this](const A64GuestHostCalls::Arguments& arguments)
        -> A64HostCallResult {
      std::uint64_t guard = 0;
      if (arguments[0] == 0 ||
          !memory_.Read(arguments[0], &guard, sizeof(guard))) {
        return {false, 0, "invalid guest pointer passed to __cxa_guard_acquire"};
      }
      // Itanium C++ ABI guard byte: bit 0 means initialization completed and
      // bit 1 marks initialization in progress. The single-thread prototype
      // avoids recursive re-entry, but doesn't implement cross-thread waits.
      if ((guard & 0x1U) != 0 || (guard & 0x2U) != 0) {
        return {true, 0, {}};
      }
      guard |= 0x2U;
      if (!memory_.Write(arguments[0], &guard, sizeof(guard))) {
        return {false, 0, "guest __cxa_guard storage is not writable"};
      }
      return {true, 1, {}};
    };
    auto release = [this](const A64GuestHostCalls::Arguments& arguments)
        -> A64HostCallResult {
      std::uint64_t guard = 0;
      if (arguments[0] == 0 ||
          !memory_.Read(arguments[0], &guard, sizeof(guard))) {
        return {false, 0, "invalid guest pointer passed to __cxa_guard_release"};
      }
      guard = (guard | 0x1U) & ~0x2ULL;
      if (!memory_.Write(arguments[0], &guard, sizeof(guard))) {
        return {false, 0, "guest __cxa_guard storage is not writable"};
      }
      return {true, 0, {}};
    };
    auto abort = [this](const A64GuestHostCalls::Arguments& arguments)
        -> A64HostCallResult {
      std::uint64_t guard = 0;
      if (arguments[0] == 0 ||
          !memory_.Read(arguments[0], &guard, sizeof(guard))) {
        return {false, 0, "invalid guest pointer passed to __cxa_guard_abort"};
      }
      guard &= ~0x3ULL;
      if (!memory_.Write(arguments[0], &guard, sizeof(guard))) {
        return {false, 0, "guest __cxa_guard storage is not writable"};
      }
      return {true, 0, {}};
    };

    const char* const providers[] = {"libc++_shared.so", "libc.so"};
    for (const auto* provider : providers) {
      if (!register_one("__cxa_guard_acquire", provider, acquire) ||
          !register_one("__cxa_guard_release", provider, release) ||
          !register_one("__cxa_guard_abort", provider, abort)) {
        return false;
      }
    }
    return true;
  }

  bool RegisterDynamicLinkerApi(std::string* error) {
    auto register_one = [this, error](
        const char* name, A64GuestHostCalls::Handler handler) {
      return host_calls_.Register(name, "libdl.so", "", std::move(handler),
                                  error);
    };
    if (!register_one("dlopen", [this](
            const A64GuestHostCalls::Arguments& arguments) {
          return GuestDlopen(arguments);
        })) return false;
    if (!register_one("dlsym", [this](
            const A64GuestHostCalls::Arguments& arguments) {
          return GuestDlsym(arguments);
        })) return false;
    if (!register_one("dlclose", [this](
            const A64GuestHostCalls::Arguments& arguments) {
          return GuestDlclose(arguments);
        })) return false;
    if (!register_one("dlerror", [this](
            const A64GuestHostCalls::Arguments&) {
          return GuestDlerror();
        })) return false;
    if (!register_one("dladdr", [this](
            const A64GuestHostCalls::Arguments& arguments) {
          return GuestDladdr(arguments);
        })) return false;
    return true;
  }

  bool Load(const std::vector<A64GuestModuleSource>& sources,
            const std::string& root_name, std::string* error) {
    auto fail = [&](std::string message) {
      if (error != nullptr) *error = std::move(message);
      return false;
    };
    if (loaded_ || load_attempted_) {
      return fail("an AArch64 guest runtime instance can only be loaded once");
    }
    load_attempted_ = true;
    if (sources.empty()) return fail("guest module catalogue is empty");
    if (options_.max_guest_memory_bytes < A64GuestMemory::kPageSize) {
      return fail("guest memory budget is smaller than one page");
    }
    constexpr std::uint32_t kMaximumStackGuardPages = 64;
    if (options_.stack_guard_pages > kMaximumStackGuardPages) {
      return fail("guest stack guard page count exceeds the configured limit");
    }
    const auto stack_guard_size =
        static_cast<std::uint64_t>(options_.stack_guard_pages) *
        A64GuestMemory::kPageSize;
    if (options_.stack_size == 0 ||
        options_.stack_base % A64GuestMemory::kPageSize != 0 ||
        options_.stack_size % A64GuestMemory::kPageSize != 0 ||
        options_.stack_base < stack_guard_size ||
        AddOverflows(options_.stack_base, options_.stack_size)) {
      return fail("guest stack range and lower guard must be page-aligned and non-overflowing");
    }
    const auto stack_end = options_.stack_base + options_.stack_size;
    if (AddOverflows(stack_end, stack_guard_size)) {
      return fail("guest stack upper guard address overflows");
    }
    if (options_.return_trap_address % 4U != 0 ||
        AddOverflows(options_.return_trap_address,
                     sizeof(kA64BreakpointInstruction))) {
      return fail("guest return-trap address must be instruction-aligned");
    }

    std::string diagnostic;
    if (options_.register_builtin_libc &&
        !host_calls_.RegisterBuiltinLibc(&diagnostic)) {
      return fail("failed to register guest libc thunks: " + diagnostic);
    }
    if (options_.register_builtin_libc &&
        !RegisterAndroidSystemProperties(&diagnostic)) {
      return fail("failed to register synthetic Android properties: " + diagnostic);
    }
    if (options_.register_builtin_libc &&
        !RegisterGuestAuxiliaryVector(&diagnostic)) {
      return fail("failed to register guest getauxval: " + diagnostic);
    }
    if (options_.register_builtin_libc &&
        !RegisterAndroidPlatformApi(&diagnostic)) {
      return fail("failed to register Android NDK platform API: " + diagnostic);
    }
    if (options_.register_builtin_libc &&
        !RegisterAndroidBitmapApi(&diagnostic)) {
      return fail("failed to register Android bitmap API: " + diagnostic);
    }
    if (options_.register_builtin_libc &&
        !RegisterAndroidNativeWindowApi(&diagnostic)) {
      return fail("failed to register Android native-window API: " + diagnostic);
    }
    if (options_.register_builtin_libc &&
        !RegisterAndroidLooperApi(&diagnostic)) {
      return fail("failed to register Android looper API: " + diagnostic);
    }
    if (options_.register_builtin_libc &&
        !RegisterAndroidAssetApi(&diagnostic)) {
      return fail("failed to register Android asset/configuration API: " + diagnostic);
    }
    if (options_.register_builtin_libc &&
        !RegisterAndroidMediaNdkApi(&diagnostic))
      return fail("failed to register Android NDK media API: " + diagnostic);
    }
    if (options_.register_builtin_libc &&
        !RegisterAndroidLoggingApi(&diagnostic)) {
      return fail("failed to register Android liblog API: " + diagnostic);
    }
    if (options_.register_builtin_libc &&
        !RegisterGuestSingleThreadSynchronizationApi(&diagnostic)) {
      return fail("failed to register limited guest pthread shims: " + diagnostic);
    }
    if (options_.register_builtin_libc &&
        !RegisterGuestCxxGuardApi(&diagnostic)) {
      return fail("failed to register C++ static-initialization guards: " + diagnostic);
    }
    if (!host_calls_.RegisterTlsGetAddr(tls_runtime_, main_thread_tls_,
                                        "libc.so", "", &diagnostic)) {
      return fail("failed to register __tls_get_addr: " + diagnostic);
    }
    if (jni_bridge_ && !jni_bridge_->Register(&diagnostic)) {
      return fail("failed to register guest JNI handlers: " + diagnostic);
    }
    if (!RegisterDynamicLinkerApi(&diagnostic)) {
      return fail("failed to register preloaded-module dlopen/dlsym thunks: " +
                  diagnostic);
    }
    if (options_.configure_host_calls &&
        !options_.configure_host_calls(host_calls_, &diagnostic)) {
      return fail("custom guest host-call registration failed: " + diagnostic);
    }

    if (!host_calls_.Install(&diagnostic)) {
      return fail("failed to install guest host-call stubs: " + diagnostic);
    }

    // Install assigns guest addresses to registered exports. Resolve the
    // TLSDESC thunk only afterwards; looking it up before Install() always
    // returns empty because uninstalled exports have no guest address yet.
    const auto tlsdesc_resolver =
        host_calls_.ResolveSymbol("__mocktail_tlsdesc_static");
    if (!tlsdesc_resolver) {
      return fail("static guest TLSDESC resolver thunk was not registered");
    }

    auto module_options = options_.module_load;
    if (options_.register_builtin_libc &&
        std::find(module_options.external_dependencies.begin(),
                  module_options.external_dependencies.end(), "libc.so") ==
            module_options.external_dependencies.end()) {
      module_options.external_dependencies.push_back("libc.so");
    }
    // libdl.so is represented by guest shims, not the host process's libdl.
    if (std::find(module_options.external_dependencies.begin(),
                  module_options.external_dependencies.end(), "libdl.so") ==
        module_options.external_dependencies.end()) {
      module_options.external_dependencies.push_back("libdl.so");
    }
    if (options_.register_builtin_libc &&
        std::find(module_options.external_dependencies.begin(),
                  module_options.external_dependencies.end(), "libandroid.so") ==
            module_options.external_dependencies.end()) {
      module_options.external_dependencies.push_back("libandroid.so");
    }
    if (options_.register_builtin_libc) {
      // These public Android platform SONAMEs may be supplied by the device
      // rather than bundled in the APK. This only permits the dependency edge;
      // imports still need a real guest module or an explicit host-call thunk.
      const char* const android_system_dependencies[] = {
          "liblog.so", "libm.so", "libz.so", "libEGL.so",
          "libGLESv1_CM.so", "libGLESv2.so", "libGLESv3.so",
          "libvulkan.so", "libjnigraphics.so", "libnativewindow.so",
          "libsync.so", "libmediandk.so", "libOpenSLES.so",
          "libOpenMAXAL.so", "libaaudio.so",
          "libcamera2ndk.so", "libamidi.so", "libbinder_ndk.so",
          "libneuralnetworks.so", "libsensor.so", "libusbhost.so"};
      for (const auto* dependency : android_system_dependencies) {
        if (std::find(module_options.external_dependencies.begin(),
                      module_options.external_dependencies.end(), dependency) ==
            module_options.external_dependencies.end()) {
          module_options.external_dependencies.emplace_back(dependency);
        }
      }
    }
    module_options.elf.tlsdesc_resolver_address = *tlsdesc_resolver;

    const auto configured_symbol_resolver =
        module_options.resolve_external_symbol;
    module_options.resolve_external_symbol =
        [this, configured_symbol_resolver](const std::string& name)
        -> std::optional<std::uint64_t> {
      const auto builtin = host_calls_.ResolveSymbol(name);
      if (builtin) return builtin;
      if (configured_symbol_resolver) return configured_symbol_resolver(name);
      return std::nullopt;
    };

    const auto configured_versioned_resolver =
        module_options.resolve_external_versioned_symbol;
    module_options.resolve_external_versioned_symbol =
        [this, configured_versioned_resolver](
            const A64SymbolRequest& request)
        -> std::optional<std::uint64_t> {
      const auto builtin = host_calls_.ResolveVersionedSymbol(request);
      if (builtin) return builtin;
      if (configured_versioned_resolver) {
        return configured_versioned_resolver(request);
      }
      return std::nullopt;
    };

    auto loaded_modules =
        LoadA64GuestModuleSet(sources, root_name, std::move(module_options));
    if (!loaded_modules) {
      return fail("failed to load AArch64 guest module set: " +
                  loaded_modules.error);
    }
    modules_ = std::move(*loaded_modules.modules);

    if (!tls_runtime_.Prepare(*modules_, &diagnostic)) {
      return fail("failed to prepare guest static TLS: " + diagnostic);
    }
    if (!tls_runtime_.CreateThread(&main_thread_tls_, &diagnostic)) {
      return fail("failed to allocate guest main-thread TLS: " + diagnostic);
    }

    for (const auto& module : modules_->modules) {
      if (!memory_.MapImage(module.image, &diagnostic)) {
        return fail("failed to map guest module '" + module.source_name +
                    "': " + diagnostic);
      }
    }
    if (stack_guard_size != 0 &&
        !memory_.Map(options_.stack_base - stack_guard_size,
                     stack_guard_size, 0, &diagnostic)) {
      return fail("failed to allocate lower guest stack guard: " + diagnostic);
    }
    if (!memory_.Map(options_.stack_base, options_.stack_size,
                     A64GuestMemory::kRead | A64GuestMemory::kWrite,
                     &diagnostic)) {
      return fail("failed to allocate guest stack: " + diagnostic);
    }
    if (stack_guard_size != 0 &&
        !memory_.Map(stack_end, stack_guard_size, 0, &diagnostic)) {
      return fail("failed to allocate upper guest stack guard: " + diagnostic);
    }

    if (!memory_.Map(options_.return_trap_address,
                     A64GuestMemory::kPageSize,
                     A64GuestMemory::kRead | A64GuestMemory::kExecute,
                     &diagnostic)) {
      return fail("failed to map guest return trap: " + diagnostic);
    }
    const std::uint8_t trap[] = {
        0x00, 0x00, 0x20, 0xD4,  // brk #0
    };
    if (!memory_.Initialize(options_.return_trap_address, trap, sizeof(trap))) {
      return fail("failed to initialize guest return trap");
    }

    callbacks_ = std::make_unique<Callbacks>(*this);
    Dynarmic::A64::UserConfig config{};
    config.callbacks = callbacks_.get();
    config.tpidr_el0 = &main_thread_tls_.tpidr_el0;
    // AddTicks is the instruction-budget enforcement point. Dynarmic must
    // report guest execution ticks or looping guest code cannot be stopped.
    config.enable_cycle_counting = true;
    config.hook_hint_instructions = true;
    jit_ = std::make_unique<Dynarmic::A64::Jit>(config);
    callbacks_->Attach(jit_.get());

    // Populate read-only JNI tables after guest mappings exist, avoiding
    // collisions with ELF images, the stack, stubs, and the return trap.
    if (jni_bridge_ && !jni_bridge_->Initialize(&diagnostic)) {
      return fail("failed to initialize guest JNI tables: " + diagnostic);
    }

    loaded_ = true;
    if (error != nullptr) error->clear();
    if (options_.run_initializers_on_load && !RunInitializers(error)) {
      loaded_ = false;
      return false;
    }
    return true;
  }

  A64GuestCallResult Call(
      std::uint64_t guest_address, const Arguments& arguments,
      std::uint64_t instruction_budget,
      const std::vector<std::uint64_t>& stack_arguments = {},
      const std::array<Dynarmic::A64::Vector, 8>* vector_arguments = nullptr) {
    auto failure = [](std::string error) {
      A64GuestCallResult result;
      result.error = std::move(error);
      return result;
    };
    if (!loaded_ || !jit_ || !callbacks_) {
      return failure("AArch64 guest runtime is not loaded");
    }
    if (guest_address % 4U != 0 ||
        !memory_.IsExecutable(guest_address, sizeof(std::uint32_t))) {
      return failure("guest function address is unaligned or not executable");
    }
    const auto budget = instruction_budget == 0
                            ? options_.instruction_budget
                            : instruction_budget;
    if (budget == 0) return failure("guest instruction budget must be non-zero");

    // AAPCS64 places general-purpose arguments after X7 in the caller's
    // stack argument area. Keep SP 16-byte aligned and bound this probe path
    // so a malformed caller cannot consume the entire guest stack.
    constexpr std::size_t kMaximumStackArguments = 256;
    if (stack_arguments.size() > kMaximumStackArguments) {
      return failure("guest stack argument count exceeds the configured limit");
    }
    const std::uint64_t stack_top =
        options_.stack_base + options_.stack_size - 16U;
    const std::uint64_t stack_bytes_unaligned =
        static_cast<std::uint64_t>(stack_arguments.size()) * sizeof(std::uint64_t);
    const std::uint64_t stack_bytes =
        (stack_bytes_unaligned + 15U) & ~std::uint64_t{15U};
    if (stack_bytes > options_.stack_size - 16U || stack_bytes > stack_top) {
      return failure("guest stack arguments exceed the available stack");
    }
    const std::uint64_t guest_sp = stack_top - stack_bytes;
    for (std::size_t index = 0; index < stack_arguments.size(); ++index) {
      const auto value = stack_arguments[index];
      if (!memory_.Write(guest_sp + index * sizeof(value), &value,
                         sizeof(value))) {
        return failure("failed to write guest stack argument");
      }
    }

    callbacks_->BeginRun(budget, true);
    jit_->SetSP(guest_sp);
    for (std::size_t index = 0; index < arguments.size(); ++index) {
      jit_->SetRegister(index, arguments[index]);
    }
    if (vector_arguments != nullptr) {
      for (std::size_t index = 0; index < vector_arguments->size(); ++index) {
        jit_->SetVector(index, (*vector_arguments)[index]);
      }
    }
    jit_->SetRegister(30, options_.return_trap_address);
    jit_->SetPC(guest_address);
    static_cast<void>(jit_->Run());

    A64GuestCallResult result;
    result.ticks = callbacks_->ticks_used();
    result.guest_exit = callbacks_->guest_exit();
    result.exit_status = callbacks_->exit_status();
    result.value = jit_->GetRegister(0);
    if (!callbacks_->failure().empty()) {
      result.error = callbacks_->failure();
      return result;
    }
    if (!callbacks_->saw_return_trap() && !result.guest_exit) {
      result.error = "guest function stopped without returning through X30";
      return result;
    }
    result.success = true;
    return result;
  }

  bool RunInitializers(std::string* error) {
    auto fail = [&](const std::string& message) {
      if (error != nullptr) *error = message;
      return false;
    };
    if (!loaded_ || !modules_) {
      return fail("cannot run guest initializers before loading modules");
    }
    if (initializers_run_) {
      return fail("guest initializers have already been executed");
    }

    const Arguments no_arguments{};
    for (const auto module_index : modules_->initialization_order) {
      if (module_index >= modules_->modules.size()) {
        return fail("guest module set has an invalid initialization-order index");
      }
      const auto& module = modules_->modules[module_index];
      for (const auto address : module.image.initializers) {
        const auto result = Call(address, no_arguments, 0);
        if (!result) {
          return fail("guest initializer in '" + module.source_name +
                      "' failed: " + result.error);
        }
      }
    }
    initializers_run_ = true;
    if (error != nullptr) error->clear();
    return true;
  }

  bool RunFinalizers(std::string* error) {
    auto fail = [&](const std::string& message) {
      if (error != nullptr) *error = message;
      return false;
    };
    if (!loaded_ || !modules_) {
      return fail("cannot run guest finalizers before loading modules");
    }
    if (!initializers_run_) {
      return fail("guest finalizers require an initializers-run state");
    }
    if (finalizers_run_) return fail("guest finalizers have already been executed");

    const Arguments no_arguments{};
    for (const auto module_index : modules_->finalization_order) {
      if (module_index >= modules_->modules.size()) {
        return fail("guest module set has an invalid finalization-order index");
      }
      const auto& module = modules_->modules[module_index];
      for (const auto address : module.image.finalizers) {
        const auto result = Call(address, no_arguments, 0);
        if (!result) {
          return fail("guest finalizer in '" + module.source_name +
                      "' failed: " + result.error);
        }
      }
    }
    finalizers_run_ = true;
    if (error != nullptr) error->clear();
    return true;
  }

  A64GuestCallResult CallSymbol(const std::string& symbol,
                                const Arguments& arguments,
                                std::uint64_t instruction_budget) {
    if (!modules_) {
      A64GuestCallResult result;
      result.error = "AArch64 guest runtime is not loaded";
      return result;
    }
    const auto address = modules_->ResolveExportedSymbol(symbol);
    if (!address) {
      A64GuestCallResult result;
      result.error = "AArch64 guest export was not found: " + symbol;
      return result;
    }
    return Call(*address, arguments, instruction_budget);
  }

  A64GuestCallResult CallSymbol(const A64SymbolRequest& request,
                                const Arguments& arguments,
                                std::uint64_t instruction_budget) {
    if (!modules_) {
      A64GuestCallResult result;
      result.error = "AArch64 guest runtime is not loaded";
      return result;
    }
    const auto address = modules_->ResolveExportedSymbol(request);
    if (!address) {
      A64GuestCallResult result;
      result.error = "AArch64 guest export was not found for symbol '" +
                     request.name + "'";
      if (!request.version.empty()) {
        result.error += " with version '" + request.version + "'";
      }
      if (!request.provider.empty()) {
        result.error += " from provider '" + request.provider + "'";
      }
      return result;
    }
    return Call(*address, arguments, instruction_budget);
  }

  A64GuestCallResult CallJniOnLoad(std::uint64_t instruction_budget) {
    A64GuestCallResult result;
    if (!loaded_) {
      result.error = "AArch64 guest runtime is not loaded";
      return result;
    }
    if (!jni_bridge_ || jni_bridge_->java_vm_address() == 0) {
      result.error = "guest JNI bridge is disabled";
      return result;
    }
    Arguments arguments{};
    arguments[0] = jni_bridge_->java_vm_address();
    return CallSymbol("JNI_OnLoad", arguments, instruction_budget);
  }

  A64GuestCallResult CallRegisteredJniNative(
      const std::string& class_name, const std::string& name,
      const std::string& signature,
      const std::vector<std::uint64_t>& java_arguments,
      std::uint64_t instruction_budget) {
    auto failure = [](std::string message) {
      A64GuestCallResult result;
      result.error = std::move(message);
      return result;
    };
    if (!loaded_) return failure("AArch64 guest runtime is not loaded");
    if (!jni_bridge_ || !jni_bridge_->initialized()) {
      return failure("guest JNI bridge is disabled or uninitialized");
    }
    if (jni_bridge_->pending_exception()) {
      return failure("guest JNI bridge has a pending exception");
    }
    constexpr std::size_t kMaximumJniArguments = 262;
    if (java_arguments.size() > kMaximumJniArguments) {
      return failure("JNI argument count exceeds the configured limit");
    }

    std::size_t descriptor_argument_count = 0;
    std::string descriptor_error;
    std::vector<char> parameter_types;
    if (!CountJniParameterTypes(signature, &descriptor_argument_count,
                                &descriptor_error, &parameter_types)) {
      return failure(descriptor_error);
    }
    if (descriptor_argument_count != java_arguments.size()) {
      return failure("JNI argument count does not match the registered signature");
    }

    const auto class_handle = jni_bridge_->FindClassHandle(class_name);
    if (class_handle == 0) {
      return failure("JNI class was not resolved by the guest bridge: " +
                     class_name);
    }
    const auto natives = jni_bridge_->registered_natives();
    const auto native = std::find_if(
        natives.begin(), natives.end(),
        [&](const A64GuestJniNativeRegistration& item) {
          return item.class_name == class_name && item.name == name &&
                 item.signature == signature;
        });
    if (native == natives.end() || native->guest_address == 0) {
      return failure("JNI native is not registered: " + class_name + "." +
                     name + signature);
    }

    // JNI's implicit JNIEnv*/jclass consume X0/X1. AAPCS64 allocates
    // integer/reference arguments from X2-X7 and float/double arguments from
    // V0-V7 independently; overflow arguments are placed in stack slots in
    // source order. The caller supplies IEEE-754 bit patterns for F/D values.
    Arguments arguments{};
    arguments[0] = jni_bridge_->jni_environment_address();
    arguments[1] = class_handle;
    std::array<Dynarmic::A64::Vector, 8> vector_arguments{};
    std::size_t next_general_register = 2;
    std::size_t next_vector_register = 0;
    std::vector<std::uint64_t> stack_arguments;
    stack_arguments.reserve(java_arguments.size());
    for (std::size_t index = 0; index < java_arguments.size(); ++index) {
      const auto type = parameter_types[index];
      if (type == 'F' || type == 'D') {
        if (next_vector_register < vector_arguments.size()) {
          vector_arguments[next_vector_register++][0] = java_arguments[index];
        } else {
          stack_arguments.push_back(java_arguments[index]);
        }
      } else if (next_general_register < arguments.size()) {
        arguments[next_general_register++] = java_arguments[index];
      } else {
        stack_arguments.push_back(java_arguments[index]);
      }
    }
    auto result = Call(native->guest_address, arguments, instruction_budget,
                       stack_arguments, &vector_arguments);
    if (result.success) {
      const auto close_paren = signature.find(')');
      if (close_paren != std::string::npos &&
          close_paren + 1U < signature.size()) {
        const char return_type = signature[close_paren + 1U];
        if (return_type == 'F' || return_type == 'D') {
          result.value = jit_->GetVector(0)[0];
          if (return_type == 'F') result.value &= 0xFFFFFFFFULL;
          result.value_is_floating_point = true;
        }
      }
    }
    return result;
  }

  std::uint64_t java_vm_address() const noexcept {
    return jni_bridge_ ? jni_bridge_->java_vm_address() : 0;
  }

  std::uint64_t jni_environment_address() const noexcept {
    return jni_bridge_ ? jni_bridge_->jni_environment_address() : 0;
  }

  bool jni_exception_pending() const noexcept {
    return jni_bridge_ && jni_bridge_->pending_exception();
  }

  std::vector<A64GuestJniNativeRegistration> registered_jni_natives() const {
    return jni_bridge_ ? jni_bridge_->registered_natives()
                       : std::vector<A64GuestJniNativeRegistration>{};
  }

  bool loaded() const noexcept { return loaded_; }
  const A64GuestModuleSet* modules() const noexcept {
    return modules_ ? &*modules_ : nullptr;
  }
  A64GuestMemory* memory() noexcept { return &memory_; }
  A64GuestHostCalls* host_calls() noexcept { return &host_calls_; }
  A64GuestTlsRuntime* tls_runtime() noexcept { return &tls_runtime_; }
  const A64GuestThreadTls* main_thread_tls() const noexcept {
    return &main_thread_tls_;
  }

 private:
  A64GuestRuntimeOptions options_;
  A64GuestMemory memory_;
  A64GuestTlsRuntime tls_runtime_;
  A64GuestThreadTls main_thread_tls_;
  A64GuestHostCalls host_calls_;
  A64LinuxSyscalls syscalls_;
  std::unique_ptr<A64GuestJniBridge> jni_bridge_;
  std::optional<A64GuestModuleSet> modules_;
  std::map<std::uint64_t, std::size_t> dl_handles_;
  std::uint64_t guest_auxv_random_address_ = 0;
  std::string dl_error_;
  std::uint64_t dl_error_buffer_address_ = 0;
  // Stable guest copies returned by dladdr; capped to avoid unbounded guest
  // mapping growth. Their lifetime is the runtime's lifetime.
  std::map<std::string, std::uint64_t> dl_guest_strings_;
  std::mutex android_property_mutex_;
  std::map<std::string, std::uint64_t> android_property_handles_;
  std::map<std::uint64_t, std::string> android_property_names_;
  struct GuestLooper final {
    struct Registration final {
      int ident = 0;
      int events = 0;
      std::uint64_t data = 0;
    };
    ~GuestLooper() {
      if (wake_fd >= 0) ::close(wake_fd);
      if (epoll_fd >= 0) ::close(epoll_fd);
    }
    int epoll_fd = -1;
    int wake_fd = -1;
    std::uint32_t references = 1;
    bool allow_non_callbacks = false;
    std::atomic<bool> polling{false};
    std::mutex mutex;
    std::unordered_map<int, Registration> registrations;
  };
  std::unique_ptr<GuestLooper> guest_looper_;
  struct GuestAsset final {
    std::vector<std::uint8_t> bytes;
    std::size_t offset = 0;
    std::uint64_t guest_buffer = 0;
  };
  std::map<std::uint64_t, GuestAsset> guest_assets_;
  std::size_t guest_asset_bytes_ = 0;
  std::set<std::uint64_t> configurations_;
  std::uint64_t next_guest_asset_handle_ = 0x4153534554000010ULL;
  std::uint64_t next_configuration_handle_ = 0x434F4E4649470010ULL;
  std::uint64_t next_android_property_handle_ = 0x50524F5000000010ULL;
  bool dl_error_pending_ = false;
  std::unique_ptr<Callbacks> callbacks_;
  std::unique_ptr<Dynarmic::A64::Jit> jit_;
  bool load_attempted_ = false;
  bool loaded_ = false;
  bool initializers_run_ = false;
  bool finalizers_run_ = false;
};

A64GuestRuntime::A64GuestRuntime(A64GuestRuntimeOptions options)
    : impl_(std::make_unique<Impl>(std::move(options))) {}

A64GuestRuntime::~A64GuestRuntime() = default;
A64GuestRuntime::A64GuestRuntime(A64GuestRuntime&&) noexcept = default;
A64GuestRuntime& A64GuestRuntime::operator=(A64GuestRuntime&&) noexcept = default;

bool A64GuestRuntime::Load(const std::vector<A64GuestModuleSource>& sources,
                           const std::string& root_name,
                           std::string* error) {
  return impl_->Load(sources, root_name, error);
}

bool A64GuestRuntime::RunInitializers(std::string* error) {
  return impl_->RunInitializers(error);
}

bool A64GuestRuntime::RunFinalizers(std::string* error) {
  return impl_->RunFinalizers(error);
}

A64GuestCallResult A64GuestRuntime::Call(
    std::uint64_t guest_address, const Arguments& arguments,
    std::uint64_t instruction_budget) {
  return impl_->Call(guest_address, arguments, instruction_budget);
}

A64GuestCallResult A64GuestRuntime::CallSymbol(
    const std::string& symbol, const Arguments& arguments,
    std::uint64_t instruction_budget) {
  return impl_->CallSymbol(symbol, arguments, instruction_budget);
}

A64GuestCallResult A64GuestRuntime::CallSymbol(
    const A64SymbolRequest& request, const Arguments& arguments,
    std::uint64_t instruction_budget) {
  return impl_->CallSymbol(request, arguments, instruction_budget);
}

A64GuestCallResult A64GuestRuntime::CallJniOnLoad(
    std::uint64_t instruction_budget) {
  return impl_->CallJniOnLoad(instruction_budget);
}

A64GuestCallResult A64GuestRuntime::CallRegisteredJniNative(
    const std::string& class_name, const std::string& name,
    const std::string& signature,
    const std::vector<std::uint64_t>& java_arguments,
    std::uint64_t instruction_budget) {
  return impl_->CallRegisteredJniNative(
      class_name, name, signature, java_arguments, instruction_budget);
}

std::uint64_t A64GuestRuntime::java_vm_address() const noexcept {
  return impl_->java_vm_address();
}

std::uint64_t A64GuestRuntime::jni_environment_address() const noexcept {
  return impl_->jni_environment_address();
}

bool A64GuestRuntime::jni_exception_pending() const noexcept {
  return impl_->jni_exception_pending();
}

std::vector<A64GuestJniNativeRegistration>
A64GuestRuntime::registered_jni_natives() const {
  return impl_->registered_jni_natives();
}

bool A64GuestRuntime::loaded() const noexcept { return impl_->loaded(); }

const A64GuestModuleSet* A64GuestRuntime::modules() const noexcept {
  return impl_->modules();
}

A64GuestMemory* A64GuestRuntime::memory() noexcept { return impl_->memory(); }

A64GuestHostCalls* A64GuestRuntime::host_calls() noexcept {
  return impl_->host_calls();
}

A64GuestTlsRuntime* A64GuestRuntime::tls_runtime() noexcept {
  return impl_->tls_runtime();
}

const A64GuestThreadTls* A64GuestRuntime::main_thread_tls() const noexcept {
  return impl_->main_thread_tls();
}

}  // namespace mocktail::translation
