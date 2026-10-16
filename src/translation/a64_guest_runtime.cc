// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_runtime.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <utility>

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
                            std::string* error) {
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
  while (cursor < signature.size() && signature[cursor] != ')') {
    if (!ParseJniTypeDescriptor(signature, &cursor, false)) {
      return fail("invalid JNI parameter type descriptor");
    }
    ++count;
    if (count > 6) {
      return fail("JNI methods with more than six register-passed arguments are unsupported");
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
    if (options_.stack_size == 0 ||
        options_.stack_base % A64GuestMemory::kPageSize != 0 ||
        options_.stack_size % A64GuestMemory::kPageSize != 0 ||
        AddOverflows(options_.stack_base, options_.stack_size)) {
      return fail("guest stack range must be page-aligned and non-overflowing");
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
    if (!host_calls_.RegisterTlsGetAddr(tls_runtime_, main_thread_tls_,
                                        "libc.so", "", &diagnostic)) {
      return fail("failed to register __tls_get_addr: " + diagnostic);
    }
    if (jni_bridge_ && !jni_bridge_->Register(&diagnostic)) {
      return fail("failed to register guest JNI handlers: " + diagnostic);
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
    if (!memory_.Map(options_.stack_base, options_.stack_size,
                     A64GuestMemory::kRead | A64GuestMemory::kWrite,
                     &diagnostic)) {
      return fail("failed to allocate guest stack: " + diagnostic);
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

  A64GuestCallResult Call(std::uint64_t guest_address,
                          const Arguments& arguments,
                          std::uint64_t instruction_budget) {
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

    callbacks_->BeginRun(budget, true);
    jit_->SetSP(options_.stack_base + options_.stack_size - 16U);
    for (std::size_t index = 0; index < arguments.size(); ++index) {
      jit_->SetRegister(index, arguments[index]);
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
    if (java_arguments.size() > 6) {
      return failure("JNI call supports at most six Java arguments in X2-X7");
    }

    std::size_t descriptor_argument_count = 0;
    std::string descriptor_error;
    if (!CountJniParameterTypes(signature, &descriptor_argument_count,
                                &descriptor_error)) {
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

    // JNI static-native ABI: X0=JNIEnv*, X1=jclass, X2-X7=Java arguments.
    Arguments arguments{};
    arguments[0] = jni_bridge_->jni_environment_address();
    arguments[1] = class_handle;
    for (std::size_t index = 0; index < java_arguments.size(); ++index) {
      arguments[index + 2] = java_arguments[index];
    }
    return Call(native->guest_address, arguments, instruction_budget);
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
