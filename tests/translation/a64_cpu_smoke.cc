// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "dynarmic/interface/A64/a64.h"
#include "dynarmic/interface/A64/config.h"
#include "translation/a64_elf_loader.h"
#include "translation/a64_guest_memory.h"
#include "translation/a64_guest_module_loader.h"
#include "translation/a64_linux_syscalls.h"
#include "a64_test_elf.h"

namespace {

using Address = Dynarmic::A64::VAddr;
using mocktail::translation::A64LoadedImage;
using mocktail::translation::A64GuestMemory;

class SmokeMemory final : public Dynarmic::A64::UserCallbacks {
 public:
  explicit SmokeMemory(A64GuestMemory& memory)
      : memory_(memory), syscalls_(memory) {}

  void Attach(Dynarmic::A64::Jit* jit) { jit_ = jit; }

  bool saw_breakpoint() const { return saw_breakpoint_; }
  const std::string& failure() const { return failure_; }
  void SetReturnTrap(Address address, bool allow_any_breakpoint) {
    return_trap_ = address;
    allow_any_breakpoint_ = allow_any_breakpoint;
  }

  std::optional<std::uint32_t> MemoryReadCode(Address address) override {
    if (!memory_.IsExecutable(address, sizeof(std::uint32_t))) {
      Fail("guest instruction fetch outside executable memory");
      return std::nullopt;
    }
    return MemoryRead32(address);
  }

  std::uint8_t MemoryRead8(Address address) override {
    std::uint8_t value = 0;
    if (!memory_.Read(address, &value, sizeof(value))) {
      Fail("guest read outside readable mapped memory");
    }
    return value;
  }

  std::uint16_t MemoryRead16(Address address) override {
    return static_cast<std::uint16_t>(MemoryRead8(address)) |
           (static_cast<std::uint16_t>(MemoryRead8(address + 1)) << 8U);
  }

  std::uint32_t MemoryRead32(Address address) override {
    return static_cast<std::uint32_t>(MemoryRead16(address)) |
           (static_cast<std::uint32_t>(MemoryRead16(address + 2)) << 16U);
  }

  std::uint64_t MemoryRead64(Address address) override {
    return static_cast<std::uint64_t>(MemoryRead32(address)) |
           (static_cast<std::uint64_t>(MemoryRead32(address + 4)) << 32U);
  }

  Dynarmic::A64::Vector MemoryRead128(Address address) override {
    return {MemoryRead64(address), MemoryRead64(address + 8)};
  }

  void MemoryWrite8(Address address, std::uint8_t value) override {
    if (!memory_.Write(address, &value, sizeof(value))) {
      Fail("guest write outside writable mapped memory");
    }
  }

  void MemoryWrite16(Address address, std::uint16_t value) override {
    const std::uint8_t bytes[] = {
        static_cast<std::uint8_t>(value),
        static_cast<std::uint8_t>(value >> 8U),
    };
    if (!memory_.Write(address, bytes, sizeof(bytes))) {
      Fail("guest write outside writable mapped memory");
    }
  }

  void MemoryWrite32(Address address, std::uint32_t value) override {
    const std::uint8_t bytes[] = {
        static_cast<std::uint8_t>(value),
        static_cast<std::uint8_t>(value >> 8U),
        static_cast<std::uint8_t>(value >> 16U),
        static_cast<std::uint8_t>(value >> 24U),
    };
    if (!memory_.Write(address, bytes, sizeof(bytes))) {
      Fail("guest write outside writable mapped memory");
    }
  }

  void MemoryWrite64(Address address, std::uint64_t value) override {
    const std::uint8_t bytes[] = {
        static_cast<std::uint8_t>(value),
        static_cast<std::uint8_t>(value >> 8U),
        static_cast<std::uint8_t>(value >> 16U),
        static_cast<std::uint8_t>(value >> 24U),
        static_cast<std::uint8_t>(value >> 32U),
        static_cast<std::uint8_t>(value >> 40U),
        static_cast<std::uint8_t>(value >> 48U),
        static_cast<std::uint8_t>(value >> 56U),
    };
    if (!memory_.Write(address, bytes, sizeof(bytes))) {
      Fail("guest write outside writable mapped memory");
    }
  }

  void MemoryWrite128(Address address, Dynarmic::A64::Vector value) override {
    MemoryWrite64(address, value[0]);
    MemoryWrite64(address + 8, value[1]);
  }

  void InterpreterFallback(Address, std::size_t) override {
    Fail("Dynarmic requested interpreter fallback for the smoke instructions");
  }

  void CallSVC(std::uint32_t immediate) override {
    if (jit_ == nullptr) {
      Fail("Dynarmic invoked SVC before the JIT was attached");
      return;
    }
    if (immediate != 0) {
      jit_->SetRegister(0, static_cast<std::uint64_t>(
                               -static_cast<std::int64_t>(38)));  // -ENOSYS
      return;
    }
    const std::array<std::uint64_t, 6> arguments{
        jit_->GetRegister(0), jit_->GetRegister(1), jit_->GetRegister(2),
        jit_->GetRegister(3), jit_->GetRegister(4), jit_->GetRegister(5)};
    const auto result = syscalls_.Dispatch(jit_->GetRegister(8), arguments);
    jit_->SetRegister(0, result.value);
    if (result.should_exit) Stop();
  }

  void ExceptionRaised(Address address,
                       Dynarmic::A64::Exception exception) override {
    if (exception == Dynarmic::A64::Exception::Breakpoint) {
      if (allow_any_breakpoint_ || address == return_trap_) {
        saw_breakpoint_ = true;
      } else {
        Fail("guest hit BRK before returning through the call trap");
      }
      // Always stop for a breakpoint, even on a failure path. Otherwise the
      // same BRK can be redispatched indefinitely and mask the original error.
      Stop();
      return;
    }
    Fail("unexpected guest CPU exception");
  }

  void AddTicks(std::uint64_t ticks) override { ticks_ += ticks; }

  std::uint64_t GetTicksRemaining() override {
    return std::numeric_limits<std::uint64_t>::max() - ticks_;
  }

  std::uint64_t GetCNTPCT() override { return ticks_; }

 private:
  void Fail(std::string message) {
    if (failure_.empty()) failure_ = std::move(message);
    Stop();
  }

  void Stop() {
    if (jit_ != nullptr) jit_->HaltExecution();
  }

  A64GuestMemory& memory_;
  mocktail::translation::A64LinuxSyscalls syscalls_;
  Dynarmic::A64::Jit* jit_ = nullptr;
  std::uint64_t ticks_ = 0;
  Address return_trap_ = 0;
  bool allow_any_breakpoint_ = true;
  bool saw_breakpoint_ = false;
  std::string failure_;
};

}  // namespace

int main(int argc, char** argv) {
  using mocktail::translation::A64GuestModuleSource;
  using mocktail::translation::LoadA64GuestModuleSet;
  using mocktail::translation::test::BuildMinimalA64Elf;

  bool call_export = false;
  bool require_tls = false;
  std::string export_name;
  int first_path = 1;
  if (argc >= 2 && std::string(argv[1]) == "--symbol") {
    if (argc < 4) {
      std::cerr << "usage: mocktail_a64_translation_smoke [--symbol name] "
                   "[root-aarch64-elf [dependency-elf ...]]\n";
      return 2;
    }
    call_export = true;
    export_name = argv[2];
    first_path = 3;
  } else if (argc >= 2 && std::string(argv[1]) == "--require-tls") {
    if (argc < 3) {
      std::cerr << "usage: mocktail_a64_translation_smoke --require-tls "
                   "tls-aarch64-elf\n";
      return 2;
    }
    require_tls = true;
    first_path = 2;
  }

  std::vector<A64GuestModuleSource> sources;
  if (argc == 1) {
    sources.push_back(
        {"libmocktail-a64-synthetic.so", BuildMinimalA64Elf()});
  } else {
    for (int index = first_path; index < argc; ++index) {
      const std::string path = argv[index];
      std::ifstream input(path, std::ios::binary);
      if (!input) {
        std::cerr << "cannot open AArch64 ELF fixture: " << path << '\n';
        return 2;
      }
      std::vector<char> raw_bytes;
      raw_bytes.assign(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
      if (raw_bytes.empty()) {
        std::cerr << "AArch64 ELF fixture is empty: " << path << '\n';
        return 2;
      }
      const auto separator = path.find_last_of('/');
      const auto name = separator == std::string::npos
                            ? path
                            : path.substr(separator + 1);
      std::vector<std::uint8_t> bytes(raw_bytes.begin(), raw_bytes.end());
      sources.push_back({name, std::move(bytes)});
    }
    if (sources.empty()) {
      std::cerr << "no AArch64 ELF files were supplied\n";
      return 2;
    }
  }

  const auto loaded = LoadA64GuestModuleSet(sources, sources.front().name);
  if (!loaded) {
    std::cerr << "AArch64 guest module loading failed: " << loaded.error
              << '\n';
    return 1;
  }
  auto& modules = *loaded.modules;
  if (modules.root_index >= modules.modules.size()) {
    std::cerr << "AArch64 guest module loader returned an invalid root index\n";
    return 1;
  }
  const auto& image = modules.modules[modules.root_index].image;
  if (require_tls) {
    if (!image.tls) {
      std::cerr << "AArch64 ELF fixture does not contain a PT_TLS segment\n";
      return 1;
    }
    const auto& tls = *image.tls;
    constexpr std::uint64_t kExpectedTlsFileSize = 8;
    constexpr std::uint64_t kExpectedTlsMemorySize = 24;
    const std::array<std::uint8_t, 8> expected_initial{
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    if (tls.file_size != kExpectedTlsFileSize ||
        tls.memory_size != kExpectedTlsMemorySize ||
        tls.template_bytes.size() != kExpectedTlsMemorySize ||
        !std::equal(tls.template_bytes.begin(),
                    tls.template_bytes.begin() + expected_initial.size(),
                    expected_initial.begin()) ||
        std::any_of(tls.template_bytes.begin() + expected_initial.size(),
                    tls.template_bytes.end(),
                    [](std::uint8_t byte) { return byte != 0; })) {
      std::cerr << "PT_TLS template contents or sizes did not match the "
                   "linker-produced fixture expectations\n";
      return 1;
    }
    std::cout << "AArch64 PT_TLS template parsed (filesz="
              << tls.file_size << "; memsz=" << tls.memory_size
              << "; BSS zero-fill verified; execution model still unsupported)\n";
  }
  Address start_address = image.entry_point;
  if (call_export) {
    const auto address = modules.ResolveExportedSymbol(export_name);
    if (!address) {
      std::cerr << "AArch64 guest export was not found: " << export_name
                << '\n';
      return 1;
    }
    start_address = *address;
  } else if (start_address == 0) {
    std::cerr << "AArch64 root module has no executable entry point; "
                 "use --symbol to call an exported function\n";
    return 1;
  }
  if (!modules.modules[modules.root_index].image.IsExecutable(
          start_address, sizeof(std::uint32_t))) {
    bool in_other_module = false;
    for (const auto& module : modules.modules) {
      if (module.image.IsExecutable(start_address, sizeof(std::uint32_t))) {
        in_other_module = true;
        break;
      }
    }
    if (!in_other_module) {
      std::cerr << "AArch64 start address is not executable guest memory\n";
      return 1;
    }
  }

  A64GuestMemory memory;
  std::string memory_error;
  for (const auto& module : modules.modules) {
    if (!memory.MapImage(module.image, &memory_error)) {
      std::cerr << "guest image mapping failed for " << module.source_name
                << ": " << memory_error << '\n';
      return 1;
    }
  }

  constexpr std::uint64_t kStackBase = 0x7000000000ULL;
  constexpr std::uint64_t kStackSize = 2U * 1024U * 1024U;
  if (!memory.Map(kStackBase, kStackSize,
                  A64GuestMemory::kRead | A64GuestMemory::kWrite,
                  &memory_error)) {
    std::cerr << "guest stack mapping failed: " << memory_error << '\n';
    return 1;
  }

  constexpr std::uint64_t kReturnTrap = 0x7FFF000000ULL;
  if (call_export) {
    if (!memory.Map(kReturnTrap, A64GuestMemory::kPageSize,
                    A64GuestMemory::kRead | A64GuestMemory::kExecute,
                    &memory_error)) {
      std::cerr << "guest return-trap mapping failed: " << memory_error << '\n';
      return 1;
    }
    const std::uint8_t trap[] = {0x00, 0x00, 0x20, 0xD4};  // brk #0
    if (!memory.Initialize(kReturnTrap, trap, sizeof(trap))) {
      std::cerr << "guest return-trap initialization failed\n";
      return 1;
    }
  }

  SmokeMemory callbacks(memory);
  callbacks.SetReturnTrap(kReturnTrap, !call_export);
  Dynarmic::A64::UserConfig config{};
  config.callbacks = &callbacks;
  config.enable_cycle_counting = false;
  config.hook_hint_instructions = true;
  Dynarmic::A64::Jit cpu{config};
  callbacks.Attach(&cpu);
  cpu.SetSP(kStackBase + kStackSize - 16);
  const auto initial_stack_pointer = cpu.GetSP();
  if (call_export) {
    cpu.SetRegister(0, 41);
    cpu.SetRegister(30, kReturnTrap);
  }
  cpu.SetPC(start_address);

  static_cast<void>(cpu.Run());
  if (!callbacks.failure().empty()) {
    std::cerr << "AArch64 ELF/JIT integration smoke test failed: "
              << callbacks.failure() << '\n';
    return 1;
  }
  if (!callbacks.saw_breakpoint()) {
    std::cerr << "AArch64 ELF/JIT integration smoke test failed: "
                 "the stop breakpoint was not observed\n";
    return 1;
  }
  if (cpu.GetRegister(0) != 42) {
    std::cerr << "AArch64 guest result register X0 was " << cpu.GetRegister(0)
              << ", expected 42\n";
    return 1;
  }
  if (!call_export && cpu.GetRegister(1) != 42) {
    std::cerr << "AArch64 guest result register X1 was " << cpu.GetRegister(1)
              << ", expected 42\n";
    return 1;
  }
  if (cpu.GetSP() != initial_stack_pointer) {
    std::cerr << "AArch64 guest stack pointer was not restored\n";
    return 1;
  }

  std::cout << "AArch64 guest module/JIT smoke test passed (modules="
            << modules.modules.size() << "; mode="
            << (call_export ? "export" : "entry")
            << "; X0=42; stack preserved)\n";
  return 0;
}
