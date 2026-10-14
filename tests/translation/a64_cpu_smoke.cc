// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

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
#include "a64_test_elf.h"

namespace {

using Address = Dynarmic::A64::VAddr;
using mocktail::translation::A64LoadedImage;

class SmokeMemory final : public Dynarmic::A64::UserCallbacks {
 public:
  explicit SmokeMemory(A64GuestMemory& memory) : memory_(memory) {}

  void Attach(Dynarmic::A64::Jit* jit) { jit_ = jit; }

  bool saw_breakpoint() const { return saw_breakpoint_; }
  const std::string& failure() const { return failure_; }

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
      Fail("guest instruction/data read outside a loaded PT_LOAD segment");
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
      Fail("guest write was outside a writable PT_LOAD segment");
    }
  }

  void MemoryWrite16(Address address, std::uint16_t value) override {
    const std::uint8_t bytes[] = {
        static_cast<std::uint8_t>(value),
        static_cast<std::uint8_t>(value >> 8U),
    };
    if (!memory_.Write(address, bytes, sizeof(bytes))) {
      Fail("guest write was outside a writable PT_LOAD segment");
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
      Fail("guest write was outside a writable PT_LOAD segment");
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
      Fail("guest write was outside a writable PT_LOAD segment");
    }
  }

  void MemoryWrite128(Address address, Dynarmic::A64::Vector value) override {
    MemoryWrite64(address, value[0]);
    MemoryWrite64(address + 8, value[1]);
  }

  void InterpreterFallback(Address, std::size_t) override {
    Fail("Dynarmic requested interpreter fallback for the smoke instructions");
  }

  void CallSVC(std::uint32_t) override {
    Fail("unexpected SVC in the smoke program");
  }

  void ExceptionRaised(Address, Dynarmic::A64::Exception exception) override {
    if (exception == Dynarmic::A64::Exception::Breakpoint) {
      saw_breakpoint_ = true;
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
  Dynarmic::A64::Jit* jit_ = nullptr;
  std::uint64_t ticks_ = 0;
  bool saw_breakpoint_ = false;
  std::string failure_;
};

}  // namespace

int main(int argc, char** argv) {
  if (argc > 2) {
    std::cerr << "usage: mocktail_a64_translation_smoke [aarch64-elf]\n";
    return 2;
  }

  std::vector<std::uint8_t> elf_bytes;
  if (argc == 2) {
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
      std::cerr << "cannot open AArch64 ELF fixture: " << argv[1] << '\n';
      return 2;
    }
    std::vector<char> raw_bytes;
    raw_bytes.assign(std::istreambuf_iterator<char>(input),
                     std::istreambuf_iterator<char>());
    elf_bytes.assign(raw_bytes.begin(), raw_bytes.end());
  } else {
    elf_bytes = mocktail::translation::test::BuildMinimalA64Elf();
  }

  auto load_result = mocktail::translation::LoadA64Elf(elf_bytes);
  if (!load_result) {
    std::cerr << "AArch64 ELF load failed: " << load_result.error << '\n';
    return 1;
  }

  auto& image = *load_result.image;
  A64GuestMemory memory;
  std::string memory_error;
  if (!memory.MapImage(image, &memory_error)) {
    std::cerr << "guest ELF mapping failed: " << memory_error << '\n';
    return 1;
  }
  constexpr std::uint64_t kStackBase = 0x7000000000ULL;
  constexpr std::uint64_t kStackSize = 2U * 1024U * 1024U;
  if (!memory.Map(kStackBase, kStackSize,
                  A64GuestMemory::kRead | A64GuestMemory::kWrite,
                  &memory_error)) {
    std::cerr << "guest stack mapping failed: " << memory_error << '\n';
    return 1;
  }
  SmokeMemory callbacks(memory);

  Dynarmic::A64::UserConfig config{};
  config.callbacks = &callbacks;
  config.enable_cycle_counting = false;
  config.hook_hint_instructions = true;
  Dynarmic::A64::Jit cpu{config};
  callbacks.Attach(&cpu);
  cpu.SetSP(kStackBase + kStackSize - 16);
  const auto initial_stack_pointer = cpu.GetSP();
  cpu.SetPC(image.entry_point);

  static_cast<void>(cpu.Run());
  if (!memory.failure().empty()) {
    std::cerr << "AArch64 ELF/JIT integration smoke test failed: "
              << memory.failure() << '\n';
    return 1;
  }
  if (!memory.saw_breakpoint()) {
    std::cerr << "AArch64 ELF/JIT integration smoke test failed: "
                 "BRK was not observed\n";
    return 1;
  }
  if (cpu.GetRegister(0) != 42) {
    std::cerr << "AArch64 ELF/JIT integration smoke test failed: X0 was "
              << cpu.GetRegister(0) << ", expected 42\n";
    return 1;
  }

  if (cpu.GetRegister(1) != 42) {
    std::cerr << "AArch64 guest stack round-trip failed: X1 was "
              << cpu.GetRegister(1) << ", expected 42\n";
    return 1;
  }
  if (cpu.GetSP() != initial_stack_pointer) {
    std::cerr << "AArch64 guest stack pointer was not restored\n";
    return 1;
  }

  std::cout << "AArch64 ELF/JIT smoke test passed (X0=X1=42; guest stack works)\n";
  return 0;
}
