// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <utility>

#include "dynarmic/interface/A64/a64.h"
#include "dynarmic/interface/A64/config.h"
#include "translation/a64_elf_loader.h"
#include "a64_test_elf.h"

namespace {

using Address = Dynarmic::A64::VAddr;
using mocktail::translation::A64LoadedImage;

class SmokeMemory final : public Dynarmic::A64::UserCallbacks {
 public:
  explicit SmokeMemory(A64LoadedImage& image) : image_(image) {}

  void Attach(Dynarmic::A64::Jit* jit) { jit_ = jit; }

  bool saw_breakpoint() const { return saw_breakpoint_; }
  const std::string& failure() const { return failure_; }

  std::uint8_t MemoryRead8(Address address) override {
    std::uint8_t value = 0;
    if (!image_.Read(address, &value, sizeof(value))) {
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
    if (!image_.Write(address, &value, sizeof(value))) {
      Fail("guest write was outside a writable PT_LOAD segment");
    }
  }

  void MemoryWrite16(Address address, std::uint16_t value) override {
    const std::uint8_t bytes[] = {
        static_cast<std::uint8_t>(value),
        static_cast<std::uint8_t>(value >> 8U),
    };
    if (!image_.Write(address, bytes, sizeof(bytes))) {
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
    if (!image_.Write(address, bytes, sizeof(bytes))) {
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
    if (!image_.Write(address, bytes, sizeof(bytes))) {
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

  A64LoadedImage& image_;
  Dynarmic::A64::Jit* jit_ = nullptr;
  std::uint64_t ticks_ = 0;
  bool saw_breakpoint_ = false;
  std::string failure_;
};

}  // namespace

int main() {
  auto load_result = mocktail::translation::LoadA64Elf(
      mocktail::translation::test::BuildMinimalA64Elf());
  if (!load_result) {
    std::cerr << "AArch64 ELF load failed: " << load_result.error << '\n';
    return 1;
  }

  auto& image = *load_result.image;
  SmokeMemory memory(image);

  Dynarmic::A64::UserConfig config{};
  config.callbacks = &memory;
  config.enable_cycle_counting = false;
  config.hook_hint_instructions = true;
  Dynarmic::A64::Jit cpu{config};
  memory.Attach(&cpu);
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

  std::cout << "AArch64 ELF/JIT integration smoke test passed (X0=42)\n";
  return 0;
}
