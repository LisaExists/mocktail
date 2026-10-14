// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>

#include "dynarmic/interface/A64/a64.h"
#include "dynarmic/interface/A64/config.h"

namespace {

using Address = Dynarmic::A64::VAddr;

class SmokeMemory final : public Dynarmic::A64::UserCallbacks {
 public:
  void Attach(Dynarmic::A64::Jit* jit) { jit_ = jit; }

  void Write32(Address address, std::uint32_t value) {
    for (unsigned int byte = 0; byte < 4; ++byte) {
      Write8(address + byte,
             static_cast<std::uint8_t>((value >> (byte * 8U)) & 0xffU));
    }
  }

  bool saw_breakpoint() const { return saw_breakpoint_; }
  const std::string& failure() const { return failure_; }

  std::uint8_t MemoryRead8(Address address) override {
    if (!Contains(address, 1)) return 0;
    return memory_[static_cast<std::size_t>(address)];
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
    Write8(address, value);
  }

  void MemoryWrite16(Address address, std::uint16_t value) override {
    Write8(address, static_cast<std::uint8_t>(value));
    Write8(address + 1, static_cast<std::uint8_t>(value >> 8U));
  }

  void MemoryWrite32(Address address, std::uint32_t value) override {
    Write32(address, value);
  }

  void MemoryWrite64(Address address, std::uint64_t value) override {
    MemoryWrite32(address, static_cast<std::uint32_t>(value));
    MemoryWrite32(address + 4, static_cast<std::uint32_t>(value >> 32U));
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
  bool Contains(Address address, std::size_t length) const {
    return address <= memory_.size() &&
           length <= memory_.size() - static_cast<std::size_t>(address);
  }

  void Write8(Address address, std::uint8_t value) {
    if (!Contains(address, 1)) {
      Fail("guest memory write out of bounds");
      return;
    }
    memory_[static_cast<std::size_t>(address)] = value;
  }

  void Fail(std::string message) {
    if (failure_.empty()) failure_ = std::move(message);
    Stop();
  }

  void Stop() {
    if (jit_ != nullptr) jit_->HaltExecution();
  }

  std::array<std::uint8_t, 4096> memory_{};
  Dynarmic::A64::Jit* jit_ = nullptr;
  std::uint64_t ticks_ = 0;
  bool saw_breakpoint_ = false;
  std::string failure_;
};

}  // namespace

int main() {
  SmokeMemory memory;
  // MOVZ X0, #42; BRK #0. This executes only toy instructions and never loads
  // a Roblox or Android payload.
  memory.Write32(0, 0xD2800540U);
  memory.Write32(4, 0xD4200000U);

  Dynarmic::A64::UserConfig config{};
  config.callbacks = &memory;
  config.enable_cycle_counting = false;
  Dynarmic::A64::Jit cpu{config};
  memory.Attach(&cpu);
  cpu.SetPC(0);

  static_cast<void>(cpu.Run());
  if (!memory.failure().empty()) {
    std::cerr << "AArch64 CPU smoke test failed: " << memory.failure() << '\n';
    return 1;
  }
  if (!memory.saw_breakpoint()) {
    std::cerr << "AArch64 CPU smoke test failed: BRK was not observed\n";
    return 1;
  }
  if (cpu.GetRegister(0) != 42) {
    std::cerr << "AArch64 CPU smoke test failed: X0 was "
              << cpu.GetRegister(0) << ", expected 42\n";
    return 1;
  }

  std::cout << "AArch64 CPU translation smoke test passed (X0=42)\n";
  return 0;
}
