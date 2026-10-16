// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_tls.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "translation/a64_guest_memory.h"

namespace {

int failures = 0;

void Check(bool condition, const std::string& label) {
  if (condition) {
    std::cout << "[PASS] " << label << '\n';
  } else {
    std::cerr << "[FAIL] " << label << '\n';
    ++failures;
  }
}

template <typename T>
T ReadValue(const mocktail::translation::A64GuestMemory& memory,
            std::uint64_t address) {
  T value{};
  static_cast<void>(memory.Read(address, &value, sizeof(value)));
  return value;
}

}  // namespace

int main() {
  using mocktail::translation::A64GuestMemory;
  using mocktail::translation::A64GuestModule;
  using mocktail::translation::A64GuestModuleSet;
  using mocktail::translation::A64GuestThreadTls;
  using mocktail::translation::A64GuestTlsRuntime;
  using mocktail::translation::A64TlsSegment;

  A64GuestMemory memory(8U * 1024U * 1024U);
  A64GuestModuleSet modules;
  A64GuestModule first;
  first.source_name = "libfirst.so";
  first.image.tls = A64TlsSegment{
      8, 16, 16, 0, 0,
      {0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
       0, 0, 0, 0, 0, 0, 0, 0}};
  modules.modules.push_back(std::move(first));

  A64GuestModule second;
  second.source_name = "libsecond.so";
  second.image.tls = A64TlsSegment{
      4, 8, 32, 0, 0, {0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0}};
  modules.modules.push_back(std::move(second));

  A64GuestTlsRuntime runtime(memory);
  std::string error;
  Check(runtime.Prepare(modules, &error), "prepares aligned static TLS layout");
  Check(error.empty(), "successful TLS preparation clears diagnostics");
  if (!runtime.prepared()) {
    std::cout << failures << " guest TLS test(s) failed\n";
    return 1;
  }

  Check(modules.modules[0].image.tls->module_id == 1 &&
            modules.modules[1].image.tls->module_id == 2,
        "assigns stable TLS module IDs");
  Check(modules.modules[0].image.tls->static_offset_from_tp >=
            A64GuestTlsRuntime::kTcbPrefixSize &&
            modules.modules[0].image.tls->static_offset_from_tp % 16 == 0 &&
            modules.modules[1].image.tls->static_offset_from_tp % 32 == 0,
        "places module TLS blocks after the TCB with required alignment");
  Check(runtime.total_tls_size() >=
            modules.modules[1].image.tls->static_offset_from_tp + 8,
        "tracks total static TLS size");

  A64GuestThreadTls thread_one;
  A64GuestThreadTls thread_two;
  Check(runtime.CreateThread(&thread_one, &error),
        "allocates and initializes first guest thread TLS");
  Check(runtime.CreateThread(&thread_two, &error),
        "allocates and initializes a second independent guest TLS block");
  Check(thread_one.valid() && thread_two.valid() &&
            thread_one.thread_pointer != thread_two.thread_pointer &&
            thread_one.tpidr_el0 == thread_one.thread_pointer,
        "returns independent guest TPIDR_EL0 values");
  Check(memory.IsMapped(thread_one.thread_pointer,
                        static_cast<std::size_t>(runtime.total_tls_size())),
        "maps the TP and its complete TLS range");

  const auto first_offset =
      modules.modules[0].image.tls->static_offset_from_tp;
  const auto second_offset =
      modules.modules[1].image.tls->static_offset_from_tp;
  Check(ReadValue<std::uint64_t>(memory, thread_one.thread_pointer + first_offset) ==
            0x1122334455667788ULL,
        "copies initialized TLS data for the first module");
  Check(ReadValue<std::uint64_t>(memory, thread_one.thread_pointer + first_offset + 8) ==
            0,
        "zero-initializes the first module TLS BSS");
  Check(ReadValue<std::uint32_t>(memory, thread_one.thread_pointer + second_offset) ==
            0xDEADBEEFU,
        "copies initialized TLS data for the second module");

  std::uint64_t resolved_tls_address = 0;
  Check(runtime.ResolveAddress(thread_one, 1, 0, &resolved_tls_address, &error) &&
            resolved_tls_address == thread_one.thread_pointer + first_offset,
        "resolves a preloaded module TLS index for a specific guest thread");
  Check(runtime.ResolveAddress(thread_two, 2, 4, &resolved_tls_address, &error) &&
            resolved_tls_address == thread_two.thread_pointer + second_offset + 4,
        "resolves module-relative offsets into another thread's TLS block");
  Check(!runtime.ResolveAddress(thread_one, 999, 0, &resolved_tls_address, &error),
        "rejects a TLS module ID outside the preloaded module set");
  Check(!runtime.ResolveAddress(thread_one, 1, 16, &resolved_tls_address, &error),
        "rejects a module-relative offset outside PT_TLS memory");

  const std::uint64_t changed = 0x0123456789ABCDEFULL;
  Check(memory.Write(thread_one.thread_pointer + first_offset, &changed,
                     sizeof(changed)),
        "allows a thread to update its TLS variable");
  Check(ReadValue<std::uint64_t>(memory, thread_two.thread_pointer + first_offset) ==
            0x1122334455667788ULL,
        "keeps TLS values isolated between guest threads");

  Check(!runtime.Prepare(modules, &error),
        "rejects re-preparing a layout after thread addresses could exist");
  const auto old_thread_pointer = thread_one.thread_pointer;
  Check(runtime.DestroyThread(&thread_one, &error),
        "releases the first guest TLS mapping");
  Check(!thread_one.valid() && !memory.IsMapped(old_thread_pointer, 1),
        "clears the thread descriptor after unmapping its TLS");
  Check(runtime.DestroyThread(&thread_two, &error),
        "releases the second guest TLS mapping");

  A64GuestTlsRuntime tiny_runtime(memory, 8);
  A64GuestModuleSet too_large;
  A64GuestModule large;
  large.source_name = "liblarge-tls.so";
  large.image.tls = A64TlsSegment{0, 64, 16, 0, 0,
                                  std::vector<std::uint8_t>(64, 0)};
  too_large.modules.push_back(std::move(large));
  Check(!tiny_runtime.Prepare(too_large, &error),
        "enforces the configured static TLS memory limit");

  std::cout << failures << " guest TLS test(s) failed\n";
  return failures == 0 ? 0 : 1;
}
