// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_host_calls.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

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

std::uint32_t ReadU32(const mocktail::translation::A64GuestMemory& memory,
                      std::uint64_t address) {
  std::array<std::uint8_t, 4> bytes{};
  if (!memory.Read(address, bytes.data(), bytes.size())) return 0;
  return static_cast<std::uint32_t>(bytes[0]) |
         (static_cast<std::uint32_t>(bytes[1]) << 8U) |
         (static_cast<std::uint32_t>(bytes[2]) << 16U) |
         (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

std::uint32_t ReadSvcImmediate(
    const mocktail::translation::A64GuestMemory& memory,
    std::uint64_t stub) {
  // A64 encoding is 0xD4000001 | (imm16 << 5).
  return (ReadU32(memory, stub) >> 5U) & 0xffffU;
}

}  // namespace

int main() {
  using mocktail::translation::A64GuestHostCalls;
  using mocktail::translation::A64GuestMemory;

  A64GuestMemory memory(2U * 1024U * 1024U);
  constexpr std::uint64_t kTestBase = 0x20000000ULL;
  std::string error;
  Check(memory.Map(kTestBase, 2U * A64GuestMemory::kPageSize,
                   A64GuestMemory::kRead | A64GuestMemory::kWrite, &error),
        "maps an isolated guest data area");

  A64GuestHostCalls calls(memory);
  Check(calls.RegisterBuiltinLibc(&error),
        "registers the explicit guest-safe libc subset");
  Check(calls.Install(&error), "installs RX AArch64 SVC/RET thunks");

  const auto strlen_stub = calls.ResolveSymbol("strlen");
  const auto memcpy_stub = calls.ResolveSymbol("memcpy");
  const auto strcmp_stub = calls.ResolveSymbol("strcmp");
  const auto malloc_stub = calls.ResolveSymbol("malloc");
  const auto realloc_stub = calls.ResolveSymbol("realloc");
  const auto free_stub = calls.ResolveSymbol("free");
  Check(strlen_stub && memcpy_stub && strcmp_stub && malloc_stub &&
            realloc_stub && free_stub,
        "resolves registered symbols to guest stub addresses");

  if (!strlen_stub || !memcpy_stub || !strcmp_stub ||
      !malloc_stub || !realloc_stub || !free_stub) {
    std::cout << failures << " guest host-call test(s) failed\n";
    return 1;
  }

  Check(memory.IsExecutable(*strlen_stub, 8),
        "thunks live in executable guest memory");
  Check(!memory.Write(*strlen_stub, "x", 1),
        "thunk pages remain read-only to guest code");
  const auto strlen_svc = ReadSvcImmediate(memory, *strlen_stub);
  Check(strlen_svc >= A64GuestHostCalls::kFirstSvcImmediate &&
            calls.HandlesSvc(strlen_svc),
        "SVC immediate identifies a registered host call");

  constexpr std::uint64_t kSource = kTestBase + 0x100;
  constexpr std::uint64_t kDestination = kTestBase + A64GuestMemory::kPageSize + 0x100;
  constexpr char kMessage[] = "hello";
  Check(memory.Write(kSource, kMessage, sizeof(kMessage)),
        "writes a guest C string");

  A64GuestHostCalls::Arguments arguments{};
  arguments[0] = kSource;
  const auto length = calls.DispatchSvc(strlen_svc, arguments);
  Check(length.success && length.value == 5,
        "strlen reads a string through guest-memory validation");

  arguments = {};
  arguments[0] = kDestination;
  arguments[1] = kSource;
  arguments[2] = sizeof(kMessage);
  const auto copied = calls.DispatchSvc(ReadSvcImmediate(memory, *memcpy_stub),
                                        arguments);
  std::array<char, sizeof(kMessage)> copied_message{};
  Check(copied.success && copied.value == kDestination &&
            memory.Read(kDestination, copied_message.data(),
                        copied_message.size()) &&
            std::memcmp(copied_message.data(), kMessage, sizeof(kMessage)) == 0,
        "memcpy copies guest-to-guest without exposing host pointers");

  arguments = {};
  arguments[0] = kSource;
  arguments[1] = kDestination;
  const auto compared = calls.DispatchSvc(ReadSvcImmediate(memory, *strcmp_stub),
                                          arguments);
  Check(compared.success && compared.value == 0,
        "strcmp compares strings from guest memory");

  arguments = {};
  arguments[0] = kSource;
  arguments[1] = A64GuestHostCalls::kMaximumTransferBytes + 1ULL;
  const auto oversized = calls.DispatchSvc(
      ReadSvcImmediate(memory, *memcpy_stub), arguments);
  Check(!oversized.success &&
            oversized.error.find("transfer limit") != std::string::npos,
        "rejects unsafe oversized memory transfers");

  arguments = {};
  arguments[0] = 32;
  const auto allocated = calls.DispatchSvc(ReadSvcImmediate(memory, *malloc_stub),
                                           arguments);
  Check(allocated.success && allocated.value != 0 &&
            memory.IsMapped(allocated.value, 1),
        "malloc returns mapped guest memory rather than a host pointer");

  constexpr std::uint64_t kSentinel = 0x123456789ABCDEF0ULL;
  Check(memory.Write(allocated.value, &kSentinel, sizeof(kSentinel)),
        "guest allocation is writable");

  arguments = {};
  arguments[0] = allocated.value;
  arguments[1] = 128;
  const auto reallocated = calls.DispatchSvc(
      ReadSvcImmediate(memory, *realloc_stub), arguments);
  std::uint64_t preserved = 0;
  Check(reallocated.success && reallocated.value != 0 &&
            memory.Read(reallocated.value, &preserved, sizeof(preserved)) &&
            preserved == kSentinel && !memory.IsMapped(allocated.value, 1),
        "realloc preserves guest bytes and releases the previous mapping");

  arguments = {};
  arguments[0] = reallocated.value;
  const auto freed = calls.DispatchSvc(ReadSvcImmediate(memory, *free_stub),
                                       arguments);
  Check(freed.success && !memory.IsMapped(reallocated.value, 1),
        "free accepts and releases only a tracked guest allocation");

  const auto versioned = calls.ResolveVersionedSymbol(
      {"strlen", "LIBC_PRIVATE", "libc.so"});
  Check(!versioned,
        "refuses to satisfy unknown versioned imports with an unversioned thunk");

  const auto abort_stub = calls.ResolveSymbol("abort");
  Check(abort_stub.has_value(), "registers a diagnostic abort thunk");
  if (abort_stub) {
    const auto abort_result = calls.DispatchSvc(
        ReadSvcImmediate(memory, *abort_stub), {});
    Check(!abort_result.success,
          "guest abort fails explicitly without aborting the host process");
  }

  std::cout << failures << " guest host-call test(s) failed\n";
  return failures == 0 ? 0 : 1;
}
