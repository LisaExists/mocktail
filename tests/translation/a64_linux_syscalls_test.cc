// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_linux_syscalls.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>

#include "translation/a64_guest_memory.h"

namespace {
int failures = 0;
void Check(bool condition, const std::string& name) {
  if (condition) std::cout << "[PASS] " << name << '\n';
  else { std::cerr << "[FAIL] " << name << '\n'; ++failures; }
}
bool IsError(const mocktail::translation::A64LinuxSyscallResult& result,
             int error) {
  return static_cast<std::int64_t>(result.value) ==
         -static_cast<std::int64_t>(error);
}
}  // namespace

int main() {
  using mocktail::translation::A64GuestMemory;
  using mocktail::translation::A64LinuxSyscalls;
  A64GuestMemory memory(1024U * 1024U);
  A64LinuxSyscalls syscalls(memory);
  const std::array<std::uint64_t, 6> empty_arguments{};
  const auto initial_break =
      syscalls.Dispatch(A64LinuxSyscalls::kBrk, empty_arguments);
  Check(initial_break.value == A64LinuxSyscalls::kInitialProgramBreak,
        "brk(0) reports the initial guest program break");

  const std::array<std::uint64_t, 6> grow_break_arguments{
      initial_break.value + A64GuestMemory::kPageSize, 0, 0, 0, 0, 0};
  const auto grown_break =
      syscalls.Dispatch(A64LinuxSyscalls::kBrk, grow_break_arguments);
  Check(grown_break.value == grow_break_arguments[0] &&
            memory.IsMapped(initial_break.value, A64GuestMemory::kPageSize),
        "brk grows the guest heap using private writable guest pages");
  const std::uint64_t heap_sentinel = 0x1122334455667788ULL;
  std::uint64_t heap_actual = 0;
  Check(memory.Write(initial_break.value, &heap_sentinel, sizeof(heap_sentinel)) &&
            memory.Read(initial_break.value, &heap_actual, sizeof(heap_actual)) &&
            heap_actual == heap_sentinel,
        "guest brk memory can be read and written without host pointers");

  const std::array<std::uint64_t, 6> shrink_break_arguments{
      initial_break.value, 0, 0, 0, 0, 0};
  const auto shrunk_break =
      syscalls.Dispatch(A64LinuxSyscalls::kBrk, shrink_break_arguments);
  Check(shrunk_break.value == initial_break.value &&
            !memory.IsMapped(initial_break.value, 1),
        "brk releases pages when shrinking the heap");
  const std::array<std::uint64_t, 6> invalid_break_arguments{
      std::numeric_limits<std::uint64_t>::max(), 0, 0, 0, 0, 0};
  const auto invalid_break =
      syscalls.Dispatch(A64LinuxSyscalls::kBrk, invalid_break_arguments);
  Check(invalid_break.value == initial_break.value,
        "brk refuses out-of-range values without changing the current break");

  const std::array<std::uint64_t, 6> mmap_arguments{
      0, 5000, 3, 0x22, std::numeric_limits<std::uint64_t>::max(), 0};
  const auto mapped = syscalls.Dispatch(A64LinuxSyscalls::kMmap, mmap_arguments);
  Check(static_cast<std::int64_t>(mapped.value) > 0,
        "mmap returns a positive guest address for anonymous private memory");
  if (static_cast<std::int64_t>(mapped.value) <= 0) return 1;

  const auto base = mapped.value;
  Check(memory.IsMapped(base, 2U * A64GuestMemory::kPageSize) &&
            memory.mapped_bytes() == 2U * A64GuestMemory::kPageSize,
        "mmap rounds the byte length to whole guest pages");
  const std::uint64_t value = 0x1122334455667788ULL;
  Check(memory.Write(base, &value, sizeof(value)),
        "guest mmap results are readable and writable");

  const std::array<std::uint64_t, 6> mprotect_arguments{base, 1, 1, 0, 0, 0};
  const auto protected_page =
      syscalls.Dispatch(A64LinuxSyscalls::kMprotect, mprotect_arguments);
  Check(protected_page.value == 0 &&
            !memory.Write(base, &value, sizeof(value)),
        "mprotect rounds the length and applies guest permissions");

  auto misaligned = mprotect_arguments;
  misaligned[0] = base + 1;
  Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kMprotect, misaligned),
                EINVAL),
        "mprotect rejects an unaligned guest address");

  const std::array<std::uint64_t, 6> invalid_flags{
      0, 4096, 3, 0x32, std::numeric_limits<std::uint64_t>::max(), 0};
  Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kMmap, invalid_flags),
                EINVAL),
        "mmap rejects MAP_FIXED rather than replacing existing guest memory");
  const std::array<std::uint64_t, 6> file_mapping{0, 4096, 1, 2, 0, 0};
  Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kMmap, file_mapping),
                ENOSYS),
        "file-backed mappings fail closed until a guest fd table exists");

  const std::array<std::uint64_t, 6> partial_unmap{
      base + A64GuestMemory::kPageSize, 1, 0, 0, 0, 0};
  const auto unmapped_second =
      syscalls.Dispatch(A64LinuxSyscalls::kMunmap, partial_unmap);
  Check(unmapped_second.value == 0 &&
            !memory.IsMapped(base + A64GuestMemory::kPageSize, 1) &&
            memory.IsMapped(base, 1),
        "munmap accepts non-page-sized lengths and removes only its pages");
  const std::array<std::uint64_t, 6> unmap_range{base, 8192, 0, 0, 0, 0};
  Check(syscalls.Dispatch(A64LinuxSyscalls::kMunmap, unmap_range).value == 0 &&
            memory.mapped_bytes() == 0,
        "munmap tolerates holes and releases remaining pages");

  const std::array<std::uint64_t, 6> invalid_length{0, 0, 0, 0, 0, 0};
  Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kMmap, invalid_length),
                EINVAL),
        "mmap rejects a zero length");
  Check(IsError(syscalls.Dispatch(999999, invalid_length), ENOSYS),
        "unsupported guest syscalls return -ENOSYS");
  const std::array<std::uint64_t, 6> exit_args{7, 0, 0, 0, 0, 0};
  const auto exit_result =
      syscalls.Dispatch(A64LinuxSyscalls::kExitGroup, exit_args);
  Check(exit_result.should_exit && exit_result.exit_status == 7,
        "exit_group requests guest-process termination without exiting the host");
  std::cout << failures << " guest syscall test(s) failed\n";
  return failures == 0 ? 0 : 1;
}
