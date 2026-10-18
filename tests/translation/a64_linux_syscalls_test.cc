// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_linux_syscalls.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
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

  const std::array<std::uint64_t, 6> fixed_noreplace_collision{
      base, A64GuestMemory::kPageSize, 3, 0x100022,
      std::numeric_limits<std::uint64_t>::max(), 0};
  Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kMmap,
                                  fixed_noreplace_collision), EEXIST) &&
            memory.IsMapped(base, A64GuestMemory::kPageSize),
        "MAP_FIXED_NOREPLACE reports EEXIST without replacing an occupied page");
  auto fixed_noreplace_success = fixed_noreplace_collision;
  fixed_noreplace_success[0] = base + 0x10000;
  const auto fixed_noreplace_result =
      syscalls.Dispatch(A64LinuxSyscalls::kMmap, fixed_noreplace_success);
  Check(fixed_noreplace_result.value == fixed_noreplace_success[0] &&
            memory.IsMapped(fixed_noreplace_success[0],
                            A64GuestMemory::kPageSize),
        "MAP_FIXED_NOREPLACE maps an available aligned guest address exactly");
  if (fixed_noreplace_result.value == fixed_noreplace_success[0]) {
    const std::array<std::uint64_t, 6> cleanup_fixed_noreplace{
        fixed_noreplace_result.value, A64GuestMemory::kPageSize, 0, 0, 0, 0};
    static_cast<void>(syscalls.Dispatch(A64LinuxSyscalls::kMunmap,
                                        cleanup_fixed_noreplace));
  }
  auto misaligned_fixed_noreplace = fixed_noreplace_success;
  misaligned_fixed_noreplace[0] += 1;
  Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kMmap,
                                  misaligned_fixed_noreplace), EINVAL),
        "MAP_FIXED_NOREPLACE rejects unaligned guest addresses");

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

  constexpr std::uint64_t kGuestSyscallScratch = 0x500000ULL;
  std::string memory_error;
  const bool scratch_mapped = memory.Map(
      kGuestSyscallScratch, A64GuestMemory::kPageSize,
      A64GuestMemory::kRead | A64GuestMemory::kWrite, &memory_error);
  Check(scratch_mapped, "maps scratch memory for guest clock and uname calls");
  if (scratch_mapped) {
    const std::array<std::uint64_t, 6> random_arguments{
        kGuestSyscallScratch, 32, 0, 0, 0, 0};
    const auto random_result =
        syscalls.Dispatch(A64LinuxSyscalls::kGetRandom, random_arguments);
    std::array<std::uint8_t, 32> random_bytes{};
    const bool read_random = memory.Read(
        kGuestSyscallScratch, random_bytes.data(), random_bytes.size());
    bool any_random_byte = false;
    for (const auto byte : random_bytes) any_random_byte |= byte != 0;
#if defined(__linux__)
    Check(random_result.value == random_bytes.size() && read_random &&
              any_random_byte,
          "getrandom fills guest memory using the host kernel's random source");
    auto invalid_random_flags = random_arguments;
    invalid_random_flags[2] = 0x80000000ULL;
    Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kGetRandom,
                                    invalid_random_flags), EINVAL),
          "getrandom rejects unsupported flag bits");
    auto invalid_random_pointer = random_arguments;
    invalid_random_pointer[0] = 0x900000ULL;
    Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kGetRandom,
                                    invalid_random_pointer), EFAULT),
          "getrandom rejects an unmapped guest output buffer");
#else
    Check(IsError(random_result, ENOSYS),
          "getrandom fails closed on hosts without a supported secure source");
#endif

    const std::array<std::uint64_t, 6> monotonic_clock{
        1, kGuestSyscallScratch, 0, 0, 0, 0};
    const auto clock_result =
        syscalls.Dispatch(A64LinuxSyscalls::kClockGetTime, monotonic_clock);
    struct GuestTimespec final {
      std::int64_t seconds;
      std::int64_t nanoseconds;
    } guest_time{};
    const bool read_time =
        memory.Read(kGuestSyscallScratch, &guest_time, sizeof(guest_time));
    Check(clock_result.value == 0 && read_time &&
              guest_time.seconds >= 0 &&
              guest_time.nanoseconds >= 0 &&
              guest_time.nanoseconds < 1000000000,
          "clock_gettime writes a valid AArch64 timespec to guest memory");
    auto invalid_clock = monotonic_clock;
    invalid_clock[0] = 10;  // Reserved guest clock ID.
    Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kClockGetTime,
                                    invalid_clock), EINVAL),
          "clock_gettime rejects unsupported guest clock IDs");
    auto invalid_clock_pointer = monotonic_clock;
    invalid_clock_pointer[1] = 0x900000ULL;
    Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kClockGetTime,
                                    invalid_clock_pointer), EFAULT),
          "clock_gettime rejects an unmapped guest timespec pointer");

    // Exercise the kernel's 8-byte AArch64 rt_sigprocmask ABI. This
    // virtual mask is private to A64LinuxSyscalls and must never alter the
    // host process's signal mask.
    constexpr std::uint64_t kSignalOne = std::uint64_t{1} << 0U;
    constexpr std::uint64_t kSignalTwo = std::uint64_t{1} << 1U;
    constexpr std::uint64_t kSignalThree = std::uint64_t{1} << 2U;
    constexpr std::uint64_t kSignalKill = std::uint64_t{1} << 8U;
    constexpr std::uint64_t kSignalStop = std::uint64_t{1} << 18U;
    std::uint64_t requested_signal_mask =
        kSignalOne | kSignalTwo | kSignalKill | kSignalStop;
    const bool wrote_requested_mask = memory.Write(
        kGuestSyscallScratch, &requested_signal_mask,
        sizeof(requested_signal_mask));
    const std::array<std::uint64_t, 6> set_guest_mask{
        2, kGuestSyscallScratch, kGuestSyscallScratch + 8,
        sizeof(std::uint64_t), 0, 0};
    const auto set_mask_result =
        syscalls.Dispatch(A64LinuxSyscalls::kRtSigprocmask, set_guest_mask);
    std::uint64_t previous_signal_mask = UINT64_MAX;
    const bool read_previous_mask = memory.Read(
        kGuestSyscallScratch + 8, &previous_signal_mask,
        sizeof(previous_signal_mask));
    Check(wrote_requested_mask && set_mask_result.value == 0 &&
              read_previous_mask && previous_signal_mask == 0,
          "rt_sigprocmask sets a guest-only signal mask and returns the prior mask");

    const std::array<std::uint64_t, 6> query_guest_mask{
        0, 0, kGuestSyscallScratch + 16, sizeof(std::uint64_t), 0, 0};
    const auto query_mask_result =
        syscalls.Dispatch(A64LinuxSyscalls::kRtSigprocmask, query_guest_mask);
    std::uint64_t current_signal_mask = 0;
    const bool read_current_mask = memory.Read(
        kGuestSyscallScratch + 16, &current_signal_mask,
        sizeof(current_signal_mask));
    Check(query_mask_result.value == 0 && read_current_mask &&
              current_signal_mask == (kSignalOne | kSignalTwo),
          "rt_sigprocmask never blocks SIGKILL or SIGSTOP");

    requested_signal_mask = kSignalThree | kSignalKill;
    const bool wrote_block_mask = memory.Write(
        kGuestSyscallScratch, &requested_signal_mask,
        sizeof(requested_signal_mask));
    auto block_guest_mask = set_guest_mask;
    block_guest_mask[0] = 0;  // SIG_BLOCK
    const auto block_mask_result =
        syscalls.Dispatch(A64LinuxSyscalls::kRtSigprocmask, block_guest_mask);
    const auto query_after_block =
        syscalls.Dispatch(A64LinuxSyscalls::kRtSigprocmask, query_guest_mask);
    current_signal_mask = 0;
    const bool read_after_block = memory.Read(
        kGuestSyscallScratch + 16, &current_signal_mask,
        sizeof(current_signal_mask));
    Check(wrote_block_mask && block_mask_result.value == 0 &&
              query_after_block.value == 0 && read_after_block &&
              current_signal_mask == (kSignalOne | kSignalTwo | kSignalThree),
          "rt_sigprocmask SIG_BLOCK adds permitted signals without blocking SIGKILL");

    requested_signal_mask = kSignalOne;
    const bool wrote_unblock_mask = memory.Write(
        kGuestSyscallScratch, &requested_signal_mask,
        sizeof(requested_signal_mask));
    auto unblock_guest_mask = set_guest_mask;
    unblock_guest_mask[0] = 1;  // SIG_UNBLOCK
    const auto unblock_mask_result =
        syscalls.Dispatch(A64LinuxSyscalls::kRtSigprocmask, unblock_guest_mask);
    const auto query_after_unblock =
        syscalls.Dispatch(A64LinuxSyscalls::kRtSigprocmask, query_guest_mask);
    current_signal_mask = 0;
    const bool read_after_unblock = memory.Read(
        kGuestSyscallScratch + 16, &current_signal_mask,
        sizeof(current_signal_mask));
    Check(wrote_unblock_mask && unblock_mask_result.value == 0 &&
              query_after_unblock.value == 0 && read_after_unblock &&
              current_signal_mask == (kSignalTwo | kSignalThree),
          "rt_sigprocmask SIG_UNBLOCK removes only the requested guest signal");

    auto invalid_sigset_size = set_guest_mask;
    invalid_sigset_size[3] = 16;
    Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kRtSigprocmask,
                                    invalid_sigset_size), EINVAL),
          "rt_sigprocmask requires the 8-byte AArch64 kernel sigset size");
    auto invalid_signal_set = set_guest_mask;
    invalid_signal_set[1] = 0x900000ULL;
    Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kRtSigprocmask,
                                    invalid_signal_set), EFAULT),
          "rt_sigprocmask rejects an unreadable guest signal set");
    auto invalid_old_signal_set = set_guest_mask;
    invalid_old_signal_set[2] = 0x900000ULL;
    Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kRtSigprocmask,
                                    invalid_old_signal_set), EFAULT),
          "rt_sigprocmask rejects an unwritable guest old-mask buffer");

    const std::array<std::uint64_t, 6> uname_arguments{
        kGuestSyscallScratch, 0, 0, 0, 0, 0};
    const auto uname_result =
        syscalls.Dispatch(A64LinuxSyscalls::kUname, uname_arguments);
    char guest_sysname[65]{};
    char guest_machine[65]{};
    const bool read_sysname = memory.Read(
        kGuestSyscallScratch, guest_sysname, sizeof(guest_sysname));
    const bool read_machine = memory.Read(
        kGuestSyscallScratch + 4 * 65, guest_machine, sizeof(guest_machine));
    Check(uname_result.value == 0 && read_sysname && read_machine &&
              std::string(guest_sysname) == "Linux" &&
              std::string(guest_machine) == "aarch64",
          "uname reports Linux and the AArch64 guest architecture");
    auto invalid_uname = uname_arguments;
    invalid_uname[0] = 0x900000ULL;
    Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kUname, invalid_uname),
                  EFAULT),
          "uname rejects an unmapped guest output pointer");

    constexpr std::uint64_t kClearTidAddress = kGuestSyscallScratch + 64;
    const std::uint32_t initial_tid_word = 0xAABBCCDDU;
    const bool initialized_tid_word = memory.Write(
        kClearTidAddress, &initial_tid_word, sizeof(initial_tid_word));
    const std::array<std::uint64_t, 6> set_tid_address{
        kClearTidAddress, 0, 0, 0, 0, 0};
    const auto set_tid_result =
        syscalls.Dispatch(A64LinuxSyscalls::kSetTidAddress, set_tid_address);
    Check(initialized_tid_word &&
              set_tid_result.value == A64LinuxSyscalls::kGuestThreadId,
          "set_tid_address returns the synthetic guest TID without exposing it to the host");

    const std::array<std::uint64_t, 6> set_robust_list{
        kGuestSyscallScratch, 3U * sizeof(std::uint64_t), 0, 0, 0, 0};
    Check(syscalls.Dispatch(A64LinuxSyscalls::kSetRobustList,
                            set_robust_list).value == 0,
          "set_robust_list accepts the AArch64 kernel robust-list-head size");
    auto invalid_robust_list = set_robust_list;
    invalid_robust_list[1] -= 8;
    Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kSetRobustList,
                                    invalid_robust_list), EINVAL),
          "set_robust_list rejects an incorrect structure size");
  }

  const auto guest_pid = syscalls.Dispatch(A64LinuxSyscalls::kGetPid, empty_arguments);
  const auto guest_ppid = syscalls.Dispatch(A64LinuxSyscalls::kGetPpid, empty_arguments);
  const auto guest_uid = syscalls.Dispatch(A64LinuxSyscalls::kGetUid, empty_arguments);
  const auto guest_euid = syscalls.Dispatch(A64LinuxSyscalls::kGetEuid, empty_arguments);
  const auto guest_gid = syscalls.Dispatch(A64LinuxSyscalls::kGetGid, empty_arguments);
  const auto guest_egid = syscalls.Dispatch(A64LinuxSyscalls::kGetEgid, empty_arguments);
  const auto guest_tid = syscalls.Dispatch(A64LinuxSyscalls::kGetTid, empty_arguments);
  Check(guest_pid.value == A64LinuxSyscalls::kGuestProcessId &&
            guest_ppid.value == A64LinuxSyscalls::kGuestParentProcessId &&
            guest_uid.value == A64LinuxSyscalls::kGuestUid &&
            guest_euid.value == A64LinuxSyscalls::kGuestUid &&
            guest_gid.value == A64LinuxSyscalls::kGuestGid &&
            guest_egid.value == A64LinuxSyscalls::kGuestGid &&
            guest_tid.value == A64LinuxSyscalls::kGuestThreadId,
        "process and credential syscalls expose the bounded unprivileged guest identity");
  Check(syscalls.Dispatch(A64LinuxSyscalls::kSchedYield, empty_arguments).value == 0,
        "sched_yield is a safe no-op until guest thread scheduling exists");

  if (memory.IsMapped(kGuestSyscallScratch, A64GuestMemory::kPageSize)) {
    const std::array<std::uint64_t, 6> clock_resolution{
        1, kGuestSyscallScratch, 0, 0, 0, 0};
    const auto resolution_result =
        syscalls.Dispatch(A64LinuxSyscalls::kClockGetRes, clock_resolution);
    struct GuestTimespec final {
      std::int64_t seconds;
      std::int64_t nanoseconds;
    } resolution{};
    const bool read_resolution = memory.Read(
        kGuestSyscallScratch, &resolution, sizeof(resolution));
    Check(resolution_result.value == 0 && read_resolution &&
              resolution.seconds >= 0 && resolution.nanoseconds >= 0 &&
              resolution.nanoseconds < 1000000000,
          "clock_getres writes a valid guest timespec");
    auto invalid_resolution = clock_resolution;
    invalid_resolution[0] = 10;
    Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kClockGetRes,
                                    invalid_resolution), EINVAL),
          "clock_getres rejects unsupported guest clock IDs");
    auto invalid_resolution_pointer = clock_resolution;
    invalid_resolution_pointer[1] = 0x900000ULL;
    Check(IsError(syscalls.Dispatch(A64LinuxSyscalls::kClockGetRes,
                                    invalid_resolution_pointer), EFAULT),
          "clock_getres validates a non-null guest timespec pointer");
    auto null_resolution = clock_resolution;
    null_resolution[1] = 0;
    Check(syscalls.Dispatch(A64LinuxSyscalls::kClockGetRes, null_resolution).value == 0,
          "clock_getres permits a null output pointer");
  }

  Check(IsError(syscalls.Dispatch(999999, invalid_length), ENOSYS),
        "unsupported guest syscalls return -ENOSYS");
  const std::array<std::uint64_t, 6> exit_args{7, 0, 0, 0, 0, 0};
  const auto exit_result =
      syscalls.Dispatch(A64LinuxSyscalls::kExitGroup, exit_args);
  Check(exit_result.should_exit && exit_result.exit_status == 7,
        "exit_group requests guest-process termination without exiting the host");
  std::uint32_t cleared_tid_word = UINT32_MAX;
  const bool read_cleared_tid = memory.Read(
      0x500040ULL, &cleared_tid_word, sizeof(cleared_tid_word));
  Check(read_cleared_tid && cleared_tid_word == 0,
        "guest thread exit clears the registered clear_child_tid word in guest memory");
  std::cout << failures << " guest syscall test(s) failed\n";
  return failures == 0 ? 0 : 1;
}
