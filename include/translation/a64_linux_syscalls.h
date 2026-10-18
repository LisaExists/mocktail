// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#ifndef MOCKTAIL_TRANSLATION_A64_LINUX_SYSCALLS_H_
#define MOCKTAIL_TRANSLATION_A64_LINUX_SYSCALLS_H_

#include <array>
#include <cstdint>

namespace mocktail::translation {

class A64GuestMemory;

struct A64LinuxSyscallResult final {
  std::uint64_t value = 0;
  bool should_exit = false;
  std::uint32_t exit_status = 0;
};

// Small explicit AArch64 Linux syscall boundary. Guest pointers and syscalls
// are never forwarded directly to the host kernel. Unsupported syscalls return
// -ENOSYS rather than being silently passed through.
class A64LinuxSyscalls final {
 public:
  static constexpr std::uint64_t kClockGetTime = 113;
  static constexpr std::uint64_t kClockGetRes = 114;
  static constexpr std::uint64_t kSchedYield = 124;
  static constexpr std::uint64_t kGetPid = 172;
  static constexpr std::uint64_t kGetPpid = 173;
  static constexpr std::uint64_t kGetUid = 174;
  static constexpr std::uint64_t kGetEuid = 175;
  static constexpr std::uint64_t kGetGid = 176;
  static constexpr std::uint64_t kGetEgid = 177;
  static constexpr std::uint64_t kGetTid = 178;
  static constexpr std::uint64_t kUname = 160;
  static constexpr std::uint64_t kGetRandom = 278;

  // Synthetic unprivileged identity for the currently single-threaded guest.
  // These are guest IDs only; they are never used as host credentials.
  static constexpr std::uint64_t kGuestProcessId = 10000;
  static constexpr std::uint64_t kGuestParentProcessId = 1;
  static constexpr std::uint64_t kGuestThreadId = 10001;
  static constexpr std::uint64_t kGuestUid = 10000;
  static constexpr std::uint64_t kGuestGid = 10000;
  static constexpr std::uint64_t kExit = 93;
  static constexpr std::uint64_t kExitGroup = 94;
  static constexpr std::uint64_t kBrk = 214;
  static constexpr std::uint64_t kInitialProgramBreak = 0x6800000000ULL;
  static constexpr std::uint64_t kMaxProgramBreak =
      kInitialProgramBreak + 256U * 1024U * 1024U;
  static constexpr std::uint64_t kMunmap = 215;
  static constexpr std::uint64_t kMmap = 222;
  static constexpr std::uint64_t kMprotect = 226;
  static constexpr std::uint64_t kRtSigprocmask = 135;
  static constexpr std::uint64_t kSetTidAddress = 96;
  static constexpr std::uint64_t kSetRobustList = 99;
  static constexpr std::uint64_t kPrctl = 167;

  explicit A64LinuxSyscalls(A64GuestMemory& memory) noexcept;
  A64LinuxSyscallResult Dispatch(
      std::uint64_t number,
      const std::array<std::uint64_t, 6>& arguments);

 private:
  A64GuestMemory& memory_;
  std::uint64_t program_break_ = kInitialProgramBreak;
  // Linux AArch64 exposes a 64-signal mask as one 8-byte kernel sigset.
  // This state models the runtime's single guest execution context only.
  std::uint64_t guest_signal_mask_ = 0;
  // clear_child_tid is guest memory and is cleared on guest thread exit.
  std::uint64_t clear_child_tid_address_ = 0;
  // Stored for ABI bookkeeping only; robust-owner-death handling requires threads.
  std::uint64_t robust_list_head_address_ = 0;
  std::array<char, 16> guest_thread_name_ = {
      'm', 'o', 'c', 'k', 't', 'a', 'i', 'l', '-', 'g', 'u', 'e', 's', 't', '\0', '\0'};
  std::uint64_t guest_dumpable_ = 1;
  bool guest_no_new_privs_ = false;
};

}  // namespace mocktail::translation

#endif  // MOCKTAIL_TRANSLATION_A64_LINUX_SYSCALLS_H_
