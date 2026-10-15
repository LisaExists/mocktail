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
  static constexpr std::uint64_t kExit = 93;
  static constexpr std::uint64_t kExitGroup = 94;
  static constexpr std::uint64_t kBrk = 214;
  static constexpr std::uint64_t kInitialProgramBreak = 0x6800000000ULL;
  static constexpr std::uint64_t kMaxProgramBreak =
      kInitialProgramBreak + 256U * 1024U * 1024U;
  static constexpr std::uint64_t kMunmap = 215;
  static constexpr std::uint64_t kMmap = 222;
  static constexpr std::uint64_t kMprotect = 226;

  explicit A64LinuxSyscalls(A64GuestMemory& memory) noexcept;
  A64LinuxSyscallResult Dispatch(
      std::uint64_t number,
      const std::array<std::uint64_t, 6>& arguments);

 private:
  A64GuestMemory& memory_;
  std::uint64_t program_break_ = kInitialProgramBreak;
};

}  // namespace mocktail::translation

#endif  // MOCKTAIL_TRANSLATION_A64_LINUX_SYSCALLS_H_
