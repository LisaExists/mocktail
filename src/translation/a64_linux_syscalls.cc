// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_linux_syscalls.h"

#include <cerrno>
#include <limits>
#include <string>

#include "translation/a64_guest_memory.h"

namespace mocktail::translation {
namespace {

constexpr std::uint64_t kProtRead = 0x1;
constexpr std::uint64_t kProtWrite = 0x2;
constexpr std::uint64_t kProtExec = 0x4;
constexpr std::uint64_t kProtMask = kProtRead | kProtWrite | kProtExec;

constexpr std::uint64_t kMapShared = 0x01;
constexpr std::uint64_t kMapPrivate = 0x02;
constexpr std::uint64_t kMapFixed = 0x10;
constexpr std::uint64_t kMapAnonymous = 0x20;
constexpr std::uint64_t kMapNoReserve = 0x4000;
constexpr std::uint64_t kMapStack = 0x20000;
constexpr std::uint64_t kMapFixedNoReplace = 0x100000;
constexpr std::uint64_t kMapAllowedFlags =
    kMapShared | kMapPrivate | kMapAnonymous | kMapNoReserve | kMapStack;

A64LinuxSyscallResult ErrorResult(int error) {
  A64LinuxSyscallResult result;
  result.value = static_cast<std::uint64_t>(
      -static_cast<std::int64_t>(error));
  return result;
}

bool RoundAddress(std::uint64_t address, std::uint64_t* rounded) noexcept {
  const auto mask = A64GuestMemory::kPageSize - 1;
  if (address > std::numeric_limits<std::uint64_t>::max() - mask) return false;
  *rounded = (address + mask) & ~mask;
  return true;
}

bool RoundLength(std::uint64_t length, std::uint64_t* rounded) noexcept {
  if (length == 0 ||
      length > std::numeric_limits<std::uint64_t>::max() -
                   (A64GuestMemory::kPageSize - 1)) {
    return false;
  }
  const auto mask = A64GuestMemory::kPageSize - 1;
  *rounded = (length + mask) & ~mask;
  return *rounded != 0;
}

bool ConvertProtection(std::uint64_t protection,
                       std::uint8_t* result) noexcept {
  if ((protection & ~kProtMask) != 0) return false;
  *result = 0;
  if ((protection & kProtRead) != 0) *result |= A64GuestMemory::kRead;
  if ((protection & kProtWrite) != 0) *result |= A64GuestMemory::kWrite;
  if ((protection & kProtExec) != 0) *result |= A64GuestMemory::kExecute;
  return true;
}

}  // namespace

A64LinuxSyscalls::A64LinuxSyscalls(A64GuestMemory& memory) noexcept
    : memory_(memory) {}

A64LinuxSyscallResult A64LinuxSyscalls::Dispatch(
    std::uint64_t number,
    const std::array<std::uint64_t, 6>& arguments) {
  switch (number) {
    case kBrk: {
      // Linux brk returns the current break on failure instead of -errno.
      // This private guest heap never maps or exposes host process memory.
      const auto requested = arguments[0];
      if (requested == 0) {
        A64LinuxSyscallResult result;
        result.value = program_break_;
        return result;
      }
      if (requested < kInitialProgramBreak || requested > kMaxProgramBreak) {
        A64LinuxSyscallResult result;
        result.value = program_break_;
        return result;
      }

      std::uint64_t old_mapping_end = 0;
      std::uint64_t new_mapping_end = 0;
      if (!RoundAddress(program_break_, &old_mapping_end) ||
          !RoundAddress(requested, &new_mapping_end)) {
        A64LinuxSyscallResult result;
        result.value = program_break_;
        return result;
      }

      std::string error;
      if (new_mapping_end > old_mapping_end) {
        if (!memory_.Map(old_mapping_end, new_mapping_end - old_mapping_end,
                         A64GuestMemory::kRead | A64GuestMemory::kWrite,
                         &error)) {
          A64LinuxSyscallResult result;
          result.value = program_break_;
          return result;
        }
      } else if (new_mapping_end < old_mapping_end) {
        if (!memory_.Unmap(new_mapping_end, old_mapping_end - new_mapping_end,
                           &error)) {
          A64LinuxSyscallResult result;
          result.value = program_break_;
          return result;
        }
      }

      program_break_ = requested;
      A64LinuxSyscallResult result;
      result.value = program_break_;
      return result;
    }

    case kMmap: {
      std::uint64_t rounded_size = 0;
      if (!RoundLength(arguments[1], &rounded_size)) {
        return ErrorResult(EINVAL);
      }
      std::uint8_t permissions = 0;
      if (!ConvertProtection(arguments[2], &permissions)) {
        return ErrorResult(EINVAL);
      }

      const auto flags = arguments[3];
      const auto sharing = flags & (kMapShared | kMapPrivate);
      if ((flags & kMapAnonymous) == 0) return ErrorResult(ENOSYS);
      if ((sharing != kMapShared && sharing != kMapPrivate) ||
          (flags & ~kMapAllowedFlags) != 0 ||
          (flags & (kMapFixed | kMapFixedNoReplace)) != 0 ||
          arguments[5] != 0) {
        return ErrorResult(EINVAL);
      }

      if (arguments[0] != 0 &&
          arguments[0] % A64GuestMemory::kPageSize == 0) {
        std::string ignored_error;
        if (memory_.Map(arguments[0], rounded_size, permissions,
                        &ignored_error)) {
          A64LinuxSyscallResult result;
          result.value = arguments[0];
          return result;
        }
      }

      std::uint64_t guest_address = 0;
      std::string error;
      if (!memory_.MapAnywhere(arguments[1], permissions, &guest_address,
                               &error)) {
        return ErrorResult(ENOMEM);
      }
      A64LinuxSyscallResult result;
      result.value = guest_address;
      return result;
    }

    case kMprotect: {
      if (arguments[0] % A64GuestMemory::kPageSize != 0) {
        return ErrorResult(EINVAL);
      }
      std::uint64_t rounded_size = 0;
      if (!RoundLength(arguments[1], &rounded_size)) {
        return ErrorResult(EINVAL);
      }
      std::uint8_t permissions = 0;
      if (!ConvertProtection(arguments[2], &permissions)) {
        return ErrorResult(EINVAL);
      }
      std::string error;
      if (!memory_.Protect(arguments[0], rounded_size, permissions, &error)) {
        if (error.find("unmapped page") != std::string::npos) {
          return ErrorResult(ENOMEM);
        }
        return ErrorResult(EINVAL);
      }
      A64LinuxSyscallResult result;
      result.value = 0;
      return result;
    }

    case kMunmap: {
      if (arguments[0] % A64GuestMemory::kPageSize != 0) {
        return ErrorResult(EINVAL);
      }
      std::uint64_t rounded_size = 0;
      if (!RoundLength(arguments[1], &rounded_size)) {
        return ErrorResult(EINVAL);
      }
      std::string error;
      if (!memory_.Unmap(arguments[0], rounded_size, &error)) {
        return ErrorResult(EINVAL);
      }
      A64LinuxSyscallResult result;
      result.value = 0;
      return result;
    }

    case kExit:
    case kExitGroup: {
      A64LinuxSyscallResult result;
      result.value = 0;
      result.should_exit = true;
      result.exit_status = static_cast<std::uint32_t>(arguments[0] & 0xffU);
      return result;
    }

    default:
      return ErrorResult(ENOSYS);
  }
}

}  // namespace mocktail::translation
