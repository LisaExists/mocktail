// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_linux_syscalls.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <sched.h>
#include <string>
#include <time.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

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

bool ConvertGuestClockId(std::uint64_t guest_id, clockid_t* host_id) noexcept {
  switch (guest_id) {
    case 0:
      *host_id = CLOCK_REALTIME;
      return true;
    case 1:
      *host_id = CLOCK_MONOTONIC;
      return true;
#ifdef CLOCK_PROCESS_CPUTIME_ID
    case 2:
      *host_id = CLOCK_PROCESS_CPUTIME_ID;
      return true;
#endif
#ifdef CLOCK_THREAD_CPUTIME_ID
    case 3:
      *host_id = CLOCK_THREAD_CPUTIME_ID;
      return true;
#endif
#ifdef CLOCK_MONOTONIC_RAW
    case 4:
      *host_id = CLOCK_MONOTONIC_RAW;
      return true;
#endif
#ifdef CLOCK_REALTIME_COARSE
    case 5:
      *host_id = CLOCK_REALTIME_COARSE;
      return true;
#endif
#ifdef CLOCK_MONOTONIC_COARSE
    case 6:
      *host_id = CLOCK_MONOTONIC_COARSE;
      return true;
#endif
#ifdef CLOCK_BOOTTIME
    case 7:
      *host_id = CLOCK_BOOTTIME;
      return true;
#endif
#ifdef CLOCK_REALTIME_ALARM
    case 8:
      *host_id = CLOCK_REALTIME_ALARM;
      return true;
#endif
#ifdef CLOCK_BOOTTIME_ALARM
    case 9:
      *host_id = CLOCK_BOOTTIME_ALARM;
      return true;
#endif
#ifdef CLOCK_TAI
    case 11:
      *host_id = CLOCK_TAI;
      return true;
#endif
    default:
      return false;
  }
}

struct A64GuestTimespec final {
  std::int64_t seconds = 0;
  std::int64_t nanoseconds = 0;
};

struct A64GuestUtsname final {
  char sysname[65]{};
  char nodename[65]{};
  char release[65]{};
  char version[65]{};
  char machine[65]{};
  char domainname[65]{};
};

void SetUtsField(char* field, std::size_t field_size,
                 const char* value) noexcept {
  if (field_size == 0) return;
  const auto length = std::min(std::strlen(value), field_size - 1);
  std::memcpy(field, value, length);
  field[length] = '\0';
}

}  // namespace

A64LinuxSyscalls::A64LinuxSyscalls(A64GuestMemory& memory) noexcept
    : memory_(memory) {}

A64LinuxSyscallResult A64LinuxSyscalls::Dispatch(
    std::uint64_t number,
    const std::array<std::uint64_t, 6>& arguments) {
  switch (number) {
    case kGetRandom: {
#if defined(__linux__)
      constexpr std::uint64_t kMaximumGetRandomReturn = 32ULL * 1024ULL * 1024ULL;
      constexpr std::uint64_t kAllowedGetRandomFlags = 0x1ULL | 0x2ULL | 0x4ULL;
      const auto requested = arguments[1];
      const auto flags = arguments[2];
      if ((flags & ~kAllowedGetRandomFlags) != 0 ||
          flags > std::numeric_limits<unsigned int>::max()) {
        return ErrorResult(EINVAL);
      }
      if (requested == 0) {
        A64LinuxSyscallResult result;
        result.value = 0;
        return result;
      }

      // Linux returns at most 32 MiB from one getrandom call. Use bounded
      // chunks and copy only through guest memory, never a guest pointer cast.
      const auto target = std::min(requested, kMaximumGetRandomReturn);
      std::array<std::uint8_t, 4096> buffer{};
      std::uint64_t copied = 0;
      while (copied < target) {
        const auto amount = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), target - copied));
        const auto count = ::getrandom(buffer.data(), amount,
                                       static_cast<unsigned int>(flags));
        if (count < 0) {
          if (copied != 0) {
            A64LinuxSyscallResult result;
            result.value = copied;
            return result;
          }
          return ErrorResult(errno == 0 ? EIO : errno);
        }
        if (count == 0) {
          if (copied != 0) {
            A64LinuxSyscallResult result;
            result.value = copied;
            return result;
          }
          return ErrorResult(EIO);
        }
        if (arguments[0] >
                std::numeric_limits<std::uint64_t>::max() - copied ||
            !memory_.Write(arguments[0] + copied, buffer.data(),
                           static_cast<std::size_t>(count))) {
          if (copied != 0) {
            A64LinuxSyscallResult result;
            result.value = copied;
            return result;
          }
          return ErrorResult(EFAULT);
        }
        copied += static_cast<std::uint64_t>(count);
        if (static_cast<std::size_t>(count) < amount) break;
      }
      A64LinuxSyscallResult result;
      result.value = copied;
      return result;
#else
      return ErrorResult(ENOSYS);
#endif
    }

    case kClockGetTime:
    case kClockGetRes: {
      clockid_t host_clock = 0;
      if (!ConvertGuestClockId(arguments[0], &host_clock)) {
        return ErrorResult(EINVAL);
      }
      struct timespec host_time {};
      const int clock_result =
          number == kClockGetTime
              ? ::clock_gettime(host_clock, &host_time)
              : ::clock_getres(host_clock, &host_time);
      if (clock_result != 0) {
        return ErrorResult(errno == 0 ? EINVAL : errno);
      }
      // Linux permits clock_getres(clock, nullptr).
      if (number == kClockGetRes && arguments[1] == 0) {
        A64LinuxSyscallResult result;
        result.value = 0;
        return result;
      }
      const A64GuestTimespec guest_time{
          static_cast<std::int64_t>(host_time.tv_sec),
          static_cast<std::int64_t>(host_time.tv_nsec)};
      if (!memory_.Write(arguments[1], &guest_time, sizeof(guest_time))) {
        return ErrorResult(EFAULT);
      }
      A64LinuxSyscallResult result;
      result.value = 0;
      return result;
    }

    case kGetPid:
    case kGetPpid:
    case kGetUid:
    case kGetEuid:
    case kGetGid:
    case kGetEgid:
    case kGetTid: {
      A64LinuxSyscallResult result;
      switch (number) {
        case kGetPid: result.value = kGuestProcessId; break;
        case kGetPpid: result.value = kGuestParentProcessId; break;
        case kGetUid:
        case kGetEuid: result.value = kGuestUid; break;
        case kGetGid:
        case kGetEgid: result.value = kGuestGid; break;
        case kGetTid: result.value = kGuestThreadId; break;
        default: return ErrorResult(ENOSYS);
      }
      return result;
    }

    case kSchedYield: {
      // Guest threads are not scheduled independently yet. Yielding therefore
      // becomes a deterministic no-op instead of yielding the entire host.
      A64LinuxSyscallResult result;
      result.value = 0;
      return result;
    }

    case kUname: {
      A64GuestUtsname value{};
      // Report the guest ABI, not the x86-64 host architecture. Keep the
      // strings stable and bounded like Linux's fixed-width utsname fields.
      SetUtsField(value.sysname, sizeof(value.sysname), "Linux");
      SetUtsField(value.nodename, sizeof(value.nodename), "mocktail-guest");
      SetUtsField(value.release, sizeof(value.release), "5.15.0-mocktail");
      SetUtsField(value.version, sizeof(value.version), "#1 SMP Mocktail");
      SetUtsField(value.machine, sizeof(value.machine), "aarch64");
      SetUtsField(value.domainname, sizeof(value.domainname), "(none)");
      if (!memory_.Write(arguments[0], &value, sizeof(value))) {
        return ErrorResult(EFAULT);
      }
      A64LinuxSyscallResult result;
      result.value = 0;
      return result;
    }

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
