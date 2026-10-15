// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_host_calls.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

#include "translation/a64_guest_memory.h"

namespace mocktail::translation {
namespace {

constexpr std::uint32_t kA64SvcBase = 0xD4000001U;
constexpr std::uint32_t kA64Ret = 0xD65F03C0U;

A64HostCallResult Failure(std::string error) {
  return A64HostCallResult{false, 0, std::move(error)};
}

bool RoundPageSize(std::uint64_t size, std::uint64_t* rounded) noexcept {
  if (size == 0 || size >
      std::numeric_limits<std::uint64_t>::max() -
          (A64GuestMemory::kPageSize - 1)) {
    return false;
  }
  *rounded = (size + A64GuestMemory::kPageSize - 1) &
             ~(A64GuestMemory::kPageSize - 1);
  return true;
}

bool ReadGuestString(A64GuestMemory& memory, std::uint64_t address,
                     std::size_t maximum, bool require_terminator,
                     std::string* output, std::string* error) {
  output->clear();
  if (maximum == 0) {
    if (require_terminator) *error = "guest string has a zero-byte limit";
    return !require_terminator;
  }

  std::array<char, A64GuestMemory::kPageSize> buffer{};
  std::size_t copied = 0;
  while (copied < maximum) {
    if (address > std::numeric_limits<std::uint64_t>::max() - copied) {
      *error = "guest string address overflows";
      return false;
    }
    const auto current = address + copied;
    const auto page_remaining = static_cast<std::size_t>(
        A64GuestMemory::kPageSize -
        (current & (A64GuestMemory::kPageSize - 1)));
    const auto amount = std::min({maximum - copied, page_remaining,
                                  buffer.size()});
    if (!memory.Read(current, buffer.data(), amount)) {
      *error = "guest string points outside readable mapped memory";
      return false;
    }
    const auto terminator = std::find(buffer.begin(), buffer.begin() + amount,
                                      '\0');
    const auto count = static_cast<std::size_t>(terminator - buffer.begin());
    output->append(buffer.data(), count);
    if (terminator != buffer.begin() + amount) return true;
    copied += amount;
  }

  if (require_terminator) {
    *error = "guest string exceeds the configured length limit or is unterminated";
    return false;
  }
  return true;
}

int CompareUnsignedStrings(const std::string& left,
                           const std::string& right,
                           std::size_t maximum) noexcept {
  const auto count = std::min({left.size(), right.size(), maximum});
  for (std::size_t index = 0; index < count; ++index) {
    const auto l = static_cast<unsigned char>(left[index]);
    const auto r = static_cast<unsigned char>(right[index]);
    if (l != r) return l < r ? -1 : 1;
  }
  if (count == maximum) return 0;
  if (left.size() == right.size()) return 0;
  return left.size() < right.size() ? -1 : 1;
}

}  // namespace

A64GuestHostCalls::A64GuestHostCalls(A64GuestMemory& memory,
                                     std::uint64_t stub_base) noexcept
    : memory_(memory), stub_base_(stub_base) {}

bool A64GuestHostCalls::Register(std::string name, std::string provider,
                                 std::string version, Handler handler,
                                 std::string* error) {
  auto fail = [&](const char* message) {
    if (error != nullptr) *error = message;
    return false;
  };
  if (name.empty() || !handler) return fail("host-call export needs a name and handler");

  std::lock_guard<std::mutex> lock(mutex_);
  if (installed_) return fail("host-call exports cannot be added after stub installation");
  for (const auto& item : exports_) {
    if (item.name == name && item.provider == provider &&
        item.version == version) {
      return fail("duplicate guest host-call export name/provider/version");
    }
  }
  if (exports_.size() >=
      std::numeric_limits<std::uint16_t>::max() -
          kFirstSvcImmediate + 1U) {
    return fail("host-call table exceeds the available SVC immediate range");
  }

  Export item;
  item.name = std::move(name);
  item.provider = std::move(provider);
  item.version = std::move(version);
  item.handler = std::move(handler);
  item.svc_immediate =
      kFirstSvcImmediate + static_cast<std::uint32_t>(exports_.size());
  exports_.push_back(std::move(item));
  if (error != nullptr) error->clear();
  return true;
}

bool A64GuestHostCalls::RegisterBuiltinLibc(std::string* error) {
  auto register_one = [&](const char* name, Handler handler) {
    return Register(name, "libc.so", "", std::move(handler), error);
  };

  auto read_bytes = [this](std::uint64_t address, std::size_t size,
                           std::vector<std::uint8_t>* bytes,
                           std::string* diagnostic) {
    if (size > kMaximumTransferBytes) {
      *diagnostic = "guest memory transfer exceeds the 64 MiB host-call limit";
      return false;
    }
    try {
      bytes->resize(size);
    } catch (const std::bad_alloc&) {
      *diagnostic = "not enough host memory for guest byte transfer";
      return false;
    }
    if (size != 0 && !memory_.Read(address, bytes->data(), size)) {
      *diagnostic = "host-call source points outside readable guest memory";
      return false;
    }
    return true;
  };

  auto allocate = [this](std::uint64_t requested) -> A64HostCallResult {
    const auto size = std::max<std::uint64_t>(requested, 1);
    if (size > kMaximumTransferBytes) return {true, 0, {}};
    std::uint64_t guest_address = 0;
    std::string diagnostic;
    if (!memory_.MapAnywhere(
            size, A64GuestMemory::kRead | A64GuestMemory::kWrite,
            &guest_address, &diagnostic)) {
      return {true, 0, {}};
    }
    std::uint64_t rounded_size = 0;
    if (!RoundPageSize(size, &rounded_size)) {
      static_cast<void>(memory_.Unmap(guest_address, A64GuestMemory::kPageSize));
      return {true, 0, {}};
    }
    try {
      std::lock_guard<std::mutex> lock(mutex_);
      allocations_.emplace(guest_address, rounded_size);
    } catch (const std::bad_alloc&) {
      static_cast<void>(memory_.Unmap(guest_address, rounded_size));
      return {true, 0, {}};
    }
    return {true, guest_address, {}};
  };

  if (!register_one("memcpy", [this, read_bytes](
          const Arguments& arguments) -> A64HostCallResult {
        const auto destination = arguments[0];
        const auto source = arguments[1];
        const auto length = arguments[2];
        if (length > kMaximumTransferBytes) {
          return Failure("memcpy length exceeds the host-call transfer limit");
        }
        std::vector<std::uint8_t> bytes;
        std::string diagnostic;
        if (!read_bytes(source, static_cast<std::size_t>(length), &bytes,
                        &diagnostic)) {
          return Failure(std::move(diagnostic));
        }
        if (length != 0 &&
            !memory_.Write(destination, bytes.data(), bytes.size())) {
          return Failure("memcpy destination points outside writable guest memory");
        }
        return {true, destination, {}};
      })) return false;

  if (!register_one("memmove", [this, read_bytes](
          const Arguments& arguments) -> A64HostCallResult {
        const auto destination = arguments[0];
        const auto source = arguments[1];
        const auto length = arguments[2];
        if (length > kMaximumTransferBytes) {
          return Failure("memmove length exceeds the host-call transfer limit");
        }
        std::vector<std::uint8_t> bytes;
        std::string diagnostic;
        if (!read_bytes(source, static_cast<std::size_t>(length), &bytes,
                        &diagnostic)) {
          return Failure(std::move(diagnostic));
        }
        if (length != 0 &&
            !memory_.Write(destination, bytes.data(), bytes.size())) {
          return Failure("memmove destination points outside writable guest memory");
        }
        return {true, destination, {}};
      })) return false;

  if (!register_one("memset", [this](const Arguments& arguments)
          -> A64HostCallResult {
        const auto destination = arguments[0];
        const auto byte = static_cast<std::uint8_t>(arguments[1]);
        const auto length = arguments[2];
        if (length > kMaximumTransferBytes) {
          return Failure("memset length exceeds the host-call transfer limit");
        }
        std::array<std::uint8_t, 4096> buffer{};
        buffer.fill(byte);
        std::uint64_t offset = 0;
        while (offset < length) {
          const auto amount = static_cast<std::size_t>(
              std::min<std::uint64_t>(buffer.size(), length - offset));
          if (destination > std::numeric_limits<std::uint64_t>::max() - offset ||
              !memory_.Write(destination + offset, buffer.data(), amount)) {
            return Failure("memset destination points outside writable guest memory");
          }
          offset += amount;
        }
        return {true, destination, {}};
      })) return false;

  if (!register_one("memcmp", [this](const Arguments& arguments)
          -> A64HostCallResult {
        const auto left = arguments[0];
        const auto right = arguments[1];
        const auto length = arguments[2];
        if (length > kMaximumTransferBytes) {
          return Failure("memcmp length exceeds the host-call transfer limit");
        }
        std::array<std::uint8_t, 4096> left_buffer{};
        std::array<std::uint8_t, 4096> right_buffer{};
        std::uint64_t offset = 0;
        while (offset < length) {
          const auto amount = static_cast<std::size_t>(
              std::min<std::uint64_t>(left_buffer.size(), length - offset));
          if (left > std::numeric_limits<std::uint64_t>::max() - offset ||
              right > std::numeric_limits<std::uint64_t>::max() - offset ||
              !memory_.Read(left + offset, left_buffer.data(), amount) ||
              !memory_.Read(right + offset, right_buffer.data(), amount)) {
            return Failure("memcmp source points outside readable guest memory");
          }
          for (std::size_t index = 0; index < amount; ++index) {
            if (left_buffer[index] != right_buffer[index]) {
              const int result = left_buffer[index] < right_buffer[index] ? -1 : 1;
              return {true, static_cast<std::uint64_t>(
                                static_cast<std::int64_t>(result)), {}};
            }
          }
          offset += amount;
        }
        return {true, 0, {}};
      })) return false;

  if (!register_one("strlen", [this](const Arguments& arguments)
          -> A64HostCallResult {
        std::string value;
        std::string diagnostic;
        if (!ReadGuestString(memory_, arguments[0], kMaximumCStringBytes,
                             true, &value, &diagnostic)) {
          return Failure(std::move(diagnostic));
        }
        return {true, value.size(), {}};
      })) return false;

  if (!register_one("strcmp", [this](const Arguments& arguments)
          -> A64HostCallResult {
        std::string left;
        std::string right;
        std::string diagnostic;
        if (!ReadGuestString(memory_, arguments[0], kMaximumCStringBytes,
                             true, &left, &diagnostic) ||
            !ReadGuestString(memory_, arguments[1], kMaximumCStringBytes,
                             true, &right, &diagnostic)) {
          return Failure(std::move(diagnostic));
        }
        const auto result = CompareUnsignedStrings(
            left, right, std::numeric_limits<std::size_t>::max());
        return {true, static_cast<std::uint64_t>(
                          static_cast<std::int64_t>(result)), {}};
      })) return false;

  if (!register_one("strncmp", [this](const Arguments& arguments)
          -> A64HostCallResult {
        const auto maximum = arguments[2];
        if (maximum > kMaximumCStringBytes) {
          return Failure("strncmp length exceeds the host-call string limit");
        }
        std::string left;
        std::string right;
        std::string diagnostic;
        if (!ReadGuestString(memory_, arguments[0],
                             static_cast<std::size_t>(maximum), false,
                             &left, &diagnostic) ||
            !ReadGuestString(memory_, arguments[1],
                             static_cast<std::size_t>(maximum), false,
                             &right, &diagnostic)) {
          return Failure(std::move(diagnostic));
        }
        const auto result = CompareUnsignedStrings(
            left, right, static_cast<std::size_t>(maximum));
        return {true, static_cast<std::uint64_t>(
                          static_cast<std::int64_t>(result)), {}};
      })) return false;

  if (!register_one("malloc", [allocate](const Arguments& arguments) {
        return allocate(arguments[0]);
      })) return false;

  if (!register_one("calloc", [allocate, this](const Arguments& arguments)
          -> A64HostCallResult {
        if (arguments[0] != 0 &&
            arguments[1] > std::numeric_limits<std::uint64_t>::max() /
                               arguments[0]) {
          return {true, 0, {}};
        }
        const auto length = arguments[0] * arguments[1];
        if (length > kMaximumTransferBytes) return {true, 0, {}};
        auto result = allocate(length);
        if (!result.success || result.value == 0 || length == 0) return result;
        std::array<std::uint8_t, 4096> zeroes{};
        std::uint64_t offset = 0;
        while (offset < length) {
          const auto amount = static_cast<std::size_t>(
              std::min<std::uint64_t>(zeroes.size(), length - offset));
          if (!memory_.Write(result.value + offset, zeroes.data(), amount)) {
            return Failure("calloc could not initialize its guest allocation");
          }
          offset += amount;
        }
        return result;
      })) return false;

  auto free_allocation = [this](std::uint64_t address)
      -> A64HostCallResult {
    if (address == 0) return {true, 0, {}};
    std::uint64_t size = 0;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      const auto found = allocations_.find(address);
      if (found == allocations_.end()) {
        return Failure("free received a pointer not owned by guest malloc");
      }
      size = found->second;
      allocations_.erase(found);
    }
    std::string diagnostic;
    if (!memory_.Unmap(address, size, &diagnostic)) {
      return Failure("free could not release its guest allocation: " +
                     diagnostic);
    }
    return {true, 0, {}};
  };

  if (!register_one("free", [free_allocation](const Arguments& arguments) {
        return free_allocation(arguments[0]);
      })) return false;

  if (!register_one("realloc", [this, allocate, read_bytes, free_allocation](
          const Arguments& arguments) -> A64HostCallResult {
        const auto old_address = arguments[0];
        const auto new_size = arguments[1];
        if (old_address == 0) return allocate(new_size);
        if (new_size == 0) {
          const auto freed = free_allocation(old_address);
          if (!freed.success) return freed;
          return {true, 0, {}};
        }
        if (new_size > kMaximumTransferBytes) return {true, 0, {}};

        std::uint64_t old_size = 0;
        {
          std::lock_guard<std::mutex> lock(mutex_);
          const auto found = allocations_.find(old_address);
          if (found == allocations_.end()) {
            return Failure("realloc received a pointer not owned by guest malloc");
          }
          old_size = found->second;
        }

        auto allocated = allocate(new_size);
        if (!allocated.success || allocated.value == 0) return allocated;
        const auto copy_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(old_size, new_size));
        std::vector<std::uint8_t> bytes;
        std::string diagnostic;
        if (!read_bytes(old_address, copy_size, &bytes, &diagnostic) ||
            (copy_size != 0 &&
             !memory_.Write(allocated.value, bytes.data(), bytes.size()))) {
          static_cast<void>(free_allocation(allocated.value));
          if (diagnostic.empty()) {
            diagnostic = "realloc could not copy old guest allocation";
          }
          return Failure(std::move(diagnostic));
        }
        const auto freed = free_allocation(old_address);
        if (!freed.success) return freed;
        return allocated;
      })) return false;

  if (!register_one("abort", [](const Arguments&) {
        return Failure("guest called abort()");
      })) return false;

  // TLSDESC resolver for the prototype's preloaded static TLS layout. The
  // guest ABI passes the descriptor address in X0; its second word is the
  // precomputed offset from TP. Dynamic TLS/DTV descriptors are not handled.
  if (!register_one("__mocktail_tlsdesc_static", [this](
          const Arguments& arguments) -> A64HostCallResult {
        if (arguments[0] >
            std::numeric_limits<std::uint64_t>::max() - sizeof(std::uint64_t)) {
          return Failure("static TLSDESC address overflows");
        }
        std::uint64_t thread_pointer_offset = 0;
        if (!memory_.Read(arguments[0] + sizeof(std::uint64_t),
                          &thread_pointer_offset,
                          sizeof(thread_pointer_offset))) {
          return Failure("static TLSDESC points outside readable guest memory");
        }
        return {true, thread_pointer_offset, {}};
      })) return false;
  if (!register_one("__stack_chk_fail", [](const Arguments&) {
        return Failure("guest stack-protector check failed");
      })) return false;

  if (error != nullptr) error->clear();
  return true;
}

bool A64GuestHostCalls::Install(std::string* error) {
  auto fail = [&](const char* message) {
    if (error != nullptr) *error = message;
    return false;
  };
  std::lock_guard<std::mutex> lock(mutex_);
  if (installed_) return fail("guest host-call stubs were already installed");
  if (exports_.empty()) return fail("cannot install an empty guest host-call table");
  if ((stub_base_ % A64GuestMemory::kPageSize) != 0) {
    return fail("guest host-call stub base must be page-aligned");
  }
  if (exports_.size() >
      std::numeric_limits<std::uint64_t>::max() / 8U) {
    return fail("guest host-call stub size overflows");
  }
  const auto bytes = static_cast<std::uint64_t>(exports_.size()) * 8U;
  std::uint64_t mapped_size = 0;
  if (!RoundPageSize(bytes, &mapped_size)) {
    return fail("guest host-call stub mapping size overflows");
  }
  std::string diagnostic;
  if (!memory_.Map(stub_base_, mapped_size,
                   A64GuestMemory::kRead | A64GuestMemory::kExecute,
                   &diagnostic)) {
    if (error != nullptr) *error = "failed to map guest host-call stubs: " + diagnostic;
    return false;
  }

  for (std::size_t index = 0; index < exports_.size(); ++index) {
    auto& item = exports_[index];
    item.guest_address = stub_base_ + index * 8U;
    const std::uint32_t svc =
        kA64SvcBase | ((item.svc_immediate & 0xffffU) << 5U);
    const std::uint32_t instructions[] = {svc, kA64Ret};
    if (!memory_.Initialize(item.guest_address, instructions,
                            sizeof(instructions))) {
      static_cast<void>(memory_.Unmap(stub_base_, mapped_size));
      return fail("failed to initialize a guest host-call stub");
    }
  }

  installed_ = true;
  if (error != nullptr) error->clear();
  return true;
}

std::optional<std::uint64_t> A64GuestHostCalls::ResolveSymbol(
    const std::string& name) const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& item : exports_) {
    if (item.name == name && item.version.empty() &&
        item.guest_address != 0) {
      return item.guest_address;
    }
  }
  return std::nullopt;
}

std::optional<std::uint64_t> A64GuestHostCalls::ResolveVersionedSymbol(
    const A64SymbolRequest& request) const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& item : exports_) {
    if (item.name != request.name || item.version != request.version ||
        item.guest_address == 0) {
      continue;
    }
    if (!request.provider.empty() && !item.provider.empty() &&
        item.provider != request.provider) {
      continue;
    }
    return item.guest_address;
  }
  return std::nullopt;
}

bool A64GuestHostCalls::HandlesSvc(std::uint32_t immediate) const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return std::any_of(exports_.begin(), exports_.end(),
                     [&](const Export& item) {
    return item.svc_immediate == immediate && item.guest_address != 0;
  });
}

A64HostCallResult A64GuestHostCalls::DispatchSvc(
    std::uint32_t immediate, const Arguments& arguments) {
  Handler handler;
  try {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = std::find_if(exports_.begin(), exports_.end(),
                                    [&](const Export& item) {
      return item.svc_immediate == immediate && item.guest_address != 0;
    });
    if (found == exports_.end()) {
      return Failure("unknown AArch64 host-call SVC immediate");
    }
    handler = found->handler;
  } catch (const std::bad_alloc&) {
    return Failure("not enough host memory to dispatch guest host-call thunk");
  }
  return handler(arguments);
}

}  // namespace mocktail::translation
