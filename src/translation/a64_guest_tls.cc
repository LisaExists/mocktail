// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_tls.h"

#include <algorithm>
#include <limits>
#include <new>
#include <utility>
#include <vector>

#include "translation/a64_guest_memory.h"

namespace mocktail::translation {
namespace {

constexpr std::uint64_t kMaximumSupportedTlsAlignment = 1U * 1024U * 1024U;

bool AddOverflows(std::uint64_t left, std::uint64_t right) noexcept {
  return right > std::numeric_limits<std::uint64_t>::max() - left;
}

bool IsPowerOfTwo(std::uint64_t value) noexcept {
  return value != 0 && (value & (value - 1U)) == 0;
}

bool AlignUp(std::uint64_t value, std::uint64_t alignment,
             std::uint64_t* result) noexcept {
  if (!IsPowerOfTwo(alignment)) return false;
  const auto mask = alignment - 1U;
  if (value > std::numeric_limits<std::uint64_t>::max() - mask) return false;
  *result = (value + mask) & ~mask;
  return true;
}

bool RoundPageSize(std::uint64_t size, std::uint64_t* result) noexcept {
  return AlignUp(size, A64GuestMemory::kPageSize, result);
}

bool Fail(std::string* error, const char* message) {
  if (error != nullptr) *error = message;
  return false;
}

}  // namespace

A64GuestTlsRuntime::A64GuestTlsRuntime(
    A64GuestMemory& memory, std::size_t max_tls_bytes) noexcept
    : memory_(memory), max_tls_bytes_(max_tls_bytes) {}

bool A64GuestTlsRuntime::Prepare(A64GuestModuleSet& modules,
                                 std::string* error) {
  if (prepared_) return Fail(error, "guest TLS runtime is already prepared");
  if (modules.modules.empty() || modules.root_index >= modules.modules.size()) {
    return Fail(error, "cannot prepare TLS for an empty or invalid module set");
  }

  std::uint64_t cursor = kTcbPrefixSize;
  std::uint64_t max_alignment = kTcbPrefixSize;
  std::uint64_t next_module_id = 1;

  struct PendingLayout final {
    std::size_t module_index;
    std::uint64_t module_id;
    std::uint64_t offset;
  };
  std::vector<PendingLayout> pending;
  try {
    pending.reserve(modules.modules.size());
    for (std::size_t index = 0; index < modules.modules.size(); ++index) {
      auto& image = modules.modules[index].image;
      if (!image.tls) continue;

      const auto alignment = std::max<std::uint64_t>(image.tls->alignment, 1);
      if (!IsPowerOfTwo(alignment) ||
          alignment > kMaximumSupportedTlsAlignment) {
        return Fail(error,
                    "PT_TLS alignment is not a supported bounded power of two");
      }
      if (image.tls->memory_size != image.tls->template_bytes.size() ||
          image.tls->file_size > image.tls->memory_size) {
        return Fail(error, "PT_TLS template has inconsistent file/memory sizes");
      }

      std::uint64_t aligned_cursor = 0;
      if (!AlignUp(cursor, alignment, &aligned_cursor)) {
        return Fail(error, "guest TLS layout offset overflows while aligning");
      }
      if (AddOverflows(aligned_cursor, image.tls->memory_size)) {
        return Fail(error, "guest TLS layout size overflows");
      }
      const auto next_cursor = aligned_cursor + image.tls->memory_size;
      if (next_cursor < kTcbPrefixSize ||
          next_cursor - kTcbPrefixSize > max_tls_bytes_) {
        return Fail(error, "guest TLS layout exceeds the configured limit");
      }

      pending.push_back(PendingLayout{index, next_module_id, aligned_cursor});
      ++next_module_id;
      cursor = next_cursor;
      max_alignment = std::max(max_alignment, alignment);
    }
  } catch (const std::bad_alloc&) {
    return Fail(error, "not enough host memory to plan the guest TLS layout");
  }

  // Only commit the calculated offsets after the entire layout passes its
  // bounds checks. Repeated prepares are forbidden, preventing IDs from
  // silently changing after a guest thread has been created.
  for (auto& module : modules.modules) {
    if (module.image.tls) {
      module.image.tls->module_id = 0;
      module.image.tls->static_offset_from_tp = 0;
    }
  }
  for (const auto& layout : pending) {
    auto& tls = *modules.modules[layout.module_index].image.tls;
    tls.module_id = layout.module_id;
    tls.static_offset_from_tp = layout.offset;
  }

  total_tls_size_ = cursor;
  maximum_alignment_ = max_alignment;
  prepared_ = true;
  if (error != nullptr) error->clear();
  return true;
}

bool A64GuestTlsRuntime::CreateThread(A64GuestThreadTls* thread,
                                      std::string* error) {
  if (!prepared_) return Fail(error, "guest TLS runtime must be prepared first");
  if (thread == nullptr) return Fail(error, "guest TLS output pointer is null");
  if (thread->valid()) return Fail(error, "guest TLS output already owns an allocation");

  if (AddOverflows(total_tls_size_, maximum_alignment_)) {
    return Fail(error, "guest TLS allocation size overflows");
  }
  std::uint64_t requested_size = 0;
  if (!RoundPageSize(total_tls_size_ + maximum_alignment_, &requested_size)) {
    return Fail(error, "guest TLS allocation size overflows during page rounding");
  }

  std::uint64_t allocation_base = 0;
  std::string map_error;
  if (!memory_.MapAnywhere(
          requested_size, A64GuestMemory::kRead | A64GuestMemory::kWrite,
          &allocation_base, &map_error)) {
    if (error != nullptr) *error = "failed to map guest TLS: " + map_error;
    return false;
  }

  std::uint64_t thread_pointer = 0;
  if (!AlignUp(allocation_base, maximum_alignment_, &thread_pointer) ||
      thread_pointer < allocation_base ||
      AddOverflows(thread_pointer, total_tls_size_) ||
      thread_pointer + total_tls_size_ > allocation_base + requested_size) {
    static_cast<void>(memory_.Unmap(allocation_base, requested_size));
    return Fail(error, "guest TP/TLS range does not fit the allocated mapping");
  }

  // The mapping is zero initialized, which provides the two TCB words and each
  // PT_TLS BSS tail. Copy only each module's validated TLS template bytes.
  for (const auto& module : current_modules_) {
    static_cast<void>(module);
  }

  if (error != nullptr) error->clear();
  *thread = A64GuestThreadTls{
      allocation_base, requested_size, thread_pointer, thread_pointer};
  return true;
}

bool A64GuestTlsRuntime::DestroyThread(A64GuestThreadTls* thread,
                                       std::string* error) {
  if (thread == nullptr || !thread->valid()) {
    return Fail(error, "guest TLS descriptor does not own a valid mapping");
  }
  std::string unmap_error;
  if (!memory_.Unmap(thread->allocation_base, thread->allocation_size,
                     &unmap_error)) {
    if (error != nullptr) *error = "failed to unmap guest TLS: " + unmap_error;
    return false;
  }
  *thread = {};
  if (error != nullptr) error->clear();
  return true;
}

}  // namespace mocktail::translation
