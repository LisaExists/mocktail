// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_memory.h"

#include "translation/a64_elf_loader.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

namespace mocktail::translation {
namespace {

constexpr std::uint8_t kAllPermissions =
    A64GuestMemory::kRead | A64GuestMemory::kWrite |
    A64GuestMemory::kExecute;

std::uint8_t ToGuestPermissions(std::uint32_t elf_flags) noexcept {
  std::uint8_t result = 0;
  if ((elf_flags & 4U) != 0) result |= A64GuestMemory::kRead;     // PF_R
  if ((elf_flags & 2U) != 0) result |= A64GuestMemory::kWrite;    // PF_W
  if ((elf_flags & 1U) != 0) result |= A64GuestMemory::kExecute;  // PF_X
  return result;
}

bool AlignUp(std::uint64_t value, std::uint64_t* result) noexcept {
  const std::uint64_t mask = A64GuestMemory::kPageSize - 1;
  if (value > std::numeric_limits<std::uint64_t>::max() - mask) return false;
  *result = (value + mask) & ~mask;
  return true;
}

}  // namespace

A64GuestMemory::A64GuestMemory(std::size_t max_mapped_bytes) noexcept
    : max_mapped_bytes_(max_mapped_bytes -
                        (max_mapped_bytes % kPageSize)) {}

bool A64GuestMemory::AddOverflows(std::uint64_t address,
                                  std::uint64_t length) noexcept {
  return length > std::numeric_limits<std::uint64_t>::max() - address;
}

bool A64GuestMemory::Map(std::uint64_t address, std::uint64_t size,
                         std::uint8_t permissions, std::string* error) {
  auto fail = [&](const char* message) {
    if (error != nullptr) *error = message;
    return false;
  };
  if ((permissions & ~kAllPermissions) != 0) {
    return fail("guest mapping contains unknown permission bits");
  }
  if (size == 0 || address % kPageSize != 0 || size % kPageSize != 0) {
    return fail("guest mappings must be non-empty and page-aligned");
  }
  if (AddOverflows(address, size)) {
    return fail("guest mapping address range overflows");
  }
  if (size > std::numeric_limits<std::size_t>::max() ||
      size > max_mapped_bytes_ ||
      mapped_bytes_ > max_mapped_bytes_ - static_cast<std::size_t>(size)) {
    return fail("guest mapping exceeds the configured memory limit");
  }

  for (std::uint64_t offset = 0; offset < size; offset += kPageSize) {
    if (pages_.find(address + offset) != pages_.end()) {
      return fail("guest mapping overlaps an existing page");
    }
  }

  std::vector<std::uint64_t> inserted;
  try {
    inserted.reserve(static_cast<std::size_t>(size / kPageSize));
    for (std::uint64_t offset = 0; offset < size; offset += kPageSize) {
      const auto page_address = address + offset;
      auto [iterator, was_inserted] = pages_.try_emplace(page_address);
      if (!was_inserted) {
        for (const auto previous : inserted) pages_.erase(previous);
        return fail("guest mapping overlaps an existing page");
      }
      iterator->second.permissions = permissions;
      inserted.push_back(page_address);
    }
  } catch (const std::bad_alloc&) {
    for (const auto previous : inserted) pages_.erase(previous);
    return fail("host memory allocation failed while mapping guest pages");
  }
  mapped_bytes_ += static_cast<std::size_t>(size);
  if (error != nullptr) error->clear();
  return true;
}

bool A64GuestMemory::MapImage(const A64LoadedImage& image,
                              std::string* error) {
  auto fail = [&](const char* message) {
    if (error != nullptr) *error = message;
    return false;
  };
  if (image.segments.empty()) return fail("ELF image has no loadable segments");

  std::map<std::uint64_t, std::uint8_t> page_plan;
  try {
    for (const auto& segment : image.segments) {
      if (segment.bytes.empty()) continue;
      const auto length = static_cast<std::uint64_t>(segment.bytes.size());
      if (AddOverflows(segment.guest_address, length)) {
        return fail("ELF segment address range overflows while mapping");
      }
      const auto end = segment.guest_address + length;
      std::uint64_t aligned_end = 0;
      if (!AlignUp(end, &aligned_end)) {
        return fail("ELF segment end overflows while aligning guest pages");
      }
      const auto first_page = segment.guest_address & ~(kPageSize - 1);
      const auto permissions = ToGuestPermissions(segment.flags);
      for (auto page = first_page; page < aligned_end; page += kPageSize) {
        page_plan[page] |= permissions;
        if (page > std::numeric_limits<std::uint64_t>::max() - kPageSize) {
          return fail("ELF segment page range overflows");
        }
      }
    }
  } catch (const std::bad_alloc&) {
    return fail("host memory allocation failed while planning ELF pages");
  }
  if (page_plan.empty()) return fail("ELF image has no mapped guest pages");
  if (page_plan.size() >
      std::numeric_limits<std::size_t>::max() / kPageSize) {
    return fail("ELF image page count overflows host size");
  }
  const auto planned_bytes = page_plan.size() * kPageSize;
  if (planned_bytes > max_mapped_bytes_ ||
      mapped_bytes_ > max_mapped_bytes_ - planned_bytes) {
    return fail("ELF guest mappings exceed the configured memory limit");
  }
  for (const auto& planned : page_plan) {
    if (pages_.find(planned.first) != pages_.end()) {
      return fail("ELF guest mapping collides with an existing guest page");
    }
  }

  std::vector<std::uint64_t> inserted;
  try {
    inserted.reserve(page_plan.size());
    for (const auto& planned : page_plan) {
      auto [iterator, was_inserted] = pages_.try_emplace(planned.first);
      if (!was_inserted) {
        for (const auto previous : inserted) pages_.erase(previous);
        return fail("ELF guest mapping collides with an existing guest page");
      }
      iterator->second.permissions = planned.second;
      inserted.push_back(planned.first);
    }
  } catch (const std::bad_alloc&) {
    for (const auto previous : inserted) pages_.erase(previous);
    return fail("host memory allocation failed while mapping ELF guest pages");
  }
  mapped_bytes_ += planned_bytes;

  for (const auto& segment : image.segments) {
    if (!segment.bytes.empty() &&
        !Initialize(segment.guest_address, segment.bytes.data(),
                    segment.bytes.size())) {
      for (const auto previous : inserted) pages_.erase(previous);
      mapped_bytes_ -= planned_bytes;
      return fail("failed to initialize mapped ELF segment bytes");
    }
  }
  if (error != nullptr) error->clear();
  return true;
}

bool A64GuestMemory::Transfer(std::uint64_t address, void* buffer,
                              std::size_t length,
                              std::uint8_t required_permission,
                              bool bypass_write_permission,
                              bool write) noexcept {
  if (length == 0) return true;
  if (buffer == nullptr ||
      AddOverflows(address, static_cast<std::uint64_t>(length))) {
    return false;
  }

  auto* bytes = static_cast<std::uint8_t*>(buffer);
  std::size_t transferred = 0;
  while (transferred < length) {
    const auto current = address + transferred;
    const auto page_address = current & ~(kPageSize - 1);
    const auto offset = static_cast<std::size_t>(current & (kPageSize - 1));
    auto iterator = pages_.find(page_address);
    if (iterator == pages_.end()) return false;
    const auto& page = iterator->second;
    if (required_permission != 0 &&
        (page.permissions & required_permission) == 0) {
      if (!(write && bypass_write_permission &&
            required_permission == kWrite)) {
        return false;
      }
    }

    const auto chunk = std::min(length - transferred,
                                static_cast<std::size_t>(kPageSize) - offset);
    if (write) {
      std::memmove(iterator->second.bytes.data() + offset,
                   bytes + transferred, chunk);
    } else {
      std::memcpy(bytes + transferred, page.bytes.data() + offset, chunk);
    }
    transferred += chunk;
  }
  return true;
}

bool A64GuestMemory::Read(std::uint64_t address, void* destination,
                          std::size_t length) const noexcept {
  return const_cast<A64GuestMemory*>(this)->Transfer(
      address, destination, length, kRead, false, false);
}

bool A64GuestMemory::Write(std::uint64_t address, const void* source,
                           std::size_t length) noexcept {
  return Transfer(address, const_cast<void*>(source), length, kWrite, false,
                  true);
}

bool A64GuestMemory::Initialize(std::uint64_t address, const void* source,
                                std::size_t length) noexcept {
  return Transfer(address, const_cast<void*>(source), length, kWrite, true,
                  true);
}

bool A64GuestMemory::IsExecutable(std::uint64_t address,
                                  std::size_t length) const noexcept {
  if (length == 0 ||
      AddOverflows(address, static_cast<std::uint64_t>(length))) {
    return false;
  }
  std::size_t checked = 0;
  while (checked < length) {
    const auto current = address + checked;
    const auto page_address = current & ~(kPageSize - 1);
    const auto iterator = pages_.find(page_address);
    if (iterator == pages_.end() ||
        (iterator->second.permissions & kExecute) == 0) {
      return false;
    }
    const auto offset = static_cast<std::size_t>(current & (kPageSize - 1));
    checked += std::min(length - checked,
                        static_cast<std::size_t>(kPageSize) - offset);
  }
  return true;
}

bool A64GuestMemory::IsMapped(std::uint64_t address,
                              std::size_t length) const noexcept {
  if (length == 0 || AddOverflows(address, static_cast<std::uint64_t>(length))) {
    return false;
  }
  std::size_t checked = 0;
  while (checked < length) {
    const auto current = address + checked;
    const auto page_address = current & ~(kPageSize - 1);
    if (pages_.find(page_address) == pages_.end()) return false;
    const auto offset = static_cast<std::size_t>(current & (kPageSize - 1));
    checked += std::min(length - checked,
                        static_cast<std::size_t>(kPageSize) - offset);
  }
  return true;
}

}  // namespace mocktail::translation
