// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#ifndef MOCKTAIL_TRANSLATION_A64_GUEST_MEMORY_H_
#define MOCKTAIL_TRANSLATION_A64_GUEST_MEMORY_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace mocktail::translation {

struct A64LoadedImage;

// Sparse, page-based AArch64 guest memory. Guest virtual addresses are never
// converted into host pointers. This first implementation is single-process
// infrastructure; synchronization and per-thread TLS are layered separately.
class A64GuestMemory final {
 public:
  static constexpr std::uint64_t kPageSize = 4096;

  enum Permission : std::uint8_t {
    kRead = 1U << 0U,
    kWrite = 1U << 1U,
    kExecute = 1U << 2U,
  };

  explicit A64GuestMemory(
      std::size_t max_mapped_bytes = 1024U * 1024U * 1024U) noexcept;

  // Maps a page-aligned anonymous range and zero-initializes it. Existing
  // mappings are an error; pages outside the mapping remain inaccessible.
  bool Map(std::uint64_t address, std::uint64_t size,
           std::uint8_t permissions, std::string* error = nullptr);

  // Maps rounded-up anonymous memory at the first available address from the
  // runtime's normal guest mmap range. The result is a guest address only.
  bool MapAnywhere(std::uint64_t size, std::uint8_t permissions,
                   std::uint64_t* guest_address,
                   std::string* error = nullptr);

  // Implements the page-aligned semantics used by mmap/mprotect/munmap.
  // Protect and Unmap validate the whole range first and leave memory unchanged
  // when validation fails.
  bool Protect(std::uint64_t address, std::uint64_t size,
               std::uint8_t permissions, std::string* error = nullptr);
  bool Unmap(std::uint64_t address, std::uint64_t size,
             std::string* error = nullptr);

  // Maps all PT_LOAD segments from an already validated image. Page permissions
  // are the union of segments sharing a page, as is required for ELF layouts
  // where adjacent segments share a hardware page.
  bool MapImage(const A64LoadedImage& image, std::string* error = nullptr);

  // Guest-visible memory operations enforce page permissions and may cross
  // adjacent mapped pages, but they never implicitly map a missing page.
  bool Read(std::uint64_t address, void* destination,
            std::size_t length) const noexcept;
  bool Write(std::uint64_t address, const void* source,
             std::size_t length) noexcept;
  bool IsExecutable(std::uint64_t address,
                    std::size_t length) const noexcept;
  bool IsMapped(std::uint64_t address, std::size_t length) const noexcept;

  // Loader-only initialization path: permits populating read-only ELF pages
  // before guest code starts, while still requiring the full range to map.
  bool Initialize(std::uint64_t address, const void* source,
                  std::size_t length) noexcept;

  std::size_t mapped_bytes() const noexcept { return mapped_bytes_; }
  std::size_t max_mapped_bytes() const noexcept { return max_mapped_bytes_; }

 private:
  struct Page final {
    std::array<std::uint8_t, kPageSize> bytes{};
    std::uint8_t permissions = 0;
  };

  static bool AddOverflows(std::uint64_t address,
                           std::uint64_t length) noexcept;
  bool Transfer(std::uint64_t address, void* buffer, std::size_t length,
                std::uint8_t required_permission,
                bool bypass_write_permission, bool write) noexcept;

  std::map<std::uint64_t, Page> pages_;
  std::size_t max_mapped_bytes_;
  std::size_t mapped_bytes_ = 0;
};

}  // namespace mocktail::translation

#endif  // MOCKTAIL_TRANSLATION_A64_GUEST_MEMORY_H_
