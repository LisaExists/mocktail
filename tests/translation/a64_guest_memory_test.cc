// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_memory.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <string>

#include "translation/a64_elf_loader.h"
#include "a64_test_elf.h"

namespace {

int failures = 0;

void Check(bool condition, const std::string& name) {
  if (condition) {
    std::cout << "[PASS] " << name << '\n';
  } else {
    std::cerr << "[FAIL] " << name << '\n';
    ++failures;
  }
}

}  // namespace

int main() {
  using mocktail::translation::A64GuestMemory;
  using mocktail::translation::LoadA64Elf;
  using mocktail::translation::test::BuildMinimalA64Elf;

  A64GuestMemory memory(8U * 1024U * 1024U);
  std::string error;
  constexpr std::uint64_t kStackBase = 0x7000000000ULL;
  constexpr std::uint64_t kStackSize = 2U * 1024U * 1024U;
  Check(memory.Map(kStackBase, kStackSize,
                   A64GuestMemory::kRead | A64GuestMemory::kWrite, &error),
        "maps a page-aligned anonymous stack");
  Check(error.empty(), "successful maps clear the prior diagnostic");
  Check(memory.mapped_bytes() == kStackSize,
        "tracks committed guest memory");
  Check(!memory.Map(kStackBase, A64GuestMemory::kPageSize,
                    A64GuestMemory::kRead, &error),
        "rejects overlapping guest pages");
  Check(!memory.Map(kStackBase + 1, A64GuestMemory::kPageSize,
                    A64GuestMemory::kRead, &error),
        "rejects unaligned guest mappings");
  Check(!memory.Map(kStackBase + kStackSize, 7U * 1024U * 1024U,
                    A64GuestMemory::kRead | A64GuestMemory::kWrite, &error),
        "enforces the configured memory limit");

  const std::uint64_t sentinel = 0x123456789ABCDEF0ULL;
  std::uint64_t actual = 0;
  Check(memory.Write(kStackBase + kStackSize - 8, &sentinel, sizeof(sentinel)),
        "writes an eight-byte value at the end of a writable page");
  Check(memory.Read(kStackBase + kStackSize - 8, &actual, sizeof(actual)) &&
            actual == sentinel,
        "reads back guest data");
  Check(!memory.Read(kStackBase - 1, &actual, sizeof(actual)),
        "rejects reads from an unmapped address");
  Check(!memory.Write(kStackBase + kStackSize, &sentinel, sizeof(sentinel)),
        "rejects writes beyond mapped memory");

  A64GuestMemory code_memory;
  auto elf_result = LoadA64Elf(BuildMinimalA64Elf());
  Check(static_cast<bool>(elf_result), "loads the synthetic AArch64 ELF fixture");
  if (elf_result) {
    Check(code_memory.MapImage(*elf_result.image, &error),
          "maps ELF PT_LOAD segments into guest memory");
    Check(code_memory.IsExecutable(elf_result.image->entry_point, 4),
          "preserves executable permissions");
    std::array<std::uint8_t, 4> instruction{};
    Check(code_memory.Read(elf_result.image->entry_point, instruction.data(),
                           instruction.size()),
          "reads instructions from the mapped image");
    const std::uint8_t replacement = 0xFF;
    Check(!code_memory.Write(elf_result.image->entry_point, &replacement, 1),
          "prevents writes to RX guest memory");
    Check(!code_memory.IsExecutable(elf_result.image->entry_point +
                                       elf_result.image->image_size,
                                   4),
          "leaves holes outside the ELF unmapped");
  }

  A64GuestMemory too_small(2U * A64GuestMemory::kPageSize);
  Check(!too_small.Map(kStackBase, 3U * A64GuestMemory::kPageSize,
                       A64GuestMemory::kRead | A64GuestMemory::kWrite, &error),
        "rejects mappings larger than the memory budget");
  Check(too_small.mapped_bytes() == 0,
        "failed mappings do not leave partially allocated pages");

  A64GuestMemory guard_memory;
  Check(guard_memory.Map(kStackBase, A64GuestMemory::kPageSize,
                         A64GuestMemory::kRead, &error),
        "maps a read-only page");
  Check(!guard_memory.Write(kStackBase, &sentinel, sizeof(sentinel)),
        "enforces page write permissions");
  Check(!guard_memory.IsExecutable(kStackBase, 4),
        "does not mistake readable data for executable code");

  A64GuestMemory anonymous_memory(1024U * 1024U);
  std::uint64_t anonymous_base = 0;
  Check(anonymous_memory.MapAnywhere(5000,
                                     A64GuestMemory::kRead |
                                         A64GuestMemory::kWrite,
                                     &anonymous_base, &error),
        "maps rounded anonymous guest memory at an available address");
  Check(anonymous_base % A64GuestMemory::kPageSize == 0 &&
            anonymous_memory.mapped_bytes() == 2U * A64GuestMemory::kPageSize,
        "rounds guest mmap sizes up to whole pages");
  std::uint64_t second_mapping = 0;
  Check(anonymous_memory.MapAnywhere(A64GuestMemory::kPageSize,
                                     A64GuestMemory::kRead,
                                     &second_mapping, &error) &&
            second_mapping >= anonymous_base +
                                  2U * A64GuestMemory::kPageSize,
        "finds a second non-overlapping anonymous address");
  Check(anonymous_memory.Protect(anonymous_base,
                                 A64GuestMemory::kPageSize,
                                 A64GuestMemory::kRead, &error),
        "changes permissions on an entire mapped page");
  Check(!anonymous_memory.Write(anonymous_base, &sentinel, sizeof(sentinel)),
        "blocks writes after guest mprotect removes write permission");
  Check(anonymous_memory.Protect(anonymous_base,
                                 A64GuestMemory::kPageSize,
                                 A64GuestMemory::kRead |
                                     A64GuestMemory::kWrite, &error),
        "restores guest page write permission");
  Check(anonymous_memory.Write(anonymous_base, &sentinel, sizeof(sentinel)),
        "permits writes after mprotect restores write permission");
  Check(!anonymous_memory.Protect(anonymous_base,
                                 4U * A64GuestMemory::kPageSize,
                                 A64GuestMemory::kRead, &error),
        "rejects mprotect ranges containing an unmapped page");
  Check(anonymous_memory.Write(anonymous_base, &sentinel, sizeof(sentinel)),
        "failed mprotect leaves earlier pages unchanged");
  Check(anonymous_memory.Unmap(anonymous_base +
                                   A64GuestMemory::kPageSize,
                               2U * A64GuestMemory::kPageSize, &error),
        "unmaps a range spanning mapped pages and holes");
  Check(anonymous_memory.IsMapped(anonymous_base,
                                  A64GuestMemory::kPageSize) &&
            !anonymous_memory.IsMapped(anonymous_base +
                                          A64GuestMemory::kPageSize, 1),
        "munmap preserves pages outside its range and releases pages inside it");
  Check(anonymous_memory.mapped_bytes() == A64GuestMemory::kPageSize,
        "accounts for pages removed by a partial munmap");
  Check(anonymous_memory.Unmap(anonymous_base, 2U * A64GuestMemory::kPageSize,
                               &error) &&
            anonymous_memory.mapped_bytes() == 0,
        "munmaps a range containing remaining memory and holes");
  Check(anonymous_memory.Unmap(second_mapping, A64GuestMemory::kPageSize,
                               &error) &&
            anonymous_memory.mapped_bytes() == 0,
        "repeatedly unmapping an empty range is harmless");

  Check(!anonymous_memory.MapAnywhere(0, A64GuestMemory::kRead,
                                      &anonymous_base, &error),
        "rejects empty anonymous guest mappings");
  Check(!anonymous_memory.MapAnywhere(A64GuestMemory::kPageSize,
                                      A64GuestMemory::kRead, nullptr, &error),
        "requires a guest address output for anonymous mappings");

  std::cout << failures << " guest-memory test(s) failed\n";
  return failures == 0 ? 0 : 1;
}
