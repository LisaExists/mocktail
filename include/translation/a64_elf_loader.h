// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#ifndef MOCKTAIL_TRANSLATION_A64_ELF_LOADER_H_
#define MOCKTAIL_TRANSLATION_A64_ELF_LOADER_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace mocktail::translation {

// One loaded PT_LOAD segment. The bytes vector is sized to p_memsz, so bytes
// not present in the file (the ELF BSS tail) are zero-initialized.
struct A64LoadSegment final {
  std::uint64_t guest_address = 0;
  std::uint64_t virtual_address = 0;
  std::uint32_t flags = 0;
  std::vector<std::uint8_t> bytes;
};

// A validated ELF image backed by ordinary host-owned memory. Guest addresses
// are numeric AArch64 addresses and must never be cast to host pointers.
struct A64LoadedImage final {
  std::uint64_t load_bias = 0;
  std::uint64_t entry_point = 0;
  std::uint64_t base_address = 0;
  std::uint64_t image_size = 0;
  std::string soname;
  std::vector<std::string> dependencies;
  std::vector<A64LoadSegment> segments;

  // Reads loaded segments, including across adjacent segments. Returns false
  // for holes or address overflow. Stack, heap and TLS mappings come later.
  bool Read(std::uint64_t address, void* destination,
            std::size_t length) const noexcept;

  // Writes are allowed only when the range is contained by one PF_W segment.
  bool Write(std::uint64_t address, const void* source,
             std::size_t length) noexcept;

  bool IsExecutable(std::uint64_t address,
                    std::size_t length) const noexcept;
};

using A64SymbolResolver =
    std::function<std::optional<std::uint64_t>(const std::string&)>;

struct A64ElfLoadOptions final {
  // Desired guest address for the aligned origin of an ET_DYN image.
  std::uint64_t preferred_base = 0x100000000ULL;
  // Bounds the total image span and aggregate mapped segment bytes.
  std::size_t max_image_size = 512U * 1024U * 1024U;
  std::size_t max_program_headers = 4096;
  std::size_t max_dynamic_entries = 1U * 1024U * 1024U;
  std::size_t max_relocations = 4U * 1024U * 1024U;
  std::size_t max_packed_relocation_bytes = 64U * 1024U * 1024U;
  std::size_t max_symbols = 1U * 1024U * 1024U;
  // Resolves undefined guest symbols to guest addresses in already-loaded
  // modules or explicit host-call thunks. No implicit host pointer conversion.
  A64SymbolResolver resolve_symbol;
};

struct A64ElfLoadResult final {
  std::optional<A64LoadedImage> image;
  std::string error;

  explicit operator bool() const noexcept {
    return image.has_value() && error.empty();
  }
};

// Loads ELF64 little-endian AArch64 ET_DYN/ET_EXEC images. Maps PT_LOAD data
// and BSS, collects DT_NEEDED/DT_SONAME metadata, and applies supported RELA
// relocations. Undefined symbols are resolved only through the caller's explicit
// resolver. Dependency loading, symbol versioning, TLS and process setup remain
// separate responsibilities. Unsupported relocation formats fail closed.
A64ElfLoadResult LoadA64Elf(const std::vector<std::uint8_t>& file,
                            A64ElfLoadOptions options = {});

}  // namespace mocktail::translation

#endif  // MOCKTAIL_TRANSLATION_A64_ELF_LOADER_H_
