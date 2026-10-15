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
struct A64ExportedSymbol final {
  std::string name;
  std::uint64_t guest_address = 0;
  std::uint64_t size = 0;
  std::uint8_t binding = 0;
  std::uint8_t type = 0;
  std::uint8_t visibility = 0;
  // Empty for unversioned symbols; populated from DT_VERDEF for versioned
  // definitions. version_hidden marks non-default versions of the same name.
  std::string version;
  bool version_hidden = false;
  // TLS symbols use offsets rather than process-wide guest addresses.
  std::uint64_t tls_module_id = 0;
  std::uint64_t tls_module_offset = 0;
  std::uint64_t tls_static_offset_from_tp = 0;
};

struct A64SymbolRequest final {
  std::string name;
  // Empty requests the default/unversioned definition. A non-empty version
  // must match exactly; provider, when present, is the DT_NEEDED filename.
  std::string version;
  std::string provider;
};

struct A64TlsSymbol final {
  std::uint64_t module_id = 0;
  std::uint64_t module_offset = 0;
  // Offset from TP to the variable when all loaded modules use the prototype's
  // preallocated static TLS block. This also powers the static TLSDESC resolver.
  std::uint64_t static_offset_from_tp = 0;
};

// PT_TLS image template for one ELF module. template_bytes is memory_size bytes
// long: file-backed initial data followed by the zero-filled TLS BSS tail.
// This records module TLS metadata only; a platform-specific per-thread TLS
// block and TLSDESC/static TLS relocations must be implemented separately.
struct A64TlsSegment final {
  std::uint64_t file_size = 0;
  std::uint64_t memory_size = 0;
  std::uint64_t alignment = 1;
  // Assigned by A64GuestTlsRuntime after the complete dependency graph loads.
  std::uint64_t module_id = 0;
  std::uint64_t static_offset_from_tp = 0;
  std::vector<std::uint8_t> template_bytes;
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
  // Externally visible definitions, including versioned definitions when
  // their DT_VERDEF metadata is valid. Version selection remains explicit.
  std::vector<A64ExportedSymbol> exported_symbols;
  // Dynamic initializer functions in ELF loader call order and finalizers in
  // reverse-construction order. Values are guest virtual addresses, not host
  // pointers; callers must execute them only after dependencies are mapped.
  std::vector<std::uint64_t> initializers;
  std::vector<std::uint64_t> finalizers;
  std::optional<A64TlsSegment> tls;
  std::vector<A64LoadSegment> segments;

  // Reads loaded segments, including across adjacent segments. Returns false
  // for holes or address overflow. Stack, heap and per-thread TLS allocation are separate.
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
using A64VersionedSymbolResolver =
    std::function<std::optional<std::uint64_t>(const A64SymbolRequest&)>;
using A64TlsSymbolResolver =
    std::function<std::optional<A64TlsSymbol>(const A64SymbolRequest&)>;

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
  // Unversioned imports may use the compact name-only resolver. Versioned
  // imports are sent only to resolve_versioned_symbol; they never silently
  // fall back to a name-only match.
  A64SymbolResolver resolve_symbol;
  A64VersionedSymbolResolver resolve_versioned_symbol;
  A64TlsSymbolResolver resolve_tls_symbol;
  // These are supplied by the multi-module linker after laying out every PT_TLS.
  std::uint64_t tls_module_id = 1;
  std::uint64_t tls_static_offset_from_tp = 16;
  // Guest address of a guest-safe TLSDESC resolver thunk. Zero disables TLSDESC.
  std::uint64_t tlsdesc_resolver_address = 0;
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
