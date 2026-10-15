// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#ifndef MOCKTAIL_TRANSLATION_A64_GUEST_MODULE_LOADER_H_
#define MOCKTAIL_TRANSLATION_A64_GUEST_MODULE_LOADER_H_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "translation/a64_elf_loader.h"

namespace mocktail::translation {

// One candidate shared object supplied by an APK extractor or another trusted
// source. name should be a filename or SONAME such as "libroblox.so".
struct A64GuestModuleSource final {
  std::string name;
  std::vector<std::uint8_t> bytes;
};

struct A64GuestModule final {
  std::string source_name;
  A64LoadedImage image;
};

struct A64GuestModuleSet final {
  // The requested root object is always modules[ root_index ].
  std::size_t root_index = 0;
  // Root first, followed by dependencies in breadth-first DT_NEEDED order.
  std::vector<A64GuestModule> modules;
  // Module indices ordered for initialization (dependencies before dependents)
  // and finalization (reverse dependency order). These describe order only;
  // this prototype does not execute constructors or destructors yet.
  std::vector<std::size_t> initialization_order;
  std::vector<std::size_t> finalization_order;

  const A64GuestModule* FindModule(const std::string& name) const;
  // An empty request.version selects an unversioned/default export. A
  // non-empty request requires an exact version and optional provider match.
  std::optional<std::uint64_t> ResolveExportedSymbol(
      const std::string& name) const;
  std::optional<std::uint64_t> ResolveExportedSymbol(
      const A64SymbolRequest& request) const;
  std::optional<A64TlsSymbol> ResolveTlsSymbol(
      const A64SymbolRequest& request) const;
};

struct A64GuestModuleLoadOptions final {
  A64ElfLoadOptions elf;
  std::uint64_t first_module_base = 0x100000000ULL;
  std::uint64_t module_gap = 0x10000ULL;
  std::size_t max_modules = 256;
  std::size_t max_total_image_size = 2U * 1024U * 1024U * 1024U;

  // Explicitly allow dependencies implemented by guest thunk modules or a
  // future Android/Bionic compatibility layer rather than supplied ELF files.
  // An allowed dependency does not automatically resolve any symbols.
  std::vector<std::string> external_dependencies;
  A64SymbolResolver resolve_external_symbol;
  A64VersionedSymbolResolver resolve_external_versioned_symbol;
  A64TlsSymbolResolver resolve_external_tls_symbol;
};

struct A64GuestModuleLoadResult final {
  std::optional<A64GuestModuleSet> modules;
  std::string error;

  explicit operator bool() const noexcept {
    return modules.has_value() && error.empty();
  }
};

// Loads the root module and its DT_NEEDED closure. A bounded metadata pass
// assigns non-overlapping guest bases and indexes exports; a second pass applies
// relocations against the complete module set. External dependencies and
// symbols must be declared/resolved explicitly. GNU version requirements are
// matched by exact version/provider; unsupported ELF features still fail closed.
A64GuestModuleLoadResult LoadA64GuestModuleSet(
    const std::vector<A64GuestModuleSource>& sources,
    const std::string& root_name,
    A64GuestModuleLoadOptions options = {});

}  // namespace mocktail::translation

#endif  // MOCKTAIL_TRANSLATION_A64_GUEST_MODULE_LOADER_H_
