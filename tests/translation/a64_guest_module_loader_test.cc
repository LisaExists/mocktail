// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_module_loader.h"

#include <elf.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "translation/a64_guest_memory.h"
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

std::vector<std::uint8_t> BuildTlsRelocationElf(bool undefined_symbol) {
  using mocktail::translation::test::BuildA64ElfWithRelativeRelocation;
  using mocktail::translation::test::ReadDynamicEntry;
  using mocktail::translation::test::ReadElfHeader;
  using mocktail::translation::test::WriteDynamicEntry;
  using mocktail::translation::test::WriteElfHeader;

  auto file = BuildA64ElfWithRelativeRelocation(
      1030, 0x1500, 0, 1, undefined_symbol);
  auto header = ReadElfHeader(file);
  header.e_phnum = 3;
  WriteElfHeader(file, header);

  Elf64_Phdr tls{};
  tls.p_type = PT_TLS;
  tls.p_flags = PF_R;
  tls.p_offset = 0x1400;
  tls.p_vaddr = 0x1400;
  tls.p_filesz = 8;
  tls.p_memsz = 16;
  tls.p_align = 8;
  std::memcpy(file.data() + header.e_phoff +
                  2 * static_cast<std::size_t>(header.e_phentsize),
              &tls, sizeof(tls));

  Elf64_Sym symbol{};
  std::memcpy(&symbol, file.data() + 0x1380 + sizeof(Elf64_Sym),
              sizeof(symbol));
  symbol.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_TLS);
  symbol.st_shndx = undefined_symbol ? SHN_UNDEF : 1;
  symbol.st_value = undefined_symbol ? 0 : 8;
  symbol.st_size = 8;
  std::memcpy(file.data() + 0x1380 + sizeof(Elf64_Sym), &symbol,
              sizeof(symbol));

  if (undefined_symbol) {
    constexpr std::size_t kExtraStringOffset = 32;
    const char soname[] = "libroot_tls.so";
    std::memcpy(file.data() + 0x1300 + kExtraStringOffset, soname,
                sizeof(soname));
    auto strsz = ReadDynamicEntry(file, 4);
    strsz.d_un.d_val = kExtraStringOffset + sizeof(soname);
    WriteDynamicEntry(file, 4, strsz);
    auto soname_entry = ReadDynamicEntry(file, 6);
    soname_entry.d_un.d_val = kExtraStringOffset;
    WriteDynamicEntry(file, 6, soname_entry);
  } else {
    auto needed = ReadDynamicEntry(file, 5);
    needed.d_tag = DT_DEBUG;
    WriteDynamicEntry(file, 5, needed);
  }
  return file;
}

}  // namespace

int main() {
  using mocktail::translation::A64GuestMemory;
  using mocktail::translation::A64GuestModuleLoadOptions;
  using mocktail::translation::A64GuestModuleSource;
  using mocktail::translation::A64SymbolRequest;
  using mocktail::translation::LoadA64GuestModuleSet;
  using mocktail::translation::test::BuildA64ElfWithRelativeRelocation;
  using mocktail::translation::test::BuildA64ElfWithSymbolVersion;
  using mocktail::translation::test::ReadDynamicEntry;
  using mocktail::translation::test::WriteDynamicEntry;

  auto root = BuildA64ElfWithRelativeRelocation(
      R_AARCH64_GLOB_DAT, 0x1500, 0, 1, true);
  auto dependency = BuildA64ElfWithRelativeRelocation();
  // Give the dependency the SONAME requested by the root test object.
  auto soname = ReadDynamicEntry(dependency, 6);
  soname.d_un.d_val = 1;  // "libc.so" in the fixture's DT_STRTAB.
  WriteDynamicEntry(dependency, 6, soname);

  const std::vector<A64GuestModuleSource> sources{
      {"libroot.so", root},
      {"libc.so", dependency},
  };
  const auto loaded = LoadA64GuestModuleSet(sources, "libroot.so");
  Check(static_cast<bool>(loaded),
        "loads a root shared object and its DT_NEEDED dependency");
  if (loaded) {
    const auto& modules = *loaded.modules;
    Check(modules.root_index == 0 && modules.modules.size() == 2,
          "keeps the requested root first and loads the dependency once");
    Check(modules.FindModule("libroot.so") != nullptr &&
              modules.FindModule("libc.so") != nullptr,
          "looks up modules by source name and SONAME");
    Check(modules.modules[0].image.base_address !=
              modules.modules[1].image.base_address,
          "assigns each shared object a distinct guest base");
    Check(modules.modules[1].image.soname == "libc.so",
          "retains the dependency SONAME");
    Check(modules.initialization_order ==
              std::vector<std::size_t>{1, 0},
          "orders dependency constructors before the root module");
    Check(modules.finalization_order ==
              std::vector<std::size_t>{0, 1},
          "orders finalization in reverse dependency order");
    Check(modules.ResolveExportedSymbol("test_symbol") ==
              std::optional<std::uint64_t>{0x123456789ULL},
          "indexes a dependency's externally visible dynamic symbol");

    std::uint64_t relocated = 0;
    const auto root_slot =
        modules.modules[0].image.load_bias + 0x1500;
    Check(modules.modules[0].image.Read(root_slot, &relocated,
                                        sizeof(relocated)) &&
              relocated == 0x123456789ULL,
          "resolves a root GLOB_DAT import against the dependency export");

    A64GuestMemory memory(16U * 1024U * 1024U);
    std::string memory_error;
    Check(memory.MapImage(modules.modules[0].image, &memory_error),
          "maps the root image into sparse guest memory");
    Check(memory.MapImage(modules.modules[1].image, &memory_error),
          "maps the dependency without colliding with the root image");
  }

  auto versioned_root = BuildA64ElfWithSymbolVersion(true);
  auto versioned_dependency = BuildA64ElfWithSymbolVersion(false);
  auto versioned_soname = ReadDynamicEntry(versioned_dependency, 6);
  versioned_soname.d_un.d_val = 1;  // libc.so
  WriteDynamicEntry(versioned_dependency, 6, versioned_soname);
  const std::vector<A64GuestModuleSource> versioned_sources{
      {"libversioned-root.so", versioned_root},
      {"libc.so", versioned_dependency},
  };
  const auto loaded_versioned =
      LoadA64GuestModuleSet(versioned_sources, "libversioned-root.so");
  Check(static_cast<bool>(loaded_versioned),
        "resolves a versioned root import from the exact dependency version");
  if (loaded_versioned) {
    const auto& modules = *loaded_versioned.modules;
    const auto resolved = modules.ResolveExportedSymbol(
        A64SymbolRequest{"test_symbol", "MOCK_ABI_1.0", "libc.so"});
    Check(resolved == std::optional<std::uint64_t>{0x123456789ULL},
          "queries an export by name, version and provider");
    std::uint64_t relocated = 0;
    const auto slot = modules.modules[0].image.load_bias + 0x1500;
    Check(modules.modules[0].image.Read(slot, &relocated, sizeof(relocated)) &&
              relocated == 0x123456789ULL,
          "applies a cross-module GLOB_DAT relocation with a version requirement");
  }

  const std::vector<A64GuestModuleSource> missing_dependency{
      {"libroot.so", root},
  };
  const auto missing = LoadA64GuestModuleSet(missing_dependency, "libroot.so");
  Check(!missing &&
            missing.error.find("missing guest dependency 'libc.so'") !=
                std::string::npos,
        "fails closed when a DT_NEEDED dependency is unavailable");

  A64GuestModuleLoadOptions explicit_external;
  explicit_external.external_dependencies = {"libc.so"};
  explicit_external.resolve_external_symbol =
      [](const std::string& name) -> std::optional<std::uint64_t> {
    if (name == "test_symbol") return 0x70000000ULL;
    return std::nullopt;
  };
  const auto external = LoadA64GuestModuleSet(
      missing_dependency, "libroot.so", explicit_external);
  Check(static_cast<bool>(external),
        "allows an explicitly declared external guest dependency");
  if (external) {
    Check(external.modules->initialization_order ==
              std::vector<std::size_t>{0} &&
              external.modules->finalization_order ==
                  std::vector<std::size_t>{0},
          "omits explicit external dependencies from module lifecycle order");
    std::uint64_t relocated = 0;
    const auto root_slot =
        external.modules->modules[0].image.load_bias + 0x1500;
    Check(external.modules->modules[0].image.Read(
              root_slot, &relocated, sizeof(relocated)) &&
              relocated == 0x70000000ULL,
          "resolves external imports only through the supplied callback");
  }

  const std::vector<A64GuestModuleSource> duplicate_names{
      {"libroot.so", root},
      {"subdir/libroot.so", dependency},
  };
  const auto duplicate =
      LoadA64GuestModuleSet(duplicate_names, "libroot.so");
  Check(!duplicate &&
            duplicate.error.find("ambiguous guest module name") !=
                std::string::npos,
        "rejects ambiguous shared-object aliases");

  const auto no_root = LoadA64GuestModuleSet(sources, "libmissing.so");
  Check(!no_root &&
            no_root.error.find("root guest module was not found") !=
                std::string::npos,
        "reports a missing root module with a useful diagnostic");

  std::cout << failures << " guest module loader test(s) failed\n";
  return failures == 0 ? 0 : 1;
}
