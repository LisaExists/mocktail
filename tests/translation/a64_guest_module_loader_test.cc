// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_module_loader.h"

#include <elf.h>

#include <cstdint>
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

}  // namespace

int main() {
  using mocktail::translation::A64GuestMemory;
  using mocktail::translation::A64GuestModuleLoadOptions;
  using mocktail::translation::A64GuestModuleSource;
  using mocktail::translation::LoadA64GuestModuleSet;
  using mocktail::translation::test::BuildA64ElfWithRelativeRelocation;
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
