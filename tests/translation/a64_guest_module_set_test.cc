// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_module_set.h"

#include <elf.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

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

void ReplaceDynamicStrings(std::vector<std::uint8_t>* file,
                           const char* strings, std::size_t strings_size,
                           std::uint64_t soname_offset,
                           std::uint64_t needed_offset,
                           bool has_dependency) {
  std::memcpy(file->data() + 0x1300, strings, strings_size);

  auto string_size = mocktail::translation::test::ReadDynamicEntry(*file, 4);
  string_size.d_un.d_val = strings_size;
  mocktail::translation::test::WriteDynamicEntry(*file, 4, string_size);

  auto needed = mocktail::translation::test::ReadDynamicEntry(*file, 5);
  if (has_dependency) {
    needed.d_tag = DT_NEEDED;
    needed.d_un.d_val = needed_offset;
  } else {
    needed.d_tag = DT_DEBUG;
    needed.d_un.d_val = 0;
  }
  mocktail::translation::test::WriteDynamicEntry(*file, 5, needed);

  auto soname = mocktail::translation::test::ReadDynamicEntry(*file, 6);
  soname.d_tag = DT_SONAME;
  soname.d_un.d_val = soname_offset;
  mocktail::translation::test::WriteDynamicEntry(*file, 6, soname);
}

void ReplaceDynamicSymbol(std::vector<std::uint8_t>* file,
                          std::uint32_t name_offset, std::uint8_t binding,
                          std::uint8_t type, std::uint16_t section_index,
                          std::uint64_t value) {
  Elf64_Sym symbol{};
  const std::size_t offset = 0x1380 + sizeof(Elf64_Sym);
  std::memcpy(&symbol, file->data() + offset, sizeof(symbol));
  symbol.st_name = name_offset;
  symbol.st_info = ELF64_ST_INFO(binding, type);
  symbol.st_shndx = section_index;
  symbol.st_value = value;
  symbol.st_size = 8;
  std::memcpy(file->data() + offset, &symbol, sizeof(symbol));
}

std::vector<std::uint8_t> BuildProvider() {
  auto file = mocktail::translation::test::BuildA64ElfWithRelativeRelocation();
  const char strings[] = "\0libprovider.so\0test_symbol";
  ReplaceDynamicStrings(&file, strings, sizeof(strings), 1, 0, false);
  ReplaceDynamicSymbol(&file, 16, STB_GLOBAL, STT_FUNC, 1, 0x1000);
  return file;
}

std::vector<std::uint8_t> BuildConsumer() {
  auto file = mocktail::translation::test::BuildA64ElfWithRelativeRelocation(
      R_AARCH64_GLOB_DAT, 0x1500, 0, 1, true);
  const char strings[] = "\0libprovider.so\0libcaller.so\0test_symbol";
  ReplaceDynamicStrings(&file, strings, sizeof(strings), 16, 1, true);
  ReplaceDynamicSymbol(&file, 29, STB_GLOBAL, STT_FUNC, SHN_UNDEF, 0);
  return file;
}

}  // namespace

int main() {
  using mocktail::translation::A64GuestModuleInput;
  using mocktail::translation::A64GuestModuleSet;

  // Put the caller first deliberately: dependencies and exports are resolved
  // only after all supplied images have loaded.
  A64GuestModuleSet modules;
  const auto consumer = BuildConsumer();
  const auto provider = BuildProvider();
  std::string error;
  Check(modules.Load({{"libcaller.so", consumer},
                      {"libprovider.so", provider}}, &error),
        "loads caller and provider regardless of input dependency order");
  if (modules.loaded()) {
    const auto* caller = modules.FindBySoname("libcaller.so");
    const auto* provider_module = modules.FindBySoname("libprovider.so");
    Check(caller != nullptr && provider_module != nullptr,
          "indexes modules by DT_SONAME");
    const auto exported = modules.FindSymbol("test_symbol");
    Check(exported.has_value() &&
              provider_module != nullptr &&
              *exported == provider_module->image.entry_point,
          "exports a function as its guest virtual address");
    if (caller != nullptr && exported.has_value()) {
      std::uint64_t got_value = 0;
      const auto got_slot = caller->image.load_bias + 0x1500;
      Check(modules.memory().Read(got_slot, &got_value, sizeof(got_value)),
            "reads consumer relocation slot from shared guest memory");
      Check(got_value == *exported,
            "resolves consumer GLOB_DAT import into provider's guest address");
    }
    Check(modules.memory().mapped_bytes() >= 2 * 4096,
          "maps both module images into the single guest address space");
  } else {
    std::cerr << "module-set diagnostic: " << error << '\n';
  }

  A64GuestModuleSet missing_dependency;
  Check(!missing_dependency.Load({{"libcaller.so", consumer}}, &error),
        "rejects a missing DT_NEEDED dependency");
  Check(!missing_dependency.loaded() &&
            missing_dependency.memory().mapped_bytes() == 0,
        "failed module-set loads publish no mappings");

  auto wrong_provider = provider;
  const char other_strings[] = "\0libprovider.so\0other_symbol";
  ReplaceDynamicStrings(&wrong_provider, other_strings, sizeof(other_strings),
                        1, 0, false);
  ReplaceDynamicSymbol(&wrong_provider, 16, STB_GLOBAL, STT_FUNC, 1, 0x1000);
  A64GuestModuleSet missing_symbol;
  Check(!missing_symbol.Load({{"libcaller.so", consumer},
                              {"libprovider.so", wrong_provider}}, &error),
        "rejects a strong import absent from every supplied module");
  Check(error.find("unresolved AArch64 symbol: test_symbol") != std::string::npos,
        "reports the exact unresolved imported symbol");

  std::cout << failures << " module-set test(s) failed\n";
  return failures == 0 ? 0 : 1;
}
