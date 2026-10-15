// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_elf_loader.h"

#include <elf.h>

#include <algorithm>
#include <array>
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

void ExpectRejected(const std::vector<std::uint8_t>& file,
                    const std::string& name,
                    mocktail::translation::A64ElfLoadOptions options = {}) {
  const auto result = mocktail::translation::LoadA64Elf(file, options);
  Check(!result && !result.error.empty(), name);
}

std::vector<std::uint8_t> BuildElfWithTls(
    std::uint64_t file_size = 8, std::uint64_t memory_size = 16,
    std::uint64_t alignment = 8, std::uint64_t virtual_address = 0x1008,
    std::uint64_t file_offset = 0x1008, bool duplicate = false) {
  using mocktail::translation::test::BuildMinimalA64Elf;
  using mocktail::translation::test::ReadElfHeader;
  using mocktail::translation::test::WriteElfHeader;

  auto file = BuildMinimalA64Elf();
  auto header = ReadElfHeader(file);
  header.e_phnum = duplicate ? 3 : 2;
  WriteElfHeader(file, header);

  Elf64_Phdr tls{};
  tls.p_type = PT_TLS;
  tls.p_flags = PF_R;
  tls.p_offset = file_offset;
  tls.p_vaddr = virtual_address;
  tls.p_filesz = file_size;
  tls.p_memsz = memory_size;
  tls.p_align = alignment;
  const auto first_tls_offset =
      static_cast<std::size_t>(header.e_phoff) + header.e_phentsize;
  std::memcpy(file.data() + first_tls_offset, &tls, sizeof(tls));
  if (duplicate) {
    std::memcpy(file.data() + first_tls_offset + header.e_phentsize,
                &tls, sizeof(tls));
  }
  return file;
}

std::vector<std::uint8_t> BuildElfWithSymbolVersion(
    bool undefined_symbol, bool hidden_version = false) {
  using mocktail::translation::test::BuildA64ElfWithRelativeRelocation;
  using mocktail::translation::test::ReadDynamicEntry;
  using mocktail::translation::test::WriteDynamicEntry;
  using mocktail::translation::test::ReadElfHeader;
  auto file = BuildA64ElfWithRelativeRelocation(
      undefined_symbol ? R_AARCH64_GLOB_DAT : R_AARCH64_RELATIVE,
      0x1500, 0, undefined_symbol ? 1 : 0, undefined_symbol);
  const char strings[] =
      "\0libc.so\0libmock.so\0test_symbol\0MOCK_ABI_1.0";
  std::memcpy(file.data() + 0x1300, strings, sizeof(strings));
  auto strsz = ReadDynamicEntry(file, 4);
  strsz.d_un.d_val = sizeof(strings);
  WriteDynamicEntry(file, 4, strsz);

  auto dynamic = [&](std::size_t index, std::int64_t tag,
                     std::uint64_t value) {
    Elf64_Dyn entry{};
    entry.d_tag = tag;
    entry.d_un.d_val = value;
    WriteDynamicEntry(file, index, entry);
  };
  // The string table intentionally starts with a NUL byte, so strstr()
  // cannot scan it as a conventional C string. This prefix size is the exact
  // byte offset of the appended version name.
  constexpr std::uint32_t version_offset =
      sizeof("\0libc.so\0libmock.so\0test_symbol");

  const Elf64_Half versym[] = {
      0,
      static_cast<Elf64_Half>(2U | (hidden_version ? 0x8000U : 0U))};
  std::memcpy(file.data() + 0x13c0, versym, sizeof(versym));

  if (undefined_symbol) {
    Elf64_Verneed need{};
    need.vn_version = VER_NEED_CURRENT;
    need.vn_cnt = 1;
    need.vn_file = 1;  // libc.so
    need.vn_aux = sizeof(Elf64_Verneed);
    need.vn_next = 0;
    std::memcpy(file.data() + 0x1400, &need, sizeof(need));

    Elf64_Vernaux auxiliary{};
    auxiliary.vna_other = 2;
    auxiliary.vna_name = version_offset;
    auxiliary.vna_next = 0;
    std::memcpy(file.data() + 0x1400 + sizeof(need), &auxiliary,
                sizeof(auxiliary));
    dynamic(10, 0x6ffffffe, 0x1400);  // DT_VERNEED
    dynamic(11, 0x6fffffff, 1);       // DT_VERNEEDNUM
  } else {
    Elf64_Verdef definition{};
    definition.vd_version = VER_DEF_CURRENT;
    definition.vd_ndx = 2;
    definition.vd_cnt = 1;
    definition.vd_aux = sizeof(Elf64_Verdef);
    definition.vd_next = 0;
    std::memcpy(file.data() + 0x1400, &definition, sizeof(definition));

    Elf64_Verdaux auxiliary{};
    auxiliary.vda_name = version_offset;
    auxiliary.vda_next = 0;
    std::memcpy(file.data() + 0x1400 + sizeof(definition), &auxiliary,
                sizeof(auxiliary));
    dynamic(10, 0x6ffffffc, 0x1400);  // DT_VERDEF
    dynamic(11, 0x6ffffffd, 1);       // DT_VERDEFNUM
  }
  dynamic(12, DT_VERSYM, 0x13c0);
  dynamic(13, DT_NULL, 0);

  auto header = ReadElfHeader(file);
  Elf64_Phdr dynamic_header{};
  std::memcpy(&dynamic_header,
              file.data() + header.e_phoff + header.e_phentsize,
              sizeof(dynamic_header));
  dynamic_header.p_filesz = 14 * sizeof(Elf64_Dyn);
  dynamic_header.p_memsz = dynamic_header.p_filesz;
  std::memcpy(file.data() + header.e_phoff + header.e_phentsize,
              &dynamic_header, sizeof(dynamic_header));
  return file;
}

std::vector<std::uint8_t> BuildElfWithInitializers() {
  using mocktail::translation::test::BuildA64ElfWithRelativeRelocation;
  using mocktail::translation::test::ReadDynamicEntry;
  using mocktail::translation::test::WriteDynamicEntry;

  auto file = BuildA64ElfWithRelativeRelocation(
      R_AARCH64_RELATIVE, 0x1600, 0x1008);
  Elf64_Rela first{};
  std::memcpy(&first, file.data() + 0x1100, sizeof(first));
  Elf64_Rela second = first;
  second.r_offset = 0x1608;
  second.r_addend = 0x1010;
  std::memcpy(file.data() + 0x1118, &second, sizeof(second));

  auto rela_size = ReadDynamicEntry(file, 1);
  rela_size.d_un.d_val = 2 * sizeof(Elf64_Rela);
  WriteDynamicEntry(file, 1, rela_size);

  auto header = mocktail::translation::test::ReadElfHeader(file);
  Elf64_Phdr dynamic_header{};
  const auto dynamic_header_offset =
      header.e_phoff + header.e_phentsize;
  std::memcpy(&dynamic_header, file.data() + dynamic_header_offset,
              sizeof(dynamic_header));
  dynamic_header.p_filesz = 17 * sizeof(Elf64_Dyn);
  dynamic_header.p_memsz = dynamic_header.p_filesz;
  std::memcpy(file.data() + dynamic_header_offset, &dynamic_header,
              sizeof(dynamic_header));

  auto write_dynamic = [&](std::size_t index, std::int64_t tag,
                           std::uint64_t value) {
    Elf64_Dyn entry{};
    entry.d_tag = tag;
    entry.d_un.d_val = value;
    std::memcpy(file.data() + 0x1140 + index * sizeof(entry),
                &entry, sizeof(entry));
  };
  write_dynamic(10, DT_INIT, 0x1004);
  write_dynamic(11, DT_INIT_ARRAY, 0x1600);
  write_dynamic(12, DT_INIT_ARRAYSZ, sizeof(std::uint64_t));
  write_dynamic(13, DT_FINI_ARRAY, 0x1608);
  write_dynamic(14, DT_FINI_ARRAYSZ, sizeof(std::uint64_t));
  write_dynamic(15, DT_FINI, 0x1014);
  write_dynamic(16, DT_NULL, 0);
  return file;
}

}  // namespace

int main() {
  using mocktail::translation::A64ElfLoadOptions;
  using mocktail::translation::LoadA64Elf;
  using mocktail::translation::test::BuildMinimalA64Elf;
  using mocktail::translation::test::ReadElfHeader;
  using mocktail::translation::test::ReadProgramHeader;
  using mocktail::translation::test::WriteElfHeader;
  using mocktail::translation::test::WriteProgramHeader;

  auto valid = BuildMinimalA64Elf();
  auto loaded = LoadA64Elf(valid);
  Check(static_cast<bool>(loaded), "loads a valid ELF64 AArch64 ET_DYN image");
  if (loaded) {
    auto& image = *loaded.image;
    Check(image.load_bias == 0xFFFFF000ULL,
          "computes the ET_DYN load bias");
    Check(image.entry_point == 0x100000000ULL,
          "relocates the guest entry point");
    Check(image.segments.size() == 1, "maps the PT_LOAD segment");
    Check(image.image_size == 0x1000, "reports the page-rounded image span");

    std::array<std::uint8_t, 24> code{};
    Check(image.Read(image.entry_point, code.data(), code.size()),
          "reads loaded instruction bytes");
    const std::array<std::uint8_t, 24> expected{
        0x40, 0x05, 0x80, 0xD2,  // mov x0, #42
        0xFF, 0x43, 0x00, 0xD1,  // sub sp, sp, #16
        0xE0, 0x03, 0x00, 0xF9,  // str x0, [sp]
        0xE1, 0x03, 0x40, 0xF9,  // ldr x1, [sp]
        0xFF, 0x43, 0x00, 0x91,  // add sp, sp, #16
        0x00, 0x00, 0x20, 0xD4,  // brk #0
    };
    Check(code == expected, "preserves ELF file and stack-access instructions");

    std::array<std::uint8_t, 8> bss{};
    Check(image.Read(image.entry_point + 24, bss.data(), bss.size()),
          "reads the PT_LOAD BSS tail");
    Check(bss == std::array<std::uint8_t, 8>{},
          "zero-fills the BSS tail");
    Check(!image.Read(image.entry_point + image.image_size, code.data(), 1),
          "rejects reads outside mapped segments");
    const std::uint8_t byte = 0;
    Check(!image.Write(image.entry_point, &byte, sizeof(byte)),
          "rejects writes to a read-execute segment");
    Check(image.IsExecutable(image.entry_point, 4),
          "recognizes executable guest addresses");
    Check(!image.IsExecutable(
              image.entry_point + image.segments.front().bytes.size(), 4),
          "does not mark addresses outside the loaded segment executable");
  }

  auto tls_file = BuildElfWithTls();
  const auto loaded_tls = LoadA64Elf(tls_file);
  Check(static_cast<bool>(loaded_tls), "loads a valid PT_TLS template");
  if (loaded_tls) {
    const auto& tls = loaded_tls.image->tls;
    Check(tls.has_value(), "retains PT_TLS metadata on the loaded image");
    if (tls) {
      Check(tls->file_size == 8 && tls->memory_size == 16 &&
                tls->alignment == 8,
            "preserves TLS file size, memory size, and alignment");
      Check(tls->template_bytes.size() == 16,
            "allocates template storage using PT_TLS memory size");
      const std::vector<std::uint8_t> expected_tail(8, 0);
      Check(std::equal(tls->template_bytes.begin() + 8,
                       tls->template_bytes.end(), expected_tail.begin()),
            "zero-fills the TLS BSS tail independently of PT_LOAD BSS");
      Check(std::equal(tls->template_bytes.begin(),
                       tls->template_bytes.begin() + 8,
                       tls_file.begin() + 0x1008),
            "copies initial TLS data from the validated load image");
    }
  }
  const auto no_tls = LoadA64Elf(BuildMinimalA64Elf());
  Check(no_tls && !no_tls.image->tls,
        "keeps TLS metadata absent for modules without PT_TLS");

  auto invalid_tls_size = BuildElfWithTls(12, 8);
  const auto invalid_tls_size_result = LoadA64Elf(invalid_tls_size);
  Check(!invalid_tls_size_result &&
            invalid_tls_size_result.error.find("PT_TLS p_filesz exceeds p_memsz") !=
                std::string::npos,
        "rejects PT_TLS file size greater than its memory size");

  auto invalid_tls_alignment = BuildElfWithTls(8, 16, 3);
  const auto invalid_tls_alignment_result = LoadA64Elf(invalid_tls_alignment);
  Check(!invalid_tls_alignment_result &&
            invalid_tls_alignment_result.error.find("PT_TLS p_align is not a power of two") !=
                std::string::npos,
        "rejects non-power-of-two PT_TLS alignment");

  auto invalid_tls_file_range =
      BuildElfWithTls(8, 16, 8, 0x1008, UINT64_MAX - 2);
  const auto invalid_tls_file_range_result = LoadA64Elf(invalid_tls_file_range);
  Check(!invalid_tls_file_range_result &&
            invalid_tls_file_range_result.error.find("PT_TLS file range is out of bounds") !=
                std::string::npos,
        "rejects PT_TLS file offsets outside the ELF image");

  auto invalid_tls_virtual_range = BuildElfWithTls(8, 16, 8, 0x3000, 0x1008);
  const auto invalid_tls_virtual_range_result =
      LoadA64Elf(invalid_tls_virtual_range);
  Check(!invalid_tls_virtual_range_result &&
            invalid_tls_virtual_range_result.error.find(
                "PT_TLS memory range is outside mapped PT_LOAD memory") !=
                std::string::npos,
        "rejects TLS initial data outside mapped PT_LOAD segments");

  const auto invalid_tls_bss_range_result =
      LoadA64Elf(BuildElfWithTls(0, 16, 8, 0x3000, 0x1008));
  Check(!invalid_tls_bss_range_result &&
            invalid_tls_bss_range_result.error.find(
                "PT_TLS memory range is outside mapped PT_LOAD memory") !=
                std::string::npos,
        "rejects an unmapped PT_TLS BSS-only range");

  const auto duplicate_tls_result = LoadA64Elf(BuildElfWithTls(8, 16, 8,
                                                              0x1008, 0x1008,
                                                              true));
  Check(!duplicate_tls_result &&
            duplicate_tls_result.error.find("multiple PT_TLS") !=
                std::string::npos,
        "rejects ELF images containing duplicate PT_TLS segments");

  auto executable = BuildMinimalA64Elf(ET_EXEC);
  auto loaded_executable = LoadA64Elf(executable);
  Check(loaded_executable && loaded_executable.image->load_bias == 0 &&
            loaded_executable.image->entry_point == 0x1000,
        "keeps ET_EXEC addresses fixed");

  auto writable = BuildMinimalA64Elf(ET_DYN, PF_R | PF_W, 0);
  auto loaded_writable = LoadA64Elf(writable);
  Check(static_cast<bool>(loaded_writable), "loads a writable ET_DYN segment");
  if (loaded_writable) {
    const std::uint8_t value = 0xA5;
    Check(loaded_writable.image->Write(
              loaded_writable.image->base_address + 8, &value, sizeof(value)),
          "writes inside a PF_W segment");
    std::uint8_t actual = 0;
    Check(loaded_writable.image->Read(
              loaded_writable.image->base_address + 8, &actual, sizeof(actual)) &&
              actual == value,
          "reads back writable guest memory");
  }

  auto relocatable =
      mocktail::translation::test::BuildA64ElfWithRelativeRelocation();
  auto loaded_relocatable = LoadA64Elf(relocatable);
  Check(static_cast<bool>(loaded_relocatable),
        "loads a PT_DYNAMIC image with an AArch64 RELATIVE relocation");
  if (loaded_relocatable) {
    auto& image = *loaded_relocatable.image;
    std::uint64_t relocated_value = 0;
    const auto relocation_slot = image.load_bias + 0x1500;
    Check(image.Read(relocation_slot, &relocated_value,
                     sizeof(relocated_value)),
          "reads a relocated guest pointer");
    Check(relocated_value == image.load_bias + 0x1000,
          "applies R_AARCH64_RELATIVE as load-bias plus addend");
    Check(image.soname == "libmock.so",
          "extracts DT_SONAME from the guest string table");
    Check(image.dependencies == std::vector<std::string>{"libc.so"},
          "collects DT_NEEDED dependencies for later resolution");
  }

  auto android_packed_rela =
      mocktail::translation::test::BuildA64ElfWithAndroidPackedRela();
  auto loaded_android_packed_rela = LoadA64Elf(android_packed_rela);
  Check(static_cast<bool>(loaded_android_packed_rela),
        "decodes Android APS2-packed RELA relocations");
  if (loaded_android_packed_rela) {
    std::uint64_t actual = 0;
    const auto target = loaded_android_packed_rela.image->load_bias + 0x1500;
    Check(loaded_android_packed_rela.image->Read(target, &actual, sizeof(actual)) &&
              actual == loaded_android_packed_rela.image->load_bias + 0x1000,
          "applies a decoded APS2 R_AARCH64_RELATIVE relocation");
  }

  auto relr = mocktail::translation::test::BuildA64ElfWithRelrRelocation();
  auto loaded_relr = LoadA64Elf(relr);
  Check(static_cast<bool>(loaded_relr), "loads a DT_RELR pointer-relocation table");
  if (loaded_relr) {
    std::uint64_t actual = 0;
    const auto target = loaded_relr.image->load_bias + 0x1500;
    Check(loaded_relr.image->Read(target, &actual, sizeof(actual)) &&
              actual == loaded_relr.image->load_bias + 0x1000,
          "applies a DT_RELR base-relative pointer");
  }

  auto defined_symbol_relocation =
      mocktail::translation::test::BuildA64ElfWithRelativeRelocation(
          R_AARCH64_ABS64, 0x1500, 0x10, 1);
  auto loaded_defined_symbol = LoadA64Elf(defined_symbol_relocation);
  Check(static_cast<bool>(loaded_defined_symbol),
        "applies an absolute relocation against a defined dynamic symbol");
  if (loaded_defined_symbol) {
    std::uint64_t actual = 0;
    Check(loaded_defined_symbol.image->Read(
              loaded_defined_symbol.image->load_bias + 0x1500,
              &actual, sizeof(actual)) &&
              actual == 0x123456799ULL,
          "computes R_AARCH64_ABS64 as symbol value plus addend");
  }

  auto imported_symbol_relocation =
      mocktail::translation::test::BuildA64ElfWithRelativeRelocation(
          R_AARCH64_GLOB_DAT, 0x1500, 0, 1, true);
  A64ElfLoadOptions symbol_options;
  symbol_options.resolve_symbol = [](const std::string& name)
      -> std::optional<std::uint64_t> {
    if (name == "test_symbol") return 0x70000000ULL;
    return std::nullopt;
  };
  auto loaded_import = LoadA64Elf(imported_symbol_relocation, symbol_options);
  Check(static_cast<bool>(loaded_import),
        "resolves an undefined global symbol through the explicit resolver");
  if (loaded_import) {
    std::uint64_t actual = 0;
    Check(loaded_import.image->Read(
              loaded_import.image->load_bias + 0x1500,
              &actual, sizeof(actual)) &&
              actual == 0x70000000ULL,
          "writes the resolved GLOB_DAT address into guest memory");
  }

  auto unresolved_result = LoadA64Elf(imported_symbol_relocation);
  Check(!unresolved_result &&
            unresolved_result.error.find("unresolved AArch64 symbol: test_symbol") !=
                std::string::npos,
        "rejects unresolved strong symbols when no resolver is supplied");

  auto plt_symbol_relocation =
      mocktail::translation::test::BuildA64ElfWithRelativeRelocation(
          R_AARCH64_JUMP_SLOT, 0x1500, 0, 1, true, true);
  auto loaded_plt = LoadA64Elf(plt_symbol_relocation, symbol_options);
  Check(static_cast<bool>(loaded_plt),
        "applies an AArch64 JUMP_SLOT from DT_JMPREL");
  if (loaded_plt) {
    std::uint64_t actual = 0;
    Check(loaded_plt.image->Read(
              loaded_plt.image->load_bias + 0x1500,
              &actual, sizeof(actual)) &&
              actual == 0x70000000ULL,
          "writes the resolved PLT target into guest memory");
  }

  auto versioned_import = BuildElfWithSymbolVersion(true);
  A64ElfLoadOptions versioned_options;
  bool saw_versioned_request = false;
  versioned_options.resolve_symbol =
      [](const std::string&) -> std::optional<std::uint64_t> {
    return 0x11111111ULL;  // Must never satisfy a versioned import.
  };
  versioned_options.resolve_versioned_symbol =
      [&](const mocktail::translation::A64SymbolRequest& request)
      -> std::optional<std::uint64_t> {
    saw_versioned_request = request.name == "test_symbol" &&
                            request.version == "MOCK_ABI_1.0" &&
                            request.provider == "libc.so";
    if (saw_versioned_request) return 0x70000000ULL;
    return std::nullopt;
  };
  const auto loaded_versioned_import =
      LoadA64Elf(versioned_import, versioned_options);
  if (!loaded_versioned_import) {
    std::cerr << "[DETAIL] versioned import error: "
              << loaded_versioned_import.error << '\n';
  }
  Check(static_cast<bool>(loaded_versioned_import) && saw_versioned_request,
        "resolves a DT_VERNEED import by exact name, version and provider");
  if (loaded_versioned_import) {
    std::uint64_t actual = 0;
    Check(loaded_versioned_import.image->Read(
              loaded_versioned_import.image->load_bias + 0x1500,
              &actual, sizeof(actual)) && actual == 0x70000000ULL,
          "writes the exact-version import target into guest memory");
  }

  A64ElfLoadOptions no_versioned_resolver;
  no_versioned_resolver.resolve_symbol =
      [](const std::string&) -> std::optional<std::uint64_t> {
    return 0x11111111ULL;
  };
  const auto refused_name_only =
      LoadA64Elf(versioned_import, no_versioned_resolver);
  if (!refused_name_only) {
    std::cerr << "[DETAIL] name-only rejection error: "
              << refused_name_only.error << '\n';
  }
  Check(!refused_name_only &&
            refused_name_only.error.find(
                "unresolved AArch64 symbol: test_symbol@MOCK_ABI_1.0 from libc.so") !=
                std::string::npos,
        "refuses to bind a versioned import through a name-only resolver");

  const auto versioned_export = LoadA64Elf(BuildElfWithSymbolVersion(false));
  if (!versioned_export) {
    std::cerr << "[DETAIL] versioned export error: "
              << versioned_export.error << '\n';
  }
  Check(static_cast<bool>(versioned_export),
        "loads a DT_VERDEF versioned symbol definition");
  if (versioned_export) {
    const auto& symbols = versioned_export.image->exported_symbols;
    const auto symbol = std::find_if(
        symbols.begin(), symbols.end(),
        [](const auto& value) { return value.name == "test_symbol"; });
    Check(symbol != symbols.end() && symbol->version == "MOCK_ABI_1.0" &&
              !symbol->version_hidden,
          "retains the exact version name for an exported symbol");
  }

  const auto hidden_version_export =
      LoadA64Elf(BuildElfWithSymbolVersion(false, true));
  if (!hidden_version_export) {
    std::cerr << "[DETAIL] hidden export error: "
              << hidden_version_export.error << '\n';
  }
  Check(static_cast<bool>(hidden_version_export),
        "loads a hidden/non-default symbol version");
  if (hidden_version_export) {
    const auto& symbols = hidden_version_export.image->exported_symbols;
    const auto symbol = std::find_if(
        symbols.begin(), symbols.end(),
        [](const auto& value) { return value.name == "test_symbol"; });
    Check(symbol != symbols.end() && symbol->version_hidden,
          "preserves the DT_VERSYM hidden bit for non-default versions");
  }

  auto malformed_version_count = BuildElfWithSymbolVersion(true);
  auto version_need_num = mocktail::translation::test::ReadDynamicEntry(
      malformed_version_count, 11);
  version_need_num.d_un.d_val = 2;
  mocktail::translation::test::WriteDynamicEntry(
      malformed_version_count, 11, version_need_num);
  const auto malformed_version_result = LoadA64Elf(malformed_version_count);
  if (malformed_version_result.error.find(
          "DT_VERNEED chain ends before DT_VERNEEDNUM") == std::string::npos) {
    std::cerr << "[DETAIL] malformed version count error: "
              << malformed_version_result.error << '\n';
  }
  Check(!malformed_version_result &&
            malformed_version_result.error.find(
                "DT_VERNEED chain ends before DT_VERNEEDNUM") !=
                std::string::npos,
        "rejects version requirement chains shorter than their count");

  auto init_fini = BuildElfWithInitializers();
  const auto loaded_init_fini = LoadA64Elf(init_fini);
  Check(static_cast<bool>(loaded_init_fini),
        "loads dynamic initializer/finalizer metadata");
  if (loaded_init_fini) {
    const auto& image = *loaded_init_fini.image;
    Check(image.initializers ==
              std::vector<std::uint64_t>{image.load_bias + 0x1004,
                                         image.load_bias + 0x1008},
          "collects DT_INIT before relocated DT_INIT_ARRAY entries");
    Check(image.finalizers ==
              std::vector<std::uint64_t>{image.load_bias + 0x1010,
                                         image.load_bias + 0x1014},
          "reverses DT_FINI_ARRAY entries before DT_FINI");
  }

  auto malformed_init_array = init_fini;
  auto init_array_size = mocktail::translation::test::ReadDynamicEntry(
      malformed_init_array, 12);
  init_array_size.d_tag = DT_DEBUG;
  mocktail::translation::test::WriteDynamicEntry(
      malformed_init_array, 12, init_array_size);
  const auto malformed_init_result = LoadA64Elf(malformed_init_array);
  Check(!malformed_init_result &&
            malformed_init_result.error.find(
                "DT_INIT_ARRAY and its size tag must be provided together") !=
                std::string::npos,
        "rejects an initializer array missing its size tag");

  auto invalid_init_pointer = init_fini;
  Elf64_Rela invalid_fini_relocation{};
  std::memcpy(&invalid_fini_relocation,
              invalid_init_pointer.data() + 0x1118,
              sizeof(invalid_fini_relocation));
  invalid_fini_relocation.r_addend = 0x3000;
  std::memcpy(invalid_init_pointer.data() + 0x1118,
              &invalid_fini_relocation, sizeof(invalid_fini_relocation));
  const auto invalid_init_result = LoadA64Elf(invalid_init_pointer);
  Check(!invalid_init_result &&
            invalid_init_result.error.find(
                "DT_FINI_ARRAY contains an entry outside executable") !=
                std::string::npos,
        "rejects initializer/finalizer pointers outside executable memory");

  auto unsupported_relocation =
      mocktail::translation::test::BuildA64ElfWithRelativeRelocation(
          R_AARCH64_IRELATIVE);
  const auto unsupported_result = LoadA64Elf(unsupported_relocation);
  Check(!unsupported_result &&
            unsupported_result.error.find("unsupported AArch64 dynamic relocation") !=
                std::string::npos,
        "fails closed for IRELATIVE relocations requiring guest execution");

  auto bad_relocation_target =
      mocktail::translation::test::BuildA64ElfWithRelativeRelocation(
          R_AARCH64_RELATIVE, 0x3000);
  const auto bad_target_result = LoadA64Elf(bad_relocation_target);
  Check(!bad_target_result &&
            bad_target_result.error.find("writable PT_LOAD") != std::string::npos,
        "rejects relocations targeting unmapped guest memory");

  auto invalid_rela_entry_size =
      mocktail::translation::test::BuildA64ElfWithRelativeRelocation();
  auto relaent = mocktail::translation::test::ReadDynamicEntry(
      invalid_rela_entry_size, 2);
  relaent.d_un.d_val = 1;
  mocktail::translation::test::WriteDynamicEntry(
      invalid_rela_entry_size, 2, relaent);
  ExpectRejected(invalid_rela_entry_size,
                 "rejects malformed DT_RELAENT metadata");

  auto unterminated_dynamic =
      mocktail::translation::test::BuildA64ElfWithRelativeRelocation();
  auto last_dynamic = mocktail::translation::test::ReadDynamicEntry(
      unterminated_dynamic, 10);
  last_dynamic.d_tag = DT_DEBUG;
  mocktail::translation::test::WriteDynamicEntry(
      unterminated_dynamic, 10, last_dynamic);
  const auto unterminated_result = LoadA64Elf(unterminated_dynamic);
  Check(!unterminated_result &&
            unterminated_result.error.find("does not end with DT_NULL") !=
                std::string::npos,
        "rejects a dynamic table without DT_NULL");

  ExpectRejected({}, "rejects a truncated ELF header");
  auto wrong_machine = valid;
  auto header = ReadElfHeader(wrong_machine);
  header.e_machine = EM_X86_64;
  WriteElfHeader(wrong_machine, header);
  ExpectRejected(wrong_machine, "rejects a non-AArch64 ELF");

  auto wrong_class = valid;
  wrong_class[EI_CLASS] = ELFCLASS32;
  ExpectRejected(wrong_class, "rejects a non-ELF64 image");

  auto wrong_endian = valid;
  wrong_endian[EI_DATA] = ELFDATA2MSB;
  ExpectRejected(wrong_endian, "rejects a big-endian ELF");

  auto unsupported_type = valid;
  header = ReadElfHeader(unsupported_type);
  header.e_type = ET_REL;
  WriteElfHeader(unsupported_type, header);
  ExpectRejected(unsupported_type, "rejects relocatable ET_REL objects");

  auto truncated_program_headers = valid;
  truncated_program_headers.resize(sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) - 1);
  ExpectRejected(truncated_program_headers,
                 "rejects a truncated program-header table");

  auto file_larger_than_memory = valid;
  auto program_header = ReadProgramHeader(file_larger_than_memory);
  program_header.p_memsz = 4;
  WriteProgramHeader(file_larger_than_memory, program_header);
  ExpectRejected(file_larger_than_memory, "rejects p_filesz greater than p_memsz");

  auto bad_alignment = valid;
  program_header = ReadProgramHeader(bad_alignment);
  program_header.p_align = 3;
  WriteProgramHeader(bad_alignment, program_header);
  ExpectRejected(bad_alignment, "rejects non-power-of-two p_align");

  auto bad_entry = BuildMinimalA64Elf(ET_DYN, PF_R | PF_W, 0x1000);
  ExpectRejected(bad_entry, "rejects an entry point outside executable memory");

  auto no_loadable_segment = valid;
  program_header = ReadProgramHeader(no_loadable_segment);
  program_header.p_type = PT_NOTE;
  WriteProgramHeader(no_loadable_segment, program_header);
  ExpectRejected(no_loadable_segment, "rejects an ELF with no PT_LOAD segment");

  A64ElfLoadOptions tiny_limit;
  tiny_limit.max_image_size = 2048;
  ExpectRejected(valid, "enforces the configured image-span limit", tiny_limit);

  auto overflowing_segment = valid;
  program_header = ReadProgramHeader(overflowing_segment);
  program_header.p_vaddr = UINT64_MAX - 8;
  program_header.p_memsz = 16;
  WriteProgramHeader(overflowing_segment, program_header);
  ExpectRejected(overflowing_segment, "rejects virtual-address overflow");

  std::cout << failures << " loader test(s) failed\n";
  return failures == 0 ? 0 : 1;
}
