// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_elf_loader.h"

#include <elf.h>

#include <array>
#include <cstdint>
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
      unterminated_dynamic, 7, last_dynamic);
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
