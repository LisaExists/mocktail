// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#ifndef MOCKTAIL_TESTS_TRANSLATION_A64_TEST_ELF_H_
#define MOCKTAIL_TESTS_TRANSLATION_A64_TEST_ELF_H_

#include <elf.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace mocktail::translation::test {

inline std::vector<std::uint8_t> BuildMinimalA64Elf(
    std::uint16_t elf_type = ET_DYN,
    std::uint32_t segment_flags = PF_R | PF_X,
    std::uint64_t entry_point = 0x1000,
    std::uint64_t virtual_address = 0x1000,
    std::uint64_t memory_size = 32,
    std::uint64_t alignment = 0x1000) {
  constexpr std::size_t kCodeOffset = 0x1000;
  constexpr std::uint64_t kFileCodeSize = 24;
  std::vector<std::uint8_t> file(kCodeOffset + kFileCodeSize, 0);

  Elf64_Ehdr header{};
  std::memcpy(header.e_ident, ELFMAG, SELFMAG);
  header.e_ident[EI_CLASS] = ELFCLASS64;
  header.e_ident[EI_DATA] = ELFDATA2LSB;
  header.e_ident[EI_VERSION] = EV_CURRENT;
  header.e_type = elf_type;
  header.e_machine = EM_AARCH64;
  header.e_version = EV_CURRENT;
  header.e_entry = entry_point;
  header.e_phoff = sizeof(Elf64_Ehdr);
  header.e_ehsize = sizeof(Elf64_Ehdr);
  header.e_phentsize = sizeof(Elf64_Phdr);
  header.e_phnum = 1;
  std::memcpy(file.data(), &header, sizeof(header));

  Elf64_Phdr program_header{};
  program_header.p_type = PT_LOAD;
  program_header.p_flags = segment_flags;
  program_header.p_offset = kCodeOffset;
  program_header.p_vaddr = virtual_address;
  program_header.p_filesz = kFileCodeSize;
  program_header.p_memsz = memory_size;
  program_header.p_align = alignment;
  std::memcpy(file.data() + header.e_phoff, &program_header,
              sizeof(program_header));

  // MOVZ X0, #42; SUB SP, SP, #16; STR X0, [SP]; LDR X1, [SP];
  // ADD SP, SP, #16; BRK #0. Encoded little-endian.
  const std::uint8_t code[] = {
      0x40, 0x05, 0x80, 0xD2,  // mov x0, #42
      0xFF, 0x43, 0x00, 0xD1,  // sub sp, sp, #16
      0xE0, 0x03, 0x00, 0xF9,  // str x0, [sp]
      0xE1, 0x03, 0x40, 0xF9,  // ldr x1, [sp]
      0xFF, 0x43, 0x00, 0x91,  // add sp, sp, #16
      0x00, 0x00, 0x20, 0xD4,  // brk #0
  };
  std::memcpy(file.data() + kCodeOffset, code, sizeof(code));
  return file;
}

inline Elf64_Ehdr ReadElfHeader(const std::vector<std::uint8_t>& file);
inline void WriteElfHeader(std::vector<std::uint8_t>& file,
                           const Elf64_Ehdr& header);
inline Elf64_Phdr ReadProgramHeader(
    const std::vector<std::uint8_t>& file);
inline void WriteProgramHeader(std::vector<std::uint8_t>& file,
                               const Elf64_Phdr& program_header);

inline std::vector<std::uint8_t> BuildA64ElfWithRelativeRelocation(
    std::uint32_t relocation_type = R_AARCH64_RELATIVE,
    std::uint64_t relocation_target = 0x1500,
    std::int64_t relocation_addend = 0x1000,
    std::uint64_t relocation_symbol = 0,
    bool undefined_symbol = false,
    bool use_plt_relocation = false) {
  constexpr std::size_t kLoadOffset = 0x1000;
  constexpr std::size_t kRelaOffset = 0x1100;
  constexpr std::size_t kDynamicOffset = 0x1140;
  constexpr std::size_t kStringOffset = 0x1300;
  constexpr std::size_t kHashOffset = 0x1340;
  constexpr std::size_t kSymbolOffset = 0x1380;
  auto file = BuildMinimalA64Elf(
      ET_DYN, PF_R | PF_W | PF_X, 0x1000, 0x1000, 0x1000, 0x1000);
  file.resize(kLoadOffset + 0x1000, 0);

  auto header = ReadElfHeader(file);
  header.e_phnum = 2;
  WriteElfHeader(file, header);

  auto load = ReadProgramHeader(file);
  load.p_offset = kLoadOffset;
  load.p_vaddr = 0x1000;
  load.p_filesz = 0x1000;
  load.p_memsz = 0x1000;
  load.p_flags = PF_R | PF_W | PF_X;
  load.p_align = 0x1000;
  WriteProgramHeader(file, load);

  Elf64_Phdr dynamic_header{};
  dynamic_header.p_type = PT_DYNAMIC;
  dynamic_header.p_flags = PF_R | PF_W;
  dynamic_header.p_offset = kDynamicOffset;
  dynamic_header.p_vaddr = kDynamicOffset;
  dynamic_header.p_filesz = (use_plt_relocation ? 14 : 11) * sizeof(Elf64_Dyn);
  dynamic_header.p_memsz = dynamic_header.p_filesz;
  dynamic_header.p_align = alignof(Elf64_Dyn);
  std::memcpy(file.data() + header.e_phoff + sizeof(Elf64_Phdr),
              &dynamic_header, sizeof(dynamic_header));

  Elf64_Rela relocation{};
  relocation.r_offset = relocation_target;
  relocation.r_info = ELF64_R_INFO(relocation_symbol, relocation_type);
  relocation.r_addend = relocation_addend;
  std::memcpy(file.data() + kRelaOffset, &relocation, sizeof(relocation));

  Elf64_Dyn dynamic[14]{};
  dynamic[0].d_tag = DT_RELA;
  dynamic[0].d_un.d_ptr = kRelaOffset;
  dynamic[1].d_tag = DT_RELASZ;
  dynamic[1].d_un.d_val =
      use_plt_relocation ? 0 : sizeof(Elf64_Rela);
  dynamic[2].d_tag = DT_RELAENT;
  dynamic[2].d_un.d_val = sizeof(Elf64_Rela);
  dynamic[3].d_tag = DT_STRTAB;
  dynamic[3].d_un.d_ptr = kStringOffset;
  dynamic[4].d_tag = DT_STRSZ;
  const char strings[] = "\0libc.so\0libmock.so\0test_symbol";
  dynamic[4].d_un.d_val = sizeof(strings);
  dynamic[5].d_tag = DT_NEEDED;
  dynamic[5].d_un.d_val = 1;
  dynamic[6].d_tag = DT_SONAME;
  dynamic[6].d_un.d_val = 9;
  dynamic[7].d_tag = DT_SYMTAB;
  dynamic[7].d_un.d_ptr = kSymbolOffset;
  dynamic[8].d_tag = DT_SYMENT;
  dynamic[8].d_un.d_val = sizeof(Elf64_Sym);
  dynamic[9].d_tag = DT_HASH;
  dynamic[9].d_un.d_ptr = kHashOffset;
  std::size_t dynamic_count = 11;
  if (use_plt_relocation) {
    dynamic[10].d_tag = DT_JMPREL;
    dynamic[10].d_un.d_ptr = kRelaOffset;
    dynamic[11].d_tag = DT_PLTRELSZ;
    dynamic[11].d_un.d_val = sizeof(Elf64_Rela);
    dynamic[12].d_tag = DT_PLTREL;
    dynamic[12].d_un.d_val = DT_RELA;
    dynamic_count = 14;
  }
  dynamic[dynamic_count - 1].d_tag = DT_NULL;
  std::memcpy(file.data() + kDynamicOffset, dynamic,
              dynamic_count * sizeof(Elf64_Dyn));
  std::memcpy(file.data() + kStringOffset, strings, sizeof(strings));

  const std::uint32_t hash[] = {1, 2, 1, 0, 0};
  std::memcpy(file.data() + kHashOffset, hash, sizeof(hash));
  Elf64_Sym symbols[2]{};
  symbols[1].st_name = 20;
  symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
  symbols[1].st_shndx = undefined_symbol ? SHN_UNDEF : SHN_ABS;
  symbols[1].st_value = 0x123456789ULL;
  std::memcpy(file.data() + kSymbolOffset, symbols, sizeof(symbols));
  return file;
}

inline Elf64_Dyn ReadDynamicEntry(
    const std::vector<std::uint8_t>& file, std::size_t index);
inline void WriteDynamicEntry(std::vector<std::uint8_t>& file,
                              std::size_t index,
                              const Elf64_Dyn& entry);

inline std::vector<std::uint8_t> BuildA64ElfWithAndroidPackedRela() {
  auto file = BuildA64ElfWithRelativeRelocation();
  constexpr std::size_t kPackedRelaOffset = 0x1100;

  // APS2 stream: one R_AARCH64_RELATIVE at 0x1500, addend 0x1000.
  // The group shares its offset delta and addend; relocation info is per-entry.
  const std::uint8_t packed[] = {
      'A', 'P', 'S', '2',
      0x01,             // relocation count = 1
      0x80, 0x2A,       // initial offset = 0x1500 (SLEB128)
      0x01,             // group size = 1
      0x0E,             // grouped offset + grouped addend + has addend
      0x00,             // offset delta = 0
      0x80, 0x20,       // addend delta = 0x1000
      0x83, 0x08,       // R_AARCH64_RELATIVE (SLEB128)
  };
  std::memcpy(file.data() + kPackedRelaOffset, packed, sizeof(packed));

  auto rela_size = ReadDynamicEntry(file, 1);
  rela_size.d_un.d_val = 0;
  WriteDynamicEntry(file, 1, rela_size);

  Elf64_Dyn android_rela{};
  android_rela.d_tag = 0x60000011;  // DT_ANDROID_RELA
  android_rela.d_un.d_ptr = kPackedRelaOffset;
  WriteDynamicEntry(file, 10, android_rela);

  Elf64_Dyn android_rela_size{};
  android_rela_size.d_tag = 0x60000012;  // DT_ANDROID_RELASZ
  android_rela_size.d_un.d_val = sizeof(packed);
  WriteDynamicEntry(file, 11, android_rela_size);

  Elf64_Dyn terminator{};
  terminator.d_tag = DT_NULL;
  WriteDynamicEntry(file, 12, terminator);

  const auto header = ReadElfHeader(file);
  Elf64_Phdr dynamic_header{};
  const std::size_t dynamic_phdr_offset =
      static_cast<std::size_t>(header.e_phoff) + sizeof(Elf64_Phdr);
  std::memcpy(&dynamic_header, file.data() + dynamic_phdr_offset,
              sizeof(dynamic_header));
  dynamic_header.p_filesz = 13 * sizeof(Elf64_Dyn);
  dynamic_header.p_memsz = dynamic_header.p_filesz;
  std::memcpy(file.data() + dynamic_phdr_offset, &dynamic_header,
              sizeof(dynamic_header));
  return file;
}

inline std::vector<std::uint8_t>
BuildA64ElfWithAndroidPackedRelaNegativeOffsetDelta() {
  auto file = BuildA64ElfWithAndroidPackedRela();
  constexpr std::size_t kPackedRelaOffset = 0x1100;
  // APS2: start at 0x1508, then apply one relocation at 0x1500 via -8.
  const std::uint8_t packed[] = {
      'A', 'P', 'S', '2',
      0x01,             // relocation count = 1
      0x88, 0x2A,       // initial offset = 0x1508
      0x01,             // group size = 1
      0x00,             // no grouped fields
      0x78,             // offset delta = -8 (valid SLEB128)
      0x83, 0x08,       // R_AARCH64_RELATIVE
  };
  std::memcpy(file.data() + kPackedRelaOffset, packed, sizeof(packed));
  auto packed_size = ReadDynamicEntry(file, 11);
  packed_size.d_un.d_val = sizeof(packed);
  WriteDynamicEntry(file, 11, packed_size);
  return file;
}

inline std::vector<std::uint8_t>
BuildA64ElfWithAndroidPackedRelaNegativeGroupedOffsetDelta() {
  auto file = BuildA64ElfWithAndroidPackedRela();
  constexpr std::size_t kPackedRelaOffset = 0x1100;
  // APS2: start at 0x1580; a grouped delta of -0x80 targets 0x1500.
  const std::uint8_t packed[] = {
      'A', 'P', 'S', '2',
      0x01,             // relocation count = 1
      0x80, 0x2B,       // initial offset = 0x1580
      0x01,             // group size = 1
      0x02,             // grouped offset delta
      0x80, 0x7F,       // grouped offset delta = -0x80
      0x83, 0x08,       // R_AARCH64_RELATIVE
  };
  std::memcpy(file.data() + kPackedRelaOffset, packed, sizeof(packed));
  auto packed_size = ReadDynamicEntry(file, 11);
  packed_size.d_un.d_val = sizeof(packed);
  WriteDynamicEntry(file, 11, packed_size);
  return file;
}

// Android-targeted linkers can retain DT_RELAENT even when they emit no
// ordinary DT_RELA/DT_RELASZ entries because all dynamic relocations are packed.
inline std::vector<std::uint8_t>
BuildA64ElfWithAndroidPackedRelaEntrySizeOnly() {
  auto file = BuildA64ElfWithAndroidPackedRela();
  std::vector<Elf64_Dyn> compact;
  for (std::size_t index = 0; index < 13; ++index) {
    const auto entry = ReadDynamicEntry(file, index);
    if (entry.d_tag == DT_RELA || entry.d_tag == DT_RELASZ) continue;
    compact.push_back(entry);
    if (entry.d_tag == DT_NULL) break;
  }
  for (std::size_t index = 0; index < compact.size(); ++index) {
    WriteDynamicEntry(file, index, compact[index]);
  }

  const auto header = ReadElfHeader(file);
  Elf64_Phdr dynamic_header{};
  const std::size_t dynamic_phdr_offset =
      static_cast<std::size_t>(header.e_phoff) + header.e_phentsize;
  std::memcpy(&dynamic_header, file.data() + dynamic_phdr_offset,
              sizeof(dynamic_header));
  dynamic_header.p_filesz = compact.size() * sizeof(Elf64_Dyn);
  dynamic_header.p_memsz = dynamic_header.p_filesz;
  std::memcpy(file.data() + dynamic_phdr_offset, &dynamic_header,
              sizeof(dynamic_header));
  return file;
}

inline std::vector<std::uint8_t> BuildA64ElfWithRelrRelocation() {
  auto file = BuildA64ElfWithRelativeRelocation();
  constexpr std::size_t kRelrOffset = 0x1100;
  constexpr std::size_t kRelocationTargetOffset = 0x1500;
  constexpr std::uint64_t kRelocationTarget = 0x1500;
  constexpr std::uint64_t kAddend = 0x1000;

  std::memcpy(file.data() + kRelrOffset, &kRelocationTarget,
              sizeof(kRelocationTarget));
  std::memcpy(file.data() + kRelocationTargetOffset, &kAddend, sizeof(kAddend));

  auto rela_size = ReadDynamicEntry(file, 1);
  rela_size.d_un.d_val = 0;
  WriteDynamicEntry(file, 1, rela_size);

  Elf64_Dyn relr{};
  relr.d_tag = 36;  // DT_RELR
  relr.d_un.d_ptr = kRelrOffset;
  WriteDynamicEntry(file, 10, relr);

  Elf64_Dyn relr_size{};
  relr_size.d_tag = 35;  // DT_RELRSZ
  relr_size.d_un.d_val = sizeof(std::uint64_t);
  WriteDynamicEntry(file, 11, relr_size);

  Elf64_Dyn relr_entry_size{};
  relr_entry_size.d_tag = 37;  // DT_RELRENT
  relr_entry_size.d_un.d_val = sizeof(std::uint64_t);
  WriteDynamicEntry(file, 12, relr_entry_size);

  Elf64_Dyn terminator{};
  terminator.d_tag = DT_NULL;
  WriteDynamicEntry(file, 13, terminator);

  const auto header = ReadElfHeader(file);
  Elf64_Phdr dynamic_header{};
  const std::size_t dynamic_phdr_offset =
      static_cast<std::size_t>(header.e_phoff) + sizeof(Elf64_Phdr);
  std::memcpy(&dynamic_header, file.data() + dynamic_phdr_offset,
              sizeof(dynamic_header));
  dynamic_header.p_filesz = 14 * sizeof(Elf64_Dyn);
  dynamic_header.p_memsz = dynamic_header.p_filesz;
  std::memcpy(file.data() + dynamic_phdr_offset, &dynamic_header,
              sizeof(dynamic_header));
  return file;
}

inline Elf64_Dyn ReadDynamicEntry(
    const std::vector<std::uint8_t>& file, std::size_t index) {
  Elf64_Dyn entry{};
  const std::size_t offset = 0x1140 + index * sizeof(Elf64_Dyn);
  if (offset <= file.size() && sizeof(entry) <= file.size() - offset) {
    std::memcpy(&entry, file.data() + offset, sizeof(entry));
  }
  return entry;
}

inline void WriteDynamicEntry(std::vector<std::uint8_t>& file,
                              std::size_t index,
                              const Elf64_Dyn& entry) {
  const std::size_t offset = 0x1140 + index * sizeof(Elf64_Dyn);
  if (offset <= file.size() && sizeof(entry) <= file.size() - offset) {
    std::memcpy(file.data() + offset, &entry, sizeof(entry));
  }
}

inline std::vector<std::uint8_t> BuildA64ElfWithSymbolVersion(
    bool undefined_symbol, bool hidden_version = false) {
  auto file = BuildA64ElfWithRelativeRelocation(
      undefined_symbol ? R_AARCH64_GLOB_DAT : R_AARCH64_RELATIVE,
      0x1500, 0, undefined_symbol ? 1 : 0, undefined_symbol);
  const char strings[] =
      "\0libc.so\0libmock.so\0test_symbol\0MOCK_ABI_1.0";
  std::memcpy(file.data() + 0x1300, strings, sizeof(strings));
  auto strsz = ReadDynamicEntry(file, 4);
  strsz.d_un.d_val = sizeof(strings);
  WriteDynamicEntry(file, 4, strsz);

  auto write_dynamic = [&](std::size_t index, std::int64_t tag,
                           std::uint64_t value) {
    Elf64_Dyn entry{};
    entry.d_tag = tag;
    entry.d_un.d_val = value;
    WriteDynamicEntry(file, index, entry);
  };
  // The string table begins with a NUL byte, so this prefix length is the
  // correct byte offset of MOCK_ABI_1.0 (strstr cannot scan this table).
  constexpr std::uint32_t kVersionNameOffset =
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
    std::memcpy(file.data() + 0x1400, &need, sizeof(need));

    Elf64_Vernaux auxiliary{};
    auxiliary.vna_other = 2;
    auxiliary.vna_name = kVersionNameOffset;
    std::memcpy(file.data() + 0x1400 + sizeof(need), &auxiliary,
                sizeof(auxiliary));
    write_dynamic(10, 0x6ffffffe, 0x1400);  // DT_VERNEED
    write_dynamic(11, 0x6fffffff, 1);       // DT_VERNEEDNUM
  } else {
    Elf64_Verdef definition{};
    definition.vd_version = VER_DEF_CURRENT;
    definition.vd_ndx = 2;
    definition.vd_cnt = 1;
    definition.vd_aux = sizeof(Elf64_Verdef);
    std::memcpy(file.data() + 0x1400, &definition, sizeof(definition));

    Elf64_Verdaux auxiliary{};
    auxiliary.vda_name = kVersionNameOffset;
    std::memcpy(file.data() + 0x1400 + sizeof(definition), &auxiliary,
                sizeof(auxiliary));
    write_dynamic(10, 0x6ffffffc, 0x1400);  // DT_VERDEF
    write_dynamic(11, 0x6ffffffd, 1);       // DT_VERDEFNUM
  }
  write_dynamic(12, DT_VERSYM, 0x13c0);
  write_dynamic(13, DT_NULL, 0);

  const auto header = ReadElfHeader(file);
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

inline Elf64_Ehdr ReadElfHeader(const std::vector<std::uint8_t>& file) {
  Elf64_Ehdr header{};
  if (file.size() >= sizeof(header)) {
    std::memcpy(&header, file.data(), sizeof(header));
  }
  return header;
}

inline void WriteElfHeader(std::vector<std::uint8_t>& file,
                           const Elf64_Ehdr& header) {
  if (file.size() >= sizeof(header)) {
    std::memcpy(file.data(), &header, sizeof(header));
  }
}

inline Elf64_Phdr ReadProgramHeader(
    const std::vector<std::uint8_t>& file) {
  const auto header = ReadElfHeader(file);
  Elf64_Phdr program_header{};
  if (header.e_phoff <= file.size() &&
      sizeof(program_header) <= file.size() - header.e_phoff) {
    std::memcpy(&program_header, file.data() + header.e_phoff,
                sizeof(program_header));
  }
  return program_header;
}

inline void WriteProgramHeader(std::vector<std::uint8_t>& file,
                               const Elf64_Phdr& program_header) {
  const auto header = ReadElfHeader(file);
  if (header.e_phoff <= file.size() &&
      sizeof(program_header) <= file.size() - header.e_phoff) {
    std::memcpy(file.data() + header.e_phoff, &program_header,
                sizeof(program_header));
  }
}

}  // namespace mocktail::translation::test

#endif  // MOCKTAIL_TESTS_TRANSLATION_A64_TEST_ELF_H_
