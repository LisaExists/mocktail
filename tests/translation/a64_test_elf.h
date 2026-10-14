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
    std::uint64_t memory_size = 16,
    std::uint64_t alignment = 0x1000) {
  constexpr std::size_t kCodeOffset = 0x1000;
  constexpr std::uint64_t kFileCodeSize = 8;
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

  // MOVZ X0, #42; BRK #0. Instructions are encoded in little-endian order.
  const std::uint8_t code[] = {
      0x40, 0x05, 0x80, 0xD2,
      0x00, 0x00, 0x20, 0xD4,
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
    std::int64_t relocation_addend = 0x1000) {
  constexpr std::size_t kLoadOffset = 0x1000;
  constexpr std::size_t kRelaOffset = 0x1100;
  constexpr std::size_t kDynamicOffset = 0x1140;
  constexpr std::size_t kStringOffset = 0x1200;
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
  dynamic_header.p_filesz = 8 * sizeof(Elf64_Dyn);
  dynamic_header.p_memsz = dynamic_header.p_filesz;
  dynamic_header.p_align = alignof(Elf64_Dyn);
  std::memcpy(file.data() + header.e_phoff + sizeof(Elf64_Phdr),
              &dynamic_header, sizeof(dynamic_header));

  Elf64_Rela relocation{};
  relocation.r_offset = relocation_target;
  relocation.r_info = ELF64_R_INFO(0, relocation_type);
  relocation.r_addend = relocation_addend;
  std::memcpy(file.data() + kRelaOffset, &relocation, sizeof(relocation));

  Elf64_Dyn dynamic[8]{};
  dynamic[0].d_tag = DT_RELA;
  dynamic[0].d_un.d_ptr = kRelaOffset;
  dynamic[1].d_tag = DT_RELASZ;
  dynamic[1].d_un.d_val = sizeof(Elf64_Rela);
  dynamic[2].d_tag = DT_RELAENT;
  dynamic[2].d_un.d_val = sizeof(Elf64_Rela);
  dynamic[3].d_tag = DT_STRTAB;
  dynamic[3].d_un.d_ptr = kStringOffset;
  dynamic[4].d_tag = DT_STRSZ;
  const char strings[] = "\0libc.so\0libmock.so";
  dynamic[4].d_un.d_val = sizeof(strings);
  dynamic[5].d_tag = DT_NEEDED;
  dynamic[5].d_un.d_val = 1;
  dynamic[6].d_tag = DT_SONAME;
  dynamic[6].d_un.d_val = 9;
  dynamic[7].d_tag = DT_NULL;
  std::memcpy(file.data() + kDynamicOffset, dynamic, sizeof(dynamic));
  std::memcpy(file.data() + kStringOffset, strings, sizeof(strings));
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
