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
