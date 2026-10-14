// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_elf_loader.h"

#include <elf.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

namespace mocktail::translation {
namespace {

constexpr std::uint64_t kGuestPageSize = 4096;

A64ElfLoadResult Failure(std::string message) {
  return A64ElfLoadResult{std::nullopt, std::move(message)};
}

bool AddOverflows(std::uint64_t left, std::uint64_t right) noexcept {
  return right > std::numeric_limits<std::uint64_t>::max() - left;
}

bool IsPowerOfTwo(std::uint64_t value) noexcept {
  return value != 0 && (value & (value - 1)) == 0;
}

std::uint64_t AlignDown(std::uint64_t value,
                        std::uint64_t alignment) noexcept {
  return value & ~(alignment - 1);
}

bool AlignUp(std::uint64_t value, std::uint64_t alignment,
             std::uint64_t* result) noexcept {
  const std::uint64_t mask = alignment - 1;
  if (AddOverflows(value, mask)) return false;
  *result = (value + mask) & ~mask;
  return true;
}

bool FileRangeWithin(std::uint64_t offset, std::uint64_t length,
                     std::size_t file_size) noexcept {
  if (offset > file_size) return false;
  return length <= static_cast<std::uint64_t>(file_size) - offset;
}

}  // namespace

bool A64LoadedImage::Read(std::uint64_t address, void* destination,
                          std::size_t length) const noexcept {
  if (length == 0) return true;
  if (destination == nullptr ||
      AddOverflows(address, static_cast<std::uint64_t>(length))) {
    return false;
  }

  auto* output = static_cast<std::uint8_t*>(destination);
  std::size_t copied = 0;
  std::uint64_t current = address;
  while (copied < length) {
    const A64LoadSegment* containing = nullptr;
    std::uint64_t offset = 0;
    for (const auto& segment : segments) {
      if (current < segment.guest_address) continue;
      const std::uint64_t candidate = current - segment.guest_address;
      if (candidate < segment.bytes.size()) {
        containing = &segment;
        offset = candidate;
        break;
      }
    }
    if (containing == nullptr) return false;

    const auto available =
        containing->bytes.size() - static_cast<std::size_t>(offset);
    const auto count = std::min(length - copied, available);
    std::memcpy(output + copied, containing->bytes.data() + offset, count);
    copied += count;
    current += static_cast<std::uint64_t>(count);
  }
  return true;
}

bool A64LoadedImage::Write(std::uint64_t address, const void* source,
                           std::size_t length) noexcept {
  if (length == 0) return true;
  if (source == nullptr ||
      AddOverflows(address, static_cast<std::uint64_t>(length))) {
    return false;
  }

  for (auto& segment : segments) {
    if (address < segment.guest_address) continue;
    const std::uint64_t offset = address - segment.guest_address;
    if (offset > segment.bytes.size()) continue;
    if (length > segment.bytes.size() - static_cast<std::size_t>(offset)) {
      continue;
    }
    if ((segment.flags & PF_W) == 0) return false;
    std::memcpy(segment.bytes.data() + offset, source, length);
    return true;
  }
  return false;
}

bool A64LoadedImage::IsExecutable(std::uint64_t address,
                                  std::size_t length) const noexcept {
  if (length == 0 || AddOverflows(address, static_cast<std::uint64_t>(length))) {
    return false;
  }
  for (const auto& segment : segments) {
    if ((segment.flags & PF_X) == 0 || address < segment.guest_address) {
      continue;
    }
    const std::uint64_t offset = address - segment.guest_address;
    if (offset <= segment.bytes.size() &&
        length <= segment.bytes.size() - static_cast<std::size_t>(offset)) {
      return true;
    }
  }
  return false;
}

A64ElfLoadResult LoadA64Elf(const std::vector<std::uint8_t>& file,
                            A64ElfLoadOptions options) {
  if (options.max_image_size == 0 || options.max_program_headers == 0) {
    return Failure("ELF load limits must be greater than zero");
  }
  if (file.size() < sizeof(Elf64_Ehdr)) {
    return Failure("file is shorter than an ELF64 header");
  }

  Elf64_Ehdr header{};
  std::memcpy(&header, file.data(), sizeof(header));
  if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) {
    return Failure("invalid ELF magic");
  }
  if (header.e_ident[EI_CLASS] != ELFCLASS64) {
    return Failure("ELF class is not ELF64");
  }
  if (header.e_ident[EI_DATA] != ELFDATA2LSB) {
    return Failure("only little-endian ELF files are supported");
  }
  if (header.e_ident[EI_VERSION] != EV_CURRENT ||
      header.e_version != EV_CURRENT) {
    return Failure("unsupported ELF version");
  }
  if (header.e_machine != EM_AARCH64) {
    return Failure("ELF machine is not AArch64");
  }
  if (header.e_type != ET_DYN && header.e_type != ET_EXEC) {
    return Failure("only ET_DYN and ET_EXEC ELF files are supported");
  }
  if (header.e_ehsize < sizeof(Elf64_Ehdr)) {
    return Failure("ELF header size is smaller than Elf64_Ehdr");
  }
  if (header.e_phnum == 0 || header.e_phnum == PN_XNUM) {
    return Failure("ELF has no supported program-header table");
  }
  if (header.e_phnum > options.max_program_headers) {
    return Failure("ELF program-header count exceeds the configured limit");
  }
  if (header.e_phentsize < sizeof(Elf64_Phdr)) {
    return Failure("ELF program-header entry is too small");
  }

  const std::uint64_t table_size =
      static_cast<std::uint64_t>(header.e_phnum) * header.e_phentsize;
  if (!FileRangeWithin(header.e_phoff, table_size, file.size())) {
    return Failure("ELF program-header table is truncated or out of bounds");
  }

  std::vector<Elf64_Phdr> load_headers;
  load_headers.reserve(header.e_phnum);
  std::uint64_t minimum_virtual_address =
      std::numeric_limits<std::uint64_t>::max();
  std::uint64_t maximum_virtual_end = 0;
  std::uint64_t maximum_alignment = kGuestPageSize;
  std::uint64_t aggregate_memory_size = 0;

  for (std::uint16_t index = 0; index < header.e_phnum; ++index) {
    const auto offset = header.e_phoff +
                        static_cast<std::uint64_t>(index) *
                            header.e_phentsize;
    Elf64_Phdr program_header{};
    std::memcpy(&program_header, file.data() + offset,
                sizeof(program_header));
    if (program_header.p_type != PT_LOAD) continue;

    if (program_header.p_memsz == 0) {
      if (program_header.p_filesz != 0) {
        return Failure("PT_LOAD has file bytes but zero memory size");
      }
      continue;
    }
    if (program_header.p_filesz > program_header.p_memsz) {
      return Failure("PT_LOAD p_filesz exceeds p_memsz");
    }
    if (!FileRangeWithin(program_header.p_offset, program_header.p_filesz,
                         file.size())) {
      return Failure("PT_LOAD file range is out of bounds");
    }
    if (AddOverflows(program_header.p_vaddr, program_header.p_memsz)) {
      return Failure("PT_LOAD virtual-address range overflows");
    }

    const std::uint64_t alignment = program_header.p_align;
    if (alignment > 1) {
      if (!IsPowerOfTwo(alignment)) {
        return Failure("PT_LOAD p_align is not a power of two");
      }
      if ((program_header.p_vaddr % alignment) !=
          (program_header.p_offset % alignment)) {
        return Failure("PT_LOAD file offset and virtual address are misaligned");
      }
      maximum_alignment = std::max(maximum_alignment, alignment);
    }

    const auto next_total = program_header.p_memsz;
    if (next_total > options.max_image_size ||
        aggregate_memory_size >
            static_cast<std::uint64_t>(options.max_image_size) - next_total) {
      return Failure("aggregate PT_LOAD memory exceeds the configured limit");
    }
    aggregate_memory_size += next_total;
    minimum_virtual_address =
        std::min(minimum_virtual_address, program_header.p_vaddr);
    maximum_virtual_end =
        std::max(maximum_virtual_end,
                 program_header.p_vaddr + program_header.p_memsz);
    load_headers.push_back(program_header);
  }

  if (load_headers.empty()) {
    return Failure("ELF contains no non-empty PT_LOAD segments");
  }

  const auto minimum_page = AlignDown(minimum_virtual_address, kGuestPageSize);
  std::uint64_t maximum_page = 0;
  if (!AlignUp(maximum_virtual_end, kGuestPageSize, &maximum_page)) {
    return Failure("ELF image end overflows while aligning to a guest page");
  }
  if (maximum_page <= minimum_page) {
    return Failure("ELF has an empty or invalid loadable address range");
  }
  const auto image_size = maximum_page - minimum_page;
  if (image_size > options.max_image_size) {
    return Failure("ELF image span exceeds the configured limit");
  }

  std::uint64_t load_bias = 0;
  if (header.e_type == ET_DYN) {
    std::uint64_t mapped_origin = 0;
    if (!AlignUp(options.preferred_base, maximum_alignment, &mapped_origin)) {
      return Failure("configured preferred guest base overflows");
    }
    const auto aligned_virtual_origin =
        AlignDown(minimum_virtual_address, maximum_alignment);
    if (mapped_origin < aligned_virtual_origin) {
      return Failure("preferred guest base is below the ELF virtual origin");
    }
    load_bias = mapped_origin - aligned_virtual_origin;
  }

  A64LoadedImage image;
  image.load_bias = load_bias;
  image.image_size = image_size;
  if (AddOverflows(minimum_page, load_bias)) {
    return Failure("relocated image base overflows the guest address space");
  }
  image.base_address = minimum_page + load_bias;
  if (AddOverflows(image.base_address, image.image_size)) {
    return Failure("relocated image range overflows the guest address space");
  }
  if (header.e_entry != 0) {
    if (AddOverflows(header.e_entry, load_bias)) {
      return Failure("ELF entry-point relocation overflows");
    }
    image.entry_point = header.e_entry + load_bias;
  }

  try {
    image.segments.reserve(load_headers.size());
    for (const auto& program_header : load_headers) {
      if (AddOverflows(program_header.p_vaddr, load_bias)) {
        return Failure("relocated PT_LOAD address overflows");
      }
      A64LoadSegment segment;
      segment.virtual_address = program_header.p_vaddr;
      segment.guest_address = program_header.p_vaddr + load_bias;
      segment.flags = program_header.p_flags;
      segment.bytes.resize(static_cast<std::size_t>(program_header.p_memsz), 0);
      if (program_header.p_filesz != 0) {
        std::memcpy(segment.bytes.data(),
                    file.data() + program_header.p_offset,
                    static_cast<std::size_t>(program_header.p_filesz));
      }
      image.segments.push_back(std::move(segment));
    }
  } catch (const std::bad_alloc&) {
    return Failure("not enough host memory to allocate the bounded ELF image");
  }

  std::sort(image.segments.begin(), image.segments.end(),
            [](const A64LoadSegment& left, const A64LoadSegment& right) {
              return left.guest_address < right.guest_address;
            });
  for (std::size_t index = 1; index < image.segments.size(); ++index) {
    const auto& previous = image.segments[index - 1];
    const auto& current = image.segments[index];
    if (AddOverflows(previous.guest_address, previous.bytes.size()) ||
        previous.guest_address + previous.bytes.size() >
            current.guest_address) {
      return Failure("PT_LOAD memory ranges overlap");
    }
  }

  if (image.entry_point != 0) {
    if ((image.entry_point & 3U) != 0) {
      return Failure("AArch64 ELF entry point is not 4-byte aligned");
    }
    if (!image.IsExecutable(image.entry_point, sizeof(std::uint32_t))) {
      return Failure("ELF entry point is outside an executable PT_LOAD segment");
    }
  }

  return A64ElfLoadResult{std::move(image), {}};
}

}  // namespace mocktail::translation
