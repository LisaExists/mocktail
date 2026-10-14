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

bool AddSignedOffset(std::uint64_t base, std::int64_t offset,
                     std::uint64_t* result) noexcept {
  if (offset >= 0) {
    const auto positive = static_cast<std::uint64_t>(offset);
    if (AddOverflows(base, positive)) return false;
    *result = base + positive;
    return true;
  }

  // Avoid negating INT64_MIN directly.
  const auto magnitude =
      static_cast<std::uint64_t>(-(offset + 1)) + 1U;
  if (base < magnitude) return false;
  *result = base - magnitude;
  return true;
}

struct DynamicMetadata final {
  std::optional<std::uint64_t> rela_address;
  std::optional<std::uint64_t> rela_size;
  std::optional<std::uint64_t> rela_entry_size;
  std::optional<std::uint64_t> strtab_address;
  std::optional<std::uint64_t> strtab_size;
  std::optional<std::uint64_t> soname_offset;
  std::vector<std::uint64_t> needed_offsets;
  std::optional<std::uint64_t> jmprel_address;
  std::optional<std::uint64_t> plt_relocation_size;
  std::optional<std::uint64_t> plt_relocation_type;
  std::optional<std::uint64_t> rel_address;
  std::optional<std::uint64_t> rel_size;
  std::optional<std::uint64_t> rel_entry_size;
  bool text_relocations = false;
  bool packed_relocations = false;
};

bool ReadDynamicString(const A64LoadedImage& image,
                       std::uint64_t load_bias,
                       std::uint64_t strtab_address,
                       std::uint64_t strtab_size,
                       std::uint64_t string_offset,
                       std::string* result,
                       std::string* error) {
  if (string_offset >= strtab_size) {
    *error = "dynamic string offset is outside DT_STRTAB";
    return false;
  }
  if (AddOverflows(load_bias, strtab_address)) {
    *error = "relocated DT_STRTAB address overflows";
    return false;
  }

  const std::uint64_t available = strtab_size - string_offset;
  const std::uint64_t relocated_strtab = load_bias + strtab_address;
  if (AddOverflows(relocated_strtab, string_offset)) {
    *error = "dynamic string address overflows";
    return false;
  }
  const std::uint64_t string_address = relocated_strtab + string_offset;
  constexpr std::uint64_t kMaximumDynamicStringLength = 4096;
  const auto limit = std::min(available, kMaximumDynamicStringLength);
  result->clear();
  result->reserve(static_cast<std::size_t>(std::min<std::uint64_t>(limit, 256)));

  for (std::uint64_t index = 0; index < limit; ++index) {
    if (AddOverflows(string_address, index)) {
      *error = "dynamic string address overflows";
      return false;
    }
    char character = '\0';
    if (!image.Read(string_address + index, &character, sizeof(character))) {
      *error = "DT_STRTAB points outside loaded PT_LOAD segments";
      return false;
    }
    if (character == '\0') return true;
    result->push_back(character);
  }

  *error = "dynamic string is unterminated or exceeds 4096 bytes";
  return false;
}

std::string ApplyDynamicMetadataAndRelocations(
    A64LoadedImage* image, const Elf64_Phdr& dynamic_header,
    const A64ElfLoadOptions& options) {
  if (dynamic_header.p_filesz == 0 ||
      dynamic_header.p_filesz % sizeof(Elf64_Dyn) != 0) {
    return "PT_DYNAMIC has an empty or mis-sized dynamic table";
  }
  const auto entry_count = dynamic_header.p_filesz / sizeof(Elf64_Dyn);
  if (entry_count > options.max_dynamic_entries) {
    return "PT_DYNAMIC entry count exceeds the configured limit";
  }
  if (AddOverflows(dynamic_header.p_vaddr, image->load_bias)) {
    return "relocated PT_DYNAMIC address overflows";
  }

  const auto dynamic_address = dynamic_header.p_vaddr + image->load_bias;
  DynamicMetadata metadata;
  bool terminated = false;

  for (std::uint64_t index = 0; index < entry_count; ++index) {
    if (index > std::numeric_limits<std::uint64_t>::max() /
                    sizeof(Elf64_Dyn)) {
      return "PT_DYNAMIC entry offset overflows";
    }
    const auto entry_offset = index * sizeof(Elf64_Dyn);
    if (AddOverflows(dynamic_address, entry_offset)) {
      return "PT_DYNAMIC guest address overflows";
    }
    Elf64_Dyn entry{};
    if (!image->Read(dynamic_address + entry_offset, &entry, sizeof(entry))) {
      return "PT_DYNAMIC is not fully contained in loaded PT_LOAD memory";
    }
    if (entry.d_tag == DT_NULL) {
      terminated = true;
      break;
    }

    const auto value = entry.d_un.d_val;
    switch (entry.d_tag) {
      case DT_RELA:
        if (metadata.rela_address) return "duplicate DT_RELA tag";
        metadata.rela_address = entry.d_un.d_ptr;
        break;
      case DT_RELASZ:
        if (metadata.rela_size) return "duplicate DT_RELASZ tag";
        metadata.rela_size = value;
        break;
      case DT_RELAENT:
        if (metadata.rela_entry_size) return "duplicate DT_RELAENT tag";
        metadata.rela_entry_size = value;
        break;
      case DT_STRTAB:
        if (metadata.strtab_address) return "duplicate DT_STRTAB tag";
        metadata.strtab_address = entry.d_un.d_ptr;
        break;
      case DT_STRSZ:
        if (metadata.strtab_size) return "duplicate DT_STRSZ tag";
        metadata.strtab_size = value;
        break;
      case DT_SONAME:
        if (metadata.soname_offset) return "duplicate DT_SONAME tag";
        metadata.soname_offset = value;
        break;
      case DT_NEEDED:
        metadata.needed_offsets.push_back(value);
        break;
      case DT_JMPREL:
        if (metadata.jmprel_address) return "duplicate DT_JMPREL tag";
        metadata.jmprel_address = entry.d_un.d_ptr;
        break;
      case DT_PLTRELSZ:
        if (metadata.plt_relocation_size) return "duplicate DT_PLTRELSZ tag";
        metadata.plt_relocation_size = value;
        break;
      case DT_PLTREL:
        if (metadata.plt_relocation_type) return "duplicate DT_PLTREL tag";
        metadata.plt_relocation_type = value;
        break;
      case DT_REL:
        if (metadata.rel_address) return "duplicate DT_REL tag";
        metadata.rel_address = entry.d_un.d_ptr;
        break;
      case DT_RELSZ:
        if (metadata.rel_size) return "duplicate DT_RELSZ tag";
        metadata.rel_size = value;
        break;
      case DT_RELENT:
        if (metadata.rel_entry_size) return "duplicate DT_RELENT tag";
        metadata.rel_entry_size = value;
        break;
      case DT_TEXTREL:
        metadata.text_relocations = true;
        break;
      case DT_FLAGS:
        if ((value & DF_TEXTREL) != 0) metadata.text_relocations = true;
        break;
      default:
        // DT_RELR and Android's packed relocation tags cannot be ignored:
        // doing so would leave pointers in the guest image unrelocated.
        if (entry.d_tag == 35 || entry.d_tag == 36 || entry.d_tag == 37 ||
            (entry.d_tag >= 0x6000000f && entry.d_tag <= 0x60000012) ||
            (entry.d_tag >= 0x6fffe000 && entry.d_tag <= 0x6fffe003)) {
          metadata.packed_relocations = true;
        }
        break;
    }
  }

  if (!terminated) return "PT_DYNAMIC does not end with DT_NULL";
  if (metadata.text_relocations) {
    return "ELF requires text relocations, which this loader does not permit";
  }
  if (metadata.packed_relocations) {
    return "packed DT_RELR/Android relocations are not supported yet";
  }
  const bool any_rel_tag = metadata.rel_address.has_value() ||
                           metadata.rel_size.has_value() ||
                           metadata.rel_entry_size.has_value();
  if (any_rel_tag &&
      (!metadata.rel_address || !metadata.rel_size ||
       !metadata.rel_entry_size)) {
    return "DT_REL, DT_RELSZ and DT_RELENT must be provided together";
  }
  if (metadata.rel_size && *metadata.rel_size != 0) {
    return "AArch64 DT_REL relocations are unsupported; DT_RELA is required";
  }

  const bool any_plt_tag = metadata.jmprel_address.has_value() ||
                           metadata.plt_relocation_size.has_value() ||
                           metadata.plt_relocation_type.has_value();
  if (any_plt_tag &&
      (!metadata.jmprel_address || !metadata.plt_relocation_size ||
       !metadata.plt_relocation_type)) {
    return "DT_JMPREL, DT_PLTRELSZ and DT_PLTREL must be provided together";
  }
  if (metadata.plt_relocation_size &&
      *metadata.plt_relocation_size != 0) {
    return "DT_JMPREL/PLT relocations require symbol resolution, not implemented yet";
  }

  const bool any_rela_tag = metadata.rela_address.has_value() ||
                            metadata.rela_size.has_value() ||
                            metadata.rela_entry_size.has_value();
  if (any_rela_tag &&
      (!metadata.rela_address || !metadata.rela_size ||
       !metadata.rela_entry_size)) {
    return "DT_RELA, DT_RELASZ and DT_RELAENT must be provided together";
  }

  const bool has_dynamic_strings = !metadata.needed_offsets.empty() ||
                                   metadata.soname_offset.has_value();
  if (has_dynamic_strings) {
    if (!metadata.strtab_address || !metadata.strtab_size ||
        *metadata.strtab_size == 0) {
      return "DT_NEEDED/DT_SONAME metadata requires DT_STRTAB and DT_STRSZ";
    }
    std::string string_error;
    if (metadata.soname_offset) {
      if (!ReadDynamicString(*image, image->load_bias,
                             *metadata.strtab_address, *metadata.strtab_size,
                             *metadata.soname_offset, &image->soname,
                             &string_error)) {
        return string_error;
      }
    }
    for (const auto offset : metadata.needed_offsets) {
      std::string dependency;
      if (!ReadDynamicString(*image, image->load_bias,
                             *metadata.strtab_address, *metadata.strtab_size,
                             offset, &dependency, &string_error)) {
        return string_error;
      }
      if (dependency.empty()) return "DT_NEEDED contains an empty dependency name";
      image->dependencies.push_back(std::move(dependency));
    }
  }

  if (!any_rela_tag) return {};
  if (*metadata.rela_entry_size != sizeof(Elf64_Rela) ||
      *metadata.rela_size % sizeof(Elf64_Rela) != 0) {
    return "DT_RELAENT/DT_RELASZ do not describe a valid Elf64_Rela table";
  }
  if (*metadata.rela_size == 0) return {};
  const auto relocation_count = *metadata.rela_size / sizeof(Elf64_Rela);
  if (relocation_count > options.max_relocations) {
    return "dynamic relocation count exceeds the configured limit";
  }
  if (AddOverflows(image->load_bias, *metadata.rela_address)) {
    return "relocated DT_RELA address overflows";
  }
  const auto relocation_table = image->load_bias + *metadata.rela_address;

  for (std::uint64_t index = 0; index < relocation_count; ++index) {
    const auto offset = index * sizeof(Elf64_Rela);
    if (AddOverflows(relocation_table, offset)) {
      return "DT_RELA entry address overflows";
    }
    Elf64_Rela relocation{};
    if (!image->Read(relocation_table + offset, &relocation,
                     sizeof(relocation))) {
      return "DT_RELA table is outside loaded PT_LOAD segments";
    }

    const auto type = ELF64_R_TYPE(relocation.r_info);
    const auto symbol = ELF64_R_SYM(relocation.r_info);
    if (type == R_AARCH64_NONE) continue;
    if (type != R_AARCH64_RELATIVE) {
      return "unsupported AArch64 dynamic relocation type " +
             std::to_string(type);
    }
    if (symbol != 0) {
      return "R_AARCH64_RELATIVE relocation unexpectedly references a symbol";
    }

    if (AddOverflows(image->load_bias, relocation.r_offset)) {
      return "relocation target address overflows";
    }
    const auto target = image->load_bias + relocation.r_offset;
    std::uint64_t relocated_value = 0;
    if (!AddSignedOffset(image->load_bias, relocation.r_addend,
                         &relocated_value)) {
      return "R_AARCH64_RELATIVE result address overflows";
    }
    if (!image->Write(target, &relocated_value, sizeof(relocated_value))) {
      return "relocation target is not contained in writable PT_LOAD memory";
    }
  }

  return {};
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
  if (options.max_image_size == 0 || options.max_program_headers == 0 ||
      options.max_dynamic_entries == 0 || options.max_relocations == 0) {
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
  std::optional<Elf64_Phdr> dynamic_header;
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
    if (program_header.p_type == PT_DYNAMIC) {
      if (dynamic_header) return Failure("ELF contains multiple PT_DYNAMIC segments");
      if (program_header.p_filesz == 0 ||
          program_header.p_filesz > program_header.p_memsz) {
        return Failure("PT_DYNAMIC has invalid file/memory sizes");
      }
      if (!FileRangeWithin(program_header.p_offset, program_header.p_filesz,
                           file.size())) {
        return Failure("PT_DYNAMIC file range is out of bounds");
      }
      if (program_header.p_filesz % sizeof(Elf64_Dyn) != 0) {
        return Failure("PT_DYNAMIC size is not a whole number of dynamic entries");
      }
      if (program_header.p_filesz / sizeof(Elf64_Dyn) >
          options.max_dynamic_entries) {
        return Failure("PT_DYNAMIC entry count exceeds the configured limit");
      }
      if (AddOverflows(program_header.p_vaddr, program_header.p_memsz)) {
        return Failure("PT_DYNAMIC virtual-address range overflows");
      }
      dynamic_header = program_header;
    }
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

  if (dynamic_header) {
    const auto dynamic_error =
        ApplyDynamicMetadataAndRelocations(&image, *dynamic_header, options);
    if (!dynamic_error.empty()) return Failure(dynamic_error);
  }

  return A64ElfLoadResult{std::move(image), {}};
}

}  // namespace mocktail::translation
