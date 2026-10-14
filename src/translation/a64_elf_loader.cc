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
  std::optional<std::uint64_t> android_rela_address;
  std::optional<std::uint64_t> android_rela_size;
  std::optional<std::uint64_t> relr_address;
  std::optional<std::uint64_t> relr_size;
  std::optional<std::uint64_t> relr_entry_size;
  std::optional<std::uint64_t> strtab_address;
  std::optional<std::uint64_t> strtab_size;
  std::optional<std::uint64_t> soname_offset;
  std::optional<std::uint64_t> symtab_address;
  std::optional<std::uint64_t> symtab_entry_size;
  std::optional<std::uint64_t> hash_address;
  std::optional<std::uint64_t> gnu_hash_address;
  std::optional<std::uint64_t> versym_address;
  std::optional<std::uint64_t> init_address;
  std::optional<std::uint64_t> fini_address;
  std::optional<std::uint64_t> init_array_address;
  std::optional<std::uint64_t> init_array_size;
  std::optional<std::uint64_t> fini_array_address;
  std::optional<std::uint64_t> fini_array_size;
  std::vector<std::uint64_t> needed_offsets;
  std::optional<std::uint64_t> jmprel_address;
  std::optional<std::uint64_t> plt_relocation_size;
  std::optional<std::uint64_t> plt_relocation_type;
  std::optional<std::uint64_t> rel_address;
  std::optional<std::uint64_t> rel_size;
  std::optional<std::uint64_t> rel_entry_size;
  bool text_relocations = false;
  bool unsupported_android_rel = false;
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

bool GetDynamicSymbolCount(const A64LoadedImage& image,
                           const DynamicMetadata& metadata,
                           const A64ElfLoadOptions& options,
                           std::uint64_t* symbol_count,
                           std::string* error) {
  if (!metadata.hash_address && !metadata.gnu_hash_address) {
    *error = "symbol relocations require DT_HASH or DT_GNU_HASH";
    return false;
  }

  if (metadata.hash_address) {
    if (AddOverflows(image.load_bias, *metadata.hash_address)) {
      *error = "relocated DT_HASH address overflows";
      return false;
    }
    const auto hash_address =
        image.load_bias + *metadata.hash_address;
    std::uint32_t header[2]{};
    if (!image.Read(hash_address, header, sizeof(header))) {
      *error = "DT_HASH header is outside loaded PT_LOAD segments";
      return false;
    }
    if (header[0] > options.max_symbols ||
        header[1] == 0 || header[1] > options.max_symbols) {
      *error = "DT_HASH has an invalid or excessive symbol count";
      return false;
    }
    *symbol_count = header[1];
    return true;
  }

  if (AddOverflows(image.load_bias, *metadata.gnu_hash_address)) {
    *error = "relocated DT_GNU_HASH address overflows";
    return false;
  }
  const auto hash_address =
      image.load_bias + *metadata.gnu_hash_address;
  std::uint32_t header[4]{};
  if (!image.Read(hash_address, header, sizeof(header))) {
    *error = "DT_GNU_HASH header is outside loaded PT_LOAD segments";
    return false;
  }
  const std::uint64_t bucket_count = header[0];
  const std::uint64_t symbol_offset = header[1];
  const std::uint64_t bloom_count = header[2];
  if (bucket_count == 0 || bucket_count > options.max_symbols ||
      bloom_count == 0 || bloom_count > options.max_symbols ||
      symbol_offset > options.max_symbols) {
    *error = "DT_GNU_HASH has invalid or excessive dimensions";
    return false;
  }

  const std::uint64_t bloom_bytes = bloom_count * sizeof(std::uint64_t);
  if (AddOverflows(hash_address, sizeof(header)) ||
      AddOverflows(hash_address + sizeof(header), bloom_bytes)) {
    *error = "DT_GNU_HASH bloom filter address overflows";
    return false;
  }
  const auto buckets_address =
      hash_address + sizeof(header) + bloom_bytes;
  const std::uint64_t bucket_bytes = bucket_count * sizeof(std::uint32_t);
  if (AddOverflows(buckets_address, bucket_bytes)) {
    *error = "DT_GNU_HASH bucket table address overflows";
    return false;
  }
  const auto chains_address = buckets_address + bucket_bytes;

  std::uint64_t count = symbol_offset;
  for (std::uint64_t bucket_index = 0; bucket_index < bucket_count;
       ++bucket_index) {
    const auto bucket_offset = bucket_index * sizeof(std::uint32_t);
    if (AddOverflows(buckets_address, bucket_offset)) {
      *error = "DT_GNU_HASH bucket address overflows";
      return false;
    }
    std::uint32_t symbol_index = 0;
    if (!image.Read(buckets_address + bucket_offset, &symbol_index,
                    sizeof(symbol_index))) {
      *error = "DT_GNU_HASH bucket table is outside loaded PT_LOAD segments";
      return false;
    }
    if (symbol_index == 0) continue;
    if (symbol_index < symbol_offset ||
        symbol_index >= options.max_symbols) {
      *error = "DT_GNU_HASH contains an invalid symbol index";
      return false;
    }

    bool chain_terminated = false;
    std::uint64_t index = symbol_index;
    while (index < options.max_symbols) {
      const auto chain_offset =
          (index - symbol_offset) * sizeof(std::uint32_t);
      if (AddOverflows(chains_address, chain_offset)) {
        *error = "DT_GNU_HASH chain address overflows";
        return false;
      }
      std::uint32_t hash_value = 0;
      if (!image.Read(chains_address + chain_offset, &hash_value,
                      sizeof(hash_value))) {
        *error = "DT_GNU_HASH chain is outside loaded PT_LOAD segments";
        return false;
      }
      count = std::max(count, index + 1);
      if ((hash_value & 1U) != 0) {
        chain_terminated = true;
        break;
      }
      ++index;
    }
    if (!chain_terminated) {
      *error = "DT_GNU_HASH chain exceeds the configured symbol limit";
      return false;
    }
  }

  if (count == 0 || count > options.max_symbols) {
    *error = "DT_GNU_HASH yielded an invalid symbol count";
    return false;
  }
  *symbol_count = count;
  return true;
}

bool ResolveDynamicSymbol(const A64LoadedImage& image,
                          const DynamicMetadata& metadata,
                          const A64ElfLoadOptions& options,
                          std::uint64_t symbol_index,
                          std::uint64_t* symbol_value,
                          std::string* error) {
  if (!metadata.symtab_address || !metadata.symtab_entry_size ||
      *metadata.symtab_entry_size != sizeof(Elf64_Sym)) {
    *error = "symbol relocation requires DT_SYMTAB and a valid DT_SYMENT";
    return false;
  }

  std::uint64_t symbol_count = 0;
  if (!GetDynamicSymbolCount(image, metadata, options, &symbol_count, error)) {
    return false;
  }
  if (symbol_index >= symbol_count || symbol_index >= options.max_symbols) {
    *error = "relocation symbol index is outside the dynamic symbol table";
    return false;
  }

  const auto symbol_offset = symbol_index * sizeof(Elf64_Sym);
  if (AddOverflows(*metadata.symtab_address, symbol_offset) ||
      AddOverflows(image.load_bias,
                   *metadata.symtab_address + symbol_offset)) {
    *error = "relocated dynamic symbol address overflows";
    return false;
  }
  const auto guest_symbol_address =
      image.load_bias + *metadata.symtab_address + symbol_offset;
  Elf64_Sym symbol{};
  if (!image.Read(guest_symbol_address, &symbol, sizeof(symbol))) {
    *error = "dynamic symbol entry is outside loaded PT_LOAD segments";
    return false;
  }

  if (metadata.versym_address) {
    const auto version_offset = symbol_index * sizeof(Elf64_Half);
    if (AddOverflows(*metadata.versym_address, version_offset) ||
        AddOverflows(image.load_bias,
                     *metadata.versym_address + version_offset)) {
      *error = "dynamic symbol-version address overflows";
      return false;
    }
    Elf64_Half version_index = 0;
    const auto guest_version_address =
        image.load_bias + *metadata.versym_address + version_offset;
    if (!image.Read(guest_version_address, &version_index,
                    sizeof(version_index))) {
      *error = "DT_VERSYM entry is outside loaded PT_LOAD segments";
      return false;
    }
    version_index &= 0x7fffU;
    if (version_index > 1) {
      *error = "versioned dynamic symbols are not supported yet";
      return false;
    }
  }

  const auto binding = ELF64_ST_BIND(symbol.st_info);
  const auto type = ELF64_ST_TYPE(symbol.st_info);
  if (type == STT_TLS) {
    *error = "TLS symbols require guest TLS support, not implemented yet";
    return false;
  }
#ifdef STT_GNU_IFUNC
  if (type == STT_GNU_IFUNC) {
    *error = "GNU IFUNC symbols require executing a guest resolver";
    return false;
  }
#endif

  if (symbol.st_shndx == SHN_UNDEF) {
    if (binding != STB_GLOBAL && binding != STB_WEAK) {
      *error = "undefined dynamic symbol is not global or weak";
      return false;
    }
    if (!metadata.strtab_address || !metadata.strtab_size ||
        symbol.st_name >= *metadata.strtab_size) {
      *error = "undefined dynamic symbol requires a valid DT_STRTAB entry";
      return false;
    }
    std::string name;
    if (!ReadDynamicString(image, image.load_bias, *metadata.strtab_address,
                           *metadata.strtab_size, symbol.st_name, &name,
                           error)) {
      return false;
    }
    if (name.empty()) {
      *error = "undefined dynamic symbol has an empty name";
      return false;
    }
    if (options.resolve_symbol) {
      const auto resolved = options.resolve_symbol(name);
      if (resolved) {
        *symbol_value = *resolved;
        return true;
      }
    }
    if (binding == STB_WEAK) {
      *symbol_value = 0;
      return true;
    }
    *error = "unresolved AArch64 symbol: " + name;
    return false;
  }

  if (symbol.st_shndx == SHN_COMMON || symbol.st_shndx == SHN_XINDEX) {
    *error = "common/extended-index dynamic symbols are unsupported";
    return false;
  }
  if (symbol.st_shndx == SHN_ABS) {
    *symbol_value = symbol.st_value;
    return true;
  }
  if (AddOverflows(image.load_bias, symbol.st_value)) {
    *error = "relocated dynamic symbol value overflows";
    return false;
  }
  *symbol_value = image.load_bias + symbol.st_value;
  return true;
}

std::string CollectDynamicExports(
    A64LoadedImage* image, const DynamicMetadata& metadata,
    const A64ElfLoadOptions& options) {
  const bool any_symbol_table = metadata.symtab_address.has_value() ||
                                metadata.symtab_entry_size.has_value() ||
                                metadata.hash_address.has_value() ||
                                metadata.gnu_hash_address.has_value();
  if (!any_symbol_table) return {};

  if (!metadata.symtab_address || !metadata.symtab_entry_size ||
      *metadata.symtab_entry_size != sizeof(Elf64_Sym) ||
      !metadata.strtab_address || !metadata.strtab_size ||
      *metadata.strtab_size == 0) {
    return "dynamic symbol exports require valid DT_SYMTAB/DT_SYMENT/"
           "DT_STRTAB/DT_STRSZ metadata";
  }

  std::uint64_t symbol_count = 0;
  std::string error;
  if (!GetDynamicSymbolCount(*image, metadata, options, &symbol_count,
                             &error)) {
    return error;
  }

  try {
    image->exported_symbols.clear();
    image->exported_symbols.reserve(
        static_cast<std::size_t>(symbol_count));
    for (std::uint64_t index = 0; index < symbol_count; ++index) {
      if (index > std::numeric_limits<std::uint64_t>::max() /
                      sizeof(Elf64_Sym)) {
        return "dynamic symbol table entry offset overflows";
      }
      const auto symbol_offset = index * sizeof(Elf64_Sym);
      if (AddOverflows(*metadata.symtab_address, symbol_offset) ||
          AddOverflows(image->load_bias,
                       *metadata.symtab_address + symbol_offset)) {
        return "dynamic symbol table address overflows";
      }
      Elf64_Sym symbol{};
      const auto symbol_address =
          image->load_bias + *metadata.symtab_address + symbol_offset;
      if (!image->Read(symbol_address, &symbol, sizeof(symbol))) {
        return "dynamic symbol table entry is outside loaded PT_LOAD segments";
      }

      if (symbol.st_shndx == SHN_UNDEF || symbol.st_shndx == SHN_COMMON ||
          symbol.st_shndx == SHN_XINDEX) {
        continue;
      }
      const auto binding = ELF64_ST_BIND(symbol.st_info);
      if (binding != STB_GLOBAL && binding != STB_WEAK
#ifdef STB_GNU_UNIQUE
          && binding != STB_GNU_UNIQUE
#endif
      ) {
        continue;
      }
      const auto visibility = ELF64_ST_VISIBILITY(symbol.st_other);
      if (visibility != STV_DEFAULT && visibility != STV_PROTECTED) continue;

      const auto type = ELF64_ST_TYPE(symbol.st_info);
      if (type == STT_TLS) continue;
#ifdef STT_GNU_IFUNC
      if (type == STT_GNU_IFUNC) continue;
#endif

      if (metadata.versym_address) {
        if (index > std::numeric_limits<std::uint64_t>::max() /
                        sizeof(Elf64_Half)) {
          return "dynamic symbol-version offset overflows";
        }
        const auto version_offset = index * sizeof(Elf64_Half);
        if (AddOverflows(*metadata.versym_address, version_offset) ||
            AddOverflows(image->load_bias,
                         *metadata.versym_address + version_offset)) {
          return "dynamic symbol-version address overflows";
        }
        Elf64_Half version_index = 0;
        if (!image->Read(image->load_bias + *metadata.versym_address +
                             version_offset,
                         &version_index, sizeof(version_index))) {
          return "DT_VERSYM entry is outside loaded PT_LOAD segments";
        }
        if ((version_index & 0x7fffU) > 1) continue;
      }

      std::string name;
      if (!ReadDynamicString(*image, image->load_bias,
                             *metadata.strtab_address, *metadata.strtab_size,
                             symbol.st_name, &name, &error)) {
        return error;
      }
      if (name.empty()) continue;

      std::uint64_t guest_address = symbol.st_value;
      if (symbol.st_shndx != SHN_ABS) {
        if (AddOverflows(image->load_bias, symbol.st_value)) {
          return "dynamic symbol guest address overflows";
        }
        guest_address = image->load_bias + symbol.st_value;
      }
      if (type == STT_FUNC &&
          !image->IsExecutable(guest_address, sizeof(std::uint32_t))) {
        return "exported function '" + name +
               "' does not point into executable PT_LOAD memory";
      }

      image->exported_symbols.push_back(A64ExportedSymbol{
          std::move(name), guest_address, symbol.st_size, binding, type,
          visibility});
    }
  } catch (const std::bad_alloc&) {
    return "not enough memory to collect bounded dynamic symbols";
  }
  return {};
}

class Sleb128Decoder final {
 public:
  Sleb128Decoder(const std::uint8_t* bytes, std::size_t size)
      : bytes_(bytes), size_(size) {}

  bool Read(std::int64_t* output) noexcept {
    std::uint64_t value = 0;
    unsigned shift = 0;
    std::uint8_t byte = 0;

    for (unsigned index = 0; index < 10; ++index) {
      if (position_ >= size_) return false;
      byte = bytes_[position_++];
      const auto payload = static_cast<std::uint8_t>(byte & 0x7fU);

      if (shift == 63U) {
        if (payload != 0 && payload != 0x7fU) return false;
        value |= static_cast<std::uint64_t>(payload & 1U) << 63U;
      } else if (shift < 63U) {
        value |= static_cast<std::uint64_t>(payload) << shift;
      }

      if ((byte & 0x80U) == 0) {
        const unsigned total_shift = shift + 7U;
        if (total_shift < 64U && (byte & 0x40U) != 0) {
          value |= (~std::uint64_t{0}) << total_shift;
        }
        std::memcpy(output, &value, sizeof(value));
        return true;
      }
      shift += 7U;
    }
    return false;
  }

  std::size_t position() const noexcept { return position_; }

 private:
  const std::uint8_t* bytes_;
  std::size_t size_;
  std::size_t position_ = 0;
};

bool DecodeAndroidPackedRela(const A64LoadedImage& image,
                             std::uint64_t load_bias,
                             std::uint64_t virtual_address,
                             std::uint64_t byte_size,
                             const A64ElfLoadOptions& options,
                             std::vector<Elf64_Rela>* relocations,
                             std::string* error) {
  if (byte_size < 4 || byte_size > options.max_packed_relocation_bytes ||
      byte_size > std::numeric_limits<std::size_t>::max()) {
    *error = "DT_ANDROID_RELA size is empty or exceeds the configured limit";
    return false;
  }
  if (AddOverflows(load_bias, virtual_address)) {
    *error = "relocated DT_ANDROID_RELA address overflows";
    return false;
  }

  std::vector<std::uint8_t> bytes;
  try {
    bytes.resize(static_cast<std::size_t>(byte_size));
  } catch (const std::bad_alloc&) {
    *error = "not enough memory to read the bounded DT_ANDROID_RELA table";
    return false;
  }
  if (!image.Read(load_bias + virtual_address, bytes.data(), bytes.size())) {
    *error = "DT_ANDROID_RELA table is outside loaded PT_LOAD segments";
    return false;
  }
  if (bytes[0] != 'A' || bytes[1] != 'P' ||
      bytes[2] != 'S' || bytes[3] != '2') {
    *error = "DT_ANDROID_RELA has an invalid APS2 signature";
    return false;
  }

  Sleb128Decoder decoder(bytes.data() + 4, bytes.size() - 4);
  std::int64_t encoded_count = 0;
  std::int64_t encoded_offset = 0;
  if (!decoder.Read(&encoded_count) || !decoder.Read(&encoded_offset) ||
      encoded_count < 0 || encoded_offset < 0 ||
      static_cast<std::uint64_t>(encoded_count) > options.max_relocations) {
    *error = "DT_ANDROID_RELA has invalid relocation count or initial offset";
    return false;
  }

  try {
    relocations->clear();
    relocations->reserve(static_cast<std::size_t>(encoded_count));
  } catch (const std::bad_alloc&) {
    *error = "not enough memory to decode the bounded DT_ANDROID_RELA table";
    return false;
  }

  std::uint64_t running_offset = static_cast<std::uint64_t>(encoded_offset);
  std::int64_t running_addend = 0;
  const std::uint64_t relocation_count =
      static_cast<std::uint64_t>(encoded_count);

  while (relocations->size() < relocation_count) {
    std::int64_t encoded_group_size = 0;
    std::int64_t encoded_flags = 0;
    if (!decoder.Read(&encoded_group_size) || !decoder.Read(&encoded_flags) ||
        encoded_group_size <= 0 || encoded_flags < 0 ||
        (static_cast<std::uint64_t>(encoded_flags) & ~0xFULL) != 0) {
      *error = "DT_ANDROID_RELA contains an invalid relocation group";
      return false;
    }

    const auto group_size = static_cast<std::uint64_t>(encoded_group_size);
    const auto flags = static_cast<std::uint64_t>(encoded_flags);
    if (group_size > relocation_count - relocations->size()) {
      *error = "DT_ANDROID_RELA group exceeds the declared relocation count";
      return false;
    }

    constexpr std::uint64_t kGroupedByInfo = 1U;
    constexpr std::uint64_t kGroupedByOffsetDelta = 2U;
    constexpr std::uint64_t kGroupedByAddend = 4U;
    constexpr std::uint64_t kHasAddend = 8U;
    if ((flags & kGroupedByAddend) != 0 &&
        (flags & kHasAddend) == 0) {
      *error = "DT_ANDROID_RELA groups addends without declaring them";
      return false;
    }

    std::uint64_t group_offset_delta = 0;
    std::uint64_t group_info = 0;
    if ((flags & kGroupedByOffsetDelta) != 0) {
      std::int64_t delta = 0;
      if (!decoder.Read(&delta) || delta < 0) {
        *error = "DT_ANDROID_RELA has an invalid grouped offset delta";
        return false;
      }
      group_offset_delta = static_cast<std::uint64_t>(delta);
    }
    if ((flags & kGroupedByInfo) != 0) {
      std::int64_t info = 0;
      if (!decoder.Read(&info) || info < 0) {
        *error = "DT_ANDROID_RELA has invalid grouped relocation info";
        return false;
      }
      group_info = static_cast<std::uint64_t>(info);
    }

    if ((flags & kHasAddend) == 0) {
      running_addend = 0;
    } else if ((flags & kGroupedByAddend) != 0) {
      std::int64_t addend_delta = 0;
      if (!decoder.Read(&addend_delta) ||
          (addend_delta > 0 &&
           running_addend > std::numeric_limits<std::int64_t>::max() - addend_delta) ||
          (addend_delta < 0 &&
           running_addend < std::numeric_limits<std::int64_t>::min() - addend_delta)) {
        *error = "DT_ANDROID_RELA has an invalid grouped addend delta";
        return false;
      }
      running_addend += addend_delta;
    }

    for (std::uint64_t index = 0; index < group_size; ++index) {
      if ((flags & kGroupedByOffsetDelta) == 0) {
        std::int64_t delta = 0;
        if (!decoder.Read(&delta) || delta < 0) {
          *error = "DT_ANDROID_RELA has an invalid relocation offset delta";
          return false;
        }
        if (AddOverflows(running_offset, static_cast<std::uint64_t>(delta))) {
          *error = "DT_ANDROID_RELA relocation offset overflows";
          return false;
        }
        running_offset += static_cast<std::uint64_t>(delta);
      } else {
        if (AddOverflows(running_offset, group_offset_delta)) {
          *error = "DT_ANDROID_RELA relocation offset overflows";
          return false;
        }
        running_offset += group_offset_delta;
      }

      std::uint64_t info = group_info;
      if ((flags & kGroupedByInfo) == 0) {
        std::int64_t decoded_info = 0;
        if (!decoder.Read(&decoded_info) || decoded_info < 0) {
          *error = "DT_ANDROID_RELA has invalid relocation info";
          return false;
        }
        info = static_cast<std::uint64_t>(decoded_info);
      }

      if ((flags & kHasAddend) != 0 &&
          (flags & kGroupedByAddend) == 0) {
        std::int64_t addend_delta = 0;
        if (!decoder.Read(&addend_delta)) {
          *error = "DT_ANDROID_RELA has a truncated relocation addend";
          return false;
        }
        if ((addend_delta > 0 &&
             running_addend > std::numeric_limits<std::int64_t>::max() - addend_delta) ||
            (addend_delta < 0 &&
             running_addend < std::numeric_limits<std::int64_t>::min() - addend_delta)) {
          *error = "DT_ANDROID_RELA relocation addend overflows";
          return false;
        }
        running_addend += addend_delta;
      }

      Elf64_Rela relocation{};
      relocation.r_offset = running_offset;
      relocation.r_info = info;
      relocation.r_addend = running_addend;
      relocations->push_back(relocation);
    }
  }

  if (decoder.position() != bytes.size() - 4) {
    *error = "DT_ANDROID_RELA has trailing or unconsumed APS2 data";
    return false;
  }
  return true;
}

std::string CollectDynamicInitializersAndFinalizers(
    A64LoadedImage* image, const DynamicMetadata& metadata,
    const A64ElfLoadOptions& options) {
  auto append_function = [&](const std::optional<std::uint64_t>& virtual_address,
                             const char* tag,
                             std::vector<std::uint64_t>* destination)
      -> std::string {
    if (!virtual_address || *virtual_address == 0) return {};
    if (AddOverflows(image->load_bias, *virtual_address)) {
      return std::string("relocated ") + tag + " address overflows";
    }
    const auto address = image->load_bias + *virtual_address;
    if (!image->IsExecutable(address, sizeof(std::uint32_t))) {
      return std::string(tag) + " does not point into executable PT_LOAD memory";
    }
    try {
      destination->push_back(address);
    } catch (const std::bad_alloc&) {
      return std::string("not enough memory to append ") + tag;
    }
    return {};
  };

  auto collect_array = [&](const std::optional<std::uint64_t>& virtual_address,
                           const std::optional<std::uint64_t>& byte_size,
                           const char* tag,
                           std::vector<std::uint64_t>* destination,
                           bool reverse) -> std::string {
    if (virtual_address.has_value() != byte_size.has_value()) {
      return std::string(tag) + " and its size tag must be provided together";
    }
    if (!virtual_address || *byte_size == 0) return {};
    if ((*byte_size % sizeof(std::uint64_t)) != 0 ||
        *byte_size / sizeof(std::uint64_t) > options.max_relocations) {
      return std::string(tag) + " size is not a valid bounded pointer array";
    }
    if (AddOverflows(image->load_bias, *virtual_address)) {
      return std::string("relocated ") + tag + " address overflows";
    }

    const auto guest_array = image->load_bias + *virtual_address;
    const auto count = *byte_size / sizeof(std::uint64_t);
    std::vector<std::uint64_t> entries;
    try {
      entries.reserve(static_cast<std::size_t>(count));
    } catch (const std::bad_alloc&) {
      return std::string("not enough memory to collect ") + tag;
    }
    for (std::uint64_t index = 0; index < count; ++index) {
      const auto offset = index * sizeof(std::uint64_t);
      if (AddOverflows(guest_array, offset)) {
        return std::string(tag) + " element address overflows";
      }
      std::uint64_t address = 0;
      if (!image->Read(guest_array + offset, &address, sizeof(address))) {
        return std::string(tag) +
               " is outside loaded PT_LOAD memory";
      }
      // Toolchains may leave empty/sentinel entries in the array. Ignore them,
      // but require every actual function pointer to name guest executable code.
      if (address == 0 || address == std::numeric_limits<std::uint64_t>::max()) {
        continue;
      }
      if (!image->IsExecutable(address, sizeof(std::uint32_t))) {
        return std::string(tag) +
               " contains an entry outside executable PT_LOAD memory";
      }
      entries.push_back(address);
    }
    if (reverse) std::reverse(entries.begin(), entries.end());
    try {
      destination->insert(destination->end(), entries.begin(), entries.end());
    } catch (const std::bad_alloc&) {
      return std::string("not enough memory to append ") + tag;
    }
    return {};
  };

  auto error = append_function(metadata.init_address, "DT_INIT",
                               &image->initializers);
  if (!error.empty()) return error;
  error = collect_array(metadata.init_array_address, metadata.init_array_size,
                        "DT_INIT_ARRAY", &image->initializers, false);
  if (!error.empty()) return error;

  error = collect_array(metadata.fini_array_address, metadata.fini_array_size,
                        "DT_FINI_ARRAY", &image->finalizers, true);
  if (!error.empty()) return error;
  return append_function(metadata.fini_address, "DT_FINI", &image->finalizers);
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
      case DT_SYMTAB:
        if (metadata.symtab_address) return "duplicate DT_SYMTAB tag";
        metadata.symtab_address = entry.d_un.d_ptr;
        break;
      case DT_SYMENT:
        if (metadata.symtab_entry_size) return "duplicate DT_SYMENT tag";
        metadata.symtab_entry_size = value;
        break;
      case DT_HASH:
        if (metadata.hash_address) return "duplicate DT_HASH tag";
        metadata.hash_address = entry.d_un.d_ptr;
        break;
      case DT_GNU_HASH:
        if (metadata.gnu_hash_address) return "duplicate DT_GNU_HASH tag";
        metadata.gnu_hash_address = entry.d_un.d_ptr;
        break;
      case DT_VERSYM:
        if (metadata.versym_address) return "duplicate DT_VERSYM tag";
        metadata.versym_address = entry.d_un.d_ptr;
        break;
      case DT_INIT:
        if (metadata.init_address) return "duplicate DT_INIT tag";
        metadata.init_address = entry.d_un.d_ptr;
        break;
      case DT_FINI:
        if (metadata.fini_address) return "duplicate DT_FINI tag";
        metadata.fini_address = entry.d_un.d_ptr;
        break;
      case DT_INIT_ARRAY:
        if (metadata.init_array_address) return "duplicate DT_INIT_ARRAY tag";
        metadata.init_array_address = entry.d_un.d_ptr;
        break;
      case DT_INIT_ARRAYSZ:
        if (metadata.init_array_size) return "duplicate DT_INIT_ARRAYSZ tag";
        metadata.init_array_size = value;
        break;
      case DT_FINI_ARRAY:
        if (metadata.fini_array_address) return "duplicate DT_FINI_ARRAY tag";
        metadata.fini_array_address = entry.d_un.d_ptr;
        break;
      case DT_FINI_ARRAYSZ:
        if (metadata.fini_array_size) return "duplicate DT_FINI_ARRAYSZ tag";
        metadata.fini_array_size = value;
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
      case 0x6000000f:  // DT_ANDROID_REL
      case 0x60000010:  // DT_ANDROID_RELSZ
        metadata.unsupported_android_rel = true;
        break;
      case 0x60000011:  // DT_ANDROID_RELA
        if (metadata.android_rela_address) return "duplicate DT_ANDROID_RELA tag";
        metadata.android_rela_address = entry.d_un.d_ptr;
        break;
      case 0x60000012:  // DT_ANDROID_RELASZ
        if (metadata.android_rela_size) return "duplicate DT_ANDROID_RELASZ tag";
        metadata.android_rela_size = value;
        break;
      case 35:  // DT_RELRSZ
      case 0x6fffe001:  // DT_ANDROID_RELRSZ
        if (metadata.relr_size) return "duplicate DT_RELRSZ/DT_ANDROID_RELRSZ tag";
        metadata.relr_size = value;
        break;
      case 36:  // DT_RELR
      case 0x6fffe000:  // DT_ANDROID_RELR
        if (metadata.relr_address) return "duplicate DT_RELR/DT_ANDROID_RELR tag";
        metadata.relr_address = entry.d_un.d_ptr;
        break;
      case 37:  // DT_RELRENT
      case 0x6fffe003:  // DT_ANDROID_RELRENT
        if (metadata.relr_entry_size) return "duplicate DT_RELRENT/DT_ANDROID_RELRENT tag";
        metadata.relr_entry_size = value;
        break;
      case 0x6fffe002:  // DT_ANDROID_RELRCOUNT
      case 0x6fffe004:  // Some toolchains' optional RELR-count tag
        break;
      case DT_TEXTREL:
        metadata.text_relocations = true;
        break;
      case DT_FLAGS:
        if ((value & DF_TEXTREL) != 0) metadata.text_relocations = true;
        break;
      default:
        break;
    }
  }

  if (!terminated) return "PT_DYNAMIC does not end with DT_NULL";
  if (metadata.text_relocations) {
    return "ELF requires text relocations, which this loader does not permit";
  }
  if (metadata.unsupported_android_rel) {
    return "DT_ANDROID_REL packed relocations are unsupported; AArch64 RELA is required";
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
      *metadata.plt_relocation_size != 0 &&
      metadata.plt_relocation_type && *metadata.plt_relocation_type != DT_RELA) {
    return "DT_JMPREL uses DT_REL; only Elf64_Rela PLT tables are supported";
  }

  const bool any_rela_tag = metadata.rela_address.has_value() ||
                            metadata.rela_size.has_value() ||
                            metadata.rela_entry_size.has_value();
  if (any_rela_tag &&
      (!metadata.rela_address || !metadata.rela_size ||
       !metadata.rela_entry_size)) {
    return "DT_RELA, DT_RELASZ and DT_RELAENT must be provided together";
  }

  const bool any_android_rela =
      metadata.android_rela_address.has_value() ||
      metadata.android_rela_size.has_value();
  if (any_android_rela &&
      (!metadata.android_rela_address || !metadata.android_rela_size)) {
    return "DT_ANDROID_RELA and DT_ANDROID_RELASZ must be provided together";
  }
  if (metadata.android_rela_size &&
      (*metadata.android_rela_size < 4 ||
       *metadata.android_rela_size > options.max_packed_relocation_bytes)) {
    return "DT_ANDROID_RELASZ is empty or exceeds the configured limit";
  }

  const bool any_relr = metadata.relr_address.has_value() ||
                        metadata.relr_size.has_value() ||
                        metadata.relr_entry_size.has_value();
  if (any_relr &&
      (!metadata.relr_address || !metadata.relr_size ||
       !metadata.relr_entry_size)) {
    return "DT_RELR, DT_RELRSZ and DT_RELRENT must be provided together";
  }
  if (any_relr &&
      (*metadata.relr_entry_size != sizeof(std::uint64_t) ||
       *metadata.relr_size % sizeof(std::uint64_t) != 0 ||
       *metadata.relr_size / sizeof(std::uint64_t) >
           options.max_relocations)) {
    return "DT_RELRENT/DT_RELRSZ do not describe a valid bounded RELR table";
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

  const auto exports_error = CollectDynamicExports(image, metadata, options);
  if (!exports_error.empty()) return exports_error;

  const bool has_android_rela =
      metadata.android_rela_address && metadata.android_rela_size &&
      *metadata.android_rela_size != 0;
  const bool has_relr =
      metadata.relr_address && metadata.relr_size && *metadata.relr_size != 0;
  const bool has_plt_relocations =
      metadata.plt_relocation_size && *metadata.plt_relocation_size != 0;
  const bool has_main_relocations = any_rela_tag && *metadata.rela_size != 0;
  if (!has_android_rela && !has_relr &&
      !has_main_relocations && !has_plt_relocations) {
    return CollectDynamicInitializersAndFinalizers(image, metadata, options);
  }

  if (has_main_relocations &&
      (*metadata.rela_entry_size != sizeof(Elf64_Rela) ||
       *metadata.rela_size % sizeof(Elf64_Rela) != 0)) {
    return "DT_RELAENT/DT_RELASZ do not describe a valid Elf64_Rela table";
  }
  if (has_plt_relocations &&
      *metadata.plt_relocation_size % sizeof(Elf64_Rela) != 0) {
    return "DT_PLTRELSZ does not describe a whole number of Elf64_Rela entries";
  }
  const auto main_relocation_count =
      has_main_relocations ? *metadata.rela_size / sizeof(Elf64_Rela) : 0;
  const auto plt_relocation_count =
      has_plt_relocations ? *metadata.plt_relocation_size / sizeof(Elf64_Rela) : 0;
  if (main_relocation_count > options.max_relocations ||
      plt_relocation_count > options.max_relocations ||
      main_relocation_count > options.max_relocations - plt_relocation_count) {
    return "combined dynamic relocation count exceeds the configured limit";
  }

  std::size_t applied_relocation_count = 0;
  auto apply_relocation = [&](const Elf64_Rela& relocation,
                              const char* table_name) -> std::string {
    const auto type = ELF64_R_TYPE(relocation.r_info);
    const auto symbol_index = ELF64_R_SYM(relocation.r_info);
    if (type == R_AARCH64_NONE) return {};
    if (applied_relocation_count >= options.max_relocations) {
      return "combined dynamic relocation count exceeds the configured limit";
    }

    if (AddOverflows(image->load_bias, relocation.r_offset)) {
      return "relocation target address overflows";
    }
    const auto target = image->load_bias + relocation.r_offset;

    std::uint64_t relocated_value = 0;
    if (type == R_AARCH64_RELATIVE) {
      if (symbol_index != 0) {
        return "R_AARCH64_RELATIVE relocation unexpectedly references a symbol";
      }
      if (!AddSignedOffset(image->load_bias, relocation.r_addend,
                           &relocated_value)) {
        return "R_AARCH64_RELATIVE result address overflows";
      }
    } else if (type == R_AARCH64_ABS64 ||
               type == R_AARCH64_GLOB_DAT ||
               type == R_AARCH64_JUMP_SLOT) {
      std::string symbol_error;
      std::uint64_t symbol_value = 0;
      if (!ResolveDynamicSymbol(*image, metadata, options, symbol_index,
                                &symbol_value, &symbol_error)) {
        return symbol_error;
      }
      if (type == R_AARCH64_JUMP_SLOT) {
        relocated_value = symbol_value;
      } else if (!AddSignedOffset(symbol_value, relocation.r_addend,
                                  &relocated_value)) {
        return "symbol relocation result overflows";
      }
    } else {
      return std::string("unsupported AArch64 dynamic relocation type ") +
             std::to_string(type) + " in " + table_name;
    }

    if (!image->Write(target, &relocated_value, sizeof(relocated_value))) {
      return "relocation target is not contained in writable PT_LOAD memory";
    }
    ++applied_relocation_count;
    return {};
  };

  auto apply_rela_table = [&](std::uint64_t virtual_address,
                              std::uint64_t relocation_count,
                              const char* table_name) -> std::string {
    if (AddOverflows(image->load_bias, virtual_address)) {
      return std::string("relocated ") + table_name + " address overflows";
    }
    const auto relocation_table = image->load_bias + virtual_address;

    for (std::uint64_t index = 0; index < relocation_count; ++index) {
      const auto offset = index * sizeof(Elf64_Rela);
      if (AddOverflows(relocation_table, offset)) {
        return std::string(table_name) + " entry address overflows";
      }
      Elf64_Rela relocation{};
      if (!image->Read(relocation_table + offset, &relocation,
                       sizeof(relocation))) {
        return std::string(table_name) +
               " table is outside loaded PT_LOAD segments";
      }
      const auto error = apply_relocation(relocation, table_name);
      if (!error.empty()) return error;
    }
    return {};
  };

  // Decode Android's APS2 stream before the standard RELR/RELA tables, matching
  // the Android loader's separation of packed and ordinary relocation formats.
  if (has_android_rela) {
    std::vector<Elf64_Rela> packed_relocations;
    std::string decode_error;
    if (!DecodeAndroidPackedRela(*image, image->load_bias,
                                 *metadata.android_rela_address,
                                 *metadata.android_rela_size, options,
                                 &packed_relocations, &decode_error)) {
      return decode_error;
    }
    for (const auto& relocation : packed_relocations) {
      const auto error = apply_relocation(relocation, "DT_ANDROID_RELA");
      if (!error.empty()) return error;
    }
  }

  if (has_relr) {
    if (AddOverflows(image->load_bias, *metadata.relr_address)) {
      return "relocated DT_RELR address overflows";
    }
    const auto relr_table = image->load_bias + *metadata.relr_address;
    const auto relr_entry_count = *metadata.relr_size / sizeof(std::uint64_t);
    std::uint64_t base = 0;
    bool have_base = false;

    auto apply_relr_offset = [&](std::uint64_t offset) -> std::string {
      if (applied_relocation_count >= options.max_relocations) {
        return "combined dynamic relocation count exceeds the configured limit";
      }
      if (AddOverflows(image->load_bias, offset)) {
        return "DT_RELR relocation target address overflows";
      }
      const auto target = image->load_bias + offset;
      std::uint64_t addend = 0;
      if (!image->Read(target, &addend, sizeof(addend))) {
        return "DT_RELR target is outside loaded PT_LOAD memory";
      }
      if (AddOverflows(addend, image->load_bias)) {
        return "DT_RELR relocated pointer value overflows";
      }
      const auto relocated_value = addend + image->load_bias;
      if (!image->Write(target, &relocated_value, sizeof(relocated_value))) {
        return "DT_RELR target is not contained in writable PT_LOAD memory";
      }
      ++applied_relocation_count;
      return {};
    };

    for (std::uint64_t index = 0; index < relr_entry_count; ++index) {
      const auto byte_offset = index * sizeof(std::uint64_t);
      if (AddOverflows(relr_table, byte_offset)) {
        return "DT_RELR entry address overflows";
      }
      std::uint64_t entry = 0;
      if (!image->Read(relr_table + byte_offset, &entry, sizeof(entry))) {
        return "DT_RELR table is outside loaded PT_LOAD segments";
      }

      if ((entry & 1U) == 0) {
        if ((entry % sizeof(std::uint64_t)) != 0) {
          return "DT_RELR direct entry is not pointer-aligned";
        }
        const auto error = apply_relr_offset(entry);
        if (!error.empty()) return error;
        if (AddOverflows(entry, sizeof(std::uint64_t))) {
          return "DT_RELR cursor overflows after a direct entry";
        }
        base = entry + sizeof(std::uint64_t);
        have_base = true;
      } else {
        if (!have_base) return "DT_RELR bitmap precedes its first direct entry";
        std::uint64_t bitmap = entry >> 1U;
        std::uint64_t bit_index = 0;
        while (bitmap != 0) {
          if ((bitmap & 1U) != 0) {
            if (bit_index > std::numeric_limits<std::uint64_t>::max() /
                                sizeof(std::uint64_t)) {
              return "DT_RELR bitmap cursor overflows";
            }
            const auto displacement = bit_index * sizeof(std::uint64_t);
            if (AddOverflows(base, displacement)) {
              return "DT_RELR bitmap target overflows";
            }
            const auto error = apply_relr_offset(base + displacement);
            if (!error.empty()) return error;
          }
          bitmap >>= 1U;
          ++bit_index;
        }
        constexpr std::uint64_t kRelrBitmapAdvance =
            63U * sizeof(std::uint64_t);
        if (AddOverflows(base, kRelrBitmapAdvance)) {
          return "DT_RELR bitmap base overflows";
        }
        base += kRelrBitmapAdvance;
      }
    }
  }

  if (has_main_relocations) {
    const auto error = apply_rela_table(
        *metadata.rela_address, main_relocation_count, "DT_RELA");
    if (!error.empty()) return error;
  }
  if (has_plt_relocations) {
    if (!metadata.jmprel_address || !metadata.plt_relocation_type) {
      return "DT_JMPREL, DT_PLTRELSZ and DT_PLTREL must be provided together";
    }
    if (*metadata.plt_relocation_type != DT_RELA) {
      return "DT_JMPREL uses DT_REL; only Elf64_Rela PLT tables are supported";
    }
    const auto error = apply_rela_table(
        *metadata.jmprel_address, plt_relocation_count, "DT_JMPREL");
    if (!error.empty()) return error;
  }

  return CollectDynamicInitializersAndFinalizers(image, metadata, options);
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
      options.max_dynamic_entries == 0 || options.max_relocations == 0 ||
      options.max_symbols == 0) {
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
