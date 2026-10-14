// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_module_set.h"

#include <algorithm>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <utility>

namespace mocktail::translation {
namespace {

bool AddOverflows(std::uint64_t address, std::uint64_t length) noexcept {
  return length > std::numeric_limits<std::uint64_t>::max() - address;
}

bool AlignUp(std::uint64_t value, std::uint64_t alignment,
             std::uint64_t* result) noexcept {
  if (alignment == 0 || (alignment & (alignment - 1)) != 0) return false;
  const auto mask = alignment - 1;
  if (value > std::numeric_limits<std::uint64_t>::max() - mask) return false;
  *result = (value + mask) & ~mask;
  return true;
}

}  // namespace

A64GuestModuleSet::A64GuestModuleSet(std::size_t max_guest_memory) noexcept
    : memory_(max_guest_memory) {}

bool A64GuestModuleSet::Load(
    const std::vector<A64GuestModuleInput>& inputs, std::string* error) {
  auto fail = [&](std::string message) {
    if (error != nullptr) *error = std::move(message);
    return false;
  };
  if (loaded_ || !modules_.empty() || memory_.mapped_bytes() != 0) {
    return fail("an AArch64 guest module set can only be loaded once");
  }
  if (inputs.empty()) return fail("no AArch64 shared objects were supplied");

  std::vector<A64GuestModule> candidate_modules;
  std::set<std::string> input_names;
  std::map<std::string, std::size_t> soname_index;
  A64ElfLoadOptions options;
  options.defer_unresolved_symbols = true;
  std::uint64_t preferred_base = 0x100000000ULL;

  try {
    candidate_modules.reserve(inputs.size());
    for (const auto& input : inputs) {
      if (input.name.empty()) return fail("guest module input has an empty name");
      if (!input_names.insert(input.name).second) {
        return fail("duplicate guest module input name: " + input.name);
      }
      if (input.bytes.empty()) {
        return fail("guest module input is empty: " + input.name);
      }

      options.preferred_base = preferred_base;
      auto load_result = LoadA64Elf(input.bytes, options);
      if (!load_result) {
        return fail("failed to load " + input.name + ": " + load_result.error);
      }
      auto image = std::move(*load_result.image);
      if (image.load_bias == 0) {
        return fail("module set only accepts position-independent ET_DYN images: " +
                    input.name);
      }

      std::string soname = image.soname.empty() ? input.name : image.soname;
      if (soname.empty()) return fail("guest module has no usable identity");
      if (soname_index.find(soname) != soname_index.end()) {
        return fail("duplicate guest module SONAME: " + soname);
      }
      soname_index.emplace(soname, candidate_modules.size());
      candidate_modules.push_back(
          A64GuestModule{input.name, soname, std::move(image)});

      const auto& loaded_image = candidate_modules.back().image;
      if (AddOverflows(loaded_image.base_address, loaded_image.image_size)) {
        return fail("guest module address range overflows: " + soname);
      }
      const auto image_end =
          loaded_image.base_address + loaded_image.image_size;
      constexpr std::uint64_t kModuleGap = 64U * 1024U;
      if (AddOverflows(image_end, kModuleGap)) {
        return fail("guest module placement address overflows: " + soname);
      }
      if (!AlignUp(image_end + kModuleGap, A64GuestMemory::kPageSize,
                   &preferred_base)) {
        return fail("guest module placement address cannot be aligned: " +
                    soname);
      }
    }
  } catch (const std::bad_alloc&) {
    return fail("not enough host memory to build the guest module table");
  }

  // Validate dependencies only after all supplied modules have been indexed;
  // this permits arbitrary input ordering while failing closed on missing libs.
  for (const auto& module : candidate_modules) {
    for (const auto& dependency : module.image.dependencies) {
      if (soname_index.find(dependency) == soname_index.end()) {
        return fail("missing DT_NEEDED dependency '" + dependency +
                    "' required by " + module.soname);
      }
    }
  }

  auto resolve = [&](const std::string& name)
      -> std::optional<std::uint64_t> {
    for (const auto& module : candidate_modules) {
      for (const auto& symbol : module.image.exported_symbols) {
        if (symbol.name == name) return symbol.guest_address;
      }
    }
    return std::nullopt;
  };

  for (auto& module : candidate_modules) {
    std::string relocation_error;
    if (!ResolveA64ElfPendingRelocations(module.image, resolve,
                                         &relocation_error)) {
      return fail("failed to link " + module.soname + ": " + relocation_error);
    }
  }

  // Build the sparse address space in a temporary object. Nothing becomes
  // visible in this module set unless every image maps successfully.
  A64GuestMemory candidate_memory(memory_.max_mapped_bytes());
  for (const auto& module : candidate_modules) {
    std::string mapping_error;
    if (!candidate_memory.MapImage(module.image, &mapping_error)) {
      return fail("failed to map " + module.soname + ": " + mapping_error);
    }
  }

  modules_ = std::move(candidate_modules);
  memory_ = std::move(candidate_memory);
  loaded_ = true;
  if (error != nullptr) error->clear();
  return true;
}

const A64GuestModule* A64GuestModuleSet::FindBySoname(
    const std::string& soname) const noexcept {
  for (const auto& module : modules_) {
    if (module.soname == soname) return &module;
  }
  return nullptr;
}

std::optional<std::uint64_t> A64GuestModuleSet::FindSymbol(
    const std::string& symbol_name) const noexcept {
  for (const auto& module : modules_) {
    for (const auto& symbol : module.image.exported_symbols) {
      if (symbol.name == symbol_name) return symbol.guest_address;
    }
  }
  return std::nullopt;
}

}  // namespace mocktail::translation
