// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_module_loader.h"

#include <algorithm>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <utility>

namespace mocktail::translation {
namespace {

struct DiscoveredModule final {
  std::size_t source_index = 0;
  std::uint64_t preferred_base = 0;
  A64LoadedImage metadata_image;
};

A64GuestModuleLoadResult Failure(std::string message) {
  return A64GuestModuleLoadResult{std::nullopt, std::move(message)};
}

bool AddOverflows(std::uint64_t left, std::uint64_t right) noexcept {
  return right > std::numeric_limits<std::uint64_t>::max() - left;
}

std::string Basename(const std::string& path) {
  const auto separator = path.find_last_of('/');
  return separator == std::string::npos ? path : path.substr(separator + 1);
}

bool AddAlias(std::map<std::string, std::size_t>* aliases,
              const std::string& alias, std::size_t source_index,
              std::string* error) {
  if (alias.empty()) {
    *error = "guest module source has an empty filename/SONAME alias";
    return false;
  }
  const auto [iterator, inserted] = aliases->emplace(alias, source_index);
  if (!inserted && iterator->second != source_index) {
    *error = "ambiguous guest module name/SONAME: " + alias;
    return false;
  }
  return true;
}

}  // namespace

const A64GuestModule* A64GuestModuleSet::FindModule(
    const std::string& name) const noexcept {
  const auto basename = Basename(name);
  for (const auto& module : modules) {
    if (module.source_name == name || Basename(module.source_name) == basename ||
        (!module.image.soname.empty() && module.image.soname == name)) {
      return &module;
    }
  }
  return nullptr;
}

std::optional<std::uint64_t> A64GuestModuleSet::ResolveExportedSymbol(
    const std::string& name) const noexcept {
  for (const auto& module : modules) {
    for (const auto& symbol : module.image.exported_symbols) {
      if (symbol.name == name) return symbol.guest_address;
    }
  }
  return std::nullopt;
}

A64GuestModuleLoadResult LoadA64GuestModuleSet(
    const std::vector<A64GuestModuleSource>& sources,
    const std::string& root_name, A64GuestModuleLoadOptions options) {
  if (sources.empty()) return Failure("guest module catalogue is empty");
  if (root_name.empty()) return Failure("root guest module name is empty");
  if (options.max_modules == 0 || options.max_total_image_size == 0) {
    return Failure("guest module limits must be greater than zero");
  }
  if (options.elf.max_image_size == 0) {
    return Failure("ELF image limit must be greater than zero");
  }

  try {
    std::map<std::string, std::size_t> aliases;
    for (std::size_t index = 0; index < sources.size(); ++index) {
      if (sources[index].name.empty() || sources[index].bytes.empty()) {
        return Failure("guest module source has an empty name or file");
      }
      std::string alias_error;
      if (!AddAlias(&aliases, sources[index].name, index, &alias_error) ||
          !AddAlias(&aliases, Basename(sources[index].name), index,
                    &alias_error)) {
        return Failure(alias_error);
      }
    }

    const auto root_alias = aliases.find(root_name);
    if (root_alias == aliases.end()) {
      return Failure("root guest module was not found in the supplied catalogue: " +
                     root_name);
    }

    std::set<std::string> external_dependencies;
    for (const auto& dependency : options.external_dependencies) {
      if (dependency.empty()) {
        return Failure("external dependency allow-list contains an empty name");
      }
      external_dependencies.insert(dependency);
    }

    std::vector<DiscoveredModule> discovered;
    std::map<std::size_t, std::size_t> source_to_module;
    std::uint64_t next_preferred_base = options.first_module_base;
    std::size_t total_image_size = 0;

    auto discover = [&](std::size_t source_index) -> std::string {
      if (source_to_module.find(source_index) != source_to_module.end()) {
        return {};
      }
      if (discovered.size() >= options.max_modules) {
        return "guest dependency graph exceeds the configured module limit";
      }

      const auto preferred_base = next_preferred_base;
      A64ElfLoadOptions preflight_options = options.elf;
      preflight_options.preferred_base = preferred_base;
      // The metadata pass must be able to enumerate dependencies and exports
      // before the complete module set exists. Zero is a temporary placeholder
      // only: all modules are loaded again and all relocations are recomputed
      // with the final resolver below.
      preflight_options.resolve_symbol =
          [](const std::string&) -> std::optional<std::uint64_t> {
        return std::uint64_t{0};
      };

      auto loaded = LoadA64Elf(sources[source_index].bytes,
                               std::move(preflight_options));
      if (!loaded) {
        return "failed to inspect guest module '" + sources[source_index].name +
               "': " + loaded.error;
      }
      if (loaded.image->load_bias == 0) {
        return "guest module '" + sources[source_index].name +
               "' is not a relocatable ET_DYN shared object";
      }
      if (loaded.image->image_size > options.max_total_image_size ||
          total_image_size > options.max_total_image_size -
                                 static_cast<std::size_t>(loaded.image->image_size)) {
        return "guest module set exceeds the configured total image-size limit";
      }
      total_image_size += static_cast<std::size_t>(loaded.image->image_size);

      const auto image_end = loaded.image->base_address + loaded.image->image_size;
      if (AddOverflows(loaded.image->base_address, loaded.image->image_size) ||
          AddOverflows(image_end, options.module_gap)) {
        return "guest module address allocation overflows";
      }
      next_preferred_base = image_end + options.module_gap;

      const auto module_index = discovered.size();
      source_to_module.emplace(source_index, module_index);
      discovered.push_back(DiscoveredModule{
          source_index, preferred_base, std::move(*loaded.image)});
      if (!discovered.back().metadata_image.soname.empty()) {
        std::string alias_error;
        if (!AddAlias(&aliases, discovered.back().metadata_image.soname,
                      source_index, &alias_error)) {
          return alias_error;
        }
      }
      return {};
    };

    const auto discovery_error = discover(root_alias->second);
    if (!discovery_error.empty()) return Failure(discovery_error);

    for (std::size_t index = 0; index < discovered.size(); ++index) {
      for (const auto& dependency :
           discovered[index].metadata_image.dependencies) {
        if (aliases.find(dependency) == aliases.end()) {
          if (external_dependencies.find(dependency) !=
              external_dependencies.end()) {
            continue;
          }
          return Failure("missing guest dependency '" + dependency +
                         "' required by '" +
                         sources[discovered[index].source_index].name + "'");
        }
        const auto dependency_source = aliases.find(dependency)->second;
        const auto error = discover(dependency_source);
        if (!error.empty()) return Failure(error);
      }
    }

    A64GuestModuleSet result;
    result.root_index = 0;
    result.modules.reserve(discovered.size());

    auto resolve_symbol = [&](const std::string& name)
        -> std::optional<std::uint64_t> {
      for (const auto& module : discovered) {
        for (const auto& symbol : module.metadata_image.exported_symbols) {
          if (symbol.name == name) return symbol.guest_address;
        }
      }
      if (options.resolve_external_symbol) {
        return options.resolve_external_symbol(name);
      }
      return std::nullopt;
    };

    for (const auto& module : discovered) {
      A64ElfLoadOptions final_options = options.elf;
      final_options.preferred_base = module.preferred_base;
      final_options.resolve_symbol = resolve_symbol;
      auto loaded = LoadA64Elf(sources[module.source_index].bytes,
                               std::move(final_options));
      if (!loaded) {
        return Failure("failed to relocate guest module '" +
                       sources[module.source_index].name + "': " +
                       loaded.error);
      }
      if (loaded.image->base_address != module.metadata_image.base_address ||
          loaded.image->image_size != module.metadata_image.image_size) {
        return Failure("guest module layout changed between metadata and relocation passes");
      }
      result.modules.push_back(A64GuestModule{
          sources[module.source_index].name, std::move(*loaded.image)});
    }

    return A64GuestModuleLoadResult{std::move(result), {}};
  } catch (const std::bad_alloc&) {
    return Failure("host memory allocation failed while loading guest module set");
  }
}

}  // namespace mocktail::translation
