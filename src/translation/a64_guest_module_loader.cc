// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_module_loader.h"

#include <elf.h>

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

bool IsPowerOfTwo(std::uint64_t value) noexcept {
  return value != 0 && (value & (value - 1U)) == 0;
}

bool AlignUp(std::uint64_t value, std::uint64_t alignment,
             std::uint64_t* result) noexcept {
  if (!IsPowerOfTwo(alignment)) return false;
  const auto mask = alignment - 1U;
  if (value > std::numeric_limits<std::uint64_t>::max() - mask) return false;
  *result = (value + mask) & ~mask;
  return true;
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
    const std::string& name) const {
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
    const std::string& name) const {
  for (const auto& module : modules) {
    for (const auto& symbol : module.image.exported_symbols) {
      if (symbol.name == name &&
          (symbol.version.empty() || !symbol.version_hidden)) {
        return symbol.guest_address;
      }
    }
  }
  return std::nullopt;
}

std::optional<A64TlsSymbol> A64GuestModuleSet::ResolveTlsSymbol(
    const A64SymbolRequest& request) const {
  for (const auto& module : modules) {
    if (!request.provider.empty() &&
        module.image.soname != request.provider &&
        module.source_name != request.provider &&
        Basename(module.source_name) != request.provider) {
      continue;
    }
    for (const auto& symbol : module.image.exported_symbols) {
      if (symbol.type != STT_TLS || symbol.name != request.name) continue;
      if (request.version.empty()) {
        if (symbol.version.empty() || !symbol.version_hidden) {
          return A64TlsSymbol{symbol.tls_module_id,
                              symbol.tls_module_offset,
                              symbol.tls_static_offset_from_tp};
        }
      } else if (symbol.version == request.version) {
        return A64TlsSymbol{symbol.tls_module_id,
                            symbol.tls_module_offset,
                            symbol.tls_static_offset_from_tp};
      }
    }
  }
  return std::nullopt;
}

std::optional<std::uint64_t> A64GuestModuleSet::ResolveExportedSymbol(
    const A64SymbolRequest& request) const {
  for (const auto& module : modules) {
    if (!request.provider.empty() &&
        module.image.soname != request.provider &&
        module.source_name != request.provider &&
        Basename(module.source_name) != request.provider) {
      continue;
    }
    for (const auto& symbol : module.image.exported_symbols) {
      if (symbol.name != request.name) continue;
      if (request.version.empty()) {
        if (symbol.version.empty() || !symbol.version_hidden) {
          return symbol.guest_address;
        }
      } else if (symbol.version == request.version) {
        return symbol.guest_address;
      }
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
      preflight_options.resolve_versioned_symbol =
          [](const A64SymbolRequest&) -> std::optional<std::uint64_t> {
        return std::uint64_t{0};
      };
      preflight_options.resolve_tls_symbol =
          [](const A64SymbolRequest&) -> std::optional<A64TlsSymbol> {
        return A64TlsSymbol{1, 0, 16};
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
      // discover() may append to the vector and reallocate it, so retain a
      // snapshot of this object's dependencies while extending the graph.
      const auto requester_name =
          sources[discovered[index].source_index].name;
      const auto dependencies =
          discovered[index].metadata_image.dependencies;
      for (const auto& dependency : dependencies) {
        if (aliases.find(dependency) == aliases.end()) {
          if (external_dependencies.find(dependency) !=
              external_dependencies.end()) {
            continue;
          }
          return Failure("missing guest dependency '" + dependency +
                         "' required by '" + requester_name + "'");
        }
        const auto dependency_source = aliases.find(dependency)->second;
        const auto error = discover(dependency_source);
        if (!error.empty()) return Failure(error);
      }
    }

    // Assign one stable module ID and static TP-relative range to every
    // PT_TLS image before applying final relocations. This supports preloaded
    // static TLS and static TLSDESC only; dlopen-style dynamic TLS is separate.
    constexpr std::uint64_t kStaticTlsTcbPrefixSize = 16;
    constexpr std::uint64_t kMaximumStaticTlsBytes = 64U * 1024U * 1024U;
    constexpr std::uint64_t kMaximumStaticTlsAlignment = 1U * 1024U * 1024U;
    std::uint64_t tls_cursor = kStaticTlsTcbPrefixSize;
    std::uint64_t next_tls_module_id = 1;
    for (auto& module : discovered) {
      auto& image = module.metadata_image;
      if (!image.tls) continue;
      auto& tls = *image.tls;
      const auto alignment = std::max<std::uint64_t>(tls.alignment, 1);
      if (!IsPowerOfTwo(alignment) ||
          alignment > kMaximumStaticTlsAlignment) {
        return Failure("PT_TLS alignment exceeds the supported static TLS layout");
      }
      if (tls.memory_size != tls.template_bytes.size() ||
          tls.file_size > tls.memory_size) {
        return Failure("PT_TLS template has inconsistent sizes");
      }
      std::uint64_t aligned_cursor = 0;
      if (!AlignUp(tls_cursor, alignment, &aligned_cursor) ||
          AddOverflows(aligned_cursor, tls.memory_size)) {
        return Failure("static guest TLS layout overflows");
      }
      const auto next_cursor_value = aligned_cursor + tls.memory_size;
      if (next_cursor_value < kStaticTlsTcbPrefixSize ||
          next_cursor_value - kStaticTlsTcbPrefixSize >
              kMaximumStaticTlsBytes) {
        return Failure("static guest TLS layout exceeds the configured limit");
      }
      tls.module_id = next_tls_module_id++;
      tls.static_offset_from_tp = aligned_cursor;
      tls_cursor = next_cursor_value;

      for (auto& symbol : image.exported_symbols) {
        if (symbol.type != STT_TLS) continue;
        if (symbol.tls_module_offset > tls.memory_size ||
            symbol.size > tls.memory_size - symbol.tls_module_offset ||
            AddOverflows(tls.static_offset_from_tp,
                         symbol.tls_module_offset)) {
          return Failure("exported TLS symbol is outside its module TLS block");
        }
        symbol.tls_module_id = tls.module_id;
        symbol.tls_static_offset_from_tp =
            tls.static_offset_from_tp + symbol.tls_module_offset;
      }
    }

    A64GuestModuleSet result;
    result.root_index = 0;
    result.modules.reserve(discovered.size());

    auto resolve_symbol = [&](const std::string& name)
        -> std::optional<std::uint64_t> {
      for (const auto& module : discovered) {
        for (const auto& symbol : module.metadata_image.exported_symbols) {
          if (symbol.type != STT_TLS && symbol.name == name &&
              (symbol.version.empty() || !symbol.version_hidden)) {
            return symbol.guest_address;
          }
        }
      }
      if (options.resolve_external_symbol) {
        return options.resolve_external_symbol(name);
      }
      return std::nullopt;
    };

    auto resolve_versioned_symbol = [&](const A64SymbolRequest& request)
        -> std::optional<std::uint64_t> {
      for (const auto& module : discovered) {
        const auto& image = module.metadata_image;
        const auto& source_name = sources[module.source_index].name;
        if (!request.provider.empty() &&
            image.soname != request.provider &&
            source_name != request.provider &&
            Basename(source_name) != request.provider) {
          continue;
        }
        for (const auto& symbol : image.exported_symbols) {
          if (symbol.type != STT_TLS && symbol.name == request.name &&
              symbol.version == request.version) {
            return symbol.guest_address;
          }
        }
      }
      if (options.resolve_external_versioned_symbol) {
        return options.resolve_external_versioned_symbol(request);
      }
      return std::nullopt;
    };

    auto resolve_tls_symbol = [&](const A64SymbolRequest& request)
        -> std::optional<A64TlsSymbol> {
      for (const auto& module : discovered) {
        const auto& image = module.metadata_image;
        const auto& source_name = sources[module.source_index].name;
        if (!request.provider.empty() &&
            image.soname != request.provider &&
            source_name != request.provider &&
            Basename(source_name) != request.provider) {
          continue;
        }
        for (const auto& symbol : image.exported_symbols) {
          if (symbol.type != STT_TLS || symbol.name != request.name) continue;
          if (request.version.empty()) {
            if (symbol.version.empty() || !symbol.version_hidden) {
              return A64TlsSymbol{symbol.tls_module_id,
                                  symbol.tls_module_offset,
                                  symbol.tls_static_offset_from_tp};
            }
          } else if (symbol.version == request.version) {
            return A64TlsSymbol{symbol.tls_module_id,
                                symbol.tls_module_offset,
                                symbol.tls_static_offset_from_tp};
          }
        }
      }
      if (options.resolve_external_tls_symbol) {
        return options.resolve_external_tls_symbol(request);
      }
      return std::nullopt;
    };

    for (const auto& module : discovered) {
      A64ElfLoadOptions final_options = options.elf;
      final_options.preferred_base = module.preferred_base;
      final_options.resolve_symbol = resolve_symbol;
      final_options.resolve_versioned_symbol = resolve_versioned_symbol;
      final_options.resolve_tls_symbol = resolve_tls_symbol;
      if (module.metadata_image.tls) {
        final_options.tls_module_id = module.metadata_image.tls->module_id;
        final_options.tls_static_offset_from_tp =
            module.metadata_image.tls->static_offset_from_tp;
      }
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

    // Emit a dependency-first postorder. Circular DT_NEEDED graphs are legal;
    // an edge back into the active DFS path is skipped, while every module is
    // still emitted once. Constructor execution can use this order later.
    std::vector<std::uint8_t> visit_state(result.modules.size(), 0);
    auto visit_module = [&](auto&& self, std::size_t module_index) -> void {
      if (visit_state[module_index] == 2) return;
      if (visit_state[module_index] == 1) return;
      visit_state[module_index] = 1;

      const auto dependencies =
          result.modules[module_index].image.dependencies;
      for (const auto& dependency : dependencies) {
        const auto* dependency_module = result.FindModule(dependency);
        if (dependency_module == nullptr) continue;  // Explicit external thunk.
        const auto dependency_index = static_cast<std::size_t>(
            dependency_module - result.modules.data());
        if (dependency_index < result.modules.size()) {
          self(self, dependency_index);
        }
      }

      visit_state[module_index] = 2;
      result.initialization_order.push_back(module_index);
    };

    for (std::size_t index = 0; index < result.modules.size(); ++index) {
      visit_module(visit_module, index);
    }
    result.finalization_order = result.initialization_order;
    std::reverse(result.finalization_order.begin(),
                 result.finalization_order.end());

    return A64GuestModuleLoadResult{std::move(result), {}};
  } catch (const std::bad_alloc&) {
    return Failure("host memory allocation failed while loading guest module set");
  }
}

}  // namespace mocktail::translation
