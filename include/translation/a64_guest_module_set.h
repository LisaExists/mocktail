// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#ifndef MOCKTAIL_TRANSLATION_A64_GUEST_MODULE_SET_H_
#define MOCKTAIL_TRANSLATION_A64_GUEST_MODULE_SET_H_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "translation/a64_elf_loader.h"
#include "translation/a64_guest_memory.h"

namespace mocktail::translation {

struct A64GuestModuleInput final {
  // Diagnostic label used when reporting load failures.
  std::string name;
  std::vector<std::uint8_t> bytes;
};

struct A64GuestModule final {
  std::string input_name;
  std::string soname;
  A64LoadedImage image;
};

// Loads a supplied set of Android/AArch64 shared objects as one address space.
// All DT_NEEDED dependencies must be present in the supplied set. Loading is
// transactional: the object publishes its modules and mappings only on success.
class A64GuestModuleSet final {
 public:
  explicit A64GuestModuleSet(
      std::size_t max_guest_memory = 1024U * 1024U * 1024U) noexcept;

  A64GuestModuleSet(const A64GuestModuleSet&) = delete;
  A64GuestModuleSet& operator=(const A64GuestModuleSet&) = delete;
  A64GuestModuleSet(A64GuestModuleSet&&) noexcept = default;
  A64GuestModuleSet& operator=(A64GuestModuleSet&&) noexcept = default;

  // Each item must be an AArch64 ET_DYN object. Module order defines symbol
  // lookup order for interposition. Dependencies may appear before or after
  // their dependents; all images are loaded before deferred imports resolve.
  bool Load(const std::vector<A64GuestModuleInput>& inputs,
            std::string* error);

  bool loaded() const noexcept { return loaded_; }
  const std::vector<A64GuestModule>& modules() const noexcept {
    return modules_;
  }

  A64GuestMemory& memory() noexcept { return memory_; }
  const A64GuestMemory& memory() const noexcept { return memory_; }

  const A64GuestModule* FindBySoname(const std::string& soname) const noexcept;
  std::optional<std::uint64_t> FindSymbol(
      const std::string& symbol_name) const noexcept;

 private:
  A64GuestMemory memory_;
  std::vector<A64GuestModule> modules_;
  bool loaded_ = false;
};

}  // namespace mocktail::translation

#endif  // MOCKTAIL_TRANSLATION_A64_GUEST_MODULE_SET_H_
