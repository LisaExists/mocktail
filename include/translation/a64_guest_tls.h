// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#ifndef MOCKTAIL_TRANSLATION_A64_GUEST_TLS_H_
#define MOCKTAIL_TRANSLATION_A64_GUEST_TLS_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "translation/a64_guest_module_loader.h"

namespace mocktail::translation {

class A64GuestMemory;

// Per-guest-thread TLS allocation. tpidr_el0 is host storage for Dynarmic's
// emulated TPIDR_EL0 register; its value is a guest virtual address.
struct A64GuestThreadTls final {
  std::uint64_t allocation_base = 0;
  std::uint64_t allocation_size = 0;
  std::uint64_t thread_pointer = 0;
  std::uint64_t tpidr_el0 = 0;

  bool valid() const noexcept {
    return allocation_size != 0 && thread_pointer != 0 &&
           tpidr_el0 == thread_pointer;
  }
};

// Prototype static TLS layout for one guest address space. It creates
// independent initialized TLS images per guest thread and uses AArch64's
// TP-relative layout: a two-word TCB prefix begins at TP, TLS blocks follow
// at their required alignments. This is not yet a full Bionic TCB/DTV or
// dynamic-TLS/TLSDESC implementation.
class A64GuestTlsRuntime final {
 public:
  static constexpr std::uint64_t kTcbPrefixSize = 2U * sizeof(std::uint64_t);
  static constexpr std::size_t kDefaultMaximumTlsBytes = 64U * 1024U * 1024U;

  explicit A64GuestTlsRuntime(
      A64GuestMemory& memory,
      std::size_t max_tls_bytes = kDefaultMaximumTlsBytes) noexcept;

  // Assigns stable module IDs and static TP offsets to every PT_TLS module.
  // Must be called once after the final guest module set has been loaded,
  // before creating any guest thread.
  bool Prepare(A64GuestModuleSet& modules, std::string* error = nullptr);

  // Creates a new independent TLS mapping, copies each module's initialized
  // TLS image and leaves its BSS zero-filled. The returned tpidr_el0 field is
  // suitable for UserConfig::tpidr_el0.
  bool CreateThread(A64GuestThreadTls* thread,
                    std::string* error = nullptr);

  // Unmaps a TLS allocation created by this runtime and clears its descriptor.
  bool DestroyThread(A64GuestThreadTls* thread,
                     std::string* error = nullptr);

  bool prepared() const noexcept { return prepared_; }
  std::uint64_t total_tls_size() const noexcept { return total_tls_size_; }
  std::uint64_t maximum_alignment() const noexcept { return maximum_alignment_; }

 private:
  struct ModuleTemplate final {
    std::uint64_t module_id = 0;
    std::uint64_t offset_from_tp = 0;
    std::vector<std::uint8_t> bytes;
  };

  A64GuestMemory& memory_;
  std::size_t max_tls_bytes_;
  std::uint64_t total_tls_size_ = 0;
  std::uint64_t maximum_alignment_ = kTcbPrefixSize;
  std::vector<ModuleTemplate> templates_;
  bool prepared_ = false;
};

}  // namespace mocktail::translation

#endif  // MOCKTAIL_TRANSLATION_A64_GUEST_TLS_H_
