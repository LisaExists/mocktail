// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#ifndef MOCKTAIL_TRANSLATION_A64_GUEST_HOST_CALLS_H_
#define MOCKTAIL_TRANSLATION_A64_GUEST_HOST_CALLS_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "translation/a64_elf_loader.h"

namespace mocktail::translation {

class A64GuestMemory;
class A64GuestTlsRuntime;
struct A64GuestThreadTls;

struct A64HostCallResult final {
  bool success = true;
  std::uint64_t value = 0;
  std::string error;
};

// Explicit host-call thunk table for AArch64 guest imports. Every thunk is a
// guest executable stub containing SVC + RET; SVC immediates are handled by the
// guest runtime and are never forwarded to the host kernel. Guest pointers stay
// numeric and are copied through A64GuestMemory instead of becoming host pointers.
class A64GuestHostCalls final {
 public:
  static constexpr std::uint64_t kDefaultStubBase = 0x7FFF100000ULL;
  static constexpr std::uint32_t kFirstSvcImmediate = 0x8000U;
  static constexpr std::size_t kMaximumTransferBytes = 64U * 1024U * 1024U;
  static constexpr std::size_t kMaximumCStringBytes = 1024U * 1024U;

  using Arguments = std::array<std::uint64_t, 8>;
  using Handler = std::function<A64HostCallResult(const Arguments&)>;

  explicit A64GuestHostCalls(
      A64GuestMemory& memory,
      std::uint64_t stub_base = kDefaultStubBase) noexcept;
  ~A64GuestHostCalls() noexcept;

  A64GuestHostCalls(const A64GuestHostCalls&) = delete;
  A64GuestHostCalls& operator=(const A64GuestHostCalls&) = delete;

  bool Register(std::string name, std::string provider, std::string version,
                Handler handler, std::string* error = nullptr);
  // Registers an already-mapped guest data object (not an SVC thunk).
  bool RegisterDataSymbol(std::string name, std::string provider,
                          std::string version, std::uint64_t guest_address,
                          std::string* error = nullptr);

  // Registers a small explicit libc subset with guest-memory-aware wrappers.
  // This deliberately does not expose arbitrary host function pointers.
  bool RegisterBuiltinLibc(std::string* error = nullptr);

  // Updates the guest process errno cell without touching host thread-local errno.
  bool SetGuestErrno(std::int32_t value) noexcept;

  // Registers __tls_get_addr for a prepared, preloaded static TLS set. The
  // provider/version must match the requested import identity.
  bool RegisterTlsGetAddr(const A64GuestTlsRuntime& runtime,
                          const A64GuestThreadTls& thread,
                          std::string provider, std::string version,
                          std::string* error = nullptr);

  // Reserve/map RX guest stubs after registering all exports. A stub's address
  // is then suitable for an AArch64 dynamic relocation.
  bool Install(std::string* error = nullptr);

  std::optional<std::uint64_t> ResolveSymbol(
      const std::string& name) const noexcept;
  std::optional<std::uint64_t> ResolveVersionedSymbol(
      const A64SymbolRequest& request) const noexcept;

  bool HandlesSvc(std::uint32_t immediate) const noexcept;
  A64HostCallResult DispatchSvc(std::uint32_t immediate,
                                const Arguments& arguments);

 private:
  struct Export final {
    std::string name;
    std::string provider;
    std::string version;
    Handler handler;
    std::uint64_t guest_address = 0;
    std::uint32_t svc_immediate = 0;
    bool data_symbol = false;
  };

  A64GuestMemory& memory_;
  std::uint64_t stub_base_;
  std::uint64_t errno_address_ = 0;
  mutable std::mutex mutex_;
  std::vector<Export> exports_;
  std::map<std::uint64_t, std::size_t> allocations_;
  bool installed_ = false;
};

}  // namespace mocktail::translation

#endif  // MOCKTAIL_TRANSLATION_A64_GUEST_HOST_CALLS_H_
