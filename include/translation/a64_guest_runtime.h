// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#ifndef MOCKTAIL_TRANSLATION_A64_GUEST_RUNTIME_H_
#define MOCKTAIL_TRANSLATION_A64_GUEST_RUNTIME_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "translation/a64_guest_module_loader.h"

namespace mocktail::translation {

class A64GuestHostCalls;
class A64GuestMemory;
class A64GuestTlsRuntime;
struct A64GuestThreadTls;

struct A64GuestRuntimeOptions final {
  A64GuestModuleLoadOptions module_load;
  std::size_t max_guest_memory_bytes = 1024U * 1024U * 1024U;
  std::uint64_t stack_base = 0x7000000000ULL;
  std::uint64_t stack_size = 2U * 1024U * 1024U;
  std::uint64_t return_trap_address = 0x7FFF000000ULL;
  std::uint64_t instruction_budget = 50U * 1000U * 1000U;
  std::size_t max_tls_bytes = 64U * 1024U * 1024U;
  bool register_builtin_libc = true;
  bool run_initializers_on_load = false;

  // Called after the built-in libc/TLS exports are registered but before
  // guest SVC stubs are installed. Applications can register explicit JNI,
  // Android platform, or test-only exports here. Arbitrary host function
  // pointers are never exposed to guest code.
  std::function<bool(A64GuestHostCalls&, std::string*)>
      configure_host_calls;
};

struct A64GuestCallResult final {
  bool success = false;
  bool guest_exit = false;
  std::uint32_t exit_status = 0;
  std::uint64_t value = 0;
  std::uint64_t ticks = 0;
  std::string error;

  explicit operator bool() const noexcept { return success; }
};

// Reusable single-guest-thread AArch64 process runtime. It composes the ELF
// module linker, sparse guest address space, static TLS, explicit guest-to-host
// thunks, an allow-listed Linux syscall dispatcher, and Dynarmic's A64 JIT.
// This is compatibility infrastructure, not a complete Android/Bionic runtime.
class A64GuestRuntime final {
 public:
  using Arguments = std::array<std::uint64_t, 8>;

  explicit A64GuestRuntime(A64GuestRuntimeOptions options = {});
  ~A64GuestRuntime();

  A64GuestRuntime(A64GuestRuntime&&) noexcept;
  A64GuestRuntime& operator=(A64GuestRuntime&&) noexcept;
  A64GuestRuntime(const A64GuestRuntime&) = delete;
  A64GuestRuntime& operator=(const A64GuestRuntime&) = delete;

  // A runtime instance is single-use. This loads the requested DT_NEEDED
  // closure, lays out static TLS, maps all images and allocates the main stack.
  bool Load(const std::vector<A64GuestModuleSource>& sources,
            const std::string& root_name, std::string* error = nullptr);

  // Executes validated ELF callbacks in dependency order. Each callback gets
  // the prototype's zero-argument call convention and a bounded instruction
  // budget. Automatic Android startup semantics are not implied.
  bool RunInitializers(std::string* error = nullptr);
  bool RunFinalizers(std::string* error = nullptr);

  // Calls one executable guest address using AAPCS64 argument registers X0-X7.
  // The target must return through X30; instruction_budget=0 uses the runtime
  // default. Guest exit, unexpected exceptions and budget exhaustion are
  // reported in the returned result.
  A64GuestCallResult Call(std::uint64_t guest_address,
                          const Arguments& arguments = {},
                          std::uint64_t instruction_budget = 0);

  A64GuestCallResult CallSymbol(const std::string& symbol,
                               const Arguments& arguments = {},
                               std::uint64_t instruction_budget = 0);
  A64GuestCallResult CallSymbol(const A64SymbolRequest& request,
                               const Arguments& arguments = {},
                               std::uint64_t instruction_budget = 0);

  bool loaded() const noexcept;
  const A64GuestModuleSet* modules() const noexcept;
  A64GuestMemory* memory() noexcept;
  A64GuestHostCalls* host_calls() noexcept;
  A64GuestTlsRuntime* tls_runtime() noexcept;
  const A64GuestThreadTls* main_thread_tls() const noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace mocktail::translation

#endif  // MOCKTAIL_TRANSLATION_A64_GUEST_RUNTIME_H_
