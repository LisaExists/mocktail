// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#ifndef MOCKTAIL_TRANSLATION_A64_GUEST_RUNTIME_H_
#define MOCKTAIL_TRANSLATION_A64_GUEST_RUNTIME_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "translation/a64_guest_module_loader.h"
#include "translation/a64_guest_jni.h"

namespace mocktail::translation {

class A64GuestHostCalls;
class A64GuestMemory;
class A64GuestTlsRuntime;
struct A64GuestThreadTls;

struct A64GuestRuntimeOptions final {
  A64GuestModuleLoadOptions module_load;
  std::size_t max_guest_memory_bytes = 1024U * 1024U * 1024U;
  // stack_base identifies the first writable stack page. Guard pages are
  // mapped with no permissions immediately below and above the stack.
  std::uint64_t stack_base = 0x7000000000ULL;
  std::uint64_t stack_size = 2U * 1024U * 1024U;
  std::uint32_t stack_guard_pages = 1;
  std::uint64_t return_trap_address = 0x7FFF000000ULL;
  std::uint64_t instruction_budget = 50U * 1000U * 1000U;
  std::size_t max_tls_bytes = 64U * 1024U * 1024U;
  bool register_builtin_libc = true;
  bool run_initializers_on_load = false;
  bool enable_jni_bridge = true;
  std::vector<std::string> jni_available_classes = {
      "java/lang/Object", "java/lang/String", "java/lang/Class",
      "java/lang/Throwable", "java/lang/RuntimeException",
      "java/lang/IllegalArgumentException"};

  // Synthetic Android property profile exposed by __system_property_get.
  // Override these values when probing a specific target profile; this does
  // not query or leak properties from the x86-64 host operating system.
  std::map<std::string, std::string> android_system_properties = {
      {"ro.build.version.sdk", "36"},
      {"ro.build.version.release", "16"},
      {"ro.build.version.codename", "REL"},
      {"ro.product.cpu.abi", "arm64-v8a"},
      {"ro.product.cpu.abilist", "arm64-v8a"},
      {"ro.product.cpu.abilist32", ""},
      {"ro.product.cpu.abilist64", "arm64-v8a"},
      {"ro.product.manufacturer", "Mocktail"},
      {"ro.product.model", "Mocktail AArch64 Guest"},
      {"ro.build.characteristics", "emulator"},
      {"ro.kernel.qemu", "1"},
      {"ro.hardware", "mocktail"},
      {"ro.build.type", "userdebug"},
      {"ro.build.tags", "test-keys"},
      {"ro.debuggable", "1"},
      {"ro.secure", "0"},
  };

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

  // Invoke JNI_OnLoad with the guest JavaVM* supplied by this bridge. This
  // validates the JNI invocation table and can collect RegisterNatives calls,
  // but it does not instantiate ART or a Java framework.
  A64GuestCallResult CallJniOnLoad(
      std::uint64_t instruction_budget = 0);

  // Invokes a method recorded by RegisterNatives using the JNI static-native
  // ABI. Integer/reference parameters use X2-X7 and float/double parameters
  // use V0-V7, independently; overflow arguments use AAPCS64 stack slots.
  // java_arguments contains raw values, with F/D arguments supplied as their
  // IEEE-754 bit patterns. ART/object construction and floating-point return
  // value reporting are not implemented.
  A64GuestCallResult CallRegisteredJniNative(
      const std::string& class_name, const std::string& name,
      const std::string& signature,
      const std::vector<std::uint64_t>& java_arguments,
      std::uint64_t instruction_budget = 0);

  std::uint64_t java_vm_address() const noexcept;
  std::uint64_t jni_environment_address() const noexcept;
  bool jni_exception_pending() const noexcept;
  std::vector<A64GuestJniNativeRegistration> registered_jni_natives() const;

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
