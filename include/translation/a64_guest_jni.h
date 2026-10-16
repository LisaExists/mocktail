// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#ifndef MOCKTAIL_TRANSLATION_A64_GUEST_JNI_H_
#define MOCKTAIL_TRANSLATION_A64_GUEST_JNI_H_

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace mocktail::translation {

class A64GuestHostCalls;
class A64GuestMemory;

struct A64GuestJniNativeRegistration final {
  std::string class_name;
  std::string name;
  std::string signature;
  std::uint64_t guest_address = 0;
};

// A deliberately small JNI invocation/native-registration compatibility layer.
// It presents guest-resident JavaVM/JNIEnv function tables whose entries point
// only to explicit AArch64 SVC thunks. It is not an ART or Java implementation:
// classes must be supplied by the embedding application, object references are
// opaque handles, and Java method dispatch/reflection are not implemented.
class A64GuestJniBridge final {
 public:
  static constexpr std::int32_t kJniVersion16 = 0x00010006;
  static constexpr std::int32_t kJniError = -1;
  static constexpr std::int32_t kJniVersionError = -3;

  static constexpr std::size_t kNativeTableEntries = 233;
  static constexpr std::size_t kInvocationTableEntries = 8;
  static constexpr std::size_t kMaximumNativeMethods = 4096;

  A64GuestJniBridge(A64GuestMemory& memory, A64GuestHostCalls& host_calls,
                    std::vector<std::string> available_classes);
  ~A64GuestJniBridge() noexcept;

  A64GuestJniBridge(const A64GuestJniBridge&) = delete;
  A64GuestJniBridge& operator=(const A64GuestJniBridge&) = delete;

  // Register handlers before A64GuestHostCalls::Install().
  bool Register(std::string* error = nullptr);

  // Build read-only guest JavaVM/JNIEnv objects and function tables after the
  // host-call stubs have been installed. Guest pointers are numeric guest
  // addresses, never host pointers.
  bool Initialize(std::string* error = nullptr);

  bool initialized() const noexcept { return initialized_; }
  std::uint64_t java_vm_address() const noexcept { return java_vm_address_; }
  std::uint64_t jni_environment_address() const noexcept {
    return jni_environment_address_;
  }

  // Returns a cached opaque class handle created by FindClass, or zero when
  // this bridge has not resolved the requested class.
  std::uint64_t FindClassHandle(const std::string& class_name) const noexcept;

  bool pending_exception() const noexcept;
  std::vector<A64GuestJniNativeRegistration> registered_natives() const;
  std::size_t registered_native_count() const noexcept;

 private:
  struct Mapping final {
    std::uint64_t address = 0;
    std::uint64_t size = 0;
  };

  struct NativeMethod final {
    std::uint64_t name_pointer = 0;
    std::uint64_t signature_pointer = 0;
    std::uint64_t function_pointer = 0;
  };

  struct StringCharsAllocation final {
    std::uint64_t string_handle = 0;
    std::uint64_t allocation_size = 0;
  };

  bool MapReadOnly(const void* bytes, std::size_t size,
                   std::uint64_t* address, std::string* error);
  bool ResolveStub(const char* name, std::uint64_t* address,
                   std::string* error) const;
  bool ReadGuestString(std::uint64_t address, std::size_t maximum,
                       std::string* value, std::string* error) const;
  std::uint64_t FindOrCreateClassHandle(const std::string& class_name);
  bool IsStringHandle(std::uint64_t handle) const noexcept;
  void SetPendingException(bool pending) noexcept;
  void ClearMappings() noexcept;

  A64GuestMemory& memory_;
  A64GuestHostCalls& host_calls_;
  std::set<std::string> available_classes_;
  mutable std::mutex mutex_;
  std::map<std::string, std::uint64_t> class_handles_by_name_;
  std::map<std::uint64_t, std::string> class_names_by_handle_;
  std::vector<A64GuestJniNativeRegistration> registered_natives_;
  std::map<std::uint64_t, std::string> string_values_by_handle_;
  std::map<std::uint64_t, StringCharsAllocation> string_chars_allocations_;
  std::vector<Mapping> mappings_;

  std::uint64_t native_function_table_address_ = 0;
  std::uint64_t invocation_function_table_address_ = 0;
  std::uint64_t jni_environment_address_ = 0;
  std::uint64_t java_vm_address_ = 0;
  std::uint64_t next_class_handle_ = 0x4A4E490000000100ULL;
  std::uint64_t next_string_handle_ = 0x4A4E530000000100ULL;
  bool registered_ = false;
  bool initialized_ = false;
  bool pending_exception_ = false;
};

}  // namespace mocktail::translation

#endif  // MOCKTAIL_TRANSLATION_A64_GUEST_JNI_H_
