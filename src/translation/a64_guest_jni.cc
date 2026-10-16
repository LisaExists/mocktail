// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_jni.h"

#include <algorithm>
#include <array>
#include <limits>
#include <new>

#include "translation/a64_guest_host_calls.h"
#include "translation/a64_guest_memory.h"

namespace mocktail::translation {
namespace {

constexpr std::uint64_t kPageMask = A64GuestMemory::kPageSize - 1U;
constexpr std::size_t kMaximumJniStringBytes = 1024U * 1024U;
constexpr std::size_t kJniNativeMethodSize = 3U * sizeof(std::uint64_t);

// JNI Native Interface table indices from the JNI 1.6 ABI.
constexpr std::size_t kJniGetVersion = 4;
constexpr std::size_t kJniGetSuperclass = 10;
constexpr std::size_t kJniIsAssignableFrom = 11;
constexpr std::size_t kJniThrow = 13;
constexpr std::size_t kJniExceptionOccurred = 15;
constexpr std::size_t kJniExceptionDescribe = 16;
constexpr std::size_t kJniExceptionClear = 17;
constexpr std::size_t kJniPushLocalFrame = 19;
constexpr std::size_t kJniPopLocalFrame = 20;
constexpr std::size_t kJniNewGlobalRef = 21;
constexpr std::size_t kJniDeleteGlobalRef = 22;
constexpr std::size_t kJniDeleteLocalRef = 23;
constexpr std::size_t kJniIsSameObject = 24;
constexpr std::size_t kJniNewLocalRef = 25;
constexpr std::size_t kJniEnsureLocalCapacity = 26;
constexpr std::size_t kJniFindClass = 6;
constexpr std::size_t kJniRegisterNatives = 215;
constexpr std::size_t kJniGetJavaVm = 219;
constexpr std::size_t kJniExceptionCheck = 228;
constexpr std::size_t kJniGetObjectRefType = 232;

// JNI invocation interface: reserved slots 0-2, DestroyJavaVM=3,
// AttachCurrentThread=4, DetachCurrentThread=5, GetEnv=6.
constexpr std::size_t kVmGetEnv = 6;

struct FunctionSpec final {
  std::size_t index;
  const char* symbol;
};

constexpr FunctionSpec kNativeFunctions[] = {
    {kJniGetVersion, "__mocktail_jni_GetVersion"},
    {kJniGetSuperclass, "__mocktail_jni_GetSuperclass"},
    {kJniIsAssignableFrom, "__mocktail_jni_IsAssignableFrom"},
    {kJniThrow, "__mocktail_jni_Throw"},
    {kJniExceptionOccurred, "__mocktail_jni_ExceptionOccurred"},
    {kJniExceptionDescribe, "__mocktail_jni_ExceptionDescribe"},
    {kJniExceptionClear, "__mocktail_jni_ExceptionClear"},
    {kJniPushLocalFrame, "__mocktail_jni_PushLocalFrame"},
    {kJniPopLocalFrame, "__mocktail_jni_PopLocalFrame"},
    {kJniNewGlobalRef, "__mocktail_jni_NewGlobalRef"},
    {kJniDeleteGlobalRef, "__mocktail_jni_DeleteGlobalRef"},
    {kJniDeleteLocalRef, "__mocktail_jni_DeleteLocalRef"},
    {kJniIsSameObject, "__mocktail_jni_IsSameObject"},
    {kJniNewLocalRef, "__mocktail_jni_NewLocalRef"},
    {kJniEnsureLocalCapacity, "__mocktail_jni_EnsureLocalCapacity"},
    {kJniFindClass, "__mocktail_jni_FindClass"},
    {kJniRegisterNatives, "__mocktail_jni_RegisterNatives"},
    {kJniGetJavaVm, "__mocktail_jni_GetJavaVM"},
    {kJniExceptionCheck, "__mocktail_jni_ExceptionCheck"},
    {kJniGetObjectRefType, "__mocktail_jni_GetObjectRefType"},
};
constexpr FunctionSpec kInvocationFunctions[] = {
    {kVmGetEnv, "__mocktail_jvm_GetEnv"},
};

bool RoundPageSize(std::size_t size, std::uint64_t* rounded) noexcept {
  if (size == 0 ||
      size > std::numeric_limits<std::uint64_t>::max() - kPageMask) {
    return false;
  }
  *rounded = (static_cast<std::uint64_t>(size) + kPageMask) & ~kPageMask;
  return *rounded != 0;
}

std::uint64_t JniErrorValue(std::int32_t error) noexcept {
  return static_cast<std::uint64_t>(static_cast<std::int64_t>(error));
}

}  // namespace

A64GuestJniBridge::A64GuestJniBridge(
    A64GuestMemory& memory, A64GuestHostCalls& host_calls,
    std::vector<std::string> available_classes)
    : memory_(memory), host_calls_(host_calls) {
  for (auto& name : available_classes) {
    if (!name.empty()) available_classes_.insert(std::move(name));
  }
}

A64GuestJniBridge::~A64GuestJniBridge() noexcept {
  ClearMappings();
}

bool A64GuestJniBridge::Register(std::string* error) {
  auto fail = [&](const std::string& message) {
    if (error != nullptr) *error = message;
    return false;
  };
  if (registered_) return fail("guest JNI bridge handlers were already registered");

  auto register_one = [&](const char* name,
                          A64GuestHostCalls::Handler handler) {
    return host_calls_.Register(name, "libmocktail-jni.so", "",
                                std::move(handler), error);
  };

  if (!register_one("__mocktail_jni_GetVersion", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, 0, {}};
        }
        return A64HostCallResult{
            true, static_cast<std::uint64_t>(kJniVersion16), {}};
      })) return false;

  if (!register_one("__mocktail_jni_FindClass", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, 0, {}};
        }
        std::string name;
        std::string diagnostic;
        if (!ReadGuestString(arguments[1], kMaximumJniStringBytes,
                             &name, &diagnostic)) {
          SetPendingException(true);
          return A64HostCallResult{true, 0, {}};
        }
        const auto handle = FindOrCreateClassHandle(name);
        SetPendingException(handle == 0);
        return A64HostCallResult{true, handle, {}};
      })) return false;

  if (!register_one("__mocktail_jni_RegisterNatives", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, JniErrorValue(kJniError), {}};
        }
        const auto class_handle = arguments[1];
        const auto methods_address = arguments[2];
        const auto count = arguments[3];
        if (count > kMaximumNativeMethods ||
            (count != 0 && methods_address == 0)) {
          SetPendingException(true);
          return A64HostCallResult{true, JniErrorValue(kJniError), {}};
        }

        std::string class_name;
        {
          std::lock_guard<std::mutex> lock(mutex_);
          const auto class_it = class_names_by_handle_.find(class_handle);
          if (class_it == class_names_by_handle_.end()) {
            pending_exception_ = true;
            return A64HostCallResult{true, JniErrorValue(kJniError), {}};
          }
          class_name = class_it->second;
        }

        std::vector<A64GuestJniNativeRegistration> pending;
        try {
          pending.reserve(static_cast<std::size_t>(count));
        } catch (const std::bad_alloc&) {
          SetPendingException(true);
          return A64HostCallResult{true, JniErrorValue(kJniError), {}};
        }

        for (std::uint64_t index = 0; index < count; ++index) {
          if (index > (std::numeric_limits<std::uint64_t>::max() -
                       methods_address) / kJniNativeMethodSize) {
            SetPendingException(true);
            return A64HostCallResult{true, JniErrorValue(kJniError), {}};
          }
          NativeMethod raw{};
          const auto entry_address =
              methods_address + index * kJniNativeMethodSize;
          if (!memory_.Read(entry_address, &raw, sizeof(raw)) ||
              raw.name_pointer == 0 || raw.signature_pointer == 0 ||
              raw.function_pointer == 0 ||
              !memory_.IsExecutable(raw.function_pointer, 4)) {
            SetPendingException(true);
            return A64HostCallResult{true, JniErrorValue(kJniError), {}};
          }

          A64GuestJniNativeRegistration method;
          method.class_name = class_name;
          method.guest_address = raw.function_pointer;
          std::string diagnostic;
          if (!ReadGuestString(raw.name_pointer, kMaximumJniStringBytes,
                               &method.name, &diagnostic) ||
              method.name.empty() ||
              !ReadGuestString(raw.signature_pointer, kMaximumJniStringBytes,
                               &method.signature, &diagnostic) ||
              method.signature.empty() ||
              method.signature.front() != '(' ||
              method.signature.find(')') == std::string::npos) {
            SetPendingException(true);
            return A64HostCallResult{true, JniErrorValue(kJniError), {}};
          }
          pending.push_back(std::move(method));
        }

        {
          std::lock_guard<std::mutex> lock(mutex_);
          if (pending.size() > kMaximumNativeMethods -
                                   std::min(registered_natives_.size(),
                                            kMaximumNativeMethods)) {
            pending_exception_ = true;
            return A64HostCallResult{true, JniErrorValue(kJniError), {}};
          }
          for (auto& method : pending) {
            const auto found = std::find_if(
                registered_natives_.begin(), registered_natives_.end(),
                [&](const A64GuestJniNativeRegistration& existing) {
                  return existing.class_name == method.class_name &&
                         existing.name == method.name &&
                         existing.signature == method.signature;
                });
            if (found != registered_natives_.end()) {
              found->guest_address = method.guest_address;
            } else {
              registered_natives_.push_back(std::move(method));
            }
          }
          pending_exception_ = false;
        }
        return A64HostCallResult{true, 0, {}};
      })) return false;

  if (!register_one("__mocktail_jni_GetJavaVM", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_ ||
            arguments[1] == 0 ||
            !memory_.Write(arguments[1], &java_vm_address_,
                           sizeof(java_vm_address_))) {
          SetPendingException(true);
          return A64HostCallResult{true, JniErrorValue(kJniError), {}};
        }
        return A64HostCallResult{true, 0, {}};
      })) return false;

  if (!register_one("__mocktail_jni_ExceptionCheck", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, 1, {}};
        }
        return A64HostCallResult{
            true, pending_exception() ? 1U : 0U, {}};
      })) return false;

  if (!register_one("__mocktail_jni_ExceptionClear", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
        } else {
          SetPendingException(false);
        }
        return A64HostCallResult{true, 0, {}};
      })) return false;

  if (!register_one("__mocktail_jni_ExceptionOccurred", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, 0, {}};
        }
        return A64HostCallResult{
            true, pending_exception() ? 1U : 0U, {}};
      })) return false;

  if (!register_one("__mocktail_jni_ExceptionDescribe", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
        }
        return A64HostCallResult{true, 0, {}};
      })) return false;

  if (!register_one("__mocktail_jni_Throw", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_ ||
            arguments[1] == 0) {
          SetPendingException(true);
          return A64HostCallResult{true, JniErrorValue(kJniError), {}};
        }
        SetPendingException(true);
        return A64HostCallResult{true, 0, {}};
      })) return false;

  if (!register_one("__mocktail_jni_GetSuperclass", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, 0, {}};
        }
        std::string name;
        {
          std::lock_guard<std::mutex> lock(mutex_);
          const auto found = class_names_by_handle_.find(arguments[1]);
          if (found == class_names_by_handle_.end()) {
            pending_exception_ = true;
            return A64HostCallResult{true, 0, {}};
          }
          name = found->second;
        }
        if (name == "java/lang/Object") return A64HostCallResult{true, 0, {}};
        return A64HostCallResult{
            true, FindOrCreateClassHandle("java/lang/Object"), {}};
      })) return false;

  if (!register_one("__mocktail_jni_IsAssignableFrom", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, 0, {}};
        }
        const auto left = arguments[1];
        const auto right = arguments[2];
        std::lock_guard<std::mutex> lock(mutex_);
        const auto left_class = class_names_by_handle_.find(left);
        const auto right_class = class_names_by_handle_.find(right);
        if (left_class == class_names_by_handle_.end() ||
            right_class == class_names_by_handle_.end()) {
          pending_exception_ = true;
          return A64HostCallResult{true, 0, {}};
        }
        const bool assignable =
            left == right || left_class->second == "java/lang/Object";
        return A64HostCallResult{true, assignable ? 1U : 0U, {}};
      })) return false;

  if (!register_one("__mocktail_jni_PushLocalFrame", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, JniErrorValue(kJniError), {}};
        }
        const auto capacity = static_cast<std::int64_t>(arguments[1]);
        return A64HostCallResult{
            true, capacity >= 0 && capacity <= 4096
                      ? 0U : JniErrorValue(kJniError), {}};
      })) return false;

  if (!register_one("__mocktail_jni_PopLocalFrame", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, 0, {}};
        }
        return A64HostCallResult{true, arguments[1], {}};
      })) return false;

  if (!register_one("__mocktail_jni_NewGlobalRef", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, 0, {}};
        }
        return A64HostCallResult{true, arguments[1], {}};
      })) return false;

  if (!register_one("__mocktail_jni_DeleteGlobalRef", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) SetPendingException(true);
        return A64HostCallResult{true, 0, {}};
      })) return false;

  if (!register_one("__mocktail_jni_DeleteLocalRef", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) SetPendingException(true);
        return A64HostCallResult{true, 0, {}};
      })) return false;

  if (!register_one("__mocktail_jni_IsSameObject", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, 0, {}};
        }
        return A64HostCallResult{
            true, arguments[1] == arguments[2] ? 1U : 0U, {}};
      })) return false;

  if (!register_one("__mocktail_jni_NewLocalRef", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, 0, {}};
        }
        return A64HostCallResult{true, arguments[1], {}};
      })) return false;

  if (!register_one("__mocktail_jni_EnsureLocalCapacity", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, JniErrorValue(kJniError), {}};
        }
        const auto capacity = static_cast<std::int64_t>(arguments[1]);
        return A64HostCallResult{
            true, capacity >= 0 && capacity <= 4096
                      ? 0U : JniErrorValue(kJniError), {}};
      })) return false;

  if (!register_one("__mocktail_jni_GetObjectRefType", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != jni_environment_address_) {
          SetPendingException(true);
          return A64HostCallResult{true, 0, {}};
        }
        std::lock_guard<std::mutex> lock(mutex_);
        const bool valid = class_names_by_handle_.find(arguments[1]) !=
                           class_names_by_handle_.end();
        // JNIInvalidRefType=0, JNILocalRefType=1.
        return A64HostCallResult{true, valid ? 1U : 0U, {}};
      })) return false;

  if (!register_one("__mocktail_jvm_GetEnv", [this](
          const A64GuestHostCalls::Arguments& arguments) {
        if (arguments[0] != java_vm_address_ || arguments[1] == 0) {
          return A64HostCallResult{true, JniErrorValue(kJniError), {}};
        }
        const auto requested = static_cast<std::int32_t>(arguments[2]);
        if (requested != 0x00010002 && requested != 0x00010004 &&
            requested != kJniVersion16) {
          return A64HostCallResult{
              true, JniErrorValue(kJniVersionError), {}};
        }
        if (!memory_.Write(arguments[1], &jni_environment_address_,
                           sizeof(jni_environment_address_))) {
          return A64HostCallResult{true, JniErrorValue(kJniError), {}};
        }
        return A64HostCallResult{true, 0, {}};
      })) return false;

  registered_ = true;
  if (error != nullptr) error->clear();
  return true;
}

bool A64GuestJniBridge::Initialize(std::string* error) {
  auto fail = [&](const std::string& message) {
    ClearMappings();
    if (error != nullptr) *error = message;
    return false;
  };
  if (!registered_) return fail("guest JNI handlers must be registered first");
  if (initialized_) return fail("guest JNI bridge was already initialized");

  std::vector<std::uint64_t> native_table(kNativeTableEntries, 0);
  std::vector<std::uint64_t> invocation_table(kInvocationTableEntries, 0);
  for (const auto& spec : kNativeFunctions) {
    std::uint64_t address = 0;
    std::string diagnostic;
    if (!ResolveStub(spec.symbol, &address, &diagnostic)) {
      return fail("failed to resolve JNI table function " +
                  std::string(spec.symbol) + ": " + diagnostic);
    }
    native_table[spec.index] = address;
  }
  for (const auto& spec : kInvocationFunctions) {
    std::uint64_t address = 0;
    std::string diagnostic;
    if (!ResolveStub(spec.symbol, &address, &diagnostic)) {
      return fail("failed to resolve JavaVM table function " +
                  std::string(spec.symbol) + ": " + diagnostic);
    }
    invocation_table[spec.index] = address;
  }

  if (!MapReadOnly(native_table.data(),
                   native_table.size() * sizeof(std::uint64_t),
                   &native_function_table_address_, error)) {
    ClearMappings();
    return false;
  }
  if (!MapReadOnly(invocation_table.data(),
                   invocation_table.size() * sizeof(std::uint64_t),
                   &invocation_function_table_address_, error)) {
    ClearMappings();
    return false;
  }
  if (!MapReadOnly(&native_function_table_address_,
                   sizeof(native_function_table_address_),
                   &jni_environment_address_, error)) {
    ClearMappings();
    return false;
  }
  if (!MapReadOnly(&invocation_function_table_address_,
                   sizeof(invocation_function_table_address_),
                   &java_vm_address_, error)) {
    ClearMappings();
    return false;
  }

  initialized_ = true;
  if (error != nullptr) error->clear();
  return true;
}

bool A64GuestJniBridge::MapReadOnly(const void* bytes, std::size_t size,
                                    std::uint64_t* address,
                                    std::string* error) {
  auto fail = [&](const std::string& message) {
    if (error != nullptr) *error = message;
    return false;
  };
  if (bytes == nullptr || size == 0 || address == nullptr) {
    return fail("invalid guest JNI mapping arguments");
  }
  std::uint64_t rounded = 0;
  if (!RoundPageSize(size, &rounded)) {
    return fail("guest JNI mapping size overflows");
  }
  std::uint64_t guest_address = 0;
  std::string diagnostic;
  if (!memory_.MapAnywhere(size, A64GuestMemory::kRead,
                           &guest_address, &diagnostic)) {
    return fail("cannot allocate read-only guest JNI memory: " + diagnostic);
  }
  if (!memory_.Initialize(guest_address, bytes, size)) {
    static_cast<void>(memory_.Unmap(guest_address, rounded));
    return fail("cannot initialize read-only guest JNI memory");
  }
  try {
    mappings_.push_back(Mapping{guest_address, rounded});
  } catch (const std::bad_alloc&) {
    static_cast<void>(memory_.Unmap(guest_address, rounded));
    return fail("not enough host memory to track guest JNI mappings");
  }
  *address = guest_address;
  if (error != nullptr) error->clear();
  return true;
}

bool A64GuestJniBridge::ResolveStub(const char* name,
                                    std::uint64_t* address,
                                    std::string* error) const {
  if (name == nullptr || address == nullptr) {
    if (error != nullptr) *error = "invalid guest JNI stub lookup";
    return false;
  }
  const auto result = host_calls_.ResolveSymbol(name);
  if (!result) {
    if (error != nullptr) *error = "registered SVC thunk is unavailable";
    return false;
  }
  *address = *result;
  if (error != nullptr) error->clear();
  return true;
}

bool A64GuestJniBridge::ReadGuestString(std::uint64_t address,
                                        std::size_t maximum,
                                        std::string* value,
                                        std::string* error) const {
  auto fail = [&](const char* message) {
    if (error != nullptr) *error = message;
    return false;
  };
  if (value == nullptr || maximum == 0) {
    return fail("invalid JNI string output or limit");
  }
  value->clear();
  std::array<char, A64GuestMemory::kPageSize> buffer{};
  std::size_t copied = 0;
  while (copied < maximum) {
    if (address > std::numeric_limits<std::uint64_t>::max() - copied) {
      return fail("JNI string address overflows");
    }
    const auto current = address + copied;
    const auto page_remaining = static_cast<std::size_t>(
        A64GuestMemory::kPageSize -
        (current & (A64GuestMemory::kPageSize - 1U)));
    const auto amount = std::min({maximum - copied, page_remaining,
                                  buffer.size()});
    if (!memory_.Read(current, buffer.data(), amount)) {
      return fail("JNI string points outside readable guest memory");
    }
    const auto terminator =
        std::find(buffer.begin(), buffer.begin() + amount, '\0');
    const auto count = static_cast<std::size_t>(terminator - buffer.begin());
    try {
      value->append(buffer.data(), count);
    } catch (const std::bad_alloc&) {
      return fail("not enough host memory for JNI string");
    }
    if (terminator != buffer.begin() + amount) {
      if (error != nullptr) error->clear();
      return true;
    }
    copied += amount;
  }
  return fail("JNI string exceeds the configured length limit");
}

std::uint64_t A64GuestJniBridge::FindOrCreateClassHandle(
    const std::string& class_name) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (available_classes_.find(class_name) == available_classes_.end()) {
    return 0;
  }
  const auto existing = class_handles_by_name_.find(class_name);
  if (existing != class_handles_by_name_.end()) return existing->second;
  if (next_class_handle_ > std::numeric_limits<std::uint64_t>::max() - 16U) {
    return 0;
  }
  const auto handle = next_class_handle_;
  next_class_handle_ += 16U;
  try {
    class_handles_by_name_.emplace(class_name, handle);
    class_names_by_handle_.emplace(handle, class_name);
  } catch (const std::bad_alloc&) {
    class_handles_by_name_.erase(class_name);
    class_names_by_handle_.erase(handle);
    return 0;
  }
  return handle;
}

std::uint64_t A64GuestJniBridge::FindClassHandle(
    const std::string& class_name) const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto found = class_handles_by_name_.find(class_name);
  return found == class_handles_by_name_.end() ? 0 : found->second;
}

void A64GuestJniBridge::SetPendingException(bool pending) noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  pending_exception_ = pending;
}

bool A64GuestJniBridge::pending_exception() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return pending_exception_;
}

std::vector<A64GuestJniNativeRegistration>
A64GuestJniBridge::registered_natives() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return registered_natives_;
}

std::size_t A64GuestJniBridge::registered_native_count() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return registered_natives_.size();
}

void A64GuestJniBridge::ClearMappings() noexcept {
  for (auto it = mappings_.rbegin(); it != mappings_.rend(); ++it) {
    static_cast<void>(memory_.Unmap(it->address, it->size));
  }
  mappings_.clear();
  native_function_table_address_ = 0;
  invocation_function_table_address_ = 0;
  jni_environment_address_ = 0;
  java_vm_address_ = 0;
  initialized_ = false;
}

}  // namespace mocktail::translation
