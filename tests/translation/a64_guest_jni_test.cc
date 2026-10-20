// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_runtime.h"
#include "translation/a64_guest_memory.h"
#include "translation/a64_guest_jni.h"

#include <algorithm>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace {

bool ReadFile(const std::string& path, std::vector<std::uint8_t>* bytes) {
  std::ifstream input(path, std::ios::binary);
  if (!input) return false;
  const std::vector<char> raw{std::istreambuf_iterator<char>(input),
                              std::istreambuf_iterator<char>()};
  if (raw.empty()) return false;
  bytes->assign(raw.begin(), raw.end());
  return true;
}

void Check(bool condition, const std::string& label, int* failures) {
  if (condition) {
    std::cout << "[PASS] " << label << '\n';
  } else {
    std::cerr << "[FAIL] " << label << '\n';
    ++*failures;
  }
}

}  // namespace

int main(int argc, char** argv) {
  using mocktail::translation::A64GuestJniBridge;
  using mocktail::translation::A64GuestModuleSource;
  using mocktail::translation::A64GuestRuntime;
  using mocktail::translation::A64GuestRuntimeOptions;

  if (argc != 2) {
    std::cerr << "usage: mocktail_a64_guest_jni_test ANDROID_JNI_ELF\n";
    return 2;
  }

  std::vector<std::uint8_t> bytes;
  if (!ReadFile(argv[1], &bytes)) {
    std::cerr << "[FAIL] unable to read Android JNI fixture\n";
    return 2;
  }
  const auto separator = std::string(argv[1]).find_last_of('/');
  const std::string root_name =
      separator == std::string::npos
          ? std::string(argv[1])
          : std::string(argv[1]).substr(separator + 1);
  const std::vector<A64GuestModuleSource> sources{{root_name, std::move(bytes)}};

  int failures = 0;
  A64GuestRuntimeOptions options;
  options.instruction_budget = 100000;
  options.jni_available_classes.push_back("com/mocktail/Smoke");
  A64GuestRuntime runtime(std::move(options));
  std::string error;
  if (!runtime.Load(sources, root_name, &error)) {
    std::cerr << "[FAIL] runtime load failed: " << error << '\n';
    return 1;
  }

  const auto vm = runtime.java_vm_address();
  const auto env = runtime.jni_environment_address();
  Check(vm != 0 && env != 0, "creates guest-resident JavaVM and JNIEnv objects", &failures);
  Check(runtime.memory()->IsMapped(vm, sizeof(std::uint64_t)) &&
            runtime.memory()->IsMapped(env, sizeof(std::uint64_t)),
        "JNI objects reside inside the guest address space", &failures);
  std::uint64_t write_probe = 0;
  Check(!runtime.memory()->Write(vm, &write_probe, sizeof(write_probe)) &&
            !runtime.memory()->Write(env, &write_probe, sizeof(write_probe)),
        "JNI objects are read-only to guest code", &failures);

  Check(runtime.RunInitializers(&error),
        "runs Android shared-object constructors before JNI_OnLoad", &failures);
  const auto on_load = runtime.CallJniOnLoad(100000);
  Check(on_load.success &&
            static_cast<std::uint32_t>(on_load.value) ==
                static_cast<std::uint32_t>(A64GuestJniBridge::kJniVersion16),
        "executes Android JNI_OnLoad through guest JavaVM.GetEnv and JNIEnv.GetVersion",
        &failures);

  const auto natives = runtime.registered_jni_natives();
  const auto has_native = [&](const std::string& name,
                              const std::string& signature) {
    return std::find_if(natives.begin(), natives.end(),
        [&](const auto& native) {
          return native.class_name == "com/mocktail/Smoke" &&
                 native.name == name && native.signature == signature &&
                 native.guest_address != 0;
        }) != natives.end();
  };
  Check(natives.size() == 6 && has_native("nativeSum", "(II)I") &&
            has_native("nativeSum8", "(IIIIIIII)I") &&
            has_native("nativeFloatScaled", "(F)I") &&
            has_native("nativeMixed", "(IFDII)I") &&
            has_native("nativeFloatReturn", "(F)F") &&
            has_native("nativeDoubleReturn", "(D)D"),
        "RegisterNatives records validated executable guest functions", &failures);

  const auto native_result = runtime.CallRegisteredJniNative(
      "com/mocktail/Smoke", "nativeSum", "(II)I",
      std::vector<std::uint64_t>{20, 22}, 100000);
  Check(native_result.success && native_result.value == 42,
        "calls a registered static native with JNIEnv/jclass and register arguments",
        &failures);
  Check(native_result.ticks > 0,
        "counts guest instructions in the registered native call", &failures);

  const auto stacked_native_result = runtime.CallRegisteredJniNative(
      "com/mocktail/Smoke", "nativeSum8", "(IIIIIIII)I",
      std::vector<std::uint64_t>{1, 2, 3, 4, 5, 6, 7, 8}, 100000);
  Check(stacked_native_result.success && stacked_native_result.value == 36,
        "passes JNI integer arguments beyond X2-X7 through a 16-byte-aligned guest stack",
        &failures);
  if (!stacked_native_result.success) {
    std::cerr << "[DEBUG] stacked JNI native call error: "
              << stacked_native_result.error << '\n';
  } else if (stacked_native_result.value != 36) {
    std::cerr << "[DEBUG] stacked JNI native returned "
              << stacked_native_result.value << ", expected 36\n";
  }

  const auto float_native_result = runtime.CallRegisteredJniNative(
      "com/mocktail/Smoke", "nativeFloatScaled", "(F)I",
      std::vector<std::uint64_t>{0x3FA00000ULL}, 100000);
  Check(float_native_result.success && float_native_result.value == 125,
        "passes an IEEE-754 float argument through V0", &failures);
  const auto mixed_native_result = runtime.CallRegisteredJniNative(
      "com/mocktail/Smoke", "nativeMixed", "(IFDII)I",
      std::vector<std::uint64_t>{1, 0x3FC00000ULL,
                                 0x4004000000000000ULL, 3, 4}, 100000);
  Check(mixed_native_result.success && mixed_native_result.value == 48,
        "allocates mixed integer/float/double arguments to independent AAPCS64 registers",
        &failures);

  const auto float_return_result = runtime.CallRegisteredJniNative(
      "com/mocktail/Smoke", "nativeFloatReturn", "(F)F",
      std::vector<std::uint64_t>{0x3FA00000ULL}, 100000);
  Check(float_return_result.success &&
            float_return_result.value_is_floating_point &&
            float_return_result.value == 0x3FE00000ULL,
        "captures a float return value from V0 as raw IEEE-754 bits", &failures);
  const auto double_return_result = runtime.CallRegisteredJniNative(
      "com/mocktail/Smoke", "nativeDoubleReturn", "(D)D",
      std::vector<std::uint64_t>{0x4004000000000000ULL}, 100000);
  Check(double_return_result.success &&
            double_return_result.value_is_floating_point &&
            double_return_result.value == 0x4008000000000000ULL,
        "captures a double return value from V0 as raw IEEE-754 bits", &failures);

  const auto missing_native = runtime.CallRegisteredJniNative(
      "com/mocktail/Smoke", "missingNative", "()I",
      std::vector<std::uint64_t>{}, 100000);
  Check(!missing_native.success &&
            missing_native.error.find("not registered") != std::string::npos,
        "rejects calls to methods absent from RegisterNatives", &failures);
  const auto wrong_argument_count = runtime.CallRegisteredJniNative(
      "com/mocktail/Smoke", "nativeSum", "(II)I",
      std::vector<std::uint64_t>{20}, 100000);
  Check(!wrong_argument_count.success &&
            wrong_argument_count.error.find("argument count") != std::string::npos,
        "validates Java argument count against its JNI descriptor", &failures);
  const auto invalid_signature = runtime.CallRegisteredJniNative(
      "com/mocktail/Smoke", "nativeSum", "(V)I",
      std::vector<std::uint64_t>{0}, 100000);
  Check(!invalid_signature.success &&
            invalid_signature.error.find("descriptor") != std::string::npos,
        "rejects malformed JNI method descriptors", &failures);

  // Unknown classes must fail as a JNI exception/null result, not fabricate a
  // Java class or crash the host. Use a second runtime so pending-exception
  // state from this negative path cannot affect the successful registration.
  A64GuestRuntimeOptions negative_options;
  negative_options.instruction_budget = 100000;
  A64GuestRuntime negative_runtime(std::move(negative_options));
  std::vector<std::uint8_t> negative_bytes;
  if (!ReadFile(argv[1], &negative_bytes)) {
    std::cerr << "[FAIL] unable to reread Android JNI fixture\n";
    return 2;
  }
  const std::vector<A64GuestModuleSource> negative_sources{
      {root_name, std::move(negative_bytes)}};
  if (!negative_runtime.Load(negative_sources, root_name, &error)) {
    std::cerr << "[FAIL] negative-path runtime load failed: " << error << '\n';
    return 1;
  }
  Check(negative_runtime.RunInitializers(&error),
        "runs constructors in the negative FindClass test runtime", &failures);
  const auto missing_class_on_load = negative_runtime.CallJniOnLoad(100000);
  Check(missing_class_on_load.success &&
            static_cast<std::uint32_t>(missing_class_on_load.value) ==
                static_cast<std::uint32_t>(-6) &&
            negative_runtime.registered_jni_natives().empty(),
        "unknown FindClass returns null and prevents native registration",
        &failures);

  std::cout << failures << " guest JNI test(s) failed\n";
  return failures == 0 ? 0 : 1;
}
