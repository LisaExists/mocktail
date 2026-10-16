// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_runtime.h"

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

  const auto on_load = runtime.CallJniOnLoad(100000);
  Check(on_load.success &&
            static_cast<std::uint32_t>(on_load.value) ==
                static_cast<std::uint32_t>(A64GuestJniBridge::kJniVersion16),
        "executes Android JNI_OnLoad through guest JavaVM.GetEnv and JNIEnv.GetVersion",
        &failures);

  const auto natives = runtime.registered_jni_natives();
  Check(natives.size() == 1 &&
            natives[0].class_name == "com/mocktail/Smoke" &&
            natives[0].name == "nativeSum" &&
            natives[0].signature == "(II)I" &&
            natives[0].guest_address != 0,
        "RegisterNatives records a validated executable guest function", &failures);

  if (natives.size() == 1 && natives[0].guest_address != 0) {
    A64GuestRuntime::Arguments arguments{};
    arguments[0] = 20;
    arguments[1] = 22;
    const auto native_result =
        runtime.Call(natives[0].guest_address, arguments, 100000);
    Check(native_result.success && native_result.value == 42,
          "calls a native method discovered through JNI registration on x86-64",
          &failures);
  }

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
