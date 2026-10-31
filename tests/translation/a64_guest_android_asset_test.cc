// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_runtime.h"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {
std::string Basename(const std::string& path) {
  const auto separator = path.find_last_of('/');
  return separator == std::string::npos ? path : path.substr(separator + 1);
}
}

int main(int argc, char** argv) {
  using mocktail::translation::A64GuestModuleSource;
  using mocktail::translation::A64GuestRuntime;
  using mocktail::translation::A64GuestRuntimeOptions;

  if (argc != 3) {
    std::cerr << "usage: android_asset_test ARM64_FIXTURE ASSET_ROOT\n";
    return 2;
  }

  std::ifstream input(argv[1], std::ios::binary);
  if (!input) {
    std::cerr << "[FAIL] cannot open Android asset guest fixture\n";
    return 1;
  }
  std::vector<char> raw{std::istreambuf_iterator<char>(input),
                        std::istreambuf_iterator<char>()};
  if (raw.empty()) {
    std::cerr << "[FAIL] Android asset guest fixture is empty\n";
    return 1;
  }
  std::vector<std::uint8_t> bytes(raw.begin(), raw.end());

  A64GuestRuntimeOptions options;
  options.android_asset_root = argv[2];
  A64GuestRuntime runtime(std::move(options));
  std::string error;
  if (!runtime.Load({A64GuestModuleSource{Basename(argv[1]), std::move(bytes)}},
                    Basename(argv[1]), &error)) {
    std::cerr << "[FAIL] runtime load: " << error << '\n';
    return 1;
  }

  const auto result = runtime.CallSymbol("guest_android_asset_smoke");
  if (!result) {
    std::cerr << "[FAIL] guest asset call: " << result.error << '\n';
    return 1;
  }
  if (result.value != 42) {
    std::cerr << "[FAIL] guest asset bridge returned " << result.value
              << ", expected 42\n";
    return 1;
  }
  std::cout << "[PASS] guest AAssetManager opened an extracted APK asset and "
               "read its guest-mapped buffer\n";
  return 0;
}
