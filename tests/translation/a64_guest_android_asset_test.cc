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
#include <sys/eventfd.h>
#include <unistd.h>

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
  const int event_fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (event_fd < 0) {
    std::cerr << "[FAIL] cannot create host eventfd for looper test\n";
    return 1;
  }
  const std::uint64_t one = 1;
  if (::write(event_fd, &one, sizeof(one)) != sizeof(one)) {
    ::close(event_fd);
    std::cerr << "[FAIL] cannot signal host eventfd for looper test\n";
    return 1;
  }
  A64GuestRuntime::Arguments looper_arguments{};
  looper_arguments[0] = static_cast<std::uint64_t>(event_fd);
  const auto looper_result =
      runtime.CallSymbol("guest_android_looper_fd_smoke", looper_arguments);
  ::close(event_fd);
  if (!looper_result || looper_result.value != 42) {
    std::cerr << "[FAIL] guest ALooper fd poll failed: "
              << (looper_result ? std::to_string(looper_result.value)
                                : looper_result.error)
              << '\n';
    return 1;
  }
  const auto window_result =
      runtime.CallSymbol("guest_android_headless_window_smoke");
  if (!window_result || window_result.value != 42) {
    std::cerr << "[FAIL] headless ANativeWindow behavior was not preserved\n";
    return 1;
  }
  const auto codec_result =
      runtime.CallSymbol("guest_android_headless_codec_smoke");
  if (!codec_result || codec_result.value != 42) {
    std::cerr << "[FAIL] headless MediaCodec behavior was not preserved\n";
    return 1;
  }
  const auto audio_result =
      runtime.CallSymbol("guest_android_headless_audio_smoke");
  if (!audio_result || audio_result.value != 42) {
    std::cerr << "[FAIL] headless OpenSL engine behavior was not preserved\n";
    return 1;
  }
  const auto graphics_result =
      runtime.CallSymbol("guest_android_headless_graphics_smoke");
  if (!graphics_result || graphics_result.value != 42) {
    std::cerr << "[FAIL] headless EGL/GLES behavior was not preserved\n";
    return 1;
  }
  const auto memory_result =
      runtime.CallSymbol("guest_libc_memory_smoke");
  if (!memory_result || memory_result.value != 42) {
    std::cerr << "[FAIL] guest libc mmap/mprotect/madvise behavior failed\n";
    return 1;
  }
  const auto process_result =
      runtime.CallSymbol("guest_libc_process_smoke");
  if (!process_result || process_result.value != 42) {
    std::cerr << "[FAIL] guest process identity/prctl behavior failed\n";
    return 1;
  }
  const auto fortify_result =
      runtime.CallSymbol("guest_libc_fortify_smoke");
  if (!fortify_result || fortify_result.value != 42) {
    std::cerr << "[FAIL] fortified guest libc memory helpers failed\n";
    return 1;
  }
  std::cout << "[PASS] guest assets, ALooper, headless graphics/audio/media, "
               "libc memory/process, and fortified memory APIs exercised\n";
  return 0;
}
