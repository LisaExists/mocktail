// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_runtime.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {

bool ReadFile(const std::string& path,
              std::vector<std::uint8_t>* bytes) {
  std::ifstream input(path, std::ios::binary);
  if (!input) return false;
  std::vector<char> raw(std::istreambuf_iterator<char>(input),
                        std::istreambuf_iterator<char>());
  if (raw.empty()) return false;
  bytes->assign(raw.begin(), raw.end());
  return true;
}

std::string Basename(const std::string& path) {
  const auto separator = path.find_last_of('/');
  return separator == std::string::npos ? path : path.substr(separator + 1);
}

int Fail(const std::string& message) {
  std::cerr << "[FAIL] " << message << '\n';
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  using mocktail::translation::A64GuestModuleSource;
  using mocktail::translation::A64GuestRuntime;
  using mocktail::translation::A64GuestRuntimeOptions;

  if (argc < 3) {
    std::cerr
        << "usage: mocktail_a64_guest_runtime_test --symbol name root.so "
           "[dependency.so ...]\n"
        << "       mocktail_a64_guest_runtime_test --budget-exhaustion "
           "root.so dependency.so [...]\n"
        << "       mocktail_a64_guest_runtime_test --initializers init.so\n";
    return 2;
  }

  const std::string mode = argv[1];
  bool run_initializers = false;
  bool expect_budget_exhaustion = false;
  std::string symbol;
  int first_path = 2;

  if (mode == "--symbol") {
    if (argc < 4) return Fail("--symbol requires a symbol and a root ELF");
    symbol = argv[2];
    first_path = 3;
  } else if (mode == "--budget-exhaustion") {
    expect_budget_exhaustion = true;
    symbol = "guest_spin_forever";
    first_path = 2;
  } else if (mode == "--initializers") {
    run_initializers = true;
    symbol = "guest_check_init";
    first_path = 2;
    if (argc != 3) return Fail("--initializers accepts one root ELF fixture");
  } else {
    return Fail("unknown runtime test mode: " + mode);
  }

  std::vector<A64GuestModuleSource> sources;
  for (int index = first_path; index < argc; ++index) {
    std::vector<std::uint8_t> bytes;
    if (!ReadFile(argv[index], &bytes)) {
      return Fail("cannot read non-empty AArch64 ELF fixture: " +
                  std::string(argv[index]));
    }
    sources.push_back({Basename(argv[index]), std::move(bytes)});
  }
  if (sources.empty()) return Fail("no AArch64 ELF fixtures were supplied");

  A64GuestRuntimeOptions options;
  options.instruction_budget = 1U * 1000U * 1000U;
  A64GuestRuntime runtime(std::move(options));
  std::string error;
  if (!runtime.Load(sources, sources.front().name, &error)) {
    return Fail("runtime load failed: " + error);
  }

  if (run_initializers && !runtime.RunInitializers(&error)) {
    return Fail("runtime initializer execution failed: " + error);
  }

  A64GuestRuntime::Arguments arguments{};
  if (symbol == "guest_exported_entry") arguments[0] = 41;
  const std::uint64_t budget = expect_budget_exhaustion ? 256 : 0;
  const auto result = runtime.CallSymbol(symbol, arguments, budget);

  if (expect_budget_exhaustion) {
    if (result.success ||
        result.error.find("instruction budget exhausted") == std::string::npos) {
      return Fail("runaway guest did not stop at the instruction budget; " +
                  result.error);
    }
    std::cout << "[PASS] runtime stops a looping guest at its instruction budget "
              << "(ticks=" << result.ticks << ")\n";
    return 0;
  }

  if (!result) {
    return Fail("guest symbol call failed: " + result.error);
  }
  if (result.value != 42) {
    return Fail("guest symbol returned " + std::to_string(result.value) +
                ", expected 42");
  }

  std::cout << "[PASS] reusable AArch64 runtime loaded " << sources.size()
            << " module(s), called " << symbol << " and returned 42";
  if (run_initializers) std::cout << " after executing DT_INIT_ARRAY";
  std::cout << " (ticks=" << result.ticks << ")\n";
  return 0;
}
