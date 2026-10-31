// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_runtime.h"

#include <elf.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr std::uint64_t kMaximumInputBytes = 512ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kBytesPerMiB = 1024ULL * 1024ULL;

std::string Basename(const std::string& path) {
  const auto separator = path.find_last_of('/');
  return separator == std::string::npos ? path : path.substr(separator + 1);
}

bool ParseUnsigned(const std::string& text, std::uint64_t* value) {
  if (text.empty() || text.front() == '-') return false;
  errno = 0;
  char* end = nullptr;
  const auto parsed = std::strtoull(text.c_str(), &end, 0);
  if (errno != 0 || end == text.c_str() || *end != '\0') return false;
  *value = static_cast<std::uint64_t>(parsed);
  return true;
}

bool ReadFile(const std::string& path, std::vector<std::uint8_t>* bytes,
              std::string* error) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    *error = "cannot open input library '" + path + "'";
    return false;
  }
  const auto end = static_cast<std::streamoff>(input.tellg());
  if (end <= 0) {
    *error = "input library is empty or unreadable: '" + path + "'";
    return false;
  }
  const auto size = static_cast<std::uint64_t>(end);
  if (size > kMaximumInputBytes) {
    *error = "input library exceeds the 512 MiB per-file safety limit: '" +
             path + "'";
    return false;
  }
  bytes->resize(static_cast<std::size_t>(size));
  input.seekg(0, std::ios::beg);
  input.read(reinterpret_cast<char*>(bytes->data()),
             static_cast<std::streamsize>(bytes->size()));
  if (!input || static_cast<std::size_t>(input.gcount()) != bytes->size()) {
    *error = "failed to read the complete input library: '" + path + "'";
    return false;
  }
  return true;
}

void PrintUsage(const char* program) {
  std::cout
      << "Mocktail experimental AArch64 guest probe\n\n"
      << "Usage: " << program
      << " --root LIBRARY.so [options] LIBRARY.so [LIBRARY.so ...]\n\n"
      << "Load an AArch64 ELF shared-object dependency set into the guest "
         "runtime on an x86-64 host. This is a native-library probe, not a "
         "complete Android application launcher.\n\n"
      << "Options:\n"
      << "  --root NAME             Root library basename (for example "
         "libroblox.so)\n"
      << "  --asset-root PATH       Extracted Android assets directory\n"
      << "  --list-exports          Print exports from every loaded module\n"
      << "  --external-dependency SONAME\n"
      << "                          Allow an absent dependency name; does not provide its symbols\n"
      << "  --call SYMBOL           Explicitly execute an exported guest symbol\n"
      << "  --jni-onload             Call JNI_OnLoad with the guest JavaVM table\n"
      << "  --call-native CLASS NAME SIGNATURE\n"
      << "                           Run JNI_OnLoad, then invoke a registered static native\n"
      << "  --java-class NAME        Add a class name available to FindClass (repeatable)\n"
      << "  --java-classes-file PATH Read JNI slash-form class names, one per line\n"
      << "  --argN VALUE            Integer/raw argument N; --call supports N=0..7,\n"
      << "                           --call-native supports N=0..261 (contiguous)\n"
      << "  --budget COUNT          Guest instruction budget for --call/--jni-onload\n"
      << "  --memory-mib COUNT      Guest memory limit (16 through 16384 MiB)\n"
      << "  --run-initializers      Execute module initializers before the requested entrypoint\n"
      << "  --help                  Show this help\n\n"
      << "Numbers accept decimal or 0x-prefixed hexadecimal notation. Guest "
         "code is not executed unless --call or --jni-onload is supplied.\n";
}

int Fail(const std::string& message) {
  std::cerr << "mocktail-a64-guest-probe: error: " << message << '\n';
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  using mocktail::translation::A64GuestModuleSource;
  using mocktail::translation::A64GuestRuntime;
  using mocktail::translation::A64GuestRuntimeOptions;

  std::string root_name;
  std::string asset_root;
  std::string call_symbol;
  std::string native_class;
  std::string native_name;
  std::string native_signature;
  std::vector<std::string> external_dependencies;
  std::vector<std::string> java_classes;
  std::vector<std::string> java_class_list_files;
  bool list_exports = false;
  bool run_initializers = false;
  bool jni_onload = false;
  bool has_call_arguments = false;
  constexpr std::size_t kMaximumJniArguments = 262;
  std::vector<bool> argument_was_set(kMaximumJniArguments, false);
  std::vector<std::uint64_t> supplied_arguments(kMaximumJniArguments, 0);
  std::uint64_t instruction_budget = 0;
  std::uint64_t memory_mib = 1024;
  A64GuestRuntime::Arguments arguments{};
  std::vector<std::string> paths;

  for (int index = 1; index < argc; ++index) {
    const std::string option = argv[index];
    auto take_value = [&](const char* label, std::string* value) {
      if (index + 1 >= argc) {
        std::cerr << "Missing value after " << label << '\n';
        return false;
      }
      *value = argv[++index];
      return true;
    };

    if (option == "--help" || option == "-h") {
      PrintUsage(argv[0]);
      return 0;
    }
    if (option == "--") {
      while (++index < argc) paths.emplace_back(argv[index]);
      break;
    }
    if (option == "--root") {
      if (!take_value("--root", &root_name)) return 2;
      continue;
    }
    if (option == "--asset-root") {
      if (!take_value("--asset-root", &asset_root)) return 2;
      continue;
    }
    if (option == "--call") {
      if (!take_value("--call", &call_symbol)) return 2;
      continue;
    }
    if (option == "--jni-onload") {
      jni_onload = true;
      continue;
    }
    if (option == "--call-native") {
      if (!take_value("--call-native CLASS", &native_class) ||
          !take_value("--call-native NAME", &native_name) ||
          !take_value("--call-native SIGNATURE", &native_signature)) {
        return 2;
      }
      continue;
    }
    if (option == "--java-class") {
      std::string class_name;
      if (!take_value("--java-class", &class_name)) return 2;
      if (class_name.empty() || class_name.find('.') != std::string::npos) {
        return Fail("--java-class requires a non-empty JNI slash-form name such as com/example/Native");
      }
      java_classes.push_back(std::move(class_name));
      continue;
    }
    if (option == "--java-classes-file") {
      std::string list_path;
      if (!take_value("--java-classes-file", &list_path)) return 2;
      java_class_list_files.push_back(std::move(list_path));
      continue;
    }
    if (option == "--external-dependency") {
      std::string soname;
      if (!take_value("--external-dependency", &soname)) return 2;
      if (soname.size() < 4 || Basename(soname) != soname ||
          soname.compare(soname.size() - 3, 3, ".so") != 0) {
        return Fail("--external-dependency must be a library SONAME such as libm.so");
      }
      external_dependencies.push_back(std::move(soname));
      continue;
    }
    if (option == "--budget" || option == "--memory-mib") {
      std::string value_text;
      if (!take_value(option.c_str(), &value_text)) return 2;
      std::uint64_t value = 0;
      if (!ParseUnsigned(value_text, &value)) {
        return Fail("invalid unsigned integer for " + option + ": " +
                    value_text);
      }
      if (option == "--budget") {
        if (value == 0) return Fail("--budget must be greater than zero");
        instruction_budget = value;
      } else {
        if (value < 16 || value > 16384) {
          return Fail("--memory-mib must be between 16 and 16384");
        }
        memory_mib = value;
      }
      continue;
    }
    if (option.rfind("--arg", 0) == 0 && option.size() > 5) {
      const std::string index_text = option.substr(5);
      std::size_t argument_index = 0;
      bool valid_index = true;
      for (const char digit : index_text) {
        if (digit < '0' || digit > '9') {
          valid_index = false;
          break;
        }
        const auto digit_value = static_cast<std::size_t>(digit - '0');
        if (argument_index > (kMaximumJniArguments - 1U - digit_value) / 10U) {
          valid_index = false;
          break;
        }
        argument_index = argument_index * 10U + digit_value;
      }
      if (!valid_index || argument_index >= kMaximumJniArguments) {
        return Fail("--arg index must be between 0 and 261");
      }
      std::string value_text;
      if (!take_value(option.c_str(), &value_text)) return 2;
      std::uint64_t value = 0;
      if (!ParseUnsigned(value_text, &value)) {
        return Fail("invalid unsigned integer for " + option + ": " +
                    value_text);
      }
      supplied_arguments[argument_index] = value;
      argument_was_set[argument_index] = true;
      if (argument_index < arguments.size()) {
        arguments[argument_index] = value;
      }
      has_call_arguments = true;
      continue;
    }
    if (option == "--list-exports") {
      list_exports = true;
      continue;
    }
    if (option == "--run-initializers") {
      run_initializers = true;
      continue;
    }
    if (!option.empty() && option.front() == '-') {
      return Fail("unknown option: " + option);
    }
    paths.push_back(option);
  }

  if (root_name.empty()) {
    PrintUsage(argv[0]);
    return Fail("--root is required");
  }
  root_name = Basename(root_name);
  if (root_name.empty()) return Fail("--root must name a library file");
  const bool call_native = !native_class.empty() ||
                            !native_name.empty() ||
                            !native_signature.empty();
  if (call_native &&
      (native_class.empty() || native_name.empty() || native_signature.empty())) {
    return Fail("--call-native requires CLASS, NAME, and SIGNATURE");
  }
  if (call_native && (native_class.find('.') != std::string::npos ||
                      native_class.front() == '/' ||
                      native_class.back() == '/')) {
    return Fail("--call-native CLASS must use JNI slash-form, e.g. com/example/Native");
  }
  if (call_native && !call_symbol.empty()) {
    return Fail("--call-native cannot be combined with --call");
  }
  if (jni_onload && (!call_symbol.empty() || call_native)) {
    return Fail("--jni-onload cannot be combined with --call or --call-native");
  }
  if (!java_classes.empty() && !jni_onload && !call_native) {
    return Fail("--java-class is only valid with --jni-onload or --call-native");
  }
  if (has_call_arguments && call_symbol.empty() && !call_native) {
    return Fail("--argN requires --call or --call-native");
  }
  if (jni_onload && has_call_arguments) {
    return Fail("--argN cannot be combined with --jni-onload");
  }
  if (!call_native) {
    for (std::size_t index = arguments.size();
         index < argument_was_set.size(); ++index) {
      if (argument_was_set[index]) {
        return Fail("--call supports only --arg0 through --arg7");
      }
    }
  } else {
    bool gap_seen = false;
    for (const bool was_set : argument_was_set) {
      if (!was_set) {
        gap_seen = true;
      } else if (gap_seen) {
        return Fail("--call-native arguments must be contiguous starting with --arg0");
      }
    }
  }
  if (!java_class_list_files.empty() && !jni_onload && !call_native) {
    return Fail("--java-classes-file requires --jni-onload or --call-native");
  }

  // APK/APKS wrappers pass class names gathered from DEX type tables as a
  // newline-delimited file. Avoid expanding thousands of class names into
  // argv and hitting the host's ARG_MAX limit.
  constexpr std::size_t kMaximumJavaClassListBytes = 64U * 1024U * 1024U;
  constexpr std::size_t kMaximumJavaClasses = 250000;
  std::size_t class_list_bytes = 0;
  for (const auto& list_path : java_class_list_files) {
    std::ifstream list_file(list_path, std::ios::binary);
    if (!list_file) return Fail("cannot open Java class list: " + list_path);
    std::string line;
    while (std::getline(list_file, line)) {
      if (line.size() >= kMaximumJavaClassListBytes ||
          class_list_bytes > kMaximumJavaClassListBytes - (line.size() + 1U)) {
        return Fail("Java class list exceeds the 64 MiB safety limit");
      }
      class_list_bytes += line.size() + 1U;
      if (!line.empty() && line.back() == '\r') line.pop_back();
      if (line.empty()) continue;
      if (line.size() > 4096 || line.front() == '/' || line.back() == '/' ||
          line.find('.') != std::string::npos ||
          line.find(';') != std::string::npos ||
          line.find('[') != std::string::npos ||
          line.find(']') != std::string::npos ||
          line.find('\0') != std::string::npos ||
          line.find("//") != std::string::npos) {
        return Fail("Java class list contains an invalid JNI slash-form name");
      }
      if (java_classes.size() >= kMaximumJavaClasses) {
        return Fail("Java class list exceeds the 250000 class safety limit");
      }
      java_classes.push_back(line);
    }
    if (list_file.bad()) {
      return Fail("failed while reading Java class list: " + list_path);
    }
  }

  if (run_initializers && call_symbol.empty() && !jni_onload && !call_native) {
    return Fail("--run-initializers requires --call, --jni-onload, or --call-native");
  }
  if (paths.empty()) return Fail("provide at least one ELF library path");

  std::vector<A64GuestModuleSource> sources;
  sources.reserve(paths.size());
  bool root_found = false;
  for (const auto& path : paths) {
    const auto name = Basename(path);
    if (name.empty()) return Fail("input path has no filename: '" + path + "'");
    for (const auto& existing : sources) {
      if (existing.name == name) {
        return Fail("two input files share the basename '" + name +
                    "'; choose an unambiguous dependency set");
      }
    }
    std::vector<std::uint8_t> bytes;
    std::string error;
    if (!ReadFile(path, &bytes, &error)) return Fail(error);
    if (bytes.size() < EI_NIDENT ||
        bytes[EI_MAG0] != ELFMAG0 || bytes[EI_MAG1] != ELFMAG1 ||
        bytes[EI_MAG2] != ELFMAG2 || bytes[EI_MAG3] != ELFMAG3) {
      return Fail("input is not an ELF file: '" + path + "'");
    }
    if (bytes[EI_CLASS] != ELFCLASS64 || bytes[EI_DATA] != ELFDATA2LSB) {
      return Fail("input must be a little-endian ELF64 AArch64 image: '" +
                  path + "'");
    }
    if (bytes.size() < sizeof(Elf64_Ehdr)) {
      return Fail("truncated ELF64 header: '" + path + "'");
    }
    Elf64_Ehdr header{};
    std::memcpy(&header, bytes.data(), sizeof(header));
    if (header.e_machine != EM_AARCH64) {
      return Fail("ELF machine is not AArch64 (EM_AARCH64): '" + path + "'");
    }
    if (name == root_name) root_found = true;
    sources.push_back({name, std::move(bytes)});
  }
  if (!root_found) {
    return Fail("root library '" + root_name +
                "' was not among the supplied input files");
  }

  A64GuestRuntimeOptions options;
  options.android_asset_root = std::move(asset_root);
  options.module_load.external_dependencies = std::move(external_dependencies);
  if (call_native) java_classes.push_back(native_class);
  for (auto& class_name : java_classes) {
    options.jni_available_classes.push_back(std::move(class_name));
  }
  options.max_guest_memory_bytes =
      static_cast<std::size_t>(memory_mib * kBytesPerMiB);
  if (instruction_budget != 0) options.instruction_budget = instruction_budget;
  A64GuestRuntime runtime(std::move(options));
  std::string error;
  if (!runtime.Load(sources, root_name, &error)) {
    return Fail("guest module load failed: " + error);
  }

  const auto* modules = runtime.modules();
  if (modules == nullptr) {
    return Fail("runtime reported success without a loaded module set");
  }
  std::cout << "Loaded " << modules->modules.size()
            << " AArch64 module(s) with Dynarmic-backed guest runtime.\n";
  for (std::size_t index = 0; index < modules->modules.size(); ++index) {
    const auto& module = modules->modules[index];
    std::cout << (index == modules->root_index ? "* " : "  ")
              << module.source_name;
    if (!module.image.soname.empty()) {
      std::cout << " (SONAME " << module.image.soname << ')';
    }
    std::cout << ", " << module.image.exported_symbols.size()
              << " exported symbol(s)\n";
    if (!module.image.dependencies.empty()) {
      std::cout << "    DT_NEEDED:";
      for (const auto& dependency : module.image.dependencies) {
        std::cout << ' ' << dependency;
      }
      std::cout << '\n';
    }
    if (list_exports) {
      for (const auto& symbol : module.image.exported_symbols) {
        std::cout << "    " << symbol.name;
        if (!symbol.version.empty()) {
          std::cout << (symbol.version_hidden ? "@" : "@@")
                    << symbol.version;
          if (symbol.version_hidden) std::cout << " [non-default]";
        }
        if (symbol.type == STT_TLS) std::cout << " [TLS]";
        std::cout << '\n';
      }
    }
  }

  // Android's linker runs DT_INIT/DT_INIT_ARRAY before JNI_OnLoad. Keep
  // raw --call opt-in for isolated probes, but preserve constructor ordering
  // automatically for JNI-oriented entrypoints, just like the Android loader.
  const bool should_run_initializers =
      run_initializers || jni_onload || call_native;
  if (should_run_initializers && !runtime.RunInitializers(&error)) {
    return Fail("guest module initializers failed: " + error);
  }
  if (jni_onload) {
    const auto result = runtime.CallJniOnLoad(instruction_budget);
    if (!result) {
      return Fail("guest JNI_OnLoad call failed: " + result.error);
    }
    const auto version = static_cast<std::uint32_t>(result.value);
    std::cout << "JNI_OnLoad returned X0=0x" << std::hex << version
              << std::dec << " (" << version << ").\n";
    const auto natives = runtime.registered_jni_natives();
    std::cout << "Registered native methods: " << natives.size() << '\n';
    for (const auto& native : natives) {
      std::cout << "    " << native.class_name << '.' << native.name
                << native.signature << " at 0x" << std::hex
                << native.guest_address << std::dec << '\n';
    }
    if (static_cast<std::int32_t>(version) < 0 ||
        (version != 0x00010002U && version != 0x00010004U &&
         version != 0x00010006U)) {
      return Fail("JNI_OnLoad returned an unsupported version/error code");
    }
    if (runtime.jni_exception_pending()) {
      return Fail("JNI_OnLoad returned with a pending Java exception");
    }
    return 0;
  }
  if (call_native) {
    const auto on_load = runtime.CallJniOnLoad(instruction_budget);
    if (!on_load) {
      return Fail("guest JNI_OnLoad call failed: " + on_load.error);
    }
    const auto version = static_cast<std::uint32_t>(on_load.value);
    if (static_cast<std::int32_t>(version) < 0 ||
        (version != 0x00010002U && version != 0x00010004U &&
         version != 0x00010006U)) {
      return Fail("JNI_OnLoad returned an unsupported version/error code");
    }
    if (runtime.jni_exception_pending()) {
      return Fail("JNI_OnLoad returned with a pending Java exception");
    }
    std::cout << "JNI_OnLoad returned X0=0x" << std::hex << version
              << std::dec << " (" << version << ").\n";
    const auto natives = runtime.registered_jni_natives();
    std::cout << "Registered native methods: " << natives.size() << '\n';

    std::vector<std::uint64_t> java_arguments;
    for (std::size_t index = 0;
         index < argument_was_set.size() && argument_was_set[index]; ++index) {
      java_arguments.push_back(supplied_arguments[index]);
    }
    const auto result = runtime.CallRegisteredJniNative(
        native_class, native_name, native_signature, java_arguments,
        instruction_budget);
    if (!result) {
      return Fail("guest JNI native call failed: " + result.error);
    }
    std::cout << "Guest JNI native " << native_class << '.' << native_name
              << native_signature << " returned "
              << (result.value_is_floating_point ? "V0" : "X0") << "=0x"
              << std::hex << result.value << std::dec;
    if (result.value_is_floating_point) {
      std::cout << " (raw IEEE-754 bits)";
    } else {
      std::cout << " (" << result.value << ')';
    }
    std::cout << ", " << result.ticks
              << " guest instruction(s) executed.\n";
  } else if (!call_symbol.empty()) {
    const auto result =
        runtime.CallSymbol(call_symbol, arguments, instruction_budget);
    if (!result) {
      return Fail("guest symbol call '" + call_symbol + "' failed: " +
                  result.error);
    }
    std::cout << "Guest call " << call_symbol << " returned X0=0x"
              << std::hex << result.value << std::dec << " ("
              << result.value << "), " << result.ticks
              << " guest instruction(s) executed.\n";
  } else {
    std::cout << "No guest function was executed. Use --call SYMBOL to run "
                 "one explicitly.\n";
  }
  return 0;
}
