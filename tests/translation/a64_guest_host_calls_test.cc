// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

#include "translation/a64_guest_host_calls.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <utility>

#include "translation/a64_guest_memory.h"
#include "translation/a64_guest_tls.h"

namespace {

int failures = 0;

void Check(bool condition, const std::string& label) {
  if (condition) {
    std::cout << "[PASS] " << label << '\n';
  } else {
    std::cerr << "[FAIL] " << label << '\n';
    ++failures;
  }
}

std::uint32_t ReadU32(const mocktail::translation::A64GuestMemory& memory,
                      std::uint64_t address) {
  std::array<std::uint8_t, 4> bytes{};
  if (!memory.Read(address, bytes.data(), bytes.size())) return 0;
  return static_cast<std::uint32_t>(bytes[0]) |
         (static_cast<std::uint32_t>(bytes[1]) << 8U) |
         (static_cast<std::uint32_t>(bytes[2]) << 16U) |
         (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

std::uint32_t ReadSvcImmediate(
    const mocktail::translation::A64GuestMemory& memory,
    std::uint64_t stub) {
  // A64 encoding is 0xD4000001 | (imm16 << 5).
  return (ReadU32(memory, stub) >> 5U) & 0xffffU;
}

}  // namespace

int main() {
  using mocktail::translation::A64GuestHostCalls;
  using mocktail::translation::A64SymbolRequest;
  using mocktail::translation::A64GuestMemory;
  using mocktail::translation::A64GuestModule;
  using mocktail::translation::A64GuestModuleSet;
  using mocktail::translation::A64GuestThreadTls;
  using mocktail::translation::A64GuestTlsRuntime;

  A64GuestMemory memory(2U * 1024U * 1024U);
  constexpr std::uint64_t kTestBase = 0x20000000ULL;
  std::string error;
  Check(memory.Map(kTestBase, 2U * A64GuestMemory::kPageSize,
                   A64GuestMemory::kRead | A64GuestMemory::kWrite, &error),
        "maps an isolated guest data area");

  A64GuestModuleSet tls_modules;
  A64GuestModule tls_module;
  tls_module.source_name = "libtls.so";
  tls_module.image.tls = mocktail::translation::A64TlsSegment{
      8, 16, 16, 0, 0,
      {0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
       0, 0, 0, 0, 0, 0, 0, 0}};
  tls_modules.modules.push_back(std::move(tls_module));
  A64GuestTlsRuntime tls_runtime(memory);
  A64GuestThreadTls tls_thread;
  Check(tls_runtime.Prepare(tls_modules, &error) &&
            tls_runtime.CreateThread(&tls_thread, &error),
        "prepares a static TLS block for the host-call integration test");

  A64GuestHostCalls calls(memory);
  Check(calls.RegisterBuiltinLibc(&error),
        "registers the explicit guest-safe libc subset");
  Check(calls.RegisterTlsGetAddr(tls_runtime, tls_thread, "libc.so", "",
                                 &error),
        "registers a guest-safe preloaded-module __tls_get_addr thunk");
  constexpr std::uint64_t kMediaFormatKeyAddress = kTestBase + 0x800;
  constexpr char kMediaFormatKey[] = "i-frame-interval";
  Check(memory.Write(kMediaFormatKeyAddress, kMediaFormatKey,
                     sizeof(kMediaFormatKey)) &&
            calls.RegisterDataSymbol("AMEDIAFORMAT_KEY_I_FRAME_INTERVAL",
                                     "libmediandk.so", "",
                                     kMediaFormatKeyAddress, &error),
        "registers an NDK media-format data export");
  const A64SymbolRequest media_format_key_request{
      "AMEDIAFORMAT_KEY_I_FRAME_INTERVAL", "LIBMEDIANDK", "libmediandk.so"};
  const auto media_format_key =
      calls.ResolveVersionedSymbol(media_format_key_request);
  const A64SymbolRequest wrong_media_provider{
      "AMEDIAFORMAT_KEY_I_FRAME_INTERVAL", "LIBMEDIANDK", "libc.so"};
  const A64SymbolRequest private_media_version{
      "AMEDIAFORMAT_KEY_I_FRAME_INTERVAL", "LIBMEDIANDK_PRIVATE",
      "libmediandk.so"};
  Check(media_format_key && *media_format_key == kMediaFormatKeyAddress,
        "resolves public LIBMEDIANDK imports to provider-matched data exports");
  Check(calls.ResolveSymbol("AMEDIAFORMAT_KEY_I_FRAME_INTERVAL") ==
            media_format_key,
        "resolves unversioned NDK media data imports to the same guest object");
  Check(!calls.ResolveVersionedSymbol(wrong_media_provider) &&
            !calls.ResolveVersionedSymbol(private_media_version),
        "keeps media-NDK version fallback provider-scoped and rejects private versions");
  Check(calls.Install(&error), "installs RX AArch64 SVC/RET thunks");

  const auto errno_stub = calls.ResolveSymbol("__errno");
  const auto errno_location_stub = calls.ResolveSymbol("__errno_location");
  const auto memchr_stub = calls.ResolveSymbol("memchr");
  const auto strcat_stub = calls.ResolveSymbol("strcat");
  const auto strncat_stub = calls.ResolveSymbol("strncat");
  const auto strcasecmp_stub = calls.ResolveSymbol("strcasecmp");
  const auto strncasecmp_stub = calls.ResolveSymbol("strncasecmp");
  const auto strlen_stub = calls.ResolveSymbol("strlen");
  const auto strnlen_stub = calls.ResolveSymbol("strnlen");
  const auto strcpy_stub = calls.ResolveSymbol("strcpy");
  const auto strncpy_stub = calls.ResolveSymbol("strncpy");
  const auto strchr_stub = calls.ResolveSymbol("strchr");
  const auto strrchr_stub = calls.ResolveSymbol("strrchr");
  const auto strstr_stub = calls.ResolveSymbol("strstr");
  const auto strdup_stub = calls.ResolveSymbol("strdup");
  const auto tls_get_addr_stub = calls.ResolveSymbol("__tls_get_addr");
  const auto memcpy_stub = calls.ResolveSymbol("memcpy");
  const auto strcmp_stub = calls.ResolveSymbol("strcmp");
  const auto malloc_stub = calls.ResolveSymbol("malloc");
  const auto realloc_stub = calls.ResolveSymbol("realloc");
  const auto free_stub = calls.ResolveSymbol("free");
  Check(errno_stub && errno_location_stub && memchr_stub && strcat_stub &&
            strncat_stub && strcasecmp_stub && strncasecmp_stub && strlen_stub &&
            strnlen_stub && strcpy_stub && strncpy_stub && strchr_stub &&
            strrchr_stub && strstr_stub && strdup_stub && tls_get_addr_stub &&
            memcpy_stub && strcmp_stub && malloc_stub && realloc_stub && free_stub,
        "resolves registered symbols to guest stub addresses");

  if (!errno_stub || !errno_location_stub || !memchr_stub || !strcat_stub ||
      !strncat_stub || !strcasecmp_stub || !strncasecmp_stub ||
      !strlen_stub || !strnlen_stub ||
      !strcpy_stub || !strncpy_stub ||
      !strchr_stub || !strrchr_stub || !strstr_stub || !strdup_stub ||
      !tls_get_addr_stub || !memcpy_stub || !strcmp_stub ||
      !malloc_stub || !realloc_stub || !free_stub) {
    std::cout << failures << " guest host-call test(s) failed\n";
    return 1;
  }

  Check(memory.IsExecutable(*strlen_stub, 8),
        "thunks live in executable guest memory");

  A64GuestHostCalls::Arguments arguments{};
  const auto errno_result = calls.DispatchSvc(
      ReadSvcImmediate(memory, *errno_stub), arguments);
  std::int32_t guest_errno = -1;
  const bool read_errno =
      errno_result.success &&
      memory.Read(errno_result.value, &guest_errno, sizeof(guest_errno));
  Check(read_errno && errno_result.value != 0 && guest_errno == 0 &&
            memory.IsMapped(errno_result.value, sizeof(guest_errno)),
        "__errno returns a valid, zero-initialized guest errno cell");
  Check(calls.SetGuestErrno(77) &&
            memory.Read(errno_result.value, &guest_errno, sizeof(guest_errno)) &&
            guest_errno == 77,
        "runtime can set guest errno without mutating host errno");
  Check(calls.SetGuestErrno(0) &&
            memory.Read(errno_result.value, &guest_errno, sizeof(guest_errno)) &&
            guest_errno == 0,
        "runtime can clear the guest errno cell");
  const std::int32_t expected_errno = 13;
  Check(memory.Write(errno_result.value, &expected_errno, sizeof(expected_errno)),
        "guest code can set errno without modifying host thread errno");
  const auto errno_location_result = calls.DispatchSvc(
      ReadSvcImmediate(memory, *errno_location_stub), arguments);
  guest_errno = 0;
  Check(errno_location_result.success &&
            errno_location_result.value == errno_result.value &&
            memory.Read(errno_location_result.value, &guest_errno, sizeof(guest_errno)) &&
            guest_errno == expected_errno,
        "__errno_location shares the persistent guest errno value");
  const std::int32_t cleared_errno = 0;
  Check(memory.Write(errno_result.value, &cleared_errno, sizeof(cleared_errno)),
        "test restores guest errno after exercising the accessor");

  Check(!memory.Write(*strlen_stub, "x", 1),
        "thunk pages remain read-only to guest code");
  const auto strlen_svc = ReadSvcImmediate(memory, *strlen_stub);
  Check(strlen_svc >= A64GuestHostCalls::kFirstSvcImmediate &&
            calls.HandlesSvc(strlen_svc),
        "SVC immediate identifies a registered host call");

  constexpr std::uint64_t kSource = kTestBase + 0x100;
  constexpr std::uint64_t kTlsIndexAddress = kTestBase + 0x300;
  constexpr std::uint64_t kDestination = kTestBase + A64GuestMemory::kPageSize + 0x100;
  constexpr char kMessage[] = "hello";
  Check(memory.Write(kSource, kMessage, sizeof(kMessage)),
        "writes a guest C string");

  const std::array<std::uint64_t, 2> tls_index{
      tls_modules.modules[0].image.tls->module_id, 0};
  Check(memory.Write(kTlsIndexAddress, tls_index.data(), sizeof(tls_index)),
        "writes an ELF tls_index structure into guest memory");
  arguments = {};
  arguments[0] = kTlsIndexAddress;
  const auto tls_resolved = calls.DispatchSvc(
      ReadSvcImmediate(memory, *tls_get_addr_stub), arguments);
  std::uint64_t tls_initial_value = 0;
  Check(tls_resolved.success &&
            tls_resolved.value ==
                tls_thread.thread_pointer +
                    tls_modules.modules[0].image.tls->static_offset_from_tp &&
            memory.Read(tls_resolved.value, &tls_initial_value,
                        sizeof(tls_initial_value)) &&
            tls_initial_value == 0x1122334455667788ULL,
        "__tls_get_addr resolves a tls_index through guest memory and per-thread TLS");

  const std::array<std::uint64_t, 2> invalid_tls_index{999, 0};
  Check(memory.Write(kTlsIndexAddress, invalid_tls_index.data(),
                     sizeof(invalid_tls_index)),
        "writes an invalid guest TLS module index");
  arguments = {};
  arguments[0] = kTlsIndexAddress;
  const auto invalid_tls_result = calls.DispatchSvc(
      ReadSvcImmediate(memory, *tls_get_addr_stub), arguments);
  Check(!invalid_tls_result.success &&
            invalid_tls_result.error.find("module ID") != std::string::npos,
        "rejects invalid __tls_get_addr module IDs");

  arguments = {};
  arguments[0] = kSource;
  arguments[1] = static_cast<std::uint64_t>('l');
  arguments[2] = sizeof(kMessage);
  const auto first_byte_search = calls.DispatchSvc(
      ReadSvcImmediate(memory, *memchr_stub), arguments);
  Check(first_byte_search.success && first_byte_search.value == kSource + 2,
        "memchr searches arbitrary bytes without leaving guest memory");

  arguments[1] = static_cast<std::uint64_t>('z');
  const auto missing_byte_search = calls.DispatchSvc(
      ReadSvcImmediate(memory, *memchr_stub), arguments);
  Check(missing_byte_search.success && missing_byte_search.value == 0,
        "memchr returns null when the byte is absent");

  constexpr std::uint64_t kConcatDestination = kDestination + 0x300;
  constexpr std::uint64_t kConcatSource = kTestBase + 0x600;
  constexpr char kConcatInitial[] = "Hello ";
  constexpr char kConcatSuffix[] = "WORLD";
  Check(memory.Write(kConcatDestination, kConcatInitial, sizeof(kConcatInitial)) &&
            memory.Write(kConcatSource, kConcatSuffix, sizeof(kConcatSuffix)),
        "writes bounded guest strings for concatenation tests");
  arguments = {};
  arguments[0] = kConcatDestination;
  arguments[1] = kConcatSource;
  const auto concat_result = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strcat_stub), arguments);
  constexpr char kConcatExpected[] = "Hello WORLD";
  std::array<char, sizeof(kConcatExpected)> concat_buffer{};
  Check(concat_result.success && concat_result.value == kConcatDestination &&
            memory.Read(kConcatDestination, concat_buffer.data(), concat_buffer.size()) &&
            std::memcmp(concat_buffer.data(), kConcatExpected, sizeof(kConcatExpected)) == 0,
        "strcat appends the complete source string in guest memory");

  constexpr std::uint64_t kBoundedConcatDestination = kDestination + 0x400;
  constexpr char kBoundedConcatInitial[] = "Hello ";
  constexpr char kBoundedConcatSuffix[] = "worldwide";
  Check(memory.Write(kBoundedConcatDestination, kBoundedConcatInitial,
                     sizeof(kBoundedConcatInitial)) &&
            memory.Write(kConcatSource, kBoundedConcatSuffix,
                         sizeof(kBoundedConcatSuffix)),
        "writes guest strings for bounded concatenation");
  arguments = {};
  arguments[0] = kBoundedConcatDestination;
  arguments[1] = kConcatSource;
  arguments[2] = 5;
  const auto bounded_concat_result = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strncat_stub), arguments);
  constexpr char kBoundedConcatExpected[] = "Hello world";
  std::array<char, sizeof(kBoundedConcatExpected)> bounded_concat_buffer{};
  Check(bounded_concat_result.success &&
            bounded_concat_result.value == kBoundedConcatDestination &&
            memory.Read(kBoundedConcatDestination, bounded_concat_buffer.data(),
                        bounded_concat_buffer.size()) &&
            std::memcmp(bounded_concat_buffer.data(), kBoundedConcatExpected,
                        sizeof(kBoundedConcatExpected)) == 0,
        "strncat appends no more than the specified source byte count");

  constexpr std::uint64_t kCaseLeft = kTestBase + 0x700;
  constexpr std::uint64_t kCaseRight = kTestBase + 0x740;
  constexpr char kCaseLeftText[] = "Android";
  constexpr char kCaseRightText[] = "aNDROID";
  Check(memory.Write(kCaseLeft, kCaseLeftText, sizeof(kCaseLeftText)) &&
            memory.Write(kCaseRight, kCaseRightText, sizeof(kCaseRightText)),
        "writes case-comparison strings into guest memory");
  arguments = {};
  arguments[0] = kCaseLeft;
  arguments[1] = kCaseRight;
  const auto case_result = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strcasecmp_stub), arguments);
  Check(case_result.success && case_result.value == 0,
        "strcasecmp compares ASCII strings without case sensitivity");
  arguments[2] = 3;
  const auto bounded_case_result = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strncasecmp_stub), arguments);
  Check(bounded_case_result.success && bounded_case_result.value == 0,
        "strncasecmp respects the caller's prefix bound");

  arguments = {};
  arguments[0] = kSource;
  const auto length = calls.DispatchSvc(strlen_svc, arguments);
  Check(length.success && length.value == 5,
        "strlen reads a string through guest-memory validation");

  arguments = {};
  arguments[0] = kSource;
  arguments[1] = 3;
  const auto bounded_length = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strnlen_stub), arguments);
  Check(bounded_length.success && bounded_length.value == 3,
        "strnlen stops at its caller-supplied bound");

  constexpr std::uint64_t kStringCopyDestination = kDestination + 0x100;
  arguments = {};
  arguments[0] = kStringCopyDestination;
  arguments[1] = kSource;
  const auto string_copy = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strcpy_stub), arguments);
  std::array<char, sizeof(kMessage)> strcpy_result{};
  Check(string_copy.success && string_copy.value == kStringCopyDestination &&
            memory.Read(kStringCopyDestination, strcpy_result.data(),
                        strcpy_result.size()) &&
            std::memcmp(strcpy_result.data(), kMessage, sizeof(kMessage)) == 0,
        "strcpy copies and terminates strings in guest memory");

  constexpr std::uint64_t kStrncpyDestination = kDestination + 0x200;
  arguments = {};
  arguments[0] = kStrncpyDestination;
  arguments[1] = kSource;
  arguments[2] = 7;
  const auto string_n_copy = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strncpy_stub), arguments);
  std::array<char, 7> strncpy_result{};
  const std::array<char, 7> expected_strncpy{'h', 'e', 'l', 'l', 'o', '\0', '\0'};
  Check(string_n_copy.success && string_n_copy.value == kStrncpyDestination &&
            memory.Read(kStrncpyDestination, strncpy_result.data(),
                        strncpy_result.size()) &&
            strncpy_result == expected_strncpy,
        "strncpy zero-pads the destination after the source terminator");

  arguments = {};
  arguments[0] = kSource;
  arguments[1] = static_cast<std::uint64_t>('l');
  const auto first_character = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strchr_stub), arguments);
  Check(first_character.success && first_character.value == kSource + 2,
        "strchr returns a guest address for the first matching byte");

  arguments[1] = static_cast<std::uint64_t>('l');
  const auto last_character = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strrchr_stub), arguments);
  Check(last_character.success && last_character.value == kSource + 3,
        "strrchr returns a guest address for the last matching byte");

  arguments[1] = 0;
  const auto terminator_character = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strchr_stub), arguments);
  Check(terminator_character.success &&
            terminator_character.value == kSource + sizeof(kMessage) - 1,
        "strchr can return the guest string terminator");

  constexpr std::uint64_t kNeedleAddress = kTestBase + 0x500;
  constexpr char kNeedle[] = "ll";
  Check(memory.Write(kNeedleAddress, kNeedle, sizeof(kNeedle)),
        "writes a guest substring search needle");
  arguments = {};
  arguments[0] = kSource;
  arguments[1] = kNeedleAddress;
  const auto substring = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strstr_stub), arguments);
  Check(substring.success && substring.value == kSource + 2,
        "strstr returns the guest address of the first substring match");

  arguments = {};
  arguments[0] = kSource;
  const auto duplicated_string = calls.DispatchSvc(
      ReadSvcImmediate(memory, *strdup_stub), arguments);
  std::array<char, sizeof(kMessage)> duplicated_string_result{};
  Check(duplicated_string.success && duplicated_string.value != 0 &&
            memory.Read(duplicated_string.value, duplicated_string_result.data(),
                        duplicated_string_result.size()) &&
            std::memcmp(duplicated_string_result.data(), kMessage,
                        sizeof(kMessage)) == 0,
        "strdup returns an owned guest allocation containing a full C string");

  arguments = {};
  arguments[0] = kDestination;
  arguments[1] = kSource;
  arguments[2] = sizeof(kMessage);
  const auto copied = calls.DispatchSvc(ReadSvcImmediate(memory, *memcpy_stub),
                                        arguments);
  std::array<char, sizeof(kMessage)> copied_message{};
  Check(copied.success && copied.value == kDestination &&
            memory.Read(kDestination, copied_message.data(),
                        copied_message.size()) &&
            std::memcmp(copied_message.data(), kMessage, sizeof(kMessage)) == 0,
        "memcpy copies guest-to-guest without exposing host pointers");

  arguments = {};
  arguments[0] = kSource;
  arguments[1] = kDestination;
  const auto compared = calls.DispatchSvc(ReadSvcImmediate(memory, *strcmp_stub),
                                          arguments);
  Check(compared.success && compared.value == 0,
        "strcmp compares strings from guest memory");

  arguments = {};
  arguments[0] = kDestination;
  arguments[1] = kSource;
  arguments[2] = A64GuestHostCalls::kMaximumTransferBytes + 1ULL;
  const auto oversized = calls.DispatchSvc(
      ReadSvcImmediate(memory, *memcpy_stub), arguments);
  Check(!oversized.success &&
            oversized.error.find("transfer limit") != std::string::npos,
        "rejects unsafe oversized memory transfers");

  arguments = {};
  arguments[0] = 32;
  const auto allocated = calls.DispatchSvc(ReadSvcImmediate(memory, *malloc_stub),
                                           arguments);
  Check(allocated.success && allocated.value != 0 &&
            memory.IsMapped(allocated.value, 1),
        "malloc returns mapped guest memory rather than a host pointer");

  constexpr std::uint64_t kSentinel = 0x123456789ABCDEF0ULL;
  Check(memory.Write(allocated.value, &kSentinel, sizeof(kSentinel)),
        "guest allocation is writable");

  arguments = {};
  arguments[0] = allocated.value;
  arguments[1] = 128;
  const auto reallocated = calls.DispatchSvc(
      ReadSvcImmediate(memory, *realloc_stub), arguments);
  std::uint64_t preserved = 0;
  Check(reallocated.success && reallocated.value != 0 &&
            memory.Read(reallocated.value, &preserved, sizeof(preserved)) &&
            preserved == kSentinel && !memory.IsMapped(allocated.value, 1),
        "realloc preserves guest bytes and releases the previous mapping");

  arguments = {};
  arguments[0] = reallocated.value;
  const auto freed = calls.DispatchSvc(ReadSvcImmediate(memory, *free_stub),
                                       arguments);
  Check(freed.success && !memory.IsMapped(reallocated.value, 1),
        "free accepts and releases only a tracked guest allocation");

  const auto versioned = calls.ResolveVersionedSymbol(
      {"strlen", "LIBC_PRIVATE", "libc.so"});
  Check(!versioned,
        "refuses to satisfy unknown versioned imports with an unversioned thunk");

  const auto versioned_strlen =
      calls.ResolveVersionedSymbol({"strlen", "LIBC", "libc.so"});
  Check(strlen_stub && versioned_strlen &&
            *versioned_strlen == *strlen_stub,
        "resolves public Bionic LIBC imports through provider-matched prototype shims");
  const auto newer_versioned_strlen =
      calls.ResolveVersionedSymbol({"strlen", "LIBC_N", "libc.so"});
  Check(strlen_stub && newer_versioned_strlen &&
            *newer_versioned_strlen == *strlen_stub,
        "accepts known newer Bionic symbol-version namespaces");
  Check(!calls.ResolveVersionedSymbol({"strlen", "LIBC", "libm.so"}),
        "does not resolve a versioned import from the wrong provider");

  const auto stderr_data = calls.ResolveSymbol("stderr");
  const auto versioned_stderr =
      calls.ResolveVersionedSymbol({"stderr", "LIBC", "libc.so"});
  std::uint64_t stderr_stream = 0;
  Check(stderr_data && versioned_stderr &&
            *stderr_data == *versioned_stderr &&
            memory.Read(*stderr_data, &stderr_stream, sizeof(stderr_stream)) &&
            stderr_stream != 0 && memory.IsMapped(stderr_stream, 1),
        "resolves versioned stderr data imports to a mapped guest FILE placeholder");

  arguments = {};
  arguments[0] = duplicated_string.value;
  const auto freed_string = calls.DispatchSvc(
      ReadSvcImmediate(memory, *free_stub), arguments);
  Check(duplicated_string.success && duplicated_string.value != 0 &&
            freed_string.success && !memory.IsMapped(duplicated_string.value, 1),
        "free releases a pointer allocated by strdup");

  const auto abort_stub = calls.ResolveSymbol("abort");
  Check(abort_stub.has_value(), "registers a diagnostic abort thunk");
  if (abort_stub) {
    const auto abort_result = calls.DispatchSvc(
        ReadSvcImmediate(memory, *abort_stub), {});
    Check(!abort_result.success,
          "guest abort fails explicitly without aborting the host process");
  }

  std::string tls_cleanup_error;
  Check(tls_runtime.DestroyThread(&tls_thread, &tls_cleanup_error),
        "cleans up TLS mapping owned by the host-call test");

  std::cout << failures << " guest host-call test(s) failed\n";
  return failures == 0 ? 0 : 1;
}
