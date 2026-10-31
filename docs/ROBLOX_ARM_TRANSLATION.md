# Roblox ARM translation on x86-64

## Scope

This branch investigates running AArch64 machine code on an x86-64 Linux host. It is an early development branch, not a working ARM64 Roblox runtime.

Mocktail's current native runtime is built for the host ISA. An x86-64 process cannot directly call AArch64 machine code; changing the APK ABI label or ELF acceptance checks is not enough. The CPU translation engine must be paired with a guest memory model, ELF loader/relocations, guest-to-host ABI bridges, Android/Bionic compatibility, thread-local storage, and a graphics interop strategy.

## First diagnostic

Run the standard-library-only APK inspector against the locally supplied Roblox APK (or each APK in a split package):

```bash
python tools/roblox-arm-preflight.py ~/Downloads/Roblox.apk
```

The tool lists native libraries, checks their ELF machine fields, and reports ABI-directory mismatches. It does not execute or modify package contents and does not verify runtime compatibility.

## Dynarmic integration

When configured with `-DMOCKTAIL_ENABLE_ROBLOX_ARM_TRANSLATION=ON`, CMake fetches a pinned Dynarmic revision and builds an isolated AArch64 CPU smoke-test target. The option is off by default so ordinary Mocktail builds do not gain the extra dependency or network fetch.

On x86-64 Linux, Dynarmic requires the Boost development headers and uses its pinned bundled external projects for other dependencies. On CachyOS/Arch, install the `boost` package before configuring the optional target.

The bounded ELF64 loader maps AArch64 `PT_LOAD` segments and zero-initializes BSS, extracts `DT_NEEDED`/`DT_SONAME`, supports RELA relocations (`RELATIVE`, `ABS64`, `GLOB_DAT`, and `JUMP_SLOT`), Android APS2-packed RELA, and RELR pointer relocations. It validates `PT_TLS` bounds/alignment and preserves the template's initial data plus its zero-filled BSS tail. It also parses bounded `DT_VERNEED`/`DT_VERDEF` metadata and resolves versioned imports only when both symbol name and version/provider match; name-only resolver fallback is deliberately forbidden for versioned imports. Static TLS relocations for preloaded modules are supported when the TLS layout and static TLSDESC thunk are supplied explicitly. Dynamic TLS allocation, IFUNCs, text relocations, and full Android symbol-version interposition rules remain unsupported and fail closed. Parsing a TLS template is not the same as providing per-thread TLS or Bionic's Android thread-pointer layout.

The experimental guest module loader now accepts a trusted catalogue of AArch64 shared-object bytes, walks the root object's `DT_NEEDED` closure, checks missing/ambiguous dependencies, assigns distinct guest address ranges, collects externally visible exports with GNU symbol-version metadata, and repeats the load with relocations resolved against the complete module set. Versioned bindings require an exact symbol name, version and provider match; the module resolver does not ignore version requirements. The runtime recognizes SONAMEs of common public Android system libraries as external dependency names when its built-in compatibility layer is enabled; this permits system-provided dependencies such as `liblog.so`, `libm.so`, and graphics libraries to be absent from the APK. That allow-list does not emulate those libraries: every imported symbol must still resolve to a guest address through a supplied ELF or an explicit host-call thunk. The ELF loader also extracts and validates `DT_INIT`, `DT_INIT_ARRAY`, `DT_FINI_ARRAY`, and `DT_FINI` after relocations. The module-set loader computes a dependency-first constructor order and reverse finalizer order, including cycle-safe graph traversal. The smoke harness has an opt-in mode that runs these callbacks in dependency order for an isolated linker-produced test library. This does not provide automatic Android process startup, Bionic-compatible constructor arguments, finalizer execution, or error recovery for complex constructor graphs; those remain runtime work.

A sparse page-based guest memory layer maps ELF images and anonymous memory with read/write/execute permissions; instruction fetch checks execute permission independently of guest data-read permission. The reusable runtime maps configurable no-access guard pages above and below the guest stack (one page on each side by default), so stack overflows/underflows fault as guest permission failures instead of silently reaching adjacent memory. The sparse guest-memory container itself is still single-threaded; page-map synchronization and concurrent guest execution are not implemented. It provides first-fit anonymous mapping, whole-range permission changes, Linux-style unmapping that tolerates holes, and a bounded `brk` heap in guest-only memory. An explicit AArch64 syscall dispatcher handles anonymous private/shared `mmap` (including non-overwriting `MAP_FIXED_NOREPLACE`), `mprotect`, `madvise` for range-validated `MADV_NORMAL`/`RANDOM`/`SEQUENTIAL`/`WILLNEED` hints, `munmap`, `brk`, `exit`, `exit_group`, `clock_gettime`, `clock_getres`, `uname`, bounded `getrandom`, single-context `rt_sigprocmask`, and a deliberately small virtual `prctl` subset for guest thread naming, dumpable state, irreversible `NO_NEW_PRIVS` metadata, and querying the guest `clear_child_tid` address with `PR_GET_TID_ADDRESS`. The guest signal mask is maintained in virtual state and never changes the host process mask; signal delivery and guest signal-handler execution are not implemented. `prctl` affects virtual guest metadata only; it never changes the host thread name, dumpability, or security policy, and unsupported options return `-EINVAL`. `PR_GET_TID_ADDRESS` writes the recorded guest address to validated guest memory and never exposes a host pointer. It reports a synthetic unprivileged guest PID/TID and UID/GID, supports `set_tid_address` and clears the registered guest `clear_child_tid` word on exit, and accepts the AArch64 `set_robust_list` structure size for the single-context prototype. Robust-owner-death recovery, futex wakeups, and independent guest-thread scheduling are not implemented; `sched_yield` remains a no-op. These virtual identities do not alter host credentials. Unsupported guest syscalls return `-ENOSYS`; guest pointers are validated through guest memory, and arbitrary guest syscalls are never forwarded blindly to the host. File-backed mappings and a guest file-descriptor layer remain unsupported. `MADV_DONTNEED` zeroes fully mapped anonymous guest pages and preserves their permissions; it fails closed on ELF image pages because no backing file is retained to repopulate them. Other `madvise` operations that alter page lifetime or fork/coredump/backing policy fail closed with `-ENOSYS`; unknown advice values return `-EINVAL`. The Dynarmic smoke harness maps every module returned by the two-pass loader into one guest address space and supplies an anonymous stack. Cross-compiled test shared objects exercise a root entry point that calls into a dependency, an exported function called through a guest return trap, and guest `svc #0` calls that allocate, access, and release anonymous memory. A small, explicit libc subset routes through guest SVC stubs rather than host function pointers. Its bounded string/memory routines include `memcpy`, `memmove`, `memset`, `memcmp`, `memchr`, `strlen`, `strnlen`, `strcmp`, `strncmp`, `strcasecmp`, `strncasecmp`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strchr`, `strrchr`, `strstr`, and `strdup`; allocation APIs return only tracked guest mappings with ownership checks. Guest `__errno`/`__errno_location` thunks return a writable guest errno cell; this remains a single-threaded errno slot until guest pthread/TLS integration is implemented.

The prototype lays out each loaded module's `PT_TLS` template at an aligned static offset from a guest thread pointer, maps an independent initialized TLS region per guest thread, and exposes that guest address through Dynarmic's emulated `TPIDR_EL0`. Cross-compiled smoke libraries now exercise TP-relative access, a static TLSDESC resolver, and an ordinary guest call through a dynamic relocation to `__tls_get_addr`. That thunk resolves the standard two-word `tls_index` through guest memory to a preloaded module's per-thread block. These paths only support modules included before TLS preparation; `dlopen`-style dynamic allocation, full Android/Bionic TCB/DTV semantics, and guest pthread scheduling remain gaps. Constructor execution remains an isolated smoke-harness feature rather than automatic Android process startup. Broader syscall coverage, JNI, Android linker namespaces, remaining symbol-version/interposition rules, and graphics interop remain gaps.

When `aarch64-linux-gnu-gcc` is installed, CMake also generates a genuine AArch64 `.so` fixture and sends it through the ELF loader and Dynarmic, stopping at a controlled `BRK`. The dedicated branch workflow installs this cross-toolchain so that the real-ELF path is tested in CI. This demonstrates basic code execution from a linker-produced guest image, not compatibility with the Android linker or the Roblox client.

## Reproducible translation test run

From the repository root on an x86-64 Linux host, configure and build the opt-in translation targets (the regular Mocktail build remains unchanged when this option is off):

```bash
cmake -S . -B build-arm-translation \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON \
  -DMOCKTAIL_ENABLE_ROBLOX_ARM_TRANSLATION=ON

cmake --build build-arm-translation --parallel 2 --target \
  mocktail_a64_elf_loader_test \
  mocktail_a64_guest_memory_test \
  mocktail_a64_guest_module_loader_test \
  mocktail_a64_linux_syscalls_test \
  mocktail_a64_guest_runtime_test \
  mocktail_a64_guest_jni_test \
  mocktail_a64_guest_probe \
  mocktail_a64_translation_smoke

ctest --test-dir build-arm-translation \
  -R '^RobloxArmTranslation\.' --output-on-failure --timeout 120
```

The build uses the installed Boost development headers and fetches the pinned Dynarmic source. If `aarch64-linux-gnu-gcc` and Clang are available, CMake also builds real linker-produced AArch64 ELF and Android-targeted ELF fixtures, which activate additional smoke tests. A passing synthetic test suite validates only the features those fixtures exercise.

Before attempting any execution against a real Roblox package, run the static preflight and ELF audit:

```bash
python3 tools/roblox-arm-preflight.py /path/to/Roblox.apk
python3 tools/a64-elf-audit.py --json /path/to/Roblox.apk \
  > roblox-arm64-audit.json
```

The optional native probe may then load the APK's supplied ARM64 shared-object dependency set. Listing exports is non-executing; `--call SYMBOL`, `--jni-onload`, `--call-native`, and `--run-initializers` explicitly enter guest code. Use the probe only against libraries you trust, and treat missing symbols, unresolved Android platform libraries, or unsupported ABI behavior as useful compatibility findings rather than as evidence that the complete Roblox application should start.

## Real-package smoke automation

The branch CI workflow has an opt-in real-client probe for the pinned Roblox Android ARM64 split (versionCode 18934). To run it from GitHub, open **Actions → ARM64 translation prototype → Run workflow** and enable `run_real_roblox_apk_smoke`. The workflow verifies pinned SHA-256 hashes, audits the package, attempts constructors plus `JNI_OnLoad` under Dynarmic with a bounded instruction budget, and uploads `real-roblox-arm64-probe` diagnostics. A successful JNI probe is only an initialization milestone, not proof that the Roblox app can launch or render.

For a push-triggered diagnostic run, a commit touching a path watched by `.github/workflows/arm64-translation.yml` can include `[real-apk-smoke]` in its message. This is intentionally non-gating: compatibility failures are preserved as logs instead of being reported as a successful app launch.

## Auditing an actual APK/APKS package

After obtaining the official ARM64 APK, an `.apks` split-set archive, or each APK from a split install, run the read-only audit first:

```bash
python3 tools/roblox-arm-preflight.py ~/Downloads/Roblox.apk
python3 tools/a64-elf-audit.py --json ~/Downloads/Roblox.apk > roblox-arm64-audit.json
```

The ELF audit reads native libraries without extracting or executing them. Its package summary resolves bundled `DT_NEEDED` edges, reports duplicate SONAMEs, checks imports against the bundle's visible exports, and lists Android platform symbols that the current explicit host-call table does not implement. A green ELF-loader candidate flag only covers this prototype's supported ELF subset; `ready_to_launch` intentionally remains false until Android/Bionic startup, the required platform APIs, JNI and graphics have been validated.

## Delta 2.743.1136 ARM64 audit findings

A supplied audit of the Delta 2.743.1136-02 package found eight ARM64 native libraries. All eight were ELF64/AArch64 `ET_DYN` images with no unsupported relocation types in that audit. `libroblox.so` uses Android APS2 packed RELA and contains a much larger relocation set than the helper libraries. These findings establish that the current ELF parser can understand the observed relocation formats; they do not establish that the package can be initialized.

The sample also exposes platform requirements beyond the currently registered shims:

- `libroblox.so` imports Android asset-manager, looper, configuration and native-window APIs, including `AAssetManager_fromJava`, `AAssetManager_open`, `ALooper_prepare`, `AConfiguration_fromAssetManager` and `ANativeWindow_fromSurface`. The runtime does not yet implement those APIs or the Java/Surface objects they depend on.
- `libsurface_util_jni.so` and `libimage_processing_util_jni.so` require native-window and bitmap operations. These need a real guest-to-host surface/bitmap boundary, not success-shaped placeholder pointers.
- `libtrampoline.so` imports the private Bionic `__libc_init` entry point. It is not in `libroblox.so`'s listed `DT_NEEDED` closure, and it must not be treated as an ordinary public libc function or satisfied with a blind no-op.
- `libdatastore_shared_counter.so` imports `__system_property_get`, which has a synthetic-profile shim in the current runtime. The audit now records registered Android shims separately from platform imports that remain unresolved.

Prioritize the asset-manager/Java bridge and looper lifecycle after the existing JNI bridge, then native-window/surface integration. Keep `__libc_init` explicitly unsupported until its call site and Bionic startup contract are understood. The audit's `prototype_loader_compatible` flag is strictly an ELF-format result; `ready_for_roblox` remains false.

## Architecture options to evaluate

1. **In-process guest execution:** Dynarmic JIT + guest address-space management + an AArch64 ELF loader + explicit ABI thunks for callbacks into native x86-64 code. Guest pointers and host pointers must never be treated as interchangeable.
2. **Separate guest process:** an ARM64 guest userspace under a user-mode translator, with IPC for lifecycle, input, audio and graphics. This provides stronger ABI isolation but significantly changes the application architecture.

The first milestone is to build the CPU smoke target on x86-64. Do not enable ARM64 package selection in Mocktail's normal runtime until the guest-loader and ABI bridge have been designed and tested.

## Milestones

- [x] Add an APK native-ABI/ELF preflight tool.
- [x] Add a read-only ARM64 ELF audit tool for APKs, split APKs, dependencies, version metadata, TLS and dynamic relocation coverage.
- [x] Add tests for ELF identification, ABI mismatch reporting and split-package detection.
- [x] Add an optional, pinned Dynarmic dependency and an isolated AArch64 CPU smoke target.
- [x] Add a bounded ELF64 little-endian AArch64 loader for PT_LOAD segments, including BSS zero-fill, ET_DYN load bias, entry-point validation and read/write bounds checks.
- [x] Validate and preserve PT_TLS templates, assign static TP offsets, allocate per-thread guest TLS blocks, and connect Dynarmic TPIDR_EL0.
- [x] Support a preloaded-module static TLS relocation subset (DTPMOD64, DTPREL64, TPREL64) and a static guest TLSDESC resolver.
- [x] Add a guest-safe `__tls_get_addr` host-call thunk for TLS modules prepared before thread creation.
- [ ] Implement `dlopen`-style dynamic TLS/DTV allocation, Bionic TCB slots, and guest pthread/thread scheduling.
- [x] Run the Dynarmic smoke instructions from a synthetic ELF image instead of a raw byte array, including guest stack stores and loads.
- [x] Parse DT_NEEDED/DT_SONAME and apply bounded AArch64 RELATIVE, ABS64, GLOB_DAT and JUMP_SLOT RELA relocations.
- [x] Add bounded SysV/GNU hash-based symbol counts and explicit undefined-symbol resolver callbacks.
- [x] Extract and validate dynamic initializer/finalizer callbacks after relocations, and execute a linker-produced initializer in the isolated smoke harness.
- [ ] Implement full Android/Bionic process startup/exit semantics, constructor arguments and automatic finalizer execution.
- [x] Compute dependency-first module initialization order and reverse finalization order, while leaving callback execution disabled.
- [x] Fail closed for unsupported relocation formats, unresolved symbol versions, IFUNCs and text relocations; support the documented preloaded-module static TLS subset.
- [x] Add branch-specific CI for the synthetic ELF and Dynarmic tests.
- [x] Add an optional cross-compiled AArch64 shared-object fixture and execute it through the loader/JIT path.
- [x] Confirm the dedicated AArch64 translation workflow passes on a clean x86-64 Linux host (25/25 translation, Android-style ELF, APK/APKS integration, and preflight tests on the uname-fix commit).
- [x] Build a two-pass multi-image dependency resolver for catalogued ET_DYN objects with exact GNU symbol version/provider matching.
- [x] Parse bounded GNU `DT_VERNEED`/`DT_VERDEF` and retain versioned exports with exact version/provider matching.
- [ ] Validate symbol-version behavior against real Android ARM64 package libraries, including default-version interposition rules.
- [x] Add sparse page-based guest mappings with basic read/write/execute permissions and an anonymous stack mapping for the CPU smoke guest.
- [x] Add bounded guest `mmap`-style address allocation, `mprotect` permissions, Linux-style `munmap` support that tolerates unmapped holes, and a private `brk` heap.
- [x] Add an allow-listed AArch64 syscall dispatcher for anonymous memory operations (including `MAP_FIXED_NOREPLACE`), range-validated safe `madvise` hints plus anonymous-page `MADV_DONTNEED`, guest process exit/`clear_child_tid`, monotonic/realtime clock queries, guest uname identity, bounded getrandom, synthetic process/credential identity, single-context `rt_sigprocmask`, guest-only `prctl` thread-name/dumpable/`NO_NEW_PRIVS` metadata plus `PR_GET_TID_ADDRESS`, robust-list metadata, and scheduler-yield fallback, with regression tests.
- [x] Add a bounded two-pass guest module-set loader with `DT_NEEDED` closure discovery, non-overlapping image placement, unversioned export indexing, and dependency relocation tests.
- [x] Add configurable no-access guard pages around the guest stack and test both sides with multiple guard pages.
- [ ] Add guest-memory synchronization before supporting concurrent guest threads or parallel JIT access.
- [x] Add explicit guest-to-host SVC thunks with bounded memory/string routines, case-insensitive string comparisons, guest errno accessors, TLS helpers, and tracked guest allocations; continue expanding coverage based on real package imports.
- [x] Add a configurable synthetic Android property profile and guest-safe `__system_property_get` thunk, tested from Android-targeted translated JNI code.
- [x] Add guest-opaque `prop_info` handles with `__system_property_find`, `__system_property_read`, `__system_property_serial`, and `__system_property_area_serial`; handle lookup, stable serials, and invalid guest buffers are covered by the Android JNI fixture.
- [x] Add a guest `getauxval` subset for page size, conservative HWCAP/HWCAP2, synthetic IDs, `AT_PLATFORM`, `AT_EXECFN`, and secure guest-memory `AT_RANDOM`; unknown keys set guest `errno` to `ENOENT`.
- [x] Expose `android_get_device_api_level()` under `libandroid.so`, sourced from the configured synthetic SDK property and covered by the JNI smoke fixture.
- [x] Add bounded `liblog.so` shims for `__android_log_write`, `__android_log_buf_write`, and `__android_log_is_loggable`; guest strings are read through guest memory and log line breaks are escaped.
- [x] Add a single-context C++ static guard subset (`__cxa_guard_acquire/release/abort`) plus no-op pthread mutex/rwlock/spin operations and synthetic `pthread_self/equal`; these are strictly not a multithreading implementation.
- [x] Fill JavaVM `AttachCurrentThread`, `AttachCurrentThreadAsDaemon`, `DetachCurrentThread`, and `GetEnv` table slots for the existing single guest execution context, with JNI_EDETACHED and bad guest output-pointer tests.
- [x] Execute an Android-style JNI_OnLoad through guest JavaVM/JNIEnv function tables, validate class lookup, and record RegisterNatives targets.
- [x] Invoke registered static JNI natives through the guest ABI with integer/reference arguments in X2-X7, float/double arguments in V0-V7, and overflow arguments on the guest stack; cover register allocation through synthetic APK integration tests.
- [x] Add bounded JNI NewStringUTF/GetStringUTFLength/GetStringUTFChars/ReleaseStringUTFChars support with guest-memory-safe buffers and pointer-failure tests.
- [x] Add bounded guest `dlopen`/`dlsym`/`dlclose`/`dlerror` thunks for the preloaded module set and exercise them through an Android-targeted APK.
- [ ] Integrate the remaining Android/Bionic APIs, object/ART lifecycle, real guest-thread attachment/scheduling and graphics boundaries.
- [ ] Validate the integration against real ARM64 Roblox libraries and the full Android framework before attempting full Roblox startup.

## Calling a registered JNI native in the prototype

The probe can exercise the narrow JNI path without pretending to start ART:

```bash
python3 tools/mocktail-a64-apk-probe.py \
  --root libexample.so \
  --call-native com/example/Native nativeSum '(II)I' \
  --arg0 20 --arg1 22 \
  path/to/client.apk
```

This loads the root dependency closure, runs dependency-ordered ELF constructors, calls `JNI_OnLoad`, checks the returned JNI version and pending-exception state, looks up the exact `RegisterNatives` tuple, and invokes the registered guest function with `JNIEnv*` in X0 and the opaque class handle in X1. Integer/reference arguments are assigned to X2-X7, float/double arguments to V0-V7 independently, and overflow arguments to 8-byte AAPCS64 stack slots. The probe accepts up to 262 parameters; CLI `--argN` values for F/D parameters are raw IEEE-754 bit patterns. `A64GuestCallResult::value_is_floating_point` marks raw IEEE-754 return bits read from V0 (32 bits for float, 64 bits for double); the probe prints V0 for those results. The JavaVM invocation table now exposes attach/detach/daemon-attach/GetEnv slots for the current guest context; it deliberately does not spawn or schedule guest pthreads, and its attachment flag is global to the one-context prototype. Static C++ initialization guards use a simplified in-progress/initialized bit state, and pthread mutex/rwlock/spin lock functions are no-ops for the single context. Calls that would require real guest thread creation or condition-variable scheduling are not implemented and must not be treated as successful concurrency support. The guest runtime also supplies `__system_property_get` from a configurable synthetic Android property profile (API level, release, ARM64 ABI, and virtual-device markers by default). Missing properties return an empty string; values obey Bionic's 92-byte `PROP_VALUE_MAX` including the NUL. The guest also exposes the older opaque `prop_info` interface through `__system_property_find/read` and fixed serials for this immutable profile; it does not implement property-change waiting, the newer read-callback interface, or mutation. The NDK's `android_get_device_api_level()` entry point is also provided from the same SDK property so the two APIs remain consistent. This is a test profile, not the host's properties and not evidence that an actual Android device identity has been recreated. Bounded `liblog.so` entry points are also present for native code that logs during `JNI_OnLoad`: tag and message strings must be readable in guest memory, are size-capped, and embedded line breaks are escaped before reaching host logs. `__android_log_is_loggable` uses the requested/default priority fallback and does not emulate Android's per-tag system-property overrides or logd buffers. The guest `getauxval` shim is similarly conservative: it reports 4 KiB pages, only baseline FP/ASIMD HWCAP, zero HWCAP2, guest UID/GID 10000, and guest-resident `AT_PLATFORM`, `AT_EXECFN`, and 16-byte `AT_RANDOM`; unsupported tags return zero and set guest `errno` to `ENOENT`. The current bridge supports predeclared class names and static native methods. For JNI-oriented probe modes, the runtime executes the dependency-ordered ELF constructors before calling `JNI_OnLoad`; raw `--call SYMBOL` keeps constructor execution opt-in via `--run-initializers`. The string surface is deliberately narrow: `NewStringUTF`, `GetStringUTFLength`, `GetStringUTFChars`, and `ReleaseStringUTFChars` keep byte sequences in opaque string handles and guest-owned temporary buffers, with bounded memory checks; the current smoke test uses ASCII, which is byte-identical in UTF-8 and modified UTF-8. It does not validate/convert arbitrary modified-UTF-8 or UTF-16, implement `NewString`, create a Java heap, or provide ART object semantics. ART, general Java method dispatch, instance construction, arrays, and arguments spilled to the stack remain unsupported. This executes actual guest code and is a validation utility, not a full application launcher.

The experimental runtime also registers guest-side `dlopen`, `dlsym`, `dlclose`, `dlerror`, and `dladdr` symbols under `libdl.so`. `dlopen` may only return handles for images already present in the initial dependency set; `dlsym` resolves an exported non-TLS, non-IFUNC symbol from the handle's dependency closure or the global preloaded namespace; `dlclose` is a no-op because images stay mapped for the runtime lifetime. `dladdr` reports the containing preloaded image and the nearest visible non-TLS/non-IFUNC exported symbol using guest-resident strings and the AArch64 guest address space. Unknown filenames/symbols return null and populate a guest-readable `dlerror` string. This is not dynamic loading: it does not load new files at runtime, relocate modules after startup, unload images, or implement arbitrary Android `libdl` semantics.

## Scope and trust

Keep the existing payload acquisition, compatibility and integrity behavior unchanged while the architecture work is developed. CPU instruction translation is only one component of an Android compatibility runtime.


The experimental native probe accepts a single APK, an `.apks` file directly, or multiple individual split APKs. It extracts only entries under `lib/arm64-v8a/`, checks that they are little-endian ELF64 AArch64 images, and rejects conflicting files with the same basename. Use `--library-dir` to add a directory of matching ARM64 Android runtime libraries (including when no APK positional argument is supplied). Explicit `--external-dependency SONAME` entries only allow a missing `DT_NEEDED` edge; they do not synthesize symbols or implement that library. The end-to-end APK test uses genuine cross-compiled test libraries in a synthetic APK and is not a Roblox compatibility claim.


## Real Roblox probe checkpoint

The pinned 2.743.1136 (versionCode 18934) base and ARM64 split APK pair is the current real-package compatibility target. The manual CI probe downloads and SHA-256 verifies both splits, audits the ARM64 ELF package, then attempts bounded constructor execution and `JNI_OnLoad` in the guest runtime. This checkpoint is diagnostic only: the workflow deliberately does not treat a nonzero probe result as a passing launch, and even a successful constructor/JNI probe would not establish that ART, Android framework services, graphics, input, or the Roblox application can run end-to-end.

Do not mark the runtime ready for a real application launch until the pinned probe has completed successfully and the unresolved imports and runtime requirements for the full package closure have been addressed. In particular, do not replace Android platform APIs with success-shaped no-op stubs merely to move the probe forward.


## Guest APK asset and configuration bridge

The experimental guest runtime now has a bounded, guest-memory-aware subset of the Android NDK asset and configuration APIs. The APK probe extracts regular files under each supplied APK's `assets/` tree into a temporary asset root, rejects traversal and symlink entries, caps individual files at 64 MiB and total expanded assets at 2 GiB, and rejects conflicting duplicate paths across splits. The runtime resolves requested paths beneath that root, returns opaque guest handles rather than host pointers, supports `AAsset_read`, `AAsset_seek`, length queries and a guest-mapped `AAsset_getBuffer`, and releases guest buffer mappings when assets close. The supported configuration profile reports English/US, normal screen size, and 360x640 dp dimensions.

This is a real API implementation for the documented subset, not a complete Android AssetManager or device configuration service. File-descriptor access, asset directory enumeration, resource-table resolution, locale/density selection, and full framework-backed Java AssetManager objects remain unsupported. The Android asset smoke fixture exercises the guest-call path against an extracted asset file; it must pass in CI before this bridge is considered validated. The current branch checkpoint also runs the pinned real Roblox APK constructor/JNI probe so its remaining platform blockers can be measured against the updated runtime.


The same guest platform layer now resolves the Delta audit's ALooper subset. It creates a per-runtime epoll/eventfd looper, supports wake, reference management, fd registration/removal, polling and output delivery for non-callback registrations. Guest callback-based fd registrations are rejected because the runtime does not yet provide safe nested guest callback dispatch. The looper smoke fixture checks both wake delivery and a readable host eventfd.

The Delta surface helper imports are also resolvable in headless mode: `ANativeWindow_fromSurface` returns null when no Android Surface/host window is attached; dimension/format queries return zero, and buffer operations fail with `ENODEV`. The `libjnigraphics.so` bitmap imports similarly return `ANDROID_BITMAP_RESULT_BAD_PARAMETER` because this JNI bridge has no ART Bitmap object or pixel backing. These null/error results are deliberate and safe; they are not a graphics implementation. A real Roblox session still requires a host-window/surface bridge, bitmap backing, Android lifecycle integration, and the remaining runtime APIs.


<!-- CI-only branch marker: validate the guest Android platform bridge. -->
