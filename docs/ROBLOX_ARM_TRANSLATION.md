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

The experimental guest module loader now accepts a trusted catalogue of AArch64 shared-object bytes, walks the root object's `DT_NEEDED` closure, checks missing/ambiguous dependencies, assigns distinct guest address ranges, collects externally visible exports with GNU symbol-version metadata, and repeats the load with relocations resolved against the complete module set. Versioned bindings require an exact symbol name, version and provider match; the module resolver does not ignore version requirements. Dependencies implemented by a guest thunk/runtime layer can be allow-listed explicitly, but every imported symbol must still resolve to a guest address. The ELF loader also extracts and validates `DT_INIT`, `DT_INIT_ARRAY`, `DT_FINI_ARRAY`, and `DT_FINI` after relocations. The module-set loader computes a dependency-first constructor order and reverse finalizer order, including cycle-safe graph traversal. The smoke harness has an opt-in mode that runs these callbacks in dependency order for an isolated linker-produced test library. This does not provide automatic Android process startup, Bionic-compatible constructor arguments, finalizer execution, or error recovery for complex constructor graphs; those remain runtime work.

A sparse page-based guest memory layer maps ELF images and anonymous memory with read/write/execute permissions; instruction fetch checks execute permission independently of guest data-read permission. The reusable runtime maps configurable no-access guard pages above and below the guest stack (one page on each side by default), so stack overflows/underflows fault as guest permission failures instead of silently reaching adjacent memory. The sparse guest-memory container itself is still single-threaded; page-map synchronization and concurrent guest execution are not implemented. It provides first-fit anonymous mapping, whole-range permission changes, Linux-style unmapping that tolerates holes, and a bounded `brk` heap in guest-only memory. An explicit AArch64 syscall dispatcher handles anonymous private/shared `mmap`, `mprotect`, `munmap`, `brk`, `exit`, `exit_group`, `clock_gettime`, `clock_getres`, `uname`, and bounded `getrandom`. It reports a synthetic unprivileged guest PID/TID and UID/GID, with `sched_yield` currently a no-op because guest thread scheduling is not implemented. These values do not alter host credentials. Unsupported guest syscalls return `-ENOSYS`; guest pointers are validated through guest memory, and arbitrary guest syscalls are never forwarded blindly to the host. File-backed mappings and a guest file-descriptor layer remain unsupported. The Dynarmic smoke harness maps every module returned by the two-pass loader into one guest address space and supplies an anonymous stack. Cross-compiled test shared objects exercise a root entry point that calls into a dependency, an exported function called through a guest return trap, and guest `svc #0` calls that allocate, access, and release anonymous memory. A small, explicit libc subset routes through guest SVC stubs rather than host function pointers. Its bounded string/memory routines include `memcpy`, `memmove`, `memset`, `memcmp`, `memchr`, `strlen`, `strnlen`, `strcmp`, `strncmp`, `strcasecmp`, `strncasecmp`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strchr`, `strrchr`, `strstr`, and `strdup`; allocation APIs return only tracked guest mappings with ownership checks. Guest `__errno`/`__errno_location` thunks return a writable guest errno cell; this remains a single-threaded errno slot until guest pthread/TLS integration is implemented.

The prototype lays out each loaded module's `PT_TLS` template at an aligned static offset from a guest thread pointer, maps an independent initialized TLS region per guest thread, and exposes that guest address through Dynarmic's emulated `TPIDR_EL0`. Cross-compiled smoke libraries now exercise TP-relative access, a static TLSDESC resolver, and an ordinary guest call through a dynamic relocation to `__tls_get_addr`. That thunk resolves the standard two-word `tls_index` through guest memory to a preloaded module's per-thread block. These paths only support modules included before TLS preparation; `dlopen`-style dynamic allocation, full Android/Bionic TCB/DTV semantics, and guest pthread scheduling remain gaps. Constructor execution remains an isolated smoke-harness feature rather than automatic Android process startup. Broader syscall coverage, JNI, Android linker namespaces, remaining symbol-version/interposition rules, and graphics interop remain gaps.

When `aarch64-linux-gnu-gcc` is installed, CMake also generates a genuine AArch64 `.so` fixture and sends it through the ELF loader and Dynarmic, stopping at a controlled `BRK`. The dedicated branch workflow installs this cross-toolchain so that the real-ELF path is tested in CI. This demonstrates basic code execution from a linker-produced guest image, not compatibility with the Android linker or the Roblox client.

## Auditing an actual APK/APKS package

After obtaining the official ARM64 APK, an `.apks` split-set archive, or each APK from a split install, run the read-only audit first:

```bash
python3 tools/roblox-arm-preflight.py ~/Downloads/Roblox.apk
python3 tools/a64-elf-audit.py --json ~/Downloads/Roblox.apk > roblox-arm64-audit.json
```

The ELF audit reads native libraries without extracting or executing them. Its package summary resolves bundled `DT_NEEDED` edges, reports duplicate SONAMEs, checks imports against the bundle's visible exports, and lists Android platform symbols that the current explicit host-call table does not implement. A green ELF-loader candidate flag only covers this prototype's supported ELF subset; `ready_to_launch` intentionally remains false until Android/Bionic startup, the required platform APIs, JNI and graphics have been validated.

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
- [ ] Implement automatic Android/Bionic startup, full constructor invocation semantics and finalizer execution.
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
- [x] Add an allow-listed AArch64 syscall dispatcher for anonymous memory operations, guest process exit, monotonic/realtime clock queries, guest uname identity, bounded getrandom, synthetic process/credential identity, and scheduler-yield fallback, with regression tests.
- [x] Add a bounded two-pass guest module-set loader with `DT_NEEDED` closure discovery, non-overlapping image placement, unversioned export indexing, and dependency relocation tests.
- [x] Add configurable no-access guard pages around the guest stack and test both sides with multiple guard pages.\n- [ ] Add guest-memory synchronization before supporting concurrent guest threads or parallel JIT access.
- [x] Add explicit guest-to-host SVC thunks with bounded memory/string routines, case-insensitive string comparisons, guest errno accessors, TLS helpers, and tracked guest allocations; continue expanding coverage based on real package imports.
- [x] Add a configurable synthetic Android property profile and guest-safe `__system_property_get` thunk, tested from Android-targeted translated JNI code.
- [x] Add a guest `getauxval` subset for page size, conservative HWCAP/HWCAP2, synthetic IDs, `AT_PLATFORM`, `AT_EXECFN`, and secure guest-memory `AT_RANDOM`; unknown keys set guest `errno` to `ENOENT`.
- [x] Execute an Android-style JNI_OnLoad through guest JavaVM/JNIEnv function tables, validate class lookup, and record RegisterNatives targets.
- [x] Invoke a registered static JNI native through the guest ABI with JNIEnv*, jclass, and Java arguments in X0-X7; cover it in synthetic APK integration tests.
- [x] Add bounded JNI NewStringUTF/GetStringUTFLength/GetStringUTFChars/ReleaseStringUTFChars support with guest-memory-safe buffers and pointer-failure tests.
- [x] Add bounded guest `dlopen`/`dlsym`/`dlclose`/`dlerror` thunks for the preloaded module set and exercise them through an Android-targeted APK.
- [ ] Integrate the remaining Android/Bionic APIs, object/ART lifecycle, guest thread attachment and graphics boundaries.
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

This loads the root dependency closure, calls `JNI_OnLoad`, checks the returned JNI version and pending-exception state, looks up the exact `RegisterNatives` tuple, and invokes the registered guest function with `JNIEnv*` in X0, the opaque class handle in X1, and up to six Java arguments in X2-X7. The guest runtime also supplies `__system_property_get` from a configurable synthetic Android property profile (API level, release, ARM64 ABI, and virtual-device markers by default). Missing properties return an empty string; values obey Bionic's 92-byte `PROP_VALUE_MAX` including the NUL. This is a test profile, not the host's properties and not evidence that an actual Android device identity has been recreated. The guest `getauxval` shim is similarly conservative: it reports 4 KiB pages, only baseline FP/ASIMD HWCAP, zero HWCAP2, guest UID/GID 10000, and guest-resident `AT_PLATFORM`, `AT_EXECFN`, and 16-byte `AT_RANDOM`; unsupported tags return zero and set guest `errno` to `ENOENT`. The current bridge supports predeclared class names and static native methods. Its string surface is deliberately narrow: `NewStringUTF`, `GetStringUTFLength`, `GetStringUTFChars`, and `ReleaseStringUTFChars` keep byte sequences in opaque string handles and guest-owned temporary buffers, with bounded memory checks; the current smoke test uses ASCII, which is byte-identical in UTF-8 and modified UTF-8. It does not validate/convert arbitrary modified-UTF-8 or UTF-16, implement `NewString`, create a Java heap, or provide ART object semantics. ART, general Java method dispatch, instance construction, arrays, and arguments spilled to the stack remain unsupported. This executes actual guest code and is a validation utility, not a full application launcher.

The experimental runtime also registers guest-side `dlopen`, `dlsym`, `dlclose`, `dlerror`, and `dladdr` symbols under `libdl.so`. `dlopen` may only return handles for images already present in the initial dependency set; `dlsym` resolves an exported non-TLS, non-IFUNC symbol from the handle's dependency closure or the global preloaded namespace; `dlclose` is a no-op because images stay mapped for the runtime lifetime. `dladdr` reports the containing preloaded image and the nearest visible non-TLS/non-IFUNC exported symbol using guest-resident strings and the AArch64 guest address space. Unknown filenames/symbols return null and populate a guest-readable `dlerror` string. This is not dynamic loading: it does not load new files at runtime, relocate modules after startup, unload images, or implement arbitrary Android `libdl` semantics.

## Scope and trust

Keep the existing payload acquisition, compatibility and integrity behavior unchanged while the architecture work is developed. CPU instruction translation is only one component of an Android compatibility runtime.


The experimental native probe accepts a single APK, an `.apks` file directly, or multiple individual split APKs. It extracts only entries under `lib/arm64-v8a/`, checks that they are little-endian ELF64 AArch64 images, and rejects conflicting files with the same basename. Use `--library-dir` to add a directory of matching ARM64 Android runtime libraries (including when no APK positional argument is supplied). Explicit `--external-dependency SONAME` entries only allow a missing `DT_NEEDED` edge; they do not synthesize symbols or implement that library. The end-to-end APK test uses genuine cross-compiled test libraries in a synthetic APK and is not a Roblox compatibility claim.
