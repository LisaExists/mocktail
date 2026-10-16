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

A sparse page-based guest memory layer maps ELF images and anonymous memory with read/write/execute permissions. It provides first-fit anonymous mapping, whole-range permission changes, Linux-style unmapping that tolerates holes, and a bounded `brk` heap in guest-only memory. An explicit AArch64 syscall dispatcher handles anonymous private/shared `mmap`, `mprotect`, `munmap`, `brk`, `exit`, and `exit_group`; it does not forward arbitrary guest syscalls to the host, and file-backed mappings remain unsupported until a guest file-descriptor layer exists. The Dynarmic smoke harness maps every module returned by the two-pass loader into one guest address space and supplies an anonymous stack. Cross-compiled test shared objects exercise a root entry point that calls into a dependency, an exported function called through a guest return trap, and guest `svc #0` calls that allocate, access, and release anonymous memory. A small, explicit libc subset routes through guest SVC stubs rather than host function pointers.

The prototype lays out each loaded module's `PT_TLS` template at an aligned static offset from a guest thread pointer, maps an independent initialized TLS region per guest thread, and exposes that guest address through Dynarmic's emulated `TPIDR_EL0`. Cross-compiled smoke libraries now exercise TP-relative access, a static TLSDESC resolver, and an ordinary guest call through a dynamic relocation to `__tls_get_addr`. That thunk resolves the standard two-word `tls_index` through guest memory to a preloaded module's per-thread block. These paths only support modules included before TLS preparation; `dlopen`-style dynamic allocation, full Android/Bionic TCB/DTV semantics, and guest pthread scheduling remain gaps. Constructor execution remains an isolated smoke-harness feature rather than automatic Android process startup. Broader syscall coverage, JNI, Android linker namespaces, remaining symbol-version/interposition rules, and graphics interop remain gaps.

When `aarch64-linux-gnu-gcc` is installed, CMake also generates a genuine AArch64 `.so` fixture and sends it through the ELF loader and Dynarmic, stopping at a controlled `BRK`. The dedicated branch workflow installs this cross-toolchain so that the real-ELF path is tested in CI. This demonstrates basic code execution from a linker-produced guest image, not compatibility with the Android linker or the Roblox client.

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
- [ ] Confirm the new branch CI succeeds on a clean x86-64 Linux host.
- [x] Build a two-pass multi-image dependency resolver for catalogued ET_DYN objects with exact GNU symbol version/provider matching.
- [x] Parse bounded GNU `DT_VERNEED`/`DT_VERDEF` and retain versioned exports with exact version/provider matching.
- [ ] Validate symbol-version behavior against real Android ARM64 package libraries, including default-version interposition rules.
- [x] Add sparse page-based guest mappings with basic read/write/execute permissions and an anonymous stack mapping for the CPU smoke guest.
- [x] Add bounded guest `mmap`-style address allocation, `mprotect` permissions, Linux-style `munmap` support that tolerates unmapped holes, and a private `brk` heap.
- [x] Add an allow-listed AArch64 syscall dispatcher for anonymous memory operations and guest process exit, with synthetic and linker-produced guest tests.
- [x] Add a bounded two-pass guest module-set loader with `DT_NEEDED` closure discovery, non-overlapping image placement, unversioned export indexing, and dependency relocation tests.
- [ ] Extend guest mappings with guard pages and memory synchronization.
- [x] Add explicit guest-to-host SVC thunks and a bounded guest-safe libc subset; expand coverage based on real library imports.
- [ ] Integrate and test the Android/Bionic and graphics boundaries.
- [ ] Validate the integration against a minimal ARM64 shared library and ordinary JNI/native calls before attempting full Roblox startup.

## Scope and trust

Keep the existing payload acquisition, compatibility and integrity behavior unchanged while the architecture work is developed. CPU instruction translation is only one component of an Android compatibility runtime.
