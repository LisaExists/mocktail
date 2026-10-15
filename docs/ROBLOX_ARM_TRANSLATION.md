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

The bounded ELF64 loader maps AArch64 `PT_LOAD` segments and zero-initializes BSS, extracts `DT_NEEDED`/`DT_SONAME`, supports RELA relocations (`RELATIVE`, `ABS64`, `GLOB_DAT`, and `JUMP_SLOT`), Android APS2-packed RELA, and RELR pointer relocations. SysV/GNU hash metadata bounds symbol lookup. Undefined symbols must be resolved by an explicit callback that returns a guest address; the loader never casts a guest pointer to a host pointer. Symbol-version enforcement, TLS symbols, IFUNCs, and text relocations remain unsupported and fail closed.

The experimental guest module loader now accepts a trusted catalogue of AArch64 shared-object bytes, walks the root object's `DT_NEEDED` closure, checks missing/ambiguous dependencies, assigns distinct guest address ranges, collects externally visible unversioned exports, and repeats the load with relocations resolved against the complete module set. Dependencies implemented by a guest thunk/runtime layer can be allow-listed explicitly, but every imported symbol must still resolve to a guest address. The ELF loader also extracts and validates `DT_INIT`, `DT_INIT_ARRAY`, `DT_FINI_ARRAY`, and `DT_FINI` after relocations. The module-set loader computes a dependency-first constructor order and reverse finalizer order, including cycle-safe graph traversal. These callbacks are metadata only for now; it does not execute them. This two-pass prototype is not a replacement for Android's dynamic linker: namespace policy, versioned symbols, TLS/TLSDESC, IFUNC, dependency-ordered constructor execution, Android linker namespaces, and Bionic system-library behavior are not implemented.

A sparse page-based guest memory layer maps ELF images and anonymous memory with read/write/execute permissions. The Dynarmic smoke harness maps every module returned by the two-pass loader into one guest address space and supplies an anonymous stack. Cross-compiled test shared objects now exercise both a root entry point that calls into a dependency and a separately exported function called through a guest return trap. These tests cover basic relocation and control flow across modules. Constructor pointer metadata is validated, but invoking it in dependency order, TLS, Android/Bionic syscall behavior, JNI, Android linker namespaces, symbol-version semantics, and graphics interop remain unimplemented.

When `aarch64-linux-gnu-gcc` is installed, CMake also generates a genuine AArch64 `.so` fixture and sends it through the ELF loader and Dynarmic, stopping at a controlled `BRK`. The dedicated branch workflow installs this cross-toolchain so that the real-ELF path is tested in CI. This demonstrates basic code execution from a linker-produced guest image, not compatibility with the Android linker or the Roblox client.

## Architecture options to evaluate

1. **In-process guest execution:** Dynarmic JIT + guest address-space management + an AArch64 ELF loader + explicit ABI thunks for callbacks into native x86-64 code. Guest pointers and host pointers must never be treated as interchangeable.
2. **Separate guest process:** an ARM64 guest userspace under a user-mode translator, with IPC for lifecycle, input, audio and graphics. This provides stronger ABI isolation but significantly changes the application architecture.

The first milestone is to build the CPU smoke target on x86-64. Do not enable ARM64 package selection in Mocktail's normal runtime until the guest-loader and ABI bridge have been designed and tested.

## Milestones

- [x] Add an APK native-ABI/ELF preflight tool.
- [x] Add tests for ELF identification, ABI mismatch reporting and split-package detection.
- [x] Add an optional, pinned Dynarmic dependency and an isolated AArch64 CPU smoke target.
- [x] Add a bounded ELF64 little-endian AArch64 loader for PT_LOAD segments, including BSS zero-fill, ET_DYN load bias, entry-point validation and read/write bounds checks.
- [x] Run the Dynarmic smoke instructions from a synthetic ELF image instead of a raw byte array, including guest stack stores and loads.
- [x] Parse DT_NEEDED/DT_SONAME and apply bounded AArch64 RELATIVE, ABS64, GLOB_DAT and JUMP_SLOT RELA relocations.
- [x] Add bounded SysV/GNU hash-based symbol counts and explicit undefined-symbol resolver callbacks.
- [x] Extract and validate dynamic initializer/finalizer callbacks after relocations; executing them is still pending.
- [x] Compute dependency-first module initialization order and reverse finalization order, while leaving callback execution disabled.
- [x] Fail closed for unsupported/packed relocation formats, symbol versions, TLS symbols, IFUNCs and text relocations.
- [x] Add branch-specific CI for the synthetic ELF and Dynarmic tests.
- [x] Add an optional cross-compiled AArch64 shared-object fixture and execute it through the loader/JIT path.
- [ ] Confirm the new branch CI succeeds on a clean x86-64 Linux host.
- [x] Build a minimal two-pass multi-image dependency resolver for catalogued ET_DYN objects (unversioned exports only).
- [ ] Add Android symbol-versioning conventions and confirm dependency resolution against the actual ARM64 package libraries.
- [x] Add sparse page-based guest mappings with basic read/write/execute permissions and an anonymous stack mapping for the CPU smoke guest.
- [x] Add a bounded two-pass guest module-set loader with `DT_NEEDED` closure discovery, non-overlapping image placement, unversioned export indexing, and dependency relocation tests.
- [ ] Extend guest mappings with guard pages, heap allocation, per-thread TLS and memory synchronization.
- [ ] Add explicit guest-to-host calling conventions, syscalls, TLS and guest-thread scheduling.
- [ ] Integrate and test the Android/Bionic and graphics boundaries.
- [ ] Validate the integration against a minimal ARM64 shared library and ordinary JNI/native calls before attempting full Roblox startup.

## Scope and trust

Keep the existing payload acquisition, compatibility and integrity behavior unchanged while the architecture work is developed. CPU instruction translation is only one component of an Android compatibility runtime.
