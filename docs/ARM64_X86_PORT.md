# ARM64 Android client on x86-64: port notes

## Status

This branch is an investigation, not a working ARM64-on-x86 runtime. The APK preflight script is diagnostic only. It does not load native code, modify an APK, disable signature checks, or bypass Roblox integrity or anti-cheat controls.

## Source-level finding

Mocktail's normal process is built for the host architecture. The guest ABI constants in \`include/compat/guest_abi.h\` currently follow the compile-time host architecture, and the native Android linker is compiled into that process. An x86-64 process cannot call AArch64 machine code directly, even if the APK's ABI checks are changed to accept \`arm64-v8a\`.

The first step is to run \`python tools/arm64-x86-preflight.py /path/to/Delta.apk\` against the *actual* locally installed package. If Delta is distributed as split APKs, inspect each APK in the set individually. The tool checks ZIP entries and ELF headers; it cannot verify APK v2/v3/v4 signing, runtime compatibility, or whether an executor works.

## Execution models to evaluate

1. **Whole guest process:** run an AArch64 userspace under a user-mode translator. This also needs compatible ARM64 runtime dependencies and a graphics plan; x86-64 SDL/Vulkan libraries cannot be loaded into the AArch64 guest process.
2. **In-process guest execution:** add an AArch64 CPU emulator/JIT and an ELF loader, guest virtual memory, AArch64 relocations, guest syscalls, Bionic/TLS/thread support, and ABI thunks for guest-to-host callbacks. Passing host function pointers directly to AArch64 code is invalid.
3. **Separate guest worker:** isolate ARM64 code in a guest process and bridge JNI, input, audio, and graphics through IPC. This is a major lifecycle/protocol change, but keeps guest pointers and calling conventions out of the x86-64 process.

A CPU translator alone solves none of the JNI, Bionic, Android API, or graphics boundaries. Before choosing a route, we should compare a minimal ARM64 ELF smoke test against the exact guest interface Mocktail needs.

## Milestones

- [x] Add a dependency-free tool to inspect packaged native ABIs and verify each library's ELF machine field.
- [ ] Capture preflight output for the exact Delta package and identify whether it is monolithic or split.
- [ ] Build this fork unchanged on x86-64 and save configure/build logs.
- [ ] Select an execution model and prove it with a small, non-Roblox AArch64 ELF.
- [ ] Add guest-memory, loader, and calling-convention support; don't enable ARM64 payload selection before this exists.
- [ ] Integrate and test JNI, Android ABI, thread/TLS, and graphics bridges.
- [ ] Validate against an unmodified, locally supplied ARM64 test payload before evaluating any third-party modified client.

## Integrity and trust boundary

Keep Mocktail's existing payload trust and compatibility checks during this work. An architecture port should not silently accept arbitrary packages or remove authenticity/integrity checks; changes to package trust should be designed and reviewed separately.
