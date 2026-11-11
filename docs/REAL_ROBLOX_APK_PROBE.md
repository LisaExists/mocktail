# Real Roblox ARM64 probe runbook

The branch workflow can run a bounded diagnostic against the pinned Roblox Android package (version 2.743.1136, versionCode 18934).

## Triggering the diagnostic

The workflow's `workflow_dispatch` input `run_real_roblox_apk_smoke` enables the probe when started manually.

A push to `experimental/roblox-arm-translation` also enables the same diagnostic when all of the following are true:

- The commit changes a path watched by `.github/workflows/arm64-translation.yml`.
- The commit message contains the exact marker `[real-apk-smoke]`.

This push-trigger path is useful when a workflow-dispatch client is unavailable. It uses the normal branch push workflow and does not require changing workflow permissions.

## What the diagnostic does

1. Downloads the pinned base APK and ARM64 split.
2. Verifies both SHA-256 hashes before parsing them.
3. Runs ABI preflight and the native ELF/dependency audit.
4. Attempts dependency-ordered constructors and `JNI_OnLoad` inside the Dynarmic guest, with a 180-second wall-clock limit, a bounded instruction budget, and a 4 GiB guest-memory ceiling.
5. Uploads `real-roblox-arm64-probe` with the guest log, preflight report, ELF audit log, and JSON audit.

The probe step is deliberately non-gating while compatibility work is ongoing. A green workflow only means the diagnostic job completed; it does not mean the guest initialization succeeded. Inspect the probe's own exit status and logs.

## Success criteria

Do not claim Roblox compatibility from APK extraction, ELF parsing, dependency resolution, synthetic JNI tests, or a green CI job alone. The first real-package milestone is a zero exit status from the guest probe after the actual `libroblox.so` constructors and `JNI_OnLoad` complete.

Even that milestone is not a playable application. ART behavior, Java framework services, lifecycle, input, audio, graphics/surface integration, and the rest of the package's runtime dependencies must still be validated before claiming end-to-end launch support.

Never add success-shaped Android API stubs just to make the probe advance. Missing behavior should remain an explicit compatibility failure until a safe implementation or a deliberately supported headless contract exists.
