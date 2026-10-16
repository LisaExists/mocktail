// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Compiled for aarch64-linux-android without a sysroot/libc. The default-visible
// data symbol is intentionally preemptible so Android-targeted PIC needs a
// symbol-based dynamic relocation in addition to any relative pointer fixes.
__attribute__((visibility("default")))
int guest_android_value = 41;

__attribute__((visibility("default")))
int guest_android_abi_smoke(int addend) {
  return guest_android_value + addend;
}
