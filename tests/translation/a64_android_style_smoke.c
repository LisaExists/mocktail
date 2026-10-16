// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Compiled for aarch64-linux-android without a sysroot/libc. This validates
// Android-targeted ELF metadata and relocation packing, not Bionic API coverage.
static int guest_state = 41;
static int *const guest_state_pointer = &guest_state;

__attribute__((visibility("default")))
int guest_android_abi_smoke(int addend) {
  return *guest_state_pointer + addend;
}
