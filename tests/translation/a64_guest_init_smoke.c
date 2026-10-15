// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// This tiny C shared object deliberately avoids libc calls. Its initializer
// sets guest data to 41; _start returns 42 only if the runtime executes
// DT_INIT_ARRAY before entering the module.
#include <stdint.h>

__attribute__((visibility("hidden"))) volatile uint64_t guest_init_state;

__attribute__((constructor, used)) static void guest_initializer(void) {
  guest_init_state = 41;
}

__attribute__((naked, noreturn, used)) void _start(void) {
  __asm__ volatile(
      "adrp x9, guest_init_state\n\t"
      "add x9, x9, :lo12:guest_init_state\n\t"
      "ldr x10, [x9]\n\t"
      "add x0, x10, #1\n\t"
      "mov x1, x0\n\t"
      "brk #0\n\t");
}
