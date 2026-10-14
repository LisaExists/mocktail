// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Minimal linker-produced AArch64 ET_DYN fixture for the Dynarmic smoke test.
// The pointer slot forces an R_AARCH64_RELATIVE relocation; the guest follows
// that pointer and loads the known value before the test harness stops at BRK.
.text
.p2align 2
.global _start
.type _start, %function
_start:
    adrp x2, pointer_slot
    add x2, x2, :lo12:pointer_slot
    ldr x2, [x2]
    ldr x1, [x2]
    mov x0, #42
    brk #0
.size _start, .-_start

.data
.p2align 3
pointer_slot:
    .xword smoke_value
smoke_value:
    .xword 42

.section .note.GNU-stack,"",%progbits
