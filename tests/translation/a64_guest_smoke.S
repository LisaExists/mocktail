// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Intentionally tiny real AArch64 ET_DYN fixture for running through Dynarmic.
// BRK is the test harness' deterministic stop instruction.
.text
.p2align 2
.global _start
.type _start, %function
_start:
    mov x0, #42
    sub sp, sp, #16
    str x0, [sp]
    ldr x1, [sp]
    add sp, sp, #16
    brk #0
.size _start, .-_start

.section .note.GNU-stack,"",%progbits
