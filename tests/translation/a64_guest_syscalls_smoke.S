// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// AArch64 SVC test: anonymous mmap, read/write guest memory, munmap. On success
// the guest stops at BRK with X0 and X1 both containing 42.
.text
.p2align 2
.global _start
.type _start, %function
_start:
    mov x0, #0
    mov x1, #4096
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0

    mov x9, x0
    mov x10, #42
    str x10, [x9]
    ldr x11, [x9]

    mov x0, x9
    mov x1, #4096
    mov x8, #215
    svc #0

    mov x0, #0
    mov x8, #214
    svc #0
    mov x12, x0

    add x0, x12, #4096
    mov x8, #214
    svc #0
    mov x10, #42
    str x10, [x12]
    ldr x13, [x12]

    mov x0, x12
    mov x8, #214
    svc #0
    mov x0, x13
    mov x1, x13
    brk #0
.size _start, .-_start

.section .note.GNU-stack,"",%progbits
