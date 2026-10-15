// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Calls the unresolved libc strlen import through an AArch64 PLT relocation.
// The host-call bridge should resolve strlen to a guest SVC thunk.
.text
.p2align 2
.global _start
.type _start, %function
_start:
    adrp x0, .Lmessage
    add x0, x0, :lo12:.Lmessage
    bl strlen
    cmp x0, #5
    b.ne .Lfailed
    mov x0, #42
    mov x1, #42
    brk #0
.Lfailed:
    mov x0, #1
    mov x1, #0
    brk #0
.size _start, .-_start

.section .rodata
.Lmessage:
    .asciz "hello"

.section .note.GNU-stack,"",%progbits
