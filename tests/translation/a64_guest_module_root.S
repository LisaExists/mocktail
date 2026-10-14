// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Calls guest_add_one through a linker-generated PLT entry. The harness
// expects X0 and X1 to both contain 42 when BRK stops execution.
.text
.p2align 2
.global _start
.type _start, %function
_start:
    mov x0, #41
    bl guest_add_one
    mov x1, x0
    mov x0, #42
    brk #0
.size _start, .-_start

.section .note.GNU-stack,"",%progbits
