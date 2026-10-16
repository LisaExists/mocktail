// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Linker-produced AArch64 ELF exercising an ordinary call through the
// guest-provided __tls_get_addr thunk. This fixture is intentionally a
// preloaded-module test: tls_index.module is 1 and tls_index.offset is zero.
.text
.p2align 2
.global _start
.type _start, %function
_start:
    adrp x0, guest_tls_index
    add x0, x0, :lo12:guest_tls_index
    bl __tls_get_addr
    ldr x1, [x0]
    ldr x3, [x0, #8]
    mov x0, #42
    brk #0
.size _start, .-_start

.section .data,"aw",%progbits
.p2align 3
.global guest_tls_index
.hidden guest_tls_index
.type guest_tls_index, %object
guest_tls_index:
    .xword 1
    .xword 0
.size guest_tls_index, .-guest_tls_index

.section .tdata,"awT",%progbits
.p2align 3
.global guest_tls_initial_value
.type guest_tls_initial_value, %tls_object
guest_tls_initial_value:
    .xword 0x1122334455667788
.size guest_tls_initial_value, .-guest_tls_initial_value

.section .tbss,"awT",%nobits
.p2align 3
.global guest_tls_zero_value
.type guest_tls_zero_value, %tls_object
guest_tls_zero_value:
    .zero 16
.size guest_tls_zero_value, .-guest_tls_zero_value

.section .note.GNU-stack,"",%progbits
