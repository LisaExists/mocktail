// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Linker-produced AArch64 TLSDESC fixture. The runtime replaces the dynamic
// TLSDESC descriptor with a static guest resolver + TP-relative offset.
.text
.p2align 2
.global _start
.type _start, %function
_start:
    adrp x0, :tlsdesc:guest_tls_initial_value
    ldr x1, [x0, #:tlsdesc_lo12:guest_tls_initial_value]
    add x0, x0, #:tlsdesc_lo12:guest_tls_initial_value
    .tlsdesccall guest_tls_initial_value
    blr x1
    mrs x2, tpidr_el0
    add x2, x2, x0
    ldr x1, [x2]

    adrp x0, :tlsdesc:guest_tls_zero_value
    ldr x4, [x0, #:tlsdesc_lo12:guest_tls_zero_value]
    add x0, x0, #:tlsdesc_lo12:guest_tls_zero_value
    .tlsdesccall guest_tls_zero_value
    blr x4
    mrs x2, tpidr_el0
    add x2, x2, x0
    ldr x3, [x2]

    mov x0, #42
    brk #0
.size _start, .-_start

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
