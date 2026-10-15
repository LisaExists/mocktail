// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Real linker-produced PT_TLS fixture. The experimental smoke harness lays out
// the module's initialized TLS and BSS in per-thread guest memory and publishes
// the guest TP through Dynarmic's TPIDR_EL0 state. This is not a complete Bionic TCB/DTV.
.text
.p2align 2
.global _start
.type _start, %function
_start:
    mrs x2, tpidr_el0
    ldr x1, [x2, #16]
    ldr x3, [x2, #24]
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
