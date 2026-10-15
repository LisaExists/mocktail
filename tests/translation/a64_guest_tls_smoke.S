// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Real linker-produced PT_TLS fixture. The smoke harness only verifies the
// initial TLS image and zero-filled TLS BSS; it does not emulate Bionic TLS.
.text
.p2align 2
.global _start
.type _start, %function
_start:
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
