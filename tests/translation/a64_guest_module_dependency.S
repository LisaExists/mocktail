// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Dependency fixture exports one ordinary AArch64 function.
.text
.p2align 2
.global guest_add_one
.type guest_add_one, %function
guest_add_one:
    add x0, x0, #1
    ret
.size guest_add_one, .-guest_add_one

.p2align 2
.global guest_spin_forever
.type guest_spin_forever, %function
guest_spin_forever:
    b guest_spin_forever
.size guest_spin_forever, .-guest_spin_forever

.section .note.GNU-stack,"",%progbits
