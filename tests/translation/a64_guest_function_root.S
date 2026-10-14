// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// ET_DYN shared-object fixture with no process entry point. Tests invoking an
// exported native function using the AArch64 procedure-call convention.
.text
.p2align 2
.global guest_exported_entry
.type guest_exported_entry, %function
guest_exported_entry:
    bl guest_add_one
    ret
.size guest_exported_entry, .-guest_exported_entry

.section .note.GNU-stack,"",%progbits
