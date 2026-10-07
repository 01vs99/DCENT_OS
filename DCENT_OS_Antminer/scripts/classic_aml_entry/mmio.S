/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Internal ordered MMIO backend. Preconditions are documented in mmio.h.
 */
.section .text,"ax"
.global dcent_mmio_begin
.type dcent_mmio_begin,%function
dcent_mmio_begin:
    mrs x3, CurrentEL
    cmp x3, #8
    b.ne .Lrefused
    mrs x3, DAIF
    and x3, x3, #0x3c0
    cmp x3, #0x3c0
    b.ne .Lrefused
    mrs x3, VBAR_EL2
    adr x4, dcent_mmio_vectors
    cmp x3, x4
    b.eq .Lrefused
    mov x5, x3
    ldr x3, [x0, #8]
    cbnz x3, .Lrefused
    stp xzr, xzr, [x0, #16]
    stp xzr, xzr, [x0, #32]
    mrs x3, ISR_EL1
    tbnz x3, #8, .Lbegin_serror
    str x5, [x0]
    msr VBAR_EL2, x4
    isb
    mov x3, #1
    str x3, [x0, #8]
    mov w0, #1
    ret
.Lbegin_serror:
    mov x3, #2
    str x3, [x0, #40]
    b .Lrefused
.size dcent_mmio_begin,.-dcent_mmio_begin

.global dcent_mmio_end
.type dcent_mmio_end,%function
dcent_mmio_end:
    mrs x3, VBAR_EL2
    adr x4, dcent_mmio_vectors
    cmp x3, x4
    b.ne .Lrefused
    ldr x3, [x0, #8]
    sub x3, x3, #1
    cmp x3, #1
    b.hi .Lrefused
    ldr x3, [x0]
    msr VBAR_EL2, x3
    isb
    str xzr, [x0, #8]
    mov w0, #1
    ret
.size dcent_mmio_end,.-dcent_mmio_end

.global dcent_mmio_read32
.type dcent_mmio_read32,%function
dcent_mmio_read32:
    mrs x3, VBAR_EL2
    adr x4, dcent_mmio_vectors
    cmp x3, x4
    b.ne .Lrefused
    ldr x3, [x0, #8]
    cmp x3, #1
    b.ne .Lrefused
    tst x1, #3
    b.ne .Lrefused
    mrs x4, ISR_EL1
    tbnz x4, #8, .Lserror
.Lread_access:
    ldr w3, [x1]
.Lread_barrier:
    dsb sy
    isb
    mrs x4, ISR_EL1
    tbnz x4, #8, .Lserror
    str w3, [x2]
    mov w0, #1
    ret
.size dcent_mmio_read32,.-dcent_mmio_read32

.global dcent_mmio_write32
.type dcent_mmio_write32,%function
dcent_mmio_write32:
    mrs x3, VBAR_EL2
    adr x4, dcent_mmio_vectors
    cmp x3, x4
    b.ne .Lrefused
    ldr x3, [x0, #8]
    cmp x3, #1
    b.ne .Lrefused
    tst x1, #3
    b.ne .Lrefused
    mrs x4, ISR_EL1
    tbnz x4, #8, .Lserror
.Lwrite_access:
    str w2, [x1]
.Lwrite_barrier:
    dsb sy
    isb
    mrs x4, ISR_EL1
    tbnz x4, #8, .Lserror
    mov w0, #1
    ret
.size dcent_mmio_write32,.-dcent_mmio_write32
.Lserror:
    mov x3, #2
    str x3, [x0, #8]
    str x3, [x0, #40]
.Lrefused:
    mov w0, #0
    ret

/* No stack access occurs in the fault vector. Only current-EL synchronous
 * slots may recover, and only from the exact internal load/store/barriers.
 * Other exceptions stop in this private vector rather than resume an entry. */
.balign 2048
.global dcent_mmio_vectors
dcent_mmio_vectors:
    b .Ldata_abort
    .space 124
.rept 3
    b .Lunexpected_exception
    .space 124
.endr
    b .Ldata_abort
    .space 124
.rept 11
    b .Lunexpected_exception
    .space 124
.endr
.Ldata_abort:
    mrs x16, ESR_EL2
    lsr x17, x16, #26
    cmp x17, #0x25
    b.ne .Lunexpected_exception
    mrs x17, ELR_EL2
    adr x15, .Lread_access
    cmp x17, x15
    b.eq .Lrecord_abort
    adr x15, .Lwrite_access
    cmp x17, x15
    b.eq .Lrecord_abort
    adr x15, .Lread_barrier
    cmp x17, x15
    b.eq .Lrecord_abort
    adr x15, .Lwrite_barrier
    cmp x17, x15
    b.ne .Lunexpected_exception
.Lrecord_abort:
    str x16, [x0, #16]
    str x17, [x0, #24]
    mrs x15, FAR_EL2
    str x15, [x0, #32]
    mov x15, #1
    str x15, [x0, #40]
    mov x15, #2
    str x15, [x0, #8]
    adr x17, .Lrefused
    msr ELR_EL2, x17
    eret
.Lunexpected_exception:
    msr DAIFSet, #15
1:  wfe
    b 1b
