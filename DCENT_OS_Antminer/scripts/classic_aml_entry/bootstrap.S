/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Register-only first stage. No stack, context or constant data is dereferenced
 * before architectural identity of its complete owned span is established.
 */
.section .entry,"ax"
.global _start
.type _start,%function
_start:
    adr x10, _start
    mov x11, #0x07800000
    cmp x10, x11
    b.ne .Lbad_pc
    mrs x0, CurrentEL
    cmp x0, #8
    b.ne .Lbad_el
    /* On exact Cortex-A53 EL2 exists only in Non-secure state (DDI0500J
     * section3.2.6). MIDR is read at EL2, where EL1 virtual ID does not apply. */
    mrs x13, MIDR_EL1
    mov x14, #0xfff0
    movk x14, #0xff0f, lsl #16
    and x15, x13, x14
    mov x14, #0xd030
    movk x14, #0x410f, lsl #16
    cmp x15, x14
    b.ne .Lbad_cpu
    mrs x1, SCTLR_EL2
    mrs x2, HCR_EL2
    tbnz x2, #0, .Lbad_cpu
    tbnz x2, #34, .Lbad_cpu
    tbnz x1, #25, .Lbad_cpu
    tbz x1, #0, .Lcpu_ok
    tbz x1, #2, .Lbad_cpu
.Lcpu_ok:
    mrs x3, TCR_EL2
    mrs x4, S3_4_C2_C0_0
    mrs x5, MAIR_EL2
    mrs x6, PAR_EL1
    mrs x7, DAIF
    mov x8, sp
    mov x9, x30
    mrs x16, SPSel
    mrs x17, MPIDR_EL1
    msr DAIFSet, #15
    tbz x1, #0, .Lidentity_ok
    mov x14, #0x4516
    movk x14, #3, lsl #16
    cmp x3, x14
    b.ne .Lbad_profile
    mov x14, #0x0400
    movk x14, #0x440c, lsl #16
    movk x14, #0x00ff, lsl #32
    cmp x5, x14
    b.ne .Lbad_profile
    mov x10, #0x07800000
    mov x11, #0x2000
    movk x11, #2, lsl #16
    add x11, x11, x10
    /* Include code/rodata, descriptor, new context and stack: 34 pages. */
.Lidentity_page:
    at s1e2r, x10
    isb
    mrs x12, PAR_EL1
    tbnz x12, #0, .Lbad_identity
    and x14, x12, #0x000ffffffffff000
    cmp x14, x10
    b.ne .Lbad_identity
    lsr x14, x12, #56
    cmp x14, #255
    b.ne .Lbad_identity
    ubfx x14, x12, #7, #2
    cbnz x14, .Lbad_identity
    add x10, x10, #4096
    cmp x10, x11
    b.lo .Lidentity_page
    /* Read identity does not prove permission for the first context/stack
     * writes. Ask the architecture about both writable pages separately. */
    mov x10, #0x07820000
.Lwrite_page:
    at s1e2w, x10
    isb
    mrs x12, PAR_EL1
    tbnz x12, #0, .Lbad_identity
    and x14, x12, #0x000ffffffffff000
    cmp x14, x10
    b.ne .Lbad_identity
    lsr x14, x12, #56
    cmp x14, #255
    b.ne .Lbad_identity
    ubfx x14, x12, #7, #2
    cbnz x14, .Lbad_identity
    add x10, x10, #4096
    cmp x10, x11
    b.lo .Lwrite_page
.Lidentity_ok:
    msr PAR_EL1, x6
    mov x14, #0x07820000
    /* The first memory access of this entry is below. */
    stp x0, x1, [x14]
    stp x2, x3, [x14, #16]
    stp x4, x5, [x14, #32]
    stp x13, x17, [x14, #48]
    stp x8, x9, [x14, #64]
    stp x7, x16, [x14, #80]
    stp x6, xzr, [x14, #96]
    str x19, [x14, #112]
    mov x19, x14
    mov x15, #0x2000
    add x15, x15, x14
    mov sp, x15
    mov x0, x14
    bl dcent_bootstrap_validated
    ldp x8, x9, [x19, #64]
    ldp x7, x16, [x19, #80]
    ldr x6, [x19, #96]
    ldr x19, [x19, #112]
    msr PAR_EL1, x6
    msr SPSel, x16
    mov sp, x8
    msr DAIF, x7
    mov x30, x9
    ret
.Lbad_profile:
    mov w0, #92
    b .Lrestore_refusal
.Lbad_identity:
    mov w0, #93
.Lrestore_refusal:
    msr PAR_EL1, x6
    msr DAIF, x7
    mov x30, x9
    ret
.Lbad_pc:
    mov w0, #89
    ret
.Lbad_el:
    mov w0, #90
    ret
.Lbad_cpu:
    mov w0, #91
    ret
.size _start,.-_start
