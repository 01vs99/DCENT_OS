/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Bounded A53 cache maintenance; register-only and returning for desk probes.
 */
.section .text,"ax"
.global dcent_cache_clean
.type dcent_cache_clean,%function
dcent_cache_clean:
    mrs x6, CurrentEL
    cmp x6, #8
    b.ne .Lbad_cpu
    mrs x6, MIDR_EL1
    mov x7, #0xfff0
    movk x7, #0xff0f, lsl #16
    and x6, x6, x7
    mov x7, #0xd030
    movk x7, #0x410f, lsl #16
    cmp x6, x7
    b.ne .Lbad_cpu
    mrs x6, DAIF
    and x6, x6, #0x3c0
    cmp x6, #0x3c0
    b.ne .Lbad_cpu
    mrs x6, CTR_EL0
    and x7, x6, #15
    cmp x7, #4
    b.ne .Lbad_geometry
    ubfx x7, x6, #16, #4
    cmp x7, #4
    b.ne .Lbad_geometry
    mrs x6, CLIDR_EL1
    and x7, x6, #0x1fffff
    cmp x7, #0x23
    b.ne .Lbad_geometry
    ubfx x7, x6, #24, #3
    cmp x7, #2
    b.ne .Lbad_geometry
    mrs x9, CSSELR_EL1
    msr CSSELR_EL1, xzr
    isb
    mrs x7, CCSIDR_EL1
    mov x6, #2
    msr CSSELR_EL1, x6
    isb
    mrs x8, CCSIDR_EL1
    msr CSSELR_EL1, x9
    isb
    /* A53 L1D:64-byte lines,4 ways,8..64KiB; L2:64-byte lines,
     *16 ways,128KiB..2MiB. Both geometries are checked before any DC/IC. */
    lsr x6, x7, #32
    cbnz x6, .Lbad_geometry
    and x6, x7, #7
    cmp x6, #2
    b.ne .Lbad_geometry
    ubfx x6, x7, #3, #10
    cmp x6, #3
    b.ne .Lbad_geometry
    ubfx x10, x7, #13, #15
    add x11, x10, #1
    cmp x11, #32
    b.lo .Lbad_geometry
    cmp x11, #256
    b.hi .Lbad_geometry
    tst x10, x11
    b.ne .Lbad_geometry
    lsr x6, x8, #32
    cbnz x6, .Lbad_geometry
    and x6, x8, #7
    cmp x6, #2
    b.ne .Lbad_geometry
    ubfx x6, x8, #3, #10
    cmp x6, #15
    b.ne .Lbad_geometry
    ubfx x10, x8, #13, #15
    add x11, x10, #1
    cmp x11, #128
    b.lo .Lbad_geometry
    cmp x11, #2048
    b.hi .Lbad_geometry
    tst x10, x11
    b.ne .Lbad_geometry
    /* Structure readability comes from the outer owned-memory proof. All
     * ranges must be nonempty,64-byte aligned starts,ordered and below256MiB. */
    mov x17, x0
    ldp x0, x1, [x17]
    ldp x2, x3, [x17, #16]
    ldp x4, x5, [x17, #32]
    orr x6, x0, x2
    orr x6, x6, x4
    tst x6, #63
    b.ne .Lbad_ranges
    cbz x0, .Lbad_ranges
    cmp x0, x1
    b.hs .Lbad_ranges
    cmp x1, x4
    b.hi .Lbad_ranges
    cmp x4, x5
    b.hs .Lbad_ranges
    cmp x5, x2
    b.hi .Lbad_ranges
    cmp x2, x3
    b.hs .Lbad_ranges
    mov x6, #0x10000000
    cmp x3, x6
    b.hi .Lbad_ranges
    dsb sy
    mov x11, x0
.Lkernel_va:
    dc cvac, x11
    add x11, x11, #64
    cmp x11, x1
    b.lo .Lkernel_va
    mov x11, x2
.Linitrd_va:
    dc cvac, x11
    add x11, x11, #64
    cmp x11, x3
    b.lo .Linitrd_va
    mov x11, x4
.Lfdt_va:
    dc cvac, x11
    add x11, x11, #64
    cmp x11, x5
    b.lo .Lfdt_va
    dsb sy
    ubfx x12, x7, #13, #15
.Ll1_set:
    mov x13, #3
.Ll1_way:
    lsl x15, x13, #30
    orr x15, x15, x12, lsl #6
    dc cisw, x15
    subs x13, x13, #1
    b.ge .Ll1_way
    subs x12, x12, #1
    b.ge .Ll1_set
    dsb sy
    ubfx x12, x8, #13, #15
.Ll2_set:
    mov x13, #15
.Ll2_way:
    lsl x15, x13, #28
    orr x15, x15, x12, lsl #6
    orr x15, x15, #2
    dc cisw, x15
    subs x13, x13, #1
    b.ge .Ll2_way
    subs x12, x12, #1
    b.ge .Ll2_set
    dsb sy
    ic ialluis
    dsb sy
    isb
    mov w0, #0
    ret
.Lbad_cpu:
    mov w0, #128
    ret
.Lbad_geometry:
    mov w0, #129
    ret
.Lbad_ranges:
    mov w0, #130
    ret
.size dcent_cache_clean,.-dcent_cache_clean
