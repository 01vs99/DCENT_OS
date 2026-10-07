/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Register-only final primary transition. No memory read/write or stack use.
 */
.section .text,"ax"
.global dcent_cpu_handoff
.type dcent_cpu_handoff,%function
dcent_cpu_handoff:
    mrs x2, CurrentEL
    cmp x2, #8
    b.ne .Lhandoff_cpu
    mrs x2, MIDR_EL1
    mov x3, #0xfff0
    movk x3, #0xff0f, lsl #16
    and x2, x2, x3
    mov x3, #0xd030
    movk x3, #0x410f, lsl #16
    cmp x2, x3
    b.ne .Lhandoff_cpu
    mrs x2, MPIDR_EL1
    mov x3, #0xffffff
    movk x3, #0xff, lsl #32
    tst x2, x3
    b.ne .Lhandoff_cpu
    tbnz x2, #24, .Lhandoff_cpu
    tbnz x2, #30, .Lhandoff_cpu
    mrs x2, DAIF
    and x2, x2, #0x3c0
    cmp x2, #0x3c0
    b.ne .Lhandoff_cpu
    mrs x2, HCR_EL2
    tbnz x2, #0, .Lhandoff_cpu
    tbnz x2, #34, .Lhandoff_cpu
    mrs x4, SCTLR_EL2
    tbnz x4, #25, .Lhandoff_cpu
    mrs x2, CNTFRQ_EL0
    mov x3, #0x3600
    movk x3, #0x16e, lsl #16
    cmp x2, x3
    b.ne .Lhandoff_timer
    mov x2, #0x01080000
    cmp x0, x2
    b.ne .Lhandoff_layout
    mov x2, #0x2000
    movk x2, #0x056a, lsl #16
    cmp x1, x2
    b.ne .Lhandoff_layout
    /* All refusals precede the first register mutation. A53 EL2 is NS.
     * HCR.RW prepares AArch64 EL1; no stage-2 or EL1 trapping is retained.
     * These local registers do not prove secure-monitor/secondary custody. */
    mov x16, x0
    mov x17, x1
    dsb sy
    mov x2, #0x80000000
    msr HCR_EL2, x2
    isb
    msr CNTHP_CTL_EL2, xzr
    msr CNTP_CTL_EL0, xzr
    msr CNTV_CTL_EL0, xzr
    msr CNTVOFF_EL2, xzr
    mov x2, #3
    msr CNTHCTL_EL2, x2
    isb
    /* Caller completed the cache sweep before this function. No load/store
     * can dirty or refill data here. Keep architectural RES1/other SCTLR bits
     * while clearing only current-EL MMU, data cache and instruction cache. */
    bic x4, x4, #1
    bic x4, x4, #4
    bic x4, x4, #0x1000
    dsb sy
    msr SCTLR_EL2, x4
    isb
    tlbi alle2
    dsb sy
    isb
    mov x0, x17
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x30, xzr
    br x16
.Lhandoff_cpu:
    mov w0, #156
    ret
.Lhandoff_timer:
    mov w0, #157
    ret
.Lhandoff_layout:
    mov w0, #158
    ret
.size dcent_cpu_handoff,.-dcent_cpu_handoff
