/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Last returning call boundary. All stack writes precede cache maintenance.
 */
.section .text,"ax"
.global dcent_entry_finish
.type dcent_entry_finish,%function
dcent_entry_finish:
    stp x19,x30,[sp,#-16]!
    bl dcent_cache_clean
    cbnz w0,.Lfinish_refused
    /* Only reads after the final clean/invalidate sweep. The terminal leaf
     * performs no data access and either refuses before transition or branches
     * directly to the already authenticated kernel with its fixed final FDT. */
    ldp x19,x30,[sp],#16
    mov x0,#0x01080000
    mov x1,#0x2000
    movk x1,#0x056a,lsl #16
    b dcent_cpu_handoff
.Lfinish_refused:
    ldp x19,x30,[sp],#16
    ret
.size dcent_entry_finish,.-dcent_entry_finish
