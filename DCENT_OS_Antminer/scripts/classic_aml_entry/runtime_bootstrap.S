/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Keep the reviewed register/translation bootstrap unchanged. Its single call
 * reaches this assembly boundary, which finishes every C epilogue BEFORE cache
 * cleaning. Late terminal refusals unwind using only loads and register writes.
 */
#define dcent_bootstrap_validated dcent_runtime_then_finish
#include "bootstrap.S"
#undef dcent_bootstrap_validated

.text
.global dcent_runtime_then_finish
.type dcent_runtime_then_finish,%function
dcent_runtime_then_finish:
    stp x19, x30, [sp, #-16]!
    bl dcent_bootstrap_validated
    cbnz w0, .Lruntime_return
    /* Complete admitted descriptor is 256 bytes; its cache snapshot follows. */
    mov x0, #0x0500
    movk x0, #0x0782, lsl #16
    bl dcent_entry_finish
.Lruntime_return:
    ldp x19, x30, [sp], #16
    ret
.size dcent_runtime_then_finish,.-dcent_runtime_then_finish
