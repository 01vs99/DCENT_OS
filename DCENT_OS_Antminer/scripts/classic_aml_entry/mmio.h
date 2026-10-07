/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef DCENT_CLASSIC_MMIO_H
#define DCENT_CLASSIC_MMIO_H
#include "preflight.h"
struct dcent_mmio_context {
  u64 prior_vbar, active, fault_esr, fault_elr, fault_far, fault_kind;
};
_Static_assert(sizeof(struct dcent_mmio_context)==48,"MMIO context size");
/* Internal backend only. Composition must first establish exact A53 EL2,
 * accessible identity-mapped Device-nGnRnE target registers, owned normal-memory
 * context/output pointers, DAIF masking and absence of competing writers.
 * active:0 inactive,1 admitted,2 poisoned after an access/pending-SError fault.
 * Only one active context is admitted: begin refuses when these private vectors
 * are already installed; accesses/end require their VBAR ownership unchanged.
 * fault_kind:0 none,1 synchronous data abort,2 pending SError observed.
 * These functions confer no board, storage command or publication authority. */
int dcent_mmio_begin(struct dcent_mmio_context *context);
int dcent_mmio_end(struct dcent_mmio_context *context);
int dcent_mmio_read32(void *context,u64 address,u32 *value);
int dcent_mmio_write32(void *context,u64 address,u32 value);
#endif
