/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef DCENT_CLASSIC_BOOTSTRAP_H
#define DCENT_CLASSIC_BOOTSTRAP_H
#include "preflight.h"
struct dcent_bootstrap_context {
  struct dcent_context cpu;
  u64 midr, mpidr, caller_sp, caller_lr, caller_daif, caller_spsel, caller_par;
  u64 reserved, caller_x19;
};
_Static_assert(sizeof(struct dcent_bootstrap_context)==120,"bootstrap context size");
/* Defined by a separately reviewed composition. A test implementation returns;
 * no candidate command or mining-kernel jump is supplied by this interface. */
int dcent_bootstrap_validated(struct dcent_bootstrap_context *context);
#endif
