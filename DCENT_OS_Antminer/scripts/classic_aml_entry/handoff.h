/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef DCENT_CLASSIC_HANDOFF_H
#define DCENT_CLASSIC_HANDOFF_H
#include "preflight.h"
enum dcent_handoff_status {
  DCENT_HANDOFF_CPU=156, DCENT_HANDOFF_TIMER=157, DCENT_HANDOFF_LAYOUT=158
};
/* Final primary-CPU transition for the exact prepared Classic layout.
 * Returns only for a pre-transition refusal. Success branches to the kernel.
 * Caller has already authenticated complete kernel/effective extent, initrd,
 * final FDT and entry bytes; proved identity mappings and full memory custody;
 * stopped all relevant DMA; established secondary/cold-route/coherency custody;
 * and completed cache maintenance with no subsequent memory writes.
 * This leaf performs no data access or stack operation. It does not establish
 * those caller prerequisites, monitor identity, physical timer accuracy or
 * consistent secondary-CPU register initialization. A standalone desk build
 * is not aggregate entry or installer authority. */
int dcent_cpu_handoff(u64 kernel_start,u64 fdt_start);
#endif
