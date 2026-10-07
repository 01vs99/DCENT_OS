/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef DCENT_CLASSIC_CACHE_H
#define DCENT_CLASSIC_CACHE_H
#include "preflight.h"
struct dcent_cache_ranges {
  u64 kernel_start,kernel_end,initrd_start,initrd_end,fdt_start,fdt_end;
};
/* Exact A53 EL2 with DAIF masked; caller proves readable owned range structure,
 * identity Normal mapping of every full cache-line/page touched, authenticated
 * payload extents and stopped relevant DMA/no competing writers. The assembly
 * validates its CPU/cache geometry and bounded disjoint DRAM extents before
 * maintenance. It cleans each range by VA to PoC, then cleans/invalidates the
 * two admitted CPU data/unified levels and invalidates instruction caches.
 * No stack/data write occurs in this function, including after the last sweep.
 * Return allows desk probes; a final handoff must not dirty memory afterwards.
 * No MMU/timer transition or Linux branch is performed by this component. */
int dcent_cache_clean(const struct dcent_cache_ranges *ranges);
#endif
