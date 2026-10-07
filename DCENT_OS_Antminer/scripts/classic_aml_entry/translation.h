/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Architectural observation adapter. Caller must have established EL2.
 */
#ifndef DCENT_CLASSIC_TRANSLATION_H
#define DCENT_CLASSIC_TRANSLATION_H
#include "preflight.h"

static int dcent_translate_el2(void *unused,u64 address,u64 *par) {
  (void)unused;
  u64 saved,observed;
  __asm__ volatile("mrs %0, par_el1\n\t"
                   "at s1e2r, %2\n\t"
                   "isb\n\t"
                   "mrs %1, par_el1\n\t"
                   "msr par_el1, %0\n\t"
                   "isb"
                   : "=&r"(saved), "=&r"(observed) : "r"(address) : "memory");
  *par=observed;
  return 1;
}
#endif
