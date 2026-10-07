/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Physical-counter delay for the held A53 EL2 frequency encodings.
 */
#ifndef DCENT_CLASSIC_TIMER_H
#define DCENT_CLASSIC_TIMER_H
#include "preflight.h"
enum dcent_timer_status {
  DCENT_TIMER_FREQUENCY=104, DCENT_TIMER_BACKWARDS=105,
  DCENT_TIMER_STALLED=106, DCENT_TIMER_STATE=107, DCENT_TIMER_ARGUMENT=108
};
struct dcent_timer_context { u64 last, frequency; u32 ready, failed; };
static u64 dcent_timer_frequency(void) {
  u64 value; __asm__ volatile("mrs %0,CNTFRQ_EL0" : "=r"(value)); return value;
}
static u64 dcent_timer_counter(void) {
  u64 value; __asm__ volatile("isb\n\tmrs %0,CNTPCT_EL0" : "=r"(value) : : "memory"); return value;
}
static int dcent_timer_frequency_admitted(u64 frequency) {
  /* Held BL33 EL3 literal is0x1800000 (25,165,824), while its AXG vendor
   * header labels that literal24MHz and the exact DTB crystal is24,000,000.
   * Preserve both encodings and wait26 ticks, conservatively rounding up
   * over either source rate. EL2's frequency register is never rewritten. */
  return frequency==24000000 || frequency==0x1800000;
}
static int dcent_timer_fail(struct dcent_timer_context *timer,u32 status) {
  timer->failed=status; return (int)status;
}
static int dcent_timer_delay(struct dcent_timer_context *timer,u32 microseconds) {
  /* Current controller components request exactly one microsecond per poll.
   * Exact A53 EL2 and owned writable timer state are caller prerequisites. */
  if(timer->ready!=1 || timer->failed) return DCENT_TIMER_STATE;
  if(microseconds!=1) return dcent_timer_fail(timer,DCENT_TIMER_ARGUMENT);
  u64 frequency=dcent_timer_frequency();
  if(!dcent_timer_frequency_admitted(frequency) || frequency!=timer->frequency)
    return dcent_timer_fail(timer,DCENT_TIMER_FREQUENCY);
  u64 start=dcent_timer_counter();
  if(start<timer->last) return dcent_timer_fail(timer,DCENT_TIMER_BACKWARDS);
  u64 previous=start;
  for(u32 attempt=0;attempt<16384;++attempt) {
    u64 now=dcent_timer_counter();
    if(now<previous) return dcent_timer_fail(timer,DCENT_TIMER_BACKWARDS);
    if(now-start>=26) {
      if(dcent_timer_frequency()!=frequency) return dcent_timer_fail(timer,DCENT_TIMER_FREQUENCY);
      timer->last=now; return 0;
    }
    previous=now;
  }
  return dcent_timer_fail(timer,DCENT_TIMER_STALLED);
}
static int dcent_timer_begin(struct dcent_timer_context *timer) {
  if(timer->ready || timer->failed) return DCENT_TIMER_STATE;
  u64 frequency=dcent_timer_frequency();
  if(!dcent_timer_frequency_admitted(frequency)) return dcent_timer_fail(timer,DCENT_TIMER_FREQUENCY);
  timer->frequency=frequency;
  timer->last=dcent_timer_counter();timer->ready=1;
  return dcent_timer_delay(timer,1);
}
/* A composed void delay callback must poison its Device-MMIO context when
 * this function refuses, making the next dependent access refuse as well.
 * This proves elapsed counter ticks, not Amlogic device behavior or a complete
 * timer/GIC/kernel handoff. No timer-control register is written here. */
#endif
