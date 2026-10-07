/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Read-only exact Classic PSCI affinity query; no CPU power requests.
 */
#ifndef DCENT_CLASSIC_AFFINITY_H
#define DCENT_CLASSIC_AFFINITY_H
#include "preflight.h"
enum dcent_affinity_status { DCENT_AFFINITY_CPU=144, DCENT_AFFINITY_VERSION=145, DCENT_AFFINITY_STATE=146 };
struct dcent_affinity_snapshot {u64 version,state[4];};
_Static_assert(sizeof(struct dcent_affinity_snapshot)==40,"affinity snapshot size");
static u64 dcent_psci_query(u64 function,u64 target) {
  register u64 r0 __asm__("x0")=function,r1 __asm__("x1")=target;
  register u64 r2 __asm__("x2")=0,r3 __asm__("x3")=0;
  register u64 r4 __asm__("x4")=0,r5 __asm__("x5")=0;
  register u64 r6 __asm__("x6")=0,r7 __asm__("x7")=0;
  __asm__ volatile("smc #0" : "+r"(r0),"+r"(r1),"+r"(r2),"+r"(r3),"+r"(r4),"+r"(r5),"+r"(r6),"+r"(r7)
      : : "x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
  return r0;
}
static int dcent_affinity_read(struct dcent_affinity_snapshot *output) {
  u64 el,midr,mpidr,daif;
  __asm__ volatile("mrs %0,CurrentEL" : "=r"(el));
  if(el!=8) return DCENT_AFFINITY_CPU;
  __asm__ volatile("mrs %0,MIDR_EL1\n\tmrs %1,MPIDR_EL1\n\tmrs %2,DAIF" : "=r"(midr),"=r"(mpidr),"=r"(daif));
  /* Exact four-core A53 cluster with primary affinity0, not a uniprocessor
   * or multithreaded MPIDR interpretation. Reserved MPIDR bits are ignored. */
  if((midr&0xff0ffff0UL)!=0x410fd030UL || (mpidr&0xff00ffffffUL) ||
     (mpidr&0x41000000UL) || (daif&0x3c0)!=0x3c0) return DCENT_AFFINITY_CPU;
  struct dcent_affinity_snapshot snapshot;
  snapshot.version=dcent_psci_query(0x84000000,0);
  if(snapshot.version!=0x10000) return DCENT_AFFINITY_VERSION;
  for(u64 index=0;index<4;++index) {
    snapshot.state[index]=dcent_psci_query(0xc4000004,index);
    if(snapshot.state[index]!=(index?1UL:0UL)) return DCENT_AFFINITY_STATE;
  }
  *output=snapshot;
  return 0;
}
/* Caller proves owned readable/writable context/stack, executable and SMC
 * exception custody, and the exact held secure-monitor lineage/PSCI contract.
 * The five read-only calls themselves do not authenticate that monitor.
 * Held implementation proof must join OFF publication to prior private-cache
 * retirement or cold-reset custody; no later CPU_ON/other power-state writer
 * is permitted through final entry. OFF is not measured physical power-off.
 * No CPU_ON, CPU_OFF, suspend, reset, power controller or flash call is made.
 * Timer, current-core cache and aggregate DMA/entry admission are separate. */
#endif
