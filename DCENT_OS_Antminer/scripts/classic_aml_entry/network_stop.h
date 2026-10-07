/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Exact Classic Ethernet/DWC3 stop and joint readback; separate from entry.
 */
#ifndef DCENT_CLASSIC_NETWORK_STOP_H
#define DCENT_CLASSIC_NETWORK_STOP_H
#include "network_profile.h"
#include "ethernet.h"
#include "xhci.h"
enum dcent_network_stop_status { DCENT_NETWORK_CHANGED=140, DCENT_NETWORK_FINAL=141 };
struct dcent_network_io {
  void *context;
  int (*read)(void *,u64,u32 *);
  int (*write)(void *,u64,u32);
  void (*delay)(void *,u32);
};
static int dcent_network_stop(const struct dcent_network_io *io) {
  struct dcent_network_profile before,after;
  int result=dcent_network_profile_read(io->context,io->read,&before);
  if(result) return result;
  const struct dcent_ethernet_io eth={io->context,io->read,io->write,io->delay};
  result=dcent_ethernet_stop(&eth);
  if(result) return result;
  u32 capability;
  if(!io->read(io->context,0xff500000,&capability) || capability==0xffffffffU) return DCENT_NETWORK_READ;
  u32 caplength=capability&255;
  if(caplength<0x20 || caplength>0xfc || (caplength&3)) return DCENT_XHCI_CAP;
  const struct dcent_xhci_io xhci={io->context,io->read,io->write,io->delay};
  result=dcent_xhci_stop(&xhci);
  if(result) return result;
  result=dcent_network_profile_read(io->context,io->read,&after);
  if(result) return result;
  if(before.soc!=after.soc || before.gates1!=after.gates1 || before.gates2!=after.gates2 ||
     before.clk81!=after.clk81 || before.fixed_pll!=after.fixed_pll || before.fdiv_gates!=after.fdiv_gates)
    return DCENT_NETWORK_CHANGED;
  /* Both operations have completed. Recheck identities, original capability,
   * MAC/DMA enable/state, USB host mode and halt/reset/save/restore state. */
  const u64 addresses[11]={0xff3f0020,0xff3f0000,0xff3f1018,0xff3f101c,0xff3f1000,0xff3f1014,
    0xff500000,0xff50c120,0xff50c110,0xff500000+caplength,0xff500004+caplength};
  const u32 masks[11]={255,12,0x2002,0xffffffffU,1,0x7e2000,0xffffffffU,0xffff0000,0x3000,0x87,0xb01};
  const u32 wanted[11]={0x37,0,0,0,0,0,capability,0x55330000,0x1000,0,1};
  for(u32 i=0;i<11;++i) {
    u32 value;
    if(!io->read(io->context,addresses[i],&value) || value==0xffffffffU) return DCENT_NETWORK_READ;
    if((value&masks[i])!=wanted[i]) return DCENT_NETWORK_FINAL;
  }
  return 0;
}
/* Caller admits AO/HIU/engine Device mappings and reset/clock accessibility,
 * supplies ordered MMIO plus bounded physical-counter delay, and excludes
 * competing writers. Zero proves only this exact Ethernet/DWC3 pair under
 * those prerequisites. Storage, DWC2 and other relevant DMA remain separate.
 * No clock, PHY, storage payload or flash command write occurs. */
#endif
