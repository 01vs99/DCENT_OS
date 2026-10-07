/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Read-only clock admission for the exact Classic Ethernet/DWC3 pair.
 */
#ifndef DCENT_CLASSIC_NETWORK_PROFILE_H
#define DCENT_CLASSIC_NETWORK_PROFILE_H
#include "preflight.h"
enum dcent_network_profile_status {
  DCENT_NETWORK_READ=136, DCENT_NETWORK_SOC=137,
  DCENT_NETWORK_GATE=138, DCENT_NETWORK_PARENT=139
};
struct dcent_network_profile {
  u32 soc,gates1,gates2,clk81,fixed_pll,fdiv_gates;
};
_Static_assert(sizeof(struct dcent_network_profile)==24,"network profile size");
static int dcent_network_profile_validate(const struct dcent_network_profile *p) {
  if((p->soc>>24)!=0x25) return DCENT_NETWORK_SOC;
  /* AXG clk81 leaves: Ethernet3/USB-general26 in MPEG1 and AHB data1/
   * control2 in MPEG2. The held DWC3 path is not legacy USB0/1-to-DDR;
   * those unrelated gates are neither enabled nor silently required here. */
  if((p->gates1&0x04000008U)!=0x04000008U ||
     (p->gates2&6)!=6 || !(p->clk81&0x80)) return DCENT_NETWORK_GATE;
  u32 needed;
  switch((p->clk81>>12)&7) {
    case 0: needed=0; break;
    case 2: needed=0x80000000U; break;
    case 5: needed=0x20000000U; break;
    case 6: needed=0x10000000U; break;
    case 7: needed=0x40000000U; break;
    default: return DCENT_NETWORK_PARENT;
  }
  if(needed && ((p->fixed_pll&0xe0000000U)!=0xc0000000U ||
                (p->fdiv_gates&needed)!=needed)) return DCENT_NETWORK_PARENT;
  return 0;
}
static int dcent_network_profile_read(void *context,
    int (*read)(void *,u64,u32 *),struct dcent_network_profile *output) {
  struct dcent_network_profile p={0};
  u32 *values[6]={&p.soc,&p.gates1,&p.gates2,&p.clk81,&p.fixed_pll,&p.fdiv_gates};
  const u64 addresses[6]={0xff800220,0xff63c144,0xff63c148,0xff63c174,0xff63c280,0xff63c294};
  /* Only caller-admitted AO/HIU registers are read. Complete parent/gate
   * validation finishes before any Ethernet or DWC3 bank may be touched. */
  for(u32 i=0;i<6;++i) {
    if(!read(context,addresses[i],values[i]) || *values[i]==0xffffffffU)
      return DCENT_NETWORK_READ;
    if(i==0 && (p.soc>>24)!=0x25) return DCENT_NETWORK_SOC;
    if(i==3 && ((p.gates1&0x04000008U)!=0x04000008U ||
       (p.gates2&6)!=6 || !(p.clk81&0x80))) return DCENT_NETWORK_GATE;
  }
  int result=dcent_network_profile_validate(&p);
  if(!result) *output=p;
  return result;
}
/* Admission only: no engine stop, Device mapping, reset release, PHY state,
 * bounded MMIO backend, or aggregate board-DMA claim. Engine-specific ID,
 * mode and stopped readbacks remain mandatory; composition rereads this
 * profile unchanged after stop. Exact clock/reset stability and absence of
 * competing writers remain caller prerequisites. */
#endif
