/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Separate bounded Classic legacy USB-device stop. No clock/reset-controller
 * mutation: an inaccessible or clock-gated controller is refused, not read.
 */
#ifndef DCENT_CLASSIC_DWC2_H
#define DCENT_CLASSIC_DWC2_H
#include "preflight.h"
enum dcent_dwc2_status {
  DCENT_DWC2_READ=148, DCENT_DWC2_PROFILE=149, DCENT_DWC2_ID=150,
  DCENT_DWC2_STATE=151, DCENT_DWC2_WRITE=152,
  DCENT_DWC2_RESET_TIMEOUT=153, DCENT_DWC2_IDLE_TIMEOUT=154,
  DCENT_DWC2_FINAL=155
};
struct dcent_dwc2_profile { u32 soc,gates1,gates2,clk81,pll,fdiv; };
static int dcent_dwc2_profile_read(void *context,
    int (*read)(void *,u64,u32 *),struct dcent_dwc2_profile *output) {
  struct dcent_dwc2_profile p={0};
  u32 *values[6]={&p.soc,&p.gates1,&p.gates2,&p.clk81,&p.pll,&p.fdiv};
  const u64 addresses[6]={0xff800220,0xff63c144,0xff63c148,0xff63c174,0xff63c280,0xff63c294};
  for(u32 i=0;i<6;++i) {
    if(!read(context,addresses[i],values[i]) || *values[i]==0xffffffffU)
      return DCENT_DWC2_READ;
    if(i==0 && (p.soc>>24)!=0x25) return DCENT_DWC2_PROFILE;
    /* USB-general26 and USB1 functional22, USB1-DDR bridge8 and both
     * AHB buses1/2. All are AXG clk81 leaves. Validate the parent before
     * the first controller-bank access, including any power-state read. */
    if(i==3 && ((p.gates1&0x04400000U)!=0x04400000U ||
       (p.gates2&0x106)!=0x106 || !(p.clk81&0x80))) return DCENT_DWC2_PROFILE;
  }
  u32 needed;
  switch((p.clk81>>12)&7) {
    case 0: needed=0; break;
    case 2: needed=0x80000000U; break;
    case 5: needed=0x20000000U; break;
    case 6: needed=0x10000000U; break;
    case 7: needed=0x40000000U; break;
    default: return DCENT_DWC2_PROFILE;
  }
  if(needed && ((p.pll&0xe0000000U)!=0xc0000000U ||
                (p.fdiv&needed)!=needed)) return DCENT_DWC2_PROFILE;
  *output=p;
  return 0;
}
static int dcent_dwc2_stop(void *context,int (*read)(void *,u64,u32 *),
    int (*write)(void *,u64,u32),void (*delay_us)(void *,u32)) {
  struct dcent_dwc2_profile before,after;
  int result=dcent_dwc2_profile_read(context,read,&before);
  if(result) return result;
  u32 id,power,mode,config,ahb,status;
  if(!read(context,0xff400e00,&power) || power==0xffffffffU) return DCENT_DWC2_READ;
  /* No transition from controller-local clock stop/clamp/reset/hibernation.
   * PHY/reset stability and bounded Device-MMIO remain outer prerequisites. */
  if(power&0x3fff) return DCENT_DWC2_STATE;
  if(!read(context,0xff400040,&id) || id==0xffffffffU) return DCENT_DWC2_READ;
  if((id&0xfffff000U)!=0x4f542000U) return DCENT_DWC2_ID;
  if(!read(context,0xff400014,&mode) || mode==0xffffffffU) return DCENT_DWC2_READ;
  if(mode&1) return DCENT_DWC2_STATE;
  if(!read(context,0xff40000c,&config) || config==0xffffffffU) return DCENT_DWC2_READ;
  if(config&0x20000000U) return DCENT_DWC2_STATE;
  if(!read(context,0xff400010,&status) || status==0xffffffffU) return DCENT_DWC2_READ;
  if(status&0x3f) return DCENT_DWC2_STATE;
  if(!read(context,0xff400008,&ahb) || ahb==0xffffffffU) return DCENT_DWC2_READ;
  if(!write(context,0xff400008,ahb&~0x21U) ||
     !write(context,0xff400018,0) ||
     !write(context,0xff400010,1)) return DCENT_DWC2_WRITE;
  /* Synopsys core soft reset terminates pending AHB transactions under the
   * bus protocol. Attempt completion and final bus-idle are separate checks;
   * a failed/stalled delay poisons the composed backend's next read. */
  u32 count;
  for(count=0;count<50000;++count) {
    delay_us(context,1);
    if(!read(context,0xff400010,&status) || status==0xffffffffU) return DCENT_DWC2_READ;
    if(!(status&1)) break;
  }
  if(count==50000) return DCENT_DWC2_RESET_TIMEOUT;
  for(count=0;count<50000;++count) {
    delay_us(context,1);
    if(!read(context,0xff400010,&status) || status==0xffffffffU) return DCENT_DWC2_READ;
    if((status&0xc000003fU)==0x80000000U) break;
  }
  if(count==50000) return DCENT_DWC2_IDLE_TIMEOUT;
  result=dcent_dwc2_profile_read(context,read,&after);
  if(result) return result;
  if(before.soc!=after.soc || before.gates1!=after.gates1 ||
     before.gates2!=after.gates2 || before.clk81!=after.clk81 ||
     before.pll!=after.pll || before.fdiv!=after.fdiv) return DCENT_DWC2_FINAL;
  const u64 addresses[8]={0xff400040,0xff400e00,0xff400014,0xff40000c,
                         0xff400008,0xff400018,0xff400010,0xff400014};
  const u32 masks[8]={0xffffffffU,0xffffffffU,1,0xffffffffU,
                     0x21,0xffffffffU,0xc000003fU,1};
  const u32 expected[8]={id,power,0,config,0,0,0x80000000U,0};
  for(u32 i=0;i<8;++i) {
    if(!read(context,addresses[i],&status) || status==0xffffffffU) return DCENT_DWC2_READ;
    if((status&masks[i])!=expected[i]) return DCENT_DWC2_FINAL;
  }
  return 0;
}
/* Caller owns admitted AO/HIU and identity Device controller mappings, exact
 * AXG clock/reset/PHY custody, synchronous-abort/SError handling and monotonic
 * bounded delay. Single stopped DWC2 device component only; no crypto, other
 * DMA, prior cold-start, CPU/cache or kernel-entry admission is implied. */
#endif
