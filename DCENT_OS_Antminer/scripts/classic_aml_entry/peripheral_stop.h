/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * One returning composition for the explicit Classic storage/network/USB set.
 */
#ifndef DCENT_CLASSIC_PERIPHERAL_STOP_H
#define DCENT_CLASSIC_PERIPHERAL_STOP_H
#include "storage_stop.h"
#include "network_stop.h"
#include "dwc2.h"

enum dcent_peripheral_status {
  DCENT_PERIPHERAL_READ=159, DCENT_PERIPHERAL_CHANGED=160,
  DCENT_PERIPHERAL_FINAL=161
};
struct dcent_peripheral_io {
  void *context;
  int (*read)(void *,u64,u32 *);
  int (*write)(void *,u64,u32);
  void (*delay)(void *,u32);
};
static int dcent_peripheral_stop(const struct dcent_peripheral_io *io) {
  struct dcent_storage_profile s0,s1;
  struct dcent_network_profile n0,n1;
  struct dcent_dwc2_profile u0,u1;
  /* Admit every group's source clock/mux profile before any engine write.
   * Each accepted leaf repeats its own admission and final checks. */
  int result=dcent_storage_profile_read(io->context,io->read,&s0);
  if(result) return result;
  result=dcent_network_profile_read(io->context,io->read,&n0);
  if(result) return result;
  result=dcent_dwc2_profile_read(io->context,io->read,&u0);
  if(result) return result;
  u32 capability,id,power,config;
  if(!io->read(io->context,0xff500000,&capability) || capability==0xffffffffU)
    return DCENT_PERIPHERAL_READ;
  u32 caplength=capability&255;
  if(caplength<0x20 || caplength>0xfc || (caplength&3)) return DCENT_XHCI_CAP;
  if(!io->read(io->context,0xff400e00,&power) || power==0xffffffffU)
    return DCENT_PERIPHERAL_READ;
  if(power&0x3fff) return DCENT_DWC2_STATE;
  if(!io->read(io->context,0xff400040,&id) || id==0xffffffffU)
    return DCENT_PERIPHERAL_READ;
  if((id&0xfffff000U)!=0x4f542000U) return DCENT_DWC2_ID;
  if(!io->read(io->context,0xff40000c,&config) || config==0xffffffffU)
    return DCENT_PERIPHERAL_READ;
  if(config&0x20000000U) return DCENT_DWC2_STATE;
  const struct dcent_storage_io storage={io->context,io->read,io->write,io->delay};
  result=dcent_storage_stop(&storage);
  if(result) return result;
  const struct dcent_network_io network={io->context,io->read,io->write,io->delay};
  result=dcent_network_stop(&network);
  if(result) return result;
  result=dcent_dwc2_stop(io->context,io->read,io->write,io->delay);
  if(result) return result;
  /* No component writes the shared gates or functional muxes. Rejoin the
   * initial profiles after all operations, including previously stopped sets. */
  result=dcent_storage_profile_read(io->context,io->read,&s1);
  if(result) return result;
  result=dcent_network_profile_read(io->context,io->read,&n1);
  if(result) return result;
  result=dcent_dwc2_profile_read(io->context,io->read,&u1);
  if(result) return result;
  if(s0.soc!=s1.soc || s0.gates!=s1.gates || s0.clk81!=s1.clk81 ||
     s0.fixed_pll!=s1.fixed_pll || s0.fdiv_gates!=s1.fdiv_gates ||
     s0.b_clock!=s1.b_clock || s0.c_clock!=s1.c_clock || s0.c_start!=s1.c_start ||
     n0.soc!=n1.soc || n0.gates1!=n1.gates1 || n0.gates2!=n1.gates2 ||
     n0.clk81!=n1.clk81 || n0.fixed_pll!=n1.fixed_pll || n0.fdiv_gates!=n1.fdiv_gates ||
     u0.soc!=u1.soc || u0.gates1!=u1.gates1 || u0.gates2!=u1.gates2 ||
     u0.clk81!=u1.clk81 || u0.pll!=u1.pll || u0.fdiv!=u1.fdiv)
    return DCENT_PERIPHERAL_CHANGED;
  if(s1.c_irq) return DCENT_PERIPHERAL_FINAL;
  const u64 addresses[24]={
    0xffe05040,0xffe05048,0xffe0504c,0xffe07804,0xffe07800,
    0xff3f0020,0xff3f0000,0xff3f1018,0xff3f101c,0xff3f1000,0xff3f1014,
    0xff500000,0xff50c120,0xff50c110,0xff500000+caplength,0xff500004+caplength,
    0xff400040,0xff400e00,0xff400014,0xff40000c,0xff400008,0xff400018,0xff400010,0xff400014};
  const u32 masks[24]={
    3,0xc0000000U,0xffffffffU,0x200000U,0x07c00000U,
    255,12,0x2002,0xffffffffU,1,0x7e2000,
    0xffffffffU,0xffff0000U,0x3000,0x87,0xb01,
    0xffffffffU,0xffffffffU,1,0xffffffffU,0x21,0xffffffffU,0xc000003fU,1};
  const u32 expected[24]={
    0,0,0,0,0,
    0x37,0,0,0,0,0,
    capability,0x55330000U,0x1000,0,1,
    id,power,0,config,0,0,0x80000000U,0};
  for(u32 i=0;i<24;++i) {
    u32 value;
    if(!io->read(io->context,addresses[i],&value) || value==0xffffffffU)
      return DCENT_PERIPHERAL_READ;
    if((value&masks[i])!=expected[i]) return DCENT_PERIPHERAL_FINAL;
  }
  return 0;
}
/* One admitted Device-MMIO context and bounded timer must cover this complete
 * call. Caller owns exact identity Device mappings, stable power/reset/PHY and
 * clock access, accepted writes, and absence of competing writers. A refusal
 * can leave earlier engines stopped; no automatic restart is attempted.
 * Zero covers only B-MMC, C-NAND, Ethernet, DWC3 host and DWC2 device under the
 * accepted leaf contracts. Crypto, other DMA, cold-route/secure/AO actors,
 * CPU/cache and final kernel entry are separate; this is not aggregate entry
 * admission. No payload/flash, shared reset, clock, mux or PHY write occurs. */
#endif
