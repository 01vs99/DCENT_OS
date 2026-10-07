/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Read-only admission for the held Classic AXG B-MMC/C-NAND profile.
 */
#ifndef DCENT_CLASSIC_STORAGE_PROFILE_H
#define DCENT_CLASSIC_STORAGE_PROFILE_H
#include "preflight.h"
enum dcent_storage_profile_status {
  DCENT_STORAGE_READ=96, DCENT_STORAGE_SOC=97, DCENT_STORAGE_GATE=98,
  DCENT_STORAGE_PARENT=99, DCENT_STORAGE_B_CLOCK=100,
  DCENT_STORAGE_NAND_CLOCK=101, DCENT_STORAGE_C_ACTIVE=102
};
struct dcent_storage_profile {
  u32 soc, gates, clk81, fixed_pll, fdiv_gates, b_clock, c_clock;
  u32 c_start, c_status, c_irq;
};
_Static_assert(sizeof(struct dcent_storage_profile)==40,"storage profile size");
static int dcent_storage_parent_validate(const struct dcent_storage_profile *p,u32 needed) {
  if(needed && ((p->fixed_pll&0xe0000000U)!=0xc0000000U ||
                (p->fdiv_gates&needed)!=needed)) return DCENT_STORAGE_PARENT;
  return 0;
}
static int dcent_storage_bus_validate(const struct dcent_storage_profile *p) {
  if((p->gates&0x06000000U)!=0x06000000U || !(p->clk81&0x80))
    return DCENT_STORAGE_GATE;
  /* Prove clk81's selected upstream source before any B/C peripheral-bank
   * read. Enabled leaf gates alone do not establish register-bus clocking. */
  u32 needed;
  switch((p->clk81>>12)&7) {
    case 0: needed=0; break;
    case 2: needed=0x80000000U; break;
    case 5: needed=0x20000000U; break;
    case 6: needed=0x10000000U; break;
    case 7: needed=0x40000000U; break;
    default: return DCENT_STORAGE_PARENT;
  }
  return dcent_storage_parent_validate(p,needed);
}
static int dcent_storage_profile_validate(const struct dcent_storage_profile *p) {
  /* Held SoC helper extracts the top byte of ff800220; AXG is0x25.
   * Board registration calls ports1 and2 even though the resident DTB marks
   * eMMC disabled. Port C must therefore be idle, not silently omitted. */
  if((p->soc>>24)!=0x25) return DCENT_STORAGE_SOC;
  int result=dcent_storage_bus_validate(p);
  if(result) return result;
  /* Held B set_ios followed by board phase setup writes this prefix and
   * selects only xtal or fclk_div2. No clock or mux is changed here. */
  if((p->b_clock&~0x7fU)!=0x10000300U || !(p->b_clock&63))
    return DCENT_STORAGE_B_CLOCK;
  if(p->c_clock!=0x90000201U && p->c_clock!=0x90000244U &&
     p->c_clock!=0x90000245U && p->c_clock!=0x90000249U)
    return DCENT_STORAGE_NAND_CLOCK;
  /* The exact upstream AXG clock tree maps these clk81 selections to
   * crystal or fixed-PLL dividers. MPLL1/2 paths are outside this profile. */
  u32 needed=((p->b_clock|p->c_clock)&0x40)?0x08000000U:0;
  result=dcent_storage_parent_validate(p,needed);
  if(result) return result;
  /* C's NAND mux is never interpreted as an MMC stop instruction. Refuse
   * any outstanding descriptor/controller activity in that shared bank. */
  if((p->c_start&3) || (p->c_status&0xc0000000U)) return DCENT_STORAGE_C_ACTIVE;
  return 0;
}
static int dcent_storage_profile_read(void *context,
    int (*read)(void *,u64,u32 *),struct dcent_storage_profile *output) {
  struct dcent_storage_profile p={0};
  u32 *values[10]={&p.soc,&p.gates,&p.clk81,&p.fixed_pll,&p.fdiv_gates,
    &p.b_clock,&p.c_clock,&p.c_start,&p.c_status,&p.c_irq};
  const u64 addresses[10]={0xff800220,0xff63c140,0xff63c174,0xff63c280,
    0xff63c294,0xffe05000,0xffe07000,0xffe07040,0xffe07048,0xffe0704c};
  for(u32 i=0;i<10;++i) {
    if(!read(context,addresses[i],values[i]) || *values[i]==0xffffffffU)
      return DCENT_STORAGE_READ;
    if(i==0 && (p.soc>>24)!=0x25) return DCENT_STORAGE_SOC;
    if(i==2 && ((p.gates&0x06000000U)!=0x06000000U || !(p.clk81&0x80)))
      return DCENT_STORAGE_GATE;
    if(i==4) {
      int result=dcent_storage_bus_validate(&p);
      if(result) return result;
    }
    /* No controller-bank access precedes the gate checks, and no C engine
     * access precedes the full clock/mux/parent checks. Its fields are still
     * zero for this first validation; final validation includes actual reads. */
    if(i==6) {
      int result=dcent_storage_profile_validate(&p);
      if(result) return result;
    }
  }
  int result=dcent_storage_profile_validate(&p);
  if(!result) *output=p;
  return result;
}
/* This profile is a prerequisite only. It does not drain B or NAND, mask C
 * interrupts, establish Device translations, or claim aggregate DMA safety.
 * Composition must reread unchanged clock/mux state and stopped C after its
 * B stop/NAND drain and admit all other relevant DMA engines separately. */
#endif
