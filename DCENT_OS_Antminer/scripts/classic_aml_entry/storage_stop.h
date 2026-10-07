/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Exact Classic B-MMC/C-NAND storage stop composition; separate from entry.
 */
#ifndef DCENT_CLASSIC_STORAGE_STOP_H
#define DCENT_CLASSIC_STORAGE_STOP_H
#include "storage_profile.h"
#include "mmc.h"
#include "nand.h"
enum dcent_storage_stop_status {
  DCENT_STORAGE_WRITE=112, DCENT_STORAGE_CHANGED=113,
  DCENT_STORAGE_FINAL=114
};
struct dcent_storage_io {
  void *context;
  int (*read)(void *,u64,u32 *);
  int (*write)(void *,u64,u32);
  void (*delay)(void *,u32);
};
static int dcent_storage_stop(const struct dcent_storage_io *io) {
  struct dcent_storage_profile before,after;
  int result=dcent_storage_profile_read(io->context,io->read,&before);
  if(result) return result;
  const struct dcent_mmc_io mmc={io->context,io->read,io->write,io->delay};
  result=dcent_mmc_stop(&mmc,0xffe05000);
  if(result) return result;
  /* C's functional mux remains NAND. Its descriptor/controller fields were
   * already idle under an admitted register clock; only mask its IRQ enable. */
  if(!io->write(io->context,0xffe0704c,0)) return DCENT_STORAGE_WRITE;
  const struct dcent_nand_io nand={io->context,io->read,io->write,io->delay};
  result=dcent_nand_drain(&nand);
  if(result) return result;
  result=dcent_storage_profile_read(io->context,io->read,&after);
  if(result) return result;
  if(before.soc!=after.soc || before.gates!=after.gates || before.clk81!=after.clk81 ||
     before.fixed_pll!=after.fixed_pll || before.fdiv_gates!=after.fdiv_gates ||
     before.b_clock!=after.b_clock || before.c_clock!=after.c_clock)
    return DCENT_STORAGE_CHANGED;
  if(after.c_irq || after.c_start!=before.c_start) return DCENT_STORAGE_FINAL;
  /* Final read-only join after both component operations. Two accepted NAND
   * IDLE writes already drained its pipeline; no new command writer is allowed. */
  const u64 addresses[5]={0xffe05040,0xffe05048,0xffe0504c,0xffe07804,0xffe07800};
  const u32 masks[5]={3,0xc0000000U,0xffffffffU,0x200000U,0x07c00000U};
  for(u32 i=0;i<5;++i) {
    u32 value;
    if(!io->read(io->context,addresses[i],&value) || value==0xffffffffU) return DCENT_STORAGE_READ;
    if(value&masks[i]) return DCENT_STORAGE_FINAL;
  }
  return 0;
}
/* Caller supplies ordered successful Device access and a truthful bounded
 * delay callback, validates every target translation before access, and
 * excludes other writers. Zero proves this storage profile only; USB,
 * Ethernet and any other relevant board DMA engines remain separate. No
 * storage payload, flash read/program/erase, clock, mux or reset write occurs. */
#endif
