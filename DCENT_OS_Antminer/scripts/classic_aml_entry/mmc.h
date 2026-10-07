/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Exact Classic SD/eMMC stop component. Caller establishes accessible MMIO.
 */
#ifndef DCENT_CLASSIC_MMC_H
#define DCENT_CLASSIC_MMC_H
#include "preflight.h"

enum dcent_mmc_status {
  DCENT_MMC_READ=64, DCENT_MMC_BASE=65, DCENT_MMC_MODE=66,
  DCENT_MMC_WRITE=67, DCENT_MMC_TIMEOUT=68, DCENT_MMC_FINAL=69
};
struct dcent_mmc_io {
  void *context;
  int (*read)(void *context,u64 address,u32 *value);
  int (*write)(void *context,u64 address,u32 value);
  void (*delay)(void *context,u32 microseconds);
};
static int dcent_mmc_read(const struct dcent_mmc_io *io,u64 address,u32 *value) {
  if(!io->read(io->context,address,value) || *value==0xffffffff) return DCENT_MMC_READ;
  return 0;
}
static int dcent_mmc_stop(const struct dcent_mmc_io *io,u64 base) {
  /* Held table0x010c5578 selects these three bases. The NAND controller uses
   * the C clock register with bit31 selecting NAND. Never change this mux or
   * interpret a NAND-selected C controller as an admitted MMC engine. */
  if(base!=0xffe03000 && base!=0xffe05000 && base!=0xffe07000) return DCENT_MMC_BASE;
  u32 value, clock;
  int result=dcent_mmc_read(io,base,&clock);
  if(result) return result;
  if((clock&0x80000000U) || !(clock&63)) return DCENT_MMC_MODE;
  result=dcent_mmc_read(io,base+0x40,&value);
  if(result) return result;
  /* Held descriptor setup clears the INIT field; other modes are refused. */
  if(value&1) return DCENT_MMC_FINAL;
  if(!io->write(io->context,base+0x40,value&~2U)) return DCENT_MMC_WRITE;
  if(!io->write(io->context,base+0x4c,0)) return DCENT_MMC_WRITE;
  u32 stopped=0;
  for(u32 attempt=0;attempt<5000;++attempt) {
    result=dcent_mmc_read(io,base+0x48,&value);
    if(result) return result;
    if(!(value&0xc0000000U)) { stopped=1; break; }
    io->delay(io->context,1);
  }
  if(!stopped) return DCENT_MMC_TIMEOUT;
  result=dcent_mmc_read(io,base+0x40,&value);
  if(result) return result;
  if(value&3) return DCENT_MMC_FINAL;
  result=dcent_mmc_read(io,base+0x4c,&value);
  if(result) return result;
  if(value) return DCENT_MMC_FINAL;
  result=dcent_mmc_read(io,base,&value);
  if(result) return result;
  if(value!=clock) return DCENT_MMC_FINAL;
  result=dcent_mmc_read(io,base+0x48,&value);
  if(result) return result;
  if(value&0xc0000000U) return DCENT_MMC_FINAL;
  return 0;
}
#endif
