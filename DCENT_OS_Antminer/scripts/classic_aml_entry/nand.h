/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Exact Classic NAND controller pipeline drain; no flash read/program/erase.
 */
#ifndef DCENT_CLASSIC_NAND_H
#define DCENT_CLASSIC_NAND_H
#include "preflight.h"

enum dcent_nand_status {
  DCENT_NAND_READ=80, DCENT_NAND_MODE=81, DCENT_NAND_WRITE=82,
  DCENT_NAND_TIMEOUT=83, DCENT_NAND_FINAL=84
};
struct dcent_nand_io {
  void *context;
  int (*read)(void *context,u64 address,u32 *value);
  int (*write)(void *context,u64 address,u32 value);
  void (*delay)(void *context,u32 microseconds);
};
static int dcent_nand_read(const struct dcent_nand_io *io,u64 address,u32 *value) {
  if(!io->read(io->context,address,value) || *value==0xffffffff) return DCENT_NAND_READ;
  return 0;
}
static int dcent_nand_fifo_empty(const struct dcent_nand_io *io) {
  for(u32 attempt=0;attempt<100000;++attempt) {
    u32 value;
    int result=dcent_nand_read(io,0xffe07800,&value);
    if(result) return result;
    if(!(value&0x07c00000U)) return 0;
    io->delay(io->context,1);
  }
  return DCENT_NAND_TIMEOUT;
}
static int dcent_nand_drain(const struct dcent_nand_io *io) {
  /* Caller establishes accessible MMIO and excludes competing CPU/IRQ writers.
   * The held source uses ffe07800 and shared ffe07000 clock with NAND bit31.
   * Its CE0 value3800 matches the exact DTB's ce0 pin and enable-pad mapping. */
  u32 clock, cfg, value;
  int result=dcent_nand_read(io,0xffe07000,&clock);
  if(result) return result;
  if(!(clock&0x80000000U) || !(clock&63)) return DCENT_NAND_MODE;
  result=dcent_nand_read(io,0xffe07804,&cfg);
  if(result) return result;
  cfg&=~0x200000U;
  if(!io->write(io->context,0xffe07804,cfg)) return DCENT_NAND_WRITE;
  result=dcent_nand_fifo_empty(io);
  if(result) return result;
  /* FIFO emptiness alone leaves up to two pipeline commands. Queue two exact
   * IDLE operations, following the held original and Amlogic upstream drain.
   * These contain no CLE/ALE, DMA, seed, address, reset or flash command. */
  for(u32 idle=0;idle<2;++idle) {
    if(!io->write(io->context,0xffe07800,0x33800)) return DCENT_NAND_WRITE;
    result=dcent_nand_fifo_empty(io);
    if(result) return result;
  }
  result=dcent_nand_read(io,0xffe07804,&value);
  if(result) return result;
  if(value!=cfg) return DCENT_NAND_FINAL;
  result=dcent_nand_read(io,0xffe07000,&value);
  if(result) return result;
  if(value!=clock) return DCENT_NAND_FINAL;
  result=dcent_nand_read(io,0xffe07800,&value);
  if(result) return result;
  if(value&0x07c00000U) return DCENT_NAND_FINAL;
  return 0;
}
#endif
