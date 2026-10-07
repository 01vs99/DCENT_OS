/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Explicit XHCI stop/reset/readback component; not aggregate DMA admission.
 */
#ifndef DCENT_CLASSIC_XHCI_H
#define DCENT_CLASSIC_XHCI_H
#include "preflight.h"

enum dcent_xhci_status {
  DCENT_XHCI_READ=32, DCENT_XHCI_ID=33, DCENT_XHCI_CAP=34,
  DCENT_XHCI_TIMEOUT=35, DCENT_XHCI_WRITE=36, DCENT_XHCI_FINAL=37,
  DCENT_XHCI_MODE=38
};
typedef int (*dcent_read32)(void *context,u64 address,u32 *value);
typedef int (*dcent_write32)(void *context,u64 address,u32 value);
typedef void (*dcent_delay_us)(void *context,u32 microseconds);
struct dcent_xhci_io {
  void *context;
  dcent_read32 read;
  dcent_write32 write;
  dcent_delay_us delay;
};
static int dcent_xhci_read(const struct dcent_xhci_io *io,u64 address,u32 *value) {
  if(!io->read(io->context,address,value) || *value==0xffffffff) return DCENT_XHCI_READ;
  return 0;
}
static int dcent_xhci_wait(const struct dcent_xhci_io *io,u64 address,u32 mask,u32 wanted,u32 attempts) {
  for(u32 index=0;index<attempts;++index) {
    u32 value;
    int result=dcent_xhci_read(io,address,&value);
    if(result) return result;
    if((value&mask)==wanted) return 0;
    io->delay(io->context,1);
  }
  return DCENT_XHCI_TIMEOUT;
}
static int dcent_xhci_stop(const struct dcent_xhci_io *io) {
  /* Source board registration at 0x01002cf4 binds config0x010be038,
   * whose first word is ff500000. Original DWC3 init checks the5533 core
   * signature at base+c120 and derives operational registers from CAPLENGTH.
   * Callbacks must establish MMIO translations before invoking this helper. */
  const u64 base=0xff500000;
  u32 value;
  int result=dcent_xhci_read(io,base+0xc120,&value);
  if(result) return result;
  if((value&0xffff0000)!=0x55330000) return DCENT_XHCI_ID;
  result=dcent_xhci_read(io,base+0xc110,&value);
  if(result) return result;
  /* Original initialization selects GCTL.PRTCAPDIR=Host at0x01072354.
   * Device/OTG modes need their own endpoint DMA shutdown implementation. */
  if(((value>>12)&3)!=1) return DCENT_XHCI_MODE;
  result=dcent_xhci_read(io,base,&value);
  if(result) return result;
  u32 caplength=value&255;
  if(caplength<0x20 || caplength>0xfc || (caplength&3)) return DCENT_XHCI_CAP;
  u64 command=base+caplength,status=command+4;
  /* xHCI forbids Operational writes (except USBSTS) while CNR is set.
   * Wait before the first command write, not only after requesting reset. */
  /* Save/restore may transfer controller state to RAM while HCH is set.
   * This profile waits for SSS/RSS too; HCH alone cannot prove quiescence. */
  result=dcent_xhci_wait(io,status,0xb00,0,250000);
  if(result) return result;
  result=dcent_xhci_read(io,command,&value);
  if(result) return result;
  /* Do not continue an unexplained reset already in progress. */
  if(value&0x82) return DCENT_XHCI_FINAL; /* HCRST or LHCRST. */
  if(value&1) {
    if(!io->write(io->context,command,value&~1U)) return DCENT_XHCI_WRITE;
  }
  result=dcent_xhci_wait(io,status,0xb01,1,16000);
  if(result) return result;
  result=dcent_xhci_read(io,command,&value);
  if(result) return result;
  if(value&0x83) return DCENT_XHCI_FINAL;
  if(!io->write(io->context,command,value|2)) return DCENT_XHCI_WRITE;
  result=dcent_xhci_wait(io,command,2,0,250000);
  if(result) return result;
  result=dcent_xhci_wait(io,status,0xb00,0,250000);
  if(result) return result;
  /* Unlike the original wrapper, every stop/reset error is propagated and
   * final state is read back. No lower callback's success is sufficient. */
  result=dcent_xhci_read(io,command,&value);
  if(result) return result;
  if(value&0x87) return DCENT_XHCI_FINAL; /* Run, either Reset or Interrupt Enable. */
  result=dcent_xhci_read(io,status,&value);
  if(result) return result;
  if((value&0xb01)!=1) return DCENT_XHCI_FINAL;
  result=dcent_xhci_read(io,base+0xc110,&value);
  if(result) return result;
  if(((value>>12)&3)!=1) return DCENT_XHCI_MODE;
  return 0;
}
#endif
