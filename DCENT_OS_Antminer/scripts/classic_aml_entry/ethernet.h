/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Exact Classic DWMAC 0x37 stop/readback component, not aggregate DMA admission.
 */
#ifndef DCENT_CLASSIC_ETHERNET_H
#define DCENT_CLASSIC_ETHERNET_H
#include "preflight.h"

enum dcent_ethernet_status {
  DCENT_ETH_READ=48, DCENT_ETH_ID=49, DCENT_ETH_WRITE=50,
  DCENT_ETH_TIMEOUT=51, DCENT_ETH_FINAL=52, DCENT_ETH_BUS_ERROR=53
};
struct dcent_ethernet_io {
  void *context;
  int (*read)(void *context,u64 address,u32 *value);
  int (*write)(void *context,u64 address,u32 value);
  void (*delay)(void *context,u32 microseconds);
};
static int dcent_eth_read(const struct dcent_ethernet_io *io,u64 address,u32 *value) {
  if(!io->read(io->context,address,value) || *value==0xffffffff) return DCENT_ETH_READ;
  return 0;
}
static int dcent_ethernet_stop(const struct dcent_ethernet_io *io) {
  /* Exact source board initialization uses ff3f0000 and admits MAC version37.
   * Source halt0x01067174 clears MAC RX/TX bits2/3 and DMA SR/ST bits1/13.
   * Add bounded process-state polling, interrupt masking and final readback. */
  const u64 base=0xff3f0000;
  u32 value;
  int result=dcent_eth_read(io,base+0x20,&value);
  if(result) return result;
  if((value&255)!=0x37) return DCENT_ETH_ID;
  result=dcent_eth_read(io,base+0x1000,&value);
  if(result) return result;
  if(value&1) return DCENT_ETH_FINAL;
  result=dcent_eth_read(io,base,&value);
  if(result) return result;
  if(!io->write(io->context,base,value&~12U)) return DCENT_ETH_WRITE;
  result=dcent_eth_read(io,base+0x1018,&value);
  if(result) return result;
  if(!io->write(io->context,base+0x1018,value&~0x2002U)) return DCENT_ETH_WRITE;
  if(!io->write(io->context,base+0x101c,0)) return DCENT_ETH_WRITE;
  u32 stopped=0;
  for(u32 attempt=0;attempt<100000;++attempt) {
    result=dcent_eth_read(io,base+0x1014,&value);
    if(result) return result;
    if(value&0x2000) return DCENT_ETH_BUS_ERROR;
    if(!(value&0x7e0000)) { stopped=1; break; }
    io->delay(io->context,1);
  }
  if(!stopped) return DCENT_ETH_TIMEOUT;
  result=dcent_eth_read(io,base,&value);
  if(result) return result;
  if(value&12) return DCENT_ETH_FINAL;
  result=dcent_eth_read(io,base+0x1018,&value);
  if(result) return result;
  if(value&0x2002) return DCENT_ETH_FINAL;
  result=dcent_eth_read(io,base+0x101c,&value);
  if(result) return result;
  if(value) return DCENT_ETH_FINAL;
  result=dcent_eth_read(io,base+0x1000,&value);
  if(result) return result;
  if(value&1) return DCENT_ETH_FINAL;
  result=dcent_eth_read(io,base+0x1014,&value);
  if(result) return result;
  if(value&0x7e2000) return DCENT_ETH_FINAL;
  return 0;
}
#endif
