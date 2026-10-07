/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Fixed descriptor and content validation; no DMA/CPU handoff authority.
 */
#ifndef DCENT_CLASSIC_CONTRACT_H
#define DCENT_CLASSIC_CONTRACT_H
#include "preflight.h"

enum dcent_contract_status {
  DCENT_BAD_DESCRIPTOR=16, DCENT_BAD_PAYLOAD_RANGE=17, DCENT_BAD_KERNEL=18,
  DCENT_BAD_INITRD=19, DCENT_BAD_FDT=20
};
struct dcent_descriptor {
  u8 magic[8];
  u32 version, size;
  u64 kernel_address, kernel_file_bytes, kernel_effective_bytes;
  u64 initrd_address, initrd_bytes, fdt_address, fdt_bytes, dram_end;
  u8 kernel_sha[32], initrd_sha[32], fdt_sha[32], bootargs_sha[32], candidate_sha[32];
  u8 reserved[16];
};
_Static_assert(sizeof(struct dcent_descriptor)==256,"descriptor size differs");

static int dcent_sha_matches(const u8 *bytes, u64 count, const u8 expected[32]) {
  u8 actual[32];
  sha256(bytes,count,actual);
  u32 difference=0;
  for(u32 i=0;i<32;++i) difference|=actual[i]^expected[i];
  return difference==0;
}
static int dcent_descriptor_check(const struct dcent_descriptor *d, const u8 expected_sha[32]) {
  if (!dcent_sha_matches((const u8 *)d,sizeof(*d),expected_sha)) return DCENT_BAD_DESCRIPTOR;
  static const u8 magic[8]={'D','C','E','2','C','L','0','1'};
  for(u32 i=0;i<8;++i) if(d->magic[i]!=magic[i]) return DCENT_BAD_DESCRIPTOR;
  for(u32 i=0;i<16;++i) if(d->reserved[i]) return DCENT_BAD_DESCRIPTOR;
  if(d->version!=1 || d->size!=sizeof(*d) || d->dram_end!=DCENT_DRAM_END) return DCENT_BAD_DESCRIPTOR;
  if(d->kernel_address!=0x01080000 || d->kernel_file_bytes!=14960648 ||
     d->kernel_effective_bytes!=0x00f2b000) return DCENT_BAD_PAYLOAD_RANGE;
  if(d->initrd_bytes==0 || d->initrd_bytes>32*1024*1024 ||
     d->initrd_address!=((0x07400000-d->initrd_bytes)&~4095ULL)) return DCENT_BAD_PAYLOAD_RANGE;
  if(d->fdt_address!=0x056a2000 || d->fdt_bytes<72 || d->fdt_bytes>0x9000 ||
     d->fdt_address+d->fdt_bytes>d->initrd_address) return DCENT_BAD_PAYLOAD_RANGE;
  return DCENT_PREFLIGHT_OK;
}
static int dcent_payload_check(const struct dcent_descriptor *d) {
  /* Call only after the descriptor and all payload translations are checked.
   * The final FDT hash binds chosen, memory, reserved nodes and initrd ranges;
   * no resident environment or runtime FDT mutation is involved. */
  if(!dcent_sha_matches((const u8 *)d->kernel_address,d->kernel_file_bytes,d->kernel_sha)) return DCENT_BAD_KERNEL;
  if(!dcent_sha_matches((const u8 *)d->initrd_address,d->initrd_bytes,d->initrd_sha)) return DCENT_BAD_INITRD;
  if(!dcent_sha_matches((const u8 *)d->fdt_address,d->fdt_bytes,d->fdt_sha)) return DCENT_BAD_FDT;
  return DCENT_PREFLIGHT_OK;
}
#endif
