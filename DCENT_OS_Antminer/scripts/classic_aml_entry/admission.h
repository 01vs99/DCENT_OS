/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Returning memory/content admission for the exact Classic direct-entry data.
 */
#ifndef DCENT_CLASSIC_ADMISSION_H
#define DCENT_CLASSIC_ADMISSION_H
#include "bootstrap.h"
#include "contract.h"
#include "cache.h"

enum dcent_admission_status {
  DCENT_ADMISSION_CONTEXT=162, DCENT_ADMISSION_CALLER=163,
  DCENT_ADMISSION_OVERLAP=164
};
struct dcent_admission_profile {
  u8 descriptor_sha[32], resident_sha[32];
  struct dcent_relocation resident_relocations[9];
};
struct dcent_admission {
  struct dcent_descriptor descriptor;
  struct dcent_cache_ranges cache;
  u64 resident;
};
_Static_assert(sizeof(struct dcent_admission)==312,"admission snapshot size");

static int dcent_empty_bl32_geometry(u32 size_word,u32 secmon_start) {
  /* Exact held FIP has BL32 size zero. Original BL2 then leaves AO_SECOS_START
   * untouched, so that unused register is neither read nor constrained here.
   * A retained nonzero low16 size is refused; it does not describe this route. */
  return size_word==0x0c000000U && secmon_start==0x05000000U
      ?0:DCENT_BAD_GEOMETRY;
}

static int dcent_admission_devices(const struct dcent_context *cpu,
                                   dcent_read64 read,dcent_translate translate,void *opaque) {
  /* Complete page set of the accepted AO/HIU, B-MMC/C-NAND, Ethernet,
   * DWC3 host and DWC2 device compositions, including dynamic xHCI offsets
   * bounded by CAPLENGTH<=0xfc. This performs no peripheral register read. */
  static const u64 pages[9]={0xff800000,0xff63c000,0xffe05000,0xffe07000,
    0xff3f0000,0xff3f1000,0xff500000,0xff50c000,0xff400000};
  for(u32 index=0;index<9;++index) {
    int result=dcent_identity_address(cpu,read,translate,opaque,pages[index]);
    if(result) return result;
  }
  return 0;
}

static int dcent_admission_memory(const struct dcent_bootstrap_context *context,
                                  const struct dcent_admission_profile *profile,
                                  dcent_read64 read,dcent_translate translate,void *opaque,
                                  struct dcent_admission *output) {
  /* Bootstrap has already proved its entire owned code/context/stack mapping
   * before entering C. Profiles are immutable compiled constants in that span.
   * This fixed output is inside the separately writable context page. */
  if((u64)context!=0x07820000 || (u64)output!=0x07820400)
    return DCENT_ADMISSION_CONTEXT;
  int result=dcent_translation_profile(&context->cpu);
  if(result) return result;
  /* The exact source go trampoline uses BR and preserves its caller's LR.
   * Complete source go returns at relocated base+0x5e4c. No scan or resident
   * helper is invoked, and a plausible LR still requires full prefix hashing. */
  if(context->caller_lr<DCENT_RESIDENT_FIRST+0x5e4c ||
     context->caller_lr>=DCENT_RESIDENT_LIMIT+0x5e4c)
    return DCENT_ADMISSION_CALLER;
  u64 resident=context->caller_lr-0x5e4c;
  if(resident&4095) return DCENT_ADMISSION_CALLER;
  const struct dcent_descriptor *descriptor=(const void *)0x07810000;
  result=dcent_identity_span(&context->cpu,read,translate,opaque,
                            (struct dcent_span){0x07810000,0x07810100});
  if(result) return result;
  result=dcent_descriptor_check(descriptor,profile->descriptor_sha);
  if(result) return result;
  const struct dcent_span spans[8]={
    {descriptor->kernel_address,descriptor->kernel_address+descriptor->kernel_effective_bytes},
    {descriptor->initrd_address,descriptor->initrd_address+descriptor->initrd_bytes},
    {descriptor->fdt_address,descriptor->fdt_address+descriptor->fdt_bytes},
    {0x05000000,0x05400000}, {0x07400000,0x07500000},
    {DCENT_ENTRY_BASE,0x07822000},
    {resident,resident+DCENT_RESIDENT_PREFIX},
    /* MMU-off entry has no active table reservation. This final span is used
     * only when M=1, after the source table bounds have been independently
     * validated by the first descriptor translation above. */
    {context->cpu.ttbr,context->cpu.ttbr+65536}
  };
  u32 count=(context->cpu.sctlr&1)?8:7;
  for(u32 index=0;index<count;++index) {
    if(!dcent_span_valid(spans[index])) return DCENT_ADMISSION_OVERLAP;
    for(u32 previous=0;previous<index;++previous)
      if(!dcent_disjoint(spans[index],spans[previous])) return DCENT_ADMISSION_OVERLAP;
  }
  /* Reserved secure/ramoops spans are never dereferenced. Every page of each
   * payload's effective extent, resident prefix and owned entry storage is
   * admitted before the first content read in those spans. */
  const u32 checked[5]={0,1,2,5,6};
  for(u32 index=0;index<5;++index) {
    result=dcent_identity_span(&context->cpu,read,translate,opaque,spans[checked[index]]);
    if(result) return result;
  }
  result=dcent_resident_digest((const u8 *)resident,resident,
                              profile->resident_relocations,9,profile->resident_sha);
  if(result) return result;
  result=dcent_payload_check(descriptor);
  if(result) return result;
  struct dcent_admission admitted;
  admitted.descriptor=*descriptor;
  admitted.cache=(struct dcent_cache_ranges){spans[0].start,spans[0].end,
    spans[1].start,spans[1].end,spans[2].start,spans[2].end};
  admitted.resident=resident;
  *output=admitted;
  return 0;
}
/* This component performs no peripheral or secure call and never branches to
 * Linux. Its snapshot is descriptive, not an aggregate entry permit. Caller
 * owns the immutable profile, executable code, writable context/stack and all
 * memory while read; bootstrap first-instruction/cache visibility and exact
 * physical board/cold lineage remain caller obligations. Payload, descriptor
 * and resident content must be rechecked after all relevant DMA/writers are
 * quiescent before final cache/handoff composition. No successful early hash
 * permits later modification between the final check and kernel entry. */
#endif
