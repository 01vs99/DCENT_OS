/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Read-only runtime guards. A passing result is not a release/install permit.
 */
#ifndef DCENT_CLASSIC_PREFLIGHT_H
#define DCENT_CLASSIC_PREFLIGHT_H
#include "sha256.h"

#define DCENT_DRAM_END 0x10000000ULL
#define DCENT_ENTRY_BASE 0x07800000ULL
#define DCENT_ENTRY_END 0x07810000ULL
#define DCENT_RESIDENT_FIRST 0x0fea0000ULL
#define DCENT_RESIDENT_LIMIT 0x0feb0000ULL
#define DCENT_RESIDENT_PREFIX 0x00094000ULL

enum dcent_preflight_status {
  DCENT_PREFLIGHT_OK=0, DCENT_BAD_EL=1, DCENT_BAD_CPU_STATE=2,
  DCENT_BAD_MEMORY_RANGE=3, DCENT_BAD_TRANSLATION=4, DCENT_BAD_GEOMETRY=5,
  DCENT_BAD_RESIDENT=6, DCENT_BAD_RELOCATION=7, DCENT_BAD_DIGEST=8
};
struct dcent_span { u64 start, end; };
struct dcent_relocation { u32 offset; u64 addend; };
struct dcent_context { u64 current_el, sctlr, hcr, tcr, ttbr, mair; };
typedef int (*dcent_read64)(void *context, u64 address, u64 *value);
typedef int (*dcent_translate)(void *context, u64 address, u64 *par);

static int dcent_span_valid(struct dcent_span span) {
  return span.start<span.end && span.end<=DCENT_DRAM_END;
}
static int dcent_disjoint(struct dcent_span first, struct dcent_span second) {
  return first.end<=second.start || second.end<=first.start;
}
static int dcent_cpu_state(const struct dcent_context *cpu) {
  /* This initial entry profile is EL2 only. EL1 needs a separate stage-2 and
   * timer witness that cannot be read from EL1. VHE and stage-2 are refused. */
  if (cpu->current_el!=8) return DCENT_BAD_EL;
  if (cpu->hcr & ((1ULL<<34)|1)) return DCENT_BAD_CPU_STATE;
  if ((cpu->sctlr & 1) && !(cpu->sctlr & 4)) return DCENT_BAD_CPU_STATE;
  if (cpu->sctlr & (1ULL<<25)) return DCENT_BAD_CPU_STATE;
  return DCENT_PREFLIGHT_OK;
}
static int dcent_translation_profile(const struct dcent_context *cpu) {
  int result=dcent_cpu_state(cpu);
  if (result) return result;
  if (!(cpu->sctlr & 1)) return DCENT_PREFLIGHT_OK;
  if(cpu->tcr!=0x34516 || cpu->mair!=0xff440c0400ULL) return DCENT_BAD_TRANSLATION;
  return DCENT_PREFLIGHT_OK;
}
static int dcent_arch_identity_span(const struct dcent_context *cpu,
                                    dcent_translate translate, void *opaque,
                                    u64 start, u64 end) {
  int result=dcent_translation_profile(cpu);
  if(result) return result;
  if(start>=end || end>(1ULL<<42)) return DCENT_BAD_TRANSLATION;
  if(!(cpu->sctlr&1)) return DCENT_PREFLIGHT_OK;
  /* Ask the architecture about every 4 KiB subrange before trusting a virtual
   * pointer to physical memory. A self-consistent table read is insufficient:
   * the actual translation could alias an unrelated matching table. */
  for(u64 cursor=start&~4095ULL;cursor<end;cursor+=4096) {
    u64 par;
    /* PAR.NS is UNKNOWN for a Non-secure translation regime and cannot prove
     * caller security state. Preserve that as a separate caller obligation.
     * Device translations report Outer Shareable regardless of table SH. */
    if(!translate(opaque,cursor,&par) || (par&1) ||
       (par&0x000ffffffffff000ULL)!=cursor ||
       (par>>56)!=(cursor<DCENT_DRAM_END?0xff:0) ||
       ((par>>7)&3)!=(cursor<DCENT_DRAM_END?0:2)) return DCENT_BAD_TRANSLATION;
  }
  return DCENT_PREFLIGHT_OK;
}
static int dcent_identity_address(const struct dcent_context *cpu,
                                  dcent_read64 read, dcent_translate translate,
                                  void *opaque, u64 address) {
  int result=dcent_translation_profile(cpu);
  if(result) return result;
  if(!(cpu->sctlr&1)) return DCENT_PREFLIGHT_OK;
  /* Exact held resident at linked 0x01001300: one 64 KiB table, 8192
   * 512 MiB blocks, 42-bit VA. Its 256 MiB DRAM bank is rounded to one
   * normal-memory block. All other blocks have the source device attributes.
   * Refuse alternate layouts, aliases, changed permissions and descriptors. */
  if (cpu->tcr!=0x34516 || address>>42) return DCENT_BAD_TRANSLATION;
  u64 table=cpu->ttbr;
  if (table<0x08000000 || table>DCENT_DRAM_END-65536 || (table&65535))
    return DCENT_BAD_TRANSLATION;
  result=dcent_arch_identity_span(cpu,translate,opaque,table,table+65536);
  if(result) return result;
  result=dcent_arch_identity_span(cpu,translate,opaque,address,address+1);
  if(result) return result;
  u64 block=address>>29, descriptor;
  if (!read(opaque,table+block*8,&descriptor)) return DCENT_BAD_TRANSLATION;
  u64 expected=(block<<29)|(block==0?0x411:0x401);
  return descriptor==expected?DCENT_PREFLIGHT_OK:DCENT_BAD_TRANSLATION;
}
static int dcent_identity_span(const struct dcent_context *cpu,
                               dcent_read64 read, dcent_translate translate,
                               void *opaque, struct dcent_span span) {
  if (!dcent_span_valid(span)) return DCENT_BAD_MEMORY_RANGE;
  int result=dcent_arch_identity_span(cpu,translate,opaque,span.start,span.end);
  if(result) return result;
  u64 cursor=span.start&~((1ULL<<29)-1);
  while (cursor<span.end) {
    result=dcent_identity_address(cpu,read,translate,opaque,cursor);
    if (result) return result;
    cursor+=1ULL<<29;
  }
  return DCENT_PREFLIGHT_OK;
}
static int dcent_geometry(u32 size_word, u32 secmon_start, u32 secos_start) {
  /* Exact source BL31 profile: high half is BL31 KiB, low half BL32 KiB.
   * Larger/different layouts are valid firmware states but are not this entry
   * profile. A successful vendor rsvmem command is not an equivalent guard. */
  if (size_word!=0x0c000000 || secmon_start!=0x05000000 || secos_start!=0x05300000)
    return DCENT_BAD_GEOMETRY;
  return DCENT_PREFLIGHT_OK;
}
static int dcent_resident_digest(const u8 *prefix, u64 resident,
                                 const struct dcent_relocation *relocations, u32 count,
                                 const u8 expected_sha[32]) {
  if (resident<DCENT_RESIDENT_FIRST || resident>=DCENT_RESIDENT_LIMIT || (resident&4095))
    return DCENT_BAD_RESIDENT;
  if (count!=9) return DCENT_BAD_RELOCATION;
  struct sha256_state state;
  u32 cursor=0;
  sha256_init(&state);
  for (u32 index=0; index<count; ++index) {
    u32 offset=relocations[index].offset;
    u64 expected=relocations[index].addend+resident-0x01000000;
    if (offset<cursor || offset>DCENT_RESIDENT_PREFIX-8 || (offset&7)) return DCENT_BAD_RELOCATION;
    u64 actual=0;
    for (u32 byte=0; byte<8; ++byte) actual|=(u64)prefix[offset+byte]<<(8*byte);
    if (actual!=expected) return DCENT_BAD_RELOCATION;
    sha256_update(&state,prefix+cursor,offset-cursor);
    u8 canonical[8];
    for (u32 byte=0; byte<8; ++byte) canonical[byte]=(u8)(relocations[index].addend>>(8*byte));
    sha256_update(&state,canonical,8);
    cursor=offset+8;
  }
  sha256_update(&state,prefix+cursor,DCENT_RESIDENT_PREFIX-cursor);
  u8 actual_sha[32];
  sha256_final(&state,actual_sha);
  u32 difference=0;
  for (u32 byte=0; byte<32; ++byte) difference|=actual_sha[byte]^expected_sha[byte];
  return difference?DCENT_BAD_DIGEST:DCENT_PREFLIGHT_OK;
}
#endif
