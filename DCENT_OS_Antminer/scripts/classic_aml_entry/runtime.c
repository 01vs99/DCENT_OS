/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Local direct-entry composition. The enclosing exact cold-loader/provenance
 * contract must establish the prerequisites that cannot be inferred from a
 * warm CPU snapshot: held BL31 lineage, no intervening secure crypto operation,
 * prior secondary cache retirement, remaining actor/memory custody and accepted
 * Device writes. A local ELF alone is not installer or physical-entry authority.
 */
#include "translation.h"
#include "entry-profile.h"
#include "device_io.h"
#include "peripheral_stop.h"
#include "affinity.h"
#include "handoff.h"

enum dcent_runtime_status {
  DCENT_RUNTIME_DEVICE_BEGIN=165, DCENT_RUNTIME_DEVICE_END=166,
  DCENT_RUNTIME_GEOMETRY_READ=167, DCENT_RUNTIME_TIMER=168,
  DCENT_RUNTIME_CPU_CHANGED=169
};

void *memcpy(void *destination,const void *source,unsigned long bytes) {
  volatile u8 *out=destination;
  const u8 *in=source;
  for(unsigned long index=0;index<bytes;++index) out[index]=in[index];
  return destination;
}
void *memset(void *destination,int value,unsigned long bytes) {
  volatile u8 *out=destination;
  for(unsigned long index=0;index<bytes;++index) out[index]=(u8)value;
  return destination;
}
static int dcent_table_read(void *unused,u64 address,u64 *value) {
  (void)unused;
  if(address<0x08000000 || address>0x10000000-8 || (address&7)) return 0;
  *value=*(const volatile u64 *)address;
  return 1;
}
static int dcent_runtime_cpu_unchanged(const struct dcent_context *saved) {
  struct dcent_context current;
  u64 daif;
  __asm__ volatile("mrs %0,CurrentEL\n\tmrs %1,SCTLR_EL2\n\tmrs %2,HCR_EL2\n\t"
                   "mrs %3,TCR_EL2\n\tmrs %4,S3_4_C2_C0_0\n\tmrs %5,MAIR_EL2\n\t"
                   "mrs %6,DAIF"
      : "=r"(current.current_el),"=r"(current.sctlr),"=r"(current.hcr),
        "=r"(current.tcr),"=r"(current.ttbr),"=r"(current.mair),"=r"(daif));
  return current.current_el==saved->current_el && current.sctlr==saved->sctlr &&
      current.hcr==saved->hcr && current.tcr==saved->tcr &&
      current.ttbr==saved->ttbr && current.mair==saved->mair && (daif&0x3c0)==0x3c0;
}
int dcent_bootstrap_validated(struct dcent_bootstrap_context *context) {
  struct dcent_admission *admitted=(void *)0x07820400;
  struct dcent_device_context *device=(void *)0x07820800;
  struct dcent_affinity_snapshot *affinity=(void *)0x07820880;
  int result=dcent_admission_memory(context,&profile,dcent_table_read,dcent_translate_el2,0,admitted);
  if(result) return result;
  result=dcent_admission_devices(&context->cpu,dcent_table_read,dcent_translate_el2,0);
  if(result) return result;
  /* Establish the primary and inactive-secondary observation before the first
   * peripheral operation. A second observation follows all device shutdowns. */
  result=dcent_affinity_read(affinity);
  if(result) return result;
  /* The returning timer component admits two observed source encodings.
   * This complete Linux entry uses the held cold BL31's exact 24 MHz value. */
  u64 frequency;
  __asm__ volatile("mrs %0,CNTFRQ_EL0" : "=r"(frequency));
  if(frequency!=24000000) return DCENT_RUNTIME_TIMER;
  if(!dcent_runtime_cpu_unchanged(&context->cpu)) return DCENT_RUNTIME_CPU_CHANGED;
  *device=(struct dcent_device_context){0};
  if(!dcent_device_begin(device)) return DCENT_RUNTIME_DEVICE_BEGIN;
  u32 size_word,secmon_start;
  if(!dcent_device_read(device,0xff80024c,&size_word) ||
     !dcent_device_read(device,0xff800254,&secmon_start))
    result=DCENT_RUNTIME_GEOMETRY_READ;
  else
    result=dcent_empty_bl32_geometry(size_word,secmon_start);
  if(!result) {
    const struct dcent_peripheral_io io={device,dcent_device_read,dcent_device_write,dcent_device_delay};
    result=dcent_peripheral_stop(&io);
  }
  if(!dcent_device_end(device)) return DCENT_RUNTIME_DEVICE_END;
  if(result) return result;
  /* SMC occurs only after the private EL2 MMIO vectors have been restored.
   * These five exact read-only PSCI queries are source-reviewed separately;
   * they neither invoke crypto nor request any CPU power-state change. */
  result=dcent_affinity_read(affinity);
  if(result) return result;
  if(!dcent_runtime_cpu_unchanged(&context->cpu)) return DCENT_RUNTIME_CPU_CHANGED;
  /* Early content admission allowed refusal before a device write. Repeat the
   * entire descriptor/resident/payload check after the stopped-device and
   * secondary-CPU observations. Under the stated complete actor custody,
   * memory remains immutable from this final check through the kernel branch. */
  result=dcent_admission_memory(context,&profile,dcent_table_read,dcent_translate_el2,0,admitted);
  if(result) return result;
  /* Return completely through the C epilogue before the assembly boundary
   * invokes cache/terminal handoff. Even a late terminal refusal must not spill
   * its return value to this C stack after the final cache clean. */
  return 0;
}
