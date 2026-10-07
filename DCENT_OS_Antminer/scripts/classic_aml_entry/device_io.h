/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Internal composition of reviewed EL2 MMIO and source-bound counter delay.
 */
#ifndef DCENT_CLASSIC_DEVICE_IO_H
#define DCENT_CLASSIC_DEVICE_IO_H
#include "mmio.h"
#include "timer.h"
struct dcent_device_context {
  struct dcent_mmio_context mmio;
  struct dcent_timer_context timer;
};
static int dcent_device_begin(struct dcent_device_context *context) {
  if(context->timer.ready || context->timer.failed) return 0;
  if(!dcent_mmio_begin(&context->mmio)) return 0;
  if(dcent_timer_begin(&context->timer)) {
    context->mmio.active=2;context->mmio.fault_kind=3;
    (void)dcent_mmio_end(&context->mmio);
    return 0;
  }
  return 1;
}
static int dcent_device_read(void *opaque,u64 address,u32 *value) {
  struct dcent_device_context *context=opaque;
  if(context->timer.ready!=1 || context->timer.failed) return 0;
  return dcent_mmio_read32(&context->mmio,address,value);
}
static int dcent_device_write(void *opaque,u64 address,u32 value) {
  struct dcent_device_context *context=opaque;
  if(context->timer.ready!=1 || context->timer.failed) return 0;
  return dcent_mmio_write32(&context->mmio,address,value);
}
static void dcent_device_delay(void *opaque,u32 microseconds) {
  struct dcent_device_context *context=opaque;
  if(context->mmio.active!=1) return;
  if(dcent_timer_delay(&context->timer,microseconds)) {
    /* Fault kind3 means source timer refusal; retain its exact status in the
     * timer context. Every later read/write refuses before register access. */
    context->mmio.active=2;context->mmio.fault_kind=3;
  }
}
static int dcent_device_end(struct dcent_device_context *context) {
  return dcent_mmio_end(&context->mmio);
}
/* Same A53 EL2/owned-memory/DAIF/Device-translation/no-competing-writer
 * prerequisites as mmio.h. One fresh zeroed context, no reuse after refusal.
 * Caller admits exact target registers and board clock/access profile.
 * This wrapper confers no storage, DMA completion or kernel-entry authority. */
#endif
