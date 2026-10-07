//! Original cold-mode/address controls and terminal engine-control clear.
//! These registers are not an electrical rail cutoff. Raw-TW and DDR jobs have
//! distinct source paths; this module does not enable the DDR-job RUN mode.
use super::*;

const DHASH: u32 = 0x100;
const NONCE_CONTEXT_BASE: u32 = 0x110;
const JOB_START_BASE: u32 = 0x118;
const FIFO_CONTROL: u32 = 0x1c;
const DHASH_RUN: u32 = 0x40;
const COMMAND_SOURCE_STOP: u32 = 0x0040_0000;

/// Register observations after a native cold preparation. The +1c source bit
/// has no proved self-clear/flush semantics, so its readback is reported only.
#[derive(Debug, Clone, Copy)]
pub struct ColdEngineObservation {
    pub dhash: u32,
    pub fifo_control: u32,
    /// The original +110 setter has no readback; do not invent readable ABI.
    pub nonce_context_base_commanded: u32,
    pub job_start_base: u32,
}

/// Terminal software-control readbacks. Neither boolean proves stopped ASIC
/// clocks, a drained hardware FIFO, reset assertion or removal of rail power.
#[derive(Debug, Default)]
pub struct EngineStopReport {
    pub command_bit22_clear: bool,
    pub dhash_bit6_clear: bool,
    pub errors: Vec<String>,
}
impl EngineStopReport {
    pub fn controls_clear(&self) -> bool {
        self.command_bit22_clear && self.dhash_bit6_clear && self.errors.is_empty()
    }
}

impl Transport<NativeMmio> {
    /// Bind exact current-kernel reserved addresses before cold ASIC setup.
    /// The reservation comes from this retained mapping, never caller numbers.
    /// Runtime owns reset/power/epoch ordering and the later raw-work mode.
    pub fn prepare_cold_engine(&self, deadline: Instant) -> Result<ColdEngineObservation, String> {
        let reserved = self.registers.dma;
        self.prepare_cold_engine_at(reserved.physical_base(), reserved.bytes(), deadline)
    }
}

impl<R: Registers> Transport<R> {
    pub(super) fn checked_engine_write(
        &self,
        offset: u32,
        value: u32,
        mask: u32,
        deadline: Instant,
        terminal: bool,
    ) -> Result<u32, String> {
        if Instant::now() >= deadline || (!terminal && self.terminal()) {
            return Err("BM1391 engine control is closed or expired".into());
        }
        self.registers.write(offset, value)?;
        let observed = self.registers.read(offset)?;
        if observed & mask != value & mask {
            return Err(format!(
                "BM1391 engine register {offset:#x} readback mismatch"
            ));
        }
        if Instant::now() >= deadline || (!terminal && self.terminal()) {
            return Err("BM1391 engine readback completed after closure".into());
        }
        Ok(observed)
    }

    fn prepare_cold_engine_at(
        &self,
        base: u32,
        bytes: u32,
        deadline: Instant,
    ) -> Result<ColdEngineObservation, String> {
        if base != dma::DMA_BASE || bytes != dma::DMA_BYTES {
            return Err("BM1391 cold engine requires the exact retained DDR profile".into());
        }
        self.with_asic_lane(deadline, || {
            self.active(deadline)?;
            // The original cold mask preserves RUN. Explicitly clear it before
            // publishing addresses; never infer a reset value from file data.
            let previous = self.registers.read(DHASH)?;
            self.checked_engine_write(DHASH, previous & !DHASH_RUN, DHASH_RUN, deadline, false)?;
            self.active(deadline)?;
            self.registers.write(NONCE_CONTEXT_BASE, base)?;
            let job_start_base = self.checked_engine_write(
                JOB_START_BASE,
                base + 0x20_0000,
                u32::MAX,
                deadline,
                false,
            )?;
            // Source S15 56bf0 / T15 cold caller: clear bits5,8..11,15,
            // then set 0x8100. Bit7 is ignored by the original DHASH setter's
            // comparison; native likewise never treats it as stable storage.
            let current = self.registers.read(DHASH)?;
            let desired = (current & 0xffff_70df & !DHASH_RUN) | 0x8100;
            let dhash = self.checked_engine_write(DHASH, desired, !0x80, deadline, false)?;
            self.active(deadline)?;
            let fifo = self.registers.read(FIFO_CONTROL)? | 0x1_0000;
            self.registers.write(FIFO_CONTROL, fifo)?;
            let fifo_control = self.registers.read(FIFO_CONTROL)?;
            self.active(deadline)?;
            Ok(ColdEngineObservation {
                dhash,
                fifo_control,
                nonce_context_base_commanded: base,
                job_start_base,
            })
        })
    }

    /// Latch before waiting for the ASIC lane, then attempt both independent
    /// source shutdown clears even when the first fails. Management remains
    /// independently serviceable for the subsequent PIC terminal-off attempt.
    /// Callers retain the transport until all actors and lanes are drained.
    pub fn terminal_stop_engine(&self, deadline: Instant) -> EngineStopReport {
        self.latch_terminal();
        let mut report = EngineStopReport::default();
        let _lane = match self.lock_until(deadline) {
            Ok(lane) => lane,
            Err(error) => {
                report.errors.push(error);
                return report;
            }
        };
        for (offset, bit) in [(COMMAND_CONTROL, COMMAND_SOURCE_STOP), (DHASH, DHASH_RUN)] {
            let result = (|| {
                if Instant::now() >= deadline {
                    return Err("BM1391 engine stop expired".into());
                }
                let previous = self.registers.read(offset)?;
                self.checked_engine_write(offset, previous & !bit, bit, deadline, true)
            })();
            match result {
                Ok(_) if offset == COMMAND_CONTROL => report.command_bit22_clear = true,
                Ok(_) => report.dhash_bit6_clear = true,
                Err(error) => report.errors.push(error),
            }
        }
        report
    }
}

#[cfg(test)]
#[path = "stock_bm1391_engine_tests.rs"]
mod tests;
