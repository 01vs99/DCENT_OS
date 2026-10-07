//! Exact FPGA reset, timeout and ASIC/controller baud controls.
//! Original complete functions are replayed in the R04 control vectors.
use super::*;
use dcentrald_common::bm1391_stock_return::Bm1391StockRegisterReturn;

const RESET: u32 = 0x34;
const TIMEOUT: u32 = 0x88;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupBaud {
    Cold,
    Operational,
}
impl StartupBaud {
    pub(super) fn code(self) -> u32 {
        match self {
            Self::Cold => 0x1a,
            Self::Operational => 0,
        }
    }
}

impl<R: Registers> Transport<R> {
    /// Complete stock population transition: every selected ASIC chain changes
    /// first at the old controller rate, then one50ms settle and one global
    /// controller switch. Caller owns current-epoch reply freshness and has
    /// established that every ASIC on each broadcast chain shares this MiscCtrl.
    /// Require one checked, identical MiscCtrl observation per retained chain,
    /// in retained order; a lone reply cannot establish per-chip uniformity.
    pub async fn set_population_asic_and_fpga_baud(
        self: &Arc<Self>,
        observed_misc: Vec<Bm1391StockRegisterReturn>,
        baud: StartupBaud,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut cancellation = AsyncCancellation::new(self.clone());
        let owner = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            owner.set_population_baud_with_delay(&observed_misc, baud, deadline, || {
                let until = Instant::now() + Duration::from_millis(50);
                loop {
                    owner.active(deadline)?;
                    let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                        return Ok(());
                    };
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            })
        })
        .await
        .map_err(|e| format!("BM1391 population baud worker: {e}"));
        if result.is_err() {
            self.latch_terminal();
        }
        cancellation.complete();
        result?
    }

    fn set_population_baud_with_delay(
        &self,
        observed: &[Bm1391StockRegisterReturn],
        baud: StartupBaud,
        deadline: Instant,
        mut delay: impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let Some(first) = observed.first() else {
            return Err("BM1391 population baud has no observations".into());
        };
        if observed.len() != self.chains.len()
            || observed.iter().zip(&self.chains).any(|(reply, chain)| {
                reply.chain_slot != *chain
                    || reply.register != 0x18
                    || reply.value != first.value
                    || !census::response_crc_valid(*reply)
            })
        {
            return Err(
                "BM1391 population baud requires ordered uniform checked MiscCtrl observations"
                    .into(),
            );
        }
        self.with_asic_lane(deadline, || {
            self.set_population_baud_locked(observed, baud, deadline, &mut delay)
        })
    }

    // Only validated observations may enter here. The startup observer retains
    // the same ASIC guard across its full read/join and this complete switch.
    pub(super) fn set_population_baud_locked(
        &self,
        observed: &[Bm1391StockRegisterReturn],
        baud: StartupBaud,
        deadline: Instant,
        delay: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let first = observed
            .first()
            .ok_or("BM1391 population baud has no observations")?;
        self.active(deadline)?;
        let initial = self.registers.read(COMMAND_CONTROL)?;
        let old_code = initial & 0x3f;
        if initial & 0x8000_0000 != 0 || old_code != (first.value >> 8) & 0x1f {
            return Err(
                "BM1391 population baud controller does not match the observed ASIC rate".into(),
            );
        }
        let code = baud.code();
        let value = (first.value & !0x1f00) | ((code & 0x1f) << 8);
        // Source439e0/43a00 calls every7bedc/7bea4 with host-switch flag0.
        for reply in observed {
            self.active(deadline)?;
            if self.registers.read(COMMAND_CONTROL)? & 0x3f != old_code {
                return Err("BM1391 controller rate changed during population broadcast".into());
            }
            self.publish_command_locked(
                reply.chain_slot,
                &Self::register_frame(0, true, 0x18, value),
                deadline,
            )?;
        }
        delay()?;
        self.active(deadline)?;
        let previous = self.registers.read(COMMAND_CONTROL)?;
        if previous & 0x8000_0000 != 0 || previous & 0x3f != old_code {
            return Err(
                "BM1391 command is active or its rate changed before the global switch".into(),
            );
        }
        self.registers
            .write(COMMAND_CONTROL, (previous & !0x3f) | code)?;
        self.active(deadline)?;
        if self.registers.read(COMMAND_CONTROL)? & 0x3f != code {
            return Err("BM1391 population controller baud readback mismatch".into());
        }
        Ok(())
    }

    /// Original S15 87310 / T15 87230 sets or clears one +34 bit while
    /// preserving every other bit. This is FPGA reset signaling, not PIC reset
    /// or an electrical power cut. Runtime owns the reset/settle lifecycle.
    pub fn set_chain_reset_level(
        &self,
        chain: u8,
        high: bool,
        deadline: Instant,
    ) -> Result<(), String> {
        if !self.chains.contains(&chain) {
            return Err("BM1391 reset is outside the retained population".into());
        }
        self.with_asic_lane(deadline, || {
            self.active(deadline)?;
            let previous = self.registers.read(RESET)?;
            let bit = 1 << chain;
            let desired = if high {
                previous | bit
            } else {
                previous & !bit
            };
            self.registers.write(RESET, desired)?;
            self.active(deadline)?;
            if self.registers.read(RESET)? != desired {
                return Err("BM1391 FPGA reset register readback mismatch".into());
            }
            Ok(())
        })
    }

    /// Original S15 87bf0 / T15 87b10 writes +88 and reads it back.
    /// The source enables bit31 and masks a 17-bit count. Units and selection
    /// belong to the exact runtime recipe; this argument is not milliseconds.
    pub fn set_work_timeout_ticks(&self, ticks: u32, deadline: Instant) -> Result<(), String> {
        if ticks == 0 || ticks > 0x1ffff {
            return Err("BM1391 enabled timeout requires a nonzero 17-bit count".into());
        }
        self.with_asic_lane(deadline, || {
            self.active(deadline)?;
            let desired = 0x8000_0000 | ticks;
            self.registers.write(TIMEOUT, desired)?;
            self.active(deadline)?;
            if self.registers.read(TIMEOUT)? != desired {
                return Err("BM1391 timeout register readback mismatch".into());
            }
            Ok(())
        })
    }

    /// Single-chain source helper; full runtime changes the population through
    /// set_population_asic_and_fpga_baud. Calling this successively for several
    /// chains would change the global controller rate after the first chain.
    /// Original ASIC register18 broadcast followed by 50ms settling and the
    /// controller's low-six-bit selector. Require a checked register18 reply
    /// from this chain to preserve its other configuration bits (including the
    /// thermal bridge); a caller-owned current startup epoch is still required
    /// because the wire has no request ID. All chips on this broadcast chain
    /// must already share the admitted MiscCtrl configuration.
    pub async fn set_asic_and_fpga_baud(
        self: &Arc<Self>,
        observed_misc: Bm1391StockRegisterReturn,
        baud: StartupBaud,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut cancellation = AsyncCancellation::new(self.clone());
        let owner = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            owner.set_baud_with_delay(observed_misc, baud, deadline, || {
                let until = Instant::now() + Duration::from_millis(50);
                loop {
                    owner.active(deadline)?;
                    let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                        return Ok(());
                    };
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            })
        })
        .await
        .map_err(|e| format!("BM1391 baud worker: {e}"));
        if result.is_err() {
            self.latch_terminal();
        }
        cancellation.complete();
        result?
    }

    fn set_baud_with_delay(
        &self,
        observed: Bm1391StockRegisterReturn,
        baud: StartupBaud,
        deadline: Instant,
        mut delay: impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        if !self.chains.contains(&observed.chain_slot)
            || observed.register != 0x18
            || !census::response_crc_valid(observed)
        {
            return Err("BM1391 baud requires a checked selected-chain MiscCtrl reply".into());
        }
        self.with_asic_lane(deadline, || {
            let code = baud.code();
            let value = (observed.value & !0x1f00) | ((code & 0x1f) << 8);
            self.publish_command_locked(
                observed.chain_slot,
                &Self::register_frame(0, true, 0x18, value),
                deadline,
            )?;
            delay()?;
            self.active(deadline)?;
            let previous = self.registers.read(COMMAND_CONTROL)?;
            if previous & 0x8000_0000 != 0 {
                return Err("BM1391 command remained active during baud switch".into());
            }
            let desired = (previous & !0x3f) | code;
            self.registers.write(COMMAND_CONTROL, desired)?;
            self.active(deadline)?;
            if self.registers.read(COMMAND_CONTROL)? & 0x3f != code {
                return Err("BM1391 controller baud readback mismatch".into());
            }
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "stock_bm1391_controls_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stock_bm1391_controls_population_tests.rs"]
mod population_tests;
