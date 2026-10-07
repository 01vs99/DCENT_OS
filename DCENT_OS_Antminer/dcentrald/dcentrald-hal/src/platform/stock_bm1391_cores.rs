//! Native stock BM1391 core warmup/configuration/opening, with bounded waits.
use super::*;

impl<R: Registers> Transport<R> {
    /// Complete source mode1 wrappers around warmup, configuration and opening.
    /// The caller first prepares the retained cold engine and admits power,
    /// cooling, census and PLL. One ASIC lane covers every control and frame.
    /// This never starts the DDR RUN engine or claims physical hashing.
    pub async fn initialize_cores_in_cold_engine(
        self: &Arc<Self>,
        chain: u8,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut cancellation = AsyncCancellation::new(self.clone());
        let owner = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            owner.initialize_cores_cold_with_delay(chain, deadline, |milliseconds| {
                let until = Instant::now() + Duration::from_millis(milliseconds);
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
        .map_err(|e| format!("BM1391 cold core-opening worker: {e}"));
        if result.is_err() {
            self.latch_terminal();
        }
        cancellation.complete();
        result?
    }

    /// Inner-stage compatibility/oracle API. Full runtime uses
    /// initialize_cores_in_cold_engine to include the global FPGA wrappers.
    /// This executes the three original core
    /// stages with their100ms/10ms intervening settles. The stock default core
    /// mode04 is pinned from both original files; no stock process is launched.
    pub async fn initialize_cores(
        self: &Arc<Self>,
        chain: u8,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut cancellation = AsyncCancellation::new(self.clone());
        let owner = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            owner.initialize_cores_with_delay(chain, deadline, |milliseconds| {
                let until = Instant::now() + Duration::from_millis(milliseconds);
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
        .map_err(|e| format!("BM1391 core-opening worker: {e}"));
        if result.is_err() {
            self.latch_terminal();
        }
        cancellation.complete();
        result?
    }

    fn initialize_cores_with_delay(
        &self,
        chain: u8,
        deadline: Instant,
        delay: impl FnMut(u64) -> Result<(), String>,
    ) -> Result<(), String> {
        self.initialize_core_stages_with_delay(chain, deadline, false, delay)
    }

    fn initialize_cores_cold_with_delay(
        &self,
        chain: u8,
        deadline: Instant,
        delay: impl FnMut(u64) -> Result<(), String>,
    ) -> Result<(), String> {
        self.initialize_core_stages_with_delay(chain, deadline, true, delay)
    }

    fn initialize_core_stages_with_delay(
        &self,
        chain: u8,
        deadline: Instant,
        cold_engine: bool,
        mut delay: impl FnMut(u64) -> Result<(), String>,
    ) -> Result<(), String> {
        if !self.chains.contains(&chain) {
            return Err("BM1391 core opening is outside the retained population".into());
        }
        self.with_asic_lane(deadline, || {
            if cold_engine {
                // S15 4536c / T15 453a0, third argument1: cold mask, HCN0.
                self.core_engine_enter_locked(false, deadline)?;
            }
            self.core_rounds_locked(chain, 5, false, cold_engine, deadline, &mut delay)?;
            if cold_engine {
                self.core_engine_restore_locked(deadline)?;
            }
            delay(100)?;
            self.active(deadline)?;
            if cold_engine {
                self.core_engine_mode_locked(deadline)?;
            }
            // Original S15 45748/T15 4577c builds the7c4cc/7c494 structure.
            // Its file-initialized core mode atB5BA0+199 is04 in both sources.
            self.publish_command_locked(
                chain,
                &Self::register_frame(0, true, 0x3c, 0x8000_8004),
                deadline,
            )?;
            delay(10)?;
            self.active(deadline)?;
            if cold_engine {
                // S15 459d0 / T15 45a04, first argument1 and file mode1.
                self.core_engine_enter_locked(true, deadline)?;
            }
            self.core_rounds_locked(chain, 64, true, cold_engine, deadline, &mut delay)?;
            if cold_engine {
                self.core_engine_restore_locked(deadline)?;
            }
            Ok(())
        })
    }

    fn core_engine_mode_locked(&self, deadline: Instant) -> Result<u32, String> {
        self.active(deadline)?;
        let mode = self.registers.read(0x100)?;
        // The ignored bit7 may change. Require mode1, bit15 set, DDR select
        // bit5 and RUN bit6 clear; preserve unrelated control bits.
        if mode & 0x8f60 != 0x8100 {
            return Err("BM1391 core setup requires observed cold mode1 with RUN clear".into());
        }
        self.active(deadline)?;
        Ok(mode)
    }

    fn core_engine_enter_locked(&self, opening: bool, deadline: Instant) -> Result<(), String> {
        let previous = self.core_engine_mode_locked(deadline)?;
        let mask = if opening { !0x8020 } else { !0x8f20 };
        self.checked_engine_write(0x100, (previous & mask) | 0x8100, !0x80, deadline, false)?;
        self.checked_engine_write(0x90, 0, u32::MAX, deadline, false)?;
        Ok(())
    }

    fn core_engine_restore_locked(&self, deadline: Instant) -> Result<(), String> {
        let previous = self.core_engine_mode_locked(deadline)?;
        // Both original files initialize B4E30 to1. This restores that source
        // mode by OR, not an arbitrary saved/previous DDR or RUN configuration.
        self.checked_engine_write(0x100, previous | 0x8100, !0x80, deadline, false)?;
        Ok(())
    }

    fn core_rounds_locked(
        &self,
        chain: u8,
        rounds: u8,
        opening: bool,
        cold_engine: bool,
        deadline: Instant,
        delay: &mut impl FnMut(u64) -> Result<(), String>,
    ) -> Result<(), String> {
        for index in 0..rounds {
            for group in 0..4 {
                if cold_engine {
                    self.core_engine_mode_locked(deadline)?;
                }
                let core = u32::from(index) | (group << 6);
                self.publish_command_locked(
                    chain,
                    &Self::register_frame(0, true, 0x3c, (core << 16) | 0x84aa),
                    deadline,
                )?;
                delay(5)?;
                self.active(deadline)?;
            }
            if opening {
                delay(5)?;
                self.active(deadline)?;
            }
            while self.registers.read(WORK_SPACE)? & (1 << chain) == 0 {
                delay(1)?;
                self.active(deadline)?;
            }
            self.active(deadline)?;
            if cold_engine {
                self.core_engine_mode_locked(deadline)?;
            }
            // This is the original dummy TW opcode01000080, not the normal
            // mining header01800000. All twelve following words are zero.
            self.registers
                .write(TW_FIRST, 0x0100_0080 | (u32::from(chain) << 16))?;
            for _ in 0..12 {
                self.registers.write(TW_NEXT, 0)?;
            }
            delay(if opening { 10 } else { 20 })?;
            self.active(deadline)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "stock_bm1391_cores_engine_tests.rs"]
mod engine_tests;

#[cfg(test)]
mod tests {
    use super::super::tests::{deadline, sample_work, RecordingRegisters};
    use super::*;

    #[test]
    fn complete_native_core_opening_matches_all_18_original_stages_and_settles() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../../"
        )).unwrap();
        let mut stores = 0;
        for release in oracle["releases"].as_array().unwrap() {
            for chain in 0..3 {
                let registers = Arc::new(RecordingRegisters::default());
                let owner = Transport::new(registers.clone(), vec![chain]).unwrap();
                owner
                    .initialize_cores_with_delay(chain, deadline(), |ms| {
                        assert!(owner.lane.try_lock().is_err());
                        registers
                            .state
                            .lock()
                            .unwrap()
                            .events
                            .push(serde_json::json!({"delay_us": ms * 1000}));
                        Ok(())
                    })
                    .unwrap();
                let mut expected = Vec::new();
                for stage in ["pre_open", "configure", "open"] {
                    let vector = release["vectors"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|v| v["chain"] == chain && v["stage"] == stage)
                        .unwrap();
                    expected.extend(vector["events"].as_array().unwrap().iter().cloned());
                    if stage == "pre_open" {
                        expected.push(serde_json::json!({"delay_us": 100000}));
                    }
                    if stage == "configure" {
                        expected.push(serde_json::json!({"delay_us": 10000}));
                    }
                }
                let state = registers.state.lock().unwrap();
                assert_eq!(state.events, expected);
                assert_eq!(state.writes.len(), 2005);
                stores += state.writes.len();
                assert!(!owner.terminal());
            }
        }
        assert_eq!(stores, 12030);
    }

    #[test]
    fn partial_core_command_or_dummy_frame_never_retries_or_advances() {
        let failures =
            (0..29).chain([144, 145, 146, 147, 148, 149, 150, 151, 152, 177, 1992, 2004]);
        for failure in failures {
            let registers = Arc::new(RecordingRegisters::default());
            registers.state.lock().unwrap().fail_at = Some(failure);
            let owner = Transport::new(registers.clone(), vec![0]).unwrap();
            assert!(owner
                .initialize_cores_with_delay(0, deadline(), |_| Ok(()))
                .is_err());
            assert!(owner.terminal());
            assert!(owner.publish_work(&sample_work(0), deadline()).is_err());
            assert_eq!(registers.state.lock().unwrap().writes.len(), failure);
        }
    }

    #[test]
    fn unavailable_dummy_fifo_and_terminal_settles_stop_without_dummy_publication() {
        for unavailable in [false, true] {
            let registers = Arc::new(RecordingRegisters {
                space: if unavailable { 0 } else { 1 },
                ..Default::default()
            });
            let owner = Transport::new(registers.clone(), vec![0]).unwrap();
            assert!(owner
                .initialize_cores_with_delay(0, deadline(), |ms| {
                    if !unavailable || ms == 1 {
                        owner.latch_terminal();
                    }
                    Ok(())
                })
                .is_err());
            assert!(owner.terminal());
            let state = registers.state.lock().unwrap();
            assert!(!state.writes.iter().any(|(offset, _)| *offset == TW_FIRST));
            assert_eq!(state.writes.len(), if unavailable { 16 } else { 4 });
        }
    }

    #[tokio::test]
    async fn actual_async_core_opening_honors_deadline_before_dummy_work() {
        let registers = Arc::new(RecordingRegisters::default());
        let owner = Transport::new(registers.clone(), vec![0]).unwrap();
        let start = Instant::now();
        assert!(owner
            .initialize_cores(0, start + Duration::from_millis(10))
            .await
            .is_err());
        assert!(start.elapsed() < Duration::from_millis(200));
        assert!(owner.terminal());
        assert!(!registers
            .state
            .lock()
            .unwrap()
            .writes
            .iter()
            .any(|(offset, _)| *offset == TW_FIRST));
    }
}
