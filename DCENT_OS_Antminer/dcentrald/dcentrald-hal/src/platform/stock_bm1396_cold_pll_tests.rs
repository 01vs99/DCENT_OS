use super::*;
use dcentrald_common::bm1396_contract::Bm1396SensorSamplingMode;
use startup_tests::{startup_hardware, StartupHardware};
use thermal_tests::ThermalHardware;

/// Both existing independent wire fixtures share one mapping and one actual
/// Transport claim. Upstream observations are acquired through production APIs.
struct ColdHardware {
    startup: Arc<StartupHardware>,
    thermal: Arc<ThermalHardware>,
    chains: Vec<u8>,
    active: AtomicBool,
    temperatures: AtomicBool,
    ticks: AtomicU32,
    emitted: AtomicU32,
    overflow: AtomicBool,
    voltage_frame: Mutex<Vec<u8>>,
    rail_frame: Mutex<Vec<u8>>,
    dac: AtomicU32,
    voltage_frames: AtomicU32,
    rail_frames: AtomicU32,
    bad_voltage_frame: AtomicU32,
    bad_rail_frame: AtomicU32,
    pll_commands: AtomicU32,
    fail_pll_command: AtomicU32,
    final_adc_failure: AtomicBool,
    busy_ticks: AtomicU32,
    delay_pll_ticks: AtomicU32,
    delay_adc_ticks: AtomicU32,
    thermal_raw: AtomicU32,
    thermal_reads: AtomicU32,
    shift_on_rail_wait: AtomicU32,
    busy_pause_ms: AtomicU32,
}
impl ColdHardware {
    fn inner(&self) -> &Arc<Fake> {
        &self.startup.inner
    }
}
impl Hardware for ColdHardware {
    fn model(&self) -> Model {
        self.inner().model()
    }
    fn validate_owner(&self) -> Result<(), String> {
        self.inner().validate_owner()
    }
    fn claim_transport(&self) -> Result<(), String> {
        self.inner().claim_transport()
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        if offset == BC && self.busy_ticks.load(Ordering::SeqCst) != 0 {
            return Ok(BUSY);
        }
        let value = self.startup.read(offset)?;
        if [0x10, 0x14].contains(&offset)
            && value == ((self.thermal_raw.load(Ordering::SeqCst) << 16) | 0x180)
        {
            self.thermal_reads.fetch_add(1, Ordering::SeqCst);
        }
        Ok(value)
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        if offset == BC && value & BUSY != 0 {
            let first = self.inner().regs.lock().unwrap()[&0xc4].to_be_bytes();
            if first[0] == 0x42 || (first[0] == 0x41 && [0x18, 0x54, 0x1c].contains(&first[3])) {
                return self.thermal.write(offset, value);
            }
            if self.active.load(Ordering::SeqCst) {
                if first[0] == 0x51 && first[3] == 8 {
                    let ordinal = self.pll_commands.fetch_add(1, Ordering::SeqCst) + 1;
                    if ordinal == self.fail_pll_command.load(Ordering::SeqCst) {
                        self.inner().write(offset, value)?;
                        return Err("injected PLL command completion failure".into());
                    }
                    if ordinal == 1 {
                        self.busy_ticks.store(
                            self.delay_pll_ticks.load(Ordering::SeqCst),
                            Ordering::SeqCst,
                        );
                    }
                }
                if [0x51, 0x52].contains(&first[0]) && [0xb0, 0xb4, 0xb8].contains(&first[3]) {
                    self.busy_ticks.store(
                        self.delay_adc_ticks.load(Ordering::SeqCst),
                        Ordering::SeqCst,
                    );
                }
                if first[0] == 0x52
                    && first[3] == 0xb4
                    && self.final_adc_failure.load(Ordering::SeqCst)
                {
                    self.startup.defect.store(28, Ordering::SeqCst);
                }
            }
            self.startup.write(offset, value)?;
            if first[0] == 0x51 && first[3] == 0x18 {
                let word = self.inner().regs.lock().unwrap()[&0xc8];
                let chain = ((value >> 16) & 15) as u8;
                for chip in [51, 36, 195, 180] {
                    self.thermal
                        .asic_registers
                        .lock()
                        .unwrap()
                        .insert((chain, chip, 0x18), word);
                }
            }
            return Ok(());
        }
        self.inner().write(offset, value)?;
        if offset == 0x30 && self.active.load(Ordering::SeqCst) {
            if value & 0xffff_ff00 == 0x0520_1100 {
                let mut frame = self.voltage_frame.lock().unwrap();
                frame.push(value as u8);
                if frame.len() == 8 {
                    assert_eq!(&frame[..4], &[0x55, 0xaa, 6, 0x83]);
                    self.dac.store(u32::from(frame[4]), Ordering::SeqCst);
                    let number = self.voltage_frames.fetch_add(1, Ordering::SeqCst) + 1;
                    if number == self.bad_voltage_frame.load(Ordering::SeqCst) {
                        frame[7] ^= 1;
                    }
                    self.inner().reply(&frame);
                    frame.clear();
                }
            } else if value & 0xfff8_ff00 == 0x0040_0000 {
                let mut frame = self.rail_frame.lock().unwrap();
                frame.push(value as u8);
                if frame.len() == 6 {
                    if frame[3] == 0x37 {
                        assert_eq!(&*frame, &[0x55, 0xaa, 4, 0x37, 0, 0x3b]);
                        // Independent original target/DAC and raw PIC goldens.
                        // Intermediate DAC frames do not trigger rail responses.
                        let raw: u16 = match self.dac.load(Ordering::SeqCst) {
                            12 => 840, // source2100cV
                            48 => 800, // source2000cV at calibration1800/temp48
                            45 => 804, // original complete T17e2010cV stepper/frame replay
                            other => panic!("unexpected completed source DAC {other}"),
                        };
                        let mut response = vec![
                            11,
                            0x37,
                            0,
                            0x12,
                            0x34,
                            (raw >> 8) as u8,
                            raw as u8,
                            2,
                            0xf8,
                        ];
                        let sum: u16 = response.iter().map(|&byte| u16::from(byte)).sum();
                        response.extend(sum.to_be_bytes());
                        let number = self.rail_frames.fetch_add(1, Ordering::SeqCst) + 1;
                        if number == self.bad_rail_frame.load(Ordering::SeqCst) {
                            response.truncate(3);
                        }
                        self.inner().reply(&response);
                    }
                    frame.clear();
                }
            }
        }
        Ok(())
    }
    fn read_dma(&self, offset: usize, out: &mut [u8]) -> Result<(), String> {
        self.inner().read_dma(offset, out)
    }
    fn write_dma(&self, offset: usize, bytes: &[u8]) -> Result<(), String> {
        self.inner().write_dma(offset, bytes)
    }
    fn barrier(&self) -> Result<(), String> {
        self.inner().barrier()
    }
    fn sleep(&self, duration: Duration) {
        self.inner().sleep(duration);
        if duration == Duration::from_secs(1)
            && self.active.load(Ordering::SeqCst)
            && self.pll_commands.load(Ordering::SeqCst) >= (8 * self.chains.len()) as u32
        {
            let mode = self.shift_on_rail_wait.load(Ordering::SeqCst);
            if mode != 0 {
                if mode == 1 {
                    self.shift_on_rail_wait.store(0, Ordering::SeqCst);
                }
                let next = if self.thermal_raw.load(Ordering::SeqCst) == 112 {
                    84
                } else {
                    112
                };
                self.thermal_raw.store(next, Ordering::SeqCst);
                let target =
                    self.thermal_reads.load(Ordering::SeqCst) + (4 * self.chains.len()) as u32;
                let end = Instant::now() + Duration::from_secs(5);
                while self.thermal_reads.load(Ordering::SeqCst) < target {
                    assert!(
                        Instant::now() < end,
                        "cold thermal change was not consumed by the ASIC worker"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        if duration == Duration::from_millis(1) && self.active.load(Ordering::SeqCst) {
            if self.busy_ticks.load(Ordering::SeqCst) != 0 {
                let pause = self.busy_pause_ms.swap(0, Ordering::SeqCst);
                if pause != 0 {
                    std::thread::sleep(Duration::from_millis(u64::from(pause)));
                }
            }
            let _ = self
                .busy_ticks
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |old| old.checked_sub(1));
            let tick = self.ticks.fetch_add(1, Ordering::SeqCst) + 1;
            if tick % 100 == 0 && self.temperatures.load(Ordering::SeqCst) {
                let mut words = Vec::new();
                for &chain in &self.chains {
                    for chip in [51, 36, 195, 180] {
                        words.extend([
                            u32::from_le_bytes([chain, 0x44, chip, 2]),
                            (self.thermal_raw.load(Ordering::SeqCst) << 16) | 0x180,
                            0x11,
                            0x5555aaaa,
                        ]);
                    }
                }
                let mut fifo = self.inner().returns.lock().unwrap();
                if fifo.len() + words.len() > 512 {
                    self.overflow.store(true, Ordering::SeqCst);
                } else {
                    fifo.extend(words);
                    self.emitted.fetch_add(1, Ordering::SeqCst);
                }
            }
            std::thread::yield_now();
        }
    }
}

async fn prepared(
    chains: Vec<u8>,
    initial_cv: u16,
) -> (
    Arc<ColdHardware>,
    Arc<Transport<ColdHardware>>,
    Arc<PicApplication<ColdHardware>>,
) {
    let startup = startup_hardware(Model::T17e, &chains);
    let hw = Arc::new(ColdHardware {
        thermal: ThermalHardware::shared(startup.inner.clone()),
        startup,
        chains: chains.clone(),
        active: AtomicBool::new(false),
        temperatures: AtomicBool::new(true),
        ticks: AtomicU32::new(0),
        emitted: AtomicU32::new(0),
        overflow: AtomicBool::new(false),
        voltage_frame: Mutex::new(Vec::new()),
        rail_frame: Mutex::new(Vec::new()),
        dac: AtomicU32::new(if initial_cv == 2100 { 12 } else { 120 }),
        voltage_frames: AtomicU32::new(0),
        rail_frames: AtomicU32::new(0),
        bad_voltage_frame: AtomicU32::new(0),
        bad_rail_frame: AtomicU32::new(0),
        pll_commands: AtomicU32::new(0),
        fail_pll_command: AtomicU32::new(0),
        final_adc_failure: AtomicBool::new(false),
        busy_ticks: AtomicU32::new(0),
        delay_pll_ticks: AtomicU32::new(0),
        delay_adc_ticks: AtomicU32::new(0),
        thermal_raw: AtomicU32::new(112),
        thermal_reads: AtomicU32::new(0),
        shift_on_rail_wait: AtomicU32::new(0),
        busy_pause_ms: AtomicU32::new(0),
    });
    let owner = Transport::observe(hw.clone(), Model::T17e, chains.clone())
        .await
        .unwrap();
    let app = PicApplication::claim(owner.clone()).unwrap();
    for _ in &chains {
        hw.inner().reply(&[5, 0x17, 0x89, 0, 0]);
    }
    app.observe_versions(deadline()).await.unwrap();
    for _ in 0..5 {
        for _ in &chains {
            hw.inner().reply(&[6, 0x16, 1, 0, 0, 0]);
        }
        app.heartbeat_round(deadline()).await.unwrap();
    }
    hw.inner().reply(&[0x55, 0xaa, 6, 0x83, 12, 0, 0x95, 0]);
    app.command_voltage_cv(initial_cv, deadline())
        .await
        .unwrap();
    app.acknowledge_voltage_attempt(&app.voltage_attempts().unwrap()[0])
        .unwrap();
    for _ in &chains {
        hw.inner().reply(&factory_tests::golden());
    }
    owner.acquire_factory_calibration(deadline()).await.unwrap();
    owner.initialize_cold_registers(deadline()).await.unwrap();
    owner.acquire_domain_adc(deadline()).await.unwrap();
    owner
        .configure_thermal(Bm1396SensorSamplingMode::Mode0, deadline())
        .await
        .unwrap();
    owner.switch_to_operational_baud(deadline()).await.unwrap();
    hw.inner().events.lock().unwrap().clear();
    hw.active.store(true, Ordering::SeqCst);
    (hw, owner, app)
}

#[tokio::test]
async fn cold_pll_joins_actual_upstream_population_pic_thermal_and_final_adc() {
    for (chains, initial) in [(vec![0], 1800), (vec![0, 2, 7], 1800), (vec![0], 2100)] {
        let (hw, owner, app) = prepared(chains.clone(), initial).await;
        let result = app.initialize_cold_pll(deadline()).await.unwrap();
        assert!(result.completed_at().is_some());
        assert!(result.failure().is_none());
        assert_eq!(
            result.initial_voltage().unwrap().requested_centivolts(),
            initial
        );
        assert_eq!(result.baseline_adc().baseline_minimum_passed(), Some(true));
        let final_adc = result.final_adc().unwrap();
        assert_eq!(final_adc.baseline_minimum_passed(), Some(true));
        assert_eq!(final_adc.restored_chains(), chains);
        assert_ne!(
            result.baseline_adc().host_baud_register(),
            final_adc.host_baud_register()
        );
        assert_eq!(
            final_adc.host_baud_register(),
            result.operational_baud().requested_host_register()
        );
        assert!(result.thermal_snapshots().len() >= 100);
        assert!(result
            .thermal_snapshots()
            .iter()
            .all(|s| s.samples().len() == 4 * chains.len()));
        assert!(!hw.overflow.load(Ordering::SeqCst));
        let expected = [
            (60, 0x40a80275),
            (75, 0x40a80274),
            (100, 0x40a80273),
            (150, 0x40a80272),
            (300, 0x40a80271),
        ];
        for (stage, (mhz, word)) in result.stages().iter().zip(expected) {
            assert_eq!(stage.frequency_mhz(), mhz);
            assert!(stage.settled_at().is_some());
            assert_eq!(
                stage
                    .commands()
                    .iter()
                    .map(|c| (c.chain(), c.register_value()))
                    .collect::<Vec<_>>(),
                (0..2)
                    .flat_map(|_| chains.iter().map(|&chain| (chain, word)))
                    .collect::<Vec<_>>()
            );
            assert!(stage.commands().iter().all(|c| c.completed_at().is_some()));
            assert!(stage
                .voltage_plans()
                .iter()
                .all(|p| p.plan().minimum_pcb_temperature_c == 48));
        }
        assert_eq!(
            hw.pll_commands.load(Ordering::SeqCst),
            (10 * chains.len()) as u32
        );
        let first = &result.stages()[0].voltage_plans()[0];
        assert_eq!(first.voltage_attempt().is_some(), initial != 2100);
        assert_eq!(first.rail_verification().unwrap().checks().len(), 2);
        assert_eq!(
            result.stages()[4].voltage_plans()[0]
                .plan()
                .target_voltage_cv,
            2000
        );
        assert!(app.voltage_attempts().unwrap().is_empty());
        assert!(app.rail_verifications().unwrap().is_empty());
        assert!(owner.pending_thermal_snapshots().unwrap().is_empty());
        let writes = hw.inner().writes().len();
        assert!(app.initialize_cold_pll(deadline()).await.is_err());
        assert_eq!(hw.inner().writes().len(), writes);
    }
}

#[tokio::test]
async fn cold_pll_missing_thermal_and_changed_host_refuse_before_new_actuation() {
    for missing in [true, false] {
        let (hw, owner, app) = prepared(vec![0], 1800).await;
        if missing {
            hw.temperatures.store(false, Ordering::SeqCst);
        } else {
            *hw.inner().regs.lock().unwrap().entry(0x3c).or_default() ^= 1 << 24;
        }
        assert!(app.initialize_cold_pll(deadline()).await.is_err());
        assert!(owner.is_terminal());
        assert_eq!(hw.voltage_frames.load(Ordering::SeqCst), 0);
        assert_eq!(hw.pll_commands.load(Ordering::SeqCst), 0);
        assert_eq!(hw.rail_frames.load(Ordering::SeqCst), 0);
        owner.drain(deadline()).await.unwrap();
    }
}

#[tokio::test]
async fn cold_pll_voltage_and_partial_rail_failures_retain_completed_command_custody() {
    for voltage_failure in [true, false] {
        let (hw, owner, app) = prepared(vec![0], 1800).await;
        if voltage_failure {
            hw.bad_voltage_frame.store(2, Ordering::SeqCst);
        } else {
            hw.bad_rail_frame.store(2, Ordering::SeqCst);
        }
        assert!(app.initialize_cold_pll(deadline()).await.is_err());
        let observation = app.cold_pll_observation().unwrap().unwrap();
        assert!(observation.completed_at().is_none());
        assert!(observation.failure().is_some());
        assert_eq!(hw.pll_commands.load(Ordering::SeqCst), 0);
        if voltage_failure {
            assert_eq!(hw.voltage_frames.load(Ordering::SeqCst), 2);
            assert_eq!(
                app.last_commanded_voltage()
                    .unwrap()
                    .unwrap()
                    .requested_centivolts(),
                1800
            );
            let attempts = app.voltage_attempts().unwrap();
            assert_eq!(attempts.len(), 1);
            assert_eq!(attempts[0].steps().len(), 2);
            assert!(attempts[0].completed_at().is_none());
        } else {
            assert!(observation.stages()[0].voltage_plans()[0]
                .voltage_attempt()
                .unwrap()
                .completed_at()
                .is_some());
            let verification = app.rail_verifications().unwrap();
            assert_eq!(verification[0].checks().len(), 1);
            assert_eq!(verification[0].passed(), None);
            let rails = app.rail_snapshots().unwrap();
            assert_eq!(rails[0].frames()[0].response().len(), 3);
            assert!(owner.management_fault.load(Ordering::SeqCst));
        }
        owner.drain(deadline()).await.unwrap();
    }
}

#[tokio::test]
async fn cold_pll_partial_second_pll_and_final_adc_failure_never_complete() {
    for pll_failure in [true, false] {
        let (hw, owner, app) = prepared(vec![0], 1800).await;
        if pll_failure {
            hw.fail_pll_command.store(2, Ordering::SeqCst);
        } else {
            hw.final_adc_failure.store(true, Ordering::SeqCst);
        }
        assert!(app.initialize_cold_pll(deadline()).await.is_err());
        let observation = app.cold_pll_observation().unwrap().unwrap();
        assert!(observation.completed_at().is_none());
        if pll_failure {
            assert_eq!(observation.stages().len(), 1);
            let commands = observation.stages()[0].commands();
            assert_eq!(commands.len(), 2);
            assert!(commands[0].completed_at().is_some());
            assert!(commands[1].completed_at().is_none());
            assert!(observation.stages()[0].settled_at().is_none());
            assert!(observation.final_adc().is_none());
        } else {
            assert_eq!(observation.stages().len(), 5);
            assert_eq!(
                observation.final_adc().unwrap().baseline_minimum_passed(),
                Some(false)
            );
            assert_eq!(observation.final_adc().unwrap().restored_chains(), [0]);
        }
        owner.drain(deadline()).await.unwrap();
    }
}

#[tokio::test]
async fn canceled_cold_pic_wait_keeps_both_actual_workers_and_fifo_custody_until_release() {
    let (hw, owner, app) = prepared(vec![0], 1800).await;
    let block = ReadBlock::new(0);
    *hw.inner().sleep_block.lock().unwrap() = Some((Duration::from_secs(1), block.clone()));
    let task = {
        let app = app.clone();
        tokio::spawn(async move { app.initialize_cold_pll(deadline()).await })
    };
    while !block.entered.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let before = hw.emitted.load(Ordering::SeqCst);
    while hw.emitted.load(Ordering::SeqCst) <= before + 2 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(!hw.overflow.load(Ordering::SeqCst));
    assert!(
        app.cold_pll_observation()
            .unwrap()
            .unwrap()
            .thermal_snapshots()
            .len()
            > 2
    );
    // Independent heartbeat crosses the released physical lane during source1s.
    hw.inner().reply(&[6, 0x16, 1, 0, 0, 0]);
    app.heartbeat_round(deadline()).await.unwrap();
    let writer = {
        let owner = owner.clone();
        tokio::spawn(async move {
            owner
                .write_register(0, None, 8, 0xdeadbeef, deadline())
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(2)).await;
    assert!(!writer.is_finished());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(5))
        .await
        .is_err());
    assert!(owner.workers.lock().unwrap().count >= 2);
    assert_eq!(hw.pll_commands.load(Ordering::SeqCst), 0);
    block.release();
    assert!(writer.await.unwrap().is_err());
    owner.drain(deadline()).await.unwrap();
    assert_eq!(owner.workers.lock().unwrap().count, 0);
    assert_eq!(app.rail_verifications().unwrap()[0].checks().len(), 1);
    assert!(app.rail_verifications().unwrap()[0].waits()[0]
        .completed_at()
        .is_none());
}

#[tokio::test]
async fn delayed_pll_and_final_adc_completion_keep_three_chain_fifo_serviced() {
    let mut outcomes = Vec::new();
    for pll_delay in [true, false] {
        let (hw, owner, app) = prepared(vec![0, 2, 7], 1800).await;
        if pll_delay {
            hw.delay_pll_ticks.store(1200, Ordering::SeqCst);
        } else {
            hw.delay_adc_ticks.store(1200, Ordering::SeqCst);
        }
        let result = app.initialize_cold_pll(deadline()).await;
        let overflow = hw.overflow.load(Ordering::SeqCst);
        println!(
            "cold delayed-command fixture pll_delay={pll_delay} overflow={overflow} result={:?}",
            result
                .as_ref()
                .map(|o| o.completed_at())
                .map_err(String::as_str)
        );
        outcomes.push((pll_delay, result.is_ok(), overflow));
        owner.drain(deadline()).await.unwrap();
    }
    assert!(
        outcomes
            .iter()
            .all(|(_, passed, overflow)| *passed && !*overflow),
        "{outcomes:?}"
    );
}

#[tokio::test]
async fn actual_thermal_change_replans_voltage_and_four_changes_refuse_final_pll_stage() {
    for repeated in [false, true] {
        let (hw, owner, app) = prepared(vec![0], 1800).await;
        hw.shift_on_rail_wait
            .store(if repeated { 2 } else { 1 }, Ordering::SeqCst);
        let result = app.initialize_cold_pll(deadline()).await;
        let observation = app.cold_pll_observation().unwrap().unwrap();
        assert_eq!(
            result.is_ok(),
            !repeated,
            "{:?}",
            result.as_ref().map(|_| ()).map_err(String::as_str)
        );
        assert_eq!(observation.stages().len(), 5);
        let final_stage = &observation.stages()[4];
        let plans = final_stage.voltage_plans();
        assert_eq!(plans.len(), if repeated { 4 } else { 2 });
        let expected = if repeated {
            vec![(48, 2000), (20, 2010), (48, 2000), (20, 2010)]
        } else {
            vec![(48, 2000), (20, 2010)]
        };
        assert_eq!(
            plans
                .iter()
                .map(|p| (
                    p.plan().minimum_pcb_temperature_c,
                    p.plan().target_voltage_cv
                ))
                .collect::<Vec<_>>(),
            expected
        );
        assert!(plans
            .windows(2)
            .all(|pair| pair[0].thermal_sequence() < pair[1].thermal_sequence()));
        assert!(plans
            .iter()
            .all(|p| p.voltage_attempt().unwrap().completed_at().is_some()
                && p.rail_verification().unwrap().passed() == Some(true)));
        if repeated {
            assert!(observation
                .failure()
                .unwrap()
                .contains("four retained plans"));
            assert!(final_stage.commands().is_empty());
            assert!(observation.final_adc().is_none());
            assert_eq!(hw.pll_commands.load(Ordering::SeqCst), 8);
        } else {
            assert!(observation.completed_at().is_some());
            assert_eq!(
                app.last_commanded_voltage()
                    .unwrap()
                    .unwrap()
                    .requested_centivolts(),
                2010
            );
            assert_eq!(hw.pll_commands.load(Ordering::SeqCst), 10);
        }
        assert!(!hw.overflow.load(Ordering::SeqCst));
        owner.drain(deadline()).await.unwrap();
    }
}

#[tokio::test]
async fn actual_deadline_during_owned_busy_pll_retains_attempt_and_stops_later_commands() {
    let (hw, owner, app) = prepared(vec![0], 1800).await;
    hw.delay_pll_ticks.store(1200, Ordering::SeqCst);
    hw.busy_pause_ms.store(2100, Ordering::SeqCst);
    assert!(app
        .initialize_cold_pll(Instant::now() + Duration::from_secs(2))
        .await
        .is_err());
    let observation = app.cold_pll_observation().unwrap().unwrap();
    assert!(observation.completed_at().is_none());
    assert_eq!(observation.stages().len(), 1);
    assert_eq!(observation.stages()[0].commands().len(), 1);
    assert!(observation.stages()[0].commands()[0]
        .completed_at()
        .is_none());
    assert_eq!(hw.pll_commands.load(Ordering::SeqCst), 1);
    assert!(owner.asic_fault.load(Ordering::SeqCst));
    owner.drain(deadline()).await.unwrap();
}
