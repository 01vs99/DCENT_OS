use super::*;
use startup_tests::{startup_hardware, StartupHardware};
use thermal_tests::ThermalHardware;

struct PreparationPin {
    inner: Arc<Fake>,
    high: AtomicBool,
}
impl gpio::Pin for Arc<PreparationPin> {
    fn high(&self) -> Result<(), String> {
        self.inner.events.lock().unwrap().push(Event::SourceHigh);
        self.high.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn low(&self) -> Result<(), String> {
        self.inner.events.lock().unwrap().push(Event::SourceLow);
        self.high.store(false, Ordering::SeqCst);
        Ok(())
    }
    fn observed_high(&self) -> Result<bool, String> {
        Ok(self.high.load(Ordering::SeqCst))
    }
}

/// Independent existing census and sensor wire fixtures share one actual mapping.
/// New explicit source frames and fixed-capacity delayed replies exercise the join.
struct PreparationHardware {
    startup: Arc<StartupHardware>,
    thermal: Arc<ThermalHardware>,
    chains: Vec<u8>,
    automatic_commands: AtomicU32,
    sensor_updates: AtomicBool,
    active: AtomicBool,
    voltage_frame: Mutex<Vec<u8>>,
    pic_frame: Mutex<Vec<u8>>,
    voltage_frames: AtomicU32,
    current_dac: AtomicU32,
    rail_frames: AtomicU32,
    pll_commands: AtomicU32,
    bad_voltage: AtomicU32,
    busy_ticks: AtomicU32,
    asic_writer: Mutex<Option<std::thread::ThreadId>>,
    non_asic_sleeps: AtomicU32,
    busy_test_gate: Mutex<Option<Arc<ReadBlock>>>,
    delay_phase: AtomicU32,
    delayed: AtomicBool,
    ticks: AtomicU32,
    emitted_nonces: AtomicU32,
    emitted_registers: AtomicU32,
    busy_read_words: AtomicU32,
    busy_thermal_records: AtomicU32,
    force_pre_dma_nonce: AtomicBool,
    emitted_temperatures: AtomicU32,
    overflow: AtomicBool,
    raw_temperature: AtomicU32,
    pause_busy_ms: AtomicU32,
    late_thermal_defect: AtomicU32,
    late_thermal_seen: AtomicBool,
    immediate_after_baud: AtomicBool,
    after_baud_sleeps: AtomicU32,
    final_cleanup_gate: Mutex<Option<Arc<ReadBlock>>>,
    adapted_reset_gate: Mutex<Option<Arc<ReadBlock>>>,
    adapted_completion_gate: Mutex<Option<Arc<ReadBlock>>>,
    final_pll_completion_gate: Mutex<Option<Arc<ReadBlock>>>,
    completion_wait_ticks: AtomicU32,
    completion_wait_gate: Mutex<Option<Arc<ReadBlock>>>,
    adapted_defect: AtomicU32,
    adapted_defect_seen: AtomicBool,
    fail_pll_predrain: AtomicBool,
    owner_observer: Mutex<std::sync::Weak<Transport<PreparationHardware>>>,
    observer: Mutex<std::sync::Weak<PicApplication<PreparationHardware>>>,
}
impl PreparationHardware {
    fn new(chains: &[u8]) -> Arc<Self> {
        let startup = startup_hardware(Model::T17e, chains);
        let thermal = ThermalHardware::shared(startup.inner.clone());
        Arc::new(Self {
            startup,
            thermal,
            chains: chains.to_vec(),
            automatic_commands: AtomicU32::new(0),
            sensor_updates: AtomicBool::new(false),
            active: AtomicBool::new(false),
            voltage_frame: Mutex::new(Vec::new()),
            pic_frame: Mutex::new(Vec::new()),
            voltage_frames: AtomicU32::new(0),
            current_dac: AtomicU32::new(0),
            rail_frames: AtomicU32::new(0),
            pll_commands: AtomicU32::new(0),
            bad_voltage: AtomicU32::new(0),
            busy_ticks: AtomicU32::new(0),
            asic_writer: Mutex::new(None),
            non_asic_sleeps: AtomicU32::new(0),
            busy_test_gate: Mutex::new(None),
            delay_phase: AtomicU32::new(0),
            delayed: AtomicBool::new(false),
            ticks: AtomicU32::new(0),
            emitted_nonces: AtomicU32::new(0),
            emitted_registers: AtomicU32::new(0),
            busy_read_words: AtomicU32::new(0),
            busy_thermal_records: AtomicU32::new(0),
            force_pre_dma_nonce: AtomicBool::new(false),
            emitted_temperatures: AtomicU32::new(0),
            overflow: AtomicBool::new(false),
            raw_temperature: AtomicU32::new(112),
            pause_busy_ms: AtomicU32::new(0),
            late_thermal_defect: AtomicU32::new(0),
            late_thermal_seen: AtomicBool::new(false),
            immediate_after_baud: AtomicBool::new(false),
            after_baud_sleeps: AtomicU32::new(0),
            final_cleanup_gate: Mutex::new(None),
            adapted_reset_gate: Mutex::new(None),
            adapted_completion_gate: Mutex::new(None),
            final_pll_completion_gate: Mutex::new(None),
            completion_wait_ticks: AtomicU32::new(0),
            completion_wait_gate: Mutex::new(None),
            adapted_defect: AtomicU32::new(0),
            adapted_defect_seen: AtomicBool::new(false),
            fail_pll_predrain: AtomicBool::new(false),
            owner_observer: Mutex::new(std::sync::Weak::new()),
            observer: Mutex::new(std::sync::Weak::new()),
        })
    }
    fn inner(&self) -> &Arc<Fake> {
        &self.startup.inner
    }
    fn queue_words(&self, words: &[u32]) {
        let mut fifo = self.inner().returns.lock().unwrap();
        if fifo.len() + words.len() > 512 {
            self.overflow.store(true, Ordering::SeqCst);
        } else {
            fifo.extend(words);
        }
    }
    fn actual_auto(&self) -> bool {
        self.automatic_commands.load(Ordering::SeqCst) >= 8 * self.chains.len() as u32
    }
}
impl Hardware for PreparationHardware {
    fn model(&self) -> Model {
        Model::T17e
    }
    fn validate_owner(&self) -> Result<(), String> {
        self.inner().validate_owner()?;
        let final_gate = self.final_pll_completion_gate.lock().unwrap().clone();
        if let Some(gate) = final_gate {
            if !gate.entered.load(Ordering::SeqCst)
                && self.asic_writer.lock().unwrap().as_ref() == Some(&std::thread::current().id())
            {
                let owner = self.owner_observer.lock().unwrap().upgrade().unwrap();
                if owner.workers.lock().unwrap().count == 1 {
                    let app = self.observer.lock().unwrap().upgrade().unwrap();
                    // Owner validation can run while cold_guard already holds
                    // either observation slot. A test observer must never wait
                    // recursively on those production locks. An unavailable slot
                    // skips this predicate; the later completion check retries.
                    let complete_stages = app.test_final_pll_gate_ready()?;
                    // Both nonblocking observation guards have dropped here;
                    // the actual stage/count gate retains no receipt mutex.
                    if complete_stages {
                        // Real PIC exit and five actually settled stages, before
                        // the outer worker reacquires the logical voltage lease.
                        gate.entered.store(true, Ordering::SeqCst);
                        let limit = Instant::now() + Duration::from_secs(10);
                        let mut released = gate.released.lock().unwrap();
                        while !*released {
                            let Some(left) = limit.checked_duration_since(Instant::now()) else {
                                break;
                            };
                            released = gate.condition.wait_timeout(released, left).unwrap().0;
                        }
                    }
                }
            }
        }
        let adapted_gate = self.adapted_completion_gate.lock().unwrap().clone();
        if let Some(gate) = adapted_gate {
            if !gate.entered.load(Ordering::SeqCst)
                && self.asic_writer.lock().unwrap().as_ref() == Some(&std::thread::current().id())
            {
                let owner = self.owner_observer.lock().unwrap().upgrade().unwrap();
                let only_outer_worker = owner.workers.lock().unwrap().count == 1;
                // Prior in-sequence final guards still have the real PIC worker.
                // Only actual PIC exit allows this before-lock owner check to
                // park the final VoltageLease acquisition's real ASIC worker.
                if only_outer_worker {
                    let app = self.observer.lock().unwrap().upgrade().unwrap();
                    let observation = app.adapted_startup_observation()?;
                    if observation.is_some_and(|row| {
                        row.completed_at().is_none()
                            && row.stage() == AdaptedStartupStage::FreshThermal
                            && row.thermal_snapshots().last().is_some()
                    }) {
                        gate.entered.store(true, Ordering::SeqCst);
                        let limit = Instant::now() + Duration::from_secs(5);
                        let mut released = gate.released.lock().unwrap();
                        while !*released {
                            let Some(left) = limit.checked_duration_since(Instant::now()) else {
                                break;
                            };
                            released = gate.condition.wait_timeout(released, left).unwrap().0;
                        }
                    }
                }
            }
        }
        let gate = self.final_cleanup_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            if !gate.entered.load(Ordering::SeqCst)
                && self.asic_writer.lock().unwrap().as_ref() == Some(&std::thread::current().id())
            {
                let app = self.observer.lock().unwrap().upgrade().unwrap();
                let owner = self.owner_observer.lock().unwrap().upgrade().unwrap();
                let only_outer_worker = owner.workers.lock().unwrap().count == 1;
                if only_outer_worker
                    && app.cold_pll_observation()?.is_some_and(|observation| {
                        observation.completed_at().is_none()
                            && observation
                                .final_adc()
                                .is_some_and(|adc| adc.completed_at().is_some())
                            && observation.stages().len() == 5
                            && observation
                                .stages()
                                .iter()
                                .all(|stage| stage.settled_at().is_some())
                    })
                {
                    // The actual PIC count guard is already gone, and all five
                    // stages plus final ADC remain in their real retained row.
                    gate.entered.store(true, Ordering::SeqCst);
                    let limit = Instant::now() + Duration::from_secs(10);
                    let mut released = gate.released.lock().unwrap();
                    while !*released {
                        let Some(left) = limit.checked_duration_since(Instant::now()) else {
                            break;
                        };
                        released = gate.condition.wait_timeout(released, left).unwrap().0;
                    }
                }
            }
        }
        Ok(())
    }
    fn claim_transport(&self) -> Result<(), String> {
        self.inner().claim_transport()
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        if offset == BC && self.busy_ticks.load(Ordering::SeqCst) > 0 {
            return Ok(BUSY);
        }
        // StartupHardware computes the real delegated FIFO count without
        // recording Fake::Read; expose this actual call in the shared event log.
        if offset == 0x18 {
            // A new counted ASIC worker can take over idle receive service
            // before it publishes its first BC command (fresh PLL thermal).
            // PIC workers never read this FIFO. During an owned busy command,
            // only the actual BC writer remains the scripted clock owner.
            if self.busy_ticks.load(Ordering::SeqCst) == 0 {
                *self.asic_writer.lock().unwrap() = Some(std::thread::current().id());
            }
            self.inner()
                .events
                .lock()
                .unwrap()
                .push(Event::Read(offset));
            if self.fail_pll_predrain.load(Ordering::SeqCst) {
                let app = self.observer.lock().unwrap().upgrade().unwrap();
                if app
                    .cold_pll_observation()?
                    .is_some_and(|observation| observation.stages().is_empty())
                {
                    self.fail_pll_predrain.store(false, Ordering::SeqCst);
                    return Err("fixture actual PLL predrain FIFO read failure".into());
                }
            }
        }
        let value = self.startup.read(offset)?;
        if [0x10, 0x14].contains(&offset) && self.busy_ticks.load(Ordering::SeqCst) > 0 {
            self.busy_read_words.fetch_add(1, Ordering::SeqCst);
        }
        Ok(value)
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        if offset == BC && value & BUSY != 0 {
            *self.asic_writer.lock().unwrap() = Some(std::thread::current().id());
            let (first, word) = {
                let regs = self.inner().regs.lock().unwrap();
                (regs[&0xc4].to_be_bytes(), regs[&0xc8])
            };
            let chain = ((value >> 16) & 15) as u8;
            let automatic = first[0] == 0x41 && first[3] == 0x1c && word == 0x07980000;
            if first[0] == 0x42 || (first[0] == 0x41 && [0x18, 0x54, 0x1c].contains(&first[3])) {
                self.thermal.write(offset, value)?;
                if first[3] == 0x18 {
                    self.sensor_updates.store(true, Ordering::SeqCst);
                }
                if automatic {
                    self.automatic_commands.fetch_add(1, Ordering::SeqCst);
                }
            } else if first[0] == 0x52
                && first[3] == 0x18
                && self.sensor_updates.load(Ordering::SeqCst)
            {
                self.inner().write(offset, value)?;
                let baseline = self
                    .startup
                    .writes
                    .lock()
                    .unwrap()
                    .iter()
                    .rev()
                    .find(|w| w.chain == chain && w.broadcast && w.register == 0x18)
                    .unwrap()
                    .value;
                let registers = self.thermal.asic_registers.lock().unwrap();
                let mut words = Vec::new();
                for ordinal in 0..78 {
                    let address = (ordinal * 3) as u8;
                    let observed = *registers.get(&(chain, address, 0x18)).unwrap_or(&baseline);
                    words.extend([
                        u32::from_le_bytes([chain, 0x18, address, 2]),
                        observed,
                        0x11,
                        0x5555aaaa,
                    ]);
                }
                drop(registers);
                self.queue_words(&words);
            } else {
                self.startup.write(offset, value)?;
                if first[0] == 0x51 && first[3] == 0x18 {
                    for address in [51, 36, 195, 180] {
                        self.thermal
                            .asic_registers
                            .lock()
                            .unwrap()
                            .insert((chain, address, 0x18), word);
                    }
                }
            }
            if first[0] == 0x51 && first[3] == 8 {
                self.pll_commands.fetch_add(1, Ordering::SeqCst);
            }
            let phase = self.delay_phase.load(Ordering::SeqCst);
            let selected = match phase {
                1 => first[0] == 0x40,
                2 => first[0] == 0x41 && first[3] == 0x2c,
                3 => first[0] == 0x52 && first[3] == 0xb4,
                4 => automatic && self.actual_auto(),
                5 => first[0] == 0x51 && first[3] == 0x18 && self.actual_auto(),
                6 => first[0] == 0x51 && first[3] == 8,
                _ => false,
            };
            if selected && !self.delayed.swap(true, Ordering::SeqCst) {
                self.busy_ticks.store(1500, Ordering::SeqCst);
                let gate = self.busy_test_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.entered.store(true, Ordering::SeqCst);
                    let limit = Instant::now() + Duration::from_secs(5);
                    let mut released = gate.released.lock().unwrap();
                    while !*released {
                        let Some(left) = limit.checked_duration_since(Instant::now()) else {
                            break;
                        };
                        released = gate.condition.wait_timeout(released, left).unwrap().0;
                    }
                }
            }
            return Ok(());
        }
        self.inner().write(offset, value)?;
        if offset == 0x34 {
            if let Some(gate) = self.adapted_reset_gate.lock().unwrap().take() {
                gate.entered.store(true, Ordering::SeqCst);
                let limit = Instant::now() + Duration::from_secs(5);
                let mut released = gate.released.lock().unwrap();
                while !*released {
                    let Some(left) = limit.checked_duration_since(Instant::now()) else {
                        break;
                    };
                    released = gate.condition.wait_timeout(released, left).unwrap().0;
                }
            }
        }
        if offset == 0x30 && self.active.load(Ordering::SeqCst) {
            if value & 0xffff_ff00 == 0x0520_1100 {
                let mut frame = self.voltage_frame.lock().unwrap();
                frame.push(value as u8);
                if frame.len() == 8 {
                    assert_eq!(&frame[..4], &[0x55, 0xaa, 6, 0x83]);
                    self.current_dac
                        .store(u32::from(frame[4]), Ordering::SeqCst);
                    let number = self.voltage_frames.fetch_add(1, Ordering::SeqCst) + 1;
                    let length = if number == self.bad_voltage.load(Ordering::SeqCst) {
                        7
                    } else {
                        8
                    };
                    self.inner().reply(&frame[..length]);
                    frame.clear();
                }
            } else if value & 0xfff8_ff00 == 0x0040_0000 {
                let mut frame = self.pic_frame.lock().unwrap();
                frame.push(value as u8);
                if frame.len() >= 3 && frame.len() == usize::from(frame[2]) + 2 {
                    match frame[3] {
                        0x15 => {
                            assert_eq!(frame.len(), 7);
                            self.inner().reply(&[0x15, 1]);
                        }
                        0x16 => self.inner().reply(&[6, 0x16, 1, 0, 0, 0]),
                        0x37 => {
                            assert_eq!(&*frame, &[0x55, 0xaa, 4, 0x37, 0, 0x3b]);
                            // Existing independently replayed original source
                            // target/DAC/raw-rail goldens; no inverse native conversion.
                            let raw: u16 = match self.current_dac.load(Ordering::SeqCst) {
                                12 => 840,
                                48 => 800,
                                45 => 804,
                                dac => panic!("unexpected prepared PLL completed DAC {dac}"),
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
                            let checksum: u16 = response.iter().map(|&byte| u16::from(byte)).sum();
                            response.extend(checksum.to_be_bytes());
                            self.inner().reply(&response);
                            self.rail_frames.fetch_add(1, Ordering::SeqCst);
                        }
                        other => panic!("unexpected preparation PIC opcode {other}"),
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
    fn write_dma(&self, offset: usize, data: &[u8]) -> Result<(), String> {
        self.inner().write_dma(offset, data)
    }
    fn barrier(&self) -> Result<(), String> {
        self.inner().barrier()
    }
    fn sleep(&self, duration: Duration) {
        self.inner().sleep(duration);
        if duration != Duration::from_millis(1) {
            return;
        }
        // The scripted ASIC clock belongs to its actual idle FIFO receiver or
        // owned BC writer. PIC/voltage-lock sleeps cannot advance that script.
        if self.asic_writer.lock().unwrap().as_ref() != Some(&std::thread::current().id()) {
            self.non_asic_sleeps.fetch_add(1, Ordering::SeqCst);
            std::thread::yield_now();
            return;
        }
        if self.busy_ticks.load(Ordering::SeqCst) > 0 {
            let pause = self.pause_busy_ms.swap(0, Ordering::SeqCst);
            if pause > 0 {
                std::thread::sleep(Duration::from_millis(u64::from(pause)));
            }
            let _ = self
                .busy_ticks
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                });
        }
        let tick = self.ticks.fetch_add(1, Ordering::SeqCst) + 1;
        if self.completion_wait_ticks.fetch_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |remaining| remaining.checked_sub(1),
        ) == Ok(1)
        {
            if let Some(gate) = self.completion_wait_gate.lock().unwrap().clone() {
                // Exactly1500 actual outer ASIC sleeps, while the independent
                // voltage task is still held at its real management read.
                gate.entered.store(true, Ordering::SeqCst);
                let limit = Instant::now() + Duration::from_secs(10);
                let mut released = gate.released.lock().unwrap();
                while !*released {
                    let Some(left) = limit.checked_duration_since(Instant::now()) else {
                        break;
                    };
                    released = gate.condition.wait_timeout(released, left).unwrap().0;
                }
            }
        }

        if self.busy_ticks.load(Ordering::SeqCst) > 0 && tick % 5 == 0 {
            if self.force_pre_dma_nonce.load(Ordering::SeqCst) {
                // Only the explicit negative control emits work before DMA.
                self.queue_words(&[0x80010080, 0, 0, 0x5555aaaa]);
                self.emitted_nonces.fetch_add(1, Ordering::SeqCst);
            } else if [1, 2].contains(&self.delay_phase.load(Ordering::SeqCst)) {
                // Normal unsolicited register traffic before the later query's
                // watermark exercises retention without manufacturing work.
                let ordinal = self.emitted_registers.fetch_add(1, Ordering::SeqCst);
                self.queue_words(&[
                    u32::from_le_bytes([self.chains[0], 0x70, 0, 2]),
                    ordinal,
                    0x11,
                    0x5555aaaa,
                ]);
            }
        }
        let after_baud = self.immediate_after_baud.load(Ordering::SeqCst)
            && self
                .observer
                .lock()
                .unwrap()
                .upgrade()
                .and_then(|app| app.conditioning_preparation_observation().unwrap())
                .is_some_and(|observation| {
                    observation
                        .operational_baud()
                        .is_some_and(|baud| baud.completed_at().is_some())
                });
        if after_baud {
            self.after_baud_sleeps.fetch_add(1, Ordering::SeqCst);
        }
        let adapted_stage = if self.adapted_defect.load(Ordering::SeqCst) != 0 {
            self.observer
                .lock()
                .unwrap()
                .upgrade()
                .and_then(|app| app.adapted_startup_observation().unwrap())
                .map(|row| row.stage())
        } else {
            None
        };
        let adapted_defect = self.adapted_defect.load(Ordering::SeqCst);
        if adapted_defect == 1 && adapted_stage == Some(AdaptedStartupStage::Reset) {
            self.raw_temperature.store(164, Ordering::SeqCst);
            self.adapted_defect_seen.store(true, Ordering::SeqCst);
        }
        let adapted_final = adapted_stage == Some(AdaptedStartupStage::FreshThermal);
        if adapted_final && adapted_defect == 3 {
            self.adapted_defect_seen.store(true, Ordering::SeqCst);
            return; // Actual absence of new automatic returns, not old timestamp edits.
        }
        if self.actual_auto() && (tick % 100 == 0 || after_baud) {
            let defect = self.late_thermal_defect.load(Ordering::SeqCst);
            let final_population = defect != 0
                && self
                    .observer
                    .lock()
                    .unwrap()
                    .upgrade()
                    .and_then(|app| app.conditioning_preparation_observation().unwrap())
                    .is_some_and(|observation| {
                        observation.stage() == ConditioningPreparationStage::FreshThermal
                    });
            if final_population {
                self.late_thermal_seen.store(true, Ordering::SeqCst);
                if defect == 3 {
                    self.late_thermal_defect.store(0, Ordering::SeqCst);
                    // Actual elapsed time, without rewriting any retained timestamp.
                    std::thread::sleep(Duration::from_millis(7100));
                    return;
                }
            }
            let mut words = Vec::new();
            for &chain in &self.chains {
                for address in [51, 36, 195, 180] {
                    words.extend([
                        u32::from_le_bytes([chain, 0x44, address, 2]),
                        ((if (final_population && defect == 1)
                            || (adapted_final && adapted_defect == 2)
                        {
                            self.adapted_defect_seen
                                .store(adapted_final, Ordering::SeqCst);
                            0
                        } else {
                            self.raw_temperature.load(Ordering::SeqCst)
                        }) << 16)
                            | if final_population && defect == 2 {
                                0x100
                            } else {
                                0x180
                            },
                        0x11,
                        0x5555aaaa,
                    ]);
                }
            }
            self.queue_words(&words);
            if self.busy_ticks.load(Ordering::SeqCst) > 0 {
                self.busy_thermal_records
                    .fetch_add((4 * self.chains.len()) as u32, Ordering::SeqCst);
            }
            self.emitted_temperatures.fetch_add(1, Ordering::SeqCst);
        }
        std::thread::yield_now();
    }
}

async fn source_ready(
    chains: &[u8],
) -> (
    Arc<PreparationHardware>,
    Arc<Transport<PreparationHardware>>,
    Arc<PicApplication<PreparationHardware>>,
    Arc<PowerLine<PreparationHardware>>,
    Arc<PreparationPin>,
) {
    let hw = PreparationHardware::new(chains);
    let owner = Transport::observe(hw.clone(), Model::T17e, chains.to_vec())
        .await
        .unwrap();
    let pin = Arc::new(PreparationPin {
        inner: hw.inner().clone(),
        high: AtomicBool::new(false),
    });
    let line = PowerLine::from_test_pin(owner.clone(), Box::new(pin.clone()));
    line.source_test_high_with_age(Duration::from_secs(61));
    let app = PicApplication::claim(owner.clone()).unwrap();
    *hw.observer.lock().unwrap() = Arc::downgrade(&app);
    *hw.owner_observer.lock().unwrap() = Arc::downgrade(&owner);
    hw.inner().reply(&[0x55, 0xaa, 6, 2, 0x42, 0, 0x4a, 0]);
    app.observe_supply_type(deadline()).await.unwrap();
    for _ in chains {
        hw.inner().reply(&factory_tests::golden());
    }
    owner.acquire_factory_calibration(deadline()).await.unwrap();
    for _ in chains {
        hw.inner().reply(&[5, 0x17, 0x89, 0, 0]);
    }
    app.observe_versions(deadline()).await.unwrap();
    for _ in 0..5 {
        for _ in chains {
            hw.inner().reply(&[6, 0x16, 1, 0, 0, 0]);
        }
        app.heartbeat_round(deadline()).await.unwrap();
    }
    let quiet = owner.quiet_fans(deadline()).await.unwrap();
    hw.inner()
        .tachs
        .lock()
        .unwrap()
        .extend((0..8).map(|i| ((i % 4) << 8) | 40));
    let fans = owner.sample_fan_tach(deadline()).await.unwrap();
    line.enable_source_after_observations(app.clone(), quiet, fans, deadline())
        .await
        .unwrap();
    hw.inner().regs.lock().unwrap().insert(0x3c, 0xc0c0c0c0);
    hw.inner().regs.lock().unwrap().insert(0x34, 0xa5a50000);
    hw.active.store(true, Ordering::SeqCst);
    (hw, owner, app, line, pin)
}

async fn prepared(
    chains: &[u8],
) -> (
    Arc<PreparationHardware>,
    Arc<Transport<PreparationHardware>>,
    Arc<PicApplication<PreparationHardware>>,
    Arc<PowerLine<PreparationHardware>>,
    Arc<PreparationPin>,
) {
    let (hw, owner, app, line, pin) = source_ready(chains).await;
    app.initialize_conditioning_reset(line.clone(), deadline())
        .await
        .unwrap();
    hw.inner().events.lock().unwrap().clear();
    (hw, owner, app, line, pin)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_joins_actual_first_reset_higher_source_frames_and_fresh_cold_adc_thermal_baud()
{
    for chains in [vec![0], vec![0, 2, 7]] {
        let (hw, owner, app, line, _) = prepared(&chains).await;
        let result = app
            .initialize_conditioning_preparation(line.clone(), 75, deadline())
            .await
            .unwrap();
        assert!(
            result.same_owner(&owner)
                && result.completed_at().is_some()
                && result.failure().is_none()
        );
        assert_eq!(result.stage(), ConditioningPreparationStage::FreshThermal);
        let high = result.higher_voltage().unwrap();
        assert_eq!(high.sequence(), 1);
        assert_eq!(high.prior_command().unwrap().requested_centivolts(), 1800);
        assert_eq!(high.planned_dac_codes(), [103, 86, 69, 52, 48]);
        assert!(high
            .steps()
            .iter()
            .all(|step| step.framing_complete() && step.completed_at().is_some()));
        assert_eq!(
            result.higher_command().unwrap(),
            app.last_commanded_voltage().unwrap().unwrap()
        );
        assert_eq!(
            result.assignment().unwrap().assigned_records().len(),
            78 * chains.len()
        );
        assert!(result.cold_registers().unwrap().completed_at().is_some());
        assert_eq!(
            result.baseline_adc().unwrap().baseline_minimum_passed(),
            Some(true)
        );
        assert_eq!(
            result
                .thermal_configuration()
                .unwrap()
                .manufacturers()
                .len(),
            4 * chains.len()
        );
        let baud = result.operational_baud().unwrap();
        assert!(baud.completed_at().is_some());
        assert_eq!(baud.baud(), 3_000_000);
        assert_eq!(baud.old_host_register(), 0xdadadada);
        let fresh = result.thermal_snapshots().last().unwrap();
        assert!(fresh
            .samples()
            .iter()
            .all(|sample| sample.received_at() > baud.completed_at().unwrap()));
        assert!(owner.pending_thermal_snapshots().unwrap().is_empty());
        assert!(app.voltage_attempts().unwrap().is_empty());
        assert!(!hw.overflow.load(Ordering::SeqCst));
        assert_eq!(hw.voltage_frames.load(Ordering::SeqCst), 13);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_delayed_assignment_cold_adc_thermal_and_baud_keep_finite_fifo_custody() {
    for phase in 1..=5 {
        let (hw, owner, app, line, _) = prepared(&[0, 2, 7]).await;
        hw.delay_phase.store(phase, Ordering::SeqCst);
        let result = app
            .initialize_conditioning_preparation(line.clone(), 75, deadline())
            .await;
        eprintln!("preparation delayed phase{phase}: result={:?} overflow={} register_records={} busy_read_words={} busy_thermal_records={}",
            result.as_ref().map(|r|r.completed_at()),hw.overflow.load(Ordering::SeqCst),hw.emitted_registers.load(Ordering::SeqCst),
            hw.busy_read_words.load(Ordering::SeqCst),hw.busy_thermal_records.load(Ordering::SeqCst));
        assert!(result.is_ok(), "phase{phase}: {result:?}");
        assert!(hw.delayed.load(Ordering::SeqCst));
        assert!(!hw.overflow.load(Ordering::SeqCst));
        assert_eq!(hw.emitted_nonces.load(Ordering::SeqCst), 0);
        let pending = owner.pending_returns().unwrap();
        if phase <= 2 {
            let count = hw.emitted_registers.load(Ordering::SeqCst);
            assert!(count > 128);
            assert_eq!(pending.len(), count as usize);
            for (ordinal, raw) in pending.iter().enumerate() {
                assert!(
                    matches!(raw.payload(),ReturnPayload::Register(record) if record.chain_slot==0 && record.register==0x70 && record.value==ordinal as u32)
                );
            }
            assert_eq!(hw.busy_read_words.load(Ordering::SeqCst), count * 4);
        } else if phase == 3 {
            // B4 legitimately contains78 records for this chain, below the
            //128-record FIFO capacity; require its real reads while BC is busy.
            assert_eq!(hw.busy_read_words.load(Ordering::SeqCst), 78 * 4);
            assert!(pending.is_empty());
        } else {
            assert!(hw.busy_thermal_records.load(Ordering::SeqCst) > 128);
            assert!(
                hw.busy_read_words.load(Ordering::SeqCst)
                    >= hw.busy_thermal_records.load(Ordering::SeqCst) * 4
            );
            let retained = result.as_ref().unwrap();
            assert!(
                retained
                    .thermal_snapshots()
                    .iter()
                    .map(|snapshot| snapshot.raw_records().len())
                    .sum::<usize>()
                    >= hw.busy_thermal_records.load(Ordering::SeqCst) as usize
            );
            assert!(pending.is_empty());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_failed_higher_frame_retains_partial_bytes_before_any_cold_command() {
    let (hw, owner, app, line, _) = prepared(&[0]).await;
    let before = hw.startup.writes.lock().unwrap().len();
    hw.bad_voltage.store(9, Ordering::SeqCst);
    assert!(app
        .initialize_conditioning_preparation(line.clone(), 75, deadline())
        .await
        .is_err());
    assert_eq!(hw.startup.writes.lock().unwrap().len(), before);
    assert!(owner.cold_register_observation().unwrap().is_none());
    let attempt = app.voltage_attempts().unwrap().remove(0);
    assert_eq!(attempt.sequence(), 1);
    assert_eq!(attempt.steps().len(), 1);
    assert_eq!(attempt.steps()[0].response().len(), 7);
    assert!(attempt.completed_at().is_none());
    assert!(owner.is_terminal());
    let retained = app.conditioning_preparation_observation().unwrap().unwrap();
    assert!(
        retained.completed_at().is_none()
            && retained.failure().is_some()
            && retained.higher_voltage().is_none()
    );
    assert_eq!(
        app.last_commanded_voltage()
            .unwrap()
            .unwrap()
            .requested_centivolts(),
        1800
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_rejects_intervening_same_value_voltage_generation_before_cold_writes() {
    let (hw, owner, app, line, _) = prepared(&[0]).await;
    app.command_voltage_cv(1800, deadline()).await.unwrap();
    let previous = app.voltage_attempts().unwrap().remove(0);
    assert_eq!(previous.sequence(), 1);
    app.acknowledge_voltage_attempt(&previous).unwrap();
    let before = hw.startup.writes.lock().unwrap().len();
    let error = app
        .initialize_conditioning_preparation(line.clone(), 75, deadline())
        .await
        .unwrap_err();
    assert!(
        error.contains("PIC worker") || error.contains("intervening"),
        "{error}"
    );
    let retained = app.conditioning_preparation_observation().unwrap().unwrap();
    assert!(retained.failure().unwrap().contains("intervening"));
    assert!(retained.higher_voltage().is_none() && retained.completed_at().is_none());
    assert_eq!(hw.startup.writes.lock().unwrap().len(), before);
    assert!(owner.is_terminal());
    assert!(owner.cold_register_observation().unwrap().is_none());
}

async fn busy_entered(hw: &PreparationHardware) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while hw.busy_ticks.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_cancel_source_change_and_actual_busy_deadline_stop_later_cold_commands() {
    for defect in 0..3 {
        let (hw, owner, app, line, pin) = prepared(&[0]).await;
        hw.delay_phase.store(2, Ordering::SeqCst);
        hw.pause_busy_ms
            .store(if defect == 2 { 1500 } else { 250 }, Ordering::SeqCst);
        let until = if defect == 2 {
            Instant::now() + Duration::from_millis(1200)
        } else {
            deadline()
        };
        let waiter = tokio::spawn({
            let app = app.clone();
            let line = line.clone();
            async move {
                app.initialize_conditioning_preparation(line, 75, until)
                    .await
            }
        });
        busy_entered(&hw).await;
        let writes = hw.startup.writes.lock().unwrap().len();
        if defect == 0 {
            waiter.abort();
            assert!(waiter.await.unwrap_err().is_cancelled());
            line.terminal_high(deadline()).await.unwrap();
            assert!(owner
                .drain(Instant::now() + Duration::from_millis(20))
                .await
                .is_err());
            owner.drain(deadline()).await.unwrap();
        } else {
            if defect == 1 {
                gpio::Pin::high(&pin).unwrap();
            }
            let error = waiter.await.unwrap().unwrap_err();
            if defect == 2 {
                assert!(error.contains("deadline"), "{error}");
            }
        }
        assert_eq!(
            hw.startup.writes.lock().unwrap().len(),
            writes,
            "defect{defect}"
        );
        let retained = app.conditioning_preparation_observation().unwrap().unwrap();
        assert!(retained.completed_at().is_none() && retained.failure().is_some());
        assert!(retained.higher_voltage().unwrap().completed_at().is_some());
        assert!(owner
            .cold_register_observation()
            .unwrap()
            .unwrap()
            .completed_at()
            .is_none());
        assert!(owner.is_terminal());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_holds_voltage_through_baud_and_fresh_thermal_while_actual_heartbeat_completes()
{
    let (hw, owner, app, line, _) = prepared(&[0]).await;
    hw.delay_phase.store(2, Ordering::SeqCst);
    let gate = ReadBlock::new(BC);
    *hw.busy_test_gate.lock().unwrap() = Some(gate.clone());
    let preparation = tokio::spawn({
        let app = app.clone();
        let line = line.clone();
        async move {
            app.initialize_conditioning_preparation(line, 75, deadline())
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !gate.entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    let before = (
        hw.ticks.load(Ordering::SeqCst),
        hw.busy_ticks.load(Ordering::SeqCst),
        hw.emitted_registers.load(Ordering::SeqCst),
        hw.emitted_temperatures.load(Ordering::SeqCst),
    );
    let other_before = hw.non_asic_sleeps.load(Ordering::SeqCst);
    app.heartbeat_round(deadline()).await.unwrap();
    let competing = tokio::spawn({
        let app = app.clone();
        async move { app.command_voltage_cv(1900, deadline()).await }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while owner.workers.lock().unwrap().count < 3
            || hw.non_asic_sleeps.load(Ordering::SeqCst) == other_before
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(hw.voltage_frames.load(Ordering::SeqCst), 13);
    assert_eq!(
        (
            hw.ticks.load(Ordering::SeqCst),
            hw.busy_ticks.load(Ordering::SeqCst),
            hw.emitted_registers.load(Ordering::SeqCst),
            hw.emitted_temperatures.load(Ordering::SeqCst)
        ),
        before
    );
    assert!(hw.non_asic_sleeps.load(Ordering::SeqCst) > other_before);
    gate.release();
    let result = preparation.await.unwrap().unwrap();
    assert_eq!(
        result.higher_command().unwrap().requested_centivolts(),
        2000
    );
    assert!(result.operational_baud().unwrap().completed_at().is_some());
    assert!(!result.thermal_snapshots().is_empty());
    assert_eq!(
        competing.await.unwrap().unwrap().requested_centivolts(),
        1900
    );
    let writes = hw.inner().writes();
    let last_asic = writes
        .iter()
        .rposition(|&(offset, value)| offset == BC && value & BUSY != 0)
        .unwrap();
    let last_voltage = writes
        .iter()
        .rposition(|&(offset, value)| offset == 0x30 && value == 0x05201155)
        .unwrap();
    assert!(last_asic < last_voltage);
    assert_eq!(hw.voltage_frames.load(Ordering::SeqCst), 14);
    assert_eq!(hw.busy_ticks.load(Ordering::SeqCst), 0);
    assert!(hw.emitted_registers.load(Ordering::SeqCst) <= 300);
    assert!(!hw.overflow.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_hot_actual_temperature_preserves_raw_records_and_refuses_completion() {
    let (hw, owner, app, line, _) = prepared(&[0, 2, 7]).await;
    hw.raw_temperature.store(164, Ordering::SeqCst);
    let error = app
        .initialize_conditioning_preparation(line.clone(), 75, deadline())
        .await
        .unwrap_err();
    assert!(
        error.contains("temperature reached configured cutoff"),
        "{error}"
    );
    let records = owner.pending_returns().unwrap();
    assert!(records.iter().any(|raw|matches!(raw.payload(),ReturnPayload::Temperature(sample) if sample.raw_channels()[0]==164)));
    let retained = app.conditioning_preparation_observation().unwrap().unwrap();
    assert!(retained.completed_at().is_none() && retained.failure().is_some());
    assert!(retained.higher_voltage().unwrap().completed_at().is_some());
    assert!(retained.thermal_configuration().is_some());
    assert!(owner.is_terminal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_requires_actual_first_reset_and_same_source_owner() {
    let (hw, owner, app, line, _pin) = source_ready(&[0]).await;
    assert!(app.conditioning_reset_observation().unwrap().is_none());
    let before = hw.inner().writes();
    let error = app
        .initialize_conditioning_preparation(line.clone(), 75, deadline())
        .await
        .unwrap_err();
    assert!(error.contains("requires actual first reset"), "{error}");
    assert_eq!(hw.inner().writes(), before);
    assert!(app
        .conditioning_preparation_observation()
        .unwrap()
        .is_none());
    assert!(owner.is_terminal());

    let (hw, owner, app, _line, _pin) = prepared(&[0]).await;
    let (_foreign_hw, foreign_owner, foreign_app, foreign_line, _foreign_pin) =
        prepared(&[0]).await;
    assert!(app
        .conditioning_reset_observation()
        .unwrap()
        .unwrap()
        .same_owner(&owner));
    assert!(foreign_app
        .conditioning_reset_observation()
        .unwrap()
        .unwrap()
        .same_owner(&foreign_owner));
    let before = hw.inner().writes();
    let foreign_before = _foreign_hw.inner().writes();
    let error = app
        .initialize_conditioning_preparation(foreign_line.clone(), 75, deadline())
        .await
        .unwrap_err();
    assert!(
        error.contains("unused same-owner post-reset state"),
        "{error}"
    );
    assert_eq!(hw.inner().writes(), before);
    assert_eq!(_foreign_hw.inner().writes(), foreign_before);
    assert!(app
        .conditioning_preparation_observation()
        .unwrap()
        .is_none());
    assert!(owner.is_terminal());
    assert!(!foreign_owner.is_terminal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_final_thermal_zero_channels_and_elapsed_staleness_keep_failure_custody() {
    for defect in 1..=3 {
        let (hw, owner, app, line, _pin) = prepared(&[0, 2, 7]).await;
        hw.late_thermal_defect.store(defect, Ordering::SeqCst);
        let started = Instant::now();
        let error = app
            .initialize_conditioning_preparation(line, 75, deadline())
            .await
            .unwrap_err();
        assert!(
            hw.late_thermal_seen.load(Ordering::SeqCst),
            "defect{defect}: {error}"
        );
        let retained = app.conditioning_preparation_observation().unwrap().unwrap();
        assert_eq!(retained.stage(), ConditioningPreparationStage::FreshThermal);
        assert!(retained.completed_at().is_none());
        assert_eq!(retained.failure(), Some(error.as_str()));
        assert!(retained.higher_voltage().unwrap().completed_at().is_some());
        let baud = retained.operational_baud().unwrap();
        assert!(baud.completed_at().is_some());
        let snapshot = retained.thermal_snapshots().last().unwrap();
        if defect == 3 {
            assert!(started.elapsed() >= Duration::from_millis(7100));
            assert!(error.contains("thermal snapshot stale"), "{error}");
            assert!(!snapshot.is_fresh_at(Instant::now()));
            assert!(snapshot
                .samples()
                .iter()
                .all(|sample| sample.raw_channels() == [112, 128]));
        } else {
            assert!(
                error.contains("sensor channel has no valid position"),
                "{error}"
            );
            let channel = (defect - 1) as usize;
            assert_eq!(snapshot.samples().len(), 12);
            assert!(snapshot
                .samples()
                .iter()
                .all(|sample| sample.raw_channels()[channel] == 0));
            assert!(snapshot
                .samples()
                .iter()
                .all(|sample| sample.raw_channels()[1 - channel] != 0));
            assert!(snapshot
                .samples()
                .iter()
                .all(|sample| sample.received_at() > baud.completed_at().unwrap()));
            // The complete invalid snapshot moved into the application before
            // the producer's oldest receipt was acknowledged; it was not lost.
            assert_eq!(snapshot.raw_records().len(), 12);
            assert!(owner.pending_thermal_snapshots().unwrap().is_empty());
        }
        assert!(owner.is_terminal());
        assert!(!hw.overflow.load(Ordering::SeqCst));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_preserves_both_original_caller_waits_with_actual_fifo_service() {
    for chains in [vec![0], vec![0, 2, 7]] {
        let (hw, _owner, app, line, _pin) = prepared(&chains).await;
        // Once the actual baud receipt is complete, offer a full sensor
        // population on every1ms tick. An omitted caller delay cannot be masked
        // by a slow sensor source that happens to make final qualification wait.
        hw.immediate_after_baud.store(true, Ordering::SeqCst);
        let result = app
            .initialize_conditioning_preparation(line.clone(), 75, deadline())
            .await
            .unwrap();
        // Assertions must not retain the shared mutex used by source-pin Drop.
        let events = hw.inner().events.lock().unwrap().clone();
        let mut command = [0u8; 4];
        let mut value = 0;
        let mut commands = Vec::new();
        for (index, event) in events.iter().enumerate() {
            match event {
                Event::Write(0xc4, word) => command = word.to_be_bytes(),
                Event::Write(0xc8, word) => value = *word,
                Event::Write(BC, word) if word & BUSY != 0 => {
                    commands.push((index, command, value))
                }
                _ => {}
            }
        }
        let (auto_index, _, _) = *commands
            .iter()
            .rfind(|(_, frame, word)| frame[0] == 0x41 && frame[3] == 0x1c && *word == 0x07980000)
            .unwrap();
        let (baud_index, frame, _) = *commands
            .iter()
            .find(|(index, _, _)| *index > auto_index)
            .unwrap();
        assert_eq!((frame[0], frame[3]), (0x52, 0x18));
        let between = &events[auto_index + 1..baud_index];
        let mut start = 0;
        let mut sleeps = 0;
        for (end, event) in between.iter().enumerate() {
            if *event == Event::Sleep(1000) {
                let serviced = &between[start..end];
                for register in [0x18, 0x34, 0x3c] {
                    assert!(
                        serviced.contains(&Event::Read(register)),
                        "missing service before sleep{sleeps}: register{register:x}"
                    );
                }
                start = end + 1;
                sleeps += 1;
            }
        }
        assert_eq!(
            sleeps, 10,
            "first source caller10ms before initial baud query"
        );
        // Ten serviced caller ticks precede the new final-population watermark,
        // and at least one later tick supplies its actually fresh population.
        assert!(hw.after_baud_sleeps.load(Ordering::SeqCst) >= 11);
        let baud = result.operational_baud().unwrap().completed_at().unwrap();
        assert!(result
            .thermal_snapshots()
            .last()
            .unwrap()
            .samples()
            .iter()
            .all(|sample| sample.received_at() > baud));
        assert!(!hw.overflow.load(Ordering::SeqCst));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_pre_dma_nonce_retains_exact_raw_bytes_and_refuses_before_work_admission() {
    let (hw, owner, app, line, _pin) = prepared(&[0]).await;
    hw.force_pre_dma_nonce.store(true, Ordering::SeqCst);
    hw.delay_phase.store(1, Ordering::SeqCst);
    let error = app
        .initialize_conditioning_preparation(line.clone(), 75, deadline())
        .await
        .unwrap_err();
    assert!(
        error.contains("outstanding table is not admitted"),
        "{error}"
    );
    assert_eq!(hw.emitted_nonces.load(Ordering::SeqCst), 1);
    let pending = owner.pending_returns().unwrap();
    let raw = pending
        .iter()
        .find(|raw| matches!(raw.payload(), ReturnPayload::Unclassified(_)))
        .unwrap();
    assert_eq!(raw.words(), [0x80010080, 0, 0, 0x5555aaaa]);
    assert!(
        matches!(raw.payload(),ReturnPayload::Unclassified(reason) if reason.contains("outstanding table is not admitted"))
    );
    assert!(raw.same_owner(&owner));
    assert!(owner.publications().unwrap().is_empty());
    assert!(!hw
        .inner()
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| matches!(event, Event::DmaWrite(_, _) | Event::DmaRead(_, _))));
    let retained = app.conditioning_preparation_observation().unwrap().unwrap();
    assert!(retained.completed_at().is_none() && retained.failure().is_some());
    assert!(retained.higher_voltage().unwrap().completed_at().is_some());
    assert!(owner.is_terminal());
    assert!(!hw.overflow.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_pll_joins_actual_preparation_source_rail_and_five_stages_with_delayed_fifo() {
    for chains in [vec![0], vec![0, 2, 7]] {
        // A distinct runtime finishes preparation and drops its blocking pool.
        // The next phase must transfer real idle FIFO service to its new worker
        // before its first PLL command; no scripted ThreadId is overwritten here.
        let selected = chains.clone();
        let (hw, owner, app, line, _pin, preparation) = tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let (hw, owner, app, line, pin) = prepared(&selected).await;
                let preparation = app
                    .initialize_conditioning_preparation(line.clone(), 75, deadline())
                    .await
                    .unwrap();
                (hw, owner, app, line, pin, preparation)
            })
        })
        .await
        .unwrap();
        let preparation_thread = *hw.asic_writer.lock().unwrap();
        hw.delay_phase.store(6, Ordering::SeqCst);
        let result = app
            .initialize_conditioning_pll(line.clone(), deadline())
            .await
            .unwrap();
        assert_ne!(*hw.asic_writer.lock().unwrap(), preparation_thread);
        assert_eq!(
            result.preparation_completed_at(),
            preparation.completed_at()
        );
        assert_eq!(result.initial_voltage(), preparation.higher_command());
        assert!(result.completed_at().is_some() && result.failure().is_none());
        assert_eq!(
            result
                .stages()
                .iter()
                .map(|stage| stage.frequency_mhz())
                .collect::<Vec<_>>(),
            [60, 75, 100, 150, 300]
        );
        assert!(result
            .stages()
            .iter()
            .all(|stage| stage.commands().len() == 2 * chains.len()
                && stage
                    .commands()
                    .iter()
                    .all(|command| command.completed_at().is_some())
                && stage.settled_at().is_some()));
        let first = &result.stages()[0].voltage_plans()[0];
        assert_eq!(
            first.voltage_attempt().unwrap().prior_command(),
            preparation.higher_command()
        );
        assert_eq!(first.rail_verification().unwrap().checks().len(), 2);
        assert_eq!(
            result.final_adc().unwrap().baseline_minimum_passed(),
            Some(true)
        );
        assert!(hw.delayed.load(Ordering::SeqCst));
        assert_eq!(hw.emitted_nonces.load(Ordering::SeqCst), 0);
        let busy_records = hw.busy_thermal_records.load(Ordering::SeqCst);
        assert!(busy_records > 0);
        if chains.len() == 3 {
            // Three chains exceed the finite128-record FIFO in this delay.
            // One chain provides actual receive service below that capacity.
            assert!(busy_records > 128);
        } else {
            assert!(busy_records <= 128);
        }
        assert!(
            hw.busy_read_words.load(Ordering::SeqCst)
                >= hw.busy_thermal_records.load(Ordering::SeqCst) * 4
        );
        assert!(
            result
                .thermal_snapshots()
                .iter()
                .map(|snapshot| snapshot.raw_records().len())
                .sum::<usize>()
                >= hw.busy_thermal_records.load(Ordering::SeqCst) as usize
        );
        assert!(owner.pending_returns().unwrap().is_empty());
        assert!(!hw.overflow.load(Ordering::SeqCst));
        assert_eq!(
            hw.pll_commands.load(Ordering::SeqCst),
            10 * chains.len() as u32
        );
        assert!(owner.pending_thermal_snapshots().unwrap().is_empty());
        assert!(
            app.voltage_attempts().unwrap().is_empty()
                && app.rail_verifications().unwrap().is_empty()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_pll_refuses_generic_bypass_and_foreign_line_before_new_actuation() {
    for foreign in [false, true] {
        let (hw, owner, app, line, _pin) = prepared(&[0]).await;
        app.initialize_conditioning_preparation(line.clone(), 75, deadline())
            .await
            .unwrap();
        let (_foreign_hw, foreign_owner, _foreign_app, foreign_line, _foreign_pin) =
            prepared(&[0]).await;
        let before = hw.inner().writes();
        let error = if foreign {
            app.initialize_conditioning_pll(foreign_line.clone(), deadline())
                .await
                .unwrap_err()
        } else {
            app.initialize_cold_pll(deadline()).await.unwrap_err()
        };
        assert!(
            error.contains(if foreign {
                "preparation receipt/state join changed"
            } else {
                "preparation-bound PLL entry point"
            }),
            "{error}"
        );
        assert_eq!(hw.inner().writes(), before);
        assert!(app.cold_pll_observation().unwrap().is_none());
        assert!(owner.is_terminal());
        assert!(!foreign_owner.is_terminal());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_pll_refuses_acknowledged_same_value_voltage_generation_under_its_lease() {
    let (hw, owner, app, line, _pin) = prepared(&[0]).await;
    app.initialize_conditioning_preparation(line.clone(), 75, deadline())
        .await
        .unwrap();
    app.command_voltage_cv(2000, deadline()).await.unwrap();
    let attempt = app.voltage_attempts().unwrap().remove(0);
    assert_eq!(attempt.sequence(), 2);
    app.acknowledge_voltage_attempt(&attempt).unwrap();
    let before = hw.voltage_frames.load(Ordering::SeqCst);
    let error = app
        .initialize_conditioning_pll(line.clone(), deadline())
        .await
        .unwrap_err();
    assert!(error.contains("intervening voltage generation"), "{error}");
    assert_eq!(hw.voltage_frames.load(Ordering::SeqCst), before);
    assert_eq!(hw.rail_frames.load(Ordering::SeqCst), 0);
    assert_eq!(hw.pll_commands.load(Ordering::SeqCst), 0);
    let retained = app.cold_pll_observation().unwrap().unwrap();
    assert!(retained.completed_at().is_none());
    assert!(retained
        .failure()
        .unwrap()
        .contains("intervening voltage generation"));
    assert!(owner.is_terminal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_pll_source_reset_hot_record_and_cancellation_keep_partial_busy_command() {
    for defect in 0..4 {
        let (hw, owner, app, line, pin) = prepared(&[0, 2, 7]).await;
        app.initialize_conditioning_preparation(line.clone(), 75, deadline())
            .await
            .unwrap();
        hw.delay_phase.store(6, Ordering::SeqCst);
        let cancellation_gate = (defect == 3).then(|| ReadBlock::new(BC));
        if let Some(gate) = &cancellation_gate {
            *hw.busy_test_gate.lock().unwrap() = Some(gate.clone());
        } else {
            hw.pause_busy_ms.store(250, Ordering::SeqCst);
        }
        let task = tokio::spawn({
            let app = app.clone();
            let line = line.clone();
            async move { app.initialize_conditioning_pll(line, deadline()).await }
        });
        busy_entered(&hw).await;
        let commands = hw.pll_commands.load(Ordering::SeqCst);
        assert_eq!(commands, 1);
        if defect == 0 {
            gpio::Pin::high(&pin).unwrap();
        }
        if defect == 1 {
            *hw.inner().regs.lock().unwrap().get_mut(&0x34).unwrap() ^= 1;
        }
        if defect == 2 {
            hw.raw_temperature.store(164, Ordering::SeqCst);
        }
        if defect == 3 {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            line.terminal_high(deadline()).await.unwrap();
            let short_drain = owner
                .drain(Instant::now() + Duration::from_millis(20))
                .await;
            // Keep the actual command parked until after the drain attempt;
            // elapsed scheduler time must not release the worker under test.
            cancellation_gate.as_ref().unwrap().release();
            owner.drain(deadline()).await.unwrap();
            assert!(short_drain.is_err());
        } else {
            let error = task.await.unwrap().unwrap_err();
            if defect == 1 {
                assert!(error.contains("reset state changed"), "{error}");
            }
            if defect == 2 {
                assert!(
                    error.contains("temperature reached configured cutoff"),
                    "{error}"
                );
                assert!(owner.pending_returns().unwrap().iter().any(|raw|matches!(raw.payload(),ReturnPayload::Temperature(sample) if sample.raw_channels()[0]==164)));
            }
        }
        assert_eq!(hw.pll_commands.load(Ordering::SeqCst), commands);
        let retained = app.cold_pll_observation().unwrap().unwrap();
        assert!(retained.completed_at().is_none() && retained.failure().is_some());
        assert_eq!(retained.stages().len(), 1);
        assert_eq!(retained.stages()[0].commands().len(), 1);
        assert!(retained.stages()[0].commands()[0].completed_at().is_none());
        assert!(owner.is_terminal());
        assert!(!hw.overflow.load(Ordering::SeqCst));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_pll_actual_cleanup_and_predrain_failures_preserve_completion_custody() {
    for defect in 0..4 {
        let (hw, owner, app, line, pin) = prepared(&[0]).await;
        app.initialize_conditioning_preparation(line.clone(), 75, deadline())
            .await
            .unwrap();
        let gate = ReadBlock::new(0);
        *hw.final_cleanup_gate.lock().unwrap() = Some(gate.clone());
        let task = tokio::spawn({
            let app = app.clone();
            let line = line.clone();
            async move { app.initialize_conditioning_pll(line, deadline()).await }
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !gate.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(owner.workers.lock().unwrap().count, 1);
        let before = app.cold_pll_observation().unwrap().unwrap();
        assert!(before.completed_at().is_none() && before.failure().is_none());
        assert_eq!(
            before.final_adc().unwrap().baseline_minimum_passed(),
            Some(true)
        );
        assert_eq!(before.stages().len(), 5);
        let last_thermal = before.thermal_snapshots().last().unwrap().clone();
        let writes = hw.inner().writes();
        match defect {
            1 => *hw.inner().regs.lock().unwrap().get_mut(&0x34).unwrap() ^= 1,
            2 => gpio::Pin::high(&pin).unwrap(),
            3 => tokio::time::sleep(Duration::from_millis(7100)).await,
            _ => {}
        }
        gate.release();
        let result = task.await.unwrap();
        let retained = app.cold_pll_observation().unwrap().unwrap();
        assert_eq!(retained.final_adc(), before.final_adc());
        assert_eq!(retained.thermal_snapshots().last(), Some(&last_thermal));
        assert_eq!(hw.inner().writes(), writes);
        if defect == 0 {
            assert!(result.is_ok(), "{result:?}");
            assert!(retained.completed_at().is_some() && retained.failure().is_none());
            assert!(!owner.is_terminal());
        } else {
            let expected = match defect {
                1 => "reset state changed",
                2 => "active source is not observed low",
                _ => "thermal snapshot stale",
            };
            let error = result.unwrap_err();
            assert!(error.contains(expected), "{error}");
            assert!(retained.completed_at().is_none());
            assert!(retained.failure().unwrap().contains(expected));
            assert!(owner.is_terminal());
        }
        assert_eq!(owner.workers.lock().unwrap().count, 0);
    }
    let (hw, owner, app, line, _pin) = prepared(&[0]).await;
    let preparation = app
        .initialize_conditioning_preparation(line.clone(), 75, deadline())
        .await
        .unwrap();
    let before = hw.inner().writes();
    hw.fail_pll_predrain.store(true, Ordering::SeqCst);
    let error = app
        .initialize_conditioning_pll(line.clone(), deadline())
        .await
        .unwrap_err();
    assert!(
        error.contains("fixture actual PLL predrain FIFO read failure"),
        "{error}"
    );
    assert!(!hw.fail_pll_predrain.load(Ordering::SeqCst));
    let retained = app.cold_pll_observation().unwrap().unwrap();
    assert!(retained.completed_at().is_none() && retained.stages().is_empty());
    assert!(retained
        .failure()
        .unwrap()
        .contains("fixture actual PLL predrain FIFO read failure"));
    assert_eq!(retained.baseline_adc(), preparation.baseline_adc().unwrap());
    assert_eq!(hw.inner().writes(), before);
    assert_eq!(hw.pll_commands.load(Ordering::SeqCst), 0);
    assert_eq!(hw.rail_frames.load(Ordering::SeqCst), 0);
    assert_eq!(owner.workers.lock().unwrap().count, 0);
    assert!(owner.is_terminal());
}

#[path = "stock_bm1396_adapted_tests.rs"]
mod adapted_tests;
