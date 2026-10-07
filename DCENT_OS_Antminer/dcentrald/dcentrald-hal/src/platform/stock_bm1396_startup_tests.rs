use super::*;

pub(super) struct StartupHardware {
    pub(super) inner: Arc<Fake>,
    commands: Mutex<Vec<(u8, [u8; 4])>>,
    assigned: Mutex<BTreeMap<u8, usize>>,
    pub(super) defect: AtomicU32,
    pub(super) adc_raw_override: AtomicU32,
    assignment_block: Mutex<Option<Arc<ReadBlock>>>,
    misc: Mutex<BTreeMap<u8, u32>>,
    pub(super) writes: Mutex<Vec<ColdRegisterCommand>>,
    cold_block: Mutex<Option<Arc<ReadBlock>>>,
    stream_returns: AtomicBool,
    stream: Mutex<VecDeque<[u32; 4]>>,
    overflow: AtomicBool,
    adc_block: Mutex<Option<Arc<ReadBlock>>>,
}
impl StartupHardware {
    pub(super) fn stream_reset_replies(&self) {
        self.stream_returns.store(true, Ordering::SeqCst);
    }
    pub(super) fn reset_stream_overflowed(&self) -> bool {
        self.overflow.load(Ordering::SeqCst)
    }
}

impl Hardware for StartupHardware {
    fn model(&self) -> Model {
        self.inner.model()
    }
    fn validate_owner(&self) -> Result<(), String> {
        self.inner.validate_owner()
    }
    fn claim_transport(&self) -> Result<(), String> {
        self.inner.claim_transport()
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        if offset == 0x18 {
            return Ok(self.inner.returns.lock().unwrap().len().min(510) as u32);
        }
        self.inner.read(offset)
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.inner.write(offset, value)?;
        if offset != BC || value & BUSY == 0 {
            return Ok(());
        }
        let frame = self.inner.regs.lock().unwrap()[&0xc4].to_be_bytes();
        let chain = ((value >> 16) & 15) as u8;
        self.commands.lock().unwrap().push((chain, frame));
        let defect = self.defect.load(Ordering::SeqCst);
        match frame[0] {
            0x52 => {
                if frame[..3] != [0x52, 5, 0] || ![0, 0x18, 0xb4, 0xb8].contains(&frame[3]) {
                    return Err("fixture only implements register0 census".into());
                }
                let assigned = *self.assigned.lock().unwrap().get(&chain).unwrap_or(&0) > 0;
                let total = match self.inner.model {
                    Model::S17e => 135,
                    Model::T17e => 78,
                };
                if defect == 7 && !assigned {
                    return Ok(());
                }
                let total = total + usize::from(defect == 35 && !assigned)
                    - usize::from((defect == 1 && !assigned) || (defect == 20 && frame[3] == 0xb4));
                let interval = match self.inner.model {
                    Model::S17e => 1,
                    Model::T17e => 3,
                };
                for index in 0..total {
                    let chip = if assigned {
                        if (defect == 3 || defect == 21) && index == 1 {
                            0
                        } else {
                            (index * interval) as u8 + u8::from(defect == 22 && index == 0)
                        }
                    } else {
                        0
                    };
                    let id = if [0xb4, 0xb8].contains(&frame[3]) {
                        if self.adc_raw_override.load(Ordering::SeqCst) != 0 {
                            let raw = self.adc_raw_override.load(Ordering::SeqCst);
                            (raw << 16) | raw
                        } else if defect == 28 && frame[3] == 0xb8 {
                            0
                        } else if defect == 29 && frame[3] == 0xb8 {
                            0x0800_0800
                        } else {
                            0xfbb8_fbb8
                        }
                    } else if frame[3] == 0x18 {
                        let value = *self
                            .misc
                            .lock()
                            .unwrap()
                            .get(&chain)
                            .unwrap_or(&0x1240_4030);
                        if index == 1 && defect == 8 && self.writes.lock().unwrap().is_empty() {
                            value ^ 1
                        } else if defect == 9 && !self.writes.lock().unwrap().is_empty() {
                            value ^ 2
                        } else {
                            value
                        }
                    } else if index == 0
                        && ((defect == 2 && !assigned) || (defect == 4 && assigned))
                    {
                        0x13970000
                    } else {
                        0x13960000
                    };
                    let reply_chain = if ((defect == 5 && !assigned) || defect == 23) && index == 0
                    {
                        (chain + 1) & 15
                    } else {
                        chain
                    };
                    let reply_register = if defect == 24 { 0x08 } else { frame[3] };
                    let words = [
                        u32::from_le_bytes([
                            reply_chain | if defect == 25 { 0x40 } else { 0 },
                            reply_register,
                            chip,
                            if defect == 33 { 0x42 } else { 2 },
                        ]),
                        id,
                        0x11,
                        0x5555aaaa,
                    ];
                    if self.stream_returns.load(Ordering::SeqCst) {
                        self.stream.lock().unwrap().push_back(words);
                    } else {
                        self.inner.words(&words);
                    }
                }
                if frame[3] == 0xb4 && defect == 26 {
                    self.inner.words(&[
                        u32::from_le_bytes([chain, 0xb8, 0, 2]),
                        0x0bb8_0bb8,
                        0x11,
                        0x5555aaaa,
                    ]);
                }
                if frame[3] == 0xb4 && defect == 32 {
                    self.inner.words(&[0x80010080, 0, 0, 0x5555aaaa]);
                }
                if frame[3] == 0xb8 {
                    if let Some(block) = self.adc_block.lock().unwrap().take() {
                        *self.inner.block.lock().unwrap() = Some(block);
                    }
                }
                if frame[3] == 0xb4 && defect == 30 {
                    *self.inner.regs.lock().unwrap().entry(0x3c).or_default() ^= 1 << 24;
                }
                if frame[3] == 0xb4 && defect == 31 {
                    self.inner.regs.lock().unwrap().insert(DHASH, RUN);
                }
            }
            0x53 => {
                if frame != [0x53, 5, 0, 0] {
                    return Err("invalid reset fixture frame".into());
                }
            }
            0x40 => {
                *self.assigned.lock().unwrap().entry(chain).or_default() += 1;
                if defect == 6 {
                    *self.inner.regs.lock().unwrap().entry(0x3c).or_default() ^= 1 << 16;
                }
                if let Some(block) = self.assignment_block.lock().unwrap().take() {
                    *self.inner.block.lock().unwrap() = Some(block);
                }
            }
            0x51 | 0x41 => {
                let word = self.inner.regs.lock().unwrap()[&0xc8];
                self.writes.lock().unwrap().push(ColdRegisterCommand {
                    chain,
                    broadcast: frame[0] == 0x51,
                    chip_address: frame[2],
                    register: frame[3],
                    value: word,
                });
                if frame[3] == 0x18 {
                    self.misc.lock().unwrap().insert(chain, word);
                }
                if frame[3] == 0xb0 && word == 0x0010_0000 && defect == 27 {
                    return Err("injected ADC B0 restore failure".into());
                }
                if frame[3] == 0x3c {
                    if let Some(block) = self.cold_block.lock().unwrap().take() {
                        *self.inner.block.lock().unwrap() = Some(block);
                    }
                }
                if defect == 10 && frame[3] == 0xb0 {
                    *self.inner.regs.lock().unwrap().entry(0x3c).or_default() ^= 1 << 24;
                }
                if defect == 11 && frame[3] == 0x2c {
                    self.inner.regs.lock().unwrap().insert(DHASH, RUN);
                }
                if defect == 12 && frame[3] == 0x2c {
                    self.inner.regs.lock().unwrap().insert(8, 0);
                }
            }
            _ => return Err("fixture rejects unknown startup command".into()),
        }
        Ok(())
    }
    fn read_dma(&self, offset: usize, out: &mut [u8]) -> Result<(), String> {
        self.inner.read_dma(offset, out)
    }
    fn write_dma(&self, offset: usize, data: &[u8]) -> Result<(), String> {
        self.inner.write_dma(offset, data)
    }
    fn barrier(&self) -> Result<(), String> {
        self.inner.barrier()
    }
    fn sleep(&self, duration: Duration) {
        self.inner.sleep(duration);
        if self.stream_returns.load(Ordering::SeqCst) {
            // One frame per millisecond; the hardware FIFO holds only16 here.
            // A monolithic300ms sleep overflows; retained1ms draining succeeds.
            for _ in 0..duration.as_millis() {
                let Some(words) = self.stream.lock().unwrap().pop_front() else {
                    break;
                };
                if self.inner.returns.lock().unwrap().len() >= 64 {
                    self.overflow.store(true, Ordering::SeqCst);
                } else {
                    self.inner.words(&words);
                }
            }
        }
    }
}
pub(super) fn startup_hardware(model: Model, chains: &[u8]) -> Arc<StartupHardware> {
    let mask = chains.iter().fold(0, |mask, chain| mask | (1 << chain));
    let hardware = Arc::new(StartupHardware {
        inner: Fake::new(model, mask),
        commands: Mutex::new(Vec::new()),
        assigned: Mutex::new(BTreeMap::new()),
        defect: AtomicU32::new(0),
        adc_raw_override: AtomicU32::new(0),
        assignment_block: Mutex::new(None),
        misc: Mutex::new(BTreeMap::new()),
        writes: Mutex::new(Vec::new()),
        cold_block: Mutex::new(None),
        stream_returns: AtomicBool::new(false),
        stream: Mutex::new(VecDeque::new()),
        overflow: AtomicBool::new(false),
        adc_block: Mutex::new(None),
    });
    hardware.inner.regs.lock().unwrap().insert(0x3c, 0x1a1a1a1a);
    hardware
}
async fn startup_owner(
    model: Model,
    chains: Vec<u8>,
) -> (Arc<StartupHardware>, Arc<Transport<StartupHardware>>) {
    let hardware = startup_hardware(model, &chains);
    let transport = Transport::observe(hardware.clone(), model, chains)
        .await
        .unwrap();
    (hardware, transport)
}

#[tokio::test]
async fn complete_original_address_counts_and_spacing_then_unique_identity_census() {
    for model in [Model::S17e, Model::T17e] {
        let (hw, transport) = startup_owner(model, vec![0, 2]).await;
        // A pre-existing correctly shaped reply is retained, never counted.
        hw.inner.words(&[0x02000000, 0x13960000, 0x11, 0x5555aaaa]);
        transport
            .initialize_assigned_population(deadline())
            .await
            .unwrap();
        let observation = transport.assignment_observation().unwrap().unwrap();
        let (chips, assignments, interval) = match model {
            Model::S17e => (135, 256, 1),
            Model::T17e => (78, 85, 3),
        };
        assert_eq!(observation.initial_records().len(), chips * 2);
        assert_eq!(observation.assigned_records().len(), chips * 2);
        assert_eq!(observation.host_baud_register(), 0x1a1a1a1a);
        assert_eq!(observation.chains(), [0, 2]);
        assert_eq!(transport.pending_returns().unwrap().len(), 1);
        let commands = hw.commands.lock().unwrap();
        assert_eq!(commands[..2], [(0, [0x52, 5, 0, 0]), (2, [0x52, 5, 0, 0])]);
        for chain in [0, 2] {
            assert_eq!(
                commands
                    .iter()
                    .filter(|(slot, frame)| *slot == chain && frame[0] == 0x53)
                    .count(),
                3
            );
            let actual: Vec<_> = commands
                .iter()
                .filter(|(slot, frame)| *slot == chain && frame[0] == 0x40)
                .map(|(_, frame)| frame[2])
                .collect();
            assert_eq!(
                actual,
                (0..assignments)
                    .map(|index| (index * interval) as u8)
                    .collect::<Vec<_>>()
            );
        }
        drop(commands);
        let events = hw.inner.events.lock().unwrap().clone();
        let mut frame = [0u8; 4];
        let mut issued = Vec::new();
        for (index, event) in events.iter().enumerate() {
            match event {
                Event::Write(0xc4, word) => frame = word.to_be_bytes(),
                Event::Write(BC, word) if word & BUSY != 0 => issued.push((index, frame)),
                _ => {}
            }
        }
        let mut spaced = 0usize;
        for pair in issued.windows(2) {
            if ![0x53, 0x40].contains(&pair[0].1[0]) {
                continue;
            }
            let between = &events[pair[0].0 + 1..pair[1].0];
            let mut elapsed_us = 0u64;
            let mut segment = 0;
            for (index, event) in between.iter().enumerate() {
                if let Event::Sleep(us) = event {
                    assert_eq!(*us, 1000);
                    assert!(between[segment..index].contains(&Event::Read(0x3c)));
                    elapsed_us += *us;
                    segment = index + 1;
                }
            }
            // Every reset/set-address has the original30ms spacing. The final
            // address is followed by the source's additional10ms before query.
            assert_eq!(
                elapsed_us,
                if pair[1].1[0] == 0x52 { 40_000 } else { 30_000 }
            );
            spaced += 1;
        }
        assert_eq!(spaced, (assignments + 3) * 2);
        assert!(
            hw.inner
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == Event::Sleep(1_000))
                .count()
                >= 2_000
        );
        let count = hw.inner.writes().len();
        assert!(transport
            .initialize_assigned_population(deadline())
            .await
            .is_err());
        assert_eq!(hw.inner.writes().len(), count);
    }
}

#[tokio::test]
async fn short_wrong_identity_duplicate_assigned_and_host_change_never_mint_observation() {
    for defect in 1..=7 {
        let (hw, transport) = startup_owner(Model::S17e, vec![0]).await;
        hw.defect.store(defect, Ordering::SeqCst);
        assert!(transport
            .initialize_assigned_population(deadline())
            .await
            .is_err());
        assert!(transport.assignment_observation().unwrap().is_none());
        assert!(transport.is_terminal());
        if defect != 7 {
            assert!(!transport.pending_returns().unwrap().is_empty());
        }
        if matches!(defect, 1 | 2 | 5 | 7) {
            assert!(!hw
                .commands
                .lock()
                .unwrap()
                .iter()
                .any(|(_, frame)| matches!(frame[0], 0x53 | 0x40)));
        }
    }
}

#[tokio::test]
async fn cancelled_mid_assignment_retains_census_and_real_worker_until_drain() {
    let (hw, transport) = startup_owner(Model::T17e, vec![0]).await;
    let block = ReadBlock::new(BC);
    *hw.assignment_block.lock().unwrap() = Some(block.clone());
    let copy = transport.clone();
    let task = tokio::spawn(async move { copy.initialize_assigned_population(deadline()).await });
    let until = Instant::now() + Duration::from_secs(2);
    while !block.entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < until);
        tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.is_err());
    assert!(transport
        .drain(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    block.release();
    transport.drain(deadline()).await.unwrap();
    assert_eq!(transport.pending_returns().unwrap().len(), 78);
    assert!(transport.assignment_observation().unwrap().is_none());
    assert_eq!(
        hw.commands
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, frame)| frame[0] == 0x40)
            .count(),
        1
    );
    assert!(transport.asic_fault.load(Ordering::SeqCst));
}

#[tokio::test]
async fn active_engine_and_short_absolute_census_budget_fail_closed() {
    let (hw, transport) = startup_owner(Model::S17e, vec![0]).await;
    hw.inner.regs.lock().unwrap().insert(DHASH, RUN);
    assert!(transport
        .initialize_assigned_population(deadline())
        .await
        .is_err());
    assert!(hw.inner.writes().is_empty());
    let (hw, transport) = startup_owner(Model::S17e, vec![0]).await;
    assert!(transport
        .initialize_assigned_population(Instant::now() + Duration::from_millis(200))
        .await
        .is_err());
    assert_eq!(hw.commands.lock().unwrap().len(), 1);
    assert!(transport.assignment_observation().unwrap().is_none());
    assert!(transport.is_terminal());
}

#[path = "stock_bm1396_adc_tests.rs"]
mod adc_tests;
#[path = "stock_bm1396_baud_tests.rs"]
mod baud_tests;
#[path = "stock_bm1396_cold_tests.rs"]
mod cold_tests;

#[tokio::test]
async fn source_wait_window_keeps_draining_a_finite_fifo_with_gradual_population() {
    for model in [Model::S17e, Model::T17e] {
        let (hw, transport) = startup_owner(model, vec![0, 2]).await;
        hw.stream_returns.store(true, Ordering::SeqCst);
        transport
            .initialize_cold_registers(deadline())
            .await
            .unwrap();
        assert!(!hw.overflow.load(Ordering::SeqCst));
        assert!(hw.stream.lock().unwrap().is_empty());
        assert!(transport
            .cold_register_observation()
            .unwrap()
            .unwrap()
            .completed_at()
            .is_some());
        assert!(transport.assignment_observation().unwrap().is_some());
    }
}
