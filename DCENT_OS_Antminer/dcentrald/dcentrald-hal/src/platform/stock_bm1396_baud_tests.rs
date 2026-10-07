use super::*;

#[test]
fn thermal_misc_heterogeneity_matches_original_shared_cache_then_broadcast() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("stock_bm1396_baud_vectors.json")).unwrap();
    for case in fixtures["thermal_joins"].as_array().unwrap() {
        let model = if case["model"] == "s17e" {
            Model::S17e
        } else {
            Model::T17e
        };
        let old = case["old_misc"].as_u64().unwrap() as u32;
        let enabled = case["shared_misc_after_enable"].as_u64().unwrap() as u32;
        let sensors = sensor_positions(model);
        let mut values: Vec<_> = (0..model.expected_chips_per_present_chain())
            .map(|index| {
                let chip = (index * u16::from(model.address_interval())) as u8;
                (
                    chip,
                    if sensors.iter().any(|sensor| sensor.wire_address() == chip) {
                        enabled
                    } else {
                        old
                    },
                )
            })
            .collect();
        assert_eq!(
            crate::platform::stock_bm1396::baud::normalized_misc(&values, model, true, Some(old))
                .unwrap(),
            enabled
        );
        assert_eq!(
            crate::platform::stock_bm1396::baud::normalized_misc(&values, model, false, Some(old))
                .is_ok(),
            old == enabled
        );
        values[0].1 ^= 0x80000000;
        assert!(crate::platform::stock_bm1396::baud::normalized_misc(
            &values,
            model,
            true,
            Some(old)
        )
        .is_err());
        values[0].1 ^= 0x80000000;
        // Every uncommanded non-sensor thermal-bit pattern is drift, even if
        // normalizing it would produce the requested all-chip broadcast.
        for bits in 0..16 {
            let pattern = ((bits & 7) << 4) | ((bits & 8) << 11);
            values[0].1 = (old & !0x4070) | pattern;
            assert_eq!(
                crate::platform::stock_bm1396::baud::normalized_misc(
                    &values,
                    model,
                    true,
                    Some(old)
                )
                .is_ok(),
                values[0].1 == old
            );
        }
        values[0].1 = old;
        assert!(
            crate::platform::stock_bm1396::baud::normalized_misc(&values, model, true, None)
                .is_err()
        );
        let sensor = values
            .iter_mut()
            .find(|(chip, _)| *chip == sensors[0].wire_address())
            .unwrap();
        sensor.1 ^= 0x10;
        assert!(crate::platform::stock_bm1396::baud::normalized_misc(
            &values,
            model,
            true,
            Some(old)
        )
        .is_err());
    }
}

struct BaudHardware {
    source: Arc<StartupHardware>,
    active: AtomicBool,
    switched: AtomicBool,
    changed_chains: Mutex<Vec<u8>>,
    defect: AtomicU32,
    host_block: Mutex<Option<Arc<ReadBlock>>>,
}
impl Hardware for BaudHardware {
    fn model(&self) -> Model {
        self.source.model()
    }
    fn validate_owner(&self) -> Result<(), String> {
        self.source.validate_owner()
    }
    fn claim_transport(&self) -> Result<(), String> {
        self.source.claim_transport()
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        let value = self.source.read(offset)?;
        Ok(
            if offset == 0x3c
                && self.switched.load(Ordering::SeqCst)
                && self.defect.load(Ordering::SeqCst) == 1
            {
                value ^ 0x40
            } else {
                value
            },
        )
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        let active = self.active.load(Ordering::SeqCst);
        let defect = self.defect.load(Ordering::SeqCst);
        if active && offset == BC && value & BUSY != 0 {
            let chain = ((value >> 16) & 15) as u8;
            let frame = self.source.inner.regs.lock().unwrap()[&0xc4].to_be_bytes();
            if frame[0] == 0x52 {
                let changed = self.changed_chains.lock().unwrap().contains(&chain);
                let host = self.source.inner.regs.lock().unwrap()[&0x3c] & 0x3f;
                let expected = if changed {
                    if self.model() == Model::S17e {
                        3
                    } else {
                        0
                    }
                } else {
                    26
                };
                if host != expected {
                    return Err("fixture actual ASIC/host baud mismatch".into());
                }
                if self.switched.load(Ordering::SeqCst) {
                    if defect == 2 {
                        self.source.defect.store(3, Ordering::SeqCst);
                    }
                    if defect == 3 {
                        self.source.defect.store(4, Ordering::SeqCst);
                    }
                    if defect == 4 && frame[3] == 0x18 {
                        *self.source.misc.lock().unwrap().get_mut(&chain).unwrap() ^= 2;
                    }
                }
            }
            if frame[0] == 0x51 && frame[3] == 0x68 && defect == 5 {
                return Err("fixture high-clock command store failure".into());
            }
            self.source.write(offset, value)?;
            if frame[0] == 0x51 && frame[3] == 0x18 {
                self.changed_chains.lock().unwrap().push(chain);
                if defect == 6 {
                    self.source.inner.regs.lock().unwrap().insert(8, 0);
                }
            }
            if frame[0] == 0x52 && frame[3] == 0x18 && defect == 9 {
                self.source.stream.lock().unwrap().get_mut(1).unwrap()[1] ^= 1;
            }
            return Ok(());
        }
        self.source.write(offset, value)?;
        if active && offset == 0x3c {
            self.switched.store(true, Ordering::SeqCst);
            if defect == 7 {
                self.source.inner.regs.lock().unwrap().insert(DHASH, RUN);
            }
            if let Some(block) = self.host_block.lock().unwrap().take() {
                *self.source.inner.block.lock().unwrap() = Some(block);
            }
        }
        Ok(())
    }
    fn read_dma(&self, offset: usize, out: &mut [u8]) -> Result<(), String> {
        self.source.read_dma(offset, out)
    }
    fn write_dma(&self, offset: usize, bytes: &[u8]) -> Result<(), String> {
        self.source.write_dma(offset, bytes)
    }
    fn barrier(&self) -> Result<(), String> {
        self.source.barrier()
    }
    fn sleep(&self, duration: Duration) {
        self.source.sleep(duration)
    }
}

async fn baud_owner(
    model: Model,
    chains: Vec<u8>,
) -> (Arc<BaudHardware>, Arc<Transport<BaudHardware>>) {
    let source = startup_hardware(model, &chains);
    source.inner.regs.lock().unwrap().insert(0x3c, 0xc19aa41a);
    for &chain in &chains {
        source.misc.lock().unwrap().insert(chain, 0xf0404030);
    }
    source.stream_returns.store(true, Ordering::SeqCst);
    let hardware = Arc::new(BaudHardware {
        source,
        active: AtomicBool::new(false),
        switched: AtomicBool::new(false),
        changed_chains: Mutex::new(Vec::new()),
        defect: AtomicU32::new(0),
        host_block: Mutex::new(None),
    });
    let owner = Transport::observe(hardware.clone(), model, chains.clone())
        .await
        .unwrap();
    owner.initialize_cold_registers(deadline()).await.unwrap();
    owner.acquire_domain_adc(deadline()).await.unwrap();
    hardware.source.writes.lock().unwrap().clear();
    hardware.source.inner.events.lock().unwrap().clear();
    hardware.active.store(true, Ordering::SeqCst);
    (hardware, owner)
}

#[tokio::test]
async fn operational_baud_matches_original_model_defaults_and_full_population() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("stock_bm1396_baud_vectors.json")).unwrap();
    for model in [Model::S17e, Model::T17e] {
        for chains in [vec![0], vec![0, 2, 7]] {
            let (hardware, owner) = baud_owner(model, chains.clone()).await;
            owner.switch_to_operational_baud(deadline()).await.unwrap();
            let observation = owner.operational_baud_observation().unwrap().unwrap();
            let key = if model == Model::S17e { "s17e" } else { "t17e" };
            let fixture = fixtures["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["model"] == key && case["old_misc"] == 0xf0004030u32)
                .unwrap();
            assert_eq!(observation.baud(), fixture["baud"].as_u64().unwrap() as u32);
            let writes: Vec<_> = fixture["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|event| event[0] == "asic_write")
                .flat_map(|event| {
                    chains.iter().map(move |&chain| {
                        (
                            chain,
                            event[1].as_u64().unwrap() as u8,
                            event[2].as_u64().unwrap() as u32,
                        )
                    })
                })
                .collect();
            assert_eq!(
                observation
                    .commands()
                    .iter()
                    .map(|command| (command.chain, command.register, command.value))
                    .collect::<Vec<_>>(),
                writes
            );
            assert!(observation
                .commands()
                .iter()
                .all(|command| command.completed));
            let host = fixture["events"].as_array().unwrap().last().unwrap()[1]
                .as_u64()
                .unwrap() as u32;
            assert_eq!(observation.requested_host_register(), host);
            assert_eq!(observation.host_readback(), Some(host));
            assert!(observation.host_write_attempted());
            assert!(observation.completed_at().is_some());
            assert_eq!(
                observation.raw_records().len(),
                chains.len() * usize::from(model.expected_chips_per_present_chain()) * 3
            );
            assert!(!hardware.source.overflow.load(Ordering::SeqCst));
            let count = hardware.source.inner.writes().len();
            assert!(owner.switch_to_operational_baud(deadline()).await.is_err());
            assert_eq!(hardware.source.inner.writes().len(), count);
            assert_eq!(
                owner.operational_baud_observation().unwrap(),
                Some(observation)
            );
        }
    }
}

#[tokio::test]
async fn operational_baud_guard_rejects_missing_or_acknowledged_adc_before_writes() {
    for model in [Model::S17e, Model::T17e] {
        let (hardware, owner) = startup_owner(model, vec![0]).await;
        assert!(owner.switch_to_operational_baud(deadline()).await.is_err());
        assert!(hardware.inner.writes().is_empty());
        for defect in [0, 1, 2] {
            let (hardware, owner) = baud_owner(model, vec![0]).await;
            match defect {
                0 => {
                    let observation = owner.domain_adc_observation().unwrap().unwrap();
                    owner.acknowledge_domain_adc(&observation).unwrap();
                }
                1 => {
                    hardware
                        .source
                        .inner
                        .regs
                        .lock()
                        .unwrap()
                        .insert(DHASH, RUN);
                }
                _ => {
                    *hardware
                        .source
                        .inner
                        .regs
                        .lock()
                        .unwrap()
                        .get_mut(&0x3c)
                        .unwrap() ^= 1 << 24;
                }
            }
            assert!(owner.switch_to_operational_baud(deadline()).await.is_err());
            assert!(hardware.source.inner.writes().is_empty());
            assert!(owner.operational_baud_observation().unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn operational_baud_failed_clock_host_population_and_presence_keep_custody() {
    for model in [Model::S17e, Model::T17e] {
        for defect in [1, 2, 3, 4, 5, 6, 7, 9, 10] {
            if model == Model::T17e && defect == 5 {
                continue;
            }
            let (hardware, owner) = baud_owner(model, vec![0]).await;
            if defect == 10 {
                *hardware.source.misc.lock().unwrap().get_mut(&0).unwrap() ^= 0x10;
            }
            hardware.defect.store(defect, Ordering::SeqCst);
            assert!(
                owner.switch_to_operational_baud(deadline()).await.is_err(),
                "{model:?}/{defect}"
            );
            assert!(owner.is_terminal());
            let observation = owner.operational_baud_observation().unwrap().unwrap();
            assert!(observation.completed_at().is_none());
            assert_eq!(
                observation.host_write_attempted(),
                [1, 2, 3, 4, 7].contains(&defect)
            );
            if defect == 5 {
                assert!(!observation.commands().last().unwrap().completed);
            }
            if [9, 10].contains(&defect) {
                assert!(observation.commands().is_empty());
                assert!(!observation.raw_records().is_empty());
            }
            assert!(!hardware.source.overflow.load(Ordering::SeqCst));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operational_baud_canceled_host_read_keeps_real_worker_and_final_word() {
    let (hardware, owner) = baud_owner(Model::S17e, vec![0]).await;
    let block = ReadBlock::new(0x3c);
    *hardware.host_block.lock().unwrap() = Some(block.clone());
    let task = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.switch_to_operational_baud(deadline()).await })
    };
    while !block.entered.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(5))
        .await
        .is_err());
    block.release();
    owner.drain(deadline()).await.unwrap();
    let observation = owner.operational_baud_observation().unwrap().unwrap();
    assert!(observation.host_write_attempted());
    assert_eq!(
        observation.host_readback(),
        Some(observation.requested_host_register())
    );
    assert!(observation
        .commands()
        .iter()
        .all(|command| command.completed));
    assert!(observation.completed_at().is_none());
}
