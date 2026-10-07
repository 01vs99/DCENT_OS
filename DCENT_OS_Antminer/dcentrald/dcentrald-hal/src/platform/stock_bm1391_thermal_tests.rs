use super::*;
use std::collections::BTreeMap;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

fn register_reply(chain: u8, chip: u8, register: u8, value: u32) -> Bm1391StockRegisterReturn {
    let mut packet = [0; 7];
    packet[..4].copy_from_slice(&value.to_be_bytes());
    packet[4] = chip;
    packet[5] = register;
    Bm1391StockRegisterReturn {
        chain_slot: chain,
        chip_address: chip,
        register,
        value,
        crc5: dcentrald_common::s9se_vil::crc5_bits(&packet, 51),
        register_type: 0,
        fpga_crc_error: false,
    }
}
fn encoded(reply: Bm1391StockRegisterReturn) -> (u32, u32) {
    (
        u32::from(reply.chain_slot)
            | (u32::from(reply.register) << 8)
            | (u32::from(reply.chip_address) << 16)
            | (u32::from(reply.crc5) << 24)
            | if reply.fpga_crc_error { 0x40 } else { 0 },
        reply.value,
    )
}
fn nonce(chain: u8, id: u16, value: u32) -> (u32, u32) {
    (
        0x8000_0080 | u32::from(chain) | (u32::from(id) << 16),
        value,
    )
}
fn census(model: Model, chain: u8) -> Census {
    Census {
        chain,
        replies: (0..model.expected_chips())
            .map(|i| register_reply(chain, i * model.address_interval(), 0, 0x1391_0000))
            .collect(),
    }
}
fn page() -> [u8; 256] {
    let mut page = [0; 256];
    page[0] = 0x7e;
    page[0x79] = 1;
    seal(&mut page);
    page
}
fn seal(page: &mut [u8; 256]) {
    let crc = dcentrald_common::bm1391_stock_work::bm1391_stock_job_crc16(&page[..254]);
    page[254..].copy_from_slice(&crc.to_le_bytes());
}

struct Script {
    words: [u32; 3],
    frames: Vec<(u8, [u8; 12])>,
    returns: VecDeque<(u32, u32)>,
    misc: BTreeMap<(u8, u8), u32>,
    bridge: BTreeMap<(u8, u8), u32>,
    config: BTreeMap<(u8, u8), u8>,
    eeprom_command: u32,
    eeprom_writes: usize,
    manufacturer: u8,
    sensor_address: u8,
    temperature: u8,
    wrong_config: bool,
    bad_crc: bool,
    wrong_echo: bool,
    busy: bool,
    omit_reply: bool,
    noise: bool,
}
impl Default for Script {
    fn default() -> Self {
        Self {
            words: [0; 3],
            frames: Vec::new(),
            returns: VecDeque::new(),
            misc: BTreeMap::new(),
            bridge: BTreeMap::new(),
            config: BTreeMap::new(),
            eeprom_command: 0,
            eeprom_writes: 0,
            manufacturer: 0x55,
            sensor_address: 0x98,
            temperature: 0x64,
            wrong_config: false,
            bad_crc: false,
            wrong_echo: false,
            busy: false,
            omit_reply: false,
            noise: false,
        }
    }
}
struct ScriptRegisters {
    model: Model,
    state: Mutex<Script>,
}
impl Registers for ScriptRegisters {
    fn model(&self) -> Option<Model> {
        Some(self.model)
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        let mut s = self.state.lock().unwrap();
        Ok(match offset {
            VERSION => 0xc501,
            PRESENCE | WORK_SPACE => 7,
            COMMAND_CONTROL => 0,
            RETURN_COUNT => s.returns.len() as u32,
            RETURN0 => s.returns.front().ok_or("empty fixture FIFO")?.0,
            RETURN1 => s.returns.pop_front().ok_or("empty fixture FIFO")?.1,
            0x30 => 0x8000_0000 | u32::from(page()[((s.eeprom_command >> 8) & 255) as usize]),
            _ => return Err(format!("unexpected thermal read {offset:x}")),
        })
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        let mut s = self.state.lock().unwrap();
        match offset {
            0x30 => {
                s.eeprom_command = value;
                s.eeprom_writes += 1;
            }
            COMMAND_BUFFER..=0xcc => s.words[((offset - COMMAND_BUFFER) / 4) as usize] = value,
            COMMAND_CONTROL => {
                let frame: [u8; 12] = std::array::from_fn(|i| s.words[i / 4].to_be_bytes()[i % 4]);
                let chain = ((value >> 16) & 15) as u8;
                let chip = frame[2];
                let register = frame[3];
                s.frames.push((chain, frame));
                let key = (chain, chip);
                match (frame[0], register) {
                    (0x41, MISC_CONTROL) => {
                        s.misc
                            .insert(key, u32::from_be_bytes(frame[4..8].try_into().unwrap()));
                    }
                    (0x41, BRIDGE) => {
                        let sensor_register = frame[6];
                        let data = if frame[5] & 1 != 0 {
                            let data = if s.wrong_config { 7 } else { frame[7] };
                            s.config.insert(key, data);
                            data
                        } else if frame[5] != s.sensor_address {
                            0
                        } else {
                            match sensor_register {
                                0xfe => s.manufacturer,
                                9 => *s.config.get(&key).unwrap_or(&0),
                                0 => s.temperature,
                                _ => 0,
                            }
                        };
                        let echo = if s.wrong_echo {
                            sensor_register ^ 1
                        } else {
                            sensor_register
                        };
                        s.bridge
                            .insert(key, (u32::from(echo) << 8) | u32::from(data));
                    }
                    (0x42, _) => {
                        let value = if register == MISC_CONTROL {
                            *s.misc.get(&key).unwrap_or(&0x3a03)
                        } else if s.busy {
                            0x8000_0000
                        } else {
                            *s.bridge.get(&key).unwrap_or(&0)
                        };
                        let mut reply = register_reply(chain, chip, register, value);
                        if s.bad_crc {
                            reply.crc5 ^= 1;
                        }
                        if s.noise {
                            s.returns.push_back(nonce(15, 0x7fff, 0xabcdef01));
                            s.returns.push_back(encoded(register_reply(
                                chain ^ 1,
                                chip,
                                register,
                                value,
                            )));
                            s.returns.push_back(encoded(register_reply(
                                chain,
                                chip ^ 1,
                                register,
                                value,
                            )));
                            s.returns.push_back(encoded(register_reply(
                                chain,
                                chip,
                                register ^ 4,
                                value,
                            )));
                        }
                        if !s.omit_reply {
                            s.returns.push_back(encoded(reply));
                        }
                    }
                    _ => return Err("unexpected thermal command".into()),
                }
            }
            _ => return Err(format!("unexpected thermal write {offset:x}")),
        }
        Ok(())
    }
}

fn fixture(
    model: Model,
    chain: u8,
    initialized: bool,
) -> (
    Arc<ScriptRegisters>,
    Arc<ThermalApplication<ScriptRegisters>>,
) {
    let registers = Arc::new(ScriptRegisters {
        model,
        state: Mutex::new(Script::default()),
    });
    let owner = Transport::new(registers.clone(), vec![chain]).unwrap();
    let endpoints = topology_from_page(model, &census(model, chain), &page()).unwrap();
    let sensors = initialized.then(|| {
        endpoints
            .iter()
            .map(|&(chain, chip_address)| ThermalSensor {
                chain,
                chip_address,
                sensor_address: 0x98,
                manufacturer: 0x55,
            })
            .collect()
    });
    let service = Arc::new(ThermalApplication {
        owner,
        endpoints,
        sensors: Mutex::new(sensors),
        operation: Mutex::new(()),
        in_flight: AtomicUsize::new(0),
        nonces: Mutex::default(),
    });
    (registers, service)
}

#[test]
fn exact_topology_requires_full_page_integrity_type_and_complete_model_census() {
    for (model, expected) in [
        (Model::S15, [0x33, 0x24, 0x9f, 0x90]),
        (Model::T15, [0x38, 0x28, 0xb0, 0xa0]),
    ] {
        let population = census(model, 2);
        assert_eq!(
            topology_from_page(model, &population, &page()).unwrap(),
            expected.map(|chip| (2, chip))
        );
        for byte in [0, 0x79, 253, 254, 255] {
            let mut corrupt = page();
            corrupt[byte] ^= 1;
            assert!(topology_from_page(model, &population, &corrupt).is_err());
        }
        for kind in [0, 6, 7, 255] {
            let mut unsupported = page();
            unsupported[0x79] = kind;
            seal(&mut unsupported);
            assert!(topology_from_page(model, &population, &unsupported).is_err());
        }
        let mut missing = population.clone();
        missing.replies.pop();
        assert!(topology_from_page(model, &missing, &page()).is_err());
        let mut wrong = population.clone();
        wrong.replies[0].crc5 ^= 1;
        assert!(topology_from_page(model, &wrong, &page()).is_err());
        let mut wrong = population;
        wrong.replies.swap(0, 1);
        assert!(topology_from_page(model, &wrong, &page()).is_err());
    }
}

#[test]
fn all_original_initializer_frames_match_native_bridge_and_misc_encodings() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut checked = 0;
    for release in oracle["releases"].as_array().unwrap() {
        for run in release["initializations"].as_array().unwrap() {
            for (index, frame) in run["command_frames"].as_array().unwrap().iter().enumerate() {
                let address = run["chip_addresses"][index / 4].as_u64().unwrap() as u8;
                let actual = match index % 4 {
                    0 => Transport::<ScriptRegisters>::register_frame(
                        address,
                        false,
                        MISC_CONTROL,
                        0x7a31,
                    ),
                    1 => bridge_frame::<ScriptRegisters>(address, 0x98, 0xfe, 0, false),
                    2 => bridge_frame::<ScriptRegisters>(address, 0x98, 9, 4, true),
                    3 => bridge_frame::<ScriptRegisters>(address, 0x98, 9, 0, false),
                    _ => unreachable!(),
                };
                for (word, event) in actual.chunks_exact(4).zip(frame.as_array().unwrap()) {
                    assert_eq!(
                        u32::from_be_bytes(word.try_into().unwrap()),
                        event["value"].as_u64().unwrap() as u32
                    );
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 288);
}

#[test]
fn initialize_discovers_supported_addresses_preserves_baud_and_requires_config_readback() {
    for model in [Model::S15, Model::T15] {
        for sensor_address in [0x98, 0x9a, 0x9c] {
            let (registers, service) = fixture(model, 1, false);
            {
                let mut s = registers.state.lock().unwrap();
                s.sensor_address = sensor_address;
                s.manufacturer = 0x41;
            }
            let sensors = service
                .owner
                .with_asic_lane(deadline(), || {
                    service.initialize_locked(deadline(), &mut |_| Ok(()), &mut 0)
                })
                .unwrap();
            assert_eq!(sensors.len(), 4);
            assert!(sensors
                .iter()
                .all(|s| s.sensor_address == sensor_address && s.manufacturer == 0x41));
            let state = registers.state.lock().unwrap();
            assert!(state.misc.values().all(|value| *value == 0x7a33));
            assert!(state.config.values().all(|value| *value == 4));
            assert!(!service.owner.terminal());
        }
    }
    let (registers, service) = fixture(Model::S15, 0, false);
    registers.state.lock().unwrap().wrong_config = true;
    assert!(service
        .owner
        .with_asic_lane(deadline(), || service.initialize_locked(
            deadline(),
            &mut |_| Ok(()),
            &mut 0
        ))
        .is_err());
    assert!(service.sensors.lock().unwrap().is_none());
    assert!(service.owner.terminal());
}

#[test]
fn runtime_sampling_preserves_nonce_flags_and_rejects_stale_registers_without_caching_temperature()
{
    let (registers, service) = fixture(Model::T15, 2, true);
    {
        let mut s = registers.state.lock().unwrap();
        s.noise = true;
        s.returns.push_back(nonce(2, 0x7abc, 0x12345678));
        s.returns
            .push_back(encoded(register_reply(2, 0x38, BRIDGE, 0x00ff)));
    }
    let mut discarded = 0;
    let samples = service
        .owner
        .with_asic_lane(deadline(), || {
            service.sample_locked(deadline(), &mut |_| Ok(()), &mut discarded)
        })
        .unwrap();
    assert_eq!(samples.len(), 4);
    assert!(samples
        .iter()
        .all(|s| s.pcb_celsius == 36 && s.estimated_chip_celsius == 51 && s.raw_extended == 0x64));
    assert_eq!(discarded, 25); // one preexisting + three mismatches for eight reads
    let pending = service.snapshot_nonces();
    assert_eq!(pending.len(), 9);
    assert_eq!(
        (pending[0].record.work_id, pending[0].record.nonce),
        (0x7abc, 0x12345678)
    );
    assert_eq!(pending[1].record.chain_slot, 15); // retained for canonical rejection
    assert_eq!(service.snapshot_nonces(), pending); // snapshots never consume
    assert!(service.acknowledge_nonces_through(10).is_err());
    service.acknowledge_nonces_through(9).unwrap();
    assert!(service.snapshot_nonces().is_empty());
    registers.state.lock().unwrap().wrong_echo = true;
    assert!(service
        .owner
        .with_asic_lane(deadline(), || service.sample_locked(
            deadline(),
            &mut |_| Ok(()),
            &mut 0
        ))
        .is_err());
    assert!(service.owner.terminal());
}

#[test]
fn crc_bridge_busy_and_deadline_failures_latch_and_keep_all_preexisting_nonces() {
    for failure in ["crc", "busy", "missing"] {
        let (registers, service) = fixture(Model::S15, 0, true);
        {
            let mut s = registers.state.lock().unwrap();
            s.returns.push_back(nonce(0, 7, 11));
            match failure {
                "crc" => s.bad_crc = true,
                "busy" => s.busy = true,
                _ => s.omit_reply = true,
            }
        }
        let until = Instant::now() + Duration::from_millis(10);
        let result = service.owner.with_asic_lane(until, || {
            service.sample_locked(until, &mut |_| Ok(()), &mut 0)
        });
        assert!(result.is_err(), "{failure}");
        assert!(service.owner.terminal());
        assert_eq!(service.snapshot_nonces()[0].record.nonce, 11);
        let frames = registers.state.lock().unwrap().frames.len();
        assert_eq!(frames, if failure == "busy" { 5 } else { 1 });
    }
}

#[test]
fn bounded_nonce_custody_leaves_next_hardware_record_unread() {
    let (registers, service) = fixture(Model::S15, 0, true);
    let record = Bm1391StockNonceReturn {
        chain_slot: 0,
        work_id: 1,
        nonce: 2,
        stock_valid: false,
        status_bit6_set: true,
    };
    {
        let mut custody = service.nonces.lock().unwrap();
        for sequence in 1..=MAX_PENDING_NONCES as u64 {
            custody
                .pending
                .push_back(PreservedThermalNonce { sequence, record });
        }
        custody.next_sequence = MAX_PENDING_NONCES as u64 + 1;
    }
    registers
        .state
        .lock()
        .unwrap()
        .returns
        .push_back(nonce(0, 3, 4));
    assert!(service
        .owner
        .with_asic_lane(deadline(), || service.sample_locked(
            deadline(),
            &mut |_| Ok(()),
            &mut 0
        ))
        .is_err());
    assert_eq!(registers.state.lock().unwrap().returns.len(), 1);
    assert!(service.acknowledge_nonces_through(1).is_err());
    assert_eq!(service.snapshot_nonces().len(), MAX_PENDING_NONCES);
    service
        .acknowledge_nonces_through(MAX_PENDING_NONCES as u64)
        .unwrap();
    assert!(service.snapshot_nonces().is_empty());
}

#[tokio::test]
async fn public_observe_reads_fresh_page_and_claims_one_model_bound_service() {
    let registers = Arc::new(ScriptRegisters {
        model: Model::S15,
        state: Mutex::new(Script::default()),
    });
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    assert!(ThermalApplication::observe(
        owner.clone(),
        Model::T15,
        &[census(Model::T15, 0)],
        deadline()
    )
    .await
    .is_err());
    assert_eq!(registers.state.lock().unwrap().eeprom_writes, 0);
    let until = Instant::now() + Duration::from_secs(5);
    let observed =
        ThermalApplication::observe(owner.clone(), Model::S15, &[census(Model::S15, 0)], until)
            .await
            .unwrap();
    assert_eq!(registers.state.lock().unwrap().eeprom_writes, 256);
    assert_eq!(
        observed.endpoints,
        [(0, 0x33), (0, 0x24), (0, 0x9f), (0, 0x90)]
    );
    assert!(
        ThermalApplication::observe(owner, Model::S15, &[census(Model::S15, 0)], deadline())
            .await
            .is_err()
    );
    assert_eq!(registers.state.lock().unwrap().eeprom_writes, 256);
}

#[tokio::test]
async fn retained_pic_pages_join_the_current_census_without_reacquiring_management_io() {
    let registers = Arc::new(ScriptRegisters {
        model: Model::T15,
        state: Mutex::new(Script::default()),
    });
    let owner = Transport::new(registers.clone(), vec![0, 1, 2]).unwrap();
    let pic = PicApplication::observe(
        owner.clone(),
        Model::T15,
        Instant::now() + Duration::from_secs(7),
    )
    .await
    .unwrap();
    assert_eq!(registers.state.lock().unwrap().eeprom_writes, 768);
    let population: Vec<_> = (0..3).map(|chain| census(Model::T15, chain)).collect();
    let mut wrong = population.clone();
    wrong[1].replies.pop();
    assert!(ThermalApplication::from_pic_observation(&pic, &wrong, deadline()).is_err());
    // Simulate ongoing management custody: a second EEPROM reader would block
    // or terminate here. Joining sealed pages and the ASIC census performs no IO.
    let _management = owner.management_lane.lock().unwrap();
    let service = ThermalApplication::from_pic_observation(&pic, &population, deadline()).unwrap();
    assert_eq!(service.endpoints.len(), 12);
    assert_eq!(registers.state.lock().unwrap().eeprom_writes, 768);
    assert!(!owner.terminal());
    assert!(ThermalApplication::from_pic_observation(&pic, &population, deadline()).is_err());
    owner.latch_terminal();
    assert!(ThermalApplication::from_pic_observation(&pic, &population, deadline()).is_err());
}

#[tokio::test]
async fn canceled_worker_custody_waits_for_final_worker_and_survives_a_dropped_snapshot() {
    let (registers, service) = fixture(Model::S15, 0, true);
    registers
        .state
        .lock()
        .unwrap()
        .returns
        .push_back(nonce(0, 1, 0x1234));
    let worker_service = service.clone();
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        worker_service
            .run(deadline(), move |service, deadline, _, _| {
                service.read_retaining_nonce(deadline)?;
                entered.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(1)).unwrap();
                service.owner.active(deadline)?;
                Ok(())
            })
            .await
    });
    waiting.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(service.owner.terminal());
    assert!(service
        .pending_nonces_after_drain(Instant::now() + Duration::from_millis(5))
        .await
        .is_err());
    assert_eq!(service.in_flight.load(Ordering::SeqCst), 1);
    release.send(()).unwrap();
    let records = service
        .pending_nonces_after_drain(deadline())
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record.nonce, 0x1234);
    drop(records);
    let again = service
        .pending_nonces_after_drain(deadline())
        .await
        .unwrap();
    assert_eq!(again[0].sequence, 1);
    service.acknowledge_nonces_through(1).unwrap();
    assert!(service
        .pending_nonces_after_drain(deadline())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn public_sample_outcome_keeps_nonce_custody_on_success_and_failure() {
    let (registers, service) = fixture(Model::S15, 0, true);
    registers
        .state
        .lock()
        .unwrap()
        .returns
        .push_back(nonce(0, 5, 99));
    let outcome = service.sample(deadline()).await;
    assert_eq!(outcome.result.unwrap().len(), 4);
    assert_eq!(outcome.pending_nonces.len(), 1);
    registers.state.lock().unwrap().bad_crc = true;
    let failure = service.sample(deadline()).await;
    assert!(failure.result.is_err());
    assert_eq!(failure.pending_nonces[0].record.nonce, 99);
    assert!(service.owner.terminal());
}
