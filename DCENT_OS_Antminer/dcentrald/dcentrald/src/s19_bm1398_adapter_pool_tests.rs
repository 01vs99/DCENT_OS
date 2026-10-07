// Real Am2Bm1398Io + CommandBackend + factory/PIC/APW worker + executor
// + work/nonce FIFO + ledger + strict pool. GPIO, fan, fabric-clock and watchdog
// custody below is explicitly a fixture and is excluded from this test scope.
use dcentrald_hal::platform::sim::{SimModel, SimNoncePolicy, TraceEvent};
#[path = "../tests/sim_support/share_oracle.rs"]
mod independent_pool;
fn bm1398_profile_config(profile: platform::Bm1398Platform) -> DcentraldConfig {
    use platform::Bm1398Platform as P;
    let image = match profile {
        P::S19Pro => include_str!("../../configs/dcentrald_s19pro_am2_baked_default.toml"),
        P::S19Classic => include_str!("../../configs/dcentrald_s19_am2_baked_default.toml"),
        P::T19 => include_str!("../../configs/dcentrald_t19_am2_baked_default.toml"),
        P::S19a => include_str!("../../configs/dcentrald_s19a_am2_baked_default.toml"),
        P::S19Plus => include_str!("../../configs/dcentrald_s19plus_am2_baked_default.toml"),
    };
    let mut config: DcentraldConfig = toml::from_str(image).unwrap();
    assert!(!config.mining.enabled);
    assert_eq!(config.mining.serial_chip_type.as_deref(), Some("BM1398"));
    assert_eq!(
        config.mining.serial_chip_count,
        Some(profile.chips_per_chain() as u8)
    );
    config.mining.enabled = true;
    config.mining.version_rolling = false;
    config.donation.enabled = false;
    config
}

#[derive(Default)]
struct AdapterOuterFixture {
    powered: std::sync::atomic::AtomicBool,
    terminal: std::sync::atomic::AtomicBool,
    stopped: std::sync::atomic::AtomicBool,
}
impl Am2Bm1398Custody for AdapterOuterFixture {
    async fn start(&self, chains: &[u8]) -> std::result::Result<(), String> {
        if chains != [0, 1, 2] {
            return Err("outer fixture requires all three owned slots".into());
        }
        Ok(())
    }
    async fn check_health(&self) -> std::result::Result<(), String> {
        if self.terminal.load(std::sync::atomic::Ordering::Acquire) {
            return Err("outer fixture terminal".into());
        }
        Ok(())
    }
    async fn hash_power(&self, enabled: bool) -> std::result::Result<(), String> {
        if enabled && self.terminal.load(std::sync::atomic::Ordering::Acquire) {
            return Err("outer fixture cannot re-energize".into());
        }
        self.powered
            .store(enabled, std::sync::atomic::Ordering::Release);
        Ok(())
    }
    async fn terminal_power_off(&self) -> std::result::Result<(), String> {
        self.terminal
            .store(true, std::sync::atomic::Ordering::Release);
        self.powered
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(())
    }
    async fn chain_reset(&self, chain: u8, _: bool) -> std::result::Result<(), String> {
        if chain > 2 {
            return Err("unowned outer reset".into());
        }
        Ok(())
    }
    async fn stop(&self) -> std::result::Result<(), String> {
        if self.powered.load(std::sync::atomic::Ordering::Acquire) {
            return Err("outer fixture stopped before source cut".into());
        }
        self.stopped
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }
}
fn adapter_chain_handles(
    profile: platform::Bm1398Platform,
    fault: dcentrald_hal::platform::sim::SimBm1398WireFault,
) -> (BTreeMap<u8, Arc<FpgaChain>>, BTreeMap<u8, Am2Bm1398ChainIo>) {
    let mut handles = BTreeMap::new();
    let mut chains = BTreeMap::new();
    for slot in 0..3 {
        let fifo = FpgaChain::open_sim_for_model(slot, SimModel::S19Pro).unwrap();
        fifo.common.write_reg(4, 0x63848b7b);
        fifo.configure_sim_bm1398_native_wire(
            profile.chips_per_chain() as u8,
            profile.address_interval(),
            fault,
        )
        .unwrap();
        fifo.set_sim_next_nonce(2083236893).unwrap();
        fifo.set_sim_nonce_policy(SimNoncePolicy::Valid).unwrap();
        let fifo = Arc::new(fifo);
        handles.insert(slot, fifo.clone());
        chains.insert(
            slot,
            Am2Bm1398ChainIo {
                commands: Arc::new(CommandBackend {
                    fifo: fifo.clone(),
                    conversation: Mutex::new(()),
                }),
                fifo,
            },
        );
    }
    (handles, chains)
}
fn actual_adapter_runtime(
    profile: platform::Bm1398Platform,
    adapter: Am2Bm1398Io<AdapterOuterFixture>,
) -> Bm1398Runtime<Am2Bm1398Io<AdapterOuterFixture>> {
    let (frequency_mhz, voltage_cv) = profile.default_operating_point();
    Bm1398Runtime::new(
        profile.board_target(),
        Bm1398RuntimeConfig {
            plan: profile.desk_plan(
                PacedEnumerationPolicy::new(
                    Duration::from_millis(1),
                    Duration::from_millis(1),
                    Duration::from_millis(50),
                    2,
                )
                .unwrap(),
                Bm1398FpgaMidstateMode::Four,
            ),
            active_chains: vec![0, 1, 2],
            frequency_mhz,
            voltage_cv,
        },
        adapter,
    )
    .unwrap()
}
async fn actual_adapter_pool(profile: platform::Bm1398Platform) {
    use dcentrald_hal::platform::am2_bm1398::simulation::{Rig, WireFault};
    use dcentrald_hal::platform::sim::SimBm1398WireFault;
    let pages = (0..3)
        .map(|_| {
            crate::am3_bb_mining::deployed_sim_identity_page(
                profile.stock_board_names()[0],
                "",
                None,
            )
        })
        .collect();
    let mut rig = Rig::new(pages, WireFault::None).unwrap();
    let (handles, chains) = adapter_chain_handles(profile, SimBm1398WireFault::None);
    let custody = Arc::new(AdapterOuterFixture::default());
    let adapter = rig
        .open_adapter(
            profile.board_target(),
            chains,
            custody.clone(),
            Am2Bm1398BoardKind::from_board_target(profile.board_target()).unwrap(),
        )
        .unwrap();
    let mut runtime = actual_adapter_runtime(profile, adapter);
    tokio::time::timeout(Duration::from_secs(60), runtime.start())
        .await
        .expect("actual AM2 adapter startup deadline")
        .unwrap();
    assert_eq!(rig.snapshot().factory_bytes, [256; 3]);
    assert_eq!(rig.snapshot().pic_enabled, [true; 3]);
    assert!(rig.snapshot().heartbeats.iter().all(|n| *n >= 5));
    assert!(custody.powered.load(std::sync::atomic::Ordering::Acquire));
    for fifo in handles.values() {
        let trace = fifo.drain_sim_trace().unwrap();
        let assignments: Vec<_> = trace
            .iter()
            .filter_map(|event| match event {
                TraceEvent::Command { bytes, .. }
                    if bytes.len() == 4 && bytes[0..2] == [0x40, 5] =>
                {
                    Some(bytes[2])
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            assignments,
            (0..profile.chips_per_chain() as u8)
                .map(|i| i * profile.address_interval())
                .collect::<Vec<_>>()
        );
        assert!(!trace
            .iter()
            .any(|event| matches!(event, TraceEvent::Work { .. })));
    }
    for slot in 0..3 {
        let worker = format!("independent.adapter.{}.{}", profile.board_target(), slot);
        let (address, pool) = independent_pool::OraclePool::spawn(&worker).await;
        let mut config = bm1398_profile_config(profile);
        config.pool.url = format!("stratum+tcp://{address}");
        config.pool.worker = worker.clone();
        config.validate().unwrap();
        let stratum = crate::config::build_stratum_config_with_enumerated_chips(
            &config,
            crate::config::stratum_donation_config(&config.donation),
            false,
            false,
            Some(u32::from(profile.chips_per_chain()) * 3),
        );
        let (job_tx, mut job_rx) = tokio::sync::mpsc::channel(8);
        let (share_tx, share_rx) = tokio::sync::mpsc::channel(8);
        let (status_tx, _status_rx) = tokio::sync::mpsc::channel(32);
        let client = dcentrald_stratum::StratumV1Client::new(stratum, job_tx, share_rx, status_tx);
        let mut retained = ledger();
        let lifecycle = async {
            let job = job_rx.recv().await.unwrap();
            let work = WorkBuilder::new().next_work(&job).unwrap();
            let reference = independent_pool::header(&work.extranonce2, 2083236893).unwrap();
            assert_eq!(work.midstates[0], reference.midstate());
            assert_eq!(work.share_target, independent_pool::target());
            dispatch_work(&mut retained, &mut runtime, slot, work)
                .await
                .unwrap();
            let trace = handles[&slot].drain_sim_trace().unwrap();
            let frames: Vec<_> = trace
                .iter()
                .filter_map(|event| match event {
                    TraceEvent::Work { bytes, .. } => Some(bytes),
                    _ => None,
                })
                .collect();
            assert_eq!(frames.len(), 1);
            let mut expected = vec![0u32, 0x1d00ffff, 0x495fab29, 0x4a5e1e4b];
            for _ in 0..4 {
                expected.extend([
                    0x4719f91b, 0x96b18736, 0x4f0103c8, 0xc3c8d8e9, 0x1e59caa8, 0x90ccac7d,
                    0x6358bff0, 0xbc909a33,
                ]);
            }
            assert_eq!(
                *frames[0],
                expected
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>()
            );
            let raw = runtime
                .transport()
                .poll_nonce(slot)
                .await
                .unwrap()
                .expect("actual adapter FIFO return");
            assert_eq!(raw, (2083236893, 0));
            publish_nonce(&mut retained, raw, &worker, &share_tx).unwrap();
            publish_nonce(&mut retained, raw, &worker, &share_tx).unwrap();
            while pool.accepted_shares() == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(retained.tickets, 1);
            retained.invalidate();
            assert!(retained.validate(raw, &worker).unwrap().is_none());
        };
        tokio::time::timeout(Duration::from_secs(5), async { tokio::select! {
            _ = lifecycle => (), _ = client.run_until_sv2_retry(Duration::from_secs(4)) => panic!("AM2 pool ended before share"),
        }}).await.expect("actual adapter pool deadline");
        assert_eq!(pool.accepted_shares(), 1);
    }
    // No-complete-frame capacity must fail through the actual adapter before
    // writing any byte or committing new attribution, then cut owned power.
    handles[&0].work_tx.write_reg(0x0c, 1 << 3);
    let mut blocked = ledger();
    tokio::time::timeout(Duration::from_secs(10), async {
        assert!(dispatch_work(&mut blocked, &mut runtime, 0, genesis_work())
            .await
            .is_err());
    })
    .await
    .unwrap();
    assert_eq!(blocked.next, 0);
    assert!(blocked.slots.iter().all(Option::is_none));
    assert!(!handles[&0]
        .drain_sim_trace()
        .unwrap()
        .iter()
        .any(|event| matches!(event, TraceEvent::Work { .. })));
    assert!(custody.stopped.load(std::sync::atomic::Ordering::Acquire));
    assert!(!custody.powered.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(rig.snapshot().pic_enabled, [false; 3]);
    assert!(runtime.transport().poll_nonce(0).await.is_err());
    assert!(
        dispatch_work(&mut ledger(), &mut runtime, 0, genesis_work())
            .await
            .is_err()
    );
    drop(runtime);
    rig.close(Instant::now() + Duration::from_secs(2)).unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s19pro_actual_adapter_init_fifo_nonce_independent_pool() {
    actual_adapter_pool(platform::Bm1398Platform::S19Pro).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s19_actual_adapter_init_fifo_nonce_independent_pool() {
    actual_adapter_pool(platform::Bm1398Platform::S19Classic).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t19_actual_adapter_init_fifo_nonce_independent_pool() {
    actual_adapter_pool(platform::Bm1398Platform::T19).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s19a_actual_adapter_init_fifo_nonce_independent_pool() {
    actual_adapter_pool(platform::Bm1398Platform::S19a).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s19plus_actual_adapter_init_fifo_nonce_independent_pool() {
    actual_adapter_pool(platform::Bm1398Platform::S19Plus).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_bm1398_adapter_factory_pic_and_population_faults_cut_before_work() {
    use dcentrald_hal::platform::am2_bm1398::simulation::{Rig, WireFault};
    use dcentrald_hal::platform::sim::SimBm1398WireFault as AsicFault;
    let profile = platform::Bm1398Platform::S19Pro;
    for (wire_fault, asic_fault, factory_crc, foreign_name) in [
        (WireFault::None, AsicFault::None, Some(1), false),
        (WireFault::None, AsicFault::None, None, true),
        (WireFault::PicVersion86, AsicFault::None, None, false),
        (WireFault::PsuNotReady, AsicFault::None, None, false),
        (WireFault::PicAck, AsicFault::None, None, false),
        (WireFault::None, AsicFault::MissingLastChip, None, false),
        (WireFault::None, AsicFault::BadResponseCrc, None, false),
    ] {
        let pages = (0..3)
            .map(|slot| {
                crate::am3_bb_mining::deployed_sim_identity_page(
                    if slot == 1 && foreign_name {
                        "NBS1902"
                    } else {
                        "NBP1901"
                    },
                    "",
                    if slot == 0 { factory_crc } else { None },
                )
            })
            .collect();
        let mut rig = Rig::new(pages, wire_fault).unwrap();
        let (handles, chains) = adapter_chain_handles(profile, asic_fault);
        let custody = Arc::new(AdapterOuterFixture::default());
        let adapter = rig
            .open_adapter(
                profile.board_target(),
                chains,
                custody.clone(),
                Am2Bm1398BoardKind::Nbp1901,
            )
            .unwrap();
        let mut runtime = actual_adapter_runtime(profile, adapter);
        let failed = tokio::time::timeout(Duration::from_secs(60), runtime.start())
            .await
            .expect("actual adapter refusal deadline");
        assert!(
            failed.is_err(),
            "fault unexpectedly admitted: {wire_fault:?}/{asic_fault:?}/{factory_crc:?}/foreign={foreign_name}"
        );
        assert!(custody.stopped.load(std::sync::atomic::Ordering::Acquire));
        assert!(!custody.powered.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(rig.snapshot().pic_enabled, [false; 3]);
        assert!(runtime.transport().poll_nonce(0).await.is_err());
        for fifo in handles.values() {
            assert!(fifo.read_nonce().is_none());
            assert!(!fifo
                .drain_sim_trace()
                .unwrap()
                .iter()
                .any(|event| matches!(event, TraceEvent::Work { .. })));
        }
        if factory_crc.is_some() || foreign_name || wire_fault == WireFault::PicVersion86 {
            assert_eq!(rig.snapshot().apw_voltage_commands, 0);
            assert!(!rig
                .snapshot()
                .frames
                .iter()
                .any(|(address, frame)| *address != 0x10 && frame[3] == 0x15 && frame[4] == 1));
        }
        drop(runtime);
        rig.close(Instant::now() + Duration::from_secs(2)).unwrap();
    }
}
#[test]
fn injected_marker_requires_exact_image_fabric_slots_and_same_simulated_command_owner() {
    use dcentrald_hal::platform::am2_bm1398::simulation::{Rig, WireFault};
    use dcentrald_hal::platform::sim::SimBm1398WireFault;
    let profile = platform::Bm1398Platform::S19Pro;
    let pages = (0..3)
        .map(|_| crate::am3_bb_mining::deployed_sim_identity_page("NBP1901", "", None))
        .collect();
    let mut rig = Rig::new(pages, WireFault::None).unwrap();
    for fault in 0..5 {
        let (handles, mut chains) = adapter_chain_handles(profile, SimBm1398WireFault::None);
        let marker = if fault == 0 {
            "am2-s19j"
        } else {
            profile.board_target()
        };
        match fault {
            1 => handles[&0].common.write_reg(4, 0),
            2 => {
                // Same slot and simulated ABI, but a different retained FIFO.
                // Slot-number checks alone must not admit this command owner.
                let (foreign, _) = adapter_chain_handles(profile, SimBm1398WireFault::None);
                chains.get_mut(&0).unwrap().commands = Arc::new(CommandBackend {
                    fifo: foreign[&0].clone(),
                    conversation: Mutex::new(()),
                });
            }
            3 => {
                let old = chains.remove(&2).unwrap();
                chains.insert(3, old);
            }
            4 => {
                chains.clear();
            }
            _ => (),
        }
        assert!(rig
            .open_adapter(
                marker,
                chains,
                Arc::new(AdapterOuterFixture::default()),
                Am2Bm1398BoardKind::Nbp1901
            )
            .is_err());
        assert!(rig.snapshot().frames.is_empty());
        assert_eq!(rig.snapshot().factory_bytes, [0; 3]);
    }
    rig.close(Instant::now() + Duration::from_secs(2)).unwrap();
}
