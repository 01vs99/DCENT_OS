use super::*;

const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
const CLASSIC: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../dcentrald/src/serial_mining/fixtures/bm1362-bhb42601.bin"
));

#[test]
fn fw89_rail_decode_matches_original_adc_instructions() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../../../"))).unwrap();
    for row in oracle["voltages"].as_array().unwrap() {
        let raw = u16::from_str_radix(row["raw_be"].as_str().unwrap(), 16).unwrap();
        // Consume the original binary64 bits: JSON decimal parsing without
        // float_roundtrip may differ by one ULP despite identical arithmetic.
        let expected_bits =
            u64::from_str_radix(row["volts_f64_bits"].as_str().unwrap(), 16).unwrap();
        assert_eq!(fw89_adc_volts(raw.to_be_bytes()).to_bits(), expected_bits);
    }
}

#[test]
fn controller_and_factory_observations_reject_cross_profile_identity() {
    assert!(validate_observations(
        "am3-aml-s19jpro",
        Some("AMLCtrl_BHB42XXX"),
        "Amlogic",
        BOOT,
        [true, false, true],
        [true, false, true]
    )
    .is_ok());
    for variant in 0..6 {
        let mut marker = "am3-aml-s19jpro";
        let mut subtype = "AMLCtrl_BHB42XXX";
        let mut model = "Amlogic";
        let mut boot = BOOT;
        let mut populated = [true, false, true];
        let mut uarts = [true, false, true];
        match variant {
            0 => marker = "am3-aml-s19jproa",
            1 => subtype = "BBCtrl_BHB42XXX",
            2 => model = "Xilinx",
            3 => boot = "",
            4 => populated = [false; 3],
            5 => uarts[2] = false,
            _ => unreachable!(),
        }
        assert!(
            validate_observations(marker, Some(subtype), model, boot, populated, uarts).is_err()
        );
    }
    assert_eq!(validate_factory_page(CLASSIC).unwrap(), 42601);
    let plus = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentrald/src/serial_mining/fixtures/bm1362-bhb42612.bin"
    ));
    let a = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentrald/src/serial_mining/fixtures/bm1362-bhb42603.bin"
    ));
    assert!(validate_factory_page(plus).is_err());
    assert!(validate_factory_page(a).is_err());
    let mut corrupted = CLASSIC.to_vec();
    corrupted[12] ^= 1;
    assert!(validate_factory_page(&corrupted).is_err());
    assert!(validate_factory_page(&CLASSIC[..32]).is_err());
}

#[test]
fn clean_native_image_needs_no_inherited_subtype_but_preserves_every_physical_gate() {
    assert!(validate_observations(
        "am3-aml-s19jpro",
        None,
        "Amlogic",
        BOOT,
        [true, false, true],
        [true, false, true]
    )
    .is_ok());
    for hint in ["", "AMLCtrl_BHB56XXX", "BBCtrl_BHB42XXX"] {
        assert!(validate_observations(
            "am3-aml-s19jpro",
            Some(hint),
            "Amlogic",
            BOOT,
            [true, false, true],
            [true, false, true]
        )
        .is_err());
    }
    for variant in 0..5 {
        let mut marker = "am3-aml-s19jpro";
        let mut model = "Amlogic";
        let mut boot = BOOT;
        let mut populated = [true, false, true];
        let mut uarts = [true, false, true];
        match variant {
            0 => marker = "am3-aml-s19jproa",
            1 => model = "Xilinx",
            2 => boot = "",
            3 => populated = [false; 3],
            _ => uarts[2] = false,
        }
        assert!(validate_observations(marker, None, model, boot, populated, uarts).is_err());
    }
}

#[test]
fn only_an_absent_subtype_file_is_optional_io_failures_are_not_absence() {
    use std::os::unix::fs::symlink;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("classic-subtype-{}-{unique}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let path = self.0.join("subtype");
            let _ = fs::remove_file(&path);
            let _ = fs::remove_dir(&path);
            let _ = fs::remove_dir(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let path = directory.join("subtype");
    assert_eq!(read_optional_subtype(&path).unwrap(), None);
    fs::write(&path, b"AMLCtrl_BHB42XXX\n").unwrap();
    assert_eq!(
        read_optional_subtype(&path).unwrap().as_deref(),
        Some("AMLCtrl_BHB42XXX")
    );
    fs::write(&path, [0xff]).unwrap();
    assert!(read_optional_subtype(&path).is_err());
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(read_optional_subtype(&path).is_err());
    fs::remove_dir(&path).unwrap();
    symlink(directory.join("missing"), &path).unwrap();
    assert!(read_optional_subtype(&path).is_err());
}

#[cfg(feature = "sim-hal")]
mod service {
    use super::*;
    use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
    use std::collections::VecDeque;
    use std::sync::{
        atomic::{AtomicU8, AtomicUsize},
        mpsc,
    };

    struct Observed {
        snapshot: Mutex<Snapshot>,
        reads: AtomicUsize,
        change_at: AtomicUsize,
        gate_at: Mutex<Option<(usize, Gate)>>,
    }
    impl Observed {
        fn new(populated: [bool; 3]) -> Arc<Self> {
            Arc::new(Self {
                snapshot: Mutex::new(Snapshot {
                    boot_id: BOOT.into(),
                    populated,
                }),
                reads: AtomicUsize::new(0),
                change_at: AtomicUsize::new(usize::MAX),
                gate_at: Mutex::new(None),
            })
        }
    }
    impl Observation for Observed {
        fn read(&self) -> Result<Snapshot> {
            let n = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            let gate = {
                let mut gate = self.gate_at.lock().unwrap();
                if gate.as_ref().is_some_and(|(at, _)| *at == n) {
                    gate.take().map(|(_, gate)| gate)
                } else {
                    None
                }
            };
            if let Some(gate) = gate {
                let _ = gate.started.send(());
                gate.release.recv_timeout(Duration::from_secs(3)).unwrap();
            }
            let mut value = self.snapshot.lock().unwrap().clone();
            if n >= self.change_at.load(Ordering::SeqCst) {
                value.boot_id = "changed-boot".into();
            }
            Ok(value)
        }
    }
    struct Gate {
        started: tokio::sync::oneshot::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    #[derive(Default)]
    struct Trace {
        writes: Vec<(u8, u8)>,
        frames: Vec<(u8, Vec<u8>)>,
        pending: BTreeMap<u8, Vec<u8>>,
        replies: BTreeMap<u8, VecDeque<u8>>,
        factory_reads: Vec<u8>,
    }
    struct Backend {
        identity: usize,
        bus: u8,
        trace: Mutex<Trace>,
        page: Mutex<Vec<u8>>,
        version: AtomicU8,
        bad_cut: AtomicU8,
        bad_heartbeat: AtomicU8,
        changed_second: AtomicBool,
        fail_factory: AtomicBool,
        gate: Mutex<Option<Gate>>,
        recoveries: AtomicUsize,
    }
    impl Backend {
        fn new(bus: u8) -> Arc<Self> {
            static NEXT: AtomicUsize = AtomicUsize::new(usize::MAX / 4);
            Arc::new(Self {
                identity: NEXT.fetch_add(1, Ordering::Relaxed),
                bus,
                trace: Mutex::new(Trace::default()),
                page: Mutex::new(CLASSIC.to_vec()),
                version: AtomicU8::new(0x89),
                bad_cut: AtomicU8::new(0xff),
                bad_heartbeat: AtomicU8::new(0xff),
                changed_second: AtomicBool::new(false),
                fail_factory: AtomicBool::new(false),
                gate: Mutex::new(None),
                recoveries: AtomicUsize::new(0),
            })
        }
        fn block_once(&self) -> (tokio::sync::oneshot::Receiver<()>, mpsc::SyncSender<()>) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            *self.gate.lock().unwrap() = Some(Gate {
                started: tx,
                release: release_rx,
            });
            (rx, release_tx)
        }
        fn gate(&self) {
            let gate = self.gate.lock().unwrap().take();
            if let Some(gate) = gate {
                let _ = gate.started.send(());
                gate.release.recv_timeout(Duration::from_secs(3)).unwrap();
            }
        }
    }
    impl I2cSimBackend for Backend {
        fn service_identity(&self) -> Option<usize> {
            Some(self.identity)
        }
        fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> Result<usize> {
            assert_eq!((bus, self.bus, bytes.len()), (0, 0, 1));
            assert!((0x20..=0x22).contains(&addr));
            self.gate();
            let mut trace = self.trace.lock().unwrap();
            trace.writes.push((addr, bytes[0]));
            let pending = trace.pending.entry(addr).or_default();
            if pending.is_empty() && bytes[0] != 0x55 {
                return Ok(1);
            }
            pending.push(bytes[0]);
            if pending.len() == 2 && pending[1] != 0xaa {
                pending.clear();
                return Ok(1);
            }
            if pending.len() == 3 && !(4..=6).contains(&pending[2]) {
                pending.clear();
                return Ok(1);
            }
            if pending.len() < 3 || pending.len() != usize::from(pending[2]) + 2 {
                return Ok(1);
            }
            let frame = std::mem::take(pending);
            let reply = match frame[3] {
                0x17 => {
                    let fw = self.version.load(Ordering::SeqCst);
                    vec![5, 0x17, fw, 0, 5_u8.wrapping_add(0x17).wrapping_add(fw)]
                }
                0x16 => {
                    let status = u8::from(self.bad_heartbeat.load(Ordering::SeqCst) != addr);
                    vec![6, 0x16, status, 0, 0, 0x1c + status]
                }
                0x15 => vec![0x15, u8::from(self.bad_cut.load(Ordering::SeqCst) != addr)],
                0x3b => vec![0x3b, 1],
                0x3c => vec![7, 0x3c, 1, 0x33, 0x80, 0, 0xf7],
                0x3a => vec![7, 0x3a, 1, 2, 0x31, 0, 0x75],
                _ => vec![],
            };
            trace.frames.push((addr, frame));
            trace.replies.entry(addr).or_default().extend(reply);
            Ok(1)
        }
        fn read(&self, bus: u8, addr: u8, bytes: &mut [u8]) -> Result<usize> {
            assert_eq!((bus, self.bus, bytes.len()), (0, 0, 1));
            match self
                .trace
                .lock()
                .unwrap()
                .replies
                .entry(addr)
                .or_default()
                .pop_front()
            {
                Some(b) => {
                    bytes[0] = b;
                    Ok(1)
                }
                None => Ok(0),
            }
        }
        fn write_read(&self, bus: u8, addr: u8, bytes: &[u8], reply: &mut [u8]) -> Result<()> {
            assert_eq!((bus, self.bus, bytes, reply.len()), (1, 1, &[0][..], 256));
            assert!((0x50..=0x52).contains(&addr));
            self.gate();
            let mut trace = self.trace.lock().unwrap();
            trace.factory_reads.push(addr);
            if self.fail_factory.load(Ordering::SeqCst) {
                return Err(error("injected factory NACK"));
            }
            reply.copy_from_slice(&self.page.lock().unwrap());
            if self.changed_second.load(Ordering::SeqCst) && trace.factory_reads.len() == 2 {
                reply[12] ^= 1;
            }
            Ok(())
        }
        fn bus_recovery(&self, _: u8) {
            self.recoveries.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn spawn_factory(
        pic: Arc<Backend>,
        identity: Arc<Backend>,
        handles: Arc<Mutex<Vec<I2cServiceHandle>>>,
    ) -> impl Fn(u8) -> Result<I2cServiceOwner> + Send + 'static {
        move |bus| {
            let backend = if bus == 0 {
                pic.clone()
            } else {
                identity.clone()
            };
            let owner = spawn_owned_sim_i2c_service(bus, backend, AMLOGIC_EEPROM_DENYLIST.to_vec())
                .map_err(|e| error(e.to_string()))?;
            handles.lock().unwrap().push(owner.request_handle());
            Ok(owner)
        }
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[tokio::test]
    async fn actual_owner_reads_every_populated_factory_then_queries_only_bound_pics() {
        for mask in 1..8 {
            let population = std::array::from_fn(|slot| mask & (1 << slot) != 0);
            let pic = Backend::new(0);
            let identity = Backend::new(1);
            let handles = Arc::new(Mutex::new(Vec::new()));
            let owner = ClassicAmlPicOwner::observe_with(
                Observed::new(population),
                deadline(),
                spawn_factory(pic.clone(), identity.clone(), handles.clone()),
            )
            .await
            .unwrap();
            let chains: Vec<u8> = (1..=3)
                .filter(|chain| mask & (1 << (chain - 1)) != 0)
                .collect();
            assert_eq!(owner.physical_chains(), chains);
            assert_eq!(
                identity.trace.lock().unwrap().factory_reads,
                chains
                    .iter()
                    .flat_map(|chain| [chain + 0x4f; 2])
                    .collect::<Vec<_>>()
            );
            let heartbeat = owner.heartbeat_round_at(deadline()).await.unwrap();
            assert_eq!(
                heartbeat
                    .chains
                    .iter()
                    .map(|(chain, _)| *chain)
                    .collect::<Vec<_>>(),
                chains
            );
            assert_eq!(heartbeat.stable_rounds, 1);
            if mask == 7 {
                let voltages = owner.voltages_at(deadline()).await.unwrap();
                assert_eq!(voltages.iter().map(|v| v.chain).collect::<Vec<_>>(), chains);
                assert!(voltages
                    .iter()
                    .all(|v| v.raw_be == [2, 0x31] && (v.volts - 13.38328).abs() < 0.000001));
                let values = owner.temperatures_at(3, deadline()).await.unwrap();
                assert_eq!(values.len(), 4);
                for (sensor, value) in (0x48..=0x4b).zip(values) {
                    assert_eq!(
                        (value.chain, value.sensor, value.raw_be, value.celsius),
                        (3, sensor, [0x33, 0x80], 51.5)
                    );
                }
            }
            let closed = owner.close_at(deadline()).await.unwrap();
            assert!(closed.workers_closed);
            assert!(closed.cuts.iter().all(|(_, r)| r.is_ok()));
            assert!(handles
                .lock()
                .unwrap()
                .iter()
                .all(I2cServiceHandle::terminal_safe_off_is_latched));
            let trace = pic.trace.lock().unwrap();
            assert!(trace
                .frames
                .iter()
                .all(|(addr, frame)| chains.contains(&(addr - 0x1f))
                    && matches!(frame[3], 0x17 | 0x16 | 0x15 | 0x3a | 0x3b | 0x3c)));
            assert!(trace
                .frames
                .iter()
                .filter(|(_, frame)| frame[3] == 0x15)
                .all(|(_, frame)| frame[4] == 0));
        }
    }

    #[tokio::test]
    async fn bad_changed_factory_or_changed_boot_never_emit_pic_payload() {
        for variant in 0..4 {
            let pic = Backend::new(0);
            let identity = Backend::new(1);
            let observed = Observed::new([true, false, false]);
            match variant {
                0 => identity.page.lock().unwrap()[12] ^= 1,
                1 => identity.changed_second.store(true, Ordering::SeqCst),
                2 => identity.fail_factory.store(true, Ordering::SeqCst),
                3 => observed.change_at.store(2, Ordering::SeqCst),
                _ => unreachable!(),
            }
            let handles = Arc::new(Mutex::new(Vec::new()));
            assert!(ClassicAmlPicOwner::observe_with(
                observed,
                deadline(),
                spawn_factory(pic.clone(), identity.clone(), handles.clone())
            )
            .await
            .is_err());
            assert!(pic.trace.lock().unwrap().writes.is_empty());
            assert_eq!(identity.recoveries.load(Ordering::SeqCst), 0);
            assert!(handles
                .lock()
                .unwrap()
                .iter()
                .all(I2cServiceHandle::terminal_safe_off_is_latched));
        }
    }

    #[tokio::test]
    async fn wrong_firmware_is_terminal_and_never_yields_thermal_owner() {
        let pic = Backend::new(0);
        let identity = Backend::new(1);
        pic.version.store(0x86, Ordering::SeqCst);
        let handles = Arc::new(Mutex::new(Vec::new()));
        assert!(ClassicAmlPicOwner::observe_with(
            Observed::new([true, false, false]),
            deadline(),
            spawn_factory(pic.clone(), identity, handles.clone())
        )
        .await
        .is_err());
        let trace = pic.trace.lock().unwrap();
        assert_eq!(trace.frames.len(), 1);
        assert_eq!(trace.frames[0].1[3], 0x17);
        assert_eq!(&trace.writes[6..], &vec![(0x20, 0); 16]);
        assert!(handles
            .lock()
            .unwrap()
            .iter()
            .all(I2cServiceHandle::terminal_safe_off_is_latched));
    }

    #[tokio::test]
    async fn cancellation_during_first_factory_read_fences_both_owners_before_resume() {
        let pic = Backend::new(0);
        let identity = Backend::new(1);
        let (started, release) = identity.block_once();
        let handles = Arc::new(Mutex::new(Vec::new()));
        let spawn = spawn_factory(pic.clone(), identity.clone(), handles.clone());
        let caller = tokio::spawn(ClassicAmlPicOwner::observe_with(
            Observed::new([true, false, true]),
            deadline(),
            spawn,
        ));
        tokio::time::timeout(Duration::from_secs(2), started)
            .await
            .unwrap()
            .unwrap();
        caller.abort();
        assert!(matches!(caller.await, Err(ref e) if e.is_cancelled()));
        assert_eq!(handles.lock().unwrap().len(), 2);
        assert!(handles
            .lock()
            .unwrap()
            .iter()
            .all(I2cServiceHandle::terminal_safe_off_is_latched));
        release.send(()).unwrap();
        for _ in 0..100 {
            if !identity.trace.lock().unwrap().factory_reads.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(identity.trace.lock().unwrap().factory_reads, vec![0x50]);
        assert!(pic.trace.lock().unwrap().writes.is_empty());
    }

    #[tokio::test]
    async fn final_boot_observation_cancel_or_expiry_never_publishes_an_owner() {
        for cancel in [true, false] {
            let pic = Backend::new(0);
            let observed = Observed::new([true, false, false]);
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            *observed.gate_at.lock().unwrap() = Some((
                3,
                Gate {
                    started: started_tx,
                    release: release_rx,
                },
            ));
            let handles = Arc::new(Mutex::new(Vec::new()));
            let expires = if cancel {
                deadline()
            } else {
                Instant::now() + Duration::from_millis(300)
            };
            let caller = tokio::spawn(ClassicAmlPicOwner::observe_with(
                observed,
                expires,
                spawn_factory(pic.clone(), Backend::new(1), handles.clone()),
            ));
            tokio::time::timeout(Duration::from_secs(2), started_rx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(pic.trace.lock().unwrap().frames.len(), 1);
            if cancel {
                caller.abort();
                assert!(matches!(caller.await, Err(ref e) if e.is_cancelled()));
                assert!(handles
                    .lock()
                    .unwrap()
                    .iter()
                    .all(I2cServiceHandle::terminal_safe_off_is_latched));
                release_tx.send(()).unwrap();
            } else {
                tokio::time::sleep_until(expires.into()).await;
                release_tx.send(()).unwrap();
                assert!(caller.await.unwrap().is_err());
                assert!(handles
                    .lock()
                    .unwrap()
                    .iter()
                    .all(I2cServiceHandle::terminal_safe_off_is_latched));
            }
            assert!(spawn_owned_sim_i2c_service(0, pic, AMLOGIC_EEPROM_DENYLIST.to_vec()).is_err());
        }
    }

    #[tokio::test]
    async fn healthy_owner_drop_without_acknowledged_cut_quarantines_pic_fabric() {
        let pic = Backend::new(0);
        let handles = Arc::new(Mutex::new(Vec::new()));
        let owner = ClassicAmlPicOwner::observe_with(
            Observed::new([true, false, true]),
            deadline(),
            spawn_factory(pic.clone(), Backend::new(1), handles.clone()),
        )
        .await
        .unwrap();
        let custody = owner.state.lock().await.custody.clone();
        drop(owner);
        assert!(handles
            .lock()
            .unwrap()
            .iter()
            .all(I2cServiceHandle::terminal_safe_off_is_latched));
        tokio::task::spawn_blocking(move || {
            let mut custody = custody.lock().unwrap();
            assert!(custody
                .pic
                .as_mut()
                .unwrap()
                .close_and_join_until(deadline())
                .is_err());
            assert!(custody
                .identity
                .as_mut()
                .unwrap()
                .close_and_join_until(deadline())
                .is_ok());
        })
        .await
        .unwrap();
        assert!(pic
            .trace
            .lock()
            .unwrap()
            .frames
            .iter()
            .all(|(_, frame)| frame[3] == 0x17));
        assert!(spawn_owned_sim_i2c_service(0, pic, AMLOGIC_EEPROM_DENYLIST.to_vec()).is_err());
    }

    #[tokio::test]
    async fn failing_cut_still_attempts_siblings_and_retains_quarantined_pic_fabric() {
        let pic = Backend::new(0);
        let identity = Backend::new(1);
        let handles = Arc::new(Mutex::new(Vec::new()));
        let owner = ClassicAmlPicOwner::observe_with(
            Observed::new([true; 3]),
            deadline(),
            spawn_factory(pic.clone(), identity, handles),
        )
        .await
        .unwrap();
        pic.bad_cut.store(0x21, Ordering::SeqCst);
        let closed = owner.close_at(deadline()).await.unwrap();
        assert_eq!(
            closed
                .cuts
                .iter()
                .map(|(_, r)| r.is_ok())
                .collect::<Vec<_>>(),
            [true, false, true]
        );
        assert!(!closed.workers_closed);
        let frames = pic.trace.lock().unwrap().frames.len();
        owner.close_at(deadline()).await.unwrap();
        assert_eq!(
            pic.trace.lock().unwrap().frames.len(),
            frames,
            "cut must not be replayed after uncertain completion"
        );
        assert!(spawn_owned_sim_i2c_service(0, pic, AMLOGIC_EEPROM_DENYLIST.to_vec()).is_err());
    }

    #[tokio::test]
    async fn stale_population_and_bad_heartbeat_close_both_normal_lanes() {
        for changed in [false, true] {
            let pic = Backend::new(0);
            let identity = Backend::new(1);
            let observed = Observed::new([true; 3]);
            let handles = Arc::new(Mutex::new(Vec::new()));
            let owner = ClassicAmlPicOwner::observe_with(
                observed.clone(),
                deadline(),
                spawn_factory(pic.clone(), identity, handles.clone()),
            )
            .await
            .unwrap();
            if changed {
                observed.snapshot.lock().unwrap().populated[2] = false;
            } else {
                pic.bad_heartbeat.store(0x21, Ordering::SeqCst);
            }
            let before = pic.trace.lock().unwrap().writes.len();
            assert!(owner.heartbeat_round_at(deadline()).await.is_err());
            if changed {
                assert_eq!(pic.trace.lock().unwrap().writes.len(), before);
            }
            assert!(handles
                .lock()
                .unwrap()
                .iter()
                .all(I2cServiceHandle::terminal_safe_off_is_latched));
            let before = pic.trace.lock().unwrap().writes.len();
            assert!(owner.temperatures_at(1, deadline()).await.is_err());
            assert_eq!(pic.trace.lock().unwrap().writes.len(), before);
            owner.close_at(deadline()).await.unwrap();
        }
    }
    mod power_composition {
        include!("classic_power_sim_tests.rs");
    }
}
