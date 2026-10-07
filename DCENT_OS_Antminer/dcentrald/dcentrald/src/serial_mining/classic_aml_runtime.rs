//! Classic BHB42601/21/41 runtime. Power, identity, parser and UART owners
//! remain independent of AM2 and of the A/Plus NoPic runtime.
use super::classic_aml_work::{Ledger, PreparedWork};
use super::*;
use crate::runtime::safety_watchdog::{
    ClassicAmlActorSlot, ClassicAmlActors, ClassicAmlWatchdogRouteScope,
    ClassicAmlWatchdogShutdownManifest,
};
use crate::runtime::watchdog_feed_gate::WatchdogFeedStopSignal;
use dcentrald_hal::platform::amlogic::classic_pic::{ClassicAmlPowerOwner, ClassicHealth};
use dcentrald_stratum::types::{JobTemplate, StratumState, StratumStatus, ValidShare};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{OnceLock, Weak};
#[path = "classic_aml_proof.rs"]
mod proof;
#[cfg(all(test, feature = "sim-hal"))]
#[path = "../../tests/sim_support/share_oracle.rs"]
mod independent_pool;

const TARGET: &str = "am3-s19jpro-aml";
const UARTS: [&str; 3] = ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"];
const POLICY: IndustrialSerialPllPolicy = IndustrialSerialPllPolicy::S19jProClassicAmlBm1362Native;

fn validate_config(
    config: &DcentraldConfig,
    target: &str,
    identity: dcentrald_common::AsicProtocolIdentity,
    frequency: u16,
) -> Result<()> {
    anyhow::ensure!(
        target == TARGET && identity == dcentrald_common::AsicProtocolIdentity::Bm1362,
        "classic runtime requires its exact controller/BM1362 dispatch"
    );
    anyhow::ensure!(
        !config.mining.passthrough && config.mining.enabled,
        "classic runtime requires enabled cold native mining"
    );
    let (chip, count) = resolve_native_serial_identity_and_geometry(
        config.mining.model.as_deref(),
        config.mining.serial_chip_count,
    )?;
    anyhow::ensure!(
        chip == 0x1362 && count == 126 && POLICY.admits_target(frequency),
        "classic native runtime requires complete126-chip geometry and400..500MHz exact steps"
    );
    anyhow::ensure!(
        (13000..=13800).contains(&config.mining.voltage_mv),
        "classic native runtime requires13.0..13.8V"
    );
    anyhow::ensure!(
        config.thermal.fan_max_pwm >= 30 && config.thermal.fan_min_pwm <= 30,
        "classic native runtime requires fixed quiet PWM30"
    );
    anyhow::ensure!(
        config.watchdog.enabled && config.watchdog.timeout_s >= 40,
        "classic native runtime requires hardware watchdog timeout>=40s"
    );
    anyhow::ensure!(
        !config.hash_on_disconnect.enabled,
        "classic native work requires terminal cutoff on upstream disconnect"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    #[cfg(feature = "sim-hal")]
    include!("classic_aml_pool_tests.rs");

    #[test]
    fn shipped_classic_image_is_idle_and_can_enter_its_exact_native_profile() {
        let image = include_str!("../../../../br2_external_dcentos/board/amlogic/am3-s19jpro-aml/rootfs-overlay/etc/dcentrald.toml");
        let mut config: DcentraldConfig = toml::from_str(image).unwrap();
        config.validate().unwrap();
        assert!(!config.mining.enabled);
        assert!(config.pool.url.is_empty());
        assert_eq!(config.mining.frequency_mhz, 400);
        assert_eq!(config.mining.serial_chip_count, Some(126));
        assert_eq!(config.thermal.dangerous_temp_c, 80);
        assert_eq!(config.watchdog.timeout_s, 40);
        assert!(
            config.autotuner.enabled,
            "preserve the operator's requested preference"
        );
        config.mining.enabled = true;
        config.pool.url = "stratum+tcp://127.0.0.1:3333".into();
        config.pool.worker = "local-config-fixture.classic".into();
        validate_config(
            &config,
            TARGET,
            dcentrald_common::AsicProtocolIdentity::Bm1362,
            config.mining.frequency_mhz,
        )
        .unwrap();
    }

    fn canonical_work() -> dcentrald_stratum::work::MiningWork {
        let merkle = [
            0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76,
            0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa,
            0x4b, 0x1e, 0x5e, 0x4a,
        ];
        dcentrald_stratum::work::MiningWork {
            work_generation: dcentrald_stratum::WorkGeneration { session: 1, job: 1 },
            midstates: vec![],
            merkle4: merkle[28..].try_into().unwrap(),
            ntime: 1231006505,
            nbits: 0x1d00ffff,
            job_id: "classic-genesis".into(),
            extranonce2: "00000000".into(),
            version: 1,
            version_mask: 0,
            share_target: dcentrald_stratum::work::difficulty_to_target(1.0),
            merkle_root: merkle,
            prev_block_hash: [0; 32],
        }
    }

    #[tokio::test]
    async fn completed_uart_publication_retains_metadata_when_waiter_is_cancelled() {
        use std::io::Read;
        let (uarts, terminal, mut master, _slave) = retained_pty();
        uarts.initialize_work(&[0]).unwrap();
        let prepared = uarts
            .work(|owned| {
                let work = canonical_work();
                owned.activate(work.work_generation)?;
                owned.ledger.prepare(0, work)
            })
            .unwrap();
        let frame = prepared.frame().to_vec();
        let mut expected = vec![0x55, 0xaa];
        expected.extend_from_slice(&frame);
        expected.extend_from_slice(&dcentrald_asic::protocol::crc16(&frame).to_be_bytes());
        let (started, seen) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let pending = uarts.clone();
        let task = tokio::spawn(async move {
            pending
                .blocking(move |owned| {
                    let backend = owned.backend(0)?;
                    backend.commit("local classic publication", || {
                        backend
                            .backend
                            .send_work(&frame)
                            .map_err(anyhow::Error::from)
                    })?;
                    started.send(()).unwrap();
                    wait.recv().unwrap();
                    owned.work(|work| work.ledger.commit(prepared))
                })
                .await
        });
        seen.await.unwrap();
        let mut actual = vec![0; expected.len()];
        master.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        terminal.revoke();
        release.send(()).unwrap();
        uarts
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        let mut body = [0u8; 9];
        body[..4].copy_from_slice(&2083236893u32.to_le_bytes());
        body[8] = (0..32)
            .map(|c| c | 0x80)
            .find(|&flag| {
                body[8] = flag;
                dcentrald_asic::protocol::crc5(&body) == 0
            })
            .unwrap();
        uarts
            .work(|work| {
                work.qualify(0, &body, "worker.classic")?;
                assert_eq!(work.outbox.len(), 1);
                assert_eq!(work.outbox[0].nonce, "7c2bac1d");
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test]
    async fn consumed_nonce_is_qualified_inside_worker_even_when_async_waiter_is_cancelled() {
        use std::io::Write;
        let (uarts, terminal, mut master, _slave) = retained_pty();
        uarts.initialize_work(&[0]).unwrap();
        uarts
            .work(|owned| {
                let work = canonical_work();
                owned.activate(work.work_generation)?;
                let prepared = owned.ledger.prepare(0, work)?;
                owned.ledger.commit(prepared)
            })
            .unwrap();
        let backend = uarts.backend(0).unwrap();
        backend.backend.set_response_len(9);
        backend.backend.set_vtime(0).unwrap();
        let mut body = [0u8; 9];
        body[..4].copy_from_slice(&2083236893u32.to_le_bytes());
        body[8] = (0..32)
            .map(|c| c | 0x80)
            .find(|&flag| {
                body[8] = flag;
                dcentrald_asic::protocol::crc5(&body) == 0
            })
            .unwrap();
        master.write_all(&[0xaa, 0x55]).unwrap();
        master.write_all(&body).unwrap();
        let (started, seen) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let pending = uarts.clone();
        let task = tokio::spawn(async move {
            pending
                .blocking(move |owned| {
                    let deadline = Instant::now() + Duration::from_secs(1);
                    let backend = owned.backend(0)?;
                    let body = loop {
                        if let Some(body) = backend.read_nonce_response()? {
                            break body;
                        }
                        anyhow::ensure!(Instant::now() < deadline, "local PTY response missing");
                    };
                    started.send(()).unwrap();
                    wait.recv().unwrap();
                    owned.work(|work| work.qualify(0, &body, "worker.classic"))
                })
                .await
        });
        seen.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        terminal.revoke();
        release.send(()).unwrap();
        uarts
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        let (output, mut receiver) = tokio::sync::mpsc::channel(1);
        uarts
            .work(|work| {
                assert_eq!(work.outbox.len(), 1);
                assert_eq!(work.outbox[0].nonce, "7c2bac1d");
                let mut occupied = work.outbox[0].clone();
                occupied.job_id = "occupied".into();
                output.try_send(occupied).unwrap();
                assert!(!work.flush(&output)?);
                assert_eq!(work.outbox.len(), 1);
                Ok(())
            })
            .unwrap();
        assert_eq!(receiver.try_recv().unwrap().job_id, "occupied");
        uarts
            .work(|work| {
                assert!(work.flush(&output)?);
                assert!(work.outbox.is_empty());
                Ok(())
            })
            .unwrap();
        let qualified = receiver.try_recv().unwrap();
        assert_eq!(qualified.job_id, "classic-genesis");
        assert_eq!(qualified.nonce, "7c2bac1d");
        drop(receiver);
        uarts
            .work(|work| {
                work.outbox.push_back(qualified);
                assert!(work.flush(&output).is_err());
                assert_eq!(work.outbox.len(), 1);
                work.invalidate();
                assert_eq!(work.retired, 1);
                assert!(work.outbox.is_empty());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn classic_runtime_configuration_cannot_select_an_adjacent_electrical_route() {
        let mut config: DcentraldConfig = toml::from_str(include_str!("../../../../br2_external_dcentos/board/amlogic/am3-s19jpro-aml/rootfs-overlay/etc/dcentrald.toml")).unwrap();
        config.mining.enabled = true;
        config.mining.passthrough = false;
        config.mining.model = Some("s19jpro".into());
        config.mining.serial_chip_count = Some(126);
        config.mining.voltage_mv = 13700;
        config.thermal.fan_min_pwm = 10;
        config.thermal.fan_max_pwm = 30;
        config.watchdog.enabled = true;
        config.watchdog.timeout_s = 40;
        config.hash_on_disconnect.enabled = false;
        let identity = dcentrald_common::AsicProtocolIdentity::Bm1362;
        assert!(validate_config(&config, TARGET, identity, 400).is_ok());
        for target in ["am2-s19jpro", "am3-s19jproa", "am3-s19jproplus", "am3-s19k"] {
            assert!(validate_config(&config, target, identity, 400).is_err());
        }
        assert!(validate_config(&config, TARGET, identity, 525).is_err());
        config.mining.serial_chip_count = Some(120);
        assert!(validate_config(&config, TARGET, identity, 400).is_err());
        config.mining.serial_chip_count = Some(126);
        config.mining.passthrough = true;
        assert!(validate_config(&config, TARGET, identity, 400).is_err());
    }

    fn retained_pty() -> (
        Arc<Uarts>,
        SerialExecutionTerminal,
        std::fs::File,
        std::fs::File,
    ) {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: two descriptor outputs are writable, optional PTY metadata
        // is absent, and this test contacts no physical UART or miner.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: successful openpty returned two newly owned descriptors.
        let master = unsafe { std::fs::File::from_raw_fd(master) };
        // SAFETY: this is the second new descriptor, adopted exactly once.
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let path = format!("/proc/self/fd/{}", slave.as_raw_fd());
        let (execution, terminal) = execution_fence_domain(SerialSessionToken {
            _run_scope: crate::runtime::safety_watchdog::WatchdogRunScope::new(),
            route: ExactSerialRoute::ClassicAml,
            descriptor: SerialSessionDescriptor {
                board_target: TARGET,
                identity: dcentrald_common::AsicProtocolIdentity::Bm1362,
                active_slot: 0,
                serial_device: path.clone(),
                configured_chip_count: 126,
                industrial_pll_policy: Some(POLICY),
            },
        });
        let uarts = Arc::new(Uarts::default());
        uarts.backends.lock().unwrap().insert(
            0,
            Arc::new(
                ValidatedSerialBackend::new(
                    SerialChainBackend::open_native_linux_only(0, &path, 115200).unwrap(),
                    execution,
                )
                .with_classic_aml_cancellation(CancellationToken::new()),
            ),
        );
        (uarts, terminal, master, slave)
    }

    #[tokio::test]
    async fn readonly_reporting_waits_for_inflight_complete_health_and_preserves_original_age() {
        let sample = |age| {
            Arc::new(ClassicHealth {
                temperatures: vec![],
                fans: vec![],
                voltages: vec![],
                observed_from: Instant::now() - age,
                completed_at: Instant::now(),
            })
        };
        let (sender, mut receiver) = tokio::sync::watch::channel(sample(Duration::from_secs(6)));
        let stop = CancellationToken::new();
        let waiting_stop = stop.clone();
        let waiting = tokio::spawn(async move {
            fresh_reported_health(
                &mut receiver,
                &waiting_stop,
                Instant::now() + Duration::from_secs(1),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        let fresh = sample(Duration::from_millis(3500));
        sender.send_replace(fresh.clone());
        let reported = waiting.await.unwrap().unwrap();
        assert!(Arc::ptr_eq(&reported, &fresh));
        assert!(reported.observed_from.elapsed() >= Duration::from_millis(3500));
        let (_stale_sender, mut stale) =
            tokio::sync::watch::channel(sample(Duration::from_secs(6)));
        assert!(fresh_reported_health(
            &mut stale,
            &stop,
            Instant::now() + Duration::from_millis(20)
        )
        .await
        .is_err());
        stop.cancel();
        assert!(
            fresh_reported_health(&mut stale, &stop, Instant::now() + Duration::from_secs(1))
                .await
                .is_err()
        );
    }

    fn assigned_geometry(frequency: u16) -> ValidatedSerialAssignedGeometry {
        let bodies = (0..126u8)
            .map(|index| {
                let address = index * 2;
                let mut body = [0x13, 0x62, 3, address, address, 0, 0, 0, 0];
                body[8] = dcentrald_asic::protocol::bm13xx_command_response_crc5(&body[..8]);
                body
            })
            .collect::<Vec<_>>();
        let window =
            validate_serial_chip_address_window(bodies.iter().map(|body| &body[..])).unwrap();
        ValidatedSerialAssignedGeometry::from_window(
            window,
            dcentrald_common::AsicProtocolIdentity::Bm1362,
            126,
            2,
        )
        .unwrap()
        .with_applied_frequency(frequency)
    }

    #[tokio::test]
    async fn cancelled_initializer_retains_exact_geometry_and_publishes_observed_values() {
        let (uarts, terminal, _master, _slave) = retained_pty();
        assert!(uarts.observed_geometry(&[0]).is_err());
        assert!(uarts.require_geometry(0).is_err());
        assert!(uarts.retain_geometry(1, assigned_geometry(425)).is_err());
        let mut wrong = assigned_geometry(425);
        wrong.identity = dcentrald_common::AsicProtocolIdentity::Bm1368;
        assert!(uarts.retain_geometry(0, wrong).is_err());
        assert!(uarts.retain_geometry(0, assigned_geometry(525)).is_err());
        let (stored, seen) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let owned = uarts.clone();
        let pending = tokio::spawn(async move {
            owned
                .blocking(move |custody| {
                    custody.retain_geometry(0, assigned_geometry(425))?;
                    stored.send(()).unwrap();
                    wait.recv().unwrap();
                    Ok(())
                })
                .await
        });
        seen.await.unwrap();
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        let observed = uarts.observed_geometry(&[0]).unwrap();
        assert_eq!(
            observed,
            vec![ObservedChain {
                slot: 0,
                chips: 126,
                frequency_mhz: 425
            }]
        );
        assert!(uarts.observed_geometry(&[0, 1]).is_err());
        assert!(uarts.retain_geometry(0, assigned_geometry(450)).is_err());
        uarts.require_geometry(0).unwrap();
        let mut state = dcentrald_api::MinerState::empty(dcentrald_api::OperatingMode::Standard);
        let health = ClassicHealth {
            temperatures: vec![],
            fans: vec![],
            voltages: vec![],
            observed_from: Instant::now(),
            completed_at: Instant::now(),
        };
        let mut ledger = Ledger::new(&[0]).unwrap();
        update_state(&mut state, &health, &observed, &mut ledger, Instant::now());
        assert_eq!(state.chains[0].chips, 126);
        assert_eq!(state.chains[0].frequency_mhz, 425);
        assert!(matches!(
            terminal.revoke().try_wait_for_commit_fence(),
            ExecutionFenceTryWait::Fenced(_)
        ));
        assert!(uarts
            .close_until(Instant::now() + Duration::from_millis(20))
            .await
            .is_err());
        assert_eq!(uarts.geometry.lock().unwrap().len(), 1);
        release.send(()).unwrap();
        uarts
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(uarts.geometry.lock().unwrap().is_empty());
        assert!(uarts.require_geometry(0).is_err());
    }

    #[tokio::test]
    async fn cancelled_uart_waiter_retains_actual_worker_and_rejects_later_commit() {
        let (uarts, terminal, master, _slave) = retained_pty();
        let (started, seen) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let pending_uarts = uarts.clone();
        let task = tokio::spawn(async move {
            pending_uarts
                .blocking(move |owned| {
                    started.send(()).unwrap();
                    wait.recv().unwrap();
                    owned.backend(0)?.send_get_address_bm1397plus()
                })
                .await
        });
        seen.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(uarts.inflight.load(Ordering::SeqCst), 1);
        assert_eq!(uarts.backends.lock().unwrap().len(), 1);
        assert!(matches!(
            terminal.revoke().try_wait_for_commit_fence(),
            ExecutionFenceTryWait::Fenced(_)
        ));
        assert!(uarts
            .close_until(Instant::now() + Duration::from_millis(20))
            .await
            .is_err());
        release.send(()).unwrap();
        uarts
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        let mut descriptor = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one owned local PTY descriptor; immediate read-only poll.
        assert_eq!(
            unsafe { libc::poll(&mut descriptor, 1, 0) },
            0,
            "revoked late worker must not emit any UART command"
        );
        assert!(
            uarts.blocking(|_| Ok(())).await.is_err(),
            "closed UART custody must refuse later health-proof workers too"
        );
    }

    #[tokio::test]
    async fn failed_uart_initialization_keeps_the_exclusive_backend_for_cutoff() {
        let (uarts, terminal, _master, _slave) = retained_pty();
        let result = uarts
            .blocking(|owned| {
                let serial = owned.backend(0)?;
                // A genuine init preflight failure before any protocol write. The
                // same retained borrow is used for all later protocol failures.
                SerialMiner::init_bm1362_aml_chain_retained(
                    &serial,
                    "local-test",
                    115200,
                    120,
                    400,
                    POLICY,
                )
            })
            .await;
        assert!(result.is_err());
        assert_eq!(uarts.backends.lock().unwrap().len(), 1);
        assert_eq!(uarts.inflight.load(Ordering::SeqCst), 0);
        assert!(matches!(
            terminal.revoke().try_wait_for_commit_fence(),
            ExecutionFenceTryWait::Fenced(_)
        ));
        uarts
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(uarts.backends.lock().unwrap().is_empty());
    }
}

const MAX_PENDING_SHARES: usize = 4096;
struct WorkState {
    ledger: Ledger,
    generation: Option<dcentrald_stratum::WorkGeneration>,
    newest: Option<dcentrald_stratum::WorkGeneration>,
    outbox: VecDeque<ValidShare>,
    retired: u64,
}
impl WorkState {
    fn new(slots: &[u8]) -> Result<Self> {
        Ok(Self {
            ledger: Ledger::new(slots)?,
            generation: None,
            newest: None,
            outbox: VecDeque::new(),
            retired: 0,
        })
    }
    fn invalidate(&mut self) {
        self.ledger.invalidate();
        self.generation = None;
        self.retired = self.retired.saturating_add(self.outbox.len() as u64);
        self.outbox.clear();
    }
    fn activate(&mut self, generation: dcentrald_stratum::WorkGeneration) -> Result<()> {
        anyhow::ensure!(
            generation != dcentrald_stratum::WorkGeneration::UNTRACKED,
            "classic untracked pool generation rejected"
        );
        if let Some(prior) = self.newest {
            anyhow::ensure!(
                (generation.session, generation.job) >= (prior.session, prior.job),
                "classic delayed pool job cannot rewind the retained generation"
            );
        }
        self.invalidate();
        self.newest = Some(generation);
        self.generation = Some(generation);
        self.ledger.select_generation(generation);
        Ok(())
    }
    fn qualify(&mut self, slot: u8, body: &[u8], worker: &str) -> Result<()> {
        if let Some(verified) = self.ledger.validate(slot, body, worker)? {
            if let Some(share) = verified.share {
                // Preserve the just-consumed result even on the terminal
                // overflow edge. The worker returns an error immediately, so
                // this one additional entry is the absolute bounded maximum.
                self.outbox.push_back(share);
                anyhow::ensure!(
                    self.outbox.len() <= MAX_PENDING_SHARES,
                    "classic retained share outbox exhausted"
                );
            }
        }
        Ok(())
    }
    fn flush(&mut self, output: &tokio::sync::mpsc::Sender<ValidShare>) -> Result<bool> {
        use tokio::sync::mpsc::error::TrySendError;
        while let Some(share) = self.outbox.pop_front() {
            if Some(share.work_generation) != self.generation {
                self.retired = self.retired.saturating_add(1);
                continue;
            }
            match output.try_send(share) {
                Ok(()) => (),
                Err(TrySendError::Full(share)) => {
                    self.outbox.push_front(share);
                    return Ok(false);
                }
                Err(TrySendError::Closed(share)) => {
                    self.outbox.push_front(share);
                    anyhow::bail!("classic pool share actor closed with retained qualified work");
                }
            }
        }
        Ok(true)
    }
}

/// All opened descriptors remain here through initialization errors. A
/// blocking task increments before queueing and holds this Arc until exit;
/// cancelling its async waiter never manufactures physical quiescence.
#[derive(Default)]
struct Uarts {
    backends: Mutex<BTreeMap<u8, Arc<ValidatedSerialBackend>>>,
    inflight: AtomicUsize,
    work: Mutex<Option<WorkState>>,
    admission_closed: Mutex<bool>,
    proof_published: AtomicBool,
    geometry: Mutex<BTreeMap<u8, ValidatedSerialAssignedGeometry>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedChain {
    slot: u8,
    chips: u8,
    frequency_mhz: u16,
}
struct Flight(Arc<Uarts>);
impl Drop for Flight {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Uarts {
    fn retain_geometry(&self, slot: u8, geometry: ValidatedSerialAssignedGeometry) -> Result<()> {
        self.backend(slot)?;
        anyhow::ensure!(
            geometry.identity == dcentrald_common::AsicProtocolIdentity::Bm1362
                && geometry.observed_chip_count() == 126
                && POLICY.admits_target(geometry.applied_frequency_mhz)
                && geometry.addresses == dcentrald_common::linear_chip_addresses(126, 2),
            "classic assigned coverage lost its exact family, population or applied PLL"
        );
        let mut retained = self
            .geometry
            .lock()
            .map_err(|_| anyhow::anyhow!("classic assigned geometry custody poisoned"))?;
        anyhow::ensure!(
            !retained.contains_key(&slot),
            "classic assigned geometry cannot replace a retained observation"
        );
        retained.insert(slot, geometry);
        Ok(())
    }
    fn observed_geometry(&self, slots: &[u8]) -> Result<Vec<ObservedChain>> {
        let retained = self
            .geometry
            .lock()
            .map_err(|_| anyhow::anyhow!("classic assigned geometry custody poisoned"))?;
        anyhow::ensure!(
            !slots.is_empty() && retained.keys().copied().eq(slots.iter().copied()),
            "classic publication requires complete assigned coverage of every selected UART"
        );
        Ok(retained
            .iter()
            .map(|(&slot, geometry)| ObservedChain {
                slot,
                chips: geometry.observed_chip_count(),
                frequency_mhz: geometry.applied_frequency_mhz,
            })
            .collect())
    }
    fn require_geometry(&self, slot: u8) -> Result<()> {
        anyhow::ensure!(
            self.geometry
                .lock()
                .map_err(|_| anyhow::anyhow!("classic assigned geometry custody poisoned"))?
                .contains_key(&slot),
            "classic work has no retained assigned coverage for this UART"
        );
        Ok(())
    }
    fn work<T>(&self, operation: impl FnOnce(&mut WorkState) -> Result<T>) -> Result<T> {
        let mut retained = self
            .work
            .lock()
            .map_err(|_| anyhow::anyhow!("classic work owner poisoned"))?;
        operation(
            retained
                .as_mut()
                .context("classic selected work owner is not initialized")?,
        )
    }
    fn initialize_work(&self, slots: &[u8]) -> Result<()> {
        let mut retained = self
            .work
            .lock()
            .map_err(|_| anyhow::anyhow!("classic work owner poisoned"))?;
        anyhow::ensure!(retained.is_none(), "classic work owner already initialized");
        *retained = Some(WorkState::new(slots)?);
        Ok(())
    }
    async fn blocking<T, F>(self: &Arc<Self>, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Uarts) -> Result<T> + Send + 'static,
    {
        {
            let closed = self
                .admission_closed
                .lock()
                .map_err(|_| anyhow::anyhow!("classic worker admission poisoned"))?;
            anyhow::ensure!(!*closed, "classic worker admission is closed");
            self.inflight.fetch_add(1, Ordering::SeqCst);
        }
        let flight = Flight(self.clone());
        tokio::task::spawn_blocking(move || {
            let result = operation(&flight.0);
            drop(flight);
            result
        })
        .await
        .context("classic UART worker panicked")?
    }
    fn backend(&self, slot: u8) -> Result<Arc<ValidatedSerialBackend>> {
        self.backends
            .lock()
            .map_err(|_| anyhow::anyhow!("classic UART custody poisoned"))?
            .get(&slot)
            .cloned()
            .context("classic UART slot has not been retained")
    }
    async fn close_until(&self, deadline: Instant) -> Result<()> {
        *self
            .admission_closed
            .lock()
            .map_err(|_| anyhow::anyhow!("classic worker admission poisoned"))? = true;
        while self.inflight.load(Ordering::SeqCst) != 0 {
            anyhow::ensure!(
                Instant::now() < deadline,
                "classic UART workers still own descriptors"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        self.backends
            .lock()
            .map_err(|_| anyhow::anyhow!("classic UART custody poisoned"))?
            .clear();
        self.geometry
            .lock()
            .map_err(|_| anyhow::anyhow!("classic assigned geometry custody poisoned"))?
            .clear();
        if self.proof_published.swap(false, Ordering::SeqCst) {
            proof::remove()?;
        }
        if let Some(work) = self
            .work
            .lock()
            .map_err(|_| anyhow::anyhow!("classic work owner poisoned"))?
            .as_ref()
        {
            tracing::info!(
                pending_qualified_shares = work.outbox.len(),
                retired_qualified_shares = work.retired,
                "classic terminal work custody observed; no late submissions"
            );
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "classic UART closeout exceeded deadline"
        );
        Ok(())
    }
}

struct Crash {
    armed: AtomicBool,
    power: Arc<ClassicAmlPowerOwner>,
    serial: SerialExecutionTerminal,
    feed: WatchdogFeedStopSignal,
    shutdown: CancellationToken,
}
impl Crash {
    fn stop(&self) {
        if !self.armed.load(Ordering::SeqCst) {
            return;
        }
        self.feed.close_terminal_lock_free();
        self.shutdown.cancel();
        self.serial.clone().revoke();
        self.power.fence();
        // Independent pins only. Parser/PSU workers may still be blocked.
        let _ = self
            .power
            .emergency_cut_until(Instant::now() + Duration::from_millis(100));
    }
}
struct CrashDrop(Arc<Crash>);
impl Drop for CrashDrop {
    fn drop(&mut self) {
        self.0.stop();
    }
}
static CRASH: OnceLock<Mutex<Option<Weak<Crash>>>> = OnceLock::new();
pub(super) fn panic_teardown() {
    let Some(registry) = CRASH.get() else {
        return;
    };
    let Ok(registered) = registry.try_lock() else {
        return;
    };
    let owner = registered.as_ref().and_then(Weak::upgrade);
    drop(registered);
    if let Some(owner) = owner {
        owner.stop();
    }
}

async fn adopt_api(
    actors: &mut ClassicAmlActors,
    config: &DcentraldConfig,
    state: tokio::sync::watch::Receiver<dcentrald_api::MinerState>,
    gate: dcentrald_hal::platform::HardwareMutationGate,
) -> Result<()> {
    // Construct just the two actual server tasks. The generic runtime API
    // helper also spawns notification actors outside this fixed roster.
    let app = dcentrald_api::build_minimal_app_state_with_hardware_mutation_gate(
        dcentrald_api::MinimalAppStateInputs {
            api_config: dcentrald_api::ApiConfig {
                cgminer_port: config.api.cgminer_port,
                http_port: config.api.http_port,
                http_bind: config.api.http_bind.clone(),
                websocket_enabled: config.api.websocket,
                websocket_tickets: config.api.websocket_tickets,
                cgminer_bind_lan: config.api.cgminer_bind_lan,
                cgminer_lan_writes: false,
                metrics_require_auth: config.api.metrics_require_auth,
                expose_boot_timeline: config.api.expose_boot_timeline,
                observer_only: true,
            },
            pool_url: config.pool.url.clone(),
            pool_protocol: config.pool.protocol.clone().unwrap_or_else(|| "sv1".into()),
            mode: dcentrald_api::OperatingMode::Standard,
            firmware_version: env!("CARGO_PKG_VERSION").into(),
            fan_pwm: 0,
            network_block: config.network_block.clone(),
            profile_path: config.autotuner.profile_path.clone(),
            control_board_label: "Amlogic classic fw89 application".into(),
            chip_type_label: "BM1362".into(),
            external_state_rx: Some(state),
        },
        gate,
    );
    app.hardware_info
        .lock()
        .map_err(|_| anyhow::anyhow!("classic API identity lock poisoned"))?
        .identification = dcentrald_api::HardwareIdentification::from_evidence(
        vec![
            dcentrald_api::HardwareIdentityEvidence::observed_control_board("Amlogic"),
            dcentrald_api::HardwareIdentityEvidence::declared_asic_board_target(TARGET, "BM1362"),
        ],
        Some(
            "Retained current-boot factory/PIC owner; ASIC coverage is reported per runtime chain"
                .into(),
        ),
    );
    let (first, second) = dcentrald_api::start_api_servers(app).await?;
    if let Err(first) = actors.adopt(ClassicAmlActorSlot::ApiServer, first) {
        first.abort();
        second.abort();
        let _ = first.await;
        let _ = second.await;
        anyhow::bail!("classic API server custody rejected");
    }
    if let Err(second) = actors.adopt(ClassicAmlActorSlot::ApiState, second) {
        second.abort();
        let _ = second.await;
        anyhow::bail!("classic API state custody rejected");
    }
    Ok(())
}

fn update_state(
    state: &mut dcentrald_api::MinerState,
    health: &ClassicHealth,
    geometry: &[ObservedChain],
    ledger: &mut Ledger,
    started: Instant,
) {
    state.uptime_s = started.elapsed().as_secs();
    state.hashrate_ghs = 0.0;
    state.hashrate_5s_ghs = 0.0;
    state.chains = geometry
        .iter()
        .map(|observed| {
            let slot = observed.slot;
            let (all, recent) = ledger.hashrates(slot, started.elapsed());
            state.hashrate_ghs += all;
            state.hashrate_5s_ghs += recent;
            dcentrald_api::ChainState {
                id: slot,
                chips: observed.chips,
                frequency_mhz: observed.frequency_mhz,
                voltage_mv: health
                    .voltages
                    .iter()
                    .find(|v| v.chain == slot + 1)
                    .map(|v| (v.volts * 1000.0).round() as u16)
                    .unwrap_or(0),
                temp_c: health
                    .temperatures
                    .iter()
                    .filter(|t| t.chain == slot + 1)
                    .map(|t| t.celsius as f32)
                    .reduce(f32::max)
                    .unwrap_or(0.0),
                temp_source: Some("classic_pic_lm75".into()),
                hashrate_ghs: recent,
                errors: 0,
                status: if recent > 0.0 { "mining" } else { "active" }.into(),
            }
        })
        .collect();
    state.fans = dcentrald_api::FanState {
        pwm: 30,
        rpm: health.fans.iter().map(|(_, rpm)| *rpm).min().unwrap_or(0),
        per_fan: health
            .fans
            .iter()
            .map(|&(id, rpm)| dcentrald_api::PerFanReading {
                id,
                rpm,
                pwm_percent: 30,
            })
            .collect(),
    };
}

async fn fresh_reported_health(
    updates: &mut tokio::sync::watch::Receiver<Arc<ClassicHealth>>,
    shutdown: &CancellationToken,
    deadline: Instant,
) -> Result<Arc<ClassicHealth>> {
    loop {
        let health = updates.borrow().clone();
        if health.observed_from.elapsed() < Duration::from_secs(5) {
            return Ok(health);
        }
        // Work uses the locked HAL observation directly. Read-only API state
        // waits for the actor to publish an in-flight complete scan instead of
        // converting its older watch value into a false hardware fault.
        tokio::select! {
            _ = shutdown.cancelled() => anyhow::bail!("classic reporting cancelled"),
            changed = tokio::time::timeout_at(deadline.into(), updates.changed()) => {
                changed.context("classic health publication remained stale")?
                    .context("classic health publisher closed")?;
            }
        }
    }
}

async fn mining(
    config: &DcentraldConfig,
    shutdown: &CancellationToken,
    watchdog: &mut SafetyWatchdogOwner,
    route: &ClassicAmlWatchdogRouteScope,
    actors: &mut ClassicAmlActors,
    crash: &Arc<Crash>,
    uarts: &Arc<Uarts>,
    execution: SerialExecutionCommitPort,
    frequency: u16,
    liveness: SafetyLiveness,
) -> Result<()> {
    let health = crash
        .power
        .start_at(
            f64::from(config.mining.voltage_mv) / 1000.0,
            1800,
            Instant::now() + Duration::from_secs(60),
        )
        .await?;
    anyhow::ensure!(
        health
            .temperatures
            .iter()
            .all(|t| t.celsius < f64::from(config.thermal.dangerous_temp_c.min(80))),
        "classic initial thermal observation exceeds configured cutoff"
    );
    let (health_tx, mut health_rx) = tokio::sync::watch::channel(Arc::new(health));
    let health_crash = crash.clone();
    let health_uarts = uarts.clone();
    let health_publication = execution.clone();
    let cutoff = f64::from(config.thermal.dangerous_temp_c.min(80));
    actors.spawn(ClassicAmlActorSlot::Health, async move {
        loop {
            if health_crash.shutdown.is_cancelled() {
                break;
            }
            match health_crash
                .power
                .health_at(Instant::now() + Duration::from_secs(5))
                .await
            {
                Ok(health) if health.temperatures.iter().all(|t| t.celsius < cutoff) => {
                    let health = Arc::new(health);
                    let published_health = health.clone();
                    let publication = health_publication.clone();
                    let stop = health_crash.shutdown.clone();
                    let chains = health_crash.power.physical_chains();
                    let published = health_uarts.blocking(move |owned| {
                        publication.commit_if("classic application health proof",
                            || !stop.is_cancelled(), || -> Result<()> {
                                proof::publish(&published_health, &chains, || !stop.is_cancelled())?;
                                owned.proof_published.store(true, Ordering::SeqCst);
                                Ok(())
                            }).map_err(anyhow::Error::from)
                    }).await;
                    if let Err(error) = published {
                        tracing::error!(%error, "classic application health proof publication failed");
                        health_crash.serial.clone().revoke();
                        health_crash.power.fence();
                        health_crash.shutdown.cancel();
                        break;
                    }
                    liveness.mark_progress();
                    health_tx.send_replace(health);
                }
                result => {
                    tracing::error!(
                        ?result,
                        "classic power/thermal heartbeat supervision failed"
                    );
                    health_crash.serial.clone().revoke();
                    health_crash.power.fence();
                    health_crash.shutdown.cancel();
                    break;
                }
            }
            tokio::select! {
                _ = health_crash.shutdown.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
        }
    })?;
    let slots: Vec<u8> = crash
        .power
        .physical_chains()
        .into_iter()
        .map(|c| c - 1)
        .collect();
    for &slot in &slots {
        let execution = execution.clone();
        let stop = shutdown.clone();
        let init = uarts.blocking(move |custody| {
            anyhow::ensure!(
                !stop.is_cancelled(),
                "classic UART init cancelled before open"
            );
            let serial =
                execution.commit("classic exclusive Linux UART open", || -> Result<_> {
                    anyhow::ensure!(
                        !stop.is_cancelled(),
                        "classic UART cancelled at open commit"
                    );
                    Ok(SerialChainBackend::open_native_linux_only(
                        slot,
                        UARTS[slot as usize],
                        115200,
                    )?)
                })?;
            let serial = Arc::new(
                ValidatedSerialBackend::new(serial, execution).with_classic_aml_cancellation(stop),
            );
            custody
                .backends
                .lock()
                .map_err(|_| anyhow::anyhow!("classic UART custody poisoned"))?
                .insert(slot, serial.clone());
            serial.commit("classic nonblocking kernel read configuration", || {
                serial.backend.set_vtime(0).map_err(anyhow::Error::from)
            })?;
            let geometry = SerialMiner::init_bm1362_aml_chain_retained(
                &serial,
                UARTS[slot as usize],
                115200,
                126,
                frequency,
                POLICY,
            )?;
            serial.set_response_len(9);
            custody.retain_geometry(slot, geometry)
        });
        tokio::select! {
            _ = shutdown.cancelled() => anyhow::bail!("classic cancelled during complete-chain initialization"),
            result = init => { result?; }
        }
    }
    // Initialization workers retain their actual coverage before their waiter
    // can be cancelled. Only the complete selected roster creates normal work.
    let observed = uarts.observed_geometry(&slots)?;
    uarts.initialize_work(&observed.iter().map(|row| row.slot).collect::<Vec<_>>())?;
    let (state_tx, state_rx) = tokio::sync::watch::channel(dcentrald_api::MinerState::empty(
        dcentrald_api::OperatingMode::Standard,
    ));
    adopt_api(actors, config, state_rx, route.api_gate()?).await?;
    let (job_tx, mut job_rx) = tokio::sync::mpsc::channel::<JobTemplate>(16);
    let (share_tx, share_rx) = tokio::sync::mpsc::channel::<ValidShare>(128);
    let (status_tx, mut status_rx) = tokio::sync::mpsc::channel::<StratumStatus>(128);
    let router_config = crate::config::build_stratum_config_with_enumerated_chips(
        config,
        crate::config::stratum_donation_config(&config.donation),
        config.mining.version_rolling,
        false,
        Some(observed.iter().map(|row| u32::from(row.chips)).sum()),
    );
    let stop = shutdown.clone();
    actors.spawn(ClassicAmlActorSlot::Stratum, async move {
        let mut router = dcentrald_stratum::StratumRouter::new(router_config);
        tokio::select! {
            _ = stop.cancelled() => {},
            _ = router.run(job_tx, share_rx, status_tx) => { stop.cancel(); }
        }
    })?;
    watchdog.enter_classic_aml_mining(route, actors).await?;
    let started = Instant::now();
    let mut state = state_tx.borrow().clone();
    state.pool.url = config.pool.url.clone();
    state.pool.worker = config.pool.worker.clone();
    let mut builder = dcentrald_stratum::work::WorkBuilder::new();
    let mut job: Option<JobTemplate> = None;
    let mut dispatched = false;
    let mut next_work = Instant::now();
    let mut next_state = Instant::now();
    loop {
        anyhow::ensure!(
            !shutdown.is_cancelled(),
            "classic runtime shutdown requested"
        );
        actors.require_running()?;
        while let Ok(event) = status_rx.try_recv() {
            match event {
                StratumStatus::StateChanged(value) => {
                    state.pool.status = format!("{value:?}").to_ascii_lowercase();
                    if matches!(value, StratumState::Disconnected | StratumState::AuthFailed) {
                        uarts.work(|work| {
                            work.invalidate();
                            Ok(())
                        })?;
                        job = None;
                        anyhow::ensure!(!dispatched,
                            "classic pool disconnected after physical work; independent cutoff required");
                    }
                }
                StratumStatus::DifficultyChanged(difficulty) => state.pool.difficulty = difficulty,
                StratumStatus::ShareAccepted { .. } => {
                    state.accepted += 1;
                }
                StratumStatus::ShareRejected { .. } => {
                    state.rejected += 1;
                }
                _ => {}
            }
        }
        while let Ok(incoming) = job_rx.try_recv() {
            if incoming.is_flush_only() {
                uarts.work(|work| {
                    work.invalidate();
                    Ok(())
                })?;
                job = None;
                anyhow::ensure!(
                    !dispatched,
                    "classic upstream work cut requires independent rail cutoff"
                );
                continue;
            }
            builder.set_version_mask(if config.mining.version_rolling {
                incoming.version_mask
            } else {
                0
            });
            uarts.work(|work| work.activate(incoming.work_generation))?;
            job = Some(incoming);
            next_work = Instant::now();
        }
        if Instant::now() >= next_work {
            if let Some(job) = &job {
                for &slot in &slots {
                    // Full source-paced health scans take more than one second
                    // even for one board. Wait for this same owner's fresh scan;
                    // bind the returned observation, not a lagging API watch.
                    let health_from = crash
                        .power
                        .require_work_health_at(Instant::now() + Duration::from_secs(5))
                        .await?;
                    let health_deadline = health_from + Duration::from_secs(5);
                    let work = builder.next_work(job)?;
                    let prepared: PreparedWork =
                        uarts.work(|owned| owned.ledger.prepare(slot, work))?;
                    let frame = prepared.frame().to_vec();
                    uarts
                        .blocking(move |owned| {
                            let backend = owned.backend(slot)?;
                            backend.commit("classic mining work health-bound commit", || {
                                owned.require_geometry(slot)?;
                                anyhow::ensure!(
                                    Instant::now() < health_deadline,
                                    "classic work health expired while waiting for UART commit"
                                );
                                backend
                                    .backend
                                    .send_work(&frame)
                                    .map_err(anyhow::Error::from)
                            })?;
                            // Actual write completion and its metadata publish
                            // are both owned by this counted physical worker.
                            owned.work(|work| work.ledger.commit(prepared))
                        })
                        .await?;
                    dispatched = true;
                }
            }
            next_work = Instant::now() + Duration::from_millis(100);
        }
        let poll_slots = slots.clone();
        let worker = config.pool.worker.clone();
        let output = share_tx.clone();
        let publication = execution.clone();
        let stop = shutdown.clone();
        uarts
            .blocking(move |owned| {
                publication.commit_if(
                    "classic queued share publication",
                    || !stop.is_cancelled(),
                    || owned.work(|work| work.flush(&output)),
                )?;
                for slot in poll_slots {
                    let backend = owned.backend(slot)?;
                    for _ in 0..32 {
                        let Some(body) = backend.read_nonce_response()? else {
                            break;
                        };
                        // Qualify and retain before returning from the physical
                        // worker: cancelling its waiter cannot lose consumed RX.
                        owned.work(|work| work.qualify(slot, &body, &worker))?;
                    }
                }
                publication
                    .commit_if(
                        "classic qualified share publication",
                        || !stop.is_cancelled(),
                        || {
                            owned.work(|work| {
                                work.flush(&output)?;
                                work.ledger.require_liveness()
                            })
                        },
                    )
                    .map_err(anyhow::Error::from)
            })
            .await?;
        if Instant::now() >= next_state {
            let health = fresh_reported_health(
                &mut health_rx,
                &shutdown,
                Instant::now() + Duration::from_secs(5),
            )
            .await?;
            uarts.work(|work| {
                update_state(&mut state, &health, &observed, &mut work.ledger, started);
                Ok(())
            })?;
            state_tx.send_replace(state.clone());
            next_state = Instant::now() + Duration::from_secs(1);
        }
        tokio::select! {
            _ = shutdown.cancelled() => anyhow::bail!("classic runtime shutdown requested"),
            _ = tokio::time::sleep(Duration::from_millis(2)) => {}
        }
    }
}

pub(super) async fn run(
    config: DcentraldConfig,
    shutdown: CancellationToken,
    admission: crate::SerialRuntimeDispatchAdmission,
    frequency: u16,
) -> Result<()> {
    validate_config(
        &config,
        admission.board_target(),
        admission.identity(),
        frequency,
    )?;
    let software_closeout_run =
        dcentrald_common::mutation_disposition::capture_software_closeout_run(admission.board_target());
    let liveness = SafetyLiveness::default();
    let (mut watchdog, armed) = SafetyWatchdogOwner::start_before_energizing(
        &config.watchdog,
        Duration::from_secs(180),
        Duration::from_secs(5),
        liveness.clone(),
    )
    .await?;
    armed.require_armed("classic AML native")?;
    let (mut route, mut actors) = watchdog.claim_classic_aml_route_scope(shutdown.clone())?;
    let power =
        match ClassicAmlPowerOwner::acquire_at(Instant::now() + Duration::from_secs(30)).await {
            Ok(owner) => Arc::new(owner),
            Err(error) => {
                watchdog.feed_stop_signal().close_terminal_lock_free();
                return Err(watchdog_reset_pending_error(
                    "classic AML native",
                    format!("retained classic factory/PIC admission failed: {error}"),
                ));
            }
        };
    route.bind_power(power.clone())?;
    let slots = power.physical_chains();
    let first = *slots.first().context("classic retained population empty")? - 1;
    let (execution, terminal) = execution_fence_domain(SerialSessionToken {
        _run_scope: route.serial_scope()?,
        route: ExactSerialRoute::ClassicAml,
        descriptor: SerialSessionDescriptor {
            board_target: TARGET,
            identity: admission.identity(),
            active_slot: first,
            serial_device: UARTS[first as usize].into(),
            configured_chip_count: 126,
            industrial_pll_policy: Some(POLICY),
        },
    });
    let crash = Arc::new(Crash {
        armed: AtomicBool::new(true),
        power,
        serial: terminal,
        feed: watchdog.feed_stop_signal(),
        shutdown: shutdown.clone(),
    });
    let crash_drop = CrashDrop(crash.clone());
    let registry = CRASH.get_or_init(|| Mutex::new(None));
    {
        let mut registered = registry
            .lock()
            .map_err(|_| anyhow::anyhow!("classic crash registry poisoned"))?;
        anyhow::ensure!(
            registered.as_ref().and_then(Weak::upgrade).is_none(),
            "classic runtime already owns crash custody"
        );
        *registered = Some(Arc::downgrade(&crash));
    }
    let uarts = Arc::new(Uarts::default());
    let result = tokio::select! {
        _ = shutdown.cancelled() => Err(anyhow::anyhow!("classic runtime shutdown requested")),
        result = mining(&config, &shutdown, &mut watchdog, &route, &mut actors,
            &crash, &uarts, execution, frequency, liveness) => result,
    };
    shutdown.cancel();
    actors.request_stop();
    crash.power.fence();
    let mut serial = crash.serial.clone().revoke();
    // Budget publication and serial/API revocation precede independent GPIO
    // cutoff. Never wait on a UART kernel call before cutting the shared rail.
    let request = match watchdog.request_teardown_budget() {
        Ok(request) => request,
        Err(error) => {
            // Missing budget authority forbids Disarm, but cannot suppress
            // the actual hardware cleanup. Stop feed admission synchronously.
            crash.feed.close_terminal_lock_free();
            let _ = route
                .close_api_at(Instant::now() + Duration::from_secs(2))
                .await;
            let _ = crash
                .power
                .close_at(Instant::now() + Duration::from_secs(26))
                .await;
            crash.stop();
            return Err(watchdog_reset_pending_error(
                "classic AML native",
                format!("watchdog could not issue terminal budget: {error:#}"),
            ));
        }
    };
    let closeout = async {
        let (budget, teardown_ack) = request.into_parts();
        let view = budget.view();
        let deadline = view.deadline(TeardownStage::CleanupComplete);
        let api_result = route
            .close_api_at(view.deadline(TeardownStage::CutoffStart))
            .await;
        // A failed API drain still cannot skip physical cutoff.
        let controls = crash.power.close_at(deadline).await;
        watchdog
            .observe_teardown_admission(teardown_ack, &view)
            .await
            .map_err(anyhow::Error::msg)?;
        let api = api_result?;
        let serial_receipt = loop {
            match serial.try_wait_for_commit_fence() {
                ExecutionFenceTryWait::Fenced(receipt) => {
                    break SerialExecutionBarrierReceipt::from_receipt(receipt)
                }
                ExecutionFenceTryWait::Pending(pending) => serial = pending,
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "classic serial physical commit did not quiesce"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        uarts.close_until(deadline).await?;
        let actor_receipt = actors.close_until(deadline).await?;
        let teardown = budget.begin_disarm_at(Instant::now())?;
        let permit = WatchdogDisarmPermit::from_classic_aml_manifest(
            ClassicAmlWatchdogShutdownManifest::new(
                route,
                api,
                serial_receipt,
                controls,
                actor_receipt,
                view,
                teardown,
            ),
        )?;
        watchdog
            .disarm_and_join(permit, DEFAULT_WATCHDOG_STOP_TIMEOUT)
            .await
    }
    .await;
    match closeout {
        Ok(receipt) => {
            crash.armed.store(false, Ordering::SeqCst);
            drop(crash_drop);
            match result {
                Ok(()) => crate::daemon::publish_orderly_software_closeout(software_closeout_run, &receipt),
                Err(error) => Err(terminal_safe_off_error(error, receipt)),
            }
        }
        Err(error) => {
            crash.stop();
            Err(watchdog_reset_pending_error(
                "classic AML native",
                format!(
                    "{}; terminal closeout: {error:#}",
                    result.err().map(|e| format!("{e:#}")).unwrap_or_default()
                ),
            ))
        }
    }
}
