//! Actual coordinator/source producers/worker/consumer/watchdog. Only descriptors
//! and a loopback pool are modeled; original producers create all receipts.
use super::*;
use dcentrald_hal::platform::stock_bm1396::simulation::{
    Fault, HoldPoint, Rig, WireEvent, WorkReturn,
};
use dcentrald_hal::platform::stock_bm1396::Model;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[path = "../tests/sim_support/stratum_oracle.rs"]
mod independent_share;
use independent_share::{difficulty_one_target, StratumOracle};

static RUNTIME_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
// Production reserves through WorkerJoin at 34s; allow 2s outer scheduling.
const CLOSEOUT_BOUND: Duration = Duration::from_secs(36);

fn vectors(model: Model) -> Value {
    serde_json::from_str(match model {
        Model::T17e => include_str!("bm1396_mining_probe_vectors.json"),
        Model::S17e => include_str!("bm1396_s17e_probe_vectors.json"),
    })
    .unwrap()
}

fn notification_for_model(model: Model) -> (Value, String, Vec<u8>) {
    let vectors = vectors(model);
    let reference = vectors["cases"][0].clone();
    let header = hex::decode(reference["header_hex"].as_str().unwrap()).unwrap();
    let coinbase = hex::decode(reference["coinbase_hex"].as_str().unwrap()).unwrap();
    // Split only inside the actual scriptSig. A one-byte EN1 and initial
    // one-byte EN2=00 reconstruct the independently retained transaction.
    let en2_at = match model {
        Model::T17e => {
            assert_eq!(coinbase[41], 27);
            assert_eq!(&coinbase[59..61], &[0x43, 0]);
            60
        }
        Model::S17e => (43..42 + usize::from(coinbase[41]))
            .find(|&index| coinbase[index] == 0)
            .expect("fixture scriptSig zero"),
    };
    let en1 = hex::encode(&coinbase[en2_at - 1..en2_at]);
    let mut previous = header[4..36].to_vec();
    for word in previous.chunks_exact_mut(4) {
        word.reverse();
    }
    let scalar = |offset| {
        format!(
            "{:08x}",
            u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap())
        )
    };
    let notify = json!({"id":null,"method":"mining.notify","params":[
            "historical-fixed-header",hex::encode(previous),hex::encode(&coinbase[..en2_at-1]),hex::encode(&coinbase[en2_at+1..]),
            reference["merkle_branches"],scalar(0),scalar(72),scalar(68),true]});
    (notify, en1, header)
}

struct Pool {
    url: String,
    submissions: mpsc::Receiver<Value>,
    clean: mpsc::Sender<()>,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Pool {
    async fn start(model: Model) -> Self {
        let (notify, en1, _) = notification_for_model(model);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("stratum+tcp://{}", listener.local_addr().unwrap());
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let (submitted, submissions) = mpsc::channel(16);
        let (clean, mut clean_requests) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            let accepted = tokio::select! {
                _ = stopped.cancelled() => return Ok(()),
                accepted = listener.accept() => accepted?,
            };
            let (reader, mut writer) = accepted.0.into_split();
            let mut lines = BufReader::new(reader.take(65_536)).lines();
            let mut active_notify = notify.clone();
            loop {
                let line = tokio::select! {
                    _ = stopped.cancelled() => return Ok(()),
                    request = clean_requests.recv() => {
                        request.context("modeled clean command owner closed")?;
                        let mut changed = notify.clone();
                        changed["params"][0] = json!("new-clean-header");
                        active_notify = changed.clone();
                        writer.write_all((changed.to_string()+"\n").as_bytes()).await?;
                        continue;
                    }
                    line = lines.next_line() => line?,
                };
                let Some(line) = line else {
                    return Ok(());
                };
                let request: Value = serde_json::from_str(&line)?;
                let method = request["method"].as_str().unwrap_or("");
                let answer = match method {
                    "mining.subscribe" => json!([[], en1, 1]),
                    "mining.configure" => json!({"version-rolling":false}),
                    "mining.submit" => {
                        let oracle = StratumOracle::from_notify(
                            &active_notify,
                            &en1,
                            1,
                            "offline.complete-runtime",
                            difficulty_one_target(),
                        )
                        .map_err(anyhow::Error::msg)?;
                        let valid = oracle.accepts(&request["params"]);
                        submitted.send(request["params"].clone()).await?;
                        json!(valid)
                    }
                    _ => json!(true),
                };
                writer
                    .write_all(
                        (json!({"id":request["id"],"result":answer,"error":null}).to_string()
                            + "\n")
                            .as_bytes(),
                    )
                    .await?;
                if method == "mining.authorize" {
                    writer
                        .write_all(
                            b"{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[1]}\n",
                        )
                        .await?;
                    writer
                        .write_all((notify.to_string() + "\n").as_bytes())
                        .await?;
                }
            }
        });
        Self {
            url,
            submissions,
            clean,
            stop,
            task,
        }
    }
    async fn close(&mut self) -> Result<()> {
        self.stop.cancel();
        match tokio::time::timeout(Duration::from_secs(3), &mut self.task).await {
            Ok(result) => result.context("modeled pool task panicked")?,
            Err(_) => {
                self.task.abort();
                let _ = (&mut self.task).await;
                bail!("modeled pool failed bounded closeout")
            }
        }
    }
}

#[test]
fn bm1396_independent_pool_oracle_checks_both_complete_retained_headers() {
    for model in [Model::T17e, Model::S17e] {
        let (notify, en1, header) = notification_for_model(model);
        let oracle = StratumOracle::from_notify(
            &notify,
            &en1,
            1,
            "offline.complete-runtime",
            difficulty_one_target(),
        )
        .unwrap();
        let submitted = json!([
            "offline.complete-runtime",
            "historical-fixed-header",
            "00",
            format!(
                "{:08x}",
                u32::from_le_bytes(header[68..72].try_into().unwrap())
            ),
            format!(
                "{:08x}",
                u32::from_le_bytes(header[76..80].try_into().unwrap())
            ),
        ]);
        let reconstructed = oracle.reconstruct(&submitted).unwrap();
        assert_eq!(reconstructed.to_wire().as_slice(), header.as_slice());
        assert_eq!(
            hex::encode(reconstructed.display_hash()),
            vectors(model)["cases"][0]["header_hash"].as_str().unwrap()
        );
        assert!(oracle.accepts(&submitted));
        for (index, bad) in [
            (0, "foreign.worker"),
            (1, "stale-job"),
            (2, "0000"),
            (3, "00000000"),
            (4, "not-hex!"),
            (4, "00000000"),
        ] {
            let mut changed = submitted.clone();
            changed[index] = json!(bad);
            assert!(
                !oracle.accepts(&changed),
                "{model:?} accepted changed field{index}: {bad}"
            );
        }
        let mut extended = submitted.as_array().unwrap().clone();
        extended.push(json!("00000000"));
        assert!(
            !oracle.accepts(&json!(extended)),
            "version rolling is disabled"
        );
        let mut clean = notify.clone();
        clean["params"][0] = json!("new-clean-header");
        let renewed = StratumOracle::from_notify(
            &clean,
            &en1,
            1,
            "offline.complete-runtime",
            difficulty_one_target(),
        )
        .unwrap();
        assert!(!renewed.accepts(&submitted));
    }
}

fn configured(model: Model, url: String) -> (DcentraldConfig, Bm1396DispatchAdmission) {
    let (target, baked) = match model {
        Model::T17e => (
            "am2-t17e",
            include_str!("../../configs/beta/am2-t17e-baked-default.toml"),
        ),
        Model::S17e => (
            "am2-s17e",
            include_str!("../../configs/beta/am2-s17e-baked-default.toml"),
        ),
    };
    let mut config: DcentraldConfig = toml::from_str(baked).unwrap();
    config.pool.url = url;
    config.pool.worker = "offline.complete-runtime".into();
    config.donation.enabled = false;
    config.mining.enabled = true;
    config.api.http_bind = "127.0.0.1".into();
    config.api.http_port = 0;
    config.api.cgminer_port = 0;
    config.api.cgminer_bind_lan = false;
    config.validate().unwrap();
    let identity = crate::daemon_lifecycle::PlatformIdentitySnapshot {
        declared_board_target: Some(target.into()),
        observed_board_target: None,
        board_desc: dcentrald_common::BoardDesc::lookup(target),
        declared_platform_marker: Some("zynq-bm1396-stock".into()),
        declared_subtype: None,
        declared_psu_hardware_variant: None,
        observed_control_board: format!("explicit modeled {model:?} host rig"),
    };
    let protocol = crate::admit_board_desc_runtime_dispatch(
        identity.board_desc,
        crate::RuntimeDispatchKind::Bm1396Native,
        config.mining_start_enabled(),
        crate::configured_asic_protocol_identity(&config).unwrap(),
    )
    .unwrap()
    .require_asic_protocol(
        crate::RuntimeDispatchKind::Bm1396Native,
        identity.board_target(),
        dcentrald_common::AsicProtocolIdentity::Bm1396,
    )
    .unwrap();
    let admission = crate::bm1396_admission::admit(&identity, &config, protocol).unwrap();
    (config, admission)
}
fn work_script(model: Model) -> Vec<WorkReturn> {
    let vectors = vectors(model);
    [0usize, 1, 0]
        .into_iter()
        .enumerate()
        .map(|(id, index)| {
            let row = &vectors["cases"][index];
            let bytes = hex::decode(row["header_hex"].as_str().unwrap()).unwrap();
            WorkReturn {
                job_id: id as u32,
                version: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                ntime: u32::from_le_bytes(bytes[68..72].try_into().unwrap()),
                raw_nonce: u32::from_be_bytes(bytes[76..80].try_into().unwrap()),
            }
        })
        .collect()
}
async fn until(mut condition: impl FnMut() -> bool, duration: Duration) -> Result<()> {
    tokio::time::timeout(duration, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .context("modeled observation deadline elapsed")
}

struct Session {
    rig: Rig,
    stop: CancellationToken,
    state: watch::Receiver<dcentrald_api::MinerState>,
    watched: Arc<crate::runtime::safety_watchdog::bm1396_sim::Observation>,
    running: tokio::task::JoinHandle<Result<()>>,
    pool: Pool,
}
impl Session {
    async fn start(chains: Vec<u8>, hold: Option<HoldPoint>) -> Self {
        Self::start_model(Model::T17e, chains, hold).await
    }
    async fn start_model(model: Model, chains: Vec<u8>, hold: Option<HoldPoint>) -> Self {
        let pool = Pool::start(model).await;
        let (config, admission) = configured(model, pool.url.clone());
        let rig = Rig::observe_model(model, chains, work_script(model))
            .await
            .unwrap();
        if let Some(hold) = hold {
            rig.hardware.hold_next(hold);
        }
        let stop = CancellationToken::new();
        let liveness = SafetyLiveness::default();
        let (watchdog, watched) =
            crate::runtime::safety_watchdog::bm1396_sim::start(&config.watchdog, liveness.clone())
                .await
                .unwrap();
        let (state_tx, state) = watch::channel(dcentrald_api::MinerState::empty(
            dcentrald_api::OperatingMode::Standard,
        ));
        let running = tokio::spawn(run_owned(
            config,
            stop.clone(),
            Some(state_tx),
            admission,
            rig.owner.clone(),
            rig.line.clone(),
            rig.pic.clone(),
            watchdog,
            liveness,
            Instant::now(),
            Err("simulated runtime has no supervised process session".into()),
        ));
        Self {
            rig,
            stop,
            state,
            watched,
            running,
            pool,
        }
    }
    async fn actual_share(&mut self) -> Result<Value> {
        tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                ensure!(!self.running.is_finished(), "actual runtime ended before submit; terminal result retained below");
                tokio::select! {
                    submitted = self.pool.submissions.recv() => return submitted.context("modeled pool closed without actual submit"),
                    _ = tokio::time::sleep(Duration::from_millis(5)) => {}
                }
            }
        }).await.context("actual full runtime did not submit within startup fixture bound")?
    }
    async fn accepted(&self) -> Result<()> {
        until(
            || self.state.borrow().accepted > 0 || self.running.is_finished(),
            Duration::from_secs(5),
        )
        .await?;
        ensure!(
            self.state.borrow().accepted > 0,
            "actual accepted-share status was not published"
        );
        Ok(())
    }
    async fn close(&mut self) -> Result<Result<()>> {
        self.stop.cancel();
        self.rig.hardware.release_hold();
        let returned = tokio::time::timeout(CLOSEOUT_BOUND, &mut self.running).await;
        let pool = self.pool.close().await;
        if returned.is_err() {
            self.running.abort();
            let _ = (&mut self.running).await;
            bail!("actual runtime failed shared 34-second teardown schedule plus outer reserve; pool={pool:?}");
        }
        pool?;
        returned.unwrap().context("actual runtime task panicked")
    }
    fn high_events(&self) -> usize {
        self.rig
            .hardware
            .events()
            .iter()
            .filter(|event| matches!(event, WireEvent::Source { high: true, .. }))
            .count()
    }
    fn assert_closed(&self, returned: &Result<()>, reset_pending: bool) {
        let error = returned
            .as_ref()
            .expect_err("terminal result must retain its initiating reason");
        assert_eq!(
            crate::runtime::safety_watchdog::is_watchdog_reset_pending(error),
            reset_pending,
            "actual result: {error:#}"
        );
        assert!(self.rig.owner.is_terminal());
        assert_eq!(
            self.watched.closes(),
            usize::from(!reset_pending),
            "only actual complete terminal composition may disarm"
        );
        assert_eq!(
            self.watched.drops_armed(),
            0,
            "unresolved modeled descriptor retains reset custody"
        );
        assert!(self.watched.kicks() > 0);
        assert!(!self.rig.hardware.overflowed());
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.stop.cancel();
        self.rig.hardware.release_hold();
        self.pool.stop.cancel();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_full_startup_worker_registry_pool_share_and_shared_terminal_receipt() {
    let _serialized = RUNTIME_SERIAL.lock().await;
    let mut session = Session::start(vec![0, 2, 7], None).await;
    let outcome: Result<()> = async {
        let submitted = session.actual_share().await?;
        ensure!(
            submitted[0] == "offline.complete-runtime"
                && submitted[1] == "historical-fixed-header"
                && submitted[2] == "00"
        );
        let vectors: Value =
            serde_json::from_str(include_str!("bm1396_mining_probe_vectors.json"))?;
        let reference = &vectors["cases"][0];
        let header = hex::decode(reference["header_hex"].as_str().context("header")?)?;
        ensure!(submitted[3] == format!("{:08x}", u32::from_le_bytes(header[68..72].try_into()?)));
        ensure!(
            submitted[4]
                == format!(
                    "{:08x}",
                    reference["canonical_nonce"].as_u64().context("nonce")?
                )
        );
        session.accepted().await?;
        let actual = session
            .rig
            .pic
            .final_pll_observation()
            .map_err(anyhow::Error::msg)?
            .context("actual final observation")?;
        ensure!(
            actual.same_owner(&session.rig.owner) && actual.completed_frequency_mhz() == Some(300)
        );
        let events = session.rig.hardware.events();
        let high = events
            .iter()
            .find_map(|event| match event {
                WireEvent::Source { high: true, at } => Some(*at),
                _ => None,
            })
            .context("actual initial high")?;
        let low = events
            .iter()
            .find_map(|event| match event {
                WireEvent::Source { high: false, at } => Some(*at),
                _ => None,
            })
            .context("actual guarded low")?;
        ensure!(low.duration_since(high) >= Duration::from_secs(61));
        Ok(())
    }
    .await;
    let returned = session.close().await.unwrap();
    assert!(
        outcome.is_ok(),
        "fixture: {outcome:#?}; actual terminal: {returned:#?}"
    );
    session.assert_closed(&returned, false);
    assert!(session.rig.hardware.source_high());
    // The continuous worker owns its ASIC mutex until actual terminal drain.
    let publications = session.rig.owner.publications().unwrap();
    assert_eq!(
        publications
            .iter()
            .map(|row| row.job_id())
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(publications
        .iter()
        .all(|row| row.completed() && row.same_owner(&session.rig.owner)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s17e_actual_factory_startup_probes_pool_share_and_fixed_epoch_thermal_cutoff() {
    let _serialized = RUNTIME_SERIAL.lock().await;
    let mut session = Session::start_model(Model::S17e, vec![0, 2], None).await;
    let outcome: Result<()> = async {
        let submitted = session.actual_share().await?;
        ensure!(
            submitted[0] == "offline.complete-runtime"
                && submitted[1] == "historical-fixed-header"
                && submitted[2] == "00"
        );
        let reference = &vectors(Model::S17e)["cases"][0];
        let header = hex::decode(reference["header_hex"].as_str().context("header")?)?;
        ensure!(submitted[3] == format!("{:08x}", u32::from_le_bytes(header[68..72].try_into()?)));
        ensure!(submitted[4] == format!("{:08x}", u32::from_le_bytes(header[76..80].try_into()?)));
        session.accepted().await?;
        let actual = session
            .rig
            .pic
            .native_pll_observation()
            .map_err(anyhow::Error::msg)?
            .context("actual S17e completion")?;
        ensure!(
            actual.same_owner(&session.rig.owner)
                && actual.model() == Model::S17e
                && actual.epoch() == 0
                && actual.completed_frequency_mhz() == Some(310)
                && actual.timeout_base() == Some(380)
                && actual.operational_baud().baud() == 6_000_000
        );
        ensure!(session
            .rig
            .pic
            .adapted_startup_observation()
            .map_err(anyhow::Error::msg)?
            .is_none());
        ensure!(session
            .rig
            .pic
            .final_pll_observation()
            .map_err(anyhow::Error::msg)?
            .is_none());
        session.rig.hardware.inject(Fault::Hot);
        until(|| session.rig.owner.is_terminal(), Duration::from_secs(8)).await?;
        until(|| session.running.is_finished(), CLOSEOUT_BOUND).await?;
        Ok(())
    }
    .await;
    let returned = session.close().await.unwrap();
    assert!(
        outcome.is_ok(),
        "S17e fixture={outcome:#?}; actual terminal={returned:#?}"
    );
    session.assert_closed(&returned, false);
    assert!(format!("{:#}", returned.unwrap_err()).contains("cutoff"));
    assert!(session.rig.hardware.source_high());
    let publications = session.rig.owner.publications().unwrap();
    assert_eq!(
        publications.iter().map(|p| p.job_id()).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(publications
        .iter()
        .all(|p| p.completed() && p.same_owner(&session.rig.owner)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_during_real_supply_and_asic_workers_cuts_before_worker_release() {
    let _serialized = RUNTIME_SERIAL.lock().await;
    for point in [HoldPoint::Supply, HoldPoint::Asic] {
        let mut session = Session::start(vec![0], Some(point)).await;
        let outcome: Result<()> = async {
            until(
                || session.rig.hardware.hold_entered() || session.running.is_finished(),
                Duration::from_secs(120),
            )
            .await?;
            ensure!(
                session.rig.hardware.hold_entered(),
                "runtime must reach actual blocked worker"
            );
            let before = session.high_events();
            session.stop.cancel();
            until(|| session.high_events() > before, Duration::from_secs(3)).await?;
            ensure!(session.rig.hardware.source_high() && session.rig.owner.is_terminal());
            ensure!(
                !session.running.is_finished(),
                "worker stays retained during independent cutoff"
            );
            Ok(())
        }
        .await;
        let returned = session.close().await.unwrap();
        assert!(
            outcome.is_ok(),
            "fixture: {outcome:#?}; actual terminal: {returned:#?}"
        );
        // Cancellation inside the supply byte leaves the management parser
        // unresolved. The real fixed PIC-off path must refuse that parser, so
        // source-high and actual worker drain cannot authorize watchdog disarm.
        // An ASIC-only interruption leaves management available for fixed off.
        let reset_pending = matches!(point, HoldPoint::Supply);
        session.assert_closed(&returned, reset_pending);
        assert!(session.rig.hardware.source_high());
        assert!(session.rig.owner.publications().unwrap().is_empty());
        if reset_pending {
            let observed = session.rig.pic.supply_type_observation().unwrap().unwrap();
            // The sixth actual TX store is the held operation. It never gains
            // the post-store completion read after the terminal fence is set.
            assert_eq!(observed.completed_request_bytes(), 5);
            assert!(observed.response().is_empty());
            assert!(!observed.framing_complete() && observed.admitted_type().is_none());
            let events = session.rig.hardware.events();
            let pic_opcodes: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    WireEvent::Pic { opcode, .. } => Some(*opcode),
                    _ => None,
                })
                .collect();
            assert_eq!(pic_opcodes, vec![2]);
            assert!(!events
                .iter()
                .any(|event| matches!(event, WireEvent::Voltage { .. })));
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ActiveFault {
    Wire(Fault),
    CleanJob,
    Disconnect,
    WatchdogClose,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_active_faults_and_incomplete_teardown_preserve_watchdog_disposition() {
    let _serialized = RUNTIME_SERIAL.lock().await;
    for fault in [
        ActiveFault::Wire(Fault::Fan),
        ActiveFault::Wire(Fault::Hot),
        ActiveFault::Wire(Fault::Heartbeat),
        ActiveFault::Wire(Fault::Source),
        ActiveFault::Wire(Fault::AsicRead),
        ActiveFault::CleanJob,
        ActiveFault::Disconnect,
        ActiveFault::Wire(Fault::SourceCut),
        ActiveFault::Wire(Fault::PicOff),
        ActiveFault::WatchdogClose,
    ] {
        eprintln!("actual runtime fault scenario starting: {fault:?}");
        let mut session = Session::start(vec![0], None).await;
        let reset_pending = matches!(
            fault,
            ActiveFault::Wire(Fault::SourceCut | Fault::PicOff) | ActiveFault::WatchdogClose
        );
        let outcome: Result<()> = async {
            session.actual_share().await?;
            session.accepted().await?;
            match fault {
                ActiveFault::Wire(fault) => session.rig.hardware.inject(fault),
                ActiveFault::CleanJob => session.pool.clean.send(()).await?,
                ActiveFault::Disconnect => session.pool.stop.cancel(),
                ActiveFault::WatchdogClose => session.watched.refuse_close(),
            }
            if reset_pending {
                session.stop.cancel();
            }
            until(|| session.rig.owner.is_terminal(), Duration::from_secs(8)).await?;
            // Preserve the actual initiating fault before test cleanup sends
            // cancellation; the coordinator's biased shutdown branch must not
            // replace a still-pending source/worker/pool error with cancellation.
            until(|| session.running.is_finished(), CLOSEOUT_BOUND).await?;
            Ok(())
        }
        .await;
        let returned = session.close().await.unwrap();
        assert!(
            outcome.is_ok(),
            "{fault:?}: fixture={outcome:#?}; actual terminal={returned:#?}"
        );
        session.assert_closed(&returned, reset_pending);
        if !matches!(fault, ActiveFault::Wire(Fault::SourceCut)) {
            assert!(session.rig.hardware.source_high());
        }
        let error = format!("{:#}", returned.unwrap_err());
        let expected = match fault {
            ActiveFault::Wire(Fault::Fan) => "four source fan observations",
            ActiveFault::Wire(Fault::Hot) => "cutoff",
            ActiveFault::Wire(Fault::Heartbeat) => "PIC chain0 opcode16 response rejected",
            ActiveFault::Wire(Fault::Source) => "source is not observed low",
            ActiveFault::Wire(Fault::AsicRead) => "simulated ASIC FIFO read failure",
            ActiveFault::CleanJob => "active pool work was invalidated",
            ActiveFault::Disconnect => "authorized pool connection ended",
            ActiveFault::Wire(Fault::SourceCut | Fault::PicOff) | ActiveFault::WatchdogClose => {
                "watchdog"
            }
            ActiveFault::Wire(Fault::None) => unreachable!(),
        };
        // Either retained observation path can win the fan-fault race. Both
        // must report the injected cause; closeout assertions above still
        // require the same power cutoff and watchdog disposition.
        let cause_matches = error.contains(expected)
            || (matches!(fault, ActiveFault::Wire(Fault::Fan))
                && error.contains("BM1396 quiet30 requires four distinct fresh fans at400RPM"));
        assert!(
            cause_matches,
            "{fault:?} must retain its actual cause: {error}"
        );
        assert_eq!(
            session.rig.owner.publications().unwrap().len(),
            3,
            "terminal epoch cannot publish replacement work"
        );
        eprintln!("actual runtime fault scenario passed: {fault:?}");
    }
}
