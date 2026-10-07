use dcentrald_common::bm1393_native::{Bm1393Runtime, Bm1393State};
use dcentrald_hal::platform::c43_bm1393::{C43Bm1393Adapter, C43Custody};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    OnceLock,
};

// Explicit outer custody fixture: real retained fan/sensor and terminal-cut
// calls, but no Daemon, C43NativeMmio, XADC or external watchdog coverage.
#[derive(Default)]
struct OuterCustodyFixture {
    transport: OnceLock<Arc<C43Transport<FifoModel>>>,
    stopped: AtomicBool,
}
impl C43Custody<FifoModel> for OuterCustodyFixture {
    async fn start(
        &self,
        transport: Arc<C43Transport<FifoModel>>,
    ) -> std::result::Result<(), String> {
        self.transport
            .set(transport)
            .map_err(|_| "custody started twice")?;
        self.check_health().await
    }
    async fn check_health(&self) -> std::result::Result<(), String> {
        let transport = self.transport.get().ok_or("custody not started")?;
        let fans = transport.fan(30).await?;
        if fans.len() != 2 || fans.iter().any(|(_, rpm)| *rpm == 0) {
            return Err("C43 fixture fan stopped".into());
        }
        let samples = transport.temperatures().await?;
        if samples.iter().any(|s| {
            s.readings.len() != 2 || s.readings.iter().any(|(_, l, r)| *l != 40.0 || *r != 40.0)
        }) {
            return Err("C43 fixture sensor sample mismatch".into());
        }
        Ok(())
    }
    async fn stop(&self) -> std::result::Result<(), String> {
        let cut = self
            .transport
            .get()
            .ok_or("custody not started")?
            .terminal_cut()
            .await;
        if !cut.completed() {
            return Err(format!("C43 fixture cut unproven: {:?}", cut.errors()));
        }
        self.stopped.store(true, Ordering::Release);
        Ok(())
    }
}
type TestedC43Runtime = Bm1393Runtime<C43Bm1393Adapter<FifoModel, OuterCustodyFixture>>;
fn native_c43_owner(
    chains: Vec<u8>,
    fault: NativeFault,
) -> (Arc<FifoModel>, Arc<OuterCustodyFixture>, TestedC43Runtime) {
    let model = Arc::new(FifoModel(Mutex::new(FifoState {
        native: Some(Box::new(NativeRegisters::new(chains.clone(), fault))),
        ..Default::default()
    })));
    let transport = C43Transport::new(model.clone(), chains.clone()).unwrap();
    let custody = Arc::new(OuterCustodyFixture::default());
    let adapter = C43Bm1393Adapter::new(transport, custody.clone());
    let runtime = Bm1393Runtime::new(adapter, chains, 400, 9500).unwrap();
    (model, custody, runtime)
}

async fn c43_native_pool(target: &'static str, image: &'static str) {
    let mut config: crate::config::DcentraldConfig = toml::from_str(image).unwrap();
    let model_key = target.strip_prefix("am1-").unwrap();
    assert_eq!(config.mining.model.as_deref(), Some(model_key));
    let spec = crate::model::lookup_model(model_key).unwrap();
    assert_eq!(
        (spec.chip_id, spec.chips_per_chain_hint),
        (Some(0x1393), Some(60))
    );
    let board = dcentrald_common::BoardDesc::lookup(target).unwrap();
    assert_eq!(board.board_target, target);
    assert!(!board.admits_standard_bm1387_runtime());
    config.mining.enabled = true;
    config.mining.frequency_mhz = 400;
    config.mining.voltage_mv = 9500;
    config.donation.enabled = false;
    config.mining.version_rolling = false;

    let (model, custody, mut runtime) = native_c43_owner(vec![0, 1, 2], NativeFault::None);
    tokio::time::timeout(Duration::from_secs(120), runtime.start())
        .await
        .expect("C43 startup deadline")
        .unwrap();
    assert_eq!(runtime.state(), Bm1393State::Running);
    assert_eq!(runtime.active_chains(), [0, 1, 2]);
    {
        let state = model.0.lock().unwrap();
        let wire = state.native.as_ref().unwrap();
        assert_eq!(wire.factory_reads, [256; 3]);
        assert_eq!(wire.enabled, [true; 3]);
        assert!(wire.heartbeats.iter().all(|n| *n >= 5));
        assert_eq!(wire.dummy_count, [65; 3]);
        assert!(wire.work.is_empty());
        for addresses in &wire.assigned {
            assert_eq!(addresses, &(0..64u8).map(|i| i * 4).collect::<Vec<_>>());
        }
    }
    let worker = format!("independent.{target}");
    let (address, pool) = independent_pool::OraclePool::spawn(&worker).await;
    config.pool.url = format!("stratum+tcp://{address}");
    config.pool.worker = worker.clone();
    config.validate().unwrap();
    let stratum = crate::config::build_stratum_config_with_enumerated_chips(
        &config,
        crate::config::stratum_donation_config(&config.donation),
        false,
        false,
        Some(180),
    );
    let (job_tx, mut job_rx) = tokio::sync::mpsc::channel(8);
    let (share_tx, share_rx) = tokio::sync::mpsc::channel(8);
    let (status_tx, _status_rx) = tokio::sync::mpsc::channel(32);
    let client = dcentrald_stratum::StratumV1Client::new(stratum, job_tx, share_rx, status_tx);
    let lifecycle = async {
        let job = job_rx.recv().await.expect("actual C43 pool notification");
        let mut builder = dcentrald_stratum::WorkBuilder::new();
        let mut feeder = Feeder::new(runtime.active_chains());
        let batch = feeder.prepare(|| Ok(builder.next_work(&job)?)).unwrap();
        assert_eq!(batch.len(), 24);
        assert_eq!(&batch[0].1[2..], &C43_GENESIS_WORDS);
        assert!(
            feeder
                .ledgers
                .get_mut(&0)
                .unwrap()
                .validate(0, 0, 0x1dac2b7c, &worker)
                .is_none(),
            "uncommitted work acquired a share"
        );
        let accepted = runtime.submit_batch(batch).await.unwrap();
        assert_eq!(accepted, [true; 24]);
        feeder.commit(&accepted).unwrap();
        let returns = runtime.poll_returns().await.unwrap();
        assert_eq!(returns.len(), 1);
        for record in returns {
            let dcentrald_common::s9se_nonce::S9SeFifoRecord::Nonce {
                chain,
                work_id,
                nonce3,
            } = record
            else {
                panic!("expected wire nonce")
            };
            let ledger = feeder.ledgers.get_mut(&chain).unwrap();
            let share = ledger
                .validate(chain, work_id, nonce3, &worker)
                .expect("actual retained ledger accepts genesis");
            assert_eq!(share.nonce, "7c2bac1d");
            assert!(
                ledger.validate(chain, work_id, nonce3, &worker).is_none(),
                "duplicate nonce escaped ledger"
            );
            share_tx.send(share).await.unwrap();
        }
        while pool.accepted_shares() == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        feeder.invalidate();
        assert!(feeder
            .ledgers
            .get_mut(&0)
            .unwrap()
            .validate(0, 0, 0x1dac2b7c, &worker)
            .is_none());
    };
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            _ = lifecycle => (),
            _ = client.run_until_sv2_retry(Duration::from_secs(4)) => panic!("C43 client ended before accepted share"),
        }
    }).await;
    tokio::time::timeout(Duration::from_secs(20), runtime.shutdown())
        .await
        .expect("C43 shutdown deadline")
        .unwrap();
    outcome.expect("C43 independent pool deadline");
    assert_eq!(pool.accepted_shares(), 1);
    assert!(custody.stopped.load(Ordering::Acquire));
    assert!(runtime.submit_work(0, 1, &[0; 12], &[0; 32]).await.is_err());
    let state = model.0.lock().unwrap();
    let wire = state.native.as_ref().unwrap();
    assert_eq!(wire.enabled, [false; 3]);
    assert_eq!(wire.registers[&0x34] & 7, 7);
    assert_eq!(wire.work.len(), 24);
    assert_eq!(&wire.work[0][2..], &C43_GENESIS_WORDS);
    assert_eq!(
        wire.work
            .iter()
            .map(|w| w[2..].to_vec())
            .collect::<HashSet<_>>()
            .len(),
        24
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s9se_c43_chain_init_work_nonce_independent_pool() {
    c43_native_pool(
        "am1-s9se",
        include_str!("../../configs/beta/am1-s9se-baked-default.toml"),
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s9k_c43_chain_init_work_nonce_independent_pool() {
    c43_native_pool(
        "am1-s9k",
        include_str!("../../configs/beta/am1-s9k-baked-default.toml"),
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c43_factory_pic_population_sensor_faults_refuse_normal_work_and_cut() {
    for fault in [
        NativeFault::FactoryCrc,
        NativeFault::PicAck,
        NativeFault::MissingChip,
        NativeFault::MixedChip,
        NativeFault::SensorAck,
    ] {
        let (model, custody, mut runtime) = native_c43_owner(vec![0], fault);
        let started = tokio::time::timeout(Duration::from_secs(80), runtime.start())
            .await
            .expect("C43 refusal deadline");
        assert!(started.is_err(), "{fault:?} admitted");
        assert!(
            custody.stopped.load(Ordering::Acquire),
            "{fault:?} did not finish checked cut"
        );
        assert!(runtime.submit_work(0, 0, &[0; 12], &[0; 32]).await.is_err());
        let state = model.0.lock().unwrap();
        let wire = state.native.as_ref().unwrap();
        assert!(wire.work.is_empty(), "{fault:?} reached normal work");
        assert!(!wire.enabled[0]);
        assert_eq!(wire.registers[&0x34] & 1, 1);
        // Stock sensor calibration follows 13 dummy open-core frames. Those
        // are counted explicitly and never presented as pool mining work.
        assert_eq!(
            wire.dummy_count[0],
            if fault == NativeFault::SensorAck {
                13
            } else {
                0
            }
        );
    }
}
