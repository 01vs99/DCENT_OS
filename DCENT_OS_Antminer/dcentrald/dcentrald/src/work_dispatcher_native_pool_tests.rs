//! BM1387 chain/dispatcher spine. The outer Daemon, PIC and watchdog owners are
//! excluded; their safety publication is a test boundary, never a hardware claim.
use super::*;
use crate::asic_identity_publication::{
    DispatcherCompositionAuthority, EnumeratedMiningChainReceipt, ExpectedMiningChain,
};
use dcentrald_asic::chain::EnumerationCommandDialect;
use dcentrald_hal::platform::sim::{SimModel, SimNoncePolicy, TraceEvent};
use std::sync::{Mutex, RwLock};

#[path = "../tests/sim_support/share_oracle.rs"]
mod independent_pool;

fn initialize_s9_chains() -> (Vec<Chain>, Vec<EnumeratedMiningChainReceipt>) {
    let registry = ChipRegistry::production();
    let driver = registry.detect(0x1387).unwrap();
    let mut chains = Vec::new();
    let mut measured = Vec::new();
    for slot in 6..=8 {
        let mut chain = Chain::new(
            FpgaChain::open_sim_for_model(slot, SimModel::S9).unwrap(),
            slot,
        );
        let report = chain
            .enumerate_chips(EnumerationCommandDialect::Bm1387)
            .unwrap();
        let identity = report.measured_identity().unwrap();
        assert_eq!((identity.chip_id(), identity.chip_count()), (0x1387, 63));
        measured.push(EnumeratedMiningChainReceipt::from_successful_get_address(
            slot, identity,
        ));
        chain.assign_addresses().unwrap();
        chain.init_with_driver(driver, 500).unwrap();
        driver
            .send_open_core_work(&mut chain.fpga, chain.chip_count)
            .unwrap();
        assert_eq!(chain.address_plan().unwrap().chip_count(), 63);
        let init = chain.fpga.drain_sim_trace().unwrap();
        assert!(
            init.iter()
                .any(|event| matches!(event, TraceEvent::Work { .. })),
            "actual BM1387 open-core writes must execute"
        );
        assert!(
            init.iter()
                .any(|event| matches!(event, TraceEvent::Command { bytes, .. }
            if bytes == &[0x58, 0x09, 0, 0x0c])),
            "actual BM1387 PLL/register initialization must execute"
        );
        chain.frequency_mhz = 500;
        chain.voltage_mv = 9100;
        chain.mining = true;
        chains.push(chain);
    }
    (chains, measured)
}

async fn s9_dispatcher_pool(target: &'static str, model: &'static str) {
    let image =
        include_str!("../../../br2_external_dcentos/board/zynq/rootfs-overlay/etc/dcentrald.toml");
    let mut config: crate::config::DcentraldConfig = toml::from_str(image).unwrap();
    assert!(!config.mining.enabled);
    config.mining.model = Some(model.into());
    config.mining.enabled = true;
    // The real BM1387 four-midstate owner requires BIP310 negotiation.
    config.mining.version_rolling = true;
    config.donation.enabled = false;
    let spec = crate::model::lookup_model(config.mining.model.as_deref().unwrap()).unwrap();
    assert_eq!(spec.model_key, model);
    assert_eq!(spec.chip_id, Some(0x1387));
    assert_eq!(spec.chips_per_chain_hint, Some(63));
    let board = dcentrald_common::BoardDesc::lookup(target).unwrap();
    assert!(board.admits_standard_bm1387_runtime());
    assert_eq!(target, format!("am1-{model}"));

    let (chains, measured) = tokio::task::spawn_blocking(initialize_s9_chains)
        .await
        .unwrap();
    let observers: Vec<_> = chains
        .iter()
        .map(|chain| chain.fpga.sim_chain_observer().unwrap())
        .collect();
    // Only the first chain receives the known genesis work: the real dispatcher
    // generates different headers on the other chains instead of duplicating it.
    chains[0]
        .fpga
        .set_sim_next_nonce(independent_pool::winning_nonce("00"))
        .unwrap();
    chains[0]
        .fpga
        .set_sim_nonce_policy(SimNoncePolicy::Valid)
        .unwrap();
    let authority = DispatcherCompositionAuthority::default();
    let expected: Vec<_> = chains
        .iter()
        .map(|chain| ExpectedMiningChain {
            chain_id: chain.chain_id,
            chip_count: 63,
        })
        .collect();
    let hardware = Arc::new(Mutex::new(dcentrald_api::HardwareInfo::default()));
    let admitted = authority
        .activate_execution(
            ChipRegistry::production().admit(0x1387).unwrap(),
            expected,
            measured,
            hardware.clone(),
        )
        .unwrap();
    assert_eq!(hardware.lock().unwrap().chip_type, "BM1387");
    let publication = Arc::new(dcentrald_common::WorkDispatchAdmissionPublication::new());
    // This boundary selects the dispatcher only. Full daemon health/custody is
    // deliberately outside this test, just as the injected FPGA is host-only.
    publication.publish_admitted();
    let worker = format!("independent.{target}");
    let (address, pool) = independent_pool::OraclePool::spawn_version_rolling(&worker).await;
    config.pool.url = format!("stratum+tcp://{address}");
    config.pool.worker = worker.clone();
    config.validate().unwrap();
    let stratum = crate::config::build_stratum_config_with_enumerated_chips(
        &config,
        crate::config::stratum_donation_config(&config.donation),
        true,
        false,
        Some(189),
    );
    let (job_tx, job_rx) = mpsc::channel(8);
    let (share_tx, share_rx) = mpsc::channel(32);
    let (status_tx, _status_rx) = mpsc::channel(64);
    let (state_tx, _state_rx) = watch::channel(dcentrald_api::MinerState::empty(
        dcentrald_api::OperatingMode::Standard,
    ));
    let (sync_tx, _) = broadcast::channel(8);
    let (power_tx, _power_rx) = watch::channel(LivePowerEstimate::default());
    let stop = CancellationToken::new();
    let dispatcher = WorkDispatcher::new(
        job_rx,
        share_tx,
        state_tx,
        sync_tx,
        stop.clone(),
        worker,
        chains,
        admitted,
        publication.clone(),
        256,
        None,
        None,
        10,
        None,
        Arc::new(AtomicU32::new(40.0f32.to_bits())),
        Arc::new(AtomicBool::new(false)),
        (0..3)
            .map(|_| Arc::new(AtomicU32::new(40.0f32.to_bits())))
            .collect(),
        (0..3).map(|_| Arc::new(AtomicU32::new(1))).collect(),
        Arc::new(Instant::now()),
        None,
        power_tx,
        0.93,
        Arc::new(RwLock::new(PowerCalibration::default())),
        Arc::new(AtomicBool::new(false)),
        false,
    )
    .unwrap();
    let client = dcentrald_stratum::StratumV1Client::new(stratum, job_tx, share_rx, status_tx);
    let mut running = tokio::spawn(dispatcher.run());
    let outcome = tokio::time::timeout(Duration::from_secs(4), async {
        tokio::select! {
            result = async {
                while pool.accepted_shares() == 0 {
                    if running.is_finished() { return Err(anyhow::anyhow!("actual dispatcher ended before an accepted share")); }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Ok(())
            } => result,
            _ = client.run_until_sv2_retry(Duration::from_secs(3)) => Err(anyhow::anyhow!("pool client ended before dispatcher share")),
        }
    }).await;
    publication.publish_revoked();
    authority
        .invalidate_active_bounded(Duration::from_secs(1))
        .await
        .unwrap();
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(1), &mut running)
        .await
        .unwrap()
        .unwrap();
    let traces: Vec<_> = observers
        .iter()
        .map(|observer| observer.drain_trace().unwrap())
        .collect();
    let frames_per_chain: Vec<_> = traces
        .iter()
        .map(|trace| {
            trace
                .iter()
                .filter(|event| matches!(event, TraceEvent::Work { .. }))
                .count()
        })
        .collect();
    let outcome = outcome
        .map_err(anyhow::Error::from)
        .and_then(|result| result);
    assert!(
        outcome.is_ok(),
        "actual BM1387 dispatcher/pool: {outcome:?}; frames={frames_per_chain:?}; requests={:?}",
        pool.requests().iter().rev().take(6).collect::<Vec<_>>()
    );
    assert_eq!(pool.accepted_shares(), 1);
    assert!(!publication.allow_work_commit());
    let mut literal = Vec::new();
    for word in [0u32, 0x1d00ffff, 0x495fab29, 0x4a5e1e4b] {
        literal.extend_from_slice(&word.to_le_bytes());
    }
    for version in [1, 0x2001, 0x4001, 0x6001] {
        let mut header =
            independent_pool::header("00", independent_pool::winning_nonce("00")).unwrap();
        header.version = version;
        for word in header.midstate().chunks_exact(4).rev() {
            literal.extend_from_slice(&u32::from_be_bytes(word.try_into().unwrap()).to_le_bytes());
        }
    }
    for (index, trace) in traces.iter().enumerate() {
        let frames: Vec<_> = trace
            .iter()
            .filter_map(|event| match event {
                TraceEvent::Work { bytes, .. } => Some(bytes),
                _ => None,
            })
            .collect();
        assert!(
            !frames.is_empty(),
            "every initialized physical chain must receive actual work"
        );
        if index == 0 {
            assert_eq!(*frames[0], literal);
        } else {
            assert_ne!(
                *frames[0], literal,
                "dispatcher must not duplicate the first chain's header"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s9_native_chain_dispatcher_init_work_nonce_independent_pool() {
    s9_dispatcher_pool("am1-s9", "s9").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s9i_native_chain_dispatcher_init_work_nonce_independent_pool() {
    s9_dispatcher_pool("am1-s9i", "s9i").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s9j_native_chain_dispatcher_init_work_nonce_independent_pool() {
    s9_dispatcher_pool("am1-s9j", "s9j").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s9_dispatcher_missing_or_mismatched_observed_population_refuses_before_work() {
    for wrong_expected_count in [false, true] {
        let mut chains = Vec::new();
        let mut receipts = Vec::new();
        for slot in 6..=if wrong_expected_count { 8 } else { 7 } {
            let mut chain = Chain::new(
                FpgaChain::open_sim_for_model(slot, SimModel::S9).unwrap(),
                slot,
            );
            let report = chain
                .enumerate_chips(EnumerationCommandDialect::Bm1387)
                .unwrap();
            assert_eq!(report.measured_identity().unwrap().chip_count(), 63);
            receipts.push(EnumeratedMiningChainReceipt::from_successful_get_address(
                slot,
                report.measured_identity().unwrap(),
            ));
            chains.push(chain);
        }
        let authority = DispatcherCompositionAuthority::default();
        let result = authority.activate_execution(
            ChipRegistry::production().admit(0x1387).unwrap(),
            (6..=8)
                .map(|chain_id| ExpectedMiningChain {
                    chain_id,
                    // Actual enumeration returned 63; an expected 64 on the
                    // third chain must not be silently accepted as that model.
                    chip_count: if wrong_expected_count && chain_id == 8 {
                        64
                    } else {
                        63
                    },
                })
                .collect(),
            receipts,
            Arc::new(Mutex::new(dcentrald_api::HardwareInfo::default())),
        );
        assert!(result.is_err());
        for chain in chains {
            assert!(!chain
                .fpga
                .drain_sim_trace()
                .unwrap()
                .iter()
                .any(|event| matches!(event, TraceEvent::Work { .. })));
        }
    }
}
