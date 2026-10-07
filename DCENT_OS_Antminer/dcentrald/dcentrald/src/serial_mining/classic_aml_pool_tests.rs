// Reuse the existing retained UART peer. These tests run the classic initializer,
// Uarts custody, ledger/nonce qualification and outbox, not the power coordinator.
use crate::serial_mining::tests::modern_native_population_tests::{NativePeer, PeerFault};
use std::sync::atomic::AtomicU32;

fn classic_pool_uart(slot: u8, path: &str) -> (Arc<Uarts>, SerialExecutionTerminal) {
    let (execution, terminal) = execution_fence_domain(SerialSessionToken {
        _run_scope: crate::runtime::safety_watchdog::WatchdogRunScope::new(),
        route: ExactSerialRoute::ClassicAml,
        descriptor: SerialSessionDescriptor {
            board_target: TARGET,
            identity: dcentrald_common::AsicProtocolIdentity::Bm1362,
            active_slot: slot,
            serial_device: path.into(),
            configured_chip_count: 126,
            industrial_pll_policy: Some(POLICY),
        },
    });
    let uarts = Arc::new(Uarts::default());
    uarts.backends.lock().unwrap().insert(
        slot,
        Arc::new(
            ValidatedSerialBackend::new(
                SerialChainBackend::open_native_linux_only(slot, path, 115_200).unwrap(),
                execution,
            )
            .with_classic_aml_cancellation(CancellationToken::new()),
        ),
    );
    (uarts, terminal)
}

async fn initialize_classic_pool_uart(uarts: &Arc<Uarts>, slot: u8, path: String) -> Result<()> {
    uarts
        .blocking(move |owned| {
            let backend = owned.backend(slot)?;
            backend.commit("classic test retained polling setup", || {
                backend.backend.set_vtime(0).map_err(anyhow::Error::from)
            })?;
            let geometry = SerialMiner::init_bm1362_aml_chain_retained(
                &backend, &path, 115_200, 126, 400, POLICY,
            )?;
            backend.set_response_len(9);
            owned.retain_geometry(slot, geometry)?;
            let observed = owned.observed_geometry(&[slot])?;
            anyhow::ensure!(
                observed
                    == [ObservedChain {
                        slot,
                        chips: 126,
                        frequency_mhz: 400
                    }]
            );
            owned.initialize_work(&[slot])
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classic_aml_each_retained_route_init_work_nonce_independent_pool() {
    let ready = Arc::new(AtomicU32::new(0));
    let stop = CancellationToken::new();
    let peers: Vec<_> = (0..3)
        .map(|slot| {
            NativePeer::for_chip(
                slot,
                126,
                0x1362,
                PeerFault::None,
                ready.clone(),
                stop.clone(),
            )
        })
        .collect();
    let mut retained = Vec::new();
    // Each supported one-board route uses its own real retained owner. Separate
    // upstream sessions allow the literal genesis header on every route without
    // defeating classic Ledger's cross-chain duplicate-header prohibition.
    for (slot, peer) in peers.iter().enumerate() {
        let (uarts, terminal) = classic_pool_uart(slot as u8, peer.path());
        initialize_classic_pool_uart(&uarts, slot as u8, peer.path().into())
            .await
            .unwrap();
        peer.assert_polling_mode();
        assert_eq!(
            peer.assigned_addresses(),
            (0..126u8).map(|id| id * 2).collect::<Vec<_>>()
        );
        assert!(peer.work_frames().is_empty());
        retained.push((uarts, terminal));
    }
    assert_eq!(ready.load(Ordering::Acquire), 7);

    for (slot, (uarts, terminal)) in retained.into_iter().enumerate() {
        let slot = slot as u8;
        let worker = format!("independent.classic-aml.{slot}");
        let (address, pool) = independent_pool::OraclePool::spawn(&worker).await;
        let image = include_str!("../../../../br2_external_dcentos/board/amlogic/am3-s19jpro-aml/rootfs-overlay/etc/dcentrald.toml");
        let mut config: DcentraldConfig = toml::from_str(image).unwrap();
        config.mining.enabled = true;
        config.pool.url = format!("stratum+tcp://{address}");
        config.pool.worker = worker.clone();
        config.donation.enabled = false;
        validate_config(
            &config,
            TARGET,
            dcentrald_common::AsicProtocolIdentity::Bm1362,
            400,
        )
        .unwrap();
        let stratum = crate::config::build_stratum_config_with_enumerated_chips(
            &config,
            crate::config::stratum_donation_config(&config.donation),
            false,
            false,
            Some(126),
        );
        let (job_tx, mut job_rx) = tokio::sync::mpsc::channel(8);
        let (share_tx, share_rx) = tokio::sync::mpsc::channel(8);
        let (status_tx, _status_rx) = tokio::sync::mpsc::channel(32);
        let client = dcentrald_stratum::StratumV1Client::new(stratum, job_tx, share_rx, status_tx);
        let lifecycle = async {
            let job = job_rx
                .recv()
                .await
                .expect("actual classic pool notification");
            let work = dcentrald_stratum::WorkBuilder::new()
                .next_work(&job)
                .unwrap();
            let header = independent_pool::header(
                &work.extranonce2,
                independent_pool::winning_nonce(&work.extranonce2),
            )
            .unwrap();
            assert_eq!(work.midstates[0], header.midstate());
            assert_eq!(work.share_target, independent_pool::target());
            let prepared = uarts
                .work(|owned| {
                    owned.activate(work.work_generation)?;
                    owned.ledger.prepare(slot, work)
                })
                .unwrap();
            let frame = prepared.frame().to_vec();
            assert_eq!(
                frame,
                hex::decode(concat!(
                    "2156000100000000ffff001d29ab5f49",
                    "4b1e5e4a3a9fb8aa888a51327fc81bc367768f617ac72c3e7a7b12b23ba3edfd",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "01000000"
                ))
                .unwrap()
            );
            // A valid nonce cannot acquire publication rights before physical TX.
            uarts
                .work(|owned| {
                    owned.qualify(slot, &[0x1d, 0xac, 0x2b, 0x7c, 0, 0, 0, 0, 0x90], &worker)?;
                    anyhow::ensure!(owned.outbox.is_empty());
                    Ok(())
                })
                .unwrap();
            let sent = frame.clone();
            uarts
                .blocking(move |owned| {
                    let backend = owned.backend(slot)?;
                    backend.commit("classic test physical work commit", || {
                        owned.require_geometry(slot)?;
                        backend
                            .backend
                            .send_work(&sent)
                            .map_err(anyhow::Error::from)
                    })?;
                    owned.work(|work| work.ledger.commit(prepared))
                })
                .await
                .unwrap();
            while pool.accepted_shares() == 0 {
                let worker = worker.clone();
                let output = share_tx.clone();
                uarts
                    .blocking(move |owned| {
                        if let Some(body) = owned.backend(slot)?.read_nonce_response()? {
                            owned.work(|work| work.qualify(slot, &body, &worker))?;
                        }
                        owned.work(|work| {
                            work.flush(&output)?;
                            work.ledger.require_liveness()
                        })
                    })
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(peers[usize::from(slot)].work_frames().len(), 1);
            assert_eq!(&peers[usize::from(slot)].work_frames()[0][..84], frame);
            let _fenced = terminal.clone().revoke();
            assert!(uarts
                .backend(slot)
                .unwrap()
                .commit("revoked classic work", || {
                    uarts
                        .backend(slot)?
                        .backend
                        .send_work(&frame)
                        .map_err(anyhow::Error::from)
                })
                .is_err());
        };
        let outcome = tokio::time::timeout(Duration::from_secs(4), async {
            tokio::select! {
                _ = lifecycle => (),
                _ = client.run_until_sv2_retry(Duration::from_secs(3)) => panic!("classic pool client ended before accepted share"),
            }
        }).await;
        let _fenced = terminal.revoke();
        uarts
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        outcome.expect("classic independent pool deadline");
        assert_eq!(pool.accepted_shares(), 1);
        assert!(uarts.backends.lock().unwrap().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classic_aml_missing_assigned_chip_refuses_work_publication() {
    let ready = Arc::new(AtomicU32::new(0));
    let peer = NativePeer::for_chip(
        0,
        126,
        0x1362,
        PeerFault::MissingAssignedChip,
        ready.clone(),
        CancellationToken::new(),
    );
    let (uarts, terminal) = classic_pool_uart(0, peer.path());
    let initialized = initialize_classic_pool_uart(&uarts, 0, peer.path().into()).await;
    let _fenced = terminal.revoke();
    uarts
        .close_until(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert!(initialized.is_err());
    assert_eq!(ready.load(Ordering::Acquire), 0);
    assert!(uarts.observed_geometry(&[0]).is_err());
    assert!(uarts.work(|_| Ok(())).is_err());
    assert!(peer.work_frames().is_empty());
}
