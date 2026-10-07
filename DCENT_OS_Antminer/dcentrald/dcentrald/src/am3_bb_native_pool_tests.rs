// Actual kernel-UART initializer, Am335x transport and BB header/nonce owners.
// Outer PSU/PIC/GPIO/thermal/watchdog loop is excluded. Initialization reports
// configured assignments and raw liveness, never an observed unique-chip count.
use crate::serial_mining::{NativeSimPeer, NativeSimPeerFault};
use std::sync::atomic::AtomicU32;

fn bb_native_uarts_after_factory(
    pages: &[Vec<u8>],
    peers: &[NativeSimPeer],
) -> Result<Vec<Am3BbChainUart>> {
    let probes = collect_am3_bb_eeprom_probes(0, peers.len(), 126, |slot| Ok(pages[slot].clone()))?;
    require_am3_bb_eeprom_family(&probes, peers.len())?;
    let mut uarts = Vec::new();
    for (slot, peer) in peers.iter().enumerate() {
        let backend = SerialChainBackend::open_native_linux_only(slot as u8, peer.path(), 115_200)?;
        backend.set_vtime(0)?;
        let mut uart = Am3BbChainUart::Kernel(backend);
        let initialized =
            bm1362_chip_init_one_chain(&mut uart, slot, 3_000_000, 0x3011, false, 126, 400, true)?;
        assert_eq!(initialized.assigned_chips, 126); // assignment intent only
        assert!(initialized.rx_proven()); // raw liveness, not unique coverage
        assert!(initialized.initial_get_address_observation.is_some());
        assert!(initialized.fast_get_address_rx_bytes > 0);
        assert_eq!(
            peer.assigned_addresses(),
            (0..126u8).map(|i| i * 2).collect::<Vec<_>>()
        );
        peer.assert_polling_mode();
        assert!(peer.work_frames().is_empty());
        uarts.push(uart);
    }
    Ok(uarts)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bb_s19jpro_factory_kernel_init_transport_nonce_independent_pool() {
    let platform = test_platform();
    let specs = chain_uart_specs(&platform);
    assert_eq!(
        specs.iter().map(|s| s.device.as_str()).collect::<Vec<_>>(),
        ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS4"]
    );
    assert_eq!(
        resolve_am3_bb_chips_per_chain(Some("s19jpro"), Some("bm1362"), None).unwrap(),
        126
    );
    let ready = Arc::new(AtomicU32::new(0));
    let peers: Vec<_> = (0..3)
        .map(|slot| {
            NativeSimPeer::for_chip(
                slot,
                126,
                0x1362,
                NativeSimPeerFault::None,
                ready.clone(),
                CancellationToken::new(),
            )
        })
        .collect();
    let pages: Vec<_> = ["BHB42601", "BHB42603", "BHB42621"]
        .iter()
        .map(|name| bb_synthetic_identity_page(name, "L1C021CK11", None))
        .collect();
    let uarts = bb_native_uarts_after_factory(&pages, &peers).unwrap();
    assert_eq!(ready.load(Ordering::Acquire), 7);
    // Each initialized UART gets its own upstream session, preserving distinct
    // pool work domains when the fixed genesis vector is replayed on each port.
    for (slot, uart) in uarts.into_iter().enumerate() {
        let worker = format!("independent.am3-bb-s19jpro.{slot}");
        let (address, pool) = independent_pool::OraclePool::spawn(&worker).await;
        let mut config = DcentraldConfig::management_only_default();
        config.mining.model = Some("s19jpro".into());
        config.mining.frequency_mhz = 400;
        config.mining.version_rolling = false;
        config.pool.url = format!("stratum+tcp://{address}");
        config.pool.worker = worker.clone();
        config.donation.enabled = false;
        config.validate().unwrap();
        let stratum = crate::config::build_stratum_config_with_enumerated_chips(
            &config,
            crate::config::stratum_donation_config(&config.donation),
            false,
            false,
            Some(126),
        );
        let (job_tx, mut job_rx) = mpsc::channel(8);
        let (share_tx, share_rx) = mpsc::channel(8);
        let (status_tx, _status_rx) = mpsc::channel(32);
        let client = dcentrald_stratum::StratumV1Client::new(stratum, job_tx, share_rx, status_tx);
        let mut transport = Am335xUartTransport::new(vec![uart], UART_SEND_INTERVAL_US);
        let mut bookkeeping =
            dcentrald_common::SerialWorkBookkeeping::<DispatchedWork>::with_depth_and_cursor(
                WORK_HISTORY_PER_ECHOED_JOB_ID,
                dcentrald_common::AsicJobIdCursor::serial_mining(JOB_ID_INCREMENT),
            );
        let lifecycle = async {
            let job = job_rx.recv().await.expect("actual BB pool notification");
            let work = dcentrald_stratum::WorkBuilder::new()
                .next_work(&job)
                .unwrap();
            let reference = independent_pool::header(
                &work.extranonce2,
                independent_pool::winning_nonce(&work.extranonce2),
            )
            .unwrap();
            assert_eq!(work.midstates[0], reference.midstate());
            assert_eq!(work.share_target, independent_pool::target());
            let id = bookkeeping.job_ids.current();
            assert_eq!(id, 0);
            let frame = build_bm1362_serial_work_frame(&work, id);
            assert_eq!(
                &frame[2..86],
                hex::decode(concat!(
                    "2156000100000000ffff001d29ab5f49",
                    "4b1e5e4a3a9fb8aa888a51327fc81bc367768f617ac72c3e7a7b12b23ba3edfd",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "01000000"
                ))
                .unwrap()
            );
            assert!(bookkeeping.history.is_empty_slot(id));
            assert!(transport.try_send_raw(0, &frame, id, 0).unwrap());
            bookkeeping.history.push(
                echoed_job_id(id),
                DispatchedWork {
                    work_generation: work.work_generation,
                    job_id: work.job_id,
                    extranonce2: work.extranonce2,
                    ntime: work.ntime,
                    nbits: work.nbits,
                    version: work.version,
                    version_mask: work.version_mask,
                    prev_block_hash: work.prev_block_hash,
                    merkle_root: work.merkle_root,
                    share_target: work.share_target,
                },
            );
            assert_eq!(bookkeeping.job_ids.take_and_advance(), id);
            assert!(
                !transport.try_send_raw(0, &frame, id, 0).unwrap(),
                "actual pacing failed"
            );
            loop {
                let returned = transport.recv_bm1362_serial_nonces();
                if returned.is_empty() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                }
                assert_eq!(returned.len(), 1);
                let (chain, nonce) = &returned[0];
                assert_eq!(*chain, 0);
                assert_ne!(nonce.flags & 0x80, 0);
                assert_eq!(nonce.job_id, echoed_job_id(id));
                let retained = bookkeeping
                    .history
                    .iter_newest_first(nonce.job_id)
                    .next()
                    .unwrap();
                let version = rolled_version_checked(
                    retained.version,
                    retained.version_mask,
                    nonce.version_bits_raw,
                )
                .unwrap();
                let header = retained.full_header(version, nonce.nonce);
                assert_eq!(header, reference.to_wire());
                assert!(dcentrald_stratum::share_pipeline::validate_full_header(
                    &header,
                    &retained.share_target
                ));
                let (current, _, _, rejects) =
                    am3_bb_replay_bm1362_nonce_decodes(std::iter::once(retained), nonce);
                assert_eq!(rejects, 0);
                assert_eq!(current.unwrap().nonce_submit, nonce.nonce);
                assert!(bookkeeping
                    .seen
                    .insert(nonce.job_id, nonce.nonce, nonce.version_bits_raw));
                assert!(!bookkeeping.seen.insert(
                    nonce.job_id,
                    nonce.nonce,
                    nonce.version_bits_raw
                ));
                share_tx
                    .send(dcentrald_stratum::types::ValidShare {
                        work_generation: retained.work_generation,
                        worker_name: worker.clone(),
                        job_id: retained.job_id.clone(),
                        extranonce2: retained.extranonce2.clone(),
                        ntime: format!("{:08x}", retained.ntime),
                        nonce: format!("{:08x}", nonce.nonce),
                        version_bits: dcentrald_stratum::work::bip310_version_bits(
                            version,
                            retained.version_mask,
                        ),
                        version,
                        achieved_difficulty: am3_bb_achieved_difficulty_from_header(&header),
                    })
                    .await
                    .unwrap();
                break;
            }
            while pool.accepted_shares() == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        let outcome = tokio::time::timeout(Duration::from_secs(4), async {
            tokio::select! {
                _ = lifecycle => (),
                _ = client.run_until_sv2_retry(Duration::from_secs(3)) => panic!("BB client ended before accepted share"),
            }
        }).await;
        transport.clean_work();
        bookkeeping.on_clean_jobs();
        assert!(bookkeeping.history.is_empty_slot(0));
        drop(transport);
        outcome.expect("BB pool deadline");
        assert_eq!(pool.accepted_shares(), 1);
        assert_eq!(peers[slot].work_frames().len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bb_bad_factory_crc_refuses_before_native_uart_initialization() {
    let ready = Arc::new(AtomicU32::new(0));
    let peers = [NativeSimPeer::for_chip(
        0,
        126,
        0x1362,
        NativeSimPeerFault::None,
        ready.clone(),
        CancellationToken::new(),
    )];
    let pages = [bb_synthetic_identity_page(
        "BHB42601",
        "L1C021CK11",
        Some(1),
    )];
    assert!(bb_native_uarts_after_factory(&pages, &peers).is_err());
    assert_eq!(ready.load(Ordering::Acquire), 0);
    assert!(peers[0].assigned_addresses().is_empty());
    assert!(peers[0].work_frames().is_empty());
}
