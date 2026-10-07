// AM2 uses its distinct BM1362 initializer and single retained serial owner.
// Outer AM2 PIC/APW/reset/watchdog custody is explicitly outside these tests.
fn am2_test_backend(slot: u8, path: &str) -> (ValidatedSerialBackend, SerialExecutionTerminal) {
    use dcentrald_common::AsicProtocolIdentity;
    let admission = ValidatedSerialChainAdmission::bind_route(
        serial_route_admission("am2-s19j", AsicProtocolIdentity::Bm1362),
        slot,
        ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"][usize::from(slot)],
        115_200,
        126,
        validate_native_cold_window(
            AsicProtocolIdentity::Bm1362,
            &vec![vec![0x13, 0x62, 3, 0, 0, 0, 0x0d]; 126],
        )
        .unwrap(),
    )
    .unwrap();
    let (execution, terminal) =
        execution_fence_domain(SerialSessionToken::from_validated_for_test(&admission));
    let backend = ValidatedSerialBackend::new(
        SerialChainBackend::open_native_linux_only(slot, path, 115_200).unwrap(),
        execution,
    )
    .with_am2_energized_cancellation(CancellationToken::new());
    backend
        .commit("AM2 PTY polling mode", || {
            backend.backend.set_vtime(0).map_err(anyhow::Error::from)
        })
        .unwrap();
    (backend, terminal)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn am2_s19j_distinct_native_init_work_nonce_independent_pool() {
    let ready = Arc::new(AtomicU32::new(0));
    let peers: Vec<_> = (0..3)
        .map(|slot| {
            NativePeer::for_chip(
                slot,
                126,
                0x1362,
                PeerFault::None,
                ready.clone(),
                CancellationToken::new(),
            )
        })
        .collect();
    let mut retained = Vec::new();
    for (slot, peer) in peers.iter().enumerate() {
        let (backend, terminal) = am2_test_backend(slot as u8, peer.path());
        // The actual PTY path avoids the optional Braiins diagnostic UIO probe.
        // Admission above retains the exact logical AM2 slot and identity.
        let (backend, geometry) =
            SerialMiner::init_bm1362_chain(backend, peer.path(), 115_200, 126, 525).unwrap();
        assert_eq!(
            geometry.identity,
            dcentrald_common::AsicProtocolIdentity::Bm1362
        );
        assert_eq!(geometry.observed_chip_count.get(), 126);
        assert_eq!(geometry.applied_frequency_mhz, 525);
        assert_eq!(
            geometry.addresses,
            (0..126u8).map(|i| i * 2).collect::<Vec<_>>()
        );
        backend.set_response_len(9);
        // This distinct initializer retains the kernel UART's100ms timeout;
        // the actual route transfers it directly after setting response length.
        peer.assert_read_timeout(1);
        assert!(peer.work_frames().is_empty());
        retained.push((SerialWorkTransport::Validated(backend), terminal));
    }
    assert_eq!(ready.load(Ordering::Acquire), 7);
    for (slot, (transport, terminal)) in retained.into_iter().enumerate() {
        let spec = crate::model::Model::S19jProAm2.spec();
        assert_eq!(
            (spec.model_key, spec.chip_id, spec.chips_per_chain_hint),
            ("s19jproam2", Some(0x1362), Some(126))
        );
        let worker = format!("independent.am2-s19j.{slot}");
        let (address, pool) = pool_oracle::OraclePool::spawn(&worker).await;
        let mut config = crate::config::DcentraldConfig::management_only_default();
        config.mining.model = Some(spec.model_key.into());
        config.mining.enabled = true;
        config.mining.frequency_mhz = 525;
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
        let lifecycle = async {
            let job = job_rx.recv().await.expect("actual AM2 pool job");
            let work = dcentrald_stratum::WorkBuilder::new()
                .next_work(&job)
                .unwrap();
            let header = pool_oracle::header(
                &work.extranonce2,
                pool_oracle::winning_nonce(&work.extranonce2),
            )
            .unwrap();
            let entry = WorkEntry {
                generation: 1,
                work_generation: work.work_generation,
                job_id: work.job_id,
                extranonce2: work.extranonce2,
                ntime: work.ntime,
                nbits: work.nbits,
                version: work.version,
                version_mask: 0,
                share_target: work.share_target,
                prev_block_hash: work.prev_block_hash,
                merkle_root: work.merkle_root,
            };
            assert_eq!(work.midstates[0], header.midstate());
            assert_eq!(entry.share_target, pool_oracle::target());
            let frame = serial_full_header_work(
                0,
                entry.version,
                entry.nbits,
                entry.ntime,
                &entry.merkle_root,
                &entry.prev_block_hash,
            );
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
            let sent = transport.send_work_with_receipt(&frame);
            assert!(sent.error.is_none() && sent.receipt.all_required_committed());
            loop {
                if let Some(body) = transport.read_nonce_response().unwrap() {
                    let nonce = u32::from_le_bytes(body[..4].try_into().unwrap());
                    let reconstructed = serial_build_header(&entry, entry.version, nonce);
                    assert_eq!(reconstructed, header.to_wire());
                    assert!(dcentrald_stratum::share_pipeline::validate_full_header(
                        &reconstructed,
                        &entry.share_target
                    ));
                    share_tx
                        .send(dcentrald_stratum::types::ValidShare {
                            work_generation: entry.work_generation,
                            worker_name: worker.clone(),
                            job_id: entry.job_id,
                            extranonce2: entry.extranonce2,
                            ntime: format!("{:08x}", entry.ntime),
                            nonce: format!("{nonce:08x}"),
                            version_bits: None,
                            version: entry.version,
                            achieved_difficulty: None,
                        })
                        .await
                        .unwrap();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            while pool.accepted_shares() == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let _fenced = terminal.clone().revoke();
            assert!(transport.send_work_with_receipt(&frame).error.is_some());
            assert!(transport.read_nonce_response().is_err());
            assert_eq!(peers[slot].work_frames().len(), 1);
            assert_eq!(&peers[slot].work_frames()[0][..84], frame);
        };
        let outcome = tokio::time::timeout(Duration::from_secs(4), async {
            tokio::select! {
                _ = lifecycle => (),
                _ = client.run_until_sv2_retry(Duration::from_secs(3)) => panic!("AM2 client ended before pool acceptance"),
            }
        }).await;
        let _fenced = terminal.revoke();
        drop(transport);
        outcome.expect("AM2 pool deadline");
        assert_eq!(pool.accepted_shares(), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn am2_s19j_missing_assigned_chip_refuses_native_work() {
    let ready = Arc::new(AtomicU32::new(0));
    let peer = NativePeer::for_chip(
        0,
        126,
        0x1362,
        PeerFault::MissingAssignedChip,
        ready.clone(),
        CancellationToken::new(),
    );
    let (backend, terminal) = am2_test_backend(0, peer.path());
    let initialized = SerialMiner::init_bm1362_chain(backend, peer.path(), 115_200, 126, 525);
    let _fenced = terminal.revoke();
    assert!(initialized.is_err());
    assert_eq!(ready.load(Ordering::Acquire), 0);
    assert!(peer.work_frames().is_empty());
}
