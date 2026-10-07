// Extends the retained PTY peer; all initialization and work transport run
// production owners. GPIO/PSU/watchdog coordination is outside this test.
async fn independent_native_population(target: &'static str, chip_id: u16, count: u8) {
    use dcentrald_common::AsicProtocolIdentity;
    let identity = match chip_id {
        0x1362 => AsicProtocolIdentity::Bm1362,
        0x1366 => AsicProtocolIdentity::Bm1366,
        0x1368 => AsicProtocolIdentity::Bm1368,
        0x1370 => AsicProtocolIdentity::Bm1370,
        _ => unreachable!(),
    };
    let frequency = if chip_id == 0x1370 { 480 } else { 400 };
    let stop = CancellationToken::new();
    let ready = Arc::new(AtomicU32::new(0));
    let peers: Vec<_> = (0..3)
        .map(|slot| {
            NativePeer::for_chip(
                slot,
                count,
                chip_id,
                PeerFault::None,
                ready.clone(),
                stop.clone(),
            )
        })
        .collect();
    let cold = if chip_id == 0x1362 {
        validate_native_cold_window(
            identity,
            &vec![vec![0x13, 0x62, 3, 0, 0, 0, 0x0d]; usize::from(count)],
        )
        .unwrap()
    } else {
        serial_window(chip_id, &vec![0; usize::from(count)])
    };
    let admission = ValidatedSerialChainAdmission::bind_route(
        serial_route_admission(target, identity),
        0,
        ROUTES[0].1,
        115_200,
        count,
        cold,
    )
    .unwrap();
    let (execution, terminal) =
        execution_fence_domain(SerialSessionToken::from_validated_for_test(&admission));
    let serial = ValidatedSerialBackend::new(
        SerialChainBackend::open(0, &peers[0].path, 115_200).unwrap(),
        execution,
    )
    .with_am2_energized_cancellation(stop.clone());
    let policy = IndustrialSerialPllPolicy::for_route(target, identity).unwrap();
    let (primary, geometry) = match identity {
        AsicProtocolIdentity::Bm1362 => SerialMiner::init_bm1362_aml_chain(
            serial,
            &peers[0].path,
            115_200,
            count,
            frequency,
            policy,
        ),
        AsicProtocolIdentity::Bm1366 => SerialMiner::init_bm1366_xp_chain(
            serial,
            &peers[0].path,
            115_200,
            count,
            frequency,
            policy,
        ),
        AsicProtocolIdentity::Bm1368 => SerialMiner::init_bm1368_chain(
            serial,
            &peers[0].path,
            115_200,
            count,
            frequency,
            policy,
        ),
        AsicProtocolIdentity::Bm1370 => SerialMiner::init_bm1370_chain(
            serial,
            &peers[0].path,
            115_200,
            count,
            frequency,
            policy,
        ),
        _ => unreachable!(),
    }
    .unwrap();
    let transport = modern_native_population::initialize(
        primary,
        &geometry,
        &ROUTES,
        identity,
        count,
        frequency,
        policy,
        9,
        &stop,
        None,
        || Ok(()),
        |slot, path| {
            assert_eq!(path, ROUTES[usize::from(slot)].1);
            Ok(SerialChainBackend::open(
                slot,
                &peers[usize::from(slot)].path,
                115_200,
            )?)
        },
    )
    .unwrap();
    assert_eq!(ready.load(Ordering::Acquire), 7);
    for peer in &peers {
        peer.assert_polling_mode();
        assert_eq!(
            peer.wire.lock().unwrap().addresses.len(),
            usize::from(count)
        );
        assert!(peer.wire.lock().unwrap().works.is_empty());
    }

    independent_retained_transport_pool(target, count, transport, &peers, terminal).await;
}

// The initializer and admission are supplied by each exact owner test; only
// the independent pool/serialized work oracle is shared between native routes.
async fn independent_retained_transport_pool(
    target: &'static str,
    count: u8,
    transport: SerialWorkTransport,
    peers: &[NativePeer],
    terminal: SerialExecutionTerminal,
) {
    let worker = format!("independent.{target}");
    let (address, pool) = pool_oracle::OraclePool::spawn(&worker).await;
    let mut config = crate::config::DcentraldConfig::management_only_default();
    config.pool.url = format!("stratum+tcp://{address}");
    config.pool.worker = worker.clone();
    config.donation.enabled = false;
    let stratum = crate::config::build_stratum_config_with_enumerated_chips(
        &config,
        crate::config::stratum_donation_config(&config.donation),
        false,
        false,
        Some(u32::from(count) * 3),
    );
    let (job_tx, mut job_rx) = mpsc::channel(8);
    let (share_tx, share_rx) = mpsc::channel(8);
    let (status_tx, _status_rx) = mpsc::channel(32);
    let client = dcentrald_stratum::StratumV1Client::new(stratum, job_tx, share_rx, status_tx);
    let lifecycle = async {
        let job = job_rx.recv().await.expect("real pool job");
        let work = dcentrald_stratum::WorkBuilder::new()
            .next_work(&job)
            .unwrap();
        let header = pool_oracle::header(
            &work.extranonce2,
            pool_oracle::winning_nonce(&work.extranonce2),
        )
        .unwrap();
        assert_eq!(work.midstates[0], header.midstate());
        assert_eq!(work.share_target, pool_oracle::target());
        let entry = WorkEntry {
            generation: 1,
            work_generation: work.work_generation,
            job_id: work.job_id.clone(),
            extranonce2: work.extranonce2.clone(),
            ntime: work.ntime,
            nbits: work.nbits,
            version: work.version,
            version_mask: 0,
            share_target: work.share_target,
            prev_block_hash: work.prev_block_hash,
            merkle_root: work.merkle_root,
        };
        let bytes = serial_full_header_work(
            0,
            entry.version,
            entry.nbits,
            entry.ntime,
            &entry.merkle_root,
            &entry.prev_block_hash,
        );
        // Independent literal genesis UART payload in the retained full-header
        // 21/56 layout: nonce placeholder, nBits, time, reversed Merkle words,
        // previous hash, version. A broken production serializer must fail
        // before the peer's known nonce can make a submission appear valid.
        let literal = hex::decode(concat!(
            "2156000100000000ffff001d29ab5f49",
            "4b1e5e4a3a9fb8aa888a51327fc81bc367768f617ac72c3e7a7b12b23ba3edfd",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "01000000"
        ))
        .unwrap();
        assert_eq!(
            bytes, literal,
            "actual ASIC work must match the independent complete header"
        );
        let sent = transport.send_work_with_receipt(&bytes);
        assert!(sent.error.is_none());
        assert!(sent.receipt.all_required_committed());
        let mut observed_paths = BTreeSet::new();
        while observed_paths.len() < 3 {
            if let Some(body) = transport.read_nonce_response().unwrap() {
                let nonce = u32::from_le_bytes(body[..4].try_into().unwrap());
                let reconstructed = serial_build_header(&entry, entry.version, nonce);
                assert_eq!(reconstructed, header.to_wire());
                assert!(dcentrald_stratum::share_pipeline::validate_full_header(
                    &reconstructed,
                    &entry.share_target
                ));
                assert!(observed_paths.insert(transport.last_rx_path().unwrap()));
                // Identical work may return the same winning nonce on each
                // UART. Submit it once; observing the other paths proves RX,
                // not three distinct pool shares.
                if observed_paths.len() == 1 {
                    share_tx
                        .send(dcentrald_stratum::types::ValidShare {
                            work_generation: entry.work_generation,
                            worker_name: worker.clone(),
                            job_id: entry.job_id.clone(),
                            extranonce2: entry.extranonce2.clone(),
                            ntime: format!("{:08x}", entry.ntime),
                            nonce: format!("{nonce:08x}"),
                            version_bits: None,
                            version: entry.version,
                            achieved_difficulty: None,
                        })
                        .await
                        .unwrap();
                }
            } else {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        while pool.accepted_shares() < 1 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            observed_paths,
            ROUTES.iter().map(|(_, path)| *path).collect()
        );
        let _fenced = terminal.revoke();
        assert!(transport.send_work_with_receipt(&bytes).error.is_some());
        assert!(transport.read_nonce_response().is_err());
        for peer in peers {
            let wire = peer.wire.lock().unwrap();
            assert_eq!(wire.works.len(), 1);
            assert_eq!(&wire.works[0][..84], bytes);
        }
    };
    tokio::time::timeout(Duration::from_secs(4), async {
        tokio::select! {
            _ = lifecycle => (),
            _ = client.run_until_sv2_retry(Duration::from_secs(3)) => panic!("pool client ended before accepted UART returns"),
        }
    }).await.expect("independent UART submission deadline");
    assert_eq!(pool.accepted_shares(), 1);
}

macro_rules! native_beta_pool_test {
    ($name:ident, $target:literal, $chip:literal, $count:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            independent_native_population($target, $chip, $count).await;
        }
    };
}
native_beta_pool_test!(
    am3_s19jproa_native_init_work_nonce_independent_pool,
    "am3-s19jproa",
    0x1362,
    126
);
native_beta_pool_test!(
    am3_s19jproplus_native_init_work_nonce_independent_pool,
    "am3-s19jproplus",
    0x1362,
    120
);
native_beta_pool_test!(
    am3_s19xp_native_init_work_nonce_independent_pool,
    "am3-s19xp",
    0x1366,
    110
);
native_beta_pool_test!(
    am3_s19jxp_native_init_work_nonce_independent_pool,
    "am3-s19jxp",
    0x1366,
    110
);
native_beta_pool_test!(
    am3_s21_native_init_work_nonce_independent_pool,
    "am3-s21",
    0x1368,
    108
);
native_beta_pool_test!(
    am3_s21pro_native_init_work_nonce_independent_pool,
    "am3-s21pro",
    0x1370,
    65
);
native_beta_pool_test!(
    am3_s21xp_native_init_work_nonce_independent_pool,
    "am3-s21xp",
    0x1370,
    91
);
