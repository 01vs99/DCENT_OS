use super::*;
use dcentrald_common::{bm1396_contract::Bm1396Model, bm1396_work::bm1396_decode_nonce_record};
use dcentrald_stratum::work_domain::WorkGeneration;

#[test]
fn fixed_packets_match_complete_original_producer_bytes_and_crc() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("bm1396_mining_packet_vectors.json")).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let branches: Vec<[u8; 32]> = (0..case["merkle_count"].as_u64().unwrap())
            .map(|index| [0x40 + index as u8; 32])
            .collect();
        let previous: [u8; 32] = std::array::from_fn(|index| index as u8);
        let coinbase: Vec<u8> = (0..40).collect();
        let encoded = encode_fixed(
            0x12345678, 0x20000000, &previous, 0x65010203, 0x1d00ffff, &coinbase, 8, &branches,
        )
        .unwrap();
        assert_eq!(hex::encode(&encoded), case["packet_hex"].as_str().unwrap());
        let parsed = bm1396_parse_job_packet(&encoded).unwrap();
        assert_eq!(parsed.nonce2_size, 0);
        assert_eq!(parsed.block_version, 0x20);
        assert_eq!(parsed.nonce2_initial, 0x0f0e0d0c0b0a0908);
    }
}

#[test]
fn actual_historical_probes_join_complete_merkle_header_nonce_order_and_exact_return_context() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("bm1396_mining_probe_vectors.json")).unwrap();
    for (index, case) in vectors["cases"].as_array().unwrap().iter().enumerate() {
        let prepared = PreparedJob::known_probe(100 + index as u32, index).unwrap();
        let raw_nonce = case["raw_nonce"].as_u64().unwrap() as u32;
        let canonical_nonce = case["canonical_nonce"].as_u64().unwrap() as u32;
        let version = u32::from_le_bytes(prepared.header()[..4].try_into().unwrap());
        let mut record = [0; 8];
        record[0] = 0x82;
        record[4..].copy_from_slice(&raw_nonce.to_le_bytes());
        let decoded = bm1396_decode_nonce_record(Bm1396Model::T17e, &record).unwrap();
        assert_eq!(
            decoded.chip_ordinal,
            case["chip_ordinal"].as_u64().unwrap() as u16
        );
        assert_eq!(decoded.chain_slot, 2);
        let qualified = prepared
            .qualify_header(decoded.nonce, prepared.fixed_nonce2(), version.swap_bytes())
            .unwrap();
        assert_eq!(qualified.canonical_nonce, canonical_nonce);
        assert_eq!(
            hex::encode(qualified.header_hash_be),
            case["header_hash"].as_str().unwrap()
        );
        assert!(!qualified.meets_pool_target);
        assert!(prepared.pool().is_none());
        assert!(prepared
            .qualify_header(raw_nonce, prepared.fixed_nonce2() ^ 1, version.swap_bytes())
            .is_err());
        // A changed non-selector version byte is still a different header.
        assert!(prepared
            .qualify_header(
                raw_nonce,
                prepared.fixed_nonce2(),
                (version ^ 0x00100000).swap_bytes()
            )
            .is_err());
        assert!(prepared
            .qualify_header(raw_nonce ^ 1, prepared.fixed_nonce2(), version.swap_bytes())
            .is_err());
        assert!(prepared
            .qualify_header(
                canonical_nonce,
                prepared.fixed_nonce2(),
                version.swap_bytes()
            )
            .is_err());
    }
    assert!(PreparedJob::known_probe(1, 2).is_err());
}

#[test]
fn s17e_probes_bind_distinct_complete_headers_to_135_interval_one_geometry() {
    let mut headers = Vec::new();
    for (index, expected_address) in [78, 82].into_iter().enumerate() {
        let job =
            PreparedJob::known_probe_for_model(Bm1396Model::S17e, index as u32, index).unwrap();
        let nonce = u32::from_be_bytes(job.header()[76..80].try_into().unwrap());
        let mut raw = [0u8; 8];
        raw[0] = 0x80;
        raw[4..].copy_from_slice(&nonce.to_le_bytes());
        let decoded = bm1396_decode_nonce_record(Bm1396Model::S17e, &raw).unwrap();
        assert_eq!(decoded.chip_ordinal, expected_address);
        let version = u32::from_le_bytes(job.header()[..4].try_into().unwrap());
        let qualified = job
            .qualify_header(nonce, job.fixed_nonce2(), version.swap_bytes())
            .unwrap();
        assert!(qualified.header_hash_be[..4].iter().all(|byte| *byte == 0));
        assert!(job
            .qualify_header(nonce ^ 1, job.fixed_nonce2(), version.swap_bytes())
            .is_err());
        headers.push(*job.header());
    }
    assert_ne!(headers[0], headers[1]);
    let t17e_only = PreparedJob::known_probe(0, 0).unwrap();
    let mut raw = [0u8; 8];
    raw[0] = 0x80;
    let nonce = u32::from_be_bytes(t17e_only.header()[76..80].try_into().unwrap());
    raw[4..].copy_from_slice(&nonce.to_le_bytes());
    assert!(bm1396_decode_nonce_record(Bm1396Model::S17e, &raw).is_err());
}

#[test]
fn qualified_header_uses_full_pool_target_with_exact_boundary_and_stricter_negative() {
    let mut prepared = PreparedJob::known_probe(1, 0).unwrap();
    let version = u32::from_le_bytes(prepared.header[..4].try_into().unwrap());
    let raw_nonce = u32::from_be_bytes(prepared.header[76..].try_into().unwrap());
    let exact = prepared
        .qualify_header(raw_nonce, prepared.fixed_nonce2, version.swap_bytes())
        .unwrap()
        .header_hash_be;
    // This tests the immutable-header target gate only. It is not a V1 domain,
    // registry publication or forged permission to dispatch a pool template.
    prepared.pool = Some(MiningWork {
        work_generation: WorkGeneration { session: 9, job: 1 },
        midstates: Vec::new(),
        merkle4: prepared.header[64..68].try_into().unwrap(),
        ntime: u32::from_le_bytes(prepared.header[68..72].try_into().unwrap()),
        nbits: u32::from_le_bytes(prepared.header[72..76].try_into().unwrap()),
        job_id: "immutable-target-test".into(),
        extranonce2: "00".into(),
        version,
        version_mask: 0,
        share_target: exact,
        merkle_root: prepared.header[36..68].try_into().unwrap(),
        prev_block_hash: prepared.header[4..36].try_into().unwrap(),
    });
    assert!(
        prepared
            .qualify_header(raw_nonce, prepared.fixed_nonce2, version.swap_bytes())
            .unwrap()
            .meets_pool_target
    );
    let mut stricter = exact;
    for byte in stricter.iter_mut().rev() {
        if *byte != 0 {
            *byte -= 1;
            break;
        }
        *byte = 255;
    }
    prepared.pool.as_mut().unwrap().share_target = stricter;
    assert!(
        !prepared
            .qualify_header(raw_nonce, prepared.fixed_nonce2, version.swap_bytes())
            .unwrap()
            .meets_pool_target
    );
}

#[test]
fn payload_limits_include_crc_and_reject_incomplete_source_en2_window() {
    assert!(check_lengths(65_534, 0, 0).is_ok());
    for args in [
        (65_535, 0, 0),
        (40, 33, 0),
        (40, 0, 129),
        (65_530, 0, 1),
        (40, usize::MAX, 0),
        (usize::MAX, 0, 0),
    ] {
        assert!(check_lengths(args.0, args.1, args.2).is_err(), "{args:?}");
    }
}

#[tokio::test]
async fn real_v1_subscription_clones_and_notify_replays_share_the_original_finite_allocator() {
    use serde_json::{json, Value};
    use std::time::Duration;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
        sync::mpsc,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("stratum+tcp://{}", listener.local_addr().unwrap());
    let (notify_tx, mut notify_rx) = mpsc::channel::<(&'static str, &'static str)>(2);
    let mut server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let notification = |job: &str, ntime: &str| {
            json!({"id":null,"method":"mining.notify","params":[job,"00".repeat(32),
                format!("0100000001{}ffffffff05", "00".repeat(32)),
                "ffffffff010000000000000000015100000000",[],"20000000","1d00ffff",ntime,true]})
            .to_string()
                + "\n"
        };
        loop {
            tokio::select! {
                command = notify_rx.recv() => {
                    let Some((job, ntime)) = command else { break };
                    writer.write_all(notification(job, ntime).as_bytes()).await?;
                }
                line = lines.next_line() => {
                    let Some(line) = line? else { break };
                    let request: Value = serde_json::from_str(&line)?;
                    let method = request["method"].as_str().unwrap_or("");
                    let result = match method {
                        "mining.subscribe" => json!([[], "deadbeef", 1]),
                        "mining.configure" => json!({"version-rolling":false}),
                        _ => json!(true),
                    };
                    writer.write_all((json!({"id":request["id"],"result":result,"error":null})
                        .to_string()+"\n").as_bytes()).await?;
                    if method == "mining.authorize" {
                        writer.write_all(notification("A", "65010203").as_bytes()).await?;
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    let mut config: crate::config::DcentraldConfig = toml::from_str(include_str!(
        "../../configs/beta/am2-t17e-baked-default.toml"
    ))
    .unwrap();
    config.pool.url = url;
    config.pool.worker = "offline.fixed-domain".into();
    // Native catalog remains management-only; this is a loopback protocol
    // fixture and does not require or assert native mining admission.
    config.validate().unwrap();
    let pool = crate::config::build_stratum_config_with_enumerated_chips(
        &config,
        crate::config::stratum_donation_config(&config.donation),
        false,
        false,
        Some(78),
    );
    let (job_tx, mut job_rx) = mpsc::channel(16);
    let (share_tx, share_rx) = mpsc::channel(16);
    let (status_tx, _status_rx) = mpsc::channel(128);
    let mut client = tokio::spawn(
        dcentrald_stratum::v1::client::StratumV1Client::new(pool, job_tx, share_rx, status_tx)
            .run(),
    );
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        async fn next(jobs: &mut mpsc::Receiver<JobTemplate>) -> Result<JobTemplate> {
            loop {
                let job = jobs.recv().await.context("actual V1 job channel closed")?;
                if !job.is_flush_only() {
                    return Ok(job);
                }
            }
        }
        let first = next(&mut job_rx).await?;
        let mut one = WorkBuilder::new();
        let mut two = WorkBuilder::new();
        let a = PreparedJob::pool_job(&mut one, &first, 10)?;
        let b = PreparedJob::pool_job(&mut two, &first.clone(), 11)?;
        ensure!(a.pool().unwrap().extranonce2 == "00" && b.pool().unwrap().extranonce2 == "01");
        ensure!(a.header() != b.header() && a.fixed_nonce2() != b.fixed_nonce2());
        notify_tx.send(("B", "65010204")).await?;
        let second = next(&mut job_rx).await?;
        ensure!(second.work_generation.session == first.work_generation.session);
        ensure!(second.work_generation.job > first.work_generation.job);
        ensure!(PreparedJob::pool_job(&mut one, &first, 12).is_err());
        let c = PreparedJob::pool_job(&mut two, &second, 13)?;
        ensure!(c.pool().unwrap().extranonce2 == "02");
        notify_tx.send(("A", "65010203")).await?;
        let replay = next(&mut job_rx).await?;
        let d = PreparedJob::pool_job(&mut one, &replay, 14)?;
        ensure!(d.pool().unwrap().extranonce2 == "03" && d.header() != a.header());
        ensure!(PreparedJob::pool_job(&mut two, &second, 15).is_err());
        for issued in [&a, &b, &c, &d] {
            let parsed = bm1396_parse_job_packet(issued.packet()).unwrap();
            ensure!(parsed.job_id == issued.id() && parsed.nonce2_size == 0);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    // Always drain the actual network tasks before reporting any failure.
    drop(share_tx);
    let client_clean = tokio::time::timeout(Duration::from_secs(3), &mut client).await;
    if client_clean.is_err() {
        client.abort();
        let _ = client.await;
    }
    drop(notify_tx);
    let server_clean = tokio::time::timeout(Duration::from_secs(3), &mut server).await;
    if server_clean.is_err() {
        server.abort();
        let _ = server.await;
    }
    outcome.unwrap().unwrap();
    assert!(matches!(client_clean, Ok(Ok(()))));
    assert!(matches!(server_clean, Ok(Ok(Ok(())))));
}
