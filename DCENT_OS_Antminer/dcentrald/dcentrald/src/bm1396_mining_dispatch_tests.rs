//! Actual consumer transitions use sealed public HAL receipts and the existing
//! registry fixture. These do not simulate or bypass final-startup admission:
//! a queued control acknowledgment is explicitly not native worker completion.
use super::*;
use crate::bm1396_mining_work::{registry::ShareDisposition, test_support::*};
use dcentrald_hal::platform::stock_bm1396::PicApplication;
use dcentrald_stratum::work_domain::WorkGeneration;
use std::sync::atomic::Ordering;

fn input_channels() -> (
    mpsc::Sender<JobTemplate>,
    mpsc::Receiver<JobTemplate>,
    mpsc::Sender<StratumStatus>,
    mpsc::Receiver<StratumStatus>,
    watch::Sender<Option<ThermalSnapshot>>,
) {
    let (jt, jr) = mpsc::channel(16);
    let (st, sr) = mpsc::channel(128);
    (jt, jr, st, sr, watch::channel(None).0)
}
fn flush() -> JobTemplate {
    JobTemplate {
        work_generation: WorkGeneration { session: 0, job: 0 },
        v1_work_domain: None,
        job_id: String::new(),
        prev_block_hash: [0; 32],
        coinbase1: vec![],
        coinbase2: vec![],
        merkle_branches: vec![],
        version: 0,
        nbits: 0,
        ntime: 0,
        clean_jobs: true,
        share_target: [0; 32],
        extranonce1: vec![],
        extranonce2_size: 1,
        version_mask: 0,
        merkle_root: [0; 32],
        pool_difficulty: 0.0,
    }
}

#[tokio::test]
async fn actual_completed_publications_and_all_chain_headers_drive_two_probe_sequence() {
    let (memory, owner, mut registry) = fixture().await;
    let pic = PicApplication::claim(owner.clone()).unwrap();
    let (control, _events, _health, _inbox) = pic.fixed_work_channels();
    let (_jt, mut jobs, _st, mut statuses, thermal) = input_channels();
    let mut input = Inputs::new(deadline());
    let mut builder = WorkBuilder::new();
    issue(
        &mut registry,
        &control,
        &mut input,
        PreparedJob::known_probe(0, 0).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(input.pending_publication, Some(0));
    assert_eq!(registry.lifetime_jobs(), 1);
    for index in 0..2 {
        let expected = PreparedJob::known_probe(index as u32, index).unwrap();
        let actual = owner
            .publish_job(expected.packet().to_vec(), false, 400, deadline())
            .await
            .unwrap();
        input
            .consume_event(
                &mut registry,
                &control,
                FixedWorkEvent::Publication(actual),
                &mut jobs,
                &mut statuses,
                &thermal,
            )
            .await
            .unwrap();
        assert_eq!(input.pending_publication, None);
        for chain in [0, 2] {
            input
                .advance(&mut registry, &control, &mut builder)
                .await
                .unwrap();
            assert_eq!(registry.lifetime_jobs(), index + 1);
            let raw = emit(&memory, &owner, &expected, chain, 0).await;
            input
                .consume_event(
                    &mut registry,
                    &control,
                    FixedWorkEvent::Return(raw),
                    &mut jobs,
                    &mut statuses,
                    &thermal,
                )
                .await
                .unwrap();
        }
        assert!(registry.probe_complete(index as u32));
        input
            .advance(&mut registry, &control, &mut builder)
            .await
            .unwrap();
        if index == 0 {
            assert_eq!(input.pending_publication, Some(1));
        }
    }
    assert_eq!(input.progress.phase, DispatchPhase::WaitingForPool);
    assert_eq!(registry.lifetime_jobs(), 2);
    assert!(registry.probes_complete());
    assert_eq!(registry.retained_returns().len(), 4);
    // Four exact acks were queued but no continuous worker was started in this
    // component test. The actual raw producer still retains all four records.
    assert_eq!(owner.pending_returns().unwrap().len(), 4);
    assert!(control
        .enqueue_publication(
            PreparedJob::known_probe(2, 0).unwrap().packet().to_vec(),
            Instant::now() + Duration::from_millis(20)
        )
        .await
        .unwrap_err()
        .contains("queue deadline"));
    assert_eq!(owner.publications().unwrap().len(), 2);
    owner.drain(deadline()).await.unwrap();
}

#[tokio::test]
async fn foreign_partial_and_unexpected_actual_publications_preserve_pending_daemon_custody() {
    for defect in 0..3 {
        let (memory, owner, mut registry) = fixture().await;
        let pic = PicApplication::claim(owner.clone()).unwrap();
        let (control, _events, _health, _inbox) = pic.fixed_work_channels();
        let (_jt, mut jobs, _st, mut statuses, thermal) = input_channels();
        let mut input = Inputs::new(deadline());
        issue(
            &mut registry,
            &control,
            &mut input,
            PreparedJob::known_probe(0, 0).unwrap(),
        )
        .await
        .unwrap();
        let charge = registry.charged_bytes();
        let foreign = fixture().await;
        let actual = match defect {
            0 => foreign
                .1
                .publish_job(
                    PreparedJob::known_probe(0, 0).unwrap().packet().to_vec(),
                    false,
                    400,
                    deadline(),
                )
                .await
                .unwrap(),
            1 => {
                memory.corrupt.store(true, Ordering::SeqCst);
                owner
                    .publish_job(
                        PreparedJob::known_probe(0, 0).unwrap().packet().to_vec(),
                        false,
                        400,
                        deadline(),
                    )
                    .await
                    .unwrap_err();
                owner.publications().unwrap().pop().unwrap()
            }
            2 => owner
                .publish_job(
                    PreparedJob::known_probe(1, 1).unwrap().packet().to_vec(),
                    false,
                    400,
                    deadline(),
                )
                .await
                .unwrap(),
            _ => unreachable!(),
        };
        let error = input
            .consume_event(
                &mut registry,
                &control,
                FixedWorkEvent::Publication(actual),
                &mut jobs,
                &mut statuses,
                &thermal,
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            if defect == 2 {
                "BM1396 completed publication is not the daemon's pending issued packet"
            } else {
                "BM1396 publication is foreign or incomplete"
            }
        );
        assert_eq!(input.pending_publication, Some(0));
        assert_eq!(registry.lifetime_jobs(), 1);
        assert_eq!(registry.charged_bytes(), charge);
        assert_eq!(registry.retained_returns().len(), 0);
        owner.drain(deadline()).await.unwrap();
        foreign.1.drain(deadline()).await.unwrap();
    }
}

#[tokio::test]
async fn closed_and_cancelled_full_request_queues_keep_original_issued_packet_without_publication()
{
    for closed in [true, false] {
        let (_memory, owner, mut registry) = fixture().await;
        let pic = PicApplication::claim(owner.clone()).unwrap();
        let (control, _events, _health, inbox) = pic.fixed_work_channels();
        let mut retained_inbox = Some(inbox);
        if closed {
            drop(retained_inbox.take());
        } else {
            for _ in 0..8 {
                control
                    .enqueue_publication(
                        PreparedJob::known_probe(0, 0).unwrap().packet().to_vec(),
                        deadline(),
                    )
                    .await
                    .unwrap();
            }
        }
        let mut input = Inputs::new(deadline());
        let result = tokio::time::timeout(
            Duration::from_millis(30),
            issue(
                &mut registry,
                &control,
                &mut input,
                PreparedJob::known_probe(0, 0).unwrap(),
            ),
        )
        .await;
        if closed {
            assert_eq!(
                result.unwrap().unwrap_err().to_string(),
                "BM1396 actual work owner closed"
            );
        } else {
            assert!(
                result.is_err(),
                "full original request queue must still own the waiter"
            );
        }
        assert_eq!(registry.lifetime_jobs(), 1);
        assert_eq!(input.pending_publication, Some(0));
        assert!(registry.charged_bytes() > 0);
        assert!(owner.publications().unwrap().is_empty());
        let charge = registry.charged_bytes();
        assert_eq!(
            issue(
                &mut registry,
                &control,
                &mut input,
                PreparedJob::known_probe(1, 1).unwrap()
            )
            .await
            .unwrap_err()
            .to_string(),
            "BM1396 daemon publication already pending"
        );
        assert_eq!(registry.charged_bytes(), charge);
        assert_eq!(registry.lifetime_jobs(), 1);
        owner.drain(deadline()).await.unwrap();
    }
}

#[tokio::test]
async fn actual_cpu_share_is_retired_before_submit_on_flush_or_authorized_disconnect() {
    for disconnect in [false, true] {
        let (memory, owner, mut registry) = fixture().await;
        probes(&memory, &owner, &mut registry).await;
        let generation = WorkGeneration { session: 9, job: 3 };
        registry.set_active_generation(Some(generation));
        let prepared = publish(
            &owner,
            &mut registry,
            pool_fixture(2, generation, [255; 32]),
        )
        .await;
        let pic = PicApplication::claim(owner.clone()).unwrap();
        let (control, _events, _health, _inbox) = pic.fixed_work_channels();
        let (_jt, mut jobs, _st, mut statuses, thermal) = input_channels();
        let mut input = Inputs::new(deadline());
        input.pool_issued = true;
        input
            .status(
                &mut registry,
                StratumStatus::StateChanged(StratumState::Authorized),
            )
            .unwrap();
        let raw = emit(&memory, &owner, &prepared, 0, 0).await;
        input
            .consume_event(
                &mut registry,
                &control,
                FixedWorkEvent::Return(raw),
                &mut jobs,
                &mut statuses,
                &thermal,
            )
            .await
            .unwrap();
        assert_eq!(registry.retained_returns().len(), 5);
        let error = if disconnect {
            input.status(
                &mut registry,
                StratumStatus::StateChanged(StratumState::Disconnected),
            )
        } else {
            input.job(&mut registry, flush())
        }
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            if disconnect {
                "BM1396 authorized pool connection ended; disconnect hashing is disabled"
            } else {
                "BM1396 active pool work was invalidated; terminal epoch required"
            }
        );
        let (tx, mut rx) = mpsc::channel(1);
        assert!(registry.offer_head(&tx).unwrap());
        assert!(rx.try_recv().is_err());
        assert_eq!(
            registry
                .retained_returns()
                .last()
                .unwrap()
                .share_disposition,
            Some(ShareDisposition::RetiredGeneration)
        );
        assert_eq!(owner.pending_returns().unwrap().len(), 1);
        owner.drain(deadline()).await.unwrap();
    }
}

#[tokio::test]
async fn actual_status_queue_controls_authorization_failures_and_bounded_service() {
    for defect in 0..4 {
        let (_memory, owner, mut registry) = fixture().await;
        let mut input = Inputs::new(deadline());
        let (_jt, mut jobs, st, mut statuses, _thermal) = input_channels();
        st.send(StratumStatus::StateChanged(StratumState::Connecting))
            .await
            .unwrap();
        input
            .drain(&mut registry, &mut jobs, &mut statuses)
            .unwrap();
        assert!(!input.ever_authorized);
        st.send(StratumStatus::StateChanged(StratumState::Authorized))
            .await
            .unwrap();
        let selected = match defect {
            0 => StratumStatus::StateChanged(StratumState::AuthFailed),
            1 => StratumStatus::StateChanged(StratumState::Donating),
            2 => StratumStatus::StateChanged(StratumState::Disconnected),
            3 => StratumStatus::StateChanged(StratumState::Connecting),
            _ => unreachable!(),
        };
        st.send(selected).await.unwrap();
        let error = input
            .drain(&mut registry, &mut jobs, &mut statuses)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            match defect {
                0 => "BM1396 pool authorization failed",
                1 => "BM1396 qualified candidate does not admit donation work",
                _ => "BM1396 authorized pool connection ended; disconnect hashing is disabled",
            }
        );
        assert!(input.ever_authorized);
        assert!(input.latest.is_none());
        assert_eq!(registry.lifetime_jobs(), 0);
        assert!(owner.publications().unwrap().is_empty());
        owner.drain(deadline()).await.unwrap();
    }
}

#[tokio::test]
async fn actual_v1_authorization_namespace_pool_publication_and_clean_flush_join_consumer() {
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
    let (status_tx, mut status_rx) = mpsc::channel(128);
    let mut client = tokio::spawn(
        dcentrald_stratum::v1::client::StratumV1Client::new(pool, job_tx, share_rx, status_tx)
            .run(),
    );
    let (memory, owner, mut registry) = fixture().await;
    probes(&memory, &owner, &mut registry).await;
    let pic = PicApplication::claim(owner.clone()).unwrap();
    let (control, _events, _health, _inbox) = pic.fixed_work_channels();
    let thermal = watch::channel(None).0;
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        let mut input = Inputs::new(deadline());
        while input.latest.is_none() {
            input.drain(&mut registry, &mut job_rx, &mut status_rx)?;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        ensure!(input.ever_authorized);
        let actual = input.latest.take().context("actual V1 notify missing")?;
        ensure!(actual.v1_work_domain.as_ref().unwrap().generation() == actual.work_generation);
        let mut builder = WorkBuilder::new();
        let prepared = PreparedJob::pool_job(&mut builder, &actual, registry.next_id()?)?;
        ensure!(prepared.pool().unwrap().extranonce2 == "00");
        input.pool_issued = true;
        let issued = issue(&mut registry, &control, &mut input, prepared).await?;
        let original_packet = issued.packet().to_vec();
        ensure!(input.pending_publication == Some(2));
        let publication = owner
            .publish_job(issued.packet().to_vec(), false, 400, deadline())
            .await
            .map_err(anyhow::Error::msg)?;
        input
            .consume_event(
                &mut registry,
                &control,
                FixedWorkEvent::Publication(publication),
                &mut job_rx,
                &mut status_rx,
                &thermal,
            )
            .await?;
        ensure!(
            input.progress.phase == DispatchPhase::PoolWork && input.pending_publication.is_none()
        );
        notify_tx.send(("B", "65010204")).await?;
        let error = loop {
            match input.drain(&mut registry, &mut job_rx, &mut status_rx) {
                Ok(()) => {
                    ensure!(
                        input.latest.as_ref().is_none_or(|job| !job.clean_jobs),
                        "actual V1 clean notify was retained after active pool publication"
                    );
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                Err(error) => break error,
            }
        };
        ensure!(
            error.to_string() == "BM1396 active pool work was invalidated; terminal epoch required"
        );
        ensure!(registry.lifetime_jobs() == 3 && issued.packet() == original_packet);
        ensure!(
            input.latest.is_none(),
            "invalidating notify cannot replace retained metadata"
        );
        ensure!(owner.publications().map_err(anyhow::Error::msg)?.len() == 3);
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
    owner.drain(deadline()).await.unwrap();
    outcome.unwrap().unwrap();
    assert!(matches!(client_clean, Ok(Ok(()))));
    assert!(matches!(server_clean, Ok(Ok(Ok(())))));
}

#[tokio::test]
async fn actual_input_bursts_stream_closure_and_precancel_have_finite_custody() {
    for defect in 0..4 {
        let (_memory, owner, mut registry) = fixture().await;
        let mut input = Inputs::new(deadline());
        let (jt, mut jobs) = mpsc::channel(32);
        let (st, mut statuses) = mpsc::channel(256);
        let mut jt = Some(jt);
        let mut st = Some(st);
        match defect {
            0 => {
                for _ in 0..129 {
                    st.as_ref()
                        .unwrap()
                        .send(StratumStatus::PoolMessage("actual queue item".into()))
                        .await
                        .unwrap();
                }
            }
            1 => {
                for _ in 0..17 {
                    jt.as_ref().unwrap().send(flush()).await.unwrap();
                }
            }
            2 => {
                drop(st.take());
            }
            3 => {
                drop(jt.take());
            }
            _ => unreachable!(),
        }
        let error = input
            .drain(&mut registry, &mut jobs, &mut statuses)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            match defect {
                0 => "BM1396 Stratum status burst exceeded bounded service turn",
                1 => "BM1396 notify burst exceeded bounded service turn",
                2 => "BM1396 Stratum status owner closed",
                3 => "BM1396 Stratum job owner closed",
                _ => unreachable!(),
            }
        );
        if defect == 0 {
            assert_eq!(statuses.len(), 1);
        }
        if defect == 1 {
            assert_eq!(jobs.len(), 1);
        }
        assert_eq!(registry.lifetime_jobs(), 0);
        assert!(owner.publications().unwrap().is_empty());
        owner.drain(deadline()).await.unwrap();
    }
    let (_memory, owner, mut registry) = fixture().await;
    let pic = PicApplication::claim(owner.clone()).unwrap();
    let (control, mut events, _health, _inbox) = pic.fixed_work_channels();
    let (_jt, mut jobs, _st, mut statuses, thermal) = input_channels();
    let (shares, _received) = mpsc::channel(1);
    let (progress, _observed) = watch::channel(DispatchProgress::default());
    let stop = CancellationToken::new();
    stop.cancel();
    let error = dispatch(
        &owner,
        &mut registry,
        &control,
        &mut events,
        &mut jobs,
        &mut statuses,
        &shares,
        &thermal,
        &progress,
        &stop,
        deadline(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(error, "BM1396 work dispatch cancelled before first issue");
    assert_eq!(registry.lifetime_jobs(), 0);
    assert!(owner.publications().unwrap().is_empty());
    owner.drain(deadline()).await.unwrap();
}

#[tokio::test]
async fn original_launch_deadline_bounds_entry_first_pool_receipts_and_full_request_waits() {
    let (_memory, owner, mut registry) = fixture().await;
    let pic = PicApplication::claim(owner.clone()).unwrap();
    let (control, mut events, _health, _inbox) = pic.fixed_work_channels();
    let (_jt, mut jobs, _st, mut statuses, thermal) = input_channels();
    let (shares, _received) = mpsc::channel(1);
    let (progress, _observed) = watch::channel(DispatchProgress::default());
    let error = dispatch(
        &owner,
        &mut registry,
        &control,
        &mut events,
        &mut jobs,
        &mut statuses,
        &shares,
        &thermal,
        &progress,
        &CancellationToken::new(),
        Instant::now() - Duration::from_millis(1),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(error, "BM1396 original probe/first-pool deadline expired");
    assert_eq!(registry.lifetime_jobs(), 0);
    assert!(owner.publications().unwrap().is_empty());
    owner.drain(deadline()).await.unwrap();

    // 0: completed receipt accepted before launch; 1: identical real receipt
    // delayed beyond original launch; 2: initial issue blocked in a full queue;
    // 3: actual completed publication reaches a blocked acknowledgment queue.
    for defect in 0..4 {
        let (memory, owner, mut registry) = fixture().await;
        probes(&memory, &owner, &mut registry).await;
        let generation = WorkGeneration {
            session: 10,
            job: 1,
        };
        registry.set_active_generation(Some(generation));
        let pic = PicApplication::claim(owner.clone()).unwrap();
        let (control, _events, _health, _inbox) = pic.fixed_work_channels();
        let (_jt, mut jobs, _st, mut statuses, thermal) = input_channels();
        let launch = Instant::now() + Duration::from_millis(if defect == 0 { 500 } else { 250 });
        let mut input = Inputs::new(launch);
        input.pool_issued = true;
        if defect == 2 {
            for _ in 0..8 {
                control
                    .enqueue_publication(
                        PreparedJob::known_probe(0, 0).unwrap().packet().to_vec(),
                        deadline(),
                    )
                    .await
                    .unwrap();
            }
            let result = tokio::time::timeout(
                Duration::from_millis(750),
                issue(
                    &mut registry,
                    &control,
                    &mut input,
                    pool_fixture(2, generation, [255; 32]),
                ),
            )
            .await;
            assert_eq!(
                result
                    .expect("pre-pool issue must use original250ms bound, not a rebased1s")
                    .unwrap_err()
                    .to_string(),
                "BM1396 work request queue deadline"
            );
            assert_eq!(input.pending_publication, Some(2));
            assert_eq!(registry.lifetime_jobs(), 3);
            assert_eq!(owner.publications().unwrap().len(), 2);
        } else {
            let issued = issue(
                &mut registry,
                &control,
                &mut input,
                pool_fixture(2, generation, [255; 32]),
            )
            .await
            .unwrap();
            let actual = owner
                .publish_job(issued.packet().to_vec(), false, 400, deadline())
                .await
                .unwrap();
            assert!(actual.completed() && actual.same_owner(&owner));
            if defect == 1 {
                tokio::time::sleep_until(tokio::time::Instant::from_std(
                    launch + Duration::from_millis(1),
                ))
                .await;
            }
            if defect == 3 {
                for _ in 0..7 {
                    control
                        .enqueue_publication(
                            PreparedJob::known_probe(0, 0).unwrap().packet().to_vec(),
                            deadline(),
                        )
                        .await
                        .unwrap();
                }
            }
            let result = tokio::time::timeout(
                Duration::from_millis(750),
                input.consume_event(
                    &mut registry,
                    &control,
                    FixedWorkEvent::Publication(actual),
                    &mut jobs,
                    &mut statuses,
                    &thermal,
                ),
            )
            .await
            .expect("first-pool acknowledgment must remain within original launch budget");
            if defect == 0 {
                result.unwrap();
                assert_eq!(input.progress.phase, DispatchPhase::PoolWork);
                assert_eq!(input.pending_publication, None);
                tokio::time::sleep_until(tokio::time::Instant::from_std(
                    launch + Duration::from_millis(1),
                ))
                .await;
                input
                    .advance(&mut registry, &control, &mut WorkBuilder::new())
                    .await
                    .unwrap();
                assert_eq!(input.progress.phase, DispatchPhase::PoolWork);
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    if defect == 1 {
                        "BM1396 original probe/first-pool deadline expired"
                    } else {
                        "BM1396 work request queue deadline"
                    }
                );
                assert_ne!(input.progress.phase, DispatchPhase::PoolWork);
                assert_eq!(input.pending_publication, Some(2));
            }
            assert_eq!(owner.publications().unwrap().len(), 3);
            assert_eq!(registry.lifetime_jobs(), 3);
        }
        owner.drain(deadline()).await.unwrap();
    }
}
