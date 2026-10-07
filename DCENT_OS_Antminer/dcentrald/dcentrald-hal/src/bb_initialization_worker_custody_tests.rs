//! Real caller return is distinct from the original service worker finalization.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joined_initialization_caller_keeps_blocked_worker_and_original_cutoff_custody() {
    struct ActualCutoff(Arc<AtomicUsize>);
    impl crate::bb_management_owner::BbHeartbeatCutoff for ActualCutoff {
        fn cutoff(&self) -> Result<(), String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    // Startup-heartbeat fixture bytes are deliberately weak. Route only the
    // bridge through that fixture; actual steady heartbeat requests/replies
    // use the unchanged RuntimeWire strict-reply implementation.
    struct ActorWire(Arc<Wire>);
    impl I2cSimBackend for ActorWire {
        fn service_identity(&self) -> Option<usize> {
            self.0.service_identity()
        }
        fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> crate::Result<usize> {
            if bytes == [0x55, 0xaa, 6, 0x3b, 0x48, 0, 0, 0x89] {
                self.0.write(bus, addr, bytes)
            } else {
                self.0.active.store(false, Ordering::SeqCst);
                self.0.original.write(bus, addr, bytes)
            }
        }
        fn read(&self, bus: u8, addr: u8, bytes: &mut [u8]) -> crate::Result<usize> {
            self.0.read(bus, addr, bytes)
        }
        fn write_read(&self, bus: u8, addr: u8, bytes: &[u8], out: &mut [u8]) -> crate::Result<()> {
            self.0.write_read(bus, addr, bytes, out)
        }
    }
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = apw::Backend::new(0x76, 0x17, 0x68, None, None);
    let wire = Wire::new(RuntimeWire::new(a.clone()));
    let mut owner = BbManagementOwner::new(
        spawn_owned_sim_i2c_service(
            0,
            Arc::new(ActorWire(wire.clone())),
            (0x50..=0x57).collect(),
        )
        .unwrap(),
        spawn_owned_sim_i2c_service(1, b.clone(), (0x50..=0x57).collect()).unwrap(),
    );
    let rig = Rig { a, b, wire };
    diagnose(&mut owner, &[0x52]).await;
    let count = Arc::new(AtomicUsize::new(0));
    let cutoff = Arc::new(ActualCutoff(count.clone()));
    let original_cutoff = Arc::downgrade(&cutoff);
    owner.start_heartbeat(cutoff.clone()).unwrap();
    drop(cutoff);
    let warmup_result = owner.wait_stable_heartbeat_until(due()).await;
    let warmup = warmup_result.unwrap_or_else(|error| {
        panic!(
            "strict original RuntimeWire warmup failed: {error}; actor={:?}",
            owner.heartbeat.as_ref().unwrap().snapshot()
        )
    });
    assert!(warmup.consecutive_complete_sweeps >= 5);
    assert!(warmup.stopped_at.is_none() && !owner.handles.is_stopped());
    assert_eq!(count.load(Ordering::SeqCst), 0);
    // Inspect actual retained sweeps and actual original backend events;
    // no reply, timestamp, actor state or completed sweep is injected here.
    let strict_reply: [u8; 6] = [6, 0x16, 1, 0, 0, 0x1d];
    let strict_reads: Vec<Vec<u8>> = strict_reply.iter().map(|byte| vec![*byte]).collect();
    assert!(warmup.retained_rounds.len() >= 5);
    for round in warmup.retained_rounds.iter().take(5) {
        assert!(round.completed_at.is_some() && round.accepted_at.is_some());
        assert!(round.failure.is_none());
        assert_eq!(round.attempts.len(), 1);
        let attempt = &round.attempts[0];
        assert_eq!((attempt.native_slot, attempt.pic_address), (2, Some(0x22)));
        assert_eq!(attempt.returned_reads.as_ref(), Some(&strict_reads));
        assert_eq!(attempt.decoded_reply, Some(strict_reply));
        assert!(attempt.strict_completed_at.is_some());
        assert!(attempt.transport_error.is_none() && attempt.failure.is_none());
    }
    let heartbeat_events: Vec<_> = rig
        .wire
        .original
        .events()
        .into_iter()
        .filter(|event| event.opcode == 0x16)
        .collect();
    assert!(heartbeat_events.len() >= 35);
    for sweep in heartbeat_events[..35].chunks_exact(7) {
        assert!(sweep[0].write && sweep[0].address == 0x22);
        assert_eq!(sweep[0].bytes, [0x55, 0xaa, 4, 0x16, 0, 0x1a]);
        for (event, byte) in sweep[1..].iter().zip(strict_reply) {
            assert!(!event.write && event.address == 0x22);
            assert_eq!(event.bytes, [byte]);
        }
    }
    assert!(rig.wire.calls.lock().unwrap().is_empty());
    rig.wire.fault.store(5, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(2);
    {
        let mut future =
            Box::pin(owner.run_retained_pic_initialization_exchange(0, Phase::Bridge, deadline));
        tokio::select! {
            result = &mut future => panic!("blocked original worker unexpectedly returned: {result:?}"),
            _ = until(|| rig.wire.gate.entered.load(Ordering::SeqCst)) => (),
        }
        drop(future);
    }
    until(|| {
        owner.initialization_callers.snapshots()[0]
            .original
            .caller_finalized_at
            .is_some()
    })
    .await;
    assert!(owner.heartbeat.as_mut().unwrap().join_until(due()).await);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let before = owner.initialization_callers.snapshots().pop().unwrap();
    assert!(before.original.request_created_at.is_some());
    assert!(before.original.worker_started_at.is_some());
    assert!(before.original.worker_finalized_at.is_none());
    assert!(before.history.joined_at.is_none());
    let cleanup_deadline = Instant::now() + Duration::from_millis(150);
    assert!(!owner.join_callers_until(cleanup_deadline).await);
    let waiting = owner.initialization_callers.snapshots().pop().unwrap();
    assert!(waiting.history.joined_at.is_some());
    assert!(waiting.original.caller_finalized_at.is_some());
    assert!(waiting.original.worker_finalized_at.is_none());
    assert!(waiting.pending && owner.initialization_callers.pending());
    let worker_wait = waiting.history.worker_waits.last().unwrap();
    assert_eq!(worker_wait.budget_deadline, cleanup_deadline);
    assert!(worker_wait.started_at >= waiting.history.joined_at.unwrap());
    assert!(worker_wait.timed_out_at.unwrap() >= cleanup_deadline);
    assert!(worker_wait.worker_finalized_at.is_none() && worker_wait.observed_at.is_none());
    let refusal = owner.release_joined_heartbeat_cutoff().unwrap_err();
    assert!(refusal.contains("management caller still retains heartbeat cutoff custody"));
    assert!(original_cutoff.upgrade().is_some());
    assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).is_err());
    assert!(owner.close_receipts().0.is_none() && owner.close_receipts().1.is_none());
    assert!(waiting.history.timely_joined_at.is_none());
    assert_eq!(waiting.history.first_failure, before.history.first_failure);
    rig.wire.gate.release();
    assert!(owner.join_callers_until(due()).await);
    let finished = owner.initialization_callers.snapshots().pop().unwrap();
    assert!(!finished.pending && finished.original.worker_finalized_at.is_some());
    assert_eq!(finished.history.joined_at, waiting.history.joined_at);
    assert_eq!(
        finished.original.request_created_at,
        waiting.original.request_created_at
    );
    assert_eq!(finished.original.original_deadline, deadline);
    assert_eq!(
        finished.history.first_failure,
        waiting.history.first_failure
    );
    assert!(
        finished.history.timely_joined_at.is_none()
            && finished.original.timely_receipt_at.is_none()
    );
    assert_eq!(rig.wire.writes(), [0x22]);
    assert!(owner.release_joined_heartbeat_cutoff().unwrap());
    assert!(original_cutoff.upgrade().is_none());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    finish(&mut owner).await;
}

#[test]
fn actual_prequeue_initialization_refusal_has_no_invented_worker_or_pending_custody() {
    // Occupy the remaining blocking pool thread after actual diagnostics/actor setup.
    // The original retained caller is created but cannot run until cancellation.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x52]).await;
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let blocker = tokio::task::spawn_blocking(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        owner
            .start_retained_pic_initialization_exchange_for_test(0, Phase::Bridge, due())
            .unwrap();
        let queued_caller = owner.initialization_callers.snapshots().pop().unwrap();
        assert!(queued_caller.pending && queued_caller.original.caller_started_at.is_none());
        assert!(queued_caller.original.request_created_at.is_none());
        owner.cancel();
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        assert!(owner.join_callers_until(due()).await);
        let refused = owner.initialization_callers.snapshots().pop().unwrap();
        assert!(
            refused.history.joined_at.is_some() && refused.original.caller_finalized_at.is_some()
        );
        assert!(refused.original.request_created_at.is_none());
        assert!(refused.original.worker_started_at.is_none());
        assert!(refused.original.worker_finalized_at.is_none());
        assert!(
            refused.original.caller_error.is_some() && refused.original.first_failure.is_some()
        );
        assert!(refused.history.worker_waits.is_empty());
        assert!(!refused.pending && !owner.initialization_callers.pending());
        assert!(refused.history.timely_joined_at.is_none());
        assert!(rig.wire.writes().is_empty());
        finish(&mut owner).await;
    });
}
