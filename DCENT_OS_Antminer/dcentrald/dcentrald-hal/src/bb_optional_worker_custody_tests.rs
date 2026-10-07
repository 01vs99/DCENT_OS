//! Real caller return is distinct from the original service worker finalization.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joined_optional_caller_keeps_blocked_worker_and_original_cutoff_custody() {
    struct ActualCutoff(Arc<AtomicUsize>);
    impl crate::bb_management_owner::BbHeartbeatCutoff for ActualCutoff {
        fn cutoff(&self) -> Result<(), String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let (mut owner, rig, _) = native(&[0x52]).await;
    let count = Arc::new(AtomicUsize::new(0));
    let cutoff = Arc::new(ActualCutoff(count.clone()));
    let original_cutoff = Arc::downgrade(&cutoff);
    owner.start_heartbeat(cutoff.clone()).unwrap();
    drop(cutoff);
    assert!(
        owner
            .wait_stable_heartbeat_until(due())
            .await
            .unwrap()
            .consecutive_complete_sweeps
            >= 5
    );
    *rig.wire.fault.lock().unwrap() = Fault::BlockAt(0);
    let deadline = Instant::now() + Duration::from_secs(2);
    {
        let mut future = Box::pin(owner.run_retained_pic_optional_bridge(0, deadline));
        tokio::select! {
            result = &mut future => panic!("blocked original worker unexpectedly returned: {result:?}"),
            _ = until(|| rig.wire.gate.entered.load(Ordering::SeqCst)) => (),
        }
        drop(future);
    }
    until(|| {
        owner.optional_callers.snapshots()[0]
            .original
            .caller_finalized_at
            .is_some()
    })
    .await;
    assert!(owner.heartbeat.as_mut().unwrap().join_until(due()).await);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let before = owner.optional_callers.snapshots().pop().unwrap();
    assert!(before.original.request_created_at.is_some());
    assert!(before.original.worker_started_at.is_some());
    assert!(before.original.worker_finalized_at.is_none());
    assert!(before.history.joined_at.is_none());
    let cleanup_deadline = Instant::now() + Duration::from_millis(150);
    assert!(!owner.join_callers_until(cleanup_deadline).await);
    let waiting = owner.optional_callers.snapshots().pop().unwrap();
    assert!(waiting.history.joined_at.is_some());
    assert!(waiting.original.caller_finalized_at.is_some());
    assert!(waiting.original.worker_finalized_at.is_none());
    assert!(waiting.pending && owner.optional_callers.pending());
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
    let finished = owner.optional_callers.snapshots().pop().unwrap();
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
    assert_eq!(rig.wire.packets.lock().unwrap().len(), 1);
    assert!(owner.release_joined_heartbeat_cutoff().unwrap());
    assert!(original_cutoff.upgrade().is_none());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    finish(&mut owner).await;
}

#[test]
fn actual_prequeue_optional_refusal_has_no_invented_worker_or_pending_custody() {
    // Occupy the remaining blocking pool thread after actual diagnostics/actor setup.
    // The original retained caller is created but cannot run until cancellation.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (mut owner, rig, _) = native(&[0x52]).await;
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let blocker = tokio::task::spawn_blocking(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        owner
            .start_retained_pic_optional_bridge_for_test(0, due())
            .unwrap();
        let queued_caller = owner.optional_callers.snapshots().pop().unwrap();
        assert!(queued_caller.pending && queued_caller.original.caller_started_at.is_none());
        assert!(queued_caller.original.request_created_at.is_none());
        owner.cancel();
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        assert!(owner.join_callers_until(due()).await);
        let refused = owner.optional_callers.snapshots().pop().unwrap();
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
        assert!(!refused.pending && !owner.optional_callers.pending());
        assert!(refused.history.timely_joined_at.is_none());
        assert!(rig.wire.calls.lock().unwrap().is_empty());
        finish(&mut owner).await;
    });
}
