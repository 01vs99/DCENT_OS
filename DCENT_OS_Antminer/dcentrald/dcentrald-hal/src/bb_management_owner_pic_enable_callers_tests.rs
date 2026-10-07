//! Descendant of the existing real service/actor fixture. No simulated clocks,
//! injected receipts, replacement actors or caller-supplied phase completions.
use super::*;
use crate::i2c::bb_pic_enable::Operation;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_enable_sparse_slots_keep_original_actor_deadline_and_all_history() {
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x52, 0x50]).await;
    let actor_started = owner.heartbeat_snapshot().unwrap().started_at;
    let deadline = due();
    for (index, address) in [0x22, 0x20].into_iter().enumerate() {
        owner
            .run_retained_pic_enable(index, deadline)
            .await
            .unwrap();
        let observations = owner.enable_callers.snapshots();
        assert_eq!(observations.len(), index + 1);
        let observed = observations.last().unwrap();
        assert!(!observed.pending);
        assert_eq!(observed.original.pic_address, address);
        assert_eq!(observed.original.factory_address, address + 0x30);
        assert_eq!(observed.original.native_slot, usize::from(address - 0x20));
        assert_eq!(observed.original.original_deadline, deadline);
        assert_eq!(observed.history.original_deadline, deadline);
        assert!(observed.history.first_failure.is_none());
        assert!(observed.original.first_failure.is_none());
        assert!(observed.history.spawn_unwound_at.is_none());
        assert!(observed.history.retained_at <= observed.history.spawn_started_at.unwrap());
        assert!(
            observed.history.spawn_started_at.unwrap()
                <= observed.original.caller_started_at.unwrap()
        );
        assert!(
            observed.history.joined_at.unwrap() >= observed.original.caller_finalized_at.unwrap()
        );
        assert!(observed.history.timely_joined_at.unwrap() < deadline);
        assert_eq!(observed.history.joins.len(), 1);
        assert!(!observed.history.joins[0].cleanup);
        assert_eq!(observed.history.joins[0].budget_deadline, deadline);
        let actual_gate = observed.history.actor_recheck.as_ref().unwrap();
        assert_eq!(actual_gate.original_deadline, deadline);
        assert!(actual_gate.started_at >= observed.history.joined_at.unwrap());
        assert!(actual_gate.observed_at.unwrap() >= actual_gate.started_at);
        assert!(actual_gate.returned_at >= actual_gate.observed_at.unwrap());
        assert!(actual_gate.returned_at < deadline);
        assert!(actual_gate.complete_sweeps.unwrap() >= 5);
        assert!(actual_gate.error.is_none());
        assert_eq!(
            owner.heartbeat_snapshot().unwrap().started_at,
            actor_started
        );
        assert!(owner.prepare_selected_pic_enable(index, due()).is_err());
    }
    assert_eq!(rig.wire.writes(), [0x22, 0x20]);
    let retained = owner.enable_callers.snapshots();
    finish(&mut owner).await;
    let closed = owner.enable_callers.snapshots();
    assert_eq!(closed.len(), retained.len());
    assert_eq!(
        closed[0].history.timely_joined_at,
        retained[0].history.timely_joined_at
    );
    assert!(owner.heartbeat.is_none());
    assert!(owner.close_receipts().0.is_some() && owner.close_receipts().1.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_enable_write_retains_original_handle_and_refuses_early_cleanup() {
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x52]).await;
    rig.wire.fault.store(5, Ordering::SeqCst);
    let deadline = due();
    {
        let mut caller = Box::pin(owner.run_retained_pic_enable(0, deadline));
        tokio::select! {
            result = &mut caller => panic!("original blocked enable returned: {result:?}"),
            _ = until(|| rig.wire.gate.entered.load(Ordering::SeqCst)) => (),
        }
        drop(caller);
    }
    let cancelled = owner.enable_callers.snapshots().pop().unwrap();
    assert!(cancelled.pending && cancelled.history.joined_at.is_none());
    assert!(cancelled.history.joins[0].cancelled_at.is_some());
    assert!(cancelled
        .history
        .first_failure
        .as_ref()
        .unwrap()
        .contains("cancelled"));
    assert!(cancelled.original.worker_started_at.is_some());
    assert!(cancelled.original.worker_returned_at.is_none());
    assert!(owner.handles.is_stopped());
    assert!(owner.prepare_selected_pic_enable(0, due()).is_err());
    assert!(owner.release_joined_heartbeat_cutoff().is_err());
    assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).is_err());
    assert!(owner.close_receipts().0.is_none() && owner.close_receipts().1.is_none());
    assert!(
        !owner
            .join_callers_until(Instant::now() + Duration::from_millis(100))
            .await
    );
    let waiting = owner.enable_callers.snapshots().pop().unwrap();
    assert!(waiting.pending && waiting.history.joined_at.is_none());
    assert!(waiting.history.actor_recheck.is_none());
    assert_eq!(waiting.original.reserved_at, cancelled.original.reserved_at);
    rig.wire.gate.release();
    assert!(owner.join_callers_until(due()).await);
    let joined = owner.enable_callers.snapshots().pop().unwrap();
    assert!(!joined.pending && joined.history.joined_at.is_some());
    assert!(joined.history.timely_joined_at.is_none() && joined.history.actor_recheck.is_none());
    assert_eq!(
        joined.history.first_failure,
        cancelled.history.first_failure
    );
    assert_eq!(joined.original.original_deadline, deadline);
    assert_eq!(joined.original.reserved_at, cancelled.original.reserved_at);
    assert!(joined.original.worker_finalized_at.is_some());
    let write = joined
        .original
        .steps
        .iter()
        .find(|step| matches!(step.operation, Operation::WriteEnable))
        .unwrap();
    assert_eq!(write.returned_count, Some(7));
    assert!(write.returned_at.is_some());
    assert_eq!(rig.wire.writes(), [0x22]);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_original_enable_deadline_keeps_actual_late_read_without_promotion() {
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x50]).await;
    rig.wire.fault.store(4, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_millis(700);
    let index = owner
        .start_retained_pic_enable_for_test(0, deadline)
        .unwrap();
    until(|| rig.wire.gate.entered.load(Ordering::SeqCst)).await;
    tokio::time::sleep_until(deadline.into()).await;
    assert!(!owner.join_retained_pic_enable_for_test(index).await);
    let expired = owner.enable_callers.snapshots().pop().unwrap();
    assert!(expired.pending && expired.history.joined_at.is_none());
    assert!(expired.history.joins[0].timed_out_at.unwrap() >= deadline);
    assert!(expired.history.actor_recheck.is_none());
    assert!(expired.original.worker_finalized_at.is_none());
    assert!(expired.original.timely_receipt_at.is_none());
    assert!(owner.handles.is_stopped());
    assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).is_err());
    rig.wire.gate.release();
    until(|| {
        owner.enable_callers.snapshots()[0]
            .original
            .worker_finalized_at
            .is_some()
    })
    .await;
    assert!(owner.join_callers_until(due()).await);
    let joined = owner.enable_callers.snapshots().pop().unwrap();
    assert!(!joined.pending && joined.history.joined_at.is_some());
    assert_eq!(joined.original.reserved_at, expired.original.reserved_at);
    assert_eq!(joined.original.original_deadline, deadline);
    assert_eq!(joined.history.original_deadline, deadline);
    assert_eq!(joined.history.first_failure, expired.history.first_failure);
    assert!(joined.history.timely_joined_at.is_none() && joined.history.actor_recheck.is_none());
    assert!(
        joined.original.transport_completed_at.is_none()
            && joined.original.timely_receipt_at.is_none()
    );
    let last = joined.original.steps.last().unwrap();
    assert!(matches!(last.operation, Operation::ReadReply));
    assert_eq!(last.returned_count, Some(1));
    assert_eq!(last.returned_bytes, Some(vec![0xff]));
    assert!(last.returned_at.unwrap() >= deadline);
    assert_eq!(rig.wire.writes(), [0x20]);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_enable_backend_error_and_unwind_preserve_actual_worker_no_replay() {
    for fault in [3, 6] {
        let (mut owner, rig) = Rig::new();
        stable(&mut owner, &[0x50]).await;
        rig.wire.fault.store(fault, Ordering::SeqCst);
        assert!(owner.run_retained_pic_enable(0, due()).await.is_err());
        until(|| {
            owner.enable_callers.snapshots()[0]
                .original
                .worker_finalized_at
                .is_some()
        })
        .await;
        assert!(owner.join_callers_until(due()).await);
        let failed = owner.enable_callers.snapshots().pop().unwrap();
        assert!(!failed.pending && failed.history.joined_at.is_some());
        assert!(failed.history.timely_joined_at.is_none());
        assert!(failed.original.first_failure.is_some());
        assert!(failed.original.timely_receipt_at.is_none());
        let last = failed.original.steps.last().unwrap();
        if fault == 3 {
            assert!(last
                .error
                .as_ref()
                .unwrap()
                .contains("authored second enable"));
            assert!(last.returned_count.is_none() && last.unwound_at.is_none());
        } else {
            assert!(last.unwound_at.is_some());
            assert!(last.returned_at.is_none() && last.returned_count.is_none());
        }
        assert!(owner.run_retained_pic_enable(0, due()).await.is_err());
        assert_eq!(owner.enable_callers.snapshots().len(), 1);
        assert_eq!(rig.wire.writes(), [0x20]);
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_enable_completion_cannot_promote_after_original_actor_stops_before_join() {
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x52]).await;
    let deadline = due();
    let index = owner
        .start_retained_pic_enable_for_test(0, deadline)
        .unwrap();
    until(|| {
        let observed = owner.enable_callers.snapshots().pop().unwrap();
        observed.original.timely_receipt_at.is_some()
            && observed.original.worker_finalized_at.is_some()
            && observed.original.caller_finalized_at.is_some()
    })
    .await;
    let complete = owner.enable_callers.snapshots().pop().unwrap();
    assert!(complete.pending && complete.history.joined_at.is_none());
    assert!(complete.original.transport_completed_at.is_some());
    owner
        .heartbeat
        .as_ref()
        .unwrap()
        .stop("authored original actor stop after real enable completion");
    assert!(owner.heartbeat.as_mut().unwrap().join_until(due()).await);
    until(|| {
        owner
            .heartbeat
            .as_ref()
            .unwrap()
            .snapshot_for_callback_release()
            .is_ok()
    })
    .await;
    assert!(owner
        .release_joined_heartbeat_cutoff()
        .unwrap_err()
        .contains("management caller still retains heartbeat cutoff custody"));
    assert!(owner.heartbeat.is_some() && owner.heartbeat_final.is_none());
    assert!(Instant::now() < deadline);
    assert!(!owner.join_retained_pic_enable_for_test(index).await);
    let refused = owner.enable_callers.snapshots().pop().unwrap();
    assert!(!refused.pending && refused.history.joined_at.is_some());
    assert!(refused.history.timely_joined_at.is_none());
    assert_eq!(refused.original.reserved_at, complete.original.reserved_at);
    assert_eq!(
        refused.original.timely_receipt_at,
        complete.original.timely_receipt_at
    );
    assert_eq!(
        refused.original.transport_completed_at,
        complete.original.transport_completed_at
    );
    let observed_actor = refused.history.actor_recheck.as_ref().unwrap();
    assert_eq!(
        observed_actor.error.as_deref(),
        Some("BB heartbeat observed original terminal fence")
    );
    assert!(observed_actor.observed_at.is_none() && observed_actor.complete_sweeps.is_none());
    assert_eq!(observed_actor.original_deadline, deadline);
    assert!(observed_actor.started_at >= refused.history.joined_at.unwrap());
    assert!(observed_actor.returned_at < deadline);
    assert!(owner.release_joined_heartbeat_cutoff().unwrap());
    assert_eq!(rig.wire.writes(), [0x22]);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_enable_admission_creates_no_original_caller_or_fake_actor_history() {
    for partial_actor in [false, true] {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x52]).await;
        if partial_actor {
            owner.start_heartbeat(Arc::new(Cutoff)).unwrap();
            until(|| owner.heartbeat_snapshot().unwrap().complete_sweeps >= 1).await;
            assert!(owner.heartbeat_snapshot().unwrap().complete_sweeps < 5);
        }
        assert!(owner.run_retained_pic_enable(0, due()).await.is_err());
        assert!(owner.enable_callers.snapshots().is_empty());
        assert!(rig.wire.writes().is_empty());
        finish(&mut owner).await;
    }
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x52]).await;
    assert!(owner.run_retained_pic_enable(1, due()).await.is_err());
    assert!(owner
        .run_retained_pic_enable(0, Instant::now())
        .await
        .is_err());
    assert!(owner.enable_callers.snapshots().is_empty());
    assert!(rig.wire.writes().is_empty());
    finish(&mut owner).await;
}

#[path = "bb_enable_worker_custody_tests.rs"]
mod worker_custody;
