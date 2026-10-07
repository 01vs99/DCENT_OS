//! Descendant of actual native factory collection/service fixtures. No actor
//! requirement, fake timestamps, replacement workers or phase-completion DTO.
use super::*;

async fn native(selected: &[u8]) -> (BbManagementOwner, Rig, Arc<FactoryWire>) {
    let pages = selected
        .iter()
        .map(|address| (*address, page("held_42601")))
        .collect();
    let (mut owner, rig, factory) = original(pages, bus0::Fault::None);
    diagnose(&mut owner, selected).await;
    owner.admit_native_optional_bridge_policy().unwrap();
    (owner, rig, factory)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_native_optional_sparse_slots_keep_actual_packets_and_original_history() {
    let (mut owner, rig, factory) = native(&[0x52, 0x50]).await;
    let deadline = due();
    for (index, address) in [0x22, 0x20].into_iter().enumerate() {
        owner
            .run_retained_pic_optional_bridge(index, deadline)
            .await
            .unwrap();
        let observations = owner.optional_callers.snapshots();
        assert_eq!(observations.len(), index + 1);
        let actual = observations.last().unwrap();
        assert!(!actual.pending && actual.history.first_failure.is_none());
        assert!(actual.original.first_failure.is_none());
        assert!(actual.original.native_profile_admitted);
        assert_eq!(
            actual.original.policy_source,
            "original_joined_exact_bhb42601_model96_one"
        );
        assert_eq!(actual.original.pic_address, address);
        assert_eq!(actual.original.factory_address, address + 0x30);
        assert_eq!(actual.original.native_slot, usize::from(address - 0x20));
        assert_eq!(actual.original.original_deadline, deadline);
        assert_eq!(actual.history.original_deadline, deadline);
        assert!(actual.history.retained_at <= actual.history.spawn_started_at.unwrap());
        assert!(
            actual.history.spawn_started_at.unwrap() <= actual.original.caller_started_at.unwrap()
        );
        assert!(actual.history.joined_at.unwrap() >= actual.original.caller_finalized_at.unwrap());
        assert!(actual.history.timely_joined_at.unwrap() < deadline);
        assert_eq!(actual.history.joins.len(), 1);
        assert!(!actual.history.joins[0].cleanup);
        assert_eq!(actual.history.joins[0].budget_deadline, deadline);
        assert!(actual.original.worker_finalized_at.is_some());
        assert_eq!(
            actual.original.requests,
            PACKETS.iter().map(|p| p.to_vec()).collect::<Vec<_>>()
        );
        assert_eq!(
            actual
                .original
                .steps
                .iter()
                .filter(|step| matches!(step.operation, Operation::ReadReply { .. }))
                .count(),
            28
        );
        assert!(owner
            .prepare_selected_pic_optional_bridge(index, due())
            .is_err());
    }
    assert!(owner.heartbeat_snapshot().is_none());
    assert_eq!(
        factory.acquired.lock().unwrap().as_slice(),
        factory.pages.as_slice()
    );
    let expected: Vec<_> = [0x22, 0x20]
        .into_iter()
        .flat_map(|address| PACKETS.iter().map(move |packet| (address, packet.to_vec())))
        .collect();
    assert_eq!(*rig.wire.packets.lock().unwrap(), expected);
    let before = owner.optional_callers.snapshots();
    finish(&mut owner).await;
    let closed = owner.optional_callers.snapshots();
    assert_eq!(closed.len(), before.len());
    assert_eq!(
        closed[0].original.reserved_at,
        before[0].original.reserved_at
    );
    assert_eq!(
        closed[0].history.timely_joined_at,
        before[0].history.timely_joined_at
    );
    assert!(owner.close_receipts().0.is_some() && owner.close_receipts().1.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_native_optional_write_or_read_keeps_original_handle_and_close_refusal() {
    for blocked_io in [0, 17] {
        let (mut owner, rig, _) = native(&[0x52]).await;
        *rig.wire.fault.lock().unwrap() = Fault::BlockAt(blocked_io);
        let deadline = due();
        {
            let mut caller = Box::pin(owner.run_retained_pic_optional_bridge(0, deadline));
            tokio::select! {
                result = &mut caller => panic!("blocked optional caller returned: {result:?}"),
                _ = until(|| rig.wire.gate.entered.load(Ordering::SeqCst)) => (),
            }
            drop(caller);
        }
        let cancelled = owner.optional_callers.snapshots().pop().unwrap();
        assert!(cancelled.pending && cancelled.history.joined_at.is_none());
        assert!(cancelled.history.joins[0].cancelled_at.is_some());
        assert!(cancelled
            .history
            .first_failure
            .as_ref()
            .unwrap()
            .contains("cancelled"));
        assert!(
            cancelled.original.worker_started_at.is_some()
                && cancelled.original.worker_returned_at.is_none()
        );
        assert!(owner.handles.is_stopped());
        assert!(owner
            .run_retained_pic_optional_bridge(0, due())
            .await
            .is_err());
        assert!(owner.admit_native_optional_bridge_policy().is_err());
        assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).is_err());
        assert!(owner.close_receipts().0.is_none() && owner.close_receipts().1.is_none());
        assert!(
            !owner
                .join_callers_until(Instant::now() + Duration::from_millis(100))
                .await
        );
        let waiting = owner.optional_callers.snapshots().pop().unwrap();
        assert!(waiting.pending && waiting.history.joined_at.is_none());
        assert!(waiting.history.joins.last().unwrap().cleanup);
        assert!(waiting.history.joins.last().unwrap().timed_out_at.is_some());
        rig.wire.gate.release();
        assert!(owner.join_callers_until(due()).await);
        let joined = owner.optional_callers.snapshots().pop().unwrap();
        assert!(!joined.pending && joined.history.joined_at.is_some());
        assert!(joined.history.timely_joined_at.is_none());
        assert_eq!(
            joined.history.first_failure,
            cancelled.history.first_failure
        );
        assert_eq!(joined.original.reserved_at, cancelled.original.reserved_at);
        assert_eq!(joined.original.original_deadline, deadline);
        assert!(joined.original.worker_finalized_at.is_some());
        let last = joined.original.steps.last().unwrap();
        assert_eq!(
            last.returned_count,
            Some(if blocked_io % 8 == 0 { 8 } else { 1 })
        );
        assert!(last.returned_at.is_some());
        assert_eq!(rig.wire.calls.lock().unwrap().len(), blocked_io + 1);
        assert_eq!(rig.wire.packets.lock().unwrap().len(), blocked_io / 8 + 1);
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_optional_deadline_keeps_actual_late_final_read_without_promotion() {
    let (mut owner, rig, _) = native(&[0x50]).await;
    *rig.wire.fault.lock().unwrap() = Fault::BlockAt(31);
    let deadline = Instant::now() + Duration::from_secs(2);
    let index = owner
        .start_retained_pic_optional_bridge_for_test(0, deadline)
        .unwrap();
    until(|| rig.wire.gate.entered.load(Ordering::SeqCst)).await;
    tokio::time::sleep_until(deadline.into()).await;
    assert!(
        !owner
            .join_retained_pic_optional_bridge_for_test(index)
            .await
    );
    let expired = owner.optional_callers.snapshots().pop().unwrap();
    assert!(expired.pending && expired.history.joined_at.is_none());
    assert!(expired.history.joins[0].timed_out_at.unwrap() >= deadline);
    assert!(expired.original.worker_finalized_at.is_none());
    assert!(expired.original.timely_receipt_at.is_none());
    assert!(owner.handles.is_stopped());
    assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).is_err());
    rig.wire.gate.release();
    until(|| {
        owner.optional_callers.snapshots()[0]
            .original
            .worker_finalized_at
            .is_some()
    })
    .await;
    assert!(owner.join_callers_until(due()).await);
    let joined = owner.optional_callers.snapshots().pop().unwrap();
    assert!(!joined.pending && joined.history.joined_at.is_some());
    assert_eq!(joined.original.reserved_at, expired.original.reserved_at);
    assert_eq!(joined.original.original_deadline, deadline);
    assert_eq!(joined.history.original_deadline, deadline);
    assert_eq!(joined.history.first_failure, expired.history.first_failure);
    assert!(joined.history.timely_joined_at.is_none());
    assert!(
        joined.original.transport_completed_at.is_none()
            && joined.original.timely_receipt_at.is_none()
    );
    let last = joined.original.steps.last().unwrap();
    assert!(matches!(
        last.operation,
        Operation::ReadReply {
            bridge_address: 0x4b,
            index: 6
        }
    ));
    assert_eq!(last.returned_count, Some(1));
    assert_eq!(last.returned_bytes, Some(vec![0]));
    assert!(last.returned_at.unwrap() >= deadline);
    assert_eq!(rig.wire.calls.lock().unwrap().len(), 32);
    assert_eq!(rig.wire.packets.lock().unwrap().len(), 4);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_optional_backend_error_and_unwind_keep_real_partial_history_without_reissue() {
    for (fault, ordinal) in [(Fault::ErrorAt(10), 10), (Fault::PanicAt(16), 16)] {
        let (mut owner, rig, _) = native(&[0x50]).await;
        *rig.wire.fault.lock().unwrap() = fault;
        assert!(owner
            .run_retained_pic_optional_bridge(0, due())
            .await
            .is_err());
        until(|| {
            owner.optional_callers.snapshots()[0]
                .original
                .worker_finalized_at
                .is_some()
        })
        .await;
        assert!(owner.join_callers_until(due()).await);
        let failed = owner.optional_callers.snapshots().pop().unwrap();
        assert!(!failed.pending && failed.history.joined_at.is_some());
        assert!(failed.history.timely_joined_at.is_none());
        assert!(failed.original.first_failure.is_some() && failed.original.caller_error.is_some());
        assert!(failed.original.timely_receipt_at.is_none());
        let last = failed.original.steps.last().unwrap();
        if ordinal == 10 {
            assert!(last.error.as_ref().unwrap().contains("I/O failure 10"));
            assert!(last.returned_at.is_some() && last.unwound_at.is_none());
        } else {
            assert!(last.unwound_at.is_some() && last.returned_at.is_none());
        }
        assert!(last.returned_count.is_none() && last.returned_bytes.is_none());
        assert!(owner
            .run_retained_pic_optional_bridge(0, due())
            .await
            .is_err());
        assert_eq!(owner.optional_callers.snapshots().len(), 1);
        assert_eq!(rig.wire.calls.lock().unwrap().len(), ordinal + 1);
        assert_eq!(rig.wire.packets.lock().unwrap().len(), ordinal / 8 + 1);
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_cutoff_release_keeps_original_optional_caller_after_actual_actor_joins() {
    struct Cutoff(Arc<AtomicUsize>);
    impl crate::bb_management_owner::BbHeartbeatCutoff for Cutoff {
        fn cutoff(&self) -> Result<(), String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let (mut owner, rig, _) = native(&[0x52]).await;
    let actual_cutoff_calls = Arc::new(AtomicUsize::new(0));
    let cutoff = Arc::new(Cutoff(actual_cutoff_calls.clone()));
    let original_cutoff = Arc::downgrade(&cutoff);
    owner.start_heartbeat(cutoff.clone()).unwrap();
    drop(cutoff);
    let warmup = owner.wait_stable_heartbeat_until(due()).await.unwrap();
    assert!(warmup.consecutive_complete_sweeps >= 5 && warmup.stopped_at.is_none());
    assert_eq!(actual_cutoff_calls.load(Ordering::SeqCst), 0);
    *rig.wire.fault.lock().unwrap() = Fault::BlockAt(0);
    let deadline = Instant::now() + Duration::from_secs(60);
    {
        let mut caller = Box::pin(owner.run_retained_pic_optional_bridge(0, deadline));
        tokio::select! {
            result = &mut caller => panic!("blocked optional caller returned: {result:?}"),
            _ = until(|| rig.wire.gate.entered.load(Ordering::SeqCst)) => (),
        }
        drop(caller);
    }
    let cancelled = owner.optional_callers.snapshots().pop().unwrap();
    assert!(cancelled.pending && cancelled.history.joins[0].cancelled_at.is_some());
    assert!(owner.heartbeat.as_mut().unwrap().join_until(due()).await);
    let actual_actor = owner
        .heartbeat
        .as_ref()
        .unwrap()
        .snapshot_for_callback_release()
        .unwrap();
    assert!(actual_actor.caller_joined_at.is_some() && actual_actor.monitor_joined_at.is_some());
    assert!(actual_actor.cutoff.as_ref().unwrap().joined_at.is_some());
    assert_eq!(actual_cutoff_calls.load(Ordering::SeqCst), 1);
    assert!(
        owner.execution_task.is_none() && owner.bus0_task.is_none() && owner.voltage_task.is_none()
    );
    assert!(!owner.enable_callers.pending() && !owner.initialization_callers.pending());
    assert!(owner.optional_callers.pending());
    assert!(owner.optional_callers.snapshots()[0]
        .original
        .worker_returned_at
        .is_none());
    let refusal = owner.release_joined_heartbeat_cutoff().unwrap_err();
    assert!(refusal.contains("management caller still retains heartbeat cutoff custody"));
    assert!(owner.heartbeat.is_some() && owner.heartbeat_final.is_none());
    assert!(original_cutoff.upgrade().is_some());
    assert!(owner.close_receipts().0.is_none() && owner.close_receipts().1.is_none());
    rig.wire.gate.release();
    assert!(owner.join_callers_until(due()).await);
    let joined = owner.optional_callers.snapshots().pop().unwrap();
    assert!(!joined.pending && joined.history.joined_at.is_some());
    assert!(joined.history.timely_joined_at.is_none());
    assert_eq!(
        joined.history.first_failure,
        cancelled.history.first_failure
    );
    assert_eq!(joined.original.reserved_at, cancelled.original.reserved_at);
    assert_eq!(joined.original.original_deadline, deadline);
    assert_eq!(joined.history.original_deadline, deadline);
    assert!(joined.original.worker_finalized_at.is_some());
    assert_eq!(
        joined.original.steps.last().unwrap().returned_count,
        Some(8)
    );
    assert_eq!(rig.wire.packets.lock().unwrap().len(), 1);
    assert!(owner.release_joined_heartbeat_cutoff().unwrap());
    assert!(original_cutoff.upgrade().is_none());
    assert!(owner.heartbeat.is_none() && owner.heartbeat_final.is_some());
    assert_eq!(actual_cutoff_calls.load(Ordering::SeqCst), 1);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_native_policy_or_invalid_entry_never_creates_optional_caller_history() {
    let (mut owner, rig, _) = original(vec![(0x52, page("held_42601"))], bus0::Fault::None);
    assert!(owner
        .run_retained_pic_optional_bridge(0, due())
        .await
        .is_err());
    assert!(owner.admit_native_optional_bridge_policy().is_err());
    diagnose(&mut owner, &[0x52]).await;
    assert!(owner
        .run_retained_pic_optional_bridge(0, due())
        .await
        .is_err());
    assert!(
        owner.optional_callers.snapshots().is_empty() && rig.wire.calls.lock().unwrap().is_empty()
    );
    owner.admit_native_optional_bridge_policy().unwrap();
    assert!(owner
        .run_retained_pic_optional_bridge(1, due())
        .await
        .is_err());
    assert!(owner
        .run_retained_pic_optional_bridge(0, Instant::now())
        .await
        .is_err());
    assert!(
        owner.optional_callers.snapshots().is_empty() && rig.wire.calls.lock().unwrap().is_empty()
    );
    assert!(owner.admit_native_optional_bridge_policy().is_err());
    assert!(owner.heartbeat_snapshot().is_none());
    finish(&mut owner).await;
}

#[path = "bb_optional_worker_custody_tests.rs"]
mod worker_custody;
