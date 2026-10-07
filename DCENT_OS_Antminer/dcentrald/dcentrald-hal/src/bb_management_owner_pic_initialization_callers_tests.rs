//! Descendant of the existing original-service fixture; no new backend seam.
use super::*;
use crate::i2c::bb_pic_initialization_exchange::Operation;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_callers_keep_actual_sparse_slot_success_and_all_prior_history() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x52, 0x50]).await;
    let deadline = due();
    let mut expected = Vec::new();
    for (index, address) in [0x22, 0x20].into_iter().enumerate() {
        for phase in PHASES {
            owner
                .run_retained_pic_initialization_exchange(index, phase, deadline)
                .await
                .unwrap();
            expected.push((address, source(phase).0));
            let observations = owner.initialization_callers.snapshots();
            assert_eq!(observations.len(), expected.len());
            let observed = observations.last().unwrap();
            assert!(!observed.pending, "{observed:?}");
            assert_eq!(observed.original.factory_address, address + 0x30);
            assert_eq!(observed.original.native_slot, usize::from(address - 0x20));
            assert_eq!(observed.original.pic_address, address);
            assert_eq!(observed.original.phase, phase);
            assert_eq!(observed.original.original_deadline, deadline);
            assert_eq!(observed.history.original_deadline, deadline);
            assert!(observed.history.first_failure.is_none());
            assert!(observed.history.spawn_unwound_at.is_none());
            assert!(observed.history.spawn_unwind.is_none());
            assert!(observed.history.retained_at <= observed.history.spawn_started_at.unwrap());
            assert!(
                observed.history.spawn_started_at.unwrap()
                    <= observed.original.caller_started_at.unwrap()
            );
            assert!(observed.history.spawn_returned_at.is_some());
            assert!(
                observed.history.joined_at.unwrap()
                    >= observed.original.caller_finalized_at.unwrap()
            );
            assert!(observed.history.timely_joined_at.unwrap() < deadline);
            assert_eq!(observed.history.joins.len(), 1);
            assert!(!observed.history.joins[0].cleanup);
            assert_eq!(observed.history.joins[0].budget_deadline, deadline);
            assert!(
                observed.history.joins[0].returned_at.unwrap()
                    >= observed.history.joins[0].started_at
            );
            assert!(observed.history.joins[0].error.is_none());
            let raw: Vec<_> = observed
                .original
                .steps
                .iter()
                .filter_map(|step| step.returned_bytes.clone())
                .collect();
            assert_eq!(
                raw,
                (0..source(phase).1)
                    .map(|n| vec![[0, 0xff][n % 2]])
                    .collect::<Vec<_>>()
            );
        }
    }
    assert_eq!(*rig.wire.packets.lock().unwrap(), expected);
    let before = owner.initialization_callers.snapshots();
    assert!(owner
        .run_retained_pic_initialization_exchange(0, Phase::Bridge, due())
        .await
        .is_err());
    assert_eq!(owner.initialization_callers.snapshots().len(), before.len());
    finish(&mut owner).await;
    let after = owner.initialization_callers.snapshots();
    for (a, b) in before.iter().zip(after) {
        assert_eq!(a.history.timely_joined_at, b.history.timely_joined_at);
        assert_eq!(a.history.original_deadline, b.history.original_deadline);
        assert_eq!(a.original.reserved_at, b.original.reserved_at);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_blocked_original_write_refuses_close_until_actual_caller_join() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x52]).await;
    rig.wire.fault.store(5, Ordering::SeqCst);
    let deadline = due();
    {
        let mut pending =
            Box::pin(owner.run_retained_pic_initialization_exchange(0, Phase::Bridge, deadline));
        tokio::select! {
            result = &mut pending => panic!("blocked caller unexpectedly returned: {result:?}"),
            _ = until(|| rig.wire.gate.entered.load(Ordering::SeqCst)) => (),
        }
        drop(pending);
    }
    let before = owner.initialization_callers.snapshots().pop().unwrap();
    assert!(before.pending && owner.handles.is_stopped());
    assert!(before.history.joins[0].cancelled_at.is_some());
    assert!(before.history.joins[0].returned_at.is_none());
    assert!(before.history.joined_at.is_none());
    assert!(before.history.timely_joined_at.is_none());
    assert!(before.original.worker_started_at.is_some());
    assert!(before.original.worker_returned_at.is_none());
    assert_eq!(rig.wire.writes(), [0x22]);
    assert!(owner.close_services_until(due()).is_err());
    assert!(owner.close_receipts().0.is_none() && owner.close_receipts().1.is_none());
    assert!(
        !owner
            .join_callers_until(Instant::now() + Duration::from_millis(20))
            .await
    );
    let blocked = owner.initialization_callers.snapshots().pop().unwrap();
    assert!(blocked.pending && blocked.history.joins.len() == 2);
    assert!(blocked.history.joins[1].cleanup && blocked.history.joins[1].timed_out_at.is_some());
    assert!(owner.close_services_until(due()).is_err());
    rig.wire.gate.release();
    assert!(owner.join_callers_until(due()).await);
    let joined = owner.initialization_callers.snapshots().pop().unwrap();
    assert!(!joined.pending && joined.history.joined_at.is_some());
    assert_eq!(joined.history.joins.len(), 3);
    assert!(joined.history.joins[2].cleanup && joined.history.joins[2].returned_at.is_some());
    assert_eq!(joined.history.first_failure, before.history.first_failure);
    assert!(joined.history.timely_joined_at.is_none());
    assert_eq!(joined.original.reserved_at, before.original.reserved_at);
    assert_eq!(
        joined.original.worker_started_at,
        before.original.worker_started_at
    );
    assert_eq!(joined.original.original_deadline, deadline);
    let last = joined.original.steps.last().unwrap();
    assert!(matches!(last.operation, Operation::WriteRequest));
    assert_eq!(last.returned_count, Some(8));
    assert!(joined.original.caller_error.is_some());
    assert!(owner
        .run_retained_pic_initialization_exchange(0, Phase::Bridge, due())
        .await
        .is_err());
    assert_eq!(rig.wire.writes(), [0x22]);
    assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).unwrap());
    assert!(owner.close_receipts().0.is_some() && owner.close_receipts().1.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_deadline_expiry_and_late_cleanup_never_promote_the_retained_attempt() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x50]).await;
    rig.wire.fault.store(4, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_millis(700);
    {
        let mut pending =
            Box::pin(owner.run_retained_pic_initialization_exchange(0, Phase::FinalRail, deadline));
        tokio::select! {
            result = &mut pending => panic!("blocked final read unexpectedly returned: {result:?}"),
            _ = until(|| rig.wire.gate.entered.load(Ordering::SeqCst)) => (),
        }
        assert!(pending.await.is_err());
    }
    let expired = owner.initialization_callers.snapshots().pop().unwrap();
    assert!(Instant::now() >= deadline);
    assert!(expired.history.first_failure.is_some() && expired.history.timely_joined_at.is_none());
    // A real JoinHandle may become ready in the same poll as the deadline.
    // Retain either actual late join or timed-out pending handle, never invent one.
    assert!(
        expired.history.joins[0].timed_out_at.is_some()
            || expired.history.joins[0].returned_at.is_some()
    );
    assert!(expired.original.worker_finalized_at.is_none());
    assert_eq!(expired.history.original_deadline, deadline);
    if expired.pending {
        assert!(owner.close_services_until(due()).is_err());
    }
    rig.wire.gate.release();
    assert!(owner.join_callers_until(due()).await);
    until(|| {
        owner.initialization_callers.snapshots()[0]
            .original
            .worker_finalized_at
            .is_some()
    })
    .await;
    let after = owner.initialization_callers.snapshots().pop().unwrap();
    assert!(!after.pending && after.history.timely_joined_at.is_none());
    assert_eq!(after.history.first_failure, expired.history.first_failure);
    assert_eq!(after.history.original_deadline, deadline);
    assert_eq!(after.original.original_deadline, deadline);
    assert_eq!(after.original.reserved_at, expired.original.reserved_at);
    assert_eq!(
        after.original.worker_started_at,
        expired.original.worker_started_at
    );
    let last = after.original.steps.last().unwrap();
    assert!(matches!(last.operation, Operation::ReadReply));
    assert_eq!(last.returned_count, Some(1));
    assert_eq!(last.returned_bytes, Some(vec![0]));
    assert!(last.returned_at.unwrap() >= deadline);
    assert!(after.original.timely_receipt_at.is_none());
    assert!(after.original.transport_completed_at.is_none());
    assert!(owner
        .run_retained_pic_initialization_exchange(0, Phase::FinalRail, due())
        .await
        .is_err());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_backend_error_and_unwind_keep_joined_original_history_without_reissue() {
    for fault in [3, 6] {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x52]).await;
        rig.wire.fault.store(fault, Ordering::SeqCst);
        assert!(owner
            .run_retained_pic_initialization_exchange(0, Phase::Bridge, due())
            .await
            .is_err());
        let observed = owner.initialization_callers.snapshots().pop().unwrap();
        assert!(!observed.pending);
        assert!(observed.history.joined_at.is_some() && observed.history.join_error.is_none());
        assert!(
            observed.history.first_failure.is_some() && observed.history.timely_joined_at.is_none()
        );
        assert!(observed.original.worker_finalized_at.is_some());
        let last = observed.original.steps.last().unwrap();
        if fault == 3 {
            assert!(last
                .error
                .as_ref()
                .unwrap()
                .contains("authored final initialization read failure"));
            assert!(last.returned_at.is_some() && last.unwound_at.is_none());
        } else {
            assert!(last.unwound_at.is_some() && last.returned_at.is_none());
            assert!(last.returned_count.is_none());
        }
        assert!(owner
            .run_retained_pic_initialization_exchange(0, Phase::Bridge, due())
            .await
            .is_err());
        assert_eq!(rig.wire.writes(), [0x22]);
        assert_eq!(owner.initialization_callers.snapshots().len(), 1);
        finish(&mut owner).await;
        let after = owner.initialization_callers.snapshots().pop().unwrap();
        assert_eq!(after.original.reserved_at, observed.original.reserved_at);
        assert_eq!(after.original.steps.len(), observed.original.steps.len());
        assert_eq!(after.history.first_failure, observed.history.first_failure);
        assert!(after.history.timely_joined_at.is_none());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_original_roster_or_expired_entry_retains_no_fabricated_caller() {
    let (mut owner, rig) = Rig::new();
    assert!(owner
        .run_retained_pic_initialization_exchange(0, Phase::Bridge, due())
        .await
        .is_err());
    diagnose(&mut owner, &[0x52]).await;
    assert!(owner
        .run_retained_pic_initialization_exchange(1, Phase::Bridge, due())
        .await
        .is_err());
    assert!(owner
        .run_retained_pic_initialization_exchange(0, Phase::Bridge, Instant::now())
        .await
        .is_err());
    assert!(owner.initialization_callers.snapshots().is_empty());
    assert!(rig.wire.writes().is_empty());
    owner
        .run_retained_pic_initialization_exchange(0, Phase::Bridge, due())
        .await
        .unwrap();
    assert_eq!(owner.initialization_callers.snapshots().len(), 1);
    assert_eq!(rig.wire.writes(), [0x22]);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_cutoff_release_refuses_unjoined_exchange_after_real_actor_and_cutoff_joins() {
    struct Cutoff(Arc<AtomicUsize>);
    impl crate::bb_management_owner::BbHeartbeatCutoff for Cutoff {
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
    let actual_cutoff_calls = Arc::new(AtomicUsize::new(0));
    let cutoff = Arc::new(Cutoff(actual_cutoff_calls.clone()));
    let original_cutoff = Arc::downgrade(&cutoff);
    owner.start_heartbeat(cutoff.clone()).unwrap();
    drop(cutoff);
    let warmup = owner.wait_stable_heartbeat_until(due()).await.unwrap();
    assert!(warmup.consecutive_complete_sweeps >= 5);
    assert!(warmup.stopped_at.is_none());
    assert_eq!(actual_cutoff_calls.load(Ordering::SeqCst), 0);
    rig.wire.fault.store(5, Ordering::SeqCst);
    let original_deadline = Instant::now() + Duration::from_secs(60);
    {
        let mut caller = Box::pin(owner.run_retained_pic_initialization_exchange(
            0,
            Phase::Bridge,
            original_deadline,
        ));
        tokio::select! {
            result = &mut caller => panic!("blocked original exchange returned: {result:?}"),
            _ = until(|| rig.wire.gate.entered.load(Ordering::SeqCst)) => (),
        }
        drop(caller);
    }
    let cancelled = owner.initialization_callers.snapshots().pop().unwrap();
    assert!(cancelled.pending && cancelled.history.joined_at.is_none());
    assert!(cancelled.history.joins[0].cancelled_at.is_some());
    assert!(cancelled.original.worker_started_at.is_some());
    assert!(cancelled.original.worker_returned_at.is_none());
    assert!(owner.handles.is_stopped());

    // Join the real actor, monitor and original operational cutoff only. The
    // original exchange JoinHandle deliberately remains in the same owner.
    assert!(owner.heartbeat.as_mut().unwrap().join_until(due()).await);
    let actual_actor = owner
        .heartbeat
        .as_ref()
        .unwrap()
        .snapshot_for_callback_release()
        .unwrap();
    assert!(actual_actor.caller_joined_at.is_some());
    assert!(actual_actor.monitor_joined_at.is_some());
    assert!(actual_actor.cutoff.as_ref().unwrap().joined_at.is_some());
    assert_eq!(actual_cutoff_calls.load(Ordering::SeqCst), 1);
    assert!(original_cutoff.upgrade().is_some());
    assert!(owner.execution_task.is_none());
    assert!(owner.bus0_task.is_none());
    assert!(owner.voltage_task.is_none());
    let blocked = owner.initialization_callers.snapshots().pop().unwrap();
    assert!(blocked.pending && blocked.history.joined_at.is_none());
    assert!(blocked.original.worker_returned_at.is_none());
    // All previous release predicates have been observed on the real owners.
    // Only the new retained-exchange pending predicate can refuse this call.
    let refusal = owner.release_joined_heartbeat_cutoff().unwrap_err();
    assert!(refusal.contains("management caller still retains heartbeat cutoff custody"));
    assert!(owner.heartbeat.is_some() && owner.heartbeat_final.is_none());
    assert!(owner
        .heartbeat_release
        .as_ref()
        .unwrap()
        .released_at
        .is_none());
    assert!(original_cutoff.upgrade().is_some());
    assert!(owner.close_receipts().0.is_none() && owner.close_receipts().1.is_none());

    rig.wire.gate.release();
    assert!(owner.join_callers_until(due()).await);
    let joined = owner.initialization_callers.snapshots().pop().unwrap();
    assert!(!joined.pending && joined.history.joined_at.is_some());
    assert!(joined.history.timely_joined_at.is_none());
    assert_eq!(
        joined.history.first_failure,
        cancelled.history.first_failure
    );
    assert_eq!(joined.original.reserved_at, cancelled.original.reserved_at);
    assert_eq!(
        joined.original.worker_started_at,
        cancelled.original.worker_started_at
    );
    assert_eq!(joined.original.original_deadline, original_deadline);
    assert_eq!(joined.history.original_deadline, original_deadline);
    assert!(joined.original.worker_finalized_at.is_some());
    assert_eq!(
        joined.original.steps.last().unwrap().returned_count,
        Some(8)
    );
    assert_eq!(rig.wire.writes(), [0x22]);
    assert!(owner.release_joined_heartbeat_cutoff().unwrap());
    assert!(owner.heartbeat.is_none() && owner.heartbeat_final.is_some());
    assert!(original_cutoff.upgrade().is_none());
    let release = owner.heartbeat_release.as_ref().unwrap();
    assert!(release.first_failure.as_ref().unwrap().contains(&refusal));
    assert!(release.released_at.is_some());
    assert_eq!(actual_cutoff_calls.load(Ordering::SeqCst), 1);
    assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).unwrap());
    assert!(owner.close_receipts().0.is_some() && owner.close_receipts().1.is_some());
}

#[path = "bb_initialization_worker_custody_tests.rs"]
mod worker_custody;
