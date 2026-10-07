//! Uses the actual existing diagnostic/initialization worker fixture above it.
//! No ready DTO, model output, generation or timestamp is injected.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_and_ordered_three_original_slots_join_disable_before_each_fresh_bridge() {
    for selected in [&[0x50][..], &[0x52, 0x50, 0x51][..]] {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, selected).await;
        let original_backend = rig.wire.service_identity();
        let deadline = due();
        owner
            .initial_disable_and_bridges_until(deadline)
            .await
            .unwrap();
        let initial = owner.initial_disable_snapshot().unwrap();
        let prefix = owner.initial_bridge_snapshot().unwrap();
        assert_eq!(prefix.selected_addresses, selected);
        assert_eq!(prefix.original_deadline, deadline);
        assert!(!prefix.original_callers_pending && prefix.first_failure.is_none());
        assert!(prefix.accepted_at.unwrap() < deadline);
        assert_eq!(prefix.calls.len(), selected.len());
        let last_disable_finalized = initial
            .original
            .slots
            .iter()
            .map(|slot| slot.worker.worker_finalized_at.unwrap())
            .max()
            .unwrap();
        let final_generation = initial.original.original_generation + selected.len() as u64;
        for (index, call) in prefix.calls.iter().enumerate() {
            let actual = call.original.as_ref().unwrap();
            assert_eq!(call.factory_address, selected[index]);
            assert_eq!(actual.native_slot, usize::from(selected[index] - 0x50));
            assert_eq!(actual.original_generation, final_generation);
            assert_eq!(actual.original_deadline, deadline);
            assert_eq!(actual.phase, Phase::Bridge);
            assert_eq!(
                actual.request_bytes,
                [0x55, 0xaa, 6, 0x3b, 0x48, 0, 0, 0x89]
            );
            assert!(last_disable_finalized <= actual.reserved_at);
            assert!(initial.history.timely_joined_at.unwrap() <= actual.reserved_at);
            assert!(actual.worker_finalized_at.unwrap() <= call.caller_joined_at.unwrap());
            assert!(call.timely_joined_at.unwrap() < deadline);
            assert_eq!(call.original_pending, Some(false));
        }
        let disables: Vec<_> = rig
            .wire
            .original
            .events()
            .iter()
            .filter(|event| event.write && event.opcode == 0x15)
            .map(|event| event.address)
            .collect();
        assert_eq!(
            disables,
            selected
                .iter()
                .map(|address| address - 0x50 + 0x20)
                .collect::<Vec<_>>()
        );
        assert_eq!(rig.wire.packets.lock().unwrap().len(), selected.len());
        assert_eq!(rig.wire.service_identity(), original_backend);
        assert!(!owner.handles.is_stopped());
        assert!(owner.heartbeat_snapshot().is_none());
        assert_eq!(
            rig.b
                .opcodes()
                .iter()
                .filter(|opcode| **opcode == 0x83)
                .count(),
            0
        );
        // A later genuinely NEW component preparation remains supported on the
        // same allocation; no stale already-prepared request is revived.
        owner
            .run_retained_pic_initialization_exchange(0, Phase::StartupHeartbeat, due())
            .await
            .unwrap();
        assert!(!owner.handles.is_stopped());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_initial_worker_timeout_never_starts_bridge_or_renews_prefix_deadline() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x52, 0x50]).await;
    let gate = rig.wire.original.block_second_disable_read();
    let deadline = Instant::now() + Duration::from_millis(250);
    assert!(owner
        .initial_disable_and_bridges_until(deadline)
        .await
        .is_err());
    assert!(gate.entered.load(Ordering::SeqCst));
    let before = owner.initial_bridge_snapshot().unwrap();
    assert!(before.first_failure.is_some() && before.accepted_at.is_none());
    assert!(before.calls.is_empty() && rig.wire.packets.lock().unwrap().is_empty());
    assert!(owner.close_services_until(due()).is_err());
    gate.release();
    finish(&mut owner).await;
    let after = owner.initial_bridge_snapshot().unwrap();
    assert_eq!(after.original_deadline, deadline);
    assert!(after.accepted_at.is_none() && !after.original_callers_pending);
    assert!(owner
        .initial_disable_and_bridges_until(due())
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_actual_bridge_retains_original_caller_and_worker_until_terminal_join() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x50, 0x52]).await;
    rig.wire.fault.store(4, Ordering::SeqCst); // Actual final Bridge read waits.
    assert!(tokio::time::timeout(
        Duration::from_millis(400),
        owner.initial_disable_and_bridges_until(due())
    )
    .await
    .is_err());
    assert!(rig.wire.gate.entered.load(Ordering::SeqCst));
    let canceled = owner.initial_bridge_snapshot().unwrap();
    assert!(canceled.cancelled_at.is_some() && canceled.accepted_at.is_none());
    assert!(canceled.original_callers_pending && owner.handles.is_stopped());
    assert_eq!(canceled.calls.len(), 1);
    assert!(owner.close_services_until(due()).is_err());
    assert!(owner.close_receipts().0.is_none() && owner.close_receipts().1.is_none());
    rig.wire.gate.release();
    finish(&mut owner).await;
    let after = owner.initial_bridge_snapshot().unwrap();
    assert!(!after.original_callers_pending && after.accepted_at.is_none());
    assert!(after.calls[0]
        .original
        .as_ref()
        .unwrap()
        .worker_finalized_at
        .is_some());
    assert_eq!(rig.wire.packets.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_bridge_capture_refuses_actual_foreign_barrier_and_other_service_allocation() {
    for foreign_barrier in [false, true] {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x50]).await;
        let deadline = due();
        owner.initial_disable_until(deadline).await.unwrap();
        owner.require_initial_disable_complete().unwrap();
        let origin = owner.initial_disable.following_phase_origin().unwrap();
        if foreign_barrier {
            // A real reserved operation in the exact guard/capture interval.
            let service = owner.handles.bus0.clone();
            let foreign =
                tokio::task::spawn_blocking(move || service.disable_bb_pic_at(0, deadline))
                    .await
                    .unwrap();
            assert!(foreign.timely_receipt_at.is_some());
            let rejected =
                OriginalService::capture_after_initial_disable(&owner.handles.bus0, &origin);
            assert!(rejected
                .err()
                .unwrap()
                .to_string()
                .contains("generation/allocation"));
            assert!(owner.require_initial_disable_complete().is_err());
        } else {
            let (mut other, _other_rig) = Rig::new();
            diagnose(&mut other, &[0x50]).await;
            other.initial_disable_until(deadline).await.unwrap();
            other.require_initial_disable_complete().unwrap();
            assert_eq!(
                owner
                    .initial_disable_snapshot()
                    .unwrap()
                    .original
                    .original_generation,
                other
                    .initial_disable_snapshot()
                    .unwrap()
                    .original
                    .original_generation
            );
            assert!(
                OriginalService::capture_after_initial_disable(&other.handles.bus0, &origin)
                    .is_err()
            );
            // Equality of selected slots and integer generations cannot bind a
            // different worker allocation; each original still closes itself.
            finish(&mut other).await;
        }
        assert!(rig.wire.packets.lock().unwrap().is_empty());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_bridge_error_preserves_initial_success_and_refuses_remaining_slots() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x52, 0x50]).await;
    rig.wire.fault.store(3, Ordering::SeqCst);
    assert!(owner
        .initial_disable_and_bridges_until(due())
        .await
        .is_err());
    let observed = owner.initial_bridge_snapshot().unwrap();
    assert!(observed.initial_disable_joined_at.is_some());
    assert!(observed.first_failure.is_some() && observed.accepted_at.is_none());
    assert_eq!(observed.calls.len(), 1);
    let original = observed.calls[0].original.as_ref().unwrap();
    assert_eq!(original.factory_address, 0x52);
    assert!(original.worker_finalized_at.is_some() && original.caller_finalized_at.is_some());
    assert!(original.first_failure.is_some());
    assert!(owner.handles.is_stopped());
    finish(&mut owner).await;
    assert_eq!(rig.wire.packets.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prefix_is_one_shot_and_never_substitutes_for_five_stable_heartbeat_sweeps() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x50]).await;
    owner
        .initial_disable_and_bridges_until(due())
        .await
        .unwrap();
    let before = rig.wire.packets.lock().unwrap().clone();
    assert!(owner
        .initial_disable_and_bridges_until(due())
        .await
        .is_err());
    assert_eq!(*rig.wire.packets.lock().unwrap(), before);
    assert!(owner.execute_voltage_once(due()).await.is_err());
    assert!(owner.snapshot().last_complete_execution.is_none());
    assert_eq!(
        rig.b
            .opcodes()
            .iter()
            .filter(|opcode| **opcode == 0x83)
            .count(),
        0
    );
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_barrier_after_real_bridge_worker_and_caller_before_owner_join_refuses_prefix() {
    use std::future::{poll_fn, Future};
    use std::task::Poll;
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x50, 0x52]).await;
    let original_service = owner.handles.bus0.clone();
    let deadline = due();
    let mut prefix = Box::pin(owner.initial_disable_and_bridges_until(deadline));
    // Retain and manually poll the ACTUAL enclosing future, never an invented
    // receipt. Once the first Bridge write exists, stop polling before its join.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if !rig.wire.packets.lock().unwrap().is_empty() {
                break;
            }
            let pending =
                poll_fn(|cx| Poll::Ready(matches!(prefix.as_mut().poll(cx), Poll::Pending))).await;
            assert!(
                pending,
                "prefix completed before retained Bridge rendezvous"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    until(|| {
        rig.wire
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|row| !row.2)
            .count()
            == 2
    })
    .await;
    // This is only fixture scheduling room after the observed final read (the
    // original worker still has its 20 ms wait). Exact original timestamps
    // below must prove worker AND caller completion before the foreign action;
    // if scheduling misses that order, this test fails instead of claiming it.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let foreign =
        tokio::task::spawn_blocking(move || original_service.disable_bb_pic_at(1, deadline))
            .await
            .unwrap();
    assert!(foreign.timely_receipt_at.is_some());
    let foreign_returned = foreign.caller_returned_at.unwrap();
    assert!(prefix.await.is_err());
    let observed = owner.initial_bridge_snapshot().unwrap();
    assert!(observed.accepted_at.is_none() && observed.first_failure.is_some());
    assert_eq!(observed.calls.len(), 1);
    let bridge = &observed.calls[0];
    let actual = bridge.original.as_ref().unwrap();
    assert!(actual.worker_finalized_at.unwrap() < foreign.caller_started_at);
    assert!(actual.caller_finalized_at.unwrap() < foreign.caller_started_at);
    assert!(bridge.caller_joined_at.unwrap() >= foreign_returned);
    assert!(bridge.timely_joined_at.is_some()); // Historical transport only.
    let initial = owner.initial_disable_snapshot().unwrap();
    assert!(!initial.history.consumption_checks.last().unwrap().accepted);
    assert!(owner.handles.is_stopped());
    assert_eq!(rig.wire.packets.lock().unwrap().len(), 1);
    finish(&mut owner).await;
}
