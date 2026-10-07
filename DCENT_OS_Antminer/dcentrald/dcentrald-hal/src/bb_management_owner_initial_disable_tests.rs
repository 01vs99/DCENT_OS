//! Authored tests only: original simulated service workers and actual timers.
//! No timestamp, caller receipt, selected roster or heartbeat readiness injection.
use super::*;
use crate::bb_management_runtime::wire_sim::RuntimeWire;
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

#[path = "bb_management_owner_execution_test_support.rs"]
mod apw;
#[path = "bb_pre_power_bus0_test_support.rs"]
mod bus0;

const DISABLE: [u8; 7] = [0x55, 0xaa, 5, 0x15, 0, 0, 0x1a];

struct Wire {
    original: Arc<RuntimeWire>,
    active: AtomicBool,
    read_index: AtomicUsize,
    fault: AtomicU8,
    writes: Mutex<Vec<(Instant, u8, Vec<u8>)>>,
}
impl Wire {
    fn new(original: Arc<RuntimeWire>) -> Arc<Self> {
        Arc::new(Self {
            original,
            active: AtomicBool::new(false),
            read_index: AtomicUsize::new(0),
            fault: AtomicU8::new(0),
            writes: Mutex::new(Vec::new()),
        })
    }
    fn disable_addresses(&self) -> Vec<u8> {
        self.writes
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, _, bytes)| bytes == &DISABLE)
            .map(|(_, addr, _)| *addr)
            .collect()
    }
}
impl I2cSimBackend for Wire {
    fn service_identity(&self) -> Option<usize> {
        self.original.service_identity()
    }
    fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> crate::Result<usize> {
        self.writes
            .lock()
            .unwrap()
            .push((Instant::now(), addr, bytes.to_vec()));
        let disable = bytes == DISABLE;
        self.active.store(disable, Ordering::SeqCst);
        self.read_index.store(0, Ordering::SeqCst);
        if disable && self.fault.load(Ordering::SeqCst) == 1 {
            return Ok(3);
        }
        self.original.write(bus, addr, bytes)
    }
    fn read(&self, bus: u8, addr: u8, bytes: &mut [u8]) -> crate::Result<usize> {
        if self.active.load(Ordering::SeqCst) && self.read_index.fetch_add(1, Ordering::SeqCst) == 1
        {
            match self.fault.load(Ordering::SeqCst) {
                2 => {
                    return Err(crate::HalError::I2c {
                        bus,
                        addr,
                        detail: "authored initial-disable second read failure".into(),
                    })
                }
                3 => return Ok(0),
                4 => panic!("authored initial-disable second read panic"),
                _ => (),
            }
        }
        self.original.read(bus, addr, bytes)
    }
    fn write_read(&self, bus: u8, addr: u8, bytes: &[u8], out: &mut [u8]) -> crate::Result<()> {
        self.active.store(false, Ordering::SeqCst);
        self.original.write_read(bus, addr, bytes, out)
    }
}
struct Rig {
    a: Arc<bus0::Backend>,
    b: Arc<apw::Backend>,
    wire: Arc<Wire>,
}
impl Rig {
    fn new() -> (BbManagementOwner, Self) {
        let a = bus0::Backend::new(bus0::Fault::None, None);
        let b = apw::Backend::new(0x76, 0x17, 0x68, None, None);
        let wire = Wire::new(RuntimeWire::new(a.clone()));
        let owner = BbManagementOwner::new(
            spawn_owned_sim_i2c_service(0, wire.clone(), (0x50..=0x57).collect()).unwrap(),
            spawn_owned_sim_i2c_service(1, b.clone(), (0x50..=0x57).collect()).unwrap(),
        );
        (owner, Self { a, b, wire })
    }
}
impl Drop for Rig {
    fn drop(&mut self) {
        self.wire.original.release();
        self.a.release();
        self.b.release();
    }
}
fn due() -> Instant {
    Instant::now() + Duration::from_secs(25)
}
async fn until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}
async fn diagnose(owner: &mut BbManagementOwner, selected: &[u8]) {
    let observed = owner.observe_pre_power_once(selected, due()).await;
    assert!(
        observed.diagnostics.historical.is_some() && observed.stopped_at.is_none(),
        "{observed:?}"
    );
}
async fn finish(owner: &mut BbManagementOwner) {
    assert!(owner.join_callers_until(due()).await);
    owner.release_joined_heartbeat_cutoff().unwrap();
    assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).unwrap());
}
struct Cutoff(AtomicUsize);
impl super::super::BbHeartbeatCutoff for Cutoff {
    fn cutoff(&self) -> Result<(), String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_and_original_ordered_three_slots_continue_to_real_five_sweeps_and_voltage_then_terminal(
) {
    for selected in [&[0x50][..], &[0x52, 0x50, 0x51][..]] {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, selected).await;
        // Request actual voltage work; the default profile has no target.
        owner.merge_requested_voltage(Some(13.4), None).unwrap();
        let backend = rig.wire.service_identity().unwrap();
        let deadline = due();
        owner.initial_disable_until(deadline).await.unwrap();
        owner.require_initial_disable_complete().unwrap();
        assert!(!owner.handles.is_stopped());
        let original = owner.initial_disable_snapshot().unwrap();
        assert!(!original.pending && original.history.timely_joined_at.is_some());
        assert_eq!(original.original.original_deadline, deadline);
        assert_eq!(
            rig.wire.disable_addresses(),
            selected
                .iter()
                .map(|addr| addr - 0x50 + 0x20)
                .collect::<Vec<_>>()
        );
        for (index, slot) in original.original.slots.iter().enumerate() {
            assert_eq!(slot.factory_address, selected[index]);
            assert_eq!(
                slot.committed_generation,
                Some(original.original.original_generation + index as u64 + 1)
            );
            assert_eq!(
                slot.generation_observed_after_worker_receipt,
                slot.committed_generation
            );
            assert!(slot.enqueued_at.unwrap() <= slot.worker.worker_started_at.unwrap());
            assert!(slot.worker.worker_finalized_at.unwrap() <= slot.caller_returned_at.unwrap());
            assert!(slot.timely_receipt_at.unwrap() < deadline);
            let raw = slot
                .worker
                .steps
                .iter()
                .filter_map(|step| {
                    matches!(
                        &step.operation,
                        crate::i2c::bb_pic_disable::Operation::ReadReply
                    )
                    .then(|| step.returned_bytes.clone().unwrap())
                })
                .collect::<Vec<_>>();
            assert_eq!(raw, vec![vec![0x15], vec![0]]); // Raw, unvalidated bytes.
        }
        let cutoff = Arc::new(Cutoff(AtomicUsize::new(0)));
        owner.start_heartbeat(cutoff.clone()).unwrap();
        assert!(owner.require_stable_heartbeat().is_err());
        let stable = owner.wait_stable_heartbeat_until(due()).await.unwrap();
        assert!(stable.consecutive_complete_sweeps >= 5);
        let actual = owner.execute_voltage_once(due()).await.unwrap();
        assert!(actual.stopped_at.is_none(), "{actual:?}");
        let completed = actual.last_complete_execution.as_ref().unwrap();
        assert!(completed.heartbeat_reserved_sweep >= 5);
        assert!(completed.heartbeat_caller_sweep.unwrap() >= completed.heartbeat_reserved_sweep);
        assert!(completed.accepted_at.unwrap() < completed.deadline);
        let attempt = completed.attempt.as_ref().unwrap();
        assert!(attempt.failure.is_none());
        assert_eq!(attempt.selected_pair.unwrap().target, 13.4);
        assert_eq!(
            attempt.exchange.as_ref().unwrap().phase,
            crate::bb_apw_voltage_exchange::Phase::Complete
        );
        assert_eq!(
            actual.committed_request_history.previous_request,
            Some(13.75)
        );
        assert_eq!(
            rig.b
                .opcodes()
                .iter()
                .filter(|opcode| **opcode == 0x83)
                .count(),
            1
        );
        assert_eq!(rig.wire.service_identity(), Some(backend));
        finish(&mut owner).await;
        assert!(owner.handles.is_stopped());
        assert!(owner.require_initial_disable_complete().is_err());
        assert!(cutoff.0.load(Ordering::SeqCst) >= 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unjoined_expired_and_terminal_entry_never_mint_a_sweep_or_write_disable() {
    for kind in 0..3 {
        let (mut owner, rig) = Rig::new();
        if kind != 0 {
            diagnose(&mut owner, &[0x50]).await;
        }
        if kind == 2 {
            owner.handles.bus0.latch_terminal_safe_off();
        }
        let deadline = if kind == 1 { Instant::now() } else { due() };
        assert!(owner.initial_disable_until(deadline).await.is_err());
        assert!(owner.initial_disable_snapshot().is_none());
        assert!(rig.wire.disable_addresses().is_empty());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_sweep_is_one_shot_and_pending_phase_refuses_profile_mutation_without_refresh() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x50]).await;
    let gate = rig.wire.original.block_second_disable_read();
    owner.start_initial_disable(due()).unwrap();
    until(|| gate.entered.load(Ordering::SeqCst)).await;
    assert!(owner.initial_disable.pending());
    assert!(owner.merge_requested_voltage(Some(14.0), None).is_err());
    assert!(owner.require_initial_disable_complete().is_err());
    assert!(owner.start_initial_disable(due()).is_err());
    gate.release();
    let original_deadline = owner
        .initial_disable_snapshot()
        .unwrap()
        .original
        .original_deadline;
    assert!(
        join_until(
            &mut owner.initial_disable,
            &owner.state,
            &owner.handles,
            original_deadline,
            false
        )
        .await
    );
    owner.require_initial_disable_complete().unwrap();
    let before = rig.wire.disable_addresses();
    assert!(owner.initial_disable_until(due()).await.is_err());
    assert_eq!(rig.wire.disable_addresses(), before);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_late_second_read_remains_worker_pending_after_caller_and_never_promotes_cleanup() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x50]).await;
    let gate = rig.wire.original.block_second_disable_read();
    let deadline = Instant::now() + Duration::from_millis(250);
    assert!(owner.initial_disable_until(deadline).await.is_err());
    assert!(gate.entered.load(Ordering::SeqCst));
    until(|| {
        owner
            .initial_disable_snapshot()
            .unwrap()
            .original
            .caller_finalized_at
            .is_some()
    })
    .await;
    let before = owner.initial_disable_snapshot().unwrap();
    assert!(before.pending && before.history.timely_joined_at.is_none());
    assert_eq!(
        before.original.slots[0]
            .worker
            .steps
            .iter()
            .filter(|step| {
                matches!(
                    &step.operation,
                    crate::i2c::bb_pic_disable::Operation::ReadReply
                ) && step.returned_at.is_some()
            })
            .count(),
        1
    );
    assert!(owner.close_services_until(due()).is_err());
    assert!(owner.close_receipts().0.is_none() && owner.close_receipts().1.is_none());
    assert!(
        !join_until(
            &mut owner.initial_disable,
            &owner.state,
            &owner.handles,
            Instant::now() + Duration::from_millis(30),
            true
        )
        .await
    );
    gate.release();
    finish(&mut owner).await;
    let late = owner.initial_disable_snapshot().unwrap();
    assert!(!late.pending && late.history.timely_joined_at.is_none());
    assert!(late.original.slots[0].worker.worker_finalized_at.unwrap() >= deadline);
    assert!(late.original.slots[0].worker.steps.iter().any(|step| {
        matches!(
            &step.operation,
            crate::i2c::bb_pic_disable::Operation::ReadReply
        ) && step.returned_at.is_some_and(|at| at >= deadline)
    }));
    assert_eq!(late.original.original_deadline, deadline);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_original_wait_keeps_caller_worker_and_both_service_owners_until_join() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x52, 0x50]).await;
    let gate = rig.wire.original.block_second_disable_read();
    let deadline = due();
    assert!(tokio::time::timeout(
        Duration::from_millis(180),
        owner.initial_disable_until(deadline)
    )
    .await
    .is_err());
    assert!(gate.entered.load(Ordering::SeqCst));
    let stopped = owner.initial_disable_snapshot().unwrap();
    assert!(stopped.pending && stopped.history.waits[0].cancelled_at.is_some());
    assert!(owner.handles.is_stopped());
    assert!(owner.close_services_until(due()).is_err());
    gate.release();
    finish(&mut owner).await;
    let done = owner.initial_disable_snapshot().unwrap();
    assert!(done.history.timely_joined_at.is_none());
    assert!(done.original.slots[1].caller_started_at.is_none());
    assert_eq!(rig.wire.disable_addresses(), vec![0x22]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_partial_write_short_read_error_and_worker_unwind_keep_raw_failure_and_stop_later_slots(
) {
    for fault in 1..=4 {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x50, 0x52]).await;
        rig.wire.fault.store(fault, Ordering::SeqCst);
        assert!(owner.initial_disable_until(due()).await.is_err());
        assert!(owner.handles.is_stopped());
        if fault == 4 {
            // A panicked worker is joined, but cannot mint a clean bus-0 receipt.
            // Keep the exact original caller/worker cleanup and independent bus-1 close.
            let cleanup_deadline = due();
            assert!(owner.join_callers_until(cleanup_deadline).await);
            owner.release_joined_heartbeat_cutoff().unwrap();
            assert!(!tokio::task::block_in_place(|| {
                owner.close_services_until(cleanup_deadline)
            })
            .unwrap());
            let closed = owner.snapshot();
            assert_eq!(closed.diagnostics.close_attempts.len(), 1);
            let close = &closed.diagnostics.close_attempts[0];
            assert_eq!(close.deadline, cleanup_deadline);
            assert!(close.began_at <= close.returned_at && close.returned_at < cleanup_deadline);
            assert_eq!(
                close.bus0_error.as_deref(),
                Some("I2C error on bus 0 addr 0x00: I2C service worker panicked before terminal join")
            );
            assert!(close.bus1_error.is_none());
            assert!(owner.close_receipts().0.is_none());
            assert_eq!(owner.close_receipts().1.unwrap().bus(), 1);
        } else {
            finish(&mut owner).await;
        }
        let observed = owner.initial_disable_snapshot().unwrap();
        let worker = &observed.original.slots[0].worker;
        assert!(worker.transport_completed_at.is_none());
        assert_eq!(worker.worker_returned_at.is_none(), fault == 4);
        if fault == 4 {
            let reads = worker
                .steps
                .iter()
                .filter(|step| {
                    matches!(
                        &step.operation,
                        crate::i2c::bb_pic_disable::Operation::ReadReply
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(reads.len(), 2);
            assert_eq!(reads[0].returned_bytes.as_deref(), Some(&[0x15][..]));
            assert!(reads[0].returned_at.is_some());
            assert!(reads[1].returned_at.is_none());
            assert!(reads[1].returned_bytes.is_none());
            assert!(reads[1].error.is_none()); // Panic did not return a transport error.
        }
        assert!(!observed.pending && observed.history.timely_joined_at.is_none());
        assert!(observed.original.first_failure.is_some());
        assert!(observed.original.slots[0]
            .worker
            .worker_finalized_at
            .is_some());
        assert!(observed.original.slots[1].caller_started_at.is_none());
        assert_eq!(rig.wire.disable_addresses(), vec![0x20]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_safe_off_after_actual_caller_completion_cannot_be_absorbed_by_final_owner_join() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x50]).await;
    let deadline = due();
    owner.start_initial_disable(deadline).unwrap();
    until(|| {
        owner
            .initial_disable_snapshot()
            .unwrap()
            .original
            .caller_finalized_at
            .is_some()
    })
    .await;
    assert!(owner
        .initial_disable_snapshot()
        .unwrap()
        .original
        .first_failure
        .is_none());
    assert!(owner
        .initial_disable
        .caller
        .as_ref()
        .unwrap()
        .original
        .final_generation_current());
    let original = owner.handles.bus0.clone();
    let foreign = tokio::task::spawn_blocking(move || original.disable_bb_pic_at(0, deadline))
        .await
        .unwrap();
    assert!(foreign.timely_receipt_at.is_some());
    assert!(!owner.handles.is_stopped());
    assert!(!owner
        .initial_disable
        .caller
        .as_ref()
        .unwrap()
        .original
        .final_generation_current());
    assert!(
        !join_until(
            &mut owner.initial_disable,
            &owner.state,
            &owner.handles,
            deadline,
            false
        )
        .await
    );
    assert!(owner.require_initial_disable_complete().is_err());
    assert_eq!(rig.wire.disable_addresses(), vec![0x20, 0x20]);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_heartbeat_started_before_initial_reservation_refuses_new_initial_sweep() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x50]).await;
    owner
        .start_heartbeat(Arc::new(Cutoff(AtomicUsize::new(0))))
        .unwrap();
    assert!(owner.initial_disable_until(due()).await.is_err());
    assert!(owner.initial_disable_snapshot().is_none());
    assert!(rig.wire.disable_addresses().is_empty());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_barrier_during_first_worker_cannot_become_the_second_owned_slot_generation() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x50, 0x52]).await;
    let gate = rig.wire.original.block_second_disable_read();
    let deadline = due();
    owner.start_initial_disable(deadline).unwrap();
    until(|| gate.entered.load(Ordering::SeqCst)).await;
    let service = owner.handles.bus0.clone();
    // The existing helper really advances and queues a foreign barrier while
    // the first original worker is borrowed. Its caller timeout is retained;
    // no field, generation, ready DTO or worker timestamp is injected.
    let foreign = tokio::task::spawn_blocking(move || {
        service.disable_bb_pic_at(1, Instant::now() + Duration::from_millis(100))
    })
    .await
    .unwrap();
    assert!(foreign.enqueued && foreign.failure.is_some());
    assert!(foreign.timely_receipt_at.is_none());
    assert!(foreign.worker_snapshot().worker_started_at.is_none());
    gate.release();
    assert!(
        !join_until(
            &mut owner.initial_disable,
            &owner.state,
            &owner.handles,
            deadline,
            false
        )
        .await
    );
    let observed = owner.initial_disable_snapshot().unwrap();
    assert!(observed
        .original
        .first_failure
        .as_ref()
        .unwrap()
        .contains("generation changed outside its own sweep"));
    assert!(observed.original.slots[1].caller_started_at.is_none());
    assert!(owner.handles.is_stopped());
    finish(&mut owner).await;
    assert_eq!(rig.wire.disable_addresses(), vec![0x20]);
    assert!(foreign.worker_snapshot().worker_finalized_at.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_barrier_or_terminal_after_join_refuses_immediate_consumption_without_refresh() {
    for terminal in [false, true] {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x50]).await;
        let deadline = due();
        owner.initial_disable_until(deadline).await.unwrap();
        let joined = owner
            .initial_disable_snapshot()
            .unwrap()
            .history
            .timely_joined_at;
        if terminal {
            owner.handles.bus0.latch_terminal_safe_off();
        } else {
            let service = owner.handles.bus0.clone();
            let foreign =
                tokio::task::spawn_blocking(move || service.disable_bb_pic_at(0, deadline))
                    .await
                    .unwrap();
            assert!(foreign.timely_receipt_at.is_some());
            assert!(!owner.handles.is_stopped());
        }
        assert!(owner.require_initial_disable_complete().is_err());
        let observed = owner.initial_disable_snapshot().unwrap();
        assert_eq!(observed.history.timely_joined_at, joined);
        assert!(observed.history.first_failure.is_some());
        assert!(!observed.history.consumption_checks.last().unwrap().accepted);
        assert!(owner.handles.is_stopped());
        let before = rig.wire.disable_addresses();
        assert!(owner.initial_disable_until(due()).await.is_err());
        assert_eq!(rig.wire.disable_addresses(), before);
        finish(&mut owner).await;
    }
}
