//! Original Sim workers, real elapsed time and retained task custody. No
//! acceptance, actor timestamps, ready snapshots or replacement rosters enter.
use super::*;
use crate::bb_management_runtime::wire_sim::{RuntimeWire, WireGate};
use crate::bb_management_runtime::{BbHeartbeatCutoff, BbTerminalOperation};
use crate::i2c::spawn_owned_sim_i2c_service;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[path = "bb_management_owner_execution_test_support.rs"]
mod apw;
#[path = "bb_pre_power_bus0_test_support.rs"]
mod bus0;

struct Cutoff {
    calls: AtomicUsize,
    gate: Option<Arc<WireGate>>,
    failure: bool,
}
impl Cutoff {
    fn new(gate: Option<Arc<WireGate>>, failure: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            gate,
            failure,
        })
    }
}
impl BbHeartbeatCutoff for Cutoff {
    fn cutoff(&self) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.gate {
            gate.wait();
        }
        if self.failure {
            Err("authored operational cutoff error; physical state unknown".into())
        } else {
            Ok(())
        }
    }
}
struct Rig {
    a: Arc<bus0::Backend>,
    b: Arc<apw::Backend>,
    wire: Arc<RuntimeWire>,
    cutoff: Arc<Cutoff>,
}
impl Rig {
    fn new(block_apw: bool, cutoff: Arc<Cutoff>) -> (BbManagementOwner, Self) {
        let a = bus0::Backend::new(bus0::Fault::None, None);
        let b = apw::Backend::new(
            0x76,
            0x17,
            0x68,
            None,
            block_apw.then_some((0x83, apw::Phase::Write)),
        );
        let wire = RuntimeWire::new(a.clone());
        let owner = BbManagementOwner::new(
            spawn_owned_sim_i2c_service(0, wire.clone(), (0x50..=0x57).collect()).unwrap(),
            spawn_owned_sim_i2c_service(1, b.clone(), (0x50..=0x57).collect()).unwrap(),
        );
        (owner, Self { a, b, wire, cutoff })
    }
}
impl Drop for Rig {
    fn drop(&mut self) {
        self.a.release();
        self.b.release();
        self.wire.release();
        if let Some(gate) = &self.cutoff.gate {
            gate.release();
        }
    }
}
struct ReleaseGate(Arc<WireGate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}
fn due() -> Instant {
    Instant::now() + Duration::from_secs(20)
}
async fn until(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
async fn diagnose(owner: &mut BbManagementOwner, selected: &[u8]) {
    let result = owner.observe_pre_power_once(selected, due()).await;
    assert!(
        result.stopped_at.is_none() && result.diagnostics.historical.is_some(),
        "{result:?}"
    );
    owner.merge_requested_voltage(Some(13.4), None).unwrap();
}
async fn stable(owner: &mut BbManagementOwner, rig: &Rig, selected: &[u8]) {
    diagnose(owner, selected).await;
    owner.start_heartbeat(rig.cutoff.clone()).unwrap();
    let observed = owner.wait_stable_heartbeat_until(due()).await.unwrap();
    assert!(observed.consecutive_complete_sweeps >= 5);
    assert!(
        observed
            .last_complete_at
            .unwrap()
            .duration_since(observed.started_at)
            >= Duration::from_millis(5050)
    );
}
async fn finish(owner: &mut BbManagementOwner) {
    assert!(owner.join_callers_until(due()).await);
    owner.release_joined_heartbeat_cutoff().unwrap();
    assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).unwrap());
    assert!(owner.close_receipts().0.is_some() && owner.close_receipts().1.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_actor_and_actual_first_sweep_refuse_before_voltage_reservation_or_wire() {
    for start_actor in [false, true] {
        let (mut owner, rig) = Rig::new(false, Cutoff::new(None, false));
        diagnose(&mut owner, &[0x50]).await;
        if start_actor {
            owner.start_heartbeat(rig.cutoff.clone()).unwrap();
            until(|| owner.heartbeat_snapshot().unwrap().complete_sweeps >= 1).await;
            let actual = owner.heartbeat_snapshot().unwrap();
            assert!(actual.complete_sweeps < 5);
        }
        let before = rig.b.opcodes();
        assert!(owner.execute_voltage_once(due()).await.is_err());
        let observed = owner.snapshot();
        assert!(observed.latest_execution.is_none() && observed.last_complete_execution.is_none());
        assert_eq!(observed.committed_request_history.previous_request, None);
        assert_eq!(rig.b.opcodes(), before);
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn five_real_sweeps_bind_reservation_and_actual_apw_caller_admission() {
    for selected in [&[0x50][..], &[0x52, 0x50, 0x51][..]] {
        let (mut owner, rig) = Rig::new(false, Cutoff::new(None, false));
        stable(&mut owner, &rig, selected).await;
        let deadline = due();
        let result = owner.execute_voltage_once(deadline).await.unwrap();
        assert!(result.stopped_at.is_none(), "{result:?}");
        let actual = result.last_complete_execution.unwrap();
        assert!(actual.heartbeat_reserved_sweep >= 5);
        assert!(actual.heartbeat_caller_sweep.unwrap() >= actual.heartbeat_reserved_sweep);
        assert!(actual.heartbeat_reserved_at <= actual.heartbeat_caller_admitted_at.unwrap());
        assert!(
            actual.heartbeat_caller_admitted_at.unwrap()
                <= actual.attempt.as_ref().unwrap().caller_started_at
        );
        assert!(actual.accepted_at.unwrap() < deadline);
        assert_eq!(
            result.committed_request_history.previous_request,
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
        finish(&mut owner).await;
    }
}

#[test]
fn queued_actual_voltage_caller_rechecks_original_deadline_before_any_apw_query() {
    // One blocking thread retains the real heartbeat caller; the second is
    // occupied by this actual gate only after bus0's real caller has joined.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (mut owner, rig) = Rig::new(false, Cutoff::new(None, false));
        stable(&mut owner, &rig, &[0x50]).await;
        let deadline = Instant::now() + Duration::from_secs(3);
        owner.begin_execution(deadline).unwrap();
        owner.bus0_task = Some(runtime_bus0::start(&owner.state, &owner.handles, deadline));
        assert!(
            runtime_bus0::join_until(
                &mut owner.bus0_task,
                &owner.state,
                &owner.handles,
                deadline,
                true
            )
            .await
        );
        let gate = WireGate::new();
        let _release = ReleaseGate(gate.clone());
        let work = gate.clone();
        let blocker = tokio::task::spawn_blocking(move || work.wait());
        until(|| gate.entered.load(Ordering::SeqCst)).await;
        let before = rig.b.opcodes();
        assert!(owner.start_execution_caller(deadline));
        assert!(owner
            .snapshot()
            .latest_execution
            .unwrap()
            .heartbeat_caller_admitted_at
            .is_none());
        tokio::time::sleep_until((deadline + Duration::from_millis(30)).into()).await;
        gate.release();
        blocker.await.unwrap();
        assert!(
            join_until(
                &mut owner.execution_task,
                &owner.state,
                &owner.handles,
                due(),
                false
            )
            .await
        );
        let actual = owner.snapshot().latest_execution.unwrap();
        assert!(actual.heartbeat_caller_admitted_at.is_none() && actual.attempt.is_none());
        assert!(actual.failure.unwrap().contains("deadline"));
        assert_eq!(rig.b.opcodes(), before);
        finish(&mut owner).await;
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_real_warmup_retains_joins_and_automatic_callback_release_observation() {
    let (mut runtime, _fixture) =
        crate::bb_management_runtime::simulated::Fixture::new(false, false);
    assert!(runtime
        .observe_initial_until(&[0x50], due())
        .await
        .unwrap()
        .diagnostic_complete());
    let cutoff = Cutoff::new(None, true);
    runtime.start_heartbeat(cutoff.clone()).unwrap();
    assert!(runtime.release_joined_heartbeat_cutoff().is_err());
    {
        let waiting = runtime.wait_stable_heartbeat_until(due());
        tokio::pin!(waiting);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {},
            result = &mut waiting => panic!("first incomplete sweep admitted warmup: {result:?}"),
        }
    }
    assert!(runtime.snapshot().stopped());
    assert!(runtime.start_heartbeat(cutoff.clone()).is_err());
    assert!(runtime.close_until(due()).await);
    let joined = runtime.heartbeat_snapshot().unwrap();
    assert!(joined.caller_joined_at.is_some() && joined.monitor_joined_at.is_some());
    let callback = joined.cutoff.unwrap();
    assert!(callback.result.unwrap().is_err() && callback.joined_at.is_some());
    let release = runtime.heartbeat_release_observation().unwrap();
    assert!(release.first_failure.is_some());
    assert!(callback.joined_at.unwrap() <= release.released_at.unwrap());
    assert_eq!(Arc::strong_count(&cutoff), 1);
    assert!(runtime.close_receipts().0.is_some() && runtime.close_receipts().1.is_some());
    assert!(runtime
        .terminal_snapshot()
        .unwrap()
        .caller_joined_at
        .is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heartbeat_fault_cuts_independently_while_original_apw_caller_is_borrowed() {
    let (mut owner, rig) = Rig::new(true, Cutoff::new(None, false));
    stable(&mut owner, &rig, &[0x50]).await;
    {
        let execution = owner.execute_voltage_once(due());
        tokio::pin!(execution);
        tokio::select! {
            _ = rig.b.wait_entered() => {},
            result = &mut execution => panic!("actual APW set did not remain in flight: {result:?}"),
        }
        rig.wire.fail_heartbeat();
        // The borrowed operation is deliberately not polled here. The retained
        // monitor and its cutoff caller must operate independently of it.
        until(|| rig.cutoff.calls.load(Ordering::SeqCst) == 1).await;
        assert_eq!(rig.b.opcodes().last(), Some(&0x83));
    }
    let stopped = owner.snapshot();
    assert!(stopped.stopped_at.is_some() && stopped.execution_caller_pending);
    assert!(
        owner.handles.bus0.terminal_safe_off_is_latched()
            && owner.handles.bus1.terminal_safe_off_is_latched()
    );
    assert_eq!(stopped.committed_request_history.previous_request, None);
    rig.b.release();
    finish(&mut owner).await;
    assert!(owner.snapshot().last_complete_execution.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_terminal_sweep_runs_after_callback_entry_without_waiting_for_return_and_never_replays(
) {
    let gate = WireGate::new();
    let cutoff = Cutoff::new(Some(gate.clone()), false);
    let (mut owner, rig) = Rig::new(false, cutoff.clone());
    diagnose(&mut owner, &[0x52, 0x50, 0x51]).await;
    owner.start_heartbeat(cutoff.clone()).unwrap();
    until(|| owner.heartbeat_snapshot().unwrap().complete_sweeps >= 1).await;
    let original = due();
    {
        let cleanup = owner.join_callers_until(original);
        tokio::pin!(cleanup);
        tokio::select! {
            _ = until(|| rig.wire.events().iter().filter(|event| event.opcode == 0x15 && !event.write).count() == 6) => {},
            result = &mut cleanup => panic!("blocked original cutoff unexpectedly joined: {result}"),
        }
    }
    assert!(gate.entered.load(Ordering::SeqCst));
    assert!(owner.release_joined_heartbeat_cutoff().is_err());
    assert!(owner
        .close_services_until(Instant::now() + Duration::from_millis(20))
        .is_err());
    gate.release();
    finish(&mut owner).await;
    let terminal = owner.terminal_snapshot().unwrap();
    assert_eq!(terminal.original_deadline, original);
    assert!(terminal.failure.is_none() && terminal.joined_within_original_deadline);
    assert_eq!(
        terminal
            .selected
            .iter()
            .map(|pic| pic.native_slot.unwrap())
            .collect::<Vec<_>>(),
        [2, 0, 1]
    );
    let callback = owner.heartbeat_snapshot().unwrap().cutoff.unwrap();
    for pic in &terminal.selected {
        let worker = pic.worker.as_ref().unwrap();
        assert!(callback.started_at.unwrap() <= worker.worker_started_at.unwrap());
        assert_eq!(worker.original_deadline, original);
        assert!(pic.caller_prepared_at.unwrap() <= pic.caller_started_at.unwrap());
        assert!(pic.caller_started_at.unwrap() <= pic.caller_returned_at.unwrap());
        assert!(worker.transport_completed_at.is_some() && pic.timely_receipt_at.is_some());
        let reads: Vec<_> = worker
            .steps
            .iter()
            .filter(|step| matches!(step.operation, BbTerminalOperation::ReadReply))
            .map(|step| step.returned_bytes.clone().unwrap())
            .collect();
        assert_eq!(reads, [vec![0x15], vec![0]]);
    }
    let writes = rig
        .wire
        .events()
        .iter()
        .filter(|event| event.opcode == 0x15 && event.write)
        .count();
    assert_eq!(writes, 3);
    assert!(owner.join_callers_until(due()).await);
    assert_eq!(
        rig.wire
            .events()
            .iter()
            .filter(|event| event.opcode == 0x15 && event.write)
            .count(),
        writes
    );
    assert_eq!(
        owner.terminal_snapshot().unwrap().original_deadline,
        original
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_read_error_and_started_late_read_keep_original_partial_worker_evidence() {
    for late in [false, true] {
        let (mut owner, rig) = Rig::new(false, Cutoff::new(None, false));
        diagnose(&mut owner, &[0x50]).await;
        owner.start_heartbeat(rig.cutoff.clone()).unwrap();
        until(|| owner.heartbeat_snapshot().unwrap().complete_sweeps >= 1).await;
        let deadline = Instant::now() + Duration::from_secs(2);
        if late {
            let gate = rig.wire.block_second_disable_read();
            {
                let cleanup = owner.join_callers_until(deadline);
                tokio::pin!(cleanup);
                tokio::select! {
                    _ = until(|| gate.entered.load(Ordering::SeqCst)) => {},
                    result = &mut cleanup => panic!("original second read did not block: {result}"),
                }
                tokio::time::sleep_until((deadline + Duration::from_millis(30)).into()).await;
            }
            assert!(owner.join_callers_until(due()).await);
            owner.release_joined_heartbeat_cutoff().unwrap();
            assert!(!tokio::task::block_in_place(
                || owner.close_services_until(Instant::now() + Duration::from_millis(30))
            )
            .unwrap());
            assert!(owner.close_receipts().0.is_none());
            let pending = owner.terminal_snapshot().unwrap().selected.remove(0);
            assert!(pending.timely_receipt_at.is_none() && pending.failure.is_some());
            gate.release();
        } else {
            rig.wire.fail_second_disable_read();
            assert!(owner.join_callers_until(deadline).await);
        }
        finish(&mut owner).await;
        let terminal = owner.terminal_snapshot().unwrap();
        assert_eq!(terminal.original_deadline, deadline);
        let pic = &terminal.selected[0];
        assert!(pic.failure.is_some() && pic.timely_receipt_at.is_none());
        let worker = pic.worker.as_ref().unwrap();
        assert!(worker.failure.is_some() && worker.transport_completed_at.is_none());
        let reads: Vec<_> = worker
            .steps
            .iter()
            .filter(|step| matches!(step.operation, BbTerminalOperation::ReadReply))
            .collect();
        assert_eq!(reads.len(), 2);
        assert_eq!(reads[0].returned_bytes, Some(vec![0x15]));
        if late {
            assert_eq!(reads[1].returned_bytes, Some(vec![0]));
            assert!(reads[1].returned_at.unwrap() >= deadline);
        } else {
            assert!(reads[1].error.is_some());
        }
        assert_eq!(
            rig.wire
                .events()
                .iter()
                .filter(|event| event.opcode == 0x15 && event.write)
                .count(),
            1
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_live_gate_blocks_callback_release_even_after_tasks_join_then_final_data_survives()
{
    let (mut owner, rig) = Rig::new(false, Cutoff::new(None, true));
    diagnose(&mut owner, &[0x50]).await;
    owner.start_heartbeat(rig.cutoff.clone()).unwrap();
    let gate = owner.heartbeat.as_ref().unwrap().voltage_gate();
    assert!(owner.join_callers_until(due()).await);
    assert!(owner.release_joined_heartbeat_cutoff().is_err());
    assert!(Arc::strong_count(&rig.cutoff) > 1);
    assert!(owner.close_services_until(due()).is_err());
    assert!(owner.close_receipts().0.is_none() && owner.close_receipts().1.is_none());
    drop(gate);
    assert!(owner.release_joined_heartbeat_cutoff().unwrap());
    assert_eq!(Arc::strong_count(&rig.cutoff), 1);
    assert!(owner
        .heartbeat_snapshot()
        .unwrap()
        .cutoff
        .unwrap()
        .result
        .unwrap()
        .is_err());
    assert!(owner.start_heartbeat(rig.cutoff.clone()).is_err());
    let record = owner.snapshot().heartbeat_release.unwrap();
    assert!(record.first_failure.is_some() && record.released_at.is_some());
    finish(&mut owner).await;
}
