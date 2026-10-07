//! Component tests use original diagnostic services and real actor sweeps.
//! No initialization-complete capability or physical rail state is synthesized.
use super::*;
use crate::bb_management_owner::BbHeartbeatCutoff;
use crate::bb_management_runtime::wire_sim::{RuntimeWire, WireGate};
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

#[path = "bb_management_owner_execution_test_support.rs"]
mod apw;
#[path = "bb_pre_power_bus0_test_support.rs"]
mod bus0;

struct Cutoff;
impl BbHeartbeatCutoff for Cutoff {
    fn cutoff(&self) -> Result<(), String> {
        Ok(())
    }
}
struct Wire {
    original: Arc<RuntimeWire>,
    enable: AtomicBool,
    position: AtomicUsize,
    fault: AtomicU8,
    calls: Mutex<Vec<(Instant, u8, bool)>>,
    gate: Arc<WireGate>,
}
impl Wire {
    fn new(original: Arc<RuntimeWire>) -> Arc<Self> {
        Arc::new(Self {
            original,
            enable: AtomicBool::new(false),
            position: AtomicUsize::new(0),
            fault: AtomicU8::new(0),
            calls: Mutex::new(Vec::new()),
            gate: WireGate::new(),
        })
    }
    fn writes(&self) -> Vec<u8> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|row| row.2)
            .map(|row| row.1)
            .collect()
    }
}
impl I2cSimBackend for Wire {
    fn service_identity(&self) -> Option<usize> {
        self.original.service_identity()
    }
    fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> crate::Result<usize> {
        self.enable.store(false, Ordering::SeqCst);
        if bytes == [0xde] {
            self.gate.wait();
            return Ok(1);
        }
        if bytes != [0x55, 0xaa, 5, 0x15, 1, 0, 0x1b] {
            return self.original.write(bus, addr, bytes);
        }
        assert_eq!(bus, 0);
        assert!((0x20..=0x22).contains(&addr));
        self.calls
            .lock()
            .unwrap()
            .push((Instant::now(), addr, true));
        self.enable.store(true, Ordering::SeqCst);
        self.position.store(0, Ordering::SeqCst);
        match self.fault.load(Ordering::SeqCst) {
            1 => return Ok(3),
            5 => self.gate.wait(),
            6 => panic!("authored enable write panic"),
            _ => (),
        }
        Ok(bytes.len())
    }
    fn read(&self, bus: u8, addr: u8, bytes: &mut [u8]) -> crate::Result<usize> {
        if !self.enable.load(Ordering::SeqCst) {
            return self.original.read(bus, addr, bytes);
        }
        assert_eq!((bus, bytes.len()), (0, 1));
        let index = self.position.fetch_add(1, Ordering::SeqCst);
        assert!(index < 2);
        self.calls
            .lock()
            .unwrap()
            .push((Instant::now(), addr, false));
        match (self.fault.load(Ordering::SeqCst), index) {
            (2, 1) => return Ok(0),
            (3, 1) => {
                return Err(crate::HalError::I2c {
                    bus,
                    addr,
                    detail: "authored second enable read failure".into(),
                })
            }
            (4, 1) => self.gate.wait(),
            _ => (),
        }
        bytes[0] = [0x00, 0xff][index];
        Ok(1)
    }
    fn write_read(&self, bus: u8, addr: u8, bytes: &[u8], out: &mut [u8]) -> crate::Result<()> {
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
        self.wire.gate.release();
        self.wire.original.release();
        self.a.release();
        self.b.release();
    }
}
fn due() -> Instant {
    Instant::now() + Duration::from_secs(20)
}
async fn until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(5)).await;
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
async fn stable(owner: &mut BbManagementOwner, selected: &[u8]) {
    diagnose(owner, selected).await;
    owner.start_heartbeat(Arc::new(Cutoff)).unwrap();
    assert!(
        owner
            .wait_stable_heartbeat_until(due())
            .await
            .unwrap()
            .consecutive_complete_sweeps
            >= 5
    );
}
async fn finish(owner: &mut BbManagementOwner) {
    assert!(owner.join_callers_until(due()).await);
    owner.release_joined_heartbeat_cutoff().unwrap();
    assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_selected_three_slots_keep_raw_reply_and_exact_minimum_waits() {
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x52, 0x50, 0x51]).await;
    for (index, addr) in [0x22, 0x20, 0x21].into_iter().enumerate() {
        let prepared = owner.prepare_selected_pic_enable(index, due()).unwrap();
        let view = prepared.observation();
        tokio::task::spawn_blocking(move || prepared.run())
            .await
            .unwrap();
        let actual = view.snapshot();
        assert_eq!(actual.pic_address, addr);
        assert_eq!(actual.native_slot, usize::from(addr - 0x20));
        assert!(
            actual.first_failure.is_none() && actual.timely_receipt_at.is_some(),
            "{actual:?}"
        );
        let reads: Vec<_> = actual
            .steps
            .iter()
            .filter_map(|step| step.returned_bytes.clone())
            .collect();
        assert_eq!(reads, [vec![0], vec![0xff]]);
        let waits: Vec<_> = actual
            .steps
            .iter()
            .filter_map(|step| match &step.operation {
                crate::i2c::bb_pic_enable::Operation::Wait(duration) => {
                    assert!(step.returned_at.unwrap().duration_since(step.started_at) >= *duration);
                    Some(duration.as_millis())
                }
                _ => None,
            })
            .collect();
        assert_eq!(waits, [50, 20, 20, 50]);
        assert!(
            actual
                .transport_completed_at
                .unwrap()
                .duration_since(actual.worker_started_at.unwrap())
                >= Duration::from_millis(140)
        );
    }
    assert_eq!(rig.wire.writes(), [0x22, 0x20, 0x21]);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_actor_and_first_real_sweep_refuse_before_preparation() {
    for start in [false, true] {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x50]).await;
        if start {
            owner.start_heartbeat(Arc::new(Cutoff)).unwrap();
            until(|| owner.heartbeat_snapshot().unwrap().complete_sweeps >= 1).await;
            assert!(owner.heartbeat_snapshot().unwrap().complete_sweeps < 5);
        }
        assert!(owner.prepare_selected_pic_enable(0, due()).is_err());
        assert!(rig.wire.writes().is_empty());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_generation_cannot_refresh_after_a_real_reserved_disable() {
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x50]).await;
    let prepared = owner.prepare_selected_pic_enable(0, due()).unwrap();
    let view = prepared.observation();
    let handle = owner.handles.bus0.clone();
    let disable = tokio::task::spawn_blocking(move || handle.disable_bb_pic_at(0, due()))
        .await
        .unwrap();
    assert!(
        disable.timely_receipt_at.is_some(),
        "{:?}",
        disable.worker_snapshot()
    );
    // Observe the original live actor immediately before this caller; a
    // heartbeat-stop error must not masquerade as generation refusal.
    owner
        .heartbeat
        .as_ref()
        .unwrap()
        .voltage_gate()
        .observe(view.snapshot().original_deadline)
        .unwrap();
    assert!(!owner.handles.is_stopped());
    tokio::task::spawn_blocking(move || prepared.run())
        .await
        .unwrap();
    let actual = view.snapshot();
    assert!(actual.timely_receipt_at.is_none());
    assert!(
        actual
            .first_failure
            .as_ref()
            .unwrap()
            .contains("queued worker request dropped"),
        "{actual:?}"
    );
    let expected = format!(
        "Energize request generation {} is no longer current",
        actual.original_generation
    );
    assert!(
        actual.caller_error.as_ref().unwrap().contains(&expected),
        "{actual:?}"
    );
    assert!(actual.caller_returned_at.is_some() && actual.caller_unwound_at.is_none());
    assert!(actual.worker_returned_at.is_none() && actual.transport_completed_at.is_none());
    assert!(actual.worker_started_at.is_none() && rig.wire.writes().is_empty());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_while_original_write_is_inflight_retains_count_and_refuses_reads() {
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x50]).await;
    rig.wire.fault.store(5, Ordering::SeqCst);
    let prepared = owner.prepare_selected_pic_enable(0, due()).unwrap();
    let view = prepared.observation();
    let caller = tokio::task::spawn_blocking(move || prepared.run());
    until(|| rig.wire.gate.entered.load(Ordering::SeqCst)).await;
    owner.cancel();
    rig.wire.gate.release();
    caller.await.unwrap();
    let actual = view.snapshot();
    assert!(actual.timely_receipt_at.is_none() && actual.first_failure.is_some());
    assert_eq!(actual.steps.last().unwrap().returned_count, Some(7));
    assert_eq!(rig.wire.calls.lock().unwrap().len(), 1);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_second_read_updates_original_view_without_promoting_caller_timeout() {
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x50]).await;
    rig.wire.fault.store(4, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_millis(700);
    let prepared = owner.prepare_selected_pic_enable(0, deadline).unwrap();
    let view = prepared.observation();
    let caller = tokio::task::spawn_blocking(move || prepared.run());
    until(|| rig.wire.gate.entered.load(Ordering::SeqCst)).await;
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        deadline + Duration::from_millis(20),
    ))
    .await;
    caller.await.unwrap();
    let before = view.snapshot();
    assert!(before.timely_receipt_at.is_none() && before.worker_finalized_at.is_none());
    rig.wire.gate.release();
    until(|| view.snapshot().worker_finalized_at.is_some()).await;
    let actual = view.snapshot();
    assert_eq!(
        actual.steps.last().unwrap().returned_bytes,
        Some(vec![0xff])
    );
    assert!(actual.steps.last().unwrap().returned_at.unwrap() >= deadline);
    assert!(actual.timely_receipt_at.is_none() && actual.transport_completed_at.is_none());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn short_write_short_read_and_io_failure_retain_distinct_raw_progress() {
    for fault in [1, 2, 3] {
        let (mut owner, rig) = Rig::new();
        stable(&mut owner, &[0x50]).await;
        rig.wire.fault.store(fault, Ordering::SeqCst);
        let prepared = owner.prepare_selected_pic_enable(0, due()).unwrap();
        let view = prepared.observation();
        tokio::task::spawn_blocking(move || prepared.run())
            .await
            .unwrap();
        let actual = view.snapshot();
        let last = actual.steps.last().unwrap();
        assert!(actual.timely_receipt_at.is_none() && actual.first_failure.is_some());
        match fault {
            1 => assert_eq!(last.returned_count, Some(3)),
            2 => {
                assert_eq!(last.returned_count, Some(0));
                assert_eq!(last.returned_bytes, Some(vec![]));
            }
            3 => {
                assert_eq!(last.returned_count, None);
                assert!(last.error.as_ref().unwrap().contains("authored second"));
            }
            _ => unreachable!(),
        }
        assert_eq!(rig.wire.writes(), [0x20]);
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_unwind_is_retained_without_fabricated_return_or_replay() {
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x50]).await;
    rig.wire.fault.store(6, Ordering::SeqCst);
    let prepared = owner.prepare_selected_pic_enable(0, due()).unwrap();
    let view = prepared.observation();
    tokio::task::spawn_blocking(move || prepared.run())
        .await
        .unwrap();
    let actual = view.snapshot();
    let last = actual.steps.last().unwrap();
    assert!(
        last.unwound_at.is_some() && last.returned_at.is_none() && last.returned_count.is_none()
    );
    assert!(actual.worker_finalized_at.is_some() && actual.timely_receipt_at.is_none());
    assert_eq!(rig.wire.writes(), [0x20]);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_expiry_retains_typed_refusal_and_never_starts_enable_worker() {
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x50]).await;
    let handle = owner.handles.bus0.clone();
    let occupied = tokio::task::spawn_blocking(move || {
        handle.write_bytes_mutating(crate::i2c::I2cMutationLabel::QueryPrelude, 0x20, &[0xde])
    });
    until(|| rig.wire.gate.entered.load(Ordering::SeqCst)).await;
    let prepared = owner
        .prepare_selected_pic_enable(0, Instant::now() + Duration::from_millis(200))
        .unwrap();
    let view = prepared.observation();
    tokio::task::spawn_blocking(move || prepared.run())
        .await
        .unwrap();
    rig.wire.gate.release();
    let _ = occupied.await.unwrap();
    until(|| view.snapshot().worker_finalized_at.is_some()).await;
    let actual = view.snapshot();
    assert!(actual.first_failure.is_some() && actual.worker_started_at.is_none());
    assert!(actual.timely_receipt_at.is_none() && rig.wire.writes().is_empty());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_shot_reservation_survives_abandonment_without_task_or_sender_escape() {
    let (mut owner, rig) = Rig::new();
    stable(&mut owner, &[0x52]).await;
    assert!(owner.prepare_selected_pic_enable(1, due()).is_err());
    let prepared = owner.prepare_selected_pic_enable(0, due()).unwrap();
    let view = prepared.observation();
    assert!(owner.prepare_selected_pic_enable(0, due()).is_err());
    drop(prepared);
    let actual = view.snapshot();
    assert!(actual.first_failure.is_some() && actual.caller_started_at.is_none());
    assert!(owner.prepare_selected_pic_enable(0, due()).is_err());
    assert!(rig.wire.writes().is_empty());
    finish(&mut owner).await;
}

// Descendant fixtures retain the original actors and services without new APIs.
#[path = "bb_management_owner_pic_enable_callers_tests.rs"]
mod retained;
