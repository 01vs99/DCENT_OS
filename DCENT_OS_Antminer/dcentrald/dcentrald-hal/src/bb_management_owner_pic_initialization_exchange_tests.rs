//! Original service/diagnostic fixtures run real normal-worker exchanges.
//! No actor, timestamp, receipt or completed initialization is synthesized.
use super::*;
use crate::bb_management_runtime::wire_sim::{RuntimeWire, WireGate};
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

#[path = "bb_management_owner_execution_test_support.rs"]
mod apw;
#[path = "bb_pre_power_bus0_test_support.rs"]
mod bus0;

struct Wire {
    original: Arc<RuntimeWire>,
    active: AtomicBool,
    position: AtomicUsize,
    read_count: AtomicUsize,
    packets: Mutex<Vec<(u8, Vec<u8>)>>,
    fault: AtomicU8,
    calls: Mutex<Vec<(Instant, u8, bool)>>,
    gate: Arc<WireGate>,
}
impl Wire {
    fn new(original: Arc<RuntimeWire>) -> Arc<Self> {
        Arc::new(Self {
            original,
            active: AtomicBool::new(false),
            position: AtomicUsize::new(0),
            read_count: AtomicUsize::new(0),
            packets: Mutex::new(Vec::new()),
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
        self.active.store(false, Ordering::SeqCst);
        if bytes == [0xde] {
            self.gate.wait();
            return Ok(1);
        }
        let count = match bytes {
            [0x55, 0xaa, 6, 0x3b, 0x48, 0, 0, 0x89] => 2,
            [0x55, 0xaa, 4, 0x16, 0, 0x1a] => 6,
            [0x55, 0xaa, 4, 0x3a, 0, 0x3e] => 7,
            _ => return self.original.write(bus, addr, bytes),
        };
        self.read_count.store(count, Ordering::SeqCst);
        self.packets.lock().unwrap().push((addr, bytes.to_vec()));
        assert_eq!(bus, 0);
        assert!((0x20..=0x22).contains(&addr));
        self.calls
            .lock()
            .unwrap()
            .push((Instant::now(), addr, true));
        self.active.store(true, Ordering::SeqCst);
        self.position.store(0, Ordering::SeqCst);
        match self.fault.load(Ordering::SeqCst) {
            1 => return Ok(3),
            5 => self.gate.wait(),
            8 => return Ok(bytes.len() + 1),
            6 => panic!("authored initialization write panic"),
            _ => (),
        }
        Ok(bytes.len())
    }
    fn read(&self, bus: u8, addr: u8, bytes: &mut [u8]) -> crate::Result<usize> {
        if !self.active.load(Ordering::SeqCst) {
            return self.original.read(bus, addr, bytes);
        }
        assert_eq!((bus, bytes.len()), (0, 1));
        let index = self.position.fetch_add(1, Ordering::SeqCst);
        assert!(index < self.read_count.load(Ordering::SeqCst));
        let last = index + 1 == self.read_count.load(Ordering::SeqCst);
        self.calls
            .lock()
            .unwrap()
            .push((Instant::now(), addr, false));
        match (self.fault.load(Ordering::SeqCst), last) {
            (2, true) => return Ok(0),
            (3, true) => {
                return Err(crate::HalError::I2c {
                    bus,
                    addr,
                    detail: "authored final initialization read failure".into(),
                })
            }
            (4, true) => self.gate.wait(),
            (7, true) => {
                bytes[0] = 0xff;
                return Ok(2);
            }
            _ => (),
        }
        bytes[0] = [0x00, 0xff][index % 2];
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
async fn finish(owner: &mut BbManagementOwner) {
    assert!(owner.join_callers_until(due()).await);
    assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).unwrap());
}

const PHASES: [Phase; 4] = [
    Phase::Bridge,
    Phase::StartupHeartbeat,
    Phase::PreEnableRail,
    Phase::FinalRail,
];

// Independent literal oracle from the held initializer rows; no worker helper used.
fn source(phase: Phase) -> (Vec<u8>, usize, Vec<u64>, &'static str) {
    match phase {
        Phase::Bridge => (
            vec![0x55, 0xaa, 6, 0x3b, 0x48, 0, 0, 0x89],
            2,
            vec![20, 20, 20],
            "NeutralControl",
        ),
        Phase::StartupHeartbeat => (
            vec![0x55, 0xaa, 4, 0x16, 0, 0x1a],
            6,
            vec![20, 20, 20, 20, 20, 20, 20, 50],
            "KeepAlive",
        ),
        Phase::PreEnableRail => (
            vec![0x55, 0xaa, 4, 0x3a, 0, 0x3e],
            7,
            vec![50, 20, 20, 20, 20, 20, 20, 20, 50],
            "UnclassifiedMutation",
        ),
        Phase::FinalRail => (
            vec![0x55, 0xaa, 4, 0x3a, 0, 0x3e],
            7,
            vec![50, 20, 20, 20, 20, 20, 20, 20],
            "UnclassifiedMutation",
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn four_fixed_phases_on_three_original_slots_preserve_raw_and_every_source_wait() {
    let (mut owner, rig) = Rig::new();
    diagnose(&mut owner, &[0x52, 0x50, 0x51]).await;
    assert!(owner.heartbeat_snapshot().is_none());
    let deadline = due();
    let mut expected_packets = Vec::new();
    // Component calls only: no initial disable, enable or initializer-complete
    // admission is fabricated by this four-phase transport coverage.
    for (index, addr) in [0x22, 0x20, 0x21].into_iter().enumerate() {
        for phase in PHASES {
            let (packet, count, waits, _) = source(phase);
            let prepared = owner
                .prepare_selected_pic_initialization_exchange(index, phase, deadline)
                .unwrap();
            let view = prepared.observation();
            tokio::task::spawn_blocking(move || prepared.run())
                .await
                .unwrap();
            let actual = view.snapshot();
            assert!(
                actual.timely_receipt_at.is_some() && actual.first_failure.is_none(),
                "{actual:?}"
            );
            assert_eq!(
                (
                    actual.native_slot,
                    actual.factory_address,
                    actual.pic_address
                ),
                (usize::from(addr - 0x20), addr + 0x30, addr)
            );
            assert_eq!(actual.original_deadline, deadline);
            assert_eq!(actual.phase, phase);
            assert_eq!(actual.request_bytes, packet);
            let reads: Vec<_> = actual
                .steps
                .iter()
                .filter_map(|step| step.returned_bytes.clone())
                .collect();
            assert_eq!(
                reads,
                (0..count)
                    .map(|n| vec![[0, 0xff][n % 2]])
                    .collect::<Vec<_>>()
            );
            let actual_waits: Vec<_> = actual
                .steps
                .iter()
                .filter_map(|step| match step.operation {
                    crate::i2c::bb_pic_initialization_exchange::Operation::Wait(duration) => {
                        assert!(
                            step.returned_at.unwrap().duration_since(step.started_at) >= duration
                        );
                        Some(duration.as_millis() as u64)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(actual_waits, waits);
            assert!(
                actual
                    .transport_completed_at
                    .unwrap()
                    .duration_since(actual.worker_started_at.unwrap())
                    >= Duration::from_millis(waits.iter().sum())
            );
            assert!(actual.caller_returned_at.is_some() && actual.worker_finalized_at.is_some());
            assert!(owner
                .prepare_selected_pic_initialization_exchange(index, phase, due())
                .is_err());
            expected_packets.push((addr, packet));
        }
    }
    assert_eq!(*rig.wire.packets.lock().unwrap(), expected_packets);
    assert!(owner.heartbeat_snapshot().is_none());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unjoined_roster_invalid_index_and_expired_deadline_do_not_reserve_or_write() {
    for phase in PHASES {
        let (mut owner, rig) = Rig::new();
        assert!(owner
            .prepare_selected_pic_initialization_exchange(0, phase, due())
            .is_err());
        diagnose(&mut owner, &[0x52]).await;
        assert!(owner
            .prepare_selected_pic_initialization_exchange(1, phase, due())
            .is_err());
        assert!(owner
            .prepare_selected_pic_initialization_exchange(0, phase, Instant::now())
            .is_err());
        let prepared = owner
            .prepare_selected_pic_initialization_exchange(0, phase, due())
            .unwrap();
        let view = prepared.observation();
        assert!(rig.wire.writes().is_empty());
        drop(prepared);
        assert!(view.snapshot().caller_started_at.is_none());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_normal_phase_retains_exact_generation_refusal_after_real_reserved_disable() {
    for phase in PHASES {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x50]).await;
        let prepared = owner
            .prepare_selected_pic_initialization_exchange(0, phase, due())
            .unwrap();
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
        assert!(!owner.handles.is_stopped());
        tokio::task::spawn_blocking(move || prepared.run())
            .await
            .unwrap();
        let actual = view.snapshot();
        let expected = format!(
            "{} request generation {} is no longer current",
            source(phase).3,
            actual.original_generation
        );
        assert!(
            actual.caller_error.as_ref().unwrap().contains(&expected),
            "{actual:?}"
        );
        assert!(
            actual
                .first_failure
                .as_ref()
                .unwrap()
                .contains("queued worker request dropped"),
            "{actual:?}"
        );
        assert!(actual.caller_returned_at.is_some() && actual.caller_unwound_at.is_none());
        assert!(actual.worker_started_at.is_none() && actual.worker_returned_at.is_none());
        assert!(actual.timely_receipt_at.is_none() && rig.wire.writes().is_empty());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_during_each_actual_write_retains_return_count_and_permanent_fence() {
    for phase in PHASES {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x50]).await;
        rig.wire.fault.store(5, Ordering::SeqCst);
        let prepared = owner
            .prepare_selected_pic_initialization_exchange(0, phase, due())
            .unwrap();
        let view = prepared.observation();
        let caller = tokio::task::spawn_blocking(move || prepared.run());
        until(|| rig.wire.gate.entered.load(Ordering::SeqCst)).await;
        owner.cancel();
        rig.wire.gate.release();
        caller.await.unwrap();
        let actual = view.snapshot();
        assert_eq!(
            actual.steps.last().unwrap().returned_count,
            Some(source(phase).0.len())
        );
        assert!(actual.timely_receipt_at.is_none() && actual.first_failure.is_some());
        assert_eq!(rig.wire.calls.lock().unwrap().len(), 1);
        assert!(owner.handles.is_stopped());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_final_read_updates_original_view_without_retroactive_caller_success() {
    for phase in PHASES {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x50]).await;
        rig.wire.fault.store(4, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_millis(700);
        let prepared = owner
            .prepare_selected_pic_initialization_exchange(0, phase, deadline)
            .unwrap();
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
        let last = actual.steps.last().unwrap();
        assert_eq!(last.returned_count, Some(1));
        assert_eq!(
            last.returned_bytes,
            Some(vec![[0, 0xff][(source(phase).1 - 1) % 2]])
        );
        assert!(last.returned_at.unwrap() >= deadline);
        assert!(actual.timely_receipt_at.is_none() && actual.transport_completed_at.is_none());
        assert!(actual.caller_error.is_some());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_impossible_counts_and_read_errors_remain_distinct_without_replay() {
    for phase in PHASES {
        for fault in [1, 2, 3, 7, 8] {
            let (mut owner, rig) = Rig::new();
            diagnose(&mut owner, &[0x50]).await;
            rig.wire.fault.store(fault, Ordering::SeqCst);
            let prepared = owner
                .prepare_selected_pic_initialization_exchange(0, phase, due())
                .unwrap();
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
                    assert!(last.returned_count.is_none());
                    assert!(last.returned_bytes.is_none());
                    assert!(last.error.as_ref().unwrap().contains("authored final"));
                }
                7 => {
                    assert_eq!(last.returned_count, Some(2));
                    assert_eq!(last.returned_bytes, Some(vec![0xff]));
                }
                8 => assert_eq!(last.returned_count, Some(source(phase).0.len() + 1)),
                _ => unreachable!(),
            }
            assert_eq!(rig.wire.writes(), [0x20]);
            finish(&mut owner).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_unwind_retains_actual_step_unwind_without_fabricated_return() {
    for phase in PHASES {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x50]).await;
        rig.wire.fault.store(6, Ordering::SeqCst);
        let prepared = owner
            .prepare_selected_pic_initialization_exchange(0, phase, due())
            .unwrap();
        let view = prepared.observation();
        tokio::task::spawn_blocking(move || prepared.run())
            .await
            .unwrap();
        let actual = view.snapshot();
        let last = actual.steps.last().unwrap();
        assert!(
            last.unwound_at.is_some()
                && last.returned_at.is_none()
                && last.returned_count.is_none()
        );
        assert!(actual.worker_finalized_at.is_some() && actual.timely_receipt_at.is_none());
        assert_eq!(rig.wire.writes(), [0x20]);
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_queued_expiry_never_starts_fixed_phase_worker_and_keeps_actual_refusal() {
    for phase in PHASES {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x50]).await;
        let handle = owner.handles.bus0.clone();
        let occupied = tokio::task::spawn_blocking(move || {
            handle.write_bytes_mutating(crate::i2c::I2cMutationLabel::QueryPrelude, 0x20, &[0xde])
        });
        until(|| rig.wire.gate.entered.load(Ordering::SeqCst)).await;
        let prepared = owner
            .prepare_selected_pic_initialization_exchange(
                0,
                phase,
                Instant::now() + Duration::from_millis(200),
            )
            .unwrap();
        let view = prepared.observation();
        tokio::task::spawn_blocking(move || prepared.run())
            .await
            .unwrap();
        rig.wire.gate.release();
        let _ = occupied.await.unwrap();
        until(|| view.snapshot().worker_finalized_at.is_some()).await;
        let actual = view.snapshot();
        assert!(actual.caller_error.is_some() && actual.worker_started_at.is_none());
        assert!(actual.timely_receipt_at.is_none() && rig.wire.writes().is_empty());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_phase_permanently_stops_original_owner_and_cannot_be_reissued() {
    for phase in PHASES {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x52]).await;
        let prepared = owner
            .prepare_selected_pic_initialization_exchange(0, phase, due())
            .unwrap();
        let view = prepared.observation();
        assert!(owner
            .prepare_selected_pic_initialization_exchange(0, phase, due())
            .is_err());
        drop(prepared);
        assert!(
            view.snapshot().first_failure.is_some() && view.snapshot().caller_started_at.is_none()
        );
        for later in PHASES {
            assert!(owner
                .prepare_selected_pic_initialization_exchange(0, later, due())
                .is_err());
        }
        assert!(rig.wire.writes().is_empty() && owner.handles.is_stopped());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_delay_and_original_service_close_cannot_launch_a_retained_phase() {
    for close in [false, true] {
        let (mut owner, rig) = Rig::new();
        diagnose(&mut owner, &[0x50]).await;
        let deadline = Instant::now() + Duration::from_millis(150);
        let prepared = owner
            .prepare_selected_pic_initialization_exchange(0, Phase::Bridge, deadline)
            .unwrap();
        let view = prepared.observation();
        if close {
            finish(&mut owner).await;
        } else {
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        }
        tokio::task::spawn_blocking(move || prepared.run())
            .await
            .unwrap();
        let actual = view.snapshot();
        assert!(actual.caller_error.is_some() && actual.worker_started_at.is_none());
        assert!(actual.timely_receipt_at.is_none() && actual.steps.is_empty());
        assert!(rig.wire.writes().is_empty());
        if !close {
            finish(&mut owner).await;
        }
    }
}

// Descendant keeps the original Rig private while exercising retained callers.
#[path = "bb_management_owner_pic_initialization_callers_tests.rs"]
mod retained;

#[path = "bb_pre_power_initial_bridge_tests.rs"]
mod pre_power_initial;
