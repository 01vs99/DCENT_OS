//! Explicit policy self-fixtures over actual original diagnostic/service owners.
//! No native selector, timestamp, readiness or initialization completion injected.
use super::*;
use crate::bb_management_runtime::wire_sim::{RuntimeWire, WireGate};
use crate::i2c::bb_pic_optional_bridge::{Observation, Operation};
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

#[path = "bb_management_owner_execution_test_support.rs"]
mod apw;
#[path = "bb_pre_power_bus0_test_support.rs"]
mod bus0;

// Independent literal oracle from held original profile-control events.
const PACKETS: [[u8; 8]; 4] = [
    [0x55, 0xaa, 0x06, 0x3c, 0x48, 0x02, 0x00, 0x8c],
    [0x55, 0xaa, 0x06, 0x3c, 0x49, 0x02, 0x00, 0x8d],
    [0x55, 0xaa, 0x06, 0x3c, 0x4a, 0x02, 0x00, 0x8e],
    [0x55, 0xaa, 0x06, 0x3c, 0x4b, 0x02, 0x00, 0x8f],
];

#[derive(Clone, Copy)]
enum Fault {
    None,
    ErrorAt(usize),
    CountAt(usize, usize),
    PanicAt(usize),
    BlockAt(usize),
}
struct Wire {
    original: Arc<RuntimeWire>,
    diagnostic_prefix: Mutex<[usize; 3]>,
    active: AtomicBool,
    position: AtomicUsize,
    ordinal: AtomicUsize,
    raw_pattern: AtomicU8,
    packets: Mutex<Vec<(u8, Vec<u8>)>>,
    calls: Mutex<Vec<(Instant, u8, bool)>>,
    fault: Mutex<Fault>,
    gate: Arc<WireGate>,
}
impl Wire {
    fn new(original: Arc<RuntimeWire>) -> Arc<Self> {
        Arc::new(Self {
            original,
            diagnostic_prefix: Mutex::new([0; 3]),
            active: AtomicBool::new(false),
            position: AtomicUsize::new(0),
            ordinal: AtomicUsize::new(0),
            raw_pattern: AtomicU8::new(2),
            packets: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
            fault: Mutex::new(Fault::None),
            gate: WireGate::new(),
        })
    }
    fn transfer(&self, addr: u8, write: bool, normal_count: usize) -> crate::Result<usize> {
        let ordinal = self.ordinal.fetch_add(1, Ordering::SeqCst);
        self.calls
            .lock()
            .unwrap()
            .push((Instant::now(), addr, write));
        let fault = *self.fault.lock().unwrap();
        match fault {
            Fault::ErrorAt(at) if ordinal == at => Err(crate::HalError::I2c {
                bus: 0,
                addr,
                detail: format!("explicit optional bridge I/O failure {ordinal}"),
            }),
            Fault::CountAt(at, count) if ordinal == at => Ok(count),
            Fault::PanicAt(at) if ordinal == at => {
                panic!("explicit optional bridge unwind {ordinal}")
            }
            Fault::BlockAt(at) if ordinal == at => {
                self.gate.wait();
                Ok(normal_count)
            }
            _ => Ok(normal_count),
        }
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
        if bytes.get(3) != Some(&0x3c) {
            return self.original.write(bus, addr, bytes);
        }
        assert_eq!(bus, 0);
        assert!((0x20..=0x22).contains(&addr), "never directly address LM75");
        // The actual pre-power executor queries these four sensors once per
        // original PIC, before any optional sweep. The packets are IDENTICAL
        // to PACKETS; this fixture must route that prefix to the unchanged
        // strict diagnostic backend. This counter is no admission/readiness
        // proof, never resets, and never changes the owner or actual replies.
        let slot = usize::from(addr - 0x20);
        let diagnostic_index = self.diagnostic_prefix.lock().unwrap()[slot];
        if diagnostic_index < 4 {
            assert_eq!(bytes, PACKETS[diagnostic_index]);
            let returned = self.original.write(bus, addr, bytes);
            if matches!(&returned, Ok(count) if *count == bytes.len()) {
                let mut prefix = self.diagnostic_prefix.lock().unwrap();
                assert_eq!(prefix[slot], diagnostic_index);
                prefix[slot] += 1;
            }
            return returned;
        }
        {
            let mut packets = self.packets.lock().unwrap();
            assert_eq!(bytes, PACKETS[packets.len() % 4]);
            packets.push((addr, bytes.to_vec()));
        }
        self.position.store(0, Ordering::SeqCst);
        self.active.store(true, Ordering::SeqCst);
        self.transfer(addr, true, bytes.len())
    }
    fn read(&self, bus: u8, addr: u8, bytes: &mut [u8]) -> crate::Result<usize> {
        if !self.active.load(Ordering::SeqCst) {
            return self.original.read(bus, addr, bytes);
        }
        assert_eq!((bus, bytes.len()), (0, 1));
        let position = self.position.fetch_add(1, Ordering::SeqCst);
        assert!(position < 7);
        bytes[0] = match self.raw_pattern.load(Ordering::SeqCst) {
            0 => 0,
            1 => 0xff,
            _ => [0, 0xff][position % 2],
        };
        let result = self.transfer(addr, false, 1);
        if position == 6 {
            self.active.store(false, Ordering::SeqCst);
        }
        result
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
    let historical = observed.diagnostics.historical.as_ref().unwrap();
    assert_eq!(historical.bus0.bridges.len(), selected.len() * 4);
    // Actual retained caller replies from the original diagnostic backend.
    // The diagnostic executor decoded them before making historical data.
    let expected_reads: Vec<Vec<u8>> = [7, 0x3c, 0x99, 0x26, 0x30, 0, 0x32]
        .into_iter()
        .map(|byte| vec![byte])
        .collect();
    for (position, attempt) in historical.bus0.bridges.iter().enumerate() {
        let factory = selected[position / 4];
        assert_eq!(attempt.factory_address, factory);
        assert_eq!(attempt.native_slot, usize::from(factory - 0x50));
        assert_eq!(attempt.pic_address, factory - 0x30);
        assert_eq!(attempt.sensor_address, 0x48 + (position % 4) as u8);
        assert!(attempt.call_returned_at.unwrap() >= attempt.call_prepared_at);
        assert_eq!(attempt.returned_reads.as_ref(), Some(&expected_reads));
        assert_eq!(
            attempt.decoded.as_ref().unwrap().raw(),
            &[7, 0x3c, 0x99, 0x26, 0x30, 0, 0x32]
        );
        assert!(attempt.error.is_none());
    }
}
async fn fixture(owner: &mut BbManagementOwner, selected: &[u8]) {
    diagnose(owner, selected).await;
    owner.admit_optional_bridge_self_fixture().unwrap();
}
async fn finish(owner: &mut BbManagementOwner) {
    assert!(owner.join_callers_until(due()).await);
    assert!(tokio::task::block_in_place(|| owner.close_services_until(due())).unwrap());
}
async fn run(owner: &mut BbManagementOwner) -> Observation {
    let prepared = owner
        .prepare_selected_pic_optional_bridge(0, due())
        .unwrap();
    let view = prepared.observation();
    tokio::task::spawn_blocking(move || prepared.run())
        .await
        .unwrap();
    view.snapshot()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_policy_unset_and_invalid_self_fixture_inputs_never_emit_optional_packets() {
    let (mut owner, rig) = Rig::new();
    assert!(owner.admit_optional_bridge_self_fixture().is_err());
    assert!(owner
        .prepare_selected_pic_optional_bridge(0, due())
        .is_err());
    diagnose(&mut owner, &[0x52]).await;
    let denied = owner
        .prepare_selected_pic_optional_bridge(0, due())
        .err()
        .unwrap();
    assert!(denied.contains("native optional bridge profile remains unadmitted"));
    owner.admit_optional_bridge_self_fixture().unwrap();
    assert!(owner.admit_optional_bridge_self_fixture().is_err());
    assert!(owner
        .prepare_selected_pic_optional_bridge(1, due())
        .is_err());
    assert!(owner
        .prepare_selected_pic_optional_bridge(0, Instant::now())
        .is_err());
    assert!(rig.wire.calls.lock().unwrap().is_empty());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn four_packets_on_three_original_slots_retain_all_raw_patterns_and_real_waits() {
    for pattern in [0, 1, 2] {
        let (mut owner, rig) = Rig::new();
        fixture(&mut owner, &[0x52, 0x50, 0x51]).await;
        // The original worker performed the strict diagnostic prefix, while
        // no optional/fault ordinal was consumed. Later existing assertions
        // require the identical requests to receive all three weak patterns.
        let diagnostic_events = rig.a.trace();
        let actual_writes: Vec<_> = diagnostic_events
            .iter()
            .filter_map(|event| match event {
                bus0::Event::Write(address, bytes) if bytes.get(3) == Some(&0x3c) => {
                    Some((*address, bytes.clone()))
                }
                _ => None,
            })
            .collect();
        let expected_writes: Vec<_> = [0x22, 0x20, 0x21]
            .into_iter()
            .flat_map(|address| PACKETS.iter().map(move |packet| (address, packet.to_vec())))
            .collect();
        assert_eq!(actual_writes, expected_writes);
        let actual_reads: Vec<_> = diagnostic_events
            .iter()
            .filter_map(|event| match event {
                bus0::Event::Read(address, Some(sensor), position) => {
                    Some((*address, *sensor, *position))
                }
                _ => None,
            })
            .collect();
        let expected_reads: Vec<_> = [0x22, 0x20, 0x21]
            .into_iter()
            .flat_map(|address| {
                (0x48..=0x4b)
                    .flat_map(move |sensor| (0..7).map(move |position| (address, sensor, position)))
            })
            .collect();
        assert_eq!(actual_reads, expected_reads);
        assert_eq!(*rig.wire.diagnostic_prefix.lock().unwrap(), [4, 4, 4]);
        assert!(rig.wire.calls.lock().unwrap().is_empty());
        assert!(rig.wire.packets.lock().unwrap().is_empty());
        assert_eq!(rig.wire.ordinal.load(Ordering::SeqCst), 0);
        rig.wire.raw_pattern.store(pattern, Ordering::SeqCst);
        assert!(owner.heartbeat_snapshot().is_none());
        let deadline = due();
        for (selected, pic) in [0x22, 0x20, 0x21].into_iter().enumerate() {
            let prepared = owner
                .prepare_selected_pic_optional_bridge(selected, deadline)
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
            assert!(!actual.native_profile_admitted);
            assert_eq!(
                actual.policy_source,
                "explicit_original_service_self_fixture_only"
            );
            assert_eq!(
                (
                    actual.pic_address,
                    actual.factory_address,
                    actual.native_slot
                ),
                (pic, pic + 0x30, usize::from(pic - 0x20))
            );
            assert_eq!(actual.original_deadline, deadline);
            assert_eq!(
                actual.requests,
                PACKETS.iter().map(|p| p.to_vec()).collect::<Vec<_>>()
            );
            let mut read_index = 0;
            let mut waits = Vec::new();
            for step in &actual.steps {
                match step.operation {
                    Operation::ReadReply {
                        bridge_address,
                        index,
                    } => {
                        assert_eq!(
                            (bridge_address, index),
                            (0x48 + (read_index / 7) as u8, read_index % 7)
                        );
                        let byte = match pattern {
                            0 => 0,
                            1 => 0xff,
                            _ => [0, 0xff][index % 2],
                        };
                        assert_eq!(step.returned_bytes, Some(vec![byte]));
                        assert_eq!(step.returned_count, Some(1));
                        read_index += 1;
                    }
                    Operation::WriteRequest { bridge_address } => {
                        assert!((0x48..=0x4b).contains(&bridge_address))
                    }
                    Operation::Wait(duration) => {
                        assert!(
                            step.returned_at.unwrap().duration_since(step.started_at) >= duration
                        );
                        waits.push(duration.as_millis());
                    }
                    Operation::SelectSlave => (),
                }
                assert!(step.error.is_none() && step.unwound_at.is_none());
            }
            assert_eq!(read_index, 28);
            assert_eq!(waits, [vec![20; 32], vec![50]].concat());
            assert!(
                actual
                    .transport_completed_at
                    .unwrap()
                    .duration_since(actual.worker_started_at.unwrap())
                    >= Duration::from_millis(690)
            );
            assert!(actual.worker_finalized_at.is_some() && actual.caller_finalized_at.is_some());
            assert!(owner
                .prepare_selected_pic_optional_bridge(selected, due())
                .is_err());
        }
        let expected: Vec<_> = [0x22, 0x20, 0x21]
            .into_iter()
            .flat_map(|addr| PACKETS.iter().map(move |p| (addr, p.to_vec())))
            .collect();
        assert_eq!(*rig.wire.packets.lock().unwrap(), expected);
        assert!(owner.heartbeat_snapshot().is_none());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_fixed_write_and_each_of_twenty_eight_reads_retains_first_error_without_replay() {
    for failed_io in 0..32 {
        let (mut owner, rig) = Rig::new();
        fixture(&mut owner, &[0x50]).await;
        *rig.wire.fault.lock().unwrap() = Fault::ErrorAt(failed_io);
        let actual = run(&mut owner).await;
        assert!(
            actual.timely_receipt_at.is_none() && actual.first_failure.is_some(),
            "{failed_io}: {actual:?}"
        );
        let last = actual.steps.last().unwrap();
        assert!(last.returned_count.is_none() && last.returned_bytes.is_none());
        assert!(last.returned_at.is_some() && last.unwound_at.is_none());
        assert!(last
            .error
            .as_ref()
            .unwrap()
            .contains(&format!("I/O failure {failed_io}")));
        assert_eq!(rig.wire.calls.lock().unwrap().len(), failed_io + 1);
        assert_eq!(rig.wire.packets.lock().unwrap().len(), failed_io / 8 + 1);
        assert!(owner.handles.is_stopped());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_and_impossible_write_read_counts_stay_distinct_for_all_four_requests() {
    for exchange in 0..4 {
        for (offset, count) in [(0, 3), (0, 9), (7, 0), (7, 2)] {
            let failed_io = exchange * 8 + offset;
            let (mut owner, rig) = Rig::new();
            fixture(&mut owner, &[0x50]).await;
            *rig.wire.fault.lock().unwrap() = Fault::CountAt(failed_io, count);
            let actual = run(&mut owner).await;
            let last = actual.steps.last().unwrap();
            assert_eq!(last.returned_count, Some(count));
            if offset == 7 {
                assert_eq!(
                    last.returned_bytes,
                    Some(if count == 0 { vec![] } else { vec![0] })
                );
            } else {
                assert!(last.returned_bytes.is_none());
            }
            assert!(actual.timely_receipt_at.is_none() && actual.first_failure.is_some());
            assert_eq!(rig.wire.calls.lock().unwrap().len(), failed_io + 1);
            finish(&mut owner).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_reserved_disable_generation_rejects_old_optional_caller_before_worker_start() {
    let (mut owner, rig) = Rig::new();
    fixture(&mut owner, &[0x50]).await;
    let prepared = owner
        .prepare_selected_pic_optional_bridge(0, due())
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
    assert!(
        actual.caller_error.as_ref().unwrap().contains(&format!(
            "UnclassifiedMutation request generation {} is no longer current",
            actual.original_generation
        )),
        "{actual:?}"
    );
    assert!(actual
        .first_failure
        .as_ref()
        .unwrap()
        .contains("queued worker request dropped"));
    assert!(actual.worker_started_at.is_none() && actual.timely_receipt_at.is_none());
    assert!(rig.wire.calls.lock().unwrap().is_empty());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_in_actual_middle_write_or_read_keeps_late_raw_and_permanent_fences() {
    for blocked_io in [16, 22] {
        let (mut owner, rig) = Rig::new();
        fixture(&mut owner, &[0x52]).await;
        *rig.wire.fault.lock().unwrap() = Fault::BlockAt(blocked_io);
        let prepared = owner
            .prepare_selected_pic_optional_bridge(0, due())
            .unwrap();
        let view = prepared.observation();
        let caller = tokio::task::spawn_blocking(move || prepared.run());
        until(|| rig.wire.gate.entered.load(Ordering::SeqCst)).await;
        owner.cancel();
        rig.wire.gate.release();
        caller.await.unwrap();
        let actual = view.snapshot();
        let last = actual.steps.last().unwrap();
        assert_eq!(
            last.returned_count,
            Some(if blocked_io % 8 == 0 { 8 } else { 1 })
        );
        assert!(last.returned_at.is_some());
        assert!(actual.timely_receipt_at.is_none() && actual.first_failure.is_some());
        assert_eq!(rig.wire.calls.lock().unwrap().len(), blocked_io + 1);
        assert!(owner.handles.is_stopped());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_read_return_after_original_deadline_cannot_promote_an_earlier_caller_timeout() {
    let (mut owner, rig) = Rig::new();
    fixture(&mut owner, &[0x50]).await;
    *rig.wire.fault.lock().unwrap() = Fault::BlockAt(31);
    let deadline = Instant::now() + Duration::from_secs(2);
    let prepared = owner
        .prepare_selected_pic_optional_bridge(0, deadline)
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
    assert!(before.caller_error.is_some() && before.worker_finalized_at.is_none());
    rig.wire.gate.release();
    until(|| view.snapshot().worker_finalized_at.is_some()).await;
    let actual = view.snapshot();
    let last = actual.steps.last().unwrap();
    assert_eq!(last.returned_bytes, Some(vec![0]));
    assert_eq!(last.returned_count, Some(1));
    assert!(last.returned_at.unwrap() >= deadline);
    assert!(actual.transport_completed_at.is_none() && actual.timely_receipt_at.is_none());
    assert_eq!(rig.wire.calls.lock().unwrap().len(), 32);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_write_and_read_unwind_record_no_fabricated_return_or_following_packet() {
    for failed_io in [8, 23] {
        let (mut owner, rig) = Rig::new();
        fixture(&mut owner, &[0x50]).await;
        *rig.wire.fault.lock().unwrap() = Fault::PanicAt(failed_io);
        let actual = run(&mut owner).await;
        let last = actual.steps.last().unwrap();
        assert!(last.unwound_at.is_some() && last.returned_at.is_none());
        assert!(last.returned_count.is_none() && last.returned_bytes.is_none());
        assert!(actual.timely_receipt_at.is_none() && actual.worker_finalized_at.is_some());
        assert_eq!(rig.wire.calls.lock().unwrap().len(), failed_io + 1);
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn occupied_original_queue_expiry_never_starts_optional_worker_or_changes_deadline() {
    let (mut owner, rig) = Rig::new();
    fixture(&mut owner, &[0x50]).await;
    let handle = owner.handles.bus0.clone();
    let occupied = tokio::task::spawn_blocking(move || {
        handle.write_bytes_mutating(crate::i2c::I2cMutationLabel::QueryPrelude, 0x20, &[0xde])
    });
    until(|| rig.wire.gate.entered.load(Ordering::SeqCst)).await;
    let deadline = Instant::now() + Duration::from_millis(200);
    let prepared = owner
        .prepare_selected_pic_optional_bridge(0, deadline)
        .unwrap();
    let view = prepared.observation();
    tokio::task::spawn_blocking(move || prepared.run())
        .await
        .unwrap();
    rig.wire.gate.release();
    let _ = occupied.await.unwrap();
    until(|| view.snapshot().worker_finalized_at.is_some()).await;
    let actual = view.snapshot();
    assert_eq!(actual.original_deadline, deadline);
    assert!(actual.caller_error.is_some() && actual.worker_started_at.is_none());
    assert!(actual.timely_receipt_at.is_none() && rig.wire.calls.lock().unwrap().is_empty());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_original_reservation_is_permanent_and_does_not_spawn_or_emit() {
    let (mut owner, rig) = Rig::new();
    fixture(&mut owner, &[0x52]).await;
    let prepared = owner
        .prepare_selected_pic_optional_bridge(0, due())
        .unwrap();
    let view = prepared.observation();
    assert!(owner
        .prepare_selected_pic_optional_bridge(0, due())
        .is_err());
    drop(prepared);
    assert!(view.snapshot().first_failure.is_some() && view.snapshot().caller_started_at.is_none());
    assert!(owner
        .prepare_selected_pic_optional_bridge(0, due())
        .is_err());
    assert!(owner.handles.is_stopped() && rig.wire.calls.lock().unwrap().is_empty());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_caller_or_closed_original_service_never_starts_retained_optional_sweep() {
    for close in [false, true] {
        let (mut owner, rig) = Rig::new();
        fixture(&mut owner, &[0x50]).await;
        let deadline = Instant::now() + Duration::from_millis(150);
        let prepared = owner
            .prepare_selected_pic_optional_bridge(0, deadline)
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
        assert!(rig.wire.calls.lock().unwrap().is_empty());
        if !close {
            finish(&mut owner).await;
        }
    }
}

#[path = "bb_management_owner_pic_optional_policy_tests.rs"]
mod native_policy_tests;
