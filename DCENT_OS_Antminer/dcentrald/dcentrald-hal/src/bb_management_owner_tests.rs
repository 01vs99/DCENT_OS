//! Real service threads and retained callers with inert bounded wire fixtures.
#[path = "bb_management_owner_runtime_tests.rs"]
mod runtime;
use super::*;
use crate::bb_voltage_planner::Decision;
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};
use std::sync::Condvar;
use std::time::Duration;

#[path = "bb_pre_power_apw_test_support.rs"]
mod apw;
#[path = "bb_pre_power_bus0_test_support.rs"]
mod bus0;

struct ControlledApw {
    inner: Arc<apw::Backend>,
    opcode: AtomicU8,
    dac: AtomicU16,
    foreign_hardware: AtomicBool,
    bad_calibration: AtomicBool,
    armed: AtomicBool,
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}

impl ControlledApw {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: apw::Backend::new(0x23, false, None),
            opcode: AtomicU8::new(0),
            dac: AtomicU16::new(0x23),
            foreign_hardware: AtomicBool::new(false),
            bad_calibration: AtomicBool::new(false),
            armed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            condition: Condvar::new(),
        })
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }

    async fn wait_entered(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }
}

impl I2cSimBackend for ControlledApw {
    fn service_identity(&self) -> Option<usize> {
        self.inner.service_identity()
    }

    fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> crate::Result<usize> {
        let result = self.inner.write(bus, addr, bytes)?;
        self.opcode.store(bytes[4], Ordering::SeqCst);
        if bytes[4] == 2 && self.armed.load(Ordering::SeqCst) {
            self.entered.store(true, Ordering::SeqCst);
            let guard = self.released.lock().unwrap();
            let (_guard, result) = self
                .condition
                .wait_timeout_while(guard, Duration::from_secs(6), |released| !*released)
                .unwrap();
            assert!(!result.timed_out(), "bounded worker gate exhausted");
        }
        Ok(result)
    }

    fn read(&self, bus: u8, addr: u8, bytes: &mut [u8]) -> crate::Result<usize> {
        let count = self.inner.read(bus, addr, bytes)?;
        match self.opcode.load(Ordering::SeqCst) {
            2 if self.foreign_hardware.load(Ordering::SeqCst) => bytes[4] = 0x77,
            3 => bytes[4..6].copy_from_slice(&self.dac.load(Ordering::SeqCst).to_le_bytes()),
            _ => {}
        }
        let checksum_offset = usize::from(bytes[2]);
        let checksum: u16 = bytes[2..checksum_offset]
            .iter()
            .map(|value| u16::from(*value))
            .sum();
        bytes[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_le_bytes());
        if self.opcode.load(Ordering::SeqCst) == 6 && self.bad_calibration.load(Ordering::SeqCst) {
            bytes[checksum_offset] ^= 1;
        }
        Ok(count)
    }

    fn write_read(&self, _: u8, _: u8, _: &[u8], _: &mut [u8]) -> crate::Result<()> {
        panic!("fixed APW fixture requires separate writes and reads")
    }
}

struct Release(Arc<ControlledApw>, Arc<bus0::Backend>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
        self.1.release();
    }
}

fn new_owner(a: &Arc<bus0::Backend>, b: &Arc<ControlledApw>) -> BbManagementOwner {
    BbManagementOwner::new(
        spawn_owned_sim_i2c_service(0, a.clone(), (0x50..=0x57).collect()).unwrap(),
        spawn_owned_sim_i2c_service(1, b.clone(), vec![]).unwrap(),
    )
}

async fn diagnosed(a: &Arc<bus0::Backend>, b: &Arc<ControlledApw>) -> BbManagementOwner {
    let mut owner = new_owner(a, b);
    let observed = owner
        .observe_pre_power_once(&[0x50], Instant::now() + Duration::from_secs(12))
        .await;
    assert!(observed.stopped_at.is_none(), "{observed:?}");
    assert!(observed.diagnostics.historical.is_some());
    owner
}

async fn finish(owner: &mut BbManagementOwner) {
    assert!(
        owner
            .join_callers_until(Instant::now() + Duration::from_secs(2))
            .await
    );
    assert!(tokio::task::block_in_place(
        || owner.close_services_until(Instant::now() + Duration::from_secs(2),)
    )
    .unwrap());
    let (bus0, bus1) = owner.close_receipts();
    assert_eq!((bus0.unwrap().bus(), bus1.unwrap().bus()), (0, 1));
    assert!(bus0.unwrap().worker_exit_observed_at() <= Instant::now());
    assert!(bus1.unwrap().worker_exit_observed_at() <= Instant::now());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_workers_survive_diagnostics_and_repeated_previews_do_not_record_applied_requests()
{
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = ControlledApw::new();
    let mut owner = diagnosed(&a, &b).await;
    let diagnostic = owner.snapshot().diagnostics.historical.unwrap();
    let trace0 = a.trace();
    owner.merge_requested_voltage(Some(13.4), None).unwrap();
    let mut retained = Vec::new();
    for sequence in 1..=2 {
        let deadline = Instant::now() + Duration::from_secs(6);
        let snapshot = owner.observe_voltage_once(deadline).await.unwrap();
        assert!(snapshot.stopped_at.is_none(), "{snapshot:?}");
        assert!(!snapshot.voltage_caller_pending);
        let observed = snapshot.latest_voltage.unwrap();
        assert_eq!((observed.sequence, observed.deadline), (sequence, deadline));
        assert!(observed.caller_prepared_at.unwrap() <= observed.caller_returned_at.unwrap());
        assert!(observed.caller_returned_at.unwrap() <= observed.caller_joined_at.unwrap());
        assert!(observed.caller_joined_at.unwrap() < deadline);
        assert_eq!(observed.attempt.as_ref().unwrap().queries.len(), 4);
        let preview = observed.preview.as_ref().unwrap();
        assert_eq!(preview.reported_millivolts, 14670);
        assert_eq!(preview.selected_pair.unwrap().target, 13.4);
        let step = preview.first_step.unwrap();
        assert_eq!(step.decision, Decision::Request(14.62));
        assert_eq!(step.history.repeated_requests, 0);
        retained.push(observed);
    }
    assert_eq!(
        retained[0].preview.as_ref().unwrap().first_step,
        retained[1].preview.as_ref().unwrap().first_step
    );
    b.dac.store(0x30, Ordering::SeqCst);
    let third = owner
        .observe_voltage_once(Instant::now() + Duration::from_secs(6))
        .await
        .unwrap();
    let third = third.latest_voltage.unwrap();
    assert_eq!(third.sequence, 3);
    assert_eq!(third.preview.as_ref().unwrap().reported_millivolts, 14510);
    assert_eq!(
        third.preview.unwrap().first_step.unwrap().decision,
        Decision::Request(14.46)
    );
    assert_eq!(a.trace(), trace0);
    assert_eq!(
        b.inner.opcodes(),
        [2, 1, 6, 3, 2, 1, 6, 3, 2, 1, 6, 3, 2, 1, 6, 3]
    );
    assert_eq!(diagnostic.apw.profile.queries.len(), 4);
    assert!(spawn_owned_sim_i2c_service(0, a.clone(), vec![]).is_err());
    assert!(spawn_owned_sim_i2c_service(1, b.clone(), vec![]).is_err());
    assert!(owner.close_receipts().0.is_none() && owner.close_receipts().1.is_none());
    finish(&mut owner).await;
    assert!(
        owner.snapshot().latest_voltage.unwrap().preview.is_some(),
        "historical preview survives terminal stop"
    );
    assert_eq!(
        retained[0].preview.as_ref().unwrap().reported_millivolts,
        14670
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_diagnostics_and_expired_deadlines_refuse_before_any_new_wire_work() {
    for defect in 0..3 {
        let a = bus0::Backend::new(bus0::Fault::None, None);
        let b = ControlledApw::new();
        let mut owner = new_owner(&a, &b);
        if defect == 1 {
            owner
                .observe_pre_power_once(&[0x53], Instant::now() + Duration::from_secs(2))
                .await;
        } else if defect == 2 {
            owner.observe_pre_power_once(&[0x50], Instant::now()).await;
        }
        assert!(owner
            .observe_voltage_once(Instant::now() + Duration::from_secs(2))
            .await
            .is_err());
        assert!(a.trace().is_empty() && b.inner.trace().is_empty());
        assert!(owner.handles.bus0.terminal_safe_off_is_latched());
        assert!(owner.handles.bus1.terminal_safe_off_is_latched());
        assert!(owner.snapshot().latest_voltage.is_none());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_partial_profile_updates_are_atomic_and_do_not_touch_either_worker() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = ControlledApw::new();
    let mut owner = new_owner(&a, &b);
    owner
        .merge_requested_voltage(Some(13.4), Some(0.07))
        .unwrap();
    let before = owner.snapshot().requested_profile;
    for update in [
        (Some(14.0), Some(f64::NAN)),
        (Some(f64::INFINITY), Some(0.05)),
        (Some(11.0), None),
        (None, Some(0.01)),
    ] {
        assert!(owner.merge_requested_voltage(update.0, update.1).is_err());
        assert_eq!(owner.snapshot().requested_profile, before);
    }
    owner.merge_requested_voltage(None, None).unwrap();
    assert_eq!(owner.snapshot().requested_profile, before);
    assert!(a.trace().is_empty() && b.inner.trace().is_empty());
    assert!(owner.snapshot().stopped_at.is_none());
    owner.cancel();
    assert!(owner.merge_requested_voltage(Some(13.8), None).is_err());
    assert_eq!(owner.snapshot().requested_profile, before);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_voltage_future_retains_caller_and_both_services_until_explicit_cleanup() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = ControlledApw::new();
    let _release = Release(b.clone(), a.clone());
    let mut owner = diagnosed(&a, &b).await;
    b.armed.store(true, Ordering::SeqCst);
    let original = Instant::now() + Duration::from_secs(5);
    {
        let observe = owner.observe_voltage_once(original);
        tokio::pin!(observe);
        tokio::select! { _ = b.wait_entered() => {}, _ = &mut observe => panic!("premature completion") }
    }
    let before = owner.snapshot();
    assert!(before.voltage_caller_pending && before.stopped_at.is_some());
    assert!(before.latest_voltage.as_ref().unwrap().preview.is_none());
    assert!(
        owner.handles.bus0.terminal_safe_off_is_latched()
            && owner.handles.bus1.terminal_safe_off_is_latched()
    );
    assert!(
        !owner
            .join_callers_until(Instant::now() + Duration::from_millis(10))
            .await
    );
    assert!(tokio::task::block_in_place(
        || owner.close_services_until(Instant::now() + Duration::from_millis(10))
    )
    .is_err());
    assert!(owner
        .observe_voltage_once(Instant::now() + Duration::from_secs(20))
        .await
        .is_err());
    assert_eq!(owner.snapshot().latest_voltage.unwrap().deadline, original);
    assert!(owner.close_receipts().0.is_none() && owner.close_receipts().1.is_none());
    assert!(spawn_owned_sim_i2c_service(0, a.clone(), vec![]).is_err());
    assert!(spawn_owned_sim_i2c_service(1, b.clone(), vec![]).is_err());
    b.release();
    finish(&mut owner).await;
    let after = owner.snapshot().latest_voltage.unwrap();
    assert!(after.caller_joined_at.is_some() && after.preview.is_none());
    assert_eq!(after.deadline, original);
    assert_eq!(b.inner.opcodes(), [2, 1, 6, 3, 2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timed_out_caller_can_join_while_started_worker_transfer_still_prevents_service_close() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = ControlledApw::new();
    let _release = Release(b.clone(), a.clone());
    let mut owner = diagnosed(&a, &b).await;
    b.armed.store(true, Ordering::SeqCst);
    let original = Instant::now() + Duration::from_millis(500);
    {
        let observe = owner.observe_voltage_once(original);
        tokio::pin!(observe);
        tokio::select! { _ = b.wait_entered() => {}, _ = &mut observe => panic!("premature completion") }
        assert!(observe.await.unwrap().stopped_at.is_some());
    }
    assert!(
        owner
            .join_callers_until(Instant::now() + Duration::from_secs(1))
            .await
    );
    assert!(!owner.snapshot().voltage_caller_pending);
    assert!(!tokio::task::block_in_place(
        || owner.close_services_until(Instant::now() + Duration::from_millis(20))
    )
    .unwrap());
    assert!(owner.close_receipts().1.is_none());
    assert!(spawn_owned_sim_i2c_service(1, b.clone(), vec![]).is_err());
    let late = owner.snapshot().latest_voltage.unwrap();
    assert!(late.preview.is_none());
    assert_eq!(late.deadline, original);
    let attempt = late.attempt.unwrap();
    assert_eq!(attempt.queries.len(), 1);
    assert!(
        attempt.queries[0].returned_reads.is_none(),
        "unavailable internal reply must stay unknown"
    );
    b.release();
    finish(&mut owner).await;
    assert!(owner.snapshot().latest_voltage.unwrap().preview.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renewed_identity_calibration_and_dac_failures_retain_exact_phase_and_fence_both_lanes() {
    for defect in 0..3 {
        let a = bus0::Backend::new(bus0::Fault::None, None);
        let b = ControlledApw::new();
        let mut owner = diagnosed(&a, &b).await;
        owner.merge_requested_voltage(Some(13.4), None).unwrap();
        match defect {
            0 => b.foreign_hardware.store(true, Ordering::SeqCst),
            1 => b.bad_calibration.store(true, Ordering::SeqCst),
            _ => b.dac.store(0xffff, Ordering::SeqCst),
        }
        let observed = owner
            .observe_voltage_once(Instant::now() + Duration::from_secs(6))
            .await
            .unwrap();
        assert!(observed.stopped_at.is_some());
        assert!(
            owner.handles.bus0.terminal_safe_off_is_latched()
                && owner.handles.bus1.terminal_safe_off_is_latched()
        );
        let last = observed.latest_voltage.unwrap();
        assert!(last.failure.is_some() && last.preview.is_none());
        assert!(last.caller_joined_at.is_some());
        assert_eq!(last.attempt.unwrap().queries.len(), [1, 3, 4][defect]);
        assert_eq!(
            &b.inner.opcodes()[4..],
            [&[2][..], &[2, 1, 6][..], &[2, 1, 6, 3][..]][defect]
        );
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn either_external_terminal_latch_prevents_a_later_deadline_from_reopening_normal_work() {
    for bus in 0..2 {
        let a = bus0::Backend::new(bus0::Fault::None, None);
        let b = ControlledApw::new();
        let mut owner = diagnosed(&a, &b).await;
        if bus == 0 {
            owner.handles.bus0.latch_terminal_safe_off();
        } else {
            owner.handles.bus1.latch_terminal_safe_off();
        }
        assert!(owner.snapshot().stopped_at.is_some());
        assert!(
            owner.handles.bus0.terminal_safe_off_is_latched()
                && owner.handles.bus1.terminal_safe_off_is_latched()
        );
        assert!(owner
            .observe_voltage_once(Instant::now() + Duration::from_secs(30))
            .await
            .is_err());
        assert_eq!(b.inner.opcodes(), [2, 1, 6, 3]);
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_or_equal_requested_voltage_stays_a_numerical_non_request() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = ControlledApw::new();
    let mut owner = diagnosed(&a, &b).await;
    for target in [None, Some(14.67)] {
        owner.merge_requested_voltage(target, None).unwrap();
        let observed = owner
            .observe_voltage_once(Instant::now() + Duration::from_secs(6))
            .await
            .unwrap();
        assert!(observed.stopped_at.is_none());
        let preview = observed.latest_voltage.unwrap().preview.unwrap();
        assert_eq!(preview.reported_millivolts, 14670);
        assert!(preview.selected_pair.is_none() && preview.first_step.is_none());
    }
    assert_eq!(b.inner.opcodes(), [2, 1, 6, 3, 2, 1, 6, 3, 2, 1, 6, 3]);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outer_cancelled_pre_power_future_keeps_actual_paired_callers_for_cleanup() {
    let a = bus0::Backend::new(bus0::Fault::None, Some((0x48, 0)));
    let b = ControlledApw::new();
    b.armed.store(true, Ordering::SeqCst);
    let _release = Release(b.clone(), a.clone());
    let mut owner = new_owner(&a, &b);
    {
        let observe =
            owner.observe_pre_power_once(&[0x50], Instant::now() + Duration::from_secs(12));
        tokio::pin!(observe);
        tokio::select! { _ = a.wait_entered() => {}, _ = &mut observe => panic!("premature completion") }
        tokio::select! { _ = b.wait_entered() => {}, _ = &mut observe => panic!("premature completion") }
    }
    assert!(owner.snapshot().stopped_at.is_some());
    assert!(
        owner.handles.bus0.terminal_safe_off_is_latched()
            && owner.handles.bus1.terminal_safe_off_is_latched()
    );
    assert!(owner
        .observe_voltage_once(Instant::now() + Duration::from_secs(30))
        .await
        .is_err());
    assert!(
        !owner
            .join_callers_until(Instant::now() + Duration::from_millis(10))
            .await
    );
    assert!(!tokio::task::block_in_place(
        || owner.close_services_until(Instant::now() + Duration::from_millis(10))
    )
    .unwrap());
    a.release();
    b.release();
    finish(&mut owner).await;
    assert!(owner.snapshot().diagnostics.historical.is_none());
}
