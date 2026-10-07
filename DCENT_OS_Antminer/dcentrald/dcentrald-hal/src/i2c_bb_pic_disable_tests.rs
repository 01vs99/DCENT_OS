use super::*;
use crate::platform::sim::{SimControllerKind, SimI2cBackend};
use std::sync::Condvar;

struct Backend {
    identity: SimI2cBackend,
    reply: [u8; 2],
    index: Mutex<usize>,
    writes: Mutex<Vec<(Instant, u8, Vec<u8>)>>,
    fail_read: Option<usize>,
    short_read: bool,
    block_read: Option<usize>,
    panic_read: bool,
    block_write: bool,
    gate: (Mutex<(bool, bool)>, Condvar),
}
impl Backend {
    fn new(reply: [u8; 2]) -> Self {
        Self {
            identity: SimI2cBackend::with_controller(SimControllerKind::Dspic),
            reply,
            index: Mutex::new(0),
            writes: Mutex::new(Vec::new()),
            fail_read: None,
            short_read: false,
            block_read: None,
            panic_read: false,
            block_write: false,
            gate: (Mutex::new((false, false)), Condvar::new()),
        }
    }
    fn entered(&self) {
        let guard = self.gate.0.lock().unwrap();
        let (guard, timeout) = self
            .gate
            .1
            .wait_timeout_while(guard, Duration::from_secs(3), |v| !v.0)
            .unwrap();
        assert!(guard.0 && !timeout.timed_out());
    }
    fn release(&self) {
        self.gate.0.lock().unwrap().1 = true;
        self.gate.1.notify_all();
    }
}
impl I2cSimBackend for Backend {
    fn service_identity(&self) -> Option<usize> {
        self.identity.service_identity()
    }
    fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> Result<usize> {
        assert_eq!(bus, 0);
        assert!((0x20..=0x22).contains(&addr));
        assert_eq!(bytes, REQUEST);
        *self.index.lock().unwrap() = 0;
        self.writes
            .lock()
            .unwrap()
            .push((Instant::now(), addr, bytes.to_vec()));
        if self.block_write {
            let mut guard = self.gate.0.lock().unwrap();
            guard.0 = true;
            self.gate.1.notify_all();
            let (guard, timeout) = self
                .gate
                .1
                .wait_timeout_while(guard, Duration::from_secs(5), |v| !v.1)
                .unwrap();
            assert!(guard.1 && !timeout.timed_out());
        }
        Ok(bytes.len())
    }
    fn read(&self, bus: u8, addr: u8, raw: &mut [u8]) -> Result<usize> {
        assert_eq!((bus, raw.len()), (0, 1));
        let index = *self.index.lock().unwrap();
        if self.block_read == Some(index) {
            let mut guard = self.gate.0.lock().unwrap();
            guard.0 = true;
            self.gate.1.notify_all();
            let (guard, timeout) = self
                .gate
                .1
                .wait_timeout_while(guard, Duration::from_secs(5), |v| !v.1)
                .unwrap();
            assert!(guard.1 && !timeout.timed_out());
        }
        if self.panic_read {
            panic!("authored original worker unwind");
        }
        if self.fail_read == Some(index) {
            return Err(HalError::I2c {
                bus,
                addr,
                detail: "authored original read transport failure".into(),
            });
        }
        if self.short_read {
            return Ok(0);
        }
        raw[0] = self.reply[index];
        *self.index.lock().unwrap() += 1;
        Ok(1)
    }
    fn write_read(&self, _: u8, _: u8, _: &[u8], _: &mut [u8]) -> Result<()> {
        panic!("combined transfer not in original disable recipe");
    }
}
struct Release(Arc<Backend>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
fn owner(bus: u8, backend: Arc<Backend>) -> I2cServiceOwner {
    spawn_owned_sim_i2c_service(bus, backend, (0x50..=0x57).collect()).unwrap()
}
fn due() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn reads(state: &WorkerObservation) -> Vec<Vec<u8>> {
    state
        .steps
        .iter()
        .filter(|x| matches!(x.operation, Operation::ReadReply))
        .filter_map(|x| x.returned_bytes.clone())
        .collect()
}

#[test]
fn original_reserved_worker_retains_two_unvalidated_bytes_and_all_four_waits_on_physical_slots() {
    // Deliberately non-ACK values: successful transport must retain them, never
    // relabel these fixtures as physical OFF or an accepted firmware reply.
    for reply in [[0x15, 0], [0, 0], [0xff, 0xff]] {
        let backend = Arc::new(Backend::new(reply));
        let mut service = owner(0, backend.clone());
        let handle = service.request_handle();
        service.terminal_fence().latch_terminal_safe_off();
        for slot in [2, 0, 1] {
            let deadline = due();
            let attempt = handle.disable_bb_pic_at(slot, deadline);
            assert!(attempt.failure.is_none(), "{:?}", attempt.failure);
            assert!(attempt.enqueued && attempt.timely_receipt_at.unwrap() < deadline);
            assert_eq!(
                (attempt.native_slot, attempt.pic_address),
                (slot, Some(0x20 + slot as u8))
            );
            let state = attempt.worker_snapshot();
            assert_eq!(state.deadline, deadline);
            assert_eq!(reads(&state), reply.map(|x| vec![x]));
            assert!(state.failure.is_none());
            assert!(state.transport_completed_at.unwrap() < deadline);
            assert!(state.worker_returned_at.unwrap() <= state.worker_finalized_at.unwrap());
            let waits: Vec<_> = state
                .steps
                .iter()
                .filter_map(|step| match step.operation {
                    Operation::Wait(d) => Some((d, step)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                waits.iter().map(|(d, _)| d.as_millis()).collect::<Vec<_>>(),
                [50, 20, 20, 20]
            );
            for (duration, step) in waits {
                assert!(step.returned_at.unwrap().duration_since(step.started_at) >= duration);
            }
        }
        assert_eq!(
            backend
                .writes
                .lock()
                .unwrap()
                .iter()
                .map(|x| x.1)
                .collect::<Vec<_>>(),
            [0x22, 0x20, 0x21]
        );
        assert!(service.close_and_join_until(due()).is_ok());
    }
}

#[test]
fn wrong_bus_slot_or_expired_deadline_refuses_before_mailbox_or_wire() {
    for (bus, slot, expired) in [(1, 0, false), (0, 3, false), (0, 0, true)] {
        let backend = Arc::new(Backend::new([0x15, 0]));
        let mut service = owner(bus, backend.clone());
        let deadline = if expired { Instant::now() } else { due() };
        let attempt = service.request_handle().disable_bb_pic_at(slot, deadline);
        assert!(
            attempt.failure.is_some() && !attempt.enqueued && attempt.timely_receipt_at.is_none()
        );
        assert!(attempt.worker_snapshot().worker_started_at.is_none());
        assert!(backend.writes.lock().unwrap().is_empty());
        assert!(service.close_and_join_until(due()).is_ok());
    }
}

#[test]
fn original_first_or_second_read_failure_retains_partial_history_without_transport_replay() {
    for fail in [0, 1] {
        let mut backend = Backend::new([0x15, 0]);
        backend.fail_read = Some(fail);
        let backend = Arc::new(backend);
        let mut service = owner(0, backend.clone());
        let attempt = service.request_handle().disable_bb_pic_at(0, due());
        assert!(
            attempt.enqueued && attempt.failure.is_some() && attempt.timely_receipt_at.is_none()
        );
        let state = attempt.worker_snapshot();
        assert_eq!(reads(&state).len(), fail);
        assert!(state
            .steps
            .last()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("authored original read transport failure"));
        assert!(state.transport_completed_at.is_none() && state.worker_finalized_at.is_some());
        assert_eq!(backend.writes.lock().unwrap().len(), 1);
        assert!(service.close_and_join_until(due()).is_ok());
    }
}

#[test]
fn actual_short_read_is_retained_as_empty_and_never_completed() {
    let mut backend = Backend::new([0x15, 0]);
    backend.short_read = true;
    let backend = Arc::new(backend);
    let mut service = owner(0, backend.clone());
    let attempt = service.request_handle().disable_bb_pic_at(0, due());
    assert!(attempt.failure.as_ref().unwrap().contains("short reply"));
    let state = attempt.worker_snapshot();
    assert_eq!(reads(&state), vec![Vec::<u8>::new()]);
    assert!(state.transport_completed_at.is_none());
    assert_eq!(backend.writes.lock().unwrap().len(), 1);
    assert!(service.close_and_join_until(due()).is_ok());
}

#[test]
fn started_second_read_outlives_caller_without_losing_first_or_actual_late_second_byte() {
    let mut backend = Backend::new([0x15, 0]);
    backend.block_read = Some(1);
    let backend = Arc::new(backend);
    let _release = Release(backend.clone());
    let mut service = owner(0, backend.clone());
    let handle = service.request_handle();
    let deadline = Instant::now() + Duration::from_millis(250);
    let caller = std::thread::spawn(move || handle.disable_bb_pic_at(0, deadline));
    backend.entered();
    let attempt = caller.join().unwrap();
    assert!(attempt.enqueued && attempt.failure.is_some() && attempt.timely_receipt_at.is_none());
    let original_failure = attempt.failure.clone();
    let pending = attempt.worker_snapshot();
    assert_eq!(reads(&pending), vec![vec![0x15]]);
    assert!(pending.worker_returned_at.is_none() && pending.worker_finalized_at.is_none());
    assert!(service
        .close_and_join_until(Instant::now() + Duration::from_millis(20))
        .is_err());
    backend.release();
    assert!(service.close_and_join_until(due()).is_ok());
    let after = attempt.worker_snapshot();
    assert_eq!(reads(&after), vec![vec![0x15], vec![0]]);
    assert!(after.worker_returned_at.unwrap() >= deadline && after.worker_finalized_at.is_some());
    assert!(after.transport_completed_at.is_none() && after.failure.is_some());
    assert_eq!(attempt.failure, original_failure);
    assert!(attempt.timely_receipt_at.is_none());
    assert_eq!(backend.writes.lock().unwrap().len(), 1);
}

#[test]
fn original_deadline_after_confirmed_write_never_starts_late_reply() {
    let mut backend = Backend::new([0x15, 0]);
    backend.block_write = true;
    let backend = Arc::new(backend);
    let _release = Release(backend.clone());
    let mut service = owner(0, backend.clone());
    let handle = service.request_handle();
    let deadline = Instant::now() + Duration::from_secs(2);
    let caller = std::thread::spawn(move || handle.disable_bb_pic_at(0, deadline));
    backend.entered();
    assert!(Instant::now() < deadline);
    // Actual write entry is established, then released near the SAME original
    // deadline. If scheduling delays its return further, that late write is
    // retained; the test never assumes the worker necessarily entered Wait.
    std::thread::sleep(
        (deadline - Duration::from_millis(20)).saturating_duration_since(Instant::now()),
    );
    backend.release();
    let attempt = caller.join().unwrap();
    assert!(attempt.failure.is_some());
    assert!(service.close_and_join_until(due()).is_ok());
    let state = attempt.worker_snapshot();
    assert!(reads(&state).is_empty() && state.transport_completed_at.is_none());
    assert_eq!(backend.writes.lock().unwrap().len(), 1);
}

#[test]
fn worker_unwind_keeps_admitted_partial_record_and_finishes_receipt_without_replay() {
    let mut backend = Backend::new([0x15, 0]);
    backend.panic_read = true;
    let backend = Arc::new(backend);
    let mut service = owner(0, backend.clone());
    let attempt = service.request_handle().disable_bb_pic_at(0, due());
    assert!(attempt.failure.is_some() && attempt.enqueued);
    let state = attempt.worker_snapshot();
    assert!(state.failure.is_some());
    assert!(state.worker_started_at.is_some() && state.worker_returned_at.is_none());
    assert!(state.worker_finalized_at.is_some() && state.transport_completed_at.is_none());
    assert!(state.steps.last().unwrap().returned_at.is_none());
    assert_eq!(backend.writes.lock().unwrap().len(), 1);
    // An unwound original worker cannot produce a successful close receipt.
    assert!(service.close_and_join_until(due()).is_err());
}

#[test]
fn queued_expiry_behind_actual_started_read_retains_original_attempt_without_disable_write() {
    let mut backend = Backend::new([0x15, 0]);
    backend.block_read = Some(0);
    let backend = Arc::new(backend);
    let _release = Release(backend.clone());
    let mut service = owner(0, backend.clone());
    let occupied = service.request_handle();
    let normal = std::thread::spawn(move || occupied.read_bytes(0x20, 1));
    backend.entered();
    let attempt = service
        .request_handle()
        .disable_bb_pic_at(0, Instant::now() + Duration::from_millis(100));
    assert!(attempt.enqueued && attempt.failure.is_some());
    assert!(attempt.worker_snapshot().worker_started_at.is_none());
    backend.release();
    let _ = normal.join().unwrap();
    assert!(service.close_and_join_until(due()).is_ok());
    let state = attempt.worker_snapshot();
    assert!(state.worker_finalized_at.is_some() && state.transport_completed_at.is_none());
    assert!(state.steps.is_empty() && backend.writes.lock().unwrap().is_empty());
}

#[test]
fn original_closed_mailbox_cannot_admit_a_new_fixed_disable_attempt() {
    let backend = Arc::new(Backend::new([0x15, 0]));
    let mut service = owner(0, backend.clone());
    let handle = service.request_handle();
    let close = service.close_and_join_until(due()).unwrap();
    assert_eq!(close.bus(), 0);
    assert!(service.worker.is_none());
    let generation = handle.safety.generation.load(Ordering::SeqCst);
    let deadline = due();
    let attempt = handle.disable_bb_pic_at(0, deadline);
    assert!(!attempt.enqueued && attempt.timely_receipt_at.is_none());
    assert_eq!(attempt.deadline, deadline);
    assert!(attempt.caller_returned_at.unwrap() >= attempt.caller_started_at);
    assert!(attempt
        .failure
        .as_ref()
        .unwrap()
        .contains("SafeOff request was not admitted: I2C service lifecycle close is in progress"));
    assert!(handle.safety.generation.load(Ordering::SeqCst) > generation);
    let state = attempt.worker_snapshot();
    assert_eq!(state.deadline, deadline);
    assert!(state.worker_started_at.is_none() && state.worker_returned_at.is_none());
    assert!(state.worker_finalized_at.is_none() && state.transport_completed_at.is_none());
    assert!(state.steps.is_empty() && state.failure.is_none());
    let mailbox = handle.safe_off_mailbox.as_ref().unwrap();
    assert_eq!(mailbox.pending_endpoint_count(), 0);
    assert_eq!(mailbox.pending_waiter_count(0x20), 0);
    assert!(backend.writes.lock().unwrap().is_empty());
    assert_eq!(*backend.index.lock().unwrap(), 0);
}
