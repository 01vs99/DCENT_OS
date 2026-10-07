use super::*;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Wire {
    bytes: Mutex<Vec<Vec<u8>>>,
    mode: AtomicU8,
    entered: Mutex<bool>,
    released: Mutex<bool>,
    condition: Condvar,
}

impl Wire {
    fn trace(&self) -> Vec<Vec<u8>> {
        self.bytes.lock().unwrap().clone()
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }
    fn wait_entered(&self) {
        let until = Instant::now() + Duration::from_secs(2);
        while !*self.entered.lock().unwrap() {
            assert!(
                Instant::now() < until,
                "simulated UART caller did not enter"
            );
            std::thread::yield_now();
        }
    }
}

struct Uart(Arc<Wire>);
impl ChainUart for Uart {
    fn write_frame(&mut self, bytes: &[u8]) -> Result<(), UartTransportError> {
        match self.0.mode.load(Ordering::SeqCst) {
            1 => {
                self.0
                    .bytes
                    .lock()
                    .unwrap()
                    .push(bytes[..bytes.len().min(2)].to_vec());
                return Err(UartTransportError::WriteFailed);
            }
            2 => panic!("injected UART caller unwind"),
            3 => {
                *self.0.entered.lock().unwrap() = true;
                let guard = self.0.released.lock().unwrap();
                let (_guard, result) = self
                    .0
                    .condition
                    .wait_timeout_while(guard, Duration::from_secs(3), |released| !*released)
                    .unwrap();
                assert!(!result.timed_out(), "bounded simulated UART wait expired");
            }
            _ => {}
        }
        self.0.bytes.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }
    fn read_avail(&mut self, _: &mut [u8]) -> usize {
        0
    }
}

struct Release(Arc<Wire>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn owner() -> (BbDispatchOwner<Uart>, Arc<Wire>) {
    let wire = Arc::new(Wire::default());
    let transport = Am335xUartTransport::new(
        vec![Uart(wire.clone())],
        super::super::MIN_DISPATCH_INTERVAL_US,
    );
    (BbDispatchOwner::new(transport), wire)
}

fn frame() -> AsicWorkFrame {
    AsicWorkFrame {
        type_byte: 0x21,
        rsvd1: 0,
        job_id: 0x42,
        rsvd2: 0,
        sno: 5,
        data2: [3; 12],
        data: [4; 64],
    }
}

#[test]
fn raw_frames_ring_and_pacing_survive_explicit_hold_and_resume() {
    let (mut owner, wire) = owner();
    assert_eq!(owner.chain_count(), 1);
    assert_eq!(owner.try_send_raw(0, &[1, 2, 3], 7, 0), Ok(true));
    let prior = owner.in_flight_ring(0);
    {
        let held = owner.hold_dispatch().unwrap();
        assert!(held.snapshot().held);
        assert!(!held.snapshot().send_caller_pending);
        assert_eq!(wire.trace(), [vec![1, 2, 3]]);
        held.resume().unwrap();
    }
    assert_eq!(owner.in_flight_ring(0), prior);
    assert_eq!(owner.try_send_raw(0, &[4, 5], 8, 1), Ok(false));
    assert_eq!(wire.trace(), [vec![1, 2, 3]]);
    assert_eq!(owner.try_send_raw(0, &[4, 5], 8, 20_000), Ok(true));
    assert_eq!(wire.trace(), [vec![1, 2, 3], vec![4, 5]]);
    assert_eq!(&owner.in_flight_ring(0).unwrap()[..2], &[Some(7), Some(8)]);
    assert!(!owner.snapshot().send_caller_pending);
}

#[test]
fn existing_diagnostic_codec_bytes_pass_through_the_same_transport() {
    let (mut owner, wire) = owner();
    let frame = frame();
    let expected = super::super::wire_frame_bytes(&frame);
    assert_eq!(owner.try_send_work(0, &frame, 0), Ok(true));
    assert_eq!(wire.trace(), [expected.to_vec()]);
    assert_eq!(owner.in_flight_ring(0).unwrap()[0], Some(frame.job_id));
}

#[test]
fn dropped_hold_permanently_stops_without_erasing_prior_wire_history() {
    let (mut owner, wire) = owner();
    owner.try_send_raw(0, &[1, 2], 4, 0).unwrap();
    let prior = owner.in_flight_ring(0);
    drop(owner.hold_dispatch().unwrap());
    assert!(owner.snapshot().permanently_stopped);
    assert!(!owner.snapshot().send_caller_pending);
    assert_eq!(
        owner.try_send_raw(0, &[3, 4], 5, 99_000),
        Err(DispatchError::Stopped)
    );
    assert_eq!(
        owner.try_send_work(0, &frame(), 99_000),
        Err(DispatchError::Stopped)
    );
    assert!(matches!(owner.hold_dispatch(), Err(DispatchError::Stopped)));
    assert_eq!(owner.in_flight_ring(0), prior);
    assert_eq!(wire.trace(), [vec![1, 2]]);
}

#[test]
fn forgotten_hold_cannot_be_bypassed_by_reborrowing_the_owner() {
    let (mut owner, wire) = owner();
    std::mem::forget(owner.hold_dispatch().unwrap());
    assert_eq!(
        owner.try_send_raw(0, &[1, 2], 5, 99_000),
        Err(DispatchError::HeldOrPending)
    );
    assert!(matches!(
        owner.hold_dispatch(),
        Err(DispatchError::HeldOrPending)
    ));
    assert!(wire.trace().is_empty());
    owner.stop_handle().stop();
    assert_eq!(
        owner.try_send_raw(0, &[1, 2], 5, 99_000),
        Err(DispatchError::Stopped)
    );
}

#[test]
fn external_stop_keeps_admitted_blocked_write_pending_until_its_real_caller_returns() {
    let (mut owner, wire) = owner();
    let _release = Release(wire.clone());
    wire.mode.store(3, Ordering::SeqCst);
    let stop = owner.stop_handle();
    let caller = std::thread::spawn(move || {
        let result = owner.try_send_raw(0, &[1, 2, 3, 4], 7, 0);
        (owner, result)
    });
    wire.wait_entered();
    let stopped = stop.stop();
    assert!(stopped.permanently_stopped && stopped.send_caller_pending);
    assert!(!caller.is_finished());
    assert!(wire.trace().is_empty());
    wire.release();
    let (mut owner, result) = caller.join().unwrap();
    assert_eq!(result, Err(DispatchError::Stopped));
    assert!(stop.snapshot().permanently_stopped && !stop.snapshot().send_caller_pending);
    // This write was admitted before stop and really completed afterwards.
    // Its real frame/ring history must not disappear behind the terminal error.
    assert_eq!(wire.trace(), [vec![1, 2, 3, 4]]);
    assert_eq!(owner.in_flight_ring(0).unwrap()[0], Some(7));
    assert_eq!(
        owner.try_send_raw(0, &[9, 9], 8, 99_000),
        Err(DispatchError::Stopped)
    );
    assert_eq!(wire.trace().len(), 1);
}

#[test]
fn partial_write_failure_stops_this_owner_and_cannot_be_retried_as_a_fresh_frame() {
    let (mut owner, wire) = owner();
    wire.mode.store(1, Ordering::SeqCst);
    assert_eq!(
        owner.try_send_raw(0, &[1, 2, 3, 4], 7, 0),
        Err(DispatchError::Transport(UartTransportError::WriteFailed))
    );
    assert_eq!(wire.trace(), [vec![1, 2]]);
    assert!(owner.in_flight_ring(0).unwrap().iter().all(Option::is_none));
    wire.mode.store(0, Ordering::SeqCst);
    assert_eq!(
        owner.try_send_raw(0, &[1, 2, 3, 4], 7, 0),
        Err(DispatchError::Stopped)
    );
    assert!(!owner.snapshot().send_caller_pending);
    assert_eq!(wire.trace(), [vec![1, 2]]);
}

#[test]
fn unwound_send_clears_pending_only_after_latching_permanent_stop() {
    let (mut owner, wire) = owner();
    wire.mode.store(2, Ordering::SeqCst);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.try_send_raw(0, &[1, 2, 3], 7, 0)
    }));
    assert!(result.is_err());
    assert!(owner.snapshot().permanently_stopped && !owner.snapshot().send_caller_pending);
    wire.mode.store(0, Ordering::SeqCst);
    assert_eq!(
        owner.try_send_work(0, &frame(), 0),
        Err(DispatchError::Stopped)
    );
    assert!(wire.trace().is_empty());
}

#[test]
fn terminal_publisher_prevents_resume_and_outlives_the_retained_owner() {
    let (mut owner, wire) = owner();
    let stop = owner.stop_handle();
    let held = owner.hold_dispatch().unwrap();
    stop.stop();
    assert_eq!(held.resume(), Err(DispatchError::Stopped));
    assert_eq!(
        owner.try_send_raw(0, &[1, 2], 7, 0),
        Err(DispatchError::Stopped)
    );
    drop(owner);
    assert!(stop.snapshot().permanently_stopped && !stop.snapshot().send_caller_pending);
    assert!(wire.trace().is_empty());
}

#[test]
fn dropping_an_idle_owner_closes_admission_on_its_original_stop_publisher() {
    let (owner, wire) = owner();
    let stop = owner.stop_handle();
    assert!(!stop.snapshot().permanently_stopped);
    drop(owner);
    assert!(stop.snapshot().permanently_stopped && !stop.snapshot().send_caller_pending);
    assert!(wire.trace().is_empty());
}
