use super::*;
use std::collections::VecDeque;
use std::sync::atomic::AtomicUsize;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

struct Input {
    chunks: Mutex<VecDeque<Result<Vec<u8>, String>>>,
    reads: AtomicUsize,
    writes: Mutex<Vec<Vec<u8>>>,
    mode: AtomicU8,
    entered: AtomicU8,
    released: Mutex<bool>,
    condition: Condvar,
}

impl Input {
    fn new(chunks: Vec<Result<Vec<u8>, String>>) -> Arc<Self> {
        Arc::new(Self {
            chunks: Mutex::new(chunks.into()),
            reads: AtomicUsize::new(0),
            writes: Mutex::new(Vec::new()),
            mode: AtomicU8::new(0),
            entered: AtomicU8::new(0),
            released: Mutex::new(false),
            condition: Condvar::new(),
        })
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }
    fn wait_entered(&self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.entered.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
    }
}

struct Uart(Arc<Input>);
impl ChainUart for Uart {
    fn write_frame(&mut self, bytes: &[u8]) -> Result<(), UartTransportError> {
        self.0.writes.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }
    fn read_avail(&mut self, _: &mut [u8]) -> usize {
        panic!("new owner must use checked reads")
    }
}
impl CheckedChainUart for Uart {
    fn read_avail_checked(&mut self, bytes: &mut [u8]) -> CheckedRead {
        self.read_result(bytes).into()
    }
}
impl Uart {
    fn read_result(&mut self, bytes: &mut [u8]) -> Result<usize, String> {
        self.0.reads.fetch_add(1, Ordering::SeqCst);
        match self.0.mode.load(Ordering::SeqCst) {
            1 => {
                bytes.fill(0xff);
                return Ok(bytes.len());
            }
            2 => {
                bytes.fill(0xaa);
                return Ok(bytes.len() + 1);
            }
            3 => {
                self.0.entered.store(1, Ordering::SeqCst);
                let guard = self.0.released.lock().unwrap();
                let (_guard, result) = self
                    .0
                    .condition
                    .wait_timeout_while(guard, Duration::from_secs(3), |released| !*released)
                    .unwrap();
                assert!(
                    !result.timed_out(),
                    "bounded checked-read fixture timed out"
                );
            }
            4 => panic!("injected checked-read unwind"),
            _ => {}
        }
        let value = self
            .0
            .chunks
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(Vec::new()))?;
        assert!(value.len() <= bytes.len());
        bytes[..value.len()].copy_from_slice(&value);
        Ok(value.len())
    }
}

struct Release(Arc<Input>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn owner(inputs: &[Arc<Input>]) -> BbDispatchOwner<Uart> {
    BbDispatchOwner::new(Am335xUartTransport::new(
        inputs.iter().cloned().map(Uart).collect(),
        20_000,
    ))
}
fn nonce(seed: u8) -> Vec<u8> {
    vec![0xaa, 0x55, seed, 2, 3, 4, 0, 0x80, 0x12, 0x34, 0x80]
}

#[test]
fn sustained_noise_is_limited_to_one_checked_read_per_chain_and_keeps_dispatch_held() {
    let inputs: Vec<_> = (0..3).map(|_| Input::new(Vec::new())).collect();
    for input in &inputs {
        input.mode.store(1, Ordering::SeqCst);
    }
    let mut owner = owner(&inputs);
    let mut held = owner.hold_dispatch().unwrap();
    for round in 1..=3 {
        let result = held.receive_once();
        assert!(result.caller_completed && result.failure.is_none());
        assert_eq!(result.reads.len(), 3);
        assert!(result.nonces.is_empty());
        assert!(
            held.snapshot().held
                && !held.snapshot().receive_caller_pending
                && !held.snapshot().send_caller_pending
        );
        for input in &inputs {
            assert_eq!(input.reads.load(Ordering::SeqCst), round);
            assert!(input.writes.lock().unwrap().is_empty());
        }
    }
    held.resume().unwrap();
    assert!(!owner.snapshot().held);
    assert!(owner
        .transport
        .bm1362_serial_rx_counters()
        .iter()
        .all(|counter| counter.raw_bytes == 768 && counter.buffered_bytes <= 1));
}

#[test]
fn partial_nonce_tail_survives_held_polls_without_resetting_work_ring_or_pacing() {
    let wire = nonce(7);
    let input = Input::new(vec![Ok(wire[..5].to_vec()), Ok(wire[5..].to_vec())]);
    let mut owner = owner(&[input.clone()]);
    owner.try_send_raw(0, &[1, 2, 3], 4, 0).unwrap();
    let ring = owner.in_flight_ring(0);
    let mut held = owner.hold_dispatch().unwrap();
    let first = held.receive_once();
    assert!(first.caller_completed && first.nonces.is_empty());
    assert_eq!(first.reads[0].returned_prefix.as_ref().unwrap(), &wire[..5]);
    let second = held.receive_once();
    assert!(second.caller_completed && second.failure.is_none());
    assert_eq!(second.nonces.len(), 1);
    assert_eq!(second.nonces[0].1.raw_frame.as_slice(), wire);
    held.resume().unwrap();
    assert_eq!(owner.in_flight_ring(0), ring);
    assert_eq!(owner.try_send_raw(0, &[4, 5], 5, 1), Ok(false));
    assert_eq!(input.writes.lock().unwrap().len(), 1);
}

#[test]
fn later_chain_read_error_keeps_earlier_nonce_and_stops_before_remaining_chain() {
    let first = Input::new(vec![Ok(nonce(1))]);
    let second = Input::new(vec![Err("actual adapter failure detail".into())]);
    let third = Input::new(vec![Ok(nonce(3))]);
    let mut owner = owner(&[first.clone(), second.clone(), third.clone()]);
    let result = owner.receive_once();
    assert!(!result.caller_completed);
    assert_eq!(
        result.failure,
        Some(ReceiveError::Read {
            chain: 1,
            detail: "actual adapter failure detail".into()
        })
    );
    assert_eq!(result.nonces.len(), 1);
    assert_eq!(result.nonces[0].1.raw_frame.as_slice(), nonce(1));
    assert_eq!(result.reads.len(), 2);
    assert!(result.reads[1].returned_count.is_none() && result.reads[1].returned_prefix.is_none());
    assert_eq!(
        result.reads[1].error.as_deref(),
        Some("actual adapter failure detail")
    );
    assert_eq!(third.reads.load(Ordering::SeqCst), 0);
    assert!(owner.snapshot().permanently_stopped && !owner.snapshot().receive_caller_pending);
    let refused = owner.receive_once();
    assert!(matches!(
        refused.failure,
        Some(ReceiveError::Admission(DispatchError::Stopped))
    ));
    assert_eq!(first.reads.load(Ordering::SeqCst), 1);
}

#[test]
fn oversized_return_count_is_retained_and_refused_without_parsing_or_next_read() {
    let first = Input::new(Vec::new());
    first.mode.store(2, Ordering::SeqCst);
    let second = Input::new(vec![Ok(nonce(2))]);
    let mut owner = owner(&[first, second.clone()]);
    let result = owner.receive_once();
    assert_eq!(
        result.failure,
        Some(ReceiveError::InvalidCount {
            chain: 0,
            reported: 257,
            capacity: 256
        })
    );
    assert_eq!(result.reads[0].returned_count, Some(257));
    assert_eq!(result.reads[0].returned_prefix.as_ref().unwrap().len(), 256);
    assert!(result.nonces.is_empty() && !result.caller_completed);
    assert_eq!(second.reads.load(Ordering::SeqCst), 0);
    assert_eq!(owner.transport.bm1362_serial_rx_counters()[0].raw_bytes, 0);
    assert!(owner.snapshot().permanently_stopped);
}

#[test]
fn external_stop_during_admitted_read_preserves_returned_nonce_and_prevents_next_chain() {
    let first = Input::new(vec![Ok(nonce(1))]);
    first.mode.store(3, Ordering::SeqCst);
    let _release = Release(first.clone());
    let second = Input::new(vec![Ok(nonce(2))]);
    let mut owner = owner(&[first.clone(), second.clone()]);
    let stop = owner.stop_handle();
    let task = std::thread::spawn(move || {
        let mut held = owner.hold_dispatch().unwrap();
        let result = held.receive_once();
        let resumed = held.resume();
        (owner, result, resumed)
    });
    first.wait_entered();
    let during = stop.stop();
    assert!(
        during.held
            && during.receive_caller_pending
            && during.permanently_stopped
            && !during.send_caller_pending
    );
    assert!(!task.is_finished());
    first.release();
    let (owner, result, resumed) = task.join().unwrap();
    assert_eq!(result.failure, Some(ReceiveError::Stopped));
    assert!(!result.caller_completed);
    assert_eq!(result.nonces.len(), 1);
    assert_eq!(result.nonces[0].1.raw_frame.as_slice(), nonce(1));
    assert_eq!(resumed, Err(DispatchError::Stopped));
    assert_eq!(second.reads.load(Ordering::SeqCst), 0);
    assert!(owner.snapshot().permanently_stopped && !owner.snapshot().receive_caller_pending);
}

#[test]
fn read_unwind_fences_before_clearing_the_receive_scope_and_hold_cannot_resume() {
    let input = Input::new(Vec::new());
    input.mode.store(4, Ordering::SeqCst);
    let mut owner = owner(&[input]);
    let mut held = owner.hold_dispatch().unwrap();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| held.receive_once()));
    assert!(unwind.is_err());
    assert!(held.snapshot().permanently_stopped && !held.snapshot().receive_caller_pending);
    assert_eq!(held.resume(), Err(DispatchError::Stopped));
}

#[test]
fn terminal_and_forgotten_hold_refuse_reads_before_touching_the_original_backend() {
    for terminal in [false, true] {
        let input = Input::new(vec![Ok(nonce(1))]);
        let mut owner = owner(&[input.clone()]);
        if terminal {
            owner.stop_handle().stop();
        } else {
            std::mem::forget(owner.hold_dispatch().unwrap());
        }
        let result = owner.receive_once();
        assert!(result.reads.is_empty() && result.nonces.is_empty() && !result.caller_completed);
        assert_eq!(
            result.failure,
            Some(ReceiveError::Admission(if terminal {
                DispatchError::Stopped
            } else {
                DispatchError::HeldOrPending
            }))
        );
        assert_eq!(input.reads.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn running_receive_preserves_raw_candidates_and_metadata_without_writing_new_work() {
    let mut bytes = vec![0, 1, 2];
    bytes.extend(nonce(8));
    bytes.extend(nonce(9));
    let input = Input::new(vec![Ok(bytes.clone())]);
    let mut owner = owner(&[input.clone()]);
    let result = owner.receive_once();
    assert!(result.caller_completed && result.failure.is_none());
    assert_eq!(result.nonces.len(), 2);
    assert_eq!(result.reads[0].returned_prefix.as_ref().unwrap(), &bytes);
    assert_eq!(result.nonces[0].0, 0);
    assert_eq!(result.nonces[0].1.nonce, u32::from_le_bytes([8, 2, 3, 4]));
    assert_eq!(result.nonces[0].1.version_bits_raw, 0x1234);
    assert_eq!(result.nonces[0].1.job_id, 0x40);
    assert!(input.writes.lock().unwrap().is_empty());
    let counters = owner.transport.bm1362_serial_rx_counters();
    assert_eq!(counters[0].parsed_frames, 2);
    assert_eq!(counters[0].resync_bytes, 3);
}

struct ReportUart {
    report: CheckedRead,
    wire: Vec<u8>,
    calls: Arc<AtomicUsize>,
}
impl ChainUart for ReportUart {
    fn write_frame(&mut self, _: &[u8]) -> Result<(), UartTransportError> {
        panic!("receive-only fixture");
    }
    fn read_avail(&mut self, _: &mut [u8]) -> usize {
        panic!("must use checked report");
    }
}
impl CheckedChainUart for ReportUart {
    fn read_avail_checked(&mut self, bytes: &mut [u8]) -> CheckedRead {
        self.calls.fetch_add(1, Ordering::SeqCst);
        bytes[..self.wire.len()].copy_from_slice(&self.wire);
        self.report.clone()
    }
}

#[test]
fn reported_prefix_with_later_error_is_parsed_before_terminal_refusal_and_next_chain_is_untouched()
{
    let calls = Arc::new(AtomicUsize::new(0));
    let mut owner = BbDispatchOwner::new(Am335xUartTransport::new(
        (0..2)
            .map(|_| ReportUart {
                report: CheckedRead {
                    returned_count: Some(11),
                    failure: Some("flags could not be restored after actual read".into()),
                },
                wire: nonce(42),
                calls: calls.clone(),
            })
            .collect(),
        20_000,
    ));
    let mut held = owner.hold_dispatch().unwrap();
    let result = held.receive_once();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.reads.len(), 1);
    assert_eq!(result.reads[0].returned_count, Some(11));
    assert_eq!(
        result.reads[0].returned_prefix.as_ref().unwrap(),
        &nonce(42)
    );
    assert!(result.reads[0].error.as_ref().unwrap().contains("restored"));
    assert_eq!(result.nonces.len(), 1);
    assert_eq!(result.nonces[0].1.raw_frame.as_slice(), nonce(42));
    assert!(
        !result.caller_completed
            && matches!(result.failure, Some(ReceiveError::Read { chain: 0, .. }))
    );
    assert!(held.snapshot().permanently_stopped);
    assert_eq!(held.resume(), Err(DispatchError::Stopped));
    assert_eq!(owner.transport.bm1362_serial_rx_counters()[0].raw_bytes, 11);
}

#[test]
fn missing_both_count_and_error_is_refused_without_parsing_unreported_scratch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut owner = BbDispatchOwner::new(Am335xUartTransport::new(
        vec![ReportUart {
            report: CheckedRead {
                returned_count: None,
                failure: None,
            },
            wire: nonce(42),
            calls: calls.clone(),
        }],
        20_000,
    ));
    let result = owner.receive_once();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(result.reads[0].returned_prefix.is_none());
    assert!(result.reads[0].error.as_ref().unwrap().contains("neither"));
    assert!(result.nonces.is_empty() && result.failure.is_some());
    assert_eq!(owner.transport.bm1362_serial_rx_counters()[0].raw_bytes, 0);
    assert!(owner.snapshot().permanently_stopped);
}
