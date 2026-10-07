use super::*;
use crate::platform::sim::{SimControllerKind, SimI2cBackend};
use std::sync::Condvar;

struct Backend {
    identity: SimI2cBackend,
    reply: [u8; 6],
    reads: Mutex<usize>,
    trace: Mutex<Vec<(Instant, u8, Option<u8>)>>,
    fail_read: Option<usize>,
    stall_read: Option<usize>,
    gate: (Mutex<(bool, bool)>, Condvar),
}
impl Backend {
    fn new(reply: [u8; 6]) -> Self {
        Self {
            identity: SimI2cBackend::with_controller(SimControllerKind::Dspic),
            reply,
            reads: Mutex::new(0),
            trace: Mutex::new(Vec::new()),
            fail_read: None,
            stall_read: None,
            gate: (Mutex::new((false, false)), Condvar::new()),
        }
    }
    fn wait_entered(&self) {
        let guard = self.gate.0.lock().unwrap();
        let (guard, timeout) = self
            .gate
            .1
            .wait_timeout_while(guard, Duration::from_secs(3), |state| !state.0)
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
        assert_eq!(bytes, crate::bb_pic_heartbeat::REQUEST);
        *self.reads.lock().unwrap() = 0;
        self.trace
            .lock()
            .unwrap()
            .push((Instant::now(), addr, None));
        Ok(bytes.len())
    }
    fn read(&self, bus: u8, addr: u8, output: &mut [u8]) -> Result<usize> {
        assert_eq!((bus, output.len()), (0, 1));
        let mut index = self.reads.lock().unwrap();
        if self.stall_read == Some(*index) {
            let mut guard = self.gate.0.lock().unwrap();
            guard.0 = true;
            self.gate.1.notify_all();
            let (guard, timeout) = self
                .gate
                .1
                .wait_timeout_while(guard, Duration::from_secs(5), |state| !state.1)
                .unwrap();
            assert!(
                guard.1 && !timeout.timed_out(),
                "test failed to release transfer"
            );
        }
        if self.fail_read == Some(*index) {
            return Err(HalError::I2cEndpointRefused {
                bus,
                addr,
                detail: "authored read failure".into(),
            });
        }
        output[0] = self.reply[*index];
        *index += 1;
        self.trace
            .lock()
            .unwrap()
            .push((Instant::now(), addr, Some(output[0])));
        Ok(1)
    }
    fn write_read(&self, _: u8, _: u8, _: &[u8], _: &mut [u8]) -> Result<()> {
        panic!("heartbeat requires separate source-timed one-byte reads")
    }
}
fn close(owner: &mut I2cServiceOwner) {
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(2))
        .unwrap();
}

#[test]
fn actual_original_worker_visits_physical_slots_and_preserves_all_seven_waits() {
    let backend = Arc::new(Backend::new([6, 0x16, 1, 0, 0, 0x1d]));
    let mut owner =
        spawn_owned_sim_i2c_service(0, backend.clone(), (0x50..=0x57).collect()).unwrap();
    let handle = owner.request_handle();
    for slot in [2, 0, 1] {
        let deadline = Instant::now() + Duration::from_secs(2);
        let result = handle.exchange_bb_pic_keepalive_at(slot, deadline);
        assert!(result.failure.is_none(), "{result:?}");
        assert_eq!(result.native_slot, slot);
        assert_eq!(result.pic_address, Some(0x20 + slot as u8));
        assert_eq!(result.deadline, deadline);
        assert_eq!(
            result.returned_reads,
            Some(backend.reply.iter().map(|b| vec![*b]).collect())
        );
        assert_eq!(result.decoded_reply, Some(backend.reply));
        assert!(result.caller_returned_at.unwrap() >= result.caller_started_at);
        assert!(result.accepted_at.unwrap() < deadline);
        let trace = backend.trace.lock().unwrap();
        let recent = &trace[trace.len() - 7..];
        assert!(recent.iter().all(|row| row.1 == 0x20 + slot as u8));
        for pair in recent.windows(2) {
            assert!(pair[1].0.duration_since(pair[0].0) >= Duration::from_millis(30));
        }
        assert!(
            result
                .caller_returned_at
                .unwrap()
                .duration_since(recent[6].0)
                >= Duration::from_millis(30)
        );
    }
    close(&mut owner);
}

#[test]
fn actual_worker_wrong_opcode_payload_checksum_and_length_keep_complete_raw_reply() {
    for reply in [
        [6, 0x17, 1, 0, 0, 0x1e],
        [6, 0x16, 0, 0, 0, 0x1c],
        [6, 0x16, 1, 0, 0, 0x1c],
        [5, 0x16, 1, 0, 0, 0x1c],
        [0xff; 6],
    ] {
        let backend = Arc::new(Backend::new(reply));
        let mut owner = spawn_owned_sim_i2c_service(0, backend.clone(), Vec::new()).unwrap();
        let result = owner
            .request_handle()
            .exchange_bb_pic_keepalive_at(0, Instant::now() + Duration::from_secs(2));
        assert!(result.failure.is_some() && result.accepted_at.is_none());
        assert!(result.transport_error.is_none() && result.decoded_reply.is_none());
        assert_eq!(
            result.returned_reads,
            Some(reply.iter().map(|b| vec![*b]).collect())
        );
        assert_eq!(backend.trace.lock().unwrap().len(), 7);
        close(&mut owner);
    }
}

#[test]
fn wrong_bus_slot_elapsed_deadline_and_terminal_fence_never_write() {
    for bus in [0, 1] {
        let backend = Arc::new(Backend::new([6, 0x16, 1, 0, 0, 0x1d]));
        let mut owner = spawn_owned_sim_i2c_service(bus, backend.clone(), Vec::new()).unwrap();
        let handle = owner.request_handle();
        for slot in [3, usize::MAX] {
            let result =
                handle.exchange_bb_pic_keepalive_at(slot, Instant::now() + Duration::from_secs(1));
            assert!(result.failure.is_some() && result.returned_reads.is_none());
        }
        if bus == 1 {
            assert!(handle
                .exchange_bb_pic_keepalive_at(0, Instant::now() + Duration::from_secs(1))
                .failure
                .is_some());
        }
        assert!(handle
            .exchange_bb_pic_keepalive_at(0, Instant::now())
            .failure
            .is_some());
        owner.terminal_fence().latch_terminal_safe_off();
        assert!(handle
            .exchange_bb_pic_keepalive_at(0, Instant::now() + Duration::from_secs(1))
            .failure
            .is_some());
        assert!(backend.trace.lock().unwrap().is_empty());
        close(&mut owner);
    }
}

#[test]
fn started_transfer_error_does_not_invent_unavailable_partial_results() {
    let mut backend = Backend::new([6, 0x16, 1, 0, 0, 0x1d]);
    backend.fail_read = Some(1);
    let backend = Arc::new(backend);
    let mut owner = spawn_owned_sim_i2c_service(0, backend.clone(), Vec::new()).unwrap();
    let result = owner
        .request_handle()
        .exchange_bb_pic_keepalive_at(0, Instant::now() + Duration::from_secs(2));
    assert!(result.transport_error.is_some() && result.failure.is_some());
    assert!(result.returned_reads.is_none() && result.accepted_at.is_none());
    assert_eq!(backend.trace.lock().unwrap().len(), 2); // write + actual first read
    close(&mut owner);
}

#[test]
fn original_deadline_during_started_read_preserves_unknown_outcome_until_real_close() {
    let mut backend = Backend::new([6, 0x16, 1, 0, 0, 0x1d]);
    backend.stall_read = Some(1);
    let backend = Arc::new(backend);
    let mut owner = spawn_owned_sim_i2c_service(0, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    let deadline = Instant::now() + Duration::from_millis(250);
    let task = std::thread::spawn(move || handle.exchange_bb_pic_keepalive_at(0, deadline));
    backend.wait_entered();
    let result = task.join().unwrap();
    assert_eq!(result.deadline, deadline);
    assert!(result.failure.is_some() && result.transport_error.is_some());
    assert!(result.returned_reads.is_none() && result.accepted_at.is_none());
    owner.terminal_fence().latch_terminal_safe_off();
    backend.release();
    close(&mut owner);
    assert!(result.accepted_at.is_none()); // eventual worker close cannot promote this result
}

#[test]
fn queued_heartbeat_expires_without_request_when_original_worker_is_occupied() {
    let backend = Arc::new(SimI2cBackend::with_controller(SimControllerKind::Dspic));
    let mut owner = spawn_owned_sim_i2c_service(0, backend.clone(), Vec::new()).unwrap();
    backend.arm_next_transfer_stall().unwrap();
    let first_handle = owner.request_handle();
    let first = std::thread::spawn(move || first_handle.read_bytes(0x20, 1));
    assert!(backend
        .wait_for_transfer_stall(Duration::from_secs(1))
        .unwrap());
    let result = owner
        .request_handle()
        .exchange_bb_pic_keepalive_at(2, Instant::now() + Duration::from_millis(30));
    assert!(result.failure.is_some() && result.returned_reads.is_none());
    backend.release_transfer_stall().unwrap();
    let _ = first.join().unwrap();
    close(&mut owner);
    assert!(!backend.drain_trace().unwrap().iter().any(|row| matches!(row,
        crate::platform::sim::TraceEvent::I2cWrite { bytes, .. } if bytes == &crate::bb_pic_heartbeat::REQUEST
    )));
}
