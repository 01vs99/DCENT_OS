//! Authored actual-owned-service checks; not compiled in the detached draft.
use super::*;
use crate::platform::sim::{SimControllerKind, SimI2cBackend, TraceEvent};

struct Lm75Backend {
    identity: SimI2cBackend,
    reads: Mutex<std::collections::VecDeque<u8>>,
    trace: Mutex<Vec<TraceEvent>>,
    status: std::sync::atomic::AtomicU8,
}

impl Lm75Backend {
    fn new() -> Self {
        Self {
            identity: SimI2cBackend::with_controller(SimControllerKind::Dspic),
            reads: Mutex::new(std::collections::VecDeque::new()),
            trace: Mutex::new(Vec::new()),
            status: std::sync::atomic::AtomicU8::new(0),
        }
    }

    fn drain(&self) -> Vec<TraceEvent> {
        std::mem::take(&mut *self.trace.lock().unwrap())
    }
}

impl I2cSimBackend for Lm75Backend {
    fn service_identity(&self) -> Option<usize> {
        self.identity.service_identity()
    }

    fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> Result<usize> {
        assert_eq!(bus, 0);
        assert!((0x20..=0x22).contains(&addr));
        assert_eq!(bytes.len(), 8);
        // Independently reconstruct the four held request bytes; do not call
        // the product request builder as the backend's expected value.
        assert!((0x48..=0x4b).contains(&bytes[4]));
        assert_eq!(
            bytes,
            [0x55, 0xaa, 6, 0x3c, bytes[4], 2, 0, bytes[4] + 0x44]
        );
        self.trace.lock().unwrap().push(TraceEvent::I2cWrite {
            bus,
            addr,
            bytes: bytes.to_vec(),
        });
        let status = self.status.load(std::sync::atomic::Ordering::SeqCst);
        self.reads
            .lock()
            .unwrap()
            .extend([7, 0x3c, 1, 0x26, 0x30, status, 0x9a]);
        Ok(bytes.len())
    }

    fn read(&self, bus: u8, addr: u8, output: &mut [u8]) -> Result<usize> {
        assert_eq!(bus, 0);
        assert_eq!(output.len(), 1);
        output[0] = self.reads.lock().unwrap().pop_front().unwrap();
        self.trace.lock().unwrap().push(TraceEvent::I2cRead {
            bus,
            addr,
            bytes: output.to_vec(),
        });
        Ok(1)
    }

    fn write_read(&self, _: u8, _: u8, _: &[u8], _: &mut [u8]) -> Result<()> {
        panic!("LM75 bridge requires separate one-byte reads")
    }
}

#[test]
fn all_native_slots_and_sensors_use_fixed_frames_and_retain_failed_status_bytes() {
    let backend = Arc::new(Lm75Backend::new());
    let mut owner = spawn_owned_sim_i2c_service(0, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    for chain in 0..3 {
        for sensor in 0x48..=0x4b {
            let result = handle
                .read_bb_pic_lm75_at(chain, sensor, Instant::now() + Duration::from_secs(3))
                .unwrap();
            assert_eq!(result, [7, 0x3c, 1, 0x26, 0x30, 0, 0x9a].map(|b| vec![b]));
            assert_eq!(
                crate::bb_pic_lm75::complete_reply(&result)
                    .unwrap()
                    .temperature_c(),
                38.1875
            );
            let trace = backend.drain();
            assert_eq!(trace.len(), 8);
            assert!(matches!(&trace[0], TraceEvent::I2cWrite { addr, bytes, .. }
                if *addr == 0x20 + chain as u8 && bytes[4] == sensor));
            assert!(trace[1..].iter().all(
                |event| matches!(event, TraceEvent::I2cRead { addr, bytes, .. }
                    if *addr == 0x20 + chain as u8 && bytes.len() == 1)
            ));
        }
    }
    backend.status.store(1, std::sync::atomic::Ordering::SeqCst);
    let result = handle
        .read_bb_pic_lm75_at(0, 0x48, Instant::now() + Duration::from_secs(3))
        .unwrap();
    assert_eq!(result, [7, 0x3c, 1, 0x26, 0x30, 1, 0x9a].map(|b| vec![b]));
    assert!(matches!(
        crate::bb_pic_lm75::complete_reply(&result),
        Err(crate::bb_pic_lm75::ReplyError::Status { actual: 1 })
    ));
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
}

#[test]
fn invalid_identity_expired_deadline_and_terminal_fence_refuse_before_wire() {
    let backend = Arc::new(Lm75Backend::new());
    let mut owner = spawn_owned_sim_i2c_service(0, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    let deadline = Instant::now() + Duration::from_secs(3);
    for chain in [3, usize::MAX] {
        assert!(handle.read_bb_pic_lm75_at(chain, 0x48, deadline).is_err());
    }
    for sensor in 0..=u8::MAX {
        if !(0x48..=0x4b).contains(&sensor) {
            assert!(handle.read_bb_pic_lm75_at(0, sensor, deadline).is_err());
        }
    }
    assert!(handle.read_bb_pic_lm75_at(0, 0x48, Instant::now()).is_err());
    assert!(backend.drain().is_empty());
    owner.terminal_fence().latch_terminal_safe_off();
    assert!(matches!(
        handle.read_bb_pic_lm75_at(0, 0x48, deadline),
        Err(HalError::I2cSafetySuperseded { .. })
    ));
    assert!(backend.drain().is_empty());
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
    let mut wrong_bus = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
    assert!(wrong_bus
        .request_handle()
        .read_bb_pic_lm75_at(0, 0x48, deadline)
        .is_err());
    assert!(backend.drain().is_empty());
    wrong_bus
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
}

#[test]
fn queued_fixed_query_expires_behind_actual_blocked_transfer_without_later_request() {
    let backend = Arc::new(SimI2cBackend::with_controller(SimControllerKind::Dspic));
    let mut owner = spawn_owned_sim_i2c_service(0, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    backend.arm_next_transfer_stall().unwrap();
    let first_handle = handle.clone();
    let first = std::thread::spawn(move || first_handle.read_bytes(0x20, 1));
    assert!(backend
        .wait_for_transfer_stall(Duration::from_secs(1))
        .unwrap());
    let result = handle.read_bb_pic_lm75_at(1, 0x48, Instant::now() + Duration::from_millis(100));
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("will not touch the bus"));
    backend.release_transfer_stall().unwrap();
    first.join().unwrap().unwrap();
    handle.read_bytes(0x22, 1).unwrap();
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
    let trace = backend.drain_trace().unwrap();
    assert!(!trace
        .iter()
        .any(|event| matches!(event, TraceEvent::I2cWrite { .. })));
    let reads: Vec<_> = trace
        .iter()
        .filter_map(|event| {
            if let TraceEvent::I2cRead { addr, .. } = event {
                Some(*addr)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(reads, [0x20, 0x22]);
}

#[test]
fn started_fixed_query_timeout_retains_service_until_actual_transfer_exit() {
    let backend = Arc::new(SimI2cBackend::with_controller(SimControllerKind::Dspic));
    let mut owner = spawn_owned_sim_i2c_service(0, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    backend.arm_next_transfer_stall().unwrap();
    let caller = std::thread::spawn(move || {
        handle.read_bb_pic_lm75_at(0, 0x48, Instant::now() + Duration::from_millis(100))
    });
    assert!(backend
        .wait_for_transfer_stall(Duration::from_secs(1))
        .unwrap());
    let result = caller.join().unwrap();
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("outcome is unknown"));
    assert!(owner
        .close_and_join_until(Instant::now() + Duration::from_millis(10))
        .is_err());
    backend.release_transfer_stall().unwrap();
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
    let trace = backend.drain_trace().unwrap();
    assert!(trace
        .iter()
        .any(|event| matches!(event, TraceEvent::I2cWrite { bytes, .. }
        if bytes == &[0x55, 0xaa, 6, 0x3c, 0x48, 2, 0, 0x8c])));
}
