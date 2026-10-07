//! Actual owned-service controls for a deadline retained across caller pauses.
use super::*;
use crate::platform::sim::{SimControllerKind, SimI2cBackend, TraceEvent};

fn read_request(addr: u8) -> (I2cRequest, mpsc::Receiver<Result<Vec<u8>>>) {
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    (
        I2cRequest::ReadBytes {
            addr,
            len: 1,
            reply_tx,
        },
        reply_rx,
    )
}

fn submit_until(handle: &I2cServiceHandle, addr: u8, deadline: Instant) -> Result<Vec<u8>> {
    let (request, reply_rx) = read_request(addr);
    let budget = I2cRequestBudget::for_request_until(&request, deadline).unwrap();
    handle.submit_with_intent_budget(
        addr,
        I2cOperationIntent::ReadOnly,
        request,
        reply_rx,
        budget,
    )
}

fn pause_past(deadline: Instant) {
    std::thread::sleep(
        deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
    );
    assert!(Instant::now() >= deadline);
}

#[test]
fn delayed_before_submission_cannot_rebase_short_or_default_sized_deadline() {
    for long_window in [false, true] {
        let backend = Arc::new(SimI2cBackend::with_controller(SimControllerKind::Dspic));
        let mut owner = spawn_owned_sim_i2c_service(33, backend.clone(), Vec::new()).unwrap();
        let handle = owner.request_handle();
        // Complete one real operation so asynchronous worker startup (which
        // records its default timeout) precedes this isolated request trace.
        assert_eq!(handle.read_bytes(0x20, 1).unwrap().len(), 1);
        let startup = backend.drain_trace().unwrap();
        assert!(startup
            .iter()
            .any(|event| matches!(event, TraceEvent::I2cTimeoutChanged { .. })));
        let (request, reply_rx) = read_request(0x20);
        let default = I2cRequestBudget::for_request(&request).unwrap();
        let window = if long_window {
            default.start + default.execution + Duration::from_millis(50)
        } else {
            Duration::from_millis(100)
        };
        let deadline = Instant::now() + window;
        let budget = I2cRequestBudget::for_request_until(&request, deadline).unwrap();
        assert_eq!(budget.absolute_limit, Some(deadline));
        if long_window {
            assert_eq!(budget.execution, default.execution);
        }
        backend.drain_trace().unwrap();
        // Real elapsed time between budget construction and the actual owned
        // service submission, including the branch returning default durations.
        pause_past(deadline);
        let error = handle
            .submit_with_intent_budget(
                0x20,
                I2cOperationIntent::ReadOnly,
                request,
                reply_rx,
                budget,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("not admitted"), "{error}");
        let expired_trace = backend.drain_trace().unwrap();
        assert!(expired_trace.is_empty(), "{expired_trace:?}");
        // The same actual service can still execute a fresh request.
        assert_eq!(handle.read_bytes(0x20, 1).unwrap().len(), 1);
        owner
            .close_and_join_until(Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            backend
                .drain_trace()
                .unwrap()
                .iter()
                .filter(|event| matches!(event, TraceEvent::I2cRead { .. }))
                .count(),
            1
        );
    }
}

#[test]
fn queued_deadline_refuses_later_wire_access_after_blocked_worker_releases() {
    let backend = Arc::new(SimI2cBackend::with_controller(SimControllerKind::Dspic));
    let mut owner = spawn_owned_sim_i2c_service(34, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    backend.arm_next_transfer_stall().unwrap();
    let first_handle = handle.clone();
    let first = std::thread::spawn(move || first_handle.read_bytes(0x20, 1));
    assert!(backend
        .wait_for_transfer_stall(Duration::from_secs(1))
        .unwrap());
    let result = submit_until(&handle, 0x21, Instant::now() + Duration::from_millis(100));
    let error = result.unwrap_err().to_string();
    assert!(error.contains("will not touch the bus"), "{error}");
    backend.release_transfer_stall().unwrap();
    first.join().unwrap().unwrap();
    // A later successful operation means the real worker has passed the
    // expired queue entry before we inspect its transfer trace.
    handle.read_bytes(0x22, 1).unwrap();
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
    let reads: Vec<_> = backend
        .drain_trace()
        .unwrap()
        .into_iter()
        .filter_map(|event| {
            if let TraceEvent::I2cRead { addr, .. } = event {
                Some(addr)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(reads, [0x20, 0x22]);
}

#[test]
fn full_owned_queue_refuses_admission_without_transfer() {
    let backend = Arc::new(SimI2cBackend::with_controller(SimControllerKind::Dspic));
    let mut owner = spawn_owned_sim_i2c_service(35, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    backend.arm_next_transfer_stall().unwrap();
    let first_handle = handle.clone();
    let first = std::thread::spawn(move || first_handle.read_bytes(0x20, 1));
    assert!(backend
        .wait_for_transfer_stall(Duration::from_secs(1))
        .unwrap());
    let I2cServiceSender::Deadline(tx) = &handle.tx else {
        panic!("owned service required")
    };
    let mut receivers = Vec::new();
    for _ in 0..64 {
        let (request, receiver) = read_request(0x21);
        receivers.push(receiver);
        tx.try_send(I2cServiceEnvelope {
            must_start_by: Instant::now(),
            state: Arc::new(AtomicU8::new(I2C_REQUEST_QUEUED)),
            permit: I2cSafetyPermit {
                authority: Arc::clone(&handle.safety),
                intent: I2cOperationIntent::ReadOnly,
                generation: handle.safety.capture(I2cOperationIntent::ReadOnly).unwrap(),
                scope: I2cPermitScope::Generic,
            },
            request,
        })
        .unwrap();
    }
    let error = submit_until(&handle, 0x22, Instant::now() + Duration::from_millis(100))
        .unwrap_err()
        .to_string();
    assert!(error.contains("not admitted"), "{error}");
    backend.release_transfer_stall().unwrap();
    first.join().unwrap().unwrap();
    for receiver in receivers {
        assert!(receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .is_err());
    }
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
    let reads: Vec<_> = backend
        .drain_trace()
        .unwrap()
        .into_iter()
        .filter_map(|event| {
            if let TraceEvent::I2cRead { addr, .. } = event {
                Some(addr)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(reads, [0x20]);
}

#[test]
fn started_transfer_timeout_is_unknown_and_does_not_join_worker() {
    let backend = Arc::new(SimI2cBackend::with_controller(SimControllerKind::Dspic));
    let mut owner = spawn_owned_sim_i2c_service(36, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    backend.arm_next_transfer_stall().unwrap();
    let caller = std::thread::spawn(move || {
        submit_until(&handle, 0x20, Instant::now() + Duration::from_millis(300))
    });
    assert!(backend
        .wait_for_transfer_stall(Duration::from_secs(1))
        .unwrap());
    let error = caller.join().unwrap().unwrap_err().to_string();
    assert!(error.contains("outcome is unknown"), "{error}");
    assert!(owner
        .close_and_join_until(Instant::now() + Duration::from_millis(10))
        .is_err());
    backend.release_transfer_stall().unwrap();
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        backend
            .drain_trace()
            .unwrap()
            .iter()
            .filter(|event| matches!(event, TraceEvent::I2cRead { .. }))
            .count(),
        1
    );
}

struct ApplicationBackend {
    identity: SimI2cBackend,
    reads: Mutex<std::collections::VecDeque<u8>>,
    trace: Mutex<Vec<TraceEvent>>,
}

impl ApplicationBackend {
    fn drain_trace(&self) -> Result<Vec<TraceEvent>> {
        Ok(std::mem::take(&mut *self.trace.lock().unwrap()))
    }
}

impl I2cSimBackend for ApplicationBackend {
    fn service_identity(&self) -> Option<usize> {
        self.identity.service_identity()
    }

    fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> Result<usize> {
        assert_eq!(bus, 0);
        assert_eq!(addr, 0x22);
        assert_eq!(bytes, crate::bb_pic_application::REQUEST);
        self.trace.lock().unwrap().push(TraceEvent::I2cWrite {
            bus,
            addr,
            bytes: bytes.to_vec(),
        });
        self.reads
            .lock()
            .unwrap()
            .extend([0x05, 0x17, 0x89, 0x00, 0xa5]);
        Ok(bytes.len())
    }

    fn read(&self, bus: u8, addr: u8, output: &mut [u8]) -> Result<usize> {
        assert_eq!(bus, 0);
        assert_eq!(addr, 0x22);
        assert_eq!(output.len(), 1);
        output[0] = self
            .reads
            .lock()
            .unwrap()
            .pop_front()
            .expect("one framed byte per real service read");
        self.trace.lock().unwrap().push(TraceEvent::I2cRead {
            bus,
            addr,
            bytes: output.to_vec(),
        });
        Ok(1)
    }

    fn write_read(&self, _: u8, _: u8, _: &[u8], _: &mut [u8]) -> Result<()> {
        panic!("the native BB query uses separate one-byte reads")
    }
}

#[test]
fn fixed_bb_query_uses_native_slots_and_remains_on_fenced_normal_lane() {
    let backend = Arc::new(ApplicationBackend {
        identity: SimI2cBackend::with_controller(SimControllerKind::Dspic),
        reads: Mutex::new(std::collections::VecDeque::new()),
        trace: Mutex::new(Vec::new()),
    });
    let mut owner = spawn_owned_sim_i2c_service(0, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    let deadline = Instant::now() + Duration::from_secs(3);
    assert!(handle.read_bb_pic_application_at(3, deadline).is_err());
    assert!(backend.drain_trace().unwrap().is_empty());
    let reads = handle.read_bb_pic_application_at(2, deadline).unwrap();
    assert_eq!(
        crate::bb_pic_application::complete_reply(&reads).unwrap(),
        [0x05, 0x17, 0x89, 0x00, 0xa5]
    );
    let trace = backend.drain_trace().unwrap();
    let writes: Vec<_> = trace
        .iter()
        .filter_map(|event| {
            if let TraceEvent::I2cWrite { addr, bytes, .. } = event {
                Some((*addr, bytes.clone()))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        writes,
        [(0x22, crate::bb_pic_application::REQUEST.to_vec())]
    );
    assert_eq!(
        trace
            .iter()
            .filter(|event| matches!(event, TraceEvent::I2cRead { .. }))
            .count(),
        5
    );
    owner.terminal_fence().latch_terminal_safe_off();
    assert!(matches!(
        handle.read_bb_pic_application_at(0, deadline),
        Err(HalError::I2cSafetySuperseded { .. })
    ));
    assert!(backend.drain_trace().unwrap().is_empty());
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
    let mut wrong_bus = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
    assert!(wrong_bus
        .request_handle()
        .read_bb_pic_application_at(0, deadline)
        .is_err());
    assert!(backend.drain_trace().unwrap().is_empty());
    wrong_bus
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
}
