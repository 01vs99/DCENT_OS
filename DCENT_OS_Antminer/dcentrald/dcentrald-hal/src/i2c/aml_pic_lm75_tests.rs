use super::*;
use std::collections::VecDeque;

fn oracle() -> serde_json::Value {
    serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../../../"))).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn fixture() -> (I2cSafetyPermit, AmlPicLm75Route) {
    let authority = Arc::new(I2cSafetyAuthority::default());
    let route = AmlPicLm75Route {
        authority: Arc::downgrade(&authority),
        generation: 0,
        board: 42601,
        chain: 1,
    };
    (
        I2cSafetyPermit {
            authority,
            generation: 0,
            intent: I2cOperationIntent::UnclassifiedMutation,
            scope: I2cPermitScope::Generic,
        },
        route,
    )
}

struct Script {
    bus: u8,
    authority: Arc<I2cSafetyAuthority>,
    selected: Vec<u8>,
    writes: Vec<u8>,
    replies: VecDeque<u8>,
    delays: Vec<u64>,
    operations: usize,
    fail_at: Option<usize>,
    panic_at: Option<usize>,
    stop_at: Option<usize>,
    started: Option<tokio::sync::oneshot::Sender<()>>,
    release: Option<mpsc::Receiver<()>>,
    cleanup_terminal: Vec<bool>,
}

impl Script {
    fn new(permit: &I2cSafetyPermit) -> Self {
        Self {
            bus: 0,
            authority: permit.authority.clone(),
            selected: vec![],
            writes: vec![],
            replies: VecDeque::from([0x3b, 1, 7, 0x3c, 1, 0x33, 0x80, 0, 0xf7]),
            delays: vec![],
            operations: 0,
            fail_at: None,
            panic_at: None,
            stop_at: None,
            started: None,
            release: None,
            cleanup_terminal: vec![],
        }
    }
    fn operation(&mut self) -> Result<()> {
        self.operations += 1;
        if let Some(started) = self.started.take() {
            let _ = started.send(());
            self.release
                .take()
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
        }
        if self.stop_at == Some(self.operations) {
            self.authority.latch_terminal_safe_off();
        }
        assert_ne!(
            self.panic_at,
            Some(self.operations),
            "injected transport panic"
        );
        if self.fail_at == Some(self.operations) {
            return Err(fault(0x20, "injected transport failure"));
        }
        Ok(())
    }
}

impl Wire for Script {
    fn bus(&self) -> u8 {
        self.bus
    }
    fn select(&mut self, addr: u8) -> Result<()> {
        self.selected.push(addr);
        Ok(())
    }
    fn write_byte(&mut self, byte: u8) -> Result<()> {
        if self.authority.terminal_safe_off.load(Ordering::SeqCst) && byte == 0 {
            self.cleanup_terminal.push(true);
        }
        self.operation()?;
        self.writes.push(byte);
        Ok(())
    }
    fn read_byte(&mut self) -> Result<u8> {
        self.operation()?;
        self.replies
            .pop_front()
            .ok_or_else(|| fault(0x20, "injected short reply"))
    }
    fn delay(&mut self, duration: Duration) {
        self.delays.push(duration.as_millis() as u64);
    }
}

fn run(
    script: &mut Script,
    route: &AmlPicLm75Route,
    sensor: u8,
    permit: &I2cSafetyPermit,
) -> Result<AmlPicLm75Sample> {
    execute_on(
        script,
        route,
        sensor,
        permit,
        Instant::now() + Duration::from_secs(3),
    )
}

#[test]
fn all_classic_routes_use_original_frames_byte_groups_and_signed_decoder() {
    let evidence = oracle();
    for chain in 1..=3 {
        for sensor in 0x48..=0x4b {
            let (permit, mut route) = fixture();
            route.chain = chain;
            route.board = [42601, 42621, 42641][usize::from(chain - 1)];
            let mut wire = Script::new(&permit);
            let sample = run(&mut wire, &route, sensor, &permit).unwrap();
            assert_eq!(sample.raw_be(), [0x33, 0x80]);
            assert_eq!(sample.celsius(), 51.5);
            assert_eq!(wire.selected, vec![chain + 0x1f]);
            let expected: Vec<u8> = evidence["frames"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["sensor"].as_u64() == Some(u64::from(sensor)))
                .flat_map(|row| {
                    let bytes = hex(row["frame"].as_str().unwrap());
                    let messages: Vec<_> = row["messages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|part| hex(part.as_str().unwrap()))
                        .collect();
                    assert!(messages.iter().all(|part| part.len() == 1));
                    assert_eq!(messages.concat(), bytes);
                    bytes
                })
                .collect();
            assert_eq!(wire.writes, expected);
            assert_eq!(wire.operations, 25);
            assert_eq!(wire.delays, [50, 100, 50]);
            assert!(!permit.authority.terminal_safe_off.load(Ordering::SeqCst));
        }
    }
    for row in evidence["temperatures"].as_array().unwrap() {
        let sample = AmlPicLm75Sample {
            raw: hex(row["raw_be"].as_str().unwrap()).try_into().unwrap(),
        };
        assert_eq!(sample.celsius(), row["celsius"].as_f64().unwrap());
    }
}

#[test]
fn wrong_model_route_sensor_owner_and_expired_generation_never_touch_wire() {
    for variant in 0..7 {
        let (permit, mut route) = fixture();
        let mut wire = Script::new(&permit);
        let mut sensor = 0x48;
        match variant {
            0 => route.board = 42603,
            1 => route.board = 42612,
            2 => route.chain = 0,
            3 => wire.bus = 1,
            4 => sensor = 0x50,
            5 => route.authority = Arc::downgrade(&Arc::new(I2cSafetyAuthority::default())),
            6 => {
                permit.authority.latch_terminal_safe_off();
            }
            _ => unreachable!(),
        }
        assert!(run(&mut wire, &route, sensor, &permit).is_err());
        assert!(wire.selected.is_empty());
        assert!(wire.writes.is_empty());
    }
}

#[test]
fn write_ack_requires_both_bytes_before_any_read_command() {
    for row in oracle()["write_acks"].as_array().unwrap() {
        let reply = hex(row["reply"].as_str().unwrap());
        // This worker asks the adapter for exactly two individual bytes; the
        // source parser's synthetic oversized Vec is not an adapter response.
        if reply.len() > 2 {
            continue;
        }
        let (permit, route) = fixture();
        let mut wire = Script::new(&permit);
        wire.replies = reply.into();
        let accepted = row["accepted"].as_bool().unwrap();
        if accepted {
            wire.replies.extend([7, 0x3c, 1, 0x33, 0x80, 0, 0xf7]);
        }
        assert_eq!(run(&mut wire, &route, 0x48, &permit).is_ok(), accepted);
        assert_eq!(&wire.writes[..8], frame(0x3b, 0x48, 0));
        if accepted {
            assert_eq!(&wire.writes[8..], frame(0x3c, 0x48, 2));
            assert!(wire.cleanup_terminal.is_empty());
            continue;
        }
        assert_eq!(&wire.writes[8..], &[0; 16]);
        assert_eq!(wire.cleanup_terminal.len(), 16);
        assert_eq!(wire.delays, [50]);
    }
}

#[test]
fn complete_read_requires_original_length_opcode_checksum_and_success_status() {
    for row in oracle()["responses"].as_array().unwrap() {
        let reply = hex(row["reply"].as_str().unwrap());
        let (permit, route) = fixture();
        let mut wire = Script::new(&permit);
        wire.replies = [vec![0x3b, 1], reply].concat().into();
        let result = run(&mut wire, &route, 0x48, &permit);
        let accepted = row["rejection_branch"].is_null() && row["status"] == 1;
        assert_eq!(result.is_ok(), accepted, "{row}");
        if !accepted {
            assert_eq!(&wire.writes[16..], &[0; 16]);
            assert!(permit.authority.terminal_safe_off.load(Ordering::SeqCst));
        }
    }
}

#[test]
fn every_partial_io_failure_latches_before_parser_cleanup_and_prevents_retries() {
    for fail_at in 1..=25 {
        let (permit, route) = fixture();
        let mut wire = Script::new(&permit);
        wire.fail_at = Some(fail_at);
        assert!(
            run(&mut wire, &route, 0x48, &permit).is_err(),
            "stage {fail_at}"
        );
        assert_eq!(&wire.writes[wire.writes.len() - 16..], &[0; 16]);
        assert_eq!(wire.cleanup_terminal.len(), 16);
        let before = wire.operations;
        assert!(run(&mut wire, &route, 0x49, &permit).is_err());
        assert_eq!(wire.operations, before);
    }
}

#[test]
fn terminal_between_bytes_ack_and_reply_prevents_the_next_normal_byte() {
    for stop_at in [1, 7, 8, 9, 10, 18, 19, 24, 25] {
        let (permit, route) = fixture();
        let mut wire = Script::new(&permit);
        wire.stop_at = Some(stop_at);
        assert!(run(&mut wire, &route, 0x48, &permit).is_err());
        assert_eq!(wire.operations, stop_at + 16);
        assert_eq!(&wire.writes[wire.writes.len() - 16..], &[0; 16]);
    }
}

#[test]
fn deadline_and_unwind_close_the_pair_and_preserve_cleanup_failure() {
    let (permit, route) = fixture();
    let mut wire = Script::new(&permit);
    assert!(execute_on(
        &mut wire,
        &route,
        0x48,
        &permit,
        Instant::now() + Duration::from_millis(10)
    )
    .is_err());
    assert_eq!(wire.writes.len(), 8 + 16);
    assert_eq!(wire.replies.len(), 9);
    let (permit, route) = fixture();
    let mut wire = Script::new(&permit);
    wire.panic_at = Some(4);
    wire.fail_at = Some(5); // First cleanup byte fails after the injected unwind.
    let error = run(&mut wire, &route, 0x48, &permit)
        .unwrap_err()
        .to_string();
    assert!(error.contains("panicked"));
    assert!(error.contains("parser flush failed"));
    assert_eq!(wire.cleanup_terminal.len(), 16);
    assert_eq!(wire.operations, 4 + 16);
    assert_eq!(&wire.writes[3..], &[0; 15]);
    assert!(permit.authority.terminal_safe_off.load(Ordering::SeqCst));
}

#[tokio::test]
async fn aborting_the_actual_async_request_latches_before_its_worker_resumes() {
    let (service, requests) = I2cServiceHandle::for_unit_tests();
    let authority = service.safety.clone();
    let route = AmlPicLm75Route {
        authority: Arc::downgrade(&authority),
        generation: 0,
        board: 42601,
        chain: 1,
    };
    let permit = I2cSafetyPermit {
        authority,
        generation: 0,
        intent: I2cOperationIntent::UnclassifiedMutation,
        scope: I2cPermitScope::Generic,
    };
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let request = requests.recv_timeout(Duration::from_secs(2)).unwrap();
        let I2cRequest::ReadClassicAmlPicLm75 {
            route,
            sensor,
            deadline,
            reply_tx,
            ..
        } = request
        else {
            panic!("wrong request")
        };
        let mut wire = Script::new(&permit);
        wire.started = Some(started_tx);
        wire.release = Some(release_rx);
        let result = execute_on(&mut wire, &route, sensor, &permit, deadline);
        assert!(result.is_err());
        let _ = reply_tx.send(result);
        wire
    });
    let caller_service = service.clone();
    let caller = tokio::spawn(async move {
        caller_service
            .read_classic_aml_pic_lm75_at(&route, 0x48, Instant::now() + Duration::from_secs(3))
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .unwrap()
        .unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(service.terminal_safe_off_is_latched());
    release_tx.send(()).unwrap();
    let wire = worker.join().unwrap();
    assert_eq!(wire.writes, [vec![0x55], vec![0; 16]].concat());
    assert!(wire.delays.is_empty());
}

#[cfg(feature = "sim-hal")]
struct ServiceBackend {
    identity: usize,
    writes: std::sync::Mutex<Vec<(u8, Vec<u8>)>>,
    replies: std::sync::Mutex<VecDeque<u8>>,
}

#[cfg(feature = "sim-hal")]
impl I2cSimBackend for ServiceBackend {
    fn service_identity(&self) -> Option<usize> {
        Some(self.identity)
    }
    fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> Result<usize> {
        assert_eq!(bus, 0);
        assert_eq!(bytes.len(), 1);
        self.writes.lock().unwrap().push((addr, bytes.to_vec()));
        Ok(1)
    }
    fn read(&self, bus: u8, addr: u8, bytes: &mut [u8]) -> Result<usize> {
        assert_eq!((bus, addr, bytes.len()), (0, 0x21, 1));
        match self.replies.lock().unwrap().pop_front() {
            Some(value) => {
                bytes[0] = value;
                Ok(1)
            }
            None => Ok(0),
        }
    }
    fn write_read(&self, _: u8, _: u8, _: &[u8], _: &mut [u8]) -> Result<()> {
        panic!("PIC bridge must preserve separate byte transfers")
    }
}

#[cfg(feature = "sim-hal")]
#[tokio::test]
async fn retained_service_dispatch_uses_real_bus_adapter_and_stops_after_rejected_ack() {
    static NEXT: AtomicUsize = AtomicUsize::new(usize::MAX / 2);
    for accepted in [true, false] {
        let backend = Arc::new(ServiceBackend {
            identity: NEXT.fetch_add(1, Ordering::Relaxed),
            writes: std::sync::Mutex::new(vec![]),
            replies: std::sync::Mutex::new(if accepted {
                VecDeque::from([0x3b, 1, 7, 0x3c, 1, 0x33, 0x80, 0, 0xf7])
            } else {
                VecDeque::from([0x3b, 0])
            }),
        });
        let mut owner =
            spawn_owned_sim_i2c_service(0, backend.clone(), (0x50..=0x57).collect()).unwrap();
        let service = owner.request_handle();
        let route = AmlPicLm75Route {
            authority: Arc::downgrade(&service.safety),
            generation: 0,
            board: 42621,
            chain: 2,
        };
        let result = service
            .read_classic_aml_pic_lm75_at(&route, 0x49, Instant::now() + Duration::from_secs(3))
            .await;
        assert_eq!(result.is_ok(), accepted, "{result:?}");
        if accepted {
            assert_eq!(result.unwrap().celsius(), 51.5);
        }
        assert_eq!(service.terminal_safe_off_is_latched(), !accepted);
        let writes = backend.writes.lock().unwrap();
        assert!(writes.iter().all(|(addr, _)| *addr == 0x21));
        let expected = if accepted {
            [frame(0x3b, 0x49, 0).to_vec(), frame(0x3c, 0x49, 2).to_vec()].concat()
        } else {
            [frame(0x3b, 0x49, 0).to_vec(), vec![0; 16]].concat()
        };
        assert_eq!(
            writes
                .iter()
                .flat_map(|(_, bytes)| bytes.iter().copied())
                .collect::<Vec<_>>(),
            expected
        );
        drop(writes);
        drop(service);
        let close = owner.close_and_join_until(Instant::now() + Duration::from_secs(2));
        assert_eq!(close.is_ok(), accepted);
        if !accepted {
            assert!(close.unwrap_err().to_string().contains("quarantined"));
            drop(owner);
            assert!(
                spawn_owned_sim_i2c_service(0, backend.clone(), (0x50..=0x57).collect()).is_err()
            );
        }
    }
}
