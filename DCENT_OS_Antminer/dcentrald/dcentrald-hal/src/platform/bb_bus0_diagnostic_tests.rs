//! Authored actual owned-service composition tests, not yet compiled.
use super::*;
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use crate::platform::sim::{SimControllerKind, SimI2cBackend};
use crate::HalError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Condvar;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    FactoryCrc,
    Firmware,
    Status,
    Short,
    Read,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Page(u8, usize),
    Write(u8, Vec<u8>),
    Read(u8, Option<u8>, usize),
}

struct Reply {
    address: u8,
    sensor: Option<u8>,
    bytes: Vec<u8>,
    position: usize,
}

struct Backend {
    identity: SimI2cBackend,
    page: Vec<u8>,
    fault: Fault,
    block: Option<(u8, usize)>,
    reply: Mutex<Option<Reply>>,
    events: Mutex<Vec<Event>>,
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}

fn fixture(name: &str) -> Vec<u8> {
    let value: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentrald-api-types/src/bb_factory_profile_vectors.json"
    )))
    .unwrap();
    let text = value["fixtures"][name]["raw"].as_str().unwrap();
    assert_eq!(text.len(), 512);
    (0..256)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap())
        .collect()
}

impl Backend {
    fn new(fault: Fault, block: Option<(u8, usize)>) -> Arc<Self> {
        let page = fixture(if fault == Fault::FactoryCrc {
            "identity_crc_mismatch"
        } else {
            "held_42601"
        });
        Arc::new(Self {
            identity: SimI2cBackend::with_controller(SimControllerKind::Dspic),
            page,
            fault,
            block,
            reply: Mutex::new(None),
            events: Mutex::new(Vec::new()),
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
        tokio::time::timeout(Duration::from_secs(3), async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }

    fn trace(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    fn wait(&self, sensor: Option<u8>, position: usize, addr: u8) -> crate::Result<()> {
        if sensor.zip(Some(position)) != self.block || self.block.is_none() {
            return Ok(());
        }
        self.entered.store(true, Ordering::SeqCst);
        let released = self.released.lock().unwrap();
        let (_released, result) = self
            .condition
            .wait_timeout_while(released, Duration::from_secs(6), |released| !*released)
            .unwrap();
        if result.timed_out() {
            return Err(HalError::I2cEndpointNotReady {
                bus: 0,
                addr,
                detail: "bounded diagnostic fixture read block elapsed".into(),
            });
        }
        Ok(())
    }
}

impl I2cSimBackend for Backend {
    fn service_identity(&self) -> Option<usize> {
        self.identity.service_identity()
    }

    fn write(&self, bus: u8, addr: u8, data: &[u8]) -> crate::Result<usize> {
        assert_eq!(bus, 0);
        assert!((0x20..=0x22).contains(&addr));
        let (sensor, bytes) = if data == [0x55, 0xaa, 4, 0x17, 0, 0x1b] {
            let firmware: u8 = if self.fault == Fault::Firmware {
                0x86
            } else {
                0x89
            };
            (
                None,
                vec![5, 0x17, firmware, 0, 0x1cu8.wrapping_add(firmware)],
            )
        } else {
            assert_eq!(data.len(), 8);
            assert!((0x48..=0x4b).contains(&data[4]));
            assert_eq!(data, [0x55, 0xaa, 6, 0x3c, data[4], 2, 0, data[4] + 0x44]);
            // Descriptor99 is intentional: replies contain no admitted sensor
            // echo. The future owner must retain the requested label separately.
            let status = u8::from(self.fault == Fault::Status && data[4] == 0x49);
            let mut reply = vec![7u8, 0x3c, 0x99, 0x26, 0x30, status];
            reply.push(reply.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
            (Some(data[4]), reply)
        };
        self.events
            .lock()
            .unwrap()
            .push(Event::Write(addr, data.to_vec()));
        *self.reply.lock().unwrap() = Some(Reply {
            address: addr,
            sensor,
            bytes,
            position: 0,
        });
        Ok(data.len())
    }

    fn read(&self, bus: u8, addr: u8, output: &mut [u8]) -> crate::Result<usize> {
        assert_eq!(bus, 0);
        assert_eq!(output.len(), 1);
        let (sensor, position, byte) = {
            let mut locked = self.reply.lock().unwrap();
            let reply = locked.as_mut().unwrap();
            assert_eq!(reply.address, addr);
            let result = (reply.sensor, reply.position, reply.bytes[reply.position]);
            reply.position += 1;
            result
        };
        self.events
            .lock()
            .unwrap()
            .push(Event::Read(addr, sensor, position));
        self.wait(sensor, position, addr)?;
        if sensor == Some(0x49) && position == 3 {
            if self.fault == Fault::Read {
                return Err(HalError::I2cEndpointNotReady {
                    bus,
                    addr,
                    detail: "injected unavailable LM75 read".into(),
                });
            }
            if self.fault == Fault::Short {
                return Ok(0);
            }
        }
        output[0] = byte;
        Ok(1)
    }

    fn write_read(&self, bus: u8, addr: u8, input: &[u8], output: &mut [u8]) -> crate::Result<()> {
        assert_eq!(bus, 0);
        assert!((0x50..=0x52).contains(&addr));
        assert_eq!(input, [0]);
        assert_eq!(output.len(), 256);
        self.events
            .lock()
            .unwrap()
            .push(Event::Page(addr, output.len()));
        output.copy_from_slice(&self.page);
        Ok(())
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn owner(backend: Arc<Backend>) -> I2cServiceOwner {
    spawn_owned_sim_i2c_service(0, backend, (0x50..=0x57).collect()).unwrap()
}

async fn close(mut diagnostic: BbBus0Diagnostic) -> BbBus0Diagnostic {
    tokio::task::spawn_blocking(move || {
        diagnostic.close_service_until(deadline()).unwrap();
        assert!(diagnostic.close_receipt().is_some());
        diagnostic
    })
    .await
    .unwrap()
}

fn bridge_writes(trace: &[Event]) -> Vec<(u8, u8)> {
    trace
        .iter()
        .filter_map(|event| match event {
            Event::Write(addr, bytes) if bytes.len() == 8 => Some((*addr, bytes[4])),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn every_selected_factory_and_fw_reply_precedes_twelve_ordered_bridge_diagnostics() {
    let backend = Backend::new(Fault::None, None);
    let mut diagnostic = BbBus0Diagnostic::new(owner(backend.clone()));
    diagnostic.start(&[0x52, 0x50, 0x51], deadline()).unwrap();
    assert!(diagnostic.join_until(deadline()).await);
    let saved = diagnostic.snapshot();
    assert!(saved.failure.is_none(), "{saved:?}");
    assert!(saved.bridge_task_joined_at.is_some());
    let data = saved.data.unwrap();
    assert_eq!(data.selected_inventory.pics.len(), 3);
    assert_eq!(data.bridges.len(), 12);
    for (attempt, (slot, sensor)) in data.bridges.iter().zip(
        [2, 0, 1]
            .into_iter()
            .flat_map(|slot| (0x48..=0x4b).map(move |sensor| (slot, sensor))),
    ) {
        assert_eq!(
            (attempt.native_slot, attempt.sensor_address),
            (slot, sensor)
        );
        assert_eq!(attempt.factory_address, 0x50 + slot as u8);
        assert_eq!(attempt.pic_address, 0x20 + slot as u8);
        assert_eq!(attempt.decoded.unwrap().temperature_c(), 38.1875);
        assert_eq!(attempt.returned_reads.as_ref().unwrap().len(), 7);
        assert!(attempt
            .returned_reads
            .as_ref()
            .unwrap()
            .iter()
            .all(|row| row.len() == 1));
    }
    let trace = backend.trace();
    assert_eq!(
        &trace[..3],
        &[
            Event::Page(0x52, 256),
            Event::Page(0x50, 256),
            Event::Page(0x51, 256)
        ]
    );
    let first_bridge = trace
        .iter()
        .position(|event| matches!(event, Event::Write(_, bytes) if bytes.len()==8))
        .unwrap();
    assert_eq!(
        trace[..first_bridge]
            .iter()
            .filter(|event| matches!(event, Event::Write(_, bytes) if bytes.len()==6))
            .count(),
        3
    );
    assert_eq!(bridge_writes(&trace).len(), 12);
    assert!(spawn_owned_sim_i2c_service(0, backend.clone(), vec![]).is_err());
    let _diagnostic = close(diagnostic).await;
    let mut replacement = owner(backend);
    replacement.close_and_join_until(deadline()).unwrap();
}

#[tokio::test]
async fn invalid_factory_or_firmware_keeps_all_bridge_queries_absent() {
    for fault in [Fault::FactoryCrc, Fault::Firmware] {
        let backend = Backend::new(fault, None);
        let mut diagnostic = BbBus0Diagnostic::new(owner(backend.clone()));
        diagnostic.start(&[0x50], deadline()).unwrap();
        assert!(diagnostic.join_until(deadline()).await);
        let saved = diagnostic.snapshot();
        assert!(saved.data.is_none() && saved.failure.is_some());
        assert!(saved.bridges.is_empty());
        assert!(bridge_writes(&backend.trace()).is_empty());
        let _diagnostic = close(diagnostic).await;
    }
}

#[tokio::test]
async fn rejected_available_status_and_short_reads_remain_distinct_from_unavailable_error_bytes() {
    for fault in [Fault::Status, Fault::Short, Fault::Read] {
        let backend = Backend::new(fault, None);
        let mut diagnostic = BbBus0Diagnostic::new(owner(backend.clone()));
        diagnostic.start(&[0x50], deadline()).unwrap();
        assert!(diagnostic.join_until(deadline()).await);
        let saved = diagnostic.snapshot();
        assert!(saved.data.is_none() && saved.failure.is_some());
        assert_eq!(saved.bridges.len(), 2);
        assert!(saved.bridges[0].decoded.is_some());
        let refused = &saved.bridges[1];
        assert!(refused.decoded.is_none() && refused.error.is_some());
        match fault {
            Fault::Status => assert_eq!(refused.returned_reads.as_ref().unwrap()[5], [1]),
            Fault::Short => assert!(refused.returned_reads.as_ref().unwrap()[3].is_empty()),
            Fault::Read => assert!(refused.returned_reads.is_none()),
            _ => unreachable!(),
        }
        assert_eq!(
            bridge_writes(&backend.trace()),
            [(0x20, 0x48), (0x20, 0x49)]
        );
        let _diagnostic = close(diagnostic).await;
    }
}

#[tokio::test]
async fn dropped_pending_bridge_join_retains_actual_task_then_permanently_refuses_promotion() {
    let backend = Backend::new(Fault::None, Some((0x48, 0)));
    let mut diagnostic = BbBus0Diagnostic::new(owner(backend.clone()));
    diagnostic.start(&[0x50], deadline()).unwrap();
    let mut join = Box::pin(diagnostic.join_until(deadline()));
    tokio::select! {
        _ = backend.wait_entered() => {},
        _ = &mut join => panic!("blocked service caller cannot already join"),
    }
    drop(join);
    assert!(diagnostic.snapshot().data.is_none());
    assert!(diagnostic.snapshot().stopped_at.is_some());
    assert!(diagnostic.close_service_until(deadline()).is_err());
    assert!(diagnostic.close_receipt().is_none());
    backend.release();
    assert!(diagnostic.join_until(deadline()).await);
    let saved = diagnostic.snapshot();
    assert!(saved.bridge_task_joined_at.is_some() && saved.data.is_none());
    assert_eq!(saved.bridges.len(), 1);
    assert!(saved.bridges[0].decoded.is_some());
    assert_eq!(bridge_writes(&backend.trace()), [(0x20, 0x48)]);
    let _diagnostic = close(diagnostic).await;
}

#[tokio::test]
async fn terminal_during_first_bridge_reply_keeps_selected_and_lm75_lifecycles_separate() {
    let backend = Backend::new(Fault::None, Some((0x48, 0)));
    let retained = owner(backend.clone());
    let handle = retained.request_handle();
    let mut diagnostic = BbBus0Diagnostic::new(retained);
    diagnostic.start(&[0x50], deadline()).unwrap();
    let (joined, ()) = tokio::join!(diagnostic.join_until(deadline()), async {
        backend.wait_entered().await;
        let _ = handle.latch_terminal_safe_off();
        backend.release();
    });
    assert!(joined);
    let saved = diagnostic.snapshot();
    assert!(saved.inventory.query_task_joined_at.is_some());
    assert!(saved.bridge_task_joined_at.is_some());
    assert!(saved.data.is_none() && saved.failure.is_some());
    assert_eq!(saved.bridges.len(), 1);
    assert_eq!(bridge_writes(&backend.trace()), [(0x20, 0x48)]);
    assert!(diagnostic.close_receipt().is_none());
    let _diagnostic = close(diagnostic).await;
}

#[tokio::test]
async fn completed_bridge_candidate_observed_after_original_deadline_never_becomes_data() {
    let backend = Backend::new(Fault::None, Some((0x4b, 6)));
    let mut diagnostic = BbBus0Diagnostic::new(owner(backend.clone()));
    let original = Instant::now() + Duration::from_secs(2);
    diagnostic.start(&[0x50], original).unwrap();
    let shared = Arc::clone(&diagnostic.state);
    let mut join = Box::pin(diagnostic.join_until(deadline()));
    tokio::select! {
        _ = backend.wait_entered() => {},
        _ = &mut join => panic!("last actual read still blocked"),
    }
    backend.release();
    // Do not poll the pending join while the actual caller completes its raw
    // candidate. This preserves an actual completed-before-deadline candidate.
    tokio::time::timeout(Duration::from_secs(1), async {
        while state_lock(&shared).candidate.is_none() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(Instant::now() < original);
    assert!(state_lock(&shared).bridge_task_joined_at.is_none());
    tokio::time::sleep_until((original + Duration::from_millis(10)).into()).await;
    assert!(join.await);
    let saved = diagnostic.snapshot();
    assert!(saved.bridge_task_joined_at.is_some());
    assert!(saved.data.is_none() && saved.stopped_at.is_some());
    assert_eq!(saved.bridges.len(), 4);
    assert!(saved.bridges.iter().all(|row| row.decoded.is_some()));
    let _diagnostic = close(diagnostic).await;
}

#[tokio::test]
async fn failed_selected_admission_is_one_shot_and_closes_the_same_actual_service() {
    let backend = Backend::new(Fault::None, None);
    let mut diagnostic = BbBus0Diagnostic::new(owner(backend.clone()));
    assert!(diagnostic.start(&[0x53], deadline()).is_err());
    assert!(diagnostic.start(&[0x50], deadline()).is_err());
    assert!(diagnostic.join_until(deadline()).await);
    assert!(diagnostic.snapshot().data.is_none());
    assert!(backend.trace().is_empty());
    let _diagnostic = close(diagnostic).await;
}
