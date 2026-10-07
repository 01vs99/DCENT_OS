//! Detached actual-owned-service lifetime groups; not yet compiled.
use super::*;
use crate::bb_apw_diagnostics::{Field, Query};
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use crate::platform::sim::{SimControllerKind, SimI2cBackend};
use crate::HalError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Condvar;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Write,
    Read,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Write(u8, Vec<u8>),
    Read(u8, Vec<u8>),
}

struct Backend {
    identity: SimI2cBackend,
    dac: u16,
    bad_calibration: bool,
    block: Option<(u8, Phase)>,
    reply: Mutex<Option<(u8, Vec<u8>)>>,
    events: Mutex<Vec<Event>>,
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}

impl Backend {
    fn new(dac: u16, bad_calibration: bool, block: Option<(u8, Phase)>) -> Arc<Self> {
        Arc::new(Self {
            identity: SimI2cBackend::with_controller(SimControllerKind::Dspic),
            dac,
            bad_calibration,
            block,
            reply: Mutex::new(None),
            events: Mutex::new(Vec::new()),
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            condition: Condvar::new(),
        })
    }

    fn trace(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    fn opcodes(&self) -> Vec<u8> {
        self.trace()
            .into_iter()
            .filter_map(|event| match event {
                Event::Write(opcode, _) => Some(opcode),
                Event::Read(_, _) => None,
            })
            .collect()
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }

    async fn wait_entered(&self) {
        tokio::time::timeout(Duration::from_secs(4), async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }

    fn wait(&self, opcode: u8, phase: Phase) -> crate::Result<()> {
        if self.block != Some((opcode, phase)) {
            return Ok(());
        }
        self.entered.store(true, Ordering::SeqCst);
        let guard = self.released.lock().unwrap();
        let (_released, result) = self
            .condition
            .wait_timeout_while(guard, Duration::from_secs(8), |released| !*released)
            .unwrap();
        if result.timed_out() {
            return Err(HalError::I2cEndpointNotReady {
                bus: 1,
                addr: 0x10,
                detail: "bounded APW fixture gate elapsed".into(),
            });
        }
        Ok(())
    }
}

impl I2cSimBackend for Backend {
    fn service_identity(&self) -> Option<usize> {
        self.identity.service_identity()
    }

    fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> crate::Result<usize> {
        assert_eq!((bus, addr), (1, 0x10));
        assert!(bytes.len() >= 7);
        let opcode = bytes[4];
        let (request, data, size) = match opcode {
            2 => (vec![0x11, 0x55, 0xaa, 4, 2, 6, 0], vec![0x76, 0], 8),
            1 => (vec![0x11, 0x55, 0xaa, 4, 1, 5, 0], vec![0x17, 0], 8),
            6 => {
                let mut data = vec![0x40];
                data.extend([0xff; 32]);
                (vec![0x11, 0x55, 0xaa, 6, 6, 0x40, 0x20, 0x6c, 0], data, 40)
            }
            3 => (
                vec![0x11, 0x55, 0xaa, 4, 3, 7, 0],
                self.dac.to_le_bytes().to_vec(),
                10,
            ),
            _ => panic!("unexpected control opcode {opcode:x}"),
        };
        assert_eq!(bytes, request);
        self.events
            .lock()
            .unwrap()
            .push(Event::Write(opcode, bytes.to_vec()));
        self.wait(opcode, Phase::Write)?;
        let len = data.len() as u8 + 4;
        let checksum = data.iter().map(|byte| u16::from(*byte)).sum::<u16>()
            + u16::from(len)
            + u16::from(opcode);
        let mut reply = vec![0x55, 0xaa, len, opcode];
        reply.extend(data);
        reply.extend(checksum.to_le_bytes());
        reply.resize(size, 0xf5);
        if opcode == 6 && self.bad_calibration {
            reply[38] ^= 1;
        }
        *self.reply.lock().unwrap() = Some((opcode, reply));
        Ok(bytes.len())
    }

    fn read(&self, bus: u8, addr: u8, bytes: &mut [u8]) -> crate::Result<usize> {
        assert_eq!((bus, addr), (1, 0x10));
        let (opcode, reply) = self
            .reply
            .lock()
            .unwrap()
            .take()
            .expect("actual prior query");
        assert_eq!(bytes.len(), reply.len());
        self.wait(opcode, Phase::Read)?;
        bytes.copy_from_slice(&reply);
        self.events.lock().unwrap().push(Event::Read(opcode, reply));
        Ok(bytes.len())
    }

    fn write_read(&self, _: u8, _: u8, _: &[u8], _: &mut [u8]) -> crate::Result<()> {
        panic!("APW requires the fixed separate delayed reply")
    }
}

fn owner(backend: &Arc<Backend>, bus: u8) -> BbApwDiagnosticOwner {
    BbApwDiagnosticOwner::new(
        spawn_owned_sim_i2c_service(bus, backend.clone(), Vec::new()).unwrap(),
    )
}

fn close(owner: &mut BbApwDiagnosticOwner) {
    tokio::task::block_in_place(|| {
        owner.close_service_until(Instant::now() + Duration::from_secs(2))
    })
    .unwrap();
    assert!(owner.close_receipt().is_some());
    assert!(owner.snapshot().service_close_observed_at.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joined_profile_retains_all_raw_phases_and_exact_service_lifetime() {
    for dac in [0x23, 0xffff] {
        let backend = Backend::new(dac, false, None);
        let mut owner = owner(&backend, 1);
        let deadline = Instant::now() + Duration::from_secs(10);
        owner.start(deadline).unwrap();
        assert!(spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).is_err());
        assert!(owner.join_until(deadline).await);
        let snapshot = owner.snapshot();
        let data = snapshot
            .data
            .as_ref()
            .expect("actual joined checked profile");
        assert!(snapshot.caller_joined_at.is_some());
        assert!(data.observed_complete_at < deadline);
        assert_eq!(backend.opcodes(), [2, 1, 6, 3]);
        assert_eq!(data.profile.queries.len(), 4);
        assert_eq!(
            data.profile.queries[3].decoded,
            Ok(Field::Dac {
                raw: dac,
                millivolts: if dac == 0x23 { Some(14670) } else { None },
            })
        );
        assert_eq!(
            data.profile
                .queries
                .iter()
                .map(|row| row.returned_reads.as_ref().unwrap()[0].len())
                .collect::<Vec<_>>(),
            [8, 8, 40, 10]
        );
        assert!(owner.close_receipt().is_none());
        owner.cancel();
        assert!(owner.snapshot().data.is_none());
        assert!(
            snapshot.data.is_some(),
            "prior issued snapshot remains historical"
        );
        close(&mut owner);
        let mut replacement = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
        tokio::task::block_in_place(|| {
            replacement.close_and_join_until(Instant::now() + Duration::from_secs(1))
        })
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_calibration_keeps_prior_identity_and_raw_rejection_without_data() {
    let backend = Backend::new(0x23, true, None);
    let mut owner = owner(&backend, 1);
    let deadline = Instant::now() + Duration::from_secs(8);
    owner.start(deadline).unwrap();
    assert!(owner.join_until(deadline).await);
    let snapshot = owner.snapshot();
    let attempt = snapshot.attempt.as_ref().unwrap();
    assert_eq!(attempt.queries.len(), 3);
    assert_eq!(attempt.queries[0].decoded, Ok(Field::Hardware(0x76)));
    assert_eq!(attempt.queries[1].decoded, Ok(Field::Firmware(0x17)));
    assert_eq!(
        &attempt.queries[2].returned_reads.as_ref().unwrap()[0][37..],
        &[0x4b, 0x21, 0xf5]
    );
    assert!(attempt.queries[2].decoded.is_err());
    assert!(snapshot.failure.is_some() && snapshot.data.is_none());
    assert_eq!(backend.opcodes(), [2, 1, 6]);
    assert!(owner.start(deadline).is_err());
    close(&mut owner);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_after_two_completed_identity_phases_keeps_them_and_stops_later_dac() {
    let backend = Backend::new(0x23, false, Some((6, Phase::Write)));
    let mut owner = owner(&backend, 1);
    let deadline = Instant::now() + Duration::from_secs(10);
    owner.start(deadline).unwrap();
    backend.wait_entered().await;
    // Entered calibration proves both actual identity replies decoded before
    // the next phase. Its write is already started when this latch changes.
    owner.owner.terminal_fence().latch_terminal_safe_off();
    backend.release();
    assert!(owner.join_until(deadline).await);
    let snapshot = owner.snapshot();
    let attempt = snapshot.attempt.as_ref().unwrap();
    assert_eq!(attempt.queries.len(), 3);
    assert_eq!(attempt.queries[0].decoded, Ok(Field::Hardware(0x76)));
    assert_eq!(attempt.queries[1].decoded, Ok(Field::Firmware(0x17)));
    assert!(attempt.queries[..2]
        .iter()
        .all(|row| row.returned_reads.as_ref().unwrap()[0].len() == 8));
    assert_eq!(attempt.queries[2].query, Query::Calibration);
    assert!(attempt.queries[2].decoded.is_err());
    assert_eq!(backend.opcodes(), [2, 1, 6]);
    assert!(snapshot.data.is_none() && snapshot.failure.is_some());
    assert!(snapshot.caller_joined_at.is_some() && owner.close_receipt().is_none());
    close(&mut owner);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_pending_join_permanently_cancels_but_retains_actual_caller_for_cleanup() {
    let backend = Backend::new(0x23, false, Some((2, Phase::Read)));
    let mut owner = owner(&backend, 1);
    let deadline = Instant::now() + Duration::from_secs(10);
    owner.start(deadline).unwrap();
    backend.wait_entered().await;
    {
        let mut pending = Box::pin(owner.join_until(deadline));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut pending)
                .await
                .is_err()
        );
    }
    assert!(owner
        .snapshot()
        .failure
        .as_ref()
        .unwrap()
        .contains("pending join cancelled"));
    assert!(owner.handle.terminal_safe_off_is_latched());
    assert!(owner.task.is_some());
    assert!(tokio::task::block_in_place(
        || owner.close_service_until(Instant::now() + Duration::from_millis(10))
    )
    .is_err());
    assert!(owner.close_receipt().is_none());
    backend.release();
    assert!(
        owner
            .join_until(Instant::now() + Duration::from_secs(2))
            .await
    );
    let snapshot = owner.snapshot();
    assert!(snapshot.caller_joined_at.is_some() && snapshot.attempt.is_some());
    assert!(snapshot.data.is_none());
    assert_eq!(backend.opcodes(), [2]);
    close(&mut owner);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_complete_profile_left_unjoined_past_original_deadline_remains_diagnostic() {
    let backend = Backend::new(0x23, false, None);
    let mut owner = owner(&backend, 1);
    let deadline = Instant::now() + Duration::from_secs(6);
    owner.start(deadline).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = owner.snapshot();
            if snapshot
                .attempt
                .as_ref()
                .is_some_and(|attempt| attempt.caller_completed_at.is_some())
                && owner.task.as_ref().unwrap().is_finished()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(owner.snapshot().caller_joined_at.is_none());
    assert!(owner.snapshot().data.is_none());
    tokio::time::sleep_until((deadline + Duration::from_millis(10)).into()).await;
    assert!(
        owner
            .join_until(Instant::now() + Duration::from_secs(1))
            .await
    );
    let snapshot = owner.snapshot();
    assert!(snapshot
        .failure
        .as_ref()
        .unwrap()
        .contains("original deadline"));
    assert!(snapshot.data.is_none());
    let attempt = snapshot.attempt.unwrap();
    assert!(attempt.caller_completed_at.unwrap() < deadline);
    assert_eq!(attempt.queries.len(), 4);
    assert!(attempt
        .queries
        .iter()
        .all(|row| row.returned_reads.is_some() && row.decoded.is_ok()));
    close(&mut owner);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn started_timeout_joins_caller_before_actual_service_can_be_closed() {
    let backend = Backend::new(0x23, false, Some((2, Phase::Write)));
    let mut owner = owner(&backend, 1);
    owner
        .start(Instant::now() + Duration::from_millis(500))
        .unwrap();
    backend.wait_entered().await;
    assert!(
        owner
            .join_until(Instant::now() + Duration::from_secs(2))
            .await
    );
    let snapshot = owner.snapshot();
    let attempt = snapshot.attempt.as_ref().unwrap();
    assert!(attempt
        .failure
        .as_ref()
        .unwrap()
        .contains("outcome is unknown"));
    assert_eq!(attempt.queries.len(), 1);
    assert!(attempt.queries[0].returned_reads.is_none());
    assert!(snapshot.caller_joined_at.is_some() && snapshot.data.is_none());
    assert!(tokio::task::block_in_place(
        || owner.close_service_until(Instant::now() + Duration::from_millis(10))
    )
    .is_err());
    assert!(owner.close_receipt().is_none());
    assert!(owner.snapshot().service_close_observed_at.is_none());
    backend.release();
    close(&mut owner);
    assert_eq!(backend.opcodes(), [2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_bus_expiry_or_prior_cancellation_is_one_shot_without_query_bytes() {
    for mode in 0..3 {
        let backend = Backend::new(0x23, false, None);
        let mut owner = owner(&backend, if mode == 0 { 0 } else { 1 });
        if mode == 2 {
            owner.cancel();
        }
        let deadline = if mode == 1 {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(1)
        };
        assert!(owner.start(deadline).is_err());
        assert!(owner
            .start(Instant::now() + Duration::from_secs(1))
            .is_err());
        assert!(
            owner
                .join_until(Instant::now() + Duration::from_secs(1))
                .await
        );
        assert!(owner.snapshot().attempt.is_none() && owner.snapshot().data.is_none());
        assert!(backend.trace().is_empty());
        close(&mut owner);
    }
}
