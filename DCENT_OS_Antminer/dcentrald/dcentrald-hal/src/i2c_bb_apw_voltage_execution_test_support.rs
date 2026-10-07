//! Owned-service APW execution fixture; authored actuator replies and bounded stalls.
use super::*;

use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use crate::platform::sim::{SimControllerKind, SimI2cBackend};
use crate::HalError;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Condvar;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Write,
    Read,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Event {
    Write(u8, Vec<u8>),
    Read(u8, Vec<u8>),
}

pub(super) struct Backend {
    identity: SimI2cBackend,
    dac: AtomicU16,
    hardware: u16,
    firmware: u16,
    fault: Option<(u8, bool)>,
    bad_calibration: bool,
    block: Option<(u8, Phase)>,
    reply: Mutex<Option<(u8, Vec<u8>)>>,
    events: Mutex<Vec<Event>>,
    entered: AtomicBool,
    fail_set_write: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}

impl Backend {
    pub(super) fn new(
        hardware: u16,
        firmware: u16,
        dac: u16,
        fault: Option<(u8, bool)>,
        block: Option<(u8, Phase)>,
    ) -> Arc<Self> {
        Arc::new(Self {
            identity: SimI2cBackend::with_controller(SimControllerKind::Dspic),
            dac: AtomicU16::new(dac),
            hardware,
            firmware,
            fault,
            bad_calibration: false,
            block,
            reply: Mutex::new(None),
            events: Mutex::new(Vec::new()),
            entered: AtomicBool::new(false),
            fail_set_write: AtomicBool::new(false),
            released: Mutex::new(false),
            condition: Condvar::new(),
        })
    }

    pub(super) fn fail_set_write(&self) {
        self.fail_set_write.store(true, Ordering::SeqCst);
    }

    pub(super) fn trace(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    pub(super) fn opcodes(&self) -> Vec<u8> {
        self.trace()
            .into_iter()
            .filter_map(|event| match event {
                Event::Write(opcode, _) => Some(opcode),
                Event::Read(_, _) => None,
            })
            .collect()
    }

    pub(super) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }

    pub(super) async fn wait_entered(&self) {
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
        if opcode == 0x83 && self.fail_set_write.load(Ordering::SeqCst) {
            self.events
                .lock()
                .unwrap()
                .push(Event::Write(opcode, bytes.to_vec()));
            return Err(HalError::I2c {
                bus,
                addr,
                detail: "fixture immediate set write failure".into(),
            });
        }
        let (request, data, size) = match opcode {
            2 => (
                vec![0x11, 0x55, 0xaa, 4, 2, 6, 0],
                self.hardware.to_le_bytes().to_vec(),
                8,
            ),
            1 => (
                vec![0x11, 0x55, 0xaa, 4, 1, 5, 0],
                self.firmware.to_le_bytes().to_vec(),
                8,
            ),
            6 => {
                let mut data = vec![0x40];
                data.extend([0xff; 32]);
                (vec![0x11, 0x55, 0xaa, 6, 6, 0x40, 0x20, 0x6c, 0], data, 40)
            }
            3 => (
                vec![0x11, 0x55, 0xaa, 4, 3, 7, 0],
                self.dac.load(Ordering::SeqCst).to_le_bytes().to_vec(),
                10,
            ),
            0x83 => {
                assert_eq!(bytes, [0x11, 0x55, 0xaa, 6, 0x83, 0x6c, 0, 0xf5, 0]);
                self.dac.store(0x6c, Ordering::SeqCst);
                let code = if self.fault == Some((0x83, true)) {
                    0x6d_u16
                } else {
                    0x6c_u16
                };
                (bytes.to_vec(), code.to_le_bytes().to_vec(), 10)
            }
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
        let mut reply = reply;
        if self.fault == Some((opcode, false))
            && (opcode != 3 || self.dac.load(Ordering::SeqCst) == 0x6c)
        {
            reply.pop();
        }
        bytes[..reply.len()].copy_from_slice(&reply);
        let actual_len = reply.len();
        self.events.lock().unwrap().push(Event::Read(opcode, reply));
        Ok(actual_len)
    }

    fn write_read(&self, _: u8, _: u8, _: &[u8], _: &mut [u8]) -> crate::Result<()> {
        panic!("APW requires the fixed separate delayed reply")
    }
}
