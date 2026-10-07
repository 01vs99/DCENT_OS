//! Copied exact retained inert wire fixture with visibility-only test seams.
use super::*;
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use crate::platform::sim::{SimControllerKind, SimI2cBackend};
use crate::HalError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Condvar;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    None,
    FactoryCrc,
    Firmware,
    Status,
    Short,
    Read,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Event {
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

pub(super) struct Backend {
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
    pub(super) fn new(fault: Fault, block: Option<(u8, usize)>) -> Arc<Self> {
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

    pub(super) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }

    pub(super) async fn wait_entered(&self) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }

    pub(super) fn trace(&self) -> Vec<Event> {
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
