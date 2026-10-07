//! Existing sim-hal only: original diagnostic backend plus authored fixed PIC
//! runtime exchanges. No actor snapshot, timestamp or readiness is injected.
use crate::i2c::I2cSimBackend;
use crate::{HalError, Result};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const HEARTBEAT: [u8; 6] = [0x55, 0xaa, 4, 0x16, 0, 0x1a];
const DISABLE: [u8; 7] = [0x55, 0xaa, 5, 0x15, 0, 0, 0x1a];
// Independent literal fixture for the held initializer Bridge request. Reply
// bytes below are intentionally unvalidated, never an ACK/physical-state DTO.
const BRIDGE: [u8; 8] = [0x55, 0xaa, 6, 0x3b, 0x48, 0, 0, 0x89];

#[derive(Clone, Debug)]
pub(crate) struct WireEvent {
    pub at: Instant,
    pub address: u8,
    pub opcode: u8,
    pub write: bool,
    pub bytes: Vec<u8>,
}
struct Reply {
    address: u8,
    opcode: u8,
    bytes: Vec<u8>,
    position: usize,
}
pub(crate) struct WireGate {
    pub entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
}
impl WireGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            changed: Condvar::new(),
        })
    }
    pub(crate) fn wait(&self) {
        self.entered.store(true, Ordering::SeqCst);
        let locked = self.released.lock().unwrap();
        let (locked, _) = self
            .changed
            .wait_timeout_while(locked, Duration::from_secs(12), |released| !*released)
            .unwrap();
        assert!(*locked, "authored original worker gate not released");
    }
    pub(crate) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}
pub(crate) struct RuntimeWire {
    original: Arc<dyn I2cSimBackend>,
    reply: Mutex<Option<Reply>>,
    events: Mutex<Vec<WireEvent>>,
    heartbeat_fault: AtomicU8,
    disable_fault: AtomicU8,
    disable_gate: Mutex<Option<Arc<WireGate>>>,
    bridge_fault: AtomicU8,
    bridge_gate: Mutex<Option<Arc<WireGate>>>,
}
impl RuntimeWire {
    pub(crate) fn new(original: Arc<dyn I2cSimBackend>) -> Arc<Self> {
        Arc::new(Self {
            original,
            reply: Mutex::new(None),
            events: Mutex::new(Vec::new()),
            heartbeat_fault: AtomicU8::new(0),
            disable_fault: AtomicU8::new(0),
            disable_gate: Mutex::new(None),
            bridge_fault: AtomicU8::new(0),
            bridge_gate: Mutex::new(None),
        })
    }
    pub(crate) fn fail_heartbeat(&self) {
        self.heartbeat_fault.store(1, Ordering::SeqCst);
    }
    pub(crate) fn fail_second_disable_read(&self) {
        self.disable_fault.store(1, Ordering::SeqCst);
    }
    pub(crate) fn events(&self) -> Vec<WireEvent> {
        self.events.lock().unwrap().clone()
    }
    pub(crate) fn block_second_disable_read(&self) -> Arc<WireGate> {
        let gate = WireGate::new();
        *self.disable_gate.lock().unwrap() = Some(gate.clone());
        gate
    }
    pub(crate) fn fail_bridge_final_read(&self) {
        self.bridge_fault.store(1, Ordering::SeqCst);
    }
    pub(crate) fn block_bridge_final_read(&self) {
        *self.bridge_gate.lock().unwrap() = Some(WireGate::new());
    }
    pub(crate) async fn wait_bridge_entered(&self) {
        let gate = self
            .bridge_gate
            .lock()
            .unwrap()
            .clone()
            .expect("actual Bridge gate installed");
        Self::wait_gate_entered(gate).await;
    }
    pub(crate) async fn wait_disable_entered(&self) {
        let gate = self
            .disable_gate
            .lock()
            .unwrap()
            .clone()
            .expect("actual disable gate installed");
        Self::wait_gate_entered(gate).await;
    }
    async fn wait_gate_entered(gate: Arc<WireGate>) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !gate.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("original simulated worker did not enter the installed gate");
    }
    pub(crate) fn release(&self) {
        if let Some(gate) = self.disable_gate.lock().unwrap().as_ref() {
            gate.release();
        }
        if let Some(gate) = self.bridge_gate.lock().unwrap().as_ref() {
            gate.release();
        }
    }
}
impl I2cSimBackend for RuntimeWire {
    fn service_identity(&self) -> Option<usize> {
        self.original.service_identity()
    }
    fn write(&self, bus: u8, address: u8, bytes: &[u8]) -> Result<usize> {
        let reply = if bytes == HEARTBEAT {
            Some((
                0x16,
                if self.heartbeat_fault.load(Ordering::SeqCst) == 0 {
                    vec![6, 0x16, 1, 0, 0, 0x1d]
                } else {
                    vec![6, 0x16, 0, 0, 0, 0x1c]
                },
            ))
        } else if bytes == DISABLE {
            // These are unvalidated bytes, deliberately not a physical ACK.
            Some((0x15, vec![0x15, 0]))
        } else if bytes == BRIDGE {
            Some((0x3b, vec![0x00, 0xff]))
        } else {
            None
        };
        if let Some((opcode, reply)) = reply {
            assert_eq!(bus, 0);
            assert!((0x20..=0x22).contains(&address));
            self.events.lock().unwrap().push(WireEvent {
                at: Instant::now(),
                address,
                opcode,
                write: true,
                bytes: bytes.to_vec(),
            });
            *self.reply.lock().unwrap() = Some(Reply {
                address,
                opcode,
                bytes: reply,
                position: 0,
            });
            Ok(bytes.len())
        } else {
            *self.reply.lock().unwrap() = None;
            self.original.write(bus, address, bytes)
        }
    }
    fn read(&self, bus: u8, address: u8, output: &mut [u8]) -> Result<usize> {
        let mut locked = self.reply.lock().unwrap();
        if let Some(reply) = locked.as_mut() {
            assert_eq!((bus, address, output.len()), (0, reply.address, 1));
            if reply.opcode == 0x15 && reply.position == 1 {
                let gate = self.disable_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.wait();
                }
            }
            if reply.opcode == 0x15
                && reply.position == 1
                && self.disable_fault.load(Ordering::SeqCst) != 0
            {
                return Err(HalError::I2cEndpointRefused {
                    bus,
                    addr: address,
                    detail: "authored actual second disable read failure".into(),
                });
            }
            if reply.opcode == 0x3b && reply.position == 1 {
                let gate = self.bridge_gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.wait();
                }
                if self.bridge_fault.load(Ordering::SeqCst) != 0 {
                    return Err(HalError::I2cEndpointRefused {
                        bus,
                        addr: address,
                        detail: "authored actual final Bridge read failure".into(),
                    });
                }
            }
            output[0] = reply.bytes[reply.position];
            reply.position += 1;
            self.events.lock().unwrap().push(WireEvent {
                at: Instant::now(),
                address,
                opcode: reply.opcode,
                write: false,
                bytes: output.to_vec(),
            });
            Ok(1)
        } else {
            drop(locked);
            self.original.read(bus, address, output)
        }
    }
    fn write_read(&self, bus: u8, address: u8, input: &[u8], output: &mut [u8]) -> Result<()> {
        *self.reply.lock().unwrap() = None;
        self.original.write_read(bus, address, input, output)
    }
}
