//! Host-only wire fixture around the actual AM2 BM1398 serialized I2C worker.
//! No controller acknowledgment, factory decode or executor decision is bypassed.
use super::*;
use crate::i2c::{spawn_owned_sim_i2c_service, I2cServiceOwner, I2cSimBackend};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireFault {
    None,
    PicVersion86,
    PicAck,
    PsuNotReady,
}
#[derive(Clone, Debug, Default)]
pub struct WireSnapshot {
    pub factory_bytes: [usize; 3],
    pub pic_enabled: [bool; 3],
    pub heartbeats: [usize; 3],
    pub frames: Vec<(u8, Vec<u8>)>,
    pub apw_voltage_commands: usize,
}
struct WireState {
    snapshot: WireSnapshot,
    requests: BTreeMap<u8, Vec<u8>>,
    replies: BTreeMap<u8, VecDeque<u8>>,
}
struct Wire {
    identity: usize,
    pages: Vec<Vec<u8>>,
    fault: WireFault,
    state: Mutex<WireState>,
}
impl Wire {
    fn error(&self, address: u8, detail: &str) -> crate::HalError {
        crate::HalError::I2c {
            bus: 0,
            addr: address,
            detail: detail.into(),
        }
    }
    fn byte(&self, address: u8, byte: u8) -> crate::Result<()> {
        let mut state = self.state.lock().unwrap();
        let request = state.requests.entry(address).or_default();
        // The real PIC worker flushes its parser after a failed exchange.
        if request.is_empty() && byte == 0 {
            return Ok(());
        }
        request.push(byte);
        if request.len() > 16 {
            return Err(self.error(address, "unbounded framed request"));
        }
        if request.len() < 3 || request.len() != usize::from(request[2]) + 2 {
            return Ok(());
        }
        let request = std::mem::take(request);
        if request[..2] != [0x55, 0xaa] {
            return Err(self.error(address, "bad controller preamble"));
        }
        let end = request.len() - 2;
        let sum: u16 = request[2..end].iter().map(|b| u16::from(*b)).sum();
        let checksum = if address == 0x10 {
            u16::from_le_bytes(request[end..].try_into().unwrap())
        } else {
            u16::from_be_bytes(request[end..].try_into().unwrap())
        };
        if sum != checksum {
            return Err(self.error(address, "bad request checksum"));
        }
        if state.replies.get(&address).is_some_and(|r| !r.is_empty()) {
            return Err(self.error(address, "interleaved controller transaction"));
        }
        if state.snapshot.frames.len() >= 4096 {
            return Err(self.error(address, "wire trace cap"));
        }
        state.snapshot.frames.push((address, request.clone()));
        let command = request[3];
        let reply = if address == 0x10 {
            match command {
                2 => vec![0x55, 0xaa, 6, 2, 0x71, 0, 0x79, 0],
                0x83 => {
                    state.snapshot.apw_voltage_commands += 1;
                    vec![0x55, 0xaa, 6, 0x83, 0, 0, 0x89, 0]
                }
                _ => return Err(self.error(address, "unowned APW command")),
            }
        } else {
            let slot = usize::from(address - 0x20);
            match command {
                0x17 => {
                    let version = if self.fault == WireFault::PicVersion86 {
                        0x86
                    } else {
                        0x89
                    };
                    vec![5, 0x17, version, 0, 5 + 0x17 + version]
                }
                0x15 => {
                    if request.len() != 7 || request[4] > 1 {
                        return Err(self.error(address, "bad PIC enable"));
                    }
                    if self.fault == WireFault::PicAck && request[4] == 1 {
                        vec![0x15, 0]
                    } else {
                        state.snapshot.pic_enabled[slot] = request[4] == 1;
                        vec![0x15, 1]
                    }
                }
                0x16 => {
                    state.snapshot.heartbeats[slot] += 1;
                    vec![6, 0x16, 1, 0, 0, 0]
                }
                _ => return Err(self.error(address, "unowned PIC command")),
            }
        };
        state.replies.insert(address, reply.into());
        Ok(())
    }
}
impl I2cSimBackend for Wire {
    fn service_identity(&self) -> Option<usize> {
        Some(self.identity)
    }
    fn write(&self, bus: u8, address: u8, data: &[u8]) -> crate::Result<usize> {
        if bus != 0 {
            return Err(self.error(address, "wrong wire bus"));
        }
        match address {
            0x10 if data.len() == 2 && data[0] == 0x11 => self.byte(address, data[1])?,
            0x20..=0x22 if data.len() == 1 && usize::from(address - 0x20) < self.pages.len() => {
                self.byte(address, data[0])?
            }
            _ => {
                return Err(self.error(
                    address,
                    "unowned raw write (factory EEPROM writes are forbidden)",
                ))
            }
        }
        Ok(data.len())
    }
    fn read(&self, bus: u8, address: u8, bytes: &mut [u8]) -> crate::Result<usize> {
        if bus != 0 || bytes.len() != 1 {
            return Err(self.error(address, "expected serialized controller byte"));
        }
        bytes[0] = self
            .state
            .lock()
            .unwrap()
            .replies
            .entry(address)
            .or_default()
            .pop_front()
            .ok_or_else(|| self.error(address, "unexpected controller read"))?;
        Ok(1)
    }
    fn write_read(
        &self,
        bus: u8,
        address: u8,
        written: &[u8],
        bytes: &mut [u8],
    ) -> crate::Result<()> {
        if bus != 0 {
            return Err(self.error(address, "wrong wire bus"));
        }
        if address == 0x10 && written == [0x11] && bytes.len() == 1 {
            return self.read(bus, address, bytes).map(|_| ());
        }
        if address == 0x10 && written == [0] && bytes.len() == 1 {
            bytes[0] = if self.fault == WireFault::PsuNotReady {
                0
            } else {
                0xf5
            };
            return Ok(());
        }
        if !(0x50..=0x52).contains(&address) || written.len() != 1 {
            return Err(self.error(address, "unowned combined request"));
        }
        let slot = usize::from(address - 0x50);
        let page = self
            .pages
            .get(slot)
            .ok_or_else(|| self.error(address, "missing factory slot"))?;
        let start = usize::from(written[0]);
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| self.error(address, "factory span overflow"))?;
        let source = page
            .get(start..end)
            .ok_or_else(|| self.error(address, "factory span outside page"))?;
        bytes.copy_from_slice(source);
        self.state.lock().unwrap().snapshot.factory_bytes[slot] += bytes.len();
        Ok(())
    }
}

/// Owns one modeled wire and the actual worker serving it. It cannot wrap a
/// caller-provided service, so the injected image marker cannot reach real I2C.
pub struct Rig {
    wire: Arc<Wire>,
    worker: I2cServiceOwner,
}
impl Rig {
    pub fn new(pages: Vec<Vec<u8>>, fault: WireFault) -> Result<Self, String> {
        if pages.is_empty() || pages.len() > 3 || pages.iter().any(|p| p.len() != 256) {
            return Err("BM1398 fixture requires one to three literal256-byte pages".into());
        }
        static NEXT: AtomicUsize = AtomicUsize::new(0x1398_1000);
        let wire = Arc::new(Wire {
            identity: NEXT.fetch_add(1, Ordering::Relaxed),
            pages,
            fault,
            state: Mutex::new(WireState {
                snapshot: WireSnapshot::default(),
                requests: BTreeMap::new(),
                replies: BTreeMap::new(),
            }),
        });
        let worker = spawn_owned_sim_i2c_service(0, wire.clone(), (0x50..=0x57).collect())
            .map_err(|e| e.to_string())?;
        Ok(Self { wire, worker })
    }
    pub fn snapshot(&self) -> WireSnapshot {
        self.wire.state.lock().unwrap().snapshot.clone()
    }
    pub fn open_adapter<C: Am2Bm1398Custody>(
        &self,
        marker: &str,
        chains: BTreeMap<u8, Am2Bm1398ChainIo>,
        custody: Arc<C>,
        board: Am2Bm1398BoardKind,
    ) -> Result<Am2Bm1398Io<C>, String> {
        if chains.values().any(|io| {
            let fifo = &io.fifo;
            fifo.sim_chain_observer().is_err()
                || [
                    fifo.common.raw_fd(),
                    fifo.cmd.raw_fd(),
                    fifo.work_rx.raw_fd(),
                    fifo.work_tx.raw_fd(),
                ]
                .iter()
                .any(|fd| *fd != -1)
                || !io.commands.sim_owns_fpga(fifo)
        }) {
            return Err(
                "injected marker requires the same wholly simulated command/work backing".into(),
            );
        }
        let pic = Nbp1901PicService::new(self.worker.request_handle())?;
        Am2Bm1398Io::from_observed_marker(pic, chains, custody, board, marker)
    }
    pub fn close(&mut self, deadline: Instant) -> Result<(), String> {
        self.worker
            .close_and_join_until(deadline)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = self
            .worker
            .close_and_join_until(Instant::now() + Duration::from_secs(2));
    }
}
