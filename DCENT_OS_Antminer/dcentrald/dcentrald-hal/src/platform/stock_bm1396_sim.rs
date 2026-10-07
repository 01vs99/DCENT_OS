//! Host-only independent T17e wire-response rig, under the existing sim-hal feature.
//! No readiness, worker receipt, clock or GPIO factory is supplied by callers.
//! Original HAL acquisition/guard/publication/closeout methods create every receipt.
use super::*;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::AtomicU32;

#[cfg(test)]
#[path = "stock_bm1396_s17e_startup_tests.rs"]
mod s17e_tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    None = 0,
    Fan = 1,
    Hot = 2,
    Heartbeat = 3,
    Source = 4,
    AsicRead = 5,
    SourceCut = 6,
    PicOff = 7,
}

#[derive(Clone, Copy)]
pub enum HoldPoint {
    Supply = 1,
    Asic = 2,
}

/// Explicit independent return script; real issued metadata and the complete
/// CPU hash are still checked by the daemon. This is modeled FIFO traffic.
#[derive(Clone, Debug)]
pub struct WorkReturn {
    pub job_id: u32,
    pub version: u32,
    pub ntime: u32,
    pub raw_nonce: u32,
}

#[derive(Clone, Debug)]
pub enum WireEvent {
    Source {
        high: bool,
        at: Instant,
    },
    Pic {
        chain: u8,
        opcode: u8,
    },
    Voltage {
        dac: u8,
    },
    Asic {
        chain: u8,
        frame: [u8; 4],
        value: u32,
    },
    Job {
        id: u32,
        at: Instant,
    },
}

pub struct Rig {
    pub hardware: Arc<WireSimulator>,
    pub owner: Arc<Transport<WireSimulator>>,
    pub line: Arc<PowerLine<WireSimulator>>,
    pub pic: Arc<PicApplication<WireSimulator>>,
}

pub struct WireSimulator {
    model: Model,
    chains: Vec<u8>,
    claimed: AtomicBool,
    registers: Mutex<BTreeMap<u32, u32>>,
    asics: Mutex<BTreeMap<(u8, u8, u8), u32>>,
    sensors: Mutex<BTreeMap<(u8, u8, u8), u8>>,
    assigned: Mutex<BTreeMap<u8, bool>>,
    fifo: Mutex<VecDeque<u32>>,
    pending_registers: Mutex<VecDeque<[u32; 4]>>,
    replies: Mutex<VecDeque<u8>>,
    frame: Mutex<Vec<u8>>,
    dma: Mutex<Vec<u8>>,
    factory: [u8; 256],
    fault: AtomicU32,
    fan_index: AtomicU32,
    automatic: AtomicU32,
    ticks: AtomicU32,
    dac: AtomicU32,
    high: AtomicBool,
    overflow: AtomicBool,
    asic_thread: Mutex<Option<std::thread::ThreadId>>,
    emitted_jobs: Mutex<Vec<u32>>,
    work: Vec<WorkReturn>,
    events: Mutex<Vec<WireEvent>>,
    hold: AtomicU32,
    held: AtomicBool,
    released: AtomicBool,
}

impl WireSimulator {
    pub fn hold_next(&self, point: HoldPoint) {
        self.held.store(false, Ordering::SeqCst);
        self.released.store(false, Ordering::SeqCst);
        self.hold.store(point as u32, Ordering::SeqCst);
    }
    pub fn hold_entered(&self) -> bool {
        self.held.load(Ordering::SeqCst)
    }
    pub fn release_hold(&self) {
        self.released.store(true, Ordering::SeqCst);
    }
    fn pause(&self, point: HoldPoint) -> Result<(), String> {
        if self
            .hold
            .compare_exchange(point as u32, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.held.store(true, Ordering::SeqCst);
            let until = Instant::now() + Duration::from_secs(10);
            while !self.released.load(Ordering::SeqCst) {
                if Instant::now() >= until {
                    return Err("modeled in-flight gate release timeout".into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }
    pub fn inject(&self, fault: Fault) {
        self.fault.store(fault as u32, Ordering::SeqCst);
        if fault == Fault::Source {
            self.high.store(true, Ordering::SeqCst);
        }
    }
    pub fn source_high(&self) -> bool {
        self.high.load(Ordering::SeqCst)
    }
    pub fn events(&self) -> Vec<WireEvent> {
        self.events.lock().unwrap().clone()
    }
    pub fn overflowed(&self) -> bool {
        self.overflow.load(Ordering::SeqCst)
    }
    fn is_fault(&self, fault: Fault) -> bool {
        self.fault.load(Ordering::SeqCst) == fault as u32
    }
    fn queue(&self, words: impl IntoIterator<Item = u32>) -> Result<(), String> {
        let words: Vec<_> = words.into_iter().collect();
        let mut fifo = self.fifo.lock().unwrap();
        if fifo.len() + words.len() > 508 {
            self.overflow.store(true, Ordering::SeqCst);
            return Err("simulated finite FIFO overflow (508 words; 9-bit count)".into());
        }
        fifo.extend(words);
        Ok(())
    }
    fn raw(chain: u8, chip: u8, register: u8, value: u32) -> [u32; 4] {
        [
            u32::from_le_bytes([chain, register, chip, 2]),
            value,
            0x11,
            0x5555aaaa,
        ]
    }
    fn asic_command(&self, control: u32) -> Result<(), String> {
        *self.asic_thread.lock().unwrap() = Some(std::thread::current().id());
        let (frame, word) = {
            let regs = self.registers.lock().unwrap();
            (regs[&0xc4].to_be_bytes(), *regs.get(&0xc8).unwrap_or(&0))
        };
        let chain = ((control >> 16) & 15) as u8;
        self.events.lock().unwrap().push(WireEvent::Asic {
            chain,
            frame,
            value: word,
        });
        self.pause(HoldPoint::Asic)?;
        if !self.chains.contains(&chain) {
            return Err("simulated command names unselected chain".into());
        }
        let chip = frame[2];
        let register = frame[3];
        match frame[0] {
            0x53 => {
                if frame != [0x53, 5, 0, 0] {
                    return Err("simulated inactive frame shape changed".into());
                }
            }
            0x40 => {
                self.assigned.lock().unwrap().insert(chain, true);
            }
            0x52 => {
                if ![0, 0x18, 0xb4, 0xb8].contains(&register) {
                    return Err("simulated broadcast query has no independent fixture".into());
                }
                let assigned = *self.assigned.lock().unwrap().get(&chain).unwrap_or(&false);
                let asics = self.asics.lock().unwrap();
                let mut pending = self.pending_registers.lock().unwrap();
                for ordinal in 0..self.model.expected_chips_per_present_chain() as u8 {
                    let address = if assigned {
                        ordinal * self.model.address_interval()
                    } else {
                        0
                    };
                    let value = match register {
                        0 => 0x13960000,
                        0x18 => *asics
                            .get(&(chain, address, register))
                            .unwrap_or(&0x12404030),
                        // Independent healthy B4/B8 lanes: 3200 * 1.5 / 4096
                        // = 1.171875 V. The old raw 3000 was 1.0986328125 V,
                        // below the source adapted minimum of 1.1 V. This
                        // models observations, not a physical DAC calibration.
                        _ => 0x0c80_0c80,
                    };
                    pending.push_back(Self::raw(chain, address, register, value));
                }
            }
            0x42 => {
                let value = *self
                    .asics
                    .lock()
                    .unwrap()
                    .get(&(chain, chip, register))
                    .unwrap_or(&0);
                self.queue(Self::raw(chain, chip, register, value))?;
            }
            0x51 | 0x41 => {
                let mut observed = word;
                if frame[0] == 0x41 && register == 0x1c {
                    if word == 0x07980000 {
                        self.automatic.fetch_add(1, Ordering::SeqCst);
                    } else if word & 0x06000000 == 0 {
                        let sensor_reg = (word >> 8) as u8;
                        if word & 0x10000 != 0 {
                            self.sensors
                                .lock()
                                .unwrap()
                                .insert((chain, chip, sensor_reg), word as u8);
                        } else {
                            let value = if sensor_reg == 0xfe {
                                if chip & 1 == 0 {
                                    0x1a
                                } else {
                                    0x55
                                }
                            } else {
                                *self
                                    .sensors
                                    .lock()
                                    .unwrap()
                                    .get(&(chain, chip, sensor_reg))
                                    .unwrap_or(&0)
                            };
                            observed = (word & !255) | u32::from(value);
                        }
                    }
                }
                let mut asics = self.asics.lock().unwrap();
                if frame[0] == 0x51 {
                    for ordinal in 0..self.model.expected_chips_per_present_chain() as u8 {
                        asics.insert(
                            (chain, ordinal * self.model.address_interval(), register),
                            observed,
                        );
                    }
                } else {
                    asics.insert((chain, chip, register), observed);
                }
            }
            _ => return Err(format!("simulated unrecognized ASIC command {frame:x?}")),
        }
        Ok(())
    }
    fn management_command(&self, value: u32) -> Result<(), String> {
        if value & 0xfff8_ff00 != 0x0040_0000 && value & 0xffff_ff00 != 0x0520_1100 {
            return Ok(()); // Actual reads and EEPROM addressed reads carry no TX byte.
        }
        let mut frame = self.frame.lock().unwrap();
        frame.push(value as u8);
        if frame.len() < 3 || frame.len() != usize::from(frame[2]) + 2 {
            return Ok(());
        }
        if frame[..2] != [0x55, 0xaa] {
            return Err("simulated PIC frame lost prefix".into());
        }
        let chain = ((value >> 16) & 7) as u8;
        self.events.lock().unwrap().push(WireEvent::Pic {
            chain,
            opcode: frame[3],
        });
        let reply = match frame[3] {
            2 if &*frame == &[0x55, 0xaa, 4, 2, 6, 0] => vec![0x55, 0xaa, 6, 2, 0x42, 0, 0x4a, 0],
            0x17 => vec![5, 0x17, 0x89, 0, 0],
            // Stock accepts long replies by length/opcode only; byte2 is not
            // a status bit. The fault is an actual wrong echoed opcode.
            0x16 if self.is_fault(Fault::Heartbeat) => vec![6, 0x17, 1, 0, 0, 0],
            0x16 => vec![6, 0x16, 1, 0, 0, 0],
            0x15 => vec![0x15, u8::from(!self.is_fault(Fault::PicOff))],
            0x83 => {
                if frame.len() != 8 {
                    return Err("simulated voltage frame length".into());
                }
                self.dac.store(u32::from(frame[4]), Ordering::SeqCst);
                self.events
                    .lock()
                    .unwrap()
                    .push(WireEvent::Voltage { dac: frame[4] });
                frame.clone()
            }
            0x29 if self.model == Model::S17e && &*frame == &[0x55, 0xaa, 4, 0x29, 0, 0x2d] => {
                // Independent fixed voltage/reference vectors use 12-bit
                // samples here, not T17e's combined 10-bit response. These
                // explicit DAC/ADC pairs cover the source matrix and fixture
                // working rail; no production voltage planner is called.
                let raw: u16 = match self.dac.load(Ordering::SeqCst) {
                    12 => 3360,  // 2100 cV
                    48 => 3200,  // 2000
                    55 => 3168,  // 1980
                    66 => 3120,  // 1950
                    77 => 3072,  // 1920
                    84 => 3040,  // 1900
                    91 => 3008,  // 1880
                    98 => 2976,  // 1860
                    120 => 2880, // 1800
                    dac => {
                        return Err(format!(
                            "simulated S17e rail lacks independent DAC{dac} fixture"
                        ))
                    }
                };
                // Original stock_bm1396_rail_vectors.json, S17e raw3200:
                // 0929010c80000000bf, with only actual modeled sample changed.
                let mut response = vec![9, 0x29, 1, (raw >> 8) as u8, raw as u8, 0, 0];
                let checksum: u16 = response.iter().map(|&byte| u16::from(byte)).sum();
                response.extend(checksum.to_be_bytes());
                response
            }
            0x28 if self.model == Model::S17e && &*frame == &[0x55, 0xaa, 4, 0x28, 0, 0x2c] => {
                // Exact companion reference0x0be0, same independent vector.
                vec![
                    0x0d, 0x28, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x0b, 0xe0, 3, 0x8a,
                ]
            }
            0x37 if self.model == Model::T17e => {
                let raw: u16 = match self.dac.load(Ordering::SeqCst) {
                    12 => 840,
                    48 => 800,
                    45 => 804,
                    dac => {
                        return Err(format!("simulated rail lacks independent DAC{dac} fixture"))
                    }
                };
                let mut response = vec![
                    11,
                    0x37,
                    0,
                    0x12,
                    0x34,
                    (raw >> 8) as u8,
                    raw as u8,
                    2,
                    0xf8,
                ];
                let sum: u16 = response.iter().map(|&byte| u16::from(byte)).sum();
                response.extend(sum.to_be_bytes());
                response
            }
            opcode => return Err(format!("simulated PIC opcode{opcode:x} unimplemented")),
        };
        frame.clear();
        self.replies.lock().unwrap().extend(reply);
        if value & 0xffff_ff00 == 0x0520_1100 && self.dac.load(Ordering::SeqCst) == 0 {
            self.pause(HoldPoint::Supply)?;
        }
        Ok(())
    }
    fn work_started(&self) -> Result<(), String> {
        let registers = self.registers.lock().unwrap();
        let id = *registers.get(&0x124).unwrap_or(&u32::MAX);
        let mut emitted = self.emitted_jobs.lock().unwrap();
        if emitted.contains(&id) {
            return Ok(());
        }
        emitted.push(id);
        self.events.lock().unwrap().push(WireEvent::Job {
            id,
            at: Instant::now(),
        });
        let Some(work) = self.work.iter().find(|work| work.job_id == id) else {
            return Ok(());
        };
        // Pool scalar strings enter the retained packet in big-endian byte
        // order, then its source parser reads LE words for raw FPGA stores.
        // The script keeps canonical numeric fields from independent headers.
        if registers.get(&0x130) != Some(&work.version.swap_bytes())
            || registers.get(&0x134) != Some(&work.ntime.swap_bytes())
        {
            return Err("simulated scripted return differs from actual version/time writes".into());
        }
        let work_id = u16::try_from(id + 1).map_err(|_| "simulated outstanding index bound")?;
        let mut record = [0u8; 64];
        record[..4].copy_from_slice(&id.to_le_bytes());
        record[4..8].copy_from_slice(&work.version.to_be_bytes());
        record[8..12].copy_from_slice(&registers.get(&0x108).copied().unwrap_or(0).to_le_bytes());
        record[12..16].copy_from_slice(&registers.get(&0x10c).copied().unwrap_or(0).to_le_bytes());
        drop(registers);
        let offset = usize::from(work_id) * 64;
        self.dma.lock().unwrap()[offset..offset + 64].copy_from_slice(&record);
        for &chain in &self.chains {
            self.queue([
                u32::from_le_bytes([0x80 | chain, 0, work_id as u8, 0x80 | (work_id >> 8) as u8]),
                work.raw_nonce,
                0,
                0x5555aaaa,
            ])?;
        }
        Ok(())
    }
}

impl Hardware for WireSimulator {
    fn model(&self) -> Model {
        self.model
    }
    fn validate_owner(&self) -> Result<(), String> {
        Ok(())
    }
    fn claim_transport(&self) -> Result<(), String> {
        self.claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|_| "simulated transport already claimed".into())
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        match offset {
            4 => {
                let fan = self.fan_index.fetch_add(1, Ordering::SeqCst) % 4;
                Ok((fan << 8) | if self.is_fault(Fault::Fan) { 0 } else { 40 })
            }
            0x18 => {
                if self.is_fault(Fault::AsicRead) {
                    return Err("simulated ASIC FIFO read failure".into());
                }
                *self.asic_thread.lock().unwrap() = Some(std::thread::current().id());
                Ok(self.fifo.lock().unwrap().len() as u32)
            }
            0x10 | 0x14 => self
                .fifo
                .lock()
                .unwrap()
                .pop_front()
                .ok_or("simulated FIFO underflow".into()),
            0x30 => {
                let command = self.registers.lock().unwrap()[&0x30];
                let byte = if command & 0xfff8_0000 == 0x03a0_0000 {
                    self.factory[((command >> 8) & 255) as usize]
                } else if command & 0x0200_0000 != 0 {
                    self.replies
                        .lock()
                        .unwrap()
                        .pop_front()
                        .ok_or("simulated PIC reply exhausted")?
                } else {
                    0
                };
                Ok(0x8000_0000 | u32::from(byte))
            }
            _ => Ok(*self.registers.lock().unwrap().get(&offset).unwrap_or(&0)),
        }
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.registers.lock().unwrap().insert(
            offset,
            if offset == 0xc0 {
                value & !0x8000_0000
            } else {
                value
            },
        );
        if offset == 0xc0 && value & 0x8000_0000 != 0 {
            self.asic_command(value)?;
        }
        if offset == 0x30 {
            self.management_command(value)?;
        }
        if offset == 0x100 && value & 0x40 != 0 {
            self.work_started()?;
        }
        Ok(())
    }
    fn read_dma(&self, offset: usize, out: &mut [u8]) -> Result<(), String> {
        let dma = self.dma.lock().unwrap();
        out.copy_from_slice(
            dma.get(offset..offset + out.len())
                .ok_or("simulated DMA read bounds")?,
        );
        Ok(())
    }
    fn write_dma(&self, offset: usize, bytes: &[u8]) -> Result<(), String> {
        self.dma
            .lock()
            .unwrap()
            .get_mut(offset..offset + bytes.len())
            .ok_or("simulated DMA write bounds")?
            .copy_from_slice(bytes);
        Ok(())
    }
    fn barrier(&self) -> Result<(), String> {
        Ok(())
    }
    fn sleep(&self, duration: Duration) {
        if duration == Duration::from_millis(1)
            && self.asic_thread.lock().unwrap().as_ref() == Some(&std::thread::current().id())
        {
            if let Some(words) = self.pending_registers.lock().unwrap().pop_front() {
                let _ = self.queue(words);
            }
            let tick = self.ticks.fetch_add(1, Ordering::SeqCst) + 1;
            if self.automatic.load(Ordering::SeqCst) >= 8 * self.chains.len() as u32
                && tick % 100 == 0
            {
                for &chain in &self.chains {
                    for address in match self.model {
                        Model::T17e => [51, 36, 195, 180],
                        Model::S17e => [27, 35, 99, 107],
                    } {
                        let value =
                            ((if self.is_fault(Fault::Hot) { 164 } else { 112 }) << 16) | 0x180;
                        let _ = self.queue(Self::raw(chain, address, 0x44, value));
                    }
                }
            }
            if self
                .registers
                .lock()
                .unwrap()
                .get(&0x100)
                .is_some_and(|value| value & 0x40 != 0)
            {
                std::thread::sleep(duration);
            }
        }
        std::thread::yield_now();
    }
}

pub(super) struct SimulatedPin(pub(super) Arc<WireSimulator>);
impl gpio::Pin for SimulatedPin {
    fn high(&self) -> Result<(), String> {
        self.0.events.lock().unwrap().push(WireEvent::Source {
            high: true,
            at: Instant::now(),
        });
        if self.0.is_fault(Fault::SourceCut) {
            return Err("simulated source cut failed".into());
        }
        self.0.high.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn low(&self) -> Result<(), String> {
        self.0.events.lock().unwrap().push(WireEvent::Source {
            high: false,
            at: Instant::now(),
        });
        self.0.high.store(false, Ordering::SeqCst);
        Ok(())
    }
    fn observed_high(&self) -> Result<bool, String> {
        Ok(self.0.source_high())
    }
}

impl Rig {
    /// Explicit host fixture construction. Its only pin is owned by this exact
    /// memory-only simulator; neither a production Hardware type nor raw pin is accepted.
    pub async fn observe(chains: Vec<u8>, work: Vec<WorkReturn>) -> Result<Self, String> {
        Self::observe_model(Model::T17e, chains, work).await
    }

    /// Distinct exact-model fixture; all observations still come from real HAL
    /// transactions over modeled wire traffic, never caller-minted receipts.
    pub async fn observe_model(
        model: Model,
        chains: Vec<u8>,
        work: Vec<WorkReturn>,
    ) -> Result<Self, String> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64"))
            || std::path::Path::new("/dev/uio0").exists()
            || std::path::Path::new("/sys/class/gpio/gpiochip906").exists()
        {
            return Err(
                "BM1396 modeled wire rig requires an x86_64 Linux host without miner devices"
                    .into(),
            );
        }
        let data: serde_json::Value =
            serde_json::from_str(include_str!("stock_bm1396_factory_vectors.json"))
                .map_err(|e| e.to_string())?;
        let hex = data["cases"]
            .as_array()
            .ok_or("simulated factory vector cases")?
            .iter()
            .find(|row| row["label"] == "range_1800")
            .ok_or("simulated original factory vector")?["records"]["0"]
            .as_str()
            .ok_or("simulated original factory bytes")?;
        let mut factory = [0; 256];
        if hex.len() != factory.len() * 2 {
            return Err("simulated factory vector length".into());
        }
        for (byte, pair) in factory.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).map_err(|e| e.to_string())?, 16)
                .map_err(|e| e.to_string())?;
        }
        if model == Model::S17e {
            factory.fill(0);
            factory[..2].copy_from_slice(&0x1396u16.to_le_bytes());
            factory[0x28..0x2a].copy_from_slice(&0x1396u16.to_le_bytes());
            for index in 0..135 {
                factory[0x2a + index] = 60 + (index % 3) as u8;
            }
            factory[0xb1..0xb3].copy_from_slice(&1900u16.to_le_bytes());
            factory[0xb9] = 1;
            // Independent fixture encoder for reflected Modbus checksum.
            fn checksum(bytes: &[u8]) -> u16 {
                let mut crc = 0xffffu16;
                for &byte in bytes {
                    crc ^= u16::from(byte);
                    for _ in 0..8 {
                        crc = if crc & 1 != 0 {
                            (crc >> 1) ^ 0xa001
                        } else {
                            crc >> 1
                        };
                    }
                }
                crc
            }
            let first = checksum(&factory[..0x26]);
            let second = checksum(&factory[0x28..0xfe]);
            factory[0x26..0x28].copy_from_slice(&first.to_le_bytes());
            factory[0xfe..].copy_from_slice(&second.to_le_bytes());
        }
        let hardware = Arc::new(WireSimulator {
            model,
            registers: Mutex::new(BTreeMap::from([
                (0, 0x1234abcd),
                (8, chains.iter().fold(0, |mask, chain| mask | (1 << chain))),
                (0x3c, 0xc0c0c0c0),
                (0x34, 0xa5a50000),
            ])),
            chains,
            claimed: AtomicBool::new(false),
            asics: Mutex::new(BTreeMap::new()),
            sensors: Mutex::new(BTreeMap::new()),
            assigned: Mutex::new(BTreeMap::new()),
            fifo: Mutex::new(VecDeque::new()),
            pending_registers: Mutex::new(VecDeque::new()),
            replies: Mutex::new(VecDeque::new()),
            frame: Mutex::new(Vec::new()),
            dma: Mutex::new(vec![0; DMA_BYTES]),
            factory,
            fault: AtomicU32::new(0),
            fan_index: AtomicU32::new(0),
            automatic: AtomicU32::new(0),
            ticks: AtomicU32::new(0),
            dac: AtomicU32::new(0),
            high: AtomicBool::new(false),
            overflow: AtomicBool::new(false),
            asic_thread: Mutex::new(None),
            emitted_jobs: Mutex::new(Vec::new()),
            work,
            events: Mutex::new(Vec::new()),
            hold: AtomicU32::new(0),
            held: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        let owner = Transport::observe(hardware.clone(), model, hardware.chains.clone()).await?;
        let line = gpio::open_simulated_source_line(
            owner.clone(),
            hardware.clone(),
            Instant::now() + Duration::from_secs(5),
        )
        .await?;
        let pic = PicApplication::claim(owner.clone())?;
        Ok(Self {
            hardware,
            owner,
            line,
            pic,
        })
    }
}
