//! C501 flat-MMIO device model for the actual S15/T15 native coordinator.
//! Only built with sim-hal (which makes the common build ineligible for release).
//! It models byte/register responses, never startup/thermal/cutoff receipts.
//! Protocol follows the neighboring source-backed HAL and its R04 wire fixtures.
use super::*;
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    SourceHigh,
    SourceLow,
    Write(u32, u32),
    Command { chain: u8, bytes: [u8; 12] },
    Work([u32; 13]),
    Return(u32, u32),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Fault {
    #[default]
    None,
    EepromCrc,
    ForeignChip,
    BadWorkNonce,
    Fan,
}

/// Caller supplies independently reconstructed known-header wire material.
/// Matching is exact across all eleven tail/midstate words before a nonce is
/// returned. The real CPU qualifier and independent pool still check the hash.
#[derive(Clone)]
pub struct ExpectedWork {
    pub tail_and_midstate: [u32; 11],
    pub canonical_nonce: u32,
}

struct State {
    words: BTreeMap<u32, u32>,
    commands: [u32; 3],
    returns: VecDeque<(u32, u32)>,
    misc: BTreeMap<(u8, u8), u32>,
    bridge: BTreeMap<(u8, u8), u32>,
    sensor_config: BTreeMap<(u8, u8), u8>,
    pic_frames: [Vec<u8>; 3],
    pic_returns: [VecDeque<u8>; 3],
    partial_work: Vec<u32>,
    events: Vec<Event>,
    tach_cursor: u8,
    pin_high: bool,
    fault: Fault,
}

struct ModeledRegisters {
    model: Model,
    pid: u32,
    claimed: AtomicBool,
    pin_claimed: AtomicBool,
    expected: Vec<ExpectedWork>,
    state: Mutex<State>,
}

pub struct Rig {
    registers: Arc<ModeledRegisters>,
}
impl Rig {
    pub fn new(model: Model, expected: Vec<ExpectedWork>, fault: Fault) -> Self {
        Self {
            registers: Arc::new(ModeledRegisters {
                model,
                pid: std::process::id(),
                claimed: AtomicBool::new(false),
                pin_claimed: AtomicBool::new(false),
                expected,
                state: Mutex::new(State {
                    words: [(COMMAND_CONTROL, 0x0010_501a)].into_iter().collect(),
                    commands: [0; 3],
                    returns: VecDeque::new(),
                    misc: BTreeMap::new(),
                    bridge: BTreeMap::new(),
                    sensor_config: BTreeMap::new(),
                    pic_frames: std::array::from_fn(|_| Vec::new()),
                    pic_returns: std::array::from_fn(|_| VecDeque::new()),
                    partial_work: Vec::new(),
                    events: Vec::new(),
                    tach_cursor: 0,
                    pin_high: true,
                    fault,
                }),
            }),
        }
    }

    /// Exact simulated model plus the production DMA-tree validator. No /dev,
    /// sysfs, native mapping or real fabric is opened by this constructor.
    pub fn open_transport(
        &self,
        model: Model,
        tree: &Path,
    ) -> Result<Arc<Transport<NativeMmio>>, String> {
        if model != self.registers.model {
            return Err("modeled BM1391 exact model differs".into());
        }
        let dma = DmaReservation::observe_kernel_tree(tree)?;
        self.registers.claim_transport()?;
        let native = Arc::new(NativeMmio {
            backing: MmioBacking::Simulated(self.registers.clone()),
            model,
            dma,
            transport_claimed: AtomicBool::new(false),
        });
        let presence = native.read(PRESENCE)?;
        Transport::new(
            native,
            (0..3)
                .filter(|chain| presence & (1 << chain) != 0)
                .collect(),
        )
    }

    pub fn open_line(
        &self,
        owner: Arc<Transport<NativeMmio>>,
        deadline: Instant,
    ) -> Result<Arc<PowerLine<NativeMmio>>, String> {
        let expected: Arc<dyn Registers> = self.registers.clone();
        if !matches!(&owner.registers.backing, MmioBacking::Simulated(actual) if Arc::ptr_eq(actual, &expected))
        {
            return Err("modeled BM1391 GPIO belongs to a different transport".into());
        }
        self.registers
            .pin_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "modeled BM1391 source pin already claimed")?;
        PowerLine::from_simulated_pin(
            owner,
            Box::new(ModeledPin(self.registers.clone())),
            deadline,
        )
    }

    pub fn events(&self) -> Vec<Event> {
        self.registers.state.lock().unwrap().events.clone()
    }
    pub fn source_high(&self) -> bool {
        self.registers.state.lock().unwrap().pin_high
    }
    pub fn inject(&self, fault: Fault) {
        self.registers.state.lock().unwrap().fault = fault;
    }
}

struct ModeledPin(Arc<ModeledRegisters>);
impl gpio::Pin for ModeledPin {
    fn high(&self) -> Result<(), String> {
        self.0.validate_owner()?;
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| "modeled GPIO state poisoned")?;
        state.pin_high = true;
        state.events.push(Event::SourceHigh);
        Ok(())
    }
    fn low(&self) -> Result<(), String> {
        self.0.validate_owner()?;
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| "modeled GPIO state poisoned")?;
        state.pin_high = false;
        state.events.push(Event::SourceLow);
        Ok(())
    }
    fn observed_high(&self) -> Result<bool, String> {
        self.0.validate_owner()?;
        Ok(self
            .0
            .state
            .lock()
            .map_err(|_| "modeled GPIO state poisoned")?
            .pin_high)
    }
}

fn page(model: Model, fault: Fault) -> [u8; 256] {
    let mut page = [0; 256];
    page[0] = 0x7e;
    page[0x79] = 1; // Original source-supported thermal topology, not a minted sensor receipt.
    let revision = if model == Model::T15 {
        0x0100_u16
    } else {
        0x0101
    };
    page[250..252].copy_from_slice(&revision.to_be_bytes());
    let crc = dcentrald_common::bm1391_stock_work::bm1391_stock_job_crc16(&page[..254]);
    page[254..].copy_from_slice(&crc.to_le_bytes());
    if fault == Fault::EepromCrc {
        page[254] ^= 1;
    }
    page
}

fn register_return(chain: u8, address: u8, register: u8, value: u32) -> (u32, u32) {
    let mut packet = [0; 7];
    packet[..4].copy_from_slice(&value.to_be_bytes());
    packet[4] = address;
    packet[5] = register;
    let crc = dcentrald_common::s9se_vil::crc5_bits(&packet, 51);
    (
        (u32::from(crc) << 24)
            | (u32::from(address) << 16)
            | (u32::from(register) << 8)
            | u32::from(chain),
        value,
    )
}

impl Registers for ModeledRegisters {
    fn model(&self) -> Option<Model> {
        Some(self.model)
    }
    fn validate_owner(&self) -> Result<(), String> {
        if std::process::id() != self.pid {
            return Err("modeled BM1391 owner crossed a process".into());
        }
        Ok(())
    }
    fn claim_transport(&self) -> Result<(), String> {
        self.validate_owner()?;
        claim_mapping_transport(&self.claimed)
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        self.validate_owner()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "modeled BM1391 state poisoned")?;
        Ok(match offset {
            VERSION => 0xc501,
            PRESENCE | WORK_SPACE => 7,
            4 => {
                let id = state.tach_cursor % 2;
                state.tach_cursor = state.tach_cursor.wrapping_add(1);
                (u32::from(id) << 8) | if state.fault == Fault::Fan { 0 } else { 10 }
            }
            RETURN_COUNT => state.returns.len() as u32,
            RETURN0 => {
                state
                    .returns
                    .front()
                    .ok_or("modeled return FIFO is empty")?
                    .0
            }
            RETURN1 => {
                let pair = state
                    .returns
                    .pop_front()
                    .ok_or("modeled return FIFO is empty")?;
                state.events.push(Event::Return(pair.0, pair.1));
                pair.1
            }
            0x30 => {
                let word = *state
                    .words
                    .get(&0x30)
                    .ok_or("management read without a byte command")?;
                let byte = if word & 0xfff0_0000 == 0x03a0_0000 {
                    page(self.model, state.fault)[((word >> 8) & 255) as usize]
                } else if word & 0xfff0_0000 == 0x0240_0000 {
                    let selector = ((word >> 16) & 7) as usize;
                    state
                        .pic_returns
                        .get_mut(selector)
                        .ok_or("foreign modeled PIC selector")?
                        .pop_front()
                        .ok_or("PIC reply read without its actual complete request")?
                } else {
                    0
                };
                0x8000_0000 | u32::from(byte)
            }
            0x110 => return Err("original BM1391 +110 has no readback ABI".into()),
            _ => state.words.get(&offset).copied().unwrap_or(0),
        })
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.validate_owner()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "modeled BM1391 state poisoned")?;
        if state.events.len() >= 200_000 {
            return Err("modeled BM1391 observation bound exceeded".into());
        }
        state.events.push(Event::Write(offset, value));
        state.words.insert(
            offset,
            if offset == COMMAND_CONTROL {
                value & !0x8000_0000
            } else {
                value
            },
        );
        match offset {
            COMMAND_BUFFER..=0xcc => {
                state.commands[((offset - COMMAND_BUFFER) / 4) as usize] = value
            }
            COMMAND_CONTROL if value & 0x8000_0000 != 0 => {
                let frame: [u8; 12] =
                    std::array::from_fn(|i| state.commands[i / 4].to_be_bytes()[i % 4]);
                let chain = ((value >> 16) & 15) as u8;
                self.command(&mut state, chain, frame)?;
            }
            0x30 => {
                let kind = value & 0xfff0_0000;
                if !matches!(kind, 0x03a0_0000 | 0x0040_0000 | 0x0240_0000 | 0x0520_0000) {
                    return Err("unrecognized/EEPROM-write management command".into());
                }
                if kind == 0x0040_0000 {
                    let selector = ((value >> 16) & 7) as usize;
                    let bytes = state
                        .pic_frames
                        .get_mut(selector)
                        .ok_or("foreign modeled PIC selector")?;
                    bytes.push(value as u8);
                    if bytes.len() > 7 {
                        return Err("modeled PIC frame exceeds its bound".into());
                    }
                    if bytes.len() >= 3 && bytes.len() == usize::from(bytes[2]) + 2 {
                        let response: &[u8] = match bytes.as_slice() {
                            [0x55, 0xaa, 4, 0x16, 0, 0x1a] => &[0, 0x16, 1, 0, 0, 0],
                            [0x55, 0xaa, 5, 0x15, 0, 0, 0x1a]
                            | [0x55, 0xaa, 5, 0x15, 1, 0, 0x1b] => &[0x15, 1],
                            _ => {
                                return Err(
                                    "unrecognized/destructive modeled PIC application frame".into(),
                                )
                            }
                        };
                        bytes.clear();
                        if !state.pic_returns[selector].is_empty() {
                            return Err("PIC request overwrote unread reply".into());
                        }
                        state.pic_returns[selector].extend(response);
                    }
                }
            }
            TW_FIRST => {
                if !state.partial_work.is_empty() {
                    return Err("partial stock TW frame overwritten".into());
                }
                state.partial_work.push(value);
            }
            TW_NEXT => {
                if state.partial_work.is_empty() {
                    return Err("stock TW continuation without first word".into());
                }
                state.partial_work.push(value);
                if state.partial_work.len() == 13 {
                    let frame: [u32; 13] = state.partial_work.as_slice().try_into().unwrap();
                    state.partial_work.clear();
                    state.events.push(Event::Work(frame));
                    if frame[0] & 0xfff0_ffff == 0x0180_0000 {
                        if let Some(proof) = self
                            .expected
                            .iter()
                            .find(|proof| proof.tail_and_midstate == frame[2..])
                        {
                            let nonce = proof.canonical_nonce
                                ^ u32::from(state.fault == Fault::BadWorkNonce);
                            state.returns.push_back((
                                0x8000_0080 | ((frame[0] >> 16) & 15) | (frame[1] << 16),
                                nonce.swap_bytes(),
                            ));
                        }
                    } else if frame[0] & 0xfff0_ffff != 0x0100_0080
                        || frame[1..].iter().any(|word| *word != 0)
                    {
                        return Err("unrecognized stock TW opcode or dummy payload".into());
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
}

impl ModeledRegisters {
    fn command(&self, state: &mut State, chain: u8, frame: [u8; 12]) -> Result<(), String> {
        if chain > 2 {
            return Err("modeled command is outside selected stock chains".into());
        }
        let length = match frame[1] {
            5 => 4,
            9 => 8,
            _ => return Err("invalid modeled ASIC frame length".into()),
        };
        if frame[length]
            != dcentrald_common::s9se_vil::crc5_bits(&frame[..length], (length * 8) as u32)
            || frame[length + 1..].iter().any(|byte| *byte != 0)
        {
            return Err("invalid modeled ASIC frame CRC/padding".into());
        }
        state.events.push(Event::Command {
            chain,
            bytes: frame,
        });
        let address = frame[2];
        let register = frame[3];
        let key = (chain, address);
        match frame[0] {
            0x53 | 0x40 => (), // Real owner emits and tests inspect inactive/address sequences.
            0x51 | 0x41 => {
                let value = u32::from_be_bytes(frame[4..8].try_into().unwrap());
                match register {
                    0x18 if frame[0] == 0x51 => {
                        for index in 0..self.model.expected_chips() {
                            state
                                .misc
                                .insert((chain, index * self.model.address_interval()), value);
                        }
                    }
                    0x18 => {
                        state.misc.insert(key, value);
                    }
                    0x1c => {
                        let sensor_register = frame[6];
                        let data = if frame[5] & 1 != 0 {
                            state.sensor_config.insert(key, frame[7]);
                            frame[7]
                        } else if frame[5] != 0x98 {
                            0
                        } else {
                            match sensor_register {
                                0xfe => 0x55,
                                9 => *state.sensor_config.get(&key).unwrap_or(&0),
                                0 => 0x64, // Extended local PCB36C, estimated chip51C.
                                _ => return Err("unexpected modeled sensor register".into()),
                            }
                        };
                        state
                            .bridge
                            .insert(key, (u32::from(sensor_register) << 8) | u32::from(data));
                    }
                    0 | 8 | 0x14 | 0x3c | 0x70 | 0x74 | 0x60 | 0x78 | 0x64 | 0x7c | 0x68 => (),
                    _ => return Err("unrecognized modeled ASIC register write".into()),
                }
            }
            0x52 | 0x42 => {
                let addresses: Vec<_> = if frame[0] == 0x52 {
                    (0..self.model.expected_chips())
                        .map(|index| index * self.model.address_interval())
                        .collect()
                } else {
                    vec![address]
                };
                for address in addresses {
                    let key = (chain, address);
                    let value = match register {
                        0 => {
                            (if state.fault == Fault::ForeignChip {
                                0x1393_0000
                            } else {
                                0x1391_0000
                            }) | u32::from(address)
                        }
                        0x18 => *state.misc.get(&key).unwrap_or(&0x3a01),
                        0x1c => *state.bridge.get(&key).unwrap_or(&0),
                        _ => return Err("unrecognized modeled ASIC register request".into()),
                    };
                    state
                        .returns
                        .push_back(register_return(chain, address, register, value));
                }
            }
            _ => return Err("unrecognized modeled ASIC command".into()),
        }
        Ok(())
    }
}
