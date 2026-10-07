// Wire fixture for the existing FifoModel. All framing, initialization,
// admission, ledger and submission run the actual C43 owners above this seam.
// The literal factory CRC and genesis words are independent of their encoders.
const C43_GENESIS_WORDS: [u32; 11] = [
    0xffff001d, 0x29ab5f49, 0x4b1e5e4a, 0x4719f91b, 0x96b18736, 0x4f0103c8, 0xc3c8d8e9, 0x1e59caa8,
    0x90ccac7d, 0x6358bff0, 0xbc909a33,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeFault {
    None,
    FactoryCrc,
    PicAck,
    MissingChip,
    MixedChip,
    SensorAck,
}
struct NativeRegisters {
    fault: NativeFault,
    chains: Vec<u8>,
    factory: [u8; 256],
    registers: BTreeMap<u32, u32>,
    pic_frame: Vec<u8>,
    pic_reply: VecDeque<u8>,
    returns: VecDeque<[u32; 2]>,
    partial: Vec<u32>,
    assigned: [Vec<u8>; 3],
    sensors: BTreeMap<(u8, u8), u32>,
    enabled: [bool; 3],
    heartbeats: [usize; 3],
    factory_reads: [usize; 3],
    work: Vec<[u32; 13]>,
    dummy_count: [usize; 3],
    fan_cursor: u32,
}
impl NativeRegisters {
    fn new(chains: Vec<u8>, fault: NativeFault) -> Self {
        let mut factory = [0; 256];
        factory[1] = 180;
        factory[121..127].copy_from_slice(&[1, 2, 31, 251, 40, 252]);
        factory[248] = 32;
        factory[254..].copy_from_slice(&[0x9c, 0x45]); // CRC16/Modbus of the fixed payload.
        if fault == NativeFault::FactoryCrc {
            factory[254] ^= 1;
        }
        Self {
            fault,
            chains,
            factory,
            registers: BTreeMap::new(),
            pic_frame: Vec::new(),
            pic_reply: VecDeque::new(),
            returns: VecDeque::new(),
            partial: Vec::new(),
            assigned: Default::default(),
            sensors: BTreeMap::new(),
            enabled: [false; 3],
            heartbeats: [0; 3],
            factory_reads: [0; 3],
            work: Vec::new(),
            dummy_count: [0; 3],
            fan_cursor: 0,
        }
    }
    fn read(&mut self, offset: u32) -> std::result::Result<u32, String> {
        Ok(match offset {
            0x04 => {
                self.fan_cursor ^= 1;
                (self.fan_cursor << 8) | 10
            }
            0x08 | 0x0c => self
                .chains
                .iter()
                .fold(0, |mask, chain| mask | (1 << chain)),
            0x10 => self.returns.front().ok_or("empty C43 return metadata")?[0],
            0x14 => self.returns.pop_front().ok_or("empty C43 return payload")?[1],
            0x18 => self.returns.len() as u32,
            _ => *self.registers.get(&offset).unwrap_or(&0),
        })
    }
    fn write(&mut self, offset: u32, value: u32) -> std::result::Result<(), String> {
        match offset {
            0x30 => {
                let address = ((value >> 16) & 7) | (((value >> 20) & 15) << 3);
                let chain = (address & 7) as usize;
                assert!(self.chains.contains(&(chain as u8)));
                let read = value & (1 << 25) != 0;
                let byte = if address & 0x78 == 0x50 {
                    assert!(
                        read && value & (1 << 24) != 0,
                        "factory EEPROM write attempted"
                    );
                    self.factory_reads[chain] += 1;
                    self.factory[((value >> 8) & 255) as usize]
                } else {
                    assert_eq!(address & 0x78, 0x20);
                    if read {
                        self.pic_reply.pop_front().unwrap_or(0)
                    } else {
                        self.pic_byte(chain, value as u8)?;
                        0
                    }
                };
                self.registers.insert(offset, 0x80000000 | u32::from(byte));
            }
            0xc0 => {
                self.registers.insert(offset, value & !0x80800000);
                if value & 0x80000000 != 0 {
                    self.asic(((value >> 16) & 15) as u8)?;
                }
            }
            0x40 => {
                assert!(self.partial.is_empty());
                self.partial.push(value);
            }
            0x44 => {
                self.partial.push(value);
                if self.partial.len() == 13 {
                    let frame: [u32; 13] = std::mem::take(&mut self.partial).try_into().unwrap();
                    let chain = ((frame[0] >> 16) & 15) as usize;
                    assert!(self.enabled[chain], "work reached an unpowered chain");
                    if frame[0] == 0x01800000 | ((chain as u32) << 16) {
                        assert!(
                            self.work.len() < 24,
                            "native fixture permits only one feeder batch"
                        );
                        if frame[2..] == C43_GENESIS_WORDS {
                            self.returns.push_back([
                                0x80000080 | ((frame[1] & 0x7fff) << 16) | chain as u32,
                                0x1dac2b7c,
                            ]);
                        }
                        self.work.push(frame);
                    } else {
                        assert!(frame[1..].iter().all(|w| *w == 0));
                        self.dummy_count[chain] += 1;
                    }
                }
            }
            0x1c | 0x34 | 0x84 | 0x88 | 0x90 | 0xc4 | 0xc8 | 0xcc | 0x100 => {
                self.registers.insert(offset, value);
            }
            _ => return Err(format!("unowned C43 register write {offset:#x}")),
        }
        assert!(self.returns.len() <= 128);
        Ok(())
    }
    fn pic_byte(&mut self, chain: usize, byte: u8) -> std::result::Result<(), String> {
        if self.pic_frame.is_empty() && byte == 0 {
            self.pic_reply.clear();
            return Ok(());
        }
        self.pic_frame.push(byte);
        assert!(self.pic_frame.len() <= 16);
        if self.pic_frame.len() < 3 || self.pic_frame.len() != usize::from(self.pic_frame[2]) + 2 {
            return Ok(());
        }
        let frame = std::mem::take(&mut self.pic_frame);
        assert_eq!(&frame[..2], &[0x55, 0xaa]);
        let end = frame.len() - 2;
        assert_eq!(
            frame[2..end].iter().map(|b| u16::from(*b)).sum::<u16>(),
            u16::from_be_bytes(frame[end..].try_into().unwrap())
        );
        assert!(self.pic_reply.is_empty(), "interleaved PIC transaction");
        self.pic_reply = match frame[3] {
            0x17 => {
                if self.fault == NativeFault::PicAck {
                    vec![5, 0x17, 0, 0, 0x1c]
                } else {
                    vec![5, 0x17, 1, 0, 0x1d]
                }
            }
            0x16 => {
                self.heartbeats[chain] += 1;
                vec![6, 0x16, 1, 0, 0, 0x1d]
            }
            0x15 => {
                assert!(frame[4] <= 1);
                self.enabled[chain] = frame[4] != 0;
                vec![0x15, 1]
            }
            0x10 => {
                assert!(frame[4] < 128);
                vec![0x10, 1]
            }
            other => return Err(format!("unexpected PIC command {other:#x}")),
        }
        .into();
        Ok(())
    }
    fn asic(&mut self, chain: u8) -> std::result::Result<(), String> {
        assert!(self.chains.contains(&chain));
        assert!(self.enabled[usize::from(chain)]);
        assert_eq!(
            self.registers[&0x34] & (1 << chain),
            0,
            "ASIC command while reset asserted"
        );
        let bytes: Vec<_> = (0..3)
            .flat_map(|i| self.registers[&(0xc4 + i * 4)].to_be_bytes())
            .collect();
        let size = usize::from(bytes[1]);
        assert!(matches!(size, 5 | 9));
        // CRC is checked by the production transport before any register write.
        let chip = bytes[2];
        let reg = bytes[3];
        match (bytes[0], reg) {
            (0x40, _) => self.assigned[usize::from(chain)].push(chip),
            (0x52, 0) => {
                assert_eq!(
                    self.assigned[usize::from(chain)],
                    (0..64u8).map(|i| i * 4).collect::<Vec<_>>()
                );
                let count = if self.fault == NativeFault::MissingChip {
                    59
                } else {
                    60
                };
                for index in 0..count {
                    let identity = if self.fault == NativeFault::MixedChip && index == 59 {
                        0x1387
                    } else {
                        0x1393
                    };
                    self.returns
                        .push_back([u32::from(chain) | ((index * 4) << 16), identity << 16]);
                }
            }
            (0x42, 0x1c) => self.returns.push_back([
                u32::from(chain) | (u32::from(chip) << 16) | 0x1c00,
                *self.sensors.get(&(chain, chip)).unwrap_or(&0),
            ]),
            (0x41, 0x1c) => {
                assert_eq!(bytes[4], 1);
                let sensor_reg = bytes[6];
                let write = bytes[5] & 1 != 0;
                let data = if write {
                    if self.fault == NativeFault::SensorAck && sensor_reg == 9 {
                        bytes[7] ^ 1
                    } else {
                        bytes[7]
                    }
                } else {
                    match sensor_reg {
                        0xfe => 0x1a,
                        0 | 1 => 104,
                        _ => return Err("unexpected sensor register".into()),
                    }
                };
                self.sensors.insert(
                    (chain, chip),
                    (u32::from(sensor_reg) << 8) | u32::from(data),
                );
            }
            (0x41 | 0x51 | 0x53, _) => (),
            other => return Err(format!("unexpected C43 ASIC request {other:?}")),
        }
        Ok(())
    }
}
