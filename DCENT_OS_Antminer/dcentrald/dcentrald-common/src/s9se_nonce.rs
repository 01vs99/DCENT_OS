//! S9 SE stock nonce classify (desk-only).
//!
//! `nonce_calc@2214E`: core = low 8 bits; chip = `HIBYTE(buf) / addrInterval`.
//! Valid only when `chain<=15`, `chip<=59`, `core<=207`, `buf!=0`.
//! This module does not consume the FPGA nonce FIFO.

#[cfg(test)]
use crate::s9se_enum::S9SE_ADDR_INTERVAL;
use crate::s9se_enum::S9SE_CHIPS_PER_CHAIN;

pub const NONCE_CORE_MAX: u8 = 207;
pub const NONCE_CHAIN_MAX: u8 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9SeNoncePlace {
    pub chain: u8,
    pub chip: u8,
    pub core: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeNonceError {
    ZeroNonce,
    ChainOutOfRange { chain: u8 },
    ChipOutOfRange { chip: u8 },
    CoreOutOfRange { core: u8 },
    FifoIoRefused,
}

pub fn classify_s9se_nonce(
    chain: u8,
    buf: u32,
    addr_interval: u8,
) -> Result<S9SeNoncePlace, S9SeNonceError> {
    if buf == 0 {
        return Err(S9SeNonceError::ZeroNonce);
    }
    if chain > NONCE_CHAIN_MAX {
        return Err(S9SeNonceError::ChainOutOfRange { chain });
    }
    if addr_interval == 0 {
        return Err(S9SeNonceError::ChipOutOfRange { chip: 0 });
    }
    let chip = ((buf >> 24) as u8) / addr_interval;
    let core = buf as u8;
    if chip >= S9SE_CHIPS_PER_CHAIN {
        return Err(S9SeNonceError::ChipOutOfRange { chip });
    }
    if core > NONCE_CORE_MAX {
        return Err(S9SeNonceError::CoreOutOfRange { core });
    }
    Ok(S9SeNoncePlace { chain, chip, core })
}

pub fn refuse_s9se_nonce_fifo_io() -> Result<(), S9SeNonceError> {
    Err(S9SeNonceError::FifoIoRefused)
}

/// FPGA return FIFO pair from `get_return_nonce` (`axi[4]`, `axi[5]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeFifoRecord {
    Register {
        chain: u8,
        chip: u8,
        reg: u8,
        crc5: u8,
        value: u32,
        crc_error: bool,
    },
    Nonce {
        chain: u8,
        work_id: u16,
        nonce3: u32,
    },
}

/// `get_nonce_and_register`: bit31 clear → register; bit31+bit7 → nonce.
pub fn classify_return_record(buf0: u32, buf1: u32) -> Option<S9SeFifoRecord> {
    if buf0 & 0x8000_0000 == 0 {
        Some(S9SeFifoRecord::Register {
            chain: (buf0 & 0xF) as u8,
            chip: ((buf0 >> 16) & 0xFF) as u8,
            reg: ((buf0 >> 8) & 0xFF) as u8,
            crc5: ((buf0 >> 24) & 0x1F) as u8,
            value: buf1,
            crc_error: buf0 & 0x40 != 0,
        })
    } else if buf0 & 0x80 != 0 {
        Some(S9SeFifoRecord::Nonce {
            chain: (buf0 & 0xF) as u8,
            work_id: ((buf0 >> 16) & 0x7FFF) as u16,
            nonce3: buf1,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_hibyte_div_interval_is_chip() {
        let buf = (u32::from(59 * S9SE_ADDR_INTERVAL) << 24) | 207;
        let place = classify_s9se_nonce(2, buf, S9SE_ADDR_INTERVAL).unwrap();
        assert_eq!(place.chain, 2);
        assert_eq!(place.chip, 59);
        assert_eq!(place.core, 207);
        assert!(classify_s9se_nonce(2, 0, 2).is_err());
        assert!(classify_s9se_nonce(2, (60 * 4) << 24 | 1, 4).is_err());
        assert_eq!(
            refuse_s9se_nonce_fifo_io(),
            Err(S9SeNonceError::FifoIoRefused)
        );
        let nonce = classify_return_record(0x8000_0082, 0xAABB_CCDD).unwrap();
        assert_eq!(
            nonce,
            S9SeFifoRecord::Nonce {
                chain: 2,
                work_id: 0,
                nonce3: 0xAABB_CCDD
            }
        );
        let reg = classify_return_record(0x0512_3402, 0x1111_2222).unwrap();
        match reg {
            S9SeFifoRecord::Register {
                chain,
                chip,
                reg,
                crc5,
                value,
                crc_error,
            } => {
                assert_eq!(chain, 2);
                assert_eq!(chip, 0x12);
                assert_eq!(reg, 0x34);
                assert_eq!(crc5, 5);
                assert_eq!(value, 0x1111_2222);
                assert!(!crc_error);
            }
            _ => panic!("expected register"),
        }
    }
}
