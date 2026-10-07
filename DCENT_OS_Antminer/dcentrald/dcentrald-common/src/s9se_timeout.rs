//! S9 SE stock timeout + working-baud facts (desk-only).
//!
//! `set_timeout@2455C`:
//! `timeout = percent * (addrInterval * (16777216 / calculate_core_number(cores)) / freq) / 100`
//! then FPGA ` (opt_multi_version * timeout) & 0x1FFFF | 0x80000000 `.
//! `bitmain_soc_init` calls `set_timeout(max_freq, 50)`.
//! `set_working_uart_baud` is `set_baud(1, 1)`.
//! This module does not write `TIME_OUT_CONTROL`.

use crate::s9se_enum::S9SE_ADDR_INTERVAL;
use crate::s9se_job::TIMEOUT_ENABLE;
use crate::s9se_job::TIMEOUT_MASK;

/// `calculate_core_number` maps 129..=208 → 256.
pub const TIMEOUT_CORE_CEILING: u16 = 256;
/// `set_timeout(..., 50)` from `bitmain_soc_init`.
pub const STOCK_TIMEOUT_PERCENT: u32 = 50;
/// `set_working_uart_baud` → `set_baud(1u, 1)`.
pub const WORKING_BAUDDIV: u8 = 1;
/// Default MISC baud field before `set_working_uart_baud`.
pub const DEFAULT_BAUDDIV: u8 = crate::s9se_regs::DEFAULT_BAUDDIV;
/// `.data ticket_mask` in unstripped S9k `cgminer` (`0x3f`).
pub const DEFAULT_TICKET_MASK: u32 = 0x3F;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeTimeoutError {
    UnsupportedCoreCount { cores: u16 },
    ZeroFrequency,
    TimeoutIoRefused,
}

/// Exact `calculate_core_number` for the 208-core BM1393 path.
pub fn calculate_core_number(actual_cores: u16) -> Result<u32, S9SeTimeoutError> {
    match actual_cores {
        1 => Ok(1),
        2 => Ok(2),
        3..=4 => Ok(4),
        5..=8 => Ok(8),
        9..=16 => Ok(16),
        17..=32 => Ok(32),
        33..=64 => Ok(64),
        65..=128 => Ok(128),
        129..=208 => Ok(u32::from(TIMEOUT_CORE_CEILING)),
        other => Err(S9SeTimeoutError::UnsupportedCoreCount { cores: other }),
    }
}

/// S9 SE `calculate_asic_number` is the same ceiling table.
pub fn calculate_asic_number(actual: u16) -> Result<u32, S9SeTimeoutError> {
    calculate_core_number(actual)
}

/// Integer stock timeout (not a FPGA write).
pub fn stock_timeout(
    freq_mhz: u32,
    percent: u32,
    addr_interval: u8,
    cores: u16,
) -> Result<u32, S9SeTimeoutError> {
    if freq_mhz == 0 {
        return Err(S9SeTimeoutError::ZeroFrequency);
    }
    let core_n = calculate_core_number(cores)?;
    let span = 16_777_216 / core_n;
    Ok(percent * (u32::from(addr_interval) * span / freq_mhz) / 100)
}

pub fn stock_timeout_s9se(freq_mhz: u32) -> Result<u32, S9SeTimeoutError> {
    stock_timeout(freq_mhz, STOCK_TIMEOUT_PERCENT, S9SE_ADDR_INTERVAL, 208)
}

/// `set_time_out_control` word. Not a write permit.
pub fn timeout_control_word(timeout: u32, version_num: u32) -> u32 {
    (version_num.saturating_mul(timeout) & TIMEOUT_MASK) | TIMEOUT_ENABLE
}

pub fn refuse_s9se_timeout_io() -> Result<(), S9SeTimeoutError> {
    Err(S9SeTimeoutError::TimeoutIoRefused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_hundred_eight_cores_ceil_to_256_and_timeout_is_integer() {
        assert_eq!(calculate_core_number(208).unwrap(), 256);
        assert_eq!(calculate_asic_number(60).unwrap(), 64);
        // 50 * (4 * (16777216/256) / 400) / 100 = 327 (integer operations).
        assert_eq!(stock_timeout_s9se(400).unwrap(), 327);
        assert_eq!(timeout_control_word(327, 1), 327 | 0x8000_0000);
        assert_eq!(WORKING_BAUDDIV, 1);
        assert_eq!(DEFAULT_TICKET_MASK, 0x3F);
        assert_eq!(
            refuse_s9se_timeout_io(),
            Err(S9SeTimeoutError::TimeoutIoRefused)
        );
        assert!(stock_timeout_s9se(0).is_err());
    }
}
