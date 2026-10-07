//! S9 SE desk-only bring-up planner.
//!
//! Sequence is reconstructed from S9k `set_addr_one_chain` /
//! `check_asic_num` / `open_core_bm1393` plus both held S9 SE production
//! `init_address_info` routines: interval four, 60 populated chips.

use crate::asic_protocol::{InitProgram, InitStep};
use crate::s9se_enum::{
    plan_s9se_address_program, S9SE_ADDR_INTERVAL, S9SE_CHIPS_PER_CHAIN, S9SE_LAST_CHIP_ADDR,
};
use crate::s9se_regs::pack_enable_core_clock;
use crate::s9se_vil::pack_chain_inactive_vil;
#[cfg(test)]
use crate::s9se_work::DHASH_MODE_RAW_TW;
use crate::s9se_work::VIL_TW_WORDS;

/// S9k `check_asic_num`: success is `chain_asic_num == 60`.
pub const EXPECTED_ASICS_PER_CHAIN: u8 = 60;
/// `set_addr_one_chain` fires `chain_inactive` three times.
pub const INACTIVE_PULSES: u8 = 3;
/// Delay between inactive pulses (`cgsleep_ms(30)`).
pub const INACTIVE_GAP_MS: u32 = 30;
/// Delay after each `set_address` (`cgsleep_ms(50)`).
pub const SET_ADDRESS_GAP_MS: u32 = 50;
/// `open_core_bm1393` banks.
pub const OPEN_CORE_SLOTS: u8 = 4;
pub const OPEN_CORE_PER_SLOT: u8 = 52;
/// First VIL TW word during open-core: `(chain << 16) | 0x1000080`.
pub const OPEN_CORE_TW0_BASE: u32 = 0x0100_0080;
/// DHASH bits around open-core (`| 0x8000`, clear 0x20).
pub const OPEN_CORE_DHASH_OR: u32 = 0x8000;
/// `open_core_BM1393_pre_open(chain, 13u, 1u)` during `bring_up_chain`.
pub const PRE_OPEN_CORE_COUNT: u8 = 13;
/// `bitmain_soc_init` 256 MiB PHY (`Detect 256MB control board of XILINX`).
pub const PHY_MEM_NONCE2_JOBID_256MIB: u32 = 0x0F00_0000;
/// S9 SE stripped `cgminer` log string (later CE than S9k `2f40e5d`).
pub const S9SE_CGMINER_COMMIT: &str = "9df023c";
pub const S9SE_CGMINER_COMMIT_TIME: &str = "2019-07-25 12:01:46";
pub const S9SE_CGMINER_BUILD_TIME: &str = "2019-07-28 21:25:53";

/// Named `bring_up_chain` / `bitmain_soc_init` steps. Planning only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeBringUpStep {
    Select256MibPhyMem,
    SetDhashRawTw,
    InitAddressInfo,
    SetDefaultUartBaud,
    PowerOrReset,
    CheckAsicNum,
    SetAddress,
    SetFreqByChain,
    PreOpenCores { count: u8 },
    CalibrateSensor { device: u8 },
    SetWorkingUartBaud,
    SetIicForTemperature,
    SetAsicTicketMask,
    DetectEnvironmentTemperature,
    SetClockDelayControl,
    OpenCoreBm1393,
    ClimbToWorkingVoltage,
    SetTimeout,
}

/// `bring_up_chain` then the post-enum `bitmain_soc_init` tail used on T11.
pub fn s9se_stock_bringup_order() -> [S9SeBringUpStep; 18] {
    [
        S9SeBringUpStep::Select256MibPhyMem,
        S9SeBringUpStep::SetDhashRawTw,
        S9SeBringUpStep::InitAddressInfo,
        S9SeBringUpStep::SetDefaultUartBaud,
        S9SeBringUpStep::PowerOrReset,
        S9SeBringUpStep::CheckAsicNum,
        S9SeBringUpStep::SetAddress,
        S9SeBringUpStep::SetFreqByChain,
        S9SeBringUpStep::PreOpenCores {
            count: PRE_OPEN_CORE_COUNT,
        },
        S9SeBringUpStep::CalibrateSensor { device: 152 },
        S9SeBringUpStep::SetWorkingUartBaud,
        S9SeBringUpStep::SetIicForTemperature,
        S9SeBringUpStep::SetAsicTicketMask,
        S9SeBringUpStep::DetectEnvironmentTemperature,
        S9SeBringUpStep::SetClockDelayControl,
        S9SeBringUpStep::OpenCoreBm1393,
        S9SeBringUpStep::ClimbToWorkingVoltage,
        S9SeBringUpStep::SetTimeout,
    ]
}

pub fn admit_stock_bringup_order() -> Result<(), S9SeInitError> {
    let order = s9se_stock_bringup_order();
    if order[0] != S9SeBringUpStep::Select256MibPhyMem {
        return Err(S9SeInitError::GeometryMismatch);
    }
    if PHY_MEM_NONCE2_JOBID_256MIB != 0x0F00_0000 {
        return Err(S9SeInitError::GeometryMismatch);
    }
    match order[8] {
        S9SeBringUpStep::PreOpenCores { count } if count == PRE_OPEN_CORE_COUNT => {}
        _ => return Err(S9SeInitError::GeometryMismatch),
    }
    match order[9] {
        S9SeBringUpStep::CalibrateSensor { device } if device == 152 => {}
        _ => return Err(S9SeInitError::GeometryMismatch),
    }
    if order[15] != S9SeBringUpStep::OpenCoreBm1393 {
        return Err(S9SeInitError::GeometryMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeInitError {
    ExecuteRefused,
    GeometryMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S9SeOpenCorePlan {
    pub core_enable_frames: Vec<[u8; 9]>,
    pub tw_words: usize,
    pub tw0_base: u32,
}

/// Declarative init intent. No I/O.
pub fn s9se_init_program() -> InitProgram {
    InitProgram {
        steps: vec![
            InitStep::SoftReset,
            InitStep::DelayMs(INACTIVE_GAP_MS),
            InitStep::EnumerateAtBaud {
                baud_label: "default-uart",
            },
            InitStep::AssignAddresses {
                chip_count: S9SE_CHIPS_PER_CHAIN,
            },
        ],
    }
}

pub fn admit_expected_asic_count(count: u8) -> Result<(), S9SeInitError> {
    if count != EXPECTED_ASICS_PER_CHAIN {
        return Err(S9SeInitError::GeometryMismatch);
    }
    Ok(())
}

/// Plan 3× inactive + 60 set_address. Not a live enum.
pub fn plan_s9se_enum_pulses() -> Result<[[u8; 5]; 3], S9SeInitError> {
    admit_expected_asic_count(S9SE_CHIPS_PER_CHAIN)?;
    let inactive = pack_chain_inactive_vil();
    Ok([inactive, inactive, inactive])
}

pub fn plan_s9se_open_core() -> Result<S9SeOpenCorePlan, S9SeInitError> {
    if u16::from(OPEN_CORE_SLOTS) * u16::from(OPEN_CORE_PER_SLOT) != 208 {
        return Err(S9SeInitError::GeometryMismatch);
    }
    let mut frames = Vec::with_capacity(208);
    // Production opens the same position in all four banks, then emits
    // one dummy work record before moving to the next position.
    for core_id in 0..OPEN_CORE_PER_SLOT {
        for slot in 0..OPEN_CORE_SLOTS {
            let idx = slot * OPEN_CORE_PER_SLOT + core_id;
            frames.push(pack_enable_core_clock(idx));
        }
    }
    Ok(S9SeOpenCorePlan {
        core_enable_frames: frames,
        tw_words: VIL_TW_WORDS,
        tw0_base: OPEN_CORE_TW0_BASE,
    })
}

pub fn open_core_tw0(chain: u8) -> u32 {
    (u32::from(chain) << 16) | OPEN_CORE_TW0_BASE
}

/// `pre_open_core_one_chain`: four banks `i`, `i+52`, `i+104`, `i-100` as u8.
pub fn pre_open_core_ids(num: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(usize::from(num) * 4);
    for i in 0..num {
        out.push(i);
        out.push(i.saturating_add(52));
        out.push(i.saturating_add(104));
        out.push(i.wrapping_sub(100));
    }
    out
}

pub fn plan_s9se_pre_open() -> Result<Vec<[u8; 9]>, S9SeInitError> {
    let ids = pre_open_core_ids(PRE_OPEN_CORE_COUNT);
    Ok(ids.into_iter().map(pack_enable_core_clock).collect())
}

/// No executor. Planning is not a bring-up permit.
pub fn refuse_s9se_init_execute() -> Result<(), S9SeInitError> {
    Err(S9SeInitError::ExecuteRefused)
}

pub fn admit_address_program_matches_capture() -> Result<(), S9SeInitError> {
    let plan = plan_s9se_address_program().map_err(|_| S9SeInitError::GeometryMismatch)?;
    if plan.set_address.len() != usize::from(S9SE_CHIPS_PER_CHAIN) {
        return Err(S9SeInitError::GeometryMismatch);
    }
    if plan.set_address[59][2] != S9SE_LAST_CHIP_ADDR {
        return Err(S9SeInitError::GeometryMismatch);
    }
    if S9SE_ADDR_INTERVAL != 4 {
        return Err(S9SeInitError::GeometryMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_asic_num_expects_60() {
        admit_expected_asic_count(60).unwrap();
        assert!(admit_expected_asic_count(63).is_err());
        let pulses = plan_s9se_enum_pulses().unwrap();
        assert_eq!(pulses.len(), 3);
        assert!(pulses.iter().all(|p| p[0] == 0x53));
    }

    #[test]
    fn open_core_is_208_enable_frames() {
        let plan = plan_s9se_open_core().unwrap();
        assert_eq!(plan.core_enable_frames.len(), 208);
        assert_eq!(plan.tw_words, 13);
        assert_eq!(open_core_tw0(2), 0x0002_0000 | 0x0100_0080);
        assert_eq!(
            refuse_s9se_init_execute(),
            Err(S9SeInitError::ExecuteRefused)
        );
        admit_address_program_matches_capture().unwrap();
        assert!(!s9se_init_program().is_empty());
        let _ = DHASH_MODE_RAW_TW;
        let _ = OPEN_CORE_DHASH_OR;
    }

    #[test]
    fn stock_bringup_order_is_256mib_then_enum_then_preopen_13() {
        admit_stock_bringup_order().unwrap();
        assert_eq!(S9SE_CGMINER_COMMIT, "9df023c");
        assert_eq!(PRE_OPEN_CORE_COUNT, 13);
        assert_eq!(PHY_MEM_NONCE2_JOBID_256MIB, 0x0F00_0000);
        let ids = pre_open_core_ids(13);
        assert_eq!(ids.len(), 52);
        assert_eq!(ids[0], 0);
        assert_eq!(ids[3], 156);
        assert_eq!(ids[51], 12u8.wrapping_sub(100));
        assert_eq!(plan_s9se_pre_open().unwrap().len(), 52);
    }
}
