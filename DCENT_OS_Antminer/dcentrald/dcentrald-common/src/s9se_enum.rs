//! S9 SE / S9k production address-assignment program.
//!
//! Both held S9 SE production ELFs and S9k `init_address_info` explicitly
//! store interval four and 208 cores. The old interval-two hypothesis from
//! issue #2 is source-refuted: see campaign evidence/r03 production captures.
//! Classic `am1-s9` remains a distinct 63-chip BM1387 composition.
//!
//! This module builds the *sequence of frames*. It does not write BC
//! buffers and does not treat enum as mining.

use crate::s9se_vil::{pack_chain_inactive_vil, pack_set_address_vil};
use crate::serial_chain_proof::{
    ChainCoverageCertificate, ChainCoverageError, PacedEnumerationPolicy,
};

pub const S9SE_CHIPS_PER_CHAIN: u8 = 60;
pub const S9SE_ADDR_INTERVAL: u8 = 4;
/// An address in the historical operator experiment; not the production last ASIC.
pub const S9SE_LAST_CHIP_ADDR_CAPTURED: u8 = 0x78;
/// Production `for i in 0..60 { i * 4 }` last populated address.
pub const S9SE_LAST_CHIP_ADDR_START_AT_ZERO: u8 = 0xec;
pub const S9SE_LAST_CHIP_ADDR: u8 = S9SE_LAST_CHIP_ADDR_START_AT_ZERO;
/// Both production models use the same assignment interval.
pub const S9K_ADDR_INTERVAL: u8 = 4;
/// Stock emits 256/interval assignment slots; only 60 are populated.
pub const S9SE_ASSIGNMENT_SLOTS: u8 = 64;
/// Classic S9 chip count — refuse as S9 SE geometry.
pub const AM1_S9_CHIPS_PER_CHAIN: u8 = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeEnumError {
    WrongInterval { observed: u8 },
    ChipCountIsAm1S9,
    LastAddrMismatch { observed: u8 },
    GeometryMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S9SeAddressProgram {
    pub inactive: [u8; 5],
    pub set_address: Vec<[u8; 5]>,
    pub pacing: Option<PacedEnumerationPolicy>,
}

impl S9SeAddressProgram {
    pub fn expected_addresses(&self) -> Vec<u8> {
        self.set_address.iter().map(|frame| frame[2]).collect()
    }

    pub fn certify_coverage(
        &self,
        observed: &[u8],
    ) -> Result<ChainCoverageCertificate, ChainCoverageError> {
        ChainCoverageCertificate::certify(&self.expected_addresses(), observed)
    }
}

/// `for i in 0..chips { i * interval }` last address.
pub fn last_chip_addr_start_at_zero(chips: u8, interval: u8) -> u16 {
    u16::from(chips.saturating_sub(1)) * u16::from(interval)
}

/// `for i in 1..=chips { i * interval }` last address (`60*2 = 0x78`).
pub fn last_chip_addr_start_at_interval(chips: u8, interval: u8) -> u16 {
    u16::from(chips) * u16::from(interval)
}

pub fn admit_s9se_geometry(chips: u8, interval: u8, last: u8) -> Result<(), S9SeEnumError> {
    admit_s9se_production_interval(interval)?;
    if chips == AM1_S9_CHIPS_PER_CHAIN {
        return Err(S9SeEnumError::ChipCountIsAm1S9);
    }
    if chips != S9SE_CHIPS_PER_CHAIN || interval != S9SE_ADDR_INTERVAL {
        return Err(S9SeEnumError::GeometryMismatch);
    }
    if last != S9SE_LAST_CHIP_ADDR {
        return Err(S9SeEnumError::LastAddrMismatch { observed: last });
    }
    Ok(())
}

pub fn admit_s9se_production_interval(interval: u8) -> Result<(), S9SeEnumError> {
    if interval != S9SE_ADDR_INTERVAL {
        return Err(S9SeEnumError::WrongInterval { observed: interval });
    }
    Ok(())
}

pub fn refuse_am1_s9_chip_count(chips: u8) -> Result<(), S9SeEnumError> {
    if chips == AM1_S9_CHIPS_PER_CHAIN {
        return Err(S9SeEnumError::ChipCountIsAm1S9);
    }
    Ok(())
}

/// `chain_inactive` then `set_address` for each chip. Not a live enum.
pub fn plan_s9se_address_program() -> Result<S9SeAddressProgram, S9SeEnumError> {
    admit_s9se_geometry(
        S9SE_CHIPS_PER_CHAIN,
        S9SE_ADDR_INTERVAL,
        S9SE_LAST_CHIP_ADDR,
    )?;
    // Expected populated addresses, separately from the stock 64-slot command
    // sequence. Exact unique post-assignment replies must cover all 60 entries.
    let mut set_address = Vec::with_capacity(usize::from(S9SE_CHIPS_PER_CHAIN));
    for i in 0..S9SE_CHIPS_PER_CHAIN {
        let addr = i.saturating_mul(S9SE_ADDR_INTERVAL);
        set_address.push(pack_set_address_vil(addr));
    }
    Ok(S9SeAddressProgram {
        inactive: pack_chain_inactive_vil(),
        set_address,
        pacing: None,
    })
}

/// Bind a caller-selected nonzero pacing policy to the exact desk program.
/// No S19k cadence is inherited into BM1393 by default.
pub fn plan_s9se_paced_address_program(
    pacing: PacedEnumerationPolicy,
) -> Result<S9SeAddressProgram, S9SeEnumError> {
    let mut plan = plan_s9se_address_program()?;
    plan.pacing = Some(pacing);
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_geometry_is_zero_through_236_at_stride_four() {
        admit_s9se_geometry(60, 4, 0xec).unwrap();
        assert_eq!(last_chip_addr_start_at_zero(60, 4), 0xec);
        assert_eq!(last_chip_addr_start_at_interval(60, 4), 0xf0);
        for (chips, interval, last) in [(60, 2, 0x78), (60, 2, 0x76), (60, 4, 0xf0), (63, 4, 0xf8)]
        {
            assert!(admit_s9se_geometry(chips, interval, last).is_err());
        }
    }

    #[test]
    fn s9k_production_interval_is_shared_but_s9_count_is_distinct() {
        assert_eq!(
            admit_s9se_production_interval(2),
            Err(S9SeEnumError::WrongInterval { observed: 2 })
        );
        admit_s9se_production_interval(S9K_ADDR_INTERVAL).unwrap();
        assert_eq!(
            refuse_am1_s9_chip_count(63),
            Err(S9SeEnumError::ChipCountIsAm1S9)
        );
        refuse_am1_s9_chip_count(60).unwrap();
    }

    #[test]
    fn address_program_is_inactive_plus_60_set_address() {
        let plan = plan_s9se_address_program().unwrap();
        assert_eq!(plan.inactive[0], 0x53);
        assert_eq!(plan.set_address.len(), 60);
        assert_eq!(plan.set_address[0][2], 0);
        assert_eq!(plan.set_address[59][2], 0xec);
        assert_eq!(plan.set_address[59][0], 0x40);
        assert!(plan.certify_coverage(&plan.expected_addresses()).is_ok());
        assert!(plan
            .certify_coverage(&plan.expected_addresses()[..59])
            .is_err());
    }
}
