//! Exact held-byte admission profiles for the two legacy four-chain Zynq
//! Antminer S19 variants — the BM1360 S19i (NBS2003, 2021-04-27) and the
//! BM1398S S19a (BHB28611, 2022-12-06) — per the R13/R14 profile doctrine
//! (campaign `2026-09-07-antminer-beta-execution`, lane R17). Pure and
//! no-I/O: this module admits and refuses; it never opens a UART, touches
//! a PSU GPIO, or grants electrical authority.
//!
//! ## Held sources (fresh SHA-256, this lane, 2026-09-11)
//!
//! | datum | held bytes |
//! |---|---|
//! | S19i production image |  — `compile_time` "Antminer S19i / Release", Tue Apr 27 23:04:17 CST 2021 |
//! | S19i miner binary | `.../s19i-20210427/components/minerfs.image.gz.tree/usr/bin/bmminer` — 392,380 B, SHA-256 `f8c69038f5937252666c36c78e9d1a659e68cb05dd727665a7580664c286250e`, carries `driver-btm-bm1360.c` (the only bm1x marker string) |
//! | S19i first-party topology | `.../s19i-20210427/components/minerfs.image.gz.tree/etc/topol.conf` — 624 lines, SHA-256 `700ebd31038001f0a4b015cb84b94266816514c64a5efccca0dc5ff6ab74855f` |
//! | S19a production image |  — `compile_time` "Antminer S19a / Release / Parallel", Tue Dec 6 18:30:57 CST 2022 |
//! | S19a miner binary | `.../s19a-20221206/components/minerfs.image.gz.tree/usr/bin/bmminer` — 396,472 B (hash in `evidence/r17/SOURCE_NOTE.md`) |
//! | S19a first-party topology | `.../s19a-20221206/components/minerfs.image.gz.tree/etc/topol.conf` — SHA-256 `01ef73a6f358ba0407368d660487ade792297805e29675ae13e97f71936b809d` |
//! | S19i carrier | `.../s19i-20210427/components/devicetree.dtb` — `xlnx,zynq-7000` (`ps7-*` nodes, `ps7-nand`); topol `processor.type = "ZYNQ7007"` |
//!
//! These are the same class of first-party evidence as R07's S19
//! `NBS1902 = 76/chain x3` topol.conf pin: stock Bitmain's own machine
//! declaration, not a marketing-suffix inference (findings.md row
//! "S19+/a/a Pro/i": "trace the held S19i production binary rather than
//! aliasing BM1398").
//!
//! ## What the bytes prove (verbatim `topol.conf` fields)
//!
//! | field | S19i | S19a |
//! |---|---|---|
//! | `machine` | `NBS2003` | `BHB28611` |
//! | `asic.asic_id` | `BM1360` | `BM1398S` |
//! | `asic.asic_addr` | `0x1360` | `0x1398` |
//! | `asic_core_num` | 156 | 156 |
//! | `asic_small_core_num` | 624 | 623 |
//! | `chain.chain_num` | **4** | **4** |
//! | `chain_row` x `chain_column` | 8 x 10 | 9 x 8 |
//! | `chain_asic_num` | 80 | 72 |
//! | `domain_asic_num` / `chain_domain_num` | 2 / 40 | 8 / 9 |
//! | `asic_addr_interval` | 3 | 3 |
//! | `power.type` | `AWP12` (sic — APW12) | `AWP12` |
//! | `power.version[]` | 66, 67, 113 | 67, 113, 116, 117, 118 |
//! | `power.i2c_addr` / `gpio` | 16 (0x10) / 907 | 16 (0x10) / 907 |
//! | `pic.type` / `i2c_addr` | `PIC1704` / 32 (0x20) | `PIC1704` / 32 |
//! | PIC `sensor[]` | 4x `LM75A` iic 72..75 | 4x `LM75A` iic 72..75 |
//! | `eeprom` | `AT24C02D` @ 80 (0x50) | `AT24C02D` @ 80 |
//!
//! `set_Voltage_S9_plus_plus`-era voltage DAC work, nonce/work codec,
//! per-bin population behavior (`NBS2001`, `NBS2001L`, `NBS2003`,
//! `NBS2003L` strings exist in the S19i bmminer) and the hashboard EEPROM
//! page layout are NOT traced by this lane: those facets stay
//! [`FacetStatus::Unproven`] and no runtime is claimed. What is
//! implemented is the exact admission contract only — the same
//! "admission target without a runtime route/power claim" posture R14
//! holds for S21+.

/// S19i board target for the F02/Lead row registration (proposed in
/// `evidence/r17/SOURCE_NOTE.md`; no `board_desc` row is landed here).
pub const S19I_BOARD_TARGET: &str = "am2-s19i";

/// S19a board target (same posture).
pub const S19A_BOARD_TARGET: &str = "am2-s19a";

/// Per-facet evidence status (R13/R14 doctrine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FacetStatus {
    /// First-party stock topology bytes (`topol.conf` in the held signed
    /// production image) state the datum.
    FirstPartyHeldTopology,
    /// A held production binary states the datum (symbol/string-level).
    HeldBinaryDeclared,
    /// No held bytes; capture-first. Never inferred from a sibling model.
    Unproven,
}

/// Exact per-variant profile. Geometry/power-topology fields are
/// first-party; everything else is facet-scoped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19LegacyZynqProfile {
    /// Campaign board target string ([`S19I_BOARD_TARGET`] /
    /// [`S19A_BOARD_TARGET`]).
    pub board_target: &'static str,
    /// Marketing model of the held image.
    pub marketing_model: &'static str,
    /// `topol.conf` `machine` string.
    pub machine: &'static str,
    /// `topol.conf` `asic.asic_id` — byte-exact silicon identity string.
    /// The S19a is `BM1398S`, a distinct identity from plain `BM1398`.
    pub asic_id: &'static str,
    /// `topol.conf` `asic.asic_addr` (ChipID the auto-detect keys on).
    pub asic_addr: u16,
    /// `topol.conf` `asic_core_num`.
    pub asic_core_num: u16,
    /// `topol.conf` `asic_small_core_num`.
    pub asic_small_core_num: u16,
    /// `topol.conf` `chain.chain_num` — both variants are FOUR-chain
    /// machines (the datum that breaks any 3-chain aliasing).
    pub chains: u8,
    /// `topol.conf` `chain.chain_asic_num`.
    pub chips_per_chain: u16,
    /// `topol.conf` `chain.chain_row` x `chain.chain_column`.
    pub chain_grid: (u8, u8),
    /// `topol.conf` `chain.domain_asic_num`.
    pub domain_asic_num: u8,
    /// `topol.conf` `asic.asic_addr_interval`.
    pub address_interval: u8,
    /// Held `topol.conf` SHA-256 (lowercase hex).
    pub topol_sha256: &'static str,
    /// PIC facet: both variants declare `PIC1704` at i2c 0x20 in
    /// `topol.conf`; the PIC wire dialect is not traced here.
    pub pic_i2c_addr: u8,
    /// Hashboard EEPROM facet: `AT24C02D` at i2c 0x50 per `topol.conf`.
    pub eeprom_i2c_addr: u8,
    /// PSU controller version set declared by `topol.conf` `power.version`.
    pub psu_versions: &'static [u8],
    /// PSU control GPIO declared by `topol.conf` `power.gpio`.
    pub psu_gpio: u16,
    /// PSU controller i2c address declared by `topol.conf`.
    pub psu_i2c_addr: u8,
    /// Runtime work/nonce codec facet: not traced by this lane.
    pub work_codec: FacetStatus,
    /// PSU voltage law facet: version set is first-party; the command law
    /// is unproven here (never inherited from APW12 lanes R12/R13).
    pub psu_voltage_law: FacetStatus,
    /// Cooling facet: 4 fans declared for S19i; control law unproven.
    pub cooling: FacetStatus,
    /// Install/storage facet: unproven (no NAND analysis this lane).
    pub install: FacetStatus,
}

impl S19LegacyZynqProfile {
    /// Full-unit population implied by the first-party geometry
    /// (`chains x chips_per_chain`).
    pub const fn chips_per_unit(&self) -> u32 {
        (self.chains as u32) * (self.chips_per_chain as u32)
    }
}

/// S19i: machine NBS2003, BM1360 @ 0x1360, 4 chains x 80 chips (8x10
/// grid, 2 chips/domain, 40 domains/chain), address interval 3.
/// 4 x 80 = 320 chips per unit.
pub const S19I_PROFILE: S19LegacyZynqProfile = S19LegacyZynqProfile {
    board_target: S19I_BOARD_TARGET,
    marketing_model: "Antminer S19i",
    machine: "NBS2003",
    asic_id: "BM1360",
    asic_addr: 0x1360,
    asic_core_num: 156,
    asic_small_core_num: 624,
    chains: 4,
    chips_per_chain: 80,
    chain_grid: (8, 10),
    domain_asic_num: 2,
    address_interval: 3,
    topol_sha256: "700ebd31038001f0a4b015cb84b94266816514c64a5efccca0dc5ff6ab74855f",
    pic_i2c_addr: 0x20,
    eeprom_i2c_addr: 0x50,
    psu_versions: &[66, 67, 113],
    psu_gpio: 907,
    psu_i2c_addr: 0x10,
    work_codec: FacetStatus::Unproven,
    psu_voltage_law: FacetStatus::Unproven,
    cooling: FacetStatus::Unproven,
    install: FacetStatus::Unproven,
};

/// S19a: machine BHB28611, BM1398S @ 0x1398, 4 chains x 72 chips (9x8
/// grid, 8 chips/domain, 9 domains/chain), address interval 3.
/// 4 x 72 = 288 chips per unit.
pub const S19A_PROFILE: S19LegacyZynqProfile = S19LegacyZynqProfile {
    board_target: S19A_BOARD_TARGET,
    marketing_model: "Antminer S19a",
    machine: "BHB28611",
    asic_id: "BM1398S",
    asic_addr: 0x1398,
    asic_core_num: 156,
    asic_small_core_num: 623,
    chains: 4,
    chips_per_chain: 72,
    chain_grid: (9, 8),
    domain_asic_num: 8,
    address_interval: 3,
    topol_sha256: "01ef73a6f358ba0407368d660487ade792297805e29675ae13e97f71936b809d",
    pic_i2c_addr: 0x20,
    eeprom_i2c_addr: 0x50,
    psu_versions: &[67, 113, 116, 117, 118],
    psu_gpio: 907,
    psu_i2c_addr: 0x10,
    work_codec: FacetStatus::Unproven,
    psu_voltage_law: FacetStatus::Unproven,
    cooling: FacetStatus::Unproven,
    install: FacetStatus::Unproven,
};

/// Profile-resolution errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyS19ProfileError {
    /// Board target has no legacy-four-chain profile.
    UnknownBoardTarget,
    /// Hashboard name is not the machine/board identity the held bytes
    /// declare (a marketing suffix never selects a profile).
    UnknownBoardName,
    /// Observed per-chain population differs from the first-party datum
    /// by even one chip.
    ChipCountMismatch {
        expected: u16,
        observed: u16,
    },
    /// Observed chain count differs from the first-party four.
    ChainCountMismatch {
        expected: u8,
        observed: u8,
    },
}

/// Resolve + admit a legacy four-chain S19 profile from an observed
/// board target, machine/board identity, chain count and per-chain chip
/// population. Every input must match the held first-party bytes; the
/// S19a identity string must be `BM1398S` exactly (plain `BM1398` never
/// selects it — "marketing suffix is not a silicon identifier", and the
/// converse: silicon strings are not interchangeable).
pub fn admit_legacy_s19(
    board_target: &str,
    machine: &str,
    chains: u8,
    chips_per_chain: u16,
) -> Result<&'static S19LegacyZynqProfile, LegacyS19ProfileError> {
    let profile = match board_target {
        S19I_BOARD_TARGET => &S19I_PROFILE,
        S19A_BOARD_TARGET => &S19A_PROFILE,
        _ => return Err(LegacyS19ProfileError::UnknownBoardTarget),
    };
    if machine != profile.machine {
        return Err(LegacyS19ProfileError::UnknownBoardName);
    }
    if chains != profile.chains {
        return Err(LegacyS19ProfileError::ChainCountMismatch {
            expected: profile.chains,
            observed: chains,
        });
    }
    if chips_per_chain != profile.chips_per_chain {
        return Err(LegacyS19ProfileError::ChipCountMismatch {
            expected: profile.chips_per_chain,
            observed: chips_per_chain,
        });
    }
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // First-party geometry pins (verbatim topol.conf fields).
    // ------------------------------------------------------------------

    #[test]
    fn s19i_geometry_is_first_party_exact() {
        assert_eq!(S19I_PROFILE.machine, "NBS2003");
        assert_eq!(S19I_PROFILE.asic_id, "BM1360");
        assert_eq!(S19I_PROFILE.asic_addr, 0x1360);
        assert_eq!(S19I_PROFILE.asic_core_num, 156);
        assert_eq!(S19I_PROFILE.asic_small_core_num, 624);
        assert_eq!(S19I_PROFILE.chains, 4);
        assert_eq!(S19I_PROFILE.chips_per_chain, 80);
        assert_eq!(S19I_PROFILE.chain_grid, (8, 10));
        assert_eq!(S19I_PROFILE.domain_asic_num, 2);
        assert_eq!(S19I_PROFILE.address_interval, 3);
        assert_eq!(S19I_PROFILE.chips_per_unit(), 320);
    }

    #[test]
    fn s19a_geometry_is_first_party_exact() {
        assert_eq!(S19A_PROFILE.machine, "BHB28611");
        assert_eq!(S19A_PROFILE.asic_id, "BM1398S");
        assert_eq!(S19A_PROFILE.asic_addr, 0x1398);
        assert_eq!(S19A_PROFILE.asic_core_num, 156);
        assert_eq!(S19A_PROFILE.asic_small_core_num, 623);
        assert_eq!(S19A_PROFILE.chains, 4);
        assert_eq!(S19A_PROFILE.chips_per_chain, 72);
        assert_eq!(S19A_PROFILE.chain_grid, (9, 8));
        assert_eq!(S19A_PROFILE.domain_asic_num, 8);
        assert_eq!(S19A_PROFILE.address_interval, 3);
        assert_eq!(S19A_PROFILE.chips_per_unit(), 288);
    }

    #[test]
    fn psu_topology_pins_are_first_party() {
        assert_eq!(S19I_PROFILE.psu_versions, &[66, 67, 113]);
        assert_eq!(S19A_PROFILE.psu_versions, &[67, 113, 116, 117, 118]);
        for p in [&S19I_PROFILE, &S19A_PROFILE] {
            assert_eq!(p.psu_gpio, 907);
            assert_eq!(p.psu_i2c_addr, 0x10);
            assert_eq!(p.pic_i2c_addr, 0x20);
            assert_eq!(p.eeprom_i2c_addr, 0x50);
            assert_eq!(p.psu_voltage_law, FacetStatus::Unproven);
            assert_eq!(p.work_codec, FacetStatus::Unproven);
            assert_eq!(p.cooling, FacetStatus::Unproven);
            assert_eq!(p.install, FacetStatus::Unproven);
        }
    }

    #[test]
    fn topol_source_pins_are_carried() {
        assert_eq!(
            S19I_PROFILE.topol_sha256,
            "700ebd31038001f0a4b015cb84b94266816514c64a5efccca0dc5ff6ab74855f"
        );
        assert_eq!(
            S19A_PROFILE.topol_sha256,
            "01ef73a6f358ba0407368d660487ade792297805e29675ae13e97f71936b809d"
        );
    }

    // ------------------------------------------------------------------
    // Admission: positive + every refusal case.
    // ------------------------------------------------------------------

    #[test]
    fn exact_observations_admit() {
        assert_eq!(
            admit_legacy_s19("am2-s19i", "NBS2003", 4, 80),
            Ok(&S19I_PROFILE)
        );
        assert_eq!(
            admit_legacy_s19("am2-s19a", "BHB28611", 4, 72),
            Ok(&S19A_PROFILE)
        );
    }

    #[test]
    fn unknown_targets_refused() {
        assert_eq!(
            admit_legacy_s19("am2-s19", "NBS2003", 4, 80),
            Err(LegacyS19ProfileError::UnknownBoardTarget)
        );
        assert_eq!(
            admit_legacy_s19("am2-s19pro", "NBP1901", 3, 114),
            Err(LegacyS19ProfileError::UnknownBoardTarget)
        );
        assert_eq!(
            admit_legacy_s19("am3-s19k", "BHB56902", 3, 77),
            Err(LegacyS19ProfileError::UnknownBoardTarget)
        );
    }

    #[test]
    fn wrong_machine_identity_refused() {
        // A 3-chain S19 Pro machine identity never selects the S19i row,
        // and the S19a machine is not interchangeable.
        assert_eq!(
            admit_legacy_s19("am2-s19i", "BHB28611", 4, 80),
            Err(LegacyS19ProfileError::UnknownBoardName)
        );
        assert_eq!(
            admit_legacy_s19("am2-s19a", "NBS2003", 4, 72),
            Err(LegacyS19ProfileError::UnknownBoardName)
        );
    }

    #[test]
    fn off_by_one_population_refused() {
        assert_eq!(
            admit_legacy_s19("am2-s19i", "NBS2003", 4, 81),
            Err(LegacyS19ProfileError::ChipCountMismatch {
                expected: 80,
                observed: 81
            })
        );
        assert_eq!(
            admit_legacy_s19("am2-s19a", "BHB28611", 4, 71),
            Err(LegacyS19ProfileError::ChipCountMismatch {
                expected: 72,
                observed: 71
            })
        );
    }

    #[test]
    fn three_chain_alias_refused() {
        // The load-bearing refusal: no lane may alias these four-chain
        // machines onto a three-chain sibling row.
        assert_eq!(
            admit_legacy_s19("am2-s19i", "NBS2003", 3, 80),
            Err(LegacyS19ProfileError::ChainCountMismatch {
                expected: 4,
                observed: 3
            })
        );
        assert_eq!(
            admit_legacy_s19("am2-s19a", "BHB28611", 3, 72),
            Err(LegacyS19ProfileError::ChainCountMismatch {
                expected: 4,
                observed: 3
            })
        );
    }

    // ------------------------------------------------------------------
    // Identity-distinctness pins.
    // ------------------------------------------------------------------

    #[test]
    fn s19a_is_not_a_plain_bm1398_row() {
        // The held identity string is BM1398S with its own asic_core /
        // domain layout; it never inherits a BM1398 (NBP1901/NBS1902)
        // runtime or population claim.
        assert_ne!(S19A_PROFILE.asic_id, "BM1398");
        assert_eq!(S19A_PROFILE.asic_id, "BM1398S");
        assert_ne!(S19A_PROFILE.asic_core_num, 114); // NBP1901 3x114 core ctx
        assert_ne!(S19A_PROFILE.chains, 3);
    }

    #[test]
    fn s19i_is_not_a_bm1398_alias() {
        assert_eq!(S19I_PROFILE.asic_id, "BM1360");
        assert_ne!(S19I_PROFILE.asic_addr, 0x1398);
        // The two legacy rows are distinct platforms from each other.
        assert_ne!(S19I_PROFILE.machine, S19A_PROFILE.machine);
        assert_ne!(S19I_PROFILE.chips_per_unit(), S19A_PROFILE.chips_per_unit());
    }
}
