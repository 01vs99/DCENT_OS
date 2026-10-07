// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-platform profiles for the BM1398 native family (R07, 2026-09-11).
//!
//! One profile per exact vendor-qualified hashboard bin, in the same structure
//! the wired NBP1901 runtime already uses:
//!
//! | bin     | model name | board_target | chips/chain | addr interval | stock ladder                          |
//! |---------|-----------|--------------|-------------|---------------|---------------------------------------|
//! | NBP1901 | S19 Pro   | am2-s19pro   | 114         | 2             | 500/525 MHz @ 12.60/12.80/13.00 V     |
//! | NBS1902 | S19       | am2-s19      | 76          | 3             | 650/675 MHz @ 13.80/14.00/14.20 V     |
//! | NBT1903 | T19       | am2-t19      | 76          | 3             | 550-625 MHz @ 14.00/14.20/14.40 V     |
//!
//! Geometry and ladder sources (each bin's OWN held first-party stock image,
//! <tree>/components/
//! minerfs.image.gz.tree/etc/`):
//!
//! - NBS1902 `topol.conf` (sha256 `59d911b44a5b68177b5f86f46cb187f3fd84a4243
//!   2cdee43f242f62088a5ad11`): `chain_asic_num` 76, `asic_addr_interval` 3,
//!   38 domains x 2, PIC1704 @ 0x20 + 4x LM75A @ 0x48..0x4b, AT24C02D @ 0x50,
//!   AWP12 @ 0x10 gpio 907.
//! - NBT1903 `topol.conf` (sha256 `360af8228ebeb5aadc2f623227aa476ad3d3067d7
//!   caa9cfc70eb688c78b10c98`): same rows under the T19 model; `power.version`
//!   [67,113,116,117,118].
//! - NBP1901 `topol.conf` (sha256 `351f6361abe4ccb68bd93e2e42f6cdebb1b3f4fd15
//!   b8e4e01f7539388bcb8de4`): 114 @ 2, identical controller/PSU endpoints.
//! - Ladders: each bin's `levels.json` (NBP1901 sha256
//!   `64aae4c71e9018087210d5923654c3684b24aa033c85f90e45c307f2f7b9ab3a`;
//!   NBS1902 sha256 `3c4fe0f3559fcab77fa035b1f7f625067383618ce7e2d83dd3bd6469
//!   85c929db`; NBT1903 sha256 `1bb4a6e535edf7e5f48afeab40b1bd4169963eb2cb1143
//!   64de9289bf0f17e1bd`). The common tables
//!   (`dcentrald_common::s19_bm1398_runtime::{NBP1901,NBS1902,NBT1903}_STOCK_LEVELS`)
//!   are the single source; this module only adds config-unit resolution.
//!
//! - S19a `s19a-20221206`: BHB28611, 72 chips, interval3, nine domains
//!   of eight; its own 40-row levels.json is BHB28611_STOCK_LEVELS.
//! - S19+ VNish Xilinx NAND 1.2.6-rc5: BHB28701, 80 chips, interval 3,
//!   ten domains of eight, exact 645 MHz / 14.00 V default. The held hwscan
//!   model/default constructor join is documented in BHB28701_VENDOR_LEVELS.
//!   Its runtime cgminer reads that generated model-info, maps BM1398 to
//!   ASIC id 0x1398 and selects the Xilinx backend before power operations.
//!
//! The selected profile is never an EEPROM observation. Native startup
//! requires an actually decoded exact name and checks every connected slot
//! before energization, then joins a sealed 0x1398 chip response and exact
//! population coverage. Held legacy `11 42` pages have no board-name field;
//! those pages remain useful for diagnostics but refuse this exact-SKU join.
//! Named-page positive tests reconstruct the supported encrypted format;
//! they are not claims of held NBS1902/NBT1903/BHB28611/BHB28701 physical pages.
//!
//! This module is pure (no HAL/IO), included by `s19_bm1398_native_mining.rs`
//! via `#[path]` exactly like its `s19_bm1398_fabric_identity.rs` sibling, so
//! the desk tests can include it by path without the daemon crate.

use dcentrald_api_types::bm1398_protocol::{
    Bm1398BoardGeometry, S19A_BHB28611_BOARD_GEOMETRY, S19_NBS1902_BOARD_GEOMETRY,
    S19_PLUS_BHB28701_BOARD_GEOMETRY, S19_PRO_NBP1901_BOARD_GEOMETRY, T19_NBT1903_BOARD_GEOMETRY,
};
use dcentrald_common::s19_bm1398_runtime::{
    Bm1398FpgaMidstateMode, Bm1398HybridDeskPlan, Bm1398HybridModel,
};
use dcentrald_common::AsicProtocolIdentity;

/// One BM1398 native family member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398Platform {
    /// S19 Pro — NBP1901 bin (the wired September 2 lane).
    S19Pro,
    /// S19 classic — NBS1902 bin (76/chain, interval 3).
    S19Classic,
    /// T19 — NBT1903 bin (76/chain, interval 3).
    T19,
    /// S19a — exact BHB28611 BM1398S topology (72/chain, interval 3).
    S19a,
    /// S19+ exact BHB28701 VNish rc5 profile, 80 chips at interval 3.
    S19Plus,
}

impl Bm1398Platform {
    /// Every admitted family member. Anything else refuses at admission.
    pub const ALL: [Bm1398Platform; 5] = [
        Self::S19Pro,
        Self::S19Classic,
        Self::T19,
        Self::S19a,
        Self::S19Plus,
    ];

    /// Exact admission join for the native dispatch: the board target must be
    /// a registered family member AND the dispatch identity must be exactly
    /// BM1398. No board target aliases, no family-prefix matching.
    pub fn from_admission(
        board_target: &str,
        identity: AsicProtocolIdentity,
    ) -> Result<Self, String> {
        if identity != AsicProtocolIdentity::Bm1398 {
            return Err(format!(
                "dispatch identity {identity:?} is not BM1398; the native family admits only exact BM1398 dispatch"
            ));
        }
        match board_target {
            "am2-s19pro" => Ok(Self::S19Pro),
            "am2-s19" => Ok(Self::S19Classic),
            "am2-t19" => Ok(Self::T19),
            "am2-s19a" => Ok(Self::S19a),
            "am2-s19plus" => Ok(Self::S19Plus),
            other => Err(format!(
                "board target {other:?} is not a BM1398 native family member (am2-s19pro/am2-s19/am2-t19/am2-s19a/am2-s19plus)"
            )),
        }
    }

    /// The `/etc/dcentos/board_target` marker this platform runs as.
    pub const fn board_target(self) -> &'static str {
        self.model().board_target()
    }

    /// The common-crate model enum (single source for geometry/ladder/identity).
    pub const fn model(self) -> Bm1398HybridModel {
        match self {
            Self::S19Pro => Bm1398HybridModel::S19Pro,
            Self::S19Classic => Bm1398HybridModel::S19Classic,
            Self::T19 => Bm1398HybridModel::T19,
            Self::S19a => Bm1398HybridModel::S19a,
            Self::S19Plus => Bm1398HybridModel::S19Plus,
        }
    }

    /// The first-party geometry row (`bm1398_protocol`) this platform must
    /// enumerate to. Counts are exact stock `chain_asic_num` values.
    pub const fn geometry(self) -> Bm1398BoardGeometry {
        match self {
            Self::S19Pro => S19_PRO_NBP1901_BOARD_GEOMETRY,
            Self::S19Classic => S19_NBS1902_BOARD_GEOMETRY,
            Self::T19 => T19_NBT1903_BOARD_GEOMETRY,
            Self::S19a => S19A_BHB28611_BOARD_GEOMETRY,
            Self::S19Plus => S19_PLUS_BHB28701_BOARD_GEOMETRY,
        }
    }

    pub const fn chips_per_chain(self) -> u16 {
        self.model().chips_per_chain()
    }

    pub const fn address_interval(self) -> u8 {
        self.model().address_interval()
    }

    /// Stock board names accepted as this platform's factory identity.
    pub const fn stock_board_names(self) -> &'static [&'static str] {
        self.model().stock_board_names()
    }

    /// Exact stock (MHz, centivolts) pairs from the bin's own levels.json.
    pub fn stock_ladder(self) -> &'static [(u16, u16)] {
        self.model().stock_levels()
    }

    /// Zero-config default operating point (all values are real ladder rows).
    pub const fn default_operating_point(self) -> (u16, u16) {
        self.model().default_operating_point()
    }

    /// Resolve the configured operating point against the platform ladder.
    ///
    /// Config units match the daemon config surface: `frequency_mhz` in MHz
    /// and `voltage_mv` in MILLIVOLTS (the wired NBP1901 runtime maps
    /// 12600/12800/13000 mV onto its 1260/1280/1300 centivolt ladder).
    ///
    /// Two regimes, deliberately:
    /// - **NBP1901 keeps the WIRED clamp semantics byte-exact** (round-1
    ///   repair: this is the historical am2-s19pro run() behavior — 0 -> 500,
    ///   <500 refuses, 500..=524 -> 500, 525.. -> 525; then any
    ///   (rung, rung) pair admits because its ladder is the full cross
    ///   product). Behavior-preserving, never weakened.
    /// - **NBS1902/NBT1903 are exact-rung only.** They have no wired
    ///   precedent, so no clamp band is invented: the requested frequency
    ///   must be an exact rung of THIS bin's own held levels.json ladder and
    ///   the resolved pair must be a row of that same table. A wrong-bin
    ///   frequency (e.g. 675 on NBT1903) is a REFUSAL, never a silent
    ///   substitution of another rung or another bin's operating point.
    ///
    /// Voltage is exact in both regimes (0 selects the bin default, which is
    /// itself a real ladder row).
    pub fn resolve_operating_point(
        self,
        frequency_mhz: u16,
        voltage_mv: u16,
    ) -> Result<(u16, u16), String> {
        let ladder = self.stock_ladder();
        let mut rungs: Vec<u16> = ladder.iter().map(|(f, _)| *f).collect();
        rungs.sort_unstable();
        rungs.dedup();
        let default = self.default_operating_point();
        let frequency = if frequency_mhz == 0 {
            default.0
        } else if matches!(self, Self::S19Pro) {
            // Wired NBP1901 semantics, byte-exact (see doc above).
            if frequency_mhz < rungs[0] {
                return Err(format!("{self} stock ladder starts at {} MHz", rungs[0]));
            }
            *rungs
                .iter()
                .filter(|&&rung| rung <= frequency_mhz)
                .last()
                .expect("frequency_mhz >= lowest rung guarantees a rung")
        } else {
            // NBS1902/NBT1903: exact rung of this bin's own ladder only.
            if !rungs.contains(&frequency_mhz) {
                return Err(format!(
                    "{self} stock ladder frequencies are exactly {rungs:?} MHz; {frequency_mhz} MHz is not a rung of this bin"
                ));
            }
            frequency_mhz
        };
        let voltage_cv = match voltage_mv {
            0 => default.1,
            mv if mv % 10 != 0 => {
                return Err(format!(
                    "{self} voltage must be a whole rung of the stock ladder in millivolts"
                ))
            }
            mv => mv / 10,
        };
        if !ladder.contains(&(frequency, voltage_cv)) {
            return Err(format!(
                "{self} operating point must select a row of the stock {frequency}-{voltage_cv} ladder band"
            ));
        }
        Ok((frequency, voltage_cv))
    }

    /// The desk plan for this platform on the shared four-midstate FPGA
    /// carrier, with the retained paced enumeration policy.
    pub fn desk_plan(
        self,
        enumeration: dcentrald_common::serial_chain_proof::PacedEnumerationPolicy,
        midstate_mode: Bm1398FpgaMidstateMode,
    ) -> Bm1398HybridDeskPlan {
        Bm1398HybridDeskPlan::for_model(self.model(), enumeration, midstate_mode)
    }
}

impl std::fmt::Display for Bm1398Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (label, board) = match self {
            Self::S19Pro => ("NBP1901", "am2-s19pro"),
            Self::S19Classic => ("NBS1902", "am2-s19"),
            Self::T19 => ("NBT1903", "am2-t19"),
            Self::S19a => ("BHB28611", "am2-s19a"),
            Self::S19Plus => ("BHB28701", "am2-s19plus"),
        };
        write!(f, "{label}/{board}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> dcentrald_common::serial_chain_proof::PacedEnumerationPolicy {
        dcentrald_common::serial_chain_proof::PacedEnumerationPolicy::new(
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(10),
            2,
        )
        .unwrap()
    }

    #[test]
    fn family_admission_is_exact_target_and_exact_identity() {
        assert_eq!(
            Bm1398Platform::from_admission("am2-s19pro", AsicProtocolIdentity::Bm1398),
            Ok(Bm1398Platform::S19Pro)
        );
        assert_eq!(
            Bm1398Platform::from_admission("am2-s19", AsicProtocolIdentity::Bm1398),
            Ok(Bm1398Platform::S19Classic)
        );
        assert_eq!(
            Bm1398Platform::from_admission("am2-t19", AsicProtocolIdentity::Bm1398),
            Ok(Bm1398Platform::T19)
        );
        for wrong_target in [
            "am2-s19j",
            "am2-s19jpro-zynq",
            "am3-s19k",
            "am2-s19pro-x",
            "am2-t19 ",
            "",
        ] {
            assert!(
                Bm1398Platform::from_admission(wrong_target, AsicProtocolIdentity::Bm1398).is_err()
            );
        }
        for wrong_identity in [
            AsicProtocolIdentity::Bm1362,
            AsicProtocolIdentity::Bm1397,
            AsicProtocolIdentity::Bm1393,
            AsicProtocolIdentity::RuntimeDiscovered,
        ] {
            assert!(
                Bm1398Platform::from_admission("am2-s19", wrong_identity).is_err(),
                "{wrong_identity:?} must never admit the BM1398 family"
            );
        }
    }

    #[test]
    fn geometry_rows_are_the_first_party_pins() {
        assert_eq!(
            Bm1398Platform::S19Pro.geometry(),
            S19_PRO_NBP1901_BOARD_GEOMETRY
        );
        assert_eq!(
            Bm1398Platform::S19Classic.geometry(),
            S19_NBS1902_BOARD_GEOMETRY
        );
        assert_eq!(Bm1398Platform::T19.geometry(), T19_NBT1903_BOARD_GEOMETRY);
        for (platform, chips, interval) in [
            (Bm1398Platform::S19Pro, 114, 2),
            (Bm1398Platform::S19Classic, 76, 3),
            (Bm1398Platform::T19, 76, 3),
            (Bm1398Platform::S19a, 72, 3),
            (Bm1398Platform::S19Plus, 80, 3),
        ] {
            assert_eq!(platform.chips_per_chain(), chips);
            assert_eq!(platform.address_interval(), interval);
            let plan = platform.desk_plan(policy(), Bm1398FpgaMidstateMode::Four);
            let expected = plan.expected_addresses();
            assert_eq!(expected.len(), usize::from(chips));
            let addresses: Vec<u8> = (0..chips as u8).map(|i| i.wrapping_mul(interval)).collect();
            assert_eq!(expected, addresses);
            assert!(plan.certify_chain(&expected).is_ok());
            assert!(plan.certify_chain(&expected[..expected.len() - 1]).is_err());
        }
    }

    /// The wired NBP1901 resolution must be preserved exactly: the old
    /// run() mapping was freq {0->500, 500..=524->500, 525..->525}, volt
    /// {0->1280, 12600->1260, 12800->1280, 13000->1300, else refuse}.
    #[test]
    fn nbp1901_operating_point_resolution_is_behavior_preserving() {
        let p = Bm1398Platform::S19Pro;
        assert_eq!(p.resolve_operating_point(0, 0).unwrap(), (500, 1280));
        assert_eq!(p.resolve_operating_point(500, 0).unwrap(), (500, 1280));
        assert_eq!(p.resolve_operating_point(524, 0).unwrap(), (500, 1280));
        assert_eq!(p.resolve_operating_point(525, 0).unwrap(), (525, 1280));
        assert_eq!(p.resolve_operating_point(525, 12600).unwrap(), (525, 1260));
        assert_eq!(p.resolve_operating_point(525, 13000).unwrap(), (525, 1300));
        for (f, v) in [(499, 0), (0, 12700), (525, 13800), (525, 126)] {
            assert!(p.resolve_operating_point(f, v).is_err(), "({f},{v})");
        }
    }

    /// The 76-chip bins are EXACT-RUNG only (round-1 repair): a request
    /// must name a rung of that bin's own held levels.json ladder and the
    /// resolved pair must be a row of the same table. No clamp band is
    /// invented for them, so a wrong-bin frequency (675 on T19, 525 on
    /// either 76-chip bin) is a refusal, never a silent substitution.
    #[test]
    fn nbs1902_and_nbt1903_ladders_admit_only_their_own_rows() {
        let s19 = Bm1398Platform::S19Classic;
        assert_eq!(s19.resolve_operating_point(0, 0).unwrap(), (650, 1380));
        assert_eq!(
            s19.resolve_operating_point(675, 13800).unwrap(),
            (675, 1380)
        );
        assert_eq!(
            s19.resolve_operating_point(650, 14200).unwrap(),
            (650, 1420)
        );
        // Non-rung frequencies (including the Pro's 525 and 674-between),
        // non-rung voltage, and Pro/T19-only rows refuse.
        for (f, v) in [
            (649, 0),
            (674, 0),
            (525, 0),
            (0, 12600),
            (650, 14400),
            (650, 14001),
            (625, 14400),
        ] {
            assert!(s19.resolve_operating_point(f, v).is_err(), "({f},{v})");
        }
        let t19 = Bm1398Platform::T19;
        assert_eq!(t19.resolve_operating_point(0, 0).unwrap(), (550, 1420));
        assert_eq!(
            t19.resolve_operating_point(625, 14400).unwrap(),
            (625, 1440)
        );
        assert_eq!(
            t19.resolve_operating_point(550, 14200).unwrap(),
            (550, 1420)
        );
        // (550, 1400) is NOT a held T19 row: the T19 ladder is not a cross product.
        assert!(t19.resolve_operating_point(550, 14000).is_err());
        // Non-rung frequencies — including 675 (NBS1902's rung) and 574
        // (between rungs) — refuse instead of clamping to another rung.
        for (f, v) in [
            (549, 0),
            (574, 0),
            (675, 0),
            (675, 13800),
            (0, 13800),
            (525, 12800),
        ] {
            assert!(t19.resolve_operating_point(f, v).is_err(), "({f},{v})");
        }
    }

    #[test]
    fn stock_board_names_and_targets_are_exact_per_bin() {
        assert_eq!(
            Bm1398Platform::S19Pro.stock_board_names(),
            &["NBP1901", "NBP1901-38"]
        );
        assert_eq!(Bm1398Platform::S19Classic.stock_board_names(), &["NBS1902"]);
        assert_eq!(Bm1398Platform::T19.stock_board_names(), &["NBT1903"]);
        assert_eq!(Bm1398Platform::S19Pro.board_target(), "am2-s19pro");
        assert_eq!(Bm1398Platform::S19Classic.board_target(), "am2-s19");
        assert_eq!(Bm1398Platform::T19.board_target(), "am2-t19");
        assert_eq!(Bm1398Platform::S19a.stock_board_names(), &["BHB28611"]);
        assert_eq!(Bm1398Platform::S19a.board_target(), "am2-s19a");
        assert_eq!(Bm1398Platform::ALL.len(), 5);
        assert_eq!(format!("{}", Bm1398Platform::S19Classic), "NBS1902/am2-s19");
    }

    #[test]
    fn s19a_uses_exact_own_ladder_and_refuses_unknown_aliases() {
        let p = Bm1398Platform::S19a;
        assert_eq!(
            Bm1398Platform::from_admission("am2-s19a", AsicProtocolIdentity::Bm1398),
            Ok(p)
        );
        assert_eq!(p.resolve_operating_point(0, 0).unwrap(), (660, 1280));
        assert_eq!(p.stock_ladder().len(), 40);
        for &(mhz, cv) in p.stock_ladder() {
            assert_eq!(p.resolve_operating_point(mhz, cv * 10).unwrap(), (mhz, cv));
        }
        for (mhz, mv) in [
            (660, 12400),
            (750, 12400),
            (690, 13800),
            (650, 13800),
            (525, 12800),
            (719, 12800),
        ] {
            assert!(p.resolve_operating_point(mhz, mv).is_err());
        }
        for name in ["am2-s19+", "am2-s19plus ", "am2-s19a "] {
            assert!(Bm1398Platform::from_admission(name, AsicProtocolIdentity::Bm1398).is_err());
        }
    }

    #[test]
    fn s19plus_uses_its_exact_default_without_inheriting_sibling_or_preset_envelopes() {
        let plus = Bm1398Platform::S19Plus;
        assert_eq!(
            Bm1398Platform::from_admission("am2-s19plus", AsicProtocolIdentity::Bm1398),
            Ok(plus)
        );
        assert_eq!(plus.stock_board_names(), &["BHB28701"]);
        assert_eq!(plus.geometry(), S19_PLUS_BHB28701_BOARD_GEOMETRY);
        assert_eq!(plus.resolve_operating_point(0, 0).unwrap(), (645, 1400));
        assert_eq!(
            plus.resolve_operating_point(645, 14000).unwrap(),
            (645, 1400)
        );
        for (mhz, mv) in [
            (650, 13800),
            (675, 14000),
            (660, 12800),
            (550, 14200),
            (605, 12800),
            (730, 13300),
            (645, 13990),
            (644, 14000),
            (646, 14000),
        ] {
            assert!(plus.resolve_operating_point(mhz, mv).is_err(), "{mhz}/{mv}");
        }
        assert!(Bm1398Platform::S19Classic
            .resolve_operating_point(645, 14000)
            .is_err());
    }
}
