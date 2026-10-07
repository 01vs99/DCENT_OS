//! Per-platform parameters for the BM1366 direct-serial runtime (Gauntlet B8).
//!
//! Exact S19k77-chip native/Track-1 geometry stays independent from the
//! S19 XP and S19j XP110-chip production profiles. The XP native executor
//! joins complete protected factory EEPROM identity, measured per-model PSU
//! versions, all selected AM3 UARTs, dual LM75 readings and checked reset/cut
//! custody. The independently held production model/factory traces are under
//!
//!
//! Software dispatch admission is not a live hashing or installation receipt.
//! Unknown factory revisions still reject before power; each selected board
//! must freshly prove all110 BM1366 responses before work is sent.
//!
//! This module is deliberately pure data + lookups (no I/O, no HAL) so it can
//! live in `dcentrald-common` next to the other stock-evidence surfaces.
//!
//! Evidence base (all desk-side, Phase A extraction trees, gitignored,
//! internal RE evidence only — never redistribute the cited binaries):
//!
//! and `.../s19j-xp-merge-20241014/` (A3 report §3.8: the XP-pair SKU set is
//! SETTLED stock-side). Mirror caveats class applies (third-party mirror,
//! internally consistency-verified, `chain_num` is the connector-slot field
//! on air boards — the XP topol records all say 3, consistent with 3-board
//! population, but live population stays a capture datum).

/// Per-platform parameters for the BM1366 direct-serial runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1366SerialPlatformProfile {
    /// Registered `BoardDesc::board_target` this profile parameterizes.
    pub board_target: &'static str,
    /// Fresh post-open population target per logical UART. This is the
    /// runtime admission geometry (what the cold-start owner joins), NOT a
    /// stock nameplate: `am3-s19k` pins the live-proven 77 here.
    pub expected_chips_per_uart: u8,
    /// Stock `chain.chain_num` (connector/slot field on air boards; the XP
    /// records' 3 is consistent with the 3-board population, but live
    /// population remains a bench capture datum).
    pub stock_chain_count: u8,
    /// Whether the daemon's Serial+BM1366 dispatch arm may admit this
    /// platform today. Evidence-only rows stay `false` — see the module doc.
    pub dispatch_admitted: bool,
    /// Fail-closed reason surfaced when a non-admitted profile is asked to
    /// dispatch (empty string on the admitted row).
    pub dispatch_gate: &'static str,
    /// Stock-contract citation block (extraction path(s) + sha256 + the
    /// board-code/PSU/PIC/fan/EEPROM/nameplate facts). Internal RE evidence
    /// only.
    pub stock_basis: &'static str,
}

/// am3-s19k expected per-UART population. Must stay numerically identical to
/// `dcentrald_hal::platform::amlogic::S19K_NATIVE_EXPECTED_CHIPS_PER_UART`
/// (77); the cold-start owner join enforces that agreement at runtime so the
/// common table and the HAL constant cannot drift apart silently.
pub const BM1366_S19K_EXPECTED_CHIPS_PER_UART: u8 = 77;

/// Stock topol S19k Pro geometry citation (Phase A §2.3/§3.8 bonus):
/// `topol_BHB56902.conf` (the default topol.conf) = 77/chain (11 dom × 7),
/// interval 2, PIC1704@0x20, APW12 — matching the pinned restore and the
/// live dual-UART proof. (Sibling records: BHB56903 77/chain APW12,
/// BHB56901 77/chain APW17 — PSU dialect is per-machine-record; TS007 is a
/// different 80/chain machine and is NOT cited here.)
const S19K_STOCK_BASIS: &str = "am3-s19k: live Track-1 + 2026-09-01 bounded-work \
dual-UART proof (ttyS1+ttyS2, 77-chip ladders both boards); stock topol \
BHB56902 (default) = 77/chain (11 dom x 7), interval 2, PIC1704 @ i2c 0x20, \
APW12 @ i2c 0x10 gpio 907 (s19k-pro-merge-20240409 zynq7007 record, \
extraction tree \
); \
HAL parity S19K_NATIVE_EXPECTED_CHIPS_PER_UART = 77";

/// S19 XP stock-contract citation (Phase A §3.8, verified B8 desk-side).
pub const AM3_S19XP_STOCK_BASIS: &str = "S19 XP stock contracts (s19-xp-merge-20241111 \
02_Antminer_S19_XP_zynq7007_BHB56XXX/components/minerfs.image.gz.tree/etc/, \
internal RE evidence only): default topol.conf == topol_BHB56801.conf \
(sha256 f4586a3b09fc9b7ce48f01272d4d06a19bea85d23d68ce2bb1b3dbf9bebd529d) = \
BHB56801: BM1366 (0x1366, 112 big + 894 small cores, addr interval 2), 3 \
chains, 110/chain (11 dom x 10), PSU APW12 @ i2c 0x10 gpio 907 (power.version \
[66,67,113,114,115,117,118,119,120]), per-chain PIC1704 @ 0x20 + 4x LM75A @ \
0x48-0x4B, hashboard EEPROM AT24C02D @ 0x50, 4 fan channels (2 right-in, \
2 left-out), ZYNQ7007 (dtb xlnx,zynq-7000); sibling bins same image: BHB56802 \
(110/chain) + BHB56806 (110/chain), BHB56601 (99/chain, 11x9), BHB56701 \
(70/chain, 10x7); levels.json 485 MHz/1320 mV + 410 MHz/1240 mV, mix_levels \
485..410 MHz; merge also ships AMLCtrl (sealed ANDROID! code-9, 15,104,512 B) \
and CVCtrl records; 2-source corroboration: the s19k-pro-merge-20240409 \
zynq7007 stock DB carries byte-consistent BHB56601/BHB56701/BHB56801/BHB56802 \
machine records (99/70/110/110 per chain, all APW12 there)";

/// S19j XP stock-contract citation (Phase A §3.8, verified B8 desk-side).
pub const AM3_S19JXP_STOCK_BASIS: &str = "S19j XP stock contracts (s19j-xp-merge-20241014 \
02_Antminer_S19j_XP_zynq7007_BHB56XXX/components/minerfs.image.gz.tree/etc/, \
internal RE evidence only): default topol.conf (sha256 \
37e0db670b673ea6167749b88349fc67060fcc5a87af8812f4d85162b0c467bd) = BHB56804: \
BM1366 (0x1366, 112 big + 894 small cores, addr interval 2), 3 chains, \
110/chain (11 dom x 10), PSU APW17 @ i2c 0x10 gpio 907 (power.version [193]; \
sibling topol_BHB56807.conf sha256 \
e49a70980c59b9506758028de24f10a365e50ec1c8204c0889486f7c5d1bb947 declares \
APW17 v[194]) — the PSU dialect deliberately differs from the S19 XP \
dialect (see AM3_S19XP_STOCK_BASIS; the two rows must never be merged); \
per-chain PIC1704 @ 0x20 + 4x LM75A @ 0x48-0x4B, hashboard EEPROM AT24C02D @ \
0x50, 4 fan channels, ZYNQ7007; levels.json 515 MHz/1320 mV + 300 MHz/1240 \
mV, mix_levels 515..400 MHz; merge also ships AMLCtrl (sealed ANDROID! \
code-9, 15,086,080 B) and CVCtrl records";

/// The per-platform BM1366 serial table. One admitted row (am3-s19k) + the
/// two evidence-only XP rows.
pub const BM1366_SERIAL_PLATFORMS: [Bm1366SerialPlatformProfile; 3] = [
    Bm1366SerialPlatformProfile {
        board_target: "am3-s19k",
        expected_chips_per_uart: BM1366_S19K_EXPECTED_CHIPS_PER_UART,
        stock_chain_count: 3,
        dispatch_admitted: true,
        dispatch_gate: "",
        stock_basis: S19K_STOCK_BASIS,
    },
    Bm1366SerialPlatformProfile {
        board_target: "am3-s19xp",
        expected_chips_per_uart: 110,
        stock_chain_count: 3,
        dispatch_admitted: true,
        dispatch_gate: "",
        stock_basis: AM3_S19XP_STOCK_BASIS,
    },
    Bm1366SerialPlatformProfile {
        board_target: "am3-s19jxp",
        expected_chips_per_uart: 110,
        stock_chain_count: 3,
        dispatch_admitted: true,
        dispatch_gate: "",
        stock_basis: AM3_S19JXP_STOCK_BASIS,
    },
];

/// Look up the per-platform BM1366 serial parameters for a registered
/// board target. `None` for every non-BM1366-serial target (the caller's
/// generic contract checks then apply unchanged).
pub fn bm1366_serial_platform_for(
    board_target: &str,
) -> Option<&'static Bm1366SerialPlatformProfile> {
    BM1366_SERIAL_PLATFORMS
        .iter()
        .find(|profile| profile.board_target == board_target)
}

/// Resolve the dispatch-admitted BM1366 serial platform for a board target.
/// `Ok` ONLY for rows whose evidence supports runtime dispatch today;
/// `Err(gate)` carries the fail-closed reason for evidence-only rows and
/// for targets outside the table.
pub fn bm1366_dispatch_admitted_serial_platform(
    board_target: &str,
) -> Result<&'static Bm1366SerialPlatformProfile, &'static str> {
    match bm1366_serial_platform_for(board_target) {
        Some(profile) if profile.dispatch_admitted => Ok(profile),
        Some(profile) => Err(profile.dispatch_gate),
        None => Err("board target has no BM1366 serial platform profile"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_targets_are_unique_and_cover_the_xp_pair() {
        let mut targets: Vec<&str> = BM1366_SERIAL_PLATFORMS
            .iter()
            .map(|profile| profile.board_target)
            .collect();
        targets.sort_unstable();
        targets.dedup();
        assert_eq!(targets.len(), BM1366_SERIAL_PLATFORMS.len());
        for expected in ["am3-s19k", "am3-s19xp", "am3-s19jxp"] {
            assert!(targets.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn three_native_routes_keep_s19k_geometry_separate() {
        let admitted: Vec<_> = BM1366_SERIAL_PLATFORMS
            .iter()
            .filter(|profile| profile.dispatch_admitted)
            .collect();
        assert_eq!(admitted.len(), 3);
        assert_eq!(admitted[0].board_target, "am3-s19k");
        assert_eq!(admitted[0].expected_chips_per_uart, 77);
        assert!(admitted[0].dispatch_gate.is_empty());
    }

    #[test]
    fn s19k_geometry_matches_the_hal_native_constant_value() {
        // dcentrald-common cannot depend on dcentrald-hal, so the numeric
        // agreement with S19K_NATIVE_EXPECTED_CHIPS_PER_UART is pinned here
        // (77) and separately enforced at the serial_mining owner join.
        assert_eq!(BM1366_S19K_EXPECTED_CHIPS_PER_UART, 77);
        assert_eq!(
            bm1366_serial_platform_for("am3-s19k")
                .unwrap()
                .expected_chips_per_uart,
            77
        );
    }

    #[test]
    fn xp_rows_admit_exact_native_110_geometry() {
        for target in ["am3-s19xp", "am3-s19jxp"] {
            let profile = bm1366_dispatch_admitted_serial_platform(target).unwrap();
            assert_eq!(profile.expected_chips_per_uart, 110);
            assert_eq!(profile.stock_chain_count, 3);
            assert!(profile.dispatch_gate.is_empty());
        }
    }

    #[test]
    fn xp_native_admission_preserves_independent_stock_psu_provenance() {
        let xp = bm1366_dispatch_admitted_serial_platform("am3-s19xp").unwrap();
        let jxp = bm1366_dispatch_admitted_serial_platform("am3-s19jxp").unwrap();
        assert!(xp.stock_basis.contains("APW12"));
        assert!(jxp.stock_basis.contains("APW17"));
        assert!(bm1366_dispatch_admitted_serial_platform("am3-s19xp-hydro").is_err());
    }

    #[test]
    fn stock_basis_blocks_pin_the_first_party_contracts() {
        let s19xp = bm1366_serial_platform_for("am3-s19xp").unwrap();
        for needle in [
            "BHB56801",
            "BHB56802",
            "BHB56806",
            "BHB56601",
            "BHB56701",
            "110/chain",
            "APW12",
            "PIC1704",
            "AT24C02D",
            "894",
            "485 MHz/1320 mV",
            "f4586a3b09fc9b7ce48f01272d4d06a19bea85d23d68ce2bb1b3dbf9bebd529d",
            "ANDROID!",
        ] {
            assert!(
                s19xp.stock_basis.contains(needle),
                "S19 XP basis missing {needle}"
            );
        }
        let s19jxp = bm1366_serial_platform_for("am3-s19jxp").unwrap();
        for needle in [
            "BHB56804",
            "BHB56807",
            "110/chain",
            "APW17",
            "PIC1704",
            "515 MHz/1320 mV",
            "37e0db670b673ea6167749b88349fc67060fcc5a87af8812f4d85162b0c467bd",
            "ANDROID!",
        ] {
            assert!(
                s19jxp.stock_basis.contains(needle),
                "S19j XP basis missing {needle}"
            );
        }
        // The PSU dialect split is the reason the pair is NOT one profile.
        assert!(!s19xp.stock_basis.contains("APW17"));
        assert!(!s19jxp.stock_basis.contains("APW12"));
    }

    #[test]
    fn lookup_misses_non_bm1366_targets() {
        for target in ["am2-s19j", "am1-s9", "am3-s21", "", "am3-s19k-alias"] {
            assert!(bm1366_serial_platform_for(target).is_none(), "{target}");
            assert!(bm1366_dispatch_admitted_serial_platform(target).is_err());
        }
    }

    #[test]
    fn s19k_row_keeps_the_live_proven_citations() {
        let profile = bm1366_serial_platform_for("am3-s19k").unwrap();
        for needle in [
            "77",
            "BHB56902",
            "APW12",
            "bounded-work",
            "S19K_NATIVE_EXPECTED_CHIPS_PER_UART",
        ] {
            assert!(
                profile.stock_basis.contains(needle),
                "am3-s19k basis missing {needle}"
            );
        }
    }
}
