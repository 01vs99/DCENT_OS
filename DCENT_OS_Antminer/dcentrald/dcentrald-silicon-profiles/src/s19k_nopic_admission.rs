//! S19k Pro / BM1366 Amlogic NoPic profile admission (BETA-shaped, offline).
//!
//! Desk/host-testable gates for community tryable-beta readiness. This module
//! admits **management-fabric identity only** — it never authorizes mining,
//! rail ENABLE, open-core, work codec, or PIC/dsPIC ownership.
//!
//! Evidence anchors (public HashSource + RE-4A/4C + private S19k vs S21 note):
//! - `Has_Pic: false` (BHB5690x Config.ini family)
//! - ChipID / catalog binding BM1366 (`0x1366`)
//! - CtrlBoard LM75A before ASIC probe (twin of BM1368 NoPic fabric)
//! - am3-s19k GPIO437 `PWR_CONTROL` is active-LOW (`0=ON`); checked
//!   HIGH (`1=OFF`) SafeOff is an orthogonal OTA gate
//!
//! Native BM1366 mining is implemented by `serial_mining`. This fabric
//! identity result cannot substitute for its fresh EEPROM, UART, cooling,
//! watchdog, power and terminal-owner admission.

use crate::hashboard_topology::descriptor_by_sku;
use crate::sensor_topology::sensor_topology_for_sku;
use dcentrald_common::cooling_medium::CoolingMedium;

/// Cooling choice cannot turn stock `Fans OK` (min_fans=0) into airflow.
/// Undeclared cooling keeps the four physical fan channels mandatory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1366CoolingRule {
    FourFans,
    /// No fan command is meaningful here. The separate liquid runtime must
    /// retain its ExternalCutoffGate; tach values cannot admit this medium.
    ExternalLoopOwnerRequired,
}

pub const BM1366_MIN_FAN_RPM: u32 = 2_000;

pub const fn bm1366_cooling_rule(medium: Option<CoolingMedium>) -> Bm1366CoolingRule {
    match medium {
        None | Some(CoolingMedium::Air) => Bm1366CoolingRule::FourFans,
        Some(CoolingMedium::Hydro | CoolingMedium::Immersion) => {
            Bm1366CoolingRule::ExternalLoopOwnerRequired
        }
    }
}

/// Check a fresh tach sample taken by the retained fan owner after a checked
/// PWM command. All four unique channels must reach the floor. This function
/// accepts no stock status string or min_fans override. It grants no power.
pub fn admit_bm1366_airflow(
    medium: Option<CoolingMedium>,
    readings: &[(u8, u32)],
) -> Result<(), &'static str> {
    if bm1366_cooling_rule(medium) != Bm1366CoolingRule::FourFans {
        return Err("BM1366 liquid cooling requires an external-loop owner and cutoff latch");
    }
    if readings.len() != 4 {
        return Err("BM1366 air cooling requires all four tach channels");
    }
    let mut seen = [false; 4];
    for &(channel, rpm) in readings {
        let slot = seen
            .get_mut(usize::from(channel))
            .ok_or("BM1366 air cooling has an unknown tach channel")?;
        if *slot || rpm < BM1366_MIN_FAN_RPM {
            return Err("BM1366 air cooling requires four unique tachs at or above 2000 RPM");
        }
        *slot = true;
    }
    Ok(())
}

/// Stock endpoints, not a frozen operating point. The driver allows quiet
/// underclocking below `low_power_mhz` and independently validates voltage,
/// temperatures and cooling. Voltage values are stock centivolts, not mV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1366StockLevels {
    pub low_power_mhz: u16,
    pub low_power_centivolts: u16,
    pub maximum_mhz: u16,
    pub maximum_centivolts: u16,
}

/// Extracted from held Bitmain `etc/levels.json` in the following packages:
/// s19k-pro-merge-20240409, s19-xp-merge-20241111, s19j-xp-merge-20241014.
/// Exact decoded SKU and model are both required; no sibling fallback.
pub fn bm1366_stock_levels(board_target: &str, sku: &str) -> Option<Bm1366StockLevels> {
    let (low_power_mhz, low_power_centivolts, maximum_mhz, maximum_centivolts) =
        match (board_target, sku) {
            ("am3-s19k", "BHB56901") => (635, 1320, 695, 1390),
            ("am3-s19k", "BHB56902" | "BHB56903") => (
                540,
                1320,
                dcentrald_common::s19k_bm1366_wire_b::S19K_NATIVE_MAX_FREQUENCY_MHZ,
                1440,
            ),
            ("am3-s19xp", "BHB56801" | "BHB56802" | "BHB56806") => (410, 1240, 485, 1320),
            ("am3-s19jxp", "BHB56804" | "BHB56807") => (300, 1240, 515, 1320),
            _ => return None,
        };
    Some(Bm1366StockLevels {
        low_power_mhz,
        low_power_centivolts,
        maximum_mhz,
        maximum_centivolts,
    })
}

/// Resolve and bound both the requested frequency and the programmed divider
/// ratio. The 100 MHz floor is driver policy, not the stock low-power level.
pub fn resolve_bm1366_stock_pll(
    board_target: &str,
    sku: &str,
    requested_mhz: u16,
) -> Result<(u32, u16), &'static str> {
    let levels = bm1366_stock_levels(board_target, sku)
        .ok_or("BM1366 PLL requires exact held stock model/SKU levels")?;
    dcentrald_common::s19k_bm1366_wire_b::bm1366_pll_in_envelope(
        requested_mhz,
        100,
        levels.maximum_mhz,
    )
}

/// Exact board_name strings admitted for S19k-class BM1366 NoPic identity.
///
/// Catalogued BHB5690x family only. Marketing names alone never admit.
pub const S19K_NOPIC_BOARD_NAMES: &[&str] =
    &["BHB56901", "BHB56902", "BHB56903", "BHB56906", "BHB56907"];

/// Canonical live-probed SKU (`a lab unit` / catalog LiveDeployedPage).
pub const S19K_CANONICAL_BOARD_NAME: &str = "BHB56902";

/// Chip name required for S19k NoPic admission.
pub const S19K_CHIP_NAME: &str = "BM1366";

/// Jig / catalog chips-per-chain geometry (physical / driver / live probe = 77).
pub const S19K_CHIPS_PER_CHAIN: u8 = 77;

/// Midstate packing for BM1366 work (S19k PT Config.ini). Binding only —
/// does **not** unlock a work codec.
pub const S19K_MIDSTATE_NUMBER: u8 = 8;

/// A fabric claim is never a capability to execute the native mining engine.
pub const S19K_NATIVE_MINING_REFUSAL: &str = "native BM1366 execution requires the exact runtime owner: fresh EEPROM identity, UART response coverage, cooling, watchdog and retained power cutoff; a NoPic fabric claim must not authorize controller, voltage or ASIC mutation";

/// Declared Has_Pic / controller-class inputs for one S19k profile candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kNoPicProfileClaim {
    pub board_name: &'static str,
    pub chip_name: &'static str,
    pub has_pic: bool,
    pub chips_per_chain: u8,
    /// True when a PIC/dsPIC/BM1362 voltage owner is being offered.
    pub offers_pic_voltage_owner: bool,
    /// True when CtrlBoard LM75-before-probe fabric is declared present.
    pub ctrlboard_lm75_before_probe: bool,
}

/// Result of S19k NoPic profile admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S19kNoPicAdmission {
    /// Fabric identity admitted for BETA offline gates. Mining remains refused.
    AdmittedFabric {
        board_name: &'static str,
        chips_per_chain: u8,
        midstate_number: u8,
        mining: S19kMiningDisposition,
    },
    Refused(String),
}

/// Mining disposition attached to every successful fabric admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kMiningDisposition {
    /// The separate native owner must admit every physical safety prerequisite.
    NativeOwnerRequired,
}

impl S19kMiningDisposition {
    pub const fn refusal_message(self) -> &'static str {
        match self {
            Self::NativeOwnerRequired => S19K_NATIVE_MINING_REFUSAL,
        }
    }
}

/// Pure fail-closed admission for S19k Amlogic NoPic fabric identity.
///
/// Refuses:
/// - unknown / non-catalog board_name
/// - chip ≠ BM1366
/// - `Has_Pic: true` or any PIC/dsPIC/BM1362 voltage owner offer
/// - missing CtrlBoard LM75-before-probe fabric declaration
/// - geometry that contradicts the BHB5690x 77 chips/chain class
///
/// Success never means mining is enabled.
pub fn admit_s19k_nopic_profile(claim: S19kNoPicProfileClaim) -> S19kNoPicAdmission {
    if !S19K_NOPIC_BOARD_NAMES.contains(&claim.board_name) {
        return S19kNoPicAdmission::Refused(format!(
            "S19k NoPic admission refused: board_name {:?} is not a catalogued BHB5690x identity",
            claim.board_name
        ));
    }
    if claim.chip_name != S19K_CHIP_NAME {
        return S19kNoPicAdmission::Refused(format!(
            "S19k NoPic admission refused: chip {:?} does not match required {S19K_CHIP_NAME} (board {})",
            claim.chip_name, claim.board_name
        ));
    }
    if claim.has_pic {
        return S19kNoPicAdmission::Refused(format!(
            "S19k NoPic admission refused: Has_Pic=true contradicts BHB5690x Config.ini (board {}); PIC/dsPIC owners are forbidden",
            claim.board_name
        ));
    }
    if claim.offers_pic_voltage_owner {
        return S19kNoPicAdmission::Refused(format!(
            "S19k NoPic admission refused: PIC/dsPIC/BM1362 voltage owner offered for NoPic board {}; refuse inheritance from BM1362 fabrics",
            claim.board_name
        ));
    }
    if !claim.ctrlboard_lm75_before_probe {
        return S19kNoPicAdmission::Refused(format!(
            "S19k NoPic admission refused: CtrlBoard LM75-before-probe fabric missing for {}; twin BM1368 NoPic thermal gate required before ASIC probe",
            claim.board_name
        ));
    }
    if claim.chips_per_chain != S19K_CHIPS_PER_CHAIN {
        return S19kNoPicAdmission::Refused(format!(
            "S19k NoPic admission refused: chips_per_chain {} != {S19K_CHIPS_PER_CHAIN} for {}",
            claim.chips_per_chain, claim.board_name
        ));
    }

    S19kNoPicAdmission::AdmittedFabric {
        board_name: claim.board_name,
        chips_per_chain: claim.chips_per_chain,
        midstate_number: S19K_MIDSTATE_NUMBER,
        mining: S19kMiningDisposition::NativeOwnerRequired,
    }
}

/// Build a claim from the pinned topology/catalog corpus for one board_name.
///
/// `vendor_declared_pic` in the jig DB is **ignored** as ownership authority
/// (RE/S21 NoPic lesson): Has_Pic is forced false for BHB5690x, and PIC owners
/// are never offered from this helper.
pub fn s19k_claim_from_pinned_corpus(board_name: &str) -> Option<S19kNoPicProfileClaim> {
    let board_name = *S19K_NOPIC_BOARD_NAMES.iter().find(|&&b| b == board_name)?;
    let desc = descriptor_by_sku(board_name)?;
    if desc.chip.name != S19K_CHIP_NAME {
        return None;
    }
    let topo = sensor_topology_for_sku(board_name)?;
    let ctrlboard_lm75 = topo.ctrl_board_sensors().any(|s| {
        // Device labels in the corpus are "LM75A".
        s.device.contains("LM75")
    });
    // Require at least the twin CtrlBoard pair (inlet/outlet class).
    let ctrlboard_count = topo.ctrl_board_sensors().count();
    let ctrlboard_lm75_before_probe = ctrlboard_lm75 && ctrlboard_count >= 2;

    Some(S19kNoPicProfileClaim {
        board_name,
        chip_name: S19K_CHIP_NAME,
        has_pic: false,
        chips_per_chain: u8::try_from(desc.chain.chips_per_chain).unwrap_or(0),
        offers_pic_voltage_owner: false,
        ctrlboard_lm75_before_probe,
    })
}

/// Admit the canonical BHB56902 row from the pinned corpus.
pub fn admit_canonical_s19k_from_corpus() -> S19kNoPicAdmission {
    match s19k_claim_from_pinned_corpus(S19K_CANONICAL_BOARD_NAME) {
        Some(claim) => admit_s19k_nopic_profile(claim),
        None => S19kNoPicAdmission::Refused(
            "S19k NoPic admission refused: canonical BHB56902 corpus row missing".into(),
        ),
    }
}

/// Whether a voltage-controller class string is a forbidden PIC inheritance.
pub fn is_forbidden_pic_voltage_class(class: &str) -> bool {
    matches!(
        class,
        "pic1704"
            | "pic16f1704"
            | "dspic33ep"
            | "Pic1704"
            | "Pic16F1704"
            | "DsPic33Ep"
            | "ChipDriverPic"
            | "HashboardDspic"
    )
}

/// Ordered fabric phases for S19k NoPic tryable-BETA (host-testable).
///
/// CtrlBoard LM75-before-probe MUST complete before ASIC probe. This is the
/// twin of BM1368 NoPic thermal gating — declaration alone is not enough;
/// callers must advance phases in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum S19kNopicFabricPhase {
    /// Identity / NoPic / PIC-refuse gates (admit_s19k_nopic_profile).
    IdentityAdmitted = 0,
    /// CtrlBoard LM75A fabric observed/required (indices [0, 4] class).
    CtrlBoardLm75BeforeProbe = 1,
    /// ASIC GetAddress / probe — forbidden until LM75 phase is latched.
    AsicProbe = 2,
}

/// Move-only latch of completed fabric phases.
#[derive(Debug, Default)]
pub struct S19kNopicFabricPhaseLatch {
    highest: Option<S19kNopicFabricPhase>,
}

impl S19kNopicFabricPhaseLatch {
    pub fn new() -> Self {
        Self { highest: None }
    }

    /// Advance to `next` if and only if every prior phase is already latched.
    pub fn advance(&mut self, next: S19kNopicFabricPhase) -> Result<(), String> {
        let required_prev = match next {
            S19kNopicFabricPhase::IdentityAdmitted => None,
            S19kNopicFabricPhase::CtrlBoardLm75BeforeProbe => {
                Some(S19kNopicFabricPhase::IdentityAdmitted)
            }
            S19kNopicFabricPhase::AsicProbe => Some(S19kNopicFabricPhase::CtrlBoardLm75BeforeProbe),
        };
        if let Some(prev) = required_prev {
            match self.highest {
                Some(h) if h >= prev => {}
                _ => {
                    return Err(format!(
                        "S19k NoPic fabric phase refused: cannot enter {next:?} before {prev:?} (LM75-before-probe order)"
                    ));
                }
            }
        }
        self.highest = Some(match self.highest {
            Some(h) if h > next => h,
            _ => next,
        });
        Ok(())
    }

    pub fn highest(&self) -> Option<S19kNopicFabricPhase> {
        self.highest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooling_medium_selects_fans_or_external_owner_without_stock_status() {
        let valid = [(3, 2_000), (1, 2_001), (0, 2_300), (2, 2_100)];
        for medium in [None, Some(CoolingMedium::Air)] {
            assert_eq!(bm1366_cooling_rule(medium), Bm1366CoolingRule::FourFans);
            admit_bm1366_airflow(medium, &valid).unwrap();
            for readings in [
                vec![],
                valid[..3].to_vec(),
                vec![(0, 2000), (0, 2000), (2, 2000), (3, 2000)],
                vec![(0, 2000), (1, 2000), (2, 2000), (4, 2000)],
            ] {
                assert!(admit_bm1366_airflow(medium, &readings).is_err());
            }
            for failed in 0..4 {
                let mut readings = valid;
                readings[failed].1 = 1_999;
                assert!(admit_bm1366_airflow(medium, &readings).is_err());
            }
        }
        for medium in [CoolingMedium::Hydro, CoolingMedium::Immersion] {
            assert_eq!(
                bm1366_cooling_rule(Some(medium)),
                Bm1366CoolingRule::ExternalLoopOwnerRequired
            );
            assert!(admit_bm1366_airflow(Some(medium), &valid).is_err());
            assert!(admit_bm1366_airflow(Some(medium), &[]).is_err());
        }
    }

    #[test]
    fn held_stock_levels_keep_s19k_and_xp_skus_separate() {
        for (target, skus, expected) in [
            ("am3-s19k", &["BHB56901"][..], (635, 1320, 695, 1390)),
            (
                "am3-s19k",
                &["BHB56902", "BHB56903"][..],
                (540, 1320, 670, 1440),
            ),
            (
                "am3-s19xp",
                &["BHB56801", "BHB56802", "BHB56806"][..],
                (410, 1240, 485, 1320),
            ),
            (
                "am3-s19jxp",
                &["BHB56804", "BHB56807"][..],
                (300, 1240, 515, 1320),
            ),
        ] {
            for sku in skus {
                let levels = bm1366_stock_levels(target, sku).unwrap();
                assert_eq!(
                    (
                        levels.low_power_mhz,
                        levels.low_power_centivolts,
                        levels.maximum_mhz,
                        levels.maximum_centivolts
                    ),
                    expected
                );
                for request in [100, 200, levels.low_power_mhz, levels.maximum_mhz] {
                    let (register, actual) =
                        resolve_bm1366_stock_pll(target, sku, request).unwrap();
                    let numerator = 25 * ((register >> 16) & 0xff);
                    let denominator = ((register >> 8) & 0xff)
                        * (((register >> 4) & 0x0f) + 1)
                        * ((register & 0x0f) + 1);
                    assert!(numerator <= u32::from(levels.maximum_mhz) * denominator);
                    assert!(actual.abs_diff(request) <= 2);
                }
                for request in [0, 99, levels.maximum_mhz + 1, u16::MAX] {
                    assert!(resolve_bm1366_stock_pll(target, sku, request).is_err());
                }
            }
        }
        for (target, sku) in [
            ("am3-s19xp", "BHB56804"),
            ("am3-s19jxp", "BHB56801"),
            ("am3-s19k", "BHB56906"),
            ("am3-s19kpro", "BHB56902"),
            ("am3-s21", "BHB56902"),
            ("", ""),
            ("am3-s19k", " BHB56902"),
        ] {
            assert!(bm1366_stock_levels(target, sku).is_none());
            assert!(resolve_bm1366_stock_pll(target, sku, 400).is_err());
        }
    }

    fn good_claim() -> S19kNoPicProfileClaim {
        S19kNoPicProfileClaim {
            board_name: "BHB56902",
            chip_name: "BM1366",
            has_pic: false,
            chips_per_chain: 77,
            offers_pic_voltage_owner: false,
            ctrlboard_lm75_before_probe: true,
        }
    }

    #[test]
    fn admits_canonical_bhb56902_fabric_but_not_mining() {
        match admit_s19k_nopic_profile(good_claim()) {
            S19kNoPicAdmission::AdmittedFabric {
                board_name,
                chips_per_chain,
                midstate_number,
                mining,
            } => {
                assert_eq!(board_name, "BHB56902");
                assert_eq!(chips_per_chain, 77);
                assert_eq!(midstate_number, 8);
                assert_eq!(mining, S19kMiningDisposition::NativeOwnerRequired);
                assert!(mining
                    .refusal_message()
                    .contains("requires the exact runtime owner"));
                assert!(mining.refusal_message().contains("NoPic"));
            }
            other => panic!("expected fabric admission, got {other:?}"),
        }
    }

    #[test]
    fn refuses_has_pic_true() {
        let mut claim = good_claim();
        claim.has_pic = true;
        match admit_s19k_nopic_profile(claim) {
            S19kNoPicAdmission::Refused(r) => {
                assert!(r.contains("Has_Pic=true"), "{r}");
                assert!(r.contains("PIC/dsPIC"), "{r}");
            }
            other => panic!("expected refuse, got {other:?}"),
        }
    }

    #[test]
    fn refuses_pic_voltage_owner_inheritance() {
        let mut claim = good_claim();
        claim.offers_pic_voltage_owner = true;
        match admit_s19k_nopic_profile(claim) {
            S19kNoPicAdmission::Refused(r) => {
                assert!(r.contains("BM1362"), "{r}");
            }
            other => panic!("expected refuse, got {other:?}"),
        }
    }

    #[test]
    fn refuses_missing_ctrlboard_lm75_before_probe() {
        let mut claim = good_claim();
        claim.ctrlboard_lm75_before_probe = false;
        match admit_s19k_nopic_profile(claim) {
            S19kNoPicAdmission::Refused(r) => {
                assert!(r.contains("LM75-before-probe"), "{r}");
                assert!(r.contains("BM1368"), "{r}");
            }
            other => panic!("expected refuse, got {other:?}"),
        }
    }

    #[test]
    fn refuses_wrong_chip_and_unknown_board() {
        let mut claim = good_claim();
        claim.chip_name = "BM1362";
        assert!(matches!(
            admit_s19k_nopic_profile(claim),
            S19kNoPicAdmission::Refused(_)
        ));
        claim = good_claim();
        claim.board_name = "BHB42601";
        assert!(matches!(
            admit_s19k_nopic_profile(claim),
            S19kNoPicAdmission::Refused(_)
        ));
    }

    #[test]
    fn refuses_wrong_geometry() {
        let mut claim = good_claim();
        claim.chips_per_chain = 126;
        assert!(matches!(
            admit_s19k_nopic_profile(claim),
            S19kNoPicAdmission::Refused(_)
        ));
    }

    #[test]
    fn catalogued_bhb5690x_rows_admit_from_pinned_corpus() {
        for board in S19K_NOPIC_BOARD_NAMES {
            let claim = s19k_claim_from_pinned_corpus(board)
                .unwrap_or_else(|| panic!("missing corpus claim for {board}"));
            assert!(!claim.has_pic, "{board} must force Has_Pic=false");
            assert!(
                !claim.offers_pic_voltage_owner,
                "{board} must not offer PIC voltage owner from corpus helper"
            );
            match admit_s19k_nopic_profile(claim) {
                S19kNoPicAdmission::AdmittedFabric { mining, .. } => {
                    assert_eq!(mining, S19kMiningDisposition::NativeOwnerRequired);
                }
                S19kNoPicAdmission::Refused(r) => panic!("{board} refused: {r}"),
            }
        }
    }

    #[test]
    fn canonical_corpus_admission_is_bhb56902() {
        match admit_canonical_s19k_from_corpus() {
            S19kNoPicAdmission::AdmittedFabric { board_name, .. } => {
                assert_eq!(board_name, "BHB56902");
            }
            other => panic!("expected canonical admit, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_pic_voltage_classes_cover_bm1362_fabrics() {
        for class in [
            "pic1704",
            "dspic33ep",
            "Pic16F1704",
            "DsPic33Ep",
            "ChipDriverPic",
            "HashboardDspic",
        ] {
            assert!(
                is_forbidden_pic_voltage_class(class),
                "{class} must be forbidden for S19k NoPic"
            );
        }
        assert!(!is_forbidden_pic_voltage_class("nopic"));
        assert!(!is_forbidden_pic_voltage_class("NoPic"));
    }

    #[test]
    fn vendor_declared_pic_in_jig_db_is_not_ownership_authority() {
        // BHB56902 corpus row historically carries vendor_declared_pic=PIC1704.
        // Corpus helper must still force Has_Pic=false and never offer PIC owners.
        let desc = descriptor_by_sku("BHB56902").expect("BHB56902 topology");
        let pic = desc
            .vendor_declared_pic
            .as_ref()
            .expect("BHB56902 still carries the vendor claim");
        assert_eq!(
            pic.device, "PIC1704",
            "fixture still carries vendor_declared_pic — regression pin"
        );
        let claim = s19k_claim_from_pinned_corpus("BHB56902").expect("claim");
        assert!(!claim.has_pic);
        assert!(!claim.offers_pic_voltage_owner);
        assert!(claim.ctrlboard_lm75_before_probe);
    }

    #[test]
    fn refuses_s21_fixture_board_name_bhb68603() {
        let mut claim = good_claim();
        claim.board_name = "BHB68603";
        // Even with BM1366 chip claim, S21 fixture board_name must not admit as S19k.
        match admit_s19k_nopic_profile(claim) {
            S19kNoPicAdmission::Refused(r) => {
                assert!(
                    r.contains("BHB68603") || r.contains("not a catalogued"),
                    "{r}"
                );
            }
            other => panic!("expected refuse BHB68603, got {other:?}"),
        }
        assert!(s19k_claim_from_pinned_corpus("BHB68603").is_none());
    }

    #[test]
    fn admits_bhb56903_fabric_has_pic_false() {
        let mut claim = good_claim();
        claim.board_name = "BHB56903";
        match admit_s19k_nopic_profile(claim) {
            S19kNoPicAdmission::AdmittedFabric {
                board_name, mining, ..
            } => {
                assert_eq!(board_name, "BHB56903");
                assert_eq!(mining, S19kMiningDisposition::NativeOwnerRequired);
            }
            other => panic!("expected admit BHB56903, got {other:?}"),
        }
        // topol chain.pic / vendor PIC1704 must not become voltage-owner authority
        if let Some(c) = s19k_claim_from_pinned_corpus("BHB56903") {
            assert!(!c.has_pic);
            assert!(!c.offers_pic_voltage_owner);
        }
        assert!(matches!(
            admit_s19k_nopic_profile({
                let mut c = good_claim();
                c.board_name = "BHB68603";
                c
            }),
            S19kNoPicAdmission::Refused(_)
        ));
    }

    #[test]
    fn lm75_before_probe_phase_order_is_enforced() {
        let mut latch = S19kNopicFabricPhaseLatch::new();
        assert!(latch
            .advance(S19kNopicFabricPhase::AsicProbe)
            .unwrap_err()
            .contains("LM75-before-probe"));
        latch
            .advance(S19kNopicFabricPhase::IdentityAdmitted)
            .expect("identity");
        assert!(latch
            .advance(S19kNopicFabricPhase::AsicProbe)
            .unwrap_err()
            .contains("CtrlBoardLm75BeforeProbe"));
        latch
            .advance(S19kNopicFabricPhase::CtrlBoardLm75BeforeProbe)
            .expect("lm75");
        latch
            .advance(S19kNopicFabricPhase::AsicProbe)
            .expect("asic probe after lm75");
        assert_eq!(latch.highest(), Some(S19kNopicFabricPhase::AsicProbe));
    }

    #[test]
    fn pic_voltage_class_plus_claim_hard_fails_together() {
        assert!(is_forbidden_pic_voltage_class("DsPic33Ep"));
        let mut claim = good_claim();
        claim.offers_pic_voltage_owner = true;
        match admit_s19k_nopic_profile(claim) {
            S19kNoPicAdmission::Refused(r) => {
                assert!(r.contains("PIC") || r.contains("BM1362"), "{r}")
            }
            other => panic!("expected refuse, got {other:?}"),
        }
    }
}
