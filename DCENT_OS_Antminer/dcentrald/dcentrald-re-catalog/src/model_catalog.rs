use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    Exact,
    Structural,
    Scaffold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ModelEvidence {
    pub slug: &'static str,
    pub chip_id: u16,
    pub chains: u8,
    pub chips_per_chain: Option<u16>,
    pub default_baud: u32,
    pub response_body_len: usize,
    pub default_frequency_mhz: Option<u16>,
    pub voltage_min_mv: Option<u16>,
    pub voltage_max_mv: Option<u16>,
    pub strength: EvidenceStrength,
    pub provenance: &'static [&'static str],
}

const MASTER_MODELS: &str = "";
const MASTER_PLL: &str = "";
const S17_JIG: &str = "";
const S19_JIG: &str = "";
const S21_PRO_JIG: &str = "";

macro_rules! model {
    ($slug:literal, $chip:literal, $chains:literal, $count:expr, $baud:literal,
     $body:literal, $freq:expr, $vmin:expr, $vmax:expr, $strength:ident, $sources:expr) => {
        ModelEvidence {
            slug: $slug,
            chip_id: $chip,
            chains: $chains,
            chips_per_chain: $count,
            default_baud: $baud,
            response_body_len: $body,
            default_frequency_mhz: $freq,
            voltage_min_mv: $vmin,
            voltage_max_mv: $vmax,
            strength: EvidenceStrength::$strength,
            provenance: $sources,
        }
    };
}

/// S9 through S23 coverage rows used by the simulator and tier-honesty gate.
/// Unknown geometry remains `None`; it is never filled from projections.
pub static ANTMINER_MODELS: &[ModelEvidence] = &[
    model!("s9", 0x1387, 3, Some(63), 115_200, 7, Some(650), Some(8_000), Some(9_000), Exact, &[MASTER_MODELS, MASTER_PLL, ""]),
    // Evidence-only marketing variant. This records held identity/geometry; it
    // does not alias S9i into the callable am1-s9 runtime or install route.
    model!("s9i", 0x1387, 3, Some(63), 115_200, 7, Some(500), None, None, Exact, &[MASTER_MODELS, ""]),
    model!("s9j", 0x1387, 3, Some(63), 115_200, 7, None, None, None, Exact, &[MASTER_MODELS, ""]),
    // The S9k's unstripped miner proves this ASIC/population tuple. This is
    // evidence coverage only: `BoardDesc::am1_s9k` deliberately keeps carrier,
    // voltage and install authority closed.
    model!("s9k", 0x1393, 3, Some(60), 115_200, 9, None, None, None, Exact, &[MASTER_MODELS, ""]),
    model!("s11", 0x1391, 3, None, 115_200, 7, None, None, None, Structural, &[MASTER_MODELS, ""]),
    model!("s15", 0x1391, 3, None, 115_200, 7, None, None, None, Scaffold, &[MASTER_MODELS]),
    model!("t15", 0x1391, 3, None, 115_200, 7, None, None, None, Scaffold, &[MASTER_MODELS]),
    model!("s17", 0x1397, 3, Some(48), 115_740, 7, Some(650), None, None, Exact, &[MASTER_MODELS, MASTER_PLL, S17_JIG]),
    model!("s17pro", 0x1397, 3, Some(48), 115_740, 7, Some(650), None, None, Exact, &[MASTER_MODELS, MASTER_PLL, S17_JIG]),
    model!("t17", 0x1397, 3, Some(30), 115_740, 7, Some(650), None, None, Exact, &[MASTER_MODELS, MASTER_PLL, S17_JIG]),
    // 2026-08-03 mapping correction (W8-G): S17+/T17+ are BM1397 (0x1397) and
    // S17e/T17e are BM1396 (0x1396). The reversed pairing came from PR-056
    // (`2026-05-16-bm1396-vs-bm1397-disambiguation.md`), whose model attribution
    // is circular (it traced only to two comment lines) and is now retracted in
    // that document's correction banner. Chip COUNTS are unchanged.
    model!("s17plus", 0x1397, 3, Some(65), 115_740, 7, None, None, None, Structural, &[MASTER_MODELS, ""]),
    model!("t17plus", 0x1397, 3, Some(44), 115_740, 7, None, None, None, Structural, &[MASTER_MODELS, ""]),
    model!("s17e", 0x1396, 3, None, 115_740, 7, None, None, None, Structural, &[MASTER_MODELS, "", ""]),
    model!("t17e", 0x1396, 3, Some(78), 115_740, 7, None, None, None, Structural, &[MASTER_MODELS, ""]),
    model!("s19", 0x1398, 3, None, 115_740, 7, Some(650), None, None, Structural, &[MASTER_MODELS, MASTER_PLL, S19_JIG]),
    model!("s19pro", 0x1398, 3, Some(114), 115_740, 7, Some(675), Some(13_000), Some(14_200), Exact, &[MASTER_MODELS, MASTER_PLL, S19_JIG, ""]),
    model!("s19a", 0x1398, 3, Some(114), 115_740, 7, None, None, None, Exact, &[MASTER_MODELS]),
    model!("s19apro", 0x1398, 3, Some(114), 115_740, 7, None, None, None, Exact, &[MASTER_MODELS]),
    // Gauntlet B5b (2026-09-02) — identity corrected from the refuted
    // "0x1398 Exact" row (which claimed S19 Pro geometry): Bitmain's own
    // s19i-20210427 stock topol states machine NBS2003 = BM1360
    // (asic_addr "0x1360"), 80 ASICs/chain (8x10 grid), 40 dom x2, interval 3,
    // 156+624 cores. Downgraded Exact -> Structural: the identity+geometry are
    // stock-exact, but NO BM1360 protocol detail is held (baud/response body
    // below remain the inherited placeholders, not evidence — B-lane Ghidra
    // owns the stripped s19i bmminer). Adjudication: PHASE_A_EVIDENCE_REPORT.md
    // §2.3/§3.5; roster evidence note row 29 (BETA_ROSTER.md).
    model!("s19i", 0x1360, 3, Some(80), 115_740, 7, None, None, None, Structural, &[MASTER_MODELS, ""]),
    // Gauntlet B5b (2026-09-02) — identity corrected from the refuted
    // "0x1398 Structural" row: Bitmain's own S19j-merge topology DB states
    // BHB42701 = BM1362 (asic_addr "0x1362"), 108 ASICs/chain (12x9 grid),
    // 36 dom x3, interval 2. Sources: the stock tree (below) and the pinned
    // transcription `dcentrald-silicon-profiles/src/s19_family_stock_topol.rs`
    // (topol sha256 61a6404b...). Same BM1362 probe-baud/response family as
    // the sibling s19jpro row. Adjudication: PHASE_A_EVIDENCE_REPORT.md §3.6.
    model!("s19j", 0x1362, 3, Some(108), 115_200, 9, None, None, None, Exact, &[MASTER_MODELS, ""]),
    model!("s19jpro", 0x1362, 3, Some(126), 115_200, 9, Some(545), None, None, Exact, &[MASTER_MODELS, MASTER_PLL, ""]),
    model!("s19jplus", 0x1362, 3, Some(110), 115_200, 9, None, None, None, Exact, &[MASTER_MODELS]),
    model!("s19xp", 0x1366, 3, Some(110), 115_200, 9, Some(675), Some(13_400), Some(14_200), Exact, &[MASTER_MODELS, MASTER_PLL, ""]),
    model!("s19jxp", 0x1366, 3, Some(110), 115_200, 9, Some(675), Some(13_400), Some(14_200), Exact, &[MASTER_MODELS, MASTER_PLL, "DCENT_OS_Antminer/dcentrald/dcentrald-silicon-profiles/src/hashboard_catalog.rs:462", ""]),
    model!("s19kpro", 0x1366, 3, Some(77), 115_200, 9, Some(670), Some(13_400), Some(14_200), Exact, &[MASTER_MODELS, MASTER_PLL, ""]),
    model!("s21", 0x1368, 3, Some(108), 115_200, 9, Some(525), Some(13_400), Some(14_200), Exact, &[MASTER_MODELS, MASTER_PLL, ""]),
    model!("s21pro", 0x1370, 3, Some(65), 115_200, 9, Some(525), Some(13_400), Some(14_200), Exact, &[MASTER_MODELS, MASTER_PLL, S21_PRO_JIG]),
    model!("s21xp", 0x1370, 3, Some(91), 115_200, 9, None, Some(13_400), Some(14_200), Exact, &[MASTER_MODELS, MASTER_PLL, S21_PRO_JIG, "DCENT_OS_Antminer/dcentrald/dcentrald-silicon-profiles/src/hashboard_catalog.rs"]),
    model!("s23", 0x1372, 4, None, 115_200, 9, None, None, None, Scaffold, &[""]),
];

pub fn model_evidence(slug: &str) -> Option<&'static ModelEvidence> {
    ANTMINER_MODELS.iter().find(|model| model.slug == slug)
}

#[cfg(test)]
mod tests {
    // clippy: the workspace sets `unwrap_used` / `expect_used` / `indexing_slicing`
    // to `warn` and CI runs `-D warnings`. Inside a test module those lints are
    // inverted: panicking IS the assertion mechanism, and a catalog row that is
    // absent when a pin says it must exist should fail the test loudly rather than
    // be silently `if let`-ed away. Scoped to `mod tests` only — production code in
    // this crate stays under the full restriction set.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn coverage_rows_are_unique_and_s23_stays_ground_truth_free() {
        for (index, model) in ANTMINER_MODELS.iter().enumerate() {
            assert!(ANTMINER_MODELS[..index]
                .iter()
                .all(|other| other.slug != model.slug));
            assert!(!model.provenance.is_empty());
        }
        let s23 = model_evidence("s23").expect("S23 reservation");
        assert_eq!(s23.strength, EvidenceStrength::Scaffold);
        assert_eq!(s23.chips_per_chain, None);
        assert_eq!(s23.default_frequency_mhz, None);
    }

    #[test]
    fn catalog_shape_strength_counts_and_provenance_are_pinned() {
        assert_eq!(ANTMINER_MODELS.len(), 29);
        assert_eq!(
            ANTMINER_MODELS
                .iter()
                .filter(|row| row.strength == EvidenceStrength::Exact)
                .count(),
            19
        );
        assert_eq!(
            ANTMINER_MODELS
                .iter()
                .filter(|row| row.strength == EvidenceStrength::Structural)
                .count(),
            7
        );
        assert_eq!(
            ANTMINER_MODELS
                .iter()
                .filter(|row| row.strength == EvidenceStrength::Scaffold)
                .count(),
            3
        );
        for row in ANTMINER_MODELS {
            assert!(row.chains > 0);
            assert!(row.default_baud > 0);
            assert!(row.response_body_len > 0);
            assert!(!row.provenance.is_empty());
            for source in row.provenance {
                assert!(!source.trim().is_empty());
                assert!(!source.starts_with('/'));
                assert!(!source.contains(".."));
                assert!(!source.contains('\\'));
            }
        }
    }

    /// The S17-class model -> chip-family mapping, pinned in both directions so
    /// a future edit cannot silently re-reverse it.
    ///
    /// HISTORY — this reversal was live in the repository for ~2.5 months. Its
    /// source is PR-056,
    /// ,
    /// which recorded `0x1396` = S17+/T17+ and `0x1397` = S17/T17/S17e/T17e. That
    /// mapping was CIRCULAR: it traced only to two in-repo comment lines
    /// (`dcentrald-asic/src/bm1393.rs:172` and
    /// `dcentrald-silicon-profiles/src/asics.rs:155`), and the document itself
    /// states it had no measurement behind it ("Empirical readback: UNKNOWN --
    /// needs hardware"). Worse, PR-056 §3/§5 declared the then-correct
    /// `drivers/bm1396.rs` "T17e/S17e-era" header a stray mis-attribution and
    /// "corrected" it to S17+/T17+, which is what later readers kept adopting.
    /// PR-056's model attribution is retracted (see its correction banner); its
    /// dispatch-safety verdict still stands and is unaffected by this test.
    ///
    /// Operator-confirmed 2026-08-03: S17+/T17+ = BM1397 (`0x1397`),
    /// S17e/T17e = BM1396 (`0x1396`). Corroborated by
    /// :16,18` and
    /// :31`
    /// (Bitmain AMTC maintenance guide: T17e = 78 chips, 13 domains x 6, 1.35 V).
    ///
    /// This pins IDENTITY only. It says nothing about driver dispatch: BM1396
    /// stays unregistered in `ChipRegistry` and `detect(0x1396)` still returns
    /// `None` (pinned separately by `pr056_bm1396_vs_bm1397_disambiguation` in
    /// `dcentrald-asic/src/drivers/mod.rs`).
    #[test]
    fn bm1396_bm1397_model_mapping_is_not_reversed() {
        // The "+" variants are BM1397. Positive assertion...
        for slug in ["s17plus", "t17plus"] {
            let row = model_evidence(slug).expect("plus-variant row");
            assert_eq!(
                row.chip_id, 0x1397,
                "{slug} must be BM1397 (0x1397); 0x1396 is the PR-056 reversal"
            );
            // ...and the explicit negative, so a swap cannot pass by accident.
            assert_ne!(
                row.chip_id, 0x1396,
                "{slug} must NOT be BM1396 -- that is the retracted PR-056 mapping"
            );
        }

        // The "e" variants are BM1396. Only S17e has a catalog row today; T17e
        // is carried by `DCENT_OS_Antminer/scripts/hw-acceptance/skus.conf`
        // (chip BM1396, chip_id capture-first) and has no row here yet. If a
        // t17e row is ever added it must land on 0x1396, which this loop then
        // enforces automatically.
        for slug in ["s17e", "t17e"] {
            let Some(row) = model_evidence(slug) else {
                continue;
            };
            assert_eq!(
                row.chip_id, 0x1396,
                "{slug} must be BM1396 (0x1396); 0x1397 is the PR-056 reversal"
            );
            assert_ne!(
                row.chip_id, 0x1397,
                "{slug} must NOT be BM1397 -- that is the retracted PR-056 mapping"
            );
        }

        // Base S17 / S17 Pro / T17 were never in dispute and stay BM1397. Pinned
        // so a future "fix" cannot drag them along with the corrected variants.
        for slug in ["s17", "s17pro", "t17"] {
            assert_eq!(
                model_evidence(slug).expect("base S17-class row").chip_id,
                0x1397,
                "{slug} is BM1397 and was never part of the reversal"
            );
        }

        // Chip COUNTS are an independent fact and must survive the correction.
        //
        // Operator-confirmed 2026-08-03, pinned for the WHOLE S17 era because the
        // 48-vs-65 pair is actively mis-stated in a source we otherwise trust:
        //  §3.2 headed
        // its S17+ profile table "3 chains x 48 chips". **48 is the S17 / S17 Pro
        // geometry, not the S17+.** Anyone reconciling code against that header
        // would drag s17plus from 65 down to 48. These asserts stop that.
        //
        //   S17, S17 Pro -> 3 x 48 = 144      S17+ -> 3 x 65 = 195
        //   T17          -> 3 x 30 =  90      T17+ -> 3 x 44 = 132
        //
        // (That same header's CHIP FAMILY half — "S17+ (BM1397)" — is correct and
        // is one of the four sources that overturned the PR-056 reversal above.
        // Trust its family, distrust its count.)
        for (slug, expected, total) in [
            ("s17", 48u16, 144u16),
            ("s17pro", 48, 144),
            ("s17plus", 65, 195),
            ("t17", 30, 90),
            ("t17plus", 44, 132),
        ] {
            let m = model_evidence(slug).expect("S17-era row");
            assert_eq!(
                m.chips_per_chain,
                Some(expected),
                "{slug} geometry is {}x{expected}={total} regardless of chip family",
                m.chains
            );
            assert_eq!(
                m.chains as u16 * expected,
                total,
                "{slug} chains x chips/chain must equal {total}"
            );
        }

        // The two chip IDs must never collapse into one another.
        assert_ne!(0x1396, 0x1397);
    }

    /// Voltage bounds must be ordered where both are present. An inverted or
    /// degenerate range (min >= max) would break any consumer that clamps a
    /// commanded voltage into `[voltage_min_mv, voltage_max_mv]` — a real safety
    /// hazard on a catalog that drives voltage envelopes. Guards new rows.
    #[test]
    fn voltage_bounds_are_ordered_when_present() {
        for m in ANTMINER_MODELS {
            if let (Some(lo), Some(hi)) = (m.voltage_min_mv, m.voltage_max_mv) {
                assert!(
                    lo < hi,
                    "{} voltage bounds inverted/degenerate: min_mv={lo} >= max_mv={hi}",
                    m.slug
                );
            }
        }
    }

    /// Every model row with EXACT evidence AND a proven default frequency must
    /// carry PLL facts in the sibling pll_bible (keyed by chip_id): if we have a
    /// proven operating frequency, we must also have the PLL register facts to
    /// program it. Catches a contributor adding an Exact chip to one catalog but
    /// not the other (the class that hid the BM1368 500-vs-525 drift). Chips
    /// without a proven frequency (Structural/Scaffold, freq None) are exempt —
    /// we never fabricate PLL facts we do not have.
    #[test]
    fn exact_models_with_a_frequency_have_pll_facts() {
        use crate::pll_bible::pll_expectation;
        for m in ANTMINER_MODELS {
            if m.strength == EvidenceStrength::Exact && m.default_frequency_mhz.is_some() {
                assert!(
                    pll_expectation(m.chip_id).is_some(),
                    "{} is Exact with a proven frequency ({} MHz) but chip_id {:#06x} has no \
                     pll_bible entry — a proven-frequency chip must carry PLL register facts",
                    m.slug,
                    m.default_frequency_mhz.unwrap(),
                    m.chip_id
                );
            }
        }
    }
}
