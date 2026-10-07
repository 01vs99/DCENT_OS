//! UB-26 (2026-08-03): declarative hashboard **identity** catalog — 61 SKUs
//! (50 v1.22.0 + the 11-row v1.24.0 delta, W3 2026-08-25), keyed by exact
//! `model_id`.
//!
//! # What this is, and what problem it closes
//!
//! [`crate::hashboards::HashboardCatalogEntry`] is the cross-chip identity row
//! (`sku` → chip name + chips/chain + EEPROM preamble + products it ships in).
//! It is reachable only through the [`crate::hashboards::Hashboard`] **enum**,
//! which carries **20** variants — 16 real Bitmain SKUs plus 4 pre-AT24C02D
//! placeholders. The held roster is **61** SKUs (50 from the v1.22.0 ePIC jig
//! DB + the 11 new-in-v1.24.0 base ids decoded from the v1.24.0 amlogic
//! `bms-miner`), so **45 catalogued hashboards have no identity row in the
//! enum** (34 per H3 §1.1 + the 11 v1.24.0 delta SKUs; the older "32 missing"
//! figure counts against ePIC's 48 published `model_id`s and omits
//! `NBP1901`/`NBS1902`).
//!
//! This module supplies those 45 as **data**, not code. Adding hashboard #51
//! is a row in `hashboard_topology_v1_22_0.json` (or, as the v1.24.0 delta
//! proved, a row in `hashboard_topology_v1_24_0_delta.json`) — zero enum
//! variants, zero `match` arms, zero prefix edits. The legacy enum and its
//! `catalog()` are **untouched and still authoritative** wherever they have
//! a row.
//!
//! # Composition, not duplication — every field is traceable to a corpus
//!
//! No value in this module is typed in by hand. Each row is JOINED at first
//! use from three already-checked-in, independently-sourced tables:
//!
//! | Source | Provenance | Supplies |
//! |---|---|---|
//! | [`crate::hashboards::Hashboard::catalog`] | DCENT (live-probe / DCENT-RE) | `chip_name` + `chips_per_chain` for the 16 overlapping SKUs. **Wins any conflict.** |
//! | [`crate::hashboard_topology`] (ePIC UMC OS v1.22.0 jig DB) | [`DescriptorProvenance::DeskJigDbExperimental`] | `chip_name` + `chips_per_chain` for the other 34; `observed_eeprom_preambles` for all 50 |
//! | [`crate::vnish_thermal`] (VNish 1.2.7 `hwscan` model JSONs) | [`DescriptorProvenance::DeskVnishFirmwareExperimental`] | candidate [`HashboardIdentityRow::used_in`] values and independent `chips_per_chain` corroboration; ambiguous unified-firmware BHB427/BHB428 bindings are suppressed |
//!
//! Because the join is computed, a corrected JSON row propagates here with no
//! second edit — the class of drift that a hand-copied second table invites
//! cannot occur.
//!
//! # Five rules this table obeys (each prevents a defect this axis already had)
//!
//! 1. **Exact `model_id` keys. NO prefix patterns, ever.** Lookup is a hash of
//!    the exact string; a miss is `None`. The `BHB68xxx → BM1370` catch-all in
//!    [`dcentrald_api_types::eeprom_record::BHB_SKU_CATALOG`] is precisely the
//!    failure mode this retires: a prefix pattern silently answered for 6
//!    BM1368 SKUs it had never seen. Pinned by
//!    `lookup_is_exact_and_never_matches_a_prefix`.
//! 2. **Provenance is a column, not a comment.** Every row carries
//!    [`HashboardIdentityRow::authority`] plus the list of desk corpora that
//!    independently agree. An ePIC-transcribed row can supply identity and
//!    geometry; it is never the sole authority for anything that energizes
//!    silicon, and it never outranks a DCENT measurement.
//! 3. **Unknown ⇒ `None`, never a sibling's value.** Rows without a unique
//!    model binding carry `used_in: None` — including
//!    `A3HB70605`/`70606`/`70607`, whose six `A3HB706xx` siblings are all
//!    "Antminer S21 Pro", and the corrected BHB42701/BHB428 rows whose VNish
//!    names come from a unified multi-model roster. Inheriting or promoting
//!    either would be a fabrication. Pinned by
//!    `used_in_is_absent_rather_than_inherited_from_a_sibling`.
//! 4. **No voltage, frequency, PLL, PSU or tuning field lives here.** Those
//!    stay in the per-chip PVT modules (`bm1362::BHB42601_FREQ_VOLT_TABLE`
//!    etc.), which are already the single source of truth. A descriptor row
//!    must never carry a V/F number, least of all one inherited from a sibling
//!    — "wrong calibration is worse than none". Pinned structurally: the row
//!    type has no such field.
//! 5. **No chain address stride is stored.** `addr_interval` is resolved
//!    through the DCENT SSOT
//!    ([`dcentrald_common::chain_transport::resolve_addr_interval`], declared
//!    table first and `floor(256/N)` fallback second) via
//!    [`HashboardIdentityRow::resolved_addr_interval`]. A per-row copy would
//!    be a second place for a stride to drift, and a wrong stride breaks chain
//!    enumeration. `A3HB40601` stays deliberately UNRESOLVED (jig 4 · ePIC 2 ·
//!    formula 7 — corroborated by nobody). Pinned by
//!    `stride_is_resolved_through_the_ssot_and_a3hb40601_stays_unresolved`.
//!
//! # Honest scope
//!
//! - **Identity and provenance only.** This table authorizes nothing. It mints
//!   no [`dcentrald_common::board_desc::AsicProtocolIdentity`], gates no
//!   install, and selects no driver. The runtime admission gate remains
//!   `dcentrald_api_types::hashboard_eeprom::DEPLOYED_SKU_IDENTITY_POLICY`,
//!   which is deliberately narrower (validated SKUs only) and is not widened
//!   by anything here.
//! - **The roster is v1.22.0 + the v1.24.0 delta.** Absence of a SKU proves
//!   nothing. The wider held corpus (VNish's 77 models — hydro/immersion,
//!   L7/L9 scrypt, BHB28xxx) is covered by [`crate::vnish_thermal`], keyed
//!   by `btm_model`. The v1.24.0 delta interacts with it three ways:
//!   8 of the 11 delta SKUs have no VNish row and stay `used_in: None`
//!   (rule 3); `M1HB70602` and `H6HB70801` have VNish rows whose geometry
//!   corroborates the ePIC decode exactly (91 and 85 chips/chain — the
//!   only two-source-corroborated delta rows) and contribute their VNish
//!   marketing names; and `BHB56701` CONFLICTS — ePIC says 70 chips/chain
//!   (10×7 grid, internally consistent), VNish says 110 — imported at the
//!   ePIC value with no VNish corroboration, conflict recorded and
//!   test-pinned, never reconciled desk-side.
//! - **`chains_per_unit` is deliberately NOT a column.** ePIC says `4` on the
//!   BHB42xxx/NB\* rows where VNish says `3` and DCENT live units have 3
//!   hashboard slots. Both sides are recorded verbatim in their own modules;
//!   promoting one into an "identity" row would silently pick a winner.

use std::collections::HashMap;
use std::sync::OnceLock;

use dcentrald_common::chain_transport::{AddrIntervalDecision, AddrIntervalError};
use serde::Serialize;

use crate::hashboard_topology::{all_descriptors, DescriptorProvenance, HashboardDescriptor};
use crate::hashboards::ALL_HASHBOARDS;
use crate::vnish_thermal::vnish_model_by_btm;

/// Which table a row's `chip_name` + `chips_per_chain` were taken from.
///
/// This is the adjudication result, not a confidence score: `DcentCatalog`
/// simply means a DCENT row exists and therefore wins. Where no DCENT row
/// exists the ePIC-transcribed value is used **and labelled as such** — it is
/// desk evidence, Experimental, and never authority for energizing silicon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAuthority {
    /// A [`crate::hashboards::Hashboard`] catalog row exists for this SKU
    /// (DCENT-RE'd from `pvt_tables.h`/factory jig, or live-probed — e.g.
    /// `BHB56902`'s 77 chips/chain from the `a lab unit` probe). DCENT values win
    /// every conflict with a third-party transcription.
    DcentCatalog,
    /// No DCENT catalog row exists. Values come from the ePIC UMC OS v1.22.0
    /// jig hashboard DB — Bitmain-derived but **ePIC-transcribed**, with known
    /// real transcription defects. Carries
    /// [`DescriptorProvenance::DeskJigDbExperimental`].
    EpicTranscribed,
}

/// One declarative hashboard identity row, keyed by exact Bitmain `model_id`.
///
/// Deliberately carries NO voltage, frequency, PLL, PSU, tuning, stride, or
/// `chains_per_unit` field — see the module docs, rules 4 and 5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HashboardIdentityRow {
    /// Exact Bitmain SKU string. The registry key; never a prefix or pattern.
    pub model_id: String,
    /// ASIC family in **DCENT spelling** (`BM1398`, not ePIC's `BM1398P`).
    pub chip_name: String,
    /// Adjudicated chips per hashboard chain. Equals
    /// [`Self::epic_declared_chips_per_chain`] on all 61 rows today (the one
    /// held conflict is with VNish, not ePIC — BHB56701, pinned in tests);
    /// the two
    /// are separate columns so a future DCENT correction is *visible* instead
    /// of silently overwriting the desk evidence.
    pub chips_per_chain: u16,
    /// The ePIC jig DB's own `chain_asic_num`, always present (all 61 roster
    /// rows are ePIC rows). Kept verbatim.
    pub epic_declared_chips_per_chain: u16,
    /// Where `chip_name` / `chips_per_chain` came from.
    pub authority: IdentityAuthority,
    /// Every desk corpus that **independently** declares the same
    /// `chips_per_chain`. Always contains the row's own source-DB
    /// provenance ([`DescriptorProvenance::DeskJigDbExperimental`] on the
    /// 50 v1.22.0 rows, [`DescriptorProvenance::DeskJigDbV124Experimental`]
    /// on the 11 delta rows); contains
    /// [`DescriptorProvenance::DeskVnishFirmwareExperimental`] on the 38
    /// rows the VNish 1.2.7 matrix also covers (BHB56701 is matrix-covered
    /// but conflicting, so it does not corroborate). Corroboration only —
    /// never used to *derive* a value.
    pub corroborating_desk_corpora: Vec<DescriptorProvenance>,
    /// Marketing product this board ships in (VNish `marketing_name`).
    /// **`None` on 27 of 61 rows** = no held corpus names a product for this
    /// SKU. Never inherited from a sibling SKU (module docs, rule 3).
    pub used_in: Option<String>,
    /// Provenance of [`Self::used_in`]; `None` exactly when `used_in` is
    /// `None`.
    pub used_in_provenance: Option<DescriptorProvenance>,
    /// EEPROM preambles **actually observed** on held decoded pages for this
    /// SKU. Attestation only, never an identity gate: empty means "no held
    /// sample" (not "no preamble"), and a SKU may carry more than one —
    /// `BHB56801` is held as BOTH format 4 (`04 11`) and format 5 (`05 11`),
    /// which is the standing proof that a SKU does not map to a format.
    pub observed_eeprom_preambles: Vec<[u8; 2]>,
    /// Whether a [`crate::hashboards::Hashboard`] enum variant exists for this
    /// SKU today. `false` on exactly the 45 rows this module adds (34
    /// v1.22.0 + 11 v1.24.0 delta).
    pub has_legacy_enum_variant: bool,
}

impl HashboardIdentityRow {
    /// `true` when the ePIC jig DB is the **only** authority for this row's
    /// identity — i.e. no DCENT catalog row exists. Consumers that require a
    /// DCENT-measured basis must refuse these.
    pub fn is_epic_transcribed_only(&self) -> bool {
        self.authority == IdentityAuthority::EpicTranscribed
    }

    /// The declared cooling medium for this hashboard SKU, resolved through
    /// the **hashboard-code discriminator** (B11,
    /// [`crate::hydro_fleet::cooling_medium_for_hashboard_code`]).
    ///
    /// This is the layer the `board_desc.rs` `cooling_medium` doc comment
    /// points at: cooling medium is a hashboard/chassis facet, never a
    /// control-board facet, and `BoardDesc::cooling_medium` stays `None`
    /// for every control-board row precisely so that THIS lookup — driven
    /// by the deployed hashboard's code — is the only thing that can ever
    /// resolve a medium.
    ///
    /// Fail-closed exactly like the discriminator: SKUs whose prefix is not
    /// in the pinned table resolve `None` (undeclared ⇒ fans stay managed,
    /// no bypass). The method adds no serialized field — the row's field
    /// set is deliberately unchanged.
    pub fn declared_cooling_medium(
        &self,
    ) -> Option<dcentrald_common::cooling_medium::CoolingMedium> {
        crate::hydro_fleet::cooling_medium_for_hashboard_code(&self.model_id)
    }

    /// Resolve this board's chain address stride through the DCENT SSOT.
    ///
    /// Delegates to [`crate::hashboard_topology::HashboardDescriptor::resolved_addr_interval`]
    /// so there is exactly ONE stride resolver in the tree: the adjudicated
    /// declared table first (a SKU is admitted there only when Bitmain's own
    /// factory-jig bucket rule and the ePIC DB independently agree), then the
    /// `floor(256/N)` fallback. This module stores no stride of its own.
    ///
    /// `None` when the row is missing from the topology registry (impossible
    /// today — the registry is this module's source) or when `chips_per_chain`
    /// does not fit a `u8`; callers fail closed rather than guess.
    pub fn resolved_addr_interval(
        &self,
    ) -> Option<Result<AddrIntervalDecision, AddrIntervalError>> {
        self.topology_descriptor()?.resolved_addr_interval()
    }

    /// Whether this board's stride is knowingly UNRESOLVED — a three-way
    /// source split that no two independent authorities settle, left on the
    /// computed fallback rather than guessed. `A3HB40601` is the only such row.
    pub fn addr_interval_is_unresolved(&self) -> bool {
        self.topology_descriptor()
            .map(HashboardDescriptor::addr_interval_is_unresolved)
            .unwrap_or(false)
    }

    /// The full ePIC topology descriptor backing this identity row (grid,
    /// domains, sensor banks, `tpl` placement). Identity rows stay narrow on
    /// purpose; the geometry lives there.
    pub fn topology_descriptor(&self) -> Option<&'static HashboardDescriptor> {
        crate::hashboard_topology::descriptor_by_sku(&self.model_id)
    }
}

struct Catalog {
    rows: Vec<HashboardIdentityRow>,
    by_model_id: HashMap<String, usize>,
}

fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        // The DCENT catalog side, indexed by SKU. `Hashboard::catalog()` is a
        // const fn over a closed enum, so this cannot fail at runtime.
        let dcent: HashMap<&'static str, (&'static str, u8)> = ALL_HASHBOARDS
            .iter()
            .map(|hb| {
                let c = hb.catalog();
                (c.sku, (c.chip_name, c.chips_per_chain))
            })
            .collect();

        let rows: Vec<HashboardIdentityRow> = all_descriptors()
            .iter()
            .map(|d| {
                let epic_chips = d.chain.chips_per_chain;
                let dcent_row = dcent.get(d.sku.as_str()).copied();

                // DCENT wins where it has a row; the ePIC value is retained in
                // its own column either way, so a divergence is visible rather
                // than overwritten. (There is none today — pinned below and by
                // `hashboard_topology::registry_never_silently_disagrees_with_the_live_catalog`.)
                let (chip_name, chips_per_chain, authority) = match dcent_row {
                    Some((chip, chips)) => (
                        chip.to_string(),
                        u16::from(chips),
                        IdentityAuthority::DcentCatalog,
                    ),
                    None => (
                        d.dcent_chip_name().to_string(),
                        epic_chips,
                        IdentityAuthority::EpicTranscribed,
                    ),
                };

                let vnish = vnish_model_by_btm(&d.sku);
                // The row's own source DB is always the primary corroboration
                // entry — DeskJigDbExperimental for v1.22.0 rows,
                // DeskJigDbV124Experimental for the 11 delta rows.
                let mut corroborating = vec![d.provenance];
                if vnish.is_some_and(|v| v.chips_per_chain == chips_per_chain) {
                    corroborating.push(DescriptorProvenance::DeskVnishFirmwareExperimental);
                }

                // VNish's BHB42701/BHB428 names are emitted by a unified
                // multi-model firmware roster, not a unique deployed
                // SKU-to-product observation. Exact held jig/pages prove
                // BM1362 identity only, so suppress those candidate marketing
                // names rather than converting co-location into authority.
                let model_binding_retracted = matches!(
                    d.sku.as_str(),
                    "BHB42701"
                        | "BHB42801"
                        | "BHB42803"
                        | "BHB42811"
                        | "BHB42821"
                        | "BHB42831"
                        | "BHB42841"
                );
                let used_in = if model_binding_retracted {
                    None
                } else {
                    vnish.map(|v| v.marketing_name.clone())
                };
                let used_in_provenance = used_in
                    .as_ref()
                    .map(|_| DescriptorProvenance::DeskVnishFirmwareExperimental);

                HashboardIdentityRow {
                    model_id: d.sku.clone(),
                    chip_name,
                    chips_per_chain,
                    epic_declared_chips_per_chain: epic_chips,
                    authority,
                    corroborating_desk_corpora: corroborating,
                    used_in,
                    used_in_provenance,
                    observed_eeprom_preambles: d.observed_eeprom_preambles.clone(),
                    has_legacy_enum_variant: dcent_row.is_some(),
                }
            })
            .collect();

        let by_model_id = rows
            .iter()
            .enumerate()
            .map(|(i, r)| (r.model_id.clone(), i))
            .collect();
        Catalog { rows, by_model_id }
    })
}

/// The total roster this catalog covers: 50 ePIC UMC OS v1.22.0 base
/// `model_id`s + the 11 new-in-v1.24.0 ids (W3, 2026-08-25). Any drift
/// between the checked-in topology data files and this constant turns
/// [`crate::hashboard_catalog::tests::roster_count_matches_the_pinned_constant`]
/// red — adding or removing a row without touching the constant (or vice
/// versa) is caught, never silent.
pub const CATALOG_ROSTER_COUNT: usize = 61;

/// Every identity row, sorted by `model_id` (50 v1.22.0 + 11 v1.24.0 delta).
pub fn all_hashboard_identities() -> &'static [HashboardIdentityRow] {
    &catalog().rows
}

/// Look up one hashboard by **exact** `model_id` (e.g. `"BHB68701"`).
///
/// No prefix, pattern, family, or fuzzy match — a miss returns `None` and the
/// caller must fail closed. This is the mechanism that retires
/// `dcentrald_api_types::eeprom_record::sku_matches_catalog_pattern`'s prefix
/// arms for roster SKUs.
pub fn hashboard_identity(model_id: &str) -> Option<&'static HashboardIdentityRow> {
    let c = catalog();
    c.by_model_id.get(model_id.trim()).map(|&i| &c.rows[i])
}

/// The chip family for an exact `model_id`, or `None`.
///
/// Exact-key counterpart to
/// [`dcentrald_api_types::eeprom_record::chip_family_for_sku`], which resolves
/// by prefix pattern and therefore also answers for SKUs nobody has ever seen.
/// This one answers only for the 50 roster SKUs.
pub fn chip_family_for_model_id(model_id: &str) -> Option<&'static str> {
    hashboard_identity(model_id).map(|r| r.chip_name.as_str())
}

/// All identity rows mounting the given chip family (DCENT spelling; ePIC's
/// `BM1398P` also accepted for convenience).
pub fn identities_for_chip(chip_name: &str) -> Vec<&'static HashboardIdentityRow> {
    let wanted = if chip_name == "BM1398P" {
        "BM1398"
    } else {
        chip_name
    };
    all_hashboard_identities()
        .iter()
        .filter(|r| r.chip_name == wanted)
        .collect()
}

/// All identity rows whose recorded product is `marketing_name` (exact match).
///
/// Rows with `used_in: None` never match anything — an unknown product is not
/// silently folded into a sibling's model.
pub fn identities_for_product(marketing_name: &str) -> Vec<&'static HashboardIdentityRow> {
    all_hashboard_identities()
        .iter()
        .filter(|r| r.used_in.as_deref() == Some(marketing_name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_common::chain_transport::AddrIntervalSource;

    /// Hand-transcribed expectation table — **the per-SKU test**, one line per
    /// row, as the queue's "one row + one test per SKU" standard asks.
    ///
    /// `chips_per_chain` was transcribed from the H3 deliverable's §1.1 table
    /// (
    /// H3-HASHBOARDS-EEPROM.md`) for the 34 new rows and from
    /// `hashboards.rs::catalog()` for the 16 legacy rows — i.e. from documents,
    /// NOT re-read out of the JSON the code under test parses. That is what
    /// makes this an independent check rather than a restatement.
    ///
    /// Columns: `model_id`, `chip_name`, `chips_per_chain`, `used_in`
    /// (`None` = no held corpus names a product), `observed preamble count`,
    /// `has_legacy_enum_variant`.
    const EXPECTED: &[(&str, &str, u16, Option<&str>, usize, bool)] = &[
        // --- BM1370 / A3HB (S21 Pro / S21 XP / S21+) — 13 rows, all NEW ---
        ("A3HB40601", "BM1370", 36, None, 0, false),
        ("A3HB70501", "BM1370", 91, Some("Antminer S21 XP"), 1, false),
        ("A3HB70502", "BM1370", 91, Some("Antminer S21 XP"), 0, false),
        ("A3HB70503", "BM1370", 91, Some("Antminer S21 XP"), 0, false),
        (
            "A3HB70601",
            "BM1370",
            65,
            Some("Antminer S21 Pro"),
            1,
            false,
        ),
        (
            "A3HB70602",
            "BM1370",
            65,
            Some("Antminer S21 Pro"),
            0,
            false,
        ),
        (
            "A3HB70603",
            "BM1370",
            65,
            Some("Antminer S21 Pro"),
            0,
            false,
        ),
        ("A3HB70605", "BM1370", 65, None, 0, false),
        ("A3HB70606", "BM1370", 65, None, 0, false),
        ("A3HB70607", "BM1370", 65, None, 0, false),
        ("A3HB70701", "BM1370", 55, Some("Antminer S21+"), 1, false),
        ("A3HB70702", "BM1370", 55, Some("Antminer S21+"), 0, false),
        ("A3HB70703", "BM1370", 55, Some("Antminer S21+"), 0, false),
        // --- BM1362 / BHB42xxx — 16 rows, 15 legacy + BHB42612 NEW ---
        (
            "BHB42601",
            "BM1362",
            126,
            Some("Antminer S19j Pro-A"),
            1,
            true,
        ),
        (
            "BHB42603",
            "BM1362",
            126,
            Some("Antminer S19j Pro"),
            1,
            true,
        ),
        ("BHB42611", "BM1362", 120, None, 0, true),
        (
            "BHB42612",
            "BM1362",
            120,
            Some("Antminer S19j Pro+"),
            1,
            false,
        ),
        (
            "BHB42621",
            "BM1362",
            126,
            Some("Antminer S19j Pro"),
            0,
            true,
        ),
        (
            "BHB42631",
            "BM1362",
            126,
            Some("Antminer S19j Pro"),
            1,
            true,
        ),
        ("BHB42632", "BM1362", 126, None, 0, true),
        (
            "BHB42641",
            "BM1362",
            126,
            Some("Antminer S19j Pro"),
            1,
            true,
        ),
        (
            "BHB42651",
            "BM1362",
            126,
            Some("Antminer S19j Pro"),
            1,
            true,
        ),
        ("BHB42701", "BM1362", 108, None, 1, true),
        ("BHB42801", "BM1362", 88, None, 1, true),
        ("BHB42803", "BM1362", 84, None, 0, true),
        ("BHB42811", "BM1362", 88, None, 0, true),
        ("BHB42821", "BM1362", 88, None, 0, true),
        ("BHB42831", "BM1362", 88, None, 1, true),
        ("BHB42841", "BM1362", 126, None, 0, true),
        // --- BM1366 / BHB56xxx — 11 rows, 10 NEW + BHB56902 legacy ---
        ("BHB56801", "BM1366", 110, Some("Antminer S19 XP"), 2, false),
        ("BHB56802", "BM1366", 110, Some("Antminer S19 XP"), 0, false),
        (
            "BHB56804",
            "BM1366",
            110,
            Some("Antminer S19j XP"),
            1,
            false,
        ),
        ("BHB56806", "BM1366", 110, Some("Antminer S19 XP"), 0, false),
        ("BHB56807", "BM1366", 110, None, 0, false),
        ("BHB56814", "BM1366", 110, None, 0, false),
        ("BHB56901", "BM1366", 77, None, 0, false),
        ("BHB56902", "BM1366", 77, Some("Antminer S19k Pro"), 1, true),
        (
            "BHB56903",
            "BM1366",
            77,
            Some("Antminer S19k Pro"),
            1,
            false,
        ),
        ("BHB56906", "BM1366", 77, None, 0, false),
        (
            "BHB56907",
            "BM1366",
            77,
            Some("Antminer S19k Pro"),
            0,
            false,
        ),
        // --- BM1368 / BHB68xxx — 8 rows, ALL NEW ---
        ("BHB68601", "BM1368", 108, None, 0, false),
        ("BHB68603", "BM1368", 108, Some("Antminer S21"), 1, false),
        ("BHB68606", "BM1368", 108, Some("Antminer S21"), 1, false),
        ("BHB68701", "BM1368", 108, Some("Antminer T21"), 1, false),
        ("BHB68703", "BM1368", 108, Some("Antminer T21"), 0, false),
        ("BHB68705", "BM1368", 108, None, 0, false),
        (
            "BHB68707",
            "BM1368",
            108,
            Some("Antminer S19 XP+"),
            0,
            false,
        ),
        (
            "BHB68709",
            "BM1368",
            108,
            Some("Antminer S19 XP+"),
            0,
            false,
        ),
        // --- BM1398 / NB* (the two non-`model_id` jig records) — both NEW ---
        ("NBP1901", "BM1398", 114, Some("Antminer S19 Pro"), 0, false),
        ("NBS1902", "BM1398", 76, Some("Antminer S19"), 0, false),
        // --- v1.24.0 delta (W3 2026-08-25): the 11 new-in-v1.24.0 base ids,
        // decoded from the amlogic bms-miner. `used_in` is None unless the
        // held VNish 1.2.7 matrix has a per-model row (it does for
        // BHB56701, H6HB70801, M1HB70602 — the latter two corroborating
        // the decode's geometry exactly). No held EEPROM pages, no legacy
        // enum variants. ---
        ("A3HB70505", "BM1370", 91, None, 0, false), // S21 XP
        ("A3HB70608", "BM1370", 65, None, 0, false), // S21 Pro+
        ("A3HB70609", "BM1370", 65, None, 0, false), // S21 Pro+
        ("A3HB70705", "BM1370", 55, None, 0, false), // S21++
        ("A3HB70707", "BM1370", 55, None, 0, false), // S21++
        ("A3HB70708", "BM1370", 55, None, 0, false), // S21++
        ("BHB56601", "BM1366", 99, None, 0, false),  // S19 XP
        (
            // VNish names it S19 XP but claims 110 chips/chain vs ePIC's
            // 70 — conflict pinned in
            // `bhb56701_vnish_chips_conflict_is_pinned_not_reconciled`.
            "BHB56701",
            "BM1366",
            70,
            Some("Antminer S19 XP"),
            0,
            false,
        ),
        (
            "H6HB70801",
            "BM1370",
            85,
            Some("Antminer S21e Hydro"),
            0,
            false,
        ),
        (
            "M1HB70602",
            "BM1370",
            91,
            Some("Antminer S21 XP Imm"),
            0,
            false,
        ),
        ("TS007", "BM1366", 80, None, 0, false), // S19 XP
    ];

    /// The 34 SKUs H3 §1.1 measured as having no `HashboardCatalogEntry`.
    /// Transcribed from that report's table, not recomputed from the code.
    const H3_MISSING_34: &[&str] = &[
        "A3HB40601",
        "A3HB70501",
        "A3HB70502",
        "A3HB70503",
        "A3HB70601",
        "A3HB70602",
        "A3HB70603",
        "A3HB70605",
        "A3HB70606",
        "A3HB70607",
        "A3HB70701",
        "A3HB70702",
        "A3HB70703",
        "BHB42612",
        "BHB56801",
        "BHB56802",
        "BHB56804",
        "BHB56806",
        "BHB56807",
        "BHB56814",
        "BHB56901",
        "BHB56903",
        "BHB56906",
        "BHB56907",
        "BHB68601",
        "BHB68603",
        "BHB68606",
        "BHB68701",
        "BHB68703",
        "BHB68705",
        "BHB68707",
        "BHB68709",
        "NBP1901",
        "NBS1902",
    ];

    /// The 11 new-in-v1.24.0 base model_ids (W3, 2026-08-25), transcribed
    /// from the L3 delta-mine roster adjudication — NOT recomputed from the
    /// topology data files this module joins.
    const V124_DELTA_11: &[&str] = &[
        "A3HB70505",
        "A3HB70608",
        "A3HB70609",
        "A3HB70705",
        "A3HB70707",
        "A3HB70708",
        "BHB56601",
        "BHB56701",
        "H6HB70801",
        "M1HB70602",
        "TS007",
    ];

    /// One assertion per SKU over every declared field. Mutating any single
    /// value in the underlying JSON, the join, or this table turns it red.
    #[test]
    fn every_row_matches_the_hand_transcribed_expectation_table() {
        assert_eq!(
            EXPECTED.len(),
            61,
            "expectation table must cover the roster"
        );
        for &(model_id, chip, chips, used_in, preambles, legacy) in EXPECTED {
            let row = hashboard_identity(model_id)
                .unwrap_or_else(|| panic!("{model_id} must have an identity row"));
            assert_eq!(row.chip_name, chip, "{model_id}: chip");
            assert_eq!(row.chips_per_chain, chips, "{model_id}: chips/chain");
            assert_eq!(row.used_in.as_deref(), used_in, "{model_id}: used_in");
            assert_eq!(
                row.observed_eeprom_preambles.len(),
                preambles,
                "{model_id}: held preamble samples"
            );
            assert_eq!(
                row.has_legacy_enum_variant, legacy,
                "{model_id}: legacy enum variant"
            );
        }
        // No extra rows beyond the table.
        assert_eq!(all_hashboard_identities().len(), EXPECTED.len());
    }

    #[test]
    fn catalog_covers_the_whole_roster_with_unique_keys() {
        assert_eq!(all_hashboard_identities().len(), CATALOG_ROSTER_COUNT);
        let mut seen = std::collections::HashSet::new();
        for r in all_hashboard_identities() {
            assert!(seen.insert(r.model_id.as_str()), "duplicate {}", r.model_id);
            assert_eq!(hashboard_identity(&r.model_id), Some(r));
        }
    }

    /// The drift catcher the W3 lane introduced: the roster count is pinned
    /// to a named constant so adding/removing a row in either topology data
    /// file without updating [`CATALOG_ROSTER_COUNT`] (or vice versa) is a
    /// test failure, never a silent gap.
    #[test]
    fn roster_count_matches_the_pinned_constant() {
        assert_eq!(all_hashboard_identities().len(), CATALOG_ROSTER_COUNT);
        assert_eq!(CATALOG_ROSTER_COUNT, 61);
    }

    /// The 45 rows this module adds are EXACTLY H3 §1.1's measured 34-set
    /// plus the 11 v1.24.0 delta ids — not 32 (that figure counts against
    /// ePIC's 48 published `model_id`s and drops `NBP1901`/`NBS1902`), and
    /// not padded with anything invented.
    #[test]
    fn the_new_rows_are_exactly_the_h3_34_plus_the_v1_24_0_delta_11() {
        let mut added: Vec<&str> = all_hashboard_identities()
            .iter()
            .filter(|r| !r.has_legacy_enum_variant)
            .map(|r| r.model_id.as_str())
            .collect();
        added.sort_unstable();
        let mut expected: Vec<&str> = H3_MISSING_34.to_vec();
        expected.extend_from_slice(V124_DELTA_11);
        expected.sort_unstable();
        assert_eq!(added.len(), 45);
        assert_eq!(added, expected);
        // ...and the complement is exactly the 16 that already had rows.
        assert_eq!(
            all_hashboard_identities()
                .iter()
                .filter(|r| r.has_legacy_enum_variant)
                .count(),
            16
        );
    }

    /// Rule 1. Lookup is EXACT. Every prefix, family label, truncation and
    /// superstring of a real SKU must miss — this is the property the
    /// `BHB68xxx → BM1370` catch-all did not have.
    #[test]
    fn lookup_is_exact_and_never_matches_a_prefix() {
        for probe in [
            "BHB68",
            "BHB686",
            "BHB68xxx",
            "BHB6860",
            "BHB686011",
            "BHB68606X",
            "BHB426",
            "BHB426xx",
            "BHB42",
            "A3HB7",
            "A3HB7xxxx",
            "A3HB706",
            "BHB569",
            "BHB56",
            "NBP",
            "NBP19011",
            "",
            "   ",
            "bhb68606",
        ] {
            assert_eq!(
                hashboard_identity(probe),
                None,
                "{probe:?} must not resolve — exact keys only"
            );
        }
        // Surrounding whitespace on an otherwise exact key is tolerated (the
        // decoded page is fixed-width and space-padded); nothing else is.
        assert!(hashboard_identity(" BHB68606 ").is_some());
        assert_eq!(chip_family_for_model_id("BHB68606"), Some("BM1368"));
        assert_eq!(chip_family_for_model_id("BHB68xxx"), None);
    }

    /// Rule 2. Every row carries its provenance, and the 45 ePIC-derived
    /// rows are labelled `EpicTranscribed` — never presented as measured.
    #[test]
    fn epic_derived_rows_carry_epic_transcribed_provenance() {
        for r in all_hashboard_identities() {
            // Every roster row is an ePIC row, so its own source DB is
            // always the primary corroboration entry: the v1.22.0 jig DB
            // for the 50 original rows, the v1.24.0 binary decode for the
            // 11 delta rows.
            let primary = if V124_DELTA_11.contains(&r.model_id.as_str()) {
                DescriptorProvenance::DeskJigDbV124Experimental
            } else {
                DescriptorProvenance::DeskJigDbExperimental
            };
            assert_eq!(
                r.corroborating_desk_corpora.first(),
                Some(&primary),
                "{}: missing its own source-DB provenance",
                r.model_id
            );
            // No row may claim a live-measured provenance — none qualifies.
            assert!(!r
                .corroborating_desk_corpora
                .contains(&DescriptorProvenance::LiveMeasuredDcent));
            let expected = if r.has_legacy_enum_variant {
                IdentityAuthority::DcentCatalog
            } else {
                IdentityAuthority::EpicTranscribed
            };
            assert_eq!(r.authority, expected, "{}", r.model_id);
            assert_eq!(r.is_epic_transcribed_only(), !r.has_legacy_enum_variant);
            // used_in provenance is present exactly when used_in is.
            assert_eq!(
                r.used_in.is_some(),
                r.used_in_provenance.is_some(),
                "{}",
                r.model_id
            );
            if let Some(p) = r.used_in_provenance {
                assert_eq!(p, DescriptorProvenance::DeskVnishFirmwareExperimental);
            }
        }
        assert_eq!(
            all_hashboard_identities()
                .iter()
                .filter(|r| r.is_epic_transcribed_only())
                .count(),
            45
        );
    }

    /// Rule 3, the sharpest form: `A3HB70605`/`70606`/`70607` sit between six
    /// siblings all recorded as "Antminer S21 Pro", and every geometry field
    /// they have is identical to those siblings — yet no held corpus names
    /// their product, so they stay `None`. The corrected BHB42701/BHB428 rows
    /// also stay `None` because their VNish names are unified-roster
    /// co-location, not unique product observations. 8 of the 11 v1.24.0
    /// delta rows stay `None` too: no held corpus names their product
    /// (the ePIC READMEs are not an independent product corpus, and rule 3
    /// bars inheriting the family name their `model_name` implies).
    #[test]
    fn used_in_is_absent_rather_than_inherited_from_a_sibling() {
        let mut unnamed: Vec<&str> = all_hashboard_identities()
            .iter()
            .filter(|r| r.used_in.is_none())
            .map(|r| r.model_id.as_str())
            .collect();
        unnamed.sort_unstable();
        assert_eq!(
            unnamed,
            [
                "A3HB40601",
                "A3HB70505",
                "A3HB70605",
                "A3HB70606",
                "A3HB70607",
                "A3HB70608",
                "A3HB70609",
                "A3HB70705",
                "A3HB70707",
                "A3HB70708",
                "BHB42611",
                "BHB42632",
                "BHB42701",
                "BHB42801",
                "BHB42803",
                "BHB42811",
                "BHB42821",
                "BHB42831",
                "BHB42841",
                "BHB56601",
                "BHB56807",
                "BHB56814",
                "BHB56901",
                "BHB56906",
                "BHB68601",
                "BHB68705",
                "TS007",
            ],
            "the unnamed set drifted — a product name was either found or invented"
        );
        // The temptation, made explicit: identical geometry, named sibling,
        // still None.
        let named = hashboard_identity("A3HB70601").unwrap();
        for orphan in ["A3HB70605", "A3HB70606", "A3HB70607"] {
            let r = hashboard_identity(orphan).unwrap();
            assert_eq!(r.chips_per_chain, named.chips_per_chain);
            assert_eq!(r.chip_name, named.chip_name);
            assert_eq!(r.used_in, None, "{orphan} must not inherit a product name");
        }
        assert_eq!(named.used_in.as_deref(), Some("Antminer S21 Pro"));
        // A product query returns only rows that actually name it.
        assert_eq!(identities_for_product("Antminer S21 Pro").len(), 3);
        assert_eq!(identities_for_product("Antminer S19 XP+").len(), 2);
        assert!(identities_for_product("Antminer S9").is_empty());
    }

    /// No `chips_per_chain` is invented: the adjudicated value equals the ePIC
    /// declaration on all 50 rows, and where VNish also covers the SKU it
    /// agrees too. If a DCENT correction ever diverges from ePIC this goes red
    /// and forces an explicit adjudication instead of a silent overwrite.
    #[test]
    fn no_chips_per_chain_is_invented_and_the_two_corpora_agree() {
        let mut vnish_corroborated = 0;
        for r in all_hashboard_identities() {
            assert_eq!(
                r.chips_per_chain, r.epic_declared_chips_per_chain,
                "{}: DCENT/ePIC chips-per-chain diverged — re-adjudicate, do not overwrite",
                r.model_id
            );
            if r.corroborating_desk_corpora
                .contains(&DescriptorProvenance::DeskVnishFirmwareExperimental)
            {
                vnish_corroborated += 1;
                let v = crate::vnish_thermal::vnish_model_by_btm(&r.model_id)
                    .expect("corroboration implies a VNish row");
                assert_eq!(v.chips_per_chain, r.chips_per_chain, "{}", r.model_id);
            }
        }
        // 36 of the 50 v1.22.0-roster SKUs appear in the VNish 1.2.7 matrix
        // and all agree; the v1.24.0 delta adds two more corroborated rows
        // (M1HB70602, H6HB70801) — the third VNish-overlapping delta SKU,
        // BHB56701, conflicts (110 vs 70 chips/chain) and is pinned, not
        // reconciled, in the test below. 38 of 61, zero conflicts elsewhere.
        assert_eq!(vnish_corroborated, 38);
    }

    /// Rule 5. No stride is stored here; resolution goes through the SSOT, and
    /// the deliberately-unresolved row stays unresolved.
    #[test]
    fn stride_is_resolved_through_the_ssot_and_a3hb40601_stays_unresolved() {
        // Two-source-corroborated declarations resolve to 2, not the formula's 3.
        // `BHB68601` (108 chips) reaches the same 2 by agreement, so it stays on
        // the computed fallback — a declaration is only recorded where the
        // sources actually disagree with the formula.
        for (sku, source) in [
            ("BHB56902", AddrIntervalSource::BoardDeclared),
            ("A3HB70601", AddrIntervalSource::BoardDeclared),
            ("BHB68601", AddrIntervalSource::ComputedFallback),
        ] {
            let d = hashboard_identity(sku)
                .unwrap()
                .resolved_addr_interval()
                .expect("fits u8")
                .expect("addressable");
            assert_eq!(d.interval, 2, "{sku}");
            assert_eq!(d.source, source, "{sku}");
        }
        // The three-way split (jig 4 · ePIC 2 · formula 7) is never guessed.
        let a = hashboard_identity("A3HB40601").unwrap();
        assert!(a.addr_interval_is_unresolved());
        assert_eq!(
            a.resolved_addr_interval()
                .expect("fits u8")
                .expect("addressable")
                .source,
            AddrIntervalSource::ComputedFallback
        );
        // Exactly one row is unresolved across the whole catalog.
        assert_eq!(
            all_hashboard_identities()
                .iter()
                .filter(|r| r.addr_interval_is_unresolved())
                .count(),
            1
        );
    }

    /// The identity row is narrow ON PURPOSE (rules 4 and 5). This pins the
    /// serialized field set so a future "just add a default voltage" edit is a
    /// deliberate, reviewed act rather than a drive-by.
    #[test]
    fn the_row_carries_no_tuning_power_or_stride_field() {
        let row = hashboard_identity("BHB42601").unwrap();
        let json = serde_json::to_value(row).unwrap();
        let obj = json.as_object().expect("row serializes to an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "authority",
                "chip_name",
                "chips_per_chain",
                "corroborating_desk_corpora",
                "epic_declared_chips_per_chain",
                "has_legacy_enum_variant",
                "model_id",
                "observed_eeprom_preambles",
                "used_in",
                "used_in_provenance",
            ],
            "identity-row field set changed — voltage/frequency/PSU/stride \
             fields belong in the PVT modules and the chain-transport SSOT"
        );
    }

    /// Chip names use DCENT spelling so a caller can match them against the
    /// chip modules directly. ePIC writes `BM1398P`; we write `BM1398`.
    #[test]
    fn chip_names_use_dcent_spelling_and_family_counts_hold() {
        for sku in ["NBP1901", "NBS1902"] {
            assert_eq!(hashboard_identity(sku).unwrap().chip_name, "BM1398");
        }
        assert_eq!(identities_for_chip("BM1362").len(), 16);
        assert_eq!(identities_for_chip("BM1366").len(), 14);
        assert_eq!(identities_for_chip("BM1368").len(), 8);
        assert_eq!(identities_for_chip("BM1370").len(), 21);
        assert_eq!(identities_for_chip("BM1398").len(), 2);
        // ePIC's own spelling resolves to the same two rows.
        assert_eq!(identities_for_chip("BM1398P").len(), 2);
        assert_eq!(
            identities_for_chip("BM1362").len()
                + identities_for_chip("BM1366").len()
                + identities_for_chip("BM1368").len()
                + identities_for_chip("BM1370").len()
                + identities_for_chip("BM1398").len(),
            CATALOG_ROSTER_COUNT
        );
    }

    /// Preambles are attestation, never identity: a SKU with two held pages
    /// carries two, an unattested SKU carries zero, and no A3HB row may ever
    /// claim the `05 11` label an older comment wrongly gave that family.
    #[test]
    fn observed_preambles_are_attestation_only() {
        let both = &hashboard_identity("BHB56801")
            .unwrap()
            .observed_eeprom_preambles;
        assert!(both.contains(&[0x04, 0x11]) && both.contains(&[0x05, 0x11]));
        for sku in ["A3HB70501", "A3HB70601", "A3HB70701"] {
            assert_eq!(
                hashboard_identity(sku).unwrap().observed_eeprom_preambles,
                vec![[0x01, 0x41]],
                "{sku}"
            );
        }
        for r in all_hashboard_identities()
            .iter()
            .filter(|r| r.model_id.starts_with("A3HB"))
        {
            assert!(!r.observed_eeprom_preambles.contains(&[0x05, 0x11]));
        }
        // 19 of 50 rows have at least one held page (20 held samples in total —
        // `BHB56801` contributes two); the other 31 stay honestly empty rather
        // than inheriting a family default.
        assert_eq!(
            all_hashboard_identities()
                .iter()
                .filter(|r| !r.observed_eeprom_preambles.is_empty())
                .count(),
            19
        );
        assert_eq!(
            all_hashboard_identities()
                .iter()
                .map(|r| r.observed_eeprom_preambles.len())
                .sum::<usize>(),
            20
        );
    }

    /// This module never contradicts the legacy enum catalog — it extends it.
    /// (The DCENT row is authoritative for all 16 overlapping SKUs.)
    #[test]
    fn identity_rows_agree_with_the_legacy_enum_catalog() {
        for hb in ALL_HASHBOARDS {
            let c = hb.catalog();
            let Some(row) = hashboard_identity(c.sku) else {
                // BHB-S9 / BHB-S11 / BHB-S17 / BHB-T15 are pre-AT24C02D
                // placeholders outside the v1.22.0 roster; they keep their
                // enum row and gain no identity row.
                assert!(c.sku.starts_with("BHB-"), "{} vanished", c.sku);
                continue;
            };
            assert_eq!(row.chip_name, c.chip_name, "{}", c.sku);
            assert_eq!(
                row.chips_per_chain,
                u16::from(c.chips_per_chain),
                "{}",
                c.sku
            );
            assert_eq!(row.authority, IdentityAuthority::DcentCatalog, "{}", c.sku);
        }
    }

    /// B11: the hashboard-DB layer answers the cooling-medium question the
    /// BoardDesc layer deliberately cannot (one control board, three media).
    /// Air SKUs resolve `Air`; the two hydro/immersion rows in this roster
    /// resolve their media and genuinely earn the fan bypass; every
    /// non-pinned prefix (the NB*/TS* records) stays undeclared.
    #[test]
    fn declared_cooling_medium_resolves_through_the_hashboard_code() {
        use dcentrald_common::cooling_medium::{fan_bypass_permitted, CoolingMedium};
        for sku in ["BHB68603", "A3HB70501", "BHB42601"] {
            assert_eq!(
                hashboard_identity(sku).unwrap().declared_cooling_medium(),
                Some(CoolingMedium::Air),
                "{sku}"
            );
        }
        assert_eq!(
            hashboard_identity("H6HB70801").unwrap().declared_cooling_medium(),
            Some(CoolingMedium::Hydro)
        );
        assert_eq!(
            hashboard_identity("M1HB70602")
                .unwrap()
                .declared_cooling_medium(),
            Some(CoolingMedium::Immersion)
        );
        // The two fanless rows genuinely carry no fan actuator…
        for (sku, medium) in [
            ("H6HB70801", CoolingMedium::Hydro),
            ("M1HB70602", CoolingMedium::Immersion),
        ] {
            let m = hashboard_identity(sku).unwrap().declared_cooling_medium();
            assert!(fan_bypass_permitted(m), "{sku}");
            assert!(!medium.has_fan_actuator(), "{sku}");
        }
        // …while the NB*/TS* jig records (prefix outside the pinned
        // discriminator) stay undeclared: fans managed, no bypass.
        for sku in ["NBP1901", "NBS1902", "TS007"] {
            let m = hashboard_identity(sku).unwrap().declared_cooling_medium();
            assert_eq!(m, None, "{sku}");
            assert!(!fan_bypass_permitted(m), "{sku}");
        }
    }

    /// The catalog authorizes nothing. It is not, and must not become, an
    /// admission gate: the runtime bridge stays narrower than this table and
    /// admits only SKUs independently listed in its held-page policy.
    #[test]
    fn identity_rows_do_not_widen_the_runtime_admission_gate() {
        use dcentrald_api_types::hashboard_eeprom::observed_protocol_for_deployed_board_name;
        use dcentrald_common::board_desc::AsicProtocolIdentity;

        // Catalogued here, still refused by the deployed-page bridge because
        // no exact held-page policy row exists.
        for sku in [
            "BHB68601",
            "BHB68701",
            "BHB68703",
            "BHB68705",
            "BHB68707",
            "BHB68709",
            "BHB56801",
            "BHB42803",
            "A3HB70601",
            "NBP1901",
            "NBS1902",
        ] {
            assert!(
                hashboard_identity(sku).is_some(),
                "{sku} must be catalogued"
            );
            assert_eq!(
                observed_protocol_for_deployed_board_name(sku),
                None,
                "{sku}: an identity row must never widen admission"
            );
        }
        // These two rows are admitted by the separate exact held-page policy,
        // not by membership in this 50-row catalog. Both remain identity-only:
        // no runtime, voltage, or write authority follows from this result.
        for sku in ["BHB42701", "BHB42801", "BHB42831"] {
            assert!(hashboard_identity(sku).is_some());
            assert_eq!(
                observed_protocol_for_deployed_board_name(sku),
                Some(AsicProtocolIdentity::Bm1362),
                "{sku}: exact held-page policy must resolve only BM1362"
            );
        }
    }
}
