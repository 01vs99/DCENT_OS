//! B11 (2026-09-02): hydro/immersion fleet foundation — stock-first-party
//! geometry + the hashboard-code cooling-medium discriminator.
//!
//! # What this is
//!
//! A declarative, stock-pinned registry of the Bitmain **hydro (water-block)
//! and immersion hashboard fleet** — every hydro/immersion `machine` row in
//! the Phase A asicminingsupplies stock-topology haul, plus the VNish-1.2.7
//! -only boards no stock firmware is held for. It is the hydro answer to the
//! question the air fleet answers through [`crate::hashboard_topology`] (ePIC
//! jig DB) and [`crate::hashboards`] (DCENT catalog): per-SKU geometry
//! (chains × chips × domains), cooling medium, and citations.
//!
//! This is **data + typing ONLY** (the mission was explicitly data + typing,
//! no energize/thermal-authority changes):
//!
//! - no [`crate::registry`] profile is created or widened;
//! - no row mints an [`dcentrald_common::board_desc::AsicProtocolIdentity`]
//!   admission — the field is *declared stock identity evidence*, and the
//!   runtime admission gate stays exactly as narrow as it is today;
//! - no voltage/frequency/PLL number lives here (the stock `levels.json`
//!   ladders are *cited*, never re-typed — same "wrong calibration is worse
//!   than none" rule as [`crate::hashboard_catalog`] rule 4);
//! - every stock-side **thermal envelope is `None` = UNKNOWN** where the
//!   stock trees carry none (they do: `levels.json` holds frequency/voltage
//!   ladders only). The only thermal bytes the stock hydro trees carry are
//!   the `strategy` autotune targets, pinned verbatim as
//!   [`HydroFleetDescriptor::stock_pid_target_temp_c`] — a stock-declared
//!   tuning target, **not** a DCENT safety limit. VNish's 90/85/80 °C
//!   thresholds stay where they already live ([`crate::vnish_thermal`]),
//!   as third-party RE evidence.
//!
//! # Provenance
//!
//! Two desk corpora, joined — never blended:
//!
//! | Corpus | Nature | Supplies |
//! |---|---|---|
//! | Bitmain stock `topol.conf` (Phase A extraction trees, gitignored) | **first-party** (Bitmain's own firmware expectation per hashboard SKU) | chains, chips/chain, domains, chip id, PSU dialect, fan slots, strategy temps |
//! | VNish 1.2.7 matrix ([`crate::vnish_thermal`]) | third-party transcription (Experimental) | independent corroboration of chains + per-chain geometry; the only source for the no-stock rows |
//!
//! Stock citations point into
//! <tree>/components/
//! minerfs.image.gz.tree/etc/{topol,levels}.conf` (gitignored RE evidence;
//! same citation convention as `PHASE_A_EVIDENCE_REPORT.md` §3.11).
//!
//! # The chain-count adjudication (conflict #14, settled for the data layer)
//!
//! The stock `topol.conf` `chain_num` field says **4** on every 2022-gen
//! hydro machine (HHB28601/02, HHB426xx/427xx, TH401) and **3** on every
//! XP/S21-gen hydro machine. The VNish matrix agrees in both generations.
//! The old  hydro rows disagreed in BOTH directions
//! (3 on the 2022-gen, 4 on the XP-gen) — they were the 2:1 outlier on the
//! 2022-gen side and are corrected in place by the B11 report.
//!
//! One caveat travels with the 4s: on BHB42xxx **air** boards the same field
//! means connector slots (stock says 4 for known 3-board SKUs — Phase A
//! §1.3.5). For the hydro fleet that caveat does **not** bite: stock and
//! VNish independently agree on 4, so the adjudicated value is 2-sources-to-1
//! (stock + VNish vs the stale catalog row) — but it is still desk data, not
//! a physically counted unit. No hydro unit has ever been on the bench.
//!
//! [`ChainCountBasis`] records which corpora back each row's chain count;
//! one-source rows (S21+ Hydro, S21e Hydro 70802, both immersion families)
//! are labelled as such and must not be treated as confirmed.
//!
//! # The cooling-medium discriminator (the layer `board_desc` points at)
//!
//! `dcentrald_common::board_desc` deliberately keeps
//! `BoardDesc::cooling_medium = None` on every control-board row: one
//! control board (`am3-s21`…) can carry air, hydro or immersion hashboards,
//! so the medium is a **hashboard facet** discriminated by the hashboard
//! code prefix. This module is where that discriminator lives:
//!
//! - [`cooling_medium_for_hashboard_code`] — prefix table exactly as the
//!   `board_desc` doc comment pins it (`BHB`/`A3HB` air · `HHB`/`H6HB`/
//!   `H1HB` hydro · `IHB`/`M1HB` immersion), fail-closed (`None`) on every
//!   other prefix — including `TH401`, `NBP1901`-style codes and lowercase
//!   input. `None` means *undeclared*, which keeps fans managed
//!   (fail-closed in the safe direction).
//! - [`HydroFleetDescriptor::cut_ladder`] — a hydro/immersion hashboard
//!   resolves to the **external-loop** ladder, which carries NO
//!   [`dcentrald_common::cooling_medium::CutRung::RaiseFansToCap`] rung —
//!   absent, not zero — and validates under the same registry validator
//!   (`validate_cut_ladder`) the BoardDesc rows are gated by.
//!
//! ## The H1HB dissent (recorded, not resolved)
//!
//! Stock ships `H1HB70601` inside the **S21 XP Hydro** image (hydro, first
//! party); the VNish matrix's `H1HB70602`/`H1HB68601` rows declare
//! immersion-only cooling. The two corpora disagree on the *plumbing label*
//! of the H1HB family. This module follows the pinned `board_desc` doc
//! comment and the first-party stock evidence (`H1HB` → `Hydro`); the
//! dissent is pinned by test, and it carries **zero** safety delta: both
//! readings project to [`dcentrald_common::cooling_medium::CoolingClass::ExternalLoop`]
//! — no fan actuator either way.
//!
//! # Honest scope
//!
//! - The stock `fan` blocks declare **4 fan slots on every hydro machine**.
//!   That is a stock wiring declaration (the APW11/AWP11 PSU-family and
//!   cabinet fans), pinned verbatim; it is NOT a fan floor, NOT a tach
//!   expectation, and NOT authority to add fan rungs to a hydro ladder.
//! - `asic: None` on VNish-only rows the VNish matrix cannot identify (it
//!   carries no chip id; `chip_type` is empty corpus-wide). S21e-Hydro
//!   `H6HB70801` and S21-XP-Imm `M1HB70602` get `Some` from the ePIC
//!   v1.24.0 delta decode (which corroborates their geometry exactly);
//!   nothing is inherited from a sibling SKU.
//! - `HHBXXX` (VNish placeholder, "S19 Pro Hydro (120T)", 4×120) is a
//!   placeholder ID, not a SKU — documented here, deliberately not a row.

use dcentrald_common::board_desc::AsicProtocolIdentity;
use dcentrald_common::cooling_medium::{
    canonical_cut_ladder, validate_cut_ladder, CoolingClass, CoolingMedium, CutLadderError,
    CutRung,
};

/// Which desk corpora back a row's `chains_per_unit`.
///
/// The adjudication result, not a confidence score. Every variant except
/// [`ChainCountBasis::StockTopolAndVnishMatrix`] marks a row that must not
/// be treated as chain-count-confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainCountBasis {
    /// Bitmain stock `topol.conf` `chain_num` and the VNish 1.2.7 matrix
    /// independently agree (every stock-backed row below except the
    /// stock-DB-only SKUs VNish does not list).
    StockTopolAndVnishMatrix,
    /// Stock `topol.conf` only — the VNish matrix has no row for this exact
    /// SKU (DB siblings of VNish-covered boards, the AWP8 machines, TH401).
    StockTopolOnly,
    /// VNish 1.2.7 matrix only — **one-source**. No stock firmware is held
    /// for the SKU (S21+ Hydro, S21e Hydro 70802, the immersion fleet,
    /// whose only stock image is the sealed Amlogic S21-Imm BMU).
    VnishMatrixOnly,
    /// VNish 1.2.7 matrix + the ePIC v1.24.0 `bms-miner` delta decode agree
    /// (geometry exactly); no Bitmain stock firmware held.
    VnishMatrixAndEpicDelta,
}

impl ChainCountBasis {
    /// `true` when Bitmain's own firmware is one of the agreeing sources.
    pub fn is_stock_backed(self) -> bool {
        matches!(
            self,
            ChainCountBasis::StockTopolAndVnishMatrix | ChainCountBasis::StockTopolOnly
        )
    }
}

/// One hydro/immersion fleet row. Geometry + medium + citations only — see
/// the module docs for the fields this type deliberately does NOT have
/// (voltage/frequency/PLL/tuning, runtime admission, thermal limits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HydroFleetDescriptor {
    /// Exact Bitmain hashboard/machine code (`"HHB28601"`). Registry key.
    pub hashboard_sku: &'static str,
    /// Marketing model (VNish spelling where a VNish row exists; a stock-DB
    /// descriptive label otherwise). Never inherited from a sibling SKU.
    pub marketing_model: &'static str,
    /// Declared cooling medium for this hashboard family.
    pub medium: CoolingMedium,
    /// Stock-declared ASIC identity where a corpus establishes it
    /// (`asic_id` in stock topol; ePIC v1.24.0 delta for the two rows it
    /// decodes). `None` = no held corpus names the chip — never a guess.
    pub asic: Option<AsicProtocolIdentity>,
    /// Adjudicated hashboard slots per unit (4 on the 2022-gen hydro,
    /// 3 on the XP/S21-gen — see module docs).
    pub chains_per_unit: u8,
    /// ASICs on one hashboard chain.
    pub chips_per_chain: u16,
    /// Voltage domains along the chain.
    pub domains_per_chain: u8,
    /// ASICs per voltage domain (`chips_per_domain * domains_per_chain ==
    /// chips_per_chain`, validated).
    pub chips_per_domain: u8,
    /// Which corpora back [`Self::chains_per_unit`].
    pub chain_basis: ChainCountBasis,
    /// Stock `topol.conf` citation (Phase A extraction tree, gitignored).
    /// `None` exactly on the no-stock rows.
    pub stock_topol_citation: Option<&'static str>,
    /// The stock `chain_num` value verbatim. `None` exactly on the no-stock
    /// rows. Must equal [`Self::chains_per_unit`] (validated) — that
    /// equality IS the pinned adjudication.
    pub stock_chain_num: Option<u8>,
    /// Stock-declared PSU dialect label (`"APW11"`, Bitmain's own `"AWP11"`
    /// typo included verbatim). Descriptive only — NOT a DCENT PSU contract.
    pub stock_psu_dialect: Option<&'static str>,
    /// Stock `strategy.pid_target_temp` (°C), verbatim. Present only on the
    /// XP/S21-gen hydro trees (50 °C corpus-wide). A stock autotune target,
    /// **not** a DCENT safety limit; danger/hot chip temps are UNKNOWN from
    /// stock on every row.
    pub stock_pid_target_temp_c: Option<i16>,
    /// Fan slots the stock `fan` block declares (4 on every hydro machine).
    /// A wiring declaration only — NOT a fan floor or tach expectation.
    pub stock_declared_fan_slots: Option<u8>,
    /// Stock `levels.json` citation (frequency/voltage ladders live there;
    /// they are cited, never re-typed here). `None` on the no-stock rows.
    pub stock_levels_citation: Option<&'static str>,
}

impl HydroFleetDescriptor {
    /// Declared ASICs across the whole unit (up to 4×180 = 720).
    pub fn declared_chips_per_unit(&self) -> u32 {
        u32::from(self.chips_per_chain) * u32::from(self.chains_per_unit)
    }

    /// The escalation ladder a carrier of this hashboard must use: the
    /// canonical **external-loop** ladder (throttle → cut hash power), which
    /// carries NO fan-raise rung — absent, not zero.
    ///
    /// This is the fanless-medium safety consumer the BoardDesc validators
    /// expect: a hydro/immersion hashboard never resolves to a ladder that
    /// commands chassis fans.
    pub fn cut_ladder(&self) -> &'static [CutRung] {
        canonical_cut_ladder(CoolingClass::ExternalLoop)
    }

    /// Validate this row's ladder under the exact registry validator the
    /// BoardDesc rows are gated by
    /// ([`dcentrald_common::cooling_medium::validate_cut_ladder`]).
    pub fn validate_cut_ladder(&self) -> Result<(), CutLadderError> {
        validate_cut_ladder(Some(self.medium), self.cut_ladder())
    }

    /// `true` when this row's chain count is backed by Bitmain's own
    /// firmware (stock topol), not only by the VNish transcription.
    pub fn chain_count_is_stock_backed(&self) -> bool {
        self.chain_basis.is_stock_backed()
    }
}

/// Validation errors for [`validate_hydro_fleet_descriptor`]. With the
/// pinned table these are unreachable (test-pinned); the error path exists
/// so future edits fail closed instead of shipping a broken row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydroFleetError {
    pub hashboard_sku: &'static str,
    pub detail: &'static str,
}

impl std::fmt::Display for HydroFleetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.hashboard_sku, self.detail)
    }
}

impl std::error::Error for HydroFleetError {}

/// Fail-closed structural validation of one row.
pub fn validate_hydro_fleet_descriptor(d: &HydroFleetDescriptor) -> Result<(), HydroFleetError> {
    let err = |detail: &'static str| HydroFleetError {
        hashboard_sku: d.hashboard_sku,
        detail,
    };
    if d.chains_per_unit != 3 && d.chains_per_unit != 4 {
        return Err(err("chains_per_unit must be 3 or 4"));
    }
    if d.chips_per_chain == 0 || d.domains_per_chain == 0 || d.chips_per_domain == 0 {
        return Err(err("zero geometry field"));
    }
    let domain_product = u16::from(d.chips_per_domain) * u16::from(d.domains_per_chain);
    if domain_product != d.chips_per_chain {
        return Err(err("domain arithmetic broken"));
    }
    // The fleet is hydro/immersion only; an Air row here would be a
    // mis-filed air SKU silently earning fanless treatment territory.
    if d.medium == CoolingMedium::Air {
        return Err(err("air row does not belong in the hydro fleet"));
    }
    // The pinned adjudication: where stock declares chain_num it must EQUAL
    // the adjudicated count (stock and VNish agree on the hydro fleet).
    if let Some(stock_n) = d.stock_chain_num {
        if stock_n != d.chains_per_unit {
            return Err(err("stock_chain_num disagrees with chains_per_unit"));
        }
    }
    // Citation coherence: stock-backed bases must cite stock and carry its
    // chain_num; VNish-only bases must not.
    let stock_backed = d.chain_basis.is_stock_backed();
    if stock_backed != d.stock_topol_citation.is_some() {
        return Err(err("chain_basis / stock_topol_citation incoherence"));
    }
    if stock_backed != d.stock_chain_num.is_some() {
        return Err(err("chain_basis / stock_chain_num incoherence"));
    }
    // VNish-only rows have no stock PSU/fan/levels/strategy bytes either.
    if !stock_backed
        && (d.stock_psu_dialect.is_some()
            || d.stock_pid_target_temp_c.is_some()
            || d.stock_declared_fan_slots.is_some()
            || d.stock_levels_citation.is_some())
    {
        return Err(err("no-stock row carries stock-only fields"));
    }
    Ok(())
}

/// The pinned hydro/immersion fleet. 37 rows: 27 stock-backed + 10
/// no-stock (VNish-only / VNish+ePIC-delta).
///
/// Transcribed from the Phase A stock `topol.conf` extraction trees (not
/// re-derived from any in-tree corpus) and cross-checked against the VNish
/// 1.2.7 matrix in `tests` below — that cross-check is what makes this
/// table an independent pin rather than a restatement.
pub const HYDRO_FLEET: &[HydroFleetDescriptor] = &[
    // ------------------------------------------------------------------
    // 2022-generation hydro — stock chain_num = 4 (S19/T19/S19 Pro(+) Hydro).
    // The old MASTER_MODEL_CATALOG rows said 3 here; corrected in place by
    // the B11 report (stock + VNish vs the stale catalog row, 2:1).
    // ------------------------------------------------------------------
    HydroFleetDescriptor {
        hashboard_sku: "HHB28601",
        marketing_model: "Antminer S19 Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1398), // stock asic_id BM1398P
        chains_per_unit: 4,
        chips_per_chain: 104,
        domains_per_chain: 52,
        chips_per_domain: 2,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(4),
        stock_psu_dialect: Some("AWP11"),
        stock_pid_target_temp_c: None, // 2022-gen trees carry no strategy block
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB28602",
        marketing_model: "Antminer T19 Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1398), // stock asic_id BM1398P
        chains_per_unit: 4,
        chips_per_chain: 104,
        domains_per_chain: 52,
        chips_per_domain: 2,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(4),
        stock_psu_dialect: Some("AWP11"),
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB42601",
        marketing_model: "Antminer S19 Pro Hydro (stock DB)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1362),
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        chain_basis: ChainCountBasis::StockTopolOnly, // no VNish HHB42601 row
        stock_topol_citation: Some(
            "\
             components/minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(4),
        stock_psu_dialect: Some("AWP11"),
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             components/minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB42602",
        marketing_model: "Antminer S19 Pro Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1362),
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             components/minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(4),
        stock_psu_dialect: Some("AWP11"),
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             components/minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB42631",
        marketing_model: "Antminer S19Pro+ Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1362),
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             components/minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(4),
        stock_psu_dialect: Some("AWP11"),
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             components/minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB42701",
        marketing_model: "Antminer S19 Pro+ Hydro, AWP8 PSU (stock DB)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1362),
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(4),
        stock_psu_dialect: Some("AWP8"),
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB42711",
        marketing_model: "Antminer S19 Pro+ Hydro, AWP8 PSU (stock DB)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1362),
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(4),
        stock_psu_dialect: Some("AWP8"),
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "TH401",
        marketing_model: "S19 Pro+ Hydro family machine TH401 (stock DB)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1362),
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(4),
        stock_psu_dialect: Some("AWP8"),
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    // ------------------------------------------------------------------
    // XP-generation hydro — stock chain_num = 3 (S19 XP / S19e XP / T19 Pro
    // Hydro). The old MASTER_MODEL_CATALOG rows said 4 here; corrected in
    // place by the B11 report.
    // ------------------------------------------------------------------
    HydroFleetDescriptor {
        hashboard_sku: "HHB56601",
        marketing_model: "Antminer S19 XP Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1366),
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             01_Antminer_S19_XP_Hyd._zynq7007_HHB56XXX/components/\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             01_Antminer_S19_XP_Hyd._zynq7007_HHB56XXX/components/\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB56603",
        marketing_model: "Antminer S19 XP Hydro (stock DB sibling)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1366),
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             01_Antminer_S19_XP_Hyd._zynq7007_HHB56XXX/components/\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             01_Antminer_S19_XP_Hyd._zynq7007_HHB56XXX/components/\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB56611",
        marketing_model: "Antminer S19 XP Hydro (stock DB sibling)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1366),
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB56613",
        marketing_model: "Antminer S19 XP Hydro (stock DB sibling)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1366),
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB56701",
        marketing_model: "Antminer S19 XP Hydro (stock DB sibling)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1366),
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             01_Antminer_S19_XP_Hyd._zynq7007_HHB56XXX/components/\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             01_Antminer_S19_XP_Hyd._zynq7007_HHB56XXX/components/\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB56702",
        marketing_model: "Antminer T19 Pro Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1366),
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "H6HB56702",
        marketing_model: "Antminer S19e XP Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1366),
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "H1HB56703",
        marketing_model: "Antminer S19 XP Hydro family, H1 board (stock DB)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1366),
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             01_Antminer_S19_XP_Hyd._zynq7007_HHB56XXX/components/\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             01_Antminer_S19_XP_Hyd._zynq7007_HHB56XXX/components/\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    // ------------------------------------------------------------------
    // S21-generation hydro — stock chain_num = 3.
    // ------------------------------------------------------------------
    HydroFleetDescriptor {
        hashboard_sku: "HHB68501",
        marketing_model: "Antminer S21 Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1368),
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB68502",
        marketing_model: "Antminer S21 Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1368),
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB68503",
        marketing_model: "Antminer S21 Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1368),
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB68504",
        marketing_model: "Antminer S21 Hydro (stock DB sibling)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1368),
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB68601",
        marketing_model: "Antminer S21 Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1368),
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB68602",
        marketing_model: "Antminer S21 Hydro (stock DB sibling)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1368),
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "HHB68701",
        marketing_model: "Antminer S19 XP+ Hydro",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1368),
        chains_per_unit: 3,
        chips_per_chain: 180,
        domains_per_chain: 18,
        chips_per_domain: 10,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "H6HB70501",
        marketing_model: "Antminer S21 XP HYDRO",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1370),
        chains_per_unit: 3,
        chips_per_chain: 160,
        domains_per_chain: 20,
        chips_per_domain: 8,
        chain_basis: ChainCountBasis::StockTopolAndVnishMatrix,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "H6HB70601",
        marketing_model: "Antminer S21 XP Hydro (stock DB sibling)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1370),
        chains_per_unit: 3,
        chips_per_chain: 160,
        domains_per_chain: 20,
        chips_per_domain: 8,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    HydroFleetDescriptor {
        hashboard_sku: "H6HB70602",
        marketing_model: "Antminer S21 XP Hydro (stock DB sibling)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1370),
        chains_per_unit: 3,
        chips_per_chain: 160,
        domains_per_chain: 20,
        chips_per_domain: 8,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    // Stock ships H1HB70601 inside the S21 XP HYDRO image: first-party
    // hydro evidence. The VNish matrix's H1HB rows are immersion-only —
    // see "The H1HB dissent" in the module docs (zero safety delta).
    HydroFleetDescriptor {
        hashboard_sku: "H1HB70601",
        marketing_model: "Antminer S21 XP Hydro, H1 board (stock DB)",
        medium: CoolingMedium::Hydro,
        asic: Some(AsicProtocolIdentity::Bm1370),
        chains_per_unit: 3,
        chips_per_chain: 160,
        domains_per_chain: 20,
        chips_per_domain: 8,
        chain_basis: ChainCountBasis::StockTopolOnly,
        stock_topol_citation: Some(
            "\
             minerfs.image.gz.tree/etc/topol.conf",
        ),
        stock_chain_num: Some(3),
        stock_psu_dialect: Some("APW11"),
        stock_pid_target_temp_c: Some(50),
        stock_declared_fan_slots: Some(4),
        stock_levels_citation: Some(
            "\
             minerfs.image.gz.tree/etc/levels.json",
        ),
    },
    // ------------------------------------------------------------------
    // NO-STOCK rows — VNish matrix only (one-source), or VNish + the ePIC
    // v1.24.0 delta decode. Stock-side thermal/PSU/fan fields stay None.
    // ------------------------------------------------------------------
    HydroFleetDescriptor {
        hashboard_sku: "H6HB70701",
        marketing_model: "Antminer S21+ Hydro",
        medium: CoolingMedium::Hydro,
        asic: None, // VNish matrix carries no chip id
        chains_per_unit: 3,
        chips_per_chain: 95,
        domains_per_chain: 19,
        chips_per_domain: 5,
        chain_basis: ChainCountBasis::VnishMatrixOnly,
        stock_topol_citation: None,
        stock_chain_num: None,
        stock_psu_dialect: None,
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: None,
        stock_levels_citation: None,
    },
    HydroFleetDescriptor {
        hashboard_sku: "H6HB70702",
        marketing_model: "Antminer S21+ Hydro",
        medium: CoolingMedium::Hydro,
        asic: None,
        chains_per_unit: 3,
        chips_per_chain: 95,
        domains_per_chain: 19,
        chips_per_domain: 5,
        chain_basis: ChainCountBasis::VnishMatrixOnly,
        stock_topol_citation: None,
        stock_chain_num: None,
        stock_psu_dialect: None,
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: None,
        stock_levels_citation: None,
    },
    HydroFleetDescriptor {
        hashboard_sku: "H6HB70704",
        marketing_model: "Antminer S21+ Hydro",
        medium: CoolingMedium::Hydro,
        asic: None,
        chains_per_unit: 3,
        chips_per_chain: 95,
        domains_per_chain: 19,
        chips_per_domain: 5,
        chain_basis: ChainCountBasis::VnishMatrixOnly,
        stock_topol_citation: None,
        stock_chain_num: None,
        stock_psu_dialect: None,
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: None,
        stock_levels_citation: None,
    },
    HydroFleetDescriptor {
        hashboard_sku: "H6HB70801",
        marketing_model: "Antminer S21e Hydro",
        medium: CoolingMedium::Hydro,
        // ePIC v1.24.0 delta: BM1370 at 85/chain, corroborating VNish
        // geometry exactly (the only two-source-corroborated delta row).
        asic: Some(AsicProtocolIdentity::Bm1370),
        chains_per_unit: 3,
        chips_per_chain: 85,
        domains_per_chain: 17,
        chips_per_domain: 5,
        chain_basis: ChainCountBasis::VnishMatrixAndEpicDelta,
        stock_topol_citation: None,
        stock_chain_num: None,
        stock_psu_dialect: None,
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: None,
        stock_levels_citation: None,
    },
    HydroFleetDescriptor {
        hashboard_sku: "H6HB70802",
        marketing_model: "Antminer S21e Hydro",
        medium: CoolingMedium::Hydro,
        asic: None, // ePIC delta decoded 70801 only — no sibling inheritance
        chains_per_unit: 3,
        chips_per_chain: 85,
        domains_per_chain: 17,
        chips_per_domain: 5,
        chain_basis: ChainCountBasis::VnishMatrixOnly,
        stock_topol_citation: None,
        stock_chain_num: None,
        stock_psu_dialect: None,
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: None,
        stock_levels_citation: None,
    },
    HydroFleetDescriptor {
        hashboard_sku: "IHB68601",
        marketing_model: "Antminer S21 Imm",
        medium: CoolingMedium::Immersion,
        asic: None, // stock S21-Imm AML image is sealed; VNish has no chip id
        chains_per_unit: 3,
        chips_per_chain: 156,
        domains_per_chain: 13,
        chips_per_domain: 12,
        chain_basis: ChainCountBasis::VnishMatrixOnly,
        stock_topol_citation: None,
        stock_chain_num: None,
        stock_psu_dialect: None,
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: None,
        stock_levels_citation: None,
    },
    HydroFleetDescriptor {
        hashboard_sku: "M1HB70601",
        marketing_model: "Antminer S21 XP Imm",
        medium: CoolingMedium::Immersion,
        asic: None, // ePIC delta decoded M1HB70602 only — no sibling inheritance
        chains_per_unit: 3,
        chips_per_chain: 91,
        domains_per_chain: 13,
        chips_per_domain: 7,
        chain_basis: ChainCountBasis::VnishMatrixOnly,
        stock_topol_citation: None,
        stock_chain_num: None,
        stock_psu_dialect: None,
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: None,
        stock_levels_citation: None,
    },
    HydroFleetDescriptor {
        hashboard_sku: "M1HB70602",
        marketing_model: "Antminer S21 XP Imm",
        medium: CoolingMedium::Immersion,
        // ePIC v1.24.0 delta: BM1370 at 91/chain, corroborating VNish
        // geometry exactly.
        asic: Some(AsicProtocolIdentity::Bm1370),
        chains_per_unit: 3,
        chips_per_chain: 91,
        domains_per_chain: 13,
        chips_per_domain: 7,
        chain_basis: ChainCountBasis::VnishMatrixAndEpicDelta,
        stock_topol_citation: None,
        stock_chain_num: None,
        stock_psu_dialect: None,
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: None,
        stock_levels_citation: None,
    },
    HydroFleetDescriptor {
        hashboard_sku: "H1HB68601",
        marketing_model: "Antminer U3S19XP+H (VNish immersion row)",
        medium: CoolingMedium::Immersion,
        asic: None,
        chains_per_unit: 3,
        chips_per_chain: 180,
        domains_per_chain: 18,
        chips_per_domain: 10,
        chain_basis: ChainCountBasis::VnishMatrixOnly,
        stock_topol_citation: None,
        stock_chain_num: None,
        stock_psu_dialect: None,
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: None,
        stock_levels_citation: None,
    },
    HydroFleetDescriptor {
        hashboard_sku: "H1HB70602",
        marketing_model: "Antminer U3S21EXPH (VNish immersion row)",
        medium: CoolingMedium::Immersion,
        asic: None,
        chains_per_unit: 3,
        chips_per_chain: 160,
        domains_per_chain: 20,
        chips_per_domain: 8,
        chain_basis: ChainCountBasis::VnishMatrixOnly,
        stock_topol_citation: None,
        stock_chain_num: None,
        stock_psu_dialect: None,
        stock_pid_target_temp_c: None,
        stock_declared_fan_slots: None,
        stock_levels_citation: None,
    },
];

/// The pinned fleet size. Any drift between [`HYDRO_FLEET`] and this
/// constant is a test failure, never a silent gap.
pub const HYDRO_FLEET_ROSTER_COUNT: usize = 37;

/// All fleet rows, in table order.
pub fn all_hydro_fleet_descriptors() -> &'static [HydroFleetDescriptor] {
    HYDRO_FLEET
}

/// Look up one fleet row by **exact** hashboard code. Fail-closed: unknown
/// codes (and every air SKU) return `None`.
pub fn hydro_fleet_descriptor(hashboard_sku: &str) -> Option<&'static HydroFleetDescriptor> {
    HYDRO_FLEET
        .iter()
        .find(|d| d.hashboard_sku == hashboard_sku)
}

/// Resolve the cooling medium from a Bitmain hashboard code by its prefix,
/// exactly as the `board_desc.rs` `cooling_medium` doc comment pins the
/// discriminator:
///
/// - `BHB…` / `A3HB…` → [`CoolingMedium::Air`] (chassis fans on the air path)
/// - `HHB…` / `H6HB…` / `H1HB…` → [`CoolingMedium::Hydro`]
/// - `IHB…` / `M1HB…` → [`CoolingMedium::Immersion`]
/// - anything else → `None` (**undeclared** — the fail-closed direction:
///   fans stay managed, no fan bypass, air-shaped ladder still validates).
///
/// This is the API the BoardDesc layer points at: cooling medium is a
/// *hashboard* facet, resolved from the hashboard code (EEPROM `machine` /
/// decoded page), never from the control-board `board_target`.
///
/// Known deliberate misses (return `None`, resolved only through
/// [`hydro_fleet_descriptor`]): `TH401` (S19 Pro+ Hydro family machine —
/// hydro per stock, but its prefix is not in the pinned discriminator), and
/// the pre-topology `NB*`/`TS*` codes. `None` is conservative for these —
/// it can never strip fan management.
pub fn cooling_medium_for_hashboard_code(code: &str) -> Option<CoolingMedium> {
    if code.starts_with("HHB")
        || code.starts_with("H6HB")
        || code.starts_with("H1HB")
    {
        Some(CoolingMedium::Hydro)
    } else if code.starts_with("IHB") || code.starts_with("M1HB") {
        Some(CoolingMedium::Immersion)
    } else if code.starts_with("BHB") || code.starts_with("A3HB") {
        Some(CoolingMedium::Air)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_common::cooling_medium::{
        fan_bypass_permitted, CANONICAL_FORCED_AIR_LADDER,
    };

    /// Hand-transcribed from the Phase A stock extraction trees and the
    /// VNish 1.2.7 matrix dump — NOT re-read out of any in-tree corpus.
    /// Columns: sku, medium, asic (chip), chains, chips, domains, per-domain,
    /// basis.
    const EXPECTED: &[(
        &str,
        CoolingMedium,
        Option<&str>,
        u8,
        u16,
        u8,
        u8,
        ChainCountBasis,
    )] = &[
        // 2022-gen hydro (stock chain_num=4).
        ("HHB28601", CoolingMedium::Hydro, Some("BM1398"), 4, 104, 52, 2, ChainCountBasis::StockTopolAndVnishMatrix),
        ("HHB28602", CoolingMedium::Hydro, Some("BM1398"), 4, 104, 52, 2, ChainCountBasis::StockTopolAndVnishMatrix),
        ("HHB42601", CoolingMedium::Hydro, Some("BM1362"), 4, 180, 60, 3, ChainCountBasis::StockTopolOnly),
        ("HHB42602", CoolingMedium::Hydro, Some("BM1362"), 4, 180, 60, 3, ChainCountBasis::StockTopolAndVnishMatrix),
        ("HHB42631", CoolingMedium::Hydro, Some("BM1362"), 4, 180, 60, 3, ChainCountBasis::StockTopolAndVnishMatrix),
        ("HHB42701", CoolingMedium::Hydro, Some("BM1362"), 4, 180, 60, 3, ChainCountBasis::StockTopolOnly),
        ("HHB42711", CoolingMedium::Hydro, Some("BM1362"), 4, 180, 60, 3, ChainCountBasis::StockTopolOnly),
        ("TH401", CoolingMedium::Hydro, Some("BM1362"), 4, 180, 60, 3, ChainCountBasis::StockTopolOnly),
        // XP-gen hydro (stock chain_num=3).
        ("HHB56601", CoolingMedium::Hydro, Some("BM1366"), 3, 204, 17, 12, ChainCountBasis::StockTopolAndVnishMatrix),
        ("HHB56603", CoolingMedium::Hydro, Some("BM1366"), 3, 204, 17, 12, ChainCountBasis::StockTopolOnly),
        ("HHB56611", CoolingMedium::Hydro, Some("BM1366"), 3, 204, 17, 12, ChainCountBasis::StockTopolOnly),
        ("HHB56613", CoolingMedium::Hydro, Some("BM1366"), 3, 204, 17, 12, ChainCountBasis::StockTopolOnly),
        ("HHB56701", CoolingMedium::Hydro, Some("BM1366"), 3, 204, 17, 12, ChainCountBasis::StockTopolOnly),
        ("HHB56702", CoolingMedium::Hydro, Some("BM1366"), 3, 204, 17, 12, ChainCountBasis::StockTopolAndVnishMatrix),
        ("H6HB56702", CoolingMedium::Hydro, Some("BM1366"), 3, 204, 17, 12, ChainCountBasis::StockTopolAndVnishMatrix),
        ("H1HB56703", CoolingMedium::Hydro, Some("BM1366"), 3, 204, 17, 12, ChainCountBasis::StockTopolOnly),
        // S21-gen hydro (stock chain_num=3).
        ("HHB68501", CoolingMedium::Hydro, Some("BM1368"), 3, 216, 18, 12, ChainCountBasis::StockTopolAndVnishMatrix),
        ("HHB68502", CoolingMedium::Hydro, Some("BM1368"), 3, 216, 18, 12, ChainCountBasis::StockTopolAndVnishMatrix),
        ("HHB68503", CoolingMedium::Hydro, Some("BM1368"), 3, 216, 18, 12, ChainCountBasis::StockTopolAndVnishMatrix),
        ("HHB68504", CoolingMedium::Hydro, Some("BM1368"), 3, 216, 18, 12, ChainCountBasis::StockTopolOnly),
        ("HHB68601", CoolingMedium::Hydro, Some("BM1368"), 3, 216, 18, 12, ChainCountBasis::StockTopolAndVnishMatrix),
        ("HHB68602", CoolingMedium::Hydro, Some("BM1368"), 3, 216, 18, 12, ChainCountBasis::StockTopolOnly),
        ("HHB68701", CoolingMedium::Hydro, Some("BM1368"), 3, 180, 18, 10, ChainCountBasis::StockTopolAndVnishMatrix),
        ("H6HB70501", CoolingMedium::Hydro, Some("BM1370"), 3, 160, 20, 8, ChainCountBasis::StockTopolAndVnishMatrix),
        ("H6HB70601", CoolingMedium::Hydro, Some("BM1370"), 3, 160, 20, 8, ChainCountBasis::StockTopolOnly),
        ("H6HB70602", CoolingMedium::Hydro, Some("BM1370"), 3, 160, 20, 8, ChainCountBasis::StockTopolOnly),
        ("H1HB70601", CoolingMedium::Hydro, Some("BM1370"), 3, 160, 20, 8, ChainCountBasis::StockTopolOnly),
        // No-stock rows.
        ("H6HB70701", CoolingMedium::Hydro, None, 3, 95, 19, 5, ChainCountBasis::VnishMatrixOnly),
        ("H6HB70702", CoolingMedium::Hydro, None, 3, 95, 19, 5, ChainCountBasis::VnishMatrixOnly),
        ("H6HB70704", CoolingMedium::Hydro, None, 3, 95, 19, 5, ChainCountBasis::VnishMatrixOnly),
        ("H6HB70801", CoolingMedium::Hydro, Some("BM1370"), 3, 85, 17, 5, ChainCountBasis::VnishMatrixAndEpicDelta),
        ("H6HB70802", CoolingMedium::Hydro, None, 3, 85, 17, 5, ChainCountBasis::VnishMatrixOnly),
        ("IHB68601", CoolingMedium::Immersion, None, 3, 156, 13, 12, ChainCountBasis::VnishMatrixOnly),
        ("M1HB70601", CoolingMedium::Immersion, None, 3, 91, 13, 7, ChainCountBasis::VnishMatrixOnly),
        ("M1HB70602", CoolingMedium::Immersion, Some("BM1370"), 3, 91, 13, 7, ChainCountBasis::VnishMatrixAndEpicDelta),
        ("H1HB68601", CoolingMedium::Immersion, None, 3, 180, 18, 10, ChainCountBasis::VnishMatrixOnly),
        ("H1HB70602", CoolingMedium::Immersion, None, 3, 160, 20, 8, ChainCountBasis::VnishMatrixOnly),
    ];

    fn chip_name(a: Option<AsicProtocolIdentity>) -> Option<&'static str> {
        a.map(|id| match id {
            AsicProtocolIdentity::Bm1362 => "BM1362",
            AsicProtocolIdentity::Bm1366 => "BM1366",
            AsicProtocolIdentity::Bm1368 => "BM1368",
            AsicProtocolIdentity::Bm1370 => "BM1370",
            AsicProtocolIdentity::Bm1398 => "BM1398",
            _ => "other",
        })
    }

    #[test]
    fn every_row_matches_the_hand_transcribed_expectation_table() {
        assert_eq!(EXPECTED.len(), HYDRO_FLEET_ROSTER_COUNT);
        assert_eq!(HYDRO_FLEET.len(), HYDRO_FLEET_ROSTER_COUNT);
        for &(sku, medium, chip, chains, chips, doms, per_dom, basis) in EXPECTED {
            let row = hydro_fleet_descriptor(sku)
                .unwrap_or_else(|| panic!("{sku} must have a fleet row"));
            assert_eq!(row.medium, medium, "{sku}: medium");
            assert_eq!(chip_name(row.asic), chip, "{sku}: asic");
            assert_eq!(row.chains_per_unit, chains, "{sku}: chains");
            assert_eq!(row.chips_per_chain, chips, "{sku}: chips/chain");
            assert_eq!(row.domains_per_chain, doms, "{sku}: domains");
            assert_eq!(row.chips_per_domain, per_dom, "{sku}: chips/domain");
            assert_eq!(row.chain_basis, basis, "{sku}: chain basis");
            validate_hydro_fleet_descriptor(row)
                .unwrap_or_else(|e| panic!("{sku} must validate: {e}"));
        }
        // No extra rows.
        let mut seen = std::collections::HashSet::new();
        for row in all_hydro_fleet_descriptors() {
            assert!(seen.insert(row.hashboard_sku), "dup {}", row.hashboard_sku);
        }
        assert_eq!(seen.len(), HYDRO_FLEET_ROSTER_COUNT);
    }

    /// The task-list headline rows, one assertion each, so the mission's own
    /// numbers are pinned independently of the big table.
    #[test]
    fn mission_headline_geometry_rows() {
        let cases: &[(&str, u8, u16)] = &[
            ("HHB28601", 4, 104), // S19 Hydro
            ("HHB28602", 4, 104), // T19 Hydro
            ("HHB42602", 4, 180), // S19 Pro Hydro
            ("HHB56702", 3, 204), // T19 Pro Hydro
            ("HHB56601", 3, 204), // S19 XP Hydro
            ("H6HB56702", 3, 204), // S19e XP Hydro
            ("HHB68501", 3, 216), // S21 Hydro
            ("HHB68502", 3, 216),
            ("HHB68503", 3, 216),
            ("HHB68601", 3, 216),
            ("H6HB70501", 3, 160), // S21 XP Hydro
            ("H6HB70701", 3, 95),  // S21+ Hydro (one-source)
            ("H6HB70702", 3, 95),
            ("H6HB70801", 3, 85),  // S21e Hydro
            ("IHB68601", 3, 156),  // S21 Imm (one-source)
            ("M1HB70601", 3, 91),  // S21 XP Imm
            ("M1HB70602", 3, 91),
        ];
        for &(sku, chains, chips) in cases {
            let row = hydro_fleet_descriptor(sku).unwrap();
            assert_eq!(
                (row.chains_per_unit, row.chips_per_chain),
                (chains, chips),
                "{sku}"
            );
            assert_eq!(
                row.declared_chips_per_unit(),
                u32::from(chains) * u32::from(chips),
                "{sku}"
            );
        }
        // 4×180 = 720 is the largest per-unit population in the corpus.
        assert_eq!(
            hydro_fleet_descriptor("HHB42602").unwrap().declared_chips_per_unit(),
            720
        );
        // 3×216 = 648 S21 Hydro.
        assert_eq!(
            hydro_fleet_descriptor("HHB68601").unwrap().declared_chips_per_unit(),
            648
        );
    }

    /// Cross-check against the checked-in VNish matrix: every fleet row
    /// whose SKU has a VNish row must agree on chains + per-chain geometry,
    /// and every basis that claims VNish agreement must actually have one.
    #[test]
    fn vnish_matrix_cross_check_agrees_where_claimed() {
        use crate::vnish_thermal::vnish_model_by_btm;
        let mut vnish_rows_checked = 0;
        for row in all_hydro_fleet_descriptors() {
            let Some(v) = vnish_model_by_btm(row.hashboard_sku) else {
                assert_ne!(
                    row.chain_basis,
                    ChainCountBasis::StockTopolAndVnishMatrix,
                    "{} claims VNish agreement but has no VNish row",
                    row.hashboard_sku
                );
                continue;
            };
            vnish_rows_checked += 1;
            assert_eq!(
                v.chains_per_unit, row.chains_per_unit,
                "{}: chains disagree with VNish",
                row.hashboard_sku
            );
            assert_eq!(
                v.chips_per_chain, row.chips_per_chain,
                "{}: chips/chain disagree with VNish",
                row.hashboard_sku
            );
            assert_eq!(
                v.domains_per_chain, row.domains_per_chain,
                "{}: domains disagree with VNish",
                row.hashboard_sku
            );
            assert_eq!(
                v.chips_per_domain, row.chips_per_domain,
                "{}: chips/domain disagree with VNish",
                row.hashboard_sku
            );
            // The VNish hydro/immersion rows are immersion-mode-only.
            assert!(v.is_immersion_only(), "{}", row.hashboard_sku);
        }
        // 23 fleet SKUs have VNish rows: the 13 stock+VNish-corroborated
        // boards plus all 10 no-stock rows themselves.
        assert_eq!(vnish_rows_checked, 23);
    }

    /// Cross-check against the ePIC v1.24.0 delta-backed identity catalog:
    /// the two rows it decodes must agree with the fleet row.
    #[test]
    fn epic_delta_rows_agree() {
        for (sku, chips) in [("H6HB70801", 85u16), ("M1HB70602", 91u16)] {
            let ident = crate::hashboard_catalog::hashboard_identity(sku)
                .unwrap_or_else(|| panic!("{sku} is in the identity catalog"));
            assert_eq!(ident.chips_per_chain, chips, "{sku}");
            assert_eq!(
                hydro_fleet_descriptor(sku).unwrap().chips_per_chain,
                chips,
                "{sku}"
            );
        }
    }

    /// Stock-side citation coherence: every stock-backed row cites a topol
    /// AND a levels file under the Phase A extraction namespace; no-stock
    /// rows cite nothing.
    #[test]
    fn citations_are_present_exactly_where_stock_backed() {
        for row in all_hydro_fleet_descriptors() {
            if row.chain_basis.is_stock_backed() {
                let topol = row.stock_topol_citation.unwrap();
                assert!(
                    topol.contains("asicminingsupplies")
                        && topol.ends_with("topol.conf"),
                    "{}: bad topol citation",
                    row.hashboard_sku
                );
                let levels = row.stock_levels_citation.unwrap();
                assert!(
                    levels.contains("asicminingsupplies")
                        && levels.ends_with("levels.json"),
                    "{}: bad levels citation",
                    row.hashboard_sku
                );
                assert!(row.stock_chain_num.is_some());
                assert!(row.stock_psu_dialect.is_some());
                assert!(row.stock_declared_fan_slots.is_some());
            } else {
                assert_eq!(row.stock_topol_citation, None);
                assert_eq!(row.stock_levels_citation, None);
                assert_eq!(row.stock_chain_num, None);
                assert_eq!(row.stock_psu_dialect, None);
                assert_eq!(row.stock_pid_target_temp_c, None);
                assert_eq!(row.stock_declared_fan_slots, None);
            }
        }
    }

    /// The chain-count adjudication, pinned: stock says 4 on EVERY 2022-gen
    /// hydro machine and 3 on every XP/S21-gen machine; no row mixes them.
    #[test]
    fn chain_count_adjudication_by_generation() {
        let gen_2022 = [
            "HHB28601", "HHB28602", "HHB42601", "HHB42602", "HHB42631", "HHB42701", "HHB42711",
            "TH401",
        ];
        for sku in gen_2022 {
            assert_eq!(
                hydro_fleet_descriptor(sku).unwrap().chains_per_unit,
                4,
                "{sku}: 2022-gen hydro is 4-chain (stock + VNish vs the old catalog row)"
            );
        }
        for row in all_hydro_fleet_descriptors() {
            if !gen_2022.contains(&row.hashboard_sku) {
                assert_eq!(
                    row.chains_per_unit, 3,
                    "{}: every non-2022-gen row is 3-chain",
                    row.hashboard_sku
                );
            }
        }
    }

    /// Thermal bytes: stock 2022-gen trees have NO strategy block (temps
    /// UNKNOWN from stock); every XP/S21-gen stock tree declares
    /// pid_target_temp 50. Danger/hot limits are unknown from stock on ALL
    /// rows — this type deliberately has no field for them.
    #[test]
    fn stock_thermal_bytes_are_pinned_verbatim() {
        for sku in ["HHB28601", "HHB28602", "HHB42602", "HHB42631", "TH401"] {
            assert_eq!(
                hydro_fleet_descriptor(sku).unwrap().stock_pid_target_temp_c,
                None,
                "{sku}: 2022-gen stock trees carry no strategy temps"
            );
        }
        for row in all_hydro_fleet_descriptors() {
            if let Some(t) = row.stock_pid_target_temp_c {
                assert_eq!(t, 50, "{}: corpus-wide XP-gen pid target", row.hashboard_sku);
                assert!(row.chain_basis.is_stock_backed());
            }
        }
        // Stock declares 4 fan slots on every hydro machine (wiring
        // declaration — NOT a fan floor).
        for row in all_hydro_fleet_descriptors() {
            assert_ne!(row.stock_declared_fan_slots, Some(0));
            if row.chain_basis.is_stock_backed() {
                assert_eq!(row.stock_declared_fan_slots, Some(4), "{}", row.hashboard_sku);
            }
        }
    }

    // ------------------------------------------------------------------
    // The fanless-medium safety consumers (the point of task 3).
    // ------------------------------------------------------------------

    /// Every hydro/immersion fleet row resolves to a cut ladder with NO
    /// fan-raise rung (ABSENT, not zero) that validates under the exact
    /// registry validator the BoardDesc rows are gated by.
    #[test]
    fn every_fleet_row_resolves_a_fanless_ladder_that_validates() {
        for row in all_hydro_fleet_descriptors() {
            let ladder = row.cut_ladder();
            assert!(
                !ladder.is_empty(),
                "{}: ladder must be non-empty",
                row.hashboard_sku
            );
            assert!(
                !ladder.iter().any(|r| r.is_fan_raise()),
                "{}: a fanless medium must carry NO RaiseFansToCap rung — absent, not zero",
                row.hashboard_sku
            );
            assert!(
                ladder.last().is_some_and(|r| r.is_power_cut()),
                "{}: terminal rung must be a power cut",
                row.hashboard_sku
            );
            row.validate_cut_ladder()
                .unwrap_or_else(|e| panic!("{}: {e}", row.hashboard_sku));
            // And the medium genuinely earns the fan bypass (external loop).
            assert!(fan_bypass_permitted(Some(row.medium)));
            assert!(!row.medium.has_fan_actuator());
        }
    }

    /// The positive refusal direction, through the fleet layer: giving a
    /// fleet row the AIR ladder must be refused by the same validator —
    /// the air ladder's fan rung is exactly the rung a fanless board must
    /// not carry.
    #[test]
    fn a_fleet_row_given_the_air_ladder_is_refused() {
        for row in all_hydro_fleet_descriptors() {
            let err = validate_cut_ladder(Some(row.medium), CANONICAL_FORCED_AIR_LADDER)
                .expect_err("air ladder on a fanless medium must be refused");
            assert!(
                matches!(err, CutLadderError::FanRungOnFanlessMedium { .. }),
                "{}: got {err:?}",
                row.hashboard_sku
            );
        }
    }

    // ------------------------------------------------------------------
    // The medium-from-hashboard-code discriminator.
    // ------------------------------------------------------------------

    #[test]
    fn medium_discriminator_resolves_the_pinned_prefixes() {
        assert_eq!(
            cooling_medium_for_hashboard_code("HHB28601"),
            Some(CoolingMedium::Hydro)
        );
        assert_eq!(
            cooling_medium_for_hashboard_code("H6HB70801"),
            Some(CoolingMedium::Hydro)
        );
        assert_eq!(
            cooling_medium_for_hashboard_code("H1HB56703"),
            Some(CoolingMedium::Hydro)
        );
        assert_eq!(
            cooling_medium_for_hashboard_code("IHB68601"),
            Some(CoolingMedium::Immersion)
        );
        assert_eq!(
            cooling_medium_for_hashboard_code("M1HB70602"),
            Some(CoolingMedium::Immersion)
        );
        assert_eq!(
            cooling_medium_for_hashboard_code("BHB68603"),
            Some(CoolingMedium::Air)
        );
        assert_eq!(
            cooling_medium_for_hashboard_code("A3HB70501"),
            Some(CoolingMedium::Air)
        );
    }

    /// Fail-closed: unknown prefixes, non-fleet codes, case variants and
    /// junk all return `None` (undeclared) — which keeps fans managed and
    /// grants no bypass. `TH401` is the deliberate known miss (hydro per
    /// stock, prefix not in the pinned discriminator).
    #[test]
    fn medium_discriminator_fails_closed() {
        for code in [
            "TH401",
            "NBP1901",
            "NBS1902",
            "TS007",
            "42801",
            "BHBXXXX",
            "",
            "hhb28601",
            "hhb",
            "H",
            "HB68601",
            "XHB99999",
        ] {
            // Note: "BHBXXXX" and "42801" ARE corpus placeholder IDs; the
            // discriminator is a *prefix* table, so "BHBXXXX" resolves Air.
            let expected = if code.starts_with("BHB") {
                Some(CoolingMedium::Air)
            } else {
                None
            };
            assert_eq!(
                cooling_medium_for_hashboard_code(code),
                expected,
                "{code:?} must match the pinned expectation"
            );
        }
        // None of the misses ever earns the fan bypass.
        for code in ["TH401", "NBP1901", "", "hhb28601"] {
            assert!(!fan_bypass_permitted(cooling_medium_for_hashboard_code(code)));
        }
    }

    /// The H1HB dissent, pinned: stock ships H1HB70601 in the S21 XP HYDRO
    /// image; VNish's H1HB70602/H1HB68601 rows are immersion-only. The
    /// discriminator follows stock + the pinned board_desc doc (Hydro);
    /// the safety projection is identical either way.
    #[test]
    fn h1hb_plumbing_dissent_is_pinned_and_safety_neutral() {
        assert_eq!(
            cooling_medium_for_hashboard_code("H1HB70601"),
            Some(CoolingMedium::Hydro)
        );
        let stock_row = hydro_fleet_descriptor("H1HB70601").unwrap();
        assert_eq!(stock_row.medium, CoolingMedium::Hydro);
        let vnish_row = hydro_fleet_descriptor("H1HB70602").unwrap();
        assert_eq!(vnish_row.medium, CoolingMedium::Immersion);
        // Zero safety delta: both project to ExternalLoop.
        assert_eq!(
            stock_row.medium.cooling_class(),
            vnish_row.medium.cooling_class()
        );
        // And the VNish immersion rows really are immersion-mode-only.
        for sku in ["H1HB70602", "H1HB68601", "IHB68601", "M1HB70601"] {
            let v = crate::vnish_thermal::vnish_model_by_btm(sku).unwrap();
            assert!(v.is_immersion_only(), "{sku}");
        }
    }

    /// The discriminator agrees with every fleet row's declared medium,
    /// with exactly two kinds of deliberate exception: `TH401` (hydro per
    /// stock, prefix outside the pinned discriminator ⇒ `None`) and the
    /// VNish immersion H1HB rows (the plumbing dissent — prefix says Hydro
    /// per stock, the row says Immersion per VNish; the cooling CLASS is
    /// identical, so neither exception has any safety delta).
    #[test]
    fn discriminator_and_fleet_table_agree_except_the_pinned_dissents() {
        for row in all_hydro_fleet_descriptors() {
            let resolved = cooling_medium_for_hashboard_code(row.hashboard_sku);
            if row.hashboard_sku == "TH401" {
                assert_eq!(resolved, None, "TH401 is the deliberate prefix miss");
                continue;
            }
            if matches!(row.hashboard_sku, "H1HB68601" | "H1HB70602") {
                // The H1HB dissent: prefix (stock-backed) says Hydro, the
                // VNish-only row says Immersion. Pin BOTH sides and the
                // identical safety projection.
                assert_eq!(resolved, Some(CoolingMedium::Hydro));
                assert_eq!(row.medium, CoolingMedium::Immersion);
                assert_eq!(
                    resolved.unwrap().cooling_class(),
                    row.medium.cooling_class()
                );
                continue;
            }
            assert_eq!(
                resolved,
                Some(row.medium),
                "{}",
                row.hashboard_sku
            );
        }
    }
}
