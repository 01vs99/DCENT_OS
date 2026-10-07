//! Capability-first hashboard-EEPROM identity bridge.
//!
//! # Why
//!
//! Two byte-exact Bitmain hashboard-EEPROM decoders now exist —
//! [`crate::zhiju_eeprom`] (BHB42xxx, block `0x42`, preamble byte 0 = `0x04`) and
//! [`crate::bm1366_eeprom`] (BHB56902, block `0x48`, preamble byte 0 = `0x05`) — and the
//! RE proved they share one CRC5, one length-gate discipline, and one identity-field
//! layout. Rather than let every future family copy a third decoder, this module is the
//! single, capability-first entry point: dispatch on the family byte, decode, and — where
//! the evidence is EXACT — produce the independent `observed` [`AsicProtocolIdentity`]
//! that [`dcentrald_common::BoardDesc::admit_asic_protocol`] needs as its second source.
//!
//! # The safety-critical asymmetry (do not weaken)
//!
//! The whole point of the two-source admission is that `observed` identity must be
//! **exact**. That is only true for some families:
//!
//! - **`0x05` (BHB56xxx)** is a UNIQUE family byte. An EEPROM with byte0 `0x05` and a
//!   `BHB56902` serial prefix is an unambiguous BM1366 NoPic board → observed
//!   [`AsicProtocolIdentity::Bm1366`]. This is the exact evidence that lets the native
//!   BM1366 refusal become a gated Experimental path.
//! - **`0x04` (BHB42xxx)** is SHARED between BM1398 (S19 Pro) and BM1362 (S19j Pro). The
//!   zhiju block carries no ASIC-model field, so byte0 `0x04` alone CANNOT disambiguate
//!   them. This resolver therefore returns `observed = None` for the `0x04` family — a
//!   deliberate, load-bearing refusal. Disambiguating BM1398 needs an EXTERNAL source
//!   (Config.ini `board_name`→`asic_type`, or a confirmed `hashboard_sn` prefix), which
//!   is not yet pinned to real board strings. Never map `0x04` to a concrete chip here.
//!
//! # Status
//!
//! Pure, host-testable, no HAL/IO. Produces identity evidence only; it authorizes
//! nothing on its own — a caller still pairs `observed` with the declared BoardDesc via
//! `admit_asic_protocol` and applies the platform's Experimental gates.

use crate::bm1366_eeprom::{self, Bhb56902Record};
use crate::zhiju_eeprom::{self, ZhijuInformationBlock};
use dcentrald_common::board_desc::AsicProtocolIdentity;

/// Which Bitmain hashboard-EEPROM family a plaintext blob belongs to, by preamble byte 0.
///
/// Not a serde DTO: this carries a `dcentrald_common::AsicProtocolIdentity` (which is
/// intentionally not `Serialize`), and it is internal admission evidence, not a wire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashboardEepromFamily {
    /// `0x04` — BHB42xxx (S19/S19j Pro/T19; BM1398 **or** BM1362; XXTEA-keyed).
    Bhb42xxx,
    /// `0x05` — BHB56xxx (S19k Pro/S19 XP; BM1366/68/70; AES-keyed).
    Bhb56xxx,
}

/// Family preamble byte 0 values.
pub const FAMILY_BYTE_BHB42XXX: u8 = 0x04;
pub const FAMILY_BYTE_BHB56XXX: u8 = 0x05;

/// Serial prefix that pins a BHB56xxx block to the BM1366 S19k Pro board.
pub const BM1366_SN_PREFIX: &str = "BHB56902";

/// A decoded hashboard-EEPROM identity plus, when exactly determinable, the independent
/// observed ASIC protocol identity for two-source admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashboardIdentity {
    pub family: HashboardEepromFamily,
    pub hashboard_sn: String,
    pub chip_die: String,
    pub chip_marking: String,
    /// The independent observed protocol identity, **only when the family evidence is
    /// exact** (see the module asymmetry note). `None` for the ambiguous `0x04` family.
    pub observed_protocol: Option<AsicProtocolIdentity>,
}

/// Reasons identification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashboardIdentifyError {
    /// Too short to read the preamble.
    Truncated,
    /// Preamble byte 0 is neither `0x04` nor `0x05`.
    UnknownFamily { byte0: u8 },
    /// The family byte was recognized but the family decoder rejected the block.
    Decode {
        family: HashboardEepromFamily,
        detail: String,
    },
}

impl core::fmt::Display for HashboardIdentifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "hashboard EEPROM too short to read preamble"),
            Self::UnknownFamily { byte0 } => {
                write!(f, "unknown hashboard EEPROM family byte 0x{byte0:02x}")
            }
            Self::Decode { family, detail } => {
                write!(f, "hashboard EEPROM {family:?} decode failed: {detail}")
            }
        }
    }
}

impl std::error::Error for HashboardIdentifyError {}

/// Decode a plaintext hashboard-EEPROM block and resolve identity.
///
/// Dispatches on preamble byte 0. `plaintext` must be post-cipher. Returns the decoded
/// identity fields and, for the unique `0x05` family, the exact observed protocol.
pub fn identify_hashboard(plaintext: &[u8]) -> Result<HashboardIdentity, HashboardIdentifyError> {
    if plaintext.is_empty() {
        return Err(HashboardIdentifyError::Truncated);
    }
    match plaintext[0] {
        FAMILY_BYTE_BHB42XXX => {
            let block: ZhijuInformationBlock = zhiju_eeprom::decode_zhiju_block(plaintext)
                .map_err(|e| HashboardIdentifyError::Decode {
                    family: HashboardEepromFamily::Bhb42xxx,
                    detail: e.to_string(),
                })?;
            Ok(HashboardIdentity {
                family: HashboardEepromFamily::Bhb42xxx,
                hashboard_sn: block.hashboard_sn,
                chip_die: block.chip_die,
                chip_marking: block.chip_marking,
                // DELIBERATELY None: 0x04 spans BM1398 and BM1362; the block cannot
                // disambiguate them. Keeping this None keeps native BM1398 refused.
                observed_protocol: None,
            })
        }
        FAMILY_BYTE_BHB56XXX => {
            let rec: Bhb56902Record =
                bm1366_eeprom::decode_bhb56902_block(plaintext).map_err(|e| {
                    HashboardIdentifyError::Decode {
                        family: HashboardEepromFamily::Bhb56xxx,
                        detail: e.to_string(),
                    }
                })?;
            // 0x05 is unique; a BHB56902 serial prefix pins it to BM1366 NoPic.
            let observed_protocol = if rec.hashboard_sn.starts_with(BM1366_SN_PREFIX) {
                Some(AsicProtocolIdentity::Bm1366)
            } else {
                None
            };
            Ok(HashboardIdentity {
                family: HashboardEepromFamily::Bhb56xxx,
                hashboard_sn: rec.hashboard_sn,
                chip_die: rec.chip_die,
                chip_marking: rec.chip_marking,
                observed_protocol,
            })
        }
        other => Err(HashboardIdentifyError::UnknownFamily { byte0: other }),
    }
}

// ----------------------------------------------------------------------------
// Native-mining experimental admission policy (pure decision)
// ----------------------------------------------------------------------------
//
// This is the decision layer that lets a deliberate `NOT IMPLEMENTED` native-mining
// refusal become a **gated, fail-closed, two-source** Experimental path — without
// deleting the safety refusal. The mining engine calls [`admit_native_experimental`]
// at the refusal site; the default (no opt-in, or any missing/mismatched evidence) is
// byte-for-byte the same refusal as before.

/// Env opt-in for native BM1366 (S19k Pro) Experimental mining. Default-OFF.
pub const EXPERIMENTAL_NATIVE_BM1366_ENV: &str = "DCENT_EXPERIMENTAL_NATIVE_BM1366";

/// Outcome of the native-mining experimental admission decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeExperimentalAdmission {
    /// Keep the hard refusal. Carries the reason for logging/`bail!`.
    Refused(String),
    /// Proceed as EXPERIMENTAL. The engine must log loudly and keep every downstream
    /// safety gate (fail-closed voltage ceiling, watchdog, teardown) in force.
    AdmittedExperimental { identity: AsicProtocolIdentity },
}

/// Decide whether a native path may run as Experimental.
///
/// Fail-closed by construction — [`NativeExperimentalAdmission::AdmittedExperimental`]
/// is returned ONLY when ALL of:
/// 1. the operator set the explicit experimental opt-in (`experimental_opt_in`),
/// 2. an independent `observed` identity was established (e.g. from
///    [`identify_hashboard`]'s exact `observed_protocol`), and
/// 3. that observed identity EXACTLY equals the engine's `required` protocol.
///
/// Any missing or mismatched input returns [`NativeExperimentalAdmission::Refused`]
/// with the reason — identical in effect to the pre-existing `NOT IMPLEMENTED` bail.
/// This never itself commands hardware.
pub fn admit_native_experimental(
    experimental_opt_in: bool,
    observed: Option<AsicProtocolIdentity>,
    required: AsicProtocolIdentity,
    baseline_refusal: &str,
) -> NativeExperimentalAdmission {
    if !experimental_opt_in {
        // Default path: unchanged refusal.
        return NativeExperimentalAdmission::Refused(baseline_refusal.to_string());
    }
    let Some(observed) = observed else {
        return NativeExperimentalAdmission::Refused(format!(
            "{baseline_refusal} [experimental opt-in set, but no independent observed \
             ASIC identity was established; fail-closed]"
        ));
    };
    if observed != required {
        return NativeExperimentalAdmission::Refused(format!(
            "{baseline_refusal} [experimental opt-in set, but observed identity {observed:?} \
             does not match required {required:?}; fail-closed]"
        ));
    }
    NativeExperimentalAdmission::AdmittedExperimental { identity: required }
}

// ----------------------------------------------------------------------------
// Deployed-format observed identity (real factory-programmed boards)
// ----------------------------------------------------------------------------
//
// [`identify_hashboard`] above decodes the factory-*jig* plaintext layout
// ([`crate::zhiju_eeprom`] / [`crate::bm1366_eeprom`]). Real deployed boards use a
// DIFFERENT on-wire layout, decoded by [`crate::deployed_eeprom`] (XXTEA + 3-region
// split, proven byte-exact against four held real dumps). These helpers bridge that
// deployed decode to an exact `observed` [`AsicProtocolIdentity`] for two-source
// admission — the piece that lets a decoded REAL board feed
// [`admit_native_experimental`].

/// How one [`DEPLOYED_SKU_IDENTITY_POLICY`] row matches a deployed `board_name`.
#[derive(Debug, Clone, Copy)]
enum DeployedSkuMatch {
    /// The whole documented family shares one chip, so a prefix is safe.
    Family(&'static str),
    /// ONLY this exact SKU is the stated chip — the surrounding prefix space is
    /// a DIFFERENT chip, so a prefix match here would mis-mint.
    Exact(&'static str),
}

impl DeployedSkuMatch {
    fn matches(self, name: &str) -> bool {
        match self {
            Self::Family(prefix) => name.starts_with(prefix),
            Self::Exact(sku) => name == sku,
        }
    }
}

/// The SKUs this bridge is willing to mint an observed identity for, each pinned
/// to the family it is expected to be.
///
/// This table is admission POLICY (which SKUs are trusted enough to mint), not
/// family authority — SKU→family stays single-sourced in
/// [`crate::eeprom_record::chip_family_for_sku`], and a row only admits when that
/// catalog independently agrees (see [`observed_protocol_for_deployed_board_name`]).
const DEPLOYED_SKU_IDENTITY_POLICY: &[(DeployedSkuMatch, AsicProtocolIdentity)] = &[
    // S19j Pro. One BM1362 family in both the catalog (`BHB426xx`, high
    // confidence) and bosminer's own held model list (`BHB42601`/`BHB42621`/
    // `BHB42641` → BM1362); `BHB42601` is validated vs the real `a lab unit` dump. The
    // prefix IS the documented family boundary here, so it is not over-broad.
    //
    // KNOWN RESIDUAL, recorded 2026-07-26 — read before wiring a consumer.
    //  §1.3 lists all 11
    // BM1398 S19 models against a `BHB42xxx` hashboard, and §1.4's S19j row reads
    // "BM1362 (early-bin BM1398 in some batches)". Note `BHB42xxx` there is the
    // doc's GENERIC placeholder — it is NOT a confirmed `BHB426xx` SKU, and every
    // per-SKU row that names digits (BHB42601/03/11/21/31/32/41/51, BHB42701) is
    // BM1362. So this is an UNRESOLVED overlap, not a proven collision.
    // If it resolves against us — a `BHB426xx`-prefixed board carrying early-bin
    // BM1398 — step (3) CANNOT catch it, because the catalog says BHB426xx →
    // BM1362 too: a two-source agreement gate gives no protection where both
    // sources share a blind spot. Narrowing to the dump-validated `BHB42601`
    // would trade that for refusing real sibling boards with no evidence they
    // differ, so the prefix stays.
    //
    // STILL OPEN after the 2026-08-02 `chip_marking` work (W5-RANK-13). The lot-code
    // corroborator below (`CHIP_MARKING_FAMILY_LETTERS` / `corroborate_marking`) does
    // NOT close this: the September 2 NBP1901 pages use a different `0x11 0x42`
    // generation, with no proven relation between their die/date strings and
    // this format's family letter. The explicit NBP1901 decoder below joins a
    // sealed chip observation; it does not generalize a new letter mapping.
    //
    // NOTE (corrected): this bridge DOES have a production caller now —
    // `serial_mining.rs` folds the retained hashboard pages through
    // `admit_native_experimental` on the non-passthrough BM1366 path, behind an
    // operator opt-in. The residual above is therefore no longer "zero live
    // exposure". It stays acceptable for THAT consumer only because its single
    // mis-mint direction is `Bm1362`, which an exact `required == Bm1366`
    // equality refuses. Any future consumer whose `required` is `Bm1362` must
    // re-adjudicate this before relying on two-source agreement.
    (
        DeployedSkuMatch::Family("BHB426"),
        AsicProtocolIdentity::Bm1362,
    ),
    // BHB427/BHB428 BM1362 efficiency/high-bin boards. EXACT page-backed SKUs
    // only: the held ePIC matched corpus contains format-4 pages for 42701,
    // 42801, and 42831; all three decrypt with lot-code family letter `C`, and
    // their factory V/F values agree with the independent BM1362 PVT/topology
    // catalogs. The four roster-only BHB428 siblings are catalogued BM1362 but
    // have no held deployed page, so they do not appear in this admission
    // policy. Never replace these with a BHB427/BHB428 prefix: unknown suffixes
    // remain unobserved and must fail closed.
    (
        DeployedSkuMatch::Exact("BHB42701"),
        AsicProtocolIdentity::Bm1362,
    ),
    (
        DeployedSkuMatch::Exact("BHB42801"),
        AsicProtocolIdentity::Bm1362,
    ),
    (
        DeployedSkuMatch::Exact("BHB42831"),
        AsicProtocolIdentity::Bm1362,
    ),
    // S19k Pro NoPic, validated vs the S19k `BHB56903` dump. Deliberately
    // NARROWER than the catalog's `BHB568xx / BHB569xx` pattern: the `BHB568`
    // half has no held dump, and this bridge admits validated SKUs only.
    (
        DeployedSkuMatch::Family("BHB569"),
        AsicProtocolIdentity::Bm1366,
    ),
    // S21 BM1368 — EXACT SKUs only. `starts_with("BHB68")` would be a
    // wrong-voltage-table hazard: every other SKU in that prefix space falls
    // through to the catalog's broad `BHB68xxx` → BM1370 row. `BHB68606` is
    // validated vs the held S21 `eeprom_dump_0x51.hex`. `BHB68603` also has
    // an exact ePIC fixture page (not an authenticated live dump), while
    // `BHB68603-` is a medium-confidence identity row with no held page and an
    // unknown EEPROM format.
    (
        DeployedSkuMatch::Exact("BHB68603"),
        AsicProtocolIdentity::Bm1368,
    ),
    // NOTE: `BHB68603-` cannot currently arrive via
    // `observed_protocol_from_deployed_page` — `deployed_eeprom::is_plausible_board_name`
    // rejects the `-` via its ASCII-alphanumeric filter. The row serves direct
    // `board_name` callers and pre-stages that decoder fix (a narrow trailing-hyphen
    // exemption, deliberately deferred to its own verified change so the wrong-key
    // entropy guard can be re-proven).
    (
        DeployedSkuMatch::Exact("BHB68603-"),
        AsicProtocolIdentity::Bm1368,
    ),
    (
        DeployedSkuMatch::Exact("BHB68606"),
        AsicProtocolIdentity::Bm1368,
    ),
];

/// Map a *deployed* hashboard `board_name` (SKU) to an exact observed ASIC identity.
///
/// **Conservative + fail-closed by design.** Two checks run, in order:
///
/// 1. The SKU must match a [`DEPLOYED_SKU_IDENTITY_POLICY`] row. Everything else
///    — unvalidated, unknown, empty, or merely catalog-known — returns `None`.
/// 2. [`crate::eeprom_record::chip_family_for_sku`] must independently resolve
///    that SKU to the SAME family. The catalog stays the single source of truth
///    for SKU→family; this function only decides which SKUs are trusted enough
///    to mint. Any divergence (catalog correction, row removal, pattern reorder)
///    is a refusal, never a silently stale identity.
///
/// Admitted today:
///
/// - `BHB426xx` → [`AsicProtocolIdentity::Bm1362`] (S19j Pro; validated vs the
///   `a lab unit` BHB42601 dump — consistent in `hashboards.rs` and `eeprom_record`).
/// - exact `BHB42701` / `BHB42801` / `BHB42831` →
///   [`AsicProtocolIdentity::Bm1362`] (held format-4 pages + BM1362
///   lot-code/PVT/topology agreement; sibling and unknown names remain refused).
/// - `BHB569xx` → [`AsicProtocolIdentity::Bm1366`] (S19k Pro; validated vs the
///   S19k BHB56903 dump — the unique `0x05` NoPic family).
/// - `BHB68603` / `BHB68603-` / `BHB68606` → [`AsicProtocolIdentity::Bm1368`]
///   (S21; EXACT SKUs only — `BHB68606` is validated vs the held S21
///   `eeprom_dump_0x51.hex`; `BHB68603` has an ePIC fixture page but not an
///   authenticated live dump; `BHB68603-` has no held EEPROM page).
///
/// Can never return [`AsicProtocolIdentity::Bm1398`]: no policy row declares it,
/// and a row only ever admits its OWN declared identity, so the catalog cannot
/// inject one either (mirrors the load-bearing "0x04 never admits BM1398"
/// invariant of [`identify_hashboard`]). Pinned by
/// `deployed_policy_table_can_never_declare_bm1398`.
pub fn observed_protocol_for_deployed_board_name(board_name: &str) -> Option<AsicProtocolIdentity> {
    let name = board_name.trim();
    // (1) Admission policy: only validated/exact SKUs may mint at all.
    let expected = DEPLOYED_SKU_IDENTITY_POLICY
        .iter()
        .find(|(matcher, _)| matcher.matches(name))
        .map(|(_, identity)| *identity)?;
    // (2) Two-table agreement: the catalog owns SKU→family, so a divergence
    // fails closed instead of minting this table's stale opinion.
    let cataloged = crate::eeprom_record::chip_family_for_sku(name)
        .and_then(AsicProtocolIdentity::from_chip_label)?;
    if cataloged == expected {
        Some(expected)
    } else {
        None
    }
}

/// Character 2 of a deployed page's factory lot code, per ASIC family.
///
/// **Held evidence, 22 pages, zero exceptions** — 17 from
///
/// plus 5 DCENT-held real dumps (`a lab unit` `0x50`/`0x52`, s19k `0x50`/`0x52`, s21 `0x51`).
/// Full byte table: `deliverables/W5-RANK-13.md` §2.
///
/// This is a **corroborator**, not an authority. It may only ever cause a REFUSAL;
/// nothing may mint a family from it. Two families are deliberately absent and must
/// stay absent until a page is held:
///
/// * **BM1398** — the family in the `:271-276` blind spot. No held page. Guessing
///   `C` here (same generation as BM1362) would manufacture agreement inside the
///   very blind spot this table is mistakenly credited with closing.
/// * **BM1370** — `A3HB7xxxx` pages are format 1 and never reach this code path.
///
/// Adding a row requires a held page, not a DB row: the ePIC capability DB is
/// ePIC-*transcribed* (CONTEXT §3 caveat 3) and carries no lot codes at all.
pub const CHIP_MARKING_FAMILY_LETTERS: &[(AsicProtocolIdentity, char)] = &[
    (AsicProtocolIdentity::Bm1362, 'C'),
    (AsicProtocolIdentity::Bm1366, 'G'),
    (AsicProtocolIdentity::Bm1368, 'V'),
];

/// Outcome of comparing a page's lot-code letter against its name-derived family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkingCorroboration {
    /// The letter is the one this family always shows on held pages.
    Agrees,
    /// The letter belongs to a DIFFERENT family, or is unknown, or is absent.
    /// All three are refusals — see [`corroborate_marking`].
    Refuses(&'static str),
}

/// Fail-closed lot-code corroboration for an identity already minted from
/// `board_name`.
///
/// Refuses on **disagreement**, on an **unknown letter**, and on an **absent
/// marking**. The unknown/absent cases are refusals rather than pass-throughs
/// because this runs only for SKUs already admitted by
/// [`DEPLOYED_SKU_IDENTITY_POLICY`], and every family in that table has a row in
/// [`CHIP_MARKING_FAMILY_LETTERS`] (pinned by
/// `every_admissible_family_has_a_marking_letter`). A page in that narrow set with
/// an unrecognised letter is anomalous, and the only production consumer is an
/// operator-opt-in Experimental lane whose refusal path is the pre-existing
/// `NOT IMPLEMENTED` bail — so refusing costs an experiment, while admitting costs
/// a wrong voltage table.
///
/// Deliberately NOT modelled on the `0x5A` end sentinel (`deployed_eeprom.rs:100`),
/// which is advisory because it sits outside every enciphered region and
/// authenticates nothing. Byte 23 is inside region 1 and under its CRC5, so a
/// mismatch is real evidence of a wrong page, not a stray byte.
pub fn corroborate_marking(
    identity: AsicProtocolIdentity,
    marking_letter: Option<char>,
) -> MarkingCorroboration {
    let Some(expected) = CHIP_MARKING_FAMILY_LETTERS
        .iter()
        .find(|(fam, _)| *fam == identity)
        .map(|(_, c)| *c)
    else {
        return MarkingCorroboration::Refuses(
            "no held-page lot-code letter for this family; fail-closed",
        );
    };
    match marking_letter {
        Some(c) if c == expected => MarkingCorroboration::Agrees,
        Some(_) => MarkingCorroboration::Refuses(
            "page lot code disagrees with the name-derived ASIC family; fail-closed",
        ),
        None => MarkingCorroboration::Refuses(
            "page carries no usable lot code to corroborate identity; fail-closed",
        ),
    }
}

/// Decode a REAL deployed 256-byte hashboard-EEPROM page and resolve its exact
/// observed ASIC identity.
///
/// Runs [`crate::deployed_eeprom::decode_deployed_eeprom`] (fail-closed), then
/// [`observed_protocol_for_deployed_board_name`], then — because only THIS entry point
/// has the page and not merely the name — [`corroborate_marking`] as a third,
/// page-intrinsic requirement. Returns `None` on any decode failure, on a
/// unvalidated SKU, and on any marking disagreement. Pure, no HAL/IO;
/// authorizes nothing on its own — a caller still pairs this `observed` with the
/// declared BoardDesc and applies the experimental opt-in via
/// [`admit_native_experimental`].
///
/// The corroborator lives here and NOT in
/// [`observed_protocol_for_deployed_board_name`], which receives only a `&str` and
/// therefore cannot check it. Callers that hold bytes must use this function.
pub fn observed_protocol_from_deployed_page(raw: &[u8]) -> Option<AsicProtocolIdentity> {
    let identity = crate::deployed_eeprom::decode_deployed_eeprom(raw).ok()?;
    let observed = observed_protocol_for_deployed_board_name(&identity.board_name)?;
    match corroborate_marking(observed, identity.chip_marking_family_letter()) {
        MarkingCorroboration::Agrees => Some(observed),
        MarkingCorroboration::Refuses(_) => None,
    }
}

/// Decode the factory-programmed NBP1901 generation captured on 2026-09-02.
///
/// These pages have no board-name field: neither the `11 42` header nor the
/// part/date code establishes an ASIC family. This function therefore returns
/// decoded data, never protocol admission. It checks the exact cipher window,
/// printable identity fields and the CRC5 verified on both distinct held pages.
/// The raw `voltage_mv` member in the legacy zhiju DTO is *centivolts* on these
/// pages; it must not be used as a requested operating voltage.
pub fn decode_nbp1901_factory_page(raw: &[u8]) -> Result<ZhijuInformationBlock, &'static str> {
    use crate::deployed_eeprom::{
        decrypt_region, key_words, BM1398_GENERATION_LIVE_HEADER,
        LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY, RAW_PAGE_LEN,
    };
    if raw.len() != RAW_PAGE_LEN {
        return Err("NBP1901 identity requires one complete 256-byte factory page");
    }
    if raw[..2] != BM1398_GENERATION_LIVE_HEADER {
        return Err("not the captured NBP1901 factory page generation");
    }
    let range = zhiju_eeprom::XXTEA_PAYLOAD_RANGE;
    let key = key_words(&LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY);
    let mut plaintext = raw[..range.start].to_vec();
    plaintext.extend_from_slice(&decrypt_region(raw, range.start, range.end, &key));
    let block = zhiju_eeprom::decode_zhiju_block(&plaintext)
        .map_err(|_| "NBP1901 factory page identity fields do not decode")?;
    if block.verify_crc5(&plaintext) != zhiju_eeprom::Crc5Check::Match {
        return Err("NBP1901 factory page CRC5 mismatch");
    }
    if block.hashboard_sn.is_empty() || block.chip_die.is_empty() || block.chip_marking.is_empty() {
        return Err("NBP1901 factory page lacks identity fields");
    }
    Ok(block)
}

/// Stock topol.conf `machine` names of the first-party-settled BM1398 native
/// family bins (S19 Pro NBP1901, S19 classic NBS1902, T19 NBT1903 — Phase A
/// §3.7 rows; sources pinned in `dcentrald_common::s19_bm1398_runtime`).
/// `NBP1901-38` is the pre-existing 38-domain alias of the September 2
/// runtime.
pub const BM1398_NATIVE_STOCK_BOARD_NAMES: [&str; 6] = [
    "NBP1901",
    "NBP1901-38",
    "NBS1902",
    "NBT1903",
    "BHB28611",
    "BHB28701",
];

/// Facts read from the EEPROM, independent of the image-selected profile.
/// Legacy 11/42 pages have no board-name field. Selecting an NBS1902 image
/// must never turn an unnamed sample into an NBS1902 observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1398FactoryPage {
    board_name: Option<String>,
    serial: String,
}

impl Bm1398FactoryPage {
    pub fn board_name(&self) -> Option<&str> {
        self.board_name.as_deref()
    }

    pub fn serial(&self) -> &str {
        &self.serial
    }
}

/// Decode physical identity before power is enabled. Named records must
/// pass both encrypted-region CRCs and match an exact stock topology name.
/// The legacy decoder remains useful for diagnostics but does not invent a
/// model from its serial, factory rail, marking characters or page preamble.
pub fn decode_bm1398_factory_page(raw: &[u8]) -> Result<Bm1398FactoryPage, &'static str> {
    if raw.get(..2) == Some(&[0x11, 0x42]) {
        let legacy = decode_nbp1901_factory_page(raw)?;
        return Ok(Bm1398FactoryPage {
            board_name: None,
            serial: legacy.hashboard_sn,
        });
    }
    let named = crate::deployed_eeprom::decode_deployed_eeprom(raw)
        .map_err(|_| "BM1398 factory identity does not decode")?;
    if !BM1398_NATIVE_STOCK_BOARD_NAMES.contains(&named.board_name.as_str())
        || named.board_serial.is_empty()
        || named.region_1_crc5 != zhiju_eeprom::Crc5Check::Match
        || named.region_2_crc5 != zhiju_eeprom::Crc5Check::Match
    {
        return Err("BM1398 factory identity requires exact stock name and both valid CRC regions");
    }
    Ok(Bm1398FactoryPage {
        board_name: Some(named.board_name),
        serial: named.board_serial,
    })
}

/// Join the selected stock profile to an independently decoded exact name,
/// both valid encrypted-region CRCs and a sealed chip-register observation.
/// An unnamed legacy page cannot acquire its selected image's profile name.
/// Named-format fixtures exercise parsing and refusal; no held named page
/// for NBS1902/NBT1903/BHB28611/BHB28701 is claimed by this bridge.
pub fn observed_protocol_from_bm1398_factory_page(
    raw: &[u8],
    stock_board_name: &str,
    observed_chip: Option<crate::bm1398_get_address::Bm1398GetAddressObservation>,
) -> Option<AsicProtocolIdentity> {
    if !BM1398_NATIVE_STOCK_BOARD_NAMES.contains(&stock_board_name)
        || observed_chip.map(|observation| observation.chip_id()) != Some(0x1398)
    {
        return None;
    }
    let observed = decode_bm1398_factory_page(raw).ok()?;
    if observed.board_name() != Some(stock_board_name) {
        return None;
    }
    Some(AsicProtocolIdentity::Bm1398)
}

/// Join the decoded factory page with an independently selected exact carrier
/// and an actual register-zero chip identity. No family is inferred from the
/// header, the lot-code characters, the operator's model label, or BHB42 alone.
///
/// `stock_board_name` must come from the exact controller/board composition;
/// `observed_chip` is the sealed CRC-checked register-zero observation, never
/// a numeric ID copied from BoardDesc. A caller must additionally certify chain coverage
/// before work. This pure bridge performs no EEPROM writes or hardware I/O.
pub fn observed_protocol_from_nbp1901_factory_page(
    raw: &[u8],
    stock_board_name: &str,
    observed_chip: Option<crate::bm1398_get_address::Bm1398GetAddressObservation>,
) -> Option<AsicProtocolIdentity> {
    if !matches!(stock_board_name, "NBP1901" | "NBP1901-38") {
        return None;
    }
    observed_protocol_from_bm1398_factory_page(raw, stock_board_name, observed_chip)
}

#[cfg(test)]
mod nbp1901_factory_runtime_tests {
    use super::*;
    use dcentrald_common::s19_bm1398_runtime::{
        executor::*, Bm1398FpgaMidstateMode, Bm1398HybridDeskPlan,
    };
    use dcentrald_common::serial_chain_proof::PacedEnumerationPolicy;
    use std::{
        future::Future,
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
        time::Duration,
    };

    // Actual Sep 2 captured ciphertext, already independently pinned in
    // zhiju_eeprom tests. The remaining page bytes are unused by this decoder.
    const PAGES: [&str; 2] = [
        concat!(
            "11422213c85248cf1657052522c82540d466dda751d68d4d5cfe15d56138b98f",
            "8cd7565a7b393d3894ec7f42e1beeef92aeb6b75955ed63d80be85f6a8131757ade4"
        ),
        concat!(
            "1142fe6b91b8ec624ae7e16b905fa3281759f33497fec9efd0c14460646f9c88",
            "b2a0fafeeb1ec7fa7b470e52b5636dbe928f3bab3eb86b048dd0e4aa985e62215d91"
        ),
    ];
    fn page(index: usize) -> Vec<u8> {
        let mut raw = vec![0xff; 256];
        for (i, pair) in PAGES[index].as_bytes().chunks_exact(2).enumerate() {
            raw[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        raw[255] = 0x5a;
        raw
    }
    fn chip_observation() -> crate::bm1398_get_address::Bm1398GetAddressObservation {
        let raw = [0x13, 0x98, 0x18, 0, 0, 0, 0x04];
        crate::bm1398_get_address::parse_bm1398_get_address_body(&raw).unwrap()
    }
    #[test]
    fn unnamed_held_factory_pages_do_not_acquire_the_selected_profile_name() {
        for (i, serial) in ["HQDZYI3BJJDBG0566", "E015YI3BJAAAH0013"]
            .iter()
            .enumerate()
        {
            let raw = page(i);
            let decoded = decode_nbp1901_factory_page(&raw).unwrap();
            assert_eq!(decoded.hashboard_sn, *serial);
            let observed = decode_bm1398_factory_page(&raw).unwrap();
            assert_eq!(observed.serial(), *serial);
            assert_eq!(observed.board_name(), None);
            assert_eq!(decoded.voltage_mv, 1280); // raw centivolts, not a request
            assert_eq!(
                observed_protocol_from_nbp1901_factory_page(
                    &raw,
                    "NBP1901",
                    Some(chip_observation())
                ),
                None
            );
            assert_eq!(observed_protocol_from_deployed_page(&raw), None);
            assert_eq!(
                observed_protocol_from_nbp1901_factory_page(
                    &raw,
                    "BHB42601",
                    Some(chip_observation())
                ),
                None
            );
            assert_eq!(
                observed_protocol_from_nbp1901_factory_page(&raw, "NBP1901", None),
                None
            );
        }
    }
    #[test]
    fn nbp1901_factory_decoder_rejects_truncation_corruption_and_header_only() {
        let raw = page(0);
        assert!(decode_nbp1901_factory_page(&raw[..66]).is_err());
        let mut broken = raw.clone();
        broken[35] ^= 0x80;
        assert!(decode_nbp1901_factory_page(&broken).is_err());
        let mut unknown = raw.clone();
        unknown[0] = 4;
        assert!(decode_nbp1901_factory_page(&unknown).is_err());
        let mut empty = vec![0; 256];
        empty[..2].copy_from_slice(&[0x11, 0x42]);
        assert!(decode_nbp1901_factory_page(&empty).is_err());
    }

    /// A captured legacy page carries no board name. Selecting any exact
    /// BM1398 profile must not supply that missing physical observation.
    #[test]
    fn bm1398_family_join_refuses_unnamed_pages_for_every_selected_profile() {
        let raw = page(0);
        for name in BM1398_NATIVE_STOCK_BOARD_NAMES {
            assert_eq!(
                observed_protocol_from_bm1398_factory_page(&raw, name, Some(chip_observation())),
                None,
                "{name} must not label the captured unnamed generation"
            );
        }
        for name in ["BHB42601", "NBS1903", "NBT1902", "", "nbp1901"] {
            assert_eq!(
                observed_protocol_from_bm1398_factory_page(&raw, name, Some(chip_observation())),
                None,
                "{name:?} must never join"
            );
        }
        // The NBP1901-only wrapper keeps exactly its two names.
        assert_eq!(
            observed_protocol_from_nbp1901_factory_page(&raw, "NBS1902", Some(chip_observation())),
            None
        );
        assert_eq!(
            observed_protocol_from_nbp1901_factory_page(&raw, "NBP1901", Some(chip_observation())),
            None
        );
    }

    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }
    fn ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("recorded transport fixture must complete synchronously"),
        }
    }

    struct StockFixtureIo {
        events: Arc<std::sync::Mutex<Vec<Bm1398RuntimeAction>>>,
        pic_version: u8,
        psu_version: u8,
        short_chain: bool,
        fail_work: bool,
    }
    impl Bm1398RuntimeIo for StockFixtureIo {
        async fn execute(
            &mut self,
            action: &Bm1398RuntimeAction,
        ) -> Result<Bm1398RuntimeReply, String> {
            self.events.lock().unwrap().push(action.clone());
            use Bm1398RuntimeAction as A;
            use Bm1398RuntimeReply as R;
            match action {
                A::ReadMiscControl { chain } => Ok(R::RegisterValue(
                    self.events
                        .lock()
                        .unwrap()
                        .iter()
                        .rev()
                        .find_map(|event| match event {
                            A::Asic {
                                chain: observed_chain,
                                operation:
                                    dcentrald_common::TransportOp::SendWriteRegBroadcastBm1397Plus {
                                        reg: 0x18,
                                        value,
                                    },
                            } if observed_chain == chain => Some(*value),
                            _ => None,
                        })
                        .unwrap_or(0x0000_7a31),
                )),
                A::VerifyFactoryIdentity { .. } => {
                    let decoded = decode_nbp1901_factory_page(&page(0)).map_err(str::to_owned)?;
                    Ok(R::FactoryIdentity {
                        // Reconstructed exact-name transport fixture. The
                        // legacy held page above proves only the serial.
                        stock_board_name: Some("NBP1901".into()),
                        serial: decoded.hashboard_sn,
                    })
                }
                A::I2c(exchange) => {
                    // Responses are reconstructed from exact stock exchange
                    // grammar, not claimed to be a live DCENT transport capture.
                    let response = match (exchange.endpoint, exchange.request[3]) {
                        (Bm1398FramedEndpoint::Pic { .. }, 0x17) => {
                            assert_eq!(exchange.request, [0x55, 0xaa, 4, 0x17, 0, 0x1b]);
                            vec![
                                5,
                                0x17,
                                self.pic_version,
                                0,
                                self.pic_version.wrapping_add(0x1c),
                            ]
                        }
                        (Bm1398FramedEndpoint::Pic { .. }, 0x15) => {
                            assert_eq!(exchange.request[5], 0);
                            assert_eq!(exchange.request[6], 0x1a + exchange.request[4]);
                            vec![0x15, 1]
                        }
                        (Bm1398FramedEndpoint::Pic { .. }, 0x16) => {
                            assert_eq!(exchange.request, [0x55, 0xaa, 4, 0x16, 0, 0x1a]);
                            vec![6, 0x16, 1, 0, 0, 0x1d]
                        }
                        (Bm1398FramedEndpoint::Apw12, command @ (2 | 0x83)) => {
                            let data = if command == 2 {
                                self.psu_version
                            } else {
                                exchange.request[4]
                            };
                            let checksum = u16::from(data) + u16::from(command) + 6;
                            vec![
                                0x55,
                                0xaa,
                                6,
                                command,
                                data,
                                0,
                                checksum as u8,
                                (checksum >> 8) as u8,
                            ]
                        }
                        _ => return Err("unexpected command: fixture does not implement it".into()),
                    };
                    Ok(R::Bytes(response))
                }
                A::ReadChipAddresses { .. } => {
                    let count = if self.short_chain { 113 } else { 114 };
                    let id = chip_observation().chip_id();
                    Ok(R::ChipAddresses((0..count).map(|i| (i * 2, id)).collect()))
                }
                A::Work { .. } if self.fail_work => Err("injected FIFO write failure".into()),
                _ => Ok(R::Complete),
            }
        }
    }
    fn fixture() -> (
        StockFixtureIo,
        Arc<std::sync::Mutex<Vec<Bm1398RuntimeAction>>>,
        Bm1398RuntimeConfig,
    ) {
        let events = Arc::new(std::sync::Mutex::new(vec![]));
        let io = StockFixtureIo {
            events: events.clone(),
            pic_version: 0x89,
            psu_version: 0x71,
            short_chain: false,
            fail_work: false,
        };
        let policy = PacedEnumerationPolicy::new(
            Duration::from_millis(1),
            Duration::from_millis(10),
            Duration::from_millis(500),
            1,
        )
        .unwrap();
        let config = Bm1398RuntimeConfig {
            plan: Bm1398HybridDeskPlan::s19_pro(policy, Bm1398FpgaMidstateMode::Four),
            active_chains: vec![0],
            frequency_mhz: 525,
            voltage_cv: 1280,
        };
        (io, events, config)
    }
    #[test]
    fn nbp1901_factory_runtime_executes_startup_work_and_power_first_shutdown() {
        let (io, events, config) = fixture();
        let mut runtime = Bm1398Runtime::new("am2-s19pro", config, io).unwrap();
        ready(runtime.start()).unwrap();
        assert_eq!(runtime.state(), Bm1398RuntimeState::Ready);
        // Exercise a real extended identifier beyond the old256-slot ledger.
        ready(runtime.submit_work(0, &[0xfffc; 36])).unwrap();
        let before_shutdown = events.lock().unwrap().len();
        ready(runtime.shutdown()).unwrap();
        let trace = events.lock().unwrap();
        assert_eq!(
            trace[before_shutdown],
            Bm1398RuntimeAction::TerminalPowerOff
        );
        assert!(trace.iter().any(
            |a| matches!(a, Bm1398RuntimeAction::Work { chain: 0, words } if words.len() == 36)
        ));
        let assignments = trace
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    Bm1398RuntimeAction::Asic {
                        operation: dcentrald_common::TransportOp::SendSetAddressBm1397Plus { .. },
                        ..
                    }
                )
            })
            .count();
        assert_eq!(assignments, 114);
        assert_eq!(runtime.state(), Bm1398RuntimeState::Stopped);
    }
    #[test]
    fn nbp1901_factory_runtime_refuses_incomplete_chain_before_pll_or_work() {
        let (mut io, events, config) = fixture();
        io.short_chain = true;
        let mut runtime = Bm1398Runtime::new("am2-s19pro", config, io).unwrap();
        assert!(ready(runtime.start()).is_err());
        let trace = events.lock().unwrap();
        assert!(!trace.iter().any(|a| matches!(
            a,
            Bm1398RuntimeAction::ConfigureWork { .. } | Bm1398RuntimeAction::Work { .. }
        )));
        assert!(trace.contains(&Bm1398RuntimeAction::HashPower { enabled: false }));
        assert!(trace.contains(&Bm1398RuntimeAction::TerminalPowerOff));
    }
    #[test]
    fn nbp1901_factory_runtime_unknown_pic_never_receives_mutating_pic_commands() {
        let (mut io, events, config) = fixture();
        io.pic_version = 0x86;
        let mut runtime = Bm1398Runtime::new("am2-s19pro", config, io).unwrap();
        assert!(ready(runtime.start()).is_err());
        let trace = events.lock().unwrap();
        assert!(!trace.iter().any(|a| matches!(a, Bm1398RuntimeAction::I2c(e) if e.request[3] == 0x15 || e.request[3] == 0x16 || e.request[3] == 0x83)));
        assert!(!trace.contains(&Bm1398RuntimeAction::HashPower { enabled: true }));
    }
    #[test]
    fn nbp1901_factory_runtime_work_failure_permanently_faults_and_cuts_power() {
        let (mut io, events, config) = fixture();
        io.fail_work = true;
        let mut runtime = Bm1398Runtime::new("am2-s19pro", config, io).unwrap();
        ready(runtime.start()).unwrap();
        let failure = ready(runtime.submit_work(0, &[0; 36])).unwrap_err();
        assert_eq!(failure.detail, "injected FIFO write failure");
        assert!(failure.shutdown_errors.is_empty());
        assert_eq!(runtime.state(), Bm1398RuntimeState::Faulted);
        let trace = events.lock().unwrap();
        let work = trace
            .iter()
            .position(|a| matches!(a, Bm1398RuntimeAction::Work { .. }))
            .unwrap();
        assert_eq!(trace[work + 1], Bm1398RuntimeAction::TerminalPowerOff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bhb56902_plaintext() -> Vec<u8> {
        // Minimal valid BHB56902 block: family 0x05, length 0x48, SN prefix BHB56902.
        let mut b = vec![0u8; bm1366_eeprom::BM1366_BLOCK_LEN];
        b[bm1366_eeprom::offset::ALGORITHM_AND_KEY_VERSION] = FAMILY_BYTE_BHB56XXX;
        b[bm1366_eeprom::offset::BOARD_INFO_LENGTH] = bm1366_eeprom::BM1366_BLOCK_LEN as u8;
        b[bm1366_eeprom::offset::HASHBOARD_SN
            ..bm1366_eeprom::offset::HASHBOARD_SN + bm1366_eeprom::HASHBOARD_SN_LEN]
            .copy_from_slice(b"BHB56902AB2345678");
        b[bm1366_eeprom::offset::CHIP_MARKING..bm1366_eeprom::offset::CHIP_MARKING + 6]
            .copy_from_slice(b"BM1366");
        b
    }

    fn bhb42_plaintext() -> Vec<u8> {
        // Minimal valid zhiju (0x04) block.
        let mut b = vec![0u8; zhiju_eeprom::ZHIJU_BLOCK_MIN_LEN];
        b[zhiju_eeprom::offset::ALGORITHM_AND_KEY_VERSION] = FAMILY_BYTE_BHB42XXX;
        b[zhiju_eeprom::offset::ZHIJU_INFORMATION_LENGTH] = 0x11;
        b[zhiju_eeprom::offset::HASHBOARD_SN..zhiju_eeprom::offset::HASHBOARD_SN + 17]
            .copy_from_slice(b"BHB42601AB2345678");
        b
    }

    #[test]
    fn bhb56902_resolves_to_exact_bm1366() {
        let id = identify_hashboard(&bhb56902_plaintext()).unwrap();
        assert_eq!(id.family, HashboardEepromFamily::Bhb56xxx);
        assert_eq!(id.hashboard_sn, "BHB56902AB2345678");
        assert_eq!(id.observed_protocol, Some(AsicProtocolIdentity::Bm1366));
    }

    /// LOAD-BEARING: the 0x04 family must NOT be disambiguated by this resolver — it
    /// spans BM1398 and BM1362, so `observed_protocol` MUST be None (keeps native
    /// BM1398 refused). Regressing this would let an ambiguous board authorize BM1398.
    #[test]
    fn bhb42_family_is_never_disambiguated_here() {
        let id = identify_hashboard(&bhb42_plaintext()).unwrap();
        assert_eq!(id.family, HashboardEepromFamily::Bhb42xxx);
        assert_eq!(
            id.observed_protocol, None,
            "0x04 spans BM1398+BM1362; this resolver must never pick one"
        );
    }

    /// A BHB56xxx block whose SN does not start with BHB56902 yields no observed
    /// protocol (fail closed — do not assume BM1366 for an unrecognized SN).
    #[test]
    fn bhb56xxx_without_known_sn_prefix_is_unresolved() {
        let mut b = bhb56902_plaintext();
        b[bm1366_eeprom::offset::HASHBOARD_SN
            ..bm1366_eeprom::offset::HASHBOARD_SN + bm1366_eeprom::HASHBOARD_SN_LEN]
            .copy_from_slice(b"XYZ99999AB2345678");
        let id = identify_hashboard(&b).unwrap();
        assert_eq!(id.observed_protocol, None);
    }

    #[test]
    fn unknown_family_byte_is_refused() {
        assert_eq!(
            identify_hashboard(&[0xFF; 80]),
            Err(HashboardIdentifyError::UnknownFamily { byte0: 0xFF })
        );
    }

    #[test]
    fn empty_input_is_truncated_not_panic() {
        assert_eq!(
            identify_hashboard(&[]),
            Err(HashboardIdentifyError::Truncated)
        );
    }

    // --- native experimental admission policy (fail-closed) ---

    const BASE: &str = "NOT IMPLEMENTED: native BM1366 ...";

    /// Default (no opt-in) is byte-for-byte the original refusal — zero regression.
    #[test]
    fn no_opt_in_is_the_unchanged_refusal() {
        assert_eq!(
            admit_native_experimental(
                false,
                Some(AsicProtocolIdentity::Bm1366),
                AsicProtocolIdentity::Bm1366,
                BASE
            ),
            NativeExperimentalAdmission::Refused(BASE.to_string())
        );
    }

    /// Opt-in but no observed identity → still refused (fail-closed).
    #[test]
    fn opt_in_without_observed_is_fail_closed() {
        match admit_native_experimental(true, None, AsicProtocolIdentity::Bm1366, BASE) {
            NativeExperimentalAdmission::Refused(r) => assert!(r.contains("fail-closed")),
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    /// Opt-in but observed identity mismatches required → refused (fail-closed).
    #[test]
    fn opt_in_with_mismatched_identity_is_fail_closed() {
        match admit_native_experimental(
            true,
            Some(AsicProtocolIdentity::Bm1362),
            AsicProtocolIdentity::Bm1366,
            BASE,
        ) {
            NativeExperimentalAdmission::Refused(r) => assert!(r.contains("does not match")),
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    /// Only opt-in + exact two-source match admits Experimental.
    #[test]
    fn opt_in_with_exact_match_admits_experimental() {
        assert_eq!(
            admit_native_experimental(
                true,
                Some(AsicProtocolIdentity::Bm1366),
                AsicProtocolIdentity::Bm1366,
                BASE
            ),
            NativeExperimentalAdmission::AdmittedExperimental {
                identity: AsicProtocolIdentity::Bm1366
            }
        );
    }

    /// End-to-end: a real BHB56902 EEPROM feeds the observed source and, with opt-in,
    /// admits BM1366 Experimental — the exact chain a mining engine would run.
    #[test]
    fn eeprom_to_admission_end_to_end_for_bm1366() {
        let id = identify_hashboard(&bhb56902_plaintext()).unwrap();
        let decision = admit_native_experimental(
            true,
            id.observed_protocol,
            AsicProtocolIdentity::Bm1366,
            BASE,
        );
        assert_eq!(
            decision,
            NativeExperimentalAdmission::AdmittedExperimental {
                identity: AsicProtocolIdentity::Bm1366
            }
        );
    }

    /// The load-bearing safety property: a BHB42 (0x04) EEPROM can NEVER admit BM1398
    /// Experimental through this chain, because the resolver yields no observed identity.
    #[test]
    fn bhb42_eeprom_can_never_admit_bm1398_experimental() {
        let id = identify_hashboard(&bhb42_plaintext()).unwrap();
        let decision = admit_native_experimental(
            true, // even WITH a (hypothetical) opt-in
            id.observed_protocol,
            AsicProtocolIdentity::Bm1398,
            "NOT IMPLEMENTED: native BM1398 ...",
        );
        assert!(matches!(decision, NativeExperimentalAdmission::Refused(_)));
    }

    #[test]
    fn wrong_family_length_surfaces_as_decode_error() {
        // 0x05 family byte but a short block -> the bm1366 decoder rejects it.
        let short = vec![FAMILY_BYTE_BHB56XXX, 0x48, 0x00];
        assert!(matches!(
            identify_hashboard(&short),
            Err(HashboardIdentifyError::Decode {
                family: HashboardEepromFamily::Bhb56xxx,
                ..
            })
        ));
    }

    // --- deployed-format observed identity (validated-only, fail-closed) ---

    #[test]
    fn deployed_bhb426_maps_to_bm1362() {
        // S19j Pro, validated against the real .25 BHB42601 dump.
        assert_eq!(
            observed_protocol_for_deployed_board_name("BHB42601"),
            Some(AsicProtocolIdentity::Bm1362)
        );
    }

    #[test]
    fn deployed_bhb569_maps_to_bm1366() {
        // S19k Pro, validated against the real S19k BHB56903 dump.
        assert_eq!(
            observed_protocol_for_deployed_board_name("BHB56903"),
            Some(AsicProtocolIdentity::Bm1366)
        );
    }

    /// The three EXACT S21 SKUs the catalog documents as BM1368. `BHB68606` is the
    /// one validated against a held live dump (
    /// eeprom_dump_0x51.hex`); BHB68603 has a held ePIC fixture page, BHB68603-
    /// has no held page, and all three are exact identity rows placed BEFORE the
    /// broad `BHB68xxx` → BM1370 row.
    #[test]
    fn deployed_bhb686_exact_skus_map_to_bm1368() {
        for sku in ["BHB68603", "BHB68603-", "BHB68606"] {
            assert_eq!(
                observed_protocol_for_deployed_board_name(sku),
                Some(AsicProtocolIdentity::Bm1368),
                "{sku} is an exact BM1368 catalog row"
            );
        }
    }

    /// LOAD-BEARING: the BM1368 rows are EXACT, never a `BHB68` prefix. Everything
    /// else in that prefix space falls through to the catalog's broad `BHB68xxx` →
    /// BM1370 row, so a prefix match would mis-mint every BM1370 board as BM1368 and
    /// route it into the wrong voltage tables. Superstrings and near-misses of the
    /// admitted SKUs must also stay closed.
    #[test]
    fn deployed_bhb68_prefix_never_mints_bm1368() {
        for sku in [
            "BHB68123",
            "BHB68000",
            "BHB68999",
            "BHB68604",
            "BHB68607",
            "BHB686",
            "BHB68606X",
            "BHB68603P",
            "BHB68701",
            "BHB68701-",
            "BHB68703",
            "BHB68",
        ] {
            assert_ne!(
                observed_protocol_for_deployed_board_name(sku),
                Some(AsicProtocolIdentity::Bm1368),
                "{sku} is not an exact BM1368 catalog row and must not mint BM1368"
            );
        }
    }

    /// The three exact BHB427/BHB428 SKUs with held deployed pages admit BM1362.
    /// The four catalogued BHB428 siblings and every unknown suffix remain closed:
    /// a roster/PVT row without a page is not sufficient to mint a
    /// runtime-observed identity.
    #[test]
    fn deployed_bhb428_admits_only_exact_page_backed_skus() {
        for sku in ["BHB42701", "BHB42801", "BHB42831"] {
            assert_eq!(
                crate::eeprom_record::chip_family_for_sku(sku),
                Some("BM1362"),
                "{sku}: exact catalog row must agree with held page evidence"
            );
            assert_eq!(
                observed_protocol_for_deployed_board_name(sku),
                Some(AsicProtocolIdentity::Bm1362),
                "page-backed SKU {sku} must mint only BM1362"
            );
        }
        for sku in [
            "BHB42803",
            "BHB42811",
            "BHB42821",
            "BHB42841",
            "BHB428",
            "BHB428xx",
            "BHB42899",
            "BHB4289999",
        ] {
            assert_eq!(observed_protocol_for_deployed_board_name(sku), None);
        }
    }

    #[test]
    fn deployed_unvalidated_or_unknown_sku_is_none() {
        // BHB68123 / A3HB70001 are catalog-KNOWN (broad BM1370 rows) but not
        // dump-validated, so admission policy still refuses them.
        for sku in [
            "BHB68123",
            "A3HB70001",
            "BHB56801",
            "BHL9999",
            "",
            "GARBAGE",
        ] {
            assert_eq!(observed_protocol_for_deployed_board_name(sku), None);
        }
    }

    /// LOAD-BEARING structural invariant: no policy row may declare BM1398, and a row
    /// only ever admits its OWN declared identity — so the delegated catalog lookup
    /// cannot inject BM1398 either. This is the table-level form of the "0x04 never
    /// admits BM1398" rule; the sweep below is its behavioural form.
    #[test]
    fn deployed_policy_table_can_never_declare_bm1398() {
        assert!(
            !DEPLOYED_SKU_IDENTITY_POLICY.is_empty(),
            "an empty policy table would make this assertion vacuous"
        );
        for (_, expected) in DEPLOYED_SKU_IDENTITY_POLICY {
            assert_ne!(
                *expected,
                AsicProtocolIdentity::Bm1398,
                "no deployed SKU may ever be admitted as BM1398"
            );
        }
    }

    /// Every family a page can be admitted as (`DEPLOYED_SKU_IDENTITY_POLICY`) must
    /// have a lot-code letter, or `corroborate_marking` would silently refuse it as
    /// "no held-page lot-code letter for this family". Stops the two tables drifting
    /// into an all-refuse regression when a new admissible family is added without a
    /// held page.
    #[test]
    fn every_admissible_family_has_a_marking_letter() {
        for (_, identity) in DEPLOYED_SKU_IDENTITY_POLICY {
            assert!(
                CHIP_MARKING_FAMILY_LETTERS
                    .iter()
                    .any(|(fam, _)| fam == identity),
                "admissible family {identity:?} has no lot-code letter — the corroborator \
                 would silently refuse every page of it"
            );
        }
    }

    /// Negative pin: NO BM1398 or BM1370 row may enter the letter table. We hold no
    /// deployed page for either, and a guessed BM1398 letter (plausibly BM1362's `C`)
    /// would manufacture agreement inside the very `:271-276` blind spot. Deleting
    /// this pin to "complete the table" must be a conscious act.
    #[test]
    fn marking_letter_table_has_no_bm1398_or_bm1370_row() {
        for (fam, _) in CHIP_MARKING_FAMILY_LETTERS {
            assert_ne!(
                *fam,
                AsicProtocolIdentity::Bm1398,
                "no held BM1398 lot code — do not guess one into the corroborator"
            );
            assert_ne!(
                *fam,
                AsicProtocolIdentity::Bm1370,
                "BM1370 (A3HB7xxxx) is format-1 and never reaches this code path"
            );
        }
    }

    /// Drift detector for the delegation: every policy row must still agree with
    /// `eeprom_record::chip_family_for_sku`. If the catalog is corrected, reordered,
    /// or loses a row, this fails loudly here instead of silently failing closed in
    /// production (or, worse, minting a stale family).
    #[test]
    fn deployed_policy_rows_agree_with_the_sku_catalog() {
        for (matcher, expected) in DEPLOYED_SKU_IDENTITY_POLICY {
            // For a family row the probe is the prefix itself (the family
            // boundary), which the catalog's own prefix pattern also matches.
            let probe = match matcher {
                DeployedSkuMatch::Family(prefix) => *prefix,
                DeployedSkuMatch::Exact(sku) => *sku,
            };
            assert_eq!(
                observed_protocol_for_deployed_board_name(probe),
                Some(*expected),
                "policy row {probe} diverged from eeprom_record::chip_family_for_sku"
            );
        }
    }

    /// The load-bearing safety invariant, mirrored for the deployed path: no deployed
    /// `board_name` can ever produce a BM1398 observed identity (native BM1398 stays
    /// refused). Exhaustive over every prefix space the policy or catalog touches.
    #[test]
    fn deployed_board_name_never_yields_bm1398() {
        for n in 0..1000u32 {
            for sku in [
                format!("BHB42{n:03}"),
                format!("BHB56{n:03}"),
                format!("BHB68{n:03}"),
                format!("A3HB7{n:04}"),
            ] {
                assert_ne!(
                    observed_protocol_for_deployed_board_name(&sku),
                    Some(AsicProtocolIdentity::Bm1398),
                    "{sku} must never observe BM1398"
                );
            }
        }
        for sku in [
            "BHB421xx",
            "BHB420xx",
            "BHB1398",
            "BM1398BB",
            "BHB56xxx",
            "BHB68xxx",
            "A3HB7xxxx",
            "BHB68603",
            "BHB68606",
        ] {
            assert_ne!(
                observed_protocol_for_deployed_board_name(sku),
                Some(AsicProtocolIdentity::Bm1398)
            );
        }
    }
}
