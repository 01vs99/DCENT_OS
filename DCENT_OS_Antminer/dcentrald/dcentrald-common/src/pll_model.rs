//! Pure PLL frequency programming model (decade P1-4 seed).
//!
//! # Why
//!
//! Engines historically re-implemented crystal-25 MHz brute-force PLL search
//! (BM1366/68/70) and BM1362 table lookup in `serial_mining`. That forked the
//! same math and left `InitStep::ProgramFrequencyMhz` unexpanded — pure init
//! plans could never produce a host-testable PLL register write.
//!
//! This module is the **HAL-free** SSOT for:
//! - nearest-frequency PLL solutions for known BM13xx families
//! - mapping protocol identity → PLL family (refuse unknown / BM1387 stock)
//! - expanding frequency intent into BM1397+ `TransportOp` write(s)
//!
//! # Status
//!
//! **PRODUCTION pure policy** for BM1362 table lookup + BM1366/BM1368/BM1370
//! 25 MHz crystal search + **BM1397 four-divider search** (raw postdiv, PLLEN
//! bit30, FBDIV 60..=200 — ESP-Miner / driver `bm1397_pll_calc` SSOT) +
//! **BM1387 discrete PLL table** (reg `0x0C`, Braiins/bug-corrected goldens;
//! TransportOp expand stays empty — stock FPGA SetConfig path) +
//! PLL0@0x08 broadcast planning + **BM1370 multi-PLL register map**
//! (PLL0/1/2 @ 0x08/0x60/0x64, RE-confirmed jig `.data`).
//! **BM1398** production pure encode is in this module (G19 vendor dual-binary
//! search); api-types / driver thin-wrap. Writing identical mining-frequency
//! solutions to PLL1/PLL2 is **not** planned
//! by default (addresses known; purpose of secondary PLLs is engine residual).
//! Live ramp dwells remain engine residual.
//!
//! Does **not** invent PLL values for RuntimeDiscovered.

use crate::board_desc::AsicProtocolIdentity;
use crate::chain_transport::TransportOp;

/// On-wire PLL0 parameter register for BM1362/66/68/70 (and BM1370 PLL0).
///
/// Matches RE-confirmed BM1370 multi-PLL map index 0 and ESP-Miner family
/// convention for primary frequency programming.
pub const PLL0_PARAMETER_REG: u8 = 0x08;

/// BM1387 PLL parameter register (stock S9 / Braiins `PllReg::REG_NUM`).
///
/// Distinct from BM1397+ PLL0@0x08 — do not alias.
pub const BM1387_PLL_PARAMETER_REG: u8 = 0x0C;

/// BM1370 per-PLL chip-register addresses (PLL0, PLL1, PLL2).
///
/// RE-CONFIRMED byte-exact from Bitmain S21 Pro `single_board_test` jig
/// `pllparameter_register_array @ .data 0x001fa848 = {0x08, 0x60, 0x64}`
/// (2026-07-02 Ghidra extraction; also `dcentrald-silicon-profiles::bm1370`).
/// `set_pllparameter` guards `which_pll < 3`.
pub const BM1370_PLL_REGISTER_ADDRS: [u8; 3] = [0x08, 0x60, 0x64];

/// BM1370 PLL count (independent PLLs on-die).
pub const BM1370_PLL_COUNT: u8 = 3;

/// The reference clock (chip XIN) every PLL table and crystal search in this
/// module assumes, in Hz (W8 CLK-4).
///
/// Every solver here — the BM1362/BM1387 discrete tables, the
/// BM1366/68/70 crystal-25 searches, the BM1397/BM1398 divider searches —
/// is a numerator over a **25 MHz** reference (;
/// `dcentrald-re-catalog::pll_bible` pins `reference_clock_mhz: 25` for all
/// nine chips, cross-pinned by `dcentrald-asic` host tests). A solution from
/// this module applied on a board whose XIN is NOT 25 MHz lands the hash
/// clock at `(actual_xin / 25 MHz) × target` — wrong frequency AND wrong
/// thermal envelope. [`admit_pll_reference`] is the fail-closed gate.
///
/// Honest scope: the entire current corpus is uniformly 25 MHz, so this guard
/// has no live mismatch to catch today — it exists so a future non-25 MHz
/// board (or a transcription error in either declaration) fails closed
/// instead of silently mis-clocking (C1 §4 CLK-4, §6 row 4).
pub const PLL_REFERENCE_HZ: u32 = 25_000_000;

/// A PLL table/search was asked to run against a reference clock it was not
/// derived for (W8 CLK-4). Fail closed — never scale or "correct" the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PllReferenceMismatch {
    /// The board/chip XIN the caller declared (`None` = undeclared).
    pub declared_xin_hz: Option<u32>,
    /// The reference this module's solutions assume.
    pub table_reference_hz: u32,
}

impl std::fmt::Display for PllReferenceMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.declared_xin_hz {
            None => write!(
                f,
                "PLL reference undeclared: refusing to apply a {} Hz-referenced \
                 PLL table on a board with no declared XIN (fail-closed)",
                self.table_reference_hz
            ),
            Some(xin) => write!(
                f,
                "PLL reference mismatch: table assumes {} Hz XIN but board \
                 declares {} Hz — applying it would land the hash clock at \
                 (declared/assumed) × target (wrong frequency and thermal envelope)",
                self.table_reference_hz, xin
            ),
        }
    }
}

impl std::error::Error for PllReferenceMismatch {}

/// Admit (or refuse) applying this module's PLL solutions against a declared
/// board XIN. `None` (undeclared) refuses — the §1.4 "absent data stays
/// `None`" invariant applied to clocks: a 25 MHz table may not run on an
/// unknown reference.
pub fn admit_pll_reference(declared_xin_hz: Option<u32>) -> Result<(), PllReferenceMismatch> {
    match declared_xin_hz {
        Some(xin) if xin == PLL_REFERENCE_HZ => Ok(()),
        other => Err(PllReferenceMismatch {
            declared_xin_hz: other,
            table_reference_hz: PLL_REFERENCE_HZ,
        }),
    }
}

/// Reference-checked variant of [`resolve_pll_for_protocol`] (W8 CLK-4).
///
/// Refuses (fail-closed) before any table lookup when the declared XIN does
/// not exactly match [`PLL_REFERENCE_HZ`]. `Ok(None)` retains the unchecked
/// function's "family unsupported offline / target 0" semantics.
pub fn resolve_pll_for_protocol_on_reference(
    protocol: AsicProtocolIdentity,
    target_mhz: u16,
    declared_xin_hz: Option<u32>,
) -> Result<Option<PllSolution>, PllReferenceMismatch> {
    admit_pll_reference(declared_xin_hz)?;
    Ok(resolve_pll_for_protocol(protocol, target_mhz))
}

/// Pure PLL family with host-testable register encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PllFamily {
    /// BM1362 — discrete proven (freq_mhz, reg) table, not brute-force.
    Bm1362,
    /// BM1366 — 25 MHz crystal search, fb_div 144..=235.
    Bm1366,
    /// BM1368 — 25 MHz crystal search, fb_div 144..=235 (same envelope as BM1366).
    Bm1368,
    /// BM1370 — 25 MHz crystal search, fb_div 160..=239.
    Bm1370,
    /// BM1397 — 25 MHz four-divider search, raw postdiv (no −1), FBDIV 60..=200.
    Bm1397,
    /// BM1398 — vendor four-divider search (NBP1901 bmminer + repair jig):
    /// FBDIV 16..=250 **12-bit**, refdiv order 2→1, VCO 2000..=3200 (refdiv1 max 3125).
    /// **Not** BM1397 alias (different envelope + FBDIV width).
    Bm1398,
    /// BM1387 — discrete proven (freq_mhz, reg) table @ reg 0x0C (stock S9).
    /// Pure encode only; not expanded to BM1397+ `TransportOp` program ops.
    Bm1387,
}

impl PllFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bm1362 => "bm1362",
            Self::Bm1366 => "bm1366",
            Self::Bm1368 => "bm1368",
            Self::Bm1370 => "bm1370",
            Self::Bm1397 => "bm1397",
            Self::Bm1398 => "bm1398",
            Self::Bm1387 => "bm1387",
        }
    }
}

/// Resolved pure PLL solution (no I/O).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PllSolution {
    /// Encoded PLL parameter register value for PLL0 write.
    pub register_value: u32,
    /// Actual frequency the solution produces (MHz, rounded for search paths).
    pub actual_freq_mhz: u16,
    pub family: PllFamily,
}

/// BM1397 PLL divider fields (decoded from a pure solution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bm1397PllDividers {
    pub fb_div: u16,
    pub ref_div: u8,
    pub post_div1: u8,
    pub post_div2: u8,
}

/// BM1398 PLL divider fields (vendor four-divider; FBDIV up to 12 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bm1398PllDividers {
    pub fb_div: u16,
    pub ref_div: u8,
    pub post_div1: u8,
    pub post_div2: u8,
}

/// Map ASIC protocol identity → pure PLL family.
///
/// Returns `None` when offline evidence does not support a pure register
/// program for this identity (catalog BM1391, runtime discovery, or BM139x
/// that use separate pure modules except BM1397). BM1387 maps to pure table
/// encode; frequency **TransportOp** expansion stays empty (stock FPGA path).
pub fn pll_family_for_protocol(protocol: AsicProtocolIdentity) -> Option<PllFamily> {
    match protocol {
        AsicProtocolIdentity::Bm1362 => Some(PllFamily::Bm1362),
        AsicProtocolIdentity::Bm1366 => Some(PllFamily::Bm1366),
        AsicProtocolIdentity::Bm1368 => Some(PllFamily::Bm1368),
        AsicProtocolIdentity::Bm1370 => Some(PllFamily::Bm1370),
        AsicProtocolIdentity::Bm1397 => Some(PllFamily::Bm1397),
        // G19: BM1398 production pure encode (vendor dual-binary search SSOT).
        AsicProtocolIdentity::Bm1398 => Some(PllFamily::Bm1398),
        AsicProtocolIdentity::Bm1387 => Some(PllFamily::Bm1387),
        // BM1396 has a separate fail-closed exact signed-firmware solver below.
        // It is deliberately not a PllFamily::Bm1397 alias; generic transport
        // planning dispatches to its exact named solver/plan instead.
        AsicProtocolIdentity::Bm1391
        | AsicProtocolIdentity::Bm1393
        | AsicProtocolIdentity::Bm1396
        | AsicProtocolIdentity::RuntimeDiscovered => None,
    }
}

// ---------------------------------------------------------------------------
// G42: BM1391 S17-jig PLL (set_BM1391_freq@128F4 — not S15/T15 stock)
// ---------------------------------------------------------------------------
//
// Bar: S17 jig `set_BM1391_freq` packs `0xC000_0000 | fb<<16 | ref<<8 | post_field`,
// external divider @ 0x70 as (div-1), program order PLL0 → 10ms → 0x70 → 10ms →
// PLL0 → 10ms. Search fails → held 200 MHz fallback `0xC078_0111` + div 15.
// Exact S15/T15 stock uses the same fallback fields (`0x0078_0111`, /15) and
// therefore the same 200 MHz frequency, but transforms the register payload to
// `0x4078_0111` and programs divider → PLL0 → divider → PLL0 without these
// jig delays. The two program plans and their top-bit encodings are not aliases.
// `pll_family_for_protocol(Bm1391)` stays None (init fail-closed); ChipDriver thin-wraps.

/// BM1391 PLL0 register (jig writes reg 0x08).
pub const BM1391_PLL0_REG: u8 = 0x08;

/// BM1391 external PLL divider register (jig writes reg 0x70).
pub const BM1391_PLL0_DIVIDER_REG: u8 = 0x70;

/// Held S17-jig inter-write spacing (`usleep(10000)`).
pub const BM1391_S17_JIG_PLL_PROGRAM_SPACING_MS: u32 = 10;

/// Held S17-jig "using 200M pll" fallback register (`0xC078_0111`).
pub const BM1391_S17_JIG_PLL_FALLBACK_200M: u32 = 0xC078_0111;

/// External divider for the held S17-jig 200 MHz fallback (`v30=15`).
pub const BM1391_S17_JIG_PLL_FALLBACK_EXTERNAL_DIV: u8 = 15;

/// Sibling-jig evidence does not authorize the exact S15/T15 stock plan.
pub const BM1391_S17_JIG_PLL_AUTHORIZES_S15_T15_PROGRAMMING: bool = false;

/// Pure BM1391 PLL solution (PLL0 + external divider).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391PllSolution {
    /// PLL0 parameter word (`0xC000_0000 | …`).
    pub pll0_register: u32,
    /// External divider written to reg 0x70 as `external_div - 1` (jig).
    pub external_div: u8,
    pub actual_freq_mhz: u16,
    pub fb_div: u16,
    pub ref_div: u8,
    pub post_div1: u8,
    pub post_div2: u8,
}

/// Pure: pack BM1391 PLL0 (jig: `0xC0000000 | fb<<16 | ref<<8 | (pd1<<4)|pd2`).
#[inline]
pub const fn bm1391_pll_pack(fb_div: u16, ref_div: u8, post_div1: u8, post_div2: u8) -> u32 {
    0xC000_0000
        | ((fb_div as u32) << 16)
        | ((ref_div as u32) << 8)
        | (((post_div1 as u32) & 0xF) << 4)
        | ((post_div2 as u32) & 0xF)
}

/// Pure: held S17-jig 200 MHz fallback solution.
pub const fn bm1391_pll_fallback_200m() -> Bm1391PllSolution {
    Bm1391PllSolution {
        pll0_register: BM1391_S17_JIG_PLL_FALLBACK_200M,
        external_div: BM1391_S17_JIG_PLL_FALLBACK_EXTERNAL_DIV,
        actual_freq_mhz: 200,
        fb_div: 120, // 0x78
        ref_div: 1,
        post_div1: 1,
        post_div2: 1,
    }
}

/// Pure: integer search for BM1391 hash PLL (postdiv 1×1 + external 1..=16).
///
/// Prefer exact or nearest chip frequency with VCO = 25·fb/ref in [2000, 3200].
/// Returns `None` if no candidate within 2 MHz (caller uses fallback).
pub fn bm1391_pll_search(target_mhz: u16) -> Option<Bm1391PllSolution> {
    if target_mhz == 0 {
        return None;
    }
    let mut best: Option<(u32, Bm1391PllSolution)> = None;
    for external_div in 1u8..=16 {
        for ref_div in [1u8, 2] {
            // Ideal VCO ≈ target × external_div (postdiv product 1).
            let ideal_vco = u32::from(target_mhz) * u32::from(external_div);
            if !(2000..=3200).contains(&ideal_vco) {
                continue;
            }
            // fb ≈ VCO * ref / 25
            let fb = ((ideal_vco * u32::from(ref_div) + 12) / 25).clamp(16, 250);
            let actual_vco = 25 * fb / u32::from(ref_div);
            if !(2000..=3200).contains(&actual_vco) {
                continue;
            }
            let actual_f = actual_vco / u32::from(external_div);
            if actual_f == 0 || actual_f > u32::from(u16::MAX) {
                continue;
            }
            let err = actual_f.abs_diff(u32::from(target_mhz));
            if err > 2 {
                continue;
            }
            let sol = Bm1391PllSolution {
                pll0_register: bm1391_pll_pack(fb as u16, ref_div, 1, 1),
                external_div,
                actual_freq_mhz: actual_f as u16,
                fb_div: fb as u16,
                ref_div,
                post_div1: 1,
                post_div2: 1,
            };
            let better = match best {
                None => true,
                Some((e, ref cur)) => {
                    err < e
                        || (err == e
                            && (external_div < cur.external_div
                                || (external_div == cur.external_div
                                    && fb < u32::from(cur.fb_div))))
                }
            };
            if better {
                best = Some((err, sol));
            }
        }
    }
    best.map(|(_, s)| s)
}

/// Pure: resolve the held S17-jig BM1391 PLL (search then 200 MHz fallback).
///
/// This is not the exact S15/T15 stock solver or four-write startup plan. See
/// [`crate::bm1391_stock_startup`] for that independently scoped contract.
pub fn resolve_bm1391_pll(target_mhz: u16) -> Bm1391PllSolution {
    if target_mhz == 200 {
        // Jig-held exact: 25*120/(1*1*1)/15 = 200.
        return bm1391_pll_fallback_200m();
    }
    bm1391_pll_search(target_mhz).unwrap_or_else(bm1391_pll_fallback_200m)
}

/// Pure: BM1391 frequency program (jig order — **not** BM1397 0x70×2 first).
///
/// `PLL0 @ 0x08` → 10 ms → `0x70 (external_div-1)` → 10 ms → `PLL0` → 10 ms.
pub fn plan_bm1391_frequency_program_ops(pll0_register: u32, external_div: u8) -> Vec<TransportOp> {
    plan_bm1391_frequency_program_ops_target(None, pll0_register, external_div)
}

/// Pure: BM1391 frequency program for one chip address.
pub fn plan_bm1391_frequency_program_ops_chip(
    chip_addr: u8,
    pll0_register: u32,
    external_div: u8,
) -> Vec<TransportOp> {
    plan_bm1391_frequency_program_ops_target(Some(chip_addr), pll0_register, external_div)
}

fn plan_bm1391_frequency_program_ops_target(
    chip_addr: Option<u8>,
    pll0_register: u32,
    external_div: u8,
) -> Vec<TransportOp> {
    let div_word = u32::from(external_div.saturating_sub(1));
    let mut ops = Vec::with_capacity(6);
    let push = |ops: &mut Vec<TransportOp>, reg: u8, value: u32| match chip_addr {
        None => ops.push(TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value }),
        Some(addr) => ops.push(TransportOp::SendWriteRegBm1397Plus {
            chip_addr: addr,
            reg,
            value,
        }),
    };
    push(&mut ops, BM1391_PLL0_REG, pll0_register);
    ops.push(TransportOp::DelayMs {
        ms: BM1391_S17_JIG_PLL_PROGRAM_SPACING_MS,
    });
    push(&mut ops, BM1391_PLL0_DIVIDER_REG, div_word);
    ops.push(TransportOp::DelayMs {
        ms: BM1391_S17_JIG_PLL_PROGRAM_SPACING_MS,
    });
    push(&mut ops, BM1391_PLL0_REG, pll0_register);
    ops.push(TransportOp::DelayMs {
        ms: BM1391_S17_JIG_PLL_PROGRAM_SPACING_MS,
    });
    ops
}

// ---------------------------------------------------------------------------
// BM1396 exact signed-firmware runtime PLL solver
// ---------------------------------------------------------------------------
//
// Ghidra analysis of exact signed S17e and T17e `bmminer` binaries recovered
// equivalent runtime solvers. This is a die-bound BM1396 pure register codec;
// it does not authorize carrier I/O, a frequency safety envelope, or live
// ChipDriver registration.

pub const BM1396_PLL_CLKI_MHZ: f32 = 25.0;
pub const BM1396_PLL_FB_DIV_MIN: u16 = 16;
pub const BM1396_PLL_FB_DIV_MAX: u16 = 250;
pub const BM1396_PLL_VCO_MIN_MHZ: f32 = 2_000.0;
pub const BM1396_PLL_VCO_MAX_MHZ: f32 = 3_200.0;
pub const BM1396_PLL_REFDIV_ONE_VCO_MAX_MHZ: f32 = 3_125.0;
pub const BM1396_PLL_MAX_ERROR_MHZ_EXCLUSIVE: f32 = 10.0;
pub const BM1396_PLL_SUCCESS_SELECTOR: u8 = 0x01;
pub const BM1396_PLL_FAILURE_SELECTOR: u8 = 0x0f;
pub const BM1396_PLL_FAILURE_REGISTER: u32 = 0x0078_0111;
pub const BM1396_PLL_PRESERVE_MASK: u32 = 0xf000_c088;
pub const BM1396_PLL_REGISTER_ADDRS: [u8; 4] = [0x08, 0x60, 0x64, 0x68];
pub const BM1396_PLL_PROGRAM_WRITE_COUNT: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bm1396PllDividers {
    pub fb_div: u16,
    pub ref_div: u8,
    pub post_div1: u8,
    pub post_div2: u8,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1396PllSolution {
    register_value: u32,
    selector: u8,
    actual_freq_mhz: f32,
    dividers: Bm1396PllDividers,
}

impl Bm1396PllSolution {
    pub const fn register_value(self) -> u32 {
        self.register_value
    }

    pub const fn selector(self) -> u8 {
        self.selector
    }

    pub const fn actual_freq_mhz(self) -> f32 {
        self.actual_freq_mhz
    }

    pub const fn dividers(self) -> Bm1396PllDividers {
        self.dividers
    }
}

/// Maturity of the clean-room BM1396 pure PLL codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396PurePllStatus {
    /// Equivalent exact signed S17e/T17e solvers plus fixed register goldens.
    OfflineVerifiedExactSignedMultiFirmware,
}

/// Production-pure PLL codec status. Carrier and electrical admission remain
/// independent and closed.
#[inline]
pub const fn bm1396_production_pure_pll_status() -> Bm1396PurePllStatus {
    Bm1396PurePllStatus::OfflineVerifiedExactSignedMultiFirmware
}

/// Whether production pure may expand frequency program ops for BM1396.
///
/// This admits pure solving and exact double-write planning. BoardDesc carrier
/// admission and the live ChipDriver remain independently closed.
#[inline]
pub const fn bm1396_production_pure_pll_admitted() -> bool {
    true
}

/// Exact signed-firmware BM1396 PLL solver.
///
/// Search order, f32 rounding, strict tie behavior, VCO limits, and register
/// preservation match both held production miners. `None` represents the
/// vendor `-1` outcome; callers must fail closed instead of programming the
/// vendor failure sentinel [`BM1396_PLL_FAILURE_REGISTER`].
pub fn resolve_bm1396_pll(target_mhz: f32, old_register_value: u32) -> Option<Bm1396PllSolution> {
    if !target_mhz.is_finite() || target_mhz <= 0.0 {
        return None;
    }

    let mut best_error = BM1396_PLL_MAX_ERROR_MHZ_EXCLUSIVE;
    let mut best: Option<(Bm1396PllDividers, f32)> = None;
    for ref_div in [2u8, 1] {
        for post_div2 in 1u8..=7 {
            for post_div1 in post_div2..=7 {
                let feedback =
                    target_mhz * f32::from(ref_div) * f32::from(post_div2) * f32::from(post_div1)
                        / BM1396_PLL_CLKI_MHZ
                        + 0.5;
                let fb_div = feedback.trunc() as u16;
                if !(BM1396_PLL_FB_DIV_MIN..=BM1396_PLL_FB_DIV_MAX).contains(&fb_div) {
                    continue;
                }
                let vco = (BM1396_PLL_CLKI_MHZ / f32::from(ref_div)) * f32::from(fb_div);
                if !(BM1396_PLL_VCO_MIN_MHZ..=BM1396_PLL_VCO_MAX_MHZ).contains(&vco)
                    || (ref_div == 1 && vco > BM1396_PLL_REFDIV_ONE_VCO_MAX_MHZ)
                {
                    continue;
                }
                let actual = vco / (f32::from(post_div1) * f32::from(post_div2));
                let error = (target_mhz - actual).abs();
                if error < best_error {
                    best_error = error;
                    best = Some((
                        Bm1396PllDividers {
                            fb_div,
                            ref_div,
                            post_div1,
                            post_div2,
                        },
                        actual,
                    ));
                }
            }
        }
    }

    best.map(|(div, actual_freq_mhz)| Bm1396PllSolution {
        register_value: (old_register_value & BM1396_PLL_PRESERVE_MASK)
            | ((u32::from(div.post_div1) & 0x7) << 4)
            | (u32::from(div.post_div2) & 0x7)
            | ((u32::from(div.ref_div) & 0x3f) << 8)
            | ((u32::from(div.fb_div) & 0x0fff) << 16),
        selector: BM1396_PLL_SUCCESS_SELECTOR,
        actual_freq_mhz,
        dividers: div,
    })
}

/// Transform a solved BM1396 word into the exact on-wire value: force bit 30
/// and clear bits 31 and 29.
pub const fn bm1396_pll_program_register_value(solved_register_value: u32) -> u32 {
    (solved_register_value & 0x5fff_ffff) | 0x4000_0000
}

/// Exact signed-firmware BM1396 PLL programming plan for index 0 through 3.
///
/// The selected register is written twice back-to-back with no intervening
/// delay or readback. Outer ramp pacing is caller-specific and is not invented
/// here.
pub fn plan_bm1396_pll_program_ops(
    solution: Bm1396PllSolution,
    pll_index: u8,
) -> Option<Vec<TransportOp>> {
    let register = *BM1396_PLL_REGISTER_ADDRS.get(usize::from(pll_index))?;
    let value = bm1396_pll_program_register_value(solution.register_value);
    Some(vec![
        TransportOp::SendWriteRegBroadcastBm1397Plus {
            reg: register,
            value,
        },
        TransportOp::SendWriteRegBroadcastBm1397Plus {
            reg: register,
            value,
        },
    ])
}

/// Resolve and plan the primary BM1396 mining PLL. An unattainable target
/// returns `None` and cannot be confused with a successful no-op or program
/// the vendor failure sentinel.
pub fn plan_bm1396_frequency_program_ops(target_mhz: u16) -> Option<Vec<TransportOp>> {
    resolve_bm1396_pll(f32::from(target_mhz), 0)
        .and_then(|solution| plan_bm1396_pll_program_ops(solution, 0))
}

/// EXPERIMENTAL: BM1396 PLL encode family-compatibility hypothesis.
///
/// Returns the **BM1397** pure solution (same register layout hypothesis from
/// PR-056: no corpus BM1396-vs-BM1397 PLL delta). Solution `.family` remains
/// [`PllFamily::Bm1397`] — the proven pure family — so callers cannot mistake
/// this for a die-bound BM1396 PRODUCTION encoder.
///
/// Retained only for historical comparison with the older BM1397 hypothesis.
/// New BM1396 work must use [`resolve_bm1396_pll`].
pub fn resolve_bm1396_pll_experimental_family_hypothesis(
    target_mhz: u16,
) -> (PllSolution, Bm1397PllDividers) {
    resolve_bm1397_pll(target_mhz)
}

/// EXPERIMENTAL: frequency program ops under the BM1396 family hypothesis.
///
/// Same cadence as [`plan_bm1397_frequency_program_ops`] (0x70×2 + PLL0×2).
/// This historical hypothesis is not used by the exact BM1396 production plan.
pub fn plan_bm1396_frequency_program_ops_experimental(
    pll0_register_value: u32,
) -> Vec<TransportOp> {
    plan_bm1397_frequency_program_ops(pll0_register_value)
}

/// Resolve a PLL solution for a known family (clamps per-family envelopes).
// clippy::expect_used: the BM1398 arm resolves against a `const` discrete-frequency
// list that is non-empty by construction, so `resolve_bm1398_pll_nearest_admitted`
// cannot return `None` for any `u16`. Making `resolve_pll` return `Option` would
// push an unreachable `None` onto every caller on a frequency-programming path.
#[allow(clippy::expect_used)]
pub fn resolve_pll(family: PllFamily, target_mhz: u16) -> PllSolution {
    match family {
        PllFamily::Bm1362 => bm1362_pll_lookup(target_mhz),
        // G28: ESP-Miner/ChipDriver full tie-break (diff → VCO → postdiv product).
        PllFamily::Bm1366 => crystal25_pll_search(
            family,
            target_mhz,
            144,
            235,
            Crystal25TieBreak::EspMinerFull,
        ),
        // G30: BM1368 = Bitmain jig table first + EspMinerFull fallback (unclamped default).
        PllFamily::Bm1368 => {
            resolve_bm1368_pll_with_policy(target_mhz, Bm1368VcoPolicy::EspMinerUnclamped)
        }
        // G29: BM1370 default pure = ESP-Miner unclamped EspMinerFull (jig clamp via policy API).
        PllFamily::Bm1370 => {
            resolve_bm1370_pll_with_policy(target_mhz, Bm1370VcoPolicy::EspMinerUnclamped)
        }
        PllFamily::Bm1397 => bm1397_pll_search(target_mhz).0,
        // Nearest pure-admitted discrete freq only (no invent-525 outside envelope).
        PllFamily::Bm1398 => {
            resolve_bm1398_pll_nearest_admitted(target_mhz)
                .expect("BM1398 discrete list always contains admitted mining freqs")
                .0
        }
        PllFamily::Bm1387 => bm1387_pll_lookup(target_mhz),
    }
}

/// Resolve BM1398 PLL0 via vendor four-divider search (fail-closed outside envelope).
///
/// Returns `None` when no candidate meets the dual-binary error ceiling
/// (strict &lt; 10 MHz). Prefer this over [`resolve_pll`] when callers must
/// distinguish refuse from invent.
#[inline]
pub fn resolve_bm1398_pll(target_mhz: u16) -> Option<(PllSolution, Bm1398PllDividers)> {
    bm1398_pll_search(target_mhz)
}

/// Exact target, else nearest pure-admitted entry on [`bm1398_pll_frequencies`].
///
/// Does **not** invent a hard-coded 525 MHz fallback when the target is outside
/// the vendor ceiling — only discrete list members that themselves resolve.
pub fn resolve_bm1398_pll_nearest_admitted(
    target_mhz: u16,
) -> Option<(PllSolution, Bm1398PllDividers)> {
    if let Some(hit) = resolve_bm1398_pll(target_mhz) {
        return Some(hit);
    }
    let mut best: Option<(u32, (PllSolution, Bm1398PllDividers))> = None;
    for &f in bm1398_pll_frequencies() {
        if let Some(sol) = resolve_bm1398_pll(f) {
            let d = (i32::from(f) - i32::from(target_mhz)).unsigned_abs();
            if best.as_ref().map(|(bd, _)| d < *bd).unwrap_or(true) {
                best = Some((d, sol));
            }
        }
    }
    best.map(|(_, sol)| sol)
}

/// Resolve BM1387 PLL table solution (driver thin-wrap SSOT).
#[inline]
pub fn resolve_bm1387_pll(target_mhz: u16) -> PllSolution {
    bm1387_pll_lookup(target_mhz)
}

/// Resolve BM1397 PLL0 solution **and** divider fields (driver thin-wrap SSOT).
///
/// Returns `(solution, dividers)`. Prefer this over re-deriving fields from
/// `register_value` when populating `PllConfig`.
pub fn resolve_bm1397_pll(target_mhz: u16) -> (PllSolution, Bm1397PllDividers) {
    bm1397_pll_search(target_mhz)
}

/// Resolve PLL for a protocol identity, or `None` if family is unsupported offline.
pub fn resolve_pll_for_protocol(
    protocol: AsicProtocolIdentity,
    target_mhz: u16,
) -> Option<PllSolution> {
    if target_mhz == 0 {
        return None;
    }
    match pll_family_for_protocol(protocol)? {
        // BM1398: fail-closed outside vendor error ceiling (do not invent clamp).
        PllFamily::Bm1398 => resolve_bm1398_pll(target_mhz).map(|(s, _)| s),
        f => Some(resolve_pll(f, target_mhz)),
    }
}

/// Why a multi-PLL plan/admission failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PllPlanError {
    /// Family has no pure multi-PLL register map (only PLL0, or unknown).
    MultiPllMapUnsupported { family: PllFamily },
    /// `pll_id` is out of range for the family's RE-confirmed map.
    PllIdOutOfRange {
        family: PllFamily,
        pll_id: u8,
        count: u8,
    },
    /// Pure encode exists but frequency is not programmed via BM1397+ TransportOp
    /// (e.g. BM1387 stock FPGA SetConfig @ reg 0x0C).
    TransportProgramUnsupported { family: PllFamily },
}

impl std::fmt::Display for PllPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MultiPllMapUnsupported { family } => write!(
                f,
                "multi-PLL register map unsupported for family {family:?} (PLL0-only pure map)"
            ),
            Self::PllIdOutOfRange {
                family,
                pll_id,
                count,
            } => write!(
                f,
                "pll_id {pll_id} out of range for {family:?} (count={count})"
            ),
            Self::TransportProgramUnsupported { family } => write!(
                f,
                "BM1397+ TransportOp frequency program unsupported for family {family:?}"
            ),
        }
    }
}

impl std::error::Error for PllPlanError {}

/// RE-confirmed on-wire PLL parameter register addresses for a family.
///
/// - BM1362 / BM1366 / BM1368 / BM1397: PLL0 only (`0x08`)
/// - BM1370: three PLLs `{0x08, 0x60, 0x64}`
/// - BM1387: PLL @ `0x0C` (Braiins `PllReg::REG_NUM`) — not BM1397+ 0x08
pub fn pll_register_addrs(family: PllFamily) -> &'static [u8] {
    match family {
        PllFamily::Bm1362
        | PllFamily::Bm1366
        | PllFamily::Bm1368
        | PllFamily::Bm1397
        | PllFamily::Bm1398 => &[PLL0_PARAMETER_REG],
        PllFamily::Bm1370 => &BM1370_PLL_REGISTER_ADDRS,
        PllFamily::Bm1387 => &[BM1387_PLL_PARAMETER_REG],
    }
}

/// Number of independent PLLs with RE-confirmed register addresses.
pub fn pll_count(family: PllFamily) -> u8 {
    pll_register_addrs(family).len() as u8
}

/// Resolve the chip register byte for `pll_id` (0-based).
pub fn admit_pll_register(family: PllFamily, pll_id: u8) -> Result<u8, PllPlanError> {
    let addrs = pll_register_addrs(family);
    addrs
        .get(pll_id as usize)
        .copied()
        .ok_or(PllPlanError::PllIdOutOfRange {
            family,
            pll_id,
            count: addrs.len() as u8,
        })
}

/// Plan a BM1397+ PLL parameter broadcast write for a specific PLL id.
///
/// Frequency solutions from [`resolve_pll`] are **mining-PLL encodings**
/// historically applied to PLL0. Callers that write the same word to PLL1/2
/// must have separate evidence that secondary PLLs accept that encoding —
/// this function only admits the **register address**, not the purpose.
pub fn plan_pll_broadcast_write(
    solution: PllSolution,
    pll_id: u8,
) -> Result<TransportOp, PllPlanError> {
    // BM1387 pure encode is table-only; stock FPGA programs via SetConfig, not
    // BM1397+ serial TransportOp writes.
    if solution.family == PllFamily::Bm1387 {
        return Err(PllPlanError::TransportProgramUnsupported {
            family: PllFamily::Bm1387,
        });
    }
    let reg = admit_pll_register(solution.family, pll_id)?;
    Ok(TransportOp::SendWriteRegBroadcastBm1397Plus {
        reg,
        value: solution.register_value,
    })
}

/// Plan a BM1397+ PLL0 broadcast write from a pure solution.
///
/// # Panics
///
/// Panics if `solution.family` is [`PllFamily::Bm1387`] (use pure resolve only;
/// stock FPGA SetConfig is the I/O path). Prefer [`plan_frequency_program_ops`]
/// which returns empty for BM1387.
// clippy::expect_used: this fn's own doc contract says it PANICS on Bm1387;
// `plan_frequency_program_ops` is the non-panicking entry point. The message is
// the diagnostic, so a silent `Option` here would be strictly worse.
#[allow(clippy::expect_used)]
pub fn plan_pll0_broadcast_write(solution: PllSolution) -> TransportOp {
    plan_pll_broadcast_write(solution, 0)
        .expect("PLL0 TransportOp admitted for BM1397+ pure families only (not BM1387)")
}

/// Plan broadcasts for **every** RE-mapped PLL with the same solution word.
///
/// # Honesty
///
/// Only BM1370 has multi-PLL addresses offline. Writing the mining-frequency
/// encoding to PLL1/PLL2 is **EXPERIMENTAL** — jig `set_pllparameter` can
/// target each `which_pll`, but production mining paths typically program
/// PLL0 only. Prefer [`plan_frequency_program_ops`] (PLL0) unless an engine
/// has evidence for secondary-PLL programming.
pub fn plan_all_pll_broadcast_writes(solution: PllSolution) -> Vec<TransportOp> {
    (0..pll_count(solution.family))
        .filter_map(|id| plan_pll_broadcast_write(solution, id).ok())
        .collect()
}

/// BM1397 PLL0 Divider register (glitch-protection prelude before PLL0 write).
///
/// ESP-Miner / S17 driver write `0x0F0F_0F00` twice with 10 ms spacing, then
/// PLL0 Parameter twice. Pure sequence owns cadence; I/O is engine residual.
pub const BM1397_PLL0_DIVIDER_REG: u8 = 0x70;

/// BM1397 PLL0 Divider pre-config value (all PLLDIV max — glitch protection).
pub const BM1397_PLL0_DIVIDER_PRECONFIG: u32 = 0x0F0F_0F00;

/// Spacing between BM1397 PLL prelude / parameter double-writes (ms).
pub const BM1397_PLL_PROGRAM_SPACING_MS: u32 = 10;

// ---------------------------------------------------------------------------
// BM1397 PLL0 readback / verify-retry policy (G9 — shipped init loop pure SSOT)
// ---------------------------------------------------------------------------
//
// Open-coded contract in `bm1397` init_chain (preserved exactly, not upgraded):
// - Match: `(readback & !LOCK) == programmed_pll0_word`
// - LOCK bit `0x8000_0000` is status-only (does not affect programmed match)
// - Up to 3 read attempts from chip 0 / PLL0 Parameter
// - On mismatch or timeout (attempts 0..=1): PLL0-only broadcast rewrite + 20 ms
//   (NOT full 0x70 frequency program — do not invent full-prelude retry)
// - Post-read settle before checking RX: 50 ms
// - Max attempts constant is fail-closed (no 4th rewrite)

/// PLL0 lock status bit in BM1397 Parameter readback (status; ignored for match).
pub const BM1397_PLL0_LOCK_BIT: u32 = 0x8000_0000;

/// Max PLL0 verify read attempts during init (shipped open-coded `0..3`).
pub const BM1397_PLL0_VERIFY_MAX_ATTEMPTS: u8 = 3;

/// Post-read settle before checking CMD RX for PLL0 verify (ms).
pub const BM1397_PLL0_VERIFY_READ_SETTLE_MS: u32 = 50;

/// Settle after PLL0-only rewrite on verify fail (ms).
pub const BM1397_PLL0_VERIFY_REWRITE_SETTLE_MS: u32 = 20;

/// Whether a PLL0 Parameter readback matches the programmed word.
///
/// Lock bit is stripped from the comparison — lock is status, not program.
#[inline]
pub const fn bm1397_pll0_readback_matches(programmed: u32, readback: u32) -> bool {
    (readback & !BM1397_PLL0_LOCK_BIT) == programmed
}

/// Whether the lock status bit is set in a PLL0 Parameter readback.
#[inline]
pub const fn bm1397_pll0_lock_bit_set(readback: u32) -> bool {
    readback & BM1397_PLL0_LOCK_BIT != 0
}

/// Whether a further PLL0-only rewrite is admitted after this attempt index.
///
/// Attempts are 0-based (`0..BM1397_PLL0_VERIFY_MAX_ATTEMPTS`). Rewrite is
/// admitted only when another read attempt remains (`attempt + 1 < max`).
#[inline]
pub const fn bm1397_pll0_verify_rewrite_admitted(attempt: u8) -> bool {
    attempt.saturating_add(1) < BM1397_PLL0_VERIFY_MAX_ATTEMPTS
}

/// Pure plan: read PLL0 Parameter from one chip, then settle for RX.
///
/// Engine residual: CMD RX drain before send; parse response words after delay.
pub fn plan_bm1397_pll0_verify_read(chip_addr: u8) -> Vec<TransportOp> {
    vec![
        TransportOp::SendReadRegBm1397Plus {
            chip_addr,
            reg: PLL0_PARAMETER_REG,
        },
        TransportOp::DelayMs {
            ms: BM1397_PLL0_VERIFY_READ_SETTLE_MS,
        },
    ]
}

/// Pure plan: PLL0-only broadcast rewrite after verify mismatch/timeout.
///
/// Preserves shipped open-coded rewrite (single PLL0 bcast + 20 ms).
/// Does **not** re-run the full 0x70 Divider prelude frequency program.
pub fn plan_bm1397_pll0_verify_retry_rewrite(pll0_register_value: u32) -> Vec<TransportOp> {
    vec![
        TransportOp::SendWriteRegBroadcastBm1397Plus {
            reg: PLL0_PARAMETER_REG,
            value: pll0_register_value,
        },
        TransportOp::DelayMs {
            ms: BM1397_PLL0_VERIFY_REWRITE_SETTLE_MS,
        },
    ]
}

/// Expand frequency programming intent to transport ops.
///
/// - Most pure families: single PLL0 broadcast.
/// - **BM1397**: Divider prelude `0x70=0x0F0F0F00` ×2 (+ delays) then PLL0
///   Parameter ×2 (+ delays) — bible / ESP-Miner / driver sequence (G5 R3).
/// - **BM1387**: empty — pure table encode only; stock FPGA SetConfig residual
///   (do not invent BM1397+ TransportOp or BM1397 `0x70` prelude for S9).
/// - **BM1396**: exact signed-firmware PLL0 double-write, no inter-write delay.
///
/// Empty when protocol has no pure PLL family/named solver, the target is
/// unattainable, or `frequency_mhz == 0`.
/// Does **not** fan out to PLL1/2 (see [`plan_all_pll_broadcast_writes`]).
pub fn plan_frequency_program_ops(
    protocol: AsicProtocolIdentity,
    frequency_mhz: u16,
) -> Vec<TransportOp> {
    if protocol == AsicProtocolIdentity::Bm1396 {
        // The exact pure resolver is available through the named BM1396 API,
        // but no carrier/output-frequency admission exists yet. Do not let a
        // generic protocol-only planner manufacture mutation-shaped ops.
        return Vec::new();
    }
    match resolve_pll_for_protocol(protocol, frequency_mhz) {
        // G5/G11: BM1397 and BM1398 share 0x70×2 + PLL0×2 program cadence.
        Some(sol) if sol.family == PllFamily::Bm1397 || sol.family == PllFamily::Bm1398 => {
            plan_bm1397_frequency_program_ops(sol.register_value)
        }
        Some(sol) if sol.family == PllFamily::Bm1387 => Vec::new(),
        Some(sol) => vec![plan_pll0_broadcast_write(sol)],
        None => Vec::new(),
    }
}

/// Pure BM1397 frequency program sequence (broadcast).
///
/// `(WriteReg 0x70 PRECONFIG + DelayMs(10)) × 2` then
/// `(WriteReg 0x08 pll_value + DelayMs(10)) × 2`.
pub fn plan_bm1397_frequency_program_ops(pll0_register_value: u32) -> Vec<TransportOp> {
    plan_bm1397_frequency_program_ops_target(/* broadcast */ None, pll0_register_value)
}

/// Pure BM1397 frequency program for a single chip address.
///
/// Same cadence as [`plan_bm1397_frequency_program_ops`]; uses
/// [`TransportOp::SendWriteRegBm1397Plus`] instead of broadcast.
pub fn plan_bm1397_frequency_program_ops_chip(
    chip_addr: u8,
    pll0_register_value: u32,
) -> Vec<TransportOp> {
    plan_bm1397_frequency_program_ops_target(Some(chip_addr), pll0_register_value)
}

/// Internal: `None` chip_addr → broadcast; `Some` → per-chip.
fn plan_bm1397_frequency_program_ops_target(
    chip_addr: Option<u8>,
    pll0_register_value: u32,
) -> Vec<TransportOp> {
    let mut ops = Vec::with_capacity(8);
    let push_write = |ops: &mut Vec<TransportOp>, reg: u8, value: u32| match chip_addr {
        None => ops.push(TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value }),
        Some(addr) => ops.push(TransportOp::SendWriteRegBm1397Plus {
            chip_addr: addr,
            reg,
            value,
        }),
    };
    for _ in 0..2 {
        push_write(
            &mut ops,
            BM1397_PLL0_DIVIDER_REG,
            BM1397_PLL0_DIVIDER_PRECONFIG,
        );
        ops.push(TransportOp::DelayMs {
            ms: BM1397_PLL_PROGRAM_SPACING_MS,
        });
    }
    for _ in 0..2 {
        push_write(&mut ops, PLL0_PARAMETER_REG, pll0_register_value);
        ops.push(TransportOp::DelayMs {
            ms: BM1397_PLL_PROGRAM_SPACING_MS,
        });
    }
    ops
}

// ---------------------------------------------------------------------------
// BM1387 discrete table (stock S9 / driver historical SSOT — G16)
// ---------------------------------------------------------------------------
//
// Formula: freq = 25 MHz * FBDIV / REFDIV / POSTDIV1 / POSTDIV2
// Encoding: bits 23:16 FBDIV, 11:8 REFDIV, 7:4 PD1, 3:0 PD2 (Braiins PllReg).
// Goldens: 500 MHz → 0x00500221, 650 MHz → 0x00680221 (braiins_bm1387.rs).
// CRITICAL: labels must match real fbdiv math (2026-03-17 bug: 0x00420221 is
// 412 MHz, not 500 — caused ~18% hashrate loss when mislabeled).

/// BM1387 PLL table — (freq_mhz, pll_reg_value). Bug-corrected discrete steps.
pub const BM1387_PLL_TABLE: &[(u16, u32)] = &[
    // Low: postdiv1=4, postdiv2=1 → 3.125 * fbdiv
    (100, 0x0020_0241),
    (125, 0x0028_0241),
    (150, 0x0030_0241),
    (175, 0x0038_0241),
    (200, 0x0040_0241),
    (225, 0x0048_0241),
    (250, 0x0050_0241),
    (275, 0x0058_0241),
    (300, 0x0060_0241),
    (325, 0x0068_0241),
    (350, 0x0070_0241),
    (375, 0x0078_0241),
    // Mid: postdiv1=2, postdiv2=1 → 6.25 * fbdiv
    (400, 0x0040_0221),
    (425, 0x0044_0221),
    (450, 0x0048_0221),
    (462, 0x004A_0221),
    (475, 0x004C_0221),
    (500, 0x0050_0221), // Braiins golden; NOT 0x0042_0221 (=412 MHz)
    (525, 0x0054_0221),
    (550, 0x0058_0221),
    (575, 0x005C_0221),
    (600, 0x0060_0221),
    (625, 0x0064_0221),
    (650, 0x0068_0221), // Braiins golden
    (700, 0x0070_0221),
    (725, 0x0074_0221),
    (750, 0x0078_0221),
    (775, 0x007C_0221),
    (800, 0x0080_0221),
    // High: postdiv1=1, postdiv2=1 → 12.5 * fbdiv
    (825, 0x0042_0211),
    (850, 0x0044_0211),
    (875, 0x0046_0211),
    (900, 0x0048_0211),
];

/// Sorted BM1387 discrete frequencies (MHz) — table order.
pub fn bm1387_pll_frequencies() -> &'static [u16] {
    &[
        100, 125, 150, 175, 200, 225, 250, 275, 300, 325, 350, 375, 400, 425, 450, 462, 475, 500,
        525, 550, 575, 600, 625, 650, 700, 725, 750, 775, 800, 825, 850, 875, 900,
    ]
}

// clippy::indexing_slicing: `BM1387_PLL_TABLE` is a `const` table with literal
// entries, so `[0]` and `[1..]` are in-bounds by construction. Rewriting to
// `.get(0)` would add an unreachable `None` arm to a pure lookup.
#[allow(clippy::indexing_slicing)]
fn bm1387_pll_lookup(target_mhz: u16) -> PllSolution {
    let target = target_mhz.clamp(100, 900);
    let mut best = BM1387_PLL_TABLE[0];
    let mut best_diff = (target as i32 - best.0 as i32).unsigned_abs();
    for &entry in &BM1387_PLL_TABLE[1..] {
        let diff = (target as i32 - entry.0 as i32).unsigned_abs();
        if diff < best_diff {
            best = entry;
            best_diff = diff;
        }
    }
    PllSolution {
        register_value: best.1,
        actual_freq_mhz: best.0,
        family: PllFamily::Bm1387,
    }
}

// ---------------------------------------------------------------------------
// BM1362 discrete table (G26 pure SSOT — ChipDriver + hybrid thin-wrap)
// ---------------------------------------------------------------------------
//
// Encoding (RE-proven, accepted-share on AM2 BM1362):
//   POSTDIV1=5, POSTDIV2=2, REFDIV=1 → postdiv byte 0x41
//   freq = 25 * FBDIV / 10 = 2.5 * FBDIV
//   VCO_SCALE=0x50 (VCO = 25*FBDIV ≥ 4000 MHz for FBDIV≥160)
//
// G26: pure table was incomplete (missing rated 545 + live 531/556). ChipDriver
// and hybrid held fuller forks — pure is now the single SSOT.

/// BM1362 PLL table — (freq_mhz, pll_reg_value). Proven discrete steps.
///
/// Includes S19j Pro **rated 545 MHz** (`0x50DA_0141`) and live autotune anchors
/// 531 / 556 from `a lab unit` chains. Sub-400 is **not** here — use ChipDriver
/// `pll_lookup_extended` (gated) only.
pub const BM1362_PLL_TABLE: &[(u16, u32)] = &[
    (400, 0x50A0_0141), // fbdiv=160
    (412, 0x50A5_0141), // fbdiv=165
    (425, 0x50AA_0141), // fbdiv=170
    (437, 0x50AF_0141), // fbdiv=175
    (450, 0x50B4_0141), // fbdiv=180
    (462, 0x50B9_0141), // fbdiv=185
    (475, 0x50BE_0141), // fbdiv=190
    (487, 0x50C3_0141), // fbdiv=195
    (500, 0x50C8_0141), // fbdiv=200
    (512, 0x50CD_0141), // fbdiv=205
    (525, 0x50D2_0141), // fbdiv=210
    (531, 0x50D4_0141), // fbdiv=212 — live autotuned on .139 chain 2
    (537, 0x50D7_0141), // fbdiv=215
    (545, 0x50DA_0141), // fbdiv=218 — RATED (S19j Pro default)
    (550, 0x50DC_0141), // fbdiv=220
    (556, 0x50DE_0141), // fbdiv=222 — live autotuned on .139 chain 3
    (562, 0x50E1_0141), // fbdiv=225
    (575, 0x50E6_0141), // fbdiv=230
    (587, 0x50EB_0141), // fbdiv=235
    (597, 0x50EF_0141), // fbdiv=239 (top of window)
];

/// Discrete BM1362 mining frequencies (MHz), same order as [`BM1362_PLL_TABLE`].
pub const BM1362_PLL_FREQUENCIES: &[u16] = &[
    400, 412, 425, 437, 450, 462, 475, 487, 500, 512, 525, 531, 537, 545, 550, 556, 562, 575, 587,
    597,
];

/// Sorted discrete PLL frequencies the BM1362 pure table admits (MHz).
#[inline]
pub fn bm1362_pll_frequencies() -> &'static [u16] {
    BM1362_PLL_FREQUENCIES
}

/// Resolve BM1362 PLL via pure table nearest-entry (driver thin-wrap SSOT).
#[inline]
pub fn resolve_bm1362_pll(target_mhz: u16) -> PllSolution {
    bm1362_pll_lookup(target_mhz)
}

/// `(register_value, actual_freq_mhz)` for BM1362 pure nearest lookup.
#[inline]
pub fn bm1362_pll_reg_and_actual(target_mhz: u16) -> (u32, u16) {
    let s = bm1362_pll_lookup(target_mhz);
    (s.register_value, s.actual_freq_mhz)
}

// clippy::indexing_slicing: `BM1362_PLL_TABLE` is a `const` table with literal
// entries, so `[0]` and `[1..]` are in-bounds by construction. Rewriting to
// `.get(0)` would add an unreachable `None` arm to a pure lookup.
#[allow(clippy::indexing_slicing)]
fn bm1362_pll_lookup(target_mhz: u16) -> PllSolution {
    let target = target_mhz.clamp(400, 597);
    let mut best = BM1362_PLL_TABLE[0];
    let mut best_diff = (target as i32 - best.0 as i32).unsigned_abs();
    for &entry in &BM1362_PLL_TABLE[1..] {
        let diff = (target as i32 - entry.0 as i32).unsigned_abs();
        if diff < best_diff {
            best = entry;
            best_diff = diff;
        }
    }
    PllSolution {
        register_value: best.1,
        actual_freq_mhz: best.0,
        family: PllFamily::Bm1362,
    }
}

// ---------------------------------------------------------------------------
// BM1397 four-divider search (raw postdiv — G5 pure SSOT)
// f = 25 MHz * FBDIV / (REFDIV * POSTDIV1 * POSTDIV2)
// Encoding: PLLEN@30 | FBDIV[26:16] | REFDIV[13:8] | PD1[6:4] | PD2[2:0]
// (NO postdiv−1; unlike BM1366+. ESP-Miner + drivers/bm1397.rs.)
// ---------------------------------------------------------------------------

/// BM1397 CLKI reference (MHz).
pub const BM1397_CLKI_MHZ: u16 = 25;
/// Inclusive FBDIV search floor (driver / ESP-Miner envelope).
pub const BM1397_FB_DIV_MIN: u16 = 60;
/// Inclusive FBDIV search ceiling.
pub const BM1397_FB_DIV_MAX: u16 = 200;
/// Mining frequency clamp floor (MHz).
pub const BM1397_FREQ_MIN_MHZ: u16 = 50;
/// Mining frequency clamp ceiling (MHz).
pub const BM1397_FREQ_MAX_MHZ: u16 = 800;

/// Encode BM1397 PLL0 parameter word from divider fields (raw postdiv).
pub const fn bm1397_pll_register_value(
    fb_div: u16,
    ref_div: u8,
    post_div1: u8,
    post_div2: u8,
) -> u32 {
    (1u32 << 30) // PLLEN
        | ((fb_div as u32 & 0x7FF) << 16)
        | ((ref_div as u32 & 0x3F) << 8)
        | ((post_div1 as u32 & 0x7) << 4)
        | (post_div2 as u32 & 0x7)
}

/// Decode divider fields from a pure BM1397 register word (test / diagnostics).
pub const fn bm1397_pll_decode_dividers(reg: u32) -> Bm1397PllDividers {
    Bm1397PllDividers {
        fb_div: ((reg >> 16) & 0x7FF) as u16,
        ref_div: ((reg >> 8) & 0x3F) as u8,
        post_div1: ((reg >> 4) & 0x7) as u8,
        post_div2: (reg & 0x7) as u8,
    }
}

/// Discrete autotuner-friendly BM1397 frequency list (historical driver SSOT).
pub fn bm1397_pll_frequencies() -> &'static [u16] {
    &[
        50, 100, 150, 200, 250, 300, 350, 400, 425, 450, 475, 500, 525, 550, 575, 600, 625, 650,
        700, 750, 800,
    ]
}

// ---------------------------------------------------------------------------
// BM1398 four-divider vendor search (G19 pure SSOT)
// Evidence: NBP1901 bmminer + BM1398 repair jig (api-types bm1398_protocol).
// Differs from BM1397: FBDIV 16..=250 12-bit, refdiv 2→1, VCO 2000..=3200.
// ---------------------------------------------------------------------------

/// BM1398 CLKI reference (MHz).
pub const BM1398_CLKI_MHZ: u16 = 25;
/// Inclusive FBDIV search floor (vendor dual-binary).
pub const BM1398_FB_DIV_MIN: u16 = 16;
/// Inclusive FBDIV search ceiling.
pub const BM1398_FB_DIV_MAX: u16 = 250;
/// VCO floor (MHz).
pub const BM1398_VCO_MIN_MHZ: u16 = 2_000;
/// VCO ceiling (MHz).
pub const BM1398_VCO_MAX_MHZ: u16 = 3_200;
/// VCO ceiling when refdiv == 1 (MHz).
pub const BM1398_REFDIV_ONE_VCO_MAX_MHZ: u16 = 3_125;
/// Strict error ceiling (millimhz); candidate must be strictly below.
pub const BM1398_MAX_ERROR_MILLIMHZ_EXCLUSIVE: u32 = 10_000;

/// Encode BM1398 PLL0 parameter word (12-bit FBDIV, raw postdiv, PLLEN@30).
pub const fn bm1398_pll_register_value(div: Bm1398PllDividers) -> u32 {
    (1u32 << 30)
        | ((div.fb_div as u32 & 0x0FFF) << 16)
        | ((div.ref_div as u32 & 0x3F) << 8)
        | ((div.post_div1 as u32 & 0x7) << 4)
        | (div.post_div2 as u32 & 0x7)
}

/// Discrete autotuner-friendly BM1398 frequency list (driver historical SSOT).
pub fn bm1398_pll_frequencies() -> &'static [u16] {
    &[
        50, 100, 150, 200, 250, 300, 350, 400, 425, 450, 475, 500, 525, 550, 575, 600, 625, 650,
        675, 700, 750, 800,
    ]
}

/// Vendor four-divider search (port of api-types `FourDividerPllSearchSpec::resolve`
/// with BM1398 envelope constants). Fail-closed outside error ceiling.
fn bm1398_pll_search(target_mhz: u16) -> Option<(PllSolution, Bm1398PllDividers)> {
    if target_mhz == 0 {
        return None;
    }
    let reference_mhz = u64::from(BM1398_CLKI_MHZ);
    let mut best: Option<(u64, u64, Bm1398PllDividers)> = None;
    // Vendor refdiv order: 2 then 1 (not BM1397's 1 then 2).
    for ref_div in [2u8, 1] {
        for post_div2 in 1u8..=7 {
            for post_div1 in post_div2.max(1)..=7 {
                let denominator = u64::from(ref_div) * u64::from(post_div1) * u64::from(post_div2);
                let requested_feedback_numerator = u64::from(target_mhz) * denominator;
                let fb_div = (requested_feedback_numerator + reference_mhz / 2) / reference_mhz;
                if fb_div < u64::from(BM1398_FB_DIV_MIN) || fb_div > u64::from(BM1398_FB_DIV_MAX) {
                    continue;
                }
                let vco_numerator = reference_mhz * fb_div;
                if vco_numerator < u64::from(BM1398_VCO_MIN_MHZ) * u64::from(ref_div)
                    || vco_numerator > u64::from(BM1398_VCO_MAX_MHZ) * u64::from(ref_div)
                    || (ref_div == 1 && vco_numerator > u64::from(BM1398_REFDIV_ONE_VCO_MAX_MHZ))
                {
                    continue;
                }
                let target_numerator = u64::from(target_mhz) * denominator;
                let error_numerator = vco_numerator.abs_diff(target_numerator);
                let candidate = Bm1398PllDividers {
                    fb_div: fb_div as u16,
                    ref_div,
                    post_div1,
                    post_div2,
                };
                let strictly_better = match best {
                    None => true,
                    Some((best_error, best_denominator, _)) => {
                        (error_numerator as u128) * (best_denominator as u128)
                            < (best_error as u128) * (denominator as u128)
                    }
                };
                if strictly_better {
                    best = Some((error_numerator, denominator, candidate));
                }
            }
        }
    }
    best.and_then(|(error_numerator, denominator, div)| {
        let error_millimhz_numerator = error_numerator as u128 * 1_000;
        let ceiling = u128::from(BM1398_MAX_ERROR_MILLIMHZ_EXCLUSIVE) * denominator as u128;
        if error_millimhz_numerator >= ceiling {
            return None;
        }
        let actual_mm = reference_mhz * u64::from(div.fb_div) * 1_000 / denominator;
        let actual_mhz = ((actual_mm + 500) / 1_000) as u16;
        let reg = bm1398_pll_register_value(div);
        Some((
            PllSolution {
                register_value: reg,
                actual_freq_mhz: actual_mhz,
                family: PllFamily::Bm1398,
            },
            div,
        ))
    })
}

fn bm1397_pll_search(target_mhz: u16) -> (PllSolution, Bm1397PllDividers) {
    // G31: full ESP-Miner `pll_get_parameters` ranking (EQUIV residual from G5 closed):
    //   1. closest frequency (millimhz)
    //   2. lowest VCO (= 25 * FBDIV / REFDIV)
    //   3. lowest postdiv1×postdiv2 product
    // Constraints: postdiv1 > postdiv2 (strict), FBDIV 60..=200, CLKI 25 MHz.
    // Loop order matches ESP (refdiv 2→1, postdiv 7→1) for complete-tie stability.
    let target = target_mhz.clamp(BM1397_FREQ_MIN_MHZ, BM1397_FREQ_MAX_MHZ);
    let target_mm = u64::from(target) * 1_000;

    let mut best_fb = 96u16;
    let mut best_ref = 1u8;
    let mut best_pd1 = 2u8;
    let mut best_pd2 = 1u8;
    let mut best_err = u64::MAX;
    let mut best_vco_mm = u64::MAX;
    let mut best_pd_prod = u16::MAX;
    let mut best_actual_mm = 0u64;
    let mut found = false;

    for ref_div in [2u8, 1] {
        for post_div1 in (1u8..=7).rev() {
            for post_div2 in (1u8..=7).rev() {
                // ESP-Miner: postdiv1 > postdiv2 (strict — equals excluded).
                if post_div1 <= post_div2 {
                    continue;
                }
                let divider = u64::from(ref_div) * u64::from(post_div1) * u64::from(post_div2);
                // Round to nearest FBDIV: fb = round(target * divider / 25).
                let fb_num = u64::from(target) * divider + (u64::from(BM1397_CLKI_MHZ) / 2);
                let fb_div = (fb_num / u64::from(BM1397_CLKI_MHZ)) as u16;
                if !(BM1397_FB_DIV_MIN..=BM1397_FB_DIV_MAX).contains(&fb_div) {
                    continue;
                }
                let actual_mm = u64::from(BM1397_CLKI_MHZ) * u64::from(fb_div) * 1_000 / divider;
                let err = actual_mm.abs_diff(target_mm);
                let vco_mm =
                    u64::from(BM1397_CLKI_MHZ) * u64::from(fb_div) * 1_000 / u64::from(ref_div);
                let pd_prod = u16::from(post_div1) * u16::from(post_div2);
                let better = err < best_err
                    || (err == best_err && vco_mm < best_vco_mm)
                    || (err == best_err && vco_mm == best_vco_mm && pd_prod < best_pd_prod);
                if better {
                    best_err = err;
                    best_vco_mm = vco_mm;
                    best_pd_prod = pd_prod;
                    best_fb = fb_div;
                    best_ref = ref_div;
                    best_pd1 = post_div1;
                    best_pd2 = post_div2;
                    best_actual_mm = actual_mm;
                    found = true;
                }
            }
        }
    }

    // Seed only if search found nothing (should not happen for 50..=800).
    if !found {
        best_fb = 96;
        best_ref = 1;
        best_pd1 = 2;
        best_pd2 = 1;
        best_actual_mm = u64::from(BM1397_CLKI_MHZ) * 96 * 1_000 / 2;
    }

    let dividers = Bm1397PllDividers {
        fb_div: best_fb,
        ref_div: best_ref,
        post_div1: best_pd1,
        post_div2: best_pd2,
    };
    let register_value = bm1397_pll_register_value(best_fb, best_ref, best_pd1, best_pd2);
    // Round actual to nearest MHz for driver parity with float `.round()`.
    let actual_freq_mhz = ((best_actual_mm + 500) / 1_000) as u16;
    (
        PllSolution {
            register_value,
            actual_freq_mhz,
            family: PllFamily::Bm1397,
        },
        dividers,
    )
}

// ---------------------------------------------------------------------------
// Crystal 25 MHz brute-force (BM1366 / BM1368 / BM1370)
// freq = 25 * fb_div / (ref_div * postdiv1 * postdiv2)
// ---------------------------------------------------------------------------

/// Tie-break policy for [`crystal25_pll_search`].
///
/// ESP-Miner `pll_get_parameters` ranks:
/// 1. closest frequency, 2. lowest VCO, 3. lowest postdiv1×postdiv2 product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Crystal25TieBreak {
    /// G28–G30 ESP-Miner full ranking (BM1366/68-fallback/70 pure SSOT).
    EspMinerFull,
    /// Historical pre-G30 BM1368 pure (strict less-than only). Superseded by
    /// table-first path; kept for explicit regression of the old ranking if needed.
    #[allow(dead_code)]
    StrictDiffOnly,
}

/// Crystal-25 divider fields (shared by BM1366/70 pure encode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crystal25PllDividers {
    pub fb_div: u16,
    pub ref_div: u8,
    pub post_div1: u8,
    pub post_div2: u8,
    /// 0x40 if VCO < 2400 MHz, else 0x50.
    pub vco_scale: u8,
}

/// BM1370 pure VCO search policy (G29).
///
/// **Default** [`EspMinerUnclamped`] matches ESP-Miner / BitAxe proven path.
/// [`BitmainJigClamp`] is **EXPERIMENTAL** (S21 Pro jig VCO envelope) — opt-in
/// via ChipDriver env `DCENT_BM1370_JIG_VCO_CLAMP=1`; never silently default-on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1370VcoPolicy {
    /// ESP-Miner unconstrained VCO (PRODUCTION pure default).
    EspMinerUnclamped,
    /// Bitmain S21 Pro jig VCO lock range (EXPERIMENTAL).
    BitmainJigClamp,
}

/// BM1370 FBDIV search floor (ESP-Miner / ChipDriver).
pub const BM1370_FB_DIV_MIN: u16 = 160;
/// BM1370 FBDIV search ceiling.
pub const BM1370_FB_DIV_MAX: u16 = 239;
/// Crystal reference (MHz).
pub const BM1370_CLKI_MHZ: f64 = 25.0;
/// Bitmain S21 Pro jig VCO min (MHz).
pub const BM1370_JIG_VCO_MIN_MHZ: f64 = 2000.0;
/// Bitmain S21 Pro jig VCO max (MHz).
pub const BM1370_JIG_VCO_MAX_MHZ: f64 = 3200.0;
/// Bitmain S21 Pro jig VCO max at REFDIV=1 (MHz).
pub const BM1370_JIG_VCO_MAX_REFDIV1_MHZ: f64 = 3125.0;

/// Pure: whether `vco_mhz` is inside the Bitmain S21 Pro jig VCO envelope.
#[inline]
pub fn bm1370_vco_in_jig_range(vco_mhz: f64, ref_div: u8) -> bool {
    let cap = if ref_div == 1 {
        BM1370_JIG_VCO_MAX_REFDIV1_MHZ
    } else {
        BM1370_JIG_VCO_MAX_MHZ
    };
    (BM1370_JIG_VCO_MIN_MHZ..=BM1370_JIG_VCO_MAX_MHZ).contains(&vco_mhz) && vco_mhz <= cap
}

// ---------------------------------------------------------------------------
// BM1368 Bitmain jig PLL table + fallback (G30 pure SSOT)
// ---------------------------------------------------------------------------

/// BM1368 FBDIV search floor (ESP-Miner / ChipDriver fallback).
pub const BM1368_FB_DIV_MIN: u16 = 144;
/// BM1368 FBDIV search ceiling.
pub const BM1368_FB_DIV_MAX: u16 = 235;
/// Crystal reference (MHz) — same 25 MHz family.
pub const BM1368_CLKI_MHZ: f64 = 25.0;
/// Top of Bitmain verified table (x100 MHz) = 475.00 MHz.
pub const BM1368_PLL_TABLE_MAX_X100: u32 = 47_500;
/// PERF-005 capability ceiling for ramp (x100 MHz) = 600.00 MHz.
pub const BM1368_PLL_RAMP_MAX_X100: u32 = 60_000;

/// BM1368 pure VCO fallback policy (G30).
///
/// Table path is always used first (in-jig by construction). Policy applies only
/// to the **off-table** EspMinerFull fallback. Default [`EspMinerUnclamped`].
/// [`BitmainJigClamp`] is EXPERIMENTAL via ChipDriver env
/// `DCENT_BM1368_JIG_VCO_CLAMP=1` (never silently default-on).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1368VcoPolicy {
    /// ESP-Miner unconstrained fallback (PRODUCTION pure default).
    EspMinerUnclamped,
    /// Bitmain S21 jig VCO lock range on fallback only (EXPERIMENTAL).
    BitmainJigClamp,
}

/// Bitmain-verified BM1368 PLL lookup table (S21 fixture jig).
///
/// Source: `single_board_test` ch0_0.log (2023-09-14). 68 entries from
/// 56.25→475.00 MHz in 6.25 MHz steps. All entries: **refdiv=2**, exact lock.
/// Format: `(freq_mhz_x100, fbdiv, postdiv1, postdiv2)`.
pub const BM1368_PLL_TABLE: &[(u16, u8, u8, u8)] = &[
    (5625, 162, 6, 6),
    (6250, 175, 7, 5),
    (6875, 165, 6, 5),
    (7500, 168, 7, 4),
    (8125, 182, 7, 4),
    (8750, 168, 6, 4),
    (9375, 180, 6, 4),
    (10000, 168, 7, 3),
    (10625, 170, 5, 4),
    (11250, 162, 6, 3),
    (11875, 171, 6, 3),
    (12500, 180, 6, 3),
    (13125, 189, 6, 3),
    (13750, 165, 5, 3),
    (14375, 161, 7, 2),
    (15000, 168, 7, 2),
    (15625, 175, 7, 2),
    (16250, 182, 7, 2),
    (16875, 162, 6, 2),
    (17500, 168, 6, 2),
    (18125, 174, 6, 2),
    (18750, 180, 6, 2),
    (19375, 186, 6, 2),
    (20000, 160, 5, 2),
    (20625, 165, 5, 2),
    (21250, 170, 5, 2),
    (21875, 175, 5, 2),
    (22500, 180, 5, 2),
    (23125, 185, 5, 2),
    (23750, 190, 5, 2),
    (24375, 195, 5, 2),
    (25000, 160, 4, 2),
    (25625, 164, 4, 2),
    (26250, 168, 4, 2),
    (26875, 172, 4, 2),
    (27500, 176, 4, 2),
    (28125, 180, 4, 2),
    (28750, 161, 7, 1),
    (29375, 188, 4, 2),
    (30000, 168, 7, 1),
    (30625, 196, 4, 2),
    (31250, 175, 7, 1),
    (31875, 204, 4, 2),
    (32500, 182, 7, 1),
    (33125, 212, 4, 2),
    (33750, 162, 6, 1),
    (34375, 165, 6, 1),
    (35000, 168, 6, 1),
    (35625, 171, 6, 1),
    (36250, 174, 6, 1),
    (36875, 177, 6, 1),
    (37500, 180, 6, 1),
    (38125, 183, 6, 1),
    (38750, 186, 6, 1),
    (39375, 189, 6, 1),
    (40000, 160, 5, 1),
    (40625, 195, 6, 1),
    (41250, 165, 5, 1),
    (41875, 201, 6, 1),
    (42500, 170, 5, 1),
    (43125, 207, 6, 1),
    (43750, 175, 5, 1),
    (44375, 213, 6, 1),
    (45000, 180, 5, 1),
    (45625, 219, 6, 1),
    (46250, 185, 5, 1),
    (46875, 225, 6, 1),
    (47500, 190, 5, 1),
];

/// Pure: BM1368 uses the same S21 jig VCO envelope as BM1370.
#[inline]
pub fn bm1368_vco_in_jig_range(vco_mhz: f64, ref_div: u8) -> bool {
    bm1370_vco_in_jig_range(vco_mhz, ref_div)
}

/// Pure: encode crystal-25 PLL register word (BM1366/68/70 layout).
pub fn crystal25_pll_encode_reg(fb_div: u8, ref_div: u8, post_div1: u8, post_div2: u8) -> u32 {
    let vco = 25.0 * f64::from(fb_div) / f64::from(ref_div.max(1));
    let vco_scale: u8 = if vco >= 2400.0 { 0x50 } else { 0x40 };
    let postdiv_byte =
        ((post_div1.saturating_sub(1) & 0x0F) << 4) | (post_div2.saturating_sub(1) & 0x0F);
    (u32::from(vco_scale) << 24)
        | (u32::from(fb_div) << 16)
        | (u32::from(ref_div) << 8)
        | u32::from(postdiv_byte)
}

/// Pure: Bitmain table lookup (exact x100, else nearest 6.25 MHz snap).
///
/// Returns dividers with **refdiv=2** (table hardcode). `None` if off-table.
pub fn bm1368_pll_table_lookup(target_mhz: f64) -> Option<Crystal25PllDividers> {
    let target_x100 = (target_mhz * 100.0).round() as u16;
    for &(freq_x100, fbdiv, pd1, pd2) in BM1368_PLL_TABLE {
        if freq_x100 == target_x100 {
            return Some(bm1368_table_entry_dividers(fbdiv, pd1, pd2));
        }
    }
    let snapped = ((target_mhz / 6.25).round() * 6.25 * 100.0).round() as u16;
    for &(freq_x100, fbdiv, pd1, pd2) in BM1368_PLL_TABLE {
        if freq_x100 == snapped {
            return Some(bm1368_table_entry_dividers(fbdiv, pd1, pd2));
        }
    }
    None
}

fn bm1368_table_entry_dividers(fbdiv: u8, pd1: u8, pd2: u8) -> Crystal25PllDividers {
    let ref_div = 2u8;
    let reg = crystal25_pll_encode_reg(fbdiv, ref_div, pd1, pd2);
    crystal25_pll_decode_dividers(reg)
}

fn solution_from_crystal25(family: PllFamily, d: Crystal25PllDividers) -> PllSolution {
    let reg = crystal25_pll_encode_reg(d.fb_div as u8, d.ref_div, d.post_div1, d.post_div2);
    let actual = 25.0 * f64::from(d.fb_div)
        / (f64::from(d.ref_div.max(1))
            * f64::from(d.post_div1.max(1))
            * f64::from(d.post_div2.max(1)));
    PllSolution {
        register_value: reg,
        actual_freq_mhz: actual.round() as u16,
        family,
    }
}

/// Resolve BM1368 PLL0 (table first, EspMinerFull fallback unclamped).
#[inline]
pub fn resolve_bm1368_pll(target_mhz: u16) -> PllSolution {
    resolve_bm1368_pll_with_policy(target_mhz, Bm1368VcoPolicy::EspMinerUnclamped)
}

/// Resolve BM1368 with explicit fallback VCO policy.
#[inline]
pub fn resolve_bm1368_pll_with_policy(target_mhz: u16, policy: Bm1368VcoPolicy) -> PllSolution {
    resolve_bm1368_pll_mhz(f64::from(target_mhz), policy).0
}

/// `(register_value, actual_freq_mhz)` for BM1368 pure default path.
#[inline]
pub fn bm1368_pll_reg_and_actual(target_mhz: u16) -> (u32, u16) {
    let s = resolve_bm1368_pll(target_mhz);
    (s.register_value, s.actual_freq_mhz)
}

/// Pure BM1368: table → EspMinerFull fallback (optional jig clamp on fallback only).
pub fn resolve_bm1368_pll_mhz(
    target_mhz: f64,
    policy: Bm1368VcoPolicy,
) -> (PllSolution, Crystal25PllDividers) {
    if let Some(d) = bm1368_pll_table_lookup(target_mhz) {
        return (solution_from_crystal25(PllFamily::Bm1368, d), d);
    }
    let clamp = matches!(policy, Bm1368VcoPolicy::BitmainJigClamp);
    crystal25_pll_search_f64(
        PllFamily::Bm1368,
        target_mhz,
        BM1368_FB_DIV_MIN,
        BM1368_FB_DIV_MAX,
        Crystal25TieBreak::EspMinerFull,
        clamp,
    )
}

/// Pure BM1368 off-table fallback only (no table). Deterministic for tests.
pub fn resolve_bm1368_pll_fallback_mhz(
    target_mhz: f64,
    policy: Bm1368VcoPolicy,
) -> (PllSolution, Crystal25PllDividers) {
    let clamp = matches!(policy, Bm1368VcoPolicy::BitmainJigClamp);
    crystal25_pll_search_f64(
        PllFamily::Bm1368,
        target_mhz,
        BM1368_FB_DIV_MIN,
        BM1368_FB_DIV_MAX,
        Crystal25TieBreak::EspMinerFull,
        clamp,
    )
}

/// Pure BM1368 fixture-style PLL ramp: `(pll_reg, freq_x100)` steps.
///
/// Walks the verified table from 56.25 MHz in 6.25 MHz steps up to
/// `min(target, 475)`, then (PERF-005) continues via table-first pure resolve
/// for targets up to [`BM1368_PLL_RAMP_MAX_X100`] (600 MHz capability ceiling).
/// Policy applies only to off-table resolve steps.
pub fn plan_bm1368_pll_ramp(target_mhz: u16, policy: Bm1368VcoPolicy) -> Vec<(u32, u32)> {
    let target_x100 = ((u32::from(target_mhz) * 100 + 312) / 625) * 625;
    let clamped_target = target_x100.clamp(5625, BM1368_PLL_RAMP_MAX_X100);
    let mut steps = Vec::new();

    let table_target = clamped_target.min(BM1368_PLL_TABLE_MAX_X100);
    for &(freq_x100, fbdiv, pd1, pd2) in BM1368_PLL_TABLE {
        let freq_x100 = u32::from(freq_x100);
        if freq_x100 > table_target {
            break;
        }
        let reg = crystal25_pll_encode_reg(fbdiv, 2, pd1, pd2);
        steps.push((reg, freq_x100));
    }

    if clamped_target > BM1368_PLL_TABLE_MAX_X100 {
        let mut next = BM1368_PLL_TABLE_MAX_X100 + 625;
        while next <= clamped_target {
            let mhz = f64::from(next) / 100.0;
            let (sol, _) = resolve_bm1368_pll_mhz(mhz, policy);
            steps.push((sol.register_value, next));
            next += 625;
        }
        if steps.last().map(|&(_, f)| f) != Some(clamped_target) {
            let mhz = f64::from(clamped_target) / 100.0;
            let (sol, _) = resolve_bm1368_pll_mhz(mhz, policy);
            steps.push((sol.register_value, clamped_target));
        }
    }

    if steps.is_empty() {
        let (sol, _) = resolve_bm1368_pll_mhz(f64::from(target_mhz), policy);
        steps.push((sol.register_value, u32::from(target_mhz) * 100));
    }
    steps
}

/// Resolve BM1366 PLL0 via pure crystal-25 search (ChipDriver thin-wrap SSOT).
#[inline]
pub fn resolve_bm1366_pll(target_mhz: u16) -> PllSolution {
    resolve_pll(PllFamily::Bm1366, target_mhz)
}

/// `(register_value, actual_freq_mhz)` for BM1366 pure nearest search.
#[inline]
pub fn bm1366_pll_reg_and_actual(target_mhz: u16) -> (u32, u16) {
    let s = resolve_bm1366_pll(target_mhz);
    (s.register_value, s.actual_freq_mhz)
}

/// Resolve BM1370 PLL0 via pure EspMinerFull search (default unclamped).
#[inline]
pub fn resolve_bm1370_pll(target_mhz: u16) -> PllSolution {
    resolve_bm1370_pll_with_policy(target_mhz, Bm1370VcoPolicy::EspMinerUnclamped)
}

/// Resolve BM1370 with explicit VCO policy (G29 pure SSOT).
#[inline]
pub fn resolve_bm1370_pll_with_policy(target_mhz: u16, policy: Bm1370VcoPolicy) -> PllSolution {
    resolve_bm1370_pll_mhz(f64::from(target_mhz), policy).0
}

/// `(register_value, actual_freq_mhz)` for BM1370 pure default unclamped search.
#[inline]
pub fn bm1370_pll_reg_and_actual(target_mhz: u16) -> (u32, u16) {
    let s = resolve_bm1370_pll(target_mhz);
    (s.register_value, s.actual_freq_mhz)
}

/// Pure BM1370 search with f64 target (ramp intermediates) + policy.
///
/// Returns `(solution, dividers)` for ChipDriver thin-wrap of encode paths.
pub fn resolve_bm1370_pll_mhz(
    target_mhz: f64,
    policy: Bm1370VcoPolicy,
) -> (PllSolution, Crystal25PllDividers) {
    let clamp = matches!(policy, Bm1370VcoPolicy::BitmainJigClamp);
    crystal25_pll_search_f64(
        PllFamily::Bm1370,
        target_mhz,
        BM1370_FB_DIV_MIN,
        BM1370_FB_DIV_MAX,
        Crystal25TieBreak::EspMinerFull,
        clamp,
    )
}

/// Decode crystal-25 register word into divider fields (test / diagnostics).
pub fn crystal25_pll_decode_dividers(reg: u32) -> Crystal25PllDividers {
    let post = (reg & 0xFF) as u8;
    Crystal25PllDividers {
        fb_div: ((reg >> 16) & 0xFF) as u16,
        ref_div: ((reg >> 8) & 0xFF) as u8,
        post_div1: ((post >> 4) & 0x0F).saturating_add(1),
        post_div2: (post & 0x0F).saturating_add(1),
        vco_scale: (reg >> 24) as u8,
    }
}

fn crystal25_pll_search(
    family: PllFamily,
    target_mhz: u16,
    fb_min: u16,
    fb_max: u16,
    tie_break: Crystal25TieBreak,
) -> PllSolution {
    crystal25_pll_search_f64(
        family,
        f64::from(target_mhz),
        fb_min,
        fb_max,
        tie_break,
        false,
    )
    .0
}

fn crystal25_pll_search_f64(
    family: PllFamily,
    target_mhz: f64,
    fb_min: u16,
    fb_max: u16,
    tie_break: Crystal25TieBreak,
    clamp_vco_jig: bool,
) -> (PllSolution, Crystal25PllDividers) {
    let target = target_mhz;
    let mut best_fb = fb_min;
    let mut best_ref = 1u8;
    let mut best_pd1 = 1u8;
    let mut best_pd2 = 1u8;
    let mut best_freq = 0.0f64;
    let mut best_diff = f64::MAX;
    let mut best_vco = f64::MAX;
    let mut best_pd_prod = u16::MAX;

    for ref_div in 1u8..=2 {
        for postdiv1 in 1u8..=7 {
            for postdiv2 in 1u8..=postdiv1 {
                for fb_div in fb_min..=fb_max {
                    let freq = 25.0 * f64::from(fb_div)
                        / (f64::from(ref_div) * f64::from(postdiv1) * f64::from(postdiv2));
                    let diff = (freq - target).abs();
                    let vco = 25.0 * f64::from(fb_div) / f64::from(ref_div);
                    if clamp_vco_jig && !bm1370_vco_in_jig_range(vco, ref_div) {
                        continue;
                    }
                    let pd_prod = u16::from(postdiv1) * u16::from(postdiv2);
                    let better = match tie_break {
                        Crystal25TieBreak::EspMinerFull => {
                            diff < best_diff
                                || (diff == best_diff && vco < best_vco)
                                || (diff == best_diff && vco == best_vco && pd_prod < best_pd_prod)
                        }
                        Crystal25TieBreak::StrictDiffOnly => diff < best_diff,
                    };
                    if better {
                        best_fb = fb_div;
                        best_ref = ref_div;
                        best_pd1 = postdiv1;
                        best_pd2 = postdiv2;
                        best_freq = freq;
                        best_diff = diff;
                        best_vco = vco;
                        best_pd_prod = pd_prod;
                    }
                }
            }
        }
    }

    let vco_scale: u8 = if best_vco >= 2400.0 { 0x50 } else { 0x40 };
    let postdiv = ((best_pd1 - 1) << 4) | (best_pd2 - 1);
    let pll_reg = (u32::from(vco_scale) << 24)
        | (u32::from(best_fb) << 16)
        | (u32::from(best_ref) << 8)
        | u32::from(postdiv);
    let dividers = Crystal25PllDividers {
        fb_div: best_fb,
        ref_div: best_ref,
        post_div1: best_pd1,
        post_div2: best_pd2,
        vco_scale,
    };
    (
        PllSolution {
            register_value: pll_reg,
            actual_freq_mhz: best_freq.round() as u16,
            family,
        },
        dividers,
    )
}

#[cfg(test)]
mod pll_reference_guard_tests {
    use super::*;
    use crate::board_desc::AsicProtocolIdentity;

    /// W8 CLK-4: the module's scattered internal 25 MHz literals must agree
    /// with the enforced SSOT constant. Mutation-sensitive: changing any one
    /// of `PLL_REFERENCE_HZ`, `BM1398_CLKI_MHZ`, `BM1370_CLKI_MHZ`, or
    /// `BM1368_CLKI_MHZ` independently fails here.
    #[test]
    fn internal_clki_literals_match_the_enforced_reference() {
        assert_eq!(PLL_REFERENCE_HZ, 25_000_000);
        assert_eq!(u32::from(BM1398_CLKI_MHZ) * 1_000_000, PLL_REFERENCE_HZ);
        assert_eq!(BM1370_CLKI_MHZ, f64::from(PLL_REFERENCE_HZ) / 1e6);
        assert_eq!(BM1368_CLKI_MHZ, f64::from(PLL_REFERENCE_HZ) / 1e6);
    }

    /// W8 CLK-4: exact 25 MHz is admitted; anything else fails CLOSED.
    #[test]
    fn admit_pll_reference_fails_closed_on_mismatch_and_undeclared() {
        assert!(admit_pll_reference(Some(25_000_000)).is_ok());
        // The C1 §4 CLK-4 negative case: a hypothetical 24 MHz-XIN board must
        // be rejected rather than silently mis-clocked at 24/25 × target.
        let err = admit_pll_reference(Some(24_000_000)).unwrap_err();
        assert_eq!(err.declared_xin_hz, Some(24_000_000));
        assert_eq!(err.table_reference_hz, 25_000_000);
        // Undeclared reference refuses (absent data stays None → fail closed).
        assert!(admit_pll_reference(None).is_err());
        // Off-by-1-Hz is still a mismatch — no tolerance window.
        assert!(admit_pll_reference(Some(25_000_001)).is_err());
    }

    /// W8 CLK-4: the checked resolver is golden-equivalent to the unchecked
    /// one on the admitted reference, and refuses before any lookup otherwise.
    #[test]
    fn checked_resolver_matches_unchecked_on_25mhz_and_refuses_otherwise() {
        for protocol in [
            AsicProtocolIdentity::Bm1362,
            AsicProtocolIdentity::Bm1368,
            AsicProtocolIdentity::Bm1370,
        ] {
            let unchecked = resolve_pll_for_protocol(protocol, 525);
            let checked =
                resolve_pll_for_protocol_on_reference(protocol, 525, Some(PLL_REFERENCE_HZ))
                    .expect("25 MHz reference must be admitted");
            assert_eq!(checked, unchecked, "{protocol:?}: golden equivalence");
        }
        assert!(resolve_pll_for_protocol_on_reference(
            AsicProtocolIdentity::Bm1362,
            525,
            Some(24_000_000)
        )
        .is_err());
        assert!(
            resolve_pll_for_protocol_on_reference(AsicProtocolIdentity::Bm1362, 525, None).is_err()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_desc::AsicProtocolIdentity;

    #[test]
    fn bm1362_lookup_hits_table_endpoints() {
        let lo = resolve_pll(PllFamily::Bm1362, 400);
        assert_eq!(lo.actual_freq_mhz, 400);
        assert_eq!(lo.register_value, 0x50A0_0141);
        let hi = resolve_pll(PllFamily::Bm1362, 597);
        assert_eq!(hi.actual_freq_mhz, 597);
        assert_eq!(hi.register_value, 0x50EF_0141);
        // Mid-band nearest
        let mid = resolve_pll(PllFamily::Bm1362, 505);
        assert_eq!(mid.actual_freq_mhz, 500);
    }

    /// G30: BM1368 pure jig table + EspMinerFull fallback + ChipDriver thin-wrap.
    #[test]
    fn bm1368_pure_jig_table_and_fallback_and_chipdriver_thin_wrap() {
        assert_eq!(BM1368_PLL_TABLE.len(), 68);
        // Endpoints: 56.25 MHz and 475.00 MHz.
        let lo = bm1368_pll_table_lookup(56.25).expect("56.25 table");
        assert_eq!(lo.fb_div, 162);
        assert_eq!(lo.ref_div, 2);
        let hi = bm1368_pll_table_lookup(475.0).expect("475 table");
        assert_eq!(hi.fb_div, 190);
        // Rated operating 400 MHz is exact table row.
        let s400 = resolve_bm1368_pll(400);
        assert_eq!(s400.actual_freq_mhz, 400);
        assert_eq!(s400.family, PllFamily::Bm1368);
        let (reg, act) = bm1368_pll_reg_and_actual(400);
        assert_eq!((reg, act), (s400.register_value, s400.actual_freq_mhz));
        // Table entry encode: fb=160, ref=2, pd1=5, pd2=1 → VCO=2000 → scale 0x40.
        assert_eq!(s400.register_value, crystal25_pll_encode_reg(160, 2, 5, 1));
        assert_eq!(s400.register_value, 0x40A0_0240);

        // Entire curated table is in-jig VCO (REFDIV=2).
        for &(_fx, fb, _p1, _p2) in BM1368_PLL_TABLE {
            let vco = BM1368_CLKI_MHZ * f64::from(fb) / 2.0;
            assert!(
                bm1368_vco_in_jig_range(vco, 2),
                "table fb={fb} VCO {vco} out of jig"
            );
        }

        // Unclamped fallback finding: 100 MHz out of jig VCO.
        let (_s, d100) = resolve_bm1368_pll_fallback_mhz(100.0, Bm1368VcoPolicy::EspMinerUnclamped);
        let vco100 = BM1368_CLKI_MHZ * f64::from(d100.fb_div) / f64::from(d100.ref_div.max(1));
        assert!(
            !bm1368_vco_in_jig_range(vco100, d100.ref_div),
            "unclamped 100 MHz fallback must be out of jig VCO"
        );

        // Clamped fallback: every 100..=900 in jig VCO.
        for t in 100..=900u16 {
            let (_s, d) =
                resolve_bm1368_pll_fallback_mhz(f64::from(t), Bm1368VcoPolicy::BitmainJigClamp);
            let vco = BM1368_CLKI_MHZ * f64::from(d.fb_div) / f64::from(d.ref_div.max(1));
            assert!(
                bm1368_vco_in_jig_range(vco, d.ref_div),
                "clamped fallback {t} VCO {vco} out of jig"
            );
        }

        // Default resolve_pll uses unclamped table-first path.
        assert_eq!(
            resolve_pll(PllFamily::Bm1368, 400).register_value,
            resolve_bm1368_pll(400).register_value
        );
        // Off-table 500: not in table → fallback, still near target.
        let s500 = resolve_bm1368_pll(500);
        let err = (s500.actual_freq_mhz as i32 - 500).unsigned_abs();
        assert!(err <= 5, "500 MHz fallback err={err}");

        // Structural thin-wrap pin.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let drv = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1368.rs"))
            .expect("bm1368");
        assert!(
            drv.contains("dcentrald_common::BM1368_PLL_TABLE")
                || drv.contains("pub use dcentrald_common::BM1368_PLL_TABLE"),
            "bm1368 must re-export pure BM1368_PLL_TABLE"
        );
        assert!(
            drv.contains("resolve_bm1368_pll_mhz")
                || drv.contains("dcentrald_common::resolve_bm1368_pll_mhz"),
            "bm1368 search must thin-wrap pure resolve_bm1368_pll_mhz"
        );
        assert!(
            drv.contains("plan_bm1368_pll_ramp")
                || drv.contains("dcentrald_common::plan_bm1368_pll_ramp"),
            "bm1368 ramp must thin-wrap pure plan_bm1368_pll_ramp"
        );
        // Pure ramp: table-only target starts at 56.25 and ends on snapped table.
        let ramp400 = plan_bm1368_pll_ramp(400, Bm1368VcoPolicy::EspMinerUnclamped);
        assert_eq!(ramp400.first().map(|&(_, f)| f), Some(5625));
        assert_eq!(ramp400.last().map(|&(_, f)| f), Some(40000));
        assert_eq!(ramp400.last().map(|&(r, _)| r), Some(0x40A0_0240));
        assert!(
            !drv.contains("const BM1368_PLL_TABLE: &[(u16, u8, u8, u8)] = &["),
            "bm1368 must not open-code local jig table after G30"
        );
        assert!(
            drv.contains("DCENT_BM1368_JIG_VCO_CLAMP"),
            "jig clamp env gate must remain default-OFF EXPERIMENTAL"
        );
    }

    /// G29: BM1370 pure EspMinerFull + jig clamp policy + ChipDriver thin-wrap pin.
    #[test]
    fn bm1370_pure_espminer_and_jig_clamp_and_chipdriver_thin_wrap() {
        // Operating eco points resolve near target (unclamped default).
        for target in [400u16, 450, 500, 525, 550, 600] {
            let sol = resolve_bm1370_pll(target);
            let err = (sol.actual_freq_mhz as i32 - target as i32).unsigned_abs();
            assert!(
                err <= 3,
                "BM1370 target={target} actual={} reg=0x{:08X} err={err}",
                sol.actual_freq_mhz,
                sol.register_value
            );
            assert_eq!(sol.family, PllFamily::Bm1370);
            let (reg, act) = bm1370_pll_reg_and_actual(target);
            assert_eq!((reg, act), (sol.register_value, sol.actual_freq_mhz));
            let d = crystal25_pll_decode_dividers(sol.register_value);
            assert!((BM1370_FB_DIV_MIN..=BM1370_FB_DIV_MAX).contains(&d.fb_div));
            assert!(d.ref_div == 1 || d.ref_div == 2);
            // Dividers path matches register.
            let (sol2, d2) =
                resolve_bm1370_pll_mhz(f64::from(target), Bm1370VcoPolicy::EspMinerUnclamped);
            assert_eq!(sol2.register_value, sol.register_value);
            assert_eq!(d2.fb_div, d.fb_div);
        }

        // Load-bearing finding: unclamped EspMinerFull selects out-of-jig VCO for
        // a non-zero share of 400..=700 MHz (REFDIV=1 high VCO). Pin exact count.
        let mut unclamped_out = 0u32;
        for t in 400..=700u16 {
            let (_s, d) = resolve_bm1370_pll_mhz(f64::from(t), Bm1370VcoPolicy::EspMinerUnclamped);
            let vco = BM1370_CLKI_MHZ * f64::from(d.fb_div) / f64::from(d.ref_div);
            if !bm1370_vco_in_jig_range(vco, d.ref_div) {
                unclamped_out += 1;
            }
        }
        assert_eq!(
            unclamped_out, 66,
            "expected 66/301 unclamped 400-700 out of jig VCO (EspMinerFull pure)"
        );
        // Concrete example 447 MHz (historical finding).
        let (_s, d447) = resolve_bm1370_pll_mhz(447.0, Bm1370VcoPolicy::EspMinerUnclamped);
        let vco447 = BM1370_CLKI_MHZ * f64::from(d447.fb_div) / f64::from(d447.ref_div);
        assert!(
            !bm1370_vco_in_jig_range(vco447, d447.ref_div),
            "unclamped 447 MHz must be out of jig range"
        );

        // Jig clamp: every 100..=900 stays in jig VCO envelope; worst err ≤2 MHz on 400-700.
        let mut worst = 0.0_f64;
        for t in 100..=900u16 {
            let (sol, d) = resolve_bm1370_pll_mhz(f64::from(t), Bm1370VcoPolicy::BitmainJigClamp);
            let vco = BM1370_CLKI_MHZ * f64::from(d.fb_div) / f64::from(d.ref_div);
            assert!(
                bm1370_vco_in_jig_range(vco, d.ref_div),
                "clamped target {t} VCO {vco} out of jig (fb={} rd={})",
                d.fb_div,
                d.ref_div
            );
            if (400..=700).contains(&t) {
                let actual = BM1370_CLKI_MHZ * f64::from(d.fb_div)
                    / (f64::from(d.ref_div) * f64::from(d.post_div1) * f64::from(d.post_div2));
                worst = worst.max((actual - f64::from(t)).abs());
                assert_eq!(sol.family, PllFamily::Bm1370);
            }
        }
        assert!(worst <= 2.0, "clamped worst err {worst} MHz on 400-700");

        // Default resolve_pll path is unclamped (not jig).
        let via_family = resolve_pll(PllFamily::Bm1370, 500);
        let via_default = resolve_bm1370_pll(500);
        assert_eq!(via_family.register_value, via_default.register_value);

        // Structural: ChipDriver thin-wraps pure + keeps env gate name.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let drv = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1370.rs"))
            .expect("bm1370");
        assert!(
            drv.contains("resolve_bm1370_pll_mhz")
                || drv.contains("dcentrald_common::resolve_bm1370_pll_mhz"),
            "bm1370 ChipDriver must thin-wrap pure resolve_bm1370_pll_mhz"
        );
        assert!(
            drv.contains("Bm1370VcoPolicy") || drv.contains("dcentrald_common::Bm1370VcoPolicy"),
            "bm1370 must use pure Bm1370VcoPolicy"
        );
        assert!(
            drv.contains("DCENT_BM1370_JIG_VCO_CLAMP"),
            "jig clamp must remain env-gated EXPERIMENTAL default-OFF"
        );
        // No open-coded FB_DIV float search remaining in compute path.
        assert!(
            !drv.contains("for fb_div in FB_DIV_MIN") && !drv.contains("for fb_div in 160"),
            "bm1370 must not keep open-coded FB_DIV search after G29"
        );
    }

    #[test]
    fn industrial_serial_routes_select_jig_vco_without_changing_global_defaults() {
        let (_safe_1368, safe_1368_dividers) =
            resolve_bm1368_pll_mhz(491.0, Bm1368VcoPolicy::BitmainJigClamp);
        let safe_1368_vco = BM1368_CLKI_MHZ * f64::from(safe_1368_dividers.fb_div)
            / f64::from(safe_1368_dividers.ref_div);
        assert!(bm1368_vco_in_jig_range(
            safe_1368_vco,
            safe_1368_dividers.ref_div
        ));
        let default_1368 =
            crystal25_pll_decode_dividers(resolve_pll(PllFamily::Bm1368, 491).register_value);
        let default_1368_vco =
            BM1368_CLKI_MHZ * f64::from(default_1368.fb_div) / f64::from(default_1368.ref_div);
        assert_eq!(default_1368_vco, 1962.5);
        assert!(!bm1368_vco_in_jig_range(
            default_1368_vco,
            default_1368.ref_div
        ));

        let (_safe_1370, safe_1370_dividers) =
            resolve_bm1370_pll_mhz(447.0, Bm1370VcoPolicy::BitmainJigClamp);
        let safe_1370_vco = BM1370_CLKI_MHZ * f64::from(safe_1370_dividers.fb_div)
            / f64::from(safe_1370_dividers.ref_div);
        assert!(bm1370_vco_in_jig_range(
            safe_1370_vco,
            safe_1370_dividers.ref_div
        ));
        let default_1370 =
            crystal25_pll_decode_dividers(resolve_pll(PllFamily::Bm1370, 447).register_value);
        let default_1370_vco =
            BM1370_CLKI_MHZ * f64::from(default_1370.fb_div) / f64::from(default_1370.ref_div);
        assert!(!bm1370_vco_in_jig_range(
            default_1370_vco,
            default_1370.ref_div
        ));

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let serial = std::fs::read_to_string(root.join("dcentrald/src/serial_mining.rs"))
            .expect("serial_mining");
        let production_end = serial
            .find("\n#[cfg(test)]\nmod tests {")
            .expect("serial production/test boundary");
        let production = &serial[..production_end];
        for marker in [
            "S21Bm1368ShippedConfig",
            "S21ProBm1370ShippedConfig",
            "S21XpBm1370ShippedConfig",
            "Bm1368VcoPolicy::BitmainJigClamp",
            "Bm1370VcoPolicy::BitmainJigClamp",
            "preflight_industrial_pll_policy",
        ] {
            assert!(
                production.contains(marker),
                "missing industrial pin {marker}"
            );
        }
        assert!(
            !production.contains("T21Bm1368ShippedConfig"),
            "T21's non-authoritative frequency scaffold must not become a shipped PLL policy"
        );
        assert!(!production.contains("resolve_pll(dcentrald_common::PllFamily::Bm1368"));
        assert!(!production.contains("resolve_pll(dcentrald_common::PllFamily::Bm1370"));
    }

    /// G28: BM1366 pure search matches ChipDriver thin-wrap (no forked float search).
    #[test]
    fn bm1366_chipdriver_thin_wraps_pure_pll_and_esp_goldens() {
        // ESP-Miner / industrial common eco points must resolve near target.
        for target in [400u16, 450, 500, 525, 550, 600] {
            let sol = resolve_bm1366_pll(target);
            let err = (sol.actual_freq_mhz as i32 - target as i32).unsigned_abs();
            assert!(
                err <= 2,
                "BM1366 target={target} actual={} reg=0x{:08X} err={err}",
                sol.actual_freq_mhz,
                sol.register_value
            );
            assert_eq!(sol.family, PllFamily::Bm1366);
            let (reg, act) = bm1366_pll_reg_and_actual(target);
            assert_eq!((reg, act), (sol.register_value, sol.actual_freq_mhz));
            // VCO scale byte is 0x40 or 0x50.
            let scale = (sol.register_value >> 24) as u8;
            assert!(scale == 0x40 || scale == 0x50, "scale=0x{scale:02X}");
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let drv = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1366.rs"))
            .expect("bm1366");
        assert!(
            drv.contains("bm1366_pll_reg_and_actual") && drv.contains("dcentrald_common"),
            "bm1366 ChipDriver must thin-wrap pure bm1366_pll_reg_and_actual"
        );
        assert!(
            !drv.contains("for fb_div in FB_DIV_MIN") && !drv.contains("for fb_div in 144"),
            "bm1366 must not keep open-coded FB_DIV float search after G28"
        );
        assert!(
            !drv.contains("const FREQ_MULT: f64 = 25.0"),
            "bm1366 must not keep forked FREQ_MULT search after G28"
        );
    }

    /// G26: pure table includes rated 545 + live 531/556; frequencies list is 1:1.
    #[test]
    fn bm1362_pure_table_includes_rated_545_and_live_anchors() {
        assert_eq!(BM1362_PLL_TABLE.len(), BM1362_PLL_FREQUENCIES.len());
        for (i, &(f, reg)) in BM1362_PLL_TABLE.iter().enumerate() {
            assert_eq!(BM1362_PLL_FREQUENCIES[i], f, "freq list vs table at {i}");
            assert_ne!(reg, 0);
        }
        let rated = resolve_bm1362_pll(545);
        assert_eq!(rated.actual_freq_mhz, 545);
        assert_eq!(rated.register_value, 0x50DA_0141);
        let a531 = resolve_bm1362_pll(531);
        assert_eq!(a531.actual_freq_mhz, 531);
        assert_eq!(a531.register_value, 0x50D4_0141);
        let a556 = resolve_bm1362_pll(556);
        assert_eq!(a556.actual_freq_mhz, 556);
        assert_eq!(a556.register_value, 0x50DE_0141);
        // Nearest around rated band (before G26 pure missed 545 → nearest was 537/550).
        assert_eq!(resolve_bm1362_pll(543).actual_freq_mhz, 545);
        assert_eq!(resolve_bm1362_pll(540).actual_freq_mhz, 537); // |540-537|=3 < |540-545|=5
        let (reg, actual) = bm1362_pll_reg_and_actual(545);
        assert_eq!((reg, actual), (0x50DA_0141, 545));
    }

    /// G26: ChipDriver + hybrid must not re-open a forked BM1362_PLL_TABLE.
    #[test]
    fn bm1362_chipdriver_and_hybrid_thin_wrap_pure_table() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let drv = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1362.rs"))
            .expect("bm1362 driver");
        assert!(
            drv.contains("dcentrald_common::BM1362_PLL_TABLE")
                || drv.contains("pub use dcentrald_common::BM1362_PLL_TABLE")
                || drv.contains("use dcentrald_common::{") && drv.contains("BM1362_PLL_TABLE"),
            "bm1362 ChipDriver must re-export/use pure BM1362_PLL_TABLE"
        );
        assert!(
            drv.contains("dcentrald_common::bm1362_pll_reg_and_actual")
                || drv.contains("bm1362_pll_reg_and_actual") && drv.contains("dcentrald_common"),
            "bm1362 ChipDriver lookup must thin-wrap pure bm1362_pll_reg_and_actual"
        );
        // No open-coded full table of 17+ tuples still living as a local const
        // (re-export is fine; inventing a second `const BM1362_PLL_TABLE: &[(u16, u32)] = &[`
        // with literals is not).
        let local_table_lit = drv
            .matches("const BM1362_PLL_TABLE: &[(u16, u32)] = &[")
            .count();
        assert_eq!(
            local_table_lit, 0,
            "bm1362 must not open-code a local BM1362_PLL_TABLE literal"
        );
        let hybrid = std::fs::read_to_string(root.join("dcentrald/src/s19j_hybrid_mining.rs"))
            .expect("hybrid");
        assert!(
            !hybrid.contains("const BM1362_PLL_TABLE"),
            "hybrid must not fork BM1362_PLL_TABLE; use ChipDriver/common pure SSOT"
        );
        assert!(
            hybrid.contains("pll_lookup(")
                || hybrid.contains("bm1362::pll_lookup")
                || hybrid.contains("dcentrald_asic::drivers::bm1362::pll_lookup")
                || hybrid.contains("bm1362_pll_reg_and_actual"),
            "hybrid must call thin-wrapped BM1362 pll_lookup (not a private forked fn)"
        );
    }

    #[test]
    fn crystal_search_is_near_target_for_common_eco_freqs() {
        for family in [PllFamily::Bm1366, PllFamily::Bm1368, PllFamily::Bm1370] {
            for target in [50u16, 200, 400, 525] {
                let sol = resolve_pll(family, target);
                let err = (sol.actual_freq_mhz as i32 - target as i32).unsigned_abs();
                assert!(
                    err <= 5,
                    "{family:?} target={target} actual={} reg=0x{:08X} err={err}",
                    sol.actual_freq_mhz,
                    sol.register_value
                );
                assert_eq!(sol.family, family);
                // PLL0 write plan always targets reg 0x08.
                match plan_pll0_broadcast_write(sol) {
                    TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value } => {
                        assert_eq!(reg, PLL0_PARAMETER_REG);
                        assert_eq!(value, sol.register_value);
                    }
                    other => panic!("expected broadcast write, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn protocol_mapping_refuses_stock_and_runtime() {
        // G16: BM1387 is pure table encode (not refused) but TransportOp expand empty.
        assert_eq!(
            pll_family_for_protocol(AsicProtocolIdentity::Bm1387),
            Some(PllFamily::Bm1387)
        );
        assert!(pll_family_for_protocol(AsicProtocolIdentity::RuntimeDiscovered).is_none());
        // G19: BM1398 production pure encode admitted.
        assert_eq!(
            pll_family_for_protocol(AsicProtocolIdentity::Bm1398),
            Some(PllFamily::Bm1398)
        );
        assert!(pll_family_for_protocol(AsicProtocolIdentity::Bm1396).is_none());
        assert_eq!(
            pll_family_for_protocol(AsicProtocolIdentity::Bm1362),
            Some(PllFamily::Bm1362)
        );
        assert_eq!(
            pll_family_for_protocol(AsicProtocolIdentity::Bm1397),
            Some(PllFamily::Bm1397)
        );
        assert!(resolve_pll_for_protocol(AsicProtocolIdentity::Bm1368, 0).is_none());
        // BM1387 pure resolve works; TransportOp plan stays empty (stock FPGA).
        assert!(plan_frequency_program_ops(AsicProtocolIdentity::Bm1387, 500).is_empty());
        assert!(!plan_frequency_program_ops(AsicProtocolIdentity::Bm1362, 500).is_empty());
        assert!(!plan_frequency_program_ops(AsicProtocolIdentity::Bm1397, 500).is_empty());
        assert!(!plan_frequency_program_ops(AsicProtocolIdentity::Bm1398, 525).is_empty());
    }

    /// G19: BM1398 vendor dual-binary goldens + anti-BM1397-alias pins.
    #[test]
    fn bm1398_pll_vendor_goldens_and_not_bm1397_alias() {
        let (s525, d525) = resolve_bm1398_pll(525).expect("525");
        assert_eq!(s525.family, PllFamily::Bm1398);
        assert_eq!(d525.ref_div, 2);
        assert_eq!(d525.fb_div, 168);
        assert_eq!(d525.post_div1, 4);
        assert_eq!(d525.post_div2, 1);
        assert_eq!(s525.register_value, 0x40a8_0241);

        let (s675, d675) = resolve_bm1398_pll(675).expect("675");
        assert_eq!(d675.ref_div, 2);
        assert_eq!(d675.fb_div, 162);
        assert_eq!(d675.post_div1, 3);
        assert_eq!(d675.post_div2, 1);
        assert_eq!(s675.register_value, 0x40a2_0231);

        // 12-bit FBDIV encode (jig golden).
        let word = bm1398_pll_register_value(Bm1398PllDividers {
            fb_div: 0x0800,
            ref_div: 1,
            post_div1: 1,
            post_div2: 1,
        });
        assert_eq!((word >> 16) & 0x0fff, 0x0800);
        assert_eq!(word, 0x4800_0111);

        // Error ceiling boundaries (vendor).
        assert!(resolve_bm1398_pll(1_990).is_none());
        assert!(resolve_bm1398_pll(1_991).is_some());
        assert!(resolve_bm1398_pll(3_134).is_some());
        assert!(resolve_bm1398_pll(3_135).is_none());

        // Program cadence shares G5/G11 BM1397 0x70 plan (not empty).
        let ops = plan_frequency_program_ops(AsicProtocolIdentity::Bm1398, 525);
        assert_eq!(ops.len(), 8);
        assert_eq!(ops, plan_bm1397_frequency_program_ops(s525.register_value));

        // Anti-silent-alias: BM1398 must not use BM1397 FBDIV 60..=200 / 11-bit mask.
        assert_ne!(BM1398_FB_DIV_MIN, BM1397_FB_DIV_MIN);
        assert_eq!(BM1398_FB_DIV_MIN, 16);
        assert_eq!(BM1398_FB_DIV_MAX, 250);
        // R2: outside-envelope exact refuse; nearest-admitted does not invent 525 for 1990.
        assert!(resolve_bm1398_pll(1_990).is_none());
        let near = resolve_bm1398_pll_nearest_admitted(1_990).expect("discrete list");
        assert_ne!(
            near.0.actual_freq_mhz, 525,
            "must not invent hard-coded 525"
        );
        assert!(near.0.actual_freq_mhz <= 800);
        // Structural: api-types resolve must thin-wrap common after G19.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let proto =
            std::fs::read_to_string(root.join("dcentrald-api-types/src/bm1398_protocol.rs"))
                .expect("bm1398_protocol");
        assert!(
            proto.contains("dcentrald_common::resolve_bm1398_pll")
                || proto.contains("resolve_bm1398_pll") && proto.contains("dcentrald_common"),
            "api-types BM1398 resolve must thin-wrap common pure SSOT"
        );
        let drv = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1398.rs"))
            .expect("bm1398 driver");
        assert!(
            !drv.contains("Identical to BM1397 PLL calculation"),
            "driver must not claim BM1398 encode is identical to BM1397"
        );
        assert!(
            drv.contains("resolve_bm1398_pll_nearest_admitted")
                || drv.contains("dcentrald_common::resolve_bm1398_pll_nearest_admitted"),
            "driver must use nearest-admitted pure path (no invent-525)"
        );
    }

    /// G16: BM1387 pure table — Braiins goldens + bug-corrected 500 MHz word.
    #[test]
    fn bm1387_pll_table_matches_braiins_goldens_and_bug_corrected_labels() {
        let s500 = resolve_bm1387_pll(500);
        assert_eq!(s500.family, PllFamily::Bm1387);
        assert_eq!(s500.actual_freq_mhz, 500);
        assert_eq!(
            s500.register_value, 0x0050_0221,
            "Braiins/bug-corrected 500 MHz (not mislabeled 0x00420221=412)"
        );
        let s650 = resolve_bm1387_pll(650);
        assert_eq!(s650.actual_freq_mhz, 650);
        assert_eq!(s650.register_value, 0x0068_0221, "Braiins 650 MHz golden");
        // Nearest-neighbor mid-band.
        let s505 = resolve_bm1387_pll(505);
        assert_eq!(s505.actual_freq_mhz, 500);
        // Protocol resolve + empty TransportOp plan (honest stock FPGA residual).
        let via_proto = resolve_pll_for_protocol(AsicProtocolIdentity::Bm1387, 500).unwrap();
        assert_eq!(via_proto, s500);
        assert!(plan_frequency_program_ops(AsicProtocolIdentity::Bm1387, 500).is_empty());
        assert_eq!(
            plan_pll_broadcast_write(s500, 0),
            Err(PllPlanError::TransportProgramUnsupported {
                family: PllFamily::Bm1387
            })
        );
        assert_eq!(
            pll_register_addrs(PllFamily::Bm1387),
            &[BM1387_PLL_PARAMETER_REG]
        );
        assert_eq!(BM1387_PLL_PARAMETER_REG, 0x0C);
        // Freq list length matches table.
        assert_eq!(bm1387_pll_frequencies().len(), BM1387_PLL_TABLE.len());
        // Driver thin-wrap structural pin.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let drv = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1387.rs"))
            .expect("bm1387 driver");
        assert!(
            drv.contains("resolve_bm1387_pll")
                || drv.contains("dcentrald_common::resolve_bm1387_pll")
                || drv.contains("resolve_pll") && drv.contains("Bm1387"),
            "bm1387 driver must thin-wrap pure BM1387 PLL resolve"
        );
        assert!(
            !drv.contains("(100, 0x0020_0241)")
                && !drv.contains("pub const BM1387_PLL_TABLE: &[(u16, u32)] = &["),
            "BM1387_PLL_TABLE must live in dcentrald-common, not open-coded in driver"
        );
    }

    #[test]
    fn bm1396_exact_signed_pll_solver_and_plan_are_admitted_but_carrier_stays_closed() {
        // Exact pure solving is admitted while generic transport and the live
        // ChipDriver stay closed. The old family hypothesis remains only as an
        // explicit comparison API, never a silent BM1397 production alias.
        assert_eq!(
            bm1396_production_pure_pll_status(),
            Bm1396PurePllStatus::OfflineVerifiedExactSignedMultiFirmware
        );
        assert!(bm1396_production_pure_pll_admitted());

        let goldens = [
            (500.0, 0x00a0_0241, (160, 2, 4, 1)),
            (600.0, 0x00c0_0241, (192, 2, 4, 1)),
            (650.0, 0x00d0_0241, (208, 2, 4, 1)),
            (700.0, 0x00a8_0231, (168, 2, 3, 1)),
        ];
        for (target, register, dividers) in goldens {
            let solved = resolve_bm1396_pll(target, 0).expect("exact signed solver");
            assert_eq!(solved.register_value, register, "target {target} MHz");
            assert_eq!(solved.selector, BM1396_PLL_SUCCESS_SELECTOR);
            assert_eq!(solved.actual_freq_mhz, target);
            assert_eq!(
                (
                    solved.dividers.fb_div,
                    solved.dividers.ref_div,
                    solved.dividers.post_div1,
                    solved.dividers.post_div2,
                ),
                dividers
            );
        }
        let preserved = resolve_bm1396_pll(600.0, u32::MAX).expect("old register preservation");
        assert_eq!(
            preserved.register_value & BM1396_PLL_PRESERVE_MASK,
            BM1396_PLL_PRESERVE_MASK
        );
        assert_eq!(
            preserved.register_value & !BM1396_PLL_PRESERVE_MASK,
            0x00c0_0241 & !BM1396_PLL_PRESERVE_MASK,
            "unpreserved old bits must not leak into the solved register"
        );
        let threshold_accepted =
            resolve_bm1396_pll(3_134.0, 0).expect("strictly less than 10 MHz error");
        assert_eq!(threshold_accepted.actual_freq_mhz, 3_125.0);
        assert!(resolve_bm1396_pll(3_135.0, 0).is_none());
        assert!(resolve_bm1396_pll(0.0, 0).is_none());
        assert!(resolve_bm1396_pll(1.0, 0).is_none());
        assert!(resolve_bm1396_pll(f32::NAN, 0).is_none());
        assert!(resolve_bm1396_pll(f32::INFINITY, 0).is_none());
        assert_eq!(BM1396_PLL_FAILURE_REGISTER, 0x0078_0111);
        assert_eq!(BM1396_PLL_FAILURE_SELECTOR, 0x0f);

        let solved_600 = resolve_bm1396_pll(600.0, 0).expect("600 MHz program plan");
        assert_eq!(
            bm1396_pll_program_register_value(solved_600.register_value),
            0x40c0_0241
        );
        let pll0_ops = plan_bm1396_pll_program_ops(solved_600, 0).expect("PLL0 index");
        assert_eq!(pll0_ops.len(), BM1396_PLL_PROGRAM_WRITE_COUNT);
        assert_eq!(
            pll0_ops,
            vec![
                TransportOp::SendWriteRegBroadcastBm1397Plus {
                    reg: 0x08,
                    value: 0x40c0_0241,
                },
                TransportOp::SendWriteRegBroadcastBm1397Plus {
                    reg: 0x08,
                    value: 0x40c0_0241,
                },
            ]
        );
        let pll3_ops = plan_bm1396_pll_program_ops(solved_600, 3).expect("PLL3 index");
        assert!(matches!(
            pll3_ops.as_slice(),
            [
                TransportOp::SendWriteRegBroadcastBm1397Plus { reg: 0x68, .. },
                TransportOp::SendWriteRegBroadcastBm1397Plus { reg: 0x68, .. }
            ]
        ));
        assert!(plan_bm1396_pll_program_ops(solved_600, 4).is_none());

        // BM1396 remains a distinct named solver rather than a silent BM1397
        // PllFamily alias. Carrier admission remains a separate closed gate.
        assert!(pll_family_for_protocol(AsicProtocolIdentity::Bm1396).is_none());
        assert!(resolve_pll_for_protocol(AsicProtocolIdentity::Bm1396, 400).is_none());
        assert!(resolve_pll_for_protocol(AsicProtocolIdentity::Bm1396, 500).is_none());
        assert!(resolve_pll_for_protocol(AsicProtocolIdentity::Bm1396, 650).is_none());
        assert_eq!(
            plan_bm1396_frequency_program_ops(600),
            Some(pll0_ops.clone())
        );
        assert!(plan_bm1396_frequency_program_ops(1).is_none());
        assert!(plan_frequency_program_ops(AsicProtocolIdentity::Bm1396, 600).is_empty());
        assert!(plan_frequency_program_ops(AsicProtocolIdentity::Bm1396, 0).is_empty());

        // Experimental hypothesis reuses BM1397 pure encoder; family label stays Bm1397.
        let (sol, div) = resolve_bm1396_pll_experimental_family_hypothesis(450);
        let (sol1397, div1397) = resolve_bm1397_pll(450);
        assert_eq!(sol, sol1397);
        assert_eq!(div, div1397);
        assert_eq!(sol.family, PllFamily::Bm1397);
        assert_eq!(
            sol.register_value, 0x4048_0221,
            "450 MHz ESP-Miner golden via hypothesis"
        );
        let exp_ops = plan_bm1396_frequency_program_ops_experimental(sol.register_value);
        assert_eq!(
            exp_ops,
            plan_bm1397_frequency_program_ops(sol.register_value)
        );
        assert_eq!(exp_ops.len(), 8);

        // Structural: production match arm must list Bm1396 with the refuse group
        // (not map to Some(PllFamily::Bm1397)).
        let src = include_str!("pll_model.rs");
        let solution_struct = src
            .split("pub struct Bm1396PllSolution")
            .nth(1)
            .and_then(|s| s.split("impl Bm1396PllSolution").next())
            .expect("BM1396 solution struct body");
        assert!(
            !solution_struct.contains("pub register_value")
                && !solution_struct.contains("pub selector")
                && !solution_struct.contains("pub actual_freq_mhz")
                && !solution_struct.contains("pub dividers"),
            "BM1396 solution fields must remain solver-owned so a failure sentinel cannot be forged"
        );
        assert!(
            src.contains("AsicProtocolIdentity::Bm1396")
                && src.contains("OfflineVerifiedExactSignedMultiFirmware")
                && src.contains("resolve_bm1396_pll"),
            "pll_model must retain the exact signed BM1396 solver"
        );
        // Anti-silent-alias: the production mapping function body must not assign
        // Bm1396 => Some(...).
        let map_fn = src
            .split("pub fn pll_family_for_protocol")
            .nth(1)
            .and_then(|s| s.split("pub fn resolve_pll").next())
            .expect("pll_family_for_protocol body");
        assert!(
            !map_fn.contains("Bm1396 => Some")
                && !map_fn.contains("Bm1396=>Some")
                && !map_fn.contains("Bm1396 => Some(PllFamily::Bm1397)"),
            "production pll_family_for_protocol must not map Bm1396 to Some(family)"
        );

        // ChipRegistry: 0x1396 remains unregistered (fail-closed detect).
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mod_src = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/mod.rs"))
            .expect("drivers mod");
        let bm1396_src = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1396.rs"))
            .expect("bm1396 scaffold");
        assert!(
            mod_src.contains("0x1396")
                && (mod_src.contains("must NOT resolve")
                    || mod_src.contains("BM1396_FAMILY_ID")
                    || mod_src.contains("pr056_bm1396")),
            "PR-056 BM1396 fail-closed pin must remain in drivers/mod.rs"
        );
        assert!(
            bm1396_src.contains("impl ChipDriver for Bm1396Driver"),
            "R06: BM1396 must keep its evidence-cited ChipDriver impl \
             (drivers/bm1396.rs); its carrier-bound methods refuse the \
             Braiins-FIFO ABI and the ChipRegistry registration pin below \
             still forbids silent production dispatch"
        );
        assert!(
            !mod_src.contains("register(Box::new(bm1396::Bm1396Driver"),
            "BM1396 must not be registered in ChipRegistry"
        );
    }

    /// G31: BM1397 pure search matches full ESP-Miner ranking (pd1>pd2 + VCO).
    #[test]
    fn bm1397_pll_esp_miner_full_ranking_g31() {
        // ESP-Miner test_pll.c golden preserved.
        let (s450, d450) = resolve_bm1397_pll(450);
        assert_eq!(
            (d450.fb_div, d450.ref_div, d450.post_div1, d450.post_div2),
            (72, 2, 2, 1)
        );
        assert_eq!(s450.register_value, 0x4048_0221);

        // Across discrete list: strict pd1>pd2, near-target, VCO-aware ranking
        // produces a legal register with PLLEN.
        for &f in bm1397_pll_frequencies() {
            let (s, d) = resolve_bm1397_pll(f);
            assert!(
                d.post_div1 > d.post_div2,
                "f={f} pd1={} pd2={}",
                d.post_div1,
                d.post_div2
            );
            assert_eq!(s.register_value >> 30, 1);
            let err = (s.actual_freq_mhz as i32 - i32::from(f)).unsigned_abs();
            assert!(err <= 5, "f={f} actual={} err={err}", s.actual_freq_mhz);
            // VCO millimhz from pure formula.
            let vco = 25.0 * f64::from(d.fb_div) / f64::from(d.ref_div.max(1));
            assert!(vco > 0.0);
        }

        // 400 MHz under ESP full ranking: lower-VCO wins over G5 product-only.
        // (64,2,2,1) VCO=800 vs old (96,1,6,1) VCO=2400 — same exact 400 MHz.
        let (s400, d400) = resolve_bm1397_pll(400);
        assert_eq!(
            (d400.fb_div, d400.ref_div, d400.post_div1, d400.post_div2),
            (64, 2, 2, 1),
            "400 MHz ESP-Miner VCO-prefer golden"
        );
        assert_eq!(s400.register_value, 0x4040_0221);
        assert_eq!(s400.actual_freq_mhz, 400);
        // Encode of old product-only winner is still a valid word, just not selected.
        assert_eq!(bm1397_pll_register_value(96, 1, 6, 1), 0x4060_0161);
    }

    /// G5: BM1397 pure encoder matches bible bit layout + ESP-Miner envelopes.
    #[test]
    fn bm1397_pll_search_encodes_raw_postdiv_and_pllen() {
        let (sol, div) = resolve_bm1397_pll(500);
        assert_eq!(sol.family, PllFamily::Bm1397);
        assert_eq!(sol.register_value >> 30, 1, "PLLEN must be set");
        assert_eq!(
            sol.register_value,
            bm1397_pll_register_value(div.fb_div, div.ref_div, div.post_div1, div.post_div2)
        );
        assert_eq!(bm1397_pll_decode_dividers(sol.register_value), div);
        // G31 / ESP-Miner: postdiv1 > postdiv2 (strict), raw (not −1).
        assert!(div.post_div1 > div.post_div2);
        assert!((1..=7).contains(&div.post_div1));
        assert!((1..=7).contains(&div.post_div2));
        assert!((BM1397_FB_DIV_MIN..=BM1397_FB_DIV_MAX).contains(&div.fb_div));
        // Closest-frequency within a few MHz for common S17 operating points.
        for target in [50u16, 200, 400, 500, 650, 800] {
            let (s, d) = resolve_bm1397_pll(target);
            let err = (s.actual_freq_mhz as i32 - target as i32).unsigned_abs();
            assert!(
                err <= 5,
                "target={target} actual={} err={err} reg=0x{:08X}",
                s.actual_freq_mhz,
                s.register_value
            );
            assert!(
                d.post_div1 > d.post_div2,
                "ESP-Miner strict pd1>pd2 at {target}: pd1={} pd2={}",
                d.post_div1,
                d.post_div2
            );
        }
        // BM1397 frequency program: Divider 0x70 prelude ×2 then PLL0 ×2.
        let ops = plan_frequency_program_ops(AsicProtocolIdentity::Bm1397, 500);
        assert_eq!(ops.len(), 8, "2×(div+delay) + 2×(pll0+delay)");
        assert_eq!(ops, plan_bm1397_frequency_program_ops(sol.register_value));
        match &ops[0] {
            TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value } => {
                assert_eq!(*reg, BM1397_PLL0_DIVIDER_REG);
                assert_eq!(*value, BM1397_PLL0_DIVIDER_PRECONFIG);
            }
            other => panic!("expected PLL0 Divider prelude, got {other:?}"),
        }
        match &ops[4] {
            TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value } => {
                assert_eq!(*reg, PLL0_PARAMETER_REG);
                assert_eq!(*value, sol.register_value);
            }
            other => panic!("expected PLL0 Parameter write, got {other:?}"),
        }
        // Discrete list is non-empty and includes autotuner anchors.
        let freqs = bm1397_pll_frequencies();
        assert!(freqs.contains(&500) && freqs.contains(&650));
        // Driver must thin-wrap pure SSOT (structural pin).
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1397.rs"))
            .expect("bm1397 driver");
        assert!(
            src.contains("resolve_bm1397_pll")
                || src.contains("dcentrald_common::resolve_bm1397_pll"),
            "bm1397 driver must consume pure resolve_bm1397_pll SSOT"
        );
        assert!(
            !src.contains("let target = target_mhz.clamp(50, 800) as f64"),
            "bm1397_pll_calc must not keep a forked float search after pure SSOT"
        );
        // ESP-Miner golden vectors (G5 + G31 full ranking).
        // test_pll.c: 450 MHz → fb=72, ref=2, pd1=2, pd2=1.
        let (s450, d450) = resolve_bm1397_pll(450);
        assert_eq!(
            (d450.fb_div, d450.ref_div, d450.post_div1, d450.post_div2),
            (72, 2, 2, 1),
            "450 MHz ESP-Miner dividers"
        );
        assert_eq!(s450.register_value, 0x4048_0221);
        assert_eq!(s450.actual_freq_mhz, 450);
        assert_eq!(
            bm1397_pll_register_value(96, 1, 6, 1),
            0x4060_0161,
            "encode (96,1,6,1) narrative word"
        );
        // Must not silently reuse BM1398 search envelope (fb 16..=250 + VCO hard filter).
        assert_eq!(BM1397_FB_DIV_MIN, 60);
        assert_eq!(BM1397_FB_DIV_MAX, 200);
        // Per-chip plan uses targeted writes (not broadcast).
        let chip_ops = plan_bm1397_frequency_program_ops_chip(0x04, sol.register_value);
        assert_eq!(chip_ops.len(), 8);
        match &chip_ops[0] {
            TransportOp::SendWriteRegBm1397Plus {
                chip_addr,
                reg,
                value,
            } => {
                assert_eq!(*chip_addr, 0x04);
                assert_eq!(*reg, BM1397_PLL0_DIVIDER_REG);
                assert_eq!(*value, BM1397_PLL0_DIVIDER_PRECONFIG);
            }
            other => panic!("expected per-chip divider write, got {other:?}"),
        }
        // Driver must execute pure plans (G5 R4).
        assert!(
            src.contains("plan_bm1397_frequency_program_ops")
                && src.contains("execute_bm1397_frequency_program_broadcast"),
            "bm1397 init/set_frequency must execute pure frequency program plan"
        );
        assert!(
            src.contains("plan_bm1397_frequency_program_ops_chip")
                || src.contains("execute_bm1397_frequency_program_chip"),
            "bm1397 set_frequency single-chip must execute pure chip plan"
        );
        assert!(
            !src.contains("const PLL0_DIV_PRECONFIG: u32 = 0x0F0F_0F00"),
            "driver must not re-open-code PLL0_DIV_PRECONFIG local (pure SSOT owns value)"
        );
    }

    #[test]
    fn bm1397_pll0_readback_match_and_verify_retry_plan() {
        // G9: pure lock-mask match + ≤3 attempts + PLL0-only rewrite (not full 0x70).
        let (sol, _) = resolve_bm1397_pll(450);
        let programmed = sol.register_value;
        assert_eq!(programmed, 0x4048_0221);

        assert!(bm1397_pll0_readback_matches(programmed, programmed));
        assert!(bm1397_pll0_readback_matches(
            programmed,
            programmed | BM1397_PLL0_LOCK_BIT
        ));
        assert!(!bm1397_pll0_lock_bit_set(programmed));
        assert!(bm1397_pll0_lock_bit_set(programmed | BM1397_PLL0_LOCK_BIT));
        assert!(!bm1397_pll0_readback_matches(programmed, programmed ^ 0x10));
        assert!(!bm1397_pll0_readback_matches(
            programmed,
            (programmed | BM1397_PLL0_LOCK_BIT) ^ 0x1
        ));

        assert_eq!(BM1397_PLL0_VERIFY_MAX_ATTEMPTS, 3);
        assert!(bm1397_pll0_verify_rewrite_admitted(0));
        assert!(bm1397_pll0_verify_rewrite_admitted(1));
        assert!(!bm1397_pll0_verify_rewrite_admitted(2));
        assert!(!bm1397_pll0_verify_rewrite_admitted(3));

        let read_ops = plan_bm1397_pll0_verify_read(0x00);
        assert_eq!(read_ops.len(), 2);
        match &read_ops[0] {
            TransportOp::SendReadRegBm1397Plus { chip_addr, reg } => {
                assert_eq!(*chip_addr, 0x00);
                assert_eq!(*reg, PLL0_PARAMETER_REG);
            }
            other => panic!("expected PLL0 read, got {other:?}"),
        }
        match &read_ops[1] {
            TransportOp::DelayMs { ms } => {
                assert_eq!(*ms, BM1397_PLL0_VERIFY_READ_SETTLE_MS);
                assert_eq!(*ms, 50);
            }
            other => panic!("expected post-read settle, got {other:?}"),
        }

        let rewrite = plan_bm1397_pll0_verify_retry_rewrite(programmed);
        assert_eq!(
            rewrite.len(),
            2,
            "PLL0-only rewrite is write+delay, not full program"
        );
        match &rewrite[0] {
            TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value } => {
                assert_eq!(*reg, PLL0_PARAMETER_REG);
                assert_eq!(*value, programmed);
            }
            other => panic!("expected PLL0 bcast rewrite, got {other:?}"),
        }
        match &rewrite[1] {
            TransportOp::DelayMs { ms } => {
                assert_eq!(*ms, BM1397_PLL0_VERIFY_REWRITE_SETTLE_MS);
                assert_eq!(*ms, 20);
            }
            other => panic!("expected rewrite settle, got {other:?}"),
        }
        // Must not accidentally emit full 0x70 frequency program on retry.
        assert!(
            !rewrite.iter().any(|op| matches!(
                op,
                TransportOp::SendWriteRegBroadcastBm1397Plus {
                    reg: BM1397_PLL0_DIVIDER_REG,
                    ..
                }
            )),
            "verify retry must stay PLL0-only (no Divider 0x70 prelude)"
        );
        assert_ne!(
            rewrite.len(),
            plan_bm1397_frequency_program_ops(programmed).len()
        );

        // Driver structural pin: consume pure match + rewrite plan.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1397.rs"))
            .expect("bm1397 driver");
        assert!(
            src.contains("bm1397_pll0_readback_matches")
                || src.contains("dcentrald_common::bm1397_pll0_readback_matches"),
            "bm1397 init must use pure pll0 readback match SSOT"
        );
        assert!(
            src.contains("plan_bm1397_pll0_verify_retry_rewrite")
                || src.contains("execute_bm1397_pll0_verify_retry_rewrite"),
            "bm1397 init must execute pure PLL0-only verify rewrite plan"
        );
        assert!(
            src.contains("BM1397_PLL0_VERIFY_MAX_ATTEMPTS"),
            "bm1397 init must use pure max-attempt constant (not open-coded 0..3)"
        );
        assert!(
            src.contains("bm1397_pll0_verify_rewrite_admitted"),
            "bm1397 init must use pure rewrite-admitted gate (not open-coded pll_retry < 2)"
        );
        assert!(
            src.contains("plan_bm1397_pll0_verify_read"),
            "bm1397 init must execute pure PLL0 verify read plan"
        );
        assert!(
            !src.contains("const PLL_LOCK_BIT: u32 = 0x8000_0000"),
            "driver must not re-open-code PLL_LOCK_BIT local (pure SSOT owns value)"
        );
    }

    #[test]
    fn bm1398_init_consumes_g9_pll0_verify_ssot_twin() {
        // G10: BM1398 shares BM1397 PLL0 Parameter lock/verify policy (same
        // reg 0x08 layout). Twin wire must consume pure G9 helpers without
        // inventing BM1398-only cadence or re-open-coding lock bit / 0..3.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1398.rs"))
            .expect("bm1398 driver");
        assert!(
            src.contains("bm1397_pll0_readback_matches"),
            "bm1398 init must use pure pll0 readback match SSOT (G9 shared)"
        );
        assert!(
            src.contains("plan_bm1397_pll0_verify_read"),
            "bm1398 init must execute pure PLL0 verify read plan"
        );
        assert!(
            src.contains("plan_bm1397_pll0_verify_retry_rewrite")
                || src.contains("execute_bm1398_pll0_verify_retry_rewrite"),
            "bm1398 init must execute pure PLL0-only verify rewrite plan"
        );
        assert!(
            src.contains("BM1397_PLL0_VERIFY_MAX_ATTEMPTS"),
            "bm1398 init must use pure max-attempt constant (not open-coded 0..3)"
        );
        assert!(
            src.contains("bm1397_pll0_verify_rewrite_admitted"),
            "bm1398 init must use pure rewrite-admitted gate"
        );
        assert!(
            src.contains("BM1397_PLL0_LOCK_BIT"),
            "bm1398 pll_register_to_freq must use pure lock-bit SSOT"
        );
        assert!(
            !src.contains("const PLL_LOCK_BIT: u32 = 0x8000_0000"),
            "bm1398 must not re-open-code PLL_LOCK_BIT local"
        );
        // Must not re-open-code attempt loop bounds or rewrite gate.
        assert!(
            !src.contains("for pll_retry in 0..3u8"),
            "bm1398 must not re-open-code 0..3 verify loop"
        );
        assert!(
            !src.contains("if pll_retry < 2"),
            "bm1398 must not re-open-code rewrite gate pll_retry < 2"
        );
    }

    #[test]
    fn bm1398_init_and_set_frequency_consume_g5_frequency_program_ssot() {
        // G11: BM1398 Step 9 / set_frequency must execute pure G5 frequency
        // program (0x70×2 + PLL0×2 @ 10 ms) — no open-coded PLL0_DIV_PRECONFIG.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1398.rs"))
            .expect("bm1398 driver");
        assert!(
            src.contains("plan_bm1397_frequency_program_ops")
                && src.contains("execute_bm1398_frequency_program_broadcast"),
            "bm1398 init/set_frequency must execute pure frequency program plan"
        );
        assert!(
            src.contains("plan_bm1397_frequency_program_ops_chip")
                || src.contains("execute_bm1398_frequency_program_chip"),
            "bm1398 set_frequency single-chip must execute pure chip plan"
        );
        assert!(
            !src.contains("const PLL0_DIV_PRECONFIG: u32 = 0x0F0F_0F00"),
            "bm1398 must not re-open-code PLL0_DIV_PRECONFIG local (pure SSOT owns value)"
        );
        // Pure plan value still documented as constant identity.
        assert_eq!(BM1397_PLL0_DIVIDER_PRECONFIG, 0x0F0F_0F00);
        assert_eq!(BM1397_PLL_PROGRAM_SPACING_MS, 10);
    }

    #[test]
    fn bm1368_and_bm1366_both_resolve_400mhz_within_tolerance() {
        // Same fb envelope; VCO tie-break differs (1366 prefers lower VCO).
        let a = resolve_pll(PllFamily::Bm1366, 400);
        let b = resolve_pll(PllFamily::Bm1368, 400);
        assert!((a.actual_freq_mhz as i32 - 400).unsigned_abs() <= 2);
        assert!((b.actual_freq_mhz as i32 - 400).unsigned_abs() <= 2);
        // Both produce a non-zero PLL0 encoding with vco scale 0x40 or 0x50.
        for sol in [a, b] {
            let scale = sol.register_value >> 24;
            assert!(scale == 0x40 || scale == 0x50, "scale=0x{scale:02X}");
        }
    }

    #[test]
    fn bm1370_multi_pll_register_map_is_re_confirmed() {
        assert_eq!(BM1370_PLL_REGISTER_ADDRS, [0x08, 0x60, 0x64]);
        assert_eq!(pll_count(PllFamily::Bm1370), 3);
        assert_eq!(admit_pll_register(PllFamily::Bm1370, 0).unwrap(), 0x08);
        assert_eq!(admit_pll_register(PllFamily::Bm1370, 1).unwrap(), 0x60);
        assert_eq!(admit_pll_register(PllFamily::Bm1370, 2).unwrap(), 0x64);
        assert!(matches!(
            admit_pll_register(PllFamily::Bm1370, 3),
            Err(PllPlanError::PllIdOutOfRange {
                pll_id: 3,
                count: 3,
                ..
            })
        ));
        // Single-PLL families refuse pll_id > 0.
        assert!(matches!(
            admit_pll_register(PllFamily::Bm1366, 1),
            Err(PllPlanError::PllIdOutOfRange { .. })
        ));
        assert_eq!(pll_register_addrs(PllFamily::Bm1362), &[0x08]);
    }

    #[test]
    fn plan_pll_id_writes_target_correct_regs() {
        let sol = resolve_pll(PllFamily::Bm1370, 500);
        let p0 = plan_pll_broadcast_write(sol, 0).unwrap();
        let p1 = plan_pll_broadcast_write(sol, 1).unwrap();
        let p2 = plan_pll_broadcast_write(sol, 2).unwrap();
        match (p0, p1, p2) {
            (
                TransportOp::SendWriteRegBroadcastBm1397Plus { reg: r0, value: v0 },
                TransportOp::SendWriteRegBroadcastBm1397Plus { reg: r1, value: v1 },
                TransportOp::SendWriteRegBroadcastBm1397Plus { reg: r2, value: v2 },
            ) => {
                assert_eq!([r0, r1, r2], [0x08, 0x60, 0x64]);
                assert_eq!(v0, sol.register_value);
                assert_eq!(v1, sol.register_value);
                assert_eq!(v2, sol.register_value);
            }
            other => panic!("unexpected ops: {other:?}"),
        }
        // Default frequency program is PLL0-only (not multi-fanout).
        let freq_ops = plan_frequency_program_ops(AsicProtocolIdentity::Bm1370, 500);
        assert_eq!(freq_ops.len(), 1);
        assert!(matches!(
            &freq_ops[0],
            TransportOp::SendWriteRegBroadcastBm1397Plus { reg: 0x08, .. }
        ));
        let all = plan_all_pll_broadcast_writes(sol);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn silicon_profiles_bm1370_pll_addrs_match_common_ssot() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let sp = std::fs::read_to_string(root.join("dcentrald-silicon-profiles/src/bm1370.rs"))
            .expect("bm1370 silicon profile");
        // Must not fork a divergent literal array once common is SSOT.
        assert!(
            sp.contains("dcentrald_common::BM1370_PLL_REGISTER_ADDRS")
                || sp.contains("BM1370_PLL_REGISTER_ADDRS") && sp.contains("[0x08, 0x60, 0x64]"),
            "silicon-profiles bm1370 must pin or re-export common multi-PLL map"
        );
        // Prefer re-export when present.
        if sp.contains("pub use dcentrald_common::BM1370_PLL_REGISTER_ADDRS")
            || sp.contains("pub const BM1370_PLL_REGISTER_ADDRS: [u8; 3] = dcentrald_common::BM1370_PLL_REGISTER_ADDRS")
        {
            // strong SSOT
        } else {
            // still require byte-identical literal until re-export lands
            assert!(
                sp.contains("[0x08, 0x60, 0x64]"),
                "silicon-profiles must keep RE-confirmed multi-PLL bytes"
            );
        }
    }

    /// G42: S17-jig PLL stays distinct from the exact S15/T15 stock contract.
    #[test]
    fn g42_bm1391_s17_jig_pll_matches_jig_without_aliasing_stock() {
        assert_eq!(
            bm1391_pll_pack(120, 1, 1, 1),
            BM1391_S17_JIG_PLL_FALLBACK_200M
        );
        assert_eq!(BM1391_S17_JIG_PLL_FALLBACK_200M, 0xC078_0111);
        assert_eq!(
            crate::bm1391_stock_startup::BM1391_STOCK_PLL_SOLVER_FALLBACK_WORD,
            0x0078_0111
        );
        assert_eq!(
            crate::bm1391_stock_startup::BM1391_STOCK_PLL_SOLVER_FALLBACK_REGISTER_PAYLOAD,
            0x4078_0111
        );
        assert_eq!(
            BM1391_S17_JIG_PLL_FALLBACK_200M & 0x3fff_ffff,
            crate::bm1391_stock_startup::BM1391_STOCK_PLL_SOLVER_FALLBACK_WORD
        );
        assert_ne!(
            BM1391_S17_JIG_PLL_FALLBACK_200M,
            crate::bm1391_stock_startup::BM1391_STOCK_PLL_SOLVER_FALLBACK_REGISTER_PAYLOAD
        );
        assert!(!BM1391_S17_JIG_PLL_AUTHORIZES_S15_T15_PROGRAMMING);

        let f200 = resolve_bm1391_pll(200);
        assert_eq!(f200.pll0_register, 0xC078_0111);
        assert_eq!(f200.external_div, 15);
        assert_eq!(f200.fb_div, 120);
        assert_eq!(f200.actual_freq_mhz, 200);
        // 25*120/(1*1*1)/15 = 200
        assert_eq!(25u32 * 120 / 1 / 15, 200);

        let ops = plan_bm1391_frequency_program_ops(f200.pll0_register, f200.external_div);
        assert_eq!(ops.len(), 6);
        // Order: PLL0, delay, 0x70 (div-1), delay, PLL0, delay — NOT BM1397 0x70×2 first.
        match &ops[0] {
            TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value } => {
                assert_eq!(*reg, 0x08);
                assert_eq!(*value, 0xC078_0111);
            }
            _ => panic!("op0 PLL0"),
        }
        assert!(matches!(ops[1], TransportOp::DelayMs { ms: 10 }));
        match &ops[2] {
            TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value } => {
                assert_eq!(*reg, 0x70);
                assert_eq!(*value, 14); // external_div - 1
            }
            _ => panic!("op2 divider"),
        }
        assert!(matches!(ops[3], TransportOp::DelayMs { ms: 10 }));
        match &ops[4] {
            TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value } => {
                assert_eq!(*reg, 0x08);
                assert_eq!(*value, 0xC078_0111);
            }
            _ => panic!("op4 PLL0 again"),
        }

        // Search finds something near 400 (not forced fallback unless OOR).
        let s400 = bm1391_pll_search(400);
        assert!(s400.is_some(), "400 MHz should admit");
        let s400 = s400.unwrap();
        assert!((s400.actual_freq_mhz as i32 - 400).unsigned_abs() <= 2);

        // Protocol map still refuse (fail-closed production).
        assert!(pll_family_for_protocol(AsicProtocolIdentity::Bm1391).is_none());

        // ChipDriver must thin-wrap pure (not open-coded freq/25 clamp).
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let drv = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1391.rs"))
            .expect("bm1391");
        assert!(
            drv.contains("resolve_bm1391_pll") && !drv.contains(".clamp(40.0, 240.0)"),
            "BM1391 pll_params must thin-wrap pure resolve_bm1391_pll"
        );
        assert!(
            !drv.contains("0xC008_0111") || drv.contains("resolve_bm1391_pll"),
            "must not claim false 200MHz fbdiv=8 encoding"
        );
    }

    /// serial_mining must call pure resolve_pll (thin wrappers), not re-open
    /// crystal-25 brute-force or BM1362 tables.
    #[test]
    fn serial_mining_wires_pure_pll_resolve() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/serial_mining.rs"))
            .expect("serial_mining");
        assert!(
            src.contains("dcentrald_common::resolve_pll")
                || src.contains("resolve_pll(dcentrald_common::PllFamily"),
            "serial_mining must call pure resolve_pll"
        );
        assert!(
            src.contains("PllFamily::Bm1362")
                && src.contains("PllFamily::Bm1366")
                && src.contains("PllFamily::Bm1368")
                && src.contains("PllFamily::Bm1370"),
            "all four pure PLL families must be named from serial_mining wrappers"
        );
        assert!(
            !src.contains("const BM1362_PLL_TABLE"),
            "BM1362 PLL table must live in dcentrald-common::pll_model, not serial_mining"
        );
        assert!(
            !src.contains("for fb_div in BM1368_FB_DIV_MIN"),
            "BM1368 crystal search must not remain open-coded in serial_mining"
        );
        // Core-reset / per-chip walks use pure linear addresses.
        assert!(
            src.contains("linear_chip_addresses"),
            "serial_mining must use linear_chip_addresses for per-chip walks"
        );
    }
}
