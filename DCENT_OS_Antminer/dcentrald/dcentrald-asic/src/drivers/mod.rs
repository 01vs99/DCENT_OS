//! ASIC chip driver registry and ChipDriver trait.
//!
//! The ChipDriver trait is the central abstraction that makes Universal Hash
//! Board Compatibility possible. Each ASIC chip family implements this trait
//! with its specific initialization sequence, register values, job format,
//! and nonce decoding.
//!
//! The ChipRegistry maps chip IDs to driver instances:
//!   0x1387 -> BM1387 (S9)
//!   0x1397 -> BM1397 (S17/T17)
//!   0x1398 -> BM1398 (S19/S19j)
//!   0x1362 -> BM1362 (S19j Pro)
//!   0x1366 -> BM1366 (S19XP)
//!   0x1368 -> BM1368 (S21)
//!   0x1370 -> BM1370 (S21 Pro)
//!   0x1373 -> BM1373 (S23) [SCAFFOLD — pre-hardware]
//!   0x1485 -> BM1485 (L3 / L3+ / L3++ Scrypt) [SCAFFOLD — refuses to
//!     energize. ⚠ SYNTHETIC key: real BM1485 silicon has no readable
//!     CHIP_ID (`bm1485::CHIP_ID_IS_SILICON_READABLE == false`), so this id
//!     can never arrive from a live enumeration.]
//!   0x1489 -> BM1489 (L7 / L9 Scrypt) [SCAFFOLD — simulator only,
//!     wave-7 W7-F. AML S11board byte-identical with S19j Pro/S21 per
//!      §1.1.]
//!
//! ## `cores_per_chip` vs `nonce_attribution_cores` (W6.8, 2026-05-07)
//!
//! `MinerProfile` carries TWO core-count fields and they are *not*
//! interchangeable:
//!
//! - **`cores_per_chip`** — the driver-facing "engine count". Mirrors what
//!   `ChipDriver::cores_per_chip()` returns. Used by chip-init code that
//!   must address each big SHA-256 engine (e.g. BM1387 open-core dummy
//!   work dispatch).
//! - **`nonce_attribution_cores`** — the count of distinct nonce slots the
//!   FPGA can attribute back to a chip. Used by all hashrate / nonces-per-
//!   second math (`MinerProfile::expected_nps`,
//!   `dcentrald_autotuner::chip_geometry::expected_nps_for_chip`,
//!   chip-health expected-NPS gating, autotuner binary-search nonce
//!   thresholds).
//!
//! For most chip families the two values are identical (BM1387=114,
//! BM1366=894, BM1368=1280). **BM1362 is the exception**:
//! `cores_per_chip = 4` big engines vs a much larger slot count. Mixing
//! the two breaks hashrate prediction by an order of magnitude on BM1362
//! and by 30% on BM1368 (the legacy autotuner constant of 894 was wrong
//! for BM1368).
//!
//! ## SG-1 corrected slot counts (rank 24, 2026-08-02 hardware-enablement queue)
//!
//! Two `nonce_attribution_cores` rows are internally inconsistent with the
//! same profile's own `ghs_per_mhz` (identity: `slots ≈ ghs_per_mhz ×
//! 1000`, see `expected_nps`):
//!
//! - **BM1362**: declared 894, our own `ghs_per_mhz = 0.550` implies ~550.
//!   Corrected value **514** (7.0% from our own implied value, inside the
//!   rank-3 gate's 10% bar; 894 is 38.5% off and over-predicts, so a
//!   healthy chain ratios ~0.615 < `min_hashrate_ratio` 0.70 → permanent
//!   `step_down_freq` throttling of healthy S19j Pro silicon).
//! - **BM1370**: declared 1280 (copied from BM1368, never measured), our
//!   own `ghs_per_mhz = 2.286` implies ~2286. Corrected value **2040**,
//!   independently held in OUR OWN live-mining ESP tree (Bitaxe Gamma
//!   BM1370: `dcentos-esp/dcentaxe/src/{api.rs:992, capabilities.rs:237,
//!   main.rs:853}`). 2040 is 12.06% from the implied 2286 — outside the
//!   10% bar — because 2286 stands on the PLACEHOLDER 525 MHz spec
//!   frequency; the residual is pinned, not hidden, in
//!   `tests/profile_core_ghs_consistency_gate.rs`.
//!
//! The corrected values ship behind the **default-OFF** env flag
//! [`SG1_CORRECTED_NONCE_CORES_ENV`]; with the flag unset, every declared
//! field and every prediction is byte-identical to the pre-rank-24 tree.
//! Prediction paths consume [`MinerProfile::nonce_attribution_cores_effective`]
//! (or `expected_nps`, which routes through it); the raw field remains the
//! declared legacy default and is what the rank-3 consistency gate pins.
//!
//! Single source of truth: `dcentrald-autotuner` consumes
//! `MinerProfile::nonce_attribution_cores_effective` directly. Per-chip
//! core constants in `dcentrald-autotuner::chip_geometry` were deleted in
//! W6.8 and the offline CI gate `chip_geometry_drift_check` rejects their
//! reintroduction.

pub mod bm1362;
pub mod bm1366;
pub mod bm1368;
pub mod bm1370;
pub mod bm1373;
/// BM1385 (Antminer S7 — 28 nm, pre-S9 generation) jig-verified scaffold.
/// Fail-closed: no live S7 on the fleet. Carries the byte-extracted 124-entry
/// `freq_pll_1385[]` table + Gen-1 FIL protocol facts. See module docs.
pub mod bm1385;
pub mod bm1387;
pub mod bm1391;
pub mod bm1393;
pub mod bm1396;
pub mod bm1397;
pub mod bm1398;
pub mod bm139x;
/// BM1485 (L3 / L3+ / L3++ Scrypt) — Scaffold, refuses to energize. Keyed on a
/// SYNTHETIC id because the chip has no readable CHIP_ID
/// (`bm1485::CHIP_ID_IS_SILICON_READABLE == false`). Carries the primary
/// citation for the register map `bm1489.rs` inherits, plus the fail-closed
/// encoding of the unresolved operational baud.
pub mod bm1485;
pub mod bm1489;
/// BM1491 (L9 — CVCtrl/CV183x variant, Scrypt) — Scaffold, refuses to energize.
/// DISTINCT chip-id `0x1491` from bm1489's `0x1489` (two L9 control-board variants).
/// Carries the byte-exact RE-recovered chain stride (2) and operational baud
/// (1,562,500) from the un-obfuscated CVCtrl `godminer`; baud stays bench-gated.
pub mod bm1491;
/// ScryptL7 (L7 / BM1489 Litecoin Scrypt) — DCENT_OS's first non-SHA256 chip
/// driver. Default-OFF: only compiled under the `scrypt-l7` Cargo feature so
/// production SHA256 builds are byte-unchanged. Pins the W3-A RE facts and
/// SUPERSEDES the older `bm1489.rs` scaffold for chip-id 0x1489 in the scaffold
/// registry when the feature is enabled. KICKOFF — chain-FIFO transport deferred.
#[cfg(feature = "scrypt-l7")]
pub mod scrypt_l7;

use std::collections::HashMap;

use crate::pic::PicController;
use crate::Result;
use dcentrald_hal::fpga_chain::FpgaChain;

/// Lab-only environment flag for registering simulator/pre-hardware ASIC drivers.
pub const ALLOW_SCAFFOLD_ASIC_DRIVERS_ENV: &str = "DCENT_ALLOW_SCAFFOLD_ASIC_DRIVERS";

/// Default-OFF opt-in for the SG-1 corrected `nonce_attribution_cores`
/// values (rank 24, 2026-08-02 hardware-enablement queue). Set to `1` to
/// make hashrate-prediction paths use the corrected slot counts from
/// [`sg1_corrected_nonce_attribution_cores`] (BM1362 894→514, BM1370
/// 1280→2040). Unset (the default), runtime behaviour is byte-identical
/// to the pre-rank-24 tree. See the module docs §"SG-1 corrected slot
/// counts" for the full derivation from our own `ghs_per_mhz`.
pub const SG1_CORRECTED_NONCE_CORES_ENV: &str = "DCENT_SG1_CORRECTED_NONCE_CORES";

/// SG-1 (rank 24) corrected nonce-attribution slot counts, as pure data.
///
/// Every value here must trace to evidence:
///
/// - `0x1362` (BM1362 / S19j Pro) → **514**. Our own profile's
///   `ghs_per_mhz = 0.550` (104 TH/s / 378 chips / 500 MHz, this file)
///   implies `0.550 × 1000 ≈ 550` slots by the `expected_nps` identity;
///   514 sits 7.0% from that — inside the rank-3 gate's 10% bar — while
///   the legacy 894 sits 38.5% off and would imply a physically
///   impossible ~169 TH/s S19j Pro (894 × 500 MHz × 378 chips). ePIC's
///   transcription supplied the 514 candidate; OUR ghs_per_mhz is the
///   authority that admits it.
/// - `0x1370` (BM1370 / S21 Pro) → **2040**. Our own live-mining ESP tree
///   (Bitaxe Gamma, BM1370) declares 2040 small cores in five places
///   (`dcentos-esp/dcentaxe/src/api.rs:992`, `capabilities.rs:237`,
///   `cgminer_tcp.rs:641`, `main.rs:853`, `derived_metrics.rs:123-124`);
///   ePIC corroborates. Our profile's `ghs_per_mhz = 2.286` implies
///   ~2286 — a 12.06% residual vs 2040 that is attributable to the
///   PLACEHOLDER 525 MHz spec frequency in that derivation and is pinned
///   (not hidden) by `tests/profile_core_ghs_consistency_gate.rs`. The
///   legacy 1280 was copied from BM1368 ("same geometry" — asserted,
///   never measured) and under-predicts by 44%, masking degradation.
///
/// Chips NOT listed here have no SG-1 correction: their declared
/// `nonce_attribution_cores` either passes the rank-3 consistency gate
/// (BM1387, BM1366, BM1368) or is a pinned allowlisted divergence whose
/// resolution is owned elsewhere (BM1397/BM1398 — see the gate test).
pub const fn sg1_corrected_nonce_attribution_cores(chip_id: u16) -> Option<u32> {
    match chip_id {
        0x1362 => Some(514),
        0x1370 => Some(2040),
        _ => None,
    }
}

/// True when the operator opted into the SG-1 corrected slot counts.
/// Mirrors the `== "1"` parse of [`ALLOW_SCAFFOLD_ASIC_DRIVERS_ENV`].
pub fn sg1_corrected_nonce_cores_enabled() -> bool {
    dcentrald_common::lab_env::var(SG1_CORRECTED_NONCE_CORES_ENV)
        .map(|value| value == "1")
        .unwrap_or(false)
}

/// Chip ID (`0x1390`) for a genuinely RE-pending future Bitmain SHA-256
/// die. It must not silently map to any production driver until the
/// register/protocol evidence is pinned.
///
/// NOTE: this sentinel is **not** the Antminer T21 die. T21 carries
/// **BM1368** (chip ID `0x1368`, DRIVEN on the fleet S21 `a lab unit`) — see
///
/// (PR-055 / R11-15) for the 10-source corpus resolution. An earlier
/// "BM1390/T21" label on this constant was a stray T21↔BM1390
/// mis-attribution; it is regression-pinned out by the
/// `pr055_t21_asic_identity` test below.
pub const BM1390_RE_PENDING_CHIP_ID: u16 = 0x1390;

pub const fn is_scaffold_driver_chip(chip_id: u16) -> bool {
    // BM1373/S23 is dual-keyed under BOTH its canonical id (0x1373) and the id
    // real silicon reports on enumeration (0x1372) — operator decision
    // 2026-07-08 to key both, fail-closed + double-env-gated, until a live S23
    // confirms which is real. Both must classify as scaffold so the
    // `chip_detection_fails_closed` no-profile assertion correctly skips both.
    chip_id == bm1373::CHIP_ID
        || chip_id == bm1373::ENUM_CHIP_ID
        || chip_id == bm1489::CHIP_ID
        // BM1491 = the L9-CVCtrl (CV183x) variant; distinct id 0x1491 from the
        // 0x1489 AML L9. Real enumerable id (godminer `machine_runtime_ctrl_ltc_1491`),
        // registered scaffold + fail-closed until a live L9-CVCtrl reconciles the
        // 0x1489-vs-0x1491 identity split.
        || chip_id == bm1491::CHIP_ID
        || chip_id == bm1391::CHIP_ID
        || chip_id == bm1393::CHIP_ID
        // BM1485 (L3/L3+/L3++). Note this key is SYNTHETIC — real BM1485
        // silicon never reports it — so no live enumeration can reach this
        // branch today. It is registered so the scaffold is reachable for
        // offline/simulator work and so the fail-closed assertions cover it.
        || chip_id == bm1485::CHIP_ID
}

pub const fn is_re_pending_chip(chip_id: u16) -> bool {
    chip_id == BM1390_RE_PENDING_CHIP_ID
}

pub fn scaffold_asic_driver_override_enabled() -> bool {
    dcentrald_common::lab_env::var(ALLOW_SCAFFOLD_ASIC_DRIVERS_ENV)
        .map(|value| value == "1")
        .unwrap_or(false)
}

/// SECOND, mandatory confirmation gate for the simulator/pre-hardware scaffold
/// ASIC drivers (BM1373 / BM1489) — W22, parity matrix #9 ("scaffold confirmation
/// gate for live hardware").
///
/// Defense-in-depth: even with [`ALLOW_SCAFFOLD_ASIC_DRIVERS_ENV`] set, the
/// operator must ALSO explicitly acknowledge that these drivers emit
/// projected/synthetic values — they do NOT perform real mining and must never
/// be trusted to drive production hardware. Requiring two independent env vars
/// means a single stray/inherited `DCENT_ALLOW_SCAFFOLD_ASIC_DRIVERS=1` can no
/// longer silently load a stub driver onto a live miner.
pub const SCAFFOLD_STUB_ACK_ENV: &str = "DCENT_CONFIRM_SCAFFOLD_DRIVERS_ARE_SIMULATOR_STUBS";

/// Whether the operator has explicitly acknowledged the scaffold/simulator stub
/// behavior via [`SCAFFOLD_STUB_ACK_ENV`]. See that constant for the rationale.
pub fn scaffold_stub_behavior_acknowledged() -> bool {
    dcentrald_common::lab_env::var(SCAFFOLD_STUB_ACK_ENV)
        .map(|value| value == "1")
        .unwrap_or(false)
}

/// Pure two-gate policy decision for registering scaffold/simulator ASIC
/// drivers: BOTH the lab override AND the explicit stub-behavior acknowledgment
/// must be present. Split out as a pure `const fn` so the policy is
/// host-testable without mutating process env.
pub const fn should_register_scaffold_drivers(allow_override: bool, stub_ack: bool) -> bool {
    allow_override && stub_ack
}

// ---------------------------------------------------------------------------
// Voltage controller type (PIC vs dsPIC)
// ---------------------------------------------------------------------------

/// Type of voltage controller on the hash board.
///
/// S9 uses PIC16F1704 (8-bit microcontroller, 8-bit DAC values, ~8-9.4V range).
/// S17/S19 use dsPIC33EP16GS202 (16-bit DSP, millivolt precision, ~12-15V range).
/// S21/S21 Pro use TAS5782M audio DACs (NoPic model, no I2C microcontroller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PicType {
    /// PIC16F1704 — S9 hash boards. I2C addresses: 0x55, 0x56, 0x57.
    /// 8-bit DAC voltage control, ~1 minute (stock) or ~10s (BraiinsOS) watchdog.
    Pic16F1704,
    /// dsPIC33EP16GS202 — S17/S19 hash boards. I2C addresses: 0x88, 0x89, 0xB9, 0xFE.
    /// Framed protocol with checksum, millivolt precision, LM75A temp passthrough.
    DsPic33EP,
    /// No PIC microcontroller — S21/S21 Pro hash boards.
    /// TAS5782M audio DACs repurposed as voltage regulators (I2S/I2C).
    NoPic,
}

// ---------------------------------------------------------------------------
// Miner profile — model-specific hardware constants
// ---------------------------------------------------------------------------

/// Encapsulates all hardware constants for a specific miner model.
///
/// When dcentrald detects the ASIC chip type via ChipID enumeration, it looks
/// up the corresponding MinerProfile to get the correct PIC addresses, chain
/// IDs, voltage range, frequency limits, and power model parameters.
///
/// This replaces the hardcoded S9 constants (PIC_ADDRS, CHAIN_IDS, chip_count)
/// that were previously scattered throughout daemon.rs.
#[derive(Debug, Clone)]
pub struct MinerProfile {
    /// Human-readable model name (e.g., "Antminer S9").
    pub name: &'static str,
    /// ASIC chip ID (e.g., 0x1387 for BM1387).
    pub chip_id: u16,
    /// Expected number of chips per chain (e.g., 63 for S9).
    /// Used as a fallback during passthrough mode when enumeration is skipped.
    pub chips_per_chain: u8,
    /// Number of hash board chains (typically 3).
    pub chain_count: u8,
    /// FPGA chain IDs (connector numbering). S9 = [6, 7, 8].
    pub chain_ids: &'static [u8],
    /// PIC I2C addresses, one per chain. S9 = [0x55, 0x56, 0x57].
    /// For dsPIC models these are the probed addresses (0x88, 0x89, etc.).
    /// For NoPic models this is empty.
    pub pic_addrs: &'static [u8],
    /// Type of voltage controller on the hash board.
    pub pic_type: PicType,
    /// Default mining frequency in MHz (safe operating point).
    pub default_freq_mhz: u16,
    /// Default chain voltage in millivolts.
    pub default_voltage_mv: u16,
    /// Maximum safe frequency in MHz.
    pub max_freq_mhz: u16,
    /// Number of SHA-256 cores per chip — driver-facing "engine count".
    ///
    /// This is the same value the chip's `ChipDriver::cores_per_chip()`
    /// trait method returns. For some chip families (notably BM1362) this
    /// is the count of *big* SHA-256 engines, not the count of distinct
    /// nonce-attribution slots. Use `nonce_attribution_cores` for hashrate
    /// / nonces-per-second math; use `cores_per_chip` only when you really
    /// want the driver-level engine count (e.g. open-core dummy work
    /// dispatch on BM1387).
    pub cores_per_chip: u32,
    /// Effective core count for nonce-rate / hashrate prediction.
    ///
    /// W6.8 (DCENT_Perf, 2026-05-07): BM1362 reports `cores_per_chip = 4`
    /// (big SHA-256 engines), but each big engine contains ~894 nonce
    /// attribution slots that the FPGA observes as distinct nonces. The
    /// autotuner predicts hashrate from
    ///   `freq_mhz * nonce_attribution_cores * 1e6 / (difficulty * 2^32)`
    /// so it must use the nonce-attribution count, not the big-engine
    /// count. For chips where the two values are identical (BM1387, BM1366,
    /// BM1368, BM1370, BM1373) this is the same number as `cores_per_chip`.
    /// Single source of truth for autotuner geometry — replaces the legacy
    /// `dcentrald_autotuner::chip_geometry::*_CORES` constants that drifted
    /// 30% out of sync with `cores_per_chip` on BM1368 (894 vs 1280).
    pub nonce_attribution_cores: u32,
    /// Hardware difficulty implied by the platform TicketMask/work format.
    ///
    /// BM1387/BM139x-style paths currently use 256. BM1368 serial-mining uses 128.
    pub hardware_difficulty: u32,
    /// CMOS power coefficient: P_chip = c_eff * V^2 * f_mhz.
    /// Calibrated from known operating points for each chip type.
    pub c_eff: f64,
    /// Static power per chain in watts (board overhead, fans, etc.).
    pub static_per_chain_w: f64,
    /// Control board overhead in watts.
    pub control_board_w: f64,
    /// UIO device base numbers for each chain (4 UIO devices per chain).
    /// S9: [1, 5, 9]. Only applicable to Zynq platforms.
    pub uio_bases: &'static [u8],
    /// I2C bus number for PIC controllers (S9 = bus 0).
    pub i2c_bus: u8,
    /// GPIO pin base for hash board plug detect (S9 = 902).
    pub plugo_gpio_base: u32,
    /// GPIO pin base for hash board enable (S9 = 893).
    pub enable_gpio_base: u32,
    /// Hashrate per chip in GH/s per MHz of clock frequency.
    /// Used by autotuner for hashrate estimation.
    pub ghs_per_mhz: f64,
}

impl MinerProfile {
    /// Get the profile for a given ASIC chip ID.
    ///
    /// Returns None if the chip ID is unknown.
    pub fn for_chip(chip_id: u16) -> Option<&'static MinerProfile> {
        // BM1373/S23 dual-key: real silicon enumerates as 0x1372 but DCENT keys
        // the scaffold profile on 0x1373. Operator decision 2026-07-08 — resolve
        // BOTH ids to the S23 profile (aliased, not duplicated) until a live S23
        // confirms which is real. The profile's `chip_id` field stays 0x1373.
        let lookup = if chip_id == bm1373::ENUM_CHIP_ID {
            bm1373::CHIP_ID
        } else {
            chip_id
        };
        MINER_PROFILES.iter().find(|p| p.chip_id == lookup)
    }

    /// Get the PLL frequency table for a given ASIC chip ID.
    ///
    /// Returns the chip-specific discrete frequency table for autotuner
    /// binary search. **Unknown chip IDs return an empty slice** — never a
    /// silent BM1387 fallback (decade backlog P1-4). Programming the wrong
    /// silicon's PLL table is worse than refusing to tune.
    ///
    /// Prefer [`Self::try_pll_frequencies_for_chip`] when the caller must
    /// distinguish "known empty scaffold" from "unknown chip".
    pub fn pll_frequencies_for_chip(chip_id: u16) -> &'static [u16] {
        Self::try_pll_frequencies_for_chip(chip_id).unwrap_or(&[])
    }

    /// PLL table for a known chip ID, or `None` if the chip is not registered.
    ///
    /// Fail-closed: unknown IDs do **not** inherit BM1387 / S9 frequencies.
    pub fn try_pll_frequencies_for_chip(chip_id: u16) -> Option<&'static [u16]> {
        match chip_id {
            0x1387 => Some(bm1387::pll_frequencies()),
            0x1397 => Some(bm1397::pll_frequencies()),
            0x1398 => Some(bm1398::pll_frequencies()),
            0x1362 => Some(bm1362::pll_frequencies()),
            0x1366 => Some(bm1366::pll_frequencies()),
            0x1368 => Some(bm1368::pll_frequencies()),
            0x1370 => Some(bm1370::pll_frequencies()),
            // BM1373/S23 dual-key: 0x1372 (enumerated) + 0x1373 (canonical) —
            // operator decision 2026-07-08 (see `is_scaffold_driver_chip`).
            0x1372 | 0x1373 => Some(bm1373::pll_frequencies()),
            0x1489 => Some(bm1489::pll_frequencies()),
            _ => None,
        }
    }

    /// True when a discrete PLL table is registered for this chip ID.
    pub fn has_pll_table(chip_id: u16) -> bool {
        Self::try_pll_frequencies_for_chip(chip_id).is_some_and(|t| !t.is_empty())
    }

    /// Snap `target_mhz` down to the nearest registered PLL entry (inclusive floor).
    ///
    /// Returns `None` when the table is empty (unknown chip — P1-4 fail-closed).
    /// Never panics on an empty table. Callers that need a numeric fallback must
    /// pass a known floor explicitly rather than indexing `pll[0]`.
    pub fn snap_pll_floor(pll_table: &[u16], target_mhz: u16) -> Option<u16> {
        if pll_table.is_empty() {
            return None;
        }
        pll_table
            .iter()
            .rev()
            .find(|&&f| f <= target_mhz)
            .copied()
            .or_else(|| pll_table.first().copied())
    }

    /// Next PLL entry strictly above `current_mhz` (boost / step-up).
    ///
    /// Returns `None` when the table is empty or `current_mhz` is already at
    /// or above the highest table entry.
    pub fn snap_pll_next_above(pll_table: &[u16], current_mhz: u16) -> Option<u16> {
        pll_table.iter().copied().find(|&f| f > current_mhz)
    }

    /// Estimated hashrate for a single chip at a given frequency (GH/s).
    pub fn chip_hashrate_ghs(&self, freq_mhz: u16) -> f64 {
        freq_mhz as f64 * self.ghs_per_mhz
    }

    /// Estimated hashrate for one full chain at a given frequency (GH/s).
    pub fn chain_hashrate_ghs(&self, freq_mhz: u16) -> f64 {
        self.chips_per_chain as f64 * self.chip_hashrate_ghs(freq_mhz)
    }

    /// Estimated total hashrate for all chains at a given frequency (TH/s).
    pub fn total_hashrate_ths(&self, freq_mhz: u16) -> f64 {
        self.chain_count as f64 * self.chain_hashrate_ghs(freq_mhz) / 1000.0
    }

    /// Nominal device hashrate in GH/s for SV2 OpenStandardMiningChannel /
    /// pool difficulty seeding (decade backlog P2-9).
    ///
    /// Prefer this over a hard-coded S9 `13500.0` when a [`MinerProfile`] is
    /// known. Returns `None` for unknown chips or non-positive geometry so
    /// callers refuse to advertise a fabricated multi-TH rate.
    ///
    /// Pure math SSOT: [`dcentrald_common::nominal_hashrate_ghs_from_geometry`]
    /// with profile `chain_count × chips_per_chain`. Live enum should prefer
    /// that helper with **responding** chip totals when partial boards exist.
    pub fn nominal_hashrate_ghs(&self, freq_mhz: u16) -> Option<f32> {
        let total = dcentrald_common::total_chips_from_profile_geometry(
            self.chain_count,
            self.chips_per_chain,
        )?;
        dcentrald_common::nominal_hashrate_ghs_from_geometry(total, freq_mhz, self.ghs_per_mhz)
    }

    /// Look up profile + nominal GH/s for a chip ID at `freq_mhz`.
    pub fn nominal_hashrate_ghs_for_chip(chip_id: u16, freq_mhz: u16) -> Option<f32> {
        Self::for_chip(chip_id)?.nominal_hashrate_ghs(freq_mhz)
    }

    /// Nonce-attribution slot count with an explicit SG-1 correction choice.
    ///
    /// Pure function for tests and callers that already resolved the flag:
    /// `corrected = true` returns the rank-24 corrected value from
    /// [`sg1_corrected_nonce_attribution_cores`] when one exists for this
    /// chip, otherwise (and always with `corrected = false`) the declared
    /// `nonce_attribution_cores` field.
    pub fn nonce_attribution_cores_with_correction(&self, corrected: bool) -> u32 {
        if corrected {
            if let Some(cores) = sg1_corrected_nonce_attribution_cores(self.chip_id) {
                return cores;
            }
        }
        self.nonce_attribution_cores
    }

    /// Nonce-attribution slot count honouring the default-OFF
    /// [`SG1_CORRECTED_NONCE_CORES_ENV`] flag. This is what every
    /// hashrate/nonces-per-second prediction path must consume; with the
    /// flag unset it is exactly the declared `nonce_attribution_cores`.
    pub fn nonce_attribution_cores_effective(&self) -> u32 {
        self.nonce_attribution_cores_with_correction(sg1_corrected_nonce_cores_enabled())
    }

    /// Expected nonces per second per chip at a given frequency and difficulty.
    ///
    /// Uses the effective nonce-attribution slot count (the count of distinct
    /// nonce-attribution slots, honouring the default-OFF SG-1 correction
    /// flag), NOT the driver-facing `cores_per_chip`. For BM1362 these
    /// differ: `cores_per_chip = 4` big engines vs 894 declared (514
    /// SG-1-corrected) slots. Autotuner hashrate prediction depends on the
    /// slot count.
    pub fn expected_nps(&self, freq_mhz: u16, difficulty: u32) -> f64 {
        self.expected_nps_with_correction(freq_mhz, difficulty, sg1_corrected_nonce_cores_enabled())
    }

    /// [`Self::expected_nps`] with an explicit SG-1 correction choice —
    /// the pure form used by tests so they need not mutate the process
    /// environment. `expected_nps` delegates here with the env-resolved
    /// flag, so this IS the production formula.
    pub fn expected_nps_with_correction(
        &self,
        freq_mhz: u16,
        difficulty: u32,
        corrected: bool,
    ) -> f64 {
        let diff = if difficulty == 0 {
            self.hardware_difficulty
        } else {
            difficulty
        };
        (freq_mhz as f64 * self.nonce_attribution_cores_with_correction(corrected) as f64 * 1e6)
            / (diff as f64 * 4.294e9)
    }

    /// Fail-closed nonce-attribution slots for a chip ID.
    ///
    /// Unknown IDs return `None`. Never a silent BM1387 114-core default.
    pub fn try_nonce_attribution_cores_for_chip(chip_id: u16) -> Option<u32> {
        Self::for_chip(chip_id).map(|profile| profile.nonce_attribution_cores_effective())
    }

    /// Fail-closed GH/s per MHz for a chip ID. Unknown IDs return `None`.
    pub fn try_ghs_per_mhz_for_chip(chip_id: u16) -> Option<f64> {
        Self::for_chip(chip_id).map(|profile| profile.ghs_per_mhz)
    }

    /// Fail-closed expected nonces/sec for a chip ID.
    ///
    /// Unknown IDs return `None` instead of inventing BM1387 114-core NPS.
    pub fn try_expected_nps_for_chip(chip_id: u16, freq_mhz: u16, difficulty: u32) -> Option<f64> {
        Self::for_chip(chip_id).map(|profile| profile.expected_nps(freq_mhz, difficulty))
    }
}

// ---------------------------------------------------------------------------
// Static profile table — all known miner models
// ---------------------------------------------------------------------------

/// All known miner profiles, indexed by chip ID.
///
/// Hardware constants sourced from:
///   - Live S9 probe data (verified)
///   - BraiinsOS source code (am1-s9, am2-s17)
///   - ASIC Register Bible
///   - AMTC test jig RE (dsPIC33EP confirmed for S17)
///   - ESP-Miner drivers (BM1366/1368/1370)
///   - S19 BraiinsOS probe data
///
/// C_eff values:
///   - BM1387: Calibrated from S9 at 650 MHz, 9.1V, 1350W total (measured).
///   - BM1397: Estimated from S17 spec: ~57 J/TH, ~80 TH/s, ~4560W.
///   - BM1398: Estimated from S19 spec: ~34.5 J/TH, ~95 TH/s, ~3278W.
///   - BM1362: Estimated from S19j Pro reference: ~29.5 J/TH, ~104 TH/s, ~3068W.
///   - BM1366: Estimated from S19 XP spec: ~21.5 J/TH, ~140 TH/s, ~3010W.
///   - BM1368: Estimated from S21 spec: ~17.5 J/TH, ~200 TH/s, ~3500W.
///   - BM1370: Estimated from S21 Pro spec: ~15 J/TH, ~234 TH/s, ~3510W.
pub static MINER_PROFILES: &[MinerProfile] = &[
    // BM1387 — Antminer S9 (verified from live hardware)
    MinerProfile {
        name: "Antminer S9",
        chip_id: 0x1387,
        chips_per_chain: 63,
        chain_count: 3,
        chain_ids: &[6, 7, 8],
        pic_addrs: &[0x55, 0x56, 0x57],
        pic_type: PicType::Pic16F1704,
        default_freq_mhz: 650,
        default_voltage_mv: 8600,
        max_freq_mhz: 900,
        cores_per_chip: 114,
        // BM1387: big engines == nonce-attribution slots == 114.
        nonce_attribution_cores: 114,
        hardware_difficulty: 256,
        // C_eff = 6.243 / (9.1^2 * 650) = 0.0001159
        c_eff: 0.000116,
        static_per_chain_w: 50.0,
        control_board_w: 20.0,
        uio_bases: &[1, 5, 9],
        i2c_bus: 0,
        plugo_gpio_base: 902,
        enable_gpio_base: 893,
        // 14 TH/s / 189 chips / 650 MHz
        ghs_per_mhz: 0.114,
    },
    // BM1397 — Antminer S17/T17 (estimated from spec sheets)
    // am2-s17 control board: chains 1-3, UIO bases 0/4/8, fan at uio16
    MinerProfile {
        name: "Antminer S17",
        chip_id: 0x1397,
        chips_per_chain: 48,
        chain_count: 3,
        chain_ids: &[1, 2, 3],
        // dsPIC I2C addresses: 0x20 + board_index (same pattern as S19 Pro)
        pic_addrs: &[0x20, 0x21, 0x22],
        pic_type: PicType::DsPic33EP,
        default_freq_mhz: 500,
        default_voltage_mv: 12000,
        max_freq_mhz: 700,
        cores_per_chip: 672,
        // BM1397: big engines == nonce-attribution slots == 672.
        nonce_attribution_cores: 672,
        hardware_difficulty: 256,
        // S17 spec: ~57 J/TH, 80 TH/s total, ~4560W, 144 chips
        // P_dynamic = 4560 - 3*50 - 20 = 4390W, P/chip = 30.49W
        // C_eff = 30.49 / (12.0^2 * 500) = 0.000423
        c_eff: 0.000423,
        static_per_chain_w: 50.0,
        control_board_w: 20.0,
        uio_bases: &[0, 4, 8],
        i2c_bus: 0,
        plugo_gpio_base: 902,
        enable_gpio_base: 897,
        // 80 TH/s / 144 chips / 500 MHz
        ghs_per_mhz: 1.111,
    },
    // BM1398 — Antminer S19/S19 Pro (from live S19 Pro probe at 203.0.113.129)
    // am2-s17 control board: chains 1-3, UIO bases 0/4/8, fan at uio16
    // Live probe: 114 chips/chain, freq 280-285 MHz, voltage 11.95V
    // dsPIC I2C: 0x20/0x21/0x22 (7-bit, confirmed by strace of bosminer)
    MinerProfile {
        name: "Antminer S19 Pro",
        chip_id: 0x1398,
        chips_per_chain: 114,
        chain_count: 3,
        chain_ids: &[1, 2, 3],
        pic_addrs: &[0x20, 0x21, 0x22],
        pic_type: PicType::DsPic33EP,
        default_freq_mhz: 675,
        default_voltage_mv: 13800,
        max_freq_mhz: 850,
        // Stock NBP1901: 156 hash-engine groups × 4 small cores, indexed 0..=623.
        cores_per_chip: 624,
        // EXPERIMENTAL: the inherited 672-slot carrier/work-time assumption has
        // not been proven by accepted shares. Keep it distinct from die geometry.
        nonce_attribution_cores: 672,
        hardware_difficulty: 256,
        // S19 Pro spec: ~29.5 J/TH, 110 TH/s, ~3245W, 342 chips (114*3)
        // P_dynamic = 3245 - 170 = 3075W, P/chip = 8.99W
        // C_eff = 8.99 / (13.8^2 * 675) = 0.0000699
        c_eff: 0.0000699,
        static_per_chain_w: 50.0,
        control_board_w: 20.0,
        uio_bases: &[0, 4, 8],
        i2c_bus: 0,
        plugo_gpio_base: 902,
        enable_gpio_base: 897,
        // 110 TH/s / 342 chips / 675 MHz
        ghs_per_mhz: 0.476,
    },
    // BM1362 — Antminer S19j Pro (AMTC + S19j Pro reference data)
    // am2-s17 control board: chains 1-3, UIO bases 0/4/8, fan at uio16
    //
    // BM1362 is the canonical "split" chip in the W6.8 cores model:
    //   - cores_per_chip = 4 (big SHA-256 engines, what the driver reports
    //     via ChipDriver::cores_per_chip() — used for engine-level
    //     bookkeeping and open-core dispatch).
    //   - nonce_attribution_cores = 894 (distinct nonce slots the FPGA can
    //     attribute back to a chip — same nonce-space partitioning as
    //     BM1366).
    // Hashrate / nonces-per-second math (autotuner, chip-health) MUST use
    // nonce_attribution_cores. Engine-state code MUST use cores_per_chip.
    // See module docs for the contract; the BM1362 driver unit test pins
    // the 4-engine value, and the autotuner W6.8 unit test pins the
    // 894-slot value.
    MinerProfile {
        name: "Antminer S19j Pro",
        chip_id: 0x1362,
        chips_per_chain: 126,
        chain_count: 3,
        chain_ids: &[1, 2, 3],
        pic_addrs: &[0x20, 0x21, 0x22],
        pic_type: PicType::DsPic33EP,
        default_freq_mhz: 500,
        default_voltage_mv: 13700,
        max_freq_mhz: 700,
        cores_per_chip: 4,
        // BM1362: 4 big SHA-256 engines per chip; the FPGA additionally
        // attributes nonces to per-chip slots. The autotuner needs the slot
        // count for hashrate prediction; the driver uses the big-engine
        // count for open-core / engine-state bookkeeping. W6.8
        // (DCENT_Perf, 2026-05-07).
        //
        // ⚠ SG-1 (rank 24, 2026-08-02): 894 appears borrowed from BM1366
        // and is inconsistent with this profile's OWN `ghs_per_mhz = 0.550`
        // a few fields below (implies ~550 slots; 894 is 38.5% off and
        // would mean a ~169 TH/s S19j Pro). The corrected value 514 ships
        // behind the default-OFF `DCENT_SG1_CORRECTED_NONCE_CORES=1` flag —
        // see `sg1_corrected_nonce_attribution_cores`. This declared field
        // stays 894 so flag-off behaviour is byte-identical; it is pinned
        // by `tests/profile_core_ghs_consistency_gate.rs` and the W6.8
        // autotuner pins, all of which must move together when the default
        // eventually flips.
        nonce_attribution_cores: 894,
        hardware_difficulty: 256,
        // S19j Pro reference: ~29.5 J/TH, 104 TH/s, ~3068W, 378 chips.
        // P_dynamic = 3068 - 170 = 2898W, P/chip = 7.67W
        // C_eff = 7.67 / (13.7^2 * 500) = 0.0000817
        c_eff: 0.0000817,
        static_per_chain_w: 50.0,
        control_board_w: 20.0,
        uio_bases: &[0, 4, 8],
        i2c_bus: 0,
        plugo_gpio_base: 902,
        enable_gpio_base: 897,
        // 104 TH/s / 378 chips / 500 MHz
        ghs_per_mhz: 0.550,
    },
    // BM1366 — Antminer S19 XP / S19k Pro (estimated from spec sheets)
    //
    // TD-003 safety: chip ID alone must not imply a dsPIC voltage controller.
    // The Antminer BM1366 entries in the daemon model catalog are NoPic-class
    // (S19 XP / S19k Pro), and any future PIC-bearing BM1366 variant must be
    // selected by an explicit platform/model profile rather than by this generic
    // chip-family fallback.
    MinerProfile {
        name: "Antminer S19 XP",
        chip_id: 0x1366,
        chips_per_chain: 110,
        chain_count: 3,
        chain_ids: &[1, 2, 3],
        pic_addrs: &[],
        pic_type: PicType::NoPic,
        default_freq_mhz: 500,
        default_voltage_mv: 12800,
        max_freq_mhz: 750,
        cores_per_chip: 894,
        // BM1366: big engines == nonce-attribution slots == 894.
        nonce_attribution_cores: 894,
        hardware_difficulty: 256,
        // S19 XP spec: ~21.5 J/TH, 140 TH/s, ~3010W, 330 chips
        // P_dynamic = 3010 - 170 = 2840W, P/chip = 8.61W
        // C_eff = 8.61 / (12.8^2 * 500) = 0.000105
        c_eff: 0.000105,
        static_per_chain_w: 50.0,
        control_board_w: 20.0,
        uio_bases: &[0, 4, 8],
        i2c_bus: 0,
        plugo_gpio_base: 902,
        enable_gpio_base: 897,
        // 140 TH/s / 330 chips / 500 MHz
        ghs_per_mhz: 0.848,
    },
    // BM1368 — Antminer S21 (estimated from spec sheets)
    // NOTE: S21 uses Amlogic A113D, not Zynq. UIO/GPIO/I2C values are placeholders.
    MinerProfile {
        name: "Antminer S21",
        chip_id: 0x1368,
        chips_per_chain: 108,
        chain_count: 3,
        chain_ids: &[1, 2, 3],
        pic_addrs: &[], // NoPic model — TAS5782M DACs
        pic_type: PicType::NoPic,
        default_freq_mhz: 500,
        default_voltage_mv: 12000,
        max_freq_mhz: 700,
        cores_per_chip: 1280, // 80 big x 16 small, confirmed by S21 fixture RE (2026-04-12)
        // BM1368: 80 big × 16 small = 1280; both the driver "engine count"
        // and the FPGA nonce-attribution slot count agree at 1280. The
        // legacy autotuner constant of 894 here was a copy from BM1366 and
        // produced a 30% low hashrate prediction on S21 — fixed in W6.8.
        nonce_attribution_cores: 1280,
        hardware_difficulty: 128,
        // S21 spec: ~17.5 J/TH, 200 TH/s, ~3500W, 324 chips
        // P_dynamic = 3500 - 170 = 3330W, P/chip = 10.28W
        // C_eff = 10.28 / (12.0^2 * 500) = 0.000143
        c_eff: 0.000143,
        static_per_chain_w: 50.0,
        control_board_w: 20.0,
        uio_bases: &[], // Amlogic platform, no UIO
        i2c_bus: 0,
        plugo_gpio_base: 0,  // TBD for Amlogic
        enable_gpio_base: 0, // TBD for Amlogic
        // 200 TH/s / 324 chips / 500 MHz
        ghs_per_mhz: 1.235,
    },
    // BM1370 — Antminer S21 Pro (estimated from spec sheets)
    // NOTE: S21 Pro also uses Amlogic/CVitek. UIO/GPIO/I2C values are placeholders.
    MinerProfile {
        name: "Antminer S21 Pro",
        chip_id: 0x1370,
        chips_per_chain: 65,
        chain_count: 3,
        chain_ids: &[1, 2, 3],
        pic_addrs: &[], // NoPic model
        pic_type: PicType::NoPic,
        default_freq_mhz: 525,
        default_voltage_mv: 12000,
        max_freq_mhz: 750,
        cores_per_chip: 1280,
        // ⚠ SG-1 (2026-08-02 hardware-enablement queue): the 1280 value was
        // COPIED from the BM1368 row ("same geometry" — asserted, never
        // measured on BM1370 silicon). This profile's own `ghs_per_mhz:
        // 2.286` (234 TH/s / 195 chips / 525 MHz spec, a few fields below)
        // implies ~2286 slots (−44% prediction error at 1280). Rank 24
        // shipped the corrected value 2040 — held in OUR OWN live-mining ESP
        // tree (Bitaxe Gamma BM1370, `dcentos-esp/dcentaxe/src/api.rs:992`
        // et al.), ePIC-corroborated — behind the default-OFF
        // `DCENT_SG1_CORRECTED_NONCE_CORES=1` flag; see
        // `sg1_corrected_nonce_attribution_cores` for the 12.06% residual
        // vs the placeholder-frequency-derived 2286. This declared field
        // stays 1280 so flag-off behaviour is byte-identical; pinned
        // byte-exact by `tests/profile_core_ghs_consistency_gate.rs` — DO
        // NOT change it without updating that gate's allowlist in the same
        // commit.
        nonce_attribution_cores: 1280,
        hardware_difficulty: 256,
        // S21 Pro spec: ~15 J/TH, 234 TH/s, ~3510W, 195 chips
        // P_dynamic = 3510 - 170 = 3340W, P/chip = 17.13W
        // C_eff = 17.13 / (12.0^2 * 525) = 0.000227
        c_eff: 0.000227,
        static_per_chain_w: 50.0,
        control_board_w: 20.0,
        uio_bases: &[], // Amlogic/CVitek platform, no UIO
        i2c_bus: 0,
        plugo_gpio_base: 0,  // TBD
        enable_gpio_base: 0, // TBD
        // 234 TH/s / 195 chips / 525 MHz
        ghs_per_mhz: 2.286,
    },
    // BM1373 — Antminer S23 (SCAFFOLD — pre-hardware)
    // Chip designation from internal intel (2026-04-14). Not publicly disclosed by Bitmain.
    // NOTE: Amlogic or successor SoC expected. Core counts are NerdQAxePlus early
    // bring-up RE (128 big / 6860 small); freq/voltage/power stay PROJECTED. ALL
    // values still need live S23 verification. ⚠️ enumeration self-reports 0x1372
    // (bm1373.rs::ENUM_CHIP_ID); operator decision 2026-07-08 keys the scaffold
    // under BOTH 0x1372 and 0x1373 (fail-closed + double-env-gated) pending live
    // S23 confirmation — `for_chip` aliases 0x1372 to this profile.
    MinerProfile {
        name: "Antminer S23",
        chip_id: 0x1373,
        chips_per_chain: 90, // PLACEHOLDER — estimated from 318 TH/s spec
        chain_count: 3,
        chain_ids: &[1, 2, 3],
        pic_addrs: &[], // NoPic model (continuation of BM1368/BM1370 pattern)
        pic_type: PicType::NoPic,
        default_freq_mhz: 550, // PLACEHOLDER — projected from efficiency improvement
        default_voltage_mv: 12000, // PLACEHOLDER
        max_freq_mhz: 800,     // PLACEHOLDER — may be higher with process improvement
        // 128 big cores/chip — NerdQAxePlus BM1373 early bring-up (commit 67dc677a).
        cores_per_chip: 128,
        // 6860 small (nonce-attribution) cores/chip — NerdQAxePlus
        // BM1373_SMALL_CORE_COUNT (corrected from 7000, commit 36124e1e).
        // Needs live S23 verification.
        nonce_attribution_cores: 6860,
        hardware_difficulty: 256, // PLACEHOLDER — could be 128 like BM1368
        // S23 spec: ~11 J/TH, 318 TH/s, ~3498W, ~270 chips (90*3, estimated)
        // P_dynamic = 3498 - 170 = 3328W, P/chip = 12.33W
        // C_eff = 12.33 / (12.0^2 * 550) = 0.000156
        c_eff: 0.000156, // PLACEHOLDER — calibrate from live measurements
        static_per_chain_w: 50.0,
        control_board_w: 20.0,
        uio_bases: &[], // Amlogic platform, no UIO
        i2c_bus: 0,
        plugo_gpio_base: 0,  // TBD
        enable_gpio_base: 0, // TBD
        // 318 TH/s / 270 chips / 550 MHz (all estimated)
        ghs_per_mhz: 2.140, // PLACEHOLDER
    },
    // BM1489 — Antminer L7 / L9 (Litecoin Scrypt) — SCAFFOLD (wave-7 W7-F)
    //
    // L9 = BM1489:199-200
    // (libbitmain `aml/chip.c` BM1489). L7 also = BM1489 per
    //  §2:42.
    //
    // AML S11board byte-identical (SHA256 `bbc25a2137fd…`) across
    // L9 + S19j Pro + S21 v1.2.6-rc5 per
    //  §1.1 → 1:1 GPIO reuse
    // from am3-aml: pwr_en=437, ch{0,1,2}_plug={439-441},
    // ch{0,1,2}_rst={454-456}.
    //
    // Hashrate semantics: For Scrypt chips, ghs_per_mhz is interpreted as
    // MH/s per MHz (NOT GH/s). L7 nameplate = 9.5 GH/s = 9500 MH/s
    // across 480 chips at 425 MHz → 9500 / 480 / 425 = 0.0466 MH/s/MHz
    // per chip. Display layer must check chip-family + scale appropriately.
    //
    // [GAP — wave-8 live verification needed for: register addresses,
    // chip enumeration, voltage controller identity (NoPic vs dsPIC vs
    // PIC16), c_eff calibration, and MH/s vs TH/s display semantics.]
    MinerProfile {
        name: "Antminer L9", // PLACEHOLDER — orchestrator merges with W7-D MinerModel::AntminerL9 enum
        chip_id: 0x1489,
        chips_per_chain: 120,
        chain_count: 4,             // L7/L9 = 4 chains, NOT 3
        chain_ids: &[1, 2, 3, 4],   // PLACEHOLDER — Amlogic platform UART mapping TBD
        pic_addrs: &[], // PLACEHOLDER — voltage controller TBD (likely NoPic on AML S11board)
        pic_type: PicType::NoPic, // PLACEHOLDER — could be DsPic33EP or PIC16; wave-8 verify
        default_freq_mhz: 425, // L7 nameplate per dcentrald-silicon-profiles/src/bm1489.rs:46
        default_voltage_mv: 13_000, // L7 nameplate (chain rail) per same file:46
        max_freq_mhz: 510, // Step +2 in silicon profile bm1489.rs:60
        cores_per_chip: 12, // [GAP] Placeholder; matches BM1485 in chip_init.rs:240
        // BM1489 (Scrypt): PLACEHOLDER — slot count == engine count until
        // live RE confirms otherwise.
        nonce_attribution_cores: 12,
        // Scrypt diff convention same as SHA-256 256: pool_target / 2^32.
        hardware_difficulty: 256,
        // L7 nameplate: 3,425 W, 480 chips, 425 MHz, 13.0 V (chain rail).
        // P_dynamic = 3425 - 4*50 - 20 = 3205 W → P/chip = 6.68 W
        // C_eff = 6.68 / (13.0^2 * 425) = 0.0000930
        c_eff: 0.0000930, // [GAP] calibrate against measured wall-watts
        static_per_chain_w: 50.0,
        control_board_w: 20.0,
        uio_bases: &[], // Amlogic platform — no FPGA, no UIO
        i2c_bus: 0,
        plugo_gpio_base: 439,  // ch0_plug per AML S11board GPIO map
        enable_gpio_base: 437, // pwr_en per AML S11board GPIO map
        // Scrypt scaling note (re-stated for clarity): for BM1489,
        // ghs_per_mhz is MH/s per MHz per chip.
        // 9.5 GH/s / 480 chips / 425 MHz = 0.0466 MH/s/MHz per chip.
        // Stored as 0.0466 here; total_hashrate_ths multiplies through
        // to give the wrong unit ("TH/s" when really GH/s for Scrypt) —
        // dashboard layer must translate.
        ghs_per_mhz: 0.0466,
    },
];

/// Mining work to be dispatched to a chain.
pub struct MiningWork {
    /// Work ID for tracking (matches against nonce responses).
    pub work_id: u16,
    /// FPGA MIDSTATE_CNT from CTRL register (runtime, from prior firmware).
    /// 2 = 4 slots (36 words), 3 = 8 slots (68 words). Drivers use this
    /// instead of hardcoded constants for work_id shift and packet size.
    pub fpga_midstate_cnt: u8,
    /// Block version.
    pub version: u32,
    /// Compact difficulty target (nBits).
    pub nbits: u32,
    /// Block timestamp.
    pub ntime: u32,
    /// Last 4 bytes of the merkle root.
    pub merkle_tail: [u8; 4],
    /// SHA-256 midstate(s) of the first 64 bytes of the block header.
    pub midstates: Vec<[u8; 32]>,
    /// Full merkle root (32 bytes, internal byte order).
    /// Required by BM1362/BM1398_6x full-header format where ASIC computes midstates.
    pub merkle_root: [u8; 32],
    /// Previous block hash (32 bytes, internal byte order).
    /// Required by BM1362/BM1398_6x full-header format.
    pub prev_block_hash: [u8; 32],
}

/// Result of decoding a nonce from the WORK_RX_FIFO.
#[derive(Debug)]
pub struct NonceResult {
    /// The nonce value (32-bit).
    pub nonce: u32,
    /// Chip index on the chain (0-62 for BM1387); `u8::MAX` means unknown.
    /// Extracted from nonce bits [7:2]. This is the chip INDEX, not the
    /// hardware address (which is index * 4 for BM1387).
    pub chip_index: u8,
    pub work_id: u16,
    /// Solution index (for multi-midstate chips).
    pub solution_id: u8,
    /// Midstate slot index (0-3 for MIDSTATE_CNT=2).
    /// Extracted from the low bits of hw_work_id. Indicates which of the
    /// 4 midstate slots in the FPGA work format produced this nonce.
    /// Must be used to select the correct midstate for share validation.
    pub midstate_idx: u8,
}

/// Per-chain FPGA state required to decode a nonce without chip-driver global
/// mutable state. The value is the log2 midstate-slot count encoded by the
/// admitted chain's FPGA control register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FpgaNonceDecodeContext {
    midstate_count_log2: u8,
}

impl FpgaNonceDecodeContext {
    /// A 16-bit echoed work-id cannot carry more than 15 slot bits.
    pub const fn try_new(midstate_count_log2: u8) -> Option<Self> {
        if midstate_count_log2 < u16::BITS as u8 {
            Some(Self {
                midstate_count_log2,
            })
        } else {
            None
        }
    }

    pub const fn midstate_count_log2(self) -> u8 {
        self.midstate_count_log2
    }
}

/// PLL configuration for a target frequency.
pub struct PllConfig {
    /// PLL feedback divider.
    pub fb_div: u16,
    /// PLL reference divider.
    pub ref_div: u8,
    /// PLL post-divider 1.
    pub post_div1: u8,
    /// PLL post-divider 2.
    pub post_div2: u8,
    /// Raw register value to write.
    pub reg_value: u32,
}

/// The core abstraction for ASIC chip family drivers.
///
/// Each BM13xx chip family implements this trait with its specific
/// initialization sequence, register values, job format, and nonce decoding.
///
/// # Architecture note (ADR-0010, 2026-07-11)
///
/// **Long-term spine:** pure `AsicProtocol` / init programs over a
/// `ChainTransport` (see `dcentrald_hal::chain_backend::Bm1397PlusChainBackend`
/// and `docs/architecture/COMPOSITION_MODEL.md`). Methods that take
/// [`FpgaChain`] are the historical Zynq-Braiins-FIFO shape. Production
/// AM2/AML/BB paths often use serial transports and do **not** all go
/// through this trait today — that is technical debt under the mining
/// strangler (ADR-0009), not a license to add more `FpgaChain`-only APIs.
///
/// Prefer: new protocol work as pure byte-level helpers + transport-agnostic
/// ops. Prefer: voltage via a future `VoltageRail`, not `PicController`-only
/// `set_voltage`. Do not silently fall back unknown chip IDs to BM1387 PLL
/// tables when adding PLL plumbing.
pub trait ChipDriver: Send + Sync {
    /// Chip identifier (e.g., 0x1387, 0x1397, 0x1366, 0x1368, 0x1370, 0x1362).
    fn chip_id(&self) -> u16;

    /// Human-readable chip name (e.g., "BM1387", "BM1370").
    fn chip_name(&self) -> &'static str;

    /// Number of cores per chip (for hashrate estimation).
    fn cores_per_chip(&self) -> u32;

    /// Expected response length from this chip (9 bytes for BM1387, 11 for BM1366+).
    fn response_length(&self) -> usize;

    /// Default ASIC UART baud rate (115200 for all, upgradeable).
    fn default_baud(&self) -> u32;

    /// Maximum operational baud rate.
    fn max_baud(&self) -> u32;

    /// Run the full chip initialization sequence on a chain.
    ///
    /// Includes PLL setup, MiscCtrl, baud upgrade, and TicketMask in the
    /// correct chip-specific order. freq_mhz is used for PLL and WORK_TIME.
    fn init_chain(&self, chain: &mut FpgaChain, chip_count: u8, freq_mhz: u16) -> Result<()>;

    /// Send open-core initialization work to activate SHA-256 cores.
    ///
    /// Some ASIC chips (e.g., BM1387) require dummy work items to activate
    /// cores one-by-one after gate_block is set. Returns the number of
    /// init nonces received (for core health verification).
    ///
    /// Default implementation does nothing (not all chips need open-core init).
    fn send_open_core_work(&self, _chain: &mut FpgaChain, _chip_count: u8) -> Result<u32> {
        Ok(0)
    }

    /// Set PLL frequency for a specific chip (or broadcast if chip_addr = 0xFF).
    fn set_frequency(&self, chain: &mut FpgaChain, chip_addr: u8, freq_mhz: u16) -> Result<()>;

    /// Verify a chip's PLL register after a frequency change.
    ///
    /// Returns:
    /// - `Ok(Some(actual_mhz))` when the driver can read back a real ASIC PLL register
    /// - `Ok(None)` when runtime readback is not implemented for this chip family yet
    /// - `Err(...)` when a supported readback path failed or returned an unknown value
    fn verify_frequency(
        &self,
        _chain: &mut FpgaChain,
        _chip_addr: u8,
        _expected_mhz: u16,
    ) -> Result<Option<u16>> {
        Ok(None)
    }

    /// Set core voltage via PIC (chain-level, not per-chip).
    fn set_voltage(&self, pic: &mut PicController, voltage_mv: u16) -> Result<()>;

    /// Submit a mining job to the chain.
    /// Returns the work_id assigned.
    fn send_work(&self, chain: &mut FpgaChain, work: &MiningWork) -> Result<u16>;

    /// Decode a nonce response from the WORK_RX_FIFO.
    fn decode_nonce(&self, raw: &[u32; 2]) -> Result<NonceResult>;

    /// Decode using immutable per-chain FPGA state. Drivers whose response
    /// shape is independent of carrier configuration retain the default.
    fn decode_nonce_with_context(
        &self,
        raw: &[u32; 2],
        _context: FpgaNonceDecodeContext,
    ) -> Result<NonceResult> {
        self.decode_nonce(raw)
    }

    /// Compute the FPGA BAUD_REG value for a target baud rate.
    fn baud_reg_value(&self, target_baud: u32, fpga_clock_hz: u32) -> u32;

    /// Configure the FPGA CTRL_REG for this chip type.
    fn ctrl_reg_value(&self) -> u32;

    /// Job dispatch interval in milliseconds (chip-specific).
    fn job_interval_ms(&self, chip_count: u8, freq_mhz: u16) -> u32;

    /// TicketMask register value for target difficulty.
    fn ticket_mask(&self, difficulty: u32) -> u32;

    /// PLL parameters for a target frequency.
    fn pll_params(&self, freq_mhz: u16) -> PllConfig;

    /// Read hash board temperature via ASIC I2C passthrough.
    ///
    /// Returns the board/chip temperature in degrees Celsius, or None if
    /// the sensor is not detected or the chip doesn't support I2C passthrough.
    ///
    /// Default implementation returns None. Override for chips with on-board
    /// temp sensors accessible via I2C passthrough (BM1387 register 0x20).
    ///
    /// IMPORTANT: This uses the CMD FIFO and temporarily reconfigures chip 0.
    /// Must only be called from the WorkDispatcher when FPGA access is safe
    /// (not during I2C heartbeats or high-speed work dispatch).
    fn read_board_temp(&self, _chain: &mut FpgaChain) -> Option<f32> {
        None
    }
}

/// Evidence maturity of one ASIC protocol implementation.
///
/// Recognition and execution are deliberately separate.  A chip ID may be
/// known well enough to parse and report without being admitted to issue
/// voltage, reset, PLL, address, or work commands on production hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipDriverMaturity {
    Production,
    Experimental,
    Scaffold,
}

/// Inert chip identity returned by [`ChipRegistry::recognize`].
///
/// This value contains no driver reference and therefore cannot authorize a
/// hardware write by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChipRecognition {
    chip_id: u16,
    chip_name: &'static str,
    maturity: ChipDriverMaturity,
}

impl ChipRecognition {
    pub const fn chip_id(self) -> u16 {
        self.chip_id
    }

    pub const fn chip_name(self) -> &'static str {
        self.chip_name
    }

    pub const fn maturity(self) -> ChipDriverMaturity {
        self.maturity
    }
}

/// Sealed proof that the active registry policy admits execution for one exact
/// chip identity.  Callers can inspect the identity but cannot construct this
/// value without crossing [`ChipRegistry::admit`].
///
/// The proof is deliberately move-only. It may be transferred into one
/// measured hardware-composition session, but it cannot be copied or cloned
/// into a second execution owner.
///
/// ```compile_fail
/// use dcentrald_asic::drivers::ChipRegistry;
///
/// let registry = ChipRegistry::production();
/// let admission = registry.admit(0x1387).unwrap();
/// let moved = admission;
/// let _ = admission.chip_id();
/// drop(moved);
/// ```
///
/// ```compile_fail
/// use dcentrald_asic::drivers::ChipRegistry;
///
/// let registry = ChipRegistry::production();
/// let admission = registry.admit(0x1387).unwrap();
/// let _duplicate = admission.clone();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ChipDriverAdmission {
    recognition: ChipRecognition,
}

impl ChipDriverAdmission {
    pub const fn recognition(&self) -> ChipRecognition {
        self.recognition
    }

    pub const fn chip_id(&self) -> u16 {
        self.recognition.chip_id
    }
}

/// Explicit executable-driver policy carried across hardware-owning runtime
/// boundaries.
///
/// Production drivers are always eligible.  Experimental authority is scoped
/// to one exact chip ID so enabling a beta for one hashboard generation cannot
/// silently enable future experimental families.  Scaffold authority remains
/// a separate simulator/lab decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChipDriverExecutionPolicy {
    experimental_chip_id: Option<u16>,
    allow_scaffold: bool,
}

impl ChipDriverExecutionPolicy {
    pub const fn production_only() -> Self {
        Self {
            experimental_chip_id: None,
            allow_scaffold: false,
        }
    }

    pub const fn with_experimental_chip(chip_id: u16) -> Self {
        Self {
            experimental_chip_id: Some(chip_id),
            allow_scaffold: false,
        }
    }

    const fn with_scaffold(mut self) -> Self {
        self.allow_scaffold = true;
        self
    }

    pub const fn experimental_chip_id(self) -> Option<u16> {
        self.experimental_chip_id
    }

    pub fn allows(self, recognition: ChipRecognition) -> bool {
        match recognition.maturity {
            ChipDriverMaturity::Production => true,
            ChipDriverMaturity::Experimental => {
                self.experimental_chip_id == Some(recognition.chip_id)
            }
            ChipDriverMaturity::Scaffold => self.allow_scaffold,
        }
    }
}

struct ChipDriverEntry {
    recognition: ChipRecognition,
    driver: Box<dyn ChipDriver>,
}

/// Registry of recognized ASIC identities plus policy-admitted executable
/// drivers.
pub struct ChipRegistry {
    entries: HashMap<u16, ChipDriverEntry>,
    execution_policy: ChipDriverExecutionPolicy,
    /// When present, this registry was created by consuming one move-only
    /// admission and may expose only that exact executable driver. It may not
    /// mint successor admissions.
    execution_scope_chip_id: Option<u16>,
}

impl ChipRegistry {
    /// Create a new registry with production-trusted chip drivers registered.
    ///
    /// Simulator/pre-hardware scaffold drivers are intentionally absent by
    /// default. Set [`ALLOW_SCAFFOLD_ASIC_DRIVERS_ENV`] to `1` only in a lab
    /// to include those drivers for simulator coverage.
    pub fn new() -> Self {
        let mut registry = Self::production();
        // W22 (parity #9): scaffold/simulator drivers require TWO independent
        // gates — the lab override AND an explicit stub-behavior acknowledgment
        // — so a single stray env var can never load a stub driver onto a live
        // miner. With override-but-no-ack we register nothing and tell the
        // operator exactly what to set.
        let allow = scaffold_asic_driver_override_enabled();
        let ack = scaffold_stub_behavior_acknowledged();
        if should_register_scaffold_drivers(allow, ack) {
            registry.execution_policy = registry.execution_policy.with_scaffold();
        } else if allow && !ack {
            tracing::warn!(
                "{ALLOW_SCAFFOLD_ASIC_DRIVERS_ENV} is set but the mandatory second \
                 confirmation gate {SCAFFOLD_STUB_ACK_ENV} is NOT — scaffold/simulator \
                 ASIC drivers (BM1373/BM1489) will NOT be registered. They emit \
                 projected/synthetic values, not real mining; set \
                 {SCAFFOLD_STUB_ACK_ENV}=1 to explicitly acknowledge stub behavior \
                 before they can be loaded."
            );
        }
        registry
    }

    pub fn production() -> Self {
        let mut registry = Self {
            entries: HashMap::new(),
            execution_policy: ChipDriverExecutionPolicy::production_only(),
            execution_scope_chip_id: None,
        };
        registry.register(Box::new(bm1387::Bm1387Driver::new()));
        registry.register_with_maturity(
            Box::new(bm1397::Bm1397Driver::new()),
            ChipDriverMaturity::Experimental,
        );
        registry.register_with_maturity(
            Box::new(bm1398::Bm1398Driver::new()),
            ChipDriverMaturity::Experimental,
        );
        registry.register(Box::new(bm1362::Bm1362Driver::new()));
        registry.register(Box::new(bm1366::Bm1366Driver::new()));
        registry.register(Box::new(bm1368::Bm1368Driver::new()));
        registry.register_with_maturity(
            Box::new(bm1370::Bm1370Driver::new()),
            ChipDriverMaturity::Experimental,
        );
        registry.register_scaffold_drivers();
        registry
    }

    pub fn with_execution_policy(execution_policy: ChipDriverExecutionPolicy) -> Self {
        let mut registry = Self::production();
        registry.execution_policy = execution_policy;
        registry
    }

    /// Consume one move-only driver admission into an exact runtime registry.
    ///
    /// The returned registry can resolve only the admitted chip and cannot mint
    /// another [`ChipDriverAdmission`]. This is the terminal transition used by
    /// a measured execution owner after all discovery/configuration stages have
    /// completed.
    pub fn from_admission(admission: ChipDriverAdmission) -> Self {
        let recognition = admission.recognition;
        let execution_policy = match recognition.maturity {
            ChipDriverMaturity::Production => ChipDriverExecutionPolicy::production_only(),
            ChipDriverMaturity::Experimental => {
                ChipDriverExecutionPolicy::with_experimental_chip(recognition.chip_id)
            }
            ChipDriverMaturity::Scaffold => {
                ChipDriverExecutionPolicy::production_only().with_scaffold()
            }
        };
        let mut registry = Self::with_execution_policy(execution_policy);
        registry.execution_scope_chip_id = Some(recognition.chip_id);
        registry
    }

    pub fn with_experimental_driver(chip_id: u16) -> Self {
        Self::with_execution_policy(ChipDriverExecutionPolicy::with_experimental_chip(chip_id))
    }

    pub fn with_scaffold_drivers() -> Self {
        let mut registry = Self::production();
        registry.execution_policy = registry.execution_policy.with_scaffold();
        registry
    }

    fn register_scaffold_drivers(&mut self) {
        self.register_with_maturity(
            Box::new(bm1373::Bm1373Driver::new()),
            ChipDriverMaturity::Scaffold,
        );
        // BM1373/S23 dual-key: real silicon reports 0x1372 on enumeration
        // (NerdQAxePlus `chip_id[6]`) but DCENT keys the scaffold on 0x1373.
        // Operator decision 2026-07-08: resolve BOTH ids to the same fail-closed
        // BM1373 scaffold until a live S23 confirms which is real. Scaffold-only
        // (never added to `production()`), so both ids still fail closed for a
        // real detect; `init_chain` remains fail-closed regardless of the key.
        self.register_alias_with_maturity(
            bm1373::ENUM_CHIP_ID,
            Box::new(bm1373::Bm1373Driver::new()),
            ChipDriverMaturity::Scaffold,
        );
        self.register_with_maturity(
            Box::new(bm1489::Bm1489Driver::new()),
            ChipDriverMaturity::Scaffold,
        );
        // BM1491 (L9 — CVCtrl/CV183x variant, Scrypt). Distinct id 0x1491 from the
        // 0x1489 AML L9 above. Scaffold: chain stride (2) and operational baud
        // (1,562,500) are byte-exact RE-recovered from the un-obfuscated CVCtrl
        // `godminer`, but every hardware method fails closed (register map + init
        // sequence unresolved), and max_baud stays at the enumeration rate until a
        // bench UART capture confirms the recovered baud on the wire.
        self.register_with_maturity(
            Box::new(bm1491::Bm1491Driver::new()),
            ChipDriverMaturity::Scaffold,
        );
        // BM1391 (S15/T15) — jig-observed protocol scaffold but fail-closed.
        // Held S15 evidence settles chip/core/board geometry, not the carrier,
        // PIC, thermal, PLL, or energization contract. Every runtime operation
        // refuses even when the explicit scaffold registry exposes the type.
        self.register_with_maturity(
            Box::new(bm1391::Bm1391Driver::new()),
            ChipDriverMaturity::Scaffold,
        );
        // BM1393 (S9 SE / S9k) — evidence-backed codec, Scaffold maturity.
        // drivers/bm1393.rs now implements every carrier-independent fact from
        // the held S9k cgminer.dec (208 cores = 4 banks x 52, verified 8-byte
        // two-word return record, held freq_pll_1393 tables, divisor-anchored
        // baud, nonce_calc chip/core attribution). Its FpgaChain-carried
        // operations still fail closed: no BM1393 s9io/Braiins-FIFO carrier
        // exists in held evidence. The production C43 lane does not consume
        // ChipRegistry at all — it runs through
        // dcentrald_common::bm1393_native::Bm1393Runtime over
        // dcentrald_hal::platform::c43_bm1393. Keep 0x1393 out of production()
        // until a real detect proves this trait surface on hardware.
        self.register_with_maturity(
            Box::new(bm1393::Bm1393Driver::new()),
            ChipDriverMaturity::Scaffold,
        );
        // BM1485 (L3 / L3+ / L3++ Scrypt) — rank 44. Scaffold: EVERY hardware
        // method returns Err (operational baud, chain address stride, PLL
        // register encoding and nonce field layout are all unresolved), and
        // its registry key is synthetic because the chip has no readable
        // CHIP_ID. Registered so the previously-stranded silicon profile has a
        // driver behind it for offline work.
        self.register_with_maturity(
            Box::new(bm1485::Bm1485Driver::new()),
            ChipDriverMaturity::Scaffold,
        );
        // BM1385 (Antminer S7 — pre-S9 28 nm generation) — jig-verified Gen-1
        // FIL protocol + byte-extracted 124-entry freq_pll_1385[] table, but
        // fail-closed (no live S7 on the fleet). init_chain refuses live
        // bring-up regardless.
        self.register_with_maturity(
            Box::new(bm1385::Bm1385Driver::new()),
            ChipDriverMaturity::Scaffold,
        );
        // ScryptL7 (W3-B): when the default-OFF `scrypt-l7` feature is compiled,
        // the W3-A-accurate driver SUPERSEDES the older `bm1489.rs` scaffold for
        // chip-id 0x1489 (registered LAST so it overrides the HashMap slot). It
        // is still a KICKOFF: its init_chain fails closed (L7 chain-FIFO deferred).
        #[cfg(feature = "scrypt-l7")]
        self.register_with_maturity(
            Box::new(scrypt_l7::ScryptL7Driver::new()),
            ChipDriverMaturity::Scaffold,
        );
    }

    /// Register a production chip driver inside the sealed catalog.
    ///
    /// This is deliberately private: exposing it let any consumer re-register
    /// an Experimental implementation (for example BM1398) as Production and
    /// bypass `ChipDriverExecutionPolicy` entirely.
    fn register(&mut self, driver: Box<dyn ChipDriver>) {
        self.register_with_maturity(driver, ChipDriverMaturity::Production);
    }

    fn register_with_maturity(
        &mut self,
        driver: Box<dyn ChipDriver>,
        maturity: ChipDriverMaturity,
    ) {
        let chip_id = driver.chip_id();
        let recognition = ChipRecognition {
            chip_id,
            chip_name: driver.chip_name(),
            maturity,
        };
        self.entries.insert(
            chip_id,
            ChipDriverEntry {
                recognition,
                driver,
            },
        );
    }

    /// Register a chip driver under an explicit `chip_id` key that may DIFFER
    /// from the driver's own [`ChipDriver::chip_id`].
    ///
    /// The seam for scaffold dual-keying, where one chip enumerates under more
    /// than one id. Today's only use: the BM1373/S23 scaffold, which real
    /// silicon reports as `0x1372` on enumeration while DCENT keys the driver on
    /// `0x1373` — operator decision 2026-07-08 to resolve BOTH ids to the same
    /// fail-closed BM1373 scaffold until a live S23 confirms which is real. The
    /// driver still reports its own canonical `chip_id()` regardless of the key.
    fn register_alias_with_maturity(
        &mut self,
        chip_id: u16,
        driver: Box<dyn ChipDriver>,
        maturity: ChipDriverMaturity,
    ) {
        let recognition = ChipRecognition {
            chip_id,
            chip_name: driver.chip_name(),
            maturity,
        };
        self.entries.insert(
            chip_id,
            ChipDriverEntry {
                recognition,
                driver,
            },
        );
    }

    /// Recognize a chip ID without granting executable driver authority.
    pub fn recognize(&self, chip_id: u16) -> Option<ChipRecognition> {
        self.entries.get(&chip_id).map(|entry| entry.recognition)
    }

    /// Mint executable authority for one exact chip identity under this
    /// registry's immutable policy.
    pub fn admit(&self, chip_id: u16) -> Option<ChipDriverAdmission> {
        if self.execution_scope_chip_id.is_some() {
            return None;
        }
        let recognition = self.recognize(chip_id)?;
        self.execution_policy
            .allows(recognition)
            .then_some(ChipDriverAdmission { recognition })
    }

    /// Look up a driver by chip ID.
    ///
    /// Returns None if no driver is registered for the given chip ID.
    pub fn detect(&self, chip_id: u16) -> Option<&dyn ChipDriver> {
        if self
            .execution_scope_chip_id
            .is_some_and(|admitted_chip_id| admitted_chip_id != chip_id)
        {
            return None;
        }
        self.entries.get(&chip_id).and_then(|entry| {
            self.execution_policy
                .allows(entry.recognition)
                .then_some(entry.driver.as_ref())
        })
    }

    /// Get a list of all registered chip IDs and names.
    pub fn list_drivers(&self) -> Vec<(u16, &'static str)> {
        self.entries
            .iter()
            .filter(|(chip_id, entry)| {
                self.execution_scope_chip_id
                    .is_none_or(|admitted_chip_id| admitted_chip_id == **chip_id)
                    && self.execution_policy.allows(entry.recognition)
            })
            .map(|(&chip_id, entry)| (chip_id, entry.recognition.chip_name))
            .collect()
    }

    /// List every inert recognition, including unadmitted experimental and
    /// scaffold entries.
    pub fn list_recognized(&self) -> Vec<ChipRecognition> {
        self.entries
            .values()
            .map(|entry| entry.recognition)
            .collect()
    }
}

impl Default for ChipRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_silicon_profiles::asics::AsicChip;

    #[test]
    fn chip_detection_fails_closed_on_every_unknown_chip_id() {
        // Production-risk pin (priority 3: hardware detection). An unknown or corrupt
        // chip_id — ANY u16 not in the production registry — must NEVER resolve to a
        // live driver, so the daemon refuses to mine on unrecognized silicon instead
        // of defaulting to some other chip's voltage/frequency envelope. Exhaustive
        // over all 65536 chip IDs. A future edit that adds a `_ => default_driver`
        // fallback to ChipRegistry::detect would fail this test.
        let prod = ChipRegistry::production();
        let executable: std::collections::BTreeSet<u16> =
            prod.list_drivers().iter().map(|(id, _)| *id).collect();
        for id in 0u16..=u16::MAX {
            let detected = prod.detect(id).is_some();
            if executable.contains(&id) {
                assert!(detected, "admitted chip 0x{id:04X} must detect a driver");
            } else {
                assert!(
                    !detected,
                    "unknown chip 0x{id:04X} must fail closed (no live driver)"
                );
                // A truly-unknown chip (not a scaffold that carries metadata-only)
                // must also have NO MinerProfile — nothing to source a voltage from.
                if prod.recognize(id).is_none() {
                    assert!(
                        MinerProfile::for_chip(id).is_none(),
                        "non-scaffold unknown chip 0x{id:04X} must have no profile"
                    );
                }
            }
        }
    }

    #[test]
    fn production_registry_is_the_executable_chip_allowlist() {
        let actual: std::collections::BTreeSet<u16> = ChipRegistry::production()
            .list_drivers()
            .iter()
            .map(|(id, _)| *id)
            .collect();
        let expected: std::collections::BTreeSet<u16> = [
            bm1387::CHIP_ID,
            bm1362::CHIP_ID,
            bm1366::CHIP_ID,
            bm1368::CHIP_ID,
        ]
        .into_iter()
        .collect();

        assert_eq!(
            actual, expected,
            "production registry is the default executable-driver authority"
        );
    }

    #[test]
    fn bm1398_is_inertly_recognized_and_requires_exact_experimental_policy() {
        let production = ChipRegistry::production();
        let recognition = production
            .recognize(bm1398::CHIP_ID)
            .expect("BM1398 identity evidence remains catalogued");
        assert_eq!(recognition.chip_name(), "BM1398");
        assert_eq!(recognition.maturity(), ChipDriverMaturity::Experimental);
        assert!(production.detect(bm1398::CHIP_ID).is_none());

        let exact = ChipRegistry::with_experimental_driver(bm1398::CHIP_ID);
        assert!(exact.detect(bm1398::CHIP_ID).is_some());

        let unrelated = ChipRegistry::with_experimental_driver(0xFFFF);
        assert!(unrelated.detect(bm1398::CHIP_ID).is_none());
        assert!(unrelated.detect(bm1387::CHIP_ID).is_some());
    }

    #[test]
    fn bm1370_is_inertly_recognized_and_requires_exact_experimental_policy() {
        let production = ChipRegistry::production();
        let recognition = production
            .recognize(bm1370::CHIP_ID)
            .expect("BM1370 identity evidence remains catalogued");
        assert_eq!(recognition.chip_name(), "BM1370");
        assert_eq!(recognition.maturity(), ChipDriverMaturity::Experimental);
        assert!(production.detect(bm1370::CHIP_ID).is_none());

        let exact = ChipRegistry::with_experimental_driver(bm1370::CHIP_ID);
        assert!(exact.detect(bm1370::CHIP_ID).is_some());

        let unrelated = ChipRegistry::with_experimental_driver(bm1398::CHIP_ID);
        assert!(unrelated.detect(bm1370::CHIP_ID).is_none());
        assert!(unrelated.detect(bm1368::CHIP_ID).is_some());
    }

    #[test]
    fn bm1397_is_recognized_but_not_executable_without_exact_experimental_policy() {
        let production = ChipRegistry::production();
        let recognition = production
            .recognize(bm1397::CHIP_ID)
            .expect("BM1397 factory-jig identity remains catalogued");
        assert_eq!(recognition.maturity(), ChipDriverMaturity::Experimental);
        assert!(production.detect(bm1397::CHIP_ID).is_none());
        assert!(ChipRegistry::with_experimental_driver(bm1397::CHIP_ID)
            .detect(bm1397::CHIP_ID)
            .is_some());
        assert!(ChipRegistry::with_experimental_driver(bm1398::CHIP_ID)
            .detect(bm1397::CHIP_ID)
            .is_none());
    }

    #[test]
    fn consumed_admission_creates_an_exact_non_reminting_runtime_registry() {
        let policy = ChipDriverExecutionPolicy::with_experimental_chip(bm1398::CHIP_ID);
        let admission = ChipRegistry::with_execution_policy(policy)
            .admit(bm1398::CHIP_ID)
            .expect("exact experimental policy must mint one BM1398 admission");

        let runtime = ChipRegistry::from_admission(admission);
        assert!(runtime.detect(bm1398::CHIP_ID).is_some());
        assert_eq!(runtime.list_drivers(), vec![(bm1398::CHIP_ID, "BM1398")]);
        assert!(
            runtime.detect(bm1387::CHIP_ID).is_none(),
            "a consumed BM1398 admission must not expose even a Production driver"
        );
        assert!(
            runtime.admit(bm1398::CHIP_ID).is_none(),
            "a terminal runtime registry must not remint the consumed admission"
        );
    }

    #[test]
    fn every_driver_max_baud_is_pinned_against_catalog_ceiling() {
        struct Case {
            source_file: &'static str,
            driver_name: &'static str,
            driver_max_baud: u32,
            catalog_chip: Option<AsicChip>,
            catalog_absence_reason: Option<&'static str>,
            driver_above_catalog_reason: Option<&'static str>,
        }

        let cases = [
            Case {
                source_file: "bm1362.rs",
                driver_name: bm1362::Bm1362Driver::new().chip_name(),
                driver_max_baud: bm1362::Bm1362Driver::new().max_baud(),
                catalog_chip: Some(AsicChip::Bm1362),
                catalog_absence_reason: None,
                driver_above_catalog_reason: None,
            },
            Case {
                source_file: "bm1366.rs",
                driver_name: bm1366::Bm1366Driver::new().chip_name(),
                driver_max_baud: bm1366::Bm1366Driver::new().max_baud(),
                catalog_chip: Some(AsicChip::Bm1366),
                catalog_absence_reason: None,
                driver_above_catalog_reason: None,
            },
            Case {
                source_file: "bm1368.rs",
                driver_name: bm1368::Bm1368Driver::new().chip_name(),
                driver_max_baud: bm1368::Bm1368Driver::new().max_baud(),
                catalog_chip: Some(AsicChip::Bm1368),
                catalog_absence_reason: None,
                driver_above_catalog_reason: None,
            },
            Case {
                source_file: "bm1370.rs",
                driver_name: bm1370::Bm1370Driver::new().chip_name(),
                driver_max_baud: bm1370::Bm1370Driver::new().max_baud(),
                catalog_chip: Some(AsicChip::Bm1370),
                catalog_absence_reason: None,
                driver_above_catalog_reason: None,
            },
            Case {
                source_file: "bm1373.rs",
                driver_name: bm1373::Bm1373Driver::new().chip_name(),
                driver_max_baud: bm1373::Bm1373Driver::new().max_baud(),
                catalog_chip: None,
                catalog_absence_reason: Some("BM1373 is a pre-hardware scaffold driver"),
                driver_above_catalog_reason: None,
            },
            Case {
                source_file: "bm1385.rs",
                driver_name: bm1385::Bm1385Driver::new().chip_name(),
                driver_max_baud: bm1385::Bm1385Driver::new().max_baud(),
                catalog_chip: None,
                catalog_absence_reason: Some(
                    "BM1385/S7 is a pre-S9 generation with no AsicChip catalog row; the jig-verified scaffold is fail-closed and unregistered in production",
                ),
                driver_above_catalog_reason: None,
            },
            Case {
                source_file: "bm1387.rs",
                driver_name: bm1387::Bm1387Driver::new().chip_name(),
                driver_max_baud: bm1387::Bm1387Driver::new().max_baud(),
                catalog_chip: Some(AsicChip::Bm1387),
                catalog_absence_reason: None,
                driver_above_catalog_reason: Some(
                    "BM1387 driver max is the FPGA-capable ceiling; asics.rs keeps the legacy S9 catalog row",
                ),
            },
            Case {
                source_file: "bm1391.rs",
                driver_name: bm1391::Bm1391Driver::new().chip_name(),
                driver_max_baud: bm1391::Bm1391Driver::new().max_baud(),
                catalog_chip: Some(AsicChip::Bm1391),
                catalog_absence_reason: None,
                driver_above_catalog_reason: Some(
                    "BM1391 is a jig-observed scaffold; catalog baud is not runtime authority without exact S15/T15 carrier and live proof",
                ),
            },
            Case {
                source_file: "bm1393.rs",
                driver_name: bm1393::Bm1393Driver::new().chip_name(),
                driver_max_baud: bm1393::Bm1393Driver::new().max_baud(),
                catalog_chip: None,
                catalog_absence_reason: Some(
                    "BM1393 is retained as an exact fail-closed S9 SE/S9k protocol scaffold; the silicon profile catalog has no executable row",
                ),
                driver_above_catalog_reason: None,
            },
            Case {
                source_file: "bm1397.rs",
                driver_name: bm1397::Bm1397Driver::new().chip_name(),
                driver_max_baud: bm1397::Bm1397Driver::new().max_baud(),
                catalog_chip: Some(AsicChip::Bm1397),
                catalog_absence_reason: None,
                driver_above_catalog_reason: None,
            },
            Case {
                source_file: "bm1398.rs",
                driver_name: bm1398::Bm1398Driver::new().chip_name(),
                driver_max_baud: bm1398::Bm1398Driver::new().max_baud(),
                catalog_chip: Some(AsicChip::Bm1398),
                catalog_absence_reason: None,
                driver_above_catalog_reason: None,
            },
            Case {
                source_file: "bm1396.rs",
                driver_name: bm1396::Bm1396Driver::new().chip_name(),
                driver_max_baud: bm1396::Bm1396Driver::new().max_baud(),
                catalog_chip: Some(AsicChip::Bm1396),
                catalog_absence_reason: None,
                driver_above_catalog_reason: Some(
                    "BM1396 driver max is the exact S17e operational 6 Mbaud \
                     (native-operational-baud-vectors-v1); the 937500 catalog \
                     row is a stale placeholder without runtime authority",
                ),
            },
            Case {
                source_file: "bm1485.rs",
                driver_name: bm1485::Bm1485Driver::new().chip_name(),
                driver_max_baud: bm1485::Bm1485Driver::new().max_baud(),
                catalog_chip: None,
                catalog_absence_reason: Some("BM1485 is a Scrypt scaffold outside asics.rs"),
                driver_above_catalog_reason: None,
            },
            Case {
                source_file: "bm1489.rs",
                driver_name: bm1489::Bm1489Driver::new().chip_name(),
                driver_max_baud: bm1489::Bm1489Driver::new().max_baud(),
                catalog_chip: None,
                catalog_absence_reason: Some("BM1489 is a Scrypt scaffold outside asics.rs"),
                driver_above_catalog_reason: None,
            },
            Case {
                source_file: "bm1491.rs",
                driver_name: bm1491::Bm1491Driver::new().chip_name(),
                driver_max_baud: bm1491::Bm1491Driver::new().max_baud(),
                catalog_chip: None,
                catalog_absence_reason: Some("BM1491 is a Scrypt scaffold (L9-CVCtrl) outside asics.rs"),
                driver_above_catalog_reason: None,
            },
        ];

        assert_eq!(
            cases.len(),
            15,
            "this pin must cover every concrete driver file with max_baud()"
        );

        // BM1491 (L9-CVCtrl): the operational baud IS RE-recovered byte-exact
        // (1_562_500, godminer chip_setting_buadrate_ltc), but max_baud() stays at
        // the enumeration rate until a bench UART capture — same "never raise a
        // driver baud without bench proof" discipline as BM1485. The recovered value
        // is preserved in bm1491::OPERATIONAL_BAUD, deliberately NOT wired to max_baud.
        assert_eq!(bm1491::Bm1491Driver::new().max_baud(), 115_200);
        assert_eq!(
            bm1491::Bm1491Driver::new().max_baud(),
            bm1491::Bm1491Driver::new().default_baud(),
        );
        assert_eq!(bm1491::OPERATIONAL_BAUD, Some(1_562_500));
        assert_ne!(
            bm1491::Bm1491Driver::new().max_baud() as u64,
            bm1491::OPERATIONAL_BAUD.unwrap() as u64,
        );

        // Rank 44: BM1485's operational baud is UNRESOLVED (bm1485.md gives
        // BOTH bt8d=7 -> 390625 and bt8d=1 -> 1562500 for the post-upgrade
        // rate, and no held L3+ binary contains either literal). The driver
        // therefore refuses to raise baud at all — max == the enumeration
        // rate. Raising this without a bench UART capture landing in the same
        // commit violates the standing "never raise a driver baud without
        // bench proof" rule.
        assert_eq!(bm1485::Bm1485Driver::new().max_baud(), 115_200);
        assert_eq!(
            bm1485::Bm1485Driver::new().max_baud(),
            bm1485::Bm1485Driver::new().default_baud(),
        );
        assert!(bm1485::OPERATIONAL_BAUD.is_none());

        for case in cases {
            match case.catalog_chip {
                Some(chip) => {
                    let catalog = chip.catalog();
                    if case.driver_max_baud > catalog.baud_max {
                        assert!(
                            case.driver_above_catalog_reason.is_some(),
                            "{} {} driver max_baud {} exceeds catalog ceiling {} without an allowlist reason",
                            case.source_file,
                            case.driver_name,
                            case.driver_max_baud,
                            catalog.baud_max
                        );
                    }
                }
                None => assert!(
                    case.catalog_absence_reason.is_some(),
                    "{} {} has no catalog row and no documented exception",
                    case.source_file,
                    case.driver_name
                ),
            }
        }

        // These two are the risky divergence called out by the readiness plan:
        // the catalog records a 3.125 Mbaud ceiling, while the live driver stays
        // at the conservative 1 Mbps path until operator bench proof exists.
        assert_eq!(bm1366::Bm1366Driver::new().max_baud(), 1_000_000);
        assert_eq!(AsicChip::Bm1366.catalog().baud_max, 3_125_000);
        assert_eq!(bm1370::Bm1370Driver::new().max_baud(), 1_000_000);
        assert_eq!(AsicChip::Bm1370.catalog().baud_max, 3_125_000);
    }

    #[test]
    fn every_driver_core_count_matches_miner_profile_driver_semantics() {
        struct Case {
            source_file: &'static str,
            driver: Box<dyn ChipDriver>,
            profile_absence_reason: Option<&'static str>,
        }

        let cases = vec![
            Case {
                source_file: "bm1362.rs",
                driver: Box::new(bm1362::Bm1362Driver::new()),
                profile_absence_reason: None,
            },
            Case {
                source_file: "bm1366.rs",
                driver: Box::new(bm1366::Bm1366Driver::new()),
                profile_absence_reason: None,
            },
            Case {
                source_file: "bm1368.rs",
                driver: Box::new(bm1368::Bm1368Driver::new()),
                profile_absence_reason: None,
            },
            Case {
                source_file: "bm1370.rs",
                driver: Box::new(bm1370::Bm1370Driver::new()),
                profile_absence_reason: None,
            },
            Case {
                source_file: "bm1373.rs",
                driver: Box::new(bm1373::Bm1373Driver::new()),
                profile_absence_reason: None,
            },
            Case {
                source_file: "bm1385.rs",
                driver: Box::new(bm1385::Bm1385Driver::new()),
                profile_absence_reason: Some(
                    "BM1385/S7 has no MinerProfile: the held jig proves 50 cores and the 45-chip board, but the S7 control board is a pre-Zynq Bitmain design with no uio/gpio/i2c values in any held artifact, c_eff is uncalibrated, and ghs_per_mhz has no measured source",
                ),
            },
            Case {
                source_file: "bm1387.rs",
                driver: Box::new(bm1387::Bm1387Driver::new()),
                profile_absence_reason: None,
            },
            Case {
                source_file: "bm1391.rs",
                driver: Box::new(bm1391::Bm1391Driver::new()),
                profile_absence_reason: Some(
                    "BM1391/S15/T15 remains scaffold-gated without a MinerProfile; core count and S15 topology are known, but the carrier and safe runtime envelope are not",
                ),
            },
            Case {
                source_file: "bm1393.rs",
                driver: Box::new(bm1393::Bm1393Driver::new()),
                profile_absence_reason: Some(
                    "BM1393/S9 SE/S9k remains scaffold-gated; exact protocol bytes do not settle the production carrier, voltage, cooling, or safe runtime envelope",
                ),
            },
            Case {
                source_file: "bm1397.rs",
                driver: Box::new(bm1397::Bm1397Driver::new()),
                profile_absence_reason: None,
            },
            Case {
                source_file: "bm1398.rs",
                driver: Box::new(bm1398::Bm1398Driver::new()),
                profile_absence_reason: None,
            },
            Case {
                source_file: "bm1396.rs",
                driver: Box::new(bm1396::Bm1396Driver::new()),
                profile_absence_reason: Some(
                    "BM1396/S17e-T17e has no MinerProfile: wire identity, CRC5 \
                     and the 135/78 chain populations are exact, but per-chip \
                     core count, measured hashrate and power calibration are \
                     unproved (driver cores_per_chip is a deliberate 0)",
                ),
            },
            Case {
                source_file: "bm1485.rs",
                driver: Box::new(bm1485::Bm1485Driver::new()),
                profile_absence_reason: Some(
                    "BM1485/L3+ has no MinerProfile: its control board is an AM335x BeagleBone with kernel /dev/ttyO UARTs and no FPGA, so the Zynq-shaped uio/gpio/i2c fields have no honest values, and c_eff is uncalibrated",
                ),
            },
            Case {
                source_file: "bm1489.rs",
                driver: Box::new(bm1489::Bm1489Driver::new()),
                profile_absence_reason: None,
            },
        ];

        assert_eq!(
            cases.len(),
            14,
            "this pin must cover every concrete driver file with cores_per_chip()"
        );

        for case in cases {
            let chip_id = case.driver.chip_id();
            let driver_cores = case.driver.cores_per_chip();
            match MinerProfile::for_chip(chip_id) {
                Some(profile) => {
                    assert_eq!(
                        driver_cores, profile.cores_per_chip,
                        "{} {} driver cores_per_chip must match MinerProfile::cores_per_chip",
                        case.source_file, profile.name
                    );
                    assert!(
                        profile.nonce_attribution_cores >= profile.cores_per_chip,
                        "{} nonce-attribution slots must not be smaller than the driver-facing engine count",
                        profile.name
                    );
                }
                None => assert!(
                    case.profile_absence_reason.is_some(),
                    "{} chip 0x{chip_id:04X} has no MinerProfile and no documented exception",
                    case.source_file
                ),
            }
        }

        let bm1362 = MinerProfile::for_chip(bm1362::CHIP_ID).expect("BM1362 profile registered");
        assert_eq!(bm1362.cores_per_chip, 4);
        // Declared field = flag-off default (SG-1 rank 24: 894 stays the
        // declared legacy value until the default flips).
        assert_eq!(bm1362.nonce_attribution_cores, 894);
        // SG-1 rank-24 corrected value, pure path (no env): 514, derived
        // from this profile's own ghs_per_mhz 0.550 → ~550 implied slots.
        assert_eq!(bm1362.nonce_attribution_cores_with_correction(false), 894);
        assert_eq!(bm1362.nonce_attribution_cores_with_correction(true), 514);
        assert!(
            514 >= bm1362.cores_per_chip,
            "corrected slot count must not be smaller than the engine count"
        );

        let bm1366 = MinerProfile::for_chip(bm1366::CHIP_ID).expect("BM1366 profile registered");
        assert_eq!(bm1366.cores_per_chip, 894);
        assert_eq!(bm1366.nonce_attribution_cores, 894);
        // BM1366 has no SG-1 correction — 894 is consistent with its own
        // ghs_per_mhz (0.848 → ~848, within the 10% gate bar).
        assert_eq!(bm1366.nonce_attribution_cores_with_correction(true), 894);

        let bm1368 = MinerProfile::for_chip(bm1368::CHIP_ID).expect("BM1368 profile registered");
        assert_eq!(bm1368.cores_per_chip, 1280);
        assert_eq!(bm1368.nonce_attribution_cores, 1280);
        // BM1368's 1280 is measured (80×16, S21 fixture RE 2026-04-12, live
        // S21 `a lab unit`) — exempt from SG-1; the correction table must not
        // touch it.
        assert_eq!(bm1368.nonce_attribution_cores_with_correction(true), 1280);

        let bm1370 = MinerProfile::for_chip(bm1370::CHIP_ID).expect("BM1370 profile registered");
        assert_eq!(bm1370.cores_per_chip, 1280);
        // Declared field = flag-off default (SG-1 rank 24: 1280 stays the
        // declared legacy value until the default flips).
        assert_eq!(bm1370.nonce_attribution_cores, 1280);
        // SG-1 rank-24 corrected value, pure path: 2040 (our own ESP-tree
        // Bitaxe Gamma evidence; ePIC-corroborated).
        assert_eq!(bm1370.nonce_attribution_cores_with_correction(false), 1280);
        assert_eq!(bm1370.nonce_attribution_cores_with_correction(true), 2040);
        assert!(
            2040 >= bm1370.cores_per_chip,
            "corrected slot count must not be smaller than the engine count"
        );

        let bm1398 = MinerProfile::for_chip(bm1398::CHIP_ID).expect("BM1398 profile registered");
        assert_eq!(
            bm1398.cores_per_chip,
            dcentrald_silicon_profiles::bm1398::BM1398_CORES_PER_CHIP,
            "driver and silicon layers must agree on physical BM1398 geometry"
        );
        assert_eq!(bm1398.cores_per_chip, 624);
        assert_eq!(
            bm1398.nonce_attribution_cores, 672,
            "legacy BM1398 work-time model remains explicit while Experimental"
        );

        assert!(MinerProfile::for_chip(bm1391::CHIP_ID).is_none());
        // BM1391's core count is no longer unresolved: 256, byte-stated by the
        // S17 jig `calculate_core_number(256u)` and cross-anchored by BM1385=50
        // and BM1397=672 in the SAME binary. This assertion previously pinned
        // the placeholder `0` and was left stale when the catalog was
        // populated, so `dcentrald-asic` contradicted `dcentrald-silicon-
        // profiles` at HEAD (Round 16 coordinator; the static offline gate runs
        // no cargo, so a red test at HEAD is invisible to it —
        // ).
        //
        // Pinned against the canonical constant rather than a repeated literal
        // so the two layers cannot drift apart again, matching the BM1398
        // treatment above.
        assert_eq!(
            u32::from(AsicChip::Bm1391.catalog().cores),
            dcentrald_silicon_profiles::bm1391::BM1391_CORE_NUM,
            "driver and silicon layers must agree on physical BM1391 geometry"
        );
        // The safety property is unchanged and is NOT the core count: BM1391
        // still has no `MinerProfile` and must stay out of production
        // detection until a live S11/S15/T15 validates it.
        assert!(
            ChipRegistry::production().detect(bm1391::CHIP_ID).is_none(),
            "BM1391 must stay scaffold-gated: a known core count is not a \
             validated mining envelope"
        );

        // Rank 44: BM1485's 12 cores/chip is the one well-attested BM1485
        // number (cgminer-ltc `BM1485_CORE_NUM`), and the driver and silicon
        // layers must not drift apart.
        assert_eq!(
            bm1485::Bm1485Driver::new().cores_per_chip(),
            dcentrald_silicon_profiles::bm1485::BM1485_CORES_PER_CHIP,
        );
        assert!(MinerProfile::for_chip(bm1485::CHIP_ID).is_none());
        assert!(
            ChipRegistry::production().detect(bm1485::CHIP_ID).is_none(),
            "BM1485 must stay scaffold-gated"
        );
    }

    #[test]
    fn production_registry_excludes_scaffold_drivers() {
        let registry = ChipRegistry::production();
        assert!(registry.detect(bm1387::CHIP_ID).is_some());
        assert!(registry.detect(bm1362::CHIP_ID).is_some());
        assert!(registry.detect(bm1373::CHIP_ID).is_none());
        assert!(registry.detect(bm1489::CHIP_ID).is_none());
        // BM1391 (S15/T15) is a jig-observed, fail-closed scaffold — excluded
        // until exact carrier contracts and live S15/T15 validation exist.
        assert!(registry.detect(bm1391::CHIP_ID).is_none());
        // BM1485 (L3/L3+) — rank 44 scaffold, unresolved baud/stride/PLL.
        assert!(registry.detect(bm1485::CHIP_ID).is_none());
    }

    #[test]
    fn scaffold_registry_is_explicit() {
        let registry = ChipRegistry::with_scaffold_drivers();
        assert!(registry.detect(bm1373::CHIP_ID).is_some());
        assert!(registry.detect(bm1489::CHIP_ID).is_some());
        assert!(registry.detect(bm1391::CHIP_ID).is_some());
        assert!(registry.detect(bm1485::CHIP_ID).is_some());
    }

    /// Rank 44: the BM1485 scaffold exists ONLY to give the previously
    /// stranded silicon profile a driver, and it must never look executable.
    ///
    /// Note the asymmetry versus every other entry in the registry: BM1485's
    /// key is SYNTHETIC (`CHIP_ID_IS_SILICON_READABLE == false`), because
    /// `bm1485.md:24` records that the chip has no verified readable CHIP_ID
    /// and cgminer-ltc detects L3 chains by chain length instead. So even in
    /// the double-env-gated scaffold registry, no LIVE enumeration can ever
    /// produce `0x1485` — the entry is reachable from offline code only.
    #[test]
    fn bm1485_is_scaffold_only_and_keyed_on_a_synthetic_id() {
        assert!(!bm1485::CHIP_ID_IS_SILICON_READABLE);
        assert!(is_scaffold_driver_chip(bm1485::CHIP_ID));

        let prod = ChipRegistry::production();
        assert!(prod.detect(bm1485::CHIP_ID).is_none());
        assert!(prod.admit(bm1485::CHIP_ID).is_none());
        let recognition = prod
            .recognize(bm1485::CHIP_ID)
            .expect("BM1485 identity stays catalogued as inert recognition");
        assert_eq!(recognition.chip_name(), "BM1485");
        assert_eq!(recognition.maturity(), ChipDriverMaturity::Scaffold);

        // An Experimental policy for BM1485 must NOT unlock it — scaffold
        // authority is a separate decision.
        assert!(ChipRegistry::with_experimental_driver(bm1485::CHIP_ID)
            .detect(bm1485::CHIP_ID)
            .is_none());

        // No PLL table: unknown/unproven silicon must not inherit another
        // chip's frequency ladder.
        assert!(MinerProfile::try_pll_frequencies_for_chip(bm1485::CHIP_ID).is_none());
        assert!(!MinerProfile::has_pll_table(bm1485::CHIP_ID));
        assert!(MinerProfile::pll_frequencies_for_chip(bm1485::CHIP_ID).is_empty());
    }

    /// Operator decision 2026-07-08: the BM1373/S23 scaffold is keyed under BOTH
    /// 0x1372 (what real silicon reports on enumeration per NerdQAxePlus RE) and
    /// 0x1373 (DCENT's canonical key) until a live S23 confirms which is real.
    /// Both ids must resolve to the SAME fail-closed BM1373 scaffold driver + the
    /// S23 profile — but ONLY in the double-env-gated scaffold registry, never in
    /// production (both stay fail-closed for a real detect).
    #[test]
    fn bm1373_s23_is_dual_keyed_0x1372_and_0x1373() {
        assert_eq!(bm1373::ENUM_CHIP_ID, 0x1372);
        assert_eq!(bm1373::CHIP_ID, 0x1373);

        // Production stays fail-closed for BOTH ids (scaffold-only, no alias).
        let prod = ChipRegistry::production();
        assert!(prod.detect(0x1372).is_none());
        assert!(prod.detect(0x1373).is_none());

        // The scaffold registry resolves BOTH ids to the BM1373 scaffold driver.
        let scaffold = ChipRegistry::with_scaffold_drivers();
        let via_1372 = scaffold
            .detect(0x1372)
            .expect("0x1372 must detect the BM1373 scaffold (enumerated id)");
        let via_1373 = scaffold
            .detect(0x1373)
            .expect("0x1373 must detect the BM1373 scaffold (canonical id)");
        assert_eq!(via_1372.chip_name(), "BM1373");
        assert_eq!(via_1373.chip_name(), "BM1373");
        // The driver reports its canonical id regardless of which key resolved it.
        assert_eq!(via_1372.chip_id(), bm1373::CHIP_ID);

        // Both ids resolve to the S23 MinerProfile (aliased, not duplicated).
        assert_eq!(MinerProfile::for_chip(0x1372).unwrap().name, "Antminer S23");
        assert_eq!(MinerProfile::for_chip(0x1373).unwrap().name, "Antminer S23");

        // Both classify as scaffold chips, and both PLL tables route to BM1373.
        assert!(is_scaffold_driver_chip(0x1372));
        assert!(is_scaffold_driver_chip(0x1373));
        assert_eq!(
            MinerProfile::pll_frequencies_for_chip(0x1372),
            bm1373::pll_frequencies()
        );
    }

    /// P1-4: unknown chip IDs must never inherit the BM1387 PLL table.
    ///
    /// A silent S9 fallback would program the wrong dividers on any future
    /// silicon that enumerates an unregistered ID — refuse instead.
    #[test]
    fn unknown_chip_pll_does_not_silently_use_bm1387() {
        let bm1387_table = bm1387::pll_frequencies();
        assert!(
            !bm1387_table.is_empty(),
            "BM1387 table must exist for contrast"
        );

        // RE-pending sentinel and a few never-registered IDs.
        for unknown in [0x0000u16, 0xFFFF, BM1390_RE_PENDING_CHIP_ID, 0x1234, 0xABCD] {
            assert!(
                MinerProfile::try_pll_frequencies_for_chip(unknown).is_none(),
                "chip 0x{unknown:04X} must not resolve a PLL table"
            );
            let table = MinerProfile::pll_frequencies_for_chip(unknown);
            assert!(
                table.is_empty(),
                "chip 0x{unknown:04X} must return empty PLL slice, not BM1387"
            );
            assert_ne!(
                table.as_ptr(),
                bm1387_table.as_ptr(),
                "chip 0x{unknown:04X} must not alias the BM1387 table pointer"
            );
            assert!(
                !MinerProfile::has_pll_table(unknown),
                "chip 0x{unknown:04X} has_pll_table must be false"
            );
        }

        // Known production chips still resolve.
        for known in [0x1387u16, 0x1362, 0x1368, 0x1370, 0x1397, 0x1398] {
            assert!(
                MinerProfile::has_pll_table(known),
                "chip 0x{known:04X} must keep a registered PLL table"
            );
            assert!(!MinerProfile::pll_frequencies_for_chip(known).is_empty());
        }
    }

    #[test]
    fn snap_pll_floor_is_empty_safe_and_floors() {
        assert_eq!(MinerProfile::snap_pll_floor(&[], 500), None);
        let table = bm1387::pll_frequencies();
        assert!(!table.is_empty());
        let floor = MinerProfile::snap_pll_floor(table, 640).expect("non-empty");
        assert!(floor <= 640);
        assert!(table.contains(&floor));
        // Below entire table → lowest entry
        let lowest = *table.first().unwrap();
        assert_eq!(
            MinerProfile::snap_pll_floor(table, lowest.saturating_sub(1)),
            Some(lowest)
        );
    }

    #[test]
    fn snap_pll_next_above_is_empty_safe() {
        assert_eq!(MinerProfile::snap_pll_next_above(&[], 400), None);
        let table = bm1387::pll_frequencies();
        let mid = table[table.len() / 2];
        let next = MinerProfile::snap_pll_next_above(table, mid).expect("has higher");
        assert!(next > mid);
        let top = *table.last().unwrap();
        assert_eq!(MinerProfile::snap_pll_next_above(table, top), None);
    }

    /// P2-9: SV2 nominal GH/s comes from profile geometry, not a silent S9 constant.
    #[test]
    fn nominal_hashrate_ghs_scales_with_profile_and_refuses_unknown() {
        let s9 = MinerProfile::for_chip(0x1387).expect("S9 profile");
        let s9_ghs = s9.nominal_hashrate_ghs(650).expect("S9 rate");
        // ~3 chains × 63 chips × 650 × 0.114 ≈ 13.5e3 GH/s order of magnitude
        assert!(s9_ghs > 10_000.0 && s9_ghs < 20_000.0, "s9_ghs={s9_ghs}");

        let s19j = MinerProfile::for_chip(0x1362).expect("BM1362 profile");
        let s19_ghs = s19j.nominal_hashrate_ghs(525).expect("S19j rate");
        // Multi-TH class must not look like S9 default
        assert!(s19_ghs > 50_000.0, "s19_ghs={s19_ghs} should dwarf S9");

        assert!(MinerProfile::nominal_hashrate_ghs_for_chip(0xFFFF, 500).is_none());
        assert!(s9.nominal_hashrate_ghs(0).is_none());
    }

    /// Rank 20: unknown chip IDs must not inherit BM1387 114-core NPS.
    #[test]
    fn unknown_chip_geometry_refuses_silent_114_nps() {
        let bm1387 = MinerProfile::for_chip(0x1387).expect("BM1387 profile");
        assert_eq!(bm1387.nonce_attribution_cores, 114);
        assert_eq!(
            MinerProfile::try_nonce_attribution_cores_for_chip(0x1387),
            Some(114)
        );
        assert!(MinerProfile::try_expected_nps_for_chip(0x1387, 650, 256).is_some());
        assert!(MinerProfile::try_ghs_per_mhz_for_chip(0x1387).is_some());

        for unknown in [0x0000u16, 0xFFFF, BM1390_RE_PENDING_CHIP_ID, 0x1234, 0xABCD] {
            assert!(
                MinerProfile::for_chip(unknown).is_none(),
                "chip 0x{unknown:04X} must have no MinerProfile"
            );
            assert_eq!(
                MinerProfile::try_nonce_attribution_cores_for_chip(unknown),
                None,
                "chip 0x{unknown:04X} must not silently report 114 cores"
            );
            assert_eq!(
                MinerProfile::try_ghs_per_mhz_for_chip(unknown),
                None,
                "chip 0x{unknown:04X} must not silently report 0.114 GH/s/MHz"
            );
            assert_eq!(
                MinerProfile::try_expected_nps_for_chip(unknown, 650, 256),
                None,
                "chip 0x{unknown:04X} must not invent BM1387 expected-nps"
            );
        }
    }

    // W22 (parity #9): scaffold drivers register only when BOTH the lab
    // override AND the explicit stub-behavior acknowledgment are present — a
    // single stray env var must never load a stub driver onto live hardware.
    #[test]
    fn scaffold_drivers_require_both_gates() {
        assert!(
            !should_register_scaffold_drivers(false, false),
            "neither gate → no scaffold"
        );
        assert!(
            !should_register_scaffold_drivers(true, false),
            "lab override alone is NOT enough — the second confirmation gate must block"
        );
        assert!(
            !should_register_scaffold_drivers(false, true),
            "ack alone is NOT enough"
        );
        assert!(
            should_register_scaffold_drivers(true, true),
            "both gates → scaffold drivers register"
        );
        // The two gate env-var names are distinct (defense-in-depth).
        assert_ne!(ALLOW_SCAFFOLD_ASIC_DRIVERS_ENV, SCAFFOLD_STUB_ACK_ENV);
    }

    #[test]
    fn scaffold_and_re_pending_chip_ids_are_classified() {
        assert!(is_scaffold_driver_chip(bm1373::CHIP_ID));
        assert!(is_scaffold_driver_chip(bm1489::CHIP_ID));
        assert!(!is_scaffold_driver_chip(bm1362::CHIP_ID));
        assert!(is_re_pending_chip(BM1390_RE_PENDING_CHIP_ID));
        assert!(ChipRegistry::production()
            .detect(BM1390_RE_PENDING_CHIP_ID)
            .is_none());
    }

    /// PR-055 / R11-15: pins the corpus-confirmed Antminer **T21 = BM1368**
    /// silicon-identity contract so a future "cleanup" cannot silently
    /// re-flip T21 onto BM1370 or onto the `0x1390` RE-pending sentinel.
    ///
    /// Resolution + 10-source citation index:
    /// .
    /// Static-analysis only; additive; asserts existing constants — no
    /// value/behavior/API change. Mirrors the PR-054
    /// `pr054_s9_family_disambiguation` pin idiom.
    #[test]
    fn pr055_t21_asic_identity() {
        // T21's runtime die is BM1368 (chip ID 0x1368), DRIVEN on the
        // fleet S21 .135. Genealogy bible :62/:186 + master catalog :197
        // + EEPROM atlas :205-206 + silicon-profiles bm1368.rs:137/:332
        // (Bm1368HashboardSku::T21) + asic drivers/bm1368.rs:3 ("S21 and
        // T21") all agree.
        assert_eq!(
            bm1368::CHIP_ID,
            0x1368,
            "T21 die = BM1368 (0x1368) per PR-055 corpus resolution"
        );

        // BM1370 (0x1370) is the S21 Pro / S21 XP Pro/XP-variant die and
        // is NEVER T21 anywhere in the corpus (genealogy :63/:186,
        // bm1370.rs:1-2). Pin BM1370 distinct from the T21/BM1368 die.
        assert_eq!(bm1370::CHIP_ID, 0x1370);
        assert_ne!(
            bm1370::CHIP_ID,
            bm1368::CHIP_ID,
            "BM1370 (S21 Pro/XP) must stay distinct from the T21/BM1368 die"
        );

        // The 0x1390 RE-pending sentinel is NOT T21's silicon. An earlier
        // stray "BM1390/T21" doc-label on BM1390_RE_PENDING_CHIP_ID
        // (drivers/mod.rs) contradicted the 10 T21=BM1368 sources; this
        // regression-pins the correction so it cannot be re-introduced.
        assert_ne!(
            BM1390_RE_PENDING_CHIP_ID,
            bm1368::CHIP_ID,
            "the 0x1390 RE-pending sentinel must never be treated as T21's die"
        );
        assert_ne!(BM1390_RE_PENDING_CHIP_ID, bm1370::CHIP_ID);
        // The sentinel itself stays an RE-pending, non-production chip ID
        // (its guard semantics are unchanged by PR-055).
        assert!(is_re_pending_chip(BM1390_RE_PENDING_CHIP_ID));
        assert!(!is_re_pending_chip(bm1368::CHIP_ID));
    }

    /// PR-056 / R11-14: pins the corpus-confirmed BM1396-vs-BM1397
    /// dispatch contract so a future "cleanup" cannot silently treat
    /// the two 7 nm S17-class chips as interchangeable.
    ///
    /// Resolution + citation index:
    /// .
    /// Static-analysis only; additive; asserts existing constants +
    /// registry membership — no value/behavior/API change. Mirrors the
    /// PR-055 `pr055_t21_asic_identity` pin idiom.
    ///
    /// Verdict: BM1397 (`0x1397`, S17/T17/S17+/T17+) is recognized and has an
    /// exact-policy Experimental runtime driver. Exact signed S17e/T17e
    /// production binaries independently prove wire BM1396 (`0x1396`), but its
    /// live driver remains unregistered until PLL, carrier, and electrical
    /// safety contracts are complete. A literal `0x1396` still resolves to
    /// `detect()` → `None` and is NEVER silently mapped onto BM1397.
    #[test]
    fn pr056_bm1396_vs_bm1397_disambiguation() {
        // BM1397 is the recognized S17-class runtime die (0x1397).
        // Mujina protocol.rs:186 (BM1397 <-> [0x13,
        // 0x97]) + genealogy :58 + bm1393.rs:173 ("0x1397 (S17/T17)")
        // all agree.
        assert_eq!(
            bm1397::CHIP_ID,
            0x1397,
            "BM1397 S17-class runtime die = 0x1397 per PR-056 corpus resolution"
        );
        let production = ChipRegistry::production();
        let recognition = production
            .recognize(bm1397::CHIP_ID)
            .expect("BM1397 (0x1397) must remain recognized");
        assert_eq!(
            recognition.chip_name(),
            "BM1397",
            "0x1397 must retain BM1397 identity (S17/T17/S17+/T17+)"
        );
        assert_eq!(recognition.maturity(), ChipDriverMaturity::Experimental);
        assert!(production.detect(bm1397::CHIP_ID).is_none());
        assert!(ChipRegistry::with_experimental_driver(bm1397::CHIP_ID)
            .detect(bm1397::CHIP_ID)
            .is_some());

        // BM1396 is a proven wire identity but code-UNREGISTERED. A literal 0x1396
        // enumeration must fall through to None
        // — it is NEVER silently mapped onto the BM1397 driver. This
        // regression-pins the absence of the interchange path so a
        // future edit can't introduce a 0x1396 -> 0x1397 fall-through.
        const BM1396_WIRE_ID: u16 = dcentrald_common::BM1396_WIRE_CHIP_ID;
        assert!(
            production.detect(BM1396_WIRE_ID).is_none(),
            "BM1396 wire ID 0x1396 must NOT resolve to any registered driver — \
             the bm1396 scaffold is intentionally unregistered (see \
             2026-05-16-bm1396-vs-bm1397-disambiguation.md §1/§5)"
        );
        // Even with scaffold drivers enabled, BM1396 is not a scaffold
        // driver (only BM1373/BM1489 are) and never gets registered.
        assert!(
            ChipRegistry::with_scaffold_drivers()
                .detect(BM1396_WIRE_ID)
                .is_none(),
            "BM1396 is not a scaffold driver; it must stay unregistered \
             even when scaffold drivers are enabled"
        );

        // BM1396 is a distinct identity from BM1397 and from the
        // scaffold / RE-pending sentinels — it is neither interchangeable
        // with BM1397 nor a simulator/pre-hardware chip.
        assert_ne!(
            BM1396_WIRE_ID,
            bm1397::CHIP_ID,
            "BM1396 and BM1397 wire identities are distinct — never collapse them"
        );
        assert!(!is_scaffold_driver_chip(BM1396_WIRE_ID));
        assert!(!is_re_pending_chip(BM1396_WIRE_ID));
    }

    /// S15 (BM1391, `0x1391`) production-readiness DET contract (2026-07-02).
    ///
    /// The Antminer S15 uses the 7 nm BM1391 die and rides the am1 Xilinx-Zynq
    /// image with the "Broad Zynq-era Hash Board Auto-Detection" core feature:
    /// on a live S15, ChipID `0x1391` dispatches to the BM1391 driver. That
    /// driver is a JIG-OBSERVED but FAIL-CLOSED scaffold. Held evidence settles
    /// the S15's 3 × 60 × 256 geometry, but not the carrier, PIC, thermal, PLL,
    /// or energization contract, so it is:
    ///   - NOT in the default `production()` registry (a stray 0x1391 must NOT
    ///     silently load a scaffold onto a live miner → `detect` = None), and
    ///   - present in the double-env-gated scaffold registry, where a live
    ///     S15 bring-up (BP-S15-BRINGUP) enables it, enumerates, and the
    ///     scaffold's `init_chain` fail-closes until an operator validates it.
    /// This pins only the scaffold registry behavior. It does not promote the
    /// S15 acceptance row beyond `NOT-IMPLEMENTED` or authorize live bring-up.
    #[test]
    fn s15_bm1391_detect_is_scaffold_gated_not_production() {
        assert_eq!(bm1391::CHIP_ID, 0x1391, "S15 die = BM1391 = 0x1391");
        // Default production path: 0x1391 must NOT resolve — no silent scaffold
        // on a live miner.
        assert!(
            ChipRegistry::production().detect(bm1391::CHIP_ID).is_none(),
            "0x1391 (BM1391/S15) must be absent from the production registry \
             (fail-closed scaffold, no live S15 to validate)"
        );
        // Scaffold registry (operator double-ack): 0x1391 dispatches to BM1391.
        let scaffold = ChipRegistry::with_scaffold_drivers();
        let d = scaffold
            .detect(bm1391::CHIP_ID)
            .expect("0x1391 must dispatch to BM1391 in the scaffold registry");
        assert_eq!(d.chip_name(), "BM1391", "S15 auto-detect target");
        assert!(
            is_scaffold_driver_chip(bm1391::CHIP_ID),
            "BM1391 is a fail-closed scaffold chip"
        );
    }

    #[test]
    fn bm1393_detect_is_scaffold_gated_not_production() {
        assert!(ChipRegistry::production().detect(bm1393::CHIP_ID).is_none());
        let scaffold = ChipRegistry::with_scaffold_drivers();
        let driver = scaffold
            .detect(bm1393::CHIP_ID)
            .expect("explicit scaffold registry must expose exact BM1393 codec");
        assert_eq!(driver.chip_name(), "BM1393");
        assert_eq!(driver.cores_per_chip(), 208);
        assert!(is_scaffold_driver_chip(bm1393::CHIP_ID));
    }

    /// Safety pin: the scaffold/pre-hardware chip PROFILES (BM1373/BM1489) carry
    /// PLACEHOLDER voltages. `MinerProfile::for_chip` is an ungated metadata lookup
    /// that returns them, but the LIVE driver path is gated — `ChipRegistry::
    /// production().detect()` returns None for every scaffold chip (init_chain
    /// fail-closes). This pins BOTH halves so a future edit can neither (a) expose
    /// a scaffold chip to a real driver, nor (b) let a placeholder profile carry an
    /// OVER-voltage that could damage hardware if some path ever consumed the
    /// metadata: every scaffold profile's default_voltage_mv stays within the same
    /// safe envelope the dsPIC HAL hard-caps at (<= 14500 mV), so it cannot overvolt
    /// even if reached.
    #[test]
    fn scaffold_chip_profiles_are_live_gated_and_voltage_safe() {
        const SAFE_VOLTAGE_CAP_MV: u16 = 14_500; // dsPIC clamp_dspic_voltage_to_hard_cap
        let production = ChipRegistry::production();
        for chip_id in [
            bm1373::CHIP_ID,
            bm1489::CHIP_ID,
            bm1391::CHIP_ID,
            bm1393::CHIP_ID,
        ] {
            assert!(
                production.detect(chip_id).is_none(),
                "scaffold chip 0x{chip_id:04X} must be absent from the production registry (live-gated)"
            );
            assert!(is_scaffold_driver_chip(chip_id));
            if let Some(profile) = MinerProfile::for_chip(chip_id) {
                assert!(
                    profile.default_voltage_mv <= SAFE_VOLTAGE_CAP_MV,
                    "scaffold profile {} default_voltage_mv={} exceeds the safe cap {}mV",
                    profile.name,
                    profile.default_voltage_mv,
                    SAFE_VOLTAGE_CAP_MV
                );
            }
        }
    }

    /// W3-B: with the default-OFF `scrypt-l7` feature compiled, chip-id 0x1489
    /// dispatches to the W3-A-accurate ScryptL7 driver (which SUPERSEDES the
    /// stale `bm1489.rs` scaffold in the scaffold registry). Production stays
    /// closed either way (0x1489 is never in `production()`), so SHA256 builds
    /// are unaffected. Feature-gated so it only runs when the feature is on.
    #[cfg(feature = "scrypt-l7")]
    #[test]
    fn scrypt_l7_supersedes_bm1489_in_scaffold_registry() {
        // Production never resolves 0x1489 — feature or not.
        assert!(ChipRegistry::production().detect(0x1489).is_none());

        // Scaffold registry resolves 0x1489 to the ScryptL7 driver, identified
        // by its W3-A-confirmed 3.0 Mbaud ceiling (the stale scaffold was 1.5M).
        let scaffold = ChipRegistry::with_scaffold_drivers();
        let d = scaffold
            .detect(0x1489)
            .expect("0x1489 must dispatch in the scaffold registry");
        assert_eq!(d.chip_name(), "BM1489");
        assert_eq!(
            d.max_baud(),
            3_000_000,
            "0x1489 must resolve to the W3-A ScryptL7 driver (3.0 Mbaud), \
             not the stale bm1489 scaffold (1.5 Mbaud)"
        );
        assert_eq!(d.cores_per_chip(), 117, "ScryptL7 CoreNum=117 per W3-A");
        // Still classified as a scaffold chip (same chip-id).
        assert!(is_scaffold_driver_chip(0x1489));
    }

    #[test]
    fn td003_bm1366_profile_does_not_imply_dspic_voltage() {
        let profile = MinerProfile::for_chip(0x1366).expect("BM1366 profile registered");
        assert_eq!(profile.pic_type, PicType::NoPic);
        assert!(
            profile.pic_addrs.is_empty(),
            "generic BM1366 chip-id profile must not carry dsPIC/PIC addresses"
        );
    }
}
