//! BM1370 silicon characterization table (Antminer S21 Pro / S21+ /
//! S21 XP / BitAxe Gamma â€” bleeding-edge 3nm BM137x family).
//!
//! 5 discrete steps from `-2` (eco-low) to `+2` (overclock). Source
//! provenance:
//! - **`mining-bible-v1/_canonical/chip-init-sequences.md` lines 233-254**
//!   â€” BM1370 register-init: `cores_per_chip = 1024+`, MiscCtrl primer
//!   `= 0xF000C100` (S21 Pro variant â€” different from BM1366/1368),
//!   reg `0x54 = 0x00000002` (NOT 0x03 â€” different from other chips),
//!   reg `0x58 = 0x00011111` (S21 Pro variant â€” NOT 0x02111111),
//!   HASHCOUNTING `= 0x00001EB5`.
//! - **`general/BM1373_S23_RESEARCH.md` line 79**: "S21 Pro: 234 TH/s Ã·
//!   195 chips = 1.2 TH/s per chip (at 525 MHz)".
//! - **`general/BM1373_S23_RESEARCH.md` line 42**: "S21 Pro (BM1370):
//!   15 J/TH" nameplate.
//! - **`protocols/POWER_PROFILES_CATALOG.md` lines 1267-1270**: BM1370
//!   variants achieve 11.6-15.0 J/TH across the profile range.
//! - **Reconstructed**: linear extrapolation around the operator-known
//!   nameplate point.
//!
//! Sweet spot at Step -2 (~3,000 W / 215 TH/s â‰ˆ 14.0 J/TH) â€” slightly
//! better than the 15.0 J/TH nameplate. The BM1370 (3nm process) is
//! the bleeding edge of the SHA-256 catalog.

use crate::{Profile, ProfileSource, SiliconTable};

/// The 5 BM1370 silicon profile rows, ordered by `step`.
///
/// Voltage column is chain-rail voltage in volts. Hashrate column is
/// in TH/s summed across 1 board Ã— 195 chips (S21 Pro single-board
/// reference; multi-board variants scale proportionally).
pub const BM1370_PROFILES: [Profile; 5] = [
    Profile {
        step: -2,
        freq_mhz: 480,
        voltage_v: 13.4,
        wall_watts: Some(3000),
        hashrate_ths: Some(215.0),
        source: ProfileSource::Reconstructed,
    },
    Profile {
        step: -1,
        freq_mhz: 500,
        voltage_v: 13.6,
        wall_watts: Some(3220),
        hashrate_ths: Some(224.0),
        source: ProfileSource::Reconstructed,
    },
    Profile {
        step: 0,
        freq_mhz: 525,
        voltage_v: 13.8,
        wall_watts: Some(3510),
        hashrate_ths: Some(234.0), // S21 Pro nameplate
        source: ProfileSource::OperatorConfirmed,
    },
    Profile {
        step: 1,
        freq_mhz: 555,
        voltage_v: 14.0,
        wall_watts: Some(3820),
        hashrate_ths: Some(245.0),
        source: ProfileSource::Reconstructed,
    },
    Profile {
        step: 2,
        freq_mhz: 585,
        voltage_v: 14.2,
        wall_watts: Some(4150),
        hashrate_ths: Some(256.0),
        source: ProfileSource::Reconstructed,
    },
];

/// Canonical BM1370 silicon table. Default = nameplate (Step 0).
/// Sweet spot at Step -2 (~3,000 W / 215 TH/s â‰ˆ 14.0 J/TH).
pub const BM1370_TABLE: SiliconTable = SiliconTable {
    chip_family: "BM1370",
    profiles: &BM1370_PROFILES,
    default_step: 0,
    sweet_spot_step: -2,
    // No live unit on the fleet (S21 Pro pending). Driver +
    // register set lifted from  §7
    // and BM1368 family encoding (driver registered in
    // ChipRegistry::production for routing-only). Per-row source
    // is `OperatorConfirmed` (nameplate) + `Reconstructed` (rest).
    live_status: crate::ChipStatus::RegisterMappedFromRE,
};

/// Per-chip cores. 1280 = 80 domains x 16 small cores, matching this crate's
/// own `operating_points.rs` BM1370 rows, the `dcentrald-asic` BM1370 driver
/// (`CORES_PER_CHIP = 1280`), and the fixture-total ground truth — the same
/// source-conflict `bm1368.rs` documents and resolves to the fixture total.
/// (Was 1024 from a spec-block small-core-matrix misread, like the pre-fix
/// BM1368; reconciled to 1280 so a future consumer can't import the wrong value.)
pub const BM1370_CORES_PER_CHIP: u32 = 1280;

/// Per-chip hashrate at S21 Pro nameplate (per BM1373_S23_RESEARCH.md
/// line 79: 234 TH/s Ã· 195 chips â‰ˆ 1.2 TH/s per chip at 525 MHz).
pub const BM1370_PER_CHIP_HASHRATE_THS: f32 = 1.2;

/// Total BM1370 chips in a standard 3-hashboard Antminer S21 Pro (195).
///
/// This is the WHOLE-UNIT count, not a per-chain count. It was previously named
/// `BM1370_CHIPS_PER_CHAIN_S21_PRO`, which contradicted the sibling doc comment
/// on `BM1370_PER_CHIP_HASHRATE_THS` above ("234 TH/s / 195 chips") and put a
/// unit total into `serial_chip_count`, a documented per-chain field
/// (`dcentrald/src/config.rs`: "serial_chip_count is chips per chain, not the
/// 144-chip unit total").
pub const BM1370_CHIPS_TOTAL_S21_PRO: u32 = 195;

/// BM1370 chips on ONE Antminer S21 Pro hashboard chain (65).
///
/// Four independent held sources agree on 3 hashboards x 65 chips = 195 total:
/// - : "3 hashboards with 65 chips
///   each, for a total of 195 chips" at a 234 TH/s nameplate.
/// - : "Antminer S21 Pro
///   (65x BM1370 chips)", and "65 chips: `0x00001EB5` (S21 Pro)".
/// - : "Chips/chain |
///   65 (S21 Pro)".
/// - `dcentrald/src/model.rs` `s21pro` -> `chips_per_chain_hint: Some(65)`.
///
/// The HASHCOUNTING value `0x00001EB5` is the 65-128 chip bucket, which is
/// itself per-chain evidence (`MYSTERY_REGISTERS.md`).
pub const BM1370_CHIPS_PER_CHAIN_S21_PRO: u32 = 65;

/// Standard Antminer S21 Pro hashboard/chain count (3).
pub const BM1370_CHAIN_COUNT_S21_PRO: u32 = 3;

/// Standard S21 Pro chain count (1 â€” single-board variant; multi-board
/// air-cooled S21 Pro uses 3 chains scaled appropriately).
pub const BM1370_CHAIN_COUNT_S21_PRO_BAXE: u32 = 1;

// --- S21 XP / S21+ geometry (Lane J, 2026-09-01) -------------------------
// Resolved from two independent held sources that agree first-hand, closing
// BETA_ROSTER conflict #2 and the stale "4x220+" MASTER_MODEL_CATALOG cells:
//  - bosminer model-list.json (num_per_hb / num_domains / num_per_domain):
//
//    model-list.json, SHA-256 c79f56e2...
//  - ePIC jig hashboard DB (chain_num, ePIC-transcribed corroboration only):
//
//    epic-jig-hashboard-db-50models.json
// These are geometry only; they grant NO controller/energize authority (no
// live BM1370 unit; GPIO437 DMM-unverified; controller unresolved).

/// BM1370 chips on ONE Antminer S21 XP hashboard chain (91 = 13 domains x 7).
/// Held A3HB70501 (bosminer num_per_hb=91, num_domains=13, num_per_domain=7;
/// ePIC A3HB705xx chain_asic_num=91). model.rs `s21xp` -> hint Some(91).
pub const BM1370_CHIPS_PER_CHAIN_S21_XP: u32 = 91;

/// Standard Antminer S21 XP hashboard/chain count (3; ttyS3/ttyS2/ttyS1).
/// ePIC A3HB705xx chain_num=3; production UART route is three chains.
pub const BM1370_CHAIN_COUNT_S21_XP: u32 = 3;

/// Whole-unit BM1370 chip count for a standard 3-board S21 XP (273 = 3 x 91).
pub const BM1370_CHIPS_TOTAL_S21_XP: u32 = 273;

/// BM1370 chips on ONE Antminer S21+ hashboard chain (55 = 11 domains x 5).
/// Held A3HB70701 (bosminer num_per_hb=55, num_domains=11, num_per_domain=5;
/// ePIC A3HB707xx chain_asic_num=55). model.rs `s21plus` -> hint Some(55).
pub const BM1370_CHIPS_PER_CHAIN_S21_PLUS: u32 = 55;

/// Standard Antminer S21+ hashboard/chain count (3; ePIC A3HB707xx chain_num=3).
pub const BM1370_CHAIN_COUNT_S21_PLUS: u32 = 3;

/// Whole-unit BM1370 chip count for a standard 3-board S21+ (165 = 3 x 55).
pub const BM1370_CHIPS_TOTAL_S21_PLUS: u32 = 165;

/// Operational baud after baud-upgrade (Bitmain firmware path).
pub const BM1370_OPERATIONAL_BAUD: u32 = 3_125_000;

/// Canonical MiscCtrl primer (S21 Pro variant â€” DIFFERENT from
/// BM1366/1368's 0xFF0FC100). Per chip-init-sequences.md line 250.
pub const BM1370_MISCCTRL_PRIMER: u32 = 0xF000_C100;

/// Register 0x54 (AnalogMux) â€” S21 Pro variant. NOT 0x03 like other
/// chips. Per chip-init-sequences.md line 251.
pub const BM1370_REG_54: u32 = 0x0000_0002;

// ── HashSource S21xp single_board_test RE (2026-06-10) ────────────────────
// Byte-exact from the Bitmain S21 XP single_board_test binary, decompiled
// corpus
// single_board_test.dec/` (S21xp is the canonical BM1370 jig image; S21pro
// omits BM1370 from get_result). CATALOG/REFERENCE — independently re-confirms
// the shipped VCO clamp. The PLL register *addresses*
// (pllparameter_register_array[0..2]) are now RE-CONFIRMED byte-exact from
// the jig .data (see BM1370_PLL_REGISTER_ADDRS below; 2026-07-02 Ghidra
// extraction) -- this closes the former "needs a live read" gap. See
//  and
//

/// BM1370 numeric chip-ID = 0x1370 (`get_asic_name@2F688.c`).
pub const BM1370_CHIP_ID: u32 = 0x0000_1370;

/// BM1370 PLL VCO range, RE-confirmed: 2000-3200 MHz at refdiv=2, or
/// 2000-3125 MHz at refdiv=1. `set_pllparameter@CADF8.c`.
pub const BM1370_VCO_MIN_MHZ: u32 = 2000;
pub const BM1370_VCO_MAX_MHZ: u32 = 3200;
pub const BM1370_VCO_MAX_MHZ_REFDIV1: u32 = 3125;

/// BM1370 PLL feedback-divider (fbdiv) range, RE-confirmed 16-250; up to 3
/// independent PLLs. `get_pllparam_divider@CB644.c`.
pub const BM1370_FBDIV_MIN: u32 = 16;
pub const BM1370_FBDIV_MAX: u32 = 250;
/// Count of RE-mapped PLLs (SSOT: `dcentrald_common::BM1370_PLL_COUNT`).
pub const BM1370_PLL_COUNT: u32 = dcentrald_common::BM1370_PLL_COUNT as u32;

/// BM1370 per-PLL chip-register addresses -- the on-wire SET_CONFIG register
/// each PLL's divider word is written to, indexed by pll_id 0..2.
///
/// RE-CONFIRMED byte-exact 2026-07-02 from the Bitmain S21 Pro
/// `single_board_test` jig binary: `pllparameter_register_array @ .data
/// 0x001fa848 = {0x08, 0x60, 0x64}`, independently corroborated by the
/// same three-byte selector used for `which_pll` in `set_pllparameter`, passed straight to
/// `send_set_config_command` as the register byte in `set_pllparameter`
/// (@0xCADF8, guarded by `which_pll < 3`). PLL1 == 0x60 matches the
/// previously-known BM1370 PLL1 address exactly, which anchors the
/// `[PLL0, PLL1, PLL2]` ordering. Closes the "needs a live read" gap; this
/// is desk-RE ground truth, not a bench promotion of the S21 Pro SKU.
/// Per-PLL SET_CONFIG register map — SSOT re-export from `dcentrald_common` (P1-4).
pub const BM1370_PLL_REGISTER_ADDRS: [u8; 3] = dcentrald_common::BM1370_PLL_REGISTER_ADDRS;

/// BM1370 PLL0 chip-register address (0x08). See [`BM1370_PLL_REGISTER_ADDRS`].
pub const BM1370_PLL0_REG_ADDR: u8 = dcentrald_common::BM1370_PLL_REGISTER_ADDRS[0];
/// BM1370 PLL1 chip-register address (0x60) -- matches the long-known value.
pub const BM1370_PLL1_REG_ADDR: u8 = dcentrald_common::BM1370_PLL_REGISTER_ADDRS[1];
/// BM1370 PLL2 chip-register address (0x64). See [`BM1370_PLL_REGISTER_ADDRS`].
pub const BM1370_PLL2_REG_ADDR: u8 = dcentrald_common::BM1370_PLL_REGISTER_ADDRS[2];

/// BM1370 SET_ADDRESS command byte = 0x40 (5-byte, CRC5 poly x^5+x^2+1,
/// init 0x1F). `generate_set_address_command@CC680.c`.
pub const BM1370_CMD_SET_ADDRESS: u8 = 0x40;

// S21 Pro/XP board DC-DC: TI DAC53401 on board "NBT2006-36". 10-bit N
// left-justified (data[0]=N>>6, data[1]=N<<2). `set_dac53401_voltage@4B718.c`.
//
// CORRECTION (2026-07-27). This was a single constant
// `BM1370_DAC53401_I2C_ADDR = 0x21`, which labelled the DAC-DATA REGISTER as
// the I2C slave address. The vendor decompilation settles it:
//
//   pic_write_iic(uint8_t which_chain, uint8_t slave, uint8_t reg, ...)   // @C5C3C
//   write_dac(...)            -> dac_addr = 72;  pic_write_iic(chain, 72u, which_reg, ...)   // @4B0C8
//   set_dac53401_voltage(...) -> write_dac(which_chain, 1u, 33u, data, 2)                    // @4B718
//
// 72 = 0x48 is the SLAVE; 33 = 0x21 is the register that receives the code.
// The sibling `bm1366` module already had this right, so the two modules
// disagreed about the same part. Split into the full trio and named to match
// `bm1366::DAC53401_*` so a future reader compares like with like.
//
// This constant had zero consumers workspace-wide, so the mislabel was a latent
// trap rather than a live bug -- and renaming it is compile-safe by
// construction. Deliberately NOT kept as a deprecated alias: the old name is
// the trap.

/// TI DAC53401 I2C slave address on the NBT2006-36 board rail (7-bit).
pub const BM1370_DAC53401_I2C_ADDR_SLAVE: u8 = 0x48;

/// DAC-DATA register that receives the `N << 2` code (big-endian u16).
pub const BM1370_DAC53401_DATA_REG: u8 = 0x21;

/// Config/init register poked during `init_dac53401_NBT2006_36`.
pub const BM1370_DAC53401_INIT_REG: u8 = 0xD1;

/// Register 0x58 (IO Driver Strength) â€” S21 Pro variant.
/// NOT 0x02111111 like other chips. Per chip-init-sequences.md line 252.
pub const BM1370_REG_58: u32 = 0x0001_1111;

/// HASHCOUNTING register value for stock S21 Pro.
/// Per chip-init-sequences.md line 253.
pub const BM1370_HASHCOUNTING_S21_PRO_STOCK: u32 = 0x0000_1EB5;

// ── BM1370 algorithmic PLL resolver (2026-07-02 Ghidra extraction) ──────────
//
// EXECUTED extraction from the Bitmain S21 Pro `single_board_test` jig
// (`get_pllparam_divider @ 0x000cb644`, ARM32). This is the piece that turns a
// target frequency into the on-wire divider tuple — the constants above pinned
// the *ranges*, but nothing computed the params. RE-ASK-02 hypothesised a
// per-frequency VALUE table; the jig proves there is NONE — it COMPUTES the
// dividers at runtime (the same shape as the BM1362 `pll_compute`).
//
// Decompiled algorithm (variable roles recovered from the pseudocode):
//   ref = 25 MHz (crystal); refdiv ∈ {2,1}; pd1 ∈ {1..7}; pd2 ∈ {pd1..7}
//   fbdiv = round(pd1 * pd2 * target * refdiv / ref)     // computed, not iterated
//   VCO   = fbdiv * ref / refdiv    ∈ [2000, 3200]       // ≤ 3125 when refdiv==1
//   fbdiv ∈ [16, 250]
//   achieved = VCO / (pd1 * pd2) = ref * fbdiv / (refdiv * pd1 * pd2)
//   pick the (refdiv,pd1,pd2,fbdiv) minimising |target - achieved|.
// VCO limits are the exact float32 constants read from the jig constant pool at
// 0x000cb7a0/a4/a8 = {3125.0, 3200.0, 2000.0} (LE). fbdiv range from the
// `iVar12 - 0x10 < 0xeb` guard. Provenance:
//

/// BM1370 PLL reference clock (crystal) in MHz — 25 MHz on S21-class boards.
pub const BM1370_REF_CLOCK_MHZ: u32 = 25;

/// BM1370 outer reference-divider values the jig searches, in {1, 2}.
pub const BM1370_REFDIV_VALUES: [u8; 2] = [1, 2];

/// BM1370 post-divider bound (both post-dividers are 1..=7, and pd2 >= pd1).
pub const BM1370_POSTDIV_MAX: u8 = 7;

/// A resolved BM1370 PLL divider set produced by [`bm1370_pll_compute`].
///
/// On-wire the jig stores (`postdiv2`, `postdiv1`, `refdiv`, `fbdiv`) into the
/// per-PLL divider word written to [`BM1370_PLL_REGISTER_ADDRS`]. Frequency is
/// commutative in the two post-dividers; we keep `postdiv1 <= postdiv2` (the
/// jig's `pd2` starts at `pd1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1370PllParams {
    pub refdiv: u8,
    pub fbdiv: u16,
    pub postdiv1: u8,
    pub postdiv2: u8,
}

impl Bm1370PllParams {
    /// Intermediate VCO frequency (MHz, truncated) = `fbdiv * ref / refdiv`.
    pub const fn vco_mhz(&self, ref_mhz: u32) -> u32 {
        if self.refdiv == 0 {
            return 0;
        }
        (ref_mhz * self.fbdiv as u32) / self.refdiv as u32
    }

    /// Output frequency (MHz, truncated) for these dividers at `ref_mhz`.
    /// `f_out = ref * fbdiv / (refdiv * postdiv1 * postdiv2)`. Multiply before
    /// dividing (u64) so a non-unit refdiv keeps precision; returns 0 on a
    /// zero divider (defensive — never produced by [`bm1370_pll_compute`]).
    pub const fn compute_freq_mhz(&self, ref_mhz: u32) -> u32 {
        let den = (self.refdiv as u64) * (self.postdiv1 as u64) * (self.postdiv2 as u64);
        if den == 0 {
            return 0;
        }
        (((ref_mhz as u64) * (self.fbdiv as u64)) / den) as u32
    }
}

/// Algorithmically resolve `target_mhz` into a BM1370 PLL divider set at
/// reference clock `ref_mhz` (25 MHz on stock hardware), faithfully mirroring
/// the jig's `get_pllparam_divider` search.
///
/// Returns the combination minimising the absolute frequency error whose VCO
/// and fbdiv satisfy the RE-confirmed envelope, or `None` when no in-range
/// candidate exists (target outside the achievable band, or a zero input).
///
/// Pure function — no I/O, no panics. Scoring uses milli-MHz integer math so
/// two candidates are compared without floating point (deterministic across
/// targets, unlike the jig's `float` accumulator, but selecting the same
/// minimum-error winner for every reachable target).
pub fn bm1370_pll_compute(target_mhz: u32, ref_mhz: u32) -> Option<Bm1370PllParams> {
    if target_mhz == 0 || ref_mhz == 0 {
        return None;
    }
    let mut best: Option<Bm1370PllParams> = None;
    let mut best_err_milli: u64 = u64::MAX;

    // Jig loop order: refdiv 2→1, pd1 1→7, pd2 pd1→7. We keep the same nesting
    // so that on an exact-error tie the first-found winner matches the jig.
    for &refdiv in BM1370_REFDIV_VALUES.iter().rev() {
        for pd1 in 1..=BM1370_POSTDIV_MAX {
            for pd2 in pd1..=BM1370_POSTDIV_MAX {
                // fbdiv = round(pd1 * pd2 * target * refdiv / ref) — computed,
                // not iterated, exactly as the jig does.
                let num = (pd1 as u64) * (pd2 as u64) * (target_mhz as u64) * (refdiv as u64);
                let fbdiv = (num + (ref_mhz as u64) / 2) / (ref_mhz as u64);
                if fbdiv < BM1370_FBDIV_MIN as u64 || fbdiv > BM1370_FBDIV_MAX as u64 {
                    continue;
                }
                // VCO = fbdiv * ref / refdiv ∈ [2000, 3200]; ≤ 3125 when refdiv==1.
                let vco = ((fbdiv * ref_mhz as u64) / refdiv as u64) as u32;
                if !(BM1370_VCO_MIN_MHZ..=BM1370_VCO_MAX_MHZ).contains(&vco) {
                    continue;
                }
                if refdiv == 1 && vco > BM1370_VCO_MAX_MHZ_REFDIV1 {
                    continue;
                }
                // achieved (milli-MHz) = ref * fbdiv * 1000 / (refdiv*pd1*pd2).
                let den = (refdiv as u64) * (pd1 as u64) * (pd2 as u64);
                let achieved_milli = ((ref_mhz as u64) * fbdiv * 1000) / den;
                let target_milli = (target_mhz as u64) * 1000;
                let err = achieved_milli.abs_diff(target_milli);
                if err < best_err_milli {
                    best_err_milli = err;
                    best = Some(Bm1370PllParams {
                        refdiv,
                        fbdiv: fbdiv as u16,
                        postdiv1: pd1,
                        postdiv2: pd2,
                    });
                }
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_five_steps_in_correct_range() {
        assert_eq!(BM1370_TABLE.profiles.len(), 5);
        assert_eq!(BM1370_TABLE.min_step(), -2);
        assert_eq!(BM1370_TABLE.max_step(), 2);
    }

    /// The DAC53401 is the same TI part on both boards, so the two modules must
    /// not disagree about which byte is the slave and which is the register.
    ///
    /// They did: `bm1370` carried a single `..._I2C_ADDR = 0x21`, naming the
    /// DAC-DATA register as the slave, while `bm1366` had the correct trio. A
    /// cross-module equality is the cheapest thing that makes that class of
    /// drift impossible to reintroduce silently in either direction.
    #[test]
    fn dac53401_addressing_agrees_with_the_bm1366_module() {
        use crate::bm1366;

        assert_eq!(
            BM1370_DAC53401_I2C_ADDR_SLAVE,
            bm1366::DAC53401_I2C_ADDR,
            "DAC53401 slave address disagrees across chip modules; the vendor's \
             write_dac@4B0C8 passes 72 (0x48) as `slave` to \
             pic_write_iic(chain, slave, reg, ..)"
        );
        assert_eq!(
            BM1370_DAC53401_DATA_REG,
            bm1366::DAC53401_DATA_REG,
            "DAC53401 data register disagrees across chip modules; \
             set_dac53401_voltage@4B718 passes 33 (0x21) as `which_reg`"
        );
        assert_eq!(
            BM1370_DAC53401_INIT_REG,
            bm1366::DAC53401_INIT_REG,
            "DAC53401 init/config register disagrees across chip modules"
        );

        // The two roles must stay distinct. If a future edit collapses them
        // back to one value, the equalities above would still pass.
        assert_ne!(
            BM1370_DAC53401_I2C_ADDR_SLAVE, BM1370_DAC53401_DATA_REG,
            "slave address and data register must not be the same byte — \
             conflating them is exactly the defect this test was added for"
        );
    }

    #[test]
    fn pll_register_addrs_re_confirmed_from_jig() {
        // Byte-exact from the S21 Pro single_board_test jig:
        // pllparameter_register_array @ .data 0x001fa848 = {0x08, 0x60, 0x64},
        // corroborated by the same three-byte selector used for which_pll in
        // set_pllparameter@0xCADF8. PLL1 must equal the long-known 0x60, which
        // anchors the [PLL0, PLL1, PLL2] ordering (2026-07-02 extraction).
        assert_eq!(BM1370_PLL_REGISTER_ADDRS, [0x08, 0x60, 0x64]);
        assert_eq!(BM1370_PLL1_REG_ADDR, 0x60);
        assert_eq!(BM1370_PLL_REGISTER_ADDRS[0], BM1370_PLL0_REG_ADDR);
        assert_eq!(BM1370_PLL_REGISTER_ADDRS[1], BM1370_PLL1_REG_ADDR);
        assert_eq!(BM1370_PLL_REGISTER_ADDRS[2], BM1370_PLL2_REG_ADDR);
        assert_eq!(BM1370_PLL_COUNT as usize, BM1370_PLL_REGISTER_ADDRS.len());
    }

    #[test]
    fn nameplate_default_step_anchors_s21_pro() {
        // S21 Pro nameplate: 234 TH/s @ 3,510 W â†’ â‰ˆ 15.0 J/TH.
        let default = BM1370_TABLE.default_profile().unwrap();
        assert_eq!(default.wall_watts, Some(3510));
        assert!((default.hashrate_ths.unwrap() - 234.0).abs() < 1e-3);
        let eff = default.watts_per_ths().unwrap();
        assert!(
            (14.5..=16.0).contains(&eff),
            "S21 Pro nameplate efficiency {} W/TH outside [14.5, 16.0]",
            eff
        );
    }

    #[test]
    fn pre_baked_sweet_spot_matches_computed_minimum() {
        let pre = BM1370_TABLE.sweet_spot_profile().unwrap();
        let computed = BM1370_TABLE.computed_sweet_spot().unwrap();
        assert_eq!(pre.step, computed.step);
    }

    #[test]
    fn underclocked_steps_beat_default_efficiency() {
        let default = BM1370_TABLE.default_profile().unwrap();
        let eff_def = default.watts_per_ths().unwrap();
        for step in [-2, -1] {
            let s = BM1370_TABLE.by_step(step).unwrap();
            let eff = s.watts_per_ths().unwrap();
            assert!(
                eff < eff_def,
                "step {} efficiency ({}) should beat default ({})",
                step,
                eff,
                eff_def
            );
        }
    }

    #[test]
    fn s21_pro_per_chip_hashrate_matches_re_doc() {
        // BM1373_S23_RESEARCH.md line 79: 234 TH/s Ã· 195 chips â‰ˆ 1.2 TH/s
        // per chip at 525 MHz.
        assert!((BM1370_PER_CHIP_HASHRATE_THS - 1.2).abs() < 1e-3);
        assert_eq!(BM1370_CHIPS_TOTAL_S21_PRO, 195);
        // 195 chips Ã— 1.2 TH/s â‰ˆ 234 TH/s â€” anchor matches.
        let computed_total = (BM1370_CHIPS_TOTAL_S21_PRO as f32) * BM1370_PER_CHIP_HASHRATE_THS;
        assert!(
            (computed_total - 234.0).abs() < 1.0,
            "computed {} TH/s should match S21 Pro nameplate 234 TH/s",
            computed_total
        );
    }

    /// Per-chain and whole-unit S21 Pro geometry must stay distinguishable.
    ///
    /// The two were previously the same constant named `..._CHIPS_PER_CHAIN_...`
    /// while holding the unit total (195). That mislabel is how the shipped
    /// `am3-s21pro/etc/dcentrald.toml` came to put 195 into `serial_chip_count`,
    /// a per-chain field. Pin the relationship so the names cannot drift back.
    #[test]
    fn s21_pro_per_chain_times_chain_count_is_the_unit_total() {
        assert_eq!(BM1370_CHIPS_PER_CHAIN_S21_PRO, 65);
        assert_eq!(BM1370_CHAIN_COUNT_S21_PRO, 3);
        assert_eq!(
            BM1370_CHIPS_PER_CHAIN_S21_PRO * BM1370_CHAIN_COUNT_S21_PRO,
            BM1370_CHIPS_TOTAL_S21_PRO,
            "3 hashboards x 65 BM1370 must equal the 195-chip S21 Pro total"
        );
        assert_ne!(
            BM1370_CHIPS_PER_CHAIN_S21_PRO, BM1370_CHIPS_TOTAL_S21_PRO,
            "per-chain must never be re-aliased to the unit total"
        );
    }

    /// S21 XP and S21+ resolved geometry (Lane J, 2026-09-01). Two independent
    /// held sources agree: bosminer model-list.json per-board counts (91/55) and
    /// the ePIC jig hashboard DB chain_num=3. Pin the per-chain x chain-count =
    /// unit-total relationship so the falsified "4x220+" cannot return.
    #[test]
    fn s21xp_and_s21plus_geometry_is_three_boards_times_the_held_per_board_count() {
        // S21 XP: A3HB70501, 13 domains x 7 = 91/board, 3 boards = 273.
        assert_eq!(BM1370_CHIPS_PER_CHAIN_S21_XP, 91);
        assert_eq!(BM1370_CHAIN_COUNT_S21_XP, 3);
        assert_eq!(
            BM1370_CHIPS_PER_CHAIN_S21_XP * BM1370_CHAIN_COUNT_S21_XP,
            BM1370_CHIPS_TOTAL_S21_XP,
            "3 x 91 BM1370 must equal the 273-chip S21 XP full SKU"
        );
        assert_ne!(BM1370_CHIPS_PER_CHAIN_S21_XP, BM1370_CHIPS_TOTAL_S21_XP);

        // S21+: A3HB70701, 11 domains x 5 = 55/board, 3 boards = 165.
        assert_eq!(BM1370_CHIPS_PER_CHAIN_S21_PLUS, 55);
        assert_eq!(BM1370_CHAIN_COUNT_S21_PLUS, 3);
        assert_eq!(
            BM1370_CHIPS_PER_CHAIN_S21_PLUS * BM1370_CHAIN_COUNT_S21_PLUS,
            BM1370_CHIPS_TOTAL_S21_PLUS,
            "3 x 55 BM1370 must equal the 165-chip S21+ full SKU"
        );

        // The three BM1370 air SKUs are distinct per-board geometries; none is
        // the falsified 220-chip machine.
        assert_ne!(BM1370_CHIPS_PER_CHAIN_S21_PRO, BM1370_CHIPS_PER_CHAIN_S21_XP);
        assert_ne!(BM1370_CHIPS_PER_CHAIN_S21_XP, BM1370_CHIPS_PER_CHAIN_S21_PLUS);
        assert_ne!(BM1370_CHIPS_TOTAL_S21_XP, 220);
        assert_ne!(BM1370_CHIPS_TOTAL_S21_PLUS, 220);
    }

    #[test]
    fn miscctrl_primer_is_s21_pro_variant() {
        // chip-init-sequences.md line 250: BM1370 uses 0xF000C100
        // (S21 Pro variant). NOT 0xFF0FC100 like BM1366/1368.
        assert_eq!(BM1370_MISCCTRL_PRIMER, 0xF000_C100);
        assert_ne!(BM1370_MISCCTRL_PRIMER, 0xFF0F_C100);
    }

    #[test]
    fn reg_54_is_two_not_three() {
        // chip-init-sequences.md line 251: "reg 0x54 = 0x00000002
        // (NOT 0x03 â€” different from other chips!)".
        assert_eq!(BM1370_REG_54, 0x0000_0002);
        assert_ne!(BM1370_REG_54, 0x0000_0003);
    }

    #[test]
    fn reg_58_is_s21_pro_variant() {
        // chip-init-sequences.md line 252: "reg 0x58 = 0x00011111
        // (S21 Pro variant â€” NOT 0x02111111)".
        assert_eq!(BM1370_REG_58, 0x0001_1111);
        assert_ne!(BM1370_REG_58, 0x0211_1111);
    }

    #[test]
    fn hashcounting_value_matches_re_doc() {
        // chip-init-sequences.md line 253: 0x00001EB5.
        assert_eq!(BM1370_HASHCOUNTING_S21_PRO_STOCK, 0x0000_1EB5);
    }

    #[test]
    fn operational_baud_matches_bitmain_path() {
        assert_eq!(BM1370_OPERATIONAL_BAUD, 3_125_000);
    }

    #[test]
    fn step_voltage_increases_with_frequency() {
        for window in BM1370_PROFILES.windows(2) {
            assert!(
                window[1].voltage_v >= window[0].voltage_v,
                "voltage non-monotonic at step {}",
                window[1].step
            );
            assert!(
                window[1].freq_mhz > window[0].freq_mhz,
                "frequency non-monotonic at step {}",
                window[1].step
            );
        }
    }

    #[test]
    fn s21_pro_efficiency_beats_s21_efficiency() {
        // BM1370 (3nm) should beat BM1368 (5nm) per generation jump.
        // Nameplate: 15.0 J/TH vs 17.5 J/TH.
        let bm1370_eff = BM1370_TABLE
            .default_profile()
            .unwrap()
            .watts_per_ths()
            .unwrap();
        assert!(
            bm1370_eff < 17.0,
            "BM1370 nameplate efficiency {} W/TH should beat BM1368's ~17.5",
            bm1370_eff
        );
    }

    #[test]
    fn json_round_trip_preserves_profile_fields() {
        let original = BM1370_TABLE.by_step(0).unwrap();
        let json = serde_json::to_string(original).unwrap();
        let recovered: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(*original, recovered);
    }

    // ── PLL resolver (2026-07-02 Ghidra extraction of get_pllparam_divider) ──

    #[test]
    fn pll_vco_limits_match_jig_constant_pool() {
        // float32 LE read from single_board_test @ 0x000cb7a0/a4/a8:
        // {3125.0, 3200.0, 2000.0}. Pin them so a future edit that widens the
        // envelope must be deliberate.
        assert_eq!(BM1370_VCO_MAX_MHZ_REFDIV1, 3125);
        assert_eq!(BM1370_VCO_MAX_MHZ, 3200);
        assert_eq!(BM1370_VCO_MIN_MHZ, 2000);
        assert_eq!(BM1370_FBDIV_MIN, 16);
        assert_eq!(BM1370_FBDIV_MAX, 250);
        assert_eq!(BM1370_REF_CLOCK_MHZ, 25);
    }

    #[test]
    fn pll_resolves_every_canonical_s21_pro_frequency_exactly() {
        // All 5 shipped profile freqs are exactly reachable at ref=25 MHz.
        for p in BM1370_PROFILES.iter() {
            let params = bm1370_pll_compute(p.freq_mhz, BM1370_REF_CLOCK_MHZ)
                .unwrap_or_else(|| panic!("no PLL solution for {} MHz", p.freq_mhz));
            let achieved = params.compute_freq_mhz(BM1370_REF_CLOCK_MHZ);
            assert_eq!(
                achieved, p.freq_mhz,
                "step {} target {} MHz resolved to {} MHz via {:?}",
                p.step, p.freq_mhz, achieved, params
            );
            // Every returned candidate must satisfy the RE-confirmed VCO band.
            let vco = params.vco_mhz(BM1370_REF_CLOCK_MHZ);
            assert!(
                (BM1370_VCO_MIN_MHZ..=BM1370_VCO_MAX_MHZ).contains(&vco),
                "{} MHz: VCO {} outside [2000,3200] via {:?}",
                p.freq_mhz,
                vco,
                params
            );
            if params.refdiv == 1 {
                assert!(
                    vco <= BM1370_VCO_MAX_MHZ_REFDIV1,
                    "{} MHz: refdiv=1 VCO {} exceeds 3125 via {:?}",
                    p.freq_mhz,
                    vco,
                    params
                );
            }
        }
    }

    #[test]
    fn pll_525_matches_hand_derived_dividers() {
        // The jig searches refdiv=2 before refdiv=1, then pd1 ascending and
        // pd2 from pd1..=7. The first strict-error winner for 525 MHz is
        // (refdiv=2, pd1=1, pd2=4, fbdiv=168), VCO=2100 MHz.
        let p = bm1370_pll_compute(525, 25).unwrap();
        assert_eq!(
            p,
            Bm1370PllParams {
                refdiv: 2,
                fbdiv: 168,
                postdiv1: 1,
                postdiv2: 4,
            }
        );
        assert_eq!(p.compute_freq_mhz(25), 525);
        assert_eq!(p.fbdiv as u32 * 25 / p.refdiv as u32, p.vco_mhz(25));
        // The product refdiv*pd1*pd2 with fbdiv must reproduce 525 exactly.
        assert_eq!(
            25 * p.fbdiv as u32,
            525 * (p.refdiv as u32 * p.postdiv1 as u32 * p.postdiv2 as u32)
        );
    }

    #[test]
    fn pll_resolver_invariants_hold_across_a_sweep() {
        // Every reachable target in the mining band yields a candidate whose
        // dividers are in the extracted ranges and whose VCO obeys the limits.
        for target in (400u32..=650).step_by(5) {
            if let Some(p) = bm1370_pll_compute(target, 25) {
                assert!((1..=7).contains(&p.postdiv1));
                assert!((1..=7).contains(&p.postdiv2));
                assert!(p.postdiv2 >= p.postdiv1, "jig keeps pd2 >= pd1");
                assert!(p.refdiv == 1 || p.refdiv == 2);
                assert!((BM1370_FBDIV_MIN as u16..=BM1370_FBDIV_MAX as u16).contains(&p.fbdiv));
                let vco = p.vco_mhz(25);
                assert!((BM1370_VCO_MIN_MHZ..=BM1370_VCO_MAX_MHZ).contains(&vco));
                if p.refdiv == 1 {
                    assert!(vco <= BM1370_VCO_MAX_MHZ_REFDIV1);
                }
                // Achieved is within the PLL divider granularity of the target.
                // Canonical profile freqs are EXACT (proven in the test above);
                // arbitrary grid targets are limited by the integer
                // (refdiv,pd1,pd2,fbdiv) lattice, so allow a few MHz (e.g.
                // 645 → 643 is the true nearest reachable point, not a bug).
                let achieved = p.compute_freq_mhz(25) as i64;
                assert!(
                    (achieved - target as i64).abs() <= 5,
                    "{target} → {achieved}"
                );
            }
        }
    }

    #[test]
    fn pll_rejects_out_of_envelope_and_zero_inputs() {
        // Below the ~40 MHz floor and above the ~3125 MHz ceiling there is no
        // in-range candidate → None (mirrors the jig returning 0xffffffff).
        assert!(bm1370_pll_compute(10, 25).is_none());
        assert!(bm1370_pll_compute(4000, 25).is_none());
        assert!(bm1370_pll_compute(0, 25).is_none());
        assert!(bm1370_pll_compute(525, 0).is_none());
    }
}
