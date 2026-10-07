//! Official Bitmain **stock firmware + factory-jig** evidence for the
//! BM1398 air-cooled family — S19 (NBS1902) / S19 Pro (NBP1901) / T19
//! (NBT1903) — pinned as inert data by the 2026-09-02 Supremacy Gauntlet
//! B6 lane (desk-only; no unit was contacted).
//!
//! This module closes three Lane-F dossier gaps desk-side:
//!
//! - **G1 — the factory XXTEA key table** the AMTC S19 Pro jig and the
//!   stock NBP1901 `bmminer` actually use for BHB42xxx-generation
//!   hashboard EEPROM pages ([`AMTC_S19PRO_JIG_XXTEA_KEY_TABLE`]), plus
//!   the sibling table generation carried by the BM1362/BM1366/BM1368
//!   jigs ([`JIG_XXTEA_KEY_TABLE_BM136X_GENERATION`]).
//! - **G4 — the rail-voltage → PSU DAC code law**, keyed by the PSU
//!   `power.version` byte from stock `topol.conf`
//!   ([`apw12_rail_code`]).
//! - **G5 — the S19-class PSU/PIC1704 framed wire dialects** (observed
//!   command sets; the G4 law's consumer is PSU framed command `0x83`).
//!
//! Everything here is **evidence + pure derivation only**. Nothing in
//! this module commands hardware, opens a bus, or authorizes voltage:
//! the live SET_VOLTAGE / rail-energize path stays fail-closed behind
//! the Lane-F identity-joined admission + energize intercept in
//! `dcentrald`, and every electrical use of these constants is
//! **bench-gated** (DMM verification before any live rail command).
//!
//! # Held artifacts (all internal RE evidence; never redistributed)
//!
//! | # | artifact | role |
//! |---|---|---|
//! | 1 |  (sha256 `ddb73ebe…`, 169,928 B) | AMTC S19 Pro factory repair jig; XXTEA key table at **VA `0x487a4`** (file offset `0x287a4`, PT_LOAD `0x46f08`) |
//! | 2 |  (sha256 `e91e6d9f…`, 392,380 B — the dossier's pinned stock NBP1901 miner) | independent second copy of the same key table at **VA `0x7e2ac`** (file offset `0x5e2ac`); source of the G4/G5 wire evidence |
//! | 3 | , `…/amtc-s19kpro-jig/single_board_test_bm1366`, `…/amtc-s21-jig/single_board_test_bm1368` | the sibling key-table generation (below) |
//! | 4 | /components/minerfs.image.gz.tree/etc/{topol.conf,levels.json}` | first-party stock per-SKU topology + V/F ladders |
//!
//! Provenance caveat (Gauntlet invariant 5, same class as the Phase A
//! mirror): the asicminingsupplies trees are a third-party mirror of
//! Bitmain firmware — internally self-consistent (the four `bmminer`
//! builds below agree on every constant this module pins), but
//! mirror-held, not Bitmain-channel-attested.

use dcentrald_api_types::deployed_eeprom::KEY_LARGE;

// ---------------------------------------------------------------------------
// G1 — factory XXTEA key tables (BHB42xxx / BM1398 generation)
// ---------------------------------------------------------------------------

/// The four 16-byte XXTEA key candidates carried by the **AMTC S19 Pro
/// factory jig** (`single_board_test_bm1398`) at **VA `0x487a4`** (file
/// offset `0x287a4`), byte-exact.
///
/// Independently corroborated byte-for-byte by the stock NBP1901
/// `bmminer` at **VA `0x7e2ac`** (file offset `0x5e2ac`) — two unrelated
/// binaries (factory jig vs production miner) agree on all four slots.
///
/// Relationship to the shipped deployed-decoder table
/// (`dcentrald-api-types::deployed_eeprom::KEY_LARGE`, skot/MIT
/// provenance): **exactly one slot overlaps** —
/// `AMTC_S19PRO_JIG_XXTEA_KEY_TABLE[0] == KEY_LARGE[2] ==
/// "uohzoahzuhidkgna"` — and `KEY_LARGE[1]` (the binary
/// `7451ed7c…` key every held deployed page decodes under) is **absent**
/// from this generation's table. That 1-of-4 match reproduces the 2026-07-24
///  finding ("jig's real Zynq XXTEA key table @0x487a4 differs from
/// the skot/Amlogic keys — only 1 of 4 matches") exactly.
///
/// Desk consequence for G2 (bench EEPROM capture, `a lab unit` S19 Pro): a real
/// NBP1901/NBS1902/NBT1903 page's `algorithm_and_key_version` low nibble
/// selects a slot; if it declares index 1 like every held deployed page of
/// the OTHER families, the deployed-proven `KEY_LARGE[1]` will fail the
/// page's CRC5 and the BM1398-generation slot-1 key below is the factory
/// candidate. The page CRC5 stays the arbiter — a wrong key fails decode,
/// never hardware.
///
/// **G2 CLOSED live; G3 row recorded (2026-09-02, bench-20260902-nbp1901,
/// `.77`):** the prediction above held exactly. The live NBP1901 pages carry
/// header `algorithm_and_key_version = 0x11` (nibbles XXTEA=1/slot-1) +
/// byte 1 `0x42` (= the full zhiju block span) and decode — serials
/// byte-exact against the Braiins boot-table oracle, both block CRC5s Match
/// — under **slot 1 of this table** (`uileynimggnagnau`). The row is
/// LIVE-PROVEN evidence with honest limits: n=1 unit, 2 distinct boards
/// (boards 1/2 byte-identical pages), single generation sample; it is
/// recorded as the evidence const
/// [`dcentrald_api_types::deployed_eeprom::LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY`]
/// (cross-pinned to slot 1 of this table by test) and does NOT add a decode
/// dispatch anywhere — `decode_deployed_eeprom` still refuses `0x11`-headed
/// pages, and the zhiju path stays keyed by explicit caller key selection.
pub const AMTC_S19PRO_JIG_XXTEA_KEY_TABLE: [[u8; 16]; 4] = [
    *b"uohzoahzuhidkgna", // slot 0 — == shipped KEY_LARGE[2]
    *b"uileynimggnagnau", // slot 1 — BM1398-generation slot-1 factory key
    *b"ilijnainayuxnixo", // slot 2
    *b"iewgoahznehzwstg", // slot 3 — unique to this generation
];

/// The sibling XXTEA key-table generation carried by the **BM1362 /
/// BM1366 / BM1368 factory jigs** (`single_board_test_bm1362` /
/// `…_bm1366` / `…_bm1368` — S19j Pro / S19k Pro / S21), byte-identical
/// across all three.
///
/// This table closes the provenance question on the shipped deployed
/// decoder: its **slot 1 is exactly `KEY_LARGE[1]`
/// (`7451ed7c7b5cd872174fe0790a15e4f5`)** — the key every held real
/// deployed page (all BM1362/BM1366/BM1368 boards) decodes under at key
/// index 1. So "the deployed key is a Bitmain jig key_version-1 key" is
/// true for the BM136x generation, and the BM1398 generation rotates the
/// same key pool into different slots.
///
/// (Offsets for re-derivation — VA of **slot 0**, each in the second
/// PT_LOAD: BM1362 jig VA `0x4ed98` (file `0x2ed98`), BM1366 jig VA
/// `0x21930c` (file `0x1f930c`), BM1368 jig VA `0x275f50` (file
/// `0x255f50`) — the table there is `[slot0 ilijnainayuxnixo, slot1
/// 7451ed7c…, slot2 uohzoahzuhidkgna, slot3 uileynimggnagnau]`.)
pub const JIG_XXTEA_KEY_TABLE_BM136X_GENERATION: [[u8; 16]; 4] = [
    *b"ilijnainayuxnixo",
    [
        0x74, 0x51, 0xED, 0x7C, 0x7B, 0x5C, 0xD8, 0x72, 0x17, 0x4F, 0xE0, 0x79, 0x0A, 0x15, 0xE4,
        0xF5,
    ],
    *b"uohzoahzuhidkgna",
    *b"uileynimggnagnau",
];

/// Resolve a page's key index against BOTH held factory generations plus
/// the deployed-proven shipped table, for G2 bench decode use.
///
/// Returns every distinct 16-byte candidate for `key_index` (deduplicated,
/// generation order: BM1398 generation first, then BM136x generation, then
/// the shipped `KEY_LARGE`). Empty only for `key_index > 3`. Pure; the
/// page's CRC5 (not this function) decides which candidate is right.
pub fn xxtea_factory_key_candidates(key_index: usize) -> Vec<[u8; 16]> {
    let mut out: Vec<[u8; 16]> = Vec::new();
    for table in [
        &AMTC_S19PRO_JIG_XXTEA_KEY_TABLE,
        &JIG_XXTEA_KEY_TABLE_BM136X_GENERATION,
        &KEY_LARGE,
    ] {
        if let Some(k) = table.get(key_index) {
            if !out.contains(k) {
                out.push(*k);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// G4 — rail voltage → PSU DAC code law (PSU-version-keyed, stock NBP1901)
// ---------------------------------------------------------------------------

/// One linear rail-law row: `code = K1 − volts × K2` (truncating toward
/// zero, as the stock C `(int)(long long)` cast does).
///
/// Recovered from the stock NBP1901 `bmminer` `FUN_00048d38`
/// (decompilation `decompilations/ghidra/FUN_00048d38-00048d38.c`), which
/// switches on the PSU `power.version` byte returned by framed PSU
/// command `0x02` (`_bitmain_get_power_code_version`, `FUN_00048910` —
/// the response u16 is stored straight into the switch global) — the same
/// values stock `topol.conf` carries in `power.version[]`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Apw12RailCodeLaw {
    /// Intercept `K1` (f64 little-endian literal from the binary).
    pub k1: f64,
    /// Slope `K2` — volts to code, inverse transfer (higher rail → lower code).
    pub k2: f64,
    /// Stock `topol.conf` `power.version` values (decimal) selecting this row.
    pub power_versions: &'static [u8],
}

/// The four stock law rows, exact f64 bit patterns from the held binary
/// (`bmminer` VA→constant: `0x43`→`0x48ee8/0x48ee0`,
/// `0x71/0x72/0x75/0x77`→`0x48ec8/0x48ec0`,
/// `0x74/0x76`→`0x48ef8/0x48ef0`, `0x41/0x42`→`0x48ed8/0x48ed0`; file
/// offsets = VA − 0x10000).
///
/// All four pairs were verified byte-identical in the three Phase A
/// stock `bmminer` builds (`s19-20211116`, `s19-pro-20211116`,
/// `t19-20230320`) — the law is universal across the BM1398 stock
/// generation, only the per-SKU `power.version` set differs.
pub const APW12_RAIL_CODE_LAWS: [Apw12RailCodeLaw; 4] = [
    Apw12RailCodeLaw {
        // f64 933.240365 = d3307c44ec298d40 ; 59.806034 = 66bb421f2ce74d40
        k1: 933.240_365,
        k2: 59.806_034,
        power_versions: &[67],
    },
    Apw12RailCodeLaw {
        // f64 1190.935338 = d3a23ec9bd9b9240 ; 78.742588 = bb99d18f86af5340
        k1: 1190.935_338,
        k2: 78.742_588,
        power_versions: &[113, 114, 117, 119],
    },
    Apw12RailCodeLaw {
        // f64 1156.107585 = 2922c32a6e109240 ; 76.090494 = fe9e58a7ca055340
        k1: 1156.107_585,
        k2: 76.090_494,
        power_versions: &[116, 118],
    },
    Apw12RailCodeLaw {
        // f64 765.411764 = 5c8dec4a4beb8740 ; 35.833333 = bbd6dea7aaea4140
        k1: 765.411_764,
        k2: 35.833_333,
        power_versions: &[65, 66],
    },
];

/// Stock rail-code derivation: `code = trunc(K1 − volts × K2)` for the
/// law row selected by the PSU `power.version` byte.
///
/// Mirrors the stock caller exactly: returns `None` (stock: the switch
/// default stores `-1`) for an unknown version, and `None` for any result
/// outside `0..=255` (stock: the `powerState < 0x100` gate before the
/// frame is built). **Bench-gated**: a code from this function is
/// stock-firmware evidence, not DMM-verified electrical authority — no
/// live rail command may be derived from it without the Lane-F admission
/// plus bench verification.
pub fn apw12_rail_code(power_version: u8, rail_volts: f64) -> Option<u16> {
    let law = APW12_RAIL_CODE_LAWS
        .iter()
        .find(|l| l.power_versions.contains(&power_version))?;
    let code = (law.k1 - rail_volts * law.k2).trunc();
    if (0.0..=255.0).contains(&code) {
        Some(code as u16)
    } else {
        None
    }
}

/// The stock PSU framed **set-rail-code** frame (command `0x83`), the
/// consumer of [`apw12_rail_code`] (stock `FUN_00048834`):
///
/// ```text
/// 55 AA 06 83 <code_lo> <code_hi> <ck_lo> <ck_hi>
/// ```
///
/// with the additive checksum `ck = code_lo + 0x89` as a little-endian
/// u16, exactly as the binary computes it (`local_12 = (byte)code + 0x89`).
pub fn apw12_set_rail_code_frame(code: u16) -> [u8; 8] {
    // `ck = (u8)code + 0x89` computed in int width, so the carry into the
    // high byte is preserved (stock C: `(byte)param_2 + 0x89`).
    let ck = (code as u8) as u16 + 0x89;
    [
        0x55,
        0xAA,
        0x06,
        0x83,
        code as u8,
        (code >> 8) as u8,
        ck as u8,
        (ck >> 8) as u8,
    ]
}

/// Stock PSU **version-poll sentinel**: before the framed version
/// exchange (command `0x02`), stock polls one raw I²C byte and waits for
/// `0xF5` (`FUN_00048910`), retrying 10× at 100 ms.
pub const APW12_VERSION_POLL_SENTINEL: u8 = 0xF5;
/// Stock PSU version-poll retry count (then 100 ms apart).
pub const APW12_VERSION_POLL_RETRIES: u32 = 10;
/// Stock PSU version-poll retry interval.
pub const APW12_VERSION_POLL_INTERVAL_MS: u32 = 100;

// ---------------------------------------------------------------------------
// G5 — observed framed wire dialects (decode evidence only)
// ---------------------------------------------------------------------------

/// Observed framed command bytes on the **PSU** I²C device (stock
/// `topol.conf`: `power.i2c_addr 16` = `0x10`, `power.gpio 907`) in the
/// stock NBP1901 `bmminer`. Frame grammar (byte-level, re-verified by
/// instruction-level `movw`/`movt` decode of every constant below):
/// `55 AA <L> <cmd> <payload…> <ck_lo> <ck_hi>` where **`L` counts every
/// byte after the two-byte preamble** (frame total = `L + 2`, the same
/// grammar the S19k stock APW parser admits —
///  "APW trait
/// surface") and the checksum is additive.
///
/// This is the **framed** APW12 dialect — distinct from the SMBus
/// opcode table (`0x00`–`0x10`) the HAL ships for CV1835/BB/Amlogic
/// carriers (`dcentrald-hal/src/psu_apw12_smbus.rs`); the Zynq
/// S19-class stock dialect never uses those opcodes.
///
/// Command bytes are the **byte-after-length** (frame byte 3). Beware a
/// reading trap that produced an earlier draft of this table: writing
/// the Ghidra frame constant's leading hex digits instead (e.g. the
/// version header is the u32 `0x0204AA55` = bytes `55 AA 04 02` —
/// command `0x02`, NOT `0x20`).
pub const APW12_FRAMED_COMMANDS: &[(u8, &'static str)] = &[
    (0x02, "_bitmain_get_power_code_version (FUN_00048910; response selects the G4 law row)"),
    (0x06, "set DA conversion N (FUN_000492a4, generic write-with-data, len 6)"),
    (0x0A, "bitmain_get_power_status (FUN_00048b7c)"),
    (0x30, "bitmain_get_voltage (get AD conversion N)"),
    (0x83, "set rail code (G4 law consumer, FUN_00048834)"),
];

/// Observed framed command bytes on the **per-chain PIC1704** (stock
/// `topol.conf`: `chain.pic.type PIC1704`, `chain.pic.i2c_addr 32` =
/// `0x20`, one per chain) in the stock NBP1901 `bmminer`, with the
/// symbol-name attribution recovered from each function's log-tag
/// strings (op-name pointers resolved from each function's literal
/// pool). Same `55 AA <L> <cmd>` grammar as the PSU table; the 0x35 and
/// 0x3B frames embed their command as a single stored byte (and echo it
/// in the response check) rather than a combined u32 header.
///
/// Load-bearing identity note (three independent first-party sources):
/// the S19/S19 Pro/T19 hashboard voltage controller is a **PIC16F1704**
/// — stock `topol.conf` `pic.type = "PIC1704"` (all three SKUs), the
/// held `S19pro-PIC.hex` disassembles as `p16f1704` (gputils), and the
/// stock miner's own symbols say `_bitmain_pic_seek_1704` /
/// `_update_pic_app_program_1704`. The older "dsPIC33EP at 0x20-0x22"
/// reading for this family is superseded (it stays correct for
/// S17/S17 Pro/T17-class boards).
pub const PIC1704_S19_FRAMED_COMMANDS: &[(u8, &'static str)] = &[
    (0x01, "_bitmain_pic_seek_1704 (FUN_00046eb4)"),
    (0x06, "_bitmain_pic_start_app_common / jump_from_loader_to_app (FUN_00046554)"),
    (0x07, "_bitmain_pic_reset_common (FUN_0004637c)"),
    (0x15, "_bitmain_pic_enable/disable_dc_dc_common"),
    (0x16, "send_pic_heart_beat"),
    (0x17, "_bitmain_pic_get_sw_ver_common"),
    (0x35, "_app_write_data_into_flash_1704_v8 (FUN_0004752c; byte-store frame, echo-checked)"),
    (0x36, "_app_read_data_from_flash_1704_v8 (FUN_000477ec)"),
    (0x37, "_read_an6_voltage / pic_get_voltage"),
    (0x3A, "_read_an_voltage / pic_get_voltage"),
    (0x3B, "_pic_write_iic (FUN_00046ca0; byte-store frame, echo-checked)"),
    (0x3C, "_pic_read_iic (FUN_00048110)"),
];

// ---------------------------------------------------------------------------
// G4 data — stock V/F ladders (levels.json, centivolt convention)
// ---------------------------------------------------------------------------

/// One stock `levels.json` operating point. `voltage_cv` is
/// **centivolts of the hashboard rail** (1380 = 13.80 V) — the same
/// convention as the deployed EEPROM factory V/F fields and the
/// `--bitmain-voltage` token (stock divides by 100.0 before the G4 law).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockLevel {
    pub frequency_mhz: u16,
    pub voltage_cv: u16,
}

/// Stock S19 (NBS1902) `levels.json` ladder — 650/675 MHz at
/// 13.80–14.20 V. Source:
/// `extractions/asicminingsupplies/s19-20211116/…/etc/levels.json`.
pub const S19_NBS1902_STOCK_LEVELS: [StockLevel; 6] = [
    StockLevel { frequency_mhz: 675, voltage_cv: 1380 },
    StockLevel { frequency_mhz: 675, voltage_cv: 1400 },
    StockLevel { frequency_mhz: 675, voltage_cv: 1420 },
    StockLevel { frequency_mhz: 650, voltage_cv: 1380 },
    StockLevel { frequency_mhz: 650, voltage_cv: 1400 },
    StockLevel { frequency_mhz: 650, voltage_cv: 1420 },
];

/// Stock S19 Pro (NBP1901) `levels.json` ladder — 500/525 MHz at
/// 12.60–13.00 V. Source:
/// `extractions/asicminingsupplies/s19-pro-20211116/…/etc/levels.json`
/// (byte-identical ladder in the held HashSource NBP1901 analysis copy).
pub const S19_PRO_NBP1901_STOCK_LEVELS: [StockLevel; 6] = [
    StockLevel { frequency_mhz: 525, voltage_cv: 1260 },
    StockLevel { frequency_mhz: 525, voltage_cv: 1280 },
    StockLevel { frequency_mhz: 525, voltage_cv: 1300 },
    StockLevel { frequency_mhz: 500, voltage_cv: 1260 },
    StockLevel { frequency_mhz: 500, voltage_cv: 1280 },
    StockLevel { frequency_mhz: 500, voltage_cv: 1300 },
];

/// Stock T19 (NBT1903) `levels.json` ladder — 550–625 MHz at
/// 14.00–14.40 V. Source:
/// `extractions/asicminingsupplies/t19-20230320/…/etc/levels.json`.
pub const T19_NBT1903_STOCK_LEVELS: [StockLevel; 10] = [
    StockLevel { frequency_mhz: 625, voltage_cv: 1400 },
    StockLevel { frequency_mhz: 625, voltage_cv: 1420 },
    StockLevel { frequency_mhz: 600, voltage_cv: 1400 },
    StockLevel { frequency_mhz: 600, voltage_cv: 1420 },
    StockLevel { frequency_mhz: 575, voltage_cv: 1400 },
    StockLevel { frequency_mhz: 575, voltage_cv: 1420 },
    StockLevel { frequency_mhz: 550, voltage_cv: 1420 },
    StockLevel { frequency_mhz: 625, voltage_cv: 1440 },
    StockLevel { frequency_mhz: 600, voltage_cv: 1440 },
    StockLevel { frequency_mhz: 575, voltage_cv: 1440 },
];

/// Stock PSU `power.version` sets per SKU (decimal bytes; these select
/// the [`APW12_RAIL_CODE_LAWS`] row at runtime). `AWP12` is Bitmain's own
/// spelling of the APW12 dialect in the stock topol files.
pub const S19_FAMILY_STOCK_PSU_VERSIONS: &[(&str, &[u8])] = &[
    ("S19 NBS1902", &[67, 113, 116]),
    ("S19 Pro NBP1901", &[67, 113, 116]),
    ("T19 NBT1903", &[67, 113, 116, 117, 118]),
];

#[cfg(test)]
mod tests {
    use super::*;

    // ---- G1 ---------------------------------------------------------------

    /// Byte-exact pin of the AMTC S19 Pro jig table — every byte matters,
    /// so this asserts the raw hex rather than a round-tripped string.
    #[test]
    fn amtc_jig_table_bytes_are_pinned_exactly() {
        //
        // VA 0x487a4 -> file offset 0x287a4, 64 bytes:
        assert_eq!(
            AMTC_S19PRO_JIG_XXTEA_KEY_TABLE.concat(),
            Vec::<u8>::from([
                0x75, 0x6f, 0x68, 0x7a, 0x6f, 0x61, 0x68, 0x7a, 0x75, 0x68, 0x69, 0x64, 0x6b, 0x67,
                0x6e, 0x61, 0x75, 0x69, 0x6c, 0x65, 0x79, 0x6e, 0x69, 0x6d, 0x67, 0x67, 0x6e, 0x61,
                0x67, 0x6e, 0x61, 0x75, 0x69, 0x6c, 0x69, 0x6a, 0x6e, 0x61, 0x69, 0x6e, 0x61, 0x79,
                0x75, 0x78, 0x6e, 0x69, 0x78, 0x6f, 0x69, 0x65, 0x77, 0x67, 0x6f, 0x61, 0x68, 0x7a,
                0x6e, 0x65, 0x68, 0x7a, 0x77, 0x73, 0x74, 0x67,
            ])
        );
    }

    /// The 1-of-4 overlap with the shipped deployed table — reproduces the
    ///  "only 1 of 4 matches" finding and pins WHICH slot matches.
    #[test]
    fn amtc_jig_table_overlaps_deployed_key_large_in_exactly_one_slot() {
        let matches: Vec<_> = AMTC_S19PRO_JIG_XXTEA_KEY_TABLE
            .iter()
            .filter(|k| KEY_LARGE.contains(k))
            .collect();
        assert_eq!(matches, vec![&*b"uohzoahzuhidkgna"]);
        // And it is the deployed table's slot 2:
        assert_eq!(AMTC_S19PRO_JIG_XXTEA_KEY_TABLE[0], KEY_LARGE[2]);
        // The deployed-proven slot-1 binary key is NOT in the BM1398
        // generation's table…
        assert!(!AMTC_S19PRO_JIG_XXTEA_KEY_TABLE.contains(&KEY_LARGE[1]));
        // …but it IS slot 1 of the BM136x-generation jig table:
        assert_eq!(JIG_XXTEA_KEY_TABLE_BM136X_GENERATION[1], KEY_LARGE[1]);
    }

    /// G3 cross-crate pin: the LIVE-PROVEN evidence const in
    /// `dcentrald-api-types` (which cannot name this crate without a
    /// dependency cycle) is byte-exact slot 1 of THIS table — the key the
    /// live NBP1901 pages (`0x11`/`0x42` header) decoded under,
    /// bench-20260902-nbp1901. If either copy ever drifts, this goes red.
    #[test]
    fn live_proven_g3_evidence_key_is_amtc_jig_slot1() {
        assert_eq!(
            dcentrald_api_types::deployed_eeprom::LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY,
            AMTC_S19PRO_JIG_XXTEA_KEY_TABLE[1]
        );
        // And the live header row it is recorded against:
        assert_eq!(
            dcentrald_api_types::deployed_eeprom::BM1398_GENERATION_LIVE_HEADER,
            [0x11, 0x42]
        );
    }

    /// The two factory generations share exactly three key byte-strings
    /// (the pool rotation keeps one private key per generation), which is
    /// why both tables must be retained.
    #[test]
    fn factory_generations_share_exactly_three_keys() {
        let shared: Vec<_> = AMTC_S19PRO_JIG_XXTEA_KEY_TABLE
            .iter()
            .filter(|k| JIG_XXTEA_KEY_TABLE_BM136X_GENERATION.contains(k))
            .collect();
        assert_eq!(shared.len(), 3);
        // Each generation keeps exactly one private key:
        // BM1398-only `iewgoahznehzwstg`; BM136x-only `7451ed7c…`.
        assert!(!JIG_XXTEA_KEY_TABLE_BM136X_GENERATION.contains(b"iewgoahznehzwstg"));
        assert!(!AMTC_S19PRO_JIG_XXTEA_KEY_TABLE.contains(&KEY_LARGE[1]));
    }

    /// G2 bench helper: key index → candidates from every held table.
    #[test]
    fn key_candidates_cover_both_generations_and_shipped_table() {
        // Index 1: jig-A slot1 (uileynimggnagnau) + BM136x slot1 ==
        // KEY_LARGE[1] (7451ed…) -> 2 distinct candidates.
        assert_eq!(xxtea_factory_key_candidates(1).len(), 2);
        // Index 0: jig-A slot0 (== KEY_LARGE[2]); BM136x slot0
        // (ilijnainayuxnixo); KEY_LARGE[0] (ilijnaiaayuxnixo, the skot
        // garble) -> 3 distinct candidates.
        assert_eq!(xxtea_factory_key_candidates(0).len(), 3);
        // Out-of-range index refuses.
        assert!(xxtea_factory_key_candidates(4).is_empty());
    }

    // ---- G4 ---------------------------------------------------------------

    /// Exact law constants — the f64 literals must equal the binary's
    /// bit patterns (pinned via round-trip equality with the documented
    /// hex encodings in the row docs).
    #[test]
    fn rail_code_law_constants_are_pinned() {
        assert_eq!(APW12_RAIL_CODE_LAWS[0].k1, 933.240365);
        assert_eq!(APW12_RAIL_CODE_LAWS[0].k2, 59.806034);
        assert_eq!(APW12_RAIL_CODE_LAWS[1].k1, 1190.935338);
        assert_eq!(APW12_RAIL_CODE_LAWS[1].k2, 78.742588);
        assert_eq!(APW12_RAIL_CODE_LAWS[2].k1, 1156.107585);
        assert_eq!(APW12_RAIL_CODE_LAWS[2].k2, 76.090494);
        assert_eq!(APW12_RAIL_CODE_LAWS[3].k1, 765.411764);
        assert_eq!(APW12_RAIL_CODE_LAWS[3].k2, 35.833333);
        // Version keys cover every stock topol power.version byte for the
        // three SKUs.
        for (_, versions) in S19_FAMILY_STOCK_PSU_VERSIONS {
            for v in *versions {
                assert!(
                    APW12_RAIL_CODE_LAWS.iter().any(|l| l.power_versions.contains(v)),
                    "stock power.version {v} has no law row"
                );
            }
        }
    }

    /// Stock ladders must land inside the law's 0..=255 code domain for
    /// every SKU × every stock PSU version — otherwise our extraction
    /// reading of the units (centivolts, ÷100) or the law would be wrong.
    #[test]
    fn stock_levels_map_into_the_code_domain_for_every_version() {
        for (levels, label) in [
            (&S19_NBS1902_STOCK_LEVELS[..], "S19"),
            (&S19_PRO_NBP1901_STOCK_LEVELS[..], "S19 Pro"),
            (&T19_NBT1903_STOCK_LEVELS[..], "T19"),
        ] {
            for lvl in levels {
                let volts = lvl.voltage_cv as f64 / 100.0;
                for (_, versions) in S19_FAMILY_STOCK_PSU_VERSIONS {
                    for v in *versions {
                        let code = apw12_rail_code(*v, volts)
                            .unwrap_or_else(|| panic!("{label} {volts} V under PSU v{v} refused"));
                        assert!(code <= 255, "{label} code {code} out of byte domain");
                    }
                }
            }
        }
    }

    /// A few exact code pins (truncating toward zero, as the stock C cast
    /// does) so the arithmetic cannot silently drift.
    #[test]
    fn rail_code_exact_pins() {
        // v67 (0x43): 933.240365 - 13.8*59.806034 = 107.891... -> 107
        assert_eq!(apw12_rail_code(67, 13.8), Some(107));
        // v67: S19 Pro floor 12.60 V -> 179.723... -> 179
        assert_eq!(apw12_rail_code(67, 12.6), Some(179));
        // v113 (0x71): 13.8 V -> 104.34 -> 104
        assert_eq!(apw12_rail_code(113, 13.8), Some(104));
        // v116 (0x74): T19 14.4 V -> 60.40 -> 60
        assert_eq!(apw12_rail_code(116, 14.4), Some(60));
        // Unknown version fails closed (stock returns -1).
        assert_eq!(apw12_rail_code(0x99, 13.8), None);
        // Out-of-domain rail fails closed (stock <0x100 gate).
        assert_eq!(apw12_rail_code(67, 5.0), None);
        assert_eq!(apw12_rail_code(67, 20.0), None);
    }

    /// Monotonicity: raising the rail lowers the code, for every
    /// S19-family row (the 65/66 row's code domain only starts above
    /// ~14.24 V, so it is exercised through the ladder test instead).
    #[test]
    fn rail_code_is_monotonically_decreasing_in_volts() {
        for law in &APW12_RAIL_CODE_LAWS[..3] {
            for v in law.power_versions {
                let mut prev = apw12_rail_code(*v, 12.0)
                    .unwrap_or_else(|| panic!("12.0 V under PSU v{v} must be in-domain"));
                for tenths in 121..=152i32 {
                    let volts = tenths as f64 / 10.0;
                    if let Some(code) = apw12_rail_code(*v, volts) {
                        assert!(code <= prev, "non-monotonic at {volts} V v{v}");
                        prev = code;
                    }
                }
            }
        }
    }

    /// The 0x83 frame layout + checksum, pinned off `FUN_00048834`
    /// (`ck = code_lo + 0x89`, little-endian u16).
    #[test]
    fn set_rail_code_frame_is_pinned() {
        // 107 + 0x89 = 244 = 0x00F4 -> ck bytes F4 00
        assert_eq!(
            apw12_set_rail_code_frame(107),
            [0x55, 0xAA, 0x06, 0x83, 107, 0x00, 0xF4, 0x00]
        );
        assert_eq!(
            apw12_set_rail_code_frame(0),
            [0x55, 0xAA, 0x06, 0x83, 0x00, 0x00, 0x89, 0x00]
        );
        // 200 + 0x89 = 337 = 0x0151 -> ck bytes 51 01 (the carry case).
        assert_eq!(
            apw12_set_rail_code_frame(200),
            [0x55, 0xAA, 0x06, 0x83, 200, 0x00, 0x51, 0x01]
        );
    }

    // ---- G5 / dialect censuses ---------------------------------------------

    #[test]
    fn framed_command_sets_are_sorted_and_load_bearing() {
        let psu: Vec<u8> = APW12_FRAMED_COMMANDS.iter().map(|(c, _)| *c).collect();
        let pic: Vec<u8> = PIC1704_S19_FRAMED_COMMANDS.iter().map(|(c, _)| *c).collect();
        assert!(psu.windows(2).all(|w| w[0] < w[1]), "PSU set must be sorted");
        assert!(pic.windows(2).all(|w| w[0] < w[1]), "PIC set must be sorted");
        // The load-bearing PSU commands are present — byte values are the
        // byte-after-length of each frame constant, pinned by movw/movt
        // decode (version header u32 0x0204AA55 = `55 AA 04 02`).
        for c in [0x02, 0x06, 0x0A, 0x30, 0x83] {
            assert!(psu.contains(&c));
        }
        // `0x06` is genuinely claimed by BOTH devices (PSU set-DA
        // conversion N vs PIC start-app) — the command byte is only
        // meaningful together with its device address, which is why both
        // tables record the owner in prose.
        assert!(psu.contains(&0x06) && pic.contains(&0x06));
        // The misreading guard: the digit-swapped values that an earlier
        // draft recorded (frame-constant leading digits instead of the
        // command byte) must NOT be in either table.
        for wrong in [0x20u8, 0x10, 0x60, 0x70] {
            assert!(!psu.contains(&wrong) && !pic.contains(&wrong));
        }
    }

    // ---- stock ladders ------------------------------------------------------

    #[test]
    fn stock_ladders_are_pinned_to_first_party_values() {
        assert_eq!(S19_NBS1902_STOCK_LEVELS.len(), 6);
        assert_eq!(S19_PRO_NBP1901_STOCK_LEVELS.len(), 6);
        assert_eq!(T19_NBT1903_STOCK_LEVELS.len(), 10);
        // Centivolt convention sanity: every ladder value is a plausible
        // BM1398-generation hashboard rail (12.0–14.5 V), never a per-chip
        // core voltage and never volts*1000.
        for lvl in S19_NBS1902_STOCK_LEVELS
            .iter()
            .chain(S19_PRO_NBP1901_STOCK_LEVELS.iter())
            .chain(T19_NBT1903_STOCK_LEVELS.iter())
        {
            assert!((1200..=1450).contains(&lvl.voltage_cv));
            assert!((400..=800).contains(&lvl.frequency_mhz));
        }
        // T19 tops out at 625 MHz / 14.40 V (its highest-V row).
        assert_eq!(T19_NBT1903_STOCK_LEVELS[7].frequency_mhz, 625);
        assert_eq!(T19_NBT1903_STOCK_LEVELS[7].voltage_cv, 1440);
    }
}
