//! Deployed Bitmain hashboard-EEPROM decoder — the on-wire format that **real,
//! factory-programmed** boards actually use, distinct from the factory-*jig* block
//! layout in [`crate::zhiju_eeprom`].
//!
//! # Why this exists
//!
//! [`crate::eeprom_record::dispatch`] recognizes the `(0x04,0x11)` and `(0x05,0x11)`
//! preambles but intentionally returns *preamble-only* records. Before this decoder
//! closed the key/framing, the daemon could not identify a real deployed hashboard:
//! the `board_name`/`chip_marking` that discriminate
//! BM1362 vs BM1366 vs BM1398 live **inside the ciphertext**, and
//! [`crate::eeprom_record::scan_known_sku`] can only find a SKU that appears in
//! *plaintext* (which never happens on an encrypted board).
//!
//! This module supplies the missing cipher + framing so the daemon can extract a
//! trustworthy `board_name` and feed it to [`crate::eeprom_record::chip_family_for_sku`].
//!
//! # Provenance (2026-07-24, host-proven)
//!
//! Originally validated byte-exact against **four held real deployed dumps** — the
//! operator's S19j Pro `a lab unit` (BHB42601, header `04 11`, ×2 hashboards) and an S19k
//! Pro (BHB56903, header `05 11`, ×2 hashboards). A 2026-07-26 repo census raised
//! the corpus to **11 distinct real deployed pages** (adding the S21 `BHB68606`
//! dump and `a lab unit` pages recovered from bosminer logs), all of which decode under
//! the same framing. Every held page decodes with **XXTEA key
//! index 1** and the **three-region split** below; the decoded `board_name`,
//! `chip_marking`, and factory V/F reproduce the values read by the shipped
//! `dcent-toolbox` decoder (`projects/dcent-toolbox/.../eeprom_decrypt.py`). The
//! real-dump validation is recorded in
//!  (it is deliberately *not* embedded in
//! this shipped crate, to avoid publishing an operator's hardware serials).
//!
//! ## Corrections this closes (vs the 2026-07-24 census / Wave-A assumptions)
//!
//! * **The deployed key was never unknown.** It is Bitmain jig `key_version = 1`
//!   (`7451ed7c7b5cd872174fe0790a15e4f5`), identical to `skot/amlogic-cb-tools`
//!   `KEY_LARGE[1]` and the shipped toolbox key table. Wave-A's "jig keys don't
//!   decrypt the deployed board" negative was a **region-framing** error (it swept
//!   contiguous single blocks, not the 96-byte region-1 block).
//! * **`0x05` boards use XXTEA, not AES.** Byte 0 is a board-class/version byte;
//!   the algorithm is byte-1's *high* nibble (`0x1` = XXTEA) and the *low* nibble
//!   is the key index. BHB42xxx (`0x04`) and BHB56xxx (`0x05`) share the same key
//!   and framing. The census unlocks "U1 (BHB42 XXTEA key unknown)" and "U2 (BHB56
//!   AES key, DMCA-blocked)" both rested on false premises.
//! * **`chip_marking` is a lot code** (e.g. `L1C021CK11`, `S1GX23CM2E`), NOT an
//!   ASIC-model string. `board_name` (`BHB42601` vs `BHB56903`) is the real
//!   discriminator, exactly as `eeprom_record::BHB_SKU_CATALOG` already encodes.
//!   It does, however, carry ONE reproducible bit of family signal: character 2
//!   of the lot code (region-1 plaintext byte 23). Across all 22 held deployed
//!   pages it is `C` on BM1362 (11), `G` on BM1366 (7), `V` on BM1368 (4), with
//!   no exceptions. That is a **corroborator only** — see
//!   [`DeployedHashboardIdentity::chip_marking_family_letter`] and
//!   `hashboard_eeprom::CHIP_MARKING_FAMILY_LETTERS`. Evidence and the explicit
//!   limits of the rule (no held BM1398/BM1370 page; it does NOT close the
//!   `hashboard_eeprom.rs` BM1362-vs-BM1398 residual): .
//!
//! Cipher/key material is public: `skot/amlogic-cb-tools` (MIT) — the same source
//! the shipped GPL toolbox already ships.
//!
//! ## G3 live datum (2026-09-02)
//!
//! The first live page whose header falls OUTSIDE the `0x04`/`0x05` rows above:
//! the bench-captured S19 Pro (NBP1901, BM1398) pages carry header `0x11`/`0x42`
//! and decode as **zhiju single blocks** (window `[2..0x42)`, see
//! [`crate::zhiju_eeprom`]) under the BM1398-generation factory slot-1 key —
//! NOT under any `KEY_LARGE` slot. The full version→key evidence table (both
//! desk-derived rows and the LIVE-PROVEN row, with caveats) lives at
//! [`LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY`]. Decode dispatch in this module
//! is unchanged by that row.
//!
//! # Status & scope
//!
//! **Experimental — decode only.** Pure data: no HAL, no I/O, no write path, and no
//! admission authority. Producing a [`DeployedHashboardIdentity`] does not by itself
//! authorize any hardware mutation; a caller must still pair a decoded identity with
//! the platform's fail-closed admission rules (`hashboard_eeprom::admit_native_experimental`).

use serde::{Deserialize, Serialize};

use crate::eeprom_record::chip_family_for_sku;
use crate::zhiju_eeprom::{bitmain_crc5, Crc5Check};

/// XXTEA delta constant (`2^32 / golden-ratio`).
const XXTEA_DELTA: u32 = 0x9E37_79B9;

/// The four 16-byte XXTEA key candidates, indexed by the header's low nibble.
///
/// From `skot/amlogic-cb-tools` `eeprom_antminer.rs` (MIT) — byte-identical to the
/// shipped `dcent-toolbox` `KEY_LARGE`. `key_version = 1` is the one every held
/// deployed board uses; the others are retained so the header nibble stays the
/// single source of key selection (and so a future board that picks a different
/// index decodes without a code change).
///
/// EVIDENCE BAR: only index 1 is validated against real dumps — all 11 held
/// deployed pages declare it. Indexes 0/2/3 are unvalidated upstream table entries
/// retained for routing only; nothing in-tree proves they carry the real keys, and
/// the round-trip tests below cannot prove it either (they encipher and decipher
/// with the same slot, so they pin nibble→slot routing, not key correctness).
pub const KEY_LARGE: [[u8; 16]; 4] = [
    *b"ilijnaiaayuxnixo",
    [
        0x74, 0x51, 0xED, 0x7C, 0x7B, 0x5C, 0xD8, 0x72, 0x17, 0x4F, 0xE0, 0x79, 0x0A, 0x15, 0xE4,
        0xF5,
    ],
    *b"uohzoahzuhidkgna",
    *b"uileynimdpfnangr",
];

// --- G3 header version→key evidence rows (2026-09-02) -----------------------
//
// Which factory XXTEA key real pages of each header shape have been PROVEN to
// decode under. EVIDENCE RECORD ONLY: `decode_deployed_eeprom` does not read
// this table and its dispatch is unchanged — decode stays keyed by explicit
// key selection (this module routes the header byte-1 nibble into `KEY_LARGE`;
// the zhiju path takes an explicit caller-supplied key). A 2-byte header is
// not authenticated, so a header value can RECORD the key real pages decoded
// under without becoming a trusted selector.
//
// | byte 0 | byte 1 | page shape | key the real pages decode under | provenance |
// |---|---|---|---|---|
// | `0x04` | `0x11` | deployed 3-region (BHB42xxx, BM1362) | `KEY_LARGE[1]` (`7451ed7c…`) | DESK-DERIVED: 22 held deployed pages; CRC5 known-answer 5/5 real pages |
// | `0x05` | `0x11` | deployed 3-region (BHB56xxx/BHB68xxx, BM1366/BM1368) | `KEY_LARGE[1]` | DESK-DERIVED: same corpus; refutes the old "BHB56 = AES" reading |
// | `0x11` | `0x42` | zhiju single block, XXTEA window `[2..0x42)` (BM1398-generation NBP1901) | [`LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY`] = `uileynimggnagnau` (AMTC jig table slot 1) | **LIVE-PROVEN** bench-20260902-nbp1901 (`.77`, BraiinsOS): 3 EEPROMs / 2 distinct pages, serials byte-exact vs the independent Braiins boot-table oracle, both decoded blocks' CRC5 recompute Match |
//
// Caveats on the live `0x11` row: n=1 unit; boards 1/2 carried byte-identical
// pages (one factory serial on two physical boards), so the sample is 2
// distinct pages, not 3; one key-generation sample. The nibble reading of
// byte 0 (`0x11` → algorithm 1 = XXTEA, key slot 1) is consistent with the
// empirically required slot-1 key and with the jig's own byte-0 field name
// `algorithm_and_key_version`, but the slot was arbitrated by the serial
// oracle, not by the header value. `decode_deployed_eeprom` still refuses a
// `0x11`-headed 256-byte page (pinned by test): the BM1398-generation page is
// a zhiju-window page, not a 3-region deployed page.

/// Two-byte header of the live-proven BM1398-generation zhiju pages
/// (bench-20260902-nbp1901): byte 0 `algorithm_and_key_version = 0x11`, byte 1
/// `zhiju_information_length = 0x42` (= 66 = the full zhiju block span, which
/// is the corroborating datum for the G3 live row).
pub const BM1398_GENERATION_LIVE_HEADER: [u8; 2] = [0x11, 0x42];

/// The BM1398-generation factory slot-1 XXTEA key the live NBP1901 pages
/// decode under: `uileynimggnagnau`, slot 1 of the AMTC S19 Pro jig table
/// (`dcentrald-silicon-profiles::s19_family_stock::AMTC_S19PRO_JIG_XXTEA_KEY_TABLE`).
///
/// This crate cannot name that path (silicon-profiles depends on
/// dcentrald-api-types, so importing back would be a dependency cycle), so the
/// bytes are pinned here and a test in that crate cross-checks that the two
/// copies stay equal. It is deliberately NOT a `KEY_LARGE` entry and is
/// byte-distinct from every `KEY_LARGE` slot (pinned by test, including the
/// near-miss `uileynimdpfnangr` at slot 3): it is evidence, not a dispatch
/// target, and conflating it with the deployed binary key `KEY_LARGE[1]` is
/// exactly the misreading those pins guard against.
pub const LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY: [u8; 16] = *b"uileynimggnagnau";

/// The three independently-enciphered regions of a 256-byte deployed page.
///
/// Each region is its own XXTEA block over `(end-start)/4` little-endian words.
/// Region 1 is board identity, region 2 is factory V/F + test results, region 3 is
/// sweep/bad-core data (exposed raw; per-byte layout not needed for identity).
pub const REGION_1: (usize, usize) = (2, 98); // 96 bytes = 24 words — identity
pub const REGION_2: (usize, usize) = (98, 114); // 16 bytes =  4 words — factory V/F
pub const REGION_3: (usize, usize) = (114, 250); // 136 bytes = 34 words — sweep data
/// Byte `0xFF` carries a `0x5A` end-sentinel on every held deployed page.
///
/// **Advisory, deliberately NOT a gate.** [`decode_deployed_eeprom`] reports it as
/// [`DeployedHashboardIdentity::end_sentinel_present`] and never refuses on it. Byte
/// 255 sits outside all three enciphered regions (region 3 ends at 250), so it
/// authenticates none of the decoded fields and a hostile page can stamp it for free
/// — enforcing it would add no wrong-key protection beyond the `board_name` guard.
/// Four dumps are also too small a sample to promote "sentinel absent" into a
/// refusal: that would reject a real board over a byte this decoder does not read,
/// against the standing prefer-Experimental-over-refusing-hardware posture. Callers
/// wanting a stricter page check read the flag; admission authority stays downstream.
pub const SENTINEL_OFFSET: usize = 255;
pub const SENTINEL_VALUE: u8 = 0x5A;

/// Expected raw EEPROM page length.
pub const RAW_PAGE_LEN: usize = 256;

/// Format-1 board-class byte (`raw[0]`). A3HB7xxxx boards — S21 Pro / S21 Pro+ /
/// S21 XP / S21+ — use this layout. Unlike the `0x04`/`0x05` XXTEA pages, byte 1
/// is NOT an algorithm/key selector: it is `board_name[0]` (`'A'` = `0x41`),
/// because `board_name` sits in the clear at [`FORMAT_1_NAME`]. The enciphered
/// body key is unrecovered, so format-1 decode mints **identity only**. See the
/// module docs of [`crate::eeprom_record`] and
/// .
pub const FORMAT_1_CLASS: u8 = 0x01;

/// Page-absolute span of the format-1 plaintext `board_name`: `raw[1..16]`,
/// NUL-padded ASCII (e.g. `A3HB70501\0\0\0\0\0\0`). `(start, len)` for
/// [`read_ascii`], matching the reference decoder's `_cstr(raw, 1, 15)`.
pub const FORMAT_1_NAME: (usize, usize) = (1, 15);

// --- Region-1 field offsets (relative to the *decrypted* region-1 plaintext) ---
mod r1 {
    pub const BOARD_SERIAL: (usize, usize) = (0, 18);
    pub const CHIP_DIE: (usize, usize) = (18, 3);
    pub const CHIP_MARKING: (usize, usize) = (21, 14);
    pub const CHIP_BIN: usize = 35;
    pub const FT_VERSION: (usize, usize) = (36, 10);
    pub const PCB_VERSION: usize = 46; // LE u16
    pub const BOM_VERSION: usize = 48; // LE u16
    pub const CHIP_TECH: (usize, usize) = (57, 3);
    pub const BOARD_NAME: (usize, usize) = (60, 9);
    pub const FACTORY_JOB: (usize, usize) = (69, 24);
}

// --- Region-2 field offsets (relative to the *decrypted* region-2 plaintext) ---
mod r2 {
    pub const VOLTAGE_CV: usize = 0; // LE u16, CENTIVOLTS (÷100 = volts)
    pub const FREQUENCY_MHZ: usize = 2; // LE u16
    pub const NONCE_RATE: usize = 4; // LE u16
    pub const PCB_TEMP_IN: usize = 6; // i8
    pub const PCB_TEMP_OUT: usize = 7; // i8
}

// --- Page CRC5 framing -------------------------------------------------------
//
// Both regions obey ONE uniform Bitmain rule, already implemented twice
// elsewhere in this crate (`zhiju_eeprom` over `data[..0x41]`, `bm1366_eeprom`
// over `data[..0x47]`): **the CRC byte is the last byte of its block, and
// covers every preceding byte of that block from block byte 0.**
//
// Block 1 begins at page byte 0, so the two PLAINTEXT header bytes are inside
// it even though the cipher region [`REGION_1`] starts at 2. Block 2 begins at
// page byte 98. Both offsets below are therefore page-absolute.
//
// Verified as a known-answer against five held factory pages — s19k `0x50`/`0x52`
// (BHB56903), s21 `0x51` (BHB68606) and xil `0x50`/`0x52` (BHB42601), i.e.
// 3 SKUs across both `0x04` and `0x05` board classes: 10 of 10 stored bytes
// equal the recompute. The region-relative alternative for block 1 (760 bits)
// missed 5 of 5. Corpus-wide the same spans verify on armada deliverable 13 §F7
// (17/17 ePIC matched samples + 5/5 real held DCENT pages). Note a 5-bit CRC collides 1 time in 32 by construction, and
// that was observed live during verification — an over-long block-1 span
// matched on one page by chance. One page can never establish this framing.
/// Page-absolute offset of the block-1 CRC5 byte.
pub const REGION_1_CRC5_PAGE_OFFSET: usize = 97;
/// Bits of block 1 covered by its CRC5: page bytes `0..97`.
pub const REGION_1_CRC5_BITS: usize = 776;
/// Page-absolute offset of the block-2 CRC5 byte.
pub const REGION_2_CRC5_PAGE_OFFSET: usize = 113;
/// Bits of block 2 covered by its CRC5: page bytes `98..113`.
pub const REGION_2_CRC5_BITS: usize = 120;

/// Recompute both page CRC5s from an already-decrypted page.
///
/// **Advisory only, and deliberately so.** A 5-bit CRC accepts a wrong page 1
/// time in 32, so it can never be a sole gate; no held page has a known-bad
/// CRC, so the false-positive rate against aged or field-rewritten EEPROMs is
/// entirely unmeasured. [`decode_deployed_eeprom`] therefore reports a
/// `Mismatch` and still returns `Ok`. Promoting this to a refusal would newly
/// reject real boards on a live admission path — do not do it without a held
/// page that genuinely fails.
///
/// Short or malformed input yields [`Crc5Check::Unknown`] rather than panicking
/// or fabricating a verdict.
pub fn verify_deployed_crc5(raw: &[u8], region1: &[u8], region2: &[u8]) -> (Crc5Check, Crc5Check) {
    let r1_check = {
        let crc_in_region = REGION_1_CRC5_PAGE_OFFSET.wrapping_sub(REGION_1.0);
        let block_len = REGION_1_CRC5_BITS / 8;
        if raw.len() < REGION_1.0 || region1.len() <= crc_in_region || block_len < REGION_1.0 {
            Crc5Check::Unknown
        } else {
            let mut block = Vec::with_capacity(block_len);
            block.extend_from_slice(&raw[..REGION_1.0]);
            block.extend_from_slice(&region1[..crc_in_region]);
            debug_assert_eq!(block.len(), block_len);
            let computed = bitmain_crc5(&block, REGION_1_CRC5_BITS);
            let stored = region1[crc_in_region] & 0x1F;
            if computed == stored {
                Crc5Check::Match
            } else {
                Crc5Check::Mismatch { computed, stored }
            }
        }
    };

    let r2_check = {
        let crc_in_region = REGION_2_CRC5_PAGE_OFFSET.wrapping_sub(REGION_2.0);
        if region2.len() <= crc_in_region {
            Crc5Check::Unknown
        } else {
            let computed = bitmain_crc5(&region2[..crc_in_region], REGION_2_CRC5_BITS);
            let stored = region2[crc_in_region] & 0x1F;
            if computed == stored {
                Crc5Check::Match
            } else {
                Crc5Check::Mismatch { computed, stored }
            }
        }
    };

    (r1_check, r2_check)
}

/// Decode failure. Every variant is a **fail-closed refusal** — no partial/guessed
/// identity is ever returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum DeployedEepromError {
    /// The blob was not a 256-byte page.
    WrongLength { got: usize },
    /// Byte-1 high nibble was not `0x1` (XXTEA). This module only decodes XXTEA
    /// boards; anything else (including a future AES nibble) refuses here.
    UnsupportedAlgorithm { algo_nibble: u8 },
    /// Byte-1 low nibble selected a key index with no entry in [`KEY_LARGE`]
    /// (i.e. `4..=15`). Refusing keeps the header nibble the *single* source of
    /// key selection; clamping into range would silently decrypt with a key the
    /// page never declared and lean on the `board_name` check to notice.
    UnsupportedKeyIndex { key_index: u8 },
    /// Decrypted `board_name` was not a plausible hashboard SKU. This is the
    /// wrong-key / mis-framed guard: a bad decrypt yields high-entropy bytes that
    /// fail the SKU-prefix + printable-ASCII check, so it refuses rather than mint
    /// a garbage identity.
    ImplausibleIdentity { board_name_lossy: String },
}

impl core::fmt::Display for DeployedEepromError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength { got } => {
                write!(
                    f,
                    "deployed EEPROM page must be {RAW_PAGE_LEN} bytes, got {got}"
                )
            }
            Self::UnsupportedAlgorithm { algo_nibble } => {
                write!(
                    f,
                    "unsupported EEPROM algorithm nibble 0x{algo_nibble:x} (only XXTEA 0x1)"
                )
            }
            Self::UnsupportedKeyIndex { key_index } => {
                let last = KEY_LARGE.len() - 1;
                write!(
                    f,
                    "unsupported EEPROM key index {key_index} (only 0..={last})"
                )
            }
            Self::ImplausibleIdentity { board_name_lossy } => {
                write!(
                    f,
                    "decrypted board_name {board_name_lossy:?} is not a plausible hashboard SKU"
                )
            }
        }
    }
}

impl std::error::Error for DeployedEepromError {}

/// How much of a [`DeployedHashboardIdentity`] is actually trustworthy.
///
/// A caller MUST branch on this before reading any field other than
/// `board_class`/`board_name`: a `Format1PlaintextName` record proves ONLY the
/// plaintext SKU; every voltage/frequency/serial/chip/sweep/CRC field on it is
/// absent (zeroed/empty/`Unknown`), because the format-1 body cipher key is
/// unrecovered. Do not read those fields as factory values on such a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeployedIdentityProvenance {
    /// Full XXTEA-decrypted `0x04`/`0x05` (format 4/5) page: every field below
    /// was decrypted with the header-declared key. This is the [`Default`] so a
    /// record minted before provenance existed — which could only have come from
    /// the decrypt path — deserializes to an honest, non-fabricated verdict.
    #[default]
    DecryptedXxtea,
    /// Format-1 (`0x01`, A3HB7xxxx) page. Only the plaintext `board_name`
    /// ([`FORMAT_1_NAME`]) is real; the enciphered body key is unrecovered, so
    /// V/F, serial, chip marking/die/tech/bin, factory job, temps, and both
    /// region CRC5s are absent. Identity is sufficient to route the ASIC family;
    /// factory tuning values are NOT available from this record.
    Format1PlaintextName,
}

/// Read-only identity decoded from a real deployed hashboard EEPROM.
///
/// Intentionally lossy: identity + factory-binned V/F only. No cipher material,
/// no write handle, no admission token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployedHashboardIdentity {
    /// Header byte 0 — board-class/version (`0x04` BHB42xxx-class, `0x05` BHB56xxx-class).
    pub board_class: u8,
    /// XXTEA key index taken from header byte-1's low nibble (`1` on every held board).
    /// Always a real [`KEY_LARGE`] index — an out-of-range nibble refuses instead.
    pub key_index: u8,
    /// Hashboard SKU — the ASIC-family discriminator (e.g. `BHB42601`, `BHB56903`).
    pub board_name: String,
    /// 17-char factory serial (unique per physical hashboard).
    pub board_serial: String,
    /// ASIC lot marking (e.g. `L1C021CK11`) — NOT an ASIC-model string.
    pub chip_marking: String,
    /// 2-char die code (e.g. `ED`).
    pub chip_die: String,
    /// Process/technology code (e.g. `AC`, `AL`).
    pub chip_tech: String,
    /// Silicon quality bin.
    pub chip_bin: u8,
    /// Functional-test program version string.
    pub ft_version: String,
    pub pcb_version: u16,
    pub bom_version: u16,
    /// Factory job ticket id.
    pub factory_job: String,
    /// Factory-binned operating voltage, **centivolts** (`1360` = 13.60 V).
    pub voltage_cv: u16,
    /// Factory-binned operating frequency, MHz.
    pub frequency_mhz: u16,
    /// Factory-measured nonce rate.
    pub nonce_rate: u16,
    /// Inlet PCB temperature, signed °C.
    pub pcb_temp_in: i8,
    /// Outlet PCB temperature, signed °C.
    pub pcb_temp_out: i8,
    /// Page carried the `0x5A` end sentinel at [`SENTINEL_OFFSET`]. **Advisory
    /// metadata only** — the decode never gates on it (see the constant's docs).
    /// `#[serde(default)]` so JSON minted before this field still deserializes.
    #[serde(default)]
    pub end_sentinel_present: bool,
    /// Recomputed block-1 CRC5 (page bytes `0..97`). **Advisory** — a mismatch
    /// is reported, never refused; see [`verify_deployed_crc5`].
    /// `#[serde(default)]` → [`Crc5Check::Unknown`] on records minted before
    /// this field existed, i.e. *no claim*, not a fabricated match.
    #[serde(default)]
    pub region_1_crc5: Crc5Check,
    /// Recomputed block-2 CRC5 (page bytes `98..113`). Advisory, as above.
    #[serde(default)]
    pub region_2_crc5: Crc5Check,
    /// Trust level of this record — the single flag a caller MUST check before
    /// reading any factory-tuning field. `DecryptedXxtea` = full `0x04`/`0x05`
    /// decrypt; `Format1PlaintextName` = A3HB7 plaintext-SKU only (V/F/serial
    /// absent). `#[serde(default)]` → [`DeployedIdentityProvenance::DecryptedXxtea`]
    /// on legacy records, which is what they in fact were.
    #[serde(default)]
    pub provenance: DeployedIdentityProvenance,
}

impl DeployedHashboardIdentity {
    /// Factory-binned voltage in volts (`voltage_cv / 100`).
    pub fn voltage_v(&self) -> f32 {
        self.voltage_cv as f32 / 100.0
    }

    /// Resolve the ASIC chip family from `board_name` via the shared SKU catalog.
    ///
    /// Returns `None` for a SKU not in [`crate::eeprom_record::BHB_SKU_CATALOG`];
    /// callers must treat that as "do not admit", never as a default family.
    pub fn chip_family(&self) -> Option<&'static str> {
        chip_family_for_sku(&self.board_name)
    }

    /// Character 2 of the factory lot code — region-1 plaintext byte 23.
    ///
    /// **Corroborating evidence only. Never a primary family source.** The whole
    /// held corpus is 22 pages over 3 families (`C`/`G`/`V`); there is no vendor
    /// documentation, and crucially **no BM1387/BM1391/BM1397/BM1398/BM1370 page
    /// exists to test a further letter**. BM1370 (`A3HB7xxxx`) is *structurally*
    /// out of reach here: those pages are format 1 (`0x01 0x41`) and
    /// [`decode_deployed_eeprom`] refuses them at
    /// [`DeployedEepromError::UnsupportedAlgorithm`], so this accessor is never
    /// reached for them.
    ///
    /// Returns `None` when the marking is absent or shorter than 3 characters —
    /// absent evidence, never a guessed letter (CONTEXT §1.4).
    pub fn chip_marking_family_letter(&self) -> Option<char> {
        // ASCII by construction: `read_ascii` yields `""` for a non-ASCII field,
        // so `chars().nth(2)` is byte 23 whenever it is `Some`.
        let c = self.chip_marking.chars().nth(2)?;
        if c.is_ascii_alphanumeric() {
            Some(c)
        } else {
            None
        }
    }
}

/// Decrypt a slice of little-endian u32 words in place with standard XXTEA.
///
/// Standard Corrected Block TEA: `delta = 0x9E3779B9`, `rounds = 6 + 52/n`, key is
/// four little-endian u32 words indexed by `(p & 3) ^ e`. Matches the shipped
/// toolbox `xxtea_decrypt` and the bosminer decrypt core (`FUN_00712af0`), both
/// confirmed by round-trip.
fn xxtea_decrypt(v: &mut [u32], key: &[u32; 4]) {
    let n = v.len();
    if n < 2 {
        return;
    }
    let n_u = n as u32;
    let rounds = 6 + 52 / n_u;
    let mut sum = rounds.wrapping_mul(XXTEA_DELTA);
    let mut y = v[0];
    for _ in 0..rounds {
        let e = (sum >> 2) & 3;
        for p in (1..n).rev() {
            let z = v[p - 1];
            let mx = mix(y, z, sum, key, p as u32, e);
            v[p] = v[p].wrapping_sub(mx);
            y = v[p];
        }
        let z = v[n - 1];
        let mx = mix(y, z, sum, key, 0, e);
        v[0] = v[0].wrapping_sub(mx);
        y = v[0];
        sum = sum.wrapping_sub(XXTEA_DELTA);
    }
}

#[inline]
fn mix(y: u32, z: u32, sum: u32, key: &[u32; 4], p: u32, e: u32) -> u32 {
    let a = (z >> 5) ^ (y << 2);
    let b = (y >> 3) ^ (z << 4);
    let c = sum ^ y;
    let d = key[((p & 3) ^ e) as usize] ^ z;
    (a.wrapping_add(b)) ^ (c.wrapping_add(d))
}

pub(crate) fn key_words(k: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_le_bytes([k[0], k[1], k[2], k[3]]),
        u32::from_le_bytes([k[4], k[5], k[6], k[7]]),
        u32::from_le_bytes([k[8], k[9], k[10], k[11]]),
        u32::from_le_bytes([k[12], k[13], k[14], k[15]]),
    ]
}

/// Decrypt one region `[start, end)` of `raw` and return its plaintext bytes.
/// The span is a whole number of words on every real page (96/16/136 bytes).
pub(crate) fn decrypt_region(raw: &[u8], start: usize, end: usize, key: &[u32; 4]) -> Vec<u8> {
    let bytes = &raw[start..end];
    let mut words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    xxtea_decrypt(&mut words, key);
    let mut out = Vec::with_capacity(words.len() * 4);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// Read a fixed-width ASCII field, trimming trailing NUL/space. `None` if any byte
/// is non-NUL and outside printable ASCII (so a bad decrypt can't pass as text).
fn read_ascii(region: &[u8], (start, len): (usize, usize)) -> Option<String> {
    let bytes = region.get(start..start + len)?;
    if !bytes.iter().all(|b| *b == 0 || (*b >= 0x20 && *b < 0x7F)) {
        return None;
    }
    let text: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as char)
        .collect();
    Some(text.trim_end().to_string())
}

fn read_le_u16(region: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([region[at], region[at + 1]])
}

/// True for a plausible deployed hashboard SKU: a known catalog prefix (`BHB`/`BHL`
/// / `A3HB`) followed by printable-ASCII, or an exact catalog hit. The prefix guard
/// is what makes a wrong-key decrypt fail closed.
fn is_plausible_board_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 9 {
        return false;
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    name.starts_with("BHB")
        || name.starts_with("BHL")
        || name.starts_with("A3HB")
        || chip_family_for_sku(name).is_some()
}

/// True when `raw` carries the observed `0x5A` end sentinel at [`SENTINEL_OFFSET`].
///
/// Advisory only — see that constant's docs. Never a decode gate, and a short or
/// empty page simply reports `false` rather than indexing out of bounds.
pub fn has_end_sentinel(raw: &[u8]) -> bool {
    raw.get(SENTINEL_OFFSET) == Some(&SENTINEL_VALUE)
}

/// Decode a real deployed 256-byte hashboard EEPROM page.
///
/// Fail-closed at every step: wrong length, non-XXTEA algorithm nibble, a key index
/// with no [`KEY_LARGE`] entry, or an implausible decrypted `board_name` all return
/// `Err`. A returned identity has a catalog-plausible SKU decrypted with the exact
/// header-declared key; callers still run their own admission policy before any
/// hardware action.
pub fn decode_deployed_eeprom(
    raw: &[u8],
) -> Result<DeployedHashboardIdentity, DeployedEepromError> {
    if raw.len() != RAW_PAGE_LEN {
        return Err(DeployedEepromError::WrongLength { got: raw.len() });
    }
    let board_class = raw[0];

    // Format 1 (A3HB7xxxx: S21 Pro / Pro+ / XP / S21+) is dispatched on raw[0]
    // BEFORE the byte-1 algorithm check. On these pages byte 1 is board_name[0]
    // (`'A'` = 0x41), so `(raw[1] >> 4) == 0x4` — the old code hard-errored here
    // with UnsupportedAlgorithm{4} and left the entire A3HB7 tier unidentifiable.
    // The body cipher key is unrecovered, so this mints identity from the
    // plaintext SKU only; it never guesses the enciphered body.
    if board_class == FORMAT_1_CLASS {
        return decode_format1_identity(raw);
    }

    let algo_nibble = (raw[1] >> 4) & 0x0F;
    let key_index = raw[1] & 0x0F;
    if algo_nibble != 0x1 {
        return Err(DeployedEepromError::UnsupportedAlgorithm { algo_nibble });
    }
    // Fail closed on an index this build has no key for. The former `.min(3)` clamp
    // decrypted with key 3 instead and relied on `is_plausible_board_name` to notice.
    let Some(key_bytes) = KEY_LARGE.get(key_index as usize) else {
        return Err(DeployedEepromError::UnsupportedKeyIndex { key_index });
    };
    let key = key_words(key_bytes);

    let region1 = decrypt_region(raw, REGION_1.0, REGION_1.1, &key);
    let region2 = decrypt_region(raw, REGION_2.0, REGION_2.1, &key);

    // board_name is the discriminator and the plausibility gate.
    let board_name = read_ascii(&region1, r1::BOARD_NAME).unwrap_or_default();
    if !is_plausible_board_name(&board_name) {
        return Err(DeployedEepromError::ImplausibleIdentity {
            board_name_lossy: region1
                .get(r1::BOARD_NAME.0..r1::BOARD_NAME.0 + r1::BOARD_NAME.1)
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default(),
        });
    }

    // Computed AFTER the plausibility gate so a garbage page still refuses on
    // identity rather than on a 5-bit checksum that accepts 1 page in 32.
    let crc5_checks = verify_deployed_crc5(raw, &region1, &region2);

    Ok(DeployedHashboardIdentity {
        board_class,
        key_index,
        board_name,
        board_serial: read_ascii(&region1, r1::BOARD_SERIAL).unwrap_or_default(),
        chip_marking: read_ascii(&region1, r1::CHIP_MARKING).unwrap_or_default(),
        chip_die: read_ascii(&region1, r1::CHIP_DIE).unwrap_or_default(),
        chip_tech: read_ascii(&region1, r1::CHIP_TECH).unwrap_or_default(),
        chip_bin: region1[r1::CHIP_BIN],
        ft_version: read_ascii(&region1, r1::FT_VERSION).unwrap_or_default(),
        pcb_version: read_le_u16(&region1, r1::PCB_VERSION),
        bom_version: read_le_u16(&region1, r1::BOM_VERSION),
        factory_job: read_ascii(&region1, r1::FACTORY_JOB).unwrap_or_default(),
        voltage_cv: read_le_u16(&region2, r2::VOLTAGE_CV),
        frequency_mhz: read_le_u16(&region2, r2::FREQUENCY_MHZ),
        nonce_rate: read_le_u16(&region2, r2::NONCE_RATE),
        pcb_temp_in: region2[r2::PCB_TEMP_IN] as i8,
        pcb_temp_out: region2[r2::PCB_TEMP_OUT] as i8,
        end_sentinel_present: has_end_sentinel(raw),
        // Advisory: computed, reported, never refused. See verify_deployed_crc5.
        region_1_crc5: crc5_checks.0,
        region_2_crc5: crc5_checks.1,
        provenance: DeployedIdentityProvenance::DecryptedXxtea,
    })
}

/// Decode a format-1 (`0x01`, A3HB7xxxx) page into **identity only**.
///
/// The only trustworthy datum on the page is the plaintext `board_name` in
/// [`FORMAT_1_NAME`] (`raw[1..16]`, NUL-padded ASCII). Everything else — V/F,
/// serial, chip marking/die/tech/bin, factory job, PCB temps, both region CRC5s
/// — lives in the enciphered body under a key D-Central does not hold, so it is
/// left absent (zero/empty/`Unknown`) and [`DeployedIdentityProvenance::Format1PlaintextName`]
/// flags the record. Fail-closed: the same [`is_plausible_board_name`] gate that
/// guards a wrong-key XXTEA decode rejects a garbage page here, so a NUL-padded
/// read of a non-A3HB page cannot mint a bogus SKU.
fn decode_format1_identity(raw: &[u8]) -> Result<DeployedHashboardIdentity, DeployedEepromError> {
    let board_name = read_ascii(raw, FORMAT_1_NAME).unwrap_or_default();
    if !is_plausible_board_name(&board_name) {
        return Err(DeployedEepromError::ImplausibleIdentity {
            board_name_lossy: raw
                .get(FORMAT_1_NAME.0..FORMAT_1_NAME.0 + FORMAT_1_NAME.1)
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default(),
        });
    }

    Ok(DeployedHashboardIdentity {
        board_class: FORMAT_1_CLASS,
        // Format-1 carries no key index (byte 1 is board_name[0], not a selector).
        // Reported as 0; provenance is what tells a caller the crypto fields are absent.
        key_index: 0,
        board_name,
        board_serial: String::new(),
        chip_marking: String::new(),
        chip_die: String::new(),
        chip_tech: String::new(),
        chip_bin: 0,
        ft_version: String::new(),
        pcb_version: 0,
        bom_version: 0,
        factory_job: String::new(),
        // Absent — factory V/F is enciphered; never fabricate it (empty-tuning
        // is the deliberate, regression-pinned posture).
        voltage_cv: 0,
        frequency_mhz: 0,
        nonce_rate: 0,
        pcb_temp_in: 0,
        pcb_temp_out: 0,
        end_sentinel_present: has_end_sentinel(raw),
        // Body is not decrypted, so no region CRC5 can be recomputed — no claim.
        region_1_crc5: Crc5Check::Unknown,
        region_2_crc5: Crc5Check::Unknown,
        provenance: DeployedIdentityProvenance::Format1PlaintextName,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// XXTEA encrypt — inverse of [`xxtea_decrypt`], test-only (the shipped surface
    /// is decrypt-only; nothing in the daemon ever re-enciphers an EEPROM).
    fn xxtea_encrypt(v: &mut [u32], key: &[u32; 4]) {
        let n = v.len();
        if n < 2 {
            return;
        }
        let n_u = n as u32;
        let rounds = 6 + 52 / n_u;
        let mut sum: u32 = 0;
        // `z` is the running previous word (standard XXTEA encode), NOT `v[p]`.
        let mut z = v[n - 1];
        for _ in 0..rounds {
            sum = sum.wrapping_add(XXTEA_DELTA);
            let e = (sum >> 2) & 3;
            for p in 0..n - 1 {
                let y = v[p + 1];
                let mx = mix(y, z, sum, key, p as u32, e);
                v[p] = v[p].wrapping_add(mx);
                z = v[p];
            }
            let y = v[0];
            let mx = mix(y, z, sum, key, (n - 1) as u32, e);
            v[n - 1] = v[n - 1].wrapping_add(mx);
            z = v[n - 1];
        }
    }

    fn encrypt_region_into(
        raw: &mut [u8],
        start: usize,
        end: usize,
        plaintext: &[u8],
        key: &[u32; 4],
    ) {
        assert_eq!(end - start, plaintext.len());
        let mut words: Vec<u32> = plaintext
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        xxtea_encrypt(&mut words, key);
        for (i, w) in words.iter().enumerate() {
            raw[start + i * 4..start + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
    }

    /// Build a synthetic-but-realistic deployed page: real SKU/V/F at the proven
    /// offsets, a fake serial, XXTEA-kv1-enciphered in the 3-region split.
    fn synth_page(
        class: u8,
        board_name: &str,
        marking: &str,
        voltage_cv: u16,
        freq: u16,
    ) -> Vec<u8> {
        synth_page_keyed(class, 1, 1, board_name, marking, voltage_cv, freq)
    }

    /// [`synth_page`] with the two key indexes split apart: encipher with
    /// `enc_key_index`, stamp `hdr_key_index` into the header nibble. Lets a test
    /// build both "declares a key we do not have" and "declares a key that is not
    /// the one used" pages.
    fn synth_page_keyed(
        class: u8,
        enc_key_index: usize,
        hdr_key_index: u8,
        board_name: &str,
        marking: &str,
        voltage_cv: u16,
        freq: u16,
    ) -> Vec<u8> {
        let key = key_words(&KEY_LARGE[enc_key_index]);
        let mut r1 = vec![0u8; REGION_1.1 - REGION_1.0];
        let put = |buf: &mut [u8], (o, l): (usize, usize), s: &str| {
            let b = s.as_bytes();
            let n = b.len().min(l);
            buf[o..o + n].copy_from_slice(&b[..n]);
        };
        put(&mut r1, r1::BOARD_SERIAL, "SYNTH0000000000AB");
        put(&mut r1, r1::CHIP_DIE, "ED");
        put(&mut r1, r1::CHIP_MARKING, marking);
        r1[r1::CHIP_BIN] = 2;
        put(&mut r1, r1::FT_VERSION, "F1V18B3C1");
        r1[r1::PCB_VERSION..r1::PCB_VERSION + 2].copy_from_slice(&288u16.to_le_bytes());
        r1[r1::BOM_VERSION..r1::BOM_VERSION + 2].copy_from_slice(&16u16.to_le_bytes());
        put(&mut r1, r1::CHIP_TECH, "AC");
        put(&mut r1, r1::BOARD_NAME, board_name);
        put(&mut r1, r1::FACTORY_JOB, "SMTT20220201001");

        let mut r2 = vec![0u8; REGION_2.1 - REGION_2.0];
        r2[r2::VOLTAGE_CV..r2::VOLTAGE_CV + 2].copy_from_slice(&voltage_cv.to_le_bytes());
        r2[r2::FREQUENCY_MHZ..r2::FREQUENCY_MHZ + 2].copy_from_slice(&freq.to_le_bytes());
        r2[r2::NONCE_RATE..r2::NONCE_RATE + 2].copy_from_slice(&9977u16.to_le_bytes());
        r2[r2::PCB_TEMP_IN] = 28i8 as u8;
        r2[r2::PCB_TEMP_OUT] = 30i8 as u8;

        let mut raw = vec![0xFFu8; RAW_PAGE_LEN];
        raw[0] = class;
        raw[1] = 0x10 | (hdr_key_index & 0x0F); // algo nibble 0x1 (XXTEA) + declared key index
        encrypt_region_into(&mut raw, REGION_1.0, REGION_1.1, &r1, &key);
        encrypt_region_into(&mut raw, REGION_2.0, REGION_2.1, &r2, &key);
        raw[SENTINEL_OFFSET] = SENTINEL_VALUE;
        raw
    }

    /// Build a synthetic page carrying CORRECT page CRC5s, so mutations below
    /// start from a known-good baseline. `corrupt_stored` flips a bit in each
    /// stored CRC byte instead.
    fn synthetic_page_with_crc5(class: u8, board_name: &str, corrupt_stored: bool) -> Vec<u8> {
        let key_index = 1usize;
        let key = key_words(&KEY_LARGE[key_index]);
        let hdr0 = class;
        let hdr1 = 0x10 | (key_index as u8 & 0x0F);

        let mut r1 = vec![0u8; REGION_1.1 - REGION_1.0];
        let put = |buf: &mut [u8], (o, l): (usize, usize), s: &str| {
            let b = s.as_bytes();
            let n = b.len().min(l);
            buf[o..o + n].copy_from_slice(&b[..n]);
        };
        put(&mut r1, r1::BOARD_SERIAL, "SYNTH0000000000AB");
        put(&mut r1, r1::BOARD_NAME, board_name);
        let mut r2 = vec![0u8; REGION_2.1 - REGION_2.0];
        r2[r2::VOLTAGE_CV..r2::VOLTAGE_CV + 2].copy_from_slice(&1360u16.to_le_bytes());

        // Stamp the CRCs using the SAME framing the production constants
        // declare: each block's CRC byte is its last byte, block 1 beginning at
        // page byte 0 (so the two plaintext header bytes are inside it).
        let r1_crc_idx = REGION_1_CRC5_PAGE_OFFSET - REGION_1.0;
        let mut block1 = vec![hdr0, hdr1];
        block1.extend_from_slice(&r1[..r1_crc_idx]);
        r1[r1_crc_idx] = bitmain_crc5(&block1, REGION_1_CRC5_BITS) ^ u8::from(corrupt_stored);

        let r2_crc_idx = REGION_2_CRC5_PAGE_OFFSET - REGION_2.0;
        r2[r2_crc_idx] =
            bitmain_crc5(&r2[..r2_crc_idx], REGION_2_CRC5_BITS) ^ u8::from(corrupt_stored);

        let mut raw = vec![0xFFu8; RAW_PAGE_LEN];
        raw[0] = hdr0;
        raw[1] = hdr1;
        encrypt_region_into(&mut raw, REGION_1.0, REGION_1.1, &r1, &key);
        encrypt_region_into(&mut raw, REGION_2.0, REGION_2.1, &r2, &key);
        raw[SENTINEL_OFFSET] = SENTINEL_VALUE;
        raw
    }

    #[test]
    fn bm1398_named_identity_uses_decoded_name_and_both_crc_regions() {
        // Reconstructed named-format pages exercise the existing cipher and
        // framing contract. They are not held physical NBS/NBT/S19a/S19+ captures.
        // The deployed format's name field is nine bytes. The jig spelling
        // NBP1901-38 cannot be represented and is never silently truncated.
        for name in ["NBP1901", "NBS1902", "NBT1903", "BHB28611", "BHB28701"] {
            let raw = synthetic_page_with_crc5(4, name, false);
            let identity = crate::hashboard_eeprom::decode_bm1398_factory_page(&raw).unwrap();
            assert_eq!(identity.board_name(), Some(name));
            assert_eq!(identity.serial(), "SYNTH0000000000AB");
            let chip = crate::bm1398_get_address::parse_bm1398_get_address_body(&[
                0x13, 0x98, 0x18, 0, 0, 0, 4,
            ])
            .unwrap();
            assert_eq!(
                crate::hashboard_eeprom::observed_protocol_from_bm1398_factory_page(
                    &raw,
                    name,
                    Some(chip),
                ),
                Some(dcentrald_common::AsicProtocolIdentity::Bm1398)
            );
            for sibling in crate::hashboard_eeprom::BM1398_NATIVE_STOCK_BOARD_NAMES {
                if sibling != name {
                    assert_eq!(
                        crate::hashboard_eeprom::observed_protocol_from_bm1398_factory_page(
                            &raw,
                            sibling,
                            Some(chip),
                        ),
                        None
                    );
                }
            }
            assert!(crate::hashboard_eeprom::decode_bm1398_factory_page(
                &synthetic_page_with_crc5(4, name, true),
            )
            .is_err());
            // Corrupt each stored CRC independently while preserving every
            // covered data byte. Random cipher mutations can collide under a
            // five-bit checksum and do not prove an integrity guarantee.
            let key = key_words(&KEY_LARGE[1]);
            for ((start, end), crc_offset) in [
                (REGION_1, REGION_1_CRC5_PAGE_OFFSET),
                (REGION_2, REGION_2_CRC5_PAGE_OFFSET),
            ] {
                let mut corrupt = raw.clone();
                let mut plain = decrypt_region(&raw, start, end, &key);
                plain[crc_offset - start] ^= 1;
                encrypt_region_into(&mut corrupt, start, end, &plain, &key);
                let decoded = decode_deployed_eeprom(&corrupt).unwrap();
                assert_eq!(decoded.board_name, name);
                assert_eq!(
                    decoded.region_1_crc5 == Crc5Check::Match,
                    start != REGION_1.0
                );
                assert_eq!(
                    decoded.region_2_crc5 == Crc5Check::Match,
                    start != REGION_2.0
                );
                assert!(
                    crate::hashboard_eeprom::decode_bm1398_factory_page(&corrupt).is_err(),
                    "{name} invalid stored CRC at {crc_offset}"
                );
            }
        }
        for name in [
            "NBP1901-38",
            "BHB42601",
            "BHB56903",
            "BHB28601",
            "NBS1902L",
            "NBT1903X",
        ] {
            assert!(
                crate::hashboard_eeprom::decode_bm1398_factory_page(&synthetic_page_with_crc5(
                    4, name, false
                ),)
                .is_err(),
                "uncovered exact name {name}"
            );
        }
    }

    /// Block 1's CRC covers the two PLAINTEXT header bytes, not just the cipher
    /// region — this is the whole span question, and it is the one thing a
    /// synthetic page can prove without shipping a real board's serial.
    ///
    /// Not a tautology: the baseline `Match` is stamp-then-recompute and proves
    /// nothing on its own. The teeth are the mutation — flipping page byte 0
    /// must break block 1 and leave block 2 untouched. If the span were
    /// region-relative (`r1[0..95]`, 760 bits) byte 0 would be outside it and
    /// this test would go green on a wrong implementation. Byte 0 is also the
    /// ONLY usable header mutation: byte 1 carries the algorithm/key nibbles, so
    /// flipping it refuses long before any CRC is compared.
    #[test]
    fn crc5_block_1_covers_the_plaintext_header_and_block_2_does_not() {
        let page = synthetic_page_with_crc5(0x05, "BHB56903", false);
        let id = decode_deployed_eeprom(&page).expect("baseline page decodes");
        assert_eq!(id.region_1_crc5, Crc5Check::Match);
        assert_eq!(id.region_2_crc5, Crc5Check::Match);

        let mut flipped = page.clone();
        flipped[0] ^= 0x01;
        let id = decode_deployed_eeprom(&flipped).expect("header flip must not refuse");
        assert!(
            matches!(id.region_1_crc5, Crc5Check::Mismatch { .. }),
            "block 1 must cover page byte 0; got {:?}",
            id.region_1_crc5
        );
        assert_eq!(
            id.region_2_crc5,
            Crc5Check::Match,
            "block 2 starts at page byte 98 and must be unaffected by a header flip"
        );
    }

    /// A mismatch is REPORTED and the page still decodes.
    ///
    /// Load-bearing because this decoder now has a production caller on the
    /// BM1366 admission path: a 5-bit CRC accepts 1 wrong page in 32, so
    /// promoting it to a refusal would newly reject real boards. Mutation: make
    /// `decode_deployed_eeprom` return `Err` on mismatch and this goes red.
    #[test]
    fn a_crc5_mismatch_is_reported_and_never_refuses_the_page() {
        let page = synthetic_page_with_crc5(0x05, "BHB56903", true);
        let id = decode_deployed_eeprom(&page).expect("a bad CRC must not refuse the page");
        assert_eq!(id.board_name, "BHB56903");
        assert!(matches!(id.region_1_crc5, Crc5Check::Mismatch { .. }));
        assert!(matches!(id.region_2_crc5, Crc5Check::Mismatch { .. }));
        // The identity a caller admits on is unchanged by a CRC verdict.
        assert_eq!(id.chip_family(), Some("BM1366"));
    }

    /// A record minted before these fields existed must deserialize to "nothing
    /// was checked", never to a fabricated `Match`.
    #[test]
    fn an_unchecked_record_defaults_to_unknown_rather_than_match() {
        assert_eq!(Crc5Check::default(), Crc5Check::Unknown);
        let legacy = serde_json::json!({
            "board_class": 5, "key_index": 1,
            "board_name": "BHB56903", "board_serial": "S", "chip_marking": "",
            "chip_die": "", "chip_tech": "", "chip_bin": 2, "ft_version": "",
            "pcb_version": 0, "bom_version": 0, "factory_job": "",
            "voltage_cv": 1360, "frequency_mhz": 670, "nonce_rate": 0,
            "pcb_temp_in": 0, "pcb_temp_out": 0
        });
        let id: DeployedHashboardIdentity =
            serde_json::from_value(legacy).expect("legacy record deserializes");
        assert_eq!(id.region_1_crc5, Crc5Check::Unknown);
        assert_eq!(id.region_2_crc5, Crc5Check::Unknown);
    }

    /// The declared spans are the ones the held factory pages validated.
    ///
    /// Verified offline as a known answer over five real pages (s19k 0x50/0x52
    /// BHB56903, s21 0x51 BHB68606, xil 0x50/0x52 BHB42601 — 3 SKUs, both
    /// board classes): 10 of 10 stored bytes equalled the recompute under these
    /// constants. The pages themselves are not committed here because they
    /// carry factory serials.
    #[test]
    fn crc5_span_constants_match_the_block_framing() {
        // Each CRC byte is the LAST byte of its block.
        assert_eq!(REGION_1_CRC5_PAGE_OFFSET, REGION_1.1 - 1);
        assert_eq!(REGION_2_CRC5_PAGE_OFFSET, REGION_2.1 - 1);
        // Block 1 starts at page byte 0; block 2 at page byte 98.
        assert_eq!(REGION_1_CRC5_BITS, REGION_1_CRC5_PAGE_OFFSET * 8);
        assert_eq!(
            REGION_2_CRC5_BITS,
            (REGION_2_CRC5_PAGE_OFFSET - REGION_2.0) * 8
        );
        // The region-relative alternative for block 1 (760 bits) is NOT what
        // the held pages validated; pin the difference so it cannot drift back.
        assert_ne!(REGION_1_CRC5_BITS, (REGION_1.1 - 1 - REGION_1.0) * 8);
    }

    /// Decode a compact hex string into bytes (test-only; keeps the three real
    /// format-1 pages readable inline without a 256-entry byte array each).
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(s.len() % 2, 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // --- Three REAL held factory format-1 pages ------------------------------
    //
    // Provenance:
    // epic-eeprom-matched-samples-20.json` (A3HB70501/70601/70701, fmt=1). These
    // raw pages are safe to embed: on a format-1 page ONLY `board_name` (already
    // a public SKU) is plaintext — the serial and all V/F live in the enciphered
    // body under a key D-Central does not hold, so these bytes leak nothing
    // readable. (Format-4/5 real pages are deliberately NOT embedded anywhere in
    // this crate because their bodies ARE recoverable with the public key and
    // carry factory serials.)
    const REAL_FMT1_A3HB70501: &str = "\
01413348423730353031000000000000f6b40d106c9522124bdcbbfac059a95c\
f611e118ef2f0436aebe133d30e83f85294002c04c64a137921447fc9b91816d\
97bc177cc0cc84abdfe4aeee3d3b5035ac355970cf5c47ec87585d16a27f340d\
7837455e7242e31842c74650a7bb43f14898d9a4a5759fa1f6c89386a5b4aa15\
a3833dcc5c3f6a5db497bacaf5c5d791ed9a25cadee09d16c72df77083f2b383\
6d8e7cb4f68cb253a22078f5959bacb351415400ca5db15da2db2468ac3f074c\
deab2966336a445044a668554c587108bfb3e00f6bfc51a490c89343d905bc26\
3e08bc01c42a60877e7e40ae40178e943813b67078faf483d0000f72aef583e3";
    const REAL_FMT1_A3HB70601: &str = "\
01413348423730363031000000000000b065cf54b9bbc65e4ed741ade7109b29\
67544bc9816a7637c476a44db691db3eff9d1cbbef307ec10ebf55bce0ea6282\
a94fff2f2abe7453bcf3fa4d216452ce3eff6b23e6dbc62482f111fe7d06d176\
304ffc7f90289de320ca07e5bd28462c96a5f1702f62f1c34d5d37f7f380ab89\
50bd9b060f7cbe70a63a15b58ee6eefc16748abd6be95ba053d78b62107179448\
6354f7141ae55da38b8625ade4a2febd67a027ecd366397491a763f864bfab0a\
92968fd7ebcb93d8d8502cbc371653aa20389034fc0de8358d1ebf05896cff9a\
8ee865d925630a0427ed34e1174c7b96f5915edab34b52d79853e8e6cffeaf6";
    const REAL_FMT1_A3HB70701: &str = "\
01413348423730373031000000000000f805bfd34b7bd4f2d2091a21d4220771\
fa398a25b0af7f609257e6da23044757c976fa11789de02ffca9a0a90b64c772\
6a421242a8c431a919c2b8fde5223dd2b14d4f7f702515f21b77a16f1199dd21\
67099645e945aa072bd83af394863818fc5e44f63523b5744d96c795764158fe\
9cd75bb7b978aa6fa17870f453971dcba83c7e6e580b3bd7f2ebd86346c56b6c\
51806a0b2fb3b727d220859bc34c98a7431365f88fb95c98c79d7dc7179ae363\
0b416ea0a63e9fb3ea2fa032fc080001cb47bb060a8168c4667d4bd603be6ee6\
f825543962db6d5a5bcf22b0438c6e3bad67545b71fc57a10dc0d22dae63d298";

    /// The load-bearing UB-01 fix: all three REAL A3HB7 pages decode to the right
    /// SKU from their plaintext `board_name` alone. Before the format-1 arm every
    /// one of these hard-errored `UnsupportedAlgorithm{4}` (byte 1 = 'A' = 0x41).
    #[test]
    fn real_format1_a3hb7_pages_decode_to_their_plaintext_sku() {
        for (hexpage, sku) in [
            (REAL_FMT1_A3HB70501, "A3HB70501"),
            (REAL_FMT1_A3HB70601, "A3HB70601"),
            (REAL_FMT1_A3HB70701, "A3HB70701"),
        ] {
            let page = hex(hexpage);
            assert_eq!(
                page.len(),
                RAW_PAGE_LEN,
                "{sku}: real page must be 256 bytes"
            );
            let id = decode_deployed_eeprom(&page)
                .unwrap_or_else(|e| panic!("{sku} must decode, got {e}"));

            assert_eq!(id.board_class, FORMAT_1_CLASS);
            assert_eq!(id.board_name, sku, "plaintext SKU must resolve");
            // The whole point of UB-01: the A3HB7 tier now routes to an ASIC family.
            assert_eq!(id.chip_family(), Some("BM1370"));
            // Honest provenance — a caller can tell this from a decrypted 4/5 record.
            assert_eq!(
                id.provenance,
                DeployedIdentityProvenance::Format1PlaintextName
            );
            // Every enciphered-body field is ABSENT, never fabricated.
            assert_eq!(id.voltage_cv, 0, "must not fabricate factory voltage");
            assert_eq!(id.frequency_mhz, 0, "must not fabricate factory frequency");
            assert_eq!(id.nonce_rate, 0);
            assert!(id.board_serial.is_empty(), "serial is enciphered/absent");
            assert!(id.chip_marking.is_empty());
            assert_eq!(id.key_index, 0, "format-1 has no key index");
            // No decrypted regions => no CRC claim.
            assert_eq!(id.region_1_crc5, Crc5Check::Unknown);
            assert_eq!(id.region_2_crc5, Crc5Check::Unknown);
        }
    }

    /// A `0x01` page whose plaintext name is high-entropy junk must fail closed on
    /// the SAME plausibility gate that guards a wrong-key XXTEA decode — a
    /// NUL-padded read must never mint a garbage SKU.
    #[test]
    fn format1_with_implausible_name_fails_closed() {
        // Non-printable bytes after the 0x01 header: read_ascii rejects, name empty.
        let mut junk = vec![0xFFu8; RAW_PAGE_LEN];
        junk[0] = FORMAT_1_CLASS;
        match decode_deployed_eeprom(&junk) {
            Err(DeployedEepromError::ImplausibleIdentity { .. }) => {}
            other => panic!("expected fail-closed ImplausibleIdentity, got {other:?}"),
        }

        // Printable but NOT a catalog SKU (e.g. "ZZZZ1234") must also refuse — the
        // prefix guard is what makes format-1 fail closed, not mere ASCII-ness.
        let mut bogus = vec![0u8; RAW_PAGE_LEN];
        bogus[0] = FORMAT_1_CLASS;
        bogus[1..1 + b"ZZZZ1234".len()].copy_from_slice(b"ZZZZ1234");
        match decode_deployed_eeprom(&bogus) {
            Err(DeployedEepromError::ImplausibleIdentity { .. }) => {}
            other => panic!("expected fail-closed ImplausibleIdentity, got {other:?}"),
        }
    }

    /// No-regression on the trust flag: a decrypted `0x04`/`0x05` page reports
    /// `DecryptedXxtea`, so a caller can always distinguish it from a format-1
    /// plaintext-name record.
    #[test]
    fn decrypted_format4_5_pages_report_decrypted_provenance() {
        let p4 = synth_page(0x04, "BHB42601", "L1C021CK11", 1360, 545);
        assert_eq!(
            decode_deployed_eeprom(&p4).unwrap().provenance,
            DeployedIdentityProvenance::DecryptedXxtea
        );
        let p5 = synth_page(0x05, "BHB56903", "S1GX23CM2E", 1380, 670);
        assert_eq!(
            decode_deployed_eeprom(&p5).unwrap().provenance,
            DeployedIdentityProvenance::DecryptedXxtea
        );
    }

    /// A record minted before `provenance` existed deserializes to the honest
    /// default (`DecryptedXxtea`) — those legacy records were all decrypt-path
    /// records, never format-1.
    #[test]
    fn legacy_record_without_provenance_defaults_to_decrypted() {
        assert_eq!(
            DeployedIdentityProvenance::default(),
            DeployedIdentityProvenance::DecryptedXxtea
        );
        let legacy = serde_json::json!({
            "board_class": 5, "key_index": 1,
            "board_name": "BHB56903", "board_serial": "S", "chip_marking": "",
            "chip_die": "", "chip_tech": "", "chip_bin": 2, "ft_version": "",
            "pcb_version": 0, "bom_version": 0, "factory_job": "",
            "voltage_cv": 1360, "frequency_mhz": 670, "nonce_rate": 0,
            "pcb_temp_in": 0, "pcb_temp_out": 0
        });
        let id: DeployedHashboardIdentity =
            serde_json::from_value(legacy).expect("legacy record deserializes");
        assert_eq!(id.provenance, DeployedIdentityProvenance::DecryptedXxtea);
    }

    #[test]
    fn xxtea_round_trips() {
        let key = key_words(&KEY_LARGE[1]);
        let original = [
            0x1122_3344u32,
            0x5566_7788,
            0x99AA_BBCC,
            0xDDEE_FF00,
            0x0102_0304,
            0xDEAD_BEEF,
        ];
        let mut v = original;
        xxtea_encrypt(&mut v, &key);
        assert_ne!(v, original, "ciphertext must differ from plaintext");
        xxtea_decrypt(&mut v, &key);
        assert_eq!(v, original, "decrypt(encrypt(x)) == x");
    }

    /// Known-answer vector for the **production** `xxtea_decrypt`, computed by the
    /// shipped `dcent-toolbox` `xxtea_decrypt` (the exact decoder proven byte-exact
    /// against the four held real deployed dumps). This cross-pins the Rust decrypt
    /// to real-board behavior independently of the self-inverse round-trip — a
    /// transcription bug in `mix`/rounds would break it.
    #[test]
    fn xxtea_decrypt_matches_toolbox_known_answer_vector() {
        let key = key_words(&KEY_LARGE[1]);
        let mut ct = [
            0xFDF7_53C8u32,
            0xCBB1_0ABC,
            0x553C_B508,
            0x374F_E460,
            0x6D0A_9190,
            0x62B7_002D,
        ];
        let expected_pt = [
            0xB302_DBA7u32,
            0xEB78_E7E7,
            0x6690_D975,
            0xF375_81FB,
            0x686A_CEB3,
            0xA975_ADC2,
        ];
        xxtea_decrypt(&mut ct, &key);
        assert_eq!(
            ct, expected_pt,
            "decrypt must match the shipped toolbox decoder"
        );
    }

    #[test]
    fn key_version_1_is_the_jig_binary_key() {
        // The load-bearing deployed key (jig key_version 1 / skot KEY_LARGE[1]).
        assert_eq!(
            KEY_LARGE[1],
            [
                0x74, 0x51, 0xED, 0x7C, 0x7B, 0x5C, 0xD8, 0x72, 0x17, 0x4F, 0xE0, 0x79, 0x0A, 0x15,
                0xE4, 0xF5
            ]
        );
    }

    /// G3: the live-proven BM1398-generation key is EVIDENCE, not a `KEY_LARGE`
    /// dispatch target. It must stay byte-distinct from every shipped slot —
    /// especially `KEY_LARGE[1]` (the deployed binary key the live pages
    /// demonstrably do NOT decode under) and the near-miss ASCII slot 3
    /// (`uileynimdpfnangr`, two characters away from `uileynimggnagnau`).
    #[test]
    fn live_proven_bm1398_key_is_distinct_from_every_key_large_slot() {
        assert_eq!(
            LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY,
            *b"uileynimggnagnau"
        );
        for slot in KEY_LARGE {
            assert_ne!(
                LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY, slot,
                "the BM1398-generation slot-1 key must never be conflated with a KEY_LARGE entry"
            );
        }
        // The live header row itself: 0x11 algorithm_and_key_version + 0x42 length.
        assert_eq!(BM1398_GENERATION_LIVE_HEADER, [0x11, 0x42]);
        // The structural corroboration pinned: 0x11 = XXTEA nibble | slot-1 nibble.
        assert_eq!(BM1398_GENERATION_LIVE_HEADER[0] >> 4, 0x1);
        assert_eq!(BM1398_GENERATION_LIVE_HEADER[0] & 0x0F, 0x1);
    }

    #[test]
    fn decodes_bhb42601_bm1362_deployed_page() {
        // S19j Pro class (header 0x04), proven V/F 13.60 V / 545 MHz.
        let page = synth_page(0x04, "BHB42601", "L1C021CK11", 1360, 545);
        let id = decode_deployed_eeprom(&page).expect("decode");
        assert_eq!(id.board_class, 0x04);
        assert_eq!(id.key_index, 1);
        assert_eq!(id.board_name, "BHB42601");
        assert_eq!(id.chip_marking, "L1C021CK11");
        assert_eq!(id.chip_die, "ED");
        assert_eq!(id.chip_tech, "AC");
        assert_eq!(id.voltage_cv, 1360);
        assert!((id.voltage_v() - 13.60).abs() < 1e-3);
        assert_eq!(id.frequency_mhz, 545);
        assert_eq!(id.pcb_temp_in, 28);
        assert_eq!(id.pcb_temp_out, 30);
        // The discriminator resolves BM1362 via the shared catalog.
        assert_eq!(id.chip_family(), Some("BM1362"));
    }

    #[test]
    fn decodes_bhb56903_bm1366_deployed_page_via_xxtea_not_aes() {
        // S19k Pro class (header 0x05) — proven to use XXTEA kv1, NOT AES.
        let page = synth_page(0x05, "BHB56903", "S1GX23CM2E", 1380, 670);
        let id = decode_deployed_eeprom(&page).expect("decode");
        assert_eq!(id.board_class, 0x05);
        assert_eq!(id.board_name, "BHB56903");
        assert_eq!(id.voltage_cv, 1380);
        assert_eq!(id.frequency_mhz, 670);
        // BHB569xx maps to BM1366 in the shared catalog.
        assert_eq!(id.chip_family(), Some("BM1366"));
    }

    #[test]
    fn wrong_length_fails_closed() {
        assert_eq!(
            decode_deployed_eeprom(&[0x04, 0x11, 0x00]),
            Err(DeployedEepromError::WrongLength { got: 3 })
        );
    }

    #[test]
    fn non_xxtea_algorithm_nibble_refuses() {
        let mut page = synth_page(0x05, "BHB56903", "S1GX23CM2E", 1380, 670);
        page[1] = 0x21; // algo nibble 0x2 (not XXTEA), key index 1
        assert_eq!(
            decode_deployed_eeprom(&page),
            Err(DeployedEepromError::UnsupportedAlgorithm { algo_nibble: 0x2 })
        );
    }

    #[test]
    fn wrong_key_index_yields_implausible_identity_not_a_guess() {
        // Encrypt with kv1 but flip the header to select kv3 -> garbage board_name.
        let mut page = synth_page(0x04, "BHB42601", "L1C021CK11", 1360, 545);
        page[1] = 0x13; // algo XXTEA, key index 3 (wrong key for this ciphertext)
        match decode_deployed_eeprom(&page) {
            Err(DeployedEepromError::ImplausibleIdentity { .. }) => {}
            other => panic!("expected fail-closed ImplausibleIdentity, got {other:?}"),
        }
    }

    #[test]
    fn out_of_range_key_index_refuses_instead_of_clamping() {
        // Header declares key index 4..15; KEY_LARGE only holds 0..=3. The former
        // `.min(3)` clamp decrypted with key 3 and hoped the name check caught it.
        let mut page = synth_page(0x04, "BHB42601", "L1C021CK11", 1360, 545);
        page[1] = 0x14; // first index past the end of KEY_LARGE
        assert_eq!(
            decode_deployed_eeprom(&page),
            Err(DeployedEepromError::UnsupportedKeyIndex { key_index: 4 })
        );
        page[1] = 0x1F; // widest out-of-range nibble
        assert_eq!(
            decode_deployed_eeprom(&page),
            Err(DeployedEepromError::UnsupportedKeyIndex { key_index: 0xF })
        );
    }

    /// The exact fail-OPEN shape the clamp created: a page enciphered with
    /// `KEY_LARGE[3]` while declaring index 15 decrypted *successfully* under
    /// `.min(3)` and minted an identity whose reported `key_index` (15) was never
    /// the key used. It must now refuse before decrypting anything.
    #[test]
    fn page_enciphered_with_key_3_declaring_index_15_refuses() {
        let lying = synth_page_keyed(0x04, 3, 0xF, "BHB42601", "L1C021CK11", 1360, 545);
        assert_eq!(
            decode_deployed_eeprom(&lying),
            Err(DeployedEepromError::UnsupportedKeyIndex { key_index: 0xF })
        );
        // The same ciphertext with an honest header still decodes — so the refusal
        // above is about the declared index, not a broken key-3 path.
        let honest = synth_page_keyed(0x04, 3, 3, "BHB42601", "L1C021CK11", 1360, 545);
        let id = decode_deployed_eeprom(&honest).expect("honest key-3 header decodes");
        assert_eq!(id.key_index, 3);
        assert_eq!(id.board_name, "BHB42601");
    }

    /// The header nibble is the single source of key selection: every real
    /// `KEY_LARGE` index round-trips when the page honestly declares it.
    #[test]
    fn header_nibble_selects_the_same_key_large_slot_used_to_encipher() {
        for idx in 0..KEY_LARGE.len() {
            let page = synth_page_keyed(0x04, idx, idx as u8, "BHB42601", "L1C021CK11", 1360, 545);
            let id = decode_deployed_eeprom(&page)
                .unwrap_or_else(|e| panic!("key index {idx} must decode, got {e}"));
            assert_eq!(id.key_index, idx as u8);
            assert_eq!(id.board_name, "BHB42601");
        }
    }

    /// Sweep every possible header byte-1 over a real ciphertext and pin the
    /// classification: non-XXTEA nibbles refuse as `UnsupportedAlgorithm`, indexes
    /// past `KEY_LARGE` refuse as `UnsupportedKeyIndex`, and nothing else may reach
    /// the decrypt.
    #[test]
    fn every_header_byte_maps_to_the_right_typed_outcome() {
        let base = synth_page(0x04, "BHB42601", "L1C021CK11", 1360, 545);
        for b1 in 0u8..=0xFF {
            let mut page = base.clone();
            page[1] = b1;
            let algo = (b1 >> 4) & 0x0F;
            let key_index = b1 & 0x0F;
            match decode_deployed_eeprom(&page) {
                Err(DeployedEepromError::UnsupportedAlgorithm { algo_nibble }) => {
                    assert_ne!(algo, 0x1, "0x{b1:02x}: XXTEA must not refuse as non-XXTEA");
                    assert_eq!(algo_nibble, algo);
                }
                Err(DeployedEepromError::UnsupportedKeyIndex { key_index: got }) => {
                    assert_eq!(algo, 0x1, "0x{b1:02x}: algorithm is checked first");
                    assert_eq!(got, key_index);
                    assert!(key_index as usize >= KEY_LARGE.len());
                }
                other => {
                    assert_eq!(
                        algo, 0x1,
                        "0x{b1:02x}: non-XXTEA reached decrypt: {other:?}"
                    );
                    assert!(
                        (key_index as usize) < KEY_LARGE.len(),
                        "0x{b1:02x}: unknown key index reached decrypt: {other:?}"
                    );
                }
            }
        }
    }

    /// The format-1 arm must not widen the door: every first byte that is not a
    /// handled format (`0x01` format-1, `0x04`/`0x05` XXTEA-class) still refuses.
    /// Byte 1 is a valid `0x11` XXTEA header on every page, so a refusal here can
    /// only come from the unhandled byte 0 — pin that no future format slips
    /// through to a decrypt-and-hope path.
    #[test]
    fn every_unhandled_first_byte_refuses_fail_closed() {
        for b0 in 0u8..=0xFF {
            if matches!(b0, FORMAT_1_CLASS | 0x04 | 0x05) {
                continue;
            }
            let mut page = vec![0x11u8; RAW_PAGE_LEN];
            page[0] = b0;
            assert!(
                decode_deployed_eeprom(&page).is_err(),
                "first byte 0x{b0:02x} is not a handled format and must refuse"
            );
        }
    }

    /// The `0x5A` end sentinel is reported, never enforced. Gating on it would
    /// reject a real board over a byte outside every enciphered region.
    #[test]
    fn end_sentinel_is_reported_but_never_gates_the_decode() {
        let page = synth_page(0x04, "BHB42601", "L1C021CK11", 1360, 545);
        assert!(has_end_sentinel(&page));
        assert!(
            decode_deployed_eeprom(&page)
                .expect("decode")
                .end_sentinel_present
        );

        let mut no_sentinel = page.clone();
        no_sentinel[SENTINEL_OFFSET] = 0x00;
        assert!(!has_end_sentinel(&no_sentinel));
        let id = decode_deployed_eeprom(&no_sentinel).expect("sentinel is advisory, not a gate");
        assert_eq!(id.board_name, "BHB42601");
        assert_eq!(id.voltage_cv, 1360);
        assert!(!id.end_sentinel_present);

        // Short/empty pages report absence instead of indexing out of bounds.
        assert!(!has_end_sentinel(&[]));
        assert!(!has_end_sentinel(&[SENTINEL_VALUE]));
    }

    /// `decrypt_region` slices `raw[start..end]` directly, so an out-of-page or
    /// sub-two-word region constant would panic on every real decode instead of
    /// failing closed.
    #[test]
    fn region_spans_stay_inside_the_raw_page() {
        for (start, end) in [REGION_1, REGION_2, REGION_3] {
            assert!(start < end, "region {start}..{end} must be non-empty");
            assert!(
                end <= RAW_PAGE_LEN,
                "region {start}..{end} exceeds the page"
            );
            assert!(
                (end - start) / 4 >= 2,
                "region {start}..{end} needs >= 2 XXTEA words"
            );
        }
        assert!(SENTINEL_OFFSET < RAW_PAGE_LEN);
    }

    #[test]
    fn all_ff_page_refuses() {
        let mut page = vec![0xFFu8; RAW_PAGE_LEN];
        page[0] = 0x04;
        page[1] = 0x11;
        // Region ciphertext is all-0xFF -> decrypts to noise -> implausible name.
        match decode_deployed_eeprom(&page) {
            Err(DeployedEepromError::ImplausibleIdentity { .. }) => {}
            other => panic!("expected fail-closed refusal on junk page, got {other:?}"),
        }
    }

    #[test]
    fn identity_serde_round_trips() {
        let page = synth_page(0x04, "BHB42601", "L1C021CK11", 1360, 545);
        let id = decode_deployed_eeprom(&page).unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: DeployedHashboardIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn region_boundaries_are_the_proven_skot_split() {
        // Pin the framing that the census's XXTEA_PAYLOAD_RANGE=2..0x42 got wrong.
        assert_eq!(REGION_1, (2, 98));
        assert_eq!(REGION_2, (98, 114));
        assert_eq!(REGION_3, (114, 250));
        assert_eq!((REGION_1.1 - REGION_1.0) % 4, 0);
        assert_eq!((REGION_2.1 - REGION_2.0) % 4, 0);
        assert_eq!((REGION_3.1 - REGION_3.0) % 4, 0);
    }

    /// End-to-end: a deployed page decodes and resolves to the exact observed
    /// identity via the admission bridge for each admitted family, including an
    /// exact page-backed BHB428 SKU.
    #[test]
    fn deployed_page_feeds_observed_identity_bridge() {
        use crate::hashboard_eeprom::{
            observed_protocol_for_deployed_board_name, observed_protocol_from_deployed_page,
        };
        use dcentrald_common::board_desc::AsicProtocolIdentity;

        let bm1362_page = synth_page(0x04, "BHB42601", "L1C021CK11", 1360, 545);
        assert_eq!(
            observed_protocol_from_deployed_page(&bm1362_page),
            Some(AsicProtocolIdentity::Bm1362)
        );

        let bm1366_page = synth_page(0x05, "BHB56903", "S1GX23CM2E", 1380, 670);
        assert_eq!(
            observed_protocol_from_deployed_page(&bm1366_page),
            Some(AsicProtocolIdentity::Bm1366)
        );

        // These are the three exact BHB427/BHB428 SKUs backed by held matched
        // pages. Each name, BM1362 lot-code letter C, and exact catalog row agree.
        for (name, marking) in [
            ("BHB42701", "L1C021CK11"),
            ("BHB42801", "L1C021CK11"),
            ("BHB42831", "E1C022AR19"),
        ] {
            let page = synth_page(0x04, name, marking, 1560, 585);
            let decoded = decode_deployed_eeprom(&page).expect("decodes");
            assert_eq!(decoded.board_name, name);
            assert_eq!(decoded.chip_family(), Some("BM1362"));
            assert_eq!(
                observed_protocol_from_deployed_page(&page),
                Some(AsicProtocolIdentity::Bm1362)
            );
            assert_eq!(
                observed_protocol_for_deployed_board_name(&decoded.board_name),
                Some(AsicProtocolIdentity::Bm1362)
            );
        }

        // A malformed page yields no observed identity (fail-closed).
        assert_eq!(observed_protocol_from_deployed_page(&[0u8; 10]), None);
    }

    /// Rank-13 named case: a page whose `board_name` says `BHB426…` (BM1362) but
    /// whose lot-code letter is `G` (BM1366's) must be refused; the same page with
    /// the correct `C` is admitted. Exercised through the production entry point
    /// `observed_protocol_from_deployed_page`, not `corroborate_marking` directly.
    #[test]
    fn marking_disagreement_refuses_the_page() {
        use crate::hashboard_eeprom::observed_protocol_from_deployed_page;
        use dcentrald_common::board_desc::AsicProtocolIdentity;

        let lying = synth_page(0x04, "BHB42601", "S1G021CK11", 1360, 545);
        assert_eq!(observed_protocol_from_deployed_page(&lying), None);

        let honest = synth_page(0x04, "BHB42601", "S1C021CK11", 1360, 545);
        assert_eq!(
            observed_protocol_from_deployed_page(&honest),
            Some(AsicProtocolIdentity::Bm1362)
        );
    }

    /// An unrecognised lot-code letter on an otherwise-admissible SKU fails closed.
    #[test]
    fn unknown_marking_letter_refuses() {
        use crate::hashboard_eeprom::observed_protocol_from_deployed_page;
        let page = synth_page(0x04, "BHB42601", "S1Q021CK11", 1360, 545);
        assert_eq!(observed_protocol_from_deployed_page(&page), None);
    }

    /// A marking with no byte 23 (empty, or shorter than 3 chars) fails closed —
    /// absent evidence is a refusal, never a guessed letter.
    #[test]
    fn absent_marking_refuses() {
        use crate::hashboard_eeprom::observed_protocol_from_deployed_page;
        let short = synth_page(0x04, "BHB42601", "AB", 1360, 545);
        assert_eq!(observed_protocol_from_deployed_page(&short), None);
        let empty = synth_page(0x04, "BHB42601", "", 1360, 545);
        assert_eq!(observed_protocol_from_deployed_page(&empty), None);
    }

    /// KAT: the three real-dump lot codes reduce to `C`/`G`/`V` via the accessor.
    /// Lot codes are shared across a production batch, not per-unit serials, so
    /// this publishes no operator hardware serial (`deployed_eeprom.rs:29-31`).
    #[test]
    fn held_page_letters_are_c_g_v() {
        for (class, name, marking, expect) in [
            (0x04u8, "BHB42601", "L1C021CK11", 'C'),
            (0x04u8, "BHB42831", "E1C022AR19", 'C'),
            (0x05u8, "BHB56903", "S1GX23CM2E", 'G'),
            (0x05u8, "BHB68606", "S1VX24AW21", 'V'),
        ] {
            let page = synth_page(class, name, marking, 1360, 545);
            let id = decode_deployed_eeprom(&page).expect("decodes");
            assert_eq!(id.chip_marking, marking);
            assert_eq!(id.chip_marking_family_letter(), Some(expect));
        }
    }

    /// The corroborator can only ever NARROW: if a page is admitted through
    /// `observed_protocol_from_deployed_page`, the name alone must also admit.
    #[test]
    fn corroboration_can_only_narrow() {
        use crate::hashboard_eeprom::{
            observed_protocol_for_deployed_board_name, observed_protocol_from_deployed_page,
        };
        for (class, name, marking) in [
            (0x04u8, "BHB42601", "S1C021CK11"), // agrees
            (0x04, "BHB42601", "S1G021CK11"),   // corroborator refuses
            (0x05, "BHB56903", "S1GX23CM2E"),   // agrees
            (0x04, "BHB42801", "S1C021CK11"),   // exact page-backed BM1362 SKU
        ] {
            let page = synth_page(class, name, marking, 1360, 545);
            if observed_protocol_from_deployed_page(&page).is_some() {
                assert!(
                    observed_protocol_for_deployed_board_name(name).is_some(),
                    "page-admit must imply name-admit for {name}"
                );
            }
        }
    }
}
