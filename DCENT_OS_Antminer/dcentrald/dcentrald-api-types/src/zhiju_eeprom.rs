//! Bitmain "zhiju information" hashboard-EEPROM block — byte-exact plaintext layout.
//!
//! # Provenance
//!
//! Extracted 2026-07-24 from Bitmain's own factory test jig
//!  (ARM32 LE, stripped)
//! via GhidraMCP. The dumper `FUN_000164bc` `printf`s every field of the decoded
//! in-memory block from base `0x001cde4c`, which yields the field order, widths, and
//! endianness directly — no guessing.
//!
//! **Corroborated on a second binary:** the BM1362 jig
//!  carries a
//! byte-identical dump block (same field set, same order, matching `%c` widths — SN[17]
//! @0x03, chip_die[2] @0x14, chip_marking[13] @0x16, chip_technology[2] @0x33). So the
//! layout is not single-source. The CRC5 ([`bitmain_crc5`]) is independently confirmed
//! against a published BM13xx command vector (see its test).
//!
//! `zhiju` (治具) is Chinese for "jig/fixture": this is the block the factory test
//! fixture writes and reads back.
//!
//! # Why this exists
//!
//! [`crate::eeprom_record`] dispatches on the 2-byte preamble and, for `(0x04, 0x11)`,
//! returns a **preamble-only** [`crate::eeprom_record::X19PlainRecord`] with the note
//! that "full field decode requires capturing a BHB42xxx plaintext dump and matching it
//! against the bosminer panic-string field list". This module supplies that field list.
//!
//! That matters for hardware enablement: `(0x04, 0x11)` covers the **whole** BHB42xxx
//! family — S19 / S19j Pro / T19, i.e. **both BM1398 and BM1362**. The preamble alone
//! therefore cannot authorize BM1398-specific voltage/reset/UART mutation, which is
//! exactly why `serial_mining.rs` refuses native BM1398 as `NOT IMPLEMENTED`. The
//! discriminating fields live *inside* this block: [`ZhijuInformationBlock::chip_marking`],
//! [`ZhijuInformationBlock::chip_die`], and [`ZhijuInformationBlock::chip_technology`].
//!
//! # Status
//!
//! **Experimental — decode only.** This module is pure data parsing: no HAL, no I/O, no
//! write path. It does not by itself authorize any hardware mutation; a caller must still
//! pair a decoded identity with the platform's admission rules.
//!
//! # Known ambiguities (deliberately NOT resolved by guessing)
//!
//! * **Byte 1.** The jig labels it `zhiju_information_length`. The live S19 Pro
//!   capture (bench-20260902-nbp1901, BM1398-generation pages) reads `0x42` (66)
//!   — exactly this block's span, supporting the "length" reading on this
//!   generation. The previously recorded `0x11` (17) values belong to the
//!   deployed-format pages (`04 11` / `05 11`, [`crate::deployed_eeprom`]) where
//!   byte 1 is the algorithm/key selector (XXTEA nibble 0x1 + key index 0x1),
//!   not to a BM1398-generation zhiju page. Both readings are recorded; neither
//!   is enforced. The byte is exposed raw as
//!   [`ZhijuInformationBlock::zhiju_information_length`].
//! * **CRC5.** The trailing byte at `+0x41` is `zhiju_information_crc5` in the jig, but the
//!   polynomial/init/width over which it is computed was not recovered. It is exposed raw
//!   and **not** validated. Do not invent a CRC check here — a wrong check would reject
//!   good boards. (The recovered [`bitmain_crc5`] + fail-open [`Crc5Check`] surface below
//!   recomputes but never rejects; it matched both live-captured blocks,
//!   bench-20260902-nbp1901.)
//! * **`+0x3F`/`+0x40`** are not printed by the jig dumper and are treated as reserved.
//! * **Trailing die/marking codes (live pages).** On the live NBP1901 pages the
//!   bytes at `[0x14..0x23)` read `ED` + `A13X20AU01` (boards 1/2) and `ED` +
//!   `H13X20BV1L` (board 3) — `chip_die` + `chip_marking` in the jig field map.
//!   Bitmain's semantics for these part/date codes are pinned by NO held
//!   factory source; the offsets and raw values are facts, and any meaning
//!   beyond them is a labeled HYPOTHESIS (B6 dossier §12). Do not build logic
//!   on the code characters.
//!
//! Cipher note: [`decode_zhiju_block`] consumes **plaintext**, matching
//! [`crate::eeprom_record::dispatch`]. Boards whose payload is enciphered must be run
//! through the cipher pass first.

use serde::{Deserialize, Serialize};

/// Offsets are relative to the start of the plaintext block (jig base `0x001cde4c`).
pub mod offset {
    pub const ALGORITHM_AND_KEY_VERSION: usize = 0x00;
    pub const ZHIJU_INFORMATION_LENGTH: usize = 0x01;
    pub const ZHIJU_INFORMATION_FORMAT_VERSION: usize = 0x02;
    pub const HASHBOARD_SN: usize = 0x03;
    pub const CHIP_DIE: usize = 0x14;
    pub const CHIP_MARKING: usize = 0x16;
    pub const CHIP_BIN: usize = 0x23;
    pub const CHIP_FT_PROGRAM_VERSION: usize = 0x24;
    pub const ASIC_SENSOR: usize = 0x28;
    pub const ASIC_SENSOR_ADDR: usize = 0x29;
    pub const PIC_SENSOR: usize = 0x2D;
    pub const PIC_SENSOR_ADDR: usize = 0x2E;
    pub const PCB_VERSION_V1: usize = 0x2F;
    pub const PCB_VERSION_V2: usize = 0x30;
    pub const BOM_VERSION_V1: usize = 0x31;
    pub const BOM_VERSION_V2: usize = 0x32;
    pub const CHIP_TECHNOLOGY: usize = 0x33;
    /// Big-endian u16 (the jig decodes with `x << 8 | x >> 8`).
    pub const VOLTAGE_MV: usize = 0x35;
    /// Big-endian u16.
    pub const FREQUENCY_MHZ: usize = 0x37;
    /// Big-endian u16.
    pub const NONCE_RATE: usize = 0x39;
    pub const PCB_TEMPERATURE_IN: usize = 0x3B;
    pub const PCB_TEMPERATURE_OUT: usize = 0x3C;
    pub const TEST_VERSION: usize = 0x3D;
    pub const TEST_STANDARD: usize = 0x3E;
    pub const ZHIJU_INFORMATION_CRC5: usize = 0x41;
}

/// Field widths for the ASCII/array members.
pub const HASHBOARD_SN_LEN: usize = 17;
pub const CHIP_DIE_LEN: usize = 2;
pub const CHIP_MARKING_LEN: usize = 13;
pub const CHIP_TECHNOLOGY_LEN: usize = 2;
/// The RAW field is 4 bytes — bounded by `asic_sensor` at `+0x28`. The BM1362 jig's
/// dump *prints* it as 9 chars, but that reads a wider parsed QR-string buffer, not a
/// 9-byte contiguous EEPROM field; a 9-byte raw field at `+0x24` would overrun
/// `asic_sensor`. Do NOT widen this offset.
pub const CHIP_FT_PROGRAM_VERSION_LEN: usize = 4;
pub const ASIC_SENSOR_ADDR_LEN: usize = 4;

/// Smallest plaintext length that contains every field the jig prints.
pub const ZHIJU_BLOCK_MIN_LEN: usize = offset::ZHIJU_INFORMATION_CRC5 + 1;

/// Decoded Bitmain zhiju hashboard-EEPROM block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZhijuInformationBlock {
    /// Raw byte 0. Selects the cipher/key generation (`0x04` BHB42xxx, `0x05`
    /// BHB56xxx — both desk-derived rows). LIVE-PROVEN third row: `0x11` on the
    /// bench-20260902-nbp1901 BM1398-generation pages (nibbles XXTEA=1/slot-1),
    /// which decode under the AMTC jig table's slot-1 key `uileynimggnagnau`
    /// and under NO `KEY_LARGE` slot — see the G3 evidence rows at
    /// [`crate::deployed_eeprom::LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY`].
    /// Evidence record only; decode stays keyed by explicit key selection.
    pub algorithm_and_key_version: u8,
    /// Raw byte 1. See the module-level ambiguity note — NOT interpreted here.
    pub zhiju_information_length: u8,
    pub zhiju_information_format_version: u8,
    /// 17-char factory serial. Unique per physical hashboard.
    pub hashboard_sn: String,
    /// 2-char die code.
    pub chip_die: String,
    /// 13-char ASIC marking — the primary chip-type discriminator within a preamble family.
    pub chip_marking: String,
    pub chip_bin: u8,
    /// 4 bytes, rendered by the jig as `*%d*%02d*%d*%d`.
    pub chip_ft_program_version: [u8; CHIP_FT_PROGRAM_VERSION_LEN],
    /// Sensor model code (e.g. NCT218 on S19 Pro per the AMTC `Config.ini`).
    pub asic_sensor: u8,
    pub asic_sensor_addr: [u8; ASIC_SENSOR_ADDR_LEN],
    /// PIC-side sensor model code (LM75A on S19 Pro).
    pub pic_sensor: u8,
    pub pic_sensor_addr: u8,
    pub pcb_version_v1: u8,
    pub pcb_version_v2: u8,
    pub bom_version_v1: u8,
    pub bom_version_v2: u8,
    /// 2-char process/technology code.
    pub chip_technology: String,
    /// Factory-binned operating voltage, millivolts (big-endian on the wire).
    pub voltage_mv: u16,
    /// Factory-binned operating frequency, MHz (big-endian on the wire).
    pub frequency_mhz: u16,
    /// Factory-measured nonce rate (big-endian on the wire).
    pub nonce_rate: u16,
    /// Signed Celsius.
    pub pcb_temperature_in: i8,
    /// Signed Celsius.
    pub pcb_temperature_out: i8,
    pub test_version: u8,
    pub test_standard: u8,
    /// Stored CRC5 byte. **Not validated** — see the module-level note.
    pub zhiju_information_crc5: u8,
}

/// Decode failure for [`decode_zhiju_block`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ZhijuDecodeError {
    /// Fewer bytes than [`ZHIJU_BLOCK_MIN_LEN`].
    Truncated { got: usize, need: usize },
    /// An ASCII field held bytes outside printable ASCII / NUL padding.
    NonAsciiField { field: &'static str, offset: usize },
}

impl core::fmt::Display for ZhijuDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { got, need } => {
                write!(f, "zhiju block truncated: got {got} bytes, need {need}")
            }
            Self::NonAsciiField { field, offset } => {
                write!(
                    f,
                    "zhiju field '{field}' at offset {offset} is not printable ASCII"
                )
            }
        }
    }
}

impl std::error::Error for ZhijuDecodeError {}

/// Read a fixed-width ASCII field, trimming NUL and trailing spaces.
///
/// Rejects any non-NUL byte outside printable ASCII so a mis-decrypted or
/// mis-offset blob surfaces as an error rather than mojibake identity.
fn read_ascii(
    plaintext: &[u8],
    start: usize,
    len: usize,
    field: &'static str,
) -> Result<String, ZhijuDecodeError> {
    let bytes = &plaintext[start..start + len];
    if !bytes.iter().all(|b| *b == 0 || (*b >= 0x20 && *b < 0x7F)) {
        return Err(ZhijuDecodeError::NonAsciiField {
            field,
            offset: start,
        });
    }
    let text: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as char)
        .collect();
    Ok(text.trim_end().to_string())
}

#[inline]
fn read_be_u16(plaintext: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([plaintext[at], plaintext[at + 1]])
}

/// Decode a plaintext zhiju block.
///
/// `plaintext` must already be post-cipher, matching
/// [`crate::eeprom_record::dispatch`]'s contract. Extra trailing bytes are ignored.
pub fn decode_zhiju_block(plaintext: &[u8]) -> Result<ZhijuInformationBlock, ZhijuDecodeError> {
    if plaintext.len() < ZHIJU_BLOCK_MIN_LEN {
        return Err(ZhijuDecodeError::Truncated {
            got: plaintext.len(),
            need: ZHIJU_BLOCK_MIN_LEN,
        });
    }

    let mut chip_ft_program_version = [0u8; CHIP_FT_PROGRAM_VERSION_LEN];
    chip_ft_program_version.copy_from_slice(
        &plaintext[offset::CHIP_FT_PROGRAM_VERSION
            ..offset::CHIP_FT_PROGRAM_VERSION + CHIP_FT_PROGRAM_VERSION_LEN],
    );

    let mut asic_sensor_addr = [0u8; ASIC_SENSOR_ADDR_LEN];
    asic_sensor_addr.copy_from_slice(
        &plaintext[offset::ASIC_SENSOR_ADDR..offset::ASIC_SENSOR_ADDR + ASIC_SENSOR_ADDR_LEN],
    );

    Ok(ZhijuInformationBlock {
        algorithm_and_key_version: plaintext[offset::ALGORITHM_AND_KEY_VERSION],
        zhiju_information_length: plaintext[offset::ZHIJU_INFORMATION_LENGTH],
        zhiju_information_format_version: plaintext[offset::ZHIJU_INFORMATION_FORMAT_VERSION],
        hashboard_sn: read_ascii(
            plaintext,
            offset::HASHBOARD_SN,
            HASHBOARD_SN_LEN,
            "hashboard_sn",
        )?,
        chip_die: read_ascii(plaintext, offset::CHIP_DIE, CHIP_DIE_LEN, "chip_die")?,
        chip_marking: read_ascii(
            plaintext,
            offset::CHIP_MARKING,
            CHIP_MARKING_LEN,
            "chip_marking",
        )?,
        chip_bin: plaintext[offset::CHIP_BIN],
        chip_ft_program_version,
        asic_sensor: plaintext[offset::ASIC_SENSOR],
        asic_sensor_addr,
        pic_sensor: plaintext[offset::PIC_SENSOR],
        pic_sensor_addr: plaintext[offset::PIC_SENSOR_ADDR],
        pcb_version_v1: plaintext[offset::PCB_VERSION_V1],
        pcb_version_v2: plaintext[offset::PCB_VERSION_V2],
        bom_version_v1: plaintext[offset::BOM_VERSION_V1],
        bom_version_v2: plaintext[offset::BOM_VERSION_V2],
        chip_technology: read_ascii(
            plaintext,
            offset::CHIP_TECHNOLOGY,
            CHIP_TECHNOLOGY_LEN,
            "chip_technology",
        )?,
        voltage_mv: read_be_u16(plaintext, offset::VOLTAGE_MV),
        frequency_mhz: read_be_u16(plaintext, offset::FREQUENCY_MHZ),
        nonce_rate: read_be_u16(plaintext, offset::NONCE_RATE),
        pcb_temperature_in: plaintext[offset::PCB_TEMPERATURE_IN] as i8,
        pcb_temperature_out: plaintext[offset::PCB_TEMPERATURE_OUT] as i8,
        test_version: plaintext[offset::TEST_VERSION],
        test_standard: plaintext[offset::TEST_STANDARD],
        zhiju_information_crc5: plaintext[offset::ZHIJU_INFORMATION_CRC5],
    })
}

// ----------------------------------------------------------------------------
// CRC5, chip_bin, and cipher framing — recovered 2026-07-24 (jig FUN_00016778)
// ----------------------------------------------------------------------------

/// Bitmain BM13xx CRC5 over a bit-length prefix of `data`, MSB-first.
///
/// Recovered from `single_board_test_bm1398` `FUN_00016778`: a bit-serial 5-stage
/// LFSR, all five state bits initialised to 1 (init `0x1F`), input consumed MSB-first,
/// feedback `f = top_bit ^ input_bit` injected at taps 0 and 2 (polynomial
/// x^5 + x^2 + 1 = `0x05`), output = the 5 register bits with no final inversion.
/// This is the same poly/init as the standing CMD-CRC5 rule
/// and the public cgminer/bmminer BM13xx CRC5 — two
/// independent corroborations of the recovered algorithm.
///
/// `bit_len` is the number of bits of `data` to consume (the jig covers `(n-1)*8`
/// bits, i.e. the block minus its trailing CRC byte).
pub fn bitmain_crc5(data: &[u8], bit_len: usize) -> u8 {
    debug_assert!(
        bit_len <= data.len() * 8,
        "bitmain_crc5 bit_len {bit_len} exceeds data ({} bits)",
        data.len() * 8
    );
    // 5-bit LFSR held as bits [4..0]; all ones = 0x1F.
    let mut reg: u8 = 0x1F;
    for bit_index in 0..bit_len {
        let byte = data[bit_index / 8];
        // MSB-first within each byte.
        let input_bit = (byte >> (7 - (bit_index % 8))) & 1;
        let top = (reg >> 4) & 1;
        let feedback = top ^ input_bit;
        // Shift left within 5 bits, then inject feedback at taps 0 and 2.
        reg = ((reg << 1) & 0x1F) ^ (feedback) ^ (feedback << 2);
    }
    reg & 0x1F
}

impl ZhijuInformationBlock {
    /// Recompute and compare the stored CRC5 over the fixed block span.
    ///
    /// The stored CRC is the byte at [`offset::ZHIJU_INFORMATION_CRC5`] (`0x41`) — the
    /// same byte [`decode_zhiju_block`] reads — and the CRC covers every byte before it
    /// (`data[..0x41]`, i.e. `0x41 * 8` bits). `data` must be the full plaintext block
    /// passed to [`decode_zhiju_block`].
    ///
    /// This deliberately does NOT derive coverage from the `zhiju_information_length`
    /// byte: that field's meaning is unreconciled in the RE (it reads `0x11` = 17 on a
    /// real S19 Pro board, not the block span `0x42`), so trusting it would put the
    /// "stored CRC" inside `hashboard_sn` and never inspect the real CRC. The residual
    /// RE uncertainty is therefore the coverage-length *source*, not the algorithm —
    /// the CRC5 arithmetic itself is confirmed against a published BM13xx command
    /// vector (see [`bitmain_crc5`]'s test).
    ///
    /// **Returns a status, never rejects.** Callers MUST treat [`Crc5Check::Mismatch`]
    /// as a WARN, not a board rejection — a wrong check rejects good boards. Validated
    /// 2026-09-02 against the two live-captured NBP1901 plaintext blocks (both `Match`,
    /// bench-20260902-nbp1901; still fail-open: n=1 unit, and a 5-bit CRC accepts a
    /// wrong page 1 time in 32 by construction).
    pub fn verify_crc5(&self, data: &[u8]) -> Crc5Check {
        // Fail-safe on short input: nothing to check rather than panic.
        if data.len() <= offset::ZHIJU_INFORMATION_CRC5 {
            return Crc5Check::Unknown;
        }
        let stored = data[offset::ZHIJU_INFORMATION_CRC5] & 0x1F;
        let computed = bitmain_crc5(
            &data[..offset::ZHIJU_INFORMATION_CRC5],
            offset::ZHIJU_INFORMATION_CRC5 * 8,
        );
        if computed == stored {
            Crc5Check::Match
        } else {
            Crc5Check::Mismatch { computed, stored }
        }
    }
}

/// Result of a **non-authoritative** CRC5 recompute. `Mismatch` is a WARN signal, not
/// a board-rejection verdict (see [`ZhijuInformationBlock::verify_crc5`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "crc5", rename_all = "snake_case")]
pub enum Crc5Check {
    Match,
    Mismatch {
        computed: u8,
        stored: u8,
    },
    /// The length byte was out of range; nothing was checked.
    ///
    /// This is the [`Default`] deliberately: it is the "no claim was made"
    /// value, so a `#[serde(default)]` field on an older persisted record
    /// deserializes to *nothing was checked* rather than fabricating a
    /// `Match` that no code ever computed.
    #[default]
    Unknown,
}

/// Decode the single-ASCII-digit `chip_bin` field (`'1'..='5'` → `1..=5`).
///
/// From jig `FUN_0001e3c0` (`get_chip_bin`): any other byte (including `0x00`/`0xFF`)
/// is "unknown" → `None`. Note the raw `ZhijuInformationBlock::chip_bin` stays the raw
/// byte; this is the interpreted form.
pub fn decode_chip_bin(raw: u8) -> Option<u8> {
    match raw {
        b'1'..=b'5' => Some(raw - b'0'),
        _ => None,
    }
}

/// Cipher framing for the BHB42xxx `(0x04,0x11)` family, from jig `FUN_0001c148`.
///
/// The two header bytes ([`offset::ALGORITHM_AND_KEY_VERSION`] and
/// [`offset::ZHIJU_INFORMATION_LENGTH`]) stay **plaintext**; XXTEA covers the payload
/// at `[2..0x42]` (64 bytes = payload + CRC). A decrypter must therefore leave bytes
/// 0 and 1 untouched and decrypt only that window. Constant provided so callers get
/// the boundary from one place.
pub const XXTEA_PAYLOAD_RANGE: core::ops::Range<usize> = 2..0x42;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic block at the jig-derived offsets.
    fn sample() -> Vec<u8> {
        let mut b = vec![0u8; ZHIJU_BLOCK_MIN_LEN];
        b[offset::ALGORITHM_AND_KEY_VERSION] = 0x04;
        b[offset::ZHIJU_INFORMATION_LENGTH] = 0x11;
        b[offset::ZHIJU_INFORMATION_FORMAT_VERSION] = 0x01;
        b[offset::HASHBOARD_SN..offset::HASHBOARD_SN + HASHBOARD_SN_LEN]
            .copy_from_slice(b"BHB42601AB2345678");
        b[offset::CHIP_DIE..offset::CHIP_DIE + CHIP_DIE_LEN].copy_from_slice(b"AA");
        b[offset::CHIP_MARKING..offset::CHIP_MARKING + CHIP_MARKING_LEN]
            .copy_from_slice(b"BM1398BB\0\0\0\0\0");
        b[offset::CHIP_BIN] = 3;
        b[offset::CHIP_FT_PROGRAM_VERSION] = 1;
        b[offset::CHIP_FT_PROGRAM_VERSION + 1] = 2;
        b[offset::CHIP_FT_PROGRAM_VERSION + 2] = 3;
        b[offset::CHIP_FT_PROGRAM_VERSION + 3] = 4;
        b[offset::ASIC_SENSOR] = 0x9C; // NCT218 per AMTC Config.ini
        b[offset::ASIC_SENSOR_ADDR] = 25;
        b[offset::ASIC_SENSOR_ADDR + 1] = 57;
        b[offset::ASIC_SENSOR_ADDR + 2] = 58;
        b[offset::ASIC_SENSOR_ADDR + 3] = 90;
        b[offset::PIC_SENSOR] = 0x90; // LM75A
        b[offset::PIC_SENSOR_ADDR] = 0x01;
        b[offset::PCB_VERSION_V1] = 1;
        b[offset::PCB_VERSION_V2] = 2;
        b[offset::BOM_VERSION_V1] = 3;
        b[offset::BOM_VERSION_V2] = 4;
        b[offset::CHIP_TECHNOLOGY..offset::CHIP_TECHNOLOGY + CHIP_TECHNOLOGY_LEN]
            .copy_from_slice(b"N7");
        // Big-endian, per the jig's `x << 8 | x >> 8` decode.
        b[offset::VOLTAGE_MV..offset::VOLTAGE_MV + 2].copy_from_slice(&1360u16.to_be_bytes());
        b[offset::FREQUENCY_MHZ..offset::FREQUENCY_MHZ + 2].copy_from_slice(&525u16.to_be_bytes());
        b[offset::NONCE_RATE..offset::NONCE_RATE + 2].copy_from_slice(&9950u16.to_be_bytes());
        b[offset::PCB_TEMPERATURE_IN] = (-5i8) as u8;
        b[offset::PCB_TEMPERATURE_OUT] = 42;
        b[offset::TEST_VERSION] = 7;
        b[offset::TEST_STANDARD] = 8;
        b[offset::ZHIJU_INFORMATION_CRC5] = 0x1F;
        b
    }

    #[test]
    fn decodes_every_jig_printed_field() {
        let d = decode_zhiju_block(&sample()).expect("decode");
        assert_eq!(d.algorithm_and_key_version, 0x04);
        assert_eq!(d.zhiju_information_length, 0x11);
        assert_eq!(d.hashboard_sn, "BHB42601AB2345678");
        assert_eq!(d.chip_die, "AA");
        assert_eq!(d.chip_marking, "BM1398BB");
        assert_eq!(d.chip_bin, 3);
        assert_eq!(d.chip_ft_program_version, [1, 2, 3, 4]);
        assert_eq!(d.asic_sensor_addr, [25, 57, 58, 90]);
        assert_eq!(d.chip_technology, "N7");
        assert_eq!(d.pcb_temperature_in, -5);
        assert_eq!(d.pcb_temperature_out, 42);
        assert_eq!(d.zhiju_information_crc5, 0x1F);
    }

    /// The jig byte-swaps these three; a little-endian read would give 20740/3075/57383.
    #[test]
    fn voltage_frequency_nonce_rate_are_big_endian() {
        let d = decode_zhiju_block(&sample()).expect("decode");
        assert_eq!(d.voltage_mv, 1360);
        assert_eq!(d.frequency_mhz, 525);
        assert_eq!(d.nonce_rate, 9950);
    }

    /// `hashboard_sn` is exactly 17 bytes, so an 18-char source is truncated, not overrun.
    #[test]
    fn hashboard_sn_is_bounded_to_seventeen_bytes() {
        let d = decode_zhiju_block(&sample()).expect("decode");
        assert_eq!(d.hashboard_sn.len(), HASHBOARD_SN_LEN);
    }

    #[test]
    fn truncated_block_is_refused_not_padded() {
        let mut short = sample();
        short.truncate(ZHIJU_BLOCK_MIN_LEN - 1);
        assert_eq!(
            decode_zhiju_block(&short),
            Err(ZhijuDecodeError::Truncated {
                got: ZHIJU_BLOCK_MIN_LEN - 1,
                need: ZHIJU_BLOCK_MIN_LEN,
            })
        );
    }

    /// A mis-decrypted blob must fail loudly rather than yield a garbage identity that
    /// could be mistaken for a real chip marking.
    #[test]
    fn non_ascii_identity_field_is_refused() {
        let mut b = sample();
        b[offset::CHIP_MARKING + 2] = 0xFF;
        assert_eq!(
            decode_zhiju_block(&b),
            Err(ZhijuDecodeError::NonAsciiField {
                field: "chip_marking",
                offset: offset::CHIP_MARKING,
            })
        );
    }

    /// Trailing bytes beyond the known block must not break the decode.
    #[test]
    fn extra_trailing_bytes_are_ignored() {
        let mut b = sample();
        b.extend_from_slice(&[0xAB; 190]);
        assert!(decode_zhiju_block(&b).is_ok());
    }

    /// Offsets are load-bearing RE facts; pin them so a refactor cannot silently shift
    /// the identity fields.
    #[test]
    fn jig_derived_offsets_are_pinned() {
        assert_eq!(offset::HASHBOARD_SN, 0x03);
        assert_eq!(offset::CHIP_DIE, 0x14);
        assert_eq!(offset::CHIP_MARKING, 0x16);
        assert_eq!(offset::CHIP_TECHNOLOGY, 0x33);
        assert_eq!(offset::VOLTAGE_MV, 0x35);
        assert_eq!(offset::ZHIJU_INFORMATION_CRC5, 0x41);
        assert_eq!(ZHIJU_BLOCK_MIN_LEN, 0x42);
    }

    // --- CRC5 / chip_bin / cipher framing (L2, fail-open) ---

    #[test]
    fn crc5_is_deterministic_and_length_sensitive() {
        // Same bytes, same CRC; different bytes, (almost surely) different CRC.
        let a = bitmain_crc5(&[0x11, 0x42, 0xAB, 0xCD], 4 * 8);
        let b = bitmain_crc5(&[0x11, 0x42, 0xAB, 0xCD], 4 * 8);
        assert_eq!(a, b);
        assert!(a <= 0x1F, "CRC5 output must be 5 bits");
        let c = bitmain_crc5(&[0x11, 0x42, 0xAB, 0xCE], 4 * 8);
        assert_ne!(a, c);
    }

    /// Published BM13xx command vector: the BM1397 GETADDRESS frame is
    /// `55 AA 52 05 00 00 0A`, i.e. CRC5 over `[0x52,0x05,0x00,0x00]` == `0x0A`
    /// (skot/BM1397, cgminer-gekko). The EEPROM zhiju CRC5 uses the same poly/init
    /// (jig FUN_00016778, 3-way corroborated), so matching this real vector confirms
    /// the algorithm AND the 5-bit output ordering — raising the CRC above
    /// self-consistency, though `verify_crc5` still ships fail-open until a real
    /// decrypted BHB42xxx block is captured.
    #[test]
    fn crc5_matches_published_bm1397_getaddress_vector() {
        assert_eq!(bitmain_crc5(&[0x52, 0x05, 0x00, 0x00], 32), 0x0A);
    }

    /// Round-trip: compute the CRC5 over the first n-1 bytes, store it at n-1, and
    /// `verify_crc5` must report Match. Corrupting a covered byte must report Mismatch.
    /// (We test the round-trip property, not a hard-coded vector, because the 5-bit
    /// output ordering is the one residual RE uncertainty — hence fail-open.)
    #[test]
    fn verify_crc5_round_trips_and_detects_corruption() {
        let mut b = sample();
        // Coverage is the FIXED block span: CRC at 0x41, covering [..0x41]. This does
        // not depend on the ambiguous length byte.
        let crc = bitmain_crc5(
            &b[..offset::ZHIJU_INFORMATION_CRC5],
            offset::ZHIJU_INFORMATION_CRC5 * 8,
        );
        b[offset::ZHIJU_INFORMATION_CRC5] = crc;
        let decoded = decode_zhiju_block(&b).unwrap();
        assert_eq!(decoded.verify_crc5(&b), Crc5Check::Match);

        // Store a deliberately-wrong CRC (flip one of the 5 bits — guaranteed a
        // different 5-bit value, unlike corrupting a covered data byte which a 5-bit
        // CRC collides with 1-in-32 of the time). This exercises the compare path
        // deterministically without perturbing an ASCII identity field.
        let mut wrong = b.clone();
        wrong[offset::ZHIJU_INFORMATION_CRC5] = crc ^ 0x01;
        assert_eq!(
            decode_zhiju_block(&wrong).unwrap().verify_crc5(&wrong),
            Crc5Check::Mismatch {
                computed: crc,
                stored: crc ^ 0x01,
            }
        );
    }

    /// A too-short slice must report Unknown, never panic (byte-1 is no longer read
    /// before a length guard).
    #[test]
    fn verify_crc5_short_slice_is_unknown_not_panic() {
        let decoded = decode_zhiju_block(&sample()).unwrap();
        assert_eq!(decoded.verify_crc5(&[]), Crc5Check::Unknown);
        assert_eq!(decoded.verify_crc5(&[0x04, 0x11]), Crc5Check::Unknown);
        // Exactly at the CRC offset (no byte to read there) is still Unknown.
        assert_eq!(
            decoded.verify_crc5(&[0u8; offset::ZHIJU_INFORMATION_CRC5]),
            Crc5Check::Unknown
        );
    }

    #[test]
    fn chip_bin_decodes_ascii_digits_only() {
        assert_eq!(decode_chip_bin(b'1'), Some(1));
        assert_eq!(decode_chip_bin(b'5'), Some(5));
        assert_eq!(decode_chip_bin(b'0'), None);
        assert_eq!(decode_chip_bin(b'6'), None);
        assert_eq!(decode_chip_bin(0x00), None);
        assert_eq!(decode_chip_bin(0xFF), None);
    }

    /// The XXTEA window leaves the 2-byte header plaintext and covers [2..0x42].
    #[test]
    fn xxtea_payload_range_leaves_header_plaintext() {
        assert_eq!(XXTEA_PAYLOAD_RANGE, 2..0x42);
        assert!(!XXTEA_PAYLOAD_RANGE.contains(&offset::ALGORITHM_AND_KEY_VERSION));
        assert!(!XXTEA_PAYLOAD_RANGE.contains(&offset::ZHIJU_INFORMATION_LENGTH));
        assert!(XXTEA_PAYLOAD_RANGE.contains(&offset::ZHIJU_INFORMATION_CRC5));
    }

    // ---- G2 bench capture: real deployed NBP1901 pages (2026-09-02) --------
    //
    // Read-only I2C capture from the operator's S19 Pro bench unit (Zynq am2,
    // BM1398, on BraiinsOS) at EEPROMs 0x50/0x51/0x52, sha256-pinned in
    //
    // Boards 1/2 carry byte-identical pages (shared factory serial, corroborated
    // by the Braiins boot table printing the same S/N for both); board 3 differs.
    // Decode: XXTEA over XXTEA_PAYLOAD_RANGE with the BM1398-generation factory
    // slot-1 key `uileynimggnagnau` (pinned in dcentrald-silicon-profiles
    // s19_family_stock::AMTC_S19PRO_JIG_XXTEA_KEY_TABLE slot 1 — exactly the
    // candidate the B6 desk ladder predicted for deployed BM1398 pages).
    // The header declares algorithm_and_key_version 0x11 — a generation outside
    // the desk tables (0x04 BHB42xxx, 0x05 BHB56xxx): the first real G3
    // mapping-table datum. Oracle: the Braiins boot table serials, byte-exact.
    //
    // Operator authorization note: the BraiinsOS image ships no i2c-tools; the
    // operator authorized (interactive, 2026-09-02) a tmpfs-resident static
    // reader that issues only EEPROM read transactions (pointer-set + read,
    // i2cdump-equivalent); deleted from the unit after the capture.

    const G2_PAGE_BOARDS_1_2_HEX: &str = concat!(
        "11422213c85248cf1657052522c82540d466dda751d68d4d5cfe15d56138b98f",
        "8cd7565a7b393d3894ec7f42e1beeef92aeb6b75955ed63d80be85f6a8131757",
        "ade4ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    const G2_PAGE_BOARD_3_HEX: &str = concat!(
        "1142fe6b91b8ec624ae7e16b905fa3281759f33497fec9efd0c14460646f9c88",
        "b2a0fafeeb1ec7fa7b470e52b5636dbe928f3bab3eb86b048dd0e4aa985e6221",
        "5d91ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );

    fn g2_from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    fn g2_decode_live_page(page_hex: &str) -> ZhijuInformationBlock {
        decode_zhiju_block(&g3_live_plaintext_block(page_hex)).expect("live page decodes")
    }

    /// The full plaintext block of a live page: the two header bytes kept
    /// plaintext + the XXTEA window `[2..0x42)` decrypted with the G3
    /// evidence-const key (so the fixtures and the mapping row cannot drift
    /// apart).
    fn g3_live_plaintext_block(page_hex: &str) -> Vec<u8> {
        let page = g2_from_hex(page_hex);
        let key = crate::deployed_eeprom::key_words(
            &crate::deployed_eeprom::LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY,
        );
        let mut block = page[..2].to_vec();
        let plain = crate::deployed_eeprom::decrypt_region(&page, 2, 0x42, &key);
        block.extend_from_slice(&plain);
        block
    }

    #[test]
    fn g2_nbp1901_live_pages_decode_with_bm1398_factory_slot1() {
        let d12 = g2_decode_live_page(G2_PAGE_BOARDS_1_2_HEX);
        assert_eq!(d12.algorithm_and_key_version, 0x11);
        assert_eq!(d12.hashboard_sn, "HQDZYI3BJJDBG0566");
        let d3 = g2_decode_live_page(G2_PAGE_BOARD_3_HEX);
        assert_eq!(d3.algorithm_and_key_version, 0x11);
        assert_eq!(d3.hashboard_sn, "E015YI3BJAAAH0013");
        // Braiins boot table (same session, logread) printed S/N
        // HQDZYI3BJJDBG0566 for hashboards #1 and #2 and E015YI3BJAAAH0013
        // for #3 — the oracle these asserts pin against.
    }

    #[test]
    fn g2_live_pages_have_distinct_serials_and_same_generation() {
        let d12 = g2_decode_live_page(G2_PAGE_BOARDS_1_2_HEX);
        let d3 = g2_decode_live_page(G2_PAGE_BOARD_3_HEX);
        assert_ne!(d12.hashboard_sn, d3.hashboard_sn);
        assert_eq!(d12.algorithm_and_key_version, d3.algorithm_and_key_version);
    }

    // ---- G3: version→key mapping row + residual fields (2026-09-02) --------
    //
    // The live pages' header (0x11/0x42) is the FIRST datum whose key-version
    // byte lies outside the desk-derived 0x04/0x05 rows. The row is recorded
    // as EVIDENCE (dossier B6 §12 + the consts in deployed_eeprom.rs):
    // 0x11 → XXTEA nibble 1 + slot-1 nibble, empirically the BM1398-generation
    // factory slot-1 key `uileynimggnagnau` (AMTC jig table slot 1). Caveats:
    // n=1 unit, 2 distinct boards (boards 1/2 byte-identical pages), single
    // generation sample; arbitration was by the serial oracle, not the header.

    /// The core G3 pin: both live pages carry the mapped header, its nibbles
    /// read XXTEA/slot-1, byte 1 equals the full block span (the jig
    /// "information length" corroboration), and the row's key is the one the
    /// fixtures actually decrypt with (via the evidence const).
    #[test]
    fn g3_live_header_pins_the_mapping_row() {
        for page_hex in [G2_PAGE_BOARDS_1_2_HEX, G2_PAGE_BOARD_3_HEX] {
            let page = g2_from_hex(page_hex);
            assert_eq!(
                page[..2],
                crate::deployed_eeprom::BM1398_GENERATION_LIVE_HEADER[..],
                "live pages must carry the pinned G3 header"
            );
            let d = g2_decode_live_page(page_hex);
            assert_eq!(d.algorithm_and_key_version, 0x11);
            assert_eq!(d.algorithm_and_key_version >> 4, 0x1, "algorithm nibble = XXTEA");
            assert_eq!(d.algorithm_and_key_version & 0x0F, 0x1, "key nibble = slot 1");
            assert_eq!(
                d.zhiju_information_length as usize, ZHIJU_BLOCK_MIN_LEN,
                "byte 1 equals the full block span on the live pages"
            );
        }
        // The evidence-const key is the AMTC jig slot-1 key, byte-exact — and
        // NOT any shipped KEY_LARGE slot (pinned separately in deployed_eeprom).
        assert_eq!(
            crate::deployed_eeprom::LIVE_PROVEN_BM1398_GENERATION_SLOT1_KEY,
            *b"uileynimggnagnau"
        );
    }

    /// First real-plaintext validation of the fail-open CRC5 framing: both live
    /// blocks' stored bytes equal the recompute over `[..0x41]`.
    #[test]
    fn g3_live_pages_crc5_recompute_matches() {
        for page_hex in [G2_PAGE_BOARDS_1_2_HEX, G2_PAGE_BOARD_3_HEX] {
            let block = g3_live_plaintext_block(page_hex);
            let d = decode_zhiju_block(&block).expect("live page decodes");
            assert_eq!(d.verify_crc5(&block), Crc5Check::Match);
        }
    }

    /// Residual G2 fields: the trailing 12-char part/date codes are exactly
    /// `chip_die[2] @0x14` + `chip_marking[13] @0x16` (NUL-padded) — already in
    /// the jig field map. Pinned here with the live values and byte extents.
    /// Semantics are NOT pinned by any held factory source — HYPOTHESIS only,
    /// see the module docs and B6 §12; do not build logic on the characters.
    #[test]
    fn g3_trailing_part_date_code_fields_pinned() {
        let b12 = g3_live_plaintext_block(G2_PAGE_BOARDS_1_2_HEX);
        let b3 = g3_live_plaintext_block(G2_PAGE_BOARD_3_HEX);
        // Byte extents: significant chars at [0x14..0x20), NUL pad [0x20..0x23).
        assert_eq!(&b12[offset::CHIP_DIE..offset::CHIP_DIE + CHIP_DIE_LEN], b"ED");
        assert_eq!(&b12[0x14..0x20], b"EDA13X20AU01");
        assert!(b12[0x20..0x23].iter().all(|&b| b == 0), "NUL padding after the 12th char");
        assert_eq!(&b3[0x14..0x20], b"EDH13X20BV1L");
        assert!(b3[0x20..0x23].iter().all(|&b| b == 0));
        // And the decoded struct fields carry the same values.
        let d12 = decode_zhiju_block(&b12).expect("decode");
        let d3 = decode_zhiju_block(&b3).expect("decode");
        assert_eq!(d12.chip_die, "ED");
        assert_eq!(d12.chip_marking, "A13X20AU01");
        assert_eq!(d3.chip_die, "ED");
        assert_eq!(d3.chip_marking, "H13X20BV1L");
        assert_eq!(format!("{}{}", d12.chip_die, d12.chip_marking), "EDA13X20AU01");
        assert_eq!(format!("{}{}", d3.chip_die, d3.chip_marking), "EDH13X20BV1L");
    }

    /// The G3 row confers NO decode authority on `decode_deployed_eeprom`: a
    /// 256-byte page built from the live capture (0xFF fill + 0x5A sentinel per
    /// the session-receipt page shape) still refuses — the BM1398-generation
    /// page is a zhiju-window page, not a 3-region deployed page. Pins that the
    /// mapping is evidence-recorded, not a dispatch.
    #[test]
    fn g3_mapping_row_adds_no_deployed_dispatch() {
        for page_hex in [G2_PAGE_BOARDS_1_2_HEX, G2_PAGE_BOARD_3_HEX] {
            let captured = g2_from_hex(page_hex);
            let mut page = vec![0xFFu8; crate::deployed_eeprom::RAW_PAGE_LEN];
            page[..captured.len()].copy_from_slice(&captured);
            page[crate::deployed_eeprom::SENTINEL_OFFSET] =
                crate::deployed_eeprom::SENTINEL_VALUE;
            assert_eq!(
                crate::deployed_eeprom::decode_deployed_eeprom(&page),
                Err(crate::deployed_eeprom::DeployedEepromError::UnsupportedAlgorithm {
                    algo_nibble: 0x4
                })
            );
        }
    }

    /// Live V/F corroboration of the big-endian decode: 525 MHz matches the
    /// stock NBP1901 ladder (B6 §2) and the session-receipt live idle reading
    /// (12.80 V / 525 MHz). The +0x35 u16 decodes to 1280 — 12.80 V under the
    /// deployed format's centivolt convention and inside the stock 12.60–13.00 V
    /// band; under this struct's millivolt field label it would be a physically
    /// nonsensical 1.28 V. Unit-label discrepancy recorded (B6 §12); the raw
    /// value exposure of the struct is deliberately unchanged.
    #[test]
    fn g3_live_vf_fields_match_stock_ladder_and_live_idle() {
        for page_hex in [G2_PAGE_BOARDS_1_2_HEX, G2_PAGE_BOARD_3_HEX] {
            let d = g2_decode_live_page(page_hex);
            assert_eq!(d.frequency_mhz, 525);
            assert_eq!(d.voltage_mv, 1280);
        }
    }
}
