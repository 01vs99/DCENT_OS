//! Pure ASIC ticket-mask (difficulty filter) encode SSOT (Gauntlet G24).
//!
//! # Families
//!
//! - **Bit-reversed** (BM1397 S17 jig `bit_swap_table` / `BM1397_set_TM`, BM1387
//!   Braiins, ESP-Miner `get_difficulty_mask` byte reverse, BM1398 protocol
//!   `bm1398_ticket_mask_value`): encode `(difficulty - 1)` as
//!   `reverse_bits().swap_bytes()` (= per-byte bit-reversal, byte order kept).
//! - **Plain** (BM1362/66/68/70 industrial DCENT + fixtures, e.g. BM1368
//!   `FIXTURE_TICKET_MASK = 0x7F` for difficulty 128): encode `difficulty - 1`
//!   without bit-reversal.
//!
//! Register addresses: BM1397+ family **0x14**; BM1387 **0x18** (different map).
//!
//! # ESP-Miner note
//!
//! ESP-Miner floors difficulty to the largest power-of-two before encoding
//! ([`ticket_mask_esp_miner_pow2_floor`]). Industrial ChipDrivers historically
//! use the raw difficulty; both are pure and named so neither is silent.

/// BM1397+ Ticket Mask register (BM1362/66/68/70/97/98).
pub const TICKET_MASK_REG_BM1397PLUS: u8 = 0x14;

/// BM1387 Ticket Mask register (S9 map — **not** 0x14).
pub const TICKET_MASK_REG_BM1387: u8 = 0x18;

/// Ticket-mask value encoding policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TicketMaskEncoding {
    /// Per-byte bit-reversal of `(difficulty - 1)` via `reverse_bits().swap_bytes()`.
    BitReversed,
    /// Plain `(difficulty - 1)` (BM136x industrial / fixtures).
    PlainDiffMinusOne,
}

/// Per-byte bit-reversal of a 32-bit mask (`reverse_bits` then `swap_bytes`).
///
/// Equivalent to indexing an 8-bit bit-swap LUT on each LE byte (BM1397 jig
/// `bit_swap_table`, BM1398 protocol table, ESP-Miner `_reverse_bits` per byte).
/// `const fn` so api-types can share the transform at compile time.
#[inline]
pub const fn bit_reverse_u32_bytewise(mask: u32) -> u32 {
    mask.reverse_bits().swap_bytes()
}

/// Encode a ticket-mask register **value** from pool/ASIC difficulty.
///
/// `difficulty == 0` saturates to mask `0` (no underflow).
#[inline]
pub fn ticket_mask_from_difficulty(encoding: TicketMaskEncoding, difficulty: u32) -> u32 {
    let base = difficulty.saturating_sub(1);
    match encoding {
        TicketMaskEncoding::BitReversed => bit_reverse_u32_bytewise(base),
        TicketMaskEncoding::PlainDiffMinusOne => base,
    }
}

/// Largest power of two ≤ `n` (ESP-Miner `_largest_power_of_two`).
///
/// For `n == 0` returns `0`; for `n == 1` returns `1`.
pub fn largest_power_of_two_le(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    1u32 << (31 - n.leading_zeros())
}

/// ESP-Miner `get_difficulty_mask` pure value (pow2 floor then bit-reversed encode).
///
/// Does **not** emit the 6-byte command frame — only the 32-bit register value.
#[inline]
pub fn ticket_mask_esp_miner_pow2_floor(difficulty: u32) -> u32 {
    let floored = largest_power_of_two_le(difficulty.max(1)).saturating_sub(1);
    bit_reverse_u32_bytewise(floored)
}

/// Protocol map: which encode policy production ChipDrivers use offline.
///
/// Unknown chip IDs return `None`. Prefer [`compute_ticket_mask_policy`] when
/// the caller must refuse silent encoding.
#[inline]
pub fn try_ticket_mask_encoding_for_chip_id(chip_id: u16) -> Option<TicketMaskEncoding> {
    match chip_id {
        // Bit-reversed family (jig / Braiins / BM1397 pure / BM1391 set_TM).
        // R06: BM1396 joins on its cold-spine golden 0x14 = 0xfe
        // (difficulty 128 bit-reversed; HAL stock_bm1396_cold.rs).
        0x1387 | 0x1391 | 0x1393 | 0x1396 | 0x1397 | 0x1398 => {
            Some(TicketMaskEncoding::BitReversed)
        }
        // BM136x industrial plain (fixture 0x7F @ diff 128).
        0x1362 | 0x1366 | 0x1368 | 0x1370 | 0x1373 => Some(TicketMaskEncoding::PlainDiffMinusOne),
        // BM1489: plain (wave-8 unconfirmed vs BM1485 bit-reversed predecessor).
        0x1489 => Some(TicketMaskEncoding::PlainDiffMinusOne),
        _ => None,
    }
}

/// Protocol map with a fail-closed unknown default of plain `(diff-1)`.
///
/// Unknown chips must not invent bit-reversal. Callers that must refuse
/// unknown IDs entirely should use [`compute_ticket_mask_policy`].
#[inline]
pub fn ticket_mask_encoding_for_chip_id(chip_id: u16) -> TicketMaskEncoding {
    try_ticket_mask_encoding_for_chip_id(chip_id).unwrap_or(TicketMaskEncoding::PlainDiffMinusOne)
}

/// Ticket-mask register for a known encoding family. BM1387 uses 0x18; BM1397+ uses 0x14.
#[inline]
pub fn ticket_mask_register_for_chip_id(chip_id: u16) -> Option<u8> {
    match try_ticket_mask_encoding_for_chip_id(chip_id) {
        None => None,
        Some(_) if chip_id == 0x1387 => Some(TICKET_MASK_REG_BM1387),
        Some(_) => Some(TICKET_MASK_REG_BM1397PLUS),
    }
}

/// Computed ticket-mask policy. Does **not** write hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketMaskPolicy {
    pub chip_id: u16,
    pub encoding: TicketMaskEncoding,
    pub register: u8,
    pub mask: u32,
}

/// Unknown-chip refuse for [`compute_ticket_mask_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketMaskPolicyError {
    UnknownChip { chip_id: u16 },
}

impl std::fmt::Display for TicketMaskPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownChip { chip_id } => write!(
                f,
                "unknown chip ID 0x{chip_id:04X}: refuse silent ticket-mask encoding"
            ),
        }
    }
}

impl std::error::Error for TicketMaskPolicyError {}

/// Compute ticket-mask value + register for a known chip. Never writes hardware.
#[inline]
pub fn compute_ticket_mask_policy(
    chip_id: u16,
    difficulty: u32,
) -> Result<TicketMaskPolicy, TicketMaskPolicyError> {
    let encoding = try_ticket_mask_encoding_for_chip_id(chip_id)
        .ok_or(TicketMaskPolicyError::UnknownChip { chip_id })?;
    let register = ticket_mask_register_for_chip_id(chip_id)
        .ok_or(TicketMaskPolicyError::UnknownChip { chip_id })?;
    Ok(TicketMaskPolicy {
        chip_id,
        encoding,
        register,
        mask: ticket_mask_from_difficulty(encoding, difficulty),
    })
}

/// Resolve ticket-mask value for a chip id + difficulty (production pure).
///
/// Unknown chips still encode plain `(diff-1)` here so existing ChipDriver
/// thin-wraps stay byte-stable. New callers that must refuse unknown IDs
/// should use [`compute_ticket_mask_policy`].
#[inline]
pub fn resolve_ticket_mask(chip_id: u16, difficulty: u32) -> u32 {
    ticket_mask_from_difficulty(ticket_mask_encoding_for_chip_id(chip_id), difficulty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_reversed_matches_bm1397_jig_goldens() {
        // Diff 256 → 0xFF (invariant under reverse).
        assert_eq!(
            ticket_mask_from_difficulty(TicketMaskEncoding::BitReversed, 256),
            0x0000_00FF
        );
        // Diff 64 → 0x3F → byte-reverse 0xFC (rank 49 desk RE).
        assert_eq!(
            ticket_mask_from_difficulty(TicketMaskEncoding::BitReversed, 64),
            0x0000_00FC
        );
        // Diff 128 → 0x7F → 0xFE under bit-reverse (ESP-Miner wire).
        assert_eq!(
            ticket_mask_from_difficulty(TicketMaskEncoding::BitReversed, 128),
            0x0000_00FE
        );
        assert_eq!(
            ticket_mask_from_difficulty(TicketMaskEncoding::BitReversed, 1),
            0
        );
        assert_eq!(
            ticket_mask_from_difficulty(TicketMaskEncoding::BitReversed, 0),
            0
        );
    }

    #[test]
    fn plain_matches_bm136x_fixtures() {
        // BM1368 FIXTURE_TICKET_MASK = 0x7F for difficulty 128.
        assert_eq!(
            ticket_mask_from_difficulty(TicketMaskEncoding::PlainDiffMinusOne, 128),
            0x0000_007F
        );
        assert_eq!(
            ticket_mask_from_difficulty(TicketMaskEncoding::PlainDiffMinusOne, 256),
            0x0000_00FF
        );
        assert_eq!(
            ticket_mask_from_difficulty(TicketMaskEncoding::PlainDiffMinusOne, 1),
            0
        );
    }

    #[test]
    fn esp_miner_pow2_floor_and_encode() {
        // 300 → floor 256 → 255 → 0xFF.
        assert_eq!(ticket_mask_esp_miner_pow2_floor(300), 0x0000_00FF);
        assert_eq!(largest_power_of_two_le(300), 256);
        assert_eq!(largest_power_of_two_le(256), 256);
        assert_eq!(largest_power_of_two_le(1), 1);
        assert_eq!(largest_power_of_two_le(0), 0);
    }

    #[test]
    fn chip_id_map_and_drivers_thin_wrap() {
        assert_eq!(
            ticket_mask_encoding_for_chip_id(0x1397),
            TicketMaskEncoding::BitReversed
        );
        assert_eq!(
            ticket_mask_encoding_for_chip_id(0x1387),
            TicketMaskEncoding::BitReversed
        );
        assert_eq!(
            ticket_mask_encoding_for_chip_id(0x1398),
            TicketMaskEncoding::BitReversed
        );
        assert_eq!(
            ticket_mask_encoding_for_chip_id(0x1366),
            TicketMaskEncoding::PlainDiffMinusOne
        );
        assert_eq!(resolve_ticket_mask(0x1397, 256), 0xFF);
        assert_eq!(resolve_ticket_mask(0x1366, 128), 0x7F);

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert_eq!(
            ticket_mask_encoding_for_chip_id(0x1391),
            TicketMaskEncoding::BitReversed
        );
        assert_eq!(
            ticket_mask_encoding_for_chip_id(0x1393),
            TicketMaskEncoding::BitReversed
        );
        assert_eq!(resolve_ticket_mask(0x1391, 64), 0xFC);
        assert_eq!(resolve_ticket_mask(0x1393, 64), 0xFC);
        assert_eq!(bit_reverse_u32_bytewise(0x0000_003F), 0x0000_00FC);
        assert_eq!(bit_reverse_u32_bytewise(0xFFFF_FFFF), 0xFFFF_FFFF);

        for (rel, encoding_needle) in [
            (
                "dcentrald-asic/src/drivers/bm1397.rs",
                "TicketMaskEncoding::BitReversed",
            ),
            (
                "dcentrald-asic/src/drivers/bm1387.rs",
                "TicketMaskEncoding::BitReversed",
            ),
            (
                "dcentrald-asic/src/drivers/bm1398.rs",
                "TicketMaskEncoding::BitReversed",
            ),
            (
                "dcentrald-asic/src/drivers/bm1391.rs",
                "TicketMaskEncoding::BitReversed",
            ),
            (
                "dcentrald-asic/src/drivers/bm1366.rs",
                "TicketMaskEncoding::PlainDiffMinusOne",
            ),
            (
                "dcentrald-asic/src/drivers/bm1362.rs",
                "TicketMaskEncoding::PlainDiffMinusOne",
            ),
            (
                "dcentrald-asic/src/drivers/bm1368.rs",
                "TicketMaskEncoding::PlainDiffMinusOne",
            ),
            (
                "dcentrald-asic/src/drivers/bm1370.rs",
                "TicketMaskEncoding::PlainDiffMinusOne",
            ),
            (
                "dcentrald-asic/src/drivers/bm1373.rs",
                "TicketMaskEncoding::PlainDiffMinusOne",
            ),
            (
                "dcentrald-asic/src/drivers/bm1489.rs",
                "TicketMaskEncoding::PlainDiffMinusOne",
            ),
            (
                "dcentrald-asic/src/drivers/scrypt_l7.rs",
                "TicketMaskEncoding::PlainDiffMinusOne",
            ),
        ] {
            let src = std::fs::read_to_string(root.join(rel)).expect(rel);
            assert!(
                src.contains("ticket_mask_from_difficulty")
                    || src.contains("dcentrald_common::ticket_mask_from_difficulty")
                    || src.contains("resolve_ticket_mask"),
                "{rel} must thin-wrap pure ticket_mask SSOT"
            );
            assert!(
                src.contains(encoding_needle) || src.contains("ticket_mask_from_difficulty"),
                "{rel} must bind pure encoding ({encoding_needle})"
            );
            // Must not open-code reverse_bits().swap_bytes() outside pure SSOT.
            let body = src
                .split("fn ticket_mask")
                .nth(1)
                .unwrap_or("")
                .split("fn ")
                .next()
                .unwrap_or("");
            assert!(
                !body.contains("reverse_bits().swap_bytes()")
                    || body.contains("ticket_mask_from_difficulty"),
                "{rel} ticket_mask must not fork reverse_bits encode"
            );
        }
        // Reg SSOT pin.
        assert_eq!(TICKET_MASK_REG_BM1397PLUS, 0x14);
        assert_eq!(TICKET_MASK_REG_BM1387, 0x18);
    }

    #[test]
    fn compute_ticket_mask_policy_is_math_only_and_refuses_unknown() {
        let s9 = compute_ticket_mask_policy(0x1387, 256).expect("BM1387");
        assert_eq!(s9.encoding, TicketMaskEncoding::BitReversed);
        assert_eq!(s9.register, TICKET_MASK_REG_BM1387);
        assert_eq!(s9.mask, 0x0000_00FF);

        let s17 = compute_ticket_mask_policy(0x1397, 64).expect("BM1397");
        assert_eq!(s17.encoding, TicketMaskEncoding::BitReversed);
        assert_eq!(s17.register, TICKET_MASK_REG_BM1397PLUS);
        assert_eq!(s17.mask, 0x0000_00FC);

        let s21 = compute_ticket_mask_policy(0x1368, 128).expect("BM1368");
        assert_eq!(s21.encoding, TicketMaskEncoding::PlainDiffMinusOne);
        assert_eq!(s21.register, TICKET_MASK_REG_BM1397PLUS);
        assert_eq!(s21.mask, 0x0000_007F);

        assert_eq!(
            compute_ticket_mask_policy(0xFFFF, 256),
            Err(TicketMaskPolicyError::UnknownChip { chip_id: 0xFFFF })
        );
        assert_eq!(try_ticket_mask_encoding_for_chip_id(0x1390), None);
        assert_eq!(ticket_mask_register_for_chip_id(0xABCD), None);

        let src = include_str!("ticket_mask.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("ticket_mask production boundary");
        for banned in ["write_reg", "set_ticket_mask", "I2cBus", "FpgaChain"] {
            assert!(
                !production.contains(banned),
                "ticket-mask policy must not write hardware ({banned})"
            );
        }
    }
}
