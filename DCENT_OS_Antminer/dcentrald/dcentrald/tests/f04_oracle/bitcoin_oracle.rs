//! F04 independent Bitcoin work/nonce oracle (test support, pure `std`).
//!
//! Campaign `2026-09-07-antminer-beta-execution`, task F04 ("provide
//! independent work/nonce oracles"). This module is deliberately implemented
//! from the specifications, NOT from dcentrald code:
//!
//! - SHA-256: FIPS 180-4 section 6.2 (compression) and 5.1 (padding).
//! - Block header: 80-byte Bitcoin wire format (version/prev/block-merkle
//!   u32/u32 little-endian, 32-byte prev-hash and merkle-root fields stored
//!   in internal byte order, i.e. the reverse of the display order).
//! - Compact target: Bitcoin Core `arith_uint256::SetCompact` semantics
//!   (mantissa in the low 23 bits, bit 23 is the sign flag, value =
//!   mantissa * 2^(8*(exponent-3))).
//! - Merkle: stratum sibling-path semantics (each path entry is the
//!   sibling hash paired on the right, per the Stratum mining protocol
//!   `merkle.branch`); a single-transaction block has an empty path.
//! - Share check: display-order (block-explorer) hash, compared against the
//!   big-endian target. Both arrays are big-endian representations, so the
//!   comparison is plain byte-lexicographic. `<=` passes (cgminer `fulltest`
//!   convention: hash at or below target is a share).
//!
//! INDEPENDENCE CONTRACT (do not weaken): this file must not call
//! `dcentrald_stratum::work`, `dcentrald_common` hash/replay code, or the
//! `sha2` crate. It is the second opinion those paths are cross-checked
//! against. It must stay a tests-only module: it grants no work-generation,
//! submission, pool, or hardware authority, and it is deliberately too slow
//! (single-block scalar SHA-256) to ever be a mining path.
//!
//! Reuse from any other integration test without touching `lib.rs`:
//!
//! ```ignore
//! #[path = "f04_oracle/bitcoin_oracle.rs"]
//! mod bitcoin_oracle;
//! ```

#![forbid(unsafe_code)]

use std::fmt;

/// FIPS 180-4 section 5.3.3 initial hash value.
pub const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// FIPS 180-4 section 4.2.2 round constants (first 64 primes).
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// One FIPS 180-4 section 6.2.2 compression step.
///
/// Returns the new chaining state; the input state is not modified.
#[must_use]
pub fn sha256_compress(state: &[u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let mut schedule = [0u32; 64];
    for (index, word) in schedule.iter_mut().take(16).enumerate() {
        let offset = index * 4;
        *word = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..64 {
        let sigma0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let sigma1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(sigma0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(sigma1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (index, constant) in K.iter().enumerate() {
        let big_sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ (!e & g);
        let temporary1 = h
            .wrapping_add(big_sigma1)
            .wrapping_add(choose)
            .wrapping_add(*constant)
            .wrapping_add(schedule[index]);
        let big_sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temporary2 = big_sigma0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temporary1);
        d = c;
        c = b;
        b = a;
        a = temporary1.wrapping_add(temporary2);
    }

    let working = [a, b, c, d, e, f, g, h];
    let mut next = *state;
    for (slot, value) in next.iter_mut().zip(working) {
        *slot = slot.wrapping_add(value);
    }
    next
}

/// FIPS 180-4 section 5.1.1 padding for one message, appended to `data`.
fn padded(data: &[u8]) -> Vec<u8> {
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut out = Vec::with_capacity(data.len() + 72);
    out.extend_from_slice(data);
    out.push(0x80);
    while out.len() % 64 != 56 {
        out.push(0);
    }
    out.extend_from_slice(&bit_len.to_be_bytes());
    out
}

/// SHA-256 of `data` (FIPS 180-4). The independent reference digest.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let padded = padded(data);
    let mut state = SHA256_INITIAL_STATE;
    for block in padded.chunks_exact(64) {
        let block: &[u8; 64] = block
            .try_into()
            .expect("chunks_exact(64) yields 64-byte blocks");
        state = sha256_compress(&state, block);
    }
    let mut digest = [0u8; 32];
    for (slot, word) in digest.chunks_exact_mut(4).zip(state) {
        slot.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Bitcoin `Hash`: double SHA-256.
#[must_use]
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Reverse the 32-byte digest to move between wire/internal order and the
/// block-explorer display order.
#[must_use]
pub fn display_from_internal(internal: &[u8; 32]) -> [u8; 32] {
    let mut display = *internal;
    display.reverse();
    display
}

/// Parse/serialization errors for the 80-byte Bitcoin header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderParseError {
    WrongLength { observed: usize },
}

impl fmt::Display for HeaderParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { observed } => {
                write!(
                    formatter,
                    "bitcoin header must be exactly 80 bytes, got {observed}"
                )
            }
        }
    }
}

impl std::error::Error for HeaderParseError {}

/// Parsed 80-byte Bitcoin block header.
///
/// `prev_hash` and `merkle_root` are kept in wire/internal byte order (the
/// same order the SHA-256 input uses, and the reverse of the display order).
/// Integers are the little-endian wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub nbits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    /// Parse the exact 80-byte wire form.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, HeaderParseError> {
        let bytes: &[u8; 80] = bytes
            .try_into()
            .map_err(|_| HeaderParseError::WrongLength {
                observed: bytes.len(),
            })?;
        let read_u32 = |offset: usize| {
            u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ])
        };
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&bytes[4..36]);
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&bytes[36..68]);
        Ok(Self {
            version: read_u32(0),
            prev_hash,
            merkle_root,
            timestamp: read_u32(68),
            nbits: read_u32(72),
            nonce: read_u32(76),
        })
    }

    /// Serialize back to the exact 80-byte wire form.
    #[must_use]
    pub fn to_wire(&self) -> [u8; 80] {
        let mut out = [0u8; 80];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_hash);
        out[36..68].copy_from_slice(&self.merkle_root);
        out[68..72].copy_from_slice(&self.timestamp.to_le_bytes());
        out[72..76].copy_from_slice(&self.nbits.to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Copy of this header with a different nonce (the ASIC nonce-search axis).
    #[must_use]
    pub fn with_nonce(mut self, nonce: u32) -> Self {
        self.nonce = nonce;
        self
    }

    /// SHA-256 midstate after the first 64 header bytes.
    ///
    /// This is the exact state a midstate-based ASIC job (BM13xx family,
    /// FPGA job planners) starts from; only the 12-byte
    /// nTime/nBits/nonce tail is re-walked per nonce.
    #[must_use]
    pub fn midstate(&self) -> [u8; 32] {
        let wire = self.to_wire();
        let mut first_block = [0u8; 64];
        first_block.copy_from_slice(&wire[0..64]);
        words_to_digest(sha256_compress(&SHA256_INITIAL_STATE, &first_block))
    }

    /// Complete the first SHA-256 round from the midstate plus the 16-byte
    /// header tail (`nTime || nBits || nonce`).
    ///
    /// Equal to `sha256(header_wire)`: for an 80-byte message the tail is
    /// padded as `tail || 0x80 || zeros || bit_len(640)` in one final block.
    #[must_use]
    pub fn midstate_sha256(&self) -> [u8; 32] {
        let wire = self.to_wire();
        let mut final_block = [0u8; 64];
        final_block[0..16].copy_from_slice(&wire[64..80]);
        final_block[16] = 0x80;
        final_block[56..64].copy_from_slice(&640u64.to_be_bytes());
        let midstate_words = digest_to_words(&self.midstate());
        words_to_digest(sha256_compress(&midstate_words, &final_block))
    }

    /// Double-SHA256 of the 80-byte wire header, in wire/internal order.
    #[must_use]
    pub fn block_hash_internal(&self) -> [u8; 32] {
        sha256(&self.midstate_sha256())
    }

    /// The block hash in block-explorer display order (leading-zero form).
    ///
    /// This array is also the big-endian representation of the hash number,
    /// which is what makes [`Self::meets_target`] a plain byte comparison.
    #[must_use]
    pub fn display_hash(&self) -> [u8; 32] {
        display_from_internal(&self.block_hash_internal())
    }

    /// The 256-bit work target decoded from this header's `nBits`, big-endian.
    /// Returns `None` on a negative or out-of-range compact encoding.
    pub fn target(&self) -> Option<[u8; 32]> {
        compact_target(self.nbits)
    }

    /// Independent share/proof-of-work check: display hash <= target.
    /// Equal-to-target passes (cgminer `fulltest` convention).
    /// Returns `false` when `nBits` does not decode.
    pub fn meets_target(&self) -> bool {
        match self.target() {
            Some(target) => display_hash_meets_target(&self.display_hash(), &target),
            None => false,
        }
    }

    /// Verify the header's merkle root against a stratum-style leaf + branch.
    ///
    /// `coinbase_hash` is the double-SHA256 of the full coinbase
    /// transaction; `path` holds the sibling hashes in stratum order (each
    /// paired on the right). A single-transaction block uses an empty path.
    #[must_use]
    pub fn header_merkle_matches(&self, coinbase_hash: &[u8; 32], path: &[[u8; 32]]) -> bool {
        merkle_root(coinbase_hash, path) == self.merkle_root
    }
}

/// Convert eight state words into the 32-byte big-endian digest form.
fn words_to_digest(words: [u32; 8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    for (slot, word) in digest.chunks_exact_mut(4).zip(words) {
        slot.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Convert a 32-byte big-endian digest into eight state words.
#[must_use]
pub fn digest_to_words(digest: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (slot, chunk) in words.iter_mut().zip(digest.chunks_exact(4)) {
        *slot = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

/// Bitcoin Core `SetCompact` decoding into a 256-bit big-endian target.
///
/// Bit 23 of the mantissa field is the sign flag (negative -> `None`;
/// this oracle only needs positive targets). Value = mantissa * 2^(8*(exp-3))
/// with `mantissa >>= 8*(3-exp)` when exp < 3. Returns `None` when a nonzero
/// mantissa byte would fall outside 256 bits.
#[must_use]
pub fn compact_target(nbits: u32) -> Option<[u8; 32]> {
    if nbits & 0x0080_0000 != 0 {
        return None; // sign flag: negative compact is not a work target
    }
    let exponent = (nbits >> 24) as usize;
    let mantissa = nbits & 0x007f_ffff;
    let mantissa_bytes = if exponent < 3 {
        mantissa >> (8 * (3 - exponent))
    } else {
        mantissa
    }
    .to_be_bytes();
    let shift_bytes = exponent.saturating_sub(3);

    let mut target = [0u8; 32];
    for (index, byte) in mantissa_bytes.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        // Byte `index` of the mantissa (MSB first) lands at big-endian
        // position 32 - shift_bytes - (4 - index); anything above 255 bits
        // worth of value overflows.
        let position = 32usize.checked_sub(shift_bytes)?.checked_sub(4 - index)?;
        target[position] = *byte;
    }
    Some(target)
}

/// Difficulty-1 target (`nBits` `0x1d00ffff`), big-endian.
pub const DIFF1_TARGET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Target for a power-of-two share difficulty: `DIFF1_TARGET >> log2`.
///
/// This is the exact "shifted target" model the BM13xx per-chip target
/// registers and the stock cgminer `floor(log2(difficulty))` gate use, so
/// driver lanes can build a hardware-shaped share oracle without floating
/// point. Saturates at zero for shifts that empty the mantissa.
#[must_use]
pub fn target_from_difficulty_pow2(difficulty_log2: u8) -> [u8; 32] {
    let mut target = DIFF1_TARGET;
    let mut remaining = u32::from(difficulty_log2);
    // Shift the big-endian array right one bit at a time; 256 iterations max.
    while remaining > 0 {
        let mut carry = 0u8;
        for byte in target.iter_mut() {
            let new_carry = *byte & 1;
            *byte = (*byte >> 1) | (carry << 7);
            carry = new_carry;
        }
        remaining -= 1;
        if target == [0u8; 32] {
            break;
        }
    }
    target
}

/// Share/proof-of-work comparison: display-order hash vs big-endian target.
///
/// Both arrays are big-endian representations of 256-bit numbers, so a plain
/// lexicographic byte comparison decides `<`. `<=` passes.
#[must_use]
pub fn display_hash_meets_target(display_hash: &[u8; 32], target: &[u8; 32]) -> bool {
    display_hash.as_slice() <= target.as_slice()
}

/// Fold a stratum merkle branch up from the coinbase hash.
///
/// Each path entry is the sibling hash; the current hash is always the left
/// half (`current || sibling`). This matches the Stratum mining protocol
/// merkle branch order. A single-transaction block uses an empty path.
#[must_use]
pub fn merkle_root(coinbase_hash: &[u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
    let mut current = *coinbase_hash;
    for sibling in path {
        let mut concatenated = [0u8; 64];
        concatenated[0..32].copy_from_slice(&current);
        concatenated[32..64].copy_from_slice(sibling);
        current = double_sha256(&concatenated);
    }
    current
}

/// Assemble a Stratum coinbase from its four wire segments
/// (`coinb1 || extranonce1 || extranonce2 || coinb2`).
#[must_use]
pub fn build_stratum_coinbase(
    coinb1: &[u8],
    extranonce1: &[u8],
    extranonce2: &[u8],
    coinb2: &[u8],
) -> Vec<u8> {
    let mut coinbase =
        Vec::with_capacity(coinb1.len() + extranonce1.len() + extranonce2.len() + coinb2.len());
    coinbase.extend_from_slice(coinb1);
    coinbase.extend_from_slice(extranonce1);
    coinbase.extend_from_slice(extranonce2);
    coinbase.extend_from_slice(coinb2);
    coinbase
}

/// Convenience: [`build_stratum_coinbase`] followed by double-SHA256.
#[must_use]
pub fn stratum_coinbase_hash(
    coinb1: &[u8],
    extranonce1: &[u8],
    extranonce2: &[u8],
    coinb2: &[u8],
) -> [u8; 32] {
    double_sha256(&build_stratum_coinbase(
        coinb1,
        extranonce1,
        extranonce2,
        coinb2,
    ))
}
