//! F04 independent share-oracle known-vector harness.
//!
//! Campaign `2026-09-07-antminer-beta-execution`, task F04. This is the
//! acceptance gate for the independent Bitcoin work/nonce oracle in
//! `f04_oracle/bitcoin_oracle.rs`. Every oracle result is cross-checked
//! against BOTH:
//!
//! 1. Public Bitcoin mainnet constants (genesis block 0, block 1, block 2),
//!    independently re-derived with Python `hashlib` before this file was
//!    written (genesis display hash additionally confirmed against a
//!    published value; blocks 1 and 2 were reproduced through the hash chain
//!    from the genesis digest, which pins the genesis digest byte-exactly).
//! 2. The `sha2` crate — a second, third-party implementation. The oracle
//!    itself never calls `sha2` (independence contract); the cross-check
//!    deliberately happens only here, in the harness.
//!
//! The oracle result is also compared to the midstate words already pinned by
//! the stock-BM1391 replay tests in `dcentrald-common` (constants recovered
//! from held stock firmware, independent of `dcentrald_stratum::work`).
//!
//! Negative coverage: a wrong nonce must FAIL the target check, and compact
//! encodings that are negative or overflow 256 bits must not decode.

#![forbid(unsafe_code)]

#[path = "f04_oracle/bitcoin_oracle.rs"]
mod bitcoin_oracle;

use bitcoin_oracle::{
    compact_target, digest_to_words, display_hash_meets_target, double_sha256, merkle_root,
    sha256, stratum_coinbase_hash, target_from_difficulty_pow2, BlockHeader, DIFF1_TARGET,
};
use sha2::{Digest, Sha256};

/// Decode a fixed-length constant hex vector.
fn fixed<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex)
        .expect("constant hex vector must parse")
        .try_into()
        .expect("constant hex vector must have the declared length")
}

/// Second-opinion SHA-256 from the `sha2` crate (harness-only cross-check).
fn sha2_ref(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Second-opinion double SHA-256 from the `sha2` crate.
fn double_sha2_ref(data: &[u8]) -> [u8; 32] {
    sha2_ref(&sha2_ref(data))
}

const GENESIS_WIRE_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
const GENESIS_DISPLAY_HEX: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
const GENESIS_INTERNAL_HEX: &str = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
const GENESIS_TARGET_HEX: &str = "00000000ffff0000000000000000000000000000000000000000000000000000";
/// Midstate words of the genesis header as pinned by the stock-BM1391
/// replay tests in `dcentrald-common` (`bm1391_share_qualification.rs`,
/// test `genesis_header_midstate_replays_stock_double_sha_and_digest_gate`);
/// recovered from held stock firmware, not from any dcentrald hash path.
const GENESIS_MIDSTATE_WORDS: [u32; 8] = [
    0xbc90_9a33,
    0x6358_bff0,
    0x90cc_ac7d,
    0x1e59_caa8,
    0xc3c8_d8e9,
    0x4f01_03c8,
    0x96b1_8736,
    0x4719_f91b,
];

const BLOCK1_WIRE_HEX: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";
const BLOCK1_DISPLAY_HEX: &str = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";
const BLOCK1_MERKLE_DISPLAY_HEX: &str = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098";

const BLOCK2_WIRE_HEX: &str = "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61";
const BLOCK2_DISPLAY_HEX: &str = "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd";

/// Genesis header with nonce incremented by one: must MISS the target.
const WRONG_NONCE_DISPLAY_HEX: &str = "9b227a4a5daa0cbae6874144bc5d7797d0513e320aceadeb3b06304971a41b1c";

const SHA256_EMPTY_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_ABC_HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const DOUBLE_SHA256_ABC_HEX: &str = "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358";

fn genesis_header() -> BlockHeader {
    BlockHeader::from_wire(&fixed::<80>(GENESIS_WIRE_HEX)).expect("genesis wire header parses")
}

#[test]
fn fips180_4_digests_match_published_vectors_and_sha2() {
    assert_eq!(sha256(b""), fixed::<32>(SHA256_EMPTY_HEX));
    assert_eq!(sha256(b"abc"), fixed::<32>(SHA256_ABC_HEX));
    assert_eq!(double_sha256(b"abc"), fixed::<32>(DOUBLE_SHA256_ABC_HEX));
    assert_eq!(sha256(b""), sha2_ref(b""), "oracle vs sha2 on empty input");
    assert_eq!(sha256(b"abc"), sha2_ref(b"abc"), "oracle vs sha2 on 'abc'");
    assert_eq!(
        double_sha256(b"abc"),
        double_sha2_ref(b"abc"),
        "oracle vs sha2 double round"
    );
}

#[test]
fn genesis_block0_known_vector_with_sha2_cross_check() {
    let genesis = genesis_header();
    assert_eq!(genesis.version, 1);
    assert_eq!(genesis.prev_hash, [0u8; 32], "genesis prev hash is null");
    assert_eq!(genesis.display_hash(), fixed::<32>(GENESIS_DISPLAY_HEX));
    assert_eq!(
        genesis.block_hash_internal(),
        fixed::<32>(GENESIS_INTERNAL_HEX),
        "wire-order digest is the display digest reversed"
    );
    assert_eq!(
        genesis.block_hash_internal(),
        double_sha2_ref(&fixed::<80>(GENESIS_WIRE_HEX)),
        "oracle double-SHA256 vs the sha2 crate"
    );
    assert!(genesis.meets_target(), "genesis must pass the difficulty-1 check");
}

#[test]
fn genesis_midstate_matches_stock_replay_words_and_sha2() {
    let genesis = genesis_header();
    assert_eq!(
        digest_to_words(&genesis.midstate()),
        GENESIS_MIDSTATE_WORDS,
        "oracle midstate must equal the words pinned from held stock firmware"
    );

    // The midstate is the raw chaining value after block 0, NOT the sha2
    // digest of the 64-byte prefix (which would append padding). It is
    // cross-checked two independent ways instead:
    // 1. the words pinned from held stock firmware (above), and
    // 2. the only midstate that completes to the sha2 one-shot digest below.
    let wire = fixed::<80>(GENESIS_WIRE_HEX);
    // Structural property: everything a midstate-based job holds constant
    // (version/prev/merkle) is in block 0; the nonce must not touch it.
    assert_eq!(
        genesis.with_nonce(genesis.nonce.wrapping_add(1)).midstate(),
        genesis.midstate(),
        "nonce lives in the header tail and must not perturb the midstate"
    );

    // Completing the round from the midstate must equal the plain one-shot hash.
    assert_eq!(
        genesis.midstate_sha256(),
        sha2_ref(&wire),
        "midstate+tail round vs sha2 one-shot"
    );
    assert_eq!(
        genesis.midstate_sha256(),
        sha256(&wire),
        "midstate+tail round vs oracle one-shot"
    );
    assert_eq!(
        sha256(&genesis.midstate_sha256()),
        genesis.block_hash_internal(),
        "second round from midstate equals the double-SHA256"
    );
}

#[test]
fn midstate_plus_nonce_path_agrees_with_full_hash_on_every_vector() {
    for hex in [GENESIS_WIRE_HEX, BLOCK1_WIRE_HEX, BLOCK2_WIRE_HEX] {
        let wire = fixed::<80>(hex);
        let header = BlockHeader::from_wire(&wire).expect("public vector parses");
        assert_eq!(
            header.midstate_sha256(),
            sha2_ref(&wire),
            "{hex}: midstate-first-round vs sha2"
        );
        assert_eq!(
            header.block_hash_internal(),
            double_sha2_ref(&wire),
            "{hex}: double round vs sha2"
        );
        let mut display_ref = double_sha2_ref(&wire);
        display_ref.reverse();
        assert_eq!(
            header.display_hash(),
            display_ref,
            "{hex}: display order is the wire digest reversed"
        );
    }
}

#[test]
fn block1_and_block2_public_vectors_match() {
    let block1 = BlockHeader::from_wire(&fixed::<80>(BLOCK1_WIRE_HEX)).expect("block 1 parses");
    let block2 = BlockHeader::from_wire(&fixed::<80>(BLOCK2_WIRE_HEX)).expect("block 2 parses");
    assert_eq!(block1.display_hash(), fixed::<32>(BLOCK1_DISPLAY_HEX));
    assert_eq!(block2.display_hash(), fixed::<32>(BLOCK2_DISPLAY_HEX));
    assert_eq!(
        block1.prev_hash,
        genesis_header().block_hash_internal(),
        "block 1 builds on the genesis digest"
    );
    assert_eq!(
        block2.prev_hash,
        block1.block_hash_internal(),
        "block 2 builds on the block-1 digest"
    );
    assert!(block1.meets_target(), "block 1 passes the era target");
    assert!(block2.meets_target(), "block 2 passes the era target");
}

#[test]
fn wrong_nonce_fails_the_share_target_check() {
    let genesis = genesis_header();
    let wrong = genesis.with_nonce(genesis.nonce.wrapping_add(1));
    assert_eq!(
        wrong.display_hash(),
        fixed::<32>(WRONG_NONCE_DISPLAY_HEX),
        "wrong-nonce digest matches the independently computed value"
    );
    assert_eq!(
        wrong.midstate_sha256(),
        sha2_ref(&wrong.to_wire()),
        "wrong-nonce midstate path still agrees with sha2"
    );
    assert_ne!(
        wrong.display_hash(),
        genesis.display_hash(),
        "a different nonce must produce a different hash"
    );
    assert!(
        !wrong.meets_target(),
        "wrong nonce must FAIL the target check"
    );
    // The same digest must also miss an explicitly provided target.
    let target = genesis.target().expect("genesis nBits decodes");
    assert!(!display_hash_meets_target(&wrong.display_hash(), &target));
}

#[test]
fn genesis_target_decodes_to_the_difficulty_one_value() {
    let genesis = genesis_header();
    assert_eq!(genesis.nbits, 0x1d00_ffff);
    assert_eq!(
        genesis.target().expect("genesis nBits decodes"),
        fixed::<32>(GENESIS_TARGET_HEX)
    );
    assert_eq!(DIFF1_TARGET, fixed::<32>(GENESIS_TARGET_HEX));
    assert!(display_hash_meets_target(&genesis.display_hash(), &DIFF1_TARGET));
}

#[test]
fn compact_target_decoding_rejects_negative_and_overflow() {
    // Difficulty-1 target.
    assert_eq!(
        compact_target(0x1d00_ffff),
        Some(fixed::<32>(GENESIS_TARGET_HEX))
    );
    // exp < 3 shifts the mantissa down: 0xffff >> 8 = 0xff.
    let mut tiny = [0u8; 32];
    tiny[31] = 0xff;
    assert_eq!(compact_target(0x0200_ffff), Some(tiny));
    // exp 33 keeps 0xffff * 2^240 inside 256 bits.
    let mut edge = [0u8; 32];
    edge[0] = 0xff;
    edge[1] = 0xff;
    assert_eq!(compact_target(0x2100_ffff), Some(edge));
    // exp 34 pushes the same mantissa past 256 bits.
    assert_eq!(compact_target(0x2200_ffff), None);
    // Bit 23 is the Bitcoin Core sign flag.
    assert_eq!(compact_target(0x2180_0001), None);
    // Zero mantissa with a huge exponent stays a valid zero target.
    assert_eq!(compact_target(0xff00_0000), Some([0u8; 32]));
}

#[test]
fn pow2_difficulty_targets_shift_diff1_exact() {
    assert_eq!(target_from_difficulty_pow2(0), DIFF1_TARGET);
    let mut shift8 = [0u8; 32];
    shift8[5] = 0xff;
    shift8[6] = 0xff;
    assert_eq!(
        target_from_difficulty_pow2(8),
        shift8,
        "difficulty 256 moves the mantissa one byte"
    );
    let mut shift32 = [0u8; 32];
    shift32[8] = 0xff;
    shift32[9] = 0xff;
    assert_eq!(target_from_difficulty_pow2(32), shift32);
    // Saturation: a shift that empties the mantissa is a zero target.
    assert_eq!(target_from_difficulty_pow2(255), [0u8; 32]);
}

#[test]
fn stratum_coinbase_and_merkle_path_round_trip_with_sha2_cross_check() {
    let coinb1 = fixed::<43>(
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2504",
    );
    let extranonce1 = [0x0bu8, 0xee, 0x11, 0x77];
    let extranonce2 = [0x00u8, 0x11, 0x22, 0x33];
    let coinb2 = fixed::<74>(
        "ffffffff0100f2052a01000000434104aabbccddeeff0011223344556677889900112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344ac00000000",
    );

    let leaf = stratum_coinbase_hash(&coinb1, &extranonce1, &extranonce2, &coinb2);
    assert_eq!(
        leaf,
        double_sha2_ref(&bitcoin_oracle::build_stratum_coinbase(
            &coinb1, &extranonce1, &extranonce2, &coinb2
        )),
        "coinbase hash vs sha2"
    );

    let sibling1 = double_sha256(b"sibling-1");
    let sibling2 = double_sha256(b"sibling-2");
    let path = [sibling1, sibling2];
    let root = merkle_root(&leaf, &path);

    // sha2 cross-check of the same fold.
    let mut level = [0u8; 64];
    level[0..32].copy_from_slice(&leaf);
    level[32..64].copy_from_slice(&sibling1);
    let level1 = double_sha2_ref(&level);
    level[0..32].copy_from_slice(&level1);
    level[32..64].copy_from_slice(&sibling2);
    assert_eq!(root, double_sha2_ref(&level), "merkle fold vs sha2");

    // Patch the root into a real header (genesis wire, new merkle field) and
    // verify the header-side check accepts and rejects exactly.
    let mut wire = fixed::<80>(GENESIS_WIRE_HEX);
    wire[36..68].copy_from_slice(&root);
    let header = BlockHeader::from_wire(&wire).expect("patched header parses");
    assert!(header.header_merkle_matches(&leaf, &path));
    assert!(!header.header_merkle_matches(&leaf, &[sibling2, sibling1]));
    assert!(!header.header_merkle_matches(&leaf, &[]));
    assert!(!header.header_merkle_matches(&sibling1, &path));

    // A different extranonce2 must move the coinbase hash and the root.
    let other_leaf = stratum_coinbase_hash(
        &coinb1,
        &extranonce1,
        &[0x00, 0x11, 0x22, 0x34],
        &coinb2,
    );
    assert_ne!(other_leaf, leaf, "extranonce2 is inside the hashed coinbase");
    assert!(!header.header_merkle_matches(&other_leaf, &path));
}

#[test]
fn block1_single_transaction_merkle_root_is_the_coinbase_txid() {
    let block1 = BlockHeader::from_wire(&fixed::<80>(BLOCK1_WIRE_HEX)).expect("block 1 parses");
    // Block 1 contains exactly one transaction, so the merkle root equals the
    // coinbase txid and the stratum branch is empty. Wire field order must be
    // internal order: reversed, it is the display txid.
    let coinbase_txid_internal = block1.merkle_root;
    let mut display = coinbase_txid_internal;
    display.reverse();
    assert_eq!(display, fixed::<32>(BLOCK1_MERKLE_DISPLAY_HEX));
    assert_eq!(merkle_root(&coinbase_txid_internal, &[]), block1.merkle_root);
    assert!(block1.header_merkle_matches(&coinbase_txid_internal, &[]));
}

#[test]
fn header_wire_round_trip_is_byte_exact() {
    for hex in [GENESIS_WIRE_HEX, BLOCK1_WIRE_HEX, BLOCK2_WIRE_HEX] {
        let wire = fixed::<80>(hex);
        let header = BlockHeader::from_wire(&wire).expect("public vector parses");
        assert_eq!(header.to_wire(), wire, "{hex}: wire round trip");
    }
    assert!(matches!(
        BlockHeader::from_wire(&[0u8; 79]),
        Err(bitcoin_oracle::HeaderParseError::WrongLength { observed: 79 })
    ));
}
