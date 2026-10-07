// SPDX-License-Identifier: GPL-3.0-or-later
//! R05 positive production-executor work/nonce/submit replay, independently
//! oracle-checked.
//!
//! Campaign `2026-09-07-antminer-beta-execution`, task R05 (2026-09-11).
//! The work path under test is the EXACT production code: the `WorkLedger`
//! and `ChainIo` seam included by path from `dcentrald/src/s17_wire.rs` (the
//! same implementation the S17 native mining loop drives), plus the real
//! `dcentrald-asic` BM1397 driver and the real `dcentrald-stratum` work
//! builder. Every accepted nonce is independently re-derived with the F04
//! Bitcoin oracle (`tests/f04_oracle/bitcoin_oracle.rs`, verified 12/0,
//! never modified here) and cross-checked against public mainnet constants
//! (genesis block 0).
//!
//! Independent anchors used:
//! - Genesis header bytes/merkle root: public mainnet block 0.
//! - Genesis display hash `000000000019d668…8ce26f`: public.
//! - Genesis midstate words `[bc909a33, 6358bff0, 90ccac7d, …]`: the
//!   held-stock BM1391 replay vector (`dcentrald-common`
//!   `bm1391_share_qualification.rs`) AND, independently, the FIPS 180-4
//!   midstate — a Python SHA-256 compression of header bytes [0..64]
//!   (compressor validated on empty/"abc" and the public genesis
//!   double-SHA256) byte-equals the stock vector. Production
//!   `compute_midstate_from_prefix` stores exactly these bytes as plain
//!   big-endian words W0..W7; the s17io FIFO consumes the region in
//!   reversed word order (W7 first).
//! - F04 oracle: independent FIPS 180-4 implementation.

#![forbid(unsafe_code)]

#[path = "../src/s17_wire.rs"]
mod s17_wire;
#[path = "f04_oracle/bitcoin_oracle.rs"]
mod bitcoin_oracle;

use bitcoin_oracle::{
    digest_to_words, display_hash_meets_target, double_sha256, target_from_difficulty_pow2,
    BlockHeader, DIFF1_TARGET,
};
use dcentrald_asic::drivers::bm1397::Bm1397Driver;
use dcentrald_asic::drivers::ChipDriver;
use dcentrald_stratum::types::JobTemplate;
use dcentrald_stratum::work::{compute_midstate_from_prefix, difficulty_to_target, WorkBuilder};
use s17_wire::{work_queue_has_complete_frame_space, ChainIo, WorkLedger};

/// Genesis merkle root (internal byte order), public mainnet block 0.
const GENESIS_MERKLE: [u8; 32] = [
    0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f,
    0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e,
    0x5e, 0x4a,
];
const GENESIS_NONCE: u32 = 2083236893;
const GENESIS_NTIME: u32 = 1231006505;
/// Public genesis display hash (first byte order as displayed).
const GENESIS_DISPLAY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e,
    0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c,
    0xe2, 0x6f,
];
/// Midstate of the genesis header prefix (SHA-256 compression of header
/// bytes [0..64]) as FIPS BE words W0..W7 — byte-equal to the held-stock
/// BM1391 replay vector (`dcentrald-common`
/// `bm1391_share_qualification.rs`): independently re-proven with a Python
/// FIPS compression validated against the public genesis display hash
/// (`compress(IV, header[0..64])` BE-serialized ==
/// `bc909a336358bff090ccac7d1e59caa8c3c8d8e94f0103c896b187364719f91b`).
/// Production `compute_midstate_from_prefix` stores exactly these plain
/// big-endian bytes.
const GENESIS_TRUE_MIDSTATE_WORDS: [u32; 8] = [
    0xbc90_9a33, 0x6358_bff0, 0x90cc_ac7d, 0x1e59_caa8, 0xc3c8_d8e9, 0x4f01_03c8, 0x96b1_8736,
    0x4719_f91b,
];
/// The midstate bytes in full (plain big-endian words W0..W7).
const GENESIS_TRUE_MIDSTATE_BYTES: [u8; 32] = [
    0xbc, 0x90, 0x9a, 0x33, 0x63, 0x58, 0xbf, 0xf0, 0x90, 0xcc, 0xac, 0x7d, 0x1e, 0x59, 0xca,
    0xa8, 0xc3, 0xc8, 0xd8, 0xe9, 0x4f, 0x01, 0x03, 0xc8, 0x96, 0xb1, 0x87, 0x36, 0x47, 0x19,
    0xf9, 0x1b,
];

/// Full 80-byte genesis header (nonce field left at zero; tests overwrite
/// `header[76..80]` when searching).
fn genesis_header80() -> [u8; 80] {
    dcentrald_stratum::v1::job::build_block_header(
        1,
        &[0; 32],
        &GENESIS_MERKLE,
        GENESIS_NTIME,
        0x1d00ffff,
        0,
    )
}

fn genesis_header_prefix() -> [u8; 64] {
    let header = genesis_header80();
    header[..64].try_into().unwrap()
}

fn genesis_work() -> dcentrald_stratum::work::MiningWork {
    let prefix = genesis_header_prefix();
    dcentrald_stratum::work::MiningWork {
        work_generation: dcentrald_stratum::work_domain::WorkGeneration { session: 1, job: 1 },
        midstates: vec![compute_midstate_from_prefix(&prefix)],
        merkle4: GENESIS_MERKLE[28..].try_into().unwrap(),
        ntime: GENESIS_NTIME,
        nbits: 0x1d00ffff,
        job_id: "genesis-fixture".into(),
        extranonce2: "00000000".into(),
        version: 1,
        version_mask: 0,
        share_target: difficulty_to_target(1.0),
        merkle_root: GENESIS_MERKLE,
        prev_block_hash: [0; 32],
    }
}

/// Fake chain recording every work-TX word frame (the ABI diff record).
#[derive(Default)]
struct ReplayChain {
    writes: Vec<[u32; 36]>,
    replies: std::collections::VecDeque<[u8; 8]>,
    full: bool,
    fail_write: bool,
    flushed: u32,
}

impl ChainIo for ReplayChain {
    fn set_divisor(&mut self, _divisor: u32) {}
    fn divisor(&self) -> u32 {
        7
    }
    fn command(&mut self, _bytes: &[u8]) {}
    fn register_reply(&mut self) -> Option<[u8; 8]> {
        self.replies.pop_front()
    }
    fn work_full(&self) -> bool {
        self.full
    }
    fn write_work(&mut self, words: &[u32; 36]) -> anyhow::Result<()> {
        if self.fail_write {
            anyhow::bail!("injected FIFO write failure");
        }
        self.writes.push(*words);
        Ok(())
    }
    fn nonce(&mut self) -> Option<[u32; 2]> {
        None
    }
    fn flush_work(&mut self) {
        self.flushed += 1;
        self.replies.clear();
    }
}

/// Wire-format helper: the RX word pair for `slot`/`midstate` producing
/// `nonce` (the FPGA delivers `[nonce, hw_work_id << 8]`).
fn rx_words(nonce: u32, slot: usize, midstate: u8) -> [u32; 2] {
    [nonce, (((slot as u32) << 2) | u32::from(midstate)) << 8]
}

// ---------------------------------------------------------------------------
// Independent hash anchors
// ---------------------------------------------------------------------------

#[test]
fn stratum_and_oracle_and_fips_compression_agree_on_the_genesis_midstate() {
    let prefix = genesis_header_prefix();
    // 1) The stratum builder…
    let midstate = compute_midstate_from_prefix(&prefix);
    // 2) …the F04 oracle…
    let oracle = BlockHeader::from_wire(&genesis_header80()).unwrap().midstate();
    assert_eq!(midstate, oracle, "stratum vs oracle midstate");
    // 3) …and the FIPS midstate, which is byte-identical to the held-stock
    //    BM1391 replay words (see the module anchor note: a validated Python
    //    FIPS compression of header bytes [0..64] reproduces
    //    `bc909a336358bff090ccac7d1e59caa8c3c8d8e94f0103c896b187364719f91b`
    //    byte-for-byte). Storage layout: PLAIN big-endian words W0..W7.
    assert_eq!(digest_to_words(&midstate), GENESIS_TRUE_MIDSTATE_WORDS);
    assert_eq!(midstate, GENESIS_TRUE_MIDSTATE_BYTES);
    // Spot bytes: W0 begins bc909a33; W2 begins 90ccac7d.
    assert_eq!(&midstate[0..4], &0xbc90_9a33u32.to_be_bytes());
    assert_eq!(&midstate[8..12], &0x90cc_ac7du32.to_be_bytes());
}

#[test]
fn difficulty_targets_agree_between_stratum_and_the_oracle() {
    // The stratum crate uses the POOL difficulty-1 target (pdiff1, 2^224-1);
    // the oracle's DIFF1_TARGET is the Bitcoin PoW limit. They are DIFFERENT
    // constants by design. Cross-checks that must hold:
    // 1. the public genesis solution meets BOTH targets;
    let genesis_display = BlockHeader::from_wire(&dcentrald_stratum::v1::job::build_block_header(
        1,
        &[0; 32],
        &GENESIS_MERKLE,
        GENESIS_NTIME,
        0x1d00ffff,
        GENESIS_NONCE,
    ))
    .unwrap()
    .display_hash();
    assert_eq!(genesis_display, GENESIS_DISPLAY);
    assert!(display_hash_meets_target(
        &genesis_display,
        &difficulty_to_target(1.0)
    ));
    assert!(display_hash_meets_target(&genesis_display, &DIFF1_TARGET));
    // 2. the pool target at difficulty 256 is never HARDER than the oracle's
    //    shifted PoW target (pdiff1 >= DIFF1), so an oracle-verified PoW
    //    ticket is always a valid stratum share at the same difficulty.
    let pool_d256 = difficulty_to_target(256.0);
    let pow_d256 = target_from_difficulty_pow2(8);
    assert!(pool_d256 >= pow_d256, "{pool_d256:?} vs {pow_d256:?}");
}

// ---------------------------------------------------------------------------
// Work TX → nonce RX → header reconstruct → share submit (production code)
// ---------------------------------------------------------------------------

#[test]
fn work_tx_frame_layout_matches_the_four_midstate_fabric_abi() {
    let mut chain = ReplayChain::default();
    let mut ledger = WorkLedger::new();
    assert!(ledger.dispatch(&mut chain, genesis_work()).unwrap());
    let words = &chain.writes[0];
    assert_eq!(words.len(), 36, "whole-frame reserve: 4 + 32 midstate words");
    assert_eq!(words[0], 0, "slot 0, midstate low bits zero");
    assert_eq!(words[1], 0x1d00ffff);
    assert_eq!(words[2], GENESIS_NTIME);
    assert_eq!(words[3], u32::from_le_bytes(GENESIS_MERKLE[28..].try_into().unwrap()));
    // The FIFO consumes midstate words in REVERSED order: dispatch writes
    // `words[4 + i]` from midstate bytes `[(7 - i) * 4 ..]`, i.e. W7 first —
    // the same production law the s17_native_runtime unit test pins. With
    // the FIPS/stock midstate words W0..W7 = bc909a33 6358bff0 90ccac7d
    // 1e59caa8 c3c8d8e9 4f0103c8 96b18736 4719f91b, the FIFO region is
    // 4719f91b 96b18736 4f0103c8 c3c8d8e9 1e59caa8 90ccac7d 6358bff0
    // bc909a33. One consistent story: plain BE storage, reversed load.
    for i in 0..8 {
        assert_eq!(
            words[4 + i],
            GENESIS_TRUE_MIDSTATE_WORDS[7 - i],
            "FIFO word {i} must be state word W{}",
            7 - i
        );
    }
    // Slots 1..3 repeat midstate 0 when only one is available.
    for i in 0..8 {
        assert_eq!(words[12 + i], GENESIS_TRUE_MIDSTATE_WORDS[7 - i]);
    }
}

#[test]
fn bm1397_driver_ctrl_and_ticket_mask_match_what_the_runtime_writes() {
    let driver = Bm1397Driver::new();
    // s17_native_runtime initialize() writes driver.ctrl_reg_value() and
    // driver.ticket_mask(256); pin them so a driver change is caught here.
    assert_eq!(driver.ctrl_reg_value(), 0x1C);
    assert_ne!(driver.ticket_mask(256), 0);
    assert_eq!(driver.chip_id(), 0x1397);
    assert_eq!(driver.cores_per_chip(), 672);
    // decode_nonce splits the RX words exactly as the ledger expects.
    let raw = rx_words(GENESIS_NONCE, 5, 2);
    let decoded = driver.decode_nonce(&raw).unwrap();
    assert_eq!(decoded.work_id, 5);
    assert_eq!(decoded.midstate_idx, 2);
    assert_eq!(decoded.nonce, GENESIS_NONCE);
}

#[test]
fn positive_work_nonce_share_replay_is_independently_oracle_verified() {
    let mut chain = ReplayChain::default();
    let mut ledger = WorkLedger::new();
    assert!(ledger.dispatch(&mut chain, genesis_work()).unwrap());

    // The known genesis solution arrives over the wire.
    let share = ledger
        .validate(rx_words(GENESIS_NONCE, 0, 0), "tester.s17")
        .unwrap()
        .expect("the genesis nonce must validate");

    // Submitted share fields are the exact public genesis values.
    assert_eq!(share.nonce, "7c2bac1d");
    assert_eq!(share.ntime, "495fab29");
    assert_eq!(share.job_id, "genesis-fixture");
    assert_eq!(share.worker_name, "tester.s17");
    assert_eq!(share.version, 1);
    assert!(share.version_bits.is_none());

    // Independent oracle reconstruction from the submitted strings: parse
    // the nonce/ntime back, rebuild the header, and verify the PUBLIC
    // genesis display hash AND the difficulty-1 target.
    let nonce = u32::from_str_radix(&share.nonce, 16).unwrap();
    let ntime = u32::from_str_radix(&share.ntime, 16).unwrap();
    let header = dcentrald_stratum::v1::job::build_block_header(
        share.version,
        &[0; 32],
        &GENESIS_MERKLE,
        ntime,
        0x1d00ffff,
        nonce,
    );
    let oracle_header = BlockHeader::from_wire(&header).unwrap();
    assert_eq!(oracle_header.display_hash(), GENESIS_DISPLAY);
    assert!(oracle_header.meets_target(), "oracle PoW check");
    assert!(display_hash_meets_target(
        &oracle_header.display_hash(),
        &difficulty_to_target(1.0)
    ));
    // The public genesis solution is a real difficulty-256 ticket (hashlib:
    // display 000000000019d668… <= pdiff1/256), so the measured-hashrate
    // counter must have counted exactly it.
    assert_eq!(ledger.valid_tickets(), 1);
}

#[test]
fn oracle_found_nonce_round_trips_through_the_production_ledger() {
    // Find a share with the ORACLE (not the stratum crate) against an
    // EXPLICIT byte target, then prove the production ledger accepts exactly
    // that nonce and refuses the neighbour. The work's pool target is set to
    // the same bytes the search used, so the oracle's hit/miss verdicts
    // transfer exactly. The target `[00, FF×31]` (≈2^248) gives a ~2^-8 hit
    // probability: the search stays bounded while remaining a real
    // double-SHA256 proof-of-work check. hashlib verification of this exact
    // vector (header = genesis fields, search from nonce 2): first hit at
    // nonce 236; nonce 235 verified a miss.
    let base = genesis_header80();
    let target: [u8; 32] = {
        let mut t = [0xFFu8; 32];
        t[0] = 0x00;
        t
    };
    let mut hit = None;
    for nonce in 2u32..100_000 {
        let mut trial = base;
        trial[76..80].copy_from_slice(&nonce.to_le_bytes());
        let internal = double_sha256(&trial);
        if display_hash_meets_target(&bitcoin_oracle::display_from_internal(&internal), &target) {
            hit = Some(nonce);
            break;
        }
    }
    let hit = hit.expect("a 2^-8 target must hit within 100k trials");
    assert_eq!(hit, 236, "hashlib-pinned first hit for this exact vector");

    let mut work = genesis_work();
    work.share_target = target;

    let mut chain = ReplayChain::default();
    let mut ledger = WorkLedger::new();
    assert!(ledger.dispatch(&mut chain, work).unwrap());

    // The immediately preceding nonce was oracle-verified as a MISS on this
    // exact target: it must NOT be submitted.
    assert!(ledger
        .validate(rx_words(hit - 1, 0, 0), "w")
        .unwrap()
        .is_none());
    // The oracle-found nonce IS submitted…
    let share = ledger
        .validate(rx_words(hit, 0, 0), "w")
        .unwrap()
        .expect("oracle-found share must validate");
    assert_eq!(share.nonce, format!("{hit:08x}"));
    // …but a pool share below difficulty 256 is NOT a measured-hashrate
    // ticket (production gates hashrate on independently validated
    // difficulty-256 tickets only).
    assert_eq!(ledger.valid_tickets(), 0);
    // Duplicate suppression: the same nonce never submits twice.
    assert!(ledger
        .validate(rx_words(hit, 0, 0), "w")
        .unwrap()
        .is_none());
}

#[test]
fn stale_job_metadata_and_foreign_slots_never_authorize_a_nonce() {
    let mut chain = ReplayChain::default();
    let mut ledger = WorkLedger::new();
    assert!(ledger.dispatch(&mut chain, genesis_work()).unwrap()); // slot 0
    assert!(ledger.dispatch(&mut chain, genesis_work()).unwrap()); // slot 1
    // A clean-job invalidation (pool notify / disconnect) kills the metadata.
    ledger.invalidate();
    assert!(ledger
        .validate(rx_words(GENESIS_NONCE, 0, 0), "w")
        .unwrap()
        .is_none());
    // A nonce naming a slot that was never dispatched is refused.
    assert!(ledger
        .validate(rx_words(GENESIS_NONCE, 2, 0), "w")
        .unwrap()
        .is_none());
    // A failed write must not leave stale metadata authorized: the slot is
    // cleared BEFORE the physical write is attempted.
    let mut failing = ReplayChain {
        fail_write: true,
        ..ReplayChain::default()
    };
    assert!(ledger.dispatch(&mut failing, genesis_work()).is_err()); // slot 2
    assert!(ledger
        .validate(rx_words(GENESIS_NONCE, 2, 0), "w")
        .unwrap()
        .is_none());
    // A fresh good dispatch re-authorizes its own slot.
    let mut ok_chain = ReplayChain::default();
    assert!(ledger.dispatch(&mut ok_chain, genesis_work()).unwrap()); // slot 2
    assert!(ledger
        .validate(rx_words(GENESIS_NONCE, 2, 0), "w")
        .unwrap()
        .is_some());
}

#[test]
fn work_id_slots_advance_wrap_and_stay_chain_independent() {
    let mut chain = ReplayChain::default();
    let mut ledger = WorkLedger::new();
    for index in 0..65 {
        let mut work = genesis_work();
        work.job_id = format!("job-{index}");
        assert!(ledger.dispatch(&mut chain, work).unwrap());
    }
    // The FPGA reconstructs 16-bit work IDs: slots 0, 32 and 64 keep
    // distinct metadata even though the low 7 wire bits collide.
    for slot in [0usize, 32, 64] {
        let share = ledger
            .validate(rx_words(GENESIS_NONCE, slot, 0), "w")
            .unwrap()
            .unwrap_or_else(|| panic!("slot {slot} must retain its job"));
        assert_eq!(share.job_id, format!("job-{slot}"));
        assert_eq!(chain.writes[slot][0], (slot as u32) << 2);
    }
    // Slot counter wraps at 16384.
    ledger.next = 16383;
    let mut work = genesis_work();
    work.job_id = "wrap".into();
    assert!(ledger.dispatch(&mut chain, work).unwrap());
    assert_eq!(chain.writes.last().unwrap()[0], 0xFFFC);
    assert_eq!(ledger.next, 0);

    // Chain independence: a second ledger (physical chain) shares nothing.
    let mut other = WorkLedger::new();
    assert!(other
        .validate(rx_words(GENESIS_NONCE, 0, 0), "w")
        .unwrap()
        .is_none());
}

// ---------------------------------------------------------------------------
// Version-rolled work through the real builder (BIP310 contract)
// ---------------------------------------------------------------------------

#[test]
fn version_rolled_midstates_dispatch_and_reconstruct_with_pool_rule() {
    let genesis = genesis_work();
    let job = JobTemplate {
        work_generation: genesis.work_generation,
        v1_work_domain: None,
        job_id: "rolled-fixture".into(),
        prev_block_hash: [0; 32],
        coinbase1: Vec::new(),
        coinbase2: Vec::new(),
        merkle_branches: Vec::new(),
        version: 0x2000_2000,
        nbits: genesis.nbits,
        ntime: genesis.ntime,
        clean_jobs: true,
        share_target: [0xff; 32],
        extranonce1: Vec::new(),
        extranonce2_size: 0,
        version_mask: 0x6000,
        merkle_root: genesis.merkle_root,
        pool_difficulty: 0.0,
    };
    let mut builder = WorkBuilder::new();
    builder.set_version_mask(job.version_mask);
    let work = builder.next_work(&job).unwrap();
    assert_eq!(work.midstates.len(), 8, "real shared builder behavior");

    let mut chain = ReplayChain::default();
    let mut ledger = WorkLedger::new();
    assert!(ledger.dispatch(&mut chain, work).unwrap());

    // The four-slot fabric consumes the first four rolled versions.
    let expected = [0x2000_2000u32, 0x2000_4000, 0x2000_6000, 0x2000_0000];
    for (midstate, version) in expected.iter().enumerate() {
        let share = ledger
            .validate(rx_words(42, 0, midstate as u8), "w")
            .unwrap()
            .unwrap_or_else(|| panic!("midstate {midstate} must validate"));
        // BIP310: the submitted version_bits are the ACTUAL masked version,
        // and the pool reconstructs (job.version & !mask) | (bits & mask).
        let bits = u32::from_str_radix(share.version_bits.as_deref().unwrap(), 16).unwrap();
        let pool_reconstructed = (job.version & !job.version_mask) | (bits & job.version_mask);
        assert_eq!(share.version, *version);
        assert_eq!(pool_reconstructed, *version);
        // The oracle independently hashes the reconstructed header: the
        // dispatched words for this midstate slot must be ITS FIPS words in
        // the FIFO's reversed load order (W7 first, per `offset = (7-i)*4`).
        let header = dcentrald_stratum::v1::job::build_block_header(
            *version,
            &[0; 32],
            &genesis.merkle_root,
            genesis.ntime,
            genesis.nbits,
            42,
        );
        let prefix: [u8; 64] = header[..64].try_into().unwrap();
        let mut midstate_words = digest_to_words(&compute_midstate_from_prefix(&prefix));
        midstate_words.reverse();
        let slot_words = chain.writes[0][4 + midstate * 8..4 + midstate * 8 + 8].to_vec();
        assert_eq!(slot_words, midstate_words, "midstate {midstate} FIFO words");
    }
}

// ---------------------------------------------------------------------------
// FIFO frame-space rule
// ---------------------------------------------------------------------------

#[test]
fn fifo_backpressure_requires_a_complete_frame_before_any_write() {
    assert!(work_queue_has_complete_frame_space(4, 1848));
    assert!(!work_queue_has_complete_frame_space(0, 1848), "EMPTY blocks");
    assert!(!work_queue_has_complete_frame_space(8 | 16, 1848), "FULL blocks");
    assert!(!work_queue_has_complete_frame_space(16, 2048), "wrong threshold");
    let mut chain = ReplayChain {
        full: true,
        ..ReplayChain::default()
    };
    let mut ledger = WorkLedger::new();
    // Backpressured dispatch is a clean skip (Ok(false)), not an error, and
    // consumes no slot.
    assert!(!ledger.dispatch(&mut chain, genesis_work()).unwrap());
    assert_eq!(ledger.next, 0);
    assert!(chain.writes.is_empty());
}
