//! R06 BM1396 ChipDriver replay tests (desk-only, no hardware; the Lead owns
//! the serialized cargo slot).
//!
//! Campaign `2026-09-07-antminer-beta-execution`, lane R06
//! ("Implement S17e/T17e mining", owner runtime_bm1396). Every constant
//! asserted here is cited in
//! evidence/r06/SOURCE_NOTE.md` to either:
//!   - the held signed S17e/T17e binaries and their pre-decompilations
//!     (/`, e.g.
//!     `get_nonce_and_register@2AA04.c`, `get_return_nonce@44D18.c`,
//!     `get_pllparam_divider@225D8.c`), or
//!   - the prior R06 HAL/common sources (HAL53 cold core, HAL58 ADC,
//!     `dcentrald-common::bm1396_*` modules) which replay the original
//!     callers (18 cold spines, 52 baud callers, 384 ADC callbacks, 128 PLL
//!     ramp stages).
//!
//! Positive paths: init/address sequence bytes, cold-spine register words,
//! stock-format job packet -> FPGA plan (work TX frame), nonce RX decode
//! from captured-style two-word records, 135 vs 78 population profiles,
//! and header reconstruct + share-target checks against the INDEPENDENT
//! F04 Bitcoin oracle (`f04_oracle/bitcoin_oracle.rs`, never dcentrald
//! hashing code).
//!
//! Fault paths: malformed/CRC-error/invalid records, model-misaligned wire
//! addresses, out-of-geometry populations (partial init), unsupported baud
//! refusal, stale outside-window returns, duplicate drops, and the
//! deliberate Braiins-FIFO carrier / midstate-work-TX refusals.
//!
//! This test grants no hardware, energization, dispatch, or registration
//! authority: BM1396 stays unregistered in `ChipRegistry` (Lead-owned
//! promotion; see `drivers/mod.rs` PR-056 pin).

#![forbid(unsafe_code)]

#[path = "f04_oracle/bitcoin_oracle.rs"]
mod bitcoin_oracle;

use bitcoin_oracle::BlockHeader;
use dcentrald_asic::drivers::bm1396::{
    bm1396_read_register_frame, bm1396_reset_address_frame, bm1396_set_address_frame,
    bm1396_write_register_frame, Bm1396Driver,
};
use dcentrald_asic::drivers::ChipDriver;
use dcentrald_common::{
    admit_bm1396_present_chain_enumeration, bm1396_baud_plan, bm1396_command_crc5,
    bm1396_decode_nonce_record, bm1396_job_scalar_writes, bm1396_job_version_mode,
    bm1396_parse_job_packet, bm1396_plan_job_fpga, bm1396_previous_hash_fpga_words,
    ticket_mask_from_difficulty, Bm1396Model, Bm1396NonceDecodeError, Bm1396VersionLaneMode,
    TicketMaskEncoding, BM1396_ADDRESS_RESET_BURST_COUNT, BM1396_PLL_FAILURE_REGISTER,
    BM1396_RETURN_RECORD_LEN, BM1396_S17E_CHIPS_PER_PRESENT_CHAIN,
    BM1396_T17E_CHIPS_PER_PRESENT_CHAIN, BM1396_WIRE_CHIP_ID,
};

fn s17e() -> Bm1396Driver {
    Bm1396Driver::new()
}

fn t17e() -> Bm1396Driver {
    Bm1396Driver::for_model(Bm1396Model::T17e)
}

// ---------------------------------------------------------------------------
// Positive: init / address assignment sequence bytes
// ---------------------------------------------------------------------------

/// Address-reset burst and per-model set-address ladders, byte-exact.
/// Reset frame `[0x53,0x05,0,0,CRC5]` x3 (BM1396_ADDRESS_RESET_BURST_COUNT,
/// 30 ms spacing) precedes assignment; assignment addresses are
/// `ordinal * interval` for `floor(256/interval)` commands
/// (S17e interval 1 stored at `0x80ea0`; T17e interval 3 at `0x81d48`).
#[test]
fn init_address_sequence_bytes_match_held_goldens() {
    let reset = bm1396_reset_address_frame();
    assert_eq!(reset, [0x53, 0x05, 0x00, 0x00, 0x03]);
    assert_eq!(BM1396_ADDRESS_RESET_BURST_COUNT, 3);

    // S17e: 256 dense assignments 0x00..=0xFF.
    let s17e = s17e();
    assert_eq!(s17e.address_interval(), 1);
    let s17e_count = s17e.model().address_assignment_count();
    assert_eq!(s17e_count, 256);
    for ordinal in 0..s17e_count {
        let address = s17e.model().assignment_address(ordinal).expect("in range");
        assert_eq!(address, ordinal as u8);
        let frame = bm1396_set_address_frame(address);
        assert_eq!(frame[0], 0x40, "CMD_SETADDRESS header 0x40, NOT BM1387's 0x41");
        assert_eq!(frame[1], 0x05);
        assert_eq!(frame[2], address);
        assert_eq!(frame[4], bm1396_command_crc5(&frame[..4]));
    }

    // T17e: 85 assignments at stride 3 ending at 0xFC (stub golden kept).
    let t17e = t17e();
    assert_eq!(t17e.address_interval(), 3);
    let t17e_count = t17e.model().address_assignment_count();
    assert_eq!(t17e_count, 85);
    let last = t17e.model().assignment_address(t17e_count - 1).unwrap();
    assert_eq!(last, 252);
    assert_eq!(bm1396_set_address_frame(last), [0x40, 0x05, 0xfc, 0x00, 0x02]);
    assert_eq!(bm1396_set_address_frame(231), [0x40, 0x05, 0xe7, 0x00, 0x0b]);
    for ordinal in 0..t17e_count {
        let address = t17e.model().assignment_address(ordinal).unwrap();
        assert_eq!(address as u16, ordinal * 3);
    }
}

/// Cold-spine register words and frames. Words are the HAL53 cold core
/// (`dcentrald-hal/src/platform/stock_bm1396_cold.rs`, 18 complete original
/// cold caller replays; `evidence/r06/native-cold-core-implementation-v1.md`):
/// Misc18 prewrite `(old & !0x0040_0000) | 0xf000_0000` with uniform
/// readback, per-chip relay 0x2c (S17e step 9 value 0x0039_0003 / T17e step 6
/// value 0x0033_0003), CoreRegCtrl 0x3c double write, TicketMask 0x14 = 0xfe,
/// then 0x54 = 3, 0xb0 = 0x0010_0000, 0x6c = 0x0200_0203.
#[test]
fn cold_spine_words_and_frames_match_held_source() {
    // Misc18 prewrite transform (model-independent).
    for old in [0x004a_0201u32, 0x0040_0000u32] {
        let new = (old & !0x0040_0000) | 0xf000_0000;
        assert_eq!(new & 0x0040_0000, 0, "bit 22 cleared");
        assert_eq!(new & 0xf000_0000, 0xf000_0000, "mode bits set");
    }
    let old = 0x004a_0201u32;
    let new = (old & !0x0040_0000) | 0xf000_0000;
    let frame = bm1396_write_register_frame(true, 0x00, 0x18, new);
    assert_eq!(&frame[..4], &[0x51, 0x09, 0x00, 0x18]);
    assert_eq!(frame[8], bm1396_command_crc5(&frame[..8]));

    // Per-chip relay frames: single-chip write header 0x41.
    let s17e_relay = bm1396_write_register_frame(false, 9, 0x2c, 0x0039_0003);
    assert_eq!(&s17e_relay[..4], &[0x41, 0x09, 0x09, 0x2c]);
    assert_eq!(&s17e_relay[4..8], &[0x00, 0x39, 0x00, 0x03]);
    let t17e_relay = bm1396_write_register_frame(false, 6, 0x2c, 0x0033_0003);
    assert_eq!(&t17e_relay[4..8], &[0x00, 0x33, 0x00, 0x03]);
    // Relay writes: the HAL53 loop is `(step..chips).step_by(step)`
    // (stock_bm1396_cold.rs:163), so it starts at ordinal `step` and never
    // touches chip address 0 — S17e emits 14 relay commands (9,18,..,126)
    // and T17e 12 (6,12,..,72). The 15/13 figure from
    // native-adc-acquisition-source-v1.md is the ADC DOMAIN COUNT
    // (135/9 and 78/6), a different fact from the relay command count.
    assert_eq!((9..135).step_by(9).count(), 14, "S17e relay ordinals");
    assert_eq!((6..78).step_by(6).count(), 12, "T17e relay ordinals");
    // Domain geometry stays 15 x 9 = 135 and 13 x 6 = 78 (r06adc).
    assert_eq!(135 / 9, 15);
    assert_eq!(78 / 6, 13);

    // Core register control double writes.
    let core_ctrl_1 = bm1396_write_register_frame(true, 0x00, 0x3c, 0x8000_8710);
    assert_eq!(&core_ctrl_1[4..8], &[0x80, 0x00, 0x87, 0x10]);
    let s17e_core = 0x8000_8004u32 | (3 << 4) | (1 << 6);
    let t17e_core = 0x8000_8004u32 | (2 << 4) | (1 << 6);
    assert_eq!(s17e_core, 0x8000_8074, "S17e built-in core tuple 1/3/1");
    assert_eq!(t17e_core, 0x8000_8064, "T17e built-in core tuple 1/2/1");

    // TicketMask / ordered clock enable / B0 / 6c words.
    let ticket = bm1396_write_register_frame(true, 0x00, 0x14, 0xfe);
    assert_eq!(&ticket[4..8], &[0x00, 0x00, 0x00, 0xfe]);
    let clock_en = bm1396_write_register_frame(true, 0x00, 0x54, 3);
    assert_eq!(&clock_en[4..8], &[0x00, 0x00, 0x00, 0x03]);
    let b0 = bm1396_write_register_frame(true, 0x00, 0xb0, 0x0010_0000);
    assert_eq!(&b0[4..8], &[0x00, 0x10, 0x00, 0x00]);
    let six_c = bm1396_write_register_frame(true, 0x00, 0x6c, 0x0200_0203);
    assert_eq!(&six_c[4..8], &[0x02, 0x00, 0x02, 0x03]);

    // TicketMask 0xfe is the bit-reversed encoding of difficulty 128 — the
    // same value the driver computes.
    assert_eq!(
        ticket_mask_from_difficulty(TicketMaskEncoding::BitReversed, 128),
        0xfe
    );
    assert_eq!(s17e().ticket_mask(128), 0xfe);
    assert_eq!(s17e().ticket_mask(256), 0x0000_00ff);

    // Enumeration read frame: unified broadcast read (0x52), register 0.
    assert_eq!(
        bm1396_read_register_frame(true, 0x00, 0x00),
        [0x52, 0x05, 0x00, 0x00, 0x0a]
    );
}

// ---------------------------------------------------------------------------
// Positive: work TX frame (stock-format job packet -> FPGA plan)
// ---------------------------------------------------------------------------

fn coinbase_padded_len(coinbase: &[u8]) -> usize {
    // SHA-256 padding: message || 0x80 || zeros || 64-bit length, 64-aligned.
    let rem = (coinbase.len() + 1) % 64;
    let zeros = if rem <= 56 { 56 - rem } else { 120 - rem };
    coinbase.len() + 1 + zeros + 8
}

/// One stock-format job packet, byte-constructed to the recovered layout
/// (`bm1396_work.rs`: 0x52 header, 0x58-byte fixed body, coinbase then
/// 32-byte merkle branches), and its exact FPGA job plan: buffer A at
/// `0x20_0000`, scalar writes per `bm1396_job_scalar_writes`, and the
/// version-lane mirrors for multiversion jobs.
#[test]
fn work_tx_frame_is_stock_job_packet_with_exact_fpga_plan() {
    let oracle_header = work_header();
    let coinbase = b"r06-replay-coinbase".to_vec();
    let mut packet = vec![0u8; 0x58];
    packet[0] = 0x52; // BM1396_JOB_HEADER
    // body_len counts everything after the 8-byte prefix (parser contract:
    // declared_total = body_len + 8 == packet length).
    let total = (0x58usize + coinbase.len() + 32) as u32; // + one merkle branch
    packet[0x04..0x08].copy_from_slice(&(total - 8).to_le_bytes());
    packet[0x09] = 0x01 | 0x02; // main-control bit7 force + ticket difficulty present
    packet[0x0a] = 0x2a; // FPGA ticket difficulty byte (register 0x8c path)
    packet[0x0c..0x10].copy_from_slice(&7u32.to_le_bytes()); // job id
    packet[0x10..0x14].copy_from_slice(&oracle_header.version.to_le_bytes());
    packet[0x14..0x34].copy_from_slice(&oracle_header.prev_hash); // previous header hash
    packet[0x34..0x38].copy_from_slice(&oracle_header.timestamp.to_le_bytes());
    packet[0x38..0x3c].copy_from_slice(&oracle_header.nbits.to_le_bytes());
    packet[0x3c..0x3e].copy_from_slice(&(coinbase.len() as u16).to_le_bytes());
    packet[0x3e..0x40].copy_from_slice(&52u16.to_le_bytes()); // nonce2 offset
    packet[0x40] = 8; // nonce2 size
    packet[0x42..0x44].copy_from_slice(&1u16.to_le_bytes()); // one merkle branch
    packet[0x48..0x50].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
    packet[0x50] = 0; // multiversion disabled
    packet.extend_from_slice(&coinbase);
    packet.extend_from_slice(&[0xa5u8; 32]); // the merkle branch

    let job = bm1396_parse_job_packet(&packet).expect("well-formed packet");
    assert_eq!(job.job_id, 7);
    assert_eq!(job.block_version, oracle_header.version);
    assert_eq!(job.previous_header_hash, oracle_header.prev_hash);
    assert_eq!(job.coinbase, coinbase.as_slice());
    assert_eq!(job.merkle_branches.len(), 32);
    assert_eq!(job.nonce2_initial, 0x0102_0304_0506_0708);

    let plan = bm1396_plan_job_fpga(&job, 0).expect("buffer 0 plan");
    assert_eq!(plan.buffer_offset(), 0x20_0000, "job buffer A");
    // Payload = SHA-256-padded coinbase + merkle branches.
    assert!(plan.buffer_payload().starts_with(&coinbase));
    assert_eq!(plan.buffer_payload().len(), coinbase_padded_len(&coinbase) + 32);
    assert!(plan.buffer_payload().ends_with(&[0xa5u8; 32]));
    assert_eq!(plan.ticket_difficulty(), Some(0x2a));

    // Buffer B index selects 0x21_0000.
    let plan_b = bm1396_plan_job_fpga(&job, 1).expect("buffer 1 plan");
    assert_eq!(plan_b.buffer_offset(), 0x21_0000);

    // Scalar write spine: exact (offset, value) sequence, single version lane.
    let mode = bm1396_job_version_mode(&plan, false).expect("single mode");
    assert_eq!(mode, Bm1396VersionLaneMode::One);
    let writes = bm1396_job_scalar_writes(&plan, mode);
    let head: &[(u32, u32)] = &[
        (0x8c, 0x2a),                   // ticket difficulty
        (0x124, 7),                     // job id
        (0x130, oracle_header.version), // block version (base lane only)
    ];
    for (index, (offset, value)) in head.iter().enumerate() {
        assert_eq!(writes[index].offset, *offset, "write {index} offset");
        assert_eq!(writes[index].value, *value, "write {index} value");
    }
    let prev_words = bm1396_previous_hash_fpga_words(&oracle_header.prev_hash);
    for (index, word) in prev_words.iter().enumerate() {
        let write = &writes[3 + index];
        assert_eq!(write.offset, 0x140 + index as u32 * 4);
        assert_eq!(write.value, *word);
    }
    let padded_blocks = (coinbase_padded_len(&coinbase) / 64) as u32;
    let payload_end = (coinbase_padded_len(&coinbase) + 32) as u32;
    let tail: &[(u32, u32)] = &[
        (0x134, oracle_header.timestamp),
        (0x138, oracle_header.nbits),
        (0x104, (52 << 16) | (8 << 8) | padded_blocks),
        (0x108, 0x0506_0708), // nonce2 low
        (0x10c, 0x0102_0304), // nonce2 high
        (0x114, 1),           // merkle branch count
        (0x11c, payload_end & 0xffe0),
    ];
    let tail_base = 3 + prev_words.len();
    for (index, (offset, value)) in tail.iter().enumerate() {
        let write = &writes[tail_base + index];
        assert_eq!(write.offset, *offset, "tail write {index} offset");
        assert_eq!(write.value, *value, "tail write {index} value");
    }
    assert_eq!(
        writes.len(),
        tail_base + tail.len(),
        "single mode adds no version-lane mirror writes"
    );

    // Multiversion job: four version lanes mirror the rolled versions.
    packet[0x50] = 1;
    packet[0x54..0x58].copy_from_slice(&4u32.to_le_bytes());
    let job4 = bm1396_parse_job_packet(&packet).expect("multiversion packet");
    let plan4 = bm1396_plan_job_fpga(&job4, 0).expect("plan");
    let mode4 = bm1396_job_version_mode(&plan4, true).expect("four lanes");
    assert_eq!(mode4, Bm1396VersionLaneMode::Four);
    let writes4 = bm1396_job_scalar_writes(&plan4, mode4);
    assert_eq!(writes4[2].offset, 0x130, "base version lane first");
    assert_eq!(writes4[2].value, oracle_header.version);
    let lane_offsets: Vec<u32> = writes4[3..6].iter().map(|w| w.offset).collect();
    assert_eq!(lane_offsets, vec![0x164, 0x168, 0x16c]);
    assert_eq!(writes4[3].value, oracle_header.version | 0x0000_4000);
    assert_eq!(writes4[4].value, oracle_header.version | 0x0000_8000);
    assert_eq!(writes4[5].value, oracle_header.version | 0x0000_c000);
}

// ---------------------------------------------------------------------------
// Positive: nonce RX decode vs the .dec-derived record layout
// ---------------------------------------------------------------------------

/// `get_return_nonce@44D18.c` reads return words at fabric offsets 0x10/0x14;
/// `get_nonce_and_register@2AA04.c` classifies bit 31 (nonce dispatch),
/// byte0 bit 7 (nonce valid), byte0 bit 6 (CRC error), work id =
/// `HIWORD(buf[0]) & 0x7FFF` = word0 bits [30:16], nonce = word1, chain =
/// word0 [3:0]. The 8-byte record is the two words in LE bytes (HAL receiver
/// mapping).
#[test]
fn nonce_rx_decode_matches_dec_captured_two_word_records() {
    // Captured-style record: work_id 5, chain 3, nonce with chip address 134
    // (bits 17..24) and core id 7 (bits 25..31); body bits stay below bit 17.
    // Work id sits at bits [30:16] (HIWORD & 0x7FFF law), hence `5 << 16`:
    // placing it at bit 15 instead decodes as 2 (verified against the .dec
    // law by hand before this fix).
    let nonce_value: u32 = (7 << 25) | (134 << 17) | 0x0001_2345;
    let word0: u32 = (1 << 31) | (5 << 16) | 0x80 | 3;
    let word1: u32 = nonce_value;
    let mut record = [0u8; BM1396_RETURN_RECORD_LEN];
    record[..4].copy_from_slice(&word0.to_le_bytes());
    record[4..].copy_from_slice(&word1.to_le_bytes());

    // Driver decode equals the common codec decode of the captured bytes.
    let via_driver = s17e().decode_return_record(word0, word1).expect("valid nonce");
    let direct = bm1396_decode_nonce_record(Bm1396Model::S17e, &record).expect("valid nonce");
    assert_eq!(via_driver, direct);
    assert_eq!(via_driver.work_id, 5);
    assert_eq!(via_driver.nonce, word1);
    assert_eq!(via_driver.core_id, 7);
    assert_eq!(via_driver.wire_chip_address, 134);
    assert_eq!(via_driver.chip_ordinal, 134, "S17e interval 1");

    // The trait surface maps the same record into NonceResult.
    let raw: [u32; 2] = [word0, word1];
    let result = s17e().decode_nonce(&raw).expect("S17e in geometry");
    assert_eq!(result.nonce, word1);
    assert_eq!(result.chip_index, 134);
    assert_eq!(result.work_id, 5);

    // T17e: wire address 231 = ordinal 77 x interval 3; work_id 9 at bit 16.
    let t17e_nonce: u32 = (2 << 25) | (231 << 17);
    let t17e_word0: u32 = (1 << 31) | (9 << 16) | 0x80 | 6;
    let t17e_result = t17e()
        .decode_nonce(&[t17e_word0, t17e_nonce])
        .expect("T17e in geometry");
    assert_eq!(t17e_result.chip_index, 77);
    assert_eq!(t17e_result.work_id, 9);

    // The S17e driver refuses the T17e-shaped record (fail-closed, never a
    // silent cross-model attribution).
    assert!(matches!(
        s17e().decode_return_record(t17e_word0, t17e_nonce),
        Err(Bm1396NonceDecodeError::ChipOrdinalOutOfRange { .. })
    ));
}

// ---------------------------------------------------------------------------
// Positive: 135 vs 78 population profiles stay separate
// ---------------------------------------------------------------------------

#[test]
fn population_profiles_135_vs_78_stay_separate_and_fail_closed() {
    assert_eq!(BM1396_S17E_CHIPS_PER_PRESENT_CHAIN, 135);
    assert_eq!(BM1396_T17E_CHIPS_PER_PRESENT_CHAIN, 78);
    assert_eq!(s17e().chips_per_chain(), 135);
    assert_eq!(t17e().chips_per_chain(), 78);

    // Enumeration admission is exact per model (chip id 0x1396 + exact count).
    assert!(s17e().admit_present_chain_enumeration(0x1396, 135).is_ok());
    assert!(t17e().admit_present_chain_enumeration(0x1396, 78).is_ok());
    // Wrong chip id (0x1397 = BM1397) never passes.
    assert!(s17e().admit_present_chain_enumeration(0x1397, 135).is_err());
    // Partial populations never pass (partial-init fault shape).
    assert!(s17e().admit_present_chain_enumeration(0x1396, 134).is_err());
    assert!(t17e().admit_present_chain_enumeration(0x1396, 79).is_err());
    assert!(t17e().admit_present_chain_enumeration(0x1396, 135).is_err());
    assert!(s17e().admit_present_chain_enumeration(0x1396, 78).is_err());
    // The free function agrees (single source).
    assert!(
        admit_bm1396_present_chain_enumeration(Bm1396Model::T17e, BM1396_WIRE_CHIP_ID, 78).is_ok()
    );

    // Hardware addresses stay inside the 8-bit wire field per model.
    assert_eq!(s17e().model().hardware_address(134), Some(134));
    assert_eq!(s17e().model().hardware_address(135), None);
    assert_eq!(t17e().model().hardware_address(77), Some(231));
    assert_eq!(t17e().model().hardware_address(78), None);

    // Metadata surface: identity, response shape, bauds, control word.
    assert_eq!(s17e().chip_id(), 0x1396);
    assert_eq!(s17e().chip_name(), "BM1396");
    assert_eq!(s17e().response_length(), 8);
    assert_eq!(s17e().default_baud(), 115_200);
    assert_eq!(s17e().max_baud(), 6_000_000);
    assert_eq!(s17e().job_interval_ms(135, 600), 1);
    assert_eq!(s17e().ctrl_reg_value(), 0x40, "stock MAIN_CONTROL RUN bit, never 0");
    assert_eq!(
        s17e().cores_per_chip(),
        0,
        "core count unproved: deliberate refusal"
    );
    assert!(Bm1396Driver::production_pure_pll_admitted());
}

// ---------------------------------------------------------------------------
// Positive: baud selectors and PLL params
// ---------------------------------------------------------------------------

#[test]
fn baud_selectors_and_pll_params_match_exact_plans() {
    // Exact signed-fabric selector table (bm1396_baud_plan), repeated across
    // all four byte lanes over the 0xc0c0_c0c0 preserve mask.
    for (baud, selector) in [
        (115_200u32, 0x1au8),
        (1_500_000, 0x01),
        (3_000_000, 0x00),
        (6_000_000, 0x03),
        (12_000_000, 0x04),
        (25_000_000, 0x05),
    ] {
        let plan = bm1396_baud_plan(baud, 0, 0).expect("supported baud");
        let repeated = u32::from(selector)
            | (u32::from(selector) << 8)
            | (u32::from(selector) << 16)
            | (u32::from(selector) << 24);
        assert_eq!(plan.fpga_register_value, repeated);
        assert_eq!(s17e().baud_reg_value(baud, 200_000_000), repeated);
    }
    // Operational goldens: S17e 6 Mbaud (divisor 7, misc 0x0001_0700) and
    // T17e 3 Mbaud (divisor 0) from native-operational-baud-vectors-v1.
    let s17e_op = bm1396_baud_plan(6_000_000, 0, 0).unwrap();
    assert_eq!((s17e_op.bt8d, s17e_op.high_speed_clock), (7, true));
    assert_eq!(s17e_op.misc_control_register_value, 0x0001_0700);
    assert_eq!(s17e().max_baud(), 6_000_000);
    let t17e_op = bm1396_baud_plan(3_000_000, 0, 0).unwrap();
    assert_eq!((t17e_op.bt8d, t17e_op.high_speed_clock), (0, false));

    // PLL: exact solver + on-wire program word (bit 30 forced).
    let params = s17e().pll_params(600);
    let solution = Bm1396Driver::resolve_pll(600.0, 0).expect("600 MHz solvable");
    assert_eq!(params.fb_div, solution.dividers().fb_div);
    assert_eq!(params.ref_div, solution.dividers().ref_div);
    assert_eq!(params.post_div1, solution.dividers().post_div1);
    assert_eq!(params.post_div2, solution.dividers().post_div2);
    assert_eq!(
        params.reg_value,
        0x4000_0000 | (solution.register_value() & 0x5fff_ffff)
    );
    // The double-write pure plan transmits exactly this word, twice, to PLL
    // bank 0x08 (native-pll-ramp-source-v1.md; PLL_PROGRAM_WRITE_COUNT = 2).
    let ops = Bm1396Driver::plan_frequency_program_ops(600).expect("plan");
    assert_eq!(ops.len(), 2);

    // Unattainable targets carry the vendor failure word — refuse to program.
    assert_eq!(s17e().pll_params(3135).reg_value, BM1396_PLL_FAILURE_REGISTER);
    assert!(Bm1396Driver::plan_frequency_program_ops(3135).is_none());
}

// ---------------------------------------------------------------------------
// Positive: header reconstruct + share target via the F04 oracle
// ---------------------------------------------------------------------------

fn work_header() -> BlockHeader {
    BlockHeader {
        version: 0x2000_0000,
        prev_hash: [0x11; 32],
        merkle_root: [0x22; 32],
        timestamp: 0x5f00_6f4d,
        // 0x2030_0000 decodes to target 0x0030_0000 << 232: hits every ~200
        // nonces, misses abundant — fast deterministic search both ways.
        nbits: 0x2030_0000,
        nonce: 0,
    }
}

/// Decode a two-word return record, rebuild the 80-byte header around the
/// returned nonce, and require the INDEPENDENT oracle to agree the hit nonce
/// meets the compact target while the miss nonce does not. This is the
/// decode -> share-target join the production receiver performs, proven
/// without any dcentrald hashing code.
#[test]
fn oracle_share_target_check_accepts_hits_and_refuses_misses() {
    let header = work_header();
    // Chip 0 / core 0 require nonce bits 17+ clear, so both nonces are
    // searched below 2^17 (the loose target yields plenty of both).
    let hit_nonce = (0u32..1 << 17)
        .find(|n| header.with_nonce(*n).meets_target())
        .expect("loose target yields a hit");
    let miss_nonce = (hit_nonce + 1..1 << 17)
        .find(|n| !header.with_nonce(*n).meets_target())
        .expect("adjacent nonce misses");

    for (nonce, expect_hit) in [(hit_nonce, true), (miss_nonce, false)] {
        // Two-word record carrying the nonce (work_id 1 at bits [30:16],
        // chain 0, chip 0).
        let word0: u32 = (1 << 31) | (1 << 16) | 0x80;
        let word1: u32 = (0 << 25) | (0 << 17) | nonce;
        let decoded = s17e().decode_nonce(&[word0, word1]).expect("chip 0 valid");
        assert_eq!(decoded.nonce, nonce);

        // Header reconstruct + oracle share check.
        let rebuilt = header.with_nonce(decoded.nonce);
        assert_eq!(rebuilt.to_wire()[76..80], nonce.to_le_bytes());
        assert_eq!(rebuilt.meets_target(), expect_hit);
    }
}

// ---------------------------------------------------------------------------
// Faults: malformed records, CRC, staleness, duplicates, baud, carrier
// ---------------------------------------------------------------------------

#[test]
fn faulted_records_and_stale_windows_fail_closed() {
    // Short record (partial RX): the common codec refuses the length.
    let short = [0u8; 7];
    assert!(matches!(
        bm1396_decode_nonce_record(Bm1396Model::S17e, &short),
        Err(Bm1396NonceDecodeError::WrongLength { .. })
    ));

    // CRC-error record (byte0 bit 6): refused before attribution.
    // (Work_id sits at bits [30:16]; its value is irrelevant to this branch.)
    let crc_err_word0: u32 = (1 << 31) | (1 << 16) | 0x80 | 0x40;
    assert!(matches!(
        s17e().decode_return_record(crc_err_word0, 0),
        Err(Bm1396NonceDecodeError::FpgaCrcError)
    ));

    // Nonce-valid bit clear: not a nonce return.
    assert!(matches!(
        s17e().decode_return_record((1 << 31) | (1 << 16), 0),
        Err(Bm1396NonceDecodeError::NotValid)
    ));

    // T17e misaligned wire address (interval 3): refused.
    let misaligned: u32 = 100 << 17;
    assert!(matches!(
        t17e().decode_return_record((1 << 31) | 0x80, misaligned),
        Err(Bm1396NonceDecodeError::MisalignedWireAddress { .. })
    ));

    // Out-of-geometry ordinals: S17e 135+ and T17e 78+ refused.
    let over_s17e: u32 = 135 << 17;
    assert!(matches!(
        s17e().decode_return_record((1 << 31) | 0x80, over_s17e),
        Err(Bm1396NonceDecodeError::ChipOrdinalOutOfRange { .. })
    ));
    let over_t17e: u32 = 234 << 17; // ordinal 78
    assert!(matches!(
        t17e().decode_return_record((1 << 31) | 0x80, over_t17e),
        Err(Bm1396NonceDecodeError::ChipOrdinalOutOfRange { .. })
    ));

    // Unsupported baud: the driver reproduces the stock 0x1a fallback while
    // the strict contract refuses (a caller typo must be caught upstream).
    assert_eq!(s17e().baud_reg_value(937_500, 200_000_000), 0x1a1a_1a1a);
    assert!(bm1396_baud_plan(937_500, 0, 0).is_err());

    // Stale / duplicate host-ring window: the stock snapshot window is
    // current/previous/oldest (wrapping distance 0..=2); distance 3+ is
    // outside and must not validate.
    use dcentrald_common::bm1396_work_binding::{
        bm1396_consume_host_nonce, Bm1396DuplicateKey, Bm1396HostBoundNonce,
        Bm1396HostNonceDisposition, Bm1396HostNonceRingState, Bm1396JobSnapshot,
    };
    assert!(Bm1396JobSnapshot::from_wrapping_distance(0).is_some());
    assert!(Bm1396JobSnapshot::from_wrapping_distance(2).is_some());
    assert!(Bm1396JobSnapshot::from_wrapping_distance(3).is_none());

    let ring = Bm1396HostNonceRingState {
        write_index: 0,
        read_index: 0,
        queued: 1,
    };
    let record = Bm1396HostBoundNonce {
        job_id: 10,
        work_id: 1,
        version_word_wire: 0,
        nonce2: 0,
        nonce3: 0x1234,
        chain_slot: 0,
        opaque_tail_20_3f: [0; 32],
    };
    let no_key = Bm1396DuplicateKey { nonce3: 0, work_id: 0 };
    // Stale return: job id moved 3 ahead -> outside the job window.
    let stale = bm1396_consume_host_nonce(ring, no_key, 13, &record).expect("ring advance ok");
    assert!(matches!(
        stale.disposition,
        Bm1396HostNonceDisposition::DropOutsideJobWindow { wrapping_distance: 3 }
    ));
    // Fresh return inside the window -> validate.
    let fresh = bm1396_consume_host_nonce(ring, no_key, 10, &record).expect("ring advance ok");
    assert!(matches!(
        fresh.disposition,
        Bm1396HostNonceDisposition::Validate(_)
    ));
    // Immediate duplicate -> dropped before hashing.
    let dup = bm1396_consume_host_nonce(
        ring,
        Bm1396DuplicateKey { nonce3: 0x1234, work_id: 1 },
        10,
        &record,
    )
    .expect("ring advance ok");
    assert!(matches!(
        dup.disposition,
        Bm1396HostNonceDisposition::DropDuplicate
    ));
}

/// The deliberate carrier refusals: no BM1396 cold start, frequency
/// programming, or midstate work TX through the Braiins-FIFO shape, and no
/// PIC16 voltage path (the framed I2C 0x11 endpoint is the ownership route).
/// The refusal text names the owning HAL artifacts.
#[test]
fn carrier_work_and_voltage_refusals_name_their_owners() {
    let carrier = Bm1396Driver::carrier_refusal_reason();
    assert!(carrier.contains("stock_bm1396::Transport"), "{carrier}");
    assert!(carrier.contains("Braiins-FIFO FpgaChain"), "{carrier}");
    let work = Bm1396Driver::work_tx_refusal_reason();
    assert!(work.contains("Bm1396JobPacket"), "{work}");
    assert!(work.contains("MiningWork"), "{work}");
}
