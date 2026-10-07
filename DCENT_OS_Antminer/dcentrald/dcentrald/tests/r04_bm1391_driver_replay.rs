//! R04 BM1391 ChipDriver replay tests (desk-only, no hardware; the Lead owns
//! the serialized cargo slot).
//!
//! Campaign `2026-09-07-antminer-beta-execution`, lane R04 ("Implement exact
//! S15/T15 mining", owner runtime_bm1391). Every constant asserted here is
//! cited in
//! SOURCE_NOTE.md` to either:
//!   - the held exact S15/T15 stock roots
//!     (-om-20191213/
//!     fw/uramdisk.image.gz.tree/usr/bin/cgminer`, SHA-256-pinned per release
//!     in `dcentrald-common::bm1391_carrier_profile`), or
//!   - the prior R04 single-source helpers (`dcentrald-common::bm1391_*`
//!     modules), the retained HAL owner (`dcentrald-hal::platform::
//!     stock_bm1391`), and the R04 evidence vectors
//!     (`evidence/r04/engine-dma-*.json/md`, `power-thermal-*`).
//!
//! Positive paths: per-release 72/60 captured-register-population replay,
//! per-board PIC selector + APW8 callsites/DAC law, stock job-packet -> FPGA
//! publication plan (work TX), nonce RX decode -> outstanding-work binding ->
//! header reconstruct -> share-target checks against the INDEPENDENT F04
//! Bitcoin oracle (`f04_oracle/bitcoin_oracle.rs`, never dcentrald hashing
//! code).
//!
//! Fault paths: timeout-overflow plans, partial-init populations, malformed /
//! CRC-error / invalid records, stale returns and discarded stale submits,
//! duplicate and full-ring backpressure, wrong-geometry and wrong-board
//! refusals (S15 profile vs T15 evidence never cross-applies), and the
//! deliberate Braiins-FIFO carrier / midstate work-TX / PIC16 voltage
//! refusals naming their owners.
//!
//! This test grants no hardware, energization, dispatch, or registration
//! authority: BM1391 stays registered Scaffold-only
//! (`ChipRegistry::production().detect(0x1391)` is `None`; drivers/mod.rs pin).

#![forbid(unsafe_code)]

#[path = "f04_oracle/bitcoin_oracle.rs"]
mod bitcoin_oracle;

use bitcoin_oracle::{
    compact_target, digest_to_words, display_hash_meets_target, double_sha256, merkle_root,
    target_from_difficulty_pow2, BlockHeader, DIFF1_TARGET,
};
use dcentrald_asic::drivers::bm1391::{misc_ctrl_baud_word, Bm1391Driver};
use dcentrald_asic::drivers::ChipDriver;
use dcentrald_common::bm1391_carrier_profile::{
    match_bm1391_exact_stock_release, Bm1391StockRelease, Bm1391StockReleaseMatchError,
    Bm1391StockReleaseObservation, BM1391_S15_BAKED_PATTERN_PATH, BM1391_S15_CGMINER_SHA256,
    BM1391_S15_STOCK_EXPECTED_CHIPS_PER_CHAIN, BM1391_T15_BAKED_PATTERN_PATH,
    BM1391_T15_CGMINER_SHA256, BM1391_T15_STOCK_EXPECTED_CHIPS_PER_CHAIN,
};
use dcentrald_common::bm1391_share_qualification::{
    bm1391_stock_async_submission_plan, bm1391_stock_full_target_passes,
    bm1391_stock_submit_wrapper_plan, Bm1391StockAsyncSubmissionInput,
    Bm1391StockAsyncSubmissionOutcome, Bm1391StockSubmitWrapperInput, Bm1391StockSnapshotAge,
};
use dcentrald_common::bm1391_stock_work::{
    decode_bm1391_stock_job_packet, plan_bm1391_stock_job_publication, Bm1391StockJobBuffer,
    Bm1391StockJobPlanError, Bm1391StockPlannerInput, Bm1391StockPublicationStep,
    Bm1391StockRelease as WorkRelease, BM1391_STOCK_DHASH_BIT7, BM1391_STOCK_DHASH_RUN_BIT,
    BM1391_STOCK_FIRST_NONCE_FIFO_ENABLE, BM1391_STOCK_JOB_BUFFER_A_OFFSET,
    BM1391_STOCK_JOB_CRC_LEN, BM1391_STOCK_JOB_TYPE, BM1391_STOCK_MERKLE_BRANCH_LEN,
    BM1391_STOCK_SINGLE_CONTROL_PRESERVE, BM1391_STOCK_SINGLE_CONTROL_WORD,
    BM1391_STOCK_TICKET_UPDATE_FLAG, BM1391_STOCK_TIMEOUT_ENABLE, BM1391_STOCK_TIMEOUT_MASK,
};
use dcentrald_common::{
    advance_bm1391_stock_ring, bind_bm1391_stock_nonce, bm1391_stock_double_sha256_from_midstate,
    bm1391_stock_normalize_share_difficulty, bm1391_stock_pre_hash_step,
    decode_bm1391_stock_consumer_record, decode_bm1391_stock_fpga_return,
    pop_bm1391_stock_consumer_ring, Bm1391StockConsumerRingState, Bm1391StockDuplicateKey,
    Bm1391StockFpgaReturn, Bm1391StockPreHashDisposition, Bm1391StockPrecomputedHashInput,
    Bm1391StockReturnDecodeError, Bm1391StockRingError, Bm1391StockRingState,
    Bm1391StockWorkBindError, BM1391_STOCK_FPGA_RETURN_RECORD_LEN,
    BM1391_STOCK_OUTSTANDING_WORK_RECORD_LEN,
};

fn s15() -> Bm1391Driver {
    Bm1391Driver::new()
}

fn t15() -> Bm1391Driver {
    Bm1391Driver::for_release(dcentrald_hal::platform::stock_bm1391::Model::T15)
}

// ---------------------------------------------------------------------------
// Positive: release-scoped response counts (S15 72 / T15 60) replayed from
// captured-style register-0 return populations
// ---------------------------------------------------------------------------

/// One register-0 (chip-address) reply shaped exactly like the exact-release
/// enumeration traffic: word0 bit 31 CLEAR (register branch), register type 2,
/// CRC5 field, the addressed slot in bits 23:16, register 0 at bits 15:8, and
/// the chain slot in bits 3:0 held at 0 — a per-chain census runs on ONE
/// present chain, and the 4-bit slot field cannot carry chip ordinals.
/// Word1 carries chip-id 0x1391 in the high halfword (S15 `FUN_00041248`
/// tests `value >> 16 == 0x1391`, T15 `FUN_00041250`).
fn register_zero_record(address: u8, crc5: u8) -> [u8; BM1391_STOCK_FPGA_RETURN_RECORD_LEN] {
    let word0: u32 = (2 << 29) | (u32::from(crc5) << 24) | (u32::from(address) << 16);
    let word1: u32 = 0x1391_0000 | u32::from(address);
    let mut record = [0u8; BM1391_STOCK_FPGA_RETURN_RECORD_LEN];
    record[..4].copy_from_slice(&word0.to_le_bytes());
    record[4..].copy_from_slice(&word1.to_le_bytes());
    record
}

/// Captured-byte replay: an exact-release census of register-0 replies over
/// the stock address ladder (interval 3 for S15 -> 85 addressed slots, 4 for
/// T15 -> 64 slots) decodes address-by-address, and only the release's exact
/// population count is admitted: S15 72, T15 60. Counts never cross-apply.
#[test]
fn captured_register_populations_replay_at_72_and_60() {
    for (driver, expected, interval) in [
        (s15(), BM1391_S15_STOCK_EXPECTED_CHIPS_PER_CHAIN, 3u8),
        (t15(), BM1391_T15_STOCK_EXPECTED_CHIPS_PER_CHAIN, 4u8),
    ] {
        let slots = 256 / u16::from(interval);
        assert_eq!(slots, if interval == 3 { 85 } else { 64 });
        let addresses: Vec<u8> = (0..expected)
            .map(|slot| (u16::from(slot) * u16::from(interval)) as u8)
            .collect();
        assert_eq!(
            u16::from(*addresses.last().unwrap()),
            (u16::from(expected - 1)) * u16::from(interval)
        );

        let mut observed = 0u32;
        for &address in addresses.iter() {
            let record = register_zero_record(address, 0x1d);
            let decoded = decode_bm1391_stock_fpga_return(&record).expect("register record");
            match decoded {
                Bm1391StockFpgaReturn::Register(register) => {
                    assert_eq!(register.register, 0, "chip-address register");
                    assert_eq!(register.chip_address, address);
                    assert_eq!(register.value >> 16, 0x1391, "chip id high word");
                    assert_eq!(register.chain_slot, 0, "one present chain slot");
                    assert_eq!(register.crc5, 0x1d, "crc5 field round-trips");
                    assert!(!register.fpga_crc_error);
                }
                Bm1391StockFpgaReturn::Nonce(_) => panic!("register bit 31 must be clear"),
            }
            observed += 1;
        }
        // The release admits exactly its own stock count and nothing else.
        assert_eq!(driver.admit_stock_response_count(observed), Ok(()));
        let wrong: u32 = if expected == 72 { 60 } else { 72 };
        assert!(driver.admit_stock_response_count(wrong).is_err());
        // Partial-init populations never pass.
        assert!(driver.admit_stock_response_count(observed - 1).is_err());
        // Addressed slots exceed the chip population (the ladder covers more
        // slots than actual chips; matching stock integer division).
        assert!(u32::from(expected) < u32::from(slots));
    }
    // The two release counts are byte-distinct facts (S15 72 vs T15 60).
    assert_eq!(s15().stock_expected_chips(), 72);
    assert_eq!(t15().stock_expected_chips(), 60);
}

// ---------------------------------------------------------------------------
// Positive: per-board PIC/APW8 resolution (never one global geometry)
// ---------------------------------------------------------------------------

#[test]
fn per_board_pic_selector_and_apw8_voltage_callsites_stay_release_exact() {
    // T15-only conditional PIC swap (chain 1<->2 at stock route state 0x0100);
    // S15 compiles the predicate to constant false.
    assert_eq!(s15().pic_selector(1, 0x0100), 0x21);
    assert_eq!(s15().pic_selector(2, 0x0100), 0x22);
    assert_eq!(t15().pic_selector(1, 0), 0x21);
    assert_eq!(t15().pic_selector(1, 0x0100), 0x22);
    assert_eq!(t15().pic_selector(2, 0x0100), 0x21);
    // Per-board APW8 set_iic_power_by_voltage receipts (file offsets differ
    // per release: S15 0x7257c, T15 0x72544; same 0x158 size).
    assert_eq!(s15().apw8_voltage_callsite(), ("S15", 0x7257c, 0x158));
    assert_eq!(t15().apw8_voltage_callsite(), ("T15", 0x72544, 0x158));
    // Factory tokens and stock tuning envelope.
    assert_eq!(s15().factory_voltage_token_mv(), 16_500);
    assert_eq!(t15().factory_voltage_token_mv(), 18_500);
    assert_eq!(Bm1391Driver::apw8_stock_envelope_mv(), (16_030, 20_280));
    // DAC law is the single-source SSOT conversion.
    assert_eq!(Bm1391Driver::apw8_dac_code(20.0), 17);
    // Stock MiscCtrl rate-code transform preserves non-0x1f00 bits. The
    // cached stock file default 0x3a01 carries the cold code 0x1a in bits
    // 12:8 ((0x3a01 >> 8) & 0x1f == 0x1a); clearing those five bits leaves
    // exactly 0x2001 (0x3a01 & !0x1f00, hand-recomputed).
    assert_eq!((0x3a01 >> 8) & 0x1f, 0x1a);
    assert_eq!(misc_ctrl_baud_word(0x3a01, 0), 0x2001);
    assert_eq!(misc_ctrl_baud_word(0x0000_0000, 0x1a), 0x1a00);
    // GPIO907 stock software intent only (physical load unproved).
    use dcentrald_common::bm1391_carrier_profile::Bm1391Gpio907StockIntent;
    assert_eq!(
        Bm1391Driver::gpio907_stock_level(Bm1391Gpio907StockIntent::PowerOn),
        0
    );
    assert_eq!(
        Bm1391Driver::gpio907_stock_level(Bm1391Gpio907StockIntent::PowerOff),
        1
    );
}

// ---------------------------------------------------------------------------
// Positive: work TX — stock job packet -> FPGA publication plan
// ---------------------------------------------------------------------------

/// Build one stock-format job packet (`bm1391_stock_work` 0x52 frame) whose
/// coinbase/merkle pair reproduces the oracle header's merkle root, so the
/// published TX and the RX share check describe the same work.
fn stock_job_frame(header: &BlockHeader, coinbase: &[u8], branch: &[u8; 32]) -> Vec<u8> {
    let mut data = vec![0u8; 0x58];
    data[0] = BM1391_STOCK_JOB_TYPE;
    // Validator contract: declared total = body_len(+0x04) + 8 == frame
    // length INCLUDING the trailing 2-byte CRC-16.
    let total = (0x58usize + coinbase.len() + branch.len() + BM1391_STOCK_JOB_CRC_LEN) as u32;
    data[0x04..0x08].copy_from_slice(&(total - 8).to_le_bytes());
    data[0x08] = 0xa5; // opaque byte (copied by producer, ignored by publisher)
    data[0x09] = BM1391_STOCK_TICKET_UPDATE_FLAG;
    data[0x0a] = 0x0f; // ticket byte (register 0x8c path)
    data[0x0c..0x10].copy_from_slice(&7u32.to_le_bytes()); // job id
    data[0x10..0x14].copy_from_slice(&header.version.to_le_bytes());
    data[0x14..0x34].copy_from_slice(&header.prev_hash);
    data[0x34..0x38].copy_from_slice(&header.timestamp.to_le_bytes());
    data[0x38..0x3c].copy_from_slice(&header.nbits.to_le_bytes());
    data[0x3c..0x3e].copy_from_slice(&(coinbase.len() as u16).to_le_bytes());
    data[0x3e..0x40].copy_from_slice(&0u16.to_le_bytes()); // nonce2 offset
    data[0x40] = 4; // nonce2 size
    data[0x42..0x44].copy_from_slice(&1u16.to_le_bytes()); // one merkle branch
    data[0x48..0x50].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
    data[0x50] = 0; // multiversion disabled
    data[0x54..0x58].copy_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(coinbase);
    data.extend_from_slice(branch);
    let crc = dcentrald_common::bm1391_stock_work::bm1391_stock_job_crc16(&data);
    data.extend_from_slice(&crc.to_le_bytes());
    data
}

fn oracle_header() -> BlockHeader {
    let coinbase = b"r04-oracle-coinbase-payload".to_vec();
    let coinbase_hash = double_sha256(&coinbase);
    let branch = [0xa5u8; 32];
    BlockHeader {
        version: 0x2000_0000,
        prev_hash: [0x11; 32],
        merkle_root: merkle_root(&coinbase_hash, &[branch]),
        timestamp: 0x5f00_6f4d,
        // Loose target: hits every ~200 nonces -> fast deterministic search.
        nbits: 0x2030_0000,
        nonce: 0,
    }
}

/// Marker tags so the collected write list can distinguish the three
/// read-modify-write DHASH/controller steps from plain register writes.
fn dhash_marker(preserve_mask: u32) -> u32 {
    if preserve_mask == BM1391_STOCK_SINGLE_CONTROL_PRESERVE {
        BM1391_STOCK_SINGLE_CONTROL_PRESERVE
    } else {
        preserve_mask & 0x7fff_ffff
    }
}

#[test]
fn work_tx_plan_replays_the_stock_publication_spine() {
    let coinbase = b"r04-oracle-coinbase-payload".to_vec();
    let branch = [0xa5u8; 32];
    let header = oracle_header();
    // The TX-side payload and the RX-side header share one merkle root (the
    // FPGA folds the coinbase hash with the branch exactly as the oracle).
    let coinbase_hash = double_sha256(&coinbase);
    assert!(header.header_merkle_matches(&coinbase_hash, &[branch]));

    let frame = stock_job_frame(&header, &coinbase, &branch);
    let job = decode_bm1391_stock_job_packet(WorkRelease::S15_1_92992_0_14, &frame)
        .expect("well-formed stock job packet");
    assert_eq!(job.job_id, 7);
    assert_eq!(job.version, header.version);
    assert_eq!(job.ntime, header.timestamp);
    assert_eq!(job.nbits, header.nbits);
    assert_eq!(job.previous_hash, header.prev_hash);
    assert_eq!(job.coinbase, coinbase.as_slice());
    assert_eq!(job.merkle_branches.len(), BM1391_STOCK_MERKLE_BRANCH_LEN);

    let plan = plan_bm1391_stock_job_publication(
        &job,
        Bm1391StockPlannerInput {
            buffer: Bm1391StockJobBuffer::A,
            observed_mem_total_kib: 500_000,
            fpga_memory_physical_base: 0x1f00_0000,
            timeout_base: 0x5000,
            first_job: true,
            runtime_multiversion_enabled: false,
        },
    )
    .expect("publication plan");
    assert!(plan.padded_coinbase_len > coinbase.len());

    // DDR writes come first (padded coinbase, then merkle branches).
    let mut ddr = 0usize;
    for step in &plan.ordered_steps {
        if let Bm1391StockPublicationStep::WriteDdrAndRequireExactReadback {
            buffer_offset,
            physical_address,
            bytes,
        } = step
        {
            ddr += 1;
            if ddr == 1 {
                assert_eq!(*buffer_offset, BM1391_STOCK_JOB_BUFFER_A_OFFSET);
                assert_eq!(
                    *physical_address,
                    0x1f00_0000 + BM1391_STOCK_JOB_BUFFER_A_OFFSET
                );
                assert!(bytes.starts_with(&coinbase), "padded coinbase first");
            } else {
                assert_eq!(ddr, 2, "exactly two DDR writes (coinbase, branches)");
                assert_eq!(bytes, &branch.to_vec(), "merkle branch second");
                let padded = u32::try_from(plan.padded_coinbase_len).unwrap();
                assert_eq!(*buffer_offset, BM1391_STOCK_JOB_BUFFER_A_OFFSET + padded);
            }
        }
    }
    assert_eq!(ddr, 2);

    // Collect the remaining ordered steps into a comparable list.
    let mut writes: Vec<(u32, u32)> = Vec::new();
    for step in &plan.ordered_steps {
        match step {
            Bm1391StockPublicationStep::Write(write) => writes.push((write.offset, write.value)),
            Bm1391StockPublicationStep::ReadModifyWriteDhashWithStockRetry {
                preserve_mask,
                set_mask,
                ..
            } => writes.push((dhash_marker(*preserve_mask), *set_mask)),
            Bm1391StockPublicationStep::ReadModifyWriteSet { offset, set_mask } => {
                writes.push((offset | 0x8000_0000, *set_mask))
            }
            Bm1391StockPublicationStep::RequireDhashBitClear { mask, max_polls, .. } => {
                assert_eq!((*mask, *max_polls), (BM1391_STOCK_DHASH_RUN_BIT, 10));
            }
            Bm1391StockPublicationStep::DelayMs(ms) => assert_eq!(*ms, 1),
            Bm1391StockPublicationStep::WriteDdrAndRequireExactReadback { .. } => {}
        }
    }

    // Step order: DHASH run-bit clear RMW, then the scalar spine head
    // (job start, ticket, job id, version), the eight previous-hash words,
    // the scalar tail, first-job FIFO enable + DHASH bit 7, the enabled
    // timeout, and the final single-version control RMW.
    assert_eq!(
        writes[0].0,
        dhash_marker(!BM1391_STOCK_DHASH_RUN_BIT),
        "first RMW clears the DHASH run bit"
    );
    assert_eq!(writes[0].1, 0, "clear RMW sets no bits");
    assert_eq!(writes[1].0, 0x118, "job start register");
    assert_eq!(writes[1].1, 0x1f00_0000 + BM1391_STOCK_JOB_BUFFER_A_OFFSET);
    assert_eq!(writes[2], (0x8c, 0x0fu32), "ticket update flag present");
    assert_eq!(writes[3], (0x124, 7), "job id");
    assert_eq!(writes[4], (0x130, header.version), "base version lane only");
    for (index, word) in
        dcentrald_common::bm1391_stock_work::bm1391_stock_previous_hash_words(&header.prev_hash)
            .into_iter()
            .enumerate()
    {
        assert_eq!(writes[5 + index], (0x140 + index as u32 * 4, word));
    }
    let base = 5 + 8;
    let padded_blocks = (plan.padded_coinbase_len / 64) as u32;
    assert_eq!(writes[base], (0x134, header.timestamp));
    assert_eq!(writes[base + 1], (0x138, header.nbits));
    assert_eq!(
        writes[base + 2],
        (0x104, (0u32 << 16) | (4 << 8) | padded_blocks)
    );
    assert_eq!(writes[base + 3], (0x108, 0x0506_0708), "nonce2 low");
    assert_eq!(writes[base + 4], (0x10c, 0x0102_0304), "nonce2 high");
    assert_eq!(writes[base + 5], (0x114, 1), "merkle count");
    let payload_len = plan.padded_coinbase_len + branch.len();
    assert_eq!(writes[base + 6], (0x11c, payload_len as u32), "job length");
    // First-job nonce FIFO enable, then DHASH bit 7, then the enabled
    // timeout, then the final single-version control RMW.
    let fifo = &writes[base + 7];
    assert_eq!(
        (fifo.0 & 0x7fff_ffff, fifo.1),
        (0x1c, BM1391_STOCK_FIRST_NONCE_FIFO_ENABLE)
    );
    assert_eq!(
        writes[base + 8],
        (dhash_marker(u32::MAX), BM1391_STOCK_DHASH_BIT7),
        "first-job DHASH bit-7 RMW"
    );
    let timeout = &writes[base + 9];
    assert_eq!(timeout.0, 0x88);
    assert_eq!(timeout.1, BM1391_STOCK_TIMEOUT_ENABLE | 0x5000);
    assert_eq!(timeout.1 & BM1391_STOCK_TIMEOUT_MASK, 0x5000);
    let final_control = writes.last().unwrap();
    assert_eq!(
        final_control.0, BM1391_STOCK_SINGLE_CONTROL_PRESERVE,
        "final RMW carries the single-version preserve mask"
    );
    assert_eq!(final_control.1, BM1391_STOCK_SINGLE_CONTROL_WORD);
    assert_eq!(BM1391_STOCK_SINGLE_CONTROL_WORD, 0x8160);
    assert_eq!(BM1391_STOCK_DHASH_BIT7, 0x80);
}

// ---------------------------------------------------------------------------
// Positive: nonce RX -> outstanding binding -> header reconstruct -> oracle
// ---------------------------------------------------------------------------

fn outstanding_snapshot(
    job_id: u32,
    version: u32,
    nonce2: u64,
) -> [u8; BM1391_STOCK_OUTSTANDING_WORK_RECORD_LEN] {
    let mut outstanding = [0u8; BM1391_STOCK_OUTSTANDING_WORK_RECORD_LEN];
    outstanding[0x00..0x04].copy_from_slice(&job_id.to_le_bytes());
    // Stock consumer-record layout via the 60-byte queue bytes: version from
    // outstanding word 0x04 (stored byte-swapped), nonce2 halves from words
    // 0x0c/0x10, nonce3 from the bound record, chain slot from word 0x18.
    outstanding[0x04..0x08].copy_from_slice(&version.swap_bytes().to_le_bytes());
    outstanding[0x08..0x0c].copy_from_slice(&(nonce2 as u32).to_le_bytes());
    outstanding[0x0c..0x10].copy_from_slice(&((nonce2 >> 32) as u32).to_le_bytes());
    for (index, byte) in outstanding[0x20..0x40].iter_mut().enumerate() {
        *byte = index as u8;
    }
    outstanding
}

/// Decode a two-word return record, bind it to the 64-byte outstanding-work
/// snapshot, rebuild the 80-byte header around the returned nonce, and require
/// the INDEPENDENT oracle to agree: the hit nonce meets the compact target and
/// the miss nonce does not. The stock record stores the nonce byte-swapped;
/// Bitcoin and Stratum name the same nonce as a LE integer (the runtime
/// qualification does `found.nonce.swap_bytes()` before the header rebuild).
#[test]
fn nonce_rx_decode_header_reconstruct_and_oracle_share_target() {
    let header = oracle_header();
    let target_be = compact_target(header.nbits).expect("compact target decodes");
    // Hit and miss nonces searched independently by the oracle.
    let hit_nonce = (0u32..1 << 17)
        .find(|n| header.with_nonce(*n).meets_target())
        .expect("loose target yields a hit");
    let miss_nonce = (hit_nonce + 1..1 << 17)
        .find(|n| !header.with_nonce(*n).meets_target())
        .expect("adjacent nonce misses");

    for (nonce, expect_hit) in [(hit_nonce, true), (miss_nonce, false)] {
        // Stock record: word0 = nonce|valid|chain 0, work id 9;
        // word1 = byte-swapped nonce (the stock SHA helper consumes it as BE).
        let word0: u32 = (1 << 31) | (9 << 16) | 0x80;
        let word1: u32 = nonce.swap_bytes();
        let raw = [word0, word1];
        let decoded = s15().decode_nonce(&raw).expect("stock-valid nonce");
        assert_eq!(decoded.nonce, word1, "raw stock word passes through");
        assert_eq!(decoded.work_id, 9);
        assert_eq!(decoded.chip_index, u8::MAX, "record carries no chip field");

        // Bitcoin nonce recovered exactly as the production runtime does.
        let bitcoin_nonce = decoded.nonce.swap_bytes();
        assert_eq!(bitcoin_nonce, nonce);

        // Header reconstruct + oracle share check.
        let rebuilt = header.with_nonce(bitcoin_nonce);
        assert_eq!(rebuilt.to_wire()[76..80], nonce.to_le_bytes());
        assert_eq!(rebuilt.meets_target(), expect_hit);

        // Decode the same record through the 8-byte codec and bind it to the
        // 64-byte outstanding-work snapshot (exact 60-byte consumer record).
        let mut record = [0u8; 8];
        record[..4].copy_from_slice(&word0.to_le_bytes());
        record[4..].copy_from_slice(&word1.to_le_bytes());
        let nonce_return = match decode_bm1391_stock_fpga_return(&record).expect("decode") {
            Bm1391StockFpgaReturn::Nonce(nonce) => nonce,
            Bm1391StockFpgaReturn::Register(_) => panic!("nonce bit set"),
        };
        let outstanding = outstanding_snapshot(7, header.version, 0x0102_0304_0506_0708);
        let bound = bind_bm1391_stock_nonce(nonce_return, true, &outstanding)
            .expect("stock-eligible bind");
        // The global nonce-path enable is a caller-owned runtime state bit;
        // with it clear stock would not bind even a stock-valid record.
        assert!(matches!(
            bind_bm1391_stock_nonce(nonce_return, false, &outstanding),
            Err(Bm1391StockWorkBindError::NonceNotStockEligible)
        ));
        let consumer = bound.stock_consumer_record().expect("consumer record");
        assert_eq!(consumer.job_id, 7);
        assert_eq!(consumer.work_id, 9);
        assert_eq!(consumer.version, header.version);
        assert_eq!(consumer.nonce2, 0x0102_0304_0506_0708);
        assert_eq!(consumer.nonce3, word1);
        assert_eq!(consumer.chain_slot, 0);

        // RX dequeue happens before any duplicate/stale gate.
        let pop = pop_bm1391_stock_consumer_ring(Bm1391StockConsumerRingState {
            read_index: 0,
            queued: 1,
        })
        .expect("pop");
        assert_eq!(pop.popped_index, 0);

        // Duplicate/stale gate: fresh work id at job age zero -> Current.
        let step = bm1391_stock_pre_hash_step(
            consumer,
            Bm1391StockDuplicateKey { nonce3: 0, work_id: 0 },
            7,
            false,
        );
        assert_eq!(
            step.disposition,
            Bm1391StockPreHashDisposition::Snapshot(Bm1391StockSnapshotAge::Current)
        );

        // Digest from the saved midstate/tail snapshot vs the ORACLE. The
        // stock snapshot pending words are the header's last FOUR wire words,
        // each big-endian-read: merkle[28..32], ntime, nbits (snapshot tail
        // +0x40..+0x4c) and the returned nonce (device +0xec). Genesis-pinned
        // AND hashlib-cross-checked: the module replay hashes the REAL
        // genesis header to the REAL genesis hash with exactly this encoding
        // (evidence/r04/SOURCE_NOTE.md adjudication, 2026-09-11).
        let midstate = header.midstate();
        let wire = rebuilt.to_wire();
        let be_word =
            |offset: usize| u32::from_be_bytes(wire[offset..offset + 4].try_into().unwrap());
        let digest = bm1391_stock_double_sha256_from_midstate(Bm1391StockPrecomputedHashInput {
            midstate_words: digest_to_words(&midstate),
            tail_words: [be_word(64), be_word(68), be_word(72)],
            nonce3: be_word(76),
        });
        assert_eq!(
            digest,
            digest_to_words(&rebuilt.block_hash_internal()),
            "stock midstate replay equals the independent oracle digest"
        );

        // Full eight-word target comparison agrees with the oracle for both
        // the hit and the miss. The compare runs on the STOCK WORK-OBJECT
        // words: each digest word is the SHA state word byte-reversed
        // ("stock's final per-word byte reversal" at +0xc0..+0xdc), and the
        // target (+0xa0..+0xbc) is stored limb-reversed so word 7 is the
        // most-significant limb in true display byte order. Python hashlib
        // cross-check: this convention reproduces the oracle decision for
        // both the hit and the miss; the unswapped words do not.
        let digest_storage: [u32; 8] = std::array::from_fn(|i| digest[i].swap_bytes());
        let target_words: [u32; 8] = std::array::from_fn(|i| {
            u32::from_be_bytes(target_be[28 - i * 4..32 - i * 4].try_into().unwrap())
        });
        assert_eq!(
            bm1391_stock_full_target_passes(digest_storage, target_words),
            expect_hit
        );
        assert_eq!(rebuilt.meets_target(), expect_hit);

        // Stock submit wrapper (FUN_000223f0 replay): digest word 7 at +0xdc
        // is the difficulty>=1 precheck — DIFF1 = 0x00000000ffff…, so every
        // legitimate share has display[0:4] == 0 and word 7 == 0. This
        // fixture's target (0x20300000, ~2^-29.6) sits BELOW the Bitcoin
        // share floor, so its digest word 7 is nonzero and stock correctly
        // short-circuits the wrapper as a hardware error BEFORE any target
        // compare (Python adjudication: SOURCE_NOTE.md §12 round 2).
        assert_ne!(
            digest[7], 0,
            "below-diff-1 digest must fail the +0xdc word-7 gate"
        );
        let plan = bm1391_stock_submit_wrapper_plan(Bm1391StockSubmitWrapperInput {
            previous_device_nonce: word1.wrapping_sub(1),
            returned_nonce: word1,
            digest_words: digest,
            target_words,
            bench_diagnostic_enabled: false,
        });
        assert!(
            !plan.wrapper_returns_one,
            "below-diff-1 digest short-circuits as a hardware error"
        );
        assert_eq!(plan.full_target_passed, None);
        assert!(!plan.async_submission_would_be_invoked);
        assert!(!plan.admits_pool_acceptance_authority());
    }
}

// ---------------------------------------------------------------------------
// Stock +0xdc word-7 gate (difficulty>=1 precheck) and the full wrapper path
// on a REAL >=diff-1 digest (genesis, oracle-anchored)
// ---------------------------------------------------------------------------

/// The real 80-byte Bitcoin genesis header (version 1, zero prev-hash,
/// merkle 3ba3edfd…4b1e5e4a, ntime 0x495fab29, nbits 0x1d00ffff, nonce
/// 0x7c2bac1d). Its digest is a genuine >=difficulty-1 hash.
fn genesis_wire() -> [u8; 80] {
    let mut wire = [0u8; 80];
    wire[0..4].copy_from_slice(&1u32.to_le_bytes());
    wire[36..68].copy_from_slice(&[
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f,
        0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e,
        0x5e, 0x4a,
    ]);
    wire[68..72].copy_from_slice(&0x495f_ab29u32.to_le_bytes());
    wire[72..76].copy_from_slice(&0x1d00_ffffu32.to_le_bytes());
    wire[76..80].copy_from_slice(&0x7c2b_ac1du32.to_le_bytes());
    wire
}

/// Digest word 7 at +0xdc is the stock difficulty>=1 precheck: it holds
/// internal digest bytes [28..32] — the four most-significant DISPLAY bytes —
/// so `word 7 == 0` is exactly `display[0:4] == 0`, the DIFF1
/// (0x00000000ffff…) share floor; candidates below it are ASIC hardware
/// errors. On a real >=diff-1 digest (genesis) the wrapper commits the nonce,
/// runs the full eight-word compare, and invokes the async path on a pass.
/// Verified against hashlib on the real genesis header
/// (evidence/r04/SOURCE_NOTE.md §12, round 2).
#[test]
fn wrapper_dc_gate_and_full_path_on_a_real_share_digest() {
    let genesis = BlockHeader::from_wire(&genesis_wire()).expect("genesis header");
    let gwire = genesis.to_wire();
    let gbe = |offset: usize| u32::from_be_bytes(gwire[offset..offset + 4].try_into().unwrap());
    let genesis_digest = bm1391_stock_double_sha256_from_midstate(Bm1391StockPrecomputedHashInput {
        midstate_words: digest_to_words(&genesis.midstate()),
        tail_words: [gbe(64), gbe(68), gbe(72)],
        nonce3: gbe(76),
    });
    assert_eq!(
        genesis_digest,
        digest_to_words(&genesis.block_hash_internal()),
        "genesis midstate replay equals the independent oracle digest"
    );
    assert_eq!(
        genesis_digest[7], 0,
        "+0xdc word 7 is zero exactly for a >=diff-1 digest"
    );
    assert!(display_hash_meets_target(&genesis.display_hash(), &DIFF1_TARGET));

    let genesis_storage: [u32; 8] = std::array::from_fn(|i| genesis_digest[i].swap_bytes());
    let diff1_words: [u32; 8] = std::array::from_fn(|i| {
        u32::from_be_bytes(DIFF1_TARGET[28 - i * 4..32 - i * 4].try_into().unwrap())
    });
    assert!(bm1391_stock_full_target_passes(genesis_storage, diff1_words));
    let pass = bm1391_stock_submit_wrapper_plan(Bm1391StockSubmitWrapperInput {
        previous_device_nonce: gbe(76).wrapping_sub(1),
        returned_nonce: gbe(76),
        digest_words: genesis_storage,
        target_words: diff1_words,
        bench_diagnostic_enabled: false,
    });
    assert!(pass.wrapper_returns_one, ">=diff-1 digest returns one");
    assert_eq!(pass.full_target_passed, Some(true));
    assert!(pass.async_submission_would_be_invoked);

    // A >=diff-1 digest that misses a harder target (DIFF1 >> 84) still
    // commits, compares, and returns one — just without the async path.
    let harder = target_from_difficulty_pow2(84);
    let harder_words: [u32; 8] =
        std::array::from_fn(|i| u32::from_be_bytes(harder[28 - i * 4..32 - i * 4].try_into().unwrap()));
    assert!(!bm1391_stock_full_target_passes(genesis_storage, harder_words));
    assert!(display_hash_meets_target(&genesis.display_hash(), &DIFF1_TARGET));
    let miss = bm1391_stock_submit_wrapper_plan(Bm1391StockSubmitWrapperInput {
        previous_device_nonce: gbe(76).wrapping_sub(1),
        returned_nonce: gbe(76),
        digest_words: genesis_storage,
        target_words: harder_words,
        bench_diagnostic_enabled: false,
    });
    assert!(miss.wrapper_returns_one);
    assert_eq!(miss.full_target_passed, Some(false));
    assert!(!miss.async_submission_would_be_invoked);
    assert!(!miss.admits_pool_acceptance_authority());
}

// ---------------------------------------------------------------------------
// Faults: timeout, partial init, malformed records, stale, duplicate, cancel
// ---------------------------------------------------------------------------

#[test]
fn timeout_partial_init_and_malformed_frames_fail_closed() {
    let coinbase = b"r04-oracle-coinbase-payload".to_vec();
    let branch = [0xa5u8; 32];
    let header = oracle_header();
    let frame = stock_job_frame(&header, &coinbase, &branch);
    let job =
        decode_bm1391_stock_job_packet(WorkRelease::T15_1_92992_0_13, &frame).expect("decode");

    // Timeout overflow: 0x20000 * 1 exceeds the 17-bit stock mask.
    assert_eq!(
        plan_bm1391_stock_job_publication(
            &job,
            Bm1391StockPlannerInput {
                buffer: Bm1391StockJobBuffer::A,
                observed_mem_total_kib: 500_000,
                fpga_memory_physical_base: 0x1f00_0000,
                timeout_base: 0x2_0000,
                first_job: false,
                runtime_multiversion_enabled: false,
            },
        ),
        Err(Bm1391StockJobPlanError::TimeoutOverflow {
            base: 0x2_0000,
            multiplier: 1,
        })
    );
    // Wrong-geometry memory base (memtotal disagrees with the physical base).
    assert!(matches!(
        plan_bm1391_stock_job_publication(
            &job,
            Bm1391StockPlannerInput {
                buffer: Bm1391StockJobBuffer::A,
                observed_mem_total_kib: 500_000,
                fpga_memory_physical_base: 0x0f00_0000,
                timeout_base: 0x5000,
                first_job: false,
                runtime_multiversion_enabled: false,
            },
        ),
        Err(Bm1391StockJobPlanError::PhysicalBaseMemTotalMismatch { .. })
    ));
    // Multiversion mode mismatch refuses the silent two-version lane.
    assert!(matches!(
        plan_bm1391_stock_job_publication(
            &job,
            Bm1391StockPlannerInput {
                buffer: Bm1391StockJobBuffer::A,
                observed_mem_total_kib: 500_000,
                fpga_memory_physical_base: 0x1f00_0000,
                timeout_base: 0x5000,
                first_job: false,
                runtime_multiversion_enabled: true,
            },
        ),
        Err(Bm1391StockJobPlanError::MultiversionModeMismatch)
    ));

    // Malformed record: wrong length refuses the partial RX frame.
    assert!(matches!(
        decode_bm1391_stock_fpga_return(&[0u8; 7]),
        Err(Bm1391StockReturnDecodeError::WrongLength { observed: 7 })
    ));

    // CRC-error register reply (word0 bit 6): stock never queues it.
    let mut record = register_zero_record(0, 0);
    record[0] |= 1 << 6; // word0 bit 6 = BM1391_STOCK_REGISTER_CRC_ERROR_BIT
    match decode_bm1391_stock_fpga_return(&record).expect("decode") {
        Bm1391StockFpgaReturn::Register(register) => {
            assert!(register.fpga_crc_error);
            assert!(!register.stock_queue_eligible(false), "CRC error never queues");
        }
        Bm1391StockFpgaReturn::Nonce(_) => panic!("register record"),
    }

    // Nonce record without the stock valid bit: never bound.
    let invalid_word0: u32 = (1 << 31) | (9 << 16);
    let mut invalid_record = [0u8; 8];
    invalid_record[..4].copy_from_slice(&invalid_word0.to_le_bytes());
    match decode_bm1391_stock_fpga_return(&invalid_record).expect("decode") {
        Bm1391StockFpgaReturn::Nonce(nonce) => {
            assert!(!nonce.stock_binding_eligible(true));
            assert!(matches!(
                bind_bm1391_stock_nonce(nonce, true, &[0u8; 0x40]),
                Err(Bm1391StockWorkBindError::NonceNotStockEligible)
            ));
        }
        Bm1391StockFpgaReturn::Register(_) => panic!("nonce record"),
    }

    // Partial-init frequency index vectors are refused per release.
    assert!(s15().validate_frequency_indices(Some(&[0u8; 71])).is_err());
    assert!(t15().validate_frequency_indices(Some(&[0u8; 59])).is_err());
    assert!(s15().validate_frequency_indices(None).is_err());
}

#[test]
fn stale_duplicate_and_backpressure_paths_fail_closed() {
    // Stale return: job id moved three ahead -> outside the three-snapshot
    // window, and stock still commits the duplicate key first.
    let record = decode_bm1391_stock_consumer_record(&{
        let mut bytes = [0u8; 60];
        bytes[0x00..0x04].copy_from_slice(&7u32.to_le_bytes());
        bytes[0x04..0x08].copy_from_slice(&9u32.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&0x1234u32.to_le_bytes());
        bytes[0x18..0x1c].copy_from_slice(&0u32.to_le_bytes());
        bytes
    })
    .expect("record");
    let step = bm1391_stock_pre_hash_step(
        record,
        Bm1391StockDuplicateKey { nonce3: 0, work_id: 0 },
        10,
        true,
    );
    assert!(matches!(
        step.disposition,
        Bm1391StockPreHashDisposition::Stale {
            wrapping_age: 3,
            account_hardware_error: true
        }
    ));
    assert_eq!(
        step.next_duplicate_key,
        Bm1391StockDuplicateKey {
            nonce3: 0x1234,
            work_id: 9,
        }
    );

    // Immediate duplicate: suppressed before hashing.
    let dup = bm1391_stock_pre_hash_step(record, step.next_duplicate_key, 10, true);
    assert!(matches!(
        dup.disposition,
        Bm1391StockPreHashDisposition::Duplicate {
            account_hardware_error: true
        }
    ));

    // Stale submits are discarded unless stale submission is requested.
    let stale = bm1391_stock_async_submission_plan(Bm1391StockAsyncSubmissionInput {
        benchmark_mode: false,
        stale: true,
        submit_stale_enabled: false,
        pool_requests_stale: false,
        stratum_work: true,
        stratum_queue_present: true,
        stratum_queue_push_succeeds: true,
        non_stratum_thread_create_succeeds: true,
    });
    assert!(matches!(
        stale.outcome,
        Bm1391StockAsyncSubmissionOutcome::DiscardedStale
    ));
    assert!(!stale.proves_network_delivery());

    // Repeat of the device's immediately preceding nonce: hardware error,
    // wrapper returns zero (timeout/cancel-class discard).
    let plan = bm1391_stock_submit_wrapper_plan(Bm1391StockSubmitWrapperInput {
        previous_device_nonce: 42,
        returned_nonce: 42,
        digest_words: [0; 8],
        target_words: [0; 8],
        bench_diagnostic_enabled: false,
    });
    assert!(!plan.wrapper_returns_one);
    assert_eq!(plan.full_target_passed, None);
    assert!(!plan.async_submission_would_be_invoked);

    // RX ring backpressure: a full 511-entry ring refuses before overwrite
    // (queue cancellation/backpressure shape), and an empty consumer ring
    // refuses to pop.
    let mut ring = Bm1391StockRingState {
        write_index: 0,
        queued: 0,
    };
    for _ in 0..510 {
        ring = advance_bm1391_stock_ring(ring).expect("advance");
    }
    ring = advance_bm1391_stock_ring(ring).expect("advance to full");
    assert!(matches!(
        advance_bm1391_stock_ring(ring),
        Err(Bm1391StockRingError::Full)
    ));
    assert!(matches!(
        pop_bm1391_stock_consumer_ring(Bm1391StockConsumerRingState {
            read_index: 0,
            queued: 0,
        }),
        Err(dcentrald_common::Bm1391StockConsumerRingError::Empty)
    ));

    // Difficulty normalization refuses out-of-domain pool values.
    assert!(bm1391_stock_normalize_share_difficulty(f64::NAN).is_err());
    assert!(bm1391_stock_normalize_share_difficulty(-1.0).is_err());
}

// ---------------------------------------------------------------------------
// Wrong-board refusal: S15 profile vs T15 evidence never cross-applies
// ---------------------------------------------------------------------------

fn exact_observation(release: Bm1391StockRelease) -> Bm1391StockReleaseObservation<'static> {
    let (package_sha256, package_size, version_number, cgminer_sha256, baked_pattern_path) =
        match release {
            Bm1391StockRelease::S15December2019 => (
                dcentrald_common::bm1391_carrier_profile::BM1391_S15_PACKAGE_SHA256,
                dcentrald_common::bm1391_carrier_profile::BM1391_S15_PACKAGE_SIZE,
                dcentrald_common::bm1391_carrier_profile::BM1391_S15_VERSION_NUMBER,
                BM1391_S15_CGMINER_SHA256,
                BM1391_S15_BAKED_PATTERN_PATH,
            ),
            Bm1391StockRelease::T15December2019 => (
                dcentrald_common::bm1391_carrier_profile::BM1391_T15_PACKAGE_SHA256,
                dcentrald_common::bm1391_carrier_profile::BM1391_T15_PACKAGE_SIZE,
                dcentrald_common::bm1391_carrier_profile::BM1391_T15_VERSION_NUMBER,
                BM1391_T15_CGMINER_SHA256,
                BM1391_T15_BAKED_PATTERN_PATH,
            ),
        };
    Bm1391StockReleaseObservation {
        package_sha256,
        package_size,
        version_number,
        cgminer_sha256,
        cgminer_size: 691_180,
        baked_pattern_path,
        boot_bin_sha256: dcentrald_common::bm1391_carrier_profile::BM1391_SHARED_BOOT_BIN_SHA256,
        boot_bin_size: dcentrald_common::bm1391_carrier_profile::BM1391_SHARED_BOOT_BIN_SIZE,
        uimage_sha256: dcentrald_common::bm1391_carrier_profile::BM1391_SHARED_UIMAGE_SHA256,
        uimage_size: dcentrald_common::bm1391_carrier_profile::BM1391_SHARED_UIMAGE_SIZE,
        axi_module_sha256: dcentrald_common::bm1391_carrier_profile::BM1391_AXI_MODULE_SHA256,
        axi_module_size: dcentrald_common::bm1391_carrier_profile::BM1391_AXI_MODULE_SIZE,
        fpga_mem_module_sha256: dcentrald_common::bm1391_carrier_profile::BM1391_FPGA_MEM_MODULE_SHA256,
        fpga_mem_module_size: dcentrald_common::bm1391_carrier_profile::BM1391_FPGA_MEM_MODULE_SIZE,
        module_vermagic: dcentrald_common::bm1391_carrier_profile::BM1391_STOCK_MODULE_VERMAGIC,
    }
}

#[test]
fn wrong_board_evidence_never_cross_applies() {
    // Each exact release tuple matches itself only.
    assert!(
        match_bm1391_exact_stock_release(exact_observation(
            Bm1391StockRelease::S15December2019
        ))
        .is_ok()
    );
    assert!(
        match_bm1391_exact_stock_release(exact_observation(
            Bm1391StockRelease::T15December2019
        ))
        .is_ok()
    );
    // A mixed tuple (S15 package claiming the T15 cgminer) fails closed.
    let mut mixed = exact_observation(Bm1391StockRelease::S15December2019);
    mixed.cgminer_sha256 = BM1391_T15_CGMINER_SHA256;
    assert_eq!(
        match_bm1391_exact_stock_release(mixed),
        Err(Bm1391StockReleaseMatchError::CgminerMismatch)
    );
    let mut mixed = exact_observation(Bm1391StockRelease::T15December2019);
    mixed.baked_pattern_path = BM1391_S15_BAKED_PATTERN_PATH;
    assert_eq!(
        match_bm1391_exact_stock_release(mixed),
        Err(Bm1391StockReleaseMatchError::BakedPatternMismatch)
    );

    // Release-scoped admission on the driver: S15 refuses the T15 census and
    // vice versa (F02 R-am1-t15: "distinct population cannot borrow S15").
    assert!(s15().admit_stock_response_count(60).is_err());
    assert!(t15().admit_stock_response_count(72).is_err());

    // Distinct board targets, intervals and factory tokens.
    assert_eq!(s15().board_target(), "am1-s15");
    assert_eq!(t15().board_target(), "am1-t15");
    assert_ne!(s15().address_interval(), t15().address_interval());
    assert_ne!(
        s15().factory_voltage_token_mv(),
        t15().factory_voltage_token_mv()
    );

    // Release evidence never mints hardware authority.
    let evidence =
        match_bm1391_exact_stock_release(exact_observation(
            Bm1391StockRelease::S15December2019,
        ))
        .unwrap();
    assert!(!evidence.admits_board_identity());
    assert!(!evidence.admits_live_carrier());
    assert!(!evidence.admits_voltage_or_rail_control());
    assert!(!evidence.admits_install());
}

// ---------------------------------------------------------------------------
// Deliberate carrier / work-TX / voltage refusals name their owners
// ---------------------------------------------------------------------------

#[test]
fn carrier_work_and_voltage_refusals_name_their_owners() {
    let carrier = Bm1391Driver::carrier_refusal_reason();
    assert!(carrier.contains("stock_bm1391::Transport"), "{carrier}");
    assert!(carrier.contains("FpgaChain"), "{carrier}");
    assert!(carrier.contains("bm1391_mining"), "{carrier}");
    let work = Bm1391Driver::work_tx_refusal_reason();
    assert!(work.contains("publish_work"), "{work}");
    assert!(work.contains("MiningWork"), "{work}");
    assert!(work.contains("plan_bm1391_stock_job_publication"), "{work}");
    assert!(work.contains("WorkDispatcher"), "{work}");
    let voltage = Bm1391Driver::voltage_refusal_owner();
    assert!(voltage.contains("Bm1391RetainedOwner"), "{voltage}");
    assert!(voltage.contains("PicApplication"), "{voltage}");

    // The voltage ownership SSOT refuses Bm1391 before any I/O.
    assert!(
        dcentrald_common::voltage_rail::chip_driver_set_voltage_admission(
            dcentrald_common::board_desc::AsicProtocolIdentity::Bm1391,
        )
        .is_err()
    );

    // Metadata surface stays pinned (identity, record shape, bauds, control).
    assert_eq!(s15().chip_id(), 0x1391);
    assert_eq!(s15().chip_name(), "BM1391");
    assert_eq!(s15().response_length(), 8);
    assert_eq!(s15().default_baud(), 115_200);
    assert_eq!(s15().max_baud(), 3_125_000);
    assert_eq!(
        s15().ctrl_reg_value(),
        0x8080_0000,
        "stock +0xc0 start shape, never 0"
    );
    assert_eq!(s15().cores_per_chip(), 256);
    assert_eq!(Bm1391Driver::apw8_stock_envelope_mv().0, 16_030);
}
