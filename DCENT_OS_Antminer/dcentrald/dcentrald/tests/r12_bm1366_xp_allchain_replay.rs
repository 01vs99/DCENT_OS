// SPDX-License-Identifier: GPL-3.0-or-later
//! R12 BM1366 XP-pair per-bin all-chain session replay (desk-only, no
//! hardware).
//!
//! Campaign `2026-09-07-antminer-beta-execution`, lane R12 (S19 XP / S19j
//! XP, BM1366, am3 Amlogic; findings.md row "S19 XP/j XP BM1366"). For EACH
//! resolved bin — XP 3x110=330 (`am3-s19xp`) and jXP 3x110=330
//! (`am3-s19jxp`) — this replay drives one full three-chain work session
//! through:
//!
//! - the exact per-bin profiles and population admission in
//!   `dcentrald-common::bm1366_xp_board_profiles` (110 exact per populated
//!   chain; partial/off-by-one AND S19k's 77 refuse before any work is
//!   planned);
//! - the per-model measured-PSU dialect law (S19 XP -> APW12 modern
//!   0x75..=0x77, S19j XP -> APW17 modern 0xc1; every other measured
//!   version — including the sibling dialect's — refuses; the pair is
//!   never merged);
//! - the all-chain work distribution planner (every populated chain
//!   receives the work item; unpopulated slots never do);
//! - the staged session composition with mid-init cancellation and stale
//!   epoch refusal (the pure model of the wire owner's terminal
//!   revocation);
//! - the REAL BM1366 driver surface in `dcentrald-asic::drivers::bm1366`
//!   (`ChipDriver::decode_nonce`, job pacing, ticket mask, PLL) — the
//!   existing codec, unmodified;
//! - the INDEPENDENT F04 Bitcoin oracle (`f04_oracle/bitcoin_oracle.rs`,
//!   never modified, never dcentrald hashing code) plus public mainnet
//!   genesis constants.
//!
//! Session shape per bin: admit the exact full unit -> walk the
//! cut-first/reset-second cold-start prefix -> plan one work item onto all
//! three chains -> each mock chain (a host transport stub in the r12 PTY-
//! regression tradition; clearly NOT a recorded wire capture and NOT
//! physical hashing) returns the independently known mainnet genesis nonce
//! in the exact two-word WORK_RX_FIFO shape -> decode through the real
//! driver -> validate against the target with the oracle -> confirm
//! chain-level attribution and assigned-address echo are exact while
//! physical per-chip health attribution stays unproven.
//!
//! Every constant is cited in
//! .
//! This test grants no hardware, energization, dispatch, install, or
//! registration authority. Chip attribution stays unproven where evidence
//! does not settle it: the decoded address field is the ASSIGNMENT echo
//! (codec mechanics), never a measured per-chip identity.

#![forbid(unsafe_code)]

#[path = "f04_oracle/bitcoin_oracle.rs"]
mod bitcoin_oracle;

use bitcoin_oracle::BlockHeader;
use dcentrald_asic::drivers::{bm1366::Bm1366Driver, ChipDriver};
use dcentrald_api_types::deployed_eeprom::decode_deployed_eeprom;
use dcentrald_common::bm1366_serial_platform::{
    bm1366_dispatch_admitted_serial_platform, bm1366_serial_platform_for,
};
use dcentrald_common::bm1366_xp_board_profiles::{
    admit_full_unit_population, admit_unit_population, coverage_complete,
    distribute_work_to_all_chains, distribute_work_to_chain, session_coverage_complete,
    Bm1366XpBoardProfile, Bm1366XpBin, Bm1366XpPsuDialect, Bm1366XpWorkSession, ChainPopulation,
    ChainWorkAssignment, DistributionError, PopulationAdmissionError, PsuDialectError,
    SessionError, SessionWorkReceipt, S19K_EXPECTED_CHIPS_PER_UART, BM1366_XP_ADDRESS_INTERVAL,
};
use dcentrald_common::linear_chip_addresses;
use dcentrald_common::s21_generation_admission::ColdInitStage;
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// Independent anchors (public mainnet block 0; oracle cross-checked in f04,
// genesis byte order re-verified by direct SHA-256 computation at the R14
// round-1 repair: hashing the INTERNAL form reproduces block 0's hash).
// ---------------------------------------------------------------------------
/// Genesis merkle root in the 80-byte header's wire/internal byte order.
/// The familiar DISPLAY hex `4a5e1e4b...fdeda33b` is the byte-REVERSE of
/// this array. Identical literal to the R12 PTY regression's
/// `entry.merkle_root` and R07's `GENESIS_MERKLE`.
const GENESIS_MERKLE_INTERNAL: [u8; 32] = [
    0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
    0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
];
const GENESIS_NONCE: u32 = 2083236893;
const GENESIS_NTIME: u32 = 1231006505;
const GENESIS_NBITS: u32 = 0x1d00_ffff;
const GENESIS_VERSION: u32 = 1;

/// Exact reconstruction of the private full-header UART job codec used by
/// the BM1366 XP native chains (`serial_mining::serial_full_header_work`,
/// read-only at replay time; the r12 PTY regression
/// `bm1366_xp_native_actual_init_work_and_known_nonce_on_xp_and_jxp_ptys`
/// pins the exact TX bytes). 84 bytes: `[0x21, 0x56, job_id, 1]`, nbits LE,
/// ntime LE, merkle (word-order-reversed), previous hash
/// (word-order-reversed), version LE. Input merkle/prevhash are internal
/// byte order, exactly as the PTY regression feeds them.
fn full_header_work_frame(
    job_id: u8,
    version: u32,
    nbits: u32,
    ntime: u32,
    merkle_internal: &[u8; 32],
    previous_internal: &[u8; 32],
) -> Vec<u8> {
    let reverse_32bit_words = |data: &[u8; 32]| -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&data[(7 - i) * 4..(7 - i + 1) * 4]);
        }
        out
    };
    let mut frame = vec![0u8; 84];
    frame[..4].copy_from_slice(&[0x21, 0x56, job_id, 1]);
    frame[8..12].copy_from_slice(&nbits.to_le_bytes());
    frame[12..16].copy_from_slice(&ntime.to_le_bytes());
    frame[16..48].copy_from_slice(&reverse_32bit_words(merkle_internal));
    frame[48..80].copy_from_slice(&reverse_32bit_words(previous_internal));
    frame[80..84].copy_from_slice(&version.to_le_bytes());
    frame
}

/// A host transport stub for one physical chain. It records the frames it
/// is dispatched and, when it holds the work item, returns the
/// independently known mainnet genesis nonce in the exact two-word
/// WORK_RX_FIFO shape consumed by `Bm1366Driver::decode_nonce`:
/// word0 = nonce, word1 = [CRC:8 | extended_work_id:16 | solution_index:8]
/// where extended_work_id = work_id << 2 (MIDSTATE_CNT = 2). Same
/// host-evidence posture as the r12 PTY regression (recorded public
/// constant, oracle-validated), WITHOUT claiming a recorded wire capture
/// or physical hashing.
struct MockBm1366XpChain {
    chain: u8,
    dispatched: Vec<(u16, Vec<u8>)>, // (work_id, frame)
    pending: VecDeque<u16>,          // work ids ready to produce a nonce
}

impl MockBm1366XpChain {
    fn new(chain: u8) -> Self {
        Self {
            chain,
            dispatched: Vec::new(),
            pending: VecDeque::new(),
        }
    }

    fn dispatch(&mut self, assignment: ChainWorkAssignment, frame: Vec<u8>) {
        self.pending.push_back(assignment.work_id);
        self.dispatched.push((assignment.work_id, frame));
    }

    /// Real-driver RX decode: the mock formats the recorded nonce into the
    /// two-word WORK_RX_FIFO shape and the ACTUAL driver decodes it. The
    /// CRC byte is a mock placeholder (the driver's decode does not verify
    /// it — CRC validation stays with the transport owner).
    fn produce_genesis_nonce(&mut self, driver: &Bm1366Driver) -> dcentrald_asic::Result<NonceDecoded> {
        let work_id = self
            .pending
            .pop_front()
            .expect("mock chain holds the dispatched work item");
        let raw = [GENESIS_NONCE, (u32::from(work_id) << 10) | 0x00];
        let decoded = driver.decode_nonce(&raw)?;
        Ok(NonceDecoded {
            chain: self.chain,
            work_id,
            decoded,
        })
    }
}

struct NonceDecoded {
    chain: u8,
    work_id: u16,
    decoded: dcentrald_asic::drivers::NonceResult,
}

/// The oracle header for mainnet block 0 with a chosen nonce (merkle in the
/// oracle's wire/internal order — see `GENESIS_MERKLE_INTERNAL`).
fn genesis_header(nonce: u32) -> BlockHeader {
    BlockHeader {
        version: GENESIS_VERSION,
        prev_hash: [0u8; 32],
        merkle_root: GENESIS_MERKLE_INTERNAL,
        timestamp: GENESIS_NTIME,
        nbits: GENESIS_NBITS,
        nonce,
    }
}

fn exact_full_unit(profile: Bm1366XpBoardProfile) -> Vec<ChainPopulation> {
    (0..3)
        .map(|chain| ChainPopulation {
            chain,
            observed_chips: profile.chips_per_chain,
        })
        .collect()
}

/// Walk a session from `begin` through the full cold-start prefix.
fn session_ready_for_work(
    profile: Bm1366XpBoardProfile,
    populations: &[ChainPopulation],
) -> Bm1366XpWorkSession {
    let unit = admit_full_unit_population(profile, populations)
        .unwrap_or_else(|e| panic!("{} exact 3x110 unit refused: {e:?}", profile.board_target));
    let mut session = Bm1366XpWorkSession::begin(unit);
    for stage in profile.desk_cold_start_prefix().iter().skip(1) {
        session
            .advance_to(*stage)
            .unwrap_or_else(|e| panic!("{} ladder advance to {stage:?} refused: {e:?}", profile.board_target));
    }
    session
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn oracle_self_check_genesis_nonce_meets_target() {
    let good = genesis_header(GENESIS_NONCE);
    assert!(good.meets_target(), "recorded mainnet genesis nonce must meet the genesis target through the independent oracle");
    assert_eq!(good.to_wire()[76..80], GENESIS_NONCE.to_le_bytes());
    // The +1 neighbor must fail: a false pass here would invalidate every
    // downstream session assertion (2^-32 chance, not a real risk).
    assert!(
        !genesis_header(GENESIS_NONCE + 1).meets_target(),
        "sanity: nonce+1 must not also meet the genesis target"
    );
}

#[test]
fn every_bin_admits_exact_110_unit_and_runs_a_three_chain_oracle_session() {
    for profile in Bm1366XpBoardProfile::ALL {
        let unit = admit_full_unit_population(profile, &exact_full_unit(profile))
            .unwrap_or_else(|e| panic!("{} exact 3x110 unit refused: {e:?}", profile.board_target));
        assert_eq!(unit.populated_count, 3);
        assert_eq!(unit.profile, profile);
        assert_eq!(unit.profile.chips_per_unit(), 330);

        // The dispatch-table join agrees before anything is planned.
        let row = profile.dispatch_platform();
        assert!(row.dispatch_admitted);
        assert_eq!(row.expected_chips_per_uart, 110);
        assert_eq!(row.stock_chain_count, 3);

        // Staged session reaches WorkEnabled only through the prefix.
        let session = session_ready_for_work(profile, &exact_full_unit(profile));
        const WORK_ID: u16 = 0x2a;
        let plan = session
            .plan_work(WORK_ID)
            .unwrap_or_else(|e| panic!("{} all-chain plan refused: {e:?}", profile.board_target));
        assert_eq!(plan.len(), 3, "{} must dispatch to all three chains", profile.board_target);
        assert_eq!(
            plan,
            vec![
                ChainWorkAssignment { chain: 0, work_id: WORK_ID },
                ChainWorkAssignment { chain: 1, work_id: WORK_ID },
                ChainWorkAssignment { chain: 2, work_id: WORK_ID },
            ]
        );

        // Each physical chain receives the same full-header job frame; the
        // codec input is the header-internal merkle exactly as the private
        // codec consumes it (`serial_full_header_work` feed convention).
        let frame = full_header_work_frame(
            WORK_ID as u8,
            GENESIS_VERSION,
            GENESIS_NBITS,
            GENESIS_NTIME,
            &GENESIS_MERKLE_INTERNAL,
            &[0u8; 32],
        );
        assert_eq!(frame[..4], [0x21, 0x56, WORK_ID as u8, 1]);
        assert_eq!(frame[8..12], GENESIS_NBITS.to_le_bytes());
        assert_eq!(frame[12..16], GENESIS_NTIME.to_le_bytes());
        assert_eq!(frame[80..84], GENESIS_VERSION.to_le_bytes());

        let driver = Bm1366Driver::new();
        let mut chains: Vec<MockBm1366XpChain> = plan
            .iter()
            .map(|assignment| {
                let mut chain = MockBm1366XpChain::new(assignment.chain);
                chain.dispatch(*assignment, frame.clone());
                chain
            })
            .collect();
        assert_eq!(chains.len(), 3);

        let mut receipts: Vec<SessionWorkReceipt> = Vec::new();
        for chain in chains.iter_mut() {
            let produced = chain
                .produce_genesis_nonce(&driver)
                .unwrap_or_else(|e| panic!("{} chain{} RX decode failed: {e:?}", profile.board_target, chain.chain));
            // Chain-level attribution is EXACT: the RX path names the chain.
            assert_eq!(produced.chain, chain.chain);
            // The real driver's work-id round-trip matches the dispatcher
            // (extended work id = work_id << 2 in the RX FIFO word shape).
            assert_eq!(produced.decoded.work_id, WORK_ID);
            assert_eq!(produced.decoded.midstate_idx, 0);
            receipts.push(SessionWorkReceipt {
                chain: produced.chain,
                work_id: produced.work_id,
                epoch: session.epoch(),
            });
            // Independent oracle validation: the decoded nonce completes the
            // exact dispatched header and meets the share target.
            let header = genesis_header(produced.decoded.nonce);
            assert_eq!(header.merkle_root, GENESIS_MERKLE_INTERNAL);
            assert!(
                header.meets_target(),
                "{} chain{}: decoded nonce must meet the target via the oracle",
                profile.board_target,
                chain.chain
            );
            assert_eq!(produced.decoded.nonce, GENESIS_NONCE);

            // Assigned-address echo (codec mechanics, NOT chip health): the
            // driver extracts the assigned address from nonce bits [24:17]
            // exactly as documented, for arbitrary and for ladder values.
            let decoded_addr = (produced.decoded.nonce >> 17) & 0xFF;
            assert_eq!(
                produced.decoded.chip_index as u32, decoded_addr,
                "{} chain{}: chip_index must be the raw assigned-address field",
                profile.board_target, chain.chain
            );
            let last_assigned = 109 * u16::from(BM1366_XP_ADDRESS_INTERVAL);
            for chip in [0u16, 54, 109] {
                let assigned = chip * u16::from(BM1366_XP_ADDRESS_INTERVAL);
                let synthetic = (u32::from(assigned) << 17) | 0x0001_5555;
                let echo = driver.decode_nonce(&[synthetic, 0]).unwrap();
                assert_eq!(echo.chip_index as u16, assigned);
                assert_eq!(
                    echo.chip_index as u16 / u16::from(BM1366_XP_ADDRESS_INTERVAL),
                    chip,
                    "{} chain{}: address field normalizes onto the interval-{} ladder",
                    profile.board_target,
                    chain.chain,
                    BM1366_XP_ADDRESS_INTERVAL
                );
            }
            assert!(last_assigned < 256);
            // Physical per-chip health/attribution stays UNPROVEN: nothing
            // here maps an address echo to a measured chip identity, and no
            // autotuning claim is made (see SOURCE_NOTE unverified list).
        }

        // Session coverage ledger: every admitted chain, exactly once, live
        // epoch only.
        session_coverage_complete(&session, WORK_ID, &receipts)
            .unwrap_or_else(|e| panic!("{} coverage failed: {e:?}", profile.board_target));
    }
}

#[test]
fn measured_psu_dialect_matrix_never_merges_the_pair() {
    // S19 XP: modern APW12, measured versions 0x75..=0x77 ONLY.
    for version in [0x75u8, 0x76, 0x77] {
        assert_eq!(
            Bm1366XpBoardProfile::XP.select_measured_psu_version(version),
            Ok(Bm1366XpPsuDialect::XpApw12Modern),
            "XP measured PSU version 0x{version:02x}"
        );
    }
    // S19j XP: modern APW17, measured version 0xc1 ONLY.
    assert_eq!(
        Bm1366XpBoardProfile::JXP.select_measured_psu_version(0xc1),
        Ok(Bm1366XpPsuDialect::JxpApw17Modern)
    );

    // THE SEPARATION MATRIX — every wrong-dialect / unknown frame refuses
    // in BOTH directions ("the pair must never be merged"):
    // - an APW17 frame (0xc1) measured on an XP profile refuses, and an
    //   APW12 frame (0x75..0x77) measured on a jXP profile refuses;
    // - 0xc2 (the BHB56807 sibling's v[194]) is NOT inferred from c1;
    // - the stock topol's older APW12 rosters (0x71..0x73, 0x78) are not
    //   the runtime admission set (the retained wire owner refuses 0x71);
    // - 0x00 never selected anything.
    for (profile, version) in [
        (Bm1366XpBoardProfile::XP, 0xc1u8),
        (Bm1366XpBoardProfile::XP, 0xc2),
        (Bm1366XpBoardProfile::XP, 0x71),
        (Bm1366XpBoardProfile::XP, 0x72),
        (Bm1366XpBoardProfile::XP, 0x73),
        (Bm1366XpBoardProfile::XP, 0x78),
        (Bm1366XpBoardProfile::XP, 0x00),
        (Bm1366XpBoardProfile::JXP, 0x75),
        (Bm1366XpBoardProfile::JXP, 0x76),
        (Bm1366XpBoardProfile::JXP, 0x77),
        (Bm1366XpBoardProfile::JXP, 0xc2),
        (Bm1366XpBoardProfile::JXP, 0x00),
    ] {
        assert_eq!(
            profile.select_measured_psu_version(version),
            Err(PsuDialectError::MeasuredVersionNotAdmitted {
                dialect: profile.psu_dialect(),
                version,
            }),
            "{:?} measured PSU 0x{version:02x} must refuse",
            profile.bin
        );
    }

    // The dispatch rows carry the SAME split as contract metadata: the XP
    // row's stock basis cites APW12 and never APW17; the jXP row cites
    // APW17 and never APW12.
    let xp_row = bm1366_serial_platform_for("am3-s19xp").unwrap();
    let jxp_row = bm1366_serial_platform_for("am3-s19jxp").unwrap();
    assert!(xp_row.stock_basis.contains("APW12"));
    assert!(!xp_row.stock_basis.contains("APW17"));
    assert!(jxp_row.stock_basis.contains("APW17"));
    assert!(!jxp_row.stock_basis.contains("APW12"));
    assert_ne!(
        Bm1366XpBoardProfile::XP.psu_dialect(),
        Bm1366XpBoardProfile::JXP.psu_dialect()
    );
}

#[test]
fn partial_population_and_s19k_77_refuse_before_any_work_is_planned() {
    for profile in Bm1366XpBoardProfile::ALL {
        // Off-by-one AND the S19k 77-chip program refuse on every slot —
        // "wrong S19k profile cannot authorize XP" and no partial census
        // ever joins work.
        for drifted in [
            profile.chips_per_chain - 1,
            profile.chips_per_chain + 1,
            u16::from(S19K_EXPECTED_CHIPS_PER_UART),
        ] {
            for chain in 0..3u8 {
                assert_eq!(
                    admit_unit_population(
                        profile,
                        &[ChainPopulation {
                            chain,
                            observed_chips: drifted,
                        }]
                    ),
                    Err(PopulationAdmissionError::PopulationMismatch {
                        chain,
                        observed: drifted,
                        expected: profile.chips_per_chain,
                    }),
                    "{}/chain population {drifted} must refuse",
                    profile.board_target
                );
            }
            // The refused unit never reaches a session: admission gates the
            // only session constructor.
        }

        // Full-unit manifest refuses a partial (two-of-three) unit.
        let mut two = exact_full_unit(profile);
        two.pop();
        assert_eq!(
            admit_full_unit_population(profile, &two),
            Err(PopulationAdmissionError::EmptyUnit)
        );

        // A two-of-three EXACT subset is admissible as a subset and its
        // dispatch covers only populated chains.
        let unit = admit_unit_population(profile, &two).expect("exact subset");
        assert_eq!(unit.populated_count, 2);
        let plan = distribute_work_to_all_chains(&unit, 3).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(
            distribute_work_to_chain(&unit, 2, 3),
            Err(DistributionError::ChainNotAdmitted)
        );
        coverage_complete(&unit, 3, &plan).expect("subset coverage");

        // Empty and duplicate observations refuse.
        assert_eq!(
            admit_unit_population(profile, &[]),
            Err(PopulationAdmissionError::EmptyUnit)
        );
    }
}

#[test]
fn cancel_mid_init_and_stale_epoch_fault_injection_refuse() {
    let profile = Bm1366XpBoardProfile::XP;
    let full = exact_full_unit(profile);

    // Fault 1: cancellation DURING init (after reset release, before
    // chains initialize). Nothing further is admitted: no advance, no work.
    let unit = admit_full_unit_population(profile, &full).unwrap();
    let mut session = Bm1366XpWorkSession::begin(unit);
    session.advance_to(ColdInitStage::RailEnergized).expect("rail stage");
    session.advance_to(ColdInitStage::ResetReleased).expect("reset stage");
    session.cancel();
    assert_eq!(
        session.plan_work(0x2a),
        Err(SessionError::SessionCancelled {
            cancelled_at: ColdInitStage::ResetReleased,
        })
    );
    assert!(session.advance_to(ColdInitStage::ChainsInitialized).is_err());

    // Fault 2: receipts from the cancelled epoch are STALE on the
    // replacement session and refuse; live-epoch receipts validate.
    let mut replacement = Bm1366XpWorkSession::begin_after(&session).expect("replacement");
    assert_eq!(replacement.epoch(), 2);
    for stage in profile
        .desk_cold_start_prefix()
        .iter()
        .skip(1)
    {
        replacement.advance_to(*stage).expect("replacement ladder");
    }
    let stale = SessionWorkReceipt { chain: 0, work_id: 7, epoch: 1 };
    assert_eq!(
        session_coverage_complete(&replacement, 7, &[stale]),
        Err(DistributionError::ReceiptStaleEpoch {
            receipt_epoch: 1,
            live_epoch: 2,
        })
    );
    let live: Vec<SessionWorkReceipt> = (0..3)
        .map(|chain| SessionWorkReceipt { chain, work_id: 7, epoch: 2 })
        .collect();
    session_coverage_complete(&replacement, 7, &live).expect("live-epoch coverage");

    // Fault 3: work planned mid-init (before WorkEnabled) refuses even
    // without cancellation.
    let mut early = Bm1366XpWorkSession::begin(admit_full_unit_population(profile, &full).unwrap());
    early.advance_to(ColdInitStage::RailEnergized).expect("rail stage");
    assert!(matches!(
        early.plan_work(0x2a),
        Err(SessionError::WorkNotEnabled { .. })
    ));

    // A live session has no successor until it is cancelled.
    assert_eq!(
        Bm1366XpWorkSession::begin_after(&early),
        Err(SessionError::ReplacementRequiresCancelledSession)
    );
}

#[test]
fn wrong_board_pages_and_foreign_targets_never_authorize() {
    // Recorded ePIC-matched factory pages (the recorded fixture manifest is
    // `evidence/r12/xp-identity-fixtures.json`; ePIC six caveats apply per
    // root ). The exact decoded name must select exactly one bin,
    // and the pair must never cross-authorize.
    let xp_class4 = decode_deployed_eeprom(include_bytes!(
        "../src/serial_mining/fixtures/bm1366-bhb56801-class4.bin"
    ))
    .expect("xp class4 fixture decodes");
    let xp_class5 = decode_deployed_eeprom(include_bytes!(
        "../src/serial_mining/fixtures/bm1366-bhb56801-class5.bin"
    ))
    .expect("xp class5 fixture decodes");
    let jxp = decode_deployed_eeprom(include_bytes!(
        "../src/serial_mining/fixtures/bm1366-bhb56804.bin"
    ))
    .expect("jxp fixture decodes");
    assert_eq!(xp_class4.board_name, "BHB56801");
    assert_eq!(xp_class5.board_name, "BHB56801");
    assert_eq!(jxp.board_name, "BHB56804");
    for page in [&xp_class4, &xp_class5] {
        assert_eq!(
            Bm1366XpBoardProfile::for_board_name(&page.board_name).map(|p| p.bin),
            Some(Bm1366XpBin::Xp)
        );
        // A jXP profile cannot admit an XP board name.
        assert_eq!(
            Bm1366XpBoardProfile::JXP.board_names.contains(&page.board_name.as_str()),
            false
        );
    }
    assert_eq!(
        Bm1366XpBoardProfile::for_board_name(&jxp.board_name).map(|p| p.bin),
        Some(Bm1366XpBin::Jxp)
    );
    assert!(!Bm1366XpBoardProfile::XP
        .board_names
        .contains(&jxp.board_name.as_str()));

    // The S19k page selects NOTHING here: the 77-chip program never
    // authorizes an XP bin.
    let s19k = decode_deployed_eeprom(include_bytes!(
        "../src/serial_mining/fixtures/s19k-bhb56903.bin"
    ))
    .expect("s19k fixture decodes");
    assert_eq!(s19k.board_name, "BHB56903");
    assert_eq!(Bm1366XpBoardProfile::for_board_name(&s19k.board_name), None);

    // Foreign board targets never resolve to an XP-pair profile.
    for target in [
        "am3-s19k",
        "am3-s21",
        "am3-s21pro",
        "am3-s21xp",
        "am3-s19xp-hydro",
        "am2-s19j",
        "am3-s19xp-alias",
        "",
    ] {
        assert_eq!(
            Bm1366XpBoardProfile::for_board_target(target),
            None,
            "{target} must not select an XP bin"
        );
    }

    // The dispatch table keeps S19k at its own 77-chip row: neither XP row
    // inherits it and the S19k row cannot be re-targeted at an XP bin.
    let s19k_row = bm1366_dispatch_admitted_serial_platform("am3-s19k").unwrap();
    // The platform-table row field is u8 (pre-existing public API); the
    // admission law in bm1366_xp_board_profiles compares chain populations
    // as u16 (observed_chips vs chips_per_chain, like the R14 sibling), so
    // the contrast const is u16 and the row field widens at the comparison.
    assert_eq!(u16::from(s19k_row.expected_chips_per_uart), S19K_EXPECTED_CHIPS_PER_UART);
    assert_ne!(s19k_row.expected_chips_per_uart, 110);
    assert!(bm1366_dispatch_admitted_serial_platform("am3-s19xp-hydro").is_err());
    assert!(bm1366_dispatch_admitted_serial_platform("am2-s19j").is_err());
}

#[test]
fn driver_surfaces_and_address_ladder_stay_inside_the_xp_program() {
    let driver = Bm1366Driver::new();
    // ESP-Miner job pacing for BM1366: 2000ms / chip count, floor 1ms.
    assert_eq!(driver.job_interval_ms(110, 400), 18);
    assert_eq!(driver.job_interval_ms(77, 400), 25); // S19k contrast: same codec, different geometry
    // Industrial plain ticket mask: difficulty - 1 (256 -> 0xff), the same
    // value the retained XP initializer writes to register 0x14.
    assert_eq!(driver.ticket_mask(256), 0xff);
    // The PLL solver resolves the DCENT default 400 MHz exactly and the
    // driver's informational decomposition agrees with it.
    let (register, actual) = dcentrald_common::bm1366_pll_reg_and_actual(400);
    assert_eq!(actual, 400);
    let pll = driver.pll_params(400);
    assert_eq!(pll.reg_value, register);

    // The interval-2 assigned ladder covers 0,2,..,218: unique, even,
    // 110 entries, last inside the byte space — the exact ladder the
    // retained initializer walks and the cold/assigned censuses gate on.
    let ladder = linear_chip_addresses(110, BM1366_XP_ADDRESS_INTERVAL);
    assert_eq!(ladder.len(), 110);
    assert_eq!(ladder[0], 0);
    assert_eq!(ladder[109], 218);
    assert!(ladder.iter().all(|addr| addr % 2 == 0));
    let mut unique = ladder.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 110);

    // RX decode is total over arbitrary FIFO words (never panics); a zero
    // extended-work word decodes to work id 0 / midstate 0. The expected
    // expressions mirror the driver's exact law (bm1366.rs:770-780):
    // nonce = raw[0]; w1 = raw[1] (u32); solution_id = w1 & 0xFF;
    // hw_work_id = ((w1 >> 8) & 0xFFFF) as u16 (line 774);
    // work_id = hw_work_id >> MIDSTATE_CNT_LOG2 (line 775, const = 2 at
    // line 71); chip_addr = ((nonce >> 17) & 0xFF) as u8 (line 780).
    for raw in [[0u32, 0], [u32::MAX, u32::MAX], [0x1234_5678, 0x0000_ab00]] {
        let decoded = driver.decode_nonce(&raw).expect("decode is total");
        assert_eq!(decoded.chip_index, ((raw[0] >> 17) & 0xFF) as u8);
        assert_eq!(decoded.work_id, (((raw[1] >> 8) & 0xFFFF) as u16) >> 2);
    }
}
