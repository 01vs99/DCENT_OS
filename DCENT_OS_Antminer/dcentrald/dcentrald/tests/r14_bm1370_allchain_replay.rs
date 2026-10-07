// SPDX-License-Identifier: GPL-3.0-or-later
//! R14 BM1370 per-bin all-chain session replay (desk-only, no hardware).
//!
//! Campaign `2026-09-07-antminer-beta-execution`, lane R14 (S21 Pro / S21+ /
//! S21 XP, BM1370, am3 Amlogic). For EACH resolved bin — Pro 3x65=195,
//! S21+ 3x55=165, XP 3x91=273 — this replay drives one full three-chain
//! work session through:
//!
//! - the exact per-bin profiles and population admission in
//!   `dcentrald-common::bm1370_board_profiles` (65/55/91 exact; off-by-one
//!   refuses before any work is planned);
//! - the all-chain work distribution planner (every populated chain receives
//!   the work item; unpopulated slots never do);
//! - the REAL BM1370 driver surfaces in `dcentrald-asic::drivers::bm1370`
//!   (`ChipDriver::decode_nonce` / `pll_params` / `ticket_mask` /
//!   `job_interval_ms`) — the September 7 register/attribution implementation,
//!   unmodified;
//! - the INDEPENDENT F04 Bitcoin oracle (`f04_oracle/bitcoin_oracle.rs`,
//!   never modified, never dcentrald hashing code) plus public mainnet
//!   genesis constants.
//!
//! Session shape per bin: admit the exact full unit -> plan one work item
//! onto all three chains -> each mock chain (a host transport stub in the
//! r14 PTY-regression tradition; clearly NOT a recorded wire capture and NOT
//! physical hashing) returns the independently known mainnet genesis nonce in
//! the exact two-word RX FIFO shape -> decode through the real driver ->
//! rebuild the header -> validate against the share target with the oracle ->
//! confirm chain-level attribution is exact while physical chip attribution
//! stays unknown (`bm1370_work_geometry` returns no chip index on this
//! no-admitted-offset-schedule path).
//!
//! Every constant is cited in
//! .
//! This test grants no hardware, energization, dispatch, install, or
//! registration authority, and no per-chip autotuning claim: chain-level
//! accepted shares do not require per-chip attribution (findings.md row
//! "S21 Pro/+/XP BM1370").

#![forbid(unsafe_code)]

#[path = "f04_oracle/bitcoin_oracle.rs"]
mod bitcoin_oracle;

use bitcoin_oracle::BlockHeader;
use dcentrald_api_types::deployed_eeprom::decode_deployed_eeprom;
use dcentrald_asic::drivers::{bm1370::Bm1370Driver, ChipDriver};
use dcentrald_common::bm1370_board_profiles::{
    admit_full_unit_population, admit_unit_population, coverage_complete,
    distribute_work_to_all_chains, distribute_work_to_chain, pro_research_topology,
    Bm1370BoardBin, Bm1370BoardProfile, ChainPopulation, ChainWorkAssignment,
    DistributionError, PopulationAdmissionError,
};
use dcentrald_common::bm1370_work_geometry::{
    replay_attribution, Bm1370Attribution, Bm1370NonceFields, CounterWindow,
};
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// Independent anchors (public mainnet block 0; oracle cross-checked in f04,
// genesis byte order re-verified by direct SHA-256 computation at the R14
// round-1 repair: hashing the INTERNAL form reproduces block 0's hash).
// ---------------------------------------------------------------------------
/// Genesis merkle root in the 80-byte header's wire/internal byte order —
/// the digest bytes exactly as the header stores and SHA-256 consumes them.
/// The familiar DISPLAY hex `4a5e1e4b...fdeda33b` is the byte-REVERSE of
/// this array; building the header from the display order hashes to
/// `f3554f2f...`, not block 0. Same literal as R07's `GENESIS_MERKLE` and
/// the r14 PTY regression's `entry.merkle_root`.
const GENESIS_MERKLE_INTERNAL: [u8; 32] = [
    0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
    0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
];
const GENESIS_NONCE: u32 = 2083236893;
const GENESIS_NTIME: u32 = 1231006505;
const GENESIS_NBITS: u32 = 0x1d00_ffff;
const GENESIS_VERSION: u32 = 1;

/// Exact reconstruction of the private full-header UART job codec used by
/// BM1362/BM1368/BM1370 native chains (`serial_mining::serial_full_header_work`,
/// read-only at replay time; layout also documented on the BM1370 driver's
/// `send_work`). 84 bytes: `[0x21, 0x56, job_id, 1]`, nbits LE, ntime LE,
/// merkle (word-order-reversed), previous hash (word-order-reversed),
/// version LE. The input merkle/prevhash are internal byte order, exactly as
/// the passing PTY regression feeds them.
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

/// A host transport stub for one physical chain. It records the frames it is
/// dispatched and, when it holds the work item, returns the independently
/// known mainnet genesis nonce in the BM1370 RX FIFO word shape. This is the
/// same host-evidence posture as the r14 PTY regression (recorded public
/// constant, oracle-validated), WITHOUT claiming a recorded wire capture or
/// physical hashing.
struct MockBm1370Chain {
    chain: u8,
    dispatched: Vec<(u16, Vec<u8>)>, // (work_id, frame)
    pending: VecDeque<u16>,          // work ids ready to produce a nonce
}

impl MockBm1370Chain {
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
    /// exact two-word WORK_RX_FIFO shape consumed by
    /// `Bm1370Driver::decode_nonce` (word0 = nonce, word1 = work_id << 8 |
    /// solution_id), and the ACTUAL driver decodes it.
    fn produce_nonce(&mut self, driver: &Bm1370Driver) -> dcentrald_asic::Result<NonceDecoded> {
        let work_id = self
            .pending
            .pop_front()
            .expect("mock chain holds the dispatched work item");
        let raw = [GENESIS_NONCE, (u32::from(work_id) << 8) | 0x00];
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

fn exact_full_unit(profile: Bm1370BoardProfile) -> Vec<ChainPopulation> {
    (0..3)
        .map(|chain| ChainPopulation {
            chain,
            observed_chips: profile.chips_per_chain,
        })
        .collect()
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
fn every_bin_admits_exact_full_unit_and_runs_a_three_chain_session() {
    for profile in Bm1370BoardProfile::ALL {
        let unit = admit_full_unit_population(profile, &exact_full_unit(profile))
            .unwrap_or_else(|e| panic!("{} exact 3x{} unit refused: {e:?}", profile.board_target, profile.chips_per_chain));
        assert_eq!(unit.populated_count, 3);
        assert_eq!(unit.profile, profile);

        // Plan ONE work item onto every populated chain.
        const WORK_ID: u16 = 0x2a;
        let plan = distribute_work_to_all_chains(&unit, WORK_ID)
            .unwrap_or_else(|e| panic!("{} all-chain plan refused: {e:?}", profile.board_target));
        assert_eq!(plan.len(), 3, "{} must dispatch to all three chains", profile.board_target);

        // Each physical chain receives the same full-header job frame; the
        // codec input is the header-internal merkle exactly as the private
        // codec consumes it (`serial_full_header_work` feed convention).
        let merkle_internal = GENESIS_MERKLE_INTERNAL;
        let frame = full_header_work_frame(WORK_ID as u8, GENESIS_VERSION, GENESIS_NBITS, GENESIS_NTIME, &merkle_internal, &[0u8; 32]);
        // Codec self-check: the frame decodes back to the oracle's genesis
        // header fields (nonce axis excluded — chips search it).
        assert_eq!(frame[..4], [0x21, 0x56, WORK_ID as u8, 1]);
        assert_eq!(frame[8..12], GENESIS_NBITS.to_le_bytes());
        assert_eq!(frame[12..16], GENESIS_NTIME.to_le_bytes());
        assert_eq!(frame[80..84], GENESIS_VERSION.to_le_bytes());

        let driver = Bm1370Driver::new();
        let mut chains: Vec<MockBm1370Chain> = plan
            .iter()
            .map(|assignment| {
                let mut chain = MockBm1370Chain::new(assignment.chain);
                chain.dispatch(*assignment, frame.clone());
                chain
            })
            .collect();
        assert_eq!(chains.len(), 3);

        let mut receipts: Vec<ChainWorkAssignment> = Vec::new();
        for chain in chains.iter_mut() {
            let produced = chain
                .produce_nonce(&driver)
                .unwrap_or_else(|e| panic!("{} chain{} RX decode failed: {e:?}", profile.board_target, chain.chain));
            // Chain-level attribution is EXACT: the RX path names the chain.
            assert_eq!(produced.chain, chain.chain);
            // The real driver's work-id round-trip matches the dispatcher.
            assert_eq!(produced.decoded.work_id, WORK_ID);
            receipts.push(ChainWorkAssignment {
                chain: produced.chain,
                work_id: produced.work_id,
            });
            // Physical chip attribution stays UNKNOWN on this path.
            assert_eq!(
                produced.decoded.chip_index, u8::MAX,
                "{} chain{}: BM1370 counter bits must not fabricate a chip address",
                profile.board_target, chain.chain
            );
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
            // Chip-level replay attribution over the session stays Unknown:
            // the industrial path admits no offset schedule / range witness.
            let fields = Bm1370NonceFields::from_header_nonce(produced.decoded.nonce);
            assert_eq!(replay_attribution(fields, &[]), Bm1370Attribution::Unknown);
        }

        // All-chain coverage ledger: every admitted chain, exactly once.
        coverage_complete(&unit, WORK_ID, &receipts)
            .unwrap_or_else(|e| panic!("{} coverage failed: {e:?}", profile.board_target));
    }
}

#[test]
fn off_by_one_population_refuses_before_any_work_is_planned() {
    for profile in Bm1370BoardProfile::ALL {
        for drifted in [profile.chips_per_chain - 1, profile.chips_per_chain + 1] {
            let bad = vec![
                ChainPopulation {
                    chain: 0,
                    observed_chips: profile.chips_per_chain,
                },
                ChainPopulation {
                    chain: 1,
                    observed_chips: profile.chips_per_chain,
                },
                ChainPopulation {
                    chain: 2,
                    observed_chips: drifted,
                },
            ];
            assert_eq!(
                admit_unit_population(profile, &bad),
                Err(PopulationAdmissionError::PopulationMismatch {
                    chain: 2,
                    observed: drifted,
                    expected: profile.chips_per_chain,
                }),
                "{} off-by-one chain population {drifted} must refuse",
                profile.board_target
            );
            // The refused unit never yields a distribution plan: with no
            // admitted unit there is nothing to dispatch (type-level gap:
            // distribute_* take an AdmittedBm1370Unit only).
        }
        // Cross-bin population confusion refuses: 65 on Plus, 55 on Pro,
        // 91-on-Pro and 65-on-XP alike.
        for other in Bm1370BoardProfile::ALL {
            if other == profile {
                continue;
            }
            let swapped = exact_full_unit(other);
            assert!(matches!(
                admit_full_unit_population(profile, &swapped),
                Err(PopulationAdmissionError::PopulationMismatch { .. })
            ));
        }
    }
}

#[test]
fn unpopulated_chains_receive_no_work_and_foreign_receipts_refuse() {
    // A one-board unit (the held S21 log posture: board 2 only) mines on its
    // populated chain alone; slots 0/1 must never be dispatched.
    let profile = Bm1370BoardProfile::PRO;
    let unit = admit_unit_population(
        profile,
        &[ChainPopulation {
            chain: 2,
            observed_chips: 65,
        }],
    )
    .expect("single exact chain");
    let plan = distribute_work_to_all_chains(&unit, 5).unwrap();
    assert_eq!(plan, vec![ChainWorkAssignment { chain: 2, work_id: 5 }]);
    assert_eq!(
        distribute_work_to_chain(&unit, 0, 5),
        Err(DistributionError::ChainNotAdmitted)
    );
    assert_eq!(
        distribute_work_to_chain(&unit, 1, 5),
        Err(DistributionError::ChainNotAdmitted)
    );
    let receipts = vec![ChainWorkAssignment { chain: 2, work_id: 5 }];
    coverage_complete(&unit, 5, &receipts).expect("populated chain covered");
    // A receipt from an unpopulated slot cannot count as coverage.
    assert_eq!(
        coverage_complete(&unit, 5, &[ChainWorkAssignment { chain: 0, work_id: 5 }]),
        Err(DistributionError::ReceiptForeignChain)
    );
}

#[test]
fn recorded_format1_fixtures_select_their_exact_bin_not_a_sibling() {
    // Recorded ePIC-matched format1 pages copied byte-for-byte from the
    // retained api-types fixtures (not claimed live DCENT captures). The
    // plaintext name is the only decoded fact; serial/tuning/CRC stay
    // unknown, and the exact decoded name must select exactly one bin.
    // (include_bytes! needs literal paths, so each fixture is decoded
    // explicitly below.)
    let pro = decode_deployed_eeprom(include_bytes!(
        "../src/serial_mining/fixtures/bm1370-a3hb70601.bin"
    ))
    .expect("pro fixture decodes");
    assert_eq!(pro.board_name, "A3HB70601");
    assert_eq!(
        Bm1370BoardProfile::for_board_name(&pro.board_name).map(|p| p.bin),
        Some(Bm1370BoardBin::Pro)
    );

    let plus = decode_deployed_eeprom(include_bytes!(
        "../src/serial_mining/fixtures/bm1370-a3hb70701.bin"
    ))
    .expect("plus fixture decodes");
    assert_eq!(plus.board_name, "A3HB70701");
    assert_eq!(
        Bm1370BoardProfile::for_board_name(&plus.board_name).map(|p| p.bin),
        Some(Bm1370BoardBin::Plus),
        "A3HB70701 is the S21+ 55-chip platform, never a Pro alias"
    );

    let xp = decode_deployed_eeprom(include_bytes!(
        "../src/serial_mining/fixtures/bm1370-a3hb70501.bin"
    ))
    .expect("xp fixture decodes");
    assert_eq!(xp.board_name, "A3HB70501");
    assert_eq!(
        Bm1370BoardProfile::for_board_name(&xp.board_name).map(|p| p.bin),
        Some(Bm1370BoardBin::Xp)
    );

    // The selected bins' geometry agrees with each fixture's bin.
    assert_eq!(Bm1370BoardProfile::PLUS.chips_per_chain, 55);
    assert_eq!(Bm1370BoardProfile::PLUS.domains_per_board * Bm1370BoardProfile::PLUS.chips_per_domain, 55);
    assert_ne!(Bm1370BoardProfile::PLUS, Bm1370BoardProfile::PRO);
}

#[test]
fn driver_job_pacing_ticket_mask_and_pll_stay_inside_the_pinned_envelope() {
    let driver = Bm1370Driver::new();
    // ESP-Miner job pacing: 500ms / chip count, floor 1ms.
    assert_eq!(driver.job_interval_ms(65, 480), 7);
    assert_eq!(driver.job_interval_ms(55, 480), 9);
    assert_eq!(driver.job_interval_ms(91, 480), 5);
    // Industrial plain ticket mask: difficulty - 1.
    assert_eq!(driver.ticket_mask(256), 255);
    assert_eq!(driver.ticket_mask(512), 511);
    // The existing PLL solver stays inside the shipped industrial envelope
    // at the DCENT default 480 MHz for every bin's identical silicon.
    for target_mhz in [400u16, 480, 500] {
        let pll = driver.pll_params(target_mhz);
        assert!((dcentrald_common::BM1370_FB_DIV_MIN..=dcentrald_common::BM1370_FB_DIV_MAX)
            .contains(&pll.fb_div));
        let actual = dcentrald_common::BM1370_CLKI_MHZ * f64::from(pll.fb_div)
            / (f64::from(pll.ref_div)
                * f64::from(pll.post_div1)
                * f64::from(pll.post_div2));
        assert!(
            (actual - f64::from(target_mhz)).abs() <= 2.0,
            "{target_mhz} MHz request resolved {actual} MHz (outside the 2 MHz industrial ceiling)"
        );
    }
    // Research plans stay Pro-capture-only: Plus/XP topologies refuse.
    assert_eq!(pro_research_topology(&Bm1370BoardProfile::PRO), Ok((13, 5)));
    assert!(pro_research_topology(&Bm1370BoardProfile::PLUS).is_err());
    assert!(pro_research_topology(&Bm1370BoardProfile::XP).is_err());
    // The replay-attribution window semantics stay research-only: a
    // non-overlapping window yields a Candidate, overlap yields Ambiguous,
    // and neither constructs a physical chip identity.
    let fields = Bm1370NonceFields {
        core_id: 3,
        counter: 100,
    };
    let windows = [
        CounterWindow {
            address: 6,
            offset: 0,
            candidates: 512,
        },
        CounterWindow {
            address: 8,
            offset: 0,
            candidates: 512,
        },
    ];
    assert_eq!(
        replay_attribution(fields, &windows),
        Bm1370Attribution::Ambiguous
    );
    assert_eq!(
        replay_attribution(fields, &windows[..1]),
        Bm1370Attribution::Candidate { address: 6 }
    );
}
