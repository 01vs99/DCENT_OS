// SPDX-License-Identifier: GPL-3.0-or-later
//! R13 base-S21 BM1368 full-unit session replay (desk-only, no hardware).
//!
//! Campaign `2026-09-07-antminer-beta-execution`, lane R13 (S21/T21,
//! BM1368, am3 Amlogic). This replay generalizes the existing
//! selected-route (single-board) ownership into the FULL three-chain
//! 3 x 108 = 324 unit and drives one complete work session through:
//!
//! - the exact base-S21 profile and full-unit population admission in
//!   `dcentrald-common::bm1368_s21_board_profiles` (108 exact per chain;
//!   wrong / duplicate / empty / off-by-one refuse before any work is
//!   planned);
//! - the all-chain work distribution planner (every populated chain receives
//!   the work item; unpopulated slots never do) and the coverage ledger;
//! - PER-ROUTE NONCE ACCOUNTING with exact attribution: every nonce is
//!   credited to the physical route (UART slot) it arrived on; foreign
//!   routes, unknown work items and duplicate nonces refuse; chip credits
//!   exist only for in-plan interval-2 decoded addresses;
//! - the REAL BM1368 driver surface `dcentrald-asic::drivers::bm1368`
//!   (`ChipDriver::decode_nonce`) — unmodified;
//! - the INDEPENDENT F04 Bitcoin oracle (`f04_oracle/bitcoin_oracle.rs`,
//!   never modified, never dcentrald hashing code) plus public mainnet
//!   genesis constants.
//!
//! Session shape: admit the exact full unit -> plan one work item onto all
//! three chains -> each mock chain (a host transport stub in the r14
//! PTY-regression tradition; clearly NOT a recorded wire capture and NOT
//! physical hashing) returns a recorded, independently validated nonce in
//! the exact two-word RX shape -> decode through the real driver -> rebuild
//! the header -> validate against the share target with the oracle -> credit
//! the per-route ledger -> confirm chain-level attribution is exact while
//! chip attribution is credited only where the decoded address is in the
//! admitted plan.
//!
//! Recorded nonces (desk-verified 2026-09-11 by direct SHA-256d computation
//! on the genesis header, re-validated here through the independent oracle):
//! - mainnet genesis nonce 2083236893 meets the true block-0 target; its
//!   BM1368 chip-address field decodes to 21 — OUTSIDE the admitted
//!   interval-2 plan — so it must stay route-attributed with no chip credit;
//! - nonce 8603 (0x0000219B) meets the recorded desk session target below
//!   and decodes chip address 0 -> chip position 0;
//! - nonce 28054374 (0x01AC1366) meets the same desk session target and
//!   decodes chip address 214 -> chip position 107.
//!
//! Acceptance clauses desk-covered here (agent_tasks R13):
//! 1. full three-by-108 S21 replay with per-route nonce accounting;
//! 2. T21 evidence-scoped profile (held stock topol bytes only);
//! 3. ZERO S19k polarity leakage (source ban-gate + functional scoping);
//! 4. clean-image dependencies closed (no bos_*/stock-tool dependency in the
//!    composed native path).
//!
//! This test grants no hardware, energization, dispatch, install, or
//! registration authority, and no live hashing claim. The Lead's cargo gate
//! remains authoritative for the full workspace build.

#![forbid(unsafe_code)]

#[path = "f04_oracle/bitcoin_oracle.rs"]
mod bitcoin_oracle;

use bitcoin_oracle::BlockHeader;
use dcentrald_asic::drivers::{bm1368::Bm1368Driver, ChipDriver};
use dcentrald_common::bm1368_s21_board_profiles::{
    admit_full_unit_population, admit_unit_population, coverage_complete,
    distribute_work_to_all_chains, distribute_work_to_chain, Bm1368S21Profile, ChainPopulation,
    ChainWorkAssignment, DistributionError, PopulationAdmissionError, RouteNonceReceipt,
    S21FullUnitAccounting, S21,
};
use dcentrald_common::s21_generation_admission::{Blocker, T21_AML};
use dcentrald_common::t21_bm1368_profile::{
    admit_t21_unit_population, T21PopulationAdmissionError, T21PsuCarrierScope, T21Unproven, T21,
    T21_DECLARED_CHAIN_CONTROLLER, T21_DECLARED_CHAIN_EEPROM, T21_POWER_POLARITY,
    T21_PSU_ZYNQ_VARIANT_DECLARATION, T21_RUNTIME_AUTHORITY, T21_STOCK_TOPOL_PINS,
};
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// Independent anchors (public mainnet block 0; oracle cross-checked in f04).
// Same literals as the R14 replay: the header-stored (internal) merkle order.
// ---------------------------------------------------------------------------
const GENESIS_MERKLE_INTERNAL: [u8; 32] = [
    0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
    0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
];
const GENESIS_NONCE: u32 = 2083236893;
const GENESIS_NTIME: u32 = 1231006505;
const GENESIS_NBITS: u32 = 0x1d00_ffff;
const GENESIS_VERSION: u32 = 1;

/// Recorded desk session share target = 2^240, used ONLY for the two
/// chip-address-constrained nonces (an 8-bit fixed nonce field leaves 2^24
/// free bits, so no real-network target can be met inside them; this target
/// models an easier private share gate). The oracle validates it
/// independently via `display_hash_meets_target`.
const SESSION_TARGET_2POW240: [u8; 32] = {
    let mut target = [0u8; 32];
    target[0] = 0x01;
    target
};

/// Recorded chip-attributed nonces (see module doc).
const NONCE_CHIP0_ADDR0: u32 = 8_603; // chip-address field 0x00
const NONCE_CHIP107_ADDR214: u32 = 28_054_374; // chip-address field 0xD6

/// Exact reconstruction of the private full-header UART job codec used by
/// BM1362/BM1368/BM1370 native chains (`serial_mining::serial_full_header_work`,
/// read-only at replay time). 84 bytes: `[0x21, 0x56, job_id, 1]`, nbits LE,
/// ntime LE, merkle (word-order-reversed), previous hash (word-order-
/// reversed), version LE.
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

/// A host transport stub for one physical route (UART slot). It records the
/// frames it is dispatched and, when it holds the work item, returns the
/// recorded nonce in the BM1368 RX FIFO word shape consumed by
/// `Bm1368Driver::decode_nonce` (word0 = nonce, word1 = work_id << 8 |
/// solution_id). Host-evidence posture only: NOT a recorded wire capture,
/// NOT physical hashing.
struct MockBm1368Chain {
    chain: u8,
    dispatched: Vec<(u16, Vec<u8>)>,
    pending: VecDeque<(u16, u32)>, // (work_id, recorded nonce)
}

impl MockBm1368Chain {
    fn new(chain: u8) -> Self {
        Self {
            chain,
            dispatched: Vec::new(),
            pending: VecDeque::new(),
        }
    }

    fn dispatch(&mut self, assignment: ChainWorkAssignment, frame: Vec<u8>) {
        self.pending.push_back((assignment.work_id, GENESIS_NONCE));
        self.dispatched.push((assignment.work_id, frame));
    }

    /// Real-driver RX decode: the mock formats the recorded nonce into the
    /// two-word WORK_RX shape and the ACTUAL driver decodes it.
    fn produce_nonce(&mut self, driver: &Bm1368Driver) -> dcentrald_asic::Result<NonceDecoded> {
        let (work_id, nonce) = self
            .pending
            .pop_front()
            .expect("mock route holds the dispatched work item");
        let raw = [nonce, (u32::from(work_id) << 8) | 0x00];
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
/// oracle's wire/internal order).
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

fn exact_full_unit() -> Vec<ChainPopulation> {
    (0..3)
        .map(|chain| ChainPopulation {
            chain,
            observed_chips: 108,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Acceptance 1: full three-by-108 S21 replay with per-route accounting.
// ---------------------------------------------------------------------------

#[test]
fn oracle_self_check_genesis_nonce_meets_target() {
    let good = genesis_header(GENESIS_NONCE);
    assert!(
        good.meets_target(),
        "recorded mainnet genesis nonce must meet the block-0 target through the independent oracle"
    );
    assert_eq!(good.to_wire()[76..80], GENESIS_NONCE.to_le_bytes());
    assert!(
        !genesis_header(GENESIS_NONCE + 1).meets_target(),
        "sanity: nonce+1 must not also meet the block-0 target"
    );
}

#[test]
fn full_three_by_108_unit_admits_plans_and_mines_with_exact_route_attribution() {
    // Admission: the FULL unit, exactly 3 x 108 = 324.
    let unit = admit_full_unit_population(S21, &exact_full_unit())
        .expect("exact 3x108 full unit must admit");
    assert_eq!(unit.populated_count, 3);
    assert_eq!(unit.profile, S21);
    assert_eq!(unit.profile.chips_per_unit(), 324);

    // Plan ONE work item onto every populated chain.
    const WORK_ID: u16 = 0x2a;
    let plan = distribute_work_to_all_chains(&unit, WORK_ID).expect("all-chain plan");
    assert_eq!(
        plan.len(),
        3,
        "a full unit must dispatch to all three chains"
    );

    // Each physical route receives the same full-header job frame; the codec
    // input is the header-internal merkle exactly as the private codec
    // consumes it (`serial_full_header_work` feed convention).
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

    // Per-route accounting opens over the admitted unit with the transport
    // route order (backend index -> slot 0/1/2), and records every dispatch.
    let accounting = S21FullUnitAccounting::new(unit, &[0, 1, 2]).expect("route order");
    for assignment in &plan {
        accounting
            .record_dispatch(assignment)
            .expect("dispatch recorded");
    }

    let driver = Bm1368Driver::new();
    let mut routes: Vec<MockBm1368Chain> = plan
        .iter()
        .map(|assignment| {
            let mut route = MockBm1368Chain::new(assignment.chain);
            route.dispatch(*assignment, frame.clone());
            route
        })
        .collect();
    assert_eq!(routes.len(), 3);
    // Every route retained its dispatched frame (route-level TX record).
    for route in &routes {
        assert_eq!(route.dispatched.len(), 1);
        assert_eq!(route.dispatched[0].1.len(), 84);
    }

    let mut receipts: Vec<ChainWorkAssignment> = Vec::new();
    for route in routes.iter_mut() {
        // The route-tagged RX point credits the physical route frame count.
        accounting
            .credit_route_frame(usize::from(route.chain))
            .expect("route frame credit");
        let produced = route
            .produce_nonce(&driver)
            .unwrap_or_else(|e| panic!("chain{} RX decode failed: {e:?}", route.chain));
        // Chain-level attribution is EXACT: the RX path names the chain.
        assert_eq!(produced.chain, route.chain);
        // The real driver's work-id round-trip matches the dispatcher.
        assert_eq!(produced.decoded.work_id, WORK_ID);
        // Independent oracle validation: the decoded nonce completes the
        // exact dispatched header and meets the block-0 target.
        let header = genesis_header(produced.decoded.nonce);
        assert_eq!(header.merkle_root, GENESIS_MERKLE_INTERNAL);
        assert!(
            header.meets_target(),
            "chain{}: decoded nonce must meet the target via the oracle",
            route.chain
        );
        assert_eq!(produced.decoded.nonce, GENESIS_NONCE);
        // The genesis nonce's BM1368 chip-address field decodes to 21 —
        // outside the admitted interval-2 plan — so the ledger must credit
        // the ROUTE and refuse to fabricate a chip identity.
        assert_eq!(produced.decoded.chip_index, 21);
        let credit = accounting
            .credit_nonce(&RouteNonceReceipt {
                route: produced.chain,
                work_id: produced.work_id,
                nonce: produced.decoded.nonce,
                decoded_chip_address: Some(produced.decoded.chip_index),
            })
            .unwrap_or_else(|e| panic!("chain{} credit failed: {e:?}", route.chain));
        assert_eq!(credit.chip_position, None, "address 21 is off-plan");
        receipts.push(ChainWorkAssignment {
            chain: produced.chain,
            work_id: produced.work_id,
        });
    }

    // All-chain coverage ledger: every admitted chain, exactly once.
    coverage_complete(&unit, WORK_ID, &receipts).expect("full coverage");

    // Accounting totals: three routes, three nonces, zero fabricated chips.
    let summary = accounting.summary();
    assert_eq!(summary.total_nonces, 3);
    assert_eq!(summary.total_frames, 3);
    assert_eq!(summary.total_chips_credited, 0);
    assert_eq!(summary.chip_unresolved, 3);
    let per_route: Vec<(u8, u32)> = summary
        .routes
        .iter()
        .map(|route| (route.chain, route.nonces))
        .collect();
    assert_eq!(per_route, vec![(0, 1), (1, 1), (2, 1)]);
    // Route names come from the verified AM3 physical-slot UART table.
    assert_eq!(summary.routes[0].uart, "/dev/ttyS3");
    assert_eq!(summary.routes[1].uart, "/dev/ttyS2");
    assert_eq!(summary.routes[2].uart, "/dev/ttyS1");

    // The accounting refuses the classic failure classes.
    assert!(matches!(
        accounting.credit_nonce(&RouteNonceReceipt {
            route: 3,
            work_id: WORK_ID,
            nonce: 1,
            decoded_chip_address: None,
        }),
        Err(dcentrald_common::bm1368_s21_board_profiles::AccountingError::RouteNotAdmitted)
    ));
    assert!(matches!(
        accounting.credit_nonce(&RouteNonceReceipt {
            route: 0,
            work_id: WORK_ID + 1,
            nonce: 2,
            decoded_chip_address: None,
        }),
        Err(dcentrald_common::bm1368_s21_board_profiles::AccountingError::UnknownWorkItem)
    ));
    assert!(matches!(
        accounting.credit_nonce(&RouteNonceReceipt {
            route: 0,
            work_id: WORK_ID,
            nonce: GENESIS_NONCE,
            decoded_chip_address: Some(21),
        }),
        Err(dcentrald_common::bm1368_s21_board_profiles::AccountingError::DuplicateNonce)
    ));
}

#[test]
fn chip_addresses_inside_the_plan_credit_exactly_one_chip_position() {
    let unit = admit_full_unit_population(S21, &exact_full_unit()).expect("full unit");
    const WORK_ID: u16 = 0x33;
    let accounting = S21FullUnitAccounting::new(unit, &[0, 1, 2]).expect("route order");
    for chain in 0..3u8 {
        accounting
            .record_dispatch(&ChainWorkAssignment {
                chain,
                work_id: WORK_ID,
            })
            .expect("dispatch recorded");
    }
    // Recorded nonces whose constrained chip-address fields decode to the
    // first and last plan entries; the independent oracle validates both
    // against the recorded desk session target.
    for (route, nonce, expected_position, expected_address) in [
        (0u8, NONCE_CHIP0_ADDR0, 0usize, 0u8),
        (2u8, NONCE_CHIP107_ADDR214, 107usize, 214u8),
    ] {
        let decoded = Bm1368Driver::new()
            .decode_nonce(&[nonce, u32::from(WORK_ID) << 8])
            .expect("driver decode");
        assert_eq!(decoded.chip_index, expected_address);
        assert_eq!(decoded.work_id, WORK_ID);
        let display = genesis_header(nonce).display_hash();
        assert!(
            bitcoin_oracle::display_hash_meets_target(&display, &SESSION_TARGET_2POW240),
            "recorded nonce {nonce} must meet the recorded desk session target"
        );
        let credit = accounting
            .credit_nonce(&RouteNonceReceipt {
                route,
                work_id: WORK_ID,
                nonce: decoded.nonce,
                decoded_chip_address: Some(decoded.chip_index),
            })
            .unwrap_or_else(|e| panic!("route{route} credit failed: {e:?}"));
        assert_eq!(credit.chip_position, Some(expected_position));
    }
    let summary = accounting.summary();
    assert_eq!(summary.total_chips_credited, 2);
    assert_eq!(summary.chip_unresolved, 0);
    // Chip credits route-exact: chip 0 landed on route 0, chip 107 on route 2.
    assert_eq!(summary.routes[0].chips_credited, 1);
    assert_eq!(summary.routes[1].chips_credited, 0);
    assert_eq!(summary.routes[2].chips_credited, 1);
}

#[test]
fn off_by_one_duplicate_empty_and_full_unit_manifest_refusals() {
    for drifted in [107u16, 109] {
        let bad = vec![
            ChainPopulation {
                chain: 0,
                observed_chips: 108,
            },
            ChainPopulation {
                chain: 1,
                observed_chips: 108,
            },
            ChainPopulation {
                chain: 2,
                observed_chips: drifted,
            },
        ];
        assert_eq!(
            admit_unit_population(S21, &bad),
            Err(PopulationAdmissionError::PopulationMismatch {
                chain: 2,
                observed: drifted,
                expected: 108,
            }),
            "off-by-one chain population {drifted} must refuse before any work is planned"
        );
    }
    // Duplicate slot refuses.
    let dup = vec![
        ChainPopulation {
            chain: 0,
            observed_chips: 108,
        },
        ChainPopulation {
            chain: 0,
            observed_chips: 108,
        },
    ];
    assert_eq!(
        admit_unit_population(S21, &dup),
        Err(PopulationAdmissionError::DuplicateChain)
    );
    // Empty refuses; the full-unit manifest refuses a missing chain.
    assert_eq!(
        admit_unit_population(S21, &[]),
        Err(PopulationAdmissionError::EmptyUnit)
    );
    let two = exact_full_unit();
    assert_eq!(
        admit_full_unit_population(S21, &two[..2]),
        Err(PopulationAdmissionError::EmptyUnit)
    );
    // Cross-model confusion refuses at the NAME gate (both platforms count
    // 108/chain; identity is never count-derived).
    assert_eq!(Bm1368S21Profile::for_board_name("BHB68701"), None);
    assert_eq!(
        dcentrald_common::t21_bm1368_profile::T21Bm1368Profile::for_board_name("BHB68603"),
        None
    );
    // Unpopulated slots receive no work and foreign receipts refuse.
    let single = admit_unit_population(
        S21,
        &[ChainPopulation {
            chain: 1,
            observed_chips: 108,
        }],
    )
    .expect("held .135 single-board posture");
    let plan = distribute_work_to_all_chains(&single, 5).unwrap();
    assert_eq!(
        plan,
        vec![ChainWorkAssignment {
            chain: 1,
            work_id: 5
        }]
    );
    assert_eq!(
        distribute_work_to_chain(&single, 0, 5),
        Err(DistributionError::ChainNotAdmitted)
    );
    assert_eq!(
        distribute_work_to_chain(&single, 2, 5),
        Err(DistributionError::ChainNotAdmitted)
    );
    assert_eq!(
        coverage_complete(
            &single,
            5,
            &[ChainWorkAssignment {
                chain: 0,
                work_id: 5
            }]
        ),
        Err(DistributionError::ReceiptForeignChain)
    );
}

// ---------------------------------------------------------------------------
// Acceptance 2: T21 evidence-scoped profile (held stock bytes only).
// ---------------------------------------------------------------------------

#[test]
fn t21_profile_pins_only_what_the_held_stock_bytes_prove() {
    // Held stock topol pins (first-party Bitmain T21 merge 20240926).
    assert_eq!(T21_STOCK_TOPOL_PINS.len(), 3);
    for pin in T21_STOCK_TOPOL_PINS {
        assert_eq!(pin.sha256.len(), 64);
    }
    // Geometry: identical across BHB68701/03/05; 12 domains x 9 = 108 x 3.
    assert_eq!(T21.board_names, &["BHB68701", "BHB68703", "BHB68705"]);
    assert_eq!(T21.domains_times_chips(), 108);
    assert_eq!(T21.chips_per_chain, 108);
    assert_eq!(T21.chains, 3);
    assert_eq!(T21.chips_per_unit(), 324);
    assert_eq!(T21.address_interval, 2);
    // Controller/PSU/eeprom records are DECLARATIONS with scopes, not
    // protocols: PIC1704@0x20 per chain, AT24C02D@0x50 per chain, and the
    // PSU record scoped to the ZYNQ-variant topol only.
    assert_eq!(T21_DECLARED_CHAIN_CONTROLLER.controller, "PIC1704");
    assert_eq!(T21_DECLARED_CHAIN_CONTROLLER.i2c_addr_7bit, 0x20);
    assert_eq!(T21_DECLARED_CHAIN_EEPROM.i2c_addr_7bit, 0x50);
    assert_eq!(T21_PSU_ZYNQ_VARIANT_DECLARATION.family, "APW11A");
    assert_eq!(T21_PSU_ZYNQ_VARIANT_DECLARATION.i2c_addr_7bit, 0x10);
    assert_eq!(T21_PSU_ZYNQ_VARIANT_DECLARATION.power_gpio, 907);
    assert_eq!(
        T21_PSU_ZYNQ_VARIANT_DECLARATION.scope,
        T21PsuCarrierScope::ZynqVariantTopolDeclaration
    );
    // The AML carrier (the only T21 carrier DCENT images target) has NO
    // proven PSU record: the stock AML member is an opaque BMU layer and
    // the held VNish rootfs identifies no PSU family.
    assert_ne!(
        T21_PSU_ZYNQ_VARIANT_DECLARATION.scope,
        T21PsuCarrierScope::AmlCarrierUnproven
    );
    // Polarity: Unproven. T21 never inherits the S21 production mapping or
    // any sibling's levels.
    assert_eq!(T21_POWER_POLARITY, T21Unproven::Unproven);
    // Runtime authority: evidence-only; every action class stays closed.
    assert!(!T21_RUNTIME_AUTHORITY.permits_uart_or_gpio_io());
    assert!(!T21_RUNTIME_AUTHORITY.permits_pic_or_psu_io());
    assert!(!T21_RUNTIME_AUTHORITY.permits_power_or_mining());
    assert!(!T21_RUNTIME_AUTHORITY.permits_install_or_recovery());
    // Planning admission exists and stays exact; it grants no authority.
    let planned = admit_t21_unit_population(
        T21,
        &(0..3)
            .map(
                |chain| dcentrald_common::t21_bm1368_profile::T21ChainPopulation {
                    chain,
                    observed_chips: 108,
                },
            )
            .collect::<Vec<_>>(),
    )
    .expect("exact T21 planning admission");
    assert_eq!(planned.populated_count, 3);
    assert!(!T21_RUNTIME_AUTHORITY.permits_power_or_mining());
    // Wrong populations refuse exactly like S21.
    assert_eq!(
        admit_t21_unit_population(
            T21,
            &[dcentrald_common::t21_bm1368_profile::T21ChainPopulation {
                chain: 0,
                observed_chips: 107,
            }],
        ),
        Err(T21PopulationAdmissionError::PopulationMismatch {
            chain: 0,
            observed: 107,
            expected: 108,
        })
    );
    // The generation-level admission contract keeps T21 non-executable:
    // verified routes but every electrical/executable blocker open.
    assert_eq!(T21_AML.chains, 3);
    assert_eq!(T21_AML.chips_per_chain, 108);
    assert!(!T21_AML.executable());
    assert!(T21_AML.blockers().contains(&Blocker::PowerPolarity));
    assert!(T21_AML.blockers().contains(&Blocker::ControllerIdentity));
    assert!(T21_AML.blockers().contains(&Blocker::PsuProtocol));
}

// ---------------------------------------------------------------------------
// Acceptance 3: ZERO S19k polarity leakage.
// ---------------------------------------------------------------------------

#[test]
fn zero_s19k_polarity_leakage_into_the_s21_t21_paths() {
    // (a) Source ban-gate: the composed S21/T21 native planning modules must
    //     not reference the S19k polarity/reset owner or any S19k-scoped
    //     constant. These modules derive their electrical scoping from R13's
    //     own production control-flow proof (S21) and from Unproven (T21).
    let s21_module = include_str!("../../dcentrald-common/src/bm1368_s21_board_profiles.rs");
    let t21_module = include_str!("../../dcentrald-common/src/t21_bm1368_profile.rs");
    for source in [s21_module, t21_module] {
        for banned in [
            "s19k_am3_gpio437",
            "S19K_AM3_GPIO437_ACTIVE_LOW",
            "S19K_AM3_GPIO437_VALUE_ON",
            "S19K_AM3_GPIO437_VALUE_OFF",
            "s19k_am3_pwr_control_sysfs_n",
            "s19k_am3_reset_sysfs_n",
            "assert_s19k_native_all_resets_checked",
            "S19K_AM3_HB_RESET_ACTIVE_LOW",
        ] {
            assert!(
                !source.contains(banned),
                "S19k-scoped symbol `{banned}` must not be reachable from the composed S21/T21 profile modules"
            );
        }
    }
    // (b) Functional scoping: the S19k GPIO437 owner refuses both board
    //     targets (its active-low PWR_CONTROL stays am3-s19k scoped).
    assert!(
        dcentrald_common::s19k_am3_gpio437::admit_s19k_am3_gpio437_board_target("am3-s21").is_err()
    );
    assert!(
        dcentrald_common::s19k_am3_gpio437::admit_s19k_am3_gpio437_board_target("am3-t21").is_err()
    );
    // (c) The S21 polarity join is the R13 production software mapping
    //     scoped to exact am3-s21; T21 has NO polarity state except
    //     Unproven, so no sibling mapping — S21's or S19k's — is reachable
    //     from a T21 path.
    assert_eq!(
        S21.power_polarity_join(),
        dcentrald_common::bm1368_s21_board_profiles::S21PowerPolarityJoin::ProductionMappedZeroOnOneOff
    );
    assert_eq!(T21_POWER_POLARITY, T21Unproven::Unproven);
    assert!(T21_AML.blockers().contains(&Blocker::PowerPolarity));
    // (d) PSU scoping: the S21 profile selects only the traced production
    //     APW1212xx family; T21 selects no PSU family at all (the APW11A
    //     record is a Zynq-variant declaration, and the S21 75..77 law is
    //     never inferred onto it).
    assert_eq!(
        S21.psu_selection(),
        dcentrald_common::bm1368_s21_board_profiles::S21PsuSelection::ProductionApw1212xxVersions75to77
    );
    assert_eq!(
        T21_PSU_ZYNQ_VARIANT_DECLARATION.scope,
        T21PsuCarrierScope::ZynqVariantTopolDeclaration
    );
}

// ---------------------------------------------------------------------------
// Acceptance 4: clean-image dependencies closed.
// ---------------------------------------------------------------------------

#[test]
fn composed_native_path_has_no_bos_or_stock_tool_dependency() {
    // The composed native planning path (the two new profile/accounting
    // modules) must reference no incumbent-runtime or stock-tool dependency:
    // discovery is DCENT-owned (HAL admission + fresh GetAddress populations),
    // and no bos_*/i2cget/cgminer/bmminer artifact or path appears in the
    // composed source. This replay file itself is deliberately NOT scanned:
    // its documentation names the banned tools, and its only include_str!
    // sources are the two modules asserted below (the include! set is pinned
    // by the two constant paths).
    let s21_module = include_str!("../../dcentrald-common/src/bm1368_s21_board_profiles.rs");
    let t21_module = include_str!("../../dcentrald-common/src/t21_bm1368_profile.rs");
    for source in [s21_module, t21_module] {
        for banned in [
            "bos_", "bosminer", "i2cget", "i2cdump", "cgminer", "bmminer", "S70miner", "vnish_",
        ] {
            assert!(
                !source.contains(banned),
                "clean-image violation: `{banned}` must not appear in the composed native path"
            );
        }
    }
    // The driver envelope the replay composes against stays pinned: 108
    // chips/chain, interval 2, the ESP-Miner-derived 4ms job pacing at 108
    // chips, and the plain ticket-mask law.
    let driver = Bm1368Driver::new();
    assert_eq!(dcentrald_asic::drivers::bm1368::CHIPS_PER_CHAIN_S21, 108);
    assert_eq!(
        dcentrald_asic::drivers::bm1368::FIXTURE_ADDRESS_INTERVAL,
        dcentrald_common::bm1368_s21_board_profiles::S21_ADDRESS_INTERVAL
    );
    assert_eq!(driver.job_interval_ms(108, 550), 4);
    assert_eq!(driver.ticket_mask(128), 127);
    assert_eq!(driver.response_length(), 11);
    // The pure SSOT interval equals the profile's plan width.
    assert_eq!(dcentrald_common::bm1397plus_addr_interval(108), 2);
    let plan = S21.address_plan();
    assert_eq!(plan.len(), 108);
    assert_eq!(plan[107], 214);
}
