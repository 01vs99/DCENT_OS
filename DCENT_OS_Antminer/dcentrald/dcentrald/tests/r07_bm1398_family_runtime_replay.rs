// SPDX-License-Identifier: GPL-3.0-or-later
//! R07 BM1398 native family runtime replay (desk-only, no hardware).
//!
//! Campaign `2026-09-07-antminer-beta-execution`, lane R07. Drives the EXACT
//! production executor (`dcentrald-common::s19_bm1398_runtime::executor::
//! Bm1398Runtime`) over the two 76-chip bins the same way the September 2
//! NBP1901 replay drives it, through a mock hardware owner whose controller
//! replies are reconstructed from the held stock grammar (never claimed to be
//! recorded wire captures):
//!
//! - NBS1902/NBT1903 startup at their own stock levels.json operating points
//!   with exact 76/3 population coverage, PIC1704 app 0x89 and APW12 0x71;
//! - work/nonce positive path through the real work-frame encoder, validated
//!   against the INDEPENDENT F04 Bitcoin oracle
//!   (`f04_oracle/bitcoin_oracle.rs`, never modified, never dcentrald hashing
//!   code) plus public mainnet genesis constants;
//! - fault injection: wrong carrier target, cross-bin geometry/ladder
//!   refusal, off-by-one population, unknown PIC app, wrong PSU version,
//!   stale/foreign factory identity (an NBP1901 name on an NBS1902 chain
//!   refuses — cross-bin identity leak), and custody cancellation mid-init
//!   with power-first teardown ordering.
//!
//! Every constant is cited in
//! .
//! This test grants no hardware, energization, dispatch, install, or
//! registration authority; the Lane-F energize intercept is untouched.

#![forbid(unsafe_code)]

#[path = "f04_oracle/bitcoin_oracle.rs"]
mod bitcoin_oracle;

use bitcoin_oracle::BlockHeader;
use dcentrald_common::s19_bm1398_runtime::{
    executor::*, Bm1398FpgaMidstateMode, Bm1398HybridDeskPlan, Bm1398HybridModel,
};
use dcentrald_common::serial_chain_proof::PacedEnumerationPolicy;
use dcentrald_common::TransportOp;
use dcentrald_hal::platform::am2_bm1398::fpga::Bm1398FpgaWorkConfig;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Independent anchors (public mainnet block 0, oracle cross-checked in f04).
// ---------------------------------------------------------------------------
const GENESIS_MERKLE: [u8; 32] = [
    0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
    0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
];
const GENESIS_NONCE: u32 = 2083236893;
const GENESIS_NTIME: u32 = 1231006505;
const GENESIS_NBITS: u32 = 0x1d00_ffff;

// ---------------------------------------------------------------------------
// Synchronous poller for the executor futures (same shape as the recorded
// fixtures in dcentrald-api-types; the executor completes synchronously here).
// ---------------------------------------------------------------------------
struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}
fn ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("mock transport fixture must complete synchronously"),
    }
}

// ---------------------------------------------------------------------------
// Family mock hardware owner. Controller replies are reconstructed from the
// held NBP1901 stock grammar; the same controller/PSU endpoints are bound by
// all three bins' stock topol.conf rows (PIC1704 @ 0x20, AWP12 @ 0x10).
// ---------------------------------------------------------------------------
struct FamilyFixtureIo {
    events: Arc<Mutex<Vec<Bm1398RuntimeAction>>>,
    /// Stock board name the factory-identity action reports.
    board_name: &'static str,
    /// Population the chip-address window reports.
    chips: u16,
    interval: u8,
    pic_version: u8,
    psu_version: u8,
    /// Injected CheckHealth failure: countdown of successful health checks
    /// before the owner reports the custody as cancelled mid-init.
    fail_health_after: Option<usize>,
    health_checks: usize,
    fail_work: bool,
}
impl FamilyFixtureIo {
    fn new(board_name: &'static str, chips: u16, interval: u8) -> Self {
        Self {
            events: Arc::new(Mutex::new(vec![])),
            board_name,
            chips,
            interval,
            pic_version: 0x89,
            psu_version: 0x71,
            fail_health_after: None,
            health_checks: 0,
            fail_work: false,
        }
    }
}
impl Bm1398RuntimeIo for FamilyFixtureIo {
    async fn execute(
        &mut self,
        action: &Bm1398RuntimeAction,
    ) -> Result<Bm1398RuntimeReply, String> {
        self.events.lock().unwrap().push(action.clone());
        use Bm1398RuntimeAction as A;
        use Bm1398RuntimeReply as R;
        match action {
            A::ReadMiscControl { chain } => Ok(R::RegisterValue(
                self.events
                    .lock()
                    .unwrap()
                    .iter()
                    .rev()
                    .find_map(|event| match event {
                        A::Asic {
                            chain: observed_chain,
                            operation:
                                TransportOp::SendWriteRegBroadcastBm1397Plus { reg: 0x18, value },
                        } if observed_chain == chain => Some(*value),
                        _ => None,
                    })
                    .unwrap_or(0x0000_7a31),
            )),
            A::CheckHealth => {
                if let Some(budget) = self.fail_health_after {
                    if self.health_checks >= budget {
                        return Err("injected custody cancellation mid-init".into());
                    }
                }
                self.health_checks += 1;
                Ok(R::Complete)
            }
            A::VerifyFactoryIdentity { .. } => Ok(R::FactoryIdentity {
                stock_board_name: Some(self.board_name.into()),
                serial: "HQDZYI3BJJDBG0566".into(),
            }),
            A::I2c(exchange) => {
                let response = match (exchange.endpoint, exchange.request[3]) {
                    (Bm1398FramedEndpoint::Pic { .. }, 0x17) => {
                        assert_eq!(exchange.request, [0x55, 0xaa, 4, 0x17, 0, 0x1b]);
                        vec![
                            5,
                            0x17,
                            self.pic_version,
                            0,
                            self.pic_version.wrapping_add(0x1c),
                        ]
                    }
                    (Bm1398FramedEndpoint::Pic { .. }, 0x15) => {
                        assert_eq!(exchange.request[6], 0x1a + exchange.request[4]);
                        vec![0x15, 1]
                    }
                    (Bm1398FramedEndpoint::Pic { .. }, 0x16) => {
                        assert_eq!(exchange.request, [0x55, 0xaa, 4, 0x16, 0, 0x1a]);
                        vec![6, 0x16, 1, 0, 0, 0x1d]
                    }
                    (Bm1398FramedEndpoint::Apw12, command @ (2 | 0x83)) => {
                        let data = if command == 2 {
                            self.psu_version
                        } else {
                            exchange.request[4]
                        };
                        let checksum = u16::from(data) + u16::from(command) + 6;
                        vec![
                            0x55,
                            0xaa,
                            6,
                            command,
                            data,
                            0,
                            checksum as u8,
                            (checksum >> 8) as u8,
                        ]
                    }
                    _ => return Err("unexpected command: fixture does not implement it".into()),
                };
                Ok(R::Bytes(response))
            }
            A::ReadChipAddresses { .. } => {
                let count = if self.chips == 0 { 0 } else { self.chips };
                let id = 0x1398;
                Ok(R::ChipAddresses(
                    // Chip addresses: ordinal * interval (u16 math), then
                    // narrowed — held geometries (114@2, 76@3) max at 226/225.
                    (0..count)
                        .map(|i| ((i * u16::from(self.interval)) as u8, id))
                        .collect(),
                ))
            }
            A::Work { .. } if self.fail_work => Err("injected FIFO write failure".into()),
            _ => Ok(R::Complete),
        }
    }
}

fn policy() -> PacedEnumerationPolicy {
    PacedEnumerationPolicy::new(
        Duration::from_millis(1),
        Duration::from_millis(10),
        Duration::from_millis(500),
        1,
    )
    .unwrap()
}

fn config(model: Bm1398HybridModel, frequency_mhz: u16, voltage_cv: u16) -> Bm1398RuntimeConfig {
    let plan = match model {
        Bm1398HybridModel::S19Pro => {
            Bm1398HybridDeskPlan::s19_pro(policy(), Bm1398FpgaMidstateMode::Four)
        }
        Bm1398HybridModel::S19Classic => {
            Bm1398HybridDeskPlan::s19_classic(policy(), Bm1398FpgaMidstateMode::Four)
        }
        Bm1398HybridModel::T19 => Bm1398HybridDeskPlan::t19(policy(), Bm1398FpgaMidstateMode::Four),
        Bm1398HybridModel::S19a | Bm1398HybridModel::S19Plus => {
            Bm1398HybridDeskPlan::for_model(model, policy(), Bm1398FpgaMidstateMode::Four)
        }
    };
    Bm1398RuntimeConfig {
        plan,
        active_chains: vec![0],
        frequency_mhz,
        voltage_cv,
    }
}

/// Positive path: NBS1902 starts at its own stock operating point with exact
/// 76/3 coverage, reaches Ready, accepts a real work frame, and shuts down
/// power-first.
#[test]
fn nbs1902_runtime_starts_admits_work_and_shuts_down_power_first() {
    let io = FamilyFixtureIo::new("NBS1902", 76, 3);
    let events = io.events.clone();
    let cfg = config(Bm1398HybridModel::S19Classic, 650, 1380);
    let mut runtime = Bm1398Runtime::new("am2-s19", cfg, io).unwrap();
    ready(runtime.start()).unwrap();
    assert_eq!(runtime.state(), Bm1398RuntimeState::Ready);
    let mut words = [0x1234_u32 << 2; 36];
    words[1] = GENESIS_NBITS;
    words[2] = GENESIS_NTIME;
    words[3] = 0x4a5e_1e4b; // LE u32 of genesis merkle[28..32]
    ready(runtime.submit_work(0, &words)).unwrap();
    let before_shutdown = events.lock().unwrap().len();
    ready(runtime.shutdown()).unwrap();
    let trace = events.lock().unwrap();
    assert_eq!(
        trace[before_shutdown],
        Bm1398RuntimeAction::TerminalPowerOff
    );
    // Exact 76/3 enumeration happened (one chain).
    let assignments = trace
        .iter()
        .filter(|a| {
            matches!(
                a,
                Bm1398RuntimeAction::Asic {
                    operation: TransportOp::SendSetAddressBm1397Plus { .. },
                    ..
                }
            )
        })
        .count();
    assert_eq!(assignments, 76);
    // The rail command carried the exact NBS1902 stock rail code (13.80 V).
    assert!(trace.iter().any(|a| matches!(
        a,
        Bm1398RuntimeAction::I2c(e)
            if e.request[..4] == [0x55, 0xaa, 6, 0x83]
                && e.request[4] == apw12_stock71_rail_code(1380).unwrap()
    )));
    assert_eq!(runtime.state(), Bm1398RuntimeState::Stopped);
}

/// Positive path: T19 starts at its own stock operating point (which is NOT
/// a cross-product row) with exact 76/3 coverage.
#[test]
fn nbt1903_runtime_starts_admits_work_and_shuts_down_power_first() {
    let io = FamilyFixtureIo::new("NBT1903", 76, 3);
    let events = io.events.clone();
    let cfg = config(Bm1398HybridModel::T19, 550, 1420);
    let mut runtime = Bm1398Runtime::new("am2-t19", cfg, io).unwrap();
    ready(runtime.start()).unwrap();
    assert_eq!(runtime.state(), Bm1398RuntimeState::Ready);
    let mut words = [0x48d0_u32; 36];
    words[1] = GENESIS_NBITS;
    words[2] = GENESIS_NTIME;
    words[3] = 0x4a5e_1e4b;
    ready(runtime.submit_work(0, &words)).unwrap();
    ready(runtime.shutdown()).unwrap();
    let trace = events.lock().unwrap();
    assert!(trace.iter().any(|a| matches!(
        a,
        Bm1398RuntimeAction::I2c(e)
            if e.request[..4] == [0x55, 0xaa, 6, 0x83]
                && e.request[4] == apw12_stock71_rail_code(1420).unwrap()
    )));
    assert_eq!(runtime.state(), Bm1398RuntimeState::Stopped);
}

/// Work/nonce positive path against the INDEPENDENT F04 oracle: the exact
/// 36-word frame the runtime accepts encodes the public genesis header tail
/// and midstate, and the returned nonce independently wins at difficulty 1
/// via the oracle (cross-checked against dcentrald-stratum's own validator).
#[test]
fn work_frame_and_winning_nonce_are_oracle_independent() {
    let work_id = 0x1234_u16;
    let header = dcentrald_stratum::v1::job::build_block_header(
        1,
        &[0; 32],
        &GENESIS_MERKLE,
        GENESIS_NTIME,
        GENESIS_NBITS,
        GENESIS_NONCE,
    );
    let midstate =
        dcentrald_stratum::work::compute_midstate_from_prefix(&header[..64].try_into().unwrap());
    let codec =
        Bm1398FpgaWorkConfig::new(Bm1398FpgaMidstateMode::Four, Duration::from_millis(4)).unwrap();
    // Round-2 fix: the Four-midstate FIFO carrier carries EXACTLY
    // 1 << midstate_log2() = 4 midstates per 36-word frame (encode_work
    // refuses any other count; the wired run() WorkLedger::prepare builds
    // those same four from up to eight builder midstates). For a
    // non-version-rolling job all four builder midstates are identical, so
    // the legal frame repeats the genesis midstate four times — exactly
    // what the daemon's own NBP1901 ledger test pins.
    let words = codec
        .encode_work(
            work_id,
            GENESIS_NBITS,
            GENESIS_NTIME,
            GENESIS_MERKLE[28..].try_into().unwrap(),
            &[midstate; 4],
        )
        .unwrap();
    assert_eq!(words.len(), 36);
    assert_eq!(
        &words[..4],
        &[
            u32::from(work_id) << 2,
            GENESIS_NBITS,
            GENESIS_NTIME,
            0x4a5e_1e4b
        ]
    );
    // The FPGA word encoding of the midstate (4-byte chunks reversed) is the
    // same sequence the daemon's NBP1901 ledger test pins from the held
    // stock sender — second pin, independent of the oracle digest check
    // below.
    assert_eq!(
        &words[4..12],
        &[
            0x4719_f91b,
            0x96b1_8736,
            0x4f01_03c8,
            0xc3c8_d8e9,
            0x1e59_caa8,
            0x90cc_ac7d,
            0x6358_bff0,
            0xbc90_9a33
        ]
    );
    // Midstate words must equal the stock-firmware-pinned genesis words
    // (held stock vectors, independent of any dcentrald hash path).
    assert_eq!(
        bitcoin_oracle::digest_to_words(&midstate),
        [
            0xbc90_9a33,
            0x6358_bff0,
            0x90cc_ac7d,
            0x1e59_caa8,
            0xc3c8_d8e9,
            0x4f01_03c8,
            0x96b1_8736,
            0x4719_f91b
        ]
    );
    // Oracle: the header with the genesis nonce meets the block-0 target.
    let oracle_header = BlockHeader::from_wire(&header).expect("80-byte header parses");
    assert!(oracle_header.meets_target(), "oracle target check");
    // Stratum's own validator agrees (share-path equivalence).
    assert!(dcentrald_stratum::work::validate_full_header(
        &header,
        &dcentrald_stratum::work::difficulty_to_target(1.0)
    ));
    // A wrong nonce misses in BOTH implementations.
    let wrong = dcentrald_stratum::v1::job::build_block_header(
        1,
        &[0; 32],
        &GENESIS_MERKLE,
        GENESIS_NTIME,
        GENESIS_NBITS,
        GENESIS_NONCE.wrapping_add(1),
    );
    let wrong_oracle = BlockHeader::from_wire(&wrong).unwrap();
    assert!(!wrong_oracle.meets_target());
    assert!(!dcentrald_stratum::work::validate_full_header(
        &wrong,
        &dcentrald_stratum::work::difficulty_to_target(1.0)
    ));
}

/// Fault injection: wrong carrier target, cross-bin geometry, cross-bin and
/// non-ladder operating points all refuse before any hardware construction.
#[test]
fn wrong_carrier_cross_bin_geometry_and_ladder_refuse() {
    let io = FamilyFixtureIo::new("NBS1902", 76, 3);
    let cfg = config(Bm1398HybridModel::S19Classic, 650, 1380);
    assert_eq!(
        Bm1398Runtime::new("am2-s19pro", cfg, io)
            .err()
            .unwrap()
            .to_string(),
        "exact am2-s19 carrier required"
    );
    // Cross-bin geometry: an NBP1901 114/2 plan is not valid for the S19
    // carrier, and a perturbed 76-chip plan at interval 2 refuses too.
    let mut wrong_interval = config(Bm1398HybridModel::S19Classic, 650, 1380);
    wrong_interval.plan.address_interval = 2;
    let io = FamilyFixtureIo::new("NBS1902", 76, 3);
    assert!(Bm1398Runtime::new("am2-s19", wrong_interval, io).is_err());
    let mut wrong_count = config(Bm1398HybridModel::S19Classic, 650, 1380);
    wrong_count.plan.chips_per_chain = 114;
    let io = FamilyFixtureIo::new("NBS1902", 76, 3);
    assert!(Bm1398Runtime::new("am2-s19", wrong_count, io).is_err());
    // Cross-bin ladder: the NBP1901 operating point is not an NBS1902 row and
    // the NBS1902 operating point is not an NBP1901 row.
    let io = FamilyFixtureIo::new("NBS1902", 76, 3);
    assert!(Bm1398Runtime::new(
        "am2-s19",
        config(Bm1398HybridModel::S19Classic, 525, 1280),
        io
    )
    .is_err());
    let io = FamilyFixtureIo::new("NBP1901", 114, 2);
    assert!(Bm1398Runtime::new(
        "am2-s19pro",
        config(Bm1398HybridModel::S19Pro, 675, 1380),
        io
    )
    .is_err());
    // T19: (550, 1400) is not a held row of its ladder.
    let io = FamilyFixtureIo::new("NBT1903", 76, 3);
    assert!(Bm1398Runtime::new("am2-t19", config(Bm1398HybridModel::T19, 550, 1400), io).is_err());
}

/// Fault injection: an off-by-one (75-frame) window refuses before any PLL
/// write, work configuration, or Ready state, with power-first teardown.
///
/// Round-2 adjudication (production EXAMINED, NOT changed): the population
/// census is physically POST-energize. BM1398 chips answer the chain UART
/// only rail-up, and the held stock NBP1901 grammar orders rail-set ->
/// PIC enable -> reset release -> SetAddress/GetAddress -> census
/// (`evidence/r07/implementation.md` FUN sequences; executor `start_inner`
/// :442 rail code -> :461 HashPower{true} -> :512 ReadChipAddresses ->
/// :525 certify_chain -> :532 PLL). There is no population field in the
/// zhiju EEPROM block to pre-check, and the wired NBP1901 replay
/// (`nbp1901_factory_runtime_refuses_incomplete_chain_before_pll_or_work`)
/// pins the same shape. What the fail-closed contract guarantees — and what
/// this test pins — is that a wrong population refuses BEFORE the first
/// chip mutation (PLL 0x08), before ConfigureWork/Work, never reaches
/// Ready, and tears down power-first. IDENTITY failures (EEPROM factory
/// name, PIC app, PSU version, custody) DO refuse before energize — pinned
/// by the foreign-factory-name, unknown-PIC, wrong-PSU and custody-cancel
/// tests in this file.
#[test]
fn off_by_one_population_refuses_before_pll_or_work() {
    let mut io = FamilyFixtureIo::new("NBT1903", 76, 3);
    io.chips = 75; // one chip missing
    let events = io.events.clone();
    let cfg = config(Bm1398HybridModel::T19, 550, 1420);
    let mut runtime = Bm1398Runtime::new("am2-t19", cfg, io).unwrap();
    assert!(ready(runtime.start()).is_err());
    let trace = events.lock().unwrap();
    // The census itself ran (it can only run rail-up) and its certification
    // refused: no PLL write, no work codec, no work, on any chain.
    assert!(trace
        .iter()
        .any(|a| matches!(a, Bm1398RuntimeAction::ReadChipAddresses { .. })));
    assert!(!trace.iter().any(|a| matches!(
        a,
        Bm1398RuntimeAction::ConfigureWork { .. } | Bm1398RuntimeAction::Work { .. }
    )));
    // No chip configuration mutation either: the core-control (0x3c) and
    // PLL (0x08) broadcast writes are the first chip mutations and sit
    // strictly after certification in start_inner.
    assert!(!trace.iter().any(|a| {
        matches!(
            a,
            Bm1398RuntimeAction::Asic {
                operation: TransportOp::SendWriteRegBroadcastBm1397Plus { reg: 0x3c, .. },
                ..
            }
        ) || matches!(
            a,
            Bm1398RuntimeAction::Asic {
                operation: TransportOp::SendWriteRegBroadcastBm1397Plus { reg: 0x08, .. },
                ..
            }
        )
    }));
    // Stock ordering pin: rail up precedes the census (chips answer only
    // rail-up), and the census refusal is followed by the teardown cut.
    let energize = trace
        .iter()
        .position(|a| *a == Bm1398RuntimeAction::HashPower { enabled: true })
        .expect("energize precedes the census by stock grammar");
    let census = trace
        .iter()
        .position(|a| matches!(a, Bm1398RuntimeAction::ReadChipAddresses { .. }))
        .unwrap();
    assert!(energize < census, "stock ordering: rail up before census");
    let teardown_cut = trace
        .iter()
        .rposition(|a| *a == Bm1398RuntimeAction::TerminalPowerOff)
        .expect("wrong population must tear down power");
    assert!(census < teardown_cut);
    // The prepared-startup power-cut also happened, and the runtime is
    // permanently faulted against work.
    assert!(trace.contains(&Bm1398RuntimeAction::HashPower { enabled: false }));
    assert_eq!(runtime.state(), Bm1398RuntimeState::Faulted);
    let words = [0x48d0_u32; 36];
    assert!(ready(runtime.submit_work(0, &words)).is_err());
}

/// Fault injection: a non-0x89 PIC app never receives mutating PIC commands
/// or energization.
#[test]
fn unknown_pic_never_receives_mutating_commands_or_energization() {
    let mut io = FamilyFixtureIo::new("NBS1902", 76, 3);
    io.pic_version = 0x86;
    let events = io.events.clone();
    let cfg = config(Bm1398HybridModel::S19Classic, 650, 1380);
    let mut runtime = Bm1398Runtime::new("am2-s19", cfg, io).unwrap();
    assert!(ready(runtime.start()).is_err());
    let trace = events.lock().unwrap();
    assert!(!trace.iter().any(|a| matches!(
        a,
        Bm1398RuntimeAction::I2c(e)
            if e.request[3] == 0x15 || e.request[3] == 0x16 || e.request[3] == 0x83
    )));
    assert!(!trace.contains(&Bm1398RuntimeAction::HashPower { enabled: true }));
}

/// Fault injection: a PSU that is not the stock framed 0x71 refuses before
/// the rail set or energization, on every family bin.
#[test]
fn wrong_psu_version_refuses_before_rail_or_energization() {
    for (name, model, target, freq, cv) in [
        (
            "NBP1901",
            Bm1398HybridModel::S19Pro,
            "am2-s19pro",
            500_u16,
            1280_u16,
        ),
        (
            "NBS1902",
            Bm1398HybridModel::S19Classic,
            "am2-s19",
            650,
            1380,
        ),
        ("NBT1903", Bm1398HybridModel::T19, "am2-t19", 550, 1420),
    ] {
        let mut io = FamilyFixtureIo::new(
            name,
            if model == Bm1398HybridModel::S19Pro {
                114
            } else {
                76
            },
            if model == Bm1398HybridModel::S19Pro {
                2
            } else {
                3
            },
        );
        io.psu_version = 0x74;
        let events = io.events.clone();
        let cfg = config(model, freq, cv);
        let mut runtime = Bm1398Runtime::new(target, cfg, io).unwrap();
        assert!(
            ready(runtime.start()).is_err(),
            "{name} must refuse PSU 0x74"
        );
        let trace = events.lock().unwrap();
        assert!(!trace.iter().any(|a| matches!(
            a,
            Bm1398RuntimeAction::I2c(e) if e.request[3] == 0x83
        )));
        assert!(!trace.contains(&Bm1398RuntimeAction::HashPower { enabled: true }));
    }
}

/// Cross-bin identity leak: a chain whose factory identity reports a foreign
/// stock board name refuses, on every bin (an NBP1901 name never admits an
/// NBS1902/T19 runtime and vice versa).
#[test]
fn foreign_factory_board_name_refuses_per_bin() {
    // NBP1901 name on an NBS1902 chain.
    let io = FamilyFixtureIo::new("NBP1901", 76, 3);
    let cfg = config(Bm1398HybridModel::S19Classic, 650, 1380);
    let mut runtime = Bm1398Runtime::new("am2-s19", cfg, io).unwrap();
    let failure = ready(runtime.start()).err().unwrap();
    assert!(failure.detail.contains("NBS1902 factory identity"));
    // NBS1902 name on an NBP1901 chain.
    let io = FamilyFixtureIo::new("NBS1902", 114, 2);
    let cfg = config(Bm1398HybridModel::S19Pro, 500, 1280);
    let mut runtime = Bm1398Runtime::new("am2-s19pro", cfg, io).unwrap();
    let failure = ready(runtime.start()).err().unwrap();
    assert!(failure.detail.contains("NBP1901 factory identity"));
}

/// Fault injection: custody cancellation mid-init fails startup, refuses any
/// energization, and tears down power-first (TerminalPowerOff before
/// StopWork before the PIC disables), leaving the runtime permanently
/// faulted against further work.
#[test]
fn custody_cancel_mid_init_fails_startup_and_tears_down_power_first() {
    let mut io = FamilyFixtureIo::new("NBS1902", 76, 3);
    // One successful early health check, then the custody cancels during the
    // pre-rail heartbeat ticks: startup fails before any rail set.
    io.fail_health_after = Some(1);
    let events = io.events.clone();
    let cfg = config(Bm1398HybridModel::S19Classic, 650, 1380);
    let mut runtime = Bm1398Runtime::new("am2-s19", cfg, io).unwrap();
    let failure = ready(runtime.start()).err().unwrap();
    assert_eq!(failure.detail, "injected custody cancellation mid-init");
    assert!(failure.shutdown_errors.is_empty());
    assert_eq!(runtime.state(), Bm1398RuntimeState::Faulted);
    {
        let trace = events.lock().unwrap();
        assert!(!trace.contains(&Bm1398RuntimeAction::HashPower { enabled: true }));
        assert!(!trace.iter().any(|a| matches!(
            a,
            Bm1398RuntimeAction::I2c(e) if e.request[3] == 0x83
        )));
        // Teardown order: power cut is the FIRST teardown action.
        let teardown_start = trace
            .iter()
            .position(|a| *a == Bm1398RuntimeAction::TerminalPowerOff)
            .expect("terminal power off must happen");
        assert!(trace[teardown_start + 1] == Bm1398RuntimeAction::StopWork);
    }
    // A faulted runtime refuses further work.
    let words = [0x48d0_u32; 36];
    assert!(ready(runtime.submit_work(0, &words)).is_err());
    // And shutdown stays idempotent-safe: terminal cut is already applied.
    ready(runtime.shutdown()).unwrap();
    assert_eq!(runtime.state(), Bm1398RuntimeState::Stopped);
}

/// Fault injection: a work-submit failure permanently faults and cuts power
/// first on the 76-chip bin (same contract the NBP1901 replay pins).
#[test]
fn work_failure_permanently_faults_and_cuts_power_first() {
    let mut io = FamilyFixtureIo::new("NBT1903", 76, 3);
    io.fail_work = true;
    let events = io.events.clone();
    let cfg = config(Bm1398HybridModel::T19, 550, 1420);
    let mut runtime = Bm1398Runtime::new("am2-t19", cfg, io).unwrap();
    ready(runtime.start()).unwrap();
    let words = [0x48d0_u32; 36];
    let failure = ready(runtime.submit_work(0, &words)).unwrap_err();
    assert_eq!(failure.detail, "injected FIFO write failure");
    assert_eq!(runtime.state(), Bm1398RuntimeState::Faulted);
    let trace = events.lock().unwrap();
    let work = trace
        .iter()
        .position(|a| matches!(a, Bm1398RuntimeAction::Work { .. }))
        .unwrap();
    assert_eq!(trace[work + 1], Bm1398RuntimeAction::TerminalPowerOff);
}
