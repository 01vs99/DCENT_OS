// SPDX-License-Identifier: GPL-3.0-or-later
//! R05 captured-byte replay of the S17-family PIC controller dialects.
//!
//! Campaign `2026-09-07-antminer-beta-execution`, task R05 (2026-09-11).
//! Every byte vector below is derived from held stock binaries:
//!
//!
//!   (factory jig): `set_dsPIC33EP16GS202_voltage@23D40`,
//!   `set_PIC16F1704_voltage@22AB8`, `heart_beat_dsPIC33EP16GS202@24190`,
//!   `heart_beat_PIC16F1704@22F58`, `get_PIC16F1704_software_version@2302C`,
//!   `enable_PIC16F1704_dc_dc@22E6C`.
//!
//!   (production S17 bmminer `1404e188…`: bus0 `0x20|slot` bytewise framed
//!   ops, 500 ms settle, six-byte heartbeat reply, `[0x15, 0x01]` enable ACK;
//!   APW9 bus1 `0x10` via register `0x11`, SUM_LE16).
//!
//! The module under test is the EXACT production leaf
//! (`dcentrald/src/s17_wire.rs`) included by path — not a copy.
//!
//! Coverage: per-dialect captured-byte init replay, NACK + flush-16-zeros
//! recovery accounting, SET_VOLTAGE-before-5-heartbeats refusal, bounded
//! timeout, corrupt-reply fail-closed, fw=0x86 / loader 0xCC refusals with no
//! destructive opcode on the wire, APW9 DAC law and frame, partial-population
//! enumeration refusals, and source contracts for the hardware-bound fault
//! gates (cancel mid-phase, stale sensor) that need a live rig.

#![forbid(unsafe_code)]

#[path = "../src/s17_wire.rs"]
mod s17_wire;

#[path = "r05_support/s17_scripted_wire.rs"]
mod scripted;

use scripted::{framed_reply_bytes, I2cFault, ScriptedS17I2cWire};
use s17_wire::{
    apw9_dac_for_bitmain_cv, apw9_dac_for_volts, apw9_set_dac_frame, clamp_pic_voltage_cv,
    discover_divisor, dspic_g2a_checksum, dspic_g2a_frame, dspic_g2a_set_voltage_frame,
    framed_reply, pic16_g2b_set_voltage_frame, s17_pic_i2c_addr, ChainIo,
    S17PicControllerClass, S17PicFirmwareState, S17VoltageExecutor, S17_APW9_I2C_ADDR,
    S17_EEPROM_WRITE_DENYLIST, S17_PSU_WATCHDOG_CMD_ABSENT,
    S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE,
};

const CHAIN1_ADDR: u8 = 0x21;

// ---------------------------------------------------------------------------
// Captured-byte constants (hand-derived from the jig .dec, checksum law
// SUM16-BE over LEN+CMD+payload)
// ---------------------------------------------------------------------------

/// `heart_beat_*@24190/@22F58`: identical no-payload frame for both classes.
const HEARTBEAT_FRAME: [u8; 6] = [0x55, 0xAA, 0x04, 0x16, 0x00, 0x1A];
/// `get_PIC16F1704_software_version@2302C` (dsPIC form is identical).
const GET_VERSION_FRAME: [u8; 6] = [0x55, 0xAA, 0x04, 0x17, 0x00, 0x1B];
/// `enable_PIC16F1704_dc_dc@22E6C` with enable=1 (dsPIC enable is the same
/// one-payload-byte framed form; production enable ACK `[0x15, 0x01]`).
const ENABLE_FRAME: [u8; 7] = [0x55, 0xAA, 0x05, 0x15, 0x01, 0x00, 0x1B];
/// Production safe-off (corrections doc: `55 aa 05 15 00 00 1a`).
const SAFE_OFF_FRAME: [u8; 7] = [0x55, 0xAA, 0x05, 0x15, 0x00, 0x00, 0x1A];
/// dsPIC G2a SET_VOLTAGE `VV=0xA0` (`set_dsPIC33EP16GS202_voltage@23D40`:
/// LEN=7, payload `A0 00 00`, ck = 7+0x10+0xA0 = 0xB7).
const G2A_SET_VOLTAGE_A0: [u8; 9] = [0x55, 0xAA, 0x07, 0x10, 0xA0, 0x00, 0x00, 0x00, 0xB7];
/// PIC16 G2b SET_VOLTAGE `VV=0x5A` (`set_PIC16F1704_voltage@22AB8`: LEN=5,
/// ONE payload byte, ck = 5+0x10+0x5A = 0x6F).
const G2B_SET_VOLTAGE_5A: [u8; 7] = [0x55, 0xAA, 0x05, 0x10, 0x5A, 0x00, 0x6F];

/// GET_VERSION reply, byte-exact per the payload-length law:
/// `[05 17 FW ck16]` — five bytes, ONE payload byte, ck16 = 5 + 0x17 + FW
/// (jig `get_PIC16F1704_software_version@2302C` reads five bytes and checks
/// `read_back_data[0]==5`, `read_back_data[1]==23`, checksum `FW + 28`;
/// production `parse_ds_pic_version_reply` requires `payload.len() == 1`
/// and `probe_firmware` reads exactly 5 bytes). fw=0x82 →
/// `[05 17 82 00 9E]`, the same vector the hybrid unit tests pin.
fn version_reply(fw: u8) -> Vec<u8> {
    framed_reply_bytes(0x17, &[fw])
}

/// HEARTBEAT reply, byte-exact: `[06 16 01 00 1D]` — six bytes, payload
/// `[0x01, 0x00]`, ck16 = 6 + 0x16 + 1 + 0 = 0x1D (jig
/// `heart_beat_*@24190/@22F58` read six bytes and check `bytes[1]==0x16 &&
/// bytes[2]==1`; identical to the vector pinned by the hybrid unit tests).
fn heartbeat_reply() -> Vec<u8> {
    framed_reply_bytes(0x16, &[0x01, 0x00])
}

/// Script a complete positive session: version probe, five stable
/// heartbeats, one SET_VOLTAGE. The frame law is class-independent, so only
/// the SET_VOLTAGE bytes differ per dialect.
fn scripted_positive_session(
    fw: u8,
    set_voltage_frame: &[u8],
) -> ScriptedS17I2cWire {
    let mut wire = ScriptedS17I2cWire::new();
    wire.expect(CHAIN1_ADDR, &GET_VERSION_FRAME, version_reply(fw));
    for _ in 0..S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE {
        wire.expect(CHAIN1_ADDR, &HEARTBEAT_FRAME, heartbeat_reply());
    }
    wire.expect(CHAIN1_ADDR, set_voltage_frame, vec![0x10, 0x01]);
    wire
}

fn run_positive_session(
    class: S17PicControllerClass,
    fw: u8,
    vv: u8,
    set_voltage_frame: &[u8],
) -> ScriptedS17I2cWire {
    let mut wire = scripted_positive_session(fw, set_voltage_frame);
    let mut executor = S17VoltageExecutor::new(class, 1, wire);
    let state = executor.probe_firmware().unwrap();
    assert_eq!(state, S17PicFirmwareState::App { version: fw });
    for _ in 0..S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE {
        executor.heartbeat().unwrap();
    }
    executor.set_voltage_code(vv).unwrap();
    executor.wire
}

// ---------------------------------------------------------------------------
// Per-controller-class captured-byte replay of the init/voltage session
// ---------------------------------------------------------------------------

#[test]
fn g2a_dspic_session_replays_captured_bytes() {
    let wire = run_positive_session(
        S17PicControllerClass::DsPicG2aFramed,
        0x82,
        0xA0,
        &G2A_SET_VOLTAGE_A0,
    );
    let writes: Vec<(u8, Vec<u8>)> = wire.log.clone();
    assert_eq!(writes.len(), 7, "version + 5 heartbeats + set_voltage");
    assert_eq!(writes[0], (CHAIN1_ADDR, GET_VERSION_FRAME.to_vec()));
    for (addr, frame) in &writes[1..6] {
        assert_eq!(*addr, CHAIN1_ADDR);
        assert_eq!(frame, &HEARTBEAT_FRAME.to_vec());
    }
    assert_eq!(writes[6], (CHAIN1_ADDR, G2A_SET_VOLTAGE_A0.to_vec()));
    // No destructive opcode (JUMP 0x06 / RESET 0x07 / ERASE 0x09) ever went
    // out on the wire.
    for (_, frame) in &writes {
        assert!(!matches!(frame.get(3), Some(0x06 | 0x07 | 0x09)));
    }
}

#[test]
fn g2b_pic16_session_replays_captured_bytes() {
    let wire = run_positive_session(
        S17PicControllerClass::Pic16G2bFramed,
        0x89,
        0x5A,
        &G2B_SET_VOLTAGE_5A,
    );
    let writes: Vec<(u8, Vec<u8>)> = wire.log.clone();
    assert_eq!(writes.len(), 7);
    assert_eq!(writes[0], (CHAIN1_ADDR, GET_VERSION_FRAME.to_vec()));
    assert_eq!(writes[6], (CHAIN1_ADDR, G2B_SET_VOLTAGE_5A.to_vec()));
    // Dialect separation: the plus-family SET_VOLTAGE is the one-payload-byte
    // form; the dsPIC three-byte form must never leak onto the G2b wire.
    assert_ne!(&writes[6].1, &G2A_SET_VOLTAGE_A0.to_vec());
    assert_eq!(writes[6].1.len(), 7, "LEN=5 frame carries exactly one payload byte");
}

#[test]
fn checksum_law_and_frame_builders_agree_with_the_jig_vectors() {
    assert_eq!(dspic_g2a_checksum(0x04, 0x17, &[]), 0x001B);
    assert_eq!(dspic_g2a_checksum(0x05, 0x10, &[0x5A]), 0x006F);
    assert_eq!(dspic_g2a_checksum(0x07, 0x10, &[0xA0, 0, 0]), 0x00B7);
    // Jig enable=1 form (`enable_PIC16F1704_dc_dc@22E6C`): ck = 5+0x15+1.
    assert_eq!(dspic_g2a_frame(0x15, &[0x01]), ENABLE_FRAME.to_vec());
    assert_eq!(dspic_g2a_set_voltage_frame(0xA0), G2A_SET_VOLTAGE_A0.to_vec());
    assert_eq!(pic16_g2b_set_voltage_frame(0x5A), G2B_SET_VOLTAGE_5A.to_vec());
    // A1 §V3 held example: `55 AA 07 10 A0 00 01 00 B8` sums to 0x00B8.
    assert_eq!(dspic_g2a_checksum(0x07, 0x10, &[0xA0, 0x00, 0x01]), 0x00B8);
    for chain in 0u8..3 {
        assert_eq!(s17_pic_i2c_addr(chain), 0x20 | chain);
    }
}

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

#[test]
fn set_voltage_before_five_stable_heartbeats_is_refused_before_any_wire_write() {
    let mut wire = ScriptedS17I2cWire::new();
    wire.expect(CHAIN1_ADDR, &GET_VERSION_FRAME, version_reply(0x82));
    for _ in 0..4 {
        wire.expect(CHAIN1_ADDR, &HEARTBEAT_FRAME, heartbeat_reply());
    }
    let mut executor =
        S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 1, wire);
    executor.probe_firmware().unwrap();
    for _ in 0..4 {
        executor.heartbeat().unwrap();
    }
    let error = executor.set_voltage_code(0xA0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("5 stable heartbeats required"));
    // Probe + four clean heartbeats reached the wire; the refused
    // SET_VOLTAGE added nothing (no voltage byte escaped).
    assert_eq!(executor.wire.transaction_count(), 5);
}

#[test]
fn heartbeat_nack_resets_stability_and_the_sixteen_zero_flush_recovers_the_session() {
    // Probe + three good heartbeats succeed, then the FOURTH heartbeat is
    // NACKed (`after_writes: 4` — faults fire after N successful
    // transactions, per the f04 report §3.2 interface).
    let mut wire = ScriptedS17I2cWire::new();
    wire.expect(CHAIN1_ADDR, &GET_VERSION_FRAME, version_reply(0x82));
    for _ in 0..3 {
        wire.expect(CHAIN1_ADDR, &HEARTBEAT_FRAME, heartbeat_reply());
    }
    wire.inject(I2cFault::Nack { after_writes: 4 });
    // Recovery script: five FRESH heartbeats (the counter restarted) and the
    // SET_VOLTAGE.
    for _ in 0..S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE {
        wire.expect(CHAIN1_ADDR, &HEARTBEAT_FRAME, heartbeat_reply());
    }
    wire.expect(CHAIN1_ADDR, &G2A_SET_VOLTAGE_A0, vec![0x10, 0x01]);

    let mut executor =
        S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 1, wire);
    executor.probe_firmware().unwrap();
    for _ in 0..3 {
        executor.heartbeat().unwrap();
    }
    // The NACKed heartbeat fails closed and resets the stability counter.
    let error = executor.heartbeat().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    assert_eq!(executor.wire.nack_events, 1);
    assert_eq!(executor.wire.transaction_count(), 5);

    // Rule #25: the caller (production: NativeHardware::pic on the same
    // serialized bus owner) flushes 16 zero bytes to the same address.
    executor.wire.flush_after_nack(CHAIN1_ADDR);
    assert_eq!(executor.wire.flush_events, 1);
    assert_eq!(
        executor.wire.flush_log[0],
        (CHAIN1_ADDR, vec![0u8; 16]),
        "the flush must be exactly sixteen zero bytes to the NACKed PIC"
    );

    // The refusals stay until stability is re-established.
    let error = executor.set_voltage_code(0xA0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

    // Recovery: five fresh stable heartbeats admit the same SET_VOLTAGE,
    // replaying the captured bytes.
    for _ in 0..S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE {
        executor.heartbeat().unwrap();
    }
    executor.set_voltage_code(0xA0).unwrap();
    let last = executor.wire.log.last().unwrap();
    assert_eq!(last.1, G2A_SET_VOLTAGE_A0.to_vec());
}

#[test]
fn silent_pic_times_out_bounded_exactly_at_the_attempt_budget() {
    let mut wire = ScriptedS17I2cWire::new();
    wire.inject(I2cFault::SilentTimeout { after_writes: 0 });
    wire.inject(I2cFault::SilentTimeout { after_writes: 0 });
    wire.inject(I2cFault::SilentTimeout { after_writes: 0 });
    let mut executor =
        S17VoltageExecutor::new(S17PicControllerClass::Pic16G2bFramed, 0, wire);
    let error = executor.heartbeat_bounded(3).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(
        executor.wire.transaction_count(),
        3,
        "exactly the bounded attempts, never an unbounded retry loop"
    );
}

#[test]
fn corrupt_version_reply_fails_closed_without_further_writes() {
    let mut wire = ScriptedS17I2cWire::new();
    wire.expect(CHAIN1_ADDR, &GET_VERSION_FRAME, version_reply(0x82));
    wire.inject(I2cFault::ReplyCorrupt {
        xor: 0x40,
        after_writes: 0,
    });
    let mut executor =
        S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 1, wire);
    let error = executor.probe_firmware().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    // The failed probe was the only transaction; the executor never got to a
    // mutating command with uncorrelated replies.
    assert_eq!(executor.wire.transaction_count(), 1);
}

#[test]
fn degraded_dspic_fw_0x86_is_refused_and_loader_0xcc_is_never_jumped() {
    for (class, fw, expected) in [
        (
            S17PicControllerClass::DsPicG2aFramed,
            0x86,
            S17PicFirmwareState::DegradedDspic,
        ),
        (
            S17PicControllerClass::Pic16G2bFramed,
            0xCC,
            S17PicFirmwareState::LoaderMode,
        ),
    ] {
        let mut wire = ScriptedS17I2cWire::new();
        wire.expect(CHAIN1_ADDR, &GET_VERSION_FRAME, version_reply(fw));
        for _ in 0..S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE {
            wire.expect(CHAIN1_ADDR, &HEARTBEAT_FRAME, heartbeat_reply());
        }
        let mut executor = S17VoltageExecutor::new(class, 1, wire);
        assert_eq!(executor.probe_firmware().unwrap(), expected);
        // Reach the firmware adjudication: the five-heartbeat gate passes
        // first, then the degraded/loader firmware refusal fires.
        for _ in 0..S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE {
            executor.heartbeat().unwrap();
        }
        let error = executor.set_voltage_code(0xA0).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        let message = error.to_string();
        if fw == 0x86 {
            assert!(message.contains("0x86"), "{message}");
        } else {
            assert!(message.contains("loader mode"), "{message}");
        }
        for (_, frame) in &executor.wire.log {
            assert!(!matches!(frame.get(3), Some(0x06 | 0x07 | 0x09)));
        }
    }
}

#[test]
fn safe_off_is_always_wire_available_for_both_classes() {
    for class in [
        S17PicControllerClass::DsPicG2aFramed,
        S17PicControllerClass::Pic16G2bFramed,
    ] {
        let mut wire = ScriptedS17I2cWire::new();
        wire.expect(0x20, &SAFE_OFF_FRAME, vec![0x15, 0x01]);
        let mut executor = S17VoltageExecutor::new(class, 0, wire);
        executor.safe_off().unwrap();
        assert_eq!(executor.wire.log[0], (0x20, SAFE_OFF_FRAME.to_vec()));
    }
}

// ---------------------------------------------------------------------------
// Reply parser and APW9 law
// ---------------------------------------------------------------------------

#[test]
fn framed_reply_parser_correlates_length_opcode_and_checksum() {
    // Version replies carry exactly ONE payload byte (the firmware byte);
    // heartbeat replies carry exactly TWO (`[ack, padding]`).
    assert_eq!(framed_reply(&version_reply(0x82), 0x17).unwrap(), [0x82u8]);
    assert_eq!(
        framed_reply(&heartbeat_reply(), 0x16).unwrap(),
        [0x01u8, 0x00]
    );
    // Wrong opcode, truncated frame, and broken checksum all fail closed.
    assert!(framed_reply(&heartbeat_reply(), 0x17).is_err());
    assert!(framed_reply(&[0x16, 0x01], 0x16).is_err());
    let mut corrupt = version_reply(0x82);
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(framed_reply(&corrupt, 0x17).is_err());
}

#[test]
fn apw9_frame_and_dac_law_match_the_production_source_anchors() {
    // Corrections doc worked example: DAC 156 → `55 aa 06 83 9c 00 25 01`,
    // checksum little-endian (0x0125), on bus 1 address 0x10 register 0x11.
    assert_eq!(
        apw9_set_dac_frame(156),
        vec![0x55, 0xAA, 0x06, 0x83, 0x9C, 0x00, 0x25, 0x01]
    );
    assert_eq!(S17_APW9_I2C_ADDR, 0x10);
    // DAC law anchors: 17.00 V → 156; saturation at both rails.
    assert_eq!(apw9_dac_for_volts(17.0), 156);
    assert_eq!(apw9_dac_for_bitmain_cv(1700), 156);
    assert_eq!(apw9_dac_for_volts(14.24), 255);
    assert_eq!(apw9_dac_for_volts(21.36), 0);
    // The big-endian checksum construction (the superseded A1 reading) is a
    // DIFFERENT frame: the byte order must never regress to BE.
    let dac = apw9_set_dac_frame(156);
    assert_eq!(
        (dac[6], dac[7]),
        (0x25, 0x01),
        "checksum must stay little-endian"
    );
}

#[test]
fn pic_voltage_envelope_and_eeprom_denylist_hold() {
    assert!(clamp_pic_voltage_cv(1850).is_ok());
    assert!(clamp_pic_voltage_cv(1799).is_err());
    assert!(clamp_pic_voltage_cv(2101).is_err());
    assert_eq!(S17_EEPROM_WRITE_DENYLIST, [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57]);
    assert_eq!(S17_PSU_WATCHDOG_CMD_ABSENT, 0x84);
}

// ---------------------------------------------------------------------------
// Population profiles: 48 / 65 / 30 / 44
// ---------------------------------------------------------------------------

/// Fake chain for enumeration replay: pushes BM1397 GetAddress replies at one
/// specific divisor.
#[derive(Default)]
struct EnumChain {
    divisor: u32,
    replies: std::collections::VecDeque<[u8; 8]>,
    commands: Vec<Vec<u8>>,
    enumerate_at: u32,
    chips: u8,
    overrun: u8,
}

impl EnumChain {
    fn new(divisor: u32, chips: u8, overrun: u8) -> Self {
        Self {
            divisor,
            enumerate_at: divisor,
            chips,
            overrun,
            ..Self::default()
        }
    }
}

impl ChainIo for EnumChain {
    fn set_divisor(&mut self, divisor: u32) {
        self.divisor = divisor;
    }
    fn divisor(&self) -> u32 {
        self.divisor
    }
    fn command(&mut self, bytes: &[u8]) {
        self.commands.push(bytes.to_vec());
        if bytes == [0x52, 5, 0, 0] && self.divisor == self.enumerate_at {
            for _ in 0..self.chips + self.overrun {
                self.replies.push_back([0x13, 0x97, 0x18, 0, 0, 0, 0, 0]);
            }
        }
    }
    fn register_reply(&mut self) -> Option<[u8; 8]> {
        self.replies.pop_front()
    }
    fn work_full(&self) -> bool {
        false
    }
    fn write_work(&mut self, _words: &[u32; 36]) -> anyhow::Result<()> {
        Ok(())
    }
    fn nonce(&mut self) -> Option<[u32; 2]> {
        None
    }
    fn flush_work(&mut self) {
        self.replies.clear();
    }
}

/// Per-target chips-per-chain, pinned here from A1 §V2 / the corrections doc
/// (S17 Pro shares the 48-chip BHB07601 geometry; T17+ is 44, never 45).
const POPULATIONS: [(&str, u8, u8); 4] = [
    ("am2-s17p", 48, 5),
    ("am2-s17plus", 65, 3),
    ("am2-t17", 30, 8),
    ("am2-t17plus", 44, 5),
];

#[tokio::test]
async fn complete_enumeration_accepts_every_advertised_population() {
    for (target, chips, _stride) in POPULATIONS {
        let mut chain = EnumChain::new(7, chips, 0);
        let divisor = discover_divisor(&mut chain, chips)
            .await
            .unwrap_or_else(|error| panic!("{target}: {error:#}"));
        assert_eq!(divisor, 7, "{target}");
        // Two complete read-only GetAddress rounds were required.
        let enumerate_commands = chain
            .commands
            .iter()
            .filter(|command| command.as_slice() == [0x52, 5, 0, 0])
            .count();
        assert_eq!(enumerate_commands, 2, "{target}");
    }
}

#[tokio::test]
async fn partial_population_never_promotes_a_divisor() {
    for (target, chips, _) in [("am2-s17p", 48u8, 5u8), ("am2-s17plus", 65, 3)] {
        let mut chain = EnumChain::new(7, chips - 1, 0);
        let error = discover_divisor(&mut chain, chips)
            .await
            .expect_err("a missing chip must refuse the divisor");
        assert!(error.to_string().contains("two complete"), "{target}: {error:#}");
    }
}

#[tokio::test]
async fn enumeration_overrunning_the_geometry_fails_closed() {
    // One extra reply must be a hard refusal, never a truncated acceptance.
    let mut chain = EnumChain::new(7, 44, 1);
    let error = discover_divisor(&mut chain, 44).await.unwrap_err();
    assert!(error.to_string().contains("exceeds exact geometry"), "{error:#}");
}

// ---------------------------------------------------------------------------
// Source contracts for the hardware-bound fault gates
// ---------------------------------------------------------------------------

const NATIVE_RUNTIME: &str = include_str!("../src/s17_native_runtime.rs");

#[test]
fn cancel_and_stale_sensor_guards_stay_in_the_hardware_path() {
    // Cancellation is checked between every per-chain phase and before
    // thermal sampling; the mining loop takes shutdown biased-first.
    assert!(NATIVE_RUNTIME.contains("S17 bringup cancelled"));
    assert!(NATIVE_RUNTIME.contains("_ = miner.shutdown.cancelled()"));
    // Stale/corrupt sensor replies are bounded and correlated: the sensor
    // engine retries a busy/error status three times, then refuses.
    assert!(NATIVE_RUNTIME.contains("S17 sensor I2C engine remained busy/error"));
    assert!(NATIVE_RUNTIME.contains("S17 sensor register response mismatch"));
    // The NACK flush is issued by the serialized bus owner on every error.
    assert!(NATIVE_RUNTIME.contains("vec![0; 16]"));
}
