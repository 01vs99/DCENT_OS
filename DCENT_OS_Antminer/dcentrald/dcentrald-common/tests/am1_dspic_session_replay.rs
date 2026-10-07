//! Captured-byte integration replay for the AM1 framed dsPIC33EP adapter
//! (`dcentrald_common::am1_dspic_adapter`).
//!
//! Every expected TX byte below is the exact stock sequence disassembled from
//! held T9+ `bmminer` (SHA-256 `f9a9d255880dc144907490c0efed943864c8f4eceb579
//! a052bcfeab713681815`, byte-at-a-time writes through
//! `T9_plus_write_pic_iic@0x2cf7c`); every scripted RX byte is the exact
//! reply shape the stock reader admits. These are DESK replays of captured
//! wire shapes, not live captures — no miner is contacted, no hardware is
//! opened, and no rail is moved by this file.
//!
//! Board coverage:
//! - `am1-t9plus` (framed dsPIC33EP, 9 chains / 3 PIC groups): full session
//!   replay — firmware read, heartbeat stability gate, staged voltage, enable.
//! - `am1-s9` / `am1-s9i` / `am1-s9j` (bare PIC16 law, held S9j bmminer
//!   SHA-256 `03e19bc31dd51330604d746ce9bf4dbb3d29b69a1461915a2c7ecb773828854a`):
//!   wrong-board refusal — the adapter must never be constructed for them and
//!   the S9 bare frames (`55 AA 15 01` / `55 AA 16`, FPGA-IIC word base
//!   `0x00A00000`) must never appear as adapter output.

use dcentrald_common::am1_dspic_adapter::*;

// ---------------------------------------------------------------------------
// Scripted raw-bus transport: plays recorded replies and records the full
// event transcript (writes, read lengths, waits) for exact-byte assertions.
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Write(Vec<u8>),
    Read(usize),
    Wait(u32),
}

struct ScriptedWire {
    /// Scripted read results, consumed in order (NoReply when exhausted).
    replies: Vec<Result<Vec<u8>, WireFailure>>,
    /// Recorded transcript.
    events: Vec<Event>,
}

impl ScriptedWire {
    fn new(replies: Vec<Result<Vec<u8>, WireFailure>>) -> Self {
        Self {
            replies,
            events: Vec::new(),
        }
    }

    fn writes(&self) -> Vec<&[u8]> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Write(b) => Some(b.as_slice()),
                _ => None,
            })
            .collect()
    }

    fn waits(&self) -> Vec<u32> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Wait(ms) => Some(*ms),
                _ => None,
            })
            .collect()
    }

    fn reads(&self) -> Vec<usize> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Read(n) => Some(*n),
                _ => None,
            })
            .collect()
    }
}

impl PicWire for ScriptedWire {
    fn write(&mut self, bytes: &[u8]) -> Result<(), WireFailure> {
        self.events.push(Event::Write(bytes.to_vec()));
        Ok(())
    }

    fn read(&mut self, len: usize) -> Result<Vec<u8>, WireFailure> {
        self.events.push(Event::Read(len));
        if self.replies.is_empty() {
            Err(WireFailure::NoReply)
        } else {
            self.replies.remove(0)
        }
    }

    fn wait_ms(&mut self, ms: u32) {
        self.events.push(Event::Wait(ms));
    }
}

// ---------------------------------------------------------------------------
// Scripted reply factories (exact stock reply shapes)
// ---------------------------------------------------------------------------

/// Version reply for firmware byte 0x89: `[5, 0x17, 0x89, crc_hi, crc_lo]`,
/// crc = 5 + 0x17 + 0x89 = 0x00A5.
fn fw_ok_0x89() -> Result<Vec<u8>, WireFailure> {
    Ok(vec![0x05, 0x17, 0x89, 0x00, 0xA5])
}

/// Version reply carrying the corruption marker 0x86: crc = 5+0x17+0x86 = 0xA2.
fn fw_corrupt_0x86() -> Result<Vec<u8>, WireFailure> {
    Ok(vec![0x05, 0x17, 0x86, 0x00, 0xA2])
}

/// Heartbeat reply: byte 0 ignored (stock reads it and never checks it),
/// `reply[1] == 0x16`, `reply[2] == 0x01`.
fn hb_ok() -> Result<Vec<u8>, WireFailure> {
    Ok(vec![0x00, 0x16, 0x01, 0x00, 0x00, 0x00])
}

/// Unacknowledged heartbeat reply (status byte != 0x01).
fn hb_bad() -> Result<Vec<u8>, WireFailure> {
    Ok(vec![0x00, 0x16, 0x00, 0x00, 0x00, 0x00])
}

/// Two-byte echo ack for the set-voltage (0x10) command.
fn ack_0x10() -> Result<Vec<u8>, WireFailure> {
    Ok(vec![0x10, 0x01])
}

/// Two-byte echo ack for the enable dc-dc (0x15) command.
fn ack_0x15() -> Result<Vec<u8>, WireFailure> {
    Ok(vec![0x15, 0x01])
}

// ---------------------------------------------------------------------------
// Expected TX frames — exact held stock byte sequences (T9+ disassembly)
// ---------------------------------------------------------------------------

const TX_VERSION: &[u8] = &[0x55, 0xAA, 0x04, 0x17, 0x00, 0x1B];
const TX_HEARTBEAT: &[u8] = &[0x55, 0xAA, 0x04, 0x16, 0x00, 0x1A];
/// PIC byte 4 = the held-law encoding of 910 cV (9.10 V); crc = 7+0x10+4.
const TX_SET_VOLTAGE_4: &[u8] = &[0x55, 0xAA, 0x07, 0x10, 0x04, 0x00, 0x00, 0x00, 0x1B];
const TX_ENABLE_1: &[u8] = &[0x55, 0xAA, 0x05, 0x15, 0x01, 0x00, 0x1B];
const TX_ENABLE_0: &[u8] = &[0x55, 0xAA, 0x05, 0x15, 0x00, 0x00, 0x1A];

#[test]
fn t9plus_full_session_replays_the_held_stock_wire_shapes() {
    // Firmware read -> five stable heartbeats -> staged voltage -> enable.
    let mut wire = ScriptedWire::new(vec![
        fw_ok_0x89(),
        hb_ok(),
        hb_ok(),
        hb_ok(),
        hb_ok(),
        hb_ok(),
        ack_0x10(),
        ack_0x15(),
    ]);
    let mut session = Am1DsPicSession::new(&mut wire);

    assert_eq!(session.read_firmware(), Ok(0x89));
    assert_eq!(
        session.firmware_state(),
        Some(FirmwareState::Framed { version: 0x89 })
    );
    for _ in 0..HEARTBEAT_TICKS_BEFORE_VOLTAGE {
        session.heartbeat_once().expect("heartbeat must acknowledge");
    }
    assert!(session.heartbeat_gate().voltage_permitted());
    // 910 cV (9.10 V) encodes to PIC byte 4 under the held stock law.
    assert_eq!(session.set_voltage(910), Ok(4));
    session.enable_dc_dc(1).expect("enable must acknowledge");

    // Exact transcript: writes in order, stock waits, stock reply lengths.
    assert_eq!(
        wire.writes(),
        vec![
            TX_VERSION,
            TX_HEARTBEAT,
            TX_HEARTBEAT,
            TX_HEARTBEAT,
            TX_HEARTBEAT,
            TX_HEARTBEAT,
            TX_SET_VOLTAGE_4,
            TX_ENABLE_1,
        ]
    );
    // read_firmware(100ms) + 5 heartbeats (500ms each) + set_voltage(100ms)
    // + enable(10ms) — the exact stock usleep values.
    assert_eq!(wire.waits(), vec![100, 500, 500, 500, 500, 500, 100, 10]);
    // version: 5 bytes; heartbeat: 6 bytes x5; the two acks: 2 bytes each.
    assert_eq!(wire.reads(), vec![5, 6, 6, 6, 6, 6, 2, 2]);
}

#[test]
fn voltage_is_refused_until_five_consecutive_heartbeats_and_resets_on_failure() {
    // Firmware admitted, but heartbeats come first (workspace rule: NEVER
    // send SET_VOLTAGE before 5 stable heartbeat ticks).
    let mut wire = ScriptedWire::new(vec![
        fw_ok_0x89(),
        hb_ok(),
        hb_ok(),
        hb_ok(),
        hb_ok(), // 4 clean ticks: still below the gate
        hb_bad(), // unacknowledged tick: consecutive count resets to zero
        hb_ok(),
        hb_ok(),
        hb_ok(),
        hb_ok(),
        hb_ok(), // five fresh clean ticks
        ack_0x10(),
    ]);
    let mut session = Am1DsPicSession::new(&mut wire);
    session.read_firmware().expect("firmware read");

    assert_eq!(
        session.set_voltage(910),
        Err(SessionError::VoltageBeforeStableHeartbeats {
            stable: 0,
            required: 5
        })
    );
    for _ in 0..4 {
        session.heartbeat_once().expect("heartbeat");
        assert!(!session.heartbeat_gate().voltage_permitted());
    }
    assert_eq!(session.heartbeat_gate().stable_ticks(), 4);
    assert_eq!(
        session.heartbeat_once(),
        Err(SessionError::HeartbeatUnacknowledged)
    );
    assert_eq!(session.heartbeat_gate().stable_ticks(), 0);
    assert_eq!(
        session.set_voltage(910),
        Err(SessionError::VoltageBeforeStableHeartbeats {
            stable: 0,
            required: 5
        })
    );

    for _ in 0..HEARTBEAT_TICKS_BEFORE_VOLTAGE {
        session.heartbeat_once().expect("heartbeat");
    }
    assert!(session.heartbeat_gate().voltage_permitted());
    assert_eq!(session.set_voltage(910), Ok(4));
}

#[test]
fn fw_0x86_is_refused_and_blocks_energizing_but_never_a_disable() {
    let mut wire = ScriptedWire::new(vec![fw_corrupt_0x86(), ack_0x15(), hb_ok(), hb_ok(), hb_ok(), hb_ok(), hb_ok()]);
    let mut session = Am1DsPicSession::new(&mut wire);

    assert_eq!(
        session.read_firmware(),
        Err(SessionError::CorruptionMarker0x86)
    );
    assert_eq!(session.firmware_state(), None);
    // Raising the rail is refused on the corruption marker.
    assert_eq!(
        session.enable_dc_dc(1),
        Err(SessionError::CorruptionMarker0x86)
    );
    // Cutting the rail must remain possible: DISABLE is not gated on healthy
    // firmware once the corruption has been discovered by the version read.
    session.enable_dc_dc(0).expect("disable must stay permitted");
    // SET_VOLTAGE stays refused even behind five clean heartbeats.
    for _ in 0..HEARTBEAT_TICKS_BEFORE_VOLTAGE {
        session.heartbeat_once().expect("heartbeat telemetry");
    }
    assert!(session.heartbeat_gate().voltage_permitted());
    assert_eq!(
        session.set_voltage(910),
        Err(SessionError::CorruptionMarker0x86)
    );
    drop(session);
    // writes[0] = the corrupted version probe; writes[1] = the enable(0)
    // disable frame; writes[2..] = the five heartbeat keepalives. The
    // enable(1) raise never touched the wire.
    assert_eq!(wire.writes()[1], TX_ENABLE_0);
}

#[test]
fn nack_flushes_sixteen_zero_bytes_then_retries_within_stock_budget() {
    // First version attempt NACKs, retry succeeds. The transcript must show
    // the framed frame, then exactly 16 zero bytes, then the retry frame.
    let mut wire = ScriptedWire::new(vec![Err(WireFailure::Nack), fw_ok_0x89()]);
    let mut session = Am1DsPicSession::new(&mut wire);
    assert_eq!(session.read_firmware(), Ok(0x89));

    let writes = wire.writes();
    assert_eq!(writes.len(), 3);
    assert_eq!(writes[0], TX_VERSION);
    assert_eq!(writes[1], &[0u8; NACK_FLUSH_BYTES][..]);
    assert_eq!(writes[2], TX_VERSION);
}

#[test]
fn exhaustive_nack_fails_closed_after_three_attempts_with_three_flushes() {
    let mut wire = ScriptedWire::new(vec![
        Err(WireFailure::Nack),
        Err(WireFailure::Nack),
        Err(WireFailure::Nack),
    ]);
    let mut session = Am1DsPicSession::new(&mut wire);
    assert_eq!(
        session.read_firmware(),
        Err(SessionError::WireExhausted { attempts: 3 })
    );
    // The failed firmware read leaves the session unadmitted and the
    // energizing path fail-closed.
    assert_eq!(session.firmware_state(), None);
    assert_eq!(
        session.set_voltage(910),
        Err(SessionError::FirmwareNotAdmitted)
    );
    drop(session);
    // frame, flush, frame, flush, frame, flush = 6 writes.
    let writes = wire.writes();
    assert_eq!(writes.len(), 6);
    for (i, w) in writes.iter().enumerate() {
        if i % 2 == 0 {
            assert_eq!(*w, TX_VERSION);
        } else {
            assert_eq!(*w, &[0u8; NACK_FLUSH_BYTES][..]);
        }
    }
}

#[test]
fn wrong_board_refusal_keeps_s9_pic16_frames_off_this_adapter() {
    // S9 / S9i / S9j run the bare PIC16 law (held S9j bmminer): the adapter
    // refuses construction for them BY NAME, naming the bare-law conflict.
    assert_eq!(admit_board("am1-t9plus"), Ok(()));
    for target in ["am1-s9", "am1-s9i", "am1-s9j"] {
        assert_eq!(admit_board(target), Err(WrongBoardError::S9Pic16BareLaw));
    }
    assert_eq!(
        admit_board("am1-s9se"),
        Err(WrongBoardError::UnsupportedTarget)
    );
    assert_eq!(admit_board("am1-s11"), Err(WrongBoardError::UnsupportedTarget));
    assert_eq!(admit_board(""), Err(WrongBoardError::UnsupportedTarget));

    // Negative fixtures hold the exact held S9j bytes...
    assert_eq!(S9_PIC16_BARE_ENABLE_FRAME, [0x55, 0xAA, 0x15, 0x01]);
    assert_eq!(S9_PIC16_BARE_HEARTBEAT_FRAME, [0x55, 0xAA, 0x16]);
    assert_eq!(S9_PIC16_FPGA_IIC_WORD_BASE, 0x00A0_0000);
    // ...and no adapter frame ever equals or starts with them.
    for command in [
        AdapterCommand::SetVoltage { pic_byte: 1 },
        AdapterCommand::EnableDcDc { enable: 1 },
        AdapterCommand::Heartbeat,
        AdapterCommand::GetSoftwareVersion,
    ] {
        let frame = pack_command(command);
        assert!(
            !frame.starts_with(&S9_PIC16_BARE_ENABLE_FRAME),
            "adapter frame must never begin with the S9 bare enable: {frame:?}"
        );
        assert!(
            !frame.starts_with(&S9_PIC16_BARE_HEARTBEAT_FRAME),
            "adapter frame must never begin with the S9 bare heartbeat: {frame:?}"
        );
        assert_ne!(frame.as_slice(), &S9_PIC16_BARE_ENABLE_FRAME[..]);
        assert_ne!(frame.as_slice(), &S9_PIC16_BARE_HEARTBEAT_FRAME[..]);
    }
}

#[test]
fn nine_chain_group_topology_gates_match_held_remainder_law() {
    // 9 chains / 3 groups: heartbeat on chain%3==0, enable on chain%3==2.
    for group in 0..3u8 {
        assert_eq!(chain_group(group * 3), Ok(group));
        assert_eq!(heartbeat_chain_gate(group * 3), Ok(true));
        assert_eq!(heartbeat_chain_gate(group * 3 + 1), Ok(false));
        assert_eq!(heartbeat_chain_gate(group * 3 + 2), Ok(false));
        assert_eq!(enable_chain_gate(group * 3), Ok(false));
        assert_eq!(enable_chain_gate(group * 3 + 1), Ok(false));
        assert_eq!(enable_chain_gate(group * 3 + 2), Ok(true));
    }
    assert_eq!(
        chain_group(9),
        Err(ChainError::OutOfPopulation { chain: 9 })
    );
    assert_eq!(chain_group(T9PLUS_CHAINS - 1), Ok(T9PLUS_PIC_GROUPS - 1));
}

#[test]
fn staged_voltage_ramp_clamps_exactly_at_target_like_change_pic_voltage_old() {
    // change_pic_voltage_old@0x34648: +5 per step, clamped at the target.
    assert!(voltage_ramp_steps(4, 4).is_empty());
    assert_eq!(voltage_ramp_steps(4, 14), vec![9, 14]);
    assert_eq!(voltage_ramp_steps(14, 4), vec![9, 4]);
    assert_eq!(voltage_ramp_steps(4, 6), vec![6]);
}
