// SPDX-License-Identifier: GPL-3.0-or-later
//! S17-family BM1397 wire-dialect leaf: controller frames, reply parsing,
//! APW9 PSU law, the fail-closed voltage executor, the chain I/O seam and the
//! work ledger.
//!
//! R05 runtime lane, campaign `2026-09-07-antminer-beta-execution` (2026-09-11).
//! This module is a DEPENDENCY-FREE leaf at the `dcentrald` crate level: it
//! references only external workspace crates (`dcentrald_common`,
//! `dcentrald_asic`, `dcentrald_stratum`) and std/tokio/anyhow, so the
//! `tests/r05_*.rs` integration targets can `#[path]`-include this exact file
//! and replay captured bytes against the production implementation instead of
//! a re-implemented copy.
//!
//! ## Evidence authorities (byte-exact, held binaries only)
//!
//! - `S17/single-board-test.dec`:
//!   factory-jig pre-decompilation carrying BOTH controller dialects:
//!   `set_dsPIC33EP16GS202_voltage@23D40` (G2a SET_VOLTAGE `55 AA 07 10 VV 00
//!   00 SUM16-BE`), `set_PIC16F1704_voltage@22AB8` (G2b SET_VOLTAGE `55 AA 05
//!   10 VV SUM16-BE` — ONE payload byte), `heart_beat_dsPIC33EP16GS202@24190` /
//!   `heart_beat_PIC16F1704@22F58` (`55 AA 04 16 00 1A`; reply checked at
//!   bytes[1]==0x16 && bytes[2]==1), `get_PIC16F1704_software_version@2302C`
//!   (reply `[05 17 FW ck]`, ck = 5+0x17+FW), `enable_PIC16F1704_dc_dc@22E6C`
//!   (`55 AA 05 15 EN ck`, ACK `[15 01]`, 100 ms pre-read / 500 ms post-OK).
//! - `2026-09-07_NATIVE_RUNTIME_SOURCE_CORRECTIONS.md`
//!: the PRODUCTION S17 bmminer
//!   (`1404e188...`) runs the same framed law bytewise at bus0 `0x20|slot`
//!   with 500 ms settle (`0x7354c..0x7374c`), six-byte heartbeat replies
//!   (`0x7392c`), `[0x15, 0x01]` enable ACK (`0x7386c`), APW9 on bus 1 addr
//!   `0x10` byte-per-register `0x11` with SUM_LE16 (`0x741ec..0x74290`), DAC
//!   law `765.411764 − 35.833333×V` (`0x742a0..0x742b7`). Both plus-family
//!   production binaries (`dcf2eccf...`, `4cda35ac...`) carry the same APW9
//!   transport/law. The historical A3 §2 "PIC16 raw S9 frames `55 AA 10 VV`"
//!   model is superseded by the jig's framed one-payload-byte form.
//! - A3 §2 gpdasm of `S17+PIC.hex`: the plus-family APPLICATION dispatch is
//!   `{0x07, 0x15, 0x16, 0x17, 0x35, 0x36, 0x37}` — opcode `0x10` is NOT in
//!   the held production plus-family dispatch, so production voltage flows
//!   through the APW9 DAC (both production paths) and PIC `0x15` owns the
//!   board enable. The G2b `set_voltage` frame below is the jig-captured wire
//!   form for bench/lab executors; the native positive path never sends it.
//! - Work/nonce: `dcentrald-asic/src/drivers/bm1397.rs` (`decode_nonce`,
//!   `ctrl_reg_value`, `ticket_mask`, `pll_params`) and the held RTL
//!   `bm13xx_core.vhd` lines 830..852 (FPGA work-ID high-bit reconstruction;
//!   16384 host work IDs, low 2 bits = midstate index).

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, anyhow, Result};

use dcentrald_asic::drivers::{bm1397::Bm1397Driver, ChipDriver};
use dcentrald_common::VoltageControllerClass;
use dcentrald_stratum::types::ValidShare;
use dcentrald_stratum::work::MiningWork;

// ---------------------------------------------------------------------------
// Controller classes and addressing
// ---------------------------------------------------------------------------

/// The two S17-family voltage-controller application ABIs. Both use the same
/// bytewise framed law `55 AA LEN CMD payload SUM16-BE` (the 2026-08-27
/// armada falsified a full frame-level fork); they differ in the SET_VOLTAGE
/// payload width (G2a three bytes `VV 00 00`, G2b one byte `VV` — jig
/// `set_dsPIC33EP16GS202_voltage@23D40` vs `set_PIC16F1704_voltage@22AB8`)
/// and in the physical controller part (dsPIC33EP16GS202 vs PIC16F1704).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S17PicControllerClass {
    /// dsPIC33EP16GS202 (am2-s17p, am2-t17).
    DsPicG2aFramed,
    /// PIC16F1704 (am2-s17plus, am2-t17plus).
    Pic16G2bFramed,
}

impl S17PicControllerClass {
    /// Map the BoardDesc adapter class to the wire class (None ⇒ not an
    /// S17-family plan).
    pub fn from_voltage_controller(controller: VoltageControllerClass) -> Option<Self> {
        match controller {
            VoltageControllerClass::DsPic33Ep => Some(Self::DsPicG2aFramed),
            VoltageControllerClass::Pic16F1704 => Some(Self::Pic16G2bFramed),
            _ => None,
        }
    }

    /// Production settle around one framed controller transaction.
    ///
    /// G2a: 500 ms production settle (corrections table `0x7354c..0x7374c`).
    /// G2b: the held jig paces 100 ms before bytewise reads and 500 ms after
    /// an accepted enable (`enable_PIC16F1704_dc_dc@22E6C`); the production
    /// plus-family PIC pacing is not held, so the runtime uses the same
    /// conservative 500 ms production settle for both classes.
    pub const fn settle_after_command(self) -> Duration {
        match self {
            Self::DsPicG2aFramed | Self::Pic16G2bFramed => Duration::from_millis(500),
        }
    }
}

/// Board PIC I²C address on the FPGA bus: `0x20 | (chain & 7)` → 0x20/0x21/0x22
/// (A1 §V1; identical for both classes, confirmed by the production corrections
/// table and both jig dialect functions).
pub const fn s17_pic_i2c_addr(chain: u8) -> u8 {
    0x20 | (chain & 7)
}

// ---------------------------------------------------------------------------
// Framing law and per-class command frames
// ---------------------------------------------------------------------------

/// Framed checksum for both controller classes: `u16` big-endian sum of
/// `LEN + CMD + payload` (jig checksums, e.g. G2b version reply
/// `ck = FW + 28 = 5 + 0x17 + FW`).
pub fn dspic_g2a_checksum(len: u8, cmd: u8, payload: &[u8]) -> u16 {
    u16::from(len) + u16::from(cmd) + payload.iter().map(|&b| u16::from(b)).sum::<u16>()
}

/// Build a framed command (both classes): `55 AA LEN CMD payload CK_HI CK_LO`
/// with `LEN = payload_len + 4` (jig + production corrections).
pub fn dspic_g2a_frame(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let len = (payload.len() + 4) as u8;
    let ck = dspic_g2a_checksum(len, cmd, payload);
    let mut frame = Vec::with_capacity(payload.len() + 6);
    frame.extend_from_slice(&[0x55, 0xAA, len, cmd]);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&ck.to_be_bytes());
    frame
}

/// dsPIC G2a SET_VOLTAGE (CMD `0x10`, payload `[VV, 0x00, 0x00]` — jig
/// `set_dsPIC33EP16GS202_voltage@23D40`: `send_data[2]=7`, `send_data[4]=VV`,
/// `*(_DWORD*)&send_data[4]=VV` zero-fills two bytes, `ck = VV+23`). `vv` is
/// the raw code byte; its cV→code law is an open live item (A1 open items).
pub fn dspic_g2a_set_voltage_frame(vv: u8) -> Vec<u8> {
    dspic_g2a_frame(0x10, &[vv, 0x00, 0x00])
}

/// dsPIC G2a SAFE-OFF / DC-DC off (CMD `0x15`, payload `[0x00]`):
/// `55 AA 05 15 00 00 1A` (corrections doc; production ACK `[0x15, 0x01]`).
pub fn dspic_g2a_safe_off_frame() -> Vec<u8> {
    dspic_g2a_frame(0x15, &[0x00])
}

/// HEARTBEAT (both classes; jig `heart_beat_dsPIC33EP16GS202@24190` /
/// `heart_beat_PIC16F1704@22F58` are byte-identical): `55 AA 04 16 00 1A`,
/// six-byte reply with `reply[1]==0x16 && reply[2]==1`.
pub fn dspic_g2a_heartbeat_frame() -> Vec<u8> {
    dspic_g2a_frame(0x16, &[])
}

/// GET_VERSION (both classes): `55 AA 04 17 00 1B`; framed reply
/// `[05 17 FW ck]` (`get_PIC16F1704_software_version@2302C`).
pub fn dspic_g2a_get_version_frame() -> Vec<u8> {
    dspic_g2a_frame(0x17, &[])
}

/// dsPIC G2a READ RAIL mV (CMD `0x29`; A3 §2: raw BE16 × 3.3/4096 × 7.6).
pub fn dspic_g2a_read_rail_frame() -> Vec<u8> {
    dspic_g2a_frame(0x29, &[])
}

/// dsPIC G2a READ PWM duty (CMD `0x2B`; A3 §2: PDC0/1/2 BE16).
pub fn dspic_g2a_read_pwm_duty_frame() -> Vec<u8> {
    dspic_g2a_frame(0x2B, &[])
}

/// PIC16 G2b SET_VOLTAGE: `55 AA 05 10 VV ck16` with `ck = 5 + 0x10 + VV`
/// (jig `set_PIC16F1704_voltage@22AB8`: `send_data[2]=5`, `send_data[4]=VV`,
/// `ck = VV+21`; reply checked `[0x10, 0x01]`).
///
/// BENCH/LAB ONLY on the plus family: the held production `S17+PIC.hex`
/// application dispatch (A3 §2 gpdasm) is `{0x07,0x15,0x16,0x17,0x35,0x36,
/// 0x37}` and does NOT admit `0x10`. Production plus-family rail selection
/// goes through the APW9 DAC; the native positive path never sends this
/// frame (see `s17_native_runtime.rs` `initialize`).
pub fn pic16_g2b_set_voltage_frame(vv: u8) -> Vec<u8> {
    dspic_g2a_frame(0x10, &[vv])
}

/// PIC16 G2b SAFE-OFF / DC-DC: `55 AA 05 15 EN ck` (jig
/// `enable_PIC16F1704_dc_dc@22E6C`, same one-payload form as the dsPIC
/// disable; disable = EN 0x00 → `55 AA 05 15 00 00 1A`, ACK `[0x15, 0x01]`).
pub fn pic16_g2b_safe_off_frame() -> Vec<u8> {
    dspic_g2a_frame(0x15, &[0x00])
}

/// PIC16 G2b HEARTBEAT: identical framed form to the dsPIC class (jig
/// `heart_beat_PIC16F1704@22F58`).
pub fn pic16_g2b_heartbeat_frame() -> Vec<u8> {
    dspic_g2a_frame(0x16, &[])
}

/// PIC16 G2b GET_VERSION: identical framed form (jig
/// `get_PIC16F1704_software_version@2302C`; reply `[05 17 FW ck]`).
pub fn pic16_g2b_get_version_frame() -> Vec<u8> {
    dspic_g2a_frame(0x17, &[])
}

/// dsPIC33 firmware version that is the proven post-PIC-RESET corruption
/// state — REFUSED for voltage commands (rust-firmware rule #30).
pub const S17_DEGRADED_DSPIC_FW: u8 = 0x86;

/// PIC16 loader-mode GET_VERSION reply — the runtime fails closed (it must
/// not send the JUMP `0x06` op; recovery-tool owns that).
pub const S17_PIC16_LOADER_MODE_FW: u8 = 0xCC;

/// Number of stable heartbeat ticks required before SET_VOLTAGE may be sent
/// (rust-firmware rule #24 — NACK before stability corrupts the PIC parser).
pub const S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE: u32 = 5;

// ---------------------------------------------------------------------------
// Framed reply parsing (both classes)
// ---------------------------------------------------------------------------

/// Parse a framed reply `LEN CMD payload… SUM16-BE` and return its payload.
/// Used by the executor and the native runtime for every correlated reply.
pub fn framed_reply(bytes: &[u8], command: u8) -> Result<&[u8]> {
    ensure!(
        bytes.len() >= 4 && usize::from(bytes[0]) == bytes.len() && bytes[1] == command,
        "S17 PIC reply length/opcode mismatch: {bytes:02x?}"
    );
    let split = bytes.len() - 2;
    let sum: u16 = bytes[..split].iter().map(|&b| u16::from(b)).sum();
    ensure!(
        bytes[split..] == sum.to_be_bytes(),
        "S17 PIC reply checksum mismatch"
    );
    Ok(&bytes[2..split])
}

/// Both production controller classes return a framed 5-byte GET_VERSION
/// reply `[05 17 FW ck]` (jig `get_PIC16F1704_software_version@2302C`).
fn parse_ds_pic_version_reply(reply: &[u8]) -> std::io::Result<u8> {
    let payload = framed_reply(reply, 0x17)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    if payload.len() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "S17 version payload length",
        ));
    }
    Ok(payload[0])
}

fn parse_pic16_version_reply(reply: &[u8]) -> std::io::Result<u8> {
    parse_ds_pic_version_reply(reply)
}

// ---------------------------------------------------------------------------
// APW9 PSU DAC
// ---------------------------------------------------------------------------

/// APW9 PSU I²C address on bus 1 (production power_send_cmd at 0x73f78).
pub const S17_APW9_I2C_ADDR: u8 = 0x10;

/// APW9 DAC-write sub-address (FPGA IIC engine sub-address field; corrections
/// table: each outgoing byte is written through register `0x11`).
pub const S17_APW9_DAC_SUBADDR: u8 = 0x11;

/// APW9 PSU SET DAC frame: `55 AA 06 83 DAC 00 CK_LO CK_HI` with
/// `CK = 0x89 + DAC` little-endian (corrections `0x741ec..0x74290`; template
/// at `0x8a6f0`; for DAC 156 the exact request is `55 aa 06 83 9c 00 25 01`).
pub fn apw9_set_dac_frame(dac: u8) -> Vec<u8> {
    let ck = 0x06u16 + 0x83 + 0x00 + u16::from(dac);
    let mut frame = Vec::with_capacity(8);
    frame.extend_from_slice(&[0x55, 0xAA, 0x06, 0x83, dac, 0x00]);
    frame.extend_from_slice(&ck.to_le_bytes());
    frame
}

/// APW9 DAC law: `uint8(765.411764 − 35.833333 × V)` clamped to `[0, 255]`
/// (f64 literals at `0x742a0..0x742b7`; identical in both plus-family
/// binaries — `0x7f7d8` / `0x7f4e0`). Truncating cast matches the stock
/// `uint8` semantics (V = 17 V → 156). Valid input range 14.24–21.36 V;
/// out-of-range volts clamp rather than wrap — callers must additionally
/// enforce the cV envelope below before asking for a DAC code.
pub fn apw9_dac_for_volts(volts: f64) -> u8 {
    let raw = 765.411_764 - 35.833_333 * volts;
    raw.clamp(0.0, 255.0) as u8
}

/// APW9 DAC from the stock `bitmain-voltage` unit (cV×10 on the PSU bus:
/// 1700 = 17.00 V).
pub fn apw9_dac_for_bitmain_cv(cv: u32) -> u8 {
    apw9_dac_for_volts(f64::from(cv) / 100.0)
}

/// NO PSU watchdog command exists in the 17-family stock (A1 §V3: "PSU
/// watchdog none — no 0x84 template anywhere in stock 17-family"). This
/// constant documents the refusal: unlike the S19j APW121215a 1 Hz heartbeat
/// requirement, the APW9 needs no 0x84 keep-alive, and sending one would be
/// an unproven mutation.
pub const S17_PSU_WATCHDOG_CMD_ABSENT: u8 = 0x84;

// ---------------------------------------------------------------------------
// Voltage envelope (clamps)
// ---------------------------------------------------------------------------

/// Vendor software clamp for the PIC-controlled hashboard input bus in cV
/// (18.0–21.0 V; the S17e-class datum "only the 1800-2100 cV vendor software
/// clamp is statically bounded", `board_desc.rs` AM2_S17E_CLASS_UNCONFIRMED_DATUMS).
pub const S17_PIC_VOLTAGE_MIN_CV: u16 = 1800;
pub const S17_PIC_VOLTAGE_MAX_CV: u16 = 2100;

/// Bring-up point: 500 MHz @ 1850 cV (VNish 2.0.4 all-SKU identical factory
/// conf, A2 §2 — the conservative desk-proven first target).
pub const S17_BRING_UP_FREQ_MHZ: u32 = 500;
pub const S17_BRING_UP_VOLTAGE_CV: u16 = 1850;

/// Clamp a requested PIC bus voltage in cV into the vendor envelope.
/// Out-of-envelope requests are REFUSED (fail-closed), not silently clamped:
/// an operator asking for 15 V or 23 V has the wrong units or the wrong board.
pub fn clamp_pic_voltage_cv(requested_cv: u16) -> Result<u16> {
    if (S17_PIC_VOLTAGE_MIN_CV..=S17_PIC_VOLTAGE_MAX_CV).contains(&requested_cv) {
        Ok(requested_cv)
    } else {
        Err(anyhow!(
            "S17 PIC bus voltage {requested_cv} cV outside the vendor envelope \
             {S17_PIC_VOLTAGE_MIN_CV}..={S17_PIC_VOLTAGE_MAX_CV} cV — refusing (wrong units or wrong board?)"
        ))
    }
}

// ---------------------------------------------------------------------------
// EEPROM write-deny (rust-firmware rule #28)
// ---------------------------------------------------------------------------

/// am2 hashboard EEPROM addresses `0x50..=0x57` — writes denied at the HAL
/// fabric; the S17 hybrid path registers this list before any wire access
/// (same production pattern as the BM1362 engine's
/// `spawn_i2c_service_no_register_touch_with_denylist_and_reserved_preparation`).
pub const S17_EEPROM_WRITE_DENYLIST: [u8; 8] =
    [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57];

// ---------------------------------------------------------------------------
// Fail-closed typed voltage executor
// ---------------------------------------------------------------------------

/// Wire transport for PIC/PSU transactions (host-mockable).
pub trait S17PicWire {
    /// Write `write` to `i2c_addr` and read `read_len` bytes back. Implementors
    /// must apply the EEPROM denylist at their fabric boundary; an `Err`
    /// return models a missing/negative reply.
    fn transact(&mut self, i2c_addr: u8, write: &[u8], read_len: usize)
        -> std::io::Result<Vec<u8>>;
}

/// Adjudicated PIC firmware state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S17PicFirmwareState {
    /// Application firmware byte accepted for voltage commands.
    App { version: u8 },
    /// dsPIC post-corruption state (fw=0x86) — refused unless lab-trusted.
    DegradedDspic,
    /// PIC16 loader mode (0xCC) — always refused; recovery-tool owns the jump.
    LoaderMode,
}

impl S17PicFirmwareState {
    pub fn from_version(class: S17PicControllerClass, version: u8) -> Self {
        if version == S17_PIC16_LOADER_MODE_FW {
            return Self::LoaderMode;
        }
        if class == S17PicControllerClass::DsPicG2aFramed && version == S17_DEGRADED_DSPIC_FW {
            return Self::DegradedDspic;
        }
        Self::App { version }
    }
}

/// Typed, fail-closed voltage executor for one hashboard PIC.
///
/// Invariants:
/// - SET_VOLTAGE is refused until [`S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE`]
///   consecutive heartbeats have succeeded (rule #24).
/// - dsPIC fw=`0x86` and PIC16 loader-mode (`0xCC`) are refused for voltage
///   commands; the executor never sends JUMP/RESET (rule #29).
/// - Any wire error propagates as `Err` — the caller must tear the chain down
///   and flush 16 zero bytes to the PIC after any NACK (rule #25, the native
///   runtime's serialized bus owner does this); there is no silent retry.
pub struct S17VoltageExecutor<W: S17PicWire> {
    class: S17PicControllerClass,
    chain: u8,
    /// Transport; visible so tests can assert the exact captured bytes.
    pub wire: W,
    stable_heartbeats: u32,
    trust_degraded_fw: bool,
    firmware_version: Option<u8>,
}

impl<W: S17PicWire> S17VoltageExecutor<W> {
    pub fn new(class: S17PicControllerClass, chain: u8, wire: W) -> Self {
        Self {
            class,
            chain,
            wire,
            stable_heartbeats: 0,
            trust_degraded_fw: false,
            firmware_version: None,
        }
    }

    /// Lab-only override for the fw=0x86 refusal (rule #30; guard refuses to
    /// combine this with energization).
    pub fn with_trust_degraded_fw(mut self, trusted: bool) -> Self {
        self.trust_degraded_fw = trusted;
        self
    }

    pub const fn i2c_addr(&self) -> u8 {
        s17_pic_i2c_addr(self.chain)
    }

    /// Probe GET_VERSION and adjudicate the firmware state. Any reply shape
    /// we cannot parse fails closed.
    pub fn probe_firmware(&mut self) -> std::io::Result<S17PicFirmwareState> {
        let parse: fn(&[u8]) -> std::io::Result<u8> = match self.class {
            S17PicControllerClass::DsPicG2aFramed => parse_ds_pic_version_reply,
            S17PicControllerClass::Pic16G2bFramed => parse_pic16_version_reply,
        };
        let frame = match self.class {
            S17PicControllerClass::DsPicG2aFramed => dspic_g2a_get_version_frame(),
            S17PicControllerClass::Pic16G2bFramed => pic16_g2b_get_version_frame(),
        };
        let reply = self.wire.transact(self.i2c_addr(), &frame, 5)?;
        let version = parse(&reply)?;
        self.firmware_version = Some(version);
        Ok(S17PicFirmwareState::from_version(self.class, version))
    }

    /// One heartbeat transaction; success increments the stability counter.
    pub fn heartbeat(&mut self) -> std::io::Result<()> {
        let frame = match self.class {
            S17PicControllerClass::DsPicG2aFramed => dspic_g2a_heartbeat_frame(),
            S17PicControllerClass::Pic16G2bFramed => pic16_g2b_heartbeat_frame(),
        };
        let checked = self
            .wire
            .transact(self.i2c_addr(), &frame, 6)
            .and_then(|reply| {
                let payload = framed_reply(&reply, 0x16).map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
                })?;
                if payload.first() != Some(&1) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "S17 heartbeat ACK mismatch",
                    ));
                }
                Ok(())
            });
        if let Err(error) = checked {
            self.stable_heartbeats = 0;
            return Err(error);
        }
        self.stable_heartbeats = self.stable_heartbeats.saturating_add(1);
        Ok(())
    }

    /// Bounded heartbeat pass: at most `max_attempts` transactions; a missing
    /// reply is an error (never an unbounded loop).
    pub fn heartbeat_bounded(&mut self, max_attempts: u32) -> std::io::Result<()> {
        let mut remaining = max_attempts.max(1);
        loop {
            match self.heartbeat() {
                Ok(()) => return Ok(()),
                Err(error) => {
                    if remaining <= 1 {
                        return Err(error);
                    }
                    remaining -= 1;
                }
            }
        }
    }

    /// SET_VOLTAGE with the raw code byte for this controller class. Refused
    /// (Err) before the 5-stable-heartbeat gate, on degraded/loader firmware,
    /// without a prior firmware probe, and on any wire fault.
    ///
    /// Class separation: the G2a frame carries the production three-byte
    /// payload `[VV, 0, 0]`; the G2b frame is the jig-captured one-byte form
    /// (see [`pic16_g2b_set_voltage_frame`] for why the plus-family
    /// production path must not use it).
    pub fn set_voltage_code(&mut self, vv: u8) -> std::io::Result<()> {
        if self.stable_heartbeats < S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "S17 PIC SET_VOLTAGE deferred: {} stable heartbeats required, {} observed",
                    S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE, self.stable_heartbeats
                ),
            ));
        }
        self.adjudicate_firmware_for_voltage()?;
        let frame = match self.class {
            S17PicControllerClass::DsPicG2aFramed => dspic_g2a_set_voltage_frame(vv),
            S17PicControllerClass::Pic16G2bFramed => pic16_g2b_set_voltage_frame(vv),
        };
        let reply = self.wire.transact(self.i2c_addr(), &frame, 2)?;
        if reply != [0x10, 1] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "S17 PIC SET_VOLTAGE ACK mismatch (fail-closed teardown)",
            ));
        }
        Ok(())
    }

    /// SAFE-OFF (DC-DC off). Always permitted — safe direction — and still
    /// fail-closed on a missing reply.
    pub fn safe_off(&mut self) -> std::io::Result<()> {
        let frame = match self.class {
            S17PicControllerClass::DsPicG2aFramed => dspic_g2a_safe_off_frame(),
            S17PicControllerClass::Pic16G2bFramed => pic16_g2b_safe_off_frame(),
        };
        let reply = self.wire.transact(self.i2c_addr(), &frame, 2)?;
        if reply != [0x15, 1] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "S17 safe-off ACK mismatch",
            ));
        }
        Ok(())
    }

    fn adjudicate_firmware_for_voltage(&self) -> std::io::Result<()> {
        let Some(version) = self.firmware_version else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "S17 PIC firmware not probed; refusing SET_VOLTAGE",
            ));
        };
        match S17PicFirmwareState::from_version(self.class, version) {
            S17PicFirmwareState::App { .. } => Ok(()),
            S17PicFirmwareState::DegradedDspic if self.trust_degraded_fw => Ok(()),
            S17PicFirmwareState::DegradedDspic => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "S17 dsPIC fw=0x86 (post-corruption state) refused for voltage; \
                 physical ICSP recovery required",
            )),
            S17PicFirmwareState::LoaderMode => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "S17 PIC16 in loader mode (0xCC) refused for voltage; \
                 recovery-tool owns the jump op",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Chain I/O seam, register helpers and enumeration (moved verbatim from
// s17_native_runtime.rs so integration tests replay the production code)
// ---------------------------------------------------------------------------

/// The sole production owner of chain MMIO. The protocol uses this narrow seam
/// so queueing, commands and nonce correlation can be tested without MMIO.
pub trait ChainIo {
    fn set_divisor(&mut self, divisor: u32);
    fn divisor(&self) -> u32;
    fn command(&mut self, bytes_without_crc: &[u8]);
    fn register_reply(&mut self) -> Option<[u8; 8]>;
    fn work_full(&self) -> bool;
    fn write_work(&mut self, words: &[u32; 36]) -> Result<()>;
    fn nonce(&mut self) -> Option<[u32; 2]>;
    fn flush_work(&mut self);
}

/// Held fifo_block_thr.vhd: volume < threshold asserts IRQ, EMPTY also
/// asserts it. 1848 leaves at least 200 words in a 2048-word FIFO.
pub fn work_queue_has_complete_frame_space(status: u32, threshold: u32) -> bool {
    threshold == 1848 && status & 8 == 0 && status & (4 | 16) != 0
}

/// Register write via the chain command FIFO (`0x41` addressed / `0x51`
/// broadcast; the FPGA appends preamble and CRC5).
pub fn register_write(io: &mut impl ChainIo, address: Option<u8>, register: u8, value: u32) {
    let v = value.to_be_bytes();
    io.command(&[
        if address.is_some() { 0x41 } else { 0x51 },
        9,
        address.unwrap_or(0),
        register,
        v[0],
        v[1],
        v[2],
        v[3],
    ]);
}

pub fn drain_commands(io: &mut impl ChainIo) {
    for _ in 0..512 {
        if io.register_reply().is_none() {
            break;
        }
    }
}

/// Register read deadline (production bounded wait).
pub const REGISTER_WAIT: Duration = Duration::from_millis(100);

/// Correlated register read: value BE32, chip address, register, flags/CRC.
/// The FPGA's command-vs-work demux already checked CRC5.
pub async fn register_read(io: &mut impl ChainIo, address: u8, register: u8) -> Result<u32> {
    drain_commands(io);
    io.command(&[0x42, 5, address, register]);
    let deadline = Instant::now() + REGISTER_WAIT;
    while Instant::now() < deadline {
        if let Some(reply) = io.register_reply() {
            if reply[4] == address && reply[5] == register {
                return Ok(u32::from_be_bytes(reply[..4].try_into().unwrap()));
            }
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    bail!("S17 register 0x{register:02x} read timed out for ASIC 0x{address:02x}")
}

/// A positive response chooses the divisor; no unheld serializer clock is
/// promoted into a fabricated baud-rate formula. Discovery issues read-only
/// GetAddress, and a complete exact enumeration is required twice.
pub async fn discover_divisor(io: &mut impl ChainIo, chips: u8) -> Result<u32> {
    let mut candidates = vec![io.divisor(), 0, 1, 3, 7, 0x6C, 53, 107, 215];
    let mut seen = HashSet::new();
    candidates.retain(|value| seen.insert(*value));
    for divisor in candidates {
        io.set_divisor(divisor);
        let mut complete = true;
        for _ in 0..2 {
            drain_commands(io);
            io.command(&[0x52, 5, 0, 0]);
            let deadline = Instant::now() + REGISTER_WAIT;
            let mut count = 0;
            while Instant::now() < deadline {
                while let Some(reply) = io.register_reply() {
                    if reply[0..2] != [0x13, 0x97] || reply[5] != 0 {
                        complete = false;
                    }
                    count += 1;
                    ensure!(
                        count <= usize::from(chips),
                        "S17 enumeration exceeds exact geometry"
                    );
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if count != usize::from(chips) {
                complete = false;
            }
            if !complete {
                break;
            }
        }
        if complete {
            return Ok(divisor);
        }
    }
    bail!("no host divider produced two complete BM1397 enumerations")
}

// ---------------------------------------------------------------------------
// Work ledger (moved verbatim from s17_native_runtime.rs)
// ---------------------------------------------------------------------------

/// Slot correlation is independent for each physical chain. Every accepted
/// nonce is reconstructed and SHA256d-checked against the exact pool target.
pub struct WorkLedger {
    /// One entry per host work ID (16384 slots); `pub` for cross-module
    /// state publication and test seeding.
    pub slots: Vec<Option<MiningWork>>,
    pub next: usize,
    pub seen: HashSet<(usize, u8, u32)>,
    pub valid_tickets: u64,
    pub ticket_window: VecDeque<Instant>,
    pub first_dispatch: Option<Instant>,
    pub last_ticket: Option<Instant>,
}

impl WorkLedger {
    // The FPGA reconstructs a 16-bit work ID from the 7-bit wire ID. Two
    // low bits select the midstate, leaving 14 host work-ID bits. A 32-slot
    // host table would wrap before the 2048-word hardware FIFO even drains.
    pub fn new() -> Self {
        Self {
            slots: vec![None; 16384],
            next: 0,
            seen: HashSet::new(),
            valid_tickets: 0,
            ticket_window: VecDeque::new(),
            first_dispatch: None,
            last_ticket: None,
        }
    }

    pub fn invalidate(&mut self) {
        self.slots.fill(None);
        self.seen.clear();
    }

    pub fn dispatch(&mut self, io: &mut impl ChainIo, work: MiningWork) -> Result<bool> {
        if io.work_full() {
            return Ok(false);
        }
        let slot = self.next;
        ensure!(
            !work.midstates.is_empty() && work.midstates.len() <= 8,
            "invalid BM1397 midstate count"
        );
        let mut words = [0; 36];
        words[0] = (slot as u32) << 2;
        words[1] = work.nbits;
        words[2] = work.ntime;
        words[3] = u32::from_le_bytes(work.merkle4);
        for n in 0..4 {
            let midstate = &work.midstates[if n < work.midstates.len() { n } else { 0 }];
            for i in 0..8 {
                let offset = (7 - i) * 4;
                words[4 + n * 8 + i] =
                    u32::from_be_bytes(midstate[offset..offset + 4].try_into().unwrap());
            }
        }
        // Clear before a possibly partial physical write. A failed write can
        // never leave old metadata authorizing a nonce with the same work ID.
        self.slots[slot] = None;
        io.write_work(&words)?;
        self.seen.retain(|(id, _, _)| *id != slot);
        self.slots[slot] = Some(work);
        self.next = (slot + 1) % 16384;
        self.first_dispatch.get_or_insert_with(Instant::now);
        Ok(true)
    }

    pub fn validate(&mut self, raw: [u32; 2], worker: &str) -> Result<Option<ValidShare>> {
        let nonce = Bm1397Driver::new().decode_nonce(&raw)?;
        let slot = usize::from(nonce.work_id);
        let Some(Some(work)) = self.slots.get(slot) else {
            return Ok(None);
        };
        let mut midstate = usize::from(nonce.midstate_idx);
        if midstate >= 4 {
            return Ok(None);
        }
        if midstate >= work.midstates.len() {
            midstate = 0;
        }
        let mut version = work.version;
        for _ in 0..midstate {
            let rolled = dcentrald_stratum::work::increment_bitmask_pub(
                version & work.version_mask,
                work.version_mask,
            );
            version = (version & !work.version_mask) | rolled;
        }
        let header = dcentrald_stratum::v1::job::build_block_header(
            version,
            &work.prev_block_hash,
            &work.merkle_root,
            work.ntime,
            work.nbits,
            nonce.nonce,
        );
        let ticket_valid = dcentrald_stratum::work::validate_full_header(
            &header,
            &dcentrald_stratum::work::difficulty_to_target(256.0),
        );
        let pool_valid = dcentrald_stratum::work::validate_full_header(&header, &work.share_target);
        if !ticket_valid && !pool_valid {
            return Ok(None);
        }
        if !self.seen.insert((slot, nonce.midstate_idx, nonce.nonce)) {
            return Ok(None);
        }
        // Hashrate comes from independently validated difficulty-256 tickets,
        // including tickets below the current pool share difficulty.
        if ticket_valid {
            let now = Instant::now();
            self.valid_tickets += 1;
            self.last_ticket = Some(now);
            self.ticket_window.push_back(now);
        }
        if !pool_valid {
            return Ok(None);
        }
        Ok(Some(ValidShare {
            work_generation: work.work_generation,
            worker_name: worker.into(),
            job_id: work.job_id.clone(),
            extranonce2: work.extranonce2.clone(),
            ntime: format!("{:08x}", work.ntime),
            nonce: format!("{:08x}", nonce.nonce),
            // BIP310 submits the actual masked version. The pool replaces
            // job_version's masked bits; it does not apply an XOR delta.
            version_bits: (work.version_mask != 0)
                .then(|| format!("{:08x}", version & work.version_mask)),
            version,
            achieved_difficulty: None,
        }))
    }

    /// Validated difficulty-256 ticket count (measured hashrate input).
    pub fn valid_tickets(&self) -> u64 {
        self.valid_tickets
    }
}

impl Default for WorkLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BM1397 serial work codec (dcentaxe-asic reference)
// ---------------------------------------------------------------------------

/// Job-packet header: `TYPE_JOB | GROUP_SINGLE | CMD_WRITE` = `0x21`
/// (`dcentaxe-asic/src/common.rs`).
pub const BM1397_JOB_HEADER: u8 = 0x21;

/// Fixed 4-midstate job-packet payload length: `14 + 4 + 4×32` = 146 bytes
/// (`14 + 4 + N×32` with N zero-padded to 4; ESP-Miner always sends the full
/// 146-byte job_packet struct).
pub const BM1397_JOB_PACKET_LEN: usize = 146;

/// BM1397 job-id advance: `+4 mod 128` (4-midstate stride;
/// `dcentaxe-mining` `DispatcherConfig::for_bm1397`).
pub const fn next_bm1397_job_id(current: u8) -> u8 {
    (current + 4) % 128
}

/// BM1397 4-midstate AsicBoost: BM1397 uses midstate-based version rolling
/// with NO chip-side BIP320 mask (baked-config note: "BM1397 is 4-midstate
/// AsicBoost (NOT BIP320 chip-side)"). This module must not import or derive
/// the BM1362 BIP320 reconstruction.
pub const BM1397_MIDSTATE_SLOTS: usize = 4;

/// Build the BM1397 serial job packet (header byte NOT included — callers
/// frame it per transport): `job_id(1) num_midstates(1) starting_nonce(4 LE)
/// nbits(4 LE) ntime(4 LE) merkle4(4) midstate0..3(32×4, zero-padded)`.
pub fn build_bm1397_job_packet(
    job_id: u8,
    midstates: &[[u8; 32]],
    starting_nonce: u32,
    nbits: u32,
    ntime: u32,
    merkle4: [u8; 4],
) -> Result<Vec<u8>> {
    if midstates.is_empty() || midstates.len() > BM1397_MIDSTATE_SLOTS {
        bail!(
            "BM1397 job requires 1..=4 midstates, got {}",
            midstates.len()
        );
    }
    let mut packet = Vec::with_capacity(BM1397_JOB_PACKET_LEN);
    packet.push(job_id);
    packet.push(midstates.len() as u8);
    packet.extend_from_slice(&starting_nonce.to_le_bytes());
    packet.extend_from_slice(&nbits.to_le_bytes());
    packet.extend_from_slice(&ntime.to_le_bytes());
    packet.extend_from_slice(&merkle4);
    for slot in 0..BM1397_MIDSTATE_SLOTS {
        match midstates.get(slot) {
            Some(midstate) => packet.extend_from_slice(midstate),
            None => packet.extend_from_slice(&[0u8; 32]),
        }
    }
    Ok(packet)
}

/// BM1397 nonce decoding: chip address lives in nonce bits `[24:17]`
/// (`dcentrald-asic` FPGA driver `decode_nonce`; the S17 jig
/// `BHB07601_check_nonce` divides by `gChain_Asic_Interval`).
pub const fn bm1397_chip_addr_from_nonce(nonce: u32) -> u8 {
    ((nonce >> 17) & 0xFF) as u8
}

/// Chip index from a nonce given the chain's address stride.
pub const fn bm1397_chip_index_from_nonce(nonce: u32, addr_interval: u8) -> u8 {
    let interval = if addr_interval == 0 { 1 } else { addr_interval };
    bm1397_chip_addr_from_nonce(nonce) / interval
}

/// Host-test mock wire: scripted replies + a transaction log. `cfg(test)` so
/// it never ships in the binary, but still visible to the `tests/r05_*.rs`
/// targets that `#[path]`-include this file (they compile under `--cfg test`).
#[cfg(test)]
#[derive(Default)]
pub struct MockS17PicWire {
    pub replies: std::collections::VecDeque<std::io::Result<Vec<u8>>>,
    pub log: Vec<(u8, Vec<u8>)>,
}

#[cfg(test)]
impl S17PicWire for MockS17PicWire {
    fn transact(
        &mut self,
        i2c_addr: u8,
        write: &[u8],
        _read_len: usize,
    ) -> std::io::Result<Vec<u8>> {
        self.log.push((i2c_addr, write.to_vec()));
        self.replies.pop_front().unwrap_or_else(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no reply",
            ))
        })
    }
}
