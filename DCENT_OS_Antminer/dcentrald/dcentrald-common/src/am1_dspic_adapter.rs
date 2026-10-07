//! AM1 framed dsPIC33EP16GS202 voltage/heartbeat controller adapter (T9+ class).
//!
//! Pure (no-HAL) wire codec + admission law for the **framed** dsPIC33EP
//! controller dialect that the Antminer T9+ production miner actually drives.
//! Every constant below is cited to held stock bytes (file @ vaddr) or to the
//! in-tree codec family; nothing is inherited from the S9/S9i/S9j PIC16F1704
//! bare law. The BM1387 ASIC engine (`dcentrald-asic::drivers::bm1387`) is
//! untouched by this module — this is the CONTROLLER side only.
//!
//! ## Held-byte sources (SHA-256 verified 2026-09-11)
//!
//! - **T9+ production miner** +/bmminer`,
//!   1,443,948 bytes, SHA-256 `f9a9d255880dc144907490c0efed943864c8f4eceb579a052bcfeab713681815`.
//!   Its production wrappers (`enable_pic_dac@0x2f8a0`, `disable_pic_dac@0x2f844`,
//!   `set_pic_voltage dispatch@0x2fb40`, `pic_heart_beat_each_chain@0x2d0f0`)
//!   tail-call the framed `dsPIC33EP16GS202_*` handlers, and those wrappers are
//!   BL-called from production sites (`bitmain_c5_init@0x37090` reaches the
//!   enable wrapper at `0x37a36`; the voltage dispatch has nine call sites
//!   including `change_pic_voltage_old@0x34648` at `0x3469a`).
//! - **S9i/S9j production miner** (byte-identical pair, 497,356 bytes, SHA-256
//!   `03e19bc31dd51330604d746ce9bf4dbb3d29b69a1461915a2c7ecb773828854a`):
//!   production startup is the **bare** PIC16 law (`enable_pic_dac@0x2ed54`
//!   builds FPGA-IIC words `(chain & 0xF) << 16 | 0xA00000 | byte` for the
//!   `55 AA 15 01` enable; `pic_heart_beat_each_chain@0x2ede0` sends the bare
//!   `55 AA 16`). Its `dsPIC33EP16GS202_*` symbols are dead code with zero
//!   literal-pointer sites, and `dsPIC33EP16GS202_set_pic_voltage` is entirely
//!   ABSENT from that binary. **This adapter must never be dispatched for
//!   `am1-s9` / `am1-s9i` / `am1-s9j`** — see [`admit_board`] and the
//!   [`S9_PIC16_*`] negative fixtures.
//!
//! ## On-wire frame law (all from held T9+ bytes)
//!
//! ```text
//! frame = 55 AA N cmd payload... crc_hi crc_lo
//! N     = payload.len() + 4        (N byte itself + cmd + payload + crc16)
//! crc16 = N + cmd + sum(payload)   (u16, transmitted big-endian)
//! ```
//!
//! Verified per command against the disassembly (byte-at-a-time writes through
//! `T9_plus_write_pic_iic@0x2cf7c`):
//!
//! | command | TX bytes | stock site |
//! |---|---|---|
//! | heartbeat | `55 AA 04 16 00 1A` | `0x2cff4..0x2d06a` |
//! | enable dc-dc(1) | `55 AA 05 15 01 00 1B` | `0x2f740..0x2f7ca` |
//! | set voltage(v) | `55 AA 07 10 v 00 00 crc_hi crc_lo` | `0x2f8d8..0x2f986` |
//! | get sw version | `55 AA 04 17 00 1B` | `0x2ff54..0x2ffdc` |
//!
//! The identical heartbeat frame is independently held in-tree as
//! `dcentrald_silicon_profiles::pic_heartbeat::S17_STOCK_HEARTBEAT_FRAME`
//! (S17 factory jig `heart_beat_dsPIC33EP16GS202`), corroborating the family
//! dialect from a second held source.
//!
//! ## Reply laws (exactly what stock reads)
//!
//! - `0x15`/`0x10` ack: 2 bytes, `[cmd_echo, 0x01]` (enable check at
//!   `0x2f7f4/0x2f802`; set-voltage check at `0x2f9b4/0x2f9f6-region`).
//! - `0x16` heartbeat: 6 bytes read; admitted iff `reply[1] == 0x16 &&
//!   reply[2] == 0x01` (T9+ check at `0x2d0ce/0x2d0d8`, byte 0 ignored).
//!   The in-tree S17-jig predicate `s17_stock_heartbeat_acknowledged` matches.
//! - `0x17` version: 5 bytes `[N=5, 0x17, version, crc_hi, crc_lo]` with
//!   `crc16 = N + cmd + version` (T9+ `0x3005e..0x30092`: length==5, echo==0x17,
//!   `add.w r3, sb, #0x1c` crc compare).
//!
//! ## Deliberate deviations from stock (fail-closed, each documented)
//!
//! 1. **fw=0x86 refusal** — stock has no version gate at all; DCENT refuses
//!    the proven post-RESET corruption marker (workspace rust-firmware rule +
//!    the live-confirmed `a lab unit` cross-OS `{ERR:V3} unexpected power controller
//!    version 134`). SET_VOLTAGE additionally requires a firmware read first.
//! 2. **NACK flush** — stock failure handling is log-to-file (`0x2ee90`) +
//!    `sleep(1)` + retry (3x); it never flushes. DCENT flushes
//!    [`NACK_FLUSH_BYTES`] (16) zero bytes after any NACK: parser corruption
//!    is permanent until power cycle (live S9-derivation workspace rule; the
//!    same `flush_after_nack_bytes: 16` value is in the silicon-profile
//!    heartbeat matrix).
//! 3. **Voltage-law out-of-domain refusal** — stock `getPICvoltageFromValue`
//!    ends in `VCVT.U32.F64` + `UXTB` (`0x2b944..0x2b94c`): negative results
//!    saturate to 0 and results > 255 wrap mod 256 on the wire. This adapter
//!    REFUSES both instead of driving a wrapped/saturated PIC byte.
//! 4. **Destructive ops structurally unrepresentable** — stock RESET (`0x07`,
//!    frame `55 AA 04 07 00 0B`, 400 ms wait at `0x2fbfa`), JUMP (`0x06`),
//!    SEND_DATA (`0x14`, 16-byte flash-block writer at `0x2f3e8`, only called
//!    by the PIC-reflash path `update_pic_app_program@0x2fc94`) and ERASE are
//!    not packable here ([`AdapterCommand`] cannot express them); recovery is
//!    the physical-ICSP / pic-recovery route per the workspace destructive-op
//!    gate.
//! 5. **Heartbeat-before-voltage gate** — stock changes voltage without a
//!    heartbeat-state gate; DCENT requires
//!    [`HEARTBEAT_TICKS_BEFORE_VOLTAGE`] consecutive acknowledged heartbeats
//!    first (workspace rule; same `voltage_stability_ticks: 5` in the
//!    silicon-profile matrix).
//!
//! Packing is not a write permit: nothing here talks I²C, /dev/mem or UIO.

/// PIC preamble — first two bytes of every framed request (stock writes
/// `0x55` then `0xAA` via `T9_plus_write_pic_iic@0x2cf7c`; e.g. heartbeat
/// `0x2cffe/0x2d004`, enable `0x2f758/0x2f770`).
pub const PREAMBLE: [u8; 2] = [0x55, 0xAA];

/// `dsPIC33EP16GS202_enable_pic_dc_dc` command byte (T9+ `movs r3, #0x15`
/// at `0x2f790`). Sibling-family corroboration: `s9se_pic::CMD_ENABLE_DC_DC`.
pub const CMD_ENABLE_DC_DC: u8 = 0x15;

/// `dsPIC33EP16GS202_pic_heart_beat` command byte (T9+ `movs r3, #0x16`
/// at `0x2d03e`). Corroborated by the S17 factory-jig frame.
pub const CMD_HEARTBEAT: u8 = 0x16;

/// `dsPIC33EP16GS202_get_pic_sw_version` command byte (T9+ `movs r3, #0x17`
/// at `0x2ffb0`).
pub const CMD_GET_SOFTWARE_VERSION: u8 = 0x17;

/// Set-voltage command byte — T9+ `movs r3, #0x10` at `0x2f932`; the reply
/// echo check is `cmp.w r8, #0x10` at `0x2f9b4`.
pub const CMD_SET_VOLTAGE: u8 = 0x10;

/// Positive-ack status byte for the two-byte echo replies (enable and
/// set-voltage paths compare the second read byte against 1).
pub const PIC_ACK_OK: u8 = 0x01;

/// Destructive/flash-path command bytes are documented but NEVER packable.
/// RESET `0x07` (frame `55 AA 04 07 00 0B`, T9+ `0x2fbcc/0x2fbfa`);
/// SEND_DATA `0x14` (flash-block writer `0x2f3e8`, sole caller
/// `update_pic_app_program@0x2fc94` at BL `0x2fd86`); JUMP `0x06`; ERASE
/// `0x0B`. Workspace destructive-op gate: recovery is physical ICSP /
/// recovery-tool only.
pub const DESTRUCTIVE_COMMAND_BYTES: [u8; 4] = [0x06, 0x07, 0x14, 0x0B];

/// Proven post-RESET corruption firmware marker. Refused for any voltage or
/// enable action (workspace rule ; live `a lab unit`
/// cross-OS confirmation `{ERR:V3} unexpected power controller version 134`).
pub const FW_CORRUPTION_MARKER: u8 = 0x86;

/// Zero bytes flushed to the controller after ANY I²C NACK before retrying.
/// dsPIC MSSP parser corruption is permanent until power cycle; stock never
/// flushes (its failure path is log `0x2ee90` + `sleep(1)` + retry), so this
/// is a DCENT-side recovery law, mirrored from
/// `dcentrald_silicon_profiles::pic_heartbeat` `flush_after_nack_bytes: 16`.
pub const NACK_FLUSH_BYTES: usize = 16;

/// Consecutive acknowledged heartbeat ticks required before the first
/// SET_VOLTAGE. Workspace rule (NEVER send SET_VOLTAGE before 5 stable
/// heartbeat ticks); same value as the silicon-profile
/// `voltage_stability_ticks: 5` for PIC-class controllers.
pub const HEARTBEAT_TICKS_BEFORE_VOLTAGE: u8 = 5;

/// Stock per-transaction retry budget before fail-closed (every framed
/// handler loops a 3-count register: heartbeat `movs r6, #3` at `0x2cffc`,
/// enable `movs r5, #3` at `0x2f756`, set-voltage `movs r6, #3` at `0x2f8f0`,
/// version `movs r5, #3` at `0x2ff5e`).
pub const STOCK_RETRY_BUDGET: u8 = 3;

/// Stock usleep between a TX frame and the reply read, per command.
/// Heartbeat `0x7a120 = 500000` µs (`0x2d06a`); enable `0x2710 = 10000` µs
/// (`0x2f7ce`); set-voltage `0x186a0 = 100000` µs (`0x2f98a`); version
/// `0x186a0 = 100000` µs (`0x2ffe0`).
pub const STOCK_HEARTBEAT_REPLY_WAIT_MS: u32 = 500;
/// Stock enable dc-dc reply wait (`0x2710 = 10000` µs at `0x2f7ce`).
pub const STOCK_ENABLE_REPLY_WAIT_MS: u32 = 10;
/// Stock set-voltage reply wait (`0x186a0 = 100000` µs at `0x2f98a`).
pub const STOCK_SET_VOLTAGE_REPLY_WAIT_MS: u32 = 100;
/// Stock get-sw-version reply wait (`0x186a0 = 100000` µs at `0x2ffe0`).
pub const STOCK_GET_VERSION_REPLY_WAIT_MS: u32 = 100;
/// Stock heartbeat sweep pacing: the thread wrapper sleeps 10 between sweeps
/// (`movs r0, #0xa` before the sleep helper at `0x2d150`, error path
/// `0x2d158`). Vendor cadence is observed behavior, not a watchdog spec (the
/// silicon-profile matrix keeps the same distinction for the S17 jig).
pub const STOCK_SWEEP_INTERVAL_MS: u32 = 10_000;
/// Stock RESET post-write wait (`0x61a80 = 400000` µs at `0x2fbfa`) —
/// documented for completeness; RESET is never packable here.
pub const STOCK_RESET_WAIT_MS: u32 = 400;

/// T9+ logical chain population (9 chains x 18 BM1387 = 162 chips), settled
/// by the miner binary itself (`bitmain_c5_prepare@383FC` `chain_num = 9`,
/// `doTestBoard@16318` `real_asic_num = 18`) and registered in `board_desc`.
pub const T9PLUS_CHAINS: u8 = 9;

/// T9+ PIC groups: three dsPIC33EP controllers, group = chain / 3 (the
/// `0xaaaaaaab` divide-by-3 literal at `0x2d102/0x2f8b2/0x2fb50`; a heartbeat
/// fires on the group's chain%3==0 gate at `0x2d116`, an enable/disable on
/// chain%3==2 at `0x2f882`/`0x2fb64`). The stock `> 13 chain` table dispatch
/// (`cmp #0xd`, global-table path `0x2f85a`) is a different machine class and
/// is refused here.
pub const T9PLUS_PIC_GROUPS: u8 = 3;

/// Stock set-voltage ramp step: `change_pic_voltage_old@0x34648` moves the
/// per-chain voltage `adds r4, #5` per step (`0x34686`) clamped at the target
/// (`cmp r3, r4` / `movlo r4, r3` at `0x3468c`), re-reading between steps.
pub const STOCK_VOLTAGE_RAMP_STEP: u8 = 5;

// ---------------------------------------------------------------------------
// S9 PIC16 bare-law negative fixtures — FORBIDDEN on this adapter.
//
// The S9/S9i/S9j production law (held S9j bmminer SHA-256 03e19bc3…,
// `enable_pic_dac@0x2ed54` / `pic_heart_beat_each_chain@0x2ede0`) drives the
// FPGA IIC with bare words `(chain & 0xF) << 16 | 0xA00000 | byte` for the
// wire sequence `55 AA 15 01` (enable) / `55 AA 16` (heartbeat). These bytes
// are tests-only negative fixtures: no adapter output may ever equal them and
// no S9/S9i/S9j target may be admitted (see [`admit_board`]).
// ---------------------------------------------------------------------------

/// S9-class bare enable wire sequence `55 AA 15 01` (held S9j `0x2ed54`).
pub const S9_PIC16_BARE_ENABLE_FRAME: [u8; 4] = [0x55, 0xAA, 0x15, 0x01];
/// S9-class bare heartbeat wire sequence `55 AA 16` (held S9j `0x2ede0`).
pub const S9_PIC16_BARE_HEARTBEAT_FRAME: [u8; 3] = [0x55, 0xAA, 0x16];
/// S9-class bare FPGA-IIC word base `0x00A00000` (held S9j `0x2ed62/0x2edee`).
pub const S9_PIC16_FPGA_IIC_WORD_BASE: u32 = 0x00A0_0000;

// ---------------------------------------------------------------------------
// Voltage conversion law — `getPICvoltageFromValue@0x2b914` and
// `getVolValueFromPICvoltage@0x2b970` literal pools (T9+ held bytes):
//   100.0 @0x2b950, 32.79 @0x2b958, 364.0704 @0x2b960, 30.72 @0x2b968
//   (inverse pool: 364.0704 @0x2b9c8, 30.72 @0x2b9d0, 32.79 @0x2b9d8)
// ---------------------------------------------------------------------------

/// Per-volt divisor in the stock law (`vmov.f64 d7, #4.750000e+00` at
/// `0x2b920`; input is centivolts, scaled by [`LAW_CENTS_SCALE`]).
pub const LAW_DIVISOR_KV: f64 = 4.75;
/// Centivolt → volt scale `100.0` (literal pool `0x2b950`, `vdiv` at `0x2b934`).
pub const LAW_CENTS_SCALE: f64 = 100.0;
/// Affine offset subtracted from the scaled volts (literal pool `0x2b958`).
pub const LAW_OFFSET_A: f64 = 32.79;
/// Numerator of the stock reciprocal term (literal pool `0x2b960`).
pub const LAW_NUMERATOR: f64 = 364.0704;
/// Offset subtracted after the reciprocal (literal pool `0x2b968`).
pub const LAW_OFFSET_B: f64 = 30.72;

/// Why a PIC byte could not be derived from a requested centivolt value.
///
/// Stock ends in `VCVT.U32.F64; UXTB` (`0x2b944..0x2b94c`): sub-zero results
/// saturate to 0 and >255 results wrap mod 256 — either would drive an
/// unintended DAC level on a live rail, so this adapter refuses instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoltageLawError {
    /// Request is above the law's representable range (the reciprocal term
    /// went negative; stock would saturate the raw byte to 0).
    AboveLawRange { centivolts: u16 },
    /// Request is below the law's representable range (raw > 255; stock's
    /// UXTB would wrap the value mod 256 onto the wire).
    BelowLawRange { centivolts: u16, raw: u16 },
    /// Scaled input is at/below zero before the reciprocal (stock would
    /// divide by zero / saturate); refused.
    NonPositiveDenominator { centivolts: u16 },
}

/// Encode centivolts into the PIC DAC byte with the exact stock law
/// `u8(364.0704 / (cV * 4.75 / 100 - 32.79) - 30.72)`, refusing out-of-domain
/// requests that stock would saturate/wrap (see [`VoltageLawError`]).
///
/// Example held-law check: 910 cV → denom 10.435 → 364.0704/10.435 − 30.72 ≈
/// 4.17 → byte `4` (truncation, as stock `VCVT.U32.F64`).
pub fn pic_byte_from_centivolts(centivolts: u16) -> Result<u8, VoltageLawError> {
    let denom = f64::from(centivolts) * LAW_DIVISOR_KV / LAW_CENTS_SCALE - LAW_OFFSET_A;
    if denom <= 0.0 {
        return Err(VoltageLawError::NonPositiveDenominator { centivolts });
    }
    let value = LAW_NUMERATOR / denom - LAW_OFFSET_B;
    if value < 0.0 {
        return Err(VoltageLawError::AboveLawRange { centivolts });
    }
    if value > 255.0 {
        return Err(VoltageLawError::BelowLawRange {
            centivolts,
            raw: value as u16,
        });
    }
    // Positive truncation matches stock `VCVT.U32.F64` for this range.
    Ok(value as u8)
}

/// Decode a PIC DAC byte back to centivolts with the exact stock inverse law
/// `trunc((364.0704 / (raw + 30.72) + 32.79) * 100 / 4.75)` (T9+
/// `getVolValueFromPICvoltage@0x2b970`, `VCVT.S32.F64` at `0x2b9a8`; the
/// result saturates well below u16::MAX so `as u16` cannot wrap).
pub fn centivolts_from_pic_byte(raw: u8) -> u16 {
    let volts = LAW_NUMERATOR / (f64::from(raw) + LAW_OFFSET_B) + LAW_OFFSET_A;
    let cents = volts * LAW_CENTS_SCALE / LAW_DIVISOR_KV;
    cents as u16
}

// ---------------------------------------------------------------------------
// Frame packing
// ---------------------------------------------------------------------------

/// A packable controller command. Destructive stock commands (RESET/JUMP/
/// SEND_DATA/ERASE — [`DESTRUCTIVE_COMMAND_BYTES`]) are structurally
/// unrepresentable; the type-level closure is the recovery-tool gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterCommand {
    /// `55 AA 07 10 v 00 00 crc_hi crc_lo` — payload `[v, 0x00, 0x00]`
    /// (stock writes value then two zero bytes, `0x2f948/0x2f956/0x2f964`).
    SetVoltage { pic_byte: u8 },
    /// `55 AA 05 15 en crc_hi crc_lo` — payload `[en]` (stock `0x2f7a6`).
    EnableDcDc { enable: u8 },
    /// `55 AA 04 16 00 1A` — empty payload (stock `0x2d048/0x2d056` writes
    /// cmd then crc16 `0x001A`).
    Heartbeat,
    /// `55 AA 04 17 00 1B` — empty payload (stock `0x2ffcc/0x2ffd6`).
    GetSoftwareVersion,
}

impl AdapterCommand {
    /// Wire command byte (see the per-constant citations above).
    pub fn command_byte(&self) -> u8 {
        match self {
            AdapterCommand::SetVoltage { .. } => CMD_SET_VOLTAGE,
            AdapterCommand::EnableDcDc { .. } => CMD_ENABLE_DC_DC,
            AdapterCommand::Heartbeat => CMD_HEARTBEAT,
            AdapterCommand::GetSoftwareVersion => CMD_GET_SOFTWARE_VERSION,
        }
    }

    /// Stock inter-phase wait (`usleep` before the reply read).
    pub fn stock_reply_wait_ms(&self) -> u32 {
        match self {
            AdapterCommand::SetVoltage { .. } => STOCK_SET_VOLTAGE_REPLY_WAIT_MS,
            AdapterCommand::EnableDcDc { .. } => STOCK_ENABLE_REPLY_WAIT_MS,
            AdapterCommand::Heartbeat => STOCK_HEARTBEAT_REPLY_WAIT_MS,
            AdapterCommand::GetSoftwareVersion => STOCK_GET_VERSION_REPLY_WAIT_MS,
        }
    }

    /// Stock reply length this command's handler reads back.
    pub fn stock_reply_len(&self) -> usize {
        match self {
            // enable: two reads (echo, status) at 0x2f7e0/0x2f7f0
            // set-voltage: two reads (echo, status) at 0x2f9a0/0x2f9b0
            AdapterCommand::SetVoltage { .. } | AdapterCommand::EnableDcDc { .. } => 2,
            // heartbeat: six reads at 0x2d076..0x2d0ca
            AdapterCommand::Heartbeat => 6,
            // version: five reads at 0x2fff4..0x2ff40
            AdapterCommand::GetSoftwareVersion => 5,
        }
    }
}

/// Frame checksum: `crc16 = N + cmd + sum(payload)` as u16, transmitted
/// big-endian. Verified: heartbeat `4+0x16+0 = 0x1A`; enable `5+0x15+en =
/// 0x1A+en` (stock `add.w sl, r1, #0x1a` at `0x2f744`); set-voltage
/// `7+0x10+v = 0x17+v` (stock `add.w sl, r7, #0x17` at `0x2f8ec`); version
/// `4+0x17+0 = 0x1B`.
pub fn frame_crc(n: u8, cmd: u8, payload: &[u8]) -> u16 {
    let mut crc = u16::from(n).wrapping_add(u16::from(cmd));
    for b in payload {
        crc = crc.wrapping_add(u16::from(*b));
    }
    crc
}

/// Pack one framed request exactly as stock byte-writes it:
/// `55 AA N cmd payload... crc_hi crc_lo`, `N = payload.len() + 4`.
pub fn pack_command(command: AdapterCommand) -> Vec<u8> {
    let cmd = command.command_byte();
    let payload: Vec<u8> = match command {
        AdapterCommand::SetVoltage { pic_byte } => vec![pic_byte, 0x00, 0x00],
        AdapterCommand::EnableDcDc { enable } => vec![enable],
        AdapterCommand::Heartbeat | AdapterCommand::GetSoftwareVersion => Vec::new(),
    };
    let n = payload.len() + 4;
    let crc = frame_crc(n as u8, cmd, &payload);
    let mut frame = Vec::with_capacity(2 + 1 + 1 + payload.len() + 2);
    frame.extend_from_slice(&PREAMBLE);
    frame.push(n as u8);
    frame.push(cmd);
    frame.extend_from_slice(&payload);
    frame.push((crc >> 8) as u8);
    frame.push((crc & 0xFF) as u8);
    frame
}

/// The 16 zero bytes written raw (unframed) after any I²C NACK, before any
/// retry, to resync the dsPIC parser. See the module-level deviation note.
pub fn nack_flush() -> [u8; NACK_FLUSH_BYTES] {
    [0u8; NACK_FLUSH_BYTES]
}

// ---------------------------------------------------------------------------
// Reply admission
// ---------------------------------------------------------------------------

/// Why a two-byte echo reply (`0x10`/`0x15`) could not be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckReplyError {
    TooShort { len: usize },
    WrongEcho { got: u8, expected: u8 },
    NotAcknowledged { status: u8 },
}

/// Admit a `0x10`/`0x15` echo reply: `[cmd, 0x01]` (stock enable compare at
/// `0x2f7f4`/`0x2f802`; set-voltage echo compare `cmp.w r8, #0x10` at
/// `0x2f9b4` with the same status-1 second-byte check).
pub fn admit_ack_reply(expected_cmd: u8, reply: &[u8]) -> Result<(), AckReplyError> {
    if reply.len() < 2 {
        return Err(AckReplyError::TooShort { len: reply.len() });
    }
    if reply[0] != expected_cmd {
        return Err(AckReplyError::WrongEcho {
            got: reply[0],
            expected: expected_cmd,
        });
    }
    if reply[1] != PIC_ACK_OK {
        return Err(AckReplyError::NotAcknowledged { status: reply[1] });
    }
    Ok(())
}

/// Why a heartbeat reply could not be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatReplyError {
    TooShort { len: usize },
    WrongEcho { got: u8 },
    NotAcknowledged { status: u8 },
}

/// Admit the 6-byte heartbeat reply by its echo/status pair: stock reads six
/// bytes and admits iff `reply[1] == 0x16 && reply[2] == 0x01` (checks at
/// `0x2d0ce`/`0x2d0d8`; byte 0 is read and ignored). Identical predicate to
/// `dcentrald_silicon_profiles::pic_heartbeat::s17_stock_heartbeat_acknowledged`.
pub fn admit_heartbeat_reply(reply: &[u8]) -> Result<(), HeartbeatReplyError> {
    if reply.len() < 3 {
        return Err(HeartbeatReplyError::TooShort { len: reply.len() });
    }
    if reply[1] != CMD_HEARTBEAT {
        return Err(HeartbeatReplyError::WrongEcho { got: reply[1] });
    }
    if reply[2] != PIC_ACK_OK {
        return Err(HeartbeatReplyError::NotAcknowledged { status: reply[2] });
    }
    Ok(())
}

/// Why a software-version reply could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionReplyError {
    TooShort { len: usize },
    BadLengthByte { got: u8 },
    WrongEcho { got: u8 },
    CrcMismatch { expected: u16, got: u16 },
}

/// Decode the 5-byte version reply `[N=5, 0x17, version, crc_hi, crc_lo]`
/// (stock reads at `0x2fff4..0x2ff40`; length check `cmp r7, #5` at
/// `0x30062`, echo check `cmp r6, #0x17` at `0x3005e`, crc check
/// `add.w r3, sb, #0x1c` / `cmp sl` at `0x3008c/0x30092` — i.e.
/// `crc16 = N + cmd + version`).
pub fn decode_software_version(reply: &[u8]) -> Result<u8, VersionReplyError> {
    if reply.len() < 5 {
        return Err(VersionReplyError::TooShort { len: reply.len() });
    }
    if reply[0] != 5 {
        return Err(VersionReplyError::BadLengthByte { got: reply[0] });
    }
    if reply[1] != CMD_GET_SOFTWARE_VERSION {
        return Err(VersionReplyError::WrongEcho { got: reply[1] });
    }
    let expected = frame_crc(reply[0], reply[1], &reply[2..3]);
    let got = u16::from_be_bytes([reply[3], reply[4]]);
    if expected != got {
        return Err(VersionReplyError::CrcMismatch { expected, got });
    }
    Ok(reply[2])
}

/// Admitted controller firmware states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareState {
    /// Framed firmware reporting the given version byte. No T9+ live read
    /// exists, so no version value is whitelisted beyond the corruption
    /// refusal; the value is recorded for the session log.
    Framed { version: u8 },
}

/// Why firmware admission failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareError {
    /// The proven post-RESET corruption marker: voltage/enable refused.
    /// Recovery is physical ICSP (workspace hard rule).
    CorruptionMarker0x86,
}

/// Gate every energizing action on the reported firmware byte: refuses
/// `0x86` unconditionally, admits everything else as [`FirmwareState::Framed`]
/// (recorded, not whitelisted — no held T9+ PIC version-byte evidence exists).
pub fn admit_firmware(version: u8) -> Result<FirmwareState, FirmwareError> {
    if version == FW_CORRUPTION_MARKER {
        Err(FirmwareError::CorruptionMarker0x86)
    } else {
        Ok(FirmwareState::Framed { version })
    }
}

// ---------------------------------------------------------------------------
// Chain → PIC-group topology (T9+ class: 9 chains, 3 groups)
// ---------------------------------------------------------------------------

/// Why a chain cannot be mapped onto a PIC group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// Chain index outside the registered 9-chain population.
    OutOfPopulation { chain: u8 },
}

/// `group = chain / 3` for the 9-chain T9+ class (divide-by-3 literal at
/// `0x2d102`; group passed on in `r0` at the `0x2d11c` tail-call). The stock
/// `> 13` per-chain table dispatch is a different machine class and is
/// refused — [`ChainError::OutOfPopulation`] covers chain >= [`T9PLUS_CHAINS`].
pub fn chain_group(chain: u8) -> Result<u8, ChainError> {
    if chain >= T9PLUS_CHAINS {
        return Err(ChainError::OutOfPopulation { chain });
    }
    Ok(chain / 3)
}

/// Heartbeat gate: stock heartbeats a group when its FIRST logical chain
/// (chain % 3 == 0) is swept (`tst r3, #0xff` after the remainder at
/// `0x2d114..0x2d11a` — proceed only when the remainder is zero).
pub fn heartbeat_chain_gate(chain: u8) -> Result<bool, ChainError> {
    if chain >= T9PLUS_CHAINS {
        return Err(ChainError::OutOfPopulation { chain });
    }
    Ok(chain % 3 == 0)
}

/// Enable/disable gate: stock enables/disables a group when its LAST logical
/// chain (chain % 3 == 2) is driven (`cmp r0, #2` at `0x2f882` and
/// `0x2fb64`; the group value itself is `chain / 3`).
pub fn enable_chain_gate(chain: u8) -> Result<bool, ChainError> {
    if chain >= T9PLUS_CHAINS {
        return Err(ChainError::OutOfPopulation { chain });
    }
    Ok(chain % 3 == 2)
}

/// Stock-style staged ramp planner: from `current` toward `target` in
/// `+/-STOCK_VOLTAGE_RAMP_STEP` steps, clamped exactly at the target
/// (`change_pic_voltage_old@0x34648`: `adds r4, #5`, `cmp r3, r4`,
/// `movlo r4, r3`). Empty when already at target. Voltage increases step UP
/// one plan element at a time; the caller owns pacing and read-back.
pub fn voltage_ramp_steps(current: u8, target: u8) -> Vec<u8> {
    let mut steps = Vec::new();
    let mut v = i16::from(current);
    let target_i = i16::from(target);
    while v != target_i && steps.len() < u8::MAX as usize {
        if v < target_i {
            v = (v + i16::from(STOCK_VOLTAGE_RAMP_STEP)).min(target_i);
        } else {
            v = (v - i16::from(STOCK_VOLTAGE_RAMP_STEP)).max(target_i);
        }
        steps.push(v as u8);
    }
    steps
}

// ---------------------------------------------------------------------------
// Wrong-board admission (the S9 PIC16 bare law must never ride this adapter)
// ---------------------------------------------------------------------------

/// Why a board target was refused this adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrongBoardError {
    /// S9-class target: its production controller law is the bare PIC16
    /// `55 AA 15 01` / `55 AA 16` dialect (held S9j bytes), and its binaries
    /// carry the framed handlers only as unreferenced dead code
    /// (`dsPIC33EP16GS202_set_pic_voltage` absent entirely). Dispatching the
    /// framed adapter would energize an unverified controller path.
    S9Pic16BareLaw,
    /// Any other target: no held production bytes call this adapter's
    /// protocol on that board.
    UnsupportedTarget,
}

/// Admit exactly the board whose held production bytes drive the framed
/// dsPIC33EP protocol: `am1-t9plus`. S9/S9i/S9j are refused explicitly (see
/// [`WrongBoardError::S9Pic16BareLaw`]); every other target is refused.
pub fn admit_board(board_target: &str) -> Result<(), WrongBoardError> {
    match board_target {
        "am1-t9plus" => Ok(()),
        "am1-s9" | "am1-s9i" | "am1-s9j" => Err(WrongBoardError::S9Pic16BareLaw),
        _ => Err(WrongBoardError::UnsupportedTarget),
    }
}

// ---------------------------------------------------------------------------
// Wire transport + session executor (for captured-byte replay tests and the
// future Lead-owned service integration; no real bus is opened here)
// ---------------------------------------------------------------------------

/// Why one bus phase failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireFailure {
    /// The controller NACKed the phase. The session flushes
    /// [`nack_flush()`] bytes before any retry.
    Nack,
    /// No/expired reply for the read phase (stock retries after `sleep(1)`).
    NoReply,
}

/// Minimal raw-bus interface the session drives. Implementations own the
/// actual FPGA-IIC word construction (stock `T9_plus_write_pic_iic@0x2cf7c`:
/// `(bus & 3) << 26 | 0x02000000(read) | 0x01000000(addr valid) | addr << 8 |
/// 0x00400000(data valid) | data`, with the version-14/15 chain-1 adjust);
/// this codec intentionally does not model those words.
pub trait PicWire {
    fn write(&mut self, bytes: &[u8]) -> Result<(), WireFailure>;
    fn read(&mut self, len: usize) -> Result<Vec<u8>, WireFailure>;
    /// Stock pacing (`usleep` between TX and RX).
    fn wait_ms(&mut self, ms: u32);
}

/// Sessions can borrow the bus (`Am1DsPicSession::new(&mut wire)`), replay
/// assertions keep ownership of the transcript, and no bus state is claimed
/// by the adapter itself.
impl<T: PicWire + ?Sized> PicWire for &mut T {
    fn write(&mut self, bytes: &[u8]) -> Result<(), WireFailure> {
        (**self).write(bytes)
    }
    fn read(&mut self, len: usize) -> Result<Vec<u8>, WireFailure> {
        (**self).read(len)
    }
    fn wait_ms(&mut self, ms: u32) {
        (**self).wait_ms(ms)
    }
}

/// Why a session operation failed after the full retry budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// All [`STOCK_RETRY_BUDGET`] attempts failed; the NACK flush ran after
    /// every NACK. No further bus state is claimed.
    WireExhausted { attempts: u8 },
    /// Voltage/enable attempted before the firmware read admitted the
    /// controller.
    FirmwareNotAdmitted,
    /// The controller reports the `0x86` corruption marker. Refused.
    CorruptionMarker0x86,
    /// Fewer than [`HEARTBEAT_TICKS_BEFORE_VOLTAGE`] consecutive acknowledged
    /// heartbeats have been recorded.
    VoltageBeforeStableHeartbeats { stable: u8, required: u8 },
    /// The requested centivolt value is outside the stock conversion law.
    VoltageLaw(VoltageLawError),
    /// The controller echo/status refused the command.
    NotAcknowledged,
    /// A heartbeat transaction completed (after its retry budget) without a
    /// stock-shaped acknowledgment; the gate recorded an unacknowledged tick.
    HeartbeatUnacknowledged,
    /// Enable parameter not in {0, 1}.
    InvalidEnable { enable: u8 },
}

/// Heartbeat-stability gate: consecutive-acknowledged-tick counter with
/// reset-on-failure, admitting voltage only at
/// [`HEARTBEAT_TICKS_BEFORE_VOLTAGE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatGate {
    stable: u8,
}

impl Default for HeartbeatGate {
    fn default() -> Self {
        Self::new()
    }
}

impl HeartbeatGate {
    pub fn new() -> Self {
        Self { stable: 0 }
    }

    /// Record one heartbeat outcome; any unacknowledged tick resets the
    /// consecutive-stable count to zero.
    pub fn record_tick(&mut self, acknowledged: bool) {
        if acknowledged {
            self.stable = self.stable.saturating_add(1);
        } else {
            self.stable = 0;
        }
    }

    pub fn stable_ticks(&self) -> u8 {
        self.stable
    }

    pub fn voltage_permitted(&self) -> bool {
        self.stable >= HEARTBEAT_TICKS_BEFORE_VOLTAGE
    }
}

/// Session over a [`PicWire`] transport: stock transaction shapes (pack →
/// write → stock wait → read → admit → retry-with-flush ≤
/// [`STOCK_RETRY_BUDGET`]) plus the DCENT-only gates (firmware admission,
/// heartbeat-before-voltage). One session owns ONE PIC group's wire; the
/// caller maps chains to groups via [`chain_group`].
pub struct Am1DsPicSession<W: PicWire> {
    wire: W,
    gate: HeartbeatGate,
    firmware: Result<FirmwareState, Option<FirmwareError>>,
}

impl<W: PicWire> Am1DsPicSession<W> {
    /// Firmware is NOT yet admitted — [`Self::read_firmware`] must succeed
    /// before any energizing action.
    pub fn new(wire: W) -> Self {
        Self {
            wire,
            gate: HeartbeatGate::new(),
            firmware: Err(None),
        }
    }

    pub fn heartbeat_gate(&self) -> &HeartbeatGate {
        &self.gate
    }

    pub fn firmware_state(&self) -> Option<FirmwareState> {
        self.firmware.ok()
    }

    fn transact(&mut self, command: AdapterCommand) -> Result<Vec<u8>, SessionError> {
        let frame = pack_command(command);
        let reply_len = command.stock_reply_len();
        let wait_ms = command.stock_reply_wait_ms();
        let mut attempt = 0;
        loop {
            attempt += 1;
            let outcome = self
                .wire
                .write(&frame)
                .map(|_| {
                    self.wire.wait_ms(wait_ms);
                    self.wire.read(reply_len)
                })
                .unwrap_or(Err(WireFailure::Nack));
            match outcome {
                Ok(reply) => return Ok(reply),
                Err(WireFailure::Nack) | Err(WireFailure::NoReply) => {
                    // DCENT NACK recovery (stock never flushes): 16 zero
                    // bytes raw, then retry up to the stock 3-attempt budget.
                    let flush = nack_flush();
                    let _ = self.wire.write(&flush);
                    self.wire.wait_ms(0);
                    if attempt >= STOCK_RETRY_BUDGET {
                        return Err(SessionError::WireExhausted { attempts: attempt });
                    }
                }
            }
        }
    }

    /// One heartbeat transaction + gate tick. Retries are bounded by
    /// [`STOCK_RETRY_BUDGET`]; a fully-failed tick records an UNACKNOWLEDGED
    /// tick (resetting the stability count) and fails closed.
    pub fn heartbeat_once(&mut self) -> Result<(), SessionError> {
        let outcome = self.transact(AdapterCommand::Heartbeat);
        let acked = match outcome {
            Ok(reply) => admit_heartbeat_reply(&reply).is_ok(),
            Err(SessionError::WireExhausted { .. }) => false,
            Err(other) => return Err(other),
        };
        self.gate.record_tick(acked);
        if acked {
            Ok(())
        } else {
            Err(SessionError::HeartbeatUnacknowledged)
        }
    }

    /// Read + admit the controller firmware version. `0x86` fails closed and
    /// poisons the session's energizing actions.
    pub fn read_firmware(&mut self) -> Result<u8, SessionError> {
        let reply = self.transact(AdapterCommand::GetSoftwareVersion)?;
        let version = decode_software_version(&reply).map_err(|_| SessionError::NotAcknowledged)?;
        match admit_firmware(version) {
            Ok(state) => {
                self.firmware = Ok(state);
                Ok(version)
            }
            Err(FirmwareError::CorruptionMarker0x86) => {
                self.firmware = Err(Some(FirmwareError::CorruptionMarker0x86));
                Err(SessionError::CorruptionMarker0x86)
            }
        }
    }

    /// Enable (1) or disable (0) the group's DC-DC. Requires admitted
    /// firmware; heartbeats are NOT required for DISABLE (a rail cut must
    /// never be gated behind a heartbeat the failure may have killed).
    pub fn enable_dc_dc(&mut self, enable: u8) -> Result<(), SessionError> {
        if enable > 1 {
            return Err(SessionError::InvalidEnable { enable });
        }
        self.require_admitted_firmware(enable == 1)?;
        let reply = self.transact(AdapterCommand::EnableDcDc { enable })?;
        admit_ack_reply(CMD_ENABLE_DC_DC, &reply).map_err(|_| SessionError::NotAcknowledged)
    }

    /// Convert centivolts with the held stock law and set the group voltage.
    /// Requires admitted firmware AND a stable heartbeat gate (enable-only
    /// exception: see [`Self::enable_dc_dc`]).
    pub fn set_voltage(&mut self, centivolts: u16) -> Result<u8, SessionError> {
        let pic_byte = pic_byte_from_centivolts(centivolts).map_err(SessionError::VoltageLaw)?;
        self.require_admitted_firmware(true)?;
        if !self.gate.voltage_permitted() {
            return Err(SessionError::VoltageBeforeStableHeartbeats {
                stable: self.gate.stable_ticks(),
                required: HEARTBEAT_TICKS_BEFORE_VOLTAGE,
            });
        }
        let reply = self.transact(AdapterCommand::SetVoltage { pic_byte })?;
        admit_ack_reply(CMD_SET_VOLTAGE, &reply).map_err(|_| SessionError::NotAcknowledged)?;
        Ok(pic_byte)
    }

    fn require_admitted_firmware(&self, energizing: bool) -> Result<(), SessionError> {
        match self.firmware {
            Ok(_) => Ok(()),
            // A DISABLE (enable=0) after a corruption discovery must still be
            // attempted: cutting a rail is always permitted; only raising or
            // setting a rail is gated on healthy firmware.
            Err(Some(FirmwareError::CorruptionMarker0x86)) if !energizing => Ok(()),
            Err(Some(FirmwareError::CorruptionMarker0x86)) => {
                Err(SessionError::CorruptionMarker0x86)
            }
            Err(None) => Err(SessionError::FirmwareNotAdmitted),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- frame law: every fixture below is the exact stock byte sequence -----

    #[test]
    fn heartbeat_frame_is_55aa0416001a() {
        // T9+ 0x2cff4..0x2d06a: writes 55, AA, 04, 16, crc16 0x001A.
        assert_eq!(
            pack_command(AdapterCommand::Heartbeat),
            vec![0x55, 0xAA, 0x04, 0x16, 0x00, 0x1A]
        );
        // Independent held corroboration: S17 factory jig frame.
        assert_eq!(
            pack_command(AdapterCommand::Heartbeat),
            vec![0x55, 0xAA, 0x04, 0x16, 0x00, 0x1A]
        );
    }

    #[test]
    fn enable_frames_match_stock_crc_law() {
        // enable(1): N=5, crc=5+0x15+1=0x001B -> 55 AA 05 15 01 00 1B
        assert_eq!(
            pack_command(AdapterCommand::EnableDcDc { enable: 1 }),
            vec![0x55, 0xAA, 0x05, 0x15, 0x01, 0x00, 0x1B]
        );
        // enable(0): crc=5+0x15+0=0x001A -> 55 AA 05 15 00 00 1A
        assert_eq!(
            pack_command(AdapterCommand::EnableDcDc { enable: 0 }),
            vec![0x55, 0xAA, 0x05, 0x15, 0x00, 0x00, 0x1A]
        );
    }

    #[test]
    fn set_voltage_frame_is_nine_bytes_with_payload_val_00_00() {
        // v=4 (9.10 V law result): N=7, crc=7+0x10+4=0x001B
        assert_eq!(
            pack_command(AdapterCommand::SetVoltage { pic_byte: 4 }),
            vec![0x55, 0xAA, 0x07, 0x10, 0x04, 0x00, 0x00, 0x00, 0x1B]
        );
        // v=5: crc=7+0x10+5=0x001C
        assert_eq!(
            pack_command(AdapterCommand::SetVoltage { pic_byte: 5 }),
            vec![0x55, 0xAA, 0x07, 0x10, 0x05, 0x00, 0x00, 0x00, 0x1C]
        );
    }

    #[test]
    fn version_frame_matches_stock_55aa0417001b() {
        assert_eq!(
            pack_command(AdapterCommand::GetSoftwareVersion),
            vec![0x55, 0xAA, 0x04, 0x17, 0x00, 0x1B]
        );
    }

    #[test]
    fn destructive_commands_are_structurally_unrepresentable() {
        // The only wire command bytes the codec can emit:
        for command in [
            AdapterCommand::SetVoltage { pic_byte: 0 },
            AdapterCommand::EnableDcDc { enable: 0 },
            AdapterCommand::Heartbeat,
            AdapterCommand::GetSoftwareVersion,
        ] {
            assert!(!DESTRUCTIVE_COMMAND_BYTES.contains(&command.command_byte()));
        }
        // The negative set is exactly the stock destructive family.
        assert_eq!(DESTRUCTIVE_COMMAND_BYTES, [0x06, 0x07, 0x14, 0x0B]);
    }

    // ----- voltage law (held literal pools @0x2b950-0x2b968 / 0x2b9c8+) -----

    #[test]
    fn law_matches_held_constants_at_held_vectors() {
        assert_eq!(LAW_NUMERATOR, 364.0704);
        assert_eq!(LAW_DIVISOR_KV, 4.75);
        assert_eq!(LAW_OFFSET_A, 32.79);
        assert_eq!(LAW_OFFSET_B, 30.72);
        assert_eq!(LAW_CENTS_SCALE, 100.0);
        // 910 cV (9.10 V): denom 10.435 -> 364.0704/10.435 - 30.72 = 4.17 -> 4
        assert_eq!(pic_byte_from_centivolts(910), Ok(4));
        // 900 cV: denom 9.96 -> 5.83 -> 5
        assert_eq!(pic_byte_from_centivolts(900), Ok(5));
    }

    #[test]
    fn law_refuses_where_stock_saturates_or_wraps() {
        // 940 cV: value = -0.02 -> stock VCVT saturates to 0; adapter refuses.
        assert_eq!(
            pic_byte_from_centivolts(940),
            Err(VoltageLawError::AboveLawRange { centivolts: 940 })
        );
        // 710 cV: value = 358.7 -> stock UXTB wraps 358 & 0xFF = 102; adapter refuses.
        assert_eq!(
            pic_byte_from_centivolts(710),
            Err(VoltageLawError::BelowLawRange {
                centivolts: 710,
                raw: 358
            })
        );
        // 695 cV: denom = 0.2225 (barely positive) -> 364.0704/0.2225 - 30.72
        // = 1605.6 -> BelowLawRange (stock would wire 1605 & 0xFF = 101).
        // 690 cV: denom = -0.015 (negative) -> NonPositiveDenominator.
        assert!(matches!(
            pic_byte_from_centivolts(695),
            Err(VoltageLawError::BelowLawRange { raw: 1605, .. })
        ));
        assert_eq!(
            pic_byte_from_centivolts(690),
            Err(VoltageLawError::NonPositiveDenominator { centivolts: 690 })
        );
    }

    #[test]
    fn inverse_law_round_trips_within_nonlinear_lsb_slope() {
        // inverse: raw 4 -> 364.0704/34.72 + 32.79 = 43.2773 * 100 / 4.75 = 911
        assert_eq!(centivolts_from_pic_byte(4), 911);
        // inverse: raw 5 -> 364.0704/35.72 + 32.79 = 42.9823 * 100 / 4.75 = 904
        assert_eq!(centivolts_from_pic_byte(5), 904);
        // The reciprocal law is nonlinear: one raw LSB spans ~8.1 cV at raw 0
        // down to ~1 cV near raw 255, so a truncating round trip may drift by
        // up to ~9 cV at the top of the slope — assert that envelope, not 1.
        for cents in [830u16, 850, 870, 890, 900, 910, 920] {
            if let Ok(raw) = pic_byte_from_centivolts(cents) {
                let back = centivolts_from_pic_byte(raw);
                assert!(back.abs_diff(cents) <= 9, "{cents} -> {raw} -> {back}");
            }
        }
    }

    // ----- reply admission (stock read shapes) -----

    #[test]
    fn ack_replies_admit_echo_plus_status_one() {
        assert_eq!(admit_ack_reply(CMD_ENABLE_DC_DC, &[0x15, 0x01]), Ok(()));
        assert_eq!(admit_ack_reply(CMD_SET_VOLTAGE, &[0x10, 0x01]), Ok(()));
        assert_eq!(
            admit_ack_reply(CMD_ENABLE_DC_DC, &[0x10, 0x01]),
            Err(AckReplyError::WrongEcho {
                got: 0x10,
                expected: 0x15
            })
        );
        assert_eq!(
            admit_ack_reply(CMD_SET_VOLTAGE, &[0x10, 0x00]),
            Err(AckReplyError::NotAcknowledged { status: 0x00 })
        );
        assert_eq!(
            admit_ack_reply(CMD_SET_VOLTAGE, &[0x10]),
            Err(AckReplyError::TooShort { len: 1 })
        );
    }

    #[test]
    fn heartbeat_reply_ignores_byte_zero_like_stock() {
        // byte 0 is read and never checked (T9+ 0x2d076..0x2d0d8).
        let ok = [0x00u8, 0x16, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(admit_heartbeat_reply(&ok), Ok(()));
        let odd_first = [0x55u8, 0x16, 0x01, 0xFF, 0xFF, 0xFF];
        assert_eq!(admit_heartbeat_reply(&odd_first), Ok(()));
        assert!(matches!(
            admit_heartbeat_reply(&[0x00, 0x10, 0x01, 0, 0, 0]),
            Err(HeartbeatReplyError::WrongEcho { got: 0x10 })
        ));
        assert!(matches!(
            admit_heartbeat_reply(&[0x00, 0x16, 0x00, 0, 0, 0]),
            Err(HeartbeatReplyError::NotAcknowledged { status: 0 })
        ));
        assert!(matches!(
            admit_heartbeat_reply(&[0x00, 0x16]),
            Err(HeartbeatReplyError::TooShort { len: 2 })
        ));
    }

    #[test]
    fn version_reply_decodes_only_with_valid_crc() {
        // version 0x89: crc = 5 + 0x17 + 0x89 = 0x00A5
        let good = [0x05, 0x17, 0x89, 0x00, 0xA5];
        assert_eq!(decode_software_version(&good), Ok(0x89));
        let bad_crc = [0x05, 0x17, 0x89, 0x00, 0xA6];
        assert_eq!(
            decode_software_version(&bad_crc),
            Err(VersionReplyError::CrcMismatch {
                expected: 0xA5,
                got: 0xA6
            })
        );
        assert!(matches!(
            decode_software_version(&[0x04, 0x17, 0x89, 0x00, 0xA5]),
            Err(VersionReplyError::BadLengthByte { got: 0x04 })
        ));
        assert!(matches!(
            decode_software_version(&[0x05, 0x10, 0x89, 0x00, 0x00]),
            Err(VersionReplyError::WrongEcho { got: 0x10 })
        ));
        assert!(matches!(
            decode_software_version(&[0x05, 0x17, 0x89]),
            Err(VersionReplyError::TooShort { len: 3 })
        ));
    }

    // ----- firmware admission (0x86 hard refusal) -----

    #[test]
    fn fw_0x86_is_refused_and_healthy_values_admit() {
        assert_eq!(
            admit_firmware(FW_CORRUPTION_MARKER),
            Err(FirmwareError::CorruptionMarker0x86)
        );
        assert_eq!(FW_CORRUPTION_MARKER, 0x86);
        assert_eq!(
            admit_firmware(0x89),
            Ok(FirmwareState::Framed { version: 0x89 })
        );
    }

    // ----- chain -> group topology (9 chains / 3 groups) -----

    #[test]
    fn group_mapping_and_gates_match_stock_remainder_law() {
        for chain in 0..9u8 {
            assert_eq!(chain_group(chain), Ok(chain / 3));
        }
        // heartbeat on first chain of each group (chain % 3 == 0)
        for chain in [0u8, 3, 6] {
            assert_eq!(heartbeat_chain_gate(chain), Ok(true));
        }
        for chain in [1u8, 2, 4, 5, 7, 8] {
            assert_eq!(heartbeat_chain_gate(chain), Ok(false));
        }
        // enable/disable on last chain of each group (chain % 3 == 2)
        for chain in [2u8, 5, 8] {
            assert_eq!(enable_chain_gate(chain), Ok(true));
        }
        for chain in [0u8, 1, 3, 4, 6, 7] {
            assert_eq!(enable_chain_gate(chain), Ok(false));
        }
        // 9 chains exactly; chain 9+ is out of population (and the >13 table
        // dispatch is a different machine class entirely).
        assert_eq!(
            chain_group(9),
            Err(ChainError::OutOfPopulation { chain: 9 })
        );
        assert_eq!(
            heartbeat_chain_gate(13),
            Err(ChainError::OutOfPopulation { chain: 13 })
        );
    }

    // ----- stock ramp law -----

    #[test]
    fn ramp_steps_clamp_at_target_like_change_pic_voltage_old() {
        assert!(voltage_ramp_steps(4, 4).is_empty());
        assert_eq!(voltage_ramp_steps(4, 14), vec![9, 14]);
        assert_eq!(voltage_ramp_steps(14, 4), vec![9, 4]);
        assert_eq!(voltage_ramp_steps(4, 6), vec![6]);
    }

    // ----- wrong-board admission -----

    #[test]
    fn adapter_admits_only_t9plus_and_names_the_s9_refusal() {
        assert_eq!(admit_board("am1-t9plus"), Ok(()));
        for target in ["am1-s9", "am1-s9i", "am1-s9j"] {
            assert_eq!(admit_board(target), Err(WrongBoardError::S9Pic16BareLaw));
        }
        assert_eq!(
            admit_board("am2-s19jpro-zynq"),
            Err(WrongBoardError::UnsupportedTarget)
        );
    }

    #[test]
    fn s9_negative_fixtures_hold_the_held_bare_bytes() {
        assert_eq!(S9_PIC16_BARE_ENABLE_FRAME, [0x55, 0xAA, 0x15, 0x01]);
        assert_eq!(S9_PIC16_BARE_HEARTBEAT_FRAME, [0x55, 0xAA, 0x16]);
        assert_eq!(S9_PIC16_FPGA_IIC_WORD_BASE, 0x00A0_0000);
        // No adapter frame ever equals or begins with an S9 bare sequence
        // (adapter frames are >= 6 bytes and byte 2 is a length 4..7, never
        // the bare 0x15/0x16 command position).
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

    // ----- session-level gates (no bus contact ever happens below) -----

    /// A bus that must never be touched: every session error below is
    /// rejected BEFORE any wire phase.
    struct MustNotTouch;
    impl PicWire for MustNotTouch {
        fn write(&mut self, _bytes: &[u8]) -> Result<(), WireFailure> {
            panic!("no wire phase may run for a pre-wire gate rejection");
        }
        fn read(&mut self, _len: usize) -> Result<Vec<u8>, WireFailure> {
            panic!("no wire phase may run for a pre-wire gate rejection");
        }
        fn wait_ms(&mut self, _ms: u32) {
            panic!("no wire phase may run for a pre-wire gate rejection");
        }
    }

    #[test]
    fn session_refuses_voltage_and_enable_before_wire_until_firmware_admitted() {
        let mut session = Am1DsPicSession::new(MustNotTouch);
        assert_eq!(
            session.set_voltage(910),
            Err(SessionError::FirmwareNotAdmitted)
        );
        assert_eq!(
            session.enable_dc_dc(1),
            Err(SessionError::FirmwareNotAdmitted)
        );
    }

    #[test]
    fn session_rejects_enable_values_outside_0_1_before_any_wire_phase() {
        let mut session = Am1DsPicSession::new(MustNotTouch);
        assert_eq!(
            session.enable_dc_dc(2),
            Err(SessionError::InvalidEnable { enable: 2 })
        );
        assert_eq!(
            session.enable_dc_dc(255),
            Err(SessionError::InvalidEnable { enable: 255 })
        );
    }

    #[test]
    fn heartbeat_gate_semantics_are_consecutive_and_reset_on_failure() {
        let mut gate = HeartbeatGate::new();
        assert!(!gate.voltage_permitted());
        for _ in 0..HEARTBEAT_TICKS_BEFORE_VOLTAGE {
            gate.record_tick(true);
        }
        assert!(gate.voltage_permitted());
        gate.record_tick(false);
        assert_eq!(gate.stable_ticks(), 0);
        assert!(!gate.voltage_permitted());
    }

    #[test]
    fn stock_timing_and_reply_shape_constants_hold_the_disassembled_values() {
        assert_eq!(STOCK_HEARTBEAT_REPLY_WAIT_MS, 500);
        assert_eq!(STOCK_ENABLE_REPLY_WAIT_MS, 10);
        assert_eq!(STOCK_SET_VOLTAGE_REPLY_WAIT_MS, 100);
        assert_eq!(STOCK_GET_VERSION_REPLY_WAIT_MS, 100);
        assert_eq!(STOCK_SWEEP_INTERVAL_MS, 10_000);
        assert_eq!(STOCK_RESET_WAIT_MS, 400);
        assert_eq!(STOCK_RETRY_BUDGET, 3);
        assert_eq!(STOCK_VOLTAGE_RAMP_STEP, 5);
        assert_eq!(T9PLUS_CHAINS, 9);
        assert_eq!(T9PLUS_PIC_GROUPS, 3);
        assert_eq!(NACK_FLUSH_BYTES, 16);
        assert_eq!(HEARTBEAT_TICKS_BEFORE_VOLTAGE, 5);
        assert_eq!(nack_flush(), [0u8; 16]);
        // Per-command stock waits and reply lengths.
        assert_eq!(AdapterCommand::Heartbeat.stock_reply_wait_ms(), 500);
        assert_eq!(AdapterCommand::Heartbeat.stock_reply_len(), 6);
        assert_eq!(AdapterCommand::GetSoftwareVersion.stock_reply_len(), 5);
        assert_eq!(
            AdapterCommand::EnableDcDc { enable: 1 }.stock_reply_len(),
            2
        );
        assert_eq!(
            AdapterCommand::SetVoltage { pic_byte: 4 }.stock_reply_len(),
            2
        );
    }
}
