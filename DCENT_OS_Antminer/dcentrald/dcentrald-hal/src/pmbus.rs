//! Generic **read-only** PMBus telemetry for the PMBus-class Bitmain PSU
//! families (APW3++ / APW10 / APW11 at I²C `0x58`).
//!
//! APW9 is intentionally excluded. Held S17/S17 Pro factory-jig bytes pin
//! APW9 to a proprietary framed-I²C protocol at `0x10`, not standard PMBus.
//! This module must never probe an APW9.
//!
//! # Status: EXPERIMENTAL — DESK-EVIDENCE ONLY
//!
//! Nothing in this module has been verified against a live PSU. It is
//! implemented from the public PMBus 1.3 Part II command set (command codes
//! and the SLINEAR11 / ULINEAR16 numeric formats are specification facts).
//! The Mujina reference miner ships an equivalent generic layer at
//!
//! (+ `pmbus/pmbus_types.rs`, GPL-3.0); it was located and used only as a
//! cross-check that our command codes and 5-bit exponent sign-extension agree
//! with an independent implementation. No Mujina code is copied here, and the
//! decode semantics below are deliberately *not* identical to theirs (see the
//! signed-mantissa note in [`slinear11`]).
//!
//! # Hard invariants (do not weaken)
//!
//! 1. **This layer is read-only.** No output-setting, on/off, fault-clearing,
//!    margin, store/restore, or page-latching command is defined anywhere in
//!    this file. [`PmbusReadCommand`] is the complete command surface and
//!    every variant is a telemetry/status/identity read. There is no encoder,
//!    no `to_*` numeric encoder, and no command-emitting API at all.
//! 2. **Every transaction goes through the existing `I2cServiceHandle`.** The
//!    `0x50..=0x57` EEPROM write denylist and the single-owner I²C service
//!    stay in force; this module never opens a bus, never maps raw physical
//!    memory, and never bypasses the service.
//! 3. **A failed read is never a number.** Every field is a
//!    [`Measured<T>`], whose absent variant carries a typed
//!    [`TelemetryUnknown`] reason. There is deliberately no zero-substituting
//!    accessor and no numeric `Default`: a bus error cannot reach a safety
//!    check or the dashboard disguised as `0 V` or `0 A`.
//! 4. **Nothing auto-enables.** [`PmbusTelemetryGate::from_env`] is
//!    default-OFF; a caller must opt in explicitly. Probing is otherwise
//!    passive (reads only).
//! 5. **No fabricated electrical values.** This module contains no PSU wattage,
//!    efficiency, or calibration constants at all.
//!
//! # SMBus read shape and its honest classification
//!
//! A PMBus read is an SMBus Read Byte/Word/Block: the host writes the command
//! code (a register pointer), then issues a repeated START and reads. The
//! command-code phase puts bytes on the wire, so the HAL classifies it as
//! [`I2cMutationLabel::QueryPrelude`] — "a write-bearing query is a controller
//! mutation even when its protocol-level purpose is observation". That is the
//! correct existing label; this module does not invent a privileged read
//! intent to route around it. No PAGE select is ever issued, so only the
//! device's currently selected page is observable.

use serde::Serialize;

use crate::i2c::{I2cMutationLabel, I2cServiceHandle};
use crate::{HalError, Result};

/// Canonical 7-bit I²C address for the PMBus-class Bitmain APW families.
///
/// Source: `dcentrald-silicon-profiles::psus` catalog rows for APW3++ /
/// APW10 / APW11 (`i2c_address: Some(0x58)`, `protocol: PmBus`). APW7 has no
/// signal terminal; APW9 is proprietary framed I²C at `0x10`.
pub const PMBUS_PSU_I2C_ADDRESS: u8 = 0x58;

/// Secondary address some APW units answer on (RE2 §5.1 notes `0x58/0x59`).
/// Recorded for completeness; the layer defaults to [`PMBUS_PSU_I2C_ADDRESS`].
pub const PMBUS_PSU_I2C_ADDRESS_ALT: u8 = 0x59;

/// DESK-EVIDENCE candidate, **UNPROBED** — not used by this module.
///
/// The ePIC UMC OS PSU "proto-V1" dispatch table carries *both*
/// `read_iout_0x04_v1` and `read_iout_0xe2_v1`, which reads as a second
/// output-current opcode on the Bitmain proprietary v1 dialect (NOT PMBus).
/// Source:
/// 06-POWER_PSU_PIC_I2C.md` §12 / §C-7.
///
/// We have **no live confirmation**, no effect classification, and no evidence
/// it is a pure read. It is recorded here as a lead only. It is intentionally
/// absent from [`PmbusReadCommand`] and is never dispatched: it belongs to a
/// different protocol family and would need its own characterized adapter.
pub const CANDIDATE_PROTO_V1_MEASURE_CURRENT_UNPROBED: u8 = 0xE2;

// ============================================================================
// Command surface — reads only
// ============================================================================

/// The complete PMBus command surface this module may emit.
///
/// Every variant is a telemetry, status, or identity **read**. Adding a
/// state-changing code here is a task failure; `tests/pmbus_read_only.rs`
/// numerically pins the admissible code region and rejects the known
/// state-changing codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PmbusReadCommand {
    /// `0x20` — output-voltage data format. Read to obtain the ULINEAR16
    /// exponent; this module never writes it.
    VoutMode,
    /// `0x79` — 16-bit status summary.
    StatusWord,
    /// `0x7A` — output-voltage status byte.
    StatusVout,
    /// `0x7B` — output-current status byte.
    StatusIout,
    /// `0x7C` — input status byte.
    StatusInput,
    /// `0x7D` — temperature status byte.
    StatusTemperature,
    /// `0x7E` — communication/logic/memory status byte.
    StatusCml,
    /// `0x7F` — other status byte.
    StatusOther,
    /// `0x88` — measured input voltage (SLINEAR11).
    ReadVin,
    /// `0x89` — measured input current (SLINEAR11).
    ReadIin,
    /// `0x8B` — measured output voltage (ULINEAR16, exponent from `0x20`).
    ReadVout,
    /// `0x8C` — measured output current (SLINEAR11).
    ReadIout,
    /// `0x8D` — measured temperature 1 (SLINEAR11).
    ReadTemperature1,
    /// `0x90` — measured fan speed 1, RPM (SLINEAR11).
    ReadFanSpeed1,
    /// `0x96` — measured output power (SLINEAR11).
    ReadPout,
    /// `0x97` — measured input power (SLINEAR11).
    ReadPin,
    /// `0x99` — manufacturer ID (block read).
    MfrId,
    /// `0x9A` — manufacturer model (block read).
    MfrModel,
    /// `0x9B` — manufacturer revision (block read).
    MfrRevision,
}

/// How many bytes a command's payload occupies on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PmbusReadWidth {
    /// SMBus Read Byte — one data byte.
    Byte,
    /// SMBus Read Word — two data bytes, little-endian.
    Word,
    /// SMBus Read Block — leading length byte then that many data bytes.
    Block,
}

/// How a numeric payload is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PmbusEncoding {
    /// Signed 11-bit mantissa, signed 5-bit exponent, self-describing.
    Slinear11,
    /// Unsigned 16-bit mantissa; exponent supplied out-of-band by `0x20`.
    Ulinear16,
    /// Raw bits (status registers, identity blocks).
    Raw,
}

impl PmbusReadCommand {
    /// PMBus 1.3 command code.
    pub const fn code(self) -> u8 {
        match self {
            Self::VoutMode => 0x20,
            Self::StatusWord => 0x79,
            Self::StatusVout => 0x7A,
            Self::StatusIout => 0x7B,
            Self::StatusInput => 0x7C,
            Self::StatusTemperature => 0x7D,
            Self::StatusCml => 0x7E,
            Self::StatusOther => 0x7F,
            Self::ReadVin => 0x88,
            Self::ReadIin => 0x89,
            Self::ReadVout => 0x8B,
            Self::ReadIout => 0x8C,
            Self::ReadTemperature1 => 0x8D,
            Self::ReadFanSpeed1 => 0x90,
            Self::ReadPout => 0x96,
            Self::ReadPin => 0x97,
            Self::MfrId => 0x99,
            Self::MfrModel => 0x9A,
            Self::MfrRevision => 0x9B,
        }
    }

    /// Wire width of the payload.
    pub const fn width(self) -> PmbusReadWidth {
        match self {
            Self::VoutMode
            | Self::StatusVout
            | Self::StatusIout
            | Self::StatusInput
            | Self::StatusTemperature
            | Self::StatusCml
            | Self::StatusOther => PmbusReadWidth::Byte,
            Self::StatusWord
            | Self::ReadVin
            | Self::ReadIin
            | Self::ReadVout
            | Self::ReadIout
            | Self::ReadTemperature1
            | Self::ReadFanSpeed1
            | Self::ReadPout
            | Self::ReadPin => PmbusReadWidth::Word,
            Self::MfrId | Self::MfrModel | Self::MfrRevision => PmbusReadWidth::Block,
        }
    }

    /// Numeric encoding of the payload.
    pub const fn encoding(self) -> PmbusEncoding {
        match self {
            Self::ReadVin
            | Self::ReadIin
            | Self::ReadIout
            | Self::ReadTemperature1
            | Self::ReadFanSpeed1
            | Self::ReadPout
            | Self::ReadPin => PmbusEncoding::Slinear11,
            Self::ReadVout => PmbusEncoding::Ulinear16,
            Self::VoutMode
            | Self::StatusWord
            | Self::StatusVout
            | Self::StatusIout
            | Self::StatusInput
            | Self::StatusTemperature
            | Self::StatusCml
            | Self::StatusOther
            | Self::MfrId
            | Self::MfrModel
            | Self::MfrRevision => PmbusEncoding::Raw,
        }
    }

    /// Short mnemonic, for logs and diagnostics.
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::VoutMode => "VOUT_MODE",
            Self::StatusWord => "STATUS_WORD",
            Self::StatusVout => "STATUS_VOUT",
            Self::StatusIout => "STATUS_IOUT",
            Self::StatusInput => "STATUS_INPUT",
            Self::StatusTemperature => "STATUS_TEMPERATURE",
            Self::StatusCml => "STATUS_CML",
            Self::StatusOther => "STATUS_OTHER",
            Self::ReadVin => "READ_VIN",
            Self::ReadIin => "READ_IIN",
            Self::ReadVout => "READ_VOUT",
            Self::ReadIout => "READ_IOUT",
            Self::ReadTemperature1 => "READ_TEMPERATURE_1",
            Self::ReadFanSpeed1 => "READ_FAN_SPEED_1",
            Self::ReadPout => "READ_POUT",
            Self::ReadPin => "READ_PIN",
            Self::MfrId => "MFR_ID",
            Self::MfrModel => "MFR_MODEL",
            Self::MfrRevision => "MFR_REVISION",
        }
    }

    /// Every command this module may ever emit, in probe order.
    pub const ALL: &'static [Self] = &[
        Self::VoutMode,
        Self::StatusWord,
        Self::StatusVout,
        Self::StatusIout,
        Self::StatusInput,
        Self::StatusTemperature,
        Self::StatusCml,
        Self::StatusOther,
        Self::ReadVin,
        Self::ReadIin,
        Self::ReadVout,
        Self::ReadIout,
        Self::ReadTemperature1,
        Self::ReadFanSpeed1,
        Self::ReadPout,
        Self::ReadPin,
        Self::MfrId,
        Self::MfrModel,
        Self::MfrRevision,
    ];
}

// ============================================================================
// Typed-unknown telemetry
// ============================================================================

/// Why a measurement is absent. Absence is always typed and always explicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "reason", content = "detail")]
pub enum TelemetryUnknown {
    /// No attempt was made (gate off, or the field is not in this probe set).
    NotProbed,
    /// The bus/service returned an error. The value is **not** zero.
    TransportError(String),
    /// The device answered with fewer bytes than the command requires.
    ShortRead(String),
    /// The device answered, but the payload cannot be decoded (for example a
    /// ULINEAR16 reading with no `VOUT_MODE` exponent available).
    UndecodableEncoding(String),
    /// The command is not supported by this PSU family or firmware.
    UnsupportedByDevice,
    /// Telemetry is gated off; the caller did not opt in.
    NotEnabled,
}

impl std::fmt::Display for TelemetryUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotProbed => f.write_str("not probed"),
            Self::TransportError(detail) => write!(f, "transport error: {detail}"),
            Self::ShortRead(detail) => write!(f, "short read: {detail}"),
            Self::UndecodableEncoding(detail) => write!(f, "undecodable: {detail}"),
            Self::UnsupportedByDevice => f.write_str("unsupported by device"),
            Self::NotEnabled => f.write_str("telemetry not enabled"),
        }
    }
}

/// A measurement that is either genuinely known or explicitly, typed-unknown.
///
/// There is deliberately **no** zero-substituting accessor and no numeric
/// `Default` on this type: an absent reading can never silently become `0`.
/// Consumers must match, or use [`Measured::known`] and handle `None`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Measured<T> {
    /// A value actually read from the device and successfully decoded.
    Known(T),
    /// No value. Carries the typed reason; never a substituted number.
    Unknown(TelemetryUnknown),
}

impl<T> Measured<T> {
    /// The value, if it was actually measured.
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown(_) => None,
        }
    }

    /// Consume into the measured value, if any.
    pub fn into_known(self) -> Option<T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown(_) => None,
        }
    }

    /// The typed reason a value is absent, if it is absent.
    pub fn unknown_reason(&self) -> Option<&TelemetryUnknown> {
        match self {
            Self::Known(_) => None,
            Self::Unknown(reason) => Some(reason),
        }
    }

    /// True when the value was actually measured.
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }

    /// Map the measured value, preserving the unknown reason unchanged.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Measured<U> {
        match self {
            Self::Known(value) => Measured::Known(f(value)),
            Self::Unknown(reason) => Measured::Unknown(reason),
        }
    }
}

impl<T> Default for Measured<T> {
    /// A default-constructed measurement is **unknown**, never zero.
    fn default() -> Self {
        Self::Unknown(TelemetryUnknown::NotProbed)
    }
}

impl From<&HalError> for TelemetryUnknown {
    fn from(error: &HalError) -> Self {
        Self::TransportError(error.to_string())
    }
}

// ============================================================================
// Numeric formats
// ============================================================================

/// Sign-extend a PMBus 5-bit two's-complement exponent to `i8`.
///
/// Range is `-16..=15`. Shared by SLINEAR11 (bits 15:11 of the word) and
/// ULINEAR16 (bits 4:0 of `VOUT_MODE`), so the two can never drift apart.
pub const fn extend_pmbus_exponent(raw_5bit: u8) -> i8 {
    let masked = raw_5bit & 0x1F;
    if masked & 0x10 != 0 {
        // Bit 4 set => negative; fill the upper three bits.
        (masked | 0xE0) as i8
    } else {
        masked as i8
    }
}

/// SLINEAR11: signed 11-bit mantissa (bits 10:0), signed 5-bit exponent
/// (bits 15:11).
///
/// The mantissa is **signed**. Decoding it as unsigned is the classic port
/// bug: it silently turns a negative temperature or a reverse current into a
/// large positive number. `READ_TEMPERATURE_1` below freezing and any
/// bidirectional current reading depend on this.
pub mod slinear11 {
    use super::extend_pmbus_exponent;

    const MANTISSA_MASK: u16 = 0x07FF;
    const MANTISSA_SIGN_BIT: u16 = 0x0400;

    /// Raw 5-bit exponent field of a SLINEAR11 word, sign-extended.
    pub const fn exponent(raw: u16) -> i8 {
        extend_pmbus_exponent(((raw >> 11) & 0x1F) as u8)
    }

    /// Signed 11-bit mantissa of a SLINEAR11 word.
    pub const fn mantissa(raw: u16) -> i16 {
        let bits = raw & MANTISSA_MASK;
        if bits & MANTISSA_SIGN_BIT != 0 {
            // Sign-extend the 11-bit field into a full i16.
            (bits | 0xF800) as i16
        } else {
            bits as i16
        }
    }

    /// Decode a SLINEAR11 word to a real value: `mantissa * 2^exponent`.
    pub fn to_f64(raw: u16) -> f64 {
        f64::from(mantissa(raw)) * exp2(exponent(raw))
    }

    /// `2^e` for the PMBus exponent range `-16..=15`, exactly representable.
    fn exp2(exponent: i8) -> f64 {
        if exponent >= 0 {
            f64::from(1u32 << (exponent as u32))
        } else {
            1.0 / f64::from(1u32 << ((-(exponent as i32)) as u32))
        }
    }
}

/// ULINEAR16: unsigned 16-bit mantissa scaled by the `VOUT_MODE` exponent.
pub mod ulinear16 {
    use super::extend_pmbus_exponent;

    /// The PMBus data-format selector in `VOUT_MODE` bits 7:5.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum VoutModeFormat {
        Linear,
        Vid,
        Direct,
        Ieee754Half,
        Reserved(u8),
    }

    /// Format selector encoded in a raw `VOUT_MODE` byte.
    pub const fn format(vout_mode: u8) -> VoutModeFormat {
        match (vout_mode >> 5) & 0x07 {
            0b000 => VoutModeFormat::Linear,
            0b001 => VoutModeFormat::Vid,
            0b010 => VoutModeFormat::Direct,
            0b011 => VoutModeFormat::Ieee754Half,
            other => VoutModeFormat::Reserved(other),
        }
    }

    /// Sign-extended exponent from `VOUT_MODE` bits 4:0.
    pub const fn exponent(vout_mode: u8) -> i8 {
        extend_pmbus_exponent(vout_mode & 0x1F)
    }

    /// Decode a ULINEAR16 word using a raw `VOUT_MODE` byte.
    ///
    /// Some parts (notably TI's TPS546 family) use only bits 6:5 for the mode
    /// and put a REL flag in bit 7, so a byte such as `0x97` decodes as Linear
    /// with exponent `-9` under that convention while bits 7:5 read as
    /// `0b100`. We therefore accept both `Linear` and any mode whose bits 6:5
    /// are zero, and refuse the genuinely different formats.
    pub fn to_f64(raw: u16, vout_mode: u8) -> Option<f64> {
        let tps546_shaped = (vout_mode >> 5) & 0x03 == 0;
        if !matches!(format(vout_mode), VoutModeFormat::Linear) && !tps546_shaped {
            return None;
        }
        Some(f64::from(raw) * exp2(exponent(vout_mode)))
    }

    fn exp2(exponent: i8) -> f64 {
        if exponent >= 0 {
            f64::from(1u32 << (exponent as u32))
        } else {
            1.0 / f64::from(1u32 << ((-(exponent as i32)) as u32))
        }
    }
}

// ============================================================================
// Status decoding (read-only interpretation of STATUS_WORD)
// ============================================================================

/// Decoded `STATUS_WORD` (`0x79`) flags. Purely interpretive; setting or
/// clearing device status is out of scope for this module by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StatusWordFlags {
    pub raw: u16,
    pub vout_fault: bool,
    pub iout_fault: bool,
    pub input_fault: bool,
    pub mfr_specific: bool,
    pub power_good_negated: bool,
    pub fan_fault: bool,
    pub other_fault: bool,
    pub busy: bool,
    pub off: bool,
    pub vout_over_voltage: bool,
    pub iout_over_current: bool,
    pub vin_under_voltage: bool,
    pub temperature_fault: bool,
    pub cml_fault: bool,
}

impl StatusWordFlags {
    /// Decode a raw `STATUS_WORD`.
    pub const fn decode(raw: u16) -> Self {
        Self {
            raw,
            vout_fault: raw & 0x8000 != 0,
            iout_fault: raw & 0x4000 != 0,
            input_fault: raw & 0x2000 != 0,
            mfr_specific: raw & 0x1000 != 0,
            power_good_negated: raw & 0x0800 != 0,
            fan_fault: raw & 0x0400 != 0,
            other_fault: raw & 0x0200 != 0,
            busy: raw & 0x0080 != 0,
            off: raw & 0x0040 != 0,
            vout_over_voltage: raw & 0x0020 != 0,
            iout_over_current: raw & 0x0010 != 0,
            vin_under_voltage: raw & 0x0008 != 0,
            temperature_fault: raw & 0x0004 != 0,
            cml_fault: raw & 0x0002 != 0,
        }
    }

    /// True when any fault or warning bit is asserted.
    pub const fn any_fault(self) -> bool {
        self.vout_fault
            || self.iout_fault
            || self.input_fault
            || self.mfr_specific
            || self.fan_fault
            || self.other_fault
            || self.vout_over_voltage
            || self.iout_over_current
            || self.vin_under_voltage
            || self.temperature_fault
            || self.cml_fault
    }
}

// ============================================================================
// Transport
// ============================================================================

/// The **only** bus capability this module requires: fetch the payload of one
/// read command.
///
/// The trait has exactly one method and it is a read. There is no
/// counterpart that emits data, so no PMBus write path can exist behind this
/// abstraction — a compile-time property, not a runtime check.
pub trait PmbusReadTransport {
    /// Point the device at `command` and read `read_len` payload bytes.
    ///
    /// Implementations MUST NOT alter device state beyond the SMBus
    /// command-code pointer that the protocol requires.
    fn read_command_payload(
        &self,
        address: u8,
        command: PmbusReadCommand,
        read_len: usize,
    ) -> Result<Vec<u8>>;
}

/// Maximum block-read payload we will accept (length byte + data).
const MAX_BLOCK_PAYLOAD: usize = 33;

impl PmbusReadTransport for I2cServiceHandle {
    fn read_command_payload(
        &self,
        address: u8,
        command: PmbusReadCommand,
        read_len: usize,
    ) -> Result<Vec<u8>> {
        // The SMBus command-code phase puts one byte on the wire, so this is
        // classified as a write-bearing query (`QueryPrelude`) by the shared
        // service — the existing, honest label. Nothing here bypasses the
        // service, its serialization, or its EEPROM write denylist.
        self.write_read_mutating(
            I2cMutationLabel::QueryPrelude,
            address,
            &[command.code()],
            read_len,
        )
    }
}

// ============================================================================
// Opt-in gate
// ============================================================================

/// Environment variable that opts a unit in to PMBus telemetry polling.
pub const PMBUS_TELEMETRY_ENV: &str = "DCENT_PMBUS_TELEMETRY";

/// Whether PMBus telemetry may be probed at all. Default is OFF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PmbusTelemetryGate {
    /// Never touch the bus. This is the default on every platform.
    Disabled,
    /// The operator explicitly opted in for this run.
    EnabledByOperator,
}

impl Default for PmbusTelemetryGate {
    fn default() -> Self {
        Self::Disabled
    }
}

impl PmbusTelemetryGate {
    /// Resolve the gate from the process environment.
    ///
    /// Only the exact value `1` enables it. Anything else — unset, empty,
    /// `0`, `true`, garbage — leaves telemetry disabled. Experimental
    /// hardware features do not get to be enabled by accident.
    pub fn from_env() -> Self {
        Self::from_raw(dcentrald_common::lab_env::var(PMBUS_TELEMETRY_ENV).ok().as_deref())
    }

    /// Pure resolver for the gate, so the policy is testable without touching
    /// process-global state.
    pub fn from_raw(raw: Option<&str>) -> Self {
        match raw {
            Some("1") => Self::EnabledByOperator,
            _ => Self::Disabled,
        }
    }

    /// True when probing is permitted.
    pub fn is_enabled(self) -> bool {
        matches!(self, Self::EnabledByOperator)
    }
}

// ============================================================================
// Families
// ============================================================================

/// PSU families this read-only layer covers.
///
/// Membership follows the `PsuProtocol::PmBus` rows of the shared PSU catalog
/// (`dcentrald-silicon-profiles::psus`). Max-power / efficiency figures are
/// deliberately not duplicated here — this module fabricates no electrical
/// constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PmbusPsuFamily {
    /// APW3++ — first-generation S9 PSU.
    Apw3PlusPlus,
    /// APW10 — catalog row marked PARTIAL upstream.
    Apw10,
    /// APW11 — catalog row marked PARTIAL upstream.
    Apw11,
}

impl PmbusPsuFamily {
    /// Every family this layer covers.
    pub const ALL: &'static [Self] = &[Self::Apw3PlusPlus, Self::Apw10, Self::Apw11];

    /// Catalog model string.
    pub const fn model(self) -> &'static str {
        match self {
            Self::Apw3PlusPlus => "APW3++",
            Self::Apw10 => "APW10",
            Self::Apw11 => "APW11",
        }
    }

    /// Catalog I²C address for every PMBus-class APW row.
    pub const fn i2c_address(self) -> u8 {
        PMBUS_PSU_I2C_ADDRESS
    }
}

// ============================================================================
// Telemetry snapshot
// ============================================================================

/// One read-only telemetry snapshot. Every field is typed-unknown-capable.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PmbusTelemetry {
    /// I²C address the snapshot was taken from.
    pub address: u8,
    /// Raw `VOUT_MODE` byte, needed to interpret `vout_v`.
    pub vout_mode_raw: Measured<u8>,
    /// Input voltage, volts.
    pub vin_v: Measured<f64>,
    /// Input current, amps.
    pub iin_a: Measured<f64>,
    /// Output voltage, volts.
    pub vout_v: Measured<f64>,
    /// Output current, amps.
    pub iout_a: Measured<f64>,
    /// Temperature sensor 1, degrees Celsius.
    pub temperature_c: Measured<f64>,
    /// Fan 1 speed, RPM.
    pub fan_speed_rpm: Measured<f64>,
    /// Output power, watts, as reported by the device.
    pub pout_w: Measured<f64>,
    /// Input power, watts, as reported by the device.
    pub pin_w: Measured<f64>,
    /// Decoded `STATUS_WORD`.
    pub status: Measured<StatusWordFlags>,
    /// Evidence tier for this snapshot. Always experimental today.
    pub evidence: &'static str,
}

/// Evidence marker stamped on every snapshot this module produces.
pub const PMBUS_EVIDENCE_TIER: &str = "EXPERIMENTAL/DESK-EVIDENCE: no live PSU verification";

impl PmbusTelemetry {
    /// An all-unknown snapshot with an explicit reason. Never zero-valued.
    pub fn all_unknown(address: u8, reason: TelemetryUnknown) -> Self {
        Self {
            address,
            vout_mode_raw: Measured::Unknown(reason.clone()),
            vin_v: Measured::Unknown(reason.clone()),
            iin_a: Measured::Unknown(reason.clone()),
            vout_v: Measured::Unknown(reason.clone()),
            iout_a: Measured::Unknown(reason.clone()),
            temperature_c: Measured::Unknown(reason.clone()),
            fan_speed_rpm: Measured::Unknown(reason.clone()),
            pout_w: Measured::Unknown(reason.clone()),
            pin_w: Measured::Unknown(reason.clone()),
            status: Measured::Unknown(reason),
            evidence: PMBUS_EVIDENCE_TIER,
        }
    }

    /// True when at least one field carries a real measurement.
    pub fn has_any_measurement(&self) -> bool {
        self.vin_v.is_known()
            || self.iin_a.is_known()
            || self.vout_v.is_known()
            || self.iout_a.is_known()
            || self.temperature_c.is_known()
            || self.fan_speed_rpm.is_known()
            || self.pout_w.is_known()
            || self.pin_w.is_known()
            || self.status.is_known()
    }
}

// ============================================================================
// Reader
// ============================================================================

/// Read-only PMBus telemetry reader bound to one device address.
pub struct PmbusReader<T: PmbusReadTransport> {
    transport: T,
    address: u8,
    gate: PmbusTelemetryGate,
}

impl<T: PmbusReadTransport> PmbusReader<T> {
    /// Bind a reader to `address` with an explicit gate. Nothing is read until
    /// a read method is called, and nothing is read at all while the gate is
    /// [`PmbusTelemetryGate::Disabled`].
    pub fn new(transport: T, address: u8, gate: PmbusTelemetryGate) -> Self {
        Self {
            transport,
            address,
            gate,
        }
    }

    /// Bind to the catalog address of a covered family.
    pub fn for_family(transport: T, family: PmbusPsuFamily, gate: PmbusTelemetryGate) -> Self {
        Self::new(transport, family.i2c_address(), gate)
    }

    /// The address this reader is bound to.
    pub fn address(&self) -> u8 {
        self.address
    }

    /// The gate this reader was constructed with.
    pub fn gate(&self) -> PmbusTelemetryGate {
        self.gate
    }

    fn payload(&self, command: PmbusReadCommand) -> std::result::Result<Vec<u8>, TelemetryUnknown> {
        if !self.gate.is_enabled() {
            return Err(TelemetryUnknown::NotEnabled);
        }
        let read_len = match command.width() {
            PmbusReadWidth::Byte => 1,
            PmbusReadWidth::Word => 2,
            PmbusReadWidth::Block => MAX_BLOCK_PAYLOAD,
        };
        let bytes = self
            .transport
            .read_command_payload(self.address, command, read_len)
            .map_err(|error| TelemetryUnknown::from(&error))?;
        let required = match command.width() {
            PmbusReadWidth::Byte => 1,
            PmbusReadWidth::Word => 2,
            PmbusReadWidth::Block => 1,
        };
        if bytes.len() < required {
            return Err(TelemetryUnknown::ShortRead(format!(
                "{} needs {} byte(s), device returned {}",
                command.mnemonic(),
                required,
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// Read a single-byte register.
    pub fn read_byte(&self, command: PmbusReadCommand) -> Measured<u8> {
        if command.width() != PmbusReadWidth::Byte {
            return Measured::Unknown(TelemetryUnknown::UndecodableEncoding(format!(
                "{} is not a byte-width command",
                command.mnemonic()
            )));
        }
        match self.payload(command) {
            Ok(bytes) => Measured::Known(bytes[0]),
            Err(reason) => Measured::Unknown(reason),
        }
    }

    /// Read a 16-bit register (SMBus word order: low byte first).
    pub fn read_word(&self, command: PmbusReadCommand) -> Measured<u16> {
        if command.width() != PmbusReadWidth::Word {
            return Measured::Unknown(TelemetryUnknown::UndecodableEncoding(format!(
                "{} is not a word-width command",
                command.mnemonic()
            )));
        }
        match self.payload(command) {
            Ok(bytes) => Measured::Known(u16::from(bytes[0]) | (u16::from(bytes[1]) << 8)),
            Err(reason) => Measured::Unknown(reason),
        }
    }

    /// Read and decode a SLINEAR11-encoded measurement.
    pub fn read_slinear11(&self, command: PmbusReadCommand) -> Measured<f64> {
        if command.encoding() != PmbusEncoding::Slinear11 {
            return Measured::Unknown(TelemetryUnknown::UndecodableEncoding(format!(
                "{} is not SLINEAR11-encoded",
                command.mnemonic()
            )));
        }
        self.read_word(command).map(slinear11::to_f64)
    }

    /// Read and decode the ULINEAR16 output voltage using a `VOUT_MODE` byte
    /// the caller already obtained. Without a mode byte the value stays
    /// unknown — it is never guessed and never defaulted to zero.
    pub fn read_vout_with_mode(&self, vout_mode: &Measured<u8>) -> Measured<f64> {
        let Some(mode) = vout_mode.known().copied() else {
            return Measured::Unknown(TelemetryUnknown::UndecodableEncoding(
                "output voltage needs a VOUT_MODE exponent, which was not readable".to_string(),
            ));
        };
        match self.read_word(PmbusReadCommand::ReadVout) {
            Measured::Known(raw) => match ulinear16::to_f64(raw, mode) {
                Some(volts) => Measured::Known(volts),
                None => Measured::Unknown(TelemetryUnknown::UndecodableEncoding(format!(
                    "VOUT_MODE 0x{mode:02X} selects a data format this layer does not decode"
                ))),
            },
            Measured::Unknown(reason) => Measured::Unknown(reason),
        }
    }

    /// Read the decoded status summary.
    pub fn read_status(&self) -> Measured<StatusWordFlags> {
        self.read_word(PmbusReadCommand::StatusWord)
            .map(StatusWordFlags::decode)
    }

    /// Read a manufacturer identity block, trimmed to printable ASCII.
    pub fn read_identity(&self, command: PmbusReadCommand) -> Measured<String> {
        if command.width() != PmbusReadWidth::Block {
            return Measured::Unknown(TelemetryUnknown::UndecodableEncoding(format!(
                "{} is not a block-read command",
                command.mnemonic()
            )));
        }
        let bytes = match self.payload(command) {
            Ok(bytes) => bytes,
            Err(reason) => return Measured::Unknown(reason),
        };
        let declared = bytes[0] as usize;
        let available = bytes.len().saturating_sub(1);
        if declared == 0 || declared > available {
            return Measured::Unknown(TelemetryUnknown::ShortRead(format!(
                "{} declared {} byte(s) but {} followed",
                command.mnemonic(),
                declared,
                available
            )));
        }
        let text: String = bytes[1..=declared]
            .iter()
            .copied()
            .take_while(|byte| *byte != 0)
            .filter(|byte| byte.is_ascii_graphic() || *byte == b' ')
            .map(char::from)
            .collect();
        let trimmed = text.trim().to_string();
        if trimmed.is_empty() {
            Measured::Unknown(TelemetryUnknown::UndecodableEncoding(format!(
                "{} returned no printable identity bytes",
                command.mnemonic()
            )))
        } else {
            Measured::Known(trimmed)
        }
    }

    /// Take one full telemetry snapshot.
    ///
    /// A gated-off reader returns an all-unknown snapshot **without touching
    /// the bus**. Individual failures degrade that field alone; they never
    /// substitute a number and never abort the remaining reads.
    pub fn snapshot(&self) -> PmbusTelemetry {
        if !self.gate.is_enabled() {
            return PmbusTelemetry::all_unknown(self.address, TelemetryUnknown::NotEnabled);
        }
        let vout_mode_raw = self.read_byte(PmbusReadCommand::VoutMode);
        PmbusTelemetry {
            address: self.address,
            vin_v: self.read_slinear11(PmbusReadCommand::ReadVin),
            iin_a: self.read_slinear11(PmbusReadCommand::ReadIin),
            vout_v: self.read_vout_with_mode(&vout_mode_raw),
            iout_a: self.read_slinear11(PmbusReadCommand::ReadIout),
            temperature_c: self.read_slinear11(PmbusReadCommand::ReadTemperature1),
            fan_speed_rpm: self.read_slinear11(PmbusReadCommand::ReadFanSpeed1),
            pout_w: self.read_slinear11(PmbusReadCommand::ReadPout),
            pin_w: self.read_slinear11(PmbusReadCommand::ReadPin),
            status: self.read_status(),
            vout_mode_raw,
            evidence: PMBUS_EVIDENCE_TIER,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records every command it is asked for, so tests can prove exactly what
    /// went on the wire.
    struct FakeBus {
        responses: Vec<(PmbusReadCommand, Result<Vec<u8>>)>,
        seen: RefCell<Vec<u8>>,
    }

    impl FakeBus {
        fn new(responses: Vec<(PmbusReadCommand, Result<Vec<u8>>)>) -> Self {
            Self {
                responses,
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl PmbusReadTransport for &FakeBus {
        fn read_command_payload(
            &self,
            _address: u8,
            command: PmbusReadCommand,
            _read_len: usize,
        ) -> Result<Vec<u8>> {
            self.seen.borrow_mut().push(command.code());
            for (candidate, response) in &self.responses {
                if *candidate == command {
                    return match response {
                        Ok(bytes) => Ok(bytes.clone()),
                        Err(error) => Err(HalError::Other(error.to_string())),
                    };
                }
            }
            Err(HalError::I2c {
                bus: 0,
                addr: PMBUS_PSU_I2C_ADDRESS,
                detail: format!("no fake response for {}", command.mnemonic()),
            })
        }
    }

    fn bus_error() -> HalError {
        HalError::I2c {
            bus: 0,
            addr: PMBUS_PSU_I2C_ADDRESS,
            detail: "simulated NACK".into(),
        }
    }

    // --- SLINEAR11 hand-computed vectors -------------------------------

    #[test]
    fn slinear11_positive_exponent_zero() {
        // 0x0064: exponent bits 00000 -> 0, mantissa 0x064 -> 100. 100 * 2^0.
        assert_eq!(slinear11::exponent(0x0064), 0);
        assert_eq!(slinear11::mantissa(0x0064), 100);
        assert!((slinear11::to_f64(0x0064) - 100.0).abs() < 1e-12);
    }

    #[test]
    fn slinear11_negative_exponent_positive_mantissa() {
        // 0xD2E6: exponent bits 11010 -> -6, mantissa 0x2E6 -> 742.
        // 742 * 2^-6 = 11.59375 exactly.
        assert_eq!(slinear11::exponent(0xD2E6), -6);
        assert_eq!(slinear11::mantissa(0xD2E6), 742);
        assert!((slinear11::to_f64(0xD2E6) - 11.59375).abs() < 1e-12);
    }

    #[test]
    fn slinear11_negative_mantissa_exponent_zero() {
        // 0x0400: exponent 0, mantissa bits 100_0000_0000 -> -1024.
        assert_eq!(slinear11::exponent(0x0400), 0);
        assert_eq!(slinear11::mantissa(0x0400), -1024);
        assert!((slinear11::to_f64(0x0400) + 1024.0).abs() < 1e-12);
        // An unsigned-mantissa port would report +1024 here.
        assert!(slinear11::to_f64(0x0400) < 0.0);
    }

    #[test]
    fn slinear11_negative_mantissa_and_negative_exponent() {
        // 0xF7D8: exponent bits 11110 -> -2, mantissa 0x7D8 -> -40.
        // -40 * 2^-2 = -10.0 degC.
        assert_eq!(slinear11::exponent(0xF7D8), -2);
        assert_eq!(slinear11::mantissa(0xF7D8), -40);
        assert!((slinear11::to_f64(0xF7D8) + 10.0).abs() < 1e-12);
    }

    #[test]
    fn slinear11_minus_one_half() {
        // 0xFFFF: exponent 11111 -> -1, mantissa 0x7FF -> -1. -1 * 2^-1.
        assert_eq!(slinear11::exponent(0xFFFF), -1);
        assert_eq!(slinear11::mantissa(0xFFFF), -1);
        assert!((slinear11::to_f64(0xFFFF) + 0.5).abs() < 1e-12);
    }

    #[test]
    fn slinear11_maximum_positive_exponent() {
        // 0x7801: exponent 01111 -> +15, mantissa 1. 1 * 2^15 = 32768.
        assert_eq!(slinear11::exponent(0x7801), 15);
        assert_eq!(slinear11::mantissa(0x7801), 1);
        assert!((slinear11::to_f64(0x7801) - 32768.0).abs() < 1e-12);
    }

    #[test]
    fn slinear11_most_negative_exponent() {
        // 0x8001: exponent 10000 -> -16, mantissa 1. 1 * 2^-16.
        assert_eq!(slinear11::exponent(0x8001), -16);
        assert!((slinear11::to_f64(0x8001) - (1.0 / 65536.0)).abs() < 1e-15);
    }

    #[test]
    fn slinear11_zero_is_zero() {
        assert_eq!(slinear11::to_f64(0x0000), 0.0);
    }

    #[test]
    fn exponent_sign_extension_spans_the_full_five_bit_range() {
        assert_eq!(extend_pmbus_exponent(0x00), 0);
        assert_eq!(extend_pmbus_exponent(0x0F), 15);
        assert_eq!(extend_pmbus_exponent(0x10), -16);
        assert_eq!(extend_pmbus_exponent(0x17), -9);
        assert_eq!(extend_pmbus_exponent(0x1E), -2);
        assert_eq!(extend_pmbus_exponent(0x1F), -1);
    }

    // --- ULINEAR16 hand-computed vectors -------------------------------

    #[test]
    fn ulinear16_standard_mode_exponent_minus_nine() {
        // VOUT_MODE 0x17: bits 7:5 = 000 (Linear), exponent 10111 -> -9.
        assert_eq!(ulinear16::exponent(0x17), -9);
        assert_eq!(ulinear16::format(0x17), ulinear16::VoutModeFormat::Linear);
        // 0x0266 = 614; 614 / 512 = 1.19921875 exactly.
        let volts = ulinear16::to_f64(0x0266, 0x17).unwrap();
        assert!((volts - 1.19921875).abs() < 1e-12);
    }

    #[test]
    fn ulinear16_twelve_volt_rail() {
        // exponent -9, 6144 counts -> 12.0 V exactly.
        let volts = ulinear16::to_f64(0x1800, 0x17).unwrap();
        assert!((volts - 12.0).abs() < 1e-12);
    }

    #[test]
    fn ulinear16_exponent_minus_twelve() {
        assert_eq!(ulinear16::exponent(0x14), -12);
        let volts = ulinear16::to_f64(4096, 0x14).unwrap();
        assert!((volts - 1.0).abs() < 1e-12);
    }

    #[test]
    fn ulinear16_positive_exponent() {
        // VOUT_MODE 0x01: Linear, exponent +1. 6 counts -> 12.0.
        assert_eq!(ulinear16::exponent(0x01), 1);
        let volts = ulinear16::to_f64(6, 0x01).unwrap();
        assert!((volts - 12.0).abs() < 1e-12);
    }

    #[test]
    fn ulinear16_accepts_the_tps546_style_rel_bit() {
        // 0x97 has bit 7 set (REL under TI's convention) but bits 6:5 zero.
        assert_eq!(ulinear16::exponent(0x97), -9);
        let volts = ulinear16::to_f64(0x0266, 0x97).unwrap();
        assert!((volts - 1.19921875).abs() < 1e-12);
    }

    #[test]
    fn ulinear16_refuses_formats_it_cannot_decode() {
        // VID (001) and Direct (010) are genuinely different encodings.
        assert!(ulinear16::to_f64(0x0100, 0x37).is_none());
        assert!(ulinear16::to_f64(0x0100, 0x57).is_none());
    }

    // --- unknown-vs-zero ------------------------------------------------

    #[test]
    fn a_bus_error_surfaces_as_typed_unknown_never_zero() {
        let bus = FakeBus::new(vec![(PmbusReadCommand::ReadVin, Err(bus_error()))]);
        let reader = PmbusReader::new(
            &bus,
            PMBUS_PSU_I2C_ADDRESS,
            PmbusTelemetryGate::EnabledByOperator,
        );
        let vin = reader.read_slinear11(PmbusReadCommand::ReadVin);
        assert!(!vin.is_known());
        assert!(vin.known().is_none());
        assert!(matches!(
            vin.unknown_reason(),
            Some(TelemetryUnknown::TransportError(_))
        ));
        // The decisive property: there is no numeric value to read out.
        assert_eq!(vin.into_known(), None);
    }

    #[test]
    fn a_short_read_surfaces_as_typed_unknown_never_zero() {
        let bus = FakeBus::new(vec![(PmbusReadCommand::ReadIout, Ok(vec![0x12]))]);
        let reader = PmbusReader::new(
            &bus,
            PMBUS_PSU_I2C_ADDRESS,
            PmbusTelemetryGate::EnabledByOperator,
        );
        let iout = reader.read_slinear11(PmbusReadCommand::ReadIout);
        assert!(matches!(
            iout.unknown_reason(),
            Some(TelemetryUnknown::ShortRead(_))
        ));
        assert_eq!(iout.into_known(), None);
    }

    #[test]
    fn an_all_zero_reply_is_a_real_zero_and_stays_distinct_from_unknown() {
        // A device that genuinely answers 0x0000 reports Known(0.0); this must
        // remain distinguishable from a failed read.
        let bus = FakeBus::new(vec![(PmbusReadCommand::ReadIout, Ok(vec![0x00, 0x00]))]);
        let reader = PmbusReader::new(
            &bus,
            PMBUS_PSU_I2C_ADDRESS,
            PmbusTelemetryGate::EnabledByOperator,
        );
        let iout = reader.read_slinear11(PmbusReadCommand::ReadIout);
        assert_eq!(iout, Measured::Known(0.0));
        assert!(iout.is_known());
    }

    #[test]
    fn default_measurement_is_unknown_not_zero() {
        let value: Measured<f64> = Measured::default();
        assert!(!value.is_known());
        assert_eq!(
            value.unknown_reason(),
            Some(&TelemetryUnknown::NotProbed),
            "a default-constructed measurement must be typed-unknown"
        );
    }

    #[test]
    fn output_voltage_without_a_mode_byte_stays_unknown() {
        let bus = FakeBus::new(vec![
            (PmbusReadCommand::VoutMode, Err(bus_error())),
            (PmbusReadCommand::ReadVout, Ok(vec![0x00, 0x18])),
        ]);
        let reader = PmbusReader::new(
            &bus,
            PMBUS_PSU_I2C_ADDRESS,
            PmbusTelemetryGate::EnabledByOperator,
        );
        let mode = reader.read_byte(PmbusReadCommand::VoutMode);
        let vout = reader.read_vout_with_mode(&mode);
        assert!(matches!(
            vout.unknown_reason(),
            Some(TelemetryUnknown::UndecodableEncoding(_))
        ));
        assert_eq!(vout.into_known(), None);
    }

    #[test]
    fn snapshot_marks_every_absent_field_and_keeps_measured_ones() {
        let bus = FakeBus::new(vec![
            (PmbusReadCommand::VoutMode, Ok(vec![0x17])),
            (PmbusReadCommand::ReadVout, Ok(vec![0x00, 0x18])),
            (PmbusReadCommand::ReadIout, Ok(vec![0xE6, 0xD2])),
            (PmbusReadCommand::ReadIin, Err(bus_error())),
        ]);
        let reader = PmbusReader::new(
            &bus,
            PMBUS_PSU_I2C_ADDRESS,
            PmbusTelemetryGate::EnabledByOperator,
        );
        let snapshot = reader.snapshot();

        assert_eq!(snapshot.vout_v, Measured::Known(12.0));
        assert!((snapshot.iout_a.known().copied().unwrap() - 11.59375).abs() < 1e-12);
        assert!(matches!(
            snapshot.iin_a.unknown_reason(),
            Some(TelemetryUnknown::TransportError(_))
        ));
        // Commands with no fake response fail as transport errors, not zeros.
        assert!(!snapshot.vin_v.is_known());
        assert!(!snapshot.temperature_c.is_known());
        assert!(!snapshot.pin_w.is_known());
        assert!(snapshot.has_any_measurement());
        assert_eq!(snapshot.evidence, PMBUS_EVIDENCE_TIER);
    }

    // --- gate -----------------------------------------------------------

    #[test]
    fn gate_defaults_to_disabled_and_only_exact_one_enables() {
        assert_eq!(PmbusTelemetryGate::default(), PmbusTelemetryGate::Disabled);
        assert_eq!(
            PmbusTelemetryGate::from_raw(None),
            PmbusTelemetryGate::Disabled
        );
        for raw in ["", "0", "true", "yes", "01", " 1", "1 ", "on"] {
            assert_eq!(
                PmbusTelemetryGate::from_raw(Some(raw)),
                PmbusTelemetryGate::Disabled,
                "{raw:?} must not enable experimental PSU telemetry"
            );
        }
        assert_eq!(
            PmbusTelemetryGate::from_raw(Some("1")),
            PmbusTelemetryGate::EnabledByOperator
        );
    }

    #[test]
    fn a_disabled_reader_never_touches_the_bus() {
        let bus = FakeBus::new(vec![(PmbusReadCommand::ReadVin, Ok(vec![0x00, 0x1B]))]);
        let reader = PmbusReader::new(&bus, PMBUS_PSU_I2C_ADDRESS, PmbusTelemetryGate::Disabled);
        let snapshot = reader.snapshot();
        assert!(bus.seen.borrow().is_empty(), "gated reader issued I/O");
        assert!(!snapshot.has_any_measurement());
        assert_eq!(
            snapshot.vin_v.unknown_reason(),
            Some(&TelemetryUnknown::NotEnabled)
        );
    }

    // --- command surface ------------------------------------------------

    #[test]
    fn every_emitted_command_code_is_a_read_command() {
        // PMBus 1.3 read/status/identity region. Anything outside this set is
        // either a configuration or a state-changing command.
        const ADMISSIBLE: &[u8] = &[
            0x20, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x88, 0x89, 0x8B, 0x8C, 0x8D, 0x90,
            0x96, 0x97, 0x99, 0x9A, 0x9B,
        ];
        for command in PmbusReadCommand::ALL {
            assert!(
                ADMISSIBLE.contains(&command.code()),
                "{} (0x{:02X}) is outside the read-only command region",
                command.mnemonic(),
                command.code()
            );
        }
    }

    #[test]
    fn no_state_changing_command_code_is_reachable() {
        // PAGE, on/off control, on/off configuration, fault clear, phase,
        // output-voltage set, margin high/low, store/restore default/user.
        const FORBIDDEN: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
        ];
        for command in PmbusReadCommand::ALL {
            assert!(
                !FORBIDDEN.contains(&command.code()),
                "{} (0x{:02X}) is a state-changing command and must not exist here",
                command.mnemonic(),
                command.code()
            );
        }
    }

    #[test]
    fn the_unprobed_proto_v1_candidate_is_never_dispatched() {
        for command in PmbusReadCommand::ALL {
            assert_ne!(
                command.code(),
                CANDIDATE_PROTO_V1_MEASURE_CURRENT_UNPROBED,
                "the DESK-EVIDENCE 0xE2 candidate must stay documentation-only"
            );
        }
    }

    #[test]
    fn command_codes_are_unique() {
        let mut codes: Vec<u8> = PmbusReadCommand::ALL.iter().map(|c| c.code()).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "duplicate PMBus command code");
    }

    #[test]
    fn covered_families_all_sit_at_the_catalog_address() {
        assert_eq!(PmbusPsuFamily::ALL.len(), 3);
        assert!(!PmbusPsuFamily::ALL
            .iter()
            .any(|family| matches!(family.model(), "APW7" | "APW9")));
        for family in PmbusPsuFamily::ALL {
            assert_eq!(family.i2c_address(), 0x58, "{}", family.model());
        }
    }

    // --- status ---------------------------------------------------------

    #[test]
    fn status_word_decodes_known_bit_positions() {
        let clean = StatusWordFlags::decode(0x0000);
        assert!(!clean.any_fault());

        let over_temp = StatusWordFlags::decode(0x0004);
        assert!(over_temp.temperature_fault);
        assert!(over_temp.any_fault());

        let over_current = StatusWordFlags::decode(0x4010);
        assert!(over_current.iout_fault);
        assert!(over_current.iout_over_current);

        let busy_only = StatusWordFlags::decode(0x0080);
        assert!(busy_only.busy);
        assert!(!busy_only.any_fault(), "BUSY alone is not a fault");
    }

    #[test]
    fn identity_block_reads_use_the_declared_length() {
        let bus = FakeBus::new(vec![(
            PmbusReadCommand::MfrId,
            Ok(vec![0x04, b'T', b'E', b'S', b'T', 0xFF, 0xFF]),
        )]);
        let reader = PmbusReader::new(
            &bus,
            PMBUS_PSU_I2C_ADDRESS,
            PmbusTelemetryGate::EnabledByOperator,
        );
        assert_eq!(
            reader.read_identity(PmbusReadCommand::MfrId),
            Measured::Known("TEST".to_string())
        );
    }

    #[test]
    fn identity_block_with_an_overlong_length_is_unknown_not_truncated_garbage() {
        let bus = FakeBus::new(vec![(PmbusReadCommand::MfrModel, Ok(vec![0x20, b'X']))]);
        let reader = PmbusReader::new(
            &bus,
            PMBUS_PSU_I2C_ADDRESS,
            PmbusTelemetryGate::EnabledByOperator,
        );
        assert!(matches!(
            reader
                .read_identity(PmbusReadCommand::MfrModel)
                .unknown_reason(),
            Some(TelemetryUnknown::ShortRead(_))
        ));
    }

    #[test]
    fn reads_are_issued_as_the_bare_command_code() {
        let bus = FakeBus::new(vec![(PmbusReadCommand::ReadVin, Ok(vec![0x00, 0x1B]))]);
        let reader = PmbusReader::new(
            &bus,
            PMBUS_PSU_I2C_ADDRESS,
            PmbusTelemetryGate::EnabledByOperator,
        );
        let _ = reader.read_slinear11(PmbusReadCommand::ReadVin);
        assert_eq!(bus.seen.borrow().as_slice(), &[0x88]);
    }
}
