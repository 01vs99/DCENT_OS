//! APW121215f UART-tunnel PSU driver — framed protocol on `/dev/i2c-N` @ 0x10.
//!
//! **Used on the AM335x BeagleBone S19j Pro on `S19J_IO_BOARD_V2_0` (the
//! `a lab unit` unit).** This is a *different* protocol from [`crate::psu_apw12_smbus`]
//! (bare SMBus opcodes 0x00-0x10 on CV1835 / Amlogic S19j Pro) — do NOT use
//! one driver for the other board.
//!
//! ## Status — wire frame format LIVE-CONFIRMED (2026-05-12 ftrace on `a lab unit`)
//!
//! A kernel `ftrace` capture on `a lab unit` (events `i2c:i2c_write/read/reply`,
//! `smbus:*`) caught luxminer's actual `/dev/i2c-1 @ 0x10` traffic — see
//!  §"R7-1".
//! The frame layout + the additive checksum + the mandatory write→read delay
//! below are reproduced from that trace. September8 source replay also closes
//! the exact HW0x76 voltage conversion, opcode03 read and opcode83 set frame;
//! see `evidence/r09/bb-apw-voltage-source-v1.json` in the beta campaign.
//! The held complete routines were executed269 times with emulated transaction
//! boundaries. Earlier assertions that APW control was only a Loki path, or
//! that a dsPIC voltage command could replace the PSU contract, were not
//! established by this warm trace. The exact BB runtime now joins a retained
//! GPIO65 controller owner to the fixed DAC0 initializer; software command
//! and readback success are not a measured physical rail result.
//!
//! ## Wire protocol (LIVE-CONFIRMED — luxos-wire-capture.md §R7-1)
//!
//! **Request (host → PSU), single I²C write of `4 + params.len() + 3` bytes:**
//!
//! ```text
//!   [0x11, 0x55, 0xAA, LEN, OPCODE, <params…>, CK_lo, CK_hi]
//!   LEN   = 4 + params.len()                       (LEN through both checksum bytes)
//!   CK16  = (LEN + OPCODE + Σ params) & 0xFFFF     (additive16-bit sum, little-endian)
//! ```
//!
//! `0x11` = host-command transport marker (NOT in the reply); `0x55 0xAA` =
//! magic preamble. The final byte is the checksum high byte. The original
//! calibration reply ends in `4b20`; earlier interpretation as a fixed zero
//! discarded that exact captured carry and left the calibration parser lenient.
//!
//! **Response (PSU → host), a SEPARATE I²C read issued ≥ ~400 ms after the
//! write** (≥ ~1 s for the calibration-block read — the APW is slow). luxminer
//! reads a *fixed* size and the APW pads anything past its actual reply with
//! `0xF5`. Locate the declared complete frame before checking remaining padding:
//!
//! ```text
//!   [0x55, 0xAA, RLEN, OPCODE_echo, <data…>, CK_lo, CK_hi]   (then 0xF5 padding)
//!   RLEN  = 4 + data.len()
//!   CK16 = (RLEN + OPCODE_echo + Σ data) & 0xFFFF
//! ```
//!
//! Worked examples from the `a lab unit` trace:
//! - `[0x11,0x55,0xAA,0x04,0x02,0x06,0x00]` (read HW type) → `[0x55,0xAA,0x06,0x02,0x76,0x00,0x7E,0x00]` → HW = `0x76`, `0x06+0x02+0x76+0x00 = 0x7E` ✓
//! - `[0x11,0x55,0xAA,0x04,0x01,0x05,0x00]` (read FW)      → `[0x55,0xAA,0x06,0x01,0x17,0x00,0x1E,0x00]` → FW = `0x17`, `0x06+0x01+0x17+0x00 = 0x1E` ✓
//! - `[0x11,0x55,0xAA,0x04,0x03,0x07,0x00]` (read 0x03)    → `[0x55,0xAA,0x06,0x03,0x23,0x00,0x2C,0x00,0xF5,0xF5]` → value = `0x0023`, `0x06+0x03+0x23+0x00 = 0x2C` ✓
//! - `[0x11,0x55,0xAA,0x06,0x06,0x40,0x20,0x6C,0x00]` (read cal block, params `[0x40,0x20]`) → 40-byte reply `[0x55,0xAA,0x25,0x06,0x40,0xFF×32,0x4B,0x20,0xF5]` (mostly uninitialised on this unit) — `0x06+0x06+0x40+0x20 = 0x6C` ✓
//! - `[0x11,0x55,0xAA,0x06,0x81,0x00,0x00,0x87,0x00]` — watchdog-disable (`0x06+0x81 = 0x87` ✓).
//! - `[0x11,0x55,0xAA,0x06,0x83,0x00,0x00,0x89,0x00]` — set-voltage DAC0, which decodes to15.12V for HW0x76; not an off command.
//!
//! ## PSU init sequence (per analysis/C §7 luxminer strings)
//!
//! 1. read HW type (expect `0x76` = APW121215f) — [`ApwUartTunnel::read_hw_type`]
//! 2. read FW (expect `0x17`) — [`ApwUartTunnel::read_fw_version`]
//! 3. send calibration message (`Sending read calibration message:`) — opcode
//!    `0x06`, params `[0x40,0x20]` (Ghidra-confirmed from `luxminer`
//!    `FUN_0061c4a8`, 2026-05-31)
//! 4. send watchdog-disable message (`Sending PSU watchdog disable message:`) —
//!    opcode `0x81`, params `[0x00,0x00]` (Ghidra-confirmed from `luxminer`
//!    `FUN_0061cd48`, 2026-05-31)
//! 5. Exact original AM33XX semantics select GPIO65, raw ON1/OFF0; the fixed
//!    opcode83 DAC0 initializer follows ON. The daemon requires the actual
//!    GPIO-bank and i2c-gpio adapter binding before retaining that owner.
//!    GPIO59's historical role label is not supply-cutoff evidence.
//!
//! ## Host-testable transport
//!
//! All actual I/O goes through the [`ApwUartTunnelBus`] trait so this module
//! is testable with a mock — same pattern as `dcentrald_asic::bm1362::uart_transport`.
//! The runtime impl ([`I2cServiceApwBus`]) routes through
//! [`crate::i2c::I2cServiceHandle`] per the SINGLE-I2C-OWNER architecture; on
//! `a lab unit` the PSU lives on the bit-banged i2c-gpio bus (bus 1).

use crate::HalError;
use crate::Result;
use std::time::Duration;

#[path = "psu_apw_uart_tunnel_voltage.rs"]
mod voltage;
pub use voltage::Apw76VoltageCode;

// ===========================================================================
//  Constants — LIVE-CONFIRMED per luxos-wire-capture.md §R7-1
// ===========================================================================

/// I²C slave address of the APW121215f on `a lab unit` (bus 1, bit-banged i2c-gpio).
pub const APW_UART_TUNNEL_I2C_ADDR: u8 = 0x10;

/// Host-command transport marker — the leading `0x11` of every request frame.
pub const TUNNEL_REG_BYTE: u8 = 0x11;

/// Tunnel magic preamble (`0x55 0xAA`), same for request and response.
pub const TUNNEL_PREAMBLE: [u8; 2] = [0x55, 0xAA];

/// The retained calibration reply ends in checksum0x204b. The final byte is
/// therefore the high checksum byte, not a fixed zero trailer.
pub const TUNNEL_CHECKSUM_BYTES: usize = 2;

/// Largest parameter block representable by the tunnel's 8-bit LEN field.
/// LEN counts itself, OPCODE, and both checksum bytes.
pub const TUNNEL_MAX_PARAMS_LEN: usize = u8::MAX as usize - 4;

/// Pad byte the APW returns for any read bytes past its actual reply length.
pub const TUNNEL_PAD_BYTE: u8 = 0xF5;

/// Minimum delay between the request write and the reply read, in ms. luxminer
/// waits ~250 ms for the I²C `result` then another ~300-500 ms before reading;
/// reading too soon yields all-`0xF5` (the original BEST-GUESS bug). The
/// calibration-block read needs ~1 s — see [`APW_CAL_READ_DELAY_MS`].
pub const APW_READ_DELAY_MS: u64 = 500;

/// Delay before reading back the calibration block (opcode [`OP_READ_CAL_BLOCK`]) —
/// the APW takes ~1.7 s end-to-end for that one in the trace.
pub const APW_CAL_READ_DELAY_MS: u64 = 1200;

/// Expected HW type byte for the APW121215f (live `a lab unit` trace + analysis/C §3).
pub const EXPECTED_HW_TYPE: u8 = 0x76;

/// Expected FW byte for the APW121215f on `a lab unit` (live `a lab unit` trace + analysis/C §3).
pub const EXPECTED_FW_VERSION: u8 = 0x17;

/// Read FW version (`0x01`). Reply value = FW byte (low byte of a u16).
pub const OP_READ_FW_VERSION: u8 = 0x01;

/// Read HW type (`0x02`). Reply value = HW byte (low byte of a u16).
pub const OP_READ_HW_TYPE: u8 = 0x02;

/// Read the PSU voltage DAC word, named status in the original warm trace.
/// Exact HW0x76 code0x0023 decodes to14.67V in the held original routine.
pub const OP_READ_STATUS_0X03: u8 = 0x03;

/// Read calibration block (`0x06`, params `[0x40, 0x20]` = addr/len on the
/// `a lab unit` trace; 34-byte data reply, mostly `0xFF` on that uninitialised unit).
/// Corresponds to luxminer's `Sending read calibration message:`.
pub const OP_READ_CAL_BLOCK: u8 = 0x06;

/// Calibration-block read params seen on `a lab unit` (`[0x40, 0x20]`).
pub const CAL_BLOCK_PARAMS: [u8; 2] = [0x40, 0x20];

// Held BB LuxOS ELF0x5aa3b0/0x5a6f08 implements opcode83 set and opcode03
// read. For HW0x76, N=trunc(1190.93534 - volts*78.742588); inverse readback
// truncates to centivolts. Apw76VoltageCode contains only that numerical
// domain. It is not operating-limit or electrical-owner authority.

/// Watchdog-control opcode (`0x81`). With params `[0x00,0x00]`, luxminer uses
/// it as watchdog-disable on APW121215f (`FUN_0061cd48`).
pub const OP_WATCHDOG_CONTROL: u8 = 0x81;

/// Watchdog-disable params seen in luxminer and the `a lab unit` ftrace.
pub const WATCHDOG_DISABLE_PARAMS: [u8; 2] = [0x00, 0x00];

// ===========================================================================
//  Pure helpers — host-safe, no I/O
// ===========================================================================

/// Additive 16-bit checksum over `[LEN, OPCODE, params…]`. The retained
/// calibration reply has a nonzero high byte; stock DAC frames also carry it.
pub fn checksum(len: u8, opcode: u8, params: &[u8]) -> u16 {
    params
        .iter()
        .copied()
        .fold(u16::from(len) + u16::from(opcode), |sum, byte| {
            sum.wrapping_add(u16::from(byte))
        })
}

/// Build a request frame for `(opcode, params)`:
/// `[0x11, 0x55, 0xAA, LEN, OPCODE, params…, CK_lo, CK_hi]` where
/// `LEN = 4 + params.len()`. Host-safe.
///
/// Returns an error before allocating when `params` cannot be represented by
/// the wire format's 8-bit LEN field.
pub fn build_request(opcode: u8, params: &[u8]) -> Result<Vec<u8>> {
    if params.len() > TUNNEL_MAX_PARAMS_LEN {
        return Err(HalError::PsuProtocolOwned(format!(
            "APW UART-tunnel request parameters are {} bytes; maximum is {}",
            params.len(),
            TUNNEL_MAX_PARAMS_LEN
        )));
    }
    let len = u8::try_from(params.len() + 4).expect("TUNNEL_MAX_PARAMS_LEN proves LEN fits in u8");
    let mut f = Vec::with_capacity(3 + len as usize);
    f.push(TUNNEL_REG_BYTE);
    f.extend_from_slice(&TUNNEL_PREAMBLE);
    f.push(len);
    f.push(opcode);
    f.extend_from_slice(params);
    f.extend_from_slice(&checksum(len, opcode, params).to_le_bytes());
    Ok(f)
}

/// Convenience: a no-param request frame.
/// Returns the same fallible frame-builder result as [`build_request`].
pub fn build_request_noparams(opcode: u8) -> Result<Vec<u8>> {
    build_request(opcode, &[])
}

/// Parsed APW121215f tunnel response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApwTunnelResponse {
    /// Echoed opcode (response byte index 3).
    pub opcode_echo: u8,
    /// Data bytes (between the echoed opcode and the checksum).
    pub data: Vec<u8>,
}

impl ApwTunnelResponse {
    fn identity_byte(&self) -> Result<u8> {
        match self.data.as_slice() {
            [value, 0] => Ok(*value),
            _ => Err(HalError::PsuProtocolOwned(
                "APW UART-tunnel identity requires exactly one little-endian byte value".into(),
            )),
        }
    }
    /// The data interpreted as a little-endian u16 (the common "value" reply
    /// shape — `[lo, hi]`). `0` if `data` is empty; the low byte alone if
    /// `data.len() == 1`.
    pub fn value_le_u16(&self) -> u16 {
        match self.data.len() {
            0 => 0,
            1 => self.data[0] as u16,
            _ => u16::from_le_bytes([self.data[0], self.data[1]]),
        }
    }
}

/// Parse the declared complete reply, including both checksum bytes, followed
/// only by captured0xf5 padding. Padding is checked after the declared boundary
/// so a checksum byte equal to0xf5 cannot be stripped from a valid frame.
pub fn parse_response(buf: &[u8]) -> Result<ApwTunnelResponse> {
    if buf.len() < 6 {
        return Err(HalError::PsuProtocolOwned(format!(
            "APW UART-tunnel response: only {} bytes (need ≥ 6)",
            buf.len()
        )));
    }
    if buf[0] != TUNNEL_PREAMBLE[0] || buf[1] != TUNNEL_PREAMBLE[1] {
        return Err(HalError::PsuProtocolOwned(format!(
            "APW UART-tunnel response: bad preamble {:02X?} (want {:02X?})",
            &buf[0..2],
            TUNNEL_PREAMBLE
        )));
    }
    let rlen = buf[2];
    // RLEN includes its own byte, opcode, data and both checksum bytes.
    let frame_len = usize::from(rlen) + 2;
    if rlen < 4 || frame_len > buf.len() {
        return Err(HalError::PsuProtocolOwned(format!(
            "APW UART-tunnel response: RLEN=0x{:02X} doesn't fit in {} bytes",
            rlen,
            buf.len()
        )));
    }
    if buf[frame_len..].iter().any(|byte| *byte != TUNNEL_PAD_BYTE) {
        return Err(HalError::PsuProtocolOwned(
            "APW UART-tunnel response has non-padding bytes after declared frame".into(),
        ));
    }
    let opcode_echo = buf[3];
    let data_len = (rlen as usize) - 4;
    let data = buf[4..4 + data_len].to_vec();
    let want_cksum = checksum(rlen, opcode_echo, &data);
    let got_cksum = u16::from_le_bytes([buf[4 + data_len], buf[5 + data_len]]);
    if got_cksum != want_cksum {
        return Err(HalError::PsuProtocolOwned(format!(
            "APW UART-tunnel response: bad checksum 0x{:04X} (want 0x{:04X}) for \
             opcode_echo=0x{:02X} data={:02X?}",
            got_cksum, want_cksum, opcode_echo, data
        )));
    }
    Ok(ApwTunnelResponse { opcode_echo, data })
}

/// Compatibility entry point; all replies now require the complete checksum.
/// The calibration block's formerly unexplained byte is its high checksum.
pub fn parse_response_lenient(buf: &[u8]) -> Result<ApwTunnelResponse> {
    parse_response(buf)
}

// ===========================================================================
//  Bus trait — host-testable transport
// ===========================================================================

/// Abstract I²C transport for the APW UART-tunnel PSU.
///
/// The runtime impl ([`I2cServiceApwBus`]) routes through
/// [`crate::i2c::I2cServiceHandle`]. Tests use a mock that records the frames
/// written and replies with canned responses.
///
/// **Important: the APW requires a write, a caller-controlled delay, and then
/// a separate read** — it needs ≥ ~400 ms to produce a reply (see
/// [`APW_READ_DELAY_MS`]). Service-backed implementations retain worker
/// ownership across that sequence, but must not collapse it into a
/// repeated-START WriteRead (read-too-soon → all `0xF5`).
pub trait ApwUartTunnelBus {
    /// A production voltage writer must bind the exact physical controller
    /// and retain terminal cutoff ownership. Read-only and recovery transports
    /// do not acquire this capability merely by implementing bus exchange.
    fn authorize_voltage_control(&mut self) -> Result<()> {
        Err(HalError::PsuUnsupported(
            "APW voltage control requires an admitted retained PSU controller".into(),
        ))
    }
    /// Write `frame` to the PSU at `addr`.
    fn write_frame(&mut self, addr: u8, frame: &[u8]) -> Result<()>;
    /// Read `read_len` bytes from the PSU at `addr`.
    fn read_reply(&mut self, addr: u8, read_len: usize) -> Result<Vec<u8>>;
    /// Execute one correlated request/delay/reply exchange. The default keeps
    /// mocks and non-service transports simple; the service-backed runtime
    /// overrides this to retain single-worker ownership across the delay.
    fn exchange(
        &mut self,
        addr: u8,
        frame: &[u8],
        read_len: usize,
        delay: Duration,
    ) -> Result<Vec<u8>> {
        self.write_frame(addr, frame)?;
        self.delay(delay);
        self.read_reply(addr, read_len)
    }
    /// Sleep for `dur` (overridable in tests so they don't actually wait).
    fn delay(&mut self, dur: Duration) {
        std::thread::sleep(dur);
    }
}

#[cfg(feature = "recovery-tool")]
mod i2c_service_bus {
    //! Runtime [`super::ApwUartTunnelBus`] impl over a real I²C service handle.
    //! Gated by the `recovery-tool` feature — not yet exercised on production
    //! hardware (no live `a lab unit` DCENT_OS install).

    use super::{ApwUartTunnelBus, Result};
    use crate::i2c::{I2cOperationIntent, I2cServiceHandle, I2cTransactionStep};

    /// [`ApwUartTunnelBus`] backed by the shared I²C service.
    pub struct I2cServiceApwBus {
        handle: I2cServiceHandle,
    }

    impl I2cServiceApwBus {
        pub fn new(handle: I2cServiceHandle) -> Self {
            Self { handle }
        }
    }

    fn validated_request(frame: &[u8]) -> Option<(u8, &[u8])> {
        if frame.len() < 7
            || frame[0] != super::TUNNEL_REG_BYTE
            || frame[1..3] != super::TUNNEL_PREAMBLE
            || frame.len() != usize::from(frame[3]) + 3
        {
            return None;
        }
        let opcode = frame[4];
        let params = &frame[5..frame.len() - 2];
        (u16::from_le_bytes([frame[frame.len() - 2], frame[frame.len() - 1]])
            == super::checksum(frame[3], opcode, params))
        .then_some((opcode, params))
    }

    fn frame_intent(frame: &[u8]) -> I2cOperationIntent {
        match validated_request(frame) {
            // Watchdog disable is standalone neutral control: it removes a
            // cutoff without itself moving the rail safe.
            Some((opcode, params))
                if opcode == super::OP_WATCHDOG_CONTROL
                    && params == super::WATCHDOG_DISABLE_PARAMS =>
            {
                I2cOperationIntent::NeutralControl
            }
            // The gated voltage opcode can raise the rail if this recovery
            // transport is ever enabled for it.
            Some((0x83, _)) => I2cOperationIntent::Energize,
            Some((opcode, params))
                if params.is_empty()
                    && matches!(
                        opcode,
                        super::OP_READ_HW_TYPE
                            | super::OP_READ_FW_VERSION
                            | super::OP_READ_STATUS_0X03
                    ) =>
            {
                I2cOperationIntent::ReadOnly
            }
            Some((opcode, params))
                if opcode == super::OP_READ_CAL_BLOCK && params == super::CAL_BLOCK_PARAMS =>
            {
                I2cOperationIntent::ReadOnly
            }
            // The opcode catalog is intentionally incomplete. Unknown
            // commands must never inherit read-only terminal privilege.
            _ => I2cOperationIntent::UnclassifiedMutation,
        }
    }

    impl ApwUartTunnelBus for I2cServiceApwBus {
        fn write_frame(&mut self, addr: u8, frame: &[u8]) -> Result<()> {
            let intent = frame_intent(frame);
            self.handle.transaction_with_intent(
                intent,
                addr,
                vec![I2cTransactionStep::Write(frame.to_vec())],
            )?;
            Ok(())
        }

        fn read_reply(&mut self, addr: u8, read_len: usize) -> Result<Vec<u8>> {
            let mut reads = self.handle.transaction_with_intent(
                I2cOperationIntent::ReadOnly,
                addr,
                vec![I2cTransactionStep::Read(read_len)],
            )?;
            reads.pop().ok_or_else(|| {
                crate::HalError::PsuProtocolOwned(
                    "APW UART-tunnel: read transaction returned no result".into(),
                )
            })
        }

        fn exchange(
            &mut self,
            addr: u8,
            frame: &[u8],
            read_len: usize,
            delay: std::time::Duration,
        ) -> Result<Vec<u8>> {
            let intent = frame_intent(frame);
            let delay_ms = u64::try_from(delay.as_nanos().div_ceil(1_000_000)).unwrap_or(u64::MAX);
            let mut reads = self.handle.transaction_with_intent(
                intent,
                addr,
                vec![
                    I2cTransactionStep::Write(frame.to_vec()),
                    I2cTransactionStep::SleepMs(delay_ms),
                    I2cTransactionStep::Read(read_len),
                ],
            )?;
            reads.pop().ok_or_else(|| {
                crate::HalError::PsuProtocolOwned(
                    "APW UART-tunnel: exchange returned no read result".into(),
                )
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn classifies_only_byte_exact_known_requests_as_privileged() {
            assert_eq!(
                frame_intent(
                    &super::super::build_request(super::super::OP_READ_HW_TYPE, &[]).unwrap()
                ),
                I2cOperationIntent::ReadOnly
            );
            assert_eq!(
                frame_intent(
                    &super::super::build_request(
                        super::super::OP_READ_CAL_BLOCK,
                        &super::super::CAL_BLOCK_PARAMS
                    )
                    .unwrap()
                ),
                I2cOperationIntent::ReadOnly
            );
            assert_eq!(
                frame_intent(
                    &super::super::build_request(
                        super::super::OP_WATCHDOG_CONTROL,
                        &super::super::WATCHDOG_DISABLE_PARAMS
                    )
                    .unwrap()
                ),
                I2cOperationIntent::NeutralControl
            );
            assert_eq!(
                frame_intent(&super::super::build_request(0x83, &[0x2A, 0x00]).unwrap()),
                I2cOperationIntent::Energize
            );
        }

        #[test]
        fn malformed_or_semantically_unknown_requests_are_unclassified_mutations() {
            let valid_read =
                super::super::build_request(super::super::OP_READ_HW_TYPE, &[]).unwrap();

            let mut bad_checksum = valid_read.clone();
            bad_checksum[5] ^= 0x01;
            assert_eq!(
                frame_intent(&bad_checksum),
                I2cOperationIntent::UnclassifiedMutation
            );

            let mut bad_length = valid_read.clone();
            bad_length[3] = bad_length[3].saturating_add(1);
            assert_eq!(
                frame_intent(&bad_length),
                I2cOperationIntent::UnclassifiedMutation
            );

            assert_eq!(
                frame_intent(&super::super::build_request(0x7F, &[]).unwrap()),
                I2cOperationIntent::UnclassifiedMutation
            );
            assert_eq!(
                frame_intent(
                    &super::super::build_request(super::super::OP_READ_HW_TYPE, &[0x00]).unwrap()
                ),
                I2cOperationIntent::UnclassifiedMutation
            );
            assert_eq!(
                frame_intent(
                    &super::super::build_request(super::super::OP_WATCHDOG_CONTROL, &[0x01, 0x00])
                        .unwrap()
                ),
                I2cOperationIntent::UnclassifiedMutation
            );
        }
    }
}

#[cfg(feature = "recovery-tool")]
pub use i2c_service_bus::I2cServiceApwBus;

// ===========================================================================
//  ApwUartTunnel — the runtime controller
// ===========================================================================

/// APW121215f UART-tunnel PSU controller for the AM335x BB S19j Pro.
///
/// Generic over [`ApwUartTunnelBus`] so it is host-testable. The runtime path
/// constructs it with an [`I2cServiceApwBus`] (feature `recovery-tool`) bound
/// to bus 1, address [`APW_UART_TUNNEL_I2C_ADDR`].
pub struct ApwUartTunnel<B: ApwUartTunnelBus> {
    bus: B,
    address: u8,
    hw_type: u8,
    fw_version: u8,
}

impl<B: ApwUartTunnelBus> ApwUartTunnel<B> {
    /// Construct at the default address ([`APW_UART_TUNNEL_I2C_ADDR`]).
    pub fn new(bus: B) -> Self {
        Self::new_at(bus, APW_UART_TUNNEL_I2C_ADDR)
    }

    /// Construct at a specific slave address (rare).
    pub fn new_at(bus: B, address: u8) -> Self {
        Self {
            bus,
            address,
            hw_type: 0,
            fw_version: 0,
        }
    }

    /// Cached I²C slave address.
    pub fn address(&self) -> u8 {
        self.address
    }

    /// Last observed HW type byte (`0` until [`Self::read_hw_type`]).
    pub fn hw_type(&self) -> u8 {
        self.hw_type
    }

    /// Last observed FW version byte (`0` until [`Self::read_fw_version`]).
    pub fn fw_version(&self) -> u8 {
        self.fw_version
    }

    /// Low-level: write a `(opcode, params)` frame, wait `delay`, read
    /// `read_len` bytes, strip `0xF5` padding, parse + checksum-verify.
    fn command(
        &mut self,
        opcode: u8,
        params: &[u8],
        read_len: usize,
        delay: Duration,
    ) -> Result<ApwTunnelResponse> {
        let frame = build_request(opcode, params)?;
        let raw = self.bus.exchange(self.address, &frame, read_len, delay)?;
        let resp = parse_response(&raw)?;
        if resp.opcode_echo != opcode {
            return Err(HalError::PsuProtocolOwned(format!(
                "APW UART-tunnel: opcode echo mismatch (sent 0x{:02X}, got 0x{:02X})",
                opcode, resp.opcode_echo
            )));
        }
        Ok(resp)
    }

    /// Read the PSU HW type byte. Expect [`EXPECTED_HW_TYPE`] (`0x76`).
    pub fn read_hw_type(&mut self) -> Result<u8> {
        let resp = self.command(
            OP_READ_HW_TYPE,
            &[],
            8,
            Duration::from_millis(APW_READ_DELAY_MS),
        )?;
        let v = resp.identity_byte()?;
        self.hw_type = v;
        tracing::info!(
            addr = format_args!("0x{:02X}", self.address),
            hw = format_args!("0x{:02X}", v),
            "APW UART-tunnel: HW type read"
        );
        Ok(v)
    }

    /// Read the PSU FW version byte. Expect [`EXPECTED_FW_VERSION`] (`0x17`).
    pub fn read_fw_version(&mut self) -> Result<u8> {
        let resp = self.command(
            OP_READ_FW_VERSION,
            &[],
            8,
            Duration::from_millis(APW_READ_DELAY_MS),
        )?;
        let v = resp.identity_byte()?;
        self.fw_version = v;
        tracing::info!(
            addr = format_args!("0x{:02X}", self.address),
            fw = format_args!("0x{:02X}", v),
            "APW UART-tunnel: FW version read"
        );
        Ok(v)
    }

    /// Read opcode03 as a raw little-endian word without voltage conversion.
    pub fn read_status_0x03(&mut self) -> Result<u16> {
        let resp = self.command(
            OP_READ_STATUS_0X03,
            &[],
            10,
            Duration::from_millis(APW_READ_DELAY_MS),
        )?;
        match resp.data.as_slice() {
            [low, high] => Ok(u16::from_le_bytes([*low, *high])),
            _ => Err(HalError::PsuProtocolOwned(
                "APW UART-tunnel opcode03 requires exactly two data bytes".into(),
            )),
        }
    }

    /// Observe the exact held hardware/firmware signature on this bus owner.
    /// Failed or mismatched replies invalidate earlier cached observations.
    pub fn probe_identity(&mut self) -> Result<()> {
        self.hw_type = 0;
        self.fw_version = 0;
        let result = self.probe_exact_identity();
        if result.is_err() {
            self.hw_type = 0;
            self.fw_version = 0;
        }
        result
    }

    fn probe_exact_identity(&mut self) -> Result<()> {
        if self.address != APW_UART_TUNNEL_I2C_ADDR {
            return Err(HalError::PsuUnsupported(
                "APW hardware0x76 observation requires exact address0x10".into(),
            ));
        }
        let hw = self.read_hw_type()?;
        if hw != EXPECTED_HW_TYPE {
            return Err(HalError::PsuUnsupported(format!(
                "APW UART-tunnel: HW type 0x{:02X}, expected 0x{:02X} (APW121215f)",
                hw, EXPECTED_HW_TYPE
            )));
        }
        let fw = self.read_fw_version()?;
        if fw != EXPECTED_FW_VERSION {
            return Err(HalError::PsuUnsupported(format!(
                "APW UART-tunnel: FW0x{fw:02X} does not match held FW0x{EXPECTED_FW_VERSION:02X}"
            )));
        }
        Ok(())
    }

    /// Read the calibration block (opcode [`OP_READ_CAL_BLOCK`], params
    /// [`CAL_BLOCK_PARAMS`]). Checks the complete16-bit checksum, including the
    /// captured0x20 high byte. Returns the raw data bytes — mostly `0xFF`
    /// (uninitialised) on the `a lab unit` unit; on a calibrated PSU this is the
    /// voltage/current trim table. An unavailable or malformed reply is an
    /// error; an observed, correctly framed block of unset bytes is valid data.
    pub fn read_calibration_block(&mut self) -> Result<Vec<u8>> {
        let frame = build_request(OP_READ_CAL_BLOCK, &CAL_BLOCK_PARAMS)?;
        let raw = self.bus.exchange(
            self.address,
            &frame,
            40,
            Duration::from_millis(APW_CAL_READ_DELAY_MS),
        )?;
        let resp = parse_response(&raw)?;
        if resp.opcode_echo != OP_READ_CAL_BLOCK
            || resp.data.len() != 33
            || resp.data.first() != Some(&CAL_BLOCK_PARAMS[0])
        {
            return Err(HalError::PsuProtocolOwned(format!(
                "APW UART-tunnel cal block: wrong address/length or opcode echo0x{:02X} (want0x{:02X})",
                resp.opcode_echo, OP_READ_CAL_BLOCK
            )));
        }
        Ok(resp.data)
    }

    /// Send the calibration message (cold-boot step 3 (c)).
    ///
    /// luxminer's `Sending read calibration message:` is the
    /// [`OP_READ_CAL_BLOCK`] read (held ELF address `0x60c4a8`, historically
    /// labelled `FUN_0061c4a8` with a load bias). Propagate transport and frame
    /// errors so a cold controller cannot release ASIC reset after a failed
    /// exchange. The held block's unset payload does not bypass validation.
    pub fn send_calibration_message(&mut self) -> Result<()> {
        let data = self.read_calibration_block()?;
        tracing::info!(
            addr = format_args!("0x{:02X}", self.address),
            bytes = data.len(),
            payload_unset = data[1..].iter().all(|&b| b == 0xFF),
            "APW UART-tunnel: calibration block validated"
        );
        Ok(())
    }

    /// Send the watchdog-disable message (cold-boot step 3 (d)).
    ///
    /// Ghidra-confirmed from luxminer `FUN_0061cd48`: opcode
    /// [`OP_WATCHDOG_CONTROL`] with [`WATCHDOG_DISABLE_PARAMS`]. A caller must
    /// propagate failures before handing the rail to the mining lifecycle.
    pub fn send_watchdog_disable_message(&mut self) -> Result<()> {
        let response = self.command(
            OP_WATCHDOG_CONTROL,
            &WATCHDOG_DISABLE_PARAMS,
            8,
            Duration::from_millis(APW_READ_DELAY_MS),
        )?;
        if response.data != WATCHDOG_DISABLE_PARAMS {
            return Err(HalError::PsuProtocolOwned(
                "APW UART-tunnel: watchdog-disable payload was not acknowledged".into(),
            ));
        }
        tracing::info!(
            addr = format_args!("0x{:02X}", self.address),
            opcode = format_args!("0x{:02X}", OP_WATCHDOG_CONTROL),
            "APW UART-tunnel: watchdog-disable acknowledged"
        );
        Ok(())
    }

    /// Set the exact HW76 DAC through opcode83, requiring its complete echo
    /// and a separate opcode03 readback. ELF0x593c48 selects the HW76 bounds
    /// 11.88..15.12V; these are PSU limits, not a hashboard operating table.
    /// The normal BB caller keeps the source-selected fixed15.12V supply
    /// while its independent dsPIC owner ramps the hashboards.
    pub fn set_voltage_mv(&mut self, mv: u16) -> Result<()> {
        if !(11_880..=15_120).contains(&mv) {
            return Err(HalError::PsuUnsupported(format!(
                "APW hardware0x76 requested{mv}mV is outside source-selected11880..15120mV"
            )));
        }
        let code = Apw76VoltageCode::from_millivolts(mv)?;
        self.bus.authorize_voltage_control()?;
        self.probe_identity()?;
        let result = (|| {
            // Original0x604720 startup chooses DAC0, not an OFF operation.
            // Quantized readback is compared as the code, not a voltage epsilon.
            let response = self.command(
                0x83,
                &code.payload(),
                8,
                Duration::from_millis(APW_READ_DELAY_MS),
            )?;
            if Apw76VoltageCode::from_reply(&response.data)? != code {
                return Err(HalError::PsuProtocolOwned(
                    "APW opcode83 DAC echo mismatch".into(),
                ));
            }
            self.require_voltage_code(code)
        })();
        if result.is_err() {
            self.hw_type = 0;
            self.fw_version = 0;
        }
        result
    }

    fn require_voltage_code(&mut self, expected: Apw76VoltageCode) -> Result<()> {
        let response = self.command(
            OP_READ_STATUS_0X03,
            &[],
            10,
            Duration::from_millis(APW_READ_DELAY_MS),
        )?;
        if Apw76VoltageCode::from_reply(&response.data)? != expected {
            return Err(HalError::PsuProtocolOwned(
                "APW opcode03 DAC readback mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Verify the unchanged upstream supply after the separate dsPIC ramp.
    /// This never writes a new voltage and never claims a measured board rail.
    pub fn require_fixed_supply(&mut self) -> Result<()> {
        self.probe_identity()?;
        let result = self.require_voltage_code(Apw76VoltageCode::from_reply(&[0, 0])?);
        if result.is_err() {
            self.hw_type = 0;
            self.fw_version = 0;
        }
        result
    }

    /// Read the PSU-reported DAC setting through original opcode03 and the
    /// exact HW0x76 conversion. This is not a hashboard rail measurement.
    /// Each observation obtains fresh HW/FW replies before decoding; no
    /// cached identity or previous voltage is substituted after an error.
    pub fn read_voltage_mv(&mut self) -> Result<u16> {
        self.probe_identity()?;
        let result = self
            .command(
                OP_READ_STATUS_0X03,
                &[],
                10,
                Duration::from_millis(APW_READ_DELAY_MS),
            )
            .and_then(|response| {
                Apw76VoltageCode::from_reply(&response.data)
                    .map(Apw76VoltageCode::reported_millivolts)
            });
        if result.is_err() {
            self.hw_type = 0;
            self.fw_version = 0;
        }
        result
    }
}

// ===========================================================================
//  Tests — all host-safe (no real I/O; mock bus skips the delays)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock bus: records the frames written, replies with canned responses,
    /// and skips the inter-message delay so tests don't actually sleep.
    struct MockBus {
        replies: std::collections::VecDeque<Result<Vec<u8>>>,
        writes: Vec<(u8, Vec<u8>)>,
        reads: Vec<(u8, usize)>,
        delays: Vec<Duration>,
        voltage_authorized: bool,
    }

    impl MockBus {
        fn new(replies: Vec<Result<Vec<u8>>>) -> Self {
            Self {
                replies: replies.into_iter().collect(),
                writes: Vec::new(),
                reads: Vec::new(),
                delays: Vec::new(),
                voltage_authorized: false,
            }
        }
    }

    impl ApwUartTunnelBus for MockBus {
        fn authorize_voltage_control(&mut self) -> Result<()> {
            if self.voltage_authorized {
                Ok(())
            } else {
                Err(HalError::PsuUnsupported(
                    "fixture has no voltage owner".into(),
                ))
            }
        }
        fn write_frame(&mut self, addr: u8, frame: &[u8]) -> Result<()> {
            self.writes.push((addr, frame.to_vec()));
            Ok(())
        }
        fn read_reply(&mut self, addr: u8, read_len: usize) -> Result<Vec<u8>> {
            self.reads.push((addr, read_len));
            self.replies.pop_front().unwrap_or(Ok(vec![0; read_len]))
        }
        fn delay(&mut self, dur: Duration) {
            self.delays.push(dur); // record, don't sleep
        }
    }

    /// Build a valid reply frame for `(opcode_echo, data)` and optionally pad
    /// it out to `pad_to` bytes with `0xF5` (mimics the APW's fixed-size read).
    fn reply_frame(opcode_echo: u8, data: &[u8], pad_to: usize) -> Vec<u8> {
        let rlen = (4 + data.len()) as u8;
        let mut f = vec![TUNNEL_PREAMBLE[0], TUNNEL_PREAMBLE[1], rlen, opcode_echo];
        f.extend_from_slice(data);
        f.extend_from_slice(&checksum(rlen, opcode_echo, data).to_le_bytes());
        while f.len() < pad_to {
            f.push(TUNNEL_PAD_BYTE);
        }
        f
    }

    #[test]
    fn constants_match_capture() {
        assert_eq!(APW_UART_TUNNEL_I2C_ADDR, 0x10);
        assert_eq!(TUNNEL_REG_BYTE, 0x11);
        assert_eq!(TUNNEL_PREAMBLE, [0x55, 0xAA]);
        assert_eq!(TUNNEL_CHECKSUM_BYTES, 2);
        assert_eq!(TUNNEL_PAD_BYTE, 0xF5);
        assert_eq!(EXPECTED_HW_TYPE, 0x76);
        assert_eq!(EXPECTED_FW_VERSION, 0x17);
        assert_eq!(OP_READ_FW_VERSION, 0x01);
        assert_eq!(OP_READ_HW_TYPE, 0x02);
        assert_eq!(OP_READ_CAL_BLOCK, 0x06);
        assert_eq!(CAL_BLOCK_PARAMS, [0x40, 0x20]);
        assert_eq!(OP_WATCHDOG_CONTROL, 0x81);
        assert_eq!(WATCHDOG_DISABLE_PARAMS, [0x00, 0x00]);
    }

    #[test]
    fn build_request_byte_exact_against_dot79_trace() {
        // luxminer's actual frames from luxos-wire-capture.md §R7-1:
        assert_eq!(
            build_request(0x02, &[]).unwrap(),
            vec![0x11, 0x55, 0xAA, 0x04, 0x02, 0x06, 0x00]
        );
        assert_eq!(
            build_request(0x01, &[]).unwrap(),
            vec![0x11, 0x55, 0xAA, 0x04, 0x01, 0x05, 0x00]
        );
        assert_eq!(
            build_request(0x03, &[]).unwrap(),
            vec![0x11, 0x55, 0xAA, 0x04, 0x03, 0x07, 0x00]
        );
        assert_eq!(
            build_request(0x06, &[0x40, 0x20]).unwrap(),
            vec![0x11, 0x55, 0xAA, 0x06, 0x06, 0x40, 0x20, 0x6C, 0x00]
        );
        assert_eq!(
            build_request(0x81, &[0x00, 0x00]).unwrap(),
            vec![0x11, 0x55, 0xAA, 0x06, 0x81, 0x00, 0x00, 0x87, 0x00]
        );
        assert_eq!(
            build_request(0x83, &[0x00, 0x00]).unwrap(),
            vec![0x11, 0x55, 0xAA, 0x06, 0x83, 0x00, 0x00, 0x89, 0x00]
        );
    }

    #[test]
    fn checksum_additive_matches_trace() {
        assert_eq!(checksum(0x04, 0x02, &[]), 0x06);
        assert_eq!(checksum(0x04, 0x01, &[]), 0x05);
        assert_eq!(checksum(0x04, 0x03, &[]), 0x07);
        assert_eq!(checksum(0x06, 0x06, &[0x40, 0x20]), 0x6C);
        assert_eq!(checksum(0x06, 0x81, &[0x00, 0x00]), 0x87);
        // Carry is part of the actual16-bit frame, not discarded.
        assert_eq!(checksum(0xFF, 0xFF, &[0x02]), 0x0200);

        // Public checksum input is not length-constrained. Its arithmetic is
        // explicitly modulo65536 even for inputs larger than any valid frame.
        let long = vec![0xFF; 1_024];
        let expected = long
            .iter()
            .copied()
            .fold(0x01FEu16, |sum, byte| sum.wrapping_add(u16::from(byte)));
        assert_eq!(checksum(0xFF, 0xFF, &long), expected);
    }

    #[test]
    fn build_request_enforces_u8_length_boundary() {
        let params = vec![0xFF; TUNNEL_MAX_PARAMS_LEN];
        let frame = build_request(0xFF, &params).unwrap();
        assert_eq!(frame[3], u8::MAX);
        assert_eq!(frame.len(), TUNNEL_MAX_PARAMS_LEN + 7);
        assert_eq!(
            &frame[frame.len() - 2..],
            &checksum(u8::MAX, 0xFF, &params).to_le_bytes()
        );

        let oversized = vec![0xFF; TUNNEL_MAX_PARAMS_LEN + 1];
        assert!(build_request(0xFF, &oversized).is_err());
    }

    #[test]
    fn parse_response_against_dot79_trace() {
        // [55 aa 06 02 76 00 7e 00] — HW = 0x76
        let r = parse_response(&[0x55, 0xAA, 0x06, 0x02, 0x76, 0x00, 0x7E, 0x00]).unwrap();
        assert_eq!(r.opcode_echo, 0x02);
        assert_eq!(r.data, vec![0x76, 0x00]);
        assert_eq!(r.value_le_u16(), 0x0076);
        // [55 aa 06 01 17 00 1e 00] — FW = 0x17
        let r = parse_response(&[0x55, 0xAA, 0x06, 0x01, 0x17, 0x00, 0x1E, 0x00]).unwrap();
        assert_eq!(r.value_le_u16(), 0x0017);
        // [55 aa 06 03 23 00 2c 00 f5 f5] — opcode 0x03, value 0x0023, padded
        let r =
            parse_response(&[0x55, 0xAA, 0x06, 0x03, 0x23, 0x00, 0x2C, 0x00, 0xF5, 0xF5]).unwrap();
        assert_eq!(r.opcode_echo, 0x03);
        assert_eq!(r.value_le_u16(), 0x0023);
        // echo-class set command [55 aa 06 81 00 00 87 00]
        let r = parse_response(&[0x55, 0xAA, 0x06, 0x81, 0x00, 0x00, 0x87, 0x00]).unwrap();
        assert_eq!(r.opcode_echo, 0x81);
        assert_eq!(r.data, vec![0x00, 0x00]);
    }

    #[test]
    fn parse_response_strips_pad_and_rejects_garbage() {
        // all-0xF5 (the "read too soon" bug symptom) → error, not a silent ""
        assert!(parse_response(&[0xF5; 8]).is_err());
        assert!(parse_response(&[]).is_err());
        // bad preamble
        assert!(parse_response(&[0xDE, 0xAD, 0x06, 0x02, 0x76, 0x00, 0x7E, 0x00]).is_err());
        // bad checksum
        assert!(parse_response(&[0x55, 0xAA, 0x06, 0x02, 0x76, 0x00, 0x99, 0x00]).is_err());
    }

    #[test]
    fn complete_checksum_handles_original_calibration_block() {
        // [55 aa 25 06 40 ff×32 4b 20 f5] — the .79 calibration block
        let mut raw = vec![0x55, 0xAA, 0x25, 0x06, 0x40];
        raw.extend(std::iter::repeat(0xFF).take(32));
        raw.extend_from_slice(&[0x4B, 0x20, 0xF5]);
        let r = parse_response(&raw).unwrap();
        assert_eq!(parse_response_lenient(&raw).unwrap(), r);
        assert_eq!(r.opcode_echo, 0x06);
        // RLEN=0x25=37 → data_len=33; data = [0x40, 0xFF×32]
        assert_eq!(r.data.len(), 33);
        assert_eq!(r.data[0], 0x40);
        assert!(r.data[1..].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn read_hw_type_round_trips_and_waits() {
        let mut psu =
            ApwUartTunnel::new(MockBus::new(vec![Ok(reply_frame(0x02, &[0x76, 0x00], 8))]));
        assert_eq!(psu.read_hw_type().unwrap(), 0x76);
        assert_eq!(psu.hw_type(), 0x76);
        // The command must have written the frame, delayed, then read.
        assert_eq!(psu.bus.writes.len(), 1);
        assert_eq!(psu.bus.writes[0].1, build_request(0x02, &[]).unwrap());
        assert_eq!(
            psu.bus.delays,
            vec![Duration::from_millis(APW_READ_DELAY_MS)]
        );
        assert_eq!(psu.bus.reads, vec![(0x10, 8)]);
    }

    #[test]
    fn read_fw_version_round_trips() {
        let mut psu =
            ApwUartTunnel::new(MockBus::new(vec![Ok(reply_frame(0x01, &[0x17, 0x00], 8))]));
        assert_eq!(psu.read_fw_version().unwrap(), 0x17);
        assert_eq!(psu.fw_version(), 0x17);
    }

    #[test]
    fn raw_status_requires_complete_word_even_with_valid_frame_checksum() {
        // Complete original PSU initializer controls accept these raw words;
        // they do not establish a physical rail or the HW76 voltage domain.
        for value in [0_u16, 1, 23, 35, 255, 65535] {
            let bus = MockBus::new(vec![Ok(reply_frame(
                OP_READ_STATUS_0X03,
                &value.to_le_bytes(),
                10,
            ))]);
            let mut psu = ApwUartTunnel::new(bus);
            assert_eq!(psu.read_status_0x03().unwrap(), value);
            assert_eq!(psu.bus.reads, vec![(APW_UART_TUNNEL_I2C_ADDR, 10)]);
        }
        for data in [&[][..], &[0][..], &[0, 0, 0][..], &[0, 0, 0, 0][..]] {
            let reply = reply_frame(OP_READ_STATUS_0X03, data, 10);
            assert_eq!(parse_response(&reply).unwrap().data, data);
            let bus = MockBus::new(vec![
                Ok(reply_frame(OP_READ_STATUS_0X03, &[35, 0], 10)),
                Ok(reply),
                Ok(reply_frame(OP_READ_STATUS_0X03, &[23, 0], 10)),
            ]);
            let mut psu = ApwUartTunnel::new(bus);
            assert_eq!(psu.read_status_0x03().unwrap(), 35);
            let error = psu.read_status_0x03().unwrap_err().to_string();
            assert!(error.contains("opcode03 requires exactly two data bytes"));
            assert_eq!(psu.read_status_0x03().unwrap(), 23);
            assert_eq!(psu.bus.reads, vec![(APW_UART_TUNNEL_I2C_ADDR, 10); 3]);
            assert!(psu
                .bus
                .writes
                .iter()
                .all(|(address, request)| *address == APW_UART_TUNNEL_I2C_ADDR
                    && request.as_slice() == [0x11, 0x55, 0xaa, 0x04, 0x03, 0x07, 0x00]));
        }
    }

    #[test]
    fn probe_identity_accepts_expected_signature() {
        let mut psu = ApwUartTunnel::new(MockBus::new(vec![
            Ok(reply_frame(0x02, &[0x76, 0x00], 8)),
            Ok(reply_frame(0x01, &[0x17, 0x00], 8)),
        ]));
        psu.probe_identity().expect("APW121215f signature");
    }

    #[test]
    fn probe_identity_rejects_wrong_hw() {
        let mut psu =
            ApwUartTunnel::new(MockBus::new(vec![Ok(reply_frame(0x02, &[0x99, 0x00], 8))]));
        assert!(psu.probe_identity().is_err());
    }

    #[test]
    fn command_rejects_opcode_echo_mismatch() {
        let mut psu =
            ApwUartTunnel::new(MockBus::new(vec![Ok(reply_frame(0xFF, &[0x76, 0x00], 8))]));
        assert!(psu.read_hw_type().is_err());
    }

    #[test]
    fn calibration_transport_failure_is_fatal() {
        let mut psu = ApwUartTunnel::new(MockBus::new(vec![Err(HalError::PsuProtocolOwned(
            "x".into(),
        ))]));
        assert!(psu.send_calibration_message().is_err());
        assert_eq!(psu.bus.writes.len(), 1);
        assert!(psu.bus.replies.is_empty());
    }

    #[test]
    fn calibration_unset_payload_requires_complete_valid_frame() {
        let mut data = vec![0x40];
        data.extend_from_slice(&[0xff; 32]);
        let valid = reply_frame(OP_READ_CAL_BLOCK, &data, 40);
        let mut psu = ApwUartTunnel::new(MockBus::new(vec![Ok(valid.clone())]));
        psu.send_calibration_message().unwrap();
        for changed in [2, 3, 4, 37, 38] {
            let mut malformed = valid.clone();
            malformed[changed] ^= 1;
            let mut psu = ApwUartTunnel::new(MockBus::new(vec![Ok(malformed)]));
            assert!(psu.send_calibration_message().is_err(), "byte {changed}");
            assert_eq!(psu.bus.writes.len(), 1);
        }
    }

    #[test]
    fn watchdog_disable_uses_ghidra_confirmed_frame() {
        let mut psu = ApwUartTunnel::new(MockBus::new(vec![Ok(reply_frame(
            OP_WATCHDOG_CONTROL,
            &[0x00, 0x00],
            8,
        ))]));
        assert!(psu.send_watchdog_disable_message().is_ok());
        assert_eq!(psu.bus.writes.len(), 1);
        assert_eq!(
            psu.bus.writes[0].1,
            vec![0x11, 0x55, 0xAA, 0x06, 0x81, 0x00, 0x00, 0x87, 0x00]
        );
        assert_eq!(
            psu.bus.delays,
            vec![Duration::from_millis(APW_READ_DELAY_MS)]
        );
        assert_eq!(psu.bus.reads, vec![(0x10, 8)]);
    }

    #[test]
    fn watchdog_disable_rejects_wrong_or_short_echo() {
        for data in [vec![], vec![0], vec![1, 0], vec![0, 1], vec![0, 0, 0]] {
            let mut psu = ApwUartTunnel::new(MockBus::new(vec![Ok(reply_frame(
                OP_WATCHDOG_CONTROL,
                &data,
                8,
            ))]));
            assert!(psu.send_watchdog_disable_message().is_err(), "{data:?}");
            assert_eq!(psu.bus.writes.len(), 1);
        }
    }

    #[test]
    fn calibration_block_read_uses_long_delay_and_complete_checksum() {
        let mut raw = vec![0x55, 0xAA, 0x25, 0x06, 0x40];
        raw.extend(std::iter::repeat(0xFF).take(32));
        raw.extend_from_slice(&[0x4B, 0x20, 0xF5]);
        let mut psu = ApwUartTunnel::new(MockBus::new(vec![Ok(raw)]));
        let data = psu.read_calibration_block().unwrap();
        assert_eq!(data.len(), 33);
        assert_eq!(
            psu.bus.delays,
            vec![Duration::from_millis(APW_CAL_READ_DELAY_MS)]
        );
    }

    #[test]
    fn voltage_actuation_requires_retained_controller_authority() {
        let mut psu = ApwUartTunnel::new(MockBus::new(vec![]));
        assert!(psu.set_voltage_mv(15000).is_err());
        assert!(psu.bus.writes.is_empty());
    }

    fn admitted_voltage_bus(replies: Vec<Result<Vec<u8>>>) -> MockBus {
        let mut bus = MockBus::new(replies);
        bus.voltage_authorized = true;
        bus
    }

    fn voltage_replies(code: &[u8]) -> Vec<Result<Vec<u8>>> {
        vec![
            Ok(reply_frame(2, &[0x76, 0], 8)),
            Ok(reply_frame(1, &[0x17, 0], 8)),
            Ok(reply_frame(0x83, code, 8)),
            Ok(reply_frame(3, code, 10)),
        ]
    }

    #[test]
    fn admitted_hw76_setter_matches_source_bounds_echo_and_separate_readback() {
        for mv in [11_880, 12_000, 13_800, 14_920, 15_000, 15_120] {
            let code = Apw76VoltageCode::from_millivolts(mv).unwrap().payload();
            let mut psu = ApwUartTunnel::new(admitted_voltage_bus(voltage_replies(&code)));
            psu.set_voltage_mv(mv).unwrap();
            assert_eq!(
                psu.bus
                    .writes
                    .iter()
                    .map(|(_, frame)| frame[4])
                    .collect::<Vec<_>>(),
                [2, 1, 0x83, 3]
            );
            assert_eq!(psu.bus.writes[2].1, build_request(0x83, &code).unwrap());
            assert_eq!(
                psu.bus.delays,
                vec![Duration::from_millis(APW_READ_DELAY_MS); 4]
            );
        }
        assert_eq!(
            Apw76VoltageCode::from_millivolts(15_120).unwrap().payload(),
            [0, 0]
        );
    }

    #[test]
    fn zero_and_out_of_bounds_never_become_off_or_clamped_voltage() {
        for mv in [0, 1, 11_879, 15_121, 15_500, u16::MAX] {
            let mut psu = ApwUartTunnel::new(admitted_voltage_bus(vec![]));
            assert!(psu.set_voltage_mv(mv).is_err());
            assert!(psu.bus.writes.is_empty());
        }
    }

    #[test]
    fn every_set_exchange_failure_or_foreign_reply_invalidates_identity_and_stops() {
        for stage in 0..4 {
            for failure in 0..5 {
                let mut replies = voltage_replies(&[0, 0]);
                let opcode = [2, 1, 0x83, 3][stage];
                replies[stage] = match failure {
                    0 => Err(HalError::PsuProtocolOwned(
                        "injected transport failure".into(),
                    )),
                    1 => Ok(reply_frame(0x7f, &[0, 0], 8)),
                    2 => Ok(reply_frame(opcode, &[1, 1], 8)),
                    3 => Ok(reply_frame(opcode, &[0], 8)),
                    _ => {
                        let mut raw = reply_frame(opcode, &[0, 0], 8);
                        raw[6] ^= 1;
                        Ok(raw)
                    }
                };
                let mut psu = ApwUartTunnel::new(admitted_voltage_bus(replies));
                assert!(
                    psu.set_voltage_mv(15_120).is_err(),
                    "stage{stage}/failure{failure}"
                );
                assert_eq!(psu.bus.writes.len(), stage + 1);
                assert_eq!((psu.hw_type(), psu.fw_version()), (0, 0));
            }
        }
    }

    #[test]
    fn changed_dac_readback_is_fatal_and_fixed_supply_check_never_sets_voltage() {
        let mut replies = voltage_replies(&[0, 0]);
        replies[3] = Ok(reply_frame(3, &[1, 0], 10));
        let mut psu = ApwUartTunnel::new(admitted_voltage_bus(replies));
        assert!(psu.set_voltage_mv(15_120).is_err());
        let mut psu = ApwUartTunnel::new(MockBus::new(vec![
            Ok(reply_frame(2, &[0x76, 0], 8)),
            Ok(reply_frame(1, &[0x17, 0], 8)),
            Ok(reply_frame(3, &[0, 0], 10)),
        ]));
        psu.require_fixed_supply().unwrap();
        assert_eq!(
            psu.bus
                .writes
                .iter()
                .map(|(_, frame)| frame[4])
                .collect::<Vec<_>>(),
            [2, 1, 3]
        );
    }

    #[test]
    fn reported_voltage_uses_fresh_exact_identity_and_original_opcode03() {
        let mut psu = ApwUartTunnel::new(MockBus::new(vec![
            Ok(reply_frame(0x02, &[0x76, 0], 8)),
            Ok(reply_frame(0x01, &[0x17, 0], 8)),
            Ok(reply_frame(0x03, &[0x23, 0], 10)),
            Ok(reply_frame(0x02, &[0x73, 0], 8)),
        ]));
        assert_eq!(psu.read_voltage_mv().unwrap(), 14670);
        assert_eq!(
            psu.bus
                .writes
                .iter()
                .map(|(_, frame)| frame[4])
                .collect::<Vec<_>>(),
            [2, 1, 3]
        );
        assert_eq!(psu.bus.reads, [(0x10, 8), (0x10, 8), (0x10, 10)]);
        assert!(psu.read_voltage_mv().is_err());
        assert_eq!((psu.hw_type(), psu.fw_version()), (0, 0));
        assert_eq!(psu.bus.writes.len(), 4);
    }

    #[test]
    fn voltage_observation_refuses_foreign_fw_address_and_invalid_raw_reply() {
        let mut foreign = ApwUartTunnel::new_at(MockBus::new(vec![]), 0x11);
        assert!(foreign.read_voltage_mv().is_err());
        assert!(foreign.bus.writes.is_empty());
        let mut firmware = ApwUartTunnel::new(MockBus::new(vec![
            Ok(reply_frame(0x02, &[0x76, 0], 8)),
            Ok(reply_frame(0x01, &[0x18, 0], 8)),
        ]));
        assert!(firmware.read_voltage_mv().is_err());
        assert_eq!((firmware.hw_type(), firmware.fw_version()), (0, 0));
        assert_eq!(firmware.bus.writes.len(), 2);
        let mut corrupted = reply_frame(0x03, &[0x23, 0], 10);
        corrupted[7] ^= 1;
        for raw in [
            reply_frame(3, &[0x23], 10),
            reply_frame(3, &[0x23, 1], 10),
            reply_frame(3, &[0x23, 0, 0], 10),
            reply_frame(4, &[0x23, 0], 10),
            vec![0xf5; 10],
            corrupted,
        ] {
            let mut psu = ApwUartTunnel::new(MockBus::new(vec![
                Ok(reply_frame(0x02, &[0x76, 0], 8)),
                Ok(reply_frame(0x01, &[0x17, 0], 8)),
                Ok(raw),
            ]));
            assert!(psu.read_voltage_mv().is_err());
            assert_eq!((psu.hw_type(), psu.fw_version()), (0, 0));
            assert_eq!(psu.bus.writes.len(), 3, "no stale/default value or retry");
        }
    }

    #[test]
    fn repeated_identity_probe_rejects_donor_stale_and_short_firmware_counterexamples() {
        // Original BB discovery can reuse the prior hardware response after a
        // zero/short firmware read, and does not bind its opcode or preamble.
        // Require a fresh complete firmware frame even after earlier success.
        let hardware = vec![0x55, 0xaa, 6, 2, 0x76, 0, 0x7e, 0];
        let firmware = vec![0x55, 0xaa, 6, 1, 0x17, 0, 0x1e, 0];
        let mut wrong_sync = firmware.clone();
        wrong_sync[..2].copy_from_slice(&[0xaa, 0x55]);
        let mut cases = vec![
            hardware.clone(),
            wrong_sync,
            reply_frame(2, &[0x17, 0], 8),
            vec![0xf5; 8],
        ];
        for length in [0, 3, 7] {
            cases.push(firmware[..length].to_vec());
        }
        for raw in cases {
            let mut psu = ApwUartTunnel::new(MockBus::new(vec![
                Ok(hardware.clone()),
                Ok(firmware.clone()),
                Ok(hardware.clone()),
                Ok(raw),
            ]));
            psu.probe_identity().unwrap();
            assert_eq!((psu.hw_type(), psu.fw_version()), (0x76, 0x17));
            assert!(psu.probe_identity().is_err());
            assert_eq!((psu.hw_type(), psu.fw_version()), (0, 0));
            assert_eq!(
                psu.bus
                    .writes
                    .iter()
                    .map(|(_, frame)| frame[4])
                    .collect::<Vec<_>>(),
                [2, 1, 2, 1]
            );
            assert_eq!(psu.bus.reads, [(0x10, 8); 4]);
            assert!(psu.bus.replies.is_empty());
        }
    }

    #[test]
    fn failed_discovery_request_invalidates_identity_without_consuming_a_reply() {
        struct FailedRequestBus {
            inner: MockBus,
            successful_writes_left: usize,
        }
        impl ApwUartTunnelBus for FailedRequestBus {
            fn write_frame(&mut self, addr: u8, frame: &[u8]) -> Result<()> {
                self.inner.write_frame(addr, frame)?;
                if self.successful_writes_left == 0 {
                    return Err(HalError::PsuProtocolOwned(
                        "incomplete request write".into(),
                    ));
                }
                self.successful_writes_left -= 1;
                Ok(())
            }
            fn read_reply(&mut self, addr: u8, len: usize) -> Result<Vec<u8>> {
                self.inner.read_reply(addr, len)
            }
            fn delay(&mut self, duration: Duration) {
                self.inner.delay(duration);
            }
        }
        // The service converts a short backend write into an error; this
        // exercises the PSU caller's handling of that error, not kernel I/O.
        let mut psu = ApwUartTunnel::new(FailedRequestBus {
            inner: MockBus::new(vec![
                Ok(reply_frame(2, &[0x76, 0], 8)),
                Ok(reply_frame(1, &[0x17, 0], 8)),
                Ok(reply_frame(2, &[0x76, 0], 8)),
            ]),
            successful_writes_left: 2,
        });
        psu.probe_identity().unwrap();
        assert!(psu.probe_identity().is_err());
        assert_eq!((psu.hw_type(), psu.fw_version()), (0, 0));
        assert_eq!(psu.bus.inner.writes.len(), 3);
        assert_eq!(psu.bus.inner.reads.len(), 2);
        assert_eq!(psu.bus.inner.delays.len(), 2);
        assert_eq!(psu.bus.inner.replies.len(), 1);
    }

    #[test]
    fn original_stock_dac_frame_keeps_checksum_carry_without_enabling_voltage_api() {
        // Independent byte-exact stock BB/S21 APW frame vectors; this merely
        // serializes them and invokes no bus or set-voltage path.
        assert_eq!(
            build_request(0x83, &[0x6c, 0]).unwrap(),
            [0x11, 0x55, 0xaa, 0x06, 0x83, 0x6c, 0, 0xf5, 0]
        );
        assert_eq!(
            build_request(0x83, &[0xff, 0]).unwrap(),
            [0x11, 0x55, 0xaa, 0x06, 0x83, 0xff, 0, 0x88, 1]
        );
    }

    #[test]
    fn response_requires_both_checksum_bytes_and_exact_padding_boundary() {
        let frame = [0x55, 0xaa, 0x06, 0x02, 0x76, 0, 0x7e, 0];
        for length in 0..frame.len() {
            assert!(parse_response(&frame[..length]).is_err(), "prefix {length}");
            assert!(parse_response_lenient(&frame[..length]).is_err());
        }
        for index in 0..frame.len() {
            let mut corrupt = frame;
            corrupt[index] ^= 1;
            assert!(parse_response(&corrupt).is_err(), "corrupted byte {index}");
        }
        for suffix in [vec![0xf5, 0], vec![0], frame.to_vec()] {
            let mut raw = frame.to_vec();
            raw.extend(suffix);
            assert!(parse_response(&raw).is_err());
        }
        // A valid declared checksum's high byte can itself equal padding.
        let mut raw = vec![0x55, 0xaa, 0xfa, 0xf9];
        raw.extend(std::iter::repeat(0xff).take(244));
        raw.extend([0xee, 0]);
        //250 +249 +244*255 +238 =62957 =0xf5ed; the data's last byte is zero.
        raw.extend([0xed, 0xf5]);
        assert_eq!(raw.len(), 252);
        assert!(parse_response(&raw).is_ok());
        raw.extend([0xf5, 0xf5]);
        assert!(parse_response(&raw).is_ok());
    }

    #[test]
    fn malformed_calibration_is_rejected_before_returning_any_payload() {
        let mut raw = vec![0x55, 0xaa, 0x25, 0x06, 0x40];
        raw.extend(std::iter::repeat(0xff).take(32));
        raw.extend([0x4b, 0x20, 0xf5]);
        for index in [5, 37, 38] {
            let mut corrupt = raw.clone();
            corrupt[index] ^= 1;
            assert!(parse_response_lenient(&corrupt).is_err());
            let mut psu = ApwUartTunnel::new(MockBus::new(vec![Ok(corrupt)]));
            assert!(psu.read_calibration_block().is_err());
            assert_eq!(psu.bus.writes.len(), 1);
        }
    }

    #[test]
    fn retained_raw_warm_trace_frames_match_actual_transport_codec() {
        let receipt: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../"
        )).unwrap();
        assert_eq!(
            receipt["source_sha256"],
            "0608a360af145828ef651400a0c24d40153e32cccd1b6335b04935cc7fcca0b0"
        );
        let decode = |value: &serde_json::Value| {
            value
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        };
        let rows = receipt["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 12);
        for row in rows {
            let frame = decode(&row["frame_hex"]);
            let data = decode(&row["data_hex"]);
            let opcode = row["opcode"].as_u64().unwrap() as u8;
            if row["operation"] == "i2c_write" {
                assert_eq!(build_request(opcode, &data).unwrap(), frame);
            } else {
                let parsed = parse_response(&frame).unwrap();
                assert_eq!(parsed.opcode_echo, opcode);
                assert_eq!(parsed.data, data);
            }
        }
    }

    #[test]
    fn validated_frames_cannot_alias_identity_or_short_calibration_payloads() {
        for data in [vec![], vec![0x76], vec![0x76, 1], vec![0x76, 0, 0]] {
            let mut psu = ApwUartTunnel::new(MockBus::new(vec![Ok(reply_frame(2, &data, 0))]));
            assert!(psu.read_hw_type().is_err());
            assert_eq!(psu.hw_type(), 0);
            let mut psu = ApwUartTunnel::new(MockBus::new(vec![Ok(reply_frame(1, &data, 0))]));
            assert!(psu.read_fw_version().is_err());
            assert_eq!(psu.fw_version(), 0);
        }
        for data in [vec![], vec![0x40], vec![0x40; 32], vec![0x41; 33]] {
            let mut psu = ApwUartTunnel::new(MockBus::new(vec![Ok(reply_frame(6, &data, 40))]));
            assert!(psu.read_calibration_block().is_err());
        }
    }
}
