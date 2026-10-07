//! UB-19 (2026-08-02) — framed dsPIC/PIC transport robustness: bounded retry,
//! errno discrimination, and command pacing parameters.
//!
//! # Provenance — DESK EVIDENCE ONLY
//!
//! Every parameter in this module is imported from ePIC's `pic_driver.ko`
//! (shipped **GPL and unstripped** in the held UMC OS corpus,
//! `knowledge-base/{firmware-archive,extractions}/epic-umcos/`). This is a
//! *protocol-and-timing* import from a GPL driver — legitimate under its
//! license — and deliberately contains **NO ePIC PL/AXI register addresses**
//! (their addresses live in their own Zynq bitstream and do not transfer).
//! None of these parameters is live-verified on a DCENT-managed unit; treat
//! every constant here as desk evidence until a live capture confirms it.
//!
//! ePIC's exact framed-transport policy:
//! - **4 attempts, 20 ms apart** for retryable failures.
//! - Retryable errno set is exactly
//!   `{EIO, ENXIO, EAGAIN, EBUSY, ETIMEDOUT, EPROTO, EREMOTEIO}` — everything
//!   else is fatal, no retry.
//! - **`0x3B` and `0x3C` are NEVER retried** (the LM75 passthrough pair; a
//!   retry corrupts the PIC-mediated I²C sequence).
//! - 25 ms write→read turnaround.
//! - **500 ms** RESET→JUMP delay (our live-proven
//!   [`super::bosminer_warmup::RESET_DELAY_MS`] is already 500 ms —
//!   convergent with BraiinsOS `braiins_power.rs:391`; no change needed).
//! - 50-jiffy (~500 ms at HZ=100) guard before any voltage command (our
//!   live-proven 5×1 Hz stable-heartbeat pre-voltage gate is strictly
//!   stronger; documented here, not wired).
//! - 45-jiffy (~450 ms at HZ=100) temperature cache validity.
//! - One SMBus transaction **per byte** (our `WriteByteByByte` /
//!   per-byte-`Read(1)` transaction shapes already match this).
//!
//! # Default-OFF wiring — and why
//!
//! The retry executor is wired into `DspicService::{write_read,
//! write_bytes_mutating, bytewise_write_then_read_mutating}` behind
//! [`EPIC_RETRY_ENV`] (`DCENT_DSPIC_EPIC_RETRY=1`), **default OFF**, because
//! silently absorbing transient wire failures would change live-proven
//! failure semantics:
//! - The daemon's dsPIC heartbeat loops use bounded *consecutive-failure*
//!   state machines whose exhaustion terminally shuts the lifecycle down
//!   (load-bearing safety, 2026-07-19 checkpoints). A service-level retry
//!   would make those counters see fewer failures and stretch the
//!   time-to-terminal-shutdown.
//! - The `a lab unit` proven-mining recipe and the `a lab unit`/ cold paths are
//!   pinned byte- and timing-faithful; adding up to 60 ms of extra error-path
//!   latency is a behaviour change on those paths.
//!
//! With the flag unset, every call site performs EXACTLY ONE attempt —
//! byte- and control-flow-identical to the pre-UB-19 code. With the flag set,
//! only the exact ePIC policy applies: allowlisted-errno wire faults on
//! retryable opcodes, at most [`EPIC_FRAMED_ATTEMPTS`] attempts,
//! [`EPIC_RETRY_GAP_MS`] apart. Typed HAL control-plane refusals
//! (`I2cEndpointRefused`, `I2cSafetySuperseded`, `I2cFabricUnavailable`,
//! `I2cAdmissionBusy`, `I2cSafeOffOutcomeUnknown`, …) are NEVER retried —
//! only `HalError::I2c` / `HalError::Io` wire faults qualify, and only when
//! their errno is in the allowlist. This module never touches the EEPROM
//! write-denylist, recovery gating, or fw=0x86 refusal logic.

use dcentrald_hal::HalError;

/// Env gate for the ePIC bounded-retry executor. Default OFF (see module doc).
pub const EPIC_RETRY_ENV: &str = "DCENT_DSPIC_EPIC_RETRY";

/// ePIC `pic_driver.ko`: total attempts per framed command (1 initial + 3
/// retries). DESK EVIDENCE.
pub const EPIC_FRAMED_ATTEMPTS: u32 = 4;

/// ePIC `pic_driver.ko`: gap between attempts, milliseconds. DESK EVIDENCE.
pub const EPIC_RETRY_GAP_MS: u64 = 20;

/// ePIC `pic_driver.ko`: write→read turnaround, milliseconds. DESK EVIDENCE.
/// Documented for reference only — our live-proven reply delays
/// (`DSPIC_GET_VERSION_REPLY_DELAY_MS` = 100 ms, bytewise 6 ms inter-byte)
/// are NOT changed by UB-19; retiming a live-proven path needs a bench pass.
pub const EPIC_WRITE_READ_TURNAROUND_MS: u64 = 25;

/// ePIC `pic_driver.ko`: RESET→JUMP delay, milliseconds. DESK EVIDENCE.
/// Convergent with our live-proven `bosminer_warmup::RESET_DELAY_MS` (500 ms,
/// BraiinsOS-derived) — pinned equal by a test below; no behaviour change.
pub const EPIC_RESET_TO_JUMP_DELAY_MS: u64 = 500;

/// ePIC `pic_driver.ko`: guard before any voltage command — 50 jiffies at
/// HZ=100 ≈ 500 ms. DESK EVIDENCE, documented only: our 5×1 Hz
/// stable-heartbeat pre-voltage gate (≈5 s) is strictly stronger.
pub const EPIC_PRE_VOLTAGE_GUARD_MS: u64 = 500;

/// ePIC `pic_driver.ko`: temperature cache validity — 45 jiffies at HZ=100
/// ≈ 450 ms. DESK EVIDENCE, documented only (no DCENT temp cache retimed).
pub const EPIC_TEMP_CACHE_VALIDITY_MS: u64 = 450;

/// ePIC `pic_driver.ko` retryable errno allowlist — EXACTLY these seven;
/// everything else is fatal with no retry. DESK EVIDENCE.
pub const EPIC_RETRYABLE_ERRNOS: [i32; 7] = [
    libc::EIO,       // 5   — generic wire/NACK fault
    libc::ENXIO,     // 6   — address NACK
    libc::EAGAIN,    // 11  — adapter busy/would-block
    libc::EBUSY,     // 16  — bus busy
    libc::ETIMEDOUT, // 110 — adapter timeout
    libc::EPROTO,    // 71  — protocol fault
    libc::EREMOTEIO, // 121 — remote I/O (Linux I²C NACK mapping)
];

/// True iff `errno` is in the exact ePIC retryable set.
pub fn errno_is_retryable(errno: i32) -> bool {
    EPIC_RETRYABLE_ERRNOS.contains(&errno)
}

/// True iff this dsPIC opcode may be retried at the transport layer.
///
/// ePIC NEVER retries `0x3B`/`0x3C` (the LM75 passthrough WRITE/READ pair):
/// the passthrough is a stateful two-frame sequence over the PIC-mediated
/// I²C bridge, and re-sending one half corrupts it. Our live `a lab unit` captures
/// confirm the same pairing (`bosminer_warmup::LM75_PT_OPCODE_{WRITE,READ}`).
pub fn opcode_may_retry(opcode: u8) -> bool {
    !matches!(
        opcode,
        super::CMD_LM75_PASSTHROUGH_WRITE | super::CMD_LM75_PASSTHROUGH_READ
    )
}

/// Extract the dsPIC opcode from a fully-encoded wire frame.
///
/// - BARE:   `[0x55, 0xAA, CMD, payload...]` → `frame[2]`
/// - FRAMED: `[0x55, 0xAA, LEN, CMD, payload..., CKSUM...]` → `frame[3]`
///
/// Returns `None` for frames without the `55 AA` preamble (e.g. raw parser
/// flush byte-strings) — the executor treats `None` as NOT retryable
/// (fail-closed: never retry what we cannot classify).
pub fn wire_frame_opcode(frame: &[u8], bare_protocol: bool) -> Option<u8> {
    if frame.len() < 3 || frame[0] != 0x55 || frame[1] != 0xAA {
        return None;
    }
    if bare_protocol {
        Some(frame[2])
    } else {
        frame.get(3).copied()
    }
}

/// Best-effort errno extraction from an error's Display string.
///
/// `HalError::I2c { detail }` embeds `std::io::Error`'s Display, which on
/// Linux ends in `(os error N)`. Structured `HalError::Io` is matched
/// directly by [`hal_error_retryable`]; this string parse covers the
/// stringified `detail` paths without widening any typed refusal.
pub fn extract_os_error(display: &str) -> Option<i32> {
    let idx = display.rfind("os error ")?;
    let digits: String = display[idx + "os error ".len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// True iff this HAL error is a *wire fault with an allowlisted errno*.
///
/// Fail-closed: typed control-plane refusals and everything unclassifiable
/// return `false` (single attempt, exactly the pre-UB-19 behaviour).
pub fn hal_error_retryable(error: &HalError) -> bool {
    match error {
        HalError::Io(io) => io.raw_os_error().map(errno_is_retryable).unwrap_or(false),
        HalError::I2c { detail, .. } => extract_os_error(detail)
            .map(errno_is_retryable)
            .unwrap_or(false),
        // Every other variant — typed refusals, ownership, safety, policy,
        // endpoint-not-ready readiness (owned by caller deadlines), SafeOff
        // ambiguity — is NEVER retried here.
        _ => false,
    }
}

/// Whether the operator has opted the framed transport into ePIC bounded
/// retry (`DCENT_DSPIC_EPIC_RETRY=1`). Default OFF.
pub fn epic_retry_enabled() -> bool {
    epic_retry_value_enabled(dcentrald_common::lab_env::var(EPIC_RETRY_ENV).ok().as_deref())
}

/// Pure policy resolver for [`epic_retry_enabled`] (host-testable without
/// process-global env mutation).
pub fn epic_retry_value_enabled(value: Option<&str>) -> bool {
    value.map(str::trim) == Some("1")
}

/// Run `op` with the exact ePIC bounded-retry policy.
///
/// - `enabled == false` (the default): exactly one attempt, no sleep —
///   control-flow-identical to the pre-UB-19 transport.
/// - `enabled == true`: up to [`EPIC_FRAMED_ATTEMPTS`] attempts,
///   [`EPIC_RETRY_GAP_MS`] apart, retrying ONLY when the opcode is retryable
///   ([`opcode_may_retry`]; `None` = not retryable) AND the failure is an
///   allowlisted-errno wire fault ([`hal_error_retryable`]).
pub fn run_with_bounded_retry_policy<T>(
    enabled: bool,
    opcode: Option<u8>,
    mut op: impl FnMut() -> dcentrald_hal::Result<T>,
) -> dcentrald_hal::Result<T> {
    let mut attempt: u32 = 1;
    loop {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let opcode_ok = opcode.map(opcode_may_retry).unwrap_or(false);
                if !enabled
                    || attempt >= EPIC_FRAMED_ATTEMPTS
                    || !opcode_ok
                    || !hal_error_retryable(&e)
                {
                    return Err(e);
                }
                tracing::warn!(
                    attempt,
                    max_attempts = EPIC_FRAMED_ATTEMPTS,
                    opcode = opcode.map(|c| format!("0x{c:02X}")),
                    error = %e,
                    "dsPIC framed transport retry (ePIC pic_driver.ko policy, DESK-EVIDENCE; DCENT_DSPIC_EPIC_RETRY=1)"
                );
                std::thread::sleep(std::time::Duration::from_millis(EPIC_RETRY_GAP_MS));
                attempt += 1;
            }
        }
    }
}

/// Env-gated wrapper over [`run_with_bounded_retry_policy`].
pub fn run_with_bounded_retry<T>(
    opcode: Option<u8>,
    op: impl FnMut() -> dcentrald_hal::Result<T>,
) -> dcentrald_hal::Result<T> {
    run_with_bounded_retry_policy(epic_retry_enabled(), opcode, op)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    fn wire_eio() -> HalError {
        HalError::I2c {
            bus: 0,
            addr: 0x20,
            detail: format!("write failed: {}", io::Error::from_raw_os_error(libc::EIO)),
        }
    }

    #[test]
    fn errno_allowlist_is_exactly_the_epic_seven() {
        for errno in [
            libc::EIO,
            libc::ENXIO,
            libc::EAGAIN,
            libc::EBUSY,
            libc::ETIMEDOUT,
            libc::EPROTO,
            libc::EREMOTEIO,
        ] {
            assert!(errno_is_retryable(errno), "errno {errno} must be retryable");
        }
        // Everything else is fatal — spot-check the classic non-members.
        for errno in [
            libc::EPERM,
            libc::ENOENT,
            libc::EINTR,
            libc::EACCES,
            libc::EFAULT,
            libc::ENODEV,
            libc::EINVAL,
            libc::ENOSYS,
        ] {
            assert!(!errno_is_retryable(errno), "errno {errno} must be fatal");
        }
    }

    #[test]
    fn lm75_passthrough_pair_is_never_retryable() {
        assert!(!opcode_may_retry(0x3B));
        assert!(!opcode_may_retry(0x3C));
        // Representative retryable opcodes.
        for cmd in [
            super::super::CMD_GET_VERSION,
            super::super::CMD_SET_VOLTAGE,
            super::super::CMD_ENABLE_VOLTAGE,
            super::super::CMD_HEARTBEAT,
            super::super::CMD_MEASURE_VOLTAGE,
        ] {
            assert!(opcode_may_retry(cmd), "0x{cmd:02X} must be retryable");
        }
    }

    #[test]
    fn wire_frame_opcode_reads_bare_and_framed_positions() {
        // BARE [55 AA 17]
        assert_eq!(wire_frame_opcode(&[0x55, 0xAA, 0x17], true), Some(0x17));
        // FRAMED [55 AA 04 17 00 1B]
        assert_eq!(
            wire_frame_opcode(&[0x55, 0xAA, 0x04, 0x17, 0x00, 0x1B], false),
            Some(0x17)
        );
        // Parser-flush zero strings have no preamble → unclassifiable → None.
        assert_eq!(wire_frame_opcode(&[0u8; 16], false), None);
        assert_eq!(wire_frame_opcode(&[0x55], false), None);
    }

    #[test]
    fn os_error_extraction_parses_linux_io_display() {
        let e = io::Error::from_raw_os_error(libc::EREMOTEIO);
        let display = format!("svc write_read: I2C error on bus 0 addr 0x20: write failed: {e}");
        assert_eq!(extract_os_error(&display), Some(libc::EREMOTEIO));
        assert_eq!(extract_os_error("no errno here"), None);
    }

    #[test]
    fn hal_error_retryable_is_fail_closed_for_typed_refusals() {
        assert!(hal_error_retryable(&wire_eio()));
        assert!(hal_error_retryable(&HalError::Io(
            io::Error::from_raw_os_error(libc::ETIMEDOUT)
        )));
        // Non-allowlisted errno on a wire fault: fatal.
        assert!(!hal_error_retryable(&HalError::Io(
            io::Error::from_raw_os_error(libc::EINVAL)
        )));
        // Typed control-plane refusals: NEVER retried, even if the detail
        // string embeds an allowlisted os error.
        let refused = HalError::I2cEndpointRefused {
            bus: 0,
            addr: 0x20,
            detail: format!("refused: {}", io::Error::from_raw_os_error(libc::EIO)),
        };
        assert!(!hal_error_retryable(&refused));
        let not_ready = HalError::I2cEndpointNotReady {
            bus: 0,
            addr: 0x20,
            detail: format!("not ready: {}", io::Error::from_raw_os_error(libc::EIO)),
        };
        assert!(!hal_error_retryable(&not_ready));
    }

    #[test]
    fn disabled_policy_makes_exactly_one_attempt() {
        let mut calls = 0;
        let r: dcentrald_hal::Result<()> =
            run_with_bounded_retry_policy(false, Some(super::super::CMD_GET_VERSION), || {
                calls += 1;
                Err(wire_eio())
            });
        assert!(r.is_err());
        assert_eq!(
            calls, 1,
            "flag OFF must be single-attempt (pre-UB-19 identical)"
        );
    }

    #[test]
    fn enabled_policy_retries_up_to_four_attempts_on_allowlisted_wire_faults() {
        let mut calls = 0;
        let r: dcentrald_hal::Result<()> =
            run_with_bounded_retry_policy(true, Some(super::super::CMD_GET_VERSION), || {
                calls += 1;
                Err(wire_eio())
            });
        assert!(r.is_err());
        assert_eq!(calls, EPIC_FRAMED_ATTEMPTS as i32, "exactly 4 attempts");
    }

    #[test]
    fn enabled_policy_recovers_on_a_mid_sequence_success() {
        let mut calls = 0;
        let r = run_with_bounded_retry_policy(true, Some(super::super::CMD_HEARTBEAT), || {
            calls += 1;
            if calls < 3 {
                Err(wire_eio())
            } else {
                Ok(42u8)
            }
        });
        assert_eq!(r.unwrap(), 42);
        assert_eq!(calls, 3);
    }

    #[test]
    fn enabled_policy_never_retries_lm75_passthrough_or_fatal_errnos() {
        // 0x3B passthrough-WRITE: single attempt even when enabled.
        let mut calls = 0;
        let r: dcentrald_hal::Result<()> = run_with_bounded_retry_policy(true, Some(0x3B), || {
            calls += 1;
            Err(wire_eio())
        });
        assert!(r.is_err());
        assert_eq!(calls, 1, "0x3B must never be retried");

        // 0x3C passthrough-READ: same.
        let mut calls = 0;
        let r: dcentrald_hal::Result<()> = run_with_bounded_retry_policy(true, Some(0x3C), || {
            calls += 1;
            Err(wire_eio())
        });
        assert!(r.is_err());
        assert_eq!(calls, 1, "0x3C must never be retried");

        // Fatal errno (EINVAL): single attempt.
        let mut calls = 0;
        let r: dcentrald_hal::Result<()> =
            run_with_bounded_retry_policy(true, Some(super::super::CMD_GET_VERSION), || {
                calls += 1;
                Err(HalError::Io(io::Error::from_raw_os_error(libc::EINVAL)))
            });
        assert!(r.is_err());
        assert_eq!(calls, 1, "non-allowlisted errno must be fatal");

        // Unclassifiable opcode (None): single attempt.
        let mut calls = 0;
        let r: dcentrald_hal::Result<()> = run_with_bounded_retry_policy(true, None, || {
            calls += 1;
            Err(wire_eio())
        });
        assert!(r.is_err());
        assert_eq!(calls, 1, "unknown opcode must be fail-closed (no retry)");
    }

    #[test]
    fn env_gate_contract_is_exact_1_only() {
        assert!(!epic_retry_value_enabled(None));
        assert!(!epic_retry_value_enabled(Some("")));
        assert!(!epic_retry_value_enabled(Some("0")));
        assert!(!epic_retry_value_enabled(Some("true")));
        assert!(epic_retry_value_enabled(Some("1")));
        assert!(epic_retry_value_enabled(Some(" 1 ")));
    }

    #[test]
    fn epic_reset_to_jump_delay_converges_with_live_proven_braiins_value() {
        // ePIC (desk) and BraiinsOS (live-proven on our fleet) independently
        // land on 500 ms — pin the convergence so neither drifts silently.
        assert_eq!(
            EPIC_RESET_TO_JUMP_DELAY_MS,
            super::super::bosminer_warmup::RESET_DELAY_MS
        );
    }

    #[test]
    fn epic_desk_constants_pinned() {
        assert_eq!(EPIC_FRAMED_ATTEMPTS, 4);
        assert_eq!(EPIC_RETRY_GAP_MS, 20);
        assert_eq!(EPIC_WRITE_READ_TURNAROUND_MS, 25);
        assert_eq!(EPIC_PRE_VOLTAGE_GUARD_MS, 500);
        assert_eq!(EPIC_TEMP_CACHE_VALIDITY_MS, 450);
        assert_eq!(
            EPIC_RETRYABLE_ERRNOS,
            [5, 6, 11, 16, 110, 71, 121],
            "Linux errno values for EIO/ENXIO/EAGAIN/EBUSY/ETIMEDOUT/EPROTO/EREMOTEIO"
        );
    }
}
