//! AM335x BeagleBone S19j Pro (`S19J_IO_BOARD_V2_0`) mining mode (`--am3-bb-mining`).
//!
//! Ties together: the Phase-B `BeagleBonePlatform` (board-target TOML +
//! `cold_boot_sequence_s19j_io_v2`), the Phase-1 `bm1362::uart_transport::Am335xUartTransport`
//! (88-byte BM1362 serial work dispatch over the OMAP UART, no kernel module),
//! the BM1362 chip-side init, and a Stratum mining loop.
//!
//! Historical bench target: `a lab unit` (LuxOS). An earlier binary produced accepted
//! shares there. The current retained-PSU GPIO65/watchdog lifecycle is EXPERIMENTAL
//! and host-validated only; an authorized current-binary bench rerun is still
//! required. Remaining inferred cold-boot surfaces are catalogued in
//! .
//!
//! ## Mining-loop wiring decision: OPTION B2 (self-contained loop, reuse the crates)
//!
//! `serial_mining.rs`'s `SerialMiner::run()` does its OWN PIC/PSU/GPIO cold-boot
//! and its OWN BM1362 PLL/MiscCtrl init by reopening the serial port — and its
//! `am3-bb uart_trans` branch is hard-wired to `DEFAULT_CHAIN_TTYS`
//! (`/dev/ttyO{1,2,4,5}`, 4 kernel `SerialChain`s), whereas the `a lab unit` unit is
//! `/dev/ttyS{1,2,4}` (3 chains) driven via `DevmemUart` (mmap). Hooking that
//! path up cleanly (B1) would mean a 4-vs-3 chain mismatch, a `/dev/ttyO*` ↔
//! `/dev/ttyS*` rename, and threading an "external cold-boot" gate through dozens
//! of `SerialMiner::run()` branches. Too invasive for the win.
//!
//! Instead this module does the `a lab unit`-specific cold-boot + BM1362 chip-side init
//! itself (the earlier sequence has historical `a lab unit` evidence), then
//! runs a **small self-contained mining loop on the existing blocking thread**
//! that REUSES the shared crates rather than re-implementing them:
//!  - `dcentrald_stratum::StratumRouter` (Stratum V1/V2 connect, job feed,
//!    share submit, status) — spawned on the main tokio runtime via a `Handle`,
//!    communicating over mpsc channels (the same channels `serial_mining.rs` uses).
//!  - `dcentrald_stratum::WorkBuilder::next_work` (coinbase → merkle root →
//!    midstate → `MiningWork`).
//!  - `dcentrald_stratum::share_pipeline::validate_full_header` (the same SHA-256d share
//!    gate that got DCENT_axe / S9 their accepted shares) + dedup-before-submit
//!.
//!  - `dcentrald_asic::bm1362::Am335xUartTransport` for paced 88-byte BM1362
//!    serial work dispatch + 11-byte nonce-frame poll (the transport this
//!    module already builds from the `DevmemUart`s; no kernel module).
//!
//! What is solid: the cold-boot orchestration, the BM1362 chip-side init
//! (GetAddress enum -> ChainInactive x3 + SetChipAddress -> core register block
//! -> PLL ramp -> fast-baud -> per-chip post-baud loop), the transport setup,
//! and the Stratum connect/work-build/dispatch/nonce-validate/dedup/submit wiring.
//!
//! ## R7-3 RESOLVED (2026-05-12, by cross-check against the PROVEN serial path)
//!
//! The earlier "BEST-GUESS `asic_work_t.data`/`.data2`" mapping was wrong: the
//! W14.B 86-byte `asic_work_t` codec ([`dcentrald_asic::bm1362::AsicWorkFrame`])
//! came from the W4 dev-kit `bm1362_frames_v2.h` and does NOT match what a
//! BM1362 chip actually speaks. The LuxOS RE corpus
//! (:
//! "standard BM1362 chip-comm framing") + cross-check against the **proven,
//! sustained-mining-validated** Amlogic-NoPic serial path
//! (`dcentrald::serial_mining` / `dcentrald_asic::drivers::bm1362::build_serial_work_frame`)
//! resolve it:
//!  - **Work-job frame (88 B on the wire)**: `[0x55 0xAA][0x21][0x56][82-byte
//!    BM1366-family full-header payload][CRC16-CCITT-FALSE hi, lo]` — built here
//!    by [`build_bm1362_serial_work_frame`] (verbatim from the proven
//!    `serial_mining.rs` builder, which operates on the same
//!    `dcentrald_stratum::share_pipeline::MiningWork`). Payload: `job_id(1) num_midstates=0x01(1)
//!    starting_nonce=0(4) nbits(4 LE) ntime(4 LE) merkle_root(32, 32-bit-word-reversed)
//!    prev_block_hash(32, 32-bit-word-reversed) version(4 LE)`.
//!  - **NO open-core dummy-work**: BM1362 is not the BM1387 14 nm — it activates
//!    its cores via init register writes, not 114 dummy-work packets (per
//!    `dcentrald_asic::drivers::bm1362` module docs, verified against bosminer).
//!    The old "N zero-payload `asic_work_t`" open-core step is removed.
//!  - **Nonce-response frame (11 B on the wire)**: `[0xAA 0x55][n3 n2 n1 n0]
//!    [midstate_idx][result][vbits_hi vbits_lo][flags]` —
//!    [`dcentrald_asic::bm1362::Bm1362SerialNonce`] / `parse_bm1362_serial_nonce`.
//!    `nonce = u32::from_le_bytes` of the 4 wire bytes; `job_id = (result & 0xF0) >> 1`
//!    (only bits [6:3] of the sent job_id round-trip, so the dispatcher steps by
//!    [`JOB_ID_INCREMENT`] = 24); `vbits` BE, rolled version reconstructed via
//!    `(base & !0x1FFF_E000) | ((vbits << 13) & 0x1FFF_E000)`; `flags` bit7 = job-response.
//!  - **CRC = CRC-16/CCITT-FALSE** (poly 0x1021, init 0xFFFF, no refin/refout, no
//!    xorout) — `dcentrald_hal::serial_chain::crc16_public`. NOT IBM-SDLC; the
//!     IBM-SDLC claim is for a different
//!    (kernel-internal) layer / was wrong for the on-chip-wire serial frame.
//!
//! BM1362 cold-boot register block (2026-05-13): [`bm1362_chip_init_one_chain`]
//! now ports the proven Amlogic-NoPic serial path to AM335x direct UART:
//! `0xA8` InitControl + MiscCtrl x3 + `0xA4` VersionMask (pre-baud),
//! `0x3C` x2 (HashClk/ClkDelay) + `0x54` AnalogMux + `0x58` IoDriver +
//! `0x14` TicketMask=0xFF + `0x10` HashCountingNumber, a 400 MHz -> target PLL
//! ramp, `0x28` FastUART + MiscCtrl x3, host baud switch, a fast-baud GetAddress
//! probe, then the per-chip post-baud `0xA8`/MiscCtrl x3/`0x3C` x3 loop. The
//! APW supply is independently bound to its exact GPIO65/adapter owner, with
//! complete acknowledgment and DAC readback required before reset release.
//!
//! The cold-boot command sequence retains its historical evidence, but its
//! authority boundary is stronger: `cold_boot_sequence_s19j_io_v2` now consumes
//! the caller's sole pre-opened ON owner and never exports/configures PSU GPIO65.
//! Set `DCENT_AM3_BB_STUB_LOOP=1` to fall back to the old logging-only
//! stub ([`run_mining_loop_stub`]) for a cold-boot/enum-only diagnostic run.
//!
//! ## Cross-references
//!
//! - `DCENT_OS_Antminer/dcentrald/dcentrald-hal/src/platform/beaglebone.rs` — `BeagleBonePlatform`
//! - `DCENT_OS_Antminer/dcentrald/dcentrald-hal/src/platform/beaglebone_cold_boot.rs` — `cold_boot_sequence_s19j_io_v2`
//! - `DCENT_OS_Antminer/dcentrald/dcentrald-hal/src/psu_apw_uart_tunnel.rs` — APW121215f UART-tunnel PSU
//! - `DCENT_OS_Antminer/dcentrald/dcentrald-asic/src/bm1362/uart_transport.rs` — pacing/ring transport + the BM1362 serial nonce parser
//! - `DCENT_OS_Antminer/dcentrald/dcentrald-asic/src/drivers/bm1362.rs` — `build_serial_work_frame` (the proven 88-byte BM1362 full-header frame) + `decode_nonce`
//! - `DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining.rs` — the shared Stratum/work-build machinery + the proven BM1362 serial work/nonce path this loop mirrors
//! -  — the v1 cold-boot sequence + the LuxOS wire capture

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use dcentrald_api_types::dspic_frame::{decode_framed_sum_reply_body, DspicOpcode};

use dcentrald_asic::bm1362::{
    build_broadcast_write_frame, build_chain_inactive_frame, build_get_address_frame,
    build_set_chip_address_frame, build_single_write_frame, cold_boot_step,
    uart_relay::{
        UART_RELAY_ALT_REG_ADDR, UART_RELAY_BOSMINER_ENABLE, UART_RELAY_BOSMINER_ENABLE_ALT,
        UART_RELAY_REG_ADDR,
    },
    Am335xUartTransport, AsicWorkFrame, Bm1362SerialNonce, ChainUart, UartTransportError,
    CMD_WORK_PACKAGE, UART_SEND_INTERVAL_US,
};
use dcentrald_asic::drivers::bm1362::{
    pll_lookup as bm1362_pll_lookup, pll_ramp_sequence as bm1362_pll_ramp_sequence,
    BM1362_INIT_PLAN, CHIP_ID as BM1362_CHIP_ID,
};
use dcentrald_hal::i2c::{
    spawn_i2c_service_no_register_touch_with_denylist, I2cDspicDisableProtocol, I2cMutationLabel,
    I2cServiceHandle, I2cTransactionStep,
};
use dcentrald_hal::platform::beaglebone::{
    authorize_am3_bb_identity, read_active_board_target_name, BeagleBonePlatform,
};
use dcentrald_hal::platform::beaglebone_psu::BbPsuControllerBinding;
use dcentrald_hal::platform::{
    FanAccess, FanCommandReceipt, HardwareMutationBarrierReceipt,
    HardwareMutationCommitFenceTryWait, HardwareMutationGate, HardwareMutationGateOwner, Platform,
};
use dcentrald_hal::psu_apw_uart_tunnel::{ApwUartTunnel, ApwUartTunnelBus};
use dcentrald_hal::serial::DevmemUart;
use dcentrald_hal::serial_chain::SerialChainBackend;

use crate::config::DcentraldConfig;
use crate::model;
use crate::runtime::safety_watchdog::{
    Am3BbNeverEnergized, Am3BbThreadSlot, Am3BbWatchdogRouteScope, Am3BbWatchdogShutdownManifest,
    SafetyLiveness, SafetyWatchdogOwner, WatchdogAdmission, WatchdogCloseoutReceipt,
    WatchdogDisarmPermit, DEFAULT_WATCHDOG_STOP_TIMEOUT,
};
use crate::runtime::teardown_budget::{TeardownBudgetView, TeardownDisarmAuthority, TeardownStage};
use crate::runtime::thread_guard::{
    FixedThreadRosterGuard, ThreadRosterOwner, ThreadRosterQuiescenceReceipt, ThreadRosterStop,
};
use crate::runtime::watchdog_feed_gate::WatchdogFeedStopSignal;

/// Number of distinct nonce→work correlation slots (`work_by_id` length).
///
/// The BM1362 serial nonce frame echoes `(sent_job_id & 0xF0) >> 1` — i.e. only
/// bits [6:3] of the sent job id survive — so the meaningful key space is
/// `{0, 8, 16, …, 120}` (16 values mapped into a 0..127 range). We size the
/// table 256 (indexing by the 0..120 echoed value is always in range) and let
/// the dispatcher step by [`JOB_ID_INCREMENT`].
const ASIC_JOB_ID_SPAN: usize = 256;
const WORK_HISTORY_PER_ECHOED_JOB_ID: usize = dcentrald_common::AM3_BB_WORK_HISTORY_PER_ID;
const ASIC_JOB_ID_MASK: u8 = 0x7F;

/// Dispatcher job-id step. Must be a multiple of 8 so it round-trips through the
/// chip's `(sent << 1) & 0xF0` echo encoding; 24 matches the proven BM1368/BM1370
/// family path (`serial_mining.rs`).
const JOB_ID_INCREMENT: u8 = 24;

/// BIP320 version-rolling field mask (bits [28:13]) — the rolled-version
/// reconstruction mask, matching `serial_mining.rs::SERIAL_VERSION_ROLLING_FIELD_MASK`.
const VERSION_ROLLING_FIELD_MASK: u32 = 0x1FFF_E000;

/// BM13xx command preamble for direct chain-UART command traffic.
///
/// The shared `dcentrald_asic::bm1362::build_*_frame` helpers return the
/// command body plus CRC5 trailer (`HDR LEN ... CRC5`) because other callers
/// feed them to transports that add framing. AM3 BB writes directly to
/// `/dev/ttyS*`, so every chip-init command must prepend `55 AA` here. Mining
/// work frames are different: `build_bm1362_serial_work_frame` already returns
/// the full 88-byte wire frame including this preamble.
const BM13XX_CMD_PREAMBLE: [u8; 2] = [0x55, 0xAA];

/// Wire shape observed in the accepted-share AM3-BB captures for a BM1362
/// GetAddress response: `AA 55 13 62 03 00 00 00 0D` (9 bytes total).
///
/// Other BM1362 protocol material describes an 11-byte nonce response, not this
/// discovery shape. The lower five trailer bits are covered by the distinct
/// response-specific CRC state machine; they are not the shared host-command
/// CRC5. Trailer bits 6:5 remain opaque. The repeated live frame is explicitly
/// an unassigned observation: repetitions do not prove unique chips or a chip
/// count, and this diagnostic surface cannot authorize Measured/High identity.
const BM13XX_GET_ADDRESS_RESPONSE_FRAME_BYTES: usize = 9;
const BM13XX_RESPONSE_PREAMBLE: [u8; 2] = [0xAA, 0x55];
const BM1362_UNASSIGNED_GET_ADDRESS_PAYLOAD: [u8; 6] = [0x13, 0x62, 0x03, 0x00, 0x00, 0x00];

/// Bound completed foreign-ON-writer serialization iterations. Every completed
/// iteration reasserts physical LOW; exhaustion leaves ON authority terminally
/// revoked and lets the armed watchdog remain the independent containment
/// boundary. This is not a wall-clock bound on a sleeping sysfs callback.
const AM3_BB_CUTOFF_SERIALIZATION_YIELD_LIMIT: usize = 4_096;
const AM3_BB_RAW_SYSCALL_EINTR_RETRY_LIMIT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GetAddressIntegrity {
    /// Lower-five-bit command-response CRC verified. Bits 6:5 remain opaque.
    CommandResponseCrc5Verified,
}

/// Diagnostic-only interpretation of one raw AM3-BB GetAddress capture.
///
/// `response_frames` counts byte frames, not unique ASICs. The type contains no
/// chip-count or assigned-address claim and cannot be converted into the
/// standard daemon's enumeration receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CrcVerifiedUnassignedGetAddressObservation {
    response_frames: usize,
    raw_bytes: usize,
    integrity: GetAddressIntegrity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GetAddressInspectionError {
    Empty,
    IncompleteFrame {
        raw_bytes: usize,
    },
    BadPreamble {
        frame_index: usize,
    },
    JobResponseTrailer {
        frame_index: usize,
    },
    BadResponseCrc5 {
        frame_index: usize,
        expected: u8,
        observed: u8,
    },
    NotRecordedUnassignedPayload {
        frame_index: usize,
    },
}

/// Strictly split a raw AM3-BB GetAddress capture into the 9-byte response
/// frames proven by live logs. No resynchronization is attempted: leading
/// noise, truncated UART reads, job responses, CRC failures, and any payload
/// other than the retained unassigned observation are rejected.
///
/// Trailer bits 6:5 are deliberately ignored. Frame repetition is not unique
/// chip or count evidence, so this remains diagnostic-only.
fn inspect_am3_bb_get_address_stream(
    raw: &[u8],
) -> std::result::Result<CrcVerifiedUnassignedGetAddressObservation, GetAddressInspectionError> {
    if raw.is_empty() {
        return Err(GetAddressInspectionError::Empty);
    }
    if !raw
        .len()
        .is_multiple_of(BM13XX_GET_ADDRESS_RESPONSE_FRAME_BYTES)
    {
        return Err(GetAddressInspectionError::IncompleteFrame {
            raw_bytes: raw.len(),
        });
    }

    let mut response_frames = 0usize;
    for (frame_index, frame) in raw
        .chunks_exact(BM13XX_GET_ADDRESS_RESPONSE_FRAME_BYTES)
        .enumerate()
    {
        if frame[..2] != BM13XX_RESPONSE_PREAMBLE {
            return Err(GetAddressInspectionError::BadPreamble { frame_index });
        }
        let trailer = frame[8];
        if trailer & 0x80 != 0 {
            return Err(GetAddressInspectionError::JobResponseTrailer { frame_index });
        }
        let expected = dcentrald_asic::protocol::bm13xx_command_response_crc5(&frame[2..8]);
        let observed = trailer & 0x1F;
        if observed != expected {
            return Err(GetAddressInspectionError::BadResponseCrc5 {
                frame_index,
                expected,
                observed,
            });
        }
        if frame[2..8] != BM1362_UNASSIGNED_GET_ADDRESS_PAYLOAD {
            return Err(GetAddressInspectionError::NotRecordedUnassignedPayload { frame_index });
        }
        response_frames += 1;
    }

    Ok(CrcVerifiedUnassignedGetAddressObservation {
        response_frames,
        raw_bytes: raw.len(),
        integrity: GetAddressIntegrity::CommandResponseCrc5Verified,
    })
}

/// Reverse 32-bit word order within a 32-byte array (8 words, MSB-first ↔
/// LSB-first). Verbatim from `dcentrald_asic::drivers::bm1362::reverse_32bit_words`
/// / `serial_mining.rs::reverse_32bit_words` — BM1362 expects `merkle_root` and
/// `prev_block_hash` with each 32-bit word reversed in the full-header job frame.
fn reverse_32bit_words(data: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&data[(7 - i) * 4..(7 - i + 1) * 4]);
    }
    out
}

/// Build the PROVEN 88-byte BM1362 serial-work wire frame from a Stratum
/// [`dcentrald_stratum::share_pipeline::MiningWork`].
///
/// Verbatim port of the canonical BM1362 builder in `serial_mining.rs`
/// (the Amlogic-NoPic / BeagleBone serial path): wire =
/// `[0x55 0xAA][0x21][0x56][82-byte full-header payload][CRC16-CCITT-FALSE hi, lo]`,
/// CRC over the 84 bytes from the `0x21` header byte through the last payload
/// byte (the `0x55 0xAA` preamble is NOT covered). Mirrors
/// `dcentrald_asic::drivers::bm1362::build_serial_work_frame` (which takes the
/// other `MiningWork` type) byte-for-byte.
fn build_bm1362_serial_work_frame(
    work: &dcentrald_stratum::share_pipeline::MiningWork,
    asic_job_id: u8,
) -> [u8; 88] {
    let mut payload = [0u8; 82];
    payload[0] = asic_job_id;
    payload[1] = 0x01; // num_midstates — BM1362 chip computes its own
                       // payload[2..6] = starting_nonce = 0 (already zero)
    payload[6..10].copy_from_slice(&work.nbits.to_le_bytes());
    payload[10..14].copy_from_slice(&work.ntime.to_le_bytes());
    let mr = reverse_32bit_words(&work.merkle_root);
    payload[14..46].copy_from_slice(&mr);
    let pbh = reverse_32bit_words(&work.prev_block_hash);
    payload[46..78].copy_from_slice(&pbh);
    payload[78..82].copy_from_slice(&work.version.to_le_bytes());

    let mut frame = [0u8; 88];
    frame[0] = 0x55;
    frame[1] = 0xAA;
    frame[2] = 0x21; // header: TYPE_JOB | GROUP_SINGLE | CMD_WRITE
    frame[3] = 0x56; // length: 86 = hdr(1)+len(1)+payload(82)+CRC16(2)
    frame[4..86].copy_from_slice(&payload);
    // CRC over bytes [0x21 .. last payload byte] = frame[2..86] (84 bytes),
    // big-endian appended (high byte first) — same as the proven path's
    // `send_work()` (and `drivers::bm1362::build_serial_work_frame`).
    let crc = dcentrald_hal::serial_chain::crc16_public(&frame[2..86]);
    frame[86] = (crc >> 8) as u8;
    frame[87] = (crc & 0xFF) as u8;
    frame
}

/// Build the W4 stock-`uart_trans` 86-byte `asic_work_t` diagnostic frame.
///
/// This is deliberately lab-gated by `DCENT_AM3_BB_WORK_CODEC=asic86`: the live
/// `a lab unit` strict runs proved the serial88 path is still not hashing, while the
/// reverse-engineering corpus contains a conflicting 86-byte `asic_work_t`
/// description. Keeping this builder next to the serial88 builder lets the
/// bench prove or kill that hypothesis without changing the default path.
fn build_bm1362_asic86_work_frame(
    work: &dcentrald_stratum::share_pipeline::MiningWork,
    asic_job_id: u8,
    sno: u32,
) -> AsicWorkFrame {
    let mut data2 = [0u8; 12];
    data2[0..4].copy_from_slice(&work.ntime.to_le_bytes());
    data2[4..8].copy_from_slice(&work.nbits.to_le_bytes());
    // W4 mapping: data2[8..12] carries job_id high bits. The live dispatcher
    // uses an 8-bit ASIC job id, so the high word is currently zero.

    let mut data = [0u8; 64];
    let midstate = work.midstates.first().copied().unwrap_or([0u8; 32]);
    data[0..32].copy_from_slice(&midstate);
    data[32..64].copy_from_slice(&work.merkle_root);

    AsicWorkFrame {
        type_byte: CMD_WORK_PACKAGE,
        rsvd1: 0,
        job_id: asic_job_id,
        rsvd2: 0,
        sno,
        data2,
        data,
    }
}

/// Reconstruct the rolled block version from a base version + the raw
/// version-rolling bits the chip returned in its nonce frame (BIP320 field
/// = bits [28:13]). Mirrors `serial_mining.rs::serial_rolled_version`.
fn rolled_version(base_version: u32, version_bits_raw: u16) -> u32 {
    let raw_masked = ((version_bits_raw as u32) << 13) & VERSION_ROLLING_FIELD_MASK;
    (base_version & !VERSION_ROLLING_FIELD_MASK) | raw_masked
}

fn rolled_version_checked(
    base_version: u32,
    version_mask: u32,
    version_bits_raw: u16,
) -> Option<u32> {
    // Cross-platform Protocol fix sweep (2026-05-15): BM1362-family chips
    // roll BIP320 unconditionally regardless of pool `mining.configure`
    // negotiation. Pre-fix `version_mask == 0 → drop if vbits != 0` was
    // the silent-drop bug pattern that cost the .135 Amlogic 0.023%
    // accept rate. Now reconstruct unconditionally; validate_full_header
    // upstream is the SOLE gate. See
    // .
    let rolled = rolled_version(base_version, version_bits_raw);
    if version_mask == 0 {
        return Some(rolled);
    }
    let delta = rolled ^ base_version;
    if delta & !version_mask != 0 {
        return None;
    }
    Some(rolled)
}

/// The job-id value the BM1362 echoes back in its nonce frame for a given
/// *sent* job id. The chip encodes the sent id as `(sent << 1) & 0xF0` in the
/// high nibble of the RESULT byte, and the parser recovers `(byte & 0xF0) >> 1`
/// — so only bits [6:3] of the sent id survive. This equals `sent & 0x78`.
/// We index `work_by_id` by this value on both store (dispatch) and lookup
/// (nonce). (Matches `serial_mining.rs`'s `(id_byte & 0xF0) >> 1` extraction.)
const fn echoed_job_id(sent: u8) -> u8 {
    ((sent << 1) & 0xF0) >> 1
}

fn next_bm1362_serial_job_id(sent: u8) -> u8 {
    sent.wrapping_add(JOB_ID_INCREMENT) & ASIC_JOB_ID_MASK
}

// ---------------------------------------------------------------------------
// BM1362 cold-boot register values — VERBATIM from the proven Amlogic-NoPic
// serial path (`dcentrald::serial_mining` BM1362 cold-boot, `serial_mining.rs`
// ~lines 415-436). These are the register writes that activate the BM1362
// cores + set the PLL — the milestone log proves the chips *respond* on `a lab unit`
// but they were never set up to hash (the prior `bm1362_chip_init_one_chain`
// did enum → fast-baud → MiscCtrl → TicketMask only). Wiring them in is the #1
// thing for first nonces on `a lab unit`. Reg numbers are the BM1397+ register
// addresses written via [`build_broadcast_write_frame`] (HDR=0x51).
// ---------------------------------------------------------------------------

/// `0xA8` InitControl - broadcast value (Step 1, pre-fast-baud).
const BM1362_REG_INIT_CONTROL: u8 = 0xA8;
const BM1362_INIT_CONTROL_BCAST: u32 = BM1362_INIT_PLAN.init_control_broadcast;
const BM1362_INIT_CONTROL_PER_CHIP: u32 = BM1362_INIT_PLAN.init_control_per_chip;
const BM1362_INIT_CONTROL_BCAST_LEGACY_AMLOGIC: u32 = 0x0000_0000;
const BM1362_INIT_CONTROL_PER_CHIP_LEGACY_AMLOGIC: u32 = 0x0200_0000;
/// `0xA4` VersionMask (Step 1).
const BM1362_REG_VERSION_MASK: u8 = 0xA4;
const BM1362_VERSION_MASK_VALUE: u32 = 0x9000_FFFF;
/// `0x3C` CoreRegCtrl — written 2× broadcast (Step 4): HashClk then ClkDelay.
const BM1362_REG_CORE_CTRL: u8 = 0x3C;
const BM1362_CORE_REG_HASH_CLK: u32 = 0x8000_8540;
const BM1362_CORE_REG_CLK_DELAY: u32 = 0x8000_8008; // BM1362-specific
const BM1362_CORE_REG_UNKNOWN: u32 = 0x8000_82AA;
/// `0x54` AnalogMux (Step 4).
const BM1362_REG_ANALOG_MUX: u8 = 0x54;
const BM1362_ANALOG_MUX_VALUE: u32 = 0x0000_0003;
/// `0x58` IoDriver (Step 4).
const BM1362_REG_IO_DRIVER: u8 = 0x58;
const BM1362_IO_DRIVER_NORMAL: u32 = 0x0001_1111;
/// `0x10` HashCountingNumber / nonce-range (Step 4) — 126 chips (S19j Pro).
const BM1362_REG_NONCE_RANGE: u8 = 0x10;
const BM1362_NONCE_RANGE_126: u32 = 0x0000_1381;
/// `0x70` PLL0 divider (Step 5).
const BM1362_REG_PLL0_DIVIDER: u8 = 0x70;
const BM1362_PLL0_DIVIDER_VALUE: u32 = 0x0000_0000;
/// `0x08` PLL0 param. The live trace's exact 525 MHz value is preserved when
/// 525 MHz is the target; other ramp steps use the canonical lookup table.
const BM1362_REG_PLL0_PARAM: u8 = 0x08;
const BM1362_PLL0_PARAM_525MHZ: u32 = 0x40A8_0265;
const BM1362_PLL_RAMP_START_MHZ: u16 = 400;
const BM1362_PLL_RAMP_STEP_MHZ: u16 = 25;
const BM1362_PLL_RAMP_SETTLE_MS: u64 = 100;
/// `0x14` TicketMask. The proven BM1362 serial path uses `0xFF` (accept 1/256).
const BM1362_REG_TICKET_MASK: u8 = 0x14;
const BM1362_TICKET_MASK_256: u32 = 0x0000_00FF;
const BM1362_SERIAL_PACE_MIN_MS: u64 = 20;
const BM1362_MAX_CHIPS_PER_CHAIN: usize = 255;
const BM1362_MISC_CONTROL_LEGACY_AMLOGIC: u32 = cold_boot_step::MISC_CONTROL_VALUE_POST_FAST_BAUD;

const ENV_AM3_BB_MINING_BAUD: &str = "DCENT_AM3_BB_MINING_BAUD";
const ENV_AM3_BB_FAST_UART_VALUE: &str = "DCENT_AM3_BB_FAST_UART_VALUE";
const ENV_AM3_BB_ENABLE_FAST_UART: &str = "DCENT_AM3_BB_ENABLE_FAST_UART";
const ENV_AM3_BB_SKIP_FAST_UART: &str = "DCENT_AM3_BB_SKIP_FAST_UART";
const ENV_AM3_BB_SKIP_UART_RELAY: &str = "DCENT_AM3_BB_SKIP_UART_RELAY";
const ENV_AM3_BB_LEGACY_AMLOGIC_INIT: &str = "DCENT_AM3_BB_LEGACY_AMLOGIC_INIT";
const ENV_AM3_BB_LEGACY_INIT_ORDER: &str = "DCENT_AM3_BB_LEGACY_INIT_ORDER";
const ENV_AM3_BB_SKIP_DSPIC_INIT: &str = "DCENT_AM3_BB_SKIP_DSPIC_INIT";
const ENV_AM3_BB_SKIP_DSPIC_SET_VOLTAGE: &str = "DCENT_AM3_BB_SKIP_DSPIC_SET_VOLTAGE";
const ENV_AM3_BB_SKIP_DSPIC_HEARTBEAT: &str = "DCENT_AM3_BB_SKIP_DSPIC_HEARTBEAT";
const ENV_AM3_BB_DSPIC_EARLY_ENABLE: &str = "DCENT_AM3_BB_DSPIC_EARLY_ENABLE";
const ENV_AM3_BB_DISABLE_HEARTBEAT_SUPERVISOR: &str = "DCENT_AM3_BB_DISABLE_HEARTBEAT_SUPERVISOR";
const ENV_AM3_BB_SKIP_THERMAL_SUPERVISOR: &str = "DCENT_AM3_BB_SKIP_THERMAL_SUPERVISOR";
// PR-021 lab escape hatch. SAFE direction only: setting this REVERTS to the
// pre-PR-021 behaviour (fan pinned at the quiet safe floor by the run guard,
// fail-closed supervisor still fully active). It can only DISABLE the new
// active cooling — it can never raise a cap or relax a fail-closed path. The
// fail-closed `Am3BbThermalSupervisor::poll_and_check` still runs regardless;
// this gate only parks the additive PID. Continuous PID is the DEFAULT.
const ENV_AM3_BB_DISABLE_FAN_PID: &str = "DCENT_AM3_BB_DISABLE_FAN_PID";
const ENV_AM3_BB_OPEN_CORE_MV: &str = "DCENT_AM3_BB_OPEN_CORE_MV";
const ENV_AM3_BB_OPEN_CORE_HOLD_MS: &str = "DCENT_AM3_BB_OPEN_CORE_HOLD_MS";
const ENV_AM3_BB_FAST_UART_SETTLE_MS: &str = "DCENT_AM3_BB_FAST_UART_SETTLE_MS";
const ENV_AM3_BB_FAST_GETADDR_DELAY_MS: &str = "DCENT_AM3_BB_FAST_GETADDR_DELAY_MS";
const ENV_AM3_BB_FAST_GETADDR_READ_MS: &str = "DCENT_AM3_BB_FAST_GETADDR_READ_MS";
const ENV_AM3_BB_SKIP_FAST_RELAY_AFTER_SWITCH: &str = "DCENT_AM3_BB_SKIP_FAST_RELAY_AFTER_SWITCH";
const ENV_AM3_BB_WRITE_PLL0_DIVIDER: &str = "DCENT_AM3_BB_WRITE_PLL0_DIVIDER";
const ENV_AM3_BB_USE_DEVMEM_UART: &str = "DCENT_AM3_BB_USE_DEVMEM_UART";
const ENV_AM3_BB_ALLOW_NO_RX_MINING: &str = "DCENT_AM3_BB_ALLOW_NO_RX_MINING";
const ENV_AM3_BB_ASSUME_JOB_RESPONSE_FLAGS: &str = "DCENT_AM3_BB_ASSUME_JOB_RESPONSE_FLAGS";
const ENV_AM3_BB_WORK_CODEC: &str = "DCENT_AM3_BB_WORK_CODEC";
const ENV_AM2_ACCEPT_DEGRADED_HARDWARE: &str = "DCENT_AM2_ACCEPT_DEGRADED_HARDWARE";

// AM3 BB hashboard-side dsPIC path. LuxOS ftrace on `a lab unit` (2026-05-13)
// shows firmware 0x89 controllers on I2C bus 0 using one full-frame write
// followed by one-byte reads. The EEPROM range on the same bus remains
// write-denied.
const AM3_BB_DSPIC_I2C_BUS: u8 = 0;
const AM3_BB_DSPIC_BASE_ADDR: u8 = 0x20;
const AM3_BB_DSPIC_HEARTBEAT_INTERVAL_MS: u64 = 1_000;
const AM3_BB_DSPIC_HEARTBEAT_READINESS_TIMEOUT_MS: u64 = 5_000;
const AM3_BB_DSPIC_HEARTBEAT_STOP_TIMEOUT_MS: u64 = 2_000;
const AM3_BB_DSPIC_POST_ENABLE_RESET_ASSERT_MS: u64 = 200;
const AM3_BB_DSPIC_POST_ENABLE_RESET_RELEASE_MS: u64 = 1_100;
const AM3_BB_DSPIC_INTER_CHAIN_RESET_MS: u64 = 10;
const AM3_BB_DSPIC_HEARTBEAT_MAX_FAILURES: u8 = 3;
const AM3_BB_DSPIC_MIN_VOLTAGE_MV: u16 = 11_940;
const AM3_BB_DSPIC_MAX_VOLTAGE_MV: u16 = 15_140;
const AM3_BB_DSPIC_DEFAULT_TARGET_MV: u16 = 13_700;
const AM3_BB_DSPIC_DEFAULT_OPEN_CORE_MV: u16 = 14_920;
const AM3_BB_DSPIC_DEFAULT_OPEN_CORE_HOLD_MS: u64 = 20_000;
const AM3_BB_FAN_SAFE_FLOOR_PWM: u8 = 10;
const AM3_BB_FAN_HARD_CAP_PWM: u8 = 30;
const AM3_BB_HASHBOARD_EEPROM_DENYLIST: [u8; 8] = [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57];
const AM3_BB_LM75_SENSOR_ADDRS: [u8; 4] = [0x48, 0x49, 0x4A, 0x4B];
/// A chain contributes fresh thermal proof only when at least one of its LM75
/// bridge reads decodes successfully. Requiring this independently for every
/// expected chain prevents a healthy board from masking a silent peer.
const AM3_BB_THERMAL_MIN_SAMPLES_PER_CHAIN: usize = 1;
const AM3_BB_LM75_REPLY_LEN: usize = 7;
const AM3_BB_LM75_MIN_VALID_C: f32 = -20.0;
const AM3_BB_LM75_MAX_VALID_C: f32 = 125.0;
/// `reply[5]` of a dsPIC LM75 bridge reply. Live `a lab unit` capture: `0x00` on every
/// good read, `0x01` on every bad one. See `am3_bb_decode_lm75_bridge_reply`.
const AM3_BB_LM75_STATUS_OK: u8 = 0x00;
/// The LM75 data register is 11-bit and left-justified, so a genuine reading
/// always has a zero low nibble. Non-zero means a framing/bus error, not a cold
/// sensor (ePIC `pic_driver.ko` returns `-EPROTO` on exactly this condition).
const AM3_BB_LM75_RAW_LOW_NIBBLE_MASK: i16 = 0x000F;
// Live `a lab unit` validation on 2026-05-13 showed the dsPIC LM75 bridge can return
// one malformed runtime poll while the pool/heartbeat path is active. Keep
// pre-start proof strict, but tolerate only a short fresh-sample window at
// runtime before cutting ASIC voltage.
const AM3_BB_THERMAL_RUNTIME_RETRY_MS: u64 = 100;
const AM3_BB_THERMAL_MAX_CONSECUTIVE_MISSES: u8 = 3;
const AM3_BB_THERMAL_MAX_STALE_MS: u64 = 15_000;
const AM3_BB_THERMAL_MIN_POLL_MS: u64 = 1_000;
// PR-021 continuous fan PID. Max single-tick PWM slew so the quiet home fan
// never audibly "jumps" — it walks toward the PID target a few PWM steps at a
// time. With AM3_BB_FAN_HARD_CAP_PWM=30 the whole legal band is 20 wide, so a
// 3-step ceiling reaches the cap in ~7 ticks (~14 s at the 2 s default) — fast
// enough for the 2-4 s BM1362 thermal time constant, slow enough to stay quiet.
const AM3_BB_FAN_PID_MAX_STEP_PWM: u8 = 3;
const AM3_BB_GPIO_SYSFS_ROOT: &str = "/sys/class/gpio";
const AM3_BB_WATCHDOG_BRINGUP_GRACE: Duration = Duration::from_secs(180);
const AM3_BB_API_MUTATION_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// Stratum cancellation is only one actor-close stage. It must not consume the
/// complete watchdog-issued cleanup window and starve API fencing, controller
/// safe-off, heartbeat join, or reset assertion.
const AM3_BB_STRATUM_STOP_TIMEOUT: Duration = Duration::from_secs(2);

fn am3_bb_thermal_poll_interval(pid_interval_s: f32) -> Duration {
    let millis =
        ((pid_interval_s.max(1.0) * 1000.0).round() as u64).max(AM3_BB_THERMAL_MIN_POLL_MS);
    Duration::from_millis(millis)
}

fn am3_bb_expected_safety_liveness_interval(pid_interval_s: f32) -> Duration {
    // Allow one bounded controller/I2C margin beyond the configured thermal
    // cadence. The watchdog derives its stall limit from this value, so a
    // legitimate slow policy does not look like a dead safety loop.
    am3_bb_thermal_poll_interval(pid_interval_s).saturating_add(Duration::from_secs(2))
}

#[cfg(test)]
const AM3_BB_DSPIC_RESET_FRAME: &[u8] = &[0x55, 0xAA, 0x04, 0x07, 0x00, 0x0B];
#[cfg(test)]
const AM3_BB_DSPIC_JUMP_FRAME: &[u8] = &[0x55, 0xAA, 0x04, 0x06, 0x00, 0x0A];
const AM3_BB_DSPIC_GET_VERSION_FRAME: &[u8] = &[0x55, 0xAA, 0x04, 0x17, 0x00, 0x1B];
#[cfg(test)]
const AM3_BB_DSPIC_DISABLE_FRAME: &[u8] = &[0x55, 0xAA, 0x05, 0x15, 0x00, 0x00, 0x1A];
const AM3_BB_DSPIC_ENABLE_FRAME: &[u8] = &[0x55, 0xAA, 0x05, 0x15, 0x01, 0x00, 0x1B];
const AM3_BB_DSPIC_HEARTBEAT_FRAME: &[u8] = &dcentrald_hal::bb_pic_heartbeat::REQUEST;
const AM3_BB_DSPIC_HEARTBEAT_REPLY_PAYLOAD: &[u8] = &[0x01, 0x00, 0x00];
const AM3_BB_DSPIC_PROBE_3B_48_FRAME: &[u8] = &[0x55, 0xAA, 0x06, 0x3B, 0x48, 0x00, 0x00, 0x89];
#[cfg(test)]
const AM3_BB_DSPIC_READ_VOLTAGE_FRAME: &[u8] = &dcentrald_hal::bb_pic_rail::READ_REQUEST;

// ===========================================================================
//  ChainUart adapter — DevmemUart -> Am335xUartTransport
// ===========================================================================

/// Adapter so [`Am335xUartTransport`] (which is HAL-free, requires a
/// [`ChainUart`]) can drive the HAL's [`DevmemUart`].
///
/// Lives in the daemon crate, which depends on both `dcentrald-asic` (the
/// transport) and `dcentrald-hal` (the UART). `dcentrald-asic` deliberately
/// does not name `DevmemUart` so the transport stays pure/host-testable
/// (same pattern as the `pic1704` sealed traits).
///
/// `DevmemUart::init()`/`open()` already programs `MCR=0x03` + `FCR=0x07`
/// — this adapter does NOT
/// re-derive that. `DevmemUart::write_bytes` / `read_bytes_timeout` both take
/// `&self` (the device is single-threaded by construction), so the inner
/// field doesn't need a `&mut` projection.
pub struct DevmemChainUart(pub DevmemUart);

impl ChainUart for DevmemChainUart {
    fn write_frame(&mut self, data: &[u8]) -> Result<(), UartTransportError> {
        self.0
            .write_bytes(data)
            .map_err(|_| UartTransportError::WriteFailed)
    }

    fn read_avail(&mut self, buf: &mut [u8]) -> usize {
        // Short timeout so the mining loop doesn't block — nonce frames
        // arrive asynchronously and the transport polls.
        self.0.read_bytes_timeout(buf, 5)
    }
}

pub enum Am3BbChainUart {
    Kernel(SerialChainBackend),
    Devmem(DevmemUart),
}

impl Am3BbChainUart {
    fn open(spec: &ChainUartSpec, baud: u32) -> Result<Self> {
        if env_flag_set(ENV_AM3_BB_USE_DEVMEM_UART) {
            warn!(
                env = ENV_AM3_BB_USE_DEVMEM_UART,
                device = %spec.device,
                "am3-bb: lab override active - using DevmemUart for chain UART mining"
            );
            return Ok(Self::Devmem(
                DevmemUart::open_no_unbind(&spec.device, baud).with_context(|| {
                    format!(
                        "am3-bb: DevmemUart::open_no_unbind({}, {}) failed",
                        spec.device, baud
                    )
                })?,
            ));
        }

        let serial =
            SerialChainBackend::open(spec.index, &spec.device, baud).with_context(|| {
                format!(
                    "am3-bb: SerialChainBackend::open({}, {}) failed",
                    spec.device, baud
                )
            })?;
        serial.set_vtime(0).with_context(|| {
            format!("am3-bb: set VTIME=0 on kernel UART {} failed", spec.device)
        })?;
        Ok(Self::Kernel(serial))
    }

    fn backend_name(&self) -> &'static str {
        match self {
            Self::Kernel(_) => "kernel",
            Self::Devmem(_) => "devmem",
        }
    }

    fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Self::Kernel(serial) => serial
                .write_raw_bytes(data)
                .context("am3-bb: kernel UART raw write failed"),
            Self::Devmem(uart) => uart
                .write_bytes(data)
                .context("am3-bb: devmem UART raw write failed"),
        }
    }

    fn read_bytes_timeout(&mut self, buf: &mut [u8], timeout_ms: u64) -> usize {
        match self {
            Self::Kernel(serial) => match serial.read_raw_bytes_timeout(buf, timeout_ms) {
                Ok(n) => n,
                Err(e) => {
                    warn!(error = %e, "am3-bb: kernel UART raw read failed");
                    0
                }
            },
            Self::Devmem(uart) => uart.read_bytes_timeout(buf, timeout_ms),
        }
    }

    fn set_baud(&mut self, baud: u32) -> Result<()> {
        match self {
            Self::Kernel(serial) => {
                serial.set_baud(baud)?;
                serial.set_vtime(0)?;
                Ok(())
            }
            Self::Devmem(uart) => uart.set_baud(baud).map_err(Into::into),
        }
    }

    fn drain_tx(&mut self) -> Result<()> {
        match self {
            Self::Kernel(serial) => serial
                .drain_tx()
                .context("am3-bb: kernel UART TX drain failed"),
            Self::Devmem(uart) => {
                uart.drain_tx();
                Ok(())
            }
        }
    }

    fn flush_io(&mut self) {
        match self {
            Self::Kernel(serial) => {
                if let Err(e) = serial.flush_io() {
                    warn!(error = %e, "am3-bb: kernel UART flush failed");
                }
            }
            Self::Devmem(uart) => uart.flush_io(),
        }
    }
}

impl ChainUart for Am3BbChainUart {
    fn write_frame(&mut self, data: &[u8]) -> Result<(), UartTransportError> {
        self.write_bytes(data)
            .map_err(|_| UartTransportError::WriteFailed)
    }

    fn read_avail(&mut self, buf: &mut [u8]) -> usize {
        self.read_bytes_timeout(buf, 5)
    }
}

// ===========================================================================
//  APW UART-tunnel bus — direct /dev/i2c-<psu_bus> backing
// ===========================================================================

/// [`ApwUartTunnelBus`] backed by a directly-opened `I2cBus` on the
/// board-target's PSU bus.
///
/// `dcentrald-hal`'s `I2cServiceApwBus` (the shared-service variant) is
/// `recovery-tool`-feature-gated, so the daemon constructs this lighter
/// direct-bus variant instead. On `a lab unit` (`S19J_IO_BOARD_V2_0`) this rides
/// the bit-banged i2c-gpio bus (bus 1, gpio4=SDA / gpio5=SCL) — the kernel's
/// i2c-gpio driver covers the slow bit-banged timing.
///
/// NOTE: this is the bring-up path. If/when `--am3-bb-mining` shares the
/// process-wide I²C service with a future thermal/EEPROM reader, switch to
/// `I2cServiceApwBus` (single-owner architecture) — but on the `a lab unit` board
/// nothing else touches the PSU bus, so a dedicated fd is fine for now.
struct DirectI2cApwBus {
    bus: dcentrald_hal::i2c::I2cBus,
    binding: BbPsuControllerBinding,
    terminal: Arc<AtomicBool>,
    on_writer_thread: Arc<AtomicUsize>,
}

impl ApwUartTunnelBus for DirectI2cApwBus {
    fn authorize_voltage_control(&mut self) -> dcentrald_hal::Result<()> {
        if self.bus.bus() != self.binding.bus() || self.terminal.load(Ordering::SeqCst) {
            return Err(dcentrald_hal::HalError::PsuUnsupported(
                "BB APW voltage owner is foreign or terminal".into(),
            ));
        }
        self.binding.revalidate()
    }
    // Two SEPARATE I²C transactions with the trait's default `delay()` sleep
    // in between — the APW needs ≥ ~400 ms to produce a reply, so a combined
    // repeated-START write-read reads all-`0xF5` (the original bring-up bug).
    fn write_frame(&mut self, addr: u8, frame: &[u8]) -> dcentrald_hal::Result<()> {
        if addr != dcentrald_hal::psu_apw_uart_tunnel::APW_UART_TUNNEL_I2C_ADDR {
            return Err(dcentrald_hal::HalError::PsuUnsupported(
                "BB APW foreign address".into(),
            ));
        }
        self.authorize_voltage_control()?;
        // The same publication serializes both GPIO ON and APW writes with
        // terminal cutoff. A cutoff racing this syscall re-cuts after it
        // retires; no protocol writer can later raise the upstream supply.
        let _publication = am3_bb_publish_psu_write(&self.terminal, &self.on_writer_thread)
            .map_err(|error| dcentrald_hal::HalError::PsuProtocolOwned(error.to_string()))?;
        self.bus.set_slave(addr)?;
        self.bus.write(frame)?;
        if self.terminal.load(Ordering::SeqCst) {
            return Err(dcentrald_hal::HalError::PsuUnsupported(
                "BB APW write raced terminal cutoff".into(),
            ));
        }
        Ok(())
    }

    fn read_reply(&mut self, addr: u8, read_len: usize) -> dcentrald_hal::Result<Vec<u8>> {
        self.bus.set_slave(addr)?;
        let mut buf = vec![0u8; read_len];
        self.bus.read(&mut buf)?;
        Ok(buf)
    }
}

fn am3_bb_publish_psu_write(
    terminal: &AtomicBool,
    writer: &Arc<AtomicUsize>,
) -> Result<Am3BbOnWriterPublication> {
    anyhow::ensure!(!terminal.load(Ordering::SeqCst), "BB PSU owner is terminal");
    writer
        .compare_exchange(
            0,
            am3_bb_current_thread_token(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .map_err(|_| anyhow::anyhow!("BB PSU writer already published"))?;
    let publication = Am3BbOnWriterPublication {
        writer_thread: Arc::clone(writer),
    };
    anyhow::ensure!(
        !terminal.load(Ordering::SeqCst),
        "BB PSU cutoff preceded protocol write"
    );
    Ok(publication)
}

/// The generic gate permits empty slots and more than one ASIC family. This
/// fixed BM1362 route energizes every configured chain. The collector below
/// retains each decoded standard 126-chip SKU; these four catalog aliases may
/// coexist because they share this route's geometry and controller recipe.
fn require_am3_bb_eeprom_family(
    probes: &[dcentrald_silicon_profiles::energize_gate::ChainProbe],
    chain_count: usize,
) -> Result<()> {
    use dcentrald_silicon_profiles::energize_gate::ChainProbe;
    use dcentrald_silicon_profiles::hashboards::Hashboard;

    anyhow::ensure!(
        (1..=3).contains(&chain_count) && probes.len() == chain_count,
        "BB fixed route requires one EEPROM observation per configured chain"
    );
    for (slot, probe) in probes.iter().enumerate() {
        anyhow::ensure!(
            matches!(probe, ChainProbe::Classified {
                chain_id,
                preamble: [0x04, 0x11],
                sku: Hashboard::Bhb42601 | Hashboard::Bhb42603
                    | Hashboard::Bhb42621 | Hashboard::Bhb42641,
            } if usize::from(*chain_id) == slot),
            "BB chain {slot} lacks the required BM1362 BHB42-family observation: {probe:?}"
        );
    }
    Ok(())
}

fn collect_am3_bb_eeprom_probes(
    bus: u8,
    chain_count: usize,
    expected_chips: usize,
    mut read: impl FnMut(usize) -> Result<Vec<u8>>,
) -> Result<Vec<dcentrald_silicon_profiles::energize_gate::ChainProbe>> {
    use dcentrald_api_types::deployed_eeprom::{
        decode_deployed_eeprom, DeployedIdentityProvenance,
    };
    use dcentrald_api_types::hashboard_eeprom::{corroborate_marking, MarkingCorroboration};
    use dcentrald_api_types::zhiju_eeprom::Crc5Check;
    use dcentrald_silicon_profiles::energize_gate::ChainProbe;
    use dcentrald_silicon_profiles::hashboards::Hashboard;
    anyhow::ensure!(
        bus == AM3_BB_DSPIC_I2C_BUS && (1..=3).contains(&chain_count),
        "BB identity requires the retained bus-0 hashboard service and 1..=3 chains"
    );
    let mut probes = Vec::with_capacity(chain_count);
    for slot in 0..chain_count {
        let bytes =
            read(slot).with_context(|| format!("BB bus-0 chain {slot} EEPROM read failed"))?;
        let identity = decode_deployed_eeprom(&bytes)
            .with_context(|| format!("BB chain {slot} factory identity decode failed"))?;
        anyhow::ensure!(
            identity.board_class == 4
                && identity.key_index == 1
                && identity.provenance == DeployedIdentityProvenance::DecryptedXxtea
                && identity.region_1_crc5 == Crc5Check::Match
                && identity.region_2_crc5 == Crc5Check::Match,
            "BB chain {slot} factory format or CRC mismatch"
        );
        let sku = match identity.board_name.as_str() {
            "BHB42601" => Hashboard::Bhb42601,
            "BHB42603" => Hashboard::Bhb42603,
            "BHB42621" => Hashboard::Bhb42621,
            "BHB42641" => Hashboard::Bhb42641,
            name => anyhow::bail!(
                "BB chain {slot} factory SKU {name} does not match this S19j Pro recipe"
            ),
        };
        anyhow::ensure!(
            usize::from(sku.catalog().chips_per_chain) == expected_chips,
            "BB chain {slot} factory geometry disagrees with configured chip count"
        );
        anyhow::ensure!(
            matches!(
                corroborate_marking(
                    dcentrald_common::AsicProtocolIdentity::Bm1362,
                    identity.chip_marking_family_letter(),
                ),
                MarkingCorroboration::Agrees
            ),
            "BB chain {slot} factory lot marking disagrees with BM1362"
        );
        probes.push(ChainProbe::Classified {
            chain_id: slot as u8,
            preamble: [4, 0x11],
            sku,
        });
    }
    require_am3_bb_eeprom_family(&probes, chain_count)?;
    Ok(probes)
}

fn read_am3_bb_eeprom_page(
    service: &I2cServiceHandle,
    slot: usize,
    deadline: Instant,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        service.bus() == AM3_BB_DSPIC_I2C_BUS && slot < 3,
        "BB EEPROM adapter/slot mismatch"
    );
    loop {
        match service.read_hashboard_eeprom_page_at(0x50 + slot as u8, deadline) {
            Ok(bytes) => return Ok(bytes),
            Err(dcentrald_hal::HalError::I2cEndpointNotReady { .. })
                if Instant::now() < deadline =>
            {
                std::thread::sleep(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(50)),
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
}

// ===========================================================================
//  Auto-detect
// ===========================================================================

/// Detect whether this unit is the AM335x BB `S19J_IO_BOARD_V2_0` carrier
/// (the `a lab unit`-class unit) so the daemon can auto-route to `--am3-bb-mining`
/// even without the explicit CLI flag.
///
/// Returns `true` when EITHER:
///  - `/etc/dcentos/board_target` reads `am3-bb-s19jpro`, OR
///  - `/proc/device-tree/compatible` contains `am335x` AND
///    `/proc/device-tree/model` contains `S19J_IO_BOARD` (LuxOS bring-up
///    unit before the DCENT_OS board-target file has been written).
pub fn auto_detect_am3_bb() -> bool {
    let Ok(marker) = read_active_board_target_name() else {
        return false;
    };
    let compatible = std::fs::read("/proc/device-tree/compatible").unwrap_or_default();
    let dt_model = std::fs::read("/proc/device-tree/model").unwrap_or_default();
    authorize_am3_bb_identity(marker.as_deref(), &compatible, &dt_model).is_ok()
}

/// Resolve the BM1362 chain geometry without manufacturing a default.
///
/// The exact AM3-BB identity gate authorizes the S19j Pro catalog entry. An
/// operator may override its per-chain count explicitly, but any explicit
/// model/chip-family declarations must agree with that hardware identity.
fn resolve_am3_bb_chips_per_chain(
    configured_model: Option<&str>,
    configured_chip_type: Option<&str>,
    configured_count: Option<u8>,
) -> Result<usize> {
    if let Some(chip_type) = configured_chip_type {
        if !chip_type.trim().eq_ignore_ascii_case("BM1362") {
            anyhow::bail!(
                "am3-bb: mining.serial_chip_type={chip_type:?} conflicts with the authorized BM1362 S19j Pro topology"
            );
        }
    }

    let catalog = if let Some(configured_model) = configured_model {
        let spec = model::lookup_model(configured_model).ok_or_else(|| {
            anyhow::anyhow!(
                "am3-bb: mining.model={configured_model:?} is not a supported catalog model"
            )
        })?;
        if spec.model_key != "s19jpro" || spec.chip_label != "BM1362" {
            anyhow::bail!(
                "am3-bb: mining.model={configured_model:?} resolves to {}/{} and conflicts with S19j Pro/BM1362",
                spec.model_key,
                spec.chip_label
            );
        }
        spec
    } else {
        model::lookup_model("s19jpro")
            .ok_or_else(|| anyhow::anyhow!("am3-bb: S19j Pro catalog geometry is unavailable"))?
    };

    if let Some(count) = configured_count {
        if count == 0 {
            anyhow::bail!("am3-bb: mining.serial_chip_count must be at least 1");
        }
        return Ok(usize::from(count));
    }

    catalog
        .chips_per_chain_hint
        .map(usize::from)
        .ok_or_else(|| anyhow::anyhow!("am3-bb: catalog has no S19j Pro chips-per-chain evidence"))
}

// ===========================================================================
//  Chain→tty derivation (pure helper — host-testable)
// ===========================================================================

/// Per-chain UART configuration derived from the board-target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainUartSpec {
    /// Logical chain index (`0..n`).
    pub index: u8,
    /// Device path (e.g. `/dev/ttyS1`).
    pub device: String,
}

fn tty_s_to_omap_alias(device: &str) -> Option<&'static str> {
    match device {
        "/dev/ttyS1" => Some("/dev/ttyO1"),
        "/dev/ttyS2" => Some("/dev/ttyO2"),
        "/dev/ttyS4" => Some("/dev/ttyO4"),
        "/dev/ttyS5" => Some("/dev/ttyO5"),
        _ => None,
    }
}

fn resolve_runtime_uart_device(device: &str) -> String {
    if Path::new(device).exists() {
        return device.to_string();
    }

    if let Some(alias) = tty_s_to_omap_alias(device) {
        if Path::new(alias).exists() {
            return alias.to_string();
        }
    }

    device.to_string()
}

/// Derive the chain→tty list from a [`BeagleBonePlatform`]'s board-target.
///
/// The enumeration order is the chain index order from the config. The live
/// LuxOS `a lab unit` proof uses `/dev/ttyS*`; older AM335x kernels expose the same
/// OMAP UARTs as `/dev/ttyO*`, so resolve that alias at runtime when needed.
pub fn chain_uart_specs(platform: &BeagleBonePlatform) -> Vec<ChainUartSpec> {
    platform
        .board_target()
        .uart
        .chains
        .iter()
        .map(|c| ChainUartSpec {
            index: c.index,
            device: resolve_runtime_uart_device(&c.device),
        })
        .collect()
}

// ===========================================================================
//  Entry point
// ===========================================================================

/// Run the AM335x BB S19j Pro (`--am3-bb-mining`) mining mode.
///
/// Signature mirrors the other mode entry points (`SerialMiner::new` etc.):
/// takes the loaded [`DcentraldConfig`] (owned) and a [`CancellationToken`]
/// for graceful shutdown.
///
/// Steps 1-7 in [`run_am3_bb_blocking`] are the cold-boot + chip-init
/// plumbing (historically exercised on `a lab unit`, current binary bench-pending);
/// step 8 is the Stratum mining loop
/// (Option B2 — reuses `dcentrald_stratum` + the `Am335xUartTransport`).
/// `DCENT_AM3_BB_STUB_LOOP=1` keeps the old logging-only stub instead.
/// Pre-energize ownership bundle shared by the AM3-BB engine and its API.
/// The immutable, read-only platform snapshot is captured first. Hardware
/// ownership is possible only after the SoC watchdog reports an initial kick.
/// The mutation gate is then the single API admission domain retained through
/// teardown.
struct Am3BbRouteReceipt {
    /// Fully normalized topology. The HAL constructor admits only the one
    /// exact S19J_IO_BOARD_V2_0 tuple and records its identity provenance.
    platform: BeagleBonePlatform,
}

impl Am3BbRouteReceipt {
    fn capture(identity: &crate::daemon_lifecycle::PlatformIdentitySnapshot) -> Result<Self> {
        if identity.board_target() != "am3-bb-s19jpro" {
            anyhow::bail!(
                "am3-bb: runtime admission snapshot names board target {:?}",
                identity.board_target()
            );
        }
        let platform = BeagleBonePlatform::new()
            .context("am3-bb: failed to capture admitted BeagleBone topology")?;
        if platform.board_target_name() != identity.board_target() {
            anyhow::bail!(
                "am3-bb: captured platform target {} contradicts startup snapshot {}",
                platform.board_target_name(),
                identity.board_target()
            );
        }
        info!(
            startup_identity_source = identity.board_target_source(),
            topology_identity_source = platform.identity_evidence().receipt_label(),
            "AM3_BB_TOPOLOGY_CAPTURE_RECEIPT schema=v3 run_pid={} board_target=am3-bb-s19jpro soc=am335x carrier=S19J_IO_BOARD_V2_0 asic=BM1362 asic_evidence=declared_runtime_composition topology_profile=s19j_io_board_v2_0_exact_v1 gpio_profile=legacy59_metadata-psu65_high-rst49_60_27_22-plug51_48_47_46-fantach7_20_110_112-led23_45 uart_profile=ttyS1_48022000-ttyS2_48024000-ttyS4_481a8000-3000000 i2c_profile=eeprom0_50_51_52-deny-psu1_10 cold_boot_profile=fixed_apw15120_runtime_owner_required-reset10_1100_retry1x2_200_100-fan10_30 identity_evidence={}",
            std::process::id(),
            platform.identity_evidence().receipt_label(),
        );
        Ok(Self { platform })
    }

    fn api_identity(&self) -> crate::runtime::api::AdmittedApiHardwareIdentity {
        let evidence_source = self.platform.identity_evidence().receipt_label();
        crate::runtime::api::AdmittedApiHardwareIdentity {
            control_board_label: "BeagleBone am3-bb-s19jpro".to_string(),
            chip_type_label: "BM1362".to_string(),
            identification: dcentrald_api::HardwareIdentification::from_evidence(
                vec![
                    dcentrald_api::HardwareIdentityEvidence::observed_control_board(format!(
                        "AM335x/S19J_IO_BOARD_V2_0/{evidence_source}"
                    )),
                    dcentrald_api::HardwareIdentityEvidence::declared_asic_board_target(
                        "am3-bb-s19jpro",
                        "BM1362",
                    ),
                ],
                Some(
                    "Exact AM335x carrier topology admitted; BM1362 is declared composition and chip population remains unproven"
                        .to_string(),
                ),
            ),
        }
    }

    fn publish_admission_receipt(&self) {
        info!(
            topology_identity_source = self.platform.identity_evidence().receipt_label(),
            "AM3_BB_ROUTE_ADMISSION_RECEIPT schema=v3 run_pid={} board_target=am3-bb-s19jpro soc=am335x carrier=S19J_IO_BOARD_V2_0 asic=BM1362 asic_evidence=declared_runtime_composition topology_profile=s19j_io_board_v2_0_exact_v1 gpio_profile=legacy59_metadata-psu65_high-rst49_60_27_22-plug51_48_47_46-fantach7_20_110_112-led23_45 uart_profile=ttyS1_48022000-ttyS2_48024000-ttyS4_481a8000-3000000 i2c_profile=eeprom0_50_51_52-deny-psu1_10 cold_boot_profile=fixed_apw15120_runtime_owner_required-reset10_1100_retry1x2_200_100-fan10_30 identity_evidence={}",
            std::process::id(),
            self.platform.identity_evidence().receipt_label(),
        );
    }
}

pub(crate) struct Am3BbSafetyAdmission {
    /// Immutable board-target topology captured while consuming the exact
    /// runtime-dispatch admission. The engine must never reread route files.
    route_receipt: Am3BbRouteReceipt,
    watchdog: SafetyWatchdogOwner,
    watchdog_route_scope: Am3BbWatchdogRouteScope,
    liveness: SafetyLiveness,
    hardware_mutation_owner: HardwareMutationGateOwner,
    never_energized: Am3BbNeverEnergized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Am3BbFailureDisposition {
    NoWatchdogOpened,
    NeverEnergizedClosed,
    TerminalSafeOffClosed,
    ResetPending,
}

#[derive(Debug)]
pub(crate) struct Am3BbLifecycleError {
    disposition: Am3BbFailureDisposition,
    source: anyhow::Error,
    closeout: Option<Am3BbFailureCloseout>,
}

impl Am3BbLifecycleError {
    fn no_watchdog_opened(source: anyhow::Error) -> Self {
        Self {
            disposition: Am3BbFailureDisposition::NoWatchdogOpened,
            source,
            closeout: None,
        }
    }

    fn never_energized_closed(
        source: anyhow::Error,
        closeout: Am3BbNeverEnergizedCloseout,
    ) -> Self {
        Self {
            disposition: Am3BbFailureDisposition::NeverEnergizedClosed,
            source,
            closeout: Some(Am3BbFailureCloseout::NeverEnergized(closeout)),
        }
    }

    fn terminal_safe_off_closed(
        source: anyhow::Error,
        closeout: Am3BbTerminalSafeOffCloseout,
    ) -> Self {
        Self {
            disposition: Am3BbFailureDisposition::TerminalSafeOffClosed,
            source,
            closeout: Some(Am3BbFailureCloseout::TerminalSafeOff(closeout)),
        }
    }

    fn reset_pending(source: anyhow::Error) -> Self {
        Self {
            disposition: Am3BbFailureDisposition::ResetPending,
            source,
            closeout: None,
        }
    }

    pub(crate) fn disposition(&self) -> Am3BbFailureDisposition {
        self.disposition
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Am3BbFailureDisposition,
        anyhow::Error,
        Option<Am3BbFailureCloseout>,
    ) {
        (self.disposition, self.source, self.closeout)
    }
}

impl std::fmt::Display for Am3BbLifecycleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:#}", self.source)
    }
}

impl std::error::Error for Am3BbLifecycleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl From<anyhow::Error> for Am3BbLifecycleError {
    fn from(source: anyhow::Error) -> Self {
        Self::reset_pending(source)
    }
}

#[derive(Debug)]
pub(crate) struct Am3BbNeverEnergizedCloseout {
    _api: HardwareMutationBarrierReceipt,
    _watchdog: WatchdogCloseoutReceipt,
}

/// Positive post-energization terminal authority. The opaque watchdog receipt
/// can be minted only after the AM3 manifest has consumed the API barriers,
/// exact heartbeat-roster join, controller-fabric transition, checked board
/// safe-off receipt, and matching absolute teardown authority, followed by a
/// successful magic-close write and watchdog-worker join.
#[derive(Debug)]
pub(crate) struct Am3BbTerminalSafeOffCloseout {
    _watchdog: WatchdogCloseoutReceipt,
}

/// Closeout evidence is state-specific so `main` cannot accidentally accept a
/// never-energized receipt for a post-energization failure (or vice versa).
#[derive(Debug)]
pub(crate) enum Am3BbFailureCloseout {
    NeverEnergized(Am3BbNeverEnergizedCloseout),
    TerminalSafeOff(Am3BbTerminalSafeOffCloseout),
}

impl Am3BbSafetyAdmission {
    pub(crate) async fn start(
        config: &DcentraldConfig,
        identity: &crate::daemon_lifecycle::PlatformIdentitySnapshot,
        runtime_dispatch_admission: crate::RuntimeDispatchAdmission,
    ) -> std::result::Result<Self, Am3BbLifecycleError> {
        let _asic_protocol_admission = runtime_dispatch_admission
            .require_asic_protocol(
                crate::RuntimeDispatchKind::Am3BeagleBone,
                "am3-bb-s19jpro",
                dcentrald_common::AsicProtocolIdentity::Bm1362,
            )
            .map_err(anyhow::Error::msg)
            .map_err(Am3BbLifecycleError::no_watchdog_opened)?;
        // Capture and normalize every mutating GPIO/UART/I2C/cold-boot field
        // once. The move-only receipt, not a target-name comparison, is the
        // route authority subsequently consumed by hardware and API state.
        let route_receipt = Am3BbRouteReceipt::capture(identity)
            .map_err(Am3BbLifecycleError::no_watchdog_opened)?;

        let liveness = SafetyLiveness::default();
        let expected_liveness =
            am3_bb_expected_safety_liveness_interval(config.thermal.pid_interval_s);
        let (mut watchdog, admission) = SafetyWatchdogOwner::start_before_energizing(
            &config.watchdog,
            AM3_BB_WATCHDOG_BRINGUP_GRACE,
            expected_liveness,
            liveness.clone(),
        )
        .await
        .map_err(anyhow::Error::new)
        .map_err(Am3BbLifecycleError::no_watchdog_opened)?;
        let receipt = match admission {
            WatchdogAdmission::Armed(receipt) => receipt,
            WatchdogAdmission::DisabledByConfiguration => {
                return Err(Am3BbLifecycleError::no_watchdog_opened(anyhow::anyhow!(
                    "am3-bb requires an armed SoC watchdog; watchdog is disabled by configuration"
                )))
            }
            WatchdogAdmission::UnavailableBeforeOpen { reason } => {
                return Err(Am3BbLifecycleError::no_watchdog_opened(anyhow::anyhow!(
                    "am3-bb watchdog was unavailable before opening a descriptor: {reason}"
                )))
            }
            WatchdogAdmission::OpenedOrOutcomeUnknown { reason } => {
                return Err(Am3BbLifecycleError::reset_pending(anyhow::anyhow!(
                    "am3-bb watchdog descriptor was opened or is outcome-unknown: {reason}"
                )))
            }
        };
        let watchdog_route_scope = watchdog.claim_am3_bb_route_scope()?;
        let never_energized = watchdog.issue_am3_bb_never_energized()?;
        route_receipt.publish_admission_receipt();
        info!(
            requested_timeout_s = receipt.requested_timeout_s,
            effective_timeout_s = receipt.effective_timeout_s,
            kick_interval_s = receipt.kick_interval_s,
            bringup_grace_s = AM3_BB_WATCHDOG_BRINGUP_GRACE.as_secs(),
            expected_liveness_ms = expected_liveness.as_millis(),
            "am3-bb: pre-energize watchdog ownership admitted"
        );
        let hardware_mutation_owner = HardwareMutationGateOwner::new_pending();
        Ok(Self {
            route_receipt,
            watchdog,
            watchdog_route_scope,
            liveness,
            hardware_mutation_owner,
            never_energized,
        })
    }

    pub(crate) fn hardware_mutation_gate(&self) -> HardwareMutationGate {
        self.hardware_mutation_owner.gate()
    }

    pub(crate) fn api_identity(&self) -> crate::runtime::api::AdmittedApiHardwareIdentity {
        self.route_receipt.api_identity()
    }

    pub(crate) async fn disarm_never_energized(self) -> Result<Am3BbNeverEnergizedCloseout> {
        let Self {
            mut watchdog,
            hardware_mutation_owner,
            never_energized,
            ..
        } = self;
        let api = hardware_mutation_owner
            .close_and_drain(Duration::ZERO)
            .context("am3-bb: pre-energization API mutation gate did not close")?;
        let watchdog = watchdog
            .disarm_am3_bb_never_energized(never_energized, DEFAULT_WATCHDOG_STOP_TIMEOUT)
            .await?;
        Ok(Am3BbNeverEnergizedCloseout {
            _api: api,
            _watchdog: watchdog,
        })
    }
}

pub async fn run_am3_bb_mining(
    config: DcentraldConfig,
    shutdown: CancellationToken,
    safety_admission: Am3BbSafetyAdmission,
    state_tx: watch::Sender<dcentrald_api::MinerState>,
) -> std::result::Result<(), Am3BbLifecycleError> {
    info!("Entering AM335x BB mining mode (--am3-bb-mining) — S19J_IO_BOARD_V2_0 / .79-class");

    if !config.mining_start_enabled()
        && dcentrald_common::lab_env::var_os("DCENT_AM3_BB_STUB_LOOP").is_none()
    {
        return match safety_admission.disarm_never_energized().await {
            Ok(closeout) => Err(Am3BbLifecycleError::never_energized_closed(
                anyhow::anyhow!(
                    "am3-bb: mining is disabled or no pool is configured; watchdog closed before hardware cold-boot"
                ),
                closeout,
            )),
            Err(error) => Err(Am3BbLifecycleError::reset_pending(error.context(
                "am3-bb: configuration refusal could not close the never-energized watchdog run",
            ))),
        };
    }

    // The cold-boot + chip-init is blocking device I/O (mmap UART, i2c-gpio
    // bus, ~seconds of sleeps); the mining loop is a blocking poll loop over
    // the transport. Run it on a blocking thread so we don't stall the tokio
    // reactor; the API/dashboard servers (spawned by main.rs before this is
    // called) keep ticking, and the `StratumRouter` runs on the captured
    // runtime handle (mpsc channels bridge the two).
    let rt_handle = tokio::runtime::Handle::current();
    let result = tokio::task::spawn_blocking(move || {
        run_am3_bb_blocking(config, shutdown, rt_handle, safety_admission, state_tx)
    })
    .await
    .map_err(|error| {
        Am3BbLifecycleError::reset_pending(
            anyhow::Error::new(error).context("am3-bb mining blocking task panicked"),
        )
    })?;
    result
}

/// The blocking body of [`run_am3_bb_mining`].
fn close_am3_bb_never_energized_after_error(
    rt_handle: &tokio::runtime::Handle,
    watchdog: SafetyWatchdogOwner,
    hardware_mutation_owner: HardwareMutationGateOwner,
    evidence: Am3BbNeverEnergized,
    primary: anyhow::Error,
) -> Am3BbLifecycleError {
    let api = match hardware_mutation_owner.close_and_drain(Duration::ZERO) {
        Ok(receipt) => receipt,
        Err(closeout) => {
            return Am3BbLifecycleError::reset_pending(anyhow::Error::new(closeout).context(
                format!("AM3-BB pre-energization API closeout failed after: {primary:#}"),
            ))
        }
    };
    match rt_handle
        .block_on(watchdog.disarm_am3_bb_never_energized(evidence, DEFAULT_WATCHDOG_STOP_TIMEOUT))
    {
        Ok(watchdog) => Am3BbLifecycleError::never_energized_closed(
            primary.context(
                "AM3-BB pre-energization failure closed the watchdog with positive evidence",
            ),
            Am3BbNeverEnergizedCloseout {
                _api: api,
                _watchdog: watchdog,
            },
        ),
        Err(closeout) => Am3BbLifecycleError::reset_pending(closeout.context(format!(
            "AM3-BB pre-energization watchdog closeout failed after: {primary:#}"
        ))),
    }
}

fn run_am3_bb_blocking(
    config: DcentraldConfig,
    shutdown: CancellationToken,
    rt_handle: tokio::runtime::Handle,
    safety_admission: Am3BbSafetyAdmission,
    state_tx: watch::Sender<dcentrald_api::MinerState>,
) -> std::result::Result<(), Am3BbLifecycleError> {
    // Declare the watchdog first so every later hardware owner drops before
    // its fail-closed owner on early-return paths.
    let Am3BbSafetyAdmission {
        route_receipt,
        mut watchdog,
        mut watchdog_route_scope,
        liveness: watchdog_liveness,
        hardware_mutation_owner,
        never_energized,
    } = safety_admission;
    let mut never_energized = Some(never_energized);
    let mut terminal_state = Am3BbTerminalStatePublisher::new(state_tx.clone());
    macro_rules! pre_energize_try {
        ($expression:expr) => {
            match $expression {
                Ok(value) => value,
                Err(error) => {
                    let evidence = match never_energized.take() {
                        Some(evidence) => evidence,
                        None => {
                            return Err(Am3BbLifecycleError::reset_pending(error.context(
                                "AM3-BB pre-energization close authority was already consumed",
                            )));
                        }
                    };
                    let lifecycle_error = close_am3_bb_never_energized_after_error(
                        &rt_handle,
                        watchdog,
                        hardware_mutation_owner,
                        evidence,
                        error.into(),
                    );
                    if lifecycle_error.disposition()
                        == Am3BbFailureDisposition::NeverEnergizedClosed
                    {
                        terminal_state.record_safe_off(true);
                    }
                    return Err(lifecycle_error);
                }
            }
        };
    }
    let platform = route_receipt.platform;
    let software_closeout_run =
        dcentrald_common::mutation_disposition::capture_software_closeout_run(
            platform.board_target_name(),
        );
    // Validate every operator assertion and resolve catalog-backed geometry
    // before the admitted platform can open any hardware owner.
    let expected_chips_per_chain = pre_energize_try!(resolve_am3_bb_chips_per_chain(
        config.mining.model.as_deref(),
        config.mining.serial_chip_type.as_deref(),
        config.mining.serial_chip_count,
    ));

    // Use the immutable platform topology from route admission. The separate
    // supply binding observes the actual kernel owner before any GPIO output.
    let bt = platform.board_target();
    let chain_specs = chain_uart_specs(&platform);
    let stub_loop = dcentrald_common::lab_env::var_os("DCENT_AM3_BB_STUB_LOOP").is_some();
    if !stub_loop {
        for forbidden_override in [
            ENV_AM3_BB_SKIP_DSPIC_INIT,
            ENV_AM3_BB_SKIP_DSPIC_SET_VOLTAGE,
            ENV_AM3_BB_SKIP_DSPIC_HEARTBEAT,
            ENV_AM3_BB_DSPIC_EARLY_ENABLE,
            ENV_AM3_BB_DISABLE_HEARTBEAT_SUPERVISOR,
            ENV_AM3_BB_SKIP_THERMAL_SUPERVISOR,
            ENV_AM3_BB_DISABLE_FAN_PID,
            ENV_AM3_BB_ALLOW_NO_RX_MINING,
            ENV_AM2_ACCEPT_DEGRADED_HARDWARE,
        ] {
            if forbidden_override_is_present(forbidden_override) {
                pre_energize_try!(Err(anyhow::anyhow!(
                    "am3-bb: watched Mining admission forbids safety override {forbidden_override}"
                )));
            }
        }
    }
    info!(
        board_target = %platform.board_target_name(),
        chain_count = bt.uart.chain_count,
        chains = ?chain_specs,
        psu_enable_gpio = dcentrald_hal::platform::beaglebone_psu::PSU_ENABLE_GPIO,
        asic_reset_gpios = ?platform.chain_reset_gpios_v2_0(),
        plug_detect_gpios = ?platform.chain_plug_gpios_v2_0(),
        eeprom_bus = platform.eeprom_i2c_bus(),
        psu_bus = platform.psu_i2c_bus(),
        psu_addr = format_args!("0x{:02X}", platform.psu_i2c_addr()),
        mining_baud = platform.mining_baud_v2_0(),
        voltage_controller = ?platform.voltage_controller(),
        "am3-bb: loaded board topology"
    );
    // Expected per-chain chip count comes from an explicit override or the
    // S19j Pro catalog. It is used for address assignment because the live
    // GetAddress response can be truncated before every chip is counted.
    let target_freq_mhz = config.mining.frequency_mhz.clamp(400, 597);
    info!(
        expected_chips_per_chain,
        configured_freq_mhz = config.mining.frequency_mhz,
        target_freq_mhz,
        "am3-bb: configured per-chain chip count"
    );
    if target_freq_mhz != config.mining.frequency_mhz {
        warn!(
            configured_freq_mhz = config.mining.frequency_mhz,
            clamped_freq_mhz = target_freq_mhz,
            "am3-bb: BM1362 PLL table only covers 400..=597 MHz; clamping configured frequency"
        );
    }

    // Arms a run-scope fail-closed guard before cold boot. Once GPIO ownership
    // begins, every return path should leave the board in a reversible bench
    // state: capped fans, ASIC resets asserted, and board-enable off. dsPIC
    // voltage disable is attached after the controllers initialize.
    let mut _run_safety_guard = Some(pre_energize_try!(Am3BbRunSafetyGuard::new(
        &platform,
        None,
        Vec::new(),
        chain_specs.len(),
        config.thermal.fan_min_pwm,
        config.thermal.fan_max_pwm,
    )));
    // Arm the crash-panic-hook teardown (panic="abort" bypasses the guard's Drop).
    // Done here, before board-enable is driven HIGH, so even a panic during
    // cold-boot cuts board power via main()'s panic hook. (wf_7c757213 safety audit.)
    let panic_board_cutoff = pre_energize_try!(_run_safety_guard
        .as_mut()
        .context("am3-bb: run safety guard disappeared before panic-hook arm")
        .and_then(Am3BbRunSafetyGuard::take_panic_board_cutoff));
    let panic_watchdog_feed_stop = watchdog.feed_stop_signal();
    pre_energize_try!(arm_am3_bb_teardown(
        &platform,
        chain_specs.len(),
        panic_board_cutoff,
        panic_watchdog_feed_stop,
    ));

    if shutdown.is_cancelled() {
        info!("am3-bb: shutdown requested before cold-boot — exiting cleanly");
        let evidence = never_energized
            .take()
            .context("am3-bb: missing never-energized close authority")?;
        let api = hardware_mutation_owner
            .close_and_drain(Duration::ZERO)
            .context("am3-bb: pre-cold-boot cancellation API gate did not close")?;
        let watchdog_closeout = rt_handle.block_on(
            watchdog.disarm_am3_bb_never_energized(evidence, DEFAULT_WATCHDOG_STOP_TIMEOUT),
        )?;
        terminal_state.finish_never_energized(Am3BbNeverEnergizedCloseout {
            _api: api,
            _watchdog: watchdog_closeout,
        });
        return Ok(());
    }

    // ── 2. Open the chain DevmemUarts (at 115200 for enumeration). ──
    //
    // `DevmemUart::open` looks the device up in the *active* UART MMIO table,
    // which defaults to Zynq (`/dev/ttyS1` → 0x4100_1000). On AM335x BB we MUST
    // select the AM335x table first (`/dev/ttyS1` → 0x4802_2000, the OMAP UART);
    // otherwise the mmap of /dev/mem hits the Zynq PL-UART address, which is an
    // unmapped region on AM335x → SIGBUS. The table is a process-wide OnceLock;
    // calling this once before any `DevmemUart::open` is the contract.
    pre_energize_try!(dcentrald_hal::serial::select_uart_table_am335x()
        .context("am3-bb: select AM335x OMAP UART MMIO table (must precede DevmemUart::open)"));
    let enum_baud = 115_200u32;
    if chain_specs.is_empty() {
        pre_energize_try!(Err(anyhow::anyhow!(
            "am3-bb: board-target declares zero chain UARTs - nothing to mine on"
        )));
    }
    let mut cold_boot_uarts: Vec<DevmemUart> = Vec::new();
    info!(
        chains = chain_specs.len(),
        "am3-bb: S19J_IO_BOARD_V2_0 cold-boot does not touch chain UARTs; skipping temporary DevmemUart opens"
    );
    if env_flag_set(ENV_AM3_BB_USE_DEVMEM_UART) {
        warn!(
            env = ENV_AM3_BB_USE_DEVMEM_UART,
            "am3-bb: lab override active - opening temporary DevmemUart handles for cold-boot shape check"
        );
        for spec in &chain_specs {
            let uart = pre_energize_try!(DevmemUart::open_no_unbind(&spec.device, enum_baud).with_context(|| {
            format!(
                "am3-bb: DevmemUart::open({}, {}) failed — is stock luxminer/cgminer still running? \
                 stop it first",
                spec.device, enum_baud
            )
        }));
            info!(device = %spec.device, baud = enum_baud, "am3-bb: temporary cold-boot UART opened");
            cold_boot_uarts.push(uart);
        }
        if cold_boot_uarts.is_empty() {
            pre_energize_try!(Err(anyhow::anyhow!(
                "am3-bb: board-target declares zero chain UARTs — nothing to mine on"
            )));
        }

        // ── 3. Build the APW121215f UART-tunnel PSU controller (bus 1 @ 0x10). ──
    }

    // The same protected bus-0 service owns identity admission and subsequent
    // dsPIC traffic. Never use the legacy sysfs probe's bus-1 fallback here:
    // that is the separate PSU adapter, not hashboard identity authority.
    let hashboard_i2c = pre_energize_try!(spawn_i2c_service_no_register_touch_with_denylist(
        AM3_BB_DSPIC_I2C_BUS,
        AM3_BB_HASHBOARD_EEPROM_DENYLIST.to_vec(),
    )
    .context("am3-bb: open protected bus-0 identity/dsPIC service"));

    let psu_bus_num = platform.psu_i2c_bus();
    let psu_addr = platform.psu_i2c_addr();
    let psu_i2c = pre_energize_try!(platform
        .open_i2c(psu_bus_num)
        .with_context(|| format!("am3-bb: open /dev/i2c-{} (PSU bus) failed", psu_bus_num)));
    let supply_owner = pre_energize_try!(_run_safety_guard
        .as_ref()
        .context("am3-bb: retained supply owner absent before APW construction"));
    let binding = pre_energize_try!(supply_owner
        .board_enable
        .psu_binding
        .as_ref()
        .context("am3-bb: exact supply controller was not observed"))
    .clone();
    let mut psu = ApwUartTunnel::new_at(
        DirectI2cApwBus {
            bus: psu_i2c,
            binding,
            terminal: Arc::clone(&supply_owner.board_enable.io.terminal),
            on_writer_thread: Arc::clone(&supply_owner.board_enable.io.on_writer_thread),
        },
        psu_addr,
    );
    info!(
        psu_bus = psu_bus_num,
        psu_addr = format_args!("0x{:02X}", psu_addr),
        "am3-bb: APW UART-tunnel PSU controller constructed"
    );

    // Exact smart-PSU control is required on this route. A telemetry PSU
    // override cannot bypass identity, controller ownership or acknowledgments.
    // Cold boot holds resets, validates APW0x76/FW0x17, asserts retained PSU65,
    // checks the source-selected fixed DAC0 and only then releases reset.
    // Observed hashboard-family admission precedes the new supply ON boundary.
    pre_energize_try!((|| -> Result<()> {
        {
            use crate::runtime::hardware_info::DEFAULT_EEPROM_READINESS_BUDGET_MS;
            use dcentrald_silicon_profiles::energize_gate::{
                accept_degraded_hardware_enabled, gate_chains_for_energize_with_opts,
                strict_sku_refuse_enabled,
            };

            let strict = strict_sku_refuse_enabled();
            let accept_degraded = accept_degraded_hardware_enabled();
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_millis(DEFAULT_EEPROM_READINESS_BUDGET_MS);
            let chain_count = chain_specs.len();
            let probes = collect_am3_bb_eeprom_probes(
                hashboard_i2c.bus(),
                chain_count,
                expected_chips_per_chain,
                |slot| read_am3_bb_eeprom_page(&hashboard_i2c, slot, deadline),
            )?;
            info!(
                strict,
                accept_degraded,
                probes = ?probes,
                "am3-bb: Phase 4b hashboard-SKU energize-gate probes"
            );
            // The held LuxOS startup reads identity before the supply initializer.
            // An absent identity may not become energization authority. The former
            // timeout skip also ran after cold boot and never proved this boundary.
            match gate_chains_for_energize_with_opts(&probes, strict, false) {
                Ok((bindings, telemetry)) => {
                    info!(
                        chains = bindings.len(),
                        bindings = ?bindings,
                        "am3-bb: Phase 4b energize gate ACCEPTED"
                    );
                    if !telemetry.is_empty() {
                        warn!(
                            reasons = %telemetry.summary(),
                            "am3-bb: [ENERGIZE-REFUSED telemetry-only — would refuse if DCENT_AM2_STRICT_SKU_REFUSE=1] {}",
                            telemetry.summary()
                        );
                    }
                }
                Err(refusal) => {
                    if accept_degraded {
                        warn!(
                            reasons = %refusal.summary(),
                            "am3-bb: [ENERGIZE-REFUSED but proceeding — DCENT_AM2_ACCEPT_DEGRADED_HARDWARE=1 lab override] {}",
                            refusal.summary()
                        );
                    } else {
                        tracing::error!(
                            reasons = %refusal.summary(),
                            "am3-bb: [ENERGIZE-REFUSED] {}",
                            refusal.summary()
                        );
                        return Err(anyhow::anyhow!(
                            "am3-bb hashboard-SKU energize gate refused: {}",
                            refusal.summary()
                        ));
                    }
                }
            }
        }

        Ok(())
    })());

    info!("am3-bb: starting cold-boot sequence (ColdBootOptsV2 from board-target)");
    let board_enable = pre_energize_try!(_run_safety_guard
        .as_mut()
        .context("am3-bb: retained board-enable owner disappeared before cold boot"))
    .board_enable_owner();
    let energizing_boundary = match never_energized.take() {
        Some(evidence) => evidence,
        None => {
            return Err(anyhow::anyhow!(
                "am3-bb: never-energized authority disappeared at the cold-boot boundary; watchdog reset pending"
            )
            .into())
        }
    };
    drop(energizing_boundary);
    platform
        .run_cold_boot(&mut psu, &mut cold_boot_uarts, board_enable)
        .context("am3-bb: cold-boot sequence failed")?;
    info!("am3-bb: cold-boot sequence returned OK");
    drop(cold_boot_uarts);
    info!("am3-bb: cold-boot complete with no temporary DevmemUart ownership");

    if shutdown.is_cancelled() {
        return Err(anyhow::anyhow!(
            "am3-bb: shutdown requested after cold-boot; safety guard will attempt cutoff during unwind; safe-off remains unproven and watchdog reset is pending"
        )
        .into());
    }

    // ── 5. Hashboard dsPIC init + heartbeat on I2C bus 0. ──
    //
    // The 2026-05-13 LuxOS ftrace disproved the earlier NoPic assumption for
    // `a lab unit`: LuxOS initializes fw=0x89 controllers at 0x20/0x21/0x22 before
    // BM1362 work starts. Keep EEPROM writes denied on 0x50..=0x57, replay the
    // traced app-mode sequence, and keep 1 Hz heartbeat replies drained while
    // mining.
    let mut dspic_heartbeat_guard: Option<Am3BbDspicHeartbeatGuard> = None;
    let mut dspic_i2c_main: Option<I2cServiceHandle> = None;
    let mut active_dspic_addrs: Vec<u8> = Vec::new();
    let dspic_target_voltage_mv = am3_bb_dspic_target_voltage_mv(config.mining.voltage_mv);
    if env_flag_set(ENV_AM3_BB_SKIP_DSPIC_INIT) {
        warn!(
            env = ENV_AM3_BB_SKIP_DSPIC_INIT,
            "am3-bb: lab override active — skipping hashboard dsPIC init/heartbeat"
        );
    } else {
        let dspic_i2c = hashboard_i2c.clone();
        info!(
            bus = AM3_BB_DSPIC_I2C_BUS,
            denylist = format_args!("{:02X?}", AM3_BB_HASHBOARD_EEPROM_DENYLIST),
            "am3-bb: hashboard dsPIC I2C service started"
        );

        let early_enable = env_flag_set(ENV_AM3_BB_DSPIC_EARLY_ENABLE);
        if early_enable {
            warn!(
                env = ENV_AM3_BB_DSPIC_EARLY_ENABLE,
                target_voltage_mv = dspic_target_voltage_mv,
                "am3-bb: lab override active - enabling dsPIC rail before BM1362 enumeration"
            );
        } else {
            info!(
                open_core_mv = AM3_BB_DSPIC_DEFAULT_OPEN_CORE_MV,
                steady_mv = dspic_target_voltage_mv,
                "am3-bb: LuxOS-style dsPIC sequence active - controller init now, rail enable after BM1362 chip init"
            );
        }
        let conservatively_owned_dspic_addrs = (0..chain_specs.len())
            .map(am3_bb_dspic_addr_for_chain)
            .collect::<Vec<_>>();
        if let Some(guard) = _run_safety_guard.as_mut() {
            // Take ownership before the first controller sequence. With the
            // installed early-enable policy, an enable can complete before a
            // later readback/heartbeat fails; that address must never vanish
            // from teardown merely because init did not return success.
            guard.set_dspic(dspic_i2c.clone(), conservatively_owned_dspic_addrs.clone());
        }
        active_dspic_addrs = am3_bb_dspic_init_all(
            &dspic_i2c,
            chain_specs.len(),
            dspic_target_voltage_mv,
            early_enable,
        );
        if active_dspic_addrs.is_empty() {
            return Err(anyhow::anyhow!(
                "am3-bb: no fw=0x89 hashboard dsPIC controllers initialized on bus {}",
                AM3_BB_DSPIC_I2C_BUS
            )
            .into());
        }
        if !stub_loop && active_dspic_addrs != conservatively_owned_dspic_addrs {
            return Err(anyhow::anyhow!(
                "am3-bb: non-stub mining requires exact dsPIC topology {:?}, observed {:?}; refusing partially owned hash power",
                conservatively_owned_dspic_addrs,
                active_dspic_addrs
            )
            .into());
        }
        info!(
            active_dspic_addrs = format_args!("{:02X?}", active_dspic_addrs),
            "am3-bb: hashboard dsPIC controllers initialized"
        );

        if let Some(guard) = _run_safety_guard.as_mut() {
            guard.set_dspic(dspic_i2c.clone(), active_dspic_addrs.clone());
        }

        if env_flag_set(ENV_AM3_BB_SKIP_DSPIC_HEARTBEAT) {
            warn!(
                env = ENV_AM3_BB_SKIP_DSPIC_HEARTBEAT,
                "am3-bb: lab override active — dsPIC runtime heartbeat thread disabled"
            );
        } else {
            let actor_owner = watchdog_route_scope.take_actor_owner()?;
            let heartbeat_board_cutoff = _run_safety_guard
                .as_mut()
                .context("am3-bb: run safety guard disappeared before heartbeat start")?
                .take_heartbeat_board_cutoff()?;
            let mut heartbeat_guard = start_am3_bb_dspic_heartbeat(
                actor_owner,
                dspic_i2c.clone(),
                active_dspic_addrs.clone(),
                shutdown.clone(),
                heartbeat_board_cutoff,
            )?;
            let readiness = heartbeat_guard
                .wait_for_verified_heartbeat_readiness(&shutdown)
                .context("am3-bb: dsPIC heartbeat readiness admission failed")?;
            info!(
                interval_ms = AM3_BB_DSPIC_HEARTBEAT_INTERVAL_MS,
                readiness_timeout_ms = AM3_BB_DSPIC_HEARTBEAT_READINESS_TIMEOUT_MS,
                validated_chains = readiness.validated_chains,
                "am3-bb: dsPIC runtime heartbeat owner established framed protocol readiness"
            );
            dspic_heartbeat_guard = Some(heartbeat_guard);
        }
        am3_bb_require_heartbeat_for_energizing_boundary(
            dspic_heartbeat_guard.as_mut(),
            &shutdown,
            !stub_loop,
            "post-dsPIC ASIC reset release",
        )?;
        am3_bb_post_dspic_reset_chains(&platform, chain_specs.len())
            .context("am3-bb: post-dsPIC ASIC reset pulse failed")?;
        dspic_i2c_main = Some(dspic_i2c);
    }

    if env_flag_set(ENV_AM3_BB_SKIP_THERMAL_SUPERVISOR) {
        warn!(
            env = ENV_AM3_BB_SKIP_THERMAL_SUPERVISOR,
            "am3-bb: lab override active - thermal preflight/supervisor disabled"
        );
    } else {
        let Some(dspic_i2c) = dspic_i2c_main.as_ref() else {
            return Err(anyhow::anyhow!(
                "am3-bb: dsPIC I2C service is unavailable; refusing to mine without thermal supervisor"
            )
            .into());
        };
        // Production requires one thermally covered dsPIC per declared
        // hash-chain. The enum-only stub may inspect a partial topology, but it
        // never enters watchdog Mining or opens hardware mutation admission.
        let expected_thermal_chains = if stub_loop {
            active_dspic_addrs.len()
        } else {
            chain_specs.len()
        };
        Am3BbThermalSupervisor::new(
            dspic_i2c.clone(),
            active_dspic_addrs.clone(),
            expected_thermal_chains,
            config.thermal.hot_temp_c,
            config.thermal.dangerous_temp_c,
        )?
        .poll_and_check("pre-chip-init")?;
    }

    if shutdown.is_cancelled() {
        return Err(anyhow::anyhow!(
            "am3-bb: shutdown requested after dsPIC init; safety guard will attempt cutoff during unwind; safe-off remains unproven and watchdog reset is pending"
        )
        .into());
    }

    // ── 6. BM1362 chip-side init per chain. ──
    //
    // Wire bytes are built with the `dcentrald_asic::bm1362` frame builders:
    // GetAddress @115200, ChainInactive + SetChipAddress, core/ticket/nonce
    // registers, PLL ramp, FastUART handoff, then per-chip mining-ready writes.
    // No open-core dummy work: BM1362 uses the register path, not the BM1387
    // dummy-work core gate.
    let mut mining_baud = platform.mining_baud_v2_0();
    if let Some(override_baud) = parse_env_u32(ENV_AM3_BB_MINING_BAUD) {
        warn!(
            env = ENV_AM3_BB_MINING_BAUD,
            default_baud = mining_baud,
            override_baud,
            "am3-bb: lab override for host mining baud is active"
        );
        mining_baud = override_baud;
    }

    let mut fast_uart_value = cold_boot_step::FAST_UART_CONFIG_VALUE;
    if let Some(override_fast_uart) = parse_env_u32(ENV_AM3_BB_FAST_UART_VALUE) {
        warn!(
            env = ENV_AM3_BB_FAST_UART_VALUE,
            default_fast_uart = format_args!("0x{:08X}", fast_uart_value),
            override_fast_uart = format_args!("0x{:08X}", override_fast_uart),
            "am3-bb: lab override for BM1362 FastUART register value is active"
        );
        fast_uart_value = override_fast_uart;
    }

    let enable_fast_uart = env_flag_set(ENV_AM3_BB_ENABLE_FAST_UART);
    if enable_fast_uart {
        warn!(
            env = ENV_AM3_BB_ENABLE_FAST_UART,
            "am3-bb: lab override active — enabling BM1362 FastUART handoff despite .79 live evidence"
        );
    } else {
        warn!(
            enable_env = ENV_AM3_BB_ENABLE_FAST_UART,
            skip_env = ENV_AM3_BB_SKIP_FAST_UART,
            "am3-bb: defaulting to 115200 mining; .79 live runs produced parsed nonce frames only when FastUART was skipped"
        );
    }

    let skip_fast_uart = !enable_fast_uart || env_flag_set(ENV_AM3_BB_SKIP_FAST_UART);
    if skip_fast_uart {
        warn!(
            env = ENV_AM3_BB_SKIP_FAST_UART,
            enable_env = ENV_AM3_BB_ENABLE_FAST_UART,
            "am3-bb: skipping BM1362 FastUART write and keeping chains at 115200"
        );
    }

    let mut uarts: Vec<Am3BbChainUart> = Vec::with_capacity(chain_specs.len());
    for spec in &chain_specs {
        let uart = Am3BbChainUart::open(spec, enum_baud)?;
        info!(
            chain = spec.index,
            device = %spec.device,
            baud = enum_baud,
            backend = uart.backend_name(),
            "am3-bb: mining chain UART opened"
        );
        uarts.push(uart);
    }
    if uarts.is_empty() {
        return Err(
            anyhow::anyhow!("am3-bb: board-target declares zero mining chain UARTs").into(),
        );
    }

    let mut total_chips: usize = 0;
    let mut init_results: Vec<Bm1362ChainInitResult> = Vec::with_capacity(uarts.len());
    for (idx, uart) in uarts.iter_mut().enumerate() {
        am3_bb_require_heartbeat_for_energizing_boundary(
            dspic_heartbeat_guard.as_mut(),
            &shutdown,
            !stub_loop,
            "BM1362 chain initialization",
        )?;
        let init = bm1362_chip_init_one_chain(
            uart,
            idx,
            mining_baud,
            fast_uart_value,
            skip_fast_uart,
            expected_chips_per_chain,
            target_freq_mhz,
            bt.cold_boot.run_miscctrl_triple_write,
        )
        .with_context(|| format!("am3-bb: BM1362 chip-init failed on chain {}", idx))?;
        am3_bb_require_heartbeat_for_energizing_boundary(
            dspic_heartbeat_guard.as_mut(),
            &shutdown,
            !stub_loop,
            "post-BM1362 chain initialization",
        )?;
        info!(
            chain = idx,
            chips = init.assigned_chips,
            initial_get_address_rx_bytes = init.initial_get_address_rx_bytes,
            fast_get_address_rx_bytes = init.fast_get_address_rx_bytes,
            initial_get_address_observation = ?init.initial_get_address_observation,
            fast_get_address_observation = ?init.fast_get_address_observation,
            rx_proven = init.rx_proven(),
            "am3-bb: BM1362 chip-init complete"
        );
        total_chips += init.assigned_chips;
        init_results.push(init);
    }
    let rx_proven_chains = init_results.iter().filter(|r| r.rx_proven()).count();
    let initial_rx_bytes: Vec<usize> = init_results
        .iter()
        .map(|r| r.initial_get_address_rx_bytes)
        .collect();
    let fast_rx_bytes: Vec<usize> = init_results
        .iter()
        .map(|r| r.fast_get_address_rx_bytes)
        .collect();
    let crc_verified_unassigned_observation_chains = init_results
        .iter()
        .filter(|result| {
            result.initial_get_address_observation.is_some()
                || result.fast_get_address_observation.is_some()
        })
        .count();
    let crc_verified_unassigned_response_frames: usize = init_results
        .iter()
        .filter_map(|result| {
            result
                .initial_get_address_observation
                .or(result.fast_get_address_observation)
        })
        .map(|observation| observation.response_frames)
        .sum();
    info!(
        chains = uarts.len(),
        assigned_chips_total = total_chips,
        rx_proven_chains,
        crc_verified_unassigned_observation_chains,
        crc_verified_unassigned_response_frames,
        initial_rx_bytes = ?initial_rx_bytes,
        fast_rx_bytes = ?fast_rx_bytes,
        "am3-bb: configured BM1362 address assignment complete; this is not measured unique-chip enumeration"
    );

    // ── 6. Build the work-dispatch transport over the per-chain UARTs. ──
    let allow_no_rx_mining = env_flag_set(ENV_AM3_BB_ALLOW_NO_RX_MINING);
    if rx_proven_chains == 0 && !stub_loop && !allow_no_rx_mining {
        return Err(anyhow::anyhow!(
            "am3-bb: refusing full mining because no BM1362 chain returned any UART bytes \
             during 115200 or fast-baud GetAddress probes (initial_rx_bytes={:?}, \
             fast_rx_bytes={:?}). Set {}=1 only for a bench override; remaining blocker is \
             pre-work BM1362 UART/RX liveness, not nonce parsing.",
            initial_rx_bytes,
            fast_rx_bytes,
            ENV_AM3_BB_ALLOW_NO_RX_MINING
        )
        .into());
    }
    if rx_proven_chains == 0 && allow_no_rx_mining {
        warn!(
            env = ENV_AM3_BB_ALLOW_NO_RX_MINING,
            initial_rx_bytes = ?initial_rx_bytes,
            fast_rx_bytes = ?fast_rx_bytes,
            "am3-bb: bench override active - dispatching work despite zero BM1362 RX proof"
        );
    }

    if let Some(dspic_i2c) = dspic_i2c_main.as_ref() {
        am3_bb_require_heartbeat_for_energizing_boundary(
            dspic_heartbeat_guard.as_mut(),
            &shutdown,
            !stub_loop,
            "dsPIC open-core voltage",
        )?;
        let open_core_mv = parse_env_u32(ENV_AM3_BB_OPEN_CORE_MV)
            .unwrap_or(u32::from(AM3_BB_DSPIC_DEFAULT_OPEN_CORE_MV))
            .clamp(
                u32::from(AM3_BB_DSPIC_MIN_VOLTAGE_MV),
                u32::from(AM3_BB_DSPIC_MAX_VOLTAGE_MV),
            ) as u16;
        let open_core_hold_ms = parse_env_u32(ENV_AM3_BB_OPEN_CORE_HOLD_MS)
            .map(u64::from)
            .unwrap_or(AM3_BB_DSPIC_DEFAULT_OPEN_CORE_HOLD_MS);
        info!(
            active_dspic_addrs = format_args!("{:02X?}", active_dspic_addrs),
            open_core_mv,
            open_core_hold_ms,
            steady_mv = dspic_target_voltage_mv,
            "am3-bb: starting LuxOS-style dsPIC open-core rail stage before work dispatch"
        );
        am3_bb_dspic_set_voltage_all(
            dspic_i2c,
            &active_dspic_addrs,
            dspic_heartbeat_guard.as_mut(),
            &shutdown,
            !stub_loop,
            open_core_mv,
            true,
            "open-core-voltage",
        )
        .context("am3-bb: dsPIC open-core rail stage failed")?;
        if open_core_hold_ms > 0 {
            am3_bb_wait_with_heartbeat_ownership(
                dspic_heartbeat_guard.as_mut(),
                &shutdown,
                !stub_loop,
                Duration::from_millis(open_core_hold_ms),
                "dsPIC open-core hold",
            )?;
        }
        am3_bb_require_heartbeat_for_energizing_boundary(
            dspic_heartbeat_guard.as_mut(),
            &shutdown,
            !stub_loop,
            "dsPIC steady voltage",
        )?;
        am3_bb_dspic_set_voltage_all(
            dspic_i2c,
            &active_dspic_addrs,
            dspic_heartbeat_guard.as_mut(),
            &shutdown,
            !stub_loop,
            dspic_target_voltage_mv,
            false,
            "steady-voltage",
        )
        .context("am3-bb: dsPIC steady rail stage failed")?;
        info!(
            steady_mv = dspic_target_voltage_mv,
            "am3-bb: dsPIC open-core -> steady rail sequence complete"
        );
    }

    drain_chain_uart_rx(&mut uarts, "pre-mining");

    let mut transport = Am335xUartTransport::new(uarts, UART_SEND_INTERVAL_US);
    info!(
        chains = transport.chain_count(),
        dispatch_interval_us = transport.dispatch_interval_us(),
        "am3-bb: Am335xUartTransport ready"
    );

    // Verify the fixed upstream supply after the independent dsPIC ramp.
    // Failure enters the existing terminal, checked power-first closeout.
    am3_bb_require_heartbeat_for_energizing_boundary(
        dspic_heartbeat_guard.as_mut(),
        &shutdown,
        !stub_loop,
        "APW fixed-supply verification",
    )?;
    psu.require_fixed_supply()
        .context("am3-bb: APW fixed supply readback failed after the dsPIC ramp")?;

    // ── 7b. Transfer the pre-energize watchdog owner into the mining loop.
    //       `Am3BbSafetyAdmission` armed and initially kicked `/dev/watchdog`
    //       before this engine or its Pending API mutation gate was constructed.
    //       There is no detached kicker here: the owned worker remains in
    //       Bringup until the thermal/fan/heartbeat/transport prerequisites below
    //       admit Mining, and it can disarm only through the receipt-bearing
    //       closeout funnel. ──
    // ── 8. Mining loop (Option B2 — reuse dcentrald_stratum + the transport).
    //       `DCENT_AM3_BB_STUB_LOOP=1` keeps the old logging-only stub for a
    //       cold-boot/enum-only diagnostic run. ──
    let (mining_result, mut stratum_tasks, stratum_ownership_result) = if stub_loop {
        warn!("am3-bb: DCENT_AM3_BB_STUB_LOOP set — running the cold-boot/enum-only logging stub, NOT the mining loop");
        run_mining_loop_stub(&mut transport, total_chips, &shutdown);
        (Ok(()), None, Ok(()))
    } else {
        // Borrow the run guard's clamp-enforced fan view for the continuous
        // PR-021 PID. The guard keeps ownership for the fail-closed teardown;
        // this is `None` if the BeagleBone PWM never opened (the PID then
        // simply doesn't run — the fail-closed supervisor still does).
        let run_guard = _run_safety_guard
            .as_mut()
            .context("am3-bb: run safety guard disappeared before mining loop")?;
        let pid_fan = run_guard.capped_fan();
        let mut runtime_cutoff = run_guard.runtime_cutoff();
        let heartbeat = dspic_heartbeat_guard
            .as_mut()
            .context("am3-bb: dsPIC heartbeat owner is missing before mining loop")?;
        match run_mining_loop(
            &config,
            &mut transport,
            total_chips,
            &shutdown,
            heartbeat,
            &rt_handle,
            dspic_i2c_main.clone(),
            active_dspic_addrs.clone(),
            pid_fan,
            &mut watchdog,
            watchdog_liveness,
            &hardware_mutation_owner,
            &mut runtime_cutoff,
            state_tx.clone(),
        ) {
            Ok(exit) => (exit.mining_result, Some(exit.stratum_tasks), Ok(())),
            Err(error) => (
                Err(error.into_source().context(
                    "am3-bb: mining loop admission failed before any Stratum task was spawned",
                )),
                None,
                Ok(()),
            ),
        }
    };

    // Every mining-loop exit after asynchronous ownership transfers enters this
    // bounded closeout, as does mining-loop admission failure before Stratum
    // ownership starts. Earlier post-energization bring-up failures retain the
    // fail-closed guard and leave watchdog reset pending. A missing closeout
    // prerequisite prevents Disarm submission and leaves the watchdog armed.
    // Once Disarm is submitted, timeout means the magic-close outcome is
    // unknown; a later join error may follow a completed magic-close and must
    // not be collapsed into an "armed" claim.
    let revoked_api_commit_fence = hardware_mutation_owner.revoke_commit_fence();
    let teardown_request = watchdog
        .request_teardown_budget()
        .context("am3-bb: watchdog could not issue its one-shot teardown budget")?;
    let (teardown_budget, pending_watchdog_teardown_admission) = teardown_request.into_parts();
    let teardown_view = teardown_budget.view();
    // Publish the independent heartbeat worker's stop before the first physical
    // cutoff can block. Its bounded join remains later on the shared absolute
    // teardown deadline so requesting cancellation cannot spend cleanup budget.
    let heartbeat_feeder_owner = dspic_heartbeat_guard
        .as_ref()
        .context("am3-bb: dsPIC heartbeat owner is missing before teardown cutoff")?;
    heartbeat_feeder_owner.request_stop();
    // PSU GPIO65 is the load-bearing physical cut. New API commits were revoked
    // synchronously above and the watchdog deadline/command are published;
    // perform the checked OFF write before waiting for the actor acknowledgement
    // or spending cleanup time on leases, controllers, actors, or reset sysfs.
    let board_cutoff_result = _run_safety_guard
        .as_mut()
        .context("am3-bb: run safety guard is missing before early board cutoff")?
        .cut_board_enable_checked(teardown_view.clone());
    if let Err(error) = &board_cutoff_result {
        warn!(
            %error,
            "am3-bb: early checked board-enable cutoff failed; defense-in-depth teardown will continue and watchdog Disarm is forbidden"
        );
    }
    if let Some(tasks) = stratum_tasks.as_ref() {
        tasks.request_stop();
    }
    terminal_state.begin_stopping();
    let watchdog_teardown_admission_result = rt_handle.block_on(
        watchdog.observe_teardown_admission(pending_watchdog_teardown_admission, &teardown_view),
    );
    if let Err(error) = &watchdog_teardown_admission_result {
        warn!(
            %error,
            "am3-bb: watchdog Teardown acknowledgement failed after local deadline publication and immediate board cutoff; defense-in-depth teardown will continue with Disarm forbidden"
        );
    }
    let api_drain_deadline = am3_bb_capped_cleanup_deadline(
        teardown_view.deadline(TeardownStage::CleanupComplete),
        Instant::now(),
        AM3_BB_API_MUTATION_DRAIN_TIMEOUT,
    );
    let api_barrier_result = hardware_mutation_owner
        .close_and_drain_until(api_drain_deadline)
        .context("am3-bb: API mutation admission did not drain before its absolute deadline");
    if let Err(error) = &api_barrier_result {
        warn!(
            %error,
            "am3-bb: API mutation drain lacked positive evidence; explicit controller and board safe-off will continue with watchdog disarm forbidden"
        );
    }
    let api_commit_fence_result = match revoked_api_commit_fence.try_wait() {
        HardwareMutationCommitFenceTryWait::Fenced(receipt) if receipt.fence_poisoned() => {
            Err(anyhow::anyhow!(
                "am3-bb: API commit fence is quiescent but poisoned by an unwound mutation"
            ))
        }
        HardwareMutationCommitFenceTryWait::Fenced(receipt) => Ok(receipt),
        HardwareMutationCommitFenceTryWait::Pending(_) => Err(anyhow::anyhow!(
            "am3-bb: API commit fence remained busy after the bounded mutation drain"
        )),
    };
    match &api_commit_fence_result {
        Ok(receipt) => info!(
            closed_generation = receipt.closed_generation(),
            fence_poisoned = receipt.fence_poisoned(),
            "am3-bb: fenced every entered API hardware commit before terminal controller safe-off"
        ),
        Err(error) => warn!(
            %error,
            "am3-bb: API final-commit fence lacked clean evidence; explicit controller and board safe-off will continue with watchdog disarm forbidden"
        ),
    }
    let dspic_i2c = dspic_i2c_main
        .as_ref()
        .context("am3-bb: dsPIC I2C ownership is missing at teardown")?;
    let pre_quiescence_i2c_barrier = dspic_i2c.latch_terminal_safe_off();
    info!(
        safety_generation = pre_quiescence_i2c_barrier.generation(),
        no_controller_mutation_stage_in_flight =
            pre_quiescence_i2c_barrier.no_controller_mutation_stage_in_flight(),
        "am3-bb: terminal I2C admission latched before actor shutdown"
    );

    let heartbeat_stop_deadline = am3_bb_capped_cleanup_deadline(
        teardown_view.deadline(TeardownStage::CleanupComplete),
        Instant::now(),
        Duration::from_millis(AM3_BB_DSPIC_HEARTBEAT_STOP_TIMEOUT_MS),
    );
    let heartbeat_shutdown = dspic_heartbeat_guard
        .as_mut()
        .context("am3-bb: dsPIC heartbeat owner is missing at teardown")?
        .stop_and_join_until(&rt_handle, heartbeat_stop_deadline);
    if !heartbeat_shutdown.graceful() {
        let evidence = heartbeat_shutdown;
        if evidence.worker_timed_out {
            let guard = _run_safety_guard
                .as_mut()
                .expect("AM3 run safety guard remains armed through shutdown");
            // A timed-out feeder may still own or await the shared I2C service.
            // The out-of-band board-enable cutoff above is the terminal safety
            // action; do not re-enter that shared controller during teardown.
            guard.dspic_i2c = None;
            guard.active_dspic_addrs.clear();
        }
        let heartbeat_error = anyhow::anyhow!(
            "am3-bb: dsPIC heartbeat shutdown was degraded; worker_timed_out={}, worker_panicked={}, timeout_ms={}, hard_board_cut_attempted={}, hard_board_cut_succeeded={}",
            evidence.worker_timed_out,
            evidence.worker_panicked,
            AM3_BB_DSPIC_HEARTBEAT_STOP_TIMEOUT_MS,
            evidence.hard_board_cut_attempted,
            evidence.hard_board_cut_succeeded
        );
        return match mining_result {
            Ok(()) => Err(heartbeat_error.into()),
            Err(mining_error) => Err(heartbeat_error
                .context(format!("mining loop also failed: {mining_error:#}"))
                .into()),
        };
    }
    let i2c_barrier = dspic_i2c.latch_terminal_safe_off();
    info!(
        safety_generation = i2c_barrier.generation(),
        no_controller_mutation_stage_in_flight =
            i2c_barrier.no_controller_mutation_stage_in_flight(),
        "am3-bb: terminal I2C mutation barrier observed after actor shutdown"
    );
    let safe_off = _run_safety_guard
        .as_mut()
        .context("am3-bb: run safety guard is missing at teardown")?
        .teardown_checked(board_cutoff_result.ok(), teardown_view.clone())?;
    terminal_state.record_safe_off(mining_result.is_err());
    // Stratum cancellation was published immediately after the load-bearing
    // PSU GPIO65 cut. Spend its bounded join budget only after controller actors
    // are quiescent and checked hardware safe-off is proven, so a wedged pool
    // task can never consume the physical-safety portion of the deadline.
    let stratum_join_deadline = am3_bb_capped_cleanup_deadline(
        teardown_view.deadline(TeardownStage::CleanupComplete),
        Instant::now(),
        AM3_BB_STRATUM_STOP_TIMEOUT,
    );
    let stratum_tasks_result = match (stratum_tasks.as_mut(), stratum_ownership_result) {
        (Some(tasks), Ok(())) => tasks.stop_and_join(stratum_join_deadline),
        (None, Err(error)) => Err(error),
        (None, Ok(())) => Ok(()),
        (Some(_), Err(error)) => Err(error.context(
            "am3-bb: contradictory Stratum task ownership result forbids watchdog Disarm",
        )),
    };
    if let Err(error) = &stratum_tasks_result {
        warn!(
            %error,
            "am3-bb: Stratum cancellation/join lacked positive evidence after checked safe-off; watchdog Disarm is forbidden"
        );
    }
    watchdog_teardown_admission_result.map_err(anyhow::Error::msg)?;
    let api_barrier = api_barrier_result?;
    let api_commit_fence = api_commit_fence_result?;
    stratum_tasks_result?;
    let teardown_disarm = teardown_budget.begin_disarm_at(Instant::now())?;
    let manifest = Am3BbWatchdogShutdownManifest::new(
        watchdog_route_scope,
        api_barrier,
        api_commit_fence,
        i2c_barrier,
        heartbeat_shutdown
            .into_actor_receipt()
            .context("am3-bb: exact dsPIC heartbeat roster lacked clean terminal authority")?,
        safe_off,
        teardown_disarm,
    );
    let permit = WatchdogDisarmPermit::from_am3_bb_manifest(manifest)?;
    let watchdog_closeout =
        rt_handle.block_on(watchdog.disarm_and_join(permit, DEFAULT_WATCHDOG_STOP_TIMEOUT))?;
    let terminal_closeout = Am3BbTerminalSafeOffCloseout {
        _watchdog: watchdog_closeout,
    };

    if let Err(mining_error) = mining_result {
        return Err(Am3BbLifecycleError::terminal_safe_off_closed(
            mining_error.context(
                "am3-bb: post-energization failure completed checked safe-off and watchdog closeout",
            ),
            terminal_closeout,
        ));
    }

    crate::daemon::publish_orderly_software_closeout(
        software_closeout_run,
        &terminal_closeout._watchdog,
    )?;
    terminal_state.finish_stopped();
    info!("am3-bb: mining mode stopped with complete shutdown evidence");
    Ok(())
}

fn bm1362_command_wire_frame(frame_without_preamble: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(BM13XX_CMD_PREAMBLE.len() + frame_without_preamble.len());
    wire.extend_from_slice(&BM13XX_CMD_PREAMBLE);
    wire.extend_from_slice(frame_without_preamble);
    wire
}

fn bm1362_write_cmd_frame(uart: &mut Am3BbChainUart, frame_without_preamble: &[u8]) -> Result<()> {
    let wire = bm1362_command_wire_frame(frame_without_preamble);
    uart.write_bytes(&wire)
}

fn drain_chain_uart_rx(uarts: &mut [Am3BbChainUart], stage: &'static str) {
    const MAX_DRAIN_READS: usize = 12;
    let mut buf = [0u8; 512];
    for (chain_idx, uart) in uarts.iter_mut().enumerate() {
        if let Err(e) = uart.drain_tx() {
            warn!(
                chain = chain_idx,
                stage,
                error = %e,
                "am3-bb: UART TX drain failed before RX cleanup"
            );
        }

        let mut total = 0usize;
        let mut preview = Vec::with_capacity(96);
        for _ in 0..MAX_DRAIN_READS {
            let n = uart.read_bytes_timeout(&mut buf, 10);
            if n == 0 {
                break;
            }
            let n = n.min(buf.len());
            let take = (96usize.saturating_sub(preview.len())).min(n);
            preview.extend_from_slice(&buf[..take]);
            total += n;
        }
        uart.flush_io();

        if total > 0 {
            warn!(
                chain = chain_idx,
                stage,
                drained_rx_bytes = total,
                rx_preview = %hex_preview(&preview, 96),
                "am3-bb: drained residual BM1362 RX before mining transport handoff"
            );
        } else {
            debug!(
                chain = chain_idx,
                stage, "am3-bb: no residual BM1362 RX before mining transport handoff"
            );
        }
    }
}

/// One BM1362 broadcast register write (`build_broadcast_write_frame`, HDR=0x51)
/// + a short pace gap. Free fn (not a closure) so the `&mut Am3BbChainUart` borrow
/// is per-call — `bm1362_chip_init_one_chain` interleaves these with direct
/// `uart.write_bytes` calls (ChainInactive / SetChipAddress).
fn bm1362_bcast(
    uart: &mut Am3BbChainUart,
    chain_idx: usize,
    reg: u8,
    val: u32,
    ms: u64,
    what: &str,
) -> Result<()> {
    bm1362_write_cmd_frame(uart, &build_broadcast_write_frame(reg, val))
        .with_context(|| format!("am3-bb chain {}: {} write failed", chain_idx, what))?;
    if ms > 0 {
        std::thread::sleep(Duration::from_millis(ms));
    }
    Ok(())
}

/// One BM1362 per-chip register write (`build_single_write_frame`, HDR=0x41)
/// + optional pace gap.
fn bm1362_single(
    uart: &mut Am3BbChainUart,
    chain_idx: usize,
    chip_addr: u8,
    reg: u8,
    val: u32,
    ms: u64,
    what: &str,
) -> Result<()> {
    bm1362_write_cmd_frame(uart, &build_single_write_frame(chip_addr, reg, val)).with_context(
        || {
            format!(
                "am3-bb chain {} chip 0x{:02X}: {} write failed",
                chain_idx, chip_addr, what
            )
        },
    )?;
    if ms > 0 {
        std::thread::sleep(Duration::from_millis(ms));
    }
    Ok(())
}

/// MiscCtrl per-chip triple-write cadence: pure `plan_misc_ctrl_triple_write_chip`.
/// Value + label remain engine policy; reg must stay `MISC_CONTROL_REG` (0x18).
fn bm1362_miscctrl_triple_write_single(
    uart: &mut Am3BbChainUart,
    chain_idx: usize,
    chip_addr: u8,
    value: u32,
    what: &str,
) -> Result<()> {
    debug_assert_eq!(
        cold_boot_step::MISC_CONTROL_REG,
        dcentrald_common::MISC_CTRL_REG_BM1397PLUS
    );
    for op in dcentrald_common::plan_misc_ctrl_triple_write_chip(chip_addr, value) {
        match op {
            dcentrald_common::TransportOp::SendWriteRegBm1397Plus {
                chip_addr: addr,
                reg,
                value: v,
            } => {
                // Sleep is owned by pure DelayMs ops below (ms=0 here).
                bm1362_single(uart, chain_idx, addr, reg, v, 0, what)?;
            }
            dcentrald_common::TransportOp::DelayMs { ms } => {
                if ms > 0 {
                    std::thread::sleep(Duration::from_millis(u64::from(ms)));
                }
            }
            _ => {
                // Pure plan only emits per-chip write + delay.
            }
        }
    }
    Ok(())
}

/// MiscCtrl broadcast triple-write cadence: pure `plan_misc_ctrl_triple_write_broadcast`.
fn bm1362_miscctrl_triple_write_bcast(
    uart: &mut Am3BbChainUart,
    chain_idx: usize,
    value: u32,
    what: &str,
) -> Result<()> {
    debug_assert_eq!(
        cold_boot_step::MISC_CONTROL_REG,
        dcentrald_common::MISC_CTRL_REG_BM1397PLUS
    );
    for op in dcentrald_common::plan_misc_ctrl_triple_write_broadcast(value) {
        match op {
            dcentrald_common::TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value: v } => {
                bm1362_bcast(uart, chain_idx, reg, v, 0, what)?;
            }
            dcentrald_common::TransportOp::DelayMs { ms } => {
                if ms > 0 {
                    std::thread::sleep(Duration::from_millis(u64::from(ms)));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Write the BM1362 ASIC UART_RELAY block that W13 reclassified as the real
/// nonce RX/TX relay control surface. This is ASIC register traffic over the
/// hash chain, not a Braiins FPGA mirror write.
fn bm1362_uart_relay_bcast(
    uart: &mut Am3BbChainUart,
    chain_idx: usize,
    stage: &'static str,
) -> Result<()> {
    if env_flag_set(ENV_AM3_BB_SKIP_UART_RELAY) {
        warn!(
            chain = chain_idx,
            stage, "am3-bb: lab override active — skipping BM1362 UART_RELAY 0x2C/0x34 broadcasts"
        );
        return Ok(());
    }

    bm1362_bcast(
        uart,
        chain_idx,
        UART_RELAY_REG_ADDR,
        UART_RELAY_BOSMINER_ENABLE,
        10,
        "UART_RELAY(0x2C)",
    )?;
    bm1362_bcast(
        uart,
        chain_idx,
        UART_RELAY_ALT_REG_ADDR,
        UART_RELAY_BOSMINER_ENABLE_ALT,
        10,
        "UART_RELAY_ALT(0x34)",
    )?;
    info!(
        chain = chain_idx,
        stage,
        reg_0x2c = format_args!("0x{:08X}", UART_RELAY_BOSMINER_ENABLE),
        reg_0x34 = format_args!("0x{:08X}", UART_RELAY_BOSMINER_ENABLE_ALT),
        "am3-bb: BM1362 UART_RELAY broadcasts applied"
    );
    Ok(())
}

fn bm1362_uart_relay_single(
    uart: &mut Am3BbChainUart,
    chain_idx: usize,
    chip_addr: u8,
    stage: &'static str,
) -> Result<()> {
    if env_flag_set(ENV_AM3_BB_SKIP_UART_RELAY) {
        return Ok(());
    }

    bm1362_single(
        uart,
        chain_idx,
        chip_addr,
        UART_RELAY_REG_ADDR,
        UART_RELAY_BOSMINER_ENABLE,
        0,
        "UART_RELAY(0x2C) per-chip",
    )?;
    bm1362_single(
        uart,
        chain_idx,
        chip_addr,
        UART_RELAY_ALT_REG_ADDR,
        UART_RELAY_BOSMINER_ENABLE_ALT,
        0,
        "UART_RELAY_ALT(0x34) per-chip",
    )?;
    debug!(
        chain = chain_idx,
        chip_addr = format_args!("0x{:02X}", chip_addr),
        stage,
        reg_0x2c = format_args!("0x{:08X}", UART_RELAY_BOSMINER_ENABLE),
        reg_0x34 = format_args!("0x{:08X}", UART_RELAY_BOSMINER_ENABLE_ALT),
        "am3-bb: BM1362 UART_RELAY per-chip writes applied"
    );
    Ok(())
}

fn bm1362_per_chip_init_loop(
    uart: &mut Am3BbChainUart,
    chain_idx: usize,
    n_assign: usize,
    addr_interval: u16,
    init_values: Bm1362Am3InitValues,
    run_miscctrl_triple_write: bool,
    stage: &'static str,
) -> Result<()> {
    info!(
        chain = chain_idx,
        chips = n_assign,
        addr_interval,
        stage,
        "am3-bb: BM1362 per-chip init starting"
    );
    for i in 0..n_assign {
        let chip_addr = (i as u16 * addr_interval) as u8;
        bm1362_single(
            uart,
            chain_idx,
            chip_addr,
            BM1362_REG_INIT_CONTROL,
            init_values.init_control_per_chip,
            0,
            "InitControl(0xA8) per-chip",
        )?;
        if run_miscctrl_triple_write {
            bm1362_miscctrl_triple_write_single(
                uart,
                chain_idx,
                chip_addr,
                init_values.misc_control_pre_baud,
                "MiscCtrl(0x18) per-chip pre-baud",
            )?;
        }
        bm1362_single(
            uart,
            chain_idx,
            chip_addr,
            BM1362_REG_CORE_CTRL,
            BM1362_CORE_REG_HASH_CLK,
            0,
            "CoreReg(0x3C) HashClk per-chip",
        )?;
        bm1362_single(
            uart,
            chain_idx,
            chip_addr,
            BM1362_REG_CORE_CTRL,
            BM1362_CORE_REG_CLK_DELAY,
            0,
            "CoreReg(0x3C) ClkDelay per-chip",
        )?;
        bm1362_single(
            uart,
            chain_idx,
            chip_addr,
            BM1362_REG_CORE_CTRL,
            BM1362_CORE_REG_UNKNOWN,
            0,
            "CoreReg(0x3C) Unknown per-chip",
        )?;
        bm1362_uart_relay_single(uart, chain_idx, chip_addr, stage)?;

        if i % 16 == 15 {
            std::thread::sleep(Duration::from_millis(BM1362_SERIAL_PACE_MIN_MS));
        }
    }
    std::thread::sleep(Duration::from_millis(100));
    info!(
        chain = chain_idx,
        chips = n_assign,
        stage,
        "am3-bb: BM1362 per-chip init complete"
    );
    Ok(())
}

fn bm1362_pll_ramp_to_target(target_freq_mhz: u16) -> Vec<(u32, u16)> {
    let target = target_freq_mhz.clamp(400, 597);
    let mut steps =
        bm1362_pll_ramp_sequence(BM1362_PLL_RAMP_START_MHZ, target, BM1362_PLL_RAMP_STEP_MHZ);

    // The live BM1362 trace has a special 525 MHz value. Keep that exact value
    // when 525 MHz is the requested endpoint; otherwise use the canonical PLL
    // lookup table for ramp steps and fallback targets.
    if target == 525 {
        for (reg, actual_mhz) in &mut steps {
            if *actual_mhz == 525 {
                *reg = BM1362_PLL0_PARAM_525MHZ;
            }
        }
    }

    if steps.is_empty() {
        steps.push(bm1362_pll_lookup(target));
    }
    steps
}

fn env_flag_set(name: &str) -> bool {
    dcentrald_common::lab_env::var_os(name).is_some()
}

// A forbidden override is still reported in release builds, even though the
// lab accessors will never grant its requested hardware behavior there.
fn forbidden_override_is_present(name: &str) -> bool {
    std::env::var_os(name).is_some()
}

fn parse_env_u32(name: &str) -> Option<u32> {
    let raw = dcentrald_common::lab_env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse::<u32>().ok()
    };

    if parsed.is_none() {
        warn!(
            env = name,
            value = %trimmed,
            "am3-bb: ignoring invalid integer environment override"
        );
    }

    parsed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Am3BbWorkCodec {
    /// Proven BM1362 chip-comm job frame:
    /// `[55 AA][21][56][82-byte full-header payload][CRC16 BE]`.
    Serial88,
    /// W4 stock-`uart_trans` `asic_work_t` frame:
    /// 86 bytes beginning with type `0xAA`, no direct `55 AA` preamble.
    Asic86,
}

impl Am3BbWorkCodec {
    fn from_env() -> Self {
        match dcentrald_common::lab_env::var(ENV_AM3_BB_WORK_CODEC)
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            None | Some("") | Some("serial88") | Some("serial") | Some("bm1362") => Self::Serial88,
            Some("asic86") | Some("w4") | Some("uart_trans86") | Some("uart-trans86") => {
                warn!(
                    env = ENV_AM3_BB_WORK_CODEC,
                    "am3-bb: lab override active - using W4 86-byte AsicWorkFrame dispatch"
                );
                Self::Asic86
            }
            Some(other) => {
                warn!(
                    env = ENV_AM3_BB_WORK_CODEC,
                    value = %other,
                    "am3-bb: unknown work codec override; falling back to serial88"
                );
                Self::Serial88
            }
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Serial88 => "serial88",
            Self::Asic86 => "asic86",
        }
    }

    fn job_id_slot(self, sent_job_id: u8) -> u8 {
        match self {
            Self::Serial88 => echoed_job_id(sent_job_id),
            Self::Asic86 => sent_job_id,
        }
    }

    fn job_id_increment(self) -> u8 {
        match self {
            Self::Serial88 => JOB_ID_INCREMENT,
            Self::Asic86 => 1,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bm1362Am3InitValues {
    init_control_broadcast: u32,
    init_control_per_chip: u32,
    misc_control_pre_baud: u32,
    misc_control_post_fast_baud: u32,
    label: &'static str,
}

fn bm1362_am3_init_values_from_env() -> Bm1362Am3InitValues {
    if env_flag_set(ENV_AM3_BB_LEGACY_AMLOGIC_INIT) {
        warn!(
            env = ENV_AM3_BB_LEGACY_AMLOGIC_INIT,
            "am3-bb: lab override active - using legacy Amlogic-derived BM1362 init values"
        );
        return Bm1362Am3InitValues {
            init_control_broadcast: BM1362_INIT_CONTROL_BCAST_LEGACY_AMLOGIC,
            init_control_per_chip: BM1362_INIT_CONTROL_PER_CHIP_LEGACY_AMLOGIC,
            misc_control_pre_baud: BM1362_MISC_CONTROL_LEGACY_AMLOGIC,
            misc_control_post_fast_baud: BM1362_MISC_CONTROL_LEGACY_AMLOGIC,
            label: "legacy-amlogic",
        };
    }

    Bm1362Am3InitValues {
        init_control_broadcast: BM1362_INIT_CONTROL_BCAST,
        init_control_per_chip: BM1362_INIT_CONTROL_PER_CHIP,
        misc_control_pre_baud: BM1362_INIT_PLAN.misc_control_pre_baud,
        misc_control_post_fast_baud: BM1362_INIT_PLAN.misc_control_post_fast_baud,
        label: "canonical-bm1362-init-plan",
    }
}

fn hex_preview(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn am3_bb_dspic_addr_for_chain(chain_idx: usize) -> u8 {
    AM3_BB_DSPIC_BASE_ADDR.saturating_add(chain_idx as u8)
}

fn am3_bb_dspic_temp_bridge_frame(sensor_addr: u8) -> [u8; 8] {
    let checksum = 0x06u8
        .wrapping_add(0x3C)
        .wrapping_add(sensor_addr)
        .wrapping_add(0x02)
        .wrapping_add(0x00);
    [0x55, 0xAA, 0x06, 0x3C, sensor_addr, 0x02, 0x00, checksum]
}

/// Decode one dsPIC-bridged LM75 reply into degrees Celsius, or reject it.
///
/// Wire layout, measured on live `a lab unit` (500 captured frames across
/// *.log`):
///
/// ```text
///   [0] 0x07      frame length          (499/500)
///   [1] 0x3C      opcode echo           (499/500)
///   [2] 0x01      payload descriptor    (499/499 well-formed; NOT a status byte)
///   [3] temp hi   LM75 raw, big-endian, signed
///   [4] temp lo   low nibble is always 0 (498/498 well-formed)
///   [5] status    0x00 = good (296), 0x01 = bad (203), 0xFF = garbage (1)
///   [6] checksum  additive sum of reply[0..=4] ONLY — reply[5] is excluded
/// ```
///
/// Two independent structural rejects are enforced here, both imported from
/// ePIC's GPL `pic_driver.ko` (`03-BEAGLEBONE_PLATFORM.md` §U-10,
/// `11-GHIDRA_BMS_MINER_DEEP_RE.md`) — DESK evidence — and then re-indexed
/// against our own live `a lab unit` measurement, which wins where the two conflict:
///
///  1. **Status byte non-zero ⇒ reject.** ePIC places its status byte at
///     `reply[2]`. On OUR frame `reply[2]` is the constant `0x01` in all 499
///     well-formed captures, so importing ePIC's byte index verbatim would
///     reject 100% of good reads and blind the thermal supervisor. The
///     equivalent byte on our bridge is `reply[5]`. Until now `reply[5] != 0`
///     was rejected only *by accident*: the checksum fold below spanned
///     `reply[..6]` while the device computes it over `reply[..5]`, so a status
///     of `0x01` showed up as an off-by-one checksum. That coincidence is the
///     recorded root cause of the `a lab unit` "noisy bridge replies" (README:26,180)
///     and it is fragile — any frame whose payload error happened to cancel the
///     status byte would have been laundered into a temperature. The predicate
///     is now explicit and named.
///  2. **`raw & 0x0F != 0` ⇒ reject.** The LM75 data register is 11-bit,
///     left-justified, so the low nibble of a genuine reading is always zero.
///     This is NOT redundant with the checksum: an 8-bit additive sum has no
///     positional weighting and cannot detect a compensating two-byte
///     corruption, whereas this invariant is a property of the sensor's own
///     data format. Live `a lab unit` frame `[07,3C,01,06,01,00,1D]` (from the
///     fail-closed negative control) would otherwise have looked like a
///     plausible, *cool* 6.0 °C.
///
/// Conversion: ePIC uses `(raw >> 4) * 62.5 m°C`. Ours is `raw / 256.0 °C`.
/// These are **exactly** equal — including for negative readings, since `>>` on
/// `i16` is arithmetic — whenever the low nibble is zero, which reject (2) now
/// guarantees. No divergence; the existing form is kept.
///
/// `reply[2]` is deliberately NOT pinned to `0x01`. It sits inside the checksum
/// span, so corruption there is already caught, and hard-pinning a byte whose
/// semantics we have not decoded would risk a total thermal blackout (and thus
/// a refusal to mine) on an undecoded board variant.
///
/// A rejected reply yields `None`, never a temperature and never a default:
/// the sample is simply not counted toward chain coverage, so the snapshot
/// reports `fresh = false` and the fail-closed supervisor owns the decision.
fn am3_bb_decode_lm75_bridge_reply(reply: &[u8]) -> Option<f32> {
    if reply.len() < AM3_BB_LM75_REPLY_LEN || reply[0] != 0x07 || reply[1] != 0x3C {
        return None;
    }
    // Structural reject 1: bridge status byte. Checked BEFORE the checksum so
    // the rejection reason is the real one rather than the historical
    // off-by-one artefact.
    if reply[5] != AM3_BB_LM75_STATUS_OK {
        return None;
    }
    // Checksum span is kept at `reply[..6]`. With the status gate above,
    // `reply[5]` is provably 0, so this is numerically identical to the
    // device's true `reply[..5]` span — but it stays strictly fail-safe if a
    // future edit ever removes the status check.
    let checksum = reply[..6].iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
    if checksum != reply[6] {
        return None;
    }
    let raw = i16::from_be_bytes([reply[3], reply[4]]);
    // Structural reject 2: LM75 low nibble must be zero.
    if raw & AM3_BB_LM75_RAW_LOW_NIBBLE_MASK != 0 {
        return None;
    }
    let temp_c = raw as f32 / 256.0;
    if (AM3_BB_LM75_MIN_VALID_C..=AM3_BB_LM75_MAX_VALID_C).contains(&temp_c) {
        Some(temp_c)
    } else {
        None
    }
}

fn am3_bb_dspic_target_voltage_mv(config_mv: u16) -> u16 {
    if (AM3_BB_DSPIC_MIN_VOLTAGE_MV..=AM3_BB_DSPIC_MAX_VOLTAGE_MV).contains(&config_mv) {
        config_mv
    } else {
        warn!(
            config_mv,
            fallback_mv = AM3_BB_DSPIC_DEFAULT_TARGET_MV,
            min_mv = AM3_BB_DSPIC_MIN_VOLTAGE_MV,
            max_mv = AM3_BB_DSPIC_MAX_VOLTAGE_MV,
            "am3-bb: mining.voltage_mv is outside the fw=0x89 dsPIC DAC range; using S19j Pro default"
        );
        AM3_BB_DSPIC_DEFAULT_TARGET_MV
    }
}

fn am3_bb_dspic_voltage_dac(voltage_mv: u16) -> u8 {
    let clamped = voltage_mv.clamp(AM3_BB_DSPIC_MIN_VOLTAGE_MV, AM3_BB_DSPIC_MAX_VOLTAGE_MV);
    let offset = u32::from(clamped - AM3_BB_DSPIC_MIN_VOLTAGE_MV);
    ((offset * 11 + 1600) / 3200) as u8
}

fn am3_bb_dspic_set_voltage_frame(voltage_mv: u16) -> [u8; 6] {
    let dac = am3_bb_dspic_voltage_dac(voltage_mv);
    let checksum = 0x04u8.wrapping_add(0x10).wrapping_add(dac);
    [0x55, 0xAA, 0x04, 0x10, dac, checksum]
}

fn am3_bb_dspic_command(
    i2c: &I2cServiceHandle,
    chain_idx: usize,
    addr: u8,
    label: I2cMutationLabel,
    frame: &[u8],
    read_count: usize,
    after_write_ms: u64,
    between_read_ms: u64,
    what: &str,
) -> Result<Vec<u8>> {
    let mut steps = Vec::with_capacity(1 + read_count.saturating_mul(2));
    steps.push(I2cTransactionStep::Write(frame.to_vec()));
    if after_write_ms > 0 {
        steps.push(I2cTransactionStep::SleepMs(after_write_ms));
    }
    for read_idx in 0..read_count {
        steps.push(I2cTransactionStep::Read(1));
        if between_read_ms > 0 && read_idx + 1 < read_count {
            steps.push(I2cTransactionStep::SleepMs(between_read_ms));
        }
    }

    let reads = i2c
        .transaction_mutating(label, addr, steps)
        .with_context(|| {
            format!(
                "am3-bb chain {} dsPIC 0x{:02X}: {} transaction failed",
                chain_idx, addr, what
            )
        })?;
    let out: Vec<u8> = reads.into_iter().flatten().collect();
    if out.len() != read_count {
        warn!(
            chain = chain_idx,
            addr = format_args!("0x{:02X}", addr),
            command = what,
            expected_read_bytes = read_count,
            actual_read_bytes = out.len(),
            reply = format_args!("{:02X?}", out),
            "am3-bb: dsPIC command returned a short reply"
        );
    }
    Ok(out)
}

fn am3_bb_dspic_read_lm75_temps(
    i2c: &I2cServiceHandle,
    chain_idx: usize,
    addr: u8,
    stage: &'static str,
) -> Vec<(u8, f32)> {
    let mut temps = Vec::new();
    for sensor_addr in AM3_BB_LM75_SENSOR_ADDRS {
        let frame = am3_bb_dspic_temp_bridge_frame(sensor_addr);
        match am3_bb_dspic_command(
            i2c,
            chain_idx,
            addr,
            I2cMutationLabel::QueryPrelude,
            &frame,
            AM3_BB_LM75_REPLY_LEN,
            20,
            20,
            "0x3c LM75 bridge read",
        ) {
            Ok(reply) => match am3_bb_decode_lm75_bridge_reply(&reply) {
                Some(temp_c) => {
                    debug!(
                        chain = chain_idx,
                        addr = format_args!("0x{:02X}", addr),
                        sensor = format_args!("0x{:02X}", sensor_addr),
                        stage,
                        temp_c,
                        reply = format_args!("{:02X?}", reply),
                        "am3-bb: dsPIC LM75 bridge temperature"
                    );
                    temps.push((sensor_addr, temp_c));
                }
                None => {
                    debug!(
                        chain = chain_idx,
                        addr = format_args!("0x{:02X}", addr),
                        sensor = format_args!("0x{:02X}", sensor_addr),
                        stage,
                        reply = format_args!("{:02X?}", reply),
                        "am3-bb: invalid dsPIC LM75 bridge reply"
                    );
                }
            },
            Err(e) => {
                debug!(
                    chain = chain_idx,
                    addr = format_args!("0x{:02X}", addr),
                    sensor = format_args!("0x{:02X}", sensor_addr),
                    stage,
                    error = %e,
                    "am3-bb: dsPIC LM75 bridge read failed"
                );
            }
        }
    }
    temps
}

#[derive(Debug, Clone, Copy)]
struct Am3BbThermalSnapshot {
    samples: usize,
    covered_chains: usize,
    expected_chains: usize,
    max_temp_c: f32,
    /// True only when this exact poll produced acceptable sensor coverage for
    /// every expected chain. A tolerated last-known-good value may guide
    /// logging but must not drive a new fan command or advance watchdog safety
    /// liveness.
    fresh: bool,
}

fn am3_bb_thermal_snapshot_from_chain_samples(
    samples_per_chain: &[usize],
    max_temp_c: f32,
) -> Am3BbThermalSnapshot {
    let samples = samples_per_chain.iter().sum();
    let covered_chains = samples_per_chain
        .iter()
        .filter(|&&samples| samples >= AM3_BB_THERMAL_MIN_SAMPLES_PER_CHAIN)
        .count();
    let expected_chains = samples_per_chain.len();
    Am3BbThermalSnapshot {
        samples,
        covered_chains,
        expected_chains,
        max_temp_c,
        fresh: expected_chains > 0 && covered_chains == expected_chains && max_temp_c.is_finite(),
    }
}

fn am3_bb_poll_dspic_temps(
    i2c: &I2cServiceHandle,
    active_addrs: &[u8],
    stage: &'static str,
) -> Am3BbThermalSnapshot {
    let mut samples_per_chain = Vec::with_capacity(active_addrs.len());
    let mut max_temp_c = f32::NEG_INFINITY;
    for &addr in active_addrs {
        let chain_idx = addr.saturating_sub(AM3_BB_DSPIC_BASE_ADDR) as usize;
        let chain_temps = am3_bb_dspic_read_lm75_temps(i2c, chain_idx, addr, stage);
        samples_per_chain.push(chain_temps.len());
        for (_sensor, temp_c) in chain_temps {
            max_temp_c = max_temp_c.max(temp_c);
        }
    }
    am3_bb_thermal_snapshot_from_chain_samples(&samples_per_chain, max_temp_c)
}

fn am3_bb_poll_thermal_attempts<F>(
    stage: &'static str,
    dangerous_temp_c: f32,
    retry_delay: Duration,
    mut poll: F,
) -> Result<Am3BbThermalSnapshot>
where
    F: FnMut(&'static str) -> Am3BbThermalSnapshot,
{
    let snapshot = poll(stage);
    am3_bb_reject_dangerous_thermal_attempt(&snapshot, dangerous_temp_c, stage)?;

    if stage == "runtime" && !snapshot.fresh {
        thread::sleep(retry_delay);
        let retry_stage = "runtime-retry";
        let retry = poll(retry_stage);
        am3_bb_reject_dangerous_thermal_attempt(&retry, dangerous_temp_c, retry_stage)?;
        Ok(retry)
    } else {
        Ok(snapshot)
    }
}

fn am3_bb_reject_dangerous_thermal_attempt(
    snapshot: &Am3BbThermalSnapshot,
    dangerous_temp_c: f32,
    stage: &'static str,
) -> Result<()> {
    // Any responding chain can prove danger even when aggregate coverage is
    // incomplete. Evaluate each attempt before a retry is allowed to replace
    // it so a cooler or missing retry can never hide an over-temperature.
    if snapshot.max_temp_c >= dangerous_temp_c {
        anyhow::bail!(
            "am3-bb: hashboard temperature {:.1}C reached dangerous threshold {:.1}C during {}",
            snapshot.max_temp_c,
            dangerous_temp_c,
            stage
        );
    }
    Ok(())
}

struct Am3BbThermalSupervisor {
    i2c: I2cServiceHandle,
    active_addrs: Vec<u8>,
    hot_temp_c: f32,
    dangerous_temp_c: f32,
    last_good: Option<(Instant, Am3BbThermalSnapshot)>,
    consecutive_misses: u8,
}

impl Am3BbThermalSupervisor {
    fn new(
        i2c: I2cServiceHandle,
        active_addrs: Vec<u8>,
        expected_chains: usize,
        hot_temp_c: u8,
        dangerous_temp_c: u8,
    ) -> Result<Self> {
        if active_addrs.is_empty() {
            anyhow::bail!("am3-bb: thermal supervisor requires at least one active dsPIC");
        }
        if active_addrs.len() != expected_chains {
            anyhow::bail!(
                "am3-bb: thermal supervisor owns {} dsPIC controller(s), but {} chain(s) require thermal coverage",
                active_addrs.len(),
                expected_chains
            );
        }
        let mut unique_addrs = active_addrs.clone();
        unique_addrs.sort_unstable();
        unique_addrs.dedup();
        if unique_addrs.len() != active_addrs.len() {
            anyhow::bail!(
                "am3-bb: thermal supervisor received duplicate dsPIC addresses: {:02X?}",
                active_addrs
            );
        }
        Ok(Self {
            i2c,
            active_addrs,
            hot_temp_c: f32::from(hot_temp_c),
            dangerous_temp_c: f32::from(dangerous_temp_c),
            last_good: None,
            consecutive_misses: 0,
        })
    }

    fn poll_and_check(&mut self, stage: &'static str) -> Result<Am3BbThermalSnapshot> {
        let snapshot = am3_bb_poll_thermal_attempts(
            stage,
            self.dangerous_temp_c,
            Duration::from_millis(AM3_BB_THERMAL_RUNTIME_RETRY_MS),
            |poll_stage| am3_bb_poll_dspic_temps(&self.i2c, &self.active_addrs, poll_stage),
        )?;
        if !snapshot.fresh {
            self.consecutive_misses = self.consecutive_misses.saturating_add(1);
            if stage == "runtime" {
                if let Some((sample_at, last_good)) = self.last_good {
                    let age = sample_at.elapsed();
                    if self.consecutive_misses <= AM3_BB_THERMAL_MAX_CONSECUTIVE_MISSES
                        && age <= Duration::from_millis(AM3_BB_THERMAL_MAX_STALE_MS)
                    {
                        warn!(
                            consecutive_misses = self.consecutive_misses,
                            observed_samples = snapshot.samples,
                            covered_chains = snapshot.covered_chains,
                            expected_chains = snapshot.expected_chains,
                            last_good_age_ms = age.as_millis(),
                            last_good_samples = last_good.samples,
                            last_good_max_temp_c = last_good.max_temp_c,
                            max_consecutive_misses = AM3_BB_THERMAL_MAX_CONSECUTIVE_MISSES,
                            max_stale_ms = AM3_BB_THERMAL_MAX_STALE_MS,
                            "am3-bb: runtime LM75 coverage was incomplete; retaining bounded last-known-good context without driving fan policy or watchdog liveness"
                        );
                        return Ok(Am3BbThermalSnapshot {
                            fresh: false,
                            ..last_good
                        });
                    }
                }
            }
            anyhow::bail!(
                "am3-bb: LM75 coverage reached only {}/{} chain(s) with {} sample(s) during {} after {} consecutive miss(es) - refusing to mine without fresh per-chain thermal proof",
                snapshot.covered_chains,
                snapshot.expected_chains,
                snapshot.samples,
                stage,
                self.consecutive_misses
            );
        }
        self.last_good = Some((Instant::now(), snapshot));
        self.consecutive_misses = 0;
        if snapshot.max_temp_c >= self.hot_temp_c {
            warn!(
                samples = snapshot.samples,
                covered_chains = snapshot.covered_chains,
                expected_chains = snapshot.expected_chains,
                max_temp_c = snapshot.max_temp_c,
                hot_temp_c = self.hot_temp_c,
                dangerous_temp_c = self.dangerous_temp_c,
                stage,
                "am3-bb: hashboard temperature is hot; quiet guard remains capped and will fail closed at dangerous threshold"
            );
        } else {
            info!(
                samples = snapshot.samples,
                covered_chains = snapshot.covered_chains,
                expected_chains = snapshot.expected_chains,
                max_temp_c = snapshot.max_temp_c,
                hot_temp_c = self.hot_temp_c,
                dangerous_temp_c = self.dangerous_temp_c,
                stage,
                "am3-bb: thermal supervisor sample OK"
            );
        }
        Ok(snapshot)
    }
}

fn am3_bb_dspic_heartbeat_once(
    i2c: &I2cServiceHandle,
    chain_idx: usize,
    addr: u8,
) -> Result<Vec<u8>> {
    let reads = i2c
        .transaction_mutating(
            I2cMutationLabel::KeepAlive,
            addr,
            dcentrald_hal::bb_pic_heartbeat::transaction_steps(),
        )
        .with_context(|| {
            format!("am3-bb chain {chain_idx} dsPIC 0x{addr:02X}: heartbeat transaction failed")
        })?;
    let reply = dcentrald_hal::bb_pic_heartbeat::complete_reply(&reads)
        .context("am3-bb: incomplete PIC heartbeat transaction results")?;
    am3_bb_validate_heartbeat_reply(chain_idx, addr, reply.to_vec())
}

/// Validate the exact framed heartbeat response established by the `a lab unit`
/// capture.
///
/// The shared codec owns framing, length, checksum, and opcode decoding. This
/// target policy owns the evidence-backed heartbeat opcode and payload. Keeping
/// those layers separate lets future dsPIC generations use the same codec
/// without inheriting `a lab unit` response policy.
fn am3_bb_validate_heartbeat_reply(chain_idx: usize, addr: u8, reply: Vec<u8>) -> Result<Vec<u8>> {
    let frame = decode_framed_sum_reply_body(&reply).map_err(|error| {
        anyhow::anyhow!(
            "am3-bb chain {chain_idx} dsPIC 0x{addr:02X}: invalid framed heartbeat reply: {error:?}"
        )
    })?;
    if frame.opcode != DspicOpcode::Heartbeat {
        anyhow::bail!(
            "am3-bb chain {chain_idx} dsPIC 0x{addr:02X}: heartbeat reply opcode was 0x{:02X}; expected 0x{:02X}",
            frame.opcode.as_u8(),
            DspicOpcode::Heartbeat.as_u8()
        );
    }
    if frame.payload.as_slice() != AM3_BB_DSPIC_HEARTBEAT_REPLY_PAYLOAD {
        anyhow::bail!(
            "am3-bb chain {chain_idx} dsPIC 0x{addr:02X}: heartbeat reply payload was {:02X?}; expected exact .79 payload {:02X?}",
            frame.payload,
            AM3_BB_DSPIC_HEARTBEAT_REPLY_PAYLOAD
        );
    }
    Ok(reply)
}

fn am3_bb_dspic_read_voltage(
    i2c: &I2cServiceHandle,
    chain_idx: usize,
    addr: u8,
    what: &str,
) -> Result<Vec<u8>> {
    let reads = i2c
        .transaction_mutating(
            I2cMutationLabel::QueryPrelude,
            addr,
            dcentrald_hal::bb_pic_rail::read_steps(),
        )
        .with_context(|| {
            format!("am3-bb chain {chain_idx} dsPIC 0x{addr:02X}: {what} rail query failed")
        })?;
    if reads.len() != dcentrald_hal::bb_pic_rail::RESPONSE_BYTES
        || reads.iter().any(|read| read.len() != 1)
    {
        anyhow::bail!("am3-bb: PIC rail query did not return seven complete one-byte reads");
    }
    let reply: Vec<u8> = reads.into_iter().flatten().collect();
    let observation = dcentrald_hal::bb_pic_rail::BbPicRailObservation::from_complete_reply(&reply)
        .context("am3-bb: incomplete PIC rail observation")?;
    info!(
        chain = chain_idx,
        addr = format_args!("0x{addr:02X}"),
        stage = what,
        raw_adc = observation.raw_adc(),
        voltage_v = observation.voltage_v(),
        checksum_validated = false,
        "am3-bb: source-decoded PIC rail observation"
    );
    Ok(reply)
}

fn am3_bb_dspic_set_voltage(
    i2c: &I2cServiceHandle,
    chain_idx: usize,
    addr: u8,
    voltage_mv: u16,
    stage: &str,
) -> Result<Vec<u8>> {
    let frame = am3_bb_dspic_set_voltage_frame(voltage_mv);
    if env_flag_set(ENV_AM3_BB_SKIP_DSPIC_SET_VOLTAGE) {
        warn!(
            chain = chain_idx,
            addr = format_args!("0x{:02X}", addr),
            voltage_mv,
            stage,
            frame = format_args!("{:02X?}", frame),
            env = ENV_AM3_BB_SKIP_DSPIC_SET_VOLTAGE,
            "am3-bb: lab override active - skipping dsPIC SetVoltage"
        );
        return Ok(Vec::new());
    }
    am3_bb_dspic_command(
        i2c,
        chain_idx,
        addr,
        I2cMutationLabel::Energize,
        &frame,
        0,
        0,
        0,
        stage,
    )?;
    thread::sleep(Duration::from_millis(50));
    Ok(frame.to_vec())
}

fn am3_bb_dspic_enable_voltage(
    i2c: &I2cServiceHandle,
    chain_idx: usize,
    addr: u8,
    stage: &str,
) -> Result<Vec<u8>> {
    let enable_ack = am3_bb_dspic_command(
        i2c,
        chain_idx,
        addr,
        I2cMutationLabel::Energize,
        AM3_BB_DSPIC_ENABLE_FRAME,
        2,
        50,
        20,
        stage,
    )?;
    let enable_ok = enable_ack.first().copied() == Some(0x15)
        && matches!(enable_ack.get(1).copied(), Some(0x00 | 0x01));
    if !enable_ok {
        anyhow::bail!(
            "am3-bb chain {} dsPIC 0x{:02X}: enable-voltage ACK mismatch during {}: {:02X?}",
            chain_idx,
            addr,
            stage,
            enable_ack
        );
    }
    Ok(enable_ack)
}

fn am3_bb_dspic_set_voltage_all(
    i2c: &I2cServiceHandle,
    active_addrs: &[u8],
    heartbeat: Option<&mut Am3BbDspicHeartbeatGuard>,
    shutdown: &CancellationToken,
    heartbeat_required: bool,
    voltage_mv: u16,
    enable: bool,
    stage: &'static str,
) -> Result<()> {
    let mut heartbeat = heartbeat;
    let mut admit = |_: usize, _: u8| {
        am3_bb_require_heartbeat_for_energizing_boundary(
            heartbeat.as_deref_mut(),
            shutdown,
            heartbeat_required,
            stage,
        )
    };

    for &addr in active_addrs {
        let chain_idx = addr.saturating_sub(AM3_BB_DSPIC_BASE_ADDR) as usize;
        let voltage_before =
            am3_bb_dspic_read_voltage(i2c, chain_idx, addr, "read-voltage-before-rail-stage")?;
        let set_frame = am3_bb_with_energize_admission(chain_idx, addr, &mut admit, || {
            am3_bb_dspic_set_voltage(i2c, chain_idx, addr, voltage_mv, stage)
        })?;
        let voltage_after_set =
            am3_bb_dspic_read_voltage(i2c, chain_idx, addr, "read-voltage-after-rail-set")?;
        let enable_ack = if enable {
            let ack = am3_bb_with_energize_admission(chain_idx, addr, &mut admit, || {
                am3_bb_dspic_enable_voltage(i2c, chain_idx, addr, stage)
            })?;
            thread::sleep(Duration::from_millis(70));
            ack
        } else {
            Vec::new()
        };
        let voltage_after =
            am3_bb_dspic_read_voltage(i2c, chain_idx, addr, "read-voltage-after-rail-stage")?;
        info!(
            chain = chain_idx,
            addr = format_args!("0x{:02X}", addr),
            stage,
            voltage_mv,
            enable,
            set_frame = format_args!("{:02X?}", set_frame),
            enable_ack = format_args!("{:02X?}", enable_ack),
            voltage_before = format_args!("{:02X?}", voltage_before),
            voltage_after_set = format_args!("{:02X?}", voltage_after_set),
            voltage_after = format_args!("{:02X?}", voltage_after),
            "am3-bb: dsPIC rail stage complete"
        );
    }
    Ok(())
}

/// Execute exactly one energizing mutation behind fresh safety admission.
///
/// Queries can take long enough for heartbeat failure or cancellation to
/// arrive, so admission belongs adjacent to `SetVoltage` and `Enable`, not at
/// the start of an address sweep. Keeping the sequencing wrapper transport-free
/// makes the no-mutation-after-cancellation property deterministic to test.
fn am3_bb_with_energize_admission<T, Admit, Energize>(
    chain_idx: usize,
    addr: u8,
    admit: &mut Admit,
    energize: Energize,
) -> Result<T>
where
    Admit: FnMut(usize, u8) -> Result<()>,
    Energize: FnOnce() -> Result<T>,
{
    admit(chain_idx, addr)?;
    energize()
}

/// Observe an already-running fw89 application through the sole service.
/// The native query retains its existing 135ms initial/20ms inter-read waits;
/// the donor's post-RESET query is a different entry state, not timing proof
/// for this query. No malformed or foreign reply authorizes RESET or JUMP.
fn am3_bb_dspic_read_application<T>(chain_idx: usize, addr: u8, transaction: T) -> Result<[u8; 5]>
where
    T: FnOnce(I2cMutationLabel, u8, Vec<I2cTransactionStep>) -> Result<Vec<Vec<u8>>>,
{
    anyhow::ensure!(
        chain_idx < 3 && addr == AM3_BB_DSPIC_BASE_ADDR + chain_idx as u8,
        "am3-bb: application query requires its exact chain/controller address"
    );
    let steps = dcentrald_hal::bb_pic_application::transaction_steps();
    let reads = transaction(I2cMutationLabel::QueryPrelude, addr, steps).with_context(|| {
        format!("am3-bb chain {chain_idx} dsPIC 0x{addr:02X}: application query failed")
    })?;
    dcentrald_hal::bb_pic_application::complete_reply(&reads)
        .map_err(|error| anyhow::anyhow!("am3-bb: {error}"))
}

fn am3_bb_dspic_init_one(
    i2c: &I2cServiceHandle,
    chain_idx: usize,
    addr: u8,
    target_voltage_mv: u16,
    early_enable: bool,
) -> Result<Option<u8>> {
    info!(
        chain = chain_idx,
        addr = format_args!("0x{:02X}", addr),
        "am3-bb: LuxOS-trace dsPIC init starting"
    );

    let version = am3_bb_dspic_read_application(chain_idx, addr, |label, addr, steps| {
        i2c.transaction_mutating(label, addr, steps)
            .map_err(anyhow::Error::new)
    })?;
    let fw = version[2];

    i2c.disable_dspic_voltage(addr, I2cDspicDisableProtocol::VnishPaddedFramed)
        .with_context(|| {
            format!(
                "am3-bb chain {} dsPIC 0x{:02X}: disable-voltage SafeOff failed",
                chain_idx, addr
            )
        })?;
    thread::sleep(Duration::from_millis(50));
    let mut disable_ack = i2c.read_bytes(addr, 1).with_context(|| {
        format!(
            "am3-bb chain {} dsPIC 0x{:02X}: first disable ACK read failed",
            chain_idx, addr
        )
    })?;
    thread::sleep(Duration::from_millis(20));
    disable_ack.extend(i2c.read_bytes(addr, 1).with_context(|| {
        format!(
            "am3-bb chain {} dsPIC 0x{:02X}: second disable ACK read failed",
            chain_idx, addr
        )
    })?);
    if disable_ack.first().copied() != Some(0x15) {
        warn!(
            chain = chain_idx,
            addr = format_args!("0x{:02X}", addr),
            reply = format_args!("{:02X?}", disable_ack),
            "am3-bb: dsPIC disable-voltage ACK mismatch; continuing with LuxOS trace sequence"
        );
    }
    thread::sleep(Duration::from_millis(40));

    let probe_3b = am3_bb_dspic_command(
        i2c,
        chain_idx,
        addr,
        I2cMutationLabel::Unclassified,
        AM3_BB_DSPIC_PROBE_3B_48_FRAME,
        2,
        20,
        20,
        "0x3b/0x48 probe",
    )?;
    debug!(
        chain = chain_idx,
        addr = format_args!("0x{:02X}", addr),
        reply = format_args!("{:02X?}", probe_3b),
        "am3-bb: dsPIC 0x3b/0x48 probe reply"
    );

    let heartbeat = am3_bb_dspic_heartbeat_once(i2c, chain_idx, addr)?;
    debug!(
        chain = chain_idx,
        addr = format_args!("0x{:02X}", addr),
        reply = format_args!("{:02X?}", heartbeat),
        "am3-bb: dsPIC initial heartbeat reply"
    );

    for sensor_addr in AM3_BB_LM75_SENSOR_ADDRS {
        let frame = am3_bb_dspic_temp_bridge_frame(sensor_addr);
        let reply = am3_bb_dspic_command(
            i2c,
            chain_idx,
            addr,
            I2cMutationLabel::QueryPrelude,
            &frame,
            7,
            20,
            20,
            "0x3c LM75 bridge read",
        )?;
        debug!(
            chain = chain_idx,
            addr = format_args!("0x{:02X}", addr),
            sensor = format_args!("0x{:02X}", sensor_addr),
            reply = format_args!("{:02X?}", reply),
            "am3-bb: dsPIC LM75 bridge reply"
        );
    }

    let voltage_before =
        am3_bb_dspic_read_voltage(i2c, chain_idx, addr, "read-voltage-before-enable")?;

    let set_voltage_frame = am3_bb_dspic_set_voltage_frame(target_voltage_mv);
    let (voltage_after_set, enable_ack, voltage_after) = if early_enable {
        am3_bb_dspic_set_voltage(i2c, chain_idx, addr, target_voltage_mv, "early-enable")?;
        let voltage_after_set =
            am3_bb_dspic_read_voltage(i2c, chain_idx, addr, "read-voltage-after-early-set")?;
        let enable_ack = am3_bb_dspic_enable_voltage(i2c, chain_idx, addr, "early-enable")?;
        thread::sleep(Duration::from_millis(70));
        let voltage_after =
            am3_bb_dspic_read_voltage(i2c, chain_idx, addr, "read-voltage-after-early-enable")?;
        (voltage_after_set, enable_ack, voltage_after)
    } else {
        info!(
            chain = chain_idx,
            addr = format_args!("0x{:02X}", addr),
            target_voltage_mv,
            "am3-bb: dsPIC controller initialized with DC/DC disabled; BM1362 enum/init will run before rail enable"
        );
        (Vec::new(), Vec::new(), voltage_before.clone())
    };
    let heartbeat_after = am3_bb_dspic_heartbeat_once(i2c, chain_idx, addr)?;

    info!(
        chain = chain_idx,
        addr = format_args!("0x{:02X}", addr),
        firmware = format_args!("0x{:02X}", fw),
        version = format_args!("{:02X?}", version),
        disable_ack = format_args!("{:02X?}", disable_ack),
        enable_ack = format_args!("{:02X?}", enable_ack),
        target_voltage_mv,
        set_voltage_frame = format_args!("{:02X?}", set_voltage_frame),
        voltage_before = format_args!("{:02X?}", voltage_before),
        voltage_after_set = format_args!("{:02X?}", voltage_after_set),
        voltage_after = format_args!("{:02X?}", voltage_after),
        heartbeat_after = format_args!("{:02X?}", heartbeat_after),
        "am3-bb: GET_VERSION-first dsPIC init complete (no RESET 0x07)"
    );

    Ok(Some(fw))
}

fn am3_bb_dspic_init_all(
    i2c: &I2cServiceHandle,
    chain_count: usize,
    target_voltage_mv: u16,
    early_enable: bool,
) -> Vec<u8> {
    let mut active_addrs = Vec::new();
    for chain_idx in 0..chain_count {
        let addr = am3_bb_dspic_addr_for_chain(chain_idx);
        match am3_bb_dspic_init_one(i2c, chain_idx, addr, target_voltage_mv, early_enable) {
            Ok(Some(_fw)) => active_addrs.push(addr),
            Ok(None) => {}
            Err(e) => warn!(
                chain = chain_idx,
                addr = format_args!("0x{:02X}", addr),
                error = %e,
                "am3-bb: dsPIC init failed on this chain controller"
            ),
        }
    }
    active_addrs
}

fn am3_bb_write_reset_gpio(gpio: u32, asserted: bool) -> Result<()> {
    am3_bb_prepare_output_gpio(gpio, true)?;
    am3_bb_write_gpio_attr_checked(gpio, "value", if asserted { "1" } else { "0" }).with_context(
        || {
            format!(
                "am3-bb: checked {} of active-low reset gpio{} failed",
                if asserted { "assert" } else { "release" },
                gpio
            )
        },
    )
}

fn am3_bb_gpio_dir_at(sysfs_root: &Path, gpio: u32) -> std::path::PathBuf {
    sysfs_root.join(format!("gpio{gpio}"))
}

fn am3_bb_export_gpio_if_needed_at(sysfs_root: &Path, gpio: u32) -> Result<()> {
    am3_bb_export_gpio_if_needed_at_with(sysfs_root, gpio, |path, value| {
        std::fs::write(path, value)
    })
}

fn am3_bb_export_gpio_if_needed_at_with<F>(
    sysfs_root: &Path,
    gpio: u32,
    export_gpio: F,
) -> Result<()>
where
    F: FnOnce(&Path, &str) -> std::io::Result<()>,
{
    let gpio_dir = am3_bb_gpio_dir_at(sysfs_root, gpio);
    if gpio_dir.exists() {
        return Ok(());
    }
    // Another process can win the export between the existence check and our
    // write. Linux reports EBUSY in that case, but the operation is usable once
    // the winner's gpioN node materializes. Preserve any write error and accept
    // it only when the bounded observation below proves that materialization.
    let gpio_text = gpio.to_string();
    let export_error = export_gpio(&sysfs_root.join("export"), &gpio_text).err();
    let deadline = Instant::now() + Duration::from_millis(250);
    while !gpio_dir.exists() {
        if Instant::now() >= deadline {
            if let Some(error) = export_error {
                return Err(error).with_context(|| {
                    format!(
                        "am3-bb: export gpio{} failed and {} did not materialize within 250ms",
                        gpio,
                        gpio_dir.display()
                    )
                });
            }
            anyhow::bail!(
                "am3-bb: gpio{} export command completed but {} did not appear within 250ms",
                gpio,
                gpio_dir.display()
            );
        }
        thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

fn am3_bb_wait_gpio_attributes_at(sysfs_root: &Path, gpio: u32) -> Result<()> {
    let gpio_dir = am3_bb_gpio_dir_at(sysfs_root, gpio);
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        let missing: Vec<&str> = ["direction", "active_low", "value"]
            .into_iter()
            .filter(|attr| !gpio_dir.join(attr).exists())
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "am3-bb: gpio{} sysfs attributes {:?} did not appear within 250ms after export",
                gpio,
                missing
            );
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn am3_bb_export_gpio_if_needed(gpio: u32) -> Result<()> {
    am3_bb_export_gpio_if_needed_at(Path::new(AM3_BB_GPIO_SYSFS_ROOT), gpio)
}

fn am3_bb_validate_gpio_attr_readback(
    gpio: u32,
    attr: &str,
    expected: &str,
    observed: &str,
) -> Result<()> {
    let observed = observed.trim();
    if observed != expected {
        anyhow::bail!(
            "am3-bb: gpio{} {} readback mismatch: expected {:?}, observed {:?}",
            gpio,
            attr,
            expected,
            observed
        );
    }
    Ok(())
}

fn am3_bb_write_gpio_attr_checked_at(
    sysfs_root: &Path,
    gpio: u32,
    attr: &str,
    value: &str,
) -> Result<()> {
    let path = am3_bb_gpio_dir_at(sysfs_root, gpio).join(attr);
    std::fs::write(&path, value)
        .with_context(|| format!("am3-bb: write gpio{} {}={} failed", gpio, attr, value))?;
    let observed = std::fs::read_to_string(&path)
        .with_context(|| format!("am3-bb: read gpio{} {} after write failed", gpio, attr))?;
    am3_bb_validate_gpio_attr_readback(gpio, attr, value, &observed)
}

fn am3_bb_write_gpio_attr_checked(gpio: u32, attr: &str, value: &str) -> Result<()> {
    am3_bb_write_gpio_attr_checked_at(Path::new(AM3_BB_GPIO_SYSFS_ROOT), gpio, attr, value)
}

fn am3_bb_prepare_output_gpio_at(sysfs_root: &Path, gpio: u32, active_low: bool) -> Result<()> {
    am3_bb_export_gpio_if_needed_at(sysfs_root, gpio)?;
    am3_bb_write_gpio_attr_checked_at(sysfs_root, gpio, "direction", "out")?;
    am3_bb_write_gpio_attr_checked_at(
        sysfs_root,
        gpio,
        "active_low",
        if active_low { "1" } else { "0" },
    )?;
    Ok(())
}

fn am3_bb_prepare_output_gpio(gpio: u32, active_low: bool) -> Result<()> {
    am3_bb_prepare_output_gpio_at(Path::new(AM3_BB_GPIO_SYSFS_ROOT), gpio, active_low)
}

#[derive(Debug, Clone, Copy)]
struct Am3BbCutoffTiming {
    write_started_at: Instant,
    completed_at: Instant,
}

#[derive(Clone, Copy)]
enum Am3BbRetainedReadbackMode {
    KernelSysfs,
    #[cfg(test)]
    OrdinaryFileFixture,
}

impl Am3BbRetainedReadbackMode {
    fn expected_direction(self) -> &'static str {
        match self {
            Self::KernelSysfs => "out",
            #[cfg(test)]
            Self::OrdinaryFileFixture => "low",
        }
    }

    #[cfg(test)]
    fn needs_value_emulation(self) -> bool {
        matches!(self, Self::OrdinaryFileFixture)
    }
}

fn am3_bb_current_thread_token() -> usize {
    // SAFETY: pthread_self has no preconditions and returns an opaque identity
    // for the calling thread. DCENT_OS targets Unix/Linux; zero is reserved as
    // the no-writer sentinel, so map an implausible zero token to one.
    let token = unsafe { libc::pthread_self() as usize };
    if token == 0 {
        1
    } else {
        token
    }
}

struct Am3BbOnWriterPublication {
    writer_thread: Arc<AtomicUsize>,
}

impl Drop for Am3BbOnWriterPublication {
    fn drop(&mut self) {
        self.writer_thread.store(0, Ordering::SeqCst);
    }
}

/// One pre-opened, physically raw PSU GPIO65 cutoff capability.
///
/// The direction writer plus direction/active-low/value readers are opened
/// before cold boot and retained for the lifetime of the consumer. Cutoff is
/// encoded only as `direction=low`, whose kernel ABI sets output and the raw
/// physical latch LOW regardless of later `active_low` drift. This type has no
/// arbitrary-level or HIGH method. Lanes use independent file descriptions so
/// panic/heartbeat work cannot race a runtime lane's offsets.
struct Am3BbPreparedBoardCutoff {
    gpio: u32,
    off_level: &'static str,
    direction_reader: File,
    direction_writer: File,
    active_low_reader: File,
    value_reader: File,
    #[cfg(test)]
    fixture_value_writer: Option<File>,
    /// Test-only rendezvous fired exactly once, immediately after the panic
    /// lane's first physical LOW and before it enters the serialization loop.
    ///
    /// This exists so the adversarial interleaving this lane defends against —
    /// a published ON writer landing HIGH *after* the first LOW — can be
    /// reproduced by construction instead of by racing the host scheduler. The
    /// previous approach spawned a thread, spun a fixed yield budget hoping to
    /// catch the window, and (when that proved flaky) injected a
    /// `#[cfg(test)] sleep(2ms)` right here to widen it. A sleep is not a
    /// synchronization primitive: under load the window still closed early, and
    /// the sleep put test-only timing inside a panic-path hook.
    ///
    /// Calling through an `Arc<dyn Fn>` performs no allocation, so the
    /// no-allocation property of the lane holds in test builds too.
    #[cfg(test)]
    after_first_low_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    readback_mode: Am3BbRetainedReadbackMode,
    terminal: Arc<AtomicBool>,
    on_writer_thread: Arc<AtomicUsize>,
}

impl Am3BbPreparedBoardCutoff {
    fn open_at(
        sysfs_root: &Path,
        gpio: u32,
        off_level: &'static str,
        lane: &'static str,
        readback_mode: Am3BbRetainedReadbackMode,
        terminal: Arc<AtomicBool>,
        on_writer_thread: Arc<AtomicUsize>,
    ) -> Result<Self> {
        anyhow::ensure!(
            off_level == "0",
            "am3-bb: GPIO{} {} raw cutoff requires physical LOW, got {:?}",
            gpio,
            lane,
            off_level
        );
        let gpio_dir = am3_bb_gpio_dir_at(sysfs_root, gpio);
        let direction_path = gpio_dir.join("direction");
        let value_path = am3_bb_gpio_dir_at(sysfs_root, gpio).join("value");
        let active_low_path = gpio_dir.join("active_low");
        let direction_reader = std::fs::OpenOptions::new()
            .read(true)
            .open(&direction_path)
            .with_context(|| {
                format!(
                    "am3-bb: pre-open GPIO{} direction reader for {} lane at {} failed",
                    gpio,
                    lane,
                    direction_path.display()
                )
            })?;
        let direction_writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&direction_path)
            .with_context(|| {
                format!(
                    "am3-bb: pre-open GPIO{} direction writer for {} lane at {} failed",
                    gpio,
                    lane,
                    direction_path.display()
                )
            })?;
        let active_low_reader = std::fs::OpenOptions::new()
            .read(true)
            .open(&active_low_path)
            .with_context(|| {
                format!(
                    "am3-bb: pre-open GPIO{} active_low reader for {} lane at {} failed",
                    gpio,
                    lane,
                    active_low_path.display()
                )
            })?;
        let value_reader = std::fs::OpenOptions::new()
            .read(true)
            .open(&value_path)
            .with_context(|| {
                format!(
                    "am3-bb: pre-open GPIO{} value reader for {} lane at {} failed",
                    gpio,
                    lane,
                    value_path.display()
                )
            })?;
        #[cfg(test)]
        let fixture_value_writer = if readback_mode.needs_value_emulation() {
            Some(
                std::fs::OpenOptions::new()
                .write(true)
                .open(&value_path)
                .with_context(|| {
                    format!(
                        "am3-bb: pre-open GPIO{} ordinary-fixture value writer for {} lane at {} failed",
                        gpio,
                        lane,
                        value_path.display()
                    )
                })?,
            )
        } else {
            None
        };
        Ok(Self {
            gpio,
            off_level,
            direction_reader,
            direction_writer,
            active_low_reader,
            value_reader,
            #[cfg(test)]
            fixture_value_writer,
            #[cfg(test)]
            after_first_low_hook: None,
            readback_mode,
            terminal,
            on_writer_thread,
        })
    }

    fn gpio(&self) -> u32 {
        self.gpio
    }

    fn off_level(&self) -> &'static str {
        self.off_level
    }

    fn read_attr_checked(&self, reader: &File, attr: &str, expected: &str) -> Result<()> {
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0)).with_context(|| {
            format!(
                "am3-bb: seek retained GPIO{} {} reader failed",
                self.gpio, attr
            )
        })?;
        let mut observed = String::new();
        reader.read_to_string(&mut observed).with_context(|| {
            format!(
                "am3-bb: retained GPIO{} {} readback failed",
                self.gpio, attr
            )
        })?;
        am3_bb_validate_gpio_attr_readback(self.gpio, attr, expected, &observed)
    }

    fn read_prepared_topology_checked(&self) -> Result<()> {
        self.read_attr_checked(
            &self.direction_reader,
            "direction",
            self.readback_mode.expected_direction(),
        )?;
        self.read_attr_checked(&self.active_low_reader, "active_low", "0")
    }

    fn read_off_checked(&self) -> Result<()> {
        self.read_prepared_topology_checked()?;
        self.read_attr_checked(&self.value_reader, "value", self.off_level)
    }

    fn read_on_checked(&self) -> Result<()> {
        self.read_prepared_topology_checked()?;
        self.read_attr_checked(&self.value_reader, "value", "1")
    }

    #[cfg(test)]
    fn emulate_fixture_raw_low(&self) -> bool {
        let Some(writer) = self.fixture_value_writer.as_ref() else {
            return true;
        };
        let fd = writer.as_raw_fd();
        // SAFETY: fd is an owned, pre-opened ordinary-file fixture descriptor;
        // the pointer addresses one live byte for exactly the syscall duration.
        if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } != 0 {
            return false;
        }
        let byte = b'0';
        // SAFETY: same descriptor/lifetime argument as above; count is one.
        unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) == 1 }
    }

    fn write_off_checked(&self) -> Result<Am3BbCutoffTiming> {
        let mut writer = &self.direction_writer;
        writer.seek(SeekFrom::Start(0)).with_context(|| {
            format!(
                "am3-bb: seek retained GPIO{} raw cutoff direction writer failed",
                self.gpio
            )
        })?;
        let write_started_at = Instant::now();
        writer.write_all(b"low").with_context(|| {
            format!(
                "am3-bb: retained GPIO{} raw direction=low cutoff failed",
                self.gpio
            )
        })?;
        #[cfg(test)]
        anyhow::ensure!(
            self.emulate_fixture_raw_low(),
            "am3-bb: ordinary-file fixture could not emulate direction=low"
        );
        self.read_off_checked()?;
        Ok(Am3BbCutoffTiming {
            write_started_at,
            completed_at: Instant::now(),
        })
    }

    fn cut_checked(&self) -> Result<Am3BbCutoffTiming> {
        self.terminal.store(true, Ordering::SeqCst);
        let current_thread = am3_bb_current_thread_token();
        for _ in 0..AM3_BB_CUTOFF_SERIALIZATION_YIELD_LIMIT {
            let writer_thread = self.on_writer_thread.load(Ordering::SeqCst);
            if writer_thread == 0 || writer_thread == current_thread {
                return self.write_off_checked();
            }
            anyhow::ensure!(
                self.write_off_raw_noalloc(),
                "am3-bb: retained GPIO{} raw cutoff failed while serializing with the sole ON writer",
                self.gpio
            );
            // SAFETY: sched_yield has no pointer or lifetime preconditions and
            // lets the published ON writer retire on single-core AM335x.
            let _ = unsafe { libc::sched_yield() };
        }
        let writer_thread = self.on_writer_thread.load(Ordering::SeqCst);
        if writer_thread == 0 || writer_thread == current_thread {
            return self.write_off_checked();
        }
        let final_raw_low = self.write_off_raw_noalloc();
        anyhow::bail!(
            "am3-bb: GPIO{} sole ON writer token {} did not retire within {} cutoff yields; final raw LOW write succeeded={}",
            self.gpio,
            writer_thread,
            AM3_BB_CUTOFF_SERIALIZATION_YIELD_LIMIT,
            final_raw_low
        )
    }

    /// Panic-hook load-bearing primitive: publish the terminal latch and issue
    /// raw `direction=low` through the already-open descriptor. If another
    /// thread owns the only HIGH write window, repeatedly force LOW and yield
    /// for a fixed iteration budget, then perform one final LOW attempt. A
    /// failed raw write returns once the syscall or bounded EINTR retry loop
    /// reports failure. The iteration budget does not make a sysfs callback
    /// wall-clock bounded: a kernel write may still sleep until the hardware
    /// watchdog resets the system. A panic on the ON-writing thread itself
    /// cannot resume that write after the aborting hook returns.
    /// No userspace allocation, formatting, readback, lock, or path lookup
    /// occurs on the production path; kernels may still allocate in sysfs.
    fn cut_raw_noalloc(&self) -> bool {
        self.terminal.store(true, Ordering::SeqCst);
        let current_thread = am3_bb_current_thread_token();
        // Snapshot the writer publication before the first LOW. If a foreign
        // writer retires while that write is in flight, its HIGH may still be
        // the later physical write; remembering the snapshot forces a final
        // LOW after retirement even though the next token load observes zero.
        let initial_writer_thread = self.on_writer_thread.load(Ordering::SeqCst);
        let first_write_ok = self.write_off_raw_noalloc();
        if !first_write_ok {
            return false;
        }
        if initial_writer_thread == current_thread {
            return true;
        }
        // The first LOW has landed and the loop has not started yet. This is the
        // exact instant a test needs in order to model a published ON writer
        // that lands HIGH after us; the hook lets it act here by construction
        // rather than by out-racing the scheduler. No production build contains
        // this field, and no test that leaves the hook unset observes any
        // behaviour change.
        #[cfg(test)]
        if let Some(after_first_low) = self.after_first_low_hook.as_ref() {
            after_first_low();
        }
        let mut waited_for_other_writer = initial_writer_thread != 0;
        for _ in 0..AM3_BB_CUTOFF_SERIALIZATION_YIELD_LIMIT {
            let writer_thread = self.on_writer_thread.load(Ordering::SeqCst);
            if writer_thread == 0 {
                return if waited_for_other_writer {
                    self.write_off_raw_noalloc()
                } else {
                    first_write_ok
                };
            }
            if writer_thread == current_thread {
                return first_write_ok;
            }
            waited_for_other_writer = true;
            if !self.write_off_raw_noalloc() {
                return false;
            }
            // SAFETY: sched_yield has no pointer or lifetime preconditions. It
            // lets the published ON writer reach its terminal check/retirement
            // on single-core AM335x systems while this hook keeps re-cutting.
            let _ = unsafe { libc::sched_yield() };
        }
        let writer_thread = self.on_writer_thread.load(Ordering::SeqCst);
        if writer_thread == 0 {
            return self.write_off_raw_noalloc();
        }
        if writer_thread == current_thread {
            return first_write_ok;
        }
        let _ = self.write_off_raw_noalloc();
        false
    }

    fn write_off_raw_noalloc(&self) -> bool {
        let fd = self.direction_writer.as_raw_fd();
        let mut seek_completed = false;
        for _ in 0..AM3_BB_RAW_SYSCALL_EINTR_RETRY_LIMIT {
            // SAFETY: fd is an owned, pre-opened direction descriptor and
            // offset zero is the required sysfs command boundary.
            let result = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
            if result == 0 {
                seek_completed = true;
                break;
            }
            // SAFETY: errno is read immediately after the failed libc syscall.
            if result < 0 && unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return false;
        }
        if !seek_completed {
            return false;
        }
        let command = b"low";
        for _ in 0..AM3_BB_RAW_SYSCALL_EINTR_RETRY_LIMIT {
            // SAFETY: command is a live three-byte array and fd is the retained
            // direction writer; the pointer is used only for this syscall.
            let result = unsafe { libc::write(fd, command.as_ptr().cast(), command.len()) };
            if result == command.len() as isize {
                #[cfg(test)]
                return self.emulate_fixture_raw_low();
                #[cfg(not(test))]
                return true;
            }
            // SAFETY: errno is read immediately after the failed libc syscall.
            if result < 0 && unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return false;
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Am3BbBoardEnableState {
    PreparedOff,
    EnergizationOutcomeUnknown,
    Energized,
    TerminalOff,
}

/// Sole owner of the PSU GPIO65 ON transition. Emergency-only lanes never hold
/// this type and therefore cannot invoke the cold-boot energization trait.
struct Am3BbBoardEnableOwner {
    io: Am3BbPreparedBoardCutoff,
    on_writer: File,
    board_enable_active_high: bool,
    state: Am3BbBoardEnableState,
    psu_binding: Option<BbPsuControllerBinding>,
    #[cfg(test)]
    fail_on_readback_after_on_write: bool,
}

impl Am3BbBoardEnableOwner {
    fn gpio(&self) -> u32 {
        self.io.gpio()
    }

    fn off_level(&self) -> &'static str {
        self.io.off_level()
    }

    fn cut_checked(&mut self) -> Result<Am3BbCutoffTiming> {
        self.state = Am3BbBoardEnableState::EnergizationOutcomeUnknown;
        match self.io.cut_checked() {
            Ok(timing) => {
                self.state = Am3BbBoardEnableState::TerminalOff;
                Ok(timing)
            }
            Err(error) => Err(error),
        }
    }

    fn cutoff_io(&self) -> &Am3BbPreparedBoardCutoff {
        &self.io
    }

    fn write_on_checked(&self) -> Result<()> {
        if let Some(binding) = &self.psu_binding {
            anyhow::ensure!(self.gpio() == binding.gpio(), "BB PSU GPIO owner changed");
            binding.revalidate()?;
        }
        self.io.read_prepared_topology_checked()?;
        let mut writer = &self.on_writer;
        writer
            .seek(SeekFrom::Start(0))
            .with_context(|| format!("am3-bb: seek sole GPIO{} ON writer failed", self.io.gpio))?;
        writer
            .write_all(b"1")
            .with_context(|| format!("am3-bb: sole GPIO{} ON write failed", self.io.gpio))?;
        #[cfg(test)]
        anyhow::ensure!(
            !self.fail_on_readback_after_on_write,
            "am3-bb: injected GPIO{} ON readback failure after the HIGH write landed",
            self.io.gpio
        );
        self.io.read_on_checked()
    }
}

impl dcentrald_hal::platform::beaglebone_cold_boot::PreparedBoardEnable for Am3BbBoardEnableOwner {
    fn cut_checked(&mut self) -> dcentrald_hal::Result<()> {
        Am3BbBoardEnableOwner::cut_checked(self)
            .map(|_| ())
            .map_err(|error| dcentrald_hal::HalError::Gpio(format!("{error:#}")))
    }
    fn gpio(&self) -> u32 {
        self.io.gpio
    }

    fn board_enable_active_high(&self) -> bool {
        self.board_enable_active_high
    }

    fn assert_checked(&mut self) -> dcentrald_hal::Result<()> {
        if self.state != Am3BbBoardEnableState::PreparedOff
            || self.io.terminal.load(Ordering::SeqCst)
        {
            return Err(dcentrald_hal::HalError::Gpio(format!(
                "am3-bb: GPIO{} board-enable assertion requires live PreparedOff authority, observed state={:?} terminal={}",
                self.io.gpio,
                self.state,
                self.io.terminal.load(Ordering::SeqCst)
            )));
        }
        self.state = Am3BbBoardEnableState::EnergizationOutcomeUnknown;
        let writer_thread = Arc::clone(&self.io.on_writer_thread);
        let thread_token = am3_bb_current_thread_token();
        writer_thread
            .compare_exchange(0, thread_token, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|observed| {
                dcentrald_hal::HalError::Gpio(format!(
                    "am3-bb: GPIO{} ON writer publication was already owned by thread token {}",
                    self.io.gpio, observed
                ))
            })?;
        let _writer_publication = Am3BbOnWriterPublication { writer_thread };
        if self.io.terminal.load(Ordering::SeqCst) {
            self.state = Am3BbBoardEnableState::TerminalOff;
            return Err(dcentrald_hal::HalError::Gpio(format!(
                "am3-bb: GPIO{} terminal cutoff arrived before the sole ON write",
                self.io.gpio
            )));
        }
        if let Err(error) = self.write_on_checked() {
            let recut = self.io.cut_checked();
            self.state = if recut.is_ok() {
                Am3BbBoardEnableState::TerminalOff
            } else {
                Am3BbBoardEnableState::EnergizationOutcomeUnknown
            };
            return Err(dcentrald_hal::HalError::Gpio(format!(
                "am3-bb: GPIO{} ON assertion failed after ON-writer publication: {error:#}; mandatory OFF re-cut={recut:?}",
                self.io.gpio
            )));
        }
        if self.io.terminal.load(Ordering::SeqCst) {
            let recut = self.io.cut_checked();
            self.state = if recut.is_ok() {
                Am3BbBoardEnableState::TerminalOff
            } else {
                Am3BbBoardEnableState::EnergizationOutcomeUnknown
            };
            return Err(dcentrald_hal::HalError::Gpio(format!(
                "am3-bb: GPIO{} terminal cutoff raced board-enable assertion; mandatory OFF re-cut={:?}",
                self.io.gpio, recut
            )));
        }
        self.state = Am3BbBoardEnableState::Energized;
        Ok(())
    }
}

/// Borrowed OFF-only view used by the synchronous mining loop. It cannot
/// access the owner's `PreparedBoardEnable` implementation.
struct Am3BbRuntimeCutoff<'a> {
    owner: &'a mut Am3BbBoardEnableOwner,
}

impl Am3BbRuntimeCutoff<'_> {
    fn cut_checked(&mut self) -> Result<Am3BbCutoffTiming> {
        self.owner.cut_checked()
    }

    fn gpio(&self) -> u32 {
        self.owner.gpio()
    }

    fn off_level(&self) -> &'static str {
        self.owner.off_level()
    }
}

struct Am3BbPreparedBoardCutoffSet {
    runtime: Am3BbBoardEnableOwner,
    heartbeat: Am3BbPreparedBoardCutoff,
    panic: Am3BbPreparedBoardCutoff,
}

fn am3_bb_prepare_active_high_board_enable_off_at<F>(
    sysfs_root: &Path,
    gpio: u32,
    read_direction: F,
) -> Result<()>
where
    F: FnOnce(&Path) -> std::io::Result<String>,
{
    am3_bb_export_gpio_if_needed_at(sysfs_root, gpio)?;
    am3_bb_wait_gpio_attributes_at(sysfs_root, gpio)?;

    // `direction=low` atomically selects output mode and a LOW latch. This
    // is a raw physical-low operation on both supported sysfs GPIO kernels, so
    // it is safe even if an inherited export has active_low=1. Normalize the
    // logical polarity only after the physical LOW latch is established.
    let direction_path = am3_bb_gpio_dir_at(sysfs_root, gpio).join("direction");
    std::fs::write(&direction_path, "low").with_context(|| {
        format!(
            "am3-bb: establish glitch-free GPIO{} direction=low failed",
            gpio
        )
    })?;
    let direction = read_direction(&direction_path).with_context(|| {
        format!(
            "am3-bb: read GPIO{} direction after direction=low failed",
            gpio
        )
    })?;
    if direction.trim() != "out" {
        anyhow::bail!(
            "am3-bb: GPIO{} direction after direction=low was {:?}, expected out",
            gpio,
            direction.trim()
        );
    }
    am3_bb_write_gpio_attr_checked_at(sysfs_root, gpio, "active_low", "0")?;
    let value = std::fs::read_to_string(am3_bb_gpio_dir_at(sysfs_root, gpio).join("value"))
        .with_context(|| format!("am3-bb: read GPIO{} after direction=low failed", gpio))?;
    am3_bb_validate_gpio_attr_readback(gpio, "value", "0", &value)
}

fn am3_bb_prepare_board_cutoff_set_at_with_direction_readback<F>(
    sysfs_root: &Path,
    gpio: u32,
    board_enable_active_high: bool,
    read_direction: F,
    readback_mode: Am3BbRetainedReadbackMode,
) -> Result<Am3BbPreparedBoardCutoffSet>
where
    F: FnOnce(&Path) -> std::io::Result<String>,
{
    if !board_enable_active_high {
        anyhow::bail!(
            "am3-bb: retained GPIO{} cutoff supports only the admitted active-high board-enable topology",
            gpio
        );
    }
    let off_level = "0";
    am3_bb_prepare_active_high_board_enable_off_at(sysfs_root, gpio, read_direction)?;

    let terminal = Arc::new(AtomicBool::new(false));
    let on_writer_thread = Arc::new(AtomicUsize::new(0));
    let runtime = Am3BbPreparedBoardCutoff::open_at(
        sysfs_root,
        gpio,
        off_level,
        "runtime",
        readback_mode,
        Arc::clone(&terminal),
        Arc::clone(&on_writer_thread),
    )?;
    let on_value_path = am3_bb_gpio_dir_at(sysfs_root, gpio).join("value");
    let on_writer = std::fs::OpenOptions::new()
        .write(true)
        .open(&on_value_path)
        .with_context(|| {
            format!(
                "am3-bb: pre-open sole GPIO{} ON writer at {} failed",
                gpio,
                on_value_path.display()
            )
        })?;
    let heartbeat = Am3BbPreparedBoardCutoff::open_at(
        sysfs_root,
        gpio,
        off_level,
        "heartbeat",
        readback_mode,
        Arc::clone(&terminal),
        Arc::clone(&on_writer_thread),
    )?;
    let panic = Am3BbPreparedBoardCutoff::open_at(
        sysfs_root,
        gpio,
        off_level,
        "panic",
        readback_mode,
        terminal,
        on_writer_thread,
    )?;
    for (lane, name) in [(&runtime, "runtime"), (&heartbeat, "heartbeat")] {
        lane.write_off_checked().with_context(|| {
            format!(
                "am3-bb: retained GPIO{} {} cutoff lane failed pre-energization OFF preflight",
                gpio, name
            )
        })?;
    }
    if !panic.write_off_raw_noalloc() {
        anyhow::bail!(
            "am3-bb: retained GPIO{} panic cutoff lane failed raw lseek+write preflight",
            gpio
        );
    }
    panic.read_off_checked().with_context(|| {
        format!(
            "am3-bb: retained GPIO{} panic cutoff lane failed raw preflight readback",
            gpio
        )
    })?;
    Ok(Am3BbPreparedBoardCutoffSet {
        runtime: Am3BbBoardEnableOwner {
            io: runtime,
            on_writer,
            board_enable_active_high,
            state: Am3BbBoardEnableState::PreparedOff,
            psu_binding: None,
            #[cfg(test)]
            fail_on_readback_after_on_write: false,
        },
        heartbeat,
        panic,
    })
}

fn am3_bb_prepare_board_cutoff_set_at(
    sysfs_root: &Path,
    gpio: u32,
    board_enable_active_high: bool,
) -> Result<Am3BbPreparedBoardCutoffSet> {
    am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
        sysfs_root,
        gpio,
        board_enable_active_high,
        |path| std::fs::read_to_string(path),
        Am3BbRetainedReadbackMode::KernelSysfs,
    )
}

fn am3_bb_prepare_board_cutoff_set(
    gpio: u32,
    board_enable_active_high: bool,
) -> Result<Am3BbPreparedBoardCutoffSet> {
    am3_bb_prepare_board_cutoff_set_at(
        Path::new(AM3_BB_GPIO_SYSFS_ROOT),
        gpio,
        board_enable_active_high,
    )
}

fn am3_bb_reprepare_active_high_board_enable_off(gpio: u32) -> Result<()> {
    am3_bb_prepare_active_high_board_enable_off_at(
        Path::new(AM3_BB_GPIO_SYSFS_ROOT),
        gpio,
        |path| std::fs::read_to_string(path),
    )
}

fn am3_bb_quiet_safe_pwm(config_min_pwm: u8, config_max_pwm: u8) -> u8 {
    let cap = config_max_pwm.min(AM3_BB_FAN_HARD_CAP_PWM);
    if cap >= AM3_BB_FAN_SAFE_FLOOR_PWM {
        config_min_pwm.max(AM3_BB_FAN_SAFE_FLOOR_PWM).min(cap)
    } else {
        cap
    }
}

/// The absolute fan-PWM ceiling for the AM3 BB home/quiet posture.
///
/// This is the single chokepoint every PR-021 continuous-PID fan write passes
/// through. It is mathematically impossible for the return value to exceed
/// `AM3_BB_FAN_HARD_CAP_PWM` (30) — the home/night/space-heater hard cap from
///  and the rust-firmware rule
/// "NEVER allow fans above PWM 30 for home mining". `config_max_pwm` only ever
/// *lowers* the cap (an operator can ask for quieter, never louder); the floor
/// keeps the fan at the whisper-quiet boot level when the PID asks for less.
fn am3_bb_clamp_pid_pwm(config_min_pwm: u8, config_max_pwm: u8, requested: u8) -> u8 {
    let cap = config_max_pwm.min(AM3_BB_FAN_HARD_CAP_PWM);
    let floor = if cap >= AM3_BB_FAN_SAFE_FLOOR_PWM {
        config_min_pwm.max(AM3_BB_FAN_SAFE_FLOOR_PWM).min(cap)
    } else {
        // Operator deliberately set an even lower cap; honour it. Safety on
        // this board comes from cutting ASIC power, never from fan blast.
        cap
    };
    requested.clamp(floor, cap)
}

/// The thermal response, in the order it must happen.
///
/// Invariant #2 (cut hash power BEFORE raising fan noise) is encoded here as a
/// total order: at or above the dangerous threshold the answer is always
/// [`Am3BbThermalAction::CutHashThenFan`], which the caller services by failing
/// closed (`poll_and_check` failure → immediate retained PSU GPIO65 raw-LOW cut,
/// then dsPIC/reset defense-in-depth and quiet fan coast-down). The PID is only consulted in the
/// [`Am3BbThermalAction::PidWithinCap`] arm, i.e. while temperature is still
/// below dangerous — so the fan is only ever raised *within* the quiet cap and
/// only while hash power is still safely on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Am3BbThermalAction {
    /// temp < dangerous: let the capped PID trim the fan toward the setpoint.
    PidWithinCap,
    /// temp >= dangerous: cut hash power first; fan stays at the quiet cap.
    /// (The actual teardown is owned by the run-scope guard / fail-closed
    /// `poll_and_check`; the PID must NOT try to "out-cool" a dangerous temp
    /// by blasting — that is explicitly the wrong order.)
    CutHashThenFan,
}

/// Pure decision: given the hottest valid board temp and the dangerous
/// threshold, which response (and in which order) applies. Kept free of I/O so
/// it is host-testable and so the ordering invariant is a unit-tested contract.
fn am3_bb_thermal_action(max_temp_c: f32, dangerous_temp_c: f32) -> Am3BbThermalAction {
    if max_temp_c >= dangerous_temp_c {
        Am3BbThermalAction::CutHashThenFan
    } else {
        Am3BbThermalAction::PidWithinCap
    }
}

/// A clamp-enforced view onto the run guard's fan.
///
/// The run-scope [`Am3BbRunSafetyGuard`] retains ownership of the physical fan
/// for teardown; this is a cheap `Arc` clone the runtime PID borrows. EVERY
/// write goes through [`am3_bb_clamp_pid_pwm`], so this type cannot be used to
/// exceed the quiet cap even if a caller passes a bogus value. There is no
/// uncapped setter and no `set_speed_override` — by construction the PID can
/// only move the fan inside `[floor, min(fan_max_pwm, 30)]`.
#[derive(Clone)]
struct Am3BbCappedFan {
    fan: Arc<dyn FanAccess>,
    fan_min_pwm: u8,
    fan_max_pwm: u8,
}

impl Am3BbCappedFan {
    fn cap(&self) -> u8 {
        self.fan_max_pwm.min(AM3_BB_FAN_HARD_CAP_PWM)
    }

    fn floor(&self) -> u8 {
        am3_bb_quiet_safe_pwm(self.fan_min_pwm, self.fan_max_pwm)
    }

    /// Apply a PID-requested PWM, clamped to the quiet envelope. Returns the
    /// PWM actually written so the caller can log/track it.
    fn apply(&self, requested: u8) -> Result<u8> {
        let pwm = am3_bb_clamp_pid_pwm(self.fan_min_pwm, self.fan_max_pwm, requested);
        let receipt = self.fan.set_speed_checked(pwm)?;
        Ok(receipt.observed_pwm())
    }

    fn get_rpm(&self) -> u32 {
        self.fan.get_rpm()
    }

    fn tach_available(&self) -> bool {
        self.fan.tach_available()
    }
}

/// The PR-021 continuous fan PID.
///
/// Wraps the proven `dcentrald_thermal::controller::PidController` (reused, not
/// reinvented — same P + anti-windup-I + D math `daemon.rs` uses) and bolts on
/// the AM3 BB quiet-home guarantees:
///  - the PID output is clamped to `[floor, min(fan_max_pwm, 30)]` BEFORE it is
///    ever written (never above the home cap, never a transient spike);
///  - the commanded PWM walks toward the target at most
///    `AM3_BB_FAN_PID_MAX_STEP_PWM` per tick (no audible jump);
///  - on an EMPTY thermal sample the PID does NOT command anything — it holds
///    the last commanded PWM and lets the fail-closed `poll_and_check` own the
///    stale/empty decision (invariant #3: never act on absent sensor data);
///  - at/above the dangerous threshold the PID stops trimming and the caller's
///    fail-closed path cuts hash power first (invariant #2 ordering).
struct Am3BbFanPid {
    pid: dcentrald_thermal::controller::PidController,
    fan: Am3BbCappedFan,
    commanded_pwm: u8,
}

impl Am3BbFanPid {
    fn new(fan: Am3BbCappedFan, target_temp_c: u8) -> Result<Self> {
        let pid = dcentrald_thermal::controller::PidController::new(f32::from(target_temp_c));
        // Start at the quiet floor — the boot/whisper level. The PID only ever
        // climbs from here on measured need, and only within the cap.
        let floor = fan.floor();
        let commanded_pwm = fan.apply(floor)?;
        Ok(Self {
            pid,
            fan,
            commanded_pwm,
        })
    }

    /// Feed the supervisor's just-validated snapshot to the PID and move the
    /// fan one bounded step toward the (capped) target. `samples == 0` means
    /// the supervisor served a tolerated last-known-good window or is about to
    /// fail closed — either way we must NOT compute a fan action from absent
    /// data; hold station and return.
    fn step(&mut self, snapshot: &Am3BbThermalSnapshot, dangerous_temp_c: f32) -> Result<()> {
        if !snapshot.fresh || snapshot.samples == 0 || !snapshot.max_temp_c.is_finite() {
            // Invariant #3: no board/LM75 data → do not drive fans off empty
            // readings. The fail-closed supervisor decides stale-vs-tolerate.
            return Ok(());
        }

        // Invariant #2: at/above dangerous, the response is cut-hash-first.
        // The PID does not try to cool its way out by ramping the fan; the
        // caller's `poll_and_check` returns Err, immediately cuts PSU GPIO65, and
        // then performs dsPIC/reset defense-in-depth with the fan held at the
        // quiet cap. So here we simply stop trimming.
        if am3_bb_thermal_action(snapshot.max_temp_c, dangerous_temp_c)
            == Am3BbThermalAction::CutHashThenFan
        {
            return Ok(());
        }

        let target = self.pid.update(snapshot.max_temp_c);
        // The PID output is 0..=100; clamp into the quiet envelope first, then
        // rate-limit the slew so the fan never audibly jumps.
        let capped = am3_bb_clamp_pid_pwm(
            self.fan.fan_min_pwm,
            self.fan.fan_max_pwm,
            target.round() as u8,
        );
        let next = if capped > self.commanded_pwm {
            self.commanded_pwm
                .saturating_add(AM3_BB_FAN_PID_MAX_STEP_PWM)
                .min(capped)
        } else {
            self.commanded_pwm
                .saturating_sub(AM3_BB_FAN_PID_MAX_STEP_PWM)
                .max(capped)
        };
        // `apply` re-clamps defensively — even a logic bug above cannot leak a
        // PWM above the home cap past this point.
        self.commanded_pwm = self.fan.apply(next)?;
        Ok(())
    }

    fn commanded_pwm(&self) -> u8 {
        self.commanded_pwm
    }
}

/// Crash-panic-hook teardown params for the am3-bb path (wf_7c757213 safety
/// audit, 2026-05-29 — the cross-platform completion of the am2 + am3-aml panic
/// hooks shipped earlier this session).
///
/// Release builds use `panic = "abort"`, which BYPASSES `Am3BbRunSafetyGuard::Drop`.
/// am3-bb's fw=0x89 dsPIC has its own ~1-minute hardware watchdog that eventually
/// cuts voltage, but without this a panic would leave the hashboards ENERGIZED
/// (board-enable HIGH) for up to that full minute on a home/office unit. This stores
/// the minimal GPIO state so the `main()` crash hook can attempt board-power cutoff
/// before reset defense-in-depth and rely on watchdog reset if sysfs blocks or fails.
/// Mirrors the am2 `AM2_TEARDOWN_PARAMS` / am3-aml `NOPIC_TEARDOWN_ARMED` pattern.
///
/// Fans are intentionally NOT re-driven here: the am3-bb run holds fans at
/// `safe_pwm` (<= `PWM_SAFETY_MAX`) for the ENTIRE run via `Am3BbCappedFan`, so on a
/// panic they are already within the home cap by construction — and the BeagleBone
/// fan PWM sysfs node is kernel-variant-dependent (pwmchip0 / pwmchip2 / legacy
/// pwm1+pwm2), so a blind `duty_cycle` write from inside the panic hook would be a
/// guess (and the ns-period varies). Cutting board-enable removes the heat source,
/// which is the actual fire-risk mitigation.
struct Am3BbPanicTeardown {
    watchdog_feed_stop: WatchdogFeedStopSignal,
    board_cutoff: Am3BbPreparedBoardCutoff,
    reset_gpios: Vec<u32>,
}

static AM3BB_TEARDOWN_ARMED: std::sync::OnceLock<Am3BbPanicTeardown> = std::sync::OnceLock::new();

/// Arm the am3-bb crash-panic-hook teardown. Call exactly once, at guard-arm
/// time (before board-enable is driven HIGH). Duplicate arming is refused.
fn arm_am3_bb_teardown(
    platform: &BeagleBonePlatform,
    chain_count: usize,
    board_cutoff: Am3BbPreparedBoardCutoff,
    watchdog_feed_stop: WatchdogFeedStopSignal,
) -> Result<()> {
    AM3BB_TEARDOWN_ARMED
        .set(Am3BbPanicTeardown {
            watchdog_feed_stop,
            board_cutoff,
            reset_gpios: platform
                .chain_reset_gpios_v2_0()
                .into_iter()
                .take(chain_count)
                .collect(),
        })
        .map_err(|_| anyhow::anyhow!("am3-bb: panic teardown was already armed"))
}

/// Best-effort cut-hash teardown for the `main()` crash panic hook on the am3-bb
/// path. No-op unless an am3-bb run armed it. The watchdog's lock-free terminal
/// feed latch is published first, then the load-bearing retained PSU GPIO65 write;
/// reset defense-in-depth follows and may use ordinary sysfs helpers. The
/// retained userspace path allocates nothing, although Linux 5.4 kernfs may
/// allocate inside a sysfs write. Errors are swallowed so the hook cannot
/// re-panic. Fans are already <= `PWM_SAFETY_MAX` by construction.
pub fn am3_bb_panic_hook_best_effort_teardown() {
    if let Some(params) = AM3BB_TEARDOWN_ARMED.get() {
        params.watchdog_feed_stop.close_terminal_lock_free();
        let _ = params.board_cutoff.cut_raw_noalloc();
        for &gpio in &params.reset_gpios {
            let _ = am3_bb_prepare_output_gpio(gpio, true)
                .and_then(|_| am3_bb_write_gpio_attr_checked(gpio, "value", "1"));
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Am3BbDspicShutdownEvidence {
    delivery_attempts: usize,
    delivery_failures: usize,
    observation_attempts: usize,
    observation_failures: usize,
}

impl Am3BbDspicShutdownEvidence {
    fn all_delivered(self) -> bool {
        self.delivery_failures == 0
    }
}

/// Disable every active dsPIC in two ordered phases.
///
/// SafeOff delivery is the safety action; ACK reads are only observation.  The
/// first pass therefore admits every write-only SafeOff before the second pass
/// performs any optional read. A slow or broken chain-0 ACK can no longer delay
/// voltage-disable delivery to chains 1 and 2, and an observation failure does
/// not get misreported as a delivery failure.
fn am3_bb_disable_dspics_two_phase<D, O>(
    active_addrs: &[u8],
    observe_replies: bool,
    mut deliver: D,
    mut observe: O,
) -> Am3BbDspicShutdownEvidence
where
    D: FnMut(usize, u8) -> Result<()>,
    O: FnMut(usize, u8) -> Result<Vec<u8>>,
{
    let mut evidence = Am3BbDspicShutdownEvidence::default();
    let mut delivered = Vec::with_capacity(active_addrs.len());

    for &addr in active_addrs {
        let chain_idx = addr.saturating_sub(AM3_BB_DSPIC_BASE_ADDR) as usize;
        evidence.delivery_attempts += 1;
        match deliver(chain_idx, addr) {
            Ok(()) => {
                delivered.push((chain_idx, addr));
                info!(
                    chain = chain_idx,
                    addr = format_args!("0x{:02X}", addr),
                    "am3-bb: safety guard delivered dsPIC voltage-disable SafeOff"
                );
            }
            Err(e) => {
                evidence.delivery_failures += 1;
                warn!(
                    chain = chain_idx,
                    addr = format_args!("0x{:02X}", addr),
                    error = %e,
                    "am3-bb: safety guard failed to deliver dsPIC voltage-disable SafeOff"
                );
            }
        }
    }

    if !observe_replies {
        return evidence;
    }

    if !delivered.is_empty() {
        thread::sleep(Duration::from_millis(50));
    }

    for (chain_idx, addr) in delivered {
        evidence.observation_attempts += 1;
        match observe(chain_idx, addr) {
            Ok(reply) => info!(
                chain = chain_idx,
                addr = format_args!("0x{:02X}", addr),
                reply = format_args!("{:02X?}", reply),
                "am3-bb: safety guard observed dsPIC voltage-disable reply"
            ),
            Err(e) => {
                evidence.observation_failures += 1;
                warn!(
                    chain = chain_idx,
                    addr = format_args!("0x{:02X}", addr),
                    error = %e,
                    "am3-bb: dsPIC voltage-disable was delivered, but optional reply observation failed"
                );
            }
        }
    }

    evidence
}

struct Am3BbRunSafetyGuard {
    dspic_i2c: Option<I2cServiceHandle>,
    active_dspic_addrs: Vec<u8>,
    reset_gpios: Vec<u32>,
    board_enable: Am3BbBoardEnableOwner,
    heartbeat_board_cutoff: Option<Am3BbPreparedBoardCutoff>,
    panic_board_cutoff: Option<Am3BbPreparedBoardCutoff>,
    /// Shared so the runtime PID can borrow a clamp-enforced view
    /// ([`Am3BbCappedFan`]) while the guard keeps ownership for teardown. The
    /// PID can only ever drive this fan inside the quiet cap; the guard always
    /// re-asserts the quiet `safe_pwm` on teardown regardless of where the PID
    /// left it.
    fan: Option<Arc<dyn FanAccess>>,
    fan_min_pwm: u8,
    fan_max_pwm: u8,
    safe_pwm: u8,
    board_cutoff_receipt_issued: bool,
    teardown_done: bool,
}

/// One-shot proof that the load-bearing board-enable GPIO was driven to its
/// configured OFF level and read back before slower controller/reset cleanup.
/// This receipt is deliberately separate from the aggregate safe-off receipt:
/// defense-in-depth work may fail, but it must never delay or impersonate the
/// physical cutoff command.
#[derive(Debug)]
struct Am3BbBoardCutoffReceipt {
    board_enable_gpio: u32,
    off_level: &'static str,
    started_at: Instant,
    completed_at: Instant,
    teardown_budget: TeardownBudgetView,
}

/// Software safe-off evidence for AM3-BB. This proves checked sysfs command
/// and readback plus delivery of every conservatively owned dsPIC SafeOff; it
/// is not an independent measurement that the physical hash rail reached 0 V.
#[derive(Debug)]
pub(crate) struct Am3BbSafeOffReceipt {
    board_enable_gpio: u32,
    reset_count: usize,
    dspic_count: usize,
    teardown_budget: TeardownBudgetView,
}

impl Am3BbSafeOffReceipt {
    pub(crate) fn same_teardown_budget(&self, authority: &TeardownDisarmAuthority) -> bool {
        self.teardown_budget.same_budget(authority)
    }
}

impl Am3BbRunSafetyGuard {
    fn new(
        platform: &BeagleBonePlatform,
        dspic_i2c: Option<I2cServiceHandle>,
        active_dspic_addrs: Vec<u8>,
        chain_count: usize,
        fan_min_pwm: u8,
        fan_max_pwm: u8,
    ) -> Result<Self> {
        // GPIO59's historical label never proved a physical cutoff. Bind the
        // exact AM33XX PSU65 controller before any output or fan write, then
        // reuse the retained single-writer/independent-cutoff machinery.
        let psu_binding = BbPsuControllerBinding::observe_system()?;
        let mut board_cutoffs = am3_bb_prepare_board_cutoff_set(psu_binding.gpio(), true)?;
        board_cutoffs.runtime.psu_binding = Some(psu_binding);
        let safe_pwm = am3_bb_quiet_safe_pwm(fan_min_pwm, fan_max_pwm);
        let fan: Arc<dyn FanAccess> = Arc::from(
            platform
                .open_fan()
                .context("am3-bb: checked cooling admission could not open BeagleBone PWM")?,
        );
        let fan_receipt = fan
            .set_speed_checked(safe_pwm)
            .context("am3-bb: checked cooling admission failed")?;
        let rpm = fan.get_rpm();
        info!(
            requested_pwm = fan_receipt.requested_pwm(),
            observed_pwm = fan_receipt.observed_pwm(),
            rpm,
            tach_available = fan.tach_available(),
            fan_count = fan.fan_count(),
            "am3-bb: checked quiet fan guard armed"
        );

        Ok(Self {
            dspic_i2c,
            active_dspic_addrs,
            reset_gpios: platform
                .chain_reset_gpios_v2_0()
                .into_iter()
                .take(chain_count)
                .collect(),
            board_enable: board_cutoffs.runtime,
            heartbeat_board_cutoff: Some(board_cutoffs.heartbeat),
            panic_board_cutoff: Some(board_cutoffs.panic),
            fan: Some(fan),
            fan_min_pwm,
            fan_max_pwm,
            safe_pwm,
            board_cutoff_receipt_issued: false,
            teardown_done: false,
        })
    }

    fn set_dspic(&mut self, dspic_i2c: I2cServiceHandle, active_dspic_addrs: Vec<u8>) {
        self.dspic_i2c = Some(dspic_i2c);
        self.active_dspic_addrs.extend(active_dspic_addrs);
        self.active_dspic_addrs.sort_unstable();
        self.active_dspic_addrs.dedup();
        info!(
            owned_dspic_addrs = format_args!("{:02X?}", self.active_dspic_addrs),
            "am3-bb: safety guard owns every dsPIC that may have been energized"
        );
    }

    fn board_enable_owner(&mut self) -> &mut Am3BbBoardEnableOwner {
        &mut self.board_enable
    }

    fn runtime_cutoff(&mut self) -> Am3BbRuntimeCutoff<'_> {
        Am3BbRuntimeCutoff {
            owner: &mut self.board_enable,
        }
    }

    fn take_heartbeat_board_cutoff(&mut self) -> Result<Am3BbPreparedBoardCutoff> {
        self.heartbeat_board_cutoff.take().context(
            "am3-bb: pre-energization heartbeat PSU GPIO65 cutoff handle was already consumed",
        )
    }

    fn take_panic_board_cutoff(&mut self) -> Result<Am3BbPreparedBoardCutoff> {
        self.panic_board_cutoff
            .take()
            .context("am3-bb: pre-energization panic PSU GPIO65 cutoff handle was already consumed")
    }

    /// A clamp-enforced, `Arc`-shared view onto the guard's fan for the
    /// runtime PID. Returns `None` when the BeagleBone PWM could not be opened
    /// (the guard's ASIC voltage/reset path stays armed regardless — a missing
    /// fan must NOT block the fail-closed teardown). The guard keeps ownership
    /// and always re-asserts the quiet `safe_pwm` on teardown, so the worst the
    /// PID can do is move the fan inside the quiet cap during the run.
    fn capped_fan(&self) -> Option<Am3BbCappedFan> {
        self.fan.as_ref().map(|fan| Am3BbCappedFan {
            fan: Arc::clone(fan),
            fan_min_pwm: self.fan_min_pwm,
            fan_max_pwm: self.fan_max_pwm,
        })
    }

    fn cut_board_enable_checked(
        &mut self,
        teardown_budget: TeardownBudgetView,
    ) -> Result<Am3BbBoardCutoffReceipt> {
        if self.board_cutoff_receipt_issued {
            anyhow::bail!(
                "am3-bb: board-enable cutoff receipt was already issued; refusing to remint it"
            );
        }
        // The retained I/O primitive timestamps immediately after its seek and
        // immediately before the raw physical-LOW direction write. Export and
        // direction preparation completed before cold boot and cannot borrow
        // CutoffStart authority.
        let timing = self.board_enable.cut_checked().with_context(|| {
            format!(
                "am3-bb: checked retained board-enable GPIO{} cutoff to level {} failed",
                self.board_enable.gpio(),
                self.board_enable.off_level()
            )
        })?;
        let cutoff_started_timely = teardown_budget
            .remaining_at(TeardownStage::CutoffStart, timing.write_started_at)
            .is_ok();
        self.board_cutoff_receipt_issued = true;
        info!(
            gpio = self.board_enable.gpio(),
            off_level = self.board_enable.off_level(),
            cutoff_started_timely,
            "am3-bb: load-bearing board-enable cutoff completed before controller/reset cleanup"
        );
        Ok(Am3BbBoardCutoffReceipt {
            board_enable_gpio: self.board_enable.gpio(),
            off_level: self.board_enable.off_level(),
            started_at: timing.write_started_at,
            completed_at: timing.completed_at,
            teardown_budget,
        })
    }

    /// Abnormal-exit power cut for [`Drop`]. This deliberately returns only a
    /// boolean diagnostic: without the watchdog-issued teardown budget it can
    /// never be upgraded into clean-shutdown or Disarm authority.
    fn cut_board_enable_fallback(&mut self) -> bool {
        match self.board_enable.cut_checked() {
            Ok(_) => true,
            Err(error) => {
                warn!(
                    %error,
                    "am3-bb: retained runtime board-enable cutoff failed; using non-authorizing fallback"
                );
                am3_bb_force_board_enable_off(
                    self.board_enable.cutoff_io(),
                    "run-safety-guard-fallback",
                )
            }
        }
    }

    /// Controller/reset/fan defense-in-depth shared by the evidence-bearing
    /// closeout and the non-authorizing Drop fallback.
    fn run_defense_in_depth(&mut self) -> (Am3BbDspicShutdownEvidence, bool, bool) {
        let dspic_shutdown = self
            .dspic_i2c
            .as_ref()
            .map(|i2c| {
                // Terminal teardown deliberately skips optional ACK reads.
                // Once every write-only SafeOff is admitted, assert resets and
                // cut board-enable immediately; observation belongs to an
                // explicit diagnostic path and must never extend Drop latency.
                am3_bb_disable_dspics_two_phase(
                    &self.active_dspic_addrs,
                    false,
                    |chain_idx, addr| {
                        i2c.disable_dspic_voltage(
                            addr,
                            I2cDspicDisableProtocol::VnishPaddedFramed,
                        )
                        .with_context(|| {
                            format!(
                                "am3-bb chain {} dsPIC 0x{:02X}: safety-guard-disable-voltage SafeOff write failed",
                                chain_idx, addr
                            )
                        })?;
                        Ok(())
                    },
                    |_chain_idx, _addr| {
                        unreachable!(
                            "run-scope teardown skips optional ACK reads before the hard cutoff"
                        )
                    },
                )
            })
            .unwrap_or_default();
        let dspic_disable_ok = !self.active_dspic_addrs.is_empty()
            && self.dspic_i2c.is_some()
            && dspic_shutdown.all_delivered();

        let mut resets_asserted_ok = !self.reset_gpios.is_empty();
        for &gpio in &self.reset_gpios {
            if let Err(e) = am3_bb_prepare_output_gpio(gpio, true)
                .and_then(|_| am3_bb_write_gpio_attr_checked(gpio, "value", "1"))
            {
                resets_asserted_ok = false;
                warn!(
                    gpio,
                    error = %e,
                    "am3-bb: safety guard failed to assert active-low ASIC reset"
                );
            }
        }

        // Acoustic coast-down follows the power cut. Once PSU GPIO65 is checked
        // OFF, a fan readback failure is degraded evidence rather than a reason
        // to reboot and potentially re-energize a software-off rail.
        if let Some(fan) = self.fan.as_ref() {
            if let Err(error) = fan.set_speed_checked(self.safe_pwm) {
                warn!(
                    %error,
                    safe_pwm = self.safe_pwm,
                    "am3-bb: power is checked off, but quiet fan coast-down failed"
                );
            }
        }

        (dspic_shutdown, dspic_disable_ok, resets_asserted_ok)
    }

    fn teardown_checked(
        &mut self,
        mut board_cutoff: Option<Am3BbBoardCutoffReceipt>,
        teardown_budget: TeardownBudgetView,
    ) -> Result<Am3BbSafeOffReceipt> {
        if self.teardown_done {
            anyhow::bail!("am3-bb: safe-off was already attempted; receipt cannot be replayed");
        }

        // A failed early sysfs preparation/write is not a terminal attempt.
        // Retry the load-bearing checked cutoff before controller/reset work;
        // only a valid receipt can authorize Disarm. If the retry also fails,
        // Drop remains armed to attempt the non-authorizing fallback again.
        if board_cutoff.is_none() {
            match self.cut_board_enable_checked(teardown_budget.clone()) {
                Ok(receipt) => {
                    warn!(
                        gpio = receipt.board_enable_gpio,
                        "am3-bb: checked board-enable cutoff succeeded on teardown retry"
                    );
                    board_cutoff = Some(receipt);
                }
                Err(error) => warn!(
                    %error,
                    "am3-bb: checked board-enable cutoff retry failed; defense-in-depth and Drop fallback remain required"
                ),
            }
        }

        let expected_off_level = self.board_enable.off_level();
        let board_enable_off_ok = board_cutoff.is_some_and(|receipt| {
            receipt.board_enable_gpio == self.board_enable.gpio()
                && receipt.off_level == expected_off_level
                && receipt.teardown_budget.same_view(&teardown_budget)
                && teardown_budget
                    .require_not_before_start(receipt.started_at)
                    .is_ok()
                && teardown_budget
                    .require_completed_at(TeardownStage::CutoffStart, receipt.started_at)
                    .is_ok()
                && teardown_budget
                    .require_completed_at(TeardownStage::CutoffComplete, receipt.completed_at)
                    .is_ok()
        });

        // prod-readiness hunt #4 (log-honesty): track the two best-effort legs
        // (dsPIC disable + reset-assert) so the final summary doesn't affirm
        // "voltage off, resets asserted" when only the board-enable-off write
        // (the load-bearing cut) succeeded. Log-only — no command/ordering change.
        let (dspic_shutdown, dspic_disable_ok, resets_asserted_ok) = self.run_defense_in_depth();

        if !board_enable_off_ok {
            let fallback_ok = self.cut_board_enable_fallback();
            warn!(
                fallback_ok,
                "am3-bb: checked cutoff evidence was unavailable; repeated physical board-enable OFF without minting Disarm authority"
            );
        }

        if dspic_disable_ok && resets_asserted_ok && board_enable_off_ok {
            teardown_budget.require_completed_at(TeardownStage::CleanupComplete, Instant::now())?;
            self.teardown_done = true;
            info!(
                reset_gpios = ?self.reset_gpios,
                board_enable_gpio = self.board_enable.gpio(),
                board_enable_off_level = expected_off_level,
                safe_pwm = self.safe_pwm,
                dspic_delivery_attempts = dspic_shutdown.delivery_attempts,
                dspic_observation_failures = dspic_shutdown.observation_failures,
                "am3-bb: every owned dsPIC SafeOff and checked reset/PSU GPIO65 readback completed; physical rail-off was not independently measured"
            );
            Ok(Am3BbSafeOffReceipt {
                board_enable_gpio: self.board_enable.gpio(),
                reset_count: self.reset_gpios.len(),
                dspic_count: self.active_dspic_addrs.len(),
                teardown_budget,
            })
        } else {
            // prod-readiness hunt #4: board-enable-off (the load-bearing power
            // cut) succeeded, but one or more best-effort legs did NOT — say so
            // instead of affirming "voltage off, resets asserted".
            warn!(
                reset_gpios = ?self.reset_gpios,
                board_enable_gpio = self.board_enable.gpio(),
                board_enable_off_level = expected_off_level,
                safe_pwm = self.safe_pwm,
                dspic_disable_ok,
                dspic_delivery_attempts = dspic_shutdown.delivery_attempts,
                dspic_delivery_failures = dspic_shutdown.delivery_failures,
                dspic_observation_failures = dspic_shutdown.observation_failures,
                resets_asserted_ok,
                "am3-bb: safety guard drove board-enable OFF (the load-bearing power cut + quiet fan cap), \
                 but did NOT confirm all legs — dsPIC-disable and/or reset-assert reported errors above. \
                 The board-enable OFF command remains the safety net; physical rail-off was not independently measured."
            );
            anyhow::bail!(
                "am3-bb: incomplete safe-off evidence: dspic_disable_ok={}, resets_asserted_ok={}, board_enable_off_ok={}",
                dspic_disable_ok,
                resets_asserted_ok,
                board_enable_off_ok
            )
        }
    }
}

impl Drop for Am3BbRunSafetyGuard {
    fn drop(&mut self) {
        if !self.teardown_done {
            self.teardown_done = true;
            let board_enable_off_ok =
                self.board_cutoff_receipt_issued || self.cut_board_enable_fallback();
            let (dspic_shutdown, dspic_disable_ok, resets_asserted_ok) =
                self.run_defense_in_depth();
            if !(board_enable_off_ok && dspic_disable_ok && resets_asserted_ok) {
                warn!(
                    board_enable_off_ok,
                    dspic_disable_ok,
                    dspic_delivery_attempts = dspic_shutdown.delivery_attempts,
                    dspic_delivery_failures = dspic_shutdown.delivery_failures,
                    resets_asserted_ok,
                    "am3-bb: fail-closed Drop safe-off was incomplete; no clean-shutdown evidence was minted"
                );
            }
        }
    }
}

fn am3_bb_post_dspic_reset_chains(platform: &BeagleBonePlatform, chain_count: usize) -> Result<()> {
    let gpios = platform.chain_reset_gpios_v2_0();
    let active_gpios: Vec<u32> = gpios.into_iter().take(chain_count).collect();
    if active_gpios.is_empty() {
        return Ok(());
    }

    for &gpio in &active_gpios {
        am3_bb_write_reset_gpio(gpio, true)?;
    }
    thread::sleep(Duration::from_millis(
        AM3_BB_DSPIC_POST_ENABLE_RESET_ASSERT_MS,
    ));

    for &gpio in &active_gpios {
        am3_bb_write_reset_gpio(gpio, false)?;
        thread::sleep(Duration::from_millis(AM3_BB_DSPIC_INTER_CHAIN_RESET_MS));
    }
    thread::sleep(Duration::from_millis(
        AM3_BB_DSPIC_POST_ENABLE_RESET_RELEASE_MS,
    ));

    info!(
        reset_gpios = ?active_gpios,
        assert_ms = AM3_BB_DSPIC_POST_ENABLE_RESET_ASSERT_MS,
        release_settle_ms = AM3_BB_DSPIC_POST_ENABLE_RESET_RELEASE_MS,
        "am3-bb: ASIC resets re-pulsed after dsPIC rail enable"
    );
    Ok(())
}

struct Am3BbHeartbeatShutdownEvidence {
    actor_stop: ThreadRosterStop<Am3BbThreadSlot>,
    worker_timed_out: bool,
    worker_panicked: bool,
    hard_board_cut_attempted: bool,
    hard_board_cut_succeeded: bool,
}

impl Am3BbHeartbeatShutdownEvidence {
    fn graceful(&self) -> bool {
        !self.worker_timed_out && !self.worker_panicked
    }

    fn into_actor_receipt(self) -> Option<ThreadRosterQuiescenceReceipt<Am3BbThreadSlot>> {
        self.actor_stop.into_receipt()
    }
}

fn am3_bb_force_runtime_board_enable_off(
    board_cutoff: &mut Am3BbRuntimeCutoff<'_>,
    reason: &'static str,
) -> bool {
    match board_cutoff.cut_checked() {
        Ok(_) => {
            warn!(
                gpio = board_cutoff.gpio(),
                off_level = board_cutoff.off_level(),
                reason,
                "am3-bb: hard board-enable cutoff applied through retained runtime owner"
            );
            true
        }
        Err(retained_error) => {
            warn!(
                gpio = board_cutoff.gpio(),
                reason,
                error = %retained_error,
                "am3-bb: retained runtime cutoff failed; attempting non-authorizing glitch-free re-prepare"
            );
            am3_bb_reprepare_active_high_board_enable_off(board_cutoff.gpio()).is_ok()
        }
    }
}

fn am3_bb_force_board_enable_off(
    board_cutoff: &Am3BbPreparedBoardCutoff,
    reason: &'static str,
) -> bool {
    match board_cutoff.cut_checked() {
        Ok(_) => {
            warn!(
                gpio = board_cutoff.gpio(),
                off_level = board_cutoff.off_level(),
                reason,
                "am3-bb: hard board-enable cutoff applied through retained handle"
            );
            true
        }
        Err(retained_error) => {
            warn!(
                gpio = board_cutoff.gpio(),
                off_level = board_cutoff.off_level(),
                reason,
                error = %retained_error,
                "am3-bb: retained hard-cutoff handle failed; attempting non-authorizing sysfs re-prepare fallback"
            );
            match am3_bb_reprepare_active_high_board_enable_off(board_cutoff.gpio()) {
                Ok(()) => {
                    warn!(
                        gpio = board_cutoff.gpio(),
                        off_level = board_cutoff.off_level(),
                        reason,
                        "am3-bb: hard board-enable cutoff required sysfs re-prepare fallback"
                    );
                    true
                }
                Err(fallback_error) => {
                    warn!(
                        gpio = board_cutoff.gpio(),
                        off_level = board_cutoff.off_level(),
                        reason,
                        error = %fallback_error,
                        "am3-bb: retained and re-prepare hard board-enable cutoff both failed"
                    );
                    false
                }
            }
        }
    }
}

#[derive(Debug)]
enum Am3BbHeartbeatEvent {
    VerifiedHeartbeatReady { validated_chains: usize },
    TerminalFailure { reason: String },
    WorkerPanicked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Am3BbHeartbeatReadinessReceipt {
    validated_chains: usize,
}

struct Am3BbHeartbeatAdmission {
    events: std_mpsc::Receiver<Am3BbHeartbeatEvent>,
    expected_chains: usize,
    receipt: Option<Am3BbHeartbeatReadinessReceipt>,
    terminal_failure: Option<String>,
}

impl Am3BbHeartbeatAdmission {
    fn new(events: std_mpsc::Receiver<Am3BbHeartbeatEvent>, expected_chains: usize) -> Self {
        Self {
            events,
            expected_chains,
            receipt: None,
            terminal_failure: None,
        }
    }

    fn apply_event(&mut self, event: Am3BbHeartbeatEvent) {
        match event {
            Am3BbHeartbeatEvent::VerifiedHeartbeatReady { validated_chains }
                if validated_chains == self.expected_chains && validated_chains > 0 =>
            {
                self.receipt = Some(Am3BbHeartbeatReadinessReceipt { validated_chains });
            }
            Am3BbHeartbeatEvent::VerifiedHeartbeatReady { validated_chains } => {
                self.terminal_failure = Some(format!(
                    "heartbeat worker reported readiness for {validated_chains} chains; expected {}",
                    self.expected_chains
                ));
            }
            Am3BbHeartbeatEvent::TerminalFailure { reason } => {
                self.terminal_failure = Some(reason);
            }
            Am3BbHeartbeatEvent::WorkerPanicked => {
                self.terminal_failure = Some("heartbeat worker panicked".to_string());
            }
        }
    }

    fn drain_events(&mut self, stage: &'static str) -> Result<()> {
        loop {
            match self.events.try_recv() {
                Ok(event) => self.apply_event(event),
                Err(std_mpsc::TryRecvError::Empty) => break,
                Err(std_mpsc::TryRecvError::Disconnected) => {
                    if self.terminal_failure.is_none() {
                        self.terminal_failure = Some(
                            "heartbeat worker exited without terminal ownership evidence"
                                .to_string(),
                        );
                    }
                    break;
                }
            }
        }
        if let Some(reason) = &self.terminal_failure {
            anyhow::bail!("am3-bb: dsPIC heartbeat failed during {stage}: {reason}");
        }
        Ok(())
    }

    fn wait_for_verified_heartbeat_readiness(
        &mut self,
        shutdown: &CancellationToken,
        timeout: Duration,
    ) -> Result<Am3BbHeartbeatReadinessReceipt> {
        let deadline = Instant::now() + timeout;
        loop {
            self.drain_events("bring-up readiness")?;
            if let Some(receipt) = self.receipt {
                return Ok(receipt);
            }
            if shutdown.is_cancelled() {
                anyhow::bail!("am3-bb: shutdown requested before dsPIC framed heartbeat readiness");
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                anyhow::bail!(
                    "am3-bb: dsPIC heartbeat did not establish framed protocol readiness for {} chains within {} ms",
                    self.expected_chains,
                    timeout.as_millis()
                );
            }
            match self
                .events
                .recv_timeout(remaining.min(Duration::from_millis(50)))
            {
                Ok(event) => self.apply_event(event),
                Err(std_mpsc::RecvTimeoutError::Timeout) => {}
                Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                    self.terminal_failure =
                        Some("heartbeat worker exited before readiness admission".to_string());
                }
            }
        }
    }

    fn require_ready_and_healthy(&mut self, stage: &'static str) -> Result<()> {
        self.drain_events(stage)?;
        if self.receipt.is_none() {
            anyhow::bail!("am3-bb: verified dsPIC heartbeat readiness is missing before {stage}");
        }
        Ok(())
    }
}

struct Am3BbDspicHeartbeatGuard {
    threads: FixedThreadRosterGuard<Am3BbThreadSlot>,
    admission: Am3BbHeartbeatAdmission,
    board_cutoff: Am3BbPreparedBoardCutoff,
    explicitly_stopped: bool,
}

fn am3_bb_cut_on_heartbeat_error<T>(
    result: Result<T>,
    board_cutoff: &Am3BbPreparedBoardCutoff,
    reason: &'static str,
) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            let cutoff_succeeded = am3_bb_force_board_enable_off(board_cutoff, reason);
            Err(error.context(format!(
                "am3-bb: immediate retained PSU GPIO65 cutoff after heartbeat failure succeeded={cutoff_succeeded}"
            )))
        }
    }
}

impl Am3BbDspicHeartbeatGuard {
    fn wait_for_verified_heartbeat_readiness(
        &mut self,
        shutdown: &CancellationToken,
    ) -> Result<Am3BbHeartbeatReadinessReceipt> {
        let result = self.admission.wait_for_verified_heartbeat_readiness(
            shutdown,
            Duration::from_millis(AM3_BB_DSPIC_HEARTBEAT_READINESS_TIMEOUT_MS),
        );
        am3_bb_cut_on_heartbeat_error(
            result,
            &self.board_cutoff,
            "dspic-heartbeat-readiness-failure",
        )
    }

    fn require_ready_and_healthy(&mut self, stage: &'static str) -> Result<()> {
        let result = self.admission.require_ready_and_healthy(stage);
        am3_bb_cut_on_heartbeat_error(
            result,
            &self.board_cutoff,
            "dspic-heartbeat-terminal-failure",
        )
    }

    fn request_stop(&self) {
        self.threads.request_stop();
    }

    fn stop_and_join_until(
        &mut self,
        rt_handle: &tokio::runtime::Handle,
        deadline: Instant,
    ) -> Am3BbHeartbeatShutdownEvidence {
        let actor_stop = rt_handle.block_on(self.threads.stop_and_join_until(deadline));
        let worker_timed_out = actor_stop.any_timed_out();
        let worker_panicked = actor_stop.any_panicked();
        let hard_board_cut_attempted = worker_timed_out || worker_panicked;
        let hard_board_cut_succeeded = hard_board_cut_attempted
            && am3_bb_force_board_enable_off(&self.board_cutoff, "dspic-heartbeat-stop-failure");
        self.explicitly_stopped = true;
        Am3BbHeartbeatShutdownEvidence {
            actor_stop,
            worker_timed_out,
            worker_panicked,
            hard_board_cut_attempted,
            hard_board_cut_succeeded,
        }
    }
}

impl Drop for Am3BbDspicHeartbeatGuard {
    fn drop(&mut self) {
        // Drop must never wait on a transport thread. If the owner did not run
        // the explicit bounded stop path, cancel the worker and cut the board
        // enable out of band before detaching its JoinHandle.
        self.threads.request_stop();
        if !self.explicitly_stopped {
            let hard_board_cut_succeeded = am3_bb_force_board_enable_off(
                &self.board_cutoff,
                "dspic-heartbeat-owner-drop-without-quiescence",
            );
            warn!(
                hard_board_cut_succeeded,
                "am3-bb: dsPIC heartbeat owner dropped without explicit quiescence; worker detached after hard cutoff attempt"
            );
        }
    }
}

fn run_am3_bb_dspic_heartbeat_worker(
    i2c: I2cServiceHandle,
    active_addrs: Vec<u8>,
    stop_worker: CancellationToken,
    shutdown: CancellationToken,
    supervisor_disabled: bool,
    events: std_mpsc::Sender<Am3BbHeartbeatEvent>,
) {
    let mut tick = 0u64;
    let mut readiness_reported = false;
    let mut consecutive_failures = vec![0u8; active_addrs.len()];
    while !stop_worker.is_cancelled() {
        tick = tick.wrapping_add(1);
        let mut sweep_protocol_valid = true;
        for (chain_idx, addr) in active_addrs.iter().copied().enumerate() {
            if stop_worker.is_cancelled() {
                return;
            }
            match am3_bb_dspic_heartbeat_once(&i2c, chain_idx, addr) {
                Ok(reply) => {
                    consecutive_failures[chain_idx] = 0;
                    if tick.is_multiple_of(30) {
                        debug!(
                            chain = chain_idx,
                            addr = format_args!("0x{:02X}", addr),
                            reply = format_args!("{:02X?}", reply),
                            "am3-bb: dsPIC runtime heartbeat framed protocol check OK"
                        );
                    }
                }
                Err(e) => {
                    sweep_protocol_valid = false;
                    consecutive_failures[chain_idx] =
                        consecutive_failures[chain_idx].saturating_add(1);
                    if tick == 1 || tick.is_multiple_of(10) {
                        warn!(
                            chain = chain_idx,
                            addr = format_args!("0x{:02X}", addr),
                            consecutive_failures = consecutive_failures[chain_idx],
                            error = %e,
                            "am3-bb: dsPIC runtime heartbeat failed"
                        );
                    }
                    if !supervisor_disabled
                        && consecutive_failures[chain_idx] >= AM3_BB_DSPIC_HEARTBEAT_MAX_FAILURES
                    {
                        let reason = format!(
                            "chain {chain_idx} dsPIC 0x{addr:02X} reached {} consecutive heartbeat failures: {e:#}",
                            consecutive_failures[chain_idx]
                        );
                        warn!(
                            chain = chain_idx,
                            addr = format_args!("0x{:02X}", addr),
                            consecutive_failures = consecutive_failures[chain_idx],
                            max_failures = AM3_BB_DSPIC_HEARTBEAT_MAX_FAILURES,
                            "am3-bb: dsPIC heartbeat supervisor cancelling mining; safety guard will cut voltage"
                        );
                        let _ = events.send(Am3BbHeartbeatEvent::TerminalFailure { reason });
                        shutdown.cancel();
                        return;
                    }
                }
            }
            if stop_worker.is_cancelled() {
                return;
            }
        }

        if !readiness_reported && sweep_protocol_valid {
            if events
                .send(Am3BbHeartbeatEvent::VerifiedHeartbeatReady {
                    validated_chains: active_addrs.len(),
                })
                .is_err()
            {
                return;
            }
            readiness_reported = true;
        }

        let sleep_start = Instant::now();
        while sleep_start.elapsed() < Duration::from_millis(AM3_BB_DSPIC_HEARTBEAT_INTERVAL_MS) {
            if stop_worker.is_cancelled() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

fn start_am3_bb_dspic_heartbeat(
    actor_owner: ThreadRosterOwner<Am3BbThreadSlot>,
    i2c: I2cServiceHandle,
    active_addrs: Vec<u8>,
    shutdown: CancellationToken,
    board_cutoff: Am3BbPreparedBoardCutoff,
) -> Result<Am3BbDspicHeartbeatGuard> {
    if active_addrs.is_empty() {
        anyhow::bail!("am3-bb: refusing to start dsPIC heartbeat owner with zero controllers");
    }
    let expected_chains = active_addrs.len();
    let worker_stop = CancellationToken::new();
    let stop_worker = worker_stop.clone();
    let mut threads = actor_owner.activate(worker_stop);
    let actor_slot = threads.reserve(Am3BbThreadSlot::DspicHeartbeat)?;
    let supervisor_disabled = env_flag_set(ENV_AM3_BB_DISABLE_HEARTBEAT_SUPERVISOR);
    if supervisor_disabled {
        warn!(
            env = ENV_AM3_BB_DISABLE_HEARTBEAT_SUPERVISOR,
            "am3-bb: lab override active - dsPIC heartbeat failures will not cancel mining"
        );
    }
    let (events_tx, events_rx) = std_mpsc::channel();
    let panic_events = events_tx.clone();
    let panic_shutdown = shutdown.clone();
    let handle = thread::Builder::new()
        .name("am3-bb-dspic-heartbeat".to_string())
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                run_am3_bb_dspic_heartbeat_worker(
                    i2c,
                    active_addrs,
                    stop_worker,
                    shutdown,
                    supervisor_disabled,
                    events_tx,
                )
            }));
            if let Err(payload) = outcome {
                let _ = panic_events.send(Am3BbHeartbeatEvent::WorkerPanicked);
                panic_shutdown.cancel();
                resume_unwind(payload);
            }
        })
        .context("am3-bb: spawn dsPIC heartbeat thread failed")?;

    actor_slot.attach(handle);
    Ok(Am3BbDspicHeartbeatGuard {
        threads,
        admission: Am3BbHeartbeatAdmission::new(events_rx, expected_chains),
        board_cutoff,
        explicitly_stopped: false,
    })
}

fn am3_bb_require_heartbeat_for_energizing_boundary(
    heartbeat: Option<&mut Am3BbDspicHeartbeatGuard>,
    shutdown: &CancellationToken,
    heartbeat_required: bool,
    stage: &'static str,
) -> Result<()> {
    match heartbeat {
        Some(heartbeat) => heartbeat.require_ready_and_healthy(stage)?,
        None if heartbeat_required => {
            anyhow::bail!("am3-bb: dsPIC heartbeat owner is missing before {stage}");
        }
        None => {}
    }
    if shutdown.is_cancelled() {
        anyhow::bail!("am3-bb: shutdown requested before energizing phase {stage}");
    }
    Ok(())
}

fn am3_bb_wait_with_heartbeat_ownership(
    heartbeat: Option<&mut Am3BbDspicHeartbeatGuard>,
    shutdown: &CancellationToken,
    heartbeat_required: bool,
    duration: Duration,
    stage: &'static str,
) -> Result<()> {
    let deadline = Instant::now() + duration;
    let mut heartbeat = heartbeat;
    loop {
        am3_bb_require_heartbeat_for_energizing_boundary(
            heartbeat.as_deref_mut(),
            shutdown,
            heartbeat_required,
            stage,
        )?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        thread::sleep(remaining.min(Duration::from_millis(50)));
    }
}

/// BM1362 chip-side init for ONE chain. Returns the detected chip count
/// (the number of chip addresses we assigned).
///
/// Wire bytes from `dcentrald_asic::bm1362` builders — the chip protocol is
/// NOT reimplemented here.
///
/// **R7-3 note (2026-05-12): BM1362 needs NO open-core dummy-work** — it is not
/// the BM1387 14 nm; it activates its cores via init register writes (per
/// `dcentrald_asic::drivers::bm1362` module docs, verified against bosminer).
/// The old "N zero-payload `asic_work_t`" step is gone.
///
/// **Cold-boot register block (2026-05-13): wired in** — the core activation
/// that the proven Amlogic-NoPic serial path does is now ported here:
/// `0xA8` InitControl + MiscCtrl×3 + `0xA4` VersionMask
/// (Step 1, pre-fast-baud) → `0x3C`×2 (HashClk/ClkDelay) + `0x54` AnalogMux +
/// `0x58` IoDriver + `0x14` TicketMask + `0x10` HashCountingNumber (Step 4) →
/// `0x70`/`0x08` PLL ramp from 400 MHz to the configured target (Step 5) →
/// `0x28` FastUART + MiscCtrl×3 + host fast-baud (Step 6) → per-chip
/// `0xA8`/MiscCtrl×3/`0x3C`×3 loop (Step 7). The APW voltage opcodes are still
/// best-effort stubs; this chip-side sequence is now the proven register plan
/// adapted to direct `/dev/ttyS*` on AM335x.
#[derive(Clone, Copy, Debug)]
struct Bm1362ChainInitResult {
    assigned_chips: usize,
    initial_get_address_rx_bytes: usize,
    fast_get_address_rx_bytes: usize,
    initial_get_address_observation: Option<CrcVerifiedUnassignedGetAddressObservation>,
    fast_get_address_observation: Option<CrcVerifiedUnassignedGetAddressObservation>,
}

impl Bm1362ChainInitResult {
    fn rx_proven(self) -> bool {
        self.initial_get_address_rx_bytes > 0 || self.fast_get_address_rx_bytes > 0
    }
}

fn bm1362_chip_init_one_chain(
    uart: &mut Am3BbChainUart,
    chain_idx: usize,
    mining_baud: u32,
    fast_uart_value: u32,
    skip_fast_uart: bool,
    expected_chips_per_chain: usize,
    target_freq_mhz: u16,
    run_miscctrl_triple_write: bool,
) -> Result<Bm1362ChainInitResult> {
    let init_values = bm1362_am3_init_values_from_env();
    let legacy_init_order = env_flag_set(ENV_AM3_BB_LEGACY_INIT_ORDER);
    info!(
        chain = chain_idx,
        init_plan = init_values.label,
        legacy_init_order,
        init_control_bcast = format_args!("0x{:08X}", init_values.init_control_broadcast),
        init_control_per_chip = format_args!("0x{:08X}", init_values.init_control_per_chip),
        misc_pre_baud = format_args!("0x{:08X}", init_values.misc_control_pre_baud),
        misc_post_fast = format_args!("0x{:08X}", init_values.misc_control_post_fast_baud),
        "am3-bb: BM1362 init values selected"
    );

    // a. GetAddress broadcast @ 115200. Read whatever comes back as liveness;
    //    the parser can recognize the retained CRC-verified unassigned frame,
    //    but repeated frames are not unique-chip or chip-count evidence.
    let get_addr = build_get_address_frame();
    bm1362_write_cmd_frame(uart, &get_addr)
        .with_context(|| format!("am3-bb chain {}: GetAddress write failed", chain_idx))?;
    std::thread::sleep(Duration::from_millis(50));
    let mut rx = [0u8; 2048];
    let n = uart.read_bytes_timeout(&mut rx, 100);
    let initial_get_address_observation = if n == 0 {
        None
    } else {
        match inspect_am3_bb_get_address_stream(&rx[..n]) {
            Ok(observation) => Some(observation),
            Err(reason) => {
                warn!(
                    chain = chain_idx,
                    ?reason,
                    raw_bytes = n,
                    "am3-bb: GetAddress bytes are not a complete CRC-verified BM1362 unassigned-response stream; retaining liveness only"
                );
                None
            }
        }
    };
    // If nothing comes back, we still proceed — the live unit may need a
    // different enum baud / settle time. Repeated unassigned responses are
    // liveness frames, not unique-chip or chip-count evidence.
    let n_assign = expected_chips_per_chain.clamp(1, BM1362_MAX_CHIPS_PER_CHAIN);
    // Pure full-population stride SSOT (P1-3) — no open-coded 256/N.
    // `n_assign` is clamped to 1..=255 (BM1362_MAX_CHIPS_PER_CHAIN) above, so
    // the u8 narrowing is lossless by construction.
    let addr_interval = u16::from(dcentrald_common::bm1397plus_addr_interval(n_assign as u8));
    let mut n_fast = 0usize;
    let mut fast_get_address_observation = None;
    info!(
        chain = chain_idx,
        backend = uart.backend_name(),
        get_address_rx_bytes = n,
        parsed_observation = ?initial_get_address_observation,
        assigned_chips = n_assign,
        addr_interval,
        rx_preview = %hex_preview(&rx[..n], 96),
        "am3-bb: GetAddress enumeration response"
    );

    // Step 1 (@115200) — VersionMask first, then InitControl + MiscCtrl.
    // This mirrors the shared BM1362 driver. The previous AM3 BB order wrote
    // InitControl before the mask and only produced status/chatter frames.
    for _ in 0..3 {
        bm1362_bcast(
            uart,
            chain_idx,
            BM1362_REG_VERSION_MASK,
            BM1362_VERSION_MASK_VALUE,
            5,
            "VersionMask(0xA4)",
        )?;
    }
    bm1362_bcast(
        uart,
        chain_idx,
        BM1362_REG_INIT_CONTROL,
        init_values.init_control_broadcast,
        10,
        "InitControl(0xA8)",
    )?;
    if run_miscctrl_triple_write {
        bm1362_miscctrl_triple_write_bcast(
            uart,
            chain_idx,
            init_values.misc_control_pre_baud,
            "MiscCtrl(0x18) pre-baud",
        )?;
    }

    // b. ChainInactive ×3 + SetChipAddress for the configured chain length.
    // The live `a lab unit` GetAddress response can be truncated (64 bytes), so do not
    // size the chain from that rough byte count; S19j Pro BB chains are 126
    // chips and use address interval 256/126 => 2.
    let chain_inactive = build_chain_inactive_frame();
    for _ in 0..3 {
        bm1362_write_cmd_frame(uart, &chain_inactive)
            .with_context(|| format!("am3-bb chain {}: ChainInactive write failed", chain_idx))?;
        std::thread::sleep(Duration::from_millis(5));
    }
    for i in 0..n_assign {
        let chip_addr = (i as u16 * addr_interval) as u8;
        let f = build_set_chip_address_frame(chip_addr);
        bm1362_write_cmd_frame(uart, &f)
            .with_context(|| format!("am3-bb chain {}: SetChipAddress write failed", chain_idx))?;
        std::thread::sleep(Duration::from_millis(2));
    }

    if legacy_init_order {
        warn!(
            chain = chain_idx,
            "am3-bb: legacy BM1362 init order active; broadcast core/hash-count/PLL before per-chip loop"
        );
        bm1362_bcast(
            uart,
            chain_idx,
            BM1362_REG_CORE_CTRL,
            BM1362_CORE_REG_HASH_CLK,
            10,
            "CoreReg(0x3C) HashClk",
        )?;
        bm1362_bcast(
            uart,
            chain_idx,
            BM1362_REG_CORE_CTRL,
            BM1362_CORE_REG_CLK_DELAY,
            10,
            "CoreReg(0x3C) ClkDelay",
        )?;
    } else {
        // Canonical BM1362 order: address chips first, then program each chip's
        // InitControl/MiscCtrl/CoreReg block before any ticket/hash-count/PLL
        // work. The earlier AM3 path inverted this and produced no real shares.
        bm1362_per_chip_init_loop(
            uart,
            chain_idx,
            n_assign,
            addr_interval,
            init_values,
            run_miscctrl_triple_write,
            "bm1362_canonical_pre_baud_per_chip",
        )?;
    }

    // Ticket/IO/analog are broadcast after the per-chip block in the canonical
    // driver. Keep the same broadcast values for the legacy escape hatch.
    bm1362_bcast(
        uart,
        chain_idx,
        BM1362_REG_TICKET_MASK,
        BM1362_TICKET_MASK_256,
        10,
        "TicketMask(0x14)",
    )?;
    bm1362_bcast(
        uart,
        chain_idx,
        BM1362_REG_IO_DRIVER,
        BM1362_IO_DRIVER_NORMAL,
        10,
        "IoDriver(0x58)",
    )?;
    bm1362_bcast(
        uart,
        chain_idx,
        BM1362_REG_ANALOG_MUX,
        BM1362_ANALOG_MUX_VALUE,
        10,
        "AnalogMux(0x54)",
    )?;
    if legacy_init_order {
        bm1362_bcast(
            uart,
            chain_idx,
            BM1362_REG_NONCE_RANGE,
            BM1362_NONCE_RANGE_126,
            10,
            "HashCountingNumber(0x10)",
        )?;
        let pll_steps = bm1362_pll_ramp_to_target(target_freq_mhz);
        let write_pll0_divider = env_flag_set(ENV_AM3_BB_WRITE_PLL0_DIVIDER);
        if write_pll0_divider {
            warn!(
                chain = chain_idx,
                env = ENV_AM3_BB_WRITE_PLL0_DIVIDER,
                "am3-bb: lab override active - writing BM1362 PLL0 divider before PLL0 param"
            );
        }
        for (step_idx, (pll_param, actual_mhz)) in pll_steps.iter().copied().enumerate() {
            if write_pll0_divider {
                bm1362_bcast(
                    uart,
                    chain_idx,
                    BM1362_REG_PLL0_DIVIDER,
                    BM1362_PLL0_DIVIDER_VALUE,
                    10,
                    "PLL0 divider(0x70)",
                )?;
            }
            bm1362_bcast(
                uart,
                chain_idx,
                BM1362_REG_PLL0_PARAM,
                pll_param,
                10,
                "PLL0 param(0x08)",
            )?;
            debug!(
                chain = chain_idx,
                pll_step = step_idx + 1,
                pll_steps = pll_steps.len(),
                actual_mhz,
                pll_param = format_args!("0x{:08X}", pll_param),
                "am3-bb: legacy-order BM1362 PLL ramp step applied"
            );
            std::thread::sleep(Duration::from_millis(BM1362_PLL_RAMP_SETTLE_MS));
        }
        info!(
            chain = chain_idx,
            target_freq_mhz,
            final_freq_mhz = pll_steps
                .last()
                .map(|(_, mhz)| *mhz)
                .unwrap_or(target_freq_mhz),
            pll_steps = pll_steps.len(),
            "am3-bb: legacy-order BM1362 hash-count + PLL ramp applied before baud stage"
        );
    }
    bm1362_uart_relay_bcast(uart, chain_idx, "bm1362_pre_baud_broadcasts")?;

    if skip_fast_uart {
        warn!(
            chain = chain_idx,
            "am3-bb: skipping FastUART/host-baud switch; continuing post-init and work dispatch at 115200"
        );
    } else {
        // ── Rank 40 (goldmine ranks-40-50; 2026-06-10 desk RE, REVISED 2026-06-10
        // intelligence-exploitation pass) — the BM1370 high-speed UART regime is now
        // FIRST-HAND Ghidra-VERIFIED, and its transfer to BM1362 is REFUTED. Do NOT
        // port a PLL1 step into this BM1362 path.
        //
        // VERIFIED (S21pro jig `set_chain_baud@CB3B0`, BM1370, decompiled in full):
        //   if (baudrate < 0x2dc6c1 /* 3_000_001 */) {            // LOW regime
        //       reg 0x28 divider = 25_000_000 / (baud<<3);        // 25 MHz reference
        //   } else {                                             // HIGH regime
        //       reg 0x60 (PLL1) := (cache & 0xc088 | 0x111), hi |= 0x50000000;
        //       send_set_config(chain,1,0,0x60,pll1); usleep(10ms);  // written 2x
        //       send_set_config(chain,1,0,0x60,pll1); usleep(10ms);
        //       reg 0x28 divider = 400_000_000 / (baud<<3);       // PLL1 = 400 MHz
        //       reg 0x28 |= 0x84500000;                           // hi-speed enable
        //   }
        //   send_set_config(chain,1,0,0x28,...); set_bt8d_chain(chain,baud);
        // So for BM1370 a >3 Mbaud chain MUST reclock its UART off PLL1@400 MHz first.
        // 3.125 Mbaud (the BM136x/BM137x run baud, Saleae-confirmed on a live S19j Pro)
        // is above the 0x2dc6c1 threshold → this path is real for BM1370/S21.
        //
        // REFUTED for BM1362 (this AM3-BB / AM2-XIL path): BM1362's fast-baud is a
        // DIFFERENT, bosminer-faithful register protocol — reg 0x28 = 0x00003011
        // (broadcast) + reg 0x18 MiscCtrl = 0x00C100B0 (triple-write), byte-pinned from
        // the live `a lab unit` capture (`baud_switch.rs`). It shares NO structure with the
        // BM1370 jig path: no reg-0x60 PLL1 write, no 400 MHz divider, no 0x84500000.
        // bosminer is exactly the firmware driving the Saleae-captured 3.125 Mbaud
        // S19j Pro (BM1362) that mines successfully, and DCENT replays bosminer's
        // frames — so the chip-side baud sequence is NOT the gap. The BM1362
        // zero-nonce-at-fast-baud blocker is downstream on the HOST transport (PL-UART
        // MCR OUT2 / FPGA UART clock-out / dsPIC engagement) — exactly where the `a lab unit`
        // v+1 OUT2 work landed.
        // Therefore: do NOT add a BM1370 PLL1 step here. BM1362's own `set_chain_baud`
        // is NOT cleanly RE-able from held assets (stock S19j Pro bmminer is
        // symbol-stripped and delegates baud to the kernel `uart_trans.ko` — zero baud
        // strings; bosminer is 43k-fn stripped Rust). The only honest way to settle
        // whether bosminer does an UNcaptured BM1362 PLL step is a gated live A/B or a
        // luxminer decode — never by porting the BM1370 jig code.
        // Source: goldmine `deliverables/RANKS_40_50_DESK_RE.md` (rank 40 / C05) +
        // `SALEAE_PROTOCOL_REPORT.md`; .
        //
        // c. fast-baud upgrade: broadcast write FAST_UART_CONFIG(0x28).
        bm1362_bcast(
            uart,
            chain_idx,
            cold_boot_step::FAST_UART_CONFIG_REG,
            fast_uart_value,
            10,
            "FastUART(0x28)",
        )?;

        // Step 6 (cont.) — MiscCtrl(0x18) triple-write at 115200 BEFORE host
        // baud switch (proven trace order). Cadence: pure plan via
        // `bm1362_miscctrl_triple_write_bcast` (P1-1); board-target opt-in only
        //.
        if run_miscctrl_triple_write {
            bm1362_miscctrl_triple_write_bcast(
                uart,
                chain_idx,
                init_values.misc_control_post_fast_baud,
                "MiscCtrl(0x18) post-fast-uart-reg",
            )?;
            info!(
                chain = chain_idx,
                misc_post_fast = format_args!("0x{:08X}", init_values.misc_control_post_fast_baud),
                "am3-bb: MiscCtrl triple-write done after FastUART register write"
            );
        } else {
            info!(
                chain = chain_idx,
                "am3-bb: MiscCtrl triple-write SKIPPED (board-target run_miscctrl_triple_write=false)"
            );
        }

        // d. switch host UART to mining_baud. On AM335x the OMAP UART base
        // baud is 3 MHz, so the BM1362 0x28 FastUART handoff is followed by
        // divisor-1 3 Mbaud by default. The lab baud override lets live RE
        // sweep this without a rebuild.
        uart.drain_tx().with_context(|| {
            format!(
                "am3-bb chain {}: drain TX before set_baud({}) failed",
                chain_idx, mining_baud
            )
        })?;
        uart.set_baud(mining_baud).with_context(|| {
            format!(
                "am3-bb chain {}: set_baud({}) failed",
                chain_idx, mining_baud
            )
        })?;
        let fast_uart_settle_ms = parse_env_u32(ENV_AM3_BB_FAST_UART_SETTLE_MS)
            .map(u64::from)
            .unwrap_or(500);
        std::thread::sleep(Duration::from_millis(fast_uart_settle_ms));
        info!(
            chain = chain_idx,
            mining_baud,
            fast_uart_settle_ms,
            fast_uart = format_args!("0x{:08X}", fast_uart_value),
            "am3-bb: host UART switched to mining baud"
        );
        if env_flag_set(ENV_AM3_BB_SKIP_FAST_RELAY_AFTER_SWITCH) {
            warn!(
                chain = chain_idx,
                env = ENV_AM3_BB_SKIP_FAST_RELAY_AFTER_SWITCH,
                "am3-bb: lab override active - skipping UART_RELAY broadcast after host baud switch"
            );
        } else {
            bm1362_uart_relay_bcast(uart, chain_idx, "bm1362_step6_fast_baud")?;
        }

        // Fast-baud liveness probe. We do not trust the configured chip count
        // as a post-baud proof: if the host and ASIC baud rates disagree, every
        // later per-chip write becomes a silent no-op and mining yields zero
        // nonce frames.
        if let Err(e) = uart.drain_tx() {
            warn!(
                chain = chain_idx,
                error = %e,
                "am3-bb: fast-baud UART_RELAY TX drain failed before liveness probe"
            );
        }
        uart.flush_io();
        bm1362_write_cmd_frame(uart, &get_addr).with_context(|| {
            format!(
                "am3-bb chain {}: fast-baud GetAddress write failed",
                chain_idx
            )
        })?;
        let fast_getaddr_delay_ms = parse_env_u32(ENV_AM3_BB_FAST_GETADDR_DELAY_MS)
            .map(u64::from)
            .unwrap_or(50);
        let fast_getaddr_read_ms = parse_env_u32(ENV_AM3_BB_FAST_GETADDR_READ_MS)
            .map(u64::from)
            .unwrap_or(300);
        std::thread::sleep(Duration::from_millis(fast_getaddr_delay_ms));
        n_fast = uart.read_bytes_timeout(&mut rx, fast_getaddr_read_ms);
        if n_fast > 0 {
            match inspect_am3_bb_get_address_stream(&rx[..n_fast]) {
                Ok(observation) => fast_get_address_observation = Some(observation),
                Err(reason) => warn!(
                    chain = chain_idx,
                    ?reason,
                    raw_bytes = n_fast,
                    "am3-bb: fast-baud GetAddress bytes are not a complete CRC-verified BM1362 unassigned-response stream; retaining liveness only"
                ),
            }
        }
        uart.flush_io();
        if n_fast == 0 {
            warn!(
                chain = chain_idx,
                backend = uart.backend_name(),
                mining_baud,
                fast_uart = format_args!("0x{:08X}", fast_uart_value),
                fast_getaddr_delay_ms,
                fast_getaddr_read_ms,
                "am3-bb: fast-baud GetAddress returned no bytes; baud handoff may still be wrong"
            );
        } else {
            info!(
                chain = chain_idx,
                backend = uart.backend_name(),
                mining_baud,
                fast_uart = format_args!("0x{:08X}", fast_uart_value),
                fast_getaddr_delay_ms,
                fast_getaddr_read_ms,
                fast_get_address_rx_bytes = n_fast,
                parsed_observation = ?fast_get_address_observation,
                rx_preview = %hex_preview(&rx[..n_fast], 96),
                "am3-bb: fast-baud GetAddress liveness response"
            );
        }
    }

    if !legacy_init_order {
        bm1362_bcast(
            uart,
            chain_idx,
            BM1362_REG_NONCE_RANGE,
            BM1362_NONCE_RANGE_126,
            10,
            "HashCountingNumber(0x10)",
        )?;
        let pll_steps = bm1362_pll_ramp_to_target(target_freq_mhz);
        let write_pll0_divider = env_flag_set(ENV_AM3_BB_WRITE_PLL0_DIVIDER);
        if write_pll0_divider {
            warn!(
                chain = chain_idx,
                env = ENV_AM3_BB_WRITE_PLL0_DIVIDER,
                "am3-bb: lab override active - writing BM1362 PLL0 divider before PLL0 param"
            );
        }
        for (step_idx, (pll_param, actual_mhz)) in pll_steps.iter().copied().enumerate() {
            if write_pll0_divider {
                bm1362_bcast(
                    uart,
                    chain_idx,
                    BM1362_REG_PLL0_DIVIDER,
                    BM1362_PLL0_DIVIDER_VALUE,
                    10,
                    "PLL0 divider(0x70)",
                )?;
            }
            bm1362_bcast(
                uart,
                chain_idx,
                BM1362_REG_PLL0_PARAM,
                pll_param,
                10,
                "PLL0 param(0x08)",
            )?;
            debug!(
                chain = chain_idx,
                pll_step = step_idx + 1,
                pll_steps = pll_steps.len(),
                actual_mhz,
                pll_param = format_args!("0x{:08X}", pll_param),
                "am3-bb: canonical-order BM1362 PLL ramp step applied"
            );
            std::thread::sleep(Duration::from_millis(BM1362_PLL_RAMP_SETTLE_MS));
        }
        info!(
            chain = chain_idx,
            target_freq_mhz,
            final_freq_mhz = pll_steps
                .last()
                .map(|(_, mhz)| *mhz)
                .unwrap_or(target_freq_mhz),
            pll_steps = pll_steps.len(),
            "am3-bb: canonical-order BM1362 hash-count + PLL ramp applied after baud stage"
        );
    } else {
        bm1362_per_chip_init_loop(
            uart,
            chain_idx,
            n_assign,
            addr_interval,
            init_values,
            run_miscctrl_triple_write,
            "bm1362_legacy_post_baud_per_chip",
        )?;
    }

    bm1362_bcast(
        uart,
        chain_idx,
        BM1362_REG_VERSION_MASK,
        BM1362_VERSION_MASK_VALUE,
        10,
        "VersionMask(0xA4) final",
    )?;

    // No open-core dummy-work: BM1362 doesn't use BM1387-style 114-dummy-work
    // to gate its cores. The register plan above is the core gate.
    info!(
        chain = chain_idx,
        n_assign, legacy_init_order, "am3-bb: BM1362 chip-side init done"
    );

    Ok(Bm1362ChainInitResult {
        assigned_chips: n_assign,
        initial_get_address_rx_bytes: n,
        fast_get_address_rx_bytes: n_fast,
        initial_get_address_observation,
        fast_get_address_observation,
    })
}

// ===========================================================================
//  Mining loop (Option B2 — reuse dcentrald_stratum + the transport)
// ===========================================================================

/// One in-flight dispatched work unit, kept so a returned nonce can be
/// validated against the exact header that produced it.
///
/// Indexed by `asic_work_t.job_id` (low 8 bits — ):
/// the BM1362 nonce frame echoes the same 8-bit field. When the dispatcher
/// wraps 0..=255 the oldest entry at that slot is overwritten — work that old
/// is stale anyway, same as the transport's 16-slot in-flight ring.
#[derive(Clone)]
struct DispatchedWork {
    work_generation: dcentrald_stratum::WorkGeneration,
    job_id: String,
    extranonce2: String,
    ntime: u32,
    nbits: u32,
    version: u32,
    version_mask: u32,
    /// `prev_block_hash` AND `merkle_root` in header byte order (already
    /// word-reversed for `prev_block_hash` — `MiningWork` does that in
    /// `WorkBuilder::next_work`).
    prev_block_hash: [u8; 32],
    merkle_root: [u8; 32],
    share_target: [u8; 32],
}

impl DispatchedWork {
    /// Assemble the 80-byte block header for this work + a candidate nonce,
    /// using `rolled_version` (the base `version` with the BM1362-returned
    /// version-rolling bits applied — see [`rolled_version`]). Pass
    /// `self.version` for a non-version-rolled share.
    ///
    /// Layout matches `WorkBuilder`'s `header_prefix` + `serial_build_header`
    /// (version LE, prev_hash [already word-reversed by `WorkBuilder`],
    /// merkle_root [raw SHA-256d order], ntime LE, nbits LE) + the trailing
    /// nonce LE — i.e. the byte order that `validate_full_header` hashes to a
    /// valid share. (Same approach that got DCENT_axe / the Amlogic path their
    /// accepted shares.)
    fn full_header(&self, rolled_version: u32, nonce: u32) -> [u8; 80] {
        self.full_header_from_nonce_bytes(rolled_version, nonce.to_le_bytes())
    }

    /// Variant used only by live diagnostics to replay plausible nonce byte
    /// interpretations while keeping pool submission on the proven path.
    fn full_header_from_nonce_bytes(&self, rolled_version: u32, nonce_bytes: [u8; 4]) -> [u8; 80] {
        let mut h = [0u8; 80];
        h[0..4].copy_from_slice(&rolled_version.to_le_bytes());
        h[4..36].copy_from_slice(&self.prev_block_hash);
        h[36..68].copy_from_slice(&self.merkle_root);
        h[68..72].copy_from_slice(&self.ntime.to_le_bytes());
        h[72..76].copy_from_slice(&self.nbits.to_le_bytes());
        h[76..80].copy_from_slice(&nonce_bytes);
        h
    }
}

fn am3_bb_full_header_hash_be(header: &[u8; 80]) -> [u8; 32] {
    let hash = dcentrald_stratum::work::double_sha256(header);
    let mut hash_be = [0u8; 32];
    for i in 0..32 {
        hash_be[i] = hash[31 - i];
    }
    hash_be
}

fn am3_bb_achieved_difficulty_from_header(header: &[u8; 80]) -> Option<f64> {
    let hash_be = am3_bb_full_header_hash_be(header);
    let difficulty = dcentrald_stratum::v1::difficulty::hash_to_difficulty(&hash_be);
    if difficulty.is_finite() && difficulty > 0.0 {
        Some(difficulty)
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct Am3BbNonceReplay {
    job_id: String,
    nonce_label: &'static str,
    version_label: &'static str,
    nonce_submit: u32,
    rolled_version: u32,
    achieved_difficulty: Option<f64>,
}

fn rolled_version_or_shift_checked(
    base_version: u32,
    version_mask: u32,
    version_bits_raw: u16,
) -> Option<u32> {
    // Canonical BIP320 reconstruction: shift vbits_raw left 13, mask with
    // 0x1FFFE000, OR into base with the field cleared. The .79 BB serial
    // path's prior `version_mask == 0 → drop if vbits != 0` early return
    // was a silent-drop bug for any pool that doesn't negotiate
    // version-rolling. See
    // .
    let (rolled, _) =
        dcentrald_asic::bm1362::bip320_reconstruct_rolled_version(base_version, version_bits_raw);
    if version_mask == 0 {
        return Some(rolled);
    }
    let delta = rolled ^ base_version;
    if delta & !version_mask != 0 {
        return None;
    }
    Some(rolled)
}

fn rolled_version_no_shift_checked(
    base_version: u32,
    version_mask: u32,
    version_bits_raw: u16,
) -> Option<u32> {
    // Alternate replay codec where the chip returned vbits already in the
    // pool-mask layout (no shift). Pre-fix `version_mask == 0 → drop if
    // vbits != 0` was the same silent-drop bug as the shift variant.
    if version_mask == 0 {
        // Without a pool mask we don't know the no-shift bit positions —
        // fall back to the canonical shifted reconstruction so we still
        // submit something the pool can validate. validate_full_header
        // upstream is the SOLE gate.
        let (rolled, _) = dcentrald_asic::bm1362::bip320_reconstruct_rolled_version(
            base_version,
            version_bits_raw,
        );
        return Some(rolled);
    }

    let rolled =
        (base_version & !VERSION_ROLLING_FIELD_MASK) | ((version_bits_raw as u32) & version_mask);
    let delta = rolled ^ base_version;
    if delta & !version_mask != 0 {
        return None;
    }
    Some(rolled)
}

fn am3_bb_update_best_replay(best: &mut Option<Am3BbNonceReplay>, replay: Am3BbNonceReplay) {
    let replay_diff = replay.achieved_difficulty.unwrap_or(0.0);
    let best_diff = best
        .as_ref()
        .and_then(|b| b.achieved_difficulty)
        .unwrap_or(0.0);
    if replay_diff > best_diff {
        *best = Some(replay);
    }
}

fn am3_bb_replay_bm1362_nonce_decodes<'a, I>(
    history: I,
    nr: &Bm1362SerialNonce,
) -> (
    Option<Am3BbNonceReplay>,
    Option<Am3BbNonceReplay>,
    Option<Am3BbNonceReplay>,
    u32,
)
where
    I: IntoIterator<Item = &'a DispatchedWork>,
{
    let nonce_wire = [
        nr.raw_frame[2],
        nr.raw_frame[3],
        nr.raw_frame[4],
        nr.raw_frame[5],
    ];
    let nonce_be = u32::from_be_bytes(nonce_wire);
    let vbits_le = u16::from_le_bytes([nr.raw_frame[8], nr.raw_frame[9]]);
    let mut best_current = None;
    let mut best_any = None;
    let mut alternate_pool_hit = None;
    let mut version_rejects = 0u32;

    // Caller supplies newest-first (WorkHistoryRing::iter_newest_first) or any order.
    for candidate in history {
        let version_variants = [
            (
                "be_shift_replace",
                rolled_version_checked(
                    candidate.version,
                    candidate.version_mask,
                    nr.version_bits_raw,
                ),
            ),
            (
                "le_shift_replace",
                rolled_version_checked(candidate.version, candidate.version_mask, vbits_le),
            ),
            ("base_version", Some(candidate.version)),
            (
                "be_shift_or",
                rolled_version_or_shift_checked(
                    candidate.version,
                    candidate.version_mask,
                    nr.version_bits_raw,
                ),
            ),
            (
                "be_no_shift_replace",
                rolled_version_no_shift_checked(
                    candidate.version,
                    candidate.version_mask,
                    nr.version_bits_raw,
                ),
            ),
        ];
        let nonce_variants = [
            ("wire_le_header", nr.nonce, nr.nonce.to_le_bytes()),
            ("be_numeric_header", nonce_be, nonce_be.to_le_bytes()),
        ];

        for (version_label, maybe_version) in version_variants {
            let Some(rolled_version) = maybe_version else {
                version_rejects = version_rejects.saturating_add(1);
                continue;
            };
            for (nonce_label, nonce_submit, nonce_header_bytes) in nonce_variants {
                let header =
                    candidate.full_header_from_nonce_bytes(rolled_version, nonce_header_bytes);
                let achieved_difficulty = am3_bb_achieved_difficulty_from_header(&header);
                let replay = Am3BbNonceReplay {
                    job_id: candidate.job_id.clone(),
                    nonce_label,
                    version_label,
                    nonce_submit,
                    rolled_version,
                    achieved_difficulty,
                };
                let is_current =
                    nonce_label == "wire_le_header" && version_label == "be_shift_replace";
                if is_current {
                    am3_bb_update_best_replay(&mut best_current, replay.clone());
                }
                am3_bb_update_best_replay(&mut best_any, replay.clone());

                if !is_current
                    && dcentrald_stratum::share_pipeline::validate_full_header(
                        &header,
                        &candidate.share_target,
                    )
                {
                    alternate_pool_hit.get_or_insert(replay);
                }
            }
        }
    }

    (best_current, best_any, alternate_pool_hit, version_rejects)
}

/// Build the `dcentrald_stratum::StratumConfig` from the daemon config.
///
/// Mirrors the construction in `serial_mining.rs::SerialMiner::run` so the
/// am3-bb path gets the same failover/donation/version-rolling behavior; the
/// caller is responsible for spawning `StratumRouter::run` with it.
fn stratum_config_from(config: &DcentraldConfig) -> dcentrald_stratum::types::StratumConfig {
    crate::config::build_stratum_config(
        config,
        crate::config::stratum_donation_config(&config.donation),
        config.mining.version_rolling,
        false,
    )
}

/// Sole owner of terminal AM3 API state. Drop is fail-closed: any return before
/// a checked safe-off receipt publishes that physical safe-off is unproven.
struct Am3BbTerminalStatePublisher {
    state_tx: watch::Sender<dcentrald_api::MinerState>,
    safe_off_proven: bool,
    completed: bool,
}

impl Am3BbTerminalStatePublisher {
    fn new(state_tx: watch::Sender<dcentrald_api::MinerState>) -> Self {
        Self {
            state_tx,
            safe_off_proven: false,
            completed: false,
        }
    }

    fn publish(&self, pool_status: &str, chain_status: &str) {
        self.state_tx.send_modify(|state| {
            state.hashrate_ghs = 0.0;
            state.hashrate_5s_ghs = 0.0;
            state.pool.status = pool_status.to_string();
            state.pool.latency_ms = 0;
            for chain in &mut state.chains {
                chain.hashrate_ghs = 0.0;
                chain.status = chain_status.to_string();
            }
        });
    }

    fn begin_stopping(&self) {
        self.publish("stopping", "stopping_population_unproven");
    }

    fn record_safe_off(&mut self, mining_faulted: bool) {
        self.safe_off_proven = true;
        if mining_faulted {
            self.publish(
                "faulted_safe_off_proven",
                "faulted_population_unproven_safe_off_proven",
            );
        } else {
            self.publish(
                "stopping_safe_off_proven",
                "stopping_population_unproven_safe_off_proven",
            );
        }
    }

    fn finish_stopped(&mut self) {
        self.publish("stopped", "stopped_population_unproven");
        self.completed = true;
    }

    fn finish_never_energized(&mut self, _closeout: Am3BbNeverEnergizedCloseout) {
        self.safe_off_proven = true;
        self.publish("stopped_never_energized", "stopped_never_energized");
        self.completed = true;
    }
}

impl Drop for Am3BbTerminalStatePublisher {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if self.safe_off_proven {
            self.publish(
                "faulted_safe_off_proven",
                "faulted_population_unproven_safe_off_proven",
            );
        } else {
            self.publish(
                "faulted_safe_off_unproven",
                "faulted_population_unproven_safe_off_unproven",
            );
        }
    }
}

/// Owns every asynchronous AM3 Stratum publisher. The closed gate is checked
/// inside every status mutation closure, so a task already scheduled when
/// teardown begins cannot overwrite terminal state.
fn am3_bb_capped_cleanup_deadline(
    cleanup_deadline: Instant,
    now: Instant,
    stage_cap: Duration,
) -> Instant {
    now.checked_add(stage_cap)
        .unwrap_or(cleanup_deadline)
        .min(cleanup_deadline)
}

struct Am3BbStratumTaskGuard {
    rt_handle: tokio::runtime::Handle,
    shutdown: CancellationToken,
    router: Option<tokio::task::JoinHandle<()>>,
    status: Option<tokio::task::JoinHandle<()>>,
    publisher_closed: Arc<AtomicBool>,
}

impl Am3BbStratumTaskGuard {
    fn pending(
        rt_handle: tokio::runtime::Handle,
        shutdown: CancellationToken,
        publisher_closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            rt_handle,
            shutdown,
            router: None,
            status: None,
            publisher_closed,
        }
    }

    fn spawn_router(&mut self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        assert!(self.router.is_none(), "AM3 Stratum router spawned twice");
        self.router = Some(self.rt_handle.spawn(future));
    }

    fn spawn_status(&mut self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        assert!(
            self.status.is_none(),
            "AM3 Stratum status task spawned twice"
        );
        self.status = Some(self.rt_handle.spawn(future));
    }

    fn close_publisher(&self) {
        self.publisher_closed.store(true, Ordering::Release);
    }

    fn request_stop(&self) {
        self.close_publisher();
        self.shutdown.cancel();
    }

    fn stop_and_join(&mut self, deadline: Instant) -> Result<()> {
        self.request_stop();
        anyhow::ensure!(
            self.router.is_some() && self.status.is_some(),
            "am3-bb: incomplete Stratum task roster cannot be consumed (router_present={}, status_present={})",
            self.router.is_some(),
            self.status.is_some()
        );
        let mut router = self
            .router
            .take()
            .expect("complete Stratum roster was checked before router take");
        let mut status = self
            .status
            .take()
            .expect("complete Stratum roster was checked before status take");
        let joined = self.rt_handle.block_on(async {
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
                tokio::join!(&mut router, &mut status)
            })
            .await
        });
        let (router_result, status_result) = match joined {
            Ok(results) => results,
            Err(_) => {
                router.abort();
                status.abort();
                anyhow::bail!(
                    "am3-bb: Stratum tasks missed the absolute cancellation deadline; abort requested without an unbounded follow-up join (router_finished={}, status_finished={})",
                    router.is_finished(),
                    status.is_finished()
                );
            }
        };
        router_result.context("am3-bb: Stratum router task panicked during terminal join")?;
        status_result.context("am3-bb: Stratum status task panicked during terminal join")?;
        anyhow::ensure!(
            Instant::now() < deadline,
            "am3-bb: Stratum tasks completed at or after the strict absolute cancellation deadline"
        );
        Ok(())
    }
}

impl Drop for Am3BbStratumTaskGuard {
    fn drop(&mut self) {
        self.close_publisher();
        self.shutdown.cancel();
        if let Some(router) = self.router.take() {
            router.abort();
        }
        if let Some(status) = self.status.take() {
            status.abort();
        }
    }
}

struct Am3BbMiningLoopExit {
    mining_result: Result<()>,
    stratum_tasks: Am3BbStratumTaskGuard,
}

/// A preparation error from `run_mining_loop` is issued only before control is
/// transferred to the infallible-top-level `run_started_mining_loop` phase.
/// The started phase owns every asynchronous spawn and captures operational
/// failures in `Am3BbMiningLoopExit::mining_result`, so the caller can
/// positively classify the Stratum roster as never spawned instead of
/// inventing unknown ownership.
#[derive(Debug)]
struct Am3BbMiningLoopNotStarted(anyhow::Error);

impl Am3BbMiningLoopNotStarted {
    fn into_source(self) -> anyhow::Error {
        self.0
    }
}

/// The Option-B2 mining loop: Stratum (router on `rt_handle`) ↔ this blocking
/// thread (work-build + paced dispatch + nonce-validate + dedup + submit).
///
/// Thermal: the run-scope guard keeps fan PWM capped at quiet home-mining levels
/// and cuts ASIC voltage/resets on exit, heartbeat failure, or an LM75 overtemp.
/// PR-021 adds a CONTINUOUS, capped fan PID on top of (not instead of) that
/// fail-closed supervisor: every runtime LM75 poll that the supervisor
/// validates is also fed to an `Am3BbFanPid` that trims the fan toward the
/// configured target temperature, hard-clamped to `min(fan_max_pwm, 30)` and
/// rate-limited so the home unit stays quiet. The proven fail-closed checks
/// (stale/empty → tolerate-or-cut, dangerous → cut hash first) are unchanged.
fn run_mining_loop<U: ChainUart>(
    config: &DcentraldConfig,
    transport: &mut Am335xUartTransport<U>,
    total_chips: usize,
    shutdown: &CancellationToken,
    heartbeat: &mut Am3BbDspicHeartbeatGuard,
    rt_handle: &tokio::runtime::Handle,
    thermal_i2c: Option<I2cServiceHandle>,
    thermal_dspic_addrs: Vec<u8>,
    pid_fan: Option<Am3BbCappedFan>,
    watchdog: &mut SafetyWatchdogOwner,
    watchdog_liveness: SafetyLiveness,
    hardware_mutation_owner: &HardwareMutationGateOwner,
    board_cutoff: &mut Am3BbRuntimeCutoff<'_>,
    state_tx: watch::Sender<dcentrald_api::MinerState>,
) -> std::result::Result<Am3BbMiningLoopExit, Am3BbMiningLoopNotStarted> {
    if config.pool.url.trim().is_empty() || config.pool.worker.trim().is_empty() {
        return Err(Am3BbMiningLoopNotStarted(anyhow::anyhow!(
            "am3-bb: mining loop requires a non-empty pool.url AND pool.worker — set a real BTC address. \
             (Use DCENT_AM3_BB_STUB_LOOP=1 for a cold-boot/enum-only run with no pool.)"
        )));
    }

    if env_flag_set(ENV_AM3_BB_SKIP_THERMAL_SUPERVISOR) {
        return Err(Am3BbMiningLoopNotStarted(anyhow::anyhow!(
            "am3-bb: watched Mining admission forbids {}",
            ENV_AM3_BB_SKIP_THERMAL_SUPERVISOR
        )));
    }
    let Some(i2c) = thermal_i2c else {
        return Err(Am3BbMiningLoopNotStarted(anyhow::anyhow!(
            "am3-bb: runtime LM75 thermal supervisor requires dsPIC I2C access"
        )));
    };
    let mut thermal_supervisor = Am3BbThermalSupervisor::new(
        i2c,
        thermal_dspic_addrs,
        transport.chain_count(),
        config.thermal.hot_temp_c,
        config.thermal.dangerous_temp_c,
    )
    .map_err(Am3BbMiningLoopNotStarted)?;
    thermal_supervisor
        .poll_and_check("pre-stratum")
        .map_err(Am3BbMiningLoopNotStarted)?;
    let thermal_poll_ms =
        am3_bb_thermal_poll_interval(config.thermal.pid_interval_s).as_millis() as u64;

    // PR-021: the CONTINUOUS, capped fan PID. Default-ON. The lab escape hatch
    // can only park the PID (revert to the pre-PR-021 pinned-fan behaviour) —
    // it can never raise a cap or relax a fail-closed path. The PID is also
    // skipped (gracefully, not fatally) when the BeagleBone PWM never opened or
    // when the fail-closed supervisor itself is disabled (lab override): with
    // no validated thermal proof there is nothing safe to drive a PID from.
    if env_flag_set(ENV_AM3_BB_DISABLE_FAN_PID) {
        return Err(Am3BbMiningLoopNotStarted(anyhow::anyhow!(
            "am3-bb: watched Mining admission forbids {}",
            ENV_AM3_BB_DISABLE_FAN_PID
        )));
    }
    let fan = pid_fan
        .context("am3-bb: watched Mining admission requires checked BeagleBone fan ownership")
        .map_err(Am3BbMiningLoopNotStarted)?;
    let mut fan_pid =
        Am3BbFanPid::new(fan, config.thermal.target_temp_c).map_err(Am3BbMiningLoopNotStarted)?;
    info!(
        target_temp_c = config.thermal.target_temp_c,
        start_pwm = fan_pid.commanded_pwm(),
        "am3-bb: continuous checked fan PID armed (clamped to the quiet home cap)"
    );

    // Mining liveness begins only after transport, fresh thermal proof, the
    // dsPIC heartbeat owner, and checked fan actuation are all established.
    am3_bb_require_heartbeat_for_energizing_boundary(
        Some(heartbeat),
        shutdown,
        true,
        "watched Mining admission",
    )
    .map_err(Am3BbMiningLoopNotStarted)?;
    rt_handle
        .block_on(watchdog.enter_mining())
        .map_err(Am3BbMiningLoopNotStarted)?;
    let api_admission = hardware_mutation_owner
        .open()
        .map_err(anyhow::Error::new)
        .map_err(Am3BbMiningLoopNotStarted)?;
    info!(
        opened_at = ?api_admission.opened_at(),
        "am3-bb: API hardware-mutation admission opened after Mining readiness"
    );

    info!(
        fan_min_pwm = config.thermal.fan_min_pwm,
        fan_max_pwm = config.thermal.fan_max_pwm,
        fan_hard_cap_pwm = AM3_BB_FAN_HARD_CAP_PWM,
        target_temp_c = config.thermal.target_temp_c,
        hot_temp_c = config.thermal.hot_temp_c,
        dangerous_temp_c = config.thermal.dangerous_temp_c,
        thermal_poll_ms,
        supervisor_enabled = true,
        fan_pid_enabled = true,
        "am3-bb: quiet thermal guard active (fail-closed LM75 hard-stop + continuous capped fan PID)"
    );

    Ok(run_started_mining_loop(
        config,
        transport,
        total_chips,
        shutdown,
        heartbeat,
        rt_handle,
        thermal_supervisor,
        thermal_poll_ms,
        fan_pid,
        watchdog_liveness,
        board_cutoff,
        state_tx,
    ))
}

/// Started AM3 mining phase.
///
/// This function is deliberately infallible at its top level: once it owns a
/// Stratum task, every operational outcome is returned inside
/// `Am3BbMiningLoopExit`, together with the complete task-owner guard.
fn run_started_mining_loop<U: ChainUart>(
    config: &DcentraldConfig,
    transport: &mut Am335xUartTransport<U>,
    total_chips: usize,
    shutdown: &CancellationToken,
    heartbeat: &mut Am3BbDspicHeartbeatGuard,
    rt_handle: &tokio::runtime::Handle,
    mut thermal_supervisor: Am3BbThermalSupervisor,
    thermal_poll_ms: u64,
    mut fan_pid: Am3BbFanPid,
    watchdog_liveness: SafetyLiveness,
    board_cutoff: &mut Am3BbRuntimeCutoff<'_>,
    state_tx: watch::Sender<dcentrald_api::MinerState>,
) -> Am3BbMiningLoopExit {
    use dcentrald_stratum::share_pipeline::{validate_full_header, WorkBuilder};

    // --- Stratum channels (same shape serial_mining.rs uses). ---
    let (job_tx, mut job_rx) = mpsc::channel::<dcentrald_stratum::types::JobTemplate>(32);
    let (share_tx, share_rx) = mpsc::channel::<dcentrald_stratum::types::ValidShare>(256);
    let (status_tx, mut status_rx) = mpsc::channel::<dcentrald_stratum::types::StratumStatus>(64);

    let stratum_config = stratum_config_from(config);
    let router = dcentrald_stratum::StratumRouter::new(stratum_config);
    let stratum_tasks_shutdown = CancellationToken::new();
    let publisher_closed = Arc::new(AtomicBool::new(false));
    // Establish cancellation and Drop ownership before the first spawn. No raw
    // JoinHandle may ever exist outside this guard across another operation.
    let mut stratum_tasks = Am3BbStratumTaskGuard::pending(
        rt_handle.clone(),
        stratum_tasks_shutdown.clone(),
        publisher_closed.clone(),
    );
    let router_shutdown = stratum_tasks_shutdown.clone();
    stratum_tasks.spawn_router(async move {
        tokio::select! {
            biased;
            _ = router_shutdown.cancelled() => {}
            _ = router.run(job_tx, share_rx, status_tx) => {}
        }
    });
    state_tx.send_modify(|state| {
        state.pool.url = config.pool.url.clone();
        state.pool.worker = config.pool.worker.clone();
        state.pool.protocol = config
            .pool
            .protocol
            .clone()
            .unwrap_or_else(|| "sv1".to_string());
        // The configured address plan is not measured enumeration. Publish
        // three known UART lanes with zero observed chips until an exact
        // current-run population receipt exists.
        state.chains = (0..transport.chain_count())
            .map(|chain| dcentrald_api::ChainState {
                id: chain as u8,
                chips: 0,
                frequency_mhz: 0,
                voltage_mv: 0,
                temp_c: 0.0,
                temp_source: None,
                hashrate_ghs: 0.0,
                errors: 0,
                status: "population_unproven".to_string(),
            })
            .collect();
    });
    // Drain Stratum status events on the runtime so the channel doesn't back
    // up and project pool-acknowledged state into the dashboard/API channel.
    let status_state_tx = state_tx.clone();
    let status_shutdown = stratum_tasks_shutdown.clone();
    let status_publisher_closed = publisher_closed.clone();
    let alert_bind = crate::runtime::notifications::MiningAlertMonitorBind::from_config(config);
    let alert_webhook =
        crate::runtime::notifications::RuntimeWebhookConfig::from(config.webhook.clone());
    let alert_miner_name = config.general.hostname.clone();
    stratum_tasks.spawn_status(async move {
        const DIFF1_HASHES: f64 = 4_294_967_296.0;
        let started = Instant::now();
        let mut accepted_difficulty_sum = 0.0_f64;
        let mut recent_accepted = VecDeque::<(Instant, f64)>::new();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        // Rank-19: MiningAlertMonitor on the am3-bb path. Daemon::run already
        // owns one; hybrid is a sibling file. Default-OFF webhook dispatch.
        let mut alert_monitor = crate::runtime::notifications::MiningAlertMonitor::new();
        let alert_tx = crate::runtime::notifications::spawn_alert_event_dispatcher(
            alert_webhook,
            alert_miner_name,
            status_shutdown.clone(),
        );
        loop {
            tokio::select! {
                biased;
                _ = status_shutdown.cancelled() => break,
                _ = tick.tick() => {
                    let now = Instant::now();
                    while recent_accepted.front().is_some_and(|(at, _)| {
                        now.duration_since(*at) > Duration::from_secs(5)
                    }) {
                        recent_accepted.pop_front();
                    }
                    let recent_difficulty: f64 = recent_accepted
                        .iter()
                        .map(|(_, difficulty)| *difficulty)
                        .sum();
                    let uptime_s = started.elapsed().as_secs();
                    let lifetime_ghs = accepted_difficulty_sum * DIFF1_HASHES
                        / started.elapsed().as_secs_f64().max(1.0)
                        / 1_000_000_000.0;
                    let recent_ghs =
                        recent_difficulty * DIFF1_HASHES / 5.0 / 1_000_000_000.0;
                    status_state_tx.send_modify(|state| {
                        if status_publisher_closed.load(Ordering::Acquire) {
                            return;
                        }
                        state.uptime_s = uptime_s;
                        state.hashrate_ghs = lifetime_ghs;
                        state.hashrate_5s_ghs = recent_ghs;
                    });
                    let health_state = status_state_tx.borrow().clone();
                    let snap = crate::runtime::notifications::mining_health_snapshot_from_state(
                        &health_state,
                        &alert_bind,
                    );
                    for event in alert_monitor.evaluate(&snap, Instant::now()) {
                        let event_name = event.event_name();
                        if let Err(err) = alert_tx.try_send(event) {
                            tracing::debug!(
                                event = event_name,
                                error = %err,
                                "am3-bb mining-health alert dropped (alert channel full or closed)"
                            );
                        }
                    }
                }
                status = status_rx.recv() => {
                    let Some(st) = status else { break; };
                    match st {
                        dcentrald_stratum::types::StratumStatus::ShareAccepted {
                            job_id,
                            pool_target_difficulty,
                            ..
                        } => {
                            let credited = if pool_target_difficulty.is_finite()
                                && pool_target_difficulty > 0.0
                            {
                                pool_target_difficulty
                            } else {
                                0.0
                            };
                            accepted_difficulty_sum += credited;
                            recent_accepted.push_back((Instant::now(), credited));
                            status_state_tx.send_modify(|state| {
                                if status_publisher_closed.load(Ordering::Acquire) {
                                    return;
                                }
                                state.accepted = state.accepted.saturating_add(1);
                                state.pool.status = "mining".to_string();
                                state.pool.last_share_at = dcentrald_api::unix_epoch_ms() / 1000;
                                state.pool.difficulty = credited;
                            });
                            info!(job_id = %job_id, pool_target_difficulty, "am3-bb: SHARE ACCEPTED")
                        }
                        dcentrald_stratum::types::StratumStatus::ShareRejected {
                            job_id,
                            error_code,
                            error_msg,
                            ..
                        } => {
                            status_state_tx.send_modify(|state| {
                                if status_publisher_closed.load(Ordering::Acquire) {
                                    return;
                                }
                                state.rejected = state.rejected.saturating_add(1);
                                let bucket = dcentrald_api::classify_reject_reason(
                                    error_code,
                                    &error_msg,
                                );
                                state.pool.reject_reason_counts[bucket] = state.pool
                                    .reject_reason_counts[bucket]
                                    .saturating_add(1);
                            });
                            warn!(job_id = %job_id, error = %error_msg, "am3-bb: SHARE REJECTED")
                        }
                        dcentrald_stratum::types::StratumStatus::DifficultyChanged(difficulty) => {
                            if difficulty.is_finite() && difficulty >= 0.0 {
                                status_state_tx.send_modify(|state| {
                                    if status_publisher_closed.load(Ordering::Acquire) {
                                        return;
                                    }
                                    state.pool.difficulty = difficulty;
                                });
                            }
                            info!(difficulty, "am3-bb: pool difficulty")
                        }
                        dcentrald_stratum::types::StratumStatus::StateChanged(pool_state) => {
                            let status = match pool_state {
                                dcentrald_stratum::types::StratumState::Disconnected => "disconnected",
                                dcentrald_stratum::types::StratumState::Connecting => "connecting",
                                dcentrald_stratum::types::StratumState::Authorized => "authorized",
                                dcentrald_stratum::types::StratumState::Mining => "mining",
                                dcentrald_stratum::types::StratumState::Donating => "donating",
                                dcentrald_stratum::types::StratumState::AuthFailed => "auth_failed",
                            };
                            status_state_tx.send_modify(|state| {
                                if status_publisher_closed.load(Ordering::Acquire) {
                                    return;
                                }
                                state.pool.status = status.to_string();
                            });
                            info!(state = ?pool_state, "am3-bb: pool state")
                        }
                        dcentrald_stratum::types::StratumStatus::Latency(latency_ms) => {
                            status_state_tx.send_modify(|state| {
                                if status_publisher_closed.load(Ordering::Acquire) {
                                    return;
                                }
                                state.pool.latency_ms = latency_ms;
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    let mining_result = (|| -> Result<()> {
        let assume_job_response_flags = env_flag_set(ENV_AM3_BB_ASSUME_JOB_RESPONSE_FLAGS);
        if assume_job_response_flags {
            warn!(
            env = ENV_AM3_BB_ASSUME_JOB_RESPONSE_FLAGS,
            "am3-bb: lab override active - validating parsed BM1362 frames even when flags bit7 is clear"
        );
        }

        let work_codec = Am3BbWorkCodec::from_env();

        info!(
            chains = transport.chain_count(),
            total_chips,
            dispatch_interval_us = transport.dispatch_interval_us(),
            work_codec = work_codec.as_str(),
            pool = %config.pool.url,
            "=== am3-bb MINING ACTIVE (Option B2) — Stratum + paced BM1362 serial-work dispatch + nonce-validate/dedup/submit ==="
        );

        let worker_name = config.pool.worker.clone();
        let mut work_builder = WorkBuilder::new();
        let mut current_job: Option<dcentrald_stratum::types::JobTemplate> = None;
        // G13: pure SerialWorkBookkeeping façade (history + job cursor + SeenShareSet).
        // Serial88 step 24 mask 0x7F; Asic86 step 1 full u8; depth AM3_BB_WORK_HISTORY_PER_ID.
        // Dedup BEFORE pool submission (feedback_s9_never_regress_checklist).
        // Do not force generation-keyed bookkeeping onto BIP320 job_id/nonce/vbits path.
        let job_cursor = match work_codec {
            Am3BbWorkCodec::Serial88 => {
                dcentrald_common::AsicJobIdCursor::serial_mining(JOB_ID_INCREMENT)
            }
            Am3BbWorkCodec::Asic86 => dcentrald_common::AsicJobIdCursor::with_mask(0, 1, 0xFF),
        };
        let mut bookkeeping =
            dcentrald_common::SerialWorkBookkeeping::<DispatchedWork>::with_depth_and_cursor(
                WORK_HISTORY_PER_ECHOED_JOB_ID,
                job_cursor,
            );
        let mut next_chain: usize = 0;

        let chain_count = transport.chain_count().max(1);
        let start = Instant::now();
        let mut last_heartbeat = Instant::now();
        let mut last_thermal_poll = Instant::now();
        let mut last_dispatch_attempt = Instant::now();
        // Per-chain ~one frame every dispatch_interval_us; loop-tick ~= the
        // interval / chain_count so all chains stay fed without flooding.
        let tick =
            Duration::from_micros((transport.dispatch_interval_us() / chain_count as u64).max(500));
        let mut total_work: u64 = 0;
        let mut total_rx_frames: u64 = 0;
        let mut total_nonces: u64 = 0;
        let mut non_job_frames: u64 = 0;
        let mut assumed_job_response_frames: u64 = 0;
        let mut shares_submitted: u64 = 0;
        let mut dup_nonces: u64 = 0;
        let mut bad_nonces: u64 = 0;
        let mut target_miss_nonces: u64 = 0;
        let mut unknown_job_nonces: u64 = 0;
        let mut alternate_decode_pool_hits: u64 = 0;
        let mut version_metadata_rejects: u64 = 0;
        let mut best_target_miss_difficulty: Option<f64> = None;

        loop {
            // Observe terminal heartbeat failure/panic before interpreting the
            // worker's cancellation as an ordinary operator shutdown.
            heartbeat.require_ready_and_healthy("runtime supervision")?;
            if shutdown.is_cancelled() {
                info!(
                    uptime_s = start.elapsed().as_secs(),
                    work_codec = work_codec.as_str(),
                    total_work,
                    total_rx_frames,
                    total_nonces,
                    non_job_frames,
                    assumed_job_response_frames,
                    shares_submitted,
                    dup_nonces,
                    bad_nonces,
                    target_miss_nonces,
                    unknown_job_nonces,
                    alternate_decode_pool_hits,
                    version_metadata_rejects,
                    best_target_miss_difficulty,
                    "am3-bb: shutdown requested — exiting mining loop"
                );
                return Ok(());
            }
            {
                if last_thermal_poll.elapsed() >= Duration::from_millis(thermal_poll_ms) {
                    last_thermal_poll = Instant::now();
                    // INVARIANT #2 + #4 ORDERING: `?` fires FIRST. If the
                    // supervisor decides dangerous temp or lost-thermal-proof, it
                    // returns Err here and the retained runtime lane cuts PSU GPIO65
                    // before dsPIC/reset defense-in-depth and quiet fan coast-down,
                    // all BEFORE the PID is ever consulted. So the PID
                    // can only ever see a snapshot the supervisor already deemed
                    // safe and fresh — it never "out-cools" a dangerous temp by
                    // ramping the fan; hash power is cut first, by construction.
                    let snapshot = match thermal_supervisor.poll_and_check("runtime") {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            am3_bb_force_runtime_board_enable_off(
                                board_cutoff,
                                "thermal-supervisor-failure",
                            );
                            return Err(error);
                        }
                    };
                    if snapshot.fresh {
                        if let Err(error) =
                            fan_pid.step(&snapshot, f32::from(config.thermal.dangerous_temp_c))
                        {
                            am3_bb_force_runtime_board_enable_off(
                                board_cutoff,
                                "checked-fan-command-failure",
                            );
                            return Err(error);
                        }
                        let observed_temp_c = snapshot.max_temp_c;
                        let fan_pwm = fan_pid.commanded_pwm();
                        let fan_rpm = fan_pid.fan.get_rpm();
                        state_tx.send_modify(|state| {
                            state.fans.pwm = fan_pwm;
                            state.fans.rpm = fan_rpm;
                            for chain in &mut state.chains {
                                chain.temp_c = observed_temp_c;
                                chain.temp_source =
                                    Some("max_across_current_lm75_chain_coverage".to_string());
                                chain.status =
                                    "temperature_observed_population_unproven".to_string();
                            }
                        });
                        // One tick proves fresh thermal sensing plus a checked fan
                        // policy iteration; loop activity alone is not liveness.
                        watchdog_liveness.mark_progress();
                    }
                }
            }

            // --- Pull any pool jobs (non-blocking; the router pushes). ---
            loop {
                match job_rx.try_recv() {
                    Ok(job) => {
                        if job.clean_jobs {
                            info!(job_id = %job.job_id, "am3-bb: NEW BLOCK — flush stale work + dedup set");
                            work_builder.reset_extranonce2();
                            transport.clean_work();
                            bookkeeping.on_clean_jobs();
                        }
                        work_builder.set_version_mask(job.version_mask);
                        if job.is_flush_only() {
                            info!(job_id = %job.job_id, "am3-bb: pool-switch flush — dispatch paused until next notify");
                            current_job = None;
                        } else {
                            current_job = Some(job);
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        warn!("am3-bb: Stratum job channel closed — exiting mining loop");
                        return Ok(());
                    }
                }
            }

            // --- Dispatch one round of work (round-robin across chains, paced). ---
            if last_dispatch_attempt.elapsed() >= tick {
                last_dispatch_attempt = Instant::now();
                if let Some(ref job) = current_job {
                    let work = match work_builder.next_work(job) {
                        Ok(work) => work,
                        Err(error) => {
                            warn!(%error, "am3-bb: V1 work domain unavailable; pausing dispatch until a fresh generation arrives");
                            current_job = None;
                            continue;
                        }
                    };

                    // R7-3: the PROVEN 88-byte BM1362 serial full-header work frame
                    // ([0x55 0xAA][0x21][0x56][82-byte payload][CRC16-CCITT-FALSE BE])
                    // — see `build_bm1362_serial_work_frame` + the module doc. The
                    // W14.B `AsicWorkFrame` 86-byte `asic_work_t` codec was a W4
                    // dev-kit fabrication and is NOT what the chip speaks.
                    let chain = next_chain % transport.chain_count().max(1);
                    next_chain = next_chain.wrapping_add(1);
                    let now = now_us();
                    let asic_job_id = bookkeeping.job_ids.current();
                    let send_result = match work_codec {
                        Am3BbWorkCodec::Serial88 => {
                            let frame_bytes = build_bm1362_serial_work_frame(&work, asic_job_id);
                            transport.try_send_raw(chain, &frame_bytes, asic_job_id, now)
                        }
                        Am3BbWorkCodec::Asic86 => {
                            let frame = build_bm1362_asic86_work_frame(
                                &work,
                                asic_job_id,
                                total_work.wrapping_add(1) as u32,
                            );
                            transport.try_send_work(chain, &frame, now)
                        }
                    };
                    match send_result {
                        Ok(true) => {
                            let job_slot = work_codec.job_id_slot(asic_job_id);
                            bookkeeping.history.push(
                                job_slot,
                                DispatchedWork {
                                    work_generation: work.work_generation,
                                    job_id: work.job_id.clone(),
                                    extranonce2: work.extranonce2.clone(),
                                    ntime: work.ntime,
                                    nbits: work.nbits,
                                    version: work.version,
                                    version_mask: work.version_mask,
                                    prev_block_hash: work.prev_block_hash,
                                    merkle_root: work.merkle_root,
                                    share_target: work.share_target,
                                },
                            );
                            let _ = bookkeeping.job_ids.take_and_advance();
                            total_work += 1;
                            if total_work == 1 {
                                info!(
                                    chain,
                                    work_codec = work_codec.as_str(),
                                    "am3-bb: first BM1362 work frame dispatched"
                                );
                            }
                        }
                        Ok(false) => { /* paced off — retry next tick */ }
                        Err(UartTransportError::ChainOutOfRange) => {
                            warn!(chain, "am3-bb: dispatch chain out of range — skipping");
                        }
                        Err(UartTransportError::WriteFailed) => {
                            warn!(chain, "am3-bb: chain UART write failed during dispatch");
                        }
                        Err(UartTransportError::FrameTooLong) => {
                            // Unreachable for try_send_raw (no length cap) — handled
                            // for exhaustiveness.
                            warn!(
                                "am3-bb: dispatch reported FrameTooLong — unexpected for raw send"
                            );
                        }
                    }
                }
            }

            // --- Poll nonces, validate, dedup, submit. ---
            if work_codec == Am3BbWorkCodec::Serial88 {
                //
                // R7-3: BM1362 serial-wire nonce frames are 11 bytes ([0xAA 0x55]
                // [n3 n2 n1 n0][midstate_idx][result][vbits_hi vbits_lo][flags]) —
                // `recv_bm1362_serial_nonces` parses them. (`recv_nonces` parses the
                // different/wrong W14.B 10-byte codec.) `flags` bit7 = job response;
                // `result` high nibble (>>1) echoes `sent_job_id & 0x78`; `vbits` BE.
                for (chain_idx, nr) in transport.recv_bm1362_serial_nonces() {
                    total_rx_frames += 1;
                    let is_job_response = nr.flags & 0x80 != 0;
                    if !is_job_response {
                        // Not a job-response frame (status / config echo) — ignore.
                        non_job_frames += 1;
                        if non_job_frames <= 8 {
                            info!(
                                chain = chain_idx,
                                job_id = nr.job_id,
                                result = format_args!("0x{:02X}", nr.result_byte),
                                small_core = nr.small_core,
                                midstate_idx = nr.midstate_idx,
                                flags = format_args!("0x{:02X}", nr.flags),
                                vbits = format_args!("0x{:04X}", nr.version_bits_raw),
                                nonce = format_args!("0x{:08X}", nr.nonce),
                                "am3-bb: non-job BM1362 serial frame ignored"
                            );
                        }
                        if !assume_job_response_flags {
                            continue;
                        }
                        assumed_job_response_frames += 1;
                    }
                    total_nonces += 1;

                    if bookkeeping.history.is_empty_slot(nr.job_id) {
                        bad_nonces += 1;
                        unknown_job_nonces += 1;
                        debug!(
                            chain = chain_idx,
                            job_id = nr.job_id,
                            result = format_args!("0x{:02X}", nr.result_byte),
                            small_core = nr.small_core,
                            flags = format_args!("0x{:02X}", nr.flags),
                            nonce = format_args!("0x{:08X}", nr.nonce),
                            "am3-bb: nonce for unknown job_id slot — dropped (stale / reused slot)"
                        );
                        continue;
                    };

                    let matched =
                        bookkeeping
                            .history
                            .iter_newest_first(nr.job_id)
                            .find_map(|candidate| {
                                let rv = rolled_version_checked(
                                    candidate.version,
                                    candidate.version_mask,
                                    nr.version_bits_raw,
                                )?;
                                let header = candidate.full_header(rv, nr.nonce);
                                if validate_full_header(&header, &candidate.share_target) {
                                    Some((candidate.clone(), rv, header))
                                } else {
                                    None
                                }
                            });
                    let Some((dw, rv, header)) = matched else {
                        bad_nonces += 1;
                        target_miss_nonces += 1;
                        let (best_current, best_any, alternate_pool_hit, version_rejects) =
                            am3_bb_replay_bm1362_nonce_decodes(
                                bookkeeping.history.iter_newest_first(nr.job_id),
                                &nr,
                            );
                        version_metadata_rejects =
                            version_metadata_rejects.saturating_add(u64::from(version_rejects));
                        if let Some(best) =
                            best_current.as_ref().and_then(|b| b.achieved_difficulty)
                        {
                            best_target_miss_difficulty = Some(
                                best_target_miss_difficulty
                                    .map(|prev| prev.max(best))
                                    .unwrap_or(best),
                            );
                        }
                        if let Some(alt) = alternate_pool_hit {
                            alternate_decode_pool_hits =
                                alternate_decode_pool_hits.saturating_add(1);
                            warn!(
                                chain = chain_idx,
                                job_id = nr.job_id,
                                raw = %hex_preview(&nr.raw_frame, nr.raw_frame.len()),
                                alt_pool_job = %alt.job_id,
                                nonce_decode = alt.nonce_label,
                                version_decode = alt.version_label,
                                nonce = format_args!("0x{:08X}", alt.nonce_submit),
                                rolled_version = format_args!("0x{:08X}", alt.rolled_version),
                                achieved_difficulty = alt.achieved_difficulty,
                                "am3-bb: alternate BM1362 nonce decode would meet pool target"
                            );
                        }
                        if total_nonces <= 8 {
                            let nonce_be = u32::from_be_bytes([
                                nr.raw_frame[2],
                                nr.raw_frame[3],
                                nr.raw_frame[4],
                                nr.raw_frame[5],
                            ]);
                            let vbits_le = u16::from_le_bytes([nr.raw_frame[8], nr.raw_frame[9]]);
                            info!(
                                chain = chain_idx,
                                job_id = nr.job_id,
                                job_id_bm1366 = nr.result_byte & 0xF8,
                                job_id_no_shift = nr.result_byte & 0xF0,
                                result = format_args!("0x{:02X}", nr.result_byte),
                                small_core = nr.small_core,
                                flags = format_args!("0x{:02X}", nr.flags),
                                vbits = format_args!("0x{:04X}", nr.version_bits_raw),
                                vbits_le = format_args!("0x{:04X}", vbits_le),
                                nonce = format_args!("0x{:08X}", nr.nonce),
                                nonce_be = format_args!("0x{:08X}", nonce_be),
                                raw = %hex_preview(&nr.raw_frame, nr.raw_frame.len()),
                                history_len = bookkeeping.history.slot_len(nr.job_id),
                                best_current_pool_diff = best_current
                                    .as_ref()
                                    .and_then(|b| b.achieved_difficulty),
                                best_any_decode = ?best_any.as_ref().map(|b| {
                                    format!(
                                        "{}+{} nonce=0x{:08X} ver=0x{:08X} diff={:?}",
                                        b.nonce_label,
                                        b.version_label,
                                        b.nonce_submit,
                                        b.rolled_version,
                                        b.achieved_difficulty
                                    )
                                }),
                                version_rejects,
                                assumed_job_response = !is_job_response && assume_job_response_flags,
                                "am3-bb: nonce did not validate against recent work history"
                            );
                        }
                        continue;
                    };

                    // P1-1 pure SeenShareSet (clear-before-insert over-cap SSOT).
                    if !bookkeeping
                        .seen
                        .insert(nr.job_id, nr.nonce, nr.version_bits_raw)
                    {
                        dup_nonces += 1;
                        continue;
                    }
                    let achieved_difficulty = am3_bb_achieved_difficulty_from_header(&header);
                    let share = dcentrald_stratum::types::ValidShare {
                        work_generation: dw.work_generation,
                        worker_name: worker_name.clone(),
                        job_id: dw.job_id.clone(),
                        extranonce2: dw.extranonce2.clone(),
                        ntime: format!("{:08x}", dw.ntime),
                        nonce: format!("{:08x}", nr.nonce),
                        version_bits: dcentrald_stratum::work::bip310_version_bits(
                            rv,
                            dw.version_mask,
                        ),
                        version: rv,
                        achieved_difficulty,
                    };
                    if share_tx.blocking_send(share).is_err() {
                        warn!("am3-bb: Stratum share channel closed — exiting mining loop");
                        return Ok(());
                    }
                    shares_submitted += 1;
                    info!(
                        chain = chain_idx,
                        job_id = %dw.job_id,
                        small_core = nr.small_core,
                        nonce = format_args!("0x{:08X}", nr.nonce),
                        version = format_args!("0x{:08X}", rv),
                        achieved_difficulty,
                        "am3-bb: VALID SHARE submitted to pool"
                    );
                }
            } else {
                for (chain_idx, nr) in transport.recv_nonces() {
                    total_rx_frames += 1;
                    total_nonces += 1;

                    if bookkeeping.history.is_empty_slot(nr.job_id) {
                        bad_nonces += 1;
                        unknown_job_nonces += 1;
                        debug!(
                            chain = chain_idx,
                            response_chain = nr.chain_id,
                            job_id = nr.job_id,
                            nonce = format_args!("0x{:08X}", nr.nonce),
                            "am3-bb: asic86 nonce for unknown job_id slot - dropped"
                        );
                        continue;
                    }

                    let matched =
                        bookkeeping
                            .history
                            .iter_newest_first(nr.job_id)
                            .find_map(|candidate| {
                                let header = candidate.full_header(candidate.version, nr.nonce);
                                if validate_full_header(&header, &candidate.share_target) {
                                    Some((candidate.clone(), header))
                                } else {
                                    None
                                }
                            });
                    let Some((dw, header)) = matched else {
                        bad_nonces += 1;
                        target_miss_nonces += 1;
                        if total_nonces <= 8 {
                            info!(
                                chain = chain_idx,
                                response_chain = nr.chain_id,
                                job_id = nr.job_id,
                                nonce = format_args!("0x{:08X}", nr.nonce),
                                history_len = bookkeeping.history.slot_len(nr.job_id),
                                "am3-bb: asic86 nonce did not validate against recent work history"
                            );
                        }
                        continue;
                    };

                    // asic86 path: no version rolling in key (vbits collapsed to 0).
                    if !bookkeeping.seen.insert(nr.job_id, nr.nonce, 0) {
                        dup_nonces += 1;
                        continue;
                    }

                    let achieved_difficulty = am3_bb_achieved_difficulty_from_header(&header);
                    let share = dcentrald_stratum::types::ValidShare {
                        work_generation: dw.work_generation,
                        worker_name: worker_name.clone(),
                        job_id: dw.job_id.clone(),
                        extranonce2: dw.extranonce2.clone(),
                        ntime: format!("{:08x}", dw.ntime),
                        nonce: format!("{:08x}", nr.nonce),
                        version_bits: None,
                        version: dw.version,
                        achieved_difficulty,
                    };
                    if share_tx.blocking_send(share).is_err() {
                        warn!("am3-bb: Stratum share channel closed - exiting mining loop");
                        return Ok(());
                    }
                    shares_submitted += 1;
                    info!(
                        chain = chain_idx,
                        response_chain = nr.chain_id,
                        job_id = %dw.job_id,
                        nonce = format_args!("0x{:08X}", nr.nonce),
                        version = format_args!("0x{:08X}", dw.version),
                        achieved_difficulty,
                        "am3-bb: VALID asic86 SHARE submitted to pool"
                    );
                }
            }

            if last_heartbeat.elapsed() >= Duration::from_secs(15) {
                let rx_counters = transport.bm1362_serial_rx_counters();
                let rx_raw_bytes: Vec<u64> = rx_counters.iter().map(|c| c.raw_bytes).collect();
                let rx_parsed_frames: Vec<u64> =
                    rx_counters.iter().map(|c| c.parsed_frames).collect();
                let rx_job_response_frames: Vec<u64> =
                    rx_counters.iter().map(|c| c.job_response_frames).collect();
                let rx_non_job_frames: Vec<u64> = rx_counters
                    .iter()
                    .map(|c| c.non_job_response_frames)
                    .collect();
                let rx_resync_bytes: Vec<u64> =
                    rx_counters.iter().map(|c| c.resync_bytes).collect();
                let rx_buffered_bytes: Vec<usize> =
                    rx_counters.iter().map(|c| c.buffered_bytes).collect();
                info!(
                    uptime_s = start.elapsed().as_secs(),
                    work_codec = work_codec.as_str(),
                    total_work,
                    total_rx_frames,
                    total_nonces,
                    non_job_frames,
                    assumed_job_response_frames,
                    shares_submitted,
                    dup_nonces,
                    bad_nonces,
                    target_miss_nonces,
                    unknown_job_nonces,
                    alternate_decode_pool_hits,
                    version_metadata_rejects,
                    best_target_miss_difficulty,
                    chains = transport.chain_count(),
                    rx_raw_bytes = ?rx_raw_bytes,
                    rx_parsed_frames = ?rx_parsed_frames,
                    rx_job_response_frames = ?rx_job_response_frames,
                    rx_non_job_frames = ?rx_non_job_frames,
                    rx_resync_bytes = ?rx_resync_bytes,
                    rx_buffered_bytes = ?rx_buffered_bytes,
                    fan_pid_pwm = fan_pid.commanded_pwm(),
                    fan_pid_rpm = fan_pid.fan.get_rpm(),
                    "am3-bb: mining loop alive"
                );
                last_heartbeat = Instant::now();
            }

            std::thread::sleep(tick);
        }
    })();

    Am3BbMiningLoopExit {
        mining_result,
        stratum_tasks,
    }
}

/// Monotonic microseconds, for [`Am335xUartTransport::try_send_raw`] pacing.
fn now_us() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_micros() as u64
}

/// Cold-boot/enum-only diagnostic stub: log readiness, then idle while polling
/// the transport for nonces so any residual-state nonces show up in the log.
///
/// This is NOT the mining loop — it is the `DCENT_AM3_BB_STUB_LOOP=1` escape
/// hatch for validating just the cold-boot orchestration + BM1362 enumeration
/// + transport setup (no pool, no work dispatch). The real loop is
/// [`run_mining_loop`].
fn run_mining_loop_stub<U: ChainUart>(
    transport: &mut Am335xUartTransport<U>,
    total_chips: usize,
    shutdown: &CancellationToken,
) {
    info!(
        chains = transport.chain_count(),
        total_chips,
        watchdog_bringup_grace_s = AM3_BB_WATCHDOG_BRINGUP_GRACE.as_secs(),
        "am3-bb: DCENT_AM3_BB_STUB_LOOP — cold-boot complete, transport ready. This is the \
         enum-only diagnostic stub: no pool, no work dispatch. Idling; will log any nonce frames \
         the chain returns from residual state. It never enters watchdog Mining or advances safety \
         liveness, so the bounded Bringup deadline remains the backstop. Unset \
         DCENT_AM3_BB_STUB_LOOP for the mining loop."
    );

    let start = Instant::now();
    let mut last_heartbeat = Instant::now();
    let mut total_nonces: u64 = 0;
    let mut job_response_nonces: u64 = 0;
    let mut non_job_frames: u64 = 0;
    loop {
        if shutdown.is_cancelled() {
            info!(
                uptime_s = start.elapsed().as_secs(),
                total_nonces,
                job_response_nonces,
                non_job_frames,
                "am3-bb: shutdown requested — exiting stub loop"
            );
            return;
        }

        // Poll the transport — in the stub we have no work dispatched, so
        // this should be empty, but if the chain is producing nonces from
        // residual state it's worth seeing. (Parses the PROVEN 11-byte BM1362
        // serial nonce frame — see R7-3 note in the module doc.)
        for (chain_idx, nonce) in transport.recv_bm1362_serial_nonces() {
            total_nonces += 1;
            if nonce.flags & 0x80 != 0 {
                job_response_nonces += 1;
            } else {
                non_job_frames += 1;
            }
            info!(
                chain = chain_idx,
                job_id = nonce.job_id,
                small_core = nonce.small_core,
                flags = format_args!("0x{:02X}", nonce.flags),
                vbits = format_args!("0x{:04X}", nonce.version_bits_raw),
                nonce = format_args!("0x{:08X}", nonce.nonce),
                "am3-bb: nonce frame received (stub loop — not submitted to any pool)"
            );
        }

        if last_heartbeat.elapsed() >= Duration::from_secs(30) {
            info!(
                uptime_s = start.elapsed().as_secs(),
                total_nonces,
                job_response_nonces,
                non_job_frames,
                chains = transport.chain_count(),
                "am3-bb: stub loop alive (no pool, no work dispatch — DCENT_AM3_BB_STUB_LOOP set)"
            );
            last_heartbeat = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

// ===========================================================================
//  Tests (host-safe — no hardware)
// ===========================================================================



#[cfg(all(test, feature = "sim-hal"))]
#[path = "../tests/sim_support/share_oracle.rs"]
mod independent_pool;

#[cfg(all(test, feature = "sim-hal"))]
pub(crate) use tests::bb_synthetic_identity_page as deployed_sim_identity_page;

#[cfg(test)]
mod tests {
    pub(crate) fn bb_synthetic_identity_page(name: &str, marking: &str, bad_crc: Option<usize>) -> Vec<u8> {
        fn encrypt(plain: &[u8]) -> Vec<u8> {
            let key: Vec<u32> = dcentrald_api_types::deployed_eeprom::KEY_LARGE[1]
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .collect();
            let mut words: Vec<u32> = plain
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .collect();
            let n = words.len();
            let mut sum = 0u32;
            let mut z = words[n - 1];
            for _ in 0..(6 + 52 / n) {
                sum = sum.wrapping_add(0x9e3779b9);
                let e = ((sum >> 2) & 3) as usize;
                for p in 0..n {
                    let y = words[(p + 1) % n];
                    let mx = ((z >> 5 ^ y << 2).wrapping_add(y >> 3 ^ z << 4))
                        ^ ((sum ^ y).wrapping_add(key[(p & 3) ^ e] ^ z));
                    words[p] = words[p].wrapping_add(mx);
                    z = words[p];
                }
            }
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }
        use dcentrald_api_types::zhiju_eeprom::bitmain_crc5;
        let mut page = vec![0xff; 256];
        page[..2].copy_from_slice(&[4, 0x11]);
        let mut identity = vec![0; 96];
        identity[..17].copy_from_slice(b"SYNTH000000000001");
        identity[21..21 + marking.len()].copy_from_slice(marking.as_bytes());
        identity[60..60 + name.len()].copy_from_slice(name.as_bytes());
        let block = [&page[..2], &identity[..95]].concat();
        identity[95] = bitmain_crc5(&block, 776) ^ u8::from(bad_crc == Some(1));
        let mut factory = vec![0; 16];
        factory[..2].copy_from_slice(&1360u16.to_le_bytes());
        factory[2..4].copy_from_slice(&545u16.to_le_bytes());
        factory[15] = bitmain_crc5(&factory[..15], 120) ^ u8::from(bad_crc == Some(2));
        page[2..98].copy_from_slice(&encrypt(&identity));
        page[98..114].copy_from_slice(&encrypt(&factory));
        page[255] = 0x5a;
        page
    }

    #[cfg(feature = "sim-hal")]
    include!("am3_bb_native_pool_tests.rs");
    #[test]
    fn lab_override_presence_does_not_hide_watched_refusal() {
        const CHILD: &str = "DCENT_AM3_BB_LAB_ENV_TEST_CHILD";
        if std::env::var(CHILD).as_deref() != Ok("1") {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "am3_bb_mining::tests::lab_override_presence_does_not_hide_watched_refusal",
                ])
                .env(CHILD, "1")
                .env(super::ENV_AM3_BB_ALLOW_NO_RX_MINING, "0")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        // The lab API preserves presence semantics even for "0". Independently,
        // watched mining must still refuse the forbidden request in every build.
        assert_eq!(
            super::env_flag_set(super::ENV_AM3_BB_ALLOW_NO_RX_MINING),
            dcentrald_common::lab_env::compiled()
        );
        assert!(super::forbidden_override_is_present(
            super::ENV_AM3_BB_ALLOW_NO_RX_MINING
        ));
    }

    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::*;
    use dcentrald_hal::platform::beaglebone::BeagleBonePlatform;
    use dcentrald_hal::platform::beaglebone_cold_boot::{ColdBootOptsV2, PreparedBoardEnable};
    use dcentrald_hal::platform::config::PlatformConfig;

    #[test]
    fn configured_bb_chains_require_individual_bm1362_family_observations() {
        use dcentrald_silicon_profiles::energize_gate::{classify_chain, ChainProbe};

        for chains in 1..=3 {
            let valid: Vec<_> = (0..chains)
                .map(|slot| classify_chain(slot as u8, Some(&[0x04, 0x11])))
                .collect();
            require_am3_bb_eeprom_family(&valid, chains).unwrap();
            for slot in 0..chains {
                let chain_id = slot as u8;
                for invalid in [
                    classify_chain(chain_id, None),
                    classify_chain(chain_id, Some(&[0xff; 8])),
                    classify_chain(chain_id, Some(&[0; 8])),
                    classify_chain(chain_id, Some(&[0x04])),
                    classify_chain(chain_id, Some(&[0x05, 0x11])),
                    ChainProbe::Timeout { chain_id },
                    classify_chain(7, Some(&[0x04, 0x11])),
                ] {
                    let mut probes = valid.clone();
                    probes[slot] = invalid;
                    assert!(require_am3_bb_eeprom_family(&probes, chains).is_err());
                }
            }
            assert!(require_am3_bb_eeprom_family(&valid[..chains - 1], chains).is_err());
        }
        assert!(require_am3_bb_eeprom_family(&[], 0).is_err());
    }

    #[test]
    fn bb_identity_reads_only_retained_bus_zero_before_supply_on() {
        let prefix = bb_synthetic_identity_page("BHB42601", "L1C021CK11", None);
        let mut reads = Vec::new();
        let probes = collect_am3_bb_eeprom_probes(0, 3, 126, |slot| {
            reads.push(slot);
            Ok(prefix.clone())
        })
        .unwrap();
        assert_eq!(reads, [0, 1, 2]);
        assert_eq!(probes.len(), 3);
        reads.clear();
        // Even valid-looking data on the PSU adapter may not admit a board.
        assert!(collect_am3_bb_eeprom_probes(1, 3, 126, |slot| {
            reads.push(slot);
            Ok(prefix.clone())
        })
        .is_err());
        assert!(reads.is_empty());
        // No bus-0 identity must remain a refusal even if bus 1 has a copy.
        let bank = std::collections::BTreeMap::from([((1u8, 0usize), prefix.clone())]);
        assert!(collect_am3_bb_eeprom_probes(0, 1, 126, |slot| {
            bank.get(&(0, slot)).cloned().context("bus-0 EEPROM absent")
        })
        .is_err());
        for count in [0, 4] {
            assert!(collect_am3_bb_eeprom_probes(0, count, 126, |_| panic!(
                "invalid chain count read"
            ))
            .is_err());
        }
        for size in [0, 2, 31, 32, 33, 255, 256, 257] {
            assert!(collect_am3_bb_eeprom_probes(0, 1, 126, |_| Ok(vec![0x04; size])).is_err());
        }
        let source = include_str!("am3_bb_mining.rs");
        let owner = source
            .find(concat!(
                "let hashboard_i2c = pre_energize_try!(",
                "spawn_i2c_service"
            ))
            .unwrap();
        let identity = source
            .find(concat!("let probes = collect_", "am3_bb_eeprom_probes("))
            .unwrap();
        let supply = source
            .find(concat!(
                ".run_cold_boot(&mut psu,",
                " &mut cold_boot_uarts, board_enable)"
            ))
            .unwrap();
        let reuse = source
            .find(concat!("let dspic_i2c = hashboard_", "i2c.clone();"))
            .unwrap();
        assert!(owner < identity && identity < supply && supply < reuse);
        assert_eq!(
            source[..reuse]
                .matches(concat!(
                    "spawn_i2c_service_no_register_touch_",
                    "with_denylist("
                ))
                .count(),
            1
        );
        assert!(
            !source[owner..reuse].contains(concat!("read_hashboard_eeprom_for_", "energize_gate("))
        );
    }


    #[test]
    fn bb_factory_identity_rejects_corrupt_foreign_and_incompatible_pages() {
        use dcentrald_silicon_profiles::energize_gate::ChainProbe;
        let names = ["BHB42601", "BHB42603", "BHB42621", "BHB42641"];
        for first in 0..4 {
            let pages: Vec<_> = (0..3)
                .map(|slot| {
                    bb_synthetic_identity_page(names[(first + slot) % 4], "L1C021CK11", None)
                })
                .collect();
            let probes =
                collect_am3_bb_eeprom_probes(0, 3, 126, |slot| Ok(pages[slot].clone())).unwrap();
            for (slot, probe) in probes.iter().enumerate() {
                match probe {
                    ChainProbe::Classified { sku, .. } => {
                        assert_eq!(sku.sku(), names[(first + slot) % 4])
                    }
                    other => panic!("exact compatible SKU was lost: {other:?}"),
                }
            }
        }
        let mut garbage = vec![0; 256];
        garbage[..2].copy_from_slice(&[4, 0x11]);
        let invalid = [
            garbage,
            bb_synthetic_identity_page("BHB42601", "L1C021CK11", Some(1)),
            bb_synthetic_identity_page("BHB42601", "L1C021CK11", Some(2)),
            bb_synthetic_identity_page("BHB42601", "L1G021CK11", None),
            bb_synthetic_identity_page("BHB42611", "L1C021CK11", None),
            bb_synthetic_identity_page("BHB56903", "L1G021CK11", None),
            bb_synthetic_identity_page("BHB42699", "L1C021CK11", None),
        ];
        let valid = bb_synthetic_identity_page("BHB42601", "L1C021CK11", None);
        for bad in invalid {
            for bad_slot in 0..3 {
                assert!(
                    collect_am3_bb_eeprom_probes(0, 3, 126, |slot| Ok(if slot == bad_slot {
                        bad.clone()
                    } else {
                        valid.clone()
                    }))
                    .is_err(),
                    "bad identity admitted on slot {bad_slot}"
                );
            }
        }
        assert!(collect_am3_bb_eeprom_probes(0, 1, 120, |_| Ok(valid.clone())).is_err());
    }

    fn test_platform() -> BeagleBonePlatform {
        // `with_config` builds the platform with the explicit `PlatformConfig`
        // and the hardcoded `a lab unit` (`S19J_IO_BOARD_V2_0`) board-target
        // defaults — the same topology the runtime sees on a LuxOS unit with
        // no `/etc/dcentos/board_targets/<name>.toml` present.
        BeagleBonePlatform::with_config(PlatformConfig::s19j_beaglebone())
    }

    // Golden frame from the accepted-share `a lab unit` captures. The live stream is
    // 126 repetitions (1134 bytes); two frames keep the host fixture compact
    // while pinning the exact response shape.
    const LIVE_BM1362_GET_ADDRESS_FRAME: [u8; 9] =
        [0xAA, 0x55, 0x13, 0x62, 0x03, 0x00, 0x00, 0x00, 0x0D];

    fn live_get_address_stream(frames: usize) -> Vec<u8> {
        LIVE_BM1362_GET_ADDRESS_FRAME.repeat(frames)
    }

    struct TempGpioRoot(PathBuf);

    impl TempGpioRoot {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "dcentos-am3-gpio-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("export"), b"").unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn add_gpio(&self, gpio: u32) -> PathBuf {
            let dir = self.0.join(format!("gpio{gpio}"));
            std::fs::create_dir_all(&dir).unwrap();
            for (name, value) in [("direction", "in"), ("active_low", "0"), ("value", "0")] {
                std::fs::write(dir.join(name), value).unwrap();
            }
            dir
        }
    }

    impl Drop for TempGpioRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn gpio_readback_validation_requires_an_exact_trimmed_value() {
        assert!(am3_bb_validate_gpio_attr_readback(59, "value", "0", "0\n").is_ok());
        assert!(am3_bb_validate_gpio_attr_readback(59, "value", "0", "1").is_err());
        assert!(am3_bb_validate_gpio_attr_readback(59, "value", "0", "00").is_err());
        assert!(am3_bb_validate_gpio_attr_readback(59, "direction", "out", "unknown").is_err());
    }

    #[test]
    fn checked_gpio_prepare_and_value_write_read_back_every_safety_attribute() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(59);

        am3_bb_prepare_output_gpio_at(root.path(), 59, false).unwrap();
        am3_bb_write_gpio_attr_checked_at(root.path(), 59, "value", "0").unwrap();

        assert_eq!(
            std::fs::read_to_string(gpio.join("direction")).unwrap(),
            "out"
        );
        assert_eq!(
            std::fs::read_to_string(gpio.join("active_low")).unwrap(),
            "0"
        );
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");
    }

    #[test]
    fn unusable_active_low_attribute_refuses_gpio_ownership() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(49);
        std::fs::remove_file(gpio.join("active_low")).unwrap();
        std::fs::create_dir(gpio.join("active_low")).unwrap();

        let error = am3_bb_prepare_output_gpio_at(root.path(), 49, true)
            .unwrap_err()
            .to_string();

        assert!(error.contains("active_low"), "{error}");
    }

    #[test]
    fn export_command_without_a_materialized_gpio_directory_is_rejected() {
        let root = TempGpioRoot::new();

        let error = am3_bb_export_gpio_if_needed_at(root.path(), 22)
            .unwrap_err()
            .to_string();

        assert!(error.contains("did not appear"), "{error}");
    }

    #[test]
    fn concurrent_gpio_export_error_is_accepted_only_after_node_materializes() {
        let root = TempGpioRoot::new();

        am3_bb_export_gpio_if_needed_at_with(root.path(), 22, |_path, _value| {
            root.add_gpio(22);
            Err(std::io::Error::from_raw_os_error(libc::EBUSY))
        })
        .unwrap();

        assert!(root.path().join("gpio22").is_dir());
    }

    #[test]
    fn delayed_gpio_attributes_are_boundedly_observed_after_export() {
        let root = TempGpioRoot::new();
        let gpio = root.path().join("gpio22");
        std::fs::create_dir(&gpio).unwrap();
        let delayed_gpio = gpio.clone();
        let materializer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            for (name, value) in [("direction", "in"), ("active_low", "0"), ("value", "0")] {
                std::fs::write(delayed_gpio.join(name), value).unwrap();
            }
        });

        am3_bb_wait_gpio_attributes_at(root.path(), 22).unwrap();
        materializer.join().unwrap();
    }

    #[test]
    fn terminal_psu_write_fence_shares_the_retained_gpio65_cutoff_publication() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        let mut set = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
            root.path(),
            65,
            true,
            |_| Ok("out".into()),
            Am3BbRetainedReadbackMode::OrdinaryFileFixture,
        )
        .unwrap();
        let terminal = Arc::clone(&set.runtime.io.terminal);
        let writer = Arc::clone(&set.runtime.io.on_writer_thread);
        let publication = am3_bb_publish_psu_write(&terminal, &writer).unwrap();
        assert!(am3_bb_publish_psu_write(&terminal, &writer).is_err());
        assert_ne!(writer.load(Ordering::SeqCst), 0);
        assert!(set.panic.cut_raw_noalloc());
        drop(publication);
        assert_eq!(writer.load(Ordering::SeqCst), 0);
        assert!(am3_bb_publish_psu_write(&terminal, &writer).is_err());
        assert!(
            dcentrald_hal::platform::beaglebone_cold_boot::PreparedBoardEnable::assert_checked(
                &mut set.runtime
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(gpio.join("value")).unwrap().trim(),
            "0"
        );
    }

    #[test]
    fn retained_gpio65_cutoff_set_prepares_glitch_free_off_and_owns_the_only_on_transition() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        std::fs::write(gpio.join("active_low"), "1").unwrap();
        std::fs::write(gpio.join("value"), "1").unwrap();

        let mut set = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
            root.path(),
            65,
            true,
            |direction_path| {
                // Model the kernel's atomic `direction=low` behavior: the
                // ordinary-file fixture does not update `value` itself.
                std::fs::write(direction_path.parent().unwrap().join("value"), "0")?;
                Ok("out\n".to_owned())
            },
            Am3BbRetainedReadbackMode::OrdinaryFileFixture,
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(gpio.join("active_low")).unwrap(),
            "0"
        );
        assert_eq!(
            std::fs::read_to_string(gpio.join("direction")).unwrap(),
            "low"
        );
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");

        PreparedBoardEnable::assert_checked(&mut set.runtime).unwrap();
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "1");
        assert!(PreparedBoardEnable::assert_checked(&mut set.runtime).is_err());

        set.heartbeat.cut_checked().unwrap();
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");
        assert!(PreparedBoardEnable::assert_checked(&mut set.runtime).is_err());
    }

    #[test]
    fn every_retained_gpio65_lane_can_cut_with_an_independent_file_offset() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        let mut set = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
            root.path(),
            65,
            true,
            |_path| Ok("out".to_owned()),
            Am3BbRetainedReadbackMode::OrdinaryFileFixture,
        )
        .unwrap();

        PreparedBoardEnable::assert_checked(&mut set.runtime).unwrap();
        set.heartbeat.cut_checked().unwrap();
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");

        std::fs::write(gpio.join("value"), "1").unwrap();
        assert!(set.panic.cut_raw_noalloc());
        set.panic.read_off_checked().unwrap();

        std::fs::write(gpio.join("value"), "1").unwrap();
        set.runtime.cut_checked().unwrap();
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");
    }

    #[test]
    fn emergency_gpio65_cut_before_energization_permanently_revokes_on_authority() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        let mut set = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
            root.path(),
            65,
            true,
            |_path| Ok("out".to_owned()),
            Am3BbRetainedReadbackMode::OrdinaryFileFixture,
        )
        .unwrap();

        set.heartbeat.cut_checked().unwrap();
        let error = PreparedBoardEnable::assert_checked(&mut set.runtime)
            .unwrap_err()
            .to_string();

        assert!(error.contains("terminal=true"), "{error}");
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");
    }

    #[test]
    fn retained_gpio65_cutoff_uses_open_inode_after_ordinary_unlink_fixture() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        let mut set = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
            root.path(),
            65,
            true,
            |_path| Ok("out".to_owned()),
            Am3BbRetainedReadbackMode::OrdinaryFileFixture,
        )
        .unwrap();

        PreparedBoardEnable::assert_checked(&mut set.runtime).unwrap();
        std::fs::remove_file(gpio.join("value")).unwrap();

        set.runtime.cut_checked().unwrap();
        set.runtime.io.read_off_checked().unwrap();
        // This proves the implementation performs no path reopen. It does not
        // model sysfs/kernfs unexport, which can invalidate retained FDs with
        // ENODEV/EIO and remains contained by checked fallback + watchdog.
        assert!(!gpio.join("value").exists());
    }

    #[test]
    fn panic_gpio65_cut_serializes_with_published_on_writer_and_finishes_low() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        let set = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
            root.path(),
            65,
            true,
            |_path| Ok("out".to_owned()),
            Am3BbRetainedReadbackMode::OrdinaryFileFixture,
        )
        .unwrap();
        let writer_thread = Arc::clone(&set.panic.on_writer_thread);
        let terminal = Arc::clone(&set.panic.terminal);

        // `usize::MAX` is the established fixture token for "some other thread
        // published an ON write and has not retired yet" — the same sentinel
        // the budget-exhaustion sibling below uses. It must not be this
        // thread's own token: the lane deliberately short-circuits when the
        // in-flight writer IS the caller, which is a different case.
        writer_thread.store(usize::MAX, Ordering::SeqCst);

        // Drive the adversarial interleaving by construction. The hook runs
        // inside the lane at the one instant that matters: after the first
        // physical LOW, before the serialization loop.
        //
        // Previously this test spawned the lane on another thread and spun a
        // 10_000-iteration yield budget hoping to catch that window. Under load
        // the spawned thread could fail to be scheduled at all within the
        // budget, so the fixture wrote its HIGH too early and the assertions
        // failed on a machine that was merely busy — and the workaround was a
        // `sleep(2ms)` compiled into the panic lane itself. Both are gone.
        let observed_first_low = Arc::new(AtomicBool::new(false));
        let mut panic_lane = set.panic;
        let hook_value_path = gpio.join("value");
        let hook_writer_thread = Arc::clone(&writer_thread);
        let hook_observed_first_low = Arc::clone(&observed_first_low);
        panic_lane.after_first_low_hook = Some(Arc::new(move || {
            // The lane must already have driven the pin LOW before it waits on
            // anyone. Asserting it here — rather than polling for it — is what
            // makes the ordering a proof instead of an observation.
            let level = std::fs::read_to_string(&hook_value_path).unwrap();
            assert!(
                level.starts_with('0'),
                "panic lane entered serialization without a first LOW (value={level:?})"
            );
            hook_observed_first_low.store(true, Ordering::SeqCst);

            // The published ON writer lands HIGH after our first LOW, then
            // retires. The lane must notice and re-cut.
            std::fs::write(&hook_value_path, "1").unwrap();
            hook_writer_thread.store(0, Ordering::SeqCst);
        }));

        let cutoff_succeeded = panic_lane.cut_raw_noalloc();

        assert!(
            observed_first_low.load(Ordering::SeqCst),
            "the rendezvous never fired, so nothing was actually serialized"
        );
        assert!(terminal.load(Ordering::SeqCst));
        assert!(cutoff_succeeded);
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");
    }

    #[test]
    fn polarity_drift_is_cut_physically_low_but_refuses_a_checked_receipt() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        let mut set = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
            root.path(),
            65,
            true,
            |_path| Ok("out".to_owned()),
            Am3BbRetainedReadbackMode::OrdinaryFileFixture,
        )
        .unwrap();
        PreparedBoardEnable::assert_checked(&mut set.runtime).unwrap();
        std::fs::write(gpio.join("active_low"), "1").unwrap();

        let error = set.heartbeat.cut_checked().unwrap_err().to_string();

        assert!(error.contains("active_low readback mismatch"), "{error}");
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");
        assert!(PreparedBoardEnable::assert_checked(&mut set.runtime).is_err());
    }

    #[test]
    fn raw_cutoff_descriptor_failure_still_revokes_on_authority() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        let mut set = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
            root.path(),
            65,
            true,
            |_path| Ok("out".to_owned()),
            Am3BbRetainedReadbackMode::OrdinaryFileFixture,
        )
        .unwrap();
        set.panic.direction_writer = std::fs::OpenOptions::new()
            .read(true)
            .open(gpio.join("direction"))
            .unwrap();

        assert!(!set.panic.cut_raw_noalloc());
        assert!(set.panic.terminal.load(Ordering::SeqCst));
        assert!(PreparedBoardEnable::assert_checked(&mut set.runtime).is_err());
    }

    #[test]
    fn landed_on_write_with_failed_readback_is_immediately_recut() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        let mut set = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
            root.path(),
            65,
            true,
            |_path| Ok("out".to_owned()),
            Am3BbRetainedReadbackMode::OrdinaryFileFixture,
        )
        .unwrap();
        set.runtime.fail_on_readback_after_on_write = true;

        let error = PreparedBoardEnable::assert_checked(&mut set.runtime)
            .unwrap_err()
            .to_string();

        assert!(error.contains("after the HIGH write landed"), "{error}");
        assert!(error.contains("mandatory OFF re-cut=Ok"), "{error}");
        assert_eq!(set.runtime.state, Am3BbBoardEnableState::TerminalOff);
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");
        assert!(set.runtime.io.terminal.load(Ordering::SeqCst));
        assert!(PreparedBoardEnable::assert_checked(&mut set.runtime).is_err());
    }

    #[test]
    fn panic_cutoff_iteration_budget_exhausts_when_a_foreign_on_writer_never_retires() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        let set = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
            root.path(),
            65,
            true,
            |_path| Ok("out".to_owned()),
            Am3BbRetainedReadbackMode::OrdinaryFileFixture,
        )
        .unwrap();
        set.panic
            .on_writer_thread
            .store(usize::MAX, Ordering::SeqCst);
        let writer_thread = Arc::clone(&set.panic.on_writer_thread);
        let terminal = Arc::clone(&set.panic.terminal);
        let (completed_tx, completed_rx) = std_mpsc::channel();
        let worker = thread::spawn(move || {
            completed_tx.send(set.panic.cut_raw_noalloc()).unwrap();
        });
        // This timeout is a DEADLOCK GUARD, not a performance assertion. The
        // property under test is "the budget is finite", and exhausting it
        // costs AM3_BB_CUTOFF_SERIALIZATION_YIELD_LIMIT (4096) real sysfs
        // writes plus a sched_yield each. On a loaded host that legitimately
        // exceeds a second, so the previous one-second bound failed the gate
        // for being busy rather than for being wrong. Keep it generous: if the
        // unbounded-loop regression ever returns, the release-then-join below
        // still unblocks the worker, so a slow machine waits and a broken lane
        // is still caught.
        let completion = completed_rx.recv_timeout(Duration::from_secs(120));
        // If the old infinite loop regresses, release the fixture before the
        // assertion so the test fails instead of hanging the entire suite.
        writer_thread.store(0, Ordering::SeqCst);
        worker.join().unwrap();

        assert_eq!(
            completion.expect(
                "panic lane never returned within the deadlock guard: the bounded \
                 serialization budget has regressed to an unbounded wait"
            ),
            false
        );
        assert!(terminal.load(Ordering::SeqCst));
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");
    }

    #[test]
    fn heartbeat_terminal_error_cuts_gpio65_before_returning_failure() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        let mut set = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
            root.path(),
            65,
            true,
            |_path| Ok("out".to_owned()),
            Am3BbRetainedReadbackMode::OrdinaryFileFixture,
        )
        .unwrap();
        PreparedBoardEnable::assert_checked(&mut set.runtime).unwrap();

        let error = am3_bb_cut_on_heartbeat_error::<()>(
            Err(anyhow::anyhow!("injected terminal heartbeat failure")),
            &set.heartbeat,
            "test-terminal-heartbeat-failure",
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("immediate retained PSU GPIO65 cutoff"),
            "{error}"
        );
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");
        assert!(PreparedBoardEnable::assert_checked(&mut set.runtime).is_err());
    }

    #[test]
    fn non_active_high_gpio65_topology_is_refused_before_any_gpio_mutation() {
        let root = TempGpioRoot::new();
        let gpio = root.add_gpio(65);
        std::fs::write(gpio.join("direction"), "inherited").unwrap();
        std::fs::write(gpio.join("active_low"), "1").unwrap();
        std::fs::write(gpio.join("value"), "1").unwrap();

        let error = am3_bb_prepare_board_cutoff_set_at(root.path(), 65, false)
            .err()
            .expect("inactive-high topology must be rejected")
            .to_string();

        assert!(error.contains("active-high"), "{error}");
        assert_eq!(
            std::fs::read_to_string(gpio.join("direction")).unwrap(),
            "inherited"
        );
        assert_eq!(
            std::fs::read_to_string(gpio.join("active_low")).unwrap(),
            "1"
        );
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "1");
        assert_eq!(
            std::fs::read_to_string(root.path().join("export")).unwrap(),
            ""
        );
    }

    #[test]
    fn am3_bb_get_address_stream_reports_only_crc_verified_unassigned_frames() {
        let raw = live_get_address_stream(2);
        let observation = inspect_am3_bb_get_address_stream(&raw).unwrap();

        assert_eq!(observation.response_frames, 2);
        assert_eq!(observation.raw_bytes, 18);
        assert_eq!(
            observation.integrity,
            GetAddressIntegrity::CommandResponseCrc5Verified
        );
    }

    #[test]
    fn am3_bb_get_address_stream_rejects_truncated_live_fixture() {
        let mut raw = live_get_address_stream(2);
        raw.pop();

        assert_eq!(
            inspect_am3_bb_get_address_stream(&raw),
            Err(GetAddressInspectionError::IncompleteFrame { raw_bytes: 17 })
        );
    }

    #[test]
    fn am3_bb_get_address_stream_rejects_bad_preamble_and_non_fixture_payload() {
        let mut bad_preamble = live_get_address_stream(2);
        bad_preamble[0] = 0x55;
        assert_eq!(
            inspect_am3_bb_get_address_stream(&bad_preamble),
            Err(GetAddressInspectionError::BadPreamble { frame_index: 0 })
        );

        let mut mixed = live_get_address_stream(2);
        mixed[12] = 0x66;
        mixed[17] = dcentrald_asic::protocol::bm13xx_command_response_crc5(&mixed[11..17]);
        assert_eq!(
            inspect_am3_bb_get_address_stream(&mixed),
            Err(GetAddressInspectionError::NotRecordedUnassignedPayload { frame_index: 1 })
        );
    }

    #[test]
    fn am3_bb_get_address_stream_rejects_bad_low_five_crc() {
        let mut raw = live_get_address_stream(1);
        raw[8] ^= 0x01;

        assert_eq!(
            inspect_am3_bb_get_address_stream(&raw),
            Err(GetAddressInspectionError::BadResponseCrc5 {
                frame_index: 0,
                expected: 0x0D,
                observed: 0x0C,
            })
        );
    }

    #[test]
    fn am3_bb_get_address_stream_ignores_opaque_trailer_bits_six_and_five() {
        let mut raw = live_get_address_stream(1);
        raw[8] |= 0x60;
        let observation = inspect_am3_bb_get_address_stream(&raw).unwrap();

        assert_eq!(observation.response_frames, 1);
        assert_eq!(
            observation.integrity,
            GetAddressIntegrity::CommandResponseCrc5Verified
        );
    }

    #[test]
    fn am3_bb_get_address_stream_rejects_job_response_trailer() {
        let mut raw = live_get_address_stream(1);
        raw[8] |= 0x80;

        assert_eq!(
            inspect_am3_bb_get_address_stream(&raw),
            Err(GetAddressInspectionError::JobResponseTrailer { frame_index: 0 })
        );
    }

    #[test]
    fn am3_bb_get_address_uses_response_crc_not_shared_command_crc5() {
        let frame = LIVE_BM1362_GET_ADDRESS_FRAME;
        let observed_trailer = frame[8];

        assert_eq!(observed_trailer, 0x0D);
        assert_eq!(
            dcentrald_asic::protocol::bm13xx_command_response_crc5(&frame[2..8]),
            observed_trailer & 0x1F
        );
        assert_eq!(dcentrald_asic::protocol::crc5(&frame[2..8]), 0x05);
        assert_eq!(dcentrald_asic::protocol::crc5(&frame[..8]), 0x01);
        assert_ne!(
            observed_trailer,
            dcentrald_asic::protocol::crc5(&frame[2..8])
        );
        assert_ne!(
            observed_trailer,
            dcentrald_asic::protocol::crc5(&frame[..8])
        );
    }

    #[test]
    fn dspic_shutdown_delivers_every_safeoff_before_observing_any_ack() {
        let events = RefCell::new(Vec::new());
        let evidence = am3_bb_disable_dspics_two_phase(
            &[0x20, 0x21, 0x22],
            true,
            |chain, _| {
                events.borrow_mut().push(format!("deliver-{chain}"));
                Ok(())
            },
            |chain, _| {
                events.borrow_mut().push(format!("observe-{chain}"));
                Ok(vec![0x15, 0x00])
            },
        );

        assert_eq!(
            events.into_inner(),
            vec![
                "deliver-0",
                "deliver-1",
                "deliver-2",
                "observe-0",
                "observe-1",
                "observe-2",
            ]
        );
        assert_eq!(
            evidence,
            Am3BbDspicShutdownEvidence {
                delivery_attempts: 3,
                delivery_failures: 0,
                observation_attempts: 3,
                observation_failures: 0,
            }
        );
    }

    #[test]
    fn dspic_shutdown_separates_delivery_and_observation_failures() {
        let observed = RefCell::new(Vec::new());
        let evidence = am3_bb_disable_dspics_two_phase(
            &[0x20, 0x21, 0x22],
            true,
            |chain, _| {
                if chain == 1 {
                    anyhow::bail!("delivery failed")
                }
                Ok(())
            },
            |chain, _| {
                observed.borrow_mut().push(chain);
                if chain == 2 {
                    anyhow::bail!("observation failed")
                }
                Ok(vec![0x15, 0x00])
            },
        );

        assert_eq!(observed.into_inner(), vec![0, 2]);
        assert_eq!(evidence.delivery_attempts, 3);
        assert_eq!(evidence.delivery_failures, 1);
        assert_eq!(evidence.observation_attempts, 2);
        assert_eq!(evidence.observation_failures, 1);
        assert!(!evidence.all_delivered());
    }

    #[test]
    fn terminal_dspic_shutdown_skips_ack_observation_before_hard_cutoff() {
        let delivered = RefCell::new(Vec::new());
        let evidence = am3_bb_disable_dspics_two_phase(
            &[0x20, 0x21, 0x22],
            false,
            |chain, _| {
                delivered.borrow_mut().push(chain);
                Ok(())
            },
            |_chain, _| -> Result<Vec<u8>> {
                panic!("terminal teardown must not attempt optional ACK observation")
            },
        );

        assert_eq!(delivered.into_inner(), vec![0, 1, 2]);
        assert_eq!(evidence.delivery_attempts, 3);
        assert_eq!(evidence.delivery_failures, 0);
        assert_eq!(evidence.observation_attempts, 0);
        assert_eq!(evidence.observation_failures, 0);
    }

    #[test]
    fn dspic_voltage_mutations_each_receive_adjacent_admission() {
        let events = RefCell::new(Vec::new());
        let mut admit = |chain, addr| {
            events
                .borrow_mut()
                .push(format!("admit-{chain}-0x{addr:02X}"));
            Ok(())
        };

        for (chain, addr) in [(0, 0x20), (1, 0x21)] {
            events
                .borrow_mut()
                .push(format!("query-before-{chain}-0x{addr:02X}"));
            am3_bb_with_energize_admission(chain, addr, &mut admit, || {
                events
                    .borrow_mut()
                    .push(format!("set-voltage-{chain}-0x{addr:02X}"));
                Ok(())
            })
            .unwrap();
            events
                .borrow_mut()
                .push(format!("query-after-set-{chain}-0x{addr:02X}"));
            am3_bb_with_energize_admission(chain, addr, &mut admit, || {
                events
                    .borrow_mut()
                    .push(format!("enable-{chain}-0x{addr:02X}"));
                Ok(())
            })
            .unwrap();
        }

        assert_eq!(
            events.into_inner(),
            vec![
                "query-before-0-0x20",
                "admit-0-0x20",
                "set-voltage-0-0x20",
                "query-after-set-0-0x20",
                "admit-0-0x20",
                "enable-0-0x20",
                "query-before-1-0x21",
                "admit-1-0x21",
                "set-voltage-1-0x21",
                "query-after-set-1-0x21",
                "admit-1-0x21",
                "enable-1-0x21",
            ]
        );
    }

    #[test]
    fn dspic_voltage_query_cancellation_stops_current_controller_energize() {
        let shutdown = CancellationToken::new();
        let events = RefCell::new(Vec::new());
        events.borrow_mut().push("query-before-0-0x20".to_string());
        shutdown.cancel();

        let error = am3_bb_with_energize_admission(
            0,
            0x20,
            &mut |chain, addr| {
                events
                    .borrow_mut()
                    .push(format!("admit-{chain}-0x{addr:02X}"));
                if shutdown.is_cancelled() {
                    anyhow::bail!("shutdown before chain {chain} energize");
                }
                Ok(())
            },
            || {
                events.borrow_mut().push("set-voltage-0-0x20".to_string());
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("shutdown before chain 0 energize"));
        assert_eq!(
            events.into_inner(),
            vec!["query-before-0-0x20", "admit-0-0x20"]
        );
    }

    #[test]
    fn pic_application_query_retains_exact_service_plan_and_admits_three_slots() {
        for chain in 0..3 {
            let mut calls = 0;
            let reply =
                am3_bb_dspic_read_application(chain, 0x20 + chain as u8, |label, addr, steps| {
                    calls += 1;
                    assert!(matches!(label, I2cMutationLabel::QueryPrelude));
                    assert_eq!(addr, 0x20 + chain as u8);
                    let mut events = Vec::new();
                    for step in steps {
                        match step {
                            I2cTransactionStep::Write(bytes) => {
                                events.push(format!("write:{bytes:02x?}"))
                            }
                            I2cTransactionStep::Read(count) => events.push(format!("read:{count}")),
                            I2cTransactionStep::SleepMs(ms) => events.push(format!("wait:{ms}")),
                            _ => panic!("unexpected application query operation"),
                        }
                    }
                    assert_eq!(
                        events,
                        [
                            "write:[55, aa, 04, 17, 00, 1b]",
                            "wait:135",
                            "read:1",
                            "wait:20",
                            "read:1",
                            "wait:20",
                            "read:1",
                            "wait:20",
                            "read:1",
                            "wait:20",
                            "read:1",
                        ]
                    );
                    Ok([0x05, 0x17, 0x89, 0x00, 0xa5]
                        .map(|byte| vec![byte])
                        .to_vec())
                })
                .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(reply, [0x05, 0x17, 0x89, 0x00, 0xa5]);
        }
    }

    #[test]
    fn pic_application_refuses_foreign_firmware_opcode_and_corrupt_frames() {
        let baseline = [0x05u8, 0x17, 0x89, 0x00, 0xa5];
        let rejects = |reply: Vec<u8>| {
            let mut calls = 0;
            let result = am3_bb_dspic_read_application(0, 0x20, |_, _, _| {
                calls += 1;
                Ok(reply.into_iter().map(|byte| vec![byte]).collect())
            });
            assert!(result.is_err());
            assert_eq!(calls, 1, "no retry or recovery query after refusal");
        };
        // Retain a valid checksum while changing every firmware/opcode/pad
        // value; a plausible version byte alone is insufficient admission.
        for index in [1, 2, 3] {
            for byte in 0..=u8::MAX {
                if byte == baseline[index] {
                    continue;
                }
                let mut reply = baseline;
                reply[index] = byte;
                reply[4] = reply[..4]
                    .iter()
                    .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
                rejects(reply.to_vec());
            }
        }
        for index in 0..5 {
            for bit in 0..8 {
                let mut reply = baseline;
                reply[index] ^= 1 << bit;
                rejects(reply.to_vec());
            }
        }
        for reply in [
            vec![],
            vec![0x82],
            vec![0xf5],
            vec![0; 5],
            vec![0xff; 5],
            vec![0x05, 0x17, 0x89],
            vec![0x05, 0x17, 0x89, 0x00, 0xa5, 0x00],
        ] {
            rejects(reply);
        }
    }

    #[test]
    fn pic_application_refuses_incomplete_redistributed_and_failed_acquisition() {
        let baseline = [0x05, 0x17, 0x89, 0x00, 0xa5]
            .map(|byte| vec![byte])
            .to_vec();
        let rejects = |reads| {
            assert!(am3_bb_dspic_read_application(0, 0x20, |_, _, _| Ok(reads)).is_err());
        };
        for count in (0..=7).filter(|count| *count != 5) {
            rejects(vec![vec![0]; count]);
        }
        for index in 0..5 {
            for length in [0, 2, 5] {
                let mut reads = baseline.clone();
                reads[index] = vec![baseline[index][0]; length];
                rejects(reads);
            }
        }
        // Flattening these altered boundaries still yields the exact valid
        // five bytes. Admission requires all five requested reads completed.
        for index in 0..4 {
            let mut reads = baseline.clone();
            let next = reads[index + 1][0];
            reads[index].push(next);
            reads[index + 1].clear();
            assert_eq!(
                reads.iter().flatten().copied().collect::<Vec<_>>(),
                [0x05, 0x17, 0x89, 0x00, 0xa5]
            );
            rejects(reads);
        }
        let mut calls = 0;
        let failure = am3_bb_dspic_read_application(0, 0x20, |_, _, _| {
            calls += 1;
            anyhow::bail!("injected service cancellation");
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert!(format!("{failure:#}").contains("injected service cancellation"));
    }

    #[test]
    fn pic_application_refuses_foreign_endpoint_before_query() {
        for chain in [0, 1, 2, 3, usize::MAX] {
            for addr in 0..=u8::MAX {
                if chain < 3 && addr == 0x20 + chain as u8 {
                    continue;
                }
                assert!(am3_bb_dspic_read_application(chain, addr, |_, _, _| {
                    panic!("foreign endpoint reached service");
                })
                .is_err());
            }
        }
    }

    #[test]
    fn heartbeat_protocol_validation_requires_exact_verified_reply() {
        let verified = vec![0x06, 0x16, 0x01, 0x00, 0x00, 0x1D];
        assert_eq!(
            am3_bb_validate_heartbeat_reply(0, 0x20, verified.clone()).unwrap(),
            verified
        );

        // Correct length is insufficient: framing checksum, opcode, and the
        // exact target payload are independent admission requirements.
        assert!(
            am3_bb_validate_heartbeat_reply(0, 0x20, vec![0x06, 0x16, 0x01, 0x00, 0x00, 0x1E])
                .unwrap_err()
                .to_string()
                .contains("CksumMismatch")
        );
        assert!(
            am3_bb_validate_heartbeat_reply(0, 0x20, vec![0x06, 0x17, 0x01, 0x00, 0x00, 0x1E])
                .unwrap_err()
                .to_string()
                .contains("opcode")
        );
        assert!(
            am3_bb_validate_heartbeat_reply(0, 0x20, vec![0x06, 0x16, 0x00, 0x00, 0x00, 0x1C])
                .unwrap_err()
                .to_string()
                .contains("payload")
        );
    }

    #[test]
    fn heartbeat_admission_requires_all_expected_protocol_valid_chains() {
        let (events_tx, events_rx) = std_mpsc::channel();
        let mut admission = Am3BbHeartbeatAdmission::new(events_rx, 3);
        events_tx
            .send(Am3BbHeartbeatEvent::VerifiedHeartbeatReady {
                validated_chains: 2,
            })
            .unwrap();

        let error = admission
            .wait_for_verified_heartbeat_readiness(
                &CancellationToken::new(),
                Duration::from_millis(50),
            )
            .unwrap_err();
        assert!(error.to_string().contains("expected 3"));
    }

    #[test]
    fn heartbeat_terminal_failure_remains_observable_after_readiness() {
        let (events_tx, events_rx) = std_mpsc::channel();
        let mut admission = Am3BbHeartbeatAdmission::new(events_rx, 3);
        events_tx
            .send(Am3BbHeartbeatEvent::VerifiedHeartbeatReady {
                validated_chains: 3,
            })
            .unwrap();
        let receipt = admission
            .wait_for_verified_heartbeat_readiness(
                &CancellationToken::new(),
                Duration::from_millis(50),
            )
            .unwrap();
        assert_eq!(receipt.validated_chains, 3);

        events_tx
            .send(Am3BbHeartbeatEvent::TerminalFailure {
                reason: "controller stopped answering".to_string(),
            })
            .unwrap();
        let error = admission
            .require_ready_and_healthy("test-runtime")
            .unwrap_err();
        assert!(error.to_string().contains("controller stopped answering"));
    }

    #[test]
    fn heartbeat_bringup_and_energizing_boundaries_are_ordered() {
        let source = include_str!("am3_bb_mining.rs");
        let start = source.find("fn run_am3_bb_blocking(").unwrap();
        let end = source[start..]
            .find("fn bm1362_command_wire_frame(")
            .map(|offset| start + offset)
            .unwrap();
        let bringup = &source[start..end];

        let readiness = bringup
            .find(".wait_for_verified_heartbeat_readiness(&shutdown)")
            .unwrap();
        let reset_boundary = bringup.find("\"post-dsPIC ASIC reset release\"").unwrap();
        let reset = bringup
            .find("am3_bb_post_dspic_reset_chains(&platform")
            .unwrap();
        let bm_boundary = bringup.find("\"BM1362 chain initialization\"").unwrap();
        let bm_init = bringup.find("bm1362_chip_init_one_chain(").unwrap();
        let open_core_boundary = bringup.find("\"dsPIC open-core voltage\"").unwrap();
        let open_core = bringup
            .find("\"open-core-voltage\",")
            .expect("open-core voltage mutation exists");

        assert!(readiness < reset_boundary && reset_boundary < reset);
        assert!(reset < bm_boundary && bm_boundary < bm_init);
        assert!(bm_init < open_core_boundary && open_core_boundary < open_core);

        let mining_loop = &source[source.find("fn run_mining_loop<U").unwrap()..];
        let heartbeat_admission = mining_loop.find("\"watched Mining admission\"").unwrap();
        let watchdog_mining = mining_loop.find("watchdog.enter_mining()").unwrap();
        assert!(heartbeat_admission < watchdog_mining);
    }

    #[test]
    fn admitted_platform_topology_is_captured_once_and_moved_into_the_engine() {
        let source = include_str!("am3_bb_mining.rs");
        let receipt_start = source
            .find("impl Am3BbRouteReceipt {")
            .expect("AM3-BB route receipt implementation");
        let receipt_end = source[receipt_start..]
            .find("pub(crate) struct Am3BbSafetyAdmission")
            .map(|offset| receipt_start + offset)
            .unwrap();
        let receipt = &source[receipt_start..receipt_end];
        assert_eq!(receipt.matches("BeagleBonePlatform::new()").count(), 1);
        let capture = receipt
            .split_once("fn capture(")
            .unwrap()
            .1
            .split_once("fn api_identity(")
            .unwrap()
            .0;
        assert!(capture.contains("AM3_BB_TOPOLOGY_CAPTURE_RECEIPT schema=v3"));
        assert!(!capture.contains("AM3_BB_ROUTE_ADMISSION_RECEIPT"));

        let admission_start = source
            .find("pub(crate) async fn start(")
            .expect("AM3-BB safety admission constructor");
        let admission_end = source[admission_start..]
            .find("pub async fn run_am3_bb_mining(")
            .map(|offset| admission_start + offset)
            .unwrap();
        let admission = &source[admission_start..admission_end];
        assert_eq!(
            admission
                .matches("Am3BbRouteReceipt::capture(identity)")
                .count(),
            1
        );
        let topology_capture = admission
            .find("Am3BbRouteReceipt::capture(identity)")
            .unwrap();
        let watchdog = admission
            .find("SafetyWatchdogOwner::start_before_energizing")
            .unwrap();
        assert!(topology_capture < watchdog);
        let armed = admission
            .find("WatchdogAdmission::Armed(receipt) => receipt")
            .unwrap();
        let route_scope = admission
            .find("watchdog.claim_am3_bb_route_scope()")
            .unwrap();
        let admitted_receipt = admission
            .find("route_receipt.publish_admission_receipt()")
            .unwrap();
        assert!(watchdog < armed && armed < route_scope && route_scope < admitted_receipt);
        assert!(
            admission.contains("runtime_dispatch_admission")
                && admission.contains(".require_asic_protocol(")
        );
        assert!(admission.contains("Ok(Self {\n            route_receipt,"));

        let blocking_start = source.find("fn run_am3_bb_blocking(").unwrap();
        let blocking_end = source[blocking_start..]
            .find("fn bm1362_command_wire_frame(")
            .map(|offset| blocking_start + offset)
            .unwrap();
        let blocking = &source[blocking_start..blocking_end];
        assert!(!blocking.contains("BeagleBonePlatform::new()"));
        assert!(blocking.contains("let Am3BbSafetyAdmission {\n        route_receipt,"));
        assert!(blocking.contains("let platform = route_receipt.platform;"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stratum_task_guard_joins_publishers_before_terminal_state() {
        let mut initial = dcentrald_api::MinerState::empty(dcentrald_api::OperatingMode::Standard);
        initial.hashrate_ghs = 123.0;
        initial.hashrate_5s_ghs = 99.0;
        initial.pool.status = "mining".to_string();
        let (state_tx, state_rx) = watch::channel(initial);
        let shutdown = CancellationToken::new();
        let router_stopped = Arc::new(AtomicBool::new(false));
        let publisher_closed = Arc::new(AtomicBool::new(false));
        let mut guard = Am3BbStratumTaskGuard::pending(
            tokio::runtime::Handle::current(),
            shutdown.clone(),
            publisher_closed.clone(),
        );

        let router_shutdown = shutdown.clone();
        let router_stopped_task = router_stopped.clone();
        guard.spawn_router(async move {
            router_shutdown.cancelled().await;
            router_stopped_task.store(true, Ordering::Release);
        });
        let status_shutdown = shutdown.clone();
        let late_state_tx = state_tx.clone();
        let late_publisher_closed = publisher_closed.clone();
        guard.spawn_status(async move {
            status_shutdown.cancelled().await;
            late_state_tx.send_modify(|state| {
                if late_publisher_closed.load(Ordering::Acquire) {
                    return;
                }
                state.hashrate_ghs = 777.0;
                state.pool.status = "late-publisher".to_string();
            });
        });

        tokio::task::spawn_blocking(move || {
            guard.stop_and_join(Instant::now() + Duration::from_secs(1))
        })
        .await
        .expect("blocking join task")
        .expect("Stratum tasks join cleanly");

        assert!(router_stopped.load(Ordering::Acquire));
        let after_join = state_rx.borrow().clone();
        assert_eq!(after_join.hashrate_ghs, 123.0);
        assert_eq!(after_join.pool.status, "mining");

        let mut terminal = Am3BbTerminalStatePublisher::new(state_tx);
        terminal.begin_stopping();
        terminal.record_safe_off(false);
        terminal.finish_stopped();
        let terminal = state_rx.borrow().clone();
        assert_eq!(terminal.hashrate_ghs, 0.0);
        assert_eq!(terminal.hashrate_5s_ghs, 0.0);
        assert_eq!(terminal.pool.status, "stopped");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stratum_abort_never_waits_beyond_the_original_absolute_deadline() {
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let shutdown = CancellationToken::new();
        let publisher_closed = Arc::new(AtomicBool::new(false));
        let router_dropped = Arc::new(AtomicBool::new(false));
        let status_dropped = Arc::new(AtomicBool::new(false));
        let mut guard = Am3BbStratumTaskGuard::pending(
            tokio::runtime::Handle::current(),
            shutdown,
            publisher_closed,
        );
        let router_drop = DropFlag(router_dropped.clone());
        guard.spawn_router(async move {
            let _drop = router_drop;
            std::future::pending::<()>().await
        });
        let status_drop = DropFlag(status_dropped.clone());
        guard.spawn_status(async move {
            let _drop = status_drop;
            std::future::pending::<()>().await
        });
        tokio::task::yield_now().await;
        let started_at = Instant::now();
        let deadline = started_at + Duration::from_millis(20);

        let error = tokio::task::spawn_blocking(move || guard.stop_and_join(deadline))
            .await
            .expect("blocking join task")
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("without an unbounded follow-up join"));
        assert!(started_at.elapsed() < Duration::from_millis(150));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !(router_dropped.load(Ordering::Acquire)
                && status_dropped.load(Ordering::Acquire))
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both aborted Stratum futures must be destroyed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stratum_partial_roster_error_retains_and_aborts_all_owned_tasks() {
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let shutdown = CancellationToken::new();
        let publisher_closed = Arc::new(AtomicBool::new(false));
        let router_dropped = Arc::new(AtomicBool::new(false));
        let mut guard = Am3BbStratumTaskGuard::pending(
            tokio::runtime::Handle::current(),
            shutdown.clone(),
            publisher_closed.clone(),
        );
        let router_drop = DropFlag(router_dropped.clone());
        guard.spawn_router(async move {
            let _drop = router_drop;
            std::future::pending::<()>().await
        });
        tokio::task::yield_now().await;

        let (guard, error) = tokio::task::spawn_blocking(move || {
            let error = guard
                .stop_and_join(Instant::now() + Duration::from_secs(1))
                .expect_err("partial roster cannot produce join evidence");
            (guard, error)
        })
        .await
        .expect("blocking partial-roster check");
        assert!(error.to_string().contains("incomplete Stratum task roster"));
        assert!(
            guard.router.is_some(),
            "router ownership must remain retained"
        );
        assert!(shutdown.is_cancelled());
        assert!(publisher_closed.load(Ordering::Acquire));
        drop(guard);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !router_dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retained router future must be destroyed by guard Drop");
    }

    #[tokio::test]
    async fn stratum_guard_owns_cancellation_before_first_spawn() {
        let shutdown = CancellationToken::new();
        let publisher_closed = Arc::new(AtomicBool::new(false));
        let mut guard = Am3BbStratumTaskGuard::pending(
            tokio::runtime::Handle::current(),
            shutdown.clone(),
            publisher_closed.clone(),
        );
        guard.spawn_router(std::future::pending::<()>());

        drop(guard);

        assert!(shutdown.is_cancelled());
        assert!(publisher_closed.load(Ordering::Acquire));
    }

    #[test]
    fn stratum_and_cleanup_deadlines_are_strictly_capped() {
        let now = Instant::now();
        let cleanup = now + Duration::from_secs(26);
        assert_eq!(
            am3_bb_capped_cleanup_deadline(cleanup, now, Duration::from_secs(2)),
            now + Duration::from_secs(2)
        );
        let nearly_expired = now + Duration::from_millis(10);
        assert_eq!(
            am3_bb_capped_cleanup_deadline(nearly_expired, now, Duration::from_secs(2)),
            nearly_expired
        );
    }

    #[test]
    fn mining_loop_top_level_error_is_structurally_pre_spawn() {
        let source = include_str!("am3_bb_mining.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production AM3 source");
        let preparation = production
            .split_once("fn run_mining_loop<U: ChainUart>(")
            .expect("AM3 mining loop")
            .1;
        let (pre_spawn, started_and_after) = preparation
            .split_once("fn run_started_mining_loop<U: ChainUart>(")
            .expect("explicit AM3 started phase");
        let started = started_and_after
            .split_once("/// Monotonic microseconds")
            .expect("AM3 started-loop boundary")
            .0;

        assert!(pre_spawn.contains("Am3BbMiningLoopNotStarted"));
        assert!(!production.contains("impl From<anyhow::Error> for Am3BbMiningLoopNotStarted"));
        assert!(pre_spawn.contains(".map_err(Am3BbMiningLoopNotStarted)?"));
        assert!(pre_spawn.contains("Ok(run_started_mining_loop("));
        assert!(!pre_spawn.contains("Am3BbStratumTaskGuard::pending("));
        assert!(!pre_spawn.contains("stratum_tasks.spawn_"));
        assert!(!pre_spawn.contains("rt_handle.spawn("));
        assert!(started.contains(") -> Am3BbMiningLoopExit"));
        assert!(started.contains("Am3BbStratumTaskGuard::pending("));
        assert!(started.contains("stratum_tasks.spawn_router("));
        assert!(started.contains("let mining_result = (|| -> Result<()>"));
        assert!(started.contains("Am3BbMiningLoopExit {"));
        assert!(!started.contains("Am3BbMiningLoopNotStarted"));
    }

    #[test]
    fn started_and_pre_stratum_errors_share_typed_terminal_closeout() {
        let source = include_str!("am3_bb_mining.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production AM3 source");
        let blocking = production
            .split_once("fn run_am3_bb_blocking(")
            .expect("AM3 blocking engine")
            .1;
        let (mining_dispatch, closeout) = blocking
            .split_once("// Every mining-loop exit after asynchronous ownership transfers")
            .expect("AM3 terminal closeout funnel");

        assert!(mining_dispatch
            .contains("Ok(exit) => (exit.mining_result, Some(exit.stratum_tasks), Ok(()))"));
        assert!(mining_dispatch
            .contains("am3-bb: mining loop admission failed before any Stratum task was spawned"));
        assert!(mining_dispatch.contains("None,\n                Ok(()),"));

        let disarm = closeout
            .find("watchdog.disarm_and_join(permit, DEFAULT_WATCHDOG_STOP_TIMEOUT)")
            .expect("AM3 watchdog closeout");
        let typed_closeout = closeout
            .find("let terminal_closeout = Am3BbTerminalSafeOffCloseout")
            .expect("typed terminal-safe-off closeout");
        let error_disposition = closeout
            .find("Am3BbLifecycleError::terminal_safe_off_closed(")
            .expect("terminal-safe-off lifecycle disposition");
        assert!(disarm < typed_closeout && typed_closeout < error_disposition);
        assert!(closeout.contains("if let Err(mining_error) = mining_result {"));
        assert!(closeout.contains("terminal_closeout,"));
        assert!(!closeout.contains("mining_result?;"));
    }

    #[test]
    fn post_energization_cancellation_never_reports_clean_shutdown() {
        let source = include_str!("am3_bb_mining.rs");
        let boundary = source.find("drop(energizing_boundary);").unwrap();
        let closeout = source[boundary..]
            .find("let revoked_api_commit_fence")
            .map(|offset| boundary + offset)
            .unwrap();
        let bringup = &source[boundary..closeout];

        assert!(bringup.contains(
            "shutdown requested after cold-boot; safety guard will attempt cutoff during unwind; safe-off remains unproven and watchdog reset is pending"
        ));
        assert!(bringup.contains(
            "shutdown requested after dsPIC init; safety guard will attempt cutoff during unwind; safe-off remains unproven and watchdog reset is pending"
        ));
        assert!(!bringup.contains("return Ok(());"));
    }

    #[test]
    fn terminal_state_drop_never_claims_stopped_without_safeoff_receipt() {
        let mut initial = dcentrald_api::MinerState::empty(dcentrald_api::OperatingMode::Standard);
        initial.pool.status = "mining".to_string();
        let (state_tx, state_rx) = watch::channel(initial);
        {
            let terminal = Am3BbTerminalStatePublisher::new(state_tx);
            terminal.begin_stopping();
            assert_eq!(state_rx.borrow().pool.status, "stopping");
        }
        assert_eq!(state_rx.borrow().pool.status, "faulted_safe_off_unproven");
    }

    #[test]
    fn heartbeat_owner_has_no_unbounded_join_path() {
        let source = include_str!("am3_bb_mining.rs");
        let production = source
            .split("//  Tests (host-safe")
            .next()
            .expect("AM3 production source");
        let forbidden_join = [".", "join", "()"].concat();
        assert!(!production.contains(&forbidden_join));
        assert!(production.contains("stop_and_join_until(&rt_handle, heartbeat_stop_deadline)"));
        assert!(production.contains("dspic-heartbeat-stop-failure"));
        assert!(production.contains("dspic-heartbeat-owner-drop-without-quiescence"));
        assert!(production.contains("catch_unwind(AssertUnwindSafe"));
        assert!(production.contains("Am3BbHeartbeatEvent::WorkerPanicked"));
    }

    #[test]
    fn heartbeat_roster_is_watchdog_issued_reserved_before_spawn_and_manifest_typed() {
        let source = include_str!("am3_bb_mining.rs");
        let production = source
            .split("//  Tests (host-safe")
            .next()
            .expect("AM3 production source");
        let heartbeat_start = production
            .split_once("fn start_am3_bb_dspic_heartbeat(")
            .expect("AM3 heartbeat owner")
            .1
            .split_once("fn am3_bb_require_heartbeat_for_energizing_boundary(")
            .expect("AM3 heartbeat owner boundary")
            .0;
        let reserve = heartbeat_start
            .find("threads.reserve(Am3BbThreadSlot::DspicHeartbeat)")
            .expect("typed dsPIC slot reservation");
        let spawn = heartbeat_start
            .find(".spawn(move ||")
            .expect("dsPIC heartbeat spawn");
        let attach = heartbeat_start
            .find("actor_slot.attach(handle)")
            .expect("typed dsPIC slot attachment");
        assert!(reserve < spawn && spawn < attach);
        assert!(heartbeat_start.contains("actor_owner.activate(worker_stop)"));
        assert!(!heartbeat_start.contains("RuntimeThreadGuard::new"));

        let closeout = production
            .split_once("// Every mining-loop exit after asynchronous ownership transfers")
            .expect("AM3 closeout")
            .1
            .split_once("if let Err(mining_error) = mining_result {")
            .expect("AM3 closeout boundary")
            .0;
        assert!(closeout.contains(".into_actor_receipt()"));
        assert!(!closeout.contains("heartbeat_shutdown.summary"));

        let watchdog = include_str!("runtime/safety_watchdog.rs");
        let manifest = watchdog
            .split_once("pub(crate) struct Am3BbWatchdogShutdownManifest")
            .expect("AM3 manifest")
            .1
            .split_once("/// Move-only standard-daemon authority")
            .expect("AM3 manifest boundary")
            .0;
        assert!(manifest.contains("actors: ThreadRosterQuiescenceReceipt<Am3BbThreadSlot>"));
        assert!(!manifest.contains("actors: ThreadStopSummary"));
    }

    #[test]
    fn watchdog_closeout_orders_barriers_quiescence_and_safeoff_before_disarm() {
        let source = include_str!("am3_bb_mining.rs");
        let start = source
            .find("// Every mining-loop exit after asynchronous ownership transfers")
            .unwrap();
        let end = source[start..]
            .find("if let Err(mining_error) = mining_result {")
            .map(|offset| start + offset)
            .unwrap();
        let closeout = &source[start..end];

        let teardown_request = closeout
            .find("watchdog\n        .request_teardown_budget(")
            .unwrap();
        let api_commit_revocation = closeout
            .find("hardware_mutation_owner.revoke_commit_fence()")
            .unwrap();
        let heartbeat_feeder_stop = closeout
            .find("heartbeat_feeder_owner.request_stop()")
            .unwrap();
        let hard_cutoff = closeout
            .find("cut_board_enable_checked(teardown_view.clone())")
            .unwrap();
        let stratum_publisher_close = closeout.find("tasks.request_stop()").unwrap();
        let terminal_stopping = closeout.find("terminal_state.begin_stopping()").unwrap();
        let stratum_join = closeout
            .find("tasks.stop_and_join(stratum_join_deadline)")
            .unwrap();
        let teardown_acknowledgement = closeout
            .find("watchdog.observe_teardown_admission(")
            .unwrap();
        let api_barrier = closeout.find("close_and_drain_until(").unwrap();
        let api_commit_fence = closeout
            .find("revoked_api_commit_fence.try_wait()")
            .unwrap();
        let i2c_latch = closeout.find("latch_terminal_safe_off()").unwrap();
        let actor_join = closeout
            .find("stop_and_join_until(&rt_handle, heartbeat_stop_deadline)")
            .unwrap();
        let safeoff = closeout
            .find("teardown_checked(board_cutoff_result.ok(), teardown_view.clone())")
            .unwrap();
        let terminal_safeoff = closeout
            .find("terminal_state.record_safe_off(mining_result.is_err())")
            .unwrap();
        let negative_evidence_gate = closeout
            .find("let api_barrier = api_barrier_result?;")
            .unwrap();
        let stratum_evidence_gate = closeout.find("stratum_tasks_result?;").unwrap();
        let disarm_authority = closeout
            .find("teardown_budget.begin_disarm_at(Instant::now())")
            .unwrap();
        let manifest = closeout
            .find("Am3BbWatchdogShutdownManifest::new(")
            .unwrap();
        let permit = closeout
            .find("WatchdogDisarmPermit::from_am3_bb_manifest")
            .unwrap();
        let disarm = closeout.find("watchdog.disarm_and_join(").unwrap();
        let terminal_closeout = closeout
            .find("let terminal_closeout = Am3BbTerminalSafeOffCloseout")
            .unwrap();

        assert!(
            api_commit_revocation < teardown_request
                && teardown_request < heartbeat_feeder_stop
                && heartbeat_feeder_stop < hard_cutoff
                && hard_cutoff < stratum_publisher_close
                && stratum_publisher_close < terminal_stopping
                && terminal_stopping < teardown_acknowledgement
                && teardown_acknowledgement < api_barrier
                && api_barrier < api_commit_fence
                && api_commit_fence < i2c_latch
                && i2c_latch < actor_join
                && actor_join < safeoff
                && safeoff < terminal_safeoff
                && terminal_safeoff < stratum_join
                && terminal_safeoff < negative_evidence_gate
                && stratum_join < negative_evidence_gate
                && negative_evidence_gate < stratum_evidence_gate
                && stratum_evidence_gate < disarm_authority
                && disarm_authority < manifest
                && manifest < permit
                && permit < disarm
                && disarm < terminal_closeout
        );
    }

    #[test]
    fn psu65_cutoff_receipt_precedes_dspic_and_reset_defense_in_depth() {
        let source = include_str!("am3_bb_mining.rs");
        let closeout_start = source
            .find("// PSU GPIO65 is the load-bearing physical cut")
            .unwrap();
        let closeout_end = source[closeout_start..]
            .find("if let Err(mining_error) = mining_result {")
            .map(|offset| closeout_start + offset)
            .unwrap();
        let closeout = &source[closeout_start..closeout_end];
        assert!(
            closeout
                .find("cut_board_enable_checked(teardown_view.clone())")
                .unwrap()
                < closeout.find("latch_terminal_safe_off()").unwrap()
        );
        assert!(
            closeout
                .find("cut_board_enable_checked(teardown_view.clone())")
                .unwrap()
                < closeout
                    .find("stop_and_join_until(&rt_handle, heartbeat_stop_deadline)")
                    .unwrap()
        );
        assert!(
            closeout
                .find("cut_board_enable_checked(teardown_view.clone())")
                .unwrap()
                < closeout
                    .find("teardown_checked(board_cutoff_result.ok(), teardown_view.clone())")
                    .unwrap()
        );

        let guard_start = source
            .find("    fn run_defense_in_depth(&mut self)")
            .expect("AM3 shared defense-in-depth method");
        let guard_end = source[guard_start..]
            .find("    fn teardown_checked(\n")
            .map(|offset| guard_start + offset)
            .expect("AM3 checked teardown boundary");
        let guard = &source[guard_start..guard_end];
        assert!(guard.contains("am3_bb_disable_dspics_two_phase("));
        assert!(guard.contains("am3_bb_prepare_output_gpio(gpio, true)"));
        assert!(!guard.contains("am3_bb_prepare_output_gpio(self.board_enable_gpio"));

        let drop_start = source
            .find("impl Drop for Am3BbRunSafetyGuard")
            .expect("AM3 fail-closed Drop");
        let drop_end = source[drop_start..]
            .find("fn am3_bb_post_dspic_reset_chains")
            .map(|offset| drop_start + offset)
            .expect("AM3 Drop boundary");
        let drop_guard = &source[drop_start..drop_end];
        assert!(drop_guard.contains("cut_board_enable_fallback()"));
        assert!(drop_guard.contains("run_defense_in_depth()"));
        assert!(!drop_guard.contains("teardown_checked("));
        assert!(!drop_guard.contains("TeardownBudget"));

        let teardown_start = source
            .find("    fn teardown_checked(\n")
            .expect("AM3 checked teardown");
        let teardown_end = source[teardown_start..]
            .find("impl Drop for Am3BbRunSafetyGuard")
            .map(|offset| teardown_start + offset)
            .expect("AM3 checked teardown boundary");
        let teardown = &source[teardown_start..teardown_end];
        let retry = teardown
            .find("self.cut_board_enable_checked(teardown_budget.clone())")
            .expect("checked PSU65 cutoff retry");
        let defense = teardown
            .find("self.run_defense_in_depth()")
            .expect("defense-in-depth attempt");
        let fallback = teardown
            .find("self.cut_board_enable_fallback()")
            .expect("non-authorizing physical cutoff retry");
        let completed = teardown
            .find("self.teardown_done = true;")
            .expect("successful safe-off completion marker");
        assert!(retry < defense && defense < fallback && fallback < completed);
        assert_eq!(teardown.matches("self.teardown_done = true;").count(), 1);
    }

    #[test]
    fn retained_psu65_authority_is_preopened_once_and_panic_cut_runs_first() {
        let source = include_str!("am3_bb_mining.rs");
        let production = source
            .split("//  Tests (host-safe")
            .next()
            .expect("AM3 production source");

        let guard_new = production
            .split_once("    fn new(\n        platform: &BeagleBonePlatform,")
            .expect("AM3 run guard constructor")
            .1
            .split_once("    fn set_dspic(")
            .expect("AM3 run guard constructor boundary")
            .0;
        assert!(
            guard_new.find("am3_bb_prepare_board_cutoff_set(").unwrap()
                < guard_new.find(".open_fan()").unwrap()
        );

        let blocking = production
            .split_once("fn run_am3_bb_blocking(")
            .expect("AM3 blocking engine")
            .1
            .split_once("fn bm1362_command_wire_frame(")
            .expect("AM3 blocking engine boundary")
            .0;
        let guard_arm = blocking.find("Am3BbRunSafetyGuard::new(").unwrap();
        let panic_arm = blocking.find("arm_am3_bb_teardown(").unwrap();
        let cold_boot = blocking.find(".run_cold_boot(").unwrap();
        assert!(guard_arm < panic_arm && panic_arm < cold_boot);
        assert!(blocking.contains(".take_heartbeat_board_cutoff()?"));
        assert!(blocking.contains("let mut runtime_cutoff = run_guard.runtime_cutoff();"));

        let panic_hook = production
            .split_once("pub fn am3_bb_panic_hook_best_effort_teardown()")
            .expect("AM3 panic hook")
            .1
            .split_once("#[derive(Debug, Default")
            .expect("AM3 panic hook boundary")
            .0;
        assert!(
            panic_hook
                .find("watchdog_feed_stop.close_terminal_lock_free()")
                .unwrap()
                < panic_hook.find("cut_raw_noalloc()").unwrap()
        );
        assert!(
            panic_hook.find("cut_raw_noalloc()").unwrap()
                < panic_hook.find("for &gpio in &params.reset_gpios").unwrap()
        );

        let prepared_impl =
            "impl dcentrald_hal::platform::beaglebone_cold_boot::PreparedBoardEnable for";
        assert_eq!(production.matches(prepared_impl).count(), 1);
        assert!(production.contains(&format!("{prepared_impl} Am3BbBoardEnableOwner")));

        let cold_boot_source =
            include_str!("../../dcentrald-hal/src/platform/beaglebone_cold_boot.rs");
        let v2_cold_boot = cold_boot_source
            .split_once("pub fn cold_boot_sequence_s19j_io_v2")
            .expect("AM3 V2 cold boot")
            .1
            .split_once("//  Tests")
            .expect("AM3 V2 cold-boot boundary")
            .0;
        assert!(v2_cold_boot.contains("initialize_exact_apw_supply(psu, board_enable"));
        let supply_init = cold_boot_source
            .split_once("fn initialize_exact_apw_supply")
            .unwrap()
            .1
            .split_once("/// Run the")
            .unwrap()
            .0;
        assert!(supply_init.contains("owner.assert_checked()?"));
        assert!(!v2_cold_boot.contains("export_sysfs_gpio(opts.board_enable_gpio)"));
        assert!(!v2_cold_boot.contains("write_sysfs_gpio_value(opts.board_enable_gpio"));
    }

    #[test]
    fn watchdog_progress_requires_fresh_thermal_and_checked_fan_work() {
        let source = include_str!("am3_bb_mining.rs");
        let loop_start = source.find("fn run_mining_loop<U: ChainUart>(").unwrap();
        let stub_start = source
            .find("fn run_mining_loop_stub<U: ChainUart>(")
            .unwrap();
        let mining_loop = &source[loop_start..stub_start];
        let thermal = mining_loop.find("poll_and_check(\"runtime\")").unwrap();
        let fresh = mining_loop.find("if snapshot.fresh").unwrap();
        let fan = mining_loop.find("fan_pid.step(").unwrap();
        let progress = mining_loop
            .find("watchdog_liveness.mark_progress()")
            .unwrap();
        assert!(thermal < fresh && fresh < fan && fan < progress);

        let stub_end = source[stub_start..]
            .find("//  Tests (host-safe")
            .map(|offset| stub_start + offset)
            .unwrap();
        let stub = &source[stub_start..stub_end];
        assert!(!stub.contains("watchdog_liveness.mark_progress()"));
        assert!(!stub.contains("watchdog.enter_mining()"));
    }

    #[test]
    fn chain_uart_specs_match_board_target() {
        let p = test_platform();
        let specs = chain_uart_specs(&p);
        // `a lab unit` S19J_IO_BOARD_V2_0 has 3 chains on ttyS1/ttyS2/ttyS4.
        assert_eq!(specs.len(), 3, "three chains on the .79 IO board");
        for (i, s) in specs.iter().enumerate() {
            assert_eq!(s.index as usize, i, "chain index matches position");
            assert!(
                s.device.starts_with("/dev/ttyS"),
                "chain {} device looks like a tty: {}",
                i,
                s.device
            );
        }
        // The default chain ttys are ttyS1, ttyS2, ttyS4 (NOT ttyS3).
        let devs: Vec<&str> = specs.iter().map(|s| s.device.as_str()).collect();
        assert_eq!(devs, vec!["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS4"]);
    }

    #[test]
    fn cold_boot_opts_pulled_from_board_target() {
        let p = test_platform();
        let opts = ColdBootOptsV2::from_board_target(p.board_target());
        // `from_board_target` builds `apw_drop_to_steady = false` — the
        // daemon flips it on the second call (step 7). If this default
        // changes, step 7's logic needs revisiting.
        assert!(
            !opts.apw_drop_to_steady,
            "ColdBootOptsV2::from_board_target must default apw_drop_to_steady=false"
        );
        // The open-core rail must be at or above the steady rail.
        assert!(
            opts.apw12_rail_open_core_mv >= opts.apw12_rail_steady_mv,
            "open-core rail ({} mV) must be >= steady rail ({} mV)",
            opts.apw12_rail_open_core_mv,
            opts.apw12_rail_steady_mv
        );
        // The steady rail is the home-mining target (~13.8 V); sanity-bound it.
        assert!(
            opts.apw12_rail_steady_mv >= 12_000 && opts.apw12_rail_steady_mv <= 15_500,
            "steady rail {} mV is in a plausible chain-voltage band",
            opts.apw12_rail_steady_mv
        );
    }

    #[test]
    fn quiet_safe_pwm_never_exceeds_home_cap() {
        assert_eq!(am3_bb_quiet_safe_pwm(10, 30), 10);
        assert_eq!(am3_bb_quiet_safe_pwm(20, 30), 20);
        assert_eq!(
            am3_bb_quiet_safe_pwm(80, 100),
            AM3_BB_FAN_HARD_CAP_PWM,
            "operator config cannot make the AM3 BB guard blast fans"
        );
        assert_eq!(
            am3_bb_quiet_safe_pwm(10, 5),
            5,
            "an intentionally lower cap is respected; safety comes from cutting ASIC power"
        );
    }

    #[test]
    fn board_target_psu_topology_is_the_79_layout() {
        let p = test_platform();
        // .79: APW121215f on the bit-banged i2c-gpio bus (bus 1) @ 0x10.
        assert_eq!(p.psu_i2c_bus(), 1, "PSU on the bit-banged i2c-gpio bus");
        assert_eq!(p.psu_i2c_addr(), 0x10, "APW12 PSU at I2C 0x10");
        // Hashboard EEPROMs on bus 0.
        assert_eq!(p.eeprom_i2c_bus(), 0, "hashboard EEPROMs on bus 0");
        // gpio59 board-enable (IO-board-specific, not the W4 BBCtrl map).
        assert_eq!(p.board_enable_gpio_v2_0(), 59, "BOARD_ENABLE = gpio59");
        assert_eq!(dcentrald_hal::platform::beaglebone_psu::PSU_ENABLE_GPIO, 65);
        assert_ne!(
            p.board_enable_gpio_v2_0(),
            dcentrald_hal::platform::beaglebone_psu::PSU_ENABLE_GPIO
        );
        // The APW UART-tunnel PSU is upstream, but the hashboards still use
        // fw=0x89 dsPIC controllers on I2C bus 0.
        assert_eq!(
            p.voltage_controller(),
            dcentrald_hal::platform::VoltageControllerKind::Dspic33Ep,
            "S19J_IO_BOARD_V2_0 uses hashboard dsPIC controllers"
        );
    }

    #[test]
    fn mining_baud_matches_am335x_fast_uart_handoff() {
        let p = test_platform();
        // LuxOS reports "3 Mbaud"; AM335x OMAP UART base_baud is 3 MHz, so
        // divisor 1 is exact. 937500 rounded to actual 1 Mbaud and produced
        // silent zero-nonce runs after the BM1362 FastUART handoff.
        assert_eq!(p.mining_baud_v2_0(), 3_000_000);
    }

    #[test]
    fn bm1362_chip_init_commands_are_preamble_framed() {
        let get = bm1362_command_wire_frame(&build_get_address_frame());
        assert_eq!(&get[..2], &[0x55, 0xAA], "GetAddress command preamble");
        assert_eq!(&get[2..6], &[0x52, 0x05, 0x00, 0x00]);
        assert_eq!(get.len(), 7, "GetAddress is preamble + 5-byte command");

        let bcast = bm1362_command_wire_frame(&build_broadcast_write_frame(0x3C, 0x8000_8540));
        assert_eq!(&bcast[..4], &[0x55, 0xAA, 0x51, 0x09]);
        assert_eq!(bcast[5], 0x3C);
        assert_eq!(
            bcast.len(),
            11,
            "broadcast write is preamble + 9-byte command"
        );

        let single = bm1362_command_wire_frame(&build_single_write_frame(0x7E, 0xA8, 0x0200_0000));
        assert_eq!(&single[..4], &[0x55, 0xAA, 0x41, 0x09]);
        assert_eq!(single[4], 0x7E);
        assert_eq!(single[5], 0xA8);
        assert_eq!(
            single.len(),
            11,
            "single write is preamble + 9-byte command"
        );
    }

    #[test]
    fn luxos_trace_dspic_frames_are_pinned() {
        // Captured from `a lab unit` LuxOS ftrace on 2026-05-13. These are full
        // write frames followed by one-byte reads, not I2C_RDWR combined
        // transactions.
        assert_eq!(
            AM3_BB_DSPIC_RESET_FRAME,
            &[0x55, 0xAA, 0x04, 0x07, 0x00, 0x0B]
        );
        // Historical LuxOS bytes stay pinned. Production init must never send them.
        let src = include_str!("am3_bb_mining.rs");
        let start = src
            .find("fn am3_bb_dspic_init_one")
            .expect("am3_bb_dspic_init_one");
        let body = &src[start..src.find("fn am3_bb_dspic_init_all").unwrap()];
        assert!(
            !body.contains("AM3_BB_DSPIC_RESET_FRAME"),
            "S19j Pro / AM3-BB init must not send PIC RESET 0x07"
        );
        assert!(!body.contains("AM3_BB_DSPIC_JUMP_FRAME"));
        assert!(!body.contains("I2cMutationLabel::Recovery"));
        let application = body.find("am3_bb_dspic_read_application").unwrap();
        assert!(application < body.find("disable_dspic_voltage").unwrap());
        assert_eq!(
            AM3_BB_DSPIC_JUMP_FRAME,
            &[0x55, 0xAA, 0x04, 0x06, 0x00, 0x0A]
        );
        assert_eq!(
            AM3_BB_DSPIC_GET_VERSION_FRAME,
            &[0x55, 0xAA, 0x04, 0x17, 0x00, 0x1B]
        );
        assert_eq!(
            AM3_BB_DSPIC_DISABLE_FRAME,
            &[0x55, 0xAA, 0x05, 0x15, 0x00, 0x00, 0x1A]
        );
        assert_eq!(
            am3_bb_dspic_set_voltage_frame(13_700),
            [0x55, 0xAA, 0x04, 0x10, 0x06, 0x1A]
        );
        assert_eq!(
            am3_bb_dspic_set_voltage_frame(13_800),
            [0x55, 0xAA, 0x04, 0x10, 0x06, 0x1A]
        );
        assert_eq!(
            AM3_BB_DSPIC_ENABLE_FRAME,
            &[0x55, 0xAA, 0x05, 0x15, 0x01, 0x00, 0x1B]
        );
        assert_eq!(
            AM3_BB_DSPIC_HEARTBEAT_FRAME,
            &[0x55, 0xAA, 0x04, 0x16, 0x00, 0x1A]
        );
        assert_eq!(
            AM3_BB_DSPIC_PROBE_3B_48_FRAME,
            &[0x55, 0xAA, 0x06, 0x3B, 0x48, 0x00, 0x00, 0x89]
        );
        assert_eq!(
            AM3_BB_DSPIC_READ_VOLTAGE_FRAME,
            &[0x55, 0xAA, 0x04, 0x3A, 0x00, 0x3E]
        );
        assert_eq!(
            am3_bb_dspic_temp_bridge_frame(0x48),
            [0x55, 0xAA, 0x06, 0x3C, 0x48, 0x02, 0x00, 0x8C]
        );
        assert_eq!(
            am3_bb_dspic_temp_bridge_frame(0x4B),
            [0x55, 0xAA, 0x06, 0x3C, 0x4B, 0x02, 0x00, 0x8F]
        );
        assert_eq!(
            am3_bb_decode_lm75_bridge_reply(&[0x07, 0x3C, 0x01, 0x1D, 0x20, 0x00, 0x81]),
            Some(29.125)
        );
        assert_eq!(
            am3_bb_decode_lm75_bridge_reply(&[0x07, 0x3C, 0x01, 0x1D, 0x20, 0x00, 0x80]),
            None,
            "LM75 bridge checksum must be enforced before mining"
        );
        assert_eq!(am3_bb_dspic_voltage_dac(AM3_BB_DSPIC_MIN_VOLTAGE_MV), 0x00);
        assert_eq!(am3_bb_dspic_voltage_dac(AM3_BB_DSPIC_MAX_VOLTAGE_MV), 0x0B);
        assert_eq!(
            am3_bb_dspic_target_voltage_mv(9_100),
            AM3_BB_DSPIC_DEFAULT_TARGET_MV
        );
        assert_eq!(am3_bb_dspic_addr_for_chain(0), 0x20);
        assert_eq!(am3_bb_dspic_addr_for_chain(1), 0x21);
        assert_eq!(am3_bb_dspic_addr_for_chain(2), 0x22);
    }

    /// UB-20. Every frame below is verbatim from
    /// *.log` on `a lab unit`.
    #[test]
    fn lm75_bridge_decoder_rejects_malformed_replies_structurally() {
        // --- Well-formed replies still decode, and to the right value. ---
        // `a lab unit` 2026-05-14T00:06:09 chain0 sensor 0x48, logged as 38.1875 C.
        assert_eq!(
            am3_bb_decode_lm75_bridge_reply(&[0x07, 0x3C, 0x01, 0x26, 0x30, 0x00, 0x9A]),
            Some(38.1875)
        );
        // `a lab unit` 2026-05-14T00:05:36 chain0 sensor 0x4B, logged as 41.25 C.
        assert_eq!(
            am3_bb_decode_lm75_bridge_reply(&[0x07, 0x3C, 0x01, 0x29, 0x40, 0x00, 0xAD]),
            Some(41.25)
        );

        // --- Reject 1: status byte reply[5] != 0. ---
        // `a lab unit` 2026-05-14T00:06:13 chain2 sensor 0x48 — logged "invalid".
        // Its checksum over the device's true reply[0..=4] span is VALID
        // (0x07+0x3C+0x01+0x25+0xB0 = 0x19), so only the status byte
        // distinguishes it from a good read. This is the frame class that the
        // old accidental checksum span happened to catch; pin it explicitly.
        let status_bad = [0x07u8, 0x3C, 0x01, 0x25, 0xB0, 0x01, 0x19];
        assert_eq!(
            status_bad[..5].iter().fold(0u8, |a, b| a.wrapping_add(*b)),
            status_bad[6],
            "fixture precondition: the device checksum (reply[0..=4]) must PASS, \
             so this frame can only be rejected by the status byte"
        );
        assert_eq!(
            am3_bb_decode_lm75_bridge_reply(&status_bad),
            None,
            "non-zero bridge status byte must reject (ePIC's reply[2] is our reply[5]); \
             a status flag is not a temperature"
        );
        // Same payload with the status byte cleared is a good 37.6875 C read —
        // proves the status byte alone is what rejects, not the payload.
        assert_eq!(
            am3_bb_decode_lm75_bridge_reply(&[0x07, 0x3C, 0x01, 0x25, 0xB0, 0x00, 0x19]),
            Some(37.6875)
        );

        // --- Reject 2: raw & 0x0F != 0. ---
        // `a lab unit` guard-failclosed 2026-05-13T22:47 — status byte is GOOD (0x00),
        // so only the low-nibble rule stands between this frame and a
        // plausible-looking, dangerously COOL 6.00 C reading.
        let low_nibble_set = [0x07u8, 0x3C, 0x01, 0x06, 0x01, 0x00, 0x1D];
        assert_eq!(low_nibble_set[5], AM3_BB_LM75_STATUS_OK);
        assert_eq!(
            am3_bb_decode_lm75_bridge_reply(&low_nibble_set),
            None,
            "raw & 0x0F != 0 must reject as a framing/bus error, never as a cold sensor"
        );
        // Synthetic: a frame whose checksum is valid on BOTH spans and whose
        // status is good, but whose low nibble is set. The additive checksum
        // provably cannot catch this class; the nibble rule must.
        let mut compensating = [0x07u8, 0x3C, 0x01, 0x26, 0x31, 0x00, 0x00];
        compensating[6] = compensating[..6]
            .iter()
            .fold(0u8, |a, b| a.wrapping_add(*b));
        assert_eq!(
            am3_bb_decode_lm75_bridge_reply(&compensating),
            None,
            "a checksum-valid, status-OK frame with a non-zero low nibble must still reject"
        );

        // --- Header and checksum rejects remain in force. ---
        // `a lab unit` guard-failclosed: fully desynchronised frame.
        assert_eq!(
            am3_bb_decode_lm75_bridge_reply(&[0x3C, 0x1C, 0xF0, 0x50, 0xFF, 0xFF, 0xFF]),
            None
        );
        assert_eq!(
            am3_bb_decode_lm75_bridge_reply(&[0x07, 0x3C, 0x01, 0x1D, 0x20, 0x00, 0x80]),
            None,
            "LM75 bridge checksum must be enforced before mining"
        );
        assert_eq!(
            am3_bb_decode_lm75_bridge_reply(&[0x07, 0x3C, 0x01, 0x1D, 0x20, 0x00]),
            None,
            "a short reply is not a temperature"
        );

        // --- Conversion parity with ePIC's (raw >> 4) * 62.5 m°C. ---
        // Exact for every accepted raw value, including negatives.
        for raw in (-8_000i16..=32_752).step_by(16) {
            let hi = (raw >> 8) as u8;
            let lo = (raw & 0xFF) as u8;
            let mut frame = [0x07u8, 0x3C, 0x01, hi, lo, 0x00, 0x00];
            frame[6] = frame[..6].iter().fold(0u8, |a, b| a.wrapping_add(*b));
            let epic_c = f32::from(raw >> 4) * 62.5 / 1000.0;
            let decoded = am3_bb_decode_lm75_bridge_reply(&frame);
            if (AM3_BB_LM75_MIN_VALID_C..=AM3_BB_LM75_MAX_VALID_C).contains(&epic_c) {
                assert_eq!(
                    decoded,
                    Some(epic_c),
                    "raw {:#06X}: our /256.0 must equal ePIC's (raw>>4)*62.5 m°C",
                    raw
                );
            } else {
                assert_eq!(decoded, None, "raw {:#06X} is out of the valid band", raw);
            }
        }
    }

    /// UB-20 fail-safe direction: a rejected read must never surface as a
    /// plausible temperature, and must never read as "cool" to fan policy.
    #[test]
    fn rejected_lm75_read_never_surfaces_as_a_plausible_temperature() {
        // Every frame the decoder rejects yields None — not 0.0, not a default.
        for bad in [
            [0x07u8, 0x3C, 0x01, 0x25, 0xB0, 0x01, 0x19], // status byte set
            [0x07, 0x3C, 0x01, 0x06, 0x01, 0x00, 0x1D],   // low nibble set -> "6.0 C"
            [0x3C, 0x1C, 0xF0, 0x50, 0xFF, 0xFF, 0xFF],   // desynchronised
        ] {
            assert_eq!(am3_bb_decode_lm75_bridge_reply(&bad), None);
        }

        // A poll in which every reply was rejected produces zero samples. The
        // snapshot must be un-fresh and must NOT carry a finite temperature
        // that downstream fan policy could mistake for a cool board.
        let all_rejected =
            am3_bb_thermal_snapshot_from_chain_samples(&[0, 0, 0], f32::NEG_INFINITY);
        assert_eq!(all_rejected.samples, 0);
        assert_eq!(all_rejected.covered_chains, 0);
        assert!(
            !all_rejected.fresh,
            "zero decoded samples must never be reported as fresh thermal proof"
        );
        assert!(
            !all_rejected.max_temp_c.is_finite(),
            "an empty poll must not synthesise a finite temperature"
        );
        assert_ne!(
            all_rejected.max_temp_c, 0.0,
            "a rejected read must never be laundered into 0 C"
        );

        // A partially rejected poll (one chain fully silent) is also un-fresh,
        // so a healthy peer can never mask a blind chain.
        let partial = am3_bb_thermal_snapshot_from_chain_samples(&[4, 0, 4], 45.0);
        assert!(!partial.fresh);

        // ...and the fan PID refuses to act on either, holding station rather
        // than treating absent data as permission to relax.
        assert_eq!(
            am3_bb_thermal_action(all_rejected.max_temp_c, 75.0),
            Am3BbThermalAction::PidWithinCap,
            "-inf must not read as dangerous..."
        );
        assert_eq!(
            am3_bb_thermal_action(80.0, 75.0),
            Am3BbThermalAction::CutHashThenFan,
            "...while a real over-temperature still cuts hash power first"
        );
    }

    #[test]
    fn auto_detect_is_false_on_a_dev_host() {
        // On the dev host there is no /etc/dcentos/board_target and no
        // /proc/device-tree/model with S19J_IO_BOARD — must not false-positive.
        assert!(
            !auto_detect_am3_bb(),
            "auto_detect_am3_bb must be false on a non-am3-bb host"
        );
    }

    #[test]
    fn am3_bb_geometry_is_explicit_or_catalog_backed() {
        assert_eq!(
            resolve_am3_bb_chips_per_chain(None, None, None).unwrap(),
            126
        );
        assert_eq!(
            resolve_am3_bb_chips_per_chain(Some("s19jpro"), Some("bm1362"), None).unwrap(),
            126
        );
        assert_eq!(
            resolve_am3_bb_chips_per_chain(Some("s19jpro"), Some("BM1362"), Some(120)).unwrap(),
            120,
            "an explicit nonzero geometry override remains available for repair/bring-up"
        );
    }

    #[test]
    fn am3_bb_geometry_rejects_conflicting_or_missing_evidence() {
        assert!(
            resolve_am3_bb_chips_per_chain(Some("s19xp"), Some("BM1362"), None)
                .unwrap_err()
                .to_string()
                .contains("conflicts")
        );
        assert!(
            resolve_am3_bb_chips_per_chain(Some("s19jpro"), Some("BM1398"), None)
                .unwrap_err()
                .to_string()
                .contains("serial_chip_type")
        );
        assert!(resolve_am3_bb_chips_per_chain(Some("not-a-model"), None, None).is_err());
        assert!(resolve_am3_bb_chips_per_chain(None, None, Some(0)).is_err());
        assert!(
            resolve_am3_bb_chips_per_chain(Some("s19jproam2"), None, None).is_err(),
            "a BM1362 model on a different control-board family must not authorize AM3-BB"
        );
    }

    #[test]
    fn devmem_chain_uart_is_a_thin_newtype() {
        // We can't construct a real DevmemUart on the host (it mmaps
        // /dev/mem), so this just pins the adapter shape: `DevmemChainUart`
        // is a 1-tuple newtype over `DevmemUart`, and it implements
        // `ChainUart`. If someone refactors it into something heavier this
        // forces a conscious decision.
        fn _assert_impls_chain_uart<T: ChainUart>() {}
        _assert_impls_chain_uart::<DevmemChainUart>();
        // size_of equality is the cheapest "it's still a newtype" check.
        assert_eq!(
            std::mem::size_of::<DevmemChainUart>(),
            std::mem::size_of::<DevmemUart>(),
            "DevmemChainUart must stay a zero-overhead newtype over DevmemUart"
        );
    }

    #[test]
    fn chain_uart_spec_is_value_equal() {
        let a = ChainUartSpec {
            index: 0,
            device: "/dev/ttyS1".to_string(),
        };
        let b = ChainUartSpec {
            index: 0,
            device: "/dev/ttyS1".to_string(),
        };
        assert_eq!(a, b);
        let c = ChainUartSpec {
            index: 1,
            device: "/dev/ttyS1".to_string(),
        };
        assert_ne!(a, c);
    }

    // -----------------------------------------------------------------
    // Mining-loop pure helpers (Option B2)
    // -----------------------------------------------------------------

    #[test]
    fn job_id_correlation_constants_and_roundtrip() {
        // work_by_id is indexed by the chip's echoed job-id (0..120 in steps of
        // 8); we size it 256 so the index is always in range.
        assert_eq!(ASIC_JOB_ID_SPAN, 256);
        assert_eq!(ASIC_JOB_ID_SPAN, u8::MAX as usize + 1);
        // The dispatcher step must be a multiple of 8 (only bits [6:3] of the
        // sent job-id round-trip through the chip's (sent<<1)&0xF0 echo).
        assert_eq!(
            JOB_ID_INCREMENT % 8,
            0,
            "JOB_ID_INCREMENT must be a multiple of 8"
        );
        assert_eq!(
            JOB_ID_INCREMENT, 24,
            "matches the proven BM1368/BM1370-family path"
        );
        assert_eq!(ASIC_JOB_ID_MASK, 0x7F, "serial job ids stay in 0..=127");
        assert_eq!(next_bm1362_serial_job_id(0), 24);
        assert_eq!(next_bm1362_serial_job_id(96), 120);
        assert_eq!(
            next_bm1362_serial_job_id(120),
            16,
            "wrap like serial_mining.rs, not through the 0x80..0xFF range"
        );
        // echoed_job_id(sent) == sent & 0x78, and that's what the parser
        // ((result & 0xF0) >> 1) recovers — so dispatch-side store and
        // nonce-side lookup land in the same slot for every value the
        // dispatcher actually uses (multiples of 8).
        for sent in (0u8..=255).step_by(8) {
            let echoed = echoed_job_id(sent);
            assert_eq!(echoed, sent & 0x78, "echoed_job_id({sent}) == sent & 0x78");
            // Re-derive via the chip's encode/decode round-trip.
            let result_byte_high_nibble = (sent << 1) & 0xF0;
            assert_eq!(result_byte_high_nibble >> 1, echoed);
        }
    }

    #[test]
    fn build_bm1362_serial_work_frame_byte_layout() {
        // Pin the PROVEN 88-byte BM1362 serial full-header work frame:
        //   [0..2]   = 0x55 0xAA preamble
        //   [2]      = 0x21 header  ·  [3] = 0x56 length
        //   [4]      = job_id  ·  [5] = 0x01 num_midstates  ·  [6..10] = nonce(0)
        //   [10..14] = nbits LE  ·  [14..18] = ntime LE
        //   [18..50] = merkle_root, 32-bit-word-reversed
        //   [50..82] = prev_block_hash, 32-bit-word-reversed
        //   [82..86] = version LE  ·  [86..88] = CRC16-CCITT-FALSE, BE-appended,
        //              over frame[2..86] (the 84 bytes from 0x21)
        let work = dcentrald_stratum::share_pipeline::MiningWork {
            work_generation: dcentrald_stratum::WorkGeneration::UNTRACKED,
            midstates: vec![[0u8; 32]],
            merkle4: [0u8; 4],
            ntime: 0x1122_3344,
            nbits: 0x5566_7788,
            job_id: "abc".to_string(),
            extranonce2: "00".to_string(),
            version: 0x2000_0004,
            version_mask: 0x1FFF_E000,
            share_target: [0xFF; 32],
            // Distinct per-word bytes so the word-reversal is visible.
            merkle_root: {
                let mut m = [0u8; 32];
                for (i, b) in m.iter_mut().enumerate() {
                    *b = i as u8;
                }
                m
            },
            prev_block_hash: {
                let mut p = [0u8; 32];
                for (i, b) in p.iter_mut().enumerate() {
                    *b = 0x80 + i as u8;
                }
                p
            },
        };
        let f = build_bm1362_serial_work_frame(&work, 0x18);
        assert_eq!(f.len(), 88, "88 bytes on the wire");
        assert_eq!(
            &f[0..4],
            &[0x55, 0xAA, 0x21, 0x56],
            "preamble + header + length"
        );
        assert_eq!(f[4], 0x18, "job_id at payload[0]");
        assert_eq!(f[5], 0x01, "num_midstates = 1");
        assert_eq!(&f[6..10], &[0, 0, 0, 0], "starting_nonce = 0");
        assert_eq!(&f[10..14], &work.nbits.to_le_bytes(), "nbits LE");
        assert_eq!(&f[14..18], &work.ntime.to_le_bytes(), "ntime LE");
        assert_eq!(
            &f[18..50],
            &reverse_32bit_words(&work.merkle_root),
            "merkle_root, 32-bit-word-reversed"
        );
        assert_eq!(
            &f[50..82],
            &reverse_32bit_words(&work.prev_block_hash),
            "prev_block_hash, 32-bit-word-reversed"
        );
        assert_eq!(&f[82..86], &work.version.to_le_bytes(), "version LE");
        // CRC over the 84 bytes from f[2] (0x21) through f[85] (last payload byte).
        let crc = dcentrald_hal::serial_chain::crc16_public(&f[2..86]);
        assert_eq!(
            f[86],
            (crc >> 8) as u8,
            "CRC hi byte first (big-endian append)"
        );
        assert_eq!(f[87], (crc & 0xFF) as u8, "CRC lo byte");
        // Cross-check the word-reversal helper against a hand-computed example.
        let mut src = [0u8; 32];
        for (i, b) in src.iter_mut().enumerate() {
            *b = i as u8;
        }
        let rev = reverse_32bit_words(&src);
        // word 0 (bytes 0..4) ↔ word 7 (bytes 28..32)
        assert_eq!(&rev[0..4], &[28, 29, 30, 31]);
        assert_eq!(&rev[28..32], &[0, 1, 2, 3]);
    }

    #[test]
    fn build_bm1362_asic86_work_frame_byte_layout() {
        let mut midstate = [0u8; 32];
        for (i, b) in midstate.iter_mut().enumerate() {
            *b = 0x40 + i as u8;
        }
        let work = dcentrald_stratum::share_pipeline::MiningWork {
            work_generation: dcentrald_stratum::WorkGeneration::UNTRACKED,
            midstates: vec![midstate],
            merkle4: [0u8; 4],
            ntime: 0x1122_3344,
            nbits: 0x5566_7788,
            job_id: "abc".to_string(),
            extranonce2: "00".to_string(),
            version: 0x2000_0004,
            version_mask: 0x1FFF_E000,
            share_target: [0xFF; 32],
            merkle_root: [0xAB; 32],
            prev_block_hash: [0xCD; 32],
        };

        let frame = build_bm1362_asic86_work_frame(&work, 0x27, 0xAABB_CCDD);
        assert_eq!(frame.type_byte, CMD_WORK_PACKAGE);
        assert_eq!(frame.job_id, 0x27);
        assert_eq!(frame.sno, 0xAABB_CCDD);
        assert_eq!(&frame.data2[0..4], &work.ntime.to_le_bytes());
        assert_eq!(&frame.data2[4..8], &work.nbits.to_le_bytes());
        assert_eq!(&frame.data2[8..12], &[0, 0, 0, 0]);
        assert_eq!(&frame.data[0..32], &midstate);
        assert_eq!(&frame.data[32..64], &work.merkle_root);
        let bytes = frame.to_bytes();
        assert_eq!(bytes.len(), 86);
        assert_eq!(bytes[0], CMD_WORK_PACKAGE);
    }

    #[test]
    fn bm1362_cold_boot_register_values_match_canonical_init_plan() {
        // Pin the AM3 BB defaults to the shared BM1362_INIT_PLAN. The legacy
        // Amlogic-derived values remain available only through
        // DCENT_AM3_BB_LEGACY_AMLOGIC_INIT for A/B bench diagnostics.
        assert_eq!(
            (BM1362_REG_INIT_CONTROL, BM1362_INIT_CONTROL_BCAST),
            (0xA8, 0x0007_0000)
        );
        assert_eq!(BM1362_INIT_CONTROL_PER_CHIP, 0x0007_01F0);
        assert_eq!(BM1362_INIT_CONTROL_BCAST_LEGACY_AMLOGIC, 0x0000_0000);
        assert_eq!(BM1362_INIT_CONTROL_PER_CHIP_LEGACY_AMLOGIC, 0x0200_0000);
        assert_eq!(
            (BM1362_REG_VERSION_MASK, BM1362_VERSION_MASK_VALUE),
            (0xA4, 0x9000_FFFF)
        );
        assert_eq!(BM1362_REG_CORE_CTRL, 0x3C);
        assert_eq!(BM1362_CORE_REG_HASH_CLK, 0x8000_8540);
        assert_eq!(BM1362_CORE_REG_CLK_DELAY, 0x8000_8008);
        assert_eq!(BM1362_CORE_REG_UNKNOWN, 0x8000_82AA);
        assert_eq!(
            (BM1362_REG_ANALOG_MUX, BM1362_ANALOG_MUX_VALUE),
            (0x54, 0x0000_0003)
        );
        assert_eq!(
            (BM1362_REG_IO_DRIVER, BM1362_IO_DRIVER_NORMAL),
            (0x58, 0x0001_1111)
        );
        assert_eq!(
            (BM1362_REG_NONCE_RANGE, BM1362_NONCE_RANGE_126),
            (0x10, 0x0000_1381)
        );
        assert_eq!(
            (BM1362_REG_PLL0_DIVIDER, BM1362_PLL0_DIVIDER_VALUE),
            (0x70, 0x0000_0000)
        );
        assert_eq!(
            (BM1362_REG_PLL0_PARAM, BM1362_PLL0_PARAM_525MHZ),
            (0x08, 0x40A8_0265)
        );
        assert_eq!(
            (BM1362_REG_TICKET_MASK, BM1362_TICKET_MASK_256),
            (0x14, 0x0000_00FF)
        );
        assert_eq!(
            (UART_RELAY_REG_ADDR, UART_RELAY_BOSMINER_ENABLE),
            (0x2C, 0x007C_0003)
        );
        assert_eq!(
            (UART_RELAY_ALT_REG_ADDR, UART_RELAY_BOSMINER_ENABLE_ALT),
            (0x34, 0x000F_0003)
        );
        assert_eq!(BM1362_PLL_RAMP_START_MHZ, 400);
        assert_eq!(BM1362_PLL_RAMP_STEP_MHZ, 25);
        assert_eq!(BM1362_PLL_RAMP_SETTLE_MS, 100);
        assert_eq!(BM1362_SERIAL_PACE_MIN_MS, 20);
        // The on-wire frame for a sample one: 0x3C = HashClk → [HDR=0x51, LEN=0x09,
        // CHIP=0x00, REG=0x3C, VAL_BE=80 00 85 40, CRC5].
        let f = build_broadcast_write_frame(BM1362_REG_CORE_CTRL, BM1362_CORE_REG_HASH_CLK);
        assert_eq!(&f[..8], &[0x51, 0x09, 0x00, 0x3C, 0x80, 0x00, 0x85, 0x40]);
        // Per-chip Step 7 uses HDR=0x41 with the assigned chip address.
        let f =
            build_single_write_frame(0x7E, BM1362_REG_INIT_CONTROL, BM1362_INIT_CONTROL_PER_CHIP);
        assert_eq!(&f[..8], &[0x41, 0x09, 0x7E, 0xA8, 0x00, 0x07, 0x01, 0xF0]);
        let pll_400 = bm1362_pll_ramp_to_target(400);
        assert_eq!(pll_400.last().map(|(_, mhz)| *mhz), Some(400));
        let pll_525 = bm1362_pll_ramp_to_target(525);
        assert_eq!(pll_525.last(), Some(&(BM1362_PLL0_PARAM_525MHZ, 525)));
        assert_eq!(BM1362_INIT_PLAN.misc_control_pre_baud, 0xFF0F_C100);
        assert_eq!(BM1362_INIT_PLAN.misc_control_post_fast_baud, 0x00C1_00B0);
        assert_eq!(BM1362_MISC_CONTROL_LEGACY_AMLOGIC, 0x00C1_00B0);
        assert_eq!(cold_boot_step::MISC_CONTROL_REG, 0x18);
        assert_eq!(
            cold_boot_step::MISC_CONTROL_VALUE_POST_FAST_BAUD,
            0x00C1_00B0
        );
    }

    #[test]
    fn rolled_version_applies_bip320_field() {
        // Base version 0x2000_0004; raw bits 0x0001 → << 13 = 0x0000_2000,
        // which is inside the 0x1FFF_E000 field → version becomes 0x2000_2004.
        assert_eq!(rolled_version(0x2000_0004, 0x0001), 0x2000_2004);
        // Zero rolling bits ⇒ unchanged.
        assert_eq!(rolled_version(0x2000_0004, 0x0000), 0x2000_0004);
        // Bits that fall outside the field (low 13 / above bit 28) are masked off.
        // 0xFFFF << 13 = 0x1FFF_E000 exactly fills the field.
        assert_eq!(
            rolled_version(0x2000_0004, 0xFFFF) & 0x1FFF_E000,
            0x1FFF_E000
        );
        // The base's bits outside the field are preserved.
        assert_eq!(
            rolled_version(0xE000_0005, 0x0000) & !0x1FFF_E000,
            0xE000_0005 & !0x1FFF_E000
        );
    }

    #[test]
    fn rolled_version_checked_respects_negotiated_mask() {
        // Updated 2026-05-15 (cross-platform Protocol fix sweep): when
        // version_mask=0 and vbits != 0, BM1362 chips have rolled BIP320
        // unconditionally; reconstruct rather than drop. The previous
        // assertion `rolled_version_checked(0x2000_0004, 0, 1) == None`
        // pinned the silent-drop bug (Q2 Protocol expert F2; fixed across
        // 4 sites in this sweep).
        assert_eq!(rolled_version_checked(0x2000_0004, 0, 0), Some(0x2000_0004));
        // vbits=1, mask=0 → reconstruct: (1 << 13) & 0x1FFFE000 = 0x2000;
        // rolled = (0x2000_0004 & !0x1FFFE000) | 0x2000 = 0x2000_2004.
        assert_eq!(rolled_version_checked(0x2000_0004, 0, 1), Some(0x2000_2004));
        // mask != 0 + delta inside mask → accept.
        assert_eq!(
            rolled_version_checked(0x2000_0004, 0x0000_6000, 1),
            Some(0x2000_2004)
        );
        // mask != 0 + delta OUTSIDE the negotiated mask → still drop
        // (the share would be rejected post-submit by the pool; drop
        // locally to avoid spamming).
        assert_eq!(
            rolled_version_checked(0x2000_0004, 0x0000_6000, 4),
            None,
            "version delta outside the negotiated mask is rejected"
        );
    }

    #[test]
    fn dispatched_work_full_header_byte_layout() {
        // Pin the 80-byte header layout so the share-validation path can't
        // drift: version LE @ [0..4], prev_block_hash @ [4..36], merkle_root
        // @ [36..68], ntime LE @ [68..72], nbits LE @ [72..76], nonce LE @
        // [76..80] — the byte order WorkBuilder produces / serial_build_header
        // uses + validate_full_header hashes.
        let dw = DispatchedWork {
            work_generation: dcentrald_stratum::WorkGeneration::UNTRACKED,
            job_id: "deadbeef".to_string(),
            extranonce2: "00000000".to_string(),
            ntime: 0x1122_3344,
            nbits: 0x5566_7788,
            version: 0x2000_0004,
            version_mask: 0x1FFF_E000,
            prev_block_hash: [0xAA; 32],
            merkle_root: [0xBB; 32],
            share_target: [0xFF; 32],
        };
        // Use a rolled version distinct from the base to prove it lands at [0..4].
        let rv = 0x2000_4004u32;
        let h = dw.full_header(rv, 0xDEAD_BEEF);
        assert_eq!(&h[0..4], &rv.to_le_bytes(), "rolled version LE @ [0..4]");
        assert_eq!(&h[4..36], &[0xAA; 32], "prev_block_hash @ [4..36]");
        assert_eq!(&h[36..68], &[0xBB; 32], "merkle_root @ [36..68]");
        assert_eq!(
            &h[68..72],
            &0x1122_3344u32.to_le_bytes(),
            "ntime LE @ [68..72]"
        );
        assert_eq!(
            &h[72..76],
            &0x5566_7788u32.to_le_bytes(),
            "nbits LE @ [72..76]"
        );
        assert_eq!(
            &h[76..80],
            &0xDEAD_BEEFu32.to_le_bytes(),
            "nonce LE @ [76..80]"
        );
        assert_eq!(h.len(), 80, "block header is exactly 80 bytes");
        // Different nonce ⇒ only the trailing 4 bytes change.
        let h2 = dw.full_header(rv, 0);
        assert_eq!(
            &h[..76],
            &h2[..76],
            "only the nonce field differs between headers"
        );
        assert_ne!(&h[76..], &h2[76..]);
    }

    #[test]
    fn dispatched_work_is_clone() {
        // The nonce → header lookup table holds `Option<DispatchedWork>` and
        // is built with `vec![None; 256]`, which requires Clone.
        fn _assert_clone<T: Clone>() {}
        _assert_clone::<DispatchedWork>();
        _assert_clone::<Option<DispatchedWork>>();
    }

    #[test]
    fn now_us_is_monotonic_and_nonzero_after_init() {
        let a = now_us();
        // Burn a little wall-clock time.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = now_us();
        assert!(b >= a, "now_us must be monotonic (a={a}, b={b})");
        // After at least one prior call the epoch is set; the second reading
        // is the elapsed-since-epoch, so it's >= the first (could be 0 only on
        // the very first call when the epoch was just created).
        assert!(b >= 2_000 || b >= a, "now_us advanced after a 2ms sleep");
    }

    #[test]
    fn stratum_config_from_propagates_pool_and_donation() {
        // Build a minimal config (all fields are #[serde(default)]).
        let cfg: DcentraldConfig = toml::from_str(
            "[pool]\nurl = \"stratum+tcp://pool.example.com:3333\"\nworker = \"bc1qtest.rig1\"\npassword = \"x\"\n\n[mining]\nversion_rolling = true\nsuggest_difficulty = 4096\n",
        )
        .expect("minimal config must parse");
        let sc = stratum_config_from(&cfg);
        assert_eq!(sc.pool1.url, "stratum+tcp://pool.example.com:3333");
        assert_eq!(sc.pool1.worker, "bc1qtest.rig1");
        assert_eq!(sc.pool1.password, "x");
        assert!(sc.pool2.is_none() && sc.pool3.is_none());
        assert_eq!(sc.routing_mode, "failover");
        assert!(sc.version_rolling);
        assert_eq!(sc.suggest_difficulty, Some(4096));
        // Donation defaults flow through (transparent 2% donation by default).
        assert_eq!(sc.donation.enabled, cfg.donation.enabled);
        assert_eq!(sc.donation.percent, cfg.donation.percent);
        assert_eq!(sc.donation.worker, cfg.donation.worker);
        // am3-bb path does not pre-claim a nominal hashrate.
        assert_eq!(sc.nominal_hashrate_ghs, 0.0);
        assert!(!sc.sv2_extended_channel);
    }

    // ─────────────────────────────────────────────────────────────────────
    // PR-021: continuous fan PID — load-bearing safety invariants.
    // ─────────────────────────────────────────────────────────────────────

    use std::sync::Mutex;

    /// Records every PWM the PID writes so tests can assert the clamp + slew.
    struct RecordingFan {
        pwm_log: Mutex<Vec<u8>>,
        rpm: u32,
        tach: bool,
    }

    impl FanAccess for RecordingFan {
        fn set_speed(&self, pwm: u8) {
            self.pwm_log.lock().unwrap().push(pwm);
        }
        fn set_speed_checked(&self, pwm: u8) -> dcentrald_hal::Result<FanCommandReceipt> {
            self.set_speed(pwm);
            FanCommandReceipt::from_matching_readback(pwm, self.get_speed_pwm())
        }
        fn get_rpm(&self) -> u32 {
            self.rpm
        }
        fn get_speed_pwm(&self) -> u8 {
            self.pwm_log.lock().unwrap().last().copied().unwrap_or(0)
        }
        fn tach_available(&self) -> bool {
            self.tach
        }
    }

    fn recording_capped_fan(
        fan_min_pwm: u8,
        fan_max_pwm: u8,
    ) -> (Am3BbCappedFan, Arc<RecordingFan>) {
        let rec = Arc::new(RecordingFan {
            pwm_log: Mutex::new(Vec::new()),
            rpm: 1260,
            tach: true,
        });
        let fan = Am3BbCappedFan {
            fan: rec.clone() as Arc<dyn FanAccess>,
            fan_min_pwm,
            fan_max_pwm,
        };
        (fan, rec)
    }

    /// INVARIANT #1: the PID PWM clamp can NEVER exceed the PWM-30 home cap,
    /// for any requested value and any operator config — and an operator can
    /// only ever make it quieter, never louder.
    #[test]
    fn clamp_pid_pwm_never_exceeds_home_cap() {
        // Sweep every possible requested PWM against the home config.
        for req in 0u8..=255 {
            let out = am3_bb_clamp_pid_pwm(0, 30, req);
            assert!(
                out <= AM3_BB_FAN_HARD_CAP_PWM,
                "requested {req} clamped to {out} which exceeds the {AM3_BB_FAN_HARD_CAP_PWM} cap"
            );
        }
        // Operator asking for a HIGHER max cannot raise the real ceiling.
        assert_eq!(
            am3_bb_clamp_pid_pwm(0, 100, 100),
            AM3_BB_FAN_HARD_CAP_PWM,
            "operator config can never make the AM3 BB fan blast past 30"
        );
        assert_eq!(am3_bb_clamp_pid_pwm(0, 100, 255), AM3_BB_FAN_HARD_CAP_PWM);
        // Below the quiet floor → snapped UP to the whisper-quiet floor.
        assert_eq!(
            am3_bb_clamp_pid_pwm(0, 30, 0),
            AM3_BB_FAN_SAFE_FLOOR_PWM,
            "PID asking for less than the quiet floor still keeps fans spinning at the boot level"
        );
        // An intentionally LOWER operator cap is honoured (safety on this
        // board comes from cutting ASIC power, not from fan blast).
        assert_eq!(am3_bb_clamp_pid_pwm(0, 5, 100), 5);
        // A normal in-band request passes through unchanged.
        assert_eq!(am3_bb_clamp_pid_pwm(10, 30, 22), 22);
    }

    #[test]
    fn watchdog_liveness_expectation_tracks_the_configured_thermal_cadence() {
        assert_eq!(am3_bb_thermal_poll_interval(0.1), Duration::from_secs(1));
        assert_eq!(
            am3_bb_thermal_poll_interval(2.5),
            Duration::from_millis(2_500)
        );
        assert_eq!(
            am3_bb_expected_safety_liveness_interval(2.5),
            Duration::from_millis(4_500)
        );
        assert_eq!(
            am3_bb_expected_safety_liveness_interval(30.0),
            Duration::from_secs(32)
        );
    }

    #[test]
    fn thermal_snapshot_rejects_one_missing_chain_even_when_peers_are_healthy() {
        let complete = am3_bb_thermal_snapshot_from_chain_samples(&[4, 1, 3], 68.0);
        assert!(complete.fresh);
        assert_eq!(complete.covered_chains, 3);
        assert_eq!(complete.expected_chains, 3);

        // Chains 0 and 2 together provide eight valid samples. That aggregate
        // must never mask chain 1 contributing no fresh thermal evidence.
        let missing_middle = am3_bb_thermal_snapshot_from_chain_samples(&[4, 0, 4], 68.0);
        assert_eq!(missing_middle.samples, 8);
        assert_eq!(missing_middle.covered_chains, 2);
        assert_eq!(missing_middle.expected_chains, 3);
        assert!(!missing_middle.fresh);
    }

    #[test]
    fn dangerous_incomplete_first_poll_cannot_be_hidden_by_cooler_retry() {
        let dangerous_incomplete = am3_bb_thermal_snapshot_from_chain_samples(&[4, 0, 4], 80.0);
        let cooler_incomplete = am3_bb_thermal_snapshot_from_chain_samples(&[4, 0, 4], 60.0);
        let mut scripted_attempts = [dangerous_incomplete, cooler_incomplete].into_iter();
        let mut polled_stages = Vec::new();

        let error = am3_bb_poll_thermal_attempts("runtime", 75.0, Duration::ZERO, |poll_stage| {
            polled_stages.push(poll_stage);
            scripted_attempts.next().unwrap()
        })
        .unwrap_err();

        assert!(error.to_string().contains("80.0C"));
        assert_eq!(polled_stages, ["runtime"]);
        assert_eq!(
            scripted_attempts.count(),
            1,
            "the cooler retry must remain unconsumed after the first attempt proves danger"
        );
    }

    /// INVARIANT #2: at/above the dangerous threshold the decision is always
    /// CutHashThenFan (hash power is cut first; the PID never tries to
    /// out-cool a dangerous temp by ramping the fan).
    #[test]
    fn thermal_action_orders_cut_hash_before_fan() {
        assert_eq!(
            am3_bb_thermal_action(54.0, 75.0),
            Am3BbThermalAction::PidWithinCap
        );
        assert_eq!(
            am3_bb_thermal_action(74.9, 75.0),
            Am3BbThermalAction::PidWithinCap
        );
        // Exactly at dangerous → cut hash first.
        assert_eq!(
            am3_bb_thermal_action(75.0, 75.0),
            Am3BbThermalAction::CutHashThenFan
        );
        assert_eq!(
            am3_bb_thermal_action(95.0, 75.0),
            Am3BbThermalAction::CutHashThenFan
        );
    }

    /// INVARIANT #2 at the PID layer: a dangerous snapshot must NOT move the
    /// fan — the PID stops trimming and lets the fail-closed path cut hash.
    #[test]
    fn pid_does_not_ramp_fan_on_dangerous_temp() {
        let (fan, rec) = recording_capped_fan(0, 30);
        let mut pid = Am3BbFanPid::new(fan, 55).unwrap();
        let writes_after_init = rec.pwm_log.lock().unwrap().len();
        // Dangerous reading: the PID must NOT issue a new fan command.
        pid.step(
            &Am3BbThermalSnapshot {
                samples: 3,
                covered_chains: 3,
                expected_chains: 3,
                max_temp_c: 80.0,
                fresh: true,
            },
            75.0,
        )
        .unwrap();
        assert_eq!(
            rec.pwm_log.lock().unwrap().len(),
            writes_after_init,
            "PID issued a fan write on a dangerous-temp sample — it must defer to cut-hash-first"
        );
    }

    /// INVARIANT #3: an EMPTY thermal sample must NOT drive the fan — the PID
    /// holds station and lets the fail-closed supervisor own stale/empty.
    #[test]
    fn pid_holds_station_on_empty_sample() {
        let (fan, rec) = recording_capped_fan(0, 30);
        let mut pid = Am3BbFanPid::new(fan, 55).unwrap();
        let start_pwm = pid.commanded_pwm();
        let writes_after_init = rec.pwm_log.lock().unwrap().len();
        pid.step(
            &Am3BbThermalSnapshot {
                samples: 0,
                covered_chains: 0,
                expected_chains: 3,
                max_temp_c: f32::NEG_INFINITY,
                fresh: false,
            },
            75.0,
        )
        .unwrap();
        assert_eq!(
            rec.pwm_log.lock().unwrap().len(),
            writes_after_init,
            "PID drove the fan from an empty sample — must NOT act on absent sensor data"
        );
        assert_eq!(pid.commanded_pwm(), start_pwm, "commanded PWM unchanged");
    }

    #[test]
    fn pid_holds_station_on_stale_last_known_good_sample() {
        let (fan, rec) = recording_capped_fan(0, 30);
        let mut pid = Am3BbFanPid::new(fan, 55).unwrap();
        let start_pwm = pid.commanded_pwm();
        let writes_after_init = rec.pwm_log.lock().unwrap().len();

        pid.step(
            &Am3BbThermalSnapshot {
                samples: 3,
                covered_chains: 3,
                expected_chains: 3,
                max_temp_c: 68.0,
                fresh: false,
            },
            75.0,
        )
        .unwrap();

        assert_eq!(rec.pwm_log.lock().unwrap().len(), writes_after_init);
        assert_eq!(pid.commanded_pwm(), start_pwm);
    }

    /// INVARIANT #6 + quiet posture: at/below the setpoint the PID stays at
    /// the whisper-quiet floor; a sustained hot (but not dangerous) temp ramps
    /// the fan only TOWARD the cap, never past it, and only a few PWM steps
    /// per tick (no audible jump).
    #[test]
    fn pid_steady_state_is_quiet_and_ramps_bounded_within_cap() {
        let (fan, _rec) = recording_capped_fan(0, 30);
        let mut pid = Am3BbFanPid::new(fan, 55).unwrap();
        // Cool: a few ticks well below the setpoint → stays at the floor.
        for _ in 0..5 {
            pid.step(
                &Am3BbThermalSnapshot {
                    samples: 3,
                    covered_chains: 3,
                    expected_chains: 3,
                    max_temp_c: 45.0,
                    fresh: true,
                },
                75.0,
            )
            .unwrap();
        }
        assert_eq!(
            pid.commanded_pwm(),
            AM3_BB_FAN_SAFE_FLOOR_PWM,
            "below setpoint the quiet home fan must stay at the whisper-quiet floor"
        );

        // Now hot-but-safe (68C, below dangerous 75): the PID ramps up, but
        // every single-tick move is bounded and the value never exceeds 30.
        let mut prev = pid.commanded_pwm();
        for _ in 0..30 {
            pid.step(
                &Am3BbThermalSnapshot {
                    samples: 3,
                    covered_chains: 3,
                    expected_chains: 3,
                    max_temp_c: 68.0,
                    fresh: true,
                },
                75.0,
            )
            .unwrap();
            let now = pid.commanded_pwm();
            assert!(
                now <= AM3_BB_FAN_HARD_CAP_PWM,
                "PID commanded {now} which exceeds the {AM3_BB_FAN_HARD_CAP_PWM} home cap"
            );
            assert!(
                now.abs_diff(prev) <= AM3_BB_FAN_PID_MAX_STEP_PWM,
                "single-tick PWM slew {} -> {} exceeds the {}-step quiet limit",
                prev,
                now,
                AM3_BB_FAN_PID_MAX_STEP_PWM
            );
            prev = now;
        }
        // Sustained hot drove it to the cap (active cooling within the quiet
        // envelope), but NOT past it.
        assert_eq!(
            pid.commanded_pwm(),
            AM3_BB_FAN_HARD_CAP_PWM,
            "sustained hot temp should ramp the fan to (but never past) the quiet cap"
        );
    }

    /// The capped-fan view itself cannot be coerced to blast: even a bogus
    /// 255 request applied directly is clamped.
    #[test]
    fn capped_fan_apply_is_clamped() {
        let (fan, rec) = recording_capped_fan(0, 30);
        let written = fan.apply(255).unwrap();
        assert_eq!(written, AM3_BB_FAN_HARD_CAP_PWM);
        assert_eq!(*rec.pwm_log.lock().unwrap().last().unwrap(), 30);
        assert_eq!(fan.apply(0).unwrap(), AM3_BB_FAN_SAFE_FLOOR_PWM);
    }
}

#[path = "am3_bb_retained_gpio.rs"]
mod retained_gpio;

#[path = "am3_bb_pre_power_run.rs"]
mod pre_power_run;
