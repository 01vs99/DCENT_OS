//! Pure chain-transport operation language (ADR-0010 / decade P1-3 I/O seed).
//!
//! # Why
//!
//! HAL already ships `Bm1397PlusChainBackend` (`dcentrald-hal::chain_backend`)
//! as the **live** I/O surface for BM1397+/BM1362-family serial + FPGA FIFO
//! backends. That trait cannot live in `dcentrald-common` (HAL, Unix fd, mmap).
//!
//! This module is the **HAL-free twin**:
//!
//! - declarative [`TransportOp`] ops that mirror the Bm1397+ backend surface
//! - pure admission of which ops a [`AsicProtocolIdentity`] may prepare
//! - pure mapping from [`ChainTransportKind`] → [`TransportBackendClass`]
//! - conversion of [`crate::asic_protocol::InitStep`] into transport ops
//! - host-mockable [`RecordingChainTransport`] so engines/tests can pin the
//!   op sequence without FPGA/UART hardware
//!
//! Live adapters (SerialChainBackend / FpgaChainBackend) remain in HAL and
//! should eventually execute these ops rather than open-coding a second matrix.
//!
//! # Status
//!
//! **PRODUCTION pure policy** for op language + admission + recorder.
//! Live HAL execute loop over these ops is **EXPERIMENTAL residual** (strangler).

use crate::asic_protocol::{
    admit_protocol_over_transport, InitProgram, InitStep, ProtocolTransportAdmission,
    ProtocolTransportError,
};
use crate::board_desc::{AsicProtocolIdentity, ChainTransportKind};

/// Coarse backend class implied by a board's [`ChainTransportKind`].
///
/// Distinct from the live HAL type: this is composition identity only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportBackendClass {
    /// Braiins-layout FPGA FIFO / UIO (`FpgaChain` / `FpgaChainBackend`).
    FpgaUioFifo,
    /// AM2 hybrid PL UART and/or FPGA recipe selection.
    ZynqHybrid,
    /// Linux serial NS16550-class (`SerialChainBackend`).
    SerialUart,
    /// Bitmain stock axi_fpga mmap (BM1387 stock path — not Bm1397+ backend).
    StockAxiFpga,
    /// CVITEK `uart_trans` kernel helper.
    UartTransKernel,
    /// No chain open.
    ManagementOnly,
}

impl TransportBackendClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FpgaUioFifo => "fpga_uio_fifo",
            Self::ZynqHybrid => "zynq_hybrid",
            Self::SerialUart => "serial_uart",
            Self::StockAxiFpga => "stock_axi_fpga",
            Self::UartTransKernel => "uart_trans_kernel",
            Self::ManagementOnly => "management_only",
        }
    }

    /// Whether this class is expected to implement the BM1397+ command surface
    /// (`Bm1397PlusChainBackend` in HAL).
    pub const fn speaks_bm1397plus_command_surface(self) -> bool {
        matches!(
            self,
            Self::FpgaUioFifo | Self::ZynqHybrid | Self::SerialUart | Self::UartTransKernel
        )
    }
}

/// Map BoardDesc transport kind → pure backend class.
pub fn transport_backend_class(kind: ChainTransportKind) -> TransportBackendClass {
    match kind {
        ChainTransportKind::FpgaUio => TransportBackendClass::FpgaUioFifo,
        ChainTransportKind::ZynqHybrid => TransportBackendClass::ZynqHybrid,
        ChainTransportKind::Serial => TransportBackendClass::SerialUart,
        ChainTransportKind::StockFpga => TransportBackendClass::StockAxiFpga,
        ChainTransportKind::UartTrans => TransportBackendClass::UartTransKernel,
        ChainTransportKind::None => TransportBackendClass::ManagementOnly,
    }
}

/// Pure transport operation (no I/O). Mirrors HAL `Bm1397PlusChainBackend`
/// method surface so adapters can execute without inventing a second API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportOp {
    SetBaudRate {
        baud: u32,
    },
    SetResponseBodyLen {
        body_len: usize,
    },
    SendGetAddressBm1397Plus,
    SendChainInactiveBm1397Plus,
    SendSetAddressBm1397Plus {
        addr: u8,
    },
    SendWriteRegBroadcastBm1397Plus {
        reg: u8,
        value: u32,
    },
    SendWriteRegBm1397Plus {
        chip_addr: u8,
        reg: u8,
        value: u32,
    },
    SendReadRegBm1397Plus {
        chip_addr: u8,
        reg: u8,
    },
    /// Fully framed work item (preamble/CRC already applied by pure codec).
    SendWorkFrame {
        frame: Vec<u8>,
    },
    /// Software delay only — adapters sleep; recorder stores intent.
    DelayMs {
        ms: u32,
    },
}

impl TransportOp {
    /// Whether this op is part of the BM1397+ command family (vs delay/work).
    pub const fn is_bm1397plus_command(self: &TransportOp) -> bool {
        matches!(
            self,
            Self::SendGetAddressBm1397Plus
                | Self::SendChainInactiveBm1397Plus
                | Self::SendSetAddressBm1397Plus { .. }
                | Self::SendWriteRegBroadcastBm1397Plus { .. }
                | Self::SendWriteRegBm1397Plus { .. }
                | Self::SendReadRegBm1397Plus { .. }
                | Self::SetBaudRate { .. }
                | Self::SetResponseBodyLen { .. }
        )
    }
}

/// Why a transport op was refused for a protocol/backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportOpError {
    ProtocolTransport(ProtocolTransportError),
    /// BM1397+ command ops are not admitted for this protocol (e.g. BM1387 stock).
    Bm1397PlusCommandsNotAdmitted {
        protocol: AsicProtocolIdentity,
    },
    /// Backend class cannot execute BM1397+ surface (stock AXI / management).
    BackendDoesNotSpeakBm1397Plus {
        backend: TransportBackendClass,
    },
    /// Empty work frame is never valid.
    EmptyWorkFrame,
    /// Op not supported by pure recorder/adapters yet.
    UnsupportedOp,
}

impl std::fmt::Display for TransportOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtocolTransport(e) => write!(f, "transport op: {e}"),
            Self::Bm1397PlusCommandsNotAdmitted { protocol } => write!(
                f,
                "BM1397+ transport commands not admitted for protocol {protocol:?}"
            ),
            Self::BackendDoesNotSpeakBm1397Plus { backend } => write!(
                f,
                "backend class {backend:?} does not speak BM1397+ command surface"
            ),
            Self::EmptyWorkFrame => write!(f, "work frame must be non-empty"),
            Self::UnsupportedOp => write!(f, "transport op unsupported on this adapter"),
        }
    }
}

impl std::error::Error for TransportOpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProtocolTransport(e) => Some(e),
            _ => None,
        }
    }
}

/// Pure admission: may this protocol issue this op over its admitted transport?
pub fn admit_transport_op(
    admission: ProtocolTransportAdmission,
    op: &TransportOp,
) -> Result<(), TransportOpError> {
    let backend = transport_backend_class(admission.transport());
    match op {
        TransportOp::DelayMs { .. } => Ok(()),
        TransportOp::SendWorkFrame { frame } => {
            if frame.is_empty() {
                return Err(TransportOpError::EmptyWorkFrame);
            }
            // Work frames are family-specific codecs; require a non-management
            // transport and non-RuntimeDiscovered protocol (already on admission).
            Ok(())
        }
        other if other.is_bm1397plus_command() => {
            if !protocol_speaks_bm1397plus_commands(admission.protocol()) {
                return Err(TransportOpError::Bm1397PlusCommandsNotAdmitted {
                    protocol: admission.protocol(),
                });
            }
            if !backend.speaks_bm1397plus_command_surface() {
                return Err(TransportOpError::BackendDoesNotSpeakBm1397Plus { backend });
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// BM1397+/BM136x families that use the HAL `Bm1397PlusChainBackend` surface.
pub fn protocol_speaks_bm1397plus_commands(protocol: AsicProtocolIdentity) -> bool {
    matches!(
        protocol,
        AsicProtocolIdentity::Bm1397
            | AsicProtocolIdentity::Bm1398
            | AsicProtocolIdentity::Bm1362
            | AsicProtocolIdentity::Bm1366
            | AsicProtocolIdentity::Bm1368
            | AsicProtocolIdentity::Bm1370
    )
}

/// Pure address stride for full-population BM1397+ chains: `floor(256 / N)`.
///
/// Matches bosminer / stock narrative (126 chips → stride 2). `chip_count == 0`
/// is treated as 1 so planners never divide by zero (callers should still
/// refuse empty chains upstream).
///
/// **One-chip rule:** mathematical `256 / 1 = 256` is not representable as a
/// non-zero `u8` (would wrap to 0 and break one-chip repair fixtures). Returns
/// `1` so only address 0 is used — matches
/// [`dcentrald_api_types::asic_command::LinearAddressPlan::from_truncated_byte_space`]
/// and serial engine `serial_address_interval` (P1-3 SSOT).
pub const fn bm1397plus_addr_interval(chip_count: u8) -> u8 {
    let n = if chip_count == 0 {
        1u16
    } else {
        chip_count as u16
    };
    if n == 1 {
        1
    } else {
        (256 / n) as u8
    }
}

// ---------------------------------------------------------------------------
// UB-25 / H2 §G-2 (2026-08-03): chain address stride as DECLARED BOARD DATA
// with `floor(256/N)` retained as the fallback.
// ---------------------------------------------------------------------------
//
// # Why this exists
//
// [`bm1397plus_addr_interval`] above computes `floor(256/N)`. That formula is
// **not** what Bitmain's own factory jigs do on the modern chip generations, and
// three of five DCENT ASIC families already bypass it entirely (BM1387 hardcodes
// 4, BM1398 uses a frozen exact plan, BM1373 hardcodes 16). Stride is data.
//
// # Evidence — two independent desk sources, no live measurement
//
// **Source A — Bitmain's own AMTC `single_board_test` jig binaries (held).**
// The stride is a *chip-count bucket*, not a division. Decompile-verified in
// four separate binaries covering four chip families:
//
// | family  | binary                                                        | site |
// |---------|---------------------------------------------------------------|------|
// | BM1362  |  | `0x24c08` |
// | BM1366  |  | `0x67a2c` |
// | BM1368  |      | `0xbecfc` |
// | BM1370  | `bitmain-antminer-binaries/S21pro/single_board_test.dec/BTC_check_config_information@B8D80.c:87-118` |
//
// All four emit the identical ladder into `gAddress_interval`:
// `N > 128 → 1` · `64 < N ≤ 128 → 2` · `32 < N ≤ 64 → 4` · `N ≤ 32 → refuse`
// (the refusal path prints `"ERROR: Asic_Num == %d"` and shows `"Asic_Num < 32"`
// on the jig LCD). The value is then consumed verbatim by
// `set_chain_asic_address(chain, addr_interval)`, which walks
// `addr += addr_interval` per `send_set_address_command` — the exact ladder
// [`plan_bm1397plus_set_address_ladder`] builds — and by
// `get_asic_index_by_nonce(nonce, addr_interval) = (u8)(nonce >> 17) / interval`.
//
// **Source B — the ePIC UMC OS v1.22.0 jig hashboard DB** (`asic_addr_interval`,
// imported as `dcentrald_silicon_profiles::hashboard_topology::ChipDesc::
// vendor_declared_addr_interval`). ePIC-transcribed and NOT authoritative on its
// own.
//
// # Adjudication rule applied here
//
// A SKU is DECLARED only where **Source A and Source B independently agree** and
// the computed fallback disagrees. Everything else keeps the fallback. Notably:
//
// - **55-chip `A3HB7070x`**: jig bucket = 4, fallback = 4, ePIC = **2**. The two
//   strong sources agree on 4, so ePIC is the outlier — the fallback already
//   yields the jig value and nothing is declared. This is direct evidence that
//   ePIC's flat `2` is *not* uniformly correct, and is why "just adopt ePIC"
//   would have been wrong.
// - **36-chip `A3HB40601`**: jig bucket = 4, fallback = **7**, ePIC = **2** — a
//   three-way split. Only one source (the jig) supports 4, so per the
//   never-fabricate-a-stride rule this board stays on the fallback and is
//   flagged as UNRESOLVED. It is the single roster row whose fallback is
//   corroborated by nobody. No DCENT unit mounts it.
//
// # Status
//
// **DESK EVIDENCE, Experimental.** No live enumeration has been run against any
// declared stride; every DCENT live-proven chain (S19j Pro 126→2, S21 `a lab unit`
// 108→2) falls in the all-sources-agree set, so nothing live changes.
// [`bm1397plus_addr_interval`] is deliberately left byte-identical so that no
// board which works today can change behaviour.

/// Where a resolved chain address stride came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrIntervalSource {
    /// A per-board declared stride from [`DECLARED_ADDR_INTERVALS`], admitted
    /// only where the Bitmain jig bucket rule and the ePIC vendor DB agree.
    BoardDeclared,
    /// The historical [`bm1397plus_addr_interval`] `floor(256/N)` computation.
    /// Used for every SKU that declares nothing, and for unknown/absent SKUs.
    ComputedFallback,
}

impl AddrIntervalSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BoardDeclared => "board_declared",
            Self::ComputedFallback => "computed_fallback_256_over_n",
        }
    }
}

/// A resolved chain address stride plus the provenance that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrIntervalDecision {
    /// Chip-address stride to walk during SetAddress assignment.
    pub interval: u8,
    /// Which authority produced [`Self::interval`].
    pub source: AddrIntervalSource,
    /// Highest chip address the plan will emit: `(chip_count - 1) * interval`.
    pub last_address: u8,
}

/// Why a stride was refused. Fail-closed: callers must not enumerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrIntervalError {
    /// `(chip_count - 1) * interval` does not fit in the 8-bit chip-address
    /// space, so the ladder would wrap and alias two chips onto one address.
    AddressSpaceOverflow {
        chip_count: u8,
        interval: u8,
        last_address: u16,
    },
    /// A stride of zero can never separate two chips.
    ZeroInterval { chip_count: u8 },
}

impl std::fmt::Display for AddrIntervalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddressSpaceOverflow {
                chip_count,
                interval,
                last_address,
            } => write!(
                f,
                "chain address stride {interval} × {chip_count} chips overflows the 8-bit \
                 chip-address space (last address would be {last_address} > 255)"
            ),
            Self::ZeroInterval { chip_count } => {
                write!(
                    f,
                    "chain address stride 0 is invalid for {chip_count} chips"
                )
            }
        }
    }
}

impl std::error::Error for AddrIntervalError {}

/// Bitmain factory-jig chip-address stride bucket (Source A above).
///
/// Decompile-verified byte-identical in the BM1362 / BM1366 / BM1368 / BM1370
/// `single_board_test` binaries. Returns `None` for the counts the jig itself
/// refuses (`N ≤ 32`, including `N == 0`) — DCENT keeps serving those from the
/// fallback because our one-chip repair fixtures are outside the jig's domain.
///
/// This is **not** applicable to BM1387 (Gen-1, stride 4), BM1398 (frozen exact
/// plan) or BM1373 (stride 16): those predate/bypass this ladder and the
/// `"Asic_Num < 32"` marker string is absent from the BM1398 jig binary.
pub const fn bitmain_jig_addr_interval(chip_count: u8) -> Option<u8> {
    // `chip_count` is u8, so the `> 128 → 1` arm is reachable for 129..=255.
    if chip_count > 128 {
        Some(1)
    } else if chip_count > 64 {
        Some(2)
    } else if chip_count > 32 {
        Some(4)
    } else {
        None
    }
}

/// One declared per-board stride row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclaredAddrInterval {
    /// Bitmain SKU string, matching
    /// `dcentrald_silicon_profiles::hashboard_topology` registry keys.
    pub sku: &'static str,
    /// Chips on one chain for this SKU (the count both sources were read at).
    pub chips_per_chain: u8,
    /// The corroborated stride.
    pub interval: u8,
}

/// Per-board declared chain address strides.
///
/// **Admission rule (do not relax):** a row exists here only where the Bitmain
/// jig bucket rule AND the ePIC vendor DB independently agree on a value that
/// [`bm1397plus_addr_interval`] gets wrong. Twelve SKUs qualify today; all
/// twelve resolve to `2` where the formula computes `3`. Two of them are
/// catalog-`Exact` rows the queue called out by name: `BHB56902` (S19k Pro, 77
/// chips) and the 65-chip `A3HB706xx` S21 Pro family.
///
/// Never add a row from a single source. Never add a row from a DCENT guess.
/// A DCENT **live measurement** would outrank both desk sources and should
/// replace the row (and its provenance comment) outright.
pub const DECLARED_ADDR_INTERVALS: &[DeclaredAddrInterval] = &[
    // 84-chip BM1362 repair-class board. jig bucket 2 · ePIC 2 · formula 3.
    row(84, 2, "BHB42803"),
    // 77-chip BM1366 (S19k Pro). jig bucket 2 · ePIC 2 · formula 3.
    // `BHB56902` is a catalog-`Exact` row named by the queue.
    row(77, 2, "BHB56901"),
    row(77, 2, "BHB56902"),
    row(77, 2, "BHB56903"),
    row(77, 2, "BHB56906"),
    row(77, 2, "BHB56907"),
    // 65-chip BM1370 (S21 Pro). jig bucket 2 · ePIC 2 · formula 3.
    // The second catalog-`Exact` row named by the queue.
    row(65, 2, "A3HB70601"),
    row(65, 2, "A3HB70602"),
    row(65, 2, "A3HB70603"),
    row(65, 2, "A3HB70605"),
    row(65, 2, "A3HB70606"),
    row(65, 2, "A3HB70607"),
];

/// Compact constructor so [`DECLARED_ADDR_INTERVALS`] reads as a table.
const fn row(chips_per_chain: u8, interval: u8, sku: &'static str) -> DeclaredAddrInterval {
    DeclaredAddrInterval {
        sku,
        chips_per_chain,
        interval,
    }
}

/// SKUs whose stride is knowingly UNRESOLVED and therefore left on the fallback.
///
/// `A3HB40601` (36-chip BM1370) is a three-way split: the Bitmain jig bucket
/// says `4`, ePIC says `2`, and [`bm1397plus_addr_interval`] computes `7`. One
/// source is not enough to declare, and inventing a value is forbidden, so it
/// keeps the fallback — the only roster row whose fallback no source
/// corroborates. Do not "fix" it without a second independent source or a live
/// enumeration. No DCENT unit mounts this board.
pub const UNRESOLVED_ADDR_INTERVAL_SKUS: &[&str] = &["A3HB40601"];

/// Look up a per-board declared stride by exact SKU string.
pub fn declared_addr_interval_for_sku(sku: &str) -> Option<u8> {
    DECLARED_ADDR_INTERVALS
        .iter()
        .find(|row| row.sku == sku)
        .map(|row| row.interval)
}

/// Highest chip address a linear ladder emits, or `None` if it does not fit.
///
/// The address-space bound is `(N - 1) * stride ≤ 255`, **not** `N * stride`:
/// the ladder assigns `0, stride, 2·stride, …, (N-1)·stride`, so a 128-chip
/// chain at stride 2 tops out at `254` and is perfectly legal even though
/// `N * stride == 256`. The queue's shorthand `N × stride ≤ 255` would have
/// falsely refused exactly that chain — which the Bitmain jig bucket explicitly
/// admits (`64 < N ≤ 128 → 2`). Pinned by
/// `address_space_gate_uses_last_address_not_n_times_stride`.
pub const fn addr_interval_last_address(chip_count: u8, interval: u8) -> Option<u8> {
    if chip_count == 0 {
        return Some(0);
    }
    let last = (chip_count as u16 - 1) * interval as u16;
    if last > 255 {
        None
    } else {
        Some(last as u8)
    }
}

/// Resolve the chain address stride: **declared board data first, computed
/// `floor(256/N)` fallback second**, then fail closed on an unaddressable plan.
///
/// `sku` is the board's exact Bitmain SKU when known. `None` (or an unknown
/// SKU) is not an error — it takes the fallback, which is the behaviour every
/// caller has today.
///
/// # Errors
///
/// [`AddrIntervalError::AddressSpaceOverflow`] when `(N-1) × stride > 255`, and
/// [`AddrIntervalError::ZeroInterval`] for a zero stride. Both are fail-closed:
/// a caller that cannot compute a valid ladder must refuse to enumerate rather
/// than emit an aliasing one.
pub fn resolve_addr_interval(
    sku: Option<&str>,
    chip_count: u8,
) -> Result<AddrIntervalDecision, AddrIntervalError> {
    let (interval, source) = match sku.and_then(declared_addr_interval_for_sku) {
        Some(declared) => (declared, AddrIntervalSource::BoardDeclared),
        None => (
            bm1397plus_addr_interval(chip_count),
            AddrIntervalSource::ComputedFallback,
        ),
    };
    if interval == 0 {
        return Err(AddrIntervalError::ZeroInterval { chip_count });
    }
    match addr_interval_last_address(chip_count, interval) {
        Some(last_address) => Ok(AddrIntervalDecision {
            interval,
            source,
            last_address,
        }),
        None => Err(AddrIntervalError::AddressSpaceOverflow {
            chip_count,
            interval,
            last_address: (chip_count as u16 - 1) * interval as u16,
        }),
    }
}

/// Plan a full-population SetAddress ladder using [`resolve_addr_interval`].
///
/// Differs from [`plan_bm1397plus_full_population_address_ladder`] only in that
/// it consults the declared-stride table first and **refuses** rather than
/// silently emitting an aliasing ladder. The older function is deliberately
/// left untouched so no wired caller changes behaviour.
pub fn plan_declared_full_population_address_ladder(
    sku: Option<&str>,
    chip_count: u8,
) -> Result<Vec<TransportOp>, AddrIntervalError> {
    let decision = resolve_addr_interval(sku, chip_count)?;
    Ok(plan_bm1397plus_set_address_ladder(
        chip_count,
        decision.interval,
    ))
}

/// Pure BM1397+ address-assign ladder (SetAddress only).
///
/// `addr_interval` is typically [`bm1397plus_addr_interval`] for full-population
/// chains. Does **not** include ChainInactive — callers decide inactive
/// count/timing (often ×3 with 300 ms dwells).
pub fn plan_bm1397plus_set_address_ladder(chip_count: u8, addr_interval: u8) -> Vec<TransportOp> {
    let interval = u16::from(addr_interval.max(1));
    (0..chip_count)
        .map(|i| TransportOp::SendSetAddressBm1397Plus {
            addr: (u16::from(i).saturating_mul(interval)) as u8,
        })
        .collect()
}

/// Plan the full-population address ladder using the canonical 256/N stride.
pub fn plan_bm1397plus_full_population_address_ladder(chip_count: u8) -> Vec<TransportOp> {
    plan_bm1397plus_set_address_ladder(chip_count, bm1397plus_addr_interval(chip_count))
}

/// Pure linear chip addresses: `i * addr_interval` for `i in 0..chip_count`.
///
/// Shared by SetAddress ladders, per-chip core-reset, and per-chip register
/// walks so engines stop re-open-coding index math (P1-1 residual / P1-3 SSOT).
pub fn linear_chip_addresses(chip_count: u8, addr_interval: u8) -> Vec<u8> {
    let interval = u16::from(addr_interval.max(1));
    (0..chip_count)
        .map(|i| (u16::from(i).saturating_mul(interval)) as u8)
        .collect()
}

/// Full-population linear addresses using [`bm1397plus_addr_interval`].
pub fn bm1397plus_full_population_chip_addresses(chip_count: u8) -> Vec<u8> {
    linear_chip_addresses(chip_count, bm1397plus_addr_interval(chip_count))
}

/// Pure ChainInactive × N (BM1397+). Delays between are adapter/engine policy.
pub fn plan_bm1397plus_chain_inactive_burst(count: u8) -> Vec<TransportOp> {
    (0..count)
        .map(|_| TransportOp::SendChainInactiveBm1397Plus)
        .collect()
}

// ---------------------------------------------------------------------------
// Hot-start baud-wake spray (P1-1 residual — multi-baud ChainInactive wake)
// ---------------------------------------------------------------------------

/// Canonical target baud after hot-start recovery (ASIC power-on default).
pub const HOT_START_TARGET_BAUD: u32 = 115_200;

/// Intermediate baud used on Zynq-class hosts when ASICs may still be at
/// 1.5625 Mbaud from a previous session.
pub const HOT_START_ZYNQ_MID_BAUD: u32 = 1_562_500;

/// Amlogic-class fast baud (host cannot produce exact 3.125 Mbaud).
pub const HOT_START_AMLOGIC_FAST_BAUD: u32 = 3_000_000;

/// Zynq-class fast baud (3.125 Mbaud).
pub const HOT_START_ZYNQ_FAST_BAUD: u32 = 3_125_000;

/// MiscCtrl (reg 0x18) value used in the historical hot-start spray to force
/// chips back toward the 115200 baud domain.
///
/// Source: `serial_mining::reset_asic_baud` dual BM1387/BM1397+ broadcast write.
pub const HOT_START_MISC_CTRL_BAUD_RESET: u32 = 0x00C1_00B0;

/// Host UART class for hot-start baud ladder selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HotStartHostClass {
    /// Zynq NS16550-class: can open 3.125M and 1.5625M.
    Zynq,
    /// Amlogic: fast path is B3000000; no 1.5625M intermediate.
    Amlogic,
}

impl HotStartHostClass {
    /// Infer host class from the platform's "fast baud" constant.
    ///
    /// `3_000_000` → Amlogic; anything else (typically 3_125_000) → Zynq.
    pub fn from_fast_baud(fast_baud: u32) -> Self {
        if fast_baud == HOT_START_AMLOGIC_FAST_BAUD {
            Self::Amlogic
        } else {
            Self::Zynq
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zynq => "zynq",
            Self::Amlogic => "amlogic",
        }
    }
}

/// One host-open baud stage in the hot-start wake ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotStartBaudStage {
    pub baud: u32,
    pub label: &'static str,
}

/// Ordered host UART open bauds for hot-start recovery (before final 115200).
///
/// Engines open each baud, execute [`plan_hot_start_baud_wake_ops`], then
/// settle and reopen at [`HOT_START_TARGET_BAUD`]. Does **not** include the
/// final 115200 open (that is the subsequent init path).
pub fn plan_hot_start_baud_wake_ladder(host: HotStartHostClass) -> Vec<HotStartBaudStage> {
    match host {
        HotStartHostClass::Amlogic => vec![HotStartBaudStage {
            baud: HOT_START_AMLOGIC_FAST_BAUD,
            label: "amlogic_fast_3m",
        }],
        HotStartHostClass::Zynq => vec![
            HotStartBaudStage {
                baud: HOT_START_ZYNQ_FAST_BAUD,
                label: "zynq_fast_3125k",
            },
            HotStartBaudStage {
                baud: HOT_START_ZYNQ_MID_BAUD,
                label: "zynq_mid_15625k",
            },
        ],
    }
}

/// Infer ladder from a platform fast-baud constant (matches historical
/// `fast_baud()` branching: Amlogic skips 1.5625M).
pub fn plan_hot_start_baud_wake_ladder_from_fast_baud(fast_baud: u32) -> Vec<HotStartBaudStage> {
    let host = HotStartHostClass::from_fast_baud(fast_baud);
    let mut stages = plan_hot_start_baud_wake_ladder(host);
    // If the platform reports a non-canonical fast baud, still spray that rate first.
    if !matches!(
        fast_baud,
        HOT_START_ZYNQ_FAST_BAUD | HOT_START_AMLOGIC_FAST_BAUD
    ) && fast_baud > 0
    {
        stages.insert(
            0,
            HotStartBaudStage {
                baud: fast_baud,
                label: "platform_fast",
            },
        );
        // Drop duplicate if platform_fast equals an existing stage.
        stages.dedup_by(|a, b| a.baud == b.baud);
    }
    stages
}

/// Pure BM1397+ ops executed **at each open baud** during hot-start wake.
///
/// Sequence (historical `reset_asic_baud` BM1397+ half):
/// 1. ChainInactive (BM1397+)
/// 2. MiscCtrl broadcast reg 0x18 = baud-reset value
/// 3. Short dwell (engine may also sleep after port close)
///
/// # Status
///
/// **PRODUCTION pure policy** for the BM1397+ half of the spray.
/// Full dual-spray (BM1387-form + BM1397+) is [`plan_hot_start_dual_spray_ops`]
/// — a separate type so we never invent BM1387 on the BM1397+ [`TransportOp`] surface.
pub fn plan_hot_start_baud_wake_ops() -> Vec<TransportOp> {
    vec![
        TransportOp::SendChainInactiveBm1397Plus,
        TransportOp::SendWriteRegBroadcastBm1397Plus {
            reg: 0x18,
            value: HOT_START_MISC_CTRL_BAUD_RESET,
        },
        TransportOp::DelayMs {
            ms: HOT_START_SPRAY_DWELL_MS,
        },
    ]
}

/// Pure **hybrid AM2** per-baud wake plan (BM1397+ only — **not** dual-spray).
///
/// Historical hybrid `reset_asic_baud` composition:
/// 1. ChainInactive (BM1397+)
/// 2. MiscCtrl **triple-write** broadcast with selected value
///    ([`am2_misc_ctrl_pre_baud_value`] / engine opt-in — not always
///    [`HOT_START_MISC_CTRL_BAUD_RESET`])
/// 3. DelayMs([`HOT_START_SPRAY_DWELL_MS`])
///
/// Distinct from [`plan_hot_start_baud_wake_ops`] (single MiscCtrl write) and
/// [`plan_hot_start_dual_spray_ops`] (BM1387-form + BM1397+). Do **not** force
/// dual-spray onto hybrid without new live evidence.
///
/// # Status
///
/// **PRODUCTION pure policy** for composition. Value selection is pure
/// [`Am2MiscCtrlPreBaudPolicy`] (G34); engines only choose the policy / opt-in
/// flag and pass the resolved `misc_value`.
pub fn plan_hot_start_hybrid_wake_ops(misc_value: u32) -> Vec<TransportOp> {
    let mut ops = Vec::with_capacity(1 + 6 + 1);
    ops.push(TransportOp::SendChainInactiveBm1397Plus);
    ops.extend(plan_misc_ctrl_triple_write_broadcast(misc_value));
    ops.push(TransportOp::DelayMs {
        ms: HOT_START_SPRAY_DWELL_MS,
    });
    ops
}

// ---------------------------------------------------------------------------
// G34: AM2 MiscCtrl pre-baud **value** pure SSOT (two held constants only)
// ---------------------------------------------------------------------------
//
// Bar: Pure owns the two inspectable AM2 MiscCtrl pre-baud register values —
// `a lab unit`/BM1362_INIT_PLAN default `0xFF0F_C100` and bosminer cold capture
// `0xB000_C100` (RE swarm `wf_b7891b82-31f`). Engines select via the existing
// opt-in flag only; do **not** invent a third value. Cadence remains MiscCtrl
// triple-write SSOT (G1).

/// `a lab unit`-proven / BM1362 AM2 init-plan MiscCtrl pre-baud value (`0xFF0F_C100`).
pub const AM2_MISC_CTRL_PRE_BAUD_DEFAULT_109: u32 = 0xFF0F_C100;

/// Bosminer cold-path MiscCtrl on `a lab unit` / healthy cold-boot capture (`0xB000_C100`).
///
/// Opt-in only (engine env `DCENT_AM2_BM1362_COLD_BROADCAST_BOSMINER`); default
/// path stays [`AM2_MISC_CTRL_PRE_BAUD_DEFAULT_109`].
pub const AM2_MISC_CTRL_PRE_BAUD_BOSMINER_COLD: u32 = 0xB000_C100;

/// Which held AM2 MiscCtrl pre-baud constant to use (no invent third value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Am2MiscCtrlPreBaudPolicy {
    /// Default `a lab unit` / ChipDriver plan (`0xFF0F_C100`).
    Default109,
    /// Bosminer cold capture (`0xB000_C100`) — lab/opt-in only.
    BosminerCold,
}

impl Am2MiscCtrlPreBaudPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default109 => "default_109",
            Self::BosminerCold => "bosminer_cold",
        }
    }
}

/// Pure: resolve MiscCtrl pre-baud register value for a named policy.
#[inline]
pub const fn am2_misc_ctrl_pre_baud_value(policy: Am2MiscCtrlPreBaudPolicy) -> u32 {
    match policy {
        Am2MiscCtrlPreBaudPolicy::Default109 => AM2_MISC_CTRL_PRE_BAUD_DEFAULT_109,
        Am2MiscCtrlPreBaudPolicy::BosminerCold => AM2_MISC_CTRL_PRE_BAUD_BOSMINER_COLD,
    }
}

/// Pure: map the existing bosminer-cold **opt-in flag** to a pre-baud value.
///
/// Engines keep env parsing; pure owns only the two held constants + mapping.
/// `opt_in == false` → Default109; `true` → BosminerCold. No third invent.
#[inline]
pub const fn am2_misc_ctrl_pre_baud_from_bosminer_cold_opt_in(opt_in: bool) -> u32 {
    am2_misc_ctrl_pre_baud_value(if opt_in {
        Am2MiscCtrlPreBaudPolicy::BosminerCold
    } else {
        Am2MiscCtrlPreBaudPolicy::Default109
    })
}

/// Pure: policy enum for the same opt-in flag (for telemetry / logging).
#[inline]
pub const fn am2_misc_ctrl_pre_baud_policy_from_bosminer_cold_opt_in(
    opt_in: bool,
) -> Am2MiscCtrlPreBaudPolicy {
    if opt_in {
        Am2MiscCtrlPreBaudPolicy::BosminerCold
    } else {
        Am2MiscCtrlPreBaudPolicy::Default109
    }
}

/// Command-family identity for hot-start dual-spray.
///
/// Distinct from [`TransportOp`] so the BM1387-form half is not fake-mapped onto
/// the BM1397+ backend trait (different UART command bytes: 0x55/0x58 vs 0x53/0x51).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HotStartCommandFamily {
    /// Legacy BM1387-form chain UART framing (`send_chain_inactive` /
    /// `send_write_reg_broadcast` without the `_bm1397plus` suffix).
    Bm1387Form,
    /// BM1397+ form (`send_*_bm1397plus` / [`TransportOp`] BM1397+ arms).
    Bm1397Plus,
}

impl HotStartCommandFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bm1387Form => "bm1387_form",
            Self::Bm1397Plus => "bm1397plus",
        }
    }
}

/// One pure op in the dual-spray hot-start sequence (both command families).
///
/// Engines execute family-tagged ops on the matching backend method rather than
/// open-coding BM1387-form then BM1397+ sequences ad hoc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotStartSprayOp {
    ChainInactive {
        family: HotStartCommandFamily,
    },
    WriteRegBroadcast {
        family: HotStartCommandFamily,
        reg: u8,
        value: u32,
    },
    DelayMs {
        ms: u32,
    },
}

/// Dwell after each dual-spray stage's command half (ms).
///
/// Matches historical `plan_hot_start_baud_wake_ops` DelayMs(20) and
/// hybrid `SERIAL_PACE_MIN_MS` for the BM1397+ half.
pub const HOT_START_SPRAY_DWELL_MS: u32 = 20;

/// Pure dual-spray plan: BM1387-form wake **then** BM1397+ wake (historical serial).
///
/// Historical `serial_mining::reset_asic_baud` sprays both command families at
/// each open baud so chips stuck in either framing domain recover toward 115200.
///
/// Sequence:
/// 1. ChainInactive (BM1387-form)
/// 2. WriteRegBroadcast reg `0x18` = [`HOT_START_MISC_CTRL_BAUD_RESET`] (BM1387-form)
/// 3. ChainInactive (BM1397+)
/// 4. WriteRegBroadcast reg `0x18` = same value (BM1397+)
/// 5. DelayMs([`HOT_START_SPRAY_DWELL_MS`])
///
/// Honesty: BM1387-form still writes reg **0x18** (not BM1387's native MiscCtrl
/// `0x1C`) — that is the historical universal-wake spray, not a claim that
/// BM1387 MiscCtrl lives at 0x18. Do not "fix" to 0x1C without new RE.
///
/// # Status
///
/// **PRODUCTION pure policy.** Live I/O is engine residual (serial dual-spray
/// wire **EXPERIMENTAL**; hybrid AM2 path uses BM1397+ + MiscCtrl triple-write
/// with a different pre_baud *value* and does **not** dual-spray by default).
pub fn plan_hot_start_dual_spray_ops() -> Vec<HotStartSprayOp> {
    let mut ops = Vec::with_capacity(5);
    // BM1387-form half (optional universal wake; open-coded residual closed here).
    ops.push(HotStartSprayOp::ChainInactive {
        family: HotStartCommandFamily::Bm1387Form,
    });
    ops.push(HotStartSprayOp::WriteRegBroadcast {
        family: HotStartCommandFamily::Bm1387Form,
        reg: MISC_CTRL_REG_BM1397PLUS,
        value: HOT_START_MISC_CTRL_BAUD_RESET,
    });
    // BM1397+ half — compose existing TransportOp SSOT (no forked literals).
    for op in plan_hot_start_baud_wake_ops() {
        match op {
            TransportOp::SendChainInactiveBm1397Plus => {
                ops.push(HotStartSprayOp::ChainInactive {
                    family: HotStartCommandFamily::Bm1397Plus,
                });
            }
            TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value } => {
                ops.push(HotStartSprayOp::WriteRegBroadcast {
                    family: HotStartCommandFamily::Bm1397Plus,
                    reg,
                    value,
                });
            }
            TransportOp::DelayMs { ms } => {
                ops.push(HotStartSprayOp::DelayMs { ms });
            }
            other => {
                // plan_hot_start_baud_wake_ops only emits inactive + miscctrl + delay.
                // Fail closed in debug; ignore unknown arms in release pure plan.
                debug_assert!(
                    false,
                    "unexpected TransportOp in hot-start BM1397+ half: {other:?}"
                );
            }
        }
    }
    ops
}

/// Project dual-spray ops that are BM1397+ into [`TransportOp`] (for recorder tests).
///
/// BM1387-form ops are **dropped** — they have no TransportOp twin. Engines must
/// execute full [`plan_hot_start_dual_spray_ops`] with family dispatch, not this
/// projection alone.
pub fn hot_start_dual_spray_bm1397plus_transport_ops(dual: &[HotStartSprayOp]) -> Vec<TransportOp> {
    let mut out = Vec::new();
    for op in dual {
        match op {
            HotStartSprayOp::ChainInactive {
                family: HotStartCommandFamily::Bm1397Plus,
            } => out.push(TransportOp::SendChainInactiveBm1397Plus),
            HotStartSprayOp::WriteRegBroadcast {
                family: HotStartCommandFamily::Bm1397Plus,
                reg,
                value,
            } => out.push(TransportOp::SendWriteRegBroadcastBm1397Plus {
                reg: *reg,
                value: *value,
            }),
            HotStartSprayOp::DelayMs { ms } => out.push(TransportOp::DelayMs { ms: *ms }),
            HotStartSprayOp::ChainInactive {
                family: HotStartCommandFamily::Bm1387Form,
            }
            | HotStartSprayOp::WriteRegBroadcast {
                family: HotStartCommandFamily::Bm1387Form,
                ..
            } => {
                // Intentionally omitted from BM1397+ TransportOp projection.
            }
        }
    }
    out
}

/// Post-ladder settle delay (ms) before reopening at 115200.
pub const HOT_START_POST_LADDER_SETTLE_MS: u32 = 50;

// ---------------------------------------------------------------------------
// MiscCtrl triple-write (load-bearing UART rule — never fire-and-forget)
// ---------------------------------------------------------------------------

/// BM1397+/BM1362-family MiscCtrl register address on the chip bus.
///
/// BM1387 uses reg [`MISC_CTRL_REG_BM1387`] (`0x1C`) on a different command
/// family — see [`plan_bm1387_misc_ctrl_triple_write_chip`] (pure cadence,
/// **not** [`TransportOp`]).
pub const MISC_CTRL_REG_BM1397PLUS: u8 = 0x18;

/// BM1387 (S9-class) MiscCtrl register on the chip bus.
///
/// Distinct from [`MISC_CTRL_REG_BM1397PLUS`] (`0x18`). Load-bearing: never
/// write BM1387 I2C-off / mining MiscCtrl through the BM1397+ TransportOp
/// surface — packing and command bytes differ (0x58 SETCONFIG-class vs 0x51).
///
/// Source: `drivers/bm1387.rs` regs::MISC_CONTROL; RE bible S9 register map.
pub const MISC_CTRL_REG_BM1387: u8 = 0x1C;

/// BM1387 MiscCtrl value that disables I2C passthrough on chip 0 (mining mode).
///
/// `0x4020_0180` — not_set_baud=1, inv_clock=1, gate_block=0, baud_div=1, mmen=0.
/// Load-bearing for the S9 75-s zero-nonce stall fix: after temp I2C, chip 0
/// must leave I2C mode or the entire chain loses nonce output.
///
/// Source: `feedback` / CLAUDE rust-firmware rule; `baud_switch` BM1387 anchor;
/// `drivers/bm1387::disable_i2c_on_chip0` historical constant.
pub const BM1387_MISC_CTRL_I2C_OFF_MINING: u32 = 0x4020_0180;

/// One pure BM1387-family register write intent (HAL-free).
///
/// Engines pack this via `fifo_cmd_write_reg_full` (or stock equivalent) —
/// **not** via BM1397+ [`TransportOp`] / `Bm1397PlusChainBackend`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bm1387RegWriteIntent {
    pub chip_addr: u8,
    pub reg: u8,
    pub value: u32,
}

/// Pure BM1387 MiscCtrl cadence op (write or inter-write delay).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1387MiscCtrlCadenceOp {
    Write(Bm1387RegWriteIntent),
    DelayMs { ms: u32 },
}

/// Plan a BM1387 MiscCtrl **per-chip** triple-write with 5 ms spacing.
///
/// Cadence constants are shared with BM1397+ ([`MISC_CTRL_TRIPLE_WRITE_COUNT`] /
/// [`MISC_CTRL_TRIPLE_WRITE_SPACING_MS`]) — the rule is universal; the **register
/// address and packing family** are not.
///
/// # Status
///
/// **PRODUCTION pure policy.** Live FIFO packing remains driver residual.
pub fn plan_bm1387_misc_ctrl_triple_write_chip(
    chip_addr: u8,
    value: u32,
) -> Vec<Bm1387MiscCtrlCadenceOp> {
    let mut ops = Vec::with_capacity((MISC_CTRL_TRIPLE_WRITE_COUNT as usize) * 2);
    for _ in 0..MISC_CTRL_TRIPLE_WRITE_COUNT {
        ops.push(Bm1387MiscCtrlCadenceOp::Write(Bm1387RegWriteIntent {
            chip_addr,
            reg: MISC_CTRL_REG_BM1387,
            value,
        }));
        ops.push(Bm1387MiscCtrlCadenceOp::DelayMs {
            ms: MISC_CTRL_TRIPLE_WRITE_SPACING_MS,
        });
    }
    ops
}

/// Plan the load-bearing chip-0 I2C-off MiscCtrl triple-write (S9 safety).
///
/// Value: [`BM1387_MISC_CTRL_I2C_OFF_MINING`]. Chip: `0x00`.
pub fn plan_bm1387_misc_ctrl_i2c_off_chip0() -> Vec<Bm1387MiscCtrlCadenceOp> {
    plan_bm1387_misc_ctrl_triple_write_chip(0x00, BM1387_MISC_CTRL_I2C_OFF_MINING)
}

/// Universal MiscCtrl write repetition count ( /  hard rule).
pub const MISC_CTRL_TRIPLE_WRITE_COUNT: u8 = 3;

/// Spacing between MiscCtrl triple-write attempts (milliseconds).
///
/// Source:  / ChipInitSpec
/// `miscctrl_triple_write` — 5 ms between attempts so the UART state machine
/// can absorb each write (BM1387 CMD readback is impossible; triple-write is
/// the only reliable approach; BM1397+ inherits the same cadence).
pub const MISC_CTRL_TRIPLE_WRITE_SPACING_MS: u32 = 5;

/// Plan a BM1397+ MiscCtrl **broadcast** triple-write with 5 ms spacing.
///
/// Sequence: `(WriteRegBroadcast(reg=0x18, value) + DelayMs(5)) × 3`.
/// Engines must execute this plan rather than open-coding `for i in 0..3`.
///
/// # Status
///
/// **PRODUCTION pure policy.** Live I/O remains engine/HAL residual.
/// Value selection (pre-baud / post-fast / RE018 / env override) is engine
/// policy — this planner only owns the **cadence and register address**.
pub fn plan_misc_ctrl_triple_write_broadcast(value: u32) -> Vec<TransportOp> {
    plan_misc_ctrl_triple_write_broadcast_reg(MISC_CTRL_REG_BM1397PLUS, value)
}

/// Plan a MiscCtrl-class broadcast triple-write to an explicit register.
///
/// Prefer [`plan_misc_ctrl_triple_write_broadcast`] for standard reg `0x18`.
/// Use this only when an engine has RE-confirmed a different MiscCtrl address
/// still on the BM1397+ command surface (not BM1387 `0x1C`).
pub fn plan_misc_ctrl_triple_write_broadcast_reg(reg: u8, value: u32) -> Vec<TransportOp> {
    let mut ops = Vec::with_capacity((MISC_CTRL_TRIPLE_WRITE_COUNT as usize) * 2);
    for _ in 0..MISC_CTRL_TRIPLE_WRITE_COUNT {
        ops.push(TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value });
        ops.push(TransportOp::DelayMs {
            ms: MISC_CTRL_TRIPLE_WRITE_SPACING_MS,
        });
    }
    ops
}

/// Plan a BM1397+ MiscCtrl **per-chip** triple-write with 5 ms spacing.
pub fn plan_misc_ctrl_triple_write_chip(chip_addr: u8, value: u32) -> Vec<TransportOp> {
    plan_misc_ctrl_triple_write_chip_reg(chip_addr, MISC_CTRL_REG_BM1397PLUS, value)
}

/// Plan a per-chip MiscCtrl-class triple-write to an explicit register.
pub fn plan_misc_ctrl_triple_write_chip_reg(
    chip_addr: u8,
    reg: u8,
    value: u32,
) -> Vec<TransportOp> {
    let mut ops = Vec::with_capacity((MISC_CTRL_TRIPLE_WRITE_COUNT as usize) * 2);
    for _ in 0..MISC_CTRL_TRIPLE_WRITE_COUNT {
        ops.push(TransportOp::SendWriteRegBm1397Plus {
            chip_addr,
            reg,
            value,
        });
        ops.push(TransportOp::DelayMs {
            ms: MISC_CTRL_TRIPLE_WRITE_SPACING_MS,
        });
    }
    ops
}

/// Version Rolling register on BM1397+ families (ESP-Miner / ChipDriver SSOT).
pub const VERSION_ROLLING_REG_BM1397PLUS: u8 = 0xA4;

/// High 16 bits of reg `0xA4` (ESP-Miner wire: `{0x90, 0x00, hi, lo}`).
///
/// G28 pure value SSOT: `0x9000_0000 | ((stratum_mask >> 13) & 0xFFFF)`.
pub const VERSION_ROLLING_REG_PREFIX: u32 = 0x9000_0000;

/// Stratum version-mask → versions_to_roll shift (ESP-Miner `mask >> 13`).
pub const VERSION_ROLLING_MASK_SHIFT: u32 = 13;

/// Common BIP-320 / pool mask (bits 13..28) used by BM136x default init.
pub const VERSION_ROLLING_STRATUM_BIP320_MASK: u32 = 0x1FFF_E000;

/// Pure: pack stratum version mask into BM136x reg `0xA4` write value.
///
/// ESP-Miner `BM1366_set_version_mask` / `BM1368` / `BM1370`:
/// `versions_to_roll = version_mask >> 13`, wire `0x90 0x00 | hi | lo`
/// ⇒ register word `0x9000_0000 | (versions_to_roll & 0xFFFF)`.
#[inline]
pub const fn version_rolling_reg_value(stratum_version_mask: u32) -> u32 {
    VERSION_ROLLING_REG_PREFIX | ((stratum_version_mask >> VERSION_ROLLING_MASK_SHIFT) & 0xFFFF)
}

/// Default BIP-320 full-mask reg value (`0x1FFFE000` → `0x9000_FFFF`).
pub const VERSION_ROLLING_REG_BIP320_DEFAULT: u32 =
    version_rolling_reg_value(VERSION_ROLLING_STRATUM_BIP320_MASK);

/// ESP-Miner BM1366 / BM1370 (and DCENT BM1362) init: version-mask **triple** write.
pub const VERSION_ROLLING_TRIPLE_COUNT: u8 = 3;

/// ESP-Miner BM1368 init: version-mask **quad** write (`for i in 0..4`).
pub const VERSION_ROLLING_QUAD_COUNT: u8 = 4;

/// Plan version-rolling (reg [`VERSION_ROLLING_REG_BM1397PLUS`]) broadcast writes.
///
/// `count` is family policy (3 for BM1366/70/62, 4 for BM1368). Optional
/// `spacing_ms` between writes (0 = back-to-back; 5 matches MiscCtrl reliability
/// dwell used by BM1362/BM1366 DCENT paths). Final post-block dwell stays engine
/// residual.
///
/// # Status
///
/// **PRODUCTION pure policy.** Value selection is engine residual.
pub fn plan_version_rolling_broadcast_writes(
    value: u32,
    count: u8,
    spacing_ms: u32,
) -> Vec<TransportOp> {
    if count == 0 {
        return Vec::new();
    }
    let mut ops = Vec::with_capacity(count as usize * 2);
    for i in 0..count {
        ops.push(TransportOp::SendWriteRegBroadcastBm1397Plus {
            reg: VERSION_ROLLING_REG_BM1397PLUS,
            value,
        });
        if spacing_ms > 0 && i + 1 < count {
            ops.push(TransportOp::DelayMs { ms: spacing_ms });
        }
    }
    ops
}

/// BM1362 / BM1366-class version-mask triple-write (5 ms spacing, MiscCtrl twin).
pub fn plan_version_rolling_triple_write_broadcast(value: u32) -> Vec<TransportOp> {
    plan_version_rolling_broadcast_writes(
        value,
        VERSION_ROLLING_TRIPLE_COUNT,
        MISC_CTRL_TRIPLE_WRITE_SPACING_MS,
    )
}

/// ESP-Miner BM1368 version-mask quad-write (no inter-write dwell in C source).
pub fn plan_version_rolling_quad_write_broadcast(value: u32) -> Vec<TransportOp> {
    plan_version_rolling_broadcast_writes(value, VERSION_ROLLING_QUAD_COUNT, 0)
}

/// ESP-Miner / ChipDriver **final** version-mask rewrite count (one write @ 0xA4).
///
/// Matches BM1366 `init795` end-of-init single, BM1368/70 final re-arm, and
/// BM1362 Step-14 belt-and-suspenders. Distinct from init-start triple/quad.
pub const VERSION_ROLLING_SINGLE_COUNT: u8 = 1;

/// Plan a single version-rolling broadcast write (final re-arm / end-of-init).
///
/// Sequence: one `SendWriteRegBroadcastBm1397Plus(reg=0xA4, value)`.
/// Post-write dwell remains engine residual.
pub fn plan_version_rolling_single_write_broadcast(value: u32) -> Vec<TransportOp> {
    plan_version_rolling_broadcast_writes(value, VERSION_ROLLING_SINGLE_COUNT, 0)
}

/// ESP-Miner-faithful MiscCtrl **single** write count (BM1366 / BM1368 / BM1370
/// ChipDriver init). Held ESP-Miner sources send one write per MiscCtrl init
/// step — do **not** force the BM1362 / hybrid triple reliability cadence onto
/// these families without new live evidence.
pub const MISC_CTRL_SINGLE_WRITE_COUNT: u8 = 1;

/// Plan a BM1397+ MiscCtrl **broadcast single write** (ESP-Miner BM1366/68/70).
///
/// Sequence: one `SendWriteRegBroadcastBm1397Plus(reg=0x18, value)` — **no**
/// triple-write spacing. Inter-step dwell after execute remains engine residual
/// (init sequences typically sleep 5–10 ms between steps).
///
/// Distinct from [`plan_misc_ctrl_triple_write_broadcast`] (BM1362 / hybrid
/// reliability) and from [`plan_hot_start_baud_wake_ops`] (inactive + MiscCtrl
/// + dwell composition).
///
/// # Status
///
/// **PRODUCTION pure policy.** Value selection is engine residual.
pub fn plan_misc_ctrl_single_write_broadcast(value: u32) -> Vec<TransportOp> {
    plan_misc_ctrl_single_write_broadcast_reg(MISC_CTRL_REG_BM1397PLUS, value)
}

/// Plan a MiscCtrl-class broadcast single write to an explicit register.
pub fn plan_misc_ctrl_single_write_broadcast_reg(reg: u8, value: u32) -> Vec<TransportOp> {
    vec![TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value }]
}

// ---------------------------------------------------------------------------
// G43: BM1397 fast-UART two-reg pure plan (PLL3 0x68 then FastUART 0x28)
// ---------------------------------------------------------------------------
//
// Bar: jig `set_baud_ext@269A4` / ESP-Miner / bible — write PLL3@0x68 =
// 0xC070_0111 then FastUART@0x28 = 0x0600_000F. Order is load-bearing.
// Do not invent alternate FBDIV (e.g. 0xC066_0011). Live host UART reclock
// after this pair remains EXPERIMENTAL / scope-gated.

/// BM1397 PLL3 Parameter register (baud-clock PLL).
pub const BM1397_PLL3_PARAMETER_REG: u8 = 0x68;

/// BM1397 Fast UART Configuration register.
pub const BM1397_FAST_UART_CONFIG_REG: u8 = 0x28;

/// Jig/ESP-Miner PLL3 word for fast-UART path (FBDIV=0x70 → 2.8 GHz VCO @ 25 MHz).
pub const BM1397_FAST_UART_PLL3_VALUE: u32 = 0xC070_0111;

/// Jig/ESP-Miner Fast UART Config word (PLL3_DIV4=6, flags 0x0F).
pub const BM1397_FAST_UART_CONFIG_VALUE: u32 = 0x0600_000F;

/// Pure: BM1397 fast-UART two-register broadcast plan (0x68 then 0x28).
///
/// **EXPERIMENTAL** live path — pure SSOT for byte values + order only.
/// Host baud reclock after these writes is engine residual (scope-gated).
pub fn plan_bm1397_fast_uart_pll3_then_config() -> Vec<TransportOp> {
    vec![
        TransportOp::SendWriteRegBroadcastBm1397Plus {
            reg: BM1397_PLL3_PARAMETER_REG,
            value: BM1397_FAST_UART_PLL3_VALUE,
        },
        TransportOp::SendWriteRegBroadcastBm1397Plus {
            reg: BM1397_FAST_UART_CONFIG_REG,
            value: BM1397_FAST_UART_CONFIG_VALUE,
        },
    ]
}

/// Pure: same pair for a single chip address (unicast lab path).
pub fn plan_bm1397_fast_uart_pll3_then_config_chip(chip_addr: u8) -> Vec<TransportOp> {
    vec![
        TransportOp::SendWriteRegBm1397Plus {
            chip_addr,
            reg: BM1397_PLL3_PARAMETER_REG,
            value: BM1397_FAST_UART_PLL3_VALUE,
        },
        TransportOp::SendWriteRegBm1397Plus {
            chip_addr,
            reg: BM1397_FAST_UART_CONFIG_REG,
            value: BM1397_FAST_UART_CONFIG_VALUE,
        },
    ]
}

/// Plan a BM1397+ MiscCtrl **per-chip single write** (ESP-Miner BM1366/68/70).
pub fn plan_misc_ctrl_single_write_chip(chip_addr: u8, value: u32) -> Vec<TransportOp> {
    plan_misc_ctrl_single_write_chip_reg(chip_addr, MISC_CTRL_REG_BM1397PLUS, value)
}

/// Plan a per-chip MiscCtrl-class single write to an explicit register.
pub fn plan_misc_ctrl_single_write_chip_reg(
    chip_addr: u8,
    reg: u8,
    value: u32,
) -> Vec<TransportOp> {
    vec![TransportOp::SendWriteRegBm1397Plus {
        chip_addr,
        reg,
        value,
    }]
}

/// Expand a pure init step into transport ops (no I/O).
///
/// SoftReset maps to ChainInactive + delay **only** for BM1397+ command families;
/// BM1387 stock path gets a pure delay (different soft-reset encoding, not invented).
/// Enumerate maps to GetAddress when the protocol speaks BM1397+.
/// AssignAddresses expands to SetChipAddress for each slot.
/// Frequency program expands via [`crate::pll_model::plan_frequency_program_ops`]
/// when the protocol has a pure PLL family (P1-4); otherwise empty (honest).
pub fn init_step_to_transport_ops(
    step: &InitStep,
    protocol: AsicProtocolIdentity,
) -> Vec<TransportOp> {
    let bm1397plus = protocol_speaks_bm1397plus_commands(protocol);
    match step {
        InitStep::DelayMs(ms) => vec![TransportOp::DelayMs { ms: *ms }],
        InitStep::SoftReset if bm1397plus => vec![
            TransportOp::SendChainInactiveBm1397Plus,
            TransportOp::DelayMs { ms: 10 },
        ],
        InitStep::SoftReset => vec![TransportOp::DelayMs { ms: 10 }],
        InitStep::EnumerateAtBaud { baud_label: _ } if bm1397plus => {
            vec![TransportOp::SendGetAddressBm1397Plus]
        }
        InitStep::EnumerateAtBaud { .. } => {
            // BM1387 stock enumeration is FPGA-register-shaped — not BM1397+ GetAddress.
            Vec::new()
        }
        // Full-population stride 256/N (bosminer/stock SSOT) — not a fixed ×4.
        InitStep::AssignAddresses { chip_count: n } if bm1397plus => {
            plan_bm1397plus_full_population_address_ladder(*n)
        }
        InitStep::AssignAddresses { .. } => Vec::new(),
        InitStep::ProgramFrequencyMhz { frequency_mhz } => {
            crate::pll_model::plan_frequency_program_ops(protocol, *frequency_mhz)
        }
    }
}

/// Expand a full pure init program into an ordered transport op list.
pub fn init_program_to_transport_ops(
    program: &InitProgram,
    protocol: AsicProtocolIdentity,
) -> Vec<TransportOp> {
    let mut out = Vec::new();
    for step in &program.steps {
        out.extend(init_step_to_transport_ops(step, protocol));
    }
    out
}

/// Admit protocol×transport then expand + admit every op in the init program.
pub fn plan_admitted_transport_ops(
    protocol: AsicProtocolIdentity,
    transport: ChainTransportKind,
    program: &InitProgram,
) -> Result<(ProtocolTransportAdmission, Vec<TransportOp>), TransportOpError> {
    let admission = admit_protocol_over_transport(protocol, transport)
        .map_err(TransportOpError::ProtocolTransport)?;
    let ops = init_program_to_transport_ops(program, protocol);
    for op in &ops {
        admit_transport_op(admission, op)?;
    }
    Ok((admission, ops))
}

/// Pure chain-transport trait (no HAL). Live HAL backends are the production
/// realization; this trait exists so host tests and future pure engines share
/// one op surface.
pub trait ChainTransport {
    fn transport_kind(&self) -> ChainTransportKind;

    fn transport_label(&self) -> &'static str;

    fn execute_op(&mut self, op: &TransportOp) -> Result<(), TransportOpError>;

    /// Execute an admitted sequence, fail-closed on first refuse.
    fn execute_ops(&mut self, ops: &[TransportOp]) -> Result<(), TransportOpError> {
        for op in ops {
            self.execute_op(op)?;
        }
        Ok(())
    }
}

/// Host-testable recorder: stores ops, never touches hardware.
#[derive(Debug, Clone)]
pub struct RecordingChainTransport {
    kind: ChainTransportKind,
    label: &'static str,
    /// When set, every op is checked against this admission before record.
    admission: Option<ProtocolTransportAdmission>,
    pub recorded: Vec<TransportOp>,
}

impl RecordingChainTransport {
    pub fn new(kind: ChainTransportKind, label: &'static str) -> Self {
        Self {
            kind,
            label,
            admission: None,
            recorded: Vec::new(),
        }
    }

    /// Bind pure protocol×transport admission so execute refuses illegal ops.
    pub fn with_admission(mut self, admission: ProtocolTransportAdmission) -> Self {
        self.admission = Some(admission);
        self
    }

    pub fn clear(&mut self) {
        self.recorded.clear();
    }
}

impl ChainTransport for RecordingChainTransport {
    fn transport_kind(&self) -> ChainTransportKind {
        self.kind
    }

    fn transport_label(&self) -> &'static str {
        self.label
    }

    fn execute_op(&mut self, op: &TransportOp) -> Result<(), TransportOpError> {
        if let Some(admission) = self.admission {
            admit_transport_op(admission, op)?;
        }
        self.recorded.push(op.clone());
        Ok(())
    }
}

/// Structural pin: HAL still owns the live Bm1397+ trait name (not reimplemented here).
#[cfg(test)]
fn hal_chain_backend_source() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    std::fs::read_to_string(root.join("dcentrald-hal/src/chain_backend.rs"))
        .expect("dcentrald-hal chain_backend.rs must exist as live I/O twin")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asic_protocol::{plan_pure_init_program, protocol_capabilities};
    use crate::board_desc::BoardDesc;

    #[test]
    fn backend_class_maps_from_transport_kind() {
        assert_eq!(
            transport_backend_class(ChainTransportKind::FpgaUio),
            TransportBackendClass::FpgaUioFifo
        );
        assert_eq!(
            transport_backend_class(ChainTransportKind::Serial),
            TransportBackendClass::SerialUart
        );
        assert_eq!(
            transport_backend_class(ChainTransportKind::StockFpga),
            TransportBackendClass::StockAxiFpga
        );
        assert_eq!(
            transport_backend_class(ChainTransportKind::None),
            TransportBackendClass::ManagementOnly
        );
        assert!(TransportBackendClass::SerialUart.speaks_bm1397plus_command_surface());
        assert!(!TransportBackendClass::StockAxiFpga.speaks_bm1397plus_command_surface());
        assert!(!TransportBackendClass::ManagementOnly.speaks_bm1397plus_command_surface());
    }

    #[test]
    fn bm1362_serial_admits_get_address_and_records() {
        let admission =
            admit_protocol_over_transport(AsicProtocolIdentity::Bm1362, ChainTransportKind::Serial)
                .expect("bm1362 serial");
        let mut t = RecordingChainTransport::new(ChainTransportKind::Serial, "test-serial")
            .with_admission(admission);
        t.execute_op(&TransportOp::SendGetAddressBm1397Plus)
            .expect("get address");
        t.execute_op(&TransportOp::SendSetAddressBm1397Plus { addr: 0x04 })
            .expect("set addr");
        assert_eq!(t.recorded.len(), 2);
        assert_eq!(t.transport_label(), "test-serial");
    }

    #[test]
    fn bm1387_fpga_refuses_bm1397plus_commands() {
        let admission = admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1387,
            ChainTransportKind::FpgaUio,
        )
        .expect("bm1387 fpga");
        let err =
            admit_transport_op(admission, &TransportOp::SendGetAddressBm1397Plus).unwrap_err();
        assert!(matches!(
            err,
            TransportOpError::Bm1397PlusCommandsNotAdmitted {
                protocol: AsicProtocolIdentity::Bm1387
            }
        ));
        // Delay is always ok (software only).
        assert!(admit_transport_op(admission, &TransportOp::DelayMs { ms: 5 }).is_ok());
    }

    #[test]
    fn stock_fpga_backend_admits_bm1397_work_but_refuses_generic_serial_commands() {
        // The native S17 owner uses stock work FIFO framing. That admission
        // cannot grant the distinct generic BM1397+ serial command surface.
        let admission = admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1397,
            ChainTransportKind::StockFpga,
        )
        .unwrap();
        assert_eq!(
            admit_transport_op(admission, &TransportOp::SendGetAddressBm1397Plus),
            Err(TransportOpError::BackendDoesNotSpeakBm1397Plus {
                backend: TransportBackendClass::StockAxiFpga,
            })
        );
        assert!(!TransportBackendClass::StockAxiFpga.speaks_bm1397plus_command_surface());
    }

    #[test]
    fn empty_work_frame_refused() {
        let admission = admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1362,
            ChainTransportKind::ZynqHybrid,
        )
        .unwrap();
        let err = admit_transport_op(admission, &TransportOp::SendWorkFrame { frame: vec![] })
            .unwrap_err();
        assert_eq!(err, TransportOpError::EmptyWorkFrame);
    }

    #[test]
    fn init_program_expands_to_get_address_and_set_address_ops() {
        let admission =
            admit_protocol_over_transport(AsicProtocolIdentity::Bm1362, ChainTransportKind::Serial)
                .unwrap();
        let program = plan_pure_init_program(admission, 3, 400);
        let (_adm, ops) = plan_admitted_transport_ops(
            AsicProtocolIdentity::Bm1362,
            ChainTransportKind::Serial,
            &program,
        )
        .expect("plan");
        assert!(ops
            .iter()
            .any(|o| matches!(o, TransportOp::SendGetAddressBm1397Plus)));
        assert!(ops
            .iter()
            .any(|o| matches!(o, TransportOp::SendChainInactiveBm1397Plus)));
        let set_addrs: Vec<u8> = ops
            .iter()
            .filter_map(|o| match o {
                TransportOp::SendSetAddressBm1397Plus { addr } => Some(*addr),
                _ => None,
            })
            .collect();
        // 256/3 = 85 full-population stride (not legacy fixed ×4).
        assert_eq!(set_addrs, vec![0, 85, 170]);
        // P1-4: BM1362 ProgramFrequencyMhz expands to pure PLL0@0x08 broadcast.
        let pll_writes: Vec<&TransportOp> = ops
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    TransportOp::SendWriteRegBroadcastBm1397Plus {
                        reg: crate::pll_model::PLL0_PARAMETER_REG,
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(
            pll_writes.len(),
            1,
            "expected one PLL0 broadcast for 400 MHz"
        );
        match pll_writes[0] {
            TransportOp::SendWriteRegBroadcastBm1397Plus { value, .. } => {
                assert_eq!(*value, 0x50A0_0141, "BM1362 400 MHz table entry");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn linear_chip_addresses_match_full_population_ladder_addrs() {
        let addrs = linear_chip_addresses(4, 64);
        assert_eq!(addrs, vec![0, 64, 128, 192]);
        let full = bm1397plus_full_population_chip_addresses(126);
        assert_eq!(full.len(), 126);
        assert_eq!(full[0], 0);
        assert_eq!(full[1], 2);
        assert_eq!(full[125], 250);
        // Ladder SetAddress sequence uses the same addresses.
        let ladder = plan_bm1397plus_full_population_address_ladder(4);
        let from_ladder: Vec<u8> = ladder
            .iter()
            .filter_map(|o| match o {
                TransportOp::SendSetAddressBm1397Plus { addr } => Some(*addr),
                _ => None,
            })
            .collect();
        assert_eq!(from_ladder, bm1397plus_full_population_chip_addresses(4));
    }

    #[test]
    fn bm1387_frequency_program_stays_empty_not_invented() {
        let admission = admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1387,
            ChainTransportKind::FpgaUio,
        )
        .unwrap();
        let program = plan_pure_init_program(admission, 63, 500);
        let (_a, ops) = plan_admitted_transport_ops(
            AsicProtocolIdentity::Bm1387,
            ChainTransportKind::FpgaUio,
            &program,
        )
        .expect("bm1387 plan");
        assert!(
            !ops.iter()
                .any(|o| matches!(o, TransportOp::SendWriteRegBroadcastBm1397Plus { .. })),
            "BM1387 must not invent BM1397+ PLL writes offline"
        );
    }

    #[test]
    fn recording_transport_executes_admitted_init_plan() {
        let admission =
            admit_protocol_over_transport(AsicProtocolIdentity::Bm1362, ChainTransportKind::Serial)
                .unwrap();
        let program = plan_pure_init_program(admission, 2, 0);
        let (_a, ops) = plan_admitted_transport_ops(
            AsicProtocolIdentity::Bm1362,
            ChainTransportKind::Serial,
            &program,
        )
        .unwrap();
        let mut rec = RecordingChainTransport::new(ChainTransportKind::Serial, "rec")
            .with_admission(admission);
        rec.execute_ops(&ops).expect("execute");
        assert_eq!(rec.recorded, ops);
    }

    #[test]
    fn hot_start_baud_wake_ladder_zynq_vs_amlogic() {
        let z = plan_hot_start_baud_wake_ladder(HotStartHostClass::Zynq);
        assert_eq!(
            z.iter().map(|s| s.baud).collect::<Vec<_>>(),
            vec![HOT_START_ZYNQ_FAST_BAUD, HOT_START_ZYNQ_MID_BAUD]
        );
        let a = plan_hot_start_baud_wake_ladder(HotStartHostClass::Amlogic);
        assert_eq!(
            a.iter().map(|s| s.baud).collect::<Vec<_>>(),
            vec![HOT_START_AMLOGIC_FAST_BAUD]
        );
        // Historical fast_baud() branching.
        assert_eq!(
            HotStartHostClass::from_fast_baud(3_000_000),
            HotStartHostClass::Amlogic
        );
        assert_eq!(
            HotStartHostClass::from_fast_baud(3_125_000),
            HotStartHostClass::Zynq
        );
        let from_aml = plan_hot_start_baud_wake_ladder_from_fast_baud(3_000_000);
        assert_eq!(from_aml.len(), 1);
        assert_eq!(from_aml[0].baud, 3_000_000);
        let from_zynq = plan_hot_start_baud_wake_ladder_from_fast_baud(3_125_000);
        assert_eq!(from_zynq.len(), 2);
        assert!(!from_zynq.iter().any(|s| s.baud == HOT_START_TARGET_BAUD));
    }

    #[test]
    fn hot_start_baud_wake_ops_are_inactive_miscctrl_delay() {
        let ops = plan_hot_start_baud_wake_ops();
        assert_eq!(ops.len(), 3);
        assert!(matches!(ops[0], TransportOp::SendChainInactiveBm1397Plus));
        assert!(matches!(
            ops[1],
            TransportOp::SendWriteRegBroadcastBm1397Plus {
                reg: 0x18,
                value: HOT_START_MISC_CTRL_BAUD_RESET,
            }
        ));
        assert!(matches!(ops[2], TransportOp::DelayMs { ms: 20 }));
        // Host-testable on RecordingChainTransport for BM1362 serial.
        let admission =
            admit_protocol_over_transport(AsicProtocolIdentity::Bm1362, ChainTransportKind::Serial)
                .unwrap();
        let mut rec = RecordingChainTransport::new(ChainTransportKind::Serial, "baud-wake")
            .with_admission(admission);
        rec.execute_ops(&ops).expect("execute baud-wake ops");
        assert_eq!(rec.recorded, ops);
    }

    #[test]
    fn hot_start_dual_spray_is_bm1387_form_then_bm1397plus() {
        let dual = plan_hot_start_dual_spray_ops();
        assert_eq!(
            dual.len(),
            5,
            "2 BM1387-form + 3 BM1397+ (inactive/write/delay)"
        );
        assert_eq!(HOT_START_SPRAY_DWELL_MS, 20);
        // BM1387-form half first.
        assert!(matches!(
            dual[0],
            HotStartSprayOp::ChainInactive {
                family: HotStartCommandFamily::Bm1387Form
            }
        ));
        assert!(matches!(
            dual[1],
            HotStartSprayOp::WriteRegBroadcast {
                family: HotStartCommandFamily::Bm1387Form,
                reg: 0x18,
                value: HOT_START_MISC_CTRL_BAUD_RESET,
            }
        ));
        // BM1397+ half composed from plan_hot_start_baud_wake_ops (no forked literals).
        assert!(matches!(
            dual[2],
            HotStartSprayOp::ChainInactive {
                family: HotStartCommandFamily::Bm1397Plus
            }
        ));
        assert!(matches!(
            dual[3],
            HotStartSprayOp::WriteRegBroadcast {
                family: HotStartCommandFamily::Bm1397Plus,
                reg: 0x18,
                value: HOT_START_MISC_CTRL_BAUD_RESET,
            }
        ));
        assert!(matches!(
            dual[4],
            HotStartSprayOp::DelayMs {
                ms: HOT_START_SPRAY_DWELL_MS
            }
        ));
        // Projection of BM1397+ half equals TransportOp SSOT.
        let projected = hot_start_dual_spray_bm1397plus_transport_ops(&dual);
        assert_eq!(projected, plan_hot_start_baud_wake_ops());
        // Honesty: reg stays 0x18 for both families (not invent 0x1C).
        for op in &dual {
            if let HotStartSprayOp::WriteRegBroadcast { reg, .. } = op {
                assert_eq!(*reg, MISC_CTRL_REG_BM1397PLUS);
            }
        }
        // BM1397+ half still host-executable on RecordingChainTransport.
        let admission =
            admit_protocol_over_transport(AsicProtocolIdentity::Bm1362, ChainTransportKind::Serial)
                .unwrap();
        let mut rec =
            RecordingChainTransport::new(ChainTransportKind::Serial, "dual-spray-bm1397plus")
                .with_admission(admission);
        rec.execute_ops(&projected)
            .expect("execute projected BM1397+ half");
        assert_eq!(rec.recorded, projected);
    }

    #[test]
    fn serial_mining_native_bm1366_is_cold_only_not_hot_start_reinit() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/serial_mining.rs"))
            .expect("serial_mining");
        let start = src
            .find("fn init_bm1366_chain(")
            .expect("native BM1366 cold executor");
        let end = src[start..]
            .find("fn init_bm1370_chain(")
            .map(|offset| start + offset)
            .expect("native BM1366 executor boundary");
        let body = &src[start..end];
        assert!(
            body.contains("serial: &ValidatedSerialBackend")
                && body.contains("S19kBm1366NativeExecutionProgram")
                && body.contains("fn init_bm1366_chains("),
            "native BM1366 cold executor must use validated multi-UART typed custody"
        );
        assert!(
            !body.contains("reset_asic_baud(")
                && !body.contains("plan_hot_start")
                && !body.contains("HotStartCommandFamily")
                && !body.contains("SerialChainBackend::open("),
            "native BM1366 cold executor must not retain hot-reinit or raw-UART escape paths"
        );
        let pre_ladder = body
            .find("native_program.pre_baud_commands")
            .expect("exact cold pre-baud ladder");
        assert!(
            !body[..pre_ladder].contains("send_get_address_bm1397plus"),
            "cold BM1366 must not demand assigned-address uniqueness before SetAddress"
        );
    }

    #[test]
    fn bm1387_misc_ctrl_i2c_off_plan_is_triple_write_at_reg_0x1c() {
        assert_eq!(MISC_CTRL_REG_BM1387, 0x1C);
        assert_ne!(MISC_CTRL_REG_BM1387, MISC_CTRL_REG_BM1397PLUS);
        assert_eq!(BM1387_MISC_CTRL_I2C_OFF_MINING, 0x4020_0180);
        let ops = plan_bm1387_misc_ctrl_i2c_off_chip0();
        assert_eq!(ops.len(), 6, "3 writes + 3 delays");
        assert_eq!(MISC_CTRL_TRIPLE_WRITE_COUNT, 3);
        assert_eq!(MISC_CTRL_TRIPLE_WRITE_SPACING_MS, 5);
        let mut writes = 0u8;
        for op in &ops {
            match op {
                Bm1387MiscCtrlCadenceOp::Write(w) => {
                    assert_eq!(w.chip_addr, 0x00);
                    assert_eq!(w.reg, MISC_CTRL_REG_BM1387);
                    assert_eq!(w.value, BM1387_MISC_CTRL_I2C_OFF_MINING);
                    writes += 1;
                }
                Bm1387MiscCtrlCadenceOp::DelayMs { ms } => {
                    assert_eq!(*ms, MISC_CTRL_TRIPLE_WRITE_SPACING_MS);
                }
            }
        }
        assert_eq!(writes, MISC_CTRL_TRIPLE_WRITE_COUNT);
        // Generic planner for other BM1387 MiscCtrl values shares cadence/reg.
        let other = plan_bm1387_misc_ctrl_triple_write_chip(0x04, 0x0020_8180);
        assert_eq!(other.len(), 6);
        if let Bm1387MiscCtrlCadenceOp::Write(w) = other[0] {
            assert_eq!(w.chip_addr, 0x04);
            assert_eq!(w.reg, 0x1C);
            assert_eq!(w.value, 0x0020_8180);
        } else {
            panic!("expected write");
        }
        // Must not be expressible as BM1397+ TransportOp MiscCtrl plan (different reg).
        let bm1397plus = plan_misc_ctrl_triple_write_broadcast(BM1387_MISC_CTRL_I2C_OFF_MINING);
        if let TransportOp::SendWriteRegBroadcastBm1397Plus { reg, .. } = bm1397plus[0] {
            assert_eq!(reg, MISC_CTRL_REG_BM1397PLUS);
            assert_ne!(reg, MISC_CTRL_REG_BM1387);
        }
    }

    /// BM1387 ChipDriver `disable_i2c_on_chip0` must consume pure cadence SSOT
    /// (S9 load-bearing triple-write — never open-code 0..3 + 5 ms alone).
    #[test]
    fn bm1387_disable_i2c_uses_pure_misc_ctrl_plan() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1387.rs"))
            .expect("bm1387 driver");
        let start = src
            .find("fn disable_i2c_on_chip0(")
            .expect("disable_i2c_on_chip0");
        let body: String = src[start..].chars().take(1600).collect();
        assert!(
            body.contains("plan_bm1387_misc_ctrl_i2c_off_chip0"),
            "disable_i2c_on_chip0 must consume pure BM1387 MiscCtrl I2C-off plan"
        );
        assert!(
            body.contains("Bm1387MiscCtrlCadenceOp") || body.contains("Bm1387RegWriteIntent"),
            "disable_i2c_on_chip0 must match pure cadence op arms"
        );
        assert!(
            !body.contains("for _ in 0..3") && !body.contains("for i in 0..3"),
            "disable_i2c_on_chip0 must not open-code 0..3 MiscCtrl loop"
        );
        assert!(
            body.contains("MISC_CTRL_REG_BM1387") || body.contains("0x1C"),
            "driver must pin BM1387 MiscCtrl reg family (0x1C)"
        );
        // Value must come from pure SSOT, not a private 0x4020_0180 only.
        assert!(
            body.contains("BM1387_MISC_CTRL_I2C_OFF_MINING")
                || body.contains("plan_bm1387_misc_ctrl_i2c_off_chip0"),
            "I2C-off value must be pure SSOT"
        );
    }

    /// G28: ESP-Miner version-mask register value pure SSOT + ChipDriver bind.
    #[test]
    fn version_rolling_reg_value_matches_esp_miner_and_drivers() {
        // BIP-320 full mask → 0x9000_FFFF (ESP-Miner BM1366_set_version_mask).
        assert_eq!(
            version_rolling_reg_value(VERSION_ROLLING_STRATUM_BIP320_MASK),
            0x9000_FFFF
        );
        assert_eq!(VERSION_ROLLING_REG_BIP320_DEFAULT, 0x9000_FFFF);
        assert_eq!(
            VERSION_ROLLING_REG_BIP320_DEFAULT,
            version_rolling_reg_value(0x1FFF_E000)
        );
        // Reduced mask: only lowest rolling bit → versions_to_roll = 1.
        assert_eq!(version_rolling_reg_value(1u32 << 13), 0x9000_0001);
        assert_eq!(version_rolling_reg_value(0), 0x9000_0000);
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for rel in [
            "dcentrald-asic/src/drivers/bm1362.rs",
            "dcentrald-asic/src/drivers/bm1366.rs",
            "dcentrald-asic/src/drivers/bm1368.rs",
            "dcentrald-asic/src/drivers/bm1370.rs",
        ] {
            let src = std::fs::read_to_string(root.join(rel)).expect(rel);
            assert!(
                src.contains("VERSION_ROLLING_REG_BIP320_DEFAULT")
                    || src.contains("version_rolling_reg_value"),
                "{rel} must bind pure version_rolling_reg_value / BIP320 default"
            );
        }
    }

    #[test]
    fn version_rolling_plans_match_esp_miner_counts() {
        let value = 0x9000_FFFF;
        let triple = plan_version_rolling_triple_write_broadcast(value);
        assert_eq!(VERSION_ROLLING_TRIPLE_COUNT, 3);
        assert_eq!(VERSION_ROLLING_REG_BM1397PLUS, 0xA4);
        // 3 writes + 2 inter-write delays (spacing only between, not after last).
        assert_eq!(triple.len(), 5);
        // ops: W D W D W
        for i in 0..3 {
            let write_idx = i * 2;
            assert_eq!(
                triple[write_idx],
                TransportOp::SendWriteRegBroadcastBm1397Plus {
                    reg: VERSION_ROLLING_REG_BM1397PLUS,
                    value,
                }
            );
            if i < 2 {
                assert_eq!(
                    triple[write_idx + 1],
                    TransportOp::DelayMs {
                        ms: MISC_CTRL_TRIPLE_WRITE_SPACING_MS
                    }
                );
            }
        }
        let quad = plan_version_rolling_quad_write_broadcast(value);
        assert_eq!(VERSION_ROLLING_QUAD_COUNT, 4);
        assert_eq!(quad.len(), 4, "quad has no inter-write delays");
        assert!(quad.iter().all(|op| matches!(
            op,
            TransportOp::SendWriteRegBroadcastBm1397Plus {
                reg: VERSION_ROLLING_REG_BM1397PLUS,
                ..
            }
        )));
        // G23: final single re-arm (ESP-Miner end-of-init / belt-and-suspenders).
        let single = plan_version_rolling_single_write_broadcast(value);
        assert_eq!(VERSION_ROLLING_SINGLE_COUNT, 1);
        assert_eq!(single.len(), 1);
        assert_eq!(
            single[0],
            TransportOp::SendWriteRegBroadcastBm1397Plus {
                reg: VERSION_ROLLING_REG_BM1397PLUS,
                value,
            }
        );
        assert_ne!(single, triple);
        // Structural: ChipDrivers consume pure plans.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for (rel, needles) in [
            (
                "dcentrald-asic/src/drivers/bm1362.rs",
                &[
                    "plan_version_rolling_triple_write_broadcast",
                    "plan_version_rolling_single_write_broadcast",
                ][..],
            ),
            (
                "dcentrald-asic/src/drivers/bm1366.rs",
                &[
                    "plan_version_rolling_triple_write_broadcast",
                    "plan_version_rolling_single_write_broadcast",
                ][..],
            ),
            (
                "dcentrald-asic/src/drivers/bm1368.rs",
                &[
                    "plan_version_rolling_quad_write_broadcast",
                    "plan_version_rolling_single_write_broadcast",
                ][..],
            ),
            (
                "dcentrald-asic/src/drivers/bm1370.rs",
                &[
                    "plan_version_rolling_broadcast_writes",
                    "plan_version_rolling_single_write_broadcast",
                ][..],
            ),
        ] {
            let src = std::fs::read_to_string(root.join(rel)).expect(rel);
            for needle in needles {
                assert!(
                    src.contains(needle) || src.contains(&format!("dcentrald_common::{needle}")),
                    "{rel} must consume pure version-rolling plan ({needle})"
                );
            }
            // G23 site-semantic: final/single re-arm uses single plan only —
            // no open-coded VERSION write without pure plan, and no multi for-loop
            // around VERSION_ROLLING/VERSION_MASK.
            assert!(
                !src.contains("for _ in 0..3 {\n            Self::write_reg_broadcast(chain, regs::VERSION")
                    && !src.contains("for i in 0..4 {\n            Self::write_reg_broadcast(chain, regs::VERSION")
                    && !src.contains("for _ in 0..3 {\n            Self::write_reg_broadcast(chain, regs::VERSION_MASK")
                    && !src.contains("for i in 0..3 {\n            Self::write_reg_broadcast(chain, regs::VERSION"),
                "{rel} must not open-code multi-write VERSION_ROLLING/VERSION_MASK loops"
            );
            // Every VERSION_ROLLING/VERSION_MASK write_reg_broadcast must be
            // inside pure plan execute (for op in plan_version_rolling_*), not bare.
            // Ban residual bare single writes that bypass pure SSOT.
            for marker in [
                "write_reg_broadcast(chain, regs::VERSION_ROLLING,",
                "write_reg_broadcast(chain, regs::VERSION_MASK,",
            ] {
                if !src.contains(marker) {
                    continue;
                }
                // Allow only as residual if plan_version_rolling is present nearby
                // (all G21/G23 sites use plan + write_reg inside match). Bare form
                // without any plan_version_rolling_* is forbidden.
                assert!(
                    src.contains("plan_version_rolling_"),
                    "{rel} has {marker} but no plan_version_rolling pure consume"
                );
            }
        }
    }

    #[test]
    fn misc_ctrl_single_write_plan_is_one_write_not_triple() {
        let value = 0xFF0F_C100;
        let bcast = plan_misc_ctrl_single_write_broadcast(value);
        assert_eq!(MISC_CTRL_SINGLE_WRITE_COUNT, 1);
        assert_eq!(bcast.len(), 1);
        assert_eq!(
            bcast[0],
            TransportOp::SendWriteRegBroadcastBm1397Plus {
                reg: MISC_CTRL_REG_BM1397PLUS,
                value,
            }
        );
        let chip = plan_misc_ctrl_single_write_chip(0x10, 0xF000_C100);
        assert_eq!(chip.len(), 1);
        assert_eq!(
            chip[0],
            TransportOp::SendWriteRegBm1397Plus {
                chip_addr: 0x10,
                reg: MISC_CTRL_REG_BM1397PLUS,
                value: 0xF000_C100,
            }
        );
        // Honesty: single ≠ triple cadence (do not invent reliability triple).
        let triple = plan_misc_ctrl_triple_write_broadcast(value);
        assert_ne!(bcast, triple);
        assert_eq!(triple.len(), 6);
        // Structural: BM1366/68/70 ChipDrivers consume pure single-write SSOT.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for rel in [
            "dcentrald-asic/src/drivers/bm1366.rs",
            "dcentrald-asic/src/drivers/bm1368.rs",
            "dcentrald-asic/src/drivers/bm1370.rs",
        ] {
            let src = std::fs::read_to_string(root.join(rel)).expect(rel);
            assert!(
                src.contains("plan_misc_ctrl_single_write_broadcast")
                    || src.contains("dcentrald_common::plan_misc_ctrl_single_write_broadcast"),
                "{rel} must consume pure MiscCtrl single-write broadcast"
            );
            assert!(
                src.contains("plan_misc_ctrl_single_write_chip")
                    || src.contains("dcentrald_common::plan_misc_ctrl_single_write_chip"),
                "{rel} must consume pure MiscCtrl single-write per-chip"
            );
            assert!(
                !src.contains("plan_misc_ctrl_triple_write"),
                "{rel} must not force MiscCtrl triple cadence (ESP-Miner single-write)"
            );
        }
    }

    /// G43: BM1397 fast-UART pure plan is 0x68 then 0x28 with jig words only.
    #[test]
    fn g43_bm1397_fast_uart_pll3_then_config_matches_jig() {
        assert_eq!(BM1397_PLL3_PARAMETER_REG, 0x68);
        assert_eq!(BM1397_FAST_UART_CONFIG_REG, 0x28);
        assert_eq!(BM1397_FAST_UART_PLL3_VALUE, 0xC070_0111);
        assert_eq!(BM1397_FAST_UART_CONFIG_VALUE, 0x0600_000F);
        // Refuted invent path must not appear.
        assert_ne!(BM1397_FAST_UART_PLL3_VALUE, 0xC066_0011);

        let ops = plan_bm1397_fast_uart_pll3_then_config();
        assert_eq!(ops.len(), 2);
        assert_eq!(
            ops[0],
            TransportOp::SendWriteRegBroadcastBm1397Plus {
                reg: 0x68,
                value: 0xC070_0111,
            }
        );
        assert_eq!(
            ops[1],
            TransportOp::SendWriteRegBroadcastBm1397Plus {
                reg: 0x28,
                value: 0x0600_000F,
            }
        );
        // Order is load-bearing: 0x68 before 0x28.
        match (&ops[0], &ops[1]) {
            (
                TransportOp::SendWriteRegBroadcastBm1397Plus { reg: r0, .. },
                TransportOp::SendWriteRegBroadcastBm1397Plus { reg: r1, .. },
            ) => {
                assert_eq!(*r0, 0x68);
                assert_eq!(*r1, 0x28);
            }
            _ => panic!("both ops must be broadcast writes"),
        }

        let chip = plan_bm1397_fast_uart_pll3_then_config_chip(0x04);
        assert_eq!(chip.len(), 2);
        assert_eq!(
            chip[0],
            TransportOp::SendWriteRegBm1397Plus {
                chip_addr: 0x04,
                reg: 0x68,
                value: 0xC070_0111,
            }
        );
        assert_eq!(
            chip[1],
            TransportOp::SendWriteRegBm1397Plus {
                chip_addr: 0x04,
                reg: 0x28,
                value: 0x0600_000F,
            }
        );

        // Driver + silicon-profiles thin-wrap pure constants / plan.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let drv = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1397.rs"))
            .expect("bm1397");
        assert!(
            drv.contains("plan_bm1397_fast_uart_pll3_then_config")
                && drv.contains("BM1397_FAST_UART_PLL3_VALUE"),
            "bm1397 driver must execute pure fast-UART plan"
        );
        // Must not open-code the invent FBDIV=0x66 word.
        assert!(
            !drv.contains("0xC066_0011") && !drv.contains("0xC0660011"),
            "must not invent PLL3 FBDIV=0x66 word"
        );
        let prof = std::fs::read_to_string(root.join("dcentrald-silicon-profiles/src/bm1397.rs"))
            .expect("silicon bm1397");
        assert!(
            prof.contains("BM1397_FAST_UART_PLL3_VALUE")
                || prof.contains("dcentrald_common::BM1397_FAST_UART"),
            "silicon-profiles must bind pure fast-UART words"
        );
    }

    #[test]
    fn misc_ctrl_triple_write_plan_is_three_writes_with_five_ms_spacing() {
        let value = HOT_START_MISC_CTRL_BAUD_RESET;
        let ops = plan_misc_ctrl_triple_write_broadcast(value);
        assert_eq!(ops.len(), 6, "3 writes + 3 delays");
        assert_eq!(MISC_CTRL_TRIPLE_WRITE_COUNT, 3);
        assert_eq!(MISC_CTRL_TRIPLE_WRITE_SPACING_MS, 5);
        assert_eq!(MISC_CTRL_REG_BM1397PLUS, 0x18);
        for i in 0..3 {
            assert_eq!(
                ops[i * 2],
                TransportOp::SendWriteRegBroadcastBm1397Plus {
                    reg: MISC_CTRL_REG_BM1397PLUS,
                    value,
                }
            );
            assert_eq!(
                ops[i * 2 + 1],
                TransportOp::DelayMs {
                    ms: MISC_CTRL_TRIPLE_WRITE_SPACING_MS
                }
            );
        }
        // Per-chip plan targets one address.
        let chip = plan_misc_ctrl_triple_write_chip(0x42, value);
        assert_eq!(chip.len(), 6);
        assert_eq!(
            chip[0],
            TransportOp::SendWriteRegBm1397Plus {
                chip_addr: 0x42,
                reg: 0x18,
                value,
            }
        );
        // Recorder executes the plan byte-for-byte.
        let admission =
            admit_protocol_over_transport(AsicProtocolIdentity::Bm1362, ChainTransportKind::Serial)
                .unwrap();
        let mut rec = RecordingChainTransport::new(ChainTransportKind::Serial, "misc-triple")
            .with_admission(admission);
        rec.execute_ops(&ops).expect("execute triple-write plan");
        assert_eq!(rec.recorded, ops);
    }

    #[test]
    fn serial_hybrid_am3bb_misc_ctrl_triple_write_use_pure_plan() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let serial = std::fs::read_to_string(root.join("dcentrald/src/serial_mining.rs"))
            .expect("serial_mining");
        let hybrid = std::fs::read_to_string(root.join("dcentrald/src/s19j_hybrid_mining.rs"))
            .expect("hybrid");
        let am3_bb =
            std::fs::read_to_string(root.join("dcentrald/src/am3_bb_mining.rs")).expect("am3_bb");
        for (label, src, broadcast_fn, chip_fn) in [
            (
                "serial_mining",
                serial.as_str(),
                "fn bm1362_misc_ctrl_triple_write_serial(",
                "fn bm1362_misc_ctrl_triple_write_chip_serial(",
            ),
            (
                "s19j_hybrid_mining",
                hybrid.as_str(),
                "fn misc_ctrl_triple_write_serial(",
                "fn misc_ctrl_triple_write_chip_serial(",
            ),
            (
                "am3_bb_mining",
                am3_bb.as_str(),
                "fn bm1362_miscctrl_triple_write_bcast(",
                "fn bm1362_miscctrl_triple_write_single(",
            ),
        ] {
            let b_start = src.find(broadcast_fn).unwrap_or_else(|| {
                panic!("{label} missing {broadcast_fn}");
            });
            // Char-safe slice: hybrid source contains multi-byte mojibake.
            let b_body: String = src[b_start..].chars().take(1200).collect();
            assert!(
                b_body.contains("plan_misc_ctrl_triple_write_broadcast"),
                "{label} broadcast MiscCtrl triple-write must consume pure plan"
            );
            assert!(
                !b_body.contains("for i in 0..3") && !b_body.contains("for _ in 0..3"),
                "{label} must not open-code 0..3 MiscCtrl loop (use pure plan)"
            );
            let c_start = src.find(chip_fn).unwrap_or_else(|| {
                panic!("{label} missing {chip_fn}");
            });
            let c_body: String = src[c_start..].chars().take(1200).collect();
            assert!(
                c_body.contains("plan_misc_ctrl_triple_write_chip"),
                "{label} chip MiscCtrl triple-write must consume pure plan"
            );
            assert!(
                !c_body.contains("for i in 0..3") && !c_body.contains("for _ in 0..3"),
                "{label} chip helper must not open-code 0..3 MiscCtrl loop"
            );
        }
        // Post-FastUART path must call the pure-wired bcast helper (not open-code 0..3).
        let post = am3_bb
            .find("MiscCtrl(0x18) post-fast-uart-reg")
            .expect("am3_bb post-fast MiscCtrl label");
        let post_window: String = am3_bb[post.saturating_sub(400)..]
            .chars()
            .take(600)
            .collect();
        assert!(
            post_window.contains("bm1362_miscctrl_triple_write_bcast"),
            "am3_bb post-FastUART MiscCtrl must use pure-wired bcast helper"
        );
        assert!(
            !post_window.contains("for _ in 0..3") && !post_window.contains("for i in 0..3"),
            "am3_bb post-FastUART must not open-code MiscCtrl 0..3"
        );
        // ChipDriver BM1362 (FPGA path) also consumes pure cadence SSOT.
        let asic_bm1362 =
            std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1362.rs"))
                .expect("bm1362 driver");
        let d_start = asic_bm1362
            .find("fn misc_ctrl_triple_write(")
            .expect("bm1362 misc_ctrl_triple_write");
        let d_body: String = asic_bm1362[d_start..].chars().take(1200).collect();
        assert!(
            d_body.contains("plan_misc_ctrl_triple_write_broadcast"),
            "bm1362 ChipDriver MiscCtrl triple-write must consume pure plan"
        );
        assert!(
            !d_body.contains("for i in 0..3"),
            "bm1362 ChipDriver must not open-code 0..3 MiscCtrl loop"
        );
    }

    /// Engines **and** ASIC ChipDriver bring-up must not open-code
    /// `256 / chip_count` for BM1397+ address stride when pure
    /// `bm1397plus_addr_interval` is the SSOT (P1-3 residual closed 2026-07-29).
    #[test]
    fn engines_use_pure_addr_interval_not_open_coded_256_div() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for rel in [
            "dcentrald/src/serial_mining.rs",
            "dcentrald/src/s19j_hybrid_mining.rs",
            "dcentrald/src/am3_bb_mining.rs",
            "dcentrald/src/work_dispatcher.rs",
            "dcentrald-asic/src/drivers/bm1362.rs",
            "dcentrald-asic/src/drivers/bm1366.rs",
            "dcentrald-asic/src/drivers/bm1368.rs",
            "dcentrald-asic/src/drivers/bm1370.rs",
        ] {
            let src = std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| {
                panic!("read {rel}: {e}");
            });
            // Allow pure helper definition comments and tests; ban live arithmetic forks.
            let open_coded = src.matches("256u16 /").count()
                + src.matches("256u16/").count()
                + src.matches("(256u16 /").count();
            let pure_uses = src.matches("bm1397plus_addr_interval").count();
            // serial_mining may still document 256/chip in comments near serial_address_interval.
            // Ban the live pattern used by the old BM1398 fork and driver ChipDriver paths.
            assert!(
                !src.contains("256u16 / (chip_count as u16)")
                    && !src.contains("256u16 / chip_count as u16")
                    && !src.contains("256u16 / chain_chip_count as u16")
                    && !src.contains("256u16 / n_assign as u16")
                    && !src.contains("256 / chip_count as u16")
                    && !src.contains("256u16 / DEFAULT_CHIPS_PER_CHAIN"),
                "{rel} must not open-code 256/chip_count address stride (use bm1397plus_addr_interval)"
            );
            if rel.contains("serial_mining")
                || rel.contains("hybrid")
                || rel.contains("am3_bb")
                || rel.contains("drivers/bm")
            {
                assert!(
                    pure_uses >= 1,
                    "{rel} must call bm1397plus_addr_interval (found {pure_uses}; open_coded_scan={open_coded})"
                );
            }
            if rel.contains("work_dispatcher") {
                assert!(
                    pure_uses >= 1,
                    "work_dispatcher must call bm1397plus_addr_interval for per-chip PLL addressing"
                );
            }
        }
        // BM1398 init must use SerialBringUpPlugin / pure ladder, not open-coded set_address loop.
        let serial = std::fs::read_to_string(root.join("dcentrald/src/serial_mining.rs"))
            .expect("serial_mining");
        let bm1398 = serial
            .find("fn init_bm1398_chain(")
            .map(|i| &serial[i..i.saturating_add(3500)])
            .expect("init_bm1398_chain");
        assert!(
            bm1398.contains("plan_serial_bring_up")
                && bm1398.contains("SerialBm1398")
                && bm1398.contains("address_ladder"),
            "init_bm1398_chain must use SerialBringUpPlugin address_ladder"
        );
    }

    #[test]
    fn hot_start_hybrid_wake_ops_is_inactive_misc_triple_delay() {
        let value = 0xFF0F_C100;
        let ops = plan_hot_start_hybrid_wake_ops(value);
        // 1 inactive + (3 write + 3 delay) + 1 final delay = 8
        assert_eq!(ops.len(), 8);
        assert!(matches!(ops[0], TransportOp::SendChainInactiveBm1397Plus));
        let triple = plan_misc_ctrl_triple_write_broadcast(value);
        assert_eq!(&ops[1..7], triple.as_slice());
        assert!(matches!(
            ops[7],
            TransportOp::DelayMs {
                ms: HOT_START_SPRAY_DWELL_MS
            }
        ));
        // Distinct from single-write baud-wake and dual-spray.
        assert_ne!(ops, plan_hot_start_baud_wake_ops());
        assert_eq!(
            hot_start_dual_spray_bm1397plus_transport_ops(&plan_hot_start_dual_spray_ops()),
            plan_hot_start_baud_wake_ops()
        );
        let admission =
            admit_protocol_over_transport(AsicProtocolIdentity::Bm1362, ChainTransportKind::Serial)
                .unwrap();
        let mut rec = RecordingChainTransport::new(ChainTransportKind::Serial, "hybrid-wake")
            .with_admission(admission);
        rec.execute_ops(&ops).expect("execute hybrid wake");
        assert_eq!(rec.recorded, ops);
    }

    /// G34: AM2 MiscCtrl pre-baud value pure SSOT — two held constants only.
    #[test]
    fn g34_am2_misc_ctrl_pre_baud_value_ssot() {
        assert_eq!(AM2_MISC_CTRL_PRE_BAUD_DEFAULT_109, 0xFF0F_C100);
        assert_eq!(AM2_MISC_CTRL_PRE_BAUD_BOSMINER_COLD, 0xB000_C100);
        assert_ne!(
            AM2_MISC_CTRL_PRE_BAUD_DEFAULT_109,
            AM2_MISC_CTRL_PRE_BAUD_BOSMINER_COLD
        );
        // Not the post-fast HOT_START value (different residual).
        assert_ne!(
            AM2_MISC_CTRL_PRE_BAUD_DEFAULT_109,
            HOT_START_MISC_CTRL_BAUD_RESET
        );
        assert_ne!(
            AM2_MISC_CTRL_PRE_BAUD_BOSMINER_COLD,
            HOT_START_MISC_CTRL_BAUD_RESET
        );

        assert_eq!(
            am2_misc_ctrl_pre_baud_value(Am2MiscCtrlPreBaudPolicy::Default109),
            0xFF0F_C100
        );
        assert_eq!(
            am2_misc_ctrl_pre_baud_value(Am2MiscCtrlPreBaudPolicy::BosminerCold),
            0xB000_C100
        );
        assert_eq!(
            am2_misc_ctrl_pre_baud_from_bosminer_cold_opt_in(false),
            0xFF0F_C100
        );
        assert_eq!(
            am2_misc_ctrl_pre_baud_from_bosminer_cold_opt_in(true),
            0xB000_C100
        );
        assert_eq!(
            am2_misc_ctrl_pre_baud_policy_from_bosminer_cold_opt_in(false),
            Am2MiscCtrlPreBaudPolicy::Default109
        );
        assert_eq!(
            am2_misc_ctrl_pre_baud_policy_from_bosminer_cold_opt_in(true),
            Am2MiscCtrlPreBaudPolicy::BosminerCold
        );

        // Hybrid wake plan still accepts the pure-resolved value.
        let ops =
            plan_hot_start_hybrid_wake_ops(am2_misc_ctrl_pre_baud_from_bosminer_cold_opt_in(false));
        assert!(ops.iter().any(|op| matches!(
            op,
            TransportOp::SendWriteRegBroadcastBm1397Plus {
                reg: 0x18,
                value: 0xFF0F_C100
            }
        )));
        let ops_b =
            plan_hot_start_hybrid_wake_ops(am2_misc_ctrl_pre_baud_from_bosminer_cold_opt_in(true));
        assert!(ops_b.iter().any(|op| matches!(
            op,
            TransportOp::SendWriteRegBroadcastBm1397Plus {
                reg: 0x18,
                value: 0xB000_C100
            }
        )));

        // ChipDriver BM1362 plan pre_baud binds pure Default109.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let bm1362 = std::fs::read_to_string(root.join("dcentrald-asic/src/drivers/bm1362.rs"))
            .expect("bm1362");
        assert!(
            bm1362.contains("AM2_MISC_CTRL_PRE_BAUD_DEFAULT_109"),
            "BM1362_INIT_PLAN.misc_control_pre_baud must bind pure Default109"
        );
        // Hybrid thin-wrap pure opt-in mapper (not open-coded if/else constants only).
        let hybrid = std::fs::read_to_string(root.join("dcentrald/src/s19j_hybrid_mining.rs"))
            .expect("hybrid");
        let start = hybrid
            .find("fn am2_misc_control_pre_baud(")
            .expect("am2_misc_control_pre_baud");
        let body: String = hybrid[start..].chars().take(400).collect();
        assert!(
            body.contains("am2_misc_ctrl_pre_baud_from_bosminer_cold_opt_in"),
            "hybrid am2_misc_control_pre_baud must thin-wrap pure G34 mapper"
        );
        // No third invent literal in the helper body.
        assert!(
            !body.contains("0x")
                || body.contains("am2_misc_ctrl_pre_baud_from_bosminer_cold_opt_in"),
            "hybrid helper body must not invent a third pre_baud literal"
        );
    }

    #[test]
    fn hybrid_reset_asic_baud_uses_pure_hot_start_ladder() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/s19j_hybrid_mining.rs"))
            .expect("hybrid");
        let start = src
            .find("fn reset_asic_baud(")
            .expect("hybrid reset_asic_baud");
        let body: String = src[start..].chars().take(2500).collect();
        assert!(
            body.contains("plan_hot_start_baud_wake_ladder")
                || body.contains("plan_hot_start_baud_wake_ladder_from_fast_baud"),
            "hybrid reset_asic_baud must use pure baud-wake ladder SSOT"
        );
        assert!(
            body.contains("HotStartHostClass::Zynq")
                || body.contains("plan_hot_start_baud_wake_ladder_from_fast_baud"),
            "hybrid AM2 path must select Zynq pure ladder (or from_fast_baud)"
        );
        assert!(
            body.contains("plan_hot_start_hybrid_wake_ops"),
            "hybrid must execute pure hybrid wake plan (inactive + MiscCtrl triple + delay)"
        );
        assert!(
            body.contains("am2_misc_control_pre_baud"),
            "hybrid must still resolve MiscCtrl value via am2_misc_control_pre_baud"
        );
        assert!(
            !body.contains("plan_hot_start_dual_spray_ops"),
            "hybrid must not dual-spray (serial-only path)"
        );
        assert!(
            !body.contains("1_562_500"),
            "hybrid must not open-code 1_562_500; pure ladder owns mid baud"
        );
        // Must not open-code composition as bare inactive + triple helper without pure plan.
        assert!(
            body.contains("hybrid_execute_bm1397plus_op") || body.contains("execute_transport_op"),
            "hybrid wake ops must execute via TransportOp path"
        );
    }

    #[test]
    fn s19j_board_desc_plans_serial_bm1397plus_ops() {
        let board = BoardDesc::lookup("am2-s19j").expect("am2-s19j");
        let admission = board.admit_protocol_transport().expect("protocol admit");
        assert!(protocol_speaks_bm1397plus_commands(admission.protocol()));
        assert!(protocol_capabilities(admission.protocol()).get_address_enumerate);
        let program = plan_pure_init_program(admission, 63, 500);
        let (_a, ops) =
            plan_admitted_transport_ops(board.asic_protocol, board.chain_transport, &program)
                .expect("s19j plan");
        assert!(!ops.is_empty());
    }

    #[test]
    fn s9_bm1387_init_program_emits_only_delays_not_bm1397plus_commands() {
        // S9 uses stock/FPGA BM1387 path — pure expansion must not invent
        // BM1397+ GetAddress/SetAddress commands offline.
        let admission = admit_protocol_over_transport(
            AsicProtocolIdentity::Bm1387,
            ChainTransportKind::FpgaUio,
        )
        .unwrap();
        let program = plan_pure_init_program(admission, 63, 500);
        let (_a, ops) = plan_admitted_transport_ops(
            AsicProtocolIdentity::Bm1387,
            ChainTransportKind::FpgaUio,
            &program,
        )
        .expect("bm1387 plan is delay-only ops");
        assert!(ops.iter().all(|o| matches!(o, TransportOp::DelayMs { .. })));
        assert!(!ops.iter().any(|o| o.is_bm1397plus_command()));
    }

    #[test]
    fn live_hal_bm1397plus_backend_remains_the_io_twin() {
        let src = hal_chain_backend_source();
        assert!(
            src.contains("pub trait Bm1397PlusChainBackend"),
            "HAL must keep Bm1397PlusChainBackend as live I/O twin of TransportOp"
        );
        for needle in [
            "fn set_baud_rate",
            "fn send_get_address_bm1397plus",
            "fn send_chain_inactive_bm1397plus",
            "fn send_set_address_bm1397plus",
            "fn send_write_reg_broadcast_bm1397plus",
            "fn send_work_frame",
            "fn read_response_frame",
            "fn transport_label",
        ] {
            assert!(
                src.contains(needle),
                "HAL Bm1397PlusChainBackend must expose {needle}"
            );
        }
    }

    #[test]
    fn hybrid_all_bm1397plus_commands_wire_execute_transport_ops() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/s19j_hybrid_mining.rs"))
            .expect("s19j_hybrid_mining.rs");
        for façade in [
            "fn hybrid_execute_bm1397plus_op",
            "fn hybrid_send_get_address",
            "fn hybrid_send_chain_inactive",
            "fn hybrid_send_set_address",
            "fn hybrid_send_write_reg_broadcast",
            "fn hybrid_send_write_reg",
            "fn hybrid_send_read_reg",
            "execute_transport_op_bm1397plus",
        ] {
            assert!(src.contains(façade), "hybrid must ship {façade}");
        }
        // No residual direct inherent BM1397+ method calls on SerialChainBackend
        // (comments may still name the methods).
        for method in [
            ".send_get_address_bm1397plus(",
            ".send_chain_inactive_bm1397plus(",
            ".send_set_address_bm1397plus(",
            ".send_write_reg_broadcast_bm1397plus(",
            ".send_write_reg_bm1397plus(",
            ".send_read_reg_bm1397plus(",
        ] {
            assert!(
                !src.contains(method),
                "hybrid residual direct backend call must be gone: {method}"
            );
        }
        // Call sites must use façades / pure planner execute (not only define them).
        assert!(src.matches("hybrid_send_write_reg_broadcast(").count() > 10);
        // ChainInactive/SetAddress may use hybrid_send_* or planner + hybrid_execute_*.
        let inactive_sites = src.matches("hybrid_send_chain_inactive(").count()
            + src.matches("plan_bm1397plus_chain_inactive_burst").count();
        assert!(
            inactive_sites >= 2,
            "hybrid must still drive ChainInactive via façade or pure planner"
        );
        let setaddr_sites = src.matches("hybrid_send_set_address(").count()
            + src.matches("plan_bm1397plus_set_address_ladder").count();
        assert!(
            setaddr_sites >= 2,
            "hybrid must still drive SetAddress via façade or pure planner"
        );
        assert!(src.contains("hybrid_send_get_address("));
        assert!(src.contains("hybrid_send_read_reg("));
        assert!(
            src.contains("hybrid_execute_bm1397plus_op(serial, op)"),
            "hybrid batch planner wire must execute planned ops via hybrid_execute_bm1397plus_op"
        );
    }

    #[test]
    fn serial_mining_validated_backend_wires_execute_transport_ops() {
        // Engine wire residual close: ValidatedSerialBackend BM1397+ commands
        // go through pure TransportOp + HAL execute adapter.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/serial_mining.rs"))
            .expect("serial_mining.rs");
        assert!(
            src.contains("fn execute_bm1397plus_op"),
            "serial ValidatedSerialBackend must own execute_bm1397plus_op façade"
        );
        assert!(
            src.contains("execute_transport_op_bm1397plus"),
            "serial must call HAL execute_transport_op_bm1397plus"
        );
        assert!(
            src.contains("TransportOp::SendGetAddressBm1397Plus"),
            "serial GetAddress must be pure TransportOp"
        );
        assert!(
            src.contains("TransportOp::SendChainInactiveBm1397Plus"),
            "serial ChainInactive must be pure TransportOp"
        );
        assert!(
            src.contains("TransportOp::SendSetAddressBm1397Plus"),
            "serial SetAddress must be pure TransportOp"
        );
        assert!(
            src.contains("TransportOp::SendWriteRegBroadcastBm1397Plus"),
            "serial broadcast write must be pure TransportOp"
        );
        assert!(
            src.contains("TransportOp::SendWriteRegBm1397Plus"),
            "serial addressed write must be pure TransportOp"
        );
        // Ensure the old direct backend call is no longer the primary path
        // for GetAddress inside ValidatedSerialBackend (must go via execute).
        let facade = src.find("fn execute_bm1397plus_op").expect("facade");
        let get_addr_method = src[facade..]
            .find("fn send_get_address_bm1397plus")
            .map(|i| facade + i)
            .expect("get address method after façade");
        let get_body_end = src[get_addr_method..]
            .find("fn send_chain_inactive_bm1397plus")
            .map(|i| get_addr_method + i)
            .expect("next method");
        let get_body = &src[get_addr_method..get_body_end];
        assert!(
            get_body.contains("execute_bm1397plus_op")
                && get_body.contains("TransportOp::SendGetAddressBm1397Plus"),
            "GetAddress method body must route through execute_bm1397plus_op"
        );
        assert!(
            !get_body.contains("self.backend\n                .send_get_address_bm1397plus()"),
            "GetAddress must not call backend method directly"
        );
    }

    #[test]
    fn address_ladder_and_inactive_burst_are_pure() {
        assert_eq!(bm1397plus_addr_interval(126), 2);
        assert_eq!(bm1397plus_addr_interval(64), 4);
        assert_eq!(bm1397plus_addr_interval(0), 1); // empty → one-chip rule
        assert_eq!(bm1397plus_addr_interval(1), 1); // not wrap-to-0
        let ladder = plan_bm1397plus_set_address_ladder(4, 64);
        assert_eq!(
            ladder,
            vec![
                TransportOp::SendSetAddressBm1397Plus { addr: 0 },
                TransportOp::SendSetAddressBm1397Plus { addr: 64 },
                TransportOp::SendSetAddressBm1397Plus { addr: 128 },
                TransportOp::SendSetAddressBm1397Plus { addr: 192 },
            ]
        );
        let full = plan_bm1397plus_full_population_address_ladder(126);
        assert_eq!(full.len(), 126);
        assert_eq!(
            full.first(),
            Some(&TransportOp::SendSetAddressBm1397Plus { addr: 0 })
        );
        assert_eq!(
            full.last(),
            Some(&TransportOp::SendSetAddressBm1397Plus { addr: 250 }) // 125*2
        );
        let burst = plan_bm1397plus_chain_inactive_burst(3);
        assert_eq!(burst.len(), 3);
        assert!(burst
            .iter()
            .all(|o| matches!(o, TransportOp::SendChainInactiveBm1397Plus)));
    }

    #[test]
    fn serial_and_hybrid_engines_consume_pure_address_planners() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let serial = std::fs::read_to_string(root.join("dcentrald/src/serial_mining.rs"))
            .expect("serial_mining.rs");
        let hybrid = std::fs::read_to_string(root.join("dcentrald/src/s19j_hybrid_mining.rs"))
            .expect("hybrid");
        for (name, src) in [("serial", serial.as_str()), ("hybrid", hybrid.as_str())] {
            // Prefer SerialBringUpPlugin plan phases; raw planners remain valid residual sites.
            let uses_bring_up = src.contains("plan_serial_bring_up") && src.contains(".phases()");
            let uses_raw = src.contains("plan_bm1397plus_chain_inactive_burst")
                && src.contains("plan_bm1397plus_set_address_ladder");
            assert!(
                uses_bring_up || uses_raw,
                "{name} must consume pure bring-up plan phases or inactive/ladder planners"
            );
        }
        assert!(
            serial.contains("bm1397plus_addr_interval"),
            "serial BM1362 path must use pure addr_interval SSOT"
        );
        assert!(
            hybrid.contains("bm1397plus_addr_interval"),
            "hybrid must use pure addr_interval SSOT"
        );
        // Open-coded 256/chip_count must not remain as the primary SSOT in wired paths.
        // (Other residual sites may still exist; these are the bring-up enumeration steps.)
        assert!(
            serial.contains("let addr_interval = bm1397plus_addr_interval(chip_count)"),
            "serial BM1362 step-3 must assign addr_interval from pure helper"
        );
        assert!(
            hybrid.contains("u16::from(bm1397plus_addr_interval(chip_count))"),
            "hybrid init/RE018 must assign addr_interval from pure helper"
        );
    }

    /// One-chip pure interval is 1 (LinearAddressPlan / serial repair fixtures),
    /// never wrap-to-0 and never the old 255 clamp.
    #[test]
    fn one_chip_addr_interval_matches_linear_plan_rule() {
        assert_eq!(bm1397plus_addr_interval(1), 1);
        assert_eq!(bm1397plus_full_population_chip_addresses(1), vec![0]);
        // Multi-chip production pins unchanged.
        assert_eq!(bm1397plus_addr_interval(126), 2);
        assert_eq!(bm1397plus_addr_interval(108), 2);
        assert_eq!(bm1397plus_addr_interval(77), 3);
    }

    #[test]
    fn live_hal_ships_transport_op_execute_adapter() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald-hal/src/transport_op_execute.rs"))
            .expect("transport_op_execute.rs");
        assert!(src.contains("fn execute_transport_op_bm1397plus"));
        assert!(src.contains("fn execute_transport_ops_bm1397plus"));
        assert!(src.contains("RecordingBm1397PlusBackendShared"));
        // Every pure TransportOp arm must reach the live backend (or sleep).
        for needle in [
            "TransportOp::SetBaudRate",
            "TransportOp::SetResponseBodyLen",
            "TransportOp::SendGetAddressBm1397Plus",
            "TransportOp::SendChainInactiveBm1397Plus",
            "TransportOp::SendSetAddressBm1397Plus",
            "TransportOp::SendWriteRegBroadcastBm1397Plus",
            "TransportOp::SendWriteRegBm1397Plus",
            "TransportOp::SendReadRegBm1397Plus",
            "TransportOp::SendWorkFrame",
            "TransportOp::DelayMs",
            "backend.set_baud_rate",
            "backend.send_get_address_bm1397plus",
            "backend.send_chain_inactive_bm1397plus",
            "backend.send_set_address_bm1397plus",
            "backend.send_write_reg_broadcast_bm1397plus",
            "backend.send_write_reg_bm1397plus",
            "backend.send_read_reg_bm1397plus",
            "backend.send_work_frame",
            "std::thread::sleep",
            "EmptyWorkFrame",
        ] {
            assert!(
                src.contains(needle),
                "HAL execute adapter must cover {needle}"
            );
        }
        // Mock-backend unit tests ship with the adapter (Linux CI; Windows HAL
        // cannot link — host proof is this structural pin + pure op suite).
        assert!(src.contains("fn executes_admitted_init_plan_for_bm1362_serial"));
        assert!(src.contains("fn empty_work_frame_refused_before_backend"));
        let lib = std::fs::read_to_string(root.join("dcentrald-hal/src/lib.rs")).expect("lib");
        assert!(
            lib.contains("pub mod transport_op_execute"),
            "HAL lib must export transport_op_execute"
        );
    }
}
