//! Stock Bitmain FPGA mining path.
//!
//! This module provides the experimental S9 mining pipeline for stock Bitmain
//! firmware (kernel 3.14.0-xilinx with bitmain_axi.ko +
//! fpga_mem_driver.ko). It replaces the BraiinsOS-specific UIO/FIFO approach
//! with direct mmap access to the stock FPGA register block. Because the
//! autonomous FPGA nonce2/job-id correlation schema cannot be verified
//! offline, runtime entry is fail-closed unless the explicit
//! `DCENT_EXPERIMENTAL_STOCK_FPGA_NONCE2` beta gate is enabled.
//!
//! Architecture differences from the BraiinsOS path (daemon.rs):
//!
//!   - **FPGA registers**: Single flat 352-byte block at 0x43C00000 via
//!     /dev/axi_fpga_dev, vs per-chain 4KB UIO blocks.
//!   - **PIC I2C**: Via FPGA IIC_COMMAND register (0x030), vs kernel
//!     /dev/i2c-0 or AXI IIC devmem.
//!   - **Work dispatch**: DHASH accelerator + DMA double-buffer, vs
//!     per-chain WORK_TX_FIFO.
//!   - **Nonce collection**: Shared RETURN_NONCE FIFO (0x010), vs
//!     per-chain WORK_RX_FIFO.
//!   - **Board detect**: FPGA HASH_ON_PLUG register (0x008), vs sysfs GPIO.
//!   - **Fan control**: FPGA FAN_CONTROL register (0x084), vs UIO fan IP.
//!   - **ASIC commands**: BC_WRITE_COMMAND register (0x0C0), vs per-chain
//!     CMD TX/RX FIFOs.
//!
//! The ASIC init sequence (chain_inactive, set_address, set_freq, open_core)
//! is the same — only the register access method changes.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use dcentrald_asic::voltage_rail_adapters::StockFpgaVoltageRail;
use dcentrald_common::{
    apply_safety_action, energize_voltage_rail, pic16_mv_to_dac, safe_off_voltage_rail,
    stock_asicboost_admitted, stock_pic16_init_dac, stock_pic16_operating_dac,
    ControllerHeartbeatObservation, DispatchRevocationCause, HeartbeatRequirement, PowerCut,
    PowerCutReason, SafetyAction, ThermalSafetyState, VoltageRail, WatchdogSafetyState,
    WorkDispatchAdmissionReceipt, WorkDispatchLifecycle, WorkDispatchSafetyError,
    WorkDispatchSafetyInputs, WorkHistoryRing, STOCK_PIC16_INIT_MV, STOCK_PIC16_OPERATING_MV,
};
use dcentrald_hal::stock_fpga::*;
use dcentrald_hal::stock_fpga_iic::StockFpgaI2c;
use dcentrald_hal::stock_fpga_preflight::StockFpgaCarrierPreflightReceipt;
use dcentrald_hal::stock_fpga_work::{StockFpgaDma, StockFpgaWorkEngine};

use crate::config::DcentraldConfig;
use crate::runtime::thread_guard::{sleep_until_cancelled, RuntimeThreadGuard, ThreadStopSummary};

// ---------------------------------------------------------------------------
// Stock FPGA chain numbering
// ---------------------------------------------------------------------------

/// Stock Bitmain chain IDs (maps to HASH_ON_PLUG bit positions).
/// These are the physical chain numbers used in the FPGA's IIC_COMMAND register.
///
/// BUG FIX (2026-04-11): Was hardcoded to [6, 7, 8]. Some S9 units use
/// chains [5, 6, 7] instead. Now check all possible chain positions (5-8)
/// and detect which ones have boards via HASH_ON_PLUG register.
const STOCK_CHAIN_IDS: [u8; 4] = [5, 6, 7, 8];

/// Number of BM1387 chips per S9 hash board.
const CHIPS_PER_CHAIN: u8 = 63;

/// Historical bmminer operating DAC (~9.10 V). Prefer
/// [`stock_pic16_operating_dac`] / [`STOCK_PIC16_OPERATING_MV`] at call sites.
#[allow(dead_code)]
const DEFAULT_VOLTAGE_DAC_HISTORICAL: u8 = 57;

/// Historical init DAC (~9.4 V). Must equal [`stock_pic16_init_dac`].
const INIT_VOLTAGE_DAC: u8 = 6;

/// PIC heartbeat interval (ms). Well within the ~1 minute stock PIC timeout.
const HEARTBEAT_INTERVAL_MS: u64 = 5000;

/// Hardware difficulty for BM1387 with TicketMask 0xFF = diff 256.
const HW_DIFFICULTY: u64 = 256;

/// Stock DHASH autonomously increments extranonce2 and returns only a work ID.
/// The exact FPGA-written nonce2/job-id DMA schema is still hardware-beta
/// evidence, so this path is fail-closed before opening any device unless the
/// a compiled lab session explicitly requests correlation testing.
const STOCK_FPGA_NONCE2_BETA_ENV: &str = "DCENT_EXPERIMENTAL_STOCK_FPGA_NONCE2";

fn stock_fpga_nonce2_beta_enabled_value(raw: Option<&str>) -> bool {
    raw.map(str::trim).is_some_and(|value| {
        value == "1"
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("yes")
            || value.eq_ignore_ascii_case("on")
    })
}

fn stock_fpga_nonce2_beta_enabled() -> bool {
    stock_fpga_nonce2_beta_enabled_value(
        dcentrald_common::lab_env::var(STOCK_FPGA_NONCE2_BETA_ENV)
            .ok()
            .as_deref(),
    )
}

/// Resolve the same V1/V2 endpoint choice as the Stratum router without
/// constructing or opening a client. The recovered stock FPGA DMA ABI needs
/// V1 coinbase/extranonce2 jobs and cannot represent SV2 Standard templates
/// that carry only a precomputed merkle root.
fn stock_fpga_pool_route_is_v1(protocol: Option<&str>, sv2_url_present: bool) -> bool {
    match protocol
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("v1" | "sv1") => true,
        Some("v2" | "sv2") => false,
        // Router Auto (including absent/unrecognized) chooses V2 whenever an
        // SV2 endpoint is present, otherwise falls back to V1.
        _ => !sv2_url_present,
    }
}

/// Pure work-domain gate for the recovered S9 DMA job carrier.
fn stock_fpga_dma_job_domain_admitted(
    has_precomputed_merkle_root: bool,
    extranonce2_size: usize,
) -> bool {
    !has_precomputed_merkle_root && (1..=8).contains(&extranonce2_size)
}

// ---------------------------------------------------------------------------
// Work-dispatch safety (shared pure policy → stock adapter)
// ---------------------------------------------------------------------------

/// Map stock-FPGA bring-up observations into the shared
/// [`WorkDispatchSafetyInputs`] matrix.
///
/// Pure and host-testable: engines must not invent a second admission matrix.
/// Heartbeat observations use chain IDs as `controller_id` (stock PIC is
/// addressed per FPGA chain slot).
pub(crate) fn stock_fpga_work_dispatch_inputs(
    soc_watchdog: WatchdogSafetyState,
    controller_heartbeats: &[ControllerHeartbeatObservation],
    thermal: ThermalSafetyState,
) -> WorkDispatchSafetyInputs {
    WorkDispatchSafetyInputs {
        watchdog: soc_watchdog,
        heartbeat_requirement: HeartbeatRequirement::AllControllersSameCycle,
        controllers: controller_heartbeats.to_vec(),
        thermal,
        // Lifecycle latch owns the terminal revoke bit; never smuggle clear here.
        previously_revoked: false,
    }
}

/// Stock-path SoC watchdog contribution from config + kicker spawn outcome.
///
/// - Config disabled → [`WatchdogSafetyState::DisabledByConfiguration`]
/// - Config enabled and kicker owner present → [`WatchdogSafetyState::Armed`]
/// - Config enabled but no owner → [`WatchdogSafetyState::Unavailable`]
pub(crate) fn stock_fpga_watchdog_safety_state(
    config_enabled: bool,
    kicker_owner_present: bool,
) -> WatchdogSafetyState {
    match (config_enabled, kicker_owner_present) {
        (false, _) => WatchdogSafetyState::DisabledByConfiguration,
        (true, true) => WatchdogSafetyState::Armed,
        (true, false) => WatchdogSafetyState::Unavailable,
    }
}

/// Admit standard work dispatch on the stock-FPGA lifecycle latch.
///
/// Call **before** the first DHASH/DMA work commit. Returns the pure receipt
/// so logs/forensics can pin which pillars were green.
pub(crate) fn stock_fpga_admit_standard_work_dispatch<'a>(
    life: &'a mut WorkDispatchLifecycle,
    inputs: &WorkDispatchSafetyInputs,
) -> Result<&'a WorkDispatchAdmissionReceipt, WorkDispatchSafetyError> {
    life.admit(inputs)
}

/// Terminal revoke for the stock-FPGA lifecycle (heartbeat miss, operator stop,
/// thermal/watchdog loss). Always cut-hash-before-noise via the shared policy.
pub(crate) fn stock_fpga_revoke_work_dispatch(
    life: &mut WorkDispatchLifecycle,
    cause: DispatchRevocationCause,
    profile_max_pwm: u8,
) -> (SafetyAction, bool) {
    life.revoke(cause, profile_max_pwm)
}

// ---------------------------------------------------------------------------
// StockMiner — top-level stock FPGA mining orchestrator
// ---------------------------------------------------------------------------

/// Process-global crash-panic teardown state for the stock-fpga (S9 BM1387)
/// path. Each chain bit is set immediately before its multi-write voltage-enable
/// and cleared only after a completed disable, so uncertain outcomes, partial
/// initialization, and later runs cannot leave the hook with a stale snapshot.
/// Mirrors the am2 `AM2_TEARDOWN_PARAMS` /
/// am3-aml `NOPIC_TEARDOWN_ARMED` / am3-bb `AM3BB_TEARDOWN_ARMED` pattern —
/// the stock-fpga path was the one energizing path with NO panic-hook peer
/// (prod-readiness hunt needs_more_thought #1).
static STOCK_FPGA_ENERGIZED_CHAIN_MASK: AtomicU32 = AtomicU32::new(0);

fn stock_chain_bit(chain: u8) -> Option<u32> {
    1u32.checked_shl(u32::from(chain))
}

fn mark_stock_chain_energized(mask: &AtomicU32, chain: u8) {
    if let Some(bit) = stock_chain_bit(chain) {
        mask.fetch_or(bit, Ordering::SeqCst);
    }
}

fn clear_stock_chain_energized(mask: &AtomicU32, chain: u8) {
    if let Some(bit) = stock_chain_bit(chain) {
        mask.fetch_and(!bit, Ordering::SeqCst);
    }
}

/// Best-effort cut-hash teardown for the `main()` crash panic hook on the
/// stock-fpga (S9) path. No-op (allocation-free early return) unless any
/// energized bit exists. Re-opens the FPGA (the running handle may be held by
/// the panicking thread — the Ok-path graceful shutdown re-opens the same way)
/// and cuts each energized chain via [`StockFpgaVoltageRail`] +
/// [`safe_off_voltage_rail`] (P1-2). Swallows ALL errors — must NEVER re-panic
/// from inside the panic hook.
///
/// Why this matters: the release profile is `panic = "abort"`, so a panic runs
/// NO `Drop`; the ordinary-return guard cannot execute. Without this the only S9
/// backstop after a panic mid-bringup is the ~60 s PIC heartbeat watchdog,
/// leaving the boards energized in the meantime. Fans are left to the FPGA
/// cooldown register the Ok path sets; the actual fire-risk mitigation is
/// cutting the chip rail, which this does immediately.
pub fn stock_fpga_panic_hook_best_effort_teardown() {
    let energized = STOCK_FPGA_ENERGIZED_CHAIN_MASK.load(Ordering::SeqCst);
    if energized == 0 {
        return;
    }
    // P1-6: cut-hash-only SafetyAction (no fan blast from the panic hook).
    let action = SafetyAction::PowerCutOnly(PowerCut {
        reason: PowerCutReason::PanicTeardown,
        cut_hash_before_noise: true,
    });
    let _ = apply_safety_action(
        action,
        |_cut| {
            if let Ok(fpga) = StockFpga::open() {
                let i2c = StockFpgaI2c::new(&fpga);
                for chain in 0u8..32 {
                    let bit = 1u32 << u32::from(chain);
                    if energized & bit == 0 {
                        continue;
                    }
                    let mut rail = StockFpgaVoltageRail::new(&i2c, chain);
                    if safe_off_voltage_rail(&mut rail).is_ok() {
                        clear_stock_chain_energized(&STOCK_FPGA_ENERGIZED_CHAIN_MASK, chain);
                    }
                }
            }
            Ok::<(), ()>(())
        },
        |_pwm| Ok(()),
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StockVoltageTeardownEvidence {
    software_attempted: bool,
    all_commands_completed: bool,
    transport_reentry_skipped: bool,
    watchdog_fallback: bool,
}

/// Run-scope owner for energized stock-FPGA hash boards.
///
/// The release profile aborts on panic, so the process-global panic hook still
/// covers that path. This guard covers every ordinary return, including the
/// cold-chain refusal and failures after voltage enable. Callers explicitly
/// invoke teardown on ordinary returns. Drop is a nonblocking last resort: it
/// performs no transport I/O and preserves the already-armed PIC watchdog.
struct StockRunSafetyGuard {
    chains: Vec<u8>,
    heartbeat_transport_quiesced: bool,
    teardown_evidence: Option<StockVoltageTeardownEvidence>,
}

impl StockRunSafetyGuard {
    fn new(chains: Vec<u8>) -> Self {
        Self {
            chains,
            heartbeat_transport_quiesced: true,
            teardown_evidence: None,
        }
    }

    fn heartbeat_started(&mut self) {
        self.heartbeat_transport_quiesced = false;
    }

    fn add_energized_chain(&mut self, chain: u8) {
        if !self.chains.contains(&chain) {
            self.chains.push(chain);
        }
    }

    fn remove_deenergized_chain(&mut self, chain: u8) {
        self.chains.retain(|candidate| *candidate != chain);
    }

    fn heartbeat_stop_observed(&mut self, summary: &ThreadStopSummary) {
        self.heartbeat_transport_quiesced = !summary.any_timed_out();
    }

    fn teardown(&mut self, reason: &'static str) -> StockVoltageTeardownEvidence {
        if let Some(evidence) = self.teardown_evidence {
            return evidence;
        }

        let evidence = if self.chains.is_empty() {
            StockVoltageTeardownEvidence {
                software_attempted: false,
                all_commands_completed: true,
                transport_reentry_skipped: false,
                watchdog_fallback: false,
            }
        } else if !self.heartbeat_transport_quiesced {
            warn!(
                reason,
                energized_chains = ?self.chains,
                software_attempted = false,
                transport_reentry_skipped = true,
                watchdog_fallback = true,
                "Stock FPGA voltage teardown skipped because the heartbeat worker did not quiesce; avoiding re-entry into a possibly held FPGA I2C transport and relying on the stock PIC watchdog"
            );
            StockVoltageTeardownEvidence {
                software_attempted: false,
                all_commands_completed: false,
                transport_reentry_skipped: true,
                watchdog_fallback: true,
            }
        } else {
            // P1-6: execute PowerCut-only SafetyAction for ordinary-return teardown.
            let chains = self.chains.clone();
            let mut completed = 0usize;
            let action = SafetyAction::PowerCutOnly(PowerCut {
                reason: PowerCutReason::OperatorSafeOff,
                cut_hash_before_noise: true,
            });
            let apply = apply_safety_action(
                action,
                |_cut| {
                    if let Ok(shutdown_fpga) = StockFpga::open() {
                        let shutdown_i2c = StockFpgaI2c::new(&shutdown_fpga);
                        for &chain in &chains {
                            let mut rail = StockFpgaVoltageRail::new(&shutdown_i2c, chain);
                            match safe_off_voltage_rail(&mut rail) {
                                Ok(()) => {
                                    completed += 1;
                                    clear_stock_chain_energized(
                                        &STOCK_FPGA_ENERGIZED_CHAIN_MASK,
                                        chain,
                                    );
                                    info!(
                                        chain,
                                        reason, "Stock FPGA VoltageRail safe_off completed"
                                    );
                                }
                                Err(error) => warn!(
                                    chain,
                                    reason,
                                    error = %error,
                                    "Stock FPGA VoltageRail safe_off failed; PIC watchdog remains the safety net"
                                ),
                            }
                        }
                        Ok::<(), ()>(())
                    } else {
                        warn!(
                            reason,
                            "Stock FPGA could not be reopened for voltage teardown; PIC watchdog remains the safety net"
                        );
                        Err(())
                    }
                },
                |_pwm| Ok(()),
            );
            let _ = apply;
            let all_commands_completed = completed == self.chains.len();
            StockVoltageTeardownEvidence {
                software_attempted: true,
                all_commands_completed,
                transport_reentry_skipped: false,
                watchdog_fallback: !all_commands_completed,
            }
        };

        self.teardown_evidence = Some(evidence);
        evidence
    }
}

impl Drop for StockRunSafetyGuard {
    fn drop(&mut self) {
        if self.teardown_evidence.is_none() {
            warn!(
                energized_chains = ?self.chains,
                heartbeat_transport_quiesced = self.heartbeat_transport_quiesced,
                software_attempted = false,
                watchdog_fallback = true,
                "Stock run-scope owner dropped without explicit teardown; Drop performs no blocking transport I/O, so the already-armed PIC watchdog is the safety path"
            );
        }
    }
}

/// Stock Bitmain FPGA mining orchestrator.
///
/// Owns the stock FPGA register interface, DMA buffers, work engine,
/// and PIC I2C interface. Manages the full mining lifecycle from board
/// detection through work dispatch and nonce collection.
pub struct StockMiner {
    config: DcentraldConfig,
    shutdown: CancellationToken,
    _declared_route_admission:
        dcentrald_common::stock_fpga_carrier_preflight::StockFpgaDeclaredRouteAdmission,
    _carrier_preflight_receipt: StockFpgaCarrierPreflightReceipt,
}

impl StockMiner {
    /// Construct only after consuming both declaration policy and a live,
    /// retained-lease carrier receipt.
    ///
    /// The HAL intentionally exposes no receipt issuer yet. Consequently this
    /// constructor is structurally complete but cannot be called by the
    /// top-level runtime while passive C5/DMA preflight remains unimplemented.
    pub fn new(
        config: DcentraldConfig,
        shutdown: CancellationToken,
        declared_route_admission: dcentrald_common::stock_fpga_carrier_preflight::StockFpgaDeclaredRouteAdmission,
        carrier_preflight_receipt: StockFpgaCarrierPreflightReceipt,
    ) -> Self {
        Self {
            config,
            shutdown,
            _declared_route_admission: declared_route_admission,
            _carrier_preflight_receipt: carrier_preflight_receipt,
        }
    }

    /// Run the stock FPGA mining pipeline.
    ///
    /// This is the stock equivalent of Daemon::run(). It handles:
    /// 1. FPGA register block open + version verify
    /// 2. Hash board detection via HASH_ON_PLUG
    /// 3. PIC init via FPGA I2C (voltage, enable, heartbeat)
    /// 4. ASIC chain init (chain_inactive, set_address, set_freq, open_core)
    /// 5. Stratum pool connection (reuses existing stratum client)
    /// 6. Work dispatch via DHASH accelerator + DMA
    /// 7. Nonce collection via shared RETURN_NONCE FIFO
    /// 8. Share validation and submission
    pub async fn run(&mut self) -> Result<()> {
        if !stock_fpga_nonce2_beta_enabled() {
            bail!(
                "stock FPGA DHASH mining is hardware-beta and refused before device access: \
                 the FPGA autonomously increments extranonce2, but its nonce2/job-id DMA return \
                 schema and wrap boundary are not yet hardware-validated. Set \
                 {STOCK_FPGA_NONCE2_BETA_ENV}=1 only during the documented instrumented beta."
            );
        }
        let primary_v1 = stock_fpga_pool_route_is_v1(
            self.config.pool.protocol.as_deref(),
            self.config.pool.sv2_url.is_some(),
        );
        let failover1_v1 = self.config.pool.failover1.as_ref().is_none_or(|endpoint| {
            stock_fpga_pool_route_is_v1(endpoint.protocol.as_deref(), endpoint.sv2_url.is_some())
        });
        let failover2_v1 = self.config.pool.failover2.as_ref().is_none_or(|endpoint| {
            stock_fpga_pool_route_is_v1(endpoint.protocol.as_deref(), endpoint.sv2_url.is_some())
        });
        if !(primary_v1 && failover1_v1 && failover2_v1) {
            bail!(
                "stock FPGA DHASH mining is refused before device access: the recovered DMA ABI requires V1 coinbase/extranonce2 jobs, but at least one configured pool route can select SV2 Standard work"
            );
        }
        self._carrier_preflight_receipt
            .validate_current_process()
            .map_err(|error| {
                anyhow::anyhow!(
                    "stock FPGA retained fabric lease is stale or belongs to another process: {error}"
                )
            })?;
        if self._carrier_preflight_receipt.fabric()
            != dcentrald_hal::stock_fpga_preflight::STOCK_FPGA_MANAGEMENT_FABRIC
        {
            bail!("stock FPGA live receipt does not retain the canonical stock-s9-fpga-iic fabric");
        }
        warn!(
            env = STOCK_FPGA_NONCE2_BETA_ENV,
            "EXPERIMENTAL stock FPGA nonce2 correlation enabled; do not use for unattended production until DMA mapping and wrap-stop beta vectors pass"
        );
        info!("=== STOCK FPGA MINING PATH ===");
        info!("Using stock Bitmain FPGA register interface (/dev/axi_fpga_dev)");
        info!("This path does NOT require BraiinsOS boot components or UIO devices");

        // ---- Phase 1: Open stock FPGA register block ----
        info!("--- Phase 1: Opening stock FPGA registers ---");
        let fpga = StockFpga::open()
            .context("Failed to open stock FPGA — is /dev/axi_fpga_dev present? This requires stock Bitmain kernel modules.")?;

        let version = fpga.read_version();
        let board_type = ((version >> 8) & 0xFF) as u16;
        let fpga_version = version & 0xFF;

        info!(
            version = format_args!("0x{:08X}", version),
            board_type = format_args!("0x{:02X}", board_type),
            fpga_ver = fpga_version,
            "Stock FPGA version: 0x{:08X} (board=0x{:02X}, ver={})",
            version,
            board_type,
            fpga_version,
        );

        if board_type != BOARD_TYPE_C5 {
            warn!(
                "FPGA board type 0x{:02X} is not C5 (Zynq S9) — proceeding anyway but results may be unexpected",
                board_type,
            );
        }

        let chip_id = fpga.read_chip_id();
        info!(
            chip_id = format_args!("0x{:016X}", chip_id),
            "FPGA chip ID: 0x{:016X}", chip_id,
        );

        // ---- Phase 2: Detect hash boards ----
        info!("--- Phase 2: Hash board detection via HASH_ON_PLUG register ---");
        let plug = fpga.read_hash_on_plug();
        info!(
            hash_on_plug = format_args!("0x{:02X}", plug),
            "HASH_ON_PLUG = 0x{:02X} (0xE0 = all 3 boards present)", plug,
        );

        let mut detected_chains: Vec<u8> = Vec::new(); // chain IDs
        for &chain_id in &STOCK_CHAIN_IDS {
            if fpga.is_board_present(chain_id) {
                info!(
                    chain_id,
                    connector = format_args!("J{}", chain_id + 1),
                    "Hash board DETECTED on chain {} (J{})",
                    chain_id,
                    chain_id + 1,
                );
                detected_chains.push(chain_id);
            } else {
                info!(
                    chain_id,
                    connector = format_args!("J{}", chain_id + 1),
                    "No hash board on chain {} (J{}) — slot empty",
                    chain_id,
                    chain_id + 1,
                );
            }
        }

        if detected_chains.is_empty() {
            bail!("No hash boards detected — cannot mine without hardware");
        }

        info!(
            boards = detected_chains.len(),
            "Found {} hash board(s) — initializing PICs and ASICs",
            detected_chains.len(),
        );

        // ---- Phase 3: PIC initialization via FPGA I2C ----
        info!("--- Phase 3: PIC voltage controller init (FPGA I2C register) ---");
        let i2c = StockFpgaI2c::new(&fpga);

        let mut initialized_chains: Vec<u8> = Vec::new();
        // Per-initialized-chain initial PIC heartbeat (same order as
        // `initialized_chains`). Feeds work-dispatch admission.
        let mut initial_pic_heartbeat_ok: Vec<bool> = Vec::new();
        let mut run_safety = StockRunSafetyGuard::new(Vec::new());

        for &chain_id in &detected_chains {
            info!(
                chain_id,
                "Initializing PIC on chain {} via FPGA IIC_COMMAND register", chain_id,
            );

            // Detect PIC state — check if in bootloader (0xCC) or app mode (0x60)
            match i2c.raw_read(chain_id) {
                Ok(0xCC) => {
                    info!(
                        chain_id,
                        "PIC on chain {} is in BOOTLOADER — sending JUMP to app mode", chain_id
                    );
                    if let Err(e) = i2c.jump_to_app(chain_id) {
                        warn!(chain_id, error = %e, "PIC JUMP failed on chain {} — trying init anyway", chain_id);
                    }
                }
                Ok(byte) => {
                    info!(
                        chain_id,
                        byte = format_args!("0x{:02X}", byte),
                        "PIC on chain {} responds 0x{:02X} (expected 0x60=app or 0xCC=bootloader)",
                        chain_id,
                        byte
                    );
                }
                Err(e) => {
                    warn!(chain_id, error = %e, "PIC raw read failed on chain {} — attempting init anyway", chain_id);
                }
            }

            // Try to read PIC version (verifies I2C communication)
            match i2c.get_pic_version(chain_id) {
                Ok(ver) => {
                    info!(
                        chain_id,
                        version = format_args!("0x{:02X}", ver),
                        "PIC version: 0x{:02X} on chain {} (0x56/0x5A/0x5E=stock, 0x03=BraiinsOS)",
                        ver,
                        chain_id,
                    );
                }
                Err(e) => {
                    warn!(
                        chain_id,
                        error = %e,
                        "PIC version read failed on chain {} — PIC may need reflash",
                        chain_id,
                    );
                }
            }

            // P1-2: full VoltageRail facet energize (set_mv → enable) via stock FPGA PIC.
            debug_assert_eq!(INIT_VOLTAGE_DAC, stock_pic16_init_dac());
            // A multi-write enable error cannot prove that no write reached the
            // PIC. Mark possible energization BEFORE the first enable stage so
            // panic and ordinary-return teardown remain conservative.
            mark_stock_chain_energized(&STOCK_FPGA_ENERGIZED_CHAIN_MASK, chain_id);
            run_safety.add_energized_chain(chain_id);
            let energize_result = {
                let mut rail = StockFpgaVoltageRail::new(&i2c, chain_id);
                energize_voltage_rail(&mut rail, STOCK_PIC16_INIT_MV)
            };
            if let Err(enable_error) = energize_result {
                let disable_result = {
                    let mut rail = StockFpgaVoltageRail::new(&i2c, chain_id);
                    safe_off_voltage_rail(&mut rail)
                };
                match disable_result {
                    Ok(()) => {
                        clear_stock_chain_energized(&STOCK_FPGA_ENERGIZED_CHAIN_MASK, chain_id);
                        run_safety.remove_deenergized_chain(chain_id);
                        warn!(
                            chain_id,
                            error = %enable_error,
                            cleanup_completed = true,
                            "Stock PIC VoltageRail energize failed; compensating safe_off completed"
                        );
                    }
                    Err(disable_error) => warn!(
                        chain_id,
                        error = %enable_error,
                        cleanup_error = %disable_error,
                        possibly_energized = true,
                        watchdog_fallback = true,
                        "Stock PIC VoltageRail energize failed and compensating safe_off failed; retaining teardown ownership"
                    ),
                }
                continue;
            }

            // Send initial heartbeat — observation feeds the shared
            // work-dispatch admission gate (same-cycle HB required for every
            // energized PIC before DHASH work may start).
            let heartbeat_ok = {
                let mut rail = StockFpgaVoltageRail::new(&i2c, chain_id);
                match rail.heartbeat() {
                    Ok(()) => true,
                    Err(e) => {
                        warn!(
                            chain_id,
                            error = %e,
                            "PIC heartbeat failed on chain {} — PIC watchdog may fire; \
                             work-dispatch admission will refuse until a green same-cycle sample exists",
                            chain_id,
                        );
                        false
                    }
                }
            };

            info!(
                chain_id,
                init_mv = STOCK_PIC16_INIT_MV,
                dac = stock_pic16_init_dac(),
                "PIC on chain {} initialized — VoltageRail energize ~9.4V (DAC={})",
                chain_id,
                stock_pic16_init_dac(),
            );
            initialized_chains.push(chain_id);
            initial_pic_heartbeat_ok.push(heartbeat_ok);
        }

        if initialized_chains.is_empty() {
            let error = anyhow::anyhow!("No PICs initialized — cannot power hash boards");
            let evidence = run_safety.teardown("no-pics-initialized");
            warn!(?evidence, "Stock no-PIC initialization teardown evidence");
            return Err(error);
        }

        // Every possibly energized board is represented by both the ordinary-return
        // guard and the allocation-free panic-hook bitmask. Both were updated
        // before each multi-write per-chain enable above.

        // `--stock-fpga` bypasses `Daemon::run()`, so it must arm the shared
        // hardware watchdog kicker itself once voltage is enabled and the PIC
        // heartbeat path has been proven. SAF-5: gate kicks on the stock mining
        // loop's status heartbeat so a live-locked loop stops feeding the SoC WDT.
        let watchdog_liveness = Arc::new(AtomicU64::new(0));
        let mut legacy_watchdog_feed_owner = crate::daemon::spawn_watchdog_kicker(
            &self.config.watchdog,
            Some(watchdog_liveness.clone()),
        );

        // Wait for voltage to stabilize and ASICs to boot
        info!("Waiting 2s for DC-DC voltage ramp and ASIC boot...");
        tokio::time::sleep(Duration::from_secs(2)).await;

        // ---- Phase 4: FPGA setup for mining ----
        info!("--- Phase 4: FPGA register configuration ---");

        let passthrough = self.config.mining.passthrough;
        if passthrough {
            // Passthrough mode: DO NOT reset hash boards or modify FPGA state.
            // bmminer already configured ASICs (PLL, baud, TicketMask, open-core).
            // Resetting boards would kill the ASIC state and require full reinit.
            info!("PASSTHROUGH mode: preserving bmminer's FPGA + ASIC configuration");
            info!("Skipping hash board reset, QN_WRITE_DATA, and timeout — using bmminer's values");
        } else {
            // Full init mode: reset boards and configure from scratch
            fpga.reset_all_hashboards();
            info!("Hash boards reset via FPGA RESET_HASHBOARD register");
            tokio::time::sleep(Duration::from_secs(4)).await;

            fpga.set_qn_write_data(0x0080_800F);
            info!("QN_WRITE_DATA set to 0x0080800F (all chains enabled)");

            fpga.set_timeout(0x8000_9C40);
            info!("ASIC response timeout set (0x80009C40)");
        }

        let effective_nonce_difficulty = if passthrough {
            // Read and preserve bmminer's ticket mask
            let existing_mask = fpga.read_reg(REG_TICKET_MASK);
            info!(
                ticket_mask = format_args!("0x{:02X}", existing_mask),
                "PASSTHROUGH: preserving bmminer's ticket mask 0x{:02X}", existing_mask,
            );
            warn!(
                ticket_mask = format_args!("0x{:08X}", existing_mask),
                "PASSTHROUGH nonce-derived hashrate is suppressed: the effective ASIC+FPGA return difficulty was not recovered from the inherited masks"
            );
            None
        } else {
            fpga.set_ticket_mask(0xFF);
            info!("Ticket mask set to 0xFF (hardware difficulty 256)");
            Some(HW_DIFFICULTY)
        };

        // Flush nonce FIFO (safe in both modes — just clears stale nonces)
        fpga.write_reg(
            REG_NONCE_FIFO_INTERRUPT,
            dcentrald_hal::stock_fpga::NONCE_FIFO_FLUSH,
        );
        std::thread::sleep(Duration::from_millis(1));
        fpga.write_reg(
            REG_NONCE_FIFO_INTERRUPT,
            dcentrald_hal::stock_fpga::NONCE_IRQ_ENABLE | 0x01,
        );
        info!("Nonce FIFO flushed and IRQ enabled");

        // ---- Phase 4b: ASIC chain init via BC_WRITE_COMMAND ----
        //
        // On the stock FPGA, ASIC commands are sent via the BC_WRITE_COMMAND register
        // (0x0C0) which broadcasts to ALL chains simultaneously. This is different from
        // BraiinsOS which has per-chain CMD TX/RX FIFOs.
        //
        // The init sequence is the same:
        //   1. chain_inactive (set all chips to address 0)
        //   2. set_chip_address (assign sequential addresses)
        //   3. set_frequency (PLL configuration)
        //   4. open_core (114 dummy work items)
        //
        // G32–G41: pure+execute library available offline for set_freq, software_set_address,
        // set_baud, ticket_mask/hcnt, timeout, open_core (EXPERIMENTAL). G41 adds a pure cold-boot
        // inventory spine only (phase4b admission flag remains false). Full composition is still
        // NOT auto-wired into this Phase 4b path (passthrough + counting gate).
        //
        // BUG FIX (2026-04-11): Hard-fail on cold boot instead of silently proceeding
        // with uninitialized ASICs (which produces 0 nonces and wastes time debugging).
        info!("--- Phase 4b: ASIC chain init ---");
        warn!("Stock FPGA full cold-boot auto-composition not yet admitted (G32–G41 pure library + \
               G41 inventory plan-only; open_core/set_baud/ticket_mask EXPERIMENTAL). Passthrough mode only — bmminer/bosminer \
               must have initialized ASICs before dcentrald.");
        // Read HASH_COUNTING_NUMBER to check if ASICs are alive.
        // REG_RETURN_NONCE (0x010) is destructive and can consume a real nonce.
        let counting = fpga.read_reg(REG_HASH_COUNTING_NUMBER);
        if counting == 0 {
            error!(
                "HASH_COUNTING_NUMBER = 0 — no ASICs detected. \
                    Stock FPGA cold-boot init is not yet implemented. \
                    Start bmminer or bosminer first to initialize ASICs, \
                    then kill it and restart dcentrald."
            );
            let error = anyhow::anyhow!(
                "Stock FPGA: no ASICs detected (cold boot not supported). \
                                         Pre-initialize with bmminer/bosminer first."
            );
            let evidence = run_safety.teardown("cold-chain-refusal");
            warn!(?evidence, "Stock cold-chain refusal teardown evidence");
            return Err(error);
        }
        info!(
            "HASH_COUNTING_NUMBER = {} — ASICs appear initialized (passthrough mode)",
            counting
        );

        // Set operating voltage (~9.1V) via VoltageRail facet (P1-2).
        let operating_dac = stock_pic16_operating_dac();
        info!(
            operating_mv = STOCK_PIC16_OPERATING_MV,
            dac = operating_dac,
            historical_dac = DEFAULT_VOLTAGE_DAC_HISTORICAL,
            "Setting operating voltage via VoltageRail (SSOT DAC; historical pin was {})",
            DEFAULT_VOLTAGE_DAC_HISTORICAL
        );
        for &chain in &initialized_chains {
            let set_result = {
                let mut rail = StockFpgaVoltageRail::new(&i2c, chain);
                rail.set_mv(STOCK_PIC16_OPERATING_MV)
            };
            if let Err(e) = set_result {
                warn!(
                    chain,
                    error = %e,
                    "Failed to set operating voltage on chain {}",
                    chain,
                );
            }
        }

        // Open every fallible mining transport before starting the heartbeat
        // owner. An ordinary error here is handled by `run_safety` without
        // racing a detached worker on the FPGA I2C registers.
        info!("--- Phase 5: Opening DMA buffer interface ---");
        let dma = match StockFpgaDma::open().context("Failed to open DMA buffer") {
            Ok(dma) => dma,
            Err(error) => {
                let evidence = run_safety.teardown("dma-open-failed");
                warn!(?evidence, "Stock DMA-open failure teardown evidence");
                return Err(error);
            }
        };

        // ---- Phase 6: Start PIC heartbeat thread ----
        info!("--- Phase 6: Starting PIC heartbeat thread ---");
        let hb_chains = initialized_chains.clone();
        let hb_shutdown = self.shutdown.clone();
        let mut runtime_threads = RuntimeThreadGuard::new(self.shutdown.clone());
        // Shared flag: any mid-run PIC heartbeat failure terminal-revokes work
        // dispatch on the next mining-loop tick (shared pure latch).
        let pic_heartbeat_failed = Arc::new(AtomicBool::new(false));
        let pic_heartbeat_failed_hb = pic_heartbeat_failed.clone();

        // The PIC heartbeat runs on a dedicated OS thread (not tokio) to guarantee
        // timing even when the async runtime is busy with work dispatch.
        // Stock PIC watchdog is ~1 minute. We send heartbeats every 5 seconds.
        let heartbeat_handle = match std::thread::Builder::new()
            .name("stock-pic-heartbeat".to_string())
            .spawn(move || {
                // Re-open FPGA in heartbeat thread (StockFpga is not Sync across threads
                // for mutable access — each thread needs its own mmap handle).
                let hb_fpga = match StockFpga::open() {
                    Ok(f) => f,
                    Err(e) => {
                        error!(error = %e, "Heartbeat thread: failed to open stock FPGA");
                        pic_heartbeat_failed_hb.store(true, Ordering::SeqCst);
                        return;
                    }
                };
                let hb_i2c = StockFpgaI2c::new(&hb_fpga);

                info!(
                    chains = hb_chains.len(),
                    interval_ms = HEARTBEAT_INTERVAL_MS,
                    "PIC heartbeat thread running — {} chain(s), every {}ms (stock timeout ~60s)",
                    hb_chains.len(),
                    HEARTBEAT_INTERVAL_MS,
                );

                loop {
                    if hb_shutdown.is_cancelled() {
                        info!("PIC heartbeat stopping");
                        break;
                    }

                    for &chain in &hb_chains {
                        if let Err(e) = hb_i2c.send_heartbeat(chain) {
                            warn!(
                                chain,
                                error = %e,
                                "PIC heartbeat failed on chain {} — signalling work-dispatch terminal revoke",
                                chain,
                            );
                            pic_heartbeat_failed_hb.store(true, Ordering::SeqCst);
                        }
                    }

                    if sleep_until_cancelled(
                        &hb_shutdown,
                        Duration::from_millis(HEARTBEAT_INTERVAL_MS),
                    ) {
                        info!("PIC heartbeat stopping during interval wait");
                        break;
                    }
                }
            }) {
            Ok(handle) => handle,
            Err(error) => {
                let evidence = run_safety.teardown("heartbeat-spawn-failed");
                warn!(?evidence, "Stock heartbeat-spawn failure teardown evidence");
                return Err(error).context("Failed to spawn PIC heartbeat thread");
            }
        };
        runtime_threads.push("stock-pic-heartbeat", heartbeat_handle);
        run_safety.heartbeat_started();

        // ---- Phase 6b: Work-dispatch safety admission (shared pure latch) ----
        // Refuse DHASH/DMA work until SoC watchdog + same-cycle PIC heartbeats
        // + thermal pillar are green. Engine wire residual shrinks to owning
        // one WorkDispatchLifecycle — not a second admission matrix.
        let mut dispatch_life = WorkDispatchLifecycle::new();
        let admission_cycle_id = 1u64;
        let controller_heartbeats: Vec<ControllerHeartbeatObservation> = initialized_chains
            .iter()
            .zip(initial_pic_heartbeat_ok.iter())
            .map(|(&chain, &ok)| ControllerHeartbeatObservation {
                controller_id: chain,
                heartbeat_ok: ok,
                cycle_id: admission_cycle_id,
            })
            .collect();
        let wd_state = stock_fpga_watchdog_safety_state(
            self.config.watchdog.enabled,
            legacy_watchdog_feed_owner.is_some(),
        );
        // No stock thermal supervisor currently owns fresh sensor evidence.
        // Absence of a latched emergency is not positive readiness, so even a
        // future carrier receipt must fail work admission until a real thermal
        // owner supplies a measured state.
        let dispatch_inputs = stock_fpga_work_dispatch_inputs(
            wd_state,
            &controller_heartbeats,
            ThermalSafetyState::NotReady,
        );
        match stock_fpga_admit_standard_work_dispatch(&mut dispatch_life, &dispatch_inputs) {
            Ok(receipt) => {
                info!(
                    watchdog = ?receipt.watchdog,
                    thermal = ?receipt.thermal,
                    controller_count = receipt.controller_count,
                    heartbeat_cycle_id = ?receipt.heartbeat_cycle_id,
                    "Stock FPGA work-dispatch admission OK — DHASH/DMA work allowed"
                );
            }
            Err(err) => {
                error!(
                    error = %err,
                    "Stock FPGA work-dispatch admission REFUSED — cutting hash before any work commit"
                );
                if let Some(owner) = legacy_watchdog_feed_owner.as_mut() {
                    owner.close_terminal();
                }
                let heartbeat_stop = runtime_threads.stop_and_join(Duration::from_secs(3)).await;
                run_safety.heartbeat_stop_observed(&heartbeat_stop);
                let evidence = run_safety.teardown("work-dispatch-admission-refused");
                warn!(?evidence, "Stock admission-refused teardown evidence");
                return Err(anyhow::anyhow!(
                    "stock FPGA work-dispatch admission refused: {err}"
                ));
            }
        }

        // ---- Phase 7: Initialize work engine ----
        info!("--- Phase 7: Initializing DHASH accelerator + work engine ---");
        let mut work_engine = StockFpgaWorkEngine::new(&fpga, &dma);

        // Total chip count across all detected boards
        let total_chips = detected_chains.len() as u32 * CHIPS_PER_CHAIN as u32;

        if passthrough {
            // Passthrough: preserve bmminer's DHASH state (0x8100, not 0x8160)
            //
            // This runs POST-ENERGIZE, so a bare `?` here would return with the
            // chain still energized and no teardown. Every fallible exit past
            // `run_safety` must cut hash explicitly first — pinned by
            // `stock_and_legacy_psu_feeders_keep_explicit_bounded_ownership`.
            if let Err(err) = work_engine.init_passthrough() {
                error!(
                    error = %err,
                    "Inherited stock FPGA DMA registers do not match the admitted layout — cutting hash before any work commit"
                );
                if !work_engine.stop() {
                    error!("Inherited DHASH/nullwork stop was not acknowledged; proceeding directly to rail-safe teardown");
                }
                if let Some(owner) = legacy_watchdog_feed_owner.as_mut() {
                    owner.close_terminal();
                }
                let heartbeat_stop = runtime_threads.stop_and_join(Duration::from_secs(3)).await;
                run_safety.heartbeat_stop_observed(&heartbeat_stop);
                let evidence = run_safety.teardown("passthrough-dma-layout-refused");
                warn!(?evidence, "Stock passthrough-refused teardown evidence");
                return Err(anyhow::anyhow!(
                    "inherited stock FPGA DMA registers do not match the admitted layout: {err}"
                ));
            }
        } else {
            if let Err(error) = work_engine.init() {
                error!(%error, "Stock FPGA DHASH init was not acknowledged; cutting hash");
                if !work_engine.stop() {
                    error!("Ambiguous full-init DHASH/nullwork stop was not acknowledged; proceeding directly to rail-safe teardown");
                }
                if let Some(owner) = legacy_watchdog_feed_owner.as_mut() {
                    owner.close_terminal();
                }
                let heartbeat_stop = runtime_threads.stop_and_join(Duration::from_secs(3)).await;
                run_safety.heartbeat_stop_observed(&heartbeat_stop);
                let evidence = run_safety.teardown("full-init-dhash-refused");
                warn!(?evidence, "Stock full-init-refused teardown evidence");
                return Err(anyhow::anyhow!(
                    "stock FPGA DHASH init was not acknowledged: {error}"
                ));
            }
        }
        info!(
            total_chips,
            boards = detected_chains.len(),
            passthrough,
            "Work engine initialized — {} chips across {} board(s)",
            total_chips,
            detected_chains.len(),
        );

        // ---- Phase 8: Connect to pool and start mining ----
        info!("--- Phase 8: Connecting to mining pool ---");

        let (job_tx, mut job_rx) = mpsc::channel::<dcentrald_stratum::types::JobTemplate>(32);
        // Keep the receiver open for the Stratum task, but never feed it from
        // this beta path until FPGA nonce2/job-id correlation is implemented.
        // Dropping the only sender would make recv() immediately-ready forever
        // in some session loops, so retain an explicitly named guard.
        let (_uncorrelated_share_tx_guard, share_rx) =
            mpsc::channel::<dcentrald_stratum::types::ValidShare>(256);
        let (status_tx, mut status_rx) =
            mpsc::channel::<dcentrald_stratum::types::StratumStatus>(64);

        // P2-9: stock path knows board×chip geometry before pool connect.
        let stratum_config = crate::config::build_stratum_config_with_enumerated_chips(
            &self.config,
            crate::config::disabled_stratum_donation_config(),
            false,
            false,
            (total_chips > 0).then_some(total_chips),
        );

        let stratum_router = dcentrald_stratum::StratumRouter::new(stratum_config);

        tokio::spawn(async move {
            stratum_router.run(job_tx, share_rx, status_tx).await;
        });

        // Stratum status logger
        let status_shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = status_shutdown.cancelled() => break,
                    Some(status) = status_rx.recv() => {
                        match status {
                            dcentrald_stratum::types::StratumStatus::StateChanged(state) => {
                                let s = match state {
                                    dcentrald_stratum::types::StratumState::Disconnected => "Disconnected",
                                    dcentrald_stratum::types::StratumState::Connecting => "Connecting",
                                    dcentrald_stratum::types::StratumState::Authorized => "Authorized",
                                    dcentrald_stratum::types::StratumState::Mining => "Mining",
                                    dcentrald_stratum::types::StratumState::Donating => "Donating",
                                    dcentrald_stratum::types::StratumState::AuthFailed => "AuthFailed",
                                };
                                info!(state = s, "Pool: {}", s);
                            }
                            dcentrald_stratum::types::StratumStatus::DifficultyChanged(d) => {
                                info!(difficulty = d, "Pool difficulty changed to {}", d);
                            }
                            dcentrald_stratum::types::StratumStatus::ShareAccepted { job_id, pool_target_difficulty, achieved_difficulty, .. } => {
                                info!(job_id = %job_id, pool_target_difficulty, achieved_difficulty, "SHARE ACCEPTED");
                            }
                            dcentrald_stratum::types::StratumStatus::ShareRejected { job_id, error_msg, .. } => {
                                warn!(job_id = %job_id, error = %error_msg, "SHARE REJECTED: {}", error_msg);
                            }
                            _ => {}
                        }
                    }
                }
            }
        });

        // ---- Phase 9: Mining loop ----
        info!("=== STOCK FPGA MINING ACTIVE ===");
        info!(
            // W1.4: the worker is the operator's wallet/payout address on Stratum
            // V1 — mask it; and strip any inline credential from the pool URL.
            pool = %dcentrald_stratum::pool_api::sanitize_pool_url(&self.config.pool.url),
            worker = %dcentrald_common::wallet_mask::mask_wallet(&self.config.pool.worker),
            boards = detected_chains.len(),
            total_chips,
            "Mining on stock Bitmain FPGA — {} board(s), {} chips",
            detected_chains.len(), total_chips,
        );

        let mut work_builder = dcentrald_stratum::share_pipeline::WorkBuilder::new();
        let mut current_job: Option<dcentrald_stratum::types::JobTemplate> = None;
        // G14/G15: pure WorkHistoryRing depth=1.
        // G15 correlation SSOT: history slots are the low byte of FPGA REG_JOB_ID
        // returned by StockFpgaWorkEngine::dispatch_work (post-inc write). Nonce
        // path maps RETURN_NONCE_EXT the same way — never a separate CPU cursor.
        // No share-dedup on this path (intentionally; do not invent one).
        let mut work_history: WorkHistoryRing<StockWorkEntry> = WorkHistoryRing::new(1);

        // Stats
        let mut total_work_dispatched: u64 = 0;
        let mut total_nonces: u64 = 0;
        let shares_submitted: u64 = 0;
        let mut uncorrelated_nonces_dropped: u64 = 0;
        let mut hw_errors: u64 = 0;
        let start_time = Instant::now();
        let mut last_hashrate_time = Instant::now();
        let mut hashrate_nonces: u64 = 0;

        // Timers
        let mut dispatch_timer = tokio::time::interval(Duration::from_millis(1));
        let mut nonce_poll_timer = tokio::time::interval(Duration::from_millis(1));
        let mut hashrate_timer = tokio::time::interval(Duration::from_secs(5));

        let mut dispatch_io_failure: Option<String> = None;
        'mining: loop {
            // Terminal revoke on mid-run PIC heartbeat failure — cut hash
            // before noise via the shared lifecycle latch (not fan blast).
            if pic_heartbeat_failed.load(Ordering::SeqCst) && dispatch_life.is_admitted() {
                let home_pwm = self
                    .config
                    .thermal
                    .fan_max_pwm
                    .min(dcentrald_hal::fan::PWM_SAFETY_MAX);
                let (action, stop_feed) = stock_fpga_revoke_work_dispatch(
                    &mut dispatch_life,
                    DispatchRevocationCause::HeartbeatFailure,
                    home_pwm,
                );
                // P1-6: execute SafetyAction steps (cut-hash policy); I/O disable
                // is owned by StockRunSafetyGuard drop after break.
                let report = apply_safety_action(
                    action,
                    |cut| {
                        error!(
                            ?cut.reason,
                            "Stock FPGA SafetyAction CutPower (PIC disable on guard drop)"
                        );
                        Ok::<(), ()>(())
                    },
                    |pwm| {
                        // Home-capped intent only — stock fan path is FPGA register; guard drop owns rails.
                        debug!(
                            pwm,
                            "Stock FPGA SafetyAction CommandFans (effective PWM recorded)"
                        );
                        Ok(())
                    },
                );
                match report {
                    Ok(r) => error!(
                        stop_watchdog_feed = stop_feed,
                        steps = r.steps_attempted,
                        cut = r.cut_power_applied,
                        "Stock FPGA work-dispatch TERMINALLY REVOKED after PIC heartbeat failure"
                    ),
                    Err((r, _)) => error!(
                        stop_watchdog_feed = stop_feed,
                        steps = r.steps_attempted,
                        "Stock FPGA work-dispatch revoke SafetyAction callback failed"
                    ),
                }
                if stop_feed {
                    if let Some(owner) = legacy_watchdog_feed_owner.as_mut() {
                        owner.close_terminal();
                    }
                }
                break;
            }

            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("Stock mining stopping — shutdown requested");
                    break;
                }

                // Receive new job from Stratum
                Some(job) = job_rx.recv() => {
                    if !stock_fpga_dma_job_domain_admitted(
                        job.merkle_root != [0u8; 32],
                        job.extranonce2_size,
                    ) {
                        error!(
                            has_precomputed_merkle_root = job.merkle_root != [0u8; 32],
                            extranonce2_size = job.extranonce2_size,
                            "Pool job is outside the recovered stock FPGA V1 coinbase/extranonce2 domain; entering rail-safe teardown"
                        );
                        dispatch_io_failure = Some(
                            "pool job is not representable by the recovered stock FPGA V1 DMA carrier"
                                .to_owned(),
                        );
                        break 'mining;
                    }
                    if job.clean_jobs {
                        info!(
                            job_id = %job.job_id,
                            "NEW BLOCK — flushing work and nonces",
                        );
                        work_history.clear_all();
                        work_engine.signal_new_block();
                        work_builder.reset_extranonce2();
                    }
                    // Propagate BIP-310 mask so WorkBuilder midstates + G17 AsicBoost
                    // packing share the negotiated mask (0 = single-version path).
                    work_builder.set_version_mask(job.version_mask);
                    current_job = Some(job);
                }

                // Dispatch work to FPGA via DMA
                _ = dispatch_timer.tick() => {
                    // Fail-closed: never commit DHASH work without a live admission.
                    if !dispatch_life.is_admitted() {
                        continue;
                    }
                    if let Some(ref job) = current_job {
                        // NOTE: BUFFER_SPACE register reads 0 during normal mining
                        // (bmminer also shows 0). It does NOT gate work dispatch.
                        // The final DHASH control RMW commits a verified job.

                        // Generate new work
                        let stratum_work = match work_builder.next_work(job) {
                            Ok(work) => work,
                            Err(error) => {
                                warn!(%error, "V1 work domain unavailable; pausing stock dispatch until a fresh generation arrives");
                                current_job = None;
                                continue;
                            }
                        };

                        // Convert prev_block_hash from pool byte order to 8 x u32 words.
                        // The FPGA uses this to construct block headers internally.
                        // Exact S9-family and BM1396 dispatchers assemble each
                        // four-byte packet word little-endian before raw MMIO.
                        let mut prev_hash_words = [0u32; 8];
                        for (i, word) in prev_hash_words.iter_mut().enumerate() {
                            *word = u32::from_le_bytes([
                                job.prev_block_hash[i * 4],
                                job.prev_block_hash[i * 4 + 1],
                                job.prev_block_hash[i * 4 + 2],
                                job.prev_block_hash[i * 4 + 3],
                            ]);
                        }

                        // Build job data for DMA buffer.
                        //
                        // For VIL mode, the DMA buffer contains the coinbase template +
                        // merkle branches. The FPGA's DHASH accelerator uses these with
                        // the nonce2 counter to generate work internally.
                        //
                        // Layout: [coinbase1 | extranonce1 | extranonce2 | coinbase2 | merkle0 | merkle1 | ...]
                        let en2_len = job.extranonce2_size;
                        let en2_bytes = decode_hex_bytes(&stratum_work.extranonce2);

                        // Nonce2 offset = position of extranonce2 in the coinbase
                        let nonce2_offset = job.coinbase1.len() + job.extranonce1.len();

                        // Build coinbase portion
                        let mut job_data = Vec::new();
                        job_data.extend_from_slice(&job.coinbase1);
                        job_data.extend_from_slice(&job.extranonce1);
                        job_data.extend_from_slice(&en2_bytes);
                        job_data.extend_from_slice(&job.coinbase2);

                        // Coinbase length is everything before the merkle branches
                        let coinbase_len = job_data.len();

                        // Append merkle branches after coinbase
                        for branch in &job.merkle_branches {
                            job_data.extend_from_slice(branch);
                        }

                        // Build header tail for share validation
                        let mut header_tail = [0u8; 12];
                        header_tail[0..4].copy_from_slice(&stratum_work.merkle4);
                        header_tail[4..8].copy_from_slice(&stratum_work.ntime.to_le_bytes());
                        header_tail[8..12].copy_from_slice(&stratum_work.nbits.to_le_bytes());

                        // Dispatch via DMA + DHASH accelerator.
                        // In VIL mode, FPGA computes midstate internally from:
                        //   prev_hash (registers) + coinbase (DMA) + merkle (DMA)
                        // G15: REG_JOB_ID (return value) is the correlation spine —
                        // push history AFTER dispatch using the low byte nonces echo.
                        // Four-way AsicBoost remains fail-closed until the
                        // page-tail lane map and nonce/version correlation are
                        // admitted for an exact board/firmware profile.
                        let use_asicboost =
                            stock_asicboost_admitted(stratum_work.version_mask);
                        let dispatch_result = if use_asicboost {
                            work_engine.dispatch_work_asicboost(
                                &job_data,
                                &prev_hash_words,
                                stratum_work.version,
                                stratum_work.version_mask,
                                stratum_work.ntime,
                                stratum_work.nbits,
                                coinbase_len,
                                en2_len,
                                nonce2_offset,
                                job.merkle_branches.len(),
                            )
                        } else {
                            work_engine.dispatch_work(
                                &job_data,
                                &prev_hash_words,
                                stratum_work.version,
                                stratum_work.ntime,
                                stratum_work.nbits,
                                coinbase_len,
                                en2_len,
                                nonce2_offset,
                                job.merkle_branches.len(),
                            )
                        };
                        let fpga_job_id = match dispatch_result {
                            Ok(job_id) => job_id,
                            Err(error) => {
                                error!(%error, "Stock FPGA job commit failed; entering rail-safe teardown");
                                dispatch_io_failure = Some(error.to_string());
                                break 'mining;
                            }
                        };
                        let work_id = (fpga_job_id & 0xFF) as u8;
                        // Up to 4 midstates for AsicBoost solution_idx validation;
                        // single-version path fills slot 0 only.
                        let mut midstates = [[0u8; 32]; 4];
                        let n_ms = stratum_work.midstates.len().min(4);
                        for (i, ms) in stratum_work.midstates.iter().take(n_ms).enumerate() {
                            midstates[i] = *ms;
                        }
                        if n_ms == 0 {
                            // Defensive: WorkBuilder always provides ≥1 midstate.
                            midstates[0] = [0u8; 32];
                        } else if n_ms == 1 {
                            // Replicate midstate0 so solution_idx never reads empty.
                            for i in 1..4 {
                                midstates[i] = midstates[0];
                            }
                        }
                        work_history.push(
                            work_id,
                            StockWorkEntry {
                                work_generation: stratum_work.work_generation,
                                job_id: stratum_work.job_id.clone(),
                                extranonce2: stratum_work.extranonce2.clone(),
                                ntime: stratum_work.ntime,
                                version: stratum_work.version,
                                version_mask: stratum_work.version_mask,
                                share_target: stratum_work.share_target,
                                midstates,
                                header_tail,
                            },
                        );

                        total_work_dispatched += 1;

                        if total_work_dispatched <= 3 {
                            info!(
                                work_id,
                                fpga_job_id,
                                job_id = %stratum_work.job_id,
                                version = format_args!("0x{:08X}", stratum_work.version),
                                ntime = format_args!("0x{:08X}", stratum_work.ntime),
                                nbits = format_args!("0x{:08X}", stratum_work.nbits),
                                "WORK #{} dispatched to stock FPGA via DMA",
                                total_work_dispatched,
                            );
                        }
                    }
                }

                // Poll for nonces from the shared RETURN_NONCE FIFO
                _ = nonce_poll_timer.tick() => {
                    while let Some((nonce, ext)) = work_engine.read_nonce() {
                        total_nonces += 1;
                        hashrate_nonces += 1;

                        // Decode extended nonce data.
                        //
                        // Stock FPGA RETURN_NONCE_EXT format (from bmminer debug):
                        //   Bits [31:24] = chain_id (or CRC)
                        //   Bits [23:8]  = extended_work_id
                        //   Bits [7:0]   = solution_index
                        //
                        // G15: extended work_id low byte is the same spine as
                        // REG_JOB_ID written at dispatch — history keys match.
                        let ext_work_id = ((ext >> 8) & 0xFFFF) as u16;
                        let solution_idx = (ext & 0xFF) as u8;
                        let work_id = (ext_work_id & 0xFF) as u8;

                        if total_nonces <= 3 {
                            info!(
                                nonce = format_args!("0x{:08X}", nonce),
                                ext = format_args!("0x{:08X}", ext),
                                work_id,
                                solution_idx,
                                "Nonce #{} from stock FPGA — ASIC chips are hashing!",
                                total_nonces,
                            );
                        }

                        // Look up work entry (depth-1 ring: latest or empty/stale).
                        let entry = match work_history.latest(work_id) {
                            Some(e) => e.clone(),
                            None => {
                                debug!(work_id, "Nonce for unknown work_id — stale");
                                continue;
                            }
                        };

                        // The stock DHASH engine advances nonce2 autonomously and
                        // writes the actual (work_id, nonce2, midstate) mapping
                        // into the separate 2 MiB FPGA store. Until hardware
                        // replay proves that correlation, using the CPU seed can
                        // validate and submit the wrong header.
                        uncorrelated_nonces_dropped += 1;
                        static WARNED_UNCORRELATED_NONCE2: AtomicBool = AtomicBool::new(false);
                        if !WARNED_UNCORRELATED_NONCE2.swap(true, Ordering::Relaxed) {
                            warn!(
                                "Stock FPGA nonce2/job-id mapping is not hardware-validated; \
                                 pool submission is suppressed for this experimental session"
                            );
                        }
                        debug!(
                            nonce = format_args!("0x{:08X}", nonce),
                            ext = format_args!("0x{:08X}", ext),
                            work_id,
                            solution_idx,
                            cpu_job_id = %entry.job_id,
                            cpu_seed_extranonce2 = %entry.extranonce2,
                            uncorrelated_nonces_dropped,
                            "Dropped uncorrelated stock FPGA nonce before local share validation"
                        );
                        continue;

                        #[cfg(any())]
                        {
                        // G17: AsicBoost solution_idx selects version slot + midstate.
                        // Single-version path uses slot 0 / midstates[0].
                        let slot = if stock_asicboost_admitted(entry.version_mask) {
                            stock_asicboost_slot_from_solution_idx(solution_idx)
                        } else {
                            0
                        };
                        let midstate = entry.midstates[slot as usize];
                        let submit_version = if stock_asicboost_admitted(entry.version_mask) {
                            stock_asicboost_version_for_solution(
                                entry.version,
                                entry.version_mask,
                                solution_idx,
                            )
                        } else {
                            entry.version
                        };

                        // BUG FIX (2026-04-11): Enable share validation. Was bypassed and
                        // submitting ALL nonces, spamming pools with invalid shares.
                        // In VIL mode the FPGA computes its own midstate from DMA coinbase.
                        // If CPU midstate doesn't match, shares are correctly rejected here
                        // rather than wasting pool bandwidth.
                        let meets_target = dcentrald_stratum::share_pipeline::validate_share(
                            &midstate,
                            &entry.header_tail,
                            nonce,
                            &entry.share_target,
                        );

                        if !meets_target {
                            continue;
                        }

                        shares_submitted += 1;
                        let share = dcentrald_stratum::types::ValidShare {
                            work_generation: entry.work_generation,
                            worker_name: self.config.pool.worker.clone(),
                            job_id: entry.job_id.clone(),
                            extranonce2: entry.extranonce2.clone(),
                            ntime: format!("{:08x}", entry.ntime),
                            nonce: format!("{:08x}", nonce),
                            version_bits: None,
                            version: submit_version,
                            achieved_difficulty: None,
                        };

                        match share_tx.send(share).await {
                            Ok(()) => {
                                info!(
                                    nonce = format_args!("0x{:08X}", nonce),
                                    job_id = %entry.job_id,
                                    total_submitted = shares_submitted,
                                    "SHARE SUBMITTED to pool (#{}) — nonce 0x{:08X}",
                                    shares_submitted, nonce,
                                );
                            }
                            Err(e) => {
                                error!(error = %e, "Share channel closed");
                                break;
                            }
                        }
                        }
                    }
                }

                // Periodic hashrate calculation
                _ = hashrate_timer.tick() => {
                    watchdog_liveness.fetch_add(1, Ordering::Relaxed);
                    let elapsed = last_hashrate_time.elapsed().as_secs_f64();
                    if elapsed > 0.0 && hashrate_nonces > 0 && effective_nonce_difficulty.is_some() {
                        let difficulty = effective_nonce_difficulty.expect("checked some");
                        let hashes = hashrate_nonces as f64 * difficulty as f64 * 4_294_967_296.0;
                        let hashrate_ghs = hashes / elapsed / 1e9;
                        let hashrate_ths = hashrate_ghs / 1000.0;

                        info!(
                            hashrate_ths = format_args!("{:.2}", hashrate_ths),
                            hashrate_ghs = format_args!("{:.0}", hashrate_ghs),
                            nonces_5s = hashrate_nonces,
                            total_nonces,
                            total_work = total_work_dispatched,
                            shares_submitted,
                            uncorrelated_nonces_dropped,
                            uptime_s = start_time.elapsed().as_secs(),
                            crc_errors = fpga.read_crc_errors(),
                            "Hashrate: {:.2} TH/s ({:.0} GH/s) — {} nonces, {} shares submitted",
                            hashrate_ths, hashrate_ghs, total_nonces, shares_submitted,
                        );

                    }
                    hashrate_nonces = 0;
                    last_hashrate_time = Instant::now();
                }
            }
        }

        // ---- Shutdown ----
        info!("=== STOCK FPGA MINING SHUTDOWN ===");

        // Operator/normal stop: terminal revoke if still admitted (heartbeat
        // failure already revoked above). Shared policy cuts hash before noise
        // and reports whether the SoC WDT feed must stop.
        if dispatch_life.is_admitted() {
            let home_pwm = self
                .config
                .thermal
                .fan_max_pwm
                .min(dcentrald_hal::fan::PWM_SAFETY_MAX);
            let (action, stop_feed) = stock_fpga_revoke_work_dispatch(
                &mut dispatch_life,
                if dispatch_io_failure.is_some() {
                    DispatchRevocationCause::HardwareIoFailure
                } else {
                    DispatchRevocationCause::OperatorSafeOff
                },
                home_pwm,
            );
            info!(
                stop_watchdog_feed = stop_feed,
                steps = action.steps().len(),
                "Stock FPGA work-dispatch revoked on operator shutdown"
            );
            if stop_feed {
                if let Some(owner) = legacy_watchdog_feed_owner.as_mut() {
                    owner.close_terminal();
                }
            }
        } else if let Some(owner) = legacy_watchdog_feed_owner.as_mut() {
            // Already revoked (e.g. heartbeat) — still close the feed owner.
            owner.close_terminal();
        }

        // Stop DHASH accelerator
        if !work_engine.stop() {
            error!(
                "Stock FPGA DHASH stop was not acknowledged; continuing directly to rail-safe teardown"
            );
        }

        // Quiesce the heartbeat owner before reopening the shared FPGA I2C
        // transport. All workers consume one total deadline. If the worker is
        // wedged, skip transport re-entry and allow the stock PIC watchdog to
        // remove hash power instead of risking a concurrent register sequence.
        let heartbeat_stop = runtime_threads.stop_and_join(Duration::from_secs(3)).await;
        run_safety.heartbeat_stop_observed(&heartbeat_stop);
        let voltage_evidence = run_safety.teardown(if dispatch_io_failure.is_some() {
            "stock-dispatch-io-failure"
        } else {
            "normal-shutdown"
        });

        // Post-mining cooldown fan. The chips were just mining and are still hot.
        // Software disable commands may have completed, or a degraded teardown
        // may still be waiting for the PIC watchdog; in either case keep airflow
        // at the configured home cap instead of the old hardcoded ~50% blast —
        // the PWM-30 home cap is
        // load-bearing (; cut-hash-before-noise) and
        // every sibling teardown (daemon.rs Step 7, NoPicPsuGuard, Am3BbRunSafetyGuard)
        // already honors it. G44: FAN_CONTROL pack = pure T9+ set_PWM SSOT (not
        // invent 0–255 scale); PWM_SAFETY_MAX (30) is still applied before pack.
        let cooldown_pct = self
            .config
            .thermal
            .fan_max_pwm
            .min(dcentrald_hal::fan::PWM_SAFETY_MAX);
        let fan_word = dcentrald_common::stock_fan_control_value(cooldown_pct);
        fpga.write_reg(REG_FAN_CONTROL, fan_word);
        info!(
            cooldown_pct,
            fan_word = format_args!("0x{:08X}", fan_word),
            "Fan set to PWM {}% (home cap) via FPGA FAN_CONTROL (T9+ pure pack) for post-mining cooldown",
            cooldown_pct
        );

        if voltage_evidence.all_commands_completed {
            info!(
                ?voltage_evidence,
                "Stock FPGA mining shutdown complete; software disable commands completed, physical rail-off was not independently measured"
            );
        } else {
            warn!(
                ?voltage_evidence,
                "Stock FPGA mining shutdown degraded; PIC watchdog cutoff is required before warm restart"
            );
        }
        if let Some(error) = dispatch_io_failure {
            return Err(anyhow::anyhow!(
                "stock FPGA dispatch failed after rail-safe teardown: {error}"
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Work tracking for stock FPGA path
// ---------------------------------------------------------------------------

/// Work entry for matching nonces back to pool jobs (stock FPGA path).
///
/// Engine-local rich payload stored in pure [`WorkHistoryRing`] depth=1 (G14/G15/G17).
/// Slot key = FPGA REG_JOB_ID low byte from dispatch_work (not a separate cursor).
/// Do not unify with hybrid/serial WorkEntry — midstate/header_tail are stock-specific.
#[derive(Clone)]
struct StockWorkEntry {
    work_generation: dcentrald_stratum::WorkGeneration,
    job_id: String,
    extranonce2: String,
    ntime: u32,
    /// Base stratum version (pre-slot packing).
    version: u32,
    /// Negotiated BIP-310 mask; 0 = single-version path.
    version_mask: u32,
    share_target: [u8; 32],
    /// Up to 4 midstates for AsicBoost solution_idx; slot 0 is single-version.
    midstates: [[u8; 32]; 4],
    header_tail: [u8; 12],
}

// ---------------------------------------------------------------------------
// Hex decoding helper
// ---------------------------------------------------------------------------

/// Decode a hex string into bytes.
fn decode_hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 2 <= hex.len() {
                u8::from_str_radix(&hex[i..i + 2], 16).ok()
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod work_dispatch_admission_tests {
    //! Drive the **shipped** stock-FPGA admission adapters
    //! (`stock_fpga_work_dispatch_inputs`, `stock_fpga_watchdog_safety_state`,
    //! `stock_fpga_admit_standard_work_dispatch`, `stock_fpga_revoke_work_dispatch`)
    //! through the real `WorkDispatchLifecycle` path — not a reimplementation.

    use super::*;
    use dcentrald_common::{power_precedes_fan_raise, SafetyStep, HOME_FAN_PWM_SAFETY_MAX};

    fn green_heartbeats(chains: &[u8]) -> Vec<ControllerHeartbeatObservation> {
        chains
            .iter()
            .map(|&id| ControllerHeartbeatObservation {
                controller_id: id,
                heartbeat_ok: true,
                cycle_id: 1,
            })
            .collect()
    }

    #[test]
    fn stock_nonce2_beta_gate_is_explicit_and_fail_closed() {
        for disabled in [None, Some(""), Some("0"), Some("false"), Some("off")] {
            assert!(!stock_fpga_nonce2_beta_enabled_value(disabled));
        }
        for enabled in [Some("1"), Some("true"), Some("YES"), Some(" on ")] {
            assert!(stock_fpga_nonce2_beta_enabled_value(enabled));
        }
    }

    #[test]
    fn stock_pool_route_and_job_domain_refuse_sv2_standard_before_work() {
        assert!(stock_fpga_pool_route_is_v1(None, false));
        assert!(stock_fpga_pool_route_is_v1(Some("v1"), true));
        assert!(stock_fpga_pool_route_is_v1(Some("sv1"), false));
        assert!(!stock_fpga_pool_route_is_v1(Some("v2"), false));
        assert!(!stock_fpga_pool_route_is_v1(Some("auto"), true));
        assert!(!stock_fpga_pool_route_is_v1(None, true));

        assert!(stock_fpga_dma_job_domain_admitted(false, 1));
        assert!(stock_fpga_dma_job_domain_admitted(false, 8));
        assert!(!stock_fpga_dma_job_domain_admitted(true, 4));
        assert!(!stock_fpga_dma_job_domain_admitted(false, 0));
        assert!(!stock_fpga_dma_job_domain_admitted(false, 9));
    }

    #[test]
    fn stock_v1_route_refusal_precedes_all_device_access() {
        let src = include_str!("stock_mining.rs");
        let run = &src[src.find("pub async fn run").expect("StockMiner::run")..];
        let route_gate = run
            .find("if !(primary_v1 && failover1_v1 && failover2_v1)")
            .expect("V1 route gate");
        let device_open = run.find("StockFpga::open()").expect("stock FPGA open");
        assert!(route_gate < device_open);
    }

    #[test]
    fn retained_live_receipt_is_revalidated_before_any_device_access() {
        let src = include_str!("stock_mining.rs");
        let run = &src[src.find("pub async fn run").expect("StockMiner::run")..];
        let process_validation = run
            .find("validate_current_process()")
            .expect("retained lease process validation");
        let exact_fabric = run
            .find("STOCK_FPGA_MANAGEMENT_FABRIC")
            .expect("canonical fabric validation");
        let device_open = run.find("StockFpga::open()").expect("stock FPGA open");
        assert!(process_validation < exact_fabric && exact_fabric < device_open);
    }

    #[test]
    fn stock_nonce2_beta_refusal_precedes_all_device_access() {
        let src = include_str!("stock_mining.rs");
        let run = &src[src.find("pub async fn run").expect("StockMiner::run")..];
        let gate = run
            .find("if !stock_fpga_nonce2_beta_enabled()")
            .expect("stock beta gate");
        let fpga_open = run.find("StockFpga::open()").expect("stock FPGA open");
        assert!(
            gate < fpga_open,
            "unvalidated stock nonce2 correlation must be refused before opening hardware"
        );
    }

    #[test]
    fn stock_nonce2_beta_suppresses_every_uncorrelated_pool_submission() {
        let src = include_str!("stock_mining.rs");
        let nonce_path = &src[src
            .find("let entry = match work_history.latest(work_id)")
            .expect("stock nonce correlation path")..];
        let suppression = nonce_path
            .find("pool submission is suppressed for this experimental session")
            .expect("explicit uncorrelated-share suppression");
        let fail_closed_continue = nonce_path[suppression..]
            .find("continue;")
            .map(|offset| suppression + offset)
            .expect("fail-closed continuation");
        let compile_excluded_reference = nonce_path
            .find("#[cfg(any())]")
            .expect("compile-excluded future correlation reference");
        let historical_send = nonce_path
            .find("share_tx.send(share)")
            .expect("future correlated submission reference");

        assert!(
            suppression < fail_closed_continue
                && fail_closed_continue < compile_excluded_reference
                && compile_excluded_reference < historical_send,
            "every observed stock nonce must stop before the compile-excluded submission reference"
        );
    }

    #[test]
    fn stock_watchdog_state_maps_config_and_kicker_presence() {
        assert_eq!(
            stock_fpga_watchdog_safety_state(false, false),
            WatchdogSafetyState::DisabledByConfiguration
        );
        assert_eq!(
            stock_fpga_watchdog_safety_state(false, true),
            WatchdogSafetyState::DisabledByConfiguration
        );
        assert_eq!(
            stock_fpga_watchdog_safety_state(true, true),
            WatchdogSafetyState::Armed
        );
        assert_eq!(
            stock_fpga_watchdog_safety_state(true, false),
            WatchdogSafetyState::Unavailable
        );
    }

    #[test]
    fn admit_before_work_dispatch_succeeds_when_pillars_green() {
        let mut life = WorkDispatchLifecycle::new();
        let hbs = green_heartbeats(&[5, 6, 7]);
        let inputs = stock_fpga_work_dispatch_inputs(
            stock_fpga_watchdog_safety_state(true, true),
            &hbs,
            ThermalSafetyState::Ready,
        );
        let (controller_count, cycle) = {
            let receipt =
                stock_fpga_admit_standard_work_dispatch(&mut life, &inputs).expect("admit");
            (receipt.controller_count, receipt.heartbeat_cycle_id)
        };
        assert!(life.is_admitted());
        assert_eq!(controller_count, 3);
        assert_eq!(cycle, Some(1));
    }

    #[test]
    fn admit_refuses_failed_initial_pic_heartbeat() {
        let mut life = WorkDispatchLifecycle::new();
        let hbs = vec![
            ControllerHeartbeatObservation {
                controller_id: 6,
                heartbeat_ok: true,
                cycle_id: 1,
            },
            ControllerHeartbeatObservation {
                controller_id: 7,
                heartbeat_ok: false, // failed initial send_heartbeat
                cycle_id: 1,
            },
        ];
        let inputs = stock_fpga_work_dispatch_inputs(
            WatchdogSafetyState::Armed,
            &hbs,
            ThermalSafetyState::Ready,
        );
        let err = stock_fpga_admit_standard_work_dispatch(&mut life, &inputs).unwrap_err();
        assert!(matches!(
            err,
            WorkDispatchSafetyError::HeartbeatFailed {
                controller_id: 7,
                ..
            }
        ));
        assert!(!life.is_admitted());
    }

    #[test]
    fn admit_refuses_when_soc_watchdog_enabled_but_kicker_missing() {
        let mut life = WorkDispatchLifecycle::new();
        let hbs = green_heartbeats(&[6]);
        let inputs = stock_fpga_work_dispatch_inputs(
            stock_fpga_watchdog_safety_state(true, false),
            &hbs,
            ThermalSafetyState::Ready,
        );
        let err = stock_fpga_admit_standard_work_dispatch(&mut life, &inputs).unwrap_err();
        assert!(matches!(
            err,
            WorkDispatchSafetyError::WatchdogNotAdmitted {
                state: WatchdogSafetyState::Unavailable
            }
        ));
    }

    /// Mid-run PIC heartbeat failure must terminally revoke: cut hash before
    /// noise, stop WDT feed, and block re-admit without full teardown.
    #[test]
    fn terminal_revoke_on_heartbeat_failure_blocks_re_admit_and_cuts_hash_first() {
        let mut life = WorkDispatchLifecycle::new();
        let hbs = green_heartbeats(&[6, 7]);
        let inputs = stock_fpga_work_dispatch_inputs(
            WatchdogSafetyState::Armed,
            &hbs,
            ThermalSafetyState::Ready,
        );
        stock_fpga_admit_standard_work_dispatch(&mut life, &inputs).expect("admit");

        let (action, stop_feed) = stock_fpga_revoke_work_dispatch(
            &mut life,
            DispatchRevocationCause::HeartbeatFailure,
            100, // profile max — home cap must still bind
        );
        assert!(stop_feed, "heartbeat revoke must stop SoC WDT feed");
        assert!(!life.is_admitted());
        assert!(life.is_terminally_revoked());

        let steps = action.steps();
        assert!(
            power_precedes_fan_raise(&steps),
            "cut-hash-before-noise must hold on stock revoke"
        );
        match &steps[1] {
            SafetyStep::CommandFans(fan) => {
                assert!(fan.effective_pwm() <= HOME_FAN_PWM_SAFETY_MAX);
            }
            other => panic!("expected fan park second, got {other:?}"),
        }

        // Green sample after revoke must not re-admit the old generation.
        let err = stock_fpga_admit_standard_work_dispatch(&mut life, &inputs).unwrap_err();
        assert_eq!(err, WorkDispatchSafetyError::TerminallyRevoked);
    }

    #[test]
    fn operator_shutdown_revoke_also_stops_feed_and_parks_fans() {
        let mut life = WorkDispatchLifecycle::new();
        let hbs = green_heartbeats(&[5]);
        let inputs = stock_fpga_work_dispatch_inputs(
            WatchdogSafetyState::DisabledByConfiguration,
            &hbs,
            ThermalSafetyState::Ready,
        );
        stock_fpga_admit_standard_work_dispatch(&mut life, &inputs).expect("admit");
        let (action, stop_feed) = stock_fpga_revoke_work_dispatch(
            &mut life,
            DispatchRevocationCause::OperatorSafeOff,
            30,
        );
        assert!(stop_feed);
        assert!(power_precedes_fan_raise(&action.steps()));
        assert!(!life.is_admitted());
    }

    /// Structural pin: `StockMiner::run` must own the lifecycle and call the
    /// shipped admit/revoke adapters — not reimplement the matrix inline.
    #[test]
    fn stock_run_owns_lifecycle_and_calls_shipped_admit_revoke_adapters() {
        let src = include_str!("stock_mining.rs");
        assert!(
            src.contains("WorkDispatchLifecycle::new()"),
            "StockMiner::run must own a WorkDispatchLifecycle"
        );
        assert!(
            src.contains("stock_fpga_admit_standard_work_dispatch"),
            "run must call the shipped admit adapter before DHASH work"
        );
        assert!(
            src.contains("stock_fpga_revoke_work_dispatch"),
            "run must call the shipped revoke adapter"
        );
        assert!(
            src.contains("DispatchRevocationCause::HeartbeatFailure"),
            "mid-run PIC HB failure must terminal-revoke via HeartbeatFailure"
        );
        assert!(
            src.contains("DispatchRevocationCause::OperatorSafeOff"),
            "operator shutdown must revoke via OperatorSafeOff"
        );
        assert!(
            src.contains("if !dispatch_life.is_admitted()"),
            "DMA dispatch tick must fail-closed when not admitted"
        );
    }
}

#[cfg(test)]
mod energized_chain_mask_tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{clear_stock_chain_energized, mark_stock_chain_energized, stock_chain_bit};

    #[test]
    fn possible_energization_is_visible_before_command_outcome() {
        let mask = AtomicU32::new(0);
        // Admission precedes the multi-write command. An error or panic after
        // this point must retain possible-energization evidence.
        mark_stock_chain_energized(&mask, 6);

        assert_eq!(mask.load(Ordering::SeqCst), stock_chain_bit(6).unwrap());
        // Model an uncertain enable error followed by a failed compensating
        // disable: no clear occurs, so the panic/watchdog fallback remains armed.
        assert_eq!(mask.load(Ordering::SeqCst), stock_chain_bit(6).unwrap());

        // Only a completed disable clears ownership.
        clear_stock_chain_energized(&mask, 6);
        assert_eq!(mask.load(Ordering::SeqCst), 0);
        assert_eq!(stock_chain_bit(32), None);
    }

    #[test]
    fn retries_and_later_runs_evolve_without_a_stale_once_snapshot() {
        let mask = AtomicU32::new(0);
        mark_stock_chain_energized(&mask, 5);
        mark_stock_chain_energized(&mask, 6);
        mark_stock_chain_energized(&mask, 6);
        clear_stock_chain_energized(&mask, 5);
        mark_stock_chain_energized(&mask, 7);

        let expected = stock_chain_bit(6).unwrap() | stock_chain_bit(7).unwrap();
        assert_eq!(mask.load(Ordering::SeqCst), expected);

        clear_stock_chain_energized(&mask, 6);
        clear_stock_chain_energized(&mask, 7);
        assert_eq!(mask.load(Ordering::SeqCst), 0);
    }
}
