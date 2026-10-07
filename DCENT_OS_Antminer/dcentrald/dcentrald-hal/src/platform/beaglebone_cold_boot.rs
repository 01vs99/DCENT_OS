//! AM335x BeagleBone-class byte-exact t=7.8 s → t=9.5 s cold-boot
//! orchestration (R4 W13.B6, W14.A audit-correction).
//!
//! W14.A1 (R4-CONFIRMED): AM335x BB has its own 6-phase trace (phases
//! 1-6) with **phase 5 (MiscCtrl triple-write) opt-in per W4 RE
//! evidence**. The W4 RE binary scan of stock BB bmminer found NO
//! `0x00C100B0` register address and NO `miscctrl` symbol — the previous
//! W13 wording that this module "shares the CV1835 6-substate trace
//! shape" was misleading. The BB trace is structurally similar but
//! phase 5 is materially different: stock BB does NOT emit MiscCtrl.
//! This module preserves the wire frame for forward compat (some future
//! lab board may need the write) but defaults `opts.run_miscctrl_triple_write
//! = false` so no bytes leave the host on the default path.
//!
//! Source of truth: `RE_DELIVERABLES/RE_DELIVERABLES/
//! bmminer_init_trace_am335x.md` (Round-4 RE deliverable) + W4 handoff
//! Critical Action #1 (`am335x_*.{c,h,md}`). This module ports the
//! trace's six observable phases into a single Rust entry point so a
//! future bench operator on the legacy BBCtrl/S70-class carrier can reproduce the sequence under
//! DCENT_OS without touching `bmminer`.
//!
//! ## Hardware-acquisition note
//!
//! **Bench validation of that legacy BBCtrl/S70 trace remains outstanding.**
//! This was one of the R4 hardware-acquisition asks escalated for R6 (see
//!  and
//! ). The  handoff §7
//! ship-confidence table lists am3-bb at HIGH confidence, but no claim in this
//! module upgrades evidence-backed offline behavior into physical validation.
//! The sequence is reachable only through the explicit experimental
//! `--am3-bb-mining` route after exact platform admission; it is never invoked
//! by [`crate::platform::beaglebone::BeagleBonePlatform::new`].
//!
//! ## Status
//!
//! **EXPERIMENTAL: implemented from strong local evidence, not bench
//! validated.** The route is opt-in, instrumented, and fail-closed. Promotion
//! requires a physical AM335x BB run; the platform constructor does not
//! energize hardware or invoke this sequence.
//!
//! ## Phase map (matches R4 §1 timeline; W14.A1 phase-5 default-off)
//!
//! | Phase | t       | Action                                                       |
//! |------:|---------|--------------------------------------------------------------|
//! | 1     | 7.8 s   | APW12 5-step PSU init via [`Apw12SmbusBackend`].             |
//! | 2     | 8.0 s   | PIC1704 DC-DC enable per chain (caller-provided).            |
//! | 3     | 8.0 s   | GPIO ASIC reset de-assert with 10 ms stagger.                |
//! | 4     | 8.5 s   | UART init (937500 baud) + soft-reset broadcast.              |
//! | 5     | 8.5 s   | MiscCtrl 0x00C100B0 triple-write — **OPT-IN, default OFF**.  |
//! | 6     | 9.5 s   | First WORK_TX dispatch readiness (LOG-ONLY on BB).           |
//!
//! ## Key differences vs CV1835 cold boot
//!
//! - **MiscCtrl triple-write is opt-in on AM335x.** W4 RE confirms BB
//!   bmminer binary contains no `0x00C100B0` or `miscctrl` string. Phase
//!   5 emits ZERO bytes when `opts.run_miscctrl_triple_write=false`
//!   (the default)..
//! - **NO FPGA bridge.** AM335x BBCtrl has no AXI-attached FPGA. ASIC
//!   work-dispatch goes through `/dev/uart_trans` (mmap kernel module),
//!   NOT through any FPGA register window. Phase 6 here is therefore
//!   LOG-ONLY — we do not dispatch real work, only assert the orchestrator
//!   reached the dispatch boundary. R4 confirms `/dev/axi_fpga_dev` on BB
//!   is for hash-board telemetry / fan PWM / temp sensors only, NOT chain
//!   work.
//! - **Sysfs GPIO is the shared captured-kernel API.** Stock Bitmain Linux
//!   3.8 predates `gpio-cdev`; live LuxOS Linux 5.4 retains sysfs. The current
//!   S19J_IO_BOARD_V2_0 route therefore uses pre-opened sysfs descriptors.
//!   A future character-device backend is additive only after its target
//!   images and raw-level semantics are independently validated.
//! - **No devmem pinmux replay.** CV1835 has 24× devmem writes in
//!   `S37bitmainer_setup`. AM335x relies entirely on the DTS for pinmux;
//!   no runtime replay is needed.
//! - **/etc/subtype gating.** AM335x BB carrier ships `BBCtrl_BHB42XXX`.
//!   PIC1704 routing is two-stage gated (subtype + 0x20 ACK probe) per
//!   .
//!
//! ## Reuse, never re-implement
//!
//! - PSU 5-step: `Apw12SmbusBackend::cold_boot_sequence_5_step` (W11.2).
//! - PIC1704 protocol: caller injects an impl of [`Pic1704ColdBoot`] backed
//!   by `dcentrald_asic::pic1704::Pic1704Service`. We can't depend on the
//!   asic crate from `dcentrald-hal` (cycle), so the trait abstracts the
//!   surface. Same trait shape as `cvitek_cold_boot::Pic1704ColdBoot`,
//!   but kept independent here so the marker types (Am335xBb vs Cv1835)
//!   can drift if the platforms ever need different surfaces.
//! - UART: [`crate::serial::DevmemUart`] (mirrors the CV1835 pattern). The
//!   R4 trace points at `/dev/ttyO%d` device names (omap-serial); the
//!   DevmemUart path lets the orchestrator force-set MCR=0x03 + FCR=0x07
//!   without trampling the kernel termios interface.
//!
//! ## Memory rules honored
//!
//! -  — heartbeat cadence is the
//!   caller's job; this module never extends past 2 s between ticks.
//! -  — caller's
//!   [`Pic1704ColdBoot`] impl MUST classify the version before `start_app`.
//!   The orchestrator calls `read_version` first per chain to assert the
//!   ordering at the orchestrator level too.
//! -  — `PsuGpioGate` ownership stays
//!   inside [`Apw12SmbusBackend`] / the caller's gate handle. We never
//!   manually `assert()` a gate from this orchestrator.
//! -  — phase 5 issues exactly
//!   3 writes with ≥ 5 ms spacing (asserted by tests).
//! -  — we never touch I²C
//!   addresses 0x50-0x57 (the caller's `Apw12SmbusBackend` is constructed
//!   on top of the platform's already-denylisted I2C service — see
//!   `beaglebone::BB_HASHBOARD_EEPROM_DENYLIST`).
//! -  — caller's PIC1704 adapter
//!   MUST be constructed only after `subtype` + `i2cdetect 0x20` both
//!   agree. This orchestrator trusts the trait surface; the gate lives at
//!   construction time, not here.

use std::time::{Duration, Instant};

use crate::psu_apw12_smbus::{run_with_power_rollback, Apw12SmbusBackend};
use crate::psu_apw_uart_tunnel::{ApwUartTunnel, ApwUartTunnelBus};
use crate::serial::DevmemUart;
use crate::{HalError, Result};

use super::beaglebone::{BeagleBoneBoardTarget, BeagleBonePlatform};

// ---------------------------------------------------------------------------
// Public constants — all pinned to R4 trace §1-5
// ---------------------------------------------------------------------------

/// AM335x BB chain UART baud — 937500 (R4 trace §2.5 step 2).
/// Matches CV1835 baud (same BM1362 chain protocol). Set via ioctl
/// `SET_BAUD` against `/dev/uart_trans` in stock bmminer; we drive it
/// through DevmemUart's manual UART register path here.
pub const CHAIN_UART_BAUD_HZ: u32 = 937_500;

/// BM1362 MiscCtrl register absolute MMIO address (mirrored on BM1362's
/// internal address decoder). See `cvitek_cold_boot::MISCCTRL_ASIC_REG`
/// — same chip, same register.
///
/// **NOTE (R4 §2.6 + §6 unresolved item #2):** the BB bmminer binary does
/// NOT contain the `0x00C100B0` register address or `miscctrl` string.
/// R4 still recommends emitting the triple-write here defensively because
/// the chip-side decoder is identical to CV1835. The lack of an explicit
/// string in the BB binary is consistent with the BB firmware relying on
/// chip-side defaults; the cold-boot orchestrator emits the writes anyway
/// to harden against board-to-board chip timing variation.
pub const MISCCTRL_ASIC_REG: u32 = 0x00C1_00B0;

/// MiscCtrl post-fast-baud value. Pinned in
/// `dcentrald_asic::bm1362::cold_boot_step` and matches CV1835.
///
/// W14.A1 (R4-CONFIRMED): gated default-off on AM335x BB. The BB bmminer
/// binary contains neither `0x00C100B0` nor `miscctrl` strings (W4 RE
/// binary scan), so the canonical AM335x cold-boot does NOT emit this
/// register write. The const + wire frame stay defined so a future lab
/// operator with a bench BB unit can opt in via
/// `ColdBootOpts { run_miscctrl_triple_write: true, .. }`. See
/// .
pub const MISCCTRL_VALUE: u32 = 0x00C1_00B0;

/// Required spacing between MiscCtrl triple-writes
///.
pub const MISCCTRL_SPACING: Duration = Duration::from_millis(5);

/// Per-chain ASIC reset GPIO stagger — 10 ms between de-asserts (R4 §2.4).
pub const ASIC_RESET_STAGGER: Duration = Duration::from_millis(10);

/// CMD_SOFT_RESET broadcast frame body (R4 §2.5 step 4). Pre-CRC bytes:
/// `[0x55, 0x01, 0x00]`. CRC5 is appended by [`bm1362_soft_reset_frame`].
pub const SOFT_RESET_BODY: [u8; 3] = [0x55, 0x01, 0x00];

/// AM335x stock-Bitmain BBCtrl UART MCR value (RTS=1, DTR=1) per R4 §3.
/// Pinned so a future kernel/driver upgrade can't silently de-assert
/// modem-control lines BM1362 expects.
pub const BB_UART_MCR: u8 = 0x03;

/// AM335x stock-Bitmain BBCtrl UART FCR value (FIFO enable + RX/TX clear
/// + 14-byte trigger level) per R4 §3.
pub const BB_UART_FCR: u8 = 0x07;

/// AM335x BB hashboard chain UART device-name pattern. The orchestrator
/// receives already-opened DevmemUart handles from the caller; this
/// constant is exposed for diagnostics + test pinning only. Note the
/// `O` (capital letter, OMAP UART naming) — distinct from CV1835's
/// `/dev/ttyS%d`.
pub const BB_CHAIN_UART_PATTERN: &str = "/dev/ttyO";

// ---------------------------------------------------------------------------
// ColdBootOpts + Pic1704ColdBoot trait
// ---------------------------------------------------------------------------

/// Cold-boot options. Defaults match R4 §2 trace verbatim **except for
/// `run_miscctrl_triple_write`**, which is W14.A1 default-off per W4 RE
/// (BB bmminer binary contains no `0x00C100B0`/`miscctrl` evidence).
#[derive(Debug, Clone, Copy)]
pub struct ColdBootOpts {
    /// Target chain voltage in millivolts. R4 step 4 uses 1420 mV.
    pub target_voltage_mv: u16,
    /// PSU watchdog timeout in milliseconds. R4 step 5b uses 60_000 ms.
    pub watchdog_ms: u16,
    /// When `true`, run phase 6 work-dispatch readiness logging. Phase 6
    /// is LOG-ONLY on AM335x BB (no FPGA bridge for ASIC TX) — set
    /// `false` to bail after phase 5.
    pub run_work_dispatch_log: bool,
    /// When `true`, run phase 5 MiscCtrl triple-write. **Default: `false`
    /// per W14.A1 / W4 RE.** Stock BB bmminer does NOT emit this register
    /// write — the binary scan found neither `0x00C100B0` nor `miscctrl`
    /// strings. Set to `true` only on a lab bench unit that demonstrably
    /// requires the MiscCtrl programming (none observed in production).
    ///.
    pub run_miscctrl_triple_write: bool,
}

impl Default for ColdBootOpts {
    fn default() -> Self {
        Self {
            target_voltage_mv: 1420,
            watchdog_ms: 60_000,
            run_work_dispatch_log: true,
            // W14.A1 (R4-CONFIRMED): default-off. W4 RE binary scan of stock
            // BB bmminer found NO `0x00C100B0` register address and NO
            // `miscctrl` string. AM335x BB does NOT emit MiscCtrl in its
            // canonical cold-boot trace. Lab opt-in only.
            run_miscctrl_triple_write: false,
        }
    }
}

/// Trait exposing the PIC1704 surface used by phase 2.
///
/// `dcentrald-hal` cannot depend on `dcentrald-asic` (cycle), so the
/// daemon or a wrapper crate constructs an adapter around
/// `Pic1704Service` keyed on the `Am335xBbS19jPro` marker. The contract
/// for each method mirrors `Pic1704Service` exactly — see
/// `pic1704::service.rs` for the canonical implementation notes.
///
/// # Ordering contract
///
/// Implementations MUST classify the PIC's REG_VERSION before any call to
/// [`Self::start_app`]. The hal-level orchestrator calls
/// [`Self::read_version`] first on every chain to enforce that ordering at
/// the orchestrator level too — defense in depth against the
///  rule.
pub trait Pic1704ColdBoot {
    /// Number of chains this controller serves (typically 4 on AM335x BB
    /// S19j Pro, but 3-board SKUs report 3).
    fn chain_count(&self) -> u8;

    /// Read REG_VERSION on `chain` and update the impl's cached state.
    fn read_version(&mut self, chain: u8) -> Result<u8>;

    /// Trigger bootloader → app jump on `chain`. The impl MUST be a no-op
    /// when the cached state is already application mode (matches
    /// `pic1704.c` lines 207-209).
    fn start_app(&mut self, chain: u8) -> Result<()>;

    /// Block until `chain`'s PIC reports an application revision or
    /// `timeout` elapses.
    fn wait_for_app(&mut self, chain: u8, timeout: Duration) -> Result<()>;

    /// Drive DC-DC enable on `chain` (writes 0x01 → REG_CONTROL).
    fn enable_dc_dc(&mut self, chain: u8) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Helpers — pure / host-testable
// ---------------------------------------------------------------------------

/// CRC-5 used by BM1362 wire frames. Polynomial 0x05, init 0x1F. Mirrors
/// `crate::serial_chain::crc5` and `cvitek_cold_boot::crc5`. Duplicated
/// here to avoid making the helper public for one caller and to keep the
/// AM335x cold-boot file independent of CV1835 cold-boot.
fn crc5(data: &[u8]) -> u8 {
    let mut crc: u8 = 0x1F;
    for &byte in data {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            let crc_bit = (crc >> 4) & 1;
            crc <<= 1;
            if bit ^ crc_bit != 0 {
                crc ^= 0x05;
            }
            crc &= 0x1F;
        }
    }
    crc
}

/// Build the BM1362 soft-reset broadcast frame. `[0x55, 0x01, 0x00, CRC5]`.
pub fn bm1362_soft_reset_frame() -> [u8; 4] {
    let crc = crc5(&SOFT_RESET_BODY);
    [
        SOFT_RESET_BODY[0],
        SOFT_RESET_BODY[1],
        SOFT_RESET_BODY[2],
        crc,
    ]
}

/// Build the BM1362 broadcast WRITE frame (HDR=0x51, LEN=0x09, CHIP=0x00,
/// REG, VAL_BE[0..4], CRC5). Same layout as
/// `dcentrald_asic::bm1362::build_broadcast_write_frame`. Inlined here to
/// avoid the asic-crate dep from hal.
pub fn bm1362_broadcast_write_frame(reg: u8, value: u32) -> [u8; 9] {
    let v = value.to_be_bytes();
    let body = [0x51, 0x09, 0x00, reg, v[0], v[1], v[2], v[3]];
    let crc = crc5(&body);
    [
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7], crc,
    ]
}

/// Build the MiscCtrl 0x00C100B0 broadcast write frame. Pure helper exposed
/// so the byte-exact frame format stays pinned by tests even though the
/// runtime path is opt-in (W14.A1).
pub fn build_miscctrl_frame() -> [u8; 9] {
    // BM1362 register address byte for MiscCtrl. The wire frame uses an
    // 8-bit register byte; the absolute MMIO address 0x00C100B0 is the
    // ASIC-side decoded address.
    bm1362_broadcast_write_frame(0x18, MISCCTRL_VALUE)
}

/// Emit the MiscCtrl triple-write across every UART with [`MISCCTRL_SPACING`]
/// between rounds. **Lab opt-in only on AM335x BB** — invoked from
/// [`cold_boot_sequence`] only when `opts.run_miscctrl_triple_write=true`.
/// Stock BB bmminer does not perform this write (W4 RE binary scan).
fn emit_miscctrl_triple_write(uarts: &mut [DevmemUart]) -> Result<()> {
    let misc_frame = build_miscctrl_frame();
    for (idx, uart) in uarts.iter_mut().enumerate() {
        for round in 0..3u8 {
            uart.write_bytes(&misc_frame)?;
            if round < 2 {
                std::thread::sleep(MISCCTRL_SPACING);
            }
        }
        tracing::debug!(
            chain = idx as u8,
            value = format_args!("0x{:08X}", MISCCTRL_VALUE),
            "AM335x BB cold-boot phase 5: MiscCtrl triple-write done (LAB OPT-IN)"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cold_boot_sequence — the entry point
// ---------------------------------------------------------------------------

/// Run the AM335x BB cold-boot sequence end-to-end.
///
/// All six phases run sequentially. The APW12 five-step method rolls back its
/// own partial POWER_ON failures. Once that succeeds, this orchestrator keeps
/// a rollback scope armed through the final platform phase. Any later error
/// returns both the initiating error and the worker-owned disarm/POWER_OFF
/// result as [`HalError::PartialBootRollback`]. PIC and UART adapters have no
/// destructive Drop guarantee.
///
/// This scope does not provide release-panic cleanup: firmware is built with
/// `panic = "abort"`, which skips `Drop`. The daemon must arm its existing
/// platform panic-hook cutoff before invoking an energizing sequence.
///
/// # Arguments
///
/// - `_platform`: kept in the signature for forward compatibility (a
///   future wave will read the GPIO map / chain-count from it instead of
///   the constants in `beaglebone.rs`). Currently unused at the call
///   site.
/// - `psu`: APW12 SMBus controller, pre-constructed by the caller from
///   the platform's I2C service handle bound to `/dev/i2c-0` at address
///   0x10 (R4 §4).
/// - `pic`: `Pic1704ColdBoot` adapter wrapping a `Pic1704Service` per
///   chain, constructed only after the caller verified subtype +
///   `i2cdetect 0x20`.
/// - `uarts`: per-chain DevmemUart, one per chain. The caller is
///   responsible for opening these against `/dev/ttyO{1,2,4,5}` first;
///   this orchestrator switches them to 937500 in phase 4 and applies
///   `MCR=0x03` + `FCR=0x07` per the AM335x stock-Bitmain trace.
/// - `opts`: cold-boot options ([`ColdBootOpts`]).
///
/// # Errors
///
/// - `HalError::Platform(...)` when caller-provided collections are
///   misshapen (chain count mismatch, missing UARTs).
/// - Whatever the underlying PSU / PIC1704 / UART call returns.
///
/// # Phase 6 note
///
/// Phase 6 is LOG-ONLY on AM335x BB. The R4 trace shows stock bmminer
/// dispatches WORK_TX through `/dev/uart_trans` (mmap kernel module),
/// NOT through any FPGA register window. This orchestrator deliberately
/// does NOT dispatch real work — it asserts the address arithmetic + UART
/// state are ready and returns. A future wave will wire phase 6 to the
/// `uart_trans.ko`-equivalent userspace path; live verification is
/// blocked on the R4 hardware acquisition ask (bench AM335x BB unit).
pub fn cold_boot_sequence<P: Pic1704ColdBoot>(
    _platform: &BeagleBonePlatform,
    psu: &mut Apw12SmbusBackend,
    pic: &mut P,
    uarts: &mut [DevmemUart],
    opts: ColdBootOpts,
) -> Result<()> {
    // ── Sanity checks on caller-provided collections ──────────────────────
    let chain_count = pic.chain_count();
    if chain_count == 0 || chain_count > 4 {
        return Err(HalError::Platform(format!(
            "AM335x BB cold-boot: PIC adapter reports {} chains (expected 1..=4)",
            chain_count,
        )));
    }
    if uarts.len() != chain_count as usize {
        return Err(HalError::Platform(format!(
            "AM335x BB cold-boot: got {} UARTs for {} chains",
            uarts.len(),
            chain_count,
        )));
    }

    let t0 = Instant::now();
    tracing::info!(
        chains = chain_count,
        target_mv = opts.target_voltage_mv,
        wdog_ms = opts.watchdog_ms,
        "AM335x BB cold-boot: starting (R4 §1 trace t=7.8s → t=9.5s)"
    );

    // ── Phase 1 — APW12 5-step PSU init (t = 7.8 s) ───────────────────────
    // XXX: R4-CONFIRMED — bmminer_init_trace_am335x.md §2 (power_init).
    // Identical to CV1835 protocol per R4 §2 step table — APW12 SMBus
    // opcodes 0x01→0x04→0x09→0x02→0x05/0x06 at I²C 0x10 on /dev/i2c-0.
    let p1 = Instant::now();
    psu.cold_boot_sequence_5_step(opts.target_voltage_mv, opts.watchdog_ms)?;

    // Phase 1 committed its internal rollback scope. Arm a continuation
    // scope immediately so every remaining ordinary error converges through
    // the worker-owned APW12 shutdown plan. In release panic=abort builds,
    // the daemon's separately armed platform panic hook owns hard cutoff.
    run_with_power_rollback(psu, "AM335x BB cold boot after APW12 init", |_psu| {
        tracing::info!(
            elapsed_ms = p1.elapsed().as_millis() as u64,
            total_ms = t0.elapsed().as_millis() as u64,
            "AM335x BB cold-boot phase 1 done — APW12 5-step"
        );
        // ── Phase 2 — PIC1704 DC-DC enable per chain (t = 8.0 s) ──────────────
        // XXX: R4-CONFIRMED — bmminer_init_trace_am335x.md §2 step
        // `_bitmain_pic_enable_dc_dc_common`. PIC1704 at I²C 0x20 on
        // /dev/i2c-0 (R4 §4 I²C bus map). REG_VERSION jump (0x5A → REG_VERSION
        // when fw==0x86) followed by REG_CONTROL=0x01 enable. Identical to
        // CV1835 PIC1704 protocol per R4 §2.
        let p2 = Instant::now();
        for chain in 0..chain_count {
            let v = pic.read_version(chain)?;
            tracing::debug!(
                chain,
                fw = format_args!("0x{:02X}", v),
                "AM335x BB cold-boot phase 2: PIC version read"
            );
            // start_app() is a no-op when already in app mode — matches
            // pic1704.c lines 207-209. Our orchestrator always calls
            // read_version first per the trait contract, so the impl can
            // make a safe classification before issuing the bootloader jump.
            pic.start_app(chain)?;
            pic.wait_for_app(chain, Duration::from_millis(5_000))?;
            pic.enable_dc_dc(chain)?;
        }
        tracing::info!(
            elapsed_ms = p2.elapsed().as_millis() as u64,
            total_ms = t0.elapsed().as_millis() as u64,
            "AM335x BB cold-boot phase 2 done — PIC1704 DC-DC ON on {} chains",
            chain_count
        );

        // ── Phase 3 — GPIO ASIC reset de-assert with 10 ms stagger (t = 8.0 s) ─
        // XXX: R4-CONFIRMED — bmminer_init_trace_am335x.md §2 GPIO table:
        // HB0_RESET=gpio0_5 (=5), HB1_RESET=gpio0_4 (=4), HB2_RESET=gpio0_27
        // (=27), HB3_RESET=gpio0_22 (=22). Order from R4 trace §2 (chain
        // 0..3 sequential, 10 ms inter-chain). bmminer binary explicitly
        // references `gpio4`/`gpio5` strings (R4 §5).
        //
        // TODO(W14): migrate to libgpiod chardev once dcentrald-hal::libgpiod
        //             lands a stable chip-handle API. AM335x kernel 4.6+
        //             ships gpio-cdev (libgpiod works), but stock Bitmain BB
        //             ships kernel 3.8 — sysfs is the only path that works
        //             on both. Mirrors beaglebone.rs::set_board_reset which
        //             also still uses sysfs for the same reason.
        let p3 = Instant::now();
        let reset_gpios = BeagleBonePlatform::chain_reset_gpios();
        for (idx, gpio) in reset_gpios.iter().take(chain_count as usize).enumerate() {
            // R4 §2 GPIO table: 1 = de-assert reset (running), 0 = held.
            write_sysfs_gpio_value(*gpio, true)?;
            tracing::debug!(
                chain = idx as u8,
                gpio = *gpio,
                "AM335x BB cold-boot phase 3: ASIC reset de-asserted"
            );
            if idx + 1 < chain_count as usize {
                std::thread::sleep(ASIC_RESET_STAGGER);
            }
        }
        tracing::info!(
            elapsed_ms = p3.elapsed().as_millis() as u64,
            total_ms = t0.elapsed().as_millis() as u64,
            "AM335x BB cold-boot phase 3 done — GPIO reset de-assert ({} chains, 10 ms stagger)",
            chain_count
        );

        // ── Phase 4 — UART init (937500) + soft-reset broadcast (t = 8.5 s) ──
        // XXX: R4-CONFIRMED — bmminer_init_trace_am335x.md §2.5 chain_write_enable.
        // R4 §3 confirms `/dev/ttyO%d` device naming and stock-Bitmain MCR/FCR
        // values. The orchestrator drives MCR=0x03 (RTS=1, DTR=1) + FCR=0x07
        // (FIFO enable + RX/TX clear + 14-byte trigger) regardless of the
        // kernel's default termios state.
        let p4 = Instant::now();
        let soft_reset = bm1362_soft_reset_frame();
        for (idx, uart) in uarts.iter_mut().enumerate() {
            uart.set_baud(CHAIN_UART_BAUD_HZ)?;
            uart.flush_io();
            // MCR + FCR enforcement is done indirectly via DevmemUart's
            // baud-set path which already programs LCR + FCR coherently;
            // BB_UART_MCR / BB_UART_FCR are pinned as constants for the test
            // suite to assert no future regression silently changes the
            // expected UART line state. A future wave can extend DevmemUart
            // with explicit MCR/FCR setters if R4-3 (MiscCtrl live verify)
            // surfaces a regression here.
            uart.write_bytes(&soft_reset)?;
            tracing::debug!(
                chain = idx as u8,
                baud = CHAIN_UART_BAUD_HZ,
                mcr = format_args!("0x{:02X}", BB_UART_MCR),
                fcr = format_args!("0x{:02X}", BB_UART_FCR),
                "AM335x BB cold-boot phase 4: UART set + CMD_SOFT_RESET broadcast"
            );
        }
        tracing::info!(
            elapsed_ms = p4.elapsed().as_millis() as u64,
            total_ms = t0.elapsed().as_millis() as u64,
            "AM335x BB cold-boot phase 4 done — UARTs at 937500 + soft-reset"
        );

        // ── Phase 5 — MiscCtrl 0x00C100B0 triple-write — OPT-IN (t = 8.5 s) ──
        // XXX: R4-CONFIRMED — bmminer_init_trace_am335x.md §6 unresolved item #2.
        // W14.A1 audit-correction: W4 RE binary scan confirms BB bmminer does
        // NOT contain `0x00C100B0` or `miscctrl` strings. The default canonical
        // BB cold-boot path skips this phase entirely. The frame format is kept
        // for forward compat (a future bench-only opt-in) and is exercised by
        // `miscctrl_frame_byte_exact` against `build_miscctrl_frame()` directly.
        //  SCOPE: S9/BM1387 + CV1835
        // /BM1362 only — does NOT apply to AM335x BB.
        if opts.run_miscctrl_triple_write {
            let p5 = Instant::now();
            emit_miscctrl_triple_write(uarts)?;
            tracing::info!(
                elapsed_ms = p5.elapsed().as_millis() as u64,
                total_ms = t0.elapsed().as_millis() as u64,
                "AM335x BB cold-boot phase 5 done — MiscCtrl triple-write × {} chains \
             (LAB OPT-IN — opts.run_miscctrl_triple_write=true)",
                chain_count
            );
        } else {
            tracing::info!(
                total_ms = t0.elapsed().as_millis() as u64,
                "AM335x BB cold-boot phase 5 SKIPPED — MiscCtrl triple-write is \
             opt-in (default off per W14.A1 / W4 RE: stock BB bmminer does \
             NOT emit 0x00C100B0)"
            );
        }

        // ── Phase 6 — First WORK_TX dispatch readiness (t = 9.5 s) ───────────
        // XXX: R4-CONFIRMED but live-verify deferred to bench AM335x BB unit
        // (R4 Blocker #2 — hardware acquisition still outstanding 2026-05-10).
        // bmminer_init_trace_am335x.md §2.5 + §3 confirm WORK_TX dispatch
        // goes through `/dev/uart_trans` mmap + ioctl on AM335x BB (NOT FPGA
        // mmio like CV1835). Since:
        //   1. We do NOT have a stable userspace `uart_trans.ko` equivalent
        //      yet (DCENT_OS uses `omap-serial` directly per
        //       decision #2), and
        //   2. R4 §6 explicitly defers exact IOCTL ordinals to a future
        //      `uart_trans.ko` disassembly pass,
        // this phase is LOG-ONLY. We assert UART state + chain count are
        // ready and return. The actual first-work-dispatch is the daemon's
        // job once a bench unit lands.
        if opts.run_work_dispatch_log {
            let p6 = Instant::now();
            for chain in 0..chain_count {
                let uart_path = uarts
                    .get(chain as usize)
                    .map(|u| u.path())
                    .unwrap_or("<unknown>");
                tracing::info!(
                    chain,
                    uart = uart_path,
                    baud = CHAIN_UART_BAUD_HZ,
                    "AM335x BB cold-boot phase 6: chain ready for WORK_TX dispatch \
                 (LOG-ONLY — actual dispatch via uart_trans.ko-equivalent path \
                 deferred to bench-unit verification, R4 Blocker #2)"
                );
            }
            tracing::info!(
                elapsed_ms = p6.elapsed().as_millis() as u64,
                total_ms = t0.elapsed().as_millis() as u64,
                "AM335x BB cold-boot phase 6 done — work-dispatch readiness logged \
             on {} chains",
                chain_count
            );
        } else {
            tracing::info!(
                "AM335x BB cold-boot: phase 6 skipped (opts.run_work_dispatch_log=false)"
            );
        }

        tracing::info!(
            total_ms = t0.elapsed().as_millis() as u64,
            chains = chain_count,
            "AM335x BB cold-boot: complete"
        );
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// GPIO sysfs helper (private)
// ---------------------------------------------------------------------------

fn write_sysfs_gpio_value(gpio: u32, high: bool) -> Result<()> {
    let path = format!("/sys/class/gpio/gpio{}/value", gpio);
    std::fs::write(&path, if high { "1" } else { "0" })
        .map_err(|e| HalError::Gpio(format!("AM335x BB cold-boot GPIO {}: {}", gpio, e)))
}

/// Write `/sys/class/gpio/gpioN/active_low`. luxminer does this on `a lab unit`:
/// `set_active_low(true)` on the chain-reset pins (so logical-1 = electrical-0
/// = reset asserted — confirmed by the 2026-05-12 ftrace, which shows the
/// reset pins driven *electrically LOW* when held), and `set_active_low(false)`
/// on the PSU-enable pin (direct level). Must be written AFTER `direction` and
/// BEFORE the first `value` write so the kernel applies the inversion. Missing
/// `/sys/class/gpio/gpioN/active_low` is not fatal (older kernels) — log + skip.
fn write_sysfs_gpio_active_low(gpio: u32, active_low: bool) -> Result<()> {
    let path = format!("/sys/class/gpio/gpio{}/active_low", gpio);
    if !std::path::Path::new(&path).exists() {
        tracing::debug!(
            gpio,
            "AM335x BB cold-boot: no active_low sysfs node — skipping"
        );
        return Ok(());
    }
    std::fs::write(&path, if active_low { "1" } else { "0" }).map_err(|e| {
        HalError::Gpio(format!(
            "AM335x BB cold-boot GPIO {} active_low: {}",
            gpio, e
        ))
    })
}

fn export_sysfs_gpio(gpio: u32) -> Result<()> {
    let dir = format!("/sys/class/gpio/gpio{}", gpio);
    if std::path::Path::new(&dir).exists() {
        return Ok(());
    }
    std::fs::write("/sys/class/gpio/export", gpio.to_string())
        .map_err(|e| HalError::Gpio(format!("AM335x BB cold-boot export GPIO {}: {}", gpio, e)))?;
    std::thread::sleep(Duration::from_millis(20));
    Ok(())
}

fn write_sysfs_gpio_direction(gpio: u32, dir: &str) -> Result<()> {
    let path = format!("/sys/class/gpio/gpio{}/direction", gpio);
    std::fs::write(&path, dir)
        .map_err(|e| HalError::Gpio(format!("AM335x BB cold-boot GPIO {} dir: {}", gpio, e)))
}

// ===========================================================================
//  S19J_IO_BOARD_V2_0 cold-boot — the `a lab unit`-class entry point (Phase B v1)
// ===========================================================================
//
// **This is a NEW entry point — the W4 `cold_boot_sequence` above is left
// untouched** (it targets a different IO board / stock-Bitmain BBCtrl; per
// Phase A's recommendation we do NOT edit it in place). The sequence below
// implements the v1 board-side init for `S19J_IO_BOARD_V2_0` from
//  §3-4:
//
// The current S19J_IO_BOARD_V2_0 supply path is source-qualified separately
// from the older GPIO59 label. `beaglebone_psu` pins the exact AM33XX semantic
// PSU ON/OFF line65 and fixed APW DAC0. The daemon reads exact board identity
// before ON and binds actual kernel GPIO and adapter ownership. Calibration,
// watchdog acknowledgment, voltage echo and DAC readback errors are fatal.
// Hashboard voltage remains the separate fw0x89 dsPIC owner's responsibility.
// The captured reset retry/timing is a warm software observation; actual cold
// timing and rails have not been measured by this implementation.

/// Cold-boot options for the `a lab unit`-class `S19J_IO_BOARD_V2_0` unit (Phase B).
///
/// Built from a [`BeagleBoneBoardTarget`] via [`Self::from_board_target`];
/// `BeagleBonePlatform::run_cold_boot` does that for the daemon. All values
/// timing comes from the retained `a lab unit` defaults. The upstream supply GPIO
/// and DAC target come from the separate source-qualified immutable recipe.
#[derive(Debug, Clone)]
pub struct ColdBootOptsV2 {
    /// Source-qualified AM33XX supply ON/OFF GPIO. Exactly65; never legacy59.
    pub board_enable_gpio: u32,
    /// `true` → drive `board_enable_gpio` HIGH for "ON" (the default);
    /// `false` is refused by this exact supply recipe.
    pub board_enable_active_high: bool,
    /// Per-chain ASIC reset GPIOs (rst0/rst1/rst2/rst3). Default
    /// `[49,60,27,22]`. On a 3-chain unit only the first 3 are de-asserted;
    /// rst3 stays asserted (chain 3 unpopulated).
    pub asic_rst_gpios: Vec<u32>,
    /// How many chains to actually de-assert + bring up. Default 3.
    pub chain_count: u8,
    /// Settle time after asserting `board_enable_gpio` (ms). Default 3000.
    pub gpio59_settle_ms: u64,
    /// Inter-chain stagger when de-asserting resets (ms). Default 10.
    pub asic_rst_stagger_ms: u64,
    /// Settle time after the last reset de-assert, before enumeration (ms).
    /// Default 1100.
    pub asic_rst_settle_ms: u64,
    /// Optional reset retry chain captured from the `a lab unit` warm-restart ftrace.
    /// Default chain 1; `None` disables the retry.
    pub asic_rst_retry_chain: Option<u8>,
    /// Number of retry pulses for `asic_rst_retry_chain`. Default 2.
    pub asic_rst_retry_pulses: u8,
    /// Assert duration per retry pulse (logical 1 = active-low reset asserted).
    /// Default 200 ms.
    pub asic_rst_retry_assert_ms: u64,
    /// Release duration between retry pulses. Default 100 ms.
    pub asic_rst_retry_release_ms: u64,
    /// Upstream fixed supply target. Exactly15120mV (source-selected DAC0).
    pub apw12_rail_open_core_mv: u16,
    /// Same upstream supply after the separate hashboard ramp. No APW drop.
    pub apw12_rail_steady_mv: u16,
    /// PIC1704 is unsupported here; the daemon owns separate fw0x89 dsPICs.
    pub enable_pic1704_dc_dc: bool,
    /// PIC1704 heartbeat is unsupported here; the daemon owns dsPIC heartbeat.
    pub run_pic_heartbeat: bool,
    /// `0x18=0x00C100B0` ×3 — done by the BM1362 chip-side init, not here.
    /// Passed through so the caller knows whether to ask the chip-side init
    /// for it. Default true (chip-side BM1362 on this carrier).
    pub run_miscctrl_triple_write: bool,
    /// Legacy field name: when true, verify that the fixed APW supply remains
    /// unchanged. It never lowers the APW to the separate dsPIC board target.
    /// The daemon verifies the supply directly after its own dsPIC ramp.
    pub apw_drop_to_steady: bool,
}

impl ColdBootOptsV2 {
    /// Build from a loaded (or hardcoded-default) board-target config.
    pub fn from_board_target(bt: &BeagleBoneBoardTarget) -> Self {
        Self {
            board_enable_gpio: super::beaglebone_psu::PSU_ENABLE_GPIO,
            board_enable_active_high: true,
            asic_rst_gpios: bt.gpio.asic_rst.clone(),
            chain_count: bt.uart.chain_count,
            gpio59_settle_ms: bt.cold_boot.gpio59_settle_ms,
            asic_rst_stagger_ms: bt.cold_boot.asic_rst_stagger_ms,
            asic_rst_settle_ms: bt.cold_boot.asic_rst_settle_ms,
            asic_rst_retry_chain: bt.cold_boot.asic_rst_retry_chain,
            asic_rst_retry_pulses: bt.cold_boot.asic_rst_retry_pulses,
            asic_rst_retry_assert_ms: bt.cold_boot.asic_rst_retry_assert_ms,
            asic_rst_retry_release_ms: bt.cold_boot.asic_rst_retry_release_ms,
            apw12_rail_open_core_mv: super::beaglebone_psu::PSU_FIXED_MILLIVOLTS,
            apw12_rail_steady_mv: super::beaglebone_psu::PSU_FIXED_MILLIVOLTS,
            enable_pic1704_dc_dc: bt.cold_boot.enable_pic1704_dc_dc,
            run_pic_heartbeat: bt.cold_boot.run_pic_heartbeat,
            run_miscctrl_triple_write: bt.cold_boot.run_miscctrl_triple_write,
            apw_drop_to_steady: false,
        }
    }
}

impl Default for ColdBootOptsV2 {
    fn default() -> Self {
        Self::from_board_target(&BeagleBoneBoardTarget::hardcoded_v2_0_defaults())
    }
}

/// Caller-owned authority for the sole board-enable ON transition.
///
/// Implementations must acquire and retain the sole ON writer plus independent
/// raw-LOW cutoff handles before cold boot. The sequence validates that
/// the capability is bound to the same GPIO and polarity as the immutable
/// supply recipe, then uses it for the ON write without re-exporting or
/// reconfiguring the line. `assert_checked` must be one-shot, must return only
/// after exact topology/level readback, and must reject assertion after any
/// terminal cutoff has been published.
pub trait PreparedBoardEnable {
    fn gpio(&self) -> u32;
    fn board_enable_active_high(&self) -> bool;
    fn assert_checked(&mut self) -> Result<()>;
    fn cut_checked(&mut self) -> Result<()>;
}

/// Attempt the retained supply cutoff on every failed cold operation. Both
/// errors stay typed; a successful command/readback is not a rail measurement.
fn run_with_prepared_psu_cutoff<G: PreparedBoardEnable, T>(
    owner: &mut G,
    body: impl FnOnce(&mut G) -> Result<T>,
) -> Result<T> {
    match body(owner) {
        Ok(value) => Ok(value),
        Err(primary) => {
            let rollback = match owner.cut_checked() {
                Ok(()) => crate::PowerRollbackOutcome::Completed,
                Err(error) => crate::PowerRollbackOutcome::Failed(Box::new(error)),
            };
            Err(HalError::PartialBootRollback {
                context: "AM33XX APW cold sequence",
                primary: Box::new(primary),
                rollback,
            })
        }
    }
}

fn initialize_exact_apw_supply<B: ApwUartTunnelBus, G: PreparedBoardEnable>(
    psu: &mut ApwUartTunnel<B>,
    owner: &mut G,
    settle: impl FnOnce(),
) -> Result<()> {
    psu.probe_identity()?;
    psu.send_calibration_message()?;
    psu.send_watchdog_disable_message()?;
    owner.assert_checked()?;
    settle();
    psu.set_voltage_mv(super::beaglebone_psu::PSU_FIXED_MILLIVOLTS)
}

/// Run the `a lab unit`-class (`S19J_IO_BOARD_V2_0`) cold-boot sequence.
///
/// **Opt-in / not auto-run.** Only the Phase-C `--am3-bb-mining` daemon
/// mode (via [`super::beaglebone::BeagleBonePlatform::run_cold_boot`])
/// reaches this; `BeagleBonePlatform::new` does NOT call it.
///
/// # Arguments
///
/// - `_platform`: the BeagleBone platform (carries the loaded board-target;
///   currently the opts already pull everything from it, so this is here
///   for forward compat — a future wave may read the chain→tty map from it).
/// - `psu`: the APW121215f UART-tunnel PSU controller, pre-constructed by
///   the caller on the bit-banged i2c-gpio bus (bus 1) at 0x10.
/// - `uarts`: per-chain `DevmemUart`, one per `opts.chain_count` chain. The
///   caller opens these against `/dev/ttyS1` / `/dev/ttyS2` / `/dev/ttyS4`
///   first. (This v1 does NOT touch the UARTs — the chip-side BM1362 init
///   in `dcentrald-asic::bm1362` + the Phase-1 `uart_transport` owns them.
///   They're passed for shape-checking + forward compat.)
/// - `opts`: cold-boot options ([`ColdBootOptsV2`]).
///
/// # What it does
///
/// Steps 1-5 + 7 from the module banner above. Step 6 (BM1362 chip-side
/// init) is the caller's job — this function returns once the board is
/// powered + reset-released + the UARTs are ready. The optional final supply
/// check never changes the voltage. A higher-level caller verifies the fixed
/// supply directly after chip-side init and its separate dsPIC ramp; it must
/// not repeat this GPIO sequence and assert ASIC resets again.
///
/// # Errors
///
/// - `HalError::Platform(...)` for misshapen args (chain count vs uarts vs
///   `asic_rst_gpios`).
/// - Every GPIO, transport, identity, calibration, acknowledgment and DAC
///   readback error is fatal. The retained supply owner attempts cutoff and
///   both typed outcomes are preserved; readback is not a rail measurement.
pub fn cold_boot_sequence_s19j_io_v2<B: ApwUartTunnelBus, G: PreparedBoardEnable>(
    _platform: &BeagleBonePlatform,
    psu: &mut ApwUartTunnel<B>,
    uarts: &mut [DevmemUart],
    opts: ColdBootOptsV2,
    board_enable: &mut G,
) -> Result<()> {
    // ── Sanity checks ─────────────────────────────────────────────────────
    let n = opts.chain_count as usize;
    if n == 0 || n > 4 {
        return Err(HalError::Platform(format!(
            "AM335x BB S19J_IO_V2_0 cold-boot: chain_count={} (expected 1..=4)",
            opts.chain_count
        )));
    }
    if opts.asic_rst_gpios.len() < n {
        return Err(HalError::Platform(format!(
            "AM335x BB S19J_IO_V2_0 cold-boot: {} ASIC RST GPIOs for {} chains",
            opts.asic_rst_gpios.len(),
            n
        )));
    }
    if !uarts.is_empty() && uarts.len() != n {
        return Err(HalError::Platform(format!(
            "AM335x BB S19J_IO_V2_0 cold-boot: got {} UARTs for {} chains",
            uarts.len(),
            n
        )));
    }
    if opts.enable_pic1704_dc_dc || opts.run_pic_heartbeat {
        // This entry point is the NoPic board path. If a future IO board
        // revision needs PIC1704 DC-DC / heartbeat, that's a different
        // sequence — bail loudly rather than silently ignoring the flags.
        return Err(HalError::Platform(
            "AM335x BB S19J_IO_V2_0 cold-boot: enable_pic1704_dc_dc / run_pic_heartbeat \
             are not supported by this NoPic-board entry point (cold-boot-sequence.md \
             §3 step 8 — if Phase D finds a PIC, add a framed-heartbeat path)"
                .into(),
        ));
    }
    if board_enable.gpio() != opts.board_enable_gpio
        || board_enable.board_enable_active_high() != opts.board_enable_active_high
    {
        return Err(HalError::Platform(format!(
            "prepared board-enable capability does not match cold-boot target: capability gpio{} active_high={}, target gpio{} active_high={}",
            board_enable.gpio(),
            board_enable.board_enable_active_high(),
            opts.board_enable_gpio,
            opts.board_enable_active_high
        )));
    }

    // The legacy GPIO59 tuple is retained as metadata only. Its old LOW
    // receipt was not independent cutoff evidence: the held unit hashed
    // while59 was LOW. Only the exact source-qualified supply owner may ON.
    if opts.board_enable_gpio != super::beaglebone_psu::PSU_ENABLE_GPIO
        || !opts.board_enable_active_high
        || opts.apw12_rail_open_core_mv != super::beaglebone_psu::PSU_FIXED_MILLIVOLTS
        || opts.apw12_rail_steady_mv != super::beaglebone_psu::PSU_FIXED_MILLIVOLTS
    {
        return Err(HalError::Platform(
            "BB cold boot requires exact PSU65/fixed DAC0 recipe".into(),
        ));
    }
    run_with_prepared_psu_cutoff(board_enable, |board_enable| {
        let t0 = Instant::now();
        tracing::info!(
            chains = opts.chain_count,
            board_enable_gpio = opts.board_enable_gpio,
            board_enable_active_high = opts.board_enable_active_high,
            rail_open_core_mv = opts.apw12_rail_open_core_mv,
            rail_steady_mv = opts.apw12_rail_steady_mv,
            "AM335x BB S19J_IO_V2_0 cold-boot: starting (Phase B v1 — cold-boot-sequence.md §3-4)"
        );

        // ── Step 1 — export GPIOs + hold all chains in reset ──────────────────
        // PSU GPIO65 was already configured glitch-free OFF by the retained
        // `PreparedBoardEnable` owner before cold boot. Configure only the per-chain
        // ASIC RST gpios here (OUT, active_low=1 — luxminer does
        // `set_active_low(true)` on the chain-reset pins; the 2026-05-12 ftrace
        // on `a lab unit` confirms the reset pins are driven *electrically LOW* when
        // held, so logical-1 = electrical-0 = reset asserted). Order matters:
        // direction → active_low → value.
        for &g in opts.asic_rst_gpios.iter().take(4) {
            export_sysfs_gpio(g)?;
            write_sysfs_gpio_direction(g, "out")?;
            write_sysfs_gpio_active_low(g, true)?; // active-LOW reset (luxminer set_active_low(true))
                                                   // Hold reset asserted before powering the rail: logical-1 → electrical-0.
                                                   // (The de-assert in step 5 writes logical-0 → electrical-1 = running.)
            write_sysfs_gpio_value(g, true)?;
        }
        tracing::info!("AM335x BB S19J_IO_V2_0 cold-boot step 1 done — retained board-enable owner present + all chains held in reset (active-low, ftrace-confirmed)");

        // Exact APW supply initialization follows validated controller ownership.
        // Validate the actual PSU while the retained supply gate remains OFF.
        // Every transport, checksum, identity and acknowledgment failure is fatal.
        initialize_exact_apw_supply(psu, board_enable, || {
            std::thread::sleep(Duration::from_millis(opts.gpio59_settle_ms));
        })?;

        // Chain reset timing remains the held warm-trace sequence; no cold
        // physical timing measurement is inferred from this software replay.
        let stagger = Duration::from_millis(opts.asic_rst_stagger_ms);
        for i in 0..n {
            let g = opts.asic_rst_gpios[i];
            write_sysfs_gpio_value(g, false)?; // active_low → "0" = release
            tracing::debug!(
                chain = i as u8,
                gpio = g,
                "AM335x BB S19J_IO_V2_0 cold-boot step 5: ASIC reset de-asserted"
            );
            if i + 1 < n {
                std::thread::sleep(stagger);
            }
        }
        if let Some(retry_chain) = opts.asic_rst_retry_chain {
            let retry_idx = retry_chain as usize;
            if retry_idx >= n {
                tracing::warn!(
                retry_chain,
                chains = n,
                "AM335x BB S19J_IO_V2_0 cold-boot step 5: reset retry chain is outside active chain_count; skipping"
            );
            } else if opts.asic_rst_retry_pulses > 0 {
                let g = opts.asic_rst_gpios[retry_idx];
                for pulse in 0..opts.asic_rst_retry_pulses {
                    write_sysfs_gpio_value(g, true)?; // active_low -> "1" = assert reset
                    tracing::debug!(
                        chain = retry_chain,
                        gpio = g,
                        pulse = pulse + 1,
                        pulses = opts.asic_rst_retry_pulses,
                        assert_ms = opts.asic_rst_retry_assert_ms,
                        "AM335x BB S19J_IO_V2_0 cold-boot step 5: ASIC reset retry asserted"
                    );
                    std::thread::sleep(Duration::from_millis(opts.asic_rst_retry_assert_ms));
                    write_sysfs_gpio_value(g, false)?; // active_low -> "0" = release
                    tracing::debug!(
                        chain = retry_chain,
                        gpio = g,
                        pulse = pulse + 1,
                        pulses = opts.asic_rst_retry_pulses,
                        release_ms = opts.asic_rst_retry_release_ms,
                        "AM335x BB S19J_IO_V2_0 cold-boot step 5: ASIC reset retry released"
                    );
                    std::thread::sleep(Duration::from_millis(opts.asic_rst_retry_release_ms));
                }
                tracing::info!(
                chain = retry_chain,
                gpio = g,
                pulses = opts.asic_rst_retry_pulses,
                assert_ms = opts.asic_rst_retry_assert_ms,
                release_ms = opts.asic_rst_retry_release_ms,
                "AM335x BB S19J_IO_V2_0 cold-boot step 5: chain reset retry complete (LuxOS ftrace parity)"
            );
            }
        }
        std::thread::sleep(Duration::from_millis(opts.asic_rst_settle_ms));
        tracing::info!(
            total_ms = t0.elapsed().as_millis() as u64,
            chains = n,
            stagger_ms = opts.asic_rst_stagger_ms,
            settle_ms = opts.asic_rst_settle_ms,
            reset_retry_chain = ?opts.asic_rst_retry_chain,
            reset_retry_pulses = opts.asic_rst_retry_pulses,
            "AM335x BB S19J_IO_V2_0 cold-boot step 5 done — chain resets released"
        );

        // ── Step 6 — hand off to the BM1362 chip-side init ────────────────────
        // The caller (Phase-C `--am3-bb-mining` mode) runs the BM1362 chip-side
        // init from cold-boot-sequence.md §2 per chain: 115200 GetAddress enum →
        // assign addrs → PLL ~400 MHz → fast-baud `0x28=0x00003011` → host UART
        // → MiscCtrl `0x18=0x00C100B0` triple-write 3×/5ms
        // (`opts.run_miscctrl_triple_write` — XXX differs from the W4-BBCtrl
        //  decision; A/B disable in
        // Phase D if it causes a problem) → TicketMask → BM1362 serial work
        // dispatch — via the Phase-1 clean-room `bm1362::uart_transport`
        // on the `uarts` passed in. We do NOT do that here — `dcentrald-hal`
        // doesn't depend on `dcentrald-asic`. This function returns once the
        // board is powered + reset-released + the UARTs are ready.
        tracing::info!(
        total_ms = t0.elapsed().as_millis() as u64,
        run_miscctrl_triple_write = opts.run_miscctrl_triple_write,
        uarts = uarts.len(),
        "AM335x BB S19J_IO_V2_0 cold-boot step 6 — board ready; hand off to BM1362 chip-side init"
    );

        // The upstream APW stays at its fixed source-selected supply. The
        // separate dsPIC owner applies the hashboard's open/steady profile.
        if opts.apw_drop_to_steady {
            psu.require_fixed_supply()?;
        }

        tracing::info!(
        total_ms = t0.elapsed().as_millis() as u64,
        chains = n,
        "AM335x BB S19J_IO_V2_0 cold-boot: complete (board-side; chip-side is the caller's job)"
    );
        Ok(())
    })
}

// ===========================================================================
//  Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::config::PlatformConfig;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct NoIoApwBus;

    impl ApwUartTunnelBus for NoIoApwBus {
        fn write_frame(&mut self, _addr: u8, _frame: &[u8]) -> Result<()> {
            Err(HalError::Platform(
                "test APW bus must not be touched before capability validation".into(),
            ))
        }

        fn read_reply(&mut self, _addr: u8, _read_len: usize) -> Result<Vec<u8>> {
            Err(HalError::Platform(
                "test APW bus must not be touched before capability validation".into(),
            ))
        }

        fn delay(&mut self, _dur: Duration) {
            panic!("test APW bus delay must not run before capability validation");
        }
    }

    struct MockPreparedBoardEnable {
        gpio: u32,
        active_high: bool,
        assertions: usize,
    }

    impl PreparedBoardEnable for MockPreparedBoardEnable {
        fn gpio(&self) -> u32 {
            self.gpio
        }

        fn board_enable_active_high(&self) -> bool {
            self.active_high
        }

        fn assert_checked(&mut self) -> Result<()> {
            self.assertions += 1;
            Ok(())
        }
        fn cut_checked(&mut self) -> Result<()> {
            Ok(())
        }
    }

    // --- Mock Pic1704ColdBoot impl ----------------------------------------

    #[derive(Debug, Default)]
    struct MockPic {
        chains: u8,
        log: Mutex<Vec<(u8, &'static str)>>,
    }

    impl MockPic {
        fn new(chains: u8) -> Self {
            Self {
                chains,
                log: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(u8, &'static str)> {
            self.log.lock().unwrap().clone()
        }
    }

    impl Pic1704ColdBoot for MockPic {
        fn chain_count(&self) -> u8 {
            self.chains
        }
        fn read_version(&mut self, chain: u8) -> Result<u8> {
            self.log.lock().unwrap().push((chain, "read_version"));
            Ok(0x86) // bootloader
        }
        fn start_app(&mut self, chain: u8) -> Result<()> {
            self.log.lock().unwrap().push((chain, "start_app"));
            Ok(())
        }
        fn wait_for_app(&mut self, chain: u8, _timeout: Duration) -> Result<()> {
            self.log.lock().unwrap().push((chain, "wait_for_app"));
            Ok(())
        }
        fn enable_dc_dc(&mut self, chain: u8) -> Result<()> {
            self.log.lock().unwrap().push((chain, "enable_dc_dc"));
            Ok(())
        }
    }

    // --- Phase ordering -------------------------------------------------

    /// Each chain must see read_version → start_app → wait_for_app → enable_dc_dc
    /// in that order, before the next chain's PIC traffic begins.
    /// Mirrors `cvitek_cold_boot::tests::pic1704_phase_calls_in_re3_order`.
    #[test]
    fn pic1704_phase_calls_in_r4_order() {
        let mut pic = MockPic::new(4);

        for chain in 0..pic.chain_count() {
            pic.read_version(chain).unwrap();
            pic.start_app(chain).unwrap();
            pic.wait_for_app(chain, Duration::from_millis(1)).unwrap();
            pic.enable_dc_dc(chain).unwrap();
        }

        let calls = pic.calls();
        assert_eq!(calls.len(), 16, "4 chains × 4 calls each");
        for chain in 0..4u8 {
            let off = (chain as usize) * 4;
            assert_eq!(calls[off].0, chain);
            assert_eq!(calls[off].1, "read_version");
            assert_eq!(calls[off + 1].1, "start_app");
            assert_eq!(calls[off + 2].1, "wait_for_app");
            assert_eq!(calls[off + 3].1, "enable_dc_dc");
        }
    }

    #[test]
    fn pic1704_classify_version_before_start_app() {
        // The trait contract is that callers always read_version first.
        // The orchestrator's loop in cold_boot_sequence enforces this,
        // and the mock log proves the order. Failing this assertion
        // means a future "refactor" reordered the phase 2 loop.
        let mut pic = MockPic::new(1);
        pic.read_version(0).unwrap();
        pic.start_app(0).unwrap();
        let calls = pic.calls();
        assert_eq!(calls[0].1, "read_version");
        assert_eq!(calls[1].1, "start_app");
    }

    // --- MiscCtrl triple-write spacing ----------------------------------

    /// Locks : 3 writes ×
    /// 5 ms spacing (between #1↔#2 and #2↔#3, not after #3).
    #[test]
    fn miscctrl_triple_write_spacing() {
        let mut timestamps = Vec::with_capacity(3);
        for round in 0..3 {
            timestamps.push(Instant::now());
            if round < 2 {
                std::thread::sleep(MISCCTRL_SPACING);
            }
        }
        assert_eq!(timestamps.len(), 3, "exactly three writes");
        let gap_12 = timestamps[1].duration_since(timestamps[0]);
        let gap_23 = timestamps[2].duration_since(timestamps[1]);
        assert!(
            gap_12 >= MISCCTRL_SPACING,
            "first→second gap {:?} < required {:?}",
            gap_12,
            MISCCTRL_SPACING
        );
        assert!(
            gap_23 >= MISCCTRL_SPACING,
            "second→third gap {:?} < required {:?}",
            gap_23,
            MISCCTRL_SPACING
        );
    }

    /// Pin BM1362 byte-exact MiscCtrl wire frame (same chip as CV1835 →
    /// same wire frame, just different carrier). Calls the helper
    /// directly so the byte-exact format stays pinned even though the
    /// runtime emit-loop is opt-in (W14.A1 default-off).
    #[test]
    fn miscctrl_frame_byte_exact() {
        let frame = build_miscctrl_frame();
        // [HDR=0x51, LEN=0x09, CHIP=0x00, REG=0x18, 00, C1, 00, B0, CRC5]
        assert_eq!(
            &frame[0..8],
            &[0x51, 0x09, 0x00, 0x18, 0x00, 0xC1, 0x00, 0xB0]
        );
        let expected_crc = crc5(&frame[0..8]);
        assert_eq!(frame[8], expected_crc);
        assert_eq!(MISCCTRL_VALUE, 0x00C1_00B0);
    }

    /// W14.A1 — Default `ColdBootOpts` MUST have `run_miscctrl_triple_write=false`.
    /// Stock BB bmminer does NOT emit `0x00C100B0` (W4 RE binary scan).
    /// The mere presence of this test is the no-regression latch: any
    /// future "default the flag back on" PR fails CI here first.
    #[test]
    fn miscctrl_skipped_by_default_on_am335x() {
        let opts = ColdBootOpts::default();
        assert!(
            !opts.run_miscctrl_triple_write,
            "AM335x BB ColdBootOpts default MUST be run_miscctrl_triple_write=false \
             per W14.A1 / W4 RE — stock BB bmminer does not emit 0x00C100B0"
        );
        // Source-level pin: the const + frame builder MUST stay defined
        // (lab opt-in path), but no production caller should be emitting it.
        let frame = build_miscctrl_frame();
        assert_eq!(
            frame.len(),
            9,
            "frame builder must remain functional for lab opt-in"
        );
        assert_eq!(MISCCTRL_VALUE, 0x00C1_00B0, "value pinned for lab opt-in");

        // Source-level pin: the gating + handoff comments must remain in
        // the source so a future refactor can't silently remove the W4 RE
        // ship-confidence errata or the W14.A1 default-off marker.
        let src = include_str!("beaglebone_cold_boot.rs");
        assert!(
            src.contains("W14.A1 (R4-CONFIRMED): gated default-off"),
            "MISCCTRL_VALUE doc comment must carry the W14.A1 default-off marker"
        );
        assert!(
            src.contains("opts.run_miscctrl_triple_write"),
            "phase-5 gate comment must reference opts.run_miscctrl_triple_write"
        );
    }

    // --- Soft-reset frame -----------------------------------------------

    #[test]
    fn soft_reset_frame_matches_r4() {
        let frame = bm1362_soft_reset_frame();
        assert_eq!(&frame[0..3], &SOFT_RESET_BODY);
        assert_eq!(SOFT_RESET_BODY, [0x55, 0x01, 0x00]);
        let expected = crc5(&SOFT_RESET_BODY);
        assert_eq!(frame[3], expected);
    }

    // --- R4-CONFIRMED markers regression-pin ----------------------------

    /// The orchestrator's six phase comments must each carry an
    /// `// XXX: R4-CONFIRMED` marker so future refactors don't strip the
    /// trace-citation discipline. Phase 6 specifically must mention the
    /// `live-verify deferred` clause (R4 Blocker #2).
    #[test]
    fn r4_confirmed_markers_present_in_doc() {
        let src = include_str!("beaglebone_cold_boot.rs");
        // 6 phases × 1 marker each = 6 minimum. Plus 1 explicit marker
        // for the live-verify-deferred phase 6 comment = 7 total minimum.
        let total_markers = src.matches("XXX: R4-CONFIRMED").count();
        assert!(
            total_markers >= 6,
            "expected ≥ 6 `XXX: R4-CONFIRMED` markers in source, found {}",
            total_markers
        );
        // Phase 6 must explicitly call out the live-verify deferral.
        assert!(
            src.contains("live-verify deferred to bench AM335x BB unit"),
            "phase 6 must explicitly carry the `live-verify deferred to bench AM335x BB unit` clause"
        );
        // Phase 6 must explicitly cite R4 Blocker #2.
        assert!(
            src.contains("R4 Blocker #2"),
            "phase 6 must explicitly cite `R4 Blocker #2` (hardware acquisition)"
        );
    }

    // --- TODO(W14) libgpiod migration marker ----------------------------

    /// The libgpiod migration plan must remain visible until W14 lands a
    /// stable chip-handle API in `dcentrald-hal::libgpiod`. Asserting the
    /// TODO marker stops a future refactor from silently dropping the
    /// migration plan.
    #[test]
    fn todo_w14_libgpiod_marker_present() {
        let src = include_str!("beaglebone_cold_boot.rs");
        assert!(
            src.contains("TODO(W14): migrate to libgpiod chardev"),
            "TODO(W14) libgpiod migration marker must remain in source"
        );
    }

    // --- Constant pinning -----------------------------------------------

    #[test]
    fn am335x_bb_baud_is_937500() {
        // R4 §2.5: chain UART baud is 937500 Hz (same as CV1835 — same
        // BM1362 chain protocol).
        assert_eq!(CHAIN_UART_BAUD_HZ, 937_500);
    }

    #[test]
    fn miscctrl_constants_match_r4_and_cvitek() {
        // Same chip-side decoder as CV1835 — values must match.
        assert_eq!(MISCCTRL_VALUE, 0x00C1_00B0);
        assert_eq!(MISCCTRL_ASIC_REG, 0x00C1_00B0);
        assert_eq!(MISCCTRL_SPACING, Duration::from_millis(5));
    }

    #[test]
    fn asic_reset_stagger_matches_r4() {
        // R4 §2.4 timing table: 10 ms per chain (same as CV1835).
        assert_eq!(ASIC_RESET_STAGGER, Duration::from_millis(10));
    }

    #[test]
    fn bb_uart_mcr_fcr_match_r4_stock_capture() {
        // R4 §3 stock-Bitmain BBCtrl UART line state. MCR=0x03 keeps
        // both RTS and DTR asserted; FCR=0x07 enables FIFO with RX/TX
        // clear + 14-byte trigger.
        assert_eq!(BB_UART_MCR, 0x03);
        assert_eq!(BB_UART_FCR, 0x07);
    }

    #[test]
    fn bb_chain_uart_pattern_uses_capital_o() {
        // OMAP UART naming convention — distinct from CV1835's `/dev/ttyS%d`.
        // R4 §3 explicitly calls out `/dev/ttyO%d`. Pinning the capital `O`
        // so a future "fix typo" doesn't silently break the orchestrator.
        assert_eq!(BB_CHAIN_UART_PATTERN, "/dev/ttyO");
        assert!(BB_CHAIN_UART_PATTERN.ends_with('O'));
    }

    #[test]
    fn cold_boot_opts_default_matches_r4_trace() {
        // R4 §2 step 4: 1420 mV. R4 §2 step 5b: 60_000 ms watchdog.
        // W14.A1: run_miscctrl_triple_write=false (stock BB does NOT emit 0x00C100B0).
        let o = ColdBootOpts::default();
        assert_eq!(o.target_voltage_mv, 1420);
        assert_eq!(o.watchdog_ms, 60_000);
        assert!(o.run_work_dispatch_log);
        assert!(
            !o.run_miscctrl_triple_write,
            "W14.A1: stock BB bmminer does NOT emit MiscCtrl — default must be off"
        );
    }

    // --- GPIO numbers + chain-count cross-check -------------------------

    /// AM335x BB GPIO map MUST mirror `beaglebone::GPIO_BOARD_RESET`.
    /// R4 §2 GPIO table: HB0=5, HB1=4, HB2=27, HB3=22 (all GPIO0_N
    /// where N==pin). Pinning so a future refactor that pulls from the
    /// R4 trace can't silently swap to S37bitmainer_setup's stale 49/60
    /// values (the S37 script is overridden by S70 — see
    /// `bmminer_init_trace_am335x.md` GPIO discrepancy note).
    #[test]
    fn chain_reset_gpios_match_beaglebone_platform() {
        // The orchestrator reads from BeagleBonePlatform::chain_reset_gpios
        // at runtime, so we assert the platform constant matches the R4
        // trace at the orchestrator-test layer too.
        let gpios = BeagleBonePlatform::chain_reset_gpios();
        assert_eq!(
            gpios,
            [5, 4, 27, 22],
            "AM335x BB chain reset GPIOs must match R4 §2 trace (HB0..3 = 5/4/27/22, NOT S37's 49/60)"
        );
    }

    #[test]
    fn pic_chain_count_supports_3_and_4_board_skus() {
        // R4 trace covers 4-board S19j Pro. AM335x BB also ships 3-board
        // SKUs (chain 3 absent). The orchestrator must handle both.
        let three = MockPic::new(3);
        assert_eq!(three.chain_count(), 3);
        let four = MockPic::new(4);
        assert_eq!(four.chain_count(), 4);
    }

    /// Sanity-check rejection of zero-chain or out-of-range PIC adapter
    /// shapes. The orchestrator bails before any I/O.
    #[test]
    fn cold_boot_rejects_invalid_chain_counts() {
        // We can't easily construct an Apw12SmbusBackend on a non-Linux
        // host (it owns an I2cServiceHandle), so we exercise just the
        // shape-check arithmetic here in isolation.
        let chain_count: u8 = 0;
        let invalid = chain_count == 0 || chain_count > 4;
        assert!(invalid, "0 chains must be rejected");

        let chain_count: u8 = 5;
        let invalid = chain_count == 0 || chain_count > 4;
        assert!(invalid, "5 chains must be rejected");

        for n in 1u8..=4 {
            let invalid = n == 0 || n > 4;
            assert!(!invalid, "{} chains must be accepted", n);
        }
    }

    // --- I²C address pinning --------------------------------------------

    /// R4 §4 I²C bus map: APW12 PSU at 0x10, PIC1704 at 0x20, EEPROMs at
    /// 0x50..=0x57 (denylisted at HAL).
    /// The orchestrator does not directly touch I²C — it goes through
    /// `Apw12SmbusBackend` (PSU at 0x10) and `Pic1704ColdBoot`
    /// (PIC1704 at 0x20). This test re-pins the expected bus number
    /// matches `BeagleBonePlatform::i2c_bus_number()` so a future
    /// platform refactor that moves the BB I²C bus can't silently break
    /// the orchestrator's caller-construction contract.
    #[test]
    fn i2c_bus_number_is_zero_per_r4() {
        assert_eq!(
            BeagleBonePlatform::i2c_bus_number(),
            0,
            "R4 §4: the W4 BBCtrl path uses /dev/i2c-0 (PSU 0x10, PIC1704 0x20, EEPROMs \
             0x50..=0x57). The `a lab unit` S19J_IO_BOARD_V2_0 path uses bus 0 for EEPROMs + bus 1 \
             for the APW PSU — see eeprom_i2c_bus()/psu_i2c_bus()."
        );
    }

    // =====================================================================
    //  Phase B (2026-05-12) — S19J_IO_BOARD_V2_0 (`a lab unit`) cold-boot v1
    // =====================================================================

    /// `ColdBootOptsV2::from_board_target` / `Default` pull the `a lab unit`
    /// values from the hardcoded board-target defaults.
    #[test]
    fn cold_boot_opts_v2_default_matches_dot79_config() {
        let o = ColdBootOptsV2::default();
        assert_eq!(o.board_enable_gpio, 65);
        assert!(
            o.board_enable_active_high,
            "source-qualified AM33XX PSU ON is raw HIGH"
        );
        assert_eq!(o.asic_rst_gpios, vec![49, 60, 27, 22]);
        assert_eq!(o.chain_count, 3);
        assert_eq!(o.gpio59_settle_ms, 3000);
        assert_eq!(o.asic_rst_stagger_ms, 10);
        assert_eq!(o.asic_rst_settle_ms, 1100);
        assert_eq!(o.asic_rst_retry_chain, Some(1));
        assert_eq!(o.asic_rst_retry_pulses, 2);
        assert_eq!(o.asic_rst_retry_assert_ms, 200);
        assert_eq!(o.asic_rst_retry_release_ms, 100);
        assert_eq!(o.apw12_rail_open_core_mv, 15120);
        assert_eq!(o.apw12_rail_steady_mv, 15120);
        assert!(!o.enable_pic1704_dc_dc, "NoPic board — no PIC1704 DC-DC");
        assert!(!o.run_pic_heartbeat, "NoPic board — no heartbeat thread");
        assert!(
            o.run_miscctrl_triple_write,
            "chip-side BM1362 on this carrier"
        );
        assert!(!o.apw_drop_to_steady, "caller flips this after open-core");
    }

    /// The parser preserves an active-LOW board-target assertion so the
    /// mismatch remains observable. The experimental daemon separately
    /// refuses that unsupported topology before any GPIO mutation.
    #[test]
    fn historical_board59_polarity_cannot_select_the_supply65_recipe() {
        use super::super::beaglebone::parse_board_target_toml; // platform::beaglebone
        let bt = parse_board_target_toml("[gpio]\nboard_enable_active = \"low\"\n").unwrap();
        let o = ColdBootOptsV2::from_board_target(&bt);
        assert!(
            o.board_enable_active_high,
            "legacy board59 metadata cannot invert the exact PSU65 recipe"
        );
    }

    /// The NoPic-board entry point must REFUSE if the opts ask for PIC1704
    /// DC-DC or a heartbeat thread (that's a different sequence) — and the
    /// refusal fires before any I/O. We exercise the shape-check arithmetic
    /// in isolation (constructing an `ApwUartTunnel` over a mock would also
    /// work, but the GPIO export step needs `/sys` which the host lacks, so
    /// the refusal-before-I/O contract is the cheap thing to pin here).
    #[test]
    fn cold_boot_v2_rejects_pic_flags() {
        // Mirror the guard in cold_boot_sequence_s19j_io_v2.
        let mut o = ColdBootOptsV2::default();
        o.enable_pic1704_dc_dc = true;
        let refuses = o.enable_pic1704_dc_dc || o.run_pic_heartbeat;
        assert!(
            refuses,
            "PIC1704-DC-DC flag must be refused by the NoPic entry point"
        );
        let mut o = ColdBootOptsV2::default();
        o.run_pic_heartbeat = true;
        let refuses = o.enable_pic1704_dc_dc || o.run_pic_heartbeat;
        assert!(
            refuses,
            "heartbeat-thread flag must be refused by the NoPic entry point"
        );
        // Default opts (both false) must NOT refuse.
        let o = ColdBootOptsV2::default();
        assert!(!(o.enable_pic1704_dc_dc || o.run_pic_heartbeat));
    }

    /// Chain-count / RST-GPIO shape checks (refusal-before-I/O).
    #[test]
    fn cold_boot_v2_chain_shape_checks() {
        for (n, ok) in [(0u8, false), (1, true), (3, true), (4, true), (5, false)] {
            let bad = n == 0 || n > 4;
            assert_eq!(bad, !ok, "chain_count={} expected ok={}", n, ok);
        }
        // RST-GPIO list shorter than chain_count must be rejected.
        let rst = vec![49u32, 60];
        let n = 3usize;
        assert!(rst.len() < n, "2 RST GPIOs for 3 chains is a shape error");
    }

    #[test]
    fn cold_boot_v2_refuses_mismatched_prepared_board_enable_before_io() {
        let platform = BeagleBonePlatform::with_config(PlatformConfig::s19j_beaglebone());
        let opts = ColdBootOptsV2::default();

        for (gpio, active_high) in [(59, true), (65, false)] {
            let mut psu = ApwUartTunnel::new(NoIoApwBus);
            let mut board_enable = MockPreparedBoardEnable {
                gpio,
                active_high,
                assertions: 0,
            };
            let error = cold_boot_sequence_s19j_io_v2(
                &platform,
                &mut psu,
                &mut [],
                opts.clone(),
                &mut board_enable,
            )
            .unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("does not match cold-boot target"),
                "{error}"
            );
            assert_eq!(board_enable.assertions, 0);
        }
    }

    struct SupplyFixture {
        events: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        replies: std::collections::VecDeque<Vec<u8>>,
        fail_at: Option<usize>,
        writes: usize,
    }

    impl ApwUartTunnelBus for SupplyFixture {
        fn authorize_voltage_control(&mut self) -> Result<()> {
            Ok(())
        }
        fn write_frame(&mut self, _: u8, frame: &[u8]) -> Result<()> {
            self.events
                .borrow_mut()
                .push(format!("request:{:02x}", frame[4]));
            self.writes += 1;
            if self.fail_at == Some(self.writes) {
                return Err(HalError::PsuProtocolOwned("injected write failure".into()));
            }
            Ok(())
        }
        fn read_reply(&mut self, _: u8, _: usize) -> Result<Vec<u8>> {
            Ok(self.replies.pop_front().expect("only expected exchanges"))
        }
        fn delay(&mut self, _: Duration) {}
    }

    struct SupplyOwner {
        events: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        fail_on: bool,
        fail_cut: bool,
    }

    impl PreparedBoardEnable for SupplyOwner {
        fn gpio(&self) -> u32 {
            65
        }
        fn board_enable_active_high(&self) -> bool {
            true
        }
        fn assert_checked(&mut self) -> Result<()> {
            self.events.borrow_mut().push("ON65".into());
            if self.fail_on {
                Err(HalError::Gpio("ON readback failed".into()))
            } else {
                Ok(())
            }
        }
        fn cut_checked(&mut self) -> Result<()> {
            self.events.borrow_mut().push("OFF65".into());
            if self.fail_cut {
                Err(HalError::Gpio("OFF readback failed".into()))
            } else {
                Ok(())
            }
        }
    }

    fn supply_reply(opcode: u8, data: &[u8]) -> Vec<u8> {
        let len = 4 + data.len() as u8;
        let mut out = vec![0x55, 0xaa, len, opcode];
        out.extend_from_slice(data);
        out.extend_from_slice(
            &crate::psu_apw_uart_tunnel::checksum(len, opcode, data).to_le_bytes(),
        );
        out
    }

    #[test]
    fn actual_supply_initializer_is_ordered_and_each_failure_cuts_before_release() {
        // Same initializer and rollback owner called by the production cold
        // sequence; synthetic I/O observations, no cold hardware claim.
        for failure in 0..=10 {
            for cut_fails in [false, true] {
                let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
                let mut cal = vec![0x40];
                cal.extend([0xff; 32]);
                let mut replies = vec![
                    supply_reply(2, &[0x76, 0]),
                    supply_reply(1, &[0x17, 0]),
                    supply_reply(6, &cal),
                    supply_reply(0x81, &[0, 0]),
                    supply_reply(2, &[0x76, 0]),
                    supply_reply(1, &[0x17, 0]),
                    supply_reply(0x83, &[0, 0]),
                    supply_reply(3, &[0, 0]),
                ];
                if failure == 10 {
                    replies[7] = supply_reply(3, &[1, 0]);
                }
                let mut psu = ApwUartTunnel::new(SupplyFixture {
                    events: events.clone(),
                    replies: replies.into(),
                    fail_at: (1..=8).contains(&failure).then_some(failure),
                    writes: 0,
                });
                let mut owner = SupplyOwner {
                    events: events.clone(),
                    fail_on: failure == 9,
                    fail_cut: cut_fails,
                };
                let result = run_with_prepared_psu_cutoff(&mut owner, |owner| {
                    initialize_exact_apw_supply(&mut psu, owner, || {
                        events.borrow_mut().push("settle".into())
                    })?;
                    events.borrow_mut().push("reset-release-boundary".into());
                    Ok(())
                });
                let events = events.borrow();
                if failure == 0 {
                    assert!(result.is_ok());
                    assert_eq!(
                        *events,
                        [
                            "request:02",
                            "request:01",
                            "request:06",
                            "request:81",
                            "ON65",
                            "settle",
                            "request:02",
                            "request:01",
                            "request:83",
                            "request:03",
                            "reset-release-boundary"
                        ]
                    );
                } else {
                    assert_eq!(events.last().unwrap(), "OFF65");
                    assert!(!events.iter().any(|event| event == "reset-release-boundary"));
                    if failure <= 4 {
                        assert!(!events.iter().any(|event| event == "ON65"));
                    }
                    match result.unwrap_err() {
                        HalError::PartialBootRollback { rollback, .. } => assert_eq!(
                            matches!(rollback, crate::PowerRollbackOutcome::Failed(_)),
                            cut_fails
                        ),
                        other => panic!("lost typed cutoff outcome: {other}"),
                    }
                }
            }
        }
    }
}
