//! S17-family BM1397 native AM2/Zynq runtime and retained pure wire helpers.
//!
//! Campaign `2026-08-27-antminer17-unlock-armada` (agent B1, 2026-08-27).
//! The native lifecycle lives in `s17_native_runtime.rs`; factory EEPROM
//! defaults and raw-source provenance live in `s17_factory_profile.rs` and
//! .
//! This module owns the BM1397 family values:
//!
//! - **Geometry** (A1 §V2 + stock pattern files): S17/S17 Pro 3×48 (BHB07601),
//!   S17+ 3×65 (BHB07602), T17 3×30 (BHB07701), T17+ 3×44 (BHB07702 — 44, not
//!   45). Address stride `floor(256/N)`: 5/3/8/5.
//! - **UART plan**: 3 chains at the 115,740 default, upgraded through chain
//!   register `0x18` (MiscCtrl) — canonical operational word `0x0000_6031`
//!   (6.25 Mbaud, `dcentrald-silicon-profiles` SSOT). The factory-jig
//!   PLL3/FastUART pair (reg `0x68`/`0x28`) is an opt-in alternative.
//! - **Production controller frames** (R05-corrected): BOTH controller
//!   classes use the bytewise framed law `55 AA LEN CMD payload SUM_BE16` at
//!   bus0 `0x20|slot`; the dialect split is the SET_VOLTAGE payload width
//!   (G2a dsPIC `VV 00 00` LEN=7 vs G2b PIC16 `VV` LEN=5 — factory-jig
//!   `set_dsPIC33EP16GS202_voltage@23D40` vs `set_PIC16F1704_voltage@22AB8`),
//!   and the held plus-family production dispatch admits no `0x10` opcode at
//!   all, so rail selection is APW9-owned. APW9 is bus1 address0x10,
//!   per-byte register0x11, with SUM_LE16 (corrected against raw stock code).
//!   The pure wire layer lives in the `wire` leaf module (`s17_wire.rs`).
//! - **Work codec**: BM1397 serial job packet `14 + 4 + N×32` with 4-midstate
//!   AsicBoost (NOT BIP320 chip-side version rolling — baked-config note),
//!   wire job-id `+4 mod128`; the UIO executor retains the FPGA-reconstructed
//!   full16-bit work ID, including high bits across wire wrap.
//! - **Power ordering** (A1 §V3): soc/fpga → scan chains → GPIO907=0 → init
//!   PIC → working voltage → set-address → baud → frequency; reverse on
//!   power-down with PIC SAFE-OFF and GPIO907=1.
//!
//! ## Safety rules enforced here (verify on every edit)
//! - am2 hashboard EEPROM `0x50..=0x57` writes are denied at the HAL fabric;
//!   the denylist is registered before any wire access (rule
//!    #28).
//! - Native execution always refuses PIC fw0x86, loader mode and malformed
//!   replies; historical lab-only pure helpers do not grant native authority.
//! - SET_VOLTAGE is deferred until 5 stable heartbeat ticks (rule #24).
//! - No destructive PIC op (RESET `0x07` / JUMP `0x06` / ERASE `0x09` /
//!   SEND_DATA `0x14`) exists in this module (rule #29); a PIC16 seen in
//!   loader mode (`0xCC`) fails closed instead of jumping.
//! - Voltage executors are fail-closed: no reply ⇒ error + teardown, never a
//!   silent retry loop; heartbeats are bounded.
//! - Signed runtime-image admission and exact route composition (or an
//!   explicit compiled lab session) are adjudicated before watchdog arm. The native owner then independently
//!   checks EEPROM, cooling, controller replies and complete ASIC geometry.
//!
//! Host tests exercise real work/nonce/share correlation and failure cleanup.
//! No live S17-family unit has run this native implementation yet.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio_util::sync::CancellationToken;

use crate::config::DcentraldConfig;
use crate::runtime::safety_watchdog::{S17WatchdogRouteScope, SafetyLiveness, SafetyWatchdogOwner};
use dcentrald_hal::platform::HardwareMutationGateOwner;

#[path = "s17_native_runtime.rs"]
mod native;
pub(crate) use native::S17SafeOffEvidence;

/// Dependency-free wire-dialect leaf (controller frames, APW9 law, executor,
/// chain I/O seam, work ledger). R05 runtime lane moved the pure layer here so
/// `tests/r05_*.rs` can `#[path]`-include the exact production implementation
/// for captured-byte replay; the names below stay the module's public surface.
#[path = "s17_wire.rs"]
mod wire;
pub(crate) use wire::{
    apw9_dac_for_bitmain_cv, apw9_dac_for_volts, apw9_set_dac_frame, bm1397_chip_addr_from_nonce,
    bm1397_chip_index_from_nonce, build_bm1397_job_packet, clamp_pic_voltage_cv,
    discover_divisor, drain_commands, dspic_g2a_checksum, dspic_g2a_frame,
    dspic_g2a_get_version_frame, dspic_g2a_heartbeat_frame, dspic_g2a_read_pwm_duty_frame,
    dspic_g2a_read_rail_frame, dspic_g2a_safe_off_frame, dspic_g2a_set_voltage_frame, framed_reply,
    next_bm1397_job_id, pic16_g2b_get_version_frame, pic16_g2b_heartbeat_frame,
    pic16_g2b_safe_off_frame, pic16_g2b_set_voltage_frame, register_read, register_write,
    s17_pic_i2c_addr, work_queue_has_complete_frame_space, BM1397_JOB_HEADER, BM1397_JOB_PACKET_LEN,
    BM1397_MIDSTATE_SLOTS, ChainIo, REGISTER_WAIT, S17_APW9_DAC_SUBADDR, S17_APW9_I2C_ADDR,
    S17_BRING_UP_FREQ_MHZ, S17_BRING_UP_VOLTAGE_CV, S17_DEGRADED_DSPIC_FW,
    S17_EEPROM_WRITE_DENYLIST, S17_PIC16_LOADER_MODE_FW, S17_PIC_VOLTAGE_MAX_CV,
    S17_PIC_VOLTAGE_MIN_CV, S17_PSU_WATCHDOG_CMD_ABSENT, S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE,
    S17PicControllerClass, S17PicFirmwareState, S17PicWire, S17VoltageExecutor, WorkLedger,
};
#[cfg(test)]
pub(crate) use wire::MockS17PicWire;

#[derive(Debug)]
struct S17TerminalSafeOffError {
    source: anyhow::Error,
    _closeout: crate::runtime::safety_watchdog::WatchdogCloseoutReceipt,
}

impl std::fmt::Display for S17TerminalSafeOffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.source)
    }
}

impl std::error::Error for S17TerminalSafeOffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub(crate) fn is_terminal_safe_off_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<S17TerminalSafeOffError>().is_some())
}

fn terminal_safe_off_error(
    source: anyhow::Error,
    closeout: crate::runtime::safety_watchdog::WatchdogCloseoutReceipt,
) -> anyhow::Error {
    anyhow::Error::new(S17TerminalSafeOffError {
        source,
        _closeout: closeout,
    })
}

// ---------------------------------------------------------------------------
// Targets, geometry, hashboard identities
// ---------------------------------------------------------------------------

/// Promoted board targets (mirrors `s17_hybrid_admission`).
pub(crate) const S17_HYBRID_BOARD_TARGETS: [&str; 4] =
    ["am2-s17p", "am2-s17plus", "am2-t17", "am2-t17plus"];

/// Hashboard part number per target (A1 §V1 constants table).
pub(crate) fn s17_hashboard_part_number(board_target: &str) -> Option<&'static str> {
    match board_target {
        "am2-s17p" => Some("BHB07601"),
        "am2-s17plus" => Some("BHB07602"),
        "am2-t17" => Some("BHB07701"),
        "am2-t17plus" => Some("BHB07702"),
        _ => None,
    }
}

/// BM1397 chips per chain per target. T17+ is **44** (stock
/// `07702_pattern_44.txt`, VNish 3.0.5 factory tables — A1 §V2); a claim of 45
/// is refused, not rounded.
pub(crate) fn s17_chips_per_chain(board_target: &str) -> Option<u8> {
    match board_target {
        "am2-s17p" => Some(48),
        "am2-s17plus" => Some(65),
        "am2-t17" => Some(30),
        "am2-t17plus" => Some(44),
        _ => None,
    }
}

/// Address stride for a chain: `floor(256/N)` via the shared SSOT
/// (`dcentrald_common::bm1397plus_addr_interval`). 48→5, 65→3, 30→8, 44→5.
pub(crate) fn s17_addr_interval(board_target: &str) -> Option<u8> {
    s17_chips_per_chain(board_target).map(dcentrald_common::bm1397plus_addr_interval)
}

/// Chain count for the S17 family (3 hashboards per unit; A2 §2 SKU table).
pub(crate) const S17_CHAIN_COUNT: u8 = 3;

// ---------------------------------------------------------------------------
// UART / MiscCtrl ladder (A1 §V4)
// ---------------------------------------------------------------------------

/// Default chain link baud before the upgrade (stock 115200-class default;
/// A2 §2: VNish ladder starts at 115,740).
pub(crate) const S17_DEFAULT_BAUD: u32 = 115_740;

/// Operational baud after the MiscCtrl upgrade
/// (`dcentrald-silicon-profiles` `BM1397_OPERATIONAL_BAUD`).
pub(crate) const S17_OPERATIONAL_BAUD: u32 = 6_250_000;

/// Canonical MiscCtrl (chain register `0x18`) word for the operational baud
/// (`dcentrald-silicon-profiles` `BM1397_MISCCTRL_BAUD_VALUE`).
pub(crate) const S17_MISCCTRL_OPERATIONAL: u32 = 0x0000_6031;

/// Hot-start baud-reset MiscCtrl word (forces chips back toward the 115,740
/// domain; mirrors the FPGA driver `init_chain` step 0,
/// `dcentrald-asic/src/drivers/bm1397.rs`).
pub(crate) const S17_MISCCTRL_RESET_BAUD: u32 = 0x0000_7A31;

/// Factory-jig fast-UART alternative: PLL3 reg `0x68` word then FastUART
/// reg `0x28` word (`dcentrald_common` SSOT; opt-in via
/// `DCENT_AM2_S17_FAST_UART_PLL3`).
pub(crate) const S17_FAST_UART_REG68: u32 = dcentrald_common::BM1397_FAST_UART_PLL3_VALUE;
pub(crate) const S17_FAST_UART_REG28: u32 = dcentrald_common::BM1397_FAST_UART_CONFIG_VALUE;

/// Stock bmminer `dhash_chip_set_baud_v2` law for the chain MiscCtrl word
/// (A1 §V4): `conf_base | (baud > 3_000_000 ? bit16 : 0) |
/// (divider & 0x1F) << 8 | ((divider >> 5) & 0xF) << 24`.
///
/// Pure; the FPGA-side divider comes from the (unheld) `hal_conf.json`
/// per-host values, so live callers must measure it on the bench unit.
pub(crate) fn miscctrl_baud_word(conf_base: u32, baud_hz: u32, divider: u32) -> u32 {
    let high_speed = if baud_hz > 3_000_000 { 1u32 << 16 } else { 0 };
    conf_base | high_speed | ((divider & 0x1F) << 8) | (((divider >> 5) & 0xF) << 24)
}

/// Decode the high-speed bit the stock law encodes (inverse of
/// [`miscctrl_baud_word`] for the bit-16 field only).
pub(crate) fn miscctrl_high_speed_enabled(word: u32) -> bool {
    word & (1 << 16) != 0
}

// ---------------------------------------------------------------------------
// GPIO907 hashboard power (A1 §V3)
// ---------------------------------------------------------------------------

/// PSU/hashboard power gate GPIO (Zynq am2; HAL const
/// `dcentrald-hal/src/platform/zynq.rs`).
pub(crate) const S17_HASHBOARD_POWER_GPIO: u32 = 907;

/// GPIO907 value that turns hashboard power ON (A1 §V3: 0 = ON, 1 = OFF).
pub(crate) const S17_HASHBOARD_POWER_ON: u8 = 0;

/// GPIO907 value that turns hashboard power OFF.
pub(crate) const S17_HASHBOARD_POWER_OFF: u8 = 1;

/// One-second settle after the sysfs GPIO907 prologue (stock `power_on`
/// sleeps 1 s after value write).
pub(crate) const S17_GPIO907_SETTLE: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// PIC controller classes and byte-exact frames: moved to the `wire` leaf
// module (see the `pub(crate) use wire::{…}` re-exports above). The G2b
// SET_VOLTAGE frame is the jig-captured one-payload-byte form
// (`set_PIC16F1704_voltage@22AB8`); the production plus-family dispatch
// admits no 0x10 opcode, so rail selection stays APW9-owned.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// APW9 PSU DAC, voltage envelope and EEPROM denylist: moved to the `wire`
// leaf module (re-exported above).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Power ordering (A1 §V3)
// ---------------------------------------------------------------------------

/// Ordered power-up steps (stock `power_on` flow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S17PowerUpStep {
    SocAndFpgaInit,
    ScanChains,
    HashboardPowerOn,
    InitPic,
    WorkingVoltage,
    SetChipAddresses,
    BaudSwitch,
    FrequencyInit,
}

/// Ordered power-down steps: reverse of power-up, with the PIC SAFE-OFF
/// preceding the GPIO907 power cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S17PowerDownStep {
    FrequencyStop,
    HashboardReleaseSleep,
    VoltageDown,
    PicSafeOff,
    HashboardPowerOff,
}

impl S17PowerUpStep {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::SocAndFpgaInit => "soc_fpga_init",
            Self::ScanChains => "scan_chains",
            Self::HashboardPowerOn => "gpio907_power_on",
            Self::InitPic => "init_pic",
            Self::WorkingVoltage => "working_voltage",
            Self::SetChipAddresses => "set_chip_addresses",
            Self::BaudSwitch => "baud_switch",
            Self::FrequencyInit => "frequency_init",
        }
    }

    pub(crate) const fn order(self) -> u8 {
        match self {
            Self::SocAndFpgaInit => 0,
            Self::ScanChains => 1,
            Self::HashboardPowerOn => 2,
            Self::InitPic => 3,
            Self::WorkingVoltage => 4,
            Self::SetChipAddresses => 5,
            Self::BaudSwitch => 6,
            Self::FrequencyInit => 7,
        }
    }
}

impl S17PowerDownStep {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::FrequencyStop => "frequency_stop",
            Self::HashboardReleaseSleep => "hashboard_release_sleep",
            Self::VoltageDown => "voltage_down",
            Self::PicSafeOff => "pic_safe_off",
            Self::HashboardPowerOff => "gpio907_power_off",
        }
    }

    pub(crate) const fn order(self) -> u8 {
        match self {
            Self::FrequencyStop => 0,
            Self::HashboardReleaseSleep => 1,
            Self::VoltageDown => 2,
            Self::PicSafeOff => 3,
            Self::HashboardPowerOff => 4,
        }
    }
}

/// Canonical power-up order (A1 §V3: fpga/soc init → init_scan_exist_chain →
/// GPIO907=0 → init_pic → init_working_voltage → set addresses → baud switch →
/// freq init).
pub(crate) const S17_POWER_UP_ORDER: [S17PowerUpStep; 8] = [
    S17PowerUpStep::SocAndFpgaInit,
    S17PowerUpStep::ScanChains,
    S17PowerUpStep::HashboardPowerOn,
    S17PowerUpStep::InitPic,
    S17PowerUpStep::WorkingVoltage,
    S17PowerUpStep::SetChipAddresses,
    S17PowerUpStep::BaudSwitch,
    S17PowerUpStep::FrequencyInit,
];

/// Canonical power-down order (A1 §V3 power-down + work order: reverse with
/// PIC SAFE-OFF + GPIO907=1).
pub(crate) const S17_POWER_DOWN_ORDER: [S17PowerDownStep; 5] = [
    S17PowerDownStep::FrequencyStop,
    S17PowerDownStep::HashboardReleaseSleep,
    S17PowerDownStep::VoltageDown,
    S17PowerDownStep::PicSafeOff,
    S17PowerDownStep::HashboardPowerOff,
];

// ---------------------------------------------------------------------------
// BM1397 serial work codec: moved to the `wire` leaf module (re-exported
// above) so integration tests replay the production builders.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Env gates (family-scoped DCENT_AM2_S17_*; -style guard)
// ---------------------------------------------------------------------------

/// Family-scoped env-flag reader with the same truthy-value semantics as the
/// BM1362 engine's `am2_env_flag` (kept local so the BM1362 file stays
/// byte-stable).
pub(crate) fn s17_env_flag(name: &str) -> bool {
    dcentrald_common::lab_env::var(name)
        .map(|v| {
            matches!(
                v.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(false)
}

/// Opt in to the factory-jig PLL3/FastUART baud pair (reg 0x68/0x28).
/// Default OFF: the stock-proven path is the MiscCtrl `0x18` ladder.
pub(crate) const ENV_S17_FAST_UART_PLL3: &str = "DCENT_AM2_S17_FAST_UART_PLL3";

/// Opt in to serial work dispatch (BM1397 job packets over the chain UART)
/// instead of the FPGA work FIFO. Default OFF until bench proof.
pub(crate) const ENV_S17_SERIAL_WORK_DISPATCH: &str = "DCENT_AM2_S17_SERIAL_WORK_DISPATCH";

/// Skip the per-chain 115200 per-chip init pass. Default OFF (per-chip init
/// RUNS) — the AM2 chain-collapse lesson requires it.
pub(crate) const ENV_S17_SKIP_PER_CHIP_INIT: &str = "DCENT_AM2_S17_SKIP_PER_CHIP_INIT";

/// Lab-only trust of dsPIC fw=0x86 for voltage commands (rule #30). Default
/// OFF; refusing to combine with energization is enforced by the guard.
pub(crate) const ENV_S17_TRUST_DEGRADED_FW: &str = "DCENT_AM2_S17_TRUST_DEGRADED_FW";

/// Lab-only bench energization request. Signed native images obtain admission
/// from the verified image and exact route; the environment cannot grant it.
pub(crate) const ENV_S17_ALLOW_ENERGIZE: &str = "DCENT_AM2_S17_ALLOW_ENERGIZE";

/// Adjudicated recipe derived from the `DCENT_AM2_S17_*` env family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct S17Recipe {
    /// Baud mechanism: MiscCtrl `0x18` ladder (stock-proven default) or the
    /// factory-jig PLL3/FastUART pair (opt-in).
    pub fast_uart_pll3: bool,
    /// Serial work dispatch instead of the FPGA work FIFO.
    pub serial_work_dispatch: bool,
    /// Per-chip 115200 init pass skipped (guard-restricted).
    pub skip_per_chip_init: bool,
    /// dsPIC fw=0x86 trusted for voltage (lab only).
    pub trust_degraded_fw: bool,
    /// Hardware energization admitted (bench gate).
    pub allow_energize: bool,
}

/// Raw env snapshot for [`adjudicate_s17_recipe_from`] (injectable for tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct S17RecipeEnv {
    pub fast_uart_pll3: bool,
    pub serial_work_dispatch: bool,
    pub skip_per_chip_init: bool,
    pub trust_degraded_fw: bool,
    pub allow_energize: bool,
}

impl S17RecipeEnv {
    /// Read the real process environment.
    pub(crate) fn from_env() -> Self {
        Self {
            fast_uart_pll3: s17_env_flag(ENV_S17_FAST_UART_PLL3),
            serial_work_dispatch: s17_env_flag(ENV_S17_SERIAL_WORK_DISPATCH),
            skip_per_chip_init: s17_env_flag(ENV_S17_SKIP_PER_CHIP_INIT),
            trust_degraded_fw: s17_env_flag(ENV_S17_TRUST_DEGRADED_FW),
            allow_energize: s17_env_flag(ENV_S17_ALLOW_ENERGIZE),
        }
    }
}

/// Pure adjudication of the env family into a recipe; refuses known-bad
/// combinations ( pattern):
///
/// 1. Energizing with the per-chip init skipped — the AM2 chain-collapse
///    lesson: per-chip 115200 init is mandatory when energizing.
/// 2. Serial work dispatch with the per-chip init skipped — same root cause.
/// 3. Trusting degraded PIC firmware while energizing — the fw=0x86 state is
///    the proven corruption state; it must never see voltage commands outside
///    a read-only lab session.
/// 4. R05 (2026-09-11): `DCENT_AM2_S17_FAST_UART_PLL3` and
///    `DCENT_AM2_S17_SERIAL_WORK_DISPATCH` are REFUSED outright — the native
///    runtime positively discovers the observed divisor and dispatches
///    through the s17io FPGA work FIFO, and these two knobs were never wired
///    into it. A bench operator who set one got a silent no-op; a typed
///    pre-watchdog refusal replaces that footgun (launchers already scrub
///    both names, so no shipped image can trip this).
pub(crate) fn adjudicate_s17_recipe_from(flags: S17RecipeEnv) -> Result<S17Recipe> {
    let recipe = S17Recipe {
        fast_uart_pll3: flags.fast_uart_pll3,
        serial_work_dispatch: flags.serial_work_dispatch,
        skip_per_chip_init: flags.skip_per_chip_init,
        trust_degraded_fw: flags.trust_degraded_fw,
        allow_energize: flags.allow_energize,
    };
    if recipe.allow_energize && recipe.skip_per_chip_init {
        return Err(anyhow!(
            "S17 recipe guard: DCENT_AM2_S17_SKIP_PER_CHIP_INIT=1 cannot be combined with \
             energization (AM2 chain-collapse lesson: per-chip 115200 init is mandatory)"
        ));
    }
    if recipe.serial_work_dispatch && recipe.skip_per_chip_init {
        return Err(anyhow!(
            "S17 recipe guard: serial work dispatch requires the per-chip init pass \
             (DCENT_AM2_S17_SKIP_PER_CHIP_INIT must stay unset)"
        ));
    }
    if recipe.allow_energize && recipe.trust_degraded_fw {
        return Err(anyhow!(
            "S17 recipe guard: DCENT_AM2_S17_TRUST_DEGRADED_FW=1 is read-path lab-only and \
             cannot be combined with energization"
        ));
    }
    if recipe.fast_uart_pll3 {
        return Err(anyhow!(
            "S17 recipe guard: DCENT_AM2_S17_FAST_UART_PLL3 is not wired into the native \
             runtime — the runtime positively discovers the observed chain divisor, so the \
             factory-jig PLL3/FastUART ladder would be a silent no-op; refusing"
        ));
    }
    if recipe.serial_work_dispatch {
        return Err(anyhow!(
            "S17 recipe guard: DCENT_AM2_S17_SERIAL_WORK_DISPATCH is not wired into the native \
             runtime — the implemented work dispatch is the s17io FPGA work FIFO, so this knob \
             would be a silent no-op; refusing"
        ));
    }
    Ok(recipe)
}

/// Adjudicate native or lab energization. Called by `main.rs` BEFORE the
/// watchdog is armed: a refusal parks management-only with the API reachable
/// and no armed watchdog (no reboot loop).
///
/// `native_route_energize` is supplied only after startup joins signed image
/// admission with the exact S17 route. It is applied before recipe guards so
/// admitted native execution still refuses every incompatible lab recipe.
pub(crate) fn adjudicate_s17_energize_gate(
    native_route_energize: bool,
) -> Result<S17Recipe> {
    adjudicate_s17_energize_gate_from(S17RecipeEnv::from_env(), native_route_energize)
}

/// Pure form of [`adjudicate_s17_energize_gate`] (injectable for tests): the
/// admitted route is applied to `allow_energize` before combination guards; a
/// recipe with no energize admission at all is a refusal (park before the
/// watchdog arms), never a silent pass-through.
pub(crate) fn adjudicate_s17_energize_gate_from(
    mut flags: S17RecipeEnv,
    native_route_energize: bool,
) -> Result<S17Recipe> {
    flags.allow_energize = flags.allow_energize || native_route_energize;
    let recipe = adjudicate_s17_recipe_from(flags)?;
    if !recipe.allow_energize {
        return Err(anyhow!(
            "S17 energize refused: no admitted native route for hardware energization. \
             A signed runtime image must match this exact board target before startup. \
             Compiled lab builds may request a bench session with DCENT_AM2_S17_ALLOW_ENERGIZE=1."
        ));
    }
    Ok(recipe)
}

// ---------------------------------------------------------------------------
// Fail-closed typed voltage executor: moved to the `wire` leaf module
// (re-exported above). The mock transport for host tests lives in
// `tests/r05_support/s17_scripted_wire.rs` (ScriptedS17I2cWire) with
// NACK/flush-16-zeros accounting per the f04 fake-transport report §3.2.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Safety admission + miner
// ---------------------------------------------------------------------------

/// Watchdog bring-up grace before the first liveness kick is expected.
const S17_HYBRID_WATCHDOG_BRINGUP_GRACE: Duration = Duration::from_secs(180);

/// Pre-energize ownership bundle for one exact AM2/Zynq BM1397 hybrid run
/// (mirrors the BM1362 `S19jHybridSafetyAdmission` shape).
#[must_use = "S17 hybrid safety admission must be moved into exactly one mining lifecycle"]
pub(crate) struct S17HybridSafetyAdmission {
    route_admission: crate::s17_hybrid_admission::S17HybridRouteAdmission,
    runtime_profile: native::S17RuntimeProfile,
    runtime_fabric: Option<native::S17FabricIdentity>,
    watchdog: SafetyWatchdogOwner,
    watchdog_route_scope: S17WatchdogRouteScope,
    liveness: SafetyLiveness,
    hardware_mutation_owner: HardwareMutationGateOwner,
}

impl S17HybridSafetyAdmission {
    pub(crate) async fn start(
        config: &DcentraldConfig,
        runtime_dispatch_admission: crate::RuntimeDispatchAdmission,
        route_admission: crate::s17_hybrid_admission::S17HybridRouteAdmission,
    ) -> Result<Self> {
        let _protocol_admission = runtime_dispatch_admission
            .require_asic_protocol(
                crate::RuntimeDispatchKind::S17Hybrid,
                route_admission.board_target(),
                dcentrald_common::AsicProtocolIdentity::Bm1397,
            )
            .map_err(anyhow::Error::msg)?;

        // Profile resolution is a desk-data prerequisite, so missing/invalid
        // data is reported before a hardware watchdog can be armed.
        let runtime_profile = native::S17RuntimeProfile::load(route_admission.board_target())?;
        // Failed boot programming/missing clock visibility parks management
        // before watchdog arm. Retain the exact observed file owners for run.
        let runtime_fabric = native::S17FabricIdentity::open()?;
        let liveness = SafetyLiveness::default();
        let expected_liveness = Duration::from_secs_f32(config.thermal.pid_interval_s.max(1.0));
        let (mut watchdog, admission) = SafetyWatchdogOwner::start_before_energizing(
            &config.watchdog,
            if crate::firstlight_census::operation_requested() {
                S17_HYBRID_WATCHDOG_BRINGUP_GRACE.min(
                    crate::firstlight_census::initialization_remaining()?,
                )
            } else {
                S17_HYBRID_WATCHDOG_BRINGUP_GRACE
            },
            expected_liveness,
            liveness.clone(),
        )
        .await?;
        let receipt = admission.require_armed("s17-hybrid")?;
        let watchdog_route_scope = watchdog.claim_s17_route_scope().map_err(|error| {
            crate::runtime::safety_watchdog::watchdog_reset_pending_error(
                "s17-hybrid",
                format!("post-arm route-scope claim failed: {error:#}"),
            )
        })?;
        tracing::info!(
            requested_timeout_s = receipt.requested_timeout_s,
            effective_timeout_s = receipt.effective_timeout_s,
            kick_interval_s = receipt.kick_interval_s,
            board_target = route_admission.board_target(),
            "s17-hybrid: pre-energize watchdog ownership admitted"
        );

        Ok(Self {
            route_admission,
            runtime_profile,
            runtime_fabric: Some(runtime_fabric),
            watchdog,
            watchdog_route_scope,
            liveness,
            hardware_mutation_owner: HardwareMutationGateOwner::new_pending(),
        })
    }

    pub(crate) fn hardware_mutation_gate(&self) -> dcentrald_hal::platform::HardwareMutationGate {
        self.hardware_mutation_owner.gate()
    }
}

/// The BM1397 hybrid engine. Constructible only with the one-shot route +
/// safety admissions; [`S17HybridMiner::run`] executes native work/nonce/share
/// processing and performs a checked shutdown on cancellation or fault.
pub struct S17HybridMiner {
    safety_admission: Option<S17HybridSafetyAdmission>,
    config: DcentraldConfig,
    shutdown: CancellationToken,
    state_tx: Option<tokio::sync::watch::Sender<dcentrald_api::MinerState>>,
    /// Configured exact native-route admission threaded from main so run's
    /// recipe check sees the same authority as the pre-watchdog admission.
    energize_opt_in: bool,
}

impl S17HybridMiner {
    /// Construct the BM1397-only hybrid engine after composition admission.
    /// No hardware is opened here; rejecting before construction keeps every
    /// future mutation behind the same invariant.
    pub fn new(
        config: DcentraldConfig,
        shutdown: CancellationToken,
        safety_admission: S17HybridSafetyAdmission,
    ) -> Result<Self> {
        Ok(Self {
            safety_admission: Some(safety_admission),
            config,
            shutdown,
            state_tx: None,
            energize_opt_in: false,
        })
    }

    /// Thread the configured native-route admission adjudicated by main.
    pub fn with_energize_opt_in(mut self, energize_opt_in: bool) -> Self {
        self.energize_opt_in = energize_opt_in;
        self
    }

    /// Attach a live `MinerState` publisher (dashboard), mirroring the BM1362
    /// builder. Fail-closed: a closed channel only drops the publish.
    pub fn with_state_tx(
        mut self,
        state_tx: tokio::sync::watch::Sender<dcentrald_api::MinerState>,
    ) -> Self {
        self.state_tx = Some(state_tx);
        self
    }

    /// Execute the native S17 lifecycle: exact profile and EEPROM identity,
    /// serialized PIC/cooling/ASIC initialization, pool work and nonce/share
    /// validation, then a watchdog-issued physical shutdown transaction.
    pub async fn run(mut self) -> Result<()> {
        let safety = self
            .safety_admission
            .take()
            .ok_or_else(|| anyhow!("s17-hybrid run() entered twice"))?;
        let mut recipe_env = S17RecipeEnv::from_env();
        recipe_env.allow_energize = recipe_env.allow_energize || self.energize_opt_in;
        let recipe = adjudicate_s17_recipe_from(recipe_env)?;
        if !recipe.allow_energize {
            return Err(anyhow!(
                "s17-hybrid energize gate refused after watchdog arm — main.rs must adjudicate \
                 the gate before arming; this is an internal ordering bug"
            ));
        }

        native::run(self, safety).await
    }
}

// ---------------------------------------------------------------------------
// Host tests (desk-exact; no hardware)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s17_am2_baked_configs_validate_after_pool_and_start() {
        for (target, model, chips) in [
            ("am2-s17p", "s17pro", 48),
            ("am2-s17plus", "s17+", 65),
            ("am2-t17", "t17", 30),
            ("am2-t17plus", "t17+", 44),
            ("am2-s19pro", "s19pro", 114),
        ] {
            let text = if target == "am2-s19pro" {
                include_str!("../../configs/dcentrald_s19pro_am2_baked_default.toml")
            } else {
                include_str!("../../configs/dcentrald_s17pro_am2_baked_default.toml")
            };
            let mut config: crate::config::DcentraldConfig = toml::from_str(text).unwrap();
            config.mining.model = Some(model.into());
            config.mining.serial_chip_count = Some(chips);
            assert!(!config.mining.enabled);
            assert!(!config.has_configured_pool());
            config.validate().expect("idle image config");
            config.pool.url = "stratum+tcp://127.0.0.1:3333".into();
            config.pool.worker = "beta-test".into();
            config.mining.enabled = true;
            config.validate().expect("ordinary pool + Start is valid configuration");
            assert!(config.mining_start_enabled());
            if target == "am2-s19pro" {
                assert_eq!(config.mining.voltage_mv, 12800);
            } else {
                assert_eq!(config.mining.frequency_mhz, 100);
            }
        }
    }

    #[test]
    fn s17_native_route_requires_exact_target_carrier_and_chip() {
        use crate::daemon_lifecycle::PlatformIdentitySnapshot;
        use crate::runtime::hardware_info::OBSERVED_CONTROL_BOARD_ZYNQ_AM2;
        use crate::s17_hybrid_admission::admit_s17_hybrid_route;
        use dcentrald_common::AsicProtocolIdentity;

        // Route composition is an independent prerequisite. Production startup
        // must also join it with signed runtime-image admission before use.
        for target in S17_HYBRID_BOARD_TARGETS {
            let identity = PlatformIdentitySnapshot {
                declared_board_target: Some(target.into()),
                observed_board_target: None,
                board_desc: dcentrald_common::BoardDesc::lookup(target),
                declared_platform_marker: Some("zynq-bm3-am2".into()),
                declared_subtype: None,
                declared_psu_hardware_variant: None,
                observed_control_board: OBSERVED_CONTROL_BOARD_ZYNQ_AM2.into(),
            };
            let route = admit_s17_hybrid_route(
                &identity, crate::RuntimeDispatchKind::S17Hybrid,
                Some(AsicProtocolIdentity::Bm1397),
            ).expect("exact supported S17 route");
            assert_eq!(route.board_target(), target);
            for chip in [None, Some(AsicProtocolIdentity::Bm1362), Some(AsicProtocolIdentity::Bm1398)] {
                assert!(admit_s17_hybrid_route(
                    &identity, crate::RuntimeDispatchKind::S17Hybrid, chip,
                ).is_err());
            }
            let mut wrong_carrier = identity.clone();
            wrong_carrier.observed_control_board = "unobserved".into();
            assert!(admit_s17_hybrid_route(
                &wrong_carrier, crate::RuntimeDispatchKind::S17Hybrid,
                Some(AsicProtocolIdentity::Bm1397),
            ).is_err());
            let mut wrong_target = identity;
            wrong_target.declared_board_target = Some("am2-s17e".into());
            assert!(admit_s17_hybrid_route(
                &wrong_target, crate::RuntimeDispatchKind::S17Hybrid,
                Some(AsicProtocolIdentity::Bm1397),
            ).is_err());
        }
    }

    const SOURCE: &str = include_str!("s17_hybrid_mining.rs");

    // ---- energize gate three-state admission (2026-09) -----------------

    /// Missing native admission and no lab request refuse before watchdog arm.
    #[test]
    fn energize_gate_refuses_without_any_admission() {
        let err = adjudicate_s17_energize_gate_from(S17RecipeEnv::default(), false)
            .expect_err("no admission must refuse energize");
        let msg = format!("{err}");
        assert!(msg.contains("signed runtime image"), "{msg}");
        assert!(msg.contains("DCENT_AM2_S17_ALLOW_ENERGIZE"), "{msg}");
    }

    /// An admitted native route keeps the conservative production recipe.
    #[test]
    fn energize_gate_admits_native_route() {
        let recipe = adjudicate_s17_energize_gate_from(S17RecipeEnv::default(), true)
            .expect("admitted native route enables energize");
        assert!(recipe.allow_energize);
        assert!(!recipe.skip_per_chip_init);
        assert!(!recipe.trust_degraded_fw);
    }

    /// Native route admission is applied before the combination guards: the unit
    /// still refuses the known-bad recipe combinations exactly like a bench
    /// unit with DCENT_AM2_S17_ALLOW_ENERGIZE=1.
    #[test]
    fn energize_gate_native_route_still_hits_combination_guards() {
        let flags = S17RecipeEnv {
            skip_per_chip_init: true,
            ..S17RecipeEnv::default()
        };
        let err = adjudicate_s17_energize_gate_from(flags, true)
            .expect_err("native route + skip_per_chip_init must refuse");
        assert!(format!("{err}").contains("SKIP_PER_CHIP_INIT"), "{err}");

        let flags = S17RecipeEnv {
            trust_degraded_fw: true,
            ..S17RecipeEnv::default()
        };
        let err = adjudicate_s17_energize_gate_from(flags, true)
            .expect_err("native route + trust_degraded_fw must refuse");
        assert!(format!("{err}").contains("TRUST_DEGRADED_FW"), "{err}");
    }

    // ---- geometry ------------------------------------------------------

    #[test]
    fn s17_geometry_per_target_matches_stock_re() {
        // A1 §V1/§V2: pattern files 07601(48)/07602(65)/07701(30)/07702(44).
        for (target, chips, hashboard) in [
            ("am2-s17p", 48u8, "BHB07601"),
            ("am2-s17plus", 65, "BHB07602"),
            ("am2-t17", 30, "BHB07701"),
            ("am2-t17plus", 44, "BHB07702"),
        ] {
            assert_eq!(s17_chips_per_chain(target), Some(chips), "{target}");
            assert_eq!(
                s17_hashboard_part_number(target),
                Some(hashboard),
                "{target}"
            );
        }
        // Unknown targets resolve nothing (no prefix inheritance).
        assert_eq!(s17_chips_per_chain("am2-s19j"), None);
        assert_eq!(s17_hashboard_part_number("am2-s17e"), None);
    }

    #[test]
    fn t17plus_is_44_not_45() {
        // A1 §V2 (HIGH): stock `07702_pattern_44.txt` + VNish 3.0.5 factory
        // tables pin 3×44=132. The retired "45" operator note must not return.
        assert_eq!(s17_chips_per_chain("am2-t17plus"), Some(44));
        assert_ne!(s17_chips_per_chain("am2-t17plus"), Some(45));
        assert_eq!(s17_addr_interval("am2-t17plus"), Some(5)); // floor(256/44)
        assert_eq!(dcentrald_common::bm1397plus_addr_interval(45), 5);
        // But 45 is not a registered model geometry:
        assert!(!S17_HYBRID_BOARD_TARGETS
            .iter()
            .any(|t| s17_chips_per_chain(t) == Some(45)));
    }

    #[test]
    fn address_intervals_match_jig_formula() {
        for (target, interval) in [
            ("am2-s17p", 5u8),
            ("am2-s17plus", 3),
            ("am2-t17", 8),
            ("am2-t17plus", 5),
        ] {
            assert_eq!(s17_addr_interval(target), Some(interval), "{target}");
        }
    }

    // ---- UART / MiscCtrl ladder ----------------------------------------

    #[test]
    fn miscctrl_baud_word_encodes_the_stock_law() {
        // A1 §V4: bit16 set iff baud > 3,000,000; divider split across
        // bits 8-12 and 24-27.
        let low = miscctrl_baud_word(0x31, 115_740, 26);
        assert!(!miscctrl_high_speed_enabled(low));
        assert_eq!((low >> 8) & 0x1F, 26 & 0x1F);
        assert_eq!((low >> 24) & 0xF, 0);

        let high = miscctrl_baud_word(0x31, 6_250_000, 33); // divider spans the split
        assert!(miscctrl_high_speed_enabled(high));
        assert_eq!((high >> 8) & 0x1F, 33 & 0x1F); // 1
        assert_eq!((high >> 24) & 0xF, (33 >> 5) & 0xF); // 1

        // Boundary: exactly 3,000,000 stays low-speed; +1 goes high.
        assert!(!miscctrl_high_speed_enabled(miscctrl_baud_word(
            0, 3_000_000, 1
        )));
        assert!(miscctrl_high_speed_enabled(miscctrl_baud_word(
            0, 3_000_001, 1
        )));

        // conf_base bits pass through untouched.
        assert_eq!(miscctrl_baud_word(0x31, 115_740, 0) & 0xFF, 0x31);
    }

    #[test]
    fn canonical_miscctrl_and_baud_constants_match_silicon_profiles() {
        assert_eq!(S17_MISCCTRL_OPERATIONAL, 0x0000_6031);
        assert_eq!(S17_MISCCTRL_RESET_BAUD, 0x0000_7A31);
        assert_eq!(S17_OPERATIONAL_BAUD, 6_250_000);
        assert_eq!(S17_DEFAULT_BAUD, 115_740);
        assert_eq!(S17_FAST_UART_REG68, 0xC070_0111);
        assert_eq!(S17_FAST_UART_REG28, 0x0600_000F);
        // Cross-check against the silicon-profiles SSOT itself.
        assert_eq!(
            S17_MISCCTRL_OPERATIONAL,
            dcentrald_silicon_profiles::bm1397::BM1397_MISCCTRL_BAUD_VALUE
        );
        assert_eq!(
            S17_OPERATIONAL_BAUD,
            dcentrald_silicon_profiles::bm1397::BM1397_OPERATIONAL_BAUD
        );
    }

    #[test]
    fn gpio907_polarity_is_on_zero_off_one() {
        assert_eq!(S17_HASHBOARD_POWER_GPIO, 907);
        assert_eq!(S17_HASHBOARD_POWER_ON, 0);
        assert_eq!(S17_HASHBOARD_POWER_OFF, 1);
    }

    // ---- PIC frame fixtures (byte-exact, A3 §2) -------------------------

    #[test]
    fn dspic_g2a_checksum_law_matches_the_held_example() {
        // A1 §V3 held example: chain1/0x00A0 payload [A0 00 01] → 00 B8.
        let frame = dspic_g2a_frame(0x10, &[0xA0, 0x00, 0x01]);
        assert_eq!(
            frame,
            vec![0x55, 0xAA, 0x07, 0x10, 0xA0, 0x00, 0x01, 0x00, 0xB8]
        );
    }

    #[test]
    fn dspic_g2a_command_frames_are_byte_exact() {
        // A3 §2 table (payload [VV 00 00] form; checksum computed by the law).
        assert_eq!(
            dspic_g2a_set_voltage_frame(0xA0),
            vec![0x55, 0xAA, 0x07, 0x10, 0xA0, 0x00, 0x00, 0x00, 0xB7]
        );
        assert_eq!(
            dspic_g2a_safe_off_frame(),
            vec![0x55, 0xAA, 0x05, 0x15, 0x00, 0x00, 0x1A]
        );
        assert_eq!(
            dspic_g2a_heartbeat_frame(),
            vec![0x55, 0xAA, 0x04, 0x16, 0x00, 0x1A]
        );
        assert_eq!(
            dspic_g2a_get_version_frame(),
            vec![0x55, 0xAA, 0x04, 0x17, 0x00, 0x1B]
        );
        assert_eq!(
            dspic_g2a_read_rail_frame(),
            vec![0x55, 0xAA, 0x04, 0x29, 0x00, 0x2D]
        );
        assert_eq!(
            dspic_g2a_read_pwm_duty_frame(),
            vec![0x55, 0xAA, 0x04, 0x2B, 0x00, 0x2F]
        );
    }

    #[test]
    fn pic16_g2b_command_frames_are_byte_exact() {
        // Jig `set_PIC16F1704_voltage@22AB8` (S17/single-board-test.dec):
        // LEN=5, ONE payload byte, ck16 = 5 + 0x10 + VV (BE). The dsPIC
        // 3-byte form must NOT leak into the plus-family dialect.
        assert_eq!(
            pic16_g2b_set_voltage_frame(0x5A),
            vec![0x55, 0xAA, 0x05, 0x10, 0x5A, 0x00, 0x6F]
        );
        assert_ne!(
            pic16_g2b_set_voltage_frame(0x5A),
            dspic_g2a_set_voltage_frame(0x5A),
            "G2a and G2b SET_VOLTAGE frames are distinct dialects"
        );
        // Jig `enable_PIC16F1704_dc_dc@22E6C` / heart_beat / get_version:
        // same framed law, no-payload ops identical to the dsPIC class.
        assert_eq!(
            pic16_g2b_safe_off_frame(),
            vec![0x55, 0xAA, 0x05, 0x15, 0x00, 0x00, 0x1A]
        );
        assert_eq!(
            pic16_g2b_heartbeat_frame(),
            vec![0x55, 0xAA, 0x04, 0x16, 0x00, 0x1A]
        );
        assert_eq!(
            pic16_g2b_get_version_frame(),
            vec![0x55, 0xAA, 0x04, 0x17, 0x00, 0x1B]
        );
    }

    #[test]
    fn pic_addresses_are_20_or_chain_for_both_classes() {
        for chain in 0u8..8 {
            assert_eq!(s17_pic_i2c_addr(chain), 0x20 | (chain & 7));
        }
        assert_eq!(s17_pic_i2c_addr(0), 0x20);
        assert_eq!(s17_pic_i2c_addr(1), 0x21);
        assert_eq!(s17_pic_i2c_addr(2), 0x22);
        // Settle/pacing per class: both use the conservative 500 ms
        // production settle (G2a corrections table; G2b jig paces 100 ms
        // pre-read and production pacing is unheld — see wire leaf).
        assert_eq!(
            S17PicControllerClass::DsPicG2aFramed.settle_after_command(),
            Duration::from_millis(500)
        );
        assert_eq!(
            S17PicControllerClass::Pic16G2bFramed.settle_after_command(),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn controller_class_maps_the_board_desc_adjudication() {
        use dcentrald_common::VoltageControllerClass;
        assert_eq!(
            S17PicControllerClass::from_voltage_controller(VoltageControllerClass::DsPic33Ep),
            Some(S17PicControllerClass::DsPicG2aFramed)
        );
        assert_eq!(
            S17PicControllerClass::from_voltage_controller(VoltageControllerClass::Pic16F1704),
            Some(S17PicControllerClass::Pic16G2bFramed)
        );
        assert_eq!(
            S17PicControllerClass::from_voltage_controller(
                VoltageControllerClass::RuntimeDiscovered
            ),
            None
        );
    }

    // ---- APW9 PSU -------------------------------------------------------

    #[test]
    fn apw9_dac_law_boundaries() {
        // Held anchor: V = 17 → DAC 156 (A1 §V3).
        assert_eq!(apw9_dac_for_volts(17.0), 156);
        assert_eq!(apw9_dac_for_bitmain_cv(1700), 156);
        // Low-voltage clamp saturates at 0xFF (A1: clamp 0xFF).
        assert_eq!(apw9_dac_for_volts(14.24), 255);
        assert_eq!(apw9_dac_for_volts(10.0), 255);
        // High-voltage clamp saturates at 0.
        assert_eq!(apw9_dac_for_volts(21.36), 0);
        assert_eq!(apw9_dac_for_volts(25.0), 0);
        // Monotone non-increasing across the range.
        let mut last = 255u8;
        for tenths in 1424..=2136 {
            let dac = apw9_dac_for_volts(f64::from(tenths) / 100.0);
            assert!(dac <= last, "DAC increased at {tenths}cV");
            last = dac;
        }
    }

    #[test]
    fn apw9_frame_is_byte_exact_with_0x89_plus_dac_checksum() {
        assert_eq!(
            apw9_set_dac_frame(156),
            vec![0x55, 0xAA, 0x06, 0x83, 0x9C, 0x00, 0x25, 0x01] // CK = 0x89+0x9C = 0x125
        );
        assert_eq!(
            apw9_set_dac_frame(0),
            vec![0x55, 0xAA, 0x06, 0x83, 0x00, 0x00, 0x89, 0x00]
        );
        assert_eq!(S17_APW9_I2C_ADDR, 0x10);
        assert_eq!(S17_APW9_DAC_SUBADDR, 0x11);
    }

    #[test]
    fn no_psu_watchdog_command_exists_in_this_generation() {
        // A1 §V3: no 0x84 template anywhere in stock 17-family. The constant
        // exists to document the refusal; the module must never build a frame
        // with that opcode.
        assert_eq!(S17_PSU_WATCHDOG_CMD_ABSENT, 0x84);
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(
            !production.contains("apw9_watchdog"),
            "the APW9 watchdog opcode must not gain an executor"
        );
    }

    // ---- voltage envelope -------------------------------------------------

    #[test]
    fn pic_voltage_envelope_refuses_out_of_range() {
        assert_eq!(clamp_pic_voltage_cv(1850).unwrap(), 1850);
        assert_eq!(clamp_pic_voltage_cv(1800).unwrap(), 1800);
        assert_eq!(clamp_pic_voltage_cv(2100).unwrap(), 2100);
        assert!(clamp_pic_voltage_cv(1799).is_err());
        assert!(clamp_pic_voltage_cv(2101).is_err());
        assert!(clamp_pic_voltage_cv(1450).is_err());
        assert!(clamp_pic_voltage_cv(1370).is_err());
        assert_eq!(S17_BRING_UP_FREQ_MHZ, 500);
        assert_eq!(S17_BRING_UP_VOLTAGE_CV, 1850);
    }

    // ---- EEPROM denylist ---------------------------------------------------

    #[test]
    fn eeprom_write_denylist_is_50_through_57() {
        assert_eq!(
            S17_EEPROM_WRITE_DENYLIST,
            [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57]
        );
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(
            production.contains("S17_EEPROM_WRITE_DENYLIST"),
            "the denylist contract must stay referenced at the wire boundary"
        );
    }

    // ---- power ordering ------------------------------------------------------

    #[test]
    fn power_up_order_matches_the_stock_flow() {
        let labels: Vec<&str> = S17_POWER_UP_ORDER.iter().map(|s| s.label()).collect();
        assert_eq!(
            labels,
            vec![
                "soc_fpga_init",
                "scan_chains",
                "gpio907_power_on",
                "init_pic",
                "working_voltage",
                "set_chip_addresses",
                "baud_switch",
                "frequency_init",
            ]
        );
        let orders: Vec<u8> = S17_POWER_UP_ORDER.iter().map(|s| s.order()).collect();
        assert_eq!(orders, (0u8..8).collect::<Vec<_>>());
    }

    #[test]
    fn power_down_order_is_reverse_safe_off_last_steps() {
        let labels: Vec<&str> = S17_POWER_DOWN_ORDER.iter().map(|s| s.label()).collect();
        assert_eq!(
            labels,
            vec![
                "frequency_stop",
                "hashboard_release_sleep",
                "voltage_down",
                "pic_safe_off",
                "gpio907_power_off",
            ]
        );
        // The PIC SAFE-OFF must precede the hashboard power cut.
        let safe_off_pos = S17_POWER_DOWN_ORDER
            .iter()
            .position(|s| matches!(s, S17PowerDownStep::PicSafeOff))
            .unwrap();
        let power_off_pos = S17_POWER_DOWN_ORDER
            .iter()
            .position(|s| matches!(s, S17PowerDownStep::HashboardPowerOff))
            .unwrap();
        assert!(safe_off_pos < power_off_pos);
        // Frequency stop is the first thing down.
        assert!(matches!(
            S17_POWER_DOWN_ORDER[0],
            S17PowerDownStep::FrequencyStop
        ));
    }

    // ---- work codec -----------------------------------------------------------

    #[test]
    fn job_packet_is_146_bytes_with_four_padded_midstates() {
        let midstates = [[0xAAu8; 32]];
        let packet = build_bm1397_job_packet(
            0x07,
            &midstates,
            0x1234_5678,
            0xFFFF_001D,
            0x6789_ABCD,
            [0xDE, 0xAD, 0xBE, 0xEF],
        )
        .unwrap();
        assert_eq!(packet.len(), 146);
        assert_eq!(packet[0], 0x07); // job id
        assert_eq!(packet[1], 1); // num_midstates
        assert_eq!(packet[2..6], 0x1234_5678u32.to_le_bytes());
        assert_eq!(packet[6..10], 0xFFFF_001Du32.to_le_bytes());
        assert_eq!(packet[10..14], 0x6789_ABCDu32.to_le_bytes());
        assert_eq!(packet[14..18], [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(packet[18..50], [0xAA; 32]); // midstate 0
        assert_eq!(packet[50..146], [0x00; 96]); // zero-padded slots 1-3
    }

    #[test]
    fn job_packet_refuses_empty_and_overflowing_midstate_sets() {
        assert!(build_bm1397_job_packet(0, &[], 0, 0, 0, [0; 4]).is_err());
        let five = [[0u8; 32]; 5];
        assert!(build_bm1397_job_packet(0, &five, 0, 0, 0, [0; 4]).is_err());
        assert_eq!(BM1397_JOB_HEADER, 0x21);
        assert_eq!(BM1397_MIDSTATE_SLOTS, 4);
    }

    #[test]
    fn job_id_advances_plus_four_mod_128() {
        assert_eq!(next_bm1397_job_id(0), 4);
        assert_eq!(next_bm1397_job_id(4), 8);
        assert_eq!(next_bm1397_job_id(124), 0); // wraps mod 128
        let mut id = 0u8;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..32 {
            seen.insert(id);
            id = next_bm1397_job_id(id);
        }
        assert_eq!(seen.len(), 32); // full 4-stride cycle
    }

    #[test]
    fn nonce_chip_address_decoding_matches_the_driver() {
        // nonce bits [24:17] carry the chip address (drivers/bm1397.rs).
        let nonce = (0x2Au32 << 17) | 0x1234;
        assert_eq!(bm1397_chip_addr_from_nonce(nonce), 0x2A);
        assert_eq!(bm1397_chip_index_from_nonce(nonce, 5), 8); // 42/5
        assert_eq!(bm1397_chip_index_from_nonce(nonce, 3), 14); // 42/3
    }

    #[test]
    fn no_bip320_reconstruction_in_the_bm1397_lane() {
        // 4-midstate AsicBoost, not chip-side BIP320 version rolling.
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("bip320_reconstruct"));
        assert!(!production.contains("BIP320_VERSION_ROLLING_MASK"));
    }

    // ---- env guard --------------------------------------------------------------

    fn env(
        fast_uart: bool,
        serial: bool,
        skip_init: bool,
        degraded: bool,
        energize: bool,
    ) -> S17RecipeEnv {
        S17RecipeEnv {
            fast_uart_pll3: fast_uart,
            serial_work_dispatch: serial,
            skip_per_chip_init: skip_init,
            trust_degraded_fw: degraded,
            allow_energize: energize,
        }
    }

    #[test]
    fn recipe_guard_admits_the_proven_default_and_refuses_unwired_knobs() {
        assert!(adjudicate_s17_recipe_from(env(false, false, false, false, false)).is_ok());
        assert!(adjudicate_s17_recipe_from(env(false, false, false, false, true)).is_ok());
        // R05: the two never-wired opt-in knobs refuse instead of silently
        // no-oping (the runtime discovers the divisor and uses the FPGA FIFO).
        let err = adjudicate_s17_recipe_from(env(true, false, false, false, true)).unwrap_err();
        assert!(err.to_string().contains("FAST_UART_PLL3"), "{err}");
        let err = adjudicate_s17_recipe_from(env(false, true, false, false, true)).unwrap_err();
        assert!(err.to_string().contains("SERIAL_WORK_DISPATCH"), "{err}");
    }

    #[test]
    fn recipe_guard_refuses_known_bad_combos() {
        // (1) energize + skipped per-chip init.
        let err = adjudicate_s17_recipe_from(env(false, false, true, false, true)).unwrap_err();
        assert!(err.to_string().contains("chain-collapse"));
        // (2) serial dispatch + skipped per-chip init (no energize needed).
        let err = adjudicate_s17_recipe_from(env(false, true, true, false, false)).unwrap_err();
        assert!(err.to_string().contains("per-chip init pass"));
        // (3) degraded-fw trust + energize.
        let err = adjudicate_s17_recipe_from(env(false, false, false, true, true)).unwrap_err();
        assert!(err.to_string().contains("lab-only"));
    }

    // ---- fail-closed executor -------------------------------------------------

    fn ok(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        Ok(bytes.to_vec())
    }

    #[test]
    fn set_voltage_is_deferred_until_five_stable_heartbeats() {
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x05, 0x17, 0x82, 0x00, 0x9E]));
        for _ in 0..5 {
            wire.replies.push_back(ok(&[6, 0x16, 1, 0, 0, 0x1D]));
        }
        wire.replies.push_back(ok(&[0x10, 0x01]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 1, wire);
        assert!(executor.probe_firmware().is_ok());

        // Four heartbeats are not enough (rule #24).
        for _ in 0..4 {
            executor.heartbeat().unwrap();
        }
        let err = executor.set_voltage_code(0xA0).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        // The fifth stable heartbeat admits it, at 0x21 for chain 1.
        executor.heartbeat().unwrap();
        executor.set_voltage_code(0xA0).unwrap();
        let (addr, last) = executor.wire.log.last().unwrap();
        assert_eq!(last, &dspic_g2a_set_voltage_frame(0xA0));
        assert_eq!(*addr, 0x21);
    }

    #[test]
    fn degraded_dspic_firmware_is_refused_unless_lab_trusted() {
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x05, 0x17, 0x86, 0x00, 0xA2])); // fw=0x86
        for _ in 0..5 {
            wire.replies.push_back(ok(&[6, 0x16, 1, 0, 0, 0x1D]));
        }
        wire.replies.push_back(ok(&[0x10, 0x01]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire);
        assert_eq!(
            executor.probe_firmware().unwrap(),
            S17PicFirmwareState::DegradedDspic
        );
        for _ in 0..5 {
            executor.heartbeat().unwrap();
        }
        let err = executor.set_voltage_code(0xA0).unwrap_err();
        assert!(err.to_string().contains("0x86"));

        // Lab-only override still works (read-path lab session).
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x05, 0x17, 0x86, 0x00, 0xA2]));
        for _ in 0..5 {
            wire.replies.push_back(ok(&[6, 0x16, 1, 0, 0, 0x1D]));
        }
        wire.replies.push_back(ok(&[0x10, 0x01]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire)
            .with_trust_degraded_fw(true);
        executor.probe_firmware().unwrap();
        for _ in 0..5 {
            executor.heartbeat().unwrap();
        }
        assert!(executor.set_voltage_code(0xA0).is_ok());
    }

    #[test]
    fn pic16_loader_mode_is_always_refused_and_never_jumped() {
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x05, 0x17, 0xCC, 0x00, 0xE8])); // loader-mode version reply
        for _ in 0..5 {
            wire.replies.push_back(ok(&[6, 0x16, 1, 0, 0, 0x1D]));
        }
        wire.replies.push_back(ok(&[0x10]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::Pic16G2bFramed, 2, wire);
        assert_eq!(
            executor.probe_firmware().unwrap(),
            S17PicFirmwareState::LoaderMode
        );
        for _ in 0..5 {
            executor.heartbeat().unwrap();
        }
        let err = executor.set_voltage_code(0x5A).unwrap_err();
        assert!(err.to_string().contains("loader mode"));
        // No JUMP (0x06) / RESET (0x07) / ERASE (0x09) opcode was ever sent.
        for (_, frame) in &executor.wire.log {
            assert_ne!(frame.get(2), Some(&0x06));
            assert_ne!(frame.get(2), Some(&0x07));
            assert_ne!(frame.get(2), Some(&0x09));
        }
        let production = SOURCE.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("jump_to_app"));
        assert!(!production.contains("pic_reset"));
    }

    #[test]
    fn unprobed_firmware_refuses_voltage_even_after_heartbeats() {
        let mut wire = MockS17PicWire::default();
        for _ in 0..5 {
            wire.replies.push_back(ok(&[6, 0x16, 1, 0, 0, 0x1D]));
        }
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire);
        for _ in 0..5 {
            executor.heartbeat().unwrap();
        }
        let err = executor.set_voltage_code(0xA0).unwrap_err();
        assert!(err.to_string().contains("not probed"));
    }

    #[test]
    fn missing_set_voltage_reply_fails_closed() {
        // Exactly the probe + five heartbeat acks; the SET transaction then has
        // no scripted reply left, so the wire is silent (fail-closed teardown).
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x05, 0x17, 0x82, 0x00, 0x9E]));
        for _ in 0..5 {
            wire.replies.push_back(ok(&[6, 0x16, 1, 0, 0, 0x1D]));
        }
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire);
        executor.probe_firmware().unwrap();
        for _ in 0..5 {
            executor.heartbeat().unwrap();
        }
        assert!(executor.set_voltage_code(0xA0).is_err());
    }

    #[test]
    fn safe_off_is_always_available_and_first_in_teardown() {
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x15, 0x01]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire);
        executor.safe_off().unwrap();
        let (addr, frame) = &executor.wire.log[0];
        assert_eq!(*addr, 0x20);
        assert_eq!(frame, &dspic_g2a_safe_off_frame());
    }

    #[test]
    fn heartbeat_retry_is_bounded() {
        let mut wire = MockS17PicWire::default(); // no replies at all
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::Pic16G2bFramed, 0, wire);
        let err = executor.heartbeat_bounded(3).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(executor.wire.log.len(), 3, "exactly the bounded attempts");
    }

    #[test]
    fn malformed_version_replies_fail_closed() {
        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x99, 0x98]));
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::DsPicG2aFramed, 0, wire);
        assert!(executor.probe_firmware().is_err());

        let mut wire = MockS17PicWire::default();
        wire.replies.push_back(ok(&[0x17, 0x82])); // PIC16 expects exactly 1 byte
        let mut executor = S17VoltageExecutor::new(S17PicControllerClass::Pic16G2bFramed, 0, wire);
        assert!(executor.probe_firmware().is_err());
    }
}
