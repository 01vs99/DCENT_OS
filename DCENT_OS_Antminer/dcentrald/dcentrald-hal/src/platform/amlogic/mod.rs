//! Amlogic A113D platform implementation.
//!
//! The Amlogic A113D (aarch64, quad Cortex-A53) is used in newer Antminer models:
//!   - S19k Pro (BM1366, NoPic on the verified .78 am3-aml unit)
//!   - Exact S19 XP / S19j XP use110 BM1366 chips, protected factory identity
//!     and independently selected production PSU voltage controllers.
//!   - Exact S21, S21 Pro and S21 XP use BM1368/BM1370 and the independently
//!     traced production PSU voltage controller rather than a hashboard PIC.
//!   - T21 package evidence exists, but its controller/PIC/PSU profile is unresolved
//!   - L9 (Scrypt, with BM1491)
//!
//! Key differences from Zynq:
//!   - NO FPGA — ASIC communication via standard Linux serial ports
//!   - S19k: /dev/ttyS1, /dev/ttyS2, /dev/ttyS3 (`a lab unit` dmesg hash UARTs)
//!   - Exact S21/Pro/XP: physical1/2/3 -> /dev/ttyS3, /dev/ttyS2, /dev/ttyS1
//!   - GPIO via sysfs or /dev/mem for plug detect and board reset
//!   - Fan control via sysfs hwmon PWM
//!   - I2C via standard /dev/i2c-N
//!   - Native S19k/S21/Pro/XP voltage control uses the retained GPIO PSU service
//!
//! GPIO mapping (plug/reset/LED/fan verified on S21 at .135, 2026-04-11):
//!   - PLUG_DETECT: gpio439=CH0, gpio440=CH1, gpio441=CH2 (active HIGH, pulldown)
//!   - BOARD_RESET: gpio454=CH0, gpio455=CH1, gpio456=CH2 (active LOW = reset)
//!   - PSU_ENABLE:  gpio437 is **board_target scoped**. Never one Amlogic
//!     pin polarity. S19k and independently traced S21/Pro/XP: 0=ON, 1=OFF.
//!     Software readback is not a DMM rail measurement.
//!   - LED_RED:     gpio438, LED_GREEN: gpio453 (active HIGH)
//!   - FAN_TACH:    gpio447-450 (falling edge, 4 fans)
//!
//! Identification:
//!   - Has Micro USB port on faceplate
//!   - /dev/ttyS1 exists but /dev/uio0 does NOT
//!   - /sys/module/uart_trans does NOT exist (that's CVitek)
//!
//! # EEPROM write protection (W3.1, 2026-05-07)
//!
//! Hashboard EEPROMs on am3-aml (S21, S19j Pro Amlogic, S19K Pro) sit on
//! `/dev/i2c-0` at addresses 0x50..=0x57 (AT24C-class, one EEPROM per
//! hashboard slot). These store factory identity (model, serial, frequency
//! profile, defective-core map). Writes to this range are PROTECTED at the
//! HAL layer to prevent the .74 hb2-class corruption pattern that bricked
//! a unit on 2026-04-29 (post-PIC-RESET, the bus master scribbled bytes
//! into hb2's EEPROM along with the dsPIC fw=0x86 downgrade).
//!
//! The new BHB56902 hashboards on S19K Pro use a `0x05 0x11` EEPROM header
//! preamble (vs BHB42xxx-class `0x04 0x11` on am2 Zynq); both are protected
//! by the same write-deny because both store identity bytes that cannot be
//! reconstructed once corrupted.
//!
//! Reads at 0x50..=0x57 still work — only writes are blocked. This is
//! parity with the am2 hybrid path's `[0x50..=0x57]` denylist registered
//! by `s19j_hybrid_mining.rs`. S9 (am1-zynq) deliberately registers no
//! denylist because its 0x55-0x57 are PIC voltage controllers, not
//! EEPROMs — applying this list there would brick PIC writes.
//!
//! See: ,
//! ,
//! `dcentrald_api_types::EEPROM_WRITE_DENYLIST`.
//!
//! ## Sub-modules (W15.D, 2026-05-10)
//!
//! - [`vnish_state`] — Detects whether the live unit is running stock
//!   Bitmain `bmminer` or VNish `cgminer` userspace. Same A113D
//!   silicon, different firmware. NOT a 4th `Platform` enum variant
//!.
//! - [`vnish_cold_boot`] — Data-only port of the W4 VNish AML
//!   cold-boot phase machine + GPIO map (15 pins). Env-gated
//!   (`DCENT_AML_VNISH_ACCEPT_INFERRED=1`) and has no orchestrator
//!   wired in W15; the data lands first so a future bench-unit
//!   operator harness can reuse it.

pub mod classic_pic;
mod s19k_native_discovery;
pub mod s21_psu;
pub mod vnish_cold_boot;
pub mod vnish_state;

use dcentrald_common::amlogic_gpio437::{self, BootGpio437Policy, Gpio437DriveRecipe};
use std::collections::BTreeMap;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::config::{
    amlogic_tty_candidate_order, probe_tty_chain_device, ChainTransport, PlatformConfig,
    VoltageControllerKind,
};
use super::{BoardType, ChainAccess, FanAccess, GpioAccess, Platform};
use crate::i2c::{
    spawn_i2c_service_no_register_touch_with_denylist,
    spawn_owned_i2c_service_no_register_touch_with_denylist_and_reserved_preparation, I2cBus,
    I2cMutationLabel, I2cServiceCloseReceipt, I2cServiceHandle, I2cServiceOwner,
    I2cServiceTerminalFence, I2cTransactionStep, Lm75TemperatureRegister,
    TerminalSafeOffTransition,
};
use crate::serial::SerialChain;
use crate::{HalError, Result};
use dcentrald_common::s19k_am3_gpio437::{
    s19k_am3_fan_tach_sysfs_n, s19k_am3_led_sysfs_n, s19k_am3_pinmux_sysfs_n,
    s19k_am3_plug_sysfs_n, s19k_am3_pwr_control_sysfs_n, s19k_am3_reset_sysfs_n,
};

/// Bus protected by [`spawn_amlogic_protected_i2c0_service`].
///
/// CORRECTION (2026-07-27): this constant used to be documented as "the I²C bus
/// that carries hashboard EEPROMs on am3-aml". That was wrong. The am3-aml
/// hashboard EEPROMs answer on bus **1**, not bus 0 — see the evidence cited at
/// [`AmlogicPowerThermalService::spawn`], which is where the EEPROM denylist
/// actually has to be registered.
///
/// The name is therefore misleading, but the VALUE is correct and must stay `0`:
/// this constant selects the bus that `spawn_amlogic_protected_i2c0_service`
/// opens (called from `daemon.rs`), and it also drives a bus comparison further
/// down this module. Changing it to `1` would make that helper a *second* owner
/// of a bus already held under reservation by `AmlogicPowerThermalService` —
/// exactly the conflict the cross-process fabric lease exists to refuse.
/// Rename it if you like; do not repoint it.
pub const AMLOGIC_HASHBOARD_EEPROM_BUS: u8 = 0;

/// AT24C-class hashboard EEPROM addresses on am3-aml `/dev/i2c-0`.
///
/// Same range as am2 (0x50..=0x57) because both platform families wire one
/// 24Cxx-style EEPROM per hashboard slot to the standard 0x50 base address.
/// Reads (board identity, serial, frequency profile) still work — only
/// writes are refused at the bus layer. See module-level doc for rationale.
pub const AMLOGIC_EEPROM_DENYLIST: [u8; 8] = [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57];

/// Spawn the kernel-fd-only I²C service for `/dev/i2c-0` with the am3-aml
/// hashboard EEPROM write-deny range pre-registered.
///
/// This is the parity-with-am2 helper. The am2 hybrid path calls
/// `spawn_i2c_service_no_register_touch_with_denylist(0, 0x50..=0x57)`
/// directly; this helper exposes the same protection for am3-aml callers
/// (`daemon.rs::Daemon::run` and any future am3-aml mining path) without
/// re-stating the address range at every site.
///
/// Errors are propagated unchanged from the underlying spawn.
pub fn spawn_amlogic_protected_i2c0_service() -> std::io::Result<I2cServiceHandle> {
    let denylist: Vec<u8> = AMLOGIC_EEPROM_DENYLIST.to_vec();
    let handle =
        spawn_i2c_service_no_register_touch_with_denylist(AMLOGIC_HASHBOARD_EEPROM_BUS, denylist)?;
    tracing::info!(
        bus = AMLOGIC_HASHBOARD_EEPROM_BUS,
        denylist = ?AMLOGIC_EEPROM_DENYLIST
            .iter()
            .map(|a| format!("0x{:02X}", a))
            .collect::<Vec<_>>(),
        "am3-aml I2C service spawned with hashboard EEPROM write-deny (parity with am2 hybrid path)"
    );
    Ok(handle)
}

/// GPIO base for hash board plug detect: 439=CH0, 440=CH1, 441=CH2 (active HIGH).
/// Verified on live S21 at .135 (2026-04-11): CH1=1 (board present), CH0=CH2=0.
const GPIO_PLUG_BASE: u32 = 439;

/// GPIO base for hash board reset: 454=CH0, 455=CH1, 456=CH2 (active LOW = reset).
/// Verified on live S21 at .135: CH1_RST=1 (running), CH0=CH2=0.
const GPIO_RESET_BASE: u32 = 454;

/// GPIO base for fan tachometer inputs: 447, 448, 449, 450 (4 fans).
/// Each fan tach line generates a falling edge per pulse. Typical 4-pin
/// brushless DC fans emit 2 pulses per revolution (`PULSES_PER_REV`),
/// so RPM = falling_edges_per_second * 60 / 2 = falling_edges * 30
/// over a 1-second sample window. Verified GPIO map and
/// the AmlogicPlatform module header (S21 / S19j Pro Amlogic / S19K Pro
/// share this layout).
const GPIO_FAN_TACH_BASE: u32 = 447;
const GPIO_FAN_TACH_COUNT: usize = 4;

/// Pulses-per-revolution assumption for am3-aml fans. This matches the
/// industry-standard 4-pin BLDC fan spec and the bosminer/BraiinsOS
/// fan-tach divisor on the same hardware. If a future production fan
/// is sourced with a different ratio, this constant is the tunable.
const PULSES_PER_REV: u32 = 2;

/// Length of the falling-edge sample window. 1 second gives ~30 RPM
/// resolution at the 2 PPR ratio, which is well below the 300 RPM
/// "degraded" threshold and the 0 RPM FanFailure threshold. The
/// thermal controller ticks every 5 seconds, so a 1 s window leaves
/// 4 s slack for the rest of the loop.
const TACH_SAMPLE_MS: u64 = 1_000;

/// Amlogic A113D platform.
pub struct AmlogicPlatform {
    config: PlatformConfig,
}

/// File-backed Amlogic NoPic topology that may construct power, cooling, and
/// thermal owners. Miner configuration alone never grants this capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmlogicNoPicProfile {
    S19k,
    S21,
    /// Production BM1370 profile: A3HB70601/02, 65 chips per board.
    S21Pro,
    /// Production BM1370 profile: A3HB70501/02/03, 91 chips per board.
    S21Xp,
    /// Exact BHB56801/02 production profile, 110 BM1366 chips per board.
    S19Xp,
    /// Exact BHB56804 production profile, 110 BM1366 chips per board.
    S19jXp,
    /// Exact BHB42603/31/51 A126 production PSU-controlled profile.
    S19jProA,
    /// Exact BHB42612 Plus120 production PSU-controlled profile.
    S19jProPlus,
}

/// Held production formatter0x86452c, physical1/2/3 -> ttyS3/2/1.
pub const S21_UARTS: [&str; 3] = ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"];

const AML_BOOT_SAFE_RECEIPT: &str = "/run/dcentos/amlogic-boot-safe-state-v2";
const AML_BOOT_SAFE_SCHEMA: &str = "dcentos.amlogic-safe-state/v2";
const AML_BOOT_SAFE_RESOURCE: &str = "amlogic-gpio437-power-gate";
const AML_BOOT_FAN_DUTY_NS: u32 = 30_000;
const AML_BOOT_FAN_PERIOD_NS: u32 = 100_000;

/// Command/readback evidence emitted by the early Amlogic Linux owner and
/// revalidated immediately before the supervisor publishes dcentrald.
///
/// This is deliberately not named an electrical receipt: GPIO sysfs readback
/// proves only controller software state. Hardware promotion still requires
/// scoped pad/rail qualification across reset and brownout.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AmlogicBootSafeHandoff {
    boot_id: String,
    platform: String,
    board_target: String,
    psu_policy: BootGpio437Policy,
    fan0_duty_ns: u32,
    fan0_period_ns: u32,
    fan1_duty_ns: u32,
    fan1_period_ns: u32,
}

fn parse_amlogic_boot_safe_handoff(source: &str) -> Result<AmlogicBootSafeHandoff> {
    let mut fields = BTreeMap::new();
    for (index, line) in source.lines().enumerate() {
        let (key, value) = line.split_once('=').ok_or_else(|| {
            HalError::Platform(format!(
                "Amlogic boot-safe receipt line {} lacks key=value framing",
                index + 1
            ))
        })?;
        if key.is_empty() || value.is_empty() {
            return Err(HalError::Platform(format!(
                "Amlogic boot-safe receipt line {} has an empty key or value",
                index + 1
            )));
        }
        if fields.insert(key, value).is_some() {
            return Err(HalError::Platform(format!(
                "Amlogic boot-safe receipt repeats field {key:?}"
            )));
        }
    }

    const REQUIRED: &[&str] = &[
        "schema",
        "state",
        "boot_id",
        "platform",
        "board_target",
        "resource",
        "gpio_direction",
        "psu_polarity_class",
        "gpio_active_low",
        "commanded_value",
        "readback_value",
        "fan0_duty_ns",
        "fan0_period_ns",
        "fan0_enabled",
        "fan1_duty_ns",
        "fan1_period_ns",
        "fan1_enabled",
        "hashboard_reset_gpio454_direction",
        "hashboard_reset_gpio454_active_low",
        "hashboard_reset_gpio454_value",
        "hashboard_reset_gpio455_direction",
        "hashboard_reset_gpio455_active_low",
        "hashboard_reset_gpio455_value",
        "hashboard_reset_gpio456_direction",
        "hashboard_reset_gpio456_active_low",
        "hashboard_reset_gpio456_value",
        "hashboard_reset_low_bitmap",
        "evidence_grade",
        "physical_rail_measured",
    ];
    if fields.len() != REQUIRED.len() || REQUIRED.iter().any(|key| !fields.contains_key(key)) {
        return Err(HalError::Platform(
            "Amlogic boot-safe receipt fields do not match schema v2".into(),
        ));
    }
    let require = |key: &str, expected: &str| -> Result<()> {
        if fields.get(key).copied() == Some(expected) {
            Ok(())
        } else {
            Err(HalError::Platform(format!(
                "Amlogic boot-safe receipt {key} is {:?}, expected {expected:?}",
                fields.get(key)
            )))
        }
    };
    require("schema", AML_BOOT_SAFE_SCHEMA)?;
    require("state", "runtime-handoff")?;
    require("resource", AML_BOOT_SAFE_RESOURCE)?;
    require("gpio_active_low", "0")?;
    let psu_policy = amlogic_gpio437::resolve_boot_policy(fields["board_target"])
        .map_err(|cause| HalError::Platform(format!("GPIO437 boot target refused: {cause:?}")))?;
    validate_boot_psu_fields(&fields, psu_policy)?;
    require("fan0_enabled", "1")?;
    require("fan1_enabled", "1")?;
    require("hashboard_reset_gpio454_direction", "out")?;
    require("hashboard_reset_gpio454_active_low", "0")?;
    require("hashboard_reset_gpio454_value", "0")?;
    require("hashboard_reset_gpio455_direction", "out")?;
    require("hashboard_reset_gpio455_active_low", "0")?;
    require("hashboard_reset_gpio455_value", "0")?;
    require("hashboard_reset_gpio456_direction", "out")?;
    require("hashboard_reset_gpio456_active_low", "0")?;
    require("hashboard_reset_gpio456_value", "0")?;
    require("hashboard_reset_low_bitmap", "0x7")?;
    require("evidence_grade", "software-readback")?;
    require("physical_rail_measured", "false")?;

    let parse_duty = |key: &str| -> Result<u32> {
        fields[key].parse::<u32>().map_err(|error| {
            HalError::Platform(format!(
                "Amlogic boot-safe receipt {key} is not a duty in ns: {error}"
            ))
        })
    };
    let receipt = AmlogicBootSafeHandoff {
        boot_id: fields["boot_id"].to_owned(),
        platform: fields["platform"].to_owned(),
        board_target: fields["board_target"].to_owned(),
        psu_policy,
        fan0_duty_ns: parse_duty("fan0_duty_ns")?,
        fan0_period_ns: parse_duty("fan0_period_ns")?,
        fan1_duty_ns: parse_duty("fan1_duty_ns")?,
        fan1_period_ns: parse_duty("fan1_period_ns")?,
    };
    if receipt.fan0_duty_ns != AML_BOOT_FAN_DUTY_NS || receipt.fan1_duty_ns != AML_BOOT_FAN_DUTY_NS
    {
        return Err(HalError::Platform(format!(
            "Amlogic boot-safe receipt fan duties are {}/{}, expected {AML_BOOT_FAN_DUTY_NS}",
            receipt.fan0_duty_ns, receipt.fan1_duty_ns
        )));
    }
    if receipt.fan0_period_ns != AML_BOOT_FAN_PERIOD_NS
        || receipt.fan1_period_ns != AML_BOOT_FAN_PERIOD_NS
    {
        return Err(HalError::Platform(format!(
            "Amlogic boot-safe receipt fan periods are {}/{}, expected {AML_BOOT_FAN_PERIOD_NS}",
            receipt.fan0_period_ns, receipt.fan1_period_ns
        )));
    }
    Ok(receipt)
}

/// Validate the receipt against an already resolved policy. This does not
/// choose a target, resolve identity, take ownership or write a GPIO.
fn validate_boot_psu_fields(
    fields: &BTreeMap<&str, &str>,
    policy: BootGpio437Policy,
) -> Result<()> {
    let require = |key: &str, expected: &str| -> Result<()> {
        if fields.get(key).copied() == Some(expected) {
            Ok(())
        } else {
            Err(HalError::Platform(format!(
                "Amlogic boot-safe receipt {key} is {:?}, expected {expected:?}",
                fields.get(key)
            )))
        }
    };
    match policy {
        BootGpio437Policy::QualifiedOff(recipe) => {
            require("psu_polarity_class", "qualified-software")?;
            require("gpio_direction", "out")?;
            require("commanded_value", &recipe.off_raw().to_string())?;
            require("readback_value", &recipe.off_raw().to_string())?;
        }
        BootGpio437Policy::Undriven => {
            require("psu_polarity_class", "undriven")?;
            require("gpio_direction", "in")?;
            require("commanded_value", "undriven")?;
            if !matches!(
                fields.get("readback_value").copied(),
                Some("0" | "1" | "unknown")
            ) {
                return Err(HalError::Platform(
                    "GPIO437 undriven readback is malformed".into(),
                ));
            }
        }
    }
    Ok(())
}

fn amlogic_handoff_identity_matches_profile(
    expected: AmlogicNoPicProfile,
    platform: &str,
    board_target: &str,
) -> bool {
    match expected {
        AmlogicNoPicProfile::S19k => platform == "am3-aml-s19k" && board_target == "am3-s19k",
        AmlogicNoPicProfile::S21 => platform == "am3-aml-s21" && board_target == "am3-s21",
        AmlogicNoPicProfile::S21Pro => platform == "am3-aml-s21pro" && board_target == "am3-s21pro",
        AmlogicNoPicProfile::S21Xp => platform == "am3-aml-s21xp" && board_target == "am3-s21xp",
        AmlogicNoPicProfile::S19Xp => platform == "am3-aml-s19xp" && board_target == "am3-s19xp",
        AmlogicNoPicProfile::S19jXp => platform == "am3-aml-s19jxp" && board_target == "am3-s19jxp",
        AmlogicNoPicProfile::S19jProA => {
            platform == "am3-aml-s19jproa" && board_target == "am3-s19jproa"
        }
        AmlogicNoPicProfile::S19jProPlus => {
            platform == "am3-aml-s19jproplus" && board_target == "am3-s19jproplus"
        }
    }
}

fn amlogic_board_target_matches_profile(expected: AmlogicNoPicProfile, board_target: &str) -> bool {
    match expected {
        AmlogicNoPicProfile::S19k => board_target == "am3-s19k",
        AmlogicNoPicProfile::S21 => board_target == "am3-s21",
        AmlogicNoPicProfile::S21Pro => board_target == "am3-s21pro",
        AmlogicNoPicProfile::S21Xp => board_target == "am3-s21xp",
        AmlogicNoPicProfile::S19Xp => board_target == "am3-s19xp",
        AmlogicNoPicProfile::S19jXp => board_target == "am3-s19jxp",
        AmlogicNoPicProfile::S19jProA => board_target == "am3-s19jproa",
        AmlogicNoPicProfile::S19jProPlus => board_target == "am3-s19jproplus",
    }
}

fn validate_amlogic_boot_safe_handoff(expected: AmlogicNoPicProfile) -> Result<String> {
    validate_amlogic_boot_safe_handoff_for(|platform, target| {
        amlogic_handoff_identity_matches_profile(expected, platform, target)
    })
}

fn validate_amlogic_boot_safe_handoff_for(
    identity_matches: impl FnOnce(&str, &str) -> bool,
) -> Result<String> {
    let metadata = fs::symlink_metadata(AML_BOOT_SAFE_RECEIPT).map_err(|error| {
        HalError::Platform(format!(
            "Amlogic NoPic admission requires boot-safe handoff {AML_BOOT_SAFE_RECEIPT}: {error}"
        ))
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(HalError::Platform(format!(
            "Amlogic boot-safe handoff must be a root-owned regular 0600 file: {AML_BOOT_SAFE_RECEIPT}"
        )));
    }
    let source = fs::read_to_string(AML_BOOT_SAFE_RECEIPT).map_err(|error| {
        HalError::Platform(format!("Amlogic boot-safe handoff read failed: {error}"))
    })?;
    let receipt = parse_amlogic_boot_safe_handoff(&source)?;

    let read_marker = |path: &str| -> Result<String> {
        fs::read_to_string(path)
            .map(|value| value.trim().to_owned())
            .map_err(|error| {
                HalError::Platform(format!("Amlogic marker {path} read failed: {error}"))
            })
    };
    let boot_id = read_marker("/proc/sys/kernel/random/boot_id")?;
    let platform = read_marker("/etc/dcentos/platform")?;
    let board_target = read_marker("/etc/dcentos/board_target")?;
    let rail_gpio = read_marker("/etc/dcentos/rail_gpio")?;
    if rail_gpio != GPIO_PSU_ENABLE.to_string() {
        return Err(HalError::Platform(format!(
            "Amlogic rail marker {rail_gpio:?} does not bind GPIO{GPIO_PSU_ENABLE}"
        )));
    }
    let identity_matches_profile = identity_matches(&platform, &board_target);
    if !identity_matches_profile
        || receipt.boot_id != boot_id
        || receipt.platform != platform
        || receipt.board_target != board_target
    {
        return Err(HalError::Platform(format!(
            "Amlogic boot-safe handoff identity/profile mismatch: receipt={receipt:?} live_platform={platform:?} live_target={board_target:?}"
        )));
    }

    let read_live = |path: &str| -> Result<String> {
        fs::read_to_string(path)
            .map(|value| value.trim().to_owned())
            .map_err(|error| {
                HalError::Platform(format!("Amlogic handoff revalidation {path}: {error}"))
            })
    };
    let direction = read_live("/sys/class/gpio/gpio437/direction")?;
    let value = read_live("/sys/class/gpio/gpio437/value")?;
    let active_low = read_live("/sys/class/gpio/gpio437/active_low")?;
    let fan0 = read_live("/sys/class/pwm/pwmchip0/pwm0/duty_cycle")?;
    let fan0_period = read_live("/sys/class/pwm/pwmchip0/pwm0/period")?;
    let fan0_enabled = read_live("/sys/class/pwm/pwmchip0/pwm0/enable")?;
    let fan1 = read_live("/sys/class/pwm/pwmchip0/pwm1/duty_cycle")?;
    let fan1_period = read_live("/sys/class/pwm/pwmchip0/pwm1/period")?;
    let fan1_enabled = read_live("/sys/class/pwm/pwmchip0/pwm1/enable")?;
    let reset454_direction = read_live("/sys/class/gpio/gpio454/direction")?;
    let reset454_active_low = read_live("/sys/class/gpio/gpio454/active_low")?;
    let reset454_value = read_live("/sys/class/gpio/gpio454/value")?;
    let reset455_direction = read_live("/sys/class/gpio/gpio455/direction")?;
    let reset455_active_low = read_live("/sys/class/gpio/gpio455/active_low")?;
    let reset455_value = read_live("/sys/class/gpio/gpio455/value")?;
    let reset456_direction = read_live("/sys/class/gpio/gpio456/direction")?;
    let reset456_active_low = read_live("/sys/class/gpio/gpio456/active_low")?;
    let reset456_value = read_live("/sys/class/gpio/gpio456/value")?;
    let rail_matches = match receipt.psu_policy {
        BootGpio437Policy::QualifiedOff(recipe) => {
            direction == "out" && value == recipe.off_raw().to_string()
        }
        BootGpio437Policy::Undriven => direction == "in",
    };
    if !rail_matches
        || active_low != "0"
        || fan0 != AML_BOOT_FAN_DUTY_NS.to_string()
        || fan0_period != AML_BOOT_FAN_PERIOD_NS.to_string()
        || fan0_enabled != "1"
        || fan1 != AML_BOOT_FAN_DUTY_NS.to_string()
        || fan1_period != AML_BOOT_FAN_PERIOD_NS.to_string()
        || fan1_enabled != "1"
        || reset454_direction != "out"
        || reset454_active_low != "0"
        || reset454_value != "0"
        || reset455_direction != "out"
        || reset455_active_low != "0"
        || reset455_value != "0"
        || reset456_direction != "out"
        || reset456_active_low != "0"
        || reset456_value != "0"
    {
        return Err(HalError::Platform(format!(
            "Amlogic boot-safe live revalidation failed: direction={direction:?} value={value:?} active_low={active_low:?} fan0={fan0:?}/{fan0_period:?}/{fan0_enabled:?} fan1={fan1:?}/{fan1_period:?}/{fan1_enabled:?} reset454={reset454_direction:?}/{reset454_active_low:?}/{reset454_value:?} reset455={reset455_direction:?}/{reset455_active_low:?}/{reset455_value:?} reset456={reset456_direction:?}/{reset456_active_low:?}/{reset456_value:?}"
        )));
    }
    Ok(board_target)
}

impl AmlogicNoPicProfile {
    fn label(self) -> &'static str {
        match self {
            Self::S19k => "S19k Amlogic PSU control",
            Self::S21 => "exact S21 Amlogic NoPic",
            Self::S21Pro => "S21 Pro Amlogic NoPic",
            Self::S21Xp => "S21 XP Amlogic NoPic",
            Self::S19Xp => "S19 XP Amlogic PSU control",
            Self::S19jXp => "S19j XP Amlogic PSU control",
            Self::S19jProA => "S19j Pro A Amlogic PSU control",
            Self::S19jProPlus => "S19j Pro+ Amlogic PSU control",
        }
    }

    fn board_target(self) -> &'static str {
        match self {
            Self::S19k => "am3-s19k",
            Self::S21 => "am3-s21",
            Self::S21Pro => "am3-s21pro",
            Self::S21Xp => "am3-s21xp",
            Self::S19Xp => "am3-s19xp",
            Self::S19jXp => "am3-s19jxp",
            Self::S19jProA => "am3-s19jproa",
            Self::S19jProPlus => "am3-s19jproplus",
        }
    }

    /// Geometry comes from exact executable model constructors, never a
    /// generic S21 family name. S21+ has a separate 55-chip profile.
    pub fn modern_s21_geometry(self) -> Option<(dcentrald_common::AsicProtocolIdentity, u8)> {
        use dcentrald_common::AsicProtocolIdentity;
        match self {
            Self::S21 => Some((AsicProtocolIdentity::Bm1368, 108)),
            Self::S21Pro => Some((AsicProtocolIdentity::Bm1370, 65)),
            Self::S21Xp => Some((AsicProtocolIdentity::Bm1370, 91)),
            Self::S19Xp | Self::S19jXp => Some((AsicProtocolIdentity::Bm1366, 110)),
            Self::S19k => None,
            Self::S19jProA => Some((AsicProtocolIdentity::Bm1362, 126)),
            Self::S19jProPlus => Some((AsicProtocolIdentity::Bm1362, 120)),
        }
    }

    fn gpio_psu_profile(self, native_session: bool) -> Option<s21_psu::ProductionProfile> {
        match (self, native_session) {
            (Self::S19k, true) => Some(s21_psu::ProductionProfile::S19kApw121215),
            (Self::S21 | Self::S19Xp | Self::S19jProA, _) => {
                Some(s21_psu::ProductionProfile::S21Apw121215)
            }
            (Self::S19jXp, _) => Some(s21_psu::ProductionProfile::ModernApw171215),
            (Self::S21Pro | Self::S21Xp | Self::S19jProPlus, _) => {
                Some(s21_psu::ProductionProfile::ModernProXpAuto)
            }
            _ => None,
        }
    }
}

/// Opaque admission proof for one physical Amlogic chain slot.
///
/// This is currently constructible only for the evidenced S21 UART-to-slot
/// route. The held S19k corpus proves that ttyS1 can answer while physical
/// slot 0 is absent, so S19k must remain unbound until ASIC-side EEPROM
/// identity supplies a real tty-to-physical-slot relation.
#[derive(Debug)]
pub struct AmlogicNoPicAdmission {
    profile: AmlogicNoPicProfile,
    board_target: String,
    active_slot: u8,
    serial_device: String,
    populated_slots: [bool; 3],
    generation: Arc<()>,
}

impl AmlogicNoPicAdmission {
    /// Detect the control-board profile independently of mining configuration,
    /// bind it to the configured chain UART, and refuse every mismatch before
    /// GPIO, PWM, or management-I2C mutation.
    pub fn detect(expected: AmlogicNoPicProfile, serial_device: &str) -> Result<Self> {
        let active_slot = amlogic_slot_from_serial_device(expected, serial_device).ok_or_else(|| {
            HalError::Platform(format!(
                "Amlogic NoPic admission cannot bind {} chain UART {serial_device:?} to a physical slot; S19k tty-to-slot topology is unbound and S21 requires its evidenced tty route",
                expected.label()
            ))
        })?;
        if !Path::new(serial_device).exists() {
            return Err(HalError::Platform(format!(
                "Amlogic NoPic admission requires the selected chain UART to exist: {serial_device}"
            )));
        }
        let observed = detect_amlogic_nopic_profile()?;
        let board_target = validate_amlogic_boot_safe_handoff(expected)?;
        let populated_slots = read_plug_topology_checked()?;
        Self::from_profile_evidence(
            expected,
            active_slot,
            serial_device,
            &board_target,
            observed,
            populated_slots,
        )
    }

    fn from_profile_evidence(
        expected: AmlogicNoPicProfile,
        active_slot: u8,
        serial_device: &str,
        board_target: &str,
        observed: AmlogicNoPicProfile,
        populated_slots: [bool; 3],
    ) -> Result<Self> {
        if observed != expected {
            return Err(HalError::Platform(format!(
                "Amlogic NoPic profile mismatch: miner requires {}, control-board identity resolved to {}",
                expected.label(),
                observed.label()
            )));
        }
        if !amlogic_board_target_matches_profile(expected, board_target) {
            return Err(HalError::Platform(format!(
                "Amlogic NoPic board target {board_target:?} is incompatible with {}",
                expected.label()
            )));
        }
        if expected == AmlogicNoPicProfile::S19k {
            return Err(HalError::Platform(
                "S19k tty-to-physical-slot topology is unbound: held .88 evidence has ttyS1 answering 77 BM1366 chips while physical slot 0 is absent; use logical multi-UART discovery until unique ASIC-side EEPROM identity binds a slot"
                    .to_string(),
            ));
        }
        if active_slot > 2 {
            return Err(HalError::Platform(format!(
                "Amlogic NoPic active slot {active_slot} is outside the verified three-slot topology"
            )));
        }
        if amlogic_slot_from_serial_device(expected, serial_device) != Some(active_slot) {
            return Err(HalError::Platform(format!(
                "Amlogic NoPic serial endpoint {serial_device:?} does not resolve to admitted slot {active_slot}"
            )));
        }
        if !populated_slots[active_slot as usize] {
            return Err(HalError::Platform(format!(
                "Amlogic NoPic UART slot {active_slot} is not asserted by checked plug-detect topology {populated_slots:?}"
            )));
        }
        Ok(Self {
            profile: observed,
            board_target: board_target.to_owned(),
            active_slot,
            serial_device: serial_device.to_owned(),
            populated_slots,
            generation: Arc::new(()),
        })
    }

    /// Exact production UART routes for all observed S21 plug slots. The
    /// primary configured endpoint is only a launch hint, never population.
    pub fn detect_s21_population() -> Result<Self> {
        Self::detect_modern_s21_population(AmlogicNoPicProfile::S21)
    }

    pub fn detect_modern_s21_population(expected: AmlogicNoPicProfile) -> Result<Self> {
        if expected.modern_s21_geometry().is_none() {
            return Err(HalError::Platform(
                "modern S21 population requested for another profile".into(),
            ));
        }
        let observed = detect_amlogic_nopic_profile()?;
        let target = validate_amlogic_boot_safe_handoff(expected)?;
        let slots = read_plug_topology_checked()?;
        let first = slots
            .iter()
            .position(|present| *present)
            .ok_or_else(|| HalError::Platform("S21 has no populated hashboard".into()))?;
        for (slot, present) in slots.iter().enumerate() {
            if *present && !Path::new(S21_UARTS[slot]).exists() {
                return Err(HalError::Platform(format!(
                    "S21 populated slot{slot} lacks {}",
                    S21_UARTS[slot]
                )));
            }
        }
        Self::from_profile_evidence(
            expected,
            first as u8,
            S21_UARTS[first],
            &target,
            observed,
            slots,
        )
    }

    pub fn s21_routes(&self) -> Result<Vec<(u8, &'static str)>> {
        if self.profile.modern_s21_geometry().is_none()
            || !amlogic_board_target_matches_profile(self.profile, &self.board_target)
        {
            return Err(HalError::Platform("exact S21 population required".into()));
        }
        Ok(self
            .populated_slots
            .iter()
            .enumerate()
            .filter(|(_, present)| **present)
            .map(|(slot, _)| (slot as u8, S21_UARTS[slot]))
            .collect())
    }

    /// Call only after validating the just-read factory pages. The slot map
    /// joins those identities to this retained management generation.
    pub fn bind_population_polarity(
        &self,
        service: &AmlogicPowerThermalService,
        names: [Option<&str>; 3],
    ) -> Result<()> {
        self.require_service(service)?;
        service
            .psu_commit
            .bind_population(self.populated_slots, names)
    }

    pub fn read_identity_pages(
        &self,
        service: &AmlogicPowerThermalService,
        deadline: Instant,
    ) -> Result<[Option<Vec<u8>>; 3]> {
        self.require_service(service)?;
        let mut pages = [None, None, None];
        for (slot, _) in self.s21_routes()? {
            let address = 0x50 + slot;
            let first = service
                .i2c
                .read_hashboard_eeprom_page_at(address, deadline)?;
            let second = service
                .i2c
                .read_hashboard_eeprom_page_at(address, deadline)?;
            if first != second {
                return Err(HalError::Platform(format!(
                    "S21 slot{slot} factory page changed between reads"
                )));
            }
            pages[slot as usize] = Some(first);
        }
        Ok(pages)
    }

    fn require_service(&self, service: &AmlogicPowerThermalService) -> Result<()> {
        if self.profile.modern_s21_geometry().is_none()
            || service.required_slots != self.populated_slots
            || service.psu_commit.is_terminal()
            || !service
                .psu_commit
                .native_generation
                .as_ref()
                .is_some_and(|generation| Arc::ptr_eq(generation, &self.generation))
        {
            return Err(HalError::Platform(
                "S21 operation lost same-population management owner".into(),
            ));
        }
        Ok(())
    }

    /// Cold boot leaves reset454..456 low. Release only present boards after
    /// same-owner PSU initialization; absent slots remain asserted. This is
    /// serialized with terminal power cut, not a guessed TAS5782M mutation.
    pub fn release_s21_resets(
        &self,
        service: &AmlogicPowerThermalService,
        power: &ApwEnableReceipt,
    ) -> Result<()> {
        self.require_service(service)?;
        if !power
            .native_generation
            .as_ref()
            .is_some_and(|generation| Arc::ptr_eq(generation, &self.generation))
        {
            return Err(HalError::Platform(
                "S21 reset release lacks same-session PSU completion".into(),
            ));
        }
        let _commit = service.psu_commit.begin_enable()?;
        for slot in 0..3u8 {
            if let Err(error) =
                set_amlogic_board_reset_checked(slot, !self.populated_slots[slot as usize])
            {
                for rollback_slot in 0..3 {
                    let _ = set_amlogic_board_reset_checked(rollback_slot, true);
                }
                return Err(error);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    pub fn profile(&self) -> AmlogicNoPicProfile {
        self.profile
    }

    pub fn board_target(&self) -> &str {
        &self.board_target
    }

    pub fn active_slot(&self) -> u8 {
        self.active_slot
    }

    pub fn serial_device(&self) -> &str {
        &self.serial_device
    }

    pub fn populated_slots(&self) -> [bool; 3] {
        self.populated_slots
    }

    /// Establish the sole retained owner of management bus 1.
    pub fn spawn_power_thermal_service(&self) -> Result<AmlogicPowerThermalService> {
        AmlogicPowerThermalService::spawn(self)
    }

    /// Open only the admitted Amlogic cooling controller. The returned shared
    /// owner can be moved to Tokio's blocking pool without reopening sysfs.
    pub fn open_fan_controller(&self) -> Result<Arc<dyn FanAccess>> {
        Ok(Arc::new(AmlogicFan::new()?))
    }
}

/// Controller-facing logical-chain route recovered independently from stock
/// and VNish S19k firmware. `logical_board_address` is the controller address
/// reported by firmware; none of these fields claims connector-face geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kNativeLogicalChainRoute {
    pub logical_chain: u8,
    pub logical_board_address: u8,
    pub uart: &'static str,
    pub plug_gpio: u32,
    pub reset_gpio: u32,
}

/// Complete logical route in stock chain order. A runtime admission selects
/// the entries whose freshly checked plug/EEPROM population is present.
pub const S19K_NATIVE_LOGICAL_CHAIN_ROUTES: [S19kNativeLogicalChainRoute; 3] = [
    S19kNativeLogicalChainRoute {
        logical_chain: 0,
        logical_board_address: 1,
        uart: "/dev/ttyS3",
        plug_gpio: 439,
        reset_gpio: 454,
    },
    S19kNativeLogicalChainRoute {
        logical_chain: 1,
        logical_board_address: 2,
        uart: "/dev/ttyS2",
        plug_gpio: 440,
        reset_gpio: 455,
    },
    S19kNativeLogicalChainRoute {
        logical_chain: 2,
        logical_board_address: 3,
        uart: "/dev/ttyS1",
        plug_gpio: 441,
        reset_gpio: 456,
    },
];
pub const S19K_NATIVE_EXPECTED_CHIPS_PER_UART: u8 = 77;

/// Read-only owner for the complete S19k fan-observation surface.
///
/// The wrapped Amlogic controller remains private so this capability cannot be
/// converted into [`FanAccess`] and used to command PWM. It exposes only tach
/// samples and current PWM readback.
pub struct S19kNativeFanObservation {
    fan: AmlogicFan,
}

impl S19kNativeFanObservation {
    fn open() -> Result<Self> {
        Ok(Self {
            fan: AmlogicFan::new()?,
        })
    }

    pub fn get_rpm(&self) -> u32 {
        self.fan.get_rpm()
    }

    pub fn get_speed_pwm(&self) -> u8 {
        self.fan.get_speed_pwm()
    }

    pub fn get_per_fan_rpm(&self) -> Vec<(u8, u32)> {
        self.fan.get_per_fan_rpm()
    }

    pub fn fan_count(&self) -> u8 {
        self.fan.fan_count()
    }

    pub fn tach_available(&self) -> bool {
        self.fan.tach_available()
    }
}

/// Opaque read-only platform admission for a freshly observed S19k population.
///
/// Unlike [`AmlogicNoPicAdmission`], this capability is aggregate. It proves
/// every UART selected by controller-facing logical-chain evidence exists and
/// at least one plug input is asserted. It retains the physical bitmap without
/// claiming connector-face geometry. It can establish cooling and retained
/// temperature observation, but it cannot mint a PSU-enable operation.
#[derive(Debug)]
pub struct S19kNativeAggregateAdmission {
    board_target: String,
    populated_slots: [bool; 3],
}

/// Profile-aware production admission for a checked S19k native population.
/// Fields stay private so an aggregate observation cannot be upgraded by
/// caller-selected UART or reset ordering.
#[derive(Debug)]
pub struct S19kNativePopulationAdmission {
    aggregate: S19kNativeAggregateAdmission,
    routes: Vec<S19kNativeLogicalChainRoute>,
    generation: Arc<()>,
}

/// Checked proof that all three physical reset lines were asserted before a
/// possible GPIO437/APW enable. The absent address-1 line is included.
#[derive(Debug)]
pub struct S19kNativeAllResetsAsserted {
    reset_gpios: [u32; 3],
}

impl S19kNativeAllResetsAsserted {
    pub fn reset_gpios(&self) -> [u32; 3] {
        self.reset_gpios
    }
}

/// Checked post-power reset release bound to the admitted population. Every
/// absent logical chain is positively re-asserted before UART ownership.
#[derive(Debug)]
pub struct S19kNativePopulationResetRelease {
    released: Vec<S19kNativeLogicalChainRoute>,
    absent_reset_gpios: Vec<u32>,
    power_writes_completed_at: Instant,
    reset_release_completed_at: Instant,
    power_status_word: Option<u16>,
    generation: Arc<()>,
}

impl S19kNativePopulationResetRelease {
    pub fn released(&self) -> &[S19kNativeLogicalChainRoute] {
        &self.released
    }

    pub fn absent_reset_gpios(&self) -> &[u32] {
        &self.absent_reset_gpios
    }

    pub fn power_writes_completed_at(&self) -> Instant {
        self.power_writes_completed_at
    }

    pub fn power_status_word(&self) -> Option<u16> {
        self.power_status_word
    }

    pub fn reset_release_completed_at(&self) -> Instant {
        self.reset_release_completed_at
    }
}

impl S19kNativeAggregateAdmission {
    /// Bind the complete logical-chain table to S19k boot-safe identity before any
    /// PSU, reset, PWM-command, UART, or management-I2C mutation. Checked plug
    /// observation may export its read-only sysfs GPIO lines.
    pub fn detect() -> Result<Self> {
        let uart_available =
            S19K_NATIVE_LOGICAL_CHAIN_ROUTES.map(|route| Path::new(route.uart).exists());
        // R11: native S19k discovery is DCENT-owned. The SKU-qualified
        // identity comes from the DCENT clean-rootfs platform marker only —
        // never from Braiins overlay files, raw I2C tools, or runner-binary
        // hashes, which remain the separately preserved Track-1 inherited
        // evidence. The boot-safe handoff receipt below still binds this
        // marker to the live boot and the checked GPIO437 rail state before
        // any mutation.
        let observed = s19k_native_discovery::detect_dcent_owned_profile()?;
        let board_target = validate_amlogic_boot_safe_handoff(AmlogicNoPicProfile::S19k)?;
        let populated_slots = read_plug_topology_checked()?;
        Self::from_profile_evidence(observed, &board_target, populated_slots, uart_available)
    }

    fn from_profile_evidence(
        observed: AmlogicNoPicProfile,
        board_target: &str,
        populated_slots: [bool; 3],
        uart_available: [bool; 3],
    ) -> Result<Self> {
        if observed != AmlogicNoPicProfile::S19k {
            return Err(HalError::Platform(format!(
                "native S19k aggregate admission observed incompatible {} identity",
                observed.label()
            )));
        }
        if !amlogic_board_target_matches_profile(AmlogicNoPicProfile::S19k, board_target) {
            return Err(HalError::Platform(format!(
                "native S19k aggregate admission refuses board target {board_target:?}"
            )));
        }
        if let Some((index, route)) = S19K_NATIVE_LOGICAL_CHAIN_ROUTES
            .iter()
            .enumerate()
            .find(|(index, _)| populated_slots[*index] && !uart_available[*index])
        {
            return Err(HalError::Platform(format!(
                "native S19k aggregate admission requires populated logical chain {index} UART {}",
                route.uart
            )));
        }
        let populated_count = populated_slots.iter().filter(|present| **present).count();
        if !(1..=S19K_NATIVE_LOGICAL_CHAIN_ROUTES.len()).contains(&populated_count) {
            return Err(HalError::Platform(format!(
                "native S19k aggregate admission requires one to three populated logical chains; observed {populated_slots:?} ({populated_count} populated)"
            )));
        }
        Ok(Self {
            board_target: board_target.to_owned(),
            populated_slots,
        })
    }

    pub fn board_target(&self) -> &str {
        &self.board_target
    }

    pub fn logical_chain_routes(&self) -> Vec<S19kNativeLogicalChainRoute> {
        S19K_NATIVE_LOGICAL_CHAIN_ROUTES
            .iter()
            .copied()
            .filter(|route| self.populated_slots[route.logical_chain as usize])
            .collect()
    }

    pub fn populated_slots(&self) -> [bool; 3] {
        self.populated_slots
    }

    /// Establish retained bus-1 thermal observation without creating a PSU
    /// enable capability. Future cold-start custody must separately promote
    /// power authority after live APW/electrical evidence exists.
    pub fn spawn_thermal_observation_service(&self) -> Result<AmlogicPowerThermalService> {
        let mut service = AmlogicPowerThermalService::spawn_with_required_slots(
            self.populated_slots,
            AmlogicNoPicProfile::S19k,
        )?;
        service.psu_enable_operation_available = false;
        Ok(service)
    }

    /// Acquire the complete four-tach read-only owner without exposing a PWM
    /// command method.
    pub fn open_fan_observation(&self) -> Result<Arc<S19kNativeFanObservation>> {
        Ok(Arc::new(S19kNativeFanObservation::open()?))
    }

    /// Promote only the freshly selected subset of the fixed logical route.
    /// Board-model admission remains the daemon's independent responsibility.
    pub fn into_population(self) -> Result<S19kNativePopulationAdmission> {
        let routes = self.logical_chain_routes();
        if routes.is_empty() || routes.len() > S19K_NATIVE_LOGICAL_CHAIN_ROUTES.len() {
            return Err(HalError::Platform(format!(
                "native S19k population route is empty or oversized: {:?}",
                self.populated_slots
            )));
        }
        Ok(S19kNativePopulationAdmission {
            aggregate: self,
            routes,
            generation: Arc::new(()),
        })
    }
}

impl S19kNativePopulationAdmission {
    pub fn board_target(&self) -> &str {
        self.aggregate.board_target()
    }

    pub fn populated_slots(&self) -> [bool; 3] {
        self.aggregate.populated_slots()
    }

    pub fn logical_chain_routes(&self) -> &[S19kNativeLogicalChainRoute] {
        &self.routes
    }

    /// Establish retained bus-1 thermal, rollback, terminal-SafeOff, and
    /// one-shot GPIO437/APW ownership for the mapped native route.
    pub fn spawn_power_thermal_service(&self) -> Result<AmlogicPowerThermalService> {
        let mut service = AmlogicPowerThermalService::spawn_with_required_slots_and_generation(
            self.populated_slots(),
            AmlogicNoPicProfile::S19k,
            Some(Arc::clone(&self.generation)),
        )?;
        service.psu_enable_operation_available = true;
        Ok(service)
    }

    /// Read the selected EEPROM pages through this population's retained bus
    /// owner before power/reset/UART mutation. A second read must agree byte
    /// for byte; a transient or partial identity is not used for native init.
    /// Only this generation's service is accepted, and no generic I2C handle
    /// escapes to the caller. Absent plug slots are never probed.
    fn require_service(&self, service: &AmlogicPowerThermalService) -> Result<()> {
        if service.required_slots != self.populated_slots()
            || service.psu_commit.is_terminal()
            || !service
                .psu_commit
                .native_generation
                .as_ref()
                .is_some_and(|generation| Arc::ptr_eq(generation, &self.generation))
        {
            return Err(HalError::Platform(
                "S19k identity reader requires its live generation-bound management service".into(),
            ));
        }
        Ok(())
    }

    /// Join validated factory names to this exact observed slot population.
    pub fn bind_population_polarity(
        &self,
        service: &AmlogicPowerThermalService,
        names: [Option<&str>; 3],
    ) -> Result<()> {
        self.require_service(service)?;
        service
            .psu_commit
            .bind_population(self.populated_slots(), names)
    }

    pub fn read_identity_pages(
        &self,
        service: &AmlogicPowerThermalService,
        deadline: Instant,
    ) -> Result<[Option<Vec<u8>>; 3]> {
        self.require_service(service)?;
        let mut pages = [None, None, None];
        for (slot, present) in self.populated_slots().into_iter().enumerate() {
            if !present {
                continue;
            }
            let addr = 0x50 + slot as u8;
            let first = service.i2c.read_hashboard_eeprom_page_at(addr, deadline)?;
            let second = service.i2c.read_hashboard_eeprom_page_at(addr, deadline)?;
            if first != second {
                return Err(HalError::Platform(format!(
                    "S19k EEPROM 0x{addr:02x} changed between consecutive identity reads"
                )));
            }
            pages[slot] = Some(first);
        }
        Ok(pages)
    }

    /// Open the retained four-channel command/tach controller. Unlike the
    /// aggregate observation facade, this surface is available only after the
    /// exact controller-facing population route has been admitted.
    pub fn open_fan_controller(&self) -> Result<Arc<dyn FanAccess>> {
        Ok(Arc::new(AmlogicFan::new()?))
    }

    pub fn assert_all_resets_checked(&self) -> Result<S19kNativeAllResetsAsserted> {
        assert_s19k_native_all_resets_checked()
    }

    /// Release only the freshly observed populated routes after the one-shot
    /// power operation completed. Any partial failure re-asserts all three reset
    /// lines before returning an error so caller rollback can cut GPIO437.
    pub fn release_mapped_resets_checked(
        &self,
        asserted: S19kNativeAllResetsAsserted,
        power: ApwEnableReceipt,
    ) -> Result<S19kNativePopulationResetRelease> {
        if asserted.reset_gpios != [454, 455, 456] {
            return Err(HalError::Platform(format!(
                "native S19k pre-power reset proof drifted: {:?}",
                asserted.reset_gpios
            )));
        }
        let power_generation = power.native_generation.as_ref().ok_or_else(|| {
            HalError::Platform(
                "native S19k mapped reset release refused a generic/foreign APW receipt".into(),
            )
        })?;
        if !Arc::ptr_eq(power_generation, &self.generation) {
            return Err(HalError::Platform(
                "native S19k mapped reset release refused an APW receipt from another cold-start generation"
                    .into(),
            ));
        }
        let release = (|| -> Result<Vec<u32>> {
            for route in &self.routes {
                let receipt = set_amlogic_board_reset_checked(route.logical_chain, false)?;
                if receipt.gpio() != route.reset_gpio || receipt.asserted() {
                    return Err(HalError::Platform(format!(
                        "native S19k population reset release mismatch: chain={} gpio={} expected_gpio={} asserted={}",
                        route.logical_chain,
                        receipt.gpio(),
                        route.reset_gpio,
                        receipt.asserted()
                    )));
                }
            }
            let mut absent_reset_gpios = Vec::new();
            for route in S19K_NATIVE_LOGICAL_CHAIN_ROUTES
                .iter()
                .filter(|route| !self.populated_slots()[route.logical_chain as usize])
            {
                let absent = set_amlogic_board_reset_checked(route.logical_chain, true)?;
                if absent.gpio() != route.reset_gpio || !absent.asserted() {
                    return Err(HalError::Platform(format!(
                        "native S19k absent logical chain {} / GPIO{} did not remain reset-asserted",
                        route.logical_chain, route.reset_gpio
                    )));
                }
                absent_reset_gpios.push(route.reset_gpio);
            }
            Ok(absent_reset_gpios)
        })();
        let absent_reset_gpios = match release {
            Ok(value) => value,
            Err(primary) => {
                return match assert_s19k_native_all_resets_checked() {
                Ok(_) => Err(HalError::Platform(format!(
                    "native S19k mapped reset release failed ({primary}); all resets re-asserted before GPIO437 rollback"
                ))),
                Err(rollback) => Err(HalError::Platform(format!(
                    "native S19k mapped reset release failed ({primary}); reset rollback also failed ({rollback})"
                ))),
            };
            }
        };
        Ok(S19kNativePopulationResetRelease {
            released: self.routes.clone(),
            absent_reset_gpios,
            power_writes_completed_at: power.writes_completed_at,
            reset_release_completed_at: Instant::now(),
            power_status_word: power.status_word,
            generation: Arc::clone(&self.generation),
        })
    }

    /// Prove that a completed reset release still belongs to this exact
    /// cold-start admission. This is consumed by the daemon's private joined
    /// owner; callers cannot manufacture or clone either side.
    pub fn owns_reset_release(&self, release: &S19kNativePopulationResetRelease) -> bool {
        Arc::ptr_eq(&self.generation, &release.generation)
    }
}

fn amlogic_slot_from_serial_device(
    profile: AmlogicNoPicProfile,
    serial_device: &str,
) -> Option<u8> {
    match profile {
        // `.88`: plug topology [false,true,true], but ttyS1 and ttyS2 each
        // answer 77 BM1366 chips. Therefore ttyS1->slot0 is directly false;
        // no alternative S19k tty-to-slot permutation is proven offline.
        AmlogicNoPicProfile::S19k => None,
        // Exact production formatter0x86452c: physical1/2/3 -> ttyS3/2/1.
        AmlogicNoPicProfile::S21
        | AmlogicNoPicProfile::S21Pro
        | AmlogicNoPicProfile::S21Xp
        | AmlogicNoPicProfile::S19Xp
        | AmlogicNoPicProfile::S19jXp
        | AmlogicNoPicProfile::S19jProA
        | AmlogicNoPicProfile::S19jProPlus => S21_UARTS
            .iter()
            .position(|path| *path == serial_device)
            .map(|slot| slot as u8),
    }
}

fn read_plug_topology_checked() -> Result<[bool; 3]> {
    let mut populated = [false; 3];
    for slot in 0..3u32 {
        let gpio = resolve_plug_gpio_global(slot)?;
        let root = format!("/sys/class/gpio/gpio{gpio}");
        let value_path = format!("{root}/value");
        if !Path::new(&value_path).exists() {
            let export_result = fs::write("/sys/class/gpio/export", gpio.to_string());
            let deadline = Instant::now() + Duration::from_millis(500);
            while !Path::new(&value_path).exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if !Path::new(&value_path).exists() {
                return Err(HalError::Platform(format!(
                    "Amlogic plug-detect GPIO{gpio} did not appear after export: {export_result:?}"
                )));
            }
        }
        let direction_path = format!("{root}/direction");
        fs::write(&direction_path, "in").map_err(|error| {
            HalError::Platform(format!(
                "Amlogic plug-detect GPIO{gpio} direction input failed: {error}"
            ))
        })?;
        let direction = fs::read_to_string(&direction_path).map_err(|error| {
            HalError::Platform(format!(
                "Amlogic plug-detect GPIO{gpio} direction readback failed: {error}"
            ))
        })?;
        if direction.trim() != "in" {
            return Err(HalError::Platform(format!(
                "Amlogic plug-detect GPIO{gpio} direction readback was {:?}, expected input",
                direction.trim()
            )));
        }
        let value = fs::read_to_string(&value_path).map_err(|error| {
            HalError::Platform(format!(
                "Amlogic plug-detect GPIO{gpio} read failed: {error}"
            ))
        })?;
        populated[slot as usize] = match value.trim() {
            "0" => false,
            "1" => true,
            other => {
                return Err(HalError::Platform(format!(
                    "Amlogic plug-detect GPIO{gpio} returned invalid value {other:?}"
                )))
            }
        };
    }
    Ok(populated)
}

impl AmlogicPlatform {
    /// Create a new Amlogic platform.
    ///
    /// Resolve enough file-backed identity to emit a precise refusal. The
    /// generic `Platform` lifecycle cannot carry the retained bus-1 owner, so
    /// production Amlogic mining must use the native serial engine.
    ///
    /// Status classification (H7 G8): this refusal is an ARCHITECTURAL
    /// ROUTING fact, not a capability gap — Amlogic mines via the native
    /// serial lane. Every Amlogic `BoardDesc` row that names that lane is
    /// `RuntimeStatus::SpecialisedLifecycle { lane: AmlogicNativeSerial,
    /// generic_construction: Refused }`, which is deliberately distinct from
    /// CVitek's `EvidenceRetainedNotImplemented`. See
    /// `dcentrald-common::board_desc` and `dcent_schema::hardware::RuntimeStatus`.
    pub fn new() -> Result<Self> {
        // Verify we're actually on Amlogic
        if !["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3", "/dev/ttyS4"]
            .iter()
            .any(|path| std::path::Path::new(path).exists())
        {
            return Err(HalError::Platform(
                "Amlogic: no ttyS1/ttyS2/ttyS3/ttyS4 device found".to_string(),
            ));
        }

        // Detect specific model
        let config = detect_amlogic_model()?;

        Err(HalError::Platform(format!(
            "{} requires the native serial-mining lifecycle with retained Amlogic power/thermal ownership; generic Platform construction is refused",
            config.name
        )))
    }

    /// Create with explicit config for host-only trait tests.
    #[cfg(test)]
    pub fn with_config(config: PlatformConfig) -> Self {
        Self { config }
    }
}

impl Platform for AmlogicPlatform {
    fn board_type(&self) -> BoardType {
        BoardType::Amlogic
    }

    fn chain_count(&self) -> u8 {
        self.config.chains.len() as u8
    }

    fn open_chain(&self, chain_id: u8) -> Result<Box<dyn ChainAccess>> {
        let chain_config = self
            .config
            .chains
            .iter()
            .find(|c| c.chain_id == chain_id)
            .ok_or_else(|| HalError::Platform(format!("chain {} not configured", chain_id)))?;

        match &chain_config.transport {
            ChainTransport::Serial { device, baud } => {
                // Chain-2 has historical ttyS3/ttyS4 drift. The priority order
                // is explicit config data with host tests; runtime probing only
                // resolves which declared candidate the live filesystem exposes.
                let resolved_device = if chain_id == 2 {
                    let label = format!("amlogic-chain-{}", chain_id);
                    let candidates = amlogic_tty_candidate_order(chain_config);
                    let candidate_refs: Vec<&str> = candidates.iter().map(String::as_str).collect();
                    probe_tty_chain_device(&candidate_refs, &label)
                        .unwrap_or_else(|| device.clone())
                } else {
                    device.clone()
                };
                let serial = SerialChain::open(&resolved_device, *baud)?;
                Ok(Box::new(AmlogicChainAccess {
                    serial: Mutex::new(serial),
                }))
            }
            other => Err(HalError::Platform(format!(
                "unexpected transport for Amlogic chain {}: {:?}",
                chain_id, other
            ))),
        }
    }

    fn open_i2c(&self, bus: u8) -> Result<I2cBus> {
        let mut handle = I2cBus::open(bus)?;
        // Defense-in-depth: any caller that obtains a raw `I2cBus` for the
        // hashboard EEPROM bus on am3-aml inherits the [0x50..=0x57]
        // write-deny. Production code should go through
        // `spawn_amlogic_protected_i2c0_service()` (the long-running
        // serialized service); this gate covers transient one-off opens.
        // See module-level doc for the BHB42xxx/BHB56902 EEPROM rationale
        // and .
        if bus == AMLOGIC_HASHBOARD_EEPROM_BUS {
            handle.set_write_denylist(&AMLOGIC_EEPROM_DENYLIST);
        }
        Ok(handle)
    }

    fn open_fan(&self) -> Result<Box<dyn FanAccess>> {
        Err(HalError::Platform(
            "generic Amlogic fan construction is refused; native mining must consume AmlogicNoPicAdmission"
                .to_string(),
        ))
    }

    fn open_gpio(&self) -> Result<Box<dyn GpioAccess>> {
        Ok(Box::new(AmlogicGpio))
    }

    fn voltage_controller(&self) -> VoltageControllerKind {
        // Production generic construction is refused above. Host-only trait
        // tests preserve exactly the explicit PlatformConfig classification;
        // the native serial lifecycle resolves controller authority itself.
        self.config.voltage_controller
    }
}

/// Serial-based chain access for Amlogic platforms.
///
/// Unlike Zynq FpgaChain which has separate FIFOs for cmd/work/nonce,
/// Amlogic multiplexes everything on a single serial port. The ASIC
/// protocol preamble (0x55 0xAA vs 0xAA 0x55) distinguishes directions.
///
/// BUG FIX (2026-04-11): Was UnsafeCell with manual Send/Sync — replaced
/// with Mutex to prevent data races on concurrent UART access.
struct AmlogicChainAccess {
    serial: Mutex<SerialChain>,
}

impl ChainAccess for AmlogicChainAccess {
    fn send_command(&self, data: &[u8]) -> Result<()> {
        let mut serial = self
            .serial
            .lock()
            .map_err(|_| HalError::Platform("serial mutex poisoned".into()))?;
        serial.write_bytes(data)
    }

    fn read_response(&self, buf: &mut [u8]) -> Result<usize> {
        let mut serial = self
            .serial
            .lock()
            .map_err(|_| HalError::Platform("serial mutex poisoned".into()))?;
        serial.read_bytes(buf)
    }

    fn send_work(&self, data: &[u8]) -> Result<()> {
        let mut serial = self
            .serial
            .lock()
            .map_err(|_| HalError::Platform("serial mutex poisoned".into()))?;
        serial.write_bytes(data)
    }

    fn read_nonce(&self, buf: &mut [u8]) -> Result<usize> {
        let mut serial = self
            .serial
            .lock()
            .map_err(|_| HalError::Platform("serial mutex poisoned".into()))?;
        serial.read_bytes(buf)
    }

    fn set_baud(&self, baud: u32) -> Result<()> {
        let mut serial = self
            .serial
            .lock()
            .map_err(|_| HalError::Platform("serial mutex poisoned".into()))?;
        serial.set_baud(baud)
    }

    fn wait_for_nonce(&self) -> Result<()> {
        // Serial port uses VTIME timeout — read_bytes will block briefly.
        // For production, this should use epoll/select.
        std::thread::yield_now();
        Ok(())
    }
}

/// Source of falling-edge counts for one fan tach line. Abstracted so
/// unit tests can mock the edge stream without real GPIO hardware.
pub(crate) trait FanTachSource: Send + Sync {
    /// Sample falling edges over the given window and return the count. Any
    /// kernel/poll/read failure invalidates the complete sample; partial counts
    /// must never be promoted to cooling evidence.
    /// Must be a non-blocking-style budget: implementations should bound
    /// the call to `window` regardless of whether edges arrive.
    fn sample_falling_edges(&self, window: Duration) -> std::io::Result<u32>;
}

/// Sysfs-backed falling-edge counter for `/sys/class/gpio/gpioN/value`.
///
/// Why sysfs and not the chardev `/dev/gpiochip*` API? Per
///  the am2 Zynq ships sysfs-only;
/// the am3-aml kernel CAN expose chardev but bosminer/BraiinsOS still
/// drives gpio447-450 through sysfs, so sysfs is the proven-on-live-
/// hardware path. Sysfs also keeps the dependency footprint zero.
///
/// How falling-edge sampling works on sysfs:
/// 1. Export the GPIO, set `direction=in`, set `edge=falling`.
/// 2. `open()` `/sys/class/gpio/gpioN/value` once and cache the fd.
/// 3. To sample, do an initial `read()` (clears any latched event),
///    then `poll(POLLPRI|POLLERR)` with the sample window as the
///    timeout. Each `poll()` return that signals `POLLPRI` is one
///    falling edge. After each event re-`lseek(0)` + `read()` to
///    re-arm the kernel-side latch and continue counting until the
///    deadline passes.
///
/// This is the mechanism the kernel documents in
/// `Documentation/gpio/sysfs.txt` and is what BraiinsOS's
/// `monitor-ipsig` GPIO reader uses on the same hardware.
struct SysfsFallingEdgeCounter {
    gpio: u32,
    fd: std::fs::File,
}

impl SysfsFallingEdgeCounter {
    fn export(gpio: u32) -> Result<Self> {
        let dir = format!("/sys/class/gpio/gpio{}", gpio);
        if !Path::new(&dir).exists() {
            // Best-effort export. If kernel returns EBUSY because another
            // process exported the line, the direction/edge writes below
            // will still succeed because sysfs allows multiple writers.
            if let Err(e) = fs::write("/sys/class/gpio/export", gpio.to_string()) {
                tracing::debug!(gpio, error = %e, "GPIO tach export returned error (may already be exported)");
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let dir_path = format!("{}/direction", dir);
        if let Err(e) = fs::write(&dir_path, "in") {
            return Err(HalError::Fan(format!(
                "fan tach gpio{} direction=in failed: {}",
                gpio, e
            )));
        }

        let edge_path = format!("{}/edge", dir);
        if let Err(e) = fs::write(&edge_path, "falling") {
            return Err(HalError::Fan(format!(
                "fan tach gpio{} edge=falling failed (kernel may lack edge support): {}",
                gpio, e
            )));
        }

        let value_path = format!("{}/value", dir);
        let fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&value_path)
            .map_err(|e| {
                HalError::Fan(format!("fan tach gpio{} open value failed: {}", gpio, e))
            })?;

        // Drain any latched event so the first poll() represents the
        // first edge inside the sample window.
        drain_value_fd(fd.as_raw_fd()).map_err(|e| {
            HalError::Fan(format!(
                "fan tach gpio{} initial value read failed: {}",
                gpio, e
            ))
        })?;

        Ok(Self { gpio, fd })
    }
}

/// Read the sysfs "value" file from offset 0. POLLPRI is edge-triggered
/// in the sense that sysfs latches one event until the value is read; a
/// fresh read primes the next event.
fn drain_value_fd(fd: i32) -> std::io::Result<()> {
    use std::io;
    let mut buf = [0u8; 8];
    unsafe {
        if libc::lseek(fd, 0, libc::SEEK_SET) < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Classify one sysfs GPIO poll result. Linux kernfs reports a valid sysfs
/// attribute notification as `POLLPRI|POLLERR`, so `POLLPRI` remains
/// authoritative even when `POLLERR` accompanies it. Bare `POLLERR`, hangup,
/// and invalid-descriptor events are evidence failures.
fn tach_poll_has_edge(revents: libc::c_short) -> std::io::Result<bool> {
    use std::io;
    if revents & (libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(io::Error::other(format!(
            "fan tach poll reported error revents=0x{revents:04X}"
        )));
    }
    if revents & libc::POLLPRI != 0 {
        return Ok(true);
    }
    if revents & libc::POLLERR != 0 {
        return Err(io::Error::other(format!(
            "fan tach poll reported bare POLLERR revents=0x{revents:04X}"
        )));
    }
    Ok(false)
}

impl FanTachSource for SysfsFallingEdgeCounter {
    fn sample_falling_edges(&self, window: Duration) -> std::io::Result<u32> {
        let raw_fd = self.fd.as_raw_fd();
        let deadline = Instant::now() + window;
        let mut edges: u32 = 0;

        // Hard cap: even if the kernel storms us with bogus events
        // (e.g. floating tach line), don't loop forever.
        const MAX_EDGES_PER_WINDOW: u32 = 100_000;

        // Make sure we start from a known-clean state.
        drain_value_fd(raw_fd)?;

        loop {
            let remaining = match deadline.checked_duration_since(Instant::now()) {
                Some(r) if !r.is_zero() => r,
                _ => break,
            };

            let mut pollfd = libc::pollfd {
                fd: raw_fd,
                events: libc::POLLPRI | libc::POLLERR,
                revents: 0,
            };

            let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            let rc = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            if rc == 0 {
                // Timeout — window expired, no further edges.
                break;
            }

            if tach_poll_has_edge(pollfd.revents)? {
                edges = edges.saturating_add(1);
                if edges >= MAX_EDGES_PER_WINDOW {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "fan tach gpio{} exceeded maximum credible edges per window ({MAX_EDGES_PER_WINDOW})",
                            self.gpio
                        ),
                    ));
                }
                // Re-arm the latch so the next falling edge fires POLLPRI again.
                drain_value_fd(raw_fd)?;
            } else {
                return Err(std::io::Error::other(format!(
                    "fan tach gpio{} poll woke without POLLPRI (revents=0x{:04X})",
                    self.gpio, pollfd.revents
                )));
            }
        }

        Ok(edges)
    }
}

/// Convert a falling-edge count over `window` into an RPM value at
/// `PULSES_PER_REV` pulses per revolution. Pulled out for unit tests.
fn edges_to_rpm(edges: u32, window: Duration) -> u32 {
    if window.is_zero() || PULSES_PER_REV == 0 {
        return 0;
    }
    let window_secs = window.as_secs_f64();
    if window_secs <= 0.0 {
        return 0;
    }
    let rpm = (edges as f64) * 60.0 / (window_secs * PULSES_PER_REV as f64);
    rpm.round().clamp(0.0, u32::MAX as f64) as u32
}

/// Amlogic fan control via sysfs PWM (pwmchip0/pwm0 and pwm1).
///
/// Verified on live S21 at .135 (2026-04-11):
///   - pwmchip0/pwm0: rear fans (FAN2, FAN4), period=100000ns (10kHz)
///   - pwmchip0/pwm1: front fans (FAN1, FAN3), period=100000ns (10kHz)
///   - duty_cycle range: 0 (off) to 100000 (100%)
///   - pwmchip0 at FF802000 (AO PWM), pwmchip4 at FFD1B000 (EE PWM)
///
/// Tach uses falling-edge counters on gpio447-450. Production construction is
/// atomic at the capability boundary: all four channels must arm before a fan
/// controller is returned. A zero-edge sample remains zero RPM. This matches
/// the held S21 Pro `single_board_test` binary, whose `fan_get_realtime_speed`
/// returns zero for a zero FPGA tach byte and whose `fan_speed_check` treats
/// low/zero RPM as a protection failure instead of inventing a positive value.
struct AmlogicFan {
    /// Rear fans duty_cycle path
    rear_duty_path: String,
    /// Front fans duty_cycle path
    front_duty_path: String,
    /// PWM period in nanoseconds (10kHz = 100000ns)
    period_ns: u32,
    /// Complete falling-edge counter set for fan slots 0..3. The fixed-size
    /// representation prevents a partially observable cooling controller from
    /// escaping production acquisition.
    tach_sources: [Box<dyn FanTachSource>; GPIO_FAN_TACH_COUNT],
    /// Monotonic health latch. Acquisition starts healthy; any typed sample or
    /// worker-creation error permanently revokes tach availability for this
    /// owner. In unwind builds a worker panic is also caught and revoked. The
    /// production abort profile instead delegates programmer-fault containment
    /// to the daemon crash-safe state and watchdog because destructors do not
    /// run after an abort.
    tach_healthy: AtomicBool,
    /// Sample window passed to each `FanTachSource::sample_falling_edges`.
    /// Owned by the struct so tests can shorten it.
    sample_window: Duration,
}

/// PWM period for Amlogic fans: 100000ns = 10kHz (confirmed on S21 probe)
const AMLOGIC_PWM_PERIOD_NS: u32 = 100_000;

/// Minimum commanded duty while an air-cooled Amlogic miner owns hash power.
/// Current shipped S21/S21 Pro profiles use 10%; lower config values are idle
/// policy, not proof that an energized chassis can safely stop its fans. The
/// pre-energization motion gate remains authoritative if a particular fan does
/// not move at this command.
pub const REQUIRED_AIRFLOW_MIN_PWM: u8 = 10;

/// Conservative minimum credible tach reading for an energized air-cooled
/// Amlogic chassis. This is an admission floor, not a target fan curve: one
/// stray edge in the one-second sample window (~30 RPM at 2 PPR) must not prove
/// cooling motion. Future board descriptions can replace this platform default
/// with PWM-dependent calibrated capability data.
pub const REQUIRED_AIRFLOW_MIN_RPM: u32 = 300;

/// Convert PWM percent (0-100) to nanosecond duty cycle for sysfs PWM.
/// Shared by Amlogic + BeagleBone fan paths so the kernel-write conversion
/// matches between platforms (and matches the userspace S82dcentrald
/// crash-fan override at PWM 30 = 30000ns / 100000ns period).
pub(super) fn amlogic_pwm_percent_to_duty_ns(pwm: u8, period_ns: u32) -> u32 {
    let pwm_clamped = pwm.min(100) as u32;
    (pwm_clamped * period_ns) / 100
}

/// Inverse of [`amlogic_pwm_percent_to_duty_ns`]. Used for read-back so
/// `set_speed(30); get_speed_pwm() == 30` (modulo integer-division rounding).
pub(super) fn amlogic_duty_ns_to_pwm_percent(duty_ns: u32, period_ns: u32) -> u8 {
    if period_ns == 0 {
        return 0;
    }
    (((duty_ns.min(period_ns) * 100) / period_ns) as u8).min(100)
}

impl AmlogicFan {
    fn new() -> Result<Self> {
        // Use sysfs PWM directly (confirmed on S21 at .135)
        let base = "/sys/class/pwm/pwmchip0";
        let rear_path = format!("{}/pwm0/duty_cycle", base);
        let front_path = format!("{}/pwm1/duty_cycle", base);

        for (label, path) in [("rear", &rear_path), ("front", &front_path)] {
            if !Path::new(path).exists() {
                return Err(HalError::Fan(format!(
                    "Amlogic {} fan PWM path not found: {}",
                    label, path
                )));
            }
        }

        // Bring up gpio447-450 as one complete cooling-observation capability.
        // Mining must not be admitted with a controller that can observe only a
        // subset of the fans.
        let mut tach_sources: Vec<Box<dyn FanTachSource>> = Vec::with_capacity(GPIO_FAN_TACH_COUNT);
        for slot in 0..GPIO_FAN_TACH_COUNT {
            let gpio = resolve_fan_tach_gpio_global(slot)?;
            let counter = SysfsFallingEdgeCounter::export(gpio).map_err(|e| {
                HalError::Fan(format!(
                    "Amlogic fan tach capability incomplete: slot {} gpio{} failed: {}",
                    slot, gpio, e
                ))
            })?;
            tach_sources.push(Box::new(counter));
        }

        let tach_sources: [Box<dyn FanTachSource>; GPIO_FAN_TACH_COUNT] =
            tach_sources
                .try_into()
                .map_err(|sources: Vec<Box<dyn FanTachSource>>| {
                    HalError::Fan(format!(
                        "Amlogic fan tach capability incomplete: armed {} of {} channels",
                        sources.len(),
                        GPIO_FAN_TACH_COUNT
                    ))
                })?;
        tracing::info!(
            tach_count = GPIO_FAN_TACH_COUNT,
            "Amlogic fan tach: complete GPIO falling-edge counter set armed"
        );

        Ok(Self {
            rear_duty_path: rear_path,
            front_duty_path: front_path,
            period_ns: AMLOGIC_PWM_PERIOD_NS,
            tach_sources,
            tach_healthy: AtomicBool::new(true),
            sample_window: Duration::from_millis(TACH_SAMPLE_MS),
        })
    }

    /// Test-only constructor that injects mock tach sources. Lets unit
    /// tests assert RPM math without poking real GPIO sysfs.
    #[cfg(test)]
    fn for_test(tach_sources: [Box<dyn FanTachSource>; GPIO_FAN_TACH_COUNT]) -> Self {
        Self {
            rear_duty_path: String::new(),
            front_duty_path: String::new(),
            period_ns: AMLOGIC_PWM_PERIOD_NS,
            tach_sources,
            tach_healthy: AtomicBool::new(true),
            sample_window: Duration::from_millis(10),
        }
    }

    /// Sample one fan slot. Zero edges deliberately remain zero RPM: callers
    /// must never confuse absence of cooling evidence with evidence of motion.
    fn sample_slot_rpm(&self, slot: usize) -> u32 {
        let Some(source) = self.tach_sources.get(slot) else {
            self.tach_healthy.store(false, Ordering::Release);
            return 0;
        };
        match source.sample_falling_edges(self.sample_window) {
            Ok(edges) => edges_to_rpm(edges, self.sample_window),
            Err(error) => {
                self.tach_healthy.store(false, Ordering::Release);
                tracing::error!(slot, %error, "Amlogic fan tach sample invalidated");
                0
            }
        }
    }

    /// Observe every tach input in one shared wall-clock window. Sampling the
    /// four one-second counters sequentially used to stall the serial miner for
    /// roughly four seconds and a later telemetry read repeated the stall.
    fn sample_all_rpm(&self) -> Vec<(u8, u32)> {
        std::thread::scope(|scope| {
            let mut workers = Vec::with_capacity(self.tach_sources.len());
            for slot in 0..self.tach_sources.len() {
                let worker = std::thread::Builder::new()
                    .name(format!("amlogic-fan-tach-{slot}"))
                    .spawn_scoped(scope, move || self.sample_slot_rpm(slot));
                match worker {
                    Ok(worker) => workers.push((slot, Some(worker))),
                    Err(error) => {
                        self.tach_healthy.store(false, Ordering::Release);
                        tracing::error!(
                            slot,
                            %error,
                            "Amlogic fan tach sampler thread could not start; reporting zero RPM"
                        );
                        workers.push((slot, None));
                    }
                }
            }
            workers
                .into_iter()
                .map(|(slot, worker)| {
                    let rpm = worker.map_or(0, |worker| {
                        worker.join().unwrap_or_else(|_| {
                            self.tach_healthy.store(false, Ordering::Release);
                            tracing::error!(
                                slot,
                                "Amlogic fan tach sampler panicked in an unwind build; reporting zero RPM"
                            );
                            0
                        })
                    });
                    (slot as u8, rpm)
                })
                .collect()
        })
    }
}

impl FanAccess for AmlogicFan {
    fn set_speed(&self, pwm: u8) {
        // Scale 0-100 (BraiinsOS / `dcentrald-thermal::FAN_PWM_MAX` convention)
        // to 0-period_ns sysfs duty_cycle. Profile values like
        // `home_quiet.fan_max_pwm = 30` mean 30% duty cycle.
        //
        // Pre-2026-04-29: this used /127 (legacy from a different platform's
        // PWM range), which silently rendered profile PWM 30 as ~24% duty.
        // Bosminer fan-autoconfigure on .78 falls back to 25% as the spinning
        // floor — at /127 we'd never reach that floor for home-mining
        // configs. Per Phase H.6 expert-agent finding (Thermal+Perf).
        let duty_ns = amlogic_pwm_percent_to_duty_ns(pwm, self.period_ns);
        let duty_str = duty_ns.to_string();
        // Set both front and rear fans to the same speed
        if let Err(e) = fs::write(&self.rear_duty_path, &duty_str) {
            tracing::error!(path = %self.rear_duty_path, error = %e, "Failed to write rear fan PWM");
        }
        if let Err(e) = fs::write(&self.front_duty_path, &duty_str) {
            tracing::error!(path = %self.front_duty_path, error = %e, "Failed to write front fan PWM");
        }
    }

    fn set_speed_checked(&self, pwm: u8) -> Result<super::FanCommandReceipt> {
        let duty_ns = amlogic_pwm_percent_to_duty_ns(pwm, self.period_ns);
        let duty = duty_ns.to_string();
        fs::write(&self.rear_duty_path, &duty)
            .map_err(|error| HalError::Fan(format!("rear fan PWM write: {error}")))?;
        fs::write(&self.front_duty_path, &duty)
            .map_err(|error| HalError::Fan(format!("front fan PWM write: {error}")))?;

        for (label, path) in [
            ("rear", &self.rear_duty_path),
            ("front", &self.front_duty_path),
        ] {
            let observed = fs::read_to_string(path)
                .map_err(|error| HalError::Fan(format!("{label} fan PWM readback: {error}")))?;
            let observed = observed.trim().parse::<u32>().map_err(|error| {
                HalError::Fan(format!("{label} fan PWM readback parse: {error}"))
            })?;
            if observed != duty_ns {
                return Err(HalError::Fan(format!(
                    "{label} fan PWM readback mismatch: requested {duty_ns}ns, observed {observed}ns"
                )));
            }
        }

        Ok(super::FanCommandReceipt {
            requested_pwm: pwm,
            observed_pwm: pwm,
        })
    }

    fn get_rpm(&self) -> u32 {
        // Return the slowest RPM including zero. One stopped fan must dominate
        // the aggregate used by the thermal protection state machine.
        self.sample_all_rpm()
            .into_iter()
            .map(|(_, rpm)| rpm)
            .min()
            .unwrap_or(0)
    }

    fn get_speed_pwm(&self) -> u8 {
        fs::read_to_string(&self.rear_duty_path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map(|duty_ns| amlogic_duty_ns_to_pwm_percent(duty_ns, self.period_ns))
            .unwrap_or(0)
    }

    fn get_per_fan_rpm(&self) -> Vec<(u8, u32)> {
        // S21 has 4 fans (GPIO tach at 447-450). Sample each slot
        // independently so the dashboard / per-fan UI can flag the
        // exact fan that's slowing down.
        self.sample_all_rpm()
    }

    fn fan_count(&self) -> u8 {
        // S21 / S19j Pro Amlogic / S19K Pro: 4 fans (2 front + 2 rear).
        GPIO_FAN_TACH_COUNT as u8
    }

    fn tach_available(&self) -> bool {
        // AmlogicFan can only be constructed after all four channels arm, and
        // any later sampler failure permanently revokes this owner's evidence.
        self.tach_healthy.load(Ordering::Acquire)
    }
}

/// Amlogic GPIO via sysfs.
struct AmlogicGpio;

/// Checked software evidence for one active-low Amlogic hashboard reset write.
///
/// This receipt proves only that the prepared sysfs line reported raw
/// `active_low=0`, output direction, and the commanded logical value after the
/// write. It does not claim an independently measured voltage at the board.
#[derive(Debug)]
pub struct AmlogicResetReceipt {
    chain: u8,
    gpio: u32,
    asserted: bool,
    commanded_value: u8,
    observed_value: u8,
    completed_at: Instant,
}

impl AmlogicResetReceipt {
    pub fn chain(&self) -> u8 {
        self.chain
    }

    pub fn gpio(&self) -> u32 {
        self.gpio
    }

    pub fn asserted(&self) -> bool {
        self.asserted
    }

    pub fn commanded_value(&self) -> u8 {
        self.commanded_value
    }

    pub fn observed_value(&self) -> u8 {
        self.observed_value
    }

    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
}

fn set_amlogic_board_reset_checked_at(
    gpio_root: &Path,
    chain: u8,
    gpio: u32,
    assert_reset: bool,
) -> Result<AmlogicResetReceipt> {
    let root = gpio_root.join(format!("gpio{gpio}"));
    let direction_path = root.join("direction");
    let active_low_path = root.join("active_low");
    let value_path = root.join("value");

    let direction = fs::read_to_string(&direction_path).map_err(|error| {
        HalError::Platform(format!(
            "Amlogic HB{chain} reset GPIO{gpio} direction read failed: {error}"
        ))
    })?;
    if direction.trim() != "out" {
        return Err(HalError::Platform(format!(
            "Amlogic HB{chain} reset GPIO{gpio} is not prepared as output: direction={:?}",
            direction.trim()
        )));
    }

    let active_low = fs::read_to_string(&active_low_path).map_err(|error| {
        HalError::Platform(format!(
            "Amlogic HB{chain} reset GPIO{gpio} active_low read failed: {error}"
        ))
    })?;
    if active_low.trim() != "0" {
        return Err(HalError::Platform(format!(
            "Amlogic HB{chain} reset GPIO{gpio} active_low={:?}; refusing to guess physical reset polarity",
            active_low.trim()
        )));
    }

    // Live S19k/S21 software evidence: raw 0 asserts HB reset, raw 1 releases.
    let commanded_value = if assert_reset { 0 } else { 1 };
    fs::write(&value_path, commanded_value.to_string()).map_err(|error| {
        HalError::Platform(format!(
            "Amlogic HB{chain} reset GPIO{gpio} write {commanded_value} failed: {error}"
        ))
    })?;
    let observed = fs::read_to_string(&value_path).map_err(|error| {
        HalError::Platform(format!(
            "Amlogic HB{chain} reset GPIO{gpio} value readback failed: {error}"
        ))
    })?;
    let observed_value = observed.trim().parse::<u8>().map_err(|error| {
        HalError::Platform(format!(
            "Amlogic HB{chain} reset GPIO{gpio} value readback {:?} is not a bit: {error}",
            observed.trim()
        ))
    })?;
    if observed_value != commanded_value {
        return Err(HalError::Platform(format!(
            "Amlogic HB{chain} reset GPIO{gpio} readback {observed_value} did not match commanded {commanded_value}"
        )));
    }

    Ok(AmlogicResetReceipt {
        chain,
        gpio,
        asserted: assert_reset,
        commanded_value,
        observed_value,
        completed_at: Instant::now(),
    })
}

/// Assert or release one prepared Amlogic hashboard reset and require checked
/// software readback. The name-first resolver preserves GPIO454-456 only as
/// legacy fallbacks; callers receive an error instead of a silent missed write.
pub fn set_amlogic_board_reset_checked(
    chain: u8,
    assert_reset: bool,
) -> Result<AmlogicResetReceipt> {
    let gpio = resolve_reset_gpio_global(chain)?;
    set_amlogic_board_reset_checked_at(Path::new("/sys/class/gpio"), chain, gpio, assert_reset)
}

/// Assert the complete S19k reset trio with checked readback. Every line is
/// attempted even after an earlier failure; callers must still cut GPIO437,
/// but no positive receipt is returned unless all three exact lines match.
pub fn assert_s19k_native_all_resets_checked() -> Result<S19kNativeAllResetsAsserted> {
    let mut reset_gpios = [0u32; 3];
    let mut failures = Vec::new();
    for chain in 0..3u8 {
        match set_amlogic_board_reset_checked(chain, true) {
            Ok(receipt) => {
                let expected_gpio = GPIO_RESET_BASE + u32::from(chain);
                if receipt.gpio() != expected_gpio || !receipt.asserted() {
                    failures.push(format!(
                        "chain{chain} returned gpio{} asserted={} (expected gpio{expected_gpio} asserted=true)",
                        receipt.gpio(),
                        receipt.asserted()
                    ));
                } else {
                    reset_gpios[usize::from(chain)] = receipt.gpio();
                }
            }
            Err(error) => failures.push(format!("chain{chain}: {error}")),
        }
    }
    if !failures.is_empty() {
        return Err(HalError::Platform(format!(
            "native S19k all-reset assertion incomplete: {}",
            failures.join("; ")
        )));
    }
    Ok(S19kNativeAllResetsAsserted { reset_gpios })
}

impl GpioAccess for AmlogicGpio {
    fn read_plug_detect(&self) -> [bool; 3] {
        let mut result = [false; 3];
        for i in 0..3u32 {
            let gpio = match resolve_plug_gpio_global(i) {
                Ok(n) => n,
                Err(error) => {
                    tracing::warn!(
                        slot = i,
                        error = %error,
                        "Amlogic plug-detect name resolve failed; treating slot as empty"
                    );
                    continue;
                }
            };
            let path = format!("/sys/class/gpio/gpio{}/value", gpio);
            result[i as usize] = fs::read_to_string(&path)
                .ok()
                .and_then(|s| s.trim().parse::<u8>().ok())
                .map(|v| v == 1) // Active HIGH: 1 = board present
                .unwrap_or(false);
        }
        result
    }

    fn set_board_reset(&self, chain: u8, assert_reset: bool) {
        if let Err(error) = set_amlogic_board_reset_checked(chain, assert_reset) {
            tracing::error!(
                chain,
                assert_reset,
                error = %error,
                "Amlogic HB reset checked write failed"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// PSU enable for cold boot
// ---------------------------------------------------------------------------

/// GPIO437 PSU gate, selected by exact admitted target. S19k T6 and the
/// independently recovered S21 production provider both drive0 for enable,
///1 for disable. S21 Pro retains its separate profile pending its own trace.
/// Raw `active_low=0` plus software readback is required; this is not a DMM
/// rail measurement. Evidence: R13 production-psu.md, Enable/Disable futures
///0x86efc0/0x86f0cc and terminal sysfs setter0xbed8fc.
const GPIO_PSU_ENABLE: u32 = 437;

/// Linux adapter selected by DCENT's current Amlogic management-fabric policy.
/// This bus number is not derived from the captured U-Boot environment.
pub const AMLOGIC_MANAGEMENT_I2C_BUS: u8 = 1;
const APW_PMBUS_ADDR: u8 = 0x1f;

/// Current Linux raw-write translation of the captured U-Boot command text:
///   `[0x03, 0x00, 0x00]`
///   `[0x01, 0xfc, 0xfc]`
///
/// U-Boot `i2c mw` describes memory-write operations. Without the exact vendor
/// implementation or a bus trace, the command text does not prove these bytes
/// were grouped into identical wire transactions.
const APW_PMBUS_CLEAR_FAULTS: [u8; 3] = [0x03, 0x00, 0x00];
const APW_PMBUS_OPERATION_ENABLE: [u8; 3] = [0x01, 0xfc, 0xfc];

/// Standard PMBus STATUS_WORD command. Some Bitmain APW firmwares NACK generic
/// telemetry; use this as a best-effort audit read, not as the enable proof.
const PMBUS_STATUS_WORD: u8 = 0x79;

/// GPIO pins that must be exported to fix I2C pinmux conflict (BOS-3528).
/// Exporting these GPIOs changes the Amlogic pinmux away from PWM/other
/// functions that corrupt the I2C bus. Must be done BEFORE any I2C access.
/// Verified from BraiinsOS S37board_setup: exported as "in" direction.
/// Legacy sysfs globals. HAL resolves `I2C_SCL`/`I2C_SDA` first.
const GPIO_PINMUX_FIX: [u32; 2] = [476, 477];
const GPIO_LED_RED: u32 = 438;
const GPIO_LED_GREEN: u32 = 453;

/// Retained single owner of the Amlogic management fabric. APW power commands
/// and LM75 telemetry must use this service for the complete hardware session;
/// callers never receive its generic I2C handle.
pub struct AmlogicPowerThermalService {
    i2c: I2cServiceHandle,
    required_slots: [bool; 3],
    lifecycle_owner: Option<AmlogicPowerThermalLifecycleOwner>,
    psu_commit: Arc<AmlogicPsuCommitAuthority>,
    psu_enable_operation_available: bool,
    s21_psu: Option<s21_psu::S21PsuService>,
}

/// Cloneable read-only facade for periodic board-temperature sampling. It has
/// no GPIO or APW enable operation and cannot close the retained worker.
#[derive(Clone)]
pub struct AmlogicThermalPort {
    i2c: I2cServiceHandle,
    required_slots: [bool; 3],
    s21_psu: Option<s21_psu::S21PsuService>,
}

/// Move-only terminal owner transferred to the PSU guard before energization.
/// It combines the sender-free barrier with the exact worker JoinHandle.
pub struct AmlogicPowerThermalLifecycleOwner {
    owner: I2cServiceOwner,
    fence: I2cServiceTerminalFence,
    psu_commit: Arc<AmlogicPsuCommitAuthority>,
    s21_psu: Option<s21_psu::S21PsuService>,
}

#[derive(Debug)]
struct AmlogicPsuCommitAuthority {
    terminal: AtomicBool,
    gpio_commit: Mutex<()>,
    board_target: &'static str,
    recipe: OnceLock<Gpio437DriveRecipe>,
    reset_after_cut: bool,
    native_generation: Option<Arc<()>>,
}

impl AmlogicPsuCommitAuthority {
    fn new(profile: AmlogicNoPicProfile, native_generation: Option<Arc<()>>) -> Self {
        Self {
            terminal: AtomicBool::new(false),
            gpio_commit: Mutex::new(()),
            board_target: profile.board_target(),
            recipe: OnceLock::new(),
            reset_after_cut: profile.modern_s21_geometry().is_some(),
            native_generation,
        }
    }

    fn recipe(&self) -> Result<Gpio437DriveRecipe> {
        self.recipe.get().copied().ok_or_else(|| {
            HalError::Platform(
                "GPIO437 is undriven: no qualified live population recipe; cannot claim SafeOff"
                    .into(),
            )
        })
    }

    fn bind_population(&self, required: [bool; 3], names: [Option<&str>; 3]) -> Result<()> {
        if names
            .iter()
            .zip(required)
            .any(|(name, present)| name.is_some() != present)
        {
            return Err(HalError::Platform(
                "GPIO437 identity/plug population mismatch".into(),
            ));
        }
        let names: Vec<_> = names.into_iter().flatten().collect();
        let recipe = amlogic_gpio437::resolve_population_recipe(self.board_target, &names)
            .map_err(|cause| {
                HalError::Platform(format!("GPIO437 population polarity refused: {cause:?}"))
            })?;
        let _commit = self.begin_enable()?;
        self.recipe.set(recipe).map_err(|_| {
            HalError::Platform(
                "GPIO437 population recipe was already bound; retained custody cannot be rebound"
                    .into(),
            )
        })
    }

    fn latch_terminal(&self) {
        self.terminal.store(true, Ordering::SeqCst);
    }

    fn is_terminal(&self) -> bool {
        self.terminal.load(Ordering::SeqCst)
    }

    fn begin_enable(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        if self.is_terminal() {
            return Err(amlogic_psu_enable_superseded(
                "Amlogic power lifecycle was terminally fenced before GPIO enable",
            ));
        }
        let commit = match self.gpio_commit.lock() {
            Ok(commit) => commit,
            Err(poisoned) => {
                let commit = poisoned.into_inner();
                let rollback = self.recipe().and_then(disable_psu_checked_for_recipe);
                drop(commit);
                return Err(HalError::Platform(match rollback {
                    Ok(_) => "Amlogic PSU GPIO commit fence was poisoned; polarity-selected checked SafeOff rollback completed and enable was refused".into(),
                    Err(error) => format!(
                        "Amlogic PSU GPIO commit fence was poisoned; enable was refused and polarity-selected checked SafeOff rollback failed ({error})"
                    ),
                }));
            }
        };
        if self.is_terminal() {
            return Err(amlogic_psu_enable_superseded(
                "Amlogic power lifecycle became terminal while waiting for the GPIO commit fence",
            ));
        }
        Ok(commit)
    }

    fn begin_terminal_cut(&self) -> std::sync::MutexGuard<'_, ()> {
        self.latch_terminal();
        self.gpio_commit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn amlogic_psu_enable_superseded(detail: &'static str) -> HalError {
    HalError::I2cSafetySuperseded {
        bus: AMLOGIC_MANAGEMENT_I2C_BUS,
        addr: APW_PMBUS_ADDR,
        detail: detail.into(),
    }
}

impl AmlogicPowerThermalLifecycleOwner {
    /// Preserve the identity-qualified parameters in an abort-time crash arm.
    /// This supplies no ownership or energizing permission.
    pub fn gpio437_recipe(&self) -> Result<Gpio437DriveRecipe> {
        self.psu_commit.recipe()
    }

    pub fn latch_terminal_safe_off(&self) -> TerminalSafeOffTransition {
        self.psu_commit.latch_terminal();
        if let Some(psu) = &self.s21_psu {
            psu.fence();
        }
        self.fence.latch_terminal_safe_off()
    }

    /// Latch both mutation domains and complete the SKU-selected checked GPIO
    /// SafeOff operation while holding the same commit fence used by the
    /// one-shot enable path. Once this returns, no later enable can commit.
    pub fn latch_terminal_and_disable_psu_checked(
        &self,
    ) -> Result<(TerminalSafeOffTransition, PsuSafeOffReceipt)> {
        self.psu_commit.latch_terminal();
        if let Some(psu) = &self.s21_psu {
            psu.fence();
        }
        let transition = self.fence.latch_terminal_safe_off();
        let _gpio_commit = self.psu_commit.begin_terminal_cut();
        let receipt = disable_psu_checked_for_recipe(self.psu_commit.recipe()?)?;
        if self.psu_commit.reset_after_cut {
            let mut failures = Vec::new();
            for slot in 0..3 {
                if let Err(error) = set_amlogic_board_reset_checked(slot, true) {
                    failures.push(error.to_string());
                }
            }
            if !failures.is_empty() {
                return Err(HalError::Platform(format!(
                    "S21 power cut completed; reset assertion incomplete: {}",
                    failures.join("; ")
                )));
            }
        }
        Ok((transition, receipt))
    }

    pub fn close_and_join_until(&mut self, deadline: Instant) -> Result<I2cServiceCloseReceipt> {
        let _ = self.latch_terminal_safe_off();
        if let Some(psu) = &self.s21_psu {
            psu.close_until(deadline)?;
        }
        self.owner.close_and_join_until(deadline)
    }
}

/// Move-only, one-shot composite PSU enable operation. A terminal owner sets
/// the shared flag before fencing I2C, so a GPIO-enable race is rechecked
/// before the APW transaction and rolled back to SKU-selected SafeOff.
pub struct AmlogicPsuEnableOperation {
    i2c: I2cServiceHandle,
    psu_commit: Arc<AmlogicPsuCommitAuthority>,
    s21_psu: Option<s21_psu::S21PsuService>,
}

/// Software evidence that both fixed APW enable writes completed. Optional
/// STATUS_WORD is diagnostic only and does not prove physical rail voltage.
#[derive(Debug)]
pub struct ApwEnableReceipt {
    writes_completed_at: Instant,
    status_word: Option<u16>,
    native_generation: Option<Arc<()>>,
}

impl ApwEnableReceipt {
    pub fn writes_completed_at(&self) -> Instant {
        self.writes_completed_at
    }

    pub fn status_word(&self) -> Option<u16> {
        self.status_word
    }
}

impl AmlogicPowerThermalService {
    /// Reserve `/dev/i2c-1`, perform the checked BOS-3528 pinmux preparation
    /// under that reservation, and start one kernel-fd-only service.
    fn spawn(admission: &AmlogicNoPicAdmission) -> Result<Self> {
        let mut service = Self::spawn_with_required_slots_and_generation(
            admission.populated_slots(),
            admission.profile(),
            Some(Arc::clone(&admission.generation)),
        )?;
        service.psu_enable_operation_available = true;
        Ok(service)
    }

    /// Track-1 leftover: own TMP75 on i2c-1 without taking a GPIO437 / PSU lease.
    pub fn spawn_track1_temps(required_slots: [bool; 3]) -> Result<Self> {
        let mut service =
            Self::spawn_with_required_slots(required_slots, AmlogicNoPicProfile::S19k)?;
        service.psu_enable_operation_available = false;
        Ok(service)
    }

    fn spawn_with_required_slots(
        required_slots: [bool; 3],
        profile: AmlogicNoPicProfile,
    ) -> Result<Self> {
        Self::spawn_with_required_slots_and_generation(required_slots, profile, None)
    }

    fn spawn_with_required_slots_and_generation(
        required_slots: [bool; 3],
        profile: AmlogicNoPicProfile,
        native_generation: Option<Arc<()>>,
    ) -> Result<Self> {
        let gpio_psu_profile = profile.gpio_psu_profile(native_generation.is_some());
        // The GPIO PSU reservation owns476/477. The native kernel-i2c-1
        // adapter is a distinct fabric; its startup must not touch PSU wires.
        // The hashboard EEPROM write-denylist belongs HERE, not only on the
        // bus-0 helper. On am3-aml the AT24C-class hashboard EEPROMs answer on
        // bus 1 — this bus — so registering an empty denylist left the
        // post-`a lab unit` write-protection guarantee covering a bus with no EEPROMs
        // on it. Evidence, three independent arms:
        //   * the artifact we ship ourselves declares `"i2c_bus": 1` for every
        //     board (board/amlogic/am3-s19kpro/.../etc/dcentos/hashboard_decoded.json,
        //     pinned by a test in `i2c_eeprom_denylist_breadth.rs`)
        //   * the live `a lab unit` probe: bus 0 scans entirely empty and every bus-0
        //     read fails, while bus 1 answers at 0x50/0x51/0x52
        //   * S21 dmesg pins `i2c-1` to the AO adapter 0xff805000
        // The denylist is write-only, so hashboard identity READS are unaffected.
        let owner =
            spawn_owned_i2c_service_no_register_touch_with_denylist_and_reserved_preparation(
                AMLOGIC_MANAGEMENT_I2C_BUS,
                AMLOGIC_EEPROM_DENYLIST.to_vec(),
                move || {
                    if gpio_psu_profile.is_some() {
                        Ok(())
                    } else {
                        prepare_management_i2c_pinmux()
                    }
                },
            )
            .map_err(|error| {
                HalError::Platform(format!(
                    "failed to reserve Amlogic management I2C fabric: {error}"
                ))
            })?;
        let i2c = owner.request_handle();
        let fence = owner.terminal_fence();
        let psu_commit = Arc::new(AmlogicPsuCommitAuthority::new(profile, native_generation));
        // A synchronous control round-trip proves the worker opened its fd and
        // accepted the fixed timeout before any power or telemetry operation.
        i2c.set_timeout(10)?;
        let s21_psu = gpio_psu_profile
            .map(s21_psu::S21PsuService::open)
            .transpose()?;
        Ok(Self {
            i2c,
            required_slots,
            lifecycle_owner: Some(AmlogicPowerThermalLifecycleOwner {
                owner,
                fence,
                psu_commit: Arc::clone(&psu_commit),
                s21_psu: s21_psu.clone(),
            }),
            psu_commit,
            psu_enable_operation_available: false,
            s21_psu,
        })
    }

    pub fn take_lifecycle_owner(&mut self) -> Result<AmlogicPowerThermalLifecycleOwner> {
        self.lifecycle_owner.take().ok_or_else(|| {
            HalError::Platform(
                "Amlogic power/thermal lifecycle owner was already transferred".into(),
            )
        })
    }

    pub fn take_psu_enable_operation(&mut self) -> Result<AmlogicPsuEnableOperation> {
        if !self.psu_enable_operation_available {
            return Err(HalError::Platform(
                "Amlogic PSU enable operation was already consumed".into(),
            ));
        }
        if self.psu_commit.is_terminal() {
            return Err(amlogic_psu_enable_superseded(
                "Amlogic power lifecycle was terminally fenced before PSU enable",
            ));
        }
        self.psu_enable_operation_available = false;
        Ok(AmlogicPsuEnableOperation {
            i2c: self.i2c.clone(),
            psu_commit: Arc::clone(&self.psu_commit),
            s21_psu: self.s21_psu.clone(),
        })
    }

    pub fn service_psu_heartbeat(&self) -> Result<()> {
        if let Some(psu) = &self.s21_psu {
            psu.heartbeat()?;
        }
        Ok(())
    }

    pub fn thermal_port(&self) -> AmlogicThermalPort {
        AmlogicThermalPort {
            i2c: self.i2c.clone(),
            required_slots: self.required_slots,
            s21_psu: self.s21_psu.clone(),
        }
    }
}

/// Hold leftover rails-up fans at PWM 100 only under the daemon's explicit
/// `--allow-loud` authority. Refusal occurs before any sysfs mutation.
pub fn hold_track1_leftover_fans_pwm100(explicit_loud_authority: bool) -> Result<()> {
    if !explicit_loud_authority {
        return Err(HalError::Fan(
            "Track-1 PWM 100 requires explicit --allow-loud authority".into(),
        ));
    }
    const DUTY: &str = "100000";
    for ch in ["pwm0", "pwm1"] {
        let base = format!("/sys/class/pwm/pwmchip0/{ch}");
        let _ = fs::write(format!("{base}/enable"), "1");
        fs::write(format!("{base}/duty_cycle"), DUTY).map_err(|error| {
            HalError::Fan(format!("Track-1 leftover {ch} PWM 100 write: {error}"))
        })?;
        let observed = fs::read_to_string(format!("{base}/duty_cycle")).map_err(|error| {
            HalError::Fan(format!("Track-1 leftover {ch} PWM 100 readback: {error}"))
        })?;
        if observed.trim() != DUTY {
            return Err(HalError::Fan(format!(
                "Track-1 leftover {ch} PWM 100 readback mismatch: {}",
                observed.trim()
            )));
        }
    }
    Ok(())
}

/// Open the four-channel tach owner used by the S19k Track-1 leftover path.
/// This does not change PWM, GPIO437, reset, or I2C state; callers must retain
/// the owner and pair measurements with the explicit PWM100 hold.
pub fn open_track1_leftover_fan_tach() -> Result<Arc<dyn FanAccess>> {
    Ok(Arc::new(AmlogicFan::new()?))
}

struct AmlogicPsuGpioRollback {
    armed: bool,
    recipe: Gpio437DriveRecipe,
}

impl AmlogicPsuGpioRollback {
    fn armed(recipe: Gpio437DriveRecipe) -> Self {
        Self {
            armed: true,
            recipe,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn attach_checked_rollback(&mut self, primary: HalError, operation: &'static str) -> HalError {
        match disable_psu_checked_for_recipe(self.recipe) {
            Ok(_) => {
                self.disarm();
                primary
            }
            Err(rollback_error) => HalError::Platform(format!(
                "{operation} ({primary}); checked rollback also failed ({rollback_error})"
            )),
        }
    }
}

impl Drop for AmlogicPsuGpioRollback {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = disable_psu_checked_for_recipe(self.recipe) {
                tracing::error!(
                    %error,
                    "Amlogic PSU enable unwound with possible enabled GPIO state; emergency polarity-selected checked SafeOff rollback failed"
                );
            }
        }
    }
}

impl AmlogicPsuEnableOperation {
    /// Enable GPIO437 and issue the two fixed DCENT APW compatibility writes
    /// derived from captured S19K Pro `a lab unit` U-Boot command text. Any failure
    /// after the GPIO mutation performs checked GPIO rollback before returning.
    pub fn enable_psu(self) -> Result<ApwEnableReceipt> {
        self.enable_psu_at_voltage(13.55)
    }

    pub fn enable_psu_at_voltage(self, voltage: f64) -> Result<ApwEnableReceipt> {
        let recipe = self.psu_commit.recipe()?;
        // Identify the dedicated controller before making the rail available.
        if let Some(psu) = &self.s21_psu {
            psu.discover()?;
        }
        let gpio_commit = self.psu_commit.begin_enable()?;
        // Arm before the first GPIO call: an unwind after any partial sysfs
        // mutation must issue the SKU-selected SafeOff value while the commit
        // fence is still held.
        let mut rollback = AmlogicPsuGpioRollback::armed(recipe);
        if let Err(enable_error) = enable_psu_gpio_for_recipe(recipe) {
            return Err(rollback.attach_checked_rollback(enable_error, "PSU GPIO enable failed"));
        }
        if self.psu_commit.is_terminal() {
            let superseded = amlogic_psu_enable_superseded(
                "terminal safe-off raced GPIO enable before the APW transaction",
            );
            return Err(rollback
                .attach_checked_rollback(superseded, "PSU enable was terminally superseded"));
        }
        let configure = if let Some(psu) = &self.s21_psu {
            psu.initialize(voltage)
        } else {
            self.enable_apw()
        };
        if let Err(enable_error) = configure {
            return Err(rollback.attach_checked_rollback(enable_error, "PSU PMBus enable failed"));
        }
        if self.psu_commit.is_terminal() {
            let superseded = amlogic_psu_enable_superseded(
                "terminal safe-off raced the APW transaction before GPIO enable commit",
            );
            return Err(rollback
                .attach_checked_rollback(superseded, "PSU enable was terminally superseded"));
        }

        let writes_completed_at = Instant::now();
        rollback.disarm();
        drop(rollback);
        drop(gpio_commit);
        std::thread::sleep(Duration::from_secs(2));
        let status_word = if self.s21_psu.is_some() {
            None
        } else {
            match self.read_apw_status_word() {
                Ok(status) => {
                    tracing::info!(
                        bus = AMLOGIC_MANAGEMENT_I2C_BUS,
                        addr = format_args!("0x{:02X}", APW_PMBUS_ADDR),
                        status = format_args!("0x{:04X}", status),
                        "Amlogic APW enable writes completed; optional STATUS_WORD available"
                    );
                    Some(status)
                }
                Err(error) => {
                    tracing::warn!(
                        bus = AMLOGIC_MANAGEMENT_I2C_BUS,
                        addr = format_args!("0x{:02X}", APW_PMBUS_ADDR),
                        %error,
                        "Amlogic APW enable writes completed; optional STATUS_WORD unavailable"
                    );
                    None
                }
            }
        };
        Ok(ApwEnableReceipt {
            writes_completed_at,
            status_word,
            native_generation: self.psu_commit.native_generation.clone(),
        })
    }

    fn enable_apw(&self) -> Result<()> {
        self.i2c.transaction_mutating(
            I2cMutationLabel::Energize,
            APW_PMBUS_ADDR,
            vec![
                I2cTransactionStep::Write(APW_PMBUS_CLEAR_FAULTS.to_vec()),
                I2cTransactionStep::SleepMs(10),
                I2cTransactionStep::Write(APW_PMBUS_OPERATION_ENABLE.to_vec()),
                I2cTransactionStep::SleepMs(200),
            ],
        )?;
        Ok(())
    }

    fn read_apw_status_word(&self) -> Result<u16> {
        let bytes = self.i2c.write_read_mutating(
            I2cMutationLabel::QueryPrelude,
            APW_PMBUS_ADDR,
            &[PMBUS_STATUS_WORD],
            2,
        )?;
        let bytes: [u8; 2] = bytes.try_into().map_err(|bytes: Vec<u8>| HalError::I2c {
            bus: AMLOGIC_MANAGEMENT_I2C_BUS,
            addr: APW_PMBUS_ADDR,
            detail: format!(
                "APW STATUS_WORD returned {} byte(s); exactly 2 required",
                bytes.len()
            ),
        })?;
        Ok(u16::from_le_bytes(bytes))
    }
}

impl AmlogicThermalPort {
    pub fn service_psu_heartbeat(&self) -> Result<()> {
        if let Some(psu) = &self.s21_psu {
            psu.heartbeat()?;
        }
        Ok(())
    }

    /// Capture all statically mapped board sensors through the same retained
    /// fabric owner. Unpowered/unpopulated endpoints remain explicit evidence
    /// in the returned snapshot rather than causing an adapter reset.
    pub fn read_board_temperatures(&self, deadline: Instant) -> AmlogicTemperatureSnapshot {
        let mut readings = Vec::with_capacity(AMLOGIC_TEMPERATURE_ENDPOINTS.len());
        let mut unavailable = Vec::new();
        for endpoint in AMLOGIC_TEMPERATURE_ENDPOINTS {
            match self
                .i2c
                .read_lm75_temperature_register_at(endpoint.address, deadline)
            {
                // LM75-family wire values top out below 128 C. Preserve every
                // high observation as hot evidence; 125 C must never be hidden
                // as "unavailable" while a cooler endpoint survives.
                Ok(register) if register.celsius() >= -40.0 => {
                    readings.push(AmlogicTemperatureReading { endpoint, register });
                }
                Ok(register) => unavailable.push(AmlogicTemperatureUnavailable {
                    endpoint,
                    reason: AmlogicTemperatureUnavailableReason::BelowAdmittedRange {
                        raw_register: register.raw_be(),
                    },
                    detail: format!(
                        "temperature {:.4} C is below the admitted board-sensor range",
                        register.celsius()
                    ),
                }),
                Err(error) => unavailable.push(AmlogicTemperatureUnavailable {
                    endpoint,
                    reason: AmlogicTemperatureUnavailableReason::from_hal_error(&error),
                    detail: error.to_string(),
                }),
            }
        }
        AmlogicTemperatureSnapshot {
            required_slots: self.required_slots,
            readings,
            unavailable,
        }
    }
}

/// Resolve the PSU enable GPIO. Name-first `PWR_CONTROL`, legacy sysfs 437
/// only when the DT name is absent.
///
/// gpio437 polarity is **board_target scoped** (not one Amlogic pin):
///   - S21-class NoPic: 1=ON / SafeOff=0
///   - S19k / am3-s19k: 0=ON / 1=OFF
/// Software SafeOff is not VerifiedRailCut. S21/VNish `echo 1` is that
/// board_target's start pattern, not a universal enable.
pub fn resolve_psu_gpio_global() -> Result<u32> {
    let resolved =
        crate::gpio_name_resolver::resolve_name_or_legacy("PWR_CONTROL", GPIO_PSU_ENABLE)?;
    s19k_am3_pwr_control_sysfs_n(resolved.global()).map_err(|e| HalError::Platform(e.into()))
}

/// Name-first `CH0_PLUG`/`CH1_PLUG`/`CH2_PLUG`. Legacy 439–441 only when
/// this kernel publishes no such name (VNish DTB). Not Zynq `HB0_PLUG`.
pub fn resolve_plug_gpio_global(slot: u32) -> Result<u32> {
    let name = match slot {
        0 => "CH0_PLUG",
        1 => "CH1_PLUG",
        2 => "CH2_PLUG",
        _ => {
            return Err(HalError::Platform(format!(
                "Amlogic plug slot {slot} out of range; S19k/S21 have 3 boards"
            )));
        }
    };
    let resolved = crate::gpio_name_resolver::resolve_name_or_legacy(name, GPIO_PLUG_BASE + slot)?;
    s19k_am3_plug_sysfs_n(slot as u8, resolved.global()).map_err(|e| HalError::Platform(e.into()))
}

/// Name-first `HB0_RESET`/`HB1_RESET`/`HB2_RESET`. Legacy 454–456 only when
/// the DT name is absent. `HB3_RESET` is not a fourth S19k board.
fn resolve_reset_gpio_global(chain: u8) -> Result<u32> {
    let name = match chain {
        0 => "HB0_RESET",
        1 => "HB1_RESET",
        2 => "HB2_RESET",
        _ => {
            return Err(HalError::Platform(format!(
                "Amlogic HB reset chain {chain} out of range; S19k has 3 boards (HB3_RESET is not a 4th slot)"
            )));
        }
    };
    let resolved = crate::gpio_name_resolver::resolve_name_or_legacy(
        name,
        GPIO_RESET_BASE + u32::from(chain),
    )?;
    s19k_am3_reset_sysfs_n(chain, resolved.global()).map_err(|e| HalError::Platform(e.into()))
}

/// Name-first S21 Braiins tach names. Legacy 447–450 only when absent.
/// ePIC 461–464 is a different revision — not this fallback.
fn resolve_fan_tach_gpio_global(slot: usize) -> Result<u32> {
    let name = match slot {
        0 => "FAN_FRONT_SPEED0",
        1 => "FAN_FRONT_SPEED1",
        2 => "FAN_REAR_SPEED0",
        3 => "FAN_REAR_SPEED1",
        _ => {
            return Err(HalError::Platform(format!(
                "Amlogic fan tach slot {slot} out of range; 4 channels"
            )));
        }
    };
    let resolved =
        crate::gpio_name_resolver::resolve_name_or_legacy(name, GPIO_FAN_TACH_BASE + slot as u32)?;
    s19k_am3_fan_tach_sysfs_n(slot as u8, resolved.global())
        .map_err(|e| HalError::Platform(e.into()))
}

/// Name-first `LED_RED`/`LED_GREEN`. Legacy 438/453 only when absent.
fn resolve_led_gpio_global(red: bool) -> Result<u32> {
    let (name, legacy) = if red {
        ("LED_RED", GPIO_LED_RED)
    } else {
        ("LED_GREEN", GPIO_LED_GREEN)
    };
    let resolved = crate::gpio_name_resolver::resolve_name_or_legacy(name, legacy)?;
    s19k_am3_led_sysfs_n(resolved.global()).map_err(|e| HalError::Platform(e.into()))
}

/// Name-first `I2C_SCL`/`I2C_SDA`. Legacy 476/477 only when absent.
fn resolve_pinmux_gpio_global(scl: bool) -> Result<u32> {
    let (name, legacy) = if scl {
        ("I2C_SCL", GPIO_PINMUX_FIX[0])
    } else {
        ("I2C_SDA", GPIO_PINMUX_FIX[1])
    };
    let resolved = crate::gpio_name_resolver::resolve_name_or_legacy(name, legacy)?;
    s19k_am3_pinmux_sysfs_n(resolved.global()).map_err(|e| HalError::Platform(e.into()))
}

/// Best-effort status LED write after name resolve. Active HIGH.
/// Does not change PSU or reset. Track-1 must not call this.
pub fn write_amlogic_status_led(red: bool, on: bool) -> Result<()> {
    let n = resolve_led_gpio_global(red)?;
    let gpio_path = format!("/sys/class/gpio/gpio{n}/value");
    if !Path::new(&gpio_path).exists() {
        let _ = fs::write("/sys/class/gpio/export", n.to_string());
        std::thread::sleep(Duration::from_millis(50));
    }
    let dir_path = format!("/sys/class/gpio/gpio{n}/direction");
    if Path::new(&dir_path).exists() {
        let _ = fs::write(&dir_path, "out");
    }
    let value = if on { "1" } else { "0" };
    fs::write(&gpio_path, value).map_err(|e| {
        HalError::Platform(format!(
            "Amlogic {} LED write failed: {e}",
            if red { "RED" } else { "GREEN" }
        ))
    })?;
    Ok(())
}

fn enable_psu_gpio_for_recipe(recipe: Gpio437DriveRecipe) -> Result<()> {
    let n = resolve_psu_gpio_global()?;
    drive_psu_checked_at(
        Path::new("/sys/class/gpio"),
        n,
        recipe,
        true,
        |path, value| fs::write(path, value),
    )
}

/// All output writes share the qualified table recipe. The writer argument
/// models the sysfs direction ABI in offline fixtures; production uses fs::write.
fn drive_psu_checked_at(
    gpio_root: &Path,
    n: u32,
    recipe: Gpio437DriveRecipe,
    on: bool,
    mut write: impl FnMut(&Path, &str) -> std::io::Result<()>,
) -> Result<()> {
    let base = gpio_root.join(format!("gpio{n}"));
    let operation = || {
        format!(
            "GPIO{n} {} for {}",
            if on { "ON" } else { "OFF" },
            recipe.board_target()
        )
    };
    if !base.join("value").exists() {
        write(&gpio_root.join("export"), &n.to_string())
            .map_err(|cause| HalError::Platform(format!("{} export: {cause}", operation())))?;
        std::thread::sleep(Duration::from_millis(100));
    }
    // Inversion changes must happen while input; changing active_low on an
    // existing output must never generate an unrequested ON edge.
    let active_low = fs::read_to_string(base.join("active_low"))
        .map_err(|cause| HalError::Platform(format!("{} active_low: {cause}", operation())))?;
    if active_low.trim() != "0" {
        write(&base.join("direction"), "in")
            .map_err(|cause| HalError::Platform(format!("{} input: {cause}", operation())))?;
        if fs::read_to_string(base.join("direction"))?.trim() != "in" {
            return Err(HalError::Platform(
                "GPIO437 inversion normalization requires input readback".into(),
            ));
        }
        write(&base.join("active_low"), "0")
            .map_err(|cause| HalError::Platform(format!("{} normalize: {cause}", operation())))?;
    }
    read_psu_active_low_disabled_checked_at(gpio_root, n)?;
    write(&base.join("direction"), recipe.off_direction()).map_err(|cause| {
        HalError::Platform(format!("{} initial OFF direction: {cause}", operation()))
    })?;
    let raw = if on {
        recipe.on_raw()
    } else {
        recipe.off_raw()
    };
    write(&base.join("value"), &raw.to_string())
        .map_err(|cause| HalError::Platform(format!("{} raw write: {cause}", operation())))?;
    if read_psu_enabled_on_with_recipe_at(gpio_root, n, recipe)? != on {
        return Err(HalError::Platform(format!(
            "{} readback mismatch",
            operation()
        )));
    }
    Ok(())
}

fn read_psu_active_low_disabled_checked_at(gpio_root: &Path, n: u32) -> Result<()> {
    let path = gpio_root.join(format!("gpio{n}/active_low"));
    let value = fs::read_to_string(&path)
        .map_err(|error| HalError::Platform(format!("PSU GPIO active_low readback: {error}")))?;
    if value.trim() == "0" {
        Ok(())
    } else {
        Err(HalError::Platform(format!(
            "PSU GPIO {} active_low readback was {:?}, expected raw active-high mode 0",
            n,
            value.trim()
        )))
    }
}

/// Checked software safe-off evidence for GPIO437. This proves that the
/// SKU-scoped sysfs SafeOff write completed and a subsequent fallible readback
/// matched it; it does not claim an independently measured physical rail.
#[derive(Debug)]
pub struct PsuSafeOffReceipt {
    gpio: u32,
    completed_at: Instant,
}

impl PsuSafeOffReceipt {
    pub fn gpio(&self) -> u32 {
        self.gpio
    }

    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
}

/// Legacy standalone cut/read callers have no live population token. Only
/// a fully qualified boot profile can supply parameters; unknowns refuse.
fn amlogic_marker_drive_recipe() -> Result<Gpio437DriveRecipe> {
    let target = fs::read_to_string("/etc/dcentos/board_target")
        .map_err(|cause| HalError::Platform(format!("GPIO437 board target read: {cause}")))?;
    amlogic_gpio437::resolve_drive_recipe(target.trim()).map_err(|cause| {
        HalError::Platform(format!("GPIO437 standalone polarity refused: {cause:?}"))
    })
}

fn disable_psu_checked_for_recipe(recipe: Gpio437DriveRecipe) -> Result<PsuSafeOffReceipt> {
    let n = resolve_psu_gpio_global()?;
    drive_psu_checked_at(
        Path::new("/sys/class/gpio"),
        n,
        recipe,
        false,
        |path, value| fs::write(path, value),
    )?;
    Ok(PsuSafeOffReceipt {
        gpio: n,
        completed_at: Instant::now(),
    })
}

/// Abort-time cutoff with parameters retained before energization. The caller
/// must already own this exact population; this never rereads a board marker.
pub fn disable_psu_with_retained_recipe_checked(
    recipe: Gpio437DriveRecipe,
) -> Result<PsuSafeOffReceipt> {
    disable_psu_checked_for_recipe(recipe)
}

pub fn disable_psu_checked() -> Result<PsuSafeOffReceipt> {
    disable_psu_checked_for_recipe(amlogic_marker_drive_recipe()?)
}

/// Already-admitted Track-1 S19k standalone cutoff. This uses the exact
/// fully-covered table row and never consults a mutable persistent marker.
pub fn disable_s19k_track1_psu_checked() -> Result<PsuSafeOffReceipt> {
    let recipe = amlogic_gpio437::resolve_drive_recipe("am3-s19k")
        .map_err(|cause| HalError::Platform(format!("S19k Track-1 polarity refused: {cause:?}")))?;
    disable_psu_checked_for_recipe(recipe)
}

pub fn disable_psu() -> Result<()> {
    disable_psu_checked().map(|_| ())
}

pub fn read_psu_enabled_checked() -> Result<bool> {
    let recipe = amlogic_marker_drive_recipe()?;
    let n = resolve_psu_gpio_global()?;
    read_psu_enabled_on_with_recipe_at(Path::new("/sys/class/gpio"), n, recipe)
}

pub fn read_s19k_track1_psu_engaged_checked() -> Result<bool> {
    let recipe = amlogic_gpio437::resolve_drive_recipe("am3-s19k")
        .map_err(|cause| HalError::Platform(format!("S19k Track-1 polarity refused: {cause:?}")))?;
    let n = resolve_psu_gpio_global()?;
    read_psu_enabled_on_with_recipe_at(Path::new("/sys/class/gpio"), n, recipe)
}

fn read_psu_enabled_on_with_recipe_at(
    gpio_root: &Path,
    n: u32,
    recipe: Gpio437DriveRecipe,
) -> Result<bool> {
    read_psu_active_low_disabled_checked_at(gpio_root, n)?;
    let base = gpio_root.join(format!("gpio{n}"));
    if fs::read_to_string(base.join("direction"))?.trim() != "out" {
        return Err(HalError::Platform(
            "GPIO437 is undriven; input value cannot prove ON or OFF".into(),
        ));
    }
    let value = fs::read_to_string(base.join("value"))
        .map_err(|cause| HalError::Platform(format!("PSU GPIO readback: {cause}")))?;
    parse_psu_gpio_engaged(&value, recipe)
}

fn parse_psu_gpio_engaged(value: &str, recipe: Gpio437DriveRecipe) -> Result<bool> {
    match value.trim() {
        "0" | "1" => Ok(value.trim() == recipe.on_raw().to_string()),
        other => Err(HalError::Platform(format!(
            "PSU GPIO readback was neither 0 nor 1: {other:?}"
        ))),
    }
}

/// Lossy telemetry compatibility helper. Safety decisions must use
/// [`read_psu_enabled_checked`] or [`disable_psu_checked`].
pub fn is_psu_enabled() -> bool {
    read_psu_enabled_checked().unwrap_or(false)
}

/// Checked BOS-3528 pinmux preparation. This runs only inside the bus-1 fabric
/// reservation, before the worker opens `/dev/i2c-1`.
fn prepare_management_i2c_pinmux() -> std::io::Result<()> {
    let export_path = "/sys/class/gpio/export";
    let resolved = [
        resolve_pinmux_gpio_global(true)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?,
        resolve_pinmux_gpio_global(false)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?,
    ];
    for gpio in resolved {
        let gpio_dir = format!("/sys/class/gpio/gpio{}", gpio);
        let gpio_path = Path::new(&gpio_dir);
        if !gpio_path.exists() {
            if let Err(error) = fs::write(export_path, gpio.to_string()) {
                if error.raw_os_error() != Some(libc::EBUSY) {
                    return Err(std::io::Error::new(
                        error.kind(),
                        format!("failed to export pinmux GPIO {gpio}: {error}"),
                    ));
                }
            }
        }

        let ready_deadline = Instant::now() + Duration::from_millis(500);
        while !gpio_path.exists() && Instant::now() < ready_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !gpio_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("pinmux GPIO {gpio} did not appear after export"),
            ));
        }

        let direction_path = format!("{gpio_dir}/direction");
        fs::write(&direction_path, "in").map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("failed to set pinmux GPIO {gpio} input: {error}"),
            )
        })?;
        let observed = fs::read_to_string(&direction_path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("failed to read pinmux GPIO {gpio} direction: {error}"),
            )
        })?;
        if observed.trim() != "in" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "pinmux GPIO {gpio} direction readback was {:?}, expected input",
                    observed.trim()
                ),
            ));
        }
        tracing::debug!(gpio, "Amlogic management-I2C pinmux GPIO verified as input");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Temperature sensor reading (LM75-compatible)
// ---------------------------------------------------------------------------

/// LM75-compatible sensor addresses on Amlogic-platform hash boards.
///
/// Verified live (.78, S19K Pro NoPic, 2026-04-29) via `bosminer.log`:
///   hb1: address 72 (inlet), 76 (outlet)   → 0x48 / 0x4C
///   hb2: address 73 (inlet), 77 (outlet)   → 0x49 / 0x4D
///   hb3: address 74 (inlet), 78 (outlet)   → 0x4A / 0x4E
///
/// Per-chain layout: inlets at `0x48 + chain_id`, outlets at
/// `0x4C + chain_id`. Same convention applies to S21 / S21 Pro / S19j Pro
/// Amlogic / S19K Pro NoPic / S19 XP — all am3-aml hashboard families.
///
/// **Bug fix history**: Pre-2026-04-29 this const declared `(0x73, ...)`
/// which was the decimal-as-hex confusion (decimal 73 = hex 0x49). The
/// raw I²C ioctl at line ~488 would NACK on hex 0x73 (no device present),
/// so temperature reads silently failed. Per Phase H.5 expert-agent
/// finding (Thermal+Perf).
///
/// The table below is keyed by physical slot, not a runtime chain count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmlogicTemperaturePosition {
    Inlet,
    Outlet,
}

/// Board-slot-bound sensor endpoint. This is physical wiring data and must
/// never be inferred from ASIC count or runtime chain enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmlogicTemperatureEndpoint {
    slot: u8,
    address: u8,
    position: AmlogicTemperaturePosition,
}

impl AmlogicTemperatureEndpoint {
    pub fn slot(self) -> u8 {
        self.slot
    }

    pub fn address(self) -> u8 {
        self.address
    }

    pub fn position(self) -> AmlogicTemperaturePosition {
        self.position
    }
}

/// Verified live on the .78 S19K Pro: inlet 0x48..=0x4a and outlet
/// 0x4c..=0x4e, paired by physical board slot.
const AMLOGIC_TEMPERATURE_ENDPOINTS: [AmlogicTemperatureEndpoint; 6] = [
    AmlogicTemperatureEndpoint {
        slot: 0,
        address: 0x48,
        position: AmlogicTemperaturePosition::Inlet,
    },
    AmlogicTemperatureEndpoint {
        slot: 0,
        address: 0x4c,
        position: AmlogicTemperaturePosition::Outlet,
    },
    AmlogicTemperatureEndpoint {
        slot: 1,
        address: 0x49,
        position: AmlogicTemperaturePosition::Inlet,
    },
    AmlogicTemperatureEndpoint {
        slot: 1,
        address: 0x4d,
        position: AmlogicTemperaturePosition::Outlet,
    },
    AmlogicTemperatureEndpoint {
        slot: 2,
        address: 0x4a,
        position: AmlogicTemperaturePosition::Inlet,
    },
    AmlogicTemperatureEndpoint {
        slot: 2,
        address: 0x4e,
        position: AmlogicTemperaturePosition::Outlet,
    },
];

#[derive(Debug, Clone, Copy)]
pub struct AmlogicTemperatureReading {
    endpoint: AmlogicTemperatureEndpoint,
    register: Lm75TemperatureRegister,
}

impl AmlogicTemperatureReading {
    pub fn endpoint(self) -> AmlogicTemperatureEndpoint {
        self.endpoint
    }

    pub fn raw_register(self) -> i16 {
        self.register.raw_be()
    }

    pub fn celsius(self) -> f32 {
        self.register.celsius()
    }
}

#[derive(Debug, Clone)]
pub struct AmlogicTemperatureUnavailable {
    endpoint: AmlogicTemperatureEndpoint,
    reason: AmlogicTemperatureUnavailableReason,
    detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmlogicTemperatureUnavailableReason {
    BelowAdmittedRange { raw_register: i16 },
    EndpointNotReady,
    EndpointRefused,
    TransportFault,
}

impl AmlogicTemperatureUnavailableReason {
    fn from_hal_error(error: &HalError) -> Self {
        match error {
            HalError::I2cEndpointNotReady { .. } => Self::EndpointNotReady,
            HalError::I2cEndpointRefused { .. }
            | HalError::I2cAdmissionBusy { .. }
            | HalError::I2cSafetySuperseded { .. } => Self::EndpointRefused,
            _ => Self::TransportFault,
        }
    }
}

impl AmlogicTemperatureUnavailable {
    pub fn endpoint(&self) -> AmlogicTemperatureEndpoint {
        self.endpoint
    }

    pub fn reason(&self) -> AmlogicTemperatureUnavailableReason {
        self.reason
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

#[derive(Debug, Clone)]
pub struct AmlogicTemperatureSnapshot {
    required_slots: [bool; 3],
    readings: Vec<AmlogicTemperatureReading>,
    unavailable: Vec<AmlogicTemperatureUnavailable>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmlogicTemperatureCoverage {
    required_slots: [bool; 3],
    inlet_available: [bool; 3],
    outlet_available: [bool; 3],
}

impl AmlogicTemperatureCoverage {
    pub fn required_slots(self) -> [bool; 3] {
        self.required_slots
    }

    pub fn inlet_available(self, slot: u8) -> bool {
        self.inlet_available
            .get(slot as usize)
            .copied()
            .unwrap_or(false)
    }

    pub fn outlet_available(self, slot: u8) -> bool {
        self.outlet_available
            .get(slot as usize)
            .copied()
            .unwrap_or(false)
    }

    pub fn is_complete(self) -> bool {
        (0..3).all(|slot| {
            !self.required_slots[slot]
                || (self.inlet_available[slot] && self.outlet_available[slot])
        })
    }

    pub fn missing_slots(self) -> Vec<u8> {
        (0..3u8)
            .filter(|slot| {
                self.required_slots[*slot as usize]
                    && !(self.inlet_available(*slot) && self.outlet_available(*slot))
            })
            .collect()
    }
}

impl AmlogicTemperatureSnapshot {
    pub fn readings(&self) -> &[AmlogicTemperatureReading] {
        &self.readings
    }

    pub fn unavailable(&self) -> &[AmlogicTemperatureUnavailable] {
        &self.unavailable
    }

    /// The PSU gate is chassis-wide, so every slot asserted by checked
    /// plug-detect topology requires both its inlet and outlet sensor.
    pub fn required_coverage(&self) -> AmlogicTemperatureCoverage {
        let mut inlet_available = [false; 3];
        let mut outlet_available = [false; 3];
        for reading in &self.readings {
            let slot = reading.endpoint.slot as usize;
            if slot >= self.required_slots.len() || !self.required_slots[slot] {
                continue;
            }
            match reading.endpoint.position {
                AmlogicTemperaturePosition::Inlet => inlet_available[slot] = true,
                AmlogicTemperaturePosition::Outlet => outlet_available[slot] = true,
            }
        }
        AmlogicTemperatureCoverage {
            required_slots: self.required_slots,
            inlet_available,
            outlet_available,
        }
    }

    pub fn hottest_celsius(&self) -> Option<f32> {
        self.readings
            .iter()
            .map(|reading| reading.celsius())
            .reduce(f32::max)
    }
}

// Board temperatures are available only through
// `AmlogicThermalPort::read_board_temperatures`.
fn normalize_model_token(model: &str) -> String {
    model
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+')
        .collect()
}

fn config_for_dcentos_platform(marker: &str) -> Result<Option<PlatformConfig>> {
    let normalized = marker.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "am3-aml-s19k" | "am3-aml-s19kpro" => Ok(Some(PlatformConfig::s19k_amlogic())),
        "am3-aml-s19xp" => Ok(Some(PlatformConfig::s19xp_amlogic())),
        "am3-aml-s19jxp" => Ok(Some(PlatformConfig::s19jxp_amlogic())),
        // A bare, SKU-less `am3-aml` marker is a GENERIC A113D control-board
        // token, not an SKU. It must never inherit an SKU transport/energization
        // profile: `am3-s21` is BM1368 while `am3-s21pro`/`am3-s21xp`
        // are BM1370 — different silicon on the same control board (verified in
        // `dcentrald-common` BoardDesc). Fail closed and let detection fall
        // through to the SKU-specific signals (`/etc/bosminer.toml` model, DTB),
        // which themselves refuse a generic "Amlogic" string. This matches the
        // descriptor's `GenericConstruction::Refused` and the sibling
        // `nopic_profile_for_dcentos_marker` / handoff-identity layers, which
        // already treat bare `am3-aml` as unqualified.
        "am3-aml" => Ok(None),
        "am3-aml-s21" => Ok(Some(PlatformConfig::s21_amlogic())),
        "am3-aml-s21pro" => Ok(Some(PlatformConfig::s21pro_amlogic())),
        "am3-aml-s21xp" => Ok(Some(PlatformConfig::s21xp_amlogic())),
        "am3-aml-s19jproa" => Ok(Some(PlatformConfig::s19jproa_amlogic())),
        "am3-aml-s19jproplus" => Ok(Some(PlatformConfig::s19jproplus_amlogic())),
        "am3-aml-t21" => Err(HalError::Platform(
            "Amlogic T21 controller/PIC/PSU profile is unresolved; refusing S21 NoPic fallback"
                .to_string(),
        )),
        // These targets use a per-hashboard controller and cannot inherit a
        // NoPic profile merely because the control board is also A113D.
        "am3-aml-s19jpro" => Ok(Some(PlatformConfig::s19jpro_classic_amlogic())),
        _ => Ok(None),
    }
}

fn nopic_profile_for_model_value(model: &str) -> Option<AmlogicNoPicProfile> {
    match normalize_model_token(model).as_str() {
        "antminers19kpro" | "antminers19kpronopic" | "s19kpro" | "s19kpronopic" => {
            Some(AmlogicNoPicProfile::S19k)
        }
        "antminers21" | "s21" => Some(AmlogicNoPicProfile::S21),
        "antminers21pro" | "s21pro" => Some(AmlogicNoPicProfile::S21Pro),
        "antminers21xp" | "s21xp" => Some(AmlogicNoPicProfile::S21Xp),
        "antminers19xp" | "s19xp" => Some(AmlogicNoPicProfile::S19Xp),
        "antminers19jxp" | "s19jxp" => Some(AmlogicNoPicProfile::S19jXp),
        "antminers19jproa" | "s19jproa" => Some(AmlogicNoPicProfile::S19jProA),
        "antminers19jpro+" | "antminers19jproplus" | "s19jpro+" | "s19jproplus" => {
            Some(AmlogicNoPicProfile::S19jProPlus)
        }
        _ => None,
    }
}

fn bosminer_model_value(source: &str) -> Result<Option<String>> {
    let document: toml::Value = toml::from_str(source).map_err(|error| {
        HalError::Platform(format!(
            "failed to parse /etc/bosminer.toml for Amlogic admission: {error}"
        ))
    })?;
    let model = document
        .get("format")
        .and_then(|format| format.get("model"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned);
    Ok(model)
}

fn nopic_profile_for_bosminer_toml(source: &str) -> Result<Option<AmlogicNoPicProfile>> {
    Ok(bosminer_model_value(source)?
        .as_deref()
        .and_then(nopic_profile_for_model_value))
}

fn config_for_bosminer_model(source: &str) -> Result<Option<PlatformConfig>> {
    let model = bosminer_model_value(source)?;
    let normalized_model = model.as_deref().map(normalize_model_token);
    if matches!(normalized_model.as_deref(), Some("antminert21" | "t21")) {
        return Err(HalError::Platform(
            "Amlogic T21 controller/PIC/PSU profile is unresolved; refusing lower-priority S21 fallback"
                .to_string(),
        ));
    }

    Ok(
        match model.as_deref().and_then(nopic_profile_for_model_value) {
            Some(AmlogicNoPicProfile::S19k) => Some(PlatformConfig::s19k_amlogic()),
            Some(AmlogicNoPicProfile::S21) => Some(PlatformConfig::s21_amlogic()),
            Some(AmlogicNoPicProfile::S21Pro) => Some(PlatformConfig::s21pro_amlogic()),
            Some(AmlogicNoPicProfile::S21Xp) => Some(PlatformConfig::s21xp_amlogic()),
            Some(AmlogicNoPicProfile::S19Xp) => Some(PlatformConfig::s19xp_amlogic()),
            Some(AmlogicNoPicProfile::S19jXp) => Some(PlatformConfig::s19jxp_amlogic()),
            Some(AmlogicNoPicProfile::S19jProA) => Some(PlatformConfig::s19jproa_amlogic()),
            Some(AmlogicNoPicProfile::S19jProPlus) => Some(PlatformConfig::s19jproplus_amlogic()),
            None => None,
        },
    )
}

fn nopic_profile_for_dcentos_marker(marker: &str) -> Option<AmlogicNoPicProfile> {
    match marker.trim().to_ascii_lowercase().as_str() {
        "am3-aml-s19k" | "am3-aml-s19kpro" => Some(AmlogicNoPicProfile::S19k),
        "am3-aml-s21" => Some(AmlogicNoPicProfile::S21),
        "am3-aml-s21pro" => Some(AmlogicNoPicProfile::S21Pro),
        "am3-aml-s21xp" => Some(AmlogicNoPicProfile::S21Xp),
        "am3-aml-s19xp" => Some(AmlogicNoPicProfile::S19Xp),
        "am3-aml-s19jxp" => Some(AmlogicNoPicProfile::S19jXp),
        "am3-aml-s19jproa" => Some(AmlogicNoPicProfile::S19jProA),
        "am3-aml-s19jproplus" => Some(AmlogicNoPicProfile::S19jProPlus),
        _ => None,
    }
}

/// Detect only identity evidence strong enough to authorize Amlogic NoPic
/// mutation. Unlike generic platform reporting, this never guesses from the
/// cross-SKU `am3-aml` marker or substring-scans an arbitrary config file.
fn detect_amlogic_nopic_profile() -> Result<AmlogicNoPicProfile> {
    if let Ok(marker) = fs::read_to_string("/etc/dcentos-platform") {
        return nopic_profile_for_dcentos_marker(&marker).ok_or_else(|| {
            HalError::Platform(format!(
                "/etc/dcentos-platform value {:?} is not SKU-qualified for Amlogic NoPic mutation",
                marker.trim()
            ))
        });
    }
    if let Ok(source) = fs::read_to_string("/etc/bosminer.toml") {
        return nopic_profile_for_bosminer_toml(&source)?.ok_or_else(|| {
            HalError::Platform(
                "/etc/bosminer.toml [format].model is missing or not an admitted Amlogic NoPic SKU"
                    .to_string(),
            )
        });
    }
    let model = fs::read_to_string("/proc/device-tree/model")
        .unwrap_or_default()
        .trim_end_matches('\0')
        .to_string();
    nopic_profile_for_model_value(&model).ok_or_else(|| {
        HalError::Platform(format!(
            "device-tree model {model:?} is not SKU-qualified for Amlogic NoPic mutation"
        ))
    })
}

/// Detect which Amlogic model we're running on.
///
/// Signal precedence (highest priority first):
/// 1. `/etc/dcentos-platform` — set explicitly by our buildroot board overlay
///    (Phase H.12). Authoritative when DCENT_OS is the running rootfs.
/// 2. `/etc/bos_platform` + `/etc/bosminer.toml` model — set by BraiinsOS+;
///    used when DCENT_OS daemon runs side-by-side with bosminer (passthrough
///    or runtime-only mode), or for Phase K dry-run install detection.
/// 3. `/proc/device-tree/model` from DTB — last resort. On `a lab unit` this is
///    just literal "Amlogic" (no specific model), so DTB alone cannot
///    disambiguate S19K Pro vs S21 vs S19j Pro Amlogic. Live-verified.
fn detect_amlogic_model() -> Result<PlatformConfig> {
    // 1. /etc/dcentos-platform takes highest precedence.
    if let Ok(plat) = fs::read_to_string("/etc/dcentos-platform") {
        let plat_norm = plat.trim().to_ascii_lowercase();
        tracing::debug!(platform = %plat_norm, "Read /etc/dcentos-platform");
        match config_for_dcentos_platform(&plat_norm)? {
            Some(config) => return Ok(config),
            None => tracing::debug!(
                platform = %plat_norm,
                "/etc/dcentos-platform did not match a known token; falling back"
            ),
        }
    }

    // 2. BraiinsOS+ secondary signal: /etc/bosminer.toml `model` field.
    //    This wins over DTB when bosminer is the running rootfs because
    //    it carries the exact factory model name (e.g. "Antminer S19K Pro NoPic").
    if let Ok(toml) = fs::read_to_string("/etc/bosminer.toml") {
        if let Some(config) = config_for_bosminer_model(&toml)? {
            tracing::info!(profile = %config.name, "Detected Amlogic profile from /etc/bosminer.toml model field");
            return Ok(config);
        }
    }

    // 3. Fallback: device-tree model. Often too generic on Amlogic AXG
    //    (.78 returns just "Amlogic"), so this is the last-resort path.
    let model = fs::read_to_string("/proc/device-tree/model")
        .unwrap_or_default()
        .trim_end_matches('\0')
        .to_string();
    let normalized = normalize_model_token(&model);

    tracing::debug!(model = %model, normalized = %normalized, "Device tree model");

    if normalized.is_empty() {
        Err(HalError::Platform(
            "Missing Amlogic model string; refusing to guess an unsafe platform profile"
                .to_string(),
        ))
    } else if matches!(normalized.as_str(), "s19xp" | "antminers19xp") {
        Ok(PlatformConfig::s19xp_amlogic())
    } else if matches!(normalized.as_str(), "s19jxp" | "antminers19jxp") {
        Ok(PlatformConfig::s19jxp_amlogic())
    } else if normalized.contains("s19jpro") {
        Err(HalError::Platform(
            format!(
                "Amlogic S19j Pro profile is not implemented yet; refusing to guess a serial platform profile for '{}'",
                model
            ),
        ))
    } else if normalized.contains("s19j") {
        Err(HalError::Platform(
            format!(
                "Amlogic S19j profile is not implemented yet; refusing to use the S19k profile for '{}'",
                model
            ),
        ))
    } else if normalized.contains("s19k") {
        Ok(PlatformConfig::s19k_amlogic())
    } else if normalized.contains("t21") {
        Err(HalError::Platform(format!(
            "Amlogic T21 controller/PIC/PSU profile is unresolved; refusing S21 NoPic fallback for '{}'",
            model
        )))
    } else if normalized.contains("s21xp") {
        Ok(PlatformConfig::s21xp_amlogic())
    } else if normalized.contains("s21plus") || normalized.contains("s21+") {
        Err(HalError::Platform(
            "S21+ has a separate55-chip profile; no Pro65 fallback".into(),
        ))
    } else if normalized.contains("s21pro") {
        Ok(PlatformConfig::s21pro_amlogic())
    } else if normalized.contains("s21") {
        Ok(PlatformConfig::s21_amlogic())
    } else if normalized.contains("s19") {
        Err(HalError::Platform(
            format!(
                "Unsupported/ambiguous Amlogic S19 model '{}'; refusing to guess an unsafe platform profile",
                model
            ),
        ))
    } else {
        Err(HalError::Platform(format!(
            "Unknown Amlogic model '{}'; refusing to guess an unsafe platform profile",
            model
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot_safe_handoff_fixture() -> String {
        [
            "schema=dcentos.amlogic-safe-state/v2",
            "state=runtime-handoff",
            "boot_id=11111111-2222-3333-4444-555555555555",
            "platform=am3-aml-s21",
            "board_target=am3-s21",
            "resource=amlogic-gpio437-power-gate",
            "gpio_direction=out",
            "psu_polarity_class=qualified-software",
            "gpio_active_low=0",
            "commanded_value=1",
            "readback_value=1",
            "fan0_duty_ns=30000",
            "fan0_period_ns=100000",
            "fan0_enabled=1",
            "fan1_duty_ns=30000",
            "fan1_period_ns=100000",
            "fan1_enabled=1",
            "hashboard_reset_gpio454_direction=out",
            "hashboard_reset_gpio454_active_low=0",
            "hashboard_reset_gpio454_value=0",
            "hashboard_reset_gpio455_direction=out",
            "hashboard_reset_gpio455_active_low=0",
            "hashboard_reset_gpio455_value=0",
            "hashboard_reset_gpio456_direction=out",
            "hashboard_reset_gpio456_active_low=0",
            "hashboard_reset_gpio456_value=0",
            "hashboard_reset_low_bitmap=0x7",
            "evidence_grade=software-readback",
            "physical_rail_measured=false",
        ]
        .join("\n")
    }

    #[test]
    fn boot_safe_handoff_s19k_requires_commanded_value_1() {
        let s19k = boot_safe_handoff_fixture()
            .replace("platform=am3-aml-s21", "platform=am3-aml-s19k")
            .replace("board_target=am3-s21", "board_target=am3-s19k")
            .replace("commanded_value=0", "commanded_value=1")
            .replace("readback_value=0", "readback_value=1");
        let receipt = parse_amlogic_boot_safe_handoff(&s19k).unwrap();
        assert_eq!(receipt.board_target, "am3-s19k");
        let lying = s19k
            .replace("commanded_value=1", "commanded_value=0")
            .replace("readback_value=1", "readback_value=0");
        assert!(
            parse_amlogic_boot_safe_handoff(&lying).is_err(),
            "am3-s19k receipt must not claim SafeOff=0 (that engages the rail)"
        );
        let family = s19k.replace("board_target=am3-s19k", "board_target=am3-aml-s19kpro");
        let family_receipt = parse_amlogic_boot_safe_handoff(&family).unwrap();
        assert_eq!(family_receipt.board_target, "am3-aml-s19kpro");
        let family_lying = family
            .replace("commanded_value=1", "commanded_value=0")
            .replace("readback_value=1", "readback_value=0");
        assert!(
            parse_amlogic_boot_safe_handoff(&family_lying).is_err(),
            "am3-aml-s19kpro receipt must not claim SafeOff=0 (that engages the rail)"
        );
    }

    #[test]
    fn boot_safe_handoff_parser_is_exact_and_honest_about_evidence() {
        let receipt = parse_amlogic_boot_safe_handoff(&boot_safe_handoff_fixture()).unwrap();
        assert_eq!(receipt.platform, "am3-aml-s21");
        assert_eq!(receipt.board_target, "am3-s21");
        assert_eq!(receipt.fan0_duty_ns, AML_BOOT_FAN_DUTY_NS);

        for mutation in [
            ("state=runtime-handoff", "state=boot-safe"),
            ("readback_value=1", "readback_value=0"),
            ("gpio_active_low=0", "gpio_active_low=1"),
            (
                "evidence_grade=software-readback",
                "evidence_grade=measured-rail-off",
            ),
            (
                "physical_rail_measured=false",
                "physical_rail_measured=true",
            ),
            ("fan1_duty_ns=30000", "fan1_duty_ns=100000"),
            ("fan0_period_ns=100000", "fan0_period_ns=30000"),
            ("fan1_enabled=1", "fan1_enabled=0"),
            (
                "hashboard_reset_gpio455_value=0",
                "hashboard_reset_gpio455_value=1",
            ),
            (
                "hashboard_reset_gpio455_active_low=0",
                "hashboard_reset_gpio455_active_low=1",
            ),
            (
                "hashboard_reset_low_bitmap=0x7",
                "hashboard_reset_low_bitmap=0x3",
            ),
        ] {
            let invalid = boot_safe_handoff_fixture().replace(mutation.0, mutation.1);
            assert!(
                parse_amlogic_boot_safe_handoff(&invalid).is_err(),
                "mutation {:?} must be refused",
                mutation
            );
        }

        let duplicate = format!("{}\nstate=runtime-handoff", boot_safe_handoff_fixture());
        assert!(parse_amlogic_boot_safe_handoff(&duplicate).is_err());
        let unknown = format!("{}\nunexpected=true", boot_safe_handoff_fixture());
        assert!(parse_amlogic_boot_safe_handoff(&unknown).is_err());
        let legacy = boot_safe_handoff_fixture()
            .replace(
                "schema=dcentos.amlogic-safe-state/v2",
                "schema=dcentos.amlogic-safe-state/v1",
            )
            .lines()
            .filter(|line| !line.contains("hashboard_reset_gpio455_active_low"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            parse_amlogic_boot_safe_handoff(&legacy).is_err(),
            "schema v1 must not silently preserve v2 reset-polarity authority"
        );
    }

    #[test]
    fn boot_handoff_undriven_cannot_claim_off_or_unknown_identity() {
        let source = boot_safe_handoff_fixture()
            .replace("am3-aml-s21", "am3-aml-s19jpro")
            .replace("am3-s21", "am3-s19jpro-aml")
            .replace(
                "psu_polarity_class=qualified-software",
                "psu_polarity_class=undriven",
            )
            .replace("gpio_direction=out", "gpio_direction=in")
            .replace("commanded_value=1", "commanded_value=undriven");
        // No real row currently lacks two independent traces. Retain pure
        // undriven-state coverage without weakening real table resolution.
        let validate_undriven = |source: &str| {
            let fields = source
                .lines()
                .map(|line| line.split_once('=').unwrap())
                .collect();
            validate_boot_psu_fields(&fields, BootGpio437Policy::Undriven)
        };
        assert!(validate_undriven(&source).is_ok());
        for (before, after) in [
            ("gpio_direction=in", "gpio_direction=out"),
            ("commanded_value=undriven", "commanded_value=1"),
            (
                "psu_polarity_class=undriven",
                "psu_polarity_class=qualified-software",
            ),
            ("readback_value=1", "readback_value=2"),
        ] {
            assert!(validate_undriven(&source.replace(before, after)).is_err());
        }
        // Classic now requires qualified OFF; a stale undriven receipt cannot
        // become an OFF claim simply because the updated table knows its pin.
        assert!(parse_amlogic_boot_safe_handoff(&source).is_err());
        assert!(
            parse_amlogic_boot_safe_handoff(&source.replace("am3-s19jpro-aml", "am3-unknown"))
                .is_err()
        );
        let qualified = boot_safe_handoff_fixture()
            .replace("am3-aml-s21", "am3-aml-s19jpro")
            .replace("am3-s21", "am3-s19jpro-aml");
        assert_eq!(
            parse_amlogic_boot_safe_handoff(&qualified)
                .unwrap()
                .psu_policy,
            amlogic_gpio437::resolve_boot_policy("am3-s19jpro-aml").unwrap()
        );
        assert!(parse_amlogic_boot_safe_handoff(
            &boot_safe_handoff_fixture().replace("psu_polarity_class=qualified-software\n", "")
        )
        .is_err());
    }

    #[test]
    fn boot_safe_handoff_identity_is_exact_sku_not_prefix_based() {
        assert!(amlogic_handoff_identity_matches_profile(
            AmlogicNoPicProfile::S19k,
            "am3-aml-s19k",
            "am3-s19k"
        ));
        for (platform, target) in [("am3-aml-s21", "am3-s21"), ("am3-aml-s21pro", "am3-s21pro")] {
            assert!(amlogic_handoff_identity_matches_profile(
                if target == "am3-s21" {
                    AmlogicNoPicProfile::S21
                } else {
                    AmlogicNoPicProfile::S21Pro
                },
                platform,
                target
            ));
        }
        for (platform, target) in [
            ("am3-aml", "am3-s21"),
            ("am3-aml-s21", "am3-s21xp"),
            ("am3-aml-s21xp", "am3-s21xp"),
            ("am3-aml-s19jpro", "am3-s19jpro-aml"),
            ("am3-aml-s21-future", "am3-s21-future"),
            ("am3-aml-t21", "am3-t21"),
        ] {
            assert!(!amlogic_handoff_identity_matches_profile(
                AmlogicNoPicProfile::S21,
                platform,
                target
            ));
        }
    }

    #[test]
    fn checked_psu_gpio_parser_never_converts_unknown_data_to_off() {
        let recipe = amlogic_gpio437::resolve_drive_recipe("am3-s21").unwrap();
        assert!(parse_psu_gpio_engaged("0\n", recipe).unwrap());
        assert!(!parse_psu_gpio_engaged("1\n", recipe).unwrap());
        for invalid in ["", "2", "off", "read error"] {
            assert!(
                parse_psu_gpio_engaged(invalid, recipe).is_err(),
                "value={invalid:?}"
            );
        }
    }

    #[test]
    fn gpio437_population_recipe_is_required_and_cannot_be_rebound() {
        let authority =
            AmlogicPsuCommitAuthority::new(AmlogicNoPicProfile::S21, Some(Arc::new(())));
        assert!(authority.recipe().is_err());
        for names in [
            [None, None, None],
            [Some("BHB56801"), None, None],
            [Some("BHB68603"), Some("BHB68606"), None],
        ] {
            assert!(authority
                .bind_population([true, false, false], names)
                .is_err());
            assert!(authority.recipe().is_err());
        }
        authority
            .bind_population([true, false, false], [Some("BHB68603"), None, None])
            .unwrap();
        let recipe = authority.recipe().unwrap();
        assert_eq!(
            (recipe.board_target(), recipe.on_raw(), recipe.off_raw()),
            ("am3-s21", 0, 1)
        );
        assert!(authority
            .bind_population([true, false, false], [Some("BHB68606"), None, None])
            .is_err());
        authority.latch_terminal();
        assert_eq!(authority.recipe().unwrap(), recipe);
        assert!(authority.begin_enable().is_err());
    }

    #[test]
    fn psu_gpio_commit_fence_orders_terminal_cut_after_inflight_enable() {
        let authority = Arc::new(AmlogicPsuCommitAuthority::new(
            AmlogicNoPicProfile::S21,
            None,
        ));
        let simulated_gpio_high = Arc::new(AtomicBool::new(false));
        let (enable_locked_tx, enable_locked_rx) = std::sync::mpsc::channel();
        let (release_enable_tx, release_enable_rx) = std::sync::mpsc::channel();

        let enable_authority = Arc::clone(&authority);
        let enable_gpio = Arc::clone(&simulated_gpio_high);
        let enable = std::thread::spawn(move || {
            let _commit = enable_authority.begin_enable().unwrap();
            enable_gpio.store(true, Ordering::SeqCst);
            enable_locked_tx.send(()).unwrap();
            release_enable_rx.recv().unwrap();
            if enable_authority.is_terminal() {
                enable_gpio.store(false, Ordering::SeqCst);
            }
        });
        enable_locked_rx.recv().unwrap();

        let (terminal_latched_tx, terminal_latched_rx) = std::sync::mpsc::channel();
        let (terminal_receipt_tx, terminal_receipt_rx) = std::sync::mpsc::channel();
        let terminal_authority = Arc::clone(&authority);
        let terminal_gpio = Arc::clone(&simulated_gpio_high);
        let terminal = std::thread::spawn(move || {
            terminal_authority.latch_terminal();
            terminal_latched_tx.send(()).unwrap();
            let _commit = terminal_authority.begin_terminal_cut();
            terminal_gpio.store(false, Ordering::SeqCst);
            terminal_receipt_tx.send(()).unwrap();
        });
        terminal_latched_rx.recv().unwrap();
        assert!(simulated_gpio_high.load(Ordering::SeqCst));
        assert!(matches!(
            terminal_receipt_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        release_enable_tx.send(()).unwrap();
        enable.join().unwrap();
        terminal_receipt_rx.recv().unwrap();
        terminal.join().unwrap();
        assert!(!simulated_gpio_high.load(Ordering::SeqCst));
        assert!(authority.begin_enable().is_err());
    }

    #[test]
    fn shipped_amlogic_platform_tokens_are_explicitly_classified_or_refused() {
        for marker in [
            "am3-aml-s19k",
            "am3-aml-s19kpro",
            "am3-aml-s21",
            "am3-aml-s21pro",
        ] {
            assert!(
                config_for_dcentos_platform(marker).unwrap().is_some(),
                "shipped marker {marker} must not fall through to generic DT detection"
            );
        }
        let classic = config_for_dcentos_platform("am3-aml-s19jpro")
            .unwrap()
            .unwrap();
        assert!(classic.has_pic);
        assert_eq!(
            classic.voltage_controller,
            crate::platform::VoltageControllerKind::ClassicAmlFw89
        );
        assert!(nopic_profile_for_dcentos_marker("am3-aml-s19jpro").is_none());
        let t21_error = config_for_dcentos_platform("am3-aml-t21")
            .expect_err("T21 must not inherit the S21 NoPic profile");
        assert!(t21_error.to_string().contains("profile is unresolved"));
        assert_eq!(
            config_for_dcentos_platform("am3-aml-s21xp")
                .unwrap()
                .unwrap()
                .name,
            PlatformConfig::s21xp_amlogic().name
        );
        for marker in ["am3-aml-s19xp", "am3-aml-s19jxp"] {
            let config = config_for_dcentos_platform(marker).unwrap().unwrap();
            assert_ne!(config.name, PlatformConfig::s19k_amlogic().name);
            assert!(nopic_profile_for_dcentos_marker(marker)
                .unwrap()
                .modern_s21_geometry()
                .is_some());
        }
        assert!(config_for_dcentos_platform("future-amlogic")
            .unwrap()
            .is_none());
        // A bare, SKU-less `am3-aml` marker must fail closed: a generic A113D
        // control-board token never inherits an SKU profile (am3-s21 is
        // BM1368, am3-s21pro/am3-s21xp are BM1370, and T21 controller
        // authority is unresolved). Queue rank 19 / H1 GAP-3.
        assert!(
            config_for_dcentos_platform("am3-aml").unwrap().is_none(),
            "generic am3-aml marker must not inherit the S21 SKU profile"
        );
    }

    #[test]
    fn bosminer_model_identity_covers_admitted_s19k_and_s21_families() {
        for model in ["Antminer S19K Pro NoPic"] {
            let config = config_for_bosminer_model(&format!("[format]\nmodel = {model:?}"))
                .unwrap()
                .expect("S19K/S19 XP bosminer identity");
            assert_eq!(config.name, PlatformConfig::s19k_amlogic().name);
        }
        for model in ["Antminer S21", "Antminer S21 Pro"] {
            let config = config_for_bosminer_model(&format!("[format]\nmodel = {model:?}"))
                .unwrap()
                .expect("S21 bosminer identity");
            assert_eq!(
                config.name,
                if model == "Antminer S21" {
                    PlatformConfig::s21_amlogic().name
                } else {
                    PlatformConfig::s21pro_amlogic().name
                }
            );
        }
        let t21_error = config_for_bosminer_model("[format]\nmodel = 'Antminer T21'")
            .expect_err("exact T21 evidence must stop lower-priority profile fallback");
        assert!(t21_error.to_string().contains("profile is unresolved"));
        assert_eq!(
            config_for_bosminer_model("[format]\nmodel = 'Antminer S21 XP'")
                .unwrap()
                .unwrap()
                .name,
            PlatformConfig::s21xp_amlogic().name
        );
        assert_eq!(
            nopic_profile_for_model_value("s21xp"),
            Some(AmlogicNoPicProfile::S21Xp)
        );
        assert_eq!(nopic_profile_for_model_value("s21+"), None);
        assert_eq!(nopic_profile_for_model_value("t21"), None);
        for model in ["Antminer S19 XP", "Antminer S19j XP"] {
            let config = config_for_bosminer_model(&format!("[format]\nmodel = {model:?}"))
                .unwrap()
                .unwrap();
            assert_ne!(config.name, PlatformConfig::s19k_amlogic().name);
        }
        assert_eq!(
            nopic_profile_for_model_value("s19xp"),
            Some(AmlogicNoPicProfile::S19Xp)
        );
        assert_eq!(
            nopic_profile_for_model_value("s19jxp"),
            Some(AmlogicNoPicProfile::S19jXp)
        );
        assert!(config_for_bosminer_model("[format]\nnotes = 'S21 spare'")
            .unwrap()
            .is_none());
        assert!(
            config_for_bosminer_model("[format]\nmodel = 'future miner'")
                .unwrap()
                .is_none()
        );
        assert!(config_for_bosminer_model("[format\nmodel = 'Antminer S21'").is_err());
        assert_eq!(nopic_profile_for_dcentos_marker("am3-aml"), None);
    }

    #[test]
    fn nopic_admission_binds_s21_route_and_refuses_unbound_s19k_route() {
        assert_eq!(
            amlogic_slot_from_serial_device(AmlogicNoPicProfile::S21, "/dev/ttyS1"),
            Some(2)
        );
        assert_eq!(
            amlogic_slot_from_serial_device(AmlogicNoPicProfile::S21, "/dev/ttyS2"),
            Some(1)
        );
        assert_eq!(
            amlogic_slot_from_serial_device(AmlogicNoPicProfile::S21, "/dev/ttyS4"),
            None
        );
        assert_eq!(
            amlogic_slot_from_serial_device(AmlogicNoPicProfile::S21, "/dev/ttyS3"),
            Some(0)
        );
        assert_eq!(
            amlogic_slot_from_serial_device(AmlogicNoPicProfile::S21, "/dev/ttyO1"),
            None
        );
        for path in ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"] {
            assert_eq!(
                amlogic_slot_from_serial_device(AmlogicNoPicProfile::S19k, path),
                None,
                "S19k {path} must remain a logical endpoint, not a physical slot"
            );
        }

        let s19k_error = AmlogicNoPicAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S19k,
            0,
            "/dev/ttyS1",
            "am3-s19k",
            AmlogicNoPicProfile::S19k,
            [false, true, true],
        )
        .unwrap_err();
        assert!(s19k_error.to_string().contains("topology is unbound"));

        let admission = AmlogicNoPicAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S21,
            1,
            "/dev/ttyS2",
            "am3-s21",
            AmlogicNoPicProfile::S21,
            [true, true, false],
        )
        .unwrap();
        assert_eq!(admission.profile(), AmlogicNoPicProfile::S21);
        assert_eq!(admission.board_target(), "am3-s21");
        assert_eq!(admission.active_slot(), 1);
        assert_eq!(admission.serial_device(), "/dev/ttyS2");
        assert_eq!(admission.populated_slots(), [true, true, false]);

        assert!(AmlogicNoPicAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S21,
            1,
            "/dev/ttyS2",
            "am3-s21",
            AmlogicNoPicProfile::S19k,
            [false, true, false],
        )
        .is_err());
        assert!(AmlogicNoPicAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S21,
            3,
            "/dev/ttyS2",
            "am3-s21",
            AmlogicNoPicProfile::S21,
            [false, true, false],
        )
        .is_err());
        assert!(AmlogicNoPicAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S21,
            1,
            "/dev/ttyS1",
            "am3-s21",
            AmlogicNoPicProfile::S21,
            [true, true, false],
        )
        .is_err());
        assert!(AmlogicNoPicAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S21,
            1,
            "/dev/ttyS2",
            "am3-s21",
            AmlogicNoPicProfile::S21,
            [true, false, false],
        )
        .is_err());
        assert!(AmlogicNoPicAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S21,
            1,
            "/dev/ttyS2",
            "am3-s19k",
            AmlogicNoPicProfile::S21,
            [true, true, false],
        )
        .is_err());
    }

    #[test]
    fn s19k_native_population_admission_binds_all_controller_routes() {
        assert_eq!(
            S19K_NATIVE_LOGICAL_CHAIN_ROUTES.map(|route| (
                route.uart,
                route.logical_chain,
                route.reset_gpio
            )),
            [
                ("/dev/ttyS3", 0, 454),
                ("/dev/ttyS2", 1, 455),
                ("/dev/ttyS1", 2, 456),
            ]
        );
        let held = S19kNativeAggregateAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S19k,
            "am3-s19k",
            [false, true, true],
            [false, true, true],
        )
        .unwrap();
        assert_eq!(held.board_target(), "am3-s19k");
        assert_eq!(held.populated_slots(), [false, true, true]);
        let population = held.into_population().unwrap();
        assert_eq!(population.populated_slots(), [false, true, true]);
        assert_eq!(
            population
                .logical_chain_routes()
                .iter()
                .map(|route| (route.uart, route.logical_chain, route.reset_gpio))
                .collect::<Vec<_>>(),
            vec![("/dev/ttyS2", 1, 455), ("/dev/ttyS1", 2, 456)]
        );

        // Every non-empty subset is selected from the immutable logical route.
        for mask in 1u8..8 {
            let topology = [mask & 1 != 0, mask & 2 != 0, mask & 4 != 0];
            let aggregate = S19kNativeAggregateAdmission::from_profile_evidence(
                AmlogicNoPicProfile::S19k,
                "am3-s19k",
                topology,
                [true, true, true],
            )
            .unwrap();
            let selected = aggregate.logical_chain_routes();
            assert_eq!(selected.len(), mask.count_ones() as usize);
            assert!(selected
                .iter()
                .all(|route| topology[route.logical_chain as usize]));
        }
        assert!(S19kNativeAggregateAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S19k,
            "am3-s19k",
            [false, false, false],
            [true, true, true],
        )
        .is_err());
        // An absent chain's UART need not exist; a populated chain's UART must.
        assert!(S19kNativeAggregateAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S19k,
            "am3-s19k",
            [false, true, true],
            [false, true, true],
        )
        .is_ok());
        for uart_available in [
            [true, false, true],
            [true, true, false],
            [false, false, false],
        ] {
            assert!(S19kNativeAggregateAdmission::from_profile_evidence(
                AmlogicNoPicProfile::S19k,
                "am3-s19k",
                [false, true, true],
                uart_available,
            )
            .is_err());
        }
        assert!(S19kNativeAggregateAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S21,
            "am3-s19k",
            [false, true, true],
            [true, true, true],
        )
        .is_err());
        assert!(S19kNativeAggregateAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S19k,
            "am3-s21",
            [false, true, true],
            [true, true, true],
        )
        .is_err());

        let source = include_str!("mod.rs");
        let start = source
            .find("impl S19kNativeAggregateAdmission")
            .expect("aggregate S19k admission implementation");
        let end = source[start..]
            .find("impl S19kNativePopulationAdmission")
            .map(|offset| start + offset)
            .expect("aggregate S19k admission implementation end");
        let body = &source[start..end];
        assert!(body.contains("service.psu_enable_operation_available = false"));
        assert!(!body.contains("service.psu_enable_operation_available = true"));
        assert!(!body.contains("take_psu_enable_operation"));
        assert!(!body.contains("set_amlogic_board_reset_checked"));
        assert!(body.contains("Result<Arc<S19kNativeFanObservation>>"));
        assert!(!body.contains("Result<Arc<dyn FanAccess>>"));

        let population_start = end;
        let population_end = source[population_start..]
            .find("fn amlogic_slot_from_serial_device")
            .map(|offset| population_start + offset)
            .expect("population S19k admission implementation end");
        let population_body = &source[population_start..population_end];
        assert!(population_body.contains("service.psu_enable_operation_available = true"));
        assert!(population_body.contains("Result<Arc<dyn FanAccess>>"));
        assert!(population_body.contains("assert_s19k_native_all_resets_checked"));
        assert!(population_body.contains("release_mapped_resets_checked"));
        assert!(population_body.contains("S19K_NATIVE_LOGICAL_CHAIN_ROUTES"));

        let observer_start = source
            .find("impl S19kNativeFanObservation")
            .expect("native S19k read-only fan observer implementation");
        let observer_end = source[observer_start..]
            .find("pub struct S19kNativeAggregateAdmission")
            .map(|offset| observer_start + offset)
            .expect("native S19k fan observer implementation end");
        let observer = &source[observer_start..observer_end];
        assert!(observer.contains("pub fn get_per_fan_rpm"));
        assert!(observer.contains("pub fn get_speed_pwm"));
        assert!(!observer.contains("pub fn set_speed"));
        assert!(!observer.contains("impl FanAccess"));
    }

    #[test]
    fn s19k_native_reset_release_refuses_foreign_power_generation_before_gpio_io() {
        let mapped = S19kNativeAggregateAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S19k,
            "am3-s19k",
            [false, true, true],
            [false, true, true],
        )
        .unwrap()
        .into_population()
        .unwrap();
        let asserted = S19kNativeAllResetsAsserted {
            reset_gpios: [454, 455, 456],
        };
        let foreign = ApwEnableReceipt {
            writes_completed_at: Instant::now(),
            status_word: None,
            native_generation: Some(Arc::new(())),
        };
        let error = mapped
            .release_mapped_resets_checked(asserted, foreign)
            .unwrap_err();
        assert!(error.to_string().contains("another cold-start generation"));

        let source = include_str!("mod.rs");
        assert!(source.contains("power: ApwEnableReceipt,"));
        assert!(!source.contains("#[derive(Debug, Clone, Copy)]\npub struct ApwEnableReceipt"));
        assert!(source.contains("Arc::ptr_eq(power_generation, &self.generation)"));
    }

    #[test]
    fn s19k_native_identity_reads_only_its_population_from_its_retained_owner() {
        use crate::i2c::{HashboardEepromSpan, I2cRequest};
        let mapped = S19kNativeAggregateAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S19k,
            "am3-s19k",
            [false, true, true],
            [false, true, true],
        )
        .unwrap()
        .into_population()
        .unwrap();
        let (i2c, requests) = I2cServiceHandle::for_unit_tests();
        let mut service = AmlogicPowerThermalService {
            i2c,
            required_slots: mapped.populated_slots(),
            lifecycle_owner: None,
            psu_commit: Arc::new(AmlogicPsuCommitAuthority::new(
                AmlogicNoPicProfile::S19k,
                Some(Arc::new(())),
            )),
            psu_enable_operation_available: false,
            s21_psu: None,
        };
        assert!(mapped
            .read_identity_pages(&service, Instant::now() + Duration::from_secs(1))
            .is_err());
        assert!(
            requests.try_recv().is_err(),
            "foreign generation reached I2C"
        );
        service.psu_commit = Arc::new(AmlogicPsuCommitAuthority::new(
            AmlogicNoPicProfile::S19k,
            Some(Arc::clone(&mapped.generation)),
        ));
        let worker = std::thread::spawn(move || {
            for expected in [0x51, 0x51, 0x52, 0x52] {
                match requests.recv_timeout(Duration::from_secs(1)).unwrap() {
                    I2cRequest::ReadHashboardEepromSpan {
                        addr,
                        span,
                        reply_tx,
                        ..
                    } => {
                        assert_eq!(addr, expected);
                        assert_eq!(span, HashboardEepromSpan::FullPage);
                        reply_tx.send(Ok(vec![addr; 256])).unwrap();
                    }
                    other => panic!("identity issued unexpected request {other:?}"),
                }
            }
            assert!(requests.try_recv().is_err());
        });
        let pages = mapped
            .read_identity_pages(&service, Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert!(pages[0].is_none());
        assert_eq!(pages[1], Some(vec![0x51; 256]));
        assert_eq!(pages[2], Some(vec![0x52; 256]));
        worker.join().unwrap();
        service.psu_commit.latch_terminal();
        assert!(mapped
            .read_identity_pages(&service, Instant::now() + Duration::from_secs(1))
            .is_err());
    }

    #[test]
    fn s19k_native_identity_refuses_a_page_changed_between_reads() {
        use crate::i2c::I2cRequest;
        let mapped = S19kNativeAggregateAdmission::from_profile_evidence(
            AmlogicNoPicProfile::S19k,
            "am3-s19k",
            [true, false, false],
            [true, false, false],
        )
        .unwrap()
        .into_population()
        .unwrap();
        let (i2c, requests) = I2cServiceHandle::for_unit_tests();
        let service = AmlogicPowerThermalService {
            i2c,
            required_slots: mapped.populated_slots(),
            lifecycle_owner: None,
            psu_commit: Arc::new(AmlogicPsuCommitAuthority::new(
                AmlogicNoPicProfile::S19k,
                Some(Arc::clone(&mapped.generation)),
            )),
            psu_enable_operation_available: false,
            s21_psu: None,
        };
        let worker = std::thread::spawn(move || {
            for byte in [1, 2] {
                match requests.recv_timeout(Duration::from_secs(1)).unwrap() {
                    I2cRequest::ReadHashboardEepromSpan { reply_tx, .. } => {
                        reply_tx.send(Ok(vec![byte; 256])).unwrap();
                    }
                    other => panic!("unexpected identity request {other:?}"),
                }
            }
        });
        let error = mapped
            .read_identity_pages(&service, Instant::now() + Duration::from_secs(1))
            .unwrap_err();
        assert!(error.to_string().contains("changed between"));
        worker.join().unwrap();
    }

    #[test]
    fn checked_amlogic_reset_requires_prepared_raw_line_and_returns_readback() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "dcentos-amlogic-reset-{}-{unique}",
            std::process::id()
        ));
        let gpio = root.join("gpio454");
        std::fs::create_dir_all(&gpio).unwrap();
        std::fs::write(gpio.join("direction"), "out\n").unwrap();
        std::fs::write(gpio.join("active_low"), "0\n").unwrap();
        std::fs::write(gpio.join("value"), "1\n").unwrap();

        let asserted = set_amlogic_board_reset_checked_at(&root, 0, 454, true).unwrap();
        assert_eq!(asserted.chain(), 0);
        assert_eq!(asserted.gpio(), 454);
        assert!(asserted.asserted());
        assert_eq!(asserted.commanded_value(), 0);
        assert_eq!(asserted.observed_value(), 0);
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");

        let released = set_amlogic_board_reset_checked_at(&root, 0, 454, false).unwrap();
        assert!(!released.asserted());
        assert_eq!(released.commanded_value(), 1);
        assert_eq!(released.observed_value(), 1);
        assert!(released.completed_at() >= asserted.completed_at());

        std::fs::write(gpio.join("active_low"), "1\n").unwrap();
        let polarity_error = set_amlogic_board_reset_checked_at(&root, 0, 454, true).unwrap_err();
        assert!(polarity_error
            .to_string()
            .contains("refusing to guess physical reset polarity"));
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "1");

        std::fs::write(gpio.join("active_low"), "0\n").unwrap();
        std::fs::write(gpio.join("direction"), "in\n").unwrap();
        let direction_error = set_amlogic_board_reset_checked_at(&root, 0, 454, true).unwrap_err();
        assert!(direction_error
            .to_string()
            .contains("not prepared as output"));
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "1");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn track1_pwm100_refuses_without_explicit_loud_authority_before_io() {
        let error = hold_track1_leftover_fans_pwm100(false).unwrap_err();
        assert!(error
            .to_string()
            .contains("explicit --allow-loud authority"));
        let source = include_str!("mod.rs");
        let start = source
            .find("pub fn hold_track1_leftover_fans_pwm100")
            .expect("Track-1 PWM100 helper");
        let body = &source[start..];
        assert!(
            body.find("if !explicit_loud_authority").unwrap() < body.find("fs::write").unwrap()
        );
    }

    #[test]
    fn gpio437_driver_requires_output_readback_and_preserves_raw_off_recipe() {
        let root = std::env::temp_dir().join(format!(
            "dcent-gpio437-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let gpio = root.join("gpio437");
        fs::create_dir_all(&gpio).unwrap();
        fs::write(gpio.join("direction"), "out").unwrap();
        fs::write(gpio.join("active_low"), "1").unwrap();
        fs::write(gpio.join("value"), "0").unwrap();
        let recipe = amlogic_gpio437::resolve_drive_recipe("am3-s19k").unwrap();
        let mut writes = Vec::new();
        drive_psu_checked_at(&root, 437, recipe, false, |path, value| {
            writes.push((
                path.file_name().unwrap().to_string_lossy().into_owned(),
                value.to_owned(),
            ));
            if path.ends_with("direction") && matches!(value, "high" | "low") {
                fs::write(path, "out")?;
                fs::write(
                    path.with_file_name("value"),
                    if value == "high" { "1" } else { "0" },
                )
            } else {
                fs::write(path, value)
            }
        })
        .unwrap();
        assert_eq!(
            writes,
            vec![
                ("direction".into(), "in".into()),
                ("active_low".into(), "0".into()),
                ("direction".into(), "high".into()),
                ("value".into(), "1".into())
            ]
        );
        assert!(!read_psu_enabled_on_with_recipe_at(&root, 437, recipe).unwrap());
        // The retained recipe drives both transitions. Each direction change
        // establishes OFF first, including the subsequent enable operation.
        for on in [true, false] {
            writes.clear();
            drive_psu_checked_at(&root, 437, recipe, on, |path, value| {
                writes.push((
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    value.to_owned(),
                ));
                if path.ends_with("direction") && matches!(value, "high" | "low") {
                    fs::write(path, "out")?;
                    fs::write(
                        path.with_file_name("value"),
                        if value == "high" { "1" } else { "0" },
                    )
                } else {
                    fs::write(path, value)
                }
            })
            .unwrap();
            assert_eq!(
                writes,
                vec![
                    ("direction".into(), "high".into()),
                    ("value".into(), if on { "0" } else { "1" }.into()),
                ]
            );
            assert_eq!(
                read_psu_enabled_on_with_recipe_at(&root, 437, recipe).unwrap(),
                on
            );
        }
        fs::write(gpio.join("direction"), "in").unwrap();
        for value in ["0", "1"] {
            fs::write(gpio.join("value"), value).unwrap();
            assert!(read_psu_enabled_on_with_recipe_at(&root, 437, recipe).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checked_fan_command_surfaces_partial_two_channel_write() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "dcentos-amlogic-fan-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let rear = root.join("rear_duty");
        std::fs::write(&rear, "0").unwrap();
        let front = root.join("missing-parent").join("front_duty");
        let fan = AmlogicFan {
            rear_duty_path: rear.to_string_lossy().into_owned(),
            front_duty_path: front.to_string_lossy().into_owned(),
            period_ns: AMLOGIC_PWM_PERIOD_NS,
            tach_sources: std::array::from_fn(|_| {
                Box::new(FixedEdgeMock(0)) as Box<dyn FanTachSource>
            }),
            tach_healthy: AtomicBool::new(true),
            sample_window: Duration::from_millis(1),
        };

        let result = fan.set_speed_checked(30);
        assert!(result.is_err(), "front-channel failure must reject receipt");
        assert_eq!(std::fs::read_to_string(&rear).unwrap(), "30000");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn apw_pmbus_compatibility_translation_is_stable() {
        // This pins DCENT's current Linux translation; it does not prove U-Boot
        // wire framing, U-Boot/Linux adapter identity, or S21 applicability.
        assert_eq!(AMLOGIC_MANAGEMENT_I2C_BUS, 1);
        assert_eq!(APW_PMBUS_ADDR, 0x1f);
        assert_eq!(APW_PMBUS_CLEAR_FAULTS, [0x03, 0x00, 0x00]);
        assert_eq!(APW_PMBUS_OPERATION_ENABLE, [0x01, 0xfc, 0xfc]);
    }

    #[test]
    fn amlogic_management_source_has_one_service_owned_bus1_path() {
        let source = include_str!("mod.rs");
        assert!(source.contains(
            "spawn_i2c_service_no_register_touch_with_denylist_and_reserved_preparation"
        ));
        assert!(source.contains("prepare_management_i2c_pinmux"));
        assert!(source.contains("read_lm75_temperature_register_at"));
        assert!(source.contains("AmlogicNoPicAdmission"));
        assert!(!source
            .lines()
            .any(|line| line.starts_with("pub fn open_fan_controller()")));
        assert!(!source
            .lines()
            .any(|line| line.starts_with("pub fn spawn() -> Result<Self>")));
        let raw_apw_open = ["I2cBus::", "open(APW_PMBUS"].concat();
        assert!(!source.contains(&raw_apw_open));
        let raw_temperature_helper = ["pub fn read_board_", "temps("].concat();
        let raw_apw_helper = ["pub fn enable_psu_", "pmbus("].concat();
        assert!(!source.contains(&raw_temperature_helper));
        assert!(!source.contains(&raw_apw_helper));
    }

    #[cfg(feature = "sim-hal")]
    struct ApwSequenceBackend {
        identity: usize,
        writes: std::sync::Mutex<Vec<(u8, u8, Vec<u8>)>>,
    }

    #[cfg(feature = "sim-hal")]
    impl ApwSequenceBackend {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
            Self {
                identity: usize::MAX
                    - 10_000
                    - NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                writes: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[cfg(feature = "sim-hal")]
    impl crate::i2c::I2cSimBackend for ApwSequenceBackend {
        fn write(&self, bus: u8, addr: u8, data: &[u8]) -> Result<usize> {
            self.writes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((bus, addr, data.to_vec()));
            Ok(data.len())
        }

        fn read(&self, bus: u8, addr: u8, _buf: &mut [u8]) -> Result<usize> {
            Err(HalError::I2c {
                bus,
                addr,
                detail: "APW test backend refuses standalone reads".into(),
            })
        }

        fn write_read(
            &self,
            bus: u8,
            addr: u8,
            _write_data: &[u8],
            _read_buf: &mut [u8],
        ) -> Result<()> {
            Err(HalError::I2cEndpointNotReady {
                bus,
                addr,
                detail: "simulated APW STATUS_WORD NACK".into(),
            })
        }

        fn service_identity(&self) -> Option<usize> {
            Some(self.identity)
        }
    }

    #[cfg(feature = "sim-hal")]
    #[test]
    fn apw_enable_writes_complete_even_when_optional_status_is_unavailable() {
        let backend = std::sync::Arc::new(ApwSequenceBackend::new());
        let owner = crate::i2c::spawn_owned_sim_i2c_service(
            AMLOGIC_MANAGEMENT_I2C_BUS,
            backend.clone(),
            Vec::new(),
        )
        .unwrap();
        let i2c = owner.request_handle();
        let fence = owner.terminal_fence();
        let psu_commit = Arc::new(AmlogicPsuCommitAuthority::new(
            AmlogicNoPicProfile::S21,
            None,
        ));
        let mut service = AmlogicPowerThermalService {
            i2c,
            required_slots: [false, true, false],
            lifecycle_owner: Some(AmlogicPowerThermalLifecycleOwner {
                owner,
                fence,
                psu_commit: Arc::clone(&psu_commit),
                s21_psu: None,
            }),
            psu_commit,
            psu_enable_operation_available: true,
            s21_psu: None,
        };
        let operation = service.take_psu_enable_operation().unwrap();

        operation.enable_apw().unwrap();
        assert!(operation.read_apw_status_word().is_err());
        assert_eq!(
            *backend
                .writes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec![
                (
                    AMLOGIC_MANAGEMENT_I2C_BUS,
                    APW_PMBUS_ADDR,
                    APW_PMBUS_CLEAR_FAULTS.to_vec(),
                ),
                (
                    AMLOGIC_MANAGEMENT_I2C_BUS,
                    APW_PMBUS_ADDR,
                    APW_PMBUS_OPERATION_ENABLE.to_vec(),
                ),
            ]
        );
    }

    #[test]
    fn fan_pwm_percent_to_duty_uses_0_to_100_scale() {
        assert_eq!(amlogic_pwm_percent_to_duty_ns(0, AMLOGIC_PWM_PERIOD_NS), 0);
        assert_eq!(
            amlogic_pwm_percent_to_duty_ns(30, AMLOGIC_PWM_PERIOD_NS),
            30_000
        );
        assert_eq!(
            amlogic_pwm_percent_to_duty_ns(100, AMLOGIC_PWM_PERIOD_NS),
            AMLOGIC_PWM_PERIOD_NS
        );
        assert_eq!(
            amlogic_pwm_percent_to_duty_ns(127, AMLOGIC_PWM_PERIOD_NS),
            AMLOGIC_PWM_PERIOD_NS,
            "legacy 0-127 inputs must clamp to 100%"
        );
    }

    #[test]
    fn fan_duty_to_pwm_getter_uses_0_to_100_scale() {
        assert_eq!(amlogic_duty_ns_to_pwm_percent(0, AMLOGIC_PWM_PERIOD_NS), 0);
        assert_eq!(
            amlogic_duty_ns_to_pwm_percent(30_000, AMLOGIC_PWM_PERIOD_NS),
            30
        );
        assert_eq!(
            amlogic_duty_ns_to_pwm_percent(100_000, AMLOGIC_PWM_PERIOD_NS),
            100
        );
        assert_eq!(
            amlogic_duty_ns_to_pwm_percent(127_000, AMLOGIC_PWM_PERIOD_NS),
            100,
            "out-of-range sysfs duty is clamped to 100%"
        );
    }

    #[test]
    fn temperature_topology_matches_live_78_physical_slots() {
        // Live-verified per .78 bosminer.log:
        //   hb1.72 (Inlet=0x48), hb1.76 (Outlet=0x4C)
        //   hb2.73 (Inlet=0x49), hb2.77 (Outlet=0x4D)
        //   hb3.74 (Inlet=0x4A), hb3.78 (Outlet=0x4E)
        assert_eq!(AMLOGIC_TEMPERATURE_ENDPOINTS.len(), 6);
        for slot in 0..=2 {
            let pair: Vec<_> = AMLOGIC_TEMPERATURE_ENDPOINTS
                .iter()
                .copied()
                .filter(|endpoint| endpoint.slot() == slot)
                .collect();
            assert_eq!(pair.len(), 2);
            assert_eq!(pair[0].address(), 0x48 + slot);
            assert_eq!(pair[0].position(), AmlogicTemperaturePosition::Inlet);
            assert_eq!(pair[1].address(), 0x4c + slot);
            assert_eq!(pair[1].position(), AmlogicTemperaturePosition::Outlet);
        }
    }

    #[test]
    fn required_slot_coverage_cannot_be_masked_by_other_slots_or_extreme_heat() {
        let reading =
            |endpoint: AmlogicTemperatureEndpoint, celsius: i16| AmlogicTemperatureReading {
                endpoint,
                register: Lm75TemperatureRegister::from_raw_be(celsius * 256),
            };
        let slot0_inlet = AMLOGIC_TEMPERATURE_ENDPOINTS[0];
        let slot0_outlet = AMLOGIC_TEMPERATURE_ENDPOINTS[1];
        let slot1_inlet = AMLOGIC_TEMPERATURE_ENDPOINTS[2];
        let slot1_outlet = AMLOGIC_TEMPERATURE_ENDPOINTS[3];

        let incomplete = AmlogicTemperatureSnapshot {
            required_slots: [true, true, false],
            readings: vec![reading(slot0_inlet, 40), reading(slot1_inlet, 45)],
            unavailable: Vec::new(),
        };
        let coverage = incomplete.required_coverage();
        assert!(coverage.inlet_available(0));
        assert!(coverage.inlet_available(1));
        assert!(!coverage.outlet_available(0));
        assert!(!coverage.outlet_available(1));
        assert_eq!(coverage.missing_slots(), vec![0, 1]);
        assert!(!coverage.is_complete());

        let complete = AmlogicTemperatureSnapshot {
            required_slots: [true, true, false],
            readings: vec![
                reading(slot0_inlet, 40),
                reading(slot0_outlet, 50),
                reading(slot1_inlet, 45),
                reading(slot1_outlet, 55),
            ],
            unavailable: Vec::new(),
        };
        assert!(complete.required_coverage().is_complete());

        let extreme = AmlogicTemperatureSnapshot {
            required_slots: [false, true, false],
            readings: vec![reading(slot1_inlet, 45), reading(slot1_outlet, 125)],
            unavailable: Vec::new(),
        };
        assert!(extreme.required_coverage().is_complete());
        assert_eq!(extreme.hottest_celsius(), Some(125.0));
    }

    // ---------------------------------------------------------------------
    // W3.1 — am3-aml hashboard EEPROM write-deny parity with am2
    // ---------------------------------------------------------------------

    #[test]
    fn amlogic_eeprom_denylist_covers_full_at24c_range() {
        // Contract: every AT24C-class hashboard EEPROM slot from 0x50..=0x57
        // is on the denylist. Same range as am2 (proven against the .74 hb2
        // corruption pattern) and now extended to am3-aml because BHB56902
        // hashboards on S19K Pro carry EEPROMs at the same standard 0x50
        // base. Live-verified via i2cdetect on .78 (2026-04-29).
        assert_eq!(AMLOGIC_EEPROM_DENYLIST.len(), 8);
        for addr in 0x50u8..=0x57u8 {
            assert!(
                AMLOGIC_EEPROM_DENYLIST.contains(&addr),
                "AMLOGIC_EEPROM_DENYLIST must cover 0x{:02X} (AT24C slot)",
                addr
            );
        }
    }

    // -----------------------------------------------------------------
    // W3.2 (2026-05-07) — GPIO falling-edge fan tach replaces synthesized RPM.
    // -----------------------------------------------------------------

    /// Mock tach source that always returns a fixed pulse count. Lets
    /// the test assert the edges→RPM math without real GPIO.
    struct FixedEdgeMock(u32);
    impl FanTachSource for FixedEdgeMock {
        fn sample_falling_edges(&self, _window: Duration) -> std::io::Result<u32> {
            Ok(self.0)
        }
    }

    struct FailingEdgeMock;
    impl FanTachSource for FailingEdgeMock {
        fn sample_falling_edges(&self, _window: Duration) -> std::io::Result<u32> {
            Err(std::io::Error::other("injected tach failure"))
        }
    }

    #[cfg(panic = "unwind")]
    struct PanickingEdgeMock;
    #[cfg(panic = "unwind")]
    impl FanTachSource for PanickingEdgeMock {
        fn sample_falling_edges(&self, _window: Duration) -> std::io::Result<u32> {
            panic!("injected tach sampler panic")
        }
    }

    struct ConcurrentEdgeMock {
        active: Arc<std::sync::atomic::AtomicUsize>,
        maximum: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl FanTachSource for ConcurrentEdgeMock {
        fn sample_falling_edges(&self, _window: Duration) -> std::io::Result<u32> {
            use std::sync::atomic::Ordering;

            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            let _ = self
                .maximum
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |maximum| {
                    Some(maximum.max(active))
                });
            std::thread::sleep(Duration::from_millis(20));
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(1)
        }
    }

    #[test]
    fn amlogic_bus0_helper_selector_stays_zero() {
        // This pins the bus that `spawn_amlogic_protected_i2c0_service` opens.
        // It is NOT a statement about where hashboard EEPROMs live.
        //
        // CORRECTION (2026-07-28): the comment previously here claimed am3-aml
        // hashboard EEPROMs answer on `/dev/i2c-0`. They do not. The live `a lab unit`
        // capture shows i2c-0 EMPTY, with the LM75s and the hashboard EEPROMs
        // both answering on i2c-1 — which is exactly why the write-denylist is
        // ALSO registered on bus 1 inside `AmlogicPowerThermalService::spawn`.
        //
        // Do not use the old comment's reasoning to strip that bus-1
        // registration. Its stated fear was that denying bus 1 would block PSU
        // enable writes; it does not. The APW answers at 0x1f, which is outside
        // the 0x50..=0x57 range, so PSU writes are unaffected. Removing the
        // bus-1 denylist would re-open the post-`a lab unit` EEPROM write hole on the
        // one bus that actually carries the EEPROMs.
        //
        // The VALUE must still stay 0: this constant selects the bus the bus-0
        // helper opens, and repointing it would make that helper a second owner
        // of a bus already held under reservation. See the constant's own doc.
        assert_eq!(AMLOGIC_HASHBOARD_EEPROM_BUS, 0);
    }

    #[test]
    fn eeprom_denylist_blocks_am3_aml_write() {
        use crate::i2c::I2cBus;
        // Open a devmem-stub bus (no real /dev/i2c-N) so the denylist can
        // be exercised without hardware. Apply the same denylist that the
        // platform wires up at startup.
        let mut bus = I2cBus::open_devmem();
        bus.set_write_denylist(&AMLOGIC_EEPROM_DENYLIST);

        // BHB42xxx-class slots (am2 legacy) and BHB56902-class slots
        // (am3-aml S19K Pro NEW) live in the same 0x50..=0x57 address
        // range — both must refuse writes via the public `write()` API.
        for addr in 0x50u8..=0x57u8 {
            bus.set_slave(addr)
                .expect("set_slave on devmem stub is infallible");
            let res = bus.write(&[0xDE, 0xAD]);
            assert!(
                res.is_err(),
                "am3-aml hashboard EEPROM at 0x{:02X} must REFUSE writes",
                addr
            );
        }
        // Counter must reflect 8 blocked writes.
        assert_eq!(
            bus.blocked_write_count(),
            8,
            "blocked_write_count must increment per refusal across 0x50..=0x57"
        );
    }

    #[test]
    fn amlogic_denylist_allows_psu_and_temp_sensors() {
        // The denylist must be EEPROM-only. PSU PMBus (0x1f), LM75 inlet
        // sensors (0x48..=0x4A), LM75 outlet sensors (0x4C..=0x4E), dsPIC
        // hybrid addresses (0x20..=0x22), and APW PSU (0x10) must remain
        // writable. If a future change extends the denylist to any of
        // these, PSU enable, temperature reads (which need a register-
        // pointer write), and dsPIC voltage commands all break.
        use crate::i2c::I2cBus;
        let mut bus = I2cBus::open_devmem();
        bus.set_write_denylist(&AMLOGIC_EEPROM_DENYLIST);

        for &(addr, label) in &[
            (0x10u8, "APW PSU"),
            (0x1fu8, "PSU PMBus"),
            (0x20u8, "dsPIC hb1"),
            (0x21u8, "dsPIC hb2"),
            (0x22u8, "dsPIC hb3"),
            (0x48u8, "LM75 inlet hb1"),
            (0x49u8, "LM75 inlet hb2"),
            (0x4Au8, "LM75 inlet hb3"),
            (0x4Cu8, "LM75 outlet hb1"),
            (0x4Du8, "LM75 outlet hb2"),
            (0x4Eu8, "LM75 outlet hb3"),
        ] {
            bus.set_slave(addr).expect("set_slave on devmem stub");
            // devmem stub `write` returns Ok for non-denied addresses
            // (the actual MMIO call is a no-op when not on real hardware).
            let res = bus.write(&[0x00]);
            // We only care that the denylist did NOT trip — devmem may
            // still error for other reasons but the error string must
            // not mention "write denylist".
            if let Err(e) = res {
                let msg = format!("{:?}", e);
                assert!(
                    !msg.contains("write denylist"),
                    "{} (0x{:02X}) was incorrectly denied: {}",
                    label,
                    addr,
                    msg
                );
            }
        }
    }

    #[test]
    fn s9_platform_must_not_inherit_amlogic_denylist() {
        // S9 (am1-zynq) registers NO denylist on startup because its
        // 0x55-0x57 are PIC voltage controllers, NOT EEPROMs. Applying
        // AMLOGIC_EEPROM_DENYLIST on S9 would brick PIC writes. This
        // test pins the contract: a fresh I2cBus has an empty denylist
        // and PIC-range writes are NOT denied by default.
        use crate::i2c::I2cBus;
        let mut s9_bus = I2cBus::open_devmem();
        // No denylist registered — simulating S9 platform startup.
        for addr in 0x55u8..=0x57u8 {
            s9_bus.set_slave(addr).expect("set_slave on devmem stub");
            // The denylist gate must not refuse this write — any error
            // from the devmem stub is unrelated to our protection.
            if let Err(e) = s9_bus.write(&[0x00]) {
                let msg = format!("{:?}", e);
                assert!(
                    !msg.contains("write denylist"),
                    "S9 PIC at 0x{:02X} was wrongly denied: {}",
                    addr,
                    msg
                );
            }
        }
        assert_eq!(
            s9_bus.blocked_write_count(),
            0,
            "S9 platform must register zero blocked writes (no denylist active)"
        );
    }

    #[test]
    fn edges_to_rpm_uses_2_pulses_per_revolution_at_1s_window() {
        // 60 falling edges in 1 s, 2 PPR ⇒ 60 * 60 / (1 * 2) = 1800 RPM.
        assert_eq!(edges_to_rpm(60, Duration::from_secs(1)), 1800);
        // 0 edges ⇒ 0 RPM. No positive fallback may hide a stopped fan.
        assert_eq!(edges_to_rpm(0, Duration::from_secs(1)), 0);
        // Very high count (industrial fan at 6000 RPM ≈ 200 edges/s).
        assert_eq!(edges_to_rpm(200, Duration::from_secs(1)), 6000);
    }

    #[test]
    fn edges_to_rpm_handles_short_window() {
        // 30 edges in 0.5 s ⇒ 30 * 60 / (0.5 * 2) = 1800 RPM.
        assert_eq!(edges_to_rpm(30, Duration::from_millis(500)), 1800);
    }

    #[test]
    fn edges_to_rpm_zero_window_does_not_panic() {
        assert_eq!(edges_to_rpm(0, Duration::from_secs(0)), 0);
        assert_eq!(edges_to_rpm(100, Duration::from_secs(0)), 0);
    }

    #[test]
    fn tach_poll_classifier_accepts_kernfs_pri_err_but_rejects_bare_errors() {
        assert_eq!(tach_poll_has_edge(libc::POLLPRI).unwrap(), true);
        assert_eq!(
            tach_poll_has_edge(libc::POLLPRI | libc::POLLERR).unwrap(),
            true,
            "kernfs valid sysfs notifications carry POLLPRI|POLLERR"
        );
        assert_eq!(tach_poll_has_edge(0).unwrap(), false);
        for revents in [libc::POLLERR, libc::POLLHUP, libc::POLLNVAL] {
            assert!(
                tach_poll_has_edge(revents).is_err(),
                "revents=0x{revents:04X} must invalidate the tach sample"
            );
        }
    }

    #[test]
    fn amlogic_fan_reports_each_measured_tach_channel() {
        // With sample_window = 10 ms and 2 PPR, N edges produces N * 3000 RPM.
        let sources: [Box<dyn FanTachSource>; GPIO_FAN_TACH_COUNT] = [
            Box::new(FixedEdgeMock(20)),
            Box::new(FixedEdgeMock(10)),
            Box::new(FixedEdgeMock(5)),
            Box::new(FixedEdgeMock(2)),
        ];
        let fan = AmlogicFan::for_test(sources);

        assert!(fan.tach_available());

        // Sample window is 10 ms in the test constructor.
        let window = Duration::from_millis(10);
        let per_fan = fan.get_per_fan_rpm();
        assert_eq!(per_fan.len(), 4, "S21/S19j Pro Amlogic has 4 fan slots");
        assert_eq!(per_fan[0], (0, edges_to_rpm(20, window)));
        assert_eq!(per_fan[1], (1, edges_to_rpm(10, window)));
        assert_eq!(per_fan[2], (2, edges_to_rpm(5, window)));
        assert_eq!(per_fan[3], (3, edges_to_rpm(2, window)));
    }

    #[test]
    fn amlogic_zero_tach_dominates_aggregate_rpm() {
        let sources: [Box<dyn FanTachSource>; GPIO_FAN_TACH_COUNT] = [
            Box::new(FixedEdgeMock(20)),
            Box::new(FixedEdgeMock(10)),
            Box::new(FixedEdgeMock(0)),
            Box::new(FixedEdgeMock(5)),
        ];
        let fan = AmlogicFan::for_test(sources);

        assert_eq!(fan.get_per_fan_rpm()[2], (2, 0));
        assert_eq!(fan.get_rpm(), 0, "a stopped fan must not be filtered out");
    }

    #[test]
    fn amlogic_tach_sample_error_revokes_runtime_availability() {
        let sources: [Box<dyn FanTachSource>; GPIO_FAN_TACH_COUNT] = [
            Box::new(FixedEdgeMock(20)),
            Box::new(FailingEdgeMock),
            Box::new(FixedEdgeMock(10)),
            Box::new(FixedEdgeMock(5)),
        ];
        let fan = AmlogicFan::for_test(sources);

        assert!(fan.tach_available());
        let readings = fan.get_per_fan_rpm();
        assert_eq!(readings[1], (1, 0));
        assert!(
            !fan.tach_available(),
            "an invalid sample must permanently revoke this owner's evidence"
        );
    }

    #[cfg(panic = "unwind")]
    #[test]
    fn amlogic_tach_sampler_panic_revokes_runtime_availability() {
        let sources: [Box<dyn FanTachSource>; GPIO_FAN_TACH_COUNT] = [
            Box::new(FixedEdgeMock(20)),
            Box::new(PanickingEdgeMock),
            Box::new(FixedEdgeMock(10)),
            Box::new(FixedEdgeMock(5)),
        ];
        let fan = AmlogicFan::for_test(sources);

        assert!(fan.tach_available());
        let readings = fan.get_per_fan_rpm();
        assert_eq!(readings[1], (1, 0));
        assert!(
            !fan.tach_available(),
            "a panicked sampler must permanently revoke this owner's evidence"
        );
    }

    #[test]
    fn fan_tach_slots_share_one_parallel_observation_window() {
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let maximum = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sources: [Box<dyn FanTachSource>; GPIO_FAN_TACH_COUNT] = std::array::from_fn(|_| {
            Box::new(ConcurrentEdgeMock {
                active: active.clone(),
                maximum: maximum.clone(),
            }) as Box<dyn FanTachSource>
        });
        let fan = AmlogicFan::for_test(sources);

        assert_eq!(fan.get_per_fan_rpm().len(), 4);
        assert!(
            maximum.load(std::sync::atomic::Ordering::SeqCst) > 1,
            "tach sources must overlap instead of consuming four sequential windows"
        );
    }

    // ─── W2A.2: PIC1704 wire-up regression guards ───

    #[test]
    fn s21_subtype_returns_nopic() {
        // S21 NoPic-class subtypes (e.g. an Amlogic carrier with no
        // BHB42/56 hashboard) classify to NoPic. The sustained-mining
        // s21 unit boots without /etc/subtype, so this guards
        // future BraiinsOS+ images that DO ship one.
        use crate::platform::subtype::classify_voltage_controller;
        assert_eq!(
            classify_voltage_controller(Some("AMLCtrl_BHB68900")),
            VoltageControllerKind::NoPic,
        );
        assert_eq!(
            classify_voltage_controller(Some("AMLCtrl_S21Pro")),
            VoltageControllerKind::NoPic,
        );
    }

    #[test]
    fn bhb56_subtype_remains_nopic_from_live_evidence() {
        // S19k Pro at .78 (`AMLCtrl_BHB56902`) is live-confirmed NoPic.
        // Unobserved BHB56 suffixes cannot widen that identity into dsPIC
        // controller authority.
        use crate::platform::subtype::classify_voltage_controller;
        assert_eq!(
            classify_voltage_controller(Some("AMLCtrl_BHB56902")),
            VoltageControllerKind::NoPic,
        );
        assert_eq!(
            classify_voltage_controller(Some("AMLCtrl_BHB56xxx")),
            VoltageControllerKind::NoPic,
        );
    }

    #[test]
    fn amlogic_with_config_voltage_controller_is_passthrough() {
        // Any `with_config` call carries voltage_controller from the
        // PlatformConfig. Default builders preserve the existing safe
        // path; only an explicit override re-routes to PIC1704. This
        // is the no-regression guard for s19jpro (sustained-mining
        // unit running existing dsPIC path): merely instantiating
        // AmlogicPlatform from a default config never silently upgrades
        // it to PIC1704.
        let cfg = PlatformConfig::s19k_amlogic();
        assert_eq!(cfg.voltage_controller, VoltageControllerKind::NoPic);
        let p = AmlogicPlatform::with_config(cfg);
        assert_eq!(p.voltage_controller(), VoltageControllerKind::NoPic);

        let cfg = PlatformConfig::s21_amlogic();
        assert_eq!(cfg.voltage_controller, VoltageControllerKind::NoPic);
        let p = AmlogicPlatform::with_config(cfg);
        assert_eq!(p.voltage_controller(), VoltageControllerKind::NoPic);
    }

    /// Exact S21 production control flow disproves the startup-high
    /// inference; keep Pro distinct until independently resolved.
    #[test]
    fn psu_polarity_is_bound_to_the_exact_admitted_profile() {
        for profile in [AmlogicNoPicProfile::S19k, AmlogicNoPicProfile::S21] {
            assert_eq!(
                amlogic_gpio437::resolve_drive_recipe(profile.board_target())
                    .unwrap()
                    .on_raw(),
                0
            );
            assert!(parse_psu_gpio_engaged(
                "0",
                amlogic_gpio437::resolve_drive_recipe(profile.board_target()).unwrap()
            )
            .unwrap());
            assert!(!parse_psu_gpio_engaged(
                "1",
                amlogic_gpio437::resolve_drive_recipe(profile.board_target()).unwrap()
            )
            .unwrap());
        }
        assert_eq!(
            amlogic_gpio437::resolve_drive_recipe(AmlogicNoPicProfile::S21Pro.board_target())
                .unwrap()
                .off_raw(),
            1
        );
        assert!(!amlogic_handoff_identity_matches_profile(
            AmlogicNoPicProfile::S21,
            "am3-aml-s21pro",
            "am3-s21pro"
        ));
        let valid = boot_safe_handoff_fixture();
        parse_amlogic_boot_safe_handoff(&valid).unwrap();
        assert!(parse_amlogic_boot_safe_handoff(
            &valid
                .replace("commanded_value=1", "commanded_value=0")
                .replace("readback_value=1", "readback_value=0")
        )
        .is_err());
    }
    #[test]
    fn native_gpio_psu_profile_selection_preserves_track1_and_cut_order() {
        assert_eq!(AmlogicNoPicProfile::S19k.gpio_psu_profile(false), None);
        assert_eq!(
            AmlogicNoPicProfile::S19k.gpio_psu_profile(true),
            Some(s21_psu::ProductionProfile::S19kApw121215)
        );
        assert_eq!(
            AmlogicNoPicProfile::S21.gpio_psu_profile(true),
            Some(s21_psu::ProductionProfile::S21Apw121215)
        );
        assert_eq!(
            AmlogicNoPicProfile::S21Pro.gpio_psu_profile(true),
            Some(s21_psu::ProductionProfile::ModernProXpAuto)
        );
        assert!(
            !AmlogicPsuCommitAuthority::new(AmlogicNoPicProfile::S19k, Some(Arc::new(())))
                .reset_after_cut
        );
        assert!(
            AmlogicPsuCommitAuthority::new(AmlogicNoPicProfile::S21, Some(Arc::new(())))
                .reset_after_cut
        );
    }
    #[test]
    fn bm1370_pro_and_xp_bind_actual_three_uart_populations_and_power_polarity() {
        for (profile, marker, target, count) in [
            (
                AmlogicNoPicProfile::S21Pro,
                "am3-aml-s21pro",
                "am3-s21pro",
                65,
            ),
            (AmlogicNoPicProfile::S21Xp, "am3-aml-s21xp", "am3-s21xp", 91),
        ] {
            assert_eq!(
                profile.modern_s21_geometry(),
                Some((dcentrald_common::AsicProtocolIdentity::Bm1370, count))
            );
            assert!(amlogic_handoff_identity_matches_profile(
                profile, marker, target
            ));
            assert_eq!(
                amlogic_gpio437::resolve_drive_recipe(profile.board_target())
                    .unwrap()
                    .on_raw(),
                0
            );
            let receipt = boot_safe_handoff_fixture()
                .replace("am3-aml-s21", marker)
                .replace(
                    "board_target=am3-s21\n",
                    &format!("board_target={target}\n"),
                );
            parse_amlogic_boot_safe_handoff(&receipt).unwrap();
            assert!(parse_amlogic_boot_safe_handoff(
                &receipt
                    .replace("commanded_value=1", "commanded_value=0")
                    .replace("readback_value=1", "readback_value=0")
            )
            .is_err());
            for mask in 1u8..8 {
                let slots = std::array::from_fn(|slot| mask & (1 << slot) != 0);
                let first = slots.iter().position(|present| *present).unwrap();
                let admission = AmlogicNoPicAdmission::from_profile_evidence(
                    profile,
                    first as u8,
                    S21_UARTS[first],
                    target,
                    profile,
                    slots,
                )
                .unwrap();
                let routes = admission.s21_routes().unwrap();
                assert_eq!(routes.len(), mask.count_ones() as usize);
                for (slot, path) in routes {
                    assert_eq!(path, S21_UARTS[slot as usize]);
                }
                assert!(amlogic_slot_from_serial_device(profile, "/dev/ttyS4").is_none());
            }
            let commit = AmlogicPsuCommitAuthority::new(profile, Some(Arc::new(())));
            assert!(commit.reset_after_cut);
        }
    }

    #[test]
    fn bm1366_xp_profiles_bind_actual_three_uart_populations_and_power_polarity() {
        for (profile, marker, target, count) in [
            (
                AmlogicNoPicProfile::S19Xp,
                "am3-aml-s19xp",
                "am3-s19xp",
                110,
            ),
            (
                AmlogicNoPicProfile::S19jXp,
                "am3-aml-s19jxp",
                "am3-s19jxp",
                110,
            ),
        ] {
            assert_eq!(
                profile.modern_s21_geometry(),
                Some((dcentrald_common::AsicProtocolIdentity::Bm1366, count))
            );
            assert!(amlogic_handoff_identity_matches_profile(
                profile, marker, target
            ));
            assert_eq!(
                amlogic_gpio437::resolve_drive_recipe(profile.board_target())
                    .unwrap()
                    .on_raw(),
                0
            );
            let receipt = boot_safe_handoff_fixture()
                .replace("am3-aml-s21", marker)
                .replace(
                    "board_target=am3-s21\n",
                    &format!("board_target={target}\n"),
                );
            parse_amlogic_boot_safe_handoff(&receipt).unwrap();
            assert!(parse_amlogic_boot_safe_handoff(
                &receipt
                    .replace("commanded_value=1", "commanded_value=0")
                    .replace("readback_value=1", "readback_value=0")
            )
            .is_err());
            for mask in 1u8..8 {
                let slots = std::array::from_fn(|slot| mask & (1 << slot) != 0);
                let first = slots.iter().position(|present| *present).unwrap();
                let admission = AmlogicNoPicAdmission::from_profile_evidence(
                    profile,
                    first as u8,
                    S21_UARTS[first],
                    target,
                    profile,
                    slots,
                )
                .unwrap();
                let routes = admission.s21_routes().unwrap();
                assert_eq!(routes.len(), mask.count_ones() as usize);
                for (slot, path) in routes {
                    assert_eq!(path, S21_UARTS[slot as usize]);
                }
                assert!(amlogic_slot_from_serial_device(profile, "/dev/ttyS4").is_none());
            }
            let commit = AmlogicPsuCommitAuthority::new(profile, Some(Arc::new(())));
            assert!(commit.reset_after_cut);
        }
    }
    #[test]
    fn bm1362_aml_a_plus_profiles_bind_all_populations_power_and_distinct_psu() {
        for (profile, marker, target, count) in [
            (
                AmlogicNoPicProfile::S19jProA,
                "am3-aml-s19jproa",
                "am3-s19jproa",
                126,
            ),
            (
                AmlogicNoPicProfile::S19jProPlus,
                "am3-aml-s19jproplus",
                "am3-s19jproplus",
                120,
            ),
        ] {
            assert_eq!(
                profile.modern_s21_geometry(),
                Some((dcentrald_common::AsicProtocolIdentity::Bm1362, count))
            );
            assert!(amlogic_handoff_identity_matches_profile(
                profile, marker, target
            ));
            assert_eq!(
                amlogic_gpio437::resolve_drive_recipe(profile.board_target())
                    .unwrap()
                    .on_raw(),
                0
            );
            let receipt = boot_safe_handoff_fixture()
                .replace("am3-aml-s21", marker)
                .replace(
                    "board_target=am3-s21\n",
                    &format!("board_target={target}\n"),
                );
            parse_amlogic_boot_safe_handoff(&receipt).unwrap();
            assert!(parse_amlogic_boot_safe_handoff(
                &receipt
                    .replace("commanded_value=1", "commanded_value=0")
                    .replace("readback_value=1", "readback_value=0")
            )
            .is_err());
            for mask in 1u8..8 {
                let slots = std::array::from_fn(|slot| mask & (1 << slot) != 0);
                let first = slots.iter().position(|present| *present).unwrap();
                let admission = AmlogicNoPicAdmission::from_profile_evidence(
                    profile,
                    first as u8,
                    S21_UARTS[first],
                    target,
                    profile,
                    slots,
                )
                .unwrap();
                let routes = admission.s21_routes().unwrap();
                assert_eq!(routes.len(), mask.count_ones() as usize);
                for (slot, path) in routes {
                    assert_eq!(path, S21_UARTS[slot as usize]);
                }
                assert!(amlogic_slot_from_serial_device(profile, "/dev/ttyS4").is_none());
            }
            assert!(!amlogic_handoff_identity_matches_profile(
                profile,
                "am3-aml-s19jpro",
                "am3-s19jpro-aml"
            ));
            let config = config_for_dcentos_platform(marker).unwrap().unwrap();
            assert!(!config.has_pic);
            assert_eq!(config.chains.len(), 3);
            assert_eq!(
                profile.gpio_psu_profile(true),
                Some(match profile {
                    AmlogicNoPicProfile::S19jProA => s21_psu::ProductionProfile::S21Apw121215,
                    AmlogicNoPicProfile::S19jProPlus => s21_psu::ProductionProfile::ModernProXpAuto,
                    _ => unreachable!(),
                })
            );
            let commit = AmlogicPsuCommitAuthority::new(profile, Some(Arc::new(())));
            assert!(commit.reset_after_cut);
        }
    }
    #[test]
    fn bm1366_xp_profiles_select_distinct_measured_psu_dialects() {
        assert_eq!(
            AmlogicNoPicProfile::S19Xp.gpio_psu_profile(true),
            Some(s21_psu::ProductionProfile::S21Apw121215)
        );
        assert_eq!(
            AmlogicNoPicProfile::S19jXp.gpio_psu_profile(true),
            Some(s21_psu::ProductionProfile::ModernApw171215)
        );
        for profile in [AmlogicNoPicProfile::S19Xp, AmlogicNoPicProfile::S19jXp] {
            assert!(AmlogicPsuCommitAuthority::new(profile, Some(Arc::new(()))).reset_after_cut);
        }
        assert!(
            !AmlogicPsuCommitAuthority::new(AmlogicNoPicProfile::S19k, Some(Arc::new(())))
                .reset_after_cut
        );
    }
}
