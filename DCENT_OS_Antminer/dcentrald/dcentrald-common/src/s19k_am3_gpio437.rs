//! am3-s19k GPIO437 `PWR_CONTROL` polarity pin — **board_target scoped**.
//!
//! Evidence (do not apply to S21 NoPic / other board_targets):
//! - `a lab unit` RE `S19K_PRO_BOSMINER_INIT_RE.md`: active LOW, 0=ON, 1=OFF
//! - Live 2026-08-12 Braiins S19k Pro NoPic: bosminer mining / tty held → 0;
//!   `S99bosminer stop` / cooldown `PSU: Disable` → 1; after `PSU: Enable` → 0
//! - ePIC UMC OS writes 1 to DISABLE (GPIO comparison only; six 2026-08-01 caveats)
//!
//! Exact S21 was independently corrected to active-low in R13 production RE;
//! this S19k evidence still does not establish any other product polarity.
//! That comment is a **different board_target**. This module does not flip it.
//! Never write sysfs from here. Observe-only helpers.
//!
//! `a lab unit` `bosminer.unpacked` opens the pin by DT label `PWR_CONTROL` through
//! `gpiod-0.2.3` + `open/utils-rs/gpio` on `/dev/gpiochip*` (`open pin out`).
//! Held Braiins `S37board_setup` exports 446/445/439–441/454–456/453/438/447–450
//! and never `echo 437`. Sysfs `gpio437/value` is still a valid **observe**
//! node after the kernel line is claimed; it is not how bosminer opens PSU.
//! DCENT `S37board_setup` *does* export 437 for boot SafeOff — that is a
//! different image, not the Braiins open model.
//!
//! `s19k_bm1366_nopic_beta::S19K_GPIO_PWR_EN_SAFE_OFF_VALUE` is this
//! board's SafeOff (`1`). S21-class SafeOff=0 is a different board_target.

use crate::s19k_bm1366_nopic_beta::S19K_AM3_BOARD_TARGET;

/// Sysfs value node (read-only from userspace helpers).
pub const GPIO437_SYSFS_VALUE: &str = "/sys/class/gpio/gpio437/value";

/// `a lab unit` bosminer DT / gpiod label. Not a polarity.
pub const S19K_AM3_PWR_CONTROL_DT_NAME: &str = "PWR_CONTROL";
/// Legacy sysfs global. Used only when `PWR_CONTROL` is absent on this kernel.
pub const S19K_AM3_PWR_CONTROL_LEGACY_GLOBAL: u32 = 437;

/// Sysfs global after name-first resolve. Name hit without a chip base
/// must not silently become 437.
pub fn s19k_am3_pwr_control_sysfs_n(resolved_global: Option<u32>) -> Result<u32, &'static str> {
    resolved_global.ok_or("PWR_CONTROL name hit without gpiochip base; refuse guessing sysfs 437")
}

/// Sysfs global after name-first plug resolve. Name hit without a chip
/// base must not silently become 439+slot. Slot >= 3 is refused.
pub fn s19k_am3_plug_sysfs_n(slot: u8, resolved_global: Option<u32>) -> Result<u32, &'static str> {
    if slot >= 3 {
        return Err("S19k/S21 have 3 plug slots; refuse slot>=3");
    }
    resolved_global.ok_or("plug DT name hit without gpiochip base; refuse guessing 439+slot")
}

/// Sysfs global after name-first reset resolve. Name hit without a chip
/// base must not silently become 454+chain. Chain >= 3 / HB3 is refused.
pub fn s19k_am3_reset_sysfs_n(
    chain: u8,
    resolved_global: Option<u32>,
) -> Result<u32, &'static str> {
    if chain >= 3 {
        return Err("S19k has 3 hashboards; refuse HB3_RESET as a 4th slot");
    }
    resolved_global.ok_or("reset DT name hit without gpiochip base; refuse guessing 454+chain")
}

/// Sysfs global after name-first fan-tach resolve. Name hit without a
/// chip base must not silently become 447+slot. Slot >= 4 is refused.
pub fn s19k_am3_fan_tach_sysfs_n(
    slot: u8,
    resolved_global: Option<u32>,
) -> Result<u32, &'static str> {
    if slot >= 4 {
        return Err("Amlogic has 4 fan tach slots; refuse slot>=4");
    }
    resolved_global.ok_or("fan tach DT name hit without gpiochip base; refuse guessing 447+slot")
}

/// Sysfs global after name-first LED resolve. Name hit without a chip
/// base must not silently become 438/453.
pub fn s19k_am3_led_sysfs_n(resolved_global: Option<u32>) -> Result<u32, &'static str> {
    resolved_global.ok_or("LED DT name hit without gpiochip base; refuse guessing 438/453")
}

/// Sysfs global after name-first I2C pinmux resolve. Name hit without a
/// chip base must not silently become 476/477.
pub fn s19k_am3_pinmux_sysfs_n(resolved_global: Option<u32>) -> Result<u32, &'static str> {
    resolved_global.ok_or("I2C pinmux DT name hit without gpiochip base; refuse guessing 476/477")
}

/// Zynq/BCB100 plug label is not the Amlogic primary key.
pub fn refuse_hb0_plug_as_amlogic_primary(name: &str) -> Result<(), &'static str> {
    if name == S19K_AM3_REFUSED_ZYNQ_PLUG_NAME {
        return Err("HB0_PLUG is Zynq/BCB100; Amlogic plug names are CH0_PLUG/CH1_PLUG/CH2_PLUG");
    }
    Ok(())
}

/// bosminer publishes HB3_RESET. S19k is a 3-board chassis.
pub fn refuse_hb3_reset_as_s19k_fourth_board(name: &str) -> Result<(), &'static str> {
    if name == S19K_AM3_REFUSED_FOURTH_RESET_NAME {
        return Err("HB3_RESET exists in bosminer; S19k has 3 boards — refuse as 4th slot");
    }
    Ok(())
}

/// `a lab unit` bosminer.unpacked string pins (file ~`0x00f29160` / `0x00f1e039`).
pub const BOSMINER_GPIO_RS: &str = "open/utils-rs/gpio/src/lib.rs";
pub const BOSMINER_GPIOD_RS: &str = "gpiod-0.2.3/src/lib.rs";
pub const BOSMINER_GPIOCHIP_PREFIX: &[u8] = b"/dev/gpiochip";
pub const BOSMINER_OPEN_PIN_OUT: &[u8] = b"open pin out";
pub const BOSMINER_PIN_NAME_NOT_FOUND: &[u8] = b"BUG: pin name  not found!";
pub const BOSMINER_PWR_CONTROL_LABEL: &[u8] = b"PWR_CONTROL";
pub const BOSMINER_HB_RESET_LABELS: [&[u8]; 4] =
    [b"HB0_RESET", b"HB1_RESET", b"HB2_RESET", b"HB3_RESET"];

fn blob_has(blob: &[u8], needle: &[u8]) -> bool {
    blob.windows(needle.len()).any(|w| w == needle)
}

/// bosminer opens PSU by DT label via gpiod, not sysfs `echo 437`.
pub fn admit_bosminer_psu_gpio_is_gpiod_label(blob: &[u8]) -> Result<(), &'static str> {
    if !blob_has(blob, BOSMINER_PWR_CONTROL_LABEL) {
        return Err("bosminer missing PWR_CONTROL label");
    }
    if !blob_has(blob, BOSMINER_GPIOCHIP_PREFIX) {
        return Err("bosminer missing /dev/gpiochip");
    }
    if !blob_has(blob, BOSMINER_GPIOD_RS.as_bytes()) {
        return Err("bosminer missing gpiod-0.2.3");
    }
    if !blob_has(blob, BOSMINER_GPIO_RS.as_bytes()) {
        return Err("bosminer missing open/utils-rs/gpio");
    }
    if !blob_has(blob, BOSMINER_OPEN_PIN_OUT) {
        return Err("bosminer missing open pin out");
    }
    if !blob_has(blob, BOSMINER_PIN_NAME_NOT_FOUND) {
        return Err("bosminer missing pin-name-not-found");
    }
    for label in BOSMINER_HB_RESET_LABELS {
        if !blob_has(blob, label) {
            return Err("bosminer missing an HB*_RESET label");
        }
    }
    Ok(())
}

/// Held Braiins `S37board_setup` never exports GPIO437. DCENT S37 does.
pub fn refuse_held_braiins_s37_as_gpio437_exporter(s37: &str) -> Result<(), &'static str> {
    if !s37.contains("echo 446") || !s37.contains("CH0_PLUG") {
        return Err("not a held Braiins S37board_setup excerpt");
    }
    if s37.contains("echo 437") {
        return Err("held Braiins S37 unexpectedly exports 437; bosminer uses gpiod PWR_CONTROL");
    }
    Ok(())
}

/// Do not treat sysfs `export 437` as the Braiins PSU open path.
pub fn refuse_sysfs_export_437_as_bosminer_open() -> Result<(), &'static str> {
    Err("bosminer opens PWR_CONTROL via gpiod /dev/gpiochip; sysfs export 437 is observe/DCENT-S37")
}

/// `PWR_CONTROL` is active LOW on am3-s19k / Braiins S19k Pro.
pub const S19K_AM3_GPIO437_ACTIVE_LOW: bool = true;
/// Engaged / PSU enable / rails up (live + `a lab unit`).
pub const S19K_AM3_GPIO437_VALUE_ON: u8 = 0;
/// Disable / cooldown (live `S99` stop).
pub const S19K_AM3_GPIO437_VALUE_OFF: u8 = 1;

/// Hashboard reset GPIOs (S37board_setup) — active LOW. Do **not** pulse on
/// passthrough (S21 lesson: reset can kill DAC).
/// These are **legacy sysfs globals**. HAL resolves `HB0_RESET`/`HB1_RESET`/
/// `HB2_RESET` first. bosminer also has `HB3_RESET` (4th label); S19k has
/// three boards — do not treat HB3 as a fourth S19k hashboard.
pub const S19K_AM3_HB_RESET_GPIOS: [u16; 3] = [454, 455, 456];
pub const S19K_AM3_HB_RESET_ACTIVE_LOW: bool = true;
pub const S19K_AM3_RESET_DT_NAMES: [&str; 3] = ["HB0_RESET", "HB1_RESET", "HB2_RESET"];
/// bosminer 4th reset label. Not an S19k board slot.
pub const S19K_AM3_REFUSED_FOURTH_RESET_NAME: &str = "HB3_RESET";

/// Plug-detect GPIOs (S37board_setup): active HIGH, optional pulldown.
/// `1` = board present. Chassis slot numbering is **not** bound to ttyS.
/// Legacy sysfs globals. HAL resolves `CH0_PLUG`/`CH1_PLUG`/`CH2_PLUG`
/// (S21 Braiins + held S37 comments). Zynq/BCB100 `HB0_PLUG` is refused.
pub const S19K_AM3_PLUG_GPIOS: [u16; 3] = [439, 440, 441];
pub const S19K_AM3_PLUG_DT_NAMES: [&str; 3] = ["CH0_PLUG", "CH1_PLUG", "CH2_PLUG"];
pub const S19K_AM3_REFUSED_ZYNQ_PLUG_NAME: &str = "HB0_PLUG";
pub const S19K_AM3_PLUG_PRESENT_VALUE: u8 = 1;
/// S21 Braiins live GPIO map (`a lab unit` 2026-04-11). Legacy 447–450.
/// ePIC 461–464 is a different Amlogic revision — do not port.
pub const S19K_AM3_FAN_TACH_GPIOS: [u16; 4] = [447, 448, 449, 450];
pub const S19K_AM3_FAN_TACH_DT_NAMES: [&str; 4] = [
    "FAN_FRONT_SPEED0",
    "FAN_FRONT_SPEED1",
    "FAN_REAR_SPEED0",
    "FAN_REAR_SPEED1",
];
/// S21 Braiins live map: LED_RED=438, LED_GREEN=453 (active HIGH).
pub const S19K_AM3_LED_RED_DT_NAME: &str = "LED_RED";
pub const S19K_AM3_LED_GREEN_DT_NAME: &str = "LED_GREEN";
pub const S19K_AM3_LED_RED_LEGACY_GLOBAL: u32 = 438;
pub const S19K_AM3_LED_GREEN_LEGACY_GLOBAL: u32 = 453;
/// S21 Braiins names. Pinmux direction is **input** (S37/HAL), not the
/// old output-high sequence on these pins.
pub const S19K_AM3_I2C_SCL_DT_NAME: &str = "I2C_SCL";
pub const S19K_AM3_I2C_SDA_DT_NAME: &str = "I2C_SDA";
pub const S19K_AM3_I2C_SCL_LEGACY_GLOBAL: u32 = 476;
pub const S19K_AM3_I2C_SDA_LEGACY_GLOBAL: u32 = 477;
pub const GPIO439_SYSFS_VALUE: &str = "/sys/class/gpio/gpio439/value";
pub const GPIO440_SYSFS_VALUE: &str = "/sys/class/gpio/gpio440/value";
pub const GPIO441_SYSFS_VALUE: &str = "/sys/class/gpio/gpio441/value";

/// Parse a sysfs `0`/`1` plug line. `1` = present (S37 active HIGH).
pub fn s19k_am3_plug_present(value: Option<u8>) -> Option<bool> {
    match value {
        Some(v) if v == S19K_AM3_PLUG_PRESENT_VALUE => Some(true),
        Some(0) => Some(false),
        _ => None,
    }
}

/// Count plugged slots from three optional sysfs reads. Unknowns do not
/// count as present or absent.
pub fn s19k_am3_plug_present_count(plugs: [Option<u8>; 3]) -> usize {
    plugs
        .iter()
        .filter(|v| s19k_am3_plug_present(**v) == Some(true))
        .count()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kAm3Gpio437Rail {
    Engaged,
    DisabledOrCooldown,
    Unknown,
}

/// Interpret a sysfs `0`/`1` read for **am3-s19k only**.
pub fn classify_s19k_am3_gpio437(value: Option<u8>) -> S19kAm3Gpio437Rail {
    match value {
        Some(S19K_AM3_GPIO437_VALUE_ON) => S19kAm3Gpio437Rail::Engaged,
        Some(S19K_AM3_GPIO437_VALUE_OFF) => S19kAm3Gpio437Rail::DisabledOrCooldown,
        _ => S19kAm3Gpio437Rail::Unknown,
    }
}

/// True when the observed bit means PSU engaged on am3-s19k.
pub fn s19k_am3_gpio437_is_engaged(value: u8) -> bool {
    value == S19K_AM3_GPIO437_VALUE_ON
}

/// Lifecycle the PSU GPIO is allowed to occupy. Values are **intended**
/// sysfs bits for am3-s19k only. This module never writes sysfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kAm3Gpio437Phase {
    ColdBootUnknown,
    /// bosminer `PSU: Enable` / kill-9 handoff with rails held.
    MiningOrHandoffEngaged,
    /// `S99bosminer stop` / cooldown / `PSU: Disable`.
    StopDisableCooldown,
    CrashOrWatchdog,
    ShutdownSafeOff,
}

/// Intended sysfs value for a phase. Electrical rail confirmation stays
/// EXPERIMENTAL (DMM). Software/log polarity is CLOSED for am3-s19k.
pub fn intended_gpio437_value(phase: S19kAm3Gpio437Phase) -> Option<u8> {
    match phase {
        S19kAm3Gpio437Phase::ColdBootUnknown => None,
        S19kAm3Gpio437Phase::MiningOrHandoffEngaged => Some(S19K_AM3_GPIO437_VALUE_ON),
        S19kAm3Gpio437Phase::StopDisableCooldown
        | S19kAm3Gpio437Phase::CrashOrWatchdog
        | S19kAm3Gpio437Phase::ShutdownSafeOff => Some(S19K_AM3_GPIO437_VALUE_OFF),
    }
}

/// HashSource / RE-4C / S21-family admit still uses SafeOff=0.
/// Using that constant as an am3-s19k rail cut **ENGAGES** the PSU.
pub fn refuse_re4c_safe_off_as_am3_s19k_cut(safe_off_value: u8) -> Result<(), &'static str> {
    if safe_off_value == S19K_AM3_GPIO437_VALUE_ON {
        return Err(
            "am3-s19k: refuse RE-4C/S21 SafeOff=0; writing 0 ENGAGES PWR_CONTROL (T6 0=ON)",
        );
    }
    if safe_off_value != S19K_AM3_GPIO437_VALUE_OFF {
        return Err("am3-s19k SafeOff must be sysfs 1 (DISABLE / cooldown)");
    }
    Ok(())
}

/// Install/NAND mutation SafeOff for **am3-s19k only**.
pub fn am3_s19k_install_safe_off_value() -> u8 {
    S19K_AM3_GPIO437_VALUE_OFF
}

fn gpio437_source_section<'a>(
    source: &'a str,
    start: &str,
    end: &str,
) -> Result<&'a str, &'static str> {
    let start = source.find(start).ok_or("missing GPIO437 source owner")?;
    let length = source[start..]
        .find(end)
        .ok_or("cannot bound GPIO437 source owner")?;
    Ok(&source[start..start + length])
}

/// The shared recipe writer must export, normalize inversion while input,
/// establish OFF direction, write the selected raw level and check readback.
pub fn admit_s19k_disable_psu_checked_exports_before_write(hal: &str) -> Result<(), &'static str> {
    let body = gpio437_source_section(
        hal,
        "fn drive_psu_checked_at(",
        "fn read_psu_active_low_disabled_checked_at(",
    )?;
    let mut after = 0;
    for needle in [
        "write(&gpio_root.join(\"export\"), &n.to_string())",
        "write(&base.join(\"direction\"), \"in\")",
        "fs::read_to_string(base.join(\"direction\"))?.trim() != \"in\"",
        "write(&base.join(\"active_low\"), \"0\")",
        "read_psu_active_low_disabled_checked_at(gpio_root, n)?",
        "write(&base.join(\"direction\"), recipe.off_direction())",
        "let raw = if on",
        "recipe.on_raw()",
        "recipe.off_raw()",
        "write(&base.join(\"value\"), &raw.to_string())",
        "read_psu_enabled_on_with_recipe_at(gpio_root, n, recipe)? != on",
    ] {
        after += body[after..]
            .find(needle)
            .ok_or("GPIO437 writer lost ordered export/normalization/OFF/raw/readback")?
            + needle.len();
    }
    let generic = gpio437_source_section(
        hal,
        "pub fn disable_psu_checked()",
        "pub fn disable_s19k_track1_psu_checked()",
    )?;
    if !generic.contains("disable_psu_checked_for_recipe(amlogic_marker_drive_recipe()?)") {
        return Err("standalone cut must resolve the exact marker through the qualified table");
    }
    let explicit = gpio437_source_section(
        hal,
        "pub fn disable_s19k_track1_psu_checked()",
        "pub fn disable_psu()",
    )?;
    if !explicit.contains("amlogic_gpio437::resolve_drive_recipe(\"am3-s19k\")")
        || !explicit.contains("disable_psu_checked_for_recipe(recipe)")
        || explicit.contains("amlogic_marker_drive_recipe")
        || explicit.contains("/etc/dcentos")
    {
        return Err("Track-1 cut must retain the exact S19k table recipe without marker reads");
    }
    Ok(())
}

/// Both recipe-bound entry points resolve PWR_CONTROL before the shared writer.
pub fn admit_s19k_hal_resolves_pwr_control_before_sysfs(hal: &str) -> Result<(), &'static str> {
    admit_s19k_disable_psu_checked_exports_before_write(hal)?;
    let resolver = gpio437_source_section(
        hal,
        "pub fn resolve_psu_gpio_global()",
        "fn resolve_plug_gpio_global",
    )?;
    if !resolver.contains("resolve_name_or_legacy(\"PWR_CONTROL\", GPIO_PSU_ENABLE)") {
        return Err("HAL must resolve the PWR_CONTROL name with its explicit carrier fallback");
    }
    for (start, end) in [
        ("fn enable_psu_gpio_for_recipe(", "fn drive_psu_checked_at("),
        (
            "fn disable_psu_checked_for_recipe(",
            "pub fn disable_psu_with_retained_recipe_checked(",
        ),
    ] {
        let body = gpio437_source_section(hal, start, end)?;
        let resolve = body
            .find("resolve_psu_gpio_global()?")
            .ok_or("missing PWR_CONTROL resolver")?;
        let write = body
            .find("drive_psu_checked_at(")
            .ok_or("missing qualified recipe writer")?;
        if resolve > write {
            return Err("PWR_CONTROL resolution must precede any recipe GPIO write");
        }
    }
    Ok(())
}

/// Population admission freezes one exact table recipe in OnceLock. Enable,
/// poisoned-lock rollback, unwind and terminal cutoff must reuse that recipe.
pub fn admit_amlogic_retained_power_owner_freezes_profile_polarity(
    hal: &str,
) -> Result<(), &'static str> {
    let authority = gpio437_source_section(
        hal,
        "struct AmlogicPsuCommitAuthority",
        "fn amlogic_psu_enable_superseded",
    )?;
    for needle in [
        "board_target: profile.board_target()",
        "recipe: OnceLock<Gpio437DriveRecipe>",
        "recipe: OnceLock::new()",
        "self.recipe.get().copied().ok_or_else",
        ".any(|(name, present)| name.is_some() != present)",
        "amlogic_gpio437::resolve_population_recipe(self.board_target, &names)",
        "let _commit = self.begin_enable()?",
        "self.recipe.set(recipe).map_err",
        "self.recipe().and_then(disable_psu_checked_for_recipe)",
    ] {
        if !authority.contains(needle) {
            return Err("PSU owner lost exact population/table/single-assignment custody");
        }
    }
    let service = gpio437_source_section(
        hal,
        "impl AmlogicPowerThermalService",
        "pub fn hold_track1_leftover_fans_pwm100",
    )?;
    let compact = service.split_whitespace().collect::<String>();
    if !compact.contains("admission.populated_slots(),admission.profile(),")
        || !compact.contains("AmlogicPsuCommitAuthority::new(profile,native_generation)")
    {
        return Err("retained Amlogic service must bind its admitted profile and generation");
    }
    let lifecycle = gpio437_source_section(
        hal,
        "impl AmlogicPowerThermalLifecycleOwner",
        "pub struct AmlogicPsuEnableOperation",
    )?;
    let fence = lifecycle
        .find("self.psu_commit.begin_terminal_cut()")
        .ok_or("missing terminal GPIO fence")?;
    let cut = lifecycle
        .find("disable_psu_checked_for_recipe(self.psu_commit.recipe()?)?")
        .ok_or("terminal cut must use the retained population recipe")?;
    if fence > cut {
        return Err("terminal GPIO fence must precede the recipe cut");
    }
    let operation = gpio437_source_section(
        hal,
        "struct AmlogicPsuGpioRollback",
        "impl AmlogicThermalPort",
    )?;
    for needle in [
        "recipe: Gpio437DriveRecipe",
        "let recipe = self.psu_commit.recipe()?",
        "let gpio_commit = self.psu_commit.begin_enable()?",
        "AmlogicPsuGpioRollback::armed(recipe)",
        "enable_psu_gpio_for_recipe(recipe)",
    ] {
        if !operation.contains(needle) {
            return Err("enable/unwind owner lost its retained population recipe");
        }
    }
    if operation
        .matches("disable_psu_checked_for_recipe(self.recipe)")
        .count()
        != 2
    {
        return Err("checked-error and unwind rollback must both reuse the retained recipe");
    }
    let armed = operation
        .find("AmlogicPsuGpioRollback::armed(recipe)")
        .unwrap();
    if armed
        > operation
            .find("enable_psu_gpio_for_recipe(recipe)")
            .unwrap()
    {
        return Err("rollback must arm before any enable mutation");
    }
    for owner in [authority, lifecycle, operation] {
        for forbidden in [
            "disable_psu_checked()",
            "amlogic_marker_drive_recipe",
            "resolve_drive_recipe(",
            "/etc/dcentos",
            "psu_is_active_low",
        ] {
            if owner.contains(forbidden) {
                return Err("retained owner must not reselect mutable marker or blanket polarity");
            }
        }
    }
    Ok(())
}

/// : plug 439–441 and reset 454–456 must resolve DT names first.
/// Polarity is unchanged (plug 1=present, reset 0=assert). Track-1 must
/// not pulse reset.
pub fn admit_s19k_hal_resolves_plug_reset_by_name(hal: &str) -> Result<(), &'static str> {
    if !hal.contains("resolve_plug_gpio_global") {
        return Err("HAL must resolve plug GPIOs by name");
    }
    if !hal.contains("resolve_reset_gpio_global") {
        return Err("HAL must resolve HB reset GPIOs by name");
    }
    for name in S19K_AM3_PLUG_DT_NAMES {
        if !hal.contains(&format!("\"{name}\"")) {
            return Err("HAL must use S21/S37 CH*_PLUG DT names");
        }
    }
    for name in S19K_AM3_RESET_DT_NAMES {
        if !hal.contains(&format!("\"{name}\"")) {
            return Err("HAL must use bosminer HB*_RESET DT names");
        }
    }
    let plug_fn_start = hal
        .find("fn resolve_plug_gpio_global")
        .ok_or("missing resolve_plug_gpio_global")?;
    let plug_fn_end = hal[plug_fn_start..]
        .find("fn resolve_reset_gpio_global")
        .ok_or("cannot bound resolve_plug_gpio_global")?;
    let plug_fn = &hal[plug_fn_start..plug_fn_start + plug_fn_end];
    if plug_fn.contains("\"HB0_PLUG\"") {
        return Err("HAL must not use Zynq/BCB100 HB0_PLUG as Amlogic plug name");
    }
    refuse_hb0_plug_as_amlogic_primary(S19K_AM3_REFUSED_ZYNQ_PLUG_NAME)
        .err()
        .ok_or("HB0_PLUG refuse helper must fail closed")?;
    refuse_hb3_reset_as_s19k_fourth_board(S19K_AM3_REFUSED_FOURTH_RESET_NAME)
        .err()
        .ok_or("HB3_RESET refuse helper must fail closed")?;
    let topo_start = hal
        .find("fn read_plug_topology_checked")
        .ok_or("missing read_plug_topology_checked")?;
    let topo_end = hal[topo_start..]
        .find("Ok(populated)")
        .ok_or("cannot bound read_plug_topology_checked")?;
    let topo = &hal[topo_start..topo_start + topo_end];
    if !topo.contains("resolve_plug_gpio_global") {
        return Err("read_plug_topology_checked must call resolve_plug_gpio_global");
    }
    if topo.contains("GPIO_PLUG_BASE +") {
        return Err("topology must not use integer plug base as primary");
    }
    let detect_start = hal
        .find("fn read_plug_detect(&self)")
        .ok_or("missing read_plug_detect")?;
    let detect_end = hal[detect_start..]
        .find("\n    fn ")
        .ok_or("cannot bound read_plug_detect")?;
    let detect = &hal[detect_start..detect_start + detect_end];
    if !detect.contains("resolve_plug_gpio_global") {
        return Err("read_plug_detect must call resolve_plug_gpio_global");
    }
    if detect.contains("GPIO_PLUG_BASE +") {
        return Err("read_plug_detect must not use integer plug base as primary");
    }
    let checked_reset_start = hal
        .find("pub fn set_amlogic_board_reset_checked(")
        .ok_or("missing checked Amlogic reset API")?;
    // Bound at the sibling receipt-assertion helper (its `GPIO_RESET_BASE +`
    // use is an expected-value cross-check of the receipt, not resolution);
    // the checked reset API itself must stay name-first.
    let checked_reset_end = hal[checked_reset_start..]
        .find("pub fn assert_s19k_native_all_resets_checked")
        .ok_or("cannot bound checked Amlogic reset API")?;
    let checked_reset = &hal[checked_reset_start..checked_reset_start + checked_reset_end];
    if !checked_reset.contains("resolve_reset_gpio_global") {
        return Err("checked Amlogic reset must call resolve_reset_gpio_global");
    }
    if checked_reset.contains("GPIO_RESET_BASE +") {
        return Err("checked Amlogic reset must not use integer reset base as primary");
    }
    let trait_reset_start = hal
        .find("fn set_board_reset(&self")
        .ok_or("missing GpioAccess set_board_reset")?;
    let trait_reset = &hal[trait_reset_start..hal.len().min(trait_reset_start + 700)];
    if !trait_reset.contains("set_amlogic_board_reset_checked") {
        return Err("GpioAccess reset wrapper must use the checked Amlogic reset API");
    }
    if trait_reset.contains("let _ = fs::write") {
        return Err("Amlogic reset must not discard a sysfs write result");
    }
    Ok(())
}

/// Track-1 GetAddress / re-arm / work-loop must not pulse HB reset.
pub fn admit_s19k_track1_does_not_pulse_hb_reset(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("PASSTHROUGH BM1366") else {
        return Err("Track-1 mining-on window missing");
    };
    let window = src[start..]
        .split("} else if passthrough {")
        .next()
        .ok_or("Track-1 mining-on window has no passthrough seam")?;
    if window.contains("set_board_reset") {
        return Err("Track-1 mining-on must not pulse HB reset");
    }
    Ok(())
}

/// : Track-1 preflight observe must use name-first PSU/plug
/// numbers, not hardcoded gpio437 / gpio439-441.
pub fn admit_s19k_track1_preflight_resolves_plug_psu(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("PASSTHROUGH BM1366") else {
        return Err("Track-1 mining-on window missing");
    };
    let window = src[start..]
        .split("} else if passthrough {")
        .next()
        .ok_or("Track-1 mining-on window has no passthrough seam")?;
    if window.contains("s19k_plug_sysfs_paths()") {
        return Err("Track-1 preflight must not use hardcoded 439-441 paths");
    }
    if window.contains("/sys/class/gpio/gpio437/value") {
        return Err("Track-1 preflight must not hardcode gpio437 path");
    }
    if !window.contains("resolve_psu_gpio_global") {
        return Err("Track-1 must resolve PWR_CONTROL before observe");
    }
    if !window.contains("resolve_plug_gpio_global") {
        return Err("Track-1 must resolve CH*_PLUG before observe");
    }
    Ok(())
}

/// : native Amlogic fan tach must resolve S21 names first.
pub fn admit_s19k_hal_resolves_fan_tach_by_name(hal: &str) -> Result<(), &'static str> {
    if !hal.contains("resolve_fan_tach_gpio_global") {
        return Err("HAL must resolve fan tach GPIOs by name");
    }
    for name in S19K_AM3_FAN_TACH_DT_NAMES {
        if !hal.contains(&format!("\"{name}\"")) {
            return Err("HAL must use S21 FAN_*_SPEED DT names");
        }
    }
    let start = hal
        .find("Bring up gpio447-450 as one complete cooling-observation")
        .ok_or("missing fan tach bring-up")?;
    let end = hal[start..]
        .find("complete GPIO falling-edge counter set armed")
        .ok_or("cannot bound fan tach bring-up")?;
    let body = &hal[start..start + end];
    if !body.contains("resolve_fan_tach_gpio_global") {
        return Err("fan tach arm must call resolve_fan_tach_gpio_global");
    }
    if body.contains("GPIO_FAN_TACH_BASE +") {
        return Err("fan tach arm must not use integer base as primary");
    }
    Ok(())
}

/// : LED 438/453 and I2C pinmux 476/477 must resolve DT names first.
pub fn admit_s19k_hal_resolves_led_and_pinmux_by_name(hal: &str) -> Result<(), &'static str> {
    if !hal.contains("resolve_led_gpio_global") {
        return Err("HAL must resolve LED GPIOs by name");
    }
    if !hal.contains("resolve_pinmux_gpio_global") {
        return Err("HAL must resolve I2C pinmux GPIOs by name");
    }
    for name in [S19K_AM3_LED_RED_DT_NAME, S19K_AM3_LED_GREEN_DT_NAME] {
        if !hal.contains(&format!("\"{name}\"")) {
            return Err("HAL must use S21 LED_RED/LED_GREEN DT names");
        }
    }
    for name in [S19K_AM3_I2C_SCL_DT_NAME, S19K_AM3_I2C_SDA_DT_NAME] {
        if !hal.contains(&format!("\"{name}\"")) {
            return Err("HAL must use S21 I2C_SCL/I2C_SDA DT names");
        }
    }
    let pinmux_start = hal
        .find("fn prepare_management_i2c_pinmux")
        .ok_or("missing prepare_management_i2c_pinmux")?;
    let pinmux_end = hal[pinmux_start..]
        .find("Ok(())")
        .ok_or("cannot bound prepare_management_i2c_pinmux")?;
    let pinmux = &hal[pinmux_start..pinmux_start + pinmux_end];
    if !pinmux.contains("resolve_pinmux_gpio_global") {
        return Err("pinmux prep must call resolve_pinmux_gpio_global");
    }
    if pinmux.contains("for gpio in GPIO_PINMUX_FIX") {
        return Err("pinmux prep must not iterate raw 476/477 as primary");
    }
    let led_start = hal
        .find("fn write_amlogic_status_led")
        .or_else(|| hal.find("pub fn write_amlogic_status_led"))
        .ok_or("missing write_amlogic_status_led")?;
    let led_end = hal[led_start..]
        .find("Ok(())")
        .ok_or("cannot bound write_amlogic_status_led")?;
    let led = &hal[led_start..led_start + led_end];
    if !led.contains("resolve_led_gpio_global") {
        return Err("LED write must resolve LED_RED/LED_GREEN first");
    }
    Ok(())
}

/// Crash/shutdown intended sysfs bit is 1. RE-4C/S21 SafeOff=0 is refused.
pub fn admit_s19k_crash_teardown_safeoff_value() -> Result<(), &'static str> {
    refuse_re4c_safe_off_as_am3_s19k_cut(S19K_AM3_GPIO437_VALUE_OFF)?;
    if intended_gpio437_value(S19kAm3Gpio437Phase::CrashOrWatchdog)
        != Some(S19K_AM3_GPIO437_VALUE_OFF)
    {
        return Err("am3-s19k crash/teardown SafeOff must be sysfs 1");
    }
    if intended_gpio437_value(S19kAm3Gpio437Phase::ShutdownSafeOff)
        != Some(S19K_AM3_GPIO437_VALUE_OFF)
    {
        return Err("am3-s19k shutdown SafeOff must be sysfs 1");
    }
    Ok(())
}

/// Track-1 GetAddress / re-arm / work-loop must not write GPIO437.
/// Panic-hook arm after preflight is allowed (`arm_s19k_track1_teardown`).
pub fn admit_s19k_track1_mining_on_does_not_write_gpio437(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("PASSTHROUGH BM1366") else {
        return Err("Track-1 mining-on window missing");
    };
    let window = src[start..]
        .split("} else if passthrough {")
        .next()
        .ok_or("Track-1 mining-on window has no passthrough seam")?;
    if window.contains("enable_psu")
        || window.contains("disable_psu(")
        || window.contains("disable_psu_checked")
        || window.contains("latch_terminal_and_disable")
    {
        return Err("Track-1 mining-on must not write GPIO437");
    }
    Ok(())
}

/// Track-1 must arm panic-hook SafeOff without `prepare_enable` / `enable_psu`.
pub fn admit_s19k_track1_arms_teardown_without_enable(src: &str) -> Result<(), &'static str> {
    if !src.contains("arm_s19k_track1_teardown") {
        return Err("Track-1 must arm panic-hook teardown without enable_psu");
    }
    Ok(())
}

/// Track-1 must positively admit and retain the SoC watchdog without taking a
/// PSU power lease. While stock still owns the energized rails, it must then
/// revalidate both live-hardware and exact-process identity plus GPIO437
/// engagement with the reset+cut guard still unarmed. Only immediately before
/// the exact signal may it assume inherited rails and arm that closeout guard.
pub fn admit_s19k_track1_arms_watchdog_without_enable(src: &str) -> Result<(), &'static str> {
    let Some(run_start) = src.find("pub async fn run(&mut self) -> Result<()> {") else {
        return Err("serial run body missing");
    };
    let run = &src[run_start..];
    let Some(guard) = run.find("S19kTrack1RunCloseoutGuard::prepare(") else {
        return Err("Track-1 result-error closeout guard preparation missing");
    };
    let Some(track1_start) =
        run.find("let watchdog_start = SafetyWatchdogOwner::start_before_energizing(")
    else {
        return Err("Track-1 exact watchdog-to-stock-handoff window missing");
    };
    let track1_end = run[track1_start..]
        .find("let mut s19k_active_tx_paths")
        .map(|offset| track1_start + offset)
        .ok_or("Track-1 handoff window has no UART boundary")?;
    let window = &run[track1_start..track1_end];
    let Some(watchdog) = window.find("start_before_energizing") else {
        return Err("Track-1 must start SoC watchdog before stock-process signal");
    };
    if guard >= track1_start + watchdog {
        return Err("Track-1 closeout guard must be prepared before SoC watchdog startup");
    }
    if window.contains("prepare_enable(") || window.contains("enable_psu(") {
        return Err("Track-1 watchdog must not take a power lease");
    }
    let owner = window
        .find("let (mut watchdog_owner, admission)")
        .ok_or("Track-1 must retain the newly started watchdog owner")?;
    let positive = window
        .find("WatchdogAdmission::Armed(receipt) => receipt")
        .ok_or("Track-1 must require a positive Armed watchdog admission")?;
    let live_identity_revalidate = window
        .find("let immediate = s19k_capture_and_require_bound_live_identity()")
        .ok_or("Track-1 must recapture live hardware identity before closeout arm")?;
    let process_revalidate = window
        .find("expected.require_exact_tree_at(Path::new(\"/proc\"))?")
        .ok_or("Track-1 must revalidate exact stock identity before closeout arm")?;
    let gpio_revalidate = window
        .find("S19k Track-1 refuses stock handoff because GPIO437 changed before SIGKILL")
        .ok_or("Track-1 must revalidate GPIO437 engagement before closeout arm")?;
    let inherited = window
        .find(".assume_inherited_rails()")
        .ok_or("Track-1 must arm reset+cut closeout immediately before stock signal")?;
    let retained = window
        .find("nopic_watchdog = Some(watchdog_owner)")
        .ok_or("Track-1 must transfer its positively admitted watchdog owner to closeout")?;
    let kill = window
        .find(".sigkill_and_wait(")
        .ok_or("Track-1 must signal the exact J3-owned process and confirm exit")?;
    if watchdog >= owner
        || owner >= positive
        || positive >= live_identity_revalidate
        || live_identity_revalidate >= process_revalidate
        || process_revalidate >= gpio_revalidate
        || gpio_revalidate >= retained
        || retained >= inherited
        || inherited >= kill
    {
        return Err("Track-1 must start/own/admit watchdog, revalidate live hardware/process/GPIO while stock owns rails, transfer watchdog to closeout, arm closeout, then kill through the exact J3 lease");
    }
    if !window.contains("requested_timeout_s = receipt.requested_timeout_s")
        || !window.contains("effective_timeout_s = receipt.effective_timeout_s")
    {
        return Err("Track-1 must consume and report the typed Armed watchdog receipt");
    }
    if !src.contains("s19k_track1_mark_watchdog_liveness") {
        return Err("Track-1 must feed watchdog liveness without GPIO writes");
    }
    Ok(())
}

/// Defense-in-depth planned-stop GPIO437 SafeOff selector. Unset/empty and
/// exact `1` all require SafeOff; no environment token grants rail retention.
pub const S19K_TRACK1_STOP_SAFEOFF_ENV: &str = "DCENT_S19K_TRACK1_STOP_SAFEOFF";

pub fn s19k_track1_planned_stop_safeoff_from_env(
    value: Option<&str>,
) -> Result<bool, &'static str> {
    match value {
        None | Some("") | Some("1") => Ok(true),
        Some(_) => Err("DCENT_S19K_TRACK1_STOP_SAFEOFF must be 1 or unset; rail retention is not an environment-authorized operation"),
    }
}

/// Fan mutation allowed from the shared NoPic panic hook after its checked
/// identity-scoped power cut. A failed cut must never reduce airflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kNoPicPanicFanAction {
    CoastAfterCheckedCut,
    RetainTrack1ExplicitPwm100,
    HoldTrack1HomeCap,
    LeaveUnchanged,
}

pub fn s19k_nopic_panic_fan_action(
    track1_armed: bool,
    checked_cut_succeeded: bool,
    explicit_loud_authority: bool,
) -> S19kNoPicPanicFanAction {
    if checked_cut_succeeded {
        S19kNoPicPanicFanAction::CoastAfterCheckedCut
    } else if track1_armed && explicit_loud_authority {
        S19kNoPicPanicFanAction::RetainTrack1ExplicitPwm100
    } else if track1_armed {
        S19kNoPicPanicFanAction::HoldTrack1HomeCap
    } else {
        S19kNoPicPanicFanAction::LeaveUnchanged
    }
}

pub fn admit_s19k_track1_planned_stop_default_is_safeoff() -> Result<(), &'static str> {
    if !s19k_track1_planned_stop_safeoff_from_env(None)? {
        return Err("unset env must require GPIO437 SafeOff on planned stop");
    }
    if !s19k_track1_planned_stop_safeoff_from_env(Some(""))? {
        return Err("empty env must require GPIO437 SafeOff on planned stop");
    }
    if !s19k_track1_planned_stop_safeoff_from_env(Some("1"))? {
        return Err("DCENT_S19K_TRACK1_STOP_SAFEOFF=1 must request SafeOff");
    }
    if s19k_track1_planned_stop_safeoff_from_env(Some("true")).is_ok() {
        return Err("non-1 tokens must be refused");
    }
    Ok(())
}

/// Production operator-stop must call the reset-before-cut helper. No env-only
/// rail-retention escape hatch exists.
pub fn admit_s19k_production_planned_stop_is_fail_closed(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_maybe_planned_stop_safeoff") {
        return Err("operator-stop must call Track-1 planned-stop helper");
    }
    if !src.contains(S19K_TRACK1_STOP_SAFEOFF_ENV) {
        return Err("planned-stop SafeOff must preserve the explicit runner marker");
    }
    if !src.contains("Ok(true) => s19k_track1_terminal_safeoff()") {
        return Err("planned stop must use checked reset-before-cut SafeOff");
    }
    if src.contains("planned stop leaves GPIO437 engaged") {
        return Err("planned stop must not retain rails without a typed live owner");
    }
    Ok(())
}

/// Track-1 passthrough: GPIO437 must remain engaged (value 0) across the
/// daemon-owned exact stock-process handoff; S99 stop is never this handoff.
pub fn passthrough_must_keep_gpio437_engaged(observed: u8) -> Result<(), &'static str> {
    if observed != S19K_AM3_GPIO437_VALUE_ON {
        return Err(
            "Track-1 passthrough: GPIO437 is not engaged (want 0). S99 stop drives 1=OFF; exact daemon-owned handoff is unavailable",
        );
    }
    Ok(())
}

/// HB reset intended values. Do **not** pulse on passthrough.
pub fn intended_hb_reset_released() -> u8 {
    1
}
pub fn intended_hb_reset_asserted() -> u8 {
    0
}

/// One `a lab unit` `gpio.timeline` sample. Does not write sysfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kGpioTimelineSample {
    pub gpio437: u8,
    pub plugs: [u8; 3],
    pub hb_reset: [u8; 3],
}

pub fn parse_s19k_gpio_timeline_line(line: &str) -> Option<S19kGpioTimelineSample> {
    fn bit(line: &str, key: &str) -> Option<u8> {
        let token = line.split_whitespace().find(|t| t.starts_with(key))?;
        let v = token.rsplit('=').next()?;
        match v.chars().next()? {
            '0' => Some(0),
            '1' => Some(1),
            _ => None,
        }
    }
    Some(S19kGpioTimelineSample {
        gpio437: bit(line, "g437=")?,
        plugs: [
            bit(line, "g439=")?,
            bit(line, "g440=")?,
            bit(line, "g441=")?,
        ],
        hb_reset: [
            bit(line, "g454=")?,
            bit(line, "g455=")?,
            bit(line, "g456=")?,
        ],
    })
}

/// `a lab unit` 2025-12-04 init: GPIO437 starts DISABLE, later ENGAGE; three plugs.
pub fn classify_s19k_78_gpio_timeline(lines: &[&str]) -> Result<(), &'static str> {
    let samples: Vec<_> = lines
        .iter()
        .filter_map(|l| parse_s19k_gpio_timeline_line(l))
        .collect();
    if samples.len() < 2 {
        return Err("gpio.timeline needs at least two parseable samples");
    }
    if samples[0].gpio437 != S19K_AM3_GPIO437_VALUE_OFF {
        return Err(".78 timeline must start GPIO437=1 (PSU Disable)");
    }
    if !samples
        .iter()
        .any(|s| s.gpio437 == S19K_AM3_GPIO437_VALUE_ON)
    {
        return Err(".78 timeline never shows GPIO437=0 (PSU Enable)");
    }
    if !samples.iter().any(|s| s.plugs == [1, 1, 1]) {
        return Err(".78 timeline never shows all three plugs present");
    }
    Ok(())
}

pub fn passthrough_must_not_pulse_hb_reset() -> Result<(), &'static str> {
    Err("Track-1 passthrough: do not pulse GPIO 454/455/456; bosminer already released reset")
}

/// `a lab unit` `gpio.timeline`: GPIO 454/455/456 move as one trio.
/// First GPIO437=0 still has reset asserted. Not DMM rail proof.
pub fn admit_s19k_78_gpio_timeline_hb_reset_ganged_after_psu(
    lines: &[&str],
) -> Result<(), &'static str> {
    let samples: Vec<_> = lines
        .iter()
        .filter_map(|l| parse_s19k_gpio_timeline_line(l))
        .collect();
    if samples.len() < 2 {
        return Err("gpio.timeline needs at least two parseable samples");
    }
    if samples
        .iter()
        .any(|s| s.hb_reset[0] != s.hb_reset[1] || s.hb_reset[1] != s.hb_reset[2])
    {
        return Err(".78 gpio.timeline HB reset 454/455/456 must stay ganged");
    }
    let first_on = samples
        .iter()
        .find(|s| s.gpio437 == S19K_AM3_GPIO437_VALUE_ON)
        .ok_or(".78 timeline never shows GPIO437=0")?;
    if first_on.hb_reset != [0, 0, 0] {
        return Err("first GPIO437=0 still has HB reset asserted (454/455/456=0)");
    }
    if !samples
        .iter()
        .any(|s| s.gpio437 == S19K_AM3_GPIO437_VALUE_ON && s.hb_reset == [1, 1, 1])
    {
        return Err(".78 timeline must later release HB reset as a ganged 1/1/1");
    }
    Ok(())
}

pub fn refuse_s19k_78_first_psu_engage_as_hb_reset_released() -> Result<(), &'static str> {
    Err("first GPIO437=0 is not HB-reset released; .78 line 58 is still 454/455/456=0")
}

pub fn refuse_s19k_78_per_chain_reset_as_bosminer_observed() -> Result<(), &'static str> {
    Err(".78 bosminer gpio.timeline never splits GPIO 454/455/456; not per-chain reset")
}

pub fn refuse_s19k_78_gpio_timeline_as_dmm_rail() -> Result<(), &'static str> {
    Err("gpio.timeline is sysfs sequencing, not a DMM rail measurement")
}

/// S21 Braiins S37 exports gpio437 as `high`. `a lab unit` S37 does not export 437.
pub fn refuse_s21_s37_437_high_export_as_78_s37(s21: &str, s78: &str) -> Result<(), &'static str> {
    if s21.contains("echo 437") && s21.contains("gpio437") && !s78.contains("echo 437") {
        return Err("S21 S37 exports gpio437 high; .78 S37 does not export 437 (bosminer gpiod)");
    }
    Ok(())
}

/// VNish S19k AML `etc/init.d/S11board` labels this pin `pwr_en` and writes 1
/// at `start`. Electrical rail confirmation stays EXPERIMENTAL.
pub const VNISH_S19K_AML_S11_PWR_EN_BOOT_VALUE: u8 = 1;

/// VNish `start` writes 1. That matches DCENT am3-s19k **software** SafeOff
/// and also matches HAL S21/VNish **ON** on a different SKU. Not DMM proof.
pub fn refuse_vnish_s11_start_as_electrical_safeoff() -> Result<(), &'static str> {
    Err("VNish S11 echo 1 is not DMM SafeOff; HAL S21/VNish start pattern is ON on other SKUs")
}

/// Admit the extracted VNish S19k AML S11board boot write is sysfs 1.
pub fn admit_vnish_s19k_s11_pwr_en_boot_is_safeoff(s11: &str) -> Result<(), &'static str> {
    if !s11.contains("# pwr_en 437") {
        return Err("not the extracted VNish S19k AML S11board");
    }
    if !s11.contains("echo 1 > /sys/class/gpio/gpio437/value") {
        return Err("VNish S11board must write 1 to gpio437 at start");
    }
    if VNISH_S19K_AML_S11_PWR_EN_BOOT_VALUE != S19K_AM3_GPIO437_VALUE_OFF {
        return Err("VNish boot write is not DCENT am3-s19k SafeOff");
    }
    Ok(())
}

/// VNish `stop)` is empty. DCENT crash/shutdown must still drive 1.
pub fn refuse_vnish_s11_empty_stop_as_dcent_shutdown() -> Result<(), &'static str> {
    Err("VNish S11board stop is empty; DCENT shutdown/crash must still drive gpio437=1")
}

/// VNish S11 exports 454-456 as out and never writes them. DCENT S37
/// asserts active-LOW reset (`configure_output_low_gpio`) at boot.
pub fn refuse_vnish_s11_uninitialized_hb_reset_as_dcent(s11: &str) -> Result<(), &'static str> {
    if !s11.contains("ch0_rst 454") || !s11.contains("ch2_rst 456") {
        return Err("not the extracted VNish S11board reset block");
    }
    if s11.contains("echo 0 > /sys/class/gpio/gpio454/value")
        || s11.contains("echo 1 > /sys/class/gpio/gpio454/value")
    {
        return Err("VNish S11 unexpectedly writes HB reset; re-check extract");
    }
    Err(
        "VNish S11board leaves GPIO 454-456 undriven; DCENT S37 must assert active-LOW reset at boot",
    )
}

/// DCENT S37 boot holds hashboards in reset until the runtime owner admits them.
pub fn admit_dcent_s37_asserts_hb_reset_at_boot(s37: &str) -> Result<(), &'static str> {
    if !s37.contains("for GPIO in 454 455 456") {
        return Err("DCENT S37 missing HB reset GPIO loop");
    }
    if !s37.contains("configure_output_low_gpio") {
        return Err("DCENT S37 must drive 454-456 low (assert reset) at boot");
    }
    if !s37.contains("Hold hashboards in reset") {
        return Err("DCENT S37 comment must keep reset-hold intent");
    }
    Ok(())
}

/// "checked low" is S21 SafeOff polarity. On am3-s19k, sysfs 0 ENGAGES the rail.
pub fn refuse_checked_low_as_am3_s19k_safeoff_wording(src: &str) -> Result<(), &'static str> {
    if src.contains("GPIO437 is checked low") || src.contains("power is checked low") {
        return Err(
            "am3-s19k SafeOff is sysfs 1; 'checked low' is S21 polarity and would engage PWR_CONTROL",
        );
    }
    Ok(())
}

/// Production crash/shutdown copy must stay polarity-neutral or am3-s19k 1=OFF.
pub fn admit_s19k_production_safeoff_wording(src: &str) -> Result<(), &'static str> {
    refuse_checked_low_as_am3_s19k_safeoff_wording(src)?;
    if !src.contains("checked SafeOff") {
        return Err("production NoPic SafeOff copy must say checked SafeOff, not checked low");
    }
    Ok(())
}

/// Refuse applying this pin to a non-s19k board_target.
pub fn admit_s19k_am3_gpio437_board_target(board_target: &str) -> Result<(), &'static str> {
    if board_target == S19K_AM3_BOARD_TARGET
        || board_target == "am3-s19kpro"
        || board_target == "am3-aml-s19k"
    {
        return Ok(());
    }
    Err("GPIO437 active-LOW PWR_CONTROL pin is am3-s19k scoped; do not apply to S21 NoPic")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn am3_s19k_active_low_0_is_on() {
        assert!(S19K_AM3_GPIO437_ACTIVE_LOW);
        assert_eq!(S19K_AM3_GPIO437_VALUE_ON, 0);
        assert_eq!(S19K_AM3_GPIO437_VALUE_OFF, 1);
        assert!(s19k_am3_gpio437_is_engaged(0));
        assert!(!s19k_am3_gpio437_is_engaged(1));
        assert_eq!(
            classify_s19k_am3_gpio437(Some(0)),
            S19kAm3Gpio437Rail::Engaged
        );
        assert_eq!(
            classify_s19k_am3_gpio437(Some(1)),
            S19kAm3Gpio437Rail::DisabledOrCooldown
        );
        assert_eq!(classify_s19k_am3_gpio437(None), S19kAm3Gpio437Rail::Unknown);
        assert!(admit_s19k_am3_gpio437_board_target("am3-s19k").is_ok());
        assert!(admit_s19k_am3_gpio437_board_target("am3-s21").is_err());
        assert!(admit_s19k_am3_gpio437_board_target("am3-bb").is_err());
        assert_eq!(S19K_AM3_HB_RESET_GPIOS, [454, 455, 456]);
        assert!(S19K_AM3_HB_RESET_ACTIVE_LOW);
        assert_eq!(GPIO437_SYSFS_VALUE, "/sys/class/gpio/gpio437/value");
        assert_eq!(S19K_AM3_PWR_CONTROL_DT_NAME, "PWR_CONTROL");
        assert_eq!(S19K_AM3_PWR_CONTROL_LEGACY_GLOBAL, 437);
        assert_eq!(s19k_am3_pwr_control_sysfs_n(Some(437)).unwrap(), 437);
        assert_eq!(s19k_am3_pwr_control_sysfs_n(Some(500)).unwrap(), 500);
        assert!(s19k_am3_pwr_control_sysfs_n(None).is_err());
        let hal = include_str!("../../dcentrald-hal/src/platform/amlogic/mod.rs");
        assert!(admit_s19k_hal_resolves_pwr_control_before_sysfs(hal).is_ok());
        assert!(admit_amlogic_retained_power_owner_freezes_profile_polarity(hal).is_ok());
        assert!(admit_s19k_hal_resolves_plug_reset_by_name(hal).is_ok());
        assert_eq!(S19K_AM3_PLUG_DT_NAMES, ["CH0_PLUG", "CH1_PLUG", "CH2_PLUG"]);
        assert_eq!(
            S19K_AM3_RESET_DT_NAMES,
            ["HB0_RESET", "HB1_RESET", "HB2_RESET"]
        );
        assert!(s19k_am3_plug_sysfs_n(0, Some(439)).is_ok());
        assert!(s19k_am3_plug_sysfs_n(0, None).is_err());
        assert!(s19k_am3_plug_sysfs_n(3, Some(442)).is_err());
        assert!(s19k_am3_reset_sysfs_n(0, Some(454)).is_ok());
        assert!(s19k_am3_reset_sysfs_n(0, None).is_err());
        assert!(s19k_am3_reset_sysfs_n(3, Some(457)).is_err());
        assert!(admit_s19k_hal_resolves_fan_tach_by_name(hal).is_ok());
        assert_eq!(
            S19K_AM3_FAN_TACH_DT_NAMES,
            [
                "FAN_FRONT_SPEED0",
                "FAN_FRONT_SPEED1",
                "FAN_REAR_SPEED0",
                "FAN_REAR_SPEED1"
            ]
        );
        assert_eq!(S19K_AM3_FAN_TACH_GPIOS, [447, 448, 449, 450]);
        assert!(s19k_am3_fan_tach_sysfs_n(0, Some(447)).is_ok());
        assert!(s19k_am3_fan_tach_sysfs_n(0, None).is_err());
        assert!(s19k_am3_fan_tach_sysfs_n(4, Some(451)).is_err());
        assert!(admit_s19k_hal_resolves_led_and_pinmux_by_name(hal).is_ok());
        assert_eq!(S19K_AM3_LED_RED_DT_NAME, "LED_RED");
        assert_eq!(S19K_AM3_LED_GREEN_DT_NAME, "LED_GREEN");
        assert_eq!(S19K_AM3_I2C_SCL_DT_NAME, "I2C_SCL");
        assert_eq!(S19K_AM3_I2C_SDA_DT_NAME, "I2C_SDA");
        assert_eq!(S19K_AM3_LED_RED_LEGACY_GLOBAL, 438);
        assert_eq!(S19K_AM3_LED_GREEN_LEGACY_GLOBAL, 453);
        assert_eq!(S19K_AM3_I2C_SCL_LEGACY_GLOBAL, 476);
        assert_eq!(S19K_AM3_I2C_SDA_LEGACY_GLOBAL, 477);
        assert!(s19k_am3_led_sysfs_n(Some(438)).is_ok());
        assert!(s19k_am3_led_sysfs_n(None).is_err());
        assert!(s19k_am3_pinmux_sysfs_n(Some(476)).is_ok());
        assert!(s19k_am3_pinmux_sysfs_n(None).is_err());
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(!serial.contains("write_amlogic_status_led"));
        assert!(refuse_hb0_plug_as_amlogic_primary("CH0_PLUG").is_ok());
        assert!(refuse_hb0_plug_as_amlogic_primary("HB0_PLUG").is_err());
        assert!(refuse_hb3_reset_as_s19k_fourth_board("HB2_RESET").is_ok());
        assert!(refuse_hb3_reset_as_s19k_fourth_board("HB3_RESET").is_err());
        assert_eq!(
            intended_gpio437_value(S19kAm3Gpio437Phase::MiningOrHandoffEngaged),
            Some(0)
        );
        assert_eq!(
            intended_gpio437_value(S19kAm3Gpio437Phase::ShutdownSafeOff),
            Some(1)
        );
        assert!(refuse_re4c_safe_off_as_am3_s19k_cut(0).is_err());
        assert!(refuse_re4c_safe_off_as_am3_s19k_cut(1).is_ok());
        assert_eq!(am3_s19k_install_safe_off_value(), 1);
        assert!(passthrough_must_keep_gpio437_engaged(0).is_ok());
        assert!(passthrough_must_keep_gpio437_engaged(1).is_err());
        assert!(admit_s19k_crash_teardown_safeoff_value().is_ok());
        let hal = include_str!("../../dcentrald-hal/src/platform/amlogic/mod.rs");
        assert!(admit_s19k_disable_psu_checked_exports_before_write(hal).is_ok());
        assert!(admit_s19k_disable_psu_checked_exports_before_write(
            "pub fn disable_psu_checked() {\n    fs::write(&gpio_path, \"1\")\n}\npub fn disable_psu() {}"
        )
        .is_err());
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_track1_mining_on_does_not_write_gpio437(serial).is_ok());
        assert!(admit_s19k_track1_does_not_pulse_hb_reset(serial).is_ok());
        assert!(admit_s19k_track1_does_not_pulse_hb_reset(
            "PASSTHROUGH BM1366\nset_board_reset(\n} else if passthrough {"
        )
        .is_err());
        assert!(admit_s19k_track1_preflight_resolves_plug_psu(serial).is_ok());
        assert!(admit_s19k_track1_preflight_resolves_plug_psu(
            "PASSTHROUGH BM1366\ns19k_plug_sysfs_paths()\n} else if passthrough {"
        )
        .is_err());
        assert!(admit_s19k_track1_preflight_resolves_plug_psu(
            "PASSTHROUGH BM1366\n/sys/class/gpio/gpio437/value\n} else if passthrough {"
        )
        .is_err());
        assert!(admit_s19k_track1_arms_teardown_without_enable(serial).is_ok());
        assert!(admit_s19k_track1_arms_watchdog_without_enable(serial).is_ok());
        assert!(admit_s19k_track1_arms_watchdog_without_enable(
            "arm_s19k_track1_teardown();\nprepare_enable(\nenable_psu(\n} else if passthrough {"
        )
        .is_err());
        assert!(admit_s19k_track1_planned_stop_default_is_safeoff().is_ok());
        assert!(admit_s19k_production_planned_stop_is_fail_closed(serial).is_ok());
        assert!(s19k_track1_planned_stop_safeoff_from_env(None).unwrap());
        assert!(s19k_track1_planned_stop_safeoff_from_env(Some("")).unwrap());
        assert!(s19k_track1_planned_stop_safeoff_from_env(Some("1")).unwrap());
        assert_eq!(
            s19k_nopic_panic_fan_action(true, true, false),
            S19kNoPicPanicFanAction::CoastAfterCheckedCut
        );
        assert_eq!(
            s19k_nopic_panic_fan_action(true, false, true),
            S19kNoPicPanicFanAction::RetainTrack1ExplicitPwm100
        );
        assert_eq!(
            s19k_nopic_panic_fan_action(true, false, false),
            S19kNoPicPanicFanAction::HoldTrack1HomeCap
        );
        assert_eq!(
            s19k_nopic_panic_fan_action(false, false, false),
            S19kNoPicPanicFanAction::LeaveUnchanged
        );
        let panic_start = serial
            .find("pub fn nopic_panic_hook_best_effort_teardown()")
            .expect("NoPic panic hook");
        let panic_end = serial[panic_start..]
            .find("trait Am2FirstStagePowerCut")
            .map(|offset| panic_start + offset)
            .expect("NoPic panic hook end");
        let panic_hook = &serial[panic_start..panic_end];
        assert!(
            panic_hook
                .find("assert_s19k_native_all_resets_checked")
                .unwrap()
                < panic_hook.find("disable_s19k_track1_psu_checked").unwrap(),
        );
        assert!(panic_hook.contains("let track1_armed"));
        assert!(panic_hook.contains("native_armed || track1_armed"));
        assert!(panic_hook.contains("S19kNoPicPanicFanAction::RetainTrack1ExplicitPwm100"));
        assert!(panic_hook.contains("S19kNoPicPanicFanAction::HoldTrack1HomeCap"));
        assert!(panic_hook.contains("hold_track1_leftover_fans_pwm100(true)"));
        assert!(!panic_hook.contains("disable_psu();"));
        let planned_start = serial
            .find("fn s19k_track1_maybe_planned_stop_safeoff() -> Result<()>")
            .expect("planned-stop helper");
        let planned_end = serial[planned_start..]
            .find("struct Track1HostBaudRestore")
            .map(|offset| planned_start + offset)
            .expect("planned-stop helper end");
        let planned = &serial[planned_start..planned_end];
        assert!(planned.contains("Ok(true) => s19k_track1_terminal_safeoff()"));
        assert!(!planned.contains("disable_psu_checked"));
        let safeoff_start = serial
            .find("fn s19k_track1_reset_then_cut_checked()")
            .expect("Track-1 reset+cut SafeOff");
        let safeoff_end = serial[safeoff_start..]
            .find("pub(crate) fn s19k_track1_recovery_safeoff(")
            .map(|offset| safeoff_start + offset)
            .expect("Track-1 reset+cut SafeOff end");
        let safeoff = &serial[safeoff_start..safeoff_end];
        assert!(safeoff.contains("disable_s19k_track1_psu_checked"));
        assert!(!safeoff.contains("disable_psu_checked()"));
        assert!(serial.contains("s19k_track1_reset_then_cut_checked().map(|_| ())"));
        assert!(serial.contains("impl Drop for S19kTrack1RunCloseoutGuard"));
        assert!(serial.contains("S19kTrack1RunCloseoutGuard::prepare("));
        let track1 = serial
            .split("pub async fn run(&mut self) -> Result<()> {")
            .nth(1)
            .expect("Track-1 runtime arm");
        assert!(
            track1.find("S19kTrack1RunCloseoutGuard::prepare(").unwrap()
                < track1.find("let nopic = is_nopic(&self.config)?;").unwrap()
        );
        assert!(
            track1.find("S19kTrack1RunCloseoutGuard::prepare(").unwrap()
                < track1
                    .find("SerialChainBackend::open_passthrough_bm1366")
                    .unwrap()
        );
        assert!(track1.contains("self.explicit_loud_fan_authority"));
        assert!(track1.contains("requires explicit --allow-loud authority"));
        assert!(track1.contains("WatchdogAdmission::Armed(receipt) => receipt"));
        assert!(track1.contains("nopic_watchdog = Some(watchdog_owner);"));
        assert!(track1.contains("expected.open_both_signal_leases_checked()?"));
        assert!(track1.contains(".assume_inherited_rails()"));
        assert!(track1.contains("S19kStockProcessRole::Supervisor"));
        assert!(track1.contains("S19kStockProcessRole::Bosminer"));
        let main = include_str!("../../dcentrald/src/main.rs");
        assert!(main.contains(
            "let explicit_loud_fan_authority = args.iter().any(|a| a == \"--allow-loud\");"
        ));
        assert!(main.contains("explicit_loud_fan_authority,"));
        assert!(serial.contains("if terminal_result.is_ok()"));
        assert!(serial.contains("guard.disarm();"));
        assert!(admit_s19k_track1_mining_on_does_not_write_gpio437(
            "PASSTHROUGH BM1366\ndisable_psu_checked()\n} else if passthrough {"
        )
        .is_err());
        assert_eq!(intended_hb_reset_released(), 1);
        assert_eq!(intended_hb_reset_asserted(), 0);
        assert_eq!(S19K_AM3_PLUG_GPIOS, [439, 440, 441]);
        assert_eq!(s19k_am3_plug_present(Some(1)), Some(true));
        assert_eq!(s19k_am3_plug_present(Some(0)), Some(false));
        assert_eq!(s19k_am3_plug_present(None), None);
        assert_eq!(s19k_am3_plug_present_count([Some(1), Some(0), Some(1)]), 2);
        assert_eq!(s19k_am3_plug_present_count([None, None, None]), 0);
        let cold = "1777484698.%N g437=1 g438=0 g439=1 g440=1 g441=1 g447=0 g448=0 g449=0 g450=0 g453=1 g454=0 g455=0 g456=0";
        let hot = "1777484731.%N g437=0 g438=1 g439=1 g440=1 g441=1 g447=0 g448=0 g449=0 g450=1 g453=0 g454=0 g455=0 g456=0";
        let c = parse_s19k_gpio_timeline_line(cold).unwrap();
        let h = parse_s19k_gpio_timeline_line(hot).unwrap();
        assert_eq!(c.gpio437, 1);
        assert_eq!(h.gpio437, 0);
        assert_eq!(c.plugs, [1, 1, 1]);
        assert!(classify_s19k_78_gpio_timeline(&[cold, hot]).is_ok());
        assert!(passthrough_must_not_pulse_hb_reset().is_err());
        let released = "1777484738.%N g437=0 g438=0 g439=1 g440=1 g441=1 g447=1 g448=0 g449=0 g450=0 g453=1 g454=1 g455=1 g456=1";
        assert!(
            admit_s19k_78_gpio_timeline_hb_reset_ganged_after_psu(&[cold, hot, released]).is_ok()
        );
        assert!(admit_s19k_78_gpio_timeline_hb_reset_ganged_after_psu(&[cold, hot]).is_err());
        let split = "1777484738.%N g437=0 g438=0 g439=1 g440=1 g441=1 g447=1 g448=0 g449=0 g450=0 g453=1 g454=1 g455=0 g456=1";
        assert!(
            admit_s19k_78_gpio_timeline_hb_reset_ganged_after_psu(&[cold, hot, split]).is_err()
        );
        assert!(refuse_s19k_78_first_psu_engage_as_hb_reset_released().is_err());
        assert!(refuse_s19k_78_per_chain_reset_as_bosminer_observed().is_err());
        assert!(refuse_s19k_78_gpio_timeline_as_dmm_rail().is_err());
        assert_eq!(
            crate::s19k_bm1366_nopic_beta::S19K_GPIO_PWR_EN_SAFE_OFF_VALUE,
            S19K_AM3_GPIO437_VALUE_OFF
        );
        assert!(refuse_re4c_safe_off_as_am3_s19k_cut(
            crate::s19k_bm1366_nopic_beta::S19K_GPIO_PWR_EN_SAFE_OFF_VALUE
        )
        .is_ok());
        assert!(refuse_re4c_safe_off_as_am3_s19k_cut(0).is_err());
        assert!(refuse_checked_low_as_am3_s19k_safeoff_wording(
            "NoPic GPIO437 is checked low, but management I2C did not close cleanly"
        )
        .is_err());
        assert!(refuse_checked_low_as_am3_s19k_safeoff_wording(
            "NoPic power is checked low, but quiet fan coast-down readback failed"
        )
        .is_err());
        assert!(refuse_checked_low_as_am3_s19k_safeoff_wording(
            "NoPic GPIO437 is at checked SafeOff, but management I2C did not close cleanly"
        )
        .is_ok());
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_safeoff_wording(serial).is_ok());
        let pin_blob = [
            BOSMINER_PWR_CONTROL_LABEL,
            BOSMINER_GPIOCHIP_PREFIX,
            BOSMINER_GPIOD_RS.as_bytes(),
            BOSMINER_GPIO_RS.as_bytes(),
            BOSMINER_OPEN_PIN_OUT,
            BOSMINER_PIN_NAME_NOT_FOUND,
            BOSMINER_HB_RESET_LABELS[0],
            BOSMINER_HB_RESET_LABELS[1],
            BOSMINER_HB_RESET_LABELS[2],
            BOSMINER_HB_RESET_LABELS[3],
        ]
        .concat();
        assert!(admit_bosminer_psu_gpio_is_gpiod_label(&pin_blob).is_ok());
        assert!(admit_bosminer_psu_gpio_is_gpiod_label(b"PWR_CONTROL only").is_err());
        let held_s37 = "function pinmux_init()\n    echo 446 > /sys/class/gpio/export\n    ## CH0_PLUG 439\n    echo 439 > /sys/class/gpio/export\n";
        assert!(refuse_held_braiins_s37_as_gpio437_exporter(held_s37).is_ok());
        assert!(refuse_held_braiins_s37_as_gpio437_exporter(
            "echo 446\nCH0_PLUG\necho 437 > /sys/class/gpio/export\n"
        )
        .is_err());
        assert!(refuse_sysfs_export_437_as_bosminer_open().is_err());
        const VNISH_S11: &str =
            include_str!("../../../");
        assert!(admit_vnish_s19k_s11_pwr_en_boot_is_safeoff(VNISH_S11).is_ok());
        assert!(refuse_vnish_s11_start_as_electrical_safeoff().is_err());
        assert!(refuse_vnish_s11_empty_stop_as_dcent_shutdown().is_err());
        assert_eq!(VNISH_S19K_AML_S11_PWR_EN_BOOT_VALUE, 1);
        assert!(VNISH_S11.contains("ch0_rst 454"));
        assert!(VNISH_S11.contains("ch2_plug 441"));
        assert!(refuse_vnish_s11_uninitialized_hb_reset_as_dcent(VNISH_S11).is_err());
        const DCENT_S37: &str = include_str!(
            "../../../br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S37board_setup"
        );
        assert!(admit_dcent_s37_asserts_hb_reset_at_boot(DCENT_S37).is_ok());
    }

    #[test]
    fn retained_power_owner_rejects_every_post_admission_polarity_reselection() {
        let hal = include_str!("../../dcentrald-hal/src/platform/amlogic/mod.rs");
        assert!(admit_amlogic_retained_power_owner_freezes_profile_polarity(hal).is_ok());

        for (from, to) in [
            ("self.recipe.set(recipe)", "self.recipe.get()"),
            (
                "board_target: profile.board_target(),",
                "board_target: \"am3-s21\",",
            ),
            (
                "disable_psu_checked_for_recipe(self.psu_commit.recipe()?)?",
                "disable_psu_checked()?",
            ),
            ("enable_psu_gpio_for_recipe(recipe)", "enable_psu_gpio()"),
            (
                "amlogic_gpio437::resolve_population_recipe(self.board_target, &names)",
                "amlogic_gpio437::resolve_drive_recipe(self.board_target)",
            ),
            (
                "self.recipe.set(recipe).map_err",
                "self.recipe.set(recipe).or_else",
            ),
            (
                "disable_psu_checked_for_recipe(self.recipe)",
                "disable_psu_checked_for_recipe(amlogic_marker_drive_recipe()?)",
            ),
        ] {
            assert!(hal.contains(from), "missing mutation anchor {from:?}");
            let mutated = hal.replacen(from, to, 1);
            assert!(
                admit_amlogic_retained_power_owner_freezes_profile_polarity(&mutated).is_err(),
                "retained-polarity gate accepted mutation {from:?} -> {to:?}"
            );
        }
    }

    #[test]
    fn recipe_writer_refuses_missing_export_inversion_off_and_readback_steps() {
        let hal = include_str!("../../dcentrald-hal/src/platform/amlogic/mod.rs");
        for needle in [
            "write(&gpio_root.join(\"export\"), &n.to_string())",
            "write(&base.join(\"direction\"), \"in\")",
            "read_psu_active_low_disabled_checked_at(gpio_root, n)?",
            "write(&base.join(\"direction\"), recipe.off_direction())",
            "read_psu_enabled_on_with_recipe_at(gpio_root, n, recipe)? != on",
        ] {
            assert!(hal.contains(needle), "missing mutation anchor {needle:?}");
            assert!(
                admit_s19k_disable_psu_checked_exports_before_write(&hal.replacen(
                    needle,
                    "removed_recipe_guard",
                    1
                ))
                .is_err(),
                "recipe writer accepted missing {needle:?}"
            );
        }
        let recipe = crate::amlogic_gpio437::resolve_population_recipe(
            "am3-s19k",
            &["BHB56902", "BHB56903"],
        )
        .unwrap();
        assert_eq!(
            (recipe.on_raw(), recipe.off_raw(), recipe.off_direction()),
            (0, 1, "high")
        );
        assert!(
            crate::amlogic_gpio437::resolve_population_recipe("am3-s19k", &["BHB42601"]).is_err()
        );
        assert!(
            crate::amlogic_gpio437::resolve_population_recipe("am3-bb", &["BHB56902"]).is_err()
        );
    }

    #[test]
    fn track1_watchdog_contract_revalidates_before_inherited_rail_closeout_arm() {
        fn source(sequence: &str) -> String {
            format!(
                "pub async fn run(&mut self) -> Result<()> {{\n\
                 let guard = S19kTrack1RunCloseoutGuard::prepare(authority);\n\
                 {sequence}\n\
                 let mut s19k_active_tx_paths = Vec::new();\n\
                 }}\n\
                 fn s19k_track1_mark_watchdog_liveness() {{}}"
            )
        }

        let watchdog = "let watchdog_start = SafetyWatchdogOwner::start_before_energizing();\n\
                        let (mut watchdog_owner, admission) = watchdog_start;\n\
                        let receipt = match admission { WatchdogAdmission::Armed(receipt) => receipt };\n\
                        requested_timeout_s = receipt.requested_timeout_s;\n\
                        effective_timeout_s = receipt.effective_timeout_s;";
        let revalidate = "let immediate = s19k_capture_and_require_bound_live_identity();\n\
                          expected.require_exact_tree_at(Path::new(\"/proc\"))?;\n\
                          S19k Track-1 refuses stock handoff because GPIO437 changed before SIGKILL;\n\
                          nopic_watchdog = Some(watchdog_owner);";
        let arm_and_kill = ".assume_inherited_rails();\n\
                            j3_lease.sigkill_and_wait(";

        let admitted = source(&format!("{watchdog}\n{revalidate}\n{arm_and_kill}"));
        assert!(admit_s19k_track1_arms_watchdog_without_enable(&admitted).is_ok());

        let stale_post_arm_revalidation =
            source(&format!("{watchdog}\n{arm_and_kill}\n{revalidate}"));
        assert!(
            admit_s19k_track1_arms_watchdog_without_enable(&stale_post_arm_revalidation).is_err()
        );

        let missing_positive = admitted.replace(
            "WatchdogAdmission::Armed(receipt) => receipt",
            "WatchdogAdmission::DisabledByConfiguration => receipt",
        );
        assert!(admit_s19k_track1_arms_watchdog_without_enable(&missing_positive).is_err());

        let missing_gpio_revalidation = admitted.replace(
            "S19k Track-1 refuses stock handoff because GPIO437 changed before SIGKILL",
            "GPIO observation omitted",
        );
        assert!(
            admit_s19k_track1_arms_watchdog_without_enable(&missing_gpio_revalidation).is_err()
        );
    }

    #[test]
    fn s19k_gpio_timeline_hb_reset_ganged_after_psu() {
        let cold = "1777484698.%N g437=1 g438=0 g439=1 g440=1 g441=1 g447=0 g448=0 g449=0 g450=0 g453=1 g454=0 g455=0 g456=0";
        let first_on = "1777484731.%N g437=0 g438=1 g439=1 g440=1 g441=1 g447=0 g448=0 g449=0 g450=1 g453=0 g454=0 g455=0 g456=0";
        let released = "1777484738.%N g437=0 g438=0 g439=1 g440=1 g441=1 g447=1 g448=0 g449=0 g450=0 g453=1 g454=1 g455=1 g456=1";
        assert!(
            admit_s19k_78_gpio_timeline_hb_reset_ganged_after_psu(&[cold, first_on, released])
                .is_ok()
        );
        assert!(admit_s19k_78_gpio_timeline_hb_reset_ganged_after_psu(&[cold, first_on]).is_err());
        assert!(refuse_s19k_78_first_psu_engage_as_hb_reset_released().is_err());
        assert!(refuse_s19k_78_per_chain_reset_as_bosminer_observed().is_err());
        assert!(refuse_s19k_78_gpio_timeline_as_dmm_rail().is_err());
        const S21_S37: &str = include_str!(
            "../../../../../"
        );
        const S78_S37: &str = include_str!(
            "../../../../../"
        );
        assert!(refuse_s21_s37_437_high_export_as_78_s37(S21_S37, S78_S37).is_err());
        assert!(S21_S37.contains("echo 437"));
        assert!(!S78_S37.contains("echo 437"));
    }
}
