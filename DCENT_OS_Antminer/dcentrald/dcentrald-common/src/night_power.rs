//! Night-hour power-target and fan-PWM reduction.
//!
//! Shared by the thermal loop, serial Amlogic/AM2 fan ticks, heater helper,
//! and the autotuner Power-mode setpoint. Pure: no clock, no HAL. Callers
//! inject the local hour.

/// Home-safety night fan ceiling. Same as `PWM_SAFETY_MAX` / PWM-30.
pub const NIGHT_FAN_PWM_SAFETY_CAP: u8 = 30;

/// One night-quiet window (home or thermal). Decrease-only: a cap, never a raise.
///
/// `max_frequency_mhz == 0` means this window does not contribute a frequency
/// ceiling (fan-only). POST / the daemon seed `with_max_frequency` for live
/// QuietMode adoption on the same watch as fan PWM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NightFanWindow {
    pub enabled: bool,
    pub start_hour: u8,
    pub end_hour: u8,
    pub max_fan_pwm: u8,
    pub max_frequency_mhz: u16,
    pub power_reduction_pct: u8,
}

impl NightFanWindow {
    pub fn new(enabled: bool, start_hour: u8, end_hour: u8, max_fan_pwm: u8) -> Self {
        Self {
            enabled,
            start_hour,
            end_hour,
            max_fan_pwm,
            max_frequency_mhz: 0,
            power_reduction_pct: 0,
        }
    }

    pub fn with_max_frequency(mut self, max_frequency_mhz: u16) -> Self {
        self.max_frequency_mhz = max_frequency_mhz;
        self
    }

    pub fn with_power_reduction(mut self, power_reduction_pct: u8) -> Self {
        self.power_reduction_pct = power_reduction_pct.min(100);
        self
    }
}

/// Whether `hour` (0..=23) sits inside `[start, end)` on a 24h clock.
/// `start > end` wraps midnight (e.g. 22 → 7).
pub fn night_hours_active(hour: u8, start_hour: u8, end_hour: u8) -> bool {
    let hour = hour.min(23);
    let start = start_hour.min(23);
    let end = end_hour.min(23);
    if start <= end {
        hour >= start && hour < end
    } else {
        hour >= start || hour < end
    }
}

/// Local wall-clock hour from Unix seconds and a whole-hour UTC offset.
pub fn local_hour_from_unix_secs(unix_secs: u64, timezone_offset_hours: i8) -> u8 {
    let offset_secs = i64::from(timezone_offset_hours) * 3600;
    let local_secs = (unix_secs as i64 + offset_secs).rem_euclid(86400) as u64;
    (local_secs / 3600) as u8
}

/// Cut `target_watts` by `reduction_pct` when `in_night` is true.
pub fn night_adjusted_watts(target_watts: u32, in_night: bool, reduction_pct: u8) -> u32 {
    if !in_night {
        return target_watts;
    }
    let reduction = target_watts.saturating_mul(u32::from(reduction_pct.min(100))) / 100;
    target_watts.saturating_sub(reduction)
}

/// Night fan PWM cap for one window, or `None` if that window is idle.
/// Always clamped to `safety_cap` (home PWM-30).
pub fn night_fan_pwm_cap(window: NightFanWindow, local_hour: u8, safety_cap: u8) -> Option<u8> {
    if window.enabled && night_hours_active(local_hour, window.start_hour, window.end_hour) {
        Some(window.max_fan_pwm.min(safety_cap))
    } else {
        None
    }
}

/// Most-restrictive live night fan ceiling from thermal + home windows.
///
/// The daemon `SetFanPwm` path and serial Amlogic/AM2 live fan commands
/// must call this. Home `[mode.home.night_mode]` is a first-class cap, not
/// ignored in favor of `thermal.night_mode` alone.
pub fn effective_night_fan_pwm(
    thermal: NightFanWindow,
    home: NightFanWindow,
    local_hour: u8,
    safety_cap: u8,
) -> Option<u8> {
    match (
        night_fan_pwm_cap(thermal, local_hour, safety_cap),
        night_fan_pwm_cap(home, local_hour, safety_cap),
    ) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

/// Apply a night fan cap to a commanded PWM. Never raises PWM.
pub fn apply_night_fan_pwm(commanded_pwm: u8, night_cap: Option<u8>) -> u8 {
    match night_cap {
        Some(cap) => commanded_pwm.min(cap),
        None => commanded_pwm,
    }
}

/// Night frequency ceiling for one window, or `None` if that window is idle.
/// `max_frequency_mhz == 0` is fan-only (no freq contribution).
pub fn night_frequency_cap(window: NightFanWindow, local_hour: u8) -> Option<u16> {
    if window.enabled
        && window.max_frequency_mhz > 0
        && night_hours_active(local_hour, window.start_hour, window.end_hour)
    {
        Some(window.max_frequency_mhz)
    } else {
        None
    }
}

/// Most-restrictive live night frequency ceiling from thermal + home windows.
///
/// The daemon QuietMode `SetFrequencyLimit` path and serial init PLL target
/// must call this. Home `[mode.home.night_mode].max_frequency_mhz` is a
/// first-class cap, not ignored in favor of `thermal.night_mode` alone.
pub fn effective_night_frequency_mhz(
    thermal: NightFanWindow,
    home: NightFanWindow,
    local_hour: u8,
) -> Option<u16> {
    match (
        night_frequency_cap(thermal, local_hour),
        night_frequency_cap(home, local_hour),
    ) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

/// Apply a night frequency cap to a commanded MHz. Never raises frequency.
pub fn apply_night_frequency_mhz(commanded_mhz: u16, night_cap: Option<u16>) -> u16 {
    match night_cap {
        Some(cap) => commanded_mhz.min(cap),
        None => commanded_mhz,
    }
}

/// QuietMode dispatcher payload: `Some(cap)` only when the night ceiling is
/// below the live nominal. Otherwise clear the QuietMode source (`None`).
pub fn quiet_mode_frequency_limit(nominal_mhz: u16, night_cap: Option<u16>) -> Option<u16> {
    match night_cap {
        Some(cap) if nominal_mhz > cap => Some(cap),
        _ => None,
    }
}

/// Honest serial night-watt adoption: scale nameplate MHz with the same
/// percent helper the tuner uses for watts. Serial has no watt PID — this
/// is a frequency-domain cut, never a `runtimeAdopted=true` tuner claim.
pub fn serial_night_power_frequency_mhz(
    nameplate_mhz: u16,
    window: NightFanWindow,
    local_hour: u8,
) -> u16 {
    let in_night =
        window.enabled && night_hours_active(local_hour, window.start_hour, window.end_hour);
    night_adjusted_watts(
        u32::from(nameplate_mhz),
        in_night,
        window.power_reduction_pct,
    ) as u16
}

/// Live serial PLL snapshot published by `serial_mining`.
/// `adopted_mhz == 0` means not yet published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialLiveFrequency {
    pub adopted_mhz: u16,
    pub nameplate_mhz: u16,
    /// Runtime watt target the serial path was started with
    /// (`[power] target_watts`; `0` = none configured). Published so
    /// GET/POST compute desired night watts from runtime truth — the same
    /// nameplate-vs-config rule the MHz fields follow — not a config re-read.
    /// Publishing it is truth plumbing only: the serial path has no watt
    /// PID and never actuates watts.
    pub nameplate_watts: u32,
    pub thermal: NightFanWindow,
    /// Same offset `serial_adopt_live_night_frequency` uses.
    pub timezone_offset_hours: i8,
}

impl Default for SerialLiveFrequency {
    fn default() -> Self {
        Self {
            adopted_mhz: 0,
            nameplate_mhz: 0,
            nameplate_watts: 0,
            thermal: NightFanWindow::new(false, 0, 0, 0),
            timezone_offset_hours: 0,
        }
    }
}

/// GET/POST honesty for serial vs tuner night-watt adoption.
/// `runtime_adopted` is tuner-only and must stay false on serial.
/// `serial_live_mhz` is last adopted `operating_freq`.
/// `serial_desired_mhz` is what the saved night policy would produce now.
pub fn serial_night_power_read_truth(
    tuner_adopted: bool,
    serial_live_mhz: Option<u16>,
    serial_desired_mhz: Option<u16>,
) -> SerialNightPowerReadTruth {
    SerialNightPowerReadTruth {
        runtime_adopted: tuner_adopted,
        serial_frequency_adopted: serial_live_mhz.is_some(),
        serial_night_power_mhz: serial_live_mhz,
        serial_night_power_desired_mhz: serial_desired_mhz,
        serial_night_power_pending: match (serial_live_mhz, serial_desired_mhz) {
            (Some(adopted), Some(desired)) => adopted != desired,
            _ => false,
        },
        saved_only: !tuner_adopted && serial_live_mhz.is_none(),
    }
}

/// Live serial adopted MHz from the publisher watch. `0` is "not yet
/// published" and must not be reported as an adopted PLL.
pub fn serial_live_mhz_from_watch(published: Option<SerialLiveFrequency>) -> Option<u16> {
    published
        .filter(|snap| snap.adopted_mhz > 0)
        .map(|snap| snap.adopted_mhz)
}

/// Desired serial PLL from nameplate + the saved (or just-POSTed) home
/// window. Uses the same helper as live adopt.
pub fn serial_night_power_desired_mhz(
    nameplate_mhz: u16,
    thermal: NightFanWindow,
    home: NightFanWindow,
    local_hour: u8,
) -> u16 {
    serial_live_night_frequency_mhz(nameplate_mhz, thermal, home, local_hour)
}

/// Desired serial PLL at `unix_secs` using the same timezone offset the
/// serial adopt path already applies. GET/POST must call this — not UTC 0.
pub fn serial_night_power_desired_at(
    nameplate_mhz: u16,
    thermal: NightFanWindow,
    home: NightFanWindow,
    unix_secs: u64,
    timezone_offset_hours: i8,
) -> u16 {
    serial_night_power_desired_mhz(
        nameplate_mhz,
        thermal,
        home,
        local_hour_from_unix_secs(unix_secs, timezone_offset_hours),
    )
}

/// Desired serial night WATTS: the runtime watt nameplate cut by the saved
/// thermal/home windows. Uses the same shared `night_adjusted_watts`
/// percent helper the tuner's `resolve_power_mode_target_watts` applies —
/// no new math — and the more restrictive window wins, mirroring
/// `serial_live_night_frequency_mhz`. No active window leaves the
/// nameplate unchanged. Desired only: the serial path has no watt PID, so
/// nothing actuates this number.
pub fn serial_night_power_desired_watts(
    nameplate_watts: u32,
    thermal: NightFanWindow,
    home: NightFanWindow,
    local_hour: u8,
) -> u32 {
    night_adjusted_watts(
        nameplate_watts,
        thermal.enabled && night_hours_active(local_hour, thermal.start_hour, thermal.end_hour),
        thermal.power_reduction_pct,
    )
    .min(night_adjusted_watts(
        nameplate_watts,
        home.enabled && night_hours_active(local_hour, home.start_hour, home.end_hour),
        home.power_reduction_pct,
    ))
}

/// Desired serial night watts at `unix_secs` using the same timezone offset
/// the serial adopt path already applies (the watt analog of
/// `serial_night_power_desired_at`).
pub fn serial_night_power_desired_watts_at(
    nameplate_watts: u32,
    thermal: NightFanWindow,
    home: NightFanWindow,
    unix_secs: u64,
    timezone_offset_hours: i8,
) -> u32 {
    serial_night_power_desired_watts(
        nameplate_watts,
        thermal,
        home,
        local_hour_from_unix_secs(unix_secs, timezone_offset_hours),
    )
}

/// GET/POST honesty for serial night WATTS.
///
/// Serial has no watt PID and no `autotuner_command_tx` consumer, so
/// `runtime_adopted` is tuner-only and must stay false on serial. A watt
/// sample is reported only when a control-authoritative source
/// (PMBus/ADC/wall-calibrated — the `PowerAuthorityKind::is_control_authoritative`
/// bar) produced it. Estimate-only watts never populate the sample and never
/// flip pending: closing a loop on the controller's own feed-forward is the
/// refused tautology, so estimates publish nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialNightWattReadTruth {
    /// Tuner-only adoption. Always false on the serial path.
    pub runtime_adopted: bool,
    /// Live authoritative wall watts, or `None` when no control-authoritative
    /// watt sample source is reachable (the serial path today).
    pub serial_watt_sample_watts: Option<u32>,
    /// Watts the saved night policy would produce from the runtime nameplate.
    pub serial_night_power_desired_watts: Option<u32>,
    /// `true` only when a live authoritative sample sits ABOVE the desired
    /// night target — the saved cut is not yet reflected in measured watts.
    /// A missing sample can never be pending (nothing was measured).
    pub serial_night_power_pending: bool,
    /// No tuner adoption and no authoritative sample: the saved policy is
    /// published as desired watts only — watts stay saved-only on serial.
    pub saved_only: bool,
}

/// Watt-domain analog of `serial_night_power_read_truth`.
pub fn serial_night_watt_read_truth(
    tuner_adopted: bool,
    authoritative_sample_watts: Option<u32>,
    desired_watts: Option<u32>,
) -> SerialNightWattReadTruth {
    SerialNightWattReadTruth {
        runtime_adopted: tuner_adopted,
        serial_watt_sample_watts: authoritative_sample_watts,
        serial_night_power_desired_watts: desired_watts,
        serial_night_power_pending: match (authoritative_sample_watts, desired_watts) {
            (Some(sample), Some(desired)) => sample > desired,
            _ => false,
        },
        saved_only: !tuner_adopted && authoritative_sample_watts.is_none(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialNightPowerReadTruth {
    pub runtime_adopted: bool,
    pub serial_frequency_adopted: bool,
    pub serial_night_power_mhz: Option<u16>,
    pub serial_night_power_desired_mhz: Option<u16>,
    pub serial_night_power_pending: bool,
    pub saved_only: bool,
}

/// Serial init/mid-run PLL target: night frequency ceiling plus the
/// honest home watt-percent scale. Never above nameplate.
pub fn serial_live_night_frequency_mhz(
    commanded_mhz: u16,
    thermal: NightFanWindow,
    home: NightFanWindow,
    local_hour: u8,
) -> u16 {
    let freq_capped = apply_night_frequency_mhz(
        commanded_mhz,
        effective_night_frequency_mhz(thermal, home, local_hour),
    );
    let watt_capped = serial_night_power_frequency_mhz(commanded_mhz, thermal, local_hour).min(
        serial_night_power_frequency_mhz(commanded_mhz, home, local_hour),
    );
    freq_capped.min(watt_capped)
}

/// Mid-run serial night frequency step. `Some(next)` only when the night
/// ceiling is strictly below `live_mhz` (decrease-only; never a raise).
pub fn serial_midrun_night_frequency_step(
    live_mhz: u16,
    thermal: NightFanWindow,
    home: NightFanWindow,
    local_hour: u8,
) -> Option<u16> {
    let next = serial_live_night_frequency_mhz(live_mhz, thermal, home, local_hour);
    (next < live_mhz).then_some(next)
}

/// Mid-run serial PLL target against configured nameplate.
///
/// Night (or the tighter live ceiling) steps down from `live_mhz`. When the
/// home-night window ends or is disabled, steps back toward `nameplate_mhz`
/// via the same PLL0 path. Never above nameplate.
pub fn serial_midrun_frequency_target(
    nameplate_mhz: u16,
    live_mhz: u16,
    thermal: NightFanWindow,
    home: NightFanWindow,
    local_hour: u8,
) -> Option<u16> {
    let desired = serial_live_night_frequency_mhz(nameplate_mhz, thermal, home, local_hour);
    (desired != live_mhz).then_some(desired)
}

/// Air-cooled supervisor `board_hot_c` (RE-005 default). A PLL *raise*
/// is refused at or above this last-known board temp. Matches
/// `dcentrald_thermal::supervisor` `default_board_hot`.
pub const SERIAL_PLL_RAISE_BOARD_HOT_C: f32 = 65.0;

/// This-tick board sample that may gate a PLL raise.
/// `None` = incomplete/stale coverage — do not raise this tick.
pub fn serial_same_tick_board_temp_c(sample_c: f32) -> Option<f32> {
    (sample_c.is_finite() && sample_c > 0.0).then_some(sample_c)
}

/// True when a daytime/nameplate PLL raise may enqueue.
///
/// A raise needs a finite this-tick board sample below `board_hot_c`.
/// Missing/non-finite samples (`<= 0`) refuse the raise. Decreases are
/// decided by the caller and are never blocked here.
pub fn serial_pll_raise_permitted(board_temp_c: f32, board_hot_c: f32) -> bool {
    match serial_same_tick_board_temp_c(board_temp_c) {
        Some(temp) => temp < board_hot_c,
        None => false,
    }
}

/// Mid-run PLL step with the split thermal gate.
/// Night decrease always proceeds, including stale/incomplete this-tick
/// coverage. Daytime raise needs a finite sample below `board_hot_c`.
pub fn serial_midrun_frequency_step(
    nameplate_mhz: u16,
    live_mhz: u16,
    thermal: NightFanWindow,
    home: NightFanWindow,
    local_hour: u8,
    board_temp_c: f32,
    board_hot_c: f32,
) -> Option<u16> {
    let next = serial_midrun_frequency_target(nameplate_mhz, live_mhz, thermal, home, local_hour)?;
    if next > live_mhz && !serial_pll_raise_permitted(board_temp_c, board_hot_c) {
        None
    } else {
        Some(next)
    }
}

/// Serial Amlogic/AM2 live fan command: apply the shared night ceiling.
/// Decrease-only; never exceeds `safety_cap` (home PWM-30).
pub fn serial_live_fan_pwm(
    commanded_pwm: u8,
    thermal: NightFanWindow,
    home: NightFanWindow,
    local_hour: u8,
    safety_cap: u8,
) -> u8 {
    apply_night_fan_pwm(
        commanded_pwm,
        effective_night_fan_pwm(thermal, home, local_hour, safety_cap),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_window_covers_late_and_early_hours() {
        assert!(night_hours_active(22, 22, 7));
        assert!(night_hours_active(3, 22, 7));
        assert!(!night_hours_active(7, 22, 7));
        assert!(!night_hours_active(12, 22, 7));
    }

    #[test]
    fn simple_window_is_half_open() {
        assert!(night_hours_active(1, 1, 6));
        assert!(!night_hours_active(6, 1, 6));
        assert!(!night_hours_active(0, 1, 6));
    }

    #[test]
    fn night_cut_is_percent_of_target() {
        assert_eq!(night_adjusted_watts(1000, false, 40), 1000);
        assert_eq!(night_adjusted_watts(1000, true, 40), 600);
        assert_eq!(night_adjusted_watts(1000, true, 0), 1000);
        assert_eq!(night_adjusted_watts(1000, true, 100), 0);
    }

    #[test]
    fn utc_minus_five_at_02_utc_is_21_local() {
        // 02:00 UTC + (-5h) = 21:00 previous local day.
        assert_eq!(local_hour_from_unix_secs(2 * 3600, -5), 21);
    }

    #[test]
    fn home_night_fan_cap_is_live_and_safety_clamped() {
        let home = NightFanWindow::new(true, 22, 7, 20);
        let thermal = NightFanWindow::new(false, 22, 7, 30);
        assert_eq!(
            effective_night_fan_pwm(thermal, home, 23, NIGHT_FAN_PWM_SAFETY_CAP),
            Some(20),
            "home night max_fan_pwm must cap the live SetFanPwm path"
        );
        let over = NightFanWindow::new(true, 22, 7, 80);
        assert_eq!(
            effective_night_fan_pwm(thermal, over, 23, NIGHT_FAN_PWM_SAFETY_CAP),
            Some(30),
            "home night PWM must never exceed the PWM-30 safety cap"
        );
        assert_eq!(
            effective_night_fan_pwm(thermal, home, 12, NIGHT_FAN_PWM_SAFETY_CAP),
            None,
            "daytime must not apply a night fan cap"
        );
    }

    #[test]
    fn thermal_and_home_night_take_the_more_restrictive_cap() {
        let thermal = NightFanWindow::new(true, 22, 7, 15);
        let home = NightFanWindow::new(true, 22, 7, 25);
        assert_eq!(
            effective_night_fan_pwm(thermal, home, 3, NIGHT_FAN_PWM_SAFETY_CAP),
            Some(15)
        );
        assert_eq!(apply_night_fan_pwm(28, Some(15)), 15);
        assert_eq!(apply_night_fan_pwm(10, Some(15)), 10);
        assert_eq!(apply_night_fan_pwm(28, None), 28);
    }

    #[test]
    fn daemon_set_fan_uses_effective_night_fan_pwm() {
        let daemon = include_str!("../../dcentrald/src/daemon.rs");
        assert!(
            daemon.contains("dcentrald_common::night_power::effective_night_fan_pwm("),
            "live SetFanPwm must use the shared night fan helper"
        );
        let rest = include_str!("../../dcentrald-api/src/rest/late.rs");
        assert!(
            rest.contains("home_night_fan_tx"),
            "POST /api/home/night-mode must publish the live home night fan window"
        );
    }

    #[test]
    fn serial_live_fan_pwm_applies_home_night_and_safety_cap() {
        let home = NightFanWindow::new(true, 22, 7, 20);
        let thermal = NightFanWindow::new(false, 22, 7, 30);
        assert_eq!(
            serial_live_fan_pwm(28, thermal, home, 23, NIGHT_FAN_PWM_SAFETY_CAP),
            20,
            "home night max_fan_pwm must cap serial Amlogic/AM2 live fan commands"
        );
        let over = NightFanWindow::new(true, 22, 7, 80);
        assert_eq!(
            serial_live_fan_pwm(30, thermal, over, 23, NIGHT_FAN_PWM_SAFETY_CAP),
            30,
            "serial live fan PWM must never exceed the PWM-30 safety cap"
        );
        assert_eq!(
            serial_live_fan_pwm(28, thermal, home, 12, NIGHT_FAN_PWM_SAFETY_CAP),
            28,
            "daytime must not apply a night fan cap"
        );
        let tight_thermal = NightFanWindow::new(true, 22, 7, 15);
        let loose_home = NightFanWindow::new(true, 22, 7, 25);
        assert_eq!(
            serial_live_fan_pwm(28, tight_thermal, loose_home, 3, NIGHT_FAN_PWM_SAFETY_CAP),
            15
        );
    }

    #[test]
    fn serial_mining_publishes_home_night_fan_and_applies_live_cap() {
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("home_night_fan_tx: Some(home_night_fan_tx)"),
            "serial mining must publish home_night_fan_tx so POST night-mode is live"
        );
        assert!(
            serial.contains("self.config.mode.home.night_mode"),
            "serial home_night_fan_tx must seed from [mode.home.night_mode]"
        );
        assert!(
            serial.contains("dcentrald_common::night_power::serial_live_fan_pwm("),
            "serial Amlogic/AM2 live fan commands must use the shared night helper"
        );
        assert!(serial.contains("S19K_TRACK1_LEFTOVER_FAN_PWM"));
        assert!(
            !serial.lines().any(|line| {
                line.contains("S19K_TRACK1_LEFTOVER_FAN_PWM")
                    && (line.contains("serial_live_night_fan_pwm")
                        || line.contains("serial_live_fan_pwm"))
            }),
            "Track-1 leftover PWM 100 must not be expanded into the night-cap path"
        );
    }

    #[test]
    fn home_night_frequency_is_live_and_most_restrictive() {
        let home = NightFanWindow::new(true, 22, 7, 20).with_max_frequency(350);
        let thermal_off = NightFanWindow::new(false, 22, 7, 30).with_max_frequency(400);
        assert_eq!(
            effective_night_frequency_mhz(thermal_off, home, 23),
            Some(350),
            "home night max_frequency_mhz must cap QuietMode even when thermal night is off"
        );
        let thermal = NightFanWindow::new(true, 22, 7, 15).with_max_frequency(400);
        let loose_home = NightFanWindow::new(true, 22, 7, 25).with_max_frequency(450);
        assert_eq!(
            effective_night_frequency_mhz(thermal, loose_home, 3),
            Some(400)
        );
        assert_eq!(
            effective_night_frequency_mhz(thermal_off, home, 12),
            None,
            "daytime must not apply a night frequency cap"
        );
        assert_eq!(quiet_mode_frequency_limit(525, Some(350)), Some(350));
        assert_eq!(quiet_mode_frequency_limit(300, Some(350)), None);
        assert_eq!(quiet_mode_frequency_limit(525, None), None);
        assert_eq!(
            serial_live_night_frequency_mhz(525, thermal_off, home, 23),
            350
        );
        assert_eq!(
            serial_live_night_frequency_mhz(525, thermal_off, home, 12),
            525
        );
        assert_eq!(
            serial_midrun_night_frequency_step(525, thermal_off, home, 23),
            Some(350),
            "mid-run must step down when the night ceiling is below live MHz"
        );
        assert_eq!(
            serial_midrun_night_frequency_step(525, thermal_off, home, 12),
            None,
            "daytime must not raise or rewrite live MHz"
        );
        assert_eq!(
            serial_midrun_night_frequency_step(300, thermal_off, home, 23),
            None,
            "already-below-cap live MHz must not raise"
        );
        assert_eq!(
            serial_midrun_frequency_target(525, 525, thermal_off, home, 23),
            Some(350),
            "night must still step nameplate 525 down to the home ceiling"
        );
        assert_eq!(
            serial_midrun_frequency_target(525, 350, thermal_off, home, 12),
            Some(525),
            "daytime must raise live PLL back toward nameplate"
        );
        assert_eq!(
            serial_midrun_frequency_target(525, 525, thermal_off, home, 12),
            None,
            "already-at-nameplate daytime must not rewrite PLL"
        );
        assert_eq!(
            serial_midrun_frequency_target(525, 350, thermal_off, home, 23),
            None,
            "already-at-night-ceiling must not rewrite PLL"
        );
        assert_eq!(
            serial_midrun_frequency_target(525, 600, thermal_off, home, 12),
            Some(525),
            "daytime raise must never exceed nameplate"
        );
        let home_off = NightFanWindow::new(false, 22, 7, 20).with_max_frequency(350);
        assert_eq!(
            serial_midrun_frequency_target(525, 350, thermal_off, home_off, 23),
            Some(525),
            "POST-disabled night must raise live PLL back toward nameplate"
        );
        assert!(serial_pll_raise_permitted(
            40.0,
            SERIAL_PLL_RAISE_BOARD_HOT_C
        ));
        assert!(
            !serial_pll_raise_permitted(0.0, SERIAL_PLL_RAISE_BOARD_HOT_C),
            "stale/incomplete this-tick coverage must not raise"
        );
        assert!(!serial_pll_raise_permitted(
            f32::NAN,
            SERIAL_PLL_RAISE_BOARD_HOT_C
        ));
        assert!(!serial_pll_raise_permitted(
            65.0,
            SERIAL_PLL_RAISE_BOARD_HOT_C
        ));
        assert!(!serial_pll_raise_permitted(
            70.0,
            SERIAL_PLL_RAISE_BOARD_HOT_C
        ));
        assert_eq!(
            serial_midrun_frequency_step(
                525,
                350,
                thermal_off,
                home,
                12,
                40.0,
                SERIAL_PLL_RAISE_BOARD_HOT_C
            ),
            Some(525),
            "cool daytime must still raise toward nameplate"
        );
        assert_eq!(
            serial_midrun_frequency_step(
                525,
                350,
                thermal_off,
                home,
                12,
                65.0,
                SERIAL_PLL_RAISE_BOARD_HOT_C
            ),
            None,
            "daytime raise must refuse at supervisor board-hot"
        );
        assert_eq!(
            serial_midrun_frequency_step(
                525,
                525,
                thermal_off,
                home,
                23,
                70.0,
                SERIAL_PLL_RAISE_BOARD_HOT_C
            ),
            Some(350),
            "night decrease must proceed even when already hot"
        );
        assert_eq!(
            serial_midrun_frequency_step(
                525,
                525,
                thermal_off,
                home,
                23,
                0.0,
                SERIAL_PLL_RAISE_BOARD_HOT_C
            ),
            Some(350),
            "night decrease must still apply with stale/incomplete this-tick coverage"
        );
        assert_eq!(
            serial_midrun_frequency_step(
                525,
                350,
                thermal_off,
                home,
                12,
                0.0,
                SERIAL_PLL_RAISE_BOARD_HOT_C
            ),
            None,
            "daytime raise must still require a finite this-tick sample"
        );
        assert_eq!(serial_same_tick_board_temp_c(40.0), Some(40.0));
        assert_eq!(serial_same_tick_board_temp_c(65.0), Some(65.0));
        assert_eq!(
            serial_same_tick_board_temp_c(0.0),
            None,
            "stale/incomplete this-tick coverage must not raise"
        );
        assert_eq!(serial_same_tick_board_temp_c(f32::NAN), None);
        let watt_home = NightFanWindow::new(true, 22, 7, 20)
            .with_max_frequency(350)
            .with_power_reduction(40);
        assert_eq!(
            serial_night_power_frequency_mhz(525, watt_home, 23),
            315,
            "serial must scale nameplate with the same 40% helper as tuner watts"
        );
        assert_eq!(
            serial_live_night_frequency_mhz(525, thermal_off, watt_home, 23),
            315,
            "watt-percent scale must be more restrictive than a 350 MHz night ceiling"
        );
        assert_eq!(
            serial_live_night_frequency_mhz(525, thermal_off, watt_home, 12),
            525,
            "daytime must not apply the serial watt-percent scale"
        );
        let serial_only = serial_night_power_read_truth(false, Some(315), Some(315));
        assert!(
            !serial_only.runtime_adopted,
            "serial must not lie runtimeAdopted"
        );
        assert!(serial_only.serial_frequency_adopted);
        assert_eq!(serial_only.serial_night_power_mhz, Some(315));
        assert_eq!(serial_only.serial_night_power_desired_mhz, Some(315));
        assert!(!serial_only.serial_night_power_pending);
        assert!(!serial_only.saved_only);
        let pending = serial_night_power_read_truth(false, Some(525), Some(315));
        assert_eq!(pending.serial_night_power_mhz, Some(525));
        assert_eq!(pending.serial_night_power_desired_mhz, Some(315));
        assert!(
            pending.serial_night_power_pending,
            "POST must distinguish last adopted MHz from newly saved policy"
        );
        assert!(!pending.runtime_adopted);
        let tuner_only = serial_night_power_read_truth(true, None, None);
        assert!(tuner_only.runtime_adopted);
        assert!(!tuner_only.serial_frequency_adopted);
        assert_eq!(tuner_only.serial_night_power_mhz, None);
        assert!(!tuner_only.serial_night_power_pending);
        assert!(!tuner_only.saved_only);
        assert!(serial_night_power_read_truth(false, None, None).saved_only);
        assert_eq!(serial_live_mhz_from_watch(None), None);
        assert_eq!(
            serial_live_mhz_from_watch(Some(SerialLiveFrequency {
                adopted_mhz: 0,
                nameplate_mhz: 525,
                nameplate_watts: 0,
                thermal: NightFanWindow::new(false, 22, 7, 30),
                timezone_offset_hours: 0,
            })),
            None
        );
        assert_eq!(
            serial_live_mhz_from_watch(Some(SerialLiveFrequency {
                adopted_mhz: 525,
                nameplate_mhz: 525,
                nameplate_watts: 1_000,
                thermal: NightFanWindow::new(false, 22, 7, 30),
                timezone_offset_hours: 0,
            })),
            Some(525)
        );
        let utc_12 = 12 * 3600;
        assert_eq!(
            serial_night_power_desired_at(525, thermal_off, watt_home, utc_12, 0),
            525,
            "12:00 UTC with offset 0 is daytime"
        );
        assert_eq!(
            serial_night_power_desired_at(525, thermal_off, watt_home, utc_12, 10),
            315,
            "12:00 UTC with the serial adopt offset +10 is local 22:00 night"
        );
        assert_eq!(
            serial_night_power_desired_mhz(525, thermal_off, watt_home, 23),
            315
        );
        assert_eq!(
            serial_night_power_desired_mhz(525, thermal_off, watt_home, 12),
            525
        );
        // The multi-line needle is line-ending sensitive: normalize the
        // checked-out file (this Windows checkout carries CRLF) before the
        // contains, exactly like the committed-matrix drift pins do.
        let supervisor = include_str!("../../dcentrald-thermal/src/supervisor.rs")
            .replace("\r\n", "\n");
        assert!(
            supervisor.contains("fn default_board_hot() -> f32 {\n    65.0\n}"),
            "SERIAL_PLL_RAISE_BOARD_HOT_C must stay pinned to supervisor board_hot"
        );
    }

    #[test]
    fn serial_night_watts_desired_and_truth_table() {
        let home = NightFanWindow::new(true, 22, 7, 20).with_power_reduction(40);
        let thermal_off = NightFanWindow::new(false, 22, 7, 30).with_power_reduction(50);
        // Desired watts use the same shared percent helper as tuner watts
        // ( pin: resolve_power_mode_target_watts(1000, 40% night) = 600).
        assert_eq!(
            serial_night_power_desired_watts(1_000, thermal_off, home, 23),
            600
        );
        assert_eq!(
            serial_night_power_desired_watts(1_000, thermal_off, home, 12),
            1_000,
            "daytime must not cut watts"
        );
        let thermal_on = NightFanWindow::new(true, 22, 7, 30).with_power_reduction(50);
        assert_eq!(
            serial_night_power_desired_watts(1_000, thermal_on, home, 23),
            500,
            "the more restrictive window must win"
        );
        let home_off = NightFanWindow::new(false, 22, 7, 20).with_power_reduction(40);
        assert_eq!(
            serial_night_power_desired_watts(1_000, thermal_on, home_off, 23),
            500,
            "the thermal window must cut even when home night is disabled"
        );
        // Timezone: 12:00 UTC offset 0 is daytime; the serial adopt offset
        // +10 makes it local 22:00 night (same pin as the MHz analog).
        let utc_12 = 12 * 3600;
        assert_eq!(
            serial_night_power_desired_watts_at(1_000, thermal_off, home, utc_12, 0),
            1_000
        );
        assert_eq!(
            serial_night_power_desired_watts_at(1_000, thermal_off, home, utc_12, 10),
            600
        );

        // Truth: serial has no authoritative watt sample source in-tree.
        let saved_only = serial_night_watt_read_truth(false, None, Some(600));
        assert!(
            !saved_only.runtime_adopted,
            "serial must not lie runtimeAdopted on watts"
        );
        assert_eq!(saved_only.serial_watt_sample_watts, None);
        assert_eq!(saved_only.serial_night_power_desired_watts, Some(600));
        assert!(
            !saved_only.serial_night_power_pending,
            "a missing sample can never be pending — nothing was measured"
        );
        assert!(
            saved_only.saved_only,
            "serial watts must surface savedOnly truth"
        );
        // An authoritative sample above the desired night target is honestly pending.
        let pending = serial_night_watt_read_truth(false, Some(1_000), Some(600));
        assert_eq!(pending.serial_watt_sample_watts, Some(1_000));
        assert!(
            pending.serial_night_power_pending,
            "measured watts above the desired night target mean the cut is not reflected"
        );
        assert!(!pending.saved_only);
        assert!(
            !pending.runtime_adopted,
            "a measured sample is observation truth, never tuner actuation"
        );
        // A sample at or below the target is not pending.
        assert!(
            !serial_night_watt_read_truth(false, Some(600), Some(600)).serial_night_power_pending
        );
        assert!(
            !serial_night_watt_read_truth(false, Some(590), Some(600)).serial_night_power_pending
        );
        // Estimate-only input is the caller's refusal: REST classifies with
        // PowerAuthorityKind and never passes an estimate here. A tuner-adopted
        // hybrid without a sample stays runtime-adopted and not saved-only.
        let tuner = serial_night_watt_read_truth(true, None, None);
        assert!(tuner.runtime_adopted);
        assert!(!tuner.saved_only);
        assert_eq!(tuner.serial_night_power_desired_watts, None);
        // A zero nameplate is "no watt target configured" and stays unpublished
        // by the REST layer (snap.nameplate_watts > 0 gate).
        assert_eq!(serial_night_power_desired_watts(0, thermal_on, home, 23), 0);
    }

    #[test]
    fn serial_night_watts_rest_and_publisher_pins() {
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        let production = serial
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production source");
        assert!(
            production.contains("let nameplate_watts = self.config.power.target_watts;"),
            "serial must publish the runtime watt nameplate from [power] target_watts"
        );
        assert!(
            production.contains("nameplate_watts,"),
            "the serial night snapshot must carry nameplate_watts for desired-watt truth"
        );
        assert!(
            !production.contains("power_tx.send"),
            "serial must NOT publish watts on the power watch — that would fake a live \
             watt sample source where none exists (estimates HOLD, never close)"
        );
        assert!(
            production.contains("autotuner_command_tx: None,"),
            "serial must keep autotuner_command_tx absent (no fake tuner consumer)"
        );
        let rest = include_str!("../../dcentrald-api/src/rest/late.rs");
        assert!(
            rest.contains("serial_night_watt_read_truth("),
            "GET/POST must report honest serial watt truth"
        );
        assert!(
            rest.contains("\"serialWattSampleWatts\": watt_truth.serial_watt_sample_watts"),
            "GET/POST must expose the authoritative watt sample (null when unreachable)"
        );
        assert!(
            rest.contains(
                "\"serialNightPowerDesiredWatts\": watt_truth.serial_night_power_desired_watts"
            ),
            "GET/POST must report the watts the saved night policy would produce"
        );
        assert!(
            rest.contains(
                "\"serialNightPowerWattsPending\": watt_truth.serial_night_power_pending"
            ),
            "GET/POST must mark pending only from a measured sample above the target"
        );
        assert!(
            rest.contains("\"serialWattSavedOnly\": watt_truth.saved_only"),
            "GET/POST must expose the watts savedOnly truth separately from the MHz one"
        );
        assert!(
            rest.contains("is_control_authoritative()"),
            "the watt sample must pass the tuner's control-authoritative bar (PMBus/ADC/wall-calibrated)"
        );
        assert!(
            rest.contains("serial_night_power_desired_watts_at("),
            "GET/POST desired watts must use the serial adopt timezone, not UTC 0"
        );
        assert!(
            rest.contains("\"unavailable\""),
            "GET/POST must label the watt sample source unavailable when none is reachable"
        );
    }

    #[test]
    fn daemon_and_serial_use_effective_night_frequency() {
        let daemon = include_str!("../../dcentrald/src/daemon.rs");
        assert!(
            daemon.contains("dcentrald_common::night_power::effective_night_frequency_mhz("),
            "live QuietMode must use the shared night frequency helper"
        );
        assert!(
            daemon.contains("dcentrald_common::night_power::quiet_mode_frequency_limit("),
            "QuietMode payload must come from quiet_mode_frequency_limit"
        );
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("dcentrald_common::night_power::serial_live_night_frequency_mhz("),
            "serial init PLL target must use the shared night frequency helper"
        );
        assert!(
            serial.contains("dcentrald_common::night_power::serial_midrun_frequency_step("),
            "serial thermal ticks must adopt the thermal-gated nameplate frequency step"
        );
        assert!(
            serial.contains("serial_adopt_live_night_frequency("),
            "serial thermal ticks must adopt PLL after this-tick temp assignment"
        );
        assert!(
            serial.contains("latest_temp_c = 0.0"),
            "stale Amlogic coverage must still reach adopt so night decrease can apply"
        );
        let rest = include_str!("../../dcentrald-api/src/rest/late.rs");
        assert!(
            rest.contains("with_max_frequency("),
            "POST /api/home/night-mode must publish the live home night frequency ceiling"
        );
        assert!(
            rest.contains("with_power_reduction("),
            "POST must publish home power_reduction_pct onto the serial night watch"
        );
        assert!(
            rest.contains("serial_night_power_read_truth("),
            "GET/POST must report honest serial frequency adoption"
        );
        assert!(
            rest.contains("\"serialFrequencyAdopted\": serial_truth.serial_frequency_adopted"),
            "GET/POST must expose serialFrequencyAdopted without flipping runtimeAdopted"
        );
        assert!(
            rest.contains("\"serialNightPowerMhz\": serial_truth.serial_night_power_mhz"),
            "GET/POST must report the live serial adopted MHz"
        );
        assert!(
            rest.contains(
                "\"serialNightPowerDesiredMhz\": serial_truth.serial_night_power_desired_mhz"
            ),
            "GET/POST must report the MHz the saved night policy would produce"
        );
        assert!(
            rest.contains("\"serialNightPowerPending\": serial_truth.serial_night_power_pending"),
            "GET/POST must mark pending when adopted MHz lags the saved policy"
        );
        assert!(
            rest.contains("serial_night_power_desired_at("),
            "GET/POST must use serial_night_power_desired_at, not UTC 0"
        );
        assert!(
            rest.contains("snap.timezone_offset_hours"),
            "GET/POST desired hour must use the serial adopt timezone"
        );
        assert!(
            serial.contains("timezone_offset_hours: thermal_night.timezone_offset_hours")
                || serial
                    .contains("timezone_offset_hours: thermal_night_mode.timezone_offset_hours"),
            "serial must publish the same thermal timezone adopt uses"
        );
        assert!(
            rest.contains("serial_live_mhz_from_watch("),
            "GET/POST must read live MHz from the serial publisher, not watch-liveness"
        );
        assert!(
            serial.contains("serial_live_mhz_tx: Some(serial_live_mhz_tx.clone())"),
            "serial must publish operating_freq on serial_live_mhz_tx"
        );
        assert!(
            serial.contains("live_mhz_tx.send(dcentrald_common::night_power::SerialLiveFrequency"),
            "serial adopt must publish adopted MHz plus nameplate for desired-policy honesty"
        );
        assert!(
            serial.contains("with_power_reduction(home.power_reduction_pct)")
                || serial.contains("with_power_reduction(home_night.power_reduction_pct)"),
            "serial init/watch must seed home power_reduction_pct"
        );
    }
}
