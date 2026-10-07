//! Crash-durable, source-aware thermal lockout for mining generations.
//!
//! A process-local thermal latch disappears on watchdog reset. This record
//! preserves the thermal domain that consumed the prior mining generation so a
//! cool control board cannot stand in for a still-hot hash board on restart.

use crate::atomic_file::{
    atomic_write, remove_file, AtomicRemoveError, AtomicRemoveOutcome, AtomicWriteError,
    AtomicWriteOptions, AtomicWriteOutcome,
};
use std::fmt;
use std::io;
use std::path::Path;

const RECORD_PREFIX: &str = "DCENT_THERMAL_LOCKOUT_V1";
pub const THERMAL_LOCKOUT_MAX_BYTES: usize = 256;
pub const EXPERIMENTAL_BOARD_PROXY_MIN_DWELL_S: u64 = 15 * 60;
pub const REQUIRED_RELEASE_SAMPLES: usize = 3;
pub const SANE_WALL_CLOCK_MIN_UNIX_S: u64 = 1_577_836_800; // 2020-01-01 UTC
const MAX_SAMPLE_RISE_C: f32 = 0.5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalLockoutSource {
    BoardSensor { chain_id: u8 },
    SocDie,
    FanFailure,
    SensorBlind,
    Unknown,
}

impl ThermalLockoutSource {
    fn encode(self) -> String {
        match self {
            Self::BoardSensor { chain_id } => format!("board:{chain_id}"),
            Self::SocDie => "soc".to_string(),
            Self::FanFailure => "fan".to_string(),
            Self::SensorBlind => "blind".to_string(),
            Self::Unknown => "unknown".to_string(),
        }
    }

    fn decode(value: &str) -> Result<Self, ThermalLockoutParseError> {
        match value {
            "soc" => Ok(Self::SocDie),
            "fan" => Ok(Self::FanFailure),
            "blind" => Ok(Self::SensorBlind),
            "unknown" => Ok(Self::Unknown),
            _ => value
                .strip_prefix("board:")
                .ok_or(ThermalLockoutParseError::InvalidSource)
                .and_then(|chain_id| {
                    chain_id
                        .parse::<u8>()
                        .map(|chain_id| Self::BoardSensor { chain_id })
                        .map_err(|_| ThermalLockoutParseError::InvalidSource)
                }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalThermalLockout {
    pub observed_unix_s: u64,
    pub source: ThermalLockoutSource,
    pub trigger_temp_milli_c: Option<i32>,
    pub dangerous_temp_c: u8,
    pub hysteresis_c: u8,
}

impl TerminalThermalLockout {
    pub fn recovery_boundary_c(self) -> f32 {
        f32::from(self.dangerous_temp_c) - f32::from(self.hysteresis_c)
    }

    pub fn encode(self) -> String {
        let trigger = self
            .trigger_temp_milli_c
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "{RECORD_PREFIX}|{}|{}|{trigger}|{}|{}\n",
            self.observed_unix_s,
            self.source.encode(),
            self.dangerous_temp_c,
            self.hysteresis_c
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ThermalLockoutParseError> {
        if bytes.is_empty() || bytes.len() > THERMAL_LOCKOUT_MAX_BYTES {
            return Err(ThermalLockoutParseError::InvalidLength);
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| ThermalLockoutParseError::InvalidEncoding)?;
        let text = text
            .strip_suffix('\n')
            .ok_or(ThermalLockoutParseError::MissingTerminator)?;
        if text.contains('\n') || text.contains('\r') {
            return Err(ThermalLockoutParseError::UnexpectedWhitespace);
        }
        let mut fields = text.split('|');
        if fields.next() != Some(RECORD_PREFIX) {
            return Err(ThermalLockoutParseError::UnsupportedVersion);
        }
        let observed_unix_s = parse_field::<u64>(fields.next())?;
        let source = ThermalLockoutSource::decode(
            fields
                .next()
                .ok_or(ThermalLockoutParseError::MissingField)?,
        )?;
        let trigger_temp_milli_c = match fields
            .next()
            .ok_or(ThermalLockoutParseError::MissingField)?
        {
            "none" => None,
            value => Some(
                value
                    .parse::<i32>()
                    .map_err(|_| ThermalLockoutParseError::InvalidNumber)?,
            ),
        };
        let dangerous_temp_c = parse_field::<u8>(fields.next())?;
        let hysteresis_c = parse_field::<u8>(fields.next())?;
        if fields.next().is_some() {
            return Err(ThermalLockoutParseError::ExtraField);
        }
        if dangerous_temp_c == 0 || hysteresis_c >= dangerous_temp_c {
            return Err(ThermalLockoutParseError::InvalidThreshold);
        }
        if trigger_temp_milli_c.is_some_and(|value| !(-100_000..=250_000).contains(&value)) {
            return Err(ThermalLockoutParseError::InvalidTemperature);
        }
        Ok(Self {
            observed_unix_s,
            source,
            trigger_temp_milli_c,
            dangerous_temp_c,
            hysteresis_c,
        })
    }
}

/// Marker installed after fresh recovery admission but before a new generation
/// can create watchdog, heartbeat, rail, or mining authority. It is
/// intentionally unreleasable by automatic startup policy: a crash before
/// source refinement must preserve "unknown thermal disposition", not absence.
pub const fn prearmed_thermal_generation(
    observed_unix_s: u64,
    startup_temp_milli_c: Option<i32>,
    dangerous_temp_c: u8,
    hysteresis_c: u8,
) -> TerminalThermalLockout {
    TerminalThermalLockout {
        observed_unix_s,
        source: ThermalLockoutSource::Unknown,
        trigger_temp_milli_c: startup_temp_milli_c,
        dangerous_temp_c,
        hysteresis_c,
    }
}

fn parse_field<T: std::str::FromStr>(field: Option<&str>) -> Result<T, ThermalLockoutParseError> {
    field
        .ok_or(ThermalLockoutParseError::MissingField)?
        .parse::<T>()
        .map_err(|_| ThermalLockoutParseError::InvalidNumber)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalLockoutParseError {
    InvalidLength,
    InvalidEncoding,
    MissingTerminator,
    UnexpectedWhitespace,
    UnsupportedVersion,
    MissingField,
    ExtraField,
    InvalidNumber,
    InvalidSource,
    InvalidThreshold,
    InvalidTemperature,
}

impl fmt::Display for ThermalLockoutParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid thermal lockout record: {self:?}")
    }
}

impl std::error::Error for ThermalLockoutParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalLockoutRefusal {
    InsufficientSamples,
    NonFiniteSample,
    SampleAtOrAboveRecoveryBoundary,
    SamplesWarming,
    FanReadinessRequired,
    BoardDomainMeasurementRequired,
    ExperimentalDwellNotElapsed,
    WallClockUnavailableOrRegressed,
    SensorVisibilityRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalLockoutReleaseDecision {
    ReleaseSameDomain,
    ReleaseExperimentalBoardProxy,
    Refuse(ThermalLockoutRefusal),
}

impl ThermalLockoutReleaseDecision {
    pub const fn may_remove_lockout(self) -> bool {
        matches!(
            self,
            Self::ReleaseSameDomain | Self::ReleaseExperimentalBoardProxy
        )
    }

    pub const fn is_experimental(self) -> bool {
        matches!(self, Self::ReleaseExperimentalBoardProxy)
    }
}

/// Decide whether a persisted terminal lockout may be removed.
///
/// `xadc_samples_c` must be consecutive fresh observations from this startup.
/// Board-triggered lockouts require the same board domain by default. The only
/// proxy release is deliberately explicit and labeled experimental: at least
/// fifteen minutes of sane wall-clock dwell plus three finite, safe, non-warming
/// XADC observations. It is not board-temperature equivalence.
// clippy::indexing_slicing: `xadc_samples_c.windows(2)` yields pairs of exactly
// 2, so `pair[0]`/`pair[1]` are in-bounds.
#[allow(clippy::indexing_slicing)]
pub fn evaluate_thermal_lockout_release(
    lockout: TerminalThermalLockout,
    now_unix_s: u64,
    xadc_samples_c: &[f32],
    current_dangerous_temp_c: u8,
    current_hysteresis_c: u8,
    fan_ready: bool,
    experimental_board_proxy_enabled: bool,
) -> ThermalLockoutReleaseDecision {
    let current_boundary = f32::from(current_dangerous_temp_c) - f32::from(current_hysteresis_c);
    let recovery_boundary = lockout.recovery_boundary_c().min(current_boundary);
    if xadc_samples_c.len() < REQUIRED_RELEASE_SAMPLES {
        return ThermalLockoutReleaseDecision::Refuse(ThermalLockoutRefusal::InsufficientSamples);
    }
    if xadc_samples_c.iter().any(|sample| !sample.is_finite()) {
        return ThermalLockoutReleaseDecision::Refuse(ThermalLockoutRefusal::NonFiniteSample);
    }
    if xadc_samples_c
        .iter()
        .any(|sample| *sample >= recovery_boundary)
    {
        return ThermalLockoutReleaseDecision::Refuse(
            ThermalLockoutRefusal::SampleAtOrAboveRecoveryBoundary,
        );
    }
    if xadc_samples_c
        .windows(2)
        .any(|pair| pair[1] > pair[0] + MAX_SAMPLE_RISE_C)
    {
        return ThermalLockoutReleaseDecision::Refuse(ThermalLockoutRefusal::SamplesWarming);
    }

    match lockout.source {
        ThermalLockoutSource::SocDie => ThermalLockoutReleaseDecision::ReleaseSameDomain,
        ThermalLockoutSource::FanFailure if fan_ready => {
            ThermalLockoutReleaseDecision::ReleaseSameDomain
        }
        ThermalLockoutSource::FanFailure => {
            ThermalLockoutReleaseDecision::Refuse(ThermalLockoutRefusal::FanReadinessRequired)
        }
        ThermalLockoutSource::BoardSensor { .. } if !experimental_board_proxy_enabled => {
            ThermalLockoutReleaseDecision::Refuse(
                ThermalLockoutRefusal::BoardDomainMeasurementRequired,
            )
        }
        ThermalLockoutSource::BoardSensor { .. } => {
            if lockout.observed_unix_s < SANE_WALL_CLOCK_MIN_UNIX_S
                || now_unix_s < lockout.observed_unix_s
            {
                return ThermalLockoutReleaseDecision::Refuse(
                    ThermalLockoutRefusal::WallClockUnavailableOrRegressed,
                );
            }
            if now_unix_s - lockout.observed_unix_s < EXPERIMENTAL_BOARD_PROXY_MIN_DWELL_S {
                return ThermalLockoutReleaseDecision::Refuse(
                    ThermalLockoutRefusal::ExperimentalDwellNotElapsed,
                );
            }
            ThermalLockoutReleaseDecision::ReleaseExperimentalBoardProxy
        }
        ThermalLockoutSource::SensorBlind | ThermalLockoutSource::Unknown => {
            ThermalLockoutReleaseDecision::Refuse(ThermalLockoutRefusal::SensorVisibilityRequired)
        }
    }
}

pub fn persist_thermal_lockout(
    path: impl AsRef<Path>,
    lockout: TerminalThermalLockout,
) -> Result<AtomicWriteOutcome, AtomicWriteError> {
    atomic_write(
        path,
        lockout.encode(),
        AtomicWriteOptions::state_file(THERMAL_LOCKOUT_MAX_BYTES),
    )
}

pub fn load_thermal_lockout(path: impl AsRef<Path>) -> io::Result<Option<TerminalThermalLockout>> {
    let path = path.as_ref();
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "thermal lockout path is not a regular non-symlink file",
        ));
    }
    if metadata.len() > THERMAL_LOCKOUT_MAX_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "thermal lockout record exceeds its bounded size",
        ));
    }
    let bytes = std::fs::read(path)?;
    TerminalThermalLockout::decode(&bytes)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn remove_thermal_lockout(
    path: impl AsRef<Path>,
) -> Result<AtomicRemoveOutcome, AtomicRemoveError> {
    remove_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn board_lockout() -> TerminalThermalLockout {
        TerminalThermalLockout {
            observed_unix_s: SANE_WALL_CLOCK_MIN_UNIX_S + 100,
            source: ThermalLockoutSource::BoardSensor { chain_id: 7 },
            trigger_temp_milli_c: Some(82_375),
            dangerous_temp_c: 80,
            hysteresis_c: 3,
        }
    }

    #[test]
    fn record_round_trips_source_threshold_and_trigger() {
        let record = board_lockout();
        assert_eq!(
            TerminalThermalLockout::decode(record.encode().as_bytes()).unwrap(),
            record
        );
    }

    #[test]
    fn corrupt_or_ambiguous_records_never_parse_as_clear() {
        for bytes in [
            b"".as_slice(),
            b"DCENT_THERMAL_LOCKOUT_V0|1|soc|70000|80|3\n".as_slice(),
            b"DCENT_THERMAL_LOCKOUT_V1|1|board:999|70000|80|3\n".as_slice(),
            b"DCENT_THERMAL_LOCKOUT_V1|1|soc|70000|3|3\n".as_slice(),
            b"DCENT_THERMAL_LOCKOUT_V1|1|soc|70000|80|3".as_slice(),
            b"DCENT_THERMAL_LOCKOUT_V1|1|soc|70000|80|3\nextra".as_slice(),
        ] {
            assert!(TerminalThermalLockout::decode(bytes).is_err());
        }
    }

    #[test]
    fn board_lockout_refuses_cool_soc_as_same_domain_evidence() {
        let decision = evaluate_thermal_lockout_release(
            board_lockout(),
            SANE_WALL_CLOCK_MIN_UNIX_S + 10_000,
            &[45.0, 44.9, 44.8],
            80,
            3,
            true,
            false,
        );
        assert_eq!(
            decision,
            ThermalLockoutReleaseDecision::Refuse(
                ThermalLockoutRefusal::BoardDomainMeasurementRequired
            )
        );
    }

    #[test]
    fn experimental_board_proxy_requires_dwell_and_non_warming_repeated_samples() {
        let lockout = board_lockout();
        let before_dwell = lockout.observed_unix_s + EXPERIMENTAL_BOARD_PROXY_MIN_DWELL_S - 1;
        assert_eq!(
            evaluate_thermal_lockout_release(
                lockout,
                before_dwell,
                &[45.0, 44.9, 44.8],
                80,
                3,
                true,
                true,
            ),
            ThermalLockoutReleaseDecision::Refuse(
                ThermalLockoutRefusal::ExperimentalDwellNotElapsed
            )
        );
        assert_eq!(
            evaluate_thermal_lockout_release(
                lockout,
                lockout.observed_unix_s + EXPERIMENTAL_BOARD_PROXY_MIN_DWELL_S,
                &[45.0, 45.6, 45.0],
                80,
                3,
                true,
                true,
            ),
            ThermalLockoutReleaseDecision::Refuse(ThermalLockoutRefusal::SamplesWarming)
        );
        let admitted = evaluate_thermal_lockout_release(
            lockout,
            lockout.observed_unix_s + EXPERIMENTAL_BOARD_PROXY_MIN_DWELL_S,
            &[45.0, 44.9, 44.8],
            80,
            3,
            true,
            true,
        );
        assert_eq!(
            admitted,
            ThermalLockoutReleaseDecision::ReleaseExperimentalBoardProxy
        );
        assert!(admitted.may_remove_lockout());
        assert!(admitted.is_experimental());
    }

    #[test]
    fn soc_release_uses_stricter_recorded_or_current_boundary() {
        let mut lockout = board_lockout();
        lockout.source = ThermalLockoutSource::SocDie;
        assert_eq!(
            evaluate_thermal_lockout_release(
                lockout,
                lockout.observed_unix_s,
                &[74.9, 74.8, 74.7],
                78,
                3,
                true,
                false,
            ),
            ThermalLockoutReleaseDecision::ReleaseSameDomain
        );
        assert_eq!(
            evaluate_thermal_lockout_release(
                lockout,
                lockout.observed_unix_s,
                &[75.0, 74.9, 74.8],
                78,
                3,
                true,
                false,
            ),
            ThermalLockoutReleaseDecision::Refuse(
                ThermalLockoutRefusal::SampleAtOrAboveRecoveryBoundary
            )
        );
    }

    #[test]
    fn fan_failure_requires_new_tach_readiness_and_safe_samples() {
        let mut lockout = board_lockout();
        lockout.source = ThermalLockoutSource::FanFailure;
        assert_eq!(
            evaluate_thermal_lockout_release(
                lockout,
                lockout.observed_unix_s,
                &[45.0, 44.9, 44.8],
                80,
                3,
                false,
                false,
            ),
            ThermalLockoutReleaseDecision::Refuse(ThermalLockoutRefusal::FanReadinessRequired)
        );
        assert_eq!(
            evaluate_thermal_lockout_release(
                lockout,
                lockout.observed_unix_s,
                &[45.0, 44.9, 44.8],
                80,
                3,
                true,
                false,
            ),
            ThermalLockoutReleaseDecision::ReleaseSameDomain
        );
    }

    #[test]
    fn sensor_blind_and_unknown_lockouts_require_real_visibility() {
        for source in [
            ThermalLockoutSource::SensorBlind,
            ThermalLockoutSource::Unknown,
        ] {
            let mut lockout = board_lockout();
            lockout.source = source;
            assert_eq!(
                evaluate_thermal_lockout_release(
                    lockout,
                    lockout.observed_unix_s + 10_000,
                    &[45.0, 44.9, 44.8],
                    80,
                    3,
                    true,
                    true,
                ),
                ThermalLockoutReleaseDecision::Refuse(
                    ThermalLockoutRefusal::SensorVisibilityRequired
                )
            );
        }
    }

    #[test]
    fn prearmed_generation_is_strict_unknown_and_never_auto_releases() {
        let marker = prearmed_thermal_generation(1_800_000_000, Some(42_500), 80, 3);
        assert_eq!(marker.source, ThermalLockoutSource::Unknown);
        assert_eq!(
            TerminalThermalLockout::decode(marker.encode().as_bytes()).unwrap(),
            marker
        );
        assert_eq!(
            evaluate_thermal_lockout_release(
                marker,
                1_800_001_000,
                &[40.0, 39.0, 38.0],
                80,
                3,
                true,
                true,
            ),
            ThermalLockoutReleaseDecision::Refuse(ThermalLockoutRefusal::SensorVisibilityRequired)
        );
    }

    #[test]
    fn daemon_closes_feed_and_requests_closeout_before_bounded_persistence() {
        let daemon = include_str!("../../dcentrald/src/daemon.rs");
        let bounded_helper = daemon
            .split_once("async fn persist_terminal_thermal_generation_bounded(")
            .expect("bounded persistence helper")
            .1
            .split_once("fn mark_thermal_emergency_active(")
            .expect("bounded persistence helper boundary")
            .0;
        assert!(
            bounded_helper.contains("tokio::task::spawn_blocking"),
            "lockout fsync work must not block the async thermal worker"
        );
        assert!(
            bounded_helper.contains(
                "tokio::time::timeout(TERMINAL_THERMAL_LOCKOUT_PERSIST_TIMEOUT, persistence)"
            ),
            "lockout persistence wait must have a strict terminal bound"
        );
        let emergency_start = daemon
            .find("ThermalAction::EmergencyShutdown => {")
            .expect("emergency arm");
        let fan_start = daemon[emergency_start..]
            .find("ThermalAction::FanFailure => {")
            .map(|offset| emergency_start + offset)
            .expect("fan-failure arm");
        let restart_start = daemon[fan_start..]
            .find("ThermalAction::RestartInit => {")
            .map(|offset| fan_start + offset)
            .expect("restart arm");

        for (name, arm) in [
            ("emergency", &daemon[emergency_start..fan_start]),
            ("fan-failure", &daemon[fan_start..restart_start]),
        ] {
            let direct_cut = arm
                .find("VoltageCommand::DisableVoltage")
                .expect("direct voltage cut");
            let persist = arm
                .rfind("persist_terminal_thermal_generation_bounded")
                .expect("bounded durable thermal lockout");
            let handoff = arm
                .rfind("request_typed_closeout_for_terminal_thermal_generation")
                .expect("typed closeout");
            assert!(
                direct_cut < handoff && handoff < persist,
                "{name} must attempt the rail cut, close feed/request typed closeout, then begin bounded persistence"
            );
            assert_eq!(
                arm.matches("persist_terminal_thermal_generation_bounded")
                    .count(),
                1,
                "{name} must have exactly one bounded terminal persistence attempt"
            );
        }

        let emergency = &daemon[emergency_start..fan_start];
        for source in [
            "ThermalLockoutSource::BoardSensor",
            "ThermalLockoutSource::SocDie",
            "ThermalLockoutSource::SensorBlind",
        ] {
            assert!(
                emergency.contains(source),
                "emergency marker must preserve {source} provenance"
            );
        }
        assert!(daemon[fan_start..restart_start].contains("ThermalLockoutSource::FanFailure"));
    }

    #[test]
    fn failed_lockout_persistence_cannot_clear_prelaunch_session_admission() {
        let supervisor = include_str!(
            "../../../br2_external_dcentos/board/common/rootfs-overlay/usr/libexec/dcentos/dcentrald-session-latch.sh"
        );
        let unresolved_before_launch = supervisor
            .find("write_marker \"$UNRESOLVED_FILE\" unresolved")
            .expect("durable unresolved marker publication");
        let child_launch = supervisor
            .find("exec \"$@\"")
            .expect("supervised daemon launch");
        assert!(
            unresolved_before_launch < child_launch,
            "the unresolved session marker must exist before the daemon can own hardware"
        );
        assert!(
            supervisor.contains("expected zero-status exit for PID $CHILD_PID remains unresolved"),
            "expected exit status alone must not clear physical disposition"
        );
        let consumer = supervisor.split_once("clear_orderly_software_session() {").unwrap().1
            .split_once("\n}\n").unwrap().0;
        let checked_receipt = consumer.find("\"$CLOSEOUT_VALIDATOR\" --check-software-closeout").unwrap();
        let clear = consumer.find("rm -f \"$UNRESOLVED_FILE\"").unwrap();
        assert!(checked_receipt < clear, "only a checked exact-session receipt may remove admission");
        assert!(consumer.contains("[ \"$SAFETY_OK\" -eq 1 ]"));
        let fallback = supervisor.split_once("promote_unresolved_locked() {").unwrap().1
            .split_once("\n}\n").unwrap().0;
        let failed_write = fallback.find("could not publish crash latch; unresolved state still blocks admission").unwrap();
        let failed_return = fallback[failed_write..].find("return 1").unwrap() + failed_write;
        let remove_unresolved = fallback.find("rm -f \"$UNRESOLVED_FILE\"").unwrap();
        assert!(failed_return < remove_unresolved, "failed marker persistence must preserve the prelaunch boundary");
        assert!(
            supervisor.contains(
                "no valid exact-session software closeout receipt; operator resolution is required before another start"
            ),
            "absent closeout proof must retain the unresolved operator boundary"
        );
    }

    #[test]
    fn daemon_prearms_unknown_and_clears_only_after_nonthermal_closeout() {
        let daemon = include_str!("../../dcentrald/src/daemon.rs");
        let init = daemon
            .split_once("async fn init(")
            .expect("standard init")
            .1;
        let measured = init
            .find("self.startup_thermal_safety = measured_startup_thermal_state(")
            .expect("measured startup admission");
        let prearm = init
            .find("let prearmed_lockout = prearmed_thermal_generation(")
            .expect("Unknown generation pre-arm");
        let prearm_persist = init[prearm..]
            .find("persist_terminal_thermal_generation_bounded(")
            .map(|offset| prearm + offset)
            .expect("durable pre-arm publication");
        let prearm_receipt = init[prearm_persist..]
            .find("self.thermal_generation_prearmed = true")
            .map(|offset| prearm_persist + offset)
            .expect("pre-arm receipt");
        let phase_one = init
            .find("// ---- Phase 1: Watchdog ----")
            .expect("first post-admission phase");
        assert!(
            measured < prearm
                && prearm < prearm_persist
                && prearm_persist < prearm_receipt
                && prearm_receipt < phase_one,
            "Unknown must be durable before watchdog, heartbeat, rail, or mining authority"
        );
        let prearm_failure = &init[prearm_persist..phase_one];
        assert!(
            prearm_failure.contains("latch_terminal_safe_off()")
                && prearm_failure.contains("anyhow::bail!("),
            "pre-arm failure must terminate before Phase 1"
        );

        let shutdown = daemon
            .split_once("async fn shutdown(&mut self)")
            .expect("typed shutdown")
            .1;
        let complete = shutdown
            .find("info!(\"=== SHUTDOWN COMPLETE ===\")")
            .expect("positive closeout boundary");
        let prearmed_guard = shutdown[complete..]
            .find("if self.thermal_generation_prearmed")
            .map(|offset| complete + offset)
            .expect("pre-armed cleanup guard");
        let thermal_guard = shutdown[prearmed_guard..]
            .find("thermal_emergency_active(&self.terminal_thermal_generation_latch)")
            .map(|offset| prearmed_guard + offset)
            .expect("thermal terminal retention guard");
        let source_guard = shutdown[thermal_guard..]
            .find("current_marker.source != ThermalLockoutSource::Unknown")
            .map(|offset| thermal_guard + offset)
            .expect("refined-source retention guard");
        let durable_remove = shutdown[source_guard..]
            .find("remove_thermal_lockout(&thermal_lockout_path)")
            .map(|offset| source_guard + offset)
            .expect("nonthermal durable removal");
        assert!(
            complete < prearmed_guard
                && prearmed_guard < thermal_guard
                && thermal_guard < source_guard
                && source_guard < durable_remove,
            "only positive nonthermal closeout may remove this generation's Unknown marker"
        );
    }

    #[cfg(unix)]
    #[test]
    fn durable_round_trip_and_removal_never_treat_corruption_as_absence() {
        let unique = format!(
            "dcent-thermal-lockout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("thermal-lockout");
        let record = board_lockout();

        persist_thermal_lockout(&path, record).unwrap();
        assert_eq!(load_thermal_lockout(&path).unwrap(), Some(record));
        assert_eq!(
            remove_thermal_lockout(&path).unwrap(),
            AtomicRemoveOutcome::Removed
        );
        assert_eq!(load_thermal_lockout(&path).unwrap(), None);

        std::fs::write(&path, b"corrupt\n").unwrap();
        assert!(load_thermal_lockout(&path).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
