//! Structured logging setup for dcentrald.
//!
//! Uses the `tracing` crate with `tracing-subscriber` for leveled, structured
//! logging. Output goes to stdout (which on the S9 is the serial console and
//! syslog). Log level is configurable via dcentrald.toml or the DCENTRALD_LOG
//! environment variable.
//!
//! Log levels — what you'll see and when:
//!   ERROR: Something broke and needs attention NOW
//!          (thermal shutdown, fan failure, PIC failure, all pools down)
//!   WARN:  Something is wrong but the miner keeps running
//!          (pool disconnect, share rejected, high CRC errors, I2C timeout)
//!   INFO:  Milestone events and periodic status updates
//!          (init phases, hashrate reports, mode changes, pool connected)
//!   DEBUG: Detailed per-event logging for troubleshooting
//!          (each share submitted, each nonce found, FIFO operations)
//!   TRACE: Wire-level protocol dumps for hardware debugging
//!          (raw I2C bytes, raw FPGA register reads/writes, Stratum JSON)
//!
//! Override at runtime: DCENTRALD_LOG="dcentrald=debug,dcentrald_stratum=trace" ./dcentrald

use std::fmt::Write as _;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::{fmt, EnvFilter};

use crate::persistent_log_ring::{log_ring_disabled_by_env, PersistentLogRing, RingTeeMakeWriter};

/// Unix seconds for 2020-01-01T00:00:00Z. A wall-clock reading below this means
/// the RTC is unset / SNTP (S41ntp) has not yet stepped the clock. Antminer
/// control boards have no battery-backed RTC, so they boot at the 1970 epoch —
/// a raw `SystemTime` timestamp on a fresh boot reads as `1970-01-01T..Z`, which
/// looks like a real wall-clock time but is not. Below this threshold we present
/// log times as uptime-relative instead. (P2-1 / D-18.)
const RTC_SANE_EPOCH_SECS: u64 = 1_577_836_800;

/// True when `now` is a plausible post-2020 wall-clock epoch (RTC synced).
fn rtc_looks_synced(now: SystemTime) -> bool {
    now.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() >= RTC_SANE_EPOCH_SECS)
        .unwrap_or(false)
}

/// RTC-aware log timestamp source. Once the wall clock looks real (>= 2020) it
/// prints the normal wall-clock UTC timestamp (delegating to the same
/// `tracing_subscriber` `SystemTime` formatter the daemon used before this
/// change). Until then it prints `+SSSS.mmm` seconds since process start so a
/// 1970-epoch line is never mistaken for a real date. The check is per-line, so
/// once SNTP steps the clock mid-run, subsequent lines switch to wall-clock with
/// no restart.
struct RtcAwareTimer {
    start: Instant,
}

impl RtcAwareTimer {
    fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl FormatTime for RtcAwareTimer {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        if rtc_looks_synced(SystemTime::now()) {
            // Clock looks real — emit the exact wall-clock format used before.
            tracing_subscriber::fmt::time::SystemTime.format_time(w)
        } else {
            let up = self.start.elapsed();
            write!(w, "+{}.{:03}s", up.as_secs(), up.subsec_millis())
        }
    }
}

/// Emit a one-time banner when the clock is not yet synced, so an operator
/// reading the log knows the `+SSSS.mmm` timestamps are uptime-relative rather
/// than wall-clock. Called once, right after the subscriber is installed.
fn emit_rtc_unsynced_banner_if_needed() {
    if !rtc_looks_synced(SystemTime::now()) {
        tracing::warn!(
            target: "boot",
            "log timestamps are uptime-relative (+SSSS.mmm) (no RTC / time not yet synced); \
             they switch to wall-clock automatically once SNTP (S41ntp) steps the clock"
        );
    }
}

/// DCENTRALD_LOG augments defaults with supported module shorthand. RUST_LOG
/// retains tracing's full-filter semantics when no DCENTRALD_LOG is supplied.
/// Parse the whole override strictly: malformed directives never partially apply.
fn logging_filter(level: &str, dcent: Option<&str>, rust: Option<&str>) -> (EnvFilter, bool) {
    let level = level
        .parse::<tracing::level_filters::LevelFilter>()
        .unwrap_or(tracing::level_filters::LevelFilter::INFO);
    let defaults = format!(
        "dcentrald={level},dcentrald_hal={level},dcentrald_asic={level},dcentrald_stratum={level},dcentrald_thermal={level},dcentrald_diagnostics={level},dcentrald_api={level},boot={level},hyper=warn,tower=warn,axum=warn"
    );
    let fallback = || EnvFilter::new(&defaults);
    if let Some(value) = dcent.filter(|v| !v.trim().is_empty()) {
        if value
            .trim()
            .parse::<tracing::level_filters::LevelFilter>()
            .is_ok()
        {
            return logging_filter(value.trim(), None, None);
        }
        let expanded = value
            .split(',')
            .map(|directive| {
                let directive = directive.trim();
                match directive.split_once('=') {
                    Some((module, level))
                        if matches!(
                            module.trim(),
                            "hal"
                                | "asic"
                                | "stratum"
                                | "thermal"
                                | "diagnostics"
                                | "api"
                                | "common"
                        ) =>
                    {
                        format!("dcentrald_{}={}", module.trim(), level.trim())
                    }
                    _ => directive.to_owned(),
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        // Reject an empty member too; otherwise the parser silently ignores it.
        if value.split(',').any(|v| v.trim().is_empty()) {
            return (fallback(), true);
        }
        return match EnvFilter::try_new(format!("{defaults},{expanded}")) {
            Ok(filter) => (filter, false),
            Err(_) => (fallback(), true),
        };
    }
    match rust.filter(|v| !v.trim().is_empty()) {
        Some(value) => match EnvFilter::try_new(value) {
            Ok(filter) => (filter, false),
            Err(_) => (fallback(), true),
        },
        None => (fallback(), false),
    }
}

/// Initialize the tracing subscriber with the given log level.
///
/// Sets up console output with:
/// - Timestamps (relative to process start for embedded, compact format)
/// - Module target names (shows which subsystem emitted the log)
/// - Structured key=value fields alongside human-readable messages
///
/// The env filter applies the configured level to all dcentrald crates while
/// keeping noisy dependencies (tokio, hyper, axum) at warn level.
pub fn init_logging(level: &str) -> Result<()> {
    let (env_filter, invalid_override) = logging_filter(
        level,
        std::env::var("DCENTRALD_LOG").ok().as_deref(),
        std::env::var("RUST_LOG").ok().as_deref(),
    );
    if invalid_override {
        eprintln!("dcentrald: invalid log filter; using configured defaults");
    }

    let ansi = dcentrald_common::s19k_am3_install::s19k_track1_tracing_ansi_enabled(
        std::env::var("RUST_LOG_STYLE").ok().as_deref(),
    );

    if !log_ring_disabled_by_env() {
        match PersistentLogRing::open_default() {
            Ok(ring) => {
                fmt()
                    .with_env_filter(env_filter)
                    .with_writer(RingTeeMakeWriter::new(ring))
                    .with_timer(RtcAwareTimer::new())
                    .with_ansi(ansi)
                    .with_target(true)
                    .with_thread_ids(false)
                    .with_file(false)
                    .with_line_number(false)
                    .compact()
                    .init();
                emit_rtc_unsynced_banner_if_needed();
                return Ok(());
            }
            Err(error) => {
                eprintln!(
                    "persistent log ring unavailable; continuing with stdout logging: {error:#}"
                );
            }
        }
    }

    fmt()
        .with_env_filter(env_filter)
        .with_timer(RtcAwareTimer::new())
        .with_ansi(ansi)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .init();

    emit_rtc_unsynced_banner_if_needed();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{logging_filter, rtc_looks_synced, RTC_SANE_EPOCH_SECS};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn shorthand_keeps_boot_defaults_and_overrides_only_selected_module() {
        let (filter, invalid) = logging_filter("info", Some("stratum=debug"), Some("off"));
        assert!(!invalid);
        let subscriber = tracing_subscriber::fmt().with_env_filter(filter).finish();
        tracing::subscriber::with_default(subscriber, || {
            assert!(tracing::enabled!(target: "boot", tracing::Level::INFO));
            assert!(tracing::enabled!(target: "dcentrald_stratum", tracing::Level::DEBUG));
            assert!(!tracing::enabled!(target: "dcentrald_hal", tracing::Level::DEBUG));
            assert!(!tracing::enabled!(target: "hyper", tracing::Level::INFO));
        });
    }

    #[test]
    fn bare_level_applies_to_project_and_boot_with_quiet_dependencies() {
        let (filter, invalid) = logging_filter("info", Some("debug"), None);
        assert!(!invalid);
        let subscriber = tracing_subscriber::fmt().with_env_filter(filter).finish();
        tracing::subscriber::with_default(subscriber, || {
            assert!(tracing::enabled!(target: "boot", tracing::Level::DEBUG));
            assert!(tracing::enabled!(target: "dcentrald_stratum", tracing::Level::DEBUG));
            assert!(!tracing::enabled!(target: "hyper", tracing::Level::DEBUG));
        });
    }

    #[test]
    fn malformed_override_cannot_partially_enable_wire_tracing() {
        let (filter, invalid) = logging_filter("info", Some("stratum=trace,hal=bogus"), None);
        assert!(invalid);
        let subscriber = tracing_subscriber::fmt().with_env_filter(filter).finish();
        tracing::subscriber::with_default(subscriber, || {
            assert!(tracing::enabled!(target: "boot", tracing::Level::INFO));
            assert!(!tracing::enabled!(target: "dcentrald_stratum", tracing::Level::TRACE));
        });
        assert!(logging_filter("info", Some("stratum=trace,"), None).1);
    }

    #[test]
    fn rust_log_retains_full_filter_behavior_and_empty_dcent_does_not_shadow_it() {
        let (filter, invalid) = logging_filter("info", Some(" "), Some("off"));
        assert!(!invalid);
        let subscriber = tracing_subscriber::fmt().with_env_filter(filter).finish();
        tracing::subscriber::with_default(subscriber, || {
            assert!(!tracing::enabled!(target: "boot", tracing::Level::ERROR));
        });
    }

    #[test]
    fn pre_2020_clock_reads_as_unsynced() {
        // A fresh boot with no RTC sits at (or just after) the 1970 epoch.
        assert!(!rtc_looks_synced(UNIX_EPOCH));
        assert!(!rtc_looks_synced(UNIX_EPOCH + Duration::from_secs(120)));
        // ~1999-01-01 — still pre-threshold.
        assert!(!rtc_looks_synced(
            UNIX_EPOCH + Duration::from_secs(915_148_800)
        ));
    }

    #[test]
    fn post_2020_clock_reads_as_synced() {
        // Exactly the threshold (2020-01-01) and a realistic 2026 time.
        assert!(rtc_looks_synced(
            UNIX_EPOCH + Duration::from_secs(RTC_SANE_EPOCH_SECS)
        ));
        assert!(rtc_looks_synced(
            UNIX_EPOCH + Duration::from_secs(1_780_000_000)
        ));
    }
}
