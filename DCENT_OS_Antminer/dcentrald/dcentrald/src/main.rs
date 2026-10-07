//! dcentrald - DCENTos Mining Daemon
//!
//! Entry point for the dcentrald mining daemon. Handles:
//! - Tokio async runtime initialization
//! - Signal handling (SIGTERM, SIGINT) for graceful shutdown
//! - Configuration loading from /data/dcentrald.toml
//! - Daemon lifecycle orchestration (init -> run -> shutdown)
//!
//! dcentrald is a clean rewrite, NOT a fork of any existing mining firmware.
//! 100% original D-Central codebase.

#![allow(
    dead_code,
    unused_assignments,
    unused_imports,
    unused_mut,
    unused_variables,
    clippy::doc_lazy_continuation,
    clippy::doc_overindented_list_items,
    clippy::enum_variant_names,
    clippy::too_many_arguments,
    clippy::type_complexity
)]
#![deny(unsafe_op_in_unsafe_fn)]

mod active_capacity;
mod am1_t15;
mod am2_bm1362_serial_admission;
mod am2_chain_plan;
mod am3_bb_mining;
mod asic_identity_publication;
mod autotune;
mod bm1391_admission;
mod bm1391_boot_safety;
mod bm1391_mining;
mod bm1391_mining_work;
// Declaration/config tests only until the native startup/work owner qualifies.
mod bm1396_admission;
mod bm1396_boot_safety;
// Compile fixed-domain work and CPU qualification; no native runtime route.
mod bm1396_mining_work;
mod board_sensor_coverage;
mod bounded_nonblocking_probe;
mod bridge_glue;
mod build_identity;
mod bringup;
mod c43_bm1393_mining;
mod c43_boot_safety;
mod chain;
mod config;
mod daemon;
mod firstlight_census;
mod daemon_lifecycle;
mod error;
mod execution_fence;
pub mod fpga;
mod hardware_mutation_fence;
pub mod history;
mod logging;
mod metrics_export;
mod model;
mod persistent_log_ring;
mod pic_firmware_snapshot;
mod restart;
mod runtime;
mod runtime_execution;
mod runtime_policy;
mod runtime_image_admission;
mod s17_hybrid_admission;
mod s17_hybrid_mining;
mod s19_bm1398_native_mining;
mod s19j_hybrid_admission;
mod s19j_hybrid_mining;
mod s19j_tap_mining;
mod s19k_endurance;
mod serial_mining;
#[cfg(feature = "sim-hal")]
mod sim_runtime;
mod solar;
mod stock_mining;
mod stratum_proxy;
mod terminal_io_owner;
mod voltage_mailbox;
mod wave55a_recipe_guard;
mod work_dispatcher;
mod work_ledger;

use anyhow::{Context, Result};
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::{load_error_is_definitely_absent, DcentraldConfig};
use crate::daemon::Daemon;
use crate::logging::init_logging;
use crate::s17_hybrid_mining::S17HybridMiner;
use crate::s19j_hybrid_mining::S19jHybridMiner;
use crate::s19j_tap_mining::S19jTapMiner;
use crate::serial_mining::{
    s19k_arm_permanent_pdeathsig_from_env, s19k_complete_daemon_pre_runtime_bootstrap,
    s19k_consume_guarded_completion_from_cli, s19k_durable_replace_from_cli,
    s19k_guarded_unlink_ephemeral_hardlink_from_cli, s19k_publish_ephemeral_journal_from_cli,
    s19k_track1_startup_barrier_and_acquire_j3, S19kPreRuntimeBootstrapRole,
    S19kPreRuntimeBootstrapState, S19kStockHandoffIdentity, S19kTrack1J3Lease,
    S19kTrack1ReceiptAuthority, SerialMiner,
};

/// Default configuration file path (persistent storage).
const DEFAULT_CONFIG_PATH: &str = "/data/dcentrald.toml";

/// Fallback configuration file path (read-only rootfs).
const FALLBACK_CONFIG_PATH: &str = "/etc/dcentrald.toml";

const VERIFY_BUNDLE_CAPABILITY_PATH: &str = "/data/dcentos/caps/verify-bundle";
const VERIFY_BUNDLE_CAPABILITY_BYTES: &[u8] = b"1\n";
/// The sentinel is currently two bytes. Keep a small bounded envelope for a
/// future version token without permitting accidental diagnostic payloads.
const VERIFY_BUNDLE_CAPABILITY_MAX_BYTES: usize = 16;
const FAN_CUSTODY_READY_PATH: &str = "/var/run/dcentrald-fanhold.ready";
const FAN_CUSTODY_READY_MAX_BYTES: usize = 256;
const FAN_CUSTODY_MAX_CONSECUTIVE_REFRESH_FAILURES: u8 = 3;

fn fan_custody_refresh_should_exit(consecutive_failures: &mut u8, success: bool) -> bool {
    if success {
        *consecutive_failures = 0;
        return false;
    }
    *consecutive_failures = consecutive_failures.saturating_add(1);
    *consecutive_failures >= FAN_CUSTODY_MAX_CONSECUTIVE_REFRESH_FAILURES
}

fn proc_stat_start_ticks(stat: &str) -> Option<u64> {
    let (_, after_comm) = stat.rsplit_once(") ")?;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

fn fan_custody_record(pid: u32, start_ticks: u64, boot_id: &str) -> Option<String> {
    let boot_id = boot_id.trim();
    if boot_id.is_empty()
        || !boot_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return None;
    }
    Some(format!("{pid} {start_ticks} fan-custodian {boot_id}\n"))
}

fn publish_fan_custody_ready(path: &std::path::Path) -> std::result::Result<(), String> {
    let pid = std::process::id();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|e| format!("cannot read exact process start ticks: {e}"))?;
    let start_ticks = proc_stat_start_ticks(&stat)
        .ok_or_else(|| "cannot parse exact process start ticks".to_string())?;
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|e| format!("cannot read boot identity: {e}"))?;
    let record = fan_custody_record(pid, start_ticks, &boot_id)
        .ok_or_else(|| "kernel boot identity has an invalid representation".to_string())?;
    dcentrald_common::atomic_file::atomic_write(
        path,
        record.as_bytes(),
        dcentrald_common::atomic_file::AtomicWriteOptions::state_file(FAN_CUSTODY_READY_MAX_BYTES),
    )
    .map_err(|e| format!("cannot atomically publish readiness: {e:?}"))?;
    Ok(())
}

#[derive(Debug)]
enum VerifyBundleCapabilityPublishError {
    CreateParent(std::io::Error),
    Publish(dcentrald_common::atomic_file::AtomicWriteError),
}

fn publish_verify_bundle_capability(
    path: &std::path::Path,
) -> std::result::Result<
    dcentrald_common::atomic_file::AtomicWriteOutcome,
    VerifyBundleCapabilityPublishError,
> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent).map_err(VerifyBundleCapabilityPublishError::CreateParent)?;
    dcentrald_common::atomic_file::atomic_write(
        path,
        VERIFY_BUNDLE_CAPABILITY_BYTES,
        dcentrald_common::atomic_file::AtomicWriteOptions::state_file(
            VERIFY_BUNDLE_CAPABILITY_MAX_BYTES,
        ),
    )
    .map_err(VerifyBundleCapabilityPublishError::Publish)
}

/// Auto-detect whether we should force `--s19j-hybrid` by reading
/// `/etc/bos_platform` (BraiinsOS's platform marker) or the DCENT_OS mirror
/// at `/etc/dcentos/platform`. The am2 S19j Pro image enters the
/// s19j-hybrid code path by default — if we let it fall through to the default
/// S9/BraiinsOS `Daemon::run()` path, `unbind_kernel_i2c_driver()` fires
/// and runs S9 AXI IIC devmem logic on the am2 PSU/PIC I2C bus. That is
/// precisely what  bans and is a
/// strong candidate for poisoning PSU state (see CE audit 06-ce.md #2).
///
/// Returns `(auto_enabled, detected_platform)`. Empty platform means the
/// marker file was missing — we leave CLI behavior unchanged in that case.
fn classify_s19j_hybrid_auto(platform: &str, board_target: &str) -> (bool, String) {
    let platform = platform.trim().to_string();
    let board_target = board_target.trim().to_string();
    let is_s19j_am2 =
        matches!(platform.as_str(), "zynq-bm3-am2") && is_s19j_am2_board_target(&board_target);
    let marker = if board_target.is_empty() {
        platform
    } else {
        format!("{}:{}", platform, board_target)
    };
    (is_s19j_am2, marker)
}

fn is_s19j_am2_board_target(board_target: &str) -> bool {
    let board_target = board_target.trim();
    board_target == "am2-s19j" || board_target.starts_with("am2-s19jpro")
}

/// Auto-route classifier for the S17 hybrid lane (2026-08-27 promotion).
///
/// Exact board-target tokens only — never an `am2-*` prefix (ADR-0013 §6):
/// `am2-s17p` covers S17 and S17 Pro (post-build stamp), with the historical
/// `am2-s17` spelling admitted; the plus/T variants each promote their own
/// registered descriptor. BM1362 targets never match here, and the two hybrid
/// lanes' token sets are disjoint by construction.
fn classify_s17_hybrid_auto(platform: &str, board_target: &str) -> bool {
    let platform = platform.trim();
    let board_target = board_target.trim();
    matches!(platform, "zynq-bm3-am2") && is_s17_am2_board_target(board_target)
}

fn is_s17_am2_board_target(board_target: &str) -> bool {
    let board_target = board_target.trim();
    matches!(
        board_target,
        "am2-s17p" | "am2-s17" | "am2-s17plus" | "am2-t17" | "am2-t17plus"
    )
}

/// R1 (2026-05-17): compute the am2 low-idle fan command tuple for the
/// management-only park paths.
///
/// Returns `Some((fan_idle_pwm, fan_max_pwm))` ONLY when the detected
/// platform is am2 (`zynq-bm3-am2*`). On S9/am1 + am3 returns `None` so the
/// park paths are byte-identical no-ops there (am1 fan idle is correctly
/// handled by the init-script `devmem` path; the am2 fan IP is UIO-bound and
/// devmem is a proven no-op on it — see
/// ). The gate
/// matches the codebase's existing am2 detection convention
/// (`detected_platform.starts_with("zynq-bm3-am2")`, cf. the
/// `serial_mining_mode` arm). The actual DOWN-clamp (≤ fan_max_pwm ≤
/// PWM_SAFETY_MAX) lives in `force_am2_fans_to_quiet_idle`. Live `a lab unit`
/// feedback proved this command is not acoustic proof; callers must use RPM
/// and operator confirmation for quiet claims.
fn am2_quiet_idle_tuple(detected_platform: &str, config: &DcentraldConfig) -> Option<(u8, u8)> {
    if detected_platform.starts_with("zynq-bm3-am2") {
        Some((config.thermal.fan_idle_pwm, config.thermal.fan_max_pwm))
    } else {
        None
    }
}

/// R2: pure PWM clamp for the `--set-fan` one-shot.
///
/// PWM is clamped to `PWM_SAFETY_MAX` (30) UNLESS an explicit `--allow-loud`
/// is also present (the  "explicit user
/// override to a higher mode" carve-out — the ONLY sanctioned way to exceed
/// the home cap). Even with `--allow-loud` the value is still clamped to the
/// IP ceiling `PWM_MAX` (100) — the BraiinsOS fan_ctrl IP panics on > 100.
/// Without `--allow-loud` the value is `min(PWM_SAFETY_MAX)` — only ever
/// driven DOWN relative to the 30 cap; never above it.
fn clamp_set_fan_pwm(requested: u8, allow_loud: bool) -> u8 {
    if allow_loud {
        requested.min(dcentrald_hal::fan::PWM_MAX)
    } else {
        requested
            .min(dcentrald_hal::fan::PWM_SAFETY_MAX)
            .min(dcentrald_hal::fan::PWM_MAX)
    }
}

/// Pre-everything CLI info request (`--help`/`-h`, `--version`/`-V`).
#[derive(Debug, PartialEq, Eq)]
enum CliInfoRequest {
    Help,
    Version,
}

/// Pure classifier for the CLI info one-shots.
///
/// **Defect this closes (production-readiness + safety + operability):**
/// `dcentrald` had NO help/version flag. The single most universal CLI
/// invocation — `dcentrald --help` — matched none of the one-shot or
/// mode flags and fell through into the auto-`s19j-hybrid` routing,
/// **silently starting the mining daemon**. On a *configured* production
/// unit that begins real mining from a "show me usage" command (it was
/// only fan-safe on `a lab unit` because no pool was configured →
/// management-only-idle). Every competitor firmware CLI (`bosminer
/// --help`, LuxOS) prints usage and exits. `--help` takes precedence
/// over `--version`, and BOTH take precedence over every daemon/one-shot
/// flag. Pure + deterministic so that precedence is unit-pinned
/// independently of the (HAL-bound, un-host-runnable) `main` body.
fn wants_cli_info(args: &[String]) -> Option<CliInfoRequest> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return Some(CliInfoRequest::Help);
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        return Some(CliInfoRequest::Version);
    }
    None
}

/// Every `--flag`/`-x` the `dcentrald` binary itself recognizes.
/// Value-bearing flags (the next argv is their value, NOT a flag):
/// `--set-fan <pwm>`, `--fan-sweep <list>`, `--dwell-ms <ms>`,
/// `--config <path>`. Kept in lockstep with the `== "--…"` matches in
/// `run_main` (a structural test pins that they don't drift).
const KNOWN_CLI_BOOL_FLAGS: &[&str] = &[
    "--lab-runtime",
    "--help",
    "-h",
    "--version",
    "-V",
    "--get-fan",
    "--bm1391-boot-cut-only",
    "--bm1396-boot-cut-only",
    "--c43-boot-cut-only",
    "--allow-loud",
    "--s19j-hybrid",
    "--s17-hybrid",
    "--serial-mining",
    "--bm1366-native-no-work",
    "--tap-mode",
    "--stratum-proxy",
    "--am3-bb-mining",
    "--stock-fpga",
    "--safe-off",
    "--s19k-track1-recovery-safeoff",
    "--s19k-install-custody-safeoff",
    "--s19k-track1-no-work",
    "--s19k-track1-bounded-work-proof",
    "--s19k-track1-endurance-work-proof",
];
const KNOWN_CLI_VALUE_FLAGS: &[&str] = &[
    "--firstlight-census",
    "--firstlight-work",
    "--firstlight-seconds",
    "--check-firstlight-idle-config",
    "--check-software-closeout",
    "--set-fan",
    "--hold-fan",
    "--fan-sweep",
    "--dwell-ms",
    "--config",
    "--verify-bundle",
    "--s19k-bosminer-pid",
    "--s19k-bosminer-start",
    "--s19k-bosminer-ppid",
    "--s19k-bosminer-pgrp",
    "--s19k-bosminer-session",
    "--s19k-bosminer-exe",
    "--s19k-bosminer-cmdline-sha256",
    "--s19k-bosminer-cmdline-bytes",
    "--s19k-bos-tools-pid",
    "--s19k-bos-tools-start",
    "--s19k-bos-tools-ppid",
    "--s19k-bos-tools-pgrp",
    "--s19k-bos-tools-session",
    "--s19k-bos-tools-exe",
    "--s19k-bos-tools-cmdline-sha256",
    "--s19k-bos-tools-cmdline-bytes",
    "--s19k-track1-runtime-active",
    "--s19k-stock-owner-retained-receipt",
    "--s19k-track1-journal-source",
    "--s19k-track1-journal-destination",
    "--s19k-track1-guarded-unlink-scratch",
    "--s19k-track1-guarded-unlink-canonical",
    "--s19k-track1-guarded-unlink-claim",
    "--s19k-track1-guarded-unlink-completion",
    "--s19k-track1-consume-completion",
    "--s19k-track1-durable-replace-source",
    "--s19k-track1-durable-replace-destination",
    "--s19k-track1-durable-replace-old-sha256",
    "--s19k-track1-durable-replace-old-bytes",
    "--s19k-track1-durable-replace-new-sha256",
    "--s19k-track1-durable-replace-new-bytes",
];

/// Pure detector for **unrecognized** `-`/`--` flags.
///
/// **Defect this surfaces (same class as the missing `--help` handler):**
/// `dcentrald` matched flags with `args.iter().any(|a| a == "--x")` and
/// did NO unknown-flag validation — so a typo like `--gte-fan` (for
/// `--get-fan`) or any unrecognized flag fell through every check into
/// auto-`s19j-hybrid` and **silently started the mining daemon**. That
/// is exactly the failure mode that caused the 2026-05-19 `a lab unit`
/// over-spawn (a flag the binary did not recognize → silent daemonize)
/// and is dangerous on a fragile home unit.
///
/// **Wave C (2026-05-19): strict-reject ENABLED.** Returned non-empty
/// ⇒ the caller emits a loud error, dumps `cli_help_text()`, and exits
/// with code 2. G-T8-1 was closed in Wave B (commit `5aaae39f` removed
/// the only known offender, `--passthrough`, from the 3 production
/// deploy scripts; the canonical 16-flag set at
/// `KNOWN_CLI_BOOL_FLAGS` + `KNOWN_CLI_VALUE_FLAGS` is now exhaustive
/// across every production launcher site — see
/// ).
/// The previous deferred-TODO non-blocking warning is gone: silent
/// daemonization on a typo'd flag was the `a lab unit` over-spawn pattern,
/// and this strict-reject is what closes that defect class.
/// `argv[0]` and the value token after a value-bearing flag are skipped.
fn unrecognized_cli_flags(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = args.iter().skip(1).peekable();
    while let Some(arg) = iter.next() {
        if KNOWN_CLI_VALUE_FLAGS.iter().any(|f| f == arg) {
            iter.next(); // consume this flag's value token
            continue;
        }
        if KNOWN_CLI_BOOL_FLAGS.iter().any(|f| f == arg) {
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            out.push(arg.clone());
        }
        // Non-`-` tokens are stray positionals; conservatively ignored
        // (could be a value the existing positional logic still picks
        // up) — only `-`/`--` look-alikes are the dangerous typo case.
    }
    out
}

fn single_cli_value(args: &[String], flag: &str) -> Result<Option<String>> {
    let mut values = args
        .windows(2)
        .filter(|window| window[0] == flag)
        .map(|window| window[1].clone());
    let value = values.next();
    anyhow::ensure!(values.next().is_none(), "{flag} may be supplied only once");
    if args.last().map(String::as_str) == Some(flag) {
        anyhow::bail!("{flag} requires a value");
    }
    Ok(value)
}

fn parse_s19k_stock_handoff_cli(args: &[String]) -> Result<Option<S19kStockHandoffIdentity>> {
    const FLAGS: [&str; 16] = [
        "--s19k-bos-tools-pid",
        "--s19k-bos-tools-start",
        "--s19k-bos-tools-ppid",
        "--s19k-bos-tools-pgrp",
        "--s19k-bos-tools-session",
        "--s19k-bos-tools-exe",
        "--s19k-bos-tools-cmdline-sha256",
        "--s19k-bos-tools-cmdline-bytes",
        "--s19k-bosminer-pid",
        "--s19k-bosminer-start",
        "--s19k-bosminer-ppid",
        "--s19k-bosminer-pgrp",
        "--s19k-bosminer-session",
        "--s19k-bosminer-exe",
        "--s19k-bosminer-cmdline-sha256",
        "--s19k-bosminer-cmdline-bytes",
    ];
    let values = FLAGS
        .iter()
        .map(|flag| single_cli_value(args, flag))
        .collect::<Result<Vec<_>>>()?;
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    anyhow::ensure!(
        values.iter().all(Option::is_some),
        "S19k stock handoff requires the complete supervisor+child process-tree CLI tuple"
    );
    let values = values
        .into_iter()
        .map(|value| value.expect("complete tuple checked above"))
        .collect::<Vec<_>>();
    Ok(Some(S19kStockHandoffIdentity::from_cli(
        &values[0],
        &values[1],
        &values[2],
        &values[3],
        &values[4],
        &values[5],
        &values[6],
        &values[7],
        &values[8],
        &values[9],
        &values[10],
        &values[11],
        &values[12],
        &values[13],
        &values[14],
        &values[15],
    )?))
}

fn parse_s19k_track1_receipt_authority_cli(
    args: &[String],
) -> Result<Option<S19kTrack1ReceiptAuthority>> {
    let active = single_cli_value(args, "--s19k-track1-runtime-active")?;
    let retained = single_cli_value(args, "--s19k-stock-owner-retained-receipt")?;
    match (active, retained) {
        (None, None) => Ok(None),
        (Some(active), Some(retained)) => Ok(Some(S19kTrack1ReceiptAuthority::from_cli(
            &active, &retained,
        )?)),
        _ => anyhow::bail!(
            "S19k Track-1 receipt authority requires both runtime_active and retained-receipt paths"
        ),
    }
}

/// Concise usage for the `--help` one-shot. Lists the safety-relevant
/// read-only fan one-shots first (an operator reaching for `--help` on a
/// fragile home unit must see these), then the bring-up modes, and is
/// explicit that bare `dcentrald` auto-detects the platform and starts
/// the mining daemon.
fn cli_help_text() -> String {
    format!(
        "dcentrald {ver} — DCENT_OS · D-Central Technologies, the Mining Hackers · https://d-central.tech · GPL-3.0\n\
         \n\
         USAGE:\n\
         \x20 dcentrald [FLAGS]      (no flag = auto-detect platform, start the mining daemon)\n\
         \n\
         READ-ONLY / SAFETY ONE-SHOTS (no daemon, no mining, exit immediately):\n\
         \x20 --help, -h            print this help and exit\n\
         \x20 --version, -V         print the version and exit\n\
         \x20 --get-fan             read-only fan PWM/RPM snapshot (key=value), exit\n\
         \x20 --bm1391-boot-cut-only park exact S15/T15 source GPIO high, exit\n\
         \x20 --bm1396-boot-cut-only park S17e/T17e GPIO high and both quiet PWMs, exit\n\
         \x20 --c43-boot-cut-only park S9 SE/S9k resets/PIC off and quiet PWM, exit\n\
         \x20 --set-fan <0-100>     command fan PWM once (clamped to {cap} unless --allow-loud), exit\n\
         \x20 --hold-fan <0-100>    PERSISTENT fan custodian: park PWM + re-assert every ~5s until\n\
         \x20                       SIGTERM (clamped to {cap} unless --allow-loud). Required on AM2:\n\
         \x20                       the board reverts fans to full speed if nothing keeps commanding them.\n\
         \x20 --fan-sweep <list>    diagnostic fan-PWM sweep (e.g. 0,5,10,15,20,25,30); [--dwell-ms N]\n\
         \x20 --allow-loud          explicit authority for fan one-shots or S19k Track-1 PWM above the {cap} home cap\n\
         \x20 --s19k-track1-recovery-safeoff\n\
         \x20                       ephemeral config-bound checked reset+S19k power-cut receipt; runner recovery only\n\
         \x20 --s19k-install-custody-safeoff\n\
         \x20                       exact receipt-bound stock custody transfer directly to checked GPIO437 SafeOff; no pool, UART, reset, ASIC, or mining work\n\
         \x20 --s19k-track1-no-work\n\
         \x20                       exact receipt-bound S19k handoff/enumeration mode; pool jobs discarded and UART work refused\n\
         \x20 --s19k-track1-bounded-work-proof\n\
         \x20                       exact receipt-bound S19k work proof; every admitted TX/RX is logged and the run closes after one accepted share per required UART or 600s\n\
         \x20 --s19k-track1-endurance-work-proof\n\
         \x20                       exact receipt-bound S19k 24h endurance proof; hash-chained minute segments require off-target collector acknowledgements and fail closed by 26h\n\
         \n\
         BRING-UP MODES (start a daemon):\n\
         \x20 (default)             auto-detect; am2/XIL auto-routes to --s19j-hybrid\n\
         \x20 --s19j-hybrid         am2 Zynq S19/S19j Pro hybrid bring-up\n\
         \x20 --serial-mining       Amlogic / serial BM1362 path\n\
         \x20 --bm1366-native-no-work\n\
         \x20                       with --serial-mining: S19k/XP native init energizes hardware, then cuts power and exits; no pool or work\n\
         \x20 --am3-bb-mining       AM335x BeagleBone S19j Pro path\n\
         \x20 --tap-mode            FPGA work-dispatch only (bosminer owns HW)\n\
         \x20 --stratum-proxy       Stratum V1 byte-relay only (zero HW access)\n\
         \x20 --stock-fpga          stock-Bitmain FPGA bitstream mode\n\
         \n\
         {lab}LOGGING ENVIRONMENT:\n\
         \x20 DCENTRALD_LOG         module overrides, e.g. stratum=debug,hal=info (preserves boot defaults)\n\
         \x20 RUST_LOG              full tracing filter when DCENTRALD_LOG is unset\n\
         \n\
         Docs + recovery: https://d-central.tech  |  config: /data/dcentrald.toml\n\
         Fund / Donate / Support: https://d-central.tech/fund/\n",
        ver = env!("CARGO_PKG_VERSION"),
        cap = dcentrald_hal::fan::PWM_SAFETY_MAX,
        lab = if cfg!(feature = "lab") {
            "LABORATORY BUILD:\n  --lab-runtime          explicitly use lab runtime admission; never a release image\n\n"
        } else { "" },
    )
}

/// R2: discover the fan-control UIO device by NAME.
///
/// Scans `/sys/class/uio/uio*/name`. Returns `(uio_number, variant)`:
///   - the uio whose name is `fan-control` is the fan IP;
///   - if a `board-control` UIO also exists ⇒ this is an am2 unit ⇒
///     `FanVariant::Am2Uio16` (the 4-fan am2 layout);
///   - otherwise it's an am1-s9 unit ⇒ `FanVariant::Am1S9`.
///
/// Name-based (not number-based) discovery so it is robust across kernel UIO
/// enumeration order. Returns `None` if no `fan-control` UIO is present
/// (defined failure → exit 1 for the init script). Synchronous filesystem
/// reads only — no device is opened here.
fn discover_fan_uio() -> Option<(u8, dcentrald_hal::fan::FanVariant)> {
    dcentrald_hal::fan::discover_fan_uio()
        .map(|discovery| (discovery.uio_number, discovery.variant))
}

fn format_fan_pairs(pairs: &[(u8, u32)]) -> String {
    pairs
        .iter()
        .map(|(fan_id, value)| format!("{}:{}", fan_id, value))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_fan_raw_registers(regs: &[dcentrald_hal::fan::FanRawRegister]) -> String {
    regs.iter()
        .map(|reg| format!("0x{:02X}:0x{:08X}", reg.offset, reg.value))
        .collect::<Vec<_>>()
        .join(",")
}

fn am2_low_pwm_floor_present(
    variant: dcentrald_hal::fan::FanVariant,
    pwm: u8,
    max_rpm: u32,
) -> bool {
    matches!(variant, dcentrald_hal::fan::FanVariant::Am2Uio16)
        && pwm <= dcentrald_hal::fan::PWM_QUIET_BOOT
        && max_rpm >= 2_000
}

fn print_fan_snapshot(
    label: &str,
    discovery: dcentrald_hal::fan::FanUioDiscovery,
    fan: &dcentrald_hal::fan::FanController,
    requested_pwm: Option<u8>,
    include_raw_regs: bool,
) -> (u8, u32) {
    let (commanded_pwm0, commanded_pwm1) = fan.get_speed_pwm_channels();
    let (raw_pwm0, raw_pwm1) = fan.get_speed_pwm_raw_channels();
    let commanded_pwm = commanded_pwm0.max(commanded_pwm1);
    let raw_rps = fan.get_raw_rps_channels();
    let per_fan_rpm = fan.get_per_fan_rpm();
    let max_rpm = per_fan_rpm.iter().map(|(_, rpm)| *rpm).max().unwrap_or(0);
    let raw_rps_text = format_fan_pairs(&raw_rps);
    let per_fan_text = format_fan_pairs(&per_fan_rpm);
    let front_fan_surface_attached = fan.has_front_fan_surface();
    let am2_c52_fan_mode = fan
        .am2_c52_fan_mode_status()
        .map(|s| format!("uio{}:0x{:08X}->0x{:08X}", s.uio_number, s.before, s.after))
        .unwrap_or_else(|| "none".to_string());
    let requested_pwm = requested_pwm
        .map(|p| p.to_string())
        .unwrap_or_else(|| "none".to_string());

    if include_raw_regs {
        let raw_regs = fan.raw_register_dump();
        let raw_regs_text = format_fan_raw_registers(&raw_regs);
        println!(
            "dcentrald {label}: uio={} variant={:?} requested_pwm={} commanded_pwm={} commanded_pwm0={} commanded_pwm1={} am2_c52_fan_mode={} front_fan_surface_attached={} raw_pwm0=0x{:08X} raw_pwm1=0x{:08X} max_rpm={} raw_rps=[{}] per_fan_rpm=[{}] raw_regs=[{}]",
            discovery.uio_number,
            discovery.variant,
            requested_pwm,
            commanded_pwm,
            commanded_pwm0,
            commanded_pwm1,
            am2_c52_fan_mode,
            front_fan_surface_attached,
            raw_pwm0,
            raw_pwm1,
            max_rpm,
            raw_rps_text,
            per_fan_text,
            raw_regs_text
        );
    } else {
        println!(
            "dcentrald {label}: uio={} variant={:?} requested_pwm={} commanded_pwm={} commanded_pwm0={} commanded_pwm1={} am2_c52_fan_mode={} front_fan_surface_attached={} raw_pwm0=0x{:08X} raw_pwm1=0x{:08X} max_rpm={} raw_rps=[{}] per_fan_rpm=[{}]",
            discovery.uio_number,
            discovery.variant,
            requested_pwm,
            commanded_pwm,
            commanded_pwm0,
            commanded_pwm1,
            am2_c52_fan_mode,
            front_fan_surface_attached,
            raw_pwm0,
            raw_pwm1,
            max_rpm,
            raw_rps_text,
            per_fan_text
        );
    }

    (commanded_pwm, max_rpm)
}

/// R2: the `--set-fan <PWM>` one-shot body. Returns the process exit code.
///
/// SAFETY: this is intentionally a synchronous open→write→readback→exit on
/// the fan register ONLY. It performs NO PIC/PSU/ASIC/I2C/voltage access and
/// builds NO tokio HW runtime. It cannot raise PWM above `PWM_SAFETY_MAX`
/// (30) unless the caller passes explicit `--allow-loud` (and even then
/// never above the IP ceiling 100). This is the am2-correct replacement for
/// the init script's `devmem` fan write (a proven no-op on the UIO-bound am2
/// fan IP). am1-s9 keeps its devmem path in the init scripts; this one-shot
/// works on both variants when invoked.
fn run_set_fan_oneshot(pwm_arg: Option<&str>, allow_loud: bool) -> i32 {
    let Some(pwm_str) = pwm_arg else {
        eprintln!(
            "dcentrald --set-fan: missing PWM argument (usage: --set-fan <0-100> [--allow-loud])"
        );
        return 2;
    };
    let Ok(requested) = pwm_str.parse::<u8>() else {
        eprintln!(
            "dcentrald --set-fan: invalid PWM '{}' — must be a non-negative integer 0-255",
            pwm_str
        );
        return 2;
    };
    let pwm = clamp_set_fan_pwm(requested, allow_loud);
    if pwm != requested {
        eprintln!(
            "dcentrald --set-fan: clamped requested PWM {} -> {} (allow_loud={}; PWM_SAFETY_MAX={}, PWM_MAX={})",
            requested,
            pwm,
            allow_loud,
            dcentrald_hal::fan::PWM_SAFETY_MAX,
            dcentrald_hal::fan::PWM_MAX
        );
    }

    let Some((uio, variant)) = discover_fan_uio() else {
        eprintln!(
            "dcentrald --set-fan: no 'fan-control' UIO found under /sys/class/uio — cannot set fan PWM"
        );
        return 1;
    };

    let board_target = std::fs::read_to_string("/etc/dcentos/board_target").unwrap_or_default();
    let mode_policy = am2_fan_mode_policy_for_board_target(&board_target);
    match dcentrald_hal::fan::FanController::open_with_variant_and_mode_policy(
        uio,
        variant,
        mode_policy,
    ) {
        Ok(fan) => {
            fan.set_speed(pwm);
            let discovery = dcentrald_hal::fan::FanUioDiscovery {
                uio_number: uio,
                variant,
                has_board_control: matches!(variant, dcentrald_hal::fan::FanVariant::Am2Uio16),
            };
            let (commanded_pwm, max_rpm) =
                print_fan_snapshot("--set-fan", discovery, &fan, Some(pwm), false);
            if am2_low_pwm_floor_present(variant, pwm, max_rpm) {
                eprintln!(
                    "dcentrald --set-fan: AM2 low-PWM floor detected (requested={}, commanded_pwm={}, max_rpm={}); register write succeeded but the physical fan floor/failsafe is still loud",
                    pwm, commanded_pwm, max_rpm
                );
            }
            // AM2 (XIL Zynq) fan PWM is held only while a process owns the
            // uio16 mmap AND keeps re-commanding it; once this one-shot exits,
            // the board's fan IP drifts the fans back to its full-speed default.
            // For a persistent AM2 hold use `--hold-fan <PWM>` (stays resident,
            // re-asserts every ~5 s until SIGTERM). See
            // .
            if matches!(variant, dcentrald_hal::fan::FanVariant::Am2Uio16) {
                eprintln!(
                    "dcentrald --set-fan: NOTE — on AM2 this write does NOT persist after exit (the board reverts fans to full speed once no process keeps commanding the uio16 mmap). Use `--hold-fan {}` for a persistent custodian.",
                    pwm
                );
            }
            0
        }
        Err(e) => {
            eprintln!(
                "dcentrald --set-fan: failed to open fan-control uio{} ({:?}): {}",
                uio, variant, e
            );
            1
        }
    }
}

/// `--hold-fan <PWM>` PERSISTENT fan custodian. Returns the process exit code
/// on SIGTERM/SIGINT or after bounded periodic custody failures revoke its
/// readiness receipt.
///
/// WHY THIS EXISTS (home-safety, AM2):
/// On AM2 (XIL Zynq) the fan PWM is held only while a process owns the uio16
/// mmap AND keeps re-commanding it. `--set-fan` writes the register once and
/// EXITS — so the board's fan IP drifts the fans back to its full-speed default,
/// blasting a home unit (observed: `--set-fan 10` then minutes later PWM 100 /
/// 6180 RPM). mmap-hold alone is NOT enough either: a daemon that wrote PWM once
/// and only held the mmap still drifted; the ~5 s re-assert is the cure. This
/// custodian parks the fan, then STAYS RESIDENT re-asserting the PWM every ~5 s.
/// Exact S19-family identity also reasserts the proven C52 mode; S17 and
/// ambiguous AM2 identity preserve the existing board mode. The process holds
/// custody until SIGTERM/SIGINT.
/// and `park_management_only_until_shutdown` (the proven in-process park path
/// this reuses).
///
/// SAFETY: PWM is only ever driven DOWN — clamped to `PWM_SAFETY_MAX` (30)
/// unless explicit `--allow-loud` (identical clamp to `--set-fan`), and even
/// then never above the IP ceiling `PWM_MAX` (100). No PIC/PSU/ASIC/I2C/voltage
/// access; fan-control UIO only. The 5 s re-assert uses the exact board-target
/// mode policy and verifies both PWM-channel readbacks. On non-AM2 variants
/// the board's fan registers/sysfs hold on their own, so the re-assert is
/// harmless redundancy — kept uniform for simplicity (a single park + 5 s
/// re-assert + SIGTERM-block path for all variants).
///
/// SIGTERM-RESPONSIVE: a `tokio::select!` races the 5 s interval tick against
/// SIGTERM/SIGINT, so a signal is acted on immediately (the init-script `stop`
/// path kills this custodian by its pidfile). Logs the initial park at `info`,
/// the periodic refreshes at `debug`. Exit codes: 0 = parked + held then clean
/// signal exit; 1 = fan-control UIO discovery/open failed; 2 = bad/missing PWM.
async fn run_hold_fan(pwm_arg: Option<&str>, allow_loud: bool) -> i32 {
    let Some(pwm_str) = pwm_arg else {
        eprintln!(
            "dcentrald --hold-fan: missing PWM argument (usage: --hold-fan <0-100> [--allow-loud])"
        );
        return 2;
    };
    let Ok(requested) = pwm_str.parse::<u8>() else {
        eprintln!(
            "dcentrald --hold-fan: invalid PWM '{}' — must be a non-negative integer 0-255",
            pwm_str
        );
        return 2;
    };
    let pwm = clamp_set_fan_pwm(requested, allow_loud);
    if pwm != requested {
        eprintln!(
            "dcentrald --hold-fan: clamped requested PWM {} -> {} (allow_loud={}; PWM_SAFETY_MAX={}, PWM_MAX={})",
            requested,
            pwm,
            allow_loud,
            dcentrald_hal::fan::PWM_SAFETY_MAX,
            dcentrald_hal::fan::PWM_MAX
        );
    }

    let Some((uio, variant)) = discover_fan_uio() else {
        eprintln!(
            "dcentrald --hold-fan: no 'fan-control' UIO found under /sys/class/uio — cannot hold fan PWM"
        );
        return 1;
    };

    let is_am2 = matches!(variant, dcentrald_hal::fan::FanVariant::Am2Uio16);
    let board_target = std::fs::read_to_string("/etc/dcentos/board_target").unwrap_or_default();
    let mode_policy = am2_fan_mode_policy_for_board_target(&board_target);

    // Initial park (open → write → dual-channel readback). On a clean open
    // failure we exit 1 (the caller — init script — treats that as a real
    // failure). C52 is enabled only for exact S19-family board targets; S17 and
    // unknown targets preserve the board's existing mode.
    match dcentrald_hal::fan::FanController::open_with_variant_and_mode_policy(
        uio,
        variant,
        mode_policy,
    ) {
        Ok(fan) => {
            fan.set_speed(pwm);
            let discovery = dcentrald_hal::fan::FanUioDiscovery {
                uio_number: uio,
                variant,
                has_board_control: is_am2,
            };
            print_fan_snapshot(
                "--hold-fan (initial park)",
                discovery,
                &fan,
                Some(pwm),
                false,
            );
            let (commanded_pwm0, commanded_pwm1) = fan.get_speed_pwm_channels();
            if commanded_pwm0 != pwm || commanded_pwm1 != pwm {
                eprintln!(
                    "dcentrald --hold-fan: initial PWM readback mismatch (requested={}, pwm0={}, pwm1={})",
                    pwm, commanded_pwm0, commanded_pwm1
                );
                return 1;
            }
            // Drop `fan` here: the periodic re-assert reopens the controller
            // with the same exact board-target policy, then re-clamps and
            // verifies both PWM channels.
        }
        Err(e) => {
            eprintln!(
                "dcentrald --hold-fan: failed to open fan-control uio{} ({:?}): {}",
                uio, variant, e
            );
            return 1;
        }
    }

    info!(
        pwm,
        uio,
        variant = ?variant,
        is_am2,
        allow_loud,
        "dcentrald --hold-fan: persistent fan custodian started — parked PWM \
         and will re-assert it every ~5 s until SIGTERM (prevents the AM2 board \
         fan-controller revert to full speed)"
    );

    // Persistent custodian: re-assert the PWM every ~5 s until SIGTERM/SIGINT.
    // PWM is only ever driven DOWN (the requested setpoint was already clamped).
    // The 5 s cadence + SIGTERM race exactly mirror the proven management-only
    // custodian, while bounded failures revoke readiness instead of preserving
    // a stale claim of custody.
    const FAN_REFRESH: std::time::Duration = std::time::Duration::from_secs(5);
    let mut refresh = tokio::time::interval(FAN_REFRESH);
    // First tick fires immediately; skip-then-wait so we don't double the entry
    // park we just performed.
    refresh.tick().await;
    let mut consecutive_refresh_failures = 0u8;

    if let Err(e) = publish_fan_custody_ready(std::path::Path::new(FAN_CUSTODY_READY_PATH)) {
        eprintln!("dcentrald --hold-fan: {e}");
        return 1;
    }

    let mut sigterm = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "dcentrald --hold-fan: failed to register SIGTERM handler: {} — holding via SIGINT only",
                e
            );
            // Degrade to SIGINT-only rather than dropping the custodian.
            loop {
                tokio::select! {
                    _ = signal::ctrl_c() => break,
                    _ = refresh.tick() => {
                        let success = hold_fan_reassert(pwm, mode_policy);
                        if fan_custody_refresh_should_exit(&mut consecutive_refresh_failures, success) {
                            let _ = std::fs::remove_file(FAN_CUSTODY_READY_PATH);
                            eprintln!(
                                "dcentrald --hold-fan: persistent PWM custody failed {} consecutive refreshes; readiness revoked",
                                consecutive_refresh_failures
                            );
                            return 1;
                        }
                    },
                }
            }
            let _ = std::fs::remove_file(FAN_CUSTODY_READY_PATH);
            info!("dcentrald --hold-fan: received SIGINT, releasing fan custodian (clean exit)");
            return 0;
        }
    };

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("dcentrald --hold-fan: received SIGINT, releasing fan custodian (clean exit)");
                break;
            }
            _ = sigterm.recv() => {
                info!("dcentrald --hold-fan: received SIGTERM, releasing fan custodian (clean exit)");
                break;
            }
            _ = refresh.tick() => {
                let success = hold_fan_reassert(pwm, mode_policy);
                if fan_custody_refresh_should_exit(&mut consecutive_refresh_failures, success) {
                    let _ = std::fs::remove_file(FAN_CUSTODY_READY_PATH);
                    eprintln!(
                        "dcentrald --hold-fan: persistent PWM custody failed {} consecutive refreshes; readiness revoked",
                        consecutive_refresh_failures
                    );
                    return 1;
                }
            },
        }
    }
    let _ = std::fs::remove_file(FAN_CUSTODY_READY_PATH);
    0
}

/// One periodic re-assert tick for `--hold-fan`. Exact S19-family targets use
/// the proven C52 + idle-clamp path; S17 and unknown targets preserve the
/// board's existing fan mode. Every path verifies both PWM-channel readbacks.
/// A failed tick is tolerated, but bounded consecutive failures cause the
/// caller to revoke readiness and exit. Logs successful refreshes at `debug`.
fn hold_fan_reassert(pwm: u8, mode_policy: dcentrald_hal::fan::Am2FanModePolicy) -> bool {
    if matches!(mode_policy, dcentrald_hal::fan::Am2FanModePolicy::EnableC52) {
        tracing::debug!(
            pwm,
            "dcentrald --hold-fan: re-asserting AM2 fan PWM (C52 + idle re-clamp)"
        );
        // Pass `pwm` as both the idle and the cap so `compute_quiet_idle_pwm`
        // resolves to exactly `pwm` (already clamped ≤ 30 unless --allow-loud,
        // which raised the value before this point but never above PWM_MAX).
        return hold_fan_reassert_open(pwm, mode_policy);
    }
    hold_fan_reassert_open(pwm, mode_policy)
}

fn hold_fan_reassert_open(pwm: u8, mode_policy: dcentrald_hal::fan::Am2FanModePolicy) -> bool {
    // Non-AM2: harmless redundant re-command (registers/sysfs already hold).
    match discover_fan_uio() {
        Some((uio, variant)) => {
            match dcentrald_hal::fan::FanController::open_with_variant_and_mode_policy(
                uio,
                variant,
                mode_policy,
            ) {
                Ok(fan) => {
                    fan.set_speed(pwm);
                    let (pwm0, pwm1) = fan.get_speed_pwm_channels();
                    tracing::debug!(
                        pwm,
                        uio,
                        "dcentrald --hold-fan: re-asserted fan PWM (non-AM2)"
                    );
                    if pwm0 != pwm || pwm1 != pwm {
                        tracing::warn!(
                            requested_pwm = pwm,
                            pwm0,
                            pwm1,
                            uio,
                            "dcentrald --hold-fan: periodic PWM readback mismatch"
                        );
                        return false;
                    }
                    true
                }
                Err(e) => {
                    tracing::warn!(
                        pwm,
                        uio,
                        error = %e,
                    "dcentrald --hold-fan: re-assert open failed (non-AM2) — custodian continues"
                    );
                    false
                }
            }
        }
        None => {
            tracing::warn!(
                pwm,
            "dcentrald --hold-fan: re-assert found no fan-control UIO (non-AM2) — custodian continues"
            );
            false
        }
    }
}

/// `--safe-off` quiet-idle fan PWM. Only ever driven DOWN and clamped to
/// `PWM_SAFETY_MAX` (30); the chips are de-energized first so this is a quiet
/// cooldown setpoint, not a thermal response.
const SAFE_OFF_FAN_PWM: u8 = 10;

/// Platform → power-cut action mapping for `--safe-off`. Pure + unit-tested so
/// the per-platform dispatch is verified without touching hardware (Wave-B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SafeOffCut {
    /// am2 Zynq (S19/S19j, incl. .25/.109/.139): drive PWR_CONTROL gpio907 low —
    /// the audited home-hard-stop cut (`s19j_hybrid_mining::force_pwr_control_low`).
    Am2PwrControl,
    /// Amlogic A113D (S21 / S19k / S19jpro-aml).
    AmlogicDisablePsu,
    /// AM335x BeagleBone (am3-bb).
    BeagleboneDisablePsu,
    /// am1 S9 + other Zynq.
    ZynqDisablePsu,
    /// Unknown platform string — power is NOT cut (honest; never a false affordance).
    Unknown,
}

/// Map `/etc/dcentos/platform` to the correct `--safe-off` power-cut action.
/// Pure (string → enum) so it is unit-testable. Order matters: the am2
/// fingerprint (`zynq-bm3-am2`) MUST be checked before the generic `zynq` arm.
fn safe_off_cut_for_platform(platform: &str) -> SafeOffCut {
    let p = platform.trim();
    if p.starts_with("zynq-bm3-am2") {
        SafeOffCut::Am2PwrControl
    } else if p.starts_with("amlogic") || p.contains("am3-aml") || p.contains("a113d") {
        SafeOffCut::AmlogicDisablePsu
    } else if p.starts_with("am3-bb") || p.contains("beaglebone") || p.contains("am335x") {
        SafeOffCut::BeagleboneDisablePsu
    } else if p.contains("cvitek") || p.contains("cv1835") {
        // CV1835 has no admitted runtime or verified power-control contract.
        SafeOffCut::Unknown
    } else if p.starts_with("zynq") {
        SafeOffCut::ZynqDisablePsu
    } else {
        SafeOffCut::Unknown
    }
}

/// Board-mode policy for the AM2 fan step of `--safe-off`.
///
/// Four-channel fan topology does not authorize the separate C49/C52
/// board-control mutation. Only exact S19-family product identity opts into
/// the held C52 behavior; S17 and missing/ambiguous identity preserve mode.
fn am2_fan_mode_policy_for_board_target(
    board_target: &str,
) -> dcentrald_hal::fan::Am2FanModePolicy {
    use dcentrald_hal::fan::Am2FanModePolicy;

    match board_target.trim() {
        "am2-s19" | "am2-s19j" | "am2-s19jpro" | "am2-s19jpro-zynq" | "am2-s19pro" | "am2-t19" => {
            Am2FanModePolicy::EnableC52
        }
        _ => Am2FanModePolicy::Preserve,
    }
}

/// `--safe-off` one-shot (Wave-B no-brick): an OPERATOR-INVOKED emergency power
/// cut. Cuts ASIC power FIRST (platform-dispatched to the audited per-platform
/// cut), then commands fans to a safe quiet idle (cut-hash-before-noise). Like
/// `--set-fan` it runs BEFORE config/logging/mode routing and touches only the
/// power-cut + fan paths — no tokio HW runtime, no mining, no EEPROM. It is a
/// NEW opt-in subcommand: it cannot alter the normal daemon path. Exit codes:
///   0 = power cut + fans set quiet; 1 = a cut/fan step failed or platform unknown.
async fn run_safe_off_oneshot() -> i32 {
    let platform = std::fs::read_to_string("/etc/dcentos/platform").unwrap_or_default();
    let board_target = std::fs::read_to_string("/etc/dcentos/board_target").unwrap_or_default();
    let cut = safe_off_cut_for_platform(&platform);
    let platform_disp = platform.trim();
    eprintln!(
        "dcentrald --safe-off: platform='{}' -> cut={:?} (cutting ASIC power first, then fans to quiet idle)",
        platform_disp, cut
    );
    let mut rc = 0;

    // 1. Cut ASIC power (the load-bearing safety action) — audited per-platform.
    match cut {
        SafeOffCut::Am2PwrControl => {
            // Emergency cut-only composition uses the signed board recipe.
            // A mutable marker alone cannot choose an AM2 electrical polarity.
            let recipe = async {
                use dcentrald_common::runtime_hardware_recipe::{HardwareRecipeProfile, RuntimeHardwareRecipe};
                let identity = crate::daemon::capture_system_platform_identity()?;
                let board = identity.board_desc.context("SafeOff requires an exact AM2 board target")?;
                let s17 = matches!(board.board_target, "am2-s17p" | "am2-s17plus" | "am2-t17" | "am2-t17plus");
                let profile = if dcentrald_common::lab_env::compiled() {
                    HardwareRecipeProfile::BoardDefault
                } else {
                    dcentrald_api::runtime_image::verify_installed_runtime_image(
                        board.board_target, env!("CARGO_PKG_VERSION"))
                        .await.map_err(anyhow::Error::msg)?.hardware_recipe()
                };
                let recipe = RuntimeHardwareRecipe::resolve(board, &identity.observed_control_board,
                    if s17 { "s17-hybrid" } else { "s19j-hybrid" }, profile)
                    .map_err(anyhow::Error::msg)?;
                dcentrald_common::runtime_hardware_recipe::install(recipe).map_err(anyhow::Error::msg)
            }.await;
            if let Err(error) = recipe {
                eprintln!("dcentrald --safe-off: AM2 wiring could not be resolved: {error}");
                rc = 1;
            } else if let Err(e) =
                s19j_hybrid_mining::force_pwr_control_low_checked(Some("907"), "cli-safe-off")
            {
                eprintln!("dcentrald --safe-off: AM2 PWR_CONTROL cut failed: {}", e);
                rc = 1;
            }
        }
        SafeOffCut::AmlogicDisablePsu => {
            if let Err(e) = dcentrald_hal::platform::amlogic::disable_psu() {
                eprintln!("dcentrald --safe-off: amlogic disable_psu failed: {}", e);
                rc = 1;
            }
        }
        SafeOffCut::BeagleboneDisablePsu => {
            if let Err(e) = dcentrald_hal::platform::beaglebone::disable_psu() {
                eprintln!("dcentrald --safe-off: beaglebone disable_psu failed: {}", e);
                rc = 1;
            }
        }
        SafeOffCut::ZynqDisablePsu => {
            if let Err(e) = dcentrald_hal::platform::zynq::disable_psu_output() {
                eprintln!(
                    "dcentrald --safe-off: zynq disable_psu_output failed: {}",
                    e
                );
                rc = 1;
            }
        }
        SafeOffCut::Unknown => {
            eprintln!(
                "dcentrald --safe-off: unknown platform '{}' — ASIC power was NOT cut. \
                 Use the unit's power switch or its init.d safety path.",
                platform_disp
            );
            rc = 1;
        }
    }

    if rc != 0 {
        eprintln!("dcentrald --safe-off: power cut was not proven; fans are left unchanged");
        return rc;
    }

    // 2. Fans -> safe quiet idle (chips are de-energized now; PWM is only ever
    //    driven DOWN, never above PWM_SAFETY_MAX). Best-effort: a fan-open
    //    failure does not abort — the power cut above is load-bearing.
    let quiet_pwm = SAFE_OFF_FAN_PWM.min(dcentrald_hal::fan::PWM_SAFETY_MAX);
    match discover_fan_uio() {
        Some((uio, variant)) => {
            let mode_policy = if matches!(variant, dcentrald_hal::fan::FanVariant::Am2Uio16) {
                am2_fan_mode_policy_for_board_target(&board_target)
            } else {
                dcentrald_hal::fan::Am2FanModePolicy::Preserve
            };
            match dcentrald_hal::fan::FanController::open_with_variant_and_mode_policy(
                uio,
                variant,
                mode_policy,
            ) {
                Ok(fan) => {
                    fan.set_speed(quiet_pwm);
                    eprintln!(
                        "dcentrald --safe-off: fans commanded to quiet idle PWM {} (uio{}, {:?}); RPM is separate proof",
                        quiet_pwm, uio, variant
                    );
                }
                Err(e) => {
                    eprintln!(
                        "dcentrald --safe-off: fan-control uio{} open failed ({:?}): {} — power already cut",
                        uio, variant, e
                    );
                    rc = 1;
                }
            }
        }
        None => {
            eprintln!(
                "dcentrald --safe-off: no 'fan-control' UIO found — fans left as-is (power already cut)"
            );
        }
    }
    rc
}

/// Read-only fan one-shot for init/verify scripts.
///
/// Same discovery/open path as `--set-fan`, but performs no writes. The output
/// is key=value so BusyBox shell can parse it without JSON tools.
/// `dcentrald --verify-bundle <sysupgrade.tar|extracted-dir>` — on-device OTA
/// signature + manifest verification, reusing the daemon's own pinned-key
/// verifier (`dcentrald_api::ota_signature::verify_sysupgrade_bundle`).
///
/// wf_c00e5d9e A/B follow-up (2026-05-29): the install scripts (e.g.
/// `install_amlogic_persistent.sh`) verify SHA256SUMS + MANIFEST but have NO
/// on-device ed25519 *signature* re-verify, because the device tool set ships no
/// openssl/ed25519 verifier. This verb gives them (and operators) that in-band
/// authenticity check by exposing the daemon's existing Rust verifier as a CLI.
/// Requires a signature (`allow_unsigned = false`) and, when present, pins the
/// bundle's embedded key against `/etc/dcentos/release_ed25519.pub`. READ-ONLY:
/// it verifies and exits, never flashes. Exit code: 0 = verified, 1 = failed,
/// 2 = usage error.
fn run_verify_bundle_oneshot(path_arg: Option<&str>) -> i32 {
    let path = match path_arg {
        Some(p) if !p.is_empty() && !p.starts_with("--") => p,
        _ => {
            eprintln!("usage: dcentrald --verify-bundle <sysupgrade.tar|extracted-dir>");
            eprintln!(
                "  Verifies the bundle's ed25519 signature + MANIFEST against the compile-time-pinned"
            );
            eprintln!(
                "  OTA key (and /etc/dcentos/release_ed25519.pub if present). Read-only; never flashes."
            );
            return 2;
        }
    };
    let pinned = std::path::Path::new("/etc/dcentos/release_ed25519.pub");
    let pinned_opt = if pinned.is_file() { Some(pinned) } else { None };
    match dcentrald_api::ota_signature::verify_sysupgrade_bundle(
        std::path::Path::new(path),
        false, // an explicit verify MUST require a signature — never allow_unsigned
        pinned_opt,
    ) {
        Ok(_bundle) => {
            println!(
                "OK: sysupgrade bundle verified (ed25519 signature + MANIFEST): {}{}",
                path,
                if pinned_opt.is_some() {
                    " [pinned against /etc/dcentos/release_ed25519.pub]"
                } else {
                    ""
                }
            );
            0
        }
        Err(e) => {
            eprintln!("FAIL: sysupgrade bundle verification failed: {e}");
            1
        }
    }
}

fn run_get_fan_oneshot() -> i32 {
    let Some((uio, variant)) = discover_fan_uio() else {
        eprintln!("dcentrald --get-fan: no 'fan-control' UIO found under /sys/class/uio");
        return 1;
    };

    match dcentrald_hal::fan::FanController::open_with_variant(uio, variant) {
        Ok(fan) => {
            let discovery = dcentrald_hal::fan::FanUioDiscovery {
                uio_number: uio,
                variant,
                has_board_control: matches!(variant, dcentrald_hal::fan::FanVariant::Am2Uio16),
            };
            print_fan_snapshot("--get-fan", discovery, &fan, None, true);
            0
        }
        Err(e) => {
            eprintln!(
                "dcentrald --get-fan: failed to open fan-control uio{} ({:?}): {}",
                uio, variant, e
            );
            1
        }
    }
}

fn parse_fan_sweep_list(raw: Option<&str>) -> Result<Vec<u8>, String> {
    let Some(raw) = raw else {
        return Err(
            "missing PWM list (usage: --fan-sweep 0,5,10,15,20,25,30 [--dwell-ms 8000])"
                .to_string(),
        );
    };
    let mut values = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err("empty PWM entry in sweep list".to_string());
        }
        let pwm = part
            .parse::<u8>()
            .map_err(|_| format!("invalid PWM entry '{part}' in sweep list"))?;
        values.push(pwm);
    }
    if values.is_empty() {
        return Err("empty PWM sweep list".to_string());
    }
    Ok(values)
}

fn parse_fan_sweep_dwell_ms(args: &[String]) -> u64 {
    let raw = args
        .iter()
        .position(|a| a == "--dwell-ms")
        .and_then(|pos| args.get(pos + 1))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(8_000);
    raw.clamp(250, 60_000)
}

fn run_fan_sweep_oneshot(list_arg: Option<&str>, dwell_ms: u64, allow_loud: bool) -> i32 {
    let list = match parse_fan_sweep_list(list_arg) {
        Ok(list) => list,
        Err(e) => {
            eprintln!("dcentrald --fan-sweep: {e}");
            return 2;
        }
    };

    let Ok((discovery, fan)) = dcentrald_hal::fan::FanController::open_discovered() else {
        eprintln!("dcentrald --fan-sweep: failed to discover/open fan-control UIO");
        return 1;
    };

    println!(
        "dcentrald --fan-sweep: uio={} variant={:?} dwell_ms={} values={:?}",
        discovery.uio_number, discovery.variant, dwell_ms, list
    );

    for requested in list {
        let pwm = clamp_set_fan_pwm(requested, allow_loud);
        if pwm != requested {
            eprintln!(
                "dcentrald --fan-sweep: clamped requested PWM {} -> {} (allow_loud={}; PWM_SAFETY_MAX={}, PWM_MAX={})",
                requested,
                pwm,
                allow_loud,
                dcentrald_hal::fan::PWM_SAFETY_MAX,
                dcentrald_hal::fan::PWM_MAX
            );
        }
        fan.set_speed(pwm);
        std::thread::sleep(std::time::Duration::from_millis(dwell_ms));
        let (commanded_pwm, max_rpm) =
            print_fan_snapshot("--fan-sweep", discovery, &fan, Some(pwm), true);
        if am2_low_pwm_floor_present(discovery.variant, pwm, max_rpm) {
            println!(
                "dcentrald --fan-sweep: LOW_PWM_FLOOR_PRESENT requested={} commanded_pwm={} max_rpm={}",
                pwm, commanded_pwm, max_rpm
            );
        }
    }
    0
}

fn config_selects_bm1362(config: &DcentraldConfig) -> bool {
    config
        .mining
        .serial_chip_type
        .as_deref()
        .map(|chip| chip.eq_ignore_ascii_case("BM1362"))
        .unwrap_or(false)
        || config.mining.model_chip_id() == Some(0x1362)
}

fn configured_asic_protocol_identity(
    config: &DcentraldConfig,
) -> std::result::Result<Option<dcentrald_common::AsicProtocolIdentity>, String> {
    use dcentrald_common::AsicProtocolIdentity;

    let serial_identity = config
        .mining
        .serial_chip_type
        .as_deref()
        .and_then(AsicProtocolIdentity::from_chip_label);
    let model_identity = config
        .mining
        .model_chip_id()
        .and_then(AsicProtocolIdentity::from_chip_id);

    if let (Some(serial), Some(model)) = (serial_identity, model_identity) {
        if serial != model {
            return Err(format!(
                "configured ASIC identity contradicts itself: serial_chip_type={serial:?}, model={model:?}"
            ));
        }
    }

    Ok(serial_identity.or(model_identity))
}

/// Existing top-level mining arm selected by CLI/auto-detection precedence.
///
/// This is deliberately not a miner model. It describes only the runtime's
/// requested chain/work ownership so BoardDesc can reject proven composition
/// contradictions without selecting ASIC, hashboard, voltage, PSU, cooling,
/// storage, or network behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeDispatchKind {
    Bm1396Native,
    Bm1391Native,
    C43Native,
    Am3BeagleBone,
    StratumProxy,
    Tap,
    S19jHybrid,
    S17Hybrid,
    Serial,
    StockFpga,
    StandardDaemon,
}

impl RuntimeDispatchKind {
    const ALL: [Self; 11] = [
        Self::Bm1396Native,
        Self::Bm1391Native,
        Self::C43Native,
        Self::Am3BeagleBone,
        Self::StratumProxy,
        Self::Tap,
        Self::S19jHybrid,
        Self::S17Hybrid,
        Self::Serial,
        Self::StockFpga,
        Self::StandardDaemon,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Bm1396Native => "bm1396-native",
            Self::Bm1391Native => "bm1391-native",
            Self::C43Native => "c43-bm1393-native",
            Self::Am3BeagleBone => "am3-beaglebone",
            Self::StratumProxy => "stratum-proxy",
            Self::Tap => "tap",
            Self::S19jHybrid => "s19j-hybrid",
            Self::S17Hybrid => "s17-hybrid",
            Self::Serial => "serial",
            Self::StockFpga => "stock-fpga",
            Self::StandardDaemon => "standard-daemon",
        }
    }

    const fn owns_chain_or_work(self) -> bool {
        !matches!(self, Self::StratumProxy)
    }

    const fn required_facets(
        self,
    ) -> (
        Option<dcentrald_common::ChainTransportKind>,
        Option<dcentrald_common::WorkEngineKind>,
    ) {
        use dcentrald_common::{ChainTransportKind, WorkEngineKind};
        match self {
            Self::Bm1396Native | Self::Bm1391Native | Self::C43Native => (
                Some(ChainTransportKind::StockFpga),
                Some(WorkEngineKind::FpgaWorkFifo),
            ),
            // These arms have exact, non-overlapping composition contracts.
            Self::Am3BeagleBone => (
                Some(ChainTransportKind::Serial),
                Some(WorkEngineKind::SerialWork),
            ),
            Self::S19jHybrid => (
                Some(ChainTransportKind::ZynqHybrid),
                Some(WorkEngineKind::SerialWork),
            ),
            // The S17 native executor owns stock UIO work/nonce FIFOs. Its
            // exact BM1397 protocol and controller remain separately admitted.
            Self::S17Hybrid => (
                Some(ChainTransportKind::StockFpga),
                Some(WorkEngineKind::FpgaWorkFifo),
            ),
            // Native serial is also an explicit AM2 diagnostic route, so its
            // work engine is exact while its carrier transport is intentionally
            // unresolved here. Existing AM2 lab admission remains downstream.
            Self::Serial => (None, Some(WorkEngineKind::SerialWork)),
            // Proxy owns no miner hardware. Tap/stock/default have ownership or
            // transport distinctions BoardDesc cannot generally express
            // faithfully. Exact am1-s9 standard-daemon resolution is applied
            // later with the descriptor in hand; all other rows fail closed
            // until they gain an explicit ownership contract.
            Self::StratumProxy | Self::Tap | Self::StockFpga | Self::StandardDaemon => (None, None),
        }
    }

    /// Exact ASIC protocol required by engines whose register plan and work
    /// codec are not yet family-generic. A matching carrier is insufficient:
    /// these arms must receive a typed protocol-admission proof.
    const fn required_asic_protocol(self) -> Option<dcentrald_common::AsicProtocolIdentity> {
        use dcentrald_common::AsicProtocolIdentity;
        match self {
            Self::Am3BeagleBone | Self::Tap | Self::S19jHybrid => {
                Some(AsicProtocolIdentity::Bm1362)
            }
            Self::S17Hybrid => Some(AsicProtocolIdentity::Bm1397),
            Self::C43Native => Some(AsicProtocolIdentity::Bm1393),
            Self::Bm1391Native => Some(AsicProtocolIdentity::Bm1391),
            Self::Bm1396Native => Some(AsicProtocolIdentity::Bm1396),
            Self::StratumProxy | Self::Serial | Self::StockFpga | Self::StandardDaemon => None,
        }
    }
}

#[must_use = "runtime dispatch admission must be consumed by the selected runtime"]
#[derive(Debug, PartialEq, Eq)]
enum DeclaredRuntimeDispatchAdmission {
    MiningInactive,
    ExternalHardwareOwner,
    Compatible {
        dispatch: RuntimeDispatchKind,
        board_target: &'static str,
        asic_protocol: Option<dcentrald_common::AsicProtocolAdmission>,
    },
}

/// Production runtime permission joins the pure route declaration with image
/// authority before any hardware-owning constructor receives it.
#[must_use]
#[derive(Debug)]
struct RuntimeDispatchAdmission {
    declared: DeclaredRuntimeDispatchAdmission,
    _image: Option<runtime_image_admission::RuntimeImageAuthority>,
}

impl RuntimeDispatchAdmission {
    fn bind(
        declared: DeclaredRuntimeDispatchAdmission,
        image: Option<runtime_image_admission::RuntimeImageAuthority>,
        cut_only: bool,
    ) -> std::result::Result<Self, String> {
        if image.as_ref().is_some_and(|proof| proof.is_cut_only()) != cut_only {
            return Err("runtime image authority does not match the requested cut-only scope".into());
        }
        if cut_only && !matches!(&declared, DeclaredRuntimeDispatchAdmission::Compatible {
            dispatch: RuntimeDispatchKind::Serial, board_target: "am3-s19k", ..
        }) {
            return Err("cut-only authority requires the exact S19k serial route".into());
        }
        if let DeclaredRuntimeDispatchAdmission::Compatible { board_target, .. } = &declared {
            let proof = image.as_ref().ok_or("runtime hardware dispatch requires signed image authority")?;
            if proof.board_target() != *board_target {
                return Err("runtime image and declared hardware route disagree".into());
            }
        }
        Ok(Self { declared, _image: image })
    }

    fn require_c43(self) -> std::result::Result<C43RuntimeDispatchAdmission, String> {
        self.require_scope(false)?;
        self.declared.require_c43()
    }

    fn require_asic_protocol(
        self,
        dispatch: RuntimeDispatchKind,
        board_target: &str,
        identity: dcentrald_common::AsicProtocolIdentity,
    ) -> std::result::Result<dcentrald_common::AsicProtocolAdmission, String> {
        self.require_scope(false)?;
        self.declared.require_asic_protocol(dispatch, board_target, identity)
    }

    fn require_serial_asic_protocol(
        self,
        identity: dcentrald_common::AsicProtocolIdentity,
    ) -> std::result::Result<SerialRuntimeDispatchAdmission, String> {
        self.require_serial_asic_protocol_for_scope(identity, false)
    }

    fn require_scope(&self, cut_only: bool) -> std::result::Result<(), String> {
        if self._image.as_ref().is_some_and(|proof| proof.is_cut_only()) != cut_only {
            return Err("cut-only runtime authority cannot be used for mining".into());
        }
        Ok(())
    }

    fn require_serial_asic_protocol_for_scope(
        self,
        identity: dcentrald_common::AsicProtocolIdentity,
        cut_only: bool,
    ) -> std::result::Result<SerialRuntimeDispatchAdmission, String> {
        self.require_scope(cut_only)?;
        self.declared.require_serial_asic_protocol(identity)
    }
}

/// Move-only BoardDesc/config authority for one direct-serial runtime.
///
/// This is declaration evidence, not observed silicon. `SerialMiner` must
/// combine it with parser-validated response evidence before family-specific
/// ASIC mutations on routes that support validated serial admission.
#[must_use = "serial runtime dispatch admission must remain bound to its miner lifecycle"]
#[derive(Debug, PartialEq, Eq)]
struct SerialRuntimeDispatchAdmission {
    board_target: &'static str,
    asic_protocol: dcentrald_common::AsicProtocolAdmission,
}

impl SerialRuntimeDispatchAdmission {
    fn board_target(&self) -> &'static str {
        self.board_target
    }

    fn identity(&self) -> dcentrald_common::AsicProtocolIdentity {
        self.asic_protocol.identity()
    }
}

/// Move-only exact C43 route authority; silicon and loaded-fabric checks follow in its owner.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
struct C43RuntimeDispatchAdmission {
    board_target: &'static str,
    asic_protocol: dcentrald_common::AsicProtocolAdmission,
}
impl C43RuntimeDispatchAdmission {
    fn board_target(&self) -> &'static str {
        self.board_target
    }
    fn identity(&self) -> dcentrald_common::AsicProtocolIdentity {
        self.asic_protocol.identity()
    }
}

impl DeclaredRuntimeDispatchAdmission {
    fn require_c43(self) -> std::result::Result<C43RuntimeDispatchAdmission, String> {
        match self {
            Self::Compatible {
                dispatch: RuntimeDispatchKind::C43Native,
                board_target,
                asic_protocol: Some(asic_protocol),
            } if matches!(board_target, "am1-s9se" | "am1-s9k")
                && asic_protocol.identity() == dcentrald_common::AsicProtocolIdentity::Bm1393 =>
            {
                Ok(C43RuntimeDispatchAdmission {
                    board_target,
                    asic_protocol,
                })
            }
            _ => Err("C43 runtime lacks exact target/BM1393 declaration admission".into()),
        }
    }

    fn require_asic_protocol(
        self,
        expected_dispatch: RuntimeDispatchKind,
        expected_board_target: &str,
        expected: dcentrald_common::AsicProtocolIdentity,
    ) -> std::result::Result<dcentrald_common::AsicProtocolAdmission, String> {
        match self {
            Self::Compatible {
                dispatch,
                board_target,
                asic_protocol: Some(admission),
            } if dispatch == expected_dispatch
                && board_target == expected_board_target
                && admission.identity() == expected =>
            {
                Ok(admission)
            }
            _ => Err(format!(
                "runtime dispatch lacks exact {expected_dispatch:?}/{expected_board_target}/{expected:?} admission"
            )),
        }
    }

    fn require_serial_asic_protocol(
        self,
        expected: dcentrald_common::AsicProtocolIdentity,
    ) -> std::result::Result<SerialRuntimeDispatchAdmission, String> {
        match self {
            Self::Compatible {
                dispatch: RuntimeDispatchKind::Serial,
                board_target,
                asic_protocol: Some(asic_protocol),
            } if asic_protocol.identity() == expected => Ok(SerialRuntimeDispatchAdmission {
                board_target,
                asic_protocol,
            }),
            _ => Err(format!(
                "runtime dispatch lacks exact direct-serial/{expected:?} protocol admission"
            )),
        }
    }
}

fn selected_runtime_dispatch(
    am3_bb: bool,
    stratum_proxy: bool,
    tap: bool,
    s19j_hybrid: bool,
    s17_hybrid: bool,
    serial: bool,
    stock_fpga: bool,
) -> RuntimeDispatchKind {
    if am3_bb {
        RuntimeDispatchKind::Am3BeagleBone
    } else if stratum_proxy {
        RuntimeDispatchKind::StratumProxy
    } else if tap {
        RuntimeDispatchKind::Tap
    } else if s19j_hybrid {
        RuntimeDispatchKind::S19jHybrid
    } else if s17_hybrid {
        RuntimeDispatchKind::S17Hybrid
    } else if serial {
        RuntimeDispatchKind::Serial
    } else if stock_fpga {
        RuntimeDispatchKind::StockFpga
    } else {
        RuntimeDispatchKind::StandardDaemon
    }
}

/// Build declaration-only authority for the exact stock S9 candidate lane.
///
/// This function is intentionally not called by `run_main`: the top-level
/// `RuntimeDispatchKind::StockFpga` route remains fail-closed until the HAL can
/// mint a retained-lease live carrier receipt and the runtime gains real
/// thermal ownership. Keeping this wrapper here pins the selected-dispatch
/// provenance instead of allowing a Boolean in lower-level code to stand in
/// for `RuntimeDispatchKind`.
fn admit_stock_fpga_declared_route(
    board_desc: Option<&dcentrald_common::BoardDesc>,
    dispatch: RuntimeDispatchKind,
    configured_or_observed_asic: Option<dcentrald_common::AsicProtocolIdentity>,
    nonce2_beta_enabled: bool,
    all_pool_routes_v1: bool,
    passthrough_enabled: bool,
) -> std::result::Result<
    dcentrald_common::stock_fpga_carrier_preflight::StockFpgaDeclaredRouteAdmission,
    String,
> {
    use dcentrald_common::stock_fpga_carrier_preflight::{
        admit_stock_fpga_declared_route as admit_declared_route, StockFpgaDeclaredRouteRequest,
    };

    let board_desc = board_desc
        .ok_or_else(|| "stock FPGA declared route requires a registered BoardDesc".to_string())?;
    admit_declared_route(StockFpgaDeclaredRouteRequest {
        explicit_stock_fpga_dispatch: dispatch == RuntimeDispatchKind::StockFpga,
        board_desc,
        configured_or_observed_asic,
        requested_transport: dcentrald_common::ChainTransportKind::StockFpga,
        requested_work_engine: dcentrald_common::WorkEngineKind::StockDma,
        nonce2_beta_enabled,
        all_pool_routes_v1,
        passthrough_enabled,
    })
    .map_err(|error| error.to_string())
}

fn admit_board_desc_runtime_dispatch(
    board_desc: Option<&dcentrald_common::BoardDesc>,
    dispatch: RuntimeDispatchKind,
    mining_start_enabled: bool,
    configured_asic_protocol: Option<dcentrald_common::AsicProtocolIdentity>,
) -> std::result::Result<DeclaredRuntimeDispatchAdmission, String> {
    use dcentrald_common::WorkEngineKind;

    if !mining_start_enabled {
        return Ok(DeclaredRuntimeDispatchAdmission::MiningInactive);
    }
    if !dispatch.owns_chain_or_work() {
        return Ok(DeclaredRuntimeDispatchAdmission::ExternalHardwareOwner);
    }
    let required_asic_protocol = dispatch.required_asic_protocol();
    let Some(board_desc) = board_desc else {
        if let Some(required) = required_asic_protocol {
            return Err(format!(
                "runtime dispatch {} requires exact {required:?} ASIC protocol admission, but no BoardDesc is registered",
                dispatch.label()
            ));
        }
        return Err(format!(
            "runtime dispatch {} owns mining hardware but no BoardDesc is registered",
            dispatch.label()
        ));
    };
    if dispatch == RuntimeDispatchKind::C43Native
        && (!matches!(board_desc.board_target, "am1-s9se" | "am1-s9k")
            || board_desc.runtime_status
                != (dcentrald_common::RuntimeStatus::SpecialisedLifecycle {
                    lane: dcentrald_common::LifecycleLane::C43Bm1393Native,
                    generic_construction: dcentrald_common::GenericConstruction::Refused,
                }))
    {
        return Err("C43 runtime requires exact C43/BM1393 lifecycle identity".into());
    }
    if dispatch == RuntimeDispatchKind::Bm1396Native
        && (!matches!(board_desc.board_target, "am2-t17e" | "am2-s17e")
            || board_desc.runtime_status
                != (dcentrald_common::RuntimeStatus::SpecialisedLifecycle {
                    lane: dcentrald_common::LifecycleLane::Bm1396Native,
                    generic_construction: dcentrald_common::GenericConstruction::Refused,
                }))
    {
        return Err("BM1396 runtime requires exact S17e or T17e native lifecycle identity".into());
    }
    if dispatch == RuntimeDispatchKind::Bm1391Native
        && (!matches!(board_desc.board_target, "am1-s15" | "am1-t15")
            || board_desc.runtime_status
                != (dcentrald_common::RuntimeStatus::SpecialisedLifecycle {
                    lane: dcentrald_common::LifecycleLane::Bm1391Native,
                    generic_construction: dcentrald_common::GenericConstruction::Refused,
                }))
    {
        return Err("BM1391 runtime requires exact S15/T15 native lifecycle identity".into());
    }
    // Exact BM1366 platform profiles keep S19k and XP geometry/PSU dialects
    // separate. The current table admits S19k and both XP compositions.
    if dispatch == RuntimeDispatchKind::Serial
        && configured_asic_protocol == Some(dcentrald_common::AsicProtocolIdentity::Bm1366)
    {
        match dcentrald_common::bm1366_serial_platform::bm1366_dispatch_admitted_serial_platform(
            board_desc.board_target,
        ) {
            Ok(_profile) => {
                let asic_protocol_admission = board_desc.admit_asic_protocol(
                    configured_asic_protocol,
                    dcentrald_common::AsicProtocolIdentity::Bm1366,
                )?;
                return Ok(DeclaredRuntimeDispatchAdmission::Compatible {
                    dispatch,
                    board_target: board_desc.board_target,
                    asic_protocol: Some(asic_protocol_admission),
                });
            }
            Err(gate) => {
                return Err(format!(
                    "BoardDesc {} BM1366 serial runtime is not dispatch-admitted: {gate}",
                    board_desc.board_target
                ));
            }
        }
    }

    if board_desc.work_engine == WorkEngineKind::ManagementOnly {
        return Err(format!(
            "BoardDesc {} is management-only but runtime dispatch {} would own mining chain/work",
            board_desc.board_target,
            dispatch.label()
        ));
    }

    // The direct serial route selects an ASIC implementation before opening
    // its hardware-owning constructor. Bind that configured identity to the
    // complete BoardDesc here; a RuntimeDiscovered descriptor is not enough to
    // authorize pre-discovery mutations.
    let serial_asic_protocol_admission = if dispatch == RuntimeDispatchKind::Serial {
        let configured = configured_asic_protocol.ok_or_else(|| {
            format!(
                "runtime dispatch {} requires an explicit ASIC identity before hardware construction",
                dispatch.label()
            )
        })?;
        if board_desc.asic_protocol == dcentrald_common::AsicProtocolIdentity::RuntimeDiscovered {
            return Err(format!(
                "BoardDesc {} leaves ASIC protocol runtime-discovered; serial hardware construction requires passive identity refinement first",
                board_desc.board_target
            ));
        }
        Some(board_desc.admit_asic_protocol(Some(configured), board_desc.asic_protocol)?)
    } else {
        None
    };

    let asic_protocol_admission = match serial_asic_protocol_admission {
        Some(admission) => Some(admission),
        None => required_asic_protocol
            .map(|required| board_desc.admit_asic_protocol(configured_asic_protocol, required))
            .transpose()?,
    };

    let (required_transport, required_work_engine) = if dispatch
        == RuntimeDispatchKind::StandardDaemon
        && board_desc.admits_standard_bm1387_runtime()
    {
        // Exact S9/S9i/S9j BM1387/PIC16 compositions consume the retained
        // standard FpgaChain and WorkDispatcher ownership contract.
        (
            Some(dcentrald_common::ChainTransportKind::FpgaUio),
            Some(dcentrald_common::WorkEngineKind::FpgaWorkFifo),
        )
    } else if dispatch == RuntimeDispatchKind::Serial
        && s19_bm1398_native_mining::platform::Bm1398Platform::from_admission(
            board_desc.board_target, board_desc.asic_protocol,
        ).is_ok()
    {
        // SerialMiner delegates this exact target to the native BM1398
        // UIO executor before opening any generic serial hardware. The
        // protocol proof above still requires configured BM1398 identity.
        (
            Some(dcentrald_common::ChainTransportKind::FpgaUio),
            Some(dcentrald_common::WorkEngineKind::FpgaWorkFifo),
        )
    } else if dispatch == RuntimeDispatchKind::StandardDaemon
        && board_desc.board_target == "am1-t9plus"
    {
        // R02 PROPOSED (Lead review pending): am1-t9plus is the only
        // registered board whose held production bytes drive the framed
        // dsPIC33EP16GS202 controller protocol — see
        // dcentrald_common::am1_dspic_adapter (desk-validated codec,
        // evidence/r02). Its control-board GPIO map and NAND slot layout
        // remain unconfirmed and no T9+ has ever been contacted, so dispatch
        // MUST keep failing closed; this arm names the exact missing
        // evidence instead of a generic facet mismatch (the generic check
        // below would refuse on ChainTransportKind::None /
        // WorkEngineKind::ManagementOnly anyway).
        return Err(format!(
            "BoardDesc am1-t9plus is CaptureFirst: the framed dsPIC33EP \
             controller adapter (dcentrald_common::am1_dspic_adapter) is \
             desk-validated only; control-board GPIO map and NAND slot layout \
             remain unconfirmed (AM1_T9PLUS_UNCONFIRMED_DATUMS) and no unit \
             has been contacted. Refusing {dispatch:?} dispatch."
        ));
    } else {
        dispatch.required_facets()
    };
    if let Some(required_transport) = required_transport {
        if board_desc.chain_transport != required_transport {
            return Err(format!(
                "BoardDesc {} declares chain transport {:?}, incompatible with runtime dispatch {} requiring {:?}",
                board_desc.board_target,
                board_desc.chain_transport,
                dispatch.label(),
                required_transport
            ));
        }
    }
    if let Some(required_work_engine) = required_work_engine {
        if board_desc.work_engine != required_work_engine {
            return Err(format!(
                "BoardDesc {} declares work engine {:?}, incompatible with runtime dispatch {} requiring {:?}",
                board_desc.board_target,
                board_desc.work_engine,
                dispatch.label(),
                required_work_engine
            ));
        }
    }

    if required_transport.is_none() && required_work_engine.is_none() {
        Err(format!(
            "runtime dispatch {} has no exact transport/work ownership contract for BoardDesc {}; refusing hardware construction",
            dispatch.label(),
            board_desc.board_target
        ))
    } else {
        Ok(DeclaredRuntimeDispatchAdmission::Compatible {
            dispatch,
            board_target: board_desc.board_target,
            asic_protocol: asic_protocol_admission,
        })
    }
}

#[cfg(test)]
mod board_desc_runtime_dispatch_tests {
    use super::*;
    use dcentrald_common::BoardDesc;

    const MAIN_SOURCE: &str = include_str!("main.rs");
    const DAEMON_SOURCE: &str = include_str!("daemon.rs");
    const TAP_SOURCE: &str = include_str!("s19j_tap_mining.rs");
    const STOCK_SOURCE: &str = include_str!("stock_mining.rs");
    const SERIAL_SOURCE: &str = include_str!("serial_mining.rs");
    const S17_INIT_SOURCE: &str = include_str!(
        "../../../br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/etc/init.d/S82dcentrald"
    );
    const S19PRO_INIT_SOURCE: &str = include_str!(
        "../../../br2_external_dcentos/board/zynq/am2-s19pro/rootfs-overlay/etc/init.d/S82dcentrald"
    );

    #[test]
    fn s19k_one_shot_track1_trials_exit_instead_of_management_only_park() {
        // Attempt-9 contract (2026-08-28): after a typed serial failure
        // disposition, the one-shot Track-1 authorities (no-work,
        // bounded-work proof, endurance proof) must return the error for
        // wrapper closeout instead of falling through to
        // enter_management_only — the park deadlocked the live bounded
        // wrapper for 26+ minutes until an ungraceful kill and the printed
        // restore.
        let marker = "enter_management_only(\"serial\", e, shutdown_token.clone(), None).await";
        let call = MAIN_SOURCE
            .find(marker)
            .expect("the serial management-only call must remain present");
        let gate = MAIN_SOURCE[..call]
            .rfind("if s19k_track1_no_work")
            .expect("the one-shot Track-1 exit gate must precede the park");
        let between = &MAIN_SOURCE[gate..call];
        assert!(
            between.contains("s19k_track1_bounded_work_proof")
                && between.contains("s19k_track1_endurance_work_proof")
                && between.contains("return Err(e.context("),
            "all three one-shot authorities must exit before the park"
        );
    }

    fn future_desc(
        board_target: &'static str,
        chain_transport: dcentrald_common::ChainTransportKind,
        work_engine: dcentrald_common::WorkEngineKind,
    ) -> dcentrald_common::BoardDesc {
        dcentrald_common::BoardDesc {
            board_target,
            family: dcentrald_common::BoardFamily::Zynq,
            chain_transport,
            work_engine,
            asic_protocol: dcentrald_common::AsicProtocolIdentity::RuntimeDiscovered,
            voltage_controller: dcentrald_common::VoltageControllerClass::RuntimeDiscovered,
            slot_policy: dcentrald_common::SlotPolicy::LabGated,
            enablement: dcentrald_common::HardwareEnablementPolicy {
                storage_topology: dcentrald_common::StorageTopology::Unknown,
                update_mechanism: dcentrald_common::UpdateMechanism::None,
                update_maturity: dcentrald_common::ImplementationMaturity::NotImplemented,
                install_authorization: dcentrald_common::InstallAuthorization::Denied,
                recovery_maturity: dcentrald_common::RecoveryMaturity::NotImplemented,
                artifact_kind: dcentrald_common::ArtifactKind::RuntimeBundle,
                artifact_maturity: dcentrald_common::ArtifactMaturity::Experimental,
                external_media_mode: dcentrald_common::ExternalMediaMode::None,
                external_media_maturity: dcentrald_common::ExternalMediaMaturity::NotImplemented,
                external_media_authorization: dcentrald_common::InstallAuthorization::Denied,
            },
            release_channel: dcentrald_common::ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
            // Round-16 B5: cooling medium is undeclared (fail-closed — never
            // earns the fan-management bypass) and the ladder is the
            // forced-air canonical one, so fans stay managed on a board whose
            // medium nobody has evidenced.
            cooling_medium: None,
            cut_ladder: dcentrald_common::cooling_medium::CANONICAL_FORCED_AIR_LADDER,
            // Fail-closed: a fabricated capture-first row must never borrow
            // another SKU's thermal-supervisor lane.
            supervisor_class: dcentrald_common::board_desc::SupervisorClass::Unclassified,
            // Fail-closed placeholder for fabricated future targets: nothing
            // is captured, so nothing may claim a lane.
            runtime_status: dcentrald_common::RuntimeStatus::CaptureFirst {
                unconfirmed: &["test-only scaffold row; no datums captured"],
            },
        }
    }

    #[test]
    fn board_desc_dispatch_priority_matches_the_runtime_branch_order() {
        assert_eq!(
            selected_runtime_dispatch(true, true, true, true, true, true, true),
            RuntimeDispatchKind::Am3BeagleBone
        );
        assert_eq!(
            selected_runtime_dispatch(false, true, true, true, true, true, true),
            RuntimeDispatchKind::StratumProxy
        );
        assert_eq!(
            selected_runtime_dispatch(false, false, true, true, true, true, true),
            RuntimeDispatchKind::Tap
        );
        assert_eq!(
            selected_runtime_dispatch(false, false, false, true, true, true, true),
            RuntimeDispatchKind::S19jHybrid
        );
        assert_eq!(
            selected_runtime_dispatch(false, false, false, false, true, true, true),
            RuntimeDispatchKind::S17Hybrid
        );
        assert_eq!(
            selected_runtime_dispatch(false, false, false, false, false, true, true),
            RuntimeDispatchKind::Serial
        );
        assert_eq!(
            selected_runtime_dispatch(false, false, false, false, false, false, true),
            RuntimeDispatchKind::StockFpga
        );
        assert_eq!(
            selected_runtime_dispatch(false, false, false, false, false, false, false),
            RuntimeDispatchKind::StandardDaemon
        );
    }

    #[test]
    fn board_desc_dispatch_unknown_hardware_ownership_fails_closed() {
        for dispatch in RuntimeDispatchKind::ALL {
            assert_eq!(
                admit_board_desc_runtime_dispatch(None, dispatch, false, None).unwrap(),
                DeclaredRuntimeDispatchAdmission::MiningInactive
            );
            let admitted = admit_board_desc_runtime_dispatch(None, dispatch, true, None);
            if dispatch == RuntimeDispatchKind::StratumProxy {
                assert_eq!(
                    admitted.unwrap(),
                    DeclaredRuntimeDispatchAdmission::ExternalHardwareOwner
                );
            } else {
                assert!(
                    admitted.is_err(),
                    "{dispatch:?} must require BoardDesc identity"
                );
            }
        }
    }

    #[test]
    fn board_desc_admission_failure_preserves_cooling_and_closes_api_mutation() {
        let marker =
            "BoardDesc runtime dispatch contradiction; parking management-only before mining hardware construction";
        let start = MAIN_SOURCE
            .rfind(marker)
            .expect("runtime admission-failure branch must remain present");
        let end = MAIN_SOURCE[start..]
            .find("if am3_bb_mode")
            .map(|offset| start + offset)
            .expect("runtime dispatch must follow admission handling");
        let branch = &MAIN_SOURCE[start..end];

        assert!(branch.contains("enter_management_only_idle("));
        assert!(
            branch.contains("spawn_proxy_mode_api_with_hardware_mutation_gate(")
                && branch.contains("HardwareMutationGate::new_closed()"),
            "an unadmitted composition must expose a read-only API plane"
        );
        assert!(
            !branch.contains("am2_quiet_idle_tuple(")
                && !branch.contains("force_am2_fans_to_quiet_idle"),
            "admission failure has no rail-off proof and must not lower cooling"
        );
    }

    #[test]
    fn board_desc_dispatch_matrix_is_exhaustive_and_requires_exact_contracts() {
        use dcentrald_common::{ChainTransportKind, WorkEngineKind};

        for board_desc in dcentrald_common::BoardDesc::all_registered() {
            for dispatch in RuntimeDispatchKind::ALL {
                let result = admit_board_desc_runtime_dispatch(
                    Some(board_desc),
                    dispatch,
                    true,
                    Some(board_desc.asic_protocol),
                );
                if dispatch == RuntimeDispatchKind::StratumProxy {
                    assert_eq!(
                        result.unwrap(),
                        DeclaredRuntimeDispatchAdmission::ExternalHardwareOwner,
                        "{}",
                        board_desc.board_target
                    );
                    continue;
                }
                if board_desc.board_target == "am3-s19k" && dispatch == RuntimeDispatchKind::Serial
                {
                    assert!(
                        result.is_ok(),
                        "am3-s19k serial BM1366 is Track-1 leftover, not native"
                    );
                    continue;
                }
                if board_desc.work_engine == WorkEngineKind::ManagementOnly {
                    assert!(
                        result.is_err(),
                        "{} / {dispatch:?}",
                        board_desc.board_target
                    );
                    continue;
                }

                match dispatch {
                    RuntimeDispatchKind::Bm1396Native => assert_eq!(result.is_ok(),
                        matches!(board_desc.board_target, "am2-t17e" | "am2-s17e")),
                    RuntimeDispatchKind::Bm1391Native => assert_eq!(result.is_ok(),
                        matches!(board_desc.board_target, "am1-s15" | "am1-t15")),
                    RuntimeDispatchKind::C43Native => assert_eq!(result.is_ok(),
                        matches!(board_desc.board_target, "am1-s9se" | "am1-s9k")),
                    RuntimeDispatchKind::Am3BeagleBone => {
                        assert_eq!(
                            result.is_ok(),
                            board_desc.chain_transport == ChainTransportKind::Serial
                                && board_desc.work_engine == WorkEngineKind::SerialWork
                                && board_desc.asic_protocol
                                    == dcentrald_common::AsicProtocolIdentity::Bm1362,
                            "{}",
                            board_desc.board_target
                        );
                    }
                    RuntimeDispatchKind::S19jHybrid => {
                        assert_eq!(
                            result.is_ok(),
                            board_desc.chain_transport == ChainTransportKind::ZynqHybrid
                                && board_desc.work_engine == WorkEngineKind::SerialWork
                                && board_desc.asic_protocol
                                    == dcentrald_common::AsicProtocolIdentity::Bm1362,
                            "{}",
                            board_desc.board_target
                        );
                    }
                    RuntimeDispatchKind::S17Hybrid => {
                        // 2026-08-27 promotion: the BM1397 hybrid engine admits
                        // exactly the four promoted S17-family rows.
                        assert_eq!(
                            result.is_ok(),
                            board_desc.chain_transport == ChainTransportKind::StockFpga
                                && board_desc.work_engine == WorkEngineKind::FpgaWorkFifo
                                && board_desc.asic_protocol
                                    == dcentrald_common::AsicProtocolIdentity::Bm1397,
                            "{}",
                            board_desc.board_target
                        );
                    }
                    RuntimeDispatchKind::Serial => {
                        assert_eq!(
                            result.is_ok(),
                            (board_desc.work_engine == WorkEngineKind::SerialWork
                                || (s19_bm1398_native_mining::platform::Bm1398Platform::from_admission(
                                        board_desc.board_target, board_desc.asic_protocol,
                                    ).is_ok()
                                    && board_desc.chain_transport == ChainTransportKind::FpgaUio
                                    && board_desc.work_engine == WorkEngineKind::FpgaWorkFifo))
                                && board_desc.asic_protocol
                                    != dcentrald_common::AsicProtocolIdentity::RuntimeDiscovered,
                            "{}",
                            board_desc.board_target
                        );
                    }
                    RuntimeDispatchKind::StandardDaemon
                        if board_desc.admits_standard_bm1387_runtime() => {
                        assert_eq!(
                            result.unwrap(),
                            DeclaredRuntimeDispatchAdmission::Compatible {
                                dispatch: RuntimeDispatchKind::StandardDaemon,
                                board_target: board_desc.board_target,
                                asic_protocol: None
                            }
                        )
                    }
                    RuntimeDispatchKind::Tap | RuntimeDispatchKind::StockFpga => assert!(
                        result.is_err(),
                        "{} / {dispatch:?} must not construct hardware without an exact ownership contract",
                        board_desc.board_target
                    ),
                    RuntimeDispatchKind::StandardDaemon => assert!(
                        result.is_err(),
                        "{} must not enter the standard hardware route",
                        board_desc.board_target
                    ),
                    RuntimeDispatchKind::StratumProxy => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn am3_s19k_serial_bm1366_is_track1_leftover_not_native() {
        use dcentrald_common::{AsicProtocolIdentity, BoardDesc, WorkEngineKind};

        let desc = BoardDesc::lookup("am3-s19k").unwrap();
        assert_eq!(desc.work_engine, WorkEngineKind::SerialWork);
        assert!(admit_board_desc_runtime_dispatch(
            Some(desc),
            RuntimeDispatchKind::Serial,
            true,
            Some(AsicProtocolIdentity::Bm1366),
        )
        .is_ok());
        assert!(admit_board_desc_runtime_dispatch(
            Some(desc),
            RuntimeDispatchKind::Serial,
            true,
            Some(AsicProtocolIdentity::Bm1368),
        )
        .is_err());
        assert!(admit_board_desc_runtime_dispatch(
            Some(desc),
            RuntimeDispatchKind::Am3BeagleBone,
            true,
            Some(AsicProtocolIdentity::Bm1366),
        )
        .is_err());
    }

    #[test]
    fn board_desc_dispatch_exact_s9_resolves_standard_daemon_without_generalizing() {
        use dcentrald_common::{
            BoardDesc, BoardFamily, ChainTransportKind, SlotPolicy, VoltageControllerClass,
            WorkEngineKind,
        };

        let s9 = BoardDesc::lookup("am1-s9").unwrap();
        assert_eq!(
            admit_board_desc_runtime_dispatch(
                Some(s9),
                RuntimeDispatchKind::StandardDaemon,
                true,
                Some(dcentrald_common::AsicProtocolIdentity::Bm1387),
            )
            .unwrap(),
            DeclaredRuntimeDispatchAdmission::Compatible {
                dispatch: RuntimeDispatchKind::StandardDaemon,
                board_target: "am1-s9",
                asic_protocol: None
            }
        );

        // Matching facets on a future target do not mint exact S9 authority.
        let future_fpga = BoardDesc {
            board_target: "future-fpga-uio",
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::FpgaUio,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: dcentrald_common::AsicProtocolIdentity::RuntimeDiscovered,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: dcentrald_common::HardwareEnablementPolicy {
                storage_topology: dcentrald_common::StorageTopology::Unknown,
                update_mechanism: dcentrald_common::UpdateMechanism::None,
                update_maturity: dcentrald_common::ImplementationMaturity::NotImplemented,
                install_authorization: dcentrald_common::InstallAuthorization::Denied,
                recovery_maturity: dcentrald_common::RecoveryMaturity::NotImplemented,
                artifact_kind: dcentrald_common::ArtifactKind::RuntimeBundle,
                artifact_maturity: dcentrald_common::ArtifactMaturity::Experimental,
                external_media_mode: dcentrald_common::ExternalMediaMode::None,
                external_media_maturity: dcentrald_common::ExternalMediaMaturity::NotImplemented,
                external_media_authorization: dcentrald_common::InstallAuthorization::Denied,
            },
            release_channel: dcentrald_common::ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
            // Round-16 B5: undeclared medium + forced-air ladder (fans stay
            // managed); no borrowed thermal-supervisor lane.
            cooling_medium: None,
            cut_ladder: dcentrald_common::cooling_medium::CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: dcentrald_common::board_desc::SupervisorClass::Unclassified,
            // Fail-closed placeholder for a fabricated future target.
            runtime_status: dcentrald_common::RuntimeStatus::CaptureFirst {
                unconfirmed: &["test-only scaffold row; no datums captured"],
            },
        };
        assert!(admit_board_desc_runtime_dispatch(
            Some(&future_fpga),
            RuntimeDispatchKind::StandardDaemon,
            true,
            None,
        )
        .is_err());

        // Conversely, a contradictory exact row is rejected rather than
        // accepted from the target string alone.
        let contradictory_s9 = BoardDesc {
            chain_transport: ChainTransportKind::Serial,
            ..future_fpga.clone()
        };
        let contradictory_s9 = BoardDesc {
            board_target: "am1-s9",
            ..contradictory_s9
        };
        assert!(admit_board_desc_runtime_dispatch(
            Some(&contradictory_s9),
            RuntimeDispatchKind::StandardDaemon,
            true,
            None,
        )
        .is_err());

        assert!(admit_board_desc_runtime_dispatch(
            None,
            RuntimeDispatchKind::StandardDaemon,
            true,
            None,
        )
        .is_err());
    }

    #[test]
    fn am3_dispatch_admission_is_move_only_and_consumed_by_the_exact_route() {
        use dcentrald_common::{AsicProtocolIdentity, BoardDesc};

        let source_start = MAIN_SOURCE
            .find("enum DeclaredRuntimeDispatchAdmission")
            .expect("runtime dispatch admission enum");
        let derive = MAIN_SOURCE[..source_start]
            .lines()
            .rev()
            .find(|line| line.contains("derive"))
            .expect("runtime dispatch admission derive");
        assert!(!derive.contains("Clone") && !derive.contains("Copy"));

        let exact = admit_board_desc_runtime_dispatch(
            BoardDesc::lookup("am3-bb-s19jpro"),
            RuntimeDispatchKind::Am3BeagleBone,
            true,
            Some(AsicProtocolIdentity::Bm1362),
        )
        .unwrap();
        assert!(exact
            .require_asic_protocol(
                RuntimeDispatchKind::Am3BeagleBone,
                "am3-bb-s19jpro",
                AsicProtocolIdentity::Bm1362,
            )
            .is_ok());

        let wrong_route = admit_board_desc_runtime_dispatch(
            BoardDesc::lookup("am3-bb-s19jpro"),
            RuntimeDispatchKind::Am3BeagleBone,
            true,
            Some(AsicProtocolIdentity::Bm1362),
        )
        .unwrap();
        assert!(wrong_route
            .require_asic_protocol(
                RuntimeDispatchKind::S19jHybrid,
                "am2-s19j",
                AsicProtocolIdentity::Bm1362,
            )
            .is_err());
    }

    #[test]
    fn board_desc_dispatch_s9_resolution_is_pinned_to_actual_standard_runtime_ownership() {
        let init_signature = ["async fn in", "it("].concat();
        let init_start = DAEMON_SOURCE.find(&init_signature).unwrap();
        let init_body = &DAEMON_SOURCE[init_start..];
        assert!(init_body.contains("FpgaChain::open("));

        let lifecycle_signature = ["async fn run_", "lifecycle("].concat();
        let lifecycle_start = DAEMON_SOURCE.find(&lifecycle_signature).unwrap();
        let lifecycle_body = &DAEMON_SOURCE[lifecycle_start..init_start];
        assert!(lifecycle_body.contains("crate::work_dispatcher::WorkDispatcher::new("));
    }

    #[test]
    fn board_desc_dispatch_tap_and_stock_fail_closed_without_ownership_contracts() {
        for board_desc in dcentrald_common::BoardDesc::all_registered() {
            for dispatch in [RuntimeDispatchKind::Tap, RuntimeDispatchKind::StockFpga] {
                let result = admit_board_desc_runtime_dispatch(
                    Some(board_desc),
                    dispatch,
                    true,
                    Some(board_desc.asic_protocol),
                );
                assert!(
                    result.is_err(),
                    "{} must not gain {dispatch:?} authority without a sealed ownership contract",
                    board_desc.board_target
                );
            }
        }
    }

    #[test]
    fn stock_declared_route_is_exact_but_never_opens_top_level_runtime() {
        use dcentrald_common::{AsicProtocolIdentity, ChainTransportKind, WorkEngineKind};

        let s9 = dcentrald_common::BoardDesc::lookup("am1-s9").expect("registered S9");
        let declared = admit_stock_fpga_declared_route(
            Some(s9),
            RuntimeDispatchKind::StockFpga,
            Some(AsicProtocolIdentity::Bm1387),
            true,
            true,
            true,
        )
        .expect("exact declaration-only stock overlay");
        assert_eq!(declared.board_target(), "am1-s9");
        assert_eq!(declared.asic_protocol(), AsicProtocolIdentity::Bm1387);
        assert_eq!(declared.transport(), ChainTransportKind::StockFpga);
        assert_eq!(declared.work_engine(), WorkEngineKind::StockDma);

        // Declaration evidence is not a live carrier receipt. The actual
        // top-level ownership gate remains closed for the same exact row.
        assert!(admit_board_desc_runtime_dispatch(
            Some(s9),
            RuntimeDispatchKind::StockFpga,
            true,
            Some(AsicProtocolIdentity::Bm1387),
        )
        .is_err());

        assert!(admit_stock_fpga_declared_route(
            Some(s9),
            RuntimeDispatchKind::StandardDaemon,
            Some(AsicProtocolIdentity::Bm1387),
            true,
            true,
            true,
        )
        .is_err());
    }

    #[test]
    fn board_desc_dispatch_am2_serial_diagnostic_admits_work_without_claiming_carrier() {
        use dcentrald_common::{ChainTransportKind, WorkEngineKind};

        let am2 = dcentrald_common::BoardDesc::lookup("am2-s19j").unwrap();
        assert_eq!(am2.chain_transport, ChainTransportKind::ZynqHybrid);
        let (required_transport, required_work) = RuntimeDispatchKind::Serial.required_facets();
        assert_eq!(
            required_transport, None,
            "serial carrier must remain unresolved"
        );
        assert_eq!(required_work, Some(WorkEngineKind::SerialWork));
        let admission = admit_board_desc_runtime_dispatch(
            Some(am2),
            RuntimeDispatchKind::Serial,
            true,
            Some(dcentrald_common::AsicProtocolIdentity::Bm1362),
        )
        .unwrap();
        assert!(matches!(
            admission,
            DeclaredRuntimeDispatchAdmission::Compatible {
                dispatch: RuntimeDispatchKind::Serial,
                board_target: "am2-s19j",
                asic_protocol: Some(protocol),
            } if protocol.identity() == dcentrald_common::AsicProtocolIdentity::Bm1362
        ));

    }

    #[test]
    fn board_desc_dispatch_future_facet_lookalikes_do_not_gain_tap_or_stock_authority() {
        use dcentrald_common::{ChainTransportKind, WorkEngineKind};

        let tap_lookalike = future_desc(
            "future-am2-lookalike",
            ChainTransportKind::ZynqHybrid,
            WorkEngineKind::SerialWork,
        );
        let stock_lookalike = future_desc(
            "future-stock-lookalike",
            ChainTransportKind::StockFpga,
            WorkEngineKind::StockDma,
        );
        let s9_facet_copy = future_desc(
            "future-s9-facet-copy",
            ChainTransportKind::FpgaUio,
            WorkEngineKind::FpgaWorkFifo,
        );

        assert!(admit_board_desc_runtime_dispatch(
            Some(&tap_lookalike),
            RuntimeDispatchKind::Tap,
            true,
            Some(tap_lookalike.asic_protocol),
        )
        .is_err());

        for (board_desc, dispatch) in [
            (&stock_lookalike, RuntimeDispatchKind::StockFpga),
            (&s9_facet_copy, RuntimeDispatchKind::StockFpga),
        ] {
            assert!(
                admit_board_desc_runtime_dispatch(
                    Some(board_desc),
                    dispatch,
                    true,
                    Some(board_desc.asic_protocol),
                )
                .is_err(),
                "{} must fail closed for {dispatch:?}",
                board_desc.board_target
            );
        }
    }

    #[test]
    fn s19pro_bm1398_can_never_enter_the_bm1362_hybrid_engine() {
        use dcentrald_common::{AsicProtocolIdentity, BoardDesc, WorkEngineKind};

        let s19pro = BoardDesc::lookup("am2-s19pro").expect("registered S19 Pro target");
        assert_eq!(s19pro.asic_protocol, AsicProtocolIdentity::Bm1398);
        assert_eq!(s19pro.work_engine, WorkEngineKind::FpgaWorkFifo);
        assert!(admit_board_desc_runtime_dispatch(
            Some(s19pro),
            RuntimeDispatchKind::S19jHybrid,
            true,
            Some(AsicProtocolIdentity::Bm1398),
        )
        .is_err());
        assert!(s19pro
            .admit_asic_protocol(
                Some(AsicProtocolIdentity::Bm1398),
                AsicProtocolIdentity::Bm1362,
            )
            .is_err());
    }

    #[test]
    fn s19pro_bm1398_native_dispatch_mints_exact_consumable_admission() {
        use dcentrald_common::{
            AsicProtocolIdentity, BoardDesc, ChainTransportKind, WorkEngineKind,
        };
        let desc = BoardDesc::am2_s19pro();
        let admission = admit_board_desc_runtime_dispatch(
            Some(&desc),
            RuntimeDispatchKind::Serial,
            true,
            Some(AsicProtocolIdentity::Bm1398),
        )
        .expect("native BM1398 must be reachable from the selected serial entry point")
        .require_serial_asic_protocol(AsicProtocolIdentity::Bm1398)
        .unwrap();
        assert_eq!(admission.board_target(), "am2-s19pro");
        assert_eq!(admission.identity(), AsicProtocolIdentity::Bm1398);
        for configured in [
            None,
            Some(AsicProtocolIdentity::Bm1362),
            Some(AsicProtocolIdentity::Bm1397),
        ] {
            assert!(admit_board_desc_runtime_dispatch(
                Some(&desc),
                RuntimeDispatchKind::Serial,
                true,
                configured
            )
            .is_err());
        }
        let mut wrong_transport = desc.clone();
        wrong_transport.chain_transport = ChainTransportKind::ZynqHybrid;
        let mut wrong_engine = desc;
        wrong_engine.work_engine = WorkEngineKind::SerialWork;
        for invalid in [wrong_transport, wrong_engine] {
            assert!(admit_board_desc_runtime_dispatch(
                Some(&invalid),
                RuntimeDispatchKind::Serial,
                true,
                Some(AsicProtocolIdentity::Bm1398)
            )
            .is_err());
        }
    }

    #[test]
    fn bm1398_family_rows_bind_exact_native_dispatch_and_identity() {
        use dcentrald_common::{AsicProtocolIdentity, ChainTransportKind, WorkEngineKind};
        for platform in s19_bm1398_native_mining::platform::Bm1398Platform::ALL {
            let desc = BoardDesc::lookup(platform.board_target()).unwrap();
            assert_eq!(desc.asic_protocol, AsicProtocolIdentity::Bm1398);
            assert_eq!(desc.chain_transport, ChainTransportKind::FpgaUio);
            assert_eq!(desc.work_engine, WorkEngineKind::FpgaWorkFifo);
            let proof = admit_board_desc_runtime_dispatch(
                Some(desc), RuntimeDispatchKind::Serial, true,
                Some(AsicProtocolIdentity::Bm1398),
            ).unwrap().require_serial_asic_protocol(AsicProtocolIdentity::Bm1398).unwrap();
            assert_eq!(proof.board_target(), platform.board_target());
            for wrong in [None, Some(AsicProtocolIdentity::Bm1362), Some(AsicProtocolIdentity::Bm1397)] {
                assert!(admit_board_desc_runtime_dispatch(
                    Some(desc), RuntimeDispatchKind::Serial, true, wrong,
                ).is_err());
            }
            let mut wrong = desc.clone();
            wrong.chain_transport = ChainTransportKind::ZynqHybrid;
            assert!(admit_board_desc_runtime_dispatch(
                Some(&wrong), RuntimeDispatchKind::Serial, true,
                Some(AsicProtocolIdentity::Bm1398),
            ).is_err());
            let mut wrong_engine = desc.clone();
            wrong_engine.work_engine = WorkEngineKind::SerialWork;
            assert!(admit_board_desc_runtime_dispatch(
                Some(&wrong_engine), RuntimeDispatchKind::Serial, true,
                Some(AsicProtocolIdentity::Bm1398),
            ).is_err());
        }
    }

    /// 2026-08-27 S17 promotion: the four BM1397 targets admit the S17Hybrid
    /// dispatch end-to-end (work facet + exact protocol proof), and the two
    /// hybrid engines stay disjoint in BOTH directions.
    #[test]
    fn s17_bm1397_targets_admit_the_s17_hybrid_engine_only() {
        use dcentrald_common::AsicProtocolIdentity;

        for target in s17_hybrid_admission::S17_HYBRID_BOARD_TARGETS {
            let desc = dcentrald_common::BoardDesc::lookup(target).unwrap();
            let admission = admit_board_desc_runtime_dispatch(
                Some(desc),
                RuntimeDispatchKind::S17Hybrid,
                true,
                Some(AsicProtocolIdentity::Bm1397),
            )
            .unwrap_or_else(|error| panic!("{target} must admit the S17 hybrid engine: {error}"));
            // The minted proof is exactly Bm1397 (no Bm1362 laundering).
            admission
                .require_asic_protocol(
                    RuntimeDispatchKind::S17Hybrid,
                    target,
                    AsicProtocolIdentity::Bm1397,
                )
                .unwrap_or_else(|error| panic!("{target}: {error}"));

            // Cross-engine refusal: a BM1397 board never enters the BM1362
            // engine, even with its own protocol configured.
            assert!(
                admit_board_desc_runtime_dispatch(
                    Some(desc),
                    RuntimeDispatchKind::S19jHybrid,
                    true,
                    Some(AsicProtocolIdentity::Bm1397),
                )
                .is_err(),
                "{target} must not enter the BM1362 hybrid engine"
            );
        }
    }

    /// The BM1362 reference board and the BM1398 management-only board can
    /// never enter the BM1397 hybrid engine.
    #[test]
    fn bm1362_and_bm1398_boards_can_never_enter_the_bm1397_hybrid_engine() {
        use dcentrald_common::AsicProtocolIdentity;

        for (target, protocol) in [
            ("am2-s19j", AsicProtocolIdentity::Bm1362),
            ("am2-s19pro", AsicProtocolIdentity::Bm1398),
        ] {
            let desc = dcentrald_common::BoardDesc::lookup(target).unwrap();
            for configured in [Some(protocol), Some(AsicProtocolIdentity::Bm1397), None] {
                assert!(
                    admit_board_desc_runtime_dispatch(
                        Some(desc),
                        RuntimeDispatchKind::S17Hybrid,
                        true,
                        configured,
                    )
                    .is_err(),
                    "{target} must not enter the BM1397 hybrid engine (configured {configured:?})"
                );
            }
        }
    }

    /// The S17 auto-router matches only the exact promoted token set and only
    /// on the am2 platform (ADR-0013 §6: never a family prefix).
    #[test]
    fn s17_hybrid_auto_route_matches_only_exact_promoted_tokens() {
        for board_target in [
            "am2-s17p",
            "am2-s17",
            "am2-s17plus",
            "am2-t17",
            "am2-t17plus",
        ] {
            assert!(
                classify_s17_hybrid_auto("zynq-bm3-am2", board_target),
                "{board_target} must auto-route"
            );
            assert!(
                !classify_s17_hybrid_auto("zynq-bm3-am1", board_target),
                "{board_target} on a non-am2 platform must not auto-route"
            );
        }
        for non_target in [
            "am2-s19j",
            "am2-s19jpro-zynq",
            "am2-s17e",
            "am2-t17e",
            "am2-t19",
            "am2-s19",
            "",
        ] {
            assert!(
                !classify_s17_hybrid_auto("zynq-bm3-am2", non_target),
                "{non_target:?} must never auto-route into the S17 lane"
            );
        }
        // The two hybrid lanes' token sets are disjoint (no ambiguous auto).
        for board_target in ["am2-s19j", "am2-s19jpro", "am2-s19jpro-zynq"] {
            assert!(!is_s17_am2_board_target(board_target));
        }
        for board_target in ["am2-s17p", "am2-s17plus", "am2-t17", "am2-t17plus"] {
            assert!(!is_s19j_am2_board_target(board_target));
        }
    }

    #[test]
    fn non_bm1362_am2_launchers_never_inject_the_bm1362_hybrid_recipe() {
        for (name, source) in [
            ("am2-s17pro", S17_INIT_SOURCE),
            ("am2-s19pro", S19PRO_INIT_SOURCE),
        ] {
            let selector_start = source
                .find("IS_BM1362_HYBRID_TARGET=0")
                .unwrap_or_else(|| panic!("{name}: missing exact protocol selector"));
            let selector_end = source[selector_start..]
                .find("# Operator escape hatch")
                .map(|offset| selector_start + offset)
                .unwrap_or(source.len());
            let selector = &source[selector_start..selector_end];

            assert!(selector
                .contains("am2-s19j|am2-s19jpro|am2-s19jpro-zynq) IS_BM1362_HYBRID_TARGET=1"));
            assert!(selector.contains("if [ \"$IS_BM1362_HYBRID_TARGET\" = \"1\" ]; then"));
            assert!(!selector.contains("if [ \"$IS_AM2\" = \"1\" ]; then"));
            assert!(selector.contains("unset DCENT_AM2_SERIAL_WORK_DISPATCH"));
        }
    }

    #[test]
    fn board_desc_dispatch_unresolved_contract_is_pinned_to_actual_runtime_ownership() {
        // Tap has split ownership that BoardDesc cannot currently express.
        assert!(TAP_SOURCE.contains("DevmemFpgaChain::open_am2("));
        assert!(TAP_SOURCE.contains("fpga.write_work("));
        assert!(TAP_SOURCE.contains("bosminer owns PSU/PIC/serial"));
        assert!(!TAP_SOURCE.contains(".enable_voltage("));
        assert!(!TAP_SOURCE.contains(".set_voltage("));

        // Stock is a distinct kernel/DMA substrate, not S9's UIO work path.
        assert!(STOCK_SOURCE.contains("StockFpga::open("));
        assert!(STOCK_SOURCE.contains("StockFpgaDma::open("));
        assert!(STOCK_SOURCE.contains("StockFpgaWorkEngine::new("));

        // Serial carrier is selected downstream from device paths and a
        // separate lab gate, so main admission may validate work only.
        assert!(SERIAL_SOURCE.contains("SerialChainBackend::open_passthrough("));
        assert!(SERIAL_SOURCE.contains("UartTransService::open_paths_with_baud("));
        assert!(SERIAL_SOURCE.contains("DCENT_AM3_BB_ENABLE_UART_TRANS_LAB"));
    }

    #[test]
    fn board_desc_dispatch_has_one_consumer_before_every_mining_engine_constructor() {
        let run_signature = ["async fn run_", "main("].concat();
        let run_end_marker = ["// `spawn_proxy_mode_api` ", "moved"].concat();
        let run_start = MAIN_SOURCE.find(&run_signature).unwrap();
        let run_end = MAIN_SOURCE[run_start..]
            .find(&run_end_marker)
            .map(|offset| run_start + offset)
            .unwrap();
        let run_body = &MAIN_SOURCE[run_start..run_end];
        assert_eq!(
            run_body
                .matches("admit_board_desc_runtime_dispatch(")
                .count(),
            1,
            "main runtime must have one typed BoardDesc dispatch consumer"
        );
        let admission = run_body.find("admit_board_desc_runtime_dispatch(").unwrap();
        for constructor in [
            "run_am3_bb_mining(",
            "S19jTapMiner::new(",
            "S19jHybridMiner::new(",
            "S17HybridMiner::new(",
            "SerialMiner::new(",
            "Daemon::new(",
        ] {
            let constructor = run_body
                .find(constructor)
                .unwrap_or_else(|| panic!("missing runtime constructor {constructor}"));
            assert!(
                admission < constructor,
                "admission must precede {constructor}"
            );
        }
        assert!(
            !run_body.contains("StockMiner::new("),
            "top-level stock construction stays impossible until HAL can mint the live retained-lease receipt"
        );
        assert!(
            !run_body.contains("admit_stock_fpga_declared_route("),
            "declaration-only stock admission must not be wired into run_main"
        );
        assert!(STOCK_SOURCE.contains("StockFpgaDeclaredRouteAdmission"));
        assert!(STOCK_SOURCE.contains("StockFpgaCarrierPreflightReceipt"));
        let stock_constructor = &STOCK_SOURCE[STOCK_SOURCE
            .find("pub fn new(")
            .expect("StockMiner constructor")
            ..STOCK_SOURCE
                .find("pub async fn run")
                .expect("StockMiner run")];
        assert!(stock_constructor.contains("StockFpgaDeclaredRouteAdmission"));
        assert!(stock_constructor.contains("StockFpgaCarrierPreflightReceipt"));

        let identity_capture = run_body
            .find("capture_system_platform_identity()")
            .expect("immutable platform identity capture");
        assert_eq!(
            run_body
                .matches("capture_system_platform_identity()")
                .count(),
            1
        );
        assert!(identity_capture < admission);
        assert!(!run_body.contains("auto_detect_s19j_hybrid()"));
        assert!(!run_body.contains("am3_bb_mining::auto_detect_am3_bb()"));
        assert!(run_body
            .split_whitespace()
            .collect::<String>()
            .contains("Daemon::new(config,resolved_config_path,platform_identity,"));
        assert!(DAEMON_SOURCE.contains("let platform_identity = self.platform_identity.clone();"));
        let daemon_lifecycle = DAEMON_SOURCE
            .split("async fn run_lifecycle(&mut self)")
            .nth(1)
            .expect("daemon lifecycle body");
        assert!(
            !daemon_lifecycle.contains("capture_identity(&SystemPlatformIdentitySource)"),
            "standard daemon must consume the admitted snapshot, never reread identity"
        );

        for stale_reread in [
            "let legacy_psu_board_target = read_first_trimmed(",
            "let thermal_has_xadc = !detect_control_board()",
            "let mixed_chip_platform = read_first_trimmed(",
            "let control_board = detect_control_board();",
            "std::fs::read_to_string(\"/etc/dcentos/platform\")",
        ] {
            assert!(
                !daemon_lifecycle.contains(stale_reread),
                "post-admission policy must not reread mutable identity: {stale_reread}"
            );
        }
    }
}

/// Read `/etc/dcentos/board_target` once, before the tokio runtime is built,
/// so we can size the runtime to the detected platform. S17 / S17 Pro
/// images stamp `am2-s17p`, while older lab notes may still say `am1-s17`.
/// These low-RAM boards cannot afford the default tokio
/// blocking-pool of 512 threads — each holds a ~2 MB stack reservation.
///
/// Returns `(worker_threads, max_blocking_threads)`. When the file is
/// missing or unrecognized we fall back to tokio defaults (worker count
/// matches CPU; blocking pool = 512).
fn tokio_pool_for_board_target() -> (Option<usize>, Option<usize>) {
    let target = std::fs::read_to_string("/etc/dcentos/board_target")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    tokio_pool_for_board_target_marker(&target)
}

fn tokio_pool_for_board_target_marker(target: &str) -> (Option<usize>, Option<usize>) {
    match target.trim() {
        // S17: 228 MB RAM, dual-core Cortex-A9. 2 workers + 4 blocking
        // threads (vs tokio default 512) keeps the resident set well under
        // the RAM budget while still giving spawn_blocking enough lanes for
        // I²C + UIO + sysfs-thermal reads.
        "am2-s17p"
        | "am2-s17pro"
        | "am2-s17plus"
        | "am2-t17"
        | "am2-t17plus"
        | "x17-s17e-dspic-planned"
        | "x17-t17e-pic16-planned"
        | "am2-s17"
        | "am1-s17" => (Some(2), Some(4)),
        // BCB100 is a 128/256 MB-class STM32MP15 board depending on BOM/firmware
        // reporting; keep the runtime pool bounded like other low-RAM targets.
        "bcb100-s19jpro-lab" | "bcb100-s19-lab" => (Some(2), Some(4)),
        // S9 / S19/S19j Pro Zynq / am3-* etc.: tokio defaults.
        _ => (None, None),
    }
}

/// Install the process-wide cut-hash-on-crash panic hook (W24-CRASH-1).
///
/// On a `panic = "abort"` build, `Drop` impls do not run, so the
/// `Am2HomeHardStopGuard` RAII teardown is bypassed on a panic. This hook is
/// the software backstop: it runs the same best-effort cut-hash-before-noise
/// teardown the guard would have (drive PWR_CONTROL low FIRST, then command
/// fans to quiet idle, capped at PWM 30), but ONLY if an am2 hybrid run armed
/// the process-global teardown params (i.e. it actually energized hardware).
/// If nothing was armed, the teardown is a no-op. After the best-effort
/// teardown the previous (default) hook is invoked so the panic message is
/// still emitted, then the runtime aborts as configured.
fn install_cut_hash_on_crash_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Best-effort cut-hash-before-noise FIRST. This only touches sysfs
        // GPIO + the fan UIO via helpers that swallow their own errors and do
        // not allocate in the no-op path; it never re-panics on its own.
        crate::s19j_hybrid_mining::panic_hook_best_effort_teardown();
        // am3-aml NoPic (S21 / S19k Pro / S19j Pro-Amlogic): NoPic uses TAS5782M DAC
        // voltage with NO PIC heartbeat watchdog, so on a panic this is the ONLY
        // backstop that cuts PSU power (PWR_EN gpio437) + quiet-coasts fans. No-op
        // (allocation-free) unless a NoPic run armed it. Fire-critical — without it a
        // panic leaves an am3-aml home unit's boards energized indefinitely.
        // (wf_e0647147 swarm GAP #1, 2026-05-29.)
        crate::serial_mining::nopic_panic_hook_best_effort_teardown();
        // am3-bb (S19j Pro on AM335x BeagleBone): panic="abort" bypasses
        // Am3BbRunSafetyGuard::Drop. The fw=0x89 dsPIC's ~1-min hardware watchdog
        // would eventually cut voltage, but this cuts board-enable (hashboard power)
        // + asserts ASIC resets IMMEDIATELY instead. No-op unless an am3-bb run armed
        // it. Fans are already <= PWM_SAFETY_MAX by construction (Am3BbCappedFan).
        // (wf_7c757213 cross-platform safety audit, 2026-05-29.)
        crate::am3_bb_mining::am3_bb_panic_hook_best_effort_teardown();
        // stock-fpga (S9 BM1387 on /dev/axi_fpga_dev): StockMiner energizes the
        // chip rail via FPGA-I2C enable_voltage but has NO Drop guard, so on a
        // panic="abort" the rail stays up until only the ~60 s PIC heartbeat
        // watchdog cuts it. This cuts it immediately. No-op (allocation-free)
        // unless a stock-fpga run armed it. (prod-readiness hunt #16, 2026-05-29.)
        crate::stock_mining::stock_fpga_panic_hook_best_effort_teardown();
        // Exact S15/T15 native owner: terminal/feed-stop precede its retained
        // independent GPIO high attempt. No-op unless armed; this emergency
        // attempt cannot issue a completed shutdown or measured-rail receipt.
        crate::bm1391_mining::panic_hook_best_effort_teardown();
        // The exact T17e custodian likewise stops publication/feed before its
        // independent terminal attempt; no-op until that route owns hardware.
        crate::bm1396_mining_work::runtime::panic_teardown();
        // All existing emergency cutoff owners run before best-effort disk IO.
        dcentrald_api::diagnostics::record_panic(info);
        // Chain to the default hook so the panic location/message is logged,
        // then `panic = "abort"` aborts the process as before.
        previous(info);
    }));
}

/// Single-chokepoint fail-closed adjudication of the durable hardware
/// mutation-disposition journal, executed in `run_main` immediately BEFORE the
/// runtime-arm dispatch branch so that NO mining arm — `run_am3_bb_mining`,
/// `S19jHybridMiner`, `SerialMiner`, tap, stock-fpga, or the standard
/// `Daemon` path — can construct hardware or assert PWR_CONTROL while a prior
/// session's Mutated/Quarantined fabric disposition is unresolved. The
/// standard `Daemon::init` gate stays in place as defense-in-depth for the
/// passthrough path; this chokepoint is what closes the fail-open gap on the
/// arms launched directly from `run_main` (am2 hybrid / native serial /
/// am3-bb), which never enter `Daemon::init`.
///
/// Semantics mirror the `Daemon::init` gate exactly:
/// - absent journal => Resolved => admit with zero side effects (a clean
///   session stays byte-identical to today);
/// - a same-boot record whose every entry is Clean or carries a typed SafeOff
///   receipt => Resolved => durably remove it (removal failure stays
///   fail-closed, mirroring the thermal-lockout removal contract);
/// - Unresolved (foreign boot id, or a receipt-less non-Clean entry) or
///   Unreadable (any IO/parse problem) => refuse to start, naming the
///   unresolved fabric. A false refusal is acceptable; a false admit is the
///   cardinal failure.
///
/// No terminal safe-off latch is issued here: at this pre-dispatch point no
/// I2C service, rail owner, or watchdog exists yet, so there is nothing to
/// latch — the refusal happens strictly BEFORE any hardware authority is
/// constructed. A Resolved journal is NOT a typed SafeOff receipt: it never
/// authorizes skipping the shell session latch (`dcentrald-session-latch.sh`)
/// and never re-enables automatic restart (`restart.rs` keeps returning
/// false).
fn adjudicate_mutation_disposition_before_runtime_arm_dispatch() -> Result<()> {
    use dcentrald_common::mutation_disposition::{
        admit_hardware_after_mutation_adjudication, clear_mutation_disposition,
        load_and_adjudicate_mutation_disposition,
    };
    let journal_path = crate::daemon::terminal_mutation_disposition_path();
    let adjudication = load_and_adjudicate_mutation_disposition(
        &journal_path,
        &crate::daemon::current_boot_id_token(),
    );
    match admit_hardware_after_mutation_adjudication(&adjudication) {
        Ok(admission) => {
            if let Some(resolved_record) = adjudication.resolved_record() {
                let clearance = admission.into_clearance().ok_or_else(|| {
                    anyhow::anyhow!(
                        "resolved mutation-disposition journal did not carry path-bound clear authority"
                    )
                })?;
                if let Err(remove_error) = clear_mutation_disposition(clearance) {
                    error!(
                        ?resolved_record,
                        path = %journal_path.display(),
                        error = %remove_error,
                        "Mutation-disposition resolution was accepted but durable journal removal failed before runtime-arm dispatch; remaining fail-closed"
                    );
                    anyhow::bail!(
                        "mutation-disposition journal removal was not durably proven: {remove_error}"
                    );
                }
                info!(
                    ?resolved_record,
                    path = %journal_path.display(),
                    "Resolved mutation-disposition journal (clean or typed-SafeOff-receipted same-boot record) removed before runtime-arm dispatch"
                );
            }
            Ok(())
        }
        Err(refusal) => {
            error!(
                path = %journal_path.display(),
                refusal = %refusal,
                "Durable mutation-disposition journal refuses hardware admission before runtime-arm dispatch; no mining arm may construct hardware or assert PWR_CONTROL until an operator resolves or clears the journal"
            );
            anyhow::bail!(
                "mutation-disposition journal refuses hardware admission before runtime-arm dispatch: {refusal}"
            );
        }
    }
}

fn main() -> Result<()> {
    build_identity::retain();
    // Reject conflicting diagnostic/custody flags before an inherited custody
    // environment can arm its parent-lifetime signal or acquire its J3 lease.
    let args = std::env::args().collect::<Vec<_>>();
    let native_no_work_requested = serial_mining::bm1366_native_no_work::requested(&args)?;
    anyhow::ensure!(
        !native_no_work_requested || std::env::var_os("DCENT_S19K_STARTUP_BOOTSTRAP").is_none(),
        "native no-work initialization refuses the inherited S19k custody bootstrap"
    );
    // Pure reset-default inspection is adjudicated before any inherited
    // custody environment can select a publisher or hardware bootstrap role.
    let reset_args = std::env::args_os().collect::<Vec<_>>();
    if reset_args.iter().any(|arg| arg == "--check-reset-default") {
        anyhow::ensure!(reset_args.len() == 2 && reset_args[1] == "--check-reset-default",
            "usage: dcentrald --check-reset-default");
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let checked = runtime.block_on(dcentrald_api::reset_default::verify_installed_reset_default())
            .map_err(anyhow::Error::msg)?;
        println!("{}", serde_json::to_string(&checked)?);
        return Ok(());
    }
    // Track-1 bootstrap is the first action for custody roles. Publisher and daemon
    // roles arm permanent PDEATHSIG=SIGKILL and bind the exact wrapper lifetime
    // before the panic hook, Tokio construction, config, logging, or hardware.
    // The daemon additionally completes J0->C1->J1->ACTIVE->J2/release and the
    // held-FIFO token/EOF proof synchronously before runtime construction.
    let mut s19k_track1_j3_lease: Option<S19kTrack1J3Lease> = None;
    if let Some(bootstrap) = s19k_arm_permanent_pdeathsig_from_env()? {
        let args = std::env::args().collect::<Vec<_>>();
        match bootstrap.role() {
            S19kPreRuntimeBootstrapRole::Publisher => {
                anyhow::ensure!(
                    matches!(bootstrap, S19kPreRuntimeBootstrapState::LiveParent(_)),
                    "S19k journal publisher lost its exact wrapper before publication"
                );
                if args.len() == 5
                    && args[1] == "--s19k-track1-journal-source"
                    && args[3] == "--s19k-track1-journal-destination"
                {
                    s19k_publish_ephemeral_journal_from_cli(&args[2], &args[4])?;
                } else if args.len() == 9
                    && args[1] == "--s19k-track1-guarded-unlink-scratch"
                    && args[3] == "--s19k-track1-guarded-unlink-canonical"
                    && args[5] == "--s19k-track1-guarded-unlink-claim"
                    && args[7] == "--s19k-track1-guarded-unlink-completion"
                {
                    s19k_guarded_unlink_ephemeral_hardlink_from_cli(
                        &args[2], &args[4], &args[6], &args[8],
                    )?;
                } else if args.len() == 5
                    && args[1] == "--s19k-track1-consume-completion"
                    && args[3] == "--s19k-track1-guarded-unlink-canonical"
                {
                    s19k_consume_guarded_completion_from_cli(&args[2], &args[4])?;
                } else if args.len() == 13
                    && args[1] == "--s19k-track1-durable-replace-source"
                    && args[3] == "--s19k-track1-durable-replace-destination"
                    && args[5] == "--s19k-track1-durable-replace-old-sha256"
                    && args[7] == "--s19k-track1-durable-replace-old-bytes"
                    && args[9] == "--s19k-track1-durable-replace-new-sha256"
                    && args[11] == "--s19k-track1-durable-replace-new-bytes"
                {
                    s19k_durable_replace_from_cli(
                        &args[2], &args[4], &args[6], &args[8], &args[10], &args[12],
                    )?;
                } else {
                    anyhow::bail!(
                        "S19k publisher requires exactly one ordered journal-publication or guarded-unlink operation"
                    );
                }
                return Ok(());
            }
            S19kPreRuntimeBootstrapRole::Daemon => {
                anyhow::ensure!(!args.iter().any(|arg| matches!(arg.as_str(), "--firstlight-census" | "--firstlight-work" | "--firstlight-seconds" | "--check-firstlight-idle-config")),
                    "firstlight census cannot inherit S19k custody");
                let identity = parse_s19k_stock_handoff_cli(&args)?.context(
                    "S19k pre-runtime daemon bootstrap lacks the complete stock tree tuple",
                )?;
                let authority = parse_s19k_track1_receipt_authority_cli(&args)?.context(
                    "S19k pre-runtime daemon bootstrap lacks the receipt authority tuple",
                )?;
                s19k_complete_daemon_pre_runtime_bootstrap(&authority, &identity, bootstrap)?;
                s19k_track1_j3_lease = Some(s19k_track1_startup_barrier_and_acquire_j3(
                    &authority, &identity,
                )?);
            }
        }
    }
    // Pure supervisor receipt consumer: no Tokio runtime, GPIO, bus, or miner
    // owner is constructed. The common validator accepts fixed protected paths.
    let closeout_args = std::env::args().collect::<Vec<_>>();
    if closeout_args.iter().any(|arg| arg == "--check-firstlight-idle-config") {
        anyhow::ensure!(closeout_args.len() == 3 && closeout_args[1] == "--check-firstlight-idle-config",
            "usage: dcentrald --check-firstlight-idle-config PATH");
        firstlight_census::check_idle_config(&closeout_args[2])?;
        return Ok(());
    }
    if closeout_args.iter().any(|arg| arg == "--check-software-closeout") {
        anyhow::ensure!(closeout_args.len() == 6 && closeout_args[1] == "--check-software-closeout",
            "usage: dcentrald --check-software-closeout PID START BOOT SESSION");
        let pid: u32 = closeout_args[2].parse().context("invalid closeout PID")?;
        let start: u64 = closeout_args[3].parse().context("invalid closeout process start")?;
        dcentrald_common::mutation_disposition::consume_orderly_software_closeout(
            pid, start, &closeout_args[4], &closeout_args[5]).map_err(anyhow::Error::msg)?;
        return Ok(());
    }
    // W24-CRASH-1 (w24-thermal-safety F-1): install the cut-hash-on-crash
    // backstop BEFORE the tokio runtime starts. The release profile sets
    // `panic = "abort"` (see `Cargo.toml [profile.release]`), so on a Rust
    // panic the process aborts and NO `Drop` impl runs — including the
    // `Am2HomeHardStopGuard::Drop` run-scope safety net that drives PWR_CONTROL
    // low + fans to quiet idle. Without this hook the only remaining backstop
    // on a panic is the ~30 s hardware PIC/PSU heartbeat watchdog, leaving an
    // am2 home unit's chains energized for up to ~30 s. This hook reads the
    // process-global teardown params the am2 hybrid run-scope arms when it
    // energizes PWR_CONTROL and performs a best-effort cut-hash-before-noise
    // teardown, then chains to the default hook so the panic message is still
    // printed and the process still aborts (`panic = "abort"` is preserved —
    // the hook only runs first). The hook is intentionally tiny and
    // allocation-free in its hot path; it is a no-op if no run armed it.
    install_cut_hash_on_crash_panic_hook();

    let (worker_threads, max_blocking) = tokio_pool_for_board_target();
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(n) = worker_threads {
        builder.worker_threads(n);
    }
    if let Some(n) = max_blocking {
        builder.max_blocking_threads(n);
    }
    let runtime = builder.build()?;
    runtime.block_on(run_main(s19k_track1_j3_lease))
}

async fn run_main(mut s19k_track1_j3_lease: Option<S19kTrack1J3Lease>) -> Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    firstlight_census::initialize(&args)?;
    // Validate this powered diagnostic before any fan/recovery one-shot can run.
    let bm1366_native_no_work = serial_mining::bm1366_native_no_work::requested(&args)?;
    #[cfg(not(feature = "lab"))]
    anyhow::ensure!(!args.iter().any(|arg| arg == "--lab-runtime"),
        "--lab-runtime requires a binary compiled with the lab feature");

    // CLI info one-shots (`--help`/`-h`, `--version`/`-V`). MUST be the
    // FIRST thing checked — before the fan one-shots, config load,
    // logging init, mode routing, and ALL hardware/daemon bring-up.
    // Closes the defect where `dcentrald --help` (no handler existed)
    // fell through to the auto-`s19j-hybrid` path and silently started
    // the mining daemon. A "show me usage" / "what version" invocation
    // must print and exit(0), never daemonize.
    match wants_cli_info(&args) {
        Some(CliInfoRequest::Help) => {
            print!("{}", cli_help_text());
            std::process::exit(0);
        }
        Some(CliInfoRequest::Version) => {
            println!("dcentrald {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        None => {}
    }

    // Unrecognized-flag STRICT REJECT (Wave C, 2026-05-19).
    //
    // The previous non-blocking warning was a deferred TODO pending the
    // launcher-flag audit. Wave A audited every production launcher
    // (`T8_FLAG_ALLOWLIST.md`); Wave B closed G-T8-1 by removing the
    // single known offender (`--passthrough`) from the 3 deploy scripts
    // (commit `5aaae39f`). Pre-Wave-C re-audit confirmed zero
    // `NOT_IN_ALLOWLIST` flags across all 11 production launcher sites.
    //
    // Strict-reject now: a typo like `--gte-fan` (the 2026-05-19 `a lab unit`
    // over-spawn pattern — a flag the binary didn't recognize → silent
    // daemonize) fails loudly with exit 2 + full help text dump instead
    // of silently starting the mining daemon on a misconfigured invocation.
    //
    // eprintln (not tracing): logging is not initialized this early —
    // consistent with the fan one-shots.
    let unknown_flags = unrecognized_cli_flags(&args);
    if !unknown_flags.is_empty() {
        eprintln!(
            "dcentrald: ERROR: unrecognized flag(s) {:?}. \
             Refusing to start to prevent silent daemonization on a typo'd \
             flag (Wave C strict-reject; G-T8-1 closed in Wave B). \
             The canonical flag list:",
            unknown_flags
        );
        eprintln!();
        eprintln!("{}", cli_help_text());
        std::process::exit(2);
    }
    if bm1391_boot_safety::requested(&args)? {
        anyhow::ensure!(
            s19k_track1_j3_lease.is_none(),
            "BM1391 boot parking cannot borrow S19k custody"
        );
        return bm1391_boot_safety::run().await;
    }
    if bm1396_boot_safety::requested(&args)? {
        anyhow::ensure!(
            s19k_track1_j3_lease.is_none(),
            "BM1396 boot parking cannot borrow S19k custody"
        );
        return bm1396_boot_safety::run().await;
    }
    if c43_boot_safety::requested(&args)? {
        anyhow::ensure!(
            s19k_track1_j3_lease.is_none(),
            "C43 boot parking cannot borrow S19k custody"
        );
        return c43_boot_safety::run().await;
    }
    let s19k_journal_source = single_cli_value(&args, "--s19k-track1-journal-source")?;
    let s19k_journal_destination = single_cli_value(&args, "--s19k-track1-journal-destination")?;
    match (s19k_journal_source, s19k_journal_destination) {
        (None, None) => {}
        (Some(_), Some(_)) => anyhow::bail!(
            "S19k journal publication was not completed by the pre-panic PDEATHSIG bootstrap"
        ),
        _ => anyhow::bail!("S19k startup journal publication requires both source and destination"),
    }
    let s19k_stock_handoff_identity = parse_s19k_stock_handoff_cli(&args)?;
    let s19k_track1_receipt_authority = parse_s19k_track1_receipt_authority_cli(&args)?;
    let s19k_track1_no_work = args.iter().any(|arg| arg == "--s19k-track1-no-work");
    let s19k_install_custody_safeoff = args
        .iter()
        .any(|arg| arg == "--s19k-install-custody-safeoff");
    let s19k_track1_bounded_work_proof = args
        .iter()
        .any(|arg| arg == "--s19k-track1-bounded-work-proof");
    let s19k_track1_endurance_work_proof = args
        .iter()
        .any(|arg| arg == "--s19k-track1-endurance-work-proof");
    anyhow::ensure!(
        s19k_stock_handoff_identity.is_some() == s19k_track1_receipt_authority.is_some(),
        "S19k Track-1 stock handoff and content-bound receipt authority must be supplied together"
    );
    anyhow::ensure!(
        s19k_stock_handoff_identity.is_some() == s19k_track1_j3_lease.is_some(),
        "S19k Track-1 CLI authority and pre-runtime J3 all-thread lease must be supplied together"
    );
    anyhow::ensure!(
        !s19k_track1_no_work || s19k_stock_handoff_identity.is_some(),
        "--s19k-track1-no-work requires the complete S19k Track-1 custody/receipt authority"
    );
    anyhow::ensure!(
        !s19k_install_custody_safeoff || s19k_stock_handoff_identity.is_some(),
        "--s19k-install-custody-safeoff requires the complete S19k Track-1 custody/receipt authority"
    );
    anyhow::ensure!(
        !s19k_track1_bounded_work_proof || s19k_stock_handoff_identity.is_some(),
        "--s19k-track1-bounded-work-proof requires the complete S19k Track-1 custody/receipt authority"
    );
    anyhow::ensure!(
        !s19k_track1_endurance_work_proof || s19k_stock_handoff_identity.is_some(),
        "--s19k-track1-endurance-work-proof requires the complete S19k Track-1 custody/receipt authority"
    );
    anyhow::ensure!(
        usize::from(s19k_install_custody_safeoff)
            + usize::from(s19k_track1_no_work)
            + usize::from(s19k_track1_bounded_work_proof)
            + usize::from(s19k_track1_endurance_work_proof)
            <= 1,
        "S19k install-custody-safeoff, no-work, bounded-work-proof, and endurance-work-proof authorities are mutually exclusive"
    );
    if let (Some(identity), Some(authority), Some(lease)) = (
        s19k_stock_handoff_identity.as_ref(),
        s19k_track1_receipt_authority.as_ref(),
        s19k_track1_j3_lease.as_ref(),
    ) {
        // The lease was acquired before Tokio construction. Rebind it to the
        // independently re-parsed CLI/runtime authority before config load.
        lease.require_context(authority, identity)?;
        lease.require_install_custody_safeoff_policy(s19k_install_custody_safeoff)?;
        lease.require_no_work_policy(s19k_track1_no_work)?;
        lease.require_bounded_work_proof_policy(s19k_track1_bounded_work_proof)?;
        lease.require_endurance_work_proof_policy(s19k_track1_endurance_work_proof)?;
    }
    let s19k_track1_recovery_safeoff_mode = args
        .iter()
        .any(|arg| arg == "--s19k-track1-recovery-safeoff");
    if s19k_install_custody_safeoff {
        anyhow::ensure!(
            args.iter().any(|arg| arg == "--serial-mining"),
            "--s19k-install-custody-safeoff requires --serial-mining"
        );
        for incompatible in [
            "--set-fan",
            "--hold-fan",
            "--get-fan",
            "--fan-sweep",
            "--safe-off",
            "--s19k-track1-recovery-safeoff",
            "--verify-bundle",
            "--s19j-hybrid",
            "--s17-hybrid",
            "--tap-mode",
            "--stratum-proxy",
            "--am3-bb-mining",
            "--stock-fpga",
        ] {
            anyhow::ensure!(
                !args.iter().any(|arg| arg == incompatible),
                "--s19k-install-custody-safeoff is incompatible with {incompatible}"
            );
        }
    }

    // R2 (2026-05-17): `--set-fan <PWM>` one-shot. This MUST run BEFORE config
    // load, logging init, any mode routing, and any hardware bring-up. It is
    // a tiny synchronous open→write→readback→exit that touches ONLY the FPGA
    // fan-control register (no PIC/PSU/ASIC/I2C/voltage, no tokio HW runtime).
    // Used by the am2 init-script paths (S82dcentrald fan_safety_override /
    // clean-stop, dcentos-early-init.sh) which can't reach the UIO-bound am2
    // fan IP via devmem
    //.
    // Exit codes are a defined contract for the init script:
    //   0 = fan PWM written + read back, 1 = UIO open/discovery failed,
    //   2 = bad/missing PWM argument.
    if let Some(pos) = args.iter().position(|a| a == "--set-fan") {
        let pwm_arg = args.get(pos + 1).map(String::as_str);
        let allow_loud = args.iter().any(|a| a == "--allow-loud");
        std::process::exit(run_set_fan_oneshot(pwm_arg, allow_loud));
    }
    // Wave (2026-05-29, fan-custodian): `--hold-fan <PWM>` PERSISTENT fan
    // custodian. Unlike `--set-fan` (write once → exit), this parks the fan at
    // the given PWM and then STAYS RESIDENT, re-asserting the PWM on a ~5 s
    // tokio interval until SIGTERM/SIGINT. This is the AM2-safe replacement for
    // the init-script `--set-fan N` that drifts loud: on AM2 (XIL Zynq) the fan
    // PWM is held only while a process owns the uio16 mmap AND keeps
    // re-commanding it (mmap-hold alone is NOT enough — a daemon that wrote PWM
    // once still drifted; the 5 s re-assert is the cure). It reuses the SAME
    // in-process fan-control paths: exact S19-family targets enable C52 while
    // S17 and unknown targets preserve their existing board mode. Clamp is
    // identical to `--set-fan` (≤ PWM_SAFETY_MAX home cap unless
    // `--allow-loud`). Runs BEFORE config/logging/mode routing; it is a NEW
    // opt-in subcommand and cannot alter the normal daemon path. It is
    // SIGTERM-responsive and also exits fail-closed after bounded consecutive
    // refresh/readback failures, revoking its readiness receipt first; rule:
    // .
    if let Some(pos) = args.iter().position(|a| a == "--hold-fan") {
        let pwm_arg = args.get(pos + 1).map(String::as_str);
        let allow_loud = args.iter().any(|a| a == "--allow-loud");
        std::process::exit(run_hold_fan(pwm_arg, allow_loud).await);
    }
    if args.iter().any(|a| a == "--get-fan") {
        std::process::exit(run_get_fan_oneshot());
    }
    if let Some(pos) = args.iter().position(|a| a == "--fan-sweep") {
        let list_arg = args.get(pos + 1).map(String::as_str);
        let dwell_ms = parse_fan_sweep_dwell_ms(&args);
        let allow_loud = args.iter().any(|a| a == "--allow-loud");
        std::process::exit(run_fan_sweep_oneshot(list_arg, dwell_ms, allow_loud));
    }
    // Wave-B no-brick (2026-05-28): `--safe-off` operator emergency power cut.
    // Runs BEFORE config/logging/mode routing (same as --set-fan); cuts ASIC
    // power per platform then sets fans quiet. New opt-in subcommand — cannot
    // alter the normal daemon path.
    if args.iter().any(|a| a == "--safe-off") {
        std::process::exit(run_safe_off_oneshot().await);
    }
    // On-device OTA bundle verification one-shot (wf_c00e5d9e follow-up,
    // 2026-05-29): reuses the daemon's ed25519 + manifest verifier so install
    // scripts/operators get an in-band signature re-verify the device's tool set
    // otherwise lacks. Runs BEFORE config/logging/daemon routing (same as the fan
    // one-shots); read-only verify + exit, never flashes — cannot alter the
    // normal daemon path.
    if let Some(pos) = args.iter().position(|a| a == "--verify-bundle") {
        let path_arg = args.get(pos + 1).map(String::as_str);
        std::process::exit(run_verify_bundle_oneshot(path_arg));
    }

    let stock_fpga_mode = args.iter().any(|a| a == "--stock-fpga");
    let serial_mining_mode = args.iter().any(|a| a == "--serial-mining");
    let explicit_loud_fan_authority = args.iter().any(|a| a == "--allow-loud");
    anyhow::ensure!(
        s19k_stock_handoff_identity.is_none() || serial_mining_mode,
        "S19k stock custody handoff identity requires --serial-mining"
    );
    let s19j_hybrid_cli = args.iter().any(|a| a == "--s19j-hybrid");
    // S17-family (BM1397) hybrid lane, 2026-08-27 promotion
    // (`2026-08-27-antminer17-unlock-armada`). Mirrors the S19j shape: explicit
    // `--s17-hybrid`, or auto-route from the exact promoted board-target tokens
    // when the operator did not request another bring-up path.
    let s17_hybrid_cli = args.iter().any(|a| a == "--s17-hybrid");
    // Phase 6 Option 3: tap mode. bosminer owns PIC/PSU/ASIC state — dcentrald
    // only dispatches work to the FPGA. Defensive alternative to --s19j-hybrid
    // while PIC 0x86 + PSU framing are unresolved.
    let tap_mode = args.iter().any(|a| a == "--tap-mode");
    // Phase 11B: Stratum V1 TCP relay. bosminer keeps full control of
    // hardware; dcentrald only proxies the Stratum V1 byte stream between
    // bosminer (localhost:3333) and the upstream pool. Zero hardware access.
    // See DCENT_OS_Antminer/dcentrald/dcentrald/src/stratum_proxy.rs.
    let stratum_proxy_mode = args.iter().any(|a| a == "--stratum-proxy");
    // Phase C (2026-05-12): AM335x BeagleBone S19j Pro (S19J_IO_BOARD_V2_0,
    // the `a lab unit`-class unit) mining mode. Cold-boot via the Phase-B
    // `BeagleBonePlatform` + `cold_boot_sequence_s19j_io_v2`, work dispatch via
    // the Phase-1 clean-room `bm1362::uart_transport::Am335xUartTransport` (no
    // kernel module). Auto-detected when the board-target file says
    // `am3-bb-s19jpro` or the device-tree model is an `S19J_IO_BOARD`.
    // See DCENT_OS_Antminer/dcentrald/dcentrald/src/am3_bb_mining.rs.
    let am3_bb_cli = args.iter().any(|a| a == "--am3-bb-mining");
    let mut platform_identity = crate::daemon::capture_system_platform_identity()?;
    let am3_bb_auto = platform_identity.board_target() == "am3-bb-s19jpro";
    let am3_bb_mode = am3_bb_cli || am3_bb_auto;

    // Auto-route am2 platforms into s19j-hybrid mode only when the operator did
    // not explicitly request another bring-up path. This keeps the am2 safety
    // guard for the default case while still letting us intentionally run the
    // serial/tap/proxy experiments on .139.
    let (auto_hybrid, detected_platform) = classify_s19j_hybrid_auto(
        platform_identity.platform_marker(),
        platform_identity.board_target(),
    );
    // The S17 lane auto-routes from the same platform identity; the two token
    // sets are disjoint, so at most one of the two auto flags can be true.
    let auto_s17_hybrid = classify_s17_hybrid_auto(
        platform_identity.platform_marker(),
        platform_identity.board_target(),
    );
    anyhow::ensure!(
        !(auto_hybrid && auto_s17_hybrid),
        "board target matched both the BM1362 and BM1397 hybrid auto-routes; \
         refusing ambiguous promotion"
    );
    anyhow::ensure!(
        !(s19j_hybrid_cli && s17_hybrid_cli),
        "--s19j-hybrid and --s17-hybrid are mutually exclusive engines"
    );
    let explicit_non_hybrid_mode =
        stock_fpga_mode || serial_mining_mode || tap_mode || stratum_proxy_mode || am3_bb_mode;
    let s19j_hybrid_mode = s19j_hybrid_cli || (auto_hybrid && !explicit_non_hybrid_mode);
    let s17_hybrid_mode = s17_hybrid_cli || (auto_s17_hybrid && !explicit_non_hybrid_mode);

    let c43_native_mode = matches!(platform_identity.board_target(), "am1-s9se" | "am1-s9k")
        && !explicit_non_hybrid_mode
        && !s19j_hybrid_cli
        && !s17_hybrid_cli;
    let bm1391_native_mode = matches!(platform_identity.board_target(), "am1-s15" | "am1-t15")
        && !explicit_non_hybrid_mode
        && !s19j_hybrid_cli
        && !s17_hybrid_cli;

    let bm1396_native_mode = matches!(platform_identity.board_target(), "am2-t17e" | "am2-s17e")
        && !explicit_non_hybrid_mode
        && !s19j_hybrid_cli
        && !s17_hybrid_cli;

    // Find --config <path> argument
    let config_path = args
        .windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_string());

    // Load configuration. NO-BRICK CONTRACT (gap-swarm daemon-startup #1/#9):
    // a config problem must NEVER `?`-crash here — S82dcentrald records a durable
    // unresolved hardware session and intentionally refuses automatic restart,
    // leaving no daemon / no :8080 API / no dashboard until disposition is
    // resolved. And a
    // PRESENT-BUT-CORRUPT primary config must NOT silently revert to the baked
    // /etc default (mining-enabled on some platforms). So:
    //   * primary loads          -> use it
    //   * primary ABSENT         -> try /etc fallback; if that also fails -> defaults
    //   * primary present+INVALID -> fail CLOSED to management-only defaults
    //                                (do NOT revert to /etc)
    // management_only_default() forces mining.enabled=false => management-only.
    let (mut config, resolved_config_path) = match DcentraldConfig::load(&config_path) {
        Ok(cfg) => (cfg, config_path.clone()),
        Err(primary_err) => {
            // Only an exact NotFound from the bounded/no-follow loader grants
            // fallback authority. `Path::exists()` follows symlinks and turns a
            // dangling primary symlink into false, which previously made an
            // unsafe PRESENT primary look absent and could activate the baked
            // fallback. Permission, type, size, symlink, parse, validation, and
            // every other indeterminate error remain management-only.
            if !load_error_is_definitely_absent(&primary_err) {
                eprintln!(
                    "dcentrald: config at {} is PRESENT but INVALID ({:#}) — NOT reverting to the baked default; entering MANAGEMENT-ONLY with safe defaults (mining disabled)",
                    config_path, primary_err
                );
                (
                    DcentraldConfig::management_only_default(),
                    "<management-only-default:invalid-primary>".to_string(),
                )
            } else {
                match DcentraldConfig::load(FALLBACK_CONFIG_PATH) {
                    Ok(cfg) => {
                        eprintln!(
                            "dcentrald: config {} absent — using fallback {}",
                            config_path, FALLBACK_CONFIG_PATH
                        );
                        (cfg, FALLBACK_CONFIG_PATH.to_string())
                    }
                    Err(fallback_err) => {
                        eprintln!(
                            "dcentrald: no usable config — {} absent and {} failed ({:#}) — entering MANAGEMENT-ONLY with safe defaults (mining disabled) instead of crashing",
                            config_path, FALLBACK_CONFIG_PATH, fallback_err
                        );
                        (
                            DcentraldConfig::management_only_default(),
                            "<management-only-default:no-config>".to_string(),
                        )
                    }
                }
            }
        }
    };
    if s19k_track1_recovery_safeoff_mode {
        if s19k_stock_handoff_identity.is_some() || serial_mining_mode {
            eprintln!("dcentrald: S19k Track-1 recovery SafeOff refuses mining/handoff flags");
            std::process::exit(2);
        }
        match crate::serial_mining::s19k_track1_recovery_safeoff(&config) {
            Ok(receipt) => {
                println!("{receipt}");
                std::process::exit(0);
            }
            Err(error) => {
                eprintln!("dcentrald: S19k Track-1 recovery SafeOff failed: {error:#}");
                std::process::exit(1);
            }
        }
    }
    anyhow::ensure!(
        !s19k_install_custody_safeoff || config.s19k_install_custody_pool_free(),
        "S19k install-custody-safeoff requires mining disabled and every primary, failover, SV2, donation, disconnect, and job-declaration route absent"
    );
    anyhow::ensure!(
        s19k_stock_handoff_identity.is_none()
            || config.mining_start_enabled()
            || s19k_install_custody_safeoff,
        "S19k stock custody handoff identity cannot be supplied to an idle/API-only config"
    );
    platform_identity.apply_config_platform_declaration(&config.platform);
    crate::daemon::exercise_s19k_nopic_config_admission(&platform_identity, &config);

    // Runtime-only acceptance is a process policy. Redirect the operator's
    // configured autotuner root as well as its default so no opted-in tuner can
    // persist profiles beneath /data while the ephemeral launcher is active.
    config.autotuner.profile_path = crate::runtime_policy::persistence_path(
        std::path::Path::new(&config.autotuner.profile_path),
        std::path::Path::new("/tmp/dcent/autotuner"),
    )
    .to_string_lossy()
    .into_owned();

    // Initialize structured logging. No-brick: a logging-subsystem failure must
    // NOT crash the daemon (S82dcentrald intentionally refuses automatic restart
    // while its durable hardware-session disposition remains unresolved). The
    // safety/management plane (API/dashboard/management-only park,
    // re-flash detection) does not depend on structured logging — degrade
    // closed-but-alive instead of dying. (gap-swarm daemon-startup #3)
    if let Err(e) = init_logging(&config.general.log_level) {
        eprintln!("dcentrald: logging init failed ({e:#}) — continuing without configured logging");
    }

    // W1.4: install the process-wide log-tail mask flag from [logging].
    // Default (true) masks wallet addresses on `/api/debug/log` responses.
    // Per-call masking on `worker=` / `username=` / `wallet=` log fields is
    // independent of this flag and cannot be disabled via config — see
    // `dcentrald-common/src/wallet_mask.rs`.
    dcentrald_common::set_mask_logs(config.logging.mask_logs);

    // Print the D-Central banner — first thing a miner sees on boot
    print_banner();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config_path = %resolved_config_path,
        stock_fpga = stock_fpga_mode,
        serial_mining = serial_mining_mode,
        s19j_hybrid = s19j_hybrid_mode,
        s19j_hybrid_cli = s19j_hybrid_cli,
        s19j_hybrid_auto = auto_hybrid,
        tap_mode = tap_mode,
        stratum_proxy = stratum_proxy_mode,
        am3_bb = am3_bb_mode,
        am3_bb_auto = am3_bb_auto,
        platform = %detected_platform,
        "dcentrald starting — loading configuration and preparing hardware"
    );

    // wf_c00e5d9e OTA follow-up: self-attest `--verify-bundle` capability. Drop a
    // marker file so install scripts (e.g. install_amlogic_persistent.sh) can
    // SAFELY decide whether the on-device dcentrald supports the verb via a
    // no-daemon-start `[ -f ]` check BEFORE invoking it for an in-band ed25519
    // OTA re-verify — resolving the probe-safety problem (invoking --verify-bundle
    // on a pre-verb binary could start the daemon). Best-effort: /data may be
    // read-only/absent on some platforms; failure is non-fatal and never blocks
    // startup. A persistent-install-capable run of THIS binary proves verb
    // support; the external-media-only AM3-BB route is intentionally excluded.
    let ephemeral_runtime = crate::runtime_policy::ephemeral_runtime_enabled();
    let verify_bundle_publication = if am3_bb_mode || ephemeral_runtime {
        // The AM3-BB acceptance route is explicitly external-media-only. Its
        // temporary binary must not create `/data` capability state merely by
        // starting on stock LuxOS. Persistent installers do not consume this
        // route, so skipping the marker is both truthful and fail-closed.
        info!(
            target = VERIFY_BUNDLE_CAPABILITY_PATH,
            ephemeral_runtime,
            "skipping persistent verify-bundle capability publication for non-persistent runtime"
        );
        None
    } else {
        Some(publish_verify_bundle_capability(std::path::Path::new(
            VERIFY_BUNDLE_CAPABILITY_PATH,
        )))
    };
    match verify_bundle_publication {
        None | Some(Ok(_)) => {}
        Some(Err(VerifyBundleCapabilityPublishError::CreateParent(error))) => tracing::debug!(
            error = %error,
            persistence_stage = "create-parent",
            target_published = false,
            publication_durability_uncertain = false,
            "could not publish verify-bundle capability sentinel (non-fatal)"
        ),
        Some(Err(VerifyBundleCapabilityPublishError::Publish(error))) => tracing::debug!(
            error = %error,
            persistence_stage = %error.stage(),
            target_published = error.target_published(),
            publication_durability_uncertain = error.target_published(),
            cleanup_error = ?error.cleanup_error(),
            "could not publish verify-bundle capability sentinel (non-fatal)"
        ),
    }

    // Explicit operator-facing log line when we flipped the mode ourselves.
    // Operators SSHing into a bring-up unit need to see this reason clearly —
    // the alternative (silent auto-route) was a painful bring-up surprise on .139.
    if s19j_hybrid_mode && auto_hybrid && !s19j_hybrid_cli {
        info!(
            platform = %detected_platform,
            "auto-enabled s19j-hybrid from /etc/bos_platform={} (no --s19j-hybrid CLI flag passed)",
            detected_platform
        );
    }

    //  HIGH-8 (2026-05-24): recipe-broken runtime guard.
    //
    // Refuse to start on `a lab unit`-class AM2-XIL-Loki hardware if any of the
    // 4 LIVE-FALSIFIED "must-not-set" env vars from the  PROVEN
    // MINING RECIPE are present. Operator Gate-1 Q2 (2026-05-24): the
    // chosen posture is fail-closed at startup — silently mining with a
    // recipe-broken env on `a lab unit` would burn an AC-cycle for the
    // operator before they notice the broken handoff. See:
    //   * src/wave55a_recipe_guard.rs (decision + logging)
    //   * tests/wave55a_recipe_broken_guard_refuses_forbidden_env_on_xil_25.rs
    //   *
    //   *
    //
    // Position: AFTER config + logging init + platform-stamp read,
    // BEFORE any I²C / UIO / PSU / PIC / chain hardware touch (no-op
    // pass for S9 / `a lab unit` / `a lab unit` / `a lab unit` / `a lab unit` — guarded by
    // fingerprint match on platform `zynq-bm3-am2` + board_target
    // ending with `xil`, so non-`a lab unit` units never see  noise).
    //
    // Override (lab-only): `DCENT_BYPASS_WAVE54_GUARD=1` flips refusal
    // to a loud warn + continue.
    if let Err(refusal) = wave55a_recipe_guard::enforce() {
        // `tracing::error!` was already emitted inside `enforce()` with
        // the full operator-facing details + runbook + memory-rule
        // pointers. Use a clean EX_CONFIG exit code rather than
        // `?`-bubbling an anyhow stack trace — the operator gets a
        // distinct exit code (78) to distinguish "recipe-broken env"
        // from generic runtime failures (1) or strict-reject unknown
        // flag (2). The `_refusal` data is already in the structured
        // error log; nothing else to do here.
        let _ = refusal;
        std::process::exit(wave55a_recipe_guard::EX_CONFIG_EXIT_CODE);
    }

    // Wave K Lane A: load the on-disk silicon-profile registry into the global
    // RwLock so the `/api/profiles/silicon/*` REST surface reflects real
    // on-device profiles (shipped at /etc/dcentrald/profiles.d via the shared
    // rootfs overlays). Fail-safe: a missing dir → empty registry (logged), a
    // malformed JSON file → skipped. READ-ONLY: this does NOT drive mining
    // freq/voltage — the daemon setpoint path is `MinerProfile::for_chip` + the
    // autotuner slug presets, both untouched. Runs in every mode so the API is
    // consistent. (Driving setpoints from a resolved profile is the deferred
    // Wave-K-C / matrix §7 #15 power-adjacent work, NOT this.)
    {
        let profile_dir = dcentrald_api_types::profile_schema::PROFILE_DROP_IN_DIR;
        match dcentrald_silicon_profiles::registry::global().write() {
            Ok(mut reg) => match reg.reload(std::path::Path::new(profile_dir)) {
                Ok(stats) => info!(
                    dir = profile_dir,
                    loaded = stats.loaded,
                    skipped = stats.skipped,
                    "silicon-profile registry loaded from disk (REST /api/profiles/silicon/*)"
                ),
                Err(e) => tracing::warn!(
                    dir = profile_dir,
                    error = %e,
                    "silicon-profile registry load failed — continuing with empty registry"
                ),
            },
            Err(_) => tracing::warn!("silicon-profile registry lock poisoned — skipping load"),
        }
    }

    // Register both Unix shutdown signals synchronously before any route can
    // enter hardware initialization. `tokio::spawn` is not a readiness barrier:
    // constructing these streams here makes signal ownership a fail-closed
    // startup prerequisite instead of racing standard-daemon bootstrap.
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .context("failed to register SIGINT shutdown handler before hardware admission")?;
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .context("failed to register SIGTERM shutdown handler before hardware admission")?;

    // Create cancellation token for coordinated shutdown
    let shutdown_token = CancellationToken::new();
    let shutdown_token_signal = shutdown_token.clone();

    // The streams are already registered; this task only awaits delivery.
    tokio::spawn(async move {
        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating graceful shutdown");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown");
            }
        }

        shutdown_token_signal.cancel();
    });

    // Exclusive bounded firstlight returns directly to exit. It never falls into
    // cold activation, API startup, simulation routing, or error parking.
    if firstlight_census::operation_requested() {
        anyhow::ensure!(resolved_config_path == config_path,
            "firstlight census refuses missing/invalid config fallback");
        let selected = selected_runtime_dispatch(
            am3_bb_mode, stratum_proxy_mode, tap_mode, s19j_hybrid_mode,
            s17_hybrid_mode, serial_mining_mode, stock_fpga_mode,
        );
        return firstlight_census::run(config, resolved_config_path,
            platform_identity, selected, shutdown_token).await;
    }

    // The initial native idle process has never acquired hardware. Its
    // API may save configuration and self-exec with the same PID to activate
    // mining. This branch is deliberately before every server/hardware route;
    // it is unavailable after bring-up, a route failure, or inherited custody.
    let cold_native_route = c43_native_mode
        || bm1391_native_mode
        || bm1396_native_mode
        || (s17_hybrid_mode && !explicit_non_hybrid_mode && !s19j_hybrid_cli)
        || (serial_mining_mode
            && matches!(
                platform_identity.board_target(),
                "am2-s19pro"
                    | "am2-s19"
                    | "am2-t19"
                    | "am2-s19a"
                    | "am2-s19plus"
                    | "am3-s21"
                    | "am3-s21pro"
                    | "am3-s21xp"
                    | "am3-s19xp"
                    | "am3-s19jxp"
                    | "am3-s19jproa"
                    | "am3-s19jproplus"
                    | "am3-s19jpro-aml"
            )
            && !stock_fpga_mode
            && !tap_mode
            && !stratum_proxy_mode
            && !am3_bb_mode
            && !s19j_hybrid_cli
            && !s17_hybrid_cli)
        || (matches!(platform_identity.board_target(), "am1-s9i" | "am1-s9j")
            && !explicit_non_hybrid_mode
            && !s19j_hybrid_cli
            && !s17_hybrid_cli);
    if crate::runtime::cold_activation::eligible(
        platform_identity.board_target(),
        &config,
        &resolved_config_path,
        cold_native_route,
        s19k_track1_j3_lease.is_some() || s19k_stock_handoff_identity.is_some(),
        crate::runtime_policy::ephemeral_runtime_enabled(),
    ) {
        let closeout = crate::runtime::cold_activation::run(
            config,
            platform_identity.board_target(),
            shutdown_token.clone(),
        )
        .await?;
        return crate::daemon::publish_never_started_software_closeout(closeout);
    }

    // Default-off gRPC telemetry/control server. Reads use daemon snapshots;
    // writes use the installed delegate to the same safety-gated REST handlers.
    // Server admission refuses a release image without a valid root-only token
    // and refuses unauthenticated non-loopback development binds.
    if config.api.grpc.enabled {
        let grpc_addr_str = format!("{}:{}", config.api.grpc.bind, config.api.grpc.port);
        match grpc_addr_str.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                let home_mode =
                    dcentrald_api::OperatingMode::from_config_str(&config.mode.active).is_home();
                // CE-122: resolve the chip family so GetConstraints returns a
                // family-honest envelope instead of always BM1362. Fail-closed
                // chain: configured serial_chip_type -> model label -> stamped
                // board_target file. Empty -> BM1362 default (byte-identical).
                let grpc_chip_family = config
                    .mining
                    .serial_chip_type
                    .clone()
                    .or_else(|| {
                        config
                            .mining
                            .model
                            .as_deref()
                            .and_then(model::model_chip_label)
                            .map(str::to_string)
                    })
                    .or_else(|| {
                        model::board_target_chip_label(platform_identity.board_target())
                            .map(str::to_string)
                    })
                    .unwrap_or_default();
                let grpc_reflection_enabled = config.api.grpc.reflection;
                tokio::spawn(async move {
                    if let Err(err) = dcentrald_api_grpc::serve(
                        addr,
                        home_mode,
                        grpc_chip_family,
                        grpc_reflection_enabled,
                    )
                    .await
                    {
                        error!(error = %err, "dcentrald-api-grpc server exited with error");
                    }
                });
                info!(
                    addr = %grpc_addr_str,
                    reflection = grpc_reflection_enabled,
                    "scheduled dcentrald-api-grpc startup (listener admission runs inside task)"
                );
            }
            Err(err) => {
                error!(
                    bind = config.api.grpc.bind.as_str(),
                    port = config.api.grpc.port,
                    error = %err,
                    "invalid [api.grpc] bind/port — gRPC server NOT started"
                );
            }
        }
    }

    #[cfg(feature = "sim-hal")]
    if dcentrald_hal::platform::sim::sim_environment_is_mentioned() {
        return sim_runtime::run(config, shutdown_token.clone()).await;
    }

    // Typed composition admission over the existing dispatch order. BoardDesc
    // does not choose a mining arm; CLI/auto-detection above still does. It can
    // only reject a proven transport/work-engine/ASIC contradiction before an
    // arm constructs hardware. Unknown and unresolved hardware ownership now
    // parks management-only; safe-direction cleanup remains independently
    // available and does not require mining admission.
    let runtime_dispatch = if bm1396_native_mode {
        RuntimeDispatchKind::Bm1396Native
    } else if bm1391_native_mode {
        RuntimeDispatchKind::Bm1391Native
    } else if c43_native_mode {
        RuntimeDispatchKind::C43Native
    } else {
        selected_runtime_dispatch(
            am3_bb_mode,
            stratum_proxy_mode,
            tap_mode,
            s19j_hybrid_mode,
            s17_hybrid_mode,
            serial_mining_mode,
            stock_fpga_mode,
        )
    };
    let runtime_board_desc = platform_identity.board_desc;
    let runtime_board_target = platform_identity.board_target().to_string();
    let image_authority = if s19k_install_custody_safeoff {
        // This exact, cut-only route cannot run a mining loop. Keep emergency
        // hash-off available even when an image cannot obtain mining admission.
        if runtime_board_target != "am3-s19k" || runtime_dispatch != RuntimeDispatchKind::Serial {
            anyhow::bail!("install custody SafeOff requires the exact S19k serial route");
        }
        Ok(Some(runtime_image_admission::RuntimeImageAuthority::SafeOffOnly {
            board_target: "am3-s19k",
        }))
    } else if runtime_dispatch.owns_chain_or_work() {
        match runtime_board_desc {
            Some(board) => runtime_image_admission::load(
                board,
                args.iter().any(|arg| arg == "--lab-runtime"),
            ).await.map(Some),
            None => Err("mining requires an exact registered image target".into()),
        }
    } else {
        Ok(None)
    };
    let (
        runtime_dispatch_admission,
        mut s19j_hybrid_route_admission,
        mut s17_hybrid_route_admission,
        mut am2_bm1362_serial_route_admission,
    ) = match image_authority.and_then(|image| configured_asic_protocol_identity(&config).and_then(|configured_asic_protocol| {
        let runtime_admission = admit_board_desc_runtime_dispatch(
            runtime_board_desc,
            runtime_dispatch,
            config.mining_start_enabled() || s19k_install_custody_safeoff,
            configured_asic_protocol,
        )?;
        let recipe_profile = image.as_ref().map(|proof| proof.hardware_recipe());
        let runtime_admission = RuntimeDispatchAdmission::bind(runtime_admission, image, s19k_install_custody_safeoff)?;
        let hybrid_route_admission = if runtime_dispatch == RuntimeDispatchKind::S19jHybrid
            && config.mining_start_enabled()
        {
            Some(s19j_hybrid_admission::admit_s19j_hybrid_route(
                &platform_identity,
                runtime_dispatch,
                configured_asic_protocol,
            )?)
        } else {
            None
        };
        let s17_hybrid_route_admission = if runtime_dispatch == RuntimeDispatchKind::S17Hybrid
            && config.mining_start_enabled()
        {
            Some(s17_hybrid_admission::admit_s17_hybrid_route(
                &platform_identity,
                runtime_dispatch,
                configured_asic_protocol,
            )?)
        } else {
            None
        };
        let am2_bm1362_serial_route_admission = if runtime_dispatch == RuntimeDispatchKind::Serial
            && config.mining_start_enabled()
            && configured_asic_protocol == Some(dcentrald_common::AsicProtocolIdentity::Bm1362)
            && !matches!(
                platform_identity.board_target(),
                "am3-s19jproa" | "am3-s19jproplus" | "am3-s19jpro-aml"
            ) {
            Some(am2_bm1362_serial_admission::admit_am2_bm1362_serial_route(
                &platform_identity,
                runtime_dispatch,
                configured_asic_protocol,
            )?)
        } else {
            None
        };
        if let Some(profile) = recipe_profile {
            let board = runtime_board_desc.ok_or("hardware recipe requires an exact BoardDesc")?;
            let recipe = dcentrald_common::runtime_hardware_recipe::RuntimeHardwareRecipe::resolve(
                board, &platform_identity.observed_control_board, runtime_dispatch.label(), profile)?;
            dcentrald_common::runtime_hardware_recipe::install(recipe).map_err(str::to_string)?;
        }
        Ok((
            runtime_admission,
            hybrid_route_admission,
            s17_hybrid_route_admission,
            am2_bm1362_serial_route_admission,
        ))
    })) {
        Ok((
            admission,
            hybrid_route_admission,
            s17_hybrid_route_admission,
            am2_bm1362_serial_route_admission,
        )) => {
            info!(
                board_target = %runtime_board_target.trim(),
                board_desc_registered = runtime_board_desc.is_some(),
                dispatch = runtime_dispatch.label(),
                admission = ?admission,
                hybrid_route_admitted = hybrid_route_admission.is_some(),
                s17_hybrid_route_admitted = s17_hybrid_route_admission.is_some(),
                am2_bm1362_serial_route_admitted = am2_bm1362_serial_route_admission.is_some(),
                "BoardDesc runtime transport/work/ASIC-protocol admission evaluated"
            );
            (
                admission,
                hybrid_route_admission,
                s17_hybrid_route_admission,
                am2_bm1362_serial_route_admission,
            )
        }
        Err(reason) => {
            tracing::warn!(
                board_target = %runtime_board_target.trim(),
                dispatch = runtime_dispatch.label(),
                reason = %reason,
                "BoardDesc runtime dispatch contradiction; parking management-only before mining hardware construction"
            );
            let (_runtime_health_tx, runtime_health_rx) =
                tokio::sync::watch::channel(dcentrald_api::RuntimeHealthSnapshot::for_mode(
                    dcentrald_api::RuntimeHealthMode::Native,
                ));
            let _api_handles =
                crate::runtime::api::spawn_proxy_mode_api_with_hardware_mutation_gate(
                    config.clone(),
                    dcentrald_api::RuntimeHealthMode::Native,
                    Some(runtime_health_rx),
                    dcentrald_hal::platform::HardwareMutationGate::new_closed(),
                    shutdown_token.clone(),
                )
                .await?;
            return enter_management_only_idle(
                "board-desc-dispatch",
                config.mining.enabled,
                config.has_configured_pool(),
                shutdown_token.clone(),
            )
            .await;
        }
    };

    // SINGLE-CHOKEPOINT mutation-disposition gate (2026-08-16): adjudicate the
    // durable journal HERE, before the runtime-arm dispatch branch below, so
    // every current and future arm — am3-bb, stratum-proxy, tap, s19j-hybrid,
    // serial, stock-fpga, and the standard Daemon path — is structurally
    // covered before any of them can construct hardware or assert
    // PWR_CONTROL. Fail-closed: Unresolved/Unreadable refuses startup. A
    // clean/absent journal admits with zero side effects (byte-identical
    // clean session). The Daemon::init gate remains as defense-in-depth for
    // the standard path.
    adjudicate_mutation_disposition_before_runtime_arm_dispatch()?;

    if am3_bb_mode {
        // Phase C: AM335x BeagleBone S19j Pro (S19J_IO_BOARD_V2_0) mining.
        // Start the dashboard / CGMiner API tasks first, then run the cold-boot
        // + transport-setup + (Phase-C stub) mining loop. Listener health is
        // observed separately. See am3_bb_mining.rs.
        info!(
            am3_bb_cli = am3_bb_cli,
            am3_bb_auto = am3_bb_auto,
            "Entering AM335x BB mining mode (--am3-bb-mining)"
        );
        let (_runtime_health_tx, runtime_health_rx) =
            tokio::sync::watch::channel(dcentrald_api::RuntimeHealthSnapshot::for_mode(
                dcentrald_api::RuntimeHealthMode::Native,
            ));
        let mut initial_miner_state =
            dcentrald_api::MinerState::empty(dcentrald_api::OperatingMode::Standard);
        initial_miner_state.pool.url = config.pool.url.clone();
        initial_miner_state.pool.worker = config.pool.worker.clone();
        initial_miner_state.pool.protocol = config
            .pool
            .protocol
            .clone()
            .unwrap_or_else(|| "sv1".to_string());
        let (miner_state_tx, miner_state_rx) = tokio::sync::watch::channel(initial_miner_state);

        // F5: same fresh-unit gate as the s19j-hybrid arm. An unconfigured
        // am3-bb unit comes up management-only (API/dashboard/wizard
        // reachable, no cold-boot, no PSU/chain I/O) until the operator
        // configures a pool and enables mining.
        if !config.mining_start_enabled() {
            let _api_handles =
                crate::runtime::api::spawn_observer_only_api_with_state_and_hardware_mutation_gate(
                    config.clone(),
                    dcentrald_api::RuntimeHealthMode::Native,
                    Some(runtime_health_rx.clone()),
                    Some(miner_state_rx.clone()),
                    dcentrald_hal::platform::HardwareMutationGate::new_closed(),
                    shutdown_token.clone(),
                )
                .await?;
            return enter_management_only_idle(
                "am3-bb",
                config.mining.enabled,
                config.has_configured_pool(),
                shutdown_token.clone(),
            )
            .await;
        }

        // The watchdog must report its initial kick before the API can admit a
        // hardware mutation and before the blocking engine can touch GPIO,
        // I2C, UART, power, or cooling state.
        let safety_admission = match am3_bb_mining::Am3BbSafetyAdmission::start(
            &config,
            &platform_identity,
            runtime_dispatch_admission,
        )
        .await
        {
            Ok(admission) => admission,
            Err(error) => {
                let (disposition, error, closeout) = error.into_parts();
                anyhow::ensure!(
                    closeout.is_none(),
                    "am3-bb watchdog admission returned contradictory never-energized closeout evidence"
                );
                if disposition != am3_bb_mining::Am3BbFailureDisposition::NoWatchdogOpened {
                    error!(
                        %error,
                        "am3-bb watchdog admission is reset-pending; refusing stable management-only operation"
                    );
                    return Err(error.context(
                        "am3-bb watchdog admission faulted/reset_pending before API startup",
                    ));
                }
                let _api_handles =
                    crate::runtime::api::spawn_observer_only_api_with_state_and_hardware_mutation_gate(
                        config.clone(),
                        dcentrald_api::RuntimeHealthMode::Native,
                        Some(runtime_health_rx.clone()),
                        Some(miner_state_rx.clone()),
                        dcentrald_hal::platform::HardwareMutationGate::new_closed(),
                        shutdown_token.clone(),
                    )
                    .await?;
                return enter_management_only(
                    "am3-bb-watchdog-admission",
                    error,
                    shutdown_token.clone(),
                    None,
                )
                .await;
            }
        };
        let api_mutation_gate = safety_admission.hardware_mutation_gate();
        let api_identity = safety_admission.api_identity();
        let _api_handles =
            match crate::runtime::api::spawn_proxy_mode_api_with_state_gate_and_identity(
                config.clone(),
                dcentrald_api::RuntimeHealthMode::Native,
                Some(runtime_health_rx),
                Some(miner_state_rx),
                api_mutation_gate.clone(),
                api_identity,
                shutdown_token.clone(),
            )
            .await
            {
                Ok(handles) => handles,
                Err(error) => {
                    let _ = api_mutation_gate.close_and_drain(std::time::Duration::ZERO);
                    safety_admission.disarm_never_energized().await.context(
                        "am3-bb: API startup failure could not close the never-energized watchdog run",
                    )?;
                    return Err(error.context(
                        "am3-bb: API failed after watchdog admission; mutation gate and never-energized watchdog were closed",
                    ));
                }
            };

        let mining_shutdown = shutdown_token.child_token();
        let am3_bb_run_result = am3_bb_mining::run_am3_bb_mining(
            config,
            mining_shutdown.clone(),
            safety_admission,
            miner_state_tx,
        )
        .await;
        // CONTROLLED-teardown journaling (2026-08-16): the am3-bb engine has
        // finished its own typed closeout (never from a panic/unwind path —
        // panic=abort routes through the panic hook, not here). Durably
        // journal any Mutated/Quarantined fabric disposition the run left
        // behind so the NEXT boot's chokepoint gate refuses admission. A
        // clean roster journals nothing (byte-identical clean session).
        crate::daemon::persist_unresolved_mutation_dispositions(
            &crate::daemon::terminal_mutation_disposition_path(),
        );
        match am3_bb_run_result {
            Ok(()) => {
                info!("dcentrald (am3-bb) stopped cleanly");
                Ok(())
            }
            // Stable management-only entry is authorized only by consuming the
            // closeout evidence matching this exact AM3-BB disposition. A
            // reset-pending fault retains no such evidence and must exit.
            Err(lifecycle_error) => {
                mining_shutdown.cancel();
                let (disposition, error, closeout) = lifecycle_error.into_parts();
                match disposition {
                    am3_bb_mining::Am3BbFailureDisposition::NoWatchdogOpened => {
                        anyhow::ensure!(
                            closeout.is_none(),
                            "am3-bb no-watchdog failure carried contradictory closeout evidence"
                        );
                        enter_management_only(
                            "am3-bb-never-energized",
                            error,
                            shutdown_token.clone(),
                            None,
                        )
                        .await
                    }
                    am3_bb_mining::Am3BbFailureDisposition::NeverEnergizedClosed => {
                        let _closeout = match closeout {
                            Some(am3_bb_mining::Am3BbFailureCloseout::NeverEnergized(
                                closeout,
                            )) => closeout,
                            Some(am3_bb_mining::Am3BbFailureCloseout::TerminalSafeOff(_)) => {
                                anyhow::bail!(
                                    "am3-bb never-energized disposition carried terminal-safe-off closeout evidence"
                                )
                            }
                            None => anyhow::bail!(
                                "am3-bb never-energized disposition lacked its positive API/watchdog closeout receipts"
                            ),
                        };
                        enter_management_only(
                            "am3-bb-never-energized",
                            error,
                            shutdown_token.clone(),
                            None,
                        )
                        .await
                    }
                    am3_bb_mining::Am3BbFailureDisposition::TerminalSafeOffClosed => {
                        let _closeout = match closeout {
                            Some(am3_bb_mining::Am3BbFailureCloseout::TerminalSafeOff(
                                closeout,
                            )) => closeout,
                            Some(am3_bb_mining::Am3BbFailureCloseout::NeverEnergized(_)) => {
                                anyhow::bail!(
                                    "am3-bb terminal-safe-off disposition carried never-energized closeout evidence"
                                )
                            }
                            None => anyhow::bail!(
                                "am3-bb terminal-safe-off disposition lacked its positive watchdog closeout receipt"
                            ),
                        };
                        enter_management_only("am3-bb", error, shutdown_token.clone(), None).await
                    }
                    am3_bb_mining::Am3BbFailureDisposition::ResetPending => {
                        anyhow::ensure!(
                            closeout.is_none(),
                            "am3-bb reset-pending failure carried contradictory closeout evidence"
                        );
                        error!(
                            %error,
                            "am3-bb faulted after route admission; watchdog reset is pending"
                        );
                        Err(error.context(
                            "am3-bb faulted/reset_pending; refusing to claim stable management-only operation",
                        ))
                    }
                }
            }
        }
    } else if stratum_proxy_mode {
        // Phase 11B MVP: pure Stratum V1 TCP relay. bosminer owns ALL
        // hardware; dcentrald never touches /dev/mem, /dev/i2c*, /dev/ttyS*,
        // or the bosminer API for control. See stratum_proxy.rs for the
        // invariant list.
        //
        // Proxy mode v0 (task #29 / #72): bring the dashboard + CGMiner API
        // up too so operators on `a lab unit` can observe the unit even though
        // bosminer drives the chain. Build a minimal AppState, spawn the API
        // server BEFORE the relay, and start the bosminer health poller.
        info!(
            "Entering STRATUM V1 relay mode (--stratum-proxy) — no hardware access for chain control"
        );
        let stats = stratum_proxy::ProxiedStats::new();
        let (runtime_health_tx, runtime_health_rx) = tokio::sync::watch::channel(
            dcentrald_api::RuntimeHealthSnapshot::for_mode(dcentrald_api::RuntimeHealthMode::Proxy),
        );
        let _api_handles = crate::runtime::api::spawn_proxy_mode_api(
            config.clone(),
            dcentrald_api::RuntimeHealthMode::Proxy,
            Some(runtime_health_rx),
            shutdown_token.clone(),
        )
        .await?;
        let mining_shutdown = shutdown_token.child_token();
        let _health_handle =
            stratum_proxy::spawn_bosminer_health_task(stats.clone(), mining_shutdown.clone());
        let _health_publish_handle = stratum_proxy::spawn_proxy_health_publisher(
            stats.clone(),
            runtime_health_tx,
            mining_shutdown.clone(),
        );
        match stratum_proxy::run(config, mining_shutdown.clone(), Some(stats)).await {
            Ok(()) => {
                info!("dcentrald (stratum proxy) stopped cleanly");
                Ok(())
            }
            // F1: management-only instead of process exit. Stratum-proxy
            // mode never owns chain hardware (bosminer does), so there is no
            // voltage/chain teardown to perform — the relay simply failed;
            // keep the API/dashboard reachable.
            Err(e) => {
                mining_shutdown.cancel();
                enter_management_only("stratum-proxy", e, shutdown_token.clone(), None).await
            }
        }
    } else if tap_mode {
        // Tap mode: bosminer owns PIC/PSU/serial/CTRL. dcentrald only dispatches
        // FPGA work. See DCENT_OS_Antminer/dcentrald/dcentrald/src/s19j_tap_mining.rs
        // for preconditions and the no-write invariant list.
        info!("Entering S19J TAP mining mode (--tap-mode) — bosminer owns hardware state");
        // F5 parity: tap mode still owns FPGA WORK_TX dispatch, so a fresh or
        // intentionally management-only unit must not construct/run the tap
        // miner unless mining is explicitly enabled with a configured pool.
        // Keep the API/dashboard reachable for onboarding, then park without
        // opening the FPGA chain or sending work.
        if !config.mining_start_enabled() {
            let (_runtime_health_tx, runtime_health_rx) =
                tokio::sync::watch::channel(dcentrald_api::RuntimeHealthSnapshot::for_mode(
                    dcentrald_api::RuntimeHealthMode::Native,
                ));
            let _api_handles = crate::runtime::api::spawn_proxy_mode_api(
                config.clone(),
                dcentrald_api::RuntimeHealthMode::Native,
                Some(runtime_health_rx),
                shutdown_token.clone(),
            )
            .await?;
            return enter_management_only_idle(
                "tap",
                config.mining.enabled,
                config.has_configured_pool(),
                shutdown_token.clone(),
            )
            .await;
        }

        let mining_shutdown = shutdown_token.child_token();
        let mut miner = match S19jTapMiner::new(config, mining_shutdown.clone()) {
            Ok(m) => m,
            Err(e) => {
                error!(error = %e, "Failed to construct S19jTapMiner");
                return Err(e);
            }
        };

        match miner.run().await {
            Ok(()) => {
                info!("dcentrald (tap) stopped cleanly — hardware untouched, bosminer resumes");
                Ok(())
            }
            // F1: management-only instead of process exit. Tap mode never
            // writes chain/PIC/PSU state (bosminer owns it), so there is no
            // hardware teardown to perform — keep the API/dashboard up.
            Err(e) => {
                mining_shutdown.cancel();
                enter_management_only("tap", e, shutdown_token.clone(), None).await
            }
        }
    } else if s19j_hybrid_mode {
        // S19j Pro hybrid mining: serial ASIC init + FPGA work dispatch via /dev/mem
        //
        // Proxy mode v0 (task #29 / #72): hybrid mode previously skipped
        // `daemon::run()` and therefore never spawned the dashboard / CGMiner
        // API. Bring up a minimal AppState before the mining loop so :8080
        // and :4028 are reachable even when the daemon path isn't entered.
        info!("Entering S19J HYBRID mining mode (--s19j-hybrid)");
        let (_runtime_health_tx, runtime_health_rx) =
            tokio::sync::watch::channel(dcentrald_api::RuntimeHealthSnapshot::for_mode(
                dcentrald_api::RuntimeHealthMode::Hybrid,
            ));
        // AT-DASH (2026-06-14): live MinerState channel for the standalone
        // hybrid path. The API serves the RECEIVER; the mining loop owns the
        // SENDER (attached via `with_state_tx` below) and pushes a fresh
        // MinerState on each am2_serial_status tick so /api/status + the
        // dashboard show real hashrate / per-dsPIC chains / accepted shares
        // instead of a blank default. Additive + fail-closed: if mining never
        // starts (idle branch) the sender is just dropped and the dashboard
        // shows zeros, exactly as before.
        let (miner_state_tx, miner_state_rx) = tokio::sync::watch::channel(
            dcentrald_api::MinerState::empty(dcentrald_api::OperatingMode::Standard),
        );
        // F5: a fresh, unconfigured am2 unit must NOT attempt a hardware
        // cold-boot / PIC preflight. Spawn the API with a permanently closed
        // mutation gate; if no pool is configured / mining is not enabled, park in
        // management-only mode so the onboarding wizard (complete OR W1-A
        // skip) is reachable. This is the production-correct first-boot
        // behavior and kills the `a lab unit`-class crash at the source — the
        // wrong-config-for-this-unit PIC preflight is never attempted.
        if !config.mining_start_enabled() {
            let _api_handles =
                crate::runtime::api::spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
                    config.clone(),
                    dcentrald_api::RuntimeHealthMode::Hybrid,
                    Some(runtime_health_rx),
                    Some(miner_state_rx),
                    dcentrald_hal::platform::HardwareMutationGate::new_closed(),
                    shutdown_token.clone(),
                )
                .await?;
            return enter_management_only_idle(
                "s19j-hybrid",
                config.mining.enabled,
                config.has_configured_pool(),
                shutdown_token.clone(),
            )
            .await;
        }

        let mining_shutdown = shutdown_token.child_token();
        // AT-DASH: attach the live MinerState publisher so the hybrid mining
        // loop feeds /api/status + the dashboard.
        let route_admission = s19j_hybrid_route_admission.take().ok_or_else(|| {
            anyhow::anyhow!(
                "s19j-hybrid reached hardware construction without one-shot route admission"
            )
        })?;
        let safety_admission = match s19j_hybrid_mining::S19jHybridSafetyAdmission::start(
            &config,
            runtime_dispatch_admission,
            route_admission,
        )
        .await
        {
            Ok(admission) => admission,
            Err(error) => {
                if crate::runtime::safety_watchdog::is_watchdog_reset_pending(&error) {
                    error!(
                        %error,
                        "s19j-hybrid watchdog admission is reset-pending; refusing stable management-only operation"
                    );
                    return Err(error.context(
                        "s19j-hybrid watchdog admission faulted/reset_pending before API startup",
                    ));
                }
                let _api_handles = crate::runtime::api::spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
                        config.clone(),
                        dcentrald_api::RuntimeHealthMode::Hybrid,
                        Some(runtime_health_rx),
                        Some(miner_state_rx),
                        dcentrald_hal::platform::HardwareMutationGate::new_closed(),
                        shutdown_token.clone(),
                    )
                    .await?;
                return enter_management_only(
                    "s19j-hybrid-watchdog-admission",
                    error,
                    shutdown_token.clone(),
                    None,
                )
                .await;
            }
        };
        let api_mutation_gate = safety_admission.hardware_mutation_gate();
        let _api_handles =
            crate::runtime::api::spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
                config.clone(),
                dcentrald_api::RuntimeHealthMode::Hybrid,
                Some(runtime_health_rx),
                Some(miner_state_rx),
                api_mutation_gate,
                shutdown_token.clone(),
            )
            .await?;
        let mut miner = S19jHybridMiner::new(config, mining_shutdown.clone(), safety_admission)?
            .with_state_tx(miner_state_tx);

        let hybrid_run_result = miner.run().await;
        // CONTROLLED-teardown journaling (2026-08-16): the hybrid engine has
        // completed its own typed closeout/safe-off arms (never a
        // panic/unwind path — panic=abort routes through the panic hook, not
        // here). Durably journal any Mutated/Quarantined fabric disposition
        // (this arm registers the EEPROM 0x50-0x57 denylist fabric) so the
        // NEXT boot's chokepoint gate refuses admission. A clean roster
        // journals nothing (byte-identical clean session).
        crate::daemon::persist_unresolved_mutation_dispositions(
            &crate::daemon::terminal_mutation_disposition_path(),
        );
        match hybrid_run_result {
            Ok(()) => {
                info!("dcentrald (s19j hybrid) stopped cleanly");
                Ok(())
            }
            // F1: do not exit after a matching software-closeout disposition.
            // Keeping the process and already-spawned management tasks alive
            // preserves their opportunity to serve; listener/network health
            // remains separately observed. Physical rail state is unmeasured.
            Err(e) => {
                mining_shutdown.cancel();
                if !s19j_hybrid_mining::is_terminal_safe_off_error(&e) {
                    error!(
                        %e,
                        "s19j-hybrid run ended without positive terminal safe-off/watchdog closeout; refusing stable management-only operation"
                    );
                    return Err(
                        e.context("s19j-hybrid terminal disposition is reset-pending or unproven")
                    );
                }
                enter_management_only("s19j-hybrid", e, shutdown_token.clone(), None).await
            }
        }
    } else if s17_hybrid_mode {
        // S17-family (BM1397) hybrid mining: 2026-08-27 promotion
        // (`2026-08-27-antminer17-unlock-armada`, agent B1). Mirrors the S19j
        // hybrid launcher shape: minimal AppState so :8080/:4028 stay reachable,
        // management-only park when mining cannot start, and the pre-bench
        // energize gate adjudicated BEFORE the watchdog is armed so a refusal
        // parks safely instead of arming-and-reboot-looping.
        info!("Entering S17 HYBRID mining mode (--s17-hybrid)");
        let (_runtime_health_tx, runtime_health_rx) =
            tokio::sync::watch::channel(dcentrald_api::RuntimeHealthSnapshot::for_mode(
                dcentrald_api::RuntimeHealthMode::Hybrid,
            ));
        let (miner_state_tx, miner_state_rx) = tokio::sync::watch::channel(
            dcentrald_api::MinerState::empty(dcentrald_api::OperatingMode::Standard),
        );
        if !config.mining_start_enabled() {
            let _api_handles =
                crate::runtime::api::spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
                    config.clone(),
                    dcentrald_api::RuntimeHealthMode::Hybrid,
                    Some(runtime_health_rx),
                    Some(miner_state_rx),
                    dcentrald_hal::platform::HardwareMutationGate::new_closed(),
                    shutdown_token.clone(),
                )
                .await?;
            return enter_management_only_idle(
                "s17-hybrid",
                config.mining.enabled,
                config.has_configured_pool(),
                shutdown_token.clone(),
            )
            .await;
        }

        // A configured mining start with one-shot exact route admission also
        // admits the native recipe. Fresh factory/fabric identity and cooling
        // checks run before power; no additional diagnostic env flag is needed.
        // Unsafe recipe combinations are still rejected before watchdog arming.
        let s17_energize_opt_in = s17_hybrid_route_admission.is_some();
        if let Err(recipe_error) =
            s17_hybrid_mining::adjudicate_s17_energize_gate(s17_energize_opt_in)
        {
            warn!(
                %recipe_error,
                "s17-hybrid recipe refused; parking management-only"
            );
            let _api_handles =
                crate::runtime::api::spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
                    config.clone(),
                    dcentrald_api::RuntimeHealthMode::Hybrid,
                    Some(runtime_health_rx),
                    Some(miner_state_rx),
                    dcentrald_hal::platform::HardwareMutationGate::new_closed(),
                    shutdown_token.clone(),
                )
                .await?;
            return enter_management_only(
                "s17-hybrid-energize-gate",
                recipe_error,
                shutdown_token.clone(),
                None,
            )
            .await;
        }

        let mining_shutdown = shutdown_token.child_token();
        let route_admission = s17_hybrid_route_admission.take().ok_or_else(|| {
            anyhow::anyhow!(
                "s17-hybrid reached hardware construction without one-shot route admission"
            )
        })?;
        let safety_admission = match s17_hybrid_mining::S17HybridSafetyAdmission::start(
            &config,
            runtime_dispatch_admission,
            route_admission,
        )
        .await
        {
            Ok(admission) => admission,
            Err(error) => {
                if crate::runtime::safety_watchdog::is_watchdog_reset_pending(&error) {
                    error!(
                        %error,
                        "s17-hybrid watchdog admission is reset-pending; refusing stable management-only operation"
                    );
                    return Err(error.context(
                        "s17-hybrid watchdog admission faulted/reset_pending before API startup",
                    ));
                }
                let _api_handles =
                    crate::runtime::api::spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
                        config.clone(),
                        dcentrald_api::RuntimeHealthMode::Hybrid,
                        Some(runtime_health_rx),
                        Some(miner_state_rx),
                        dcentrald_hal::platform::HardwareMutationGate::new_closed(),
                        shutdown_token.clone(),
                    )
                    .await?;
                return enter_management_only(
                    "s17-hybrid-watchdog-admission",
                    error,
                    shutdown_token.clone(),
                    None,
                )
                .await;
            }
        };
        let api_mutation_gate = safety_admission.hardware_mutation_gate();
        let _api_handles =
            crate::runtime::api::spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
                config.clone(),
                dcentrald_api::RuntimeHealthMode::Hybrid,
                Some(runtime_health_rx),
                Some(miner_state_rx),
                api_mutation_gate,
                shutdown_token.clone(),
            )
            .await?;
        let mut miner = S17HybridMiner::new(config, mining_shutdown.clone(), safety_admission)?
            .with_state_tx(miner_state_tx)
            .with_energize_opt_in(s17_energize_opt_in);

        let hybrid_run_result = miner.run().await;
        crate::daemon::persist_unresolved_mutation_dispositions(
            &crate::daemon::terminal_mutation_disposition_path(),
        );
        match hybrid_run_result {
            Ok(()) => {
                info!("dcentrald (s17 hybrid) stopped cleanly");
                Ok(())
            }
            // Only the S17 owner's matching checked hardware/fabric/watchdog
            // closeout permits continued management after a mining failure.
            Err(e) => {
                mining_shutdown.cancel();
                if !s17_hybrid_mining::is_terminal_safe_off_error(&e) {
                    error!(%e, "s17-hybrid run ended without checked terminal safe-off/watchdog closeout");
                    return Err(
                        e.context("s17-hybrid terminal disposition is reset-pending or unproven")
                    );
                }
                enter_management_only("s17-hybrid", e, shutdown_token.clone(), None).await
            }
        }
    } else if bm1396_native_mode {
        if !config.mining_start_enabled() {
            let _api = crate::runtime::api::spawn_initial_idle_api(
                config.clone(), platform_identity.board_target(), shutdown_token.clone(),
            ).await?;
            return enter_management_only_idle(
                "bm1396-native", config.mining.enabled, config.has_configured_pool(),
                shutdown_token.clone(),
            ).await;
        }
        let protocol = runtime_dispatch_admission.require_asic_protocol(
            RuntimeDispatchKind::Bm1396Native, platform_identity.board_target(),
            dcentrald_common::AsicProtocolIdentity::Bm1396,
        ).map_err(anyhow::Error::msg)?;
        let admission = bm1396_admission::admit(&platform_identity, &config, protocol)
            .map_err(anyhow::Error::msg)?;
        let result = bm1396_mining_work::runtime::run(
            config.clone(), shutdown_token.child_token(), None, admission,
        ).await;
        crate::daemon::persist_unresolved_mutation_dispositions(
            &crate::daemon::terminal_mutation_disposition_path(),
        );
        // The runtime owns all terminal and watchdog disposition checks.
        // Without a typed safe-off error, a failed run must end this process.
        result.context("BM1396 native runtime ended; retain its exact terminal disposition")
    } else if bm1391_native_mode {
        if !config.mining_start_enabled() {
            let _api = crate::runtime::api::spawn_initial_idle_api(
                config.clone(),
                platform_identity.board_target(),
                shutdown_token.clone(),
            )
            .await?;
            return enter_management_only_idle(
                "bm1391-native",
                config.mining.enabled,
                config.has_configured_pool(),
                shutdown_token.clone(),
            )
            .await;
        }
        let _protocol = runtime_dispatch_admission
            .require_asic_protocol(
                RuntimeDispatchKind::Bm1391Native,
                platform_identity.board_target(),
                dcentrald_common::AsicProtocolIdentity::Bm1391,
            )
            .map_err(anyhow::Error::msg)?;
        let admission =
            bm1391_admission::admit(&platform_identity, &config).map_err(anyhow::Error::msg)?;
        let result = bm1391_mining::run(
            config.clone(),
            shutdown_token.child_token(),
            None,
            admission,
        )
        .await;
        crate::daemon::persist_unresolved_mutation_dispositions(
            &crate::daemon::terminal_mutation_disposition_path(),
        );
        match result {
            Ok(()) => Ok(()),
            Err(error) if bm1391_mining::is_terminal_safe_off(&error) => {
                let _api = crate::runtime::api::spawn_initial_idle_api(
                    config,
                    platform_identity.board_target(),
                    shutdown_token.clone(),
                )
                .await?;
                enter_management_only("bm1391-native", error, shutdown_token.clone(), None).await
            }
            Err(error) => {
                Err(error.context("BM1391 terminal disposition is reset-pending or unproven"))
            }
        }
    } else if c43_native_mode {
        if !config.mining_start_enabled() {
            let _api = crate::runtime::api::spawn_initial_idle_api(
                config.clone(),
                platform_identity.board_target(),
                shutdown_token.clone(),
            )
            .await?;
            return enter_management_only_idle(
                "c43-bm1393-native",
                config.mining.enabled,
                config.has_configured_pool(),
                shutdown_token.clone(),
            )
            .await;
        }
        let admission = runtime_dispatch_admission
            .require_c43()
            .map_err(anyhow::Error::msg)?;
        let (state_tx, _) = tokio::sync::watch::channel(dcentrald_api::MinerState::empty(
            dcentrald_api::OperatingMode::Standard,
        ));
        let result = c43_bm1393_mining::run(
            config.clone(),
            shutdown_token.child_token(),
            Some(state_tx),
            admission,
        )
        .await;
        crate::daemon::persist_unresolved_mutation_dispositions(
            &crate::daemon::terminal_mutation_disposition_path(),
        );
        match result {
            Ok(()) => Ok(()),
            Err(error) if c43_bm1393_mining::is_terminal_safe_off(&error) => {
                let _api = crate::runtime::api::spawn_initial_idle_api(
                    config,
                    platform_identity.board_target(),
                    shutdown_token.clone(),
                )
                .await?;
                enter_management_only("c43-bm1393-native", error, shutdown_token.clone(), None)
                    .await
            }
            Err(error) => {
                Err(error.context("C43 terminal disposition is reset-pending or unproven"))
            }
        }
    } else if serial_mining_mode {
        // Serial UART mining path — direct ASIC communication via /dev/ttyS*
        // Used for S19j Pro (BM1362) and other UART-based platforms
        if !config.mining_start_enabled() && !s19k_install_custody_safeoff && !bm1366_native_no_work {
            anyhow::ensure!(
                s19k_track1_j3_lease.is_none(),
                "S19k Track-1 J3 lease refuses an idle/API-only lifetime; exiting returns the uncommitted ptrace lease to stock"
            );
            info!(
                mining_enabled = config.mining.enabled,
                pool_configured = config.has_configured_pool(),
                "Serial mining startup gated by config; starting API/dashboard only and skipping hardware init"
            );
            let (_runtime_health_tx, runtime_health_rx) =
                tokio::sync::watch::channel(dcentrald_api::RuntimeHealthSnapshot::for_mode(
                    dcentrald_api::RuntimeHealthMode::Native,
                ));
            let _api_handles = crate::runtime::api::spawn_proxy_mode_api(
                config.clone(),
                dcentrald_api::RuntimeHealthMode::Native,
                Some(runtime_health_rx),
                shutdown_token.clone(),
            )
            .await?;
            shutdown_token.cancelled().await;
            info!("dcentrald (serial idle/API-only) stopped cleanly");
            return Ok(());
        }

        info!("Entering SERIAL mining mode (--serial-mining)");
        let mining_shutdown = shutdown_token.child_token();
        let s19k_track1_launch = s19k_stock_handoff_identity.is_some();
        let mut miner = match SerialMiner::new(
            config.clone(),
            mining_shutdown.clone(),
            explicit_loud_fan_authority,
            bm1366_native_no_work,
            s19k_install_custody_safeoff,
            s19k_track1_no_work,
            s19k_track1_bounded_work_proof,
            s19k_track1_endurance_work_proof,
            s19k_stock_handoff_identity,
            s19k_track1_receipt_authority,
            s19k_track1_j3_lease.take(),
            runtime_dispatch_admission,
            am2_bm1362_serial_route_admission.take(),
        ) {
            Ok(miner) => miner,
            Err(error) => {
                if bm1366_native_no_work {
                    return Err(error.context("BM1366 native no-work admission refused"));
                }
                if s19k_track1_launch {
                    return Err(error.context(
                        "S19k Track-1 construction refused after J3 acquisition; exiting returns the uncommitted ptrace lease to stock",
                    ));
                }
                let (_runtime_health_tx, runtime_health_rx) =
                    tokio::sync::watch::channel(dcentrald_api::RuntimeHealthSnapshot::for_mode(
                        dcentrald_api::RuntimeHealthMode::Native,
                    ));
                let _api_handles =
                    crate::runtime::api::spawn_proxy_mode_api_with_hardware_mutation_gate(
                        config.clone(),
                        dcentrald_api::RuntimeHealthMode::Native,
                        Some(runtime_health_rx),
                        dcentrald_hal::platform::HardwareMutationGate::new_closed(),
                        shutdown_token.clone(),
                    )
                    .await?;
                return enter_management_only(
                    "serial-admission",
                    error,
                    shutdown_token.clone(),
                    None,
                )
                .await;
            }
        };

        let serial_run_result = miner.run().await;
        // CONTROLLED-teardown journaling (2026-08-16): SerialMiner has
        // completed its own voltage-cut/teardown (never a panic/unwind path —
        // panic=abort routes through the panic hook, not here). Durably
        // journal any Mutated/Quarantined fabric disposition the run left
        // behind so the NEXT boot's chokepoint gate refuses admission. A
        // clean roster journals nothing (byte-identical clean session).
        crate::daemon::persist_unresolved_mutation_dispositions(
            &crate::daemon::terminal_mutation_disposition_path(),
        );
        if bm1366_native_no_work {
            return serial_run_result;
        }
        match serial_run_result {
            Ok(()) => {
                info!("dcentrald (serial) stopped cleanly");
                Ok(())
            }
            // F1: management-only instead of process exit — same lifetime
            // semantics this arm already uses for the config-gated idle
            // branch above (spawn API, then `shutdown_token.cancelled()`).
            // SerialMiner performs its own voltage-cut/teardown on failure.
            Err(e) => {
                mining_shutdown.cancel();
                if crate::runtime::safety_watchdog::is_watchdog_reset_pending(&e) {
                    error!(
                        %e,
                        "serial watchdog admission is reset-pending; refusing stable management-only operation"
                    );
                    return Err(e.context(
                        "serial watchdog admission faulted/reset_pending; watchdog reset is required",
                    ));
                }
                match serial_mining::failure_disposition(&e) {
                    Some(serial_mining::SerialFailureDisposition::NeverEnergizedClosed) => {
                        info!(
                            %e,
                            "serial run failed before the AM2 energizing boundary and closed with positive never-energized/watchdog evidence"
                        );
                    }
                    Some(serial_mining::SerialFailureDisposition::StockOwnerRetainedClosed) => {
                        error!(
                            %e,
                            "S19k Track-1 refused before route/process/GPIO handoff and positively closed its watchdog with the exact stock owner retained; exiting so external custody remains unresolved (no automatic receipt cleanup is authorized)"
                        );
                        return Err(e.context(
                            "S19k stock owner retained after pre-handoff refusal; external runner custody must remain until separately audited cleanup",
                        ));
                    }
                    Some(serial_mining::SerialFailureDisposition::TerminalSafeOffClosed) => {
                        info!(
                            %e,
                            "serial run closed with positive terminal safe-off/watchdog evidence"
                        );
                    }
                    None if s19_bm1398_native_mining::is_terminal_safe_off_error(&e) => {
                        info!(%e, "BM1398 native runtime closed with checked power/fabric/watchdog evidence");
                    }
                    None => {
                        error!(
                            %e,
                            "serial run ended without a positive typed watchdog closeout; refusing stable management-only operation"
                        );
                        return Err(
                            e.context("serial terminal disposition is reset-pending or unproven")
                        );
                    }
                }
                // S19k Track-1 one-shot trial routes (no-work, bounded-work
                // proof, endurance proof) must never park in management-only
                // after a typed failure disposition: the wrapper's closeout
                // chain waits for process exit, and the park deadlocks it
                // (live attempt 9, 2026-08-28: bounded mining-init failure
                // parked 26+ minutes until an ungraceful wrapper kill and the
                // printed restore). The typed disposition above already
                // minted its receipts; exit so the wrapper's normal SIGCHLD
                // closeout proceeds. Every other serial route keeps the
                // management-only behavior byte-for-byte.
                if s19k_install_custody_safeoff
                    || s19k_track1_no_work
                    || s19k_track1_bounded_work_proof
                    || s19k_track1_endurance_work_proof
                {
                    return Err(e.context(
                        "S19k Track-1 one-shot trial ended with a typed disposition; \
                         exiting for wrapper closeout instead of a management-only park",
                    ));
                }
                enter_management_only("serial", e, shutdown_token.clone(), None).await
            }
        }
    } else if stock_fpga_mode {
        // Stock Bitmain FPGA mining path — uses /dev/axi_fpga_dev + /dev/fpga_mem
        // No BraiinsOS boot components or UIO devices required
        info!("Stock FPGA mode requested; live mining remains admission-gated (--stock-fpga)");

        // F5 no-brick posture: this branch remains management-only whether or
        // not mining was requested. Declaration evidence alone must never
        // reach the dormant rail-owning StockMiner implementation.
        // The declaration-only am1-s9/BM1387/StockDma token is implemented,
        // but it is not live carrier authority. HAL intentionally exposes no
        // issuer for StockFpgaCarrierPreflightReceipt until one retained
        // stock-S9 FPGA-IIC fabric lease, a read-only C5 probe, exact
        // conflicting clean-image chain-UIO exclusion, and inherited
        // DMA-layout validation are wired. Thermal
        // supervision is also not owned by this lane. Keep every API mutation
        // closed and do not construct StockMiner.
        warn!(
            "stock FPGA runtime remains NOT-ADMITTED: offline declared-route policy exists, but live retained-lease carrier and thermal receipts cannot be minted"
        );
        let (_runtime_health_tx, runtime_health_rx) =
            tokio::sync::watch::channel(dcentrald_api::RuntimeHealthSnapshot::for_mode(
                dcentrald_api::RuntimeHealthMode::Native,
            ));
        let _api_handles = crate::runtime::api::spawn_proxy_mode_api_with_hardware_mutation_gate(
            config.clone(),
            dcentrald_api::RuntimeHealthMode::Native,
            Some(runtime_health_rx),
            dcentrald_hal::platform::HardwareMutationGate::new_closed(),
            shutdown_token.clone(),
        )
        .await?;
        enter_management_only_idle(
            "stock-fpga-not-admitted",
            config.mining.enabled,
            config.has_configured_pool(),
            shutdown_token.clone(),
        )
        .await
    } else {
        // BraiinsOS FPGA mining path — uses UIO devices + per-chain FIFOs
        // (S9/am1 + am2-s17 Zynq). The typed lifecycle returns an opaque
        // terminal closeout only after its complete one-shot shutdown succeeds.
        // That evidence closes the owned hardware lifecycle, but it does not
        // retire the process-global gRPC/MQTT graph or accepted CGMiner children.
        // Consume the matching closeout and exit explicitly; safe in-process
        // observer rebinding requires a future atomically owned task graph.
        let mut daemon = Daemon::new(
            config,
            resolved_config_path,
            platform_identity,
            shutdown_token.clone(),
        );

        match daemon.run_with_lifecycle_disposition().await {
            Ok(()) => {
                info!("dcentrald stopped cleanly after lifecycle software closeout; physical rail state was not measured");
                Ok(())
            }
            Err(lifecycle_error) => {
                let (disposition, e, closeout) = lifecycle_error.into_parts();
                match disposition {
                    crate::daemon::StandardDaemonFailureDisposition::TerminalSafeOffClosed => {
                        let _closeout = match closeout {
                            Some(crate::daemon::StandardDaemonFailureCloseout::TerminalSafeOff(
                                closeout,
                            )) => closeout,
                            None => anyhow::bail!(
                                "standard daemon terminal-safe-off disposition lacked matching positive closeout evidence"
                            ),
                        };
                        error!(
                            error = %e,
                            "standard daemon closed its hardware lifecycle, but its process-global API/MQTT/gRPC task graph cannot yet be atomically retired and rebound; exiting instead of claiming observer-only availability"
                        );
                        Err(e.context(
                            "standard daemon terminal closeout succeeded, but safe in-process observer rebinding is not implemented",
                        ))
                    }
                    crate::daemon::StandardDaemonFailureDisposition::NeverEnergized => {
                        anyhow::ensure!(
                            closeout.is_none(),
                            "standard daemon never-energized failure carried contradictory terminal closeout evidence"
                        );
                        error!(
                            error = %e,
                            "standard daemon failed without terminal closeout evidence; refusing management-only re-entry"
                        );
                        Err(e.context(
                            "standard daemon failure was never-energized but did not carry terminal closeout authority",
                        ))
                    }
                    crate::daemon::StandardDaemonFailureDisposition::ResetPending => {
                        anyhow::ensure!(
                            closeout.is_none(),
                            "standard daemon reset-pending failure carried contradictory terminal closeout evidence"
                        );
                        error!(
                            error = %e,
                            "standard daemon shutdown is unproven/reset-pending; refusing stable management-only operation"
                        );
                        Err(e.context(
                            "standard daemon faulted/reset_pending; refusing to claim stable management-only operation",
                        ))
                    }
                }
            }
        }
    }
}

// `spawn_proxy_mode_api` moved to `crate::runtime::api::spawn_proxy_mode_api`
// (W2.1, 2026-05-07). The `MiningRuntime::default_api_servers` trait method
// in `runtime::mod` now delegates to the same helper, so adding a new
// mining mode automatically gets the dashboard up and closes the
//  regression class.

/// Park a management-only process until SIGTERM/SIGINT. An optional AM2 fan
/// hold may be supplied only by the post-failure helper after its caller has
/// consumed typed software-closeout evidence. Config-gated and non-owning
/// routes never receive that authority: skipping bring-up does not prove an
/// inherited board is de-energized or cool, so those routes preserve the
/// existing cooling command.
///
/// When a closeout-authorized hold is present, a `tokio::select!` races the
/// five-second refresh against shutdown. This keeps termination responsive and
/// prevents the controller from silently reverting a previously requested idle
/// setpoint. It is command evidence only; physical rail state remains unmeasured.
async fn park_management_only_until_shutdown(
    mode_label: &str,
    shutdown_token: CancellationToken,
    am2_quiet_idle: Option<(u8, u8)>,
) {
    // S9/am1 + am3, or any non-am2 fan variant: no periodic fan refresh needed
    // (am2_quiet_idle is None). Byte-identical to the prior terminal await.
    let Some((fan_idle_pwm, fan_max_pwm)) = am2_quiet_idle else {
        shutdown_token.cancelled().await;
        return;
    };

    // am2/XIL: re-assert the idle fan setpoint every ~5 s until SIGTERM so the
    // board's fan IP cannot drift back to its full-speed default while the
    // daemon idles. Exact S19-family targets may also reassert C52; S17 and
    // ambiguous identities preserve the current board mode.
    const FAN_REFRESH: std::time::Duration = std::time::Duration::from_secs(5);
    let mut refresh = tokio::time::interval(FAN_REFRESH);
    // The first tick fires immediately; skip-then-wait so we don't double the
    // entry park the caller just performed.
    refresh.tick().await;
    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => break,
            _ = refresh.tick() => {
                tracing::debug!(
                    mode = mode_label,
                    fan_idle_pwm,
                    fan_max_pwm,
                    "AM2 management-only fan-hold refresh: re-asserting idle PWM \
                     (prevents board fan-controller revert to full speed)"
                );
                crate::s19j_hybrid_mining::force_am2_fans_to_quiet_idle(
                    fan_idle_pwm,
                    fan_max_pwm,
                    "management-only periodic fan-hold refresh (am2, software closeout)",
                );
            }
        }
    }
}

async fn enter_management_only_idle(
    mode_label: &str,
    mining_enabled: bool,
    pool_configured: bool,
    shutdown_token: CancellationToken,
) -> Result<()> {
    info!(
        mode = mode_label,
        mining_enabled,
        pool_configured,
        "mining startup gated by config (no pool configured and/or mining \
         not enabled) — starting API/dashboard/onboarding wizard only and \
         SKIPPING all hardware bring-up (no PIC preflight, no PSU, no chain). \
         This is the production-correct first-boot state for a fresh, \
         unconfigured unit. Mining starts after the operator configures a \
         pool and enables mining (then restarts the daemon)."
    );
    // This gate proves only that this process skipped bring-up. It does not
    // prove inherited rails or temperature, so the type carries no fan-lowering
    // authority and the current cooling command is preserved.
    park_management_only_until_shutdown(mode_label, shutdown_token, None).await;
    info!(
        mode = mode_label,
        "dcentrald ({mode_label} idle/API-only — unconfigured unit) stopped cleanly"
    );
    Ok(())
}

/// F1 (2026-05-17): decouple the management/API plane lifetime from
/// mining-init success.
///
/// ROOT CAUSE this fixes (`a lab unit` first-boot dcentrald-down,
/// ):
/// when `S19jHybridMiner::run()` (or any other mining arm) returns `Err`,
/// returning that `Err` from `run_main()` exits the process — which tears
/// down the in-process `:8080` API task spawned by `spawn_proxy_mode_api`.
/// With the API dead, the dashboard's `:80`→`:8080` proxy has no target,
/// the onboarding wizard (complete OR W1-A skip) is unreachable, and the
/// toolbox detector returns `board_target=unknown` so the unit can't even
/// be re-flashed. `S82dcentrald` must then refuse an unverified replacement.
/// The management plane should not die with mining after route-specific positive
/// terminal closeout authorizes management-only operation.
///
/// This is the EXACT pattern the codebase already endorses for the
/// serial-mining *gated-off* case at `main.rs` (the
/// `if !config.mining_start_enabled()` branch in the `serial_mining_mode`
/// arm): spawn the API, then `shutdown_token.cancelled().await` instead of
/// exiting. F1 generalizes that proven precedent from "mining-init *gated*"
/// to "mining-init *failed*", platform-wide.
///
/// SAFETY: each caller must independently establish that stable management-only
/// parking is allowed: a non-owning route, a never-energized route, or a typed
/// positive terminal closeout. A closeout proves software commands/readbacks,
/// not physical rail state. For the am2 s19j-hybrid PIC-preflight failure that
/// triggered the `a lab unit` incident, the closeout path is
/// `force_am2_home_hard_stop(...)` (PWR_CONTROL low / voltage cut / fan →
/// PWM 30 / resets asserted) + `teardown_am2_power_after_failed_pic_preflight(...)`
/// at `s19j_hybrid_mining.rs:4401-4406`, executed strictly BEFORE the
/// `anyhow::bail!` at :4407. This function does ZERO hardware access — it only
/// parks the process without performing voltage or chain I/O. It preserves the
/// already-spawned management tasks, while listener/network reachability remains
/// separately observed. A route
/// whose terminal closeout is incomplete remains ResetPending and never reaches
/// this function. The `DCENT_AM2_TRUST_RAIL_FALLBACK` default-off gate is
/// untouched.
///
/// R1 (2026-05-17, ):
/// `am2_quiet_idle` is `Some((fan_idle_pwm, fan_max_pwm))` ONLY on the am2
/// platform (gated at the call site). When present, AFTER the mode's typed
/// terminal closeout has completed (the hard-stop commands fans to its
/// `fan_max_pwm`/30 cap and requests voltage cutoff BEFORE the Err that drives
/// us here), we drive the am2 unit's fans DOWN further to the idle PWM via the
/// uio16-mmap `FanController`. This is a low-PWM command after positive software
/// closeout, not acoustic or physical rail proof: PWM is
/// only ever lowered, never raised, never above `PWM_SAFETY_MAX` (30); it
/// does NOT replace or reorder the hard-stop. `None` on S9/am1 + am3 →
/// byte-identical no-op. Best-effort: a FanController open failure is logged,
/// not fatal.
async fn enter_management_only(
    mode_label: &str,
    err: anyhow::Error,
    shutdown_token: CancellationToken,
    am2_quiet_idle: Option<(u8, u8)>,
) -> Result<()> {
    error!(
        mode = mode_label,
        error = %err,
        "mining init failed — entering MANAGEMENT-ONLY mode. \
         The caller established a stable non-owning, never-energized, or \
         software-terminal-closeout disposition; physical rail state was not \
         measured here. The \
         management process/tasks remain alive, while listener and network \
         reachability remain separately observed. This dcentrald route will \
         NOT dispatch or re-attempt mining; external-owner mining state is \
         unmeasured."
    );
    // R1: an am2-only low-idle capability is supplied only by an owning caller
    // after its typed terminal closeout completed PWR_CONTROL/voltage/fan/reset
    // commands and readbacks. Non-owning and never-energized callers pass None.
    // Physical rail state remains unmeasured; the owning route may now drive
    // fans DOWN further to the idle setpoint (separate, lower
    // than the hard-stop cap; only ever driven DOWN, never above
    // PWM_SAFETY_MAX). No-op on S9/am1 + am3.
    if let Some((fan_idle_pwm, fan_max_pwm)) = am2_quiet_idle {
        crate::s19j_hybrid_mining::force_am2_fans_to_quiet_idle(
            fan_idle_pwm,
            fan_max_pwm,
            "management-only after mining-init failure (am2 terminal closeout complete)",
        );
    }
    info!(
        mode = mode_label,
        "dcentrald is alive in management-only mode (this route is not \
         dispatching mining; external-owner state is unmeasured; stable caller \
         disposition retained). Waiting for SIGTERM."
    );
    // Park until SIGTERM/SIGINT (the signal handler task cancels this token).
    // On am2/XIL the idle fan setpoint is RE-ASSERTED every ~5 s so the board's
    // fan IP cannot silently revert the fans to its full-speed default while the
    // daemon idles here (home-safety fix, live-confirmed 2026-05-29 on `a lab unit`).
    // Identical lifetime + (no-op periodic refresh) semantics to the
    // serial-mining idle/API-only branch on S9/am1 + am3 (am2_quiet_idle None).
    park_management_only_until_shutdown(mode_label, shutdown_token, am2_quiet_idle).await;
    info!(
        mode = mode_label,
        "dcentrald (management-only after mining-init failure) stopped cleanly"
    );
    Ok(())
}

/// Print the D-Central Technologies startup banner.
///
/// This is the first thing a miner operator sees on serial console or SSH.
/// Keep it readable on 80-column terminals.
fn print_banner() {
    eprintln!();
    eprintln!("  ____   ____ _____ _   _ _____           ");
    eprintln!(" |  _ \\ / ___| ____| \\ | |_   _|___  ___  ");
    eprintln!(" | | | | |   |  _| |  \\| | | | / _ \\/ __| ");
    eprintln!(" | |_| | |___| |___| |\\  | | || (_) \\__ \\ ");
    eprintln!(" |____/ \\____|_____|_| \\_| |_| \\___/|___/ ");
    eprintln!();
    eprintln!(
        "  dcentrald v{}  —  D-Central Technologies",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("  Mining Hackers from Laval, QC  |  d-central.tech");
    eprintln!("  Open source firmware for the mining plebs");
    eprintln!();
    eprintln!("  Licensed under GPL-3.0. This software is provided AS-IS,");
    eprintln!("  with NO WARRANTY of any kind. See LICENSE for details.");
    eprintln!();
}

#[cfg(test)]
mod tests {
    //! F1 + F5 regression pins (2026-05-17, `a lab unit` first-boot
    //! dcentrald-down rootcause).
    //!
    //! Most per-mode assertions remain structural because the legacy mining
    //! arms still construct their own HALs. The standard daemon's init-timeout
    //! recovery ordering is now also exercised behaviorally through
    //! `daemon_lifecycle`; these assertions retain coverage for the remaining
    //! arms until they migrate behind the same injectable lifecycle port.

    const MAIN_RS: &str = include_str!("main.rs");
    const S19J_HYBRID_RS: &str = include_str!("s19j_hybrid_mining.rs");
    const DAEMON_RS: &str = include_str!("daemon.rs");
    const SERIAL_MINING_RS: &str = include_str!("serial_mining.rs");
    const AM3_BB_RS: &str = include_str!("am3_bb_mining.rs");
    const STOCK_MINING_RS: &str = include_str!("stock_mining.rs");

    #[test]
    fn fan_custody_receipt_binds_exact_process_and_boot() {
        assert_eq!(
            super::proc_stat_start_ticks(
                "123 (dcentrald) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 98765"
            ),
            Some(98765)
        );
        assert_eq!(
            super::fan_custody_record(123, 98765, "boot-id\n").as_deref(),
            Some("123 98765 fan-custodian boot-id\n")
        );
        assert!(super::fan_custody_record(123, 98765, "bad boot id").is_none());
        assert!(super::fan_custody_record(123, 98765, "").is_none());
    }

    #[test]
    fn fan_custody_readiness_is_revoked_after_bounded_refresh_failures() {
        let mut failures = 0;
        assert!(!super::fan_custody_refresh_should_exit(
            &mut failures,
            false
        ));
        assert_eq!(failures, 1);
        assert!(!super::fan_custody_refresh_should_exit(
            &mut failures,
            false
        ));
        assert_eq!(failures, 2);
        assert!(!super::fan_custody_refresh_should_exit(&mut failures, true));
        assert_eq!(failures, 0, "a verified refresh resets the failure budget");
        for _ in 1..super::FAN_CUSTODY_MAX_CONSECUTIVE_REFRESH_FAILURES {
            assert!(!super::fan_custody_refresh_should_exit(
                &mut failures,
                false
            ));
        }
        assert!(super::fan_custody_refresh_should_exit(&mut failures, false));
    }

    fn first_function_end_offset(source: &str) -> usize {
        source
            .find("\n}\n")
            .or_else(|| source.find("\r\n}\r\n"))
            .or_else(|| source.find("\n}\r\n"))
            .expect("fn end not found")
    }

    #[cfg(unix)]
    #[test]
    fn verify_bundle_capability_publication_is_complete_and_replaceable() {
        let directory = std::env::temp_dir().join(format!(
            "dcentrald-verify-bundle-cap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let target = directory.join("caps").join("verify-bundle");

        let first = super::publish_verify_bundle_capability(&target).unwrap();
        assert!(!first.replaced_existing);
        assert_eq!(
            std::fs::read(&target).unwrap(),
            super::VERIFY_BUNDLE_CAPABILITY_BYTES
        );
        let second = super::publish_verify_bundle_capability(&target).unwrap();
        assert!(second.replaced_existing);
        assert!(
            super::VERIFY_BUNDLE_CAPABILITY_BYTES.len()
                <= super::VERIFY_BUNDLE_CAPABILITY_MAX_BYTES
        );
        assert_eq!(
            std::fs::read_dir(target.parent().unwrap()).unwrap().count(),
            1
        );

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn verify_bundle_capability_startup_path_is_atomic_observable_and_nonfatal() {
        let start_marker = ["// wf_c00e5d9e OTA follow-up", ": self-attest"].concat();
        let start = MAIN_RS.find(&start_marker).unwrap();
        let end = MAIN_RS[start..]
            .find("// Explicit operator-facing log line")
            .map(|offset| start + offset)
            .unwrap();
        let startup_block = &MAIN_RS[start..end];

        assert!(startup_block.contains("publish_verify_bundle_capability"));
        assert!(!startup_block.contains("std::fs::write"));
        assert!(startup_block.contains("VerifyBundleCapabilityPublishError::CreateParent"));
        assert!(startup_block.contains("VerifyBundleCapabilityPublishError::Publish"));
        assert!(startup_block.contains("target_published = error.target_published()"));
        assert!(startup_block.contains("publication_durability_uncertain"));
        assert!(!startup_block.contains("return Err"));
        assert!(MAIN_RS.contains("dcentrald_common::atomic_file::atomic_write"));
    }

    #[test]
    fn am2_s19j_auto_route_requires_exact_board_identity() {
        use super::classify_s19j_hybrid_auto;

        assert_eq!(
            classify_s19j_hybrid_auto("zynq-bm3-am2", ""),
            (false, "zynq-bm3-am2".to_string()),
            "generic AM2 platform marker without board_target must not auto-route into S19j"
        );
        assert_eq!(
            classify_s19j_hybrid_auto("zynq-bm3-am2\n", "  "),
            (false, "zynq-bm3-am2".to_string()),
            "whitespace-only board_target is still ambiguous"
        );

        for board_target in [
            "am2-s19j",
            "am2-s19jpro",
            "am2-s19jpro-zynq",
            "am2-s19jpro-xil",
        ] {
            assert_eq!(
                classify_s19j_hybrid_auto("zynq-bm3-am2\n", board_target).0,
                true,
                "{board_target} should keep the established S19j hybrid auto-route"
            );
        }

        for board_target in [
            "am2-s17",
            "am2-s17p",
            "am2-s19",
            "am2-s19pro",
            "am2-s19xp",
            "am2-t17",
            "am2-t19",
            "am3-bb-s19jpro",
        ] {
            assert_eq!(
                classify_s19j_hybrid_auto("zynq-bm3-am2", board_target).0,
                false,
                "{board_target} must stay out of the S19j hybrid auto-route"
            );
        }

        assert_eq!(
            classify_s19j_hybrid_auto("zynq-bm1-s9", "am2-s19j"),
            (false, "zynq-bm1-s9:am2-s19j".to_string()),
            "board_target alone is insufficient without the AM2 platform marker"
        );
    }

    #[test]
    fn s17_board_targets_use_low_memory_tokio_pool() {
        use super::tokio_pool_for_board_target_marker;

        for target in [
            "am2-s17p",
            "am2-s17pro",
            "am2-s17plus",
            "am2-t17",
            "am2-t17plus",
            "x17-s17e-dspic-planned",
            "x17-t17e-pic16-planned",
            "am2-s17",
            "am1-s17",
        ] {
            assert_eq!(
                tokio_pool_for_board_target_marker(target),
                (Some(2), Some(4)),
                "{target} must stay on the bounded low-memory runtime pool"
            );
        }

        assert_eq!(
            tokio_pool_for_board_target_marker("  am2-s17p\n"),
            (Some(2), Some(4)),
            "board_target file whitespace must not defeat the low-memory runtime cap"
        );
    }

    #[test]
    fn s19_family_board_targets_keep_default_tokio_pool() {
        use super::tokio_pool_for_board_target_marker;

        for target in [
            "",
            "am1-s9",
            "am2-s19j",
            "am2-s19jpro",
            "am2-s19jpro-zynq",
            "am2-s19pro",
            "am2-t19",
            "am2-s19xp",
            "am3-s19k",
            "am3-s21",
            "am3-bb-s19jpro",
        ] {
            assert_eq!(
                tokio_pool_for_board_target_marker(target),
                (None, None),
                "{target:?} should keep tokio defaults unless explicitly low-memory capped"
            );
        }
    }

    /// F1 command-order regression: on an am2 PIC-preflight failure the
    /// software safe-off sequence (`force_am2_home_hard_stop` +
    /// `teardown_am2_power_after_failed_pic_preflight`) executes STRICTLY
    /// BEFORE the `anyhow::bail!` that produces the `Err` — and
    /// `enter_management_only` only runs AFTER that `Err` propagates out of
    /// `miner.run()`. This proves command ordering only: physical rails and
    /// cooling remain bench-unqualified. F1 changed what happens to the `Err`
    /// (park instead of exit); it did not reorder the software closeout.
    #[test]
    fn f1_hard_stop_precedes_bail_in_pic_preflight_failure() {
        let hard_stop = S19J_HYBRID_RS
            .find("force_am2_home_hard_stop(&self.config, \"pic-get-version-failed\")")
            .expect(
                "F1 REGRESSION: the am2 PIC-get-version-failed software \
                  closeout call disappeared from s19j_hybrid_mining.rs",
            );
        let bail = S19J_HYBRID_RS
            .find("\"PIC GET_VERSION failed at 0x")
            .expect("F1: PIC GET_VERSION bail site missing");

        assert!(
            hard_stop < bail,
            "F1 ORDERING VIOLATION: force_am2_home_hard_stop must lexically \
             precede the PIC GET_VERSION bail; this does not claim physical \
             rail cutoff"
        );
        // The matching power teardown must live in the SAME failure block,
        // i.e. between the hard-stop and the bail (there are other,
        // unrelated teardown call sites elsewhere in the file — scope the
        // assertion so it can't pass on a coincidental earlier match).
        let pic_fail_block = &S19J_HYBRID_RS[hard_stop..bail];
        assert!(
            pic_fail_block.contains("teardown_am2_power_after_failed_pic_preflight("),
            "F1 SAFETY VIOLATION: teardown_am2_power_after_failed_pic_preflight \
             must be called between force_am2_home_hard_stop and the PIC \
             GET_VERSION bail! (same fail-closed block)"
        );
    }

    /// F1: `enter_management_only(...)` is invoked only from explicit failure
    /// arms. Owning routes validate terminal software closeout first; non-owning
    /// proxy/tap routes must carry no quiet-idle fan authority.
    #[test]
    fn f1_management_only_only_reached_via_err_arm() {
        // Each real call must appear inside an `Err(e)` arm. The arm may be a
        // block now because it cancels the miner child token before parking on
        // the parent process token.
        for label in [
            "\"s19j-hybrid\"",
            "\"serial\"",
            "\"tap\"",
            "\"stratum-proxy\"",
        ] {
            let call = format!("enter_management_only({label}, e, shutdown_token.clone()");
            let call_idx = MAIN_RS
                .find(&call)
                .unwrap_or_else(|| panic!("F1: management-only call missing for {label}"));
            let err_idx = MAIN_RS[..call_idx]
                .rfind("Err(e)")
                .unwrap_or_else(|| panic!("F1: call for {label} is not after an Err(e) arm"));
            let ok_idx = MAIN_RS[..call_idx].rfind("Ok(())").unwrap_or(0);
            assert!(
                err_idx > ok_idx,
                "F1: management-only call for {label} must live in the Err(e) \
                 arm for that mining mode, not the success path"
            );
        }
        assert!(MAIN_RS.contains(
            "am3-bb faulted/reset_pending; refusing to claim stable management-only operation"
        ));
        assert!(!MAIN_RS.contains("enter_management_only(\"am3-bb\", e, shutdown_token.clone()"));
    }

    #[test]
    fn am3_bb_management_only_consumes_matching_terminal_closeout() {
        let arm_start = MAIN_RS
            .find("if am3_bb_mode {")
            .expect("AM3-BB runtime arm");
        let arm_end = MAIN_RS[arm_start..]
            .find("} else if stratum_proxy_mode {")
            .map(|offset| arm_start + offset)
            .expect("AM3-BB runtime arm boundary");
        let arm = &MAIN_RS[arm_start..arm_end];
        let disposition = arm
            .find("Am3BbFailureDisposition::TerminalSafeOffClosed =>")
            .expect("AM3-BB terminal-safe-off disposition");
        let matching_evidence = arm[disposition..]
            .find("Some(am3_bb_mining::Am3BbFailureCloseout::TerminalSafeOff(")
            .map(|offset| disposition + offset)
            .expect("AM3-BB matching terminal-safe-off evidence");
        let management_only = arm[matching_evidence..]
            .find("enter_management_only(\"am3-bb\", error, shutdown_token.clone(), None)")
            .map(|offset| matching_evidence + offset)
            .expect("AM3-BB evidence-gated management-only entry");
        let reset_pending = arm[management_only..]
            .find("Am3BbFailureDisposition::ResetPending =>")
            .map(|offset| management_only + offset)
            .expect("AM3-BB reset-pending branch");

        assert!(disposition < matching_evidence && matching_evidence < management_only);
        assert!(!arm[reset_pending..].contains("enter_management_only(\"am3-bb\""));
    }

    #[test]
    fn nonowning_proxy_and_tap_routes_never_receive_fan_lowering_authority() {
        let proxy_start = MAIN_RS
            .find("} else if stratum_proxy_mode {")
            .expect("stratum-proxy runtime arm");
        let tap_start = MAIN_RS[proxy_start..]
            .find("} else if tap_mode {")
            .map(|offset| proxy_start + offset)
            .expect("tap runtime arm");
        let hybrid_start = MAIN_RS[tap_start..]
            .find("} else if s19j_hybrid_mode {")
            .map(|offset| tap_start + offset)
            .expect("s19j-hybrid runtime arm");

        let proxy = &MAIN_RS[proxy_start..tap_start];
        let tap = &MAIN_RS[tap_start..hybrid_start];
        assert!(proxy
            .contains("enter_management_only(\"stratum-proxy\", e, shutdown_token.clone(), None)"));
        assert!(tap.contains("enter_management_only(\"tap\", e, shutdown_token.clone(), None)"));
        for (label, arm) in [("stratum-proxy", proxy), ("tap", tap)] {
            assert!(
                !arm.contains("am2_quiet_idle_tuple")
                    && !arm.contains("force_am2_fans_to_quiet_idle"),
                "nonowning {label} route must not command a competing fan actor"
            );
        }
    }

    /// F1 platform-wide: routes whose complete control-plane task graph is
    /// lifecycle-owned may park after positive closeout evidence. The standard
    /// daemon is deliberately excluded: its process-global gRPC/MQTT state and
    /// detached accepted CGMiner children cannot yet be atomically retired and
    /// rebound without stale write or telemetry authority.
    #[test]
    fn f1_only_fully_owned_closeout_arms_use_management_only_on_err() {
        assert!(MAIN_RS.contains("Am3BbFailureDisposition::TerminalSafeOffClosed =>"));
        assert!(MAIN_RS
            .contains("enter_management_only(\"am3-bb\", error, shutdown_token.clone(), None)"));
        for label in [
            "\"s19j-hybrid\"",
            "\"serial\"",
            "\"tap\"",
            "\"stratum-proxy\"",
        ] {
            assert!(
                MAIN_RS.contains(&format!("enter_management_only({label}, e, shutdown_token")),
                "F1: mining arm {label} does not route miner.run() Err through \
                 enter_management_only — the coupled-lifetime regression class \
                 (`a lab unit` daemon exits → API dies) is not closed for this arm"
            );
        }
        assert!(!MAIN_RS.contains("enter_management_only(\"daemon\""));
    }

    #[test]
    fn standard_terminal_error_refuses_unowned_observer_rebind() {
        let branch_start = MAIN_RS
            .find("StandardDaemonFailureDisposition::TerminalSafeOffClosed =>")
            .expect("standard terminal-closeout branch");
        let branch_end = MAIN_RS[branch_start..]
            .find("StandardDaemonFailureDisposition::NeverEnergized =>")
            .map(|offset| branch_start + offset)
            .expect("standard terminal-closeout branch boundary");
        let branch = &MAIN_RS[branch_start..branch_end];

        let closeout = branch
            .find("StandardDaemonFailureCloseout::TerminalSafeOff")
            .expect("matching standard closeout evidence");
        let refusal = branch
            .find("safe in-process observer rebinding is not implemented")
            .expect("standard observer-rebind refusal");
        assert!(closeout < refusal);
        assert!(!branch.contains("spawn_observer_only_api"));
        assert!(!branch.contains("enter_management_only(\"daemon\""));
        assert!(DAEMON_RS.contains("standard_api_tasks:"));
        assert!(DAEMON_RS.contains(
            "self.standard_api_tasks = match dcentrald_api::start_api_servers(app_state).await"
        ));
    }

    /// no-brick #6: the typed standard lifecycle attempts its one-shot shutdown
    /// before reporting a mining error. Only shutdown success carries opaque
    /// terminal closeout; shutdown failure stays reset-pending, and a prior
    /// shutdown attempt is never retried. The api-only fall-through remains
    /// distinctly never-energized and does not invoke mining teardown.
    #[test]
    fn nobrick6_daemon_run_tears_down_hardware_on_mining_error() {
        assert!(
            DAEMON_RS.contains("self.run_lifecycle().await"),
            "no-brick #6: Daemon::run() must delegate to run_lifecycle() so the \
             typed software-closeout teardown wrapper is never bypassed"
        );
        let mining_arm = DAEMON_RS.find("Err(e) if mining =>").expect(
            "no-brick #6: the `Err(e) if mining =>` teardown arm is missing from Daemon::run()",
        );
        let fallthrough = DAEMON_RS[mining_arm..]
            .find("Err(e) => Err(StandardDaemonLifecycleError::never_energized(e))")
            .map(|i| i + mining_arm)
            .expect("no-brick #6: the typed api-only never-energized fall-through arm is missing");
        assert!(
            mining_arm < fallthrough,
            "no-brick #6: the mining teardown arm must precede the api-only fall-through"
        );
        let mining_arm_body = &DAEMON_RS[mining_arm..fallthrough];
        assert!(
            mining_arm_body.contains("self.shutdown().await"),
            "no-brick #6 SAFETY VIOLATION: the mining-lifecycle Err arm of \
             Daemon::run() must run the typed software-closeout teardown \
             (self.shutdown()) before propagating — otherwise boards can stay \
             energized + watchdog armed on an error exit"
        );
        assert!(
            mining_arm_body.contains(
                "Ok(closeout) => Err(StandardDaemonLifecycleError::terminal_safe_off_closed("
            ),
            "standard daemon lifecycle may classify TerminalSafeOffClosed only after shutdown returns opaque terminal closeout evidence"
        );
        let teardown_error_arm = mining_arm_body
            .find("Err(te) =>")
            .expect("standard daemon lifecycle wrapper must classify shutdown failure");
        assert!(
            mining_arm_body[teardown_error_arm..]
                .contains("StandardDaemonLifecycleError::reset_pending("),
            "standard daemon shutdown failure must remain reset-pending"
        );
        assert!(
            mining_arm_body.contains("if self.shutdown_attempted"),
            "an already-attempted one-shot shutdown must not be retried or treated as closed"
        );
        // The api-only fall-through must NOT tear down (nothing was energized).
        let fallthrough_tail = &DAEMON_RS[fallthrough..fallthrough + 64];
        assert!(
            !fallthrough_tail.contains("shutdown"),
            "no-brick #6: the api-only `Err(e) => Err(e)` arm must NOT run the \
             mining teardown (no hardware was energized in api-only mode)"
        );
    }

    #[test]
    fn standard_daemon_terminal_closeout_refuses_unowned_management_rebind() {
        let arm_start = MAIN_RS
            .find("match daemon.run_with_lifecycle_disposition().await")
            .expect("standard daemon main arm must retain typed lifecycle disposition");
        let arm_end = MAIN_RS[arm_start..]
            .find("// `spawn_proxy_mode_api`")
            .map(|offset| arm_start + offset)
            .expect("standard daemon main arm boundary missing");
        let arm = &MAIN_RS[arm_start..arm_end];

        let terminal = arm
            .find("StandardDaemonFailureDisposition::TerminalSafeOffClosed =>")
            .expect("standard daemon main arm must handle terminal-safe-off closeout");
        let matching_closeout = arm[terminal..]
            .find("Some(crate::daemon::StandardDaemonFailureCloseout::TerminalSafeOff(")
            .map(|offset| terminal + offset)
            .expect("standard daemon terminal disposition must consume matching closeout evidence");
        let refusal = arm[matching_closeout..]
            .find("safe in-process observer rebinding is not implemented")
            .map(|offset| matching_closeout + offset)
            .expect("standard daemon terminal closeout must refuse the unowned observer rebind");
        assert!(terminal < matching_closeout);
        assert!(matching_closeout < refusal);
        assert!(
            !arm.contains("enter_management_only(\"daemon\""),
            "standard daemon must not retain a stale process-global writer graph"
        );

        let reset_pending = arm
            .find("StandardDaemonFailureDisposition::ResetPending =>")
            .expect("standard daemon main arm must handle reset-pending shutdown failure");
        assert!(arm[reset_pending..].contains("closeout.is_none()"));
        assert!(arm[reset_pending..].contains("Err(e.context("));
        assert!(
            !arm[reset_pending..].contains("enter_management_only(\"daemon\""),
            "reset-pending standard shutdown must refuse stable management-only operation"
        );
    }

    /// no-brick #16: every energizing mining path must have a cut-hash peer in
    /// the crash-panic hook (panic=abort bypasses Drop). Pin the retained
    /// platform peers, including native S15/T15 BM1391, so a
    /// future platform path can't silently ship without its panic-hook teardown.
    #[test]
    fn panic_hook_chains_all_platform_teardowns() {
        let hook_start = MAIN_RS
            .find("fn install_cut_hash_on_crash_panic_hook()")
            .expect("install_cut_hash_on_crash_panic_hook missing");
        // Bound the search to the function body (up to `previous(info);`, the
        // last statement before the hook closure/fn close).
        let prev_rel = MAIN_RS[hook_start..]
            .find("previous(info);")
            .expect("panic hook must chain the previous hook via previous(info)");
        let hook_body = &MAIN_RS[hook_start..hook_start + prev_rel];
        for peer in [
            "s19j_hybrid_mining::panic_hook_best_effort_teardown",
            "serial_mining::nopic_panic_hook_best_effort_teardown",
            "am3_bb_mining::am3_bb_panic_hook_best_effort_teardown",
            "stock_mining::stock_fpga_panic_hook_best_effort_teardown",
            "bm1391_mining::panic_hook_best_effort_teardown",
        ] {
            assert!(
                hook_body.contains(peer),
                "no-brick #16: crash-panic hook is missing the cut-hash teardown peer `{peer}` — \
                 an energizing path without a panic-hook cut leaves boards hot on panic=abort"
            );
        }
    }

    #[test]
    fn s19k_track1_bootstrap_precedes_panic_hook_and_tokio() {
        let main_start = MAIN_RS
            .find("fn main() -> Result<()> {")
            .expect("main function missing");
        let main_tail = &MAIN_RS[main_start..];
        let pdeath = main_tail
            .find("s19k_arm_permanent_pdeathsig_from_env()?")
            .expect("S19k permanent PDEATHSIG bootstrap missing from main");
        let synchronous_chain = main_tail
            .find("s19k_complete_daemon_pre_runtime_bootstrap(&authority, &identity, bootstrap)?")
            .expect("S19k synchronous C1/J1/FIFO bootstrap missing from main");
        let j3 = main_tail
            .find("s19k_track1_startup_barrier_and_acquire_j3(")
            .expect("S19k pre-runtime J3 acquisition missing from main");
        let panic_hook = main_tail
            .find("install_cut_hash_on_crash_panic_hook();")
            .expect("panic hook call missing from main");
        let tokio = main_tail
            .find("tokio::runtime::Builder::new_multi_thread()")
            .expect("Tokio builder missing from main");
        assert!(pdeath < synchronous_chain);
        assert!(synchronous_chain < j3);
        assert!(j3 < panic_hook);
        assert!(panic_hook < tokio);
    }

    /// WATCHDOG (2026-06-28): every mining entry path that bypasses
    /// `Daemon::run()` (`--s19j-hybrid`, `--serial-mining`, `--am3-bb-mining`,
    /// `--stock-fpga`) MUST
    /// arm the hardware `/dev/watchdog`. Native serial NoPic, S19j hybrid, and
    /// AM3-BB use the stricter pre-energize `SafetyWatchdogOwner`; legacy stock
    /// mode
    /// use the shared `spawn_watchdog_kicker` helper after bring-up. The standard
    /// `Daemon::run` path uses its owned watchdog lifecycle. A CPU/runtime hang on
    /// an unarmed path leaves the hash boards energized & unsupervised. Source-order
    /// pin (mirrors `panic_hook_chains_all_platform_teardowns`): these are
    /// binary-crate / HAL-bound paths that cannot be driven in a host unit test.
    #[test]
    fn watchdog_armed_on_all_mining_entry_paths() {
        // The shared helper definition lives in daemon.rs.
        assert!(
            DAEMON_RS.contains("pub(crate) fn spawn_watchdog_kicker("),
            "WATCHDOG: the shared spawn_watchdog_kicker helper is missing from daemon.rs"
        );
        // The standard path must retain the watchdog under an independent task
        // owner with a thermal-liveness clock and explicit teardown/disarm intent.
        assert!(
            DAEMON_RS.contains("owned_watchdog_kicker(")
                && DAEMON_RS.contains("watch::channel(WatchdogIntent::Mining)")
                && DAEMON_RS.contains(".spawn(\"soc-watchdog-kicker\"")
                && DAEMON_RS.contains("StandardWatchdogDisarmPermit::from_evidence(evidence)")
                && DAEMON_RS.contains("disarm_tx.send(permit)"),
            "WATCHDOG: the standard path must use owned, same-run evidence-gated watchdog supervision"
        );
        // Each Daemon::run-bypassing mining entry path must arm via the helper
        // with a path-local liveness counter (SAF-5). Passing None here is a
        // regression: a live-locked runtime would keep petting `/dev/watchdog`.
        for (src, name) in [(STOCK_MINING_RS, "stock-fpga")] {
            assert!(
                src.contains("let watchdog_liveness = Arc::new(AtomicU64::new(0));")
                    && src.contains("Some(watchdog_liveness.clone())")
                    && src.contains("watchdog_liveness.fetch_add(1, Ordering::Relaxed)"),
                "WATCHDOG: the {name} mining entry path must arm /dev/watchdog via \
                 spawn_watchdog_kicker with a live runtime counter — a CPU/runtime hang there leaves boards energized & \
                 unsupervised"
            );
            assert!(
                !src.contains(
                    "crate::daemon::spawn_watchdog_kicker(&self.config.watchdog, self.shutdown.clone(), None)"
                ),
                "WATCHDOG: the {name} mining entry path regressed to unconditional watchdog kicks"
            );
        }
        assert!(
            S19J_HYBRID_RS.contains("SafetyWatchdogOwner::start_before_energizing")
                && S19J_HYBRID_RS.contains("admission.require_armed(\"s19j-hybrid\")")
                && S19J_HYBRID_RS.contains("HardwareMutationGateOwner::new_pending()")
                && S19J_HYBRID_RS.contains(".enter_mining()")
                && S19J_HYBRID_RS.contains(".open()")
                && S19J_HYBRID_RS.contains("watchdog_liveness.mark_progress()")
                && S19J_HYBRID_RS.contains(".request_teardown_budget()")
                && S19J_HYBRID_RS.contains("Am2TerminalSafeOffEvidence")
                && S19J_HYBRID_RS.contains("close_am2_power_control_after_safe_off(")
                && S19J_HYBRID_RS.contains("HybridWatchdogShutdownManifest::new(")
                && S19J_HYBRID_RS.contains("WatchdogDisarmPermit::from_hybrid_manifest(")
                && S19J_HYBRID_RS.contains(".disarm_and_join("),
            "WATCHDOG: S19j hybrid must retain pre-energize ownership, API admission, safety liveness, terminal PWR_CONTROL closeout, and evidence-gated disarm"
        );
        assert!(
            !S19J_HYBRID_RS.contains("spawn_watchdog_kicker"),
            "WATCHDOG: S19j hybrid regressed to the detached legacy kicker"
        );
        let hybrid_admission = MAIN_RS
            .find("S19jHybridSafetyAdmission::start(")
            .expect("S19j hybrid pre-energize admission missing from main");
        let hybrid_gate = MAIN_RS[hybrid_admission..]
            .find("let api_mutation_gate = safety_admission.hardware_mutation_gate();")
            .map(|offset| hybrid_admission + offset)
            .expect("S19j hybrid admitted mutation gate extraction missing");
        let hybrid_api = MAIN_RS[hybrid_gate..]
            .find("spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(")
            .map(|offset| hybrid_gate + offset)
            .expect("S19j hybrid shared API gate spawn missing after admission");
        let hybrid_miner = MAIN_RS[hybrid_api..]
            .find("S19jHybridMiner::new(")
            .map(|offset| hybrid_api + offset)
            .expect("S19j hybrid miner construction missing");
        assert!(
            hybrid_admission < hybrid_gate && hybrid_gate < hybrid_api && hybrid_api < hybrid_miner,
            "WATCHDOG: S19j hybrid admission must precede shared API admission and miner construction"
        );
        let hybrid_arm = MAIN_RS
            .split("} else if s19j_hybrid_mode {")
            .nth(1)
            .expect("S19j hybrid main arm missing")
            .split("} else if serial_mining_mode {")
            .next()
            .expect("bounded S19j hybrid main arm");
        let idle = hybrid_arm
            .split("if !config.mining_start_enabled() {")
            .nth(1)
            .expect("S19j hybrid idle branch missing")
            .split("let mining_shutdown")
            .next()
            .expect("bounded S19j hybrid idle branch");
        assert!(
            idle.contains("HardwareMutationGate::new_closed()"),
            "WATCHDOG: S19j hybrid idle API must receive a permanently closed mutation gate"
        );
        let admission_failure = hybrid_arm
            .split("Err(error) => {")
            .nth(1)
            .expect("S19j hybrid admission-failure branch missing")
            .split("let api_mutation_gate")
            .next()
            .expect("bounded S19j hybrid admission-failure branch");
        assert!(
            admission_failure.contains("HardwareMutationGate::new_closed()")
                && admission_failure.contains("s19j-hybrid-watchdog-admission")
                && admission_failure.contains("is_watchdog_reset_pending(&error)")
                && admission_failure.contains(
                    "s19j-hybrid watchdog admission faulted/reset_pending before API startup"
                ),
            "WATCHDOG: only proven pre-open hybrid failures may park behind a closed API gate; post-open failures must exit reset-pending"
        );
        // Passthrough policy is owned by `S19jHybridMiner::run()`, which branches on
        // `self.config.mining.passthrough` across every Phase-0 branch (PSU, I2C service,
        // hard-stop guard, open-core) and refuses to mint daemon-owned terminal safe-off
        // evidence under passthrough. The route selector deliberately does NOT re-branch on
        // it: a second copy of that policy here could drift from the engine's. What keeps a
        // passthrough run safe is that `S19jHybridSafetyAdmission::start` above is
        // unconditional, so passthrough is still watchdog-admitted before miner construction.
        assert!(
            hybrid_arm.contains("is_terminal_safe_off_error(&e)")
                && hybrid_arm.contains("if !s19j_hybrid_mining::is_terminal_safe_off_error(&e)")
                && hybrid_arm.contains("enter_management_only(\"s19j-hybrid\", e, shutdown_token.clone(), None)"),
            "WATCHDOG: hybrid parking requires positive post-disarm evidence and never starts a management-only fan actor"
        );
        let s17_arm = MAIN_RS
            .split("} else if s17_hybrid_mode {")
            .nth(1)
            .expect("S17 main arm missing")
            .split("} else if serial_mining_mode {")
            .next()
            .unwrap();
        let closeout_check = s17_arm
            .find("if !s17_hybrid_mining::is_terminal_safe_off_error(&e)")
            .expect("S17 requires its own typed terminal closeout");
        let reset_pending = s17_arm[closeout_check..]
            .find("return Err(")
            .map(|offset| closeout_check + offset)
            .expect("unproven S17 shutdown must return an error");
        let management = s17_arm
            .find("enter_management_only(\"s17-hybrid\", e, shutdown_token.clone(), None)")
            .expect("checked S17 shutdown preserves management");
        assert!(closeout_check < reset_pending && reset_pending < management);
        assert!(
            SERIAL_MINING_RS.contains("SafetyWatchdogOwner::start_before_energizing")
                && SERIAL_MINING_RS.contains("nopic_watchdog_liveness.mark_progress()")
                && SERIAL_MINING_RS.contains("if nopic_watchdog.is_none()")
                && SERIAL_MINING_RS.contains("NoPicWatchdogShutdownManifest::new(")
                && SERIAL_MINING_RS.contains("Am2SerialWatchdogShutdownManifest::new(")
                && SERIAL_MINING_RS.contains("WatchdogDisarmPermit::from_nopic_manifest(")
                && SERIAL_MINING_RS
                    .contains("WatchdogDisarmPermit::from_am2_serial_manifest("),
            "WATCHDOG: native serial NoPic and exact AM2 must use pre-energize ownership and exact evidence manifests while other serial routes retain the legacy helper temporarily"
        );
        assert!(
            MAIN_RS.contains("is_watchdog_reset_pending(&e)")
                && MAIN_RS.contains(
                    "serial watchdog admission faulted/reset_pending; watchdog reset is required"
                )
                && MAIN_RS.contains("match serial_mining::failure_disposition(&e)")
                && MAIN_RS.contains(
                    "Some(serial_mining::SerialFailureDisposition::NeverEnergizedClosed)"
                )
                && MAIN_RS.contains(
                    "Some(serial_mining::SerialFailureDisposition::StockOwnerRetainedClosed)"
                )
                && MAIN_RS.contains(
                    "external runner custody must remain until separately audited cleanup"
                )
                && MAIN_RS.contains(
                    "Some(serial_mining::SerialFailureDisposition::TerminalSafeOffClosed)"
                )
                && MAIN_RS.contains("enter_management_only(\"serial\", e, shutdown_token.clone(), None)"),
            "WATCHDOG: serial parking requires a positive typed never-energized or terminal-safe-off watchdog closeout and post-open failures remain reset-pending"
        );
        // AM3-BB admits the owner before API/hardware access, advances only
        // safety liveness, and can magic-close only from the complete evidence
        // set. Its enum-only stub must never counterfeit Mining liveness.
        assert!(
            AM3_BB_RS.contains("SafetyWatchdogOwner::start_before_energizing")
                && AM3_BB_RS.contains("WatchdogAdmission::Armed(receipt) => receipt")
                && AM3_BB_RS.contains("HardwareMutationGateOwner::new_pending()")
                && AM3_BB_RS.contains("watchdog.enter_mining()")
                && AM3_BB_RS.contains("let api_admission = hardware_mutation_owner\n        .open()")
                && AM3_BB_RS.contains("watchdog_liveness.mark_progress()")
                && AM3_BB_RS.contains("watchdog\n        .request_teardown_budget(")
                && AM3_BB_RS.contains("watchdog.observe_teardown_admission(")
                && AM3_BB_RS.contains("Am3BbWatchdogShutdownManifest::new(")
                && AM3_BB_RS.contains("WatchdogDisarmPermit::from_am3_bb_manifest(")
                && AM3_BB_RS.contains("watchdog.disarm_and_join("),
            "WATCHDOG: AM3-BB must retain pre-energize ownership, safety liveness, and evidence-gated closeout"
        );
        assert!(
            !AM3_BB_RS.contains("spawn_watchdog_kicker") && !AM3_BB_RS.contains("Arc<AtomicU64>"),
            "WATCHDOG: AM3-BB regressed to the detached legacy kicker"
        );
        let admission = MAIN_RS
            .find("Am3BbSafetyAdmission::start(")
            .expect("AM3-BB pre-energize admission missing from main");
        let api = MAIN_RS[admission..]
            .find("spawn_proxy_mode_api_with_state_gate_and_identity(")
            .map(|offset| admission + offset)
            .expect("AM3-BB shared API gate spawn missing");
        let mining = MAIN_RS[api..]
            .find("am3_bb_mining::run_am3_bb_mining(")
            .map(|offset| api + offset)
            .expect("AM3-BB mining call missing");
        assert!(
            admission < api && api < mining,
            "WATCHDOG: AM3-BB watchdog admission must precede shared API admission and mining"
        );
    }

    #[test]
    fn am3_bb_api_is_route_identified_and_pool_acknowledgement_driven() {
        let arm_start = MAIN_RS
            .find("if am3_bb_mode {")
            .expect("AM3-BB runtime arm missing");
        let arm_end = MAIN_RS[arm_start..]
            .find("} else if s19j_hybrid_mode {")
            .map(|offset| arm_start + offset)
            .expect("AM3-BB runtime arm boundary missing");
        let arm = &MAIN_RS[arm_start..arm_end];

        assert!(
            arm.contains("spawn_proxy_mode_api_with_state_gate_and_identity(")
                && arm.contains("let api_identity = safety_admission.api_identity();")
                && arm.contains("api_identity,")
                && arm.contains("Some(miner_state_rx)")
                && arm.contains("miner_state_tx,"),
            "AM3-BB API must receive exact carrier identity plus the matching live state channel"
        );
        assert!(
            AM3_BB_RS.contains("control_board_label: \"BeagleBone am3-bb-s19jpro\"")
                && AM3_BB_RS.contains("declared_asic_board_target(")
                && AM3_BB_RS.contains("StratumStatus::ShareAccepted")
                && AM3_BB_RS.contains("state.accepted = state.accepted.saturating_add(1)")
                && AM3_BB_RS.contains("pool_target_difficulty")
                && AM3_BB_RS.contains("chips: 0")
                && AM3_BB_RS.contains("population_unproven"),
            "AM3-BB API state must follow pool acknowledgements without publishing configured chips as measured population"
        );
    }

    /// Legacy stock/generic-serial supervision has no exact closeout manifest.
    /// Process cancellation must therefore stop feeds without granting itself
    /// magic-close authority before route-specific safe-off even begins.
    #[test]
    fn legacy_watchdog_cancellation_never_magic_closes_before_safeoff() {
        let legacy = DAEMON_RS
            .rsplit_once("fn watchdog_kicker_loop(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split("#[derive(Debug, Clone, Copy)]").next())
            .expect("bounded legacy watchdog implementation");
        let cancellation = legacy
            .split("shutdown.cancelled()")
            .nth(1)
            .and_then(|tail| tail.split("_ = interval.tick()").next())
            .expect("bounded legacy watchdog cancellation branch");

        assert!(!cancellation.contains("close_magic"));
        assert!(cancellation.contains("std::mem::forget(wd)"));
        assert!(cancellation.contains("withholding future kicks"));
        assert_eq!(legacy.matches("close_magic").count(), 0);
        assert!(SERIAL_MINING_RS.contains("crate::daemon::spawn_watchdog_kicker("));
        assert!(STOCK_MINING_RS.contains("crate::daemon::spawn_watchdog_kicker("));
    }

    /// F5: the s19j-hybrid / am3-bb / tap arms gate on
    /// `!config.mining_start_enabled()` and return via
    /// `enter_management_only_idle` BEFORE constructing/running the miner —
    /// so a fresh, unconfigured unit performs NO PIC preflight / cold boot
    /// / FPGA work dispatch at all ("does LESS, never MORE").
    #[test]
    fn f5_fresh_unit_gate_precedes_miner_run() {
        let run_start = MAIN_RS
            .find("async fn run_main(mut s19k_track1_j3_lease: Option<S19kTrack1J3Lease>) -> Result<()> {")
            .expect("run_main entry missing");
        let tests_start = MAIN_RS[run_start..]
            .find("#[cfg(test)]")
            .map(|offset| run_start + offset)
            .expect("runtime test module boundary missing");
        let runtime_main = &MAIN_RS[run_start..tests_start];

        // s19j-hybrid: the gate must precede `S19jHybridMiner::new`.
        let s19j_new = runtime_main
            .find("S19jHybridMiner::new(")
            .expect("s19j-hybrid miner construction missing");
        let s19j_gate = runtime_main[..s19j_new]
            .rfind("if !config.mining_start_enabled() {")
            .expect(
                "F5: s19j-hybrid arm has no mining_start_enabled() gate before miner construction",
            );
        assert!(
            s19j_gate < s19j_new,
            "F5 SAFETY: the mining_start_enabled() gate must precede \
             S19jHybridMiner::new — a fresh unit must NOT construct/run the \
             miner (no PIC preflight, no cold boot, no crash)"
        );
        // am3-bb: the gate must precede `run_am3_bb_mining(`.
        let am3_run = runtime_main
            .find("am3_bb_mining::run_am3_bb_mining(")
            .expect("am3-bb mining entry missing");
        let am3_gate = runtime_main[..am3_run]
            .rfind("if !config.mining_start_enabled() {")
            .expect("F5: am3-bb arm has no mining_start_enabled() gate before run_am3_bb_mining");
        assert!(
            am3_gate < am3_run,
            "F5 SAFETY: am3-bb fresh-unit gate must precede run_am3_bb_mining"
        );

        // tap: the gate must precede `S19jTapMiner::new`, because the tap
        // miner dispatches FPGA work even though bosminer owns PIC/PSU/serial.
        let tap_arm = runtime_main
            .find("} else if tap_mode {")
            .expect("tap-mode arm missing");
        let tap_new = runtime_main
            .find("S19jTapMiner::new(config, mining_shutdown.clone())")
            .expect("tap miner construction missing");
        let tap_gate = runtime_main[tap_arm..tap_new]
            .find("if !config.mining_start_enabled() {")
            .map(|idx| tap_arm + idx)
            .expect("F5: tap arm has no mining_start_enabled() gate before S19jTapMiner::new");
        let tap_idle_body = &runtime_main[tap_arm..tap_new];
        assert!(
            tap_gate < tap_new,
            "F5 SAFETY: tap fresh-unit gate must precede S19jTapMiner::new"
        );
        assert!(
            tap_idle_body.contains("spawn_proxy_mode_api("),
            "F5: tap idle branch must bring up API/dashboard before parking \
             management-only"
        );

        // All gated arms return through the idle helper, not a crash path.
        // `return enter_management_only_idle(` is the exact call shape used
        // by these arms (the fn definition uses `async fn`, prose/this test
        // do not use that prefix), so this count is exactly the call sites.
        assert!(
            runtime_main
                .matches("return enter_management_only_idle(")
                .count()
                >= 3,
            "F5: the s19j-hybrid, am3-bb, and tap fresh-unit gates must \
             `return enter_management_only_idle(...)` (park, not crash)"
        );
    }


    /// F1: `enter_management_only` parks on the shutdown token and returns
    /// `Ok(())` (it does NOT propagate the mining error as a process exit).
    /// This is what keeps the API alive — pin the no-`Err`-return shape.
    #[test]
    fn f1_management_only_parks_and_returns_ok() {
        let body_start = MAIN_RS
            .find("async fn enter_management_only(")
            .expect("enter_management_only definition missing");
        let body = &MAIN_RS[body_start..];
        let body_end = first_function_end_offset(body) + body_start;
        let body = &MAIN_RS[body_start..body_end];
        assert!(
            body.contains("park_management_only_until_shutdown("),
            "F1: enter_management_only must park the process on the shutdown \
             token (via park_management_only_until_shutdown, which awaits \
             shutdown_token.cancelled()) so the already-spawned API task stays \
             alive"
        );
        assert!(
            body.contains("Ok(())"),
            "F1: enter_management_only must return Ok(()) — returning Err \
             would exit the process and kill the API (the `a lab unit` defect)"
        );
        assert!(
            !body.contains("Err(e)") && !body.contains("return Err"),
            "F1: enter_management_only must NOT return the mining Err"
        );
    }

    /// F1-B: mining modes receive child cancellation tokens, while
    /// management-only parks on the parent process token. This prevents a
    /// miner-local failure path from cancelling the API parking lifetime.
    #[test]
    fn f1_mining_modes_use_child_tokens_not_process_token() {
        for marker in [
            "stratum_proxy::run(config, mining_shutdown.clone(), Some(stats))",
            "S19jTapMiner::new(config, mining_shutdown.clone())",
        ] {
            assert!(
                MAIN_RS.contains(marker),
                "F1-B: mining mode missing child-token call marker `{marker}`. \
                 Miner-local cancellation must not cancel the process token \
                 used by management-only parking."
            );
        }
        let serial_call = MAIN_RS
            .find("let mut miner = match SerialMiner::new(")
            .expect("F1-B: serial miner construction missing");
        assert!(
            MAIN_RS[serial_call..].contains("mining_shutdown.clone(),"),
            "F1-B: SerialMiner must receive its mining child token"
        );
        assert!(
            MAIN_RS
                .contains("S19jHybridMiner::new(config, mining_shutdown.clone(), route_admission)"),
            "F1-B: S19jHybridMiner must receive its mining child token and one-shot route proof"
        );
        let am3_call = MAIN_RS
            .find("am3_bb_mining::run_am3_bb_mining(")
            .expect("AM3-BB mining call missing");
        assert!(
            MAIN_RS[am3_call..].contains("mining_shutdown.clone(),"),
            "F1-B: AM3-BB must receive its mining child token"
        );

        assert!(
            MAIN_RS
                .matches("let mining_shutdown = shutdown_token.child_token();")
                .count()
                >= 5,
            "F1-B: expected mining modes to derive child tokens from the \
             process shutdown token before starting miner-owned tasks"
        );
        assert!(
            MAIN_RS.matches("mining_shutdown.cancel();").count() >= 5,
            "F1-B: each miner Err arm should cancel the child token to stop \
             mode-owned tasks before parking the API on the process token"
        );
        assert!(
            MAIN_RS.contains("enter_management_only(\"s19j-hybrid\", e, shutdown_token.clone()"),
            "F1-B: management-only must still park on the parent process \
             shutdown token, not the miner child token"
        );
    }

    /// HOME-SAFETY (2026-05-29, `a lab unit`): management-only mode must PERIODICALLY
    /// re-assert the am2 idle fan setpoint, not command it once and idle — the
    /// AM2 board's fan IP reverts the fans to full speed if nothing re-commands
    /// the PWM. Pin the periodic-refresh + SIGTERM-responsiveness shape of the
    /// shared park helper. Config-gated/non-owning parking must still route
    /// through it with `None`, preserving cooling without receiving the
    /// closeout-only fan-lowering capability.
    #[test]
    fn management_only_periodically_reasserts_am2_idle_fan() {
        let start = MAIN_RS
            .find("async fn park_management_only_until_shutdown(")
            .expect("park_management_only_until_shutdown definition missing");
        let body = &MAIN_RS[start..];
        let body_end = first_function_end_offset(body);
        let body = &body[..body_end];

        // It must still park on the shutdown token (lifetime preserved) ...
        assert!(
            body.contains("shutdown_token.cancelled().await"),
            "park helper must await shutdown_token.cancelled() (park the process)"
        );
        // ... race the refresh tick against shutdown so SIGTERM is prompt ...
        assert!(
            body.contains("tokio::select!") && body.contains("refresh.tick()"),
            "park helper must select! between a periodic tick and shutdown so \
             the periodic fan refresh never delays SIGTERM"
        );
        // ... and the periodic body must RE-RUN the proven fan-park call.
        assert!(
            body.contains("force_am2_fans_to_quiet_idle"),
            "park helper must re-assert the am2 idle fan setpoint on each tick \
             (reuse the proven in-process FanController park, NOT --set-fan)"
        );
        // The refresh is gated on the am2/uio16 variant (Some) — None paths
        // (S9/am1 + am3) must keep the old single terminal await (no fan I/O).
        assert!(
            body.contains("let Some((fan_idle_pwm, fan_max_pwm)) = am2_quiet_idle else"),
            "park helper periodic refresh must be gated on am2_quiet_idle = \
             Some(..) (am2/uio16 only); None = byte-identical single await"
        );

        // Split so this counting contract cannot match its own literal: MAIN_RS is
        // `include_str!("main.rs")`, i.e. this very file, so a contiguous literal here
        // would inflate the count by one and make `== 1` unsatisfiable by construction.
        let fan_hold_forward = [
            "park_management_only_until_shutdown(mode_label, shutdown_token, ",
            "am2_quiet_idle)",
        ]
        .concat();
        assert_eq!(
            MAIN_RS.matches(&fan_hold_forward).count(),
            1,
            "only the typed post-closeout helper may forward fan-hold authority"
        );
        let idle_start = MAIN_RS
            .find("async fn enter_management_only_idle(")
            .expect("config-gated management-only helper missing");
        let idle_tail = &MAIN_RS[idle_start..];
        let idle_end = first_function_end_offset(idle_tail);
        let idle_body = &idle_tail[..idle_end];
        assert!(
            idle_body
                .contains("park_management_only_until_shutdown(mode_label, shutdown_token, None)"),
            "config-gated routes must preserve inherited cooling"
        );
        assert!(
            !idle_body.contains("Option<(u8, u8)>")
                && !idle_body.contains("force_am2_fans_to_quiet_idle")
                && !idle_body.contains("am2_quiet_idle_tuple"),
            "config-gated helper must not carry or synthesize fan-lowering authority"
        );
    }

    // -----------------------------------------------------------------------
    // R2 — `--set-fan` one-shot clamp + arg parse
    //
    // -----------------------------------------------------------------------

    use super::{
        am2_low_pwm_floor_present, clamp_set_fan_pwm, format_fan_raw_registers,
        parse_fan_sweep_list, run_set_fan_oneshot,
    };

    /// Wave-B `--safe-off`: the pure platform→power-cut mapping must route each
    /// platform to its AUDITED cut, and the am2 fingerprint must NOT fall
    /// through to the generic zynq arm (am2 uses PWR_CONTROL gpio907, not
    /// zynq::disable_psu_output). Runtime assertions, not a source-string parse.
    #[test]
    fn safe_off_cut_maps_each_platform_to_its_audited_cut() {
        use super::{safe_off_cut_for_platform, SafeOffCut};
        assert_eq!(
            safe_off_cut_for_platform("zynq-bm3-am2"),
            SafeOffCut::Am2PwrControl
        );
        // real .25 stamp variants (trailing newline + xil suffix) still route am2
        assert_eq!(
            safe_off_cut_for_platform("zynq-bm3-am2\n"),
            SafeOffCut::Am2PwrControl
        );
        assert_eq!(
            safe_off_cut_for_platform("amlogic-a113d"),
            SafeOffCut::AmlogicDisablePsu
        );
        assert_eq!(
            safe_off_cut_for_platform("am3-bb-s19jpro"),
            SafeOffCut::BeagleboneDisablePsu
        );
        assert_eq!(
            safe_off_cut_for_platform("cvitek-cv1835"),
            SafeOffCut::Unknown
        );
        // generic zynq (S9 / am1) only AFTER the am2 fingerprint check
        assert_eq!(
            safe_off_cut_for_platform("zynq-bm1-s9"),
            SafeOffCut::ZynqDisablePsu
        );
        assert_ne!(
            safe_off_cut_for_platform("zynq-bm3-am2"),
            SafeOffCut::ZynqDisablePsu
        );
        // unknown / empty → NOT cut (honest, never a false affordance)
        assert_eq!(safe_off_cut_for_platform(""), SafeOffCut::Unknown);
        assert_eq!(
            safe_off_cut_for_platform("future-board-x"),
            SafeOffCut::Unknown
        );
        // safe-off fan PWM is a quiet idle, never above the home safety cap
        assert!(super::SAFE_OFF_FAN_PWM <= dcentrald_hal::fan::PWM_SAFETY_MAX);
    }

    #[test]
    fn am2_fan_mode_requires_exact_s19_product_identity() {
        use super::am2_fan_mode_policy_for_board_target;
        use dcentrald_hal::fan::Am2FanModePolicy;

        for target in ["am2-s17", "am2-s17p", "am2-s17pro", "am2-s17plus", ""] {
            assert_eq!(
                am2_fan_mode_policy_for_board_target(target),
                Am2FanModePolicy::Preserve,
                "S17/ambiguous identity must not authorize C52: {target}"
            );
        }
        assert_eq!(
            am2_fan_mode_policy_for_board_target("unknown-am2"),
            Am2FanModePolicy::Preserve
        );
        assert_eq!(
            am2_fan_mode_policy_for_board_target("am2-s19pro"),
            Am2FanModePolicy::EnableC52
        );
        assert_eq!(
            am2_fan_mode_policy_for_board_target("am2-s19jpro-zynq\n"),
            Am2FanModePolicy::EnableC52
        );
    }

    /// Without `--allow-loud`, PWM is clamped to PWM_SAFETY_MAX (30) — only
    /// ever driven DOWN relative to the home cap, never above it.
    #[test]
    fn set_fan_clamps_to_safety_max_by_default() {
        assert_eq!(clamp_set_fan_pwm(10, false), 10);
        assert_eq!(clamp_set_fan_pwm(30, false), 30);
        assert_eq!(
            clamp_set_fan_pwm(31, false),
            30,
            "31 must clamp DOWN to PWM_SAFETY_MAX (30) without --allow-loud"
        );
        assert_eq!(clamp_set_fan_pwm(100, false), 30);
        assert_eq!(clamp_set_fan_pwm(255, false), 30);
        assert_eq!(
            clamp_set_fan_pwm(30, false),
            dcentrald_hal::fan::PWM_SAFETY_MAX
        );
    }

    /// `--allow-loud` is the ONLY sanctioned bypass (rust-firmware.md
    /// "explicit user override to a higher mode") — but still clamped to the
    /// IP ceiling PWM_MAX (100) since the fan_ctrl IP panics on > 100.
    #[test]
    fn set_fan_allow_loud_bypasses_safety_but_not_ip_max() {
        assert_eq!(clamp_set_fan_pwm(50, true), 50);
        assert_eq!(clamp_set_fan_pwm(80, true), 80);
        assert_eq!(clamp_set_fan_pwm(100, true), 100);
        assert_eq!(
            clamp_set_fan_pwm(255, true),
            dcentrald_hal::fan::PWM_MAX,
            "even --allow-loud must clamp to PWM_MAX (100) — the IP panics on >100"
        );
        // Low values are never raised by the carve-out.
        assert_eq!(clamp_set_fan_pwm(5, true), 5);
    }

    /// A missing PWM argument is a defined exit-code-2 failure.
    #[test]
    fn set_fan_missing_arg_exits_2() {
        assert_eq!(run_set_fan_oneshot(None, false), 2);
    }

    /// A non-numeric PWM argument is a defined exit-code-2 failure (parse
    /// rejected) — it must NOT touch any hardware.
    #[test]
    fn set_fan_non_numeric_arg_exits_2() {
        assert_eq!(run_set_fan_oneshot(Some("loud"), false), 2);
        assert_eq!(run_set_fan_oneshot(Some(""), false), 2);
        assert_eq!(run_set_fan_oneshot(Some("-5"), false), 2);
        assert_eq!(run_set_fan_oneshot(Some("3.5"), false), 2);
    }

    #[test]
    fn fan_sweep_parser_accepts_comma_list() {
        assert_eq!(
            parse_fan_sweep_list(Some("0, 5,10,30")).unwrap(),
            vec![0, 5, 10, 30]
        );
        assert!(parse_fan_sweep_list(None).is_err());
        assert!(parse_fan_sweep_list(Some("10,,30")).is_err());
        assert!(parse_fan_sweep_list(Some("10,loud")).is_err());
    }

    #[test]
    fn fan_raw_register_format_is_parseable_and_keeps_mirror_offsets() {
        let regs = [
            dcentrald_hal::fan::FanRawRegister {
                offset: 0x18,
                value: 0x0000_0010,
            },
            dcentrald_hal::fan::FanRawRegister {
                offset: 0x1C,
                value: 0x0000_0014,
            },
            dcentrald_hal::fan::FanRawRegister {
                offset: 0x20,
                value: 0x0000_0020,
            },
        ];
        assert_eq!(
            format_fan_raw_registers(&regs),
            "0x18:0x00000010,0x1C:0x00000014,0x20:0x00000020"
        );
    }

    #[test]
    fn get_fan_and_fan_sweep_enable_raw_dump_but_set_fan_does_not() {
        assert!(
            MAIN_RS.contains("print_fan_snapshot(\"--get-fan\", discovery, &fan, None, true)"),
            "--get-fan must print the bounded raw fan register dump"
        );
        assert!(
            MAIN_RS
                .contains("print_fan_snapshot(\"--fan-sweep\", discovery, &fan, Some(pwm), true)"),
            "--fan-sweep must print the bounded raw fan register dump"
        );
        assert!(
            MAIN_RS
                .contains("print_fan_snapshot(\"--set-fan\", discovery, &fan, Some(pwm), false)"),
            "--set-fan output should not grow the diagnostics-only raw dump"
        );
    }

    #[test]
    fn am2_low_pwm_floor_predicate_requires_am2_low_pwm_and_high_rpm() {
        assert!(am2_low_pwm_floor_present(
            dcentrald_hal::fan::FanVariant::Am2Uio16,
            10,
            2460
        ));
        assert!(!am2_low_pwm_floor_present(
            dcentrald_hal::fan::FanVariant::Am2Uio16,
            30,
            2460
        ));
        assert!(!am2_low_pwm_floor_present(
            dcentrald_hal::fan::FanVariant::Am1S9,
            10,
            2460
        ));
        assert!(!am2_low_pwm_floor_present(
            dcentrald_hal::fan::FanVariant::Am2Uio16,
            10,
            1260
        ));
    }

    /// R2 source invariant: the `--set-fan` early-exit is positioned BEFORE
    /// config load, logging init, and mode routing. Pin it by lexical order
    /// so a future edit can't accidentally move hardware/runtime work ahead
    /// of the fan-only one-shot (which must stay a tiny sync open→write→exit).
    #[test]
    fn set_fan_oneshot_precedes_config_and_mode_routing() {
        let set_fan = MAIN_RS
            .find("args.iter().position(|a| a == \"--set-fan\")")
            .expect("R2: --set-fan early-exit branch missing from run_main");
        let config_load = MAIN_RS
            .find("DcentraldConfig::load(&config_path)")
            .expect("config load site missing");
        let logging = MAIN_RS
            .find("init_logging(&config.general.log_level)")
            .expect("logging init site missing");
        assert!(
            set_fan < config_load,
            "R2: --set-fan one-shot must run BEFORE config load"
        );
        assert!(
            set_fan < logging,
            "R2: --set-fan one-shot must run BEFORE logging init"
        );
        // It must early-exit the process, never fall through into routing.
        let branch = &MAIN_RS[set_fan..config_load];
        assert!(
            branch.contains("std::process::exit(run_set_fan_oneshot("),
            "R2: the --set-fan branch must std::process::exit (early-exit, \
             never fall through to mode routing / hardware bring-up)"
        );
    }

    /// `--hold-fan` source invariant: the persistent fan-custodian early-exit
    /// is positioned BEFORE config load + logging init (same as `--set-fan`),
    /// must dispatch via `run_hold_fan` and `std::process::exit`, and must be
    /// awaited (it is async — it stays resident on the tokio runtime).
    #[test]
    fn hold_fan_oneshot_precedes_config_and_mode_routing() {
        let hold_fan = MAIN_RS
            .find("args.iter().position(|a| a == \"--hold-fan\")")
            .expect("--hold-fan early-exit branch missing from run_main");
        let config_load = MAIN_RS
            .find("DcentraldConfig::load(&config_path)")
            .expect("config load site missing");
        assert!(
            hold_fan < config_load,
            "--hold-fan custodian must run BEFORE config load / mode routing"
        );
        let branch = &MAIN_RS[hold_fan..config_load];
        assert!(
            branch.contains("std::process::exit(run_hold_fan("),
            "the --hold-fan branch must std::process::exit(run_hold_fan(..)) \
             (early-exit, never fall through to mode routing)"
        );
        assert!(
            branch.contains("run_hold_fan(pwm_arg, allow_loud).await"),
            "--hold-fan must be awaited (it is a resident async custodian on the \
             tokio runtime, not a sync one-shot)"
        );
    }

    /// `--hold-fan` honors the SAME clamp as `--set-fan`: PWM only ever driven
    /// DOWN (≤ PWM_SAFETY_MAX) unless explicit `--allow-loud`, and never above
    /// the IP ceiling PWM_MAX even with `--allow-loud`. (Both call
    /// `clamp_set_fan_pwm`, pinned here so a future divergence is caught.)
    #[test]
    fn hold_fan_uses_set_fan_clamp() {
        use super::clamp_set_fan_pwm;
        let safety = dcentrald_hal::fan::PWM_SAFETY_MAX;
        let max = dcentrald_hal::fan::PWM_MAX;
        // Without --allow-loud: clamped to the home cap.
        assert_eq!(clamp_set_fan_pwm(100, false), safety);
        assert_eq!(clamp_set_fan_pwm(10, false), 10.min(safety));
        // With --allow-loud: permitted above the cap, still ≤ IP ceiling.
        assert_eq!(clamp_set_fan_pwm(200, true), max);
        // Source pin: run_hold_fan routes through the same clamp helper.
        let body_start = MAIN_RS
            .find("async fn run_hold_fan(")
            .expect("run_hold_fan definition missing");
        let body = &MAIN_RS[body_start..];
        let end = first_function_end_offset(body);
        assert!(
            body[..end].contains("clamp_set_fan_pwm(requested, allow_loud)"),
            "--hold-fan must clamp via the shared clamp_set_fan_pwm (home cap \
             unless --allow-loud — never raise PWM above the cap)"
        );
    }

    /// `--hold-fan` is SIGTERM-responsive: its hold loop must race a SIGTERM
    /// (and SIGINT) future against the 5 s re-assert interval so the
    /// init-script `stop` path (kill by pidfile) is acted on immediately.
    #[test]
    fn hold_fan_is_sigterm_responsive() {
        let body_start = MAIN_RS
            .find("async fn run_hold_fan(")
            .expect("run_hold_fan definition missing");
        let body = &MAIN_RS[body_start..];
        assert!(
            body.contains("SignalKind::terminate()"),
            "--hold-fan must register a SIGTERM handler"
        );
        assert!(
            body.contains("signal::ctrl_c()"),
            "--hold-fan must also respond to SIGINT"
        );
        assert!(
            body.contains("Duration::from_secs(5)"),
            "--hold-fan must re-assert on a ~5 s interval (mmap-hold alone drifts)"
        );
    }

    /// R2 source invariant: the one-shot body touches the fan register ONLY
    /// — no PIC / PSU / I2C / voltage / ASIC / tokio-HW-runtime symbols.
    #[test]
    fn set_fan_oneshot_is_fan_register_only() {
        let start = MAIN_RS
            .find("fn run_set_fan_oneshot(")
            .expect("run_set_fan_oneshot definition missing");
        let body = &MAIN_RS[start..];
        let end = first_function_end_offset(body);
        let body = &body[..end];
        for forbidden in [
            "Pic0x89",
            "Apw121215",
            "PsuBypassGate",
            "I2cBus",
            "I2cService",
            "i2c-0",
            "set_voltage",
            "cold_boot",
            "tokio::runtime",
            "Runtime::new",
        ] {
            assert!(
                !body.contains(forbidden),
                "R2 SAFETY: the --set-fan one-shot must be fan-register-ONLY \
                 — found forbidden symbol `{forbidden}` in run_set_fan_oneshot"
            );
        }
        // It DOES use the proven uio-mmap FanController.
        assert!(
            body.contains("FanController::open_with_variant"),
            "R2: the one-shot must use the proven uio-mmap FanController"
        );
    }

    // ---------------------------------------------------------------
    // CLI info one-shots (`--help`/`-h`, `--version`/`-V`).
    //
    // Closes the defect where `dcentrald --help` had no handler and fell
    // through to the auto-`s19j-hybrid` daemon path (silently starting
    // the miner on a configured unit). Pure behavioral test + structural
    // ordering pin (same style as the R2 `--set-fan` pins above).
    // ---------------------------------------------------------------

    #[test]
    fn cli_info_classifier_help_version_precedence() {
        use super::{wants_cli_info, CliInfoRequest};
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        // Bare / mode / fan-one-shot flags → NOT an info request (the
        // daemon + fan one-shot paths must be entirely unchanged).
        assert_eq!(wants_cli_info(&s(&["dcentrald"])), None);
        assert_eq!(wants_cli_info(&s(&["dcentrald", "--s19j-hybrid"])), None);
        assert_eq!(wants_cli_info(&s(&["dcentrald", "--get-fan"])), None);
        assert_eq!(wants_cli_info(&s(&["dcentrald", "--set-fan", "10"])), None);

        // Help / version recognized (long + short).
        assert_eq!(
            wants_cli_info(&s(&["dcentrald", "--help"])),
            Some(CliInfoRequest::Help)
        );
        assert_eq!(
            wants_cli_info(&s(&["dcentrald", "-h"])),
            Some(CliInfoRequest::Help)
        );
        assert_eq!(
            wants_cli_info(&s(&["dcentrald", "--version"])),
            Some(CliInfoRequest::Version)
        );
        assert_eq!(
            wants_cli_info(&s(&["dcentrald", "-V"])),
            Some(CliInfoRequest::Version)
        );

        // Help wins over version, AND over any daemon/one-shot flag —
        // an operator asking for help must NEVER start the miner.
        assert_eq!(
            wants_cli_info(&s(&["dcentrald", "--version", "--help"])),
            Some(CliInfoRequest::Help)
        );
        assert_eq!(
            wants_cli_info(&s(&["dcentrald", "--s19j-hybrid", "--help"])),
            Some(CliInfoRequest::Help)
        );
        assert_eq!(
            wants_cli_info(&s(&["dcentrald", "--set-fan", "99", "--allow-loud", "-h"])),
            Some(CliInfoRequest::Help)
        );
    }

    /// HARD RULE: every DCENT_ open-source surface must point operators at
    /// https://d-central.tech/fund/ (Stripe + BTCPay). `dcentrald --help`
    /// is the CLI footer; do not drop the canonical URL from this string.
    #[test]
    fn cli_help_text_includes_canonical_fund_url() {
        let help = crate::cli_help_text();
        assert!(
            help.contains("https://d-central.tech/fund/"),
            "dcentrald --help must include the canonical Fund URL; got:\n{help}"
        );
        assert!(
            help.contains("Fund / Donate / Support"),
            "dcentrald --help footer must label the Fund/Donate/Support affordance; got:\n{help}"
        );
    }

    /// Structural pin: the `wants_cli_info` match must run BEFORE the
    /// `--set-fan` one-shot, config load, logging, AND mode routing, and
    /// must `std::process::exit(0)` — so `dcentrald --help` can never
    /// fall through to the daemon. (Mirrors the R2 `--set-fan` pins.)
    #[test]
    fn cli_info_oneshot_precedes_everything_in_run_main() {
        let info = MAIN_RS
            .find("match wants_cli_info(&args)")
            .expect("CLI info one-shot branch missing from run_main");
        let set_fan = MAIN_RS
            .find("args.iter().position(|a| a == \"--set-fan\")")
            .expect("--set-fan branch missing");
        let config_load = MAIN_RS
            .find("DcentraldConfig::load(&config_path)")
            .expect("config load site missing");
        let hybrid_route = MAIN_RS
            .find("let s19j_hybrid_cli = args.iter().any(|a| a == \"--s19j-hybrid\")")
            .expect("s19j-hybrid routing site missing");
        assert!(
            info < set_fan,
            "CLI info must be checked BEFORE the --set-fan one-shot"
        );
        assert!(info < config_load, "CLI info must run BEFORE config load");
        assert!(
            info < hybrid_route,
            "CLI info must run BEFORE any daemon/mode routing"
        );
        // It must early-exit, never fall through into the daemon path.
        let branch = &MAIN_RS[info..set_fan];
        assert!(
            branch.contains("std::process::exit(0)"),
            "the CLI info branch must std::process::exit(0) — `dcentrald \
             --help` must NEVER fall through to the mining daemon"
        );
    }

    #[test]
    fn unrecognized_cli_flags_behavioral() {
        use super::unrecognized_cli_flags;
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let empty: Vec<String> = vec![];

        // Bare / known boolean / mode combos → nothing unrecognized.
        assert_eq!(unrecognized_cli_flags(&s(&["dcentrald"])), empty);
        assert_eq!(
            unrecognized_cli_flags(&s(&["dcentrald", "--s19j-hybrid"])),
            empty
        );
        assert_eq!(
            unrecognized_cli_flags(&s(&["dcentrald", "--get-fan"])),
            empty
        );
        assert_eq!(
            unrecognized_cli_flags(&s(&["dcentrald", "--serial-mining", "--allow-loud"])),
            empty
        );

        // Value-bearing flags: the VALUE token must NOT be mis-flagged,
        // even when it could look flag-ish; `--get-fan` is boolean so it
        // does NOT swallow a following token.
        assert_eq!(
            unrecognized_cli_flags(&s(&["dcentrald", "--set-fan", "10"])),
            empty
        );
        assert_eq!(
            unrecognized_cli_flags(&s(&[
                "dcentrald",
                "--fan-sweep",
                "0,5,10,15",
                "--dwell-ms",
                "8000"
            ])),
            empty
        );
        assert_eq!(
            unrecognized_cli_flags(&s(&["dcentrald", "--config", "/data/dcentrald.toml"])),
            empty
        );

        // The dangerous typo case: an unrecognized `--flag` IS surfaced.
        assert_eq!(
            unrecognized_cli_flags(&s(&["dcentrald", "--gte-fan"])),
            s(&["--gte-fan"])
        );
        assert_eq!(
            unrecognized_cli_flags(&s(&["dcentrald", "--s19j-hybrid", "--totally-unknown"])),
            s(&["--totally-unknown"])
        );
        // A bare `-` (e.g. stdin sentinel) is NOT treated as a flag typo.
        assert_eq!(unrecognized_cli_flags(&s(&["dcentrald", "-"])), empty);
    }

    #[test]
    fn serial_allow_loud_is_explicitly_threaded_into_track1_owner() {
        let source = include_str!("main.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production main source");
        let authority = source
            .find("let explicit_loud_fan_authority = args.iter().any(|a| a == \"--allow-loud\");")
            .expect("explicit CLI loud-fan authority capture");
        let serial = source
            .find("let mut miner = match SerialMiner::new(")
            .expect("serial miner constructor");
        let constructor = &source[serial..];
        assert!(authority < serial);
        assert!(constructor.contains("explicit_loud_fan_authority,"));
        assert!(crate::cli_help_text().contains("S19k Track-1 PWM"));
        assert!(crate::cli_help_text().contains("https://d-central.tech/fund/"));
    }

    #[test]
    fn s19k_stock_handoff_cli_requires_one_complete_exact_tree() {
        use super::parse_s19k_stock_handoff_cli;
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        assert!(parse_s19k_stock_handoff_cli(&s(&["dcentrald"]))
            .unwrap()
            .is_none());
        let exact = s(&[
            "dcentrald",
            "--s19k-bos-tools-pid",
            "1458",
            "--s19k-bos-tools-start",
            "1251",
            "--s19k-bos-tools-ppid",
            "1",
            "--s19k-bos-tools-pgrp",
            "1457",
            "--s19k-bos-tools-session",
            "1457",
            "--s19k-bos-tools-exe",
            "/usr/bin/bos-tools",
            "--s19k-bos-tools-cmdline-sha256",
            "2e8273fd19bccb1b1744b2f26f48825aae6de73e55be9919a472d0a953cfac52",
            "--s19k-bos-tools-cmdline-bytes",
            "68",
            "--s19k-bosminer-pid",
            "9495",
            "--s19k-bosminer-start",
            "1044815",
            "--s19k-bosminer-ppid",
            "1458",
            "--s19k-bosminer-pgrp",
            "1457",
            "--s19k-bosminer-session",
            "1457",
            "--s19k-bosminer-exe",
            "/usr/bin/bosminer",
            "--s19k-bosminer-cmdline-sha256",
            "465804a74a48655761ec62edfd4e08659b6fcaf7486e475260c1e490f2e9d3d3",
            "--s19k-bosminer-cmdline-bytes",
            "32",
        ]);
        assert!(parse_s19k_stock_handoff_cli(&exact).unwrap().is_some());
        assert!(
            parse_s19k_stock_handoff_cli(&s(&["dcentrald", "--s19k-bosminer-pid", "9495",]))
                .is_err()
        );
        let mut duplicate = exact.clone();
        duplicate.extend(s(&["--s19k-bosminer-pid", "9496"]));
        assert!(parse_s19k_stock_handoff_cli(&duplicate).is_err());
        let mut invalid_parent = exact;
        let index = invalid_parent
            .iter()
            .position(|arg| arg == "--s19k-bosminer-ppid")
            .unwrap()
            + 1;
        invalid_parent[index] = "1".to_string();
        assert!(parse_s19k_stock_handoff_cli(&invalid_parent).is_err());
    }

    /// Drift guard: every `== "--…"` / `== "-x"` flag literal the parser
    /// matches in `run_main` MUST appear in the known-flag consts, so the
    /// warning allowlist can never silently diverge from the real parser
    /// (divergence ⇒ either spurious warnings on a real flag or a missed
    /// dangerous typo). Pairs with the behavioral test above.
    #[test]
    fn known_cli_flag_consts_cover_every_parser_literal() {
        use super::{KNOWN_CLI_BOOL_FLAGS, KNOWN_CLI_VALUE_FLAGS};
        // Scan only NON-test source (the test module legitimately
        // contains `== "--flag"` literals inside structural-pin
        // .find() strings, which would be false matches). Every
        // `== "-…"` flag comparison in real code must be in the
        // allowlist.
        let test_mod = MAIN_RS
            .find("\n#[cfg(test)]\nmod tests")
            .unwrap_or(MAIN_RS.len());
        let body = &MAIN_RS[..test_mod];
        // Scan per line, stripping any `//` line-comment first. Doc-comments in
        // non-test code legitimately contain illustrative literals like
        // `a == "--x"` (the unrecognized-flag detector's own typo example at the
        // `unrecognized_cli_flags` doc), which are prose, not real parser
        // comparisons — without this strip the scanner false-matches them.
        for raw_line in body.lines() {
            let line = match raw_line.find("//") {
                Some(c) => &raw_line[..c],
                None => raw_line,
            };
            let mut rest = line;
            while let Some(p) = rest.find("== \"-") {
                let after = &rest[p + 4..]; // past `== "`
                if let Some(end) = after.find('"') {
                    let lit = &after[..end];
                    if lit.starts_with('-') {
                        let known = KNOWN_CLI_BOOL_FLAGS.contains(&lit)
                            || KNOWN_CLI_VALUE_FLAGS.contains(&lit);
                        assert!(
                            known,
                            "parser matches flag `{lit}` but it is missing \
                             from KNOWN_CLI_BOOL_FLAGS/KNOWN_CLI_VALUE_FLAGS — \
                             the unknown-flag warning allowlist has drifted \
                             from the real parser"
                        );
                    }
                    rest = &after[end..];
                } else {
                    break;
                }
            }
        }
    }

    /// Structural pin: the unknown-flag handler MUST be a strict reject
    /// (Wave C, 2026-05-19) — `process::exit(2)` AFTER dumping
    /// `cli_help_text()`. A future regression that removes the strict
    /// reject (or reverts to a non-blocking warning) would silently
    /// daemonize on typo'd flags again (the 2026-05-19 `a lab unit` over-spawn
    /// pattern); this catches it.
    ///
    /// Inverted from the prior `unrecognized_flag_warning_is_non_blocking`
    /// pin in Wave C. Wave B closed G-T8-1 (the `--passthrough` corpus
    /// hazard); the 16-flag canonical allowlist is now exhaustive across
    /// every production launcher site, so strict-reject is safe to ship.
    #[test]
    fn strict_reject_unknown_flags_exits_2_with_usage() {
        let warn = MAIN_RS
            .find("let unknown_flags = unrecognized_cli_flags(&args);")
            .expect("unknown-flag detector site missing from run_main");
        let set_fan = MAIN_RS
            .find("args.iter().position(|a| a == \"--set-fan\")")
            .expect("--set-fan branch missing");
        assert!(
            warn < set_fan,
            "the unknown-flag check must run BEFORE the --set-fan one-shot \
             and daemon routing (so it can reject before the daemon starts)"
        );
        let block = &MAIN_RS[warn..set_fan];
        assert!(
            block.contains("process::exit(2)"),
            "REGRESSION: Wave C strict-reject was REMOVED — the unknown-flag \
             handler MUST `std::process::exit(2)` to prevent silent \
             daemonization on typo'd flags (the 2026-05-19 `a lab unit` over-spawn \
             pattern)."
        );
        assert!(
            block.contains("cli_help_text"),
            "REGRESSION: Wave C strict-reject MUST dump cli_help_text() \
             before exiting so operators see the full flag list inline \
             (don't make them re-run with --help to find the right flag). \
"
        );
    }
}
