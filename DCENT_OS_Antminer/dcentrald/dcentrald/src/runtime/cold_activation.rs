//! First-boot idle to mining activation without ending the supervisor session.
//!
//! The caller enters this branch before hardware construction. API hardware
//! mutation stays closed for this entire process lifetime. A Linux self-exec
//! retires its listeners, tasks and process globals while retaining PID and
//! start time; the fresh daemon performs normal route and hardware admission.

use std::ffi::OsString;
use std::time::Duration;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::config::DcentraldConfig;

/// Only this initial-idle owner can issue this move-only closeout. An absent
/// supervisor binding remains an error value and can never publish a receipt.
#[derive(Debug)]
pub(crate) struct ColdIdleCloseout {
    run: std::result::Result<
        dcentrald_common::mutation_disposition::SoftwareCloseoutRun,
        String,
    >,
}

impl ColdIdleCloseout {
    pub(crate) fn into_run(self) -> std::result::Result<
        dcentrald_common::mutation_disposition::SoftwareCloseoutRun,
        String,
    > {
        self.run
    }
}

async fn close_initial_idle(
    run: std::result::Result<
        dcentrald_common::mutation_disposition::SoftwareCloseoutRun,
        String,
    >,
    api: (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>),
    shutdown: &CancellationToken,
    deadline: tokio::time::Instant,
) -> Result<ColdIdleCloseout> {
    anyhow::ensure!(shutdown.is_cancelled(), "initial-idle closeout requires actual shutdown");
    // Both top-level listeners are retired before either join can consume the
    // shared deadline. Their permanently closed hardware gate never acquires
    // a mutation owner; the consumer additionally requires process death.
    api.0.abort();
    api.1.abort();
    for task in [api.0, api.1] {
        match tokio::time::timeout_at(deadline, task).await {
            Ok(Ok(())) => {},
            Ok(Err(error)) if error.is_cancelled() => {},
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => anyhow::bail!("initial-idle API retirement deadline expired"),
        }
    }
    Ok(ColdIdleCloseout { run })
}

pub(crate) fn eligible(
    target: &str,
    config: &DcentraldConfig,
    config_path: &str,
    native_route: bool,
    inherited_custody: bool,
    ephemeral: bool,
) -> bool {
    matches!(
        target,
        "am2-s17p"
            | "am2-s17plus"
            | "am2-t17"
            | "am2-t17plus"
            | "am2-t17e"
            | "am2-s17e"
            | "am2-s19pro"
            | "am1-s9i"
            | "am1-s9j"
            | "am1-s9se"
            | "am1-s9k"
            | "am1-s15"
            | "am1-t15"
            | "am3-s21"
            | "am3-s21pro"
            | "am3-s21xp"
            | "am3-s19xp"
            | "am3-s19jxp"
            | "am3-s19jproa"
            | "am3-s19jproplus"
            | "am3-s19jpro-aml"
    ) && !config.mining_start_enabled()
        && !config.mining.passthrough
        && matches!(config_path, "/data/dcentrald.toml" | "/etc/dcentrald.toml")
        && native_route
        && !inherited_custody
        && !ephemeral
}

fn activation_arguments(arguments: &[OsString]) -> Vec<OsString> {
    let mut result = Vec::with_capacity(arguments.len() + 2);
    let mut source = arguments.iter().skip(1);
    while let Some(argument) = source.next() {
        if argument == "--config" {
            let _ = source.next();
        } else {
            result.push(argument.clone());
        }
    }
    // REST persistence has one canonical destination, including when the
    // initial boot loaded the immutable /etc default.
    result.push("--config".into());
    result.push("/data/dcentrald.toml".into());
    result
}

#[cfg(target_os = "linux")]
fn replace_current_process(arguments: &[OsString]) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    // /proc/self/exe pins the running inode even if an update replaced its
    // pathname. No shell, subprocess, supervisor restart, or exit is involved.
    std::process::Command::new("/proc/self/exe")
        .args(arguments)
        .exec()
}

#[cfg(not(target_os = "linux"))]
fn replace_current_process(_arguments: &[OsString]) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "cold activation requires Linux",
    )
}

pub(crate) async fn run(
    config: DcentraldConfig,
    board_target: &str,
    shutdown: CancellationToken,
) -> Result<ColdIdleCloseout> {
    let software_closeout_run =
        dcentrald_common::mutation_disposition::capture_software_closeout_run(board_target);
    let wake = dcentrald_api::cold_activation::install_initial_idle_activation()
        .map_err(anyhow::Error::msg)?;
    let api = super::api::spawn_initial_idle_api(config, board_target, shutdown.clone()).await?;
    let arguments = activation_arguments(&std::env::args_os().collect::<Vec<_>>());
    let mut poll = tokio::time::interval(Duration::from_secs(1));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ready_since = None;
    tracing::info!("Initial idle: save a pool and enable mining to start from the dashboard");
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return close_initial_idle(
                software_closeout_run, api, &shutdown,
                tokio::time::Instant::now() + Duration::from_secs(2),
            ).await,
            _ = wake.notified() => {},
            _ = poll.tick() => {},
        }
        let ready = DcentraldConfig::load("/data/dcentrald.toml")
            .map(|updated| updated.mining_start_enabled() && !updated.mining.passthrough)
            .unwrap_or(false);
        if !ready {
            ready_since = None;
            continue;
        }
        let since = ready_since.get_or_insert_with(tokio::time::Instant::now);
        if since.elapsed() < Duration::from_secs(1) {
            continue;
        }
        // Finish the API response and serialize against every REST config
        // writer before the last bounded/no-follow validation and exec.
        let _write_guard = dcentrald_api::atomic_io::config_write_lock();
        if shutdown.is_cancelled() {
            drop(_write_guard);
            return close_initial_idle(
                software_closeout_run, api, &shutdown,
                tokio::time::Instant::now() + Duration::from_secs(2),
            ).await;
        }
        let still_ready = DcentraldConfig::load("/data/dcentrald.toml")
            .map(|updated| updated.mining_start_enabled() && !updated.mining.passthrough)
            .unwrap_or(false);
        if !still_ready {
            ready_since = None;
            continue;
        }
        tracing::info!("Activating saved mining configuration; retaining the daemon PID");
        let error = replace_current_process(&arguments);
        // exec returns only on failure. Retain the API and closed hardware
        // gate rather than terminating the supervisor's session.
        tracing::error!(%error, "Cold activation failed; initial idle API remains available");
        ready_since = Some(tokio::time::Instant::now() + Duration::from_secs(4));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unbound_run() -> std::result::Result<
        dcentrald_common::mutation_disposition::SoftwareCloseoutRun, String,
    > {
        Err("desk fixture has no supervised process identity".into())
    }

    #[tokio::test]
    async fn cancelled_initial_idle_observes_both_tasks_before_closeout() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let left = tokio::spawn(std::future::pending::<()>());
        let right = tokio::spawn(std::future::pending::<()>());
        let closeout = close_initial_idle(unbound_run(), (left, right), &shutdown,
            tokio::time::Instant::now() + Duration::from_secs(1)).await.unwrap();
        // Task completion cannot manufacture a missing supervisor context.
        assert!(closeout.into_run().is_err());
    }

    #[tokio::test]
    async fn idle_success_without_shutdown_has_no_closeout_authority() {
        let tasks = (tokio::spawn(async {}), tokio::spawn(async {}));
        assert!(close_initial_idle(unbound_run(), tasks, &CancellationToken::new(),
            tokio::time::Instant::now() + Duration::from_secs(1)).await.is_err());
    }

    #[tokio::test]
    async fn failed_idle_api_task_cannot_mint_closeout() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let failed = tokio::spawn(async { panic!("retirement fixture") });
        while !failed.is_finished() { tokio::task::yield_now().await; }
        assert!(close_initial_idle(unbound_run(), (failed, tokio::spawn(async {})), &shutdown,
            tokio::time::Instant::now() + Duration::from_secs(1)).await.is_err());
    }

    #[tokio::test]
    async fn pending_idle_api_task_cannot_mint_closeout() {
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let release = Arc::new(AtomicBool::new(false));
        let worker_release = release.clone();
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let stuck = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            while !worker_release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        started_rx.await.unwrap();
        let result = close_initial_idle(unbound_run(), (stuck, tokio::spawn(async {})), &shutdown,
            tokio::time::Instant::now() + Duration::from_millis(10)).await;
        release.store(true, Ordering::SeqCst);
        assert!(result.is_err());
    }

    #[test]
    fn cold_activation_arguments_preserve_engine_and_use_persisted_config() {
        let original = [
            "dcentrald",
            "--serial-mining",
            "--config",
            "/etc/dcentrald.toml",
        ]
        .map(OsString::from);
        assert_eq!(
            activation_arguments(&original),
            ["--serial-mining", "--config", "/data/dcentrald.toml"].map(OsString::from)
        );
    }

    #[test]
    fn cold_activation_is_exact_idle_native_and_without_inherited_custody() {
        let mut config = DcentraldConfig::management_only_default();
        config.mining.passthrough = false;
        for target in [
            "am2-s17p",
            "am2-s17plus",
            "am2-t17",
            "am2-t17plus",
            "am2-t17e",
            "am2-s17e",
            "am2-s19pro",
            "am1-s9i",
            "am1-s9j",
            "am3-s21",
            "am3-s21pro",
            "am3-s21xp",
            "am3-s19xp",
            "am3-s19jxp",
            "am3-s19jproa",
            "am3-s19jproplus",
            "am1-s9se",
            "am1-s9k",
        ] {
            assert!(eligible(
                target,
                &config,
                "/etc/dcentrald.toml",
                true,
                false,
                false
            ));
            assert!(!eligible(
                target,
                &config,
                "/etc/dcentrald.toml",
                false,
                false,
                false
            ));
            assert!(!eligible(
                target,
                &config,
                "/etc/dcentrald.toml",
                true,
                true,
                false
            ));
            assert!(!eligible(
                target,
                &config,
                "/etc/dcentrald.toml",
                true,
                false,
                true
            ));
            assert!(!eligible(
                target,
                &config,
                "/tmp/dcentrald.toml",
                true,
                false,
                false
            ));
        }
        for target in ["am3-s19k", "am2-s19jpro", "am2-s19", "am2-s17p-extra", "am2-s17e-extra", "am2-s17", "am2-t17e-extra", ""] {
            assert!(!eligible(
                target,
                &config,
                "/etc/dcentrald.toml",
                true,
                false,
                false
            ));
        }
        config.mining.passthrough = true;
        assert!(!eligible(
            "am2-s19pro",
            &config,
            "/etc/dcentrald.toml",
            true,
            false,
            false
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cold_activation_linux_exec_preserves_pid_and_closes_listener() {
        const TEST: &str = "runtime::cold_activation::tests::cold_activation_linux_exec_preserves_pid_and_closes_listener";
        match std::env::var("DCENT_COLD_EXEC_TEST_STAGE").as_deref() {
            Ok("second") => {
                assert_eq!(
                    std::env::var("DCENT_COLD_EXEC_TEST_PID").unwrap(),
                    std::process::id().to_string()
                );
                let address = std::env::var("DCENT_COLD_EXEC_TEST_ADDRESS").unwrap();
                let _listener =
                    std::net::TcpListener::bind(address).expect("old API socket closed by exec");
            }
            Ok("first") => {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                std::env::set_var(
                    "DCENT_COLD_EXEC_TEST_ADDRESS",
                    listener.local_addr().unwrap().to_string(),
                );
                std::env::set_var("DCENT_COLD_EXEC_TEST_PID", std::process::id().to_string());
                std::env::set_var("DCENT_COLD_EXEC_TEST_STAGE", "second");
                let error = replace_current_process(&[
                    OsString::from("--exact"),
                    TEST.into(),
                    "--nocapture".into(),
                ]);
                panic!("exec failed: {error}");
            }
            _ => {
                assert!(std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .env("DCENT_COLD_EXEC_TEST_STAGE", "first")
                    .status()
                    .unwrap()
                    .success());
            }
        }
    }
}
