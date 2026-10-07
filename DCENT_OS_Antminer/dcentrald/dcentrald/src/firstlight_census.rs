//! Restrictive first-light enumeration mode. It never grants hardware admission.
//!
//! Owners publish only after fresh GetAddress/address verification and return
//! through their ordinary checked teardown. The observation itself is not a
//! SafeOff receipt; the host must also verify the supervised software closeout.

use std::sync::OnceLock;

use anyhow::{ensure, Context, Result};
use serde::Serialize;

static REQUEST: OnceLock<Option<String>> = OnceLock::new();
static WORK_REQUEST: OnceLock<Option<(String, u64)>> = OnceLock::new();
static ADMITTED_TARGET: OnceLock<String> = OnceLock::new();
static DEADLINE: OnceLock<std::time::Instant> = OnceLock::new();
pub(crate) const MAX_CENSUS_SECONDS: u64 = 90;
const MAX_WORK_SECONDS: u64 = 300;

pub(crate) fn check_idle_config(path: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(metadata.is_file() && metadata.len() > 0 && metadata.len() <= 1024 * 1024,
        "idle config must be a bounded regular file");
    let raw = std::fs::read_to_string(path)?;
    ensure!(raw.len() <= 1024 * 1024, "idle config grew during read");
    let value: toml::Value = toml::from_str(&raw)?;
    ensure!(value.get("mining").and_then(|v| v.get("enabled")).and_then(toml::Value::as_bool) == Some(false),
        "idle restore requires explicit mining.enabled=false");
    let config = crate::config::DcentraldConfig::load(path)?;
    ensure!(!config.mining.enabled, "loaded config must remain idle");
    Ok(())
}

pub(crate) fn initialize(args: &[String]) -> Result<()> {
    let work = parse_work_request(args)?;
    let request = parse_request(args)?;
    ensure!(
        request.is_none() || work.is_none(),
        "firstlight phases are exclusive"
    );
    ensure!(
        WORK_REQUEST.set(work).is_ok(),
        "firstlight work already initialized"
    );
    ensure!(
        REQUEST.set(request).is_ok(),
        "firstlight mode was already initialized"
    );
    Ok(())
}

fn parse_work_request(args: &[String]) -> Result<Option<(String, u64)>> {
    if !args
        .iter()
        .any(|v| v == "--firstlight-work" || v == "--firstlight-seconds")
    {
        return Ok(None);
    }
    ensure!(
        args.len() == 7,
        "bounded work requires exactly three valued options"
    );
    let mut values = std::collections::BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        ensure!(
            matches!(
                pair[0].as_str(),
                "--firstlight-work" | "--firstlight-seconds" | "--config"
            ),
            "bounded work refuses alternate process options"
        );
        ensure!(
            values.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
            "duplicate bounded-work option"
        );
    }
    let token = *values
        .get("--firstlight-work")
        .context("work session missing")?;
    ensure!(
        token.len() == 32
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "work session must be 32 lowercase hex characters"
    );
    let seconds = values
        .get("--firstlight-seconds")
        .context("work bound missing")?
        .parse::<u64>()
        .context("invalid work bound")?;
    ensure!(
        (1..=MAX_WORK_SECONDS).contains(&seconds),
        "work bound must be 1..300 seconds"
    );
    ensure!(
        values
            .get("--config")
            .is_some_and(|value| value.starts_with('/')),
        "work requires an absolute explicit config"
    );
    Ok(Some((token.to_owned(), seconds)))
}

fn parse_request(args: &[String]) -> Result<Option<String>> {
    let indices: Vec<_> = args
        .iter()
        .enumerate()
        .filter_map(|(i, value)| (value == "--firstlight-census").then_some(i))
        .collect();
    ensure!(indices.len() <= 1, "duplicate firstlight census option");
    let Some(index) = indices.first() else {
        return Ok(None);
    };
    // Census is an exclusive process route. A diagnostic/maintenance flag
    // cannot execute before this request reaches signed route admission.
    let mut cursor = 1;
    while cursor < args.len() {
        ensure!(
            matches!(args[cursor].as_str(), "--firstlight-census" | "--config"),
            "firstlight census refuses every alternate process option"
        );
        ensure!(
            args.get(cursor + 1).is_some(),
            "census option value missing"
        );
        cursor += 2;
    }
    ensure!(
        args.iter()
            .filter(|value| value.as_str() == "--config")
            .count()
            == 1,
        "firstlight census requires one explicit config path"
    );
    let token = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("firstlight census session missing"))?;
    ensure!(
        token.len() == 32
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "firstlight census requires a 32-character lowercase hex session"
    );
    Ok(Some(token.clone()))
}

pub(crate) fn requested() -> bool {
    REQUEST.get().and_then(Option::as_ref).is_some()
}

pub(crate) fn operation_requested() -> bool {
    requested() || WORK_REQUEST.get().and_then(Option::as_ref).is_some()
}

pub(crate) fn work_requested() -> bool {
    WORK_REQUEST.get().and_then(Option::as_ref).is_some()
}

/// Network-only tasks owned by a bounded hybrid trial. Dropping after an
/// earlier owner failure requests cancellation; only retire() proves they
/// actually ended before a successful trial may be reported.
#[derive(Default)]
pub(crate) struct RetainedTrialTasks(Vec<tokio::task::JoinHandle<()>>);

impl RetainedTrialTasks {
    pub(crate) fn retain(&mut self, task: tokio::task::JoinHandle<()>) {
        self.0.push(task);
    }

    pub(crate) async fn retire(&mut self, budget: std::time::Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + budget;
        let mut failure = None;
        for mut task in self.0.drain(..) {
            match tokio::time::timeout_at(deadline, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failure = Some(format!("firstlight network task failed: {error}")),
                Err(_) => {
                    task.abort();
                    // Await actual cancellation, never treat abort() itself as
                    // a successful retirement receipt. The trial remains an
                    // error even if this defensive cleanup succeeds.
                    let _ = tokio::time::timeout(std::time::Duration::from_millis(100), task).await;
                    failure = Some("firstlight network task missed its retirement deadline".into());
                }
            }
        }
        match failure {
            Some(error) => anyhow::bail!(error),
            None => Ok(()),
        }
    }
}

impl Drop for RetainedTrialTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

pub(crate) fn initialization_deadline() -> Result<std::time::Instant> {
    DEADLINE
        .get()
        .copied()
        .context("firstlight absolute deadline was not installed")
}

pub(crate) fn initialization_remaining() -> Result<std::time::Duration> {
    let remaining = initialization_deadline()?.saturating_duration_since(std::time::Instant::now());
    ensure!(
        !remaining.is_zero(),
        "firstlight deadline expired before initialization"
    );
    Ok(remaining.min(std::time::Duration::from_secs(MAX_CENSUS_SECONDS)))
}

/// A diagnostic failure cannot cancel or short-circuit the real shutdown
/// future. Teardown failure has precedence over reporting failure.
pub(crate) async fn finish_observation_after_closeout<T, F>(
    observation: Result<()>,
    closeout: F,
) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    let receipt = closeout.await?;
    observation?;
    Ok(receipt)
}

/// The timer only requests cancellation. The awaited owner still executes its
/// full checked teardown; no timeout drops that future or its shutdown proof.
async fn run_bounded<F: std::future::Future<Output = Result<()>>>(
    deadline: std::time::Instant,
    shutdown: tokio_util::sync::CancellationToken,
    owner: F,
) -> Result<()> {
    struct Timer(Option<tokio::task::JoinHandle<()>>);
    impl Drop for Timer {
        fn drop(&mut self) {
            if let Some(task) = self.0.as_ref() {
                task.abort();
            }
        }
    }
    ensure!(
        !shutdown.is_cancelled() && std::time::Instant::now() < deadline,
        "firstlight cancelled before owner start"
    );
    let token = shutdown.clone();
    let mut timer = Timer(Some(tokio::spawn(async move {
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        token.cancel();
    })));
    let result = owner.await;
    let task = timer.0.take().expect("owned firstlight timer");
    task.abort();
    // Await task retirement even when the owner returned before its deadline.
    // Dropping the guard on any cancellation also aborts the timer task.
    let _ = task.await;
    result
}

/// Called once by dispatch after its signed image/exact route admission. This
/// only permits skipping a pool requirement; every hardware owner still admits
/// its ordinary composition and must stop before any work pipeline exists.
pub(crate) fn admit(target: &str, passthrough: bool) -> Result<()> {
    ensure!(
        operation_requested(),
        "census admission requires an explicit process request"
    );
    ensure!(
        !passthrough,
        "firstlight census requires a fresh cold hardware owner"
    );
    ensure!(
        supports(target),
        "this exact runtime has no firstlight census checkpoint"
    );
    ensure!(
        ADMITTED_TARGET.set(target.to_owned()).is_ok(),
        "census route was already sealed"
    );
    Ok(())
}

pub(crate) fn pool_free_start_is_admitted() -> bool {
    requested() && ADMITTED_TARGET.get().is_some()
}

/// Dedicated one-shot dispatch returns directly to process exit. It creates no
/// API/Stratum graph, and neither errors nor partial init can park in another
/// route with this process's pool-free admission.
pub(crate) async fn run(
    mut config: crate::config::DcentraldConfig,
    config_path: String,
    identity: crate::daemon_lifecycle::PlatformIdentitySnapshot,
    selected: crate::RuntimeDispatchKind,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<()> {
    ensure!(
        operation_requested(),
        "firstlight dispatch was not requested"
    );
    let target = identity.board_target().to_string();
    ensure!(
        supports(&target),
        "this exact runtime has no firstlight census checkpoint"
    );
    let expected = if target == "am2-s19j" {
        crate::RuntimeDispatchKind::S19jHybrid
    } else if target.starts_with("am1-") {
        crate::RuntimeDispatchKind::StandardDaemon
    } else {
        crate::RuntimeDispatchKind::S17Hybrid
    };
    ensure!(
        selected == expected,
        "census selected an unowned runtime route"
    );
    ensure!(
        !config_path.starts_with('<'),
        "census requires a successfully loaded explicit config"
    );
    // This existing pure predicate checks all primary/failover/SV2/donation/
    // disconnect/job-declaration routes and mining=false. It grants no S19k
    // custody; that target is absent from this checkpoint roster.
    if requested() {
        ensure!(
            config.s19k_install_custody_pool_free(),
            "census configuration must contain no pool or work routes"
        );
    } else {
        ensure!(
            !config.mining.enabled && config.has_configured_pool(),
            "bounded work requires a saved idle config with the tester's explicit pool"
        );
        let mut no_primary = config.clone();
        no_primary.pool.url.clear();
        no_primary.pool.worker.clear();
        no_primary.pool.password.clear();
        ensure!(
            no_primary.s19k_install_custody_pool_free(),
            "bounded work refuses donation, failover, SV2 and independent work routes"
        );
    }
    ensure!(
        !config.mining.passthrough && config.watchdog.enabled && config.thermal.fan_max_pwm <= 30,
        "firstlight requires a cold owner, enabled watchdog and the home fan ceiling"
    );
    let board = identity
        .board_desc
        .context("census requires an exact BoardDesc")?;
    let image = crate::runtime_image_admission::load(board, false)
        .await
        .map_err(anyhow::Error::msg)?;
    let profile = image.hardware_recipe();
    let configured =
        crate::configured_asic_protocol_identity(&config).map_err(anyhow::Error::msg)?;
    let declared =
        crate::admit_board_desc_runtime_dispatch(Some(board), selected, true, configured)
            .map_err(anyhow::Error::msg)?;
    let bound = crate::RuntimeDispatchAdmission::bind(declared, Some(image), false)
        .map_err(anyhow::Error::msg)?;
    let recipe = dcentrald_common::runtime_hardware_recipe::RuntimeHardwareRecipe::resolve(
        board,
        &identity.observed_control_board,
        selected.label(),
        profile,
    )
    .map_err(anyhow::Error::msg)?;
    dcentrald_common::runtime_hardware_recipe::install(recipe).map_err(anyhow::Error::msg)?;
    crate::adjudicate_mutation_disposition_before_runtime_arm_dispatch()?;
    admit(&target, config.mining.passthrough)?;
    let seconds = WORK_REQUEST
        .get()
        .and_then(Option::as_ref)
        .map(|(_, seconds)| *seconds)
        .unwrap_or(MAX_CENSUS_SECONDS);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    ensure!(
        DEADLINE.set(deadline).is_ok(),
        "firstlight deadline cannot be reset"
    );
    config.mining.enabled = true;
    let owner_shutdown = shutdown.clone();
    let result = run_bounded(deadline, shutdown, async move {
        if selected == crate::RuntimeDispatchKind::StandardDaemon {
            crate::daemon::Daemon::new(config, config_path, identity, owner_shutdown)
                .run()
                .await
        } else if selected == crate::RuntimeDispatchKind::S19jHybrid {
            let route = crate::s19j_hybrid_admission::admit_s19j_hybrid_route(
                &identity, selected, configured,
            ).map_err(anyhow::Error::msg)?;
            let safety = crate::s19j_hybrid_mining::S19jHybridSafetyAdmission::start(
                &config, bound, route,
            ).await?;
            crate::s19j_hybrid_mining::S19jHybridMiner::new(config, owner_shutdown, safety)?
                .run().await
        } else {
            let route = crate::s17_hybrid_admission::admit_s17_hybrid_route(
                &identity, selected, configured,
            )
            .map_err(anyhow::Error::msg)?;
            crate::s17_hybrid_mining::adjudicate_s17_energize_gate(true)?;
            let safety =
                crate::s17_hybrid_mining::S17HybridSafetyAdmission::start(&config, bound, route)
                    .await?;
            crate::s17_hybrid_mining::S17HybridMiner::new(config, owner_shutdown, safety)?
                .with_energize_opt_in(true)
                .run()
                .await
        }
    })
    .await;
    crate::daemon::persist_unresolved_mutation_dispositions(
        &crate::daemon::terminal_mutation_disposition_path(),
    );
    result
}

fn supports(target: &str) -> bool {
    matches!(
        target,
        "am1-s9" | "am1-s9i" | "am1-s9j" | "am2-s17p" | "am2-s17plus" | "am2-t17" | "am2-t17plus" | "am2-s19j"
    )
}

#[derive(Debug, Serialize)]
struct Chain {
    chain_id: u8,
    chip_id: u16,
    chips: u16,
}

fn observation(
    session: &str,
    target: &str,
    measured: &[(u8, u16, u16)],
) -> Result<serde_json::Value> {
    ensure!(supports(target), "unsupported census owner");
    ensure!(
        !measured.is_empty() && measured.len() <= 16,
        "no bounded measured census"
    );
    ensure!(
        target != "am2-s19j" || measured.len() == 1,
        "S19j firstlight observes only the retained primary chain"
    );
    let mut seen = std::collections::BTreeSet::new();
    let mut chains = Vec::new();
    for &(chain_id, chip_id, chips) in measured {
        ensure!(seen.insert(chain_id), "duplicate measured census chain");
        ensure!(
            chips > 0 && chips <= 256,
            "invalid measured census chip count"
        );
        let expected = if target == "am2-s19j" {
            0x1362
        } else if target.starts_with("am1-") {
            0x1387
        } else {
            0x1397
        };
        ensure!(
            chip_id == expected,
            "measured census ASIC differs from exact target"
        );
        chains.push(Chain {
            chain_id,
            chip_id,
            chips,
        });
    }
    Ok(
        serde_json::json!({"schema": "dcentos.firstlight-census.v1", "session": session,
        "board_target": target, "source": "fresh_get_address", "chains": chains,
        "pool_work_dispatched": false, "software_closeout": "pending", "physical_rail": "unmeasured"}),
    )
}

pub(crate) fn publish(target: &str, measured: &[(u8, u16, u16)]) -> Result<()> {
    ensure!(
        ADMITTED_TARGET.get().map(String::as_str) == Some(target),
        "census checkpoint differs from the admitted process route"
    );
    let session = REQUEST
        .get()
        .and_then(Option::as_ref)
        .ok_or_else(|| anyhow::anyhow!("census publication without an explicit request"))?;
    let report = observation(session, target, measured)?;
    tracing::info!(target: "firstlight", report = %report, "DCENT_FIRSTLIGHT_CENSUS");
    Ok(())
}

pub(crate) fn publish_work(
    target: &str,
    accepted: u64,
    rejected: u64,
    hashrate_ghs: f64,
    elapsed_seconds: u64,
    temperatures: &[f32],
    fan_pwm: u8,
) -> Result<()> {
    let Some((session, limit)) = WORK_REQUEST.get().and_then(Option::as_ref) else {
        return Ok(());
    };
    ensure!(
        ADMITTED_TARGET.get().map(String::as_str) == Some(target),
        "work observation differs from admitted process"
    );
    ensure!(
        hashrate_ghs.is_finite()
            && hashrate_ghs >= 0.0
            && !temperatures.is_empty()
            && temperatures.len() <= 16
            && temperatures.iter().all(|v| v.is_finite())
            && fan_pwm <= 30,
        "bounded work observation lacks finite owned telemetry"
    );
    let report = serde_json::json!({
        "schema": "dcentos.firstlight-work.v1", "session": session,
        "board_target": target, "accepted": accepted, "rejected": rejected,
        "hashrate_ghs": hashrate_ghs, "elapsed_seconds": elapsed_seconds,
        "maximum_owner_seconds": limit, "temperatures_c": temperatures,
        "fan_pwm": fan_pwm, "software_closeout": "pending",
        "physical_rail": "unmeasured"
    });
    tracing::info!(target: "firstlight", report = %report, "DCENT_FIRSTLIGHT_WORK");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn firstlight_retains_and_observes_actual_network_task_cancellation() {
        let stop = tokio_util::sync::CancellationToken::new();
        let task_stop = stop.clone();
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_finished = finished.clone();
        let mut tasks = RetainedTrialTasks::default();
        tasks.retain(tokio::spawn(async move {
            task_stop.cancelled().await;
            task_finished.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        stop.cancel();
        tasks.retire(std::time::Duration::from_secs(1)).await.unwrap();
        assert!(finished.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn firstlight_pending_or_failed_network_task_cannot_close_as_success() {
        let mut pending = RetainedTrialTasks::default();
        let (retired, observed) = tokio::sync::oneshot::channel();
        struct RetireOnDrop(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for RetireOnDrop {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }
        pending.retain(tokio::spawn(async move {
            let _retirement = RetireOnDrop(Some(retired));
            std::future::pending::<()>().await;
        }));
        tokio::task::yield_now().await;
        assert!(pending.retire(std::time::Duration::from_millis(5)).await.is_err());
        tokio::time::timeout(std::time::Duration::from_secs(1), observed)
            .await.unwrap().unwrap();
        let mut failed = RetainedTrialTasks::default();
        failed.retain(tokio::spawn(async { panic!("injected actual trial task failure") }));
        assert!(failed.retire(std::time::Duration::from_secs(1)).await.is_err());
    }

    #[test]
    fn firstlight_idle_restore_parser_requires_explicit_valid_disabled_config() {
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "dcent-firstlight-idle-{}-{}.toml", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        ));
        std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let _fixture = Fixture(path.clone());
        std::fs::write(&path, "[mining]\nenabled=false\n").unwrap();
        check_idle_config(path.to_str().unwrap()).unwrap();
        for raw in ["", "[mining]\nenabled=true\n", "[mining]\nenabled=0\n", "[mining]\n"] {
            std::fs::write(&path, raw).unwrap();
            assert!(check_idle_config(path.to_str().unwrap()).is_err());
        }
    }

    #[tokio::test]
    async fn firstlight_reporting_failure_always_awaits_closeout_and_preserves_safety_error() {
        for fail_closeout in [false, true] {
            let completed = std::sync::atomic::AtomicBool::new(false);
            let result =
                finish_observation_after_closeout(Err(anyhow::anyhow!("report failed")), async {
                    tokio::task::yield_now().await;
                    completed.store(true, std::sync::atomic::Ordering::SeqCst);
                    if fail_closeout {
                        anyhow::bail!("shutdown failed");
                    }
                    Ok(())
                })
                .await;
            assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
            assert_eq!(
                result.unwrap_err().to_string(),
                if fail_closeout {
                    "shutdown failed"
                } else {
                    "report failed"
                }
            );
        }
    }

    #[test]
    fn firstlight_work_bound_and_exclusive_options_are_checked() {
        let args = |seconds: &str| {
            vec![
                "dcentrald",
                "--firstlight-work",
                "0123456789abcdef0123456789abcdef",
                "--config",
                "/tmp/work.toml",
                "--firstlight-seconds",
                seconds,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
        };
        assert_eq!(parse_work_request(&args("300")).unwrap().unwrap().1, 300);
        for bad in ["0", "301", "-1", "infinite", "1.0"] {
            assert!(parse_work_request(&args(bad)).is_err());
        }
        for flag in [
            "--lab-runtime",
            "--serial-mining",
            "--firstlight-census",
            "--config",
        ] {
            let mut values = args("30");
            values[5] = flag.into();
            assert!(parse_work_request(&values).is_err());
        }
        assert!(parse_work_request(&[
            "dcentrald".into(),
            "--firstlight-seconds".into(),
            "1".into()
        ])
        .is_err());
    }

    #[tokio::test]
    async fn firstlight_deadline_cancels_work_but_awaits_checked_teardown() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let observer = shutdown.clone();
        let started = std::time::Instant::now();
        run_bounded(
            started + std::time::Duration::from_millis(10),
            shutdown,
            async move {
                observer.cancelled().await;
                // A pending closeout is still owned after the work deadline.
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                Ok(())
            },
        )
        .await
        .unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_millis(30));
    }

    #[tokio::test]
    async fn firstlight_early_failure_retires_timer_and_preserves_error() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let observer = shutdown.clone();
        assert!(run_bounded(
            std::time::Instant::now() + std::time::Duration::from_millis(10),
            shutdown,
            async { anyhow::bail!("owner refused") }
        )
        .await
        .is_err());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !observer.is_cancelled(),
            "retired owner must not leave a delayed timer task"
        );
        observer.cancel();
        let invoked = std::sync::atomic::AtomicBool::new(false);
        assert!(run_bounded(
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            observer,
            async {
                invoked.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        )
        .await
        .is_err());
        assert!(!invoked.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn census_request_is_explicit_unique_and_session_bound() {
        assert_eq!(parse_request(&[]).unwrap(), None);
        let token = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            parse_request(&[
                "dcentrald".into(),
                "--firstlight-census".into(),
                token.into(),
                "--config".into(),
                "/tmp/census.toml".into()
            ])
            .unwrap(),
            Some(token.into())
        );
        for args in [
            vec!["--firstlight-census"],
            vec!["--firstlight-census", "../bad"],
            vec!["--firstlight-census", token, "--firstlight-census", token],
            vec![
                "dcentrald",
                "--firstlight-census",
                token,
                "--config",
                "/tmp/census.toml",
                "--serial-mining",
            ],
            vec![
                "dcentrald",
                "--firstlight-census",
                token,
                "--config",
                "/tmp/census.toml",
                "--lab-runtime",
            ],
        ] {
            assert!(
                parse_request(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err()
            );
        }
    }

    #[test]
    fn census_counts_never_imply_safeoff_or_admit_wrong_sibling() {
        let value = observation("session", "am1-s9", &[(6, 0x1387, 63), (7, 0x1387, 63)]).unwrap();
        assert_eq!(value["software_closeout"], "pending");
        assert_eq!(value["chains"][1]["chips"], 63);
        assert!(observation("session", "am1-s9k", &[(6, 0x1387, 63)]).is_err());
        for rows in [
            vec![],
            vec![(6, 0x1387, 0)],
            vec![(6, 0x1397, 63)],
            vec![(6, 0x1387, 63), (6, 0x1387, 63)],
        ] {
            assert!(observation("session", "am1-s9", &rows).is_err());
        }
    }

    #[test]
    fn firstlight_s19j_observation_requires_exact_bm1362_primary_chain() {
        let value = observation("session", "am2-s19j", &[(1, 0x1362, 126)]).unwrap();
        assert_eq!(value["chains"].as_array().unwrap().len(), 1);
        assert_eq!(value["physical_rail"], "unmeasured");
        assert_eq!(value["software_closeout"], "pending");
        assert_eq!(value["pool_work_dispatched"], false);
        for measured in [vec![], vec![(1, 0x1398, 126)], vec![(1, 0x1362, 0)],
                         vec![(1, 0x1362, 126), (2, 0x1362, 126)]] {
            assert!(observation("session", "am2-s19j", &measured).is_err());
        }
        for sibling in ["am2-s19jpro", "am2-s19pro", "am2-t17e"] {
            assert!(observation("session", sibling, &[(1, 0x1362, 126)]).is_err());
        }
    }

    #[tokio::test]
    async fn firstlight_deadline_stops_actual_tasks_and_keeps_late_teardown_owned() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        let work_ticks = Arc::new(AtomicUsize::new(0));
        let shutdown = tokio_util::sync::CancellationToken::new();
        let worker_stop = shutdown.clone();
        let owner_stop = shutdown.clone();
        let worker_ticks = work_ticks.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let mut tasks = RetainedTrialTasks::default();
        tasks.retain(tokio::spawn(async move {
            worker_ticks.fetch_add(1, Ordering::SeqCst);
            let _ = started.send(());
            loop {
                tokio::select! {
                    biased;
                    _ = worker_stop.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(1)) => {
                        worker_ticks.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }));
        ready.await.unwrap();
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let owner_closed = closed.clone();
        run_bounded(std::time::Instant::now() + std::time::Duration::from_millis(10), shutdown, async move {
            owner_stop.cancelled().await;
            tasks.retire(std::time::Duration::from_secs(1)).await?;
            // A deliberately late reporting failure still awaits shutdown.
            finish_observation_after_closeout(Err(anyhow::anyhow!("report failed")), async move {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                owner_closed.store(true, Ordering::SeqCst);
                Ok(())
            }).await
        }).await.unwrap_err();
        assert!(closed.load(Ordering::SeqCst));
        let final_count = work_ticks.load(Ordering::SeqCst);
        assert!(final_count > 0);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(work_ticks.load(Ordering::SeqCst), final_count);
    }
}
