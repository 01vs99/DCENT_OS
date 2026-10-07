//! Default API-server bring-up shared by every non-`Daemon` mining mode.
//!
//! Originally lived in `main.rs::spawn_proxy_mode_api` (W2.1). Hoisted here
//! so the [`crate::runtime::MiningRuntime`] trait can reference it from a
//! default method, closing .
//!
//! The function constructs a minimal `AppState` (per
//! `dcentrald_api::build_minimal_app_state`) and spawns the CGMiner TCP
//! server on `:4028` plus the HTTP/REST/WebSocket server on `:8080`. It is
//! safe to call from any mode that doesn't already construct its own
//! `AppState` from live telemetry channels.

use anyhow::Result;
use tracing::{error, info, warn};

use dcentrald_hal::platform::HardwareMutationGate;

use crate::config::DcentraldConfig;

/// Route-admitted API identity. Construction belongs to the hardware route;
/// the API cannot mint this from a presentation string or mutable config.
#[derive(Debug, Clone)]
pub(crate) struct AdmittedApiHardwareIdentity {
    pub control_board_label: String,
    pub chip_type_label: String,
    pub identification: dcentrald_api::HardwareIdentification,
}

/// Build a minimal AppState and spawn the dashboard / CGMiner API servers.
///
/// Used by `--stratum-proxy`, `--s19j-hybrid`, `--tap-mode`,
/// `--serial-mining` (idle path), and `--stock-fpga`. All of these own
/// their hardware state outside of `Daemon::run()`, but the dashboard and
/// `pyasic`-style monitoring still need to bind `:8080` + `:4028`. Returns
/// the CGMiner + HTTP `JoinHandle`s so the caller can explicitly own their
/// lifetime. Dropping a Tokio handle detaches its still-running task.
///
/// Errors are fatal — the dashboard not coming up is a deploy-rollback
/// condition for proxy / hybrid mode, since the operator's only
/// indication that the daemon is alive is the API.
pub async fn spawn_proxy_mode_api(
    config: DcentraldConfig,
    runtime_mode: dcentrald_api::RuntimeHealthMode,
    runtime_health_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::RuntimeHealthSnapshot>>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    spawn_proxy_mode_api_with_state(config, runtime_mode, runtime_health_rx, None, shutdown).await
}

/// Variant of [`spawn_proxy_mode_api`] that shares mutation admission with a
/// hardware-owning mining runtime.
///
/// The supplied gate is installed into the API's [`dcentrald_api::AppState`]
/// by identity. This lets the mining owner close and drain API hardware calls
/// before safe-off. The legacy wrapper remains open-by-default for modes that
/// do not supply an ownership domain.
pub async fn spawn_proxy_mode_api_with_hardware_mutation_gate(
    config: DcentraldConfig,
    runtime_mode: dcentrald_api::RuntimeHealthMode,
    runtime_health_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::RuntimeHealthSnapshot>>,
    hardware_mutation_gate: HardwareMutationGate,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
        config,
        runtime_mode,
        runtime_health_rx,
        None,
        hardware_mutation_gate,
        shutdown,
    )
    .await
}

/// Variant of [`spawn_proxy_mode_api`] that also accepts a live `MinerState`
/// receiver published by the mining mode itself.
///
/// When `external_state_rx` is `Some`, the dashboard / CGMiner API serve that
/// receiver, so `/api/status` reflects real hashrate, per-chain
/// (per-dsPIC) `ChainState`, and accepted/rejected shares. This is what the
/// `--s19j-hybrid` standalone path uses so its dashboard is no longer blank.
/// When `None`, behaviour is identical to the original
/// `spawn_proxy_mode_api` (static default-empty `MinerState`).
///
/// Purely additive + fail-closed: a missing/empty receiver only makes the
/// dashboard show zeros — it never blocks API bring-up or mining.
pub async fn spawn_proxy_mode_api_with_state(
    config: DcentraldConfig,
    runtime_mode: dcentrald_api::RuntimeHealthMode,
    runtime_health_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::RuntimeHealthSnapshot>>,
    external_state_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::MinerState>>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
        config,
        runtime_mode,
        runtime_health_rx,
        external_state_rx,
        HardwareMutationGate::new_open(),
        shutdown,
    )
    .await
}

/// Fully owned proxy-mode API variant with live state and shared mutation
/// admission supplied by the mining runtime.
pub async fn spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
    config: DcentraldConfig,
    runtime_mode: dcentrald_api::RuntimeHealthMode,
    runtime_health_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::RuntimeHealthSnapshot>>,
    external_state_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::MinerState>>,
    hardware_mutation_gate: HardwareMutationGate,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    spawn_proxy_mode_api_with_identity(
        config,
        runtime_mode,
        runtime_health_rx,
        external_state_rx,
        hardware_mutation_gate,
        false,
        None,
        shutdown,
    )
    .await
}

/// Fully owned proxy-mode API with an explicit, route-admitted control-board
/// identity. Standalone hardware runtimes use this when `RuntimeHealthMode`
/// alone is too coarse to identify the SoC (for example AM3-BB is Native but
/// physically AM335x, not Zynq).
pub async fn spawn_proxy_mode_api_with_state_gate_and_identity(
    config: DcentraldConfig,
    runtime_mode: dcentrald_api::RuntimeHealthMode,
    runtime_health_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::RuntimeHealthSnapshot>>,
    external_state_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::MinerState>>,
    hardware_mutation_gate: HardwareMutationGate,
    identity: AdmittedApiHardwareIdentity,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    spawn_proxy_mode_api_with_identity(
        config,
        runtime_mode,
        runtime_health_rx,
        external_state_rx,
        hardware_mutation_gate,
        true,
        Some(identity),
        shutdown,
    )
    .await
}

/// Observation-only API without asserted hardware identity. Used when an AM3
/// CLI request is disabled or exact route admission fails: management remains
/// reachable, but neither persistent API mutation nor a fabricated board label
/// is allowed.
pub async fn spawn_observer_only_api_with_state_and_hardware_mutation_gate(
    config: DcentraldConfig,
    runtime_mode: dcentrald_api::RuntimeHealthMode,
    runtime_health_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::RuntimeHealthSnapshot>>,
    external_state_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::MinerState>>,
    hardware_mutation_gate: HardwareMutationGate,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    spawn_proxy_mode_api_with_identity(
        config,
        runtime_mode,
        runtime_health_rx,
        external_state_rx,
        hardware_mutation_gate,
        true,
        None,
        shutdown,
    )
    .await
}

fn fallback_hardware_labels(
    observer_only: bool,
    runtime_mode: dcentrald_api::RuntimeHealthMode,
    serial_chip_type: Option<&str>,
    configured_model: Option<&str>,
) -> (String, String) {
    if observer_only {
        return ("Unknown".to_string(), "Unknown".to_string());
    }
    (
        format!("DCENT_OS ({} mode)", runtime_mode.as_str()),
        serial_chip_type
            .or(configured_model)
            .unwrap_or("Proxied")
            .to_string(),
    )
}

/// Initial idle API with the immutable image's declared target. This is
/// configuration identity only: no ASIC, rail, or topology was measured.
pub(crate) async fn spawn_initial_idle_api(
    config: DcentraldConfig,
    board_target: &str,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    let chip = match board_target {
        "am2-s17p" | "am2-s17plus" | "am2-t17" | "am2-t17plus" => "BM1397",
        "am2-t17e" | "am2-s17e" => "BM1396",
        "am2-s19pro" => "BM1398",
        "am1-s9i" | "am1-s9j" => "BM1387",
        "am1-s9se" | "am1-s9k" => "BM1393",
        "am3-s21" => "BM1368",
        "am3-s21pro" | "am3-s21xp" => "BM1370",
        "am3-s19xp" | "am3-s19jxp" => "BM1366",
        "am3-s19jproa" | "am3-s19jproplus" => "BM1362",
        _ => anyhow::bail!("no initial idle API composition for {board_target}"),
    };
    let identity = AdmittedApiHardwareIdentity {
        control_board_label: format!("{board_target} (image declaration)"),
        chip_type_label: chip.to_string(),
        identification: dcentrald_api::HardwareIdentification::from_evidence(
            vec![
                dcentrald_api::HardwareIdentityEvidence::declared_asic_board_target(
                    board_target,
                    chip,
                ),
            ],
            Some("Initial idle image declaration; ASIC detection has not run".to_string()),
        ),
    };
    spawn_proxy_mode_api_with_identity(
        config,
        dcentrald_api::RuntimeHealthMode::Native,
        None,
        None,
        HardwareMutationGate::new_closed(),
        false,
        Some(identity),
        shutdown,
    )
    .await
}

async fn spawn_proxy_mode_api_with_identity(
    config: DcentraldConfig,
    runtime_mode: dcentrald_api::RuntimeHealthMode,
    runtime_health_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::RuntimeHealthSnapshot>>,
    external_state_rx: Option<tokio::sync::watch::Receiver<dcentrald_api::MinerState>>,
    hardware_mutation_gate: HardwareMutationGate,
    observer_only: bool,
    admitted_identity: Option<AdmittedApiHardwareIdentity>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    let api_config = dcentrald_api::ApiConfig {
        cgminer_port: config.api.cgminer_port,
        http_port: config.api.http_port,
        http_bind: config.api.http_bind.clone(),
        websocket_enabled: config.api.websocket,
        websocket_tickets: config.api.websocket_tickets,
        cgminer_bind_lan: config.api.cgminer_bind_lan,
        cgminer_lan_writes: config.api.cgminer_lan_writes,
        metrics_require_auth: config.api.metrics_require_auth,
        // W13.D1: dev-mode boot-timeline gate. See ApiConfig docs.
        expose_boot_timeline: config.api.expose_boot_timeline,
        observer_only,
    };
    let mode = dcentrald_api::OperatingMode::from_config_str(&config.mode.active);
    let firmware_version = std::fs::read_to_string("/etc/dcentos-version")
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
        .trim()
        .to_string();
    let pool_protocol = config
        .pool
        .protocol
        .clone()
        .unwrap_or_else(|| "sv1".to_string());
    let fallback_labels = fallback_hardware_labels(
        observer_only,
        runtime_mode,
        config.mining.serial_chip_type.as_deref(),
        config.mining.model.as_deref(),
    );
    let inputs = dcentrald_api::MinimalAppStateInputs {
        api_config,
        pool_url: config.pool.url.clone(),
        pool_protocol,
        mode,
        firmware_version,
        // Minimal/proxy API state has no live fan command proof. Seed unknown
        // as 0 so the dashboard does not infer quiet from PWM without tach.
        fan_pwm: 0,
        network_block: config.network_block.clone(),
        profile_path: config.autotuner.profile_path.clone(),
        control_board_label: admitted_identity
            .as_ref()
            .map(|identity| identity.control_board_label.clone())
            .unwrap_or_else(|| fallback_labels.0.clone()),
        chip_type_label: admitted_identity
            .as_ref()
            .map(|identity| identity.chip_type_label.clone())
            .unwrap_or_else(|| fallback_labels.1.clone()),
        external_state_rx,
    };
    if let Some(rx) = runtime_health_rx {
        if !dcentrald_api::install_runtime_health_rx(rx) {
            warn!(
                mode = runtime_mode.as_str(),
                "runtime health channel already installed; keeping existing publisher"
            );
        }
    }
    let app_state = dcentrald_api::build_minimal_app_state_with_hardware_mutation_gate(
        inputs,
        hardware_mutation_gate,
    );
    if let Some(identity) = admitted_identity {
        let mut hardware = app_state
            .hardware_info
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        hardware.identification = identity.identification;
    }

    // P1-4 (Omega): bring up the shared notification stack (MQTT publisher +
    // event-bus webhook dispatcher + mining-sync bridge) for EVERY non-`Daemon`
    // mining mode that routes through here (--s19j-hybrid, --stratum-proxy,
    // --am3-bb-mining, serial/stock idle). Before P1-4 these modes got NEITHER
    // MQTT nor webhooks — only the S9 `Daemon` path did. Default-OFF: nothing
    // fires until `[mqtt]` / `[webhook]` are enabled in config. The dispatcher +
    // bridge subscribe to the same `mining_sync_tx` event bus the dashboard
    // WebSocket uses. `reload_path = None`: transient /tmp bring-ups don't
    // live-reload; the stack still honors the initial config.
    {
        let mac = std::fs::read_to_string("/sys/class/net/eth0/address")
            .unwrap_or_else(|_| "00:00:00:00:00:00".to_string())
            .trim()
            .to_string();
        crate::runtime::notifications::spawn_notification_stack(
            crate::runtime::notifications::RuntimeNotificationConfig::from_config(&config),
            None,
            mac,
            config.general.hostname.clone(),
            app_state.stats_tx.clone(),
            app_state.mining_sync_tx.clone(),
            shutdown,
            // P2-7 (Omega): the proxy/hybrid AppState exposes the same clamped
            // fan setter + autotuner command channel, so HA command setpoints
            // route through the same caps here as on the S9 Daemon path.
            if observer_only {
                None
            } else {
                Some(dcentrald_api::rest::app_state_mqtt_command_sink(
                    app_state.clone(),
                ))
            },
        );
    }

    let cgminer_port = config.api.cgminer_port;
    let http_port = config.api.http_port;

    #[cfg(all(test, target_os = "linux"))]
    initial_idle_api_tests::observe_app_state(&app_state);

    match dcentrald_api::start_api_servers(app_state).await {
        Ok((cg, http)) => {
            info!(
                cgminer_port,
                http_port,
                mode = runtime_mode.as_str(),
                "API servers online (proxy/hybrid mode) — dashboard on :{}, CGMiner API on :{}",
                http_port,
                cgminer_port,
            );
            Ok((cg, http))
        }
        Err(e) => {
            error!(
                error = %e,
                mode = runtime_mode.as_str(),
                "Failed to start API servers in proxy/hybrid mode — dashboard will be unreachable"
            );
            Err(e.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fallback_hardware_labels;

    #[test]
    fn observer_fallback_never_asserts_configured_hardware_identity() {
        let labels = fallback_hardware_labels(
            true,
            dcentrald_api::RuntimeHealthMode::Native,
            Some("BM1362"),
            Some("S19j Pro"),
        );
        assert_eq!(labels, ("Unknown".to_string(), "Unknown".to_string()));

        let labels = fallback_hardware_labels(
            false,
            dcentrald_api::RuntimeHealthMode::Native,
            Some("BM1362"),
            Some("S19j Pro"),
        );
        assert_eq!(labels.1, "BM1362");
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "initial_idle_api_tests.rs"]
mod initial_idle_api_tests;
