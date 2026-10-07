//! Host-only observations of the actual idle API composition. The task-local
//! observer copies its AppState; it cannot supply identity, gates, or receipts.

use std::cell::RefCell;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dcentrald_api::{AppState, HardwareIdentityEvidenceLevel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::spawn_initial_idle_api;
use crate::config::DcentraldConfig;

tokio::task_local! {
    static OBSERVER: RefCell<Option<oneshot::Sender<Arc<AppState>>>>;
}

pub(super) fn observe_app_state(state: &Arc<AppState>) {
    let _ = OBSERVER.try_with(|observer| {
        if let Some(sender) = observer.borrow_mut().take() {
            let _ = sender.send(state.clone());
        }
    });
}

fn isolated_child(name: &str) -> bool {
    let exact = format!("runtime::api::initial_idle_api_tests::{name}");
    if std::env::var("DCENT_T17E_IDLE_API_TEST_CHILD").as_deref() == Ok(name) {
        // No canonical config/auth mutation, target device, or release-image
        // auth initialization is appropriate in this host fixture.
        for path in [
            "/data/dcentrald.toml",
            "/etc/dcentrald.toml",
            "/data/dcent/auth.json",
            "/etc/dcentos/release-image",
            "/dev/mem",
            "/dev/uio0",
            "/dev/i2c-0",
        ] {
            assert!(!Path::new(path).exists(), "host fixture refuses {path}");
        }
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact, "--nocapture"])
        .env("DCENT_T17E_IDLE_API_TEST_CHILD", name)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated child {exact}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout).replace('\n', "\n| "),
        String::from_utf8_lossy(&output.stderr).replace('\n', "\n| ")
    );
    false
}

fn idle_config(target: Option<&str>) -> (DcentraldConfig, [TcpListener; 2]) {
    let held = [
        TcpListener::bind(("127.0.0.1", 0)).unwrap(),
        TcpListener::bind(("127.0.0.1", 0)).unwrap(),
    ];
    let mut config = match target {
        Some("am2-s17e") => toml::from_str(include_str!(
            "../../../configs/beta/am2-s17e-baked-default.toml"
        )).unwrap(),
        Some("am2-t17e") => toml::from_str(include_str!(
            "../../../configs/beta/am2-t17e-baked-default.toml"
        )).unwrap(),
        None => DcentraldConfig::management_only_default(),
        Some(other) => panic!("unknown native idle fixture {other}"),
    };
    config.mining.passthrough = false;
    config.api.http_bind = "127.0.0.1".into();
    config.api.http_port = held[0].local_addr().unwrap().port();
    config.api.cgminer_port = held[1].local_addr().unwrap().port();
    config.api.cgminer_bind_lan = false;
    config.api.cgminer_lan_writes = false;
    assert!(!config.mining_start_enabled());
    (config, held)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn assert_declared_closed(state: &AppState, target: &str) {
    assert!(state.hardware_mutation_gate.try_acquire().is_err());
    let hardware = state.hardware_info.lock().unwrap();
    assert_eq!(hardware.control_board, format!("{target} (image declaration)"));
    assert_eq!(hardware.chip_type, "BM1396");
    let identity = &hardware.identification;
    assert_eq!(identity.declared_board_target(), Some(target));
    assert_eq!(identity.evidence.len(), 1);
    assert_eq!(
        identity.evidence[0].level(),
        HardwareIdentityEvidenceLevel::Declared
    );
    assert_eq!(identity.evidence[0].source_value, target);
    assert_eq!(identity.evidence[0].resolved_value, "BM1396");
    assert!(identity.evidence[0].composition.is_none());
    assert!(identity
        .note
        .as_deref()
        .unwrap()
        .contains("ASIC detection has not run"));
    drop(hardware);
    let miner = state.state_rx.borrow();
    assert!(miner.chains.is_empty());
    assert_eq!(miner.hashrate_ghs, 0.0);
    assert_eq!(miner.accepted, 0);
    assert_eq!(miner.fans.pwm, 0);
    drop(miner);
    // This is the real internal control entry, independent of HTTP auth.
    // Its capability refusal and the actual gate refusal are distinct checks.
    let error = dcentrald_api::rest::grpc_bridge_set_fan(state, 30).unwrap_err();
    assert!(error.contains("capability"), "{error}");
}

async fn loopback_readback(http_port: u16, cgminer_port: u16, target: &str) {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let info = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match client
                .get(format!("http://127.0.0.1:{http_port}/api/system/info"))
                .send()
                .await
            {
                Ok(response) => {
                    break response
                        .error_for_status()
                        .unwrap()
                        .json::<serde_json::Value>()
                        .await
                        .unwrap()
                }
                Err(error) if error.is_connect() => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(error) => panic!("idle API response failed: {error}"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(info["board_target"], target);
    assert_eq!(info["chip_type"], "BM1396");
    assert_eq!(info["identification_confidence"], "low");
    assert_eq!(info["chip_count"], 0);
    assert_eq!(info["chain_count"], 0);
    assert_eq!(info["hashrate_ghs"], 0.0);
    assert_eq!(info["live_power_available"], false);
    let mut cg = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(stream) = tokio::net::TcpStream::connect(("127.0.0.1", cgminer_port)).await {
                break stream;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    cg.write_all(b"{\"command\":\"summary\"}\n").await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), cg.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["SUMMARY"][0]["Accepted"], 0);
    assert_eq!(body["SUMMARY"][0]["MHS av"], 0.0);
}

fn assert_listeners_retired(ports: [u16; 2]) {
    for port in ports {
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    }
}

#[test]
fn t17e_initial_idle_api_loopback_identity_gate_and_owned_listener_cleanup() {
    if !isolated_child("t17e_initial_idle_api_loopback_identity_gate_and_owned_listener_cleanup") {
        return;
    }
    idle_api_loopback_identity_gate_and_owned_listener_cleanup("am2-t17e");
}

#[test]
fn s17e_initial_idle_api_loopback_identity_gate_and_owned_listener_cleanup() {
    if !isolated_child("s17e_initial_idle_api_loopback_identity_gate_and_owned_listener_cleanup") {
        return;
    }
    idle_api_loopback_identity_gate_and_owned_listener_cleanup("am2-s17e");
}

fn idle_api_loopback_identity_gate_and_owned_listener_cleanup(target: &str) {
    let (config, held) = idle_config(Some(target));
    let ports = [config.api.http_port, config.api.cgminer_port];
    let shutdown = CancellationToken::new();
    let rt = runtime();
    rt.block_on(async {
        let (tx, rx) = oneshot::channel();
        drop(held);
        let (cg, http) = OBSERVER
            .scope(
                RefCell::new(Some(tx)),
                spawn_initial_idle_api(config, target, shutdown.clone()),
            )
            .await
            .unwrap();
        let state = rx.await.unwrap();
        assert_declared_closed(&state, target);
        loopback_readback(ports[0], ports[1], target).await;
        assert!(!cg.is_finished() && !http.is_finished());
        shutdown.cancel();
        // API listener ownership is explicit: notification cancellation alone
        // does not retire these handles. Abort and join the two owned tasks.
        cg.abort();
        http.abort();
        assert!(cg.await.unwrap_err().is_cancelled());
        assert!(http.await.unwrap_err().is_cancelled());
        assert_declared_closed(&state, target);
    });
    drop(rt);
    assert_listeners_retired(ports);
}

#[test]
fn t17e_default_disabled_cold_idle_survives_poll_until_cancellation() {
    if !isolated_child("t17e_default_disabled_cold_idle_survives_poll_until_cancellation") {
        return;
    }
    default_disabled_cold_idle_survives_poll_until_cancellation("am2-t17e");
}

#[test]
fn s17e_default_disabled_cold_idle_survives_poll_until_cancellation() {
    if !isolated_child("s17e_default_disabled_cold_idle_survives_poll_until_cancellation") {
        return;
    }
    default_disabled_cold_idle_survives_poll_until_cancellation("am2-s17e");
}

fn default_disabled_cold_idle_survives_poll_until_cancellation(target: &str) {
    let (config, held) = idle_config(Some(target));
    assert!(crate::runtime::cold_activation::eligible(
        target,
        &config,
        "/etc/dcentrald.toml",
        true,
        false,
        false
    ));
    let ports = [config.api.http_port, config.api.cgminer_port];
    let shutdown = CancellationToken::new();
    let rt = runtime();
    rt.block_on(async {
        let (tx, rx) = oneshot::channel();
        drop(held);
        let idle = OBSERVER.scope(
            RefCell::new(Some(tx)),
            crate::runtime::cold_activation::run(config, target, shutdown.clone()),
        );
        tokio::pin!(idle);
        tokio::select! {
            result = &mut idle => panic!("cold idle exited before API construction: {result:?}"),
            state = rx => {
                let state = state.expect("actual idle AppState observer");
                assert_declared_closed(&state, target);
                // Drive the same idle future alongside requests and a real
                // polling interval; no readiness or clock value is injected.
                tokio::select! {
                    result = &mut idle => panic!("cold idle terminated while disabled: {result:?}"),
                    _ = async {
                        loopback_readback(ports[0], ports[1], target).await;
                        tokio::time::sleep(Duration::from_millis(1200)).await;
                        loopback_readback(ports[0], ports[1], target).await;
                    } => {}
                }
                assert_declared_closed(&state, target);
                shutdown.cancel();
                tokio::time::timeout(Duration::from_secs(2), &mut idle).await.unwrap().unwrap();
                assert_declared_closed(&state, target);
            }
        }
    });
    // cold_activation retains its API until process/runtime termination. This
    // mirrors its shutdown boundary and retires all detached notification/API
    // tasks; do not claim that cancellation alone closes the API listeners.
    drop(rt);
    assert_listeners_retired(ports);
}

#[test]
fn bm1396_initial_idle_api_refuses_legacy_aliases_and_near_suffixes_before_composition() {
    if !isolated_child("bm1396_initial_idle_api_refuses_legacy_aliases_and_near_suffixes_before_composition") {
        return;
    }
    runtime().block_on(async {
        for target in [
            "am2-s17",
            "am2-s17e-extra",
            "am2-s17e ",
            "AM2-S17E",
            "am2-t17e-plus",
            "am2-t17e-",
            "am2-t17ex",
            "AM2-T17E",
            "am2-t17e ",
        ] {
            let (config, held) = idle_config(None);
            let ports = [config.api.http_port, config.api.cgminer_port];
            let (tx, rx) = oneshot::channel();
            drop(held);
            let error = OBSERVER
                .scope(
                    RefCell::new(Some(tx)),
                    spawn_initial_idle_api(config, target, CancellationToken::new()),
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("no initial idle API composition for {target}")
            );
            assert!(
                rx.await.is_err(),
                "refused target constructed AppState: {target}"
            );
            assert_listeners_retired(ports);
        }
    });
}
