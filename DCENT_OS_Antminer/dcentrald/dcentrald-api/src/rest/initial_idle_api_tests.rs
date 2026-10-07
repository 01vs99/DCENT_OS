//! Actual REST router persistence with a closed hardware gate and declared
//! identity. The filesystem override exists only in this isolated test child;
//! production continues to use the canonical /data and /etc locations.

use super::*;
use axum::body::Body;
use axum::http::Request;
use dcentrald_hal::platform::HardwareMutationGate;
use tower::ServiceExt;

fn idle_state(target: &str, chip: &str) -> Arc<AppState> {
    let state = crate::build_minimal_app_state_with_hardware_mutation_gate(
        crate::MinimalAppStateInputs {
            api_config: crate::ApiConfig::default(),
            pool_url: String::new(),
            pool_protocol: "sv1".into(),
            mode: crate::OperatingMode::Standard,
            firmware_version: "test".into(),
            fan_pwm: 0,
            network_block: Default::default(),
            profile_path: "/unused".into(),
            control_board_label: format!("{target} (image declaration)"),
            chip_type_label: chip.into(),
            external_state_rx: None,
        },
        HardwareMutationGate::new_closed(),
    );
    state.hardware_info.lock().unwrap().identification =
        crate::HardwareIdentification::from_evidence(
            vec![crate::HardwareIdentityEvidence::declared_asic_board_target(
                target, chip,
            )],
            Some("Initial idle image declaration; ASIC detection has not run".into()),
        );
    state
}

async fn post(router: Router, path: &str, payload: serde_json::Value) -> Response {
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[test]
fn initial_idle_api_config_persistence_and_activation() {
    const NAME: &str =
        "rest::initial_idle_api_tests::initial_idle_api_config_persistence_and_activation";
    if std::env::var("DCENT_COLD_API_TEST_CHILD").as_deref() != Ok("1") {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env("DCENT_COLD_API_TEST_CHILD", "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    let root = std::env::temp_dir().join(format!("dcent-cold-api-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let persistent = root.join("persisted.toml");
    let baked = root.join("baked.toml");
    CONFIG_TEST_PATHS
        .set((
            Box::leak(persistent.to_string_lossy().into_owned().into_boxed_str()),
            Box::leak(baked.to_string_lossy().into_owned().into_boxed_str()),
        ))
        .unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let unknown = idle_state("unregistered-target", "BM1397");
        let unknown_descriptor = current_antminer_capability_descriptor(&unknown);
        assert!(!unknown_descriptor.runtime_caps.contains(&RuntimeCapability::ConfigRw));
        let target_rows = [
            ("am2-s17p", "BM1397", "s17pro"),
            ("am2-s17plus", "BM1397", "s17plus"),
            ("am2-t17", "BM1397", "t17"),
            ("am2-t17plus", "BM1397", "t17plus"),
            ("am2-s19pro", "BM1398", "s19pro"),
            ("am1-s9i", "BM1387", "s9i"),
            ("am1-s9j", "BM1387", "s9j"),
            ("am3-s21", "BM1368", "s21"),
            ("am3-s21pro", "BM1370", "s21pro"),
            ("am3-s21xp", "BM1370", "s21xp"),
            ("am3-s19xp", "BM1366", "s19xp"),
            ("am3-s19jproa", "BM1362", "s19jproa"),
            ("am3-s19jproplus", "BM1362", "s19jproplus"),
            ("am3-s19jxp", "BM1366", "s19jxp"),
            ("am1-s9se", "BM1393", "s9se"),
            ("am1-s9k", "BM1393", "s9k"),
        ];
        for (target, chip, model) in target_rows {
            let _ = std::fs::remove_file(&persistent);
            std::fs::write(&baked, format!("[mining]\nenabled = false\nmodel = {model:?}\nfrequency_mhz = 100\nvoltage_mv = 9000\n[pool]\nurl = \"\"\nworker = \"\"\n[thermal]\nfan_max_pwm = 30\n")).unwrap();
            let state = idle_state(target, chip);
            let descriptor = current_antminer_capability_descriptor(&state);
            assert!(descriptor.runtime_caps.contains(&RuntimeCapability::ConfigRw), "{target}");
            assert!(descriptor.runtime_caps.contains(&RuntimeCapability::PoolsRw), "{target}");
            assert!(!descriptor.runtime_caps.contains(&RuntimeCapability::AsicOptions), "{target}");
            assert!(!descriptor.runtime_caps.contains(&RuntimeCapability::PowerControl), "{target}");
            assert!(!descriptor.runtime_caps.contains(&RuntimeCapability::Reboot), "{target}");
            assert!(!descriptor.fail_safe.mining_start_allowed);
            assert!(state.hardware_mutation_gate.try_acquire().is_err());
            let router = build_router().with_state(state);
            let response = post(router.clone(), "/api/config", serde_json::json!({
                "pool": {"url":"stratum+tcp://127.0.0.1:3333", "worker":"tester", "password":"x"},
                "mining": {"enabled":true},
            })).await;
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1_048_576).await.unwrap();
            assert_eq!(status, StatusCode::OK, "{target}: {}", String::from_utf8_lossy(&body));
            let bytes = std::fs::read(&persistent).unwrap();
            let parsed: toml::Table = toml::from_str(std::str::from_utf8(&bytes).unwrap()).unwrap();
            assert_eq!(parsed["mining"]["enabled"].as_bool(), Some(true));
            assert_eq!(parsed["mining"]["model"].as_str(), Some(model));
            assert_eq!(parsed["pool"]["worker"].as_str(), Some("tester"));
            let response = post(router, "/api/config", serde_json::json!({"mining":{"voltage_mv":30_000}})).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(std::fs::read(&persistent).unwrap(), bytes);
        }
        let router = build_router().with_state(idle_state("am2-s19pro", "BM1398"));
        assert_eq!(post(router.clone(), "/api/action/restart", serde_json::json!({})).await.status(), StatusCode::CONFLICT);
        let wake = crate::cold_activation::install_initial_idle_activation().unwrap();
        assert_eq!(post(router, "/api/action/restart", serde_json::json!({})).await.status(), StatusCode::ACCEPTED);
        tokio::time::timeout(std::time::Duration::from_millis(250), wake.notified()).await.unwrap();
    });
    std::fs::remove_dir_all(root).unwrap();
}
