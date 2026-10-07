//! Authored R08 boot-origin checks. No process environment or hardware writes.
use super::{am2_boot_origin_preflight, DcentraldConfig};
use crate::config::Am2BootOrigin;

fn config(origin: Option<Am2BootOrigin>, passthrough: bool) -> DcentraldConfig {
    let mut config: DcentraldConfig = toml::from_str("").unwrap();
    config.mining.am2_boot_origin = origin;
    config.mining.passthrough = passthrough;
    config
}

#[test]
fn legacy_configs_preserve_every_existing_selection_combination() {
    for passthrough in [false, true] {
        for inherited in [false, true] {
            for standalone in [false, true] {
                am2_boot_origin_preflight(&config(None, passthrough), inherited, standalone)
                    .expect("absent field must preserve existing selection");
            }
        }
    }
}

#[test]
fn native_origin_cannot_be_satisfied_by_inherited_or_unselected_state() {
    for passthrough in [false, true] {
        for inherited in [false, true] {
            for standalone in [false, true] {
                let result = am2_boot_origin_preflight(
                    &config(Some(Am2BootOrigin::NativeCold), passthrough),
                    inherited,
                    standalone,
                );
                assert_eq!(result.is_ok(), !passthrough && !inherited && standalone);
            }
        }
    }
    let error =
        am2_boot_origin_preflight(&config(Some(Am2BootOrigin::NativeCold), false), true, false)
            .unwrap_err()
            .to_string();
    assert!(error.contains("DCENT_AM2_TRUST_RAIL_FALLBACK"));
}

#[test]
fn inherited_origin_requires_its_existing_selection_without_standalone() {
    for passthrough in [false, true] {
        for inherited in [false, true] {
            for standalone in [false, true] {
                let result = am2_boot_origin_preflight(
                    &config(Some(Am2BootOrigin::InheritedHandoff), passthrough),
                    inherited,
                    standalone,
                );
                assert_eq!(result.is_ok(), !standalone && (passthrough || inherited));
            }
        }
    }
}

#[test]
fn exact_boot_origin_strings_round_trip_and_invalid_values_refuse() {
    for (text, expected) in [
        ("native_cold", Am2BootOrigin::NativeCold),
        ("inherited_handoff", Am2BootOrigin::InheritedHandoff),
    ] {
        let parsed: DcentraldConfig =
            toml::from_str(&format!("[mining]\nam2_boot_origin = \"{text}\"\n")).unwrap();
        assert_eq!(parsed.mining.am2_boot_origin, Some(expected));
        let serialized = toml::to_string(&parsed).unwrap();
        let recovered: DcentraldConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(recovered.mining.am2_boot_origin, Some(expected));
    }
    for invalid in [
        "native",
        "native_cold_other",
        "xil",
        "bm1362",
        "",
        "NATIVE_COLD",
    ] {
        assert!(toml::from_str::<DcentraldConfig>(&format!(
            "[mining]\nam2_boot_origin = \"{invalid}\"\n"
        ))
        .is_err());
    }
    let legacy = config(None, false);
    assert!(!toml::to_string(&legacy)
        .unwrap()
        .contains("am2_boot_origin"));
}

#[test]
fn real_clean_and_legacy_config_files_keep_idle_and_boot_origin_separate() {
    // Retain the ordinary-file fixture for the eventual runner receipt. No
    // external crate, network, process environment mutation or device is used.
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "dcent-am2-boot-origin-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let clean = include_str!("../../configs/dcentrald_s19jpro_xil_baked_default.toml");
    let legacy = include_str!("../../configs/dcentrald_s19jpro_xil_override.toml");
    for (name, contents, expected) in [("clean.toml", clean, None), ("legacy.toml", legacy, None)] {
        let path = directory.join(name);
        std::fs::write(&path, contents).unwrap();
        let loaded = DcentraldConfig::load(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.mining.am2_boot_origin, expected);
        if name == "clean.toml" {
            assert!(!loaded.mining_start_enabled());
            assert!(loaded.pool.url.is_empty());
            assert!(loaded.power.psu_override.as_ref().unwrap().enabled);
            assert!(!loaded.mining.version_rolling);
            assert_eq!(loaded.mining.serial_chip_count, Some(126));
            // No per-unit standalone flag or inherited rail is required by
            // the generic shipped config. Operator Start remains explicit.
            let mut enabled = loaded.clone();
            enabled.mining.enabled = true;
            enabled.pool.url = "stratum+tcp://127.0.0.1:3333".into();
            enabled.pool.worker = "operator-worker".into();
            assert!(enabled.mining_start_enabled());
            enabled.validate().expect("configured fresh image");
            am2_boot_origin_preflight(&enabled, false, false)
                .expect("generic fresh image must not require .25 selection");
            super::am2_boot_origin_runtime_preflight(&enabled)
                .expect("actual boot-origin preflight without standalone environment");
            let serialized = toml::to_string(&enabled).unwrap();
            std::fs::write(&path, serialized).unwrap();
            let reread = DcentraldConfig::load(path.to_str().unwrap()).unwrap();
            assert_eq!(reread.mining.am2_boot_origin, None);
        } else {
            am2_boot_origin_preflight(&loaded, true, false).unwrap();
        }
    }
}

#[test]
fn fresh_xil_config_reaches_the_shipped_work_gate_after_explicit_start() {
    use super::{
        hybrid_admit_standard_work_dispatch, hybrid_heartbeat_inputs, hybrid_watchdog_safety_state,
        hybrid_work_dispatch_inputs, ThermalSafetyState, WorkDispatchLifecycle,
    };
    let mut configured: DcentraldConfig = toml::from_str(include_str!(
        "../../configs/dcentrald_s19jpro_xil_baked_default.toml"
    ))
    .unwrap();
    assert!(!configured.mining_start_enabled());
    configured.pool.url = "stratum+tcp://127.0.0.1:3333".into();
    configured.pool.worker = "operator-worker".into();
    assert!(
        !configured.mining_start_enabled(),
        "pool settings cannot energize an idle image"
    );
    configured.mining.enabled = true;
    configured.validate().unwrap();
    assert!(configured.mining_start_enabled());
    super::am2_boot_origin_runtime_preflight(&configured).unwrap();

    // These are modeled observations, not minted physical watchdog/controller
    // authority. This regression joins actual config loading and the real work
    // gate; the full hardware-owner simulation belongs to the positive spine.
    let (requirement, heartbeats) =
        hybrid_heartbeat_inputs(false, 0x20, true, &[(0x21, true), (0x22, true)], 1);
    let inputs = hybrid_work_dispatch_inputs(
        hybrid_watchdog_safety_state(configured.watchdog.enabled, true),
        requirement,
        &heartbeats,
        ThermalSafetyState::Ready,
    );
    let mut lifecycle = WorkDispatchLifecycle::new();
    assert_eq!(
        hybrid_admit_standard_work_dispatch(&mut lifecycle, &inputs)
            .unwrap()
            .controller_count,
        3
    );
    assert!(lifecycle.is_admitted());
    let mut failed = inputs.clone();
    failed.controllers[1].heartbeat_ok = false;
    assert!(
        hybrid_admit_standard_work_dispatch(&mut WorkDispatchLifecycle::new(), &failed).is_err()
    );
}

#[tokio::test]
async fn actual_safety_start_refuses_native_passthrough_before_watchdog_admission() {
    let mut config = config(Some(Am2BootOrigin::NativeCold), true);
    // If ordering regresses, a disabled watchdog stays inert and returns its
    // own refusal. The required native-origin error must occur first.
    config.watchdog.enabled = false;
    let identity = crate::daemon_lifecycle::PlatformIdentitySnapshot {
        declared_board_target: Some("am2-s19j".to_string()),
        observed_board_target: None,
        board_desc: dcentrald_common::BoardDesc::lookup("am2-s19j"),
        declared_platform_marker: Some("zynq-bm3-am2".to_string()),
        declared_subtype: None,
        declared_psu_hardware_variant: None,
        observed_control_board: crate::runtime::hardware_info::OBSERVED_CONTROL_BOARD_ZYNQ_AM2
            .to_string(),
    };
    let protocol = Some(dcentrald_common::AsicProtocolIdentity::Bm1362);
    let dispatch = crate::admit_board_desc_runtime_dispatch(
        identity.board_desc,
        crate::RuntimeDispatchKind::S19jHybrid,
        true,
        protocol,
    )
    .unwrap();
    // This unit fixture isolates boot-origin ordering before watchdog access.
    // Production callers must use RuntimeDispatchAdmission::bind, which joins
    // this declaration to verified image authority; that boundary has its own
    // unsigned-image and cross-board refusal tests.
    let dispatch = crate::RuntimeDispatchAdmission {
        declared: dispatch,
        _image: None,
    };
    let route = crate::s19j_hybrid_admission::admit_s19j_hybrid_route(
        &identity,
        crate::RuntimeDispatchKind::S19jHybrid,
        protocol,
    )
    .unwrap();
    let result = super::S19jHybridSafetyAdmission::start(&config, dispatch, route).await;
    let error = match result {
        Ok(_) => panic!("native passthrough cannot acquire the safety watchdog"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("native_cold configuration conflicts"),
        "{error}"
    );
}
