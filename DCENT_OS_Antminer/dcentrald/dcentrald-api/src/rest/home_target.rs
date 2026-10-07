//! Persist an operator's heater request and report the actual owner's acknowledgement.
use super::*;
static REQUEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(super) fn supports_persisted_power_policy(state: &AppState, board_target: &str) -> bool {
    board_target != "am2-s19j"
        || state
            .autotuner_command_tx
            .as_ref()
            .is_some_and(|tx| !tx.is_closed())
}

pub(crate) fn apply_home_power_target_to_table(
    table: &mut toml::Table,
    target_watts: u32,
    preset: Option<&str>,
) -> Result<(), String> {
    apply_home_request_to_table(table, target_watts, preset, true)
}

pub(super) fn apply_home_request_to_table(
    table: &mut toml::Table,
    target_watts: u32,
    preset: Option<&str>,
    owner_supports_power_policy: bool,
) -> Result<(), String> {
    fn section<'a>(table: &'a mut toml::Table, key: &str) -> Result<&'a mut toml::Table, String> {
        table
            .entry(key.to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or_else(|| format!("config section {key} must be a table"))
    }
    let mode = dcentrald_autotuner::config::TunerMode::PowerTarget {
        watts: target_watts,
    };
    mode.validate()?;
    // Build the whole change before replacing the caller's table. A malformed
    // section must not leave half a policy behind, even in memory.
    let mut updated = table.clone();
    for home in ["legacy", "canonical"] {
        let parent = if home == "canonical" {
            section(&mut updated, "mode")?
        } else {
            &mut updated
        };
        let home = section(parent, "home")?;
        home.insert(
            "target_watts".into(),
            toml::Value::Integer(target_watts.into()),
        );
        match preset {
            Some(name) => {
                home.insert("preset".into(), toml::Value::String(name.into()));
            }
            None => {
                home.remove("preset");
            }
        }
    }
    // The daemon actually consumes this policy on startup; [home] alone was
    // display-only. Preserve enabled, voltage/DVFS, circuit and thermal limits.
    if !owner_supports_power_policy {
        *table = updated;
        return Ok(());
    }
    let tuner = section(&mut updated, "autotuner")?;
    tuner.insert("target_mode".into(), toml::Value::String("power".into()));
    tuner.insert(
        "target_watts".into(),
        toml::Value::Integer(target_watts.into()),
    );
    tuner.insert(
        "tuner_mode".into(),
        toml::Value::try_from(&mode).map_err(|e| e.to_string())?,
    );
    *table = updated;
    Ok(())
}

pub(super) async fn save_and_dispatch(
    state: &AppState,
    board_target: &str,
    watts: u32,
    preset: Option<&str>,
    save: impl FnOnce() -> Result<(), String>,
) -> Result<serde_json::Value, String> {
    let _request_guard = REQUEST_LOCK.lock().await;
    // No runtime mutation when persistence fails. The exact owner retains its
    // circuit, thermal, frequency and voltage bounds after receiving the request.
    save()?;
    let runtime = if !supports_persisted_power_policy(state, board_target) {
        serde_json::json!({
            "channel_available": false, "accepted": false, "applied_runtime": false,
            "status": "unavailable",
            "message": "This S19j hybrid runtime has no watt-control owner with admitted power inputs; the request is saved only.",
        })
    } else {
        super::late::dispatch_autotuner_mode_command(
            state,
            dcentrald_autotuner::config::TunerMode::PowerTarget { watts },
        )
        .await
    };
    let applied = runtime["applied_runtime"].as_bool() == Some(true);
    Ok(serde_json::json!({
        "status": "ok", "saved": true, "applied_runtime": applied,
        "message": if applied { "Power target saved and adopted by the autotuner; check live power for the achieved result." }
            else { "Power target saved; live application has not been confirmed." },
        "target_watts": watts, "preset": preset, "runtime": runtime,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> Arc<AppState> {
        crate::build_minimal_app_state(crate::MinimalAppStateInputs {
            api_config: crate::ApiConfig::default(),
            pool_url: String::new(),
            pool_protocol: "sv1".into(),
            mode: crate::OperatingMode::Home,
            firmware_version: "heater-test".into(),
            fan_pwm: 30,
            network_block: crate::NetworkBlockConfig::default(),
            profile_path: "/nonexistent/heater-test".into(),
            control_board_label: "test".into(),
            chip_type_label: "BM1387".into(),
            external_state_rx: None,
        })
    }

    #[test]
    fn canonical_home_target_preserves_safety_and_clears_stale_preset() {
        let mut table: toml::Table = toml::from_str(
            "[mining]\nenabled=false\n[thermal]\nfan_max_pwm=30\n[autotuner]\nenabled=false\nvoltage_optimization=false\ntotal_power_limit_w=700\n[mode.home]\npreset='high'\n[mode.home.night_mode]\nenabled=true\n",
        ).unwrap();
        apply_home_power_target_to_table(&mut table, 600, Some("s19j_low")).unwrap();
        assert_eq!(
            table["mode"]["home"]["target_watts"].as_integer(),
            Some(600)
        );
        assert_eq!(
            table["mode"]["home"]["night_mode"]["enabled"].as_bool(),
            Some(true)
        );
        let policy: dcentrald_autotuner::config::TunerMode =
            table["autotuner"]["tuner_mode"].clone().try_into().unwrap();
        assert_eq!(policy.target_watts(), Some(600));
        assert_eq!(table["mining"]["enabled"].as_bool(), Some(false));
        assert_eq!(table["thermal"]["fan_max_pwm"].as_integer(), Some(30));
        assert_eq!(table["autotuner"]["enabled"].as_bool(), Some(false));
        assert_eq!(
            table["autotuner"]["voltage_optimization"].as_bool(),
            Some(false)
        );
        assert_eq!(
            table["autotuner"]["total_power_limit_w"].as_integer(),
            Some(700)
        );
        apply_home_power_target_to_table(&mut table, 650, None).unwrap();
        assert!(table["mode"]["home"].get("preset").is_none());
        assert!(table["home"].get("preset").is_none());
    }

    #[test]
    fn malformed_home_sections_leave_the_full_table_unchanged() {
        for text in [
            "mode=4",
            "[mode]\nhome=false",
            "home=4",
            "autotuner='invalid'",
        ] {
            let mut table: toml::Table = toml::from_str(text).unwrap();
            let before = table.clone();
            assert!(apply_home_power_target_to_table(&mut table, 600, None).is_err());
            assert_eq!(table, before);
        }
    }

    #[test]
    fn unsupported_s19j_request_never_activates_a_zero_voltage_power_model_on_restart() {
        let mut table: toml::Table = toml::from_str(
            "[autotuner]\nam2_frequency_autotune=true\ntarget_mode='efficiency'\ntarget_watts=0\n",
        )
        .unwrap();
        let previous = table["autotuner"].clone();
        apply_home_request_to_table(&mut table, 600, Some("s19j_low"), false).unwrap();
        assert_eq!(
            table["mode"]["home"]["target_watts"].as_integer(),
            Some(600)
        );
        assert_eq!(table["autotuner"], previous);
    }

    #[tokio::test]
    async fn failed_save_never_sends_an_owner_command() {
        let mut state = state();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        Arc::get_mut(&mut state).unwrap().autotuner_command_tx = Some(tx);
        assert!(
            save_and_dispatch(&state, "am1-s9", 600, None, || Err("disk full".into()))
                .await
                .is_err()
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn home_target_handler_rejects_wrong_model_ambiguous_and_unsafe_requests() {
        let state = state();
        state.hardware_info.lock().unwrap().identification =
            crate::HardwareIdentification::from_evidence(
                vec![
                    crate::HardwareIdentityEvidence::declared_asic_board_target("am1-s9", "BM1387"),
                    crate::HardwareIdentityEvidence::measured_asic_enumeration(
                        0x1387,
                        "BM1387",
                        crate::HardwareCompositionToken::new(1, "test:am1-s9"),
                    ),
                ],
                Some("test S9 enumeration".into()),
            );
        for (preset, watts) in [
            (Some("s19j_low"), None),
            (Some("max"), Some(600)),
            (None, Some(49)),
            (None, Some(1801)),
            (None, None),
        ] {
            let response = super::super::late::post_home_target(
                State(state.clone()),
                Json(HomeTargetRequest {
                    preset: preset.map(str::to_string),
                    watts,
                }),
            )
            .await
            .into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn absent_s19j_owner_never_claims_live_power_control() {
        let result = save_and_dispatch(&state(), "am2-s19j", 600, Some("s19j_low"), || Ok(()))
            .await
            .unwrap();
        assert_eq!(result["saved"], true);
        assert_eq!(result["applied_runtime"], false);
        assert!(result["runtime"]["message"]
            .as_str()
            .unwrap()
            .contains("admitted power inputs"));
    }

    #[tokio::test]
    async fn missing_or_closed_s19j_owner_preserves_restart_policy() {
        for closed in [false, true] {
            let mut state = state();
            if closed {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                drop(rx);
                Arc::get_mut(&mut state).unwrap().autotuner_command_tx = Some(tx);
            }
            let mut table: toml::Table = toml::from_str(
                "[autotuner]\nam2_frequency_autotune=true\ntarget_mode='efficiency'\ntarget_watts=0\n",
            ).unwrap();
            let previous = table["autotuner"].clone();
            let result = save_and_dispatch(&state, "am2-s19j", 600, Some("s19j_low"), || {
                apply_home_request_to_table(
                    &mut table,
                    600,
                    Some("s19j_low"),
                    supports_persisted_power_policy(&state, "am2-s19j"),
                )
            })
            .await
            .unwrap();
            assert_eq!(table["autotuner"], previous);
            assert_eq!(
                table["mode"]["home"]["target_watts"].as_integer(),
                Some(600)
            );
            assert_eq!(result["saved"], true);
            assert_eq!(result["applied_runtime"], false);
            assert_eq!(result["runtime"]["status"], "unavailable");
            assert_eq!(result["runtime"]["channel_available"], false);
        }
    }

    #[tokio::test]
    async fn closed_owner_never_claims_application() {
        let mut state = state();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        Arc::get_mut(&mut state).unwrap().autotuner_command_tx = Some(tx);
        let result = save_and_dispatch(&state, "am1-s9", 600, None, || Ok(()))
            .await
            .unwrap();
        assert_eq!(result["applied_runtime"], false);
        assert_eq!(result["runtime"]["status"], "closed");
    }

    #[tokio::test]
    async fn saved_home_target_reaches_real_s9_tuner_and_requires_dispatcher_ack() {
        use dcentrald_autotuner::config::AutoTunerConfig;
        use dcentrald_autotuner::{AutoTuner, ChipProfile, FreqCommand, TuningProfile};
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0.join("config.toml"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        for (voltage_mv, accepted, applied) in
            [(9100, true, true), (9100, false, false), (0, true, false)]
        {
            let root = std::env::temp_dir().join(format!(
                "heater-ack-{}-{}-{accepted}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            let scratch = Scratch(root);
            let path = scratch.0.join("config.toml");
            let mut state = state();
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            Arc::get_mut(&mut state).unwrap().autotuner_command_tx = Some(tx);
            let mut tuner = AutoTuner::new(
                AutoTunerConfig {
                    circuit_capacity_watts: Some(450),
                    total_power_limit_w: 400,
                    voltage_optimization: false,
                    dvfs_enabled: false,
                    ..AutoTunerConfig::default()
                },
                625,
                "BM1387".into(),
                "pic16".into(),
                Arc::new(std::sync::RwLock::new(
                    dcentrald_autotuner::PowerCalibration::default(),
                )),
            );
            let chips: Vec<ChipProfile> = (0..63)
                .map(|chip_index| ChipProfile {
                    chip_index,
                    max_stable_mhz: 625,
                    operating_mhz: 625,
                    grade: dcentrald_autotuner::profile::ChipGrade::B,
                    error_rate: 0.0,
                    nonces_counted: 100,
                    vf_curve: None,
                    thermal_max_stable_mhz: None,
                })
                .collect();
            let stats = TuningProfile::compute_stats(&chips, 10.0);
            let profile = serde_json::from_value(serde_json::json!({
                "version": 2, "chip_type": "BM1387", "chain_id": 6, "chip_count": 63,
                "voltage_mv": voltage_mv, "tuned_at": "0", "chips": chips, "stats": stats,
            }))
            .unwrap();
            tuner.install_profile_for_test(6, profile);
            tuner.force_state_for_test(dcentrald_autotuner::tuner::TunerState::BackgroundAdjust);
            tuner.set_command_receiver(rx);
            let (freq_tx, mut freq_rx) = tokio::sync::mpsc::channel(128);
            let save = save_and_dispatch(&state, "am1-s9", 600, None, || {
                let mut table = toml::Table::new();
                apply_home_power_target_to_table(&mut table, 600, None)?;
                atomic_write(&path, toml::to_string(&table).unwrap()).map_err(|e| e.to_string())
            });
            let owner = async {
                assert!(tuner.tick_runtime_commands_for_test(&freq_tx).await);
                drop(freq_tx);
                assert_eq!(tuner.last_resolved_power_target_watts_for_test(), Some(400));
            };
            // Hardware is replaced at the existing FreqCommand boundary only.
            // The actual tuner allocates watts and waits for these exact ACKs.
            let dispatcher = async {
                let mut frequency_commands = 0;
                while let Some(command) = freq_rx.recv().await {
                    let saved: toml::Table =
                        toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
                    assert_eq!(
                        saved["mode"]["home"]["target_watts"].as_integer(),
                        Some(600)
                    );
                    match command {
                        FreqCommand::SetChipFreq {
                            freq_mhz, ack_tx, ..
                        } => {
                            assert!(freq_mhz < 625);
                            frequency_commands += 1;
                            ack_tx
                                .unwrap()
                                .send(if accepted {
                                    Ok(freq_mhz)
                                } else {
                                    Err("test dispatcher refused".into())
                                })
                                .unwrap();
                        }
                        FreqCommand::UpdateWorkTime { .. } => {}
                        FreqCommand::Barrier { ack_tx } => {
                            ack_tx.send(()).unwrap();
                        }
                        other => {
                            panic!("heater power request must not write voltage or fans: {other:?}")
                        }
                    }
                }
                assert_eq!(frequency_commands, 63);
            };
            let (result, (), ()) = tokio::join!(save, owner, dispatcher);
            let result = result.unwrap();
            assert_eq!(result["saved"], true);
            assert_eq!(result["applied_runtime"], applied);
            assert_eq!(
                result["runtime"]["status"],
                if applied { "applied" } else { "deferred" }
            );
        }
    }
}
