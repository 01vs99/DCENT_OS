use dcentrald_common::lab_env;
use dcentrald_hal::platform::amlogic::vnish_cold_boot::env_gate_is_set;
use dcentrald_hal::pmbus::PmbusTelemetryGate;
use dcentrald_hal::psu_gpio_i2c::{loki_inter_txn_gap_ms, LOKI_INTER_TXN_GAP_MS_DEFAULT};

#[test]
fn hardware_adapters_preserve_defaults_and_lab_parsers() {
    const CHILD: &str = "DCENT_HAL_LAB_ENV_TEST_CHILD";
    const NAMES: &[&str] = &[
        "DCENT_AML_VNISH_ACCEPT_INFERRED",
        "DCENT_PMBUS_TELEMETRY",
        "DCENT_AM2_PSU_LOKI_INTER_TXN_GAP_MS",
    ];
    let cases = [
        ("absent", None, None, false, LOKI_INTER_TXN_GAP_MS_DEFAULT),
        ("enabled", Some("1"), Some("91"), true, 91),
        ("strict_truthy", Some("true"), Some("0"), false, 1),
        ("clamp", Some("0"), Some("999"), false, 500),
        (
            "invalid",
            Some(""),
            Some("bad"),
            false,
            LOKI_INTER_TXN_GAP_MS_DEFAULT,
        ),
    ];
    if let Ok(selected) = std::env::var(CHILD) {
        let (_, _, _, enabled, gap) = cases.iter().find(|case| case.0 == selected).unwrap();
        assert_eq!(env_gate_is_set(), lab_env::compiled() && *enabled);
        assert_eq!(
            PmbusTelemetryGate::from_env().is_enabled(),
            lab_env::compiled() && *enabled
        );
        assert_eq!(
            loki_inter_txn_gap_ms(),
            if lab_env::compiled() {
                *gap
            } else {
                LOKI_INTER_TXN_GAP_MS_DEFAULT
            }
        );
        return;
    }
    for (name, flag, gap, _, _) in cases {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child.args([
            "--exact",
            "hardware_adapters_preserve_defaults_and_lab_parsers",
        ]);
        child.env(CHILD, name);
        for key in NAMES {
            child.env_remove(key);
        }
        if let Some(flag) = flag {
            child.env(NAMES[0], flag).env(NAMES[1], flag);
        }
        if let Some(gap) = gap {
            child.env(NAMES[2], gap);
        }
        assert!(
            child.status().unwrap().success(),
            "HAL environment case {name}"
        );
    }
}
