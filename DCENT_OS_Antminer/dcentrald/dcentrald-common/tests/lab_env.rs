use dcentrald_common::lab_env::{compiled, var, var_os};
use std::env::VarError;
use std::ffi::OsString;

// Real caller names span register values, presence flags, safety overrides,
// timing and chip-driver selection. A subprocess avoids global-env races
// with the hardware crates' existing tests.
const OVERRIDES: &[(&str, &str)] = &[
    ("DCENT_AM2_PER_VERSION_DAC", "1"),
    ("DCENT_AM3_BB_MINING_BAUD", "3000000"),
    ("DCENT_AM3_BB_WORK_CODEC", "asic86"),
    ("DCENT_AM3_BB_STUB_LOOP", "0"),
    ("DCENT_AM2_ACCEPT_DEGRADED_HARDWARE", "true"),
    ("DCENT_BM1366_HASH_COUNTING", "0x00001446"),
    ("DCENT_BM1370_JIG_VCO_CLAMP", "1"),
    ("DCENT_AM2_DSPIC_KEEPALIVE_INTERVAL_MS", "50"),
    ("DCENT_AM2_S17_ALLOW_ENERGIZE", "YES"),
    ("DCENT_CV1835_ACCEPT_INFERRED_SOC_REGS", ""),
];

#[test]
fn hardware_override_reads_follow_compiled_capability() {
    const CHILD: &str = "DCENT_LAB_ENV_TEST_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "hardware_override_reads_follow_compiled_capability",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .envs(OVERRIDES.iter().copied())
            .status()
            .expect("launch isolated hardware override check");
        assert!(status.success(), "hardware override subprocess failed");
        return;
    }
    for &(name, value) in OVERRIDES {
        assert_eq!(std::env::var(name).unwrap(), value);
        if compiled() {
            assert_eq!(var(name).unwrap(), value, "{name}");
            assert_eq!(var_os(name), Some(OsString::from(value)), "{name}");
        } else {
            assert!(matches!(var(name), Err(VarError::NotPresent)), "{name}");
            assert_eq!(var_os(name), None, "{name}");
        }
    }
}

#[cfg(unix)]
#[test]
fn non_unicode_override_keeps_std_env_semantics_only_in_lab() {
    use std::os::unix::ffi::OsStringExt;
    const NAME: &str = "DCENT_LAB_ENV_NON_UNICODE_TEST";
    let raw = OsString::from_vec(vec![0xff, b'1']);
    // This name belongs exclusively to this test, so it cannot alter a
    // hardware caller or interfere with the subprocess test above.
    std::env::set_var(NAME, &raw);
    let unicode_result = var(NAME);
    let os_result = var_os(NAME);
    std::env::remove_var(NAME);
    if compiled() {
        assert_eq!(unicode_result, Err(VarError::NotUnicode(raw.clone())));
        assert_eq!(os_result, Some(raw));
    } else {
        assert_eq!(unicode_result, Err(VarError::NotPresent));
        assert_eq!(os_result, None);
    }
}
