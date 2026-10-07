//! Exact SKU refusal is enabled by default in every build.
//! Environment overrides exist only with the explicit compiled lab capability.
//! The shared mutex serializes test-owned process environment changes.

use std::sync::Mutex;

use dcentrald_silicon_profiles::energize_gate::{
    accept_degraded_hardware_enabled, strict_sku_refuse_enabled,
};

/// Serializes every test that mutates the shared process-global env vars, so
/// cargo's parallel test threads cannot race on them.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Lock the env mutex, ignoring poison (a prior panicking test must not
/// cascade-fail the rest — the guard's only job is mutual exclusion).
fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
}

#[test]
fn strict_default_is_on() {
    let _env = env_guard();
    std::env::remove_var("DCENT_AM2_STRICT_SKU_REFUSE");
    assert!(
        strict_sku_refuse_enabled(),
        "exact SKU refusal must remain the default in every build"
    );
}

#[test]
fn strict_recognizes_explicit_1() {
    let _env = env_guard();
    std::env::set_var("DCENT_AM2_STRICT_SKU_REFUSE", "1");
    assert!(strict_sku_refuse_enabled());
    std::env::remove_var("DCENT_AM2_STRICT_SKU_REFUSE");
}

#[test]
fn strict_recognizes_true_case_insensitive() {
    let _env = env_guard();
    std::env::set_var("DCENT_AM2_STRICT_SKU_REFUSE", "TrUe");
    assert!(strict_sku_refuse_enabled());
    std::env::remove_var("DCENT_AM2_STRICT_SKU_REFUSE");
}

#[test]
fn only_compiled_lab_can_disable_strict_refusal() {
    let _env = env_guard();
    // A release binary must ignore every environment attempt to disable the gate.
    std::env::set_var("DCENT_AM2_STRICT_SKU_REFUSE", "yes");
    assert_eq!(
        strict_sku_refuse_enabled(),
        !dcentrald_common::lab_env::compiled()
    );
    std::env::set_var("DCENT_AM2_STRICT_SKU_REFUSE", "0");
    assert_eq!(
        strict_sku_refuse_enabled(),
        !dcentrald_common::lab_env::compiled()
    );
    std::env::set_var("DCENT_AM2_STRICT_SKU_REFUSE", "");
    assert_eq!(
        strict_sku_refuse_enabled(),
        !dcentrald_common::lab_env::compiled()
    );
    std::env::remove_var("DCENT_AM2_STRICT_SKU_REFUSE");
}

#[test]
fn accept_degraded_default_is_off() {
    let _env = env_guard();
    std::env::remove_var("DCENT_AM2_ACCEPT_DEGRADED_HARDWARE");
    assert!(
        !accept_degraded_hardware_enabled(),
        "accept_degraded_hardware_enabled must default to false — lab override only"
    );
}

#[test]
fn accept_degraded_recognizes_explicit_1() {
    let _env = env_guard();
    std::env::set_var("DCENT_AM2_ACCEPT_DEGRADED_HARDWARE", "1");
    assert_eq!(
        accept_degraded_hardware_enabled(),
        dcentrald_common::lab_env::compiled()
    );
    std::env::remove_var("DCENT_AM2_ACCEPT_DEGRADED_HARDWARE");
}
