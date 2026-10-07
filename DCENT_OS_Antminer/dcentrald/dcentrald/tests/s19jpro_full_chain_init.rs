//! Current-source S19j Pro full-roster and launcher contracts.
//! Physical chip census is covered separately by the native simulation spine
//! and later bench validation; no archived journey record is a build input.

const MODEL_RS: &str = include_str!("../src/model.rs");
const HYBRID_RS: &str = include_str!("../src/s19j_hybrid_mining.rs");
const BM1362_RS: &str = include_str!("../../dcentrald-silicon-profiles/src/bm1362.rs");
const LAUNCHER: &str = include_str!("../../../scripts/run_wave56_25_STANDALONE_MINING.sh");
/// The four env vars that MUST NOT be set on `a lab unit`-class hybrid mining
/// ( `dcentrald` startup guard refuses to start if any is set).
const FORBIDDEN_ENV_VARS: &[&str] = &[
    "DCENT_AM2_PIC_RESET_AND_START_APP",
    "DCENT_AM2_PIC_RESET_STRACE_DERIVED",
    "DCENT_AM2_PSU_LOKI_REGISTER_POINTER",
    "DCENT_AM2_PSU_CALIBRATION_PROBE_WAKE",
];

#[test]
fn s19jpro_full_chain_126_roster_metadata_contract() {
    // 1. `s19jproam2` ModelSpec declares the full 126-chips-per-chain roster.
    let am2_start = MODEL_RS
        .find("\"s19jproam2\" => ModelSpec {")
        .expect("s19jproam2 ModelSpec arm must exist");
    let am2_block = &MODEL_RS[am2_start..am2_start + 600];
    assert!(
        am2_block.contains("chips_per_chain_hint: Some(126)"),
        "s19jproam2 must keep chips_per_chain_hint Some(126); got block:\n{am2_block}"
    );

    // S19j Pro+ keeps its distinct 120 roster (BHB42612, 3x120).
    let plus_start = MODEL_RS
        .find("\"s19jpro+\" | \"s19jproplus\" => ModelSpec {")
        .expect("s19jproplus ModelSpec arm must exist");
    let plus_block = &MODEL_RS[plus_start..plus_start + 600];
    assert!(
        plus_block.contains("chips_per_chain_hint: Some(120)"),
        "s19jproplus must keep chips_per_chain_hint Some(120); got block:\n{plus_block}"
    );

    // 2. Silicon profile agrees (live-pinned on .139 / .133).
    assert!(
        BM1362_RS.contains("pub const CHIPS_PER_CHAIN: u8 = 126;"),
        "bm1362 silicon profile must keep CHIPS_PER_CHAIN = 126"
    );
}

#[test]
fn s19jpro_full_chain_126_hybrid_bit8_gate_is_consumed() {
    // 3. The hybrid path consumes the board-control bit8 enum-fix gate.
    assert!(
        HYBRID_RS.contains("DCENT_AM2_BOARD_CONTROL_BIT8"),
        "s19j_hybrid_mining.rs must consume DCENT_AM2_BOARD_CONTROL_BIT8 \
         (the 2026-06-14 standalone full-roster enum fix)"
    );
}

#[test]
fn s19jpro_full_chain_126_standalone_launcher_contract() {
    // 4a. The proven standalone launcher exists and exports the gate.
    assert!(
        LAUNCHER.contains("export DCENT_AM2_BOARD_CONTROL_BIT8=1"),
        "run_wave56_25_STANDALONE_MINING.sh must export \
         DCENT_AM2_BOARD_CONTROL_BIT8=1"
    );
    // 4b. None of the four must-not-set vars is ever EXPORTED; the launcher
    //     actively scrubs inherited values (unset lines,  guard).
    for forbidden in FORBIDDEN_ENV_VARS {
        assert!(
            !LAUNCHER.contains(&format!("export {forbidden}")),
            "standalone launcher must not export {forbidden} (re-breaks .25-class mining)"
        );
        assert!(
            LAUNCHER.contains(&format!("unset {forbidden}")),
            "standalone launcher must scrub inherited {forbidden} before launch"
        );
    }
}

#[test]
fn s19jpro_full_chain_126_compiled_profile_agrees_with_roster() {
    assert_eq!(
        dcentrald_silicon_profiles::bm1362::chip::CHIPS_PER_CHAIN,
        126
    );
}
