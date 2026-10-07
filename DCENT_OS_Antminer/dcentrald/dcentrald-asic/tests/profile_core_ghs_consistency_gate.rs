//! CI gate: `ghs_per_mhz` ↔ `nonce_attribution_cores` consistency (SG-1 pin).
//!
//! Hardware-enablement campaign 2026-08-02, IMPLEMENTATION_QUEUE rank 3
//! (H2 #1, R2 #6). **Gate only — no runtime value is changed by this test.**
//!
//! ## The invariant
//!
//! For a SHA-256 chip where every nonce-attribution slot performs one
//! double-SHA per clock, per-chip hashrate is
//! `freq_MHz × slots × 1e6 H/s`, i.e. `ghs_per_mhz ≈ slots / 1000`.
//! `MinerProfile` carries both numbers ~3 fields apart
//! (`drivers/mod.rs`): `nonce_attribution_cores` feeds the autotuner's
//! hashrate prediction (`expected_nps`, `dcentrald-autotuner/src/lib.rs:165`)
//! while `ghs_per_mhz` feeds nominal-hashrate display math. When they
//! disagree, the autotuner's `min_hashrate_ratio` bar (default 0.70,
//! `config.rs:1871`) is computed against a wrong prediction: a +63% inflated
//! slot count (BM1362) makes a healthy chain look permanently unhealthy and
//! drives real `step_down_freq` throttling (`tuner.rs:5585`).
//!
//! ## Criterion
//!
//! `|ghs_per_mhz*1000 − nonce_attribution_cores| / nonce_attribution_cores
//! ≤ 0.10` for every `MinerProfile` row.
//!
//! ## The allowlist (read before touching)
//!
//! Six rows diverge today. They are pinned BYTE-EXACT below instead of being
//! `#[ignore]`d, so that:
//!   1. the gate passes today (the build stays green),
//!   2. a NEW divergence on any other row fails the build,
//!   3. a silent "correction" of an allowlisted row (changing either value
//!      without shrinking this list) fails the build — the baseline cannot
//!      rot, and rank 24 (the actual value change, default-OFF-flagged) is
//!      FORCED to update this gate in the same commit, proving the intended
//!      sequencing "rank 3 ships and fails before rank 24" (queue §5.1).
//!
//! The queue names four defective rows (BM1362 / BM1370 / BM1397 / BM1398).
//! Direct measurement finds two more rows over the 10% bar — BM1373 and
//! BM1489 — which the queue's count implicitly excluded because both are
//! fail-closed scaffolds outside `ChipRegistry::production()` and BM1489's
//! `ghs_per_mhz` is MH/s-per-MHz (Scrypt), so the SHA-256 identity is not
//! dimensionally applicable. They are allowlisted explicitly (not silently
//! skipped) so that a change to either still trips the gate.

use dcentrald_asic::drivers::MINER_PROFILES;

/// A deliberately-documented divergence, pinned byte-exact.
///
/// `expected_error` is the measured relative error at pin time, recorded for
/// the human reading a failure — the assertions run on the exact
/// (`ghs_per_mhz`, `nonce_attribution_cores`) pair, not on the error.
struct AllowedDivergence {
    chip_id: u16,
    name: &'static str,
    /// Exact `ghs_per_mhz` at pin time (2026-08-02).
    pinned_ghs_per_mhz: f64,
    /// Exact `nonce_attribution_cores` at pin time (2026-08-02).
    pinned_cores: u32,
    /// Measured `|ghs*1000 − cores| / cores` at pin time (documentation).
    expected_error: f64,
    note: &'static str,
}

/// The 2026-08-02 baseline. Shrink this list — never grow it silently.
const ALLOWED_DIVERGENCES: &[AllowedDivergence] = &[
    AllowedDivergence {
        chip_id: 0x1397,
        name: "Antminer S17",
        pinned_ghs_per_mhz: 1.111,
        pinned_cores: 672,
        expected_error: 0.653, // 1111 vs 672 → +65.3%
        note: "ghs_per_mhz (80 TH/s / 144 chips / 500 MHz spec) implies ~1111 \
               slots; the 672 'big engines == slots' claim is unproven by \
               accepted shares. SG-1 family; resolution owned by rank 24's \
               evidence pass — do not change either value here.",
    },
    AllowedDivergence {
        chip_id: 0x1398,
        name: "Antminer S19 Pro",
        pinned_ghs_per_mhz: 0.476,
        pinned_cores: 672,
        expected_error: 0.292, // 476 vs 672 → −29.2%
        note: "the profile's own comment marks the inherited 672-slot \
               work-time model EXPERIMENTAL (never proven by accepted \
               shares); ghs_per_mhz (110 TH/s spec) implies ~476. SG-1 \
               family; rank-24 evidence pass owns resolution.",
    },
    AllowedDivergence {
        chip_id: 0x1362,
        name: "Antminer S19j Pro",
        pinned_ghs_per_mhz: 0.550,
        pinned_cores: 894,
        expected_error: 0.385, // 550 vs 894 → −38.5% (prediction +63% high)
        note: "THE live SG-1 defect: 894 appears borrowed from BM1366; our \
               own ghs_per_mhz (104 TH/s / 378 chips / 500 MHz) implies ~550. \
               Prediction runs +63% high, so a healthy chain yields hashrate \
               ratio ~0.615 and can never clear min_hashrate_ratio 0.70 → \
               persistent step_down_freq throttling of healthy S19j Pro \
               silicon. RANK 24 SHIPPED (2026-08-02, W8): corrected value 514 \
               behind the default-OFF DCENT_SG1_CORRECTED_NONCE_CORES flag \
               (sg1_corrected_nonce_attribution_cores). The DECLARED field \
               stays 894 so flag-off runtime is byte-identical — this entry \
               therefore remains pinned and shrinks only when the default \
               flips. The W6.8 pins in dcentrald-autotuner/src/lib.rs were \
               edited with intent (they now pin the declared default AND the \
               corrected pure path); do not delete them.",
    },
    AllowedDivergence {
        chip_id: 0x1370,
        name: "Antminer S21 Pro",
        pinned_ghs_per_mhz: 2.286,
        pinned_cores: 1280,
        expected_error: 0.786, // 2286 vs 1280 → prediction −44% low
        note: "1280 is copied from BM1368 ('same 1280-slot geometry as \
               BM1368' — asserted, never measured); our own ghs_per_mhz \
               (234 TH/s / 195 chips / 525 MHz spec) implies ~2286. \
               Prediction runs 44% LOW — masks degradation instead of \
               throttling. RANK 24 SHIPPED (2026-08-02, W8): corrected value \
               2040 behind the default-OFF DCENT_SG1_CORRECTED_NONCE_CORES \
               flag, evidenced by OUR OWN live-mining ESP tree (Bitaxe Gamma \
               BM1370 = 2040 small cores, dcentos-esp/dcentaxe/src/api.rs:992 \
               et al.), ePIC-corroborated. The 2286-vs-2040 gap (12.06%) is \
               attributed to the PLACEHOLDER 525 MHz spec frequency inside \
               the ghs_per_mhz derivation and is pinned by \
               sg1_rank24_corrected_values below. The DECLARED field stays \
               1280 so flag-off runtime is byte-identical — this entry \
               shrinks only when the default flips.",
    },
    AllowedDivergence {
        chip_id: 0x1373,
        name: "Antminer S23",
        pinned_ghs_per_mhz: 2.140,
        pinned_cores: 6860,
        expected_error: 0.688, // 2140 vs 6860
        note: "fail-closed scaffold, excluded from ChipRegistry::production(). \
               BOTH values are placeholders from different sources \
               (ghs_per_mhz from the 318 TH/s spec estimate; 6860 from \
               NerdQAxePlus BM1373_SMALL_CORE_COUNT RE). Not part of the \
               queue's four-row SG-1 count; pinned so live S23 bring-up must \
               reconcile them deliberately.",
    },
    AllowedDivergence {
        chip_id: 0x1489,
        name: "Antminer L9",
        pinned_ghs_per_mhz: 0.0466,
        pinned_cores: 12,
        expected_error: 2.883, // 46.6 vs 12
        note: "Scrypt scaffold: ghs_per_mhz is documented as MH/s-per-MHz per \
               chip (NOT GH/s), so the SHA-256 slots≈ghs×1000 identity is not \
               dimensionally applicable; cores=12 is itself a [GAP] \
               placeholder. Excluded from production registry. Pinned, not \
               skipped, so unit-semantics changes trip this gate.",
    },
];

/// Relative error of the slots↔ghs identity for one profile.
fn relative_error(ghs_per_mhz: f64, nonce_attribution_cores: u32) -> f64 {
    let implied = ghs_per_mhz * 1000.0;
    (implied - nonce_attribution_cores as f64).abs() / nonce_attribution_cores as f64
}

const MAX_ERROR: f64 = 0.10;

#[test]
fn ghs_per_mhz_and_nonce_attribution_cores_are_consistent_or_allowlisted() {
    let mut failures: Vec<String> = Vec::new();

    // Always print the full divergence table so CI output documents SG-1
    // even while the gate passes (visible with `--nocapture` and on failure).
    println!();
    println!(
        "SG-1 divergence table: |ghs_per_mhz*1000 - nonce_attribution_cores| / cores (bar {MAX_ERROR:.2})"
    );
    println!(
        "{:<18} {:>8} {:>12} {:>12} {:>9}  status",
        "profile", "chip", "ghs*1000", "cores", "error"
    );
    for profile in MINER_PROFILES {
        let implied = profile.ghs_per_mhz * 1000.0;
        let err = relative_error(profile.ghs_per_mhz, profile.nonce_attribution_cores);
        let allow = ALLOWED_DIVERGENCES
            .iter()
            .find(|a| a.chip_id == profile.chip_id);
        let status = match (err <= MAX_ERROR, allow.is_some()) {
            (true, false) => "OK",
            (true, true) => "OK-BUT-ALLOWLISTED (stale entry)",
            (false, true) => "DIVERGENT (allowlisted baseline)",
            (false, false) => "DIVERGENT (NOT allowlisted) — FAIL",
        };
        println!(
            "{:<18} 0x{:04X} {:>12.1} {:>12} {:>8.1}%  {status}",
            profile.name,
            profile.chip_id,
            implied,
            profile.nonce_attribution_cores,
            err * 100.0,
        );

        match (err <= MAX_ERROR, allow) {
            (true, None) => {} // consistent, nothing pinned — the goal state.
            (true, Some(a)) => failures.push(format!(
                "{} (0x{:04X}): now CONSISTENT (error {:.1}% <= {:.0}%) but still \
                 allowlisted. Shrink ALLOWED_DIVERGENCES in \
                 tests/profile_core_ghs_consistency_gate.rs in the same commit \
                 so the baseline cannot rot. (Pinned note: {})",
                profile.name,
                profile.chip_id,
                err * 100.0,
                MAX_ERROR * 100.0,
                a.note
            )),
            (false, None) => failures.push(format!(
                "{} (0x{:04X}): NEW divergence — ghs_per_mhz {} implies ~{:.0} \
                 slots but nonce_attribution_cores is {} (error {:.1}% > {:.0}%). \
                 Either fix the inconsistent value (with evidence) or add a \
                 documented AllowedDivergence entry explaining why both numbers \
                 are simultaneously correct.",
                profile.name,
                profile.chip_id,
                profile.ghs_per_mhz,
                implied,
                profile.nonce_attribution_cores,
                err * 100.0,
                MAX_ERROR * 100.0,
            )),
            (false, Some(a)) => {
                // Divergent AND allowlisted: the pinned pair must be
                // byte-exact. Any drift — including the rank-24 value change
                // itself — must update this gate deliberately.
                if profile.ghs_per_mhz != a.pinned_ghs_per_mhz
                    || profile.nonce_attribution_cores != a.pinned_cores
                {
                    failures.push(format!(
                        "{} (0x{:04X}): allowlisted divergence CHANGED without \
                         updating the baseline. Pinned (ghs_per_mhz={}, cores={}), \
                         found (ghs_per_mhz={}, cores={}). If this is the rank-24 \
                         correction, update/remove this AllowedDivergence entry in \
                         the same commit (and update the W6.8 autotuner pins with \
                         intent). Pinned note: {}",
                        profile.name,
                        profile.chip_id,
                        a.pinned_ghs_per_mhz,
                        a.pinned_cores,
                        profile.ghs_per_mhz,
                        profile.nonce_attribution_cores,
                        a.note
                    ));
                }
            }
        }
    }

    // Dead allowlist entries (chip removed/renamed) must not linger.
    for a in ALLOWED_DIVERGENCES {
        if !MINER_PROFILES.iter().any(|p| p.chip_id == a.chip_id) {
            failures.push(format!(
                "AllowedDivergence for {} (0x{:04X}) references a chip_id with no \
                 MinerProfile row — remove the stale entry.",
                a.name, a.chip_id
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "\nghs_per_mhz <-> nonce_attribution_cores consistency gate failed:\n - {}\n",
        failures.join("\n - ")
    );
}

/// The recorded `expected_error` documentation values must themselves match
/// the measured errors (±0.5 percentage point), so the table above cannot
/// quietly desynchronise from the pinned pairs.
#[test]
fn allowlist_documented_errors_match_measured_errors() {
    for a in ALLOWED_DIVERGENCES {
        let measured = relative_error(a.pinned_ghs_per_mhz, a.pinned_cores);
        assert!(
            (measured - a.expected_error).abs() < 0.005,
            "{} (0x{:04X}): AllowedDivergence.expected_error {} does not match the \
             error {:.4} computed from its own pinned pair — fix the documentation \
             field.",
            a.name,
            a.chip_id,
            a.expected_error,
            measured
        );
        assert!(
            measured > MAX_ERROR,
            "{} (0x{:04X}): pinned pair is within the {:.0}% bar — this entry \
             should not exist.",
            a.name,
            a.chip_id,
            MAX_ERROR * 100.0
        );
    }
}

/// Rank 24 (SG-1 value change, 2026-08-02): the corrected slot counts are
/// pinned byte-exact and each is adjudicated against OUR OWN `ghs_per_mhz`
/// — ePIC only supplied candidates and never outranks our own measurement.
///
/// - BM1362 894→514: our ghs_per_mhz 0.550 implies ~550; 514 is 7.0% off —
///   INSIDE the 10% bar. The correction is admitted by our own data.
/// - BM1370 1280→2040: our ghs_per_mhz 2.286 implies ~2286; 2040 is 12.06%
///   off — OUTSIDE the bar, because 2.286 stands on the PLACEHOLDER 525 MHz
///   spec frequency (drivers/mod.rs marks the whole S21 Pro row "estimated
///   from spec sheets"). The 2040 value is held in OUR OWN live-mining ESP
///   tree (Bitaxe Gamma BM1370: dcentos-esp/dcentaxe/src/api.rs:992,
///   capabilities.rs:237, cgminer_tcp.rs:641, main.rs:853). The residual is
///   pinned here so it cannot silently drift: if ghs_per_mhz is ever
///   re-derived and the error moves, this test forces a deliberate update.
#[test]
fn sg1_rank24_corrected_values() {
    use dcentrald_asic::drivers::sg1_corrected_nonce_attribution_cores;

    // BM1362: corrected value pinned, and consistent with our own ghs_per_mhz.
    assert_eq!(sg1_corrected_nonce_attribution_cores(0x1362), Some(514));
    let bm1362_err = relative_error(0.550, 514);
    assert!(
        (bm1362_err - 0.0700).abs() < 0.005,
        "BM1362 corrected-value error vs our own ghs_per_mhz drifted: {bm1362_err:.4} (pinned 0.0700)"
    );
    assert!(
        bm1362_err <= MAX_ERROR,
        "BM1362 corrected value 514 must be consistent with our own ghs_per_mhz \
         0.550 within the {MAX_ERROR:.2} bar — it measured {bm1362_err:.4}. If this \
         fails, the rank-24 premise is broken; do not paper over it."
    );

    // BM1370: corrected value pinned; the 12.06% residual vs the
    // placeholder-frequency-derived 2286 is documented, not hidden.
    assert_eq!(sg1_corrected_nonce_attribution_cores(0x1370), Some(2040));
    let bm1370_err = relative_error(2.286, 2040);
    assert!(
        (bm1370_err - 0.1206).abs() < 0.005,
        "BM1370 corrected-value residual vs our own ghs_per_mhz drifted: \
         {bm1370_err:.4} (pinned 0.1206). If ghs_per_mhz was re-derived, update \
         this pin AND the AllowedDivergence note deliberately."
    );

    // No other chip carries a silent correction.
    for profile in MINER_PROFILES {
        if profile.chip_id != 0x1362 && profile.chip_id != 0x1370 {
            assert_eq!(
                sg1_corrected_nonce_attribution_cores(profile.chip_id),
                None,
                "{}: unexpected SG-1 correction entry — every corrected chip must \
                 be adjudicated in this test with file:line evidence",
                profile.name
            );
        }
    }
}

/// Mode selector for the SG-1 wiring child processes (mirrors the
/// `process_environment_source_contract` child-process pattern in
/// `src/lib.rs` — the dcentrald-asic source contract bans process-global
/// env mutation, so flag-on behaviour is exercised in spawned children
/// whose environment is set at spawn time via `Command::env`).
const SG1_WIRING_CHILD_ENV: &str = "DCENT_SG1_WIRING_CONTRACT_CHILD";

/// Assertions shared by the parent (flag unset) and the spawned children:
/// the PRODUCTION accessors (`nonce_attribution_cores_effective` /
/// `expected_nps`) must reflect exactly the corrected-or-declared choice
/// implied by the process environment.
fn assert_sg1_effective(corrected_active: bool) {
    use dcentrald_asic::drivers::MinerProfile;

    let bm1362 = MinerProfile::for_chip(0x1362).expect("BM1362 profile");
    let bm1368 = MinerProfile::for_chip(0x1368).expect("BM1368 profile");
    let bm1370 = MinerProfile::for_chip(0x1370).expect("BM1370 profile");

    if corrected_active {
        assert_eq!(
            bm1362.nonce_attribution_cores_effective(),
            514,
            "flag on: BM1362 effective slot count must be the corrected 514"
        );
        assert_eq!(
            bm1370.nonce_attribution_cores_effective(),
            2040,
            "flag on: BM1370 effective slot count must be the corrected 2040"
        );
    } else {
        for profile in MINER_PROFILES {
            assert_eq!(
                profile.nonce_attribution_cores_effective(),
                profile.nonce_attribution_cores,
                "{}: with the flag inactive, effective slot count must be \
                 byte-identical to the declared field",
                profile.name
            );
        }
    }
    // BM1368 (measured 80×16, SG-1-exempt) is untouched in every mode.
    assert_eq!(bm1368.nonce_attribution_cores_effective(), 1280);

    // The production prediction formula must route through the same
    // effective value (env-resolved `expected_nps` == pure form with the
    // mode's expected correction choice).
    let nps = bm1362.expected_nps(500, 256);
    let expected = bm1362.expected_nps_with_correction(500, 256, corrected_active);
    assert!(
        (nps - expected).abs() < f64::EPSILON,
        "expected_nps must follow the env-resolved correction choice \
         (corrected_active={corrected_active}, nps={nps}, expected={expected})"
    );
    // And the two pure forms differ by exactly 514/894 for BM1362, so the
    // corrected path is provably distinct from the declared one.
    let ratio = bm1362.expected_nps_with_correction(500, 256, true)
        / bm1362.expected_nps_with_correction(500, 256, false);
    assert!(
        (ratio - 514.0 / 894.0).abs() < 1e-12,
        "corrected/declared BM1362 prediction ratio must be 514/894, got {ratio}"
    );
}

/// Spawn this test binary again with `SG1_WIRING_CHILD_ENV` selecting a
/// mode and the SG-1 flag injected at spawn time (never mutated in-process).
fn run_sg1_wiring_child(mode: &str) {
    use dcentrald_asic::drivers::SG1_CORRECTED_NONCE_CORES_ENV;

    let current_exe = std::env::current_exe().expect("current gate test executable");
    let mut child = std::process::Command::new(current_exe);
    child
        .arg("--exact")
        .arg("sg1_flag_default_off_then_env_wires_production_path")
        .arg("--nocapture")
        .env(SG1_WIRING_CHILD_ENV, mode);
    match mode {
        "flag-unset" => {
            child.env_remove(SG1_CORRECTED_NONCE_CORES_ENV);
        }
        "flag-1" => {
            child.env(SG1_CORRECTED_NONCE_CORES_ENV, "1");
        }
        // Any value other than exactly "1" must NOT enable the correction.
        "flag-true" => {
            child.env(SG1_CORRECTED_NONCE_CORES_ENV, "true");
        }
        other => panic!("unknown SG-1 wiring mode: {other}"),
    }
    let status = child.status().expect("run isolated SG-1 wiring child");
    assert!(
        status.success(),
        "{mode} SG-1 wiring child failed: {status}"
    );
}

/// Rank 24 flag contract: with `DCENT_SG1_CORRECTED_NONCE_CORES` unset (or
/// set to anything but exactly `"1"`), every effective slot count and every
/// `expected_nps` prediction is byte-identical to the declared values
/// (default-OFF); with it set to `"1"` in a compiled lab build, the corrected
/// values flow through the accessors. Production builds ignore hardware
/// environment overrides, including this flag. Flag-on/odd-value
/// modes run in child processes per the dcentrald-asic env source contract.
#[test]
fn sg1_flag_default_off_then_env_wires_production_path() {
    use dcentrald_asic::drivers::SG1_CORRECTED_NONCE_CORES_ENV;

    match std::env::var(SG1_WIRING_CHILD_ENV) {
        Ok(mode) if mode == "flag-1" => assert_sg1_effective(dcentrald_common::lab_env::compiled()),
        Ok(mode) if mode == "flag-unset" || mode == "flag-true" => assert_sg1_effective(false),
        Ok(other) => panic!("unknown SG-1 wiring mode: {other}"),
        Err(_) => {
            // Parent: CI must run with the flag globally unset — fail loudly
            // (rather than silently changing baselines) if it is not.
            assert_ne!(
                std::env::var(SG1_CORRECTED_NONCE_CORES_ENV).ok().as_deref(),
                Some("1"),
                "the SG-1 correction flag must not be globally enabled in CI"
            );
            assert_sg1_effective(false);
            run_sg1_wiring_child("flag-unset");
            run_sg1_wiring_child("flag-1");
            run_sg1_wiring_child("flag-true");
        }
    }
}
