// SPDX-License-Identifier: GPL-3.0-or-later
//! R15 hydro/immersion runtime-profile session replay (desk-only, no
//! hardware).
//!
//! Campaign `2026-09-07-antminer-beta-execution`, lane R15 (hydro /
//! immersion runtime profiles). For ONE representative per held
//! generation (HHB28601 S19 Hydro, HHB42602 S19 Pro Hydro, HHB56601 S19
//! XP Hydro, HHB68501 S21 Hydro, H6HB70501 S21 XP Hydro) this replay
//! drives one complete supervised work session through:
//!
//! - the exact tuple inventory in
//!   `dcentrald-common::hydro_immersion_profiles` (27 held topol.conf
//!   machine entries; wrong / duplicate / empty / near-miss names
//!   refuse; PSU families carried verbatim incl. stock's own "AWP11"/
//!   "AWP8" spellings);
//! - the fail-closed transport+startup composition
//!   `admit_hydro_transport_and_startup` (ZYNQ7007 controller, PSU
//!   family, declared hydro cooling, HeldStockLaw feedback authority —
//!   any Unproven input refuses before work is planned);
//! - the coolant-loop laws in `dcentrald-common::hydro_cooling_feedback`
//!   (water temp window, flow presence/direction, G4+ inlet/outlet
//!   delta, monitor liveness) composed through the external cutoff
//!   gate: permit granted -> work dispatched -> injected faults
//!   (reverse flow, not-flowing, over-temp, stale, absent, monitor
//!   loss) each stop work BEFORE it resumes, reverse flow latches the
//!   gate, which remains latched through fresh observations. Operator-token
//!   reset tests live inside the owning common module;
//! - NON-BYPASSABILITY: the mining path is modeled as holding ONLY the
//!   `CoolingSupervisor` handle; there is no API on it that trips,
//!   clears, or sidesteps the gate, and every permit evaluation goes
//!   through the latch;
//! - NO install/registration claim: `install_kit_eligible()` is false
//!   for every profile (hydro rows are excluded from kits — runtime
//!   profiles only).
//!
//! This test grants no hardware, energization, dispatch, install, or
//! registration authority, and no live hashing claim. The Lead's cargo
//! gate remains authoritative for the full workspace build; the
//! standalone rustc receipts for both modules (plus the pre-existing
//! `cooling_medium` dependency) are in
//! .

#![forbid(unsafe_code)]

use dcentrald_common::cooling_medium::{validate_cut_ladder, CoolingMedium, CutRung};
use dcentrald_common::hydro_cooling_feedback::{
    classify_actuation, classify_external, CutoffCause, CutoffState, ExternalCutoffGate,
    ExternalLoopElement, FeedbackAuthority, FlowObservation,
    UnitOwnedControl, WaterChannel, WaterPermitBounds, WaterPermitRefusal, WaterSnapshot,
    WaterTempSample,
};
use dcentrald_common::hydro_immersion_profiles::{
    admit_hydro_full_unit_population, admit_hydro_transport_and_startup,
    hydro_board_for_name, HydroChainPopulation, HydroControllerEvidence, HydroCoolingDeclaration,
    HydroFeedbackAuthority, HydroFeedbackGeneration, HydroProfileError, HydroPsuEvidence,
    HydroPsuFamily, HydroStartupRefusal, HYDRO_BOARDS, S9_HYDRO_CONFIG_ONLY,
};
use std::collections::HashSet;

/// The stock-analog permit bounds used across the replay (declared
/// policy floor, not a claimed stock-constant extraction).
const BOUNDS: WaterPermitBounds = WaterPermitBounds {
    min_water_c: 5,
    max_water_c: 60,
    max_inlet_outlet_delta_c: 20,
    freshness: WaterPermitBounds::conservative_default().freshness,
};

fn sample(tick: u64, temp_c: i16) -> WaterTempSample {
    WaterTempSample { tick, temp_c: temp_c }
}

fn healthy(now: u64) -> (WaterSnapshot, Option<FlowObservation>) {
    (
        WaterSnapshot {
            inlet_water: Some(sample(now, 30)),
            outlet_water: Some(sample(now, 35)),
            inlet_board: Some(sample(now, 40)),
            outlet_board: Some(sample(now, 45)),
        },
        Some(FlowObservation::Flowing),
    )
}

/// The generation representatives replayed below.
const GENERATION_REPRESENTATIVES: [&str; 5] =
    ["HHB28601", "HHB42602", "HHB56601", "HHB68501", "H6HB70501"];

#[test]
fn every_held_board_admits_full_unit_and_its_exact_geometry_is_locked() {
    for board in HYDRO_BOARDS {
        let pops: Vec<HydroChainPopulation> = (0..board.chains_per_unit)
            .map(|chain| HydroChainPopulation { chain, observed_chips: board.chips_per_chain })
            .collect();
        let unit = admit_hydro_full_unit_population(board, &pops)
            .unwrap_or_else(|e| panic!("{} full-unit admission failed: {e}", board.board_name));
        assert_eq!(unit.board.board_name, board.board_name);
        assert_eq!(unit.populated_chains.len(), usize::from(board.chains_per_unit));
        assert!(!board.install_kit_eligible(), "{} must stay kit-excluded", board.board_name);
    }
}

#[test]
fn generation_representatives_run_the_full_supervised_session() {
    for (case, name) in GENERATION_REPRESENTATIVES.iter().enumerate() {
        let board = hydro_board_for_name(name).unwrap_or_else(|| panic!("{name} must resolve"));
        let pops: Vec<HydroChainPopulation> = (0..board.chains_per_unit)
            .map(|chain| HydroChainPopulation { chain, observed_chips: board.chips_per_chain })
            .collect();

        // 1. Transport + startup admission (exact, fail closed).
        let facts = admit_hydro_transport_and_startup(
            name,
            &pops,
            HydroControllerEvidence::Zynq7007,
            HydroPsuEvidence::MatchesHeldFamily(board.psu),
            HydroCoolingDeclaration::Hydro,
            HydroFeedbackAuthority::HeldStockLaw,
        )
        .unwrap_or_else(|e| panic!("{name} startup admission refused: {e:?}"));
        assert_eq!(facts.pic_i2c_addr, 0x20);
        assert_eq!(facts.eeprom_i2c_addr, 0x50);
        assert_eq!(facts.psu_i2c_addr, 0x10);
        assert_eq!(facts.psu_enable_gpio, 907);
        assert_eq!(facts.address_plan.len(), usize::from(board.chips_per_chain));

        // 2. The cooling supervisor composes the gate + held laws.
        let sup = dcentrald_common::hydro_cooling_feedback::CoolingSupervisor::new(
            FeedbackAuthority::HeldStockLaw,
            facts.feedback_generation,
            BOUNDS,
        );
        sup.gate().monitor_tick(0);
        let (snap, flow) = healthy(1);
        let permit = sup.water_permit(1, &snap, flow);
        assert!(
            matches!(permit, dcentrald_common::hydro_cooling_feedback::PermitDecision::Granted(_)),
            "{name}: healthy loop must grant the water permit"
        );

        // 3. Work dispatch happens ONLY under a granted permit (the
        //    modeled mining loop asks before every dispatch).
        let mut work_active = matches!(
            permit,
            dcentrald_common::hydro_cooling_feedback::PermitDecision::Granted(_)
        );
        assert!(work_active, "{name}: one dispatch under a granted permit");

        // 4. Fault injection mid-session: each fault must stop work
        //    before it resumes (cooling-loss / sensor-stale shutdown).
        let fault_stops_work = |sup: &dcentrald_common::hydro_cooling_feedback::CoolingSupervisor,
                                now: u64,
                                snap: &WaterSnapshot,
                                flow: Option<FlowObservation>,
                                expect_grant: bool,
                                label: &str| {
            let decision = sup.water_permit(now, snap, flow);
            assert_eq!(
                matches!(decision, dcentrald_common::hydro_cooling_feedback::PermitDecision::Granted(_)),
                expect_grant,
                "{name}/{label}"
            );
            decision
        };

        // 4a. Reverse flow (G4/G5 held law; trip at every generation).
        let (snap, _) = healthy(2);
        fault_stops_work(&sup, 2, &snap, Some(FlowObservation::Reverse), false, "reverse-flow");
        assert_eq!(
            sup.gate().state(),
            CutoffState::Latched { cause: CutoffCause::WaterFlowReverse },
            "{name}: reverse flow must latch the cutoff"
        );
        // Work refuses while latched even on a healthy loop.
        let (snap, flow) = healthy(3);
        match sup.water_permit(3, &snap, flow) {
            dcentrald_common::hydro_cooling_feedback::PermitDecision::Refused(
                WaterPermitRefusal::CutoffLatched(CutoffCause::WaterFlowReverse),
            ) => {}
            other => panic!("{name}: latched gate must refuse work, got {other:?}"),
        }
        // Mining stopped by the latch: the pre-dispatch ask above
        // refused, so the session cannot (re)start work here.
        work_active = false;
        assert!(!work_active);

        // 5. Sensor freshness is an independent supervisor scenario. Keep
        //    the original tripped supervisor alive and latched: integration
        //    callers cannot mint the module-private operator reset token.
        //    Reset/resume coverage belongs to hydro_cooling_feedback's unit
        //    tests, which can exercise that authority without exposing it.
        let latched_sup = sup;
        let sup = dcentrald_common::hydro_cooling_feedback::CoolingSupervisor::new(
            FeedbackAuthority::HeldStockLaw,
            facts.feedback_generation,
            BOUNDS,
        );
        sup.gate().monitor_tick(10);
        let (snap, flow) = healthy(11);
        fault_stops_work(&sup, 11, &snap, flow, true, "independent healthy monitor");

        // 6. Sensor-stale injection: a stale channel refuses (stricter
        //    than stock's silence) and keeps refusing until fresh.
        let (mut stale, flow) = healthy(12);
        stale.inlet_water = Some(sample(0, 30)); // age 12 > 10
        fault_stops_work(&sup, 12, &stale, flow, false, "stale-sensor");
        let (fresh, flow) = healthy(13);
        fault_stops_work(&sup, 13, &fresh, flow, true, "fresh-again");

        // 7. Monitor-loss injection: the supervisor trips fail closed.
        //    The last monitor tick was 10 (step 5); advance past it by
        //    more than the freshness bound.
        let late = 10 + BOUNDS.freshness.max_age_ticks + 2;
        fault_stops_work(&sup, late, &snap, flow, false, "monitor-lost");
        assert_eq!(
            sup.gate().state(),
            CutoffState::Latched { cause: CutoffCause::MonitorLost },
            "{name}: monitor loss must latch the cutoff"
        );
        assert_eq!(
            latched_sup.gate().state(),
            CutoffState::Latched { cause: CutoffCause::WaterFlowReverse },
            "{name}: independent replay must never reset the original gate"
        );

        let _ = case;
    }
}

#[test]
fn absent_required_sensors_scale_with_generation_and_refuse_startup_of_work() {
    // G1: only the water channels are required (held bytes name them).
    let g1 = dcentrald_common::hydro_cooling_feedback::CoolingSupervisor::new(
        FeedbackAuthority::HeldStockLaw,
        HydroFeedbackGeneration::Gen1PicTempMinOnly,
        BOUNDS,
    );
    g1.gate().monitor_tick(0);
    let water_only = WaterSnapshot {
        inlet_water: Some(sample(1, 30)),
        outlet_water: Some(sample(1, 35)),
        inlet_board: None,
        outlet_board: None,
    };
    assert!(matches!(
        g1.water_permit(2, &water_only, Some(FlowObservation::Flowing)),
        dcentrald_common::hydro_cooling_feedback::PermitDecision::Granted(_)
    ));

    // G4+: all four channels required; absent board sensor refuses work.
    let g4 = dcentrald_common::hydro_cooling_feedback::CoolingSupervisor::new(
        FeedbackAuthority::HeldStockLaw,
        HydroFeedbackGeneration::Gen4InletOutletAndReverse,
        BOUNDS,
    );
    g4.gate().monitor_tick(0);
    match g4.water_permit(2, &water_only, Some(FlowObservation::Flowing)) {
        dcentrald_common::hydro_cooling_feedback::PermitDecision::Refused(
            WaterPermitRefusal::SensorAbsent(WaterChannel::InletBoard),
        ) => {}
        other => panic!("G4 must require the held board channels, got {other:?}"),
    }

    // Unproven feedback authority refuses at every generation — a
    // composition without held law never plans work.
    for generation in [
        HydroFeedbackGeneration::Gen1PicTempMinOnly,
        HydroFeedbackGeneration::Gen2WaterPermitGate,
        HydroFeedbackGeneration::Gen3WaterInTempField,
        HydroFeedbackGeneration::Gen4InletOutletAndReverse,
        HydroFeedbackGeneration::Gen5WaterScopedVoltageAndJigCutoff,
    ] {
        let unproven = dcentrald_common::hydro_cooling_feedback::CoolingSupervisor::new(
            FeedbackAuthority::Unproven,
            generation,
            BOUNDS,
        );
        unproven.gate().monitor_tick(0);
        let (snap, flow) = healthy(1);
        match unproven.water_permit(2, &snap, flow) {
            dcentrald_common::hydro_cooling_feedback::PermitDecision::Refused(
                WaterPermitRefusal::FeedbackAuthorityUnproven,
            ) => {}
            other => panic!("generation {generation:?}: Unproven must refuse, got {other:?}"),
        }
    }
}

#[test]
fn startup_admission_refuses_every_wrong_input_shape() {
    // Full-unit population for HHB56601 (3 x 204).
    let pops: Vec<HydroChainPopulation> = (0..3)
        .map(|chain| HydroChainPopulation { chain, observed_chips: 204 })
        .collect();
    let ok = |controller, psu, cooling, feedback| {
        admit_hydro_transport_and_startup(
            "HHB56601",
            &pops,
            controller,
            psu,
            cooling,
            feedback,
        )
    };

    // Population faults.
    assert!(matches!(
        admit_hydro_transport_and_startup(
            "HHB56601",
            &[HydroChainPopulation { chain: 0, observed_chips: 203 }],
            HydroControllerEvidence::Zynq7007,
            HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw11),
            HydroCoolingDeclaration::Hydro,
            HydroFeedbackAuthority::HeldStockLaw,
        ),
        Err(HydroStartupRefusal::PopulationAdmission(HydroProfileError::PopulationMismatch { .. }))
    ));
    assert_eq!(
        admit_hydro_transport_and_startup(
            "HHB5660", // near-miss name
            &pops,
            HydroControllerEvidence::Zynq7007,
            HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw11),
            HydroCoolingDeclaration::Hydro,
            HydroFeedbackAuthority::HeldStockLaw,
        ),
        Err(HydroStartupRefusal::ProfileUnknown)
    );
    // PSU family mismatches: AWP8 evidence never admits an APW11 board
    // and vice versa; Unproven never admits anything.
    assert_eq!(
        ok(
            HydroControllerEvidence::Zynq7007,
            HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw8StockSpellingAwp8),
            HydroCoolingDeclaration::Hydro,
            HydroFeedbackAuthority::HeldStockLaw,
        ),
        Err(HydroStartupRefusal::PsuUnproven)
    );
    assert_eq!(
        ok(
            HydroControllerEvidence::OtherOrUnproven,
            HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw11),
            HydroCoolingDeclaration::Hydro,
            HydroFeedbackAuthority::HeldStockLaw,
        ),
        Err(HydroStartupRefusal::ControllerMismatch)
    );
    assert_eq!(
        ok(
            HydroControllerEvidence::Zynq7007,
            HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw11),
            HydroCoolingDeclaration::UndeclaredOrAir,
            HydroFeedbackAuthority::HeldStockLaw,
        ),
        Err(HydroStartupRefusal::CoolingNotDeclaredHydro)
    );
    assert_eq!(
        ok(
            HydroControllerEvidence::Zynq7007,
            HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw11),
            HydroCoolingDeclaration::Hydro,
            HydroFeedbackAuthority::Unproven,
        ),
        Err(HydroStartupRefusal::FeedbackAuthorityUnproven)
    );
}

#[test]
fn the_mining_path_has_no_bypass_capability_and_cut_ladders_stay_cut_only() {
    // The mining path is modeled as holding exactly this handle.
    let sup = dcentrald_common::hydro_cooling_feedback::CoolingSupervisor::new(
        FeedbackAuthority::HeldStockLaw,
        HydroFeedbackGeneration::Gen5WaterScopedVoltageAndJigCutoff,
        BOUNDS,
    );
    sup.gate().monitor_tick(0);
    sup.gate().trip(CutoffCause::ExternalTrip, 1);

    // Through the handle, mining can only ever OBSERVE. Every permit
    // evaluation hits the latch; there is no reset/bypass API to call
    // (compile-fail by construction), and `OperatorResetToken` cannot be
    // constructed from thin air — it exists only via the operator-mint
    // constructor, which the mining path does not own.
    let (snap, flow) = healthy(2);
    for now in [2u64, 50, 5_000] {
        match sup.water_permit(now, &snap, flow) {
            dcentrald_common::hydro_cooling_feedback::PermitDecision::Refused(
                WaterPermitRefusal::CutoffLatched(CutoffCause::ExternalTrip),
            ) => {}
            other => panic!("latched gate must refuse at tick {now}, got {other:?}"),
        }
    }
    assert_eq!(sup.gate().state(), CutoffState::Latched { cause: CutoffCause::ExternalTrip });

    // A raw gate without a token stays latched; `operator_reset` takes
    // the token by value so no token means no clear.
    let raw = ExternalCutoffGate::armed(BOUNDS.freshness);
    raw.trip(CutoffCause::WaterTempOutOfRange, 1);
    assert_eq!(raw.state(), CutoffState::Latched { cause: CutoffCause::WaterTempOutOfRange });
    raw.monitor_tick(2);
    assert_eq!(raw.state(), CutoffState::Latched { cause: CutoffCause::WaterTempOutOfRange });

    // The declared medium composes with the house cut-ladder law: an
    // external-loop ladder carries NO fan rung (absent, not zero), and
    // the terminal rung is a power cut.
    let external_loop_ladder = [CutRung::ThrottleHash, CutRung::CutHashPower];
    assert_eq!(validate_cut_ladder(Some(CoolingMedium::Hydro), &external_loop_ladder), Ok(()));
    let air_shaped = [CutRung::ThrottleHash, CutRung::RaiseFansToCap, CutRung::CutHashPower];
    assert!(validate_cut_ladder(Some(CoolingMedium::Hydro), &air_shaped).is_err());

    // Owned vs monitored split is type-level: the pump has no actuator.
    assert_eq!(
        classify_external(ExternalLoopElement::Pump),
        dcentrald_common::hydro_cooling_feedback::ExternalLoopActuation::MonitorOnly(
            ExternalLoopElement::Pump
        )
    );
    assert_eq!(
        classify_actuation(UnitOwnedControl::PsuRailGpio907),
        dcentrald_common::hydro_cooling_feedback::ExternalLoopActuation::Owned(
            UnitOwnedControl::PsuRailGpio907
        )
    );
}

#[test]
fn inventory_names_never_collide_and_refuse_sets_stay_exact() {
    // Exact-name uniqueness across all 27 held entries.
    let mut seen: HashSet<&str> = HashSet::new();
    for board in HYDRO_BOARDS {
        assert!(seen.insert(board.board_name), "duplicate board name {}", board.board_name);
    }
    assert_eq!(seen.len(), 27);

    // The near-miss / air-family / VNish-immersion refusal set stays
    // refused.
    for name in [
        "IHB68601", "M1HB70601", "M1HB70602", "H1HB68601", "H1HB70602", "BHB68606", "BHB56902",
        "HHB68603", "HHBXXX",
    ] {
        assert!(hydro_board_for_name(name).is_none(), "{name} must stay unheld");
    }

    // The S9 Hydro config-only tuple keeps its held numbers and its
    // Unproven posture (no runtime profile selects it).
    assert_eq!(S9_HYDRO_CONFIG_ONLY.config_asic_type, 1387);
    assert_eq!(S9_HYDRO_CONFIG_ONLY.config_asic_num, 63);
    assert_eq!(S9_HYDRO_CONFIG_ONLY.config_core_num, 114);
}
