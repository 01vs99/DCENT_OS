use super::*;

struct OriginalCase {
    label: &'static str,
    current: u64,
    target: u64,
    step: u64,
    previous: u64,
    repeats_before: u32,
    expected_request: Option<u64>,
    // 0=request, 1=unchanged, 2=within tolerance, 3=outside tolerance.
    expected_decision: u8,
    previous_after: u64,
    repeats_after: u32,
}

include!("bb_voltage_planner_vectors.rs");

#[test]
fn original_arm_requests_history_and_tolerance_match_exact_bits() {
    assert_eq!(ORIGINAL_CASES.len(), 113);
    for case in ORIGINAL_CASES {
        let plan = source_step(
            f64::from_bits(case.current),
            f64::from_bits(case.target),
            f64::from_bits(case.step),
            History {
                previous_request: Some(f64::from_bits(case.previous)),
                repeated_requests: case.repeats_before,
            },
        )
        .unwrap();
        let (decision, request) = match plan.decision {
            Decision::Request(value) => (0, Some(value.to_bits())),
            Decision::UnchangedCentivolts => (1, None),
            Decision::HistoryTolerance {
                within_source_tolerance: true,
            } => (2, None),
            Decision::HistoryTolerance {
                within_source_tolerance: false,
            } => (3, None),
        };
        assert_eq!(decision, case.expected_decision, "{}", case.label);
        assert_eq!(request, case.expected_request, "{}", case.label);
        assert_eq!(
            plan.history.previous_request.unwrap().to_bits(),
            case.previous_after,
            "{}",
            case.label
        );
        assert_eq!(
            plan.history.repeated_requests, case.repeats_after,
            "{}",
            case.label
        );
    }
}

#[test]
fn native_admission_refuses_source_full_target_fallback_steps() {
    let history = History {
        previous_request: None,
        repeated_requests: 0,
    };
    for step in [
        0.0,
        -0.0,
        -0.05,
        0.005,
        0.009999,
        f64::NAN,
        f64::INFINITY,
        f64::MAX,
    ] {
        assert_eq!(
            plan_step(13.8, 14.92, step, history),
            Err(PlanError::InvalidStep)
        );
    }
    let plan = plan_step(13.8, 14.92, SOURCE_DEFAULT_STEP_VOLTS, history).unwrap();
    assert_eq!(
        plan.decision,
        Decision::Request(f64::from_bits(4623986474909643571))
    );
    assert_eq!(plan.history.repeated_requests, 0);
}

#[test]
fn invalid_numbers_and_uninitialized_or_overflowing_history_are_refused() {
    let empty = History {
        previous_request: None,
        repeated_requests: 0,
    };
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, f64::MAX, -1.0] {
        assert_eq!(
            plan_step(value, 14.92, 0.05, empty),
            Err(PlanError::InvalidVoltage)
        );
        assert_eq!(
            plan_step(13.8, value, 0.05, empty),
            Err(PlanError::InvalidVoltage)
        );
        assert_eq!(
            plan_step(
                13.8,
                14.92,
                0.05,
                History {
                    previous_request: Some(value),
                    repeated_requests: 0,
                }
            ),
            Err(PlanError::InvalidHistory)
        );
    }
    assert_eq!(
        plan_step(
            13.8,
            14.92,
            0.05,
            History {
                previous_request: None,
                repeated_requests: 1,
            }
        ),
        Err(PlanError::InvalidHistory)
    );
    let first = plan_step(13.8, 14.92, 0.05, empty).unwrap();
    assert_eq!(
        plan_step(
            13.8,
            14.92,
            0.05,
            History {
                previous_request: first.history.previous_request,
                repeated_requests: u32::MAX,
            }
        ),
        Err(PlanError::RepeatCounterOverflow)
    );
}

#[test]
fn actual_original_truncation_helper_cases_match_native_operation() {
    assert_eq!(TRUNC_CASES.len(), 18);
    for &(input, expected) in TRUNC_CASES {
        assert_eq!(f64::from_bits(input).trunc().to_bits(), expected);
    }
}
