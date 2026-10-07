use super::*;

struct SelectionCase {
    label: &'static str,
    target: Option<u64>,
    step: Option<u64>,
    current: u64,
    error: Option<ProfileError>,
    pair: Option<(u64, u64)>,
}

struct MergeCase {
    label: &'static str,
    before_target: Option<u64>,
    before_step: Option<u64>,
    request_target: Option<u64>,
    request_step: Option<u64>,
    error: Option<ProfileError>,
    after_target: Option<u64>,
    after_step: Option<u64>,
}

struct ParserCase {
    label: &'static str,
    step: bool,
    bits: u64,
    original_accepted: bool,
    native_accepted: bool,
}

include!("bb_voltage_profile_vectors.rs");

#[test]
fn original_hw76_bounds_and_default_step_match_exact_bits() {
    assert_eq!(SOURCE_MIN_VOLTS.to_bits(), ORIGINAL_BOUNDS[0]);
    assert_eq!(SOURCE_MAX_VOLTS.to_bits(), ORIGINAL_BOUNDS[1]);
    assert_eq!(SOURCE_MIN_STEP_VOLTS.to_bits(), ORIGINAL_BOUNDS[2]);
    assert_eq!(SOURCE_MAX_STEP_VOLTS.to_bits(), ORIGINAL_BOUNDS[3]);
    assert_eq!(SOURCE_DEFAULT_STEP_VOLTS.to_bits(), ORIGINAL_DEFAULT_STEP);
}

#[test]
fn original_stored_profile_selection_matches_or_is_deliberately_refused() {
    assert_eq!(SELECTION_CASES.len(), 32);
    for case in SELECTION_CASES {
        let mut profile = Hw76RequestedVoltageProfile::default();
        let result = profile.merge_request(
            case.target.map(f64::from_bits),
            case.step.map(f64::from_bits),
        );
        assert_eq!(result.err(), case.error, "{}", case.label);
        if case.error.is_none() {
            let actual = profile.select_pair(f64::from_bits(case.current)).unwrap();
            assert_eq!(
                actual.map(|pair| (pair.target.to_bits(), pair.maximum_step.to_bits())),
                case.pair,
                "{}",
                case.label
            );
        } else {
            assert_eq!(profile, Hw76RequestedVoltageProfile::default());
        }
    }
}

#[test]
fn original_partial_merge_fields_match_and_refusals_are_atomic() {
    assert_eq!(MERGE_CASES.len(), 28);
    for case in MERGE_CASES {
        let mut profile = Hw76RequestedVoltageProfile::default();
        profile
            .merge_request(
                case.before_target.map(f64::from_bits),
                case.before_step.map(f64::from_bits),
            )
            .unwrap();
        let before = profile;
        let result = profile.merge_request(
            case.request_target.map(f64::from_bits),
            case.request_step.map(f64::from_bits),
        );
        assert_eq!(result.err(), case.error, "{}", case.label);
        if case.error.is_some() {
            assert_eq!(profile, before, "{}", case.label);
        } else {
            assert_eq!(profile.target.map(f64::to_bits), case.after_target);
            assert_eq!(profile.step_override.map(f64::to_bits), case.after_step);
        }
    }
}

#[test]
fn original_parsed_boundaries_match_except_explicit_nan_refusal() {
    assert_eq!(PARSER_CASES.len(), 29);
    let mut differences = 0;
    for case in PARSER_CASES {
        let mut profile = Hw76RequestedVoltageProfile::default();
        let value = Some(f64::from_bits(case.bits));
        let result = if case.step {
            profile.merge_request(None, value)
        } else {
            profile.merge_request(value, None)
        };
        assert_eq!(result.is_ok(), case.native_accepted, "{}", case.label);
        if case.original_accepted != case.native_accepted {
            assert!(case.step && f64::from_bits(case.bits).is_nan());
            assert_eq!(result, Err(ProfileError::InvalidStep));
            differences += 1;
        }
    }
    assert_eq!(differences, 2);
}

#[test]
fn invalid_current_and_mixed_bad_updates_cannot_change_requested_state() {
    let mut profile = Hw76RequestedVoltageProfile::default();
    profile.merge_request(Some(13.4), Some(0.07)).unwrap();
    let before = profile;
    for (target, step) in [
        (Some(14.0), Some(f64::NAN)),
        (Some(f64::NAN), Some(0.09)),
        (Some(15.12001), Some(0.09)),
        (Some(14.0), Some(0.049999)),
        (Some(14.0), Some(10.00001)),
    ] {
        assert!(profile.merge_request(target, step).is_err());
        assert_eq!(profile, before);
    }
    for current in [f64::NAN, f64::INFINITY, -1.0, 11.87999, 15.12001] {
        assert_eq!(
            profile.select_pair(current),
            Err(ProfileError::InvalidCurrent)
        );
        assert_eq!(profile, before);
    }
    profile.merge_request(None, None).unwrap();
    assert_eq!(profile, before);
    profile.merge_request(Some(14.0), None).unwrap();
    assert_eq!(profile.step_override, Some(0.07));
    assert_eq!(profile.select_pair(14.009).unwrap(), None);
}
