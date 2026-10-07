use super::*;

#[test]
fn all_selected_rail_and_four_fans_are_required_without_fabricated_values() {
    let fans = vec![(0, 1800), (1, 1900), (2, 2000), (3, 1800)];
    assert!(validate_fans(&fans, 1800).is_ok());
    for slot in 0..4 {
        let mut bad = fans.clone();
        bad[slot].1 = 0;
        assert!(validate_fans(&bad, 1800).is_err());
        let mut duplicate = fans.clone();
        duplicate[slot].0 = 9;
        assert!(validate_fans(&duplicate, 1800).is_err());
    }
    assert!(validate_fans(&fans[..3], 1800).is_err());
    let rails = vec![
        ClassicVoltage {
            chain: 1,
            raw_be: [2, 0x31],
            volts: 13.38328,
        },
        ClassicVoltage {
            chain: 3,
            raw_be: [2, 0x31],
            volts: 13.38328,
        },
    ];
    assert!(validate_voltages(&rails, &[1, 3], 13.4).is_ok());
    assert!(validate_voltages(&rails, &[1, 2], 13.4).is_err());
    assert!(validate_voltages(&rails[..1], &[1, 3], 13.4).is_err());
    assert!(validate_voltages(&rails, &[1, 3], 13.8).is_err());
    assert!(validate_voltages(
        &[ClassicVoltage {
            chain: 1,
            raw_be: [0; 2],
            volts: f64::NAN
        }],
        &[1],
        13.4
    )
    .is_err());
}

#[test]
fn cleanup_requires_every_selected_cut_ack_and_all_retained_owners() {
    let mut report = ClassicPowerCloseReport {
        issuer: Arc::new(()),
        cutoff_started: Some(Instant::now()),
        cutoff_observed_at: Some(Instant::now()),
        finished_at: Instant::now(),
        controls: ClassicControlCut {
            attempted_at: Some(Instant::now()),
            rail_observed_at: Some(Instant::now()),
            rail_off: true,
            resets_held: true,
            quiet_fans: true,
            errors: vec![],
        },
        pic: Some(ClassicCloseReport {
            cuts: vec![(1, Ok(())), (3, Ok(()))],
            workers_closed: true,
        }),
        psu_closed: true,
        errors: vec![],
    };
    assert!(report.software_cleanup_complete());
    report.pic.as_mut().unwrap().cuts[1].1 = Err("NACK".into());
    assert!(!report.software_cleanup_complete());
    report.pic.as_mut().unwrap().cuts[1].1 = Ok(());
    report.psu_closed = false;
    assert!(!report.software_cleanup_complete());
}
