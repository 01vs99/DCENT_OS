//! Actual model-specific startup and work over the independent host wire rig.
//! No ready token, receipt timestamp, power GPIO or physical device is injected.
use super::*;

fn until() -> Instant {
    Instant::now() + Duration::from_secs(150)
}

fn packet() -> Vec<u8> {
    // Fixed-EN2 HAL grammar fixture; CPU proof belongs to daemon probe tests.
    let mut bytes = vec![0; 0x58 + 16 + 2];
    bytes[0] = 0x52;
    let length = bytes.len() as u32 - 8;
    bytes[4..8].copy_from_slice(&length.to_le_bytes());
    bytes[9] = 3;
    bytes[10] = 0x0f;
    bytes[16..20].copy_from_slice(&4u32.to_be_bytes());
    bytes[60..62].copy_from_slice(&16u16.to_le_bytes());
    bytes[84..88].copy_from_slice(&1u32.to_le_bytes());
    let mut crc = 0xffffu16;
    for byte in &bytes[..bytes.len() - 2] {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
        }
    }
    let end = bytes.len();
    bytes[end - 2..].copy_from_slice(&crc.to_le_bytes());
    bytes
}

#[tokio::test]
async fn s17e_simulated_rail_frames_match_original_separate_adc_vectors() {
    let rig = Rig::observe_model(Model::S17e, vec![0], Vec::new())
        .await
        .unwrap();
    // Drive the simulator's actual management TX parser, without a source
    // enable, startup receipt or caller-injected voltage state.
    for byte in [0x55u8, 0xaa, 6, 0x83, 48, 0, 0xb9, 0] {
        rig.hardware
            .management_command(0x0520_1100 | u32::from(byte))
            .unwrap();
    }
    assert_eq!(
        rig.hardware
            .replies
            .lock()
            .unwrap()
            .drain(..)
            .collect::<Vec<_>>(),
        vec![0x55, 0xaa, 6, 0x83, 48, 0, 0xb9, 0]
    );
    for byte in [0x55u8, 0xaa, 4, 0x29, 0, 0x2d] {
        rig.hardware
            .management_command(0x0040_0000 | u32::from(byte))
            .unwrap();
    }
    let voltage: Vec<_> = rig.hardware.replies.lock().unwrap().drain(..).collect();
    assert_eq!(voltage, [9, 0x29, 1, 0x0c, 0x80, 0, 0, 0, 0xbf]);
    for byte in [0x55u8, 0xaa, 4, 0x28, 0, 0x2c] {
        rig.hardware
            .management_command(0x0040_0000 | u32::from(byte))
            .unwrap();
    }
    let reference: Vec<_> = rig.hardware.replies.lock().unwrap().drain(..).collect();
    assert_eq!(
        reference,
        [13, 0x28, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x0b, 0xe0, 3, 0x8a]
    );
    let (raw, reference_raw, volts) =
        management::rail::decode(Model::S17e, &voltage, Some(&reference)).unwrap();
    assert_eq!((raw, reference_raw), (3200, 3040));
    assert!((volts - 20.0).abs() < 0.001);
    assert!(management::rail::decode(Model::T17e, &voltage, Some(&reference)).is_err());
    assert!(!rig.hardware.events().iter().any(|event| matches!(
        event,
        WireEvent::Source { high: false, .. } | WireEvent::Job { .. }
    )));
    rig.owner.drain(until()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s17e_actual_factory_startup_reaches_fixed_baseline_addressed_pll_and_owned_work() {
    let rig = Rig::observe_model(Model::S17e, vec![0, 2], Vec::new())
        .await
        .unwrap();
    let owner = &rig.owner;
    let app = &rig.pic;
    assert!(app.native_pll_observation().unwrap().is_none());
    owner.acquire_factory_calibration(until()).await.unwrap();
    app.observe_supply_type(until()).await.unwrap();
    app.observe_versions(until()).await.unwrap();
    for _ in 0..5 {
        app.heartbeat_round(until()).await.unwrap();
    }
    let heartbeats = {
        let app = app.clone();
        let owner = owner.clone();
        tokio::spawn(async move {
            while !owner.is_terminal() {
                app.heartbeat_round(Instant::now() + Duration::from_secs(2))
                    .await?;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok::<(), String>(())
        })
    };
    let start_at = rig.line.source_enable_not_before().unwrap();
    tokio::time::sleep_until(tokio::time::Instant::from_std(start_at)).await;
    let quiet = owner.quiet_fans(until()).await.unwrap();
    let fans = owner.sample_fan_tach(until()).await.unwrap();
    rig.line
        .enable_source_after_observations(app.clone(), quiet, fans, until())
        .await
        .unwrap();
    app.initialize_conditioning_reset(rig.line.clone(), until())
        .await
        .unwrap();
    app.initialize_conditioning_preparation(rig.line.clone(), 75, until())
        .await
        .unwrap();
    let sequence = app
        .initialize_conditioning_pll(rig.line.clone(), until())
        .await
        .unwrap();
    assert!(sequence.completed_at().is_some() && sequence.failure().is_none());
    assert_eq!(
        sequence.profile(),
        dcentrald_common::bm1396_auto_adapt_voltage::Bm1396AutoAdaptProfile::Signed2020S17eFixed
    );
    assert_eq!(sequence.operational_baud().baud(), 6_000_000);
    assert!(sequence.stages().iter().any(|s| !s.before_adc().is_empty()));
    let factory = owner.s17e_factory_records().unwrap();
    for (chain, record) in factory {
        let mut applied = [0; 135];
        for command in sequence
            .stages()
            .iter()
            .flat_map(|s| s.commands())
            .filter(|c| c.chain() == chain)
        {
            assert!(command.completed_at().is_some());
            let mhz = dcentrald_common::bm1396_s17e_factory::register_frequency_mhz(
                command.register_value(),
            )
            .unwrap();
            match command.chip_ordinal() {
                Some(chip) => applied[usize::from(chip)] = mhz,
                None => applied.fill(mhz),
            }
        }
        for (got, expected) in applied.into_iter().zip(record.frequencies_mhz()) {
            assert!(got.abs_diff(*expected) <= 1);
        }
    }
    assert!(app.adapted_startup_observation().unwrap().is_none());
    assert!(app.final_pll_observation().unwrap().is_none());
    let native = app.native_pll_observation().unwrap().unwrap();
    assert!(native.same_owner(owner));
    assert_eq!(native.model(), Model::S17e);
    assert_eq!(native.epoch(), 0);
    assert_eq!(native.completed_frequency_mhz(), Some(310));
    assert_eq!(native.timeout_base(), Some(380));
    let (control, mut events, _, inbox) = app.fixed_work_channels();
    control
        .enqueue_publication(packet(), until())
        .await
        .unwrap();
    let task = {
        let app = app.clone();
        let line = rig.line.clone();
        tokio::spawn(async move { app.serve_fixed_work(line, inbox, until()).await })
    };
    let publication = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.next().await.expect("actual work event owner") {
                FixedWorkEvent::Publication(publication) => break publication,
                FixedWorkEvent::Thermal(snapshot) => {
                    assert_eq!(snapshot.epoch(), 0);
                    control
                        .acknowledge_thermal(snapshot, until())
                        .await
                        .unwrap();
                }
                other => panic!("unexpected modeled work event: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
    assert!(publication.completed() && publication.same_owner(owner));
    assert_eq!(publication.job_id(), 0);
    assert!(rig
        .hardware
        .events()
        .iter()
        .any(|event| matches!(event, WireEvent::Job { id: 0, .. })));
    owner.begin_terminal();
    rig.line.terminal_high(until()).await.unwrap();
    assert!(task.await.unwrap().is_err());
    heartbeats.abort();
    let _ = heartbeats.await;
    owner.drain(until()).await.unwrap();
    assert!(rig.hardware.source_high() && !rig.hardware.overflowed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s17e_cannot_use_t17e_final_pass_or_publish_without_actual_factory_startup() {
    let rig = Rig::observe_model(Model::S17e, vec![0], Vec::new())
        .await
        .unwrap();
    assert!(rig
        .pic
        .initialize_final_pll(rig.line.clone(), until())
        .await
        .is_err());
    let (_, _events, _, inbox) = rig.pic.fixed_work_channels();
    assert!(rig
        .pic
        .serve_fixed_work(rig.line.clone(), inbox, until())
        .await
        .is_err());
    assert!(!rig.hardware.events().iter().any(|event| matches!(
        event,
        WireEvent::Job { .. } | WireEvent::Source { high: false, .. }
    )));
    rig.owner.drain(until()).await.unwrap();
}
