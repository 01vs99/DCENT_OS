use super::*;

struct SourcePin {
    fake: Arc<Fake>,
    high: AtomicBool,
    failure: u8,
}
impl gpio::Pin for SourcePin {
    fn high(&self) -> Result<(), String> {
        self.fake.events.lock().unwrap().push(Event::SourceHigh);
        self.high.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn low(&self) -> Result<(), String> {
        self.fake.events.lock().unwrap().push(Event::SourceLow);
        if self.failure == 1 {
            return Err("injected low store failure".into());
        }
        if self.failure != 2 {
            self.high.store(false, Ordering::SeqCst);
        }
        Ok(())
    }
    fn observed_high(&self) -> Result<bool, String> {
        Ok(self.high.load(Ordering::SeqCst))
    }
}

async fn prepared(
    failure: u8,
    age: Duration,
) -> (
    Arc<Fake>,
    Arc<Transport<Fake>>,
    Arc<PicApplication<Fake>>,
    Arc<PowerLine<Fake>>,
    QuietFanSetting,
    FanTachSnapshot,
) {
    prepared_for(Model::T17e, failure, age).await
}

async fn prepared_for(
    model: Model,
    failure: u8,
    age: Duration,
) -> (
    Arc<Fake>,
    Arc<Transport<Fake>>,
    Arc<PicApplication<Fake>>,
    Arc<PowerLine<Fake>>,
    QuietFanSetting,
    FanTachSnapshot,
) {
    let (fake, owner) = owner(model).await;
    let line = PowerLine::from_test_pin(
        owner.clone(),
        Box::new(SourcePin {
            fake: fake.clone(),
            high: AtomicBool::new(false),
            failure,
        }),
    );
    line.source_test_high_with_age(age);
    let app = PicApplication::claim(owner.clone()).unwrap();
    fake.reply(&[0x55, 0xaa, 6, 2, 0x42, 0, 0x4a, 0]);
    app.observe_supply_type(deadline()).await.unwrap();
    fake.reply(&match model {
        Model::T17e => factory_tests::golden(),
        Model::S17e => factory_tests::s17e_record(1900),
    });
    owner.acquire_factory_calibration(deadline()).await.unwrap();
    fake.reply(&[5, 0x17, 0x89, 0, 0]);
    app.observe_versions(deadline()).await.unwrap();
    qualify(&fake, &app).await;
    let quiet = owner.quiet_fans(deadline()).await.unwrap();
    // Four distinct IDs, two observations each. Original decoder gives
    // count4*120=480RPM for this retained raw version, without guessed labels.
    fake.tachs
        .lock()
        .unwrap()
        .extend((0..8).map(|i| ((i % 4) << 8) | 4));
    let fans = owner.sample_fan_tach(deadline()).await.unwrap();
    assert!(fans.samples().iter().all(|(_, reading)| reading.rpm == 480));
    fake.events.lock().unwrap().clear();
    (fake, owner, app, line, quiet, fans)
}

#[tokio::test]
async fn s17e_source_requires_actual_model_factory_profile_before_any_low() {
    for remove_factory in [false, true] {
        let (fake, owner, app, line, quiet, fans) =
            prepared_for(Model::S17e, 0, Duration::from_secs(61)).await;
        if remove_factory {
            *owner.factory_calibration.lock().unwrap() = None;
        }
        let result = line
            .enable_source_after_observations(app, quiet, fans, deadline())
            .await;
        assert_eq!(result.is_ok(), !remove_factory);
        // The retained model-specific source must remain usable by the next
        // real reset/preparation step, and must reject a later cut readback.
        if !remove_factory {
            line.check_active_source(&owner, deadline()).unwrap();
            // Zero elapsed injection: this existing fixture helper performs
            // the actual pin high/readback through its owning module.
            line.source_test_high_with_age(Duration::ZERO);
            assert_eq!(
                line.check_active_source(&owner, deadline()).unwrap_err(),
                "S17e active source is not observed low"
            );
        }
        assert_eq!(
            fake.events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == Event::SourceLow)
                .count(),
            usize::from(!remove_factory)
        );
    }
}

#[tokio::test]
async fn source_low_joins_actual_supply_factory_pic_fans_and_retained_high_then_settles_once() {
    let (fake, owner, app, line, quiet, fans) = prepared(0, Duration::from_secs(61)).await;
    let saved = line
        .enable_source_after_observations(app.clone(), quiet.clone(), fans.clone(), deadline())
        .await
        .unwrap();
    assert!(saved.same_owner(&owner));
    assert!(saved.initial_off().observed_at() + Duration::from_secs(61) <= saved.attempted_at());
    assert!(saved.low_observed_at().unwrap() <= saved.settled_at().unwrap());
    assert_eq!(saved.supply().admitted_type(), Some(0x42));
    assert!(fake
        .events
        .lock()
        .unwrap()
        .contains(&Event::Sleep(1_000_000)));
    assert_eq!(
        fake.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| **e == Event::SourceLow)
            .count(),
        1
    );
    assert!(line
        .enable_source_after_observations(app, quiet, fans, deadline())
        .await
        .is_err());
    assert_eq!(
        fake.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| **e == Event::SourceLow)
            .count(),
        1
    );
    let (_, foreign) = super::owner(Model::T17e).await;
    assert!(!saved.same_owner(&foreign));
}

#[tokio::test]
async fn source_low_refuses_foreign_missing_stale_or_changed_prerequisites_before_write() {
    for defect in 0..10 {
        let (fake, owner, mut app, line, mut quiet, mut fans) = prepared(
            0,
            if defect == 0 {
                Duration::ZERO
            } else {
                Duration::from_secs(61)
            },
        )
        .await;
        match defect {
            0 => (),
            1 => {
                let (_, foreign) = super::owner(Model::T17e).await;
                app = PicApplication::claim(foreign).unwrap();
            }
            2 => {
                let (_, foreign) = super::owner(Model::T17e).await;
                quiet = foreign.quiet_fans(deadline()).await.unwrap();
            }
            3 => {
                let (_, foreign) = super::owner(Model::T17e).await;
                fans = foreign.sample_fan_tach(deadline()).await.unwrap();
            }
            4 => {
                fake.write(0x84, 0).unwrap();
            }
            5 => {
                fake.write(DHASH, RUN).unwrap();
            }
            6 => {
                fake.write(BC, BUSY).unwrap();
                fake.bc_timeout.store(true, Ordering::SeqCst);
                fake.write(BC, BUSY).unwrap();
            }
            7 => {
                fake.tachs.lock().unwrap().extend([40; 8]);
                fans = owner.sample_fan_tach(deadline()).await.unwrap();
            }
            8 => {
                std::thread::sleep(Duration::from_millis(1100));
            }
            9 => {
                *owner.factory_calibration.lock().unwrap() = None;
            }
            _ => unreachable!(),
        }
        assert!(
            line.enable_source_after_observations(app, quiet, fans, deadline())
                .await
                .is_err(),
            "defect{defect}"
        );
        assert!(
            !fake.events.lock().unwrap().contains(&Event::SourceLow),
            "defect{defect}"
        );
        assert!(line.source_start_observation().unwrap().is_none());
    }
}

#[tokio::test]
async fn failed_source_low_keeps_attempt_without_completed_or_settled_receipt() {
    for failure in [1, 2] {
        let (fake, owner, app, line, quiet, fans) =
            prepared(failure, Duration::from_secs(61)).await;
        assert!(line
            .enable_source_after_observations(app, quiet, fans, deadline())
            .await
            .is_err());
        let saved = line.source_start_observation().unwrap().unwrap();
        assert!(saved.low_observed_at().is_none() && saved.settled_at().is_none());
        assert!(owner.is_terminal());
        line.terminal_high(deadline()).await.unwrap();
        assert_eq!(
            fake.events
                .lock()
                .unwrap()
                .iter()
                .filter(|e| **e == Event::SourceLow)
                .count(),
            1
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_source_settle_preserves_actual_low_and_allows_independent_cut_before_worker_release(
) {
    let (fake, owner, app, line, quiet, fans) = prepared(0, Duration::from_secs(61)).await;
    let block = ReadBlock::new(0);
    *fake.sleep_block.lock().unwrap() = Some((Duration::from_secs(1), block.clone()));
    let task_line = line.clone();
    let task = tokio::spawn(async move {
        task_line
            .enable_source_after_observations(app, quiet, fans, deadline())
            .await
    });
    while !block.entered.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let saved = line.source_start_observation().unwrap().unwrap();
    assert!(saved.low_observed_at().is_some() && saved.settled_at().is_none());
    line.terminal_high(deadline()).await.unwrap();
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    block.release();
    owner.drain(deadline()).await.unwrap();
    assert!(line
        .source_start_observation()
        .unwrap()
        .unwrap()
        .settled_at()
        .is_none());
    let events = fake.events.lock().unwrap();
    let low = events.iter().position(|e| *e == Event::SourceLow).unwrap();
    let high = events.iter().position(|e| *e == Event::SourceHigh).unwrap();
    assert!(low < high);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_low_holds_voltage_sequence_through_settle_while_heartbeat_lane_remains_live() {
    let (fake, owner, app, line, quiet, fans) = prepared(0, Duration::from_secs(61)).await;
    let block = ReadBlock::new(0);
    *fake.sleep_block.lock().unwrap() = Some((Duration::from_secs(1), block.clone()));
    let source_line = line.clone();
    let source_app = app.clone();
    let source = tokio::spawn(async move {
        source_line
            .enable_source_after_observations(source_app, quiet, fans, deadline())
            .await
    });
    while !block.entered.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    // This is a complete actual heartbeat while source-low's one-second
    // physical wait is deliberately held. The management lane remains live.
    fake.reply(&[6, 0x16, 1, 0, 0, 0]);
    app.heartbeat_round(deadline()).await.unwrap();
    fake.reply(&[0x55, 0xaa, 6, 0x83, 12, 0, 0x95, 0]);
    let voltage_app = app.clone();
    let mut voltage =
        tokio::spawn(async move { voltage_app.command_voltage_cv(1800, deadline()).await });
    // Wait for counted admission (or actual early completion) before the
    // observation interval; a delayed Tokio spawn cannot satisfy the test.
    while owner.workers.lock().unwrap().count < 2 && !voltage.is_finished() {
        tokio::task::yield_now().await;
    }
    let early = tokio::time::timeout(Duration::from_millis(50), &mut voltage)
        .await
        .ok();
    let attempted_during_settle = app.voltage_attempts().unwrap().len();
    block.release();
    let source_result = source.await.unwrap().unwrap();
    let completed_early = early.is_some();
    let voltage_result = match early {
        Some(result) => result,
        None => voltage.await,
    }
    .unwrap()
    .unwrap();
    eprintln!("source-low voltage interleave: attempted_during_settle={attempted_during_settle} completed_early={completed_early} source_settled={:?} voltage_completed={:?}",
        source_result.settled_at(), voltage_result.completed_at());
    assert!(!owner.is_terminal());
    assert!(
        !completed_early,
        "voltage completed inside source-low's retained settle"
    );
    assert_eq!(
        attempted_during_settle, 0,
        "first voltage attempt escaped phase custody"
    );
    assert!(source_result.settled_at().unwrap() <= voltage_result.completed_at());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_low_waits_for_inflight_first_voltage_then_refuses_without_low() {
    let (fake, owner, app, line, quiet, fans) = prepared(0, Duration::from_secs(61)).await;
    let block = ReadBlock::new(0);
    *fake.sleep_block.lock().unwrap() = Some((Duration::from_millis(500), block.clone()));
    fake.reply(&[0x55, 0xaa, 6, 0x83, 12, 0, 0x95, 0]);
    let voltage_app = app.clone();
    let voltage =
        tokio::spawn(async move { voltage_app.command_voltage_cv(1800, deadline()).await });
    while !block.entered.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    assert!(app.last_commanded_voltage().unwrap().is_none());
    assert_eq!(app.voltage_attempts().unwrap().len(), 1);
    let source_line = line.clone();
    let source_app = app.clone();
    let mut source = tokio::spawn(async move {
        source_line
            .enable_source_after_observations(source_app, quiet, fans, deadline())
            .await
    });
    while owner.workers.lock().unwrap().count < 2 && !source.is_finished() {
        tokio::task::yield_now().await;
    }
    let early = tokio::time::timeout(Duration::from_millis(50), &mut source)
        .await
        .ok();
    let attempted_while_voltage_inflight = line.source_start_observation().unwrap().is_some();
    block.release();
    let completed_voltage = voltage.await.unwrap().unwrap();
    let completed_early = early.is_some();
    let source_result = match early {
        Some(result) => result,
        None => source.await,
    }
    .unwrap();
    eprintln!("source-low first-voltage interleave: completed_early={completed_early} attempted_while_voltage_inflight={attempted_while_voltage_inflight} voltage_completed={:?} source_error={source_result:?}", completed_voltage.completed_at());
    assert!(!completed_early);
    assert!(!attempted_while_voltage_inflight);
    assert!(source_result
        .unwrap_err()
        .contains("precede every voltage attempt"));
    assert!(line.source_start_observation().unwrap().is_none());
    assert!(!fake.events.lock().unwrap().contains(&Event::SourceLow));
    assert!(owner.is_terminal());
    line.terminal_high(deadline()).await.unwrap();
}
