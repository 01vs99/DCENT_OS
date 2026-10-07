use super::*;
use startup_tests::{startup_hardware, StartupHardware};

struct ResetPin {
    fake: Arc<Fake>,
    high: AtomicBool,
}
impl gpio::Pin for Arc<ResetPin> {
    fn high(&self) -> Result<(), String> {
        self.fake.events.lock().unwrap().push(Event::SourceHigh);
        self.high.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn low(&self) -> Result<(), String> {
        self.fake.events.lock().unwrap().push(Event::SourceLow);
        self.high.store(false, Ordering::SeqCst);
        Ok(())
    }
    fn observed_high(&self) -> Result<bool, String> {
        Ok(self.high.load(Ordering::SeqCst))
    }
}
fn voltage_reply(code: u8) -> [u8; 8] {
    let sum = 6u16 + 0x83 + u16::from(code);
    [0x55, 0xaa, 6, 0x83, code, 0, sum as u8, (sum >> 8) as u8]
}
async fn prepared(
    chains: &[u8],
) -> (
    Arc<StartupHardware>,
    Arc<Transport<StartupHardware>>,
    Arc<PicApplication<StartupHardware>>,
    Arc<PowerLine<StartupHardware>>,
    Arc<ResetPin>,
) {
    let hw = startup_hardware(Model::T17e, chains);
    let owner = Transport::observe(hw.clone(), Model::T17e, chains.to_vec())
        .await
        .unwrap();
    let pin = Arc::new(ResetPin {
        fake: hw.inner.clone(),
        high: AtomicBool::new(false),
    });
    let line = PowerLine::from_test_pin(owner.clone(), Box::new(pin.clone()));
    line.source_test_high_with_age(Duration::from_secs(61));
    let app = PicApplication::claim(owner.clone()).unwrap();
    hw.inner.reply(&[0x55, 0xaa, 6, 2, 0x42, 0, 0x4a, 0]);
    app.observe_supply_type(deadline()).await.unwrap();
    for _ in chains {
        hw.inner.reply(&factory_tests::golden());
    }
    owner.acquire_factory_calibration(deadline()).await.unwrap();
    for _ in chains {
        hw.inner.reply(&[5, 0x17, 0x89, 0, 0]);
    }
    app.observe_versions(deadline()).await.unwrap();
    for _ in 0..5 {
        for _ in chains {
            hw.inner.reply(&[6, 0x16, 1, 0, 0, 0]);
        }
        app.heartbeat_round(deadline()).await.unwrap();
    }
    let quiet = owner.quiet_fans(deadline()).await.unwrap();
    hw.inner
        .tachs
        .lock()
        .unwrap()
        .extend((0..8).map(|i| ((i % 4) << 8) | 40));
    let fans = owner.sample_fan_tach(deadline()).await.unwrap();
    line.enable_source_after_observations(app.clone(), quiet, fans, deadline())
        .await
        .unwrap();
    hw.inner.regs.lock().unwrap().insert(0x3c, 0xc0c0c0c0);
    hw.inner.regs.lock().unwrap().insert(0x34, 0xa5a50000);
    hw.inner.events.lock().unwrap().clear();
    (hw, owner, app, line, pin)
}
fn ready_replies(hw: &StartupHardware, chains: &[u8]) {
    for code in [236, 219, 202, 185, 168, 151, 134, 120] {
        hw.inner.reply(&voltage_reply(code));
    }
    for _ in chains {
        hw.inner.reply(&[0x15, 1]);
    }
}
async fn entered(block: &ReadBlock) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !block.entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditioning_reset_joins_source_context_frames_preserved_masks_and_complete_streamed_census(
) {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("stock_bm1396_initial_voltage_vectors.json")).unwrap();
    let expected: Vec<u8> = vectors["cases"][0]["stages"][0]["codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect();
    for chains in [vec![0], vec![0, 2, 7]] {
        let (hw, owner, app, line, _) = prepared(&chains).await;
        hw.stream_reset_replies();
        ready_replies(&hw, &chains);
        let result = app
            .initialize_conditioning_reset(line.clone(), deadline())
            .await
            .unwrap();
        assert!(result.same_owner(&owner));
        assert!(result.completed_at().is_some() && result.failure().is_none());
        assert_eq!(result.old_host_register(), 0xc0c0c0c0);
        assert_eq!(result.requested_host_register(), 0xdadadada);
        assert_eq!(result.completed_chains(), chains);
        assert_eq!(result.census_records().len(), 78 * chains.len());
        assert!(!hw.reset_stream_overflowed());
        assert_eq!(hw.inner.regs.lock().unwrap()[&0x34], 0xa5a50000);
        let low = result.low_voltage().unwrap();
        assert_eq!(low.planned_dac_codes(), expected);
        assert_eq!(low.initial_source_context_centivolts(), Some(0));
        assert!(low.prior_command().is_none() && low.is_stepped());
        assert_eq!(low.steps().len(), 8);
        assert!(low
            .steps()
            .iter()
            .all(|s| s.completed_at().is_some() && s.framing_complete()));
        assert_eq!(
            app.last_commanded_voltage()
                .unwrap()
                .unwrap()
                .requested_centivolts(),
            1800
        );
        assert!(app.voltage_attempts().unwrap().is_empty());
        assert!(owner.pending_returns().unwrap().is_empty());
        assert!(owner.assignment_observation().unwrap().is_none());
        assert!(owner.cold_register_observation().unwrap().is_none());
        let enables: Vec<_> = result
            .events()
            .iter()
            .filter_map(|event| match event {
                ConditioningResetEvent::PicEnable {
                    chain,
                    transmitted,
                    response,
                    framing_complete,
                    completed_at,
                    ..
                } => {
                    assert_eq!(*transmitted, 7);
                    assert_eq!(response, &[0x15, 1]);
                    assert!(*framing_complete && completed_at.is_some());
                    Some(*chain)
                }
                _ => None,
            })
            .collect();
        assert_eq!(enables, chains);
        let writes = hw.inner.writes();
        let reset_set = writes
            .iter()
            .position(|&(o, v)| {
                o == 0x34 && v == (0xa5a50000 | chains.iter().fold(0, |m, c| m | (1 << c)))
            })
            .unwrap();
        let first_voltage = writes
            .iter()
            .position(|&(o, v)| o == 0x30 && v == 0x05201155)
            .unwrap();
        assert!(reset_set < first_voltage);
        assert!(hw
            .writes
            .lock()
            .unwrap()
            .iter()
            .filter(|w| w.register == 0x18)
            .all(|w| w.value == 0x0040ba05));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditioning_reset_refuses_wrong_short_and_extra_census_without_losing_prior_command() {
    for defect in [1, 2, 5, 35] {
        let (hw, owner, app, line, _) = prepared(&[0]).await;
        ready_replies(&hw, &[0]);
        hw.defect.store(defect, Ordering::SeqCst);
        assert!(app
            .initialize_conditioning_reset(line.clone(), deadline())
            .await
            .is_err());
        let saved = app.conditioning_reset_observation().unwrap().unwrap();
        assert!(saved.completed_at().is_none() && saved.failure().is_some());
        assert!(saved.low_voltage().unwrap().completed_at().is_some());
        assert!(saved.completed_chains().is_empty());
        assert!(!owner.pending_returns().unwrap().is_empty());
        assert!(owner.is_terminal());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditioning_reset_preserves_failed_initial_voltage_bytes_and_never_enables_a_chain() {
    let (hw, owner, app, line, _) = prepared(&[0]).await;
    hw.inner.reply(&voltage_reply(236)[..7]);
    assert!(app
        .initialize_conditioning_reset(line.clone(), deadline())
        .await
        .is_err());
    let saved = app.conditioning_reset_observation().unwrap().unwrap();
    assert!(saved.failure().is_some() && saved.low_voltage().is_none());
    assert!(!saved
        .events()
        .iter()
        .any(|e| matches!(e, ConditioningResetEvent::PicEnable { .. })));
    let attempts = app.voltage_attempts().unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].initial_source_context_centivolts(), Some(0));
    assert_eq!(attempts[0].steps()[0].response(), &voltage_reply(236)[..7]);
    assert!(!attempts[0].steps()[0].framing_complete());
    assert!(app.last_commanded_voltage().unwrap().is_none() && owner.is_terminal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditioning_reset_preserves_partial_pic_enable_and_unreleased_selected_reset() {
    let (hw, owner, app, line, _) = prepared(&[0]).await;
    for code in [236, 219, 202, 185, 168, 151, 134, 120] {
        hw.inner.reply(&voltage_reply(code));
    }
    hw.inner.reply(&[0x15]);
    assert!(app
        .initialize_conditioning_reset(line.clone(), deadline())
        .await
        .is_err());
    let saved = app.conditioning_reset_observation().unwrap().unwrap();
    assert!(saved.failure().is_some() && saved.low_voltage().is_some());
    let last = saved
        .events()
        .iter()
        .find(|e| matches!(e, ConditioningResetEvent::PicEnable { .. }))
        .unwrap();
    let ConditioningResetEvent::PicEnable {
        transmitted,
        response,
        framing_complete,
        completed_at,
        ..
    } = last
    else {
        unreachable!()
    };
    assert_eq!(*transmitted, 7);
    assert_eq!(response, &[0x15]);
    assert!(!framing_complete && completed_at.is_none());
    assert_eq!(hw.inner.regs.lock().unwrap()[&0x34], 0xa5a50001);
    assert!(owner.is_terminal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditioning_reset_cancelled_pic_byte_retains_worker_and_allows_independent_source_high() {
    let (hw, owner, app, line, _) = prepared(&[0]).await;
    ready_replies(&hw, &[0]);
    let block = ReadBlock::new(0x30);
    *hw.inner.block.lock().unwrap() = Some(block.clone());
    let task = tokio::spawn({
        let app = app.clone();
        let line = line.clone();
        async move {
            app.initialize_conditioning_reset(line.clone(), deadline())
                .await
        }
    });
    entered(&block).await;
    task.abort();
    let _ = task.await;
    assert!(owner.is_terminal());
    let high = line.terminal_high(deadline()).await.unwrap();
    assert!(high.pin_high);
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(20))
        .await
        .is_err());
    block.release();
    owner.drain(deadline()).await.unwrap();
    let saved = app.conditioning_reset_observation().unwrap().unwrap();
    assert!(saved.completed_at().is_none() && saved.failure().is_some());
    assert!(app.last_commanded_voltage().unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditioning_reset_rejects_foreign_source_prior_voltage_and_source_high_before_reset_writes(
) {
    // Every real worker error terminal-seals its owner. Each negative therefore
    // requires a fresh admitted fixture; no later check can ride an old error.
    for defect in 0..3 {
        let (hw, owner, app, line, pin) = prepared(&[0]).await;
        let attempted_line = if defect == 0 {
            let (_hw, _owner, _app, foreign, _) = prepared(&[0]).await;
            foreign
        } else {
            line.clone()
        };
        if defect == 1 {
            pin.high.store(true, Ordering::SeqCst);
        }
        if defect == 2 {
            hw.inner.reply(&voltage_reply(120));
            app.command_voltage_cv(1800, deadline()).await.unwrap();
        }
        hw.inner.events.lock().unwrap().clear();
        assert!(app
            .initialize_conditioning_reset(attempted_line, deadline())
            .await
            .is_err());
        assert_eq!(
            app.conditioning_reset_observation().unwrap().is_some(),
            defect == 2
        );
        assert!(!hw
            .inner
            .writes()
            .iter()
            .any(|&(o, _)| [0x100, 0xf8, 0x34].contains(&o)));
        assert!(owner.is_terminal());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditioning_reset_keeps_heartbeat_lane_live_and_voltage_lease_through_census() {
    let (hw, owner, app, line, _) = prepared(&[0]).await;
    let block = ReadBlock::new(0);
    *hw.inner.sleep_block.lock().unwrap() = Some((Duration::from_millis(1), block.clone()));
    let reset = tokio::spawn({
        let app = app.clone();
        let line = line.clone();
        async move {
            app.initialize_conditioning_reset(line.clone(), deadline())
                .await
        }
    });
    entered(&block).await;
    hw.inner.reply(&[6, 0x16, 1, 0, 0, 0]);
    app.heartbeat_round(deadline()).await.unwrap();
    let waiting = tokio::spawn({
        let app = app.clone();
        async move { app.command_voltage_cv(1900, deadline()).await }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while owner.workers.lock().unwrap().count < 3 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!hw
        .inner
        .writes()
        .iter()
        .any(|&(o, v)| o == 0x30 && v == 0x05201155));
    ready_replies(&hw, &[0]);
    hw.inner.reply(&voltage_reply(84));
    block.release();
    let receipt = reset.await.unwrap().unwrap();
    assert_eq!(receipt.census_records().len(), 78);
    assert!(waiting.await.unwrap().is_ok());
    let writes = hw.inner.writes();
    let last_census = writes
        .iter()
        .rposition(|&(o, v)| o == BC && v & BUSY != 0)
        .unwrap();
    let later_voltage = writes
        .iter()
        .rposition(|&(o, v)| o == 0x30 && v == 0x05201155)
        .unwrap();
    assert!(last_census < later_voltage);
}
