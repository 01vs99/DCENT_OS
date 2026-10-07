use super::*;
use dcentrald_common::{
    bm1396_domain_voltage_policy, Bm1396DomainVoltageAdaptiveLevel, Bm1396DomainVoltageMode,
};

async fn conditioned(
    chains: &[u8],
) -> (
    Arc<PreparationHardware>,
    Arc<Transport<PreparationHardware>>,
    Arc<PicApplication<PreparationHardware>>,
    Arc<PowerLine<PreparationHardware>>,
    Arc<PreparationPin>,
) {
    let (hw, owner, app, line, pin) = prepared(chains).await;
    app.initialize_conditioning_preparation(line.clone(), 75, deadline())
        .await
        .unwrap();
    app.initialize_conditioning_pll(line.clone(), deadline())
        .await
        .unwrap();
    // Explicit actual B4/B8 fixture words for the new phase only. Each lane
    // is 3200*1.5/4096=1.171875, above the source Adapted1.1 threshold.
    hw.startup.adc_raw_override.store(3200, Ordering::SeqCst);
    (hw, owner, app, line, pin)
}
fn queue_temperature(hw: &PreparationHardware, raw: u8) {
    let mut words = Vec::new();
    for &chain in &hw.chains {
        for address in [51, 36, 195, 180] {
            words.extend([
                u32::from_le_bytes([chain, 0x44, address, 2]),
                (u32::from(raw) << 16) | 0x180,
                0x11,
                0x5555aaaa,
            ]);
        }
    }
    hw.queue_words(&words);
}
async fn wait_gate(gate: &ReadBlock) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !gate.entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}
fn no_new_actuation(hw: &PreparationHardware) {
    let events = hw.inner().events.lock().unwrap().clone();
    assert!(!events.iter().any(|event| matches!(
        event,
        Event::Write(_, _) | Event::DmaWrite(_, _) | Event::SourceLow
    )));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapted_second_reset_preserves_first_receipts_and_requalifies_exact_current_epoch() {
    for chains in [vec![0], vec![0, 2, 7]] {
        let (hw, owner, app, line, _pin) = conditioned(&chains).await;
        let original_reset = app.conditioning_reset_observation().unwrap().unwrap();
        let original_pll = app.cold_pll_observation().unwrap().unwrap();
        let old_snapshot = original_pll.thermal_snapshots().last().unwrap().clone();
        // These are actual pending epoch0 records before the second worker.
        queue_temperature(&hw, 111);
        owner.poll_returns(128, deadline()).await.unwrap();
        let old_pending = owner.pending_returns().unwrap();
        assert!(old_pending.iter().all(
            |raw| matches!(raw.payload(),ReturnPayload::Temperature(sample) if sample.epoch()==0)
        ));
        let before_return = owner.asic.lock().unwrap().next_return;
        let old_assignment = owner.assignment_observation().unwrap().unwrap();
        let old_adc = owner.domain_adc_observation().unwrap().unwrap();
        let old_voltage = app.last_commanded_voltage().unwrap().unwrap();
        hw.inner().events.lock().unwrap().clear();
        let result = app
            .initialize_adapted_startup(line.clone(), deadline())
            .await
            .unwrap();
        assert!(
            result.same_owner(&owner)
                && result.completed_at().is_some()
                && result.failure().is_none()
        );
        assert_eq!(result.epoch(), 1);
        assert_eq!(result.stage(), AdaptedStartupStage::FreshThermal);
        assert_eq!(result.predecessor_voltage(), old_voltage);
        assert_eq!(
            result.predecessor_pll().completed_at(),
            original_pll.completed_at()
        );
        assert_eq!(
            app.conditioning_reset_observation()
                .unwrap()
                .unwrap()
                .completed_at(),
            original_reset.completed_at()
        );
        assert_eq!(
            app.cold_pll_observation().unwrap().unwrap().final_adc(),
            original_pll.final_adc()
        );
        let reset = result.reset().unwrap();
        assert_eq!(reset.completed_chains(), chains);
        assert_eq!(reset.census_records().len(), 78 * chains.len());
        assert_eq!(
            reset.low_voltage().unwrap().prior_command(),
            Some(old_voltage)
        );
        assert_eq!(
            reset
                .low_voltage()
                .unwrap()
                .initial_source_context_centivolts(),
            None
        );
        assert_eq!(
            result
                .higher_voltage()
                .unwrap()
                .prior_command()
                .unwrap()
                .requested_centivolts(),
            1800
        );
        assert_eq!(
            result.higher_command().unwrap().requested_centivolts(),
            2000
        );
        assert!(reset.events().iter().any(|event| matches!(
            event,
            ConditioningResetEvent::Asic {
                register: 0x18,
                value: Some(0xf000fa35),
                completed_at: Some(_),
                ..
            }
        )));
        assert!(!reset.events().iter().any(|event| matches!(
            event,
            ConditioningResetEvent::Register {
                offset: 0x100 | 0xf8,
                ..
            }
        )));
        let adc = result.adapted_adc().unwrap();
        assert_eq!(
            adc.adaptive_level(),
            Bm1396DomainVoltageAdaptiveLevel::Adapted
        );
        assert_eq!(adc.baseline_minimum_passed(), None);
        assert_eq!(adc.adapted_minimum_passed(), Some(true));
        assert_eq!(adc.restored_chains(), chains);
        assert!(adc.sequence() > old_adc.sequence());
        assert_eq!(
            result.assignment().unwrap().assigned_records().len(),
            old_assignment.assigned_records().len()
        );
        let watermark = result.receive_watermark().unwrap();
        assert!(watermark > before_return);
        let fresh = result.thermal_snapshots().last().unwrap();
        assert_eq!(fresh.epoch(), 1);
        assert!(fresh.sequence() > old_snapshot.sequence());
        assert!(fresh
            .raw_records()
            .iter()
            .all(|raw| raw.sequence() >= watermark));
        assert!(fresh
            .samples()
            .iter()
            .all(|sample| sample.epoch() == 1 && !sample.is_historical()));
        assert_eq!(fresh.samples().len(), chains.len() * 4);
        assert!(result.prequalification_records().iter().any(|raw| matches!(raw.payload(),ReturnPayload::HistoricalTemperature(sample) if sample.epoch()==0 && sample.is_historical())));
        for raw in old_pending {
            assert!(result.prequalification_records().contains(&raw));
        }
        assert!(result.prequalification_records().iter().any(
            |raw| matches!(raw.payload(),ReturnPayload::Temperature(sample) if sample.epoch()==1)
        ));
        assert!(owner
            .acknowledge_thermal_snapshot(&old_snapshot)
            .unwrap_err()
            .contains("foreign, stale or out of order"));
        let state = owner.asic.lock().unwrap();
        assert_eq!(state.thermal_epoch, 1);
        assert_eq!(state.requalification_deadline, None);
        assert_eq!(state.prior_assignment.as_ref(), Some(&old_assignment));
        assert_eq!(state.prior_domain_adc.as_ref(), Some(&old_adc));
        assert!(!state.dma_initialized && state.publications.is_empty());
        drop(state);
        assert!(!owner.is_terminal() && !hw.overflow.load(Ordering::SeqCst));
        assert_eq!(owner.workers.lock().unwrap().count, 0);
        assert_eq!(
            hw.pll_commands.load(Ordering::SeqCst),
            10 * chains.len() as u32,
            "second phase issues no unqualified final PLL/work"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapted_refuses_missing_actual_predecessors_and_foreign_line_before_mutation() {
    for phase in 0..3 {
        let (hw, owner, app, line, _pin) = source_ready(&[0]).await;
        if phase >= 1 {
            app.initialize_conditioning_reset(line.clone(), deadline())
                .await
                .unwrap();
        }
        if phase >= 2 {
            app.initialize_conditioning_preparation(line.clone(), 75, deadline())
                .await
                .unwrap();
        }
        hw.inner().events.lock().unwrap().clear();
        let error = app
            .initialize_adapted_startup(line.clone(), deadline())
            .await
            .unwrap_err();
        assert!(
            error.contains("never-worked cold owner")
                || error.contains("preparation absent")
                || error.contains("PLL absent"),
            "{error}"
        );
        no_new_actuation(&hw);
        assert!(app.adapted_startup_observation().unwrap().is_none());
        assert_eq!(owner.asic.lock().unwrap().thermal_epoch, 0);
    }
    let (hw, owner, app, _line, _pin) = conditioned(&[0]).await;
    let (_foreign_hw, foreign_owner, _foreign_app, foreign_line, _foreign_pin) =
        source_ready(&[0]).await;
    hw.inner().events.lock().unwrap().clear();
    assert!(app
        .initialize_adapted_startup(foreign_line.clone(), deadline())
        .await
        .is_err());
    no_new_actuation(&hw);
    assert!(!foreign_owner.is_terminal());
    assert!(owner.is_terminal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapted_rejects_acknowledged_same_value_voltage_generation_before_epoch_or_reset() {
    let (hw, owner, app, line, _pin) = conditioned(&[0]).await;
    let previous = app.last_commanded_voltage().unwrap().unwrap();
    app.command_voltage_ramp(previous.requested_centivolts(), deadline())
        .await
        .unwrap();
    let attempt = app.voltage_attempts().unwrap().remove(0);
    app.acknowledge_voltage_attempt(&attempt).unwrap();
    hw.inner().events.lock().unwrap().clear();
    let error = app
        .initialize_adapted_startup(line.clone(), deadline())
        .await
        .unwrap_err();
    assert!(error.contains("generation/custody changed"), "{error}");
    no_new_actuation(&hw);
    let observation = app.adapted_startup_observation().unwrap().unwrap();
    assert!(observation.completed_at().is_none() && observation.failure().is_some());
    assert_eq!(owner.asic.lock().unwrap().thermal_epoch, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapted_actual_adc_between_baseline_and_adapted_threshold_fails_after_b0_restore() {
    let (hw, owner, app, line, _pin) = prepared(&[0]).await;
    // Both actual Baseline acquisitions and the later Adapted acquisition use
    // identical raw2800 words. Only the privately admitted phase changes.
    hw.startup.adc_raw_override.store(2800, Ordering::SeqCst);
    app.initialize_conditioning_preparation(line.clone(), 75, deadline())
        .await
        .unwrap();
    app.initialize_conditioning_pll(line.clone(), deadline())
        .await
        .unwrap();
    let baseline_policy = bm1396_domain_voltage_policy(
        Model::T17e,
        Bm1396DomainVoltageAdaptiveLevel::Baseline,
        Bm1396DomainVoltageMode::Minimum,
    )
    .unwrap();
    let adapted_policy = bm1396_domain_voltage_policy(
        Model::T17e,
        Bm1396DomainVoltageAdaptiveLevel::Adapted,
        Bm1396DomainVoltageMode::Minimum,
    )
    .unwrap();
    assert_eq!(baseline_policy.minimum_v().unwrap().to_bits(), 0x3f4c_cccd);
    assert_eq!(adapted_policy.minimum_v().unwrap().to_bits(), 0x3f8c_cccd);
    let baseline = app
        .cold_pll_observation()
        .unwrap()
        .unwrap()
        .final_adc()
        .unwrap()
        .clone();
    assert_eq!(baseline.baseline_minimum_passed(), Some(true));
    // Exact binary rational 2800*1.5/4096=1.025390625: passes0.8, fails1.1.
    hw.startup.adc_raw_override.store(2800, Ordering::SeqCst);
    let error = app
        .initialize_adapted_startup(line.clone(), deadline())
        .await
        .unwrap_err();
    assert!(
        error.contains("BM1396 fresh ADC adapted minimum failed; complete observation retained"),
        "{error}"
    );
    let observation = app.adapted_startup_observation().unwrap().unwrap();
    let adc = observation.adapted_adc().unwrap();
    assert_eq!(adc.adapted_minimum_passed(), Some(false));
    assert_eq!(adc.baseline_minimum_passed(), None);
    assert_eq!(adc.restored_chains(), [0]);
    assert!(adc.completed_at().is_some());
    assert!(
        observation.thermal_configuration().is_none() && observation.operational_baud().is_none()
    );
    assert_eq!(observation.stage(), AdaptedStartupStage::AdaptedAdc);
    assert!(owner.is_terminal());
    assert_eq!(
        app.cold_pll_observation().unwrap().unwrap().final_adc(),
        Some(&baseline)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapted_historical_hot_record_remains_actionable_during_reset() {
    let (hw, owner, app, line, _pin) = conditioned(&[0]).await;
    hw.adapted_defect.store(1, Ordering::SeqCst);
    let old_voltage_frames = hw.voltage_frames.load(Ordering::SeqCst);
    let error = app
        .initialize_adapted_startup(line.clone(), deadline())
        .await
        .unwrap_err();
    assert!(
        error.contains("pending temperature reached cutoff"),
        "{error}"
    );
    assert!(hw.adapted_defect_seen.load(Ordering::SeqCst));
    let observation = app.adapted_startup_observation().unwrap().unwrap();
    assert!(observation.completed_at().is_none() && observation.failure().is_some());
    assert_eq!(observation.stage(), AdaptedStartupStage::Reset);
    assert_eq!(hw.voltage_frames.load(Ordering::SeqCst), old_voltage_frames);
    assert!(owner.pending_returns().unwrap().iter().any(|raw| matches!(raw.payload(),ReturnPayload::HistoricalTemperature(sample) if sample.raw_channels()[0]==164)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapted_reset_retains_partial_command_on_source_cut_cancellation_and_deadline() {
    for fault in 0..3 {
        let (hw, owner, app, line, pin) = conditioned(&[0]).await;
        let gate = ReadBlock::new(0x34);
        *hw.adapted_reset_gate.lock().unwrap() = Some(gate.clone());
        let phase_deadline = if fault == 2 {
            Instant::now() + Duration::from_millis(700)
        } else {
            deadline()
        };
        let task = {
            let app = app.clone();
            let line = line.clone();
            tokio::spawn(async move { app.initialize_adapted_startup(line, phase_deadline).await })
        };
        wait_gate(&gate).await;
        let before = hw.voltage_frames.load(Ordering::SeqCst);
        // Real heartbeat worker and physical lane remain available while the
        // real reset ASIC writer is parked at the actual reset register store.
        app.heartbeat_round(deadline()).await.unwrap();
        assert_eq!(owner.workers.lock().unwrap().count, 2);
        match fault {
            0 => gpio::Pin::high(&pin).unwrap(),
            1 => task.abort(),
            _ => tokio::time::sleep(Duration::from_millis(750)).await,
        }
        gate.release();
        if fault == 1 {
            assert!(task.await.unwrap_err().is_cancelled());
            owner.drain(deadline()).await.unwrap();
        } else {
            assert!(task.await.unwrap().is_err());
        }
        let observation = app.adapted_startup_observation().unwrap().unwrap();
        assert!(observation.completed_at().is_none() && observation.failure().is_some());
        let reset = observation.reset().unwrap();
        assert!(reset
            .events()
            .iter()
            .any(|event| matches!(event, ConditioningResetEvent::Register { offset: 0x34, .. })));
        assert_eq!(hw.voltage_frames.load(Ordering::SeqCst), before);
        assert_eq!(owner.workers.lock().unwrap().count, 0);
        assert!(owner.is_terminal());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapted_requires_complete_valid_post_setup_thermal_population() {
    for fault in [2, 3] {
        let (hw, owner, app, line, _pin) = conditioned(&[0]).await;
        hw.adapted_defect.store(fault, Ordering::SeqCst);
        // The caller owes independent heartbeat service throughout this
        // deliberately incomplete thermal census, just as the runtime does.
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let heartbeats = {
            let app = app.clone();
            let owner = owner.clone();
            tokio::spawn(async move {
                while !owner.is_terminal() {
                    if let Err(error) = app.heartbeat_round(deadline()).await {
                        if owner.is_terminal() { break; }
                        return Err(error);
                    }
                    tokio::select! {
                        _ = stopped.changed() => break,
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                    }
                }
                Ok::<(), String>(())
            })
        };
        let result = app
            .initialize_adapted_startup(line.clone(), deadline())
            .await;
        let _ = stop.send(true);
        heartbeats.await.unwrap().unwrap();
        let error = result.unwrap_err();
        assert!(hw.adapted_defect_seen.load(Ordering::SeqCst));
        assert!(
            if fault == 2 {
                error.contains("sensor channel has no valid position")
            } else {
                error.contains("fresh complete thermal population timed out")
            },
            "{error}"
        );
        let observation = app.adapted_startup_observation().unwrap().unwrap();
        assert_eq!(observation.stage(), AdaptedStartupStage::FreshThermal);
        assert!(observation.receive_watermark().is_some());
        assert!(observation
            .operational_baud()
            .unwrap()
            .completed_at()
            .is_some());
        assert_eq!(
            observation.adapted_adc().unwrap().adapted_minimum_passed(),
            Some(true)
        );
        assert!(observation.failure().is_some() && observation.completed_at().is_none());
        if fault == 2 {
            assert_eq!(observation.thermal_snapshots().len(), 1);
        } else {
            assert!(observation.thermal_snapshots().is_empty());
        }
        assert!(owner.is_terminal());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapted_old_epoch_raw_custody_cannot_satisfy_current_collection_or_snapshot_ack() {
    let (hw, owner, app, line, _pin) = conditioned(&[0]).await;
    queue_temperature(&hw, 111);
    owner.poll_returns(128, deadline()).await.unwrap();
    let old = owner.pending_returns().unwrap();
    assert_eq!(old.len(), 4);
    let snapshot = app
        .cold_pll_observation()
        .unwrap()
        .unwrap()
        .thermal_snapshots()
        .last()
        .unwrap()
        .clone();
    app.initialize_adapted_startup(line.clone(), deadline())
        .await
        .unwrap();
    // Deliberate stale-custody fault injection reoffers exact unchanged records;
    // no epoch/timestamp/sequence is rewritten to manufacture a new sample.
    let mut state = owner.asic.lock().unwrap();
    assert!(state.pending.is_empty());
    state.pending.extend(old.clone());
    assert!(owner
        .collect_thermal_locked(&mut state, 0, deadline())
        .unwrap()
        .is_none());
    assert!(owner
        .acknowledge_thermal_snapshot_locked(&mut state, &snapshot)
        .is_err());
    assert_eq!(state.pending.iter().cloned().collect::<Vec<_>>(), old);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapted_final_pic_exit_reacquires_exact_voltage_generation_before_completion() {
    for intervening_command in [false, true] {
        let (hw, owner, app, line, _pin) = conditioned(&[0]).await;
        let gate = ReadBlock::new(0x30);
        *hw.adapted_completion_gate.lock().unwrap() = Some(gate.clone());
        let task = {
            let app = app.clone();
            let line = line.clone();
            tokio::spawn(async move { app.initialize_adapted_startup(line, deadline()).await })
        };
        wait_gate(&gate).await;
        assert_eq!(
            owner.workers.lock().unwrap().count,
            1,
            "actual counted PIC worker has exited"
        );
        assert!(
            owner.asic.try_lock().is_err(),
            "same outer ASIC guard remains held"
        );
        let before = app.adapted_startup_observation().unwrap().unwrap();
        assert_eq!(before.stage(), AdaptedStartupStage::FreshThermal);
        assert_eq!(before.thermal_snapshots().len(), 1);
        assert!(before.completed_at().is_none());
        assert_eq!(hw.automatic_commands.load(Ordering::SeqCst), 16);
        let previous = app.last_commanded_voltage().unwrap().unwrap();
        assert_eq!(previous, before.higher_command().unwrap());
        let voltage_frames = hw.voltage_frames.load(Ordering::SeqCst);
        if intervening_command {
            // The real public voltage worker acquires the actual lease in the
            // handoff gap, writes the same value, receives its frame and retires
            // its actual attempt. The monotonic generation must still expose it.
            let newer = app
                .command_voltage_ramp(previous.requested_centivolts(), deadline())
                .await
                .unwrap();
            assert_eq!(
                newer.requested_centivolts(),
                previous.requested_centivolts()
            );
            assert_ne!(newer.completed_at(), previous.completed_at());
            let attempt = app.voltage_attempts().unwrap().remove(0);
            assert_eq!(attempt.prior_command(), Some(previous));
            assert!(attempt.completed_at().is_some());
            app.acknowledge_voltage_attempt(&attempt).unwrap();
            assert!(app.voltage_attempts().unwrap().is_empty());
            assert!(hw.voltage_frames.load(Ordering::SeqCst) > voltage_frames);
        }
        gate.release();
        let result = task.await.unwrap();
        let after = app.adapted_startup_observation().unwrap().unwrap();
        assert_eq!(after.thermal_snapshots(), before.thermal_snapshots());
        assert_eq!(after.higher_command(), before.higher_command());
        assert_eq!(
            after.adapted_adc().unwrap().adapted_minimum_passed(),
            Some(true)
        );
        assert!(after.operational_baud().unwrap().completed_at().is_some());
        if intervening_command {
            assert!(result
                .unwrap_err()
                .contains("voltage changed before retained completion"));
            assert!(
                after.completed_at().is_none() && after.failure().is_some() && owner.is_terminal()
            );
        } else {
            assert!(result.unwrap().completed_at().is_some());
            assert!(after.failure().is_none() && !owner.is_terminal());
            assert_eq!(hw.voltage_frames.load(Ordering::SeqCst), voltage_frames);
        }
        assert_eq!(owner.workers.lock().unwrap().count, 0);
    }
}

#[path = "stock_bm1396_final_pll_tests.rs"]
mod final_pll_tests;
