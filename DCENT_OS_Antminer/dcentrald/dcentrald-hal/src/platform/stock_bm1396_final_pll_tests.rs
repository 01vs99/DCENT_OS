use super::*;

async fn adapted(
    chains: &[u8],
) -> (
    Arc<PreparationHardware>,
    Arc<Transport<PreparationHardware>>,
    Arc<PicApplication<PreparationHardware>>,
    Arc<PowerLine<PreparationHardware>>,
    Arc<PreparationPin>,
    AdaptedStartupObservation,
) {
    let (hw, owner, app, line, pin) = conditioned(chains).await;
    let observation = app
        .initialize_adapted_startup(line.clone(), deadline())
        .await
        .unwrap();
    hw.inner().events.lock().unwrap().clear();
    hw.pll_commands.store(0, Ordering::SeqCst);
    (hw, owner, app, line, pin, observation)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_pll_runs_source_stages_after_adapted_epoch_and_keeps_adc_without_conditioning_tail()
{
    for chains in [vec![0], vec![0, 2, 7]] {
        let (hw, owner, app, line, _pin, adapted) = adapted(&chains).await;
        let original = app.cold_pll_observation().unwrap().unwrap();
        let adc = owner.domain_adc_observation().unwrap().unwrap();
        let adc_commands = hw
            .startup
            .writes
            .lock()
            .unwrap()
            .iter()
            .filter(|write| [0xb0, 0xb4, 0xb8].contains(&write.register))
            .count();
        let before_ticks = hw.ticks.load(Ordering::SeqCst);
        hw.delay_phase.store(6, Ordering::SeqCst);
        let result = app
            .initialize_final_pll(line.clone(), deadline())
            .await
            .unwrap();
        assert!(
            result.same_owner(&owner)
                && result.completed_at().is_some()
                && result.failure().is_none()
        );
        assert_eq!(result.epoch(), 1);
        assert_eq!(
            result.adapted_startup().completed_at(),
            adapted.completed_at()
        );
        assert_eq!(result.initial_voltage(), adapted.higher_command());
        assert_eq!(result.initial_adc(), &adc);
        assert_eq!(owner.domain_adc_observation().unwrap().as_ref(), Some(&adc));
        assert_eq!(result.initial_adc().adapted_minimum_passed(), Some(true));
        assert_eq!(result.completed_frequency_mhz(), Some(300));
        assert_eq!(result.timeout_base(), Some(1179));
        assert_eq!(
            app.cold_pll_observation().unwrap().as_ref(),
            Some(&original)
        );
        assert_eq!(
            result
                .stages()
                .iter()
                .map(|stage| stage.frequency_mhz())
                .collect::<Vec<_>>(),
            [60, 75, 100, 150, 300]
        );
        for (stage, word) in result
            .stages()
            .iter()
            .zip([0x40a80275, 0x40a80274, 0x40a80273, 0x40a80272, 0x40a80271])
        {
            assert!(stage.settled_at().is_some());
            assert_eq!(stage.commands().len(), 2 * chains.len());
            for (command, chain) in stage.commands().iter().zip(chains.iter().cycle()) {
                assert_eq!(command.chain(), *chain);
                assert_eq!(command.register_value(), word);
                assert!(command.completed_at().is_some());
            }
        }
        assert_eq!(
            hw.pll_commands.load(Ordering::SeqCst),
            10 * chains.len() as u32
        );
        assert_eq!(
            hw.startup
                .writes
                .lock()
                .unwrap()
                .iter()
                .filter(|write| [0xb0, 0xb4, 0xb8].contains(&write.register))
                .count(),
            adc_commands,
            "final wrapper emits no new ADC commands"
        );
        assert!(hw.ticks.load(Ordering::SeqCst) - before_ticks >= 10_000);
        assert!(hw.delayed.load(Ordering::SeqCst));
        let busy_records = hw.busy_thermal_records.load(Ordering::SeqCst);
        assert!(busy_records > 0);
        if chains.len() == 3 {
            assert!(busy_records > 128);
        }
        assert!(hw.busy_read_words.load(Ordering::SeqCst) >= busy_records * 4);
        assert!(!hw.overflow.load(Ordering::SeqCst));
        assert!(result.thermal_snapshots().iter().all(|row| row.epoch() == 1
            && row
                .samples()
                .iter()
                .all(|sample| sample.epoch() == 1 && !sample.is_historical())));
        assert!(owner.pending_returns().unwrap().is_empty());
        assert!(owner.pending_thermal_snapshots().unwrap().is_empty());
        assert!(
            app.voltage_attempts().unwrap().is_empty()
                && app.rail_verifications().unwrap().is_empty()
        );
        assert_eq!(owner.workers.lock().unwrap().count, 0);
        assert!(!owner.is_terminal());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_pll_refuses_conditioning_history_or_foreign_source_before_actuation() {
    for foreign in [false, true] {
        let (hw, owner, app, line, _pin) = conditioned(&[0]).await;
        let (_foreign_hw, foreign_owner, _foreign_app, foreign_line, _foreign_pin) =
            prepared(&[0]).await;
        if foreign {
            app.initialize_adapted_startup(line.clone(), deadline())
                .await
                .unwrap();
        }
        hw.inner().events.lock().unwrap().clear();
        let selected = if foreign {
            foreign_line.clone()
        } else {
            line.clone()
        };
        let error = app
            .initialize_final_pll(selected, deadline())
            .await
            .unwrap_err();
        assert!(
            error.contains(if foreign {
                "another owner"
            } else {
                "requires actual adapted startup"
            }),
            "{error}"
        );
        no_new_actuation(&hw);
        assert!(app.final_pll_observation().unwrap().is_none());
        assert!(owner.is_terminal() && !foreign_owner.is_terminal());
        assert_eq!(owner.workers.lock().unwrap().count, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_pll_refuses_acknowledged_same_value_voltage_before_first_stage() {
    let (hw, owner, app, line, _pin, adapted) = adapted(&[0]).await;
    let newer = app.command_voltage_ramp(2000, deadline()).await.unwrap();
    let attempt = app.voltage_attempts().unwrap().remove(0);
    assert_eq!(
        attempt.sequence(),
        adapted.higher_voltage().unwrap().sequence() + 1
    );
    assert_eq!(attempt.prior_command(), adapted.higher_command());
    app.acknowledge_voltage_attempt(&attempt).unwrap();
    assert_ne!(newer, adapted.higher_command().unwrap());
    let writes = hw.inner().writes();
    let error = app
        .initialize_final_pll(line.clone(), deadline())
        .await
        .unwrap_err();
    assert!(error.contains("intervening voltage generation"), "{error}");
    assert_eq!(hw.inner().writes(), writes);
    let saved = app.final_pll_observation().unwrap().unwrap();
    assert!(saved.stages().is_empty() && saved.completed_at().is_none());
    assert!(saved
        .failure()
        .unwrap()
        .contains("intervening voltage generation"));
    assert_eq!(saved.timeout_base(), None);
    assert_eq!(hw.pll_commands.load(Ordering::SeqCst), 0);
    assert!(owner.is_terminal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_pll_busy_service_preserves_partial_command_on_cut_reset_hot_cancel_and_deadline() {
    for defect in 0..5 {
        let (hw, owner, app, line, pin, _) = adapted(&[0, 2, 7]).await;
        hw.delay_phase.store(6, Ordering::SeqCst);
        let gate = ReadBlock::new(BC);
        *hw.busy_test_gate.lock().unwrap() = Some(gate.clone());
        let until = if defect == 4 {
            Instant::now() + Duration::from_secs(2)
        } else {
            deadline()
        };
        let task = {
            let app = app.clone();
            let line = line.clone();
            tokio::spawn(async move { app.initialize_final_pll(line, until).await })
        };
        wait_gate(&gate).await;
        assert_eq!(hw.pll_commands.load(Ordering::SeqCst), 1);
        // This actual independent physical lane stays available during ASIC BUSY.
        app.heartbeat_round(deadline()).await.unwrap();
        app.check_health(deadline()).unwrap();
        match defect {
            0 => gpio::Pin::high(&pin).unwrap(),
            1 => *hw.inner().regs.lock().unwrap().get_mut(&0x34).unwrap() ^= 1,
            2 => {
                queue_temperature(&hw, 164);
            }
            3 => {
                task.abort();
                line.terminal_high(deadline()).await.unwrap();
            }
            _ => {
                tokio::time::sleep_until(tokio::time::Instant::from_std(
                    until + Duration::from_millis(10),
                ))
                .await;
            }
        }
        gate.release();
        if defect == 3 {
            assert!(task.await.unwrap_err().is_cancelled());
            owner.drain(deadline()).await.unwrap();
        } else {
            let error = task.await.unwrap().unwrap_err();
            let expected = match defect {
                0 => "active source is not observed low",
                1 => "reset state changed",
                2 => "temperature reached configured cutoff",
                _ => "deadline",
            };
            assert!(error.contains(expected), "{error}");
        }
        let retained = app.final_pll_observation().unwrap().unwrap();
        assert!(retained.completed_at().is_none() && retained.failure().is_some());
        assert_eq!(retained.completed_frequency_mhz(), None);
        assert_eq!(retained.timeout_base(), None);
        assert_eq!(retained.stages().len(), 1);
        assert_eq!(retained.stages()[0].commands().len(), 1);
        assert!(retained.stages()[0].commands()[0].completed_at().is_none());
        assert_eq!(hw.pll_commands.load(Ordering::SeqCst), 1);
        assert_eq!(owner.workers.lock().unwrap().count, 0);
        assert!(owner.is_terminal() && !hw.overflow.load(Ordering::SeqCst));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_pll_completion_reacquires_voltage_lineage_and_rechecks_fresh_thermal() {
    for defect in 0..3 {
        let (hw, owner, app, line, _pin, _) = adapted(&[0]).await;
        let gate = ReadBlock::new(0x30);
        *hw.final_pll_completion_gate.lock().unwrap() = Some(gate.clone());
        let task = {
            let app = app.clone();
            let line = line.clone();
            tokio::spawn(async move { app.initialize_final_pll(line, deadline()).await })
        };
        wait_gate(&gate).await;
        assert_eq!(owner.workers.lock().unwrap().count, 1);
        assert!(owner.asic.try_lock().is_err());
        let before = app.final_pll_observation().unwrap().unwrap();
        assert_eq!(before.stages().len(), 5);
        assert!(before.completed_at().is_none() && before.timeout_base().is_none());
        let previous = app.last_commanded_voltage().unwrap().unwrap();
        if defect == 1 {
            let newer = app
                .command_voltage_ramp(previous.requested_centivolts(), deadline())
                .await
                .unwrap();
            assert_ne!(newer.completed_at(), previous.completed_at());
            let attempt = app.voltage_attempts().unwrap().remove(0);
            assert_eq!(attempt.prior_command(), Some(previous));
            app.acknowledge_voltage_attempt(&attempt).unwrap();
            assert!(app.voltage_attempts().unwrap().is_empty());
        } else if defect == 2 {
            tokio::time::sleep(Duration::from_millis(7100)).await;
        }
        gate.release();
        let result = task.await.unwrap();
        let after = app.final_pll_observation().unwrap().unwrap();
        assert_eq!(after.stages(), before.stages());
        assert_eq!(after.thermal_snapshots(), before.thermal_snapshots());
        assert_eq!(after.initial_adc(), before.initial_adc());
        if defect == 0 {
            assert!(result.unwrap().completed_at().is_some());
            assert_eq!(after.timeout_base(), Some(1179));
            assert!(!owner.is_terminal());
        } else {
            let expected = if defect == 1 {
                "final voltage generation/custody changed"
            } else {
                "thermal snapshot stale"
            };
            assert!(result.unwrap_err().contains(expected));
            assert!(after.failure().unwrap().contains(expected));
            assert_eq!(after.timeout_base(), None);
            assert!(owner.is_terminal());
        }
        assert_eq!(owner.workers.lock().unwrap().count, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_pll_refuses_reoffered_historical_temperature_and_retains_original_raw_adc() {
    let (hw, owner, app, line, _pin) = conditioned(&[0]).await;
    queue_temperature(&hw, 111);
    owner.poll_returns(128, deadline()).await.unwrap();
    let adapted = app
        .initialize_adapted_startup(line.clone(), deadline())
        .await
        .unwrap();
    let historical = adapted
        .prequalification_records()
        .iter()
        .find(|raw| matches!(raw.payload(), ReturnPayload::HistoricalTemperature(_)))
        .unwrap()
        .clone();
    // Reoffer an actual unchanged archived record; no synthetic epoch or time.
    owner
        .asic
        .lock()
        .unwrap()
        .pending
        .push_back(historical.clone());
    let writes = hw.inner().writes();
    let error = app
        .initialize_final_pll(line.clone(), deadline())
        .await
        .unwrap_err();
    assert!(
        error.contains("refuses historical thermal custody"),
        "{error}"
    );
    assert_eq!(hw.inner().writes(), writes);
    let retained = app.final_pll_observation().unwrap().unwrap();
    assert!(retained.stages().is_empty() && retained.completed_at().is_none());
    assert_eq!(retained.initial_adc(), adapted.adapted_adc().unwrap());
    assert_eq!(
        owner.domain_adc_observation().unwrap().as_ref(),
        adapted.adapted_adc()
    );
    assert!(owner.pending_returns().unwrap().contains(&historical));
    assert!(retained
        .failure()
        .unwrap()
        .contains("historical thermal custody"));
    assert!(owner.is_terminal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapted_and_final_contended_completion_service_finite_fifo_before_generation_hot_cancel_deadline_refusal(
) {
    for final_phase in [false, true] {
        for defect in 0..4 {
            let (hw, owner, app, line, _pin) = conditioned(&[0, 2, 7]).await;
            if final_phase {
                app.initialize_adapted_startup(line.clone(), deadline())
                    .await
                    .unwrap();
            }
            let entry = ReadBlock::new(0x30);
            if final_phase {
                *hw.final_pll_completion_gate.lock().unwrap() = Some(entry.clone());
            } else {
                *hw.adapted_completion_gate.lock().unwrap() = Some(entry.clone());
            }
            let until = if defect == 3 {
                Instant::now() + Duration::from_secs(2)
            } else {
                deadline()
            };
            let task = {
                let app = app.clone();
                let line = line.clone();
                tokio::spawn(async move {
                    if final_phase {
                        app.initialize_final_pll(line, until).await.map(|_| ())
                    } else {
                        app.initialize_adapted_startup(line, until)
                            .await
                            .map(|_| ())
                    }
                })
            };
            wait_gate(&entry).await;
            assert_eq!(owner.workers.lock().unwrap().count, 1);
            let before_thermal = if final_phase {
                app.final_pll_observation()
                    .unwrap()
                    .unwrap()
                    .thermal_snapshots()
                    .to_vec()
            } else {
                app.adapted_startup_observation()
                    .unwrap()
                    .unwrap()
                    .thermal_snapshots()
                    .to_vec()
            };
            let previous = app.last_commanded_voltage().unwrap().unwrap();
            let management = ReadBlock::new(0x30);
            *hw.inner().block.lock().unwrap() = Some(management.clone());
            let competitor = {
                let app = app.clone();
                tokio::spawn(async move {
                    app.command_voltage_ramp(previous.requested_centivolts(), deadline())
                        .await
                })
            };
            wait_gate(&management).await;
            assert_eq!(owner.workers.lock().unwrap().count, 2);
            let attempt = app.voltage_attempts().unwrap().remove(0);
            assert!(attempt.completed_at().is_none());
            assert_eq!(attempt.prior_command(), Some(previous));
            assert_eq!(app.last_commanded_voltage().unwrap(), Some(previous));
            let service_gate = ReadBlock::new(0x18);
            *hw.completion_wait_gate.lock().unwrap() = Some(service_gate.clone());
            hw.completion_wait_ticks.store(1500, Ordering::SeqCst);
            let before_populations = hw.emitted_temperatures.load(Ordering::SeqCst);
            let before_ticks = hw.ticks.load(Ordering::SeqCst);
            // The PIC task is actually admitted and blocked with the real lease.
            // No externally assigned synthetic worker identity advances ticks.
            assert!(!competitor.is_finished());
            entry.release();
            wait_gate(&service_gate).await;
            assert_eq!(hw.completion_wait_ticks.load(Ordering::SeqCst), 0);
            assert_eq!(hw.ticks.load(Ordering::SeqCst) - before_ticks, 1500);
            assert!(!competitor.is_finished());
            assert!(owner.asic.try_lock().is_err());
            let emitted =
                (hw.emitted_temperatures.load(Ordering::SeqCst) - before_populations) * 12;
            assert!(
                emitted > 128,
                "actual three-chain traffic exceeds the finite FIFO"
            );
            assert!(!hw.overflow.load(Ordering::SeqCst));
            let serviced = if final_phase {
                app.final_pll_observation()
                    .unwrap()
                    .unwrap()
                    .thermal_snapshots()
                    .to_vec()
            } else {
                app.adapted_startup_observation()
                    .unwrap()
                    .unwrap()
                    .thermal_snapshots()
                    .to_vec()
            };
            assert!(serviced.starts_with(&before_thermal));
            let added: usize = serviced[before_thermal.len()..]
                .iter()
                .map(|row| row.raw_records().len())
                .sum();
            assert!(
                added >= emitted as usize,
                "actual populations retained and acknowledged before next wait"
            );
            assert!(serviced.iter().all(|row| row.epoch() == 1
                && row
                    .samples()
                    .iter()
                    .all(|sample| sample.epoch() == 1 && !sample.is_historical())));
            assert!(app.voltage_attempts().unwrap()[0].completed_at().is_none());
            let competitor = if defect == 0 {
                // Finish and acknowledge the real same-value mutation only now,
                // after the contended owner has serviced more than one FIFO.
                management.release();
                let newer = competitor.await.unwrap().unwrap();
                assert_ne!(newer.completed_at(), previous.completed_at());
                let completed = app.voltage_attempts().unwrap().remove(0);
                assert_eq!(completed.sequence(), attempt.sequence());
                app.acknowledge_voltage_attempt(&completed).unwrap();
                None
            } else {
                Some(competitor)
            };
            if defect == 1 {
                queue_temperature(&hw, 164);
            }
            if defect == 2 {
                task.abort();
            }
            if defect == 3 {
                tokio::time::sleep_until(tokio::time::Instant::from_std(
                    until + Duration::from_millis(10),
                ))
                .await;
            }
            service_gate.release();
            if defect == 2 {
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                let error = task.await.unwrap().unwrap_err();
                let expected = match defect {
                    0 if final_phase => "final voltage generation/custody changed",
                    0 => "voltage changed before retained completion",
                    1 if final_phase => "temperature reached configured cutoff",
                    1 => "pending temperature reached cutoff",
                    _ => "deadline",
                };
                assert!(
                    error.contains(expected),
                    "phase={final_phase} defect={defect}: {error}"
                );
            }
            management.release();
            if let Some(competitor) = competitor {
                assert!(competitor.await.unwrap().is_err());
                let saved_attempt = app.voltage_attempts().unwrap().remove(0);
                assert_eq!(saved_attempt.sequence(), attempt.sequence());
                assert!(saved_attempt.completed_at().is_none());
            }
            owner.drain(deadline()).await.unwrap();
            if final_phase {
                let saved = app.final_pll_observation().unwrap().unwrap();
                assert!(saved.completed_at().is_none() && saved.failure().is_some());
                assert_eq!(saved.timeout_base(), None);
                assert!(saved.thermal_snapshots().starts_with(&serviced));
            } else {
                let saved = app.adapted_startup_observation().unwrap().unwrap();
                assert!(saved.completed_at().is_none() && saved.failure().is_some());
                assert!(saved.thermal_snapshots().starts_with(&serviced));
                assert_eq!(
                    saved.adapted_adc().unwrap().adapted_minimum_passed(),
                    Some(true)
                );
            }
            assert!(owner.is_terminal() && !hw.overflow.load(Ordering::SeqCst));
            assert_eq!(owner.workers.lock().unwrap().count, 0);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_pll_fixture_observer_is_bounded_under_actual_preworker_admission_and_retained_locks()
{
    let (hw, owner, app, line, _pin, _) = adapted(&[0]).await;
    let gate = ReadBlock::new(0x30);
    *hw.final_pll_completion_gate.lock().unwrap() = Some(gate.clone());
    let (tx, rx) = tokio::sync::oneshot::channel();
    let checked_owner = owner.clone();
    let checked_hw = hw.clone();
    // A separate runtime bounds failure of the deliberately nested observer.
    // If a future fixture reintroduces a blocking lock, shutdown_timeout lets
    // this regression report its actual timeout instead of hanging libtest.
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async move {
            tokio::time::timeout(
                Duration::from_millis(500),
                checked_owner.worker(deadline(), false, move |owner| {
                    let _asic = owner.lock(&owner.asic, deadline(), false)?;
                    // The real FIFO read identifies this actual counted ASIC
                    // receiver. No invented thread identity or worker count.
                    checked_hw.read(0x18)?;
                    assert_eq!(owner.workers.lock().unwrap().count, 1);
                    app.test_owner_check_with_final_slots_held(|| owner.check(deadline(), false))?;
                    Ok::<_, String>(())
                }),
            )
            .await
            .map_err(|_| "fixture observer exceeded bounded lock check".to_string())?
        });
        runtime.shutdown_timeout(Duration::from_millis(100));
        let _ = tx.send(result);
    });
    let result = tokio::time::timeout(Duration::from_secs(2), rx)
        .await
        .unwrap()
        .unwrap();
    thread.join().unwrap();
    result.unwrap();
    assert!(!gate.entered.load(Ordering::SeqCst));
    assert_eq!(owner.workers.lock().unwrap().count, 0);
    assert!(!owner.is_terminal());
    assert!(line.same_owner(&owner));
}

#[path = "stock_bm1396_work_owner_tests.rs"]
mod work_owner_tests;
