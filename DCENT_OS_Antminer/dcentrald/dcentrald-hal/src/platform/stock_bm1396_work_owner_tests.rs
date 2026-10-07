//! Actual work-owner custody and mixed-FIFO tests using the existing
//! adapted/prepared hardware; no synthetic startup-ready fixture.
use super::*;

fn fixed_test_packet(id: u32) -> Vec<u8> {
    // Independent fixed source grammar fixture; no CPU/header qualification is
    // claimed by this HAL custody test. The daemon has separate actual vectors.
    let mut bytes = packet(id);
    bytes.extend([0, 0]);
    let body = bytes.len() as u32 - 8;
    bytes[4..8].copy_from_slice(&body.to_le_bytes());
    bytes[9] = 3;
    bytes[10] = 0x0f;
    bytes[0x40] = 0;
    bytes[0x54..0x58].copy_from_slice(&1u32.to_le_bytes());
    let fixed = bytes[0x60..0x68].to_vec();
    bytes[0x48..0x50].copy_from_slice(&fixed);
    let mut crc = 0xffffu16;
    for &byte in &bytes[..bytes.len() - 2] {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xa001 } else { 0 };
        }
    }
    let end = bytes.len();
    bytes[end - 2..].copy_from_slice(&crc.to_le_bytes());
    bytes
}
fn thermal_word(address: u8) -> [u32; 4] {
    [
        u32::from_le_bytes([0, 0x44, address, 2]),
        (112 << 16) | 0x180,
        0x11,
        0x5555aaaa,
    ]
}
fn arm_work_step(hw: &PreparationHardware) -> Arc<ReadBlock> {
    let gate = ReadBlock::new(0);
    *hw.inner().sleep_block.lock().unwrap() = Some((Duration::from_millis(1), gate.clone()));
    gate
}
async fn advance_work_step(hw: &PreparationHardware, previous: &ReadBlock) -> Arc<ReadBlock> {
    let next = arm_work_step(hw);
    previous.release();
    wait_gate(&next).await;
    next
}
async fn work_event(events: &mut FixedWorkEvents) -> FixedWorkEvent {
    tokio::time::timeout(Duration::from_secs(1), events.next())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_work_waits_for_partial_thermal_head_before_offering_and_acknowledging_later_nonce() {
    let (hw, owner, app, line, _pin, _) = adapted(&[0]).await;
    let final_observation = app
        .initialize_final_pll(line.clone(), deadline())
        .await
        .unwrap();
    // Existing fixture absence mode stops only automatic traffic emission after
    // actual adapted FreshThermal. This test injects real register44 words below;
    // no timestamp, configuration, worker identity or ready record is replaced.
    hw.adapted_defect.store(3, Ordering::SeqCst);
    let (control, mut events, _health, inbox) = app.fixed_work_channels();
    control
        .enqueue_publication(fixed_test_packet(0), deadline())
        .await
        .unwrap();
    let first = arm_work_step(&hw);
    let task = {
        let app = app.clone();
        let line = line.clone();
        tokio::spawn(async move { app.serve_fixed_work(line, inbox, deadline()).await })
    };
    wait_gate(&first).await; // Actual original publication Delay1ms before seal.
    let mut gate = advance_work_step(&hw, &first).await;
    let FixedWorkEvent::Publication(publication) = work_event(&mut events).await else {
        panic!("actual completed publication must precede work returns")
    };
    assert!(publication.completed() && publication.same_owner(&owner));
    assert_eq!(publication.job_id(), 0);
    control
        .acknowledge_publication(publication, deadline())
        .await
        .unwrap();
    gate = advance_work_step(&hw, &gate).await;
    hw.inner().dma.lock().unwrap()[64..68].copy_from_slice(&0u32.to_le_bytes());
    let first_thermal = thermal_word(51);
    hw.queue_words(&first_thermal);
    hw.queue_words(&[0x80010080, 0, 0, 0x5555aaaa]);
    gate = advance_work_step(&hw, &gate).await;
    assert!(
        hw.inner().returns.lock().unwrap().is_empty(),
        "actual mixed bytes were consumed"
    );
    assert_eq!(owner.workers.lock().unwrap().count, 1);
    assert!(owner.asic.try_lock().is_err());
    let early = tokio::time::timeout(Duration::from_millis(5), events.next()).await;
    match early {
        Err(_) => {}
        Ok(Some(FixedWorkEvent::Return(raw))) => {
            // Against preserved v2 this is the actual premature-delivery path:
            // its valid copied nonce cannot acknowledge the prior temperature head.
            control.acknowledge_return(raw, deadline()).await.unwrap();
            gate.release();
            let result = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            panic!(
                "nonce overtook incomplete thermal head; actual acknowledgement result: {result:?}"
            );
        }
        other => panic!("no event may bypass incomplete thermal head: {other:?}"),
    }
    assert!(!task.is_finished() && !owner.is_terminal());
    for address in [36, 195, 180] {
        hw.queue_words(&thermal_word(address));
    }
    gate = advance_work_step(&hw, &gate).await;
    let FixedWorkEvent::Thermal(snapshot) = work_event(&mut events).await else {
        panic!("complete actual thermal population must take custody first")
    };
    let FixedWorkEvent::Return(raw) = work_event(&mut events).await else {
        panic!("retained nonce follows completed thermal transfer")
    };
    assert_eq!(snapshot.epoch(), 1);
    assert_eq!(snapshot.raw_records().len(), 4);
    assert_eq!(snapshot.raw_records()[0].words(), first_thermal.as_slice());
    assert!(snapshot.raw_records()[0].sequence() < raw.sequence());
    assert!(raw.sequence() < snapshot.raw_records()[1].sequence());
    assert!(matches!(raw.payload(), ReturnPayload::Nonce { .. }));
    assert!(raw.same_owner(&owner));
    control
        .acknowledge_thermal(snapshot, deadline())
        .await
        .unwrap();
    control.acknowledge_return(raw, deadline()).await.unwrap();
    gate = advance_work_step(&hw, &gate).await;
    gate = advance_work_step(&hw, &gate).await;
    assert!(!task.is_finished() && !owner.is_terminal());
    owner.begin_terminal();
    gate.release();
    assert!(task.await.unwrap().is_err());
    line.terminal_high(deadline()).await.unwrap();
    owner.drain(deadline()).await.unwrap();
    assert!(owner.pending_returns().unwrap().is_empty());
    assert!(owner.pending_thermal_snapshots().unwrap().is_empty());
    assert_eq!(
        app.final_pll_observation().unwrap().unwrap().completed_at(),
        final_observation.completed_at()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_work_requires_actual_final_and_exact_inbox_before_any_dma_or_job_publication() {
    for foreign in [false, true] {
        let (hw, owner, app, line, _pin, _) = adapted(&[0]).await;
        let (_other_hw, other_owner, other_app, _other_line, _other_pin) = prepared(&[0]).await;
        if foreign {
            app.initialize_final_pll(line.clone(), deadline())
                .await
                .unwrap();
        }
        let (control, _events, _health, inbox) = if foreign {
            other_app.fixed_work_channels()
        } else {
            app.fixed_work_channels()
        };
        control
            .enqueue_publication(fixed_test_packet(0), deadline())
            .await
            .unwrap();
        let before = hw.inner().events.lock().unwrap().clone();
        let error = app
            .serve_fixed_work(line.clone(), inbox, deadline())
            .await
            .unwrap_err();
        assert!(
            error.contains(if foreign {
                "inbox belongs to another transport"
            } else {
                "actual final PLL absent"
            }),
            "{error}"
        );
        let events = hw.inner().events.lock().unwrap().clone();
        assert!(!events[before.len()..].iter().any(|event| matches!(
            event,
            Event::DmaWrite(_, _) | Event::Write(0x110 | 0x118, _)
        )));
        assert!(owner.publications().unwrap().is_empty());
        assert!(!owner.asic.lock().unwrap().dma_initialized);
        assert!(owner.is_terminal() && !other_owner.is_terminal());
        assert_eq!(owner.workers.lock().unwrap().count, 0);
        line.terminal_high(deadline()).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_work_keeps_voltage_lease_and_heartbeat_lane_until_cancelled_partial_publication_drains(
) {
    let (hw, owner, app, line, _pin, _) = adapted(&[0]).await;
    app.initialize_final_pll(line.clone(), deadline())
        .await
        .unwrap();
    hw.adapted_defect.store(3, Ordering::SeqCst);
    let current = app.last_commanded_voltage().unwrap().unwrap();
    let before_voltage_frames = hw.voltage_frames.load(Ordering::SeqCst);
    let (control, _events, _health, inbox) = app.fixed_work_channels();
    control
        .enqueue_publication(fixed_test_packet(0), deadline())
        .await
        .unwrap();
    let gate = arm_work_step(&hw);
    let task = {
        let app = app.clone();
        let line = line.clone();
        tokio::spawn(async move { app.serve_fixed_work(line, inbox, deadline()).await })
    };
    wait_gate(&gate).await; // Original first publication Delay1ms, not a fake busy bit.
    let competitor = {
        let app = app.clone();
        tokio::spawn(async move {
            app.command_voltage_ramp(current.requested_centivolts(), deadline())
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while owner.workers.lock().unwrap().count != 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(!competitor.is_finished());
    assert!(owner.asic.try_lock().is_err());
    assert!(app.voltage_attempts().unwrap().is_empty());
    assert_eq!(
        hw.voltage_frames.load(Ordering::SeqCst),
        before_voltage_frames
    );
    app.heartbeat_round(deadline()).await.unwrap();
    app.check_health(deadline()).unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    line.terminal_high(deadline()).await.unwrap();
    gate.release();
    assert!(competitor.await.unwrap().is_err());
    owner.drain(deadline()).await.unwrap();
    assert_eq!(owner.workers.lock().unwrap().count, 0);
    assert_eq!(app.last_commanded_voltage().unwrap(), Some(current));
    assert_eq!(
        hw.voltage_frames.load(Ordering::SeqCst),
        before_voltage_frames
    );
    let retained = owner.publications().unwrap();
    assert_eq!(retained.len(), 1);
    assert!(!retained[0].completed());
    assert!(owner.is_terminal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_work_closed_control_or_receipt_channel_refuses_before_dma_admission() {
    for close_control in [false, true] {
        let (hw, owner, app, line, _pin, _) = adapted(&[0]).await;
        app.initialize_final_pll(line.clone(), deadline())
            .await
            .unwrap();
        let (control, events, _health, inbox) = app.fixed_work_channels();
        let mut control = Some(control);
        let mut events = Some(events);
        if close_control {
            control.take();
        } else {
            events.take();
        }
        let before = hw.inner().events.lock().unwrap().clone();
        let error = app
            .serve_fixed_work(line.clone(), inbox, deadline())
            .await
            .unwrap_err();
        assert!(
            error.contains("channel owner closed before DMA admission"),
            "{error}"
        );
        let after = hw.inner().events.lock().unwrap().clone();
        assert!(!after[before.len()..].iter().any(|event| matches!(
            event,
            Event::DmaWrite(_, _) | Event::Write(0x110 | 0x118, _)
        )));
        assert!(!owner.asic.lock().unwrap().dma_initialized);
        assert!(owner.publications().unwrap().is_empty());
        assert!(owner.is_terminal());
        line.terminal_high(deadline()).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_work_next_publication_requires_exact_completed_publication_acknowledgement() {
    for foreign_ack in [false, true] {
        let (hw, owner, app, line, _pin, _) = adapted(&[0]).await;
        app.initialize_final_pll(line.clone(), deadline())
            .await
            .unwrap();
        hw.adapted_defect.store(3, Ordering::SeqCst);
        let (control, mut events, _health, inbox) = app.fixed_work_channels();
        control
            .enqueue_publication(fixed_test_packet(0), deadline())
            .await
            .unwrap();
        let first = arm_work_step(&hw);
        let task = {
            let app = app.clone();
            let line = line.clone();
            tokio::spawn(async move { app.serve_fixed_work(line, inbox, deadline()).await })
        };
        wait_gate(&first).await;
        let gate = advance_work_step(&hw, &first).await;
        let FixedWorkEvent::Publication(published) = work_event(&mut events).await else {
            panic!("publication expected")
        };
        assert!(published.completed());
        if foreign_ack {
            let (_other_hw, other) = crate::platform::stock_bm1396::tests::owner(Model::T17e).await;
            other.initialize_dma(deadline()).await.unwrap();
            let other_publication = other
                .publish_job(fixed_test_packet(0), false, 1179, deadline())
                .await
                .unwrap();
            assert!(!other_publication.same_owner(&owner));
            control
                .acknowledge_publication(other_publication, deadline())
                .await
                .unwrap();
        } else {
            control
                .enqueue_publication(fixed_test_packet(1), deadline())
                .await
                .unwrap();
        }
        gate.release();
        let error = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(
            error.contains(if foreign_ack {
                "publication acknowledgement is foreign or out of order"
            } else {
                "prior completed publication is not acknowledged"
            }),
            "{error}"
        );
        line.terminal_high(deadline()).await.unwrap();
        owner.drain(deadline()).await.unwrap();
        assert_eq!(owner.publications().unwrap(), vec![published]);
        assert!(owner.is_terminal());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_work_packet_bounds_and_original_queue_deadline_refuse_without_hardware_admission() {
    let (_hw, owner, app, line, _pin) = prepared(&[0]).await;
    let (control, _events, _health, _inbox) = app.fixed_work_channels();
    for (offset, value, expected) in [
        (9, 1, "qualified fixed-domain"),
        (10, 6, "qualified fixed-domain"),
        (0x40, 8, "qualified fixed-domain"),
        (0x54, 2, "qualified fixed-domain"),
        (0x48, 0, "fixed EN2 differs"),
        (0x58, 0, "packet CRC differs"),
    ] {
        let mut bytes = fixed_test_packet(0);
        bytes[offset] = value;
        let error = control
            .enqueue_publication(bytes, deadline())
            .await
            .unwrap_err();
        assert!(error.contains(expected), "offset {offset:x}: {error}");
    }
    let error = control
        .enqueue_publication(vec![0; 0x10000 + 0x59], deadline())
        .await
        .unwrap_err();
    assert!(error.contains("packet exceeds source bound"), "{error}");
    let error = control
        .enqueue_publication(fixed_test_packet(0), Instant::now())
        .await
        .unwrap_err();
    assert!(error.contains("deadline already elapsed"), "{error}");
    // All refusals preceded reservation: every one of the eight real slots is
    // still available. The ninth actual request waits only its original budget.
    for id in 0..8 {
        control
            .enqueue_publication(fixed_test_packet(id), deadline())
            .await
            .unwrap();
    }
    let error = control
        .enqueue_publication(
            fixed_test_packet(8),
            Instant::now() + Duration::from_millis(10),
        )
        .await
        .unwrap_err();
    assert!(error.contains("queue deadline"), "{error}");
    assert!(!owner.is_terminal());
    assert!(!owner.asic.lock().unwrap().dma_initialized);
    assert!(owner.publications().unwrap().is_empty());
    line.terminal_high(deadline()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_work_actual_return_backpressure_preserves_sequence_without_duplicate_delivery() {
    let (hw, owner, app, line, _pin, _) = adapted(&[0]).await;
    app.initialize_final_pll(line.clone(), deadline())
        .await
        .unwrap();
    hw.adapted_defect.store(3, Ordering::SeqCst);
    let (control, mut events, _health, inbox) = app.fixed_work_channels();
    control
        .enqueue_publication(fixed_test_packet(0), deadline())
        .await
        .unwrap();
    let first = arm_work_step(&hw);
    let task = {
        let app = app.clone();
        let line = line.clone();
        tokio::spawn(async move { app.serve_fixed_work(line, inbox, deadline()).await })
    };
    wait_gate(&first).await;
    let mut gate = advance_work_step(&hw, &first).await;
    let FixedWorkEvent::Publication(publication) = work_event(&mut events).await else {
        panic!("publication expected")
    };
    control
        .acknowledge_publication(publication, deadline())
        .await
        .unwrap();
    gate = advance_work_step(&hw, &gate).await;
    hw.inner().dma.lock().unwrap()[64..68].copy_from_slice(&0u32.to_le_bytes());
    for nonce in 0..24 {
        hw.queue_words(&[0x80010080, nonce, 0, 0x5555aaaa]);
    }
    gate = advance_work_step(&hw, &gate).await;
    assert!(hw.inner().returns.lock().unwrap().is_empty());
    assert!(!hw.overflow.load(Ordering::SeqCst));
    // Twenty-four actual retained records exceed the sixteen-event channel;
    // repeated full flush attempts must retain the remainder without reoffering.
    for _ in 0..3 {
        gate = advance_work_step(&hw, &gate).await;
    }
    let mut delivered = Vec::new();
    let mut last_delivered = None;
    for _ in 0..24 {
        let FixedWorkEvent::Return(raw) = work_event(&mut events).await else {
            panic!("nonce expected")
        };
        assert!(matches!(raw.payload(), ReturnPayload::Nonce { .. }));
        assert!(raw.same_owner(&owner));
        if let Some(previous) = delivered.last() {
            assert_eq!(raw.sequence(), previous + 1);
        }
        delivered.push(raw.sequence());
        last_delivered = Some(raw.clone());
        control.acknowledge_return(raw, deadline()).await.unwrap();
        gate = advance_work_step(&hw, &gate).await;
    }
    assert_eq!(delivered.len(), 24);
    assert!(
        tokio::time::timeout(Duration::from_millis(5), events.next())
            .await
            .is_err()
    );
    assert!(!task.is_finished() && !owner.is_terminal());
    // The exact last record was delivered and its first actual ack completed.
    // A duplicate cannot advance another record or silently count as progress.
    control
        .acknowledge_return(last_delivered.unwrap(), deadline())
        .await
        .unwrap();
    gate.release();
    let error = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        error.contains("return was not offered to this consumer"),
        "{error}"
    );
    line.terminal_high(deadline()).await.unwrap();
    owner.drain(deadline()).await.unwrap();
    assert!(owner.pending_returns().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_work_partial_publication_retains_actual_hot_reset_source_and_elapsed_budget_failures(
) {
    for defect in 0..4 {
        let (hw, owner, app, line, _pin, _) = adapted(&[0]).await;
        let final_receipt = app
            .initialize_final_pll(line.clone(), deadline())
            .await
            .unwrap();
        hw.adapted_defect.store(3, Ordering::SeqCst);
        let (control, _events, _health, inbox) = app.fixed_work_channels();
        control
            .enqueue_publication(fixed_test_packet(0), deadline())
            .await
            .unwrap();
        let gate = arm_work_step(&hw);
        let task = {
            let app = app.clone();
            let line = line.clone();
            tokio::spawn(async move { app.serve_fixed_work(line, inbox, deadline()).await })
        };
        wait_gate(&gate).await;
        match defect {
            0 => {
                let mut hot = thermal_word(51);
                hot[1] = (164 << 16) | 0x180;
                hw.queue_words(&hot);
            }
            1 => {
                *hw.inner().regs.lock().unwrap().entry(0x34).or_default() ^= 1;
            }
            2 => {
                line.terminal_high(deadline()).await.unwrap();
            }
            3 => {
                tokio::time::sleep(Duration::from_millis(1100)).await;
            }
            _ => unreachable!(),
        }
        gate.release();
        let error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(
            error.contains(match defect {
                0 => "temperature reached cutoff",
                1 => "current work epoch/source state changed",
                2 => "terminal",
                3 => "deadline",
                _ => unreachable!(),
            }),
            "defect {defect}: {error}"
        );
        line.terminal_high(deadline()).await.unwrap();
        owner.drain(deadline()).await.unwrap();
        let publications = owner.publications().unwrap();
        assert_eq!(publications.len(), 1);
        assert!(!publications[0].completed());
        assert!(owner.is_terminal());
        assert_eq!(
            app.final_pll_observation().unwrap().unwrap().completed_at(),
            final_receipt.completed_at()
        );
        if defect == 0 {
            let raw = owner.pending_returns().unwrap();
            assert_eq!(raw.len(), 1);
            assert!(matches!(raw[0].payload(), ReturnPayload::Temperature(_)));
            assert_eq!(raw[0].words()[1], (164 << 16) | 0x180);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_work_channel_close_while_actual_asic_entry_is_blocked_prevents_dma() {
    for close_control in [false, true] {
        let (hw, owner, app, line, _pin, _) = adapted(&[0]).await;
        app.initialize_final_pll(line.clone(), deadline())
            .await
            .unwrap();
        let (control, events, _health, inbox) = app.fixed_work_channels();
        control
            .enqueue_publication(fixed_test_packet(0), deadline())
            .await
            .unwrap();
        let mut control = Some(control);
        let mut events = Some(events);
        let gate = ReadBlock::new(0x34);
        *hw.inner().block.lock().unwrap() = Some(gate.clone());
        let holder = {
            let owner = owner.clone();
            tokio::spawn(async move {
                owner
                    .worker(deadline(), false, move |owner| {
                        let _state = owner.lock(&owner.asic, deadline(), false)?;
                        owner.hardware.read(0x34)?;
                        Ok(())
                    })
                    .await
            })
        };
        wait_gate(&gate).await;
        let before = hw.inner().events.lock().unwrap().clone();
        let task = {
            let app = app.clone();
            let line = line.clone();
            tokio::spawn(async move { app.serve_fixed_work(line, inbox, deadline()).await })
        };
        // The holder never sleeps. This actual one-millisecond sleep therefore
        // proves serve entered the real ASIC WouldBlock loop after its first
        // closure check, instead of merely waiting for a Tokio spawn to run.
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let now = hw.inner().events.lock().unwrap().clone();
                if now[before.len()..]
                    .iter()
                    .any(|event| matches!(event, Event::Sleep(1000)))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(owner.workers.lock().unwrap().count, 2);
        assert!(!task.is_finished());
        if close_control {
            control.take();
        } else {
            events.take();
        }
        gate.release();
        holder.await.unwrap().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(
            error.contains("channel owner closed during operation service"),
            "{error}"
        );
        line.terminal_high(deadline()).await.unwrap();
        owner.drain(deadline()).await.unwrap();
        let after = hw.inner().events.lock().unwrap().clone();
        assert!(!after[before.len()..].iter().any(|event| matches!(
            event,
            Event::DmaWrite(_, _) | Event::Write(0x110 | 0x118, _)
        )));
        assert!(!owner.asic.lock().unwrap().dma_initialized);
        assert!(owner.publications().unwrap().is_empty());
        assert!(owner.is_terminal());
    }
}
