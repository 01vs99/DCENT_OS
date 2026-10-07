use super::*;

#[tokio::test]
async fn exact_original_cold_commands_use_built_in_model_profile_and_order() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("stock_bm1396_cold_vectors.json")).unwrap();
    for (model, name) in [(Model::S17e, "s17e"), (Model::T17e, "t17e")] {
        let chains = vec![0, 2];
        let (hw, transport) = startup_owner(model, chains.clone()).await;
        for &chain in &chains {
            hw.misc.lock().unwrap().insert(chain, 0x1234_5678);
        }
        // Retain a stale record outside the new identity/Misc windows.
        hw.inner.words(&[0x02001800, 0x1234_5678, 0x11, 0x5555aaaa]);
        transport
            .initialize_cold_registers(deadline())
            .await
            .unwrap();
        let source = vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["model"] == name && case["old_misc"] == 0x1234_5678u32)
            .unwrap();
        let mut expected = Vec::new();
        for event in source["events"].as_array().unwrap() {
            if event[0] == "asic_write" {
                for &chain in &chains {
                    expected.push(ColdRegisterCommand {
                        chain,
                        broadcast: event[2] == 1,
                        chip_address: event[3].as_u64().unwrap() as u8,
                        register: event[4].as_u64().unwrap() as u8,
                        value: event[5].as_u64().unwrap() as u32,
                    });
                }
            }
        }
        assert_eq!(*hw.writes.lock().unwrap(), expected);
        let observation = transport.cold_register_observation().unwrap().unwrap();
        assert!(observation.completed_at().is_some());
        assert_eq!(observation.commands(), expected);
        assert_eq!(observation.host_baud_register(), 0x1a1a1a1a);
        assert_eq!(
            observation.raw_misc_records().len(),
            usize::from(model.expected_chips_per_present_chain()) * 4
        );
        assert_eq!(
            observation.core_profile(),
            if model == Model::S17e {
                [1, 3, 1]
            } else {
                [1, 2, 1]
            }
        );
        assert!(transport.assignment_observation().unwrap().is_some());
        assert_eq!(transport.pending_returns().unwrap().len(), 1);
        assert!(!hw
            .inner
            .writes()
            .iter()
            .any(|(offset, _)| *offset == DHASH || *offset == 0x30));
        assert!(transport
            .initialize_assigned_population(deadline())
            .await
            .is_err());
    }
}

#[tokio::test]
async fn cold_misc_uniformity_readback_and_changed_engine_presence_baud_refuse() {
    for defect in 8..=12 {
        let (hw, transport) = startup_owner(Model::T17e, vec![0]).await;
        hw.defect.store(defect, Ordering::SeqCst);
        assert!(
            transport
                .initialize_cold_registers(deadline())
                .await
                .is_err(),
            "defect {defect}"
        );
        assert!(transport.is_terminal());
        assert!(transport.asic_fault.load(Ordering::SeqCst));
        assert!(transport
            .cold_register_observation()
            .unwrap()
            .unwrap()
            .completed_at()
            .is_none());
        if defect == 8 {
            assert!(hw.writes.lock().unwrap().is_empty());
        }
        if defect <= 9 {
            assert!(!hw
                .commands
                .lock()
                .unwrap()
                .iter()
                .any(|(_, frame)| frame[0] == 0x40));
        }
        if defect == 10 {
            assert!(!hw
                .writes
                .lock()
                .unwrap()
                .iter()
                .any(|command| command.register == 0x6c));
        }
        if defect >= 11 {
            assert_eq!(
                hw.writes
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|command| command.register == 0x2c)
                    .count(),
                1
            );
        }
    }
}

#[tokio::test]
async fn canceled_cold_command_keeps_attempt_and_misc_custody_until_real_drain() {
    let (hw, transport) = startup_owner(Model::T17e, vec![0]).await;
    let block = ReadBlock::new(BC);
    *hw.cold_block.lock().unwrap() = Some(block.clone());
    let copy = transport.clone();
    let task = tokio::spawn(async move { copy.initialize_cold_registers(deadline()).await });
    let until = Instant::now() + Duration::from_secs(2);
    while !block.entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < until);
        tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.is_err());
    assert!(transport
        .drain(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    block.release();
    transport.drain(deadline()).await.unwrap();
    let observation = transport.cold_register_observation().unwrap().unwrap();
    assert!(observation.completed_at().is_none());
    assert_eq!(observation.raw_misc_records().len(), 156);
    assert_eq!(observation.commands().last().unwrap().register, 0x3c);
    assert_eq!(observation.commands().last().unwrap().value, 0x8000_8710);
    assert_eq!(
        observation
            .commands()
            .iter()
            .filter(|command| command.register == 0x3c)
            .count(),
        1
    );
    assert!(transport.assignment_observation().unwrap().is_some());
    assert!(transport.asic_fault.load(Ordering::SeqCst));
}

#[tokio::test]
async fn cold_active_or_spent_owner_cannot_issue_any_new_mutation() {
    let (hw, transport) = startup_owner(Model::S17e, vec![0]).await;
    hw.inner.regs.lock().unwrap().insert(DHASH, RUN);
    assert!(transport
        .initialize_cold_registers(deadline())
        .await
        .is_err());
    assert!(hw.inner.writes().is_empty());
    let (hw, transport) = startup_owner(Model::T17e, vec![0]).await;
    transport
        .initialize_assigned_population(deadline())
        .await
        .unwrap();
    let count = hw.inner.writes().len();
    assert!(transport
        .initialize_cold_registers(deadline())
        .await
        .is_err());
    assert_eq!(hw.inner.writes().len(), count);
    assert!(transport.cold_register_observation().unwrap().is_none());
}
