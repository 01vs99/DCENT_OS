use super::*;

async fn ready(
    model: Model,
    chains: Vec<u8>,
) -> (Arc<StartupHardware>, Arc<Transport<StartupHardware>>) {
    let (hw, owner) = startup_owner(model, chains).await;
    hw.stream_returns.store(true, Ordering::SeqCst);
    owner.initialize_cold_registers(deadline()).await.unwrap();
    hw.inner.events.lock().unwrap().clear();
    (hw, owner)
}

#[tokio::test]
async fn original_adc_windows_commands_reserved_lane_gaps_and_complete_custody() {
    for model in [Model::S17e, Model::T17e] {
        // All8 distinct PIC selectors exercise complete bounded ADC storage.
        let (hw, owner) = ready(model, (0..8).collect()).await;
        hw.inner.words(&[0x0200b400, 0xdead_beef, 0x11, 0x5555aaaa]);
        let sequence = owner.acquire_domain_adc(deadline()).await.unwrap();
        let observation = owner.domain_adc_observation().unwrap().unwrap();
        assert_eq!(observation.sequence(), sequence);
        assert_eq!(observation.model(), model);
        assert_eq!(observation.host_baud_register(), 0x1a1a1a1a);
        assert_eq!(observation.restored_chains(), (0..8).collect::<Vec<_>>());
        assert_eq!(observation.baseline_minimum_passed(), Some(true));
        assert_eq!(
            observation.raw_records().len(),
            usize::from(model.expected_chips_per_present_chain()) * 16
        );
        let expected: Vec<_> = (0..8)
            .flat_map(|chain| {
                [
                    DomainAdcCommand {
                        chain,
                        register: 0xb0,
                        value: Some(0x3014_003a),
                    },
                    DomainAdcCommand {
                        chain,
                        register: 0xb4,
                        value: None,
                    },
                    DomainAdcCommand {
                        chain,
                        register: 0xb8,
                        value: None,
                    },
                    DomainAdcCommand {
                        chain,
                        register: 0xb0,
                        value: Some(0x0010_0000),
                    },
                ]
            })
            .collect();
        assert_eq!(observation.commands(), expected);
        assert_eq!(
            hw.inner
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == Event::Sleep(1000))
                .count(),
            8 * 450
        );
        for chain in observation.chains() {
            assert_eq!(
                chain.chip_lanes().len(),
                usize::from(model.expected_chips_per_present_chain())
            );
            assert!(chain.chip_lanes().iter().all(|lanes| *lanes == [3000; 4]));
            assert_eq!(
                chain.domains().len(),
                if model == Model::S17e { 15 } else { 13 }
            );
            assert!(chain
                .domains()
                .iter()
                .all(|domain| domain.domain_voltage_v.to_bits() == 1.0986328125f32.to_bits()));
        }
        assert!(!hw.overflow.load(Ordering::SeqCst));
        assert_eq!(owner.pending_returns().unwrap().len(), 1);
        let writes = hw.inner.writes().len();
        assert!(owner.acquire_domain_adc(deadline()).await.is_err());
        assert_eq!(hw.inner.writes().len(), writes);
        owner.acknowledge_domain_adc(&observation).unwrap();
        assert!(owner.acknowledge_domain_adc(&observation).is_err());
        assert!(owner.domain_adc_observation().unwrap().is_none());
    }
}

#[tokio::test]
async fn missing_duplicate_foreign_early_crc_or_changed_carrier_adc_never_complete() {
    for defect in [20, 21, 22, 23, 24, 25, 26, 30, 31, 32, 33] {
        let (hw, owner) = ready(Model::T17e, vec![0, 2]).await;
        if defect == 20 {
            // A pre-existing valid final B4 cannot fill the missing fresh slot.
            hw.inner.words(&[
                u32::from_le_bytes([0, 0xb4, 231, 2]),
                0x0bb8_0bb8,
                0x11,
                0x5555aaaa,
            ]);
        }
        hw.defect.store(defect, Ordering::SeqCst);
        assert!(
            owner.acquire_domain_adc(deadline()).await.is_err(),
            "defect {defect}"
        );
        assert!(owner.is_terminal());
        let observation = owner.domain_adc_observation().unwrap().unwrap();
        assert!(observation.completed_at().is_none());
        assert!(observation.restored_chains().is_empty());
        assert!(owner.acknowledge_domain_adc(&observation).is_err());
        if !matches!(defect, 30 | 31) {
            assert!(!owner.pending_returns().unwrap().is_empty());
        }
        if defect == 32 {
            assert!(owner
                .pending_returns()
                .unwrap()
                .iter()
                .any(|raw| raw.words() == [0x80010080, 0, 0, 0x5555aaaa]));
        }
    }
}

#[tokio::test]
async fn below_minimum_retains_complete_adc_and_restore_failure_is_explicit_partial() {
    for defect in [27, 28, 29] {
        let (hw, owner) = ready(Model::S17e, vec![0, 2]).await;
        hw.defect.store(defect, Ordering::SeqCst);
        assert!(owner.acquire_domain_adc(deadline()).await.is_err());
        assert!(owner.is_terminal());
        let observation = owner.domain_adc_observation().unwrap().unwrap();
        assert!(!observation.raw_records().is_empty());
        if defect == 27 {
            assert_eq!(
                observation.commands().last().unwrap().value,
                Some(0x0010_0000)
            );
            assert!(observation.restored_chains().is_empty());
            assert!(observation.completed_at().is_none());
        } else {
            assert_eq!(observation.restored_chains(), [0, 2]);
            assert_eq!(observation.baseline_minimum_passed(), Some(false));
            assert_eq!(observation.raw_records().len(), 540);
        }
    }
}

#[tokio::test]
async fn canceled_second_adc_request_keeps_partial_returns_and_real_worker_until_drain() {
    let (hw, owner) = ready(Model::T17e, vec![0]).await;
    let block = ReadBlock::new(BC);
    *hw.adc_block.lock().unwrap() = Some(block.clone());
    let copy = owner.clone();
    let task = tokio::spawn(async move { copy.acquire_domain_adc(deadline()).await });
    let until = Instant::now() + Duration::from_secs(2);
    while !block.entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < until);
        tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.is_err());
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    assert!(owner.domain_adc_observation().is_err());
    block.release();
    owner.drain(deadline()).await.unwrap();
    let observation = owner.domain_adc_observation().unwrap().unwrap();
    assert_eq!(observation.commands().last().unwrap().register, 0xb8);
    assert!(observation.completed_at().is_none());
    assert!(observation.restored_chains().is_empty());
    assert_eq!(owner.pending_returns().unwrap().len(), 78);
    assert!(owner.asic_fault.load(Ordering::SeqCst));
}

#[tokio::test]
async fn adc_requires_cold_receipt_deadline_and_same_owner_acknowledgment() {
    let (hw, owner) = startup_owner(Model::S17e, vec![0]).await;
    assert!(owner.acquire_domain_adc(deadline()).await.is_err());
    assert!(hw.inner.writes().is_empty());
    let (hw, owner) = ready(Model::S17e, vec![0]).await;
    let reads = hw.commands.lock().unwrap().len();
    assert!(owner
        .acquire_domain_adc(Instant::now() + Duration::from_millis(100))
        .await
        .is_err());
    assert!(hw.commands.lock().unwrap().len() <= reads + 2);
    assert!(owner
        .domain_adc_observation()
        .unwrap()
        .unwrap()
        .completed_at()
        .is_none());
    let (_, first) = ready(Model::T17e, vec![0]).await;
    let (_, second) = ready(Model::T17e, vec![0]).await;
    first.acquire_domain_adc(deadline()).await.unwrap();
    second.acquire_domain_adc(deadline()).await.unwrap();
    let foreign = first.domain_adc_observation().unwrap().unwrap();
    assert!(second.acknowledge_domain_adc(&foreign).is_err());
}
