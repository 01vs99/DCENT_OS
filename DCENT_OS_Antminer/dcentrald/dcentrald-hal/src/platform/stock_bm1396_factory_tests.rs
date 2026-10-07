use super::*;
use dcentrald_common::bm1396_auto_adapt_voltage::Bm1396AutoAdaptProfile;

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("stock_bm1396_factory_vectors.json")).unwrap()
}
fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
pub(super) fn golden() -> Vec<u8> {
    let data = vectors();
    bytes(
        data["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["label"] == "range_1800")
            .unwrap()["records"]["0"]
            .as_str()
            .unwrap(),
    )
}
async fn factory_owner(chains: Vec<u8>) -> (Arc<Fake>, Arc<Transport<Fake>>) {
    let mask = chains.iter().fold(0, |mask, &chain| mask | 1 << chain);
    let fake = Fake::new(Model::T17e, mask);
    let owner = Transport::observe(fake.clone(), Model::T17e, chains)
        .await
        .unwrap();
    (fake, owner)
}

#[tokio::test]
async fn factory_all_selectors_match_complete_original_read_words() {
    for chains in (0..8)
        .map(|chain| vec![chain])
        .chain(std::iter::once(vec![0, 2, 7]))
    {
        let (fake, owner) = factory_owner(chains.clone()).await;
        for _ in &chains {
            fake.reply(&golden());
        }
        let profile = owner.acquire_factory_calibration(deadline()).await.unwrap();
        assert_eq!(
            profile,
            Bm1396AutoAdaptProfile::Signed2020T17eCalibration {
                calibration_cv: 1800
            }
        );
        assert_eq!(owner.factory_calibration_profile().unwrap(), profile);
        let observation = owner.factory_calibration_observation().unwrap().unwrap();
        assert!(observation.acquired_at().is_some());
        assert_eq!(observation.profile(), Some(profile));
        assert_eq!(observation.records().len(), chains.len());
        for (chain, record) in chains.iter().zip(observation.records()) {
            assert_eq!(record.chain(), *chain);
            assert_eq!(record.bytes(), golden());
            assert!(record.completed_at().is_some());
            assert_eq!(record.calibration().unwrap().as_ref().unwrap(), &1800);
        }
        let expected: Vec<_> = chains
            .iter()
            .flat_map(|&chain| {
                (0..=255).map(move |offset| {
                    (0x30, 0x03a00000 | (u32::from(chain) << 16) | (offset << 8))
                })
            })
            .collect();
        assert_eq!(fake.writes(), expected);
        let events = fake.events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == Event::Sleep(500000))
                .count(),
            chains.len()
        );
    }
}

#[tokio::test]
async fn factory_original_population_cases_and_narrow_native_anchors() {
    let data = vectors();
    for case in data["cases"].as_array().unwrap() {
        if !case["timeout"].is_null() {
            continue;
        }
        let records = case["records"].as_object().unwrap();
        let chains: Vec<_> = records
            .keys()
            .map(|key| key.parse::<u8>().unwrap())
            .collect();
        let (fake, owner) = factory_owner(chains.clone()).await;
        for chain in &chains {
            fake.reply(&bytes(records[&chain.to_string()].as_str().unwrap()));
        }
        let value = case["calibration_cv"].as_u64().unwrap();
        let accepted = case["returned"] == 0 && (1760..=1840).contains(&value);
        assert_eq!(
            owner.acquire_factory_calibration(deadline()).await.is_ok(),
            accepted,
            "{}",
            case["label"]
        );
        let observation = owner.factory_calibration_observation().unwrap().unwrap();
        assert!(observation.acquired_at().is_some());
        assert!(observation
            .records()
            .iter()
            .all(|record| record.bytes().len() == 256));
        assert_eq!(observation.profile().is_some(), accepted);
        assert_eq!(owner.factory_calibration_profile().is_ok(), accepted);
        assert_eq!(owner.is_terminal(), !accepted);
        // Fully consumed negative data does not invent an incomplete PIC frame.
        assert!(!owner.management_fault.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn factory_model_engine_presence_and_spent_owner_fail_before_new_store() {
    for change in ["run", "presence", "startup"] {
        let (fake, owner) = factory_owner(vec![0]).await;
        match change {
            "run" => {
                fake.regs.lock().unwrap().insert(DHASH, RUN);
            }
            "presence" => {
                fake.regs.lock().unwrap().insert(8, 3);
            }
            _ => {
                owner.asic.lock().unwrap().startup_attempted = true;
            }
        }
        assert!(owner.acquire_factory_calibration(deadline()).await.is_err());
        assert!(fake.writes().is_empty());
        assert!(owner.factory_calibration_observation().unwrap().is_none());
    }
    let (fake, owner) = factory_owner(vec![0]).await;
    fake.reply(&golden());
    owner.acquire_factory_calibration(deadline()).await.unwrap();
    let before = owner.factory_calibration_observation().unwrap();
    let writes = fake.writes();
    assert!(owner.acquire_factory_calibration(deadline()).await.is_err());
    assert_eq!(fake.writes(), writes);
    assert_eq!(owner.factory_calibration_observation().unwrap(), before);
}

pub(super) fn s17e_record(voltage: u16) -> Vec<u8> {
    use dcentrald_common::bm1396_s17e_factory::factory_crc;
    let mut bytes = vec![0; 256];
    bytes[..2].copy_from_slice(&0x1396u16.to_le_bytes());
    bytes[0x28..0x2a].copy_from_slice(&0x1396u16.to_le_bytes());
    for (index, value) in bytes[0x2a..0xb1].iter_mut().enumerate() {
        *value = 78 + (index % 9) as u8;
    }
    bytes[0xb1..0xb3].copy_from_slice(&voltage.to_le_bytes());
    bytes[0xb9] = 1;
    let first = factory_crc(&bytes[..0x26]);
    let second = factory_crc(&bytes[0x28..0xfe]);
    bytes[0x26..0x28].copy_from_slice(&first.to_le_bytes());
    bytes[0xfe..].copy_from_slice(&second.to_le_bytes());
    bytes
}

#[tokio::test]
async fn s17e_acquires_each_actual_factory_record_and_never_uses_t17e_calibration() {
    for invalid in [false, true] {
        let fake = Fake::new(Model::S17e, 5);
        let owner = Transport::observe(fake.clone(), Model::S17e, vec![0, 2])
            .await
            .unwrap();
        assert!(owner.s17e_factory_records().is_err());
        for voltage in [1900, 1920] {
            fake.reply(&if invalid {
                golden()
            } else {
                s17e_record(voltage)
            });
        }
        let result = owner.acquire_factory_calibration(deadline()).await;
        let observed = owner.factory_calibration_observation().unwrap().unwrap();
        assert_eq!(observed.records().len(), 2);
        assert!(observed
            .records()
            .iter()
            .all(|record| record.bytes().len() == 256 && record.calibration().is_none()));
        assert_eq!(fake.writes().len(), 512);
        assert!(fake
            .writes()
            .iter()
            .all(|(offset, word)| *offset == 0x30 && word & 0xfff0_00ff == 0x03a0_0000));
        if invalid {
            assert!(result.is_err());
            assert!(owner.s17e_factory_records().is_err());
            assert!(owner.is_terminal());
        } else {
            assert_eq!(result.unwrap(), Bm1396AutoAdaptProfile::Signed2020S17eFixed);
            let records = owner.s17e_factory_records().unwrap();
            assert_eq!(
                records.iter().map(|(chain, _)| *chain).collect::<Vec<_>>(),
                [0, 2]
            );
            assert_eq!(records[1].1.frequencies_mhz().len(), 135);
            assert_eq!(records[1].1.frequencies_mhz()[134], 430);
            let before = fake.writes();
            assert!(owner.acquire_factory_calibration(deadline()).await.is_err());
            assert_eq!(fake.writes(), before);
        }
    }
}

#[tokio::test]
async fn factory_short_timeout_and_failed_store_retain_actual_progress() {
    for kind in ["short", "timeout", "store"] {
        let (fake, owner) = factory_owner(vec![0, 2]).await;
        match kind {
            "short" => fake.reply(&golden()[..131]),
            "timeout" => fake.management_timeout.store(true, Ordering::SeqCst),
            _ => fake.fail_write.store(0x30, Ordering::SeqCst),
        }
        assert!(owner.acquire_factory_calibration(deadline()).await.is_err());
        assert!(owner.is_terminal());
        assert!(owner.management_fault.load(Ordering::SeqCst));
        let observation = owner.factory_calibration_observation().unwrap().unwrap();
        assert_eq!(observation.records().len(), 1);
        let read = if kind == "short" { 131 } else { 0 };
        assert_eq!(observation.records()[0].bytes().len(), read);
        assert_eq!(
            observation.records()[0].attempted_word(),
            Some(0x03a00000 | ((read as u32) << 8))
        );
        assert_eq!(observation.records()[0].completed_at(), None);
        assert_eq!(observation.acquired_at(), None);
        assert_eq!(observation.profile(), None);
        assert_eq!(fake.writes().len(), read + 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn factory_cancellation_retains_completed_byte_and_real_worker() {
    let (fake, owner) = factory_owner(vec![0]).await;
    fake.reply(&golden());
    let block = ReadBlock::new(0x30);
    *fake.block.lock().unwrap() = Some(block.clone());
    let task = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.acquire_factory_calibration(deadline()).await })
    };
    while !block.entered.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(owner.is_terminal());
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(5))
        .await
        .is_err());
    block.release();
    owner.drain(deadline()).await.unwrap();
    let observation = owner.factory_calibration_observation().unwrap().unwrap();
    assert_eq!(observation.records()[0].bytes(), &golden()[..1]);
    assert!(observation.acquired_at().is_none());
    assert!(observation.profile().is_none());
    assert_eq!(fake.writes(), [(0x30, 0x03a00000)]);
}

#[tokio::test]
async fn factory_late_final_byte_is_retained_without_admission() {
    let (fake, owner) = factory_owner(vec![0]).await;
    fake.reply(&golden());
    fake.late_final_reply.store(true, Ordering::SeqCst);
    assert!(owner
        .acquire_factory_calibration(Instant::now() + Duration::from_millis(500))
        .await
        .is_err());
    let observation = owner.factory_calibration_observation().unwrap().unwrap();
    assert_eq!(observation.records()[0].bytes(), golden());
    assert!(observation.records()[0].completed_at().is_none());
    assert!(observation.acquired_at().is_none());
    assert!(observation.profile().is_none());
    assert!(!owner.management_fault.load(Ordering::SeqCst));
}
