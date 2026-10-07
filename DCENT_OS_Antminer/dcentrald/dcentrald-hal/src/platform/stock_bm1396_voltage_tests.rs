use super::*;

fn response() -> [u8; 8] {
    [0x55, 0xaa, 6, 0x83, 12, 0, 0x95, 0]
}
pub(super) async fn voltage_owner(
    model: Model,
    current: Option<u16>,
) -> (Arc<Fake>, Arc<Transport<Fake>>, Arc<PicApplication<Fake>>) {
    let (fake, owner) = owner(model).await;
    let app = PicApplication::claim(owner.clone()).unwrap();
    fake.reply(&[5, 0x17, 0x89, 0, 0]);
    app.observe_versions(deadline()).await.unwrap();
    qualify(&fake, &app).await;
    if let Some(current) = current {
        fake.reply(&response());
        app.command_voltage_cv(current, deadline()).await.unwrap();
    }
    fake.events.lock().unwrap().clear();
    (fake, owner, app)
}

#[tokio::test]
async fn exact_original_98_voltage_ramps_preserve_codes_frames_and_completed_receipt() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("stock_bm1396_voltage_vectors.json")).unwrap();
    for case in fixtures["cases"].as_array().unwrap() {
        let model = if case["model"] == "s17e" {
            Model::S17e
        } else {
            Model::T17e
        };
        let current = case["current_voltage_cv"].as_u64().unwrap() as u16;
        let target = case["target_voltage_cv"].as_u64().unwrap() as u16;
        let (fake, _owner, app) = voltage_owner(model, Some(current)).await;
        let previous = app.last_commanded_voltage().unwrap().unwrap();
        for _ in case["dac_codes"].as_array().unwrap() {
            fake.reply(&response());
        }
        let result = app.command_voltage_ramp(target, deadline()).await.unwrap();
        let attempts = app.voltage_attempts().unwrap();
        assert_eq!(attempts.len(), 2);
        let attempt = &attempts[1];
        assert!(attempt.is_stepped());
        assert_eq!(attempt.prior_command(), Some(previous));
        assert_eq!(attempt.requested_centivolts(), target);
        assert_eq!(attempt.completed_at(), Some(result.completed_at()));
        let codes: Vec<_> = case["dac_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_u64().unwrap() as u8)
            .collect();
        assert_eq!(attempt.planned_dac_codes(), codes);
        assert_eq!(attempt.steps().len(), codes.len());
        let mut expected = Vec::new();
        for (step, frame) in attempt
            .steps()
            .iter()
            .zip(case["frames"].as_array().unwrap())
        {
            let hex = frame.as_str().unwrap();
            let bytes: Vec<_> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(step.request().as_slice(), bytes);
            assert_eq!(step.dac(), bytes[4]);
            assert_eq!(step.completed_request_bytes(), 8);
            assert_eq!(step.response(), response());
            assert!(step.framing_complete());
            assert!(step.completed_at().is_some());
            expected.extend(
                bytes
                    .iter()
                    .map(|&byte| (0x30, 0x05201100 | u32::from(byte))),
            );
            expected.extend([(0x30, 0x06200000); 8]);
        }
        assert_eq!(fake.writes(), expected);
        assert_eq!(result.requested_centivolts(), target);
        assert_eq!(result.dac(), *codes.last().unwrap());
        assert_eq!(app.last_commanded_voltage().unwrap(), Some(result));
    }
}

#[tokio::test]
async fn voltage_failed_second_step_keeps_prior_command_and_never_retries() {
    for model in [Model::S17e, Model::T17e] {
        for bad_checksum in [false, true] {
            let (fake, owner, app) = voltage_owner(model, Some(1800)).await;
            let prior = app.last_commanded_voltage().unwrap();
            fake.reply(&response());
            if bad_checksum {
                let mut bad = response();
                bad[6] ^= 1;
                fake.reply(&bad);
            }
            assert!(app.command_voltage_ramp(2100, deadline()).await.is_err());
            assert!(owner.is_terminal());
            assert_eq!(app.last_commanded_voltage().unwrap(), prior);
            let attempts = app.voltage_attempts().unwrap();
            let attempt = &attempts[1];
            assert!(attempt.completed_at().is_none());
            assert_eq!(attempt.steps().len(), 2);
            assert!(attempt.steps()[0].completed_at().is_some());
            let failed = &attempt.steps()[1];
            assert_eq!(failed.completed_request_bytes(), 8);
            assert_eq!(failed.framing_complete(), bad_checksum);
            assert!(failed.completed_at().is_none());
            assert_eq!(failed.response().len(), if bad_checksum { 8 } else { 0 });
            assert_eq!(owner.management_fault.load(Ordering::SeqCst), !bad_checksum);
            assert!(app.acknowledge_voltage_attempt(attempt).is_err());
            let count = fake.writes().len();
            assert!(app.command_voltage_ramp(2100, deadline()).await.is_err());
            assert_eq!(fake.writes().len(), count);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn voltage_late_final_reply_preserves_whole_step_without_replacing_prior_command() {
    let (fake, owner, app) = voltage_owner(Model::T17e, Some(2000)).await;
    let prior = app.last_commanded_voltage().unwrap();
    fake.reply(&response());
    fake.late_final_reply.store(true, Ordering::SeqCst);
    assert!(app
        .command_voltage_ramp(2000, Instant::now() + Duration::from_millis(600))
        .await
        .is_err());
    assert_eq!(app.last_commanded_voltage().unwrap(), prior);
    let attempts = app.voltage_attempts().unwrap();
    let attempt = &attempts[1];
    let step = &attempt.steps()[0];
    assert_eq!(step.response(), response());
    assert!(step.framing_complete());
    assert!(step.completed_at().is_none());
    assert!(attempt.completed_at().is_none());
    assert!(!owner.management_fault.load(Ordering::SeqCst));
    assert!(owner.is_terminal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_voltage_sequence_blocks_another_voltage_and_rail_worker_until_real_release() {
    let (fake, owner, app) = voltage_owner(Model::S17e, Some(1800)).await;
    let block = ReadBlock::new(0x30);
    *fake.block.lock().unwrap() = Some(block.clone());
    let first = {
        let app = app.clone();
        tokio::spawn(async move { app.command_voltage_ramp(2100, deadline()).await })
    };
    while !block.entered.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let second = {
        let app = app.clone();
        tokio::spawn(async move { app.command_voltage_cv(1900, deadline()).await })
    };
    let rail = {
        let app = app.clone();
        tokio::spawn(async move { app.acquire_commanded_rail_voltages(deadline()).await })
    };
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(fake.writes().len(), 1);
    assert!(app.rail_snapshots().unwrap().is_empty());
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(5))
        .await
        .is_err());
    block.release();
    owner.drain(deadline()).await.unwrap();
    assert!(second.await.unwrap().is_err());
    assert!(rail.await.unwrap().is_err());
    let attempts = app.voltage_attempts().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1].steps()[0].completed_request_bytes(), 1);
    assert_eq!(fake.writes().len(), 1);
}

#[tokio::test]
async fn voltage_retention_capacity_order_issuer_and_missing_prior_refuse_before_new_bytes() {
    let (fake, _owner, app) = voltage_owner(Model::T17e, None).await;
    assert!(app.command_voltage_ramp(2000, deadline()).await.is_err());
    assert!(fake.writes().is_empty());
    assert!(app.voltage_attempts().unwrap().is_empty());
    let (fake, _owner, app) = voltage_owner(Model::T17e, Some(2000)).await;
    let (_foreign, _other, other) = voltage_owner(Model::T17e, Some(2000)).await;
    let before = fake.writes();
    assert!(app.command_voltage_ramp(1799, deadline()).await.is_err());
    assert_eq!(fake.writes(), before);
    for _ in 0..15 {
        fake.reply(&response());
        app.command_voltage_ramp(2000, deadline()).await.unwrap();
    }
    let attempts = app.voltage_attempts().unwrap();
    assert_eq!(attempts.len(), 16);
    assert!(other.acknowledge_voltage_attempt(&attempts[0]).is_err());
    assert!(app.acknowledge_voltage_attempt(&attempts[1]).is_err());
    app.acknowledge_voltage_attempt(&attempts[0]).unwrap();
    assert!(app.acknowledge_voltage_attempt(&attempts[0]).is_err());
    fake.reply(&response());
    app.command_voltage_ramp(2000, deadline()).await.unwrap();
    let count = fake.writes().len();
    assert!(app.command_voltage_ramp(2000, deadline()).await.is_err());
    assert_eq!(fake.writes().len(), count);
    assert_eq!(app.voltage_attempts().unwrap().len(), 16);
}
