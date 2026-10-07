use super::rail_tests::{queue_case, rail_owner, selected_case};
use super::voltage_tests::voltage_owner;
use super::*;

fn queue_population(fake: &Fake, model: Model, passing: bool) {
    // Actual original raw PIC replies, not a substituted boolean decoder.
    // Both fixtures are measured against this owner's accepted2000cV request.
    queue_case(
        fake,
        &selected_case(model, &[0], if passing { 800 } else { 759 }, None),
    );
}

#[tokio::test]
async fn complete_original_20_verifier_transitions_retain_up_to60_actual_populations() {
    let original: serde_json::Value =
        serde_json::from_str(include_str!("stock_bm1396_verifier_vectors.json")).unwrap();
    for case in original["cases"].as_array().unwrap() {
        let model = if case["model"] == "s17e" {
            Model::S17e
        } else {
            Model::T17e
        };
        let (fake, owner, app) = rail_owner(model, vec![0]).await;
        for event in case["events"].as_array().unwrap() {
            if event[0] == "check" {
                queue_population(&fake, model, event[1] == 0);
            }
        }
        let result = app.verify_commanded_rail_voltages(deadline()).await;
        let passed = case["returned"] == 0;
        assert_eq!(result.is_ok(), passed, "{case:?}");
        assert_eq!(owner.is_terminal(), !passed);
        let observation = app.rail_verifications().unwrap().remove(0);
        assert_eq!(observation.passed(), Some(passed));
        assert!(observation.completed_at().is_some());
        assert_eq!(
            observation.commanded_voltage(),
            app.last_commanded_voltage().unwrap().unwrap()
        );
        assert_eq!(
            observation.checks().len() as u64,
            case["check_count"].as_u64().unwrap()
        );
        assert_eq!(
            observation.waits().len() as u64,
            case["sleep_count"].as_u64().unwrap()
        );
        assert!(app.rail_snapshots().unwrap().is_empty());
        let actual: Vec<serde_json::Value> = observation
            .events()
            .iter()
            .map(|event| match event {
                RailVerificationEvent::Check(index) => {
                    let check = &observation.checks()[usize::from(*index)];
                    assert!(check.snapshot().completed_at().is_some());
                    assert_eq!(
                        check.snapshot().commanded_voltage(),
                        observation.commanded_voltage()
                    );
                    assert_eq!(check.snapshot().samples().len(), 1);
                    serde_json::json!([
                        "check",
                        if check.snapshot().all_within_target() == Some(true) {
                            0u32
                        } else {
                            u32::MAX
                        }
                    ])
                }
                RailVerificationEvent::Wait(index) => {
                    assert!(observation.waits()[usize::from(*index)]
                        .completed_at()
                        .is_some());
                    serde_json::json!(["sleep", 1])
                }
            })
            .collect();
        assert_eq!(serde_json::json!(actual), case["events"]);
        let physical_waits = fake
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| matches!(event, Event::Sleep(1_000_000)))
            .count();
        assert_eq!(physical_waits, observation.waits().len());
        assert!(fake.replies.lock().unwrap().is_empty());
        // Transferring a complete failed loop preserves its truth and bytes.
        app.acknowledge_rail_verification(&observation).unwrap();
    }
}

#[tokio::test]
async fn verifier_partial_second_population_keeps_first_check_and_actual_unresolved_bytes() {
    let (fake, owner, app) = rail_owner(Model::T17e, vec![0]).await;
    queue_population(&fake, Model::T17e, true);
    fake.reply(&[11, 0x37, 0]);
    assert!(app
        .verify_commanded_rail_voltages(deadline())
        .await
        .is_err());
    let observation = app.rail_verifications().unwrap().remove(0);
    assert_eq!(observation.checks().len(), 1);
    assert_eq!(observation.waits().len(), 1);
    assert!(observation.waits()[0].completed_at().is_some());
    assert_eq!(observation.passed(), None);
    assert!(observation.completed_at().is_none());
    let partial = app.rail_snapshots().unwrap().remove(0);
    assert_eq!(partial.frames()[0].completed_request_bytes(), 6);
    assert_eq!(partial.frames()[0].response(), &[11, 0x37, 0]);
    assert!(partial.completed_at().is_none());
    assert!(!partial.frames()[0].framing_complete());
    assert!(owner.management_fault.load(Ordering::SeqCst));
    assert!(owner.is_terminal());
    assert!(app.acknowledge_rail_verification(&observation).is_err());
    assert!(app.acknowledge_rail_snapshot(&partial).is_err());
    let count = fake.writes().len();
    assert!(app
        .verify_commanded_rail_voltages(deadline())
        .await
        .is_err());
    assert_eq!(fake.writes().len(), count);
}

#[tokio::test]
async fn verifier_bad_complete_header_never_becomes_a_tolerance_retry() {
    let (fake, owner, app) = rail_owner(Model::T17e, vec![0]).await;
    queue_case(
        &fake,
        &selected_case(Model::T17e, &[0, 7], 800, Some("header")),
    );
    assert!(app
        .verify_commanded_rail_voltages(deadline())
        .await
        .is_err());
    let observation = app.rail_verifications().unwrap().remove(0);
    assert!(observation.checks().is_empty());
    assert!(observation.waits().is_empty());
    assert_eq!(observation.passed(), None);
    let partial = app.rail_snapshots().unwrap().remove(0);
    assert_eq!(partial.frames().len(), 1);
    assert!(partial.frames()[0].framing_complete());
    assert_eq!(partial.frames()[0].response().len(), 11);
    assert_eq!(fake.writes().len(), 17);
    assert!(owner.is_terminal());
    assert!(!owner.management_fault.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn verifier_wait_admits_heartbeat_while_external_voltage_stays_serialized() {
    let (fake, owner, app) = rail_owner(Model::T17e, vec![0]).await;
    let block = ReadBlock::new(0);
    *fake.sleep_block.lock().unwrap() = Some((Duration::from_secs(1), block.clone()));
    queue_population(&fake, Model::T17e, true);
    let verify = {
        let app = app.clone();
        tokio::spawn(async move { app.verify_commanded_rail_voltages(deadline()).await })
    };
    while !block.entered.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    fake.reply(&[6, 0x16, 1, 0, 0, 0]);
    app.heartbeat_round(deadline()).await.unwrap();
    let count = fake.writes().len();
    let mut writer = {
        let app = app.clone();
        tokio::spawn(async move { app.command_voltage_cv(1900, deadline()).await })
    };
    assert!(tokio::time::timeout(Duration::from_millis(10), &mut writer)
        .await
        .is_err());
    assert_eq!(fake.writes().len(), count);
    assert_eq!(
        app.last_commanded_voltage()
            .unwrap()
            .unwrap()
            .requested_centivolts(),
        2000
    );
    queue_population(&fake, Model::T17e, true);
    fake.reply(&[0x55, 0xaa, 6, 0x83, 12, 0, 0x95, 0]);
    block.release();
    let observation = verify.await.unwrap().unwrap();
    assert_eq!(observation.passed(), Some(true));
    assert_eq!(observation.commanded_voltage().requested_centivolts(), 2000);
    assert_eq!(writer.await.unwrap().unwrap().requested_centivolts(), 1900);
    assert!(!owner.is_terminal());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_verification_wait_keeps_actual_worker_and_transferred_population_until_drain() {
    let (fake, owner, app) = rail_owner(Model::T17e, vec![0]).await;
    let block = ReadBlock::new(0);
    *fake.sleep_block.lock().unwrap() = Some((Duration::from_secs(1), block.clone()));
    queue_population(&fake, Model::T17e, true);
    let verify = {
        let app = app.clone();
        tokio::spawn(async move { app.verify_commanded_rail_voltages(deadline()).await })
    };
    while !block.entered.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    verify.abort();
    assert!(verify.await.unwrap_err().is_cancelled());
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(5))
        .await
        .is_err());
    let observation = app.rail_verifications().unwrap().remove(0);
    assert_eq!(observation.checks().len(), 1);
    assert_eq!(observation.waits().len(), 1);
    assert!(observation.waits()[0].completed_at().is_none());
    assert!(observation.completed_at().is_none());
    assert!(app.rail_snapshots().unwrap().is_empty());
    block.release();
    owner.drain(deadline()).await.unwrap();
    assert_eq!(fake.writes().len(), 17);
    assert!(app.rail_verifications().unwrap()[0].waits()[0]
        .completed_at()
        .is_none());
}

#[tokio::test]
async fn verification_capacity_exact_owner_ack_and_missing_prior_custody_refuse_before_new_wire() {
    let (fake, _owner, app) = rail_owner(Model::T17e, vec![0]).await;
    let (_foreign, _other, other) = rail_owner(Model::T17e, vec![0]).await;
    for _ in 0..16 {
        queue_population(&fake, Model::T17e, true);
        queue_population(&fake, Model::T17e, true);
        app.verify_commanded_rail_voltages(deadline())
            .await
            .unwrap();
    }
    let observations = app.rail_verifications().unwrap();
    assert!(app.acknowledge_rail_verification(&observations[1]).is_err());
    assert!(other
        .acknowledge_rail_verification(&observations[0])
        .is_err());
    app.acknowledge_rail_verification(&observations[0]).unwrap();
    assert!(app.acknowledge_rail_verification(&observations[0]).is_err());
    queue_population(&fake, Model::T17e, true);
    queue_population(&fake, Model::T17e, true);
    app.verify_commanded_rail_voltages(deadline())
        .await
        .unwrap();
    let count = fake.writes().len();
    assert!(app
        .verify_commanded_rail_voltages(deadline())
        .await
        .is_err());
    assert_eq!(fake.writes().len(), count);
    assert_eq!(app.rail_verifications().unwrap().len(), 16);
    let (fake, _owner, app) = voltage_owner(Model::T17e, None).await;
    assert!(app
        .verify_commanded_rail_voltages(deadline())
        .await
        .is_err());
    assert!(fake.writes().is_empty());
    assert!(app.rail_verifications().unwrap().is_empty());
    let (fake, _owner, app) = rail_owner(Model::T17e, vec![0]).await;
    queue_population(&fake, Model::T17e, true);
    let prior = app
        .acquire_commanded_rail_voltages(deadline())
        .await
        .unwrap();
    let count = fake.writes().len();
    assert!(app
        .verify_commanded_rail_voltages(deadline())
        .await
        .is_err());
    assert_eq!(fake.writes().len(), count);
    assert_eq!(app.rail_snapshots().unwrap(), [prior]);
    assert!(app.rail_verifications().unwrap().is_empty());
}

#[tokio::test]
async fn verifier_short_source_wait_budget_keeps_attempt_without_false_completion() {
    let (fake, owner, app) = rail_owner(Model::T17e, vec![0]).await;
    queue_population(&fake, Model::T17e, true);
    assert!(app
        .verify_commanded_rail_voltages(Instant::now() + Duration::from_millis(600))
        .await
        .is_err());
    let observation = app.rail_verifications().unwrap().remove(0);
    assert_eq!(observation.checks().len(), 1);
    assert_eq!(observation.waits().len(), 1);
    assert!(observation.waits()[0].completed_at().is_none());
    assert_eq!(observation.passed(), None);
    assert_eq!(fake.writes().len(), 17);
    assert!(owner.is_terminal());
}
