use super::*;

#[tokio::test]
async fn actual_supply_type_frames_match_complete_original_cases_without_source_retries() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("stock_bm1396_supply_vectors.json")).unwrap();
    for case in vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["initializer"] == false)
    {
        let (fake, owner) = owner(Model::T17e).await;
        let app = PicApplication::claim(owner.clone()).unwrap();
        let response = case["response"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        fake.reply(&response);
        let result = app.observe_supply_type(deadline()).await;
        let accepted = case["kind"] == 0x42 && case["defect"].is_null();
        assert_eq!(result.is_ok(), accepted, "{case}");
        let saved = app.supply_type_observation().unwrap().unwrap();
        assert_eq!(saved.response(), response);
        assert!(saved.framing_complete());
        assert_eq!(saved.completed_request_bytes(), 6);
        assert_eq!(saved.admitted_type(), accepted.then_some(0x42));
        let writes = fake.writes();
        assert_eq!(
            writes.iter().filter(|(offset, _)| *offset == 0x30).count(),
            14
        );
        assert_eq!(
            &writes[..6],
            &[0x55, 0xaa, 4, 2, 6, 0].map(|byte| (0x30, 0x05201100 | byte))
        );
        assert!(app.observe_supply_type(deadline()).await.is_err());
        assert_eq!(fake.writes(), writes);
    }
}

#[tokio::test]
async fn supply_type_partial_or_late_final_byte_retains_exact_wire_custody_and_no_admission() {
    for late in [false, true] {
        let (fake, owner) = owner(Model::T17e).await;
        let app = PicApplication::claim(owner.clone()).unwrap();
        let response = [0x55, 0xaa, 6, 2, 0x42, 0, 0x4a, 0];
        fake.reply(if late { &response } else { &response[..7] });
        fake.late_final_reply.store(late, Ordering::SeqCst);
        let until = if late {
            Instant::now() + Duration::from_millis(600)
        } else {
            deadline()
        };
        assert!(app.observe_supply_type(until).await.is_err());
        let saved = app.supply_type_observation().unwrap().unwrap();
        assert_eq!(
            saved.response(),
            if late { &response[..] } else { &response[..7] }
        );
        assert_eq!(saved.framing_complete(), late);
        assert_eq!(saved.admitted_type(), None);
        assert!(owner.is_terminal());
        assert!(app.last_commanded_voltage().unwrap().is_none());
    }
}

#[tokio::test]
async fn s17e_independent_source_profile_requires_its_actual_type42_frame() {
    for kind in [0x42u8, 0x43] {
        let (fake, owner) = owner(Model::S17e).await;
        let app = PicApplication::claim(owner.clone()).unwrap();
        fake.reply(&[0x55, 0xaa, 6, 2, kind, 0, 8 + kind, 0]);
        let observed = app.observe_supply_type(deadline()).await;
        assert_eq!(observed.is_ok(), kind == 0x42);
        let retained = app.supply_type_observation().unwrap().unwrap();
        assert_eq!(retained.request(), &[0x55, 0xaa, 4, 2, 6, 0]);
        assert_eq!(retained.completed_request_bytes(), 6);
        assert_eq!(
            retained.admitted_type(),
            if kind == 0x42 { Some(0x42) } else { None }
        );
        assert!(app.last_commanded_voltage().unwrap().is_none());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_supply_type_preserves_actual_pending_byte_until_worker_drains() {
    let (fake, owner) = owner(Model::T17e).await;
    let app = PicApplication::claim(owner.clone()).unwrap();
    let block = ReadBlock::new(0x30);
    *fake.block.lock().unwrap() = Some(block.clone());
    let task_app = app.clone();
    let task = tokio::spawn(async move { task_app.observe_supply_type(deadline()).await });
    while !block.entered.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    assert_eq!(
        app.supply_type_observation()
            .unwrap()
            .unwrap()
            .completed_request_bytes(),
        0
    );
    block.release();
    owner
        .drain(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let saved = app.supply_type_observation().unwrap().unwrap();
    assert_eq!(saved.completed_request_bytes(), 1);
    assert!(saved.response().is_empty());
    assert!(!saved.framing_complete() && saved.admitted_type().is_none());
    assert_eq!(
        fake.writes()
            .iter()
            .filter(|(offset, _)| *offset == 0x30)
            .count(),
        1
    );
}
