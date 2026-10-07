use super::*;

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("stock_bm1396_rail_vectors.json")).unwrap()
}
fn bytes(value: &serde_json::Value) -> Vec<u8> {
    let hex = value.as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}
fn key(model: Model) -> &'static str {
    if model == Model::S17e {
        "s17e"
    } else {
        "t17e"
    }
}
pub(super) fn selected_case(
    model: Model,
    chains: &[u8],
    voltage: u64,
    defect: Option<&str>,
) -> serde_json::Value {
    let factor = if model == Model::S17e { 4 } else { 1 };
    fixtures()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            case["model"] == key(model)
                && case["chains"] == serde_json::json!(chains)
                && case["raw_voltage"] == voltage * factor
                && case["raw_reference"] == 760 * factor
                && case["defect"] == serde_json::json!(defect)
        })
        .unwrap()
        .clone()
}
pub(super) fn queue_case(fake: &Fake, case: &serde_json::Value) {
    for request in case["requests"].as_array().unwrap() {
        fake.reply(&bytes(&request["response_hex"]));
    }
}

pub(super) async fn rail_owner(
    model: Model,
    chains: Vec<u8>,
) -> (Arc<Fake>, Arc<Transport<Fake>>, Arc<PicApplication<Fake>>) {
    let fake = Fake::new(
        model,
        chains.iter().fold(0, |mask, &chain| mask | 1 << chain),
    );
    let owner = Transport::observe(fake.clone(), model, chains.clone())
        .await
        .unwrap();
    let app = PicApplication::claim(owner.clone()).unwrap();
    for _ in &chains {
        fake.reply(&[5, 0x17, 0x89, 0, 0]);
    }
    app.observe_versions(deadline()).await.unwrap();
    for _ in 0..5 {
        for _ in &chains {
            fake.reply(&[6, 0x16, 1, 0, 0, 0]);
        }
        app.heartbeat_round(deadline()).await.unwrap();
    }
    fake.reply(&[0x55, 0xaa, 6, 0x83, 12, 0, 0x95, 0]);
    app.command_voltage_cv(2000, deadline()).await.unwrap();
    fake.events.lock().unwrap().clear();
    (fake, owner, app)
}

#[test]
fn original_complete_pic_rail_vectors_match_exact_model_decoder_and_failures() {
    for case in fixtures()["cases"].as_array().unwrap() {
        let model = if case["model"] == "s17e" {
            Model::S17e
        } else {
            Model::T17e
        };
        let requests = case["requests"].as_array().unwrap();
        if requests.is_empty() {
            continue;
        }
        let voltage = bytes(&requests[0]["response_hex"]);
        let reference =
            if model == Model::S17e && requests.get(1).is_some_and(|r| r["opcode"] == 0x28) {
                Some(bytes(&requests[1]["response_hex"]))
            } else {
                None
            };
        let result = management::rail::decode(model, &voltage, reference.as_deref());
        // Integer goldens preserve the original D0 result without decimal
        // parsing rounding in serde_json builds without float_roundtrip.
        let original = case["measured_voltage_bits"][0][1].as_u64().unwrap();
        if original == 0 {
            assert!(result.is_err(), "{case:?}");
        } else {
            let (v, r, actual) = result.unwrap();
            assert_eq!(u64::from(v), case["raw_voltage"].as_u64().unwrap());
            assert_eq!(u64::from(r), case["raw_reference"].as_u64().unwrap());
            assert_eq!(actual.to_bits(), original, "{case:?}");
        }
    }
}

#[tokio::test]
async fn rail_acquisition_matches_original_full_wire_population_and_target_predicate() {
    for model in [Model::S17e, Model::T17e] {
        for chains in [vec![0], vec![7], vec![0, 2, 7]] {
            for voltage in [759, 800, 841] {
                let (fake, _owner, app) = rail_owner(model, chains.clone()).await;
                let case = selected_case(model, &chains, voltage, None);
                queue_case(&fake, &case);
                let snapshot = app
                    .acquire_commanded_rail_voltages(deadline())
                    .await
                    .unwrap();
                assert_eq!(snapshot.all_within_target(), Some(case["returned"] == 0));
                assert!(snapshot.completed_at().is_some());
                assert_eq!(snapshot.commanded_voltage().requested_centivolts(), 2000);
                assert_eq!(snapshot.samples().len(), chains.len());
                for (sample, original) in snapshot
                    .samples()
                    .iter()
                    .zip(case["measured_voltage_bits"].as_array().unwrap())
                {
                    assert_eq!(u64::from(sample.chain()), original[0].as_u64().unwrap());
                    assert_eq!(sample.voltage_v().to_bits(), original[1].as_u64().unwrap());
                    assert!(sample.received_at() <= snapshot.completed_at().unwrap());
                }
                assert!(snapshot
                    .frames()
                    .iter()
                    .all(|frame| frame.framing_complete()
                        && frame.completed_request_bytes() == 6
                        && frame.completed_at().is_some()));
                assert_eq!(
                    fake.writes(),
                    case["writes_30"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|word| (0x30, word.as_u64().unwrap() as u32))
                        .collect::<Vec<_>>()
                );
                assert_eq!(app.rail_snapshots().unwrap(), vec![snapshot]);
            }
        }
    }
}

#[tokio::test]
async fn rail_bad_frames_reference_and_unresolved_portal_preserve_actual_progress() {
    for model in [Model::S17e, Model::T17e] {
        for defect in [0, 1, 2, 3] {
            let (fake, owner, app) = rail_owner(model, vec![0]).await;
            let case = selected_case(model, &[0], 800, None);
            match defect {
                0 => {
                    fake.fail_write.store(0x30, Ordering::SeqCst);
                }
                1 => {
                    fake.management_timeout.store(true, Ordering::SeqCst);
                }
                2 => {
                    let mut response = bytes(&case["requests"][0]["response_hex"]);
                    response[0] ^= 1;
                    fake.reply(&response);
                }
                _ => {
                    for request in case["requests"].as_array().unwrap() {
                        let mut response = bytes(&request["response_hex"]);
                        let reference_index = if model == Model::T17e { 7 } else { 9 };
                        if model == Model::T17e || request["opcode"] == 0x28 {
                            response[reference_index] = 0;
                            response[reference_index + 1] = 0;
                        }
                        fake.reply(&response);
                    }
                }
            }
            assert!(app
                .acquire_commanded_rail_voltages(deadline())
                .await
                .is_err());
            assert!(owner.is_terminal());
            let snapshots = app.rail_snapshots().unwrap();
            assert_eq!(snapshots.len(), 1);
            let snapshot = &snapshots[0];
            assert!(snapshot.completed_at().is_none());
            assert!(app.acknowledge_rail_snapshot(snapshot).is_err());
            let frame = &snapshot.frames()[0];
            if defect < 2 {
                assert_eq!(frame.completed_request_bytes(), 0);
                assert!(frame.response().is_empty());
                assert!(!frame.framing_complete());
            } else {
                assert_eq!(frame.completed_request_bytes(), 6);
                assert!(frame.framing_complete());
                assert!(!frame.response().is_empty());
            }
            assert_eq!(owner.management_fault.load(Ordering::SeqCst), defect < 2);
            let count = fake.writes().len();
            assert!(app
                .acquire_commanded_rail_voltages(deadline())
                .await
                .is_err());
            assert_eq!(fake.writes().len(), count);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_rail_first_byte_keeps_real_worker_and_voltage_sequence_custody() {
    let (fake, owner, app) = rail_owner(Model::T17e, vec![0]).await;
    let block = ReadBlock::new(0x30);
    *fake.block.lock().unwrap() = Some(block.clone());
    let task = {
        let app = app.clone();
        tokio::spawn(async move { app.acquire_commanded_rail_voltages(deadline()).await })
    };
    while !block.entered.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(5))
        .await
        .is_err());
    block.release();
    owner.drain(deadline()).await.unwrap();
    let snapshot = app.rail_snapshots().unwrap().remove(0);
    assert_eq!(snapshot.frames()[0].completed_request_bytes(), 1);
    assert!(snapshot.frames()[0].response().is_empty());
    assert!(snapshot.completed_at().is_none());
    assert_eq!(fake.writes().len(), 1);
}

#[tokio::test]
async fn rail_snapshot_capacity_order_and_issuer_are_retained() {
    let (fake, _owner, app) = rail_owner(Model::T17e, vec![0]).await;
    let (_foreign, _other, other) = rail_owner(Model::T17e, vec![0]).await;
    let case = selected_case(Model::T17e, &[0], 800, None);
    for _ in 0..16 {
        queue_case(&fake, &case);
        app.acquire_commanded_rail_voltages(deadline())
            .await
            .unwrap();
    }
    let snapshots = app.rail_snapshots().unwrap();
    assert!(app.acknowledge_rail_snapshot(&snapshots[1]).is_err());
    assert!(other.acknowledge_rail_snapshot(&snapshots[0]).is_err());
    app.acknowledge_rail_snapshot(&snapshots[0]).unwrap();
    assert!(app.acknowledge_rail_snapshot(&snapshots[0]).is_err());
    queue_case(&fake, &case);
    app.acquire_commanded_rail_voltages(deadline())
        .await
        .unwrap();
    let count = fake.writes().len();
    assert!(app
        .acquire_commanded_rail_voltages(deadline())
        .await
        .is_err());
    assert_eq!(fake.writes().len(), count);
    assert_eq!(app.rail_snapshots().unwrap().len(), 16);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rail_late_final_byte_preserves_full_frame_without_false_completion() {
    let (fake, owner, app) = rail_owner(Model::T17e, vec![0]).await;
    queue_case(&fake, &selected_case(Model::T17e, &[0], 800, None));
    fake.late_final_reply.store(true, Ordering::SeqCst);
    assert!(app
        .acquire_commanded_rail_voltages(Instant::now() + Duration::from_millis(600))
        .await
        .is_err());
    let snapshot = app.rail_snapshots().unwrap().remove(0);
    let frame = &snapshot.frames()[0];
    assert_eq!(frame.response().len(), 11);
    assert!(frame.framing_complete());
    assert!(frame.received_at().is_some());
    assert!(frame.completed_at().is_none());
    assert!(snapshot.completed_at().is_none());
    assert!(owner.is_terminal());
    assert!(!owner.management_fault.load(Ordering::SeqCst));
}

#[tokio::test]
async fn rail_requires_retained_voltage_health_and_unchanged_selected_presence() {
    let (fake, owner) = owner(Model::T17e).await;
    let app = PicApplication::claim(owner).unwrap();
    assert!(app
        .acquire_commanded_rail_voltages(deadline())
        .await
        .is_err());
    assert!(fake.writes().is_empty());
    assert!(app.rail_snapshots().unwrap().is_empty());
    let (fake, _owner, app) = rail_owner(Model::T17e, vec![0]).await;
    fake.regs.lock().unwrap().insert(8, 3);
    assert!(app
        .acquire_commanded_rail_voltages(deadline())
        .await
        .is_err());
    assert!(fake.writes().is_empty());
    assert!(app.rail_snapshots().unwrap().is_empty());
}
