use super::super::tests::{deadline, sample_work, RecordingRegisters};
use super::*;

fn reply(chain: u8, address: u8, register: u8, value: u32) -> (u32, u32) {
    let mut packet = [0; 7];
    packet[..4].copy_from_slice(&value.to_be_bytes());
    packet[4] = address;
    packet[5] = register;
    let crc = dcentrald_common::s9se_vil::crc5_bits(&packet, 51);
    (
        (u32::from(crc) << 24)
            | (u32::from(address) << 16)
            | (u32::from(register) << 8)
            | u32::from(chain),
        value,
    )
}

#[test]
fn response_validation_matches_180_original_census_assembler_and_crc_executions() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut count = 0;
    for release in oracle["releases"].as_array().unwrap() {
        for vector in release["vectors"].as_array().unwrap() {
            let mut observed = Bm1391StockRegisterReturn {
                chain_slot: 0,
                register: vector["register"].as_u64().unwrap() as u8,
                chip_address: vector["chip_address"].as_u64().unwrap() as u8,
                crc5: vector["crc5"].as_u64().unwrap() as u8,
                register_type: 0,
                value: vector["value"].as_u64().unwrap() as u32,
                fpga_crc_error: false,
            };
            assert!(response_crc_valid(observed));
            for kind in 0..4 {
                observed.register_type = kind;
                assert!(response_crc_valid(observed));
            }
            observed.crc5 ^= 1;
            assert!(!response_crc_valid(observed));
            observed.crc5 ^= 1;
            observed.fpga_crc_error = true;
            assert!(!response_crc_valid(observed));
            count += 1;
        }
    }
    assert_eq!(count, 180);
}

#[test]
fn actual_census_drains_stale_fifo_then_observes_s15_t15_populations() {
    let requests: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    for (release, model) in [Model::S15, Model::T15].into_iter().enumerate() {
        for chain in 0..3 {
            let registers = Arc::new(RecordingRegisters::default());
            // A stale valid ID must be drained before the new request.
            registers
                .state
                .lock()
                .unwrap()
                .returns
                .push_back(reply(chain, 252, 0, 0x1391_0000));
            let owner = Transport::new(registers.clone(), vec![chain]).unwrap();
            let mut delays = Vec::new();
            let result = owner
                .census_with_delay(model, chain, deadline(), |ms| {
                    delays.push(ms);
                    assert!(owner.lane.try_lock().is_err());
                    if delays.len() == 1 {
                        let mut state = registers.state.lock().unwrap();
                        assert!(state.returns.is_empty());
                        assert_eq!(state.writes.len(), 4);
                        for index in (0..model.expected_chips()).rev() {
                            let address = index * model.address_interval();
                            state.returns.push_back(reply(
                                chain,
                                address,
                                0,
                                0x1391_0000 | u32::from(address),
                            ));
                        }
                        // Retransmission does not manufacture an additional chip.
                        state.returns.push_back(reply(chain, 0, 0, 0x1391_0000));
                    }
                    Ok(())
                })
                .unwrap();
            assert_eq!(result.chain, chain);
            assert_eq!(result.replies.len(), model.expected_chips() as usize);
            assert_eq!(
                result
                    .replies
                    .iter()
                    .map(|r| r.chip_address)
                    .collect::<Vec<_>>(),
                (0..model.expected_chips())
                    .map(|i| i * model.address_interval())
                    .collect::<Vec<_>>()
            );
            assert_eq!(delays, vec![300, 300, 100, 300, 100, 300, 100]);
            let original = requests["releases"][release]["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| {
                    v["chain"] == chain
                        && v["address"] == 0
                        && v["register"] == 0
                        && v["broadcast"] == true
                })
                .unwrap();
            let expected: Vec<_> = original["writes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    (
                        v["offset"].as_u64().unwrap() as u32,
                        v["value"].as_u64().unwrap() as u32,
                    )
                })
                .collect();
            assert_eq!(registers.state.lock().unwrap().writes, expected);
            assert!(!owner.terminal());
        }
    }
}

#[test]
fn stale_only_or_wrong_identity_address_crc_register_or_nonce_never_forms_census() {
    let good = reply(0, 0, 0, 0x1391_0000);
    for injected in [
        None,
        Some(reply(0, 0, 0, 0x1393_0000)),
        Some(reply(0, 1, 0, 0x1391_0000)),
        Some(reply(0, 255, 0, 0x1391_0000)),
        Some(reply(0, 0, 8, 0x1391_0000)),
        Some((good.0 ^ (1 << 24), good.1)),
        Some((good.0 | 0x40, good.1)),
        Some((0x8000_0080, 123)),
        Some(reply(1, 0, 0, 0x1391_0000)),
    ] {
        let registers = Arc::new(RecordingRegisters::default());
        registers.state.lock().unwrap().returns.push_back(good);
        let owner = Transport::new(registers.clone(), vec![0, 1]).unwrap();
        let mut injected_once = false;
        assert!(owner
            .census_with_delay(Model::S15, 0, deadline(), |_| {
                if !injected_once {
                    if let Some(record) = injected {
                        registers.state.lock().unwrap().returns.push_back(record);
                    }
                    injected_once = true;
                }
                Ok(())
            })
            .is_err());
        assert!(owner.terminal());
        assert!(owner.publish_work(&sample_work(0), deadline()).is_err());
        assert_eq!(registers.state.lock().unwrap().writes.len(), 4);
    }
}

#[test]
fn conflicting_duplicate_or_failed_settle_stops_the_census() {
    for failure in 0..3 {
        let registers = Arc::new(RecordingRegisters::default());
        let owner = Transport::new(registers.clone(), vec![0]).unwrap();
        assert!(owner
            .census_with_delay(Model::S15, 0, deadline(), |_| {
                match failure {
                    0 => {
                        let mut state = registers.state.lock().unwrap();
                        state.returns.push_back(reply(0, 0, 0, 0x1391_0000));
                        state.returns.push_back(reply(0, 0, 0, 0x1391_0100));
                    }
                    1 => return Err("settling failed".into()),
                    _ => owner.latch_terminal(),
                }
                Ok(())
            })
            .is_err());
        assert!(owner.terminal());
        owner.terminal_drain(deadline()).unwrap();
        assert_eq!(registers.state.lock().unwrap().writes.len(), 4);
    }
}

#[tokio::test]
async fn actual_async_census_obeys_deadline_before_or_during_first_settle() {
    let registers = Arc::new(RecordingRegisters::default());
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    let start = Instant::now();
    let error = owner
        .census(Model::S15, 0, start + Duration::from_millis(20))
        .await
        .unwrap_err();
    assert_eq!(error, "BM1391 transaction is terminal or expired");
    assert!(start.elapsed() < Duration::from_millis(200));
    assert!(owner.terminal());
    // The blocking worker may start after the deadline under host load. An
    // earlier refusal is valid; at most the first register request may escape.
    assert!(registers.state.lock().unwrap().writes.len() <= 4);
    assert!(owner.publish_work(&sample_work(0), deadline()).is_err());
}
