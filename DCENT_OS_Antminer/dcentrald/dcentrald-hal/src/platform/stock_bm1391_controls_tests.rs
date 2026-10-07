use super::*;
use std::collections::BTreeMap;

#[derive(Default)]
struct Recording {
    words: Mutex<BTreeMap<u32, u32>>,
    events: Mutex<Vec<serde_json::Value>>,
    fail_at: Mutex<Option<usize>>,
}
impl Registers for Recording {
    fn read(&self, offset: u32) -> Result<u32, String> {
        Ok(match offset {
            VERSION => 0xc501,
            PRESENCE => 7,
            COMMAND_CONTROL => *self.words.lock().unwrap().get(&offset).unwrap_or(&0) & 0x7fff_ffff,
            _ => *self.words.lock().unwrap().get(&offset).unwrap_or(&0),
        })
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        let mut events = self.events.lock().unwrap();
        if *self.fail_at.lock().unwrap() == Some(events.len()) {
            return Err("injected control write failure".into());
        }
        events.push(serde_json::json!({"offset": offset, "value": value}));
        self.words.lock().unwrap().insert(offset, value);
        Ok(())
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn observed(chain: u8, value: u32) -> Bm1391StockRegisterReturn {
    let mut packet = [0; 7];
    packet[..4].copy_from_slice(&value.to_be_bytes());
    packet[5] = 0x18;
    Bm1391StockRegisterReturn {
        chain_slot: chain,
        chip_address: 0,
        register: 0x18,
        value,
        crc5: dcentrald_common::s9se_vil::crc5_bits(&packet, 51),
        register_type: 0,
        fpga_crc_error: false,
    }
}

#[test]
fn all_original_reset_timeout_and_baud_traces_match_actual_native_stores() {
    let source: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../"
    ))).unwrap();
    let mut checked = 0;
    for release in source["releases"].as_array().unwrap() {
        for vector in release["vectors"].as_array().unwrap() {
            let registers = Arc::new(Recording::default());
            let chain = vector["chain"].as_u64().unwrap() as u8;
            let argument = vector["argument"].as_u64().unwrap() as u32;
            let prior = vector["prior"].as_u64().unwrap() as u32;
            registers
                .words
                .lock()
                .unwrap()
                .extend([(RESET, prior), (COMMAND_CONTROL, 0x0020501a)]);
            let owner = Transport::new(registers.clone(), vec![chain]).unwrap();
            match vector["stage"].as_str().unwrap() {
                "reset" => owner
                    .set_chain_reset_level(chain, argument != 0, deadline())
                    .unwrap(),
                "timeout" => owner
                    .set_work_timeout_ticks(argument & 0x1ffff, deadline())
                    .unwrap(),
                "baud" => owner
                    .set_baud_with_delay(
                        observed(chain, prior),
                        if argument == 0 {
                            StartupBaud::Operational
                        } else {
                            StartupBaud::Cold
                        },
                        deadline(),
                        || {
                            registers
                                .events
                                .lock()
                                .unwrap()
                                .push(serde_json::json!({"delay_us":50000}));
                            Ok(())
                        },
                    )
                    .unwrap(),
                other => panic!("unexpected oracle stage {other}"),
            }
            assert_eq!(
                *registers.events.lock().unwrap(),
                *vector["events"].as_array().unwrap(),
                "{vector}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 54);
}

#[test]
fn partial_baud_or_settle_failure_never_advances_controller_rate() {
    for fail_at in 0..5 {
        let registers = Arc::new(Recording::default());
        *registers.fail_at.lock().unwrap() = Some(fail_at);
        let owner = Transport::new(registers.clone(), vec![0]).unwrap();
        assert!(owner
            .set_baud_with_delay(
                observed(0, 0x3a01),
                StartupBaud::Operational,
                deadline(),
                || Ok(())
            )
            .is_err());
        assert!(owner.terminal());
        assert_eq!(registers.events.lock().unwrap().len(), fail_at);
        assert!(owner.set_chain_reset_level(0, true, deadline()).is_err());
        assert_eq!(registers.events.lock().unwrap().len(), fail_at);
    }
    let registers = Arc::new(Recording::default());
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    assert!(owner
        .set_baud_with_delay(
            observed(0, 0x7a31),
            StartupBaud::Operational,
            deadline(),
            || Err("settle cancelled".into())
        )
        .is_err());
    assert!(owner.terminal());
    assert_eq!(registers.events.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn public_baud_honors_deadline_and_rejects_unchecked_identity_before_io() {
    let registers = Arc::new(Recording::default());
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    let mut bad = observed(0, 0x3a01);
    bad.crc5 ^= 1;
    assert!(owner
        .set_asic_and_fpga_baud(bad, StartupBaud::Cold, deadline())
        .await
        .is_err());
    assert!(registers.events.lock().unwrap().is_empty());
    assert!(!owner.terminal());
    assert!(owner.set_work_timeout_ticks(0, deadline()).is_err());
    assert!(owner.set_work_timeout_ticks(0x20000, deadline()).is_err());
    assert!(owner.set_chain_reset_level(2, true, deadline()).is_err());
    assert!(registers.events.lock().unwrap().is_empty());
    assert!(owner
        .set_asic_and_fpga_baud(
            observed(0, 0x3a01),
            StartupBaud::Cold,
            Instant::now() + Duration::from_millis(10)
        )
        .await
        .is_err());
    assert!(owner.terminal());
    assert_eq!(registers.events.lock().unwrap().len(), 4);
}
