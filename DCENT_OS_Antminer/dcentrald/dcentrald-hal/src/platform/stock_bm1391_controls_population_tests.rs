use super::*;
use std::collections::BTreeMap;

#[derive(Default)]
struct State {
    words: BTreeMap<u32, u32>,
    events: Vec<serde_json::Value>,
    stores: usize,
    fail_at: Option<usize>,
}
#[derive(Default)]
struct Recording(Mutex<State>);
impl Registers for Recording {
    fn read(&self, offset: u32) -> Result<u32, String> {
        let state = self.0.lock().unwrap();
        Ok(match offset {
            VERSION => 0xc501,
            PRESENCE => 7,
            COMMAND_CONTROL => state.words.get(&offset).copied().unwrap_or(0) & 0x7fff_ffff,
            _ => state.words.get(&offset).copied().unwrap_or(0),
        })
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        if state.fail_at == Some(state.stores) {
            return Err("injected population baud write failure".into());
        }
        state.stores += 1;
        state
            .events
            .push(serde_json::json!({"offset": offset, "value": value}));
        state.words.insert(offset, value);
        Ok(())
    }
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
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn fixture() -> (
    Arc<Recording>,
    Arc<Transport<Recording>>,
    Vec<Bm1391StockRegisterReturn>,
) {
    let registers = Arc::new(Recording::default());
    registers
        .0
        .lock()
        .unwrap()
        .words
        .insert(COMMAND_CONTROL, 0x0020_501a);
    let owner = Transport::new(registers.clone(), vec![0, 1, 2]).unwrap();
    (
        registers,
        owner,
        (0..3).map(|chain| observed(chain, 0x3a01)).collect(),
    )
}

#[test]
fn complete_population_transitions_match_original_for_allselected_and_missingmiddle_chains() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../"
    ))).unwrap();
    let mut checked = 0;
    for release in oracle["releases"].as_array().unwrap() {
        for vector in release["vectors"].as_array().unwrap() {
            let code = vector["rate_code"].as_u64().unwrap();
            if code == 1 {
                continue; // Separately retained production caller evidence; raw runtime enum is0/1a.
            }
            let chains: Vec<u8> = vector["chains"]
                .as_array()
                .unwrap()
                .iter()
                .map(|chain| chain.as_u64().unwrap() as u8)
                .collect();
            let prior = vector["prior_misc"].as_u64().unwrap() as u32;
            let registers = Arc::new(Recording::default());
            registers
                .0
                .lock()
                .unwrap()
                .words
                .insert(COMMAND_CONTROL, 0x0020_501a);
            let owner = Transport::new(registers.clone(), chains.clone()).unwrap();
            let replies: Vec<_> = chains.iter().map(|chain| observed(*chain, prior)).collect();
            owner
                .set_population_baud_with_delay(
                    &replies,
                    if code == 0 {
                        StartupBaud::Operational
                    } else {
                        StartupBaud::Cold
                    },
                    deadline(),
                    || {
                        assert!(owner.lane.try_lock().is_err());
                        let mut state = registers.0.lock().unwrap();
                        assert_eq!(state.stores, chains.len() * 4);
                        assert_eq!(state.words[&COMMAND_CONTROL] & 0x3f, 0x1a);
                        state.events.push(serde_json::json!({"delay_us": 50000}));
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(
                registers.0.lock().unwrap().events,
                *vector["events"].as_array().unwrap()
            );
            assert!(!owner.terminal());
            checked += 1;
        }
    }
    assert_eq!(checked, 16);
}

#[test]
fn missing_duplicate_disordered_nonuniform_or_badcrc_population_never_broadcasts() {
    for case in 0..6 {
        let (registers, owner, mut replies) = fixture();
        match case {
            0 => {
                replies.pop();
            }
            1 => {
                replies[2] = replies[1];
            }
            2 => replies.swap(0, 1),
            3 => replies[1] = observed(1, 0x3a03),
            4 => replies[1].crc5 ^= 1,
            5 => replies.clear(),
            _ => unreachable!(),
        }
        assert!(owner
            .set_population_baud_with_delay(
                &replies,
                StartupBaud::Operational,
                deadline(),
                || panic!("invalid observations reached settle")
            )
            .is_err());
        assert_eq!(registers.0.lock().unwrap().stores, 0);
    }
}

#[test]
fn every_partial_population_write_and_failed_settle_prevents_global_switch_or_retry() {
    for failure in 0..13 {
        let (registers, owner, replies) = fixture();
        registers.0.lock().unwrap().fail_at = Some(failure);
        assert!(owner
            .set_population_baud_with_delay(&replies, StartupBaud::Operational, deadline(), || Ok(
                ()
            ))
            .is_err());
        assert!(owner.terminal());
        assert_eq!(registers.0.lock().unwrap().stores, failure);
        assert_eq!(
            registers.0.lock().unwrap().words[&COMMAND_CONTROL] & 0x3f,
            0x1a
        );
        assert!(owner
            .set_population_baud_with_delay(&replies, StartupBaud::Operational, deadline(), || Ok(
                ()
            ))
            .is_err());
        assert_eq!(registers.0.lock().unwrap().stores, failure);
    }
    let (registers, owner, replies) = fixture();
    assert!(owner
        .set_population_baud_with_delay(&replies, StartupBaud::Operational, deadline(), || Err(
            "injected population settle failure".into()
        ))
        .is_err());
    assert!(owner.terminal());
    assert_eq!(registers.0.lock().unwrap().stores, 12);
}

#[test]
fn mismatched_initial_hostrate_or_changed_hostrate_at_settle_latches_before_switch() {
    for initial_bad in [true, false] {
        let (registers, owner, replies) = fixture();
        if initial_bad {
            registers
                .0
                .lock()
                .unwrap()
                .words
                .insert(COMMAND_CONTROL, 0x3a);
        }
        assert!(owner
            .set_population_baud_with_delay(&replies, StartupBaud::Operational, deadline(), || {
                registers.0.lock().unwrap().words.insert(COMMAND_CONTROL, 7);
                Ok(())
            })
            .is_err());
        assert!(owner.terminal());
        assert_eq!(
            registers.0.lock().unwrap().stores,
            if initial_bad { 0 } else { 12 }
        );
    }
}

#[tokio::test]
async fn canceled_population_settle_retains_old_host_rate_until_worker_drains() {
    let (registers, owner, replies) = fixture();
    let worker_owner = owner.clone();
    let task = tokio::spawn(async move {
        worker_owner
            .set_population_asic_and_fpga_baud(replies, StartupBaud::Operational, deadline())
            .await
    });
    let limit = deadline();
    while registers.0.lock().unwrap().stores < 12 {
        assert!(Instant::now() < limit);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(owner.terminal());
    let _drained = owner.lock_until(deadline()).unwrap();
    let state = registers.0.lock().unwrap();
    assert_eq!(state.stores, 12);
    assert_eq!(state.words[&COMMAND_CONTROL] & 0x3f, 0x1a);
}
