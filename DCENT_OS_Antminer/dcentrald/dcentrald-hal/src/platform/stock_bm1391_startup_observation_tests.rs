use super::*;
use std::collections::VecDeque;
use std::sync::Condvar;

#[derive(Clone, Copy, Default)]
enum Mutation {
    #[default]
    None,
    Missing,
    Crc,
    WrongRegister,
    WrongChain,
    WrongAddress,
    Nonuniform,
    RateMismatch,
    Conflicting,
    StaleOnly,
    Endless,
}
#[derive(Default)]
struct State {
    words: BTreeMap<u32, u32>,
    writes: Vec<(u32, u32)>,
    returns: VecDeque<(u32, u32)>,
    mutation: Mutation,
    fail_at: Option<usize>,
}
struct Recording {
    model: Model,
    state: Mutex<State>,
    pop_started: AtomicBool,
    pop_gate: Option<Arc<(Mutex<bool>, Condvar)>>,
}
fn raw(reply: Bm1391StockRegisterReturn) -> (u32, u32) {
    (
        (u32::from(reply.crc5) << 24)
            | (u32::from(reply.chip_address) << 16)
            | (u32::from(reply.register) << 8)
            | u32::from(reply.chain_slot),
        reply.value,
    )
}
fn reply(chain: u8, address: u8, register: u8, value: u32) -> Bm1391StockRegisterReturn {
    let mut packet = [0; 7];
    packet[..4].copy_from_slice(&value.to_be_bytes());
    packet[4] = address;
    packet[5] = register;
    Bm1391StockRegisterReturn {
        chain_slot: chain,
        chip_address: address,
        register,
        value,
        crc5: dcentrald_common::s9se_vil::crc5_bits(&packet, 51),
        register_type: 0,
        fpga_crc_error: false,
    }
}
impl Registers for Recording {
    fn model(&self) -> Option<Model> {
        Some(self.model)
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        if offset == RETURN1 {
            self.pop_started.store(true, Ordering::SeqCst);
            if let Some(gate) = &self.pop_gate {
                let (lock, wake) = &**gate;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = wake.wait(released).unwrap();
                }
            }
        }
        let mut state = self.state.lock().unwrap();
        Ok(match offset {
            VERSION => 0xc501,
            PRESENCE => 7,
            RETURN_COUNT => state.returns.len() as u32,
            RETURN0 => state.returns.front().unwrap().0,
            RETURN1 => {
                let pair = state.returns.pop_front().unwrap();
                if matches!(state.mutation, Mutation::Endless) {
                    state.returns.push_back(pair);
                }
                pair.1
            }
            _ => state.words.get(&offset).copied().unwrap_or(0),
        })
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if state.fail_at == Some(state.writes.len()) {
            return Err("injected publication failure".into());
        }
        state.writes.push((offset, value));
        state.words.insert(
            offset,
            value
                & if offset == COMMAND_CONTROL {
                    0x7fff_ffff
                } else {
                    u32::MAX
                },
        );
        if offset == COMMAND_CONTROL
            && value & 0x8000_0000 != 0
            && state.words[&COMMAND_BUFFER] >> 24 == 0x52
        {
            let chain = ((value >> 16) & 0xf) as u8;
            let mutation = state.mutation;
            if matches!(mutation, Mutation::StaleOnly) {
                return Ok(());
            }
            for index in (0..self.model.expected_chips()).rev() {
                if index == 0 && matches!(mutation, Mutation::Missing) {
                    continue;
                }
                let address = index * self.model.address_interval();
                let mut record = reply(chain, address, 0x18, 0x3a01);
                if index == 0 {
                    record = match mutation {
                        Mutation::WrongRegister => reply(chain, address, 0x1c, 0x3a01),
                        Mutation::WrongChain => reply(3, address, 0x18, 0x3a01),
                        Mutation::WrongAddress => reply(chain, 255, 0x18, 0x3a01),
                        Mutation::Nonuniform => reply(chain, address, 0x18, 0x3a03),
                        Mutation::RateMismatch => reply(chain, address, 0x18, 0x3901),
                        _ => record,
                    };
                    if matches!(mutation, Mutation::Crc) {
                        record.crc5 ^= 1;
                    }
                }
                state.returns.push_back(raw(record));
            }
            if matches!(mutation, Mutation::Conflicting) {
                state.returns.push_back(raw(reply(chain, 0, 0x18, 0x3a03)));
            } else {
                // Identical retransmission must not count as an additional chip.
                state.returns.push_back(raw(reply(
                    chain,
                    3 * self.model.address_interval(),
                    0x18,
                    0x3a01,
                )));
            }
        }
        Ok(())
    }
}
fn population(model: Model, chains: &[u8]) -> Vec<Census> {
    chains
        .iter()
        .map(|chain| Census {
            chain: *chain,
            replies: (0..model.expected_chips())
                .map(|index| {
                    let address = index * model.address_interval();
                    reply(*chain, address, 0, 0x1391_0000 | u32::from(address))
                })
                .collect(),
        })
        .collect()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn fixture(model: Model, chains: Vec<u8>) -> (Arc<Recording>, Arc<StartupObservation<Recording>>) {
    let registers = Arc::new(Recording {
        model,
        state: Mutex::new(State::default()),
        pop_started: AtomicBool::new(false),
        pop_gate: None,
    });
    registers
        .state
        .lock()
        .unwrap()
        .words
        .insert(COMMAND_CONTROL, 0x0010_501a);
    let owner = Transport::new(registers.clone(), chains.clone()).unwrap();
    let service = StartupObservation::new(owner, population(model, &chains)).unwrap();
    (registers, service)
}

#[test]
fn full_current_population_at_unchanged_host_is_joined_before_one_atomic_switch() {
    for model in [Model::S15, Model::T15] {
        for switch in [None, Some(StartupBaud::Operational)] {
            let (registers, service) = fixture(model, vec![0, 2]);
            // Valid but stale replies cannot satisfy the later complete join.
            registers
                .state
                .lock()
                .unwrap()
                .returns
                .push_back(raw(reply(0, 0, 0x18, 0x3a03)));
            let mut settles = 0;
            let report = service
                .run_with_delay(switch, deadline(), &mut |ms| {
                    assert!(service.owner.lane.try_lock().is_err());
                    let state = registers.state.lock().unwrap();
                    assert_eq!(state.words[&COMMAND_CONTROL] & 0x3f, 0x1a);
                    if ms == 50 {
                        settles += 1;
                        assert_eq!(state.writes.len(), 16); // Both reads then both writes.
                    }
                    Ok(())
                })
                .unwrap();
            assert_eq!(report.host_before(), 0x1a);
            assert_eq!(report.host_after(), if switch.is_some() { 0 } else { 0x1a });
            assert_eq!(
                report.replies().len(),
                usize::from(model.expected_chips()) * 2
            );
            assert_eq!(report.stale_registers(), 1);
            assert_eq!(settles, usize::from(switch.is_some()));
            let state = registers.state.lock().unwrap();
            assert_eq!(state.writes.len(), if switch.is_some() { 17 } else { 8 });
            assert!(!service.owner.terminal());
        }
    }
}

#[test]
fn missing_corrupt_conflicting_unexpected_or_nonuniform_chips_never_authorize_a_write() {
    for mutation in [
        Mutation::Missing,
        Mutation::Crc,
        Mutation::WrongRegister,
        Mutation::WrongChain,
        Mutation::WrongAddress,
        Mutation::Nonuniform,
        Mutation::RateMismatch,
        Mutation::Conflicting,
        Mutation::StaleOnly,
        Mutation::Endless,
    ] {
        let (registers, service) = fixture(Model::S15, vec![0]);
        registers.state.lock().unwrap().mutation = mutation;
        assert!(service
            .run_with_delay(Some(StartupBaud::Operational), deadline(), &mut |_| Ok(()))
            .is_err());
        assert!(service.owner.terminal());
        let state = registers.state.lock().unwrap();
        assert_eq!(state.writes.len(), 4); // Only the read request was issued.
        assert_eq!(state.words[&COMMAND_CONTROL] & 0x3f, 0x1a);
    }
}

#[test]
fn admission_requires_exact_complete_census_and_permanent_singleton() {
    let (registers, service) = fixture(Model::T15, vec![0, 2]);
    assert!(
        StartupObservation::new(service.owner.clone(), population(Model::T15, &[0, 2])).is_err()
    );
    for failure in 0..6 {
        let registers = Arc::new(Recording {
            model: Model::T15,
            state: Mutex::new(State::default()),
            pop_started: AtomicBool::new(false),
            pop_gate: None,
        });
        let owner = Transport::new(registers.clone(), vec![0, 2]).unwrap();
        let mut observed = population(Model::T15, &[0, 2]);
        match failure {
            0 => {
                observed.pop();
            }
            1 => {
                observed[0].replies.pop();
            }
            2 => {
                observed[0].replies.swap(0, 1);
            }
            3 => {
                observed[0].replies[0].crc5 ^= 1;
            }
            4 => {
                observed[0].replies[0] = reply(0, 0, 0, 0x1393_0000);
            }
            _ => {
                observed.swap(0, 1);
            }
        }
        assert!(StartupObservation::new(owner.clone(), observed).is_err());
        assert!(registers.state.lock().unwrap().writes.is_empty());
        assert!(!owner.startup_observation_claimed.load(Ordering::SeqCst));
    }
    assert!(registers.state.lock().unwrap().writes.is_empty());
}

#[test]
fn host_alias_drift_expiration_and_every_partial_publication_are_terminal() {
    for host in [0x3a, 0x8000_001a] {
        let (registers, service) = fixture(Model::T15, vec![0]);
        registers
            .state
            .lock()
            .unwrap()
            .words
            .insert(COMMAND_CONTROL, host);
        assert!(service
            .run_with_delay(Some(StartupBaud::Operational), deadline(), &mut |_| Ok(()))
            .is_err());
        assert!(registers.state.lock().unwrap().writes.is_empty());
        assert!(service.owner.terminal());
    }
    let (registers, service) = fixture(Model::T15, vec![0]);
    assert!(service
        .run_with_delay(Some(StartupBaud::Operational), deadline(), &mut |_| {
            registers
                .state
                .lock()
                .unwrap()
                .words
                .insert(COMMAND_CONTROL, 7);
            Ok(())
        })
        .is_err());
    assert_eq!(registers.state.lock().unwrap().writes.len(), 4);
    for failure in 0..9 {
        let (registers, service) = fixture(Model::T15, vec![0]);
        registers.state.lock().unwrap().fail_at = Some(failure);
        assert!(service
            .run_with_delay(Some(StartupBaud::Operational), deadline(), &mut |_| Ok(()))
            .is_err());
        assert_eq!(registers.state.lock().unwrap().writes.len(), failure);
        assert!(service.owner.terminal());
    }
    let (registers, service) = fixture(Model::T15, vec![0]);
    assert!(service
        .run_with_delay(None, Instant::now(), &mut |_| Ok(()))
        .is_err());
    assert!(registers.state.lock().unwrap().writes.is_empty());
}

#[test]
fn continuous_stale_traffic_is_bounded_and_unexpected_nonce_is_retained_even_off_population() {
    let (registers, service) = fixture(Model::S15, vec![0]);
    registers
        .state
        .lock()
        .unwrap()
        .returns
        .extend(std::iter::repeat_n(raw(reply(0, 0, 0x18, 0x3a01)), 511));
    assert!(service
        .run_with_delay(None, deadline(), &mut |_| Ok(()))
        .is_err());
    assert!(registers.state.lock().unwrap().writes.is_empty());
    let (registers, service) = fixture(Model::S15, vec![0]);
    registers
        .state
        .lock()
        .unwrap()
        .returns
        .extend([(0x8123_0082, 123), raw(reply(0, 0, 0x18, 0x3a01))]);
    assert!(service
        .run_with_delay(None, deadline(), &mut |_| Ok(()))
        .is_err());
    let retained = service.unexpected_nonce.lock().unwrap().unwrap();
    assert_eq!(
        (retained.chain_slot, retained.work_id, retained.nonce),
        (2, 0x123, 123)
    );
    assert_eq!(registers.state.lock().unwrap().returns.len(), 1);
    assert!(registers.state.lock().unwrap().writes.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_active_reader_retains_nonce_until_worker_finishes() {
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let registers = Arc::new(Recording {
        model: Model::T15,
        state: Mutex::new(State::default()),
        pop_started: AtomicBool::new(false),
        pop_gate: Some(gate.clone()),
    });
    registers
        .state
        .lock()
        .unwrap()
        .words
        .insert(COMMAND_CONTROL, 0x1a);
    registers
        .state
        .lock()
        .unwrap()
        .returns
        .push_back((0x8001_0080, 456));
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    let service = StartupObservation::new(owner.clone(), population(Model::T15, &[0])).unwrap();
    let copy = service.clone();
    let task = tokio::spawn(async move { copy.observe(deadline()).await });
    let until = deadline();
    while !registers.pop_started.load(Ordering::SeqCst) {
        assert!(Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(owner.terminal());
    assert!(service
        .unexpected_nonce_after_drain(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    let nonce = service
        .unexpected_nonce_after_drain(deadline())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(nonce.nonce, 456);
    assert_eq!(service.in_flight.load(Ordering::SeqCst), 0);
    assert!(registers.state.lock().unwrap().writes.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_lane_waiter_cannot_later_publish_or_consume_returns() {
    let (registers, service) = fixture(Model::T15, vec![0]);
    let lane = service.owner.lane.lock().unwrap();
    let copy = service.clone();
    let task = tokio::spawn(async move { copy.observe(deadline()).await });
    let until = deadline();
    while service.in_flight.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(lane);
    assert!(service
        .unexpected_nonce_after_drain(deadline())
        .await
        .unwrap()
        .is_none());
    assert!(service.owner.terminal());
    assert!(registers.state.lock().unwrap().writes.is_empty());
}
