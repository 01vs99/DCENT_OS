use super::*;
use dcentrald_hal::platform::c43_bm1393::transport::{C43Registers, C43Transport};
use std::sync::{Arc, Mutex};

// BM1393 allocates nonce high byte to chip and low byte to core. Each of the
// 60*208 physical cores therefore has 2^16 unique trials in one raw-TW frame.
// This model counts only cycles actually consumed from complete unique frames;
// writes to a full FIFO and repeated headers cannot inflate useful throughput.
#[derive(Default)]
struct FifoState {
    queues: [VecDeque<u64>; 3],
    hashes: [u64; 3],
    unique: [HashSet<Vec<u32>>; 3],
    partial: Vec<u32>,
    broken: Option<usize>,
    registers: BTreeMap<u32, u32>,
    pic_read: usize,
    #[cfg(feature = "sim-hal")]
    native: Option<Box<NativeRegisters>>,
}
#[derive(Default)]
struct FifoModel(Mutex<FifoState>);
impl FifoModel {
    fn advance(&self, micros: u64) {
        let mut state = self.0.lock().unwrap();
        for chain in 0..3 {
            if state.broken == Some(chain) {
                continue;
            }
            let mut cycles = micros * 400;
            while cycles > 0 {
                let Some(left) = state.queues[chain].front_mut() else {
                    break;
                };
                let used = cycles.min(*left);
                *left -= used;
                cycles -= used;
                if *left == 0 {
                    state.queues[chain].pop_front();
                }
                state.hashes[chain] += used * 60 * 208;
            }
        }
    }
}
impl C43Registers for FifoModel {
    fn read(&self, offset: u32) -> std::result::Result<u32, String> {
        let mut state = self.0.lock().unwrap();
        #[cfg(feature = "sim-hal")]
        if let Some(native) = state.native.as_mut() {
            return native.read(offset);
        }
        Ok(match offset {
            0x08 => 7,
            0x0c => (0..3)
                .filter(|&chain| state.queues[chain].len() < 8 && state.broken != Some(chain))
                .fold(0, |mask, chain| mask | (1 << chain)),
            _ => *state.registers.get(&offset).unwrap_or(&0),
        })
    }
    fn write(&self, offset: u32, value: u32) -> std::result::Result<(), String> {
        let mut state = self.0.lock().unwrap();
        #[cfg(feature = "sim-hal")]
        if let Some(native) = state.native.as_mut() {
            return native.write(offset, value);
        }
        match offset {
            0x40 => {
                assert!(
                    state.partial.is_empty(),
                    "new frame interrupted retained write"
                );
                state.partial.push(value);
            }
            0x44 => {
                state.partial.push(value);
                if state.partial.len() == 13 {
                    let frame = std::mem::take(&mut state.partial);
                    let chain = ((frame[0] >> 16) & 15) as usize;
                    assert!(state.queues[chain].len() < 8, "FIFO overflow");
                    assert!(
                        state.unique[chain].insert(frame[2..].to_vec()),
                        "repeated hashing work"
                    );
                    state.queues[chain].push_back(65536);
                }
            }
            0x30 => {
                let data = if value & (1 << 25) != 0 {
                    let byte = [0x15, 1][state.pic_read % 2];
                    state.pic_read += 1;
                    byte
                } else {
                    0
                };
                state.registers.insert(offset, 0x8000_0000 | data);
            }
            _ => {
                state.registers.insert(offset, value);
            }
        }
        Ok(())
    }
}

#[cfg(feature = "sim-hal")]
include!("c43_bm1393_native_register_fixture.rs");
#[cfg(feature = "sim-hal")]
#[path = "../tests/sim_support/share_oracle.rs"]
mod independent_pool;
#[cfg(feature = "sim-hal")]
include!("c43_bm1393_native_pool_tests.rs");

#[tokio::test]
async fn production_feeder_and_retained_fifo_exceed_eighty_percent_simulated_nameplate() {
    let model = Arc::new(FifoModel::default());
    let owner = C43Transport::new(model.clone(), vec![0, 1, 2]).unwrap();
    let mut feeder = Feeder::new(&[0, 1, 2]);
    let mut sequence = 0;
    let mut elapsed_us = 0;
    for tick in 0..2000 {
        let items = feeder
            .prepare(|| {
                let mut work = oracle_work(0);
                sequence += 1;
                work.ntime += sequence;
                Ok(work)
            })
            .unwrap();
        assert_eq!(items.len(), 24);
        let accepted = owner.try_work_batch(items).await.unwrap();
        feeder.commit(&accepted).unwrap();
        // Include scheduler/return-drain overhead and a 200ms sensor pause.
        let step = if tick == 1000 { 200_000 } else { 1_020 };
        model.advance(step);
        elapsed_us += step;
    }
    let state = model.0.lock().unwrap();
    let nameplate = elapsed_us * 400 * 60 * 208;
    for chain in 0..3 {
        assert!(
            state.hashes[chain] >= nameplate * 80 / 100,
            "chain{chain}: {} / {nameplate} useful simulated hashes",
            state.hashes[chain]
        );
        assert!(state.hashes[chain] <= nameplate);
    }
    let useful: u64 = state.hashes.iter().sum();
    println!("C43 simulated useful feed: {:.3} TH/s, {:.2}% of 14.976 TH/s nameplate; finite 8-frame FIFOs and 200ms sensor pause",
        useful as f64 / elapsed_us as f64 / 1_000_000.0,
        useful as f64 * 100.0 / (nameplate * 3) as f64);
}

#[tokio::test]
async fn busy_then_checked_faulted_chain_does_not_stall_two_healthy_fifos() {
    let model = Arc::new(FifoModel::default());
    let owner = C43Transport::new(model.clone(), vec![0, 1, 2]).unwrap();
    let mut feeder = Feeder::new(&[0, 1, 2]);
    let mut sequence = 0;
    let mut waiting = None;
    for tick in 0..200 {
        if tick == 50 {
            model.0.lock().unwrap().broken = Some(1);
        }
        if tick == 100 {
            let proof = owner.isolate_chain(1).await.unwrap();
            assert!(owner.accepts_isolation(&proof));
            feeder.retain_active(&owner.active_chains());
        }
        let items = feeder
            .prepare(|| {
                let mut work = oracle_work(0);
                sequence += 1;
                work.ntime += sequence;
                Ok(work)
            })
            .unwrap();
        if (50..100).contains(&tick) {
            let pending: Vec<_> = items
                .iter()
                .filter(|(chain, _)| *chain == 1)
                .cloned()
                .collect();
            if let Some(previous) = &waiting {
                assert_eq!(&pending, previous);
            }
            waiting = Some(pending);
        }
        feeder
            .commit(&owner.try_work_batch(items).await.unwrap())
            .unwrap();
        model.advance(1000);
    }
    let state = model.0.lock().unwrap();
    let nameplate = 200_000 * 400 * 60 * 208;
    for chain in [0, 2] {
        assert!(state.hashes[chain] >= nameplate * 80 / 100);
    }
    assert_eq!(owner.active_chains(), [0, 2]);
    assert!(!owner.terminal());
    assert_eq!(feeder.ledgers.len(), 2);
}

#[test]
fn pending_generation_invalidation_wrap_and_malformed_completion_do_not_admit_work() {
    let mut feeder = Feeder::new(&[0]);
    feeder.ledgers.get_mut(&0).unwrap().next = 29997;
    let batch = feeder.prepare(|| Ok(oracle_work(0))).unwrap();
    assert_eq!(
        batch.iter().map(|(_, words)| words[1]).collect::<Vec<_>>(),
        [29997, 29998, 29999, 0, 1, 2, 3, 4]
    );
    assert!(feeder
        .commit(&[false, true, false, false, false, false, false, false])
        .is_err());
    assert!(feeder.ledgers[&0].slots.iter().all(Option::is_none));
    feeder.invalidate();
    let next = feeder.prepare(|| Ok(oracle_work(1))).unwrap();
    assert!(next
        .iter()
        .all(|(_, words)| !batch.iter().any(|(_, old)| old[1] == words[1])));
    feeder.commit(&[true; 8]).unwrap();
    assert!(feeder.ledgers[&0]
        .slots
        .iter()
        .flatten()
        .all(|work| work.work_generation.job == 1));
}

#[test]
fn never_accepted_first_batch_has_a_deadline_without_claiming_a_dispatch() {
    let mut feeder = Feeder::new(&[0]);
    feeder.prepare(|| Ok(oracle_work(0))).unwrap();
    feeder.commit(&[false; 8]).unwrap();
    let ledger = &feeder.ledgers[&0];
    let first = ledger.first_offer.unwrap();
    assert!(ledger.first_dispatch.is_none());
    assert!(ledger.slots.iter().all(Option::is_none));
    assert!(!ledger.ticket_deadline_expired(first + Duration::from_secs(59)));
    assert!(ledger.ticket_deadline_expired(first + Duration::from_secs(60)));
    feeder.invalidate();
    assert!(feeder.ledgers[&0].ticket_deadline_expired(first + Duration::from_secs(600)));
    feeder.pause(first + Duration::from_secs(600));
    assert!(!feeder.ledgers[&0].ticket_deadline_expired(first + Duration::from_secs(601)));
}

#[test]
fn job_churn_does_not_reset_chain_health_and_reconnections_pause_only_unused_time() {
    let start = Instant::now();
    let mut ledger = Ledger::new(Codec);
    ledger.offered_at(start);
    for seconds in (5..60).step_by(5) {
        ledger.invalidate();
        ledger.offered_at(start + Duration::from_secs(seconds));
        assert!(!ledger.ticket_deadline_expired(start + Duration::from_secs(seconds)));
    }
    assert!(ledger.ticket_deadline_expired(start + Duration::from_secs(60)));

    let mut reconnecting = Ledger::new(Codec);
    for cycle in 0..6 {
        let now = start + Duration::from_secs(cycle * 110);
        reconnecting.invalidate();
        reconnecting.offered_at(now);
        assert_eq!(
            reconnecting.ticket_deadline_expired(now + Duration::from_secs(10)),
            cycle == 5
        );
        reconnecting.pause_health(now + Duration::from_secs(10));
        assert!(!reconnecting.ticket_deadline_expired(now + Duration::from_secs(100)));
    }
    reconnecting.offered_at(start + Duration::from_secs(1000));
    assert!(reconnecting.ticket_deadline_expired(start + Duration::from_secs(1000)));
}

#[test]
fn reused_wire_id_rejects_delayed_old_header_and_identical_proof_cannot_refresh_health() {
    let mut ledger = Ledger::new(Codec);
    let first = oracle_work(1);
    let (id, _, _) = ledger.prepare(&first).unwrap();
    ledger.commit(id, first.clone());
    ledger.next = id; // The actual wire-ID slot is reused, not a different ID.
                      // Genesis exceeds the retained difficulty-64 ticket threshold. Height 1
                      // is a valid difficulty-1 pool share but cannot reset chain health.
    let current = oracle_work(0);
    assert_eq!(ledger.prepare(&current).unwrap().0, id);
    ledger.commit(id, current.clone());
    let stalled_since = Instant::now();
    ledger.health_since = Some(stalled_since);
    assert!(ledger.validate(0, id, 0x01e36299, "pool.worker").is_none());
    assert_eq!(ledger.tickets, 0);
    assert_eq!(ledger.health_since, Some(stalled_since));
    assert!(ledger.ticket_deadline_expired(stalled_since + Duration::from_secs(61)));
    assert!(ledger.validate(0, id, 0x1dac2b7c, "pool.worker").is_some());
    assert_eq!(ledger.tickets, 1);
    assert!(!ledger.ticket_deadline_expired(Instant::now()));
    let last = ledger.last_ticket;
    ledger.invalidate();
    ledger.next = id;
    let mut repeated = current;
    repeated.work_generation.session += 1;
    assert_eq!(ledger.prepare(&repeated).unwrap().0, id);
    ledger.commit(id, repeated);
    assert!(ledger.validate(0, id, 0x1dac2b7c, "pool.worker").is_none());
    assert_eq!(ledger.last_ticket, last);
    assert_eq!(ledger.tickets, 1);
}
