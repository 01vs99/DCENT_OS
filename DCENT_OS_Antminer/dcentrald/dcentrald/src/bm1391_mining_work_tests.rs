use super::*;
use dcentrald_common::{
    bm1391_share_qualification::{
        bm1391_stock_double_sha256_from_midstate, Bm1391StockPrecomputedHashInput,
    },
    bm1391_stock_return::Bm1391StockFpgaReturn,
};
use std::{collections::VecDeque, sync::Mutex, time::Duration};

const HEADERS: [&str;2] = [
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
    "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
];
const HASHES: [&str; 2] = [
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
];

include!("bm1391_mining_pool_order_tests.rs");

#[test]
fn verified_ticket_liveness_is_independent_of_pool_target_and_rejects_replays() {
    let mmio = Arc::new(Mmio::default());
    let owner = Transport::new(mmio, vec![0]).unwrap();
    let mut dispatcher = WorkDispatcher::new(owner, "ticket.worker".into());
    let (mut genesis, bytes) = sample(0);
    let generation = genesis.work_generation;
    // The independently pinned genesis digest meets difficulty64 but cannot
    // meet an all-zero pool target. This is actual full-header SHA checking.
    genesis.share_target = [0; 32];
    dispatcher.registry.activate(generation);
    let id = dispatcher
        .registry
        .dispatch_prepared(vec![(0, genesis)], deadline())
        .unwrap();
    let raw = u32::from_be_bytes(bytes[76..80].try_into().unwrap());
    let found = returned(0, id, raw);
    assert!(dispatcher
        .registry
        .qualify(found, generation, "ticket.worker")
        .is_none());
    let observed = dispatcher.ticket_observations();
    assert_eq!(observed[0].total, 1);
    assert!(observed[0].last.is_some());
    assert_eq!(observed[1].total, 0);
    assert_eq!(observed[2].total, 0);
    for candidate in [found, returned(1, id, raw), returned(0, id, raw ^ 1)] {
        assert!(dispatcher
            .registry
            .qualify(candidate, generation, "ticket.worker")
            .is_none());
    }
    assert_eq!(dispatcher.ticket_observations()[0].last, observed[0].last);
    assert_eq!(dispatcher.ticket_observations()[0].total, 1);
    dispatcher.disconnect();
    assert!(dispatcher
        .registry
        .qualify(found, generation, "ticket.worker")
        .is_none());
    assert_eq!(dispatcher.ticket_observations()[0].last, observed[0].last);

    // Block1 is valid at difficulty1, below64. A real pool-eligible share
    // therefore cannot itself be counted as a difficulty64 liveness ticket.
    let (block1, bytes) = sample(1);
    let generation = block1.work_generation;
    dispatcher.registry.activate(generation);
    let id = dispatcher
        .registry
        .dispatch_prepared(vec![(0, block1)], deadline())
        .unwrap();
    let found = returned(0, id, u32::from_be_bytes(bytes[76..80].try_into().unwrap()));
    assert!(dispatcher
        .registry
        .qualify(found, generation, "ticket.worker")
        .is_some());
    assert_eq!(dispatcher.ticket_observations()[0].total, 1);
    assert_eq!(dispatcher.ticket_observations()[0].last, observed[0].last);
}

fn dispatcher_fixture() -> (Arc<Mmio>, WorkDispatcher<Mmio>, WorkGeneration, u16) {
    let mmio = Arc::new(Mmio::default());
    let owner = Transport::new(mmio.clone(), vec![0, 1, 2]).unwrap();
    let mut dispatcher = WorkDispatcher::new(owner, "retained.outbox".into());
    let generation = WorkGeneration {
        session: 50,
        job: 1,
    };
    dispatcher.registry.activate(generation);
    let mut population = distinct_population(generation);
    // This queue-custody fixture deliberately admits every hash. The immutable
    // public-block tests below separately establish real difficulty1 hashes.
    for (_, work) in &mut population {
        work.share_target = [0xff; 32];
    }
    let id = dispatcher
        .registry
        .dispatch_prepared(population, deadline())
        .unwrap();
    (mmio, dispatcher, generation, id)
}

#[test]
fn dispatcher_backpressure_keeps_every_consumed_share_and_leaves_next_fifo_record_unread() {
    let (mmio, mut dispatcher, generation, id) = dispatcher_fixture();
    for raw in 0..129 {
        mmio.0
            .lock()
            .unwrap()
            .returns
            .push_back((0x8000_0080 | raw % 3 | (u32::from(id) << 16), raw));
    }
    assert_eq!(dispatcher.drain_fifo(deadline()).unwrap(), (128, 0));
    assert_eq!(mmio.0.lock().unwrap().returns.len(), 1);
    assert_eq!(dispatcher.drain_fifo(deadline()).unwrap(), (0, 0));
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    assert!(!dispatcher.flush_shares(&tx).unwrap());
    assert_eq!(dispatcher.drain_fifo(deadline()).unwrap(), (1, 0));
    let mut seen = HashSet::new();
    for _ in 0..129 {
        let share = rx.try_recv().unwrap();
        assert_eq!(share.work_generation, generation);
        assert!(seen.insert(u32::from_str_radix(&share.nonce, 16).unwrap().swap_bytes()));
        dispatcher.flush_shares(&tx).unwrap();
    }
    assert_eq!(seen, (0..129).collect());
    assert!(rx.try_recv().is_err());
    assert!(dispatcher.flush_shares(&tx).unwrap());
}

#[test]
fn dispatcher_thermal_snapshots_are_idempotent_and_acknowledgment_stops_before_full_outbox() {
    use dcentrald_hal::platform::stock_bm1391::PreservedThermalNonce;
    let (_, mut dispatcher, _, id) = dispatcher_fixture();
    let pending: Vec<_> = (1..=129)
        .map(|sequence| PreservedThermalNonce {
            sequence,
            record: returned((sequence % 3) as u8, id, sequence as u32),
        })
        .collect();
    assert_eq!(dispatcher.offer_preserved(&pending).unwrap(), Some(128));
    assert_eq!(dispatcher.offer_preserved(&pending).unwrap(), Some(128));
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    assert!(dispatcher.flush_shares(&tx).unwrap());
    assert_eq!(dispatcher.offer_preserved(&pending).unwrap(), Some(129));
    assert_eq!(dispatcher.offer_preserved(&pending).unwrap(), Some(129));
    assert!(dispatcher.flush_shares(&tx).unwrap());
    let mut shares = Vec::new();
    while let Ok(share) = rx.try_recv() {
        shares.push(share);
    }
    assert_eq!(shares.len(), 129);
    let gap = [PreservedThermalNonce {
        sequence: 131,
        record: returned(0, id, 131),
    }];
    assert!(dispatcher.offer_preserved(&gap).is_err());
    assert!(dispatcher.registry.transport.terminal());
}

#[test]
fn dispatcher_closed_share_actor_latches_and_disconnect_discards_queued_stale_work() {
    let (mmio, mut dispatcher, _, id) = dispatcher_fixture();
    mmio.0
        .lock()
        .unwrap()
        .returns
        .push_back((0x8000_0080 | (u32::from(id) << 16), 0));
    dispatcher.drain_fifo(deadline()).unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    drop(rx);
    assert!(dispatcher.flush_shares(&tx).is_err());
    assert!(dispatcher.registry.transport.terminal());
    dispatcher.disconnect();
    assert!(dispatcher.flush_shares(&tx).unwrap());
    assert!(!dispatcher.dispatch_if_ready(deadline()).unwrap());
}
fn sample(index: usize) -> (MiningWork, [u8; 80]) {
    let bytes: [u8; 80] =
        std::array::from_fn(|i| u8::from_str_radix(&HEADERS[index][i * 2..i * 2 + 2], 16).unwrap());
    (
        MiningWork {
            work_generation: WorkGeneration {
                session: 9,
                job: index as u64,
            },
            midstates: vec![dcentrald_stratum::work::compute_midstate_from_prefix(
                &bytes[..64].try_into().unwrap(),
            )],
            merkle4: bytes[64..68].try_into().unwrap(),
            ntime: u32::from_le_bytes(bytes[68..72].try_into().unwrap()),
            nbits: u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
            job_id: format!("bm1391-public-block-{index}"),
            extranonce2: "0102".into(),
            version: 1,
            version_mask: 0,
            share_target: dcentrald_stratum::work::difficulty_to_target(1.0),
            merkle_root: bytes[36..68].try_into().unwrap(),
            prev_block_hash: bytes[4..36].try_into().unwrap(),
        },
        bytes,
    )
}
#[derive(Default)]
struct State {
    writes: Vec<(u32, u32)>,
    returns: VecDeque<(u32, u32)>,
    fail: Option<usize>,
}
#[derive(Default)]
struct Mmio(Mutex<State>);
impl Registers for Mmio {
    fn read(&self, offset: u32) -> Result<u32, String> {
        let mut state = self.0.lock().unwrap();
        match offset {
            0 => Ok(0xc501),
            8 | 12 => Ok(7),
            0x18 => Ok(state.returns.len() as u32),
            0x10 => Ok(state.returns.front().unwrap().0),
            0x14 => Ok(state.returns.pop_front().unwrap().1),
            _ => Err(format!("unexpected register{offset:x}")),
        }
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        if state.fail == Some(state.writes.len()) {
            return Err("partial native work".into());
        }
        state.writes.push((offset, value));
        Ok(())
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(1)
}

fn distinct_population(generation: WorkGeneration) -> Vec<(u8, MiningWork)> {
    (0..3)
        .map(|chain| {
            let (mut work, _) = sample(usize::from(chain == 1));
            work.work_generation = generation;
            work.extranonce2 = format!("0000000{chain}");
            if chain == 2 {
                work.ntime += 1;
                work.share_target = [0xff; 32];
            }
            (chain, work)
        })
        .collect()
}

fn returned(chain: u8, id: u16, raw: u32) -> Bm1391StockNonceReturn {
    let bytes: Vec<_> = [0x8000_0080 | u32::from(chain) | (u32::from(id) << 16), raw]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let Bm1391StockFpgaReturn::Nonce(found) =
        dcentrald_common::bm1391_stock_return::decode_bm1391_stock_fpga_return(&bytes).unwrap()
    else {
        panic!("nonce fixture did not decode")
    };
    found
}

#[test]
fn registry_commits_unique_chain_headers_and_routes_actual_fifo_to_exact_submit_fields() {
    let mmio = Arc::new(Mmio::default());
    let owner = Transport::new(mmio.clone(), vec![0, 1, 2]).unwrap();
    let mut registry = WorkRegistry::new(owner.clone());
    let generation = WorkGeneration {
        session: 22,
        job: 5,
    };
    registry.activate(generation);
    let work = distinct_population(generation);
    let id = registry
        .dispatch_prepared(work.clone(), deadline())
        .unwrap();
    let stores = mmio.0.lock().unwrap().writes.clone();
    assert_eq!(stores.len(), 39);
    let mut encoded = HashSet::new();
    for (chain, frame) in stores.chunks_exact(13).enumerate() {
        assert_eq!(frame[0].1, 0x0180_0000 | ((chain as u32) << 16));
        assert_eq!(frame[1].1, u32::from(id));
        assert!(encoded.insert(frame[2..].iter().map(|(_, word)| *word).collect::<Vec<_>>()));
        let raw = if chain == 1 { 0x01e36299 } else { 0x1dac2b7c };
        let found = returned(chain as u8, id, raw);
        mmio.0
            .lock()
            .unwrap()
            .returns
            .push_back((0x8000_0080 | chain as u32 | (u32::from(id) << 16), raw));
        let Some(Bm1391StockFpgaReturn::Nonce(actual)) = owner.read_return(deadline()).unwrap()
        else {
            panic!("actual HAL FIFO did not return work nonce")
        };
        let share = registry
            .qualify(actual, generation, "native.population")
            .unwrap();
        assert_eq!(share.extranonce2, work[chain].1.extranonce2);
        assert_eq!(share.ntime, format!("{:08x}", work[chain].1.ntime));
        assert_eq!(share.job_id, work[chain].1.job_id);
        assert_eq!(share.nonce, format!("{:08x}", raw.swap_bytes()));
        assert!(registry.qualify(found, generation, "duplicate").is_none());
    }
    // The same raw nonce is valid on both chain0 and chain2's different work;
    // duplicate classification is scoped to the actual chain's canonical job.
    assert_eq!(encoded.len(), 3);
    assert!(registry
        .qualify(
            returned(0, id, 0x1dac2b7c),
            WorkGeneration {
                session: 23,
                job: 5
            },
            "stale"
        )
        .is_none());
    registry.invalidate();
    assert!(registry
        .qualify(returned(0, id, 0x1dac2b7c), generation, "revoked")
        .is_none());
}

#[test]
fn registry_rejects_duplicate_or_incomplete_populations_before_any_frame_and_clears_partial_commits(
) {
    let mmio = Arc::new(Mmio::default());
    let owner = Transport::new(mmio.clone(), vec![0, 1, 2]).unwrap();
    let generation = WorkGeneration {
        session: 22,
        job: 5,
    };
    let mut registry = WorkRegistry::new(owner.clone());
    registry.activate(generation);
    let mut duplicate = distinct_population(generation);
    duplicate[1].1 = duplicate[0].1.clone();
    assert!(registry.dispatch_prepared(duplicate, deadline()).is_err());
    let mut missing = distinct_population(generation);
    missing.pop();
    assert!(registry.dispatch_prepared(missing, deadline()).is_err());
    assert!(mmio.0.lock().unwrap().writes.is_empty());
    assert!(!owner.terminal());
    let id = registry
        .dispatch_prepared(distinct_population(generation), deadline())
        .unwrap();
    let before = mmio.0.lock().unwrap().writes.len();
    mmio.0.lock().unwrap().fail = Some(before + 14);
    assert!(registry
        .dispatch_prepared(distinct_population(generation), deadline())
        .is_err());
    assert_eq!(mmio.0.lock().unwrap().writes.len(), before + 14);
    assert!(owner.terminal());
    assert!(registry.slots.iter().all(Option::is_none));
    assert!(registry
        .qualify(returned(0, id, 0x1dac2b7c), generation, "old")
        .is_none());
}

#[test]
fn registry_wraps_full_wire_id_space_without_restarting_on_generation_change() {
    let mmio = Arc::new(Mmio::default());
    let owner = Transport::new(mmio.clone(), vec![0]).unwrap();
    let mut registry = WorkRegistry::new(owner);
    let (first, _) = sample(0);
    registry.activate(first.work_generation);
    assert_eq!(
        registry
            .dispatch_prepared(vec![(0, first.clone())], deadline())
            .unwrap(),
        0
    );
    registry.next_id = 0x7fff;
    assert_eq!(
        registry
            .dispatch_prepared(vec![(0, first.clone())], deadline())
            .unwrap(),
        0x7fff
    );
    let (mut second, _) = sample(1);
    second.work_generation = first.work_generation;
    assert_eq!(
        registry
            .dispatch_prepared(vec![(0, second)], deadline())
            .unwrap(),
        0
    );
    assert!(registry
        .qualify(
            returned(0, 0, 0x1dac2b7c),
            first.work_generation,
            "old-header"
        )
        .is_none());
    assert!(registry
        .qualify(
            returned(0, 0, 0x01e36299),
            first.work_generation,
            "new-header"
        )
        .is_some());
    let next_generation = WorkGeneration {
        session: first.work_generation.session,
        job: 99,
    };
    registry.activate(next_generation);
    assert_eq!(registry.next_id, 1);
    assert!(registry.slots.iter().all(Option::is_none));
    let mut next = first;
    next.work_generation = next_generation;
    assert_eq!(
        registry
            .dispatch_prepared(vec![(0, next)], deadline())
            .unwrap(),
        1
    );
}

#[test]
fn two_canonical_blocks_cross_three_chain_mmio_fifo_hash_and_submit_fields() {
    for index in 0..2 {
        let (work, bytes) = sample(index);
        let mmio = Arc::new(Mmio::default());
        let owner = Transport::new(mmio.clone(), vec![0, 1, 2]).unwrap();
        let mut committed =
            CommittedWork::publish(owner.clone(), 0x7fff, work.clone(), deadline()).unwrap();
        let stores = mmio.0.lock().unwrap().writes.clone();
        assert_eq!(stores.len(), 39);
        let raw_nonce = u32::from_be_bytes(bytes[76..].try_into().unwrap());
        for (chain, frame) in stores.chunks_exact(13).enumerate() {
            assert_eq!(frame[0], (0x40, 0x0180_0000 | ((chain as u32) << 16)));
            assert_eq!(frame[1], (0x44, 0x7fff));
            assert!(frame[1..].iter().all(|(offset, _)| *offset == 0x44));
            // Decode only actual published words using the independently replayed
            // stock SHA consumer, then compare with immutable public block hashes.
            let digest =
                bm1391_stock_double_sha256_from_midstate(Bm1391StockPrecomputedHashInput {
                    midstate_words: std::array::from_fn(|i| frame[12 - i].1),
                    tail_words: std::array::from_fn(|i| frame[4 - i].1),
                    nonce3: raw_nonce,
                });
            let display: String = digest
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .rev()
                .map(|v| format!("{v:02x}"))
                .collect();
            assert_eq!(display, HASHES[index]);
            mmio.0
                .lock()
                .unwrap()
                .returns
                .push_back((0xffff_0080 | chain as u32, raw_nonce));
            let Some(Bm1391StockFpgaReturn::Nonce(found)) = owner.read_return(deadline()).unwrap()
            else {
                panic!("missing native nonce")
            };
            // Independently qualify each physical route; duplicate suppression
            // across identical-work chains is checked separately below.
            committed.seen.clear();
            let share = committed
                .qualify(found, work.work_generation, "beta.worker")
                .unwrap();
            assert_eq!(
                share.nonce,
                format!(
                    "{:08x}",
                    u32::from_le_bytes(bytes[76..].try_into().unwrap())
                )
            );
            assert_eq!(share.ntime, format!("{:08x}", work.ntime));
            assert_eq!(share.work_generation, work.work_generation);
            assert_eq!(share.job_id, work.job_id);
            assert_eq!(share.extranonce2, "0102");
            assert!(committed
                .qualify(found, work.work_generation, "beta.worker")
                .is_none());
        }
    }
}

#[test]
fn mismatched_headers_partial_commit_and_closed_or_stale_work_cannot_submit() {
    let (work, bytes) = sample(0);
    for bad in 0..2 {
        let mmio = Arc::new(Mmio::default());
        let owner = Transport::new(mmio.clone(), vec![0, 1, 2]).unwrap();
        let mut broken = work.clone();
        if bad == 0 {
            broken.midstates[0][0] ^= 1;
        } else {
            broken.merkle4[0] ^= 1;
        }
        assert!(CommittedWork::publish(owner, 1, broken, deadline()).is_err());
        assert!(mmio.0.lock().unwrap().writes.is_empty());
    }
    let mmio = Arc::new(Mmio::default());
    mmio.0.lock().unwrap().fail = Some(17);
    let owner = Transport::new(mmio.clone(), vec![0, 1, 2]).unwrap();
    assert!(CommittedWork::publish(owner.clone(), 1, work.clone(), deadline()).is_err());
    assert!(owner.terminal());
    assert_eq!(mmio.0.lock().unwrap().writes.len(), 17);
    let mmio = Arc::new(Mmio::default());
    let owner = Transport::new(mmio, vec![0, 1, 2]).unwrap();
    let mut committed = CommittedWork::publish(owner.clone(), 1, work.clone(), deadline()).unwrap();
    let found = Bm1391StockNonceReturn {
        chain_slot: 0,
        work_id: 1,
        nonce: u32::from_be_bytes(bytes[76..].try_into().unwrap()),
        stock_valid: true,
        status_bit6_set: false,
    };
    for bad in [
        Bm1391StockNonceReturn {
            stock_valid: false,
            ..found
        },
        Bm1391StockNonceReturn {
            chain_slot: 3,
            ..found
        },
        Bm1391StockNonceReturn {
            work_id: 2,
            ..found
        },
        Bm1391StockNonceReturn {
            nonce: 123,
            ..found
        },
    ] {
        assert!(committed
            .qualify(bad, work.work_generation, "worker")
            .is_none());
    }
    assert!(committed
        .qualify(
            found,
            WorkGeneration {
                session: 10,
                job: 0
            },
            "worker"
        )
        .is_none());
    owner.latch_terminal();
    assert!(committed
        .qualify(found, work.work_generation, "worker")
        .is_none());
}
