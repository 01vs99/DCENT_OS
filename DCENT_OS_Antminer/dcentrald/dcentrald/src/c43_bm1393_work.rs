//! Pinned C43 raw-TW codec and generation-bound work ledger.
//! S9k cgminer SHA256 d09c482f9f5f7358f355dea427005eb9fc7db87efdd52e8dbe3f14e0f38118e7:
//! check_hw@21EDC reverses the whole stored midstate into native ARM words;
//! rev+flip_swab reconstructs the canonical twelve-byte tail. The raw FIFO
//! nonce is byte-swapped before the Bitcoin header is CPU-validated.

use anyhow::{ensure, Result};
use dcentrald_common::s9se_nonce::classify_s9se_nonce;
use dcentrald_stratum::{types::ValidShare, work::MiningWork};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Codec;

fn reverse_words<const N: usize>(bytes: [u8; N]) -> [u8; N] {
    std::array::from_fn(|i| bytes[N - 4 - (i / 4) * 4 + i % 4])
}

impl Codec {
    pub fn encode(&self, work: &MiningWork) -> Result<([u8; 12], [u8; 32])> {
        ensure!(!work.midstates.is_empty(), "C43 work has no midstate");
        let mut tail = [0; 12];
        tail[..4].copy_from_slice(&work.merkle4);
        tail[4..8].copy_from_slice(&work.ntime.to_le_bytes());
        tail[8..].copy_from_slice(&work.nbits.to_le_bytes());
        Ok((reverse_words(tail), reverse_words(work.midstates[0])))
    }
    fn nonce(&self, raw: u32) -> u32 {
        raw.swap_bytes()
    }
}

pub(super) fn header(work: &MiningWork, nonce: u32) -> [u8; 80] {
    dcentrald_stratum::v1::job::build_block_header(
        work.version,
        &work.prev_block_hash,
        &work.merkle_root,
        work.ntime,
        work.nbits,
        nonce,
    )
}

/// Two independent public-chain records: genesis and height1. Height1 was
/// retained from Blockstream's raw-header API in campaign r03; its prevhash,
/// merkle and timestamp are nonzero and distinct. Tests check exact block hashes.
#[cfg(test)]
pub(super) fn oracle_work(index: usize) -> MiningWork {
    const HEADERS: [&str; 2] = [
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
    ];
    let bytes: Vec<u8> = HEADERS[index]
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    MiningWork {
        work_generation: dcentrald_stratum::work_domain::WorkGeneration {
            session: 0,
            job: index as u64,
        },
        midstates: vec![dcentrald_stratum::work::compute_midstate_from_prefix(
            &bytes[..64].try_into().unwrap(),
        )],
        merkle4: bytes[64..68].try_into().unwrap(),
        ntime: u32::from_le_bytes(bytes[68..72].try_into().unwrap()),
        nbits: u32::from_le_bytes(bytes[72..76].try_into().unwrap()),
        job_id: format!("c43-codec-oracle-{index}"),
        extranonce2: String::new(),
        version: 1,
        version_mask: 0,
        share_target: dcentrald_stratum::work::difficulty_to_target(1.0),
        merkle_root: bytes[36..68].try_into().unwrap(),
        prev_block_hash: bytes[4..36].try_into().unwrap(),
    }
}

pub(super) struct Ledger {
    slots: Vec<Option<MiningWork>>,
    next: u16,
    seen: HashSet<(u16, u32)>,
    pub codec: Codec,
    pub tickets: u64,
    pub recent: VecDeque<Instant>,
    pub first_dispatch: Option<Instant>,
    first_offer: Option<Instant>,
    pub last_ticket: Option<Instant>,
    health_since: Option<Instant>,
    health_remaining: Duration,
    proved_headers: HashSet<[u8; 32]>,
    proof_order: VecDeque<[u8; 32]>,
}

struct PendingWork {
    id: u16,
    work: MiningWork,
    words: [u32; 13],
}

/// Eight retained frames per chain, visited round-robin. Capacity refusal
/// never consumes another work ID or discards the unsubmitted header.
pub(super) struct Feeder {
    pub ledgers: BTreeMap<u8, Ledger>,
    pending: BTreeMap<u8, VecDeque<PendingWork>>,
    offered: Vec<u8>,
}
impl Feeder {
    pub fn new(chains: &[u8]) -> Self {
        Self {
            ledgers: chains
                .iter()
                .map(|&chain| (chain, Ledger::new(Codec)))
                .collect(),
            pending: chains
                .iter()
                .map(|&chain| (chain, VecDeque::new()))
                .collect(),
            offered: Vec::new(),
        }
    }
    pub fn retain_active(&mut self, chains: &[u8]) {
        self.ledgers.retain(|chain, _| chains.contains(chain));
        self.pending.retain(|chain, _| chains.contains(chain));
    }
    pub fn invalidate(&mut self) {
        for ledger in self.ledgers.values_mut() {
            ledger.invalidate();
        }
        for queue in self.pending.values_mut() {
            queue.clear();
        }
        self.offered.clear();
    }
    pub fn pause(&mut self, now: Instant) {
        self.invalidate();
        for ledger in self.ledgers.values_mut() {
            ledger.pause_health(now);
        }
    }
    pub fn prepare(
        &mut self,
        mut next: impl FnMut() -> Result<MiningWork>,
    ) -> Result<Vec<(u8, [u32; 13])>> {
        ensure!(
            self.offered.is_empty(),
            "C43 previous batch has no completion"
        );
        for (&chain, ledger) in &mut self.ledgers {
            let queue = self
                .pending
                .get_mut(&chain)
                .expect("same active population");
            while queue.len() < 8 {
                let work = next()?;
                let (id, tail, midstate) = ledger.prepare(&work)?;
                let words = dcentrald_common::bm1393_native::encode_bm1393_work(
                    chain, id, &tail, &midstate,
                )
                .map_err(anyhow::Error::msg)?;
                queue.push_back(PendingWork { id, work, words });
            }
        }
        let mut batch = Vec::with_capacity(24);
        for slot in 0..8 {
            for (&chain, queue) in &self.pending {
                batch.push((chain, queue[slot].words));
                self.offered.push(chain);
            }
        }
        Ok(batch)
    }
    pub fn commit(&mut self, accepted: &[bool]) -> Result<()> {
        ensure!(
            accepted.len() == self.offered.len(),
            "C43 feeder reply length mismatch"
        );
        let mut blocked = HashSet::new();
        for (&chain, &accepted) in self.offered.iter().zip(accepted) {
            ensure!(
                !accepted || !blocked.contains(&chain),
                "C43 feeder reply is not a chain prefix"
            );
            if !accepted {
                blocked.insert(chain);
            }
        }
        for (chain, &accepted) in self.offered.drain(..).zip(accepted) {
            if accepted {
                let item = self
                    .pending
                    .get_mut(&chain)
                    .expect("offered active chain")
                    .pop_front()
                    .expect("bounded offered work");
                self.ledgers
                    .get_mut(&chain)
                    .expect("offered active ledger")
                    .commit(item.id, item.work);
            }
        }
        Ok(())
    }
}
impl Ledger {
    pub fn new(codec: Codec) -> Self {
        Self {
            slots: vec![None; 30000],
            next: 0,
            seen: HashSet::new(),
            codec,
            tickets: 0,
            recent: VecDeque::new(),
            first_dispatch: None,
            first_offer: None,
            last_ticket: None,
            health_since: None,
            health_remaining: Duration::from_secs(60),
            proved_headers: HashSet::new(),
            proof_order: VecDeque::new(),
        }
    }
    pub fn invalidate(&mut self) {
        self.slots.fill(None);
        self.seen.clear();
        // Header/job invalidation is not evidence of a healthy chain. Keep
        // accumulated active-work liveness and confirmed-header duplicates.
    }
    pub fn prepare(&mut self, work: &MiningWork) -> Result<(u16, [u8; 12], [u8; 32])> {
        let (tail, midstate) = self.codec.encode(work)?;
        let id = self.next;
        self.slots[usize::from(id)] = None;
        self.seen.retain(|(old, _)| *old != id);
        self.next = (self.next + 1) % 30000;
        self.offered_at(Instant::now());
        Ok((id, tail, midstate))
    }
    pub fn commit(&mut self, id: u16, work: MiningWork) {
        self.slots[usize::from(id)] = Some(work);
        self.first_dispatch.get_or_insert_with(Instant::now);
    }
    pub fn ticket_deadline_expired(&self, now: Instant) -> bool {
        self.health_since
            .is_some_and(|since| now.saturating_duration_since(since) >= self.health_remaining)
    }
    fn offered_at(&mut self, now: Instant) {
        self.first_offer.get_or_insert(now);
        self.health_since.get_or_insert(now);
    }
    fn pause_health(&mut self, now: Instant) {
        if let Some(since) = self.health_since.take() {
            self.health_remaining = self
                .health_remaining
                .saturating_sub(now.saturating_duration_since(since));
        }
    }
    pub fn validate(&mut self, chain: u8, id: u16, raw: u32, worker: &str) -> Option<ValidShare> {
        classify_s9se_nonce(chain, raw, 4).ok()?;
        let work = self.slots.get(usize::from(id))?.as_ref()?;
        let nonce = self.codec.nonce(raw);
        let header = header(work, nonce);
        let ticket = dcentrald_stratum::work::validate_full_header(
            &header,
            &dcentrald_stratum::work::difficulty_to_target(64.0),
        );
        let pool = dcentrald_stratum::work::validate_full_header(&header, &work.share_target);
        if (!ticket && !pool) || !self.seen.insert((id, raw)) {
            return None;
        }
        // Wire IDs wrap much sooner than the old feeder's IDs did. Retain a
        // bounded full-header/nonce duplicate window across those wraps and
        // pool generations; changing an ID alone cannot make old work fresh.
        let proof = dcentrald_stratum::work::double_sha256(&header);
        if !self.proved_headers.insert(proof) {
            return None;
        }
        self.proof_order.push_back(proof);
        if self.proof_order.len() > dcentrald_common::bm1393_native::BM1393_WORK_ID_SLOTS {
            let oldest = self.proof_order.pop_front().expect("bounded proof queue");
            self.proved_headers.remove(&oldest);
        }
        if ticket {
            let now = Instant::now();
            self.tickets += 1;
            self.last_ticket = Some(now);
            self.recent.push_back(now);
            self.health_since = Some(now);
            self.health_remaining = Duration::from_secs(60);
        }
        if !pool {
            return None;
        }
        Some(ValidShare {
            work_generation: work.work_generation,
            worker_name: worker.into(),
            job_id: work.job_id.clone(),
            extranonce2: work.extranonce2.clone(),
            ntime: format!("{:08x}", work.ntime),
            nonce: format!("{nonce:08x}"),
            version_bits: dcentrald_stratum::work::bip310_version_bits(
                work.version,
                work.version_mask,
            ),
            version: work.version,
            achieved_difficulty: None,
        })
    }
}

#[cfg(test)]
#[path = "c43_bm1393_feeder_tests.rs"]
mod feeder_tests;

#[cfg(test)]
mod tests {
    use super::*;
    const NONCES: [u32; 2] = [0x7c2bac1d, 0x9962e301];
    #[test]
    fn pinned_codec_matches_original_thumb_check_hw_for_two_bitcoin_headers() {
        // Executed against SHA256-pinned S9k ELF check_hw@21edd, using its
        // own sha2_starts/update for prefix state (only libc memcpy/memset
        // replaced). Both raw winners return0; nonce xor1 and reversed tail
        // return1. These constants are independent of Codec::encode.
        let vectors = [
            [
                0xffff001d, 0x29ab5f49, 0x4b1e5e4a, 0x4719f91b, 0x96b18736, 0x4f0103c8, 0xc3c8d8e9,
                0x1e59caa8, 0x90ccac7d, 0x6358bff0, 0xbc909a33,
            ],
            [
                0xffff001d, 0x61bc6649, 0x57233e0e, 0x0e7501ac, 0x5ff2646f, 0x28757b75, 0xccbd0ee0,
                0x7d617869, 0x066ca2d4, 0x7fbb2a30, 0xa9f61323,
            ],
        ];
        for (index, expected) in vectors.into_iter().enumerate() {
            let work = oracle_work(index);
            let (tail, midstate) = Codec.encode(&work).unwrap();
            let words =
                dcentrald_common::bm1393_native::encode_bm1393_work(2, 32767, &tail, &midstate)
                    .unwrap();
            assert_eq!(&words[..2], &[0x01820000, 32767]);
            assert_eq!(&words[2..], &expected);
            let raw = [0x1dac2b7c, 0x01e36299][index];
            assert_eq!(Codec.nonce(raw), NONCES[index]);
            assert!(dcentrald_stratum::work::validate_full_header(
                &header(&work, Codec.nonce(raw)),
                &work.share_target
            ));
            assert!(!dcentrald_stratum::work::validate_full_header(
                &header(&work, Codec.nonce(raw ^ 1)),
                &work.share_target
            ));
        }
    }
    #[test]
    fn c43_oracle_headers_match_two_independent_bitcoin_blocks() {
        let expected = [
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        ];
        for i in 0..2 {
            let mut hash =
                dcentrald_stratum::work::double_sha256(&header(&oracle_work(i), NONCES[i]));
            hash.reverse();
            assert_eq!(
                hash.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                expected[i]
            );
            assert!(classify_s9se_nonce(0, NONCES[i], 4).is_ok());
            assert!(classify_s9se_nonce(0, NONCES[i].swap_bytes(), 4).is_ok());
        }
    }
    #[test]
    fn c43_pool_work_full_id_duplicate_generation_and_failed_write() {
        let mut ledger = Ledger::new(Codec);
        ledger.next = 0x1234;
        let work = oracle_work(0);
        let (id, _, _) = ledger.prepare(&work).unwrap();
        ledger.commit(id, work.clone());
        let share = ledger
            .validate(2, id, NONCES[0].swap_bytes(), "tester.c43")
            .unwrap();
        assert_eq!(share.nonce, "7c2bac1d");
        assert_eq!(share.worker_name, "tester.c43");
        assert!(ledger
            .validate(2, id, NONCES[0].swap_bytes(), "tester")
            .is_none());
        ledger.invalidate();
        assert!(ledger
            .validate(2, id, NONCES[0].swap_bytes(), "tester")
            .is_none());
        ledger.next = id;
        ledger.prepare(&work).unwrap();
        assert!(ledger
            .validate(2, id, NONCES[0].swap_bytes(), "tester")
            .is_none());
        assert!(ledger
            .validate(2, 30000, NONCES[0].swap_bytes(), "tester")
            .is_none());
    }
}
