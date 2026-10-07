//! Exact classic BM1362 full-header work/nonce ownership. Physical UART I/O
//! remains in the runtime; metadata becomes valid only after that write succeeds.
use super::*;
use dcentrald_stratum::work::MiningWork;
use std::collections::{BTreeMap, HashSet, VecDeque};

struct Entry {
    work: MiningWork,
    header_key: [u8; 80],
    seen: HashSet<(u32, u32)>,
}
struct Chain {
    next_id: u8,
    pending: Option<u8>,
    entries: BTreeMap<u8, Entry>,
    tickets: u64,
    recent: VecDeque<Instant>,
    first_dispatch: Option<Instant>,
    last_ticket: Option<Instant>,
}
pub(super) struct PreparedWork {
    issuer: Arc<()>,
    epoch: u64,
    slot: u8,
    id: u8,
    work: MiningWork,
    header_key: [u8; 80],
    frame: Vec<u8>,
}
impl PreparedWork {
    pub(super) fn frame(&self) -> &[u8] {
        &self.frame
    }
}
pub(super) struct Ledger {
    issuer: Arc<()>,
    epoch: u64,
    generation: Option<dcentrald_stratum::WorkGeneration>,
    chains: BTreeMap<u8, Chain>,
    headers: HashSet<[u8; 80]>,
    ticket_target: [u8; 32],
}
pub(super) struct VerifiedNonce {
    pub(super) share: Option<dcentrald_stratum::types::ValidShare>,
}
impl Ledger {
    pub(super) fn new(slots: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            !slots.is_empty() && slots.len() <= 3 && slots.iter().all(|s| *s < 3),
            "classic work needs1..3 exact physical slots"
        );
        let mut chains = BTreeMap::new();
        for &slot in slots {
            anyhow::ensure!(
                chains
                    .insert(
                        slot,
                        Chain {
                            next_id: 0,
                            pending: None,
                            entries: BTreeMap::new(),
                            tickets: 0,
                            recent: VecDeque::new(),
                            first_dispatch: None,
                            last_ticket: None
                        }
                    )
                    .is_none(),
                "classic duplicate physical work slot"
            );
        }
        Ok(Self {
            issuer: Arc::new(()),
            epoch: 0,
            generation: None,
            chains,
            headers: HashSet::new(),
            ticket_target: dcentrald_stratum::work::difficulty_to_target(256.0),
        })
    }
    pub(super) fn invalidate(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.generation = None;
        self.headers.clear();
        for chain in self.chains.values_mut() {
            chain.entries.clear();
            chain.pending = None;
            // Pool job changes must not restart the hardware liveness clock:
            // frequent clean jobs cannot hide a chain that returns no tickets.
        }
    }
    pub(super) fn select_generation(&mut self, generation: dcentrald_stratum::WorkGeneration) {
        self.invalidate();
        self.generation = Some(generation);
    }
    pub(super) fn prepare(&mut self, slot: u8, work: MiningWork) -> Result<PreparedWork> {
        anyhow::ensure!(
            self.generation == Some(work.work_generation),
            "classic work belongs to another pool generation"
        );
        let chain = self
            .chains
            .get_mut(&slot)
            .context("classic work slot is not selected")?;
        anyhow::ensure!(
            chain.pending.is_none(),
            "classic physical write still pending"
        );
        let id = chain.next_id;
        chain.next_id = (id + 24) & 0x7f;
        // Retire this hardware ID before I/O. A failed overwrite can never
        // authorize a new nonce through old cached metadata for that ID.
        if let Some(old) = chain.entries.remove(&id) {
            self.headers.remove(&old.header_key);
        }
        let header_key = dcentrald_stratum::v1::job::build_block_header(
            work.version,
            &work.prev_block_hash,
            &work.merkle_root,
            work.ntime,
            work.nbits,
            0,
        );
        anyhow::ensure!(
            self.headers.insert(header_key),
            "classic chains require independent, unrepeated Bitcoin headers"
        );
        chain.pending = Some(id);
        let frame = serial_full_header_work(
            id,
            work.version,
            work.nbits,
            work.ntime,
            &work.merkle_root,
            &work.prev_block_hash,
        );
        Ok(PreparedWork {
            issuer: self.issuer.clone(),
            epoch: self.epoch,
            slot,
            id,
            work,
            header_key,
            frame,
        })
    }
    pub(super) fn commit(&mut self, prepared: PreparedWork) -> Result<()> {
        anyhow::ensure!(
            Arc::ptr_eq(&self.issuer, &prepared.issuer)
                && self.epoch == prepared.epoch
                && self.generation == Some(prepared.work.work_generation),
            "classic physical completion belongs to another work owner/epoch"
        );
        let chain = self
            .chains
            .get_mut(&prepared.slot)
            .context("classic completion slot missing")?;
        anyhow::ensure!(
            chain.pending == Some(prepared.id),
            "classic physical completion was superseded"
        );
        chain.pending = None;
        chain.first_dispatch.get_or_insert_with(Instant::now);
        chain.entries.insert(
            prepared.id,
            Entry {
                work: prepared.work,
                header_key: prepared.header_key,
                seen: HashSet::new(),
            },
        );
        Ok(())
    }
    pub(super) fn validate(
        &mut self,
        slot: u8,
        body: &[u8],
        worker: &str,
    ) -> Result<Option<VerifiedNonce>> {
        if body.len() != 9 || dcentrald_asic::protocol::crc5(body) != 0 {
            return Ok(None);
        }
        let mut raw = [0u8; 11];
        raw[..2].copy_from_slice(&[0xaa, 0x55]);
        raw[2..].copy_from_slice(body);
        let parsed = dcentrald_asic::bm1362::parse_bm1362_serial_nonce(&raw)
            .context("classic exact nonce parser rejected admitted shape")?;
        if parsed.flags & 0x80 == 0 || parsed.midstate_idx != 0 {
            return Ok(None);
        }
        let chain = self
            .chains
            .get_mut(&slot)
            .context("classic nonce arrived from an unselected physical UART")?;
        let Some(entry) = chain.entries.get_mut(&parsed.job_id) else {
            return Ok(None);
        };
        if self.generation != Some(entry.work.work_generation) {
            return Ok(None);
        }
        let meta = WorkEntry {
            generation: self.epoch,
            work_generation: entry.work.work_generation,
            job_id: entry.work.job_id.clone(),
            extranonce2: entry.work.extranonce2.clone(),
            ntime: entry.work.ntime,
            nbits: entry.work.nbits,
            version: entry.work.version,
            version_mask: entry.work.version_mask,
            share_target: entry.work.share_target,
            prev_block_hash: entry.work.prev_block_hash,
            merkle_root: entry.work.merkle_root,
        };
        let (version, _) = dcentrald_asic::bm1362::bip320_reconstruct_rolled_version(
            entry.work.version,
            parsed.version_bits_raw,
        );
        // The response is the complete rolled field, not an XOR delta. Pool
        // authorization must account for cleared base bits as well as set
        // bits. A hardware-valid ticket still proves liveness when its version
        // cannot be expressed by this pool's narrower negotiated mask.
        // With no negotiated mask the V1 encoder omits the version field,
        // so the pool can reconstruct only its original job version.
        let pool_version_admitted =
            ((version ^ entry.work.version) & !entry.work.version_mask) == 0;
        let header = serial_build_header(&meta, version, parsed.nonce);
        // A valid CRC and an occupied ID are insufficient mining liveness.
        if !dcentrald_stratum::share_pipeline::validate_full_header(&header, &self.ticket_target) {
            return Ok(None);
        }
        anyhow::ensure!(
            entry.seen.len() < 1024,
            "classic ticket dedup capacity exceeded"
        );
        if !entry.seen.insert((parsed.nonce, version)) {
            return Ok(None);
        }
        let now = Instant::now();
        chain.tickets = chain.tickets.saturating_add(1);
        chain.last_ticket = Some(now);
        chain.recent.push_back(now);
        let share = if pool_version_admitted
            && dcentrald_stratum::share_pipeline::validate_full_header(
                &header,
                &entry.work.share_target,
            ) {
            Some(dcentrald_stratum::types::ValidShare {
                work_generation: entry.work.work_generation,
                worker_name: worker.into(),
                job_id: entry.work.job_id.clone(),
                extranonce2: entry.work.extranonce2.clone(),
                ntime: format!("{:08x}", entry.work.ntime),
                nonce: format!("{:08x}", parsed.nonce),
                version_bits: dcentrald_stratum::work::bip310_version_bits(
                    version,
                    entry.work.version_mask,
                ),
                version,
                achieved_difficulty: serial_achieved_difficulty_from_header(&header),
            })
        } else {
            None
        };
        Ok(Some(VerifiedNonce { share }))
    }
    pub(super) fn hashrates(&mut self, slot: u8, elapsed: Duration) -> (f64, f64) {
        let chain = self
            .chains
            .get_mut(&slot)
            .expect("selected classic work slot");
        while chain
            .recent
            .front()
            .is_some_and(|at| at.elapsed() > Duration::from_secs(5))
        {
            chain.recent.pop_front();
        }
        let seconds = elapsed.as_secs_f64().max(1.0);
        (
            chain.tickets as f64 * 256.0 * 4.294967296 / seconds,
            chain.recent.len() as f64 * 256.0 * 4.294967296 / seconds.min(5.0),
        )
    }
    pub(super) fn require_liveness(&self) -> Result<()> {
        for (&slot, chain) in &self.chains {
            if let Some(last) = chain.last_ticket.or(chain.first_dispatch) {
                anyhow::ensure!(
                    last.elapsed() < Duration::from_secs(60),
                    "classic slot{slot} has no independently verified ticket for60s"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn genesis() -> MiningWork {
        let merkle = [
            0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76,
            0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa,
            0x4b, 0x1e, 0x5e, 0x4a,
        ];
        MiningWork {
            work_generation: dcentrald_stratum::WorkGeneration { session: 1, job: 1 },
            midstates: vec![],
            merkle4: merkle[28..].try_into().unwrap(),
            ntime: 1231006505,
            nbits: 0x1d00ffff,
            job_id: "classic-genesis".into(),
            extranonce2: "00000000".into(),
            version: 1,
            version_mask: 0,
            share_target: dcentrald_stratum::work::difficulty_to_target(1.0),
            merkle_root: merkle,
            prev_block_hash: [0; 32],
        }
    }
    fn response(id: u8, nonce: u32) -> [u8; 9] {
        let mut b = [0u8; 9];
        b[..4].copy_from_slice(&nonce.to_le_bytes());
        b[5] = id << 1;
        b[8] = (0..32)
            .map(|c| 0x80 | c)
            .find(|&flag| {
                b[8] = flag;
                dcentrald_asic::protocol::crc5(&b) == 0
            })
            .unwrap();
        b
    }
    #[test]
    fn chip_rolled_version_is_verified_against_the_canonical_header_and_negotiated_mask() {
        // The transmitted base differs from Genesis inside BIP320. A returned
        // zero rolling field reconstructs the independently known Genesis
        // header, rather than hashing the cached base version unchanged.
        for (base, mask, can_submit) in [
            (0x2001, 0, false),
            (1, 0, true),
            (0x2001, 0x2000, true),
            (0x2001, 0x4000, false),
        ] {
            let mut work = genesis();
            work.version = base;
            work.version_mask = mask;
            let mut ledger = Ledger::new(&[1]).unwrap();
            ledger.select_generation(work.work_generation);
            let prepared = ledger.prepare(1, work).unwrap();
            ledger.commit(prepared).unwrap();
            let validated = ledger
                .validate(1, &response(0, 2083236893), "worker.classic")
                .unwrap();
            if !can_submit {
                assert!(
                    validated.unwrap().share.is_none(),
                    "negotiated mask cannot authorize a different changed bit"
                );
                assert_eq!(ledger.chains[&1].tickets, 1,
                    "independently valid hardware ticket remains liveness even with an unsubmitable pool version");
            } else {
                let share = validated.unwrap().share.unwrap();
                assert_eq!(share.version, 1);
                assert_eq!(share.nonce, "7c2bac1d");
                assert_eq!(
                    share.version_bits,
                    if mask == 0 {
                        None
                    } else {
                        Some("00000000".into())
                    }
                );
                let request = dcentrald_stratum::v1::messages::submit_request(
                    1,
                    &share.worker_name,
                    &share.job_id,
                    &share.extranonce2,
                    &share.ntime,
                    &share.nonce,
                    share.version_bits.as_deref(),
                );
                let wire = serde_json::to_string(&request).unwrap();
                let wire: serde_json::Value = serde_json::from_str(&wire).unwrap();
                let params = wire["params"].as_array().unwrap();
                assert_eq!(params.len(), if mask == 0 { 5 } else { 6 });
                let reconstructed_version = if mask == 0 {
                    base
                } else {
                    (base & !mask)
                        | (u32::from_str_radix(params[5].as_str().unwrap(), 16).unwrap() & mask)
                };
                assert_eq!(
                    reconstructed_version, share.version,
                    "actual V1 wire fields must reconstruct the CPU-validated version"
                );
            }
        }
    }
    #[test]
    fn canonical_genesis_work_receipt_and_nonce_reconstruct_an_independent_valid_share() {
        let mut ledger = Ledger::new(&[0, 2]).unwrap();
        let work = genesis();
        ledger.select_generation(work.work_generation);
        let prepared = ledger.prepare(2, work).unwrap();
        assert_eq!(prepared.frame().len(), 84);
        assert_eq!(&prepared.frame()[..4], &[0x21, 0x56, 0, 1]);
        assert_eq!(
            &prepared.frame()[8..16],
            &[0xff, 0xff, 0, 0x1d, 0x29, 0xab, 0x5f, 0x49]
        );
        let nonce = response(0, 2083236893);
        assert!(ledger
            .validate(2, &nonce, "worker.classic")
            .unwrap()
            .is_none());
        ledger.commit(prepared).unwrap();
        let share = ledger
            .validate(2, &nonce, "worker.classic")
            .unwrap()
            .unwrap()
            .share
            .unwrap();
        assert_eq!(share.job_id, "classic-genesis");
        assert_eq!(share.nonce, "7c2bac1d");
        assert_eq!(share.ntime, "495fab29");
        assert_eq!(share.version, 1);
        assert!(ledger
            .validate(2, &nonce, "worker.classic")
            .unwrap()
            .is_none());
        assert!(ledger
            .validate(0, &nonce, "worker.classic")
            .unwrap()
            .is_none());
        ledger.invalidate();
        assert!(ledger
            .validate(2, &nonce, "worker.classic")
            .unwrap()
            .is_none());
    }
    #[test]
    fn work_cannot_cross_population_generation_owner_or_duplicate_another_chain_header() {
        assert!(Ledger::new(&[0, 0]).is_err());
        assert!(Ledger::new(&[3]).is_err());
        let work = genesis();
        let mut ledger = Ledger::new(&[0, 2]).unwrap();
        ledger.select_generation(work.work_generation);
        assert!(ledger.prepare(1, work.clone()).is_err());
        let first = ledger.prepare(0, work.clone()).unwrap();
        assert!(ledger.prepare(2, work.clone()).is_err());
        let mut other = Ledger::new(&[0, 2]).unwrap();
        other.select_generation(work.work_generation);
        assert!(other.commit(first).is_err());
        ledger.invalidate();
        assert!(ledger.prepare(0, work.clone()).is_err());
        ledger.select_generation(work.work_generation);
        let pending = ledger.prepare(0, work).unwrap();
        ledger.invalidate();
        assert!(ledger.commit(pending).is_err());
    }
    #[test]
    fn invalid_crc_flags_midstate_and_nonwinning_nonce_never_feed_ticket_liveness() {
        let work = genesis();
        let mut ledger = Ledger::new(&[0]).unwrap();
        ledger.select_generation(work.work_generation);
        let p = ledger.prepare(0, work).unwrap();
        ledger.commit(p).unwrap();
        for case in 0..4 {
            let mut body = response(0, if case == 3 { 0 } else { 2083236893 });
            match case {
                0 => body[8] ^= 1,
                1 => body[8] &= 0x7f,
                2 => body[4] = 1,
                _ => {}
            };
            if matches!(case, 1 | 2) {
                let flags = body[8] & 0xe0;
                body[8] = (0..32)
                    .map(|crc| flags | crc)
                    .find(|&candidate| {
                        body[8] = candidate;
                        dcentrald_asic::protocol::crc5(&body) == 0
                    })
                    .unwrap();
            }
            assert!(ledger.validate(0, &body, "worker").unwrap().is_none());
        }
        assert_eq!(ledger.hashrates(0, Duration::from_secs(1)), (0.0, 0.0));
    }

    #[test]
    fn frequent_pool_generations_cannot_reset_missing_hardware_ticket_deadline() {
        let work = genesis();
        let mut ledger = Ledger::new(&[0]).unwrap();
        ledger.select_generation(work.work_generation);
        let prepared = ledger.prepare(0, work.clone()).unwrap();
        ledger.commit(prepared).unwrap();
        ledger.chains.get_mut(&0).unwrap().first_dispatch =
            Some(Instant::now() - Duration::from_secs(61));
        for job in 2..10 {
            let generation = dcentrald_stratum::WorkGeneration { session: 1, job };
            ledger.select_generation(generation);
            let mut next = work.clone();
            next.work_generation = generation;
            let prepared = ledger.prepare(0, next).unwrap();
            ledger.commit(prepared).unwrap();
            assert!(ledger.require_liveness().is_err());
        }
    }
}
