//! Canonical pool work through the exact native S15/T15 thirteen-word carrier.
//! The stock pattern oracle establishes SHA word order. Canonical header bytes
//! are converted here; the FIFO nonce word is byte-swapped exactly once when
//! producing the canonical Bitcoin nonce/Stratum submit field.
use anyhow::{ensure, Result};
use dcentrald_common::bm1391_stock_return::Bm1391StockNonceReturn;
use dcentrald_hal::platform::stock_bm1391::{Registers, Transport, Work};
use dcentrald_stratum::{
    types::{JobTemplate, ValidShare},
    work::{MiningWork, WorkBuilder},
    work_domain::WorkGeneration,
};
use std::{collections::HashSet, sync::Arc, time::Instant};

#[path = "bm1391_mining_dispatch.rs"]
mod dispatch;
pub(crate) use dispatch::WorkDispatcher;

fn header(work: &MiningWork, nonce: u32) -> [u8; 80] {
    dcentrald_stratum::v1::job::build_block_header(
        work.version,
        &work.prev_block_hash,
        &work.merkle_root,
        work.ntime,
        work.nbits,
        nonce,
    )
}

fn encode(work: &MiningWork, chain: u8, id: u16) -> Result<Work> {
    let canonical = header(work, 0);
    let midstate = dcentrald_stratum::work::compute_midstate_from_prefix(
        &canonical[..64].try_into().expect("fixed header prefix"),
    );
    // The flat carrier sends one midstate. Its first cached midstate must join
    // the same version/header metadata used to validate a returned nonce.
    ensure!(
        work.midstates.first() == Some(&midstate),
        "BM1391 pool midstate/header mismatch"
    );
    ensure!(
        work.merkle4 == canonical[64..68],
        "BM1391 pool merkle tail/header mismatch"
    );
    let state_words =
        std::array::from_fn(|i| u32::from_be_bytes(midstate[i * 4..i * 4 + 4].try_into().unwrap()));
    let tail_words = std::array::from_fn(|i| {
        u32::from_be_bytes(canonical[64 + i * 4..68 + i * 4].try_into().unwrap())
    });
    Work::from_sha256_words(chain, id, state_words, tail_words).map_err(anyhow::Error::msg)
}

/// A saved pool snapshot exists only after every selected chain's full frame
/// committed through the retained transport. Runtime generation/ID allocation,
/// startup and register/nonce FIFO dispatch remain owned by the mining loop.
pub(crate) struct CommittedWork<R: Registers> {
    transport: Arc<Transport<R>>,
    work: MiningWork,
    id: u16,
    chains: Vec<u8>,
    seen: HashSet<u32>,
}
impl<R: Registers> CommittedWork<R> {
    // Broadcast remains useful only for the independent known-header oracle.
    // Production dispatch below builds unique work for every selected chain.
    #[cfg(test)]
    pub(crate) fn publish(
        transport: Arc<Transport<R>>,
        id: u16,
        work: MiningWork,
        deadline: Instant,
    ) -> Result<Self> {
        let chains = transport.selected_chains().to_vec();
        let frames: Vec<_> = chains
            .iter()
            .map(|&chain| encode(&work, chain, id))
            .collect::<Result<_>>()?;
        for frame in frames {
            transport
                .publish_work(&frame, deadline)
                .map_err(anyhow::Error::msg)?;
        }
        ensure!(
            !transport.terminal(),
            "BM1391 work generation closed during population commit"
        );
        Ok(Self {
            transport,
            work,
            id,
            chains,
            seen: HashSet::new(),
        })
    }

    pub(crate) fn qualify(
        &mut self,
        found: Bm1391StockNonceReturn,
        active_generation: WorkGeneration,
        worker: &str,
    ) -> Option<ValidShare> {
        self.qualify_with_ticket(found, active_generation, worker).0
    }

    fn qualify_with_ticket(
        &mut self,
        found: Bm1391StockNonceReturn,
        active_generation: WorkGeneration,
        worker: &str,
    ) -> (Option<ValidShare>, bool) {
        if self.transport.terminal()
            || self.work.work_generation != active_generation
            || !found.stock_binding_eligible(true)
            || found.work_id != self.id
            || !self.chains.contains(&found.chain_slot)
            || self.seen.contains(&found.nonce)
        {
            return (None, false);
        }
        // The stock SHA helper consumes this raw word as BE bytes in the last
        // header word; Bitcoin and Stratum name the same nonce as a LE integer.
        let nonce = found.nonce.swap_bytes();
        let canonical = header(&self.work, nonce);
        let ticket = dcentrald_stratum::work::validate_full_header(
            &canonical,
            &dcentrald_stratum::work::difficulty_to_target(64.0),
        );
        let pool_share =
            dcentrald_stratum::work::validate_full_header(&canonical, &self.work.share_target);
        if !pool_share && !ticket {
            return (None, false);
        }
        self.seen.insert(found.nonce);
        if !pool_share {
            return (None, ticket);
        }
        (
            Some(ValidShare {
                work_generation: self.work.work_generation,
                worker_name: worker.into(),
                job_id: self.work.job_id.clone(),
                extranonce2: self.work.extranonce2.clone(),
                ntime: format!("{:08x}", self.work.ntime),
                nonce: format!("{nonce:08x}"),
                version_bits: dcentrald_stratum::work::bip310_version_bits(
                    self.work.version,
                    self.work.version_mask,
                ),
                version: self.work.version,
                achieved_difficulty: None,
            }),
            ticket,
        )
    }
}

/// CPU-verified difficulty64 tickets, independently of pool share difficulty.
/// Totals are run-local and survive a pool generation change. Raw FIFO counts
/// never increment these observations, and duplicate/stale work cannot refresh
/// the last verified time. Runtime may difference totals over measured time.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TicketObservation {
    pub(crate) total: u64,
    pub(crate) last: Option<Instant>,
}

/// Serialized fifteen-bit work registry. Each slot joins a complete selected
/// population commit, with a different canonical header for each chain.
/// Mutable access serializes allocation, retirement and nonce qualification.
pub(crate) struct WorkRegistry<R: Registers> {
    transport: Arc<Transport<R>>,
    generation: Option<WorkGeneration>,
    slots: Vec<Option<Vec<CommittedWork<R>>>>,
    next_id: u16,
    tickets: [TicketObservation; 3],
}
impl<R: Registers> WorkRegistry<R> {
    pub(crate) fn new(transport: Arc<Transport<R>>) -> Self {
        Self {
            transport,
            generation: None,
            slots: (0..=0x7fff).map(|_| None).collect(),
            next_id: 0,
            tickets: [TicketObservation::default(); 3],
        }
    }

    /// Call on pool generation/connection changes before dispatch or submit.
    /// Keep the ID cursor moving across generations; never restart allocation
    /// merely because a wire job ID was reused by the pool.
    pub(crate) fn activate(&mut self, generation: WorkGeneration) {
        if self.generation != Some(generation) {
            self.invalidate();
            self.generation = Some(generation);
        }
    }

    pub(crate) fn invalidate(&mut self) {
        for slot in &mut self.slots {
            *slot = None;
        }
        self.generation = None;
    }

    /// WorkBuilder consumes the subscription's shared finite extranonce2
    /// domain once per selected chain. Exhaustion or any malformed header
    /// rejects before publishing the first frame; consumed allocations are
    /// never returned to the domain. Pool generations must still be checked
    /// by the caller at dispatch and by the Stratum owner at actual submit.
    pub(crate) fn dispatch(
        &mut self,
        job: &JobTemplate,
        builder: &mut WorkBuilder,
        deadline: Instant,
    ) -> Result<u16> {
        ensure!(
            self.generation == Some(job.work_generation),
            "BM1391 pool generation is not active"
        );
        let work = self
            .transport
            .selected_chains()
            .iter()
            .map(|&chain| builder.next_work(job).map(|work| (chain, work)))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        self.dispatch_prepared(work, deadline)
    }

    fn dispatch_prepared(&mut self, work: Vec<(u8, MiningWork)>, deadline: Instant) -> Result<u16> {
        ensure!(
            Instant::now() < deadline && !self.transport.terminal(),
            "BM1391 work dispatch is closed or expired"
        );
        ensure!(
            work.iter().map(|(chain, _)| *chain).eq(self
                .transport
                .selected_chains()
                .iter()
                .copied()),
            "BM1391 work does not cover the exact retained population"
        );
        let mut headers = HashSet::new();
        let id = self.next_id;
        let mut frames = Vec::with_capacity(work.len());
        for (chain, candidate) in &work {
            ensure!(
                self.generation == Some(candidate.work_generation),
                "BM1391 prepared work belongs to another generation"
            );
            ensure!(
                headers.insert(header(candidate, 0)),
                "BM1391 selected chains would duplicate the same header work"
            );
            frames.push(encode(candidate, *chain, id)?);
        }
        // Retire this ID before its first new byte, so an old slot is never
        // authoritative during an incomplete replacement. Successful new work
        // publishes one immutable complete-population cache below.
        self.slots[usize::from(id)] = None;
        let publication = (|| {
            for frame in frames {
                self.transport
                    .publish_work(&frame, deadline)
                    .map_err(anyhow::Error::msg)?;
            }
            ensure!(
                !self.transport.terminal() && Instant::now() < deadline,
                "BM1391 work closed during population publication"
            );
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = publication {
            self.transport.latch_terminal();
            self.invalidate();
            return Err(error);
        }
        self.slots[usize::from(id)] = Some(
            work.into_iter()
                .map(|(chain, mut work)| {
                    // This wire carries one midstate. Do not retain seven unused
                    // version-rolling midstates per chain in the bounded work cache.
                    work.midstates.truncate(1);
                    CommittedWork {
                        transport: self.transport.clone(),
                        work,
                        id,
                        chains: vec![chain],
                        seen: HashSet::new(),
                    }
                })
                .collect(),
        );
        self.next_id = (id + 1) & 0x7fff;
        Ok(id)
    }

    pub(crate) fn qualify(
        &mut self,
        found: Bm1391StockNonceReturn,
        active_generation: WorkGeneration,
        worker: &str,
    ) -> Option<ValidShare> {
        if self.generation != Some(active_generation) || self.transport.terminal() {
            return None;
        }
        let (share, ticket) = self
            .slots
            .get_mut(usize::from(found.work_id))?
            .as_mut()?
            .iter_mut()
            .find(|work| work.chains == [found.chain_slot])?
            .qualify_with_ticket(found, active_generation, worker);
        if ticket {
            let observation = &mut self.tickets[usize::from(found.chain_slot)];
            let Some(total) = observation.total.checked_add(1) else {
                self.transport.latch_terminal();
                return None;
            };
            observation.total = total;
            observation.last = Some(Instant::now());
        }
        share
    }
}

#[cfg(test)]
#[path = "bm1391_mining_work_tests.rs"]
mod tests;
