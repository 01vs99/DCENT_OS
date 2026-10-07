//! Lifetime job and return custody for the qualified fixed-EN2 candidate.
//! This draft requires the sealed HAL publication/return owner getters before
//! registration. It grants no native startup or FPGA qualification itself.
use crate::bm1396_mining_work::PreparedJob;
use anyhow::{ensure, Context, Result};
use dcentrald_hal::platform::stock_bm1396::{
    Hardware, JobPublication, Model, PreservedReturn, ReturnPayload, Transport,
};
use dcentrald_stratum::{types::ValidShare, work_domain::WorkGeneration};
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};
use tokio::sync::mpsc;

const JOB_LIMIT: usize = 4096;
const CUSTODY_BYTES: usize = 8 * 1024 * 1024;
const RETURN_LIMIT: usize = 65_536;
const OUTBOX_LIMIT: usize = 128;
// Independently bound metadata replicated into each share, regardless of the
// V1 consumer's configured line limit. 128 queued payloads retain at most
// 128*(1024+256+16+8+8)=167936 string bytes, plus fixed object allocations.
const POOL_JOB_ID_BYTES: usize = 1024;
const EXTRANONCE2_HEX_BYTES: usize = 16;

struct IssuedJob {
    prepared: Arc<PreparedJob>,
    publication: Option<JobPublication>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReturnDisposition {
    Probe,
    Duplicate,
    BelowPoolTarget,
    RetiredGeneration,
    ShareQueued,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ShareDisposition {
    Queued,
    OfferedToStratum,
    RetiredGeneration,
}

/// One retained CPU-qualified return. Pool acceptance is owned by the actual
/// Stratum result stream, not this local queue or a successful channel send.
pub(super) struct ReturnCustody {
    pub(super) raw: PreservedReturn,
    pub(super) job_id: u32,
    pub(super) hash_be: [u8; 32],
    pub(super) disposition: ReturnDisposition,
    pub(super) share_disposition: Option<ShareDisposition>,
}

pub(super) struct WorkRegistry<H: Hardware> {
    owner: Arc<Transport<H>>,
    jobs: Vec<IssuedJob>,
    charged_bytes: usize,
    active: Option<WorkGeneration>,
    seen_pool: HashSet<(u32, u32)>,
    pool_templates: HashSet<[u8; 80]>,
    probes: HashSet<(u32, u8)>,
    returns: Vec<ReturnCustody>,
    outbox: VecDeque<(usize, ValidShare)>,
    worker: String,
}

impl<H: Hardware> WorkRegistry<H> {
    pub(super) fn new(owner: Arc<Transport<H>>, worker: String) -> Result<Self> {
        ensure!(
            !owner.chains().is_empty() && !owner.is_terminal(),
            "BM1396 fixed-domain registry requires a live exact BM1396 owner"
        );
        ensure!(
            !worker.is_empty() && worker.len() <= 256,
            "BM1396 worker identity outside bounded registry"
        );
        Ok(Self {
            owner,
            jobs: Vec::new(),
            charged_bytes: 0,
            active: None,
            seen_pool: HashSet::new(),
            pool_templates: HashSet::new(),
            probes: HashSet::new(),
            returns: Vec::new(),
            outbox: VecDeque::new(),
            worker,
        })
    }

    pub(super) fn model(&self) -> Model {
        self.owner.model()
    }

    pub(super) fn epoch(&self) -> u64 {
        match self.owner.model() {
            Model::S17e => 0,
            Model::T17e => 1,
        }
    }

    pub(super) fn next_id(&self) -> Result<u32> {
        ensure!(!self.owner.is_terminal(), "BM1396 registry is terminal");
        ensure!(
            self.jobs.len() < JOB_LIMIT,
            "BM1396 lifetime 4096-job custody exhausted"
        );
        Ok(self.jobs.len() as u32)
    }

    pub(super) fn set_active_generation(&mut self, generation: Option<WorkGeneration>) {
        self.active = generation;
    }

    /// Read only actual CPU-qualified observations already retained here. This
    /// supports ordered probe0/probe1 publication without a second proof set.
    pub(super) fn probe_complete(&self, id: u32) -> bool {
        id < 2
            && self
                .owner
                .chains()
                .iter()
                .all(|&chain| self.probes.contains(&(id, chain)))
    }

    pub(super) fn probes_complete(&self) -> bool {
        self.owner
            .chains()
            .iter()
            .all(|&chain| self.probes.contains(&(0, chain)) && self.probes.contains(&(1, chain)))
    }

    /// Retain complete immutable metadata BEFORE actual publication. The caller
    /// publishes this Arc's exact packet without holding the registry mutex,
    /// then joins its completed receipt. IDs and allocations are never reused.
    pub(super) fn retain_issued(&mut self, job: PreparedJob) -> Result<Arc<PreparedJob>> {
        ensure!(
            job.id() == self.next_id()?,
            "BM1396 issued ID skipped or reused"
        );
        if let Some(work) = job.pool() {
            ensure!(
                !work.job_id.is_empty()
                    && work.job_id.len() <= POOL_JOB_ID_BYTES
                    && !work.extranonce2.is_empty()
                    && work.extranonce2.len() <= EXTRANONCE2_HEX_BYTES
                    && work.extranonce2.len() % 2 == 0
                    && work
                        .extranonce2
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit()),
                "BM1396 pool share metadata exceeds local bounded ID/EN2 contract"
            );
            ensure!(
                self.probes_complete(),
                "BM1396 pool work precedes every chain's two actual probes"
            );
            ensure!(
                self.active == Some(work.work_generation),
                "BM1396 issued pool generation is not current"
            );
            let mut template = *job.header();
            template[76..80].fill(0);
            ensure!(
                !self.pool_templates.contains(&template),
                "BM1396 pool attempted to reuse an immutable full work template"
            );
        } else {
            ensure!(job.id() < 2, "BM1396 probe IDs are exactly zero and one");
            if job.id() == 1 {
                ensure!(
                    job.header() != self.jobs[0].prepared.header(),
                    "BM1396 physical probes require two distinct retained headers"
                );
            }
        }
        let metadata = job.pool().map_or(0, |work| {
            work.job_id.capacity() + work.extranonce2.capacity() + work.midstates.capacity() * 32
        });
        // Charge both the retained packet and HAL's publication copy, plus
        // metadata and a fixed per-entry allocation allowance. This bounded
        // candidate cannot accumulate 4096 maximum-size packets on a miner.
        let charge = job
            .packet()
            .len()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(metadata + std::mem::size_of::<PreparedJob>() + 128)
            })
            .context("BM1396 job custody charge overflow")?;
        let total = self
            .charged_bytes
            .checked_add(charge)
            .context("BM1396 custody charge overflow")?;
        ensure!(
            total <= CUSTODY_BYTES,
            "BM1396 retained job custody byte budget exhausted"
        );
        if job.pool().is_some() {
            let mut template = *job.header();
            template[76..80].fill(0);
            self.pool_templates.insert(template);
        }
        let prepared = Arc::new(job);
        self.jobs.push(IssuedJob {
            prepared: prepared.clone(),
            publication: None,
        });
        self.charged_bytes = total;
        Ok(prepared)
    }

    pub(super) fn join_publication(&mut self, publication: &JobPublication) -> Result<()> {
        // Getter is produced only by the actual retained HAL writer. No daemon
        // constructor can synthesize its owner seal or completed state.
        ensure!(
            publication.same_owner(&self.owner) && publication.completed(),
            "BM1396 publication is foreign or incomplete"
        );
        let slot = self
            .jobs
            .get_mut(publication.job_id() as usize)
            .context("BM1396 publication has no retained issued job")?;
        ensure!(
            slot.prepared.id() == publication.job_id()
                && slot.prepared.packet() == publication.packet()
                && publication.sequence() == u64::from(publication.job_id()) + 1,
            "BM1396 publication differs from immutable issued packet"
        );
        if let Some(previous) = &slot.publication {
            ensure!(previous == publication, "BM1396 issued publication changed");
        } else {
            slot.publication = Some(publication.clone());
        }
        Ok(())
    }

    /// The caller acknowledges the HAL return only after this method retains
    /// its CPU-qualified result and any bounded share. An error leaves raw HAL
    /// custody intact and requires terminal closeout by the runtime owner.
    pub(super) fn qualify_return(&mut self, raw: &PreservedReturn) -> Result<ReturnDisposition> {
        ensure!(
            !self.owner.is_terminal() && raw.same_owner(&self.owner),
            "BM1396 return is terminal or foreign"
        );
        ensure!(
            self.returns.len() < RETURN_LIMIT,
            "BM1396 lifetime return custody exhausted"
        );
        let ReturnPayload::Nonce { nonce, outstanding } = raw.payload() else {
            anyhow::bail!("BM1396 work registry requires a classified nonce");
        };
        ensure!(
            self.owner.chains().contains(&nonce.chain_slot),
            "BM1396 nonce chain is not retained"
        );
        ensure!(
            nonce.work_id == outstanding.work_id(),
            "BM1396 return/table work ID differs"
        );
        let table = outstanding.decoded();
        ensure!(
            table.job_id == outstanding.publication().job_id(),
            "BM1396 table/publication ID differs"
        );
        // A worker may complete before its async waiter resumes. The return's
        // own sealed completed publication joins the same pre-retained job.
        self.join_publication(outstanding.publication())?;
        let issued = &self.jobs[table.job_id as usize].prepared;
        let qualified =
            issued.qualify_header(nonce.nonce, table.nonce2, table.version_word_wire)?;
        let mut share = None;
        let disposition = if let Some(work) = issued.pool() {
            if self.seen_pool.contains(&(table.job_id, nonce.nonce)) {
                ReturnDisposition::Duplicate
            } else if self.active != Some(work.work_generation) {
                ReturnDisposition::RetiredGeneration
            } else if !qualified.meets_pool_target {
                ReturnDisposition::BelowPoolTarget
            } else {
                ensure!(
                    self.outbox.len() < OUTBOX_LIMIT,
                    "BM1396 retained share outbox full"
                );
                share = Some(ValidShare {
                    work_generation: work.work_generation,
                    worker_name: self.worker.clone(),
                    job_id: work.job_id.clone(),
                    extranonce2: work.extranonce2.clone(),
                    ntime: format!("{:08x}", work.ntime),
                    nonce: format!("{:08x}", qualified.canonical_nonce),
                    version_bits: None,
                    version: work.version,
                    achieved_difficulty: None,
                });
                ReturnDisposition::ShareQueued
            }
        } else if self.probes.insert((table.job_id, nonce.chain_slot)) {
            ReturnDisposition::Probe
        } else {
            ReturnDisposition::Duplicate
        };
        if issued.pool().is_some() {
            self.seen_pool.insert((table.job_id, nonce.nonce));
        }
        let index = self.returns.len();
        self.returns.push(ReturnCustody {
            raw: raw.clone(),
            job_id: table.job_id,
            hash_be: qualified.header_hash_be,
            disposition,
            share_disposition: share.as_ref().map(|_| ShareDisposition::Queued),
        });
        if let Some(share) = share {
            self.outbox.push_back((index, share));
        }
        Ok(disposition)
    }

    /// Retain queue entries on backpressure or closed-channel error. The actual
    /// V1 owner checks WorkGeneration again immediately before its socket write.
    pub(super) fn offer_head(&mut self, sender: &mpsc::Sender<ValidShare>) -> Result<bool> {
        ensure!(!self.owner.is_terminal(), "BM1396 submit gate is terminal");
        let Some((index, share)) = self.outbox.front() else {
            return Ok(false);
        };
        let index = *index;
        if self.active != Some(share.work_generation) {
            self.returns[index].share_disposition = Some(ShareDisposition::RetiredGeneration);
            self.outbox.pop_front();
            return Ok(true);
        }
        match sender.try_reserve() {
            Ok(permit) => {
                // The synchronous reservation proves channel capacity before
                // removing custody. Move the existing strings; Full and Closed
                // neither allocate a clone nor remove the queued payload.
                let (_, share) = self.outbox.pop_front().expect("retained reserved head");
                permit.send(share);
                self.returns[index].share_disposition = Some(ShareDisposition::OfferedToStratum);
                Ok(true)
            }
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                anyhow::bail!("BM1396 Stratum share owner closed")
            }
        }
    }

    pub(super) fn retained_returns(&self) -> &[ReturnCustody] {
        &self.returns
    }
    pub(super) fn lifetime_jobs(&self) -> usize {
        self.jobs.len()
    }
    pub(super) fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }
}

#[cfg(test)]
#[path = "bm1396_mining_registry_tests.rs"]
mod tests;
