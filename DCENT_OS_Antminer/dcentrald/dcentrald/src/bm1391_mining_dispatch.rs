//! Serialized pool-job, FIFO and bounded share-outbox custody for native BM1391.
//! Runtime owns this dispatcher alongside its thermal service; no other normal
//! FIFO reader or work producer may operate concurrently. Thermal returns use
//! the same registry via offer_preserved, then the caller acknowledges only the
//! returned sequence in the retained thermal service.
use super::*;
use dcentrald_common::bm1391_stock_return::Bm1391StockFpgaReturn;
use dcentrald_hal::platform::stock_bm1391::PreservedThermalNonce;
use std::collections::VecDeque;
use tokio::sync::mpsc::{error::TrySendError, Sender};

const MAX_OUTBOX: usize = 128;
const MAX_FIFO_BATCH: usize = 128;

pub(crate) struct WorkDispatcher<R: Registers> {
    pub(super) registry: WorkRegistry<R>,
    builder: WorkBuilder,
    job: Option<JobTemplate>,
    newest: Option<WorkGeneration>,
    outbox: VecDeque<ValidShare>,
    last_thermal_sequence: u64,
    worker: String,
    pool_active: bool,
}
impl<R: Registers> WorkDispatcher<R> {
    pub(crate) fn ticket_observations(&self) -> [TicketObservation; 3] {
        self.registry.tickets
    }

    pub(crate) fn new(transport: Arc<Transport<R>>, worker: String) -> Self {
        Self {
            registry: WorkRegistry::new(transport),
            builder: WorkBuilder::new(),
            job: None,
            newest: None,
            outbox: VecDeque::new(),
            last_thermal_sequence: 0,
            worker,
            pool_active: false,
        }
    }

    /// A session/clean transition invalidates saved work and queued old shares.
    /// The finite subscription allocator still owns extranonce uniqueness.
    pub(crate) fn accept_job(&mut self, job: JobTemplate) -> Result<()> {
        let generation = job.work_generation;
        ensure!(
            generation != WorkGeneration::UNTRACKED,
            "BM1391 job has no pool generation"
        );
        if let Some(previous) = self.newest {
            ensure!(
                (generation.session, generation.job) >= (previous.session, previous.job),
                "BM1391 delayed job would rewind the pool generation"
            );
        }
        self.newest = Some(generation);
        if job.is_flush_only() {
            self.disconnect();
            return Ok(());
        }
        if self.registry.generation != Some(generation) || job.clean_jobs {
            self.registry.invalidate();
            self.outbox.clear();
        }
        self.builder.set_version_mask(job.version_mask);
        self.registry.activate(generation);
        self.job = Some(job);
        Ok(())
    }
    pub(crate) fn disconnect(&mut self) {
        self.pool_active = false;
        self.job = None;
        self.registry.invalidate();
        self.outbox.clear();
    }

    /// Status and jobs arrive on separate queues. An accepted generation may
    /// be queued before a newer disconnect; it cannot grant work by itself.
    pub(crate) fn observe_pool_state(&mut self, state: dcentrald_stratum::types::StratumState) {
        self.pool_active = matches!(
            state,
            dcentrald_stratum::types::StratumState::Mining
                | dcentrald_stratum::types::StratumState::Donating
        );
        if !self.pool_active {
            self.disconnect();
        }
    }

    /// Full queues retain the exact share at the front; no nonce is re-read
    /// and no duplicate qualification is needed when the receiver catches up.
    pub(crate) fn flush_shares(&mut self, output: &Sender<ValidShare>) -> Result<bool> {
        while let Some(share) = self.outbox.pop_front() {
            if Some(share.work_generation) != self.registry.generation {
                continue;
            }
            match output.try_send(share) {
                Ok(()) => (),
                Err(TrySendError::Full(share)) => {
                    self.outbox.push_front(share);
                    return Ok(false);
                }
                Err(TrySendError::Closed(share)) => {
                    self.outbox.push_front(share);
                    self.registry.transport.latch_terminal();
                    anyhow::bail!("BM1391 share actor closed with a retained unsent share");
                }
            }
        }
        Ok(true)
    }
    fn offer(&mut self, nonce: Bm1391StockNonceReturn) {
        if let Some(generation) = self.registry.generation {
            if let Some(share) = self.registry.qualify(nonce, generation, &self.worker) {
                self.outbox.push_back(share);
            }
        }
    }

    /// Stop before consuming another FIFO record when the outbox is full.
    /// Register replies are counted separately; runtime must have finished all
    /// register/census operations or hand the ASIC lane to its thermal service.
    pub(crate) fn drain_fifo(&mut self, deadline: Instant) -> Result<(usize, usize)> {
        let (mut nonces, mut registers) = (0, 0);
        for _ in 0..MAX_FIFO_BATCH {
            if self.outbox.len() == MAX_OUTBOX {
                break;
            }
            match self
                .registry
                .transport
                .read_return(deadline)
                .map_err(anyhow::Error::msg)?
            {
                None => break,
                Some(Bm1391StockFpgaReturn::Nonce(nonce)) => {
                    self.offer(nonce);
                    nonces += 1;
                }
                Some(Bm1391StockFpgaReturn::Register(_)) => registers += 1,
            }
        }
        Ok((nonces, registers))
    }

    /// Consume a retained thermal snapshot in order, keeping accepted shares
    /// locally before authorizing acknowledgment. Repeated snapshots are safe.
    /// Caller must supply only this runtime's one retained thermal service.
    pub(crate) fn offer_preserved(
        &mut self,
        pending: &[PreservedThermalNonce],
    ) -> Result<Option<u64>> {
        let mut through = None;
        for saved in pending {
            if saved.sequence <= self.last_thermal_sequence {
                through = Some(saved.sequence);
                continue;
            }
            if self.outbox.len() == MAX_OUTBOX {
                break;
            }
            if self.last_thermal_sequence.checked_add(1) != Some(saved.sequence) {
                self.registry.transport.latch_terminal();
                anyhow::bail!("BM1391 thermal nonce custody has a sequence gap");
            }
            self.offer(saved.record);
            self.last_thermal_sequence = saved.sequence;
            through = Some(saved.sequence);
        }
        Ok(through)
    }

    /// Native scheduling policy: one distinct work item per selected chain per
    /// turn, immediately when all have capacity. Caller yields between turns
    /// and waits5ms on no capacity (the original raw sender's blocked wait).
    /// A partial physical commit remains terminal in the underlying registry.
    pub(crate) fn dispatch_if_ready(&mut self, deadline: Instant) -> Result<bool> {
        if !self.pool_active || self.outbox.len() == MAX_OUTBOX {
            return Ok(false);
        }
        let Some(job) = self.job.as_ref() else {
            return Ok(false);
        };
        if !self
            .registry
            .transport
            .selected_work_ready(deadline)
            .map_err(anyhow::Error::msg)?
        {
            return Ok(false);
        }
        self.registry.dispatch(job, &mut self.builder, deadline)?;
        Ok(true)
    }
}
