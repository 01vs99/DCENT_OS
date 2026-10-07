//! Detached daemon custody consumer for the actual continuous HAL owner.
//! Private child of work::runtime. Actual registry lifetime is owned by run()
//! outside this future and remains retained through terminal closeout.
use crate::bm1396_mining_work::{registry::WorkRegistry, PreparedJob};
use anyhow::{bail, ensure, Context, Result};
use dcentrald_hal::platform::stock_bm1396::{
    FixedWorkControl, FixedWorkEvent, FixedWorkEvents, Hardware, ThermalSnapshot, Transport,
};
use dcentrald_stratum::{
    types::{JobTemplate, StratumState, StratumStatus, ValidShare},
    work::WorkBuilder,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DispatchPhase {
    FirstProbe,
    SecondProbe,
    WaitingForPool,
    PoolWork,
}

/// Read-only progress for logging/API state. Never accepted by HAL admission,
/// watchdog entry, the registry or any work-publication producer.
#[derive(Clone, Debug)]
pub(super) struct DispatchProgress {
    pub(super) phase: DispatchPhase,
    pub(super) retained_jobs: usize,
    pub(super) retained_returns: usize,
    pub(super) charged_job_bytes: usize,
    pub(super) accepted_shares: u64,
    pub(super) rejected_shares: u64,
    pub(super) connection: StratumState,
    pub(super) pool_difficulty: Option<f64>,
    pub(super) latency_ms: Option<u64>,
    pub(super) last_accepted_at: Option<u64>,
}
impl Default for DispatchProgress {
    fn default() -> Self {
        Self {
            phase: DispatchPhase::FirstProbe,
            retained_jobs: 0,
            retained_returns: 0,
            charged_job_bytes: 0,
            accepted_shares: 0,
            rejected_shares: 0,
            connection: StratumState::Disconnected,
            pool_difficulty: None,
            latency_ms: None,
            last_accepted_at: None,
        }
    }
}

struct Inputs {
    launch_deadline: Instant,
    latest: Option<JobTemplate>,
    pool_issued: bool,
    ever_authorized: bool,
    pending_publication: Option<u32>,
    progress: DispatchProgress,
}
impl Inputs {
    fn new(launch_deadline: Instant) -> Self {
        Self {
            launch_deadline,
            latest: None,
            pool_issued: false,
            ever_authorized: false,
            pending_publication: None,
            progress: DispatchProgress::default(),
        }
    }
    fn require_launch(&self) -> Result<()> {
        ensure!(
            self.progress.phase == DispatchPhase::PoolWork || Instant::now() < self.launch_deadline,
            "BM1396 original probe/first-pool deadline expired"
        );
        Ok(())
    }
    fn request_deadline(&self) -> Instant {
        let operational = Instant::now() + Duration::from_secs(1);
        if self.progress.phase == DispatchPhase::PoolWork {
            operational
        } else {
            operational.min(self.launch_deadline)
        }
    }
    async fn advance<H: Hardware>(
        &mut self,
        registry: &mut WorkRegistry<H>,
        control: &FixedWorkControl,
        builder: &mut WorkBuilder,
    ) -> Result<()> {
        self.require_launch()?;
        if self.pending_publication.is_none() {
            if registry.lifetime_jobs() == 1 && registry.probe_complete(0) {
                self.progress.phase = DispatchPhase::SecondProbe;
                issue(
                    registry,
                    control,
                    self,
                    PreparedJob::known_probe_for_model(registry.model(), 1, 1)?,
                )
                .await?;
            } else if registry.probes_complete() {
                if let Some(job) = self.latest.take() {
                    let id = registry.next_id()?;
                    let prepared = PreparedJob::pool_job(builder, &job, id)?;
                    self.pool_issued = true;
                    issue(registry, control, self, prepared).await?;
                } else if !self.pool_issued {
                    self.progress.phase = DispatchPhase::WaitingForPool;
                }
            }
        }
        Ok(())
    }
    async fn consume_event<H: Hardware>(
        &mut self,
        registry: &mut WorkRegistry<H>,
        control: &FixedWorkControl,
        event: FixedWorkEvent,
        jobs: &mut mpsc::Receiver<JobTemplate>,
        statuses: &mut mpsc::Receiver<StratumStatus>,
        current_thermal: &watch::Sender<Option<ThermalSnapshot>>,
    ) -> Result<()> {
        self.require_launch()?;
        match event {
            FixedWorkEvent::Publication(publication) => {
                ensure!(
                    self.pending_publication == Some(publication.job_id()),
                    "BM1396 completed publication is not the daemon's pending issued packet"
                );
                registry.join_publication(&publication)?;
                let pool = publication.job_id() >= 2;
                control
                    .acknowledge_publication(publication, self.request_deadline())
                    .await
                    .map_err(anyhow::Error::msg)?;
                // Successful enqueue is not completion; a scheduling delay
                // after it cannot promote first-pool receipt beyond launch.
                self.require_launch()?;
                self.pending_publication = None;
                if pool {
                    self.progress.phase = DispatchPhase::PoolWork;
                }
            }
            FixedWorkEvent::Return(raw) => {
                // Drain exact current generation again after wake-up;
                // retired issued headers remain CPU-qualified/custodied.
                self.drain(registry, jobs, statuses)?;
                registry.qualify_return(&raw)?;
                control
                    .acknowledge_return(raw, self.request_deadline())
                    .await
                    .map_err(anyhow::Error::msg)?;
            }
            FixedWorkEvent::Thermal(snapshot) => {
                ensure!(
                    snapshot.epoch() == registry.epoch() && snapshot.is_fresh_at(Instant::now()),
                    "BM1396 actual current work thermal receipt stale or wrong epoch"
                );
                // This is a copy of the exact actual HAL event, retained
                // independently before acknowledging its original slot.
                current_thermal.send_replace(Some(snapshot.clone()));
                control
                    .acknowledge_thermal(snapshot, self.request_deadline())
                    .await
                    .map_err(anyhow::Error::msg)?;
            }
        }
        Ok(())
    }
    fn status<H: Hardware>(
        &mut self,
        registry: &mut WorkRegistry<H>,
        status: StratumStatus,
    ) -> Result<()> {
        if let StratumStatus::StateChanged(state) = &status {
            self.progress.connection = state.clone();
        }
        match status {
            StratumStatus::StateChanged(StratumState::AuthFailed) => {
                registry.set_active_generation(None);
                self.latest = None;
                bail!("BM1396 pool authorization failed");
            }
            StratumStatus::StateChanged(StratumState::Disconnected | StratumState::Connecting) => {
                registry.set_active_generation(None);
                self.latest = None;
                ensure!(
                    !self.ever_authorized,
                    "BM1396 authorized pool connection ended; disconnect hashing is disabled"
                );
            }
            StratumStatus::StateChanged(StratumState::Authorized | StratumState::Mining) => {
                self.ever_authorized = true;
            }
            StratumStatus::StateChanged(StratumState::Donating)
            | StratumStatus::DonationStateChanged { active: true, .. } => {
                registry.set_active_generation(None);
                self.latest = None;
                bail!("BM1396 qualified candidate does not admit donation work");
            }
            StratumStatus::DifficultyChanged(value) => {
                ensure!(
                    value.is_finite() && value > 0.0,
                    "BM1396 observed pool difficulty invalid"
                );
                self.progress.pool_difficulty = Some(value);
            }
            StratumStatus::Latency(value) => self.progress.latency_ms = Some(value),
            StratumStatus::ShareAccepted { .. } => {
                self.progress.last_accepted_at = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .context("BM1396 wall clock precedes Unix epoch")?
                        .as_secs(),
                );
                self.progress.accepted_shares = self
                    .progress
                    .accepted_shares
                    .checked_add(1)
                    .context("BM1396 accepted-share count exhausted")?;
            }
            StratumStatus::ShareRejected { .. } => {
                self.progress.rejected_shares = self
                    .progress
                    .rejected_shares
                    .checked_add(1)
                    .context("BM1396 rejected-share count exhausted")?;
            }
            _ => {}
        }
        Ok(())
    }
    fn job<H: Hardware>(&mut self, registry: &mut WorkRegistry<H>, job: JobTemplate) -> Result<()> {
        if job.clean_jobs {
            registry.set_active_generation(None);
            self.latest = None;
            // This candidate has no separate proved hold/reset-and-resume work
            // epoch. Stop the actual owner instead of continuing a retired job.
            // A real V1 clean notify carries a complete job, not a flush-only
            // sentinel; both invalidate already-issued active pool work.
            ensure!(
                !self.pool_issued,
                "BM1396 active pool work was invalidated; terminal epoch required"
            );
            if job.is_flush_only() {
                return Ok(());
            }
        }
        ensure!(
            self.ever_authorized,
            "BM1396 notify preceded observed pool authorization"
        );
        let domain = job
            .v1_work_domain
            .as_ref()
            .context("BM1396 notify lacks actual V1 namespace")?;
        ensure!(
            domain.generation() == job.work_generation,
            "BM1396 notify namespace generation already superseded"
        );
        registry.set_active_generation(Some(job.work_generation));
        // The bounded Stratum owner retains its generation domain; only the
        // newest not-yet-issued notify is needed here. Issued templates remain
        // immutable in WorkRegistry, including any retired generation returns.
        self.latest = Some(job);
        Ok(())
    }
    fn drain<H: Hardware>(
        &mut self,
        registry: &mut WorkRegistry<H>,
        jobs: &mut mpsc::Receiver<JobTemplate>,
        statuses: &mut mpsc::Receiver<StratumStatus>,
    ) -> Result<()> {
        // These are the actual channel capacities made by run(). A continuing
        // producer burst cannot starve receive/ack service indefinitely.
        for _ in 0..128 {
            match statuses.try_recv() {
                Ok(status) => self.status(registry, status)?,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    bail!("BM1396 Stratum status owner closed")
                }
            }
        }
        ensure!(
            statuses.is_empty(),
            "BM1396 Stratum status burst exceeded bounded service turn"
        );
        for _ in 0..16 {
            match jobs.try_recv() {
                Ok(job) => self.job(registry, job)?,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    bail!("BM1396 Stratum job owner closed")
                }
            }
        }
        ensure!(
            jobs.is_empty(),
            "BM1396 notify burst exceeded bounded service turn"
        );
        Ok(())
    }
    fn publish_progress<H: Hardware>(
        &mut self,
        registry: &WorkRegistry<H>,
        progress: &watch::Sender<DispatchProgress>,
    ) {
        self.progress.retained_jobs = registry.lifetime_jobs();
        self.progress.retained_returns = registry.retained_returns().len();
        self.progress.charged_job_bytes = registry.charged_bytes();
        progress.send_replace(self.progress.clone());
    }
}

async fn issue<H: Hardware>(
    registry: &mut WorkRegistry<H>,
    control: &FixedWorkControl,
    input: &mut Inputs,
    job: PreparedJob,
) -> Result<Arc<PreparedJob>> {
    ensure!(
        input.pending_publication.is_none(),
        "BM1396 daemon publication already pending"
    );
    input.require_launch()?;
    let id = job.id();
    // Actual immutable CPU/header/packet metadata is retained BEFORE the HAL
    // receives a request. Any enqueue or publication failure keeps this slot.
    let issued = registry.retain_issued(job)?;
    input.pending_publication = Some(id);
    control
        .enqueue_publication(issued.packet().to_vec(), input.request_deadline())
        .await
        .map_err(anyhow::Error::msg)?;
    Ok(issued)
}

/// The absolute launch bound covers both observed probe sequences and first
/// pool work. It is a native scheduling limit, not a generator refresh period,
/// nonce-exhaustion calculation or evidence of electrical readiness.
pub(super) async fn dispatch<H: Hardware>(
    owner: &Arc<Transport<H>>,
    registry: &mut WorkRegistry<H>,
    control: &FixedWorkControl,
    events: &mut FixedWorkEvents,
    jobs: &mut mpsc::Receiver<JobTemplate>,
    statuses: &mut mpsc::Receiver<StratumStatus>,
    shares: &mpsc::Sender<ValidShare>,
    current_thermal: &watch::Sender<Option<ThermalSnapshot>>,
    progress: &watch::Sender<DispatchProgress>,
    shutdown: &CancellationToken,
    launch_deadline: Instant,
) -> Result<()> {
    ensure!(
        !shutdown.is_cancelled(),
        "BM1396 work dispatch cancelled before first issue"
    );
    ensure!(
        !owner.is_terminal(),
        "BM1396 actual work owner became terminal"
    );
    let mut input = Inputs::new(launch_deadline);
    let mut builder = WorkBuilder::new(); // Sole existing V1 EN2 allocator.
    input.drain(registry, jobs, statuses)?;
    issue(
        registry,
        control,
        &mut input,
        PreparedJob::known_probe_for_model(owner.model(), 0, 0)?,
    )
    .await?;
    loop {
        ensure!(
            !owner.is_terminal(),
            "BM1396 actual work owner became terminal"
        );
        input.drain(registry, jobs, statuses)?;
        // Refresh the submit gate from actual latest notify/status inputs before
        // moving any retained share. The V1 socket owner checks it again.
        for _ in 0..128 {
            if !registry.offer_head(shares)? {
                break;
            }
        }
        input.advance(registry, control, &mut builder).await?;
        input.publish_progress(registry, progress);
        input.require_launch()?;
        tokio::select! {
            biased;
            _=shutdown.cancelled()=>bail!("BM1396 work dispatch cancelled"),
            event=events.next()=>{
                input.consume_event(registry,control,event.context("BM1396 actual work receipt owner closed")?,
                    jobs,statuses,current_thermal).await?;
            }
            status=statuses.recv()=>input.status(registry,status.context("BM1396 Stratum status stream closed")?)?,
            job=jobs.recv()=>input.job(registry,job.context("BM1396 Stratum job stream closed")?)?,
            _=tokio::time::sleep(Duration::from_millis(10))=>{},
        }
    }
}

#[cfg(test)]
#[path = "bm1396_mining_dispatch_tests.rs"]
mod tests;
