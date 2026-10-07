//! Fixed original BB initializer exchanges, held .79 ELF send PCs
//! 0x4afe60 (bridge), 0x4b05b8 (startup heartbeat), and 0x4b17c8/0x4b37bc (rail).
//! Exact packets/timing are pinned by SOURCE_NOTE.md and source-sequence.json.
//! Weak raw replies grant no ACK, rail, steady-actor, or initialization authority.
use super::*;
use crate::bb_management_owner::pic_initialization_exchange::{Admission, Phase};

fn request(phase: Phase) -> &'static [u8] {
    match phase {
        Phase::Bridge => &[0x55, 0xaa, 6, 0x3b, 0x48, 0, 0, 0x89],
        Phase::StartupHeartbeat => &[0x55, 0xaa, 4, 0x16, 0, 0x1a],
        Phase::PreEnableRail | Phase::FinalRail => &[0x55, 0xaa, 4, 0x3a, 0, 0x3e],
    }
}
fn intent(phase: Phase) -> I2cOperationIntent {
    match phase {
        Phase::Bridge => I2cOperationIntent::NeutralControl,
        Phase::StartupHeartbeat => I2cOperationIntent::KeepAlive,
        // Both reads first write the controller: existing QueryPrelude semantics.
        Phase::PreEnableRail | Phase::FinalRail => I2cOperationIntent::UnclassifiedMutation,
    }
}
fn read_count(phase: Phase) -> usize {
    match phase {
        Phase::Bridge => 2,
        Phase::StartupHeartbeat => 6,
        Phase::PreEnableRail | Phase::FinalRail => 7,
    }
}
fn first_wait(phase: Phase) -> Duration {
    Duration::from_millis(match phase {
        Phase::Bridge | Phase::StartupHeartbeat => 20,
        Phase::PreEnableRail | Phase::FinalRail => 50,
    })
}
fn extra_transition_wait(phase: Phase) -> bool {
    matches!(phase, Phase::StartupHeartbeat | Phase::PreEnableRail)
}

#[derive(Clone, Debug)]
pub(crate) enum Operation {
    SelectSlave,
    WriteRequest,
    ReadReply,
    Wait(Duration),
}
#[derive(Clone, Debug)]
pub(crate) struct Step {
    pub operation: Operation,
    pub started_at: Instant,
    pub returned_at: Option<Instant>,
    pub unwound_at: Option<Instant>,
    pub recorded_at: Option<Instant>,
    pub returned_count: Option<usize>,
    pub returned_bytes: Option<Vec<u8>>,
    pub error: Option<String>,
}
#[derive(Clone, Debug)]
pub(crate) struct Observation {
    pub phase: Phase,
    pub request_bytes: Vec<u8>,
    pub native_slot: usize,
    pub factory_address: u8,
    pub pic_address: u8,
    pub original_generation: u64,
    pub original_deadline: Instant,
    pub reserved_at: Instant,
    pub caller_started_at: Option<Instant>,
    pub caller_returned_at: Option<Instant>,
    /// Exact returned caller error, retained independently of an earlier
    /// request Drop refusal. This is never a fabricated worker result.
    pub caller_error: Option<String>,
    pub caller_unwound_at: Option<Instant>,
    pub caller_unwind: Option<String>,
    pub caller_finalized_at: Option<Instant>,
    /// Set only after this original Queued request has actually been constructed.
    pub request_created_at: Option<Instant>,
    pub worker_started_at: Option<Instant>,
    pub worker_returned_at: Option<Instant>,
    pub worker_finalized_at: Option<Instant>,
    pub steps: Vec<Step>,
    pub transport_completed_at: Option<Instant>,
    pub timely_receipt_at: Option<Instant>,
    pub first_failure: Option<String>,
}
type Shared = Arc<Mutex<Observation>>;

/// Opaque original handle/generation binding; no raw handle/token extraction.
pub(crate) struct OriginalService {
    handle: I2cServiceHandle,
    generation: I2cServiceGenerationToken,
}
impl OriginalService {
    /// Fresh normal request capture, bounded to the retained initial sweep's
    /// exact allocation and generation. A foreign barrier cannot be adopted
    /// between the immediate owner check and this new preparation.
    pub(crate) fn capture_after_initial_disable(
        handle: &I2cServiceHandle, origin: &bb_pic_initial_disable::Attempt,
    ) -> Result<Self> {
        let fresh = Self::capture(handle)?;
        if !origin.matches_following_service(&fresh.handle, &fresh.generation) {
            return Err(error(0, "new bridge token does not match original initial-disable generation/allocation"));
        }
        Ok(fresh)
    }

    pub(crate) fn capture(handle: &I2cServiceHandle) -> Result<Self> {
        if handle.bus != 0 {
            return Err(error(
                0,
                "BB initialization exchange requires original bus0",
            ));
        }
        Ok(Self {
            handle: handle.clone(),
            generation: handle.capture_generation_token()?,
        })
    }
}

pub(crate) struct Prepared {
    service: OriginalService,
    admission: Arc<Admission>,
    shared: Shared,
    launched: bool,
}
/// A sender-free retained view exists before caller submission. A queue/start
/// timeout can later gain raw worker details, but never a timely caller receipt.
pub(crate) struct Attempt {
    shared: Shared,
}
impl Attempt {
    pub(crate) fn snapshot(&self) -> Observation {
        lock(&self.shared).clone()
    }
}

/// Only Prepared constructs a request. Its private fields bind exact slot,
/// original authority allocation, generation, fixed phase and absolute deadline.
pub(super) struct Queued {
    admission: Arc<Admission>,
    shared: Shared,
    authority: Arc<I2cSafetyAuthority>,
    generation: u64,
    finalized: bool,
}
// I2cRequest is Debug; emit only immutable identity without locks or handles.
impl std::fmt::Debug for Queued {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BbPicInitializationExchangeQueued")
            .field("phase", &self.admission.phase())
            .field("native_slot", &self.admission.native_slot())
            .field("generation", &self.generation)
            .field("deadline", &self.admission.deadline())
            .finish_non_exhaustive()
    }
}
impl Drop for Queued {
    fn drop(&mut self) {
        if !self.finalized {
            self.refuse("BB initialization exchange queued worker request dropped or unwound before finalization");
        }
        lock(&self.shared)
            .worker_finalized_at
            .get_or_insert_with(Instant::now);
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        if !self.launched {
            self.admission
                .refuse("BB initialization exchange prepared original attempt abandoned");
            failure(
                &self.shared,
                "BB initialization exchange prepared original attempt abandoned",
            );
        }
    }
}

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, Observation> {
    shared.lock().unwrap_or_else(|poison| {
        let mut state = poison.into_inner();
        state
            .first_failure
            .get_or_insert_with(|| "BB initialization exchange observation poisoned".into());
        state
    })
}
fn error(addr: u8, detail: impl Into<String>) -> HalError {
    HalError::I2c {
        bus: 0,
        addr,
        detail: detail.into(),
    }
}
fn failure(shared: &Shared, reason: &str) {
    lock(shared)
        .first_failure
        .get_or_insert_with(|| reason.into());
}

impl Prepared {
    pub(crate) fn new(
        service: OriginalService,
        admission: Admission,
    ) -> std::result::Result<Self, String> {
        admission.observe()?;
        let addr = crate::bb_pic_application::native_pic_address(admission.native_slot())
            .ok_or_else(|| {
                "BB initialization exchange admission native slot is invalid".to_string()
            })?;
        let shared = Arc::new(Mutex::new(Observation {
            phase: admission.phase(),
            request_bytes: request(admission.phase()).to_vec(),
            native_slot: admission.native_slot(),
            factory_address: admission.factory_address(),
            pic_address: addr,
            original_generation: service.generation.generation,
            original_deadline: admission.deadline(),
            reserved_at: Instant::now(),
            caller_started_at: None,
            caller_returned_at: None,
            caller_error: None,
            caller_unwound_at: None,
            caller_unwind: None,
            caller_finalized_at: None,
            request_created_at: None,
            worker_started_at: None,
            worker_returned_at: None,
            worker_finalized_at: None,
            steps: Vec::new(),
            transport_completed_at: None,
            timely_receipt_at: None,
            first_failure: None,
        }));
        Ok(Self {
            service,
            admission: Arc::new(admission),
            shared,
            launched: false,
        })
    }
    pub(crate) fn observation(&self) -> Attempt {
        Attempt {
            shared: self.shared.clone(),
        }
    }
    /// Blocking caller: enclosing owner must retain its actual JoinHandle and
    /// the observation before spawn, then explicitly join before service close.
    pub(crate) fn run(mut self) {
        self.launched = true;
        lock(&self.shared).caller_started_at = Some(Instant::now());
        let addr = lock(&self.shared).pic_address;
        let deadline = self.admission.deadline();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.admission
                .observe()
                .map_err(|reason| error(addr, reason))?;
            let (reply_tx, reply_rx) = mpsc::sync_channel(1);
            let request = I2cRequest::BbPicInitializationExchange {
                operation: Queued {
                    admission: self.admission.clone(),
                    shared: self.shared.clone(),
                    authority: self.service.handle.safety.clone(),
                    generation: self.service.generation.generation,
                    finalized: false,
                },
                reply_tx,
            };
            lock(&self.shared).request_created_at = Some(Instant::now());
            let budget =
                I2cRequestBudget::for_request_until(&request, deadline).ok_or_else(|| {
                    error(
                        addr,
                        "BB initialization exchange original deadline expired before submission",
                    )
                })?;
            self.service
                .handle
                .submit_with_intent_budget_at_generation(
                    addr,
                    intent(self.admission.phase()),
                    request,
                    reply_rx,
                    budget,
                    I2cSubmissionAuthority::Generation(&self.service.generation),
                )?;
            self.admission
                .observe()
                .map_err(|reason| error(addr, reason))?;
            Ok::<(), HalError>(())
        }));
        let returned_at = Instant::now();
        let mut state = lock(&self.shared);
        let now = Instant::now();
        match result {
            Ok(result) => {
                state.caller_returned_at = Some(returned_at);
                match result {
                    Ok(())
                        if now < deadline
                            && state.first_failure.is_none()
                            && state.transport_completed_at.is_some() =>
                    {
                        state.timely_receipt_at = Some(now)
                    }
                    Ok(()) => {
                        state.first_failure.get_or_insert_with(|| {
                            "BB initialization exchange caller completion late or incomplete".into()
                        });
                    }
                    Err(problem) => {
                        let actual_error = problem.to_string();
                        state.caller_error = Some(actual_error.clone());
                        state.first_failure.get_or_insert(actual_error);
                    }
                }
            }
            Err(payload) => {
                state.caller_unwound_at = Some(returned_at);
                state.caller_unwind = Some(
                    payload
                        .downcast_ref::<&str>()
                        .map(|text| (*text).to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "non-string panic payload unavailable".into()),
                );
                state.first_failure.get_or_insert_with(|| {
                    "BB initialization exchange original caller unwound".into()
                });
            }
        }
        state.caller_finalized_at = Some(now);
        let reason = state.first_failure.clone();
        drop(state);
        if let Some(reason) = reason {
            self.admission.refuse(&reason);
        }
    }
}

impl Queued {
    /// Parent budget counts slave select + fixed write + fixed single-byte reads.
    /// These constants include the donor's separate transition waits.
    pub(super) fn kernel_operations_and_waits(&self) -> (usize, Duration) {
        let phase = self.admission.phase();
        let wait = first_wait(phase)
            + Duration::from_millis(20 * read_count(phase) as u64)
            + if extra_transition_wait(phase) {
                Duration::from_millis(50)
            } else {
                Duration::ZERO
            };
        (2 + read_count(phase), wait)
    }
    pub(super) fn address(&self) -> u8 {
        lock(&self.shared).pic_address
    }
    pub(super) fn refuse(&self, reason: &str) {
        failure(&self.shared, reason);
        self.admission.refuse(reason);
    }
    fn check(&self, permit: &I2cSafetyPermit) -> Result<()> {
        let addr = self.address();
        if permit.intent != intent(self.admission.phase())
            || permit.generation != self.generation
            || !Arc::ptr_eq(&permit.authority, &self.authority)
        {
            return Err(error(
                addr,
                "BB initialization exchange worker permit is not the original fixed-phase intent/generation",
            ));
        }
        permit.validate_admission(0, addr)?;
        self.admission
            .observe()
            .map_err(|reason| error(addr, reason))?;
        let state = lock(&self.shared);
        if state.first_failure.is_some() || Instant::now() >= state.original_deadline {
            return Err(error(
                addr,
                "BB initialization exchange attempt failed or original deadline elapsed",
            ));
        }
        // Recheck after the observation lock; a terminal fence can arrive while
        // any earlier lock was contended. A later in-flight syscall is still
        // possible and remains an observation, never proof of physical control.
        permit.validate_admission(0, addr)
    }
    fn step(
        &self,
        permit: &I2cSafetyPermit,
        operation: Operation,
        perform: impl FnOnce() -> Result<(Option<usize>, Option<Vec<u8>>)>,
    ) -> Result<()> {
        self.check(permit)?;
        let addr = self.address();
        let index = {
            let mut state = lock(&self.shared);
            let now = Instant::now();
            if state.first_failure.is_some() || now >= state.original_deadline {
                return Err(error(
                    addr,
                    "BB initialization exchange step expired while recording admission",
                ));
            }
            let index = state.steps.len();
            state.steps.push(Step {
                operation,
                started_at: now,
                returned_at: None,
                unwound_at: None,
                recorded_at: None,
                returned_count: None,
                returned_bytes: None,
                error: None,
            });
            index
        };
        // Admission-record lock contention must not preserve an older permit
        // check. Revalidate original owner/deadline/generation after that lock.
        self.check(permit)?;
        let stage = permit.begin_stage(0, addr, "fixed BB selected PIC initialization step")?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(perform));
        let returned_at = Instant::now();
        drop(stage);
        let mut state = lock(&self.shared);
        let now = Instant::now();
        let row = &mut state.steps[index];
        row.recorded_at = Some(now);
        let result = match result {
            Ok(result) => {
                row.returned_at = Some(returned_at);
                match &result {
                    Ok((count, bytes)) => {
                        row.returned_count = *count;
                        row.returned_bytes = bytes.clone();
                    }
                    Err(problem) => row.error = Some(problem.to_string()),
                }
                result.map(|_| ())
            }
            Err(_) => {
                row.unwound_at = Some(returned_at);
                row.error = Some("BB initialization exchange backend step unwound".into());
                Err(error(
                    addr,
                    "BB initialization exchange backend step unwound",
                ))
            }
        };
        // Preserve raw/count/error before refusal. In particular an error API
        // that exposes no partial count stays None; do not invent progress.
        result?;
        if now >= state.original_deadline {
            return Err(error(
                addr,
                "BB initialization exchange step returned or was recorded too late",
            ));
        }
        drop(state);
        self.check(permit)
    }
    fn wait(&self, permit: &I2cSafetyPermit, duration: Duration) -> Result<()> {
        self.step(permit, Operation::Wait(duration), || {
            let remaining = self
                .admission
                .deadline()
                .saturating_duration_since(Instant::now());
            std::thread::sleep(duration.min(remaining));
            Ok((None, None))
        })
    }
    /// Parent normal-worker branch calls once and performs no recovery/replay.
    pub(super) fn execute(&mut self, i2c: &mut I2cBus, permit: &I2cSafetyPermit) -> Result<()> {
        let addr = self.address();
        let result = (|| {
            if i2c.bus != 0 {
                return Err(error(
                    addr,
                    "BB initialization exchange worker must own original bus0",
                ));
            }
            self.check(permit)?;
            {
                let mut state = lock(&self.shared);
                if state.worker_started_at.is_some() {
                    return Err(error(
                        addr,
                        "BB initialization exchange worker replay refused",
                    ));
                }
                state.worker_started_at = Some(Instant::now());
            }
            self.step(permit, Operation::SelectSlave, || {
                i2c.set_slave(addr)?;
                Ok((None, None))
            })?;
            self.step(permit, Operation::WriteRequest, || {
                i2c.write(request(self.admission.phase()))
                    .map(|count| (Some(count), None))
            })?;
            let written = lock(&self.shared)
                .steps
                .last()
                .and_then(|row| row.returned_count);
            if written != Some(request(self.admission.phase()).len()) {
                return Err(error(
                    addr,
                    "BB initialization exchange short or impossible write count",
                ));
            }
            self.wait(permit, first_wait(self.admission.phase()))?;
            for _ in 0..read_count(self.admission.phase()) {
                self.step(permit, Operation::ReadReply, || {
                    let mut raw = [0u8; 1];
                    let count = i2c.read(&mut raw)?;
                    // Keep an impossible count too; no out-of-bounds indexing.
                    Ok((Some(count), Some(raw[..count.min(raw.len())].to_vec())))
                })?;
                if lock(&self.shared)
                    .steps
                    .last()
                    .and_then(|row| row.returned_count)
                    != Some(1)
                {
                    return Err(error(
                        addr,
                        "BB initialization exchange short or impossible reply count",
                    ));
                }
                self.wait(permit, Duration::from_millis(20))?;
            }
            if extra_transition_wait(self.admission.phase()) {
                self.wait(permit, Duration::from_millis(50))?;
            }
            self.check(permit)
        })();
        let returned_at = Instant::now();
        let mut state = lock(&self.shared);
        let now = Instant::now();
        state.worker_returned_at = Some(returned_at);
        let result = match result {
            Ok(())
                if now < state.original_deadline
                    && state.first_failure.is_none()
                    && permit.validate_admission(0, addr).is_ok() =>
            {
                state.transport_completed_at = Some(now);
                Ok(())
            }
            Ok(()) => Err(error(
                addr,
                "BB initialization exchange final completion late, failed or superseded",
            )),
            Err(problem) => Err(problem),
        };
        if let Err(problem) = &result {
            state
                .first_failure
                .get_or_insert_with(|| problem.to_string());
        }
        let reason = state.first_failure.clone();
        drop(state);
        if let Some(reason) = reason {
            self.admission.refuse(&reason);
        }
        result
    }
    pub(super) fn finalize(&mut self, result: &Result<()>) {
        if let Err(problem) = result {
            self.refuse(&problem.to_string());
        }
        lock(&self.shared)
            .worker_finalized_at
            .get_or_insert_with(Instant::now);
        self.finalized = true;
    }
}
