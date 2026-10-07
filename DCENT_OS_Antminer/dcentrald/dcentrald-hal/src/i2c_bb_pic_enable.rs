//! Fixed original BB initializer enable, held .79 ELF send PC 0x4b2c50:
//! 55aa051501001b, wait50/read1/wait20/read1/wait20/wait50 ms.
//! Raw replies are not ACKs and transport completion is not physical rail ON.
//! This child is detached; the parent integration contract is sealed alongside.
use super::*;
use crate::bb_management_owner::pic_enable::Admission;

const REQUEST: [u8; 7] = [0x55, 0xaa, 5, 0x15, 1, 0, 0x1b];

#[derive(Clone, Debug)]
pub(crate) enum Operation {
    SelectSlave,
    WriteEnable,
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
    pub(crate) fn capture(handle: &I2cServiceHandle) -> Result<Self> {
        if handle.bus != 0 {
            return Err(error(0, "BB enable requires original bus0"));
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
/// original authority allocation, generation, actor and absolute deadline.
pub(super) struct Queued {
    admission: Arc<Admission>,
    shared: Shared,
    authority: Arc<I2cSafetyAuthority>,
    generation: u64,
    finalized: bool,
}
// I2cRequest is Debug. Print only immutable fixed request identity; formatting
// must not expose authority handles or acquire management/observation locks.
impl std::fmt::Debug for Queued {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BbPicEnableQueued")
            .field("native_slot", &self.admission.native_slot())
            .field("generation", &self.generation)
            .field("deadline", &self.admission.deadline())
            .finish_non_exhaustive()
    }
}
impl Drop for Queued {
    fn drop(&mut self) {
        if !self.finalized {
            self.refuse("BB enable queued worker request dropped or unwound before finalization");
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
                .refuse("BB enable prepared original attempt abandoned");
            failure(
                &self.shared,
                "BB enable prepared original attempt abandoned",
            );
        }
    }
}

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, Observation> {
    shared.lock().unwrap_or_else(|poison| {
        let mut state = poison.into_inner();
        state
            .first_failure
            .get_or_insert_with(|| "BB enable observation poisoned".into());
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
            .ok_or_else(|| "BB enable admission native slot is invalid".to_string())?;
        let shared = Arc::new(Mutex::new(Observation {
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
            let request = I2cRequest::BbPicEnable {
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
                        "BB enable original deadline expired before submission",
                    )
                })?;
            self.service
                .handle
                .submit_with_intent_budget_at_generation(
                    addr,
                    I2cOperationIntent::Energize,
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
                            "BB enable caller completion late or incomplete".into()
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
                state
                    .first_failure
                    .get_or_insert_with(|| "BB enable original caller unwound".into());
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
    pub(super) fn address(&self) -> u8 {
        lock(&self.shared).pic_address
    }
    pub(super) fn refuse(&self, reason: &str) {
        failure(&self.shared, reason);
        self.admission.refuse(reason);
    }
    fn check(&self, permit: &I2cSafetyPermit) -> Result<()> {
        let addr = self.address();
        if permit.intent != I2cOperationIntent::Energize
            || permit.generation != self.generation
            || !Arc::ptr_eq(&permit.authority, &self.authority)
        {
            return Err(error(
                addr,
                "BB enable worker permit is not the original Energize generation",
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
                "BB enable attempt failed or original deadline elapsed",
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
                    "BB enable step expired while recording admission",
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
        // check. Revalidate live actor/deadline/generation after that lock.
        self.check(permit)?;
        let stage = permit.begin_stage(0, addr, "fixed BB selected PIC enable step")?;
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
                row.error = Some("BB enable backend step unwound".into());
                Err(error(addr, "BB enable backend step unwound"))
            }
        };
        // Preserve raw/count/error before refusal. In particular an error API
        // that exposes no partial count stays None; do not invent progress.
        result?;
        if now >= state.original_deadline {
            return Err(error(
                addr,
                "BB enable step returned or was recorded too late",
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
                return Err(error(addr, "BB enable worker must own original bus0"));
            }
            self.check(permit)?;
            {
                let mut state = lock(&self.shared);
                if state.worker_started_at.is_some() {
                    return Err(error(addr, "BB enable worker replay refused"));
                }
                state.worker_started_at = Some(Instant::now());
            }
            self.step(permit, Operation::SelectSlave, || {
                i2c.set_slave(addr)?;
                Ok((None, None))
            })?;
            self.step(permit, Operation::WriteEnable, || {
                i2c.write(&REQUEST).map(|count| (Some(count), None))
            })?;
            let written = lock(&self.shared)
                .steps
                .last()
                .and_then(|row| row.returned_count);
            if written != Some(REQUEST.len()) {
                return Err(error(addr, "BB enable short or impossible write count"));
            }
            self.wait(permit, Duration::from_millis(50))?;
            for _ in 0..2 {
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
                    return Err(error(addr, "BB enable short or impossible reply count"));
                }
                self.wait(permit, Duration::from_millis(20))?;
            }
            self.wait(permit, Duration::from_millis(50))?;
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
                "BB enable final completion late, failed or superseded",
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
