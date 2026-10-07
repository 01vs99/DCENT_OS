//! Retain the actual blocking caller and original running/held UART owner.
//! The enclosing controller must retain this value through explicit cleanup;
//! Drop is a terminal fence, never a join or physical power-off receipt.
use super::*;
use std::sync::{Mutex, MutexGuard};
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub(crate) enum UartRequest {
    SendRaw {
        chain: usize,
        bytes: Vec<u8>,
        job: u8,
        now_us: u64,
    },
    Receive,
    Hold,
    ObserveHeld,
    ColdControl {
        chain: usize,
        control: ColdControl,
    },
    Resume,
}

#[derive(Clone, Debug)]
pub(crate) enum UartOutput {
    Sent(SerialDispatchAttempt),
    Received(SerialReceiveAttempt),
    Held,
    Observed(HeldTransmitterAttempt),
    Controlled(ColdControlAttempt),
    Resumed,
}

impl UartOutput {
    fn complete(&self) -> bool {
        match self {
            Self::Sent(value) => value.dispatch.is_ok(),
            Self::Received(value) => {
                value.parsed.caller_completed && value.parsed.failure.is_none()
            }
            Self::Observed(value) => value.caller_completed_at.is_some() && value.failure.is_none(),
            Self::Controlled(value) => {
                value.caller_completed_at.is_some() && value.failure.is_none()
            }
            Self::Held | Self::Resumed => true,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UartCallRecord {
    pub sequence: u64,
    pub request: UartRequest,
    pub deadline: Instant,
    pub started_at: Option<Instant>,
    pub returned_at: Option<Instant>,
    pub joined_at: Option<Instant>,
    pub output: Option<UartOutput>,
    pub failure: Option<String>,
    pub promoted_at: Option<Instant>,
}

#[derive(Clone, Debug)]
pub(crate) struct UartCloseRecord {
    pub started_at: Instant,
    pub owner_drop_returned_at: Option<Instant>,
    pub caller_joined_at: Option<Instant>,
    pub failure: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct UartRuntimeSnapshot {
    pub dispatch: DispatchObservation,
    /// Monotonic history of an actual cold-call reservation, never reset by receive/hold/resume.
    pub cold_control_started: bool,
    pub caller_pending: bool,
    pub close_caller_pending: bool,
    pub latest: Option<UartCallRecord>,
    pub last_complete: Option<UartCallRecord>,
    pub stopped_reason: Option<String>,
    pub close: Option<UartCloseRecord>,
}

enum OwnerState {
    Running(BbSerialDispatchOwner),
    Held(BbSerialHeldOwner),
}

struct State {
    owner: Option<OwnerState>,
    sequence: u64,
    cold_control_started: bool,
    latest: Option<UartCallRecord>,
    last_complete: Option<UartCallRecord>,
    stopped_reason: Option<String>,
    close: Option<UartCloseRecord>,
}

fn lock<'a>(state: &'a Mutex<State>, stop: &DispatchStop) -> MutexGuard<'a, State> {
    match state.lock() {
        Ok(state) => state,
        Err(poison) => {
            stop.stop();
            let mut state = poison.into_inner();
            state
                .stopped_reason
                .get_or_insert_with(|| "UART runtime state poisoned".into());
            state
        }
    }
}

fn fence(state: &Mutex<State>, stop: &DispatchStop, reason: &str) {
    stop.stop();
    lock(state, stop)
        .stopped_reason
        .get_or_insert_with(|| reason.into());
}

struct PendingFuture {
    state: Arc<Mutex<State>>,
    stop: DispatchStop,
    armed: bool,
}
impl Drop for PendingFuture {
    fn drop(&mut self) {
        if self.armed {
            fence(&self.state, &self.stop, "UART pending future cancelled");
        }
    }
}

struct Caller {
    sequence: u64,
    deadline: Instant,
    task: JoinHandle<()>,
}

pub(crate) struct BbUartRuntime {
    stop: DispatchStop,
    source_chain_ids: Vec<u8>,
    state: Arc<Mutex<State>>,
    caller: Option<Caller>,
    close_caller: Option<JoinHandle<()>>,
}

fn perform(
    owner: &mut Option<OwnerState>,
    request: &UartRequest,
    deadline: Instant,
) -> Result<UartOutput, String> {
    match request {
        UartRequest::SendRaw {
            chain,
            bytes,
            job,
            now_us,
        } => match owner.as_mut() {
            Some(OwnerState::Running(owner)) => Ok(UartOutput::Sent(
                owner.try_send_raw_until(*chain, bytes, *job, *now_us, deadline),
            )),
            _ => Err("UART raw send requires its running owner".into()),
        },
        UartRequest::Receive => match owner.as_mut() {
            Some(OwnerState::Running(owner)) => {
                Ok(UartOutput::Received(owner.receive_until(deadline)))
            }
            Some(OwnerState::Held(owner)) => {
                Ok(UartOutput::Received(owner.receive_until(deadline)))
            }
            None => Err("UART receive has no original owner".into()),
        },
        UartRequest::ObserveHeld => match owner.as_mut() {
            Some(OwnerState::Held(owner)) => Ok(UartOutput::Observed(
                owner.observe_transmitters_until(deadline),
            )),
            _ => Err("UART transmitter observation requires its held owner".into()),
        },
        UartRequest::ColdControl { chain, control } => match owner.as_mut() {
            Some(OwnerState::Held(owner)) => Ok(UartOutput::Controlled(
                owner.cold_control_until(*chain, control, deadline),
            )),
            _ => Err("BB cold control requires the original held UART owner".into()),
        },
        UartRequest::Hold => match owner.take() {
            Some(OwnerState::Running(running)) => match running.into_hold() {
                Ok(held) => {
                    *owner = Some(OwnerState::Held(held));
                    Ok(UartOutput::Held)
                }
                Err((running, error)) => {
                    *owner = Some(OwnerState::Running(running));
                    Err(format!("UART hold: {error:?}"))
                }
            },
            other => {
                *owner = other;
                Err("UART hold requires its running owner".into())
            }
        },
        UartRequest::Resume => match owner.take() {
            Some(OwnerState::Held(held)) => match held.resume() {
                Ok(running) => {
                    *owner = Some(OwnerState::Running(running));
                    Ok(UartOutput::Resumed)
                }
                Err((held, error)) => {
                    *owner = Some(OwnerState::Held(held));
                    Err(format!("UART resume: {error:?}"))
                }
            },
            other => {
                *owner = other;
                Err("UART resume requires its held owner".into())
            }
        },
    }
}

impl BbUartRuntime {
    pub(crate) fn new(owner: BbSerialDispatchOwner) -> Self {
        Self {
            stop: owner.stop_handle(),
            source_chain_ids: owner
                .inner
                .transport
                .chains
                .iter()
                .map(|uart| uart.backend.chain_id())
                .collect(),
            state: Arc::new(Mutex::new(State {
                owner: Some(OwnerState::Running(owner)),
                sequence: 0,
                cold_control_started: false,
                latest: None,
                last_complete: None,
                stopped_reason: None,
                close: None,
            })),
            caller: None,
            close_caller: None,
        }
    }

    /// Immutable labels captured from the consumed original backends; no route or physical identity proof.
    pub(crate) fn source_chain_ids(&self) -> &[u8] {
        &self.source_chain_ids
    }

    pub(crate) fn stop_handle(&self) -> DispatchStop {
        self.stop.clone()
    }
    pub(crate) fn cancel(&self) {
        fence(
            &self.state,
            &self.stop,
            "UART runtime terminal cancellation",
        );
    }
    pub(crate) fn snapshot(&self) -> UartRuntimeSnapshot {
        let state = lock(&self.state, &self.stop);
        UartRuntimeSnapshot {
            dispatch: self.stop.snapshot(),
            cold_control_started: state.cold_control_started,
            caller_pending: self.caller.is_some(),
            close_caller_pending: self.close_caller.is_some(),
            latest: state.latest.clone(),
            last_complete: state.last_complete.clone(),
            stopped_reason: state.stopped_reason.clone(),
            close: state.close.clone(),
        }
    }

    // Test fixtures can hold a real caller after its return record but before
    // the task actually returns. Production always uses perform and an empty
    // after-record closure; no external callback enters the shipped API.
    fn start_with(
        &mut self,
        request: UartRequest,
        deadline: Instant,
        work: impl FnOnce(&mut Option<OwnerState>, &UartRequest, Instant) -> Result<UartOutput, String>
            + Send
            + 'static,
        after_record: impl FnOnce() + Send + 'static,
    ) -> Result<(), String> {
        let mut state = lock(&self.state, &self.stop);
        if self.caller.is_some()
            || self.close_caller.is_some()
            || state.close.is_some()
            || state.owner.is_none()
            || state.stopped_reason.is_some()
            || self.stop.snapshot().permanently_stopped
            || Instant::now() >= deadline
        {
            self.stop.stop();
            state.stopped_reason.get_or_insert_with(|| {
                "UART request requires an idle retained owner and live deadline".into()
            });
            return Err(state.stopped_reason.clone().expect("recorded refusal"));
        }
        let Some(sequence) = state.sequence.checked_add(1) else {
            self.stop.stop();
            state.stopped_reason = Some("UART sequence exhausted".into());
            return Err("UART sequence exhausted".into());
        };
        state.sequence = sequence;
        state.cold_control_started |= matches!(request, UartRequest::ColdControl { .. });
        state.latest = Some(UartCallRecord {
            sequence,
            request: request.clone(),
            deadline,
            started_at: None,
            returned_at: None,
            joined_at: None,
            output: None,
            failure: None,
            promoted_at: None,
        });
        drop(state);
        let shared = self.state.clone();
        let stop = self.stop.clone();
        let task = tokio::task::spawn_blocking(move || {
            let mut state = lock(&shared, &stop);
            if stop.snapshot().permanently_stopped || Instant::now() >= deadline {
                stop.stop();
                state
                    .stopped_reason
                    .get_or_insert_with(|| "UART caller refused before preparation".into());
                if let Some(record) = state.latest.as_mut() {
                    record.failure = Some("UART caller refused before preparation".into());
                }
                return;
            }
            state
                .latest
                .as_mut()
                .expect("reserved current record")
                .started_at = Some(Instant::now());
            let mut owner = state.owner.take();
            drop(state);
            // Keep the actual owner outside the unwind boundary. Raw I/O only
            // borrows it; atomic owned hold/resume returns it on every error.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                work(&mut owner, &request, deadline)
            }));
            let returned_at = Instant::now();
            let (output, failure) = match outcome {
                Ok(Ok(output)) => {
                    let failure = (!output.complete())
                        .then(|| "UART caller returned an incomplete operation".into());
                    (Some(output), failure)
                }
                Ok(Err(error)) => (None, Some(error)),
                Err(_) => (
                    None,
                    Some("UART caller unwound; original owner retained".into()),
                ),
            };
            let mut state = lock(&shared, &stop);
            state.owner = owner;
            if state.owner.is_none()
                || failure.is_some()
                || returned_at >= deadline
                || stop.snapshot().permanently_stopped
            {
                stop.stop();
                state.stopped_reason.get_or_insert_with(|| {
                    "UART caller failed, stopped, lost custody or returned late".into()
                });
            }
            let record = state
                .latest
                .as_mut()
                .expect("pending record cannot be replaced");
            if record.sequence != sequence || record.deadline != deadline {
                stop.stop();
                state
                    .stopped_reason
                    .get_or_insert_with(|| "UART return identity mismatch".into());
            } else {
                record.returned_at = Some(returned_at);
                record.output = output;
                record.failure = failure;
            }
            drop(state);
            after_record();
        });
        self.caller = Some(Caller {
            sequence,
            deadline,
            task,
        });
        Ok(())
    }

    pub(crate) async fn execute(
        &mut self,
        request: UartRequest,
        deadline: Instant,
    ) -> Result<UartRuntimeSnapshot, String> {
        self.start_with(request, deadline, perform, || {})?;
        self.join_until(deadline, true).await;
        Ok(self.snapshot())
    }

    async fn join_until(&mut self, deadline: Instant, promote: bool) -> bool {
        let Some(caller) = self.caller.as_mut() else {
            return true;
        };
        if Instant::now() >= deadline {
            self.cancel();
            return false;
        }
        let mut guard = PendingFuture {
            state: self.state.clone(),
            stop: self.stop.clone(),
            armed: true,
        };
        let joined = tokio::select! {
            result = &mut caller.task => Some(result),
            _ = tokio::time::sleep_until(deadline.into()) => None,
        };
        let Some(joined) = joined else {
            self.cancel();
            return false;
        };
        let sequence = caller.sequence;
        let original_deadline = caller.deadline;
        self.caller = None;
        let now = Instant::now();
        let mut state = lock(&self.state, &self.stop);
        let record = state
            .latest
            .as_mut()
            .expect("actual caller retained its record");
        record.joined_at = Some(now);
        if let Err(error) = joined {
            record
                .failure
                .get_or_insert_with(|| format!("UART caller task failed: {error}"));
        }
        let valid = record.sequence == sequence
            && record.deadline == original_deadline
            && now < original_deadline
            && now < deadline
            && record.failure.is_none()
            && record
                .returned_at
                .is_some_and(|time| time < original_deadline)
            && record.output.as_ref().is_some_and(UartOutput::complete);
        if !valid {
            self.stop.stop();
            state.stopped_reason.get_or_insert_with(|| {
                "UART caller join was failed, incomplete, mismatched or late".into()
            });
        } else if promote
            && state.stopped_reason.is_none()
            && !self.stop.snapshot().permanently_stopped
        {
            let record = state.latest.as_mut().expect("actual current record");
            record.promoted_at = Some(now);
            state.last_complete = Some(record.clone());
        }
        guard.armed = false;
        true
    }

    pub(crate) async fn join_callers_until(&mut self, deadline: Instant) -> bool {
        self.cancel();
        self.join_until(deadline, false).await
    }

    /// Close is separately retained and joined. A timed-out operation caller
    /// prevents close from starting; a timed-out close caller remains available
    /// for retry. This reports owner Drop/caller join, never physical power-off.
    pub(crate) async fn close_until(&mut self, deadline: Instant) -> bool {
        self.close_with(deadline, || {}).await
    }

    // Private fixture can retain the actual close caller after its Drop record
    // but before task return. Shipping entry supplies only an empty closure.
    async fn close_with(
        &mut self,
        deadline: Instant,
        after_record: impl FnOnce() + Send + 'static,
    ) -> bool {
        self.cancel();
        if !self.join_until(deadline, false).await {
            return false;
        }
        if self.close_caller.is_none() {
            let mut state = lock(&self.state, &self.stop);
            if let Some(record) = state
                .close
                .as_ref()
                .filter(|record| record.caller_joined_at.is_some())
            {
                return record.failure.is_none() && record.owner_drop_returned_at.is_some();
            }
            if Instant::now() >= deadline {
                return false;
            }
            if state.owner.is_none() {
                return false;
            }
            let owner = state.owner.take();
            state.close = Some(UartCloseRecord {
                started_at: Instant::now(),
                owner_drop_returned_at: None,
                caller_joined_at: None,
                failure: None,
            });
            drop(state);
            let shared = self.state.clone();
            let stop = self.stop.clone();
            self.close_caller = Some(tokio::task::spawn_blocking(move || {
                drop(owner);
                lock(&shared, &stop)
                    .close
                    .as_mut()
                    .expect("reserved close record")
                    .owner_drop_returned_at = Some(Instant::now());
                after_record();
            }));
        }
        if Instant::now() >= deadline {
            return false;
        }
        let mut guard = PendingFuture {
            state: self.state.clone(),
            stop: self.stop.clone(),
            armed: true,
        };
        let joined = tokio::select! {
            result = self.close_caller.as_mut().expect("retained close task") => Some(result),
            _ = tokio::time::sleep_until(deadline.into()) => None,
        };
        let Some(joined) = joined else {
            return false;
        };
        self.close_caller = None;
        let mut state = lock(&self.state, &self.stop);
        let record = state.close.as_mut().expect("actual close record");
        record.caller_joined_at = Some(Instant::now());
        if let Err(error) = joined {
            record.failure = Some(format!("UART close task failed: {error}"));
        }
        let closed = record.failure.is_none()
            && record.owner_drop_returned_at.is_some()
            && record.caller_joined_at.is_some_and(|time| time < deadline);
        guard.armed = false;
        closed
    }
}

impl Drop for BbUartRuntime {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
#[path = "uart_runtime_owner_tests.rs"]
mod tests;

#[path = "bb_controller.rs"]
mod controller;
pub(crate) use controller::BbController;

pub use controller::{
    BbClosedController, BbControllerObservation, BbOwnedController, BbOwnedControllerStop,
};
