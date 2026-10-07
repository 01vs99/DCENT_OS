//! One selected disable sweep on original private SafeOff handles. Transport
//! observations never establish PIC ACK, physical OFF or a new teardown budget.
use super::Handles;
use crate::i2c::bb_pic_disable::{Attempt, Operation, WorkerObservation};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub enum BbTerminalOperation {
    SelectSlave,
    WriteDisable,
    ReadReply,
    Wait(Duration),
}
#[derive(Clone, Debug)]
pub struct BbTerminalStepObservation {
    pub operation: BbTerminalOperation,
    pub started_at: Instant,
    pub returned_at: Option<Instant>,
    pub recorded_at: Option<Instant>,
    pub returned_bytes: Option<Vec<u8>>,
    pub error: Option<String>,
}
#[derive(Clone, Debug)]
pub struct BbTerminalWorkerObservation {
    pub original_deadline: Instant,
    pub worker_started_at: Option<Instant>,
    pub worker_returned_at: Option<Instant>,
    pub worker_finalized_at: Option<Instant>,
    pub steps: Vec<BbTerminalStepObservation>,
    pub transport_completed_at: Option<Instant>,
    pub failure: Option<String>,
}
impl From<WorkerObservation> for BbTerminalWorkerObservation {
    fn from(actual: WorkerObservation) -> Self {
        Self {
            original_deadline: actual.deadline,
            worker_started_at: actual.worker_started_at,
            worker_returned_at: actual.worker_returned_at,
            worker_finalized_at: actual.worker_finalized_at,
            steps: actual
                .steps
                .into_iter()
                .map(|step| BbTerminalStepObservation {
                    operation: match step.operation {
                        Operation::SelectSlave => BbTerminalOperation::SelectSlave,
                        Operation::WriteDisable => BbTerminalOperation::WriteDisable,
                        Operation::ReadReply => BbTerminalOperation::ReadReply,
                        Operation::Wait(duration) => BbTerminalOperation::Wait(duration),
                    },
                    started_at: step.started_at,
                    returned_at: step.returned_at,
                    recorded_at: step.recorded_at,
                    returned_bytes: step.returned_bytes,
                    error: step.error,
                })
                .collect(),
            transport_completed_at: actual.transport_completed_at,
            failure: actual.failure,
        }
    }
}
#[derive(Clone, Debug)]
pub struct BbTerminalPicObservation {
    pub native_slot: Option<usize>,
    pub factory_address: u8,
    pub original_deadline: Instant,
    pub caller_prepared_at: Option<Instant>,
    pub caller_started_at: Option<Instant>,
    pub caller_returned_at: Option<Instant>,
    pub enqueued: bool,
    pub timely_receipt_at: Option<Instant>,
    pub failure: Option<String>,
    pub worker: Option<BbTerminalWorkerObservation>,
}
#[derive(Clone, Debug)]
pub struct BbTerminalSweepObservation {
    pub original_deadline: Instant,
    pub prepared_at: Instant,
    pub caller_started_at: Option<Instant>,
    pub caller_returned_at: Option<Instant>,
    pub caller_joined_at: Option<Instant>,
    pub joined_within_original_deadline: bool,
    pub failure: Option<String>,
    pub selected: Vec<BbTerminalPicObservation>,
}
struct Slot {
    address: u8,
    caller_started_at: Option<Instant>,
    attempt: Option<Attempt>,
}
struct State {
    original_deadline: Instant,
    prepared_at: Instant,
    caller_started_at: Option<Instant>,
    caller_returned_at: Option<Instant>,
    caller_joined_at: Option<Instant>,
    failure: Option<String>,
    slots: Vec<Slot>,
}
fn lock(state: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    state.lock().unwrap_or_else(|poison| {
        let mut state = poison.into_inner();
        state
            .failure
            .get_or_insert_with(|| "BB terminal sweep state poisoned".into());
        state
    })
}

pub(super) struct Sweep {
    state: Arc<Mutex<State>>,
    caller: Option<JoinHandle<()>>,
    launch_handles: Option<Handles>,
}
impl Sweep {
    /// Roster comes only from the original owner's joined selected diagnostics.
    /// A single retained blocking caller executes those helper invocations in
    /// original selected order. Cleanup retries never create another sweep.
    pub(super) fn prepare(selected: &[u8], handles: Handles, deadline: Instant) -> Self {
        handles.fence();
        let valid = !selected.is_empty()
            && selected.len() <= 3
            && selected.iter().enumerate().all(|(i, address)| {
                (0x50..=0x52).contains(address) && !selected[..i].contains(address)
            });
        let state = Arc::new(Mutex::new(State {
            original_deadline: deadline,
            prepared_at: Instant::now(),
            caller_started_at: None,
            caller_returned_at: None,
            caller_joined_at: None,
            failure: (!valid)
                .then(|| "BB terminal sweep lacks original joined selected roster".into()),
            slots: selected
                .iter()
                .map(|address| Slot {
                    address: *address,
                    caller_started_at: None,
                    attempt: None,
                })
                .collect(),
        }));
        if !valid {
            return Self {
                state,
                caller: None,
                launch_handles: None,
            };
        }
        Self {
            state,
            caller: None,
            launch_handles: Some(handles),
        }
    }

    /// The owner calls this only after observing entry into its retained
    /// operational cutoff callback. Entry is not GPIO syscall or physical OFF
    /// evidence; the enclosing daemon must perform its own immediate cutoff.
    pub(super) fn launch_once(&mut self) {
        let Some(handles) = self.launch_handles.take() else {
            return;
        };
        let work = self.state.clone();
        let deadline = lock(&work).original_deadline;
        let caller = tokio::task::spawn_blocking(move || {
            lock(&work).caller_started_at = Some(Instant::now());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for index in 0..selected_len(&work) {
                    let address = {
                        let mut state = lock(&work);
                        let slot = &mut state.slots[index];
                        slot.caller_started_at = Some(Instant::now());
                        slot.address
                    };
                    // Expired later helper invocations are still recorded as
                    // refused/no-enqueue attempts under this SAME deadline.
                    let attempt = handles
                        .bus0
                        .disable_bb_pic_at(usize::from(address - 0x50), deadline);
                    let mut state = lock(&work);
                    if let Some(reason) = &attempt.failure {
                        state.failure.get_or_insert_with(|| reason.clone());
                    }
                    state.slots[index].attempt = Some(attempt);
                }
            }));
            let mut state = lock(&work);
            state.caller_returned_at = Some(Instant::now());
            if result.is_err() {
                state.failure.get_or_insert_with(|| {
                    "BB retained terminal sweep caller unwound; no replay".into()
                });
            }
        });
        self.caller = Some(caller);
    }

    pub(super) fn snapshot(&self) -> BbTerminalSweepObservation {
        let state = lock(&self.state);
        BbTerminalSweepObservation {
            original_deadline: state.original_deadline,
            prepared_at: state.prepared_at,
            caller_started_at: state.caller_started_at,
            caller_returned_at: state.caller_returned_at,
            caller_joined_at: state.caller_joined_at,
            joined_within_original_deadline: state
                .caller_joined_at
                .is_some_and(|at| at < state.original_deadline),
            failure: state.failure.clone(),
            selected: state
                .slots
                .iter()
                .map(|slot| {
                    let attempt = slot.attempt.as_ref();
                    BbTerminalPicObservation {
                        native_slot: (0x50..=0x52)
                            .contains(&slot.address)
                            .then(|| usize::from(slot.address - 0x50)),
                        factory_address: slot.address,
                        original_deadline: state.original_deadline,
                        caller_prepared_at: slot.caller_started_at,
                        caller_started_at: attempt.map(|attempt| attempt.caller_started_at),
                        caller_returned_at: attempt.and_then(|attempt| attempt.caller_returned_at),
                        enqueued: attempt.is_some_and(|attempt| attempt.enqueued),
                        timely_receipt_at: attempt.and_then(|attempt| attempt.timely_receipt_at),
                        failure: attempt.and_then(|attempt| attempt.failure.clone()),
                        worker: attempt.map(|attempt| attempt.worker_snapshot().into()),
                    }
                })
                .collect(),
        }
    }
    pub(super) fn awaiting_launch(&self) -> bool {
        self.launch_handles.is_some()
    }
    pub(super) fn record_callback_entry_wait_expired(&self) {
        lock(&self.state).failure.get_or_insert_with(|| {
            "BB terminal cleanup wait elapsed before operational cutoff callback entry; original reservation retained".into()
        });
    }
    pub(super) fn pending(&self) -> bool {
        self.caller.is_some() || self.awaiting_launch()
    }
    pub(super) async fn join_until(&mut self, cleanup_deadline: Instant) -> bool {
        let Some(caller) = self.caller.as_mut() else {
            return !self.awaiting_launch();
        };
        if Instant::now() >= cleanup_deadline {
            return false;
        }
        let result = tokio::select! {
            result = caller => Some(result),
            _ = tokio::time::sleep_until(cleanup_deadline.into()) => None,
        };
        let Some(result) = result else {
            return false;
        };
        self.caller = None;
        let joined_at = Instant::now();
        let mut state = lock(&self.state);
        state.caller_joined_at = Some(joined_at);
        if let Err(error) = result {
            state
                .failure
                .get_or_insert_with(|| format!("BB terminal sweep task join failed: {error}"));
        }
        if joined_at >= state.original_deadline {
            state.failure.get_or_insert_with(|| {
                "BB terminal sweep joined after its original deadline".into()
            });
        }
        // This result concerns actual task custody under a cleanup wait only.
        // Earlier failed/late transport observations remain permanently failed.
        Instant::now() < cleanup_deadline
    }
}
fn selected_len(state: &Mutex<State>) -> usize {
    lock(state).slots.len()
}
pub(super) async fn join_until(sweep: &mut Option<Sweep>, deadline: Instant) -> bool {
    match sweep.as_mut() {
        Some(sweep) => sweep.join_until(deadline).await,
        None => true,
    }
}
