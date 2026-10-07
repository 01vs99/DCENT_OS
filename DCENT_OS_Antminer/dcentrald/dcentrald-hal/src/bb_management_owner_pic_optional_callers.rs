//! Original fixed-optional-bridge callers retained by the original management owner.
//! Timely join is historical transport data, never a phase-order, temperature, ACK or physical receipt.
use super::{lock, stop, BbManagementOwner, Handles, State};
use crate::i2c::bb_pic_optional_bridge::{Attempt, Observation};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub(super) struct JoinObservation {
    pub(super) started_at: Instant,
    pub(super) budget_deadline: Instant,
    pub(super) cleanup: bool,
    pub(super) returned_at: Option<Instant>,
    pub(super) timed_out_at: Option<Instant>,
    pub(super) cancelled_at: Option<Instant>,
    pub(super) error: Option<String>,
}

/// Actual cleanup observations, separate from the caller's original deadline.
#[derive(Clone, Debug)]
pub(super) struct WorkerWaitObservation {
    pub(super) started_at: Instant,
    pub(super) budget_deadline: Instant,
    pub(super) worker_finalized_at: Option<Instant>,
    pub(super) observed_at: Option<Instant>,
    pub(super) timed_out_at: Option<Instant>,
    pub(super) cancelled_at: Option<Instant>,
}

#[derive(Clone, Debug)]
pub(super) struct CallerHistory {
    pub(super) original_deadline: Instant,
    pub(super) retained_at: Instant,
    pub(super) spawn_started_at: Option<Instant>,
    pub(super) spawn_returned_at: Option<Instant>,
    pub(super) spawn_unwound_at: Option<Instant>,
    pub(super) spawn_unwind: Option<String>,
    pub(super) joined_at: Option<Instant>,
    pub(super) join_error: Option<String>,
    pub(super) timely_joined_at: Option<Instant>,
    pub(super) first_failure: Option<String>,
    pub(super) joins: Vec<JoinObservation>,
    pub(super) worker_waits: Vec<WorkerWaitObservation>,
}

#[derive(Clone, Debug)]
pub(super) struct CallerObservation {
    pub(super) original: Observation,
    pub(super) history: CallerHistory,
    pub(super) pending: bool,
}

struct Caller {
    original: Attempt,
    task: Option<JoinHandle<()>>,
    history: Arc<Mutex<CallerHistory>>,
}

impl Caller {
    fn worker_pending(&self) -> bool {
        let original = self.original.snapshot();
        original.request_created_at.is_some() && original.worker_finalized_at.is_none()
    }

    fn pending(&self) -> bool {
        self.task.is_some() || self.worker_pending()
    }
}

#[derive(Default)]
pub(in crate::bb_management_owner) struct RetainedCallers {
    // Original native-slot reservations cap this at three one-shot attempts.
    calls: Vec<Caller>,
}

impl RetainedCallers {
    pub(in crate::bb_management_owner) fn pending(&self) -> bool {
        self.calls.iter().any(Caller::pending)
    }

    pub(super) fn snapshots(&self) -> Vec<CallerObservation> {
        self.calls
            .iter()
            .map(|call| CallerObservation {
                original: call.original.snapshot(),
                history: history(&call.history).clone(),
                pending: call.pending(),
            })
            .collect()
    }
}

fn history(shared: &Mutex<CallerHistory>) -> MutexGuard<'_, CallerHistory> {
    shared.lock().unwrap_or_else(|poison| {
        let mut retained = poison.into_inner();
        retained
            .first_failure
            .get_or_insert_with(|| "BB optional bridge caller history poisoned".into());
        retained
    })
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string caller spawn panic payload unavailable".into())
}

struct PendingJoin {
    state: Arc<Mutex<State>>,
    handles: Handles,
    history: Arc<Mutex<CallerHistory>>,
    index: usize,
    armed: bool,
}

impl Drop for PendingJoin {
    fn drop(&mut self) {
        if self.armed {
            // Fence first. The original JoinHandle stays in the owner.
            stop(
                &self.state,
                &self.handles,
                "BB optional bridge original caller join future cancelled",
            );
            let now = Instant::now();
            let mut retained = history(&self.history);
            retained.joins[self.index].cancelled_at = Some(now);
            retained.first_failure.get_or_insert_with(|| {
                "BB optional bridge original caller join future cancelled".into()
            });
        }
    }
}

impl BbManagementOwner {
    fn start_retained_pic_optional_bridge(
        &mut self,
        selected_index: usize,
        deadline: Instant,
    ) -> Result<usize, String> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "BB optional bridge caller requires the enclosing Tokio runtime")?;
        if self.optional_callers.pending() {
            return Err("BB optional bridge caller requires the preceding actual join".into());
        }
        let prepared = self.prepare_selected_pic_optional_bridge(selected_index, deadline)?;
        let original = prepared.observation();
        let original_deadline = original.snapshot().original_deadline;
        let retained_at = Instant::now();
        let index = self.optional_callers.calls.len();
        self.optional_callers.calls.push(Caller {
            original,
            task: None,
            history: Arc::new(Mutex::new(CallerHistory {
                original_deadline,
                retained_at,
                spawn_started_at: None,
                spawn_returned_at: None,
                spawn_unwound_at: None,
                spawn_unwind: None,
                joined_at: None,
                join_error: None,
                timely_joined_at: None,
                first_failure: None,
                joins: Vec::new(),
                worker_waits: Vec::new(),
            })),
        });
        // The actual original Attempt is already in self before spawn can run.
        let call = &mut self.optional_callers.calls[index];
        history(&call.history).spawn_started_at = Some(Instant::now());
        let spawned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.spawn_blocking(move || prepared.run())
        }));
        let observed_at = Instant::now();
        match spawned {
            Ok(task) => {
                call.task = Some(task);
                history(&call.history).spawn_returned_at = Some(observed_at);
                Ok(index)
            }
            Err(payload) => {
                stop(
                    &self.state,
                    &self.handles,
                    "BB optional bridge original caller spawn unwound",
                );
                let mut retained = history(&call.history);
                retained.spawn_unwound_at = Some(observed_at);
                retained.spawn_unwind = Some(panic_text(payload.as_ref()));
                retained.first_failure.get_or_insert_with(|| {
                    "BB optional bridge original caller spawn unwound".into()
                });
                Err("BB optional bridge original caller spawn unwound".into())
            }
        }
    }

    #[cfg(all(test, feature = "sim-hal"))]
    pub(super) fn start_retained_pic_optional_bridge_for_test(
        &mut self,
        selected_index: usize,
        deadline: Instant,
    ) -> Result<usize, String> {
        self.start_retained_pic_optional_bridge(selected_index, deadline)
    }

    #[cfg(all(test, feature = "sim-hal"))]
    pub(super) async fn join_retained_pic_optional_bridge_for_test(
        &mut self,
        index: usize,
    ) -> bool {
        let call = &mut self.optional_callers.calls[index];
        let deadline = history(&call.history).original_deadline;
        join_one(call, &self.state, &self.handles, deadline, false).await
    }

    /// Only the fixed-optional-bridge child and descendants can enter this component.
    /// No runtime/daemon API or caller-supplied completion proof is added.
    pub(super) async fn run_retained_pic_optional_bridge(
        &mut self,
        selected_index: usize,
        deadline: Instant,
    ) -> Result<(), String> {
        let index = self.start_retained_pic_optional_bridge(selected_index, deadline)?;
        let call = &mut self.optional_callers.calls[index];
        if join_one(call, &self.state, &self.handles, deadline, false).await {
            Ok(())
        } else {
            Err(history(&call.history)
                .first_failure
                .clone()
                .unwrap_or_else(|| {
                    "BB optional bridge original caller was not timely joined".into()
                }))
        }
    }
}

async fn join_one(
    call: &mut Caller,
    state: &Arc<Mutex<State>>,
    handles: &Handles,
    deadline: Instant,
    cleanup: bool,
) -> bool {
    let Some(task) = call.task.as_mut() else {
        return true;
    };
    let started_at = Instant::now();
    let index = {
        let mut retained = history(&call.history);
        let index = retained.joins.len();
        retained.joins.push(JoinObservation {
            started_at,
            budget_deadline: deadline,
            cleanup,
            returned_at: None,
            timed_out_at: None,
            cancelled_at: None,
            error: None,
        });
        index
    };
    let mut pending = PendingJoin {
        state: state.clone(),
        handles: handles.clone(),
        history: call.history.clone(),
        index,
        armed: true,
    };
    let result = if Instant::now() >= deadline {
        None
    } else {
        tokio::select! {
            result = task => Some(result),
            _ = tokio::time::sleep_until(deadline.into()) => None,
        }
    };
    let observed_at = Instant::now();
    let Some(result) = result else {
        stop(
            state,
            handles,
            "BB optional bridge original caller join deadline elapsed",
        );
        let mut retained = history(&call.history);
        retained.joins[index].timed_out_at = Some(observed_at);
        retained.first_failure.get_or_insert_with(|| {
            "BB optional bridge original caller join deadline elapsed".into()
        });
        pending.armed = false;
        return false;
    };
    // Consume a handle only after observing its actual JoinHandle return.
    call.task = None;
    let original = call.original.snapshot();
    let error = result.err().map(|error| error.to_string());
    let mut management = lock(state, handles);
    let mut retained = history(&call.history);
    let now = Instant::now();
    retained.joined_at = Some(observed_at);
    retained.join_error = error.clone();
    retained.joins[index].returned_at = Some(observed_at);
    retained.joins[index].error = error.clone();
    let timely = now < deadline;
    let complete = !cleanup
        && timely
        && now < retained.original_deadline
        && retained.first_failure.is_none()
        && error.is_none()
        && management.can_continue(handles)
        && original.original_deadline == retained.original_deadline
        && original.caller_returned_at.is_some()
        && original.caller_finalized_at.is_some()
        && original.worker_returned_at.is_some()
        && original.worker_finalized_at.is_some()
        && original.transport_completed_at.is_some()
        && original.timely_receipt_at.is_some()
        && original.first_failure.is_none()
        && original.caller_error.is_none()
        && original.caller_unwound_at.is_none();
    if complete {
        retained.timely_joined_at = Some(now);
    } else if !cleanup || !timely || error.is_some() {
        handles.fence();
        management.stop("BB optional bridge original caller join failed or was not timely");
        let reason = error
            .or_else(|| original.first_failure.clone())
            .unwrap_or_else(|| {
                "BB optional bridge original caller join failed or was not timely".into()
            });
        retained.first_failure.get_or_insert(reason);
    }
    pending.armed = false;
    // Cleanup returns actual join/resource custody only, including failed callers.
    // It cannot manufacture timely_joined_at or clear any original failure.
    if cleanup {
        timely
    } else {
        complete
    }
}

struct PendingWorkerWait {
    state: Arc<Mutex<State>>,
    handles: Handles,
    history: Arc<Mutex<CallerHistory>>,
    index: usize,
    armed: bool,
}

impl Drop for PendingWorkerWait {
    fn drop(&mut self) {
        if self.armed {
            stop(
                &self.state,
                &self.handles,
                "BB optional bridge original worker cleanup cancelled",
            );
            let now = Instant::now();
            let mut retained = history(&self.history);
            retained.worker_waits[self.index].cancelled_at = Some(now);
            retained.first_failure.get_or_insert_with(|| {
                "BB optional bridge original worker cleanup cancelled".into()
            });
        }
    }
}

async fn wait_worker_until(
    call: &mut Caller,
    state: &Arc<Mutex<State>>,
    handles: &Handles,
    deadline: Instant,
) -> bool {
    // Never infer worker absence merely because the caller's JoinHandle returned.
    // A prequeue refusal has no request and needs no fabricated worker finalization.
    if !call.worker_pending() {
        return true;
    }
    let index = {
        let mut retained = history(&call.history);
        let index = retained.worker_waits.len();
        retained.worker_waits.push(WorkerWaitObservation {
            started_at: Instant::now(),
            budget_deadline: deadline,
            worker_finalized_at: None,
            observed_at: None,
            timed_out_at: None,
            cancelled_at: None,
        });
        index
    };
    let mut pending = PendingWorkerWait {
        state: state.clone(),
        handles: handles.clone(),
        history: call.history.clone(),
        index,
        armed: true,
    };
    loop {
        let original = call.original.snapshot();
        let observed_at = Instant::now();
        if let Some(finalized_at) = original.worker_finalized_at {
            let mut retained = history(&call.history);
            retained.worker_waits[index].worker_finalized_at = Some(finalized_at);
            retained.worker_waits[index].observed_at = Some(observed_at);
            if observed_at < deadline {
                pending.armed = false;
                return true;
            }
        }
        if observed_at >= deadline {
            stop(
                state,
                handles,
                "BB optional bridge original worker cleanup deadline elapsed",
            );
            let mut retained = history(&call.history);
            retained.worker_waits[index].timed_out_at = Some(observed_at);
            retained.first_failure.get_or_insert_with(|| {
                "BB optional bridge original worker cleanup deadline elapsed".into()
            });
            pending.armed = false;
            return false;
        }
        // This only samples the sender-free original Attempt. It does not reissue
        // I/O, renew its deadline, acquire another service or promote completion.
        let next = (observed_at + std::time::Duration::from_millis(5)).min(deadline);
        tokio::time::sleep_until(next.into()).await;
    }
}

pub(in crate::bb_management_owner) async fn join_until(
    retained: &mut RetainedCallers,
    state: &Arc<Mutex<State>>,
    handles: &Handles,
    deadline: Instant,
) -> bool {
    let mut joined = true;
    for call in &mut retained.calls {
        if !join_one(call, state, handles, deadline, true).await {
            joined = false;
        }
        if call.task.is_none() && !wait_worker_until(call, state, handles, deadline).await {
            joined = false;
        }
    }
    joined && !retained.pending()
}
