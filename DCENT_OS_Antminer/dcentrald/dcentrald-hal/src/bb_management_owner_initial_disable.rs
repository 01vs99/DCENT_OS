//! Original joined-roster initial disable; successful completion is nonterminal.
//! This child does not establish voltage, GPIO, initializer or mining readiness.
use super::{lock, stop, BbManagementOwner, Handles, State};
use crate::i2c::bb_pic_initial_disable::{Attempt, Observation, Prepared};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

#[derive(Clone)]
pub(crate) struct Admission {
    state: Arc<Mutex<State>>,
    handles: Handles,
    selected: Vec<u8>,
    sequence: u64,
    profile_generation: u64,
    deadline: Instant,
}
impl Admission {
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn selected_addresses(&self) -> &[u8] {
        &self.selected
    }
    pub(crate) fn refuse(&self, why: &str) {
        stop(&self.state, &self.handles, why);
    }
    pub(crate) fn observe(&self) -> Result<(), String> {
        let mut state = lock(&self.state, &self.handles);
        // Ordinary can_continue is closed during this phase. Only this private
        // admission can observe it; it does not clear a terminal fence.
        if Instant::now() >= self.deadline
            || self.handles.is_stopped()
            || state.stopped_at.is_some()
            || !state.initial_disable_active
            || !state.diagnostic_joined
            || state.selected_addresses != self.selected
            || state.sequence != self.sequence
            || state.execution.profile_generation != self.profile_generation
        {
            self.handles.fence();
            state.stop("initial-disable original owner admission became stale or terminal");
            return Err(state.stop_reason.clone().expect("original stop retained"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct WaitObservation {
    pub started_at: Instant,
    pub deadline: Instant,
    pub cleanup: bool,
    pub caller_joined_at: Option<Instant>,
    pub worker_finalized_observed_at: Option<Instant>,
    pub returned_at: Option<Instant>,
    pub timed_out_at: Option<Instant>,
    pub cancelled_at: Option<Instant>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct History {
    pub retained_at: Instant,
    pub spawn_started_at: Option<Instant>,
    pub spawn_returned_at: Option<Instant>,
    pub spawn_unwound_at: Option<Instant>,
    pub joined_at: Option<Instant>,
    pub join_error: Option<String>,
    pub timely_joined_at: Option<Instant>,
    pub first_failure: Option<String>,
    pub waits: Vec<WaitObservation>,
    pub consumption_checks: Vec<ConsumptionCheck>,
}

#[derive(Clone, Debug)]
pub(crate) struct ConsumptionCheck {
    pub observed_at: Instant,
    pub accepted: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ReservationObservation {
    pub reserved_at: Instant,
    pub original_deadline: Instant,
    pub selected_addresses: Vec<u8>,
    pub sequence: u64,
    pub profile_generation: u64,
    pub prepared_at: Option<Instant>,
    pub preparation_failed_at: Option<Instant>,
    pub preparation_error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct InitialDisableObservation {
    pub original: Observation,
    pub history: History,
    pub pending: bool,
}

struct Caller {
    admission: Admission,
    original: Attempt,
    history: Arc<Mutex<History>>,
    task: Option<JoinHandle<()>>,
}

#[derive(Default)]
pub(super) struct Retained {
    reservation: Option<ReservationObservation>,
    // Some is permanent one-shot reservation history, even after failure/join.
    caller: Option<Caller>,
}
impl Retained {
    // Sender-free actual origin; only this same owner and descendants can join
    // it to a newly captured normal-phase token. No snapshot becomes authority.
    pub(super) fn following_phase_origin(&self) -> Option<Attempt> {
        self.caller.as_ref().map(|call| call.original.clone())
    }

    pub(super) fn pending(&self) -> bool {
        self.caller
            .as_ref()
            .is_some_and(|call| call.task.is_some() || call.original.worker_pending())
    }
    fn snapshot(&self) -> Option<InitialDisableObservation> {
        self.caller.as_ref().map(|call| InitialDisableObservation {
            original: call.original.snapshot(),
            history: history(&call.history).clone(),
            pending: self.pending(),
        })
    }
}

fn history(value: &Mutex<History>) -> MutexGuard<'_, History> {
    value.lock().unwrap_or_else(|poison| {
        let mut held = poison.into_inner();
        held.first_failure
            .get_or_insert_with(|| "initial-disable join history poisoned".into());
        held
    })
}

impl BbManagementOwner {
    fn start_initial_disable(&mut self, deadline: Instant) -> Result<(), String> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "initial disable requires original enclosing Tokio runtime")?;
        if self.initial_disable.reservation.is_some() {
            return Err("initial-disable original sweep is one-shot and cannot restart".into());
        }
        let diagnostics = self.diagnostics.snapshot();
        let mut state = lock(&self.state, &self.handles);
        let selected = state.selected_addresses.clone();
        let valid = state.diagnostic_joined
            && diagnostics.stop.is_none()
            && diagnostics.both_callers_joined_observed_at.is_some()
            && selected == diagnostics.selected_addresses
            && !selected.is_empty()
            && selected.len() <= 3
            && selected
                .iter()
                .enumerate()
                .all(|(i, addr)| (0x50..=0x52).contains(addr) && !selected[..i].contains(addr))
            && diagnostics.historical.as_ref().is_some_and(|data| {
                let pics = &data.bus0.selected_inventory.pics;
                pics.len() == selected.len()
                    && pics.iter().zip(&selected).all(|(pic, addr)| {
                        pic.factory_address == *addr
                            && pic.native_slot == usize::from(addr - 0x50)
                            && pic.pic_address == 0x20 + (addr - 0x50)
                            && pic.call_returned_at.is_some()
                            && pic.error.is_none()
                            && pic.returned_reads.as_ref().is_some_and(|reads| {
                                crate::bb_pic_application::complete_reply(reads).ok()
                                    == pic.accepted_reply
                                    && pic.accepted_reply.is_some()
                            })
                    })
            });
        if !valid
            || Instant::now() >= deadline
            || !state.can_continue(&self.handles)
            || self.heartbeat.is_some()
            || self.heartbeat_final.is_some()
            || self.terminal.is_some()
            || self.voltage_task.is_some()
            || self.bus0_task.is_some()
            || self.execution_task.is_some()
            || self.initialization_callers.pending()
            || self.enable_callers.pending()
            || self.optional_callers.pending()
            || state.sequence != 0
            || state.execution.latest.is_some()
            || state.pic_enable_reserved.iter().any(|value| *value)
            || state
                .pic_initialization_reserved
                .iter()
                .flatten()
                .any(|value| *value)
            || state.pic_optional_bridge.has_reservation()
        {
            return Err("initial disable requires joined idle original fw89 diagnostics before all normal phases".into());
        }
        let admission = Admission {
            state: self.state.clone(),
            handles: self.handles.clone(),
            selected,
            sequence: state.sequence,
            profile_generation: state.execution.profile_generation,
            deadline,
        };
        state.initial_disable_active = true;
        self.initial_disable.reservation = Some(ReservationObservation {
            reserved_at: Instant::now(),
            original_deadline: deadline,
            selected_addresses: admission.selected.clone(),
            sequence: admission.sequence,
            profile_generation: admission.profile_generation,
            prepared_at: None,
            preparation_failed_at: None,
            preparation_error: None,
        });
        drop(state);
        let prepared = Prepared::new(&self.handles.bus0, admission.clone()).map_err(|error| {
            let retained = self
                .initial_disable
                .reservation
                .as_mut()
                .expect("original reservation retained before preparation");
            retained.preparation_failed_at = Some(Instant::now());
            retained.preparation_error = Some(error.to_string());
            stop(
                &self.state,
                &self.handles,
                "initial-disable original service preparation failed",
            );
            error.to_string()
        })?;
        self.initial_disable
            .reservation
            .as_mut()
            .expect("original reservation retained")
            .prepared_at = Some(Instant::now());
        self.initial_disable.caller = Some(Caller {
            admission,
            original: prepared.observation(),
            task: None,
            history: Arc::new(Mutex::new(History {
                retained_at: Instant::now(),
                spawn_started_at: None,
                spawn_returned_at: None,
                spawn_unwound_at: None,
                joined_at: None,
                join_error: None,
                timely_joined_at: None,
                first_failure: None,
                waits: Vec::new(),
                consumption_checks: Vec::new(),
            })),
        });
        let call = self
            .initial_disable
            .caller
            .as_mut()
            .expect("original caller retained before spawn");
        history(&call.history).spawn_started_at = Some(Instant::now());
        let spawned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.spawn_blocking(move || prepared.run())
        }));
        match spawned {
            Ok(task) => {
                call.task = Some(task);
                history(&call.history).spawn_returned_at = Some(Instant::now());
                Ok(())
            }
            Err(_) => {
                call.admission.refuse("initial-disable spawn unwound");
                let mut held = history(&call.history);
                held.spawn_unwound_at = Some(Instant::now());
                held.first_failure
                    .get_or_insert_with(|| "initial-disable spawn unwound".into());
                Err("initial-disable spawn unwound".into())
            }
        }
    }

    /// Same-owner component entry for a later enclosing initializer. No caller
    /// roster, frame, service or ready DTO can enter this transition.
    pub(crate) async fn initial_disable_until(&mut self, deadline: Instant) -> Result<(), String> {
        self.start_initial_disable(deadline)?;
        if join_until(
            &mut self.initial_disable,
            &self.state,
            &self.handles,
            deadline,
            false,
        )
        .await
        {
            Ok(())
        } else {
            Err(self
                .initial_disable
                .snapshot()
                .and_then(|v| v.history.first_failure)
                .unwrap_or_else(|| "initial-disable original sweep did not complete".into()))
        }
    }

    pub(crate) fn initial_disable_snapshot(&self) -> Option<InitialDisableObservation> {
        self.initial_disable.snapshot()
    }

    pub(crate) fn initial_disable_reservation_snapshot(&self) -> Option<ReservationObservation> {
        self.initial_disable.reservation.clone()
    }

    /// Immediate same-owner consumption before preparing a NEW normal phase.
    /// New later operations may capture their own token on this same allocation;
    /// this guard never refreshes a previously prepared operation or this sweep.
    pub(crate) fn require_initial_disable_complete(&self) -> Result<(), String> {
        let mut state = lock(&self.state, &self.handles);
        let call = self
            .initial_disable
            .caller
            .as_ref()
            .ok_or("initial disable has no prepared original caller")?;
        let pending = self.initial_disable.pending();
        let mut held = history(&call.history);
        let generation_current = call.original.final_generation_current();
        let now = Instant::now();
        let accepted = !self.handles.is_stopped()
            && state.stopped_at.is_none()
            && !state.initial_disable_active
            && !pending
            && held.first_failure.is_none()
            && held.timely_joined_at.is_some()
            && generation_current
            && now < call.admission.deadline
            && state.selected_addresses == call.admission.selected
            && state.sequence == call.admission.sequence
            && state.execution.profile_generation == call.admission.profile_generation;
        let error = (!accepted).then(|| {
            "original initial-disable immediate transition is unjoined, stale, late or terminal"
                .to_string()
        });
        held.consumption_checks.push(ConsumptionCheck {
            observed_at: now,
            accepted,
            error: error.clone(),
        });
        if !accepted {
            // A harmless pending-status query does not cancel active work. A
            // failed consumption of an already joined sweep is terminal.
            if held.timely_joined_at.is_some() {
                self.handles.fence();
                state.stop(
                    error
                        .as_deref()
                        .expect("failed consumption reason retained"),
                );
                held.first_failure
                    .get_or_insert_with(|| error.clone().unwrap());
            }
            return Err("original initial-disable caller and workers are not timely joined".into());
        }
        Ok(())
    }
}

struct PendingWait {
    state: Arc<Mutex<State>>,
    handles: Handles,
    history: Arc<Mutex<History>>,
    index: usize,
    armed: bool,
}
impl Drop for PendingWait {
    fn drop(&mut self) {
        if self.armed {
            stop(
                &self.state,
                &self.handles,
                "initial-disable join cancelled; originals retained",
            );
            let mut held = history(&self.history);
            held.waits[self.index].cancelled_at = Some(Instant::now());
            held.first_failure
                .get_or_insert_with(|| "initial-disable join cancelled; originals retained".into());
        }
    }
}

pub(super) async fn join_until(
    retained: &mut Retained,
    state: &Arc<Mutex<State>>,
    handles: &Handles,
    deadline: Instant,
    cleanup: bool,
) -> bool {
    let Some(call) = retained.caller.as_mut() else {
        return cleanup;
    };
    let index = {
        let mut held = history(&call.history);
        let index = held.waits.len();
        held.waits.push(WaitObservation {
            started_at: Instant::now(),
            deadline,
            cleanup,
            caller_joined_at: None,
            worker_finalized_observed_at: None,
            returned_at: None,
            timed_out_at: None,
            cancelled_at: None,
            error: None,
        });
        index
    };
    let mut pending = PendingWait {
        state: state.clone(),
        handles: handles.clone(),
        history: call.history.clone(),
        index,
        armed: true,
    };
    if let Some(task) = call.task.as_mut() {
        let result = if Instant::now() >= deadline {
            None
        } else {
            tokio::select! {
                result = task => Some(result),
                _ = tokio::time::sleep_until(deadline.into()) => None,
            }
        };
        if let Some(result) = result {
            call.task = None;
            let observed_at = Instant::now();
            let mut held = history(&call.history);
            held.joined_at = Some(observed_at);
            held.waits[index].caller_joined_at = Some(observed_at);
            if let Err(error) = result {
                held.join_error = Some(error.to_string());
                held.waits[index].error = Some(error.to_string());
                held.first_failure.get_or_insert_with(|| error.to_string());
            }
        }
    }
    while call.task.is_none() && call.original.worker_pending() && Instant::now() < deadline {
        let next = (Instant::now() + Duration::from_millis(5)).min(deadline);
        tokio::time::sleep_until(next.into()).await;
    }
    let original = call.original.snapshot();
    let worker_pending = call.original.worker_pending();
    let mut management = lock(state, handles);
    let mut held = history(&call.history);
    let joined = call.task.is_none() && !worker_pending;
    let generation_current = call.original.final_generation_current();
    let now = Instant::now();
    if joined && original.slots.iter().any(|slot| slot.enqueued_at.is_some()) {
        held.waits[index].worker_finalized_observed_at = Some(now);
    }
    let completed = joined
        && generation_current
        && !handles.is_stopped()
        && management.stopped_at.is_none()
        && management.initial_disable_active
        && management.selected_addresses == call.admission.selected
        && management.sequence == call.admission.sequence
        && management.execution.profile_generation == call.admission.profile_generation
        && original.caller_returned_at.is_some()
        && original.caller_finalized_at.is_some()
        && original.first_failure.is_none()
        && original.caller_unwound_at.is_none()
        && held.joined_at.is_some()
        && held.join_error.is_none()
        && held.first_failure.is_none()
        && original.slots.iter().all(|slot| {
            slot.timely_receipt_at.is_some()
                && slot.committed_generation.is_some()
                && slot.generation_observed_after_worker_receipt == slot.committed_generation
                && slot.caller_error.is_none()
                && slot.worker.failure.is_none()
                && slot.worker.transport_completed_at.is_some()
                && slot
                    .worker
                    .worker_finalized_at
                    .is_some_and(|at| at < original.original_deadline)
        });
    let accepted_at = Instant::now();
    let completed = completed && accepted_at < deadline && accepted_at < original.original_deadline;
    held.waits[index].returned_at = Some(accepted_at);
    if !cleanup && completed {
        // Only actual timely caller AND worker joins reopen ordinary phase
        // admission. This never clears either service's terminal SafeOff bit.
        management.initial_disable_active = false;
        held.timely_joined_at = Some(accepted_at);
    } else if !cleanup || !joined || accepted_at >= deadline {
        handles.fence();
        management.stop("initial-disable sweep join failed or exceeded original deadline");
        if accepted_at >= deadline {
            held.waits[index].timed_out_at = Some(accepted_at);
        }
        held.first_failure.get_or_insert_with(|| {
            original.first_failure.clone().unwrap_or_else(|| {
                "initial-disable sweep join failed or exceeded original deadline".into()
            })
        });
    }
    pending.armed = false;
    if cleanup {
        joined && accepted_at < deadline
    } else {
        completed
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_management_owner_initial_disable_tests.rs"]
mod tests;
