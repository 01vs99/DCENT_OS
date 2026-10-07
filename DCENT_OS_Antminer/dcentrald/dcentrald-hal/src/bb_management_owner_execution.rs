//! Staged management integration: one retained caller and successful-request history.
//! This module supplies neither physical admission nor an ASIC/GPIO owner.
use super::{
    lock, runtime_bus0, stop, BbManagementOwner, BbManagementSnapshot, Handles, PendingActivity,
};
use crate::bb_voltage_planner::{Decision, History};
use crate::bb_voltage_profile::Hw76RequestedVoltageProfile;
use crate::i2c::bb_apw_voltage_execution::{execute, VoltageExecutionAttempt};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub(crate) struct BbOwnedExecutionObservation {
    pub sequence: u64,
    pub profile_generation: u64,
    pub deadline: Instant,
    pub requested_profile: Hw76RequestedVoltageProfile,
    pub prior_history: History,
    pub attempt: Option<VoltageExecutionAttempt>,
    pub caller_joined_at: Option<Instant>,
    /// Both selected bus0 and execution callers joined in this cycle. This is
    /// historical protocol completion, never physical freshness or convergence.
    pub accepted_at: Option<Instant>,
    pub failure: Option<String>,
    pub heartbeat_reserved_at: Instant,
    pub heartbeat_reserved_sweep: u64,
    pub heartbeat_caller_admitted_at: Option<Instant>,
    pub heartbeat_caller_sweep: Option<u64>,
}

pub(super) struct State {
    pub profile_generation: u64,
    pub history: History,
    pub latest: Option<BbOwnedExecutionObservation>,
    pub last_complete: Option<BbOwnedExecutionObservation>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            profile_generation: 0,
            history: History {
                previous_request: None,
                repeated_requests: 0,
            },
            latest: None,
            last_complete: None,
        }
    }
}

impl BbManagementOwner {
    /// Candidate entry for the enclosing cold/runtime controller. No production
    /// caller is registered. Selected bus0 observations join before the APW
    /// caller starts, and all work uses this one original absolute deadline.
    pub(crate) async fn execute_voltage_once(
        &mut self,
        deadline: Instant,
    ) -> Result<BbManagementSnapshot, String> {
        self.begin_execution(deadline)?;
        let mut pending = PendingActivity {
            state: self.state.clone(),
            handles: self.handles.clone(),
            armed: true,
        };
        self.bus0_task = Some(runtime_bus0::start(&self.state, &self.handles, deadline));
        let joined = runtime_bus0::join_until(
            &mut self.bus0_task,
            &self.state,
            &self.handles,
            deadline,
            true,
        )
        .await;
        if !joined || !self.start_execution_caller(deadline) {
            stop(
                &self.state,
                &self.handles,
                "BB execution lacks joined selected bus0 observations",
            );
            pending.armed = false;
            return Ok(self.snapshot());
        }
        join_until(
            &mut self.execution_task,
            &self.state,
            &self.handles,
            deadline,
            true,
        )
        .await;
        pending.armed = false;
        Ok(self.snapshot())
    }

    fn begin_execution(&mut self, deadline: Instant) -> Result<(), String> {
        let mut state = lock(&self.state, &self.handles);
        if self.execution_task.is_some()
            || self.voltage_task.is_some()
            || self.bus0_task.is_some()
            || !state.diagnostic_joined
            || Instant::now() >= deadline
            || !state.can_continue(&self.handles)
        {
            self.handles.fence();
            state.stop(
                "BB execution requires joined diagnostics, no pending caller and a live deadline",
            );
            return Err(state.stop_reason.clone().expect("stop recorded"));
        }
        let Some(actor) = self.heartbeat.as_ref() else {
            self.handles.fence();
            state.stop("BB voltage reservation requires the original retained heartbeat actor");
            return Err(state.stop_reason.clone().expect("stop recorded"));
        };
        let admitted = actor.voltage_gate().observe(deadline).map_err(|reason| {
            self.handles.fence();
            state.stop(&reason);
            reason
        })?;
        let Some(sequence) = state.sequence.checked_add(1) else {
            self.handles.fence();
            state.stop("BB execution sequence exhausted");
            return Err(state.stop_reason.clone().expect("stop recorded"));
        };
        state.sequence = sequence;
        state.execution.latest = Some(BbOwnedExecutionObservation {
            sequence,
            profile_generation: state.execution.profile_generation,
            deadline,
            requested_profile: state.profile,
            prior_history: state.execution.history,
            attempt: None,
            caller_joined_at: None,
            accepted_at: None,
            failure: None,
            heartbeat_reserved_at: admitted.observed_at,
            heartbeat_reserved_sweep: admitted.complete_sweeps,
            heartbeat_caller_admitted_at: None,
            heartbeat_caller_sweep: None,
        });
        Ok(())
    }

    fn start_execution_caller(&mut self, deadline: Instant) -> bool {
        let Some(actor) = self.heartbeat.as_ref() else {
            return false;
        };
        let heartbeat = actor.voltage_gate();
        let mut state = lock(&self.state, &self.handles);
        let ready = self.execution_task.is_none()
            && self.voltage_task.is_none()
            && self.bus0_task.is_none()
            && Instant::now() < deadline
            && state.can_continue(&self.handles)
            && state.latest_bus0.as_ref().is_some_and(|bus0| {
                bus0.accepted_at.is_some()
                    && bus0.sequence == state.sequence
                    && bus0.deadline == deadline
            })
            && state.execution.latest.as_ref().is_some_and(|latest| {
                latest.sequence == state.sequence
                    && latest.deadline == deadline
                    && latest.attempt.is_none()
                    && latest.caller_joined_at.is_none()
            });
        if !ready {
            return false;
        }
        if let Err(reason) = heartbeat.observe(deadline) {
            state.stop(&reason);
            return false;
        }
        let operation = state
            .execution
            .latest
            .clone()
            .expect("current retained operation");
        drop(state);
        let shared = self.state.clone();
        let handles = self.handles.clone();
        self.execution_task = Some(tokio::task::spawn_blocking(move || {
            {
                let mut state = lock(&shared, &handles);
                // The real blocking caller may have waited in Tokio's pool.
                // Recheck the original actor after acquiring this state lock;
                // neither reservation time nor a cloned snapshot admits I/O.
                let admission = heartbeat.observe(deadline);
                match admission {
                    Ok(admitted) if state.can_continue(&handles) => {
                        let latest = state
                            .execution
                            .latest
                            .as_mut()
                            .expect("retained actual execution");
                        latest.heartbeat_caller_admitted_at = Some(admitted.observed_at);
                        latest.heartbeat_caller_sweep = Some(admitted.complete_sweeps);
                    }
                    result => {
                        let reason = result.err().unwrap_or_else(|| {
                            "BB actual voltage caller observed terminal management".into()
                        });
                        state
                            .execution
                            .latest
                            .as_mut()
                            .expect("retained actual execution")
                            .failure = Some(reason.clone());
                        handles.fence();
                        state.stop(&reason);
                        return;
                    }
                }
            }
            let attempt = execute(
                &handles.bus1,
                operation.requested_profile,
                operation.prior_history,
                deadline,
            );
            let completed = attempt.caller_completed_at.is_some();
            let failure = attempt.failure.clone();
            let mut state = lock(&shared, &handles);
            let latest = state
                .execution
                .latest
                .as_mut()
                .expect("pending operation retained until join");
            latest.attempt = Some(attempt);
            latest.failure = failure.clone();
            if failure.is_some() || !completed || Instant::now() >= deadline {
                handles.fence();
                state.stop("BB execution caller failed, incomplete or late");
            }
            state.can_continue(&handles);
        }));
        true
    }
}

pub(super) async fn join_until(
    task: &mut Option<JoinHandle<()>>,
    shared: &Arc<Mutex<super::State>>,
    handles: &Handles,
    deadline: Instant,
    promote: bool,
) -> bool {
    let Some(join) = task.as_mut() else {
        return true;
    };
    if Instant::now() >= deadline {
        stop(shared, handles, "BB execution join deadline elapsed");
        return false;
    }
    let mut pending = PendingActivity {
        state: shared.clone(),
        handles: handles.clone(),
        armed: true,
    };
    let result = tokio::select! {
        result = join => Some(result),
        _ = tokio::time::sleep_until(deadline.into()) => None,
    };
    let Some(result) = result else {
        stop(
            shared,
            handles,
            "BB execution caller was not joined before deadline",
        );
        return false;
    };
    *task = None;
    let now = Instant::now();
    let mut state = lock(shared, handles);
    let latest = state
        .execution
        .latest
        .as_mut()
        .expect("actual caller has retained operation");
    latest.caller_joined_at = Some(now);
    if let Err(error) = result {
        latest
            .failure
            .get_or_insert_with(|| format!("BB execution task failed: {error}"));
        handles.fence();
        state.stop("BB execution task failed");
    } else if now >= deadline || now >= latest.deadline {
        handles.fence();
        state.stop("BB execution caller joined after its original deadline");
    } else if promote && state.can_continue(handles) {
        match completed_history(&state, now) {
            Ok(history) => {
                if let Some(history) = history {
                    state.execution.history = history;
                }
                let latest = state
                    .execution
                    .latest
                    .as_mut()
                    .expect("actual retained operation");
                latest.accepted_at = Some(now);
                state.execution.last_complete = Some(latest.clone());
            }
            Err(error) => {
                state
                    .execution
                    .latest
                    .as_mut()
                    .expect("actual retained operation")
                    .failure
                    .get_or_insert(error);
                handles.fence();
                state.stop("BB execution joined result failed identity or completion checks");
            }
        }
    }
    pending.armed = false;
    true
}

fn completed_history(state: &super::State, now: Instant) -> Result<Option<History>, String> {
    let latest = state
        .execution
        .latest
        .as_ref()
        .ok_or("missing retained execution")?;
    if latest.sequence != state.sequence
        || latest.profile_generation != state.execution.profile_generation
        || latest.requested_profile != state.profile
        || latest.prior_history != state.execution.history
        || latest.deadline <= now
        || latest.failure.is_some()
        || latest.caller_joined_at != Some(now)
    {
        return Err("BB execution operation identity changed before join".into());
    }
    let bus0 = state
        .latest_bus0
        .as_ref()
        .ok_or("missing selected bus0 result")?;
    if bus0.sequence != latest.sequence
        || bus0.deadline != latest.deadline
        || bus0.accepted_at.is_none()
        || bus0.failure.is_some()
        || bus0.selected_addresses != state.selected_addresses
    {
        return Err("BB execution lacks its matching selected bus0 join".into());
    }
    let attempt = latest
        .attempt
        .as_ref()
        .ok_or("missing actual execution caller result")?;
    if attempt.deadline != latest.deadline
        || attempt.requested_profile != latest.requested_profile
        || attempt.prior_history != latest.prior_history
        || attempt.failure.is_some()
        || !attempt
            .caller_completed_at
            .is_some_and(|at| at <= now && at < latest.deadline)
    {
        return Err(
            "BB execution caller result is incomplete or belongs to another operation".into(),
        );
    }
    match attempt.plan {
        Some(plan) if matches!(plan.decision, Decision::Request(_)) => {
            let exchange = attempt
                .exchange
                .as_ref()
                .ok_or("request lacks the actual wire exchange")?;
            if exchange.phase != crate::bb_apw_voltage_exchange::Phase::Complete
                || exchange.failure.is_some()
                || exchange.protocol_completed_at.is_none()
                || exchange.deadline != latest.deadline
            {
                return Err("request exchange did not complete before join".into());
            }
            Ok(Some(plan.history))
        }
        _ if attempt.exchange.is_none() => Ok(None),
        _ => Err("non-request unexpectedly retained an electrical exchange".into()),
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_management_owner_execution_tests.rs"]
mod tests;

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_management_lifecycle_tests.rs"]
mod lifecycle_tests;
