//! Detached retained bus-1 APW diagnostic lifetime, before any power recipe.
//!
//! Owns the existing service and one fixed-profile blocking caller. No device,
//! frame, cached identity, checked DTO or readiness capability is accepted.
//! All returned data is historical; caller join and service close are separate.
use crate::bb_apw_diagnostics::ProfileAttempt;
use crate::i2c::{I2cServiceCloseReceipt, I2cServiceHandle, I2cServiceOwner};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub(crate) struct BbApwDiagnosticData {
    pub profile: ProfileAttempt,
    pub observed_complete_at: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct BbApwDiagnosticSnapshot {
    pub deadline: Option<Instant>,
    /// Caller timestamps, never actual bus-stage start or rail-sampling times.
    pub caller_prepared_at: Option<Instant>,
    pub caller_returned_at: Option<Instant>,
    pub caller_joined_at: Option<Instant>,
    /// Complete result returned by the fixed profile method, including every
    /// available earlier/rejected phase. Internal unavailable bytes stay absent.
    pub attempt: Option<ProfileAttempt>,
    pub stopped_at: Option<Instant>,
    pub failure: Option<String>,
    pub data: Option<BbApwDiagnosticData>,
    pub service_close_observed_at: Option<Instant>,
}

struct State {
    snapshot: BbApwDiagnosticSnapshot,
}

impl State {
    fn stop(&mut self, reason: String) {
        self.snapshot.stopped_at.get_or_insert_with(Instant::now);
        self.snapshot.failure.get_or_insert(reason);
        self.snapshot.data = None;
    }

    fn can_continue(&mut self, handle: &I2cServiceHandle) -> bool {
        if self
            .snapshot
            .deadline
            .is_none_or(|limit| Instant::now() >= limit)
        {
            self.stop("BB APW owner original deadline elapsed or absent".into());
        }
        if handle.terminal_safe_off_is_latched() {
            self.stop("BB APW owner observed terminal service latch".into());
        }
        self.snapshot.stopped_at.is_none()
    }
}

fn state_lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poison) => {
            let mut guard = poison.into_inner();
            guard.stop("BB APW diagnostic state poisoned".into());
            guard
        }
    }
}

fn stop_and_fence(state: &Mutex<State>, handle: &I2cServiceHandle, reason: &str) {
    state_lock(state).stop(reason.into());
    // This closes normal-lane admission on the actual service. It neither
    // interrupts an already-started kernel transfer nor switches physical power.
    handle.latch_terminal_safe_off();
}

struct PendingJoinCancellation {
    state: Arc<Mutex<State>>,
    handle: I2cServiceHandle,
    armed: bool,
}

impl Drop for PendingJoinCancellation {
    fn drop(&mut self) {
        if self.armed {
            stop_and_fence(&self.state, &self.handle, "BB APW pending join cancelled");
        }
    }
}

/// Move-only retained lifetime. Explicit caller join and a separately observed
/// synchronous service close must precede any future enclosing-owner disposal.
pub(crate) struct BbApwDiagnosticOwner {
    owner: I2cServiceOwner,
    handle: I2cServiceHandle,
    task: Option<JoinHandle<()>>,
    state: Arc<Mutex<State>>,
    started: bool,
    close_receipt: Option<I2cServiceCloseReceipt>,
}

impl BbApwDiagnosticOwner {
    pub(crate) fn new(owner: I2cServiceOwner) -> Self {
        let handle = owner.request_handle();
        Self {
            owner,
            handle,
            task: None,
            started: false,
            close_receipt: None,
            state: Arc::new(Mutex::new(State {
                snapshot: BbApwDiagnosticSnapshot {
                    deadline: None,
                    caller_prepared_at: None,
                    caller_returned_at: None,
                    caller_joined_at: None,
                    attempt: None,
                    stopped_at: None,
                    failure: None,
                    data: None,
                    service_close_observed_at: None,
                },
            })),
        }
    }

    /// One fixed diagnostic attempt, including refused admission. Must run in
    /// the enclosing Tokio runtime; no second adapter/service is constructed.
    pub(crate) fn start(&mut self, deadline: Instant) -> Result<(), String> {
        if self.started {
            return Err("BB APW diagnostic attempt already consumed".into());
        }
        self.started = true;
        let mut state = state_lock(&self.state);
        state.snapshot.deadline = Some(deadline);
        if self.handle.bus() != 1 {
            state.stop("BB APW diagnostic requires the retained bus-1 owner".into());
        }
        if !state.can_continue(&self.handle) {
            return Err(state.snapshot.failure.clone().expect("refusal retained"));
        }
        drop(state);
        let shared = Arc::clone(&self.state);
        let handle = self.handle.clone();
        self.task = Some(tokio::task::spawn_blocking(move || {
            {
                let mut state = state_lock(&shared);
                if !state.can_continue(&handle) {
                    return;
                }
                state.snapshot.caller_prepared_at = Some(Instant::now());
            }
            // A prepared call may enter after cancellation; the real terminal
            // fence and fixed method's checks bound further normal admission.
            let attempt = handle.read_bb_apw_profile_at(deadline);
            let mut state = state_lock(&shared);
            state.snapshot.caller_returned_at = Some(Instant::now());
            let failure = attempt.failure.clone();
            let completed = attempt.caller_completed_at.is_some();
            state.snapshot.attempt = Some(attempt);
            if let Some(error) = failure {
                state.stop(format!("BB APW fixed profile failed: {error}"));
            } else if !completed {
                state.stop("BB APW fixed profile has no completed caller result".into());
            }
            state.can_continue(&handle);
        }));
        Ok(())
    }

    /// Existing snapshot clones remain historical after cancellation or time
    /// passing. This accessor grants no fresh field/rail or runtime authority.
    pub(crate) fn snapshot(&self) -> BbApwDiagnosticSnapshot {
        state_lock(&self.state).snapshot.clone()
    }

    /// Permanent promotion refusal and terminal normal-lane admission fence.
    /// Started transfers can still finish; available returned phases are kept.
    pub(crate) fn cancel(&self) {
        stop_and_fence(&self.state, &self.handle, "BB APW diagnostic cancelled");
    }

    /// True means the actual blocking caller was joined, or no caller existed.
    /// It does not imply accepted data, timeliness or actual service drain.
    /// Dropping this pending future retains the JoinHandle and permanently
    /// refuses promotion; a later cleanup call can still observe actual join.
    pub(crate) async fn join_until(&mut self, observe_deadline: Instant) -> bool {
        if state_lock(&self.state).snapshot.caller_joined_at.is_some() {
            return true;
        }
        if self.task.is_none() {
            return true;
        }
        if Instant::now() >= observe_deadline {
            self.cancel();
            return false;
        }
        let mut pending = PendingJoinCancellation {
            state: Arc::clone(&self.state),
            handle: self.handle.clone(),
            armed: true,
        };
        let task = self.task.as_mut().expect("actual caller retained");
        let result = tokio::select! {
            result = task => Some(result),
            _ = tokio::time::sleep_until(observe_deadline.into()) => None,
        };
        let Some(result) = result else {
            self.cancel();
            return false;
        };
        self.task = None;
        let observed = Instant::now();
        let mut state = state_lock(&self.state);
        state.snapshot.caller_joined_at = Some(observed);
        if let Err(error) = result {
            state.stop(format!("BB APW blocking caller failed: {error}"));
        } else if observed >= observe_deadline {
            state.stop("BB APW caller observed after join deadline".into());
        } else if state.can_continue(&self.handle) {
            if let Some(profile) = state.snapshot.attempt.clone().filter(|attempt| {
                attempt.failure.is_none() && attempt.caller_completed_at.is_some()
            }) {
                state.snapshot.data = Some(BbApwDiagnosticData {
                    profile,
                    observed_complete_at: observed,
                });
            } else {
                state.stop("BB APW actual caller returned no complete profile".into());
            }
        }
        pending.armed = false;
        true
    }

    /// Synchronous blocking teardown. The caller must first be joined; this
    /// method then closes/joins the exact retained service. A timeout preserves
    /// that owner for retry and never manufactures a close receipt.
    pub(crate) fn close_service_until(&mut self, deadline: Instant) -> Result<(), String> {
        self.cancel();
        if self.task.is_some() {
            return Err("BB APW caller must be joined before service close".into());
        }
        if self.close_receipt.is_some() {
            return Ok(());
        }
        let receipt = self
            .owner
            .close_and_join_until(deadline)
            .map_err(|error| error.to_string())?;
        self.close_receipt = Some(receipt);
        state_lock(&self.state).snapshot.service_close_observed_at = Some(Instant::now());
        Ok(())
    }

    pub(crate) fn close_receipt(&self) -> Option<&I2cServiceCloseReceipt> {
        self.close_receipt.as_ref()
    }
}

impl Drop for BbApwDiagnosticOwner {
    fn drop(&mut self) {
        self.cancel();
        // Dropped handles do not establish actual task/service exit or physical
        // voltage cutoff. The future enclosing runtime must complete both joins.
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_apw_diagnostic_owner_tests.rs"]
mod tests;
