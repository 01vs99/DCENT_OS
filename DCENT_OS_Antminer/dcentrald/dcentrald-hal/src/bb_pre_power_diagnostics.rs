//! Retain both original BB diagnostic workers before any future power recipe.
//!
//! Complete data is historical, never field freshness, power or startup
//! authority. Cancellation fences both normal lanes; actual caller joins and
//! exact service close receipts remain separate observations on retained owners.
use crate::bb_apw_diagnostic_owner::{
    BbApwDiagnosticData, BbApwDiagnosticOwner, BbApwDiagnosticSnapshot,
};
use crate::i2c::{
    I2cServiceCloseReceipt, I2cServiceOwner, I2cServiceTerminalFence, TerminalSafeOffTransition,
};
use crate::platform::bb_bus0_diagnostic::{
    BbBus0Diagnostic, BbBus0DiagnosticData, BbBus0DiagnosticSnapshot,
};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

#[derive(Clone, Debug)]
pub(crate) struct BbPrePowerHistoricalData {
    pub bus0: BbBus0DiagnosticData,
    pub apw: BbApwDiagnosticData,
    pub both_observed_at: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct BbPairedDiagnosticStop {
    pub observed_at: Instant,
    pub reason: String,
    /// Actual terminal admission transitions, never physical cutoff receipts.
    pub bus0: TerminalSafeOffTransition,
    pub bus1: TerminalSafeOffTransition,
}

#[derive(Clone, Debug)]
pub(crate) struct BbPairedServiceCloseAttempt {
    pub deadline: Instant,
    pub began_at: Instant,
    pub bus0_error: Option<String>,
    pub bus1_error: Option<String>,
    pub returned_at: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct BbPrePowerDiagnosticSnapshot {
    pub original_deadline: Option<Instant>,
    pub selected_addresses: Vec<u8>,
    pub bus0: BbBus0DiagnosticSnapshot,
    pub apw: BbApwDiagnosticSnapshot,
    pub stop: Option<BbPairedDiagnosticStop>,
    pub both_callers_joined_observed_at: Option<Instant>,
    /// A previously complete diagnostic stays readable after time or stop.
    /// No method exposes it as a fresh readiness or energizing capability.
    pub historical: Option<BbPrePowerHistoricalData>,
    pub close_attempts: Vec<BbPairedServiceCloseAttempt>,
}

#[derive(Clone)]
struct Fences {
    bus0: I2cServiceTerminalFence,
    bus1: I2cServiceTerminalFence,
}

impl Fences {
    fn latch(&self, reason: &str) -> BbPairedDiagnosticStop {
        let bus0 = self.bus0.latch_terminal_safe_off();
        let bus1 = self.bus1.latch_terminal_safe_off();
        BbPairedDiagnosticStop {
            observed_at: Instant::now(),
            reason: reason.into(),
            bus0,
            bus1,
        }
    }
}

#[derive(Default)]
struct State {
    original_deadline: Option<Instant>,
    selected_addresses: Vec<u8>,
    stop: Option<BbPairedDiagnosticStop>,
    both_callers_joined_observed_at: Option<Instant>,
    historical: Option<BbPrePowerHistoricalData>,
    close_attempts: Vec<BbPairedServiceCloseAttempt>,
}

fn lock<'a>(state: &'a Mutex<State>, fences: &Fences) -> MutexGuard<'a, State> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poison) => {
            let stopped = fences.latch("BB paired diagnostic state poisoned");
            let mut guard = poison.into_inner();
            guard.stop.get_or_insert(stopped);
            guard
        }
    }
}

fn stop(state: &Mutex<State>, fences: &Fences, reason: &str) {
    // Fence both services before taking the aggregate mutex or waiting for any
    // caller. Already-started kernel transfers remain separately joinable.
    let stopped = fences.latch(reason);
    lock(state, fences).stop.get_or_insert(stopped);
}

struct PendingObservation {
    state: Arc<Mutex<State>>,
    fences: Fences,
    armed: bool,
}

impl Drop for PendingObservation {
    fn drop(&mut self) {
        if self.armed {
            stop(
                &self.state,
                &self.fences,
                "BB paired diagnostic observation cancelled",
            );
        }
    }
}

pub(crate) struct BbPrePowerDiagnostics {
    bus0: BbBus0Diagnostic,
    apw: BbApwDiagnosticOwner,
    fences: Fences,
    supplied_buses: (u8, u8),
    state: Arc<Mutex<State>>,
    started: bool,
}

impl BbPrePowerDiagnostics {
    /// Consume each original service exactly once. Only sender-free terminal
    /// fences are retained alongside the existing diagnostic owners.
    pub(crate) fn new(bus0: I2cServiceOwner, bus1: I2cServiceOwner) -> Self {
        let supplied_buses = (bus0.request_handle().bus(), bus1.request_handle().bus());
        let fences = Fences {
            bus0: bus0.terminal_fence(),
            bus1: bus1.terminal_fence(),
        };
        Self {
            bus0: BbBus0Diagnostic::new(bus0),
            apw: BbApwDiagnosticOwner::new(bus1),
            fences,
            supplied_buses,
            state: Arc::new(Mutex::new(State::default())),
            started: false,
        }
    }

    pub(crate) fn snapshot(&self) -> BbPrePowerDiagnosticSnapshot {
        let state = lock(&self.state, &self.fences);
        BbPrePowerDiagnosticSnapshot {
            original_deadline: state.original_deadline,
            selected_addresses: state.selected_addresses.clone(),
            bus0: self.bus0.snapshot(),
            apw: self.apw.snapshot(),
            stop: state.stop.clone(),
            both_callers_joined_observed_at: state.both_callers_joined_observed_at,
            historical: state.historical.clone(),
            close_attempts: state.close_attempts.clone(),
        }
    }

    pub(crate) fn cancel(&self) {
        stop(&self.state, &self.fences, "BB paired diagnostics cancelled");
        self.bus0.cancel();
        self.apw.cancel();
    }

    /// One attempt under one original absolute deadline. Each child completion
    /// fences both lanes on failure before waiting for the other child. A
    /// dropped pending future retains both actual owners and all caller handles.
    pub(crate) async fn observe_once(
        &mut self,
        selected: &[u8],
        deadline: Instant,
    ) -> BbPrePowerDiagnosticSnapshot {
        if self.started {
            self.cancel();
            return self.snapshot();
        }
        self.started = true;
        {
            let mut state = lock(&self.state, &self.fences);
            state.original_deadline = Some(deadline);
            state.selected_addresses = selected.to_vec();
        }
        let mut pending = PendingObservation {
            state: self.state.clone(),
            fences: self.fences.clone(),
            armed: true,
        };
        // Reject both identities and all endpoint declarations before either
        // worker is started. No partial work on a valid half of a bad pair.
        let valid_selected = !selected.is_empty()
            && selected.len() <= 3
            && selected.iter().enumerate().all(|(index, address)| {
                (0x50..=0x52).contains(address) && !selected[..index].contains(address)
            });
        if self.supplied_buses != (0, 1)
            || !valid_selected
            || Instant::now() >= deadline
            || lock(&self.state, &self.fences).stop.is_some()
        {
            stop(
                &self.state,
                &self.fences,
                "BB paired diagnostic identity, endpoint or original deadline refused",
            );
        } else {
            if let Err(error) = self.bus0.start(selected, deadline) {
                stop(
                    &self.state,
                    &self.fences,
                    &format!("BB bus-0 diagnostic start refused: {error}"),
                );
            }
            if let Err(error) = self.apw.start(deadline) {
                stop(
                    &self.state,
                    &self.fences,
                    &format!("BB APW diagnostic start refused: {error}"),
                );
            }
            let state = &self.state;
            let fences = &self.fences;
            let bus0 = &mut self.bus0;
            let apw = &mut self.apw;
            let (joined0, joined1) = tokio::join!(
                async {
                    let joined = bus0.join_until(deadline).await;
                    let snapshot = bus0.snapshot();
                    if !joined || snapshot.failure.is_some() || snapshot.data.is_none() {
                        stop(
                            state,
                            fences,
                            &format!("BB bus-0 diagnostic incomplete: {:?}", snapshot.failure),
                        );
                    }
                    joined
                },
                async {
                    let joined = apw.join_until(deadline).await;
                    let snapshot = apw.snapshot();
                    if !joined || snapshot.failure.is_some() || snapshot.data.is_none() {
                        stop(
                            state,
                            fences,
                            &format!("BB APW diagnostic incomplete: {:?}", snapshot.failure),
                        );
                    }
                    joined
                }
            );
            let observed = Instant::now();
            if observed >= deadline {
                stop(
                    &self.state,
                    &self.fences,
                    "BB paired diagnostics observed after original deadline",
                );
            }
            let mut state = lock(&self.state, &self.fences);
            if joined0 && joined1 {
                state.both_callers_joined_observed_at = Some(observed);
                if state.stop.is_none() {
                    if let (Some(bus0), Some(apw)) =
                        (self.bus0.snapshot().data, self.apw.snapshot().data)
                    {
                        state.historical = Some(BbPrePowerHistoricalData {
                            bus0,
                            apw,
                            both_observed_at: observed,
                        });
                    }
                }
            }
        }
        pending.armed = false;
        self.snapshot()
    }

    /// Cleanup can observe later joins without extending the original data
    /// deadline or reopening either normal lane. A cancelled cleanup retains
    /// the original child handles for the next explicit cleanup attempt.
    pub(crate) async fn join_callers_until(&mut self, deadline: Instant) -> bool {
        self.cancel();
        let mut pending = PendingObservation {
            state: self.state.clone(),
            fences: self.fences.clone(),
            armed: true,
        };
        let (bus0, apw) = tokio::join!(
            self.bus0.join_until(deadline),
            self.apw.join_until(deadline)
        );
        if bus0 && apw {
            lock(&self.state, &self.fences)
                .both_callers_joined_observed_at
                .get_or_insert_with(Instant::now);
        }
        pending.armed = false;
        bus0 && apw
    }

    /// Synchronous teardown only, after actual caller joins. Always attempt
    /// both original service closes under the same supplied cleanup deadline,
    /// retaining independent errors and move-only close receipts for retry.
    pub(crate) fn close_services_until(&mut self, deadline: Instant) -> bool {
        self.cancel();
        let began_at = Instant::now();
        let bus0_error = self.bus0.close_service_until(deadline).err();
        let bus1_error = self.apw.close_service_until(deadline).err();
        lock(&self.state, &self.fences)
            .close_attempts
            .push(BbPairedServiceCloseAttempt {
                deadline,
                began_at,
                bus0_error,
                bus1_error,
                returned_at: Instant::now(),
            });
        self.bus0.close_receipt().is_some() && self.apw.close_receipt().is_some()
    }

    pub(crate) fn close_receipts(
        &self,
    ) -> (
        Option<&I2cServiceCloseReceipt>,
        Option<&I2cServiceCloseReceipt>,
    ) {
        (self.bus0.close_receipt(), self.apw.close_receipt())
    }
}

impl Drop for BbPrePowerDiagnostics {
    fn drop(&mut self) {
        self.cancel();
        // A terminal fence is not a join, a worker-close receipt or physical
        // power-off. The future runtime must retain this owner through cleanup.
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_pre_power_diagnostics_tests.rs"]
mod tests;
