//! Opaque cross-crate lifetime for the original BB management workers.
//! Constructors with real service owners remain inside HAL. Observations are
//! historical data; neither snapshots nor terminal fences authorize rail power.
pub use crate::bb_management_owner::{
    BbHeartbeatCutoff, BbHeartbeatCutoffObservation, BbHeartbeatPicObservation,
    BbHeartbeatReleaseObservation, BbHeartbeatRound, BbHeartbeatSnapshot, BbTerminalOperation,
    BbTerminalPicObservation, BbTerminalStepObservation, BbTerminalSweepObservation,
    BbTerminalWorkerObservation,
};
use crate::bb_management_owner::{BbManagementOwner, BbManagementSnapshot};
use crate::i2c::{I2cServiceCloseReceipt, I2cServiceOwner, I2cServiceTerminalFence};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Instant;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct BbManagementStop {
    bus0: I2cServiceTerminalFence,
    bus1: I2cServiceTerminalFence,
    stopped: Arc<AtomicBool>,
}
impl BbManagementStop {
    pub fn stop(&self) {
        self.bus0.latch_terminal_safe_off();
        self.bus1.latch_terminal_safe_off();
        self.stopped.store(true, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug)]
pub struct BbManagementObservation {
    inner: BbManagementSnapshot,
    stopped: bool,
}
impl BbManagementObservation {
    pub fn stopped(&self) -> bool {
        self.stopped || self.inner.stopped_at.is_some()
    }
    pub fn diagnostic_complete(&self) -> bool {
        self.inner.diagnostics.historical.is_some()
    }
    pub fn factory(&self) -> Option<&dcentrald_api_types::bb_factory_profile::BbFactoryCollection> {
        self.inner
            .diagnostics
            .historical
            .as_ref()
            .map(|data| &data.bus0.selected_inventory.factory)
    }
    pub fn last_pair_sequence(&self) -> Option<u64> {
        self.inner
            .last_complete_pair
            .as_ref()
            .map(|data| data.sequence)
    }
    pub fn last_execution_sequence(&self) -> Option<u64> {
        self.inner
            .last_complete_execution
            .as_ref()
            .map(|data| data.sequence)
    }
    pub fn profile_generation(&self) -> u64 {
        self.inner.profile_generation
    }
}

#[derive(Clone, Debug)]
pub struct BbManagementCloseObservation {
    pub attempt: u64,
    pub deadline: Instant,
    pub started_at: Instant,
    pub services_returned_at: Option<Instant>,
    pub both_service_receipts: bool,
    pub caller_joined_at: Option<Instant>,
    pub failure: Option<String>,
}

struct Pending(BbManagementStop);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.stop();
    }
}

struct PendingWarmup {
    stop: BbManagementStop,
    armed: bool,
}
impl Drop for PendingWarmup {
    fn drop(&mut self) {
        if self.armed {
            self.stop.stop();
        }
    }
}

/// Read-only retained prefix data. It cannot construct a phase/rail token.
#[derive(Clone, Debug)]
pub struct BbInitialBridgeObservation {
    inner: crate::bb_management_owner::BbInitialBridgeData,
}
impl BbInitialBridgeObservation {
    pub fn selected_eeproms(&self) -> &[u8] { &self.inner.selected_addresses }
    pub fn original_deadline(&self) -> Instant { self.inner.original_deadline }
    pub fn initial_disable_joined_at(&self) -> Option<Instant> { self.inner.initial_disable_joined_at }
    pub fn bridge_calls(&self) -> usize { self.inner.calls.len() }
    pub fn accepted_at(&self) -> Option<Instant> { self.inner.accepted_at }
    pub fn caller_or_worker_pending(&self) -> bool { self.inner.original_callers_pending }
    pub fn failure(&self) -> Option<&str> { self.inner.first_failure.as_deref() }
}

pub struct BbManagementRuntime {
    owner: Option<BbManagementOwner>,
    stop: BbManagementStop,
    close_caller: Option<JoinHandle<(BbManagementOwner, Result<bool, String>)>>,
    close_record: Arc<Mutex<Option<BbManagementCloseObservation>>>,
    retained: BbManagementSnapshot,
}

impl BbManagementRuntime {
    pub(crate) fn new(bus0: I2cServiceOwner, bus1: I2cServiceOwner) -> Self {
        let stop = BbManagementStop {
            bus0: bus0.terminal_fence(),
            bus1: bus1.terminal_fence(),
            stopped: Arc::new(AtomicBool::new(false)),
        };
        let owner = BbManagementOwner::new(bus0, bus1);
        let retained = owner.snapshot();
        Self {
            owner: Some(owner),
            stop,
            close_caller: None,
            close_record: Arc::new(Mutex::new(None)),
            retained,
        }
    }
    pub fn stop_handle(&self) -> BbManagementStop {
        self.stop.clone()
    }
    pub fn cancel(&self) {
        self.stop.stop();
    }
    pub fn snapshot(&self) -> BbManagementObservation {
        BbManagementObservation {
            inner: self
                .owner
                .as_ref()
                .map(|owner| owner.snapshot())
                .unwrap_or_else(|| self.retained.clone()),
            stopped: self.stop.stopped.load(Ordering::SeqCst),
        }
    }
    pub fn close_observation(&self) -> Option<BbManagementCloseObservation> {
        self.close_record
            .lock()
            .unwrap_or_else(|poison| {
                self.cancel();
                poison.into_inner()
            })
            .clone()
    }
    pub fn close_caller_pending(&self) -> bool {
        self.close_caller.is_some()
    }
    pub fn close_receipts(
        &self,
    ) -> (
        Option<&I2cServiceCloseReceipt>,
        Option<&I2cServiceCloseReceipt>,
    ) {
        self.owner
            .as_ref()
            .map(|owner| owner.close_receipts())
            .unwrap_or((None, None))
    }
    fn active(&mut self) -> Result<&mut BbManagementOwner, String> {
        if self.stop.stopped.load(Ordering::SeqCst) || self.close_caller.is_some() {
            return Err("BB management is terminal or closing".into());
        }
        self.owner
            .as_mut()
            .ok_or_else(|| "BB original management owner unavailable".into())
    }
    /// Same original owner: disable, immediate consumption and actual Bridge
    /// calls share one deadline. This prefix starts no steady heartbeat/voltage.
    pub async fn initial_disable_and_bridges_until(&mut self, deadline: Instant) -> Result<(), String> {
        let mut pending = PendingWarmup { stop: self.stop.clone(), armed: true };
        let result = self.active()?.initial_disable_and_bridges_until(deadline).await;
        if result.is_ok() { pending.armed = false; }
        result
    }

    /// None while a blocking close caller temporarily owns the actual manager;
    /// snapshots never stand in for that retained owner or a pending worker.
    pub fn initial_bridge_observation(&self) -> Option<BbInitialBridgeObservation> {
        self.owner.as_ref().and_then(|owner| owner.initial_bridge_snapshot())
            .map(|inner| BbInitialBridgeObservation { inner })
    }

    pub fn start_heartbeat(&mut self, cutoff: Arc<dyn BbHeartbeatCutoff>) -> Result<(), String> {
        self.active()?.start_heartbeat(cutoff)
    }

    pub fn heartbeat_snapshot(&self) -> Option<BbHeartbeatSnapshot> {
        self.owner
            .as_ref()
            .and_then(|owner| owner.heartbeat_snapshot())
            .or_else(|| self.retained.heartbeat.clone())
    }

    pub fn terminal_snapshot(&self) -> Option<BbTerminalSweepObservation> {
        self.owner
            .as_ref()
            .and_then(|owner| owner.terminal_snapshot())
            .or_else(|| self.retained.terminal.clone())
    }

    pub fn heartbeat_release_observation(&self) -> Option<BbHeartbeatReleaseObservation> {
        self.owner
            .as_ref()
            .and_then(|owner| owner.snapshot().heartbeat_release)
            .or_else(|| self.retained.heartbeat_release.clone())
    }

    pub async fn wait_stable_heartbeat_until(
        &mut self,
        deadline: Instant,
    ) -> Result<BbHeartbeatSnapshot, String> {
        let mut pending = PendingWarmup {
            stop: self.stop.clone(),
            armed: true,
        };
        let result = self.active()?.wait_stable_heartbeat_until(deadline).await;
        if result.is_ok() {
            pending.armed = false;
        }
        result
    }

    pub fn release_joined_heartbeat_cutoff(&mut self) -> Result<bool, String> {
        if self.close_caller.is_some() {
            return Err("BB management close caller still owns the actual manager".into());
        }
        self.owner
            .as_mut()
            .ok_or("BB original manager unavailable for cutoff release")?
            .release_joined_heartbeat_cutoff()
    }

    /// Returns historical/policy data, never an energizing or terminal token.
    pub fn require_stable_heartbeat(&self) -> Result<BbHeartbeatSnapshot, String> {
        if self.stop.stopped.load(Ordering::SeqCst) || self.close_caller.is_some() {
            return Err("BB heartbeat original runtime is terminal or closing".into());
        }
        self.owner
            .as_ref()
            .ok_or("BB heartbeat original owner unavailable")?
            .require_stable_heartbeat()
    }

    pub fn stop_heartbeat(&self) {
        self.stop.stop();
        if let Some(owner) = self.owner.as_ref() {
            owner.stop_heartbeat();
        }
    }

    pub fn merge_requested_voltage(
        &mut self,
        target: Option<f64>,
        maximum_step: Option<f64>,
    ) -> Result<(), String> {
        self.active()?.merge_requested_voltage(target, maximum_step)
    }
    pub async fn observe_initial_until(
        &mut self,
        selected: &[u8],
        deadline: Instant,
    ) -> Result<BbManagementObservation, String> {
        self.active()?
            .observe_pre_power_once(selected, deadline)
            .await;
        Ok(self.snapshot())
    }
    pub async fn observe_runtime_until(
        &mut self,
        deadline: Instant,
    ) -> Result<BbManagementObservation, String> {
        self.active()?.observe_runtime_once(deadline).await?;
        Ok(self.snapshot())
    }
    pub async fn execute_voltage_until(
        &mut self,
        deadline: Instant,
    ) -> Result<BbManagementObservation, String> {
        self.active()?.execute_voltage_once(deadline).await?;
        Ok(self.snapshot())
    }

    /// Explicitly retain this object outside cancelled operation/cleanup futures.
    /// Actual service-worker joins and the blocking close-caller join are distinct.
    /// A failed service close restores the same manager for a later cleanup retry.
    /// The original actor's cutoff callback is released after actual actor and
    /// management caller joins, before either service close. Its final snapshot,
    /// callback result and release failures remain historical observations.
    pub async fn close_until(&mut self, deadline: Instant) -> bool {
        self.close_with(deadline, || {}).await
    }
    async fn close_with(
        &mut self,
        deadline: Instant,
        after_record: impl FnOnce() + Send + 'static,
    ) -> bool {
        self.cancel();
        let _pending = Pending(self.stop.clone());
        if self.close_caller.is_none() {
            let Some(owner) = self.owner.as_mut() else {
                return false;
            };
            if !owner.join_callers_until(deadline).await {
                return false;
            }
            if owner.release_joined_heartbeat_cutoff().is_err() {
                return false;
            }
            let receipts = owner.close_receipts();
            if receipts.0.is_some()
                && receipts.1.is_some()
                && self.close_observation().is_some_and(|record| {
                    record.caller_joined_at.is_some() && record.failure.is_none()
                })
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            let attempt = match self.close_observation() {
                Some(record) => match record.attempt.checked_add(1) {
                    Some(value) => value,
                    None => return false,
                },
                None => 1,
            };
            let mut owner = self
                .owner
                .take()
                .expect("original manager retained before close");
            self.retained = owner.snapshot();
            *self
                .close_record
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) =
                Some(BbManagementCloseObservation {
                    attempt,
                    deadline,
                    started_at: Instant::now(),
                    services_returned_at: None,
                    both_service_receipts: false,
                    caller_joined_at: None,
                    failure: None,
                });
            let record = self.close_record.clone();
            self.close_caller = Some(tokio::task::spawn_blocking(move || {
                // Keep the sole manager outside both catch scopes, including
                // the fixture tail. A caught unwind cannot discard its workers.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    owner.close_services_until(deadline)
                }))
                .unwrap_or_else(|_| Err("BB management close unwound".into()));
                {
                    let mut state = record.lock().unwrap_or_else(|poison| poison.into_inner());
                    let state = state.as_mut().expect("reserved actual close record");
                    state.services_returned_at = Some(Instant::now());
                    let receipts = owner.close_receipts();
                    state.both_service_receipts = receipts.0.is_some() && receipts.1.is_some();
                    state.failure = outcome.as_ref().err().cloned();
                }
                let outcome = if std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    after_record,
                ))
                .is_err()
                {
                    Err("BB close caller tail unwound".into())
                } else {
                    outcome
                };
                (owner, outcome)
            }));
        }
        if Instant::now() >= deadline {
            return false;
        }
        let joined = tokio::select! {
            value = self.close_caller.as_mut().expect("actual close caller retained") => Some(value),
            _ = tokio::time::sleep_until(deadline.into()) => None,
        };
        let Some(joined) = joined else {
            return false;
        };
        self.close_caller = None;
        let now = Instant::now();
        let result = match joined {
            Ok((owner, outcome)) => {
                self.retained = owner.snapshot();
                self.owner = Some(owner);
                outcome
            }
            Err(error) => Err(format!("BB close caller failed: {error}")),
        };
        let mut state = self
            .close_record
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let record = state.as_mut().expect("joined caller retained close record");
        record.caller_joined_at = Some(now);
        record.failure = result.as_ref().err().cloned();
        matches!(result, Ok(true)) && record.both_service_receipts && now < deadline
    }
}
impl Drop for BbManagementRuntime {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(feature = "sim-hal")]
#[path = "bb_management_runtime_wire_sim.rs"]
pub(crate) mod wire_sim;

#[cfg(feature = "sim-hal")]
#[path = "bb_management_runtime_sim.rs"]
#[doc(hidden)]
pub mod simulated;

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_management_runtime_tests.rs"]
mod tests;
