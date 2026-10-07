//! Detached bus-0 diagnostic composition before any future power phase.
//!
//! The same actual service owner stays inside BbSelectedInventory. This wrapper
//! retains its private request-handle clone and one further LM75 caller task.
//! It creates no adapter, runtime admission token, global bridge/CPU selector,
//! or power operation. All four requested sensor labels are diagnostic probes,
//! independent of the unresolved original optional-startup selector.
use super::bb_selected_inventory::{
    BbSelectedInventory, BbSelectedInventoryData, BbSelectedInventorySnapshot,
};
use crate::bb_pic_lm75::{self, Sample};
use crate::i2c::{I2cServiceCloseReceipt, I2cServiceHandle, I2cServiceOwner};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub(crate) struct BbBridgeDiagnosticAttempt {
    pub factory_address: u8,
    pub native_slot: usize,
    pub pic_address: u8,
    pub sensor_address: u8,
    /// Caller timestamps only, not measured bus start or sensor sampling times.
    pub call_prepared_at: Instant,
    pub call_returned_at: Option<Instant>,
    /// Exactly what the synchronous method returned. Internal partial or late
    /// service bytes unavailable on Err remain unknown rather than padded.
    pub returned_reads: Option<Vec<Vec<u8>>>,
    /// Parser acceptance only; even late/cancelled bytes can be inspected here.
    pub decoded: Option<Sample>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct BbBus0DiagnosticData {
    pub selected_inventory: BbSelectedInventoryData,
    pub bridges: Vec<BbBridgeDiagnosticAttempt>,
    pub observed_complete_at: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct BbBus0DiagnosticSnapshot {
    pub deadline: Option<Instant>,
    pub inventory: BbSelectedInventorySnapshot,
    pub bridges: Vec<BbBridgeDiagnosticAttempt>,
    pub stopped_at: Option<Instant>,
    pub failure: Option<String>,
    pub bridge_task_joined_at: Option<Instant>,
    pub all_caller_tasks_joined_at: Option<Instant>,
    pub data: Option<BbBus0DiagnosticData>,
}

struct State {
    deadline: Option<Instant>,
    bridges: Vec<BbBridgeDiagnosticAttempt>,
    stopped_at: Option<Instant>,
    failure: Option<String>,
    bridge_task_joined_at: Option<Instant>,
    all_caller_tasks_joined_at: Option<Instant>,
    candidate: Option<BbBus0DiagnosticData>,
    data: Option<BbBus0DiagnosticData>,
}

impl State {
    fn stop(&mut self, detail: String) {
        self.stopped_at.get_or_insert_with(Instant::now);
        self.failure.get_or_insert(detail);
        self.candidate = None;
        self.data = None;
    }

    fn can_continue(&mut self, handle: &I2cServiceHandle) -> bool {
        if self.deadline.is_none_or(|limit| Instant::now() >= limit) {
            self.stop("BB bus-0 diagnostic original deadline elapsed or absent".into());
        }
        if handle.terminal_safe_off_is_latched() {
            self.stop("BB bus-0 diagnostic observed terminal service latch".into());
        }
        self.stopped_at.is_none()
    }
}

fn state_lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poison) => {
            let mut guard = poison.into_inner();
            guard.stop("BB bus-0 diagnostic state poisoned".into());
            guard
        }
    }
}

struct PendingJoinCancellation {
    state: Arc<Mutex<State>>,
    armed: bool,
}

impl Drop for PendingJoinCancellation {
    fn drop(&mut self) {
        if self.armed {
            state_lock(&self.state).stop("BB bus-0 diagnostic pending join cancelled".into());
        }
    }
}

/// Move-only ownership. Only `new` consumes a real service owner; no checked
/// inventory, bridge reply, caller DTO or replacement service can be supplied.
pub(crate) struct BbBus0Diagnostic {
    inventory: BbSelectedInventory,
    handle: I2cServiceHandle,
    bridge_task: Option<JoinHandle<()>>,
    state: Arc<Mutex<State>>,
    started: bool,
    bridge_started: bool,
}

impl BbBus0Diagnostic {
    pub(crate) fn new(owner: I2cServiceOwner) -> Self {
        let handle = owner.request_handle();
        Self {
            inventory: BbSelectedInventory::new(owner),
            handle,
            bridge_task: None,
            state: Arc::new(Mutex::new(State {
                deadline: None,
                bridges: Vec::new(),
                stopped_at: None,
                failure: None,
                bridge_task_joined_at: None,
                all_caller_tasks_joined_at: None,
                candidate: None,
                data: None,
            })),
            started: false,
            bridge_started: false,
        }
    }

    /// The existing selected inventory validates one to three unique native
    /// factory labels 0x50..0x52, protected full pages and every selected fw89.
    pub(crate) fn start(&mut self, selected: &[u8], deadline: Instant) -> Result<(), String> {
        if self.started {
            return Err("BB bus-0 diagnostic attempt already consumed".into());
        }
        self.started = true;
        state_lock(&self.state).deadline = Some(deadline);
        let result = self.inventory.start(selected, deadline);
        if let Err(error) = &result {
            state_lock(&self.state).stop(error.clone());
        }
        result
    }

    pub(crate) fn snapshot(&self) -> BbBus0DiagnosticSnapshot {
        let state = state_lock(&self.state);
        BbBus0DiagnosticSnapshot {
            deadline: state.deadline,
            inventory: self.inventory.snapshot(),
            bridges: state.bridges.clone(),
            stopped_at: state.stopped_at,
            failure: state.failure.clone(),
            bridge_task_joined_at: state.bridge_task_joined_at,
            all_caller_tasks_joined_at: state.all_caller_tasks_joined_at,
            data: state.data.clone(),
        }
    }

    /// Permanent promotion refusal. An attempt already recorded under the
    /// state lock may enter its synchronous query after cancel returns; its
    /// available result stays diagnostic only. No following attempt is admitted.
    pub(crate) fn cancel(&self) {
        state_lock(&self.state).stop("BB bus-0 diagnostic cancelled".into());
        self.inventory.cancel();
    }

    /// True means all created caller tasks were joined, including a cleanup
    /// retry after refusal. It means neither accepted data, within-deadline
    /// completion nor actual service drain. Dropping this pending future keeps
    /// every task handle but permanently prevents later data promotion.
    /// Previously issued snapshot clones remain historical observations.
    pub(crate) async fn join_until(&mut self, observe_deadline: Instant) -> bool {
        if state_lock(&self.state).all_caller_tasks_joined_at.is_some() {
            return true;
        }
        if Instant::now() >= observe_deadline {
            self.cancel();
            return false;
        }
        let mut pending = PendingJoinCancellation {
            state: Arc::clone(&self.state),
            armed: true,
        };
        if !self.inventory.join_until(observe_deadline).await {
            self.cancel();
            return false;
        }
        if !self.bridge_started {
            let joined = self.inventory.snapshot();
            let mut state = state_lock(&self.state);
            if !state.can_continue(&self.handle) || joined.inventory.is_none() {
                if state.stopped_at.is_none() {
                    state.stop(joined.failure.unwrap_or_else(|| {
                        "BB bus-0 diagnostic lacks joined selected inventory".into()
                    }));
                }
                state.all_caller_tasks_joined_at = Some(Instant::now());
                pending.armed = false;
                return true;
            }
            let inventory = joined.inventory.expect("actual joined inventory checked");
            let deadline = state.deadline.expect("started original deadline");
            let shared = Arc::clone(&self.state);
            let handle = self.handle.clone();
            drop(state);
            self.bridge_started = true;
            self.bridge_task = Some(tokio::task::spawn_blocking(move || {
                query_bridges(handle, inventory, deadline, shared)
            }));
        }
        if let Some(task) = &mut self.bridge_task {
            let result = tokio::select! {
                result = task => Some(result),
                _ = tokio::time::sleep_until(observe_deadline.into()) => None,
            };
            let Some(result) = result else {
                self.cancel();
                return false;
            };
            self.bridge_task = None;
            let observed = Instant::now();
            let mut state = state_lock(&self.state);
            state.bridge_task_joined_at = Some(observed);
            state.all_caller_tasks_joined_at = Some(observed);
            if let Err(error) = result {
                state.stop(format!("BB bus-0 bridge caller failed: {error}"));
            } else if observed >= observe_deadline {
                state.stop("BB bus-0 bridge caller observed after join deadline".into());
            } else if state.can_continue(&self.handle) {
                state.data = state.candidate.take();
            }
        }
        pending.armed = false;
        true
    }

    /// Synchronous blocking teardown only. Actual LM75 caller join precedes
    /// delegation to the same retained inventory/service owner. A timeout
    /// preserves that owner; no clone or task handle alone proves worker exit.
    pub(crate) fn close_service_until(&mut self, deadline: Instant) -> Result<(), String> {
        self.cancel();
        if self.bridge_task.is_some() {
            return Err("BB bus-0 bridge caller must be joined before service close".into());
        }
        self.inventory.close_service_until(deadline)
    }

    pub(crate) fn close_receipt(&self) -> Option<&I2cServiceCloseReceipt> {
        self.inventory.close_receipt()
    }
}

impl Drop for BbBus0Diagnostic {
    fn drop(&mut self) {
        self.cancel();
        let _ = self.handle.latch_terminal_safe_off();
        // The retained inventory fallback also fences its real service. Neither
        // Drop implementation claims actual joins or any physical voltage cut.
    }
}

fn query_bridges(
    handle: I2cServiceHandle,
    inventory: BbSelectedInventoryData,
    deadline: Instant,
    shared: Arc<Mutex<State>>,
) {
    for pic in &inventory.pics {
        for sensor in bb_pic_lm75::SENSOR_ADDRESSES {
            let index = {
                let mut state = state_lock(&shared);
                if !state.can_continue(&handle) {
                    return;
                }
                let index = state.bridges.len();
                state.bridges.push(BbBridgeDiagnosticAttempt {
                    factory_address: pic.factory_address,
                    native_slot: pic.native_slot,
                    pic_address: pic.pic_address,
                    sensor_address: sensor,
                    call_prepared_at: Instant::now(),
                    call_returned_at: None,
                    returned_reads: None,
                    decoded: None,
                    error: None,
                });
                index
            };
            let result = handle.read_bb_pic_lm75_at(pic.native_slot, sensor, deadline);
            let mut state = state_lock(&shared);
            state.bridges[index].call_returned_at = Some(Instant::now());
            let decoded = match result {
                Ok(reads) => {
                    let decoded = bb_pic_lm75::complete_reply(&reads)
                        .map_err(|error| format!("BB LM75 reply refused: {error:?}"));
                    state.bridges[index].returned_reads = Some(reads);
                    decoded
                }
                Err(error) => Err(error.to_string()),
            };
            match decoded {
                Ok(sample) => state.bridges[index].decoded = Some(sample),
                Err(error) => {
                    state.bridges[index].error = Some(error.clone());
                    state.stop(error);
                    return;
                }
            }
            if !state.can_continue(&handle) {
                return;
            }
        }
    }
    let mut state = state_lock(&shared);
    if state.can_continue(&handle) {
        state.candidate = Some(BbBus0DiagnosticData {
            selected_inventory: inventory,
            bridges: state.bridges.clone(),
            observed_complete_at: Instant::now(),
        });
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_bus0_diagnostic_tests.rs"]
mod tests;
