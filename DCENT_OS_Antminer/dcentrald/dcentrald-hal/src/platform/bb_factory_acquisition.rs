//! UNREGISTERED REVIEW DRAFT. Diagnostic data acquisition only.
//! Proposed HAL child; caller retains the actual I2cServiceOwner separately.
//! No runtime startup, physical readiness, freshness or shutdown capability.

use crate::i2c::{I2cServiceHandle, I2cServiceOwner};
use dcentrald_api_types::bb_factory_profile::BbFactoryCollection;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub(crate) struct BbFactoryPageAttempt {
    /// Explicit caller-selected bus-0 endpoint; never a proven chain number.
    pub address: u8,
    /// The blocking call was about to be invoked, not a bus-start receipt.
    pub call_prepared_at: Instant,
    pub call_returned_at: Option<Instant>,
    /// Exact bytes returned by the existing full-page operation, including
    /// a late successful reply. On error no unavailable bytes are invented.
    pub returned_page: Option<Vec<u8>>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct BbFactoryAcquisitionSnapshot {
    pub selected_addresses: Vec<u8>,
    pub deadline: Instant,
    pub attempts: Vec<BbFactoryPageAttempt>,
    pub stopped_at: Option<Instant>,
    pub failure: Option<String>,
    pub blocking_task_joined_at: Option<Instant>,
    /// Present only after the whole selected collection was checked and its
    /// blocking task was actually joined before the original deadline.
    /// This remains historical diagnostic data, never live admission.
    pub collection: Option<BbFactoryCollection>,
}

struct State {
    snapshot: BbFactoryAcquisitionSnapshot,
    candidate: Option<BbFactoryCollection>,
}

impl State {
    fn stop(&mut self, detail: String) {
        self.snapshot.stopped_at.get_or_insert_with(Instant::now);
        self.snapshot.failure.get_or_insert(detail);
        self.snapshot.collection = None;
        self.candidate = None;
    }

    fn can_continue(&mut self) -> bool {
        if Instant::now() >= self.snapshot.deadline {
            self.stop("BB factory acquisition deadline elapsed".into());
        }
        self.snapshot.stopped_at.is_none()
    }
}

fn lock_state(state: &Mutex<State>) -> MutexGuard<'_, State> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poison) => {
            // A poisoned diagnostic state can never yield a checked result.
            // Recover only to retain the error and any already stored bytes.
            let mut guard = poison.into_inner();
            guard.stop("BB factory acquisition state was poisoned".into());
            guard
        }
    }
}

/// Owns only the blocking caller task. The future enclosing controller keeps
/// this object AND the original move-only I2cServiceOwner until actual cleanup.
/// It must explicitly close/join that service owner under its cleanup deadline.
pub(crate) struct BbFactoryAcquisition {
    state: Arc<Mutex<State>>,
    task: Option<JoinHandle<()>>,
    service: I2cServiceHandle,
}

struct PendingJoinCancellation {
    state: Arc<Mutex<State>>,
    armed: bool,
}

impl Drop for PendingJoinCancellation {
    fn drop(&mut self) {
        if self.armed {
            lock_state(&self.state).stop("BB factory pending join future was cancelled".into());
        }
    }
}

impl BbFactoryAcquisition {
    pub(crate) fn start(
        owner: &I2cServiceOwner,
        selected_addresses: &[u8],
        deadline: Instant,
    ) -> Result<Self, String> {
        let handle = owner.request_handle();
        if handle.bus() != 0 {
            return Err(
                "BB factory diagnostic acquisition requires the retained bus-0 owner".into(),
            );
        }
        // These bounds prevent any I/O to an invalid selected set. They mirror
        // the existing pure collection's four endpoint-label policy only;
        // the collection still performs its own complete checked validation.
        if selected_addresses.is_empty() || selected_addresses.len() > 4 {
            return Err("BB factory selection must contain one to four endpoints".into());
        }
        for (index, address) in selected_addresses.iter().enumerate() {
            if !(0x50..=0x53).contains(address) || selected_addresses[..index].contains(address) {
                return Err(
                    "BB factory selection contains an invalid or duplicate endpoint".into(),
                );
            }
        }
        if Instant::now() >= deadline || handle.terminal_safe_off_is_latched() {
            return Err(
                "BB factory acquisition cannot start after its deadline or terminal latch".into(),
            );
        }
        let state = Arc::new(Mutex::new(State {
            snapshot: BbFactoryAcquisitionSnapshot {
                selected_addresses: selected_addresses.to_vec(),
                deadline,
                attempts: Vec::with_capacity(selected_addresses.len()),
                stopped_at: None,
                failure: None,
                blocking_task_joined_at: None,
                collection: None,
            },
            candidate: None,
        }));
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            format!("BB factory acquisition requires an active runtime: {error}")
        })?;
        let task_state = Arc::clone(&state);
        let worker_handle = handle.clone();
        let task = runtime.spawn_blocking(move || acquire(worker_handle, task_state));
        Ok(Self {
            state,
            task: Some(task),
            service: handle,
        })
    }

    /// Does not abort/detach the retained task or claim to stop a started read.
    /// Cancellation permanently removes the ability to return a collection.
    pub(crate) fn cancel(&self) {
        lock_state(&self.state).stop("BB factory acquisition cancelled".into());
    }

    pub(crate) fn snapshot(&self) -> BbFactoryAcquisitionSnapshot {
        lock_state(&self.state).snapshot.clone()
    }

    /// Retains the JoinHandle on timeout, so the same object can retry cleanup.
    /// This joins the blocking CALLER only, not the actual I2c service worker.
    /// True means a blocking-task join was observed, possibly late or failed.
    /// It does not mean within-deadline acceptance, data success or service drain.
    /// Dropping this future while pending cancels result promotion permanently;
    /// the retained task can still be joined by a later cleanup call.
    pub(crate) async fn join_until(&mut self, observe_deadline: Instant) -> bool {
        if self.task.is_none() {
            return self.snapshot().blocking_task_joined_at.is_some();
        }
        if Instant::now() >= observe_deadline {
            self.cancel();
            return false;
        }
        let mut cancellation = PendingJoinCancellation {
            state: Arc::clone(&self.state),
            armed: true,
        };
        let task = self.task.as_mut().expect("checked retained blocking task");
        let result = tokio::select! {
            result = task => Some(result),
            _ = tokio::time::sleep_until(observe_deadline.into()) => None,
        };
        let Some(result) = result else {
            self.cancel();
            return false;
        };
        self.task = None;
        let mut state = lock_state(&self.state);
        let observed_at = Instant::now();
        state.snapshot.blocking_task_joined_at = Some(observed_at);
        if let Err(error) = result {
            state.stop(format!("BB factory blocking task failed: {error}"));
        } else if observed_at >= observe_deadline {
            state.stop("BB factory blocking task observed after join deadline".into());
        } else if self.service.terminal_safe_off_is_latched() {
            state.stop(
                "BB factory acquisition observed terminal latch before collection acceptance"
                    .into(),
            );
        } else if state.can_continue() {
            state.snapshot.collection = state.candidate.take();
        }
        cancellation.armed = false;
        true
    }
}

impl Drop for BbFactoryAcquisition {
    fn drop(&mut self) {
        self.cancel();
        // Rust will detach an outstanding JoinHandle here. This fallback only
        // suppresses result promotion; it is NOT a worker-drain guarantee.
        // The future controller must retain this object until explicit join.
    }
}

fn acquire(handle: I2cServiceHandle, shared: Arc<Mutex<State>>) {
    let (addresses, deadline) = {
        let state = lock_state(&shared);
        (
            state.snapshot.selected_addresses.clone(),
            state.snapshot.deadline,
        )
    };
    for address in &addresses {
        let index = {
            let mut state = lock_state(&shared);
            if handle.terminal_safe_off_is_latched() {
                state.stop("BB factory acquisition observed terminal latch".into());
            }
            if !state.can_continue() {
                return;
            }
            let index = state.snapshot.attempts.len();
            state.snapshot.attempts.push(BbFactoryPageAttempt {
                address: *address,
                call_prepared_at: Instant::now(),
                call_returned_at: None,
                returned_page: None,
                error: None,
            });
            index
        };
        // The sole existing protected operation performs the exact full read.
        // Cancellation after the above check may race with this one submitted
        // call. Its result is retained, and no later endpoint is submitted.
        let result = handle.read_hashboard_eeprom_page_at(*address, deadline);
        let returned_at = Instant::now();
        let mut state = lock_state(&shared);
        state.snapshot.attempts[index].call_returned_at = Some(returned_at);
        match result {
            Ok(raw) => state.snapshot.attempts[index].returned_page = Some(raw),
            Err(error) => {
                let detail = error.to_string();
                state.snapshot.attempts[index].error = Some(detail.clone());
                state.stop(detail);
                // A timed-out response can leave the actual service worker
                // active. No late raw payload is available via this API.
                return;
            }
        }
        if handle.terminal_safe_off_is_latched() {
            state.stop("BB factory acquisition observed terminal latch after read".into());
        }
        if !state.can_continue() {
            return;
        }
    }
    let mut state = lock_state(&shared);
    if !state.can_continue() {
        return;
    }
    let records: Option<Vec<_>> = state
        .snapshot
        .attempts
        .iter()
        .map(|attempt| {
            attempt
                .returned_page
                .as_ref()
                .map(|raw| (attempt.address, raw.as_slice()))
        })
        .collect();
    let Some(records) = records else {
        state.stop("BB factory acquisition is missing a selected full-page result".into());
        return;
    };
    match BbFactoryCollection::decode(&addresses, &records) {
        Ok(collection) => {
            if state.can_continue() && !handle.terminal_safe_off_is_latched() {
                state.candidate = Some(collection);
            } else {
                state.stop("BB factory collection completed after cancellation, deadline or terminal latch".into());
            }
        }
        Err(error) => state.stop(error.to_string()),
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_factory_acquisition_tests.rs"]
mod tests;
