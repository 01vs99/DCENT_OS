//! Detached, unregistered review candidate: selected diagnostic inventory.
//!
//! Retains the already-created bus-0 service owner, factory caller and PIC
//! query caller. A completed inventory is historical checked data only. It
//! proves neither populated physical slots, CPU/carrier identity, PIC startup,
//! APW readiness, current freshness nor permission to change hardware.
//! No raw frame, checked DTO or replacement service is accepted as an input.

use super::bb_factory_acquisition::{BbFactoryAcquisition, BbFactoryAcquisitionSnapshot};
use crate::bb_pic_application;
use crate::i2c::{I2cServiceCloseReceipt, I2cServiceHandle, I2cServiceOwner};
use dcentrald_api_types::bb_factory_profile::BbFactoryCollection;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub(crate) struct BbSelectedPicAttempt {
    /// Selected endpoint labels under the current native three-slot policy.
    pub factory_address: u8,
    pub native_slot: usize,
    pub pic_address: u8,
    /// Caller preparation/return times, not actual bus-stage start timestamps.
    pub call_prepared_at: Instant,
    pub call_returned_at: Option<Instant>,
    /// Only bytes returned by the existing synchronous transaction API.
    /// On timeout, unavailable partial or later service bytes stay unknown.
    pub returned_reads: Option<Vec<Vec<u8>>>,
    pub accepted_reply: Option<[u8; 5]>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct BbSelectedInventoryData {
    pub factory: BbFactoryCollection,
    pub pics: Vec<BbSelectedPicAttempt>,
    pub observed_complete_at: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct BbSelectedInventorySnapshot {
    pub selected_addresses: Vec<u8>,
    pub deadline: Option<Instant>,
    pub factory: Option<BbFactoryAcquisitionSnapshot>,
    pub pics: Vec<BbSelectedPicAttempt>,
    pub stopped_at: Option<Instant>,
    pub failure: Option<String>,
    pub query_task_joined_at: Option<Instant>,
    pub all_caller_tasks_joined_at: Option<Instant>,
    pub inventory: Option<BbSelectedInventoryData>,
    pub service_close_observed_at: Option<Instant>,
}

struct State {
    snapshot: BbSelectedInventorySnapshot,
    candidate: Option<BbSelectedInventoryData>,
}

impl State {
    fn stop(&mut self, detail: String) {
        self.snapshot.stopped_at.get_or_insert_with(Instant::now);
        self.snapshot.failure.get_or_insert(detail);
        self.snapshot.inventory = None;
        self.candidate = None;
    }

    fn can_continue(&mut self, handle: &I2cServiceHandle) -> bool {
        if self
            .snapshot
            .deadline
            .is_none_or(|limit| Instant::now() >= limit)
        {
            self.stop("BB selected inventory deadline elapsed or absent".into());
        }
        if handle.terminal_safe_off_is_latched() {
            self.stop("BB selected inventory observed terminal service latch".into());
        }
        self.snapshot.stopped_at.is_none()
    }
}

fn state_lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poison) => {
            let mut guard = poison.into_inner();
            guard.stop("BB selected inventory diagnostic state poisoned".into());
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
            state_lock(&self.state)
                .stop("BB selected inventory pending join future cancelled".into());
        }
    }
}

/// Move-only enclosing lifetime. Explicit async caller joins and synchronous
/// service close/join must finish before the future runtime drops this object.
/// Dropping Rust handles does not join or interrupt a started kernel transfer.
pub(crate) struct BbSelectedInventory {
    owner: I2cServiceOwner,
    factory: Option<BbFactoryAcquisition>,
    query: Option<JoinHandle<()>>,
    state: Arc<Mutex<State>>,
    started: bool,
    query_started: bool,
    close_receipt: Option<I2cServiceCloseReceipt>,
}

impl BbSelectedInventory {
    /// Takes the existing owner. It creates no adapter, worker or admission.
    pub(crate) fn new(owner: I2cServiceOwner) -> Self {
        Self {
            owner,
            factory: None,
            query: None,
            started: false,
            query_started: false,
            close_receipt: None,
            state: Arc::new(Mutex::new(State {
                snapshot: BbSelectedInventorySnapshot {
                    selected_addresses: Vec::new(),
                    deadline: None,
                    factory: None,
                    pics: Vec::new(),
                    stopped_at: None,
                    failure: None,
                    query_task_joined_at: None,
                    all_caller_tasks_joined_at: None,
                    inventory: None,
                    service_close_observed_at: None,
                },
                candidate: None,
            })),
        }
    }

    /// One selected attempt per enclosing owner, including failed admission.
    /// 0x50..=0x52 maps only to current native endpoint labels 0..=2; the pure
    /// factory decoder's fourth diagnostic address is deliberately not used.
    pub(crate) fn start(&mut self, selected: &[u8], deadline: Instant) -> Result<(), String> {
        if self.started {
            return Err("BB selected inventory attempt already consumed".into());
        }
        self.started = true;
        let result = (|| {
            let mut state = state_lock(&self.state);
            state.snapshot.deadline = Some(deadline);
            if selected.is_empty() || selected.len() > 3 {
                return Err("BB selected inventory requires one to three endpoints".to_string());
            }
            state.snapshot.selected_addresses = selected.to_vec();
            for (index, address) in selected.iter().enumerate() {
                if !(0x50..=0x52).contains(address) || selected[..index].contains(address) {
                    return Err("BB selected inventory has invalid or duplicate endpoint".into());
                }
            }
            let handle = self.owner.request_handle();
            if handle.bus() != 0 {
                return Err("BB selected inventory requires retained bus-0 owner".into());
            }
            if !state.can_continue(&handle) {
                return Err(state.snapshot.failure.clone().expect("refusal retained"));
            }
            drop(state);
            self.factory = Some(BbFactoryAcquisition::start(
                &self.owner,
                selected,
                deadline,
            )?);
            Ok(())
        })();
        if let Err(error) = &result {
            state_lock(&self.state).stop(error.clone());
        }
        result
    }

    pub(crate) fn snapshot(&self) -> BbSelectedInventorySnapshot {
        let mut snapshot = state_lock(&self.state).snapshot.clone();
        snapshot.factory = self.factory.as_ref().map(BbFactoryAcquisition::snapshot);
        snapshot
    }

    /// Permanently suppresses data promotion; it does not stop an active read.
    pub(crate) fn cancel(&self) {
        state_lock(&self.state).stop("BB selected inventory cancelled".into());
        if let Some(factory) = &self.factory {
            factory.cancel();
        }
    }

    /// True means every caller task actually created by this attempt has been
    /// joined. It does NOT mean data success, observation within either deadline
    /// or actual service drain. A cleanup retry may return true after failure.
    /// Dropping this pending future permanently cancels inventory promotion;
    /// both handles remain in this enclosing object for a later cleanup join.
    pub(crate) async fn join_until(&mut self, observe_deadline: Instant) -> bool {
        if state_lock(&self.state)
            .snapshot
            .all_caller_tasks_joined_at
            .is_some()
        {
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
        if let Some(factory) = &mut self.factory {
            if !factory.join_until(observe_deadline).await {
                self.cancel();
                return false;
            }
        }
        if !self.query_started {
            let handle = self.owner.request_handle();
            let collection = self
                .factory
                .as_ref()
                .and_then(|factory| factory.snapshot().collection);
            let mut state = state_lock(&self.state);
            let allowed = state.can_continue(&handle);
            if !allowed || collection.is_none() {
                if allowed {
                    let detail = self
                        .factory
                        .as_ref()
                        .and_then(|factory| factory.snapshot().failure)
                        .unwrap_or_else(|| {
                            "BB selected inventory has no joined checked factory collection".into()
                        });
                    state.stop(detail);
                }
                state.snapshot.all_caller_tasks_joined_at = Some(Instant::now());
                pending.armed = false;
                return true;
            }
            let collection = collection.expect("checked collection from retained acquisition");
            let actual: Vec<u8> = collection
                .pages()
                .iter()
                .map(|page| page.address())
                .collect();
            if actual != state.snapshot.selected_addresses {
                state.stop(
                    "BB selected inventory acquired collection differs from selected endpoints"
                        .into(),
                );
                state.snapshot.all_caller_tasks_joined_at = Some(Instant::now());
                pending.armed = false;
                return true;
            }
            let shared = Arc::clone(&self.state);
            drop(state);
            self.query_started = true;
            self.query = Some(tokio::task::spawn_blocking(move || {
                query_selected(handle, collection, shared)
            }));
        }
        if let Some(task) = &mut self.query {
            let result = tokio::select! {
                result = task => Some(result),
                _ = tokio::time::sleep_until(observe_deadline.into()) => None,
            };
            let Some(result) = result else {
                self.cancel();
                return false;
            };
            self.query = None;
            let observed = Instant::now();
            let handle = self.owner.request_handle();
            let mut state = state_lock(&self.state);
            state.snapshot.query_task_joined_at = Some(observed);
            state.snapshot.all_caller_tasks_joined_at = Some(observed);
            if let Err(error) = result {
                state.stop(format!("BB selected inventory query task failed: {error}"));
            } else if observed >= observe_deadline {
                state.stop("BB selected inventory query task observed after join deadline".into());
            } else if state.can_continue(&handle) {
                state.snapshot.inventory = state.candidate.take();
            }
        }
        pending.armed = false;
        true
    }

    /// Call only in the enclosing runtime's blocking teardown context, after
    /// its intended SafeOff operations. No async task is abandoned to do this.
    /// A timeout retains the actual service owner for retry. Caller-task joins
    /// must be observed first; the service may still be in a timed-out transfer.
    pub(crate) fn close_service_until(&mut self, deadline: Instant) -> Result<(), String> {
        self.cancel();
        if self.close_receipt.is_some() {
            return Ok(());
        }
        if self
            .factory
            .as_ref()
            .is_some_and(|factory| factory.snapshot().blocking_task_joined_at.is_none())
            || self.query.is_some()
        {
            return Err(
                "BB selected inventory caller tasks must be joined before service close".into(),
            );
        }
        let receipt = self
            .owner
            .close_and_join_until(deadline)
            .map_err(|error| error.to_string())?;
        state_lock(&self.state).snapshot.service_close_observed_at =
            Some(receipt.worker_exit_observed_at());
        self.close_receipt = Some(receipt);
        Ok(())
    }

    pub(crate) fn close_receipt(&self) -> Option<&I2cServiceCloseReceipt> {
        self.close_receipt.as_ref()
    }
}

impl Drop for BbSelectedInventory {
    fn drop(&mut self) {
        self.cancel();
        let _ = self.owner.request_handle().latch_terminal_safe_off();
        // Fallback closes future mutation admission, but dropping either Rust
        // JoinHandle detaches it. Only explicit joins above prove lifecycle
        // cleanup; this Drop implementation never claims drain or rail safety.
    }
}

fn query_selected(
    handle: I2cServiceHandle,
    collection: BbFactoryCollection,
    shared: Arc<Mutex<State>>,
) {
    let deadline = state_lock(&shared)
        .snapshot
        .deadline
        .expect("started attempt deadline");
    for page in collection.pages() {
        let address = page.address();
        let index = {
            let mut state = state_lock(&shared);
            if !state.can_continue(&handle) {
                return;
            }
            let Some(slot) = address
                .checked_sub(0x50)
                .map(usize::from)
                .filter(|slot| *slot < 3)
            else {
                state.stop("BB selected inventory acquired an unsupported native endpoint".into());
                return;
            };
            let index = state.snapshot.pics.len();
            state.snapshot.pics.push(BbSelectedPicAttempt {
                factory_address: address,
                native_slot: slot,
                pic_address: bb_pic_application::native_pic_address(slot)
                    .expect("checked native slot"),
                call_prepared_at: Instant::now(),
                call_returned_at: None,
                returned_reads: None,
                accepted_reply: None,
                error: None,
            });
            index
        };
        // Cancellation can race with this single call. Keep its available
        // result diagnostic and never send a later selected query after stop.
        let result = handle.read_bb_pic_application_at(usize::from(address - 0x50), deadline);
        let mut state = state_lock(&shared);
        state.snapshot.pics[index].call_returned_at = Some(Instant::now());
        let result = match result {
            Ok(reads) => {
                let parsed =
                    bb_pic_application::complete_reply(&reads).map_err(|error| error.to_string());
                state.snapshot.pics[index].returned_reads = Some(reads);
                parsed
            }
            Err(error) => Err(error.to_string()),
        };
        match result {
            Ok(reply) => state.snapshot.pics[index].accepted_reply = Some(reply),
            Err(error) => {
                state.snapshot.pics[index].error = Some(error.clone());
                state.stop(error);
                return;
            }
        }
        if !state.can_continue(&handle) {
            return;
        }
    }
    let mut state = state_lock(&shared);
    if state.can_continue(&handle) {
        state.candidate = Some(BbSelectedInventoryData {
            factory: collection,
            pics: state.snapshot.pics.clone(),
            observed_complete_at: Instant::now(),
        });
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_selected_inventory_tests.rs"]
mod tests;
