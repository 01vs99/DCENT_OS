//! Retained timer over the parent's original selected fw89 service lifetime.
//! Timing limits below are conservative software policy, not measured hardware
//! health guarantees. A stable observation does not authorize voltage/mining.

use super::Handles;
use crate::i2c::bb_pic_keepalive::Attempt;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

const ROUND_LIMIT: Duration = Duration::from_secs(2);
const AFTER_SWEEP: Duration = Duration::from_secs(1);
const START_GRACE: Duration = Duration::from_millis(250);
const MONITOR_PERIOD: Duration = Duration::from_millis(20);
const WARMUP_LIMIT: Duration = Duration::from_secs(16);
const MAX_COMPLETE_AGE: Duration = Duration::from_millis(3500);
const STABLE_SWEEPS: u64 = 5;
const RETAINED_NORMAL_ROUNDS: usize = 64;

/// Independently owned operational callback. Returning Ok records callback
/// completion only; it creates no physical OFF proof or terminal capability.
/// The enclosing owner must bind its original UART fence and actual GPIO
/// cutoff custody here; this actor itself fences only its two I2C services.
pub trait BbHeartbeatCutoff: Send + Sync + 'static {
    fn cutoff(&self) -> Result<(), String>;
}

#[derive(Clone, Debug)]
pub struct BbHeartbeatPicObservation {
    pub native_slot: usize,
    pub pic_address: Option<u8>,
    pub deadline: Instant,
    pub caller_started_at: Instant,
    pub caller_returned_at: Option<Instant>,
    pub returned_reads: Option<Vec<Vec<u8>>>,
    pub decoded_reply: Option<[u8; 6]>,
    pub transport_error: Option<String>,
    pub failure: Option<String>,
    pub strict_completed_at: Option<Instant>,
}
impl From<Attempt> for BbHeartbeatPicObservation {
    fn from(value: Attempt) -> Self {
        Self {
            native_slot: value.native_slot,
            pic_address: value.pic_address,
            deadline: value.deadline,
            caller_started_at: value.caller_started_at,
            caller_returned_at: value.caller_returned_at,
            returned_reads: value.returned_reads,
            decoded_reply: value.decoded_reply,
            transport_error: value.transport_error,
            failure: value.failure,
            strict_completed_at: value.accepted_at,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BbHeartbeatRound {
    pub sequence: u64,
    pub scheduled_start: Instant,
    pub latest_start: Instant,
    pub deadline: Instant,
    pub caller_started_at: Option<Instant>,
    pub attempts: Vec<BbHeartbeatPicObservation>,
    pub completed_at: Option<Instant>,
    pub accepted_at: Option<Instant>,
    pub failure: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BbHeartbeatCutoffObservation {
    pub prepared_at: Instant,
    pub started_at: Option<Instant>,
    pub returned_at: Option<Instant>,
    pub joined_at: Option<Instant>,
    pub result: Option<Result<(), String>>,
}

#[derive(Clone, Debug)]
pub struct BbHeartbeatSnapshot {
    pub started_at: Instant,
    pub warmup_deadline: Instant,
    pub selected_factory_addresses: Vec<u8>,
    pub complete_sweeps: u64,
    pub consecutive_complete_sweeps: u64,
    pub last_complete_at: Option<Instant>,
    pub current_round: BbHeartbeatRound,
    /// Last64 normal rounds plus the unreplaceable current terminal round.
    /// Aggregate sweep counts remain cumulative; no stopped actor can restart.
    pub retained_rounds: VecDeque<BbHeartbeatRound>,
    pub stopped_at: Option<Instant>,
    pub first_failure: Option<String>,
    pub caller_started_at: Option<Instant>,
    pub caller_returned_at: Option<Instant>,
    pub caller_joined_at: Option<Instant>,
    pub monitor_started_at: Option<Instant>,
    pub monitor_returned_at: Option<Instant>,
    pub monitor_joined_at: Option<Instant>,
    pub cutoff: Option<BbHeartbeatCutoffObservation>,
}

struct Shared {
    state: Mutex<BbHeartbeatSnapshot>,
    changed: Condvar,
    monitor_wake: Notify,
    handles: Handles,
    cutoff: Arc<dyn BbHeartbeatCutoff>,
    cutoff_task: Mutex<Option<JoinHandle<()>>>,
    #[cfg(all(test, feature = "sim-hal"))]
    before_promotion: Mutex<Option<Arc<tests::Gate>>>,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, BbHeartbeatSnapshot> {
        self.state.lock().unwrap_or_else(|poison| {
            self.handles.fence();
            let mut state = poison.into_inner();
            state.stopped_at.get_or_insert_with(Instant::now);
            state
                .first_failure
                .get_or_insert_with(|| "BB heartbeat state poisoned".into());
            self.changed.notify_all();
            self.monitor_wake.notify_one();
            state
        })
    }

    fn stop(&self, reason: &str) {
        self.handles.fence();
        let mut state = self.lock();
        state.stopped_at.get_or_insert_with(Instant::now);
        state.first_failure.get_or_insert_with(|| reason.into());
        state
            .current_round
            .failure
            .get_or_insert_with(|| reason.into());
        state.consecutive_complete_sweeps = 0;
        drop(state);
        self.changed.notify_all();
        self.monitor_wake.notify_one();
    }

    fn violation(&self) -> Option<&'static str> {
        let state = self.lock();
        self.violation_locked(&state, Instant::now())
    }

    // Every caller samples now after acquiring this exact state lock.
    fn violation_locked(&self, state: &BbHeartbeatSnapshot, now: Instant) -> Option<&'static str> {
        if self.handles.is_stopped() {
            return Some("BB heartbeat observed original terminal fence");
        }
        if state.stopped_at.is_some() {
            return Some("BB heartbeat permanently stopped");
        }
        if now >= state.current_round.deadline {
            return Some("BB heartbeat original round deadline elapsed");
        }
        if state.current_round.caller_started_at.is_none()
            && now >= state.current_round.latest_start
        {
            return Some("BB heartbeat caller missed original next-round start bound");
        }
        if state.complete_sweeps < STABLE_SWEEPS && now >= state.warmup_deadline {
            return Some("BB heartbeat original warmup deadline elapsed");
        }
        if state
            .last_complete_at
            .is_some_and(|last| now.saturating_duration_since(last) >= MAX_COMPLETE_AGE)
        {
            return Some("BB heartbeat complete-roster observation too old");
        }
        None
    }
}

pub(super) struct Actor {
    shared: Arc<Shared>,
    caller: Option<JoinHandle<()>>,
    monitor: Option<JoinHandle<()>>,
}

/// Private live reference to this exact actor. No snapshot or caller-provided
/// timestamp can construct the gate; electrical callers recheck it on entry.
pub(super) struct VoltageGate {
    shared: Arc<Shared>,
}
pub(super) struct VoltageObservation {
    pub observed_at: Instant,
    pub complete_sweeps: u64,
}
impl VoltageGate {
    pub(super) fn observe(&self, deadline: Instant) -> Result<VoltageObservation, String> {
        let state = self.shared.lock();
        let now = Instant::now();
        let failure = self.shared.violation_locked(&state, now).or_else(|| {
            if now >= deadline {
                Some("BB voltage caller original deadline elapsed")
            } else if state.consecutive_complete_sweeps < STABLE_SWEEPS {
                Some("BB voltage caller requires five actual complete heartbeat sweeps")
            } else {
                None
            }
        });
        if let Some(reason) = failure {
            drop(state);
            self.shared.stop(reason);
            return Err(reason.into());
        }
        Ok(VoltageObservation {
            observed_at: now,
            complete_sweeps: state.complete_sweeps,
        })
    }
}

struct PendingWarmup {
    shared: Arc<Shared>,
    joined: bool,
}
impl Drop for PendingWarmup {
    fn drop(&mut self) {
        if !self.joined {
            self.shared
                .stop("BB original heartbeat warmup cancelled or refused");
        }
    }
}

fn reserved_round(sequence: u64, scheduled_start: Instant) -> BbHeartbeatRound {
    BbHeartbeatRound {
        sequence,
        scheduled_start,
        latest_start: scheduled_start + START_GRACE,
        deadline: scheduled_start + ROUND_LIMIT,
        caller_started_at: None,
        attempts: Vec::new(),
        completed_at: None,
        accepted_at: None,
        failure: None,
    }
}

impl Actor {
    /// Called only after the parent checks its actual joined diagnostics. The
    /// selected roster and handles are private parent data, never public inputs.
    pub(super) fn start(
        selected: Vec<u8>,
        handles: Handles,
        cutoff: Arc<dyn BbHeartbeatCutoff>,
    ) -> Self {
        let started_at = Instant::now();
        let shared = Arc::new(Shared {
            state: Mutex::new(BbHeartbeatSnapshot {
                started_at,
                warmup_deadline: started_at + WARMUP_LIMIT,
                selected_factory_addresses: selected,
                complete_sweeps: 0,
                consecutive_complete_sweeps: 0,
                last_complete_at: None,
                current_round: reserved_round(1, started_at),
                retained_rounds: VecDeque::new(),
                stopped_at: None,
                first_failure: None,
                caller_started_at: None,
                caller_returned_at: None,
                caller_joined_at: None,
                monitor_started_at: None,
                monitor_returned_at: None,
                monitor_joined_at: None,
                cutoff: None,
            }),
            changed: Condvar::new(),
            monitor_wake: Notify::new(),
            handles,
            cutoff,
            cutoff_task: Mutex::new(None),
            #[cfg(all(test, feature = "sim-hal"))]
            before_promotion: Mutex::new(None),
        });
        let worker = shared.clone();
        let caller = tokio::task::spawn_blocking(move || {
            worker.lock().caller_started_at = Some(Instant::now());
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_caller(&worker)))
                .is_err()
            {
                worker.stop("BB heartbeat caller unwound");
            }
            worker.lock().caller_returned_at = Some(Instant::now());
            worker.monitor_wake.notify_one();
        });
        let observer = shared.clone();
        let monitor = tokio::spawn(async move {
            observer.lock().monitor_started_at = Some(Instant::now());
            let body = async {
                loop {
                    if let Some(reason) = observer.violation() {
                        observer.stop(reason);
                        retain_cutoff(&observer);
                        return;
                    }
                    tokio::select! {
                        _ = observer.monitor_wake.notified() => {},
                        _ = tokio::time::sleep(MONITOR_PERIOD) => {},
                    }
                }
            };
            tokio::pin!(body);
            let returned = std::future::poll_fn(|context| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    std::future::Future::poll(body.as_mut(), context)
                })) {
                    Ok(std::task::Poll::Ready(())) => std::task::Poll::Ready(Ok(())),
                    Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
                    Err(_) => std::task::Poll::Ready(Err(())),
                }
            })
            .await;
            if returned.is_err() {
                observer.stop("BB heartbeat monitor unwound");
                retain_cutoff(&observer);
            }
            observer.lock().monitor_returned_at = Some(Instant::now());
        });
        Self {
            shared,
            caller: Some(caller),
            monitor: Some(monitor),
        }
    }

    pub(super) fn snapshot(&self) -> BbHeartbeatSnapshot {
        self.shared.lock().clone()
    }

    pub(super) fn stop(&self, reason: &str) {
        self.shared.stop(reason);
    }

    pub(super) fn require_stable(&self) -> Result<BbHeartbeatSnapshot, String> {
        let state = self.shared.lock();
        let observed_at = Instant::now();
        if let Some(reason) = self.shared.violation_locked(&state, observed_at) {
            drop(state);
            self.shared.stop(reason);
            return Err(reason.into());
        }
        if state.consecutive_complete_sweeps < STABLE_SWEEPS {
            return Err(
                "BB heartbeat needs five consecutive complete selected-roster sweeps".into(),
            );
        }
        // The time check belongs to this actual locked observation. Returning
        // data still creates neither a hardware mutation lease nor rail proof.
        Ok(state.clone())
    }

    pub(super) fn voltage_gate(&self) -> VoltageGate {
        VoltageGate {
            shared: self.shared.clone(),
        }
    }

    pub(super) async fn wait_stable_until(
        &self,
        deadline: Instant,
    ) -> Result<BbHeartbeatSnapshot, String> {
        let mut pending = PendingWarmup {
            shared: self.shared.clone(),
            joined: false,
        };
        loop {
            {
                let state = self.shared.lock();
                let now = Instant::now();
                if let Some(reason) = self.shared.violation_locked(&state, now) {
                    return Err(reason.into());
                }
                if now >= deadline {
                    return Err("BB heartbeat warmup caller original deadline elapsed".into());
                }
                if state.consecutive_complete_sweeps >= STABLE_SWEEPS {
                    pending.joined = true;
                    return Ok(state.clone());
                }
            }
            tokio::time::sleep_until((Instant::now() + MONITOR_PERIOD).min(deadline).into()).await;
        }
    }

    /// Called only by the retained owner after all task joins. The final data
    /// is preserved separately before dropping this actual callback owner.
    pub(super) fn snapshot_for_callback_release(&self) -> Result<BbHeartbeatSnapshot, String> {
        if self.pending() || Arc::strong_count(&self.shared) != 1 {
            return Err(
                "BB heartbeat caller, monitor, cutoff or private gate still owns callback custody"
                    .into(),
            );
        }
        Ok(self.snapshot())
    }

    pub(super) fn pending(&self) -> bool {
        self.caller.is_some()
            || self.monitor.is_some()
            || self
                .shared
                .cutoff_task
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_some()
            || self
                .shared
                .lock()
                .cutoff
                .as_ref()
                .is_none_or(|record| record.joined_at.is_none())
    }

    pub(super) async fn join_until(&mut self, deadline: Instant) -> bool {
        self.stop("BB heartbeat permanent cleanup requested");
        // Monitor joins first, so its retained cutoff task is known before we
        // inspect that handle. Every wait uses this same cleanup deadline.
        if !join_task(&mut self.monitor, deadline, &self.shared, "monitor").await {
            return false;
        }
        if !join_task(&mut self.caller, deadline, &self.shared, "caller").await {
            return false;
        }
        // Keep the cutoff handle in shared ownership across cancellation. Poll
        // it under a short lock; no synchronous mutex guard crosses an await.
        if self
            .shared
            .cutoff_task
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_none()
        {
            return self
                .shared
                .lock()
                .cutoff
                .as_ref()
                .is_some_and(|x| x.joined_at.is_some());
        }
        if Instant::now() >= deadline {
            return false;
        }
        let joined = tokio::select! {
            result = std::future::poll_fn(|context| {
                let mut slot = self.shared.cutoff_task.lock().unwrap_or_else(|p| p.into_inner());
                match slot.as_mut() {
                    Some(task) => std::future::Future::poll(std::pin::Pin::new(task), context).map(Some),
                    None => std::task::Poll::Ready(None),
                }
            }) => result,
            _ = tokio::time::sleep_until(deadline.into()) => None,
        };
        let Some(joined) = joined else {
            return false;
        };
        *self
            .shared
            .cutoff_task
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
        let now = Instant::now();
        if let Some(record) = self.shared.lock().cutoff.as_mut() {
            record.joined_at = Some(now);
            if let Err(error) = joined {
                record.result = Some(Err(format!("BB cutoff task join failed: {error}")));
            }
        }
        now < deadline && !self.pending()
    }
}

impl Drop for Actor {
    fn drop(&mut self) {
        self.stop("BB heartbeat owner dropped; explicit joins still required");
        // Like the enclosing original-service owners, Drop can fence but cannot
        // asynchronously join. Enclosing cleanup must retain this actor until
        // join_until succeeds; a Drop fence is never a successful close receipt.
    }
}

fn run_caller(shared: &Arc<Shared>) {
    loop {
        let mut state = shared.lock();
        while state.stopped_at.is_none() && Instant::now() < state.current_round.scheduled_start {
            let remaining = state
                .current_round
                .scheduled_start
                .saturating_duration_since(Instant::now());
            state = shared
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        drop(state);
        if let Some(reason) = shared.violation() {
            shared.stop(reason);
            return;
        }
        let (selected, deadline) = {
            let mut state = shared.lock();
            let started_at = Instant::now();
            if let Some(reason) = shared.violation_locked(&state, started_at) {
                drop(state);
                shared.stop(reason);
                return;
            }
            state.current_round.caller_started_at = Some(started_at);
            (
                state.selected_factory_addresses.clone(),
                state.current_round.deadline,
            )
        };
        for address in selected {
            if let Some(reason) = shared.violation() {
                shared.stop(reason);
                return;
            }
            let attempt = shared
                .handles
                .bus0
                .exchange_bb_pic_keepalive_at(usize::from(address - 0x50), deadline);
            let error = attempt.failure.clone();
            // Append actual late/error bytes before any refusal or early exit.
            shared.lock().current_round.attempts.push(attempt.into());
            if let Some(error) = error {
                shared.stop(&error);
                return;
            }
            if let Some(reason) = shared.violation() {
                shared.stop(reason);
                return;
            }
        }
        let completed_at = Instant::now();
        #[cfg(all(test, feature = "sim-hal"))]
        {
            let pause = shared
                .before_promotion
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if let Some(pause) = pause {
                pause.wait();
            }
        }
        let mut state = shared.lock();
        // Preserve actual caller completion separately, including when this
        // lock was delayed. Acceptance uses actual time after lock acquisition.
        state.current_round.completed_at = Some(completed_at);
        let accepted_at = Instant::now();
        if let Some(reason) = shared.violation_locked(&state, accepted_at) {
            drop(state);
            shared.stop(reason);
            return;
        }
        state.current_round.accepted_at = Some(accepted_at);
        state.complete_sweeps += 1;
        state.consecutive_complete_sweeps += 1;
        state.last_complete_at = Some(completed_at);
        let completed = state.current_round.clone();
        if state.retained_rounds.len() == RETAINED_NORMAL_ROUNDS {
            state.retained_rounds.pop_front();
        }
        state.retained_rounds.push_back(completed);
        // Reserve the next deadline now from actual completion, never when a
        // late caller eventually wakes. The independent monitor covers this gap.
        state.current_round = reserved_round(state.complete_sweeps + 1, completed_at + AFTER_SWEEP);
        drop(state);
        shared.monitor_wake.notify_one();
    }
}

fn retain_cutoff(shared: &Arc<Shared>) {
    let mut slot = shared.cutoff_task.lock().unwrap_or_else(|p| p.into_inner());
    if shared.lock().cutoff.is_some() {
        return;
    }
    shared.lock().cutoff = Some(BbHeartbeatCutoffObservation {
        prepared_at: Instant::now(),
        started_at: None,
        returned_at: None,
        joined_at: None,
        result: None,
    });
    let work = shared.clone();
    *slot = Some(tokio::task::spawn_blocking(move || {
        if let Some(record) = work.lock().cutoff.as_mut() {
            record.started_at = Some(Instant::now());
        }
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work.cutoff.cutoff()))
                .unwrap_or_else(
                    |_| Err("BB independently retained cutoff callback unwound".into()),
                );
        if let Some(record) = work.lock().cutoff.as_mut() {
            record.returned_at = Some(Instant::now());
            record.result = Some(result);
        }
    }));
}

async fn join_task(
    task: &mut Option<JoinHandle<()>>,
    deadline: Instant,
    shared: &Shared,
    kind: &str,
) -> bool {
    let Some(handle) = task.as_mut() else {
        return true;
    };
    if Instant::now() >= deadline {
        return false;
    }
    let joined = tokio::select! {
        result = handle => Some(result),
        _ = tokio::time::sleep_until(deadline.into()) => None,
    };
    let Some(joined) = joined else {
        return false;
    };
    *task = None;
    let now = Instant::now();
    if let Err(error) = joined {
        shared.stop(&format!("BB heartbeat {kind} join failed: {error}"));
    }
    let mut state = shared.lock();
    if kind == "caller" {
        state.caller_joined_at = Some(now);
    } else {
        state.monitor_joined_at = Some(now);
    }
    now < deadline
}

pub(super) async fn join_until(actor: &mut Option<Actor>, deadline: Instant) -> bool {
    match actor.as_mut() {
        Some(actor) => actor.join_until(deadline).await,
        None => true,
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_management_owner_heartbeat_tests.rs"]
mod tests;
