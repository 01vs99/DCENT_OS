//! Bounded ownership for Tokio runtime tasks.
//!
//! Dropping a Tokio [`JoinHandle`] detaches its task. Runtime components that
//! own hardware or a command channel must instead retain every handle, cancel
//! one shared token, and observe task termination before releasing resources.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::{JoinError, JoinHandle};
use tokio::time::{sleep, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::runtime::safety_watchdog::{
    StandardMiningActorExpectation, StandardMiningActorIssuer, WatchdogRunScope,
};

const TASK_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_ABORT_RESERVE: Duration = Duration::from_millis(100);

/// Terminal state observed while reclaiming an asynchronous runtime task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskStopOutcome {
    Completed,
    Panicked,
    Cancelled,
    Aborted,
    /// An abort was requested but task termination was not observed by the
    /// shared deadline. This normally indicates blocking work inside an async
    /// task and must be treated as a resource-ownership failure.
    TimedOut,
}

/// Per-task shutdown evidence returned to the runtime owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskStopReport {
    pub(crate) name: String,
    pub(crate) outcome: TaskStopOutcome,
}

/// Aggregate result for one bounded shutdown operation.
#[derive(Debug)]
pub(crate) struct TaskStopSummary {
    reports: Vec<TaskStopReport>,
}

/// Diagnostic-only observation returned by maintenance reaping. This type can
/// never satisfy terminal shutdown authority, even when every report happens
/// to be successful.
#[derive(Debug)]
pub(crate) struct TaskReapSummary {
    reports: Vec<TaskStopReport>,
}

impl TaskReapSummary {
    pub(crate) fn any_timed_out(&self) -> bool {
        self.reports
            .iter()
            .any(|report| report.outcome == TaskStopOutcome::TimedOut)
    }

    pub(crate) fn any_panicked(&self) -> bool {
        self.reports
            .iter()
            .any(|report| report.outcome == TaskStopOutcome::Panicked)
    }

    #[cfg(test)]
    fn reports(&self) -> &[TaskStopReport] {
        &self.reports
    }
}

impl TaskStopSummary {
    pub(crate) fn is_empty(&self) -> bool {
        self.reports.is_empty()
    }

    pub(crate) fn any_timed_out(&self) -> bool {
        self.reports
            .iter()
            .any(|report| report.outcome == TaskStopOutcome::TimedOut)
    }

    pub(crate) fn any_panicked(&self) -> bool {
        self.reports
            .iter()
            .any(|report| report.outcome == TaskStopOutcome::Panicked)
    }

    #[cfg(test)]
    fn reports(&self) -> &[TaskStopReport] {
        &self.reports
    }
}

struct NamedTask {
    name: String,
    handle: JoinHandle<()>,
    abort_requested: bool,
    timeout_reported: bool,
}

/// Owns related Tokio tasks under one cancellation and shutdown deadline.
pub(crate) struct RuntimeTaskGuard {
    shutdown: CancellationToken,
    tasks: Vec<NamedTask>,
}

impl RuntimeTaskGuard {
    pub(crate) fn new(shutdown: CancellationToken) -> Self {
        Self {
            shutdown,
            tasks: Vec::new(),
        }
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    #[must_use = "task registration failure must alter the owning lifecycle"]
    pub(crate) fn spawn<F>(&mut self, name: impl Into<String>, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let name = name.into();
        if self.shutdown.is_cancelled() {
            warn!(task = %name, "refusing runtime task spawn after owner cancellation");
            return false;
        }
        if self.tasks.iter().any(|task| task.name == name) {
            warn!(task = %name, "refusing duplicate runtime task name before spawn");
            return false;
        }
        self.tasks.push(NamedTask {
            name,
            handle: tokio::spawn(future),
            abort_requested: false,
            timeout_reported: false,
        });
        true
    }

    pub(crate) fn request_stop(&self) {
        self.shutdown.cancel();
    }

    /// Read-only liveness observation for retained handles. A route must
    /// separately require its complete roster; this grants no new ownership
    /// or closeout authority, and a later task exit remains possible.
    pub(crate) fn all_running(&self) -> bool {
        !self.shutdown.is_cancelled()
            && !self.tasks.is_empty()
            && self.tasks.iter().all(|task| !task.handle.is_finished())
    }

    /// Adopt an already-running helper task without wrapping/detaching its
    /// JoinHandle. Rejection returns the original handle to caller custody.
    pub(crate) fn adopt(
        &mut self,
        name: impl Into<String>,
        handle: JoinHandle<()>,
    ) -> Result<(), JoinHandle<()>> {
        let name = name.into();
        if self.shutdown.is_cancelled() || self.tasks.iter().any(|task| task.name == name) {
            return Err(handle);
        }
        self.tasks.push(NamedTask {
            name,
            handle,
            abort_requested: false,
            timeout_reported: false,
        });
        Ok(())
    }

    /// Cancel and reclaim every task under one total deadline.
    ///
    /// Most of the deadline is reserved for cooperative cancellation. The
    /// final bounded slice requests abort and observes the resulting joins, so
    /// a normal return never silently converts a task into a detached task.
    pub(crate) async fn stop_and_join(&mut self, total_timeout: Duration) -> TaskStopSummary {
        self.stop_and_join_at(Instant::now() + total_timeout, total_timeout)
            .await
    }

    /// Cancel and reclaim every task against a caller-owned absolute deadline.
    /// No intermediate duration conversion may extend that schedule.
    pub(crate) async fn stop_and_join_until(
        &mut self,
        deadline: std::time::Instant,
    ) -> TaskStopSummary {
        let total_timeout = deadline.saturating_duration_since(std::time::Instant::now());
        self.stop_and_join_at(Instant::from_std(deadline), total_timeout)
            .await
    }

    async fn stop_and_join_at(
        &mut self,
        deadline: Instant,
        total_timeout: Duration,
    ) -> TaskStopSummary {
        self.request_stop();
        let abort_reserve = MAX_ABORT_RESERVE.min(total_timeout / 2);
        let cooperative_deadline = deadline - abort_reserve;
        let mut reports = Vec::with_capacity(self.tasks.len());

        while !self.tasks.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                for task in &mut self.tasks {
                    if !task.timeout_reported {
                        warn!(
                            task = %task.name,
                            timeout_ms = total_timeout.as_millis(),
                            "runtime task completion was not observed before the shared deadline; retaining its handle under ownership"
                        );
                        task.timeout_reported = true;
                    }
                    reports.push(TaskStopReport {
                        name: task.name.clone(),
                        outcome: TaskStopOutcome::TimedOut,
                    });
                }
                break;
            }
            self.collect_finished(&mut reports, Some(deadline)).await;
            if self.tasks.is_empty() {
                break;
            }

            let now = Instant::now();
            if now >= cooperative_deadline {
                for task in &mut self.tasks {
                    if !task.abort_requested {
                        task.handle.abort();
                        task.abort_requested = true;
                    }
                }
            }
            sleep(TASK_POLL_INTERVAL.min(deadline.saturating_duration_since(now))).await;
        }

        TaskStopSummary { reports }
    }

    /// Observe and remove tasks that have already completed without changing
    /// the group's cancellation state. Dynamic task producers call this before
    /// registration so completed handles cannot accumulate for the process
    /// lifetime.
    pub(crate) async fn reap_finished(&mut self) -> TaskReapSummary {
        let mut reports = Vec::new();
        self.collect_finished(&mut reports, None).await;
        TaskReapSummary { reports }
    }

    #[cfg(test)]
    fn owned_task_count(&self) -> usize {
        self.tasks.len()
    }

    async fn collect_finished(
        &mut self,
        reports: &mut Vec<TaskStopReport>,
        deadline: Option<Instant>,
    ) {
        while let Some(index) = self.tasks.iter().position(|task| task.handle.is_finished()) {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return;
            }
            let task = self.tasks.swap_remove(index);
            let outcome = classify_join(task.handle.await, task.abort_requested);
            match outcome {
                TaskStopOutcome::Completed => info!(task = %task.name, "runtime task joined"),
                TaskStopOutcome::Panicked => warn!(task = %task.name, "runtime task panicked"),
                TaskStopOutcome::Cancelled | TaskStopOutcome::Aborted => {
                    info!(task = %task.name, ?outcome, "runtime task stopped")
                }
                TaskStopOutcome::TimedOut => unreachable!("finished task cannot time out"),
            }
            reports.push(TaskStopReport {
                name: task.name,
                outcome,
            });
        }
    }
}

/// Fixed standard-daemon hardware actor roster. Callers cannot register
/// arbitrary strings and later claim that a partial or unrelated group was
/// the mining roster expected by watchdog shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StandardMiningActorSlot {
    WorkDispatcher,
    ThermalController,
}

impl StandardMiningActorSlot {
    const COUNT: usize = 2;

    fn index(self) -> usize {
        match self {
            Self::WorkDispatcher => 0,
            Self::ThermalController => 1,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::WorkDispatcher => "work-dispatcher",
            Self::ThermalController => "thermal-controller",
        }
    }

    fn all() -> [Self; Self::COUNT] {
        [Self::WorkDispatcher, Self::ThermalController]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StandardMiningActorTerminal {
    NeverStarted,
    Completed,
}

/// Opaque move-only proof that registration is irreversibly closed and every
/// declared standard mining slot is either NeverStarted or observably
/// terminal. Diagnostic task reports remain inside this receipt and cannot be
/// assembled by callers.
pub(crate) struct StandardMiningActorQuiescenceReceipt {
    run_scope: WatchdogRunScope,
    issuer: Arc<()>,
    _terminal_slots: [StandardMiningActorTerminal; StandardMiningActorSlot::COUNT],
}

impl StandardMiningActorQuiescenceReceipt {
    pub(crate) fn same_run(&self, run_scope: &WatchdogRunScope) -> bool {
        self.run_scope.same_run(run_scope)
    }

    pub(crate) fn authorizes(
        &self,
        run_scope: &WatchdogRunScope,
        expectation: &StandardMiningActorExpectation,
    ) -> bool {
        self.run_scope.same_run(run_scope) && expectation.matches_identity(&self.issuer)
    }
}

/// Result of one terminal standard-roster transition. Failure diagnostics are
/// retained, but only `receipt` is positive watchdog authority.
pub(crate) struct StandardMiningActorStop {
    summary: TaskStopSummary,
    receipt: Option<StandardMiningActorQuiescenceReceipt>,
}

impl StandardMiningActorStop {
    pub(crate) fn any_timed_out(&self) -> bool {
        self.summary.any_timed_out()
    }

    pub(crate) fn any_panicked(&self) -> bool {
        self.summary.any_panicked()
    }

    pub(crate) fn into_receipt(self) -> Option<StandardMiningActorQuiescenceReceipt> {
        self.receipt
    }
}

/// Safety wrapper for the two asynchronous standard mining actors. It owns the
/// complete declared roster for the run and has no maintenance-reap surface.
pub(crate) struct StandardMiningTaskGuard {
    inner: RuntimeTaskGuard,
    run_scope: WatchdogRunScope,
    issuer: Arc<()>,
    started: [bool; StandardMiningActorSlot::COUNT],
    terminalized: bool,
}

impl StandardMiningTaskGuard {
    pub(crate) fn new(
        shutdown: CancellationToken,
        run_scope: WatchdogRunScope,
        issuer: StandardMiningActorIssuer,
    ) -> Self {
        Self {
            inner: RuntimeTaskGuard::new(shutdown),
            run_scope,
            issuer: issuer.into_identity(),
            started: [false; StandardMiningActorSlot::COUNT],
            terminalized: false,
        }
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.inner.cancellation_token()
    }

    #[must_use = "task registration failure must alter the owning lifecycle"]
    pub(crate) fn spawn<F>(&mut self, slot: StandardMiningActorSlot, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let index = slot.index();
        if self.terminalized || self.started[index] {
            warn!(
                task = slot.name(),
                "refusing duplicate or post-terminal standard mining actor spawn"
            );
            return false;
        }
        if !self.inner.spawn(slot.name(), future) {
            return false;
        }
        self.started[index] = true;
        true
    }

    pub(crate) fn request_stop(&self) {
        self.inner.request_stop();
    }

    pub(crate) async fn stop_and_join(
        &mut self,
        total_timeout: Duration,
    ) -> StandardMiningActorStop {
        if self.terminalized {
            warn!("refusing to mint a second standard mining actor closeout");
            let summary = self.inner.stop_and_join(total_timeout).await;
            return StandardMiningActorStop {
                summary,
                receipt: None,
            };
        }
        self.terminalized = true;
        let summary = self.inner.stop_and_join(total_timeout).await;
        self.finish_stop(summary)
    }

    pub(crate) async fn stop_and_join_until(
        &mut self,
        deadline: std::time::Instant,
    ) -> StandardMiningActorStop {
        if self.terminalized {
            warn!("refusing to mint a second standard mining actor closeout");
            let summary = self.inner.stop_and_join_until(deadline).await;
            return StandardMiningActorStop {
                summary,
                receipt: None,
            };
        }
        self.terminalized = true;
        let summary = self.inner.stop_and_join_until(deadline).await;
        self.finish_stop(summary)
    }

    fn finish_stop(&self, summary: TaskStopSummary) -> StandardMiningActorStop {
        // The watchdog is opened only after WorkDispatcher registration. A
        // roster that never owned that required actor is not this run's mining
        // actor graph and cannot authorize Disarm. ThermalController may be
        // owner-issued NeverStarted when shutdown interrupts later startup.
        let roster_complete = self.started[StandardMiningActorSlot::WorkDispatcher.index()]
            && !summary.any_timed_out()
            && StandardMiningActorSlot::all()
                .into_iter()
                .filter(|slot| self.started[slot.index()])
                .all(|slot| {
                    summary
                        .reports
                        .iter()
                        .filter(|report| {
                            report.name == slot.name()
                                && report.outcome == TaskStopOutcome::Completed
                        })
                        .count()
                        == 1
                })
            && summary.reports.len() == self.started.iter().filter(|started| **started).count();
        if !roster_complete {
            return StandardMiningActorStop {
                summary,
                receipt: None,
            };
        }
        let receipt = StandardMiningActorQuiescenceReceipt {
            run_scope: self.run_scope.clone(),
            issuer: Arc::clone(&self.issuer),
            _terminal_slots: self.started.map(|started| {
                if started {
                    StandardMiningActorTerminal::Completed
                } else {
                    StandardMiningActorTerminal::NeverStarted
                }
            }),
        };
        StandardMiningActorStop {
            summary,
            receipt: Some(receipt),
        }
    }
}

impl Drop for RuntimeTaskGuard {
    fn drop(&mut self) {
        // Tokio JoinHandle::drop detaches. Request cancellation and abort before
        // the non-blocking handle drop. This is best effort: synchronous blocking
        // code inside a task can continue until it returns to an await boundary.
        self.request_stop();
        for task in &self.tasks {
            task.handle.abort();
        }
    }
}

fn classify_join(result: Result<(), JoinError>, abort_requested: bool) -> TaskStopOutcome {
    match result {
        Ok(()) => TaskStopOutcome::Completed,
        Err(error) if error.is_panic() => TaskStopOutcome::Panicked,
        Err(error) if error.is_cancelled() && abort_requested => TaskStopOutcome::Aborted,
        Err(error) if error.is_cancelled() => TaskStopOutcome::Cancelled,
        Err(_) => TaskStopOutcome::Cancelled,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant as StdInstant};

    use tokio_util::sync::CancellationToken;

    use super::{
        RuntimeTaskGuard, StandardMiningActorSlot, StandardMiningTaskGuard, TaskStopOutcome,
    };

    #[tokio::test]
    async fn retained_running_observation_detects_finished_adopted_task_and_cancellation() {
        let stop = CancellationToken::new();
        let mut guard = RuntimeTaskGuard::new(stop.clone());
        assert!(!guard.all_running());
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        assert!(guard
            .adopt(
                "observed",
                tokio::spawn(async move {
                    let _ = wait.await;
                })
            )
            .is_ok());
        assert!(guard.all_running());
        release.send(()).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while guard.all_running() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        assert!(guard.spawn("pending", std::future::pending()));
        assert!(
            !guard.all_running(),
            "one exited sibling cannot be hidden by a live task"
        );
        stop.cancel();
        assert!(!guard.all_running());
        let closed = guard.stop_and_join(Duration::from_secs(1)).await;
        assert!(!closed.any_timed_out() && !closed.any_panicked());
    }
    use crate::runtime::safety_watchdog::{StandardWatchdogRunAdmission, WatchdogRunScope};
    use crate::runtime::source_contract::compact_rust_source;

    #[tokio::test]
    async fn cooperative_tasks_are_cancelled_and_joined() {
        let shutdown = CancellationToken::new();
        let worker_shutdown = shutdown.clone();
        let mut guard = RuntimeTaskGuard::new(shutdown);
        assert!(guard.spawn("cooperative", async move {
            worker_shutdown.cancelled().await;
        }));

        let summary = guard.stop_and_join(Duration::from_secs(1)).await;

        assert_eq!(summary.reports().len(), 1);
        assert_eq!(summary.reports()[0].outcome, TaskStopOutcome::Completed);
        assert!(!summary.any_timed_out());
    }

    #[tokio::test]
    async fn completion_first_observed_at_the_deadline_is_not_positive_evidence() {
        let mut guard = RuntimeTaskGuard::new(CancellationToken::new());
        assert!(guard.spawn("finished-before-zero-budget", async {}));
        tokio::task::yield_now().await;

        let summary = guard.stop_and_join(Duration::ZERO).await;
        assert!(summary.any_timed_out());
        assert_eq!(summary.reports()[0].outcome, TaskStopOutcome::TimedOut);
        assert_eq!(guard.owned_task_count(), 1);

        let reaped = guard.reap_finished().await;
        assert!(!reaped.any_timed_out());
        assert_eq!(guard.owned_task_count(), 0);
    }

    #[tokio::test]
    async fn absolute_task_join_never_rebases_an_expired_deadline() {
        let mut guard = RuntimeTaskGuard::new(CancellationToken::new());
        assert!(guard.spawn("finished-before-expired-deadline", async {}));
        tokio::task::yield_now().await;
        let original_deadline = StdInstant::now();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let started = StdInstant::now();
        let summary = guard.stop_and_join_until(original_deadline).await;

        assert!(started.elapsed() < Duration::from_millis(40));
        assert_eq!(summary.reports().len(), 1);
        assert_eq!(summary.reports()[0].outcome, TaskStopOutcome::TimedOut);
        assert_eq!(guard.owned_task_count(), 1);

        let reaped = guard.reap_finished().await;
        assert!(!reaped.any_timed_out());
        assert_eq!(guard.owned_task_count(), 0);
    }

    #[tokio::test]
    async fn panics_are_observed_instead_of_silently_detached() {
        let mut guard = RuntimeTaskGuard::new(CancellationToken::new());
        assert!(guard.spawn("panicked", async { panic!("intentional test panic") }));

        let summary = guard.stop_and_join(Duration::from_secs(1)).await;

        assert!(summary.any_panicked());
        assert_eq!(summary.reports()[0].outcome, TaskStopOutcome::Panicked);
    }

    #[tokio::test]
    async fn noncooperative_pending_task_is_aborted_within_shared_deadline() {
        let mut guard = RuntimeTaskGuard::new(CancellationToken::new());
        assert!(guard.spawn("pending", std::future::pending()));
        let started = StdInstant::now();

        let summary = guard.stop_and_join(Duration::from_millis(80)).await;

        assert_eq!(summary.reports().len(), 1);
        assert_eq!(summary.reports()[0].outcome, TaskStopOutcome::Aborted);
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn drop_cancels_and_aborts_without_detaching_live_work() {
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let mut guard = RuntimeTaskGuard::new(shutdown.clone());
        assert!(guard.spawn("drop", async move {
            struct MarkDrop(Arc<AtomicBool>);
            impl Drop for MarkDrop {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let _mark = MarkDrop(task_dropped);
            task_shutdown.cancelled().await;
            std::future::pending::<()>().await;
        }));
        tokio::task::yield_now().await;

        drop(guard);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn duplicate_names_are_refused_without_replacing_the_owner() {
        let mut guard = RuntimeTaskGuard::new(CancellationToken::new());
        assert!(guard.spawn("unique", std::future::pending()));
        let duplicate_started = Arc::new(AtomicBool::new(false));
        let duplicate_started_task = Arc::clone(&duplicate_started);
        assert!(!guard.spawn("unique", async move {
            duplicate_started_task.store(true, Ordering::Release);
        }));
        tokio::task::yield_now().await;
        assert!(!duplicate_started.load(Ordering::Acquire));
        assert_eq!(guard.owned_task_count(), 1);

        let summary = guard.stop_and_join(Duration::from_millis(80)).await;
        assert_eq!(summary.reports()[0].outcome, TaskStopOutcome::Aborted);
        assert!(!guard.spawn("after-stop", async {
            panic!("cancelled owner must not spawn this body");
        }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_task_handle_remains_owned_until_termination_is_observed() {
        let mut guard = RuntimeTaskGuard::new(CancellationToken::new());
        assert!(guard.spawn("blocking-poll", async {
            std::thread::sleep(Duration::from_millis(180));
        }));
        tokio::task::yield_now().await;

        let summary = guard.stop_and_join(Duration::from_millis(40)).await;
        assert!(summary.any_timed_out());
        assert_eq!(guard.owned_task_count(), 1);

        let repeated = guard.stop_and_join(Duration::from_millis(20)).await;
        assert!(repeated.any_timed_out());
        assert_eq!(guard.owned_task_count(), 1);

        tokio::time::sleep(Duration::from_millis(200)).await;
        let summary = guard.stop_and_join(Duration::from_secs(1)).await;
        assert!(!summary.any_timed_out());
        assert_eq!(guard.owned_task_count(), 0);
    }

    #[tokio::test]
    async fn repeated_dynamic_tasks_are_reaped_without_unbounded_handle_growth() {
        let mut guard = RuntimeTaskGuard::new(CancellationToken::new());
        for sequence in 0..128_u64 {
            assert!(guard.spawn(format!("dynamic-{sequence}"), async {}));
            tokio::task::yield_now().await;
            let summary = guard.reap_finished().await;
            assert!(!summary.any_panicked());
            assert!(guard.owned_task_count() <= 1);
        }
        tokio::task::yield_now().await;
        let _ = guard.reap_finished().await;
        assert_eq!(guard.owned_task_count(), 0);
    }

    #[tokio::test]
    async fn global_signal_cannot_pre_cancel_independent_mining_owner() {
        let global_shutdown = CancellationToken::new();
        let mining_shutdown = CancellationToken::new();
        let mut mining_tasks = RuntimeTaskGuard::new(mining_shutdown.clone());
        let task_shutdown = mining_shutdown.clone();
        assert!(mining_tasks.spawn("mining", async move {
            task_shutdown.cancelled().await;
        }));

        global_shutdown.cancel();
        tokio::task::yield_now().await;
        assert!(global_shutdown.is_cancelled());
        assert!(!mining_shutdown.is_cancelled());
        assert_eq!(mining_tasks.owned_task_count(), 1);

        mining_tasks.request_stop();
        let summary = mining_tasks.stop_and_join(Duration::from_secs(1)).await;
        assert!(!summary.any_timed_out());
        assert_eq!(mining_tasks.owned_task_count(), 0);
    }

    #[tokio::test]
    async fn standard_roster_rejects_every_slot_never_started() {
        let (scope, issuer, _expectation, _, _, _, _) =
            StandardWatchdogRunAdmission::new().into_parts();
        let mut guard = StandardMiningTaskGuard::new(CancellationToken::new(), scope, issuer);

        assert!(guard
            .stop_and_join(Duration::ZERO)
            .await
            .into_receipt()
            .is_none());
    }

    #[tokio::test]
    async fn standard_roster_receipt_is_run_and_issuer_bound() {
        let (scope, issuer, expectation, _, _, _, _) =
            StandardWatchdogRunAdmission::new().into_parts();
        let other_run = WatchdogRunScope::new();
        let mut guard =
            StandardMiningTaskGuard::new(CancellationToken::new(), scope.clone(), issuer);
        let (_foreign_scope, foreign_issuer, foreign_expectation, _, _, _, _) =
            StandardWatchdogRunAdmission::for_scope_for_test(scope.clone()).into_parts();
        let _foreign_guard =
            StandardMiningTaskGuard::new(CancellationToken::new(), scope.clone(), foreign_issuer);
        assert!(guard.spawn(StandardMiningActorSlot::WorkDispatcher, async {}));
        let receipt = guard
            .stop_and_join(Duration::from_secs(1))
            .await
            .into_receipt()
            .unwrap();

        assert!(receipt.authorizes(&scope, &expectation));
        assert!(!receipt.authorizes(&scope, &foreign_expectation));
        assert!(!receipt.authorizes(&other_run, &expectation));
    }

    #[tokio::test]
    async fn standard_roster_terminalization_is_one_shot_and_closes_spawn_admission() {
        let (scope, issuer, _expectation, _, _, _, _) =
            StandardWatchdogRunAdmission::new().into_parts();
        let mut guard = StandardMiningTaskGuard::new(CancellationToken::new(), scope, issuer);
        let worker_shutdown = guard.cancellation_token();
        assert!(
            guard.spawn(StandardMiningActorSlot::WorkDispatcher, async move {
                worker_shutdown.cancelled().await;
            })
        );

        assert!(guard
            .stop_and_join(Duration::from_secs(1))
            .await
            .into_receipt()
            .is_some());
        assert!(
            !guard.spawn(StandardMiningActorSlot::ThermalController, async {
                panic!("post-terminal actor body must not start")
            })
        );
        assert!(guard
            .stop_and_join(Duration::ZERO)
            .await
            .into_receipt()
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn standard_roster_timeout_returns_diagnostics_without_authority() {
        let (scope, issuer, _expectation, _, _, _, _) =
            StandardWatchdogRunAdmission::new().into_parts();
        let mut guard = StandardMiningTaskGuard::new(CancellationToken::new(), scope, issuer);
        assert!(guard.spawn(StandardMiningActorSlot::WorkDispatcher, async {
            std::thread::sleep(Duration::from_millis(180));
        }));
        tokio::task::yield_now().await;

        let stop = guard.stop_and_join(Duration::from_millis(20)).await;
        assert!(stop.any_timed_out());
        assert!(stop.into_receipt().is_none());
    }

    #[tokio::test]
    async fn standard_roster_panic_is_quiescent_but_not_clean_disarm_authority() {
        let (scope, issuer, _expectation, _, _, _, _) =
            StandardWatchdogRunAdmission::new().into_parts();
        let mut guard = StandardMiningTaskGuard::new(CancellationToken::new(), scope, issuer);
        assert!(guard.spawn(StandardMiningActorSlot::WorkDispatcher, async {
            panic!("actor panic fixture");
        }));

        let stop = guard.stop_and_join(Duration::from_secs(1)).await;
        assert!(stop.any_panicked());
        assert!(stop.into_receipt().is_none());
    }

    #[test]
    fn mining_hardware_tasks_are_owned_and_quiesced_before_hardware_teardown() {
        let daemon = include_str!("../daemon.rs");
        let dispatcher = include_str!("../work_dispatcher.rs");
        let compact_daemon = compact_rust_source(daemon);
        let compact_dispatcher = compact_rust_source(dispatcher);

        assert!(daemon.contains("StandardMiningTaskGuard::new("));
        assert!(daemon.contains("watchdog_run_scope.clone()"));
        assert!(!daemon.contains("StandardMiningTaskGuard::new(shutdown_token.child_token()"));
        assert!(daemon.contains(".spawn(StandardMiningActorSlot::WorkDispatcher"));
        assert!(daemon.contains(".spawn(StandardMiningActorSlot::ThermalController"));
        assert_eq!(
            daemon.matches(".spawn(StandardMiningActorSlot::").count(),
            2
        );
        assert!(!compact_daemon.contains("tokio::spawn(asyncmove{dispatcher.run().await;"));

        let thermal_start = daemon
            .find("let thermal_liveness_loop = thermal_liveness.clone();")
            .expect("thermal controller task start");
        let thermal_end = daemon[thermal_start..]
            .find("// ---- Start state publisher task")
            .map(|offset| thermal_start + offset)
            .expect("thermal controller task end");
        let thermal_scope = &daemon[thermal_start..thermal_end];
        assert!(thermal_scope.contains(".spawn(StandardMiningActorSlot::ThermalController"));
        assert!(!thermal_scope.contains("tokio::spawn"));

        let watchdog_start = daemon
            .split("let thermal_liveness =")
            .nth(1)
            .and_then(|tail| {
                // Bound the region to the watchdog owner's own wiring terminal
                // so later, unrelated task spawns (which legitimately clone the
                // generic shutdown token) cannot leak into this assertion.
                tail.split("self.watchdog_receipt_rx = Some(watchdog_receipt_rx);")
                    .next()
            })
            .expect("standard daemon watchdog owner");
        assert!(watchdog_start.contains("owned_watchdog_kicker("));
        assert!(watchdog_start.contains("self.watchdog_tasks.cancellation_token()"));
        assert!(watchdog_start.contains(".spawn(\"soc-watchdog-kicker\""));
        assert!(!watchdog_start.contains("shutdown.clone()"));
        let watchdog_registration = watchdog_start
            .find(".spawn(\"soc-watchdog-kicker\"")
            .expect("watchdog task registration");
        let watchdog_state_publication = watchdog_start
            .find("self.watchdog_intent_tx = Some(watchdog_intent_tx)")
            .expect("watchdog lifecycle state publication");
        assert!(watchdog_registration < watchdog_state_publication);

        let owned_watchdog = daemon
            .rsplit_once("fn owned_watchdog_kicker(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split("pub(crate) fn spawn_watchdog_kicker(").next())
            .expect("owned watchdog implementation");
        let owner_cancel = owned_watchdog
            .split("owner_shutdown.cancelled()")
            .nth(1)
            .and_then(|tail| tail.split("changed = intent_rx.changed()").next())
            .expect("abnormal watchdog owner cancellation branch");
        assert!(!owner_cancel.contains("close_magic"));
        assert!(owned_watchdog.contains("permit = &mut disarm_rx"));
        let compact_owned_watchdog = owned_watchdog.split_whitespace().collect::<String>();
        assert!(compact_owned_watchdog.contains(
            "permit.authorizes(&watchdog_scope,&mining_actor_expectation,&unit_closeout_expectation,&teardown_budget_expectation,)"
        ));
        assert!(!daemon.contains("WatchdogIntent::Disarm"));
        assert_eq!(owned_watchdog.matches("wd.try_close_magic()").count(), 1);
        assert!(owned_watchdog.contains("std::panic::catch_unwind("));
        assert!(owned_watchdog.contains("std::panic::AssertUnwindSafe(|| wd.try_close_magic())"));
        assert!(owned_watchdog.contains("std::panic::resume_unwind(payload)"));
        assert!(owned_watchdog.contains("std::mem::ManuallyDrop::new(wd)"));
        assert!(owned_watchdog.contains("std::mem::ManuallyDrop::into_inner(wd)"));
        assert!(owned_watchdog.matches("std::mem::forget(wd)").count() >= 6);

        let shutdown = daemon
            .split("async fn shutdown(&mut self)")
            .nth(1)
            .expect("daemon shutdown function");
        let terminal_latch = shutdown
            .find("voltage_mailbox.latch_terminal()")
            .expect("terminal voltage latch");
        let mining_cancel = shutdown
            .find("self.mining_tasks.request_stop()")
            .expect("mining task cancellation request");
        let mining_join = shutdown
            .find(".stop_and_join(mining_stop_timeout)")
            .expect("owned mining task join");
        let checked_first_cut = shutdown
            .find("StandardTeardownProgress::after_checked_cut(")
            .expect("worker-timed first voltage cutoff");
        let voltage_disable = shutdown
            .find("Step 5a: Disabling hash board voltages")
            .expect("voltage teardown");
        let teardown_intent = shutdown
            .find("WatchdogIntent::Teardown { deadline }")
            .expect("bounded watchdog teardown intent");
        let retry_guard = shutdown
            .find("std::mem::replace(&mut self.shutdown_attempted, true)")
            .expect("single-admission shutdown guard");
        let heartbeat_stop = shutdown
            .find("self.heartbeat_shutdown_token.cancel()")
            .expect("heartbeat stop");
        let cooldown = shutdown
            .find("Step 9: Fans commanded back to home idle PWM")
            .expect("cooldown completion");
        let explicit_disarm = shutdown
            .find("disarm_tx.send(permit)")
            .expect("same-run evidence-gated watchdog disarm");
        let positive_receipt = shutdown
            .find("Some(WatchdogTaskReceipt::MagicCloseWriteCompleted { completed_at })")
            .expect("positive watchdog disarm receipt");
        assert!(retry_guard < teardown_intent);
        assert!(teardown_intent < terminal_latch);
        assert!(terminal_latch < mining_cancel);
        assert!(mining_cancel < checked_first_cut);
        assert!(checked_first_cut < mining_join);
        assert!(terminal_latch < voltage_disable);
        assert!(voltage_disable < heartbeat_stop);
        assert!(heartbeat_stop < cooldown);
        assert!(cooldown < explicit_disarm);
        assert!(explicit_disarm < positive_receipt);
        // Incomplete shutdown evidence must refuse terminal closeout UNCONDITIONALLY.
        // The historical guard `self.watchdog_disarm_tx.is_some() && !watchdog_disarm_allowed`
        // was fail-OPEN: when no disarm sender existed the refusal was skipped entirely and
        // closeout proceeded on incomplete evidence. Pin the unconditional form and ban the
        // old conjunction by construction.
        assert!(shutdown.contains("if !watchdog_disarm_allowed {"));
        let fail_open_disarm_guard = [
            "if self.watchdog_disarm_tx.is_some()",
            " && !watchdog_disarm_allowed",
        ]
        .concat();
        assert!(!shutdown.contains(&fail_open_disarm_guard));
        assert!(shutdown.contains("StandardDaemonShutdownEvidence::new("));
        assert!(shutdown.contains("api_mutation_barrier_result"));
        assert!(shutdown.contains("standard watchdog disarm requires the exact API drain receipt"));
        assert!(shutdown.contains("api_commit_fence_result.context("));
        assert!(shutdown.contains("composition_fence_result.context("));
        assert!(shutdown.contains("terminal_i2c_transition.context("));
        assert!(shutdown.contains("mining_actor_receipt.context("));
        assert!(shutdown.contains("StandardWatchdogDisarmPermit::from_evidence(evidence)"));
        assert!(shutdown.contains("SoC watchdog remains armed"));
        assert!(shutdown.contains("if magic_close_write_completed"));
        assert!(shutdown.contains("This daemon performed no SoC watchdog magic-close write"));

        assert_eq!(dispatcher.matches("voltage_reply_tasks.spawn(").count(), 2);
        assert!(!compact_dispatcher.contains("tokio::spawn(asyncmove{let(timed_out,result)"));
    }
}
