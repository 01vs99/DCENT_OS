//! Neutral terminal fence for hardware-execution generations.
//!
//! The standard measured runtime and parser-validated serial runtime carry
//! different evidence tokens, but need identical commit-vs-revocation
//! ordering. This primitive supplies that ordering without converting one
//! evidence grade into another.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, TryLockError};
use std::time::Instant;

pub(crate) trait ExecutionFenceIdentity: Clone + Send + Sync + 'static {
    fn execution_identity(&self) -> String;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionFencePhase {
    Open,
    Closed,
}

#[derive(Debug)]
struct ExecutionFenceState<T> {
    phase: ExecutionFencePhase,
    token: T,
}

#[derive(Debug)]
struct ExecutionFenceInner<T> {
    state: Mutex<ExecutionFenceState<T>>,
    commit_fence: RwLock<()>,
    commit_panicked: AtomicBool,
}

#[derive(Debug)]
pub(crate) struct ExecutionFencePort<T> {
    inner: Arc<ExecutionFenceInner<T>>,
}

impl<T> Clone for ExecutionFencePort<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ExecutionFenceTerminal<T> {
    inner: Arc<ExecutionFenceInner<T>>,
}

/// Move-only proof that admission is already closed even if an entered
/// physical commit has not returned yet. Safety closeout can therefore revoke
/// immediately, impose its own wait deadline, and keep progressing toward an
/// out-of-band cutoff without reopening the generation.
#[derive(Debug)]
pub(crate) struct RevokedExecutionFence<T> {
    inner: Arc<ExecutionFenceInner<T>>,
    token: T,
}

/// One-shot observation of a revoked physical-commit domain.
///
/// `Pending` returns the same move-only authority so callers can impose an
/// asynchronous deadline without abandoning a blocking lock waiter. `Fenced`
/// consumes that authority and is the only state that mints a quiescence
/// receipt.
#[derive(Debug)]
pub(crate) enum ExecutionFenceTryWait<T> {
    Pending(RevokedExecutionFence<T>),
    Fenced(ExecutionFenceReceipt<T>),
}

impl<T> Clone for ExecutionFenceTerminal<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionCommitError {
    detail: String,
}

impl fmt::Display for ExecutionCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for ExecutionCommitError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionFenceReceipt<T> {
    token: T,
    fenced_at: Instant,
    fence_poisoned: bool,
}

impl<T> ExecutionFenceReceipt<T> {
    pub(crate) fn token(&self) -> &T {
        &self.token
    }

    pub(crate) fn fenced_at(&self) -> Instant {
        self.fenced_at
    }

    /// Quiescence was observed, but an entered commit unwound or the lock was
    /// poisoned. The physical mutation may be partial; this receipt cannot
    /// support clean watchdog disarm or composition replacement.
    pub(crate) fn fence_poisoned(&self) -> bool {
        self.fence_poisoned
    }
}

struct ExecutionCommitUnwindGuard<'a> {
    commit_panicked: &'a AtomicBool,
    completed: bool,
}

impl Drop for ExecutionCommitUnwindGuard<'_> {
    fn drop(&mut self) {
        if !self.completed && std::thread::panicking() {
            self.commit_panicked.store(true, Ordering::Release);
        }
    }
}

pub(crate) fn execution_fence_domain<T>(
    token: T,
) -> (ExecutionFencePort<T>, ExecutionFenceTerminal<T>) {
    let inner = Arc::new(ExecutionFenceInner {
        state: Mutex::new(ExecutionFenceState {
            phase: ExecutionFencePhase::Open,
            token,
        }),
        commit_fence: RwLock::new(()),
        commit_panicked: AtomicBool::new(false),
    });
    (
        ExecutionFencePort {
            inner: Arc::clone(&inner),
        },
        ExecutionFenceTerminal { inner },
    )
}

impl<T: ExecutionFenceIdentity> ExecutionFencePort<T> {
    /// Immutable identity for route-specific command validation. This snapshot
    /// never grants a commit; the subsequent mutation still uses this fence.
    pub(crate) fn identity_snapshot(&self) -> Option<T> {
        self.inner
            .state
            .lock()
            .ok()
            .map(|state| state.token.clone())
    }

    #[cfg(test)]
    pub(crate) fn owner_count_for_test(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    pub(crate) fn commit<R, E>(
        &self,
        operation: &'static str,
        mutation: impl FnOnce() -> Result<R, E>,
    ) -> Result<R, ExecutionCommitError>
    where
        E: fmt::Display,
    {
        self.commit_if(operation, || true, mutation)
    }

    /// Commit only while both this fence and an owning subsystem's external
    /// generation latch remain open. The external predicate is checked before
    /// and after acquiring the physical-commit fence, so cancellation-safe
    /// subsystem revocation does not need the terminal merely to reject later
    /// work.
    pub(crate) fn commit_if<R, E, A>(
        &self,
        operation: &'static str,
        externally_admitted: A,
        mutation: impl FnOnce() -> Result<R, E>,
    ) -> Result<R, ExecutionCommitError>
    where
        E: fmt::Display,
        A: Fn() -> bool,
    {
        // Do not block on a writer-preferring RwLock before observing terminal
        // phase. A queued closeout writer may be waiting behind an already
        // entered commit; a late reader that blocks behind that writer would
        // deadlock callers which must reject the late commit before releasing
        // the entered one. The second phase check closes the race between the
        // first observation and acquiring the read-side physical-commit fence.
        let _fence = loop {
            if !externally_admitted() {
                return Err(ExecutionCommitError {
                    detail: format!("execution generation is closed; refusing {operation}"),
                });
            }
            let state = self.inner.state.lock().map_err(|_| ExecutionCommitError {
                detail: format!("execution state is unavailable before {operation}"),
            })?;
            if state.phase != ExecutionFencePhase::Open {
                return Err(ExecutionCommitError {
                    detail: format!(
                        "execution generation {} is closed; refusing {operation}",
                        state.token.execution_identity()
                    ),
                });
            }
            drop(state);

            match self.inner.commit_fence.try_read() {
                Ok(fence) => {
                    if !externally_admitted() {
                        return Err(ExecutionCommitError {
                            detail: format!("execution generation is closed; refusing {operation}"),
                        });
                    }
                    let state = self.inner.state.lock().map_err(|_| ExecutionCommitError {
                        detail: format!("execution state is unavailable before {operation}"),
                    })?;
                    if state.phase != ExecutionFencePhase::Open {
                        return Err(ExecutionCommitError {
                            detail: format!(
                                "execution generation {} is closed; refusing {operation}",
                                state.token.execution_identity()
                            ),
                        });
                    }
                    drop(state);
                    break fence;
                }
                Err(TryLockError::WouldBlock) => std::thread::yield_now(),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(ExecutionCommitError {
                        detail: format!("execution commit fence is unavailable before {operation}"),
                    });
                }
            }
        };
        let mut unwind_guard = ExecutionCommitUnwindGuard {
            commit_panicked: &self.inner.commit_panicked,
            completed: false,
        };
        let result = mutation();
        unwind_guard.completed = true;
        result.map_err(|error| ExecutionCommitError {
            detail: format!("{operation} failed: {error}"),
        })
    }
}

impl<T: ExecutionFenceIdentity> ExecutionFenceTerminal<T> {
    pub(crate) fn revoke(self) -> RevokedExecutionFence<T> {
        let token = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.phase = ExecutionFencePhase::Closed;
            state.token.clone()
        };
        RevokedExecutionFence {
            inner: self.inner,
            token,
        }
    }
}

impl<T: ExecutionFenceIdentity> RevokedExecutionFence<T> {
    pub(crate) fn execution_identity(&self) -> String {
        self.token.execution_identity()
    }

    /// Observe quiescence without parking an OS thread.
    ///
    /// Revocation has already closed admission. A successful exclusive probe
    /// therefore proves that every commit which entered the physical mutation
    /// section has returned. A contender which observed Open before revocation
    /// but had not acquired the read fence must recheck Closed after acquiring
    /// it and cannot execute its mutation.
    pub(crate) fn try_wait_for_commit_fence(self) -> ExecutionFenceTryWait<T> {
        let lock_poisoned = match self.inner.commit_fence.try_write() {
            Ok(fence) => {
                drop(fence);
                Some(false)
            }
            Err(TryLockError::WouldBlock) => None,
            Err(TryLockError::Poisoned(error)) => {
                drop(error.into_inner());
                Some(true)
            }
        };
        if let Some(lock_poisoned) = lock_poisoned {
            ExecutionFenceTryWait::Fenced(ExecutionFenceReceipt {
                token: self.token,
                fenced_at: Instant::now(),
                fence_poisoned: lock_poisoned || self.inner.commit_panicked.load(Ordering::Acquire),
            })
        } else {
            ExecutionFenceTryWait::Pending(self)
        }
    }

    #[cfg(test)]
    fn wait_for_commit_fence_for_test(self) -> ExecutionFenceReceipt<T> {
        let fence = self
            .inner
            .commit_fence
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(fence);
        ExecutionFenceReceipt {
            token: self.token,
            fenced_at: Instant::now(),
            fence_poisoned: self.inner.commit_panicked.load(Ordering::Acquire),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[derive(Clone)]
    struct Identity(&'static str);

    impl ExecutionFenceIdentity for Identity {
        fn execution_identity(&self) -> String {
            self.0.to_string()
        }
    }

    #[test]
    fn revocation_is_nonblocking_and_rejects_late_commit_before_wait_finishes() {
        let (port, terminal) = execution_fence_domain(Identity("test-generation"));
        let held_port = port.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let commit = std::thread::spawn(move || {
            held_port
                .commit("held commit", || -> Result<(), &'static str> {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let revoked = terminal.revoke();
        let (fenced_tx, fenced_rx) = std::sync::mpsc::channel();
        let (wait_started_tx, wait_started_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            wait_started_tx.send(()).unwrap();
            fenced_tx
                .send(revoked.wait_for_commit_fence_for_test())
                .unwrap();
        });
        wait_started_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        let writer_wait_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match port.inner.commit_fence.try_read() {
                Err(TryLockError::WouldBlock) => break,
                Ok(probe) => drop(probe),
                Err(TryLockError::Poisoned(_)) => panic!("commit fence poisoned"),
            }
            assert!(
                Instant::now() < writer_wait_deadline,
                "terminal fence writer never entered its wait"
            );
            std::thread::yield_now();
        }

        let late_executed = Arc::new(AtomicBool::new(false));
        let late_executed_worker = Arc::clone(&late_executed);
        let (late_tx, late_rx) = std::sync::mpsc::channel();
        let late_port = port.clone();
        let late_thread = std::thread::spawn(move || {
            let result = late_port.commit("late commit", || -> Result<(), &'static str> {
                late_executed_worker.store(true, Ordering::SeqCst);
                Ok(())
            });
            late_tx.send(result).unwrap();
        });
        let late = late_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("closed admission must not block behind the terminal writer");
        assert!(late.is_err());
        assert!(!late_executed.load(Ordering::SeqCst));

        assert!(matches!(
            fenced_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        release_tx.send(()).unwrap();
        let receipt = fenced_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(receipt.token().0, "test-generation");
        commit.join().unwrap();
        late_thread.join().unwrap();
        waiter.join().unwrap();
    }

    #[test]
    fn revoked_try_wait_is_pending_without_spawning_and_completes_after_release() {
        let (port, terminal) = execution_fence_domain(Identity("polled-generation"));
        let held_port = port.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let commit = std::thread::spawn(move || {
            held_port
                .commit("held commit", || -> Result<(), &'static str> {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let revoked = terminal.revoke();
        assert_eq!(revoked.execution_identity(), "polled-generation");
        let pending = match revoked.try_wait_for_commit_fence() {
            ExecutionFenceTryWait::Pending(pending) => pending,
            ExecutionFenceTryWait::Fenced(_) => {
                panic!("held physical commit unexpectedly appeared quiescent")
            }
        };
        assert!(port
            .commit("late commit", || -> Result<(), &'static str> { Ok(()) })
            .is_err());

        release_tx.send(()).unwrap();
        commit.join().unwrap();
        let receipt = match pending.try_wait_for_commit_fence() {
            ExecutionFenceTryWait::Fenced(receipt) => receipt,
            ExecutionFenceTryWait::Pending(_) => {
                panic!("released physical commit remained unexpectedly busy")
            }
        };
        assert_eq!(receipt.token().0, "polled-generation");
    }

    #[test]
    fn panicked_commit_marks_the_quiescent_fence_receipt_dirty() {
        let (port, terminal) = execution_fence_domain(Identity("panic-generation"));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = port.commit("panicking commit", || -> Result<(), &'static str> {
                panic!("fixture commit panic after possible physical mutation")
            });
        }));
        assert!(panic.is_err());

        let receipt = match terminal.revoke().try_wait_for_commit_fence() {
            ExecutionFenceTryWait::Fenced(receipt) => receipt,
            ExecutionFenceTryWait::Pending(_) => {
                panic!("unwound commit retained its read-side fence")
            }
        };
        assert!(receipt.fence_poisoned());
        assert!(port
            .commit("late commit", || -> Result<(), &'static str> { Ok(()) })
            .is_err());
    }
}
