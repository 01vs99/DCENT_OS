use super::*;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::AtomicBool;
use std::sync::Condvar;
use std::time::Duration;

#[test]
fn cancelled_and_timed_out_close_retains_actual_task_and_never_restarts_owner_drop() {
    run(async {
        let (mut runtime, _master, _slave) = pty();
        runtime.execute(UartRequest::Hold, due()).await.unwrap();
        let gate = Gate::new();
        let _release = Release(gate.clone());
        let worker_gate = gate.clone();
        let mut pending = Box::pin(runtime.close_with(due(), move || worker_gate.wait()));
        tokio::select! {
            _ = &mut pending => panic!("close caller returned while deliberately retained"),
            _ = gate.wait_entered() => {},
        }
        drop(pending);
        let state = runtime.snapshot();
        assert!(state.close_caller_pending && !state.caller_pending);
        let close = state.close.unwrap();
        assert!(close.owner_drop_returned_at.is_some() && close.caller_joined_at.is_none());
        assert!(!runtime.close_caller.as_ref().unwrap().is_finished());
        assert!(
            !runtime
                .close_until(Instant::now() + Duration::from_millis(10))
                .await
        );
        let retained = runtime.snapshot();
        assert!(retained.close_caller_pending);
        assert_eq!(retained.close.unwrap().started_at, close.started_at);
        gate.release();
        assert!(runtime.close_until(due()).await);
        let finished = runtime.snapshot();
        assert!(!finished.close_caller_pending);
        let actual = finished.close.unwrap();
        assert_eq!(actual.started_at, close.started_at);
        assert_eq!(actual.owner_drop_returned_at, close.owner_drop_returned_at);
        assert!(actual.caller_joined_at.is_some());
    });
}

#[test]
fn async_held_transmitter_failure_retains_actual_pty_report_and_prior_joined_history() {
    run(async {
        let (mut runtime, mut master, slave) = pty();
        runtime.execute(UartRequest::Hold, due()).await.unwrap();
        master.write_all(&[1, 2, 3]).unwrap();
        input_ready(&slave);
        let state = runtime
            .execute(UartRequest::ObserveHeld, due())
            .await
            .unwrap();
        assert!(state.dispatch.permanently_stopped && state.dispatch.held);
        assert!(!state.caller_pending && !state.dispatch.observation_caller_pending);
        assert_eq!(state.last_complete.unwrap().sequence, 1);
        let record = state.latest.unwrap();
        assert!(record.joined_at.is_some() && record.promoted_at.is_none());
        let UartOutput::Observed(value) = record.output.unwrap() else {
            panic!("missing actual transmitter report")
        };
        assert!(value.failure.is_some() && value.caller_completed_at.is_none());
        let attempt = value.observations[0].attempt.as_ref().unwrap();
        assert_eq!(attempt.last.pending_output, Some(0));
        assert!(attempt.last.line_status.is_none());
        input_ready(&slave);
        assert!(runtime.execute(UartRequest::Resume, due()).await.is_err());
        assert!(runtime.close_until(due()).await);
    });
}

fn due() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn run(body: impl std::future::Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(body);
}
fn pty() -> (BbUartRuntime, File, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: initialized fresh local PTY output descriptors; optional output
    // and configuration pointers absent. No physical UART is accessed.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    // SAFETY: adopt each independently returned descriptor exactly once.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: this fresh slave descriptor has not been otherwise adopted.
    let slave = unsafe { File::from_raw_fd(slave) };
    let backend = SerialChainBackend::open_native_linux_only(
        0,
        &format!("/proc/self/fd/{}", slave.as_raw_fd()),
        115200,
    )
    .unwrap();
    (
        BbUartRuntime::new(BbSerialDispatchOwner::new(vec![backend], 20_000)),
        master,
        slave,
    )
}
fn input_ready(slave: &File) {
    let mut item = libc::pollfd {
        fd: slave.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd for the retained software PTY, bounded wait.
    assert_eq!(unsafe { libc::poll(&mut item, 1, 500) }, 1);
}
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}
impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            condition: Condvar::new(),
        })
    }
    fn wait(&self) {
        self.entered.store(true, Ordering::SeqCst);
        let guard = self.released.lock().unwrap();
        let (_guard, timed) = self
            .condition
            .wait_timeout_while(guard, Duration::from_secs(4), |released| !*released)
            .unwrap();
        assert!(!timed.timed_out(), "bounded runtime fixture timed out");
    }
    async fn wait_entered(&self) {
        let deadline = due();
        while !self.entered.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[test]
fn async_owned_hold_receive_resume_and_send_keep_actual_uart_and_joined_records() {
    run(async {
        let (mut runtime, mut master, slave) = pty();
        let held = runtime.execute(UartRequest::Hold, due()).await.unwrap();
        let record = held.last_complete.unwrap();
        assert_eq!(record.sequence, 1);
        assert!(record.joined_at.is_some() && record.promoted_at.is_some());
        assert!(held.dispatch.held && !held.caller_pending);
        let wire = vec![0xaa, 0x55, 1, 2, 3, 4, 0, 0x80, 0x12, 0x34, 0x80];
        master.write_all(&wire).unwrap();
        input_ready(&slave);
        let received = runtime.execute(UartRequest::Receive, due()).await.unwrap();
        let record = received.last_complete.unwrap();
        assert_eq!(record.sequence, 2);
        let UartOutput::Received(value) = record.output.unwrap() else {
            panic!("wrong output")
        };
        assert_eq!(value.parsed.nonces[0].1.raw_frame.as_slice(), wire);
        assert!(received.dispatch.held);
        runtime.execute(UartRequest::Resume, due()).await.unwrap();
        let sent = runtime
            .execute(
                UartRequest::SendRaw {
                    chain: 0,
                    bytes: vec![1, 2, 3],
                    job: 40,
                    now_us: 0,
                },
                due(),
            )
            .await
            .unwrap();
        assert_eq!(sent.last_complete.unwrap().sequence, 4);
        let mut actual = [0; 3];
        master.read_exact(&mut actual).unwrap();
        assert_eq!(actual, [1, 2, 3]);
        assert!(runtime.close_until(due()).await);
    });
}

#[test]
fn returned_record_is_not_promoted_until_the_retained_actual_task_joins() {
    run(async {
        let (mut runtime, _master, _slave) = pty();
        let gate = Gate::new();
        let _release = Release(gate.clone());
        let worker_gate = gate.clone();
        let deadline = due();
        runtime
            .start_with(UartRequest::Hold, deadline, perform, move || {
                worker_gate.wait()
            })
            .unwrap();
        gate.wait_entered().await;
        let state = runtime.snapshot();
        let record = state.latest.unwrap();
        assert!(
            record.returned_at.is_some()
                && record.joined_at.is_none()
                && record.promoted_at.is_none()
        );
        assert!(state.caller_pending && state.last_complete.is_none());
        assert!(!runtime.caller.as_ref().unwrap().task.is_finished());
        gate.release();
        assert!(runtime.join_until(deadline, true).await);
        let state = runtime.snapshot();
        assert!(!state.caller_pending);
        let record = state.last_complete.unwrap();
        assert!(record.returned_at.unwrap() <= record.joined_at.unwrap());
        assert!(runtime.close_until(due()).await);
    });
}

#[test]
fn dropping_pending_join_future_fences_but_retains_original_owner_and_actual_handle() {
    run(async {
        let (mut runtime, _master, _slave) = pty();
        let gate = Gate::new();
        let _release = Release(gate.clone());
        let worker_gate = gate.clone();
        let deadline = due();
        runtime
            .start_with(UartRequest::Hold, deadline, perform, move || {
                worker_gate.wait()
            })
            .unwrap();
        gate.wait_entered().await;
        let mut pending = Box::pin(runtime.join_until(deadline, true));
        tokio::select! {
            _ = &mut pending => panic!("blocked caller joined early"),
            _ = tokio::time::sleep(Duration::from_millis(10)) => {},
        }
        drop(pending);
        let state = runtime.snapshot();
        assert!(state.dispatch.permanently_stopped && state.caller_pending);
        assert!(state.latest.unwrap().joined_at.is_none() && state.last_complete.is_none());
        assert!(lock(&runtime.state, &runtime.stop).owner.is_some());
        gate.release();
        assert!(runtime.join_callers_until(due()).await);
        let state = runtime.snapshot();
        assert!(!state.caller_pending && state.latest.unwrap().joined_at.is_some());
        assert!(state.last_complete.is_none());
        assert!(runtime.close_until(due()).await);
    });
}

#[test]
fn late_join_cleanup_preserves_original_deadline_and_blocks_close_until_real_return() {
    run(async {
        let (mut runtime, _master, _slave) = pty();
        let gate = Gate::new();
        let _release = Release(gate.clone());
        let worker_gate = gate.clone();
        let original = Instant::now() + Duration::from_millis(200);
        runtime
            .start_with(UartRequest::Hold, original, perform, move || {
                worker_gate.wait()
            })
            .unwrap();
        gate.wait_entered().await;
        assert!(!runtime.join_until(original, true).await);
        assert!(
            runtime.snapshot().caller_pending && runtime.snapshot().dispatch.permanently_stopped
        );
        assert!(
            !runtime
                .close_until(Instant::now() + Duration::from_millis(10))
                .await
        );
        assert!(runtime.snapshot().close.is_none());
        gate.release();
        assert!(runtime.join_callers_until(due()).await);
        let state = runtime.snapshot();
        let record = state.latest.unwrap();
        assert_eq!(record.deadline, original);
        assert!(record.joined_at.unwrap() >= original);
        assert!(record.promoted_at.is_none() && state.last_complete.is_none());
        assert!(runtime.close_until(due()).await);
    });
}

#[test]
fn caught_worker_unwind_retains_the_original_uart_for_explicit_close() {
    run(async {
        let (mut runtime, _master, _slave) = pty();
        let deadline = due();
        runtime
            .start_with(
                UartRequest::Hold,
                deadline,
                |owner, request, deadline| {
                    assert!(matches!(owner, Some(OwnerState::Running(_))));
                    let _ = perform(owner, request, deadline).unwrap();
                    assert!(matches!(owner, Some(OwnerState::Held(_))));
                    panic!("injected raw caller unwind");
                },
                || {},
            )
            .unwrap();
        assert!(runtime.join_until(deadline, true).await);
        let state = runtime.snapshot();
        let record = state.latest.unwrap();
        assert!(record.failure.as_ref().unwrap().contains("unwound"));
        assert!(
            record.returned_at.is_some()
                && record.joined_at.is_some()
                && record.promoted_at.is_none()
        );
        assert!(lock(&runtime.state, &runtime.stop).owner.is_some());
        assert!(state.dispatch.permanently_stopped && state.last_complete.is_none());
        assert!(runtime.close_until(due()).await);
    });
}

#[test]
fn overlapping_request_is_refused_without_replacing_the_pending_call_or_uart() {
    run(async {
        let (mut runtime, _master, _slave) = pty();
        let gate = Gate::new();
        let _release = Release(gate.clone());
        let worker_gate = gate.clone();
        runtime
            .start_with(UartRequest::Hold, due(), perform, move || {
                worker_gate.wait()
            })
            .unwrap();
        gate.wait_entered().await;
        assert!(runtime.execute(UartRequest::Receive, due()).await.is_err());
        let state = runtime.snapshot();
        assert_eq!(state.latest.unwrap().sequence, 1);
        assert!(
            state.caller_pending
                && state.dispatch.permanently_stopped
                && state.last_complete.is_none()
        );
        gate.release();
        assert!(runtime.join_callers_until(due()).await);
        assert!(runtime.close_until(due()).await);
    });
}

#[test]
fn terminal_or_expired_request_does_not_spawn_or_consume_pending_input() {
    run(async {
        for terminal in [false, true] {
            let (mut runtime, mut master, slave) = pty();
            master.write_all(&[1, 2, 3]).unwrap();
            input_ready(&slave);
            if terminal {
                runtime.stop_handle().stop();
            }
            let deadline = if terminal { due() } else { Instant::now() };
            assert!(runtime
                .execute(UartRequest::Receive, deadline)
                .await
                .is_err());
            let state = runtime.snapshot();
            assert!(
                !state.caller_pending && state.latest.is_none() && state.last_complete.is_none()
            );
            input_ready(&slave);
            assert!(runtime.close_until(due()).await);
        }
    });
}

#[test]
fn later_actual_transport_error_preserves_last_complete_historical_record() {
    run(async {
        let (mut runtime, mut master, _slave) = pty();
        runtime
            .execute(
                UartRequest::SendRaw {
                    chain: 0,
                    bytes: vec![1, 2, 3],
                    job: 40,
                    now_us: 0,
                },
                due(),
            )
            .await
            .unwrap();
        let mut actual = [0; 3];
        master.read_exact(&mut actual).unwrap();
        drop(master);
        let result = runtime
            .execute(
                UartRequest::SendRaw {
                    chain: 0,
                    bytes: vec![4, 5, 6],
                    job: 42,
                    now_us: 20_000,
                },
                due(),
            )
            .await
            .unwrap();
        assert_eq!(result.last_complete.unwrap().sequence, 1);
        let record = result.latest.unwrap();
        assert_eq!(record.sequence, 2);
        assert!(record.promoted_at.is_none());
        let UartOutput::Sent(output) = record.output.unwrap() else {
            panic!("missing raw error")
        };
        assert!(output.io.unwrap().status.failure.is_some());
        assert!(result.dispatch.permanently_stopped);
        assert!(runtime.close_until(due()).await);
    });
}

#[test]
fn explicit_close_joins_owner_drop_and_is_idempotent_without_new_request_admission() {
    run(async {
        let (mut runtime, _master, _slave) = pty();
        runtime.execute(UartRequest::Hold, due()).await.unwrap();
        assert!(runtime.close_until(due()).await);
        let state = runtime.snapshot();
        let close = state.close.unwrap();
        assert!(close.started_at <= close.owner_drop_returned_at.unwrap());
        assert!(close.owner_drop_returned_at.unwrap() <= close.caller_joined_at.unwrap());
        assert!(!state.caller_pending && !state.close_caller_pending);
        assert!(lock(&runtime.state, &runtime.stop).owner.is_none());
        assert!(runtime.close_until(due()).await);
        assert_eq!(
            runtime.snapshot().close.unwrap().caller_joined_at,
            close.caller_joined_at
        );
        assert!(runtime.execute(UartRequest::Resume, due()).await.is_err());
    });
}

#[test]
fn exhausted_sequence_refuses_new_work_and_keeps_original_owner_for_cleanup() {
    run(async {
        let (mut runtime, _master, _slave) = pty();
        lock(&runtime.state, &runtime.stop).sequence = u64::MAX;
        assert!(runtime.execute(UartRequest::Hold, due()).await.is_err());
        let state = runtime.snapshot();
        assert!(!state.caller_pending && state.latest.is_none());
        assert!(state.stopped_reason.unwrap().contains("exhausted"));
        assert!(lock(&runtime.state, &runtime.stop).owner.is_some());
        assert!(runtime.close_until(due()).await);
    });
}
