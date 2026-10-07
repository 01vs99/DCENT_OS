use super::*;
use dcentrald_hal::serial_chain::{BackendKind, Reading};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

fn due() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn held_stop() -> DispatchStop {
    DispatchStop {
        state: Arc::new(AtomicU8::new(HELD)),
    }
}
fn reported_empty(deadline: Instant) -> TxDrainAttempt {
    let now = Instant::now();
    TxDrainAttempt {
        started_at: now,
        deadline,
        polls: 1,
        last: Reading {
            backend: BackendKind::Kernel,
            pending_output: Some(0),
            line_status: Some(1),
            observed_at: Some(now),
        },
        caller_completed_at: Some(now),
        failure: None,
    }
}
fn pty() -> (SerialChainBackend, File, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: two initialized output pointers for fresh local software PTYs;
    // all optional configuration/name pointers absent, no physical device.
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
    // SAFETY: each fresh descriptor is consumed by exactly one File owner.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: the independent returned slave has not yet been adopted.
    let slave = unsafe { File::from_raw_fd(slave) };
    let backend = SerialChainBackend::open_native_linux_only(
        0,
        &format!("/proc/self/fd/{}", slave.as_raw_fd()),
        115200,
    )
    .unwrap();
    (backend, master, slave)
}
fn input_ready(slave: &File) {
    let mut item = libc::pollfd {
        fd: slave.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd for the retained local PTY, bounded wait.
    assert_eq!(unsafe { libc::poll(&mut item, 1, 500) }, 1);
}

#[test]
fn completed_observations_remain_held_with_no_implicit_resume_or_electrical_capability() {
    let stop = held_stop();
    let deadline = due();
    let mut calls = Vec::new();
    let result = observe_backends(&stop, 2, deadline, |chain| {
        assert!(stop.snapshot().held && stop.snapshot().observation_caller_pending);
        assert!(!stop.snapshot().send_caller_pending && !stop.snapshot().receive_caller_pending);
        calls.push(chain);
        Ok(reported_empty(deadline))
    });
    assert_eq!(calls, [0, 1]);
    assert_eq!(result.observations.len(), 2);
    assert_eq!(result.deadline, deadline);
    assert!(result.caller_completed_at.unwrap() >= result.started_at);
    assert!(result.failure.is_none());
    assert!(stop.snapshot().held && !stop.snapshot().permanently_stopped);
    assert!(!stop.snapshot().observation_caller_pending);
    assert_eq!(
        SendScope::enter(&stop).err(),
        Some(DispatchError::HeldOrPending)
    );
}

#[test]
fn later_partial_status_error_preserves_prior_and_current_reports_and_skips_next_chain() {
    let stop = held_stop();
    let deadline = due();
    let mut calls = Vec::new();
    let result = observe_backends(&stop, 3, deadline, |chain| {
        calls.push(chain);
        let mut report = reported_empty(deadline);
        if chain == 1 {
            report.last.line_status = None;
            report.caller_completed_at = None;
            report.failure = Some("driver does not implement line status".into());
        }
        Ok(report)
    });
    assert_eq!(calls, [0, 1]);
    assert_eq!(result.observations.len(), 2);
    assert_eq!(
        result.observations[0]
            .attempt
            .as_ref()
            .unwrap()
            .last
            .line_status,
        Some(1)
    );
    let partial = result.observations[1].attempt.as_ref().unwrap();
    assert_eq!(partial.last.pending_output, Some(0));
    assert!(partial.last.line_status.is_none());
    assert!(result
        .failure
        .as_ref()
        .unwrap()
        .contains("does not implement"));
    assert!(result.caller_completed_at.is_none());
    assert!(stop.snapshot().permanently_stopped && !stop.snapshot().observation_caller_pending);
}

#[test]
fn preexpired_stopped_unheld_and_empty_owner_admission_never_calls_a_backend() {
    for variant in 0..4 {
        let stop = held_stop();
        if variant == 1 {
            stop.stop();
        }
        if variant == 2 {
            stop.state.store(0, Ordering::SeqCst);
        }
        let deadline = if variant == 0 { Instant::now() } else { due() };
        let result = observe_backends(&stop, if variant == 3 { 0 } else { 1 }, deadline, |_| {
            panic!("unadmitted query")
        });
        assert!(result.failure.is_some() && result.caller_completed_at.is_none());
        assert!(result.observations.is_empty());
        assert!(!stop.snapshot().observation_caller_pending);
        if variant != 2 {
            assert!(stop.snapshot().permanently_stopped);
        }
    }
}

#[test]
fn an_admitted_blocked_observation_remains_pending_until_actual_return_and_join() {
    let stop = held_stop();
    let peer_stop = stop.clone();
    let deadline = due();
    let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
    let worker_gate = gate.clone();
    let task = std::thread::spawn(move || {
        let mut calls = Vec::new();
        let result = observe_backends(&peer_stop, 2, deadline, |chain| {
            calls.push(chain);
            let (mutex, condition) = &*worker_gate;
            let mut guard = mutex.lock().unwrap();
            guard.0 = true;
            condition.notify_all();
            let (_guard, waited) = condition
                .wait_timeout_while(guard, Duration::from_secs(3), |state| !state.1)
                .unwrap();
            assert!(!waited.timed_out());
            Ok(reported_empty(deadline))
        });
        (result, calls)
    });
    let (mutex, condition) = &*gate;
    let guard = mutex.lock().unwrap();
    let (mut guard, waited) = condition
        .wait_timeout_while(guard, Duration::from_secs(1), |state| !state.0)
        .unwrap();
    assert!(!waited.timed_out());
    stop.stop();
    assert!(stop.snapshot().observation_caller_pending && stop.snapshot().held);
    assert!(!task.is_finished());
    guard.1 = true;
    condition.notify_all();
    drop(guard);
    let (result, calls) = task.join().unwrap();
    assert_eq!(calls, [0]);
    assert_eq!(result.observations.len(), 1);
    assert_eq!(
        result.observations[0]
            .attempt
            .as_ref()
            .unwrap()
            .last
            .line_status,
        Some(1)
    );
    assert!(
        result.failure.as_ref().unwrap().contains("stopped")
            && result.caller_completed_at.is_none()
    );
    assert!(!stop.snapshot().observation_caller_pending && stop.snapshot().permanently_stopped);
}

#[test]
fn observation_unwind_stops_before_clearing_the_active_scope() {
    let stop = held_stop();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        observe_backends(&stop, 1, due(), |_| {
            assert!(stop.snapshot().observation_caller_pending);
            panic!("injected observation unwind");
        })
    }));
    assert!(result.is_err());
    assert!(stop.snapshot().permanently_stopped && stop.snapshot().held);
    assert!(!stop.snapshot().observation_caller_pending);
}

#[test]
fn backend_error_without_attempt_is_retained_without_filling_historical_fields() {
    let stop = held_stop();
    let result = observe_backends(&stop, 2, due(), |_| {
        Err(dcentrald_hal::HalError::Platform(
            "poisoned exact owner".into(),
        ))
    });
    assert_eq!(result.observations.len(), 1);
    assert_eq!(result.observations[0].chain, 0);
    assert!(result.observations[0].attempt.is_none());
    assert!(result.observations[0]
        .error
        .as_ref()
        .unwrap()
        .contains("poisoned"));
    assert!(result.failure.is_some() && result.caller_completed_at.is_none());
}

#[test]
fn borrowed_held_real_pty_refuses_unsupported_status_without_consuming_input_or_changing_ring() {
    let (backend, mut master, slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let sent = owner.try_send_raw_until(0, &[1, 2, 3], 40, 0, due());
    assert_eq!(sent.dispatch, Ok(true));
    master.write_all(&[9, 8, 7]).unwrap();
    input_ready(&slave);
    let ring = owner.in_flight_ring(0);
    let mut held = owner.hold_dispatch().unwrap();
    let result = held.observe_transmitters_until(due());
    assert!(result.failure.is_some() && result.caller_completed_at.is_none());
    assert_eq!(result.observations.len(), 1);
    let attempt = result.observations[0].attempt.as_ref().unwrap();
    assert_eq!(attempt.last.pending_output, Some(0));
    assert!(attempt.last.line_status.is_none());
    assert_eq!(held.resume(), Err(DispatchError::Stopped));
    assert_eq!(owner.in_flight_ring(0), ring);
    input_ready(&slave);
    let mut tx = [0; 3];
    master.read_exact(&mut tx).unwrap();
    assert_eq!(tx, [1, 2, 3]);
}

#[test]
fn owned_hold_moves_with_actual_uart_to_worker_and_back_before_explicit_resume() {
    let (backend, mut master, slave) = pty();
    let owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let held = owner
        .into_hold()
        .unwrap_or_else(|(_, error)| panic!("{error:?}"));
    let stop = held.stop_handle();
    let wire = vec![0xaa, 0x55, 1, 2, 3, 4, 0, 0x80, 0x12, 0x34, 0x80];
    master.write_all(&wire).unwrap();
    input_ready(&slave);
    let task = std::thread::spawn(move || {
        let mut held = held;
        let received = held.receive_until(due());
        (held, received)
    });
    let (held, received) = task.join().unwrap();
    assert!(received.parsed.caller_completed);
    assert_eq!(received.parsed.nonces[0].1.raw_frame.as_slice(), wire);
    assert!(held.snapshot().held && stop.snapshot().held);
    let mut owner = held
        .resume()
        .unwrap_or_else(|(_, error)| panic!("{error:?}"));
    assert!(!stop.snapshot().held);
    let result = owner.try_send_raw_until(0, &[4, 5, 6], 40, 0, due());
    assert_eq!(result.dispatch, Ok(true));
    let mut tx = [0; 3];
    master.read_exact(&mut tx).unwrap();
    assert_eq!(tx, [4, 5, 6]);
}

#[test]
fn owned_hold_terminal_resume_failure_retains_original_uart_and_drop_keeps_stop() {
    let (backend, _master, _slave) = pty();
    let owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let mut held = owner
        .into_hold()
        .unwrap_or_else(|(_, error)| panic!("{error:?}"));
    let stop = held.stop_handle();
    let result = held.observe_transmitters_until(due());
    assert!(result.failure.is_some());
    let (held, error) = match held.resume() {
        Ok(_) => panic!("terminal resumed"),
        Err(value) => value,
    };
    assert_eq!(error, DispatchError::Stopped);
    assert_eq!(held.owner.inner.chain_count(), 1);
    assert!(held.snapshot().permanently_stopped && held.snapshot().held);
    drop(held);
    assert!(stop.snapshot().permanently_stopped);
    let (backend, _master2, _slave2) = pty();
    let held = BbSerialDispatchOwner::new(vec![backend], 20_000)
        .into_hold()
        .unwrap_or_else(|(_, error)| panic!("{error:?}"));
    let drop_stop = held.stop_handle();
    drop(held);
    assert!(drop_stop.snapshot().permanently_stopped);
}

#[test]
fn failed_owned_transition_returns_exact_owner_and_cannot_bypass_forgotten_borrowed_hold() {
    for terminal in [false, true] {
        let (backend, _master, _slave) = pty();
        let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
        let stop = owner.stop_handle();
        if terminal {
            stop.stop();
        } else {
            std::mem::forget(owner.hold_dispatch().unwrap());
        }
        let (mut owner, error) = match owner.into_hold() {
            Ok(_) => panic!("invalid owned transition"),
            Err(value) => value,
        };
        assert_eq!(
            error,
            if terminal {
                DispatchError::Stopped
            } else {
                DispatchError::HeldOrPending
            }
        );
        assert_eq!(owner.inner.chain_count(), 1);
        assert!(owner
            .try_send_raw_until(0, &[1, 2], 40, 0, due())
            .dispatch
            .is_err());
        drop(owner);
        assert!(stop.snapshot().permanently_stopped);
    }
}
