use super::*;
use dcentrald_hal::bb_management_runtime::simulated::Fixture;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::Duration;

fn due() -> Instant {
    Instant::now() + Duration::from_secs(12)
}
fn run(body: impl std::future::Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(body);
}
fn controller(block: bool, bad_factory: bool) -> (BbController, Fixture, File, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: fresh initialized local PTY outputs with no optional buffers or
    // termios pointers. This test never contacts a physical serial device.
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
    // SAFETY: each newly created descriptor is adopted exactly once.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: the distinct fresh slave descriptor is not otherwise adopted.
    let slave = unsafe { File::from_raw_fd(slave) };
    let backend = SerialChainBackend::open_native_linux_only(
        0,
        &format!("/proc/self/fd/{}", slave.as_raw_fd()),
        115200,
    )
    .unwrap();
    let uart = BbUartRuntime::new(BbSerialDispatchOwner::new(vec![backend], 20_000));
    let (management, fixture) = Fixture::new(block, bad_factory);
    (BbController::new(management, uart), fixture, master, slave)
}
fn input_ready(slave: &File) {
    let mut item = libc::pollfd {
        fd: slave.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized descriptor for the retained local PTY, 500ms bound.
    assert_eq!(unsafe { libc::poll(&mut item, 1, 500) }, 1);
}
fn closed(value: &BbController) {
    let state = value.snapshot();
    assert!(state.uart.dispatch.permanently_stopped && state.management.stopped());
    assert!(
        !state.uart.caller_pending
            && !state.uart.close_caller_pending
            && !state.management_close_caller_pending
    );
    let management = state.management_close.unwrap();
    assert!(management.both_service_receipts && management.caller_joined_at.is_some());
    let uart = state.uart.close.unwrap();
    assert!(uart.owner_drop_returned_at.is_some() && uart.caller_joined_at.is_some());
    let close = state.cleanup.unwrap();
    assert!(close.management_closed && close.uart_closed && close.returned_at.is_some());
}

#[test]
fn actual_joint_diagnostics_and_runtime_receive_preserve_same_workers_and_uart() {
    run(async {
        let (mut value, fixture, mut master, slave) = controller(false, false);
        let initial = value.diagnose_held_until(&[0x50], due()).await.unwrap();
        assert!(initial.uart.dispatch.held && initial.management.diagnostic_complete());
        assert_eq!(initial.last_complete.unwrap().sequence, 1);
        value.merge_requested_voltage(Some(13.4), None).unwrap();
        master.write_all(&[0xaa, 0x55, 1, 2, 3]).unwrap();
        input_ready(&slave);
        let observed = value.observe_held_until(due()).await.unwrap();
        assert_eq!(observed.last_complete.unwrap().sequence, 2);
        assert!(observed.management.last_pair_sequence().is_some());
        let record = observed.uart.latest.unwrap();
        assert!(record.joined_at.is_some() && record.promoted_at.is_some());
        let UartOutput::Received(rx) = record.output.unwrap() else {
            panic!("actual receive absent")
        };
        assert_eq!(rx.io[0].1.bytes, [0xaa, 0x55, 1, 2, 3]);
        assert_eq!(fixture.apw_opcodes(), [2, 1, 6, 3, 2, 1, 6, 3]);
        assert!(value.close_until(due()).await);
        closed(&value);
    });
}

#[test]
fn unsupported_actual_pty_line_status_refuses_voltage_before_any_new_apw_bytes() {
    run(async {
        let (mut value, fixture, _master, _slave) = controller(false, false);
        value.diagnose_held_until(&[0x50], due()).await.unwrap();
        value.merge_requested_voltage(Some(13.4), None).unwrap();
        let before = fixture.apw_opcodes();
        assert!(value.voltage_held_until(due()).await.is_err());
        let state = value.snapshot();
        assert!(state.management.stopped() && state.uart.dispatch.permanently_stopped);
        assert_eq!(state.last_complete.unwrap().sequence, 1);
        assert!(state.latest.unwrap().accepted_at.is_none());
        assert!(state.management.last_execution_sequence().is_none());
        let UartOutput::Observed(observed) = state.uart.latest.unwrap().output.unwrap() else {
            panic!("actual drain attempt absent")
        };
        let attempt = observed.observations[0].attempt.as_ref().unwrap();
        assert_eq!(attempt.last.pending_output, Some(0));
        assert!(attempt.last.line_status.is_none() && attempt.failure.is_some());
        assert_eq!(fixture.apw_opcodes(), before);
        assert!(value.close_until(due()).await);
        closed(&value);
    });
}

#[test]
fn cancelled_joint_diagnostic_fences_both_and_closes_uart_while_bus_worker_is_blocked() {
    run(async {
        let (mut value, fixture, _master, _slave) = controller(true, false);
        let mut pending = Box::pin(value.diagnose_held_until(&[0x50], due()));
        tokio::select! { _ = &mut pending => panic!("actual worker blocked"), _ = fixture.wait_apw_entered() => {} }
        drop(pending);
        let state = value.snapshot();
        assert!(state.management.stopped() && state.uart.dispatch.permanently_stopped);
        assert!(state.last_complete.is_none());
        assert!(
            !value
                .close_until(Instant::now() + Duration::from_millis(100))
                .await
        );
        let partial = value.snapshot();
        assert!(partial
            .uart
            .close
            .as_ref()
            .unwrap()
            .caller_joined_at
            .is_some());
        assert!(value.management.close_receipts().1.is_none());
        fixture.release();
        assert!(value.close_until(due()).await);
        closed(&value);
        assert!(value.snapshot().last_complete.is_none());
        assert_eq!(fixture.apw_opcodes(), [2]);
    });
}

#[test]
fn external_combined_stop_refuses_both_subsystems_without_io() {
    run(async {
        let (mut value, fixture, _master, _slave) = controller(false, false);
        value.stop_handle().stop();
        assert!(value.diagnose_held_until(&[0x50], due()).await.is_err());
        assert!(value.voltage_held_until(due()).await.is_err());
        assert!(fixture.apw_opcodes().is_empty() && fixture.bus0_events() == 0);
        assert!(value.close_until(due()).await);
        closed(&value);
    });
}

#[test]
fn invalid_original_factory_fences_held_uart_and_has_no_accepted_controller_history() {
    run(async {
        let (mut value, _fixture, _master, _slave) = controller(false, true);
        assert!(value.diagnose_held_until(&[0x50], due()).await.is_err());
        let state = value.snapshot();
        assert!(state.uart.dispatch.permanently_stopped && state.management.stopped());
        assert!(state.last_complete.is_none() && state.management.factory().is_none());
        assert!(value.close_until(due()).await);
        closed(&value);
    });
}

#[test]
fn expired_admission_and_sequence_exhaustion_start_no_transport_or_management_io() {
    run(async {
        for exhausted in [false, true] {
            let (mut value, fixture, _master, _slave) = controller(false, false);
            if exhausted {
                value.sequence = u64::MAX;
            }
            let deadline = if exhausted { due() } else { Instant::now() };
            assert!(value.diagnose_held_until(&[0x50], deadline).await.is_err());
            assert!(value.snapshot().uart.latest.is_none());
            assert!(fixture.apw_opcodes().is_empty() && fixture.bus0_events() == 0);
            assert!(value.close_until(due()).await);
            closed(&value);
        }
    });
}

#[test]
fn cancelled_cleanup_retains_component_tasks_and_retry_never_reopens_any_owner() {
    run(async {
        let (mut value, fixture, _master, _slave) = controller(true, false);
        let mut diagnosis = Box::pin(value.diagnose_held_until(&[0x50], due()));
        tokio::select! { _ = &mut diagnosis => panic!("blocked"), _ = fixture.wait_apw_entered() => {} }
        drop(diagnosis);
        let mut cleanup = Box::pin(value.close_until(due()));
        tokio::select! { _ = &mut cleanup => panic!("worker still blocked"), _ = tokio::time::sleep(Duration::from_millis(30)) => {} }
        drop(cleanup);
        assert!(value.snapshot().cleanup.unwrap().returned_at.is_none());
        fixture.release();
        assert!(value.close_until(due()).await);
        closed(&value);
        let before = value.snapshot().uart.close.unwrap().started_at;
        assert!(value.close_until(due()).await);
        closed(&value);
        assert_eq!(value.snapshot().uart.close.unwrap().started_at, before);
        assert_eq!(fixture.apw_opcodes(), [2]);
    });
}

#[test]
fn joined_controller_cold_write_uses_original_uart_without_new_apw_exchange() {
    run(async {
        let (mut value, fixture, mut master, _slave) = controller(false, false);
        value.diagnose_held_until(&[0x50], due()).await.unwrap();
        let before = fixture.apw_opcodes();
        let state = value
            .cold_control_until(0, ColdControl::MiscBroadcast(0x00c1_00b0), due())
            .await
            .unwrap();
        assert_eq!(state.last_complete.unwrap().sequence, 2);
        assert!(state.uart.dispatch.held && !state.uart.dispatch.control_caller_pending);
        let record = state.uart.latest.unwrap();
        assert!(record.joined_at.is_some() && record.promoted_at.is_some());
        let UartOutput::Controlled(actual) = record.output.unwrap() else {
            panic!("actual cold report absent")
        };
        assert!(actual.caller_completed_at.is_some() && actual.failure.is_none());
        assert_eq!((actual.writes.len(), actual.delays.len()), (3, 3));
        let mut arrived = [0; 33];
        master.read_exact(&mut arrived).unwrap();
        let mut expected = crate::protocol::CMD_PREAMBLE.to_vec();
        expected.extend_from_slice(&crate::bm1362::build_broadcast_write_frame(
            crate::drivers::bm1362::regs::MISC_CONTROL,
            0x00c1_00b0,
        ));
        assert_eq!(arrived.as_slice(), expected.repeat(3));
        assert_eq!(fixture.apw_opcodes(), before);
        assert!(value.close_until(due()).await);
        closed(&value);
    });
}

#[test]
fn unsupported_actual_baud_drain_fences_both_without_new_management_writes() {
    run(async {
        let (mut value, fixture, _master, _slave) = controller(false, false);
        value.diagnose_held_until(&[0x50], due()).await.unwrap();
        let before = fixture.apw_opcodes();
        assert!(value
            .cold_control_until(
                0,
                ColdControl::HostBaud(dcentrald_hal::serial_chain::NativeBbBaud::Mining),
                due()
            )
            .await
            .is_err());
        let state = value.snapshot();
        assert!(state.management.stopped() && state.uart.dispatch.permanently_stopped);
        assert_eq!(state.last_complete.unwrap().sequence, 1);
        assert!(state.latest.unwrap().accepted_at.is_none());
        let UartOutput::Controlled(actual) = state.uart.latest.unwrap().output.unwrap() else {
            panic!("actual baud failure missing")
        };
        let baud = actual.host_baud.unwrap();
        assert!(baud.drain.unwrap().failure.is_some() && baud.set_started_at.is_none());
        assert_eq!(fixture.apw_opcodes(), before);
        assert!(value.close_until(due()).await);
        closed(&value);
    });
}
