use super::*;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};

fn due() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn pty() -> (SerialChainBackend, File, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: initialized descriptors for a fresh local PTY; optional buffers
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
    // SAFETY: adopt each distinct newly created descriptor exactly once.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: this fresh slave is not otherwise owned.
    let slave = unsafe { File::from_raw_fd(slave) };
    let backend = SerialChainBackend::open_native_linux_only(
        0,
        &format!("/proc/self/fd/{}", slave.as_raw_fd()),
        115200,
    )
    .unwrap();
    (backend, master, slave)
}
fn input_ready(file: &File, wait: i32) -> bool {
    let mut item = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd for an owned host PTY and bounded wait.
    (unsafe { libc::poll(&mut item, 1, wait) }) == 1
}
fn good(attempt: &ColdControlAttempt) {
    assert!(attempt.failure.is_none(), "{attempt:?}");
    assert!(attempt.caller_completed_at.unwrap() < attempt.deadline);
    assert!(attempt
        .writes
        .iter()
        .all(|write| write.attempt.accepted_prefix == write.requested
            && write.attempt.status.flags_restored));
}
fn reset_wire() -> Vec<u8> {
    vec![0xaa, 0x55, 0x13, 0x62, 0x03, 0, 0, 0, 0x0d]
}

#[test]
fn actual_cold_command_bytes_leave_ring_and_first_work_pacing_untouched() {
    let (backend, mut master, _slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let requests = [
        ColdControl::GetAddress,
        ColdControl::ChainInactive,
        ColdControl::SetChipAddress(2),
        ColdControl::Broadcast {
            register: ColdRegister::VersionMask,
            value: 0xffff_0000,
        },
        ColdControl::Chip {
            address: 2,
            register: ColdRegister::CoreControl,
            value: 0x8000_8004,
        },
    ];
    let expected = [
        wire(&build_get_address_frame()),
        wire(&build_chain_inactive_frame()),
        wire(&build_set_chip_address_frame(2)),
        wire(&build_broadcast_write_frame(
            regs::VERSION_MASK,
            0xffff_0000,
        )),
        wire(&build_single_write_frame(
            2,
            regs::CORE_REG_CTRL,
            0x8000_8004,
        )),
    ];
    let mut held = owner.hold_dispatch().unwrap();
    for (request, expected) in requests.iter().zip(expected) {
        let result = held.cold_control_until(0, request, due());
        good(&result);
        let mut actual = vec![0; expected.len()];
        master.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(held.snapshot().held && !held.snapshot().control_caller_pending);
    }
    held.resume().unwrap();
    assert_eq!(owner.in_flight_ring(0), Some([None; SEND_WORK_RING_SLOTS]));
    let frame = vec![0x42; 88];
    let sent = owner.try_send_raw_until(0, &frame, 24, 0, due());
    assert_eq!(sent.dispatch, Ok(true));
    assert_eq!(owner.in_flight_ring(0).unwrap()[0], Some(24));
    let mut actual = [0; 88];
    master.read_exact(&mut actual).unwrap();
    assert_eq!(actual.as_slice(), frame);
}

#[test]
fn miscctrl_uses_three_actual_writes_and_all_original_five_ms_delays() {
    for request in [
        ColdControl::MiscBroadcast(0xff0f_c100),
        ColdControl::MiscChip {
            address: 4,
            value: 0x00c1_00b0,
        },
    ] {
        let (backend, mut master, _slave) = pty();
        let owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
        let mut held = owner.into_hold().unwrap_or_else(|_| panic!("hold"));
        let result = held.cold_control_until(0, &request, due());
        good(&result);
        assert_eq!((result.writes.len(), result.delays.len()), (3, 3));
        for (index, delay) in result.delays.iter().enumerate() {
            assert_eq!(delay.milliseconds, 5);
            assert!(
                delay.completed_at.unwrap().duration_since(delay.started_at)
                    >= Duration::from_millis(5)
            );
            if index < 2 {
                assert!(result.writes[index + 1].started_at >= delay.completed_at.unwrap());
            }
        }
        let mut actual = [0; 33];
        master.read_exact(&mut actual).unwrap();
        let expected = match request {
            ColdControl::MiscBroadcast(value) => {
                wire(&build_broadcast_write_frame(regs::MISC_CONTROL, value))
            }
            ColdControl::MiscChip { address, value } => wire(&build_single_write_frame(
                address,
                regs::MISC_CONTROL,
                value,
            )),
            _ => unreachable!(),
        };
        assert_eq!(actual.as_slice(), expected.repeat(3));
        let owner = held.resume().unwrap_or_else(|_| panic!("resume"));
        assert_eq!(owner.in_flight_ring(0), Some([None; 16]));
    }
}

#[test]
fn actual_fragmented_nine_byte_baseline_replies_are_counted_without_mining_parser_or_population() {
    let (backend, mut master, _slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let reply = reset_wire().repeat(2);
    let expected = reply.clone();
    let peer = std::thread::spawn(move || {
        let mut query = [0; 7];
        master.read_exact(&mut query).unwrap();
        assert_eq!(query.as_slice(), wire(&build_get_address_frame()));
        std::thread::sleep(Duration::from_millis(55));
        master.write_all(&reply[..4]).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        master.write_all(&reply[4..]).unwrap();
        master
    });
    let mut held = owner.hold_dispatch().unwrap();
    let result = held.cold_control_until(0, &ColdControl::ResetBaseline, due());
    good(&result);
    let baseline = result.baseline.unwrap();
    assert_eq!(baseline.raw, expected);
    assert_eq!(baseline.observed_frames, Some(2));
    assert!(
        baseline
            .reads
            .iter()
            .filter(|read| read.returned_count.is_some_and(|count| count > 0))
            .count()
            >= 2
    );
    held.resume().unwrap();
    assert!(owner.inner.transport.rx_bm1362_serial[0].is_empty());
    assert_eq!(owner.inner.transport.rx_bm1362_serial_raw_bytes[0], 0);
    assert_eq!(owner.in_flight_ring(0), Some([None; 16]));
    let _master = peer.join().unwrap();
}

#[test]
fn invalid_crc_partial_and_assigned_reply_shapes_preserve_raw_bytes_and_refuse() {
    let mut bad = reset_wire();
    bad[8] ^= 1;
    for reply in [
        bad,
        reset_wire()[..8].to_vec(),
        vec![0xaa, 0x55, 0x13, 0x62, 3, 2, 2, 0, 0, 0, 0],
    ] {
        let (backend, mut master, _slave) = pty();
        let owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
        let expected = reply.clone();
        let peer = std::thread::spawn(move || {
            let mut query = [0; 7];
            master.read_exact(&mut query).unwrap();
            master.write_all(&reply).unwrap();
            master
        });
        let mut held = owner.into_hold().unwrap_or_else(|_| panic!("hold"));
        let result = held.cold_control_until(0, &ColdControl::ResetBaseline, due());
        assert!(result.failure.is_some() && result.caller_completed_at.is_none());
        let baseline = result.baseline.unwrap();
        assert_eq!(baseline.raw, expected);
        assert!(baseline.observed_frames.is_none());
        assert!(held.snapshot().permanently_stopped && !held.snapshot().control_caller_pending);
        let _master = peer.join().unwrap();
    }
}

#[test]
fn cold_reconfiguration_after_any_mining_work_refuses_without_resetting_original_ring() {
    let (backend, mut master, _slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    assert_eq!(
        owner.try_send_raw_until(0, &[7; 88], 40, 0, due()).dispatch,
        Ok(true)
    );
    let mut work = [0; 88];
    master.read_exact(&mut work).unwrap();
    let ring = owner.in_flight_ring(0);
    let mut held = owner.hold_dispatch().unwrap();
    let result = held.cold_control_until(0, &ColdControl::ChainInactive, due());
    assert!(result.failure.unwrap().contains("mining work"));
    assert!(result.writes.is_empty());
    drop(held);
    assert_eq!(owner.in_flight_ring(0), ring);
    assert!(!input_ready(&master, 0));
}

#[test]
fn partial_mining_parser_bytes_cannot_be_consumed_or_cleared_by_cold_control() {
    let (backend, mut master, slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    master.write_all(&[0xaa, 0x55, 1, 2, 3]).unwrap();
    assert!(input_ready(&slave, 500));
    assert!(owner.receive_until(due()).parsed.caller_completed);
    let retained = owner.inner.transport.rx_bm1362_serial[0].clone();
    assert_eq!(retained.len(), 5);
    let mut held = owner.hold_dispatch().unwrap();
    let result = held.cold_control_until(0, &ColdControl::ResetBaseline, due());
    assert!(result.failure.unwrap().contains("parser bytes"));
    assert!(result.writes.is_empty() && result.baseline.is_none());
    drop(held);
    assert_eq!(owner.inner.transport.rx_bm1362_serial[0], retained);
    assert!(!input_ready(&master, 0));
}

#[test]
fn missing_hold_expired_deadline_and_foreign_chain_start_no_raw_control_io() {
    let (backend, master, _slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let result = control_held(&mut owner, 0, &ColdControl::GetAddress, due());
    assert!(result.failure.is_some() && result.writes.is_empty());
    for expired in [false, true] {
        let (backend, master, _slave) = pty();
        let owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
        let mut held = owner.into_hold().unwrap_or_else(|_| panic!("hold"));
        let result = held.cold_control_until(
            if expired { 0 } else { 1 },
            &ColdControl::GetAddress,
            if expired { Instant::now() } else { due() },
        );
        assert!(result.failure.is_some() && result.writes.is_empty());
        assert!(!input_ready(&master, 0));
        assert!(held.snapshot().permanently_stopped && !held.snapshot().control_caller_pending);
    }
    assert!(!input_ready(&master, 0));
}

#[test]
fn actual_full_pty_backpressure_retains_the_single_failed_command_attempt() {
    let (mut backend, mut master, _slave) = pty();
    let fill = backend.write_raw_until(
        &vec![0x5a; 1024 * 1024],
        Instant::now() + Duration::from_millis(30),
        &|| false,
    );
    assert!(fill.accepted_bytes > 0 && fill.accepted_bytes < fill.requested_bytes);
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let mut held = owner.hold_dispatch().unwrap();
    let result = held.cold_control_until(
        0,
        &ColdControl::GetAddress,
        Instant::now() + Duration::from_millis(30),
    );
    assert!(result.failure.is_some() && result.caller_completed_at.is_none());
    assert_eq!(result.writes.len(), 1);
    let raw = &result.writes[0].attempt;
    assert!(raw.status.flags_restored);
    assert!(held.snapshot().permanently_stopped);
    let mut arrived = vec![0; fill.accepted_bytes + raw.accepted_bytes];
    master.read_exact(&mut arrived).unwrap();
    assert_eq!(&arrived[..fill.accepted_bytes], fill.accepted_prefix);
    assert_eq!(&arrived[fill.accepted_bytes..], raw.accepted_prefix);
    drop(held);
    assert_eq!(owner.in_flight_ring(0), Some([None; 16]));
}

#[test]
fn baseline_overflow_keeps_the_actual_extra_byte_and_never_accepts_truncated_maximum() {
    let (backend, mut master, _slave) = pty();
    let owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let reply = reset_wire().repeat(256);
    let expected = reply.clone();
    let peer = std::thread::spawn(move || {
        let mut query = [0; 7];
        master.read_exact(&mut query).unwrap();
        master.write_all(&reply).unwrap();
        master
    });
    let mut held = owner.into_hold().unwrap_or_else(|_| panic!("hold"));
    let result = held.cold_control_until(0, &ColdControl::ResetBaseline, due());
    assert!(result.failure.unwrap().contains("bound exceeded"));
    let baseline = result.baseline.unwrap();
    assert_eq!(baseline.raw, expected[..255 * 9 + 1]);
    assert!(baseline.observed_frames.is_none());
    let _master = peer.join().unwrap();
}

#[tokio::test]
async fn retained_async_control_joins_actual_caller_before_promoting_its_raw_report() {
    let (backend, mut master, _slave) = pty();
    let mut runtime = BbUartRuntime::new(BbSerialDispatchOwner::new(vec![backend], 20_000));
    runtime
        .execute(runtime_owner::UartRequest::Hold, due())
        .await
        .unwrap();
    let value = runtime
        .execute(
            runtime_owner::UartRequest::ColdControl {
                chain: 0,
                control: ColdControl::MiscBroadcast(0x00c1_00b0),
            },
            due(),
        )
        .await
        .unwrap();
    let record = value.latest.unwrap();
    assert!(record.joined_at.is_some() && record.promoted_at.is_some());
    let runtime_owner::UartOutput::Controlled(actual) = record.output.unwrap() else {
        panic!("missing original control report")
    };
    good(&actual);
    assert_eq!(actual.writes.len(), 3);
    let mut wire = [0; 33];
    master.read_exact(&mut wire).unwrap();
    assert!(runtime.close_until(due()).await);
}

#[tokio::test]
async fn cancelled_async_baseline_retains_its_caller_and_previous_joined_history_for_cleanup() {
    let (backend, mut master, _slave) = pty();
    let mut runtime = BbUartRuntime::new(BbSerialDispatchOwner::new(vec![backend], 20_000));
    runtime
        .execute(runtime_owner::UartRequest::Hold, due())
        .await
        .unwrap();
    let mut peer = tokio::task::spawn_blocking(move || {
        let mut query = [0; 7];
        master.read_exact(&mut query).unwrap();
        (master, query)
    });
    let mut pending = Box::pin(runtime.execute(
        runtime_owner::UartRequest::ColdControl {
            chain: 0,
            control: ColdControl::ResetBaseline,
        },
        due(),
    ));
    let (_master, query) = tokio::select! {_=&mut pending=>panic!("baseline window already returned"),value=&mut peer=>value.unwrap()};
    assert_eq!(query.as_slice(), wire(&build_get_address_frame()));
    drop(pending);
    assert!(runtime.snapshot().caller_pending && runtime.snapshot().dispatch.permanently_stopped);
    assert!(runtime.close_until(due()).await);
    let state = runtime.snapshot();
    assert_eq!(state.last_complete.unwrap().sequence, 1);
    let latest = state.latest.unwrap();
    assert!(latest.joined_at.is_some() && latest.promoted_at.is_none());
    let runtime_owner::UartOutput::Controlled(actual) = latest.output.unwrap() else {
        panic!("retained cancelled command report")
    };
    assert_eq!(actual.writes.len(), 1);
    assert!(actual.failure.is_some() && actual.caller_completed_at.is_none());
}

#[test]
fn held_baud_transition_keeps_actual_unsupported_driver_report_and_pending_bytes() {
    let (backend, mut master, slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    master.write_all(&[0xaa, 0x55, 3, 4, 5]).unwrap();
    assert!(input_ready(&slave, 500));
    let mut held = owner.hold_dispatch().unwrap();
    let result = held.cold_control_until(0, &ColdControl::HostBaud(NativeBbBaud::Mining), due());
    assert!(result.failure.is_some() && result.writes.is_empty() && result.baseline.is_none());
    let actual = result.host_baud.unwrap();
    assert_eq!(actual.cached_before, Some(115200));
    assert!(actual.drain.unwrap().failure.is_some());
    assert!(actual.set_started_at.is_none() && actual.readback.is_none());
    drop(held);
    assert!(owner.snapshot().permanently_stopped && !owner.snapshot().control_caller_pending);
    assert_eq!(owner.in_flight_ring(0), Some([None; 16]));
    let backend = &mut owner.inner.transport.chains[0].backend;
    assert_eq!(backend.baud(), 115200);
    let mut bytes = [0; 5];
    let read = backend.read_raw_once_bounded(&mut bytes, due(), &|| false);
    assert_eq!(read.bytes, [0xaa, 0x55, 3, 4, 5]);
    assert!(owner.inner.transport.rx_bm1362_serial[0].is_empty());
    assert!(!input_ready(&master, 0));
}
#[test]
fn any_previous_mining_work_refuses_host_baud_before_driver_or_termios_observation() {
    let (backend, mut master, _slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    assert_eq!(
        owner.try_send_raw_until(0, &[8; 88], 40, 0, due()).dispatch,
        Ok(true)
    );
    let mut work = [0; 88];
    master.read_exact(&mut work).unwrap();
    let ring = owner.in_flight_ring(0);
    let mut held = owner.hold_dispatch().unwrap();
    let result = held.cold_control_until(0, &ColdControl::HostBaud(NativeBbBaud::Mining), due());
    assert!(result.failure.unwrap().contains("mining work"));
    assert!(result.host_baud.is_none() && result.writes.is_empty());
    drop(held);
    assert_eq!(owner.in_flight_ring(0), ring);
    assert_eq!(owner.inner.transport.chains[0].backend.baud(), 115200);
}
#[tokio::test]
async fn actual_async_baud_refusal_joins_and_preserves_last_completed_cold_command() {
    let (backend, mut master, _slave) = pty();
    let mut runtime = BbUartRuntime::new(BbSerialDispatchOwner::new(vec![backend], 20_000));
    runtime
        .execute(runtime_owner::UartRequest::Hold, due())
        .await
        .unwrap();
    runtime
        .execute(
            runtime_owner::UartRequest::ColdControl {
                chain: 0,
                control: ColdControl::ChainInactive,
            },
            due(),
        )
        .await
        .unwrap();
    let mut wire = [0; 7];
    master.read_exact(&mut wire).unwrap();
    let state = runtime
        .execute(
            runtime_owner::UartRequest::ColdControl {
                chain: 0,
                control: ColdControl::HostBaud(NativeBbBaud::Mining),
            },
            due(),
        )
        .await
        .unwrap();
    assert_eq!(state.last_complete.unwrap().sequence, 2);
    assert!(state.dispatch.permanently_stopped);
    let latest = state.latest.unwrap();
    assert!(latest.joined_at.is_some() && latest.promoted_at.is_none());
    let runtime_owner::UartOutput::Controlled(actual) = latest.output.unwrap() else {
        panic!("retained actual baud attempt")
    };
    assert!(actual.host_baud.unwrap().set_started_at.is_none());
    assert!(runtime.close_until(due()).await);
}
