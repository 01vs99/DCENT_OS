use super::*;
use crate::bm1362::assigned_address::AssignedAddressResponseError;
use crate::protocol::bm13xx_command_response_crc5;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};

fn due() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn pty() -> (SerialChainBackend, File, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: initialized output descriptors for a fresh local PTY; all
    // optional pointers are null. These tests never open a physical UART.
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
    // SAFETY: each successful openpty descriptor is adopted exactly once.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: this distinct new slave descriptor has no other owning wrapper.
    let slave = unsafe { File::from_raw_fd(slave) };
    let backend = SerialChainBackend::open_native_linux_only(
        0,
        &format!("/proc/self/fd/{}", slave.as_raw_fd()),
        115200,
    )
    .unwrap();
    (backend, master, slave)
}
fn input_ready(file: &File, milliseconds: i32) -> bool {
    let mut item = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd for an owned host descriptor, bounded wait.
    (unsafe { libc::poll(&mut item, 1, milliseconds) }) == 1
}
fn queued(file: &File) -> usize {
    let mut bytes: libc::c_int = -1;
    // SAFETY: FIONREAD writes one c_int into valid initialized storage for the
    // retained host PTY. It observes queued bytes without consuming any.
    assert_eq!(
        unsafe { libc::ioctl(file.as_raw_fd(), libc::FIONREAD, &mut bytes) },
        0
    );
    usize::try_from(bytes).unwrap()
}
fn read_query(master: &mut File) {
    assert!(input_ready(master, 2_000));
    let mut query = [0; 7];
    master.read_exact(&mut query).unwrap();
    assert_eq!(query.as_slice(), wire(&build_get_address_frame()));
}
fn frame(address: u8) -> Vec<u8> {
    let mut bytes = vec![0xaa, 0x55, 0x13, 0x62, 3, address, address, 0, 0, 0, 0];
    bytes[10] = bm13xx_command_response_crc5(&bytes[2..10]);
    bytes
}
fn scan(expected_addresses: Vec<u8>) -> ColdControl {
    ColdControl::AssignedScan { expected_addresses }
}
fn good(attempt: &ColdControlAttempt) {
    assert!(attempt.failure.is_none(), "{attempt:?}");
    assert!(attempt.caller_completed_at.unwrap() < attempt.deadline);
    assert_eq!(attempt.writes.len(), 1);
    assert_eq!(
        attempt.writes[0].attempt.accepted_prefix,
        wire(&build_get_address_frame())
    );
    assert!(attempt.baseline.is_none() && attempt.host_baud.is_none());
}
fn actual_reply(reply: Vec<u8>, expected_addresses: Vec<u8>) -> ColdControlAttempt {
    let (backend, mut master, _slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let expected_raw = reply.clone();
    let peer = std::thread::spawn(move || {
        read_query(&mut master);
        master.write_all(&reply).unwrap();
        master
    });
    let mut held = owner.hold_dispatch().unwrap();
    let actual = held.cold_control_until(0, &scan(expected_addresses), due());
    let observed = actual.assigned_scan.as_ref().unwrap();
    assert_eq!(observed.raw, expected_raw);
    assert_eq!(
        observed.raw,
        observed
            .reads
            .iter()
            .flat_map(|r| r.bytes.iter().copied())
            .collect::<Vec<_>>()
    );
    assert!(observed.reads.len() <= MAX_READS);
    assert!(observed.window_completed_at.is_some());
    assert!(observed.collection_returned_at.is_some());
    if actual.failure.is_some() {
        assert!(held.snapshot().permanently_stopped);
        assert!(actual.caller_completed_at.is_none());
    }
    let _master = peer.join().unwrap();
    actual
}

#[test]
fn actual_full_126_fragmented_assigned_window_retains_exact_bytes_and_exclusive_owner() {
    // Pin one independently retained Xilinx response before making the full
    // authored PTY population. No simulated population is hardware evidence.
    assert_eq!(
        frame(0xca),
        [0xaa, 0x55, 0x13, 0x62, 3, 0xca, 0xca, 0, 0, 0, 8]
    );
    let expected = (0u8..126).map(|n| n * 2).collect::<Vec<_>>();
    let reply = expected
        .iter()
        .rev()
        .flat_map(|&a| frame(a))
        .collect::<Vec<_>>();
    let expected_raw = reply.clone();
    let (backend, mut master, _slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let peer = std::thread::spawn(move || {
        read_query(&mut master);
        std::thread::sleep(Duration::from_millis(55));
        for fragment in reply.chunks(37) {
            master.write_all(fragment).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
        master
    });
    let mut held = owner.hold_dispatch().unwrap();
    let actual = held.cold_control_until(0, &scan(expected.clone()), due());
    good(&actual);
    let observed = actual.assigned_scan.unwrap();
    assert_eq!(observed.expected_addresses, expected);
    assert_eq!(observed.raw, expected_raw);
    assert_eq!(
        observed.report.as_ref().unwrap().coverage,
        AssignedAddressCoverage::ExactExpectedSet
    );
    assert_eq!(observed.report.unwrap().valid_responses, 126);
    assert!(
        observed
            .reads
            .iter()
            .filter(|r| !r.bytes.is_empty())
            .count()
            > 1
    );
    assert!(observed.reads.iter().all(|r| r.status.flags_restored));
    let settle = &actual.delays[0];
    assert_eq!(settle.milliseconds, SETTLE_MS);
    assert!(settle.completed_at.unwrap() - settle.started_at >= Duration::from_millis(50));
    assert!(observed.window_started_at.unwrap() >= settle.completed_at.unwrap());
    assert_eq!(
        observed.window_deadline.unwrap() - observed.window_started_at.unwrap(),
        Duration::from_millis(300)
    );
    assert!(observed.window_completed_at.unwrap() >= observed.window_deadline.unwrap());
    held.resume().unwrap();
    assert_eq!(owner.in_flight_ring(0), Some([None; SEND_WORK_RING_SLOTS]));
    assert!(owner.inner.transport.rx_bm1362_serial[0].is_empty());
    assert_eq!(owner.inner.transport.rx_bm1362_serial_raw_bytes[0], 0);
    let master = peer.join().unwrap();
    assert!(!input_ready(&master, 0));
}

#[test]
fn actual_malformed_assigned_frames_and_partial_tail_are_never_resynchronized_or_dropped() {
    let mut cases = Vec::new();
    let mut crc = frame(2);
    crc[10] ^= 1;
    cases.push(crc);
    for (index, value) in [(0, 0), (2, 0x12), (4, 4), (5, 4), (7, 4), (8, 1)] {
        let mut bytes = frame(2);
        bytes[index] = value;
        bytes[10] = bm13xx_command_response_crc5(&bytes[2..10]);
        cases.push(bytes);
    }
    for flags in [0x80, 0x20, 0x40] {
        let mut bytes = frame(2);
        bytes[10] |= flags;
        cases.push(bytes);
    }
    cases.push(vec![0xaa, 0x55, 0x13, 0x62, 3, 0, 0, 0, 0x0d]);
    cases.push(frame(2)[..7].to_vec());
    cases.push([vec![0xff], frame(2)].concat());
    for bad in cases {
        let actual = actual_reply([frame(0), bad].concat(), vec![0, 2]);
        assert!(actual.failure.is_some());
        let report = actual.assigned_scan.unwrap().report.unwrap();
        assert_eq!(report.coverage, AssignedAddressCoverage::Partial);
        assert_eq!(report.valid_responses, 1);
        assert_eq!(report.missing_addresses, [2]);
        assert!(!report.rejected.is_empty());
        assert_eq!(report.rejected[0].response_index, 1);
    }
}

#[test]
fn actual_duplicate_unexpected_missing_and_empty_windows_remain_distinct_reports() {
    for (reply, coverage, missing, duplicate, unexpected) in [
        (
            Vec::new(),
            AssignedAddressCoverage::Empty,
            vec![0, 2],
            vec![],
            vec![],
        ),
        (
            frame(0),
            AssignedAddressCoverage::Partial,
            vec![2],
            vec![],
            vec![],
        ),
        (
            [frame(0), frame(2), frame(2)].concat(),
            AssignedAddressCoverage::Partial,
            vec![],
            vec![2],
            vec![],
        ),
        (
            [frame(0), frame(2), frame(4)].concat(),
            AssignedAddressCoverage::Partial,
            vec![],
            vec![],
            vec![4],
        ),
    ] {
        let actual = actual_reply(reply, vec![0, 2]);
        assert!(actual.failure.is_some());
        let report = actual.assigned_scan.unwrap().report.unwrap();
        assert_eq!(report.coverage, coverage);
        assert_eq!(report.missing_addresses, missing);
        assert_eq!(report.duplicate_addresses, duplicate);
        assert_eq!(report.unexpected_addresses, unexpected);
        assert!(report.rejected.is_empty());
    }
}

#[test]
fn invalid_expected_sets_refuse_before_any_query_and_preserve_queued_uart_bytes() {
    for expected in [vec![], vec![0, 2, 0], (0u8..=255).collect()] {
        let (backend, mut master, slave) = pty();
        let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
        let queued_response = frame(2);
        master.write_all(&queued_response).unwrap();
        assert!(input_ready(&slave, 500));
        let mut held = owner.hold_dispatch().unwrap();
        let actual = held.cold_control_until(0, &scan(expected), due());
        assert!(actual
            .failure
            .as_ref()
            .unwrap()
            .contains("expected addresses"));
        assert!(actual.writes.is_empty() && actual.delays.is_empty());
        assert!(actual.assigned_scan.is_none() && actual.caller_completed_at.is_none());
        assert!(held.snapshot().permanently_stopped);
        drop(held);
        let mut bytes = [0; 11];
        let actual = owner.inner.transport.chains[0]
            .backend
            .read_raw_once_bounded(&mut bytes, due(), &|| false);
        assert_eq!(actual.bytes, queued_response);
        assert!(!input_ready(&master, 0));
    }
}

#[test]
fn actual_255_limit_accepts_once_each_and_overflow_retains_extra_byte_and_unread_suffix() {
    let expected = (0u8..255).collect::<Vec<_>>();
    let maximum = expected.iter().flat_map(|&a| frame(a)).collect::<Vec<_>>();
    good(&actual_reply(maximum.clone(), expected.clone()));
    let (backend, mut master, _slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let reply = [maximum, frame(255)].concat();
    let expected_raw = reply.clone();
    let peer = std::thread::spawn(move || {
        read_query(&mut master);
        master.write_all(&reply).unwrap();
        master
    });
    let mut held = owner.hold_dispatch().unwrap();
    let actual = held.cold_control_until(0, &scan(expected), due());
    assert!(actual.failure.as_ref().unwrap().contains("bound exceeded"));
    assert!(actual.caller_completed_at.is_none());
    let observed = actual.assigned_scan.unwrap();
    assert_eq!(observed.raw, expected_raw[..MAX_RAW + 1]);
    assert!(observed.window_completed_at.is_none());
    let report = observed.report.unwrap();
    assert_eq!(report.valid_responses, 255);
    assert_eq!(report.coverage, AssignedAddressCoverage::Partial);
    assert_eq!(
        report.rejected[0].reason,
        AssignedAddressResponseError::Length { observed: 1 }
    );
    assert!(held.snapshot().permanently_stopped);
    drop(held);
    let mut bytes = [0; 11];
    let remaining = owner.inner.transport.chains[0]
        .backend
        .read_raw_once_bounded(&mut bytes, due(), &|| false);
    assert_eq!(remaining.bytes, expected_raw[MAX_RAW + 1..]);
    let _master = peer.join().unwrap();
}

#[tokio::test]
async fn cancelled_actual_scan_retains_consumed_exact_bytes_without_completion_and_previous_history(
) {
    let (backend, mut master, mut slave) = pty();
    let mut runtime = BbUartRuntime::new(BbSerialDispatchOwner::new(vec![backend], 20_000));
    runtime
        .execute(runtime_owner::UartRequest::Hold, due())
        .await
        .unwrap();
    let prior = runtime
        .execute(
            runtime_owner::UartRequest::ColdControl {
                chain: 0,
                control: ColdControl::ChainInactive,
            },
            due(),
        )
        .await
        .unwrap()
        .last_complete
        .unwrap();
    assert_eq!(prior.sequence, 2);
    let expected_prior = wire(&build_chain_inactive_frame());
    let mut prior_bytes = vec![0; expected_prior.len()];
    assert!(input_ready(&master, 500));
    master.read_exact(&mut prior_bytes).unwrap();
    assert_eq!(prior_bytes, expected_prior);

    // Bytes deliberately precede this query. Actual queue consumption proves
    // collection occurred, while explicitly offering no freshness/causality.
    let response = [frame(0), frame(2)].concat();
    master.write_all(&response).unwrap();
    assert!(input_ready(&slave, 500));
    let observer = slave.try_clone().unwrap();
    let mut peer = tokio::task::spawn_blocking(move || {
        read_query(&mut master);
        let end = due();
        while queued(&observer) != 0 {
            assert!(
                Instant::now() < end,
                "collector did not consume queued response"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        master
    });
    let mut pending = Box::pin(runtime.execute(
        runtime_owner::UartRequest::ColdControl {
            chain: 0,
            control: scan(vec![0, 2]),
        },
        due(),
    ));
    let mut master = tokio::select! {
        _ = &mut pending => panic!("scan completed before the observed queue drain"),
        peer = &mut peer => peer.unwrap(),
    };
    drop(pending);
    assert!(runtime.snapshot().dispatch.permanently_stopped);
    assert!(runtime.close_until(due()).await);
    let state = runtime.snapshot();
    let previous = state.last_complete.unwrap();
    assert_eq!(previous.sequence, prior.sequence);
    assert_eq!(previous.joined_at, prior.joined_at);
    let latest = state.latest.unwrap();
    assert!(latest.joined_at.is_some() && latest.promoted_at.is_none());
    let runtime_owner::UartOutput::Controlled(actual) = latest.output.unwrap() else {
        panic!("missing actual cancelled scan")
    };
    assert!(actual.failure.is_some() && actual.caller_completed_at.is_none());
    let observed = actual.assigned_scan.unwrap();
    assert_eq!(observed.raw, response);
    assert!(observed.window_started_at.is_some() && observed.window_completed_at.is_none());
    assert_eq!(
        observed.report.unwrap().coverage,
        AssignedAddressCoverage::ExactExpectedSet
    );
    assert_eq!(
        observed.raw,
        observed
            .reads
            .iter()
            .flat_map(|r| r.bytes.iter().copied())
            .collect::<Vec<_>>()
    );
    // Original unrelated PTY descriptors remain usable; cleanup has not flushed
    // the input or manufactured a returned/read record for these later bytes.
    master.write_all(&[0x71, 0x72, 0x73]).unwrap();
    assert!(input_ready(&slave, 500));
    let mut later = [0; 3];
    slave.read_exact(&mut later).unwrap();
    assert_eq!(later, [0x71, 0x72, 0x73]);
}

#[test]
fn original_deadline_during_actual_window_keeps_partial_assessment_and_completed_settle() {
    let (backend, mut master, slave) = pty();
    let mut owner = BbSerialDispatchOwner::new(vec![backend], 20_000);
    let response = frame(0);
    master.write_all(&response).unwrap();
    assert!(input_ready(&slave, 500));
    let mut held = owner.hold_dispatch().unwrap();
    let deadline = Instant::now() + Duration::from_millis(180);
    let actual = held.cold_control_until(0, &scan(vec![0, 2]), deadline);
    assert!(actual.failure.is_some() && actual.caller_completed_at.is_none());
    assert_eq!(actual.deadline, deadline);
    assert!(actual.delays[0].completed_at.is_some());
    let observed = actual.assigned_scan.unwrap();
    assert_eq!(observed.raw, response);
    assert!(observed.window_started_at.is_some() && observed.window_completed_at.is_none());
    assert!(observed.window_deadline.unwrap() > deadline);
    let report = observed.report.unwrap();
    assert_eq!(report.coverage, AssignedAddressCoverage::Partial);
    assert_eq!(report.missing_addresses, [2]);
    assert!(held.snapshot().permanently_stopped);
    read_query(&mut master);
}
