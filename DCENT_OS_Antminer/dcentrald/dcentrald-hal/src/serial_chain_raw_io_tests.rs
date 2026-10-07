use super::*;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::Duration;

fn pty() -> (SerialChainBackend, std::fs::File, std::fs::File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: two valid output pointers receive fresh local PTY descriptors;
    // optional name/termios/window outputs are absent. No physical UART opens.
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
    // SAFETY: each fresh descriptor is consumed exactly once by its File owner.
    let master = unsafe { std::fs::File::from_raw_fd(master) };
    // SAFETY: the independently returned slave descriptor has not been adopted.
    let slave = unsafe { std::fs::File::from_raw_fd(slave) };
    let path = format!("/proc/self/fd/{}", slave.as_raw_fd());
    let serial = SerialChainBackend::open_native_linux_only(0, &path, 115200).unwrap();
    (serial, master, slave)
}

fn flags(serial: &SerialChainBackend) -> i32 {
    let backend = serial.serial.lock().unwrap();
    let UartBackend::File(file) = &*backend else {
        panic!("PTY changed backend")
    };
    // SAFETY: the exact retained live descriptor, integer-only F_GETFL.
    unsafe { libc::fcntl(file.raw_fd(), libc::F_GETFL) }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(1)
}

fn await_input(serial: &SerialChainBackend) {
    let backend = serial.serial.lock().unwrap();
    let UartBackend::File(file) = &*backend else {
        panic!("PTY backend changed")
    };
    let mut item = libc::pollfd {
        fd: file.raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd for the live owner and a bounded wait.
    assert_eq!(unsafe { libc::poll(&mut item, 1, 500) }, 1);
    assert_ne!(item.revents & libc::POLLIN, 0);
}

#[test]
fn empty_pty_read_ignores_long_vtime_without_altering_termios_or_original_flags() {
    let (mut serial, _master, slave) = pty();
    let original_flags = flags(&serial);
    // SAFETY: initialized termios output, exact live local PTY descriptor.
    let mut configured: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut configured) },
        0
    );
    configured.c_cc[libc::VMIN] = 0;
    configured.c_cc[libc::VTIME] = 20;
    // SAFETY: exact local PTY and a fully initialized termios configuration.
    assert_eq!(
        unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &configured) },
        0
    );
    let start = Instant::now();
    let result =
        serial.read_raw_once_bounded(&mut [0; 256], start + Duration::from_millis(100), &|| false);
    assert!(start.elapsed() < Duration::from_millis(500));
    assert_eq!(result.returned_count, Some(0));
    assert!(result.bytes.is_empty());
    assert_eq!(result.status.io_calls, 1);
    assert!(result.status.caller_completed_at.is_some(), "{result:?}");
    assert!(result.status.flags_restored && result.status.failure.is_none());
    assert_eq!(flags(&serial), original_flags);
    // SAFETY: initialized output and the same local PTY retained above.
    let mut after: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut after) }, 0);
    assert_eq!(configured.c_cc, after.c_cc);
    assert_eq!(
        (
            configured.c_iflag,
            configured.c_oflag,
            configured.c_cflag,
            configured.c_lflag
        ),
        (after.c_iflag, after.c_oflag, after.c_cflag, after.c_lflag)
    );
}

#[test]
fn one_read_preserves_remaining_wire_bytes_and_existing_response_parser() {
    let (mut serial, mut master, _slave) = pty();
    let original_flags = flags(&serial);
    {
        let rx = serial.rx_buf.get_mut().unwrap();
        rx.buf[..3].copy_from_slice(&[9, 8, 7]);
        rx.len = 3;
        rx.retained.push_back(vec![6, 5, 4]);
    }
    master.write_all(&[1, 2, 3, 4, 5]).unwrap();
    await_input(&serial);
    for expected in [&[1, 2][..], &[3, 4][..], &[5][..]] {
        let result = serial.read_raw_once_bounded(&mut [0; 2], deadline(), &|| false);
        assert_eq!(result.bytes, expected);
        assert_eq!(result.returned_count, Some(expected.len()));
        assert_eq!(result.status.io_calls, 1);
        assert!(result.status.failure.is_none());
    }
    let rx = serial.rx_buf.get_mut().unwrap();
    assert_eq!(&rx.buf[..rx.len], &[9, 8, 7]);
    assert_eq!(rx.retained.front().unwrap(), &[6, 5, 4]);
    assert_eq!(serial.rx_wire_bytes.load(Ordering::Relaxed), 0);
    assert_eq!(flags(&serial), original_flags);
}

#[test]
fn preexpired_and_precancelled_reads_and_writes_leave_both_streams_untouched() {
    let (mut serial, mut master, _slave) = pty();
    let original_flags = flags(&serial);
    master.write_all(&[1, 2, 3]).unwrap();
    await_input(&serial);
    for cancelled in [false, true] {
        let due = if cancelled {
            deadline()
        } else {
            Instant::now()
        };
        let read = serial.read_raw_once_bounded(&mut [0; 3], due, &|| cancelled);
        let write = serial.write_raw_until(&[9, 8, 7], due, &|| cancelled);
        assert_eq!(read.status.io_calls, 0);
        assert_eq!(write.status.io_calls, 0);
        assert!(read.returned_count.is_none() && read.bytes.is_empty());
        assert_eq!(write.accepted_bytes, 0);
        assert!(read.status.failure.is_some() && write.status.failure.is_some());
        assert!(
            read.status.original_file_flags.is_none() && write.status.original_file_flags.is_none()
        );
        assert_eq!(flags(&serial), original_flags);
    }
    let result = serial.read_raw_once_bounded(&mut [0; 3], deadline(), &|| false);
    assert_eq!(result.bytes, [1, 2, 3]);
    let mut item = libc::pollfd {
        fd: master.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd on the retained local PTY, zero timeout.
    assert_eq!(unsafe { libc::poll(&mut item, 1, 0) }, 0);
}

#[test]
fn cancellation_after_actual_read_keeps_its_reported_prefix_and_restores_flags() {
    let (mut serial, mut master, _slave) = pty();
    let original_flags = flags(&serial);
    master.write_all(&[1, 2, 3, 4]).unwrap();
    await_input(&serial);
    let checks = std::cell::Cell::new(0);
    let cancel = || {
        checks.set(checks.get() + 1);
        checks.get() >= 3
    };
    let result = serial.read_raw_once_bounded(&mut [0; 4], deadline(), &cancel);
    assert_eq!(result.returned_count, Some(4));
    assert_eq!(result.bytes, [1, 2, 3, 4]);
    assert_eq!(result.status.io_calls, 1);
    assert!(result
        .status
        .failure
        .as_ref()
        .unwrap()
        .contains("cancelled"));
    assert!(result.status.caller_completed_at.is_none() && result.status.flags_restored);
    assert_eq!(flags(&serial), original_flags);
}

#[test]
fn unwind_with_nonblocking_scope_restores_flags_and_keeps_unread_input() {
    let (mut serial, mut master, _slave) = pty();
    let original_flags = flags(&serial);
    master.write_all(&[1, 2]).unwrap();
    await_input(&serial);
    let checks = std::cell::Cell::new(0);
    let panic_after_flags = || {
        checks.set(checks.get() + 1);
        assert_ne!(checks.get(), 2, "injected unwind after setting nonblocking");
        false
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        serial.read_raw_once_bounded(&mut [0; 2], deadline(), &panic_after_flags)
    }));
    assert!(result.is_err());
    assert_eq!(flags(&serial), original_flags);
    let read = serial.read_raw_once_bounded(&mut [0; 2], deadline(), &|| false);
    assert_eq!(read.bytes, [1, 2]);
}

#[test]
fn complete_raw_frame_write_preserves_wire_bytes_input_and_flags() {
    let (mut serial, mut master, _slave) = pty();
    let original_flags = flags(&serial);
    let frame: Vec<u8> = (0..88).map(|n| n as u8).collect();
    master.write_all(&[7, 6, 5]).unwrap();
    await_input(&serial);
    let result = serial.write_raw_until(&frame, deadline(), &|| false);
    assert_eq!(result.requested_bytes, 88);
    assert_eq!(result.accepted_bytes, 88);
    assert_eq!(result.accepted_prefix, frame);
    assert!(result.status.caller_completed_at.is_some() && result.status.failure.is_none());
    assert!(result.status.flags_restored);
    assert_eq!(flags(&serial), original_flags);
    let mut actual = [0; 88];
    master.read_exact(&mut actual).unwrap();
    assert_eq!(actual.as_slice(), frame);
    let read = serial.read_raw_once_bounded(&mut [0; 3], deadline(), &|| false);
    assert_eq!(read.bytes, [7, 6, 5]);
}

#[test]
fn full_pty_queue_returns_at_deadline_with_actual_partial_prefix_and_no_retry_claim() {
    let (mut serial, mut master, _slave) = pty();
    let original_flags = flags(&serial);
    let frame: Vec<u8> = (0..1024 * 1024).map(|n| (n % 251) as u8).collect();
    let start = Instant::now();
    let result = serial.write_raw_until(&frame, start + Duration::from_millis(40), &|| false);
    assert!(start.elapsed() < Duration::from_millis(500));
    assert!(result.accepted_bytes > 0 && result.accepted_bytes < frame.len());
    assert_eq!(result.accepted_prefix, frame[..result.accepted_bytes]);
    assert!(result.status.failure.as_ref().unwrap().contains("deadline"));
    assert!(result.status.caller_completed_at.is_none() && result.status.flags_restored);
    assert!(result.status.io_calls > 1);
    assert_eq!(flags(&serial), original_flags);
    let mut actual = vec![0; result.accepted_bytes];
    master.read_exact(&mut actual).unwrap();
    assert_eq!(actual, result.accepted_prefix);
}

#[test]
fn cancellation_after_complete_backend_write_keeps_actual_accepted_frame() {
    let (mut serial, mut master, _slave) = pty();
    let original_flags = flags(&serial);
    let checks = std::cell::Cell::new(0);
    let cancel = || {
        checks.set(checks.get() + 1);
        checks.get() >= 4
    };
    let result = serial.write_raw_until(&[1, 2, 3, 4], deadline(), &cancel);
    assert_eq!(result.accepted_bytes, 4);
    assert_eq!(result.accepted_prefix, [1, 2, 3, 4]);
    assert_eq!(result.status.io_calls, 1);
    assert!(result
        .status
        .failure
        .as_ref()
        .unwrap()
        .contains("cancelled"));
    assert!(result.status.caller_completed_at.is_none() && result.status.flags_restored);
    assert_eq!(flags(&serial), original_flags);
    let mut actual = [0; 4];
    master.read_exact(&mut actual).unwrap();
    assert_eq!(actual, [1, 2, 3, 4]);
}

#[test]
fn poisoned_owner_is_refused_without_claiming_io_or_replacing_the_backend() {
    let (mut serial, _master, _slave) = pty();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = serial.serial.lock().unwrap();
        panic!("injected poison");
    }));
    assert!(result.is_err());
    let read = serial.read_raw_once_bounded(&mut [0; 4], deadline(), &|| false);
    let write = serial.write_raw_until(&[1, 2], deadline(), &|| false);
    assert!(read.status.failure.as_ref().unwrap().contains("poisoned"));
    assert!(write.status.failure.as_ref().unwrap().contains("poisoned"));
    assert_eq!(read.status.io_calls, 0);
    assert_eq!(write.status.io_calls, 0);
    assert!(read.returned_count.is_none());
    assert_eq!(write.accepted_bytes, 0);
    assert!(serial.serial.get_mut().is_err());
}

#[test]
fn actual_pty_hangup_write_error_does_not_become_successful_empty_write() {
    let (mut serial, master, _slave) = pty();
    let original_flags = flags(&serial);
    drop(master);
    let result = serial.write_raw_until(&[1, 2, 3], deadline(), &|| false);
    assert_eq!(result.status.io_calls, 1);
    assert_eq!(result.accepted_bytes, 0);
    assert!(result.accepted_prefix.is_empty());
    assert!(result.status.failure.is_some() && result.status.caller_completed_at.is_none());
    assert!(result.status.flags_restored);
    assert_eq!(flags(&serial), original_flags);
}
