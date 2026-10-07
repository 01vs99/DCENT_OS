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

#[test]
fn actual_pty_refuses_unsupported_hardware_status_and_preserves_both_streams_and_flags() {
    let (mut serial, mut master, _slave) = pty();
    let original_flags = flags(&serial);
    master.write_all(&[9, 8, 7, 6]).unwrap();
    serial.write_raw_bytes(&[1, 2, 3, 4]).unwrap();
    let result = serial
        .observe_transmitter_until(Instant::now() + Duration::from_secs(1), &|| false)
        .unwrap();
    assert!(result.failure.is_some(), "{result:?}");
    assert!(result.caller_completed_at.is_none());
    assert_eq!(result.polls, 1);
    assert_eq!(result.last.pending_output, Some(0));
    assert!(result.last.line_status.is_none());
    assert_eq!(flags(&serial), original_flags);
    let mut tx = [0; 4];
    master.read_exact(&mut tx).unwrap();
    assert_eq!(tx, [1, 2, 3, 4]);
    let mut rx = [0; 4];
    assert_eq!(serial.read_raw_bytes_timeout(&mut rx, 100).unwrap(), 4);
    assert_eq!(rx, [9, 8, 7, 6]);
}

#[test]
fn actual_owner_preexpired_or_precancelled_attempt_keeps_unavailable_fields_unavailable() {
    let (mut serial, _master, _slave) = pty();
    let original_flags = flags(&serial);
    for cancel in [false, true] {
        let deadline = if cancel {
            Instant::now() + Duration::from_secs(1)
        } else {
            Instant::now()
        };
        let result = serial
            .observe_transmitter_until(deadline, &|| cancel)
            .unwrap();
        assert_eq!(result.polls, 0);
        assert!(
            result.last.observed_at.is_none()
                && result.last.pending_output.is_none()
                && result.last.line_status.is_none()
        );
        assert!(result.failure.is_some() && result.caller_completed_at.is_none());
        assert_eq!(flags(&serial), original_flags);
    }
}
