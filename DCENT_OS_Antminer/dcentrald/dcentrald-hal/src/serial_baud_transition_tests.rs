use super::*;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::Duration;
fn due() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn pty() -> (SerialChain, File, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: initialized outputs for fresh local PTY descriptors; all optional
    // inputs absent. Only local pseudo terminals are opened by these tests.
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
    // SAFETY: distinct fresh descriptors adopted exactly once each.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: this separately returned fresh slave has no other File owner.
    let slave = unsafe { File::from_raw_fd(slave) };
    let serial =
        SerialChain::open(&format!("/proc/self/fd/{}", slave.as_raw_fd()), BAUD_115200).unwrap();
    (serial, master, slave)
}
fn current(slave: &File) -> Termios2 {
    // SAFETY: initialized POD output for an actual kernel TCGETS2 on this owned
    // local PTY; no fake observed state or physical device is involved.
    let mut value: Termios2 = unsafe { std::mem::zeroed() };
    // SAFETY: valid original slave descriptor and initialized ABI output.
    assert_eq!(
        unsafe {
            libc::ioctl(
                slave.as_raw_fd(),
                ioctl_request(TCGETS2),
                &mut value as *mut Termios2,
            )
        },
        0
    );
    value
}
fn flags(serial: &SerialChain) -> i32 {
    // SAFETY: integer-only F_GETFL on this retained live descriptor.
    unsafe { libc::fcntl(serial.raw_fd(), libc::F_GETFL) }
}
#[test]
fn actual_private_kernel_setter_changes_both_rates_without_flushing_or_changing_other_settings() {
    let (mut serial, mut master, slave) = pty();
    let original_flags = flags(&serial);
    for baud in [NativeBbBaud::Mining, NativeBbBaud::Enumeration] {
        let before = BaudSettings::from(current(&slave));
        master.write_all(&[9, 8, 7, 6]).unwrap();
        serial.write_bytes(&[1, 2, 3, 4]).unwrap();
        let mut result = BaudTransitionAttempt::new(baud, due());
        result.cached_before = Some(serial.baud);
        apply(&mut serial, &mut result, &|| false).unwrap();
        assert!(result.drain.is_none() && result.caller_completed_at.is_none());
        assert_eq!(result.set_result, Some(0));
        assert!(result.set_returned_at.is_some());
        let actual = BaudSettings::from(current(&slave));
        assert_eq!(Some(actual.clone()), result.readback);
        assert_eq!(
            (actual.input_speed, actual.output_speed, serial.baud),
            (baud.rate(), baud.rate(), baud.rate())
        );
        let mut preserved = actual.clone();
        preserved.control_flags = before.control_flags;
        preserved.input_speed = before.input_speed;
        preserved.output_speed = before.output_speed;
        assert_eq!(preserved, before);
        assert_eq!(
            actual.control_flags & !(libc::CBAUD | libc::CIBAUD),
            before.control_flags & !(libc::CBAUD | libc::CIBAUD)
        );
        assert_eq!(flags(&serial), original_flags);
        let mut sent = [0; 4];
        master.read_exact(&mut sent).unwrap();
        assert_eq!(sent, [1, 2, 3, 4]);
        let mut received = [0; 4];
        assert_eq!(serial.read_bytes(&mut received).unwrap(), 4);
        assert_eq!(received, [9, 8, 7, 6]);
    }
}
#[test]
fn expired_and_cancelled_admission_never_observes_or_changes_kernel_settings() {
    let (mut serial, _master, slave) = pty();
    let original = BaudSettings::from(current(&slave));
    for cancelled in [false, true] {
        let deadline = if cancelled { due() } else { Instant::now() };
        let full =
            serial.transition_native_bb_baud_until(NativeBbBaud::Mining, deadline, &|| cancelled);
        assert!(
            full.failure.is_some()
                && full.drain.is_none()
                && full.before.is_none()
                && full.set_started_at.is_none()
        );
        let mut kernel = BaudTransitionAttempt::new(NativeBbBaud::Mining, deadline);
        assert!(apply(&mut serial, &mut kernel, &|| cancelled).is_err());
        assert!(kernel.before.is_none() && kernel.set_started_at.is_none());
        assert_eq!(BaudSettings::from(current(&slave)), original);
    }
}
#[test]
fn cancellation_or_deadline_after_actual_set_preserves_mutation_without_fabricated_readback_or_rollback(
) {
    for expire in [false, true] {
        let (mut serial, _master, slave) = pty();
        let deadline = Instant::now() + Duration::from_millis(50);
        let mut result = BaudTransitionAttempt::new(NativeBbBaud::Mining, deadline);
        let error = apply(&mut serial, &mut result, &|| {
            // Decide from the actual kernel result, not a counted mock call.
            if current(&slave).c_ospeed == BAUD_3000000 {
                if expire {
                    std::thread::sleep(Duration::from_millis(60));
                    false
                } else {
                    true
                }
            } else {
                false
            }
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains(if expire { "deadline" } else { "cancelled" }));
        assert_eq!(result.set_result, Some(0));
        assert!(result.set_returned_at.is_some());
        assert!(result.readback.is_none() && result.caller_completed_at.is_none());
        assert_eq!(current(&slave).c_ospeed, BAUD_3000000);
        assert_eq!(serial.baud, BAUD_115200);
        // The stale cache is explicitly not verification after a partial attempt.
    }
}
#[test]
fn changed_actual_starting_rate_refuses_before_set_and_preserves_observed_drift() {
    let (mut serial, _master, slave) = pty();
    let mut drift = current(&slave);
    drift.c_cflag = (drift.c_cflag & !(libc::CBAUD | libc::CIBAUD)) | libc::B57600;
    drift.c_ispeed = 57600;
    drift.c_ospeed = 57600;
    // SAFETY: deliberate drift on this owned local PTY through a valid kernel
    // termios2 input. This fixture never supplies a forged readback to apply.
    assert_eq!(
        unsafe {
            libc::ioctl(
                slave.as_raw_fd(),
                ioctl_request(TCSETS2),
                &drift as *const Termios2,
            )
        },
        0
    );
    let mut result = BaudTransitionAttempt::new(NativeBbBaud::Mining, due());
    assert!(apply(&mut serial, &mut result, &|| false)
        .unwrap_err()
        .to_string()
        .contains("starting rate"));
    assert_eq!(result.before.unwrap().output_speed, 57600);
    assert!(result.set_started_at.is_none());
    assert_eq!(current(&slave).c_ospeed, 57600);
    assert_eq!(serial.baud, BAUD_115200);
}
#[test]
fn actual_full_pty_transition_refuses_unsupported_line_status_without_setting_or_discarding_bytes()
{
    let (mut serial, mut master, slave) = pty();
    let original = BaudSettings::from(current(&slave));
    let original_flags = flags(&serial);
    master.write_all(&[5, 6, 7]).unwrap();
    serial.write_bytes(&[2, 3, 4]).unwrap();
    let result = serial.transition_native_bb_baud_until(NativeBbBaud::Mining, due(), &|| false);
    assert!(result.failure.is_some() && result.caller_completed_at.is_none());
    let drain = result.drain.unwrap();
    assert_eq!(drain.last.pending_output, Some(0));
    assert!(drain.last.line_status.is_none() && drain.failure.is_some());
    assert!(
        result.before.is_none() && result.set_started_at.is_none() && result.readback.is_none()
    );
    assert_eq!(BaudSettings::from(current(&slave)), original);
    assert_eq!(flags(&serial), original_flags);
    let mut arrived = [0; 3];
    master.read_exact(&mut arrived).unwrap();
    assert_eq!(arrived, [2, 3, 4]);
    assert_eq!(serial.read_bytes(&mut arrived).unwrap(), 3);
    assert_eq!(arrived, [5, 6, 7]);
}
