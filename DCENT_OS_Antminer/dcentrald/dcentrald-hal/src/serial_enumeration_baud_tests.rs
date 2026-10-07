use super::*;
use std::cell::Cell;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::Duration;

fn due() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn pty(rate: u32) -> (SerialChain, File, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: valid outputs for fresh host PTY descriptors; optional inputs are
    // absent. No miner or physical UART is opened by this fixture.
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
    // SAFETY: each distinct newly returned descriptor is adopted once.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: this distinct slave descriptor has no other owning File.
    let slave = unsafe { File::from_raw_fd(slave) };
    let serial = SerialChain::open(&format!("/proc/self/fd/{}", slave.as_raw_fd()), rate).unwrap();
    (serial, master, slave)
}
fn current(slave: &File) -> Termios2 {
    // SAFETY: initialized existing Linux termios2 ABI output on an owned PTY.
    let mut value: Termios2 = unsafe { std::mem::zeroed() };
    // SAFETY: TCGETS2 only fills valid local output for the retained test slave.
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
fn set_rates(slave: &File, input: u32, output: u32) {
    fn selector(rate: u32) -> u32 {
        match rate {
            57600 => libc::B57600,
            115200 => libc::B115200,
            3000000 => libc::B3000000,
            _ => panic!("fixture rate"),
        }
    }
    let mut value = current(slave);
    // Linux's separate input selector occupies bits16..; select both actual
    // standard speeds so the fixture can demonstrate input-only kernel drift.
    value.c_cflag = (value.c_cflag & !(libc::CBAUD | libc::CIBAUD))
        | selector(output)
        | (selector(input) << 16);
    value.c_ispeed = input;
    value.c_ospeed = output;
    // SAFETY: actual TCSETS2 on this owned local test PTY only. This is fixture
    // setup, never a fabricated return/settings value in the observed method.
    assert_eq!(
        unsafe {
            libc::ioctl(
                slave.as_raw_fd(),
                ioctl_request(TCSETS2),
                &value as *const Termios2,
            )
        },
        0
    );
    let observed = current(slave);
    assert_eq!((observed.c_ispeed, observed.c_ospeed), (input, output));
}
fn flags(serial: &SerialChain) -> i32 {
    // SAFETY: F_GETFL reads the original retained file's status flags only.
    unsafe { libc::fcntl(serial.raw_fd(), libc::F_GETFL) }
}
fn actual_read(result: &EnumerationBaudAttempt) {
    assert_eq!(result.read_result, Some(0));
    assert!(result.read_errno.is_none() && result.read_error.is_none());
    assert!(result.read_started_at.unwrap() >= result.started_at);
    assert!(result.read_returned_at.unwrap() >= result.read_started_at.unwrap());
    assert!(result.settings.is_some());
}

#[test]
fn actual_matching_enumeration_preserves_full_kernel_settings_cache_flags_and_pending_bytes() {
    let (mut serial, mut master, slave) = pty(115200);
    let before = BaudSettings::from(current(&slave));
    let before_flags = flags(&serial);
    master.write_all(&[0xaa, 0x55, 7, 9]).unwrap();
    serial.write_bytes(&[0x55, 0xaa, 11, 13]).unwrap();
    let deadline = due();
    let result = serial.observe_native_bb_enumeration_baud_until(deadline, &|| false);
    actual_read(&result);
    assert_eq!(result.deadline, deadline);
    assert!(result.failure.is_none());
    assert!(result.caller_completed_at.unwrap() >= result.read_returned_at.unwrap());
    assert!(result.caller_completed_at.unwrap() < deadline);
    assert_eq!(result.settings, Some(before.clone()));
    assert_eq!(
        (result.cached_before, result.cached_after, serial.baud()),
        (Some(115200), Some(115200), 115200)
    );
    assert_eq!(BaudSettings::from(current(&slave)), before);
    assert_eq!(flags(&serial), before_flags);
    let mut tx = [0; 4];
    master.read_exact(&mut tx).unwrap();
    assert_eq!(tx, [0x55, 0xaa, 11, 13]);
    let mut rx = [0; 4];
    assert_eq!(serial.read_bytes(&mut rx).unwrap(), 4);
    assert_eq!(rx, [0xaa, 0x55, 7, 9]);
}

#[test]
fn actual_input_output_and_cache_drift_are_independently_refused_without_repair() {
    for (cache, input, output) in [
        (115200, 57600, 115200),
        (115200, 115200, 57600),
        (115200, 3000000, 3000000),
        (57600, 115200, 115200),
    ] {
        let (serial, _master, slave) = pty(cache);
        set_rates(&slave, input, output);
        let before = BaudSettings::from(current(&slave));
        let result = serial.observe_native_bb_enumeration_baud_until(due(), &|| false);
        actual_read(&result);
        assert!(result.failure.as_ref().unwrap().contains("cached 115200"));
        assert!(result.caller_completed_at.is_none());
        assert_eq!(result.settings, Some(before.clone()));
        assert_eq!(
            (result.cached_before, result.cached_after, serial.baud()),
            (Some(cache), Some(cache), cache)
        );
        assert_eq!(BaudSettings::from(current(&slave)), before);
    }
}

#[test]
fn cancelled_or_expired_admission_retains_cache_without_entering_kernel_read() {
    for cancel in [false, true] {
        let (serial, _master, slave) = pty(115200);
        let before = BaudSettings::from(current(&slave));
        let deadline = if cancel { due() } else { Instant::now() };
        let result = serial.observe_native_bb_enumeration_baud_until(deadline, &|| cancel);
        assert_eq!(result.cached_before, Some(115200));
        assert!(result.cached_after.is_none() && result.read_started_at.is_none());
        assert!(result.read_returned_at.is_none() && result.read_result.is_none());
        assert!(result.settings.is_none() && result.caller_completed_at.is_none());
        assert!(result.failure.is_some());
        assert_eq!(BaudSettings::from(current(&slave)), before);
    }
}

#[test]
fn cancellation_and_real_deadline_after_actual_read_keep_settings_without_completion() {
    for expire in [false, true] {
        let (serial, _master, slave) = pty(115200);
        let before = BaudSettings::from(current(&slave));
        let calls = Cell::new(0);
        let deadline = Instant::now() + Duration::from_millis(50);
        let result = serial.observe_native_bb_enumeration_baud_until(deadline, &|| {
            // Fault injection affects only the cancellation predicate at its
            // second check. The ioctl, settings, timestamps and elapsed time
            // are real and independently asserted below, never substituted.
            calls.set(calls.get() + 1);
            if calls.get() > 1 {
                if expire {
                    std::thread::sleep(
                        deadline.saturating_duration_since(Instant::now())
                            + Duration::from_millis(1),
                    );
                    false
                } else {
                    true
                }
            } else {
                false
            }
        });
        actual_read(&result);
        assert_eq!(calls.get(), 2);
        assert!(result.failure.as_ref().unwrap().contains(if expire {
            "deadline"
        } else {
            "cancelled"
        }));
        assert!(result.caller_completed_at.is_none());
        assert_eq!(result.settings, Some(before.clone()));
        assert_eq!(
            (result.cached_before, result.cached_after),
            (Some(115200), Some(115200))
        );
        assert_eq!(BaudSettings::from(current(&slave)), before);
        if expire {
            assert!(Instant::now() >= deadline);
        }
    }
}

#[test]
fn actual_pty_hangup_retains_kernel_error_and_never_invents_settings_or_completion() {
    let (serial, master, _slave) = pty(115200);
    drop(master);
    let result = serial.observe_native_bb_enumeration_baud_until(due(), &|| false);
    assert_eq!(result.read_result, Some(-1));
    assert_eq!(result.read_errno, Some(libc::EIO));
    assert!(result.read_error.is_some() && result.failure.is_some());
    assert!(result.read_returned_at.unwrap() >= result.read_started_at.unwrap());
    assert!(result.settings.is_none() && result.caller_completed_at.is_none());
    assert_eq!(
        (result.cached_before, result.cached_after, serial.baud()),
        (Some(115200), Some(115200), 115200)
    );
}
