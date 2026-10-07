use super::*;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::Duration;
fn pty() -> (SerialChainBackend, File, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: two valid fresh descriptor outputs; optional PTY settings absent.
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
    // SAFETY: newly returned distinct descriptors adopted once each.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: this fresh slave has no existing File owner.
    let slave = unsafe { File::from_raw_fd(slave) };
    let serial = SerialChainBackend::open_native_linux_only(
        0,
        &format!("/proc/self/fd/{}", slave.as_raw_fd()),
        115200,
    )
    .unwrap();
    (serial, master, slave)
}
#[test]
fn same_exclusive_kernel_backend_retains_actual_unsupported_drain_and_original_baud() {
    let (mut serial, _master, _slave) = pty();
    let result = serial.transition_native_bb_baud_until(
        NativeBbBaud::Mining,
        Instant::now() + Duration::from_secs(1),
        &|| false,
    );
    assert_eq!(result.cached_before, Some(115200));
    assert!(result.drain.unwrap().failure.is_some());
    assert!(result.set_started_at.is_none() && result.failure.is_some());
    assert_eq!(serial.baud(), 115200);
}
#[test]
fn poisoned_original_backend_refuses_without_unwrapping_or_replacing_owner() {
    let (mut serial, _master, _slave) = pty();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = serial.serial.lock().unwrap();
        panic!("owned fixture poisons original mutex");
    }));
    assert!(failure.is_err());
    let result = serial.transition_native_bb_baud_until(
        NativeBbBaud::Mining,
        Instant::now() + Duration::from_secs(1),
        &|| false,
    );
    assert!(result.failure.unwrap().contains("poisoned"));
    assert!(
        result.cached_before.is_none() && result.drain.is_none() && result.set_started_at.is_none()
    );
}

#[test]
fn original_backend_read_only_enumeration_works_without_pty_drain_and_preserves_pending_rx() {
    use std::io::{Read, Write};
    let (mut serial, mut master, mut slave) = pty();
    master.write_all(&[0xaa, 0x55, 3, 5]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    let result = serial.observe_native_bb_enumeration_baud_until(deadline, &|| false);
    assert!(result.failure.is_none());
    assert!(result.caller_completed_at.unwrap() < deadline);
    assert_eq!(result.read_result, Some(0));
    let settings = result.settings.unwrap();
    assert_eq!(
        (settings.input_speed, settings.output_speed, serial.baud()),
        (115200, 115200, 115200)
    );
    assert_eq!(
        (result.cached_before, result.cached_after),
        (Some(115200), Some(115200))
    );
    let mut arrived = [0; 4];
    slave.read_exact(&mut arrived).unwrap();
    assert_eq!(arrived, [0xaa, 0x55, 3, 5]);
}

#[test]
fn enumeration_poisoned_original_backend_retains_refusal_without_read_or_replacement() {
    let (mut serial, _master, _slave) = pty();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = serial.serial.lock().unwrap();
        panic!("owned fixture poisons original mutex");
    }));
    assert!(failure.is_err());
    let result = serial
        .observe_native_bb_enumeration_baud_until(Instant::now() + Duration::from_secs(1), &|| {
            false
        });
    assert!(result.failure.unwrap().contains("poisoned"));
    assert!(result.cached_before.is_none() && result.read_started_at.is_none());
    assert!(result.read_returned_at.is_none() && result.settings.is_none());
    assert!(result.caller_completed_at.is_none());
}
