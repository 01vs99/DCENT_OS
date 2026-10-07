//! Local Linux PTYs exercise the real SerialChain API and kernel termios2.
//! A PTY proves configuration semantics, not physical UART clocks or wire baud.

use super::*;
use std::os::fd::FromRawFd;

// Independent oracle: retained /usr/include/asm-generic/termbits.h. Do not use
// the production BOTHER constant to decide whether the kernel accepted a rate.
const ABI_BOTHER: u32 = 0o010000;
const ABI_CBAUD: u32 = 0o010017;

fn pty() -> (File, File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: initialized output pointers for fresh local PTY descriptors;
    // optional name, termios and winsize inputs are absent.
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
        0,
        "local openpty failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: openpty returned two distinct, live, newly owned descriptors.
    unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
}

fn path(slave: &File) -> String {
    // This points only at the owned PTY above, never a miner's ttyS device.
    format!("/proc/self/fd/{}", slave.as_raw_fd())
}

fn current(slave: &File) -> Termios2 {
    // SAFETY: Termios2 is POD with the Linux ABI layout. The actual kernel
    // initializes the output buffer through the live, owned PTY descriptor.
    let mut value: Termios2 = unsafe { std::mem::zeroed() };
    // SAFETY: the live local descriptor and writable ABI output outlive ioctl.
    assert_eq!(
        unsafe {
            libc::ioctl(
                slave.as_raw_fd(),
                ioctl_request(TCGETS2),
                &mut value as *mut Termios2,
            )
        },
        0,
        "actual kernel TCGETS2 failed: {}",
        std::io::Error::last_os_error()
    );
    value
}

fn assert_custom_readback(chain: &SerialChain, slave: &File, requested: u32) {
    let actual = current(slave);
    assert_eq!(
        (actual.c_ispeed, actual.c_ospeed),
        (requested, requested),
        "TCGETS2 actual speeds differ from request; cached={} c_cflag={:#x}",
        chain.baud,
        actual.c_cflag
    );
    assert_eq!(actual.c_cflag & ABI_CBAUD, ABI_BOTHER);
    assert!(chain.current_termios2_uses_bother());
}

fn open_custom(requested: u32) {
    let (_master, slave) = pty();
    let chain = SerialChain::open(&path(&slave), requested).unwrap();
    assert_custom_readback(&chain, &slave, requested);
}

#[test]
fn actual_open_custom_1562500_reads_back_both_kernel_speeds() {
    open_custom(1_562_500);
}

#[test]
fn actual_open_custom_3125000_reads_back_both_kernel_speeds() {
    open_custom(3_125_000);
}

fn set_custom(first: u32, next: u32) {
    let (_master, slave) = pty();
    let mut chain = SerialChain::open(&path(&slave), BAUD_115200).unwrap();
    let initial = current(&slave);
    assert_eq!((initial.c_ispeed, initial.c_ospeed), (115_200, 115_200));
    for requested in [first, next, first] {
        chain.set_baud(requested).unwrap();
        assert_custom_readback(&chain, &slave, requested);
    }
    chain.set_baud(BAUD_115200).unwrap();
    let restored = current(&slave);
    assert_eq!((restored.c_ispeed, restored.c_ospeed), (115_200, 115_200));
    assert_ne!(restored.c_cflag & ABI_CBAUD, ABI_BOTHER);
    assert!(!chain.current_termios2_uses_bother());
}

#[test]
fn actual_set_custom_1562500_and_repeated_transitions_read_back_kernel() {
    set_custom(1_562_500, 3_125_000);
}

#[test]
fn actual_set_custom_3125000_and_repeated_transitions_read_back_kernel() {
    set_custom(3_125_000, 1_562_500);
}

#[test]
fn actual_extended_standard_rates_are_never_reported_as_bother() {
    let (_master, slave) = pty();
    let mut chain = SerialChain::open(&path(&slave), BAUD_115200).unwrap();
    // 4 Mbaud is especially useful: its enum equals the legacy wrong BOTHER.
    for requested in [115_200, 3_000_000, 4_000_000] {
        chain.set_baud(requested).unwrap();
        let actual = current(&slave);
        assert_eq!((actual.c_ispeed, actual.c_ospeed), (requested, requested));
        assert_ne!(actual.c_cflag & ABI_CBAUD, ABI_BOTHER);
        assert!(
            !chain.current_termios2_uses_bother(),
            "standard rate {requested} was misclassified; kernel c_cflag={:#x}",
            actual.c_cflag
        );
    }
}

#[test]
fn actual_independently_configured_custom_state_is_recognized() {
    let (_master, slave) = pty();
    let mut configured = current(&slave);
    configured.c_cflag = (configured.c_cflag & !ABI_CBAUD) | ABI_BOTHER;
    configured.c_ispeed = 3_125_000;
    configured.c_ospeed = 3_125_000;
    // SAFETY: an independently prepared Linux ABI input remains valid during
    // this actual TCSETS2 on our owned local PTY. This is not a readback mock.
    assert_eq!(
        unsafe {
            libc::ioctl(
                slave.as_raw_fd(),
                ioctl_request(TCSETS2),
                &configured as *const Termios2,
            )
        },
        0
    );
    let chain = SerialChain::open_passthrough(&path(&slave)).unwrap();
    assert_custom_readback(&chain, &slave, 3_125_000);
}
