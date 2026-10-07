//! Native BB host baud transition on the exclusively retained Linux UART.
//! Kernel readback is a host configuration observation, never ASIC baud proof.
use super::tx_observation::{BackendKind, TxDrainAttempt};
use super::*;
use std::time::Instant;

/// Existing BB enumeration/mining rates from am3_bb_mining.rs. Broader custom
/// divisors and the Xilinx 3.125M route are outside this native transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeBbBaud {
    Enumeration,
    Mining,
}
impl NativeBbBaud {
    pub fn rate(self) -> u32 {
        match self {
            Self::Enumeration => BAUD_115200,
            Self::Mining => BAUD_3000000,
        }
    }
    fn kernel_speed(self) -> u32 {
        match self {
            Self::Enumeration => libc::B115200,
            Self::Mining => libc::B3000000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaudSettings {
    pub input_flags: u32,
    pub output_flags: u32,
    pub control_flags: u32,
    pub local_flags: u32,
    pub line: u8,
    pub characters: [u8; 19],
    pub input_speed: u32,
    pub output_speed: u32,
}
impl From<Termios2> for BaudSettings {
    fn from(t: Termios2) -> Self {
        Self {
            input_flags: t.c_iflag,
            output_flags: t.c_oflag,
            control_flags: t.c_cflag,
            local_flags: t.c_lflag,
            line: t.c_line,
            characters: t.c_cc,
            input_speed: t.c_ispeed,
            output_speed: t.c_ospeed,
        }
    }
}
#[derive(Clone, Debug)]
pub struct BaudTransitionAttempt {
    pub requested: NativeBbBaud,
    pub deadline: Instant,
    pub started_at: Instant,
    pub cached_before: Option<u32>,
    pub drain: Option<TxDrainAttempt>,
    pub before: Option<BaudSettings>,
    pub requested_settings: Option<BaudSettings>,
    pub set_started_at: Option<Instant>,
    pub set_returned_at: Option<Instant>,
    pub set_result: Option<i32>,
    pub set_error: Option<String>,
    pub readback: Option<BaudSettings>,
    pub caller_completed_at: Option<Instant>,
    pub failure: Option<String>,
}
impl BaudTransitionAttempt {
    pub(crate) fn new(requested: NativeBbBaud, deadline: Instant) -> Self {
        Self {
            requested,
            deadline,
            started_at: Instant::now(),
            cached_before: None,
            drain: None,
            before: None,
            requested_settings: None,
            set_started_at: None,
            set_returned_at: None,
            set_result: None,
            set_error: None,
            readback: None,
            caller_completed_at: None,
            failure: None,
        }
    }
}
fn check(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<()> {
    if cancelled() {
        return Err(HalError::Platform(
            "native BB baud transition cancelled".into(),
        ));
    }
    if Instant::now() >= deadline {
        return Err(HalError::Platform(
            "native BB baud transition original deadline expired".into(),
        ));
    }
    Ok(())
}
fn settings(serial: &SerialChain) -> Result<Termios2> {
    // SAFETY: the existing Linux kernel termios2 POD layout is zero-initialized;
    // TCGETS2 initializes the output before fields are used.
    let mut value: Termios2 = unsafe { std::mem::zeroed() };
    // SAFETY: original retained tty descriptor and valid output of the same
    // existing ABI/layout used by SerialChain; no open or descriptor transfer.
    if unsafe {
        libc::ioctl(
            serial.raw_fd(),
            ioctl_request(TCGETS2),
            &mut value as *mut Termios2,
        )
    } < 0
    {
        return Err(HalError::Io(std::io::Error::last_os_error()));
    }
    Ok(value)
}

// This private step is called only after this module observes the same retained
// UART's actual transmitter. Host tests exercise this setter directly to verify
// real kernel TCSETS2 behavior; that does not fabricate successful PTY drain.
fn apply(
    serial: &mut SerialChain,
    result: &mut BaudTransitionAttempt,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    check(result.deadline, cancelled)?;
    let before = settings(serial)?;
    result.before = Some(before.into());
    check(result.deadline, cancelled)?;
    if !matches!(before.c_ospeed, BAUD_115200 | BAUD_3000000)
        || before.c_ispeed != before.c_ospeed
        || before.c_ospeed != serial.baud
    {
        return Err(HalError::Platform(
            "native BB baud owner/kernel starting rate differs".into(),
        ));
    }
    let mut requested = before;
    // Linux asm-generic/termbits.h standard baud selectors. Clear the separate
    // input selector so input follows the selected output rate. Preserve every
    // other flag/control character; TCSETS2 is immediate and never flushes RX/TX.
    requested.c_cflag =
        (requested.c_cflag & !(libc::CBAUD | libc::CIBAUD)) | result.requested.kernel_speed();
    requested.c_ispeed = result.requested.rate();
    requested.c_ospeed = result.requested.rate();
    result.requested_settings = Some(requested.into());
    check(result.deadline, cancelled)?;
    result.set_started_at = Some(Instant::now());
    // SAFETY: exclusive original tty owner, initialized kernel termios2 input,
    // and existing glibc/musl ioctl request conversion. Already-started ioctl is
    // not interruptible: caller must retain the blocking task through its join.
    let returned = unsafe {
        libc::ioctl(
            serial.raw_fd(),
            ioctl_request(TCSETS2),
            &requested as *const Termios2,
        )
    };
    let failure = if returned < 0 {
        Some(std::io::Error::last_os_error().to_string())
    } else {
        None
    };
    result.set_returned_at = Some(Instant::now());
    result.set_result = Some(returned);
    result.set_error = failure.clone();
    if let Some(error) = failure {
        return Err(HalError::Platform(format!("native BB TCSETS2: {error}")));
    }
    check(result.deadline, cancelled)?;
    let readback = settings(serial)?;
    // Preserve the actual output-speed observation in the existing cache even
    // if a following deadline/mismatch check refuses overall completion. If a
    // set returned but readback did not occur, the old cache is not verification.
    serial.baud = readback.c_ospeed;
    result.readback = Some(readback.into());
    check(result.deadline, cancelled)?;
    if result.readback != result.requested_settings {
        return Err(HalError::Platform(
            "native BB kernel baud/settings readback differs from requested state".into(),
        ));
    }
    Ok(())
}
impl SerialChain {
    pub(crate) fn transition_native_bb_baud_until(
        &mut self,
        requested: NativeBbBaud,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> BaudTransitionAttempt {
        let mut result = BaudTransitionAttempt::new(requested, deadline);
        result.cached_before = Some(self.baud);
        let outcome = (|| -> Result<()> {
            check(deadline, cancelled)?;
            let drain = tx_observation::observe_until(
                BackendKind::Kernel,
                deadline,
                cancelled,
                |reading| self.observe_transmitter(reading, deadline, cancelled),
            );
            let complete = drain.caller_completed_at.is_some() && drain.failure.is_none();
            result.drain = Some(drain);
            if !complete {
                return Err(HalError::Platform(
                    "native BB baud transition lacks actual original transmitter drain".into(),
                ));
            }
            apply(self, &mut result, cancelled)?;
            check(deadline, cancelled)?;
            let completed = Instant::now();
            if completed >= deadline {
                return Err(HalError::Platform(
                    "native BB baud completion was late".into(),
                ));
            }
            result.caller_completed_at = Some(completed);
            Ok(())
        })();
        if let Err(error) = outcome {
            result.failure = Some(error.to_string());
        }
        result
    }
}
#[path = "serial_enumeration_baud.rs"]
mod enumeration;
pub use enumeration::EnumerationBaudAttempt;

#[cfg(test)]
#[path = "serial_baud_transition_tests.rs"]
mod tests;
