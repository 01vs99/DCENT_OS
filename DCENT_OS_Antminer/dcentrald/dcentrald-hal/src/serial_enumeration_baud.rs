//! Read-only initial BB enumeration-rate observation on the original Linux tty.
//! Completion is historical host configuration, never transmitter/ASIC proof.
use super::*;

#[derive(Clone, Debug)]
pub struct EnumerationBaudAttempt {
    pub deadline: Instant,
    pub started_at: Instant,
    pub cached_before: Option<u32>,
    pub read_started_at: Option<Instant>,
    pub read_returned_at: Option<Instant>,
    pub read_result: Option<i32>,
    pub read_errno: Option<i32>,
    pub read_error: Option<String>,
    pub settings: Option<BaudSettings>,
    pub cached_after: Option<u32>,
    pub caller_completed_at: Option<Instant>,
    pub failure: Option<String>,
}
impl EnumerationBaudAttempt {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            started_at: Instant::now(),
            cached_before: None,
            read_started_at: None,
            read_returned_at: None,
            read_result: None,
            read_errno: None,
            read_error: None,
            settings: None,
            cached_after: None,
            caller_completed_at: None,
            failure: None,
        }
    }
}
fn active(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<()> {
    if cancelled() {
        return Err(HalError::Platform(
            "native BB enumeration baud observation cancelled".into(),
        ));
    }
    if Instant::now() >= deadline {
        return Err(HalError::Platform(
            "native BB enumeration baud original deadline expired".into(),
        ));
    }
    Ok(())
}
impl SerialChain {
    pub(crate) fn observe_native_bb_enumeration_baud_until(
        &self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> EnumerationBaudAttempt {
        let mut result = EnumerationBaudAttempt::new(deadline);
        result.cached_before = Some(self.baud);
        let outcome = (|| -> Result<()> {
            active(deadline, cancelled)?;
            // SAFETY: initialized Linux termios2 POD with the existing checked
            // ABI. TCGETS2 alone fills this local output; no setter is invoked.
            let mut settings: Termios2 = unsafe { std::mem::zeroed() };
            result.read_started_at = Some(Instant::now());
            // SAFETY: the original exclusively retained live tty descriptor and
            // a valid local termios2 output. No FD leaves this owner, and no
            // open, transfer, drain, flush, fcntl or configuration write occurs.
            let returned = unsafe {
                libc::ioctl(
                    self.raw_fd(),
                    ioctl_request(TCGETS2),
                    &mut settings as *mut Termios2,
                )
            };
            // Capture errno before any later observation can disturb it. An
            // already-entered ioctl is not claimed to be interruptible.
            let error = (returned < 0).then(std::io::Error::last_os_error);
            result.read_returned_at = Some(Instant::now());
            result.read_result = Some(returned);
            result.read_errno = error.as_ref().and_then(std::io::Error::raw_os_error);
            result.read_error = error.as_ref().map(ToString::to_string);
            result.cached_after = Some(self.baud);
            if let Some(error) = error {
                return Err(HalError::Io(error));
            }
            // Retain actual settings before cancellation/deadline checks. No
            // observed field, even a mismatch, updates the requested-rate cache.
            result.settings = Some(settings.into());
            active(deadline, cancelled)?;
            if settings.c_ispeed != BAUD_115200
                || settings.c_ospeed != BAUD_115200
                || result.cached_before != Some(BAUD_115200)
                || result.cached_after != Some(BAUD_115200)
            {
                return Err(HalError::Platform(
                    "native BB enumeration requires actual input/output and cached 115200".into(),
                ));
            }
            let completed = Instant::now();
            if completed >= deadline {
                return Err(HalError::Platform(
                    "native BB enumeration completion was late".into(),
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

#[cfg(test)]
#[path = "serial_enumeration_baud_tests.rs"]
mod tests;
