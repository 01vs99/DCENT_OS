//! Internal deadline-aware transmitter observations; no dispatch or power authority.
//!
//! Linux v5.4 asm-generic/ioctls.h defines TIOCSERGETLSR=0x5459 and
//! TIOCSER_TEMT=1. serial_core.c uart_get_lsr_info consults tx_empty and the
//! pending software queue. The exact target driver must separately be qualified:
//! a successful ioctl is only that driver's report. It is not ASIC idle proof.
//! Reference sources/hashes: evidence/r09/bb-uart-drain-linux-v5_4/sources.json.
use super::*;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    Kernel,
    Mmio,
}

#[derive(Clone, Debug)]
pub struct Reading {
    pub backend: BackendKind,
    pub pending_output: Option<i32>,
    pub line_status: Option<u32>,
    pub observed_at: Option<Instant>,
}

impl Reading {
    fn empty(backend: BackendKind) -> Self {
        Self {
            backend,
            pending_output: None,
            line_status: None,
            observed_at: None,
        }
    }
    fn reports_empty(&self) -> bool {
        match self.backend {
            BackendKind::Kernel => {
                self.pending_output == Some(0)
                    && self.line_status.is_some_and(|status| status & 1 != 0)
            }
            BackendKind::Mmio => self
                .line_status
                .is_some_and(|status| status & LSR_TX_IDLE == LSR_TX_IDLE),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TxDrainAttempt {
    pub started_at: Instant,
    pub deadline: Instant,
    pub polls: u64,
    pub last: Reading,
    pub caller_completed_at: Option<Instant>,
    pub failure: Option<String>,
}

pub(super) fn check(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<()> {
    if cancelled() {
        return Err(HalError::Platform(
            "transmitter observation cancelled".into(),
        ));
    }
    if Instant::now() >= deadline {
        return Err(HalError::Platform(
            "transmitter observation deadline expired".into(),
        ));
    }
    Ok(())
}

/// The closure is internal and always bound to the same borrowed owner. Tests
/// inject status/error observations without claiming physical hardware evidence.
pub(crate) fn observe_until(
    backend: BackendKind,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
    mut observe: impl FnMut(&mut Reading) -> Result<()>,
) -> TxDrainAttempt {
    let mut result = TxDrainAttempt {
        started_at: Instant::now(),
        deadline,
        polls: 0,
        last: Reading::empty(backend),
        caller_completed_at: None,
        failure: None,
    };
    let outcome = (|| -> Result<()> {
        loop {
            check(deadline, cancelled)?;
            result.polls = result.polls.checked_add(1).ok_or_else(|| {
                HalError::Platform("transmitter observation count exhausted".into())
            })?;
            // Keep only the most recent poll, including partial fields on an
            // error. A previous complete poll cannot fill a missing new field.
            result.last = Reading::empty(backend);
            let observed = observe(&mut result.last);
            result.last.observed_at = Some(Instant::now());
            observed?;
            check(deadline, cancelled)?;
            if result.last.reports_empty() {
                let now = Instant::now();
                if now >= deadline {
                    return Err(HalError::Platform("transmitter completion was late".into()));
                }
                result.caller_completed_at = Some(now);
                return Ok(());
            }
            std::thread::yield_now();
        }
    })();
    if let Err(error) = outcome {
        result.failure = Some(error.to_string());
    }
    result
}

impl SerialChain {
    pub(crate) fn observe_transmitter(
        &self,
        reading: &mut Reading,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<()> {
        check(deadline, cancelled)?;
        let mut pending: libc::c_int = 0;
        // SAFETY: this owner retains its live fd; ioctl writes one c_int into
        // the initialized local. TIOCOUTQ does not read or discard RX/TX data.
        if unsafe { libc::ioctl(self.raw_fd(), libc::TIOCOUTQ, &mut pending) } < 0 {
            return Err(HalError::Io(std::io::Error::last_os_error()));
        }
        reading.pending_output = Some(pending);
        check(deadline, cancelled)?;
        if pending < 0 {
            return Err(HalError::Platform("negative kernel output count".into()));
        }
        let mut status: libc::c_uint = 0;
        // SAFETY: same retained fd, correct Linux ioctl ABI through the existing
        // musl/glibc request conversion, and one initialized c_uint output.
        // Unsupported-driver errors are preserved, never converted to empty.
        if unsafe { libc::ioctl(self.raw_fd(), ioctl_request(0x5459), &mut status) } < 0 {
            return Err(HalError::Io(std::io::Error::last_os_error()));
        }
        reading.line_status = Some(status);
        check(deadline, cancelled)
    }
}

impl DevmemUart {
    pub(crate) fn observe_transmitter(
        &self,
        reading: &mut Reading,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<()> {
        check(deadline, cancelled)?;
        // Existing owned MMIO accessor and verified UART_LSR/LSR_TX_IDLE bits;
        // no new mapping, address, register write or RX drain is introduced.
        reading.line_status = Some(self.read_reg(UART_LSR));
        check(deadline, cancelled)
    }
}

#[cfg(test)]
#[path = "serial_tx_observation_tests.rs"]
mod tests;
