//! Bounded raw I/O on an exclusively borrowed existing UART owner.
//! These records report host I/O progress only. They confer no power authority.
use super::*;

#[derive(Clone, Debug)]
pub struct RawIoStatus {
    pub started_at: Instant,
    pub deadline: Instant,
    pub io_calls: u64,
    pub original_file_flags: Option<i32>,
    pub flags_restored: bool,
    pub caller_completed_at: Option<Instant>,
    pub failure: Option<String>,
    pub restore_error: Option<String>,
}

impl RawIoStatus {
    fn new(deadline: Instant) -> Self {
        Self {
            started_at: Instant::now(),
            deadline,
            io_calls: 0,
            original_file_flags: None,
            flags_restored: false,
            caller_completed_at: None,
            failure: None,
            restore_error: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RawReadAttempt {
    pub status: RawIoStatus,
    pub returned_count: Option<usize>,
    /// Exact available prefix on a successful backend return, even if a later
    /// deadline/cancellation/flag-restoration check fails. Errors do not invent
    /// a count for scratch bytes the backend did not report.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RawWriteAttempt {
    pub status: RawIoStatus,
    pub requested_bytes: usize,
    /// Successful per-call counts, accumulated before post-call checks. This is
    /// acceptance by the backend, not transmission or ASIC acknowledgement.
    pub accepted_bytes: usize,
    pub accepted_prefix: Vec<u8>,
}

fn check(deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<()> {
    if cancelled() {
        return Err(HalError::Platform("raw UART I/O cancelled".into()));
    }
    if Instant::now() >= deadline {
        return Err(HalError::Platform("raw UART I/O deadline expired".into()));
    }
    Ok(())
}

struct RawScope<'a> {
    backend: &'a mut UartBackend,
    original_flags: Option<i32>,
}

impl RawScope<'_> {
    fn restore(&mut self) -> Result<()> {
        if let (Some(flags), UartBackend::File(serial)) = (self.original_flags, &mut self.backend) {
            serial.restore_io_flags(flags)?;
            self.original_flags = None;
        }
        Ok(())
    }
}

impl Drop for RawScope<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            tracing::error!(%error, "failed to restore original raw UART flags during scope drop");
        }
    }
}

fn operate(
    backend: &mut UartBackend,
    status: &mut RawIoStatus,
    cancelled: &dyn Fn() -> bool,
    operation: impl FnOnce(&mut UartBackend, &mut RawIoStatus) -> Result<()>,
) {
    let outcome = (|| -> Result<()> {
        check(status.deadline, cancelled)?;
        let original_flags = match backend {
            UartBackend::File(serial) => Some(serial.begin_bounded_io()?),
            UartBackend::Devmem(_) => None,
        };
        status.original_file_flags = original_flags;
        let mut scope = RawScope {
            backend,
            original_flags,
        };
        let result =
            check(status.deadline, cancelled).and_then(|()| operation(scope.backend, status));
        match scope.restore() {
            Ok(()) => status.flags_restored = true,
            Err(error) => status.restore_error = Some(error.to_string()),
        }
        result?;
        if status.restore_error.is_some() {
            return Err(HalError::Platform(
                "raw UART flag restoration failed".into(),
            ));
        }
        check(status.deadline, cancelled)?;
        let completed = Instant::now();
        if completed >= status.deadline {
            return Err(HalError::Platform("raw UART completion was late".into()));
        }
        status.caller_completed_at = Some(completed);
        Ok(())
    })();
    if let Err(error) = outcome {
        status.failure = Some(error.to_string());
    }
}

fn next_call(status: &mut RawIoStatus) -> Result<()> {
    status.io_calls = status
        .io_calls
        .checked_add(1)
        .ok_or_else(|| HalError::Platform("raw UART call count exhausted".into()))?;
    Ok(())
}

impl SerialChainBackend {
    /// Make at most one nonblocking backend read. This temporarily changes and
    /// restores the existing file's flags; it never opens, extracts, replaces,
    /// flushes or changes its baud, termios or buffered response parser.
    ///
    /// Exclusive access avoids waiting on the backend mutex. An already-started
    /// syscall is not interruptible by these checks: the async caller must
    /// retain and join its blocking task before reusing or closing this owner.
    pub fn read_raw_once_bounded(
        &mut self,
        bytes: &mut [u8],
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> RawReadAttempt {
        let mut result = RawReadAttempt {
            status: RawIoStatus::new(deadline),
            returned_count: None,
            bytes: Vec::new(),
        };
        if bytes.is_empty() {
            result.status.failure = Some("raw UART read requires nonempty capacity".into());
            return result;
        }
        let backend = match self.serial.get_mut() {
            Ok(backend) => backend,
            Err(_) => {
                result.status.failure = Some("raw UART owner poisoned".into());
                return result;
            }
        };
        operate(backend, &mut result.status, cancelled, |backend, status| {
            next_call(status)?;
            // File is O_NONBLOCK for this exact scope. The MMIO implementation
            // already bounds its register-read loop by the supplied capacity.
            let n = backend.read_bytes(bytes)?;
            result.returned_count = Some(n);
            result.bytes.extend_from_slice(&bytes[..n.min(bytes.len())]);
            if n > bytes.len() {
                return Err(HalError::Platform(
                    "raw UART reported oversized read count".into(),
                ));
            }
            check(deadline, cancelled)
        });
        result
    }

    /// Write a caller-owned raw frame under one original absolute deadline,
    /// retaining every successfully reported prefix before a later error.
    /// No drain or acknowledgement is inferred from full backend acceptance.
    pub fn write_raw_until(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> RawWriteAttempt {
        let mut result = RawWriteAttempt {
            status: RawIoStatus::new(deadline),
            requested_bytes: bytes.len(),
            accepted_bytes: 0,
            accepted_prefix: Vec::new(),
        };
        if bytes.is_empty() {
            result.status.failure = Some("raw UART write requires a nonempty frame".into());
            return result;
        }
        let backend = match self.serial.get_mut() {
            Ok(backend) => backend,
            Err(_) => {
                result.status.failure = Some("raw UART owner poisoned".into());
                return result;
            }
        };
        operate(backend, &mut result.status, cancelled, |backend, status| {
            while result.accepted_bytes < bytes.len() {
                check(deadline, cancelled)?;
                next_call(status)?;
                let rest = &bytes[result.accepted_bytes..];
                let n = match backend {
                    UartBackend::File(serial) => serial.try_write_bounded(rest)?,
                    UartBackend::Devmem(serial) => serial.try_write_bounded(rest)?,
                };
                if n > rest.len() {
                    return Err(HalError::Platform(
                        "raw UART reported oversized write count".into(),
                    ));
                }
                result.accepted_bytes += n;
                result.accepted_prefix.extend_from_slice(&rest[..n]);
                check(deadline, cancelled)?;
                if n == 0 {
                    std::thread::yield_now();
                }
            }
            Ok(())
        });
        result
    }
}

#[cfg(test)]
#[path = "serial_chain_raw_io_tests.rs"]
mod tests;
