//! Borrow the exact serial owner for bounded polling; preserve RX and file flags.
use super::*;
use crate::serial::tx_observation::{self, BackendKind, TxDrainAttempt};

impl SerialChainBackend {
    /// Read kernel queue plus driver line status, or MMIO LSR, until reported
    /// empty or the original deadline/cancellation. No tcdrain, new open, flush,
    /// parser mutation, baud change or dispatch is performed. An already-started
    /// ioctl cannot be interrupted by this deadline; the enclosing async runtime
    /// must retain and join its blocking caller before reusing/closing the owner.
    /// Success is historical driver-reported empty, not ASIC idle or permission
    /// to change voltage. The caller must independently exclude future writers.
    pub fn observe_transmitter_until(
        &mut self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<TxDrainAttempt> {
        // Exclusive mutable access avoids an unbounded mutex wait. The backend
        // is never extracted, reopened or replaced, even on an observation error.
        let backend = self
            .serial
            .get_mut()
            .map_err(|_| HalError::Platform("transmitter owner poisoned".into()))?;
        let kind = match backend {
            UartBackend::File(_) => BackendKind::Kernel,
            UartBackend::Devmem(_) => BackendKind::Mmio,
        };
        Ok(tx_observation::observe_until(
            kind,
            deadline,
            cancelled,
            |reading| match backend {
                UartBackend::File(serial) => {
                    serial.observe_transmitter(reading, deadline, cancelled)
                }
                UartBackend::Devmem(serial) => {
                    serial.observe_transmitter(reading, deadline, cancelled)
                }
            },
        ))
    }
}

#[cfg(test)]
#[path = "serial_chain_tx_observation_tests.rs"]
mod tests;
