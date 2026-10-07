//! Native Linux baud transition through the exclusively retained backend.
use super::*;
impl SerialChainBackend {
    /// Read the original Linux tty configuration without changing its cache,
    /// pending bytes or flags. This is not a transmitter-drain observation.
    pub fn observe_native_bb_enumeration_baud_until(
        &mut self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> EnumerationBaudAttempt {
        match self.serial.get_mut() {
            Ok(UartBackend::File(serial)) => {
                serial.observe_native_bb_enumeration_baud_until(deadline, cancelled)
            }
            other => {
                let mut result = EnumerationBaudAttempt::new(deadline);
                result.failure = Some(
                    if other.is_err() {
                        "native BB enumeration baud owner poisoned"
                    } else {
                        "native BB enumeration requires the original Linux UART"
                    }
                    .into(),
                );
                result
            }
        }
    }

    /// Requires the same UART's actual driver drain immediately before TCSETS2.
    /// No mutex wait, RX flush, raw compatibility setter or MMIO fallback. The
    /// enclosing async owner must retain its blocking caller and close lifetime.
    pub fn transition_native_bb_baud_until(
        &mut self,
        requested: NativeBbBaud,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> BaudTransitionAttempt {
        match self.serial.get_mut() {
            Ok(UartBackend::File(serial)) => {
                serial.transition_native_bb_baud_until(requested, deadline, cancelled)
            }
            other => {
                let mut result = BaudTransitionAttempt::new(requested, deadline);
                result.failure = Some(
                    if other.is_err() {
                        "native BB baud owner poisoned"
                    } else {
                        "native BB baud requires the original Linux UART"
                    }
                    .into(),
                );
                result
            }
        }
    }
}
#[cfg(test)]
#[path = "serial_chain_baud_transition_tests.rs"]
mod tests;
