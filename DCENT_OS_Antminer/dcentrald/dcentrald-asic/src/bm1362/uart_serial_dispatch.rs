//! Concrete adapter consuming existing HAL UART owners, never opening devices.
use super::receive::CheckedRead;
use super::*;
use dcentrald_hal::serial_chain::{RawReadAttempt, RawWriteAttempt, SerialChainBackend};
use std::time::Instant;

struct SerialUart {
    backend: SerialChainBackend,
    stop: DispatchStop,
    deadline: Option<Instant>,
    last_read: Option<RawReadAttempt>,
    last_write: Option<RawWriteAttempt>,
}

impl ChainUart for SerialUart {
    fn write_frame(&mut self, bytes: &[u8]) -> Result<(), UartTransportError> {
        let Some(deadline) = self.deadline.take() else {
            self.stop.stop();
            return Err(UartTransportError::WriteFailed);
        };
        let stop = self.stop.clone();
        let attempt = self
            .backend
            .write_raw_until(bytes, deadline, &|| stop.snapshot().permanently_stopped);
        let complete = attempt.status.caller_completed_at.is_some()
            && attempt.status.failure.is_none()
            && attempt.status.restore_error.is_none()
            && attempt.accepted_bytes == bytes.len();
        self.last_write = Some(attempt);
        if !complete {
            self.stop.stop();
            return Err(UartTransportError::WriteFailed);
        }
        Ok(())
    }

    fn read_avail(&mut self, _: &mut [u8]) -> usize {
        // This private adapter has no compatibility reader. Latch stop if an
        // internal programming error ever routes it through the usize-only API.
        self.stop.stop();
        0
    }
}

impl CheckedChainUart for SerialUart {
    fn read_avail_checked(&mut self, bytes: &mut [u8]) -> CheckedRead {
        let Some(deadline) = self.deadline.take() else {
            self.stop.stop();
            return CheckedRead {
                returned_count: None,
                failure: Some("UART call has no original deadline".into()),
            };
        };
        let stop = self.stop.clone();
        let attempt = self
            .backend
            .read_raw_once_bounded(bytes, deadline, &|| stop.snapshot().permanently_stopped);
        let complete = attempt.status.caller_completed_at.is_some()
            && attempt.status.failure.is_none()
            && attempt.status.restore_error.is_none();
        let report = CheckedRead {
            returned_count: attempt.returned_count,
            failure: if complete {
                None
            } else {
                Some(
                    attempt
                        .status
                        .failure
                        .clone()
                        .unwrap_or_else(|| "raw UART read did not complete".into()),
                )
            },
        };
        self.last_read = Some(attempt);
        if !complete {
            self.stop.stop();
        }
        report
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SerialDispatchAttempt {
    pub dispatch: Result<bool, DispatchError>,
    /// None means this attempt made no adapter call (including pacing refusal).
    pub io: Option<RawWriteAttempt>,
}

#[derive(Clone, Debug)]
pub(crate) struct SerialReceiveAttempt {
    pub parsed: ReceiveAttempt,
    pub io: Vec<(usize, RawReadAttempt)>,
}

pub(crate) struct BbSerialDispatchOwner {
    inner: BbDispatchOwner<SerialUart>,
}

fn admitted_state(stop: &DispatchStop, held: bool) -> Result<(), DispatchError> {
    let state = stop.snapshot();
    if state.permanently_stopped {
        return Err(DispatchError::Stopped);
    }
    if state.held != held
        || state.send_caller_pending
        || state.receive_caller_pending
        || state.observation_caller_pending
        || state.control_caller_pending
    {
        return Err(DispatchError::HeldOrPending);
    }
    Ok(())
}

fn receive_until(
    owner: &mut BbDispatchOwner<SerialUart>,
    held: bool,
    deadline: Instant,
) -> SerialReceiveAttempt {
    if let Err(error) = admitted_state(&owner.stop, held) {
        return SerialReceiveAttempt {
            parsed: ReceiveAttempt {
                reads: Vec::new(),
                nonces: Vec::new(),
                caller_completed: false,
                failure: Some(ReceiveError::Admission(error)),
            },
            io: Vec::new(),
        };
    }
    for uart in &mut owner.transport.chains {
        uart.deadline = Some(deadline);
        uart.last_read = None;
    }
    let parsed = owner.receive_scoped(held);
    let mut io = Vec::new();
    for (chain, uart) in owner.transport.chains.iter_mut().enumerate() {
        uart.deadline = None;
        if let Some(attempt) = &uart.last_read {
            io.push((chain, attempt.clone()));
        }
    }
    SerialReceiveAttempt { parsed, io }
}

impl BbSerialDispatchOwner {
    /// Takes ownership of existing, already prepared backends. This constructor
    /// supplies no hardware identity/admission, opens, reconfiguration or new
    /// fd/MMIO mapping. No extraction, replacement or Clone API is exposed.
    pub(crate) fn new(backends: Vec<SerialChainBackend>, dispatch_interval_us: u64) -> Self {
        let stop = DispatchStop {
            state: Arc::new(AtomicU8::new(0)),
        };
        let chains = backends
            .into_iter()
            .map(|backend| SerialUart {
                backend,
                stop: stop.clone(),
                deadline: None,
                last_read: None,
                last_write: None,
            })
            .collect();
        Self {
            inner: BbDispatchOwner {
                transport: Am335xUartTransport::new(chains, dispatch_interval_us),
                stop,
            },
        }
    }

    pub(crate) fn stop_handle(&self) -> DispatchStop {
        self.inner.stop_handle()
    }
    pub(crate) fn snapshot(&self) -> DispatchObservation {
        self.inner.snapshot()
    }
    pub(crate) fn in_flight_ring(
        &self,
        chain: usize,
    ) -> Option<[Option<u8>; SEND_WORK_RING_SLOTS]> {
        self.inner.in_flight_ring(chain)
    }

    pub(crate) fn try_send_raw_until(
        &mut self,
        chain: usize,
        frame: &[u8],
        job: u8,
        now_us: u64,
        deadline: Instant,
    ) -> SerialDispatchAttempt {
        if let Err(error) = admitted_state(&self.inner.stop, false) {
            return SerialDispatchAttempt {
                dispatch: Err(error),
                io: None,
            };
        }
        if let Some(uart) = self.inner.transport.chains.get_mut(chain) {
            uart.deadline = Some(deadline);
            uart.last_write = None;
        }
        let dispatch = self.inner.try_send_raw(chain, frame, job, now_us);
        let io = self.inner.transport.chains.get_mut(chain).and_then(|uart| {
            uart.deadline = None;
            uart.last_write.clone()
        });
        SerialDispatchAttempt { dispatch, io }
    }

    pub(crate) fn receive_until(&mut self, deadline: Instant) -> SerialReceiveAttempt {
        receive_until(&mut self.inner, false, deadline)
    }

    pub(crate) fn hold_dispatch(&mut self) -> Result<BbSerialDispatchHold<'_>, DispatchError> {
        Ok(BbSerialDispatchHold {
            inner: self.inner.hold_dispatch()?,
        })
    }
}

pub(crate) struct BbSerialDispatchHold<'a> {
    inner: DispatchHold<'a, SerialUart>,
}

impl BbSerialDispatchHold<'_> {
    pub(crate) fn snapshot(&self) -> DispatchObservation {
        self.inner.snapshot()
    }
    pub(crate) fn receive_until(&mut self, deadline: Instant) -> SerialReceiveAttempt {
        receive_until(self.inner.owner, true, deadline)
    }
    pub(crate) fn resume(self) -> Result<(), DispatchError> {
        self.inner.resume()
    }
}

#[cfg(test)]
#[path = "uart_serial_dispatch_tests.rs"]
mod tests;

#[path = "uart_held_transmitter.rs"]
mod held_transmitter;
pub(crate) use held_transmitter::{BbSerialHeldOwner, HeldTransmitterAttempt};

#[path = "uart_runtime_owner.rs"]
mod runtime_owner;
pub(crate) use runtime_owner::BbUartRuntime;

#[path = "uart_cold_control.rs"]
mod cold_control;
pub(crate) use cold_control::{ColdControl, ColdControlAttempt, ColdRegister};

pub use runtime_owner::{
    BbClosedController, BbControllerObservation, BbOwnedController, BbOwnedControllerStop,
};
