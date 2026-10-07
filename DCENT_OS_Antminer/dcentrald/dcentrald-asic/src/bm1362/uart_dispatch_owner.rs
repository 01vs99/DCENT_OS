//! Staged BB dispatch ownership around the existing transport and wire codecs.
//! No ASIC command, UART open, electrical idle or voltage capability is added.
//! A stopped admission gate remains distinct from a started write's return,
//! the UART driver's transmitter report, and actual ASIC computation stopping.
use super::{
    Am335xUartTransport, AsicWorkFrame, ChainUart, UartTransportError, SEND_WORK_RING_SLOTS,
};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

// Native software state only; none of these bits are hardware registers.
const STOPPED: u8 = 1;
const HELD: u8 = 2;
const ACTIVE: u8 = 4;
const RECEIVE: u8 = 8;
const OBSERVING: u8 = 16;
const CONTROL: u8 = 32;

#[derive(Clone)]
pub(crate) struct DispatchStop {
    state: Arc<AtomicU8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DispatchObservation {
    pub permanently_stopped: bool,
    pub held: bool,
    /// A Rust caller has admitted a send and has not left its call scope.
    /// Zero does not prove a UART transmitter or ASIC is electrically idle.
    pub send_caller_pending: bool,
    pub receive_caller_pending: bool,
    pub observation_caller_pending: bool,
    pub control_caller_pending: bool,
}

impl DispatchStop {
    pub(crate) fn stop(&self) -> DispatchObservation {
        self.state.fetch_or(STOPPED, Ordering::SeqCst);
        self.snapshot()
    }

    pub(crate) fn snapshot(&self) -> DispatchObservation {
        let value = self.state.load(Ordering::SeqCst);
        DispatchObservation {
            permanently_stopped: value & STOPPED != 0,
            held: value & HELD != 0,
            send_caller_pending: value & ACTIVE != 0,
            receive_caller_pending: value & RECEIVE != 0,
            observation_caller_pending: value & OBSERVING != 0,
            control_caller_pending: value & CONTROL != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchError {
    Stopped,
    HeldOrPending,
    Transport(UartTransportError),
}

struct SendScope {
    stop: DispatchStop,
    completed: bool,
}

impl SendScope {
    fn enter(stop: &DispatchStop) -> Result<Self, DispatchError> {
        stop.state
            .compare_exchange(0, ACTIVE, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|value| {
                if value & STOPPED != 0 {
                    DispatchError::Stopped
                } else {
                    DispatchError::HeldOrPending
                }
            })?;
        Ok(Self {
            stop: stop.clone(),
            completed: false,
        })
    }
}

impl Drop for SendScope {
    fn drop(&mut self) {
        // A partial write, error or unwind cannot silently restore dispatch.
        // Mark terminal before clearing the actual admitted caller bit.
        if !self.completed {
            self.stop.stop();
        }
        self.stop.state.fetch_and(!ACTIVE, Ordering::SeqCst);
    }
}

pub(crate) struct BbDispatchOwner<U: ChainUart> {
    transport: Am335xUartTransport<U>,
    stop: DispatchStop,
}

impl<U: ChainUart> BbDispatchOwner<U> {
    pub(crate) fn new(transport: Am335xUartTransport<U>) -> Self {
        Self {
            transport,
            stop: DispatchStop {
                state: Arc::new(AtomicU8::new(0)),
            },
        }
    }

    /// Sender-free permanent stop publisher; it cannot reopen, configure or
    /// extract the original UARTs. An already-admitted call must still return.
    pub(crate) fn stop_handle(&self) -> DispatchStop {
        self.stop.clone()
    }

    pub(crate) fn snapshot(&self) -> DispatchObservation {
        self.stop.snapshot()
    }

    pub(crate) fn chain_count(&self) -> usize {
        self.transport.chain_count()
    }

    pub(crate) fn in_flight_ring(
        &self,
        chain: usize,
    ) -> Option<[Option<u8>; SEND_WORK_RING_SLOTS]> {
        self.transport.in_flight_ring(chain)
    }

    pub(crate) fn try_send_work(
        &mut self,
        chain: usize,
        frame: &AsicWorkFrame,
        now_us: u64,
    ) -> Result<bool, DispatchError> {
        let mut scope = SendScope::enter(&self.stop)?;
        let sent = self
            .transport
            .try_send_work(chain, frame, now_us)
            .map_err(DispatchError::Transport)?;
        // The transport records a completed frame before this terminal check.
        // Its real ring/history remains available even when stop races a write.
        if self.stop.snapshot().permanently_stopped {
            return Err(DispatchError::Stopped);
        }
        scope.completed = true;
        Ok(sent)
    }

    pub(crate) fn try_send_raw(
        &mut self,
        chain: usize,
        frame: &[u8],
        job: u8,
        now_us: u64,
    ) -> Result<bool, DispatchError> {
        let mut scope = SendScope::enter(&self.stop)?;
        let sent = self
            .transport
            .try_send_raw(chain, frame, job, now_us)
            .map_err(DispatchError::Transport)?;
        if self.stop.snapshot().permanently_stopped {
            return Err(DispatchError::Stopped);
        }
        scope.completed = true;
        Ok(sent)
    }

    /// Hold the actual transport by exclusive borrow. This only excludes new
    /// host sends; it does not drain queued bytes or stop ASIC computation.
    pub(crate) fn hold_dispatch(&mut self) -> Result<DispatchHold<'_, U>, DispatchError> {
        self.stop
            .state
            .compare_exchange(0, HELD, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|value| {
                if value & STOPPED != 0 {
                    DispatchError::Stopped
                } else {
                    DispatchError::HeldOrPending
                }
            })?;
        Ok(DispatchHold {
            owner: self,
            resumed: false,
        })
    }
}

impl<U: ChainUart> Drop for BbDispatchOwner<U> {
    fn drop(&mut self) {
        self.stop.stop();
    }
}

pub(crate) struct DispatchHold<'a, U: ChainUart> {
    owner: &'a mut BbDispatchOwner<U>,
    resumed: bool,
}

impl<U: ChainUart> DispatchHold<'_, U> {
    pub(crate) fn snapshot(&self) -> DispatchObservation {
        self.owner.snapshot()
    }

    /// The enclosing controller calls this only after its other owners agree.
    /// This method itself proves no voltage/freshness/ASIC admission. A terminal
    /// stop, cancelled/dropped hold, or forgotten hold cannot be reset here.
    pub(crate) fn resume(mut self) -> Result<(), DispatchError> {
        self.owner
            .stop
            .state
            .compare_exchange(HELD, 0, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| DispatchError::Stopped)?;
        self.resumed = true;
        Ok(())
    }
}

impl<U: ChainUart> Drop for DispatchHold<'_, U> {
    fn drop(&mut self) {
        if !self.resumed {
            self.owner.stop.stop();
        }
    }
}

#[cfg(test)]
#[path = "uart_dispatch_owner_tests.rs"]
mod tests;

#[path = "uart_dispatch_receive.rs"]
mod receive;
pub(crate) use receive::{CheckedChainUart, ReceiveAttempt, ReceiveError};

#[path = "uart_serial_dispatch.rs"]
mod serial_dispatch;
pub(crate) use serial_dispatch::{BbSerialDispatchHold, BbSerialDispatchOwner};

pub use serial_dispatch::{
    BbClosedController, BbControllerObservation, BbOwnedController, BbOwnedControllerStop,
};
