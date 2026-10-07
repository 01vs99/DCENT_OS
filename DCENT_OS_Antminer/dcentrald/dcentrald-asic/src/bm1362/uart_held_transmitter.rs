//! Observe the retained UARTs while dispatch is held. Own a hold across moves.
use super::*;
use dcentrald_hal::serial_chain::TxDrainAttempt;

#[derive(Clone, Debug)]
pub(crate) struct ChainTransmitterObservation {
    pub chain: usize,
    pub attempt: Option<TxDrainAttempt>,
    /// Failure before a HAL attempt was available, such as a poisoned owner.
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct HeldTransmitterAttempt {
    pub started_at: Instant,
    pub deadline: Instant,
    pub observations: Vec<ChainTransmitterObservation>,
    /// Completion of this synchronous observation call only. Neither task join
    /// nor an ASIC-stop/voltage capability is supplied by driver-reported empty.
    pub caller_completed_at: Option<Instant>,
    pub failure: Option<String>,
}

struct ObservationScope {
    stop: DispatchStop,
    completed: bool,
}

impl ObservationScope {
    fn enter(stop: &DispatchStop) -> Result<Self, DispatchError> {
        stop.state
            .compare_exchange(HELD, HELD | OBSERVING, Ordering::SeqCst, Ordering::SeqCst)
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

impl Drop for ObservationScope {
    fn drop(&mut self) {
        if !self.completed {
            self.stop.stop();
        }
        self.stop.state.fetch_and(!OBSERVING, Ordering::SeqCst);
    }
}

fn check(stop: &DispatchStop, deadline: Instant) -> Result<(), String> {
    if stop.snapshot().permanently_stopped {
        return Err("held transmitter observation stopped".into());
    }
    if Instant::now() >= deadline {
        return Err("held transmitter observation deadline expired".into());
    }
    Ok(())
}

/// Private helper: production supplies a closure borrowing each original HAL
/// owner. Tests can model status/blocked callers without opening real UARTs.
fn observe_backends(
    stop: &DispatchStop,
    count: usize,
    deadline: Instant,
    mut observe: impl FnMut(usize) -> dcentrald_hal::Result<TxDrainAttempt>,
) -> HeldTransmitterAttempt {
    let mut result = HeldTransmitterAttempt {
        started_at: Instant::now(),
        deadline,
        observations: Vec::new(),
        caller_completed_at: None,
        failure: None,
    };
    let mut scope = match ObservationScope::enter(stop) {
        Ok(scope) => scope,
        Err(error) => {
            result.failure = Some(format!("held transmitter admission: {error:?}"));
            return result;
        }
    };
    let outcome = (|| -> Result<(), String> {
        check(stop, deadline)?;
        if count == 0 {
            return Err("held transmitter observation requires retained chains".into());
        }
        for chain in 0..count {
            check(stop, deadline)?;
            match observe(chain) {
                Ok(attempt) => {
                    let failure = attempt.failure.clone().or_else(|| {
                        if attempt.deadline != deadline || attempt.caller_completed_at.is_none() {
                            Some("HAL transmitter observation did not complete under original deadline".into())
                        } else { None }
                    });
                    result.observations.push(ChainTransmitterObservation {
                        chain,
                        attempt: Some(attempt),
                        error: None,
                    });
                    if let Some(failure) = failure {
                        return Err(failure);
                    }
                }
                Err(error) => {
                    let detail = error.to_string();
                    result.observations.push(ChainTransmitterObservation {
                        chain,
                        attempt: None,
                        error: Some(detail.clone()),
                    });
                    return Err(detail);
                }
            }
            // A stop racing an already-admitted ioctl leaves its returned raw
            // report intact and excludes every following chain observation.
            check(stop, deadline)?;
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("held transmitter completion was late".into());
        }
        check(stop, deadline)?;
        result.caller_completed_at = Some(now);
        Ok(())
    })();
    match outcome {
        Ok(()) => scope.completed = true,
        Err(error) => result.failure = Some(error),
    }
    result
}

fn observe_owner(owner: &mut BbSerialDispatchOwner, deadline: Instant) -> HeldTransmitterAttempt {
    let stop = owner.inner.stop.clone();
    let count = owner.inner.transport.chains.len();
    observe_backends(&stop, count, deadline, |chain| {
        owner.inner.transport.chains[chain]
            .backend
            .observe_transmitter_until(deadline, &|| stop.snapshot().permanently_stopped)
    })
}

impl BbSerialDispatchHold<'_> {
    pub(crate) fn observe_transmitters_until(
        &mut self,
        deadline: Instant,
    ) -> HeldTransmitterAttempt {
        let stop = self.inner.owner.stop.clone();
        let count = self.inner.owner.transport.chains.len();
        observe_backends(&stop, count, deadline, |chain| {
            self.inner.owner.transport.chains[chain]
                .backend
                .observe_transmitter_until(deadline, &|| stop.snapshot().permanently_stopped)
        })
    }
}

/// Owns the exact original UART transport in held state. It can move into and
/// return from a retained blocking task; no borrowed/self-referential guard,
/// forgotten hold, new open or backend extraction is used. Dropping this value
/// drops the original dispatch owner, whose Drop permanently stops admission.
pub(crate) struct BbSerialHeldOwner {
    owner: BbSerialDispatchOwner,
}

impl BbSerialDispatchOwner {
    /// A failed transition returns this same owner with its historical reports.
    pub(crate) fn into_hold(self) -> Result<BbSerialHeldOwner, (Self, DispatchError)> {
        let transition =
            self.inner
                .stop
                .state
                .compare_exchange(0, HELD, Ordering::SeqCst, Ordering::SeqCst);
        match transition {
            Ok(_) => Ok(BbSerialHeldOwner { owner: self }),
            Err(value) => {
                let error = if value & STOPPED != 0 {
                    DispatchError::Stopped
                } else {
                    DispatchError::HeldOrPending
                };
                Err((self, error))
            }
        }
    }
}

impl BbSerialHeldOwner {
    pub(crate) fn snapshot(&self) -> DispatchObservation {
        self.owner.snapshot()
    }
    pub(crate) fn stop_handle(&self) -> DispatchStop {
        self.owner.stop_handle()
    }
    pub(crate) fn receive_until(&mut self, deadline: Instant) -> SerialReceiveAttempt {
        receive_until(&mut self.owner.inner, true, deadline)
    }
    pub(crate) fn observe_transmitters_until(
        &mut self,
        deadline: Instant,
    ) -> HeldTransmitterAttempt {
        observe_owner(&mut self.owner, deadline)
    }
    /// Only an explicit successful transition can return a running owner. A
    /// failure returns the exact held owner for terminal observation/cleanup.
    /// The full controller must separately require every management/ASIC and
    /// actual task-join condition; this transition proves none of them itself.
    pub(crate) fn resume(self) -> Result<BbSerialDispatchOwner, (Self, DispatchError)> {
        if self
            .owner
            .inner
            .stop
            .state
            .compare_exchange(HELD, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err((self, DispatchError::Stopped));
        }
        Ok(self.owner)
    }
}

#[cfg(test)]
#[path = "uart_held_transmitter_tests.rs"]
mod tests;

impl BbSerialHeldOwner {
    pub(crate) fn cold_control_until(
        &mut self,
        chain: usize,
        control: &super::ColdControl,
        deadline: Instant,
    ) -> super::ColdControlAttempt {
        super::cold_control::control_held(&mut self.owner, chain, control, deadline)
    }
}
