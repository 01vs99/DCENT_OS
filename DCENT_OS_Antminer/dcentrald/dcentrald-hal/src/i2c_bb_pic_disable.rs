//! Fixed original BB fw89 PIC-disable request on the reserved SafeOff worker.
//! Original initializer source: held ELF 4af5f0, request55aa051500001a,
//! two one-byte reads, 50/20/20/20ms waits (r09 source-v1 receipt).
//! Reply semantics were not validated by that original. Raw data and transport
//! completion below deliberately do not assert an ACK or physical rail OFF.
use super::*;

const REQUEST: [u8; 7] = [0x55, 0xaa, 5, 0x15, 0, 0, 0x1a];

#[derive(Clone, Debug)]
pub(crate) enum Operation {
    SelectSlave,
    WriteDisable,
    ReadReply,
    Wait(Duration),
}

#[derive(Clone, Debug)]
pub(crate) struct Step {
    pub operation: Operation,
    pub started_at: Instant,
    pub returned_at: Option<Instant>,
    pub recorded_at: Option<Instant>,
    pub returned_bytes: Option<Vec<u8>>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct WorkerObservation {
    pub deadline: Instant,
    pub worker_started_at: Option<Instant>,
    pub worker_returned_at: Option<Instant>,
    pub worker_finalized_at: Option<Instant>,
    pub steps: Vec<Step>,
    pub transport_completed_at: Option<Instant>,
    pub failure: Option<String>,
}

pub(super) type Shared = Arc<Mutex<WorkerObservation>>;

/// The original retained observation remains live if a started kernel call
/// outlives the caller. A later snapshot cannot promote that caller timeout.
pub(crate) struct Attempt {
    pub native_slot: usize,
    pub pic_address: Option<u8>,
    pub deadline: Instant,
    pub caller_started_at: Instant,
    pub caller_returned_at: Option<Instant>,
    pub enqueued: bool,
    pub timely_receipt_at: Option<Instant>,
    pub failure: Option<String>,
    shared: Shared,
}

impl Attempt {
    pub(crate) fn worker_snapshot(&self) -> WorkerObservation {
        lock(&self.shared).clone()
    }
}

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, WorkerObservation> {
    shared.lock().unwrap_or_else(|poison| {
        let mut state = poison.into_inner();
        state
            .failure
            .get_or_insert_with(|| "BB disable observation poisoned".into());
        state
    })
}

fn error(bus: u8, addr: u8, reason: impl Into<String>) -> HalError {
    HalError::I2cSafeOffOutcomeUnknown {
        bus,
        addr,
        detail: reason.into(),
    }
}

fn check_time(shared: &Shared, bus: u8, addr: u8) -> Result<()> {
    let state = lock(shared);
    if state.failure.is_some() || Instant::now() >= state.deadline {
        return Err(error(
            bus,
            addr,
            "BB disable original worker deadline elapsed or observation failed",
        ));
    }
    Ok(())
}

fn step(
    shared: &Shared,
    bus: u8,
    addr: u8,
    operation: Operation,
    perform: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<()> {
    let index = {
        let mut state = lock(shared);
        let now = Instant::now();
        if state.failure.is_some() || now >= state.deadline {
            return Err(error(
                bus,
                addr,
                "BB disable expired before original worker operation",
            ));
        }
        let index = state.steps.len();
        state.steps.push(Step {
            operation,
            started_at: now,
            returned_at: None,
            recorded_at: None,
            returned_bytes: None,
            error: None,
        });
        index
    };
    let result = perform();
    let returned_at = Instant::now();
    let mut state = lock(shared);
    let now = Instant::now();
    let row = &mut state.steps[index];
    row.returned_at = Some(returned_at);
    row.recorded_at = Some(now);
    match &result {
        Ok(bytes) => row.returned_bytes = Some(bytes.clone()),
        Err(problem) => row.error = Some(problem.to_string()),
    }
    result?;
    if now >= state.deadline || state.failure.is_some() {
        return Err(error(
            bus,
            addr,
            "BB disable original worker operation returned too late",
        ));
    }
    Ok(())
}

fn wait(shared: &Shared, bus: u8, addr: u8, duration: Duration) -> Result<()> {
    step(shared, bus, addr, Operation::Wait(duration), || {
        let remaining = lock(shared)
            .deadline
            .saturating_duration_since(Instant::now());
        std::thread::sleep(duration.min(remaining));
        Ok(Vec::new())
    })
}

pub(super) fn execute(
    i2c: &mut I2cBus,
    addr: u8,
    permit: &I2cSafetyPermit,
    shared: &Shared,
) -> Result<()> {
    {
        let mut state = lock(shared);
        let now = Instant::now();
        if state.worker_started_at.is_some() {
            return Err(error(
                i2c.bus,
                addr,
                "BB disable worker must not replay the original attempt",
            ));
        }
        state.worker_started_at = Some(now);
    }
    let bus = i2c.bus;
    let result = (|| {
        check_time(shared, bus, addr)?;
        // The exact reserved permit spans this indivisible worker plan. No
        // normal request, parser flush or transport retry is inserted.
        let _stage = permit.begin_stage(bus, addr, "fixed BB reserved PIC disable")?;
        step(shared, bus, addr, Operation::SelectSlave, || {
            i2c.set_slave(addr)?;
            Ok(Vec::new())
        })?;
        step(shared, bus, addr, Operation::WriteDisable, || {
            i2c.write_exact(&REQUEST, "fixed BB PIC disable")?;
            Ok(Vec::new())
        })?;
        wait(shared, bus, addr, Duration::from_millis(50))?;
        for _ in 0..2 {
            step(shared, bus, addr, Operation::ReadReply, || {
                let mut raw = [0u8; 1];
                let count = i2c.read(&mut raw)?;
                if count > raw.len() {
                    return Err(error(
                        bus,
                        addr,
                        "BB disable backend returned an impossible read length",
                    ));
                }
                // A short successful read is retained as empty, then refused.
                Ok(raw[..count].to_vec())
            })?;
            if lock(shared)
                .steps
                .last()
                .unwrap()
                .returned_bytes
                .as_ref()
                .is_none_or(|bytes| bytes.len() != 1)
            {
                return Err(error(bus, addr, "BB disable short reply read"));
            }
            wait(shared, bus, addr, Duration::from_millis(20))?;
        }
        wait(shared, bus, addr, Duration::from_millis(20))?;
        Ok(())
    })();
    let mut state = lock(shared);
    let now = Instant::now();
    state.worker_returned_at = Some(now);
    match result {
        Ok(()) if now < state.deadline && state.failure.is_none() => {
            state.transport_completed_at = Some(now);
            Ok(())
        }
        Ok(()) => {
            state.failure.get_or_insert_with(|| {
                "BB disable final worker completion exceeded original deadline".into()
            });
            Err(error(bus, addr, state.failure.clone().unwrap()))
        }
        Err(problem) => {
            state.failure.get_or_insert_with(|| problem.to_string());
            Err(problem)
        }
    }
}

pub(super) fn finalized(shared: &Shared, failure: Option<&str>) {
    let mut state = lock(shared);
    state.worker_finalized_at.get_or_insert_with(Instant::now);
    if let Some(failure) = failure {
        state.failure.get_or_insert_with(|| failure.into());
    }
}

impl I2cServiceHandle {
    /// Fixed private native0..2/bus0 SafeOff operation. No caller frame, intent,
    /// arbitrary address, recovery/JUMP or generic read privilege is accepted.
    pub(crate) fn disable_bb_pic_at(&self, native_slot: usize, deadline: Instant) -> Attempt {
        let shared = Arc::new(Mutex::new(WorkerObservation {
            deadline,
            worker_started_at: None,
            worker_returned_at: None,
            worker_finalized_at: None,
            steps: Vec::new(),
            transport_completed_at: None,
            failure: None,
        }));
        let mut attempt = Attempt {
            native_slot,
            pic_address: crate::bb_pic_application::native_pic_address(native_slot),
            deadline,
            caller_started_at: Instant::now(),
            caller_returned_at: None,
            enqueued: false,
            timely_receipt_at: None,
            failure: None,
            shared: shared.clone(),
        };
        let result = (|| {
            let addr = attempt
                .pic_address
                .ok_or_else(|| error(self.bus, 0, "BB disable requires native slot0..2"))?;
            if self.bus != 0 {
                return Err(error(self.bus, addr, "BB disable requires original bus0"));
            }
            check_time(&shared, self.bus, addr)?;
            let mailbox = self.safe_off_mailbox.as_ref().ok_or_else(|| {
                error(
                    self.bus,
                    addr,
                    "BB disable requires original reserved worker mailbox",
                )
            })?;
            let (reply_tx, reply_rx) = mpsc::sync_channel(1);
            self.commit_pre_management_safe_off(addr, |permit| {
                mailbox.enqueue(
                    self.bus,
                    addr,
                    I2cSafeOffKey::BbPicDisable {
                        addr,
                        attempt: Arc::as_ptr(&shared) as usize,
                    },
                    I2cSafeOffOperation::BbPicDisable {
                        observation: shared.clone(),
                    },
                    permit,
                    I2cSafeOffWaiter::Unit(reply_tx),
                )
            })?;
            attempt.enqueued = true;
            let remaining = deadline.saturating_duration_since(Instant::now());
            match reply_rx.recv_timeout(remaining) {
                Ok(result) => result,
                Err(_) => Err(error(self.bus, addr, "BB disable receipt unavailable within original deadline; retain original attempt and worker, do not resubmit")),
            }
        })();
        let now = Instant::now();
        attempt.caller_returned_at = Some(now);
        match result {
            Ok(()) if now < deadline => attempt.timely_receipt_at = Some(now),
            Ok(()) => {
                attempt.failure = Some("BB disable receipt returned after original deadline".into())
            }
            Err(problem) => attempt.failure = Some(problem.to_string()),
        }
        attempt
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "i2c_bb_pic_disable_tests.rs"]
mod tests;
