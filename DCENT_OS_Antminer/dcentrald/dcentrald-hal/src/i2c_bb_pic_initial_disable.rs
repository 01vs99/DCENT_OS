//! One original initial-disable sweep, before ordinary BB initialization.
//! Reuses the unchanged fixed reserved BbPicDisable worker and raw observation.
//! Its own generation advances are counted; no token is recaptured or refreshed.
use super::*;
use crate::bb_management_owner::initial_disable::Admission;

#[derive(Clone, Debug)]
pub(crate) struct SlotObservation {
    pub factory_address: u8,
    pub native_slot: usize,
    pub pic_address: u8,
    pub caller_started_at: Option<Instant>,
    pub committed_generation: Option<u64>,
    pub barrier_committed_at: Option<Instant>,
    pub enqueued_at: Option<Instant>,
    /// Actual authority read after this exact worker's finalized reply. This
    /// is caller observation, not a new field fabricated in the old worker.
    pub generation_observed_after_worker_receipt: Option<u64>,
    pub caller_returned_at: Option<Instant>,
    pub caller_error: Option<String>,
    pub timely_receipt_at: Option<Instant>,
    pub worker: bb_pic_disable::WorkerObservation,
}

#[derive(Clone, Debug)]
pub(crate) struct Observation {
    pub retained_at: Instant,
    pub original_deadline: Instant,
    pub original_generation: u64,
    pub caller_started_at: Option<Instant>,
    pub caller_returned_at: Option<Instant>,
    pub caller_finalized_at: Option<Instant>,
    pub caller_unwound_at: Option<Instant>,
    pub caller_unwind: Option<String>,
    pub first_failure: Option<String>,
    pub slots: Vec<SlotObservation>,
}

#[derive(Clone)]
pub(crate) struct Attempt {
    observation: Arc<Mutex<Observation>>,
    workers: Vec<bb_pic_disable::Shared>,
    original_authority: Weak<I2cSafetyAuthority>,
    expected_final_generation: u64,
}

impl Attempt {
    fn lock(&self) -> std::sync::MutexGuard<'_, Observation> {
        self.observation.lock().unwrap_or_else(|poison| {
            let mut retained = poison.into_inner();
            retained
                .first_failure
                .get_or_insert_with(|| "initial-disable observation poisoned".into());
            retained
        })
    }

    pub(crate) fn snapshot(&self) -> Observation {
        let mut observed = self.lock().clone();
        for (slot, worker) in observed.slots.iter_mut().zip(&self.workers) {
            slot.worker = worker
                .lock()
                .unwrap_or_else(|poison| {
                    let mut retained = poison.into_inner();
                    retained.failure.get_or_insert_with(|| {
                        "initial-disable worker observation poisoned".into()
                    });
                    retained
                })
                .clone();
        }
        observed
    }

    pub(crate) fn worker_pending(&self) -> bool {
        self.snapshot()
            .slots
            .iter()
            .any(|slot| slot.enqueued_at.is_some() && slot.worker.worker_finalized_at.is_none())
    }

    /// Validate a genuinely new following-phase token against this original
    /// sweep. Neither this check nor its caller updates either generation.
    pub(super) fn matches_following_service(
        &self, handle: &I2cServiceHandle, token: &I2cServiceGenerationToken,
    ) -> bool {
        self.original_authority.upgrade().is_some_and(|original| {
            token.authority.upgrade().is_some_and(|fresh| {
                handle.bus == 0 && token.bus == 0
                    && Arc::ptr_eq(&original, &handle.safety)
                    && Arc::ptr_eq(&original, &fresh)
                    && token.generation == self.expected_final_generation
                    && token.is_current() && self.final_generation_current()
            })
        })
    }

    /// Read-only final-join guard, never a replacement generation token.
    pub(crate) fn final_generation_current(&self) -> bool {
        self.original_authority.upgrade().is_some_and(|authority| {
            authority.validate(
                I2cOperationIntent::KeepAlive,
                self.expected_final_generation,
            ) && authority.capture(I2cOperationIntent::KeepAlive).ok()
                == Some(self.expected_final_generation)
        })
    }
}

pub(crate) struct Prepared {
    handle: I2cServiceHandle,
    original_generation: I2cServiceGenerationToken,
    admission: Admission,
    attempt: Attempt,
    finished: bool,
}

fn failure(bus: u8, addr: u8, detail: impl Into<String>) -> HalError {
    HalError::I2cSafetySuperseded {
        bus,
        addr,
        detail: detail.into(),
    }
}

impl Prepared {
    pub(crate) fn new(handle: &I2cServiceHandle, admission: Admission) -> Result<Self> {
        admission
            .observe()
            .map_err(|why| failure(handle.bus, 0, why))?;
        if handle.bus != 0 || handle.safe_off_mailbox.is_none() {
            return Err(failure(
                handle.bus,
                0,
                "initial disable requires the original bus0 reserved service",
            ));
        }
        let original_generation = handle.capture_generation_token()?;
        let deadline = admission.deadline();
        let mut workers = Vec::new();
        let slots = admission
            .selected_addresses()
            .iter()
            .map(|address| {
                let native_slot = usize::from(*address - 0x50);
                let worker = bb_pic_disable::WorkerObservation {
                    deadline,
                    worker_started_at: None,
                    worker_returned_at: None,
                    worker_finalized_at: None,
                    steps: Vec::new(),
                    transport_completed_at: None,
                    failure: None,
                };
                workers.push(Arc::new(Mutex::new(worker.clone())));
                SlotObservation {
                    factory_address: *address,
                    native_slot,
                    pic_address: crate::bb_pic_application::native_pic_address(native_slot)
                        .expect("private original selected roster was checked"),
                    caller_started_at: None,
                    committed_generation: None,
                    barrier_committed_at: None,
                    enqueued_at: None,
                    generation_observed_after_worker_receipt: None,
                    caller_returned_at: None,
                    caller_error: None,
                    timely_receipt_at: None,
                    worker,
                }
            })
            .collect();
        let expected_final_generation = original_generation
            .generation
            .checked_add(workers.len() as u64)
            .ok_or_else(|| failure(handle.bus, 0, "initial-disable generation exhausted"))?;
        let attempt = Attempt {
            observation: Arc::new(Mutex::new(Observation {
                retained_at: Instant::now(),
                original_deadline: deadline,
                original_generation: original_generation.generation,
                caller_started_at: None,
                caller_returned_at: None,
                caller_finalized_at: None,
                caller_unwound_at: None,
                caller_unwind: None,
                first_failure: None,
                slots,
            })),
            workers,
            original_authority: Arc::downgrade(&handle.safety),
            expected_final_generation,
        };
        Ok(Self {
            handle: handle.clone(),
            original_generation,
            admission,
            attempt,
            finished: false,
        })
    }

    pub(crate) fn observation(&self) -> Attempt {
        self.attempt.clone()
    }

    fn expected_generation(&self, completed_barriers: usize) -> Result<u64> {
        self.original_generation
            .generation
            .checked_add(completed_barriers as u64)
            .ok_or_else(|| failure(self.handle.bus, 0, "initial-disable generation exhausted"))
    }

    fn require_original_generation(&self, completed_barriers: usize) -> Result<u64> {
        self.admission
            .observe()
            .map_err(|why| failure(self.handle.bus, 0, why))?;
        let authority = self
            .original_generation
            .authority
            .upgrade()
            .ok_or_else(|| {
                failure(
                    self.handle.bus,
                    0,
                    "original initial-disable service was dropped",
                )
            })?;
        let expected = self.expected_generation(completed_barriers)?;
        if self.original_generation.bus != self.handle.bus
            || !Arc::ptr_eq(&authority, &self.handle.safety)
            || !authority.validate(I2cOperationIntent::KeepAlive, expected)
            || authority
                .capture(I2cOperationIntent::KeepAlive)
                .map_err(|why| failure(self.handle.bus, 0, why))?
                != expected
        {
            return Err(failure(
                self.handle.bus,
                0,
                "initial-disable original generation changed outside its own sweep",
            ));
        }
        Ok(expected)
    }

    fn run_slot(&self, index: usize) -> Result<()> {
        let (addr, deadline) = {
            let mut retained = self.attempt.lock();
            retained.slots[index].caller_started_at = Some(Instant::now());
            (
                retained.slots[index].pic_address,
                retained.original_deadline,
            )
        };
        let result = (|| {
            let expected = self.require_original_generation(index)?;
            let next = self.expected_generation(index + 1)?;
            let mailbox = self
                .handle
                .safe_off_mailbox
                .as_ref()
                .ok_or_else(|| failure(0, addr, "original initial-disable mailbox absent"))?;
            let (reply_tx, reply_rx) = mpsc::sync_channel(1);
            {
                // Same publication lock as commit_pre_management_safe_off. The
                // compare_exchange counts only this sweep's own barrier; a
                // concurrent foreign SafeOff never becomes a refreshed token.
                let publication = self
                    .handle
                    .safety
                    .pic16_service_state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if publication.is_managed(addr) {
                    return Err(managed_pic16_address_error(0, addr));
                }
                self.require_original_generation(index)?;
                self.handle
                    .safety
                    .generation
                    .compare_exchange(expected, next, Ordering::SeqCst, Ordering::SeqCst)
                    .map_err(|_| {
                        failure(
                            0,
                            addr,
                            "initial-disable original generation raced another barrier",
                        )
                    })?;
                {
                    let mut retained = self.attempt.lock();
                    retained.slots[index].committed_generation = Some(next);
                    retained.slots[index].barrier_committed_at = Some(Instant::now());
                }
                // A terminal race may still admit harmless SafeOff; continuation
                // below must observe that fence and can never become normal work.
                let permit = I2cSafetyPermit {
                    authority: self.handle.safety.clone(),
                    intent: I2cOperationIntent::SafeOff,
                    generation: next,
                    scope: I2cPermitScope::Pic16PreManagementSafeOff { address: addr },
                };
                mailbox.enqueue_with_acceptance(
                    0,
                    addr,
                    I2cSafeOffKey::BbPicDisable {
                        addr,
                        attempt: Arc::as_ptr(&self.attempt.workers[index]) as usize,
                    },
                    I2cSafeOffOperation::BbPicDisable {
                        observation: self.attempt.workers[index].clone(),
                    },
                    permit,
                    I2cSafeOffWaiter::Unit(reply_tx),
                    || self.attempt.lock().slots[index].enqueued_at = Some(Instant::now()),
                )?;
            }
            match reply_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(result) => result?,
                Err(error) => {
                    return Err(failure(
                        0,
                        addr,
                        format!("initial-disable original receipt unavailable: {error}"),
                    ))
                }
            }
            let observed_generation = self.require_original_generation(index + 1)?;
            self.attempt.lock().slots[index].generation_observed_after_worker_receipt =
                Some(observed_generation);
            let worker = self.attempt.snapshot().slots[index].worker.clone();
            if worker.failure.is_some()
                || worker.transport_completed_at.is_none()
                || worker.worker_returned_at.is_none()
                || !worker.worker_finalized_at.is_some_and(|at| at < deadline)
                || Instant::now() >= deadline
            {
                return Err(failure(
                    0,
                    addr,
                    "initial-disable worker did not finalize within its original deadline",
                ));
            }
            Ok(())
        })();
        let mut retained = self.attempt.lock();
        let now = Instant::now();
        retained.slots[index].caller_returned_at = Some(now);
        match &result {
            Ok(()) if now < deadline => retained.slots[index].timely_receipt_at = Some(now),
            Ok(()) => {
                let error = failure(
                    0,
                    addr,
                    "initial-disable actual caller observation became late",
                );
                retained.slots[index].caller_error = Some(error.to_string());
                return Err(error);
            }
            Err(error) => retained.slots[index].caller_error = Some(error.to_string()),
        }
        result
    }

    pub(crate) fn run(mut self) {
        self.attempt.lock().caller_started_at = Some(Instant::now());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for index in 0..self.attempt.workers.len() {
                self.run_slot(index)?;
            }
            self.require_original_generation(self.attempt.workers.len())?;
            Ok::<(), HalError>(())
        }));
        let mut retained = self.attempt.lock();
        let returned = Instant::now();
        match result {
            Ok(result) => {
                retained.caller_returned_at = Some(returned);
                if let Err(error) = result {
                    retained
                        .first_failure
                        .get_or_insert_with(|| error.to_string());
                }
            }
            Err(payload) => {
                retained.caller_unwound_at = Some(returned);
                retained.caller_unwind = Some(
                    payload
                        .downcast_ref::<&str>()
                        .map(|s| (*s).into())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "non-string caller unwind".into()),
                );
                retained
                    .first_failure
                    .get_or_insert_with(|| "initial-disable caller unwound".into());
            }
        }
        if Instant::now() >= retained.original_deadline {
            retained.first_failure.get_or_insert_with(|| {
                "initial-disable caller finalized after original deadline".into()
            });
        }
        retained.caller_finalized_at = Some(Instant::now());
        let failed = retained.first_failure.is_some();
        drop(retained);
        if failed {
            self.admission
                .refuse("initial-disable original caller failed");
        }
        self.finished = true;
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if !self.finished {
            self.admission
                .refuse("initial-disable prepared caller abandoned or unwound");
            self.attempt.lock().first_failure.get_or_insert_with(|| {
                "initial-disable prepared caller abandoned or unwound".into()
            });
        }
    }
}
