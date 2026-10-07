//! Consecutive actual PIC rail populations under one logical voltage lease.
//! Original20 transition cases:30 iterations, at most60 complete populations.
use super::*;

const CAPACITY: usize = 16;
const ITERATIONS: u8 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RailVerificationEvent {
    Check(u8),
    Wait(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub struct RailVerificationCheck {
    iteration: u8,
    second: bool,
    snapshot: RailSnapshot,
}
impl RailVerificationCheck {
    /// Zero-based original failed-iteration counter.
    pub fn iteration(&self) -> u8 {
        self.iteration
    }
    pub fn is_second_check(&self) -> bool {
        self.second
    }
    pub fn snapshot(&self) -> &RailSnapshot {
        &self.snapshot
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RailVerificationWait {
    iteration: u8,
    first_passed: bool,
    started_at: Instant,
    completed_at: Option<Instant>,
}
impl RailVerificationWait {
    pub fn iteration(&self) -> u8 {
        self.iteration
    }
    /// True is the gap between a passing first check and its second check.
    /// False is the source wait after a failed first or second check.
    pub fn follows_passing_first_check(&self) -> bool {
        self.first_passed
    }
    pub fn started_at(&self) -> Instant {
        self.started_at
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RailVerificationObservation {
    issuer: Arc<()>,
    sequence: u64,
    commanded: CommandedVoltage,
    checks: Vec<RailVerificationCheck>,
    waits: Vec<RailVerificationWait>,
    events: Vec<RailVerificationEvent>,
    passed: Option<bool>,
    completed_at: Option<Instant>,
}
impl RailVerificationObservation {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn commanded_voltage(&self) -> CommandedVoltage {
        self.commanded
    }
    pub fn checks(&self) -> &[RailVerificationCheck] {
        &self.checks
    }
    pub fn waits(&self) -> &[RailVerificationWait] {
        &self.waits
    }
    /// Exact custody order; indexes refer to this observation's bounded arrays.
    pub fn events(&self) -> &[RailVerificationEvent] {
        &self.events
    }
    /// None preserves incomplete physical work; Some(false) is an exhausted
    /// complete source verification loop and is terminal, never admission.
    pub fn passed(&self) -> Option<bool> {
        self.passed
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
}

impl<H: Hardware> PicApplication<H> {
    pub fn rail_verifications(&self) -> Result<Vec<RailVerificationObservation>, String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?
            .rail_verifications
            .iter()
            .cloned()
            .collect())
    }

    pub fn acknowledge_rail_verification(
        &self,
        observation: &RailVerificationObservation,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?;
        if !Arc::ptr_eq(&observation.issuer, &self.owner.identity)
            || observation.completed_at.is_none()
            || state.rail_verifications.front() != Some(observation)
        {
            return Err("BM1396 rail verification acknowledgment requires oldest exact completed owner observation".into());
        }
        state.rail_verifications.pop_front();
        Ok(())
    }

    /// Two actual within-target populations separated by the source1s wait.
    /// Serializes voltage throughout; physical management is available between
    /// chains and during waits for the independent heartbeat owner. The caller
    /// must continue ASIC/thermal receive service during this PIC-only worker.
    pub async fn verify_commanded_rail_voltages(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<RailVerificationObservation, String> {
        let app = self.clone();
        self.owner
            .worker(deadline, false, move |_owner| {
                let lease = app.voltage_lease(deadline)?;
                app.verify_rail_locked(&lease, deadline)
            })
            .await
    }

    pub(super) fn verify_rail_locked(
        &self,
        lease: &VoltageLease<'_>,
        deadline: Instant,
    ) -> Result<RailVerificationObservation, String> {
        self.require_voltage_lease(lease)?;
        self.require_health(deadline)?;
        self.owner.query_presence(deadline)?;
        let sequence = {
            let mut state = self.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
            if !state.rails.is_empty() {
                return Err(
                    "BM1396 rail verifier requires prior snapshot custody acknowledged".into(),
                );
            }
            if state.rail_verifications.len() >= CAPACITY {
                return Err("BM1396 retained rail verification capacity exhausted".into());
            }
            let commanded = state
                .last_voltage
                .ok_or("BM1396 verifier requires retained completed voltage command")?;
            let sequence = state.next_rail_verification;
            state.next_rail_verification = sequence
                .checked_add(1)
                .ok_or("BM1396 rail verification sequence exhausted")?;
            state
                .rail_verifications
                .push_back(RailVerificationObservation {
                    issuer: self.owner.identity.clone(),
                    sequence,
                    commanded,
                    checks: Vec::with_capacity(60),
                    waits: Vec::with_capacity(60),
                    events: Vec::with_capacity(120),
                    passed: None,
                    completed_at: None,
                });
            sequence
        };
        for iteration in 0..ITERATIONS {
            if self.verification_check(lease, sequence, iteration, false, deadline)? {
                self.verification_wait(sequence, iteration, true, deadline)?;
                if self.verification_check(lease, sequence, iteration, true, deadline)? {
                    return self.finish_verification(sequence, true, deadline);
                }
            }
            self.verification_wait(sequence, iteration, false, deadline)?;
        }
        self.finish_verification(sequence, false, deadline)?;
        Err("BM1396 rail verification exhausted30 original iterations".into())
    }

    fn verification_check(
        &self,
        lease: &VoltageLease<'_>,
        sequence: u64,
        iteration: u8,
        second: bool,
        deadline: Instant,
    ) -> Result<bool, String> {
        let snapshot = self.acquire_rail_locked(lease, deadline)?;
        let passed = snapshot
            .all_within_target()
            .ok_or("BM1396 verifier received incomplete rail predicate")?;
        // Atomic exact-owner transfer into the verifier: no completed sample is
        // discarded to make room in the16-entry standalone acquisition queue.
        let mut state = self.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
        let observation = state
            .rail_verifications
            .back()
            .filter(|item| item.sequence == sequence)
            .ok_or("BM1396 rail verification custody lost")?;
        if snapshot.completed_at().is_none()
            || snapshot.commanded_voltage() != observation.commanded
            || state.rails.front() != Some(&snapshot)
            || observation.checks.len() >= 60
        {
            return Err(
                "BM1396 verifier cannot transfer changed, foreign or incomplete rail snapshot"
                    .into(),
            );
        }
        let snapshot = state.rails.pop_front().expect("checked front");
        let observation = state
            .rail_verifications
            .back_mut()
            .expect("checked sequence");
        observation
            .events
            .push(RailVerificationEvent::Check(observation.checks.len() as u8));
        observation.checks.push(RailVerificationCheck {
            iteration,
            second,
            snapshot,
        });
        Ok(passed)
    }

    fn verification_wait(
        &self,
        sequence: u64,
        iteration: u8,
        first_passed: bool,
        deadline: Instant,
    ) -> Result<(), String> {
        self.require_health(deadline)?;
        self.owner.query_presence(deadline)?;
        {
            let mut state = self.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
            let observation = state
                .rail_verifications
                .back_mut()
                .filter(|item| item.sequence == sequence)
                .ok_or("BM1396 rail verification custody lost")?;
            if observation.waits.len() >= 60 {
                return Err("BM1396 verification wait capacity exhausted".into());
            }
            observation
                .events
                .push(RailVerificationEvent::Wait(observation.waits.len() as u8));
            observation.waits.push(RailVerificationWait {
                iteration,
                first_passed,
                started_at: Instant::now(),
                completed_at: None,
            });
        }
        self.owner.delay(Duration::from_secs(1), deadline, false)?;
        self.require_health(deadline)?;
        self.owner.query_presence(deadline)?;
        let mut state = self.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
        let wait = state
            .rail_verifications
            .back_mut()
            .filter(|item| item.sequence == sequence)
            .and_then(|item| item.waits.last_mut())
            .ok_or("BM1396 verification wait custody lost")?;
        wait.completed_at = Some(Instant::now());
        Ok(())
    }

    fn finish_verification(
        &self,
        sequence: u64,
        passed: bool,
        deadline: Instant,
    ) -> Result<RailVerificationObservation, String> {
        self.require_health(deadline)?;
        self.owner.query_presence(deadline)?;
        let mut state = self.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
        let commanded = state.last_voltage;
        let observation = state
            .rail_verifications
            .back_mut()
            .filter(|item| item.sequence == sequence)
            .ok_or("BM1396 rail verification custody lost")?;
        if commanded != Some(observation.commanded) {
            return Err(
                "BM1396 commanded voltage changed inside logical verification lease".into(),
            );
        }
        observation.passed = Some(passed);
        observation.completed_at = Some(Instant::now());
        Ok(observation.clone())
    }
}
