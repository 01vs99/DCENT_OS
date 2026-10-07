//! Exact +30 byte completion and framed PIC/voltage application transactions.
//! No reset, jump, erase, EEPROM write, speculative parser flush, or retry.
use super::*;
use dcentrald_common::bm1396_pic::*;

#[path = "stock_bm1396_adapted_predecessor.rs"]
mod adapted_predecessor;
use adapted_predecessor::AdaptedPredecessor;

#[path = "stock_bm1396_reset.rs"]
mod reset;
pub use reset::{
    AdaptedStartupHealth, AdaptedStartupObservation, AdaptedStartupStage, ConditioningResetEvent,
    ConditioningResetObservation,
};

#[path = "stock_bm1396_preparation.rs"]
mod preparation;
pub use preparation::{ConditioningPreparationObservation, ConditioningPreparationStage};

#[path = "stock_bm1396_cold_pll.rs"]
mod cold_pll;
use cold_pll::PreparedColdAdmission;
pub use cold_pll::{
    ColdPllCommand, ColdPllObservation, ColdPllStage, ColdPllVoltagePlan, FinalPllObservation, NativePllObservation,
    FixedWorkControl, FixedWorkEvent, FixedWorkEvents, FixedWorkHealth, FixedWorkInbox,
};

#[path = "stock_bm1396_rail.rs"]
pub(super) mod rail;
pub use rail::{RailFrameObservation, RailSample, RailSnapshot};
#[path = "stock_bm1396_voltage.rs"]
mod voltage;
pub use voltage::{VoltageAttempt, VoltageStepObservation};
#[path = "stock_bm1396_supply.rs"]
mod supply;
pub use supply::SupplyTypeObservation;
#[path = "stock_bm1396_verifier.rs"]
mod verifier;
pub use verifier::{
    RailVerificationCheck, RailVerificationEvent, RailVerificationObservation, RailVerificationWait,
};

#[derive(Debug, Clone)]
pub struct PicReply {
    chain: u8,
    bytes: Vec<u8>,
    completed_at: Instant,
}
impl PicReply {
    pub fn chain(&self) -> u8 {
        self.chain
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
}

#[derive(Default)]
struct ApplicationState {
    supply_type: Option<SupplyTypeObservation>,
    versions: Vec<PicReply>,
    heartbeats: Vec<PicReply>,
    stable_rounds: u8,
    last_off: Vec<PicReply>,
    last_voltage: Option<CommandedVoltage>,
    rails: VecDeque<RailSnapshot>,
    next_rail: u64,
    voltage_attempts: VecDeque<VoltageAttempt>,
    next_voltage: u64,
    rail_verifications: VecDeque<RailVerificationObservation>,
    next_rail_verification: u64,
}

/// A complete accepted voltage reply is framing evidence, not measured rail
/// voltage; stock even accepts a reply DAC different from the request DAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandedVoltage {
    requested_cv: u16,
    dac: u8,
    response: [u8; 8],
    completed_at: Instant,
}
impl CommandedVoltage {
    pub fn requested_centivolts(&self) -> u16 {
        self.requested_cv
    }
    pub fn dac(&self) -> u8 {
        self.dac
    }
    pub fn response(&self) -> &[u8; 8] {
        &self.response
    }
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
}

pub struct PicApplication<H: Hardware> {
    owner: Arc<Transport<H>>,
    state: Mutex<ApplicationState>,
    // Serializes voltage mutation and rail sampling, while heartbeat frames
    // can still acquire the physical management lane between sampled chains.
    voltage_sequence: Mutex<()>,
    cold_pll: Mutex<Option<ColdPllObservation>>,
    prepared_cold: Mutex<Option<PreparedColdAdmission<H>>>,
    final_pll: Mutex<Option<ColdPllObservation>>,
    prepared_final: Mutex<Option<PreparedColdAdmission<H>>>,
    conditioning_reset: Mutex<Option<ConditioningResetObservation>>,
    adapted_reset: Mutex<Option<ConditioningResetObservation>>,
    adapted_startup: Mutex<Option<AdaptedStartupObservation>>,
    conditioning_preparation: Mutex<Option<ConditioningPreparationObservation>>,
}

/// A private physical mutex guard plus its exact application's transport seal.
/// Nested helpers borrow this lease instead of taking the logical lock twice.
struct VoltageLease<'a> {
    _guard: MutexGuard<'a, ()>,
    issuer: &'a Arc<()>,
}

impl<H: Hardware> PicApplication<H> {
    pub(super) fn same_owner(&self, owner: &Arc<Transport<H>>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }
    fn voltage_lease(&self, deadline: Instant) -> Result<VoltageLease<'_>, String> {
        Ok(VoltageLease {
            _guard: self.owner.lock(&self.voltage_sequence, deadline, false)?,
            issuer: &self.owner.identity,
        })
    }

    /// Only the enclosing ASIC phase uses this after its counted PIC task exits.
    /// A competing voltage transaction may still own the logical lease, so the
    /// caller services its retained FIFO/thermal/source custody between attempts.
    fn voltage_lease_serviced(
        &self,
        deadline: Instant,
        mut service: impl FnMut() -> Result<(), String>,
    ) -> Result<VoltageLease<'_>, String> {
        let mut waited = false;
        loop {
            self.owner.check(deadline, false)?;
            match self.voltage_sequence.try_lock() {
                Ok(guard) => {
                    let lease = VoltageLease {
                        _guard: guard,
                        issuer: &self.owner.identity,
                    };
                    // Preserve bytes arriving during the last actual wait tick
                    // before the caller's lineage check and full final guard.
                    if waited {
                        service()?;
                    }
                    return Ok(lease);
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err("BM1396 logical voltage lease poisoned".into())
                }
                Err(TryLockError::WouldBlock) => {
                    service()?;
                    waited = true;
                    self.owner
                        .delay(Duration::from_millis(1), deadline, false)?;
                }
            }
        }
    }

    fn require_voltage_lease(&self, lease: &VoltageLease<'_>) -> Result<(), String> {
        if Arc::ptr_eq(lease.issuer, &self.owner.identity) {
            Ok(())
        } else {
            Err("BM1396 logical voltage lease belongs to another owner".into())
        }
    }

    /// Source enable and its complete settle interval precede the application's
    /// first voltage attempt. Hold the same logical lease as voltage workers;
    /// leave the physical management lane available for supervised heartbeats.
    pub(super) fn with_source_start_voltage_custody<T>(
        &self,
        deadline: Instant,
        start: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let _lease = self.voltage_lease(deadline)?;
        {
            let state = self.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
            // The monotonic counter survives acknowledgment of retained
            // attempts and also catches a failed or incomplete first command.
            if state.next_voltage != 0
                || state.last_voltage.is_some()
                || !state.voltage_attempts.is_empty()
            {
                return Err("T17e source-low must precede every voltage attempt".into());
            }
        }
        start()
    }

    /// Synchronous ownership claim, before any asynchronous observation. The
    /// caller retains this handle even if a later observation waiter is dropped.
    pub fn claim(owner: Arc<Transport<H>>) -> Result<Arc<Self>, String> {
        if owner.is_terminal() {
            return Err("BM1396 PIC claim after terminal".into());
        }
        owner
            .pic_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "BM1396 PIC application already has an owner")?;
        Ok(Arc::new(Self {
            owner,
            state: Mutex::new(ApplicationState::default()),
            voltage_sequence: Mutex::new(()),
            cold_pll: Mutex::new(None),
            prepared_cold: Mutex::new(None),
            final_pll: Mutex::new(None),
            prepared_final: Mutex::new(None),
            conditioning_reset: Mutex::new(None),
            adapted_reset: Mutex::new(None),
            adapted_startup: Mutex::new(None),
            conditioning_preparation: Mutex::new(None),
        }))
    }

    pub fn version_observations(&self) -> Result<Vec<PicReply>, String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?
            .versions
            .clone())
    }
    pub fn last_off_observations(&self) -> Result<Vec<PicReply>, String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?
            .last_off
            .clone())
    }
    pub fn last_commanded_voltage(&self) -> Result<Option<CommandedVoltage>, String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?
            .last_voltage)
    }

    pub async fn observe_versions(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<Vec<PicReply>, String> {
        let app = Arc::clone(self);
        self.owner
            .worker(deadline, false, move |owner| {
                let _lane = owner.lock(&owner.management, deadline, false)?;
                if !app
                    .state
                    .lock()
                    .map_err(|_| "BM1396 PIC state poisoned")?
                    .versions
                    .is_empty()
                {
                    return Err("BM1396 application version observation already started".into());
                }
                for &chain in &owner.chains {
                    let bytes = owner.pic_transaction_locked(
                        chain,
                        &bm1396_pic_version_frame(),
                        5,
                        0x17,
                        false,
                        false,
                        deadline,
                    )?;
                    let reply = PicReply {
                        chain,
                        bytes,
                        completed_at: Instant::now(),
                    };
                    // Retain complete replies even if later chains fail/cancel.
                    app.state
                        .lock()
                        .map_err(|_| "BM1396 PIC state poisoned")?
                        .versions
                        .push(reply);
                }
                app.version_observations()
            })
            .await
    }

    pub async fn heartbeat_round(self: &Arc<Self>, deadline: Instant) -> Result<(), String> {
        let app = Arc::clone(self);
        self.owner
            .worker(deadline, false, move |owner| {
                let _lane = owner.lock(&owner.management, deadline, false)?;
                if app
                    .state
                    .lock()
                    .map_err(|_| "BM1396 PIC state poisoned")?
                    .versions
                    .len()
                    != owner.chains.len()
                {
                    return Err(
                        "BM1396 heartbeat requires complete retained application observations"
                            .into(),
                    );
                }
                for &chain in &owner.chains {
                    let bytes = owner.pic_transaction_locked(
                        chain,
                        &bm1396_pic_heartbeat_frame(),
                        6,
                        0x16,
                        false,
                        true,
                        deadline,
                    )?;
                    let mut state = app.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
                    state.heartbeats.retain(|reply| reply.chain != chain);
                    state.heartbeats.push(PicReply {
                        chain,
                        bytes,
                        completed_at: Instant::now(),
                    });
                    drop(state);
                    owner.delay(Duration::from_millis(10), deadline, false)?;
                }
                let mut state = app.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
                state.stable_rounds = state.stable_rounds.saturating_add(1);
                Ok(())
            })
            .await
    }

    /// Rechecked at each energizing first byte after taking management custody.
    /// Five whole successful rounds and fresh per-chain samples are necessary;
    /// the composed runtime still owes independent cutoff/fan/thermal policy.
    pub(super) fn require_health(&self, deadline: Instant) -> Result<(), String> {
        self.owner.check(deadline, false)?;
        let state = self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC health poisoned")?;
        if state.versions.len() != self.owner.chains.len() || state.stable_rounds < 5 {
            return Err("BM1396 requires complete application observations and five stable heartbeat rounds".into());
        }
        // The dsPIC degraded-application marker is never admitted for voltage.
        // Raw version replies remain available; no generic PIC recovery runs.
        if self.owner.model == Model::S17e
            && state.versions.iter().any(|v| v.bytes.get(2) == Some(&0x86))
        {
            return Err("BM1396 S17e degraded dsPIC application 0x86 is not admitted".into());
        }
        for &chain in &self.owner.chains {
            let heartbeat = state
                .heartbeats
                .iter()
                .find(|h| h.chain == chain)
                .ok_or("BM1396 chain heartbeat missing")?;
            if heartbeat.completed_at.elapsed() >= Duration::from_secs(15) {
                return Err("BM1396 per-chain heartbeat is stale".into());
            }
        }
        Ok(())
    }

    /// Fresh whole-population heartbeat health from this retained application.
    /// Read-only runtime supervision; this does not energize or issue authority.
    pub fn check_health(&self, deadline: Instant) -> Result<(), String> {
        self.require_health(deadline)
    }

    pub async fn enable_chain(
        self: &Arc<Self>,
        chain: u8,
        deadline: Instant,
    ) -> Result<PicReply, String> {
        self.owner.chain(chain)?;
        let app = Arc::clone(self);
        self.owner
            .worker(deadline, false, move |owner| {
                let _lane = owner.lock(&owner.management, deadline, false)?;
                app.require_health(deadline)?;
                let bytes = owner.pic_transaction_locked(
                    chain,
                    &bm1396_pic_rail_enable_frame(),
                    2,
                    0x15,
                    false,
                    false,
                    deadline,
                )?;
                Ok(PicReply {
                    chain,
                    bytes,
                    completed_at: Instant::now(),
                })
            })
            .await
    }

    /// Source fixed disable is available before qualification and after terminal,
    /// but never over an incomplete management frame. It is not a GPIO rail cut.
    pub async fn disable_all(
        self: &Arc<Self>,
        deadline: Instant,
        terminal: bool,
    ) -> Result<Vec<PicReply>, String> {
        if terminal {
            self.owner.begin_terminal();
        }
        let app = Arc::clone(self);
        self.owner
            .worker(deadline, terminal, move |owner| {
                let _lane = owner.lock(&owner.management, deadline, terminal)?;
                let mut replies = Vec::new();
                for &chain in &owner.chains {
                    let bytes = owner.pic_transaction_locked(
                        chain,
                        &bm1396_pic_rail_disable_frame(),
                        2,
                        0x15,
                        terminal,
                        false,
                        deadline,
                    )?;
                    let reply = PicReply {
                        chain,
                        bytes,
                        completed_at: Instant::now(),
                    };
                    app.state
                        .lock()
                        .map_err(|_| "BM1396 PIC state poisoned")?
                        .last_off
                        .push(reply.clone());
                    replies.push(reply);
                }
                Ok(replies)
            })
            .await
    }

    /// Exact software conversion inside the original 1800..2100 cV envelope.
    /// This is not a declaration of physical safe limits for every board SKU;
    /// the source-profile ramp and independent physical qualification are separate.
    pub async fn command_voltage_cv(
        self: &Arc<Self>,
        requested_cv: u16,
        deadline: Instant,
    ) -> Result<CommandedVoltage, String> {
        self.command_voltage_retained(requested_cv, false, deadline)
            .await
    }
}

impl<H: Hardware> Transport<H> {
    pub(super) fn management_byte_locked(
        &self,
        word: u32,
        deadline: Instant,
        terminal_allowed: bool,
    ) -> Result<u8, String> {
        self.check(deadline, terminal_allowed)?;
        if self.management_fault.load(Ordering::SeqCst) {
            return Err("BM1396 management portal unresolved".into());
        }
        // Source clears bits31..30 on its ONE store. Bit31 SET is completion;
        // unlike BC, a clear bit31 is still busy. Bit30 semantics are unproved.
        let mut fault = FaultGuard::new(&self.management_fault, &self.terminal);
        self.store(0x30, word & !0xc000_0000, deadline, terminal_allowed)?;
        for poll in 0..102 {
            self.check(deadline, terminal_allowed)?;
            let response = self.hardware.read(0x30)?;
            if response & BUSY != 0 {
                // Complete wire-byte consumption is retained before a possibly
                // late final-read deadline failure is reported to the frame.
                fault.complete();
                // The frame must first record this consumed byte. Its next
                // operation checks the deadline, or its final-byte path marks
                // complete framing before reporting the elapsed deadline.
                return Ok(response as u8);
            }
            if poll != 101 {
                self.delay(Duration::from_micros(5000), deadline, terminal_allowed)?;
            }
        }
        Err("BM1396 management byte exhausted 102 original polls".into())
    }

    fn pic_transaction_locked(
        &self,
        chain: u8,
        request: &[u8],
        response_len: usize,
        opcode: u8,
        terminal_off: bool,
        heartbeat: bool,
        deadline: Instant,
    ) -> Result<Vec<u8>, String> {
        self.chain(chain)?;
        self.check(deadline, terminal_off)?;
        if self.management_fault.load(Ordering::SeqCst) {
            return Err("BM1396 management portal unresolved".into());
        }
        // Only the already-admitted fixed heartbeat may finish after terminal.
        // No following frame inherits this allowance or refreshes health.
        let finish_allowed = terminal_off || heartbeat;
        let mut fault = FaultGuard::new(&self.management_fault, &self.terminal);
        let prefix = 0x0040_0000 | (u32::from(chain & 7) << 16);
        for &byte in request {
            self.management_byte_locked(prefix | u32::from(byte), deadline, finish_allowed)?;
        }
        self.delay(Duration::from_millis(500), deadline, finish_allowed)?;
        let mut reply = Vec::with_capacity(response_len);
        for _ in 0..response_len {
            reply.push(self.management_byte_locked(
                prefix | 0x0200_0000,
                deadline,
                finish_allowed,
            )?);
        }
        fault.complete();
        self.check(deadline, finish_allowed)?;
        self.delay(Duration::from_millis(500), deadline, finish_allowed)?;
        if !bm1396_pic_response_accepted(&reply, response_len as u8, opcode) {
            return Err(format!(
                "BM1396 PIC chain{chain} opcode{opcode:x} response rejected"
            ));
        }
        self.check(deadline, terminal_off)?;
        Ok(reply)
    }
}

#[cfg(test)]
#[path = "stock_bm1396_final_pll_fixture.rs"]
mod final_pll_fixture;
