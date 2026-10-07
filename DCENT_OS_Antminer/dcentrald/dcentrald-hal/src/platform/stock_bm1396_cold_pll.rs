//! Model-specific source PLL composition with continuous same-owner FIFO custody.
//! S17e consumes its actual per-chip factory records on the fixed Baseline pass;
//! T17e retains its cold300 conditioning and distinct final Adapted pass.
use super::*;
use dcentrald_common::bm1396_auto_adapt_voltage::{
    plan_bm1396_auto_adapt_voltage, Bm1396AutoAdaptProfile, Bm1396AutoAdaptVoltagePlan,
};
use dcentrald_common::bm1396_contract::bm1396_write_register_frame;
use dcentrald_common::bm1396_lifecycle::Bm1396FirmwareRelease;
use dcentrald_common::bm1396_s17e_factory::{
    self as s17e_factory, FactoryPllCommand, FactoryPllStage,
};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};

/// Private binding captured under the same ASIC owner; no public fabricated
/// receipt can supply this preparation or its physical source line.
pub(super) struct PreparedColdAdmission<H: Hardware> {
    reset_word: u32,
    higher_command: CommandedVoltage,
    next_voltage: u64,
    epoch: u64,
    line: Arc<PowerLine<H>>,
    cutoff_c: i16,
    thermal: ThermalSnapshot,
    adapted: Option<AdaptedStartupObservation>,
}

#[path = "stock_bm1396_final_pll.rs"]
mod final_pll;
pub use final_pll::{
    FinalPllObservation, FixedWorkControl, FixedWorkEvent, FixedWorkEvents, FixedWorkHealth,
    FixedWorkInbox, NativePllObservation,
};

const STAGES: [(u16, u32); 5] = [
    (60, 0x40a8_0275),
    (75, 0x40a8_0274),
    (100, 0x40a8_0273),
    (150, 0x40a8_0272),
    (300, 0x40a8_0271),
];
const THERMAL_CAPACITY: usize = 1024;
const THERMAL_RECORD_CAPACITY: usize = 65_536;
const PLANS_PER_STAGE: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColdPllCommand {
    chain: u8,
    chip: Option<u8>,
    value: u32,
    completed_at: Option<Instant>,
}
impl ColdPllCommand {
    pub fn chain(&self) -> u8 {
        self.chain
    }
    pub fn chip_ordinal(&self) -> Option<u8> {
        self.chip
    }
    pub fn register_value(&self) -> u32 {
        self.value
    }
    /// Portal completion only; neither PLL lock nor ASIC application readback.
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ColdPllVoltagePlan {
    thermal_sequence: u64,
    plan: Bm1396AutoAdaptVoltagePlan,
    attempt: Option<VoltageAttempt>,
    rail_verification: Option<RailVerificationObservation>,
}
impl ColdPllVoltagePlan {
    pub fn thermal_sequence(&self) -> u64 {
        self.thermal_sequence
    }
    pub fn plan(&self) -> &Bm1396AutoAdaptVoltagePlan {
        &self.plan
    }
    pub fn voltage_attempt(&self) -> Option<&VoltageAttempt> {
        self.attempt.as_ref()
    }
    pub fn rail_verification(&self) -> Option<&RailVerificationObservation> {
        self.rail_verification.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ColdPllStage {
    frequency_mhz: u16,
    plans: Vec<ColdPllVoltagePlan>,
    commands: Vec<ColdPllCommand>,
    settled_at: Option<Instant>,
    before_adc: Vec<DomainAdcObservation>,
    after_adc: Option<DomainAdcObservation>,
}
impl ColdPllStage {
    pub fn frequency_mhz(&self) -> u16 {
        self.frequency_mhz
    }
    pub fn voltage_plans(&self) -> &[ColdPllVoltagePlan] {
        &self.plans
    }
    pub fn commands(&self) -> &[ColdPllCommand] {
        &self.commands
    }
    pub fn settled_at(&self) -> Option<Instant> {
        self.settled_at
    }
    pub fn before_adc(&self) -> &[DomainAdcObservation] {
        &self.before_adc
    }
    pub fn after_adc(&self) -> Option<&DomainAdcObservation> {
        self.after_adc.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ColdPllObservation {
    preparation_completed_at: Option<Instant>,
    issuer: Arc<()>,
    profile: Bm1396AutoAdaptProfile,
    baud: OperationalBaudObservation,
    initial_adc: DomainAdcObservation,
    initial_voltage: Option<CommandedVoltage>,
    thermal: Vec<ThermalSnapshot>,
    thermal_records: usize,
    stages: Vec<ColdPllStage>,
    final_adc: Option<DomainAdcObservation>,
    completed_at: Option<Instant>,
    failure: Option<String>,
}
impl ColdPllObservation {
    pub fn preparation_completed_at(&self) -> Option<Instant> {
        self.preparation_completed_at
    }
    pub fn profile(&self) -> Bm1396AutoAdaptProfile {
        self.profile
    }
    pub fn operational_baud(&self) -> &OperationalBaudObservation {
        &self.baud
    }
    pub fn baseline_adc(&self) -> &DomainAdcObservation {
        &self.initial_adc
    }
    pub fn initial_voltage(&self) -> Option<CommandedVoltage> {
        self.initial_voltage
    }
    pub fn thermal_snapshots(&self) -> &[ThermalSnapshot] {
        &self.thermal
    }
    pub fn stages(&self) -> &[ColdPllStage] {
        &self.stages
    }
    pub fn final_adc(&self) -> Option<&DomainAdcObservation> {
        self.final_adc.as_ref()
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
}

#[derive(Clone, Copy)]
struct PicRequest {
    stage: usize,
    plan: usize,
    target: u16,
    command: bool,
}
enum PicCompletion {
    Ready(CommandedVoltage),
    Applied(PicRequest, CommandedVoltage),
}

impl<H: Hardware> PicApplication<H> {
    /// Bounded read-only health view while the controller holds ASIC custody.
    /// It clones only the most recent complete thermal population, leaving the
    /// full retained command/rail/FIFO history in this application.
    pub fn cold_pll_latest_thermal(&self) -> Result<Option<ThermalSnapshot>, String> {
        Ok(self
            .cold_pll
            .lock()
            .map_err(|_| "BM1396 cold PLL custody poisoned")?
            .as_ref()
            .and_then(|observation| observation.thermal.last().cloned()))
    }

    pub fn cold_pll_observation(&self) -> Result<Option<ColdPllObservation>, String> {
        Ok(self
            .cold_pll
            .lock()
            .map_err(|_| "BM1396 cold PLL custody poisoned")?
            .clone())
    }

    /// One exact T17e cold300 attempt. Inputs come exclusively from this owner's
    /// completed factory/cold/ADC/baud/thermal and PIC observations. The caller
    /// retains independent heartbeat, fan and physical-cutoff supervision.
    pub async fn initialize_cold_pll(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<ColdPllObservation, String> {
        self.initialize_cold_pll_input(None, deadline).await
    }

    /// Runtime conditioning uses the actual complete preparation and source
    /// line; standalone producer tests keep their separate explicit entry point.
    pub async fn initialize_conditioning_pll(
        self: &Arc<Self>,
        line: Arc<PowerLine<H>>,
        deadline: Instant,
    ) -> Result<ColdPllObservation, String> {
        self.initialize_cold_pll_input(Some(line), deadline).await
    }

    async fn initialize_cold_pll_input(
        self: &Arc<Self>,
        line: Option<Arc<PowerLine<H>>>,
        deadline: Instant,
    ) -> Result<ColdPllObservation, String> {
        if self.owner.model == Model::S17e && line.is_none() {
            return Err("S17e factory PLL requires the actual preparation-bound source".into());
        }
        let app = self.clone();
        let runtime = tokio::runtime::Handle::current();
        self.owner.worker(deadline, false, move |owner| {
            let mut state = owner.lock(&owner.asic, deadline, false)?;
            let profile = owner.factory_calibration_profile()?;
            let baud = state.operational_baud.clone().ok_or("BM1396 cold PLL requires completed operational baud")?;
            let old_host = baud.old_host_register();
            let host = baud.requested_host_register();
            if baud.completed_at().is_none()
                || baud.model() != owner.model
                || baud.baud() != match owner.model { Model::S17e => 6_000_000, Model::T17e => 3_000_000 }
                || baud.host_readback() != Some(host)
                || state.assignment.as_ref().is_none_or(|o| o.host_baud_register() != old_host)
                || state.cold_registers.as_ref().is_none_or(|o| o.completed_at().is_none() || o.host_baud_register() != old_host)
                || state.domain_adc.as_ref().is_none_or(|o| o.baseline_minimum_passed() != Some(true) || o.host_baud_register() != old_host)
                || state.thermal.as_ref().is_none_or(|t| !t.configuration_matches_host(old_host) || t.has_pending_snapshots())
                || !state.publications.is_empty()
            {
                return Err("BM1396 cold PLL requires same-owner complete cold/ADC/thermal/baud custody".into());
            }
            let preparation_completed_at = if let Some(line) = line {
                let prepared = app.conditioning_preparation_observation()?
                    .ok_or("T17e conditioning PLL requires actual preparation")?;
                let completed_at = prepared.completed_at().ok_or("T17e conditioning preparation incomplete")?;
                let reset_word = prepared.reset().events().iter().rev().find_map(|event| match event {
                    ConditioningResetEvent::Register { offset: 0x34, value, completed_at: Some(_) } => Some(*value),
                    _ => None,
                }).ok_or("T17e prepared reset word absent")?;
                let higher_command = prepared.higher_command().ok_or("T17e prepared higher voltage absent")?;
                let thermal = prepared.thermal_snapshots().last().cloned()
                    .ok_or("T17e prepared thermal population absent")?;
                if !prepared.same_owner(&owner) || !line.same_owner(&owner) || prepared.failure().is_some()
                    || state.assignment.as_ref() != prepared.assignment()
                    || state.cold_registers.as_ref() != prepared.cold_registers()
                    || state.domain_adc.as_ref() != prepared.baseline_adc()
                    || state.operational_baud.as_ref() != prepared.operational_baud()
                    || state.thermal.as_ref().and_then(|t|t.complete_configuration()) != prepared.thermal_configuration() {
                    return Err("T17e conditioning PLL preparation receipt/state join changed".into());
                }
                line.check_active_source(&owner, deadline)?;
                app.preparation_validate_thermal(&thermal, prepared.cutoff_c())?;
                let mut admission = app.prepared_cold.lock().map_err(|_| "T17e prepared PLL custody poisoned")?;
                if admission.is_some() { return Err("T17e prepared PLL attempt already spent".into()); }
                *admission = Some(PreparedColdAdmission { reset_word, higher_command, next_voltage: 2, epoch: 0, line, cutoff_c:prepared.cutoff_c(), thermal, adapted: None });
                Some(completed_at)
            } else {
                if app.conditioning_preparation_observation()?.is_some() {
                    return Err("T17e prepared startup requires the preparation-bound PLL entry point".into());
                }
                None
            };
            PllTransaction::first(&app).cold_guard(host, deadline)?;
            let baseline = state.domain_adc.clone().expect("checked ADC");
            {
                let mut retained = app.cold_pll.lock().map_err(|_| "BM1396 cold PLL custody poisoned")?;
                if retained.is_some() { return Err("BM1396 cold PLL attempt already spent".into()); }
                *retained = Some(ColdPllObservation {
                    preparation_completed_at,
                    issuer: owner.identity.clone(), profile, baud, initial_adc: baseline.clone(),
                    initial_voltage: None, thermal: Vec::new(), thermal_records: 0,
                    stages: Vec::with_capacity(5), final_adc: None, completed_at: None, failure: None,
                });
            }
            // Actual same-owner baseline moves into retained cold custody before
            // its exact acknowledgment frees the later ADC acquisition slot.
            let pre_worker = owner.acknowledge_domain_adc_locked(&mut state, &baseline)
                .and_then(|()| owner.query_predrain(&mut state, deadline));
            if let Err(error) = pre_worker {
                owner.begin_terminal();
                let mut retained = app.cold_pll.lock().map_err(|_| "BM1396 cold PLL custody poisoned")?;
                retained.as_mut().ok_or("BM1396 cold PLL custody lost")?.failure = Some(error.clone());
                return Err(error);
            }
            let mut watermark = state.next_return;
            let (requests, request_rx) = mpsc::sync_channel(1);
            let (completed_tx, completed) = mpsc::sync_channel(1);
            let pic_app = app.clone();
            let pic_owner = owner.clone();
            let pic_worker = runtime.spawn(async move {
                pic_owner.worker(deadline, false, move |_| {
                    let lease = pic_app.voltage_lease(deadline)?;
                    PllTransaction::first(&pic_app).cold_pic_loop(&lease, request_rx, completed_tx, deadline)
                }).await
            });
            // The ASIC mutex remains here for the entire phase. The PIC worker
            // never needs it; joining that actual worker during cleanup cannot
            // strand a queued ASIC operation behind this retained guard.
            let result = PllTransaction::first(&app).cold_sequence(&mut state, host, profile, &mut watermark, &requests, &completed, deadline);
            if result.is_err() { owner.begin_terminal(); }
            drop(requests);
            let pic_result = runtime.block_on(pic_worker).map_err(|e| format!("BM1396 cold PIC worker join: {e}"))
                .and_then(|r| r);
            let result = match (result, pic_result) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(first), Err(second)) => Err(format!("{first}; PIC worker: {second}")),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }.and_then(|()| PllTransaction::first(&app).cold_guard(host, deadline));
            // S17e's fixed pass is its final source ramp. Reacquire the actual
            // PIC lease and verify every voltage generation before completion.
            let completion_lease = if owner.model == Model::S17e && result.is_ok() {
                Some(app.voltage_lease_serviced(deadline, || {
                    PllTransaction::first(&app).cold_service(&mut state, host, &mut watermark, deadline)
                }))
            } else { None };
            let result = result.and_then(|()| match &completion_lease {
                Some(Ok(lease)) => PllTransaction::first(&app).final_voltage_completion(lease),
                Some(Err(error)) => Err(error.clone()),
                None => Ok(()),
            });
            let mut retained = app.cold_pll.lock().map_err(|_| "BM1396 cold PLL custody poisoned")?;
            let observation = retained.as_mut().ok_or("BM1396 cold PLL custody lost")?;
            if let Err(error) = result { observation.failure = Some(error.clone()); return Err(error); }
            observation.completed_at = Some(Instant::now());
            Ok(observation.clone())
        }).await
    }
}

// Both source PLL passes retain distinct observations and admission slots.
// The conditioning-only tail remains outside the shared five-stage ramp.
struct PllTransaction<'a, H: Hardware> {
    app: &'a PicApplication<H>,
    retained: &'a Mutex<Option<ColdPllObservation>>,
    admission: &'a Mutex<Option<PreparedColdAdmission<H>>>,
}
impl<H: Hardware> std::ops::Deref for PllTransaction<'_, H> {
    type Target = PicApplication<H>;
    fn deref(&self) -> &Self::Target {
        self.app
    }
}
impl<'a, H: Hardware> PllTransaction<'a, H> {
    fn voltage_plan(
        &self,
        source: &FactoryPllStage,
        profile: Bm1396AutoAdaptProfile,
        minimum: i16,
        current: u16,
    ) -> Result<Bm1396AutoAdaptVoltagePlan, String> {
        if source.factory_working_voltage {
            if self.owner.model != Model::S17e
                || profile != Bm1396AutoAdaptProfile::Signed2020S17eFixed
            {
                return Err("S17e working voltage requires its exact factory profile".into());
            }
            let records = self
                .owner
                .s17e_factory_records()?
                .into_iter()
                .map(|(_, record)| record)
                .collect::<Vec<_>>();
            s17e_factory::working_voltage_plan(&records, source.frequency_mhz, minimum, current)
        } else {
            plan_bm1396_auto_adapt_voltage(
                Bm1396FirmwareRelease::Signed2020,
                self.owner.model,
                profile,
                source.frequency_mhz,
                minimum,
                current,
            )
            .map_err(|error| error.to_string())
        }
    }
    fn source_stages(&self) -> Result<Vec<FactoryPllStage>, String> {
        match self.owner.model {
            Model::S17e => s17e_factory::startup_plan(&self.owner.s17e_factory_records()?),
            Model::T17e => Ok(STAGES
                .into_iter()
                .map(|(frequency_mhz, register)| FactoryPllStage {
                    frequency_mhz,
                    commands: self
                        .owner
                        .chains
                        .iter()
                        .cycle()
                        .take(2 * self.owner.chains.len())
                        .map(|&chain| FactoryPllCommand {
                            chain,
                            chip: None,
                            register,
                        })
                        .collect(),
                    wait_ms: 2000,
                    domain_adc_after: false,
                    factory_working_voltage: false,
                })
                .collect()),
        }
    }

    /// Retain the actual complete or failed ADC population before clearing its
    /// exact slot. A fabricated result cannot authorize the next PLL command.
    fn stage_domain_adc(
        &self,
        state: &mut AsicState,
        host: u32,
        watermark: &mut u64,
        stage: usize,
        after: bool,
        deadline: Instant,
    ) -> Result<(), String> {
        let result = self
            .owner
            .acquire_domain_adc_serviced(state, deadline, |state, point| {
                self.cold_command_service(state, host, watermark, point, deadline)
            });
        let observation = state
            .domain_adc
            .clone()
            .ok_or("BM1396 PLL ADC custody absent")?;
        {
            let mut retained = self
                .retained
                .lock()
                .map_err(|_| "BM1396 PLL custody poisoned")?;
            let stage = &mut retained.as_mut().ok_or("BM1396 PLL custody lost")?.stages[stage];
            if after {
                stage.after_adc = Some(observation.clone());
            } else {
                if stage.before_adc.len() >= PLANS_PER_STAGE {
                    return Err("BM1396 PLL pre-command ADC capacity exhausted".into());
                }
                stage.before_adc.push(observation.clone());
            }
        }
        result?;
        self.owner
            .acknowledge_domain_adc_locked(state, &observation)
    }
    fn first(app: &'a PicApplication<H>) -> Self {
        Self {
            app,
            retained: &app.cold_pll,
            admission: &app.prepared_cold,
        }
    }

    fn native(app: &'a PicApplication<H>) -> Self {
        match app.owner.model {
            Model::T17e => Self::final_stage(app),
            Model::S17e => Self::first(app),
        }
    }

    fn final_stage(app: &'a PicApplication<H>) -> Self {
        Self {
            app,
            retained: &app.final_pll,
            admission: &app.prepared_final,
        }
    }

    fn cold_guard(&self, host: u32, deadline: Instant) -> Result<(), String> {
        self.cold_guard_owned(host, deadline, false)
    }

    fn cold_guard_owned(
        &self,
        host: u32,
        deadline: Instant,
        command_pending: bool,
    ) -> Result<(), String> {
        self.require_health(deadline)?;
        if let Some(admission) = self
            .admission
            .lock()
            .map_err(|_| "T17e prepared PLL custody poisoned")?
            .as_ref()
        {
            admission.line.check_active_source(&self.owner, deadline)?;
            if self.owner.hardware.read(0x34)? != admission.reset_word {
                return Err("T17e prepared PLL reset state changed".into());
            }
            let retained = self
                .retained
                .lock()
                .map_err(|_| "BM1396 cold PLL custody poisoned")?;
            let snapshot = retained
                .as_ref()
                .and_then(|o| o.thermal.last())
                .unwrap_or(&admission.thermal);
            if snapshot.epoch() != admission.epoch
                || snapshot
                    .samples()
                    .iter()
                    .any(|sample| sample.is_historical() || sample.epoch() != admission.epoch)
            {
                return Err("T17e PLL thermal snapshot belongs to another epoch".into());
            }
            self.preparation_validate_thermal(snapshot, admission.cutoff_c)?;
        }

        self.owner.query_presence(deadline)?;
        if command_pending {
            // Only a post-publication callback under this worker's ASIC mutex
            // reaches here. Its own BC BUSY is expected, not foreign admission.
            if self.owner.hardware.read(0x3c)? != host {
                return Err("BM1396 cold PLL host baud changed during owned command".into());
            }
        } else {
            self.owner.query_host(host, deadline)?;
        }
        if self.owner.hardware.read(DHASH)? & RUN != 0 {
            return Err("BM1396 cold PLL engine became active".into());
        }
        self.owner.check(deadline, false)
    }

    fn cold_pic_loop(
        &self,
        lease: &VoltageLease<'_>,
        requests: Receiver<PicRequest>,
        completed: SyncSender<PicCompletion>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.require_health(deadline)?;
        let initial = {
            let state = self
                .state
                .lock()
                .map_err(|_| "BM1396 PIC custody poisoned")?;
            if !state.voltage_attempts.is_empty()
                || !state.rail_verifications.is_empty()
                || !state.rails.is_empty()
            {
                return Err(
                    "BM1396 cold PLL requires prior PIC observation custody acknowledged".into(),
                );
            }
            if let Some(admission) = self
                .admission
                .lock()
                .map_err(|_| "T17e prepared PLL custody poisoned")?
                .as_ref()
            {
                if state.next_voltage != admission.next_voltage
                    || state.last_voltage != Some(admission.higher_command)
                {
                    return Err(
                        "T17e prepared PLL refuses an intervening voltage generation".into(),
                    );
                }
            }
            state
                .last_voltage
                .ok_or("BM1396 cold PLL requires completed initial voltage")?
        };
        completed
            .send(PicCompletion::Ready(initial))
            .map_err(|_| "BM1396 cold ASIC worker disconnected")?;
        loop {
            let request = match requests.recv_timeout(Duration::from_millis(1)) {
                Ok(request) => request,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
                Err(RecvTimeoutError::Timeout) => {
                    self.require_health(deadline)?;
                    continue;
                }
            };
            self.require_health(deadline)?;
            {
                let retained = self
                    .retained
                    .lock()
                    .map_err(|_| "BM1396 cold PLL custody poisoned")?;
                let plan = retained
                    .as_ref()
                    .and_then(|o| o.stages.get(request.stage))
                    .and_then(|s| s.plans.get(request.plan))
                    .ok_or("BM1396 cold PIC request has no retained source plan")?;
                if plan.plan.target_voltage_cv != request.target
                    || plan.attempt.is_some()
                    || plan.rail_verification.is_some()
                    || plan.plan.stepped_dac_codes.is_empty() == request.command
                {
                    return Err(
                        "BM1396 cold PIC request is changed, duplicate or a source no-op".into(),
                    );
                }
            }
            let commanded = if request.command {
                self.command_voltage_locked(lease, request.target, true, deadline)?
            } else {
                let commanded = self
                    .last_commanded_voltage()?
                    .ok_or("BM1396 cold initial rail target absent")?;
                if commanded.requested_centivolts() != request.target {
                    return Err("BM1396 cold initial rail target changed".into());
                }
                commanded
            };
            if request.command {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| "BM1396 PIC custody poisoned")?;
                let attempt = state
                    .voltage_attempts
                    .front()
                    .ok_or("BM1396 cold voltage attempt custody lost")?;
                let mut retained = self
                    .retained
                    .lock()
                    .map_err(|_| "BM1396 cold PLL custody poisoned")?;
                let plan = retained
                    .as_mut()
                    .and_then(|o| o.stages.get_mut(request.stage))
                    .and_then(|s| s.plans.get_mut(request.plan))
                    .ok_or("BM1396 cold voltage plan custody lost")?;
                if attempt.completed_at().is_none()
                    || attempt.requested_centivolts() != request.target
                    || attempt.planned_dac_codes() != plan.plan.stepped_dac_codes
                    || attempt.prior_command().map(|v| v.requested_centivolts())
                        != Some(plan.plan.current_voltage_cv)
                {
                    return Err(
                        "BM1396 cold voltage attempt differs from retained source plan".into(),
                    );
                }
                plan.attempt = state.voltage_attempts.pop_front();
            }
            let verification = self.verify_rail_locked(lease, deadline)?;
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| "BM1396 PIC custody poisoned")?;
                if state.rail_verifications.front() != Some(&verification)
                    || verification.passed() != Some(true)
                    || verification.commanded_voltage() != commanded
                {
                    return Err(
                        "BM1396 cold rail verification changed or lost exact oldest custody".into(),
                    );
                }
                let mut retained = self
                    .retained
                    .lock()
                    .map_err(|_| "BM1396 cold PLL custody poisoned")?;
                let plan = retained
                    .as_mut()
                    .and_then(|o| o.stages.get_mut(request.stage))
                    .and_then(|s| s.plans.get_mut(request.plan))
                    .ok_or("BM1396 cold rail plan custody lost")?;
                plan.rail_verification = state.rail_verifications.pop_front();
            }
            completed
                .send(PicCompletion::Applied(request, commanded))
                .map_err(|_| "BM1396 cold ASIC worker disconnected")?;
        }
    }

    fn cold_service(
        &self,
        state: &mut AsicState,
        host: u32,
        watermark: &mut u64,
        deadline: Instant,
    ) -> Result<(), String> {
        self.cold_receive(state, host, watermark, deadline, false)
    }

    fn cold_receive(
        &self,
        state: &mut AsicState,
        host: u32,
        watermark: &mut u64,
        deadline: Instant,
        command_pending: bool,
    ) -> Result<(), String> {
        self.cold_guard_owned(host, deadline, command_pending)?;
        self.owner.receive_locked(state, 128, deadline)?;
        self.cold_pending_prepared_thermal(state)?;
        if let Some(snapshot) = self
            .owner
            .collect_thermal_locked(state, *watermark, deadline)?
        {
            {
                let mut retained = self
                    .retained
                    .lock()
                    .map_err(|_| "BM1396 cold PLL custody poisoned")?;
                let observation = retained.as_mut().ok_or("BM1396 cold PLL custody lost")?;
                if observation.thermal.len() >= THERMAL_CAPACITY
                    || observation.thermal_records + snapshot.raw_records().len()
                        > THERMAL_RECORD_CAPACITY
                {
                    return Err("BM1396 cold thermal retention capacity exhausted; actual snapshot retained in ASIC owner".into());
                }
                observation.thermal_records += snapshot.raw_records().len();
                observation.thermal.push(snapshot.clone());
            }
            self.owner
                .acknowledge_thermal_snapshot_locked(state, &snapshot)?;
            *watermark = state.next_return;
        }
        self.cold_guard_owned(host, deadline, command_pending)
    }

    /// A partial automatic population cannot hide a known hot or stale sample
    /// while waiting for the other positions. BeforePublish inspects only bytes
    /// already retained; it never advances the current query's receive watermark.
    fn cold_pending_prepared_thermal(&self, state: &AsicState) -> Result<(), String> {
        let (cutoff, epoch) = match self
            .admission
            .lock()
            .map_err(|_| "T17e prepared PLL custody poisoned")?
            .as_ref()
            .map(|admission| (admission.cutoff_c, admission.epoch))
        {
            Some(values) => values,
            None => return Ok(()),
        };
        for raw in &state.pending {
            if matches!(raw.payload(), ReturnPayload::HistoricalTemperature(_)) {
                return Err("T17e PLL refuses historical thermal custody".into());
            }
            if let ReturnPayload::Temperature(sample) = raw.payload() {
                if sample.epoch() != epoch || sample.is_historical() {
                    return Err("T17e PLL pending thermal belongs to another epoch".into());
                }
                if Instant::now()
                    .checked_duration_since(sample.received_at())
                    .is_none_or(|age| age >= Duration::from_millis(6960))
                {
                    return Err("T17e prepared PLL pending thermal record stale".into());
                }
                for (channel, temperature) in
                    sample.raw_channels().into_iter().zip(sample.temperatures_c(
                        dcentrald_common::bm1396_contract::Bm1396SensorSamplingMode::Mode0,
                    ))
                {
                    if channel != 0 && temperature >= cutoff {
                        return Err(
                            "T17e prepared PLL temperature reached configured cutoff".into()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn cold_command_service(
        &self,
        state: &mut AsicState,
        host: u32,
        watermark: &mut u64,
        point: CommandServicePoint,
        deadline: Instant,
    ) -> Result<(), String> {
        match point {
            // ADC/query watermarks may already exist. No receive before actual
            // publication may be mislabeled as a response to the new request.
            CommandServicePoint::BeforePublish => {
                self.cold_guard(host, deadline)?;
                self.cold_pending_prepared_thermal(state)?;
            }
            CommandServicePoint::Poll => {
                self.cold_receive(state, host, watermark, deadline, true)?
            }
            CommandServicePoint::IdleReceive => {
                self.cold_service(state, host, watermark, deadline)?
            }
        }
        self.cold_temperature()?;
        Ok(())
    }

    fn cold_temperature(&self) -> Result<(u64, i16), String> {
        let retained = self
            .retained
            .lock()
            .map_err(|_| "BM1396 cold PLL custody poisoned")?;
        let snapshot = retained
            .as_ref()
            .and_then(|o| o.thermal.last())
            .ok_or("BM1396 cold PLL fresh thermal population missing")?;
        if !snapshot.is_fresh_at(Instant::now()) {
            return Err("BM1396 cold PLL thermal population stale".into());
        }
        let minimum = snapshot
            .samples()
            .iter()
            .filter(|sample| sample.raw_channels()[0] != 0)
            .map(|sample| sample.temperatures_c(snapshot.sampling_mode())[0])
            .min()
            .ok_or("BM1396 cold PLL has no valid channel0 PCB temperature")?;
        Ok((snapshot.sequence(), minimum))
    }

    fn cold_wait(
        &self,
        state: &mut AsicState,
        host: u32,
        watermark: &mut u64,
        milliseconds: usize,
        deadline: Instant,
    ) -> Result<(), String> {
        for _ in 0..milliseconds {
            self.cold_service(state, host, watermark, deadline)?;
            self.cold_temperature()?;
            self.owner
                .delay(Duration::from_millis(1), deadline, false)?;
        }
        self.cold_service(state, host, watermark, deadline)?;
        self.cold_temperature()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn cold_ramp_sequence(
        &self,
        state: &mut AsicState,
        host: u32,
        profile: Bm1396AutoAdaptProfile,
        watermark: &mut u64,
        requests: &SyncSender<PicRequest>,
        completed: &Receiver<PicCompletion>,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut current = loop {
            self.cold_service(state, host, watermark, deadline)?;
            match completed.try_recv() {
                Ok(PicCompletion::Ready(value)) => break value,
                Ok(_) => return Err("BM1396 cold PIC result arrived out of order".into()),
                Err(TryRecvError::Disconnected) => {
                    return Err("BM1396 cold PIC worker stopped before initial admission".into())
                }
                Err(TryRecvError::Empty) => {
                    self.owner
                        .delay(Duration::from_millis(1), deadline, false)?
                }
            }
        };
        self.retained
            .lock()
            .map_err(|_| "BM1396 cold PLL custody poisoned")?
            .as_mut()
            .ok_or("BM1396 cold PLL custody lost")?
            .initial_voltage = Some(current);
        // New complete population, never a caller-supplied scalar or old cache.
        for tick in 0..6970 {
            self.cold_service(state, host, watermark, deadline)?;
            if self
                .retained
                .lock()
                .map_err(|_| "BM1396 cold PLL custody poisoned")?
                .as_ref()
                .is_some_and(|o| !o.thermal.is_empty())
            {
                break;
            }
            if tick == 6969 {
                return Err("BM1396 cold PLL fresh thermal population timed out".into());
            }
            self.owner
                .delay(Duration::from_millis(1), deadline, false)?;
        }
        let mut verified_command = None;
        for (stage_index, source) in self.source_stages()?.into_iter().enumerate() {
            let frequency = source.frequency_mhz;
            self.retained
                .lock()
                .map_err(|_| "BM1396 cold PLL custody poisoned")?
                .as_mut()
                .ok_or("BM1396 cold PLL custody lost")?
                .stages
                .push(ColdPllStage {
                    frequency_mhz: frequency,
                    plans: Vec::with_capacity(PLANS_PER_STAGE),
                    commands: Vec::new(),
                    settled_at: None,
                    before_adc: Vec::new(),
                    after_adc: None,
                });
            let mut ready = false;
            for plan_index in 0..PLANS_PER_STAGE {
                self.cold_service(state, host, watermark, deadline)?;
                let (thermal_sequence, minimum) = self.cold_temperature()?;
                let plan =
                    self.voltage_plan(&source, profile, minimum, current.requested_centivolts())?;
                let target = plan.target_voltage_cv;
                let changed = !plan.stepped_dac_codes.is_empty();
                let before_adc = plan.helper_invokes_domain_adc_mode1_before_pll;
                self.retained
                    .lock()
                    .map_err(|_| "BM1396 cold PLL custody poisoned")?
                    .as_mut()
                    .ok_or("BM1396 cold PLL custody lost")?
                    .stages[stage_index]
                    .plans
                    .push(ColdPllVoltagePlan {
                        thermal_sequence,
                        plan,
                        attempt: None,
                        rail_verification: None,
                    });
                // Even when the source setter is a no-op, initial native PLL
                // admission still requires two actual matching rail populations.
                if changed || verified_command != Some(current) {
                    let request = PicRequest {
                        stage: stage_index,
                        plan: plan_index,
                        target,
                        command: changed,
                    };
                    requests
                        .send(request)
                        .map_err(|_| "BM1396 cold PIC worker disconnected before command")?;
                    loop {
                        self.cold_service(state, host, watermark, deadline)?;
                        self.cold_temperature()?;
                        match completed.try_recv() {
                            Ok(PicCompletion::Applied(actual, voltage))
                                if actual.stage == stage_index
                                    && actual.plan == plan_index
                                    && actual.target == target
                                    && actual.command == changed =>
                            {
                                current = voltage;
                                verified_command = Some(voltage);
                                break;
                            }
                            Ok(_) => {
                                return Err(
                                    "BM1396 cold PIC completion mismatches source plan".into()
                                )
                            }
                            Err(TryRecvError::Disconnected) => {
                                return Err(
                                    "BM1396 cold PIC worker failed during command/verification"
                                        .into(),
                                )
                            }
                            Err(TryRecvError::Empty) => {
                                self.owner
                                    .delay(Duration::from_millis(1), deadline, false)?
                            }
                        }
                    }
                }
                if before_adc {
                    self.stage_domain_adc(state, host, watermark, stage_index, false, deadline)?;
                }
                self.cold_service(state, host, watermark, deadline)?;
                let (_, minimum) = self.cold_temperature()?;
                let checked =
                    self.voltage_plan(&source, profile, minimum, current.requested_centivolts())?;
                if checked.target_voltage_cv == current.requested_centivolts() {
                    ready = true;
                    break;
                }
            }
            if !ready {
                return Err("BM1396 cold PLL thermal voltage target did not stabilize within four retained plans".into());
            }
            // T17e broadcasts twice; S17e follows its exact addressed factory
            // plan. Portal completion does not establish electrical PLL lock.
            for command in &source.commands {
                let chain = command.chain;
                let address = match command.chip {
                    None => 0,
                    Some(chip) => self
                        .owner
                        .model
                        .hardware_address(u16::from(chip))
                        .ok_or("BM1396 factory PLL chip outside exact geometry")?,
                };
                self.cold_service(state, host, watermark, deadline)?;
                let (_, minimum) = self.cold_temperature()?;
                let latest =
                    self.voltage_plan(&source, profile, minimum, current.requested_centivolts())?;
                if latest.target_voltage_cv != current.requested_centivolts() {
                    return Err("BM1396 cold PLL thermal target changed before command; partial stage retained".into());
                }
                self.retained
                    .lock()
                    .map_err(|_| "BM1396 cold PLL custody poisoned")?
                    .as_mut()
                    .ok_or("BM1396 cold PLL custody lost")?
                    .stages[stage_index]
                    .commands
                    .push(ColdPllCommand {
                        chain,
                        chip: command.chip,
                        value: command.register,
                        completed_at: None,
                    });
                self.owner.command_locked_serviced(
                    chain,
                    &bm1396_write_register_frame(
                        command.chip.is_none(),
                        address,
                        8,
                        command.register,
                    ),
                    deadline,
                    |point| self.cold_command_service(state, host, watermark, point, deadline),
                )?;
                self.cold_guard(host, deadline)?;
                self.retained
                    .lock()
                    .map_err(|_| "BM1396 cold PLL custody poisoned")?
                    .as_mut()
                    .ok_or("BM1396 cold PLL custody lost")?
                    .stages[stage_index]
                    .commands
                    .last_mut()
                    .expect("retained command")
                    .completed_at = Some(Instant::now());
            }
            self.cold_wait(state, host, watermark, source.wait_ms as usize, deadline)?;
            if source.domain_adc_after {
                self.stage_domain_adc(state, host, watermark, stage_index, true, deadline)?;
            }
            self.retained
                .lock()
                .map_err(|_| "BM1396 cold PLL custody poisoned")?
                .as_mut()
                .ok_or("BM1396 cold PLL custody lost")?
                .stages[stage_index]
                .settled_at = Some(Instant::now());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn cold_sequence(
        &self,
        state: &mut AsicState,
        host: u32,
        profile: Bm1396AutoAdaptProfile,
        watermark: &mut u64,
        requests: &SyncSender<PicRequest>,
        completed: &Receiver<PicCompletion>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.cold_ramp_sequence(
            state, host, profile, watermark, requests, completed, deadline,
        )?;
        self.cold_wait(state, host, watermark, 500, deadline)?;
        let result = self
            .owner
            .acquire_domain_adc_serviced(state, deadline, |state, point| {
                self.cold_command_service(state, host, watermark, point, deadline)
            });
        self.retained
            .lock()
            .map_err(|_| "BM1396 cold PLL custody poisoned")?
            .as_mut()
            .ok_or("BM1396 cold PLL custody lost")?
            .final_adc = state.domain_adc.clone();
        result?;
        self.cold_service(state, host, watermark, deadline)?;
        self.cold_temperature()?;
        self.cold_guard(host, deadline)
    }
}
