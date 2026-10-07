//! First S17e/T17e higher-voltage/cold/ADC/thermal/baud preparation.
//! Source: complete16958, initial-voltage-context2 and existing exact producers.
//! S17e18dbc ->5dec8 raises the initial2000cV context before16d9c cold setup;
//! operational baud, 135-chip assignment, domain ADC and sensors are model-owned.
//! This retains one ASIC guard and one counted PIC worker's voltage lease.
use super::*;
use dcentrald_common::bm1396_contract::Bm1396SensorSamplingMode;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};

const THERMAL_CAPACITY: usize = 1024;
const THERMAL_RECORD_CAPACITY: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditioningPreparationStage {
    Admitted,
    HigherVoltage,
    ColdRegisters,
    BaselineAdc,
    ThermalConfiguration,
    OperationalBaud,
    FreshThermal,
}

#[derive(Clone, Debug)]
pub struct ConditioningPreparationObservation {
    issuer: Arc<()>,
    reset: ConditioningResetObservation,
    cutoff_c: i16,
    reset_word: u32,
    stage: ConditioningPreparationStage,
    higher_voltage: Option<VoltageAttempt>,
    higher_command: Option<CommandedVoltage>,
    assignment: Option<AssignmentObservation>,
    cold: Option<ColdRegisterObservation>,
    baseline_adc: Option<DomainAdcObservation>,
    thermal_configuration: Option<ThermalConfiguration>,
    baud: Option<OperationalBaudObservation>,
    thermal: Vec<ThermalSnapshot>,
    thermal_records: usize,
    completed_at: Option<Instant>,
    failure: Option<String>,
}
impl ConditioningPreparationObservation {
    pub fn same_owner<H: Hardware>(&self, owner: &Arc<Transport<H>>) -> bool {
        Arc::ptr_eq(&self.issuer, &owner.identity)
    }
    pub fn reset(&self) -> &ConditioningResetObservation {
        &self.reset
    }
    pub fn cutoff_c(&self) -> i16 {
        self.cutoff_c
    }
    pub fn stage(&self) -> ConditioningPreparationStage {
        self.stage
    }
    pub fn higher_voltage(&self) -> Option<&VoltageAttempt> {
        self.higher_voltage.as_ref()
    }
    pub fn higher_command(&self) -> Option<CommandedVoltage> {
        self.higher_command
    }
    pub fn assignment(&self) -> Option<&AssignmentObservation> {
        self.assignment.as_ref()
    }
    pub fn cold_registers(&self) -> Option<&ColdRegisterObservation> {
        self.cold.as_ref()
    }
    pub fn baseline_adc(&self) -> Option<&DomainAdcObservation> {
        self.baseline_adc.as_ref()
    }
    pub fn thermal_configuration(&self) -> Option<&ThermalConfiguration> {
        self.thermal_configuration.as_ref()
    }
    pub fn operational_baud(&self) -> Option<&OperationalBaudObservation> {
        self.baud.as_ref()
    }
    pub fn thermal_snapshots(&self) -> &[ThermalSnapshot] {
        &self.thermal
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
}

enum PicRequest {
    HigherVoltage,
}
enum PicCompletion {
    Ready,
    HigherVoltage,
}

impl<H: Hardware> PicApplication<H> {
    pub fn conditioning_preparation_observation(
        &self,
    ) -> Result<Option<ConditioningPreparationObservation>, String> {
        Ok(self
            .conditioning_preparation
            .lock()
            .map_err(|_| "T17e preparation custody poisoned")?
            .clone())
    }

    /// Read-only health view remains available while the ASIC guard is held.
    pub fn conditioning_preparation_latest_thermal(
        &self,
    ) -> Result<Option<ThermalSnapshot>, String> {
        Ok(self
            .conditioning_preparation
            .lock()
            .map_err(|_| "T17e preparation custody poisoned")?
            .as_ref()
            .and_then(|o| o.thermal.last().cloned()))
    }

    /// Same application's completed first reset, then actual source2000 ramp,
    /// fresh cold/assignment/Baseline ADC/thermal/baud and a new thermal population.
    /// The caller retains the actual heartbeat, fan and independent cut actors.
    pub async fn initialize_conditioning_preparation(
        self: &Arc<Self>,
        line: Arc<PowerLine<H>>,
        cutoff_c: i16,
        deadline: Instant,
    ) -> Result<ConditioningPreparationObservation, String> {
        let app = self.clone();
        let runtime = tokio::runtime::Handle::current();
        self.owner.worker(deadline, false, move |owner| {
            let mut state = owner.lock(&owner.asic, deadline, false)?;
            if !line.same_owner(&owner) || !(16..=80).contains(&cutoff_c)
                || state.startup_attempted || state.dma_initialized || state.assignment.is_some()
                || state.cold_registers.is_some() || state.domain_adc.is_some() || state.thermal.is_some()
                || state.operational_baud.is_some() || !state.publications.is_empty()
                || !state.register_observations.is_empty() {
                return Err("T17e preparation requires unused same-owner post-reset state and cutoff16..80C".into());
            }
            let reset = app.conditioning_reset_observation()?.ok_or("T17e preparation requires actual first reset")?;
            if !reset.same_owner(&owner) || reset.completed_at().is_none() || reset.failure().is_some()
                || reset.completed_chains() != owner.chains.as_slice()
                || reset.census_records().len() != usize::from(owner.model.expected_chips_per_present_chain()) * owner.chains.len()
                || reset.low_voltage().is_none_or(|attempt| attempt.sequence() != 0
                    || attempt.completed_at().is_none() || attempt.prior_command().is_some()
                    || attempt.initial_source_context_centivolts() != Some(0)
                    || attempt.requested_centivolts() != 1800) {
                return Err("T17e preparation first reset/voltage custody is incomplete or foreign".into());
            }
            let reset_word = reset.events().iter().rev().find_map(|event| match event {
                ConditioningResetEvent::Register { offset: 0x34, value, completed_at: Some(_) } => Some(*value),
                _ => None,
            }).ok_or("T17e preparation reset word custody absent")?;
            owner.factory_calibration_profile()?;
            app.require_health(deadline)?;
            line.check_active_source(&owner, deadline)?;
            if owner.hardware.read(0x34)? != reset_word
                || owner.hardware.read(0x3c)? != reset.requested_host_register()
                || owner.hardware.read(DHASH)? & RUN != 0 {
                return Err("T17e preparation reset, host or RUN changed after census".into());
            }
            {
                let mut retained = app.conditioning_preparation.lock().map_err(|_| "T17e preparation custody poisoned")?;
                if retained.is_some() { return Err("T17e preparation attempt already spent".into()); }
                *retained = Some(ConditioningPreparationObservation {
                    issuer: owner.identity.clone(), reset, cutoff_c, reset_word,
                    stage: ConditioningPreparationStage::Admitted, higher_voltage: None, higher_command: None,
                    assignment: None, cold: None, baseline_adc: None, thermal_configuration: None,
                    baud: None, thermal: Vec::new(), thermal_records: 0, completed_at: None, failure: None,
                });
            }
            let (requests, request_rx) = mpsc::sync_channel(1);
            let (completed_tx, completed) = mpsc::sync_channel(1);
            let pic_app = app.clone(); let pic_owner = owner.clone();
            let pic_worker = runtime.spawn(async move {
                pic_owner.worker(deadline, false, move |_| {
                    let lease = pic_app.voltage_lease(deadline)?;
                    pic_app.preparation_pic_loop(&lease, request_rx, completed_tx, deadline)
                }).await
            });
            let result = app.preparation_sequence(&mut state, &line, &requests, &completed, deadline);
            if result.is_err() { owner.begin_terminal(); }
            drop(requests);
            let pic_result = runtime.block_on(pic_worker).map_err(|e| format!("T17e preparation PIC worker join: {e}"))
                .and_then(|result| result);
            let result = match (result, pic_result) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(first), Err(second)) => Err(format!("{first}; PIC worker: {second}")),
                (Err(error), _) | (_, Err(error)) => Err(error),
            } .and_then(|()| owner.check(deadline, false));
            let mut retained = app.conditioning_preparation.lock().map_err(|_| "T17e preparation custody poisoned")?;
            let observation = retained.as_mut().ok_or("T17e preparation custody lost")?;
            if let Err(error) = result {
                owner.begin_terminal(); observation.failure = Some(error.clone()); return Err(error);
            }
            observation.completed_at = Some(Instant::now());
            Ok(observation.clone())
        }).await
    }

    fn preparation_pic_loop(
        &self,
        lease: &VoltageLease<'_>,
        requests: Receiver<PicRequest>,
        completed: SyncSender<PicCompletion>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.require_voltage_lease(lease)?;
        self.require_health(deadline)?;
        let reset = self
            .conditioning_reset_observation()?
            .ok_or("T17e preparation first reset lost")?;
        let lower = reset
            .low_voltage()
            .ok_or("T17e preparation lower voltage lost")?;
        {
            let state = self.state.lock().map_err(|_| "T17e PIC state poisoned")?;
            let current = state
                .last_voltage
                .ok_or("T17e preparation lower completed command missing")?;
            if state.next_voltage != 1
                || !state.voltage_attempts.is_empty()
                || current.requested_centivolts() != 1800
                || current.dac() != 120
                || lower
                    .steps()
                    .last()
                    .is_none_or(|step| step.response() != current.response())
                || reset
                    .completed_at()
                    .is_none_or(|time| current.completed_at() > time)
            {
                return Err(
                    "T17e preparation refuses any intervening voltage attempt after first reset"
                        .into(),
                );
            }
        }
        completed
            .send(PicCompletion::Ready)
            .map_err(|_| "T17e preparation ASIC worker disconnected")?;
        loop {
            let request = match requests.recv_timeout(Duration::from_millis(1)) {
                Ok(value) => value,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
                Err(RecvTimeoutError::Timeout) => {
                    self.require_health(deadline)?;
                    continue;
                }
            };
            self.require_health(deadline)?;
            match request {
                PicRequest::HigherVoltage => {
                    self.command_voltage_locked(lease, 2000, true, deadline)?;
                    let mut state = self.state.lock().map_err(|_| "T17e PIC state poisoned")?;
                    let attempt = state
                        .voltage_attempts
                        .front()
                        .ok_or("T17e higher voltage custody lost")?;
                    let command = state
                        .last_voltage
                        .ok_or("T17e higher completed command lost")?;
                    if state.next_voltage != 2
                        || attempt.sequence() != 1
                        || attempt.completed_at().is_none()
                        || attempt.requested_centivolts() != 2000
                        || !attempt.is_stepped()
                        || attempt.planned_dac_codes() != [103, 86, 69, 52, 48]
                        || command.requested_centivolts() != 2000
                        || command.dac() != 48
                    {
                        return Err(
                            "T17e higher voltage differs from source default sequence".into()
                        );
                    }
                    let mut retained = self
                        .conditioning_preparation
                        .lock()
                        .map_err(|_| "T17e preparation custody poisoned")?;
                    let observation = retained.as_mut().ok_or("T17e preparation custody lost")?;
                    if observation.higher_voltage.is_some() {
                        return Err("T17e higher voltage already retained".into());
                    }
                    observation.higher_command = Some(command);
                    observation.higher_voltage = state.voltage_attempts.pop_front();
                    drop(retained);
                    drop(state);
                    completed
                        .send(PicCompletion::HigherVoltage)
                        .map_err(|_| "T17e preparation ASIC worker disconnected")?;
                }
            }
        }
    }

    fn preparation_guard(
        &self,
        state: &AsicState,
        line: &PowerLine<H>,
        point: CommandServicePoint,
        deadline: Instant,
    ) -> Result<(u32, i16), String> {
        self.require_health(deadline)?;
        line.check_active_source(&self.owner, deadline)?;
        self.owner.query_presence(deadline)?;
        let (initial_host, reset_word, cutoff) = {
            let retained = self
                .conditioning_preparation
                .lock()
                .map_err(|_| "T17e preparation custody poisoned")?;
            let observation = retained.as_ref().ok_or("T17e preparation custody lost")?;
            if let Some(snapshot) = observation.thermal.last() {
                self.preparation_validate_thermal(snapshot, observation.cutoff_c)?;
            }
            (
                observation.reset.requested_host_register(),
                observation.reset_word,
                observation.cutoff_c,
            )
        };
        let host = state
            .operational_baud
            .as_ref()
            .and_then(|baud| baud.host_readback())
            .unwrap_or(initial_host);
        if self.owner.hardware.read(0x3c)? != host
            || self.owner.hardware.read(0x34)? != reset_word
            || self.owner.hardware.read(DHASH)? & RUN != 0
            || (!matches!(point, CommandServicePoint::Poll)
                && self.owner.hardware.read(BC)? & BUSY != 0)
        {
            return Err("T17e preparation source, reset, host or engine state changed".into());
        }
        self.owner.check(deadline, false)?;
        Ok((initial_host, cutoff))
    }

    fn preparation_service(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        watermark: &mut u64,
        point: CommandServicePoint,
        deadline: Instant,
    ) -> Result<(), String> {
        let (initial_host, cutoff) = self.preparation_guard(state, line, point, deadline)?;
        // These bytes remain in the pending queue until their actual complete
        // snapshot takes custody. Partial automatic setup cannot qualify one.
        for raw in &state.pending {
            if let ReturnPayload::Temperature(sample) = raw.payload() {
                if Instant::now()
                    .checked_duration_since(sample.received_at())
                    .is_none_or(|age| age >= Duration::from_millis(6960))
                {
                    return Err("T17e preparation pending thermal record became stale".into());
                }
                for (raw_channel, temperature) in sample
                    .raw_channels()
                    .into_iter()
                    .zip(sample.temperatures_c(Bm1396SensorSamplingMode::Mode0))
                {
                    if raw_channel != 0 && temperature >= cutoff {
                        return Err("T17e preparation temperature reached configured cutoff".into());
                    }
                }
            }
        }
        if matches!(point, CommandServicePoint::BeforePublish) {
            return Ok(());
        }
        if state
            .thermal
            .as_ref()
            .is_some_and(|thermal| thermal.configuration_matches_host(initial_host))
        {
            if let Some(snapshot) = self
                .owner
                .collect_thermal_locked(state, *watermark, deadline)?
            {
                let mut retained = self
                    .conditioning_preparation
                    .lock()
                    .map_err(|_| "T17e preparation custody poisoned")?;
                let observation = retained.as_mut().ok_or("T17e preparation custody lost")?;
                if observation.thermal.len() >= THERMAL_CAPACITY
                    || observation.thermal_records + snapshot.raw_records().len()
                        > THERMAL_RECORD_CAPACITY
                {
                    return Err("T17e preparation thermal retention exhausted; snapshot remains in ASIC owner".into());
                }
                observation.thermal_records += snapshot.raw_records().len();
                observation.thermal.push(snapshot.clone());
                drop(retained);
                self.owner
                    .acknowledge_thermal_snapshot_locked(state, &snapshot)?;
                *watermark = state.next_return;
                self.preparation_validate_thermal(&snapshot, cutoff)?;
            }
        }
        self.preparation_guard(state, line, point, deadline)
            .map(|_| ())
    }

    pub(super) fn preparation_validate_thermal(
        &self,
        snapshot: &ThermalSnapshot,
        cutoff: i16,
    ) -> Result<(), String> {
        if !snapshot.is_fresh_at(Instant::now()) {
            return Err("T17e preparation thermal snapshot stale".into());
        }
        for &chain in &self.owner.chains {
            for channel in 0..2 {
                let mut valid = false;
                for sample in snapshot
                    .samples()
                    .iter()
                    .filter(|sample| sample.register().chain_slot == chain)
                {
                    if sample.raw_channels()[channel] == 0 {
                        continue;
                    }
                    valid = true;
                    if sample.temperatures_c(snapshot.sampling_mode())[channel] >= cutoff {
                        return Err("T17e preparation temperature reached configured cutoff".into());
                    }
                }
                if !valid {
                    return Err("T17e preparation sensor channel has no valid position".into());
                }
            }
        }
        Ok(())
    }

    fn preparation_receive(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        watermark: &mut u64,
        deadline: Instant,
    ) -> Result<(), String> {
        self.preparation_guard(state, line, CommandServicePoint::IdleReceive, deadline)?;
        self.owner.receive_locked(state, 128, deadline)?;
        self.preparation_service(
            state,
            line,
            watermark,
            CommandServicePoint::IdleReceive,
            deadline,
        )
    }

    /// Exact containing-caller delay, with the same FIFO and safety service as
    /// the surrounding producers. This adds no receipt from a future phase.
    fn preparation_wait(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        watermark: &mut u64,
        milliseconds: usize,
        deadline: Instant,
    ) -> Result<(), String> {
        for _ in 0..milliseconds {
            self.preparation_receive(state, line, watermark, deadline)?;
            self.owner
                .delay(Duration::from_millis(1), deadline, false)?;
        }
        self.preparation_receive(state, line, watermark, deadline)
    }

    fn preparation_stage(&self, stage: ConditioningPreparationStage) -> Result<(), String> {
        self.conditioning_preparation
            .lock()
            .map_err(|_| "T17e preparation custody poisoned")?
            .as_mut()
            .ok_or("T17e preparation custody lost")?
            .stage = stage;
        Ok(())
    }

    fn preparation_sequence(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        requests: &SyncSender<PicRequest>,
        completed: &Receiver<PicCompletion>,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut watermark = state.next_return;
        for phase in 0..2 {
            loop {
                self.preparation_receive(state, line, &mut watermark, deadline)?;
                match completed.try_recv() {
                    Ok(PicCompletion::Ready) if phase == 0 => break,
                    Ok(PicCompletion::HigherVoltage) if phase == 1 => break,
                    Ok(_) => return Err("T17e preparation PIC result out of order".into()),
                    Err(TryRecvError::Disconnected) => {
                        return Err("T17e preparation PIC worker stopped before completion".into())
                    }
                    Err(TryRecvError::Empty) => {
                        self.owner
                            .delay(Duration::from_millis(1), deadline, false)?
                    }
                }
            }
            if phase == 0 {
                self.preparation_stage(ConditioningPreparationStage::HigherVoltage)?;
                requests
                    .try_send(PicRequest::HigherVoltage)
                    .map_err(|_| "T17e preparation PIC request channel unavailable")?;
            }
        }
        self.preparation_stage(ConditioningPreparationStage::ColdRegisters)?;
        self.owner
            .initialize_cold_registers_serviced(state, deadline, &mut |state, point| {
                self.preparation_service(state, line, &mut watermark, point, deadline)
            })?;
        {
            let mut retained = self
                .conditioning_preparation
                .lock()
                .map_err(|_| "T17e preparation custody poisoned")?;
            let observation = retained.as_mut().ok_or("T17e preparation custody lost")?;
            observation.assignment = state.assignment.clone();
            observation.cold = state.cold_registers.clone();
        }
        self.preparation_stage(ConditioningPreparationStage::BaselineAdc)?;
        self.owner
            .acquire_domain_adc_serviced(state, deadline, |state, point| {
                // ADC owns its command loop directly; unlike the extracted startup
                // helper it delegates the actual busy receive to its caller.
                if matches!(point, CommandServicePoint::Poll) {
                    self.owner.receive_locked(state, 128, deadline)?;
                }
                self.preparation_service(state, line, &mut watermark, point, deadline)
            })?;
        if state
            .domain_adc
            .as_ref()
            .is_none_or(|adc| adc.baseline_minimum_passed() != Some(true))
        {
            return Err("T17e preparation Baseline ADC did not pass".into());
        }
        self.conditioning_preparation
            .lock()
            .map_err(|_| "T17e preparation custody poisoned")?
            .as_mut()
            .ok_or("T17e preparation custody lost")?
            .baseline_adc = state.domain_adc.clone();
        self.preparation_stage(ConditioningPreparationStage::ThermalConfiguration)?;
        self.owner.configure_thermal_serviced(
            state,
            Bm1396SensorSamplingMode::Mode0,
            deadline,
            &mut |state, point| {
                self.preparation_service(state, line, &mut watermark, point, deadline)
            },
        )?;
        self.conditioning_preparation
            .lock()
            .map_err(|_| "T17e preparation custody poisoned")?
            .as_mut()
            .ok_or("T17e preparation custody lost")?
            .thermal_configuration = state
            .thermal
            .as_ref()
            .and_then(|thermal| thermal.complete_configuration())
            .cloned();
        // Complete original16958 calls delay_ms(10) after thermal_setup.
        self.preparation_wait(state, line, &mut watermark, 10, deadline)?;
        self.preparation_stage(ConditioningPreparationStage::OperationalBaud)?;
        self.owner
            .switch_to_operational_baud_serviced(state, deadline, &mut |state, point| {
                self.preparation_service(state, line, &mut watermark, point, deadline)
            })?;
        self.conditioning_preparation
            .lock()
            .map_err(|_| "T17e preparation custody poisoned")?
            .as_mut()
            .ok_or("T17e preparation custody lost")?
            .baud = state.operational_baud.clone();
        // A second original caller delay follows actual operational-baud return.
        self.preparation_wait(state, line, &mut watermark, 10, deadline)?;
        self.preparation_stage(ConditioningPreparationStage::FreshThermal)?;
        // Require a new complete population after the actual baud switch and
        // its readback queries, not a snapshot retained during setup.
        watermark = state.next_return;
        let before = self
            .conditioning_preparation
            .lock()
            .map_err(|_| "T17e preparation custody poisoned")?
            .as_ref()
            .ok_or("T17e preparation custody lost")?
            .thermal
            .len();
        for tick in 0..6970 {
            self.preparation_receive(state, line, &mut watermark, deadline)?;
            if self
                .conditioning_preparation
                .lock()
                .map_err(|_| "T17e preparation custody poisoned")?
                .as_ref()
                .ok_or("T17e preparation custody lost")?
                .thermal
                .len()
                > before
            {
                return Ok(());
            }
            if tick == 6969 {
                return Err("T17e preparation fresh thermal population timed out".into());
            }
            self.owner
                .delay(Duration::from_millis(1), deadline, false)?;
        }
        unreachable!("bounded thermal loop returns")
    }
}
