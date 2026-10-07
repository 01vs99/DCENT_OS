//! Exact T17e second reset and adapted ADC/thermal requalification.
//! The caller owns independent fan, heartbeat, watchdog and source-high actors.
//! The absolute phase deadline is a native execution bound, not evidence of a
//! physically safe sensor-suspension interval. Automatic44 has no wire epoch.
use super::*;
use dcentrald_common::{Bm1396DomainVoltageAdaptiveLevel, Bm1396SensorSamplingMode};

const ADAPTED_THERMAL_RECORDS: usize = 65_536;
const ADAPTED_THERMAL_POPULATIONS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdaptedStartupStage {
    Admitted,
    Reset,
    HigherVoltage,
    ColdRegisters,
    AdaptedAdc,
    ThermalConfiguration,
    OperationalBaud,
    FreshThermal,
}

/// Retains the actual first-pass predecessor and the second phase separately.
/// A completed receipt proves this observed protocol sequence, not electrical
/// reset/rail/PLL behavior or the physical production age of an automatic reply.
#[derive(Clone, Debug)]
pub struct AdaptedStartupObservation {
    predecessor: AdaptedPredecessor,
    stage: AdaptedStartupStage,
    epoch: u64,
    reset: Option<ConditioningResetObservation>,
    higher_voltage: Option<VoltageAttempt>,
    higher_command: Option<CommandedVoltage>,
    assignment: Option<AssignmentObservation>,
    cold: Option<ColdRegisterObservation>,
    adc: Option<DomainAdcObservation>,
    thermal_configuration: Option<ThermalConfiguration>,
    baud: Option<OperationalBaudObservation>,
    // Exact unchanged raw records, including current-configuration records that
    // arrived before the final watermark. These are never current admission.
    prequalification: Vec<PreservedReturn>,
    thermal: Vec<ThermalSnapshot>,
    receive_watermark: Option<u64>,
    completed_at: Option<Instant>,
    failure: Option<String>,
}
impl AdaptedStartupObservation {
    pub fn same_owner<H: Hardware>(&self, owner: &Arc<Transport<H>>) -> bool {
        Arc::ptr_eq(&self.predecessor.issuer, &owner.identity)
    }
    pub fn predecessor_preparation(&self) -> &ConditioningPreparationObservation {
        &self.predecessor.preparation
    }
    pub fn predecessor_pll(&self) -> &ColdPllObservation {
        &self.predecessor.pll
    }
    pub fn predecessor_voltage(&self) -> CommandedVoltage {
        self.predecessor.current_voltage
    }
    pub fn admitted_at(&self) -> Instant {
        self.predecessor.captured_at
    }
    pub fn phase_deadline(&self) -> Instant {
        self.predecessor.phase_deadline
    }
    pub fn stage(&self) -> AdaptedStartupStage {
        self.stage
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn reset(&self) -> Option<&ConditioningResetObservation> {
        self.reset.as_ref()
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
    pub fn adapted_adc(&self) -> Option<&DomainAdcObservation> {
        self.adc.as_ref()
    }
    pub fn thermal_configuration(&self) -> Option<&ThermalConfiguration> {
        self.thermal_configuration.as_ref()
    }
    pub fn operational_baud(&self) -> Option<&OperationalBaudObservation> {
        self.baud.as_ref()
    }
    pub fn prequalification_records(&self) -> &[PreservedReturn] {
        &self.prequalification
    }
    pub fn thermal_snapshots(&self) -> &[ThermalSnapshot] {
        &self.thermal
    }
    pub fn receive_watermark(&self) -> Option<u64> {
        self.receive_watermark
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
}

/// Read-only current phase data for independent supervision. This value is
/// never accepted by a reset/PLL/work admission method; all authority remains
/// in the original retained observation and its private predecessor.
#[derive(Clone, Debug)]
pub struct AdaptedStartupHealth {
    stage: AdaptedStartupStage,
    epoch: u64,
    phase_deadline: Instant,
    completed_at: Option<Instant>,
    failed: bool,
    latest: Option<ThermalSnapshot>,
}
impl AdaptedStartupHealth {
    pub fn stage(&self) -> AdaptedStartupStage {
        self.stage
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn phase_deadline(&self) -> Instant {
        self.phase_deadline
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
    pub fn failed(&self) -> bool {
        self.failed
    }
    pub fn latest_thermal(&self) -> Option<&ThermalSnapshot> {
        self.latest.as_ref()
    }
}

impl<H: Hardware> PicApplication<H> {
    /// Copy only the current phase fields and latest actual population, avoiding
    /// full predecessor/prequalification history cloning in every health tick.
    pub fn adapted_startup_health(&self) -> Result<Option<AdaptedStartupHealth>, String> {
        let retained = self
            .adapted_startup
            .lock()
            .map_err(|_| "T17e adapted custody poisoned")?;
        Ok(retained.as_ref().map(|row| AdaptedStartupHealth {
            stage: row.stage,
            epoch: row.epoch,
            phase_deadline: row.predecessor.phase_deadline,
            completed_at: row.completed_at,
            failed: row.failure.is_some(),
            latest: row.thermal.last().cloned(),
        }))
    }

    pub fn adapted_startup_observation(&self) -> Result<Option<AdaptedStartupObservation>, String> {
        Ok(self
            .adapted_startup
            .lock()
            .map_err(|_| "T17e adapted custody poisoned")?
            .clone())
    }

    /// One second reset after this same source's actual conditioning300 and
    /// final Baseline ADC. The whole reset/higher/cold/Adapted ADC/thermal/baud
    /// phase retains the ASIC mutex and a counted PIC worker's logical lease.
    pub async fn initialize_adapted_startup(
        self: &Arc<Self>,
        line: Arc<PowerLine<H>>,
        deadline: Instant,
    ) -> Result<AdaptedStartupObservation, String> {
        let app = self.clone();
        let runtime = tokio::runtime::Handle::current();
        self.owner
            .worker(deadline, false, move |owner| {
                let mut state = owner.lock(&owner.asic, deadline, false)?;
                let predecessor =
                    Arc::new(app.capture_adapted_predecessor_locked(&state, &line, deadline)?);
                if state.thermal_epoch != 0
                    || state.adc_level != Bm1396DomainVoltageAdaptiveLevel::Baseline
                    || state.prior_thermal.is_some()
                    || state.prior_assignment.is_some()
                    || state.prior_cold_registers.is_some()
                    || state.prior_domain_adc.is_some()
                    || state.prior_operational_baud.is_some()
                    || state.requalification_deadline.is_some()
                    || predecessor.reset
                        & owner
                            .chains
                            .iter()
                            .fold(0u32, |bits, &chain| bits | (1 << chain))
                        != 0
                {
                    return Err("T17e adapted epoch is already spent or reset is asserted".into());
                }
                {
                    // Fixed order adapted_startup -> adapted_reset. No path holds
                    // either while taking the physical PIC lane or ASIC mutex.
                    let mut retained = app
                        .adapted_startup
                        .lock()
                        .map_err(|_| "T17e adapted custody poisoned")?;
                    let mut reset = app
                        .adapted_reset
                        .lock()
                        .map_err(|_| "T17e adapted reset custody poisoned")?;
                    if retained.is_some() || reset.is_some() {
                        return Err("T17e adapted attempt already spent".into());
                    }
                    *reset = Some(ConditioningResetObservation {
                        issuer: owner.identity.clone(),
                        source: predecessor.preparation.reset().source().clone(),
                        old_host: predecessor.host,
                        requested_host: (predecessor.host & 0xc0c0_c0c0) | 0x1a1a_1a1a,
                        events: Vec::new(),
                        low_voltage: None,
                        unsolicited: Vec::new(),
                        census: Vec::new(),
                        completed_chains: Vec::new(),
                        completed_at: None,
                        failure: None,
                    });
                    *retained = Some(AdaptedStartupObservation {
                        predecessor: (*predecessor).clone(),
                        stage: AdaptedStartupStage::Admitted,
                        epoch: 1,
                        reset: None,
                        higher_voltage: None,
                        higher_command: None,
                        assignment: None,
                        cold: None,
                        adc: None,
                        thermal_configuration: None,
                        baud: None,
                        prequalification: Vec::new(),
                        thermal: Vec::new(),
                        receive_watermark: None,
                        completed_at: None,
                        failure: None,
                    });
                }
                let (requests, request_rx) = mpsc::sync_channel(1);
                let (completion_tx, completed) = mpsc::sync_channel(1);
                let pic_app = app.clone();
                let pic_owner = owner.clone();
                let pic_predecessor = predecessor.clone();
                let pic_worker =
                    runtime.spawn(async move {
                        pic_owner
                            .worker(deadline, false, move |_| {
                                let lease = pic_app.voltage_lease(deadline)?;
                                ResetTransaction::adapted(&pic_app, &pic_predecessor)
                                    .reset_pic_loop(&lease, request_rx, completion_tx, deadline)
                            })
                            .await
                    });
                let transaction = ResetTransaction::adapted(&app, &predecessor);
                let result = transaction
                    .adapted_sequence(&mut state, &line, &requests, &completed, deadline);
                if result.is_err() {
                    owner.begin_terminal();
                }
                drop(requests);
                let pic_result = runtime
                    .block_on(pic_worker)
                    .map_err(|e| format!("T17e adapted PIC worker join: {e}"))
                    .and_then(|r| r);
                // Reacquire the same logical lease for final retained completion.
                // A competing mutation in the PIC-exit handoff is detected by
                // the exact generation/current-command check below.
                let completion_lease = if result.is_ok() && pic_result.is_ok() {
                    app.voltage_lease_serviced(deadline, || {
                        // Keep all post-qualification populations under current
                        // epoch custody while an actual competitor owns the lease.
                        let watermark = app
                            .adapted_startup
                            .lock()
                            .map_err(|_| "T17e adapted custody poisoned")?
                            .as_ref()
                            .and_then(|row| row.receive_watermark)
                            .ok_or("T17e adapted completion watermark absent")?;
                        transaction.adapted_receive(
                            &mut state,
                            &line,
                            Some(watermark),
                            deadline,
                        )?;
                        transaction.adapted_final_guard(&state, &line, deadline)
                    })
                    .map(Some)
                } else {
                    Ok(None)
                };
                let result = match (result, pic_result) {
                    (Ok(()), Ok(())) => match &completion_lease {
                        Ok(Some(lease)) => transaction
                            .adapted_voltage_completion(lease)
                            .and_then(|_| transaction.adapted_final_guard(&state, &line, deadline)),
                        Err(error) => Err(error.clone()),
                        Ok(None) => Err("T17e adapted completion lease absent".into()),
                    },
                    (Err(a), Err(b)) => Err(format!("{a}; PIC worker: {b}")),
                    (Err(error), _) | (_, Err(error)) => Err(error),
                };
                // Copy partial evidence even when a helper fails; the original raw
                // pending queues and helper receipts also remain under this owner.
                let mut retained = app
                    .adapted_startup
                    .lock()
                    .map_err(|_| "T17e adapted custody poisoned")?;
                let mut reset = app
                    .adapted_reset
                    .lock()
                    .map_err(|_| "T17e adapted reset custody poisoned")?;
                let observation = retained.as_mut().ok_or("T17e adapted custody lost")?;
                if state.thermal_epoch == observation.epoch {
                    observation.assignment = state.assignment.clone();
                    observation.cold = state.cold_registers.clone();
                    observation.adc = state.domain_adc.clone();
                    observation.baud = state.operational_baud.clone();
                    observation.thermal_configuration = state
                        .thermal
                        .as_ref()
                        .and_then(|thermal| thermal.complete_configuration())
                        .cloned();
                }
                if let Err(error) = result {
                    owner.begin_terminal();
                    observation.failure = Some(error.clone());
                    if let Some(reset) = reset.as_mut().filter(|reset| reset.completed_at.is_none())
                    {
                        reset.failure = Some(error.clone());
                    }
                    observation.reset = reset.clone();
                    return Err(error);
                }
                observation.reset = reset.clone();
                state.requalification_deadline = None;
                observation.completed_at = Some(Instant::now());
                Ok(observation.clone())
            })
            .await
    }

    pub(super) fn retain_adapted_higher(&self, command: CommandedVoltage) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "T17e adapted PIC state poisoned")?;
        let mut retained = self
            .adapted_startup
            .lock()
            .map_err(|_| "T17e adapted custody poisoned")?;
        let observation = retained.as_mut().ok_or("T17e adapted custody lost")?;
        let low = self
            .adapted_reset
            .lock()
            .map_err(|_| "T17e adapted reset custody poisoned")?;
        let low = low
            .as_ref()
            .and_then(|r| r.low_voltage.as_ref())
            .ok_or("T17e adapted lower receipt lost")?;
        let attempt = state
            .voltage_attempts
            .front()
            .ok_or("T17e adapted higher attempt lost")?;
        if observation.higher_voltage.is_some()
            || attempt.completed_at().is_none()
            || attempt.sequence()
                != observation
                    .predecessor
                    .next_voltage
                    .checked_add(1)
                    .ok_or("T17e adapted generation overflow")?
            || attempt.prior_command().is_none_or(|prior| {
                prior.requested_centivolts() != 1800
                    || low.completed_at() != Some(prior.completed_at())
            })
            || attempt.requested_centivolts() != 2000
            || command.requested_centivolts() != 2000
        {
            return Err("T17e adapted higher command lineage differs".into());
        }
        observation.higher_voltage = state.voltage_attempts.pop_front();
        observation.higher_command = Some(command);
        Ok(())
    }

    pub(super) fn check_adapted_pending_temperature(
        &self,
        state: &AsicState,
        cutoff: i16,
    ) -> Result<(), String> {
        for raw in &state.pending {
            let sample = match raw.payload() {
                ReturnPayload::Temperature(sample)
                | ReturnPayload::HistoricalTemperature(sample) => sample,
                _ => continue,
            };
            for (raw, temperature) in sample
                .raw_channels()
                .into_iter()
                .zip(sample.temperatures_c(Bm1396SensorSamplingMode::Mode0))
            {
                if raw != 0 && temperature >= cutoff {
                    return Err("T17e adapted pending temperature reached cutoff".into());
                }
            }
        }
        Ok(())
    }

    pub(super) fn retain_adapted_temperatures(
        &self,
        state: &mut AsicState,
        all: bool,
    ) -> Result<(), String> {
        let selected = |raw: &PreservedReturn| match raw.payload() {
            ReturnPayload::HistoricalTemperature(_) => true,
            ReturnPayload::Temperature(sample) => all || sample.epoch() != state.thermal_epoch,
            _ => false,
        };
        let records: Vec<_> = state
            .pending
            .iter()
            .filter(|raw| selected(raw))
            .cloned()
            .collect();
        if records.is_empty() {
            return Ok(());
        }
        let mut retained = self
            .adapted_startup
            .lock()
            .map_err(|_| "T17e adapted custody poisoned")?;
        let observation = retained.as_mut().ok_or("T17e adapted custody lost")?;
        if observation.prequalification.len() + records.len() > ADAPTED_THERMAL_RECORDS {
            return Err(
                "T17e adapted prequalification capacity exhausted; pending retained".into(),
            );
        }
        let sequences: Vec<_> = records.iter().map(PreservedReturn::sequence).collect();
        observation.prequalification.extend(records);
        state
            .pending
            .retain(|raw| !sequences.contains(&raw.sequence()));
        Ok(())
    }
}

impl<H: Hardware> ResetTransaction<'_, H> {
    fn adapted_stage(&self, stage: AdaptedStartupStage) -> Result<(), String> {
        self.adapted_startup
            .lock()
            .map_err(|_| "T17e adapted custody poisoned")?
            .as_mut()
            .ok_or("T17e adapted custody lost")?
            .stage = stage;
        Ok(())
    }

    fn adapted_guard(
        &self,
        state: &AsicState,
        line: &PowerLine<H>,
        point: CommandServicePoint,
        deadline: Instant,
    ) -> Result<(), String> {
        let prior = self.predecessor.ok_or("T17e adapted predecessor lost")?;
        if state.requalification_deadline != Some(deadline)
            || state.thermal_epoch != 1
            || state.adc_level != Bm1396DomainVoltageAdaptiveLevel::Adapted
        {
            return Err("T17e adapted private epoch/deadline changed".into());
        }
        let initial_host = (prior.host & 0xc0c0_c0c0) | 0x1a1a_1a1a;
        let host = state
            .operational_baud
            .as_ref()
            .and_then(|baud| baud.host_readback())
            .unwrap_or(initial_host);
        self.reset_guard(
            line,
            host,
            Some(prior.reset),
            matches!(point, CommandServicePoint::Poll),
            deadline,
        )?;
        self.check_adapted_pending_temperature(state, prior.preparation.cutoff_c())
    }

    fn adapted_service(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        watermark: Option<u64>,
        point: CommandServicePoint,
        deadline: Instant,
    ) -> Result<(), String> {
        self.adapted_guard(state, line, point, deadline)?;
        if matches!(point, CommandServicePoint::BeforePublish) {
            return Ok(());
        }
        self.retain_adapted_temperatures(state, watermark.is_none())?;
        if let Some(watermark) = watermark {
            if let Some(snapshot) = self
                .owner
                .collect_thermal_locked(state, watermark, deadline)?
            {
                let mut retained = self
                    .adapted_startup
                    .lock()
                    .map_err(|_| "T17e adapted custody poisoned")?;
                let observation = retained.as_mut().ok_or("T17e adapted custody lost")?;
                if snapshot.epoch() != observation.epoch
                    || observation.thermal.len() >= ADAPTED_THERMAL_POPULATIONS
                    || observation
                        .thermal
                        .iter()
                        .map(|row| row.raw_records().len())
                        .sum::<usize>()
                        + snapshot.raw_records().len()
                        > ADAPTED_THERMAL_RECORDS
                {
                    return Err(
                        "T17e adapted thermal epoch/capacity differs; snapshot retained".into(),
                    );
                }
                observation.thermal.push(snapshot.clone());
                drop(retained);
                self.owner
                    .acknowledge_thermal_snapshot_locked(state, &snapshot)?;
                self.preparation_validate_thermal(
                    &snapshot,
                    self.predecessor.expect("adapted").preparation.cutoff_c(),
                )?;
            }
        }
        self.adapted_guard(state, line, point, deadline)
    }

    fn adapted_receive(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        watermark: Option<u64>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.adapted_guard(state, line, CommandServicePoint::IdleReceive, deadline)?;
        self.owner.receive_locked(state, 128, deadline)?;
        self.adapted_service(
            state,
            line,
            watermark,
            CommandServicePoint::IdleReceive,
            deadline,
        )
    }
    fn adapted_wait(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        milliseconds: usize,
        deadline: Instant,
    ) -> Result<(), String> {
        for _ in 0..milliseconds {
            self.adapted_receive(state, line, None, deadline)?;
            self.owner
                .delay(Duration::from_millis(1), deadline, false)?;
        }
        self.adapted_receive(state, line, None, deadline)
    }

    fn adapted_sequence(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        requests: &SyncSender<PicRequest>,
        completed: &Receiver<PicCompletion>,
        deadline: Instant,
    ) -> Result<(), String> {
        let prior = self.predecessor.ok_or("T17e adapted predecessor lost")?;
        if !matches!(
            self.reset_completion(
                state,
                line,
                prior.host,
                Some(prior.reset),
                completed,
                deadline
            )?,
            PicCompletion::Ready
        ) {
            return Err("T17e adapted first PIC completion is not lease admission".into());
        }
        // Ready means the counted PIC worker owns the exact validated lease.
        // Fresh old-epoch safety is rechecked immediately before the one-way
        // reset interval. Historical timestamps are never altered or extended.
        self.preparation_validate_thermal(
            prior
                .pll
                .thermal_snapshots()
                .last()
                .ok_or("T17e adapted prior thermal absent")?,
            prior.preparation.cutoff_c(),
        )?;
        self.reset_guard(line, prior.host, Some(prior.reset), false, deadline)?;
        state.prior_thermal = state.thermal.take();
        state.prior_assignment = state.assignment.take();
        state.prior_cold_registers = state.cold_registers.take();
        state.prior_domain_adc = state.domain_adc.take();
        state.prior_operational_baud = state.operational_baud.take();
        state.thermal_epoch = 1;
        state.adc_level = Bm1396DomainVoltageAdaptiveLevel::Adapted;
        state.requalification_deadline = Some(deadline);
        self.adapted_stage(AdaptedStartupStage::Reset)?;
        self.reset_sequence(state, line, prior.host, requests, completed, deadline)?;
        {
            let mut retained = self
                .retained
                .lock()
                .map_err(|_| "T17e adapted reset custody poisoned")?;
            retained
                .as_mut()
                .ok_or("T17e adapted reset custody lost")?
                .completed_at = Some(Instant::now());
        }
        self.adapted_stage(AdaptedStartupStage::HigherVoltage)?;
        requests
            .try_send(PicRequest::HighVoltage)
            .map_err(|_| "T17e adapted higher request unavailable")?;
        if !matches!(
            self.reset_completion(
                state,
                line,
                (prior.host & 0xc0c0_c0c0) | 0x1a1a_1a1a,
                Some(prior.reset),
                completed,
                deadline
            )?,
            PicCompletion::HighVoltage
        ) {
            return Err("T17e adapted higher completion changed".into());
        }
        self.adapted_stage(AdaptedStartupStage::ColdRegisters)?;
        // No public caller can reach this one-way reset: ASIC custody has not
        // been released, DMA/work are absent, and a failure latches terminal.
        state.startup_attempted = false;
        self.owner
            .initialize_cold_registers_serviced(state, deadline, &mut |state, point| {
                self.adapted_service(state, line, None, point, deadline)
            })?;
        self.adapted_stage(AdaptedStartupStage::AdaptedAdc)?;
        self.owner
            .acquire_domain_adc_serviced(state, deadline, |state, point| {
                if matches!(point, CommandServicePoint::Poll) {
                    self.owner.receive_locked(state, 128, deadline)?;
                }
                self.adapted_service(state, line, None, point, deadline)
            })?;
        if state
            .domain_adc
            .as_ref()
            .is_none_or(|adc| adc.adapted_minimum_passed() != Some(true))
        {
            return Err("T17e adapted ADC minimum did not pass".into());
        }
        self.adapted_stage(AdaptedStartupStage::ThermalConfiguration)?;
        self.owner.configure_thermal_serviced(
            state,
            Bm1396SensorSamplingMode::Mode0,
            deadline,
            &mut |state, point| self.adapted_service(state, line, None, point, deadline),
        )?;
        self.adapted_wait(state, line, 10, deadline)?;
        self.adapted_stage(AdaptedStartupStage::OperationalBaud)?;
        self.owner
            .switch_to_operational_baud_serviced(state, deadline, &mut |state, point| {
                self.adapted_service(state, line, None, point, deadline)
            })?;
        self.adapted_wait(state, line, 10, deadline)?;
        self.adapted_stage(AdaptedStartupStage::FreshThermal)?;
        // The actual new setup/readback and both source waits precede this
        // watermark. There is no wire epoch; later arrivals are receive-custody
        // evidence only, not a claim of physically newer sensor production.
        let watermark = state.next_return;
        self.adapted_startup
            .lock()
            .map_err(|_| "T17e adapted custody poisoned")?
            .as_mut()
            .ok_or("T17e adapted custody lost")?
            .receive_watermark = Some(watermark);
        for tick in 0..6970 {
            self.adapted_receive(state, line, Some(watermark), deadline)?;
            if self
                .adapted_startup
                .lock()
                .map_err(|_| "T17e adapted custody poisoned")?
                .as_ref()
                .ok_or("T17e adapted custody lost")?
                .thermal
                .last()
                .is_some()
            {
                return self.adapted_final_guard(state, line, deadline);
            }
            if tick != 6969 {
                self.owner
                    .delay(Duration::from_millis(1), deadline, false)?;
            }
        }
        Err("T17e adapted fresh complete thermal population timed out".into())
    }

    fn adapted_voltage_completion(&self, lease: &VoltageLease<'_>) -> Result<(), String> {
        self.require_voltage_lease(lease)?;
        let state = self
            .state
            .lock()
            .map_err(|_| "T17e adapted PIC state poisoned")?;
        let retained = self
            .adapted_startup
            .lock()
            .map_err(|_| "T17e adapted custody poisoned")?;
        let observation = retained.as_ref().ok_or("T17e adapted custody lost")?;
        if state.next_voltage
            != observation
                .predecessor
                .next_voltage
                .checked_add(2)
                .ok_or("T17e adapted generation overflow")?
            || observation.higher_command.is_none()
            || state.last_voltage != observation.higher_command
            || !state.voltage_attempts.is_empty()
            || !state.rails.is_empty()
            || !state.rail_verifications.is_empty()
        {
            return Err("T17e adapted voltage changed before retained completion".into());
        }
        Ok(())
    }

    fn adapted_final_guard(
        &self,
        state: &AsicState,
        line: &PowerLine<H>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.adapted_guard(state, line, CommandServicePoint::IdleReceive, deadline)?;
        let retained = self
            .adapted_startup
            .lock()
            .map_err(|_| "T17e adapted custody poisoned")?;
        let observation = retained.as_ref().ok_or("T17e adapted custody lost")?;
        let snapshot = observation
            .thermal
            .last()
            .ok_or("T17e adapted final thermal absent")?;
        if snapshot.epoch() != state.thermal_epoch
            || snapshot
                .samples()
                .iter()
                .any(|sample| sample.is_historical() || sample.epoch() != state.thermal_epoch)
            || state
                .domain_adc
                .as_ref()
                .is_none_or(|adc| adc.adapted_minimum_passed() != Some(true))
            || state
                .operational_baud
                .as_ref()
                .is_none_or(|baud| baud.completed_at().is_none())
        {
            return Err("T17e adapted final current epoch qualification differs".into());
        }
        self.preparation_validate_thermal(
            snapshot,
            observation.predecessor.preparation.cutoff_c(),
        )?;
        self.owner.check(deadline, false)
    }
}
