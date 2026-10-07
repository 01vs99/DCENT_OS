//! Detached private adapted-pass predecessor and logical voltage admission.
//! No reset, thermal grace or ADC phase mutation is performed by this helper.
//! The future second-reset controller must retain ASIC custody across capture,
//! counted PIC lease validation, archive/epoch mutation and full requalification.
use super::*;

#[derive(Clone, Debug)]
pub(super) struct AdaptedPredecessor {
    pub(super) issuer: Arc<()>,
    pub(super) preparation: ConditioningPreparationObservation,
    pub(super) pll: ColdPllObservation,
    pub(super) current_voltage: CommandedVoltage,
    pub(super) next_voltage: u64,
    pub(super) host: u32,
    pub(super) reset: u32,
    pub(super) captured_at: Instant,
    pub(super) phase_deadline: Instant,
}

impl<H: Hardware> PicApplication<H> {
    // Caller holds the actual ASIC mutex. This captures history, never an
    // authorization to suspend thermal checks or issue a source/reset command.
    pub(super) fn capture_adapted_predecessor_locked(
        &self,
        state: &AsicState,
        line: &PowerLine<H>,
        phase_deadline: Instant,
    ) -> Result<AdaptedPredecessor, String> {
        self.require_health(phase_deadline)?;
        line.check_active_source(&self.owner, phase_deadline)?;
        if self.owner.model != Model::T17e
            || !state.startup_attempted
            || state.dma_initialized
            || !state.publications.is_empty()
            || !state.register_observations.is_empty()
            || self.owner.hardware.read(DHASH)? & RUN != 0
        {
            return Err("T17e adapted predecessor requires exact never-worked cold owner".into());
        }
        let preparation = self
            .conditioning_preparation_observation()?
            .ok_or("T17e adapted predecessor preparation absent")?;
        let pll = self
            .cold_pll_observation()?
            .ok_or("T17e adapted predecessor PLL absent")?;
        if !preparation.same_owner(&self.owner)
            || preparation.completed_at().is_none()
            || preparation.failure().is_some()
            || pll.completed_at().is_none()
            || pll.failure().is_some()
            || pll.preparation_completed_at() != preparation.completed_at()
            || pll.initial_voltage() != preparation.higher_command()
            || state.assignment.as_ref() != preparation.assignment()
            || state.cold_registers.as_ref() != preparation.cold_registers()
            || state.operational_baud.as_ref() != preparation.operational_baud()
            || state
                .thermal
                .as_ref()
                .and_then(|t| t.complete_configuration())
                != preparation.thermal_configuration()
            || state
                .thermal
                .as_ref()
                .is_none_or(|t| t.has_pending_snapshots())
            || state.domain_adc.as_ref() != pll.final_adc()
            || pll
                .final_adc()
                .is_none_or(|adc| adc.baseline_minimum_passed() != Some(true))
        {
            return Err("T17e adapted predecessor actual receipt/state join differs".into());
        }
        let frequencies: Vec<_> = pll
            .stages()
            .iter()
            .map(|stage| stage.frequency_mhz())
            .collect();
        if frequencies != [60, 75, 100, 150, 300]
            || pll.stages().iter().any(|stage| {
                stage.settled_at().is_none()
                    || stage.commands().len() != 2 * self.owner.chains.len()
                    || stage
                        .commands()
                        .iter()
                        .any(|command| command.completed_at().is_none())
            })
        {
            return Err("T17e adapted predecessor lacks complete source five-stage PLL".into());
        }
        let thermal = pll
            .thermal_snapshots()
            .last()
            .ok_or("T17e adapted predecessor thermal absent")?;
        self.preparation_validate_thermal(thermal, preparation.cutoff_c())?;
        let host = preparation
            .operational_baud()
            .and_then(|baud| baud.host_readback())
            .ok_or("T17e adapted predecessor host absent")?;
        let reset = preparation
            .reset()
            .events()
            .iter()
            .rev()
            .find_map(|event| match event {
                ConditioningResetEvent::Register {
                    offset: 0x34,
                    value,
                    completed_at: Some(_),
                } => Some(*value),
                _ => None,
            })
            .ok_or("T17e adapted predecessor reset absent")?;
        self.owner.query_presence(phase_deadline)?;
        self.owner.query_host(host, phase_deadline)?;
        if self.owner.hardware.read(0x34)? != reset {
            return Err("T17e adapted predecessor reset changed".into());
        }
        // Derive every consumed generation from retained actual attempts; a
        // same-value command outside this lineage must fail the later lease join.
        let higher = preparation
            .higher_voltage()
            .ok_or("T17e adapted higher attempt absent")?;
        let mut next_voltage = higher
            .sequence()
            .checked_add(1)
            .ok_or("T17e adapted voltage generation overflow")?;
        let mut current = preparation
            .higher_command()
            .ok_or("T17e adapted higher command absent")?;
        let mut verified = None;
        for stage in pll.stages() {
            for plan in stage.voltage_plans() {
                if let Some(attempt) = plan.voltage_attempt() {
                    if attempt.sequence() != next_voltage
                        || attempt.completed_at().is_none()
                        || attempt.prior_command() != Some(current)
                    {
                        return Err("T17e adapted retained voltage lineage is discontinuous".into());
                    }
                    next_voltage = next_voltage
                        .checked_add(1)
                        .ok_or("T17e adapted voltage generation overflow")?;
                    let verification = plan
                        .rail_verification()
                        .ok_or("T17e adapted changed voltage has no verification")?;
                    current = verification.commanded_voltage();
                    if current.requested_centivolts() != attempt.requested_centivolts() {
                        return Err("T17e adapted command/attempt target differs".into());
                    }
                }
                if let Some(verification) = plan.rail_verification() {
                    if verification.passed() != Some(true)
                        || verification.commanded_voltage() != current
                    {
                        return Err(
                            "T17e adapted rail custody does not bind current voltage".into()
                        );
                    }
                    verified = Some(current);
                }
            }
        }
        if verified != Some(current) {
            return Err("T17e adapted current voltage was not verified".into());
        }
        self.owner.check(phase_deadline, false)?;
        Ok(AdaptedPredecessor {
            issuer: self.owner.identity.clone(),
            preparation,
            pll,
            current_voltage: current,
            next_voltage,
            host,
            reset,
            captured_at: Instant::now(),
            phase_deadline,
        })
    }

    // Runs inside the future counted PIC worker while it owns the same actual
    // VoltageLease for the whole reset/requalification phase. No physical lock
    // is retained here, allowing independently scheduled heartbeats between frames.
    pub(super) fn validate_adapted_predecessor_voltage_locked(
        &self,
        lease: &VoltageLease<'_>,
        predecessor: &AdaptedPredecessor,
    ) -> Result<(), String> {
        self.require_voltage_lease(lease)?;
        self.require_health(predecessor.phase_deadline)?;
        if !Arc::ptr_eq(&predecessor.issuer, &self.owner.identity) {
            return Err("T17e adapted predecessor belongs to another owner".into());
        }
        let state = self
            .state
            .lock()
            .map_err(|_| "T17e adapted PIC state poisoned")?;
        if state.next_voltage != predecessor.next_voltage
            || state.last_voltage != Some(predecessor.current_voltage)
            || !state.voltage_attempts.is_empty()
            || !state.rails.is_empty()
            || !state.rail_verifications.is_empty()
        {
            return Err("T17e adapted predecessor voltage generation/custody changed".into());
        }
        Ok(())
    }
}
