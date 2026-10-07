//! Final exact T17e300 source ramp after actual adapted requalification.
//! The original uniform-frequency wrapper has no conditioning ADC tail.
use super::*;
use dcentrald_common::Bm1396DomainVoltageAdaptiveLevel;

#[path = "stock_bm1396_native_pll.rs"]
mod native_pll;
pub use native_pll::NativePllObservation;

#[path = "stock_bm1396_work_owner.rs"]
mod work_owner;
pub use work_owner::{
    FixedWorkControl, FixedWorkEvent, FixedWorkEvents, FixedWorkHealth, FixedWorkInbox,
};

/// A distinct final-pass receipt; the earlier conditioning PLL remains history.
/// Completion records portal writes, source waits and observed rail/thermal
/// checks. It does not establish electrical PLL lock or nonce exhaustion.
#[derive(Clone, Debug)]
pub struct FinalPllObservation {
    adapted: AdaptedStartupObservation,
    sequence: ColdPllObservation,
}
impl FinalPllObservation {
    pub fn same_owner<H: Hardware>(&self, owner: &Arc<Transport<H>>) -> bool {
        Arc::ptr_eq(&self.sequence.issuer, &owner.identity) && self.adapted.same_owner(owner)
    }
    pub fn adapted_startup(&self) -> &AdaptedStartupObservation {
        &self.adapted
    }
    pub fn epoch(&self) -> u64 {
        self.adapted.epoch()
    }
    pub fn profile(&self) -> Bm1396AutoAdaptProfile {
        self.sequence.profile
    }
    pub fn initial_adc(&self) -> &DomainAdcObservation {
        &self.sequence.initial_adc
    }
    pub fn operational_baud(&self) -> &OperationalBaudObservation {
        &self.sequence.baud
    }
    pub fn initial_voltage(&self) -> Option<CommandedVoltage> {
        self.sequence.initial_voltage
    }
    pub fn stages(&self) -> &[ColdPllStage] {
        &self.sequence.stages
    }
    pub fn thermal_snapshots(&self) -> &[ThermalSnapshot] {
        &self.sequence.thermal
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.sequence.completed_at
    }
    pub fn failure(&self) -> Option<&str> {
        self.sequence.failure.as_deref()
    }
    /// Fixed source profile only. This is never a hardware lock observation.
    pub fn completed_frequency_mhz(&self) -> Option<u16> {
        self.sequence.completed_at.map(|_| 300)
    }
    /// Original timeout fields96 -> rounded128, interval3, percentage90 and
    /// completed300 produce1179. Work version scaling remains the job planner's
    /// responsibility; this is not a generator exhaustion bound.
    pub fn timeout_base(&self) -> Option<u32> {
        self.sequence.completed_at.map(|_| 1179)
    }
}

impl<H: Hardware> PicApplication<H> {
    pub fn final_pll_observation(&self) -> Result<Option<FinalPllObservation>, String> {
        // Fixed admission -> retained order, shared with the phase guard.
        let admission = self
            .prepared_final
            .lock()
            .map_err(|_| "T17e final PLL admission poisoned")?;
        let retained = self
            .final_pll
            .lock()
            .map_err(|_| "T17e final PLL custody poisoned")?;
        match retained.as_ref() {
            None => Ok(None),
            Some(sequence) => Ok(Some(FinalPllObservation {
                adapted: admission
                    .as_ref()
                    .and_then(|a| a.adapted.clone())
                    .ok_or("T17e final PLL adapted admission lost")?,
                sequence: sequence.clone(),
            })),
        }
    }

    /// Small read-only health view while the actual phase retains ASIC custody.
    pub fn final_pll_latest_thermal(&self) -> Result<Option<ThermalSnapshot>, String> {
        Ok(self
            .final_pll
            .lock()
            .map_err(|_| "T17e final PLL custody poisoned")?
            .as_ref()
            .and_then(|o| o.thermal.last().cloned()))
    }

    /// One exact final300 attempt on this owner's completed adapted epoch.
    /// Independent heartbeat/fan/watchdog/source-high supervision stays live.
    pub async fn initialize_final_pll(
        self: &Arc<Self>,
        line: Arc<PowerLine<H>>,
        deadline: Instant,
    ) -> Result<FinalPllObservation, String> {
        let app = self.clone();
        let runtime = tokio::runtime::Handle::current();
        self.owner
            .worker(deadline, false, move |owner| {
                let mut state = owner.lock(&owner.asic, deadline, false)?;
                let adapted = app
                    .adapted_startup_observation()?
                    .ok_or("T17e final PLL requires actual adapted startup")?;
                validate_adapted_state(&owner, &state, &adapted)?;
                line.check_active_source(&owner, deadline)?;
                let profile = owner.factory_calibration_profile()?;
                let baud = adapted
                    .operational_baud()
                    .cloned()
                    .ok_or("T17e final PLL baud absent")?;
                let host = baud.requested_host_register();
                let initial_adc = adapted
                    .adapted_adc()
                    .cloned()
                    .ok_or("T17e final PLL ADC absent")?;
                let higher_command = adapted
                    .higher_command()
                    .ok_or("T17e final PLL higher command absent")?;
                let next_voltage = adapted
                    .higher_voltage()
                    .ok_or("T17e final PLL higher attempt absent")?
                    .sequence()
                    .checked_add(1)
                    .ok_or("T17e final PLL voltage generation overflow")?;
                let reset_word = adapted
                    .reset()
                    .and_then(|reset| {
                        reset.events().iter().rev().find_map(|event| match event {
                            ConditioningResetEvent::Register {
                                offset: 0x34,
                                value,
                                completed_at: Some(_),
                            } => Some(*value),
                            _ => None,
                        })
                    })
                    .ok_or("T17e final PLL reset state absent")?;
                let thermal = adapted
                    .thermal_snapshots()
                    .last()
                    .cloned()
                    .ok_or("T17e final PLL thermal absent")?;
                let cutoff_c = adapted.predecessor_preparation().cutoff_c();
                app.preparation_validate_thermal(&thermal, cutoff_c)?;
                {
                    let mut admission = app
                        .prepared_final
                        .lock()
                        .map_err(|_| "T17e final PLL admission poisoned")?;
                    let mut retained = app
                        .final_pll
                        .lock()
                        .map_err(|_| "T17e final PLL custody poisoned")?;
                    if admission.is_some() || retained.is_some() {
                        return Err("T17e final PLL attempt already spent".into());
                    }
                    *admission = Some(PreparedColdAdmission {
                        reset_word,
                        higher_command,
                        next_voltage,
                        epoch: adapted.epoch(),
                        line,
                        cutoff_c,
                        thermal,
                        adapted: Some(adapted.clone()),
                    });
                    *retained = Some(ColdPllObservation {
                        preparation_completed_at: adapted.completed_at(),
                        issuer: owner.identity.clone(),
                        profile,
                        baud,
                        initial_adc,
                        initial_voltage: None,
                        thermal: Vec::new(),
                        thermal_records: 0,
                        stages: Vec::with_capacity(5),
                        final_adc: None,
                        completed_at: None,
                        failure: None,
                    });
                }
                let transaction = PllTransaction::final_stage(&app);
                // The adapted ADC remains in its actual owner slot. The final source
                // wrapper does not reacquire ADC or consume the conditioning tail.
                let pre_worker = transaction
                    .cold_guard(host, deadline)
                    .and_then(|()| owner.query_predrain(&mut state, deadline))
                    .and_then(|()| transaction.cold_pending_prepared_thermal(&state));
                if let Err(error) = pre_worker {
                    owner.begin_terminal();
                    app.final_pll
                        .lock()
                        .map_err(|_| "T17e final PLL custody poisoned")?
                        .as_mut()
                        .ok_or("T17e final PLL custody lost")?
                        .failure = Some(error.clone());
                    return Err(error);
                }
                let mut watermark = state.next_return;
                let (requests, request_rx) = mpsc::sync_channel(1);
                let (completion_tx, completed) = mpsc::sync_channel(1);
                let pic_app = app.clone();
                let pic_owner = owner.clone();
                let pic_worker = runtime.spawn(async move {
                    pic_owner
                        .worker(deadline, false, move |_| {
                            let lease = pic_app.voltage_lease(deadline)?;
                            PllTransaction::final_stage(&pic_app).cold_pic_loop(
                                &lease,
                                request_rx,
                                completion_tx,
                                deadline,
                            )
                        })
                        .await
                });
                let result = transaction
                    .cold_ramp_sequence(
                        &mut state,
                        host,
                        profile,
                        &mut watermark,
                        &requests,
                        &completed,
                        deadline,
                    )
                    .and_then(|()| {
                        transaction.cold_service(&mut state, host, &mut watermark, deadline)
                    });
                if result.is_err() {
                    owner.begin_terminal();
                }
                drop(requests);
                let pic_result = runtime
                    .block_on(pic_worker)
                    .map_err(|e| format!("T17e final PLL PIC worker join: {e}"))
                    .and_then(|result| result);
                // The actual PIC task has exited. Reacquire its logical lease and
                // validate the whole retained command lineage before completion.
                let completion_lease = if result.is_ok() && pic_result.is_ok() {
                    app.voltage_lease_serviced(deadline, || {
                        transaction.cold_service(&mut state, host, &mut watermark, deadline)
                    })
                    .map(Some)
                } else {
                    Ok(None)
                };
                let result = match (result, pic_result) {
                    (Ok(()), Ok(())) => match &completion_lease {
                        Ok(Some(lease)) => transaction
                            .final_voltage_completion(lease)
                            .and_then(|()| validate_adapted_state(&owner, &state, &adapted))
                            .and_then(|()| transaction.cold_guard(host, deadline)),
                        Err(error) => Err(error.clone()),
                        Ok(None) => Err("T17e final PLL completion lease absent".into()),
                    },
                    (Err(a), Err(b)) => Err(format!("{a}; PIC worker: {b}")),
                    (Err(error), _) | (_, Err(error)) => Err(error),
                };
                let mut retained = app
                    .final_pll
                    .lock()
                    .map_err(|_| "T17e final PLL custody poisoned")?;
                let observation = retained.as_mut().ok_or("T17e final PLL custody lost")?;
                if let Err(error) = result {
                    owner.begin_terminal();
                    observation.failure = Some(error.clone());
                    return Err(error);
                }
                observation.completed_at = Some(Instant::now());
                Ok(FinalPllObservation {
                    adapted,
                    sequence: observation.clone(),
                })
            })
            .await
    }
}

// The caller holds the actual ASIC mutex. A historical copied adapted receipt
// cannot promote another state, an old epoch, DMA or already issued work.
fn validate_adapted_state<H: Hardware>(
    owner: &Arc<Transport<H>>,
    state: &AsicState,
    adapted: &AdaptedStartupObservation,
) -> Result<(), String> {
    let baud = adapted
        .operational_baud()
        .ok_or("T17e final PLL adapted baud absent")?;
    let old_host = baud.old_host_register();
    if owner.model != Model::T17e
        || !adapted.same_owner(owner)
        || adapted.completed_at().is_none()
        || adapted.failure().is_some()
        || adapted.stage() != AdaptedStartupStage::FreshThermal
        || adapted.epoch() != 1
        || state.thermal_epoch != adapted.epoch()
        || state.adc_level != Bm1396DomainVoltageAdaptiveLevel::Adapted
        || state.requalification_deadline.is_some()
        || !state.startup_attempted
        || state.dma_initialized
        || !state.publications.is_empty()
        || !state.register_observations.is_empty()
        || owner.hardware.read(DHASH)? & RUN != 0
        || state.assignment.as_ref() != adapted.assignment()
        || state.cold_registers.as_ref() != adapted.cold_registers()
        || state.domain_adc.as_ref() != adapted.adapted_adc()
        || state.operational_baud.as_ref() != Some(baud)
        || state
            .thermal
            .as_ref()
            .and_then(|t| t.complete_configuration())
            != adapted.thermal_configuration()
        || state
            .thermal
            .as_ref()
            .is_none_or(|t| t.has_pending_snapshots() || !t.configuration_matches_host(old_host))
        || adapted.adapted_adc().is_none_or(|adc| {
            adc.adapted_minimum_passed() != Some(true)
                || adc.adaptive_level() != Bm1396DomainVoltageAdaptiveLevel::Adapted
                || adc.host_baud_register() != old_host
        })
        || baud.model() != Model::T17e
        || baud.baud() != 3_000_000
        || baud.completed_at().is_none()
        || baud.host_readback() != Some(baud.requested_host_register())
        || adapted
            .reset()
            .is_none_or(|reset| reset.completed_at().is_none() || reset.failure().is_some())
    {
        return Err("T17e final PLL actual adapted receipt/state join differs".into());
    }
    Ok(())
}

impl<H: Hardware> PllTransaction<'_, H> {
    pub(super) fn final_voltage_completion(&self, lease: &VoltageLease<'_>) -> Result<(), String> {
        self.require_voltage_lease(lease)?;
        let (expected_next, expected_current) =
            {
                let admission = self
                    .admission
                    .lock()
                    .map_err(|_| "T17e final PLL admission poisoned")?;
                let admission = admission.as_ref().ok_or("T17e final PLL admission lost")?;
                if self.owner.model == Model::T17e && admission.adapted.is_none() {
                    return Err("T17e final PLL adapted lineage absent".into());
                }
                if self.owner.model == Model::S17e
                    && (admission.adapted.is_some() || admission.epoch != 0)
                {
                    return Err("S17e factory PLL requires its fixed Baseline lineage".into());
                }
                let retained = self
                    .retained
                    .lock()
                    .map_err(|_| "T17e final PLL custody poisoned")?;
                let observation = retained.as_ref().ok_or("T17e final PLL custody lost")?;
                let mut next = admission.next_voltage;
                let mut current = admission.higher_command;
                let mut verified = None;
                let expected_stages = self.source_stages()?;
                if observation.initial_voltage != Some(current)
                    || observation.stages.len() != expected_stages.len()
                {
                    return Err("T17e final PLL incomplete initial/stage custody".into());
                }
                for (stage, expected) in observation.stages.iter().zip(expected_stages) {
                    if stage.frequency_mhz != expected.frequency_mhz
                        || stage.settled_at.is_none()
                        || stage.commands.len() != expected.commands.len()
                        || stage.commands.iter().zip(&expected.commands).any(
                            |(command, expected)| {
                                command.chain != expected.chain
                                    || command.chip != expected.chip
                                    || command.value != expected.register
                                    || command.completed_at.is_none()
                            },
                        )
                    {
                        return Err("T17e final PLL source stage/command custody differs".into());
                    }
                    let before_expected = stage
                        .plans
                        .iter()
                        .filter(|plan| plan.plan.helper_invokes_domain_adc_mode1_before_pll)
                        .count();
                    if stage.before_adc.len() != before_expected
                        || stage.after_adc.is_some() != expected.domain_adc_after
                        || stage
                            .before_adc
                            .iter()
                            .chain(stage.after_adc.iter())
                            .any(|adc| {
                                adc.baseline_minimum_passed() != Some(true)
                                    || adc.adaptive_level()
                                        != Bm1396DomainVoltageAdaptiveLevel::Baseline
                            })
                    {
                        return Err("BM1396 source PLL domain ADC custody differs".into());
                    }
                    for plan in &stage.plans {
                        if let Some(attempt) = &plan.attempt {
                            if attempt.sequence() != next
                                || attempt.completed_at().is_none()
                                || attempt.prior_command() != Some(current)
                            {
                                return Err("T17e final PLL voltage lineage discontinuous".into());
                            }
                            next = next
                                .checked_add(1)
                                .ok_or("T17e final PLL voltage generation overflow")?;
                            current = plan
                                .rail_verification
                                .as_ref()
                                .ok_or("T17e final PLL changed command unverified")?
                                .commanded_voltage();
                            if current.requested_centivolts() != attempt.requested_centivolts() {
                                return Err("T17e final PLL voltage target differs".into());
                            }
                        }
                        if let Some(verification) = &plan.rail_verification {
                            if verification.passed() != Some(true)
                                || verification.commanded_voltage() != current
                            {
                                return Err("T17e final PLL rail custody differs".into());
                            }
                            verified = Some(current);
                        }
                    }
                }
                if verified != Some(current) {
                    return Err("T17e final PLL current command unverified".into());
                }
                (next, current)
            };
        let state = self
            .state
            .lock()
            .map_err(|_| "T17e final PLL PIC custody poisoned")?;
        if state.next_voltage != expected_next
            || state.last_voltage != Some(expected_current)
            || !state.voltage_attempts.is_empty()
            || !state.rails.is_empty()
            || !state.rail_verifications.is_empty()
        {
            return Err("T17e final PLL final voltage generation/custody changed".into());
        }
        Ok(())
    }
}
