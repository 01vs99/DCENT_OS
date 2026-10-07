//! Actual model-specific final startup captured from this physical application.
//! S17e's fixed factory pass cannot acquire T17e's Adapted ADC authority.
use super::*;

#[derive(Clone, Debug)]
enum Predecessor {
    T17e(AdaptedStartupObservation),
    S17e(ConditioningPreparationObservation),
}

#[derive(Clone, Debug)]
pub struct NativePllObservation {
    predecessor: Predecessor,
    sequence: ColdPllObservation,
    maximum_frequency: u16,
    timeout: u32,
}

impl NativePllObservation {
    pub fn model(&self) -> Model {
        match self.predecessor {
            Predecessor::T17e(_) => Model::T17e,
            Predecessor::S17e(_) => Model::S17e,
        }
    }
    pub fn same_owner<H: Hardware>(&self, owner: &Arc<Transport<H>>) -> bool {
        self.model() == owner.model
            && Arc::ptr_eq(&self.sequence.issuer, &owner.identity)
            && match &self.predecessor {
                Predecessor::T17e(prepared) => prepared.same_owner(owner),
                Predecessor::S17e(prepared) => prepared.same_owner(owner),
            }
    }
    pub fn epoch(&self) -> u64 {
        match &self.predecessor {
            Predecessor::T17e(p) => p.epoch(),
            Predecessor::S17e(_) => 0,
        }
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.sequence.completed_at
    }
    pub fn failure(&self) -> Option<&str> {
        self.sequence.failure.as_deref()
    }
    pub fn completed_frequency_mhz(&self) -> Option<u16> {
        self.completed_at().map(|_| self.maximum_frequency)
    }
    pub fn timeout_base(&self) -> Option<u32> {
        self.completed_at().map(|_| self.timeout)
    }
    pub fn operational_baud(&self) -> &OperationalBaudObservation {
        &self.sequence.baud
    }
    pub fn thermal_snapshots(&self) -> &[ThermalSnapshot] {
        &self.sequence.thermal
    }
    pub(super) fn adc_level(&self) -> Bm1396DomainVoltageAdaptiveLevel {
        match self.predecessor {
            Predecessor::T17e(_) => Bm1396DomainVoltageAdaptiveLevel::Adapted,
            Predecessor::S17e(_) => Bm1396DomainVoltageAdaptiveLevel::Baseline,
        }
    }
    pub(super) fn current_adc(&self) -> Result<&DomainAdcObservation, String> {
        match self.predecessor {
            Predecessor::T17e(_) => Ok(&self.sequence.initial_adc),
            Predecessor::S17e(_) => self
                .sequence
                .final_adc
                .as_ref()
                .ok_or("S17e final ADC absent".into()),
        }
    }
    pub(super) fn assignment(&self) -> Option<&AssignmentObservation> {
        match &self.predecessor {
            Predecessor::T17e(p) => p.assignment(),
            Predecessor::S17e(p) => p.assignment(),
        }
    }
    pub(super) fn cold_registers(&self) -> Option<&ColdRegisterObservation> {
        match &self.predecessor {
            Predecessor::T17e(p) => p.cold_registers(),
            Predecessor::S17e(p) => p.cold_registers(),
        }
    }
    pub(super) fn thermal_configuration(&self) -> Option<&ThermalConfiguration> {
        match &self.predecessor {
            Predecessor::T17e(p) => p.thermal_configuration(),
            Predecessor::S17e(p) => p.thermal_configuration(),
        }
    }
    pub(super) fn validate_entry<H: Hardware>(
        &self,
        owner: &Arc<Transport<H>>,
        state: &AsicState,
    ) -> Result<(), String> {
        if !self.same_owner(owner)
            || self.completed_at().is_none()
            || self.failure().is_some()
            || state.dma_initialized
            || !state.publications.is_empty()
            || owner.hardware.read(DHASH)? & RUN != 0
        {
            return Err("BM1396 actual native PLL completion absent or spent".into());
        }
        match &self.predecessor {
            Predecessor::T17e(p) => validate_adapted_state(owner, state, p),
            Predecessor::S17e(p) => {
                let adc = self.current_adc()?;
                if p.completed_at().is_none()
                    || p.failure().is_some()
                    || self.sequence.preparation_completed_at != p.completed_at()
                    || self.sequence.profile != Bm1396AutoAdaptProfile::Signed2020S17eFixed
                    || state.thermal_epoch != 0
                    || state.adc_level != Bm1396DomainVoltageAdaptiveLevel::Baseline
                    || state.requalification_deadline.is_some()
                    || !state.startup_attempted
                    || !state.register_observations.is_empty()
                    || state.assignment.as_ref() != p.assignment()
                    || state.cold_registers.as_ref() != p.cold_registers()
                    || state.domain_adc.as_ref() != Some(adc)
                    || adc.baseline_minimum_passed() != Some(true)
                    || adc.adaptive_level() != Bm1396DomainVoltageAdaptiveLevel::Baseline
                    || adc.host_baud_register() != self.operational_baud().requested_host_register()
                    || state.operational_baud.as_ref() != Some(self.operational_baud())
                    || state
                        .thermal
                        .as_ref()
                        .and_then(|t| t.complete_configuration())
                        != p.thermal_configuration()
                    || state
                        .thermal
                        .as_ref()
                        .is_none_or(|t| t.has_pending_snapshots())
                {
                    return Err("S17e fixed factory PLL receipt/state join differs".into());
                }
                Ok(())
            }
        }
    }
}

impl<H: Hardware> PicApplication<H> {
    pub fn native_pll_observation(&self) -> Result<Option<NativePllObservation>, String> {
        match self.owner.model {
            Model::T17e => Ok(self
                .final_pll_observation()?
                .map(|actual| NativePllObservation {
                    predecessor: Predecessor::T17e(actual.adapted),
                    sequence: actual.sequence,
                    maximum_frequency: 300,
                    timeout: 1179,
                })),
            Model::S17e => {
                let Some(sequence) = self.cold_pll_observation()? else {
                    return Ok(None);
                };
                let prepared = self
                    .conditioning_preparation_observation()?
                    .ok_or("S17e actual preparation absent")?;
                let records = self.owner.s17e_factory_records()?;
                let maximum_frequency = records
                    .iter()
                    .map(|(_, record)| record.maximum_mhz())
                    .max()
                    .ok_or("S17e factory population absent")?;
                Ok(Some(NativePllObservation {
                    predecessor: Predecessor::S17e(prepared),
                    sequence,
                    maximum_frequency,
                    timeout: s17e_factory::timeout_base(maximum_frequency)?,
                }))
            }
        }
    }
}
