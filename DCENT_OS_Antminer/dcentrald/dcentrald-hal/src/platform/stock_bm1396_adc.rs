//! Fresh source B4/B8 acquisition through the retained ASIC/FIFO owner.
//! Original complete callers/B0 wrappers: native-adc-acquisition-vectors-v1.
use super::*;
use dcentrald_common::bm1396_contract::{bm1396_read_register_frame, bm1396_write_register_frame};
use dcentrald_common::bm1396_domain_voltage::{
    bm1396_decode_domain_adc_registers, bm1396_domain_voltage_policy,
    bm1396_evaluate_domain_voltages, bm1396_summarize_domain_adc, Bm1396DomainAdcSummary,
    Bm1396DomainVoltageAdaptiveLevel, Bm1396DomainVoltageDecision, Bm1396DomainVoltageMode,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainAdcCommand {
    pub chain: u8,
    pub register: u8,
    /// None is the source broadcast read, Some is an attempted B0 write.
    pub value: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DomainAdcChain {
    chain: u8,
    chip_lanes: Vec<[u16; 4]>,
    domains: Vec<Bm1396DomainAdcSummary>,
    adaptive_level: Bm1396DomainVoltageAdaptiveLevel,
    minimum: Bm1396DomainVoltageDecision,
    received_at: Instant,
}
impl DomainAdcChain {
    pub fn chain(&self) -> u8 {
        self.chain
    }
    pub fn chip_lanes(&self) -> &[[u16; 4]] {
        &self.chip_lanes
    }
    /// ASIC-reported raw ADC conversion, not an independent rail measurement.
    pub fn domains(&self) -> &[Bm1396DomainAdcSummary] {
        &self.domains
    }
    pub fn adaptive_level(&self) -> Bm1396DomainVoltageAdaptiveLevel {
        self.adaptive_level
    }
    pub fn minimum(&self) -> Bm1396DomainVoltageDecision {
        self.minimum
    }
    /// A decision from the adapted producer is never mislabeled as baseline.
    pub fn baseline_minimum(&self) -> Option<Bm1396DomainVoltageDecision> {
        (self.adaptive_level == Bm1396DomainVoltageAdaptiveLevel::Baseline).then_some(self.minimum)
    }
    /// Host time after consuming both complete populations for this chain.
    pub fn received_at(&self) -> Instant {
        self.received_at
    }
}

/// Same-owner custody, including incomplete progress after cancellation/error.
/// Completion means every selected population was received and B0 restored.
/// The recorded phase is chosen by the owner's retained startup epoch before
/// acquisition; a completed baseline result cannot be relabeled as adapted.
#[derive(Clone, Debug, PartialEq)]
pub struct DomainAdcObservation {
    issuer: Arc<()>,
    sequence: u64,
    model: Model,
    host_baud_register: u32,
    adaptive_level: Bm1396DomainVoltageAdaptiveLevel,
    records: Vec<PreservedReturn>,
    commands: Vec<DomainAdcCommand>,
    chains: Vec<DomainAdcChain>,
    restored_chains: Vec<u8>,
    completed_at: Option<Instant>,
}
impl DomainAdcObservation {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn model(&self) -> Model {
        self.model
    }
    pub fn host_baud_register(&self) -> u32 {
        self.host_baud_register
    }
    pub fn raw_records(&self) -> &[PreservedReturn] {
        &self.records
    }
    pub fn commands(&self) -> &[DomainAdcCommand] {
        &self.commands
    }
    pub fn chains(&self) -> &[DomainAdcChain] {
        &self.chains
    }
    /// Chains whose B0 restore command transport completed; no ASIC readback.
    pub fn restored_chains(&self) -> &[u8] {
        &self.restored_chains
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
    pub fn adaptive_level(&self) -> Bm1396DomainVoltageAdaptiveLevel {
        self.adaptive_level
    }
    pub fn minimum_passed(&self) -> Option<bool> {
        self.completed_at.map(|_| {
            self.chains.iter().all(|chain| {
                chain.adaptive_level == self.adaptive_level
                    && matches!(chain.minimum, Bm1396DomainVoltageDecision::Pass { .. })
            })
        })
    }
    pub fn baseline_minimum_passed(&self) -> Option<bool> {
        (self.adaptive_level == Bm1396DomainVoltageAdaptiveLevel::Baseline)
            .then(|| self.minimum_passed())
            .flatten()
    }
    pub fn adapted_minimum_passed(&self) -> Option<bool> {
        (self.adaptive_level == Bm1396DomainVoltageAdaptiveLevel::Adapted)
            .then(|| self.minimum_passed())
            .flatten()
    }
}

impl<H: Hardware> Transport<H> {
    pub fn domain_adc_observation(&self) -> Result<Option<DomainAdcObservation>, String> {
        Ok(self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 ASIC owner busy or poisoned")?
            .domain_adc
            .clone())
    }

    pub fn acknowledge_domain_adc(&self, observation: &DomainAdcObservation) -> Result<(), String> {
        let mut state = self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 ASIC owner busy or poisoned")?;
        self.acknowledge_domain_adc_locked(&mut state, observation)
    }

    pub(super) fn acknowledge_domain_adc_locked(
        &self,
        state: &mut AsicState,
        observation: &DomainAdcObservation,
    ) -> Result<(), String> {
        if !Arc::ptr_eq(&observation.issuer, &self.identity)
            || observation.completed_at.is_none()
            || state.domain_adc.as_ref() != Some(observation)
        {
            return Err("BM1396 ADC acknowledgment is foreign, incomplete or stale".into());
        }
        state.domain_adc = None;
        Ok(())
    }

    /// One cold-engine acquisition after complete source register setup. All
    /// raw returns remain attached to this worker/owner before async completion.
    /// The private owner epoch selects Baseline or Adapted. There is no public
    /// phase selector; power/heartbeat/watchdog custody remains mandatory.
    pub async fn acquire_domain_adc(self: &Arc<Self>, deadline: Instant) -> Result<u64, String> {
        self.worker(deadline, false, move |this| {
            let mut state = this.lock(&this.asic, deadline, false)?;
            this.acquire_domain_adc_locked(&mut state, deadline)
        })
        .await
    }

    /// Caller retains the physical ASIC mutex through this complete acquisition.
    pub(super) fn acquire_domain_adc_locked(
        &self,
        state: &mut AsicState,
        deadline: Instant,
    ) -> Result<u64, String> {
        self.acquire_domain_adc_serviced(state, deadline, |_, _| Ok(()))
    }

    pub(super) fn acquire_domain_adc_serviced<F>(
        &self,
        state: &mut AsicState,
        deadline: Instant,
        mut service: F,
    ) -> Result<u64, String>
    where
        F: FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    {
        let this = self;
        if state.domain_adc.is_some()
            || state
                .cold_registers
                .as_ref()
                .and_then(ColdRegisterObservation::completed_at)
                .is_none()
            || state.assignment.is_none()
            || !state.publications.is_empty()
            || this.hardware.read(DHASH)? & RUN != 0
        {
            return Err(
                "BM1396 ADC requires completed cold setup, idle engine and acknowledged custody"
                    .into(),
            );
        }
        let mut fault = FaultGuard::new(&this.asic_fault, &this.terminal);
        let host = this.hardware.read(0x3c)?;
        this.adc_guard(host, deadline)?;
        this.query_predrain(state, deadline)?;
        let sequence = state.next_observation;
        state.next_observation = sequence
            .checked_add(1)
            .ok_or("BM1396 ADC sequence exhausted")?;
        let adaptive_level = state.adc_level;
        state.domain_adc = Some(DomainAdcObservation {
            issuer: Arc::clone(&this.identity),
            sequence,
            model: this.model,
            host_baud_register: host,
            adaptive_level,
            records: Vec::new(),
            commands: Vec::new(),
            chains: Vec::new(),
            restored_chains: Vec::new(),
            completed_at: None,
        });
        for &chain in &this.chains {
            // Original per-chain enable, B4,150ms,B8,150ms,150ms,restore.
            this.adc_command(
                state,
                chain,
                0xb0,
                Some(0x3014_003a),
                host,
                deadline,
                &mut service,
            )?;
            let first = state.next_return;
            this.adc_command(state, chain, 0xb4, None, host, deadline, &mut service)?;
            this.adc_window(state, host, deadline, &mut service)?;
            // Reject unrelated/duplicate/early B8 responses before issuing
            // the second request. B4 may continue arriving in its window.
            this.adc_matches(state, first, None, chain, false)?;
            let second = state.next_return;
            this.adc_command(state, chain, 0xb8, None, host, deadline, &mut service)?;
            this.adc_window(state, host, deadline, &mut service)?;
            this.adc_window(state, host, deadline, &mut service)?;
            let records = this.adc_matches(state, first, Some(second), chain, true)?;
            let count = usize::from(this.model.expected_chips_per_present_chain());
            let mut words = vec![[0u32; 2]; count];
            for raw in &records {
                let ReturnPayload::Register(value) = raw.payload() else {
                    unreachable!("validated ADC record")
                };
                let ordinal = usize::from(value.chip_address / this.model.address_interval());
                words[ordinal][usize::from(value.register == 0xb8)] = value.value;
            }
            let lanes: Vec<_> = words
                .into_iter()
                .map(|[b4, b8]| bm1396_decode_domain_adc_registers(b4, b8).lanes)
                .collect();
            let domains = bm1396_summarize_domain_adc(this.model, &lanes)
                .map_err(|e| format!("BM1396 ADC grouping: {e:?}"))?;
            let policy = bm1396_domain_voltage_policy(
                this.model,
                adaptive_level,
                Bm1396DomainVoltageMode::Minimum,
            )
            .map_err(|e| format!("BM1396 ADC phase policy: {e:?}"))?;
            let decision = bm1396_evaluate_domain_voltages(
                policy,
                &domains
                    .iter()
                    .map(|domain| domain.domain_voltage_v)
                    .collect::<Vec<_>>(),
            )
            .map_err(|e| format!("BM1396 ADC phase input: {e:?}"))?;
            let ids: Vec<_> = records.iter().map(PreservedReturn::sequence).collect();
            let retained = state.domain_adc.as_mut().ok_or("BM1396 lost ADC custody")?;
            retained.records.extend(records);
            retained.chains.push(DomainAdcChain {
                chain,
                chip_lanes: lanes,
                domains,
                adaptive_level,
                minimum: decision,
                received_at: Instant::now(),
            });
            state.pending.retain(|raw| !ids.contains(&raw.sequence()));
            this.adc_command(
                state,
                chain,
                0xb0,
                Some(0x0010_0000),
                host,
                deadline,
                &mut service,
            )?;
            state
                .domain_adc
                .as_mut()
                .ok_or("BM1396 lost ADC custody")?
                .restored_chains
                .push(chain);
        }
        this.adc_guard(host, deadline)?;
        let observation = state.domain_adc.as_mut().ok_or("BM1396 lost ADC custody")?;
        observation.completed_at = Some(Instant::now());
        if observation.minimum_passed() != Some(true) {
            return Err(match adaptive_level {
                Bm1396DomainVoltageAdaptiveLevel::Baseline => {
                    "BM1396 fresh ADC baseline minimum failed; complete observation retained"
                }
                Bm1396DomainVoltageAdaptiveLevel::Adapted => {
                    "BM1396 fresh ADC adapted minimum failed; complete observation retained"
                }
            }
            .into());
        }
        fault.complete();
        Ok(sequence)
    }

    fn adc_guard(&self, host: u32, deadline: Instant) -> Result<(), String> {
        self.query_presence(deadline)?;
        self.query_host(host, deadline)?;
        if self.hardware.read(DHASH)? & RUN != 0 {
            return Err("BM1396 ADC cold engine became active".into());
        }
        self.check(deadline, false)
    }

    fn adc_window<F>(
        &self,
        state: &mut AsicState,
        host: u32,
        deadline: Instant,
        service: &mut F,
    ) -> Result<(), String>
    where
        F: FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    {
        // Same-owner1ms draining retains the stock independent receiver's work.
        self.query_receive_window_serviced(state, 150, host, deadline, |state| {
            service(state, CommandServicePoint::IdleReceive)
        })?;
        self.adc_guard(host, deadline)
    }

    #[allow(clippy::too_many_arguments)]
    fn adc_command<F>(
        &self,
        state: &mut AsicState,
        chain: u8,
        register: u8,
        value: Option<u32>,
        host: u32,
        deadline: Instant,
        service: &mut F,
    ) -> Result<(), String>
    where
        F: FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    {
        self.adc_guard(host, deadline)?;
        state
            .domain_adc
            .as_mut()
            .ok_or("BM1396 lost ADC custody")?
            .commands
            .push(DomainAdcCommand {
                chain,
                register,
                value,
            });
        let frame = if let Some(word) = value {
            bm1396_write_register_frame(true, 0, register, word).to_vec()
        } else {
            bm1396_read_register_frame(true, 0, register).to_vec()
        };
        self.command_locked_serviced(chain, &frame, deadline, |point| service(state, point))?;
        self.adc_guard(host, deadline)
    }

    fn adc_matches(
        &self,
        state: &AsicState,
        first: u64,
        second: Option<u64>,
        chain: u8,
        complete: bool,
    ) -> Result<Vec<PreservedReturn>, String> {
        let count = usize::from(self.model.expected_chips_per_present_chain());
        let mut seen = vec![[false; 2]; count];
        let mut matches = Vec::new();
        for raw in state.pending.iter().filter(|raw| raw.sequence() >= first) {
            let ReturnPayload::Register(value) = raw.payload() else {
                continue;
            };
            if value.chain_slot != chain || ![0xb4, 0xb8].contains(&value.register) {
                return Err("BM1396 fresh ADC reply has foreign chain/register".into());
            }
            if value.register == 0xb8 && second.is_none_or(|start| raw.sequence() < start) {
                return Err("BM1396 B8 response arrived before its request".into());
            }
            let interval = self.model.address_interval();
            let ordinal = usize::from(value.chip_address / interval);
            if value.chip_address % interval != 0 || ordinal >= count {
                return Err("BM1396 ADC address is outside the assigned geometry".into());
            }
            if std::mem::replace(
                &mut seen[ordinal][usize::from(value.register == 0xb8)],
                true,
            ) {
                return Err("BM1396 duplicate fresh ADC response".into());
            }
            matches.push(raw.clone());
        }
        if complete && seen.iter().any(|pair| *pair != [true, true]) {
            return Err("BM1396 ADC observation window ended without every B4/B8 reply".into());
        }
        Ok(matches)
    }
}
