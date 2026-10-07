//! Exact retained cold register spine, excluding its final domain-ADC check.
//! Original constructors/callers: R06 native-cold-core-vectors-v1 (18 cases).
use super::*;
use dcentrald_common::bm1396_contract::bm1396_write_register_frame;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColdRegisterCommand {
    pub chain: u8,
    pub broadcast: bool,
    pub chip_address: u8,
    pub register: u8,
    pub value: u32,
}

/// Completed command transport plus actual Misc18 observations. This is not a
/// domain-ADC result, a PLL lock observation, or physical core/hash admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColdRegisterObservation {
    issuer: Arc<()>,
    model: Model,
    host_baud_register: u32,
    core_profile: [u8; 3],
    records: Vec<PreservedReturn>,
    commands: Vec<ColdRegisterCommand>,
    completed_at: Option<Instant>,
}
impl ColdRegisterObservation {
    pub fn model(&self) -> Model {
        self.model
    }
    pub fn host_baud_register(&self) -> u32 {
        self.host_baud_register
    }
    pub fn core_profile(&self) -> [u8; 3] {
        self.core_profile
    }
    pub fn raw_misc_records(&self) -> &[PreservedReturn] {
        &self.records
    }
    /// Attempted commands are recorded before any physical publication. Only
    /// the complete observation states that every transport call completed.
    pub fn commands(&self) -> &[ColdRegisterCommand] {
        &self.commands
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
}

impl<H: Hardware> Transport<H> {
    /// Includes incomplete progress so cancellation cannot strand query records
    /// or hide an attempted command. Completion is explicitly optional.
    pub fn cold_register_observation(&self) -> Result<Option<ColdRegisterObservation>, String> {
        Ok(self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 ASIC owner busy or poisoned")?
            .cold_registers
            .clone())
    }

    /// One unused cold attempt: fresh identity, observed Misc prelude, exact
    /// address assignment and source relay/core/filter register commands. The
    /// original final ADC check is still a separate required startup stage.
    /// Retained power/watchdog/heartbeat ownership belongs to the runtime caller.
    pub async fn initialize_cold_registers(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.worker(deadline, false, move |this| {
            let mut state = this.lock(&this.asic, deadline, false)?;
            this.initialize_cold_registers_serviced(&mut state, deadline, &mut |_, _| Ok(()))
        })
        .await
    }

    pub(super) fn initialize_cold_registers_serviced(
        &self,
        state: &mut AsicState,
        deadline: Instant,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<(), String> {
        if state.startup_attempted
            || state.thermal.is_some()
            || !state.publications.is_empty()
            || self.hardware.read(DHASH)? & RUN != 0
        {
            return Err("BM1396 cold registers require one unused cold startup attempt".into());
        }
        state.startup_attempted = true;
        let mut fault = FaultGuard::new(&self.asic_fault, &self.terminal);
        self.query_presence(deadline)?;
        let host = self.hardware.read(0x3c)?;
        self.query_host(host, deadline)?;
        self.query_predrain(state, deadline)?;
        let core = match self.model {
            Model::S17e => [1, 3, 1],
            Model::T17e => [1, 2, 1],
        };
        state.cold_registers = Some(ColdRegisterObservation {
            issuer: Arc::clone(&self.identity),
            model: self.model,
            host_baud_register: host,
            core_profile: core,
            records: Vec::new(),
            commands: Vec::new(),
            completed_at: None,
        });
        let mut initial = Vec::new();
        for &chain in &self.chains {
            initial.extend(
                self.initial_register_population_serviced(
                    state, chain, 0, host, deadline, service,
                )?,
            );
        }
        // Pre-assignment addresses may repeat. Require the whole exact
        // count and one common value per chain before any Misc mutation.
        let mut values = Vec::new();
        for &chain in &self.chains {
            let records = self.initial_register_population_serviced(
                state, chain, 0x18, host, deadline, service,
            )?;
            let old = uniform_misc(&records)?;
            values.push((chain, (old & !0x0040_0000) | 0xf000_0000));
            retain_misc(state, records)?;
        }
        for &(chain, value) in &values {
            self.cold_write(
                state,
                ColdRegisterCommand {
                    chain,
                    broadcast: true,
                    chip_address: 0,
                    register: 0x18,
                    value,
                },
                host,
                deadline,
                service,
            )?;
        }
        for &(chain, expected) in &values {
            let records = self.initial_register_population_serviced(
                state, chain, 0x18, host, deadline, service,
            )?;
            let actual = uniform_misc(&records)?;
            retain_misc(state, records)?;
            if actual != expected {
                return Err("BM1396 cold Misc18 readback mismatch".into());
            }
        }
        self.assign_counted_population_serviced(state, host, initial, deadline, service)?;
        self.query_receive_window_serviced(state, 10, host, deadline, |state| {
            service(state, CommandServicePoint::IdleReceive)
        })?;
        let (step, relay) = match self.model {
            Model::S17e => (9, 0x0039_0003),
            Model::T17e => (6, 0x0033_0003),
        };
        // The original all-chain writer completes one ordinal on every
        // present chain before moving to the next domain boundary.
        for ordinal in (step..self.model.expected_chips_per_present_chain()).step_by(step as usize)
        {
            for &chain in &self.chains {
                self.cold_write(
                    state,
                    ColdRegisterCommand {
                        chain,
                        broadcast: false,
                        chip_address: (ordinal * u16::from(self.model.address_interval())) as u8,
                        register: 0x2c,
                        value: relay,
                    },
                    host,
                    deadline,
                    service,
                )?;
            }
        }
        self.query_receive_window_serviced(state, 100, host, deadline, |state| {
            service(state, CommandServicePoint::IdleReceive)
        })?;
        self.cold_broadcast(state, 0x3c, 0x8000_8710, host, deadline, service)?;
        self.cold_broadcast(
            state,
            0x3c,
            0x8000_8004 | (u32::from(core[1]) << 4) | (u32::from(core[2]) << 6),
            host,
            deadline,
            service,
        )?;
        self.query_receive_window_serviced(state, 5, host, deadline, |state| {
            service(state, CommandServicePoint::IdleReceive)
        })?;
        self.cold_broadcast(state, 0x14, 0xfe, host, deadline, service)?;
        self.query_receive_window_serviced(state, 10, host, deadline, |state| {
            service(state, CommandServicePoint::IdleReceive)
        })?;
        for (register, value) in [(0x54, 3), (0xb0, 0x0010_0000), (0x6c, 0x0200_0203)] {
            self.cold_broadcast(state, register, value, host, deadline, service)?;
        }
        self.query_presence(deadline)?;
        self.query_host(host, deadline)?;
        service(state, CommandServicePoint::IdleReceive)?;
        state
            .cold_registers
            .as_mut()
            .ok_or("BM1396 lost cold custody")?
            .completed_at = Some(Instant::now());
        fault.complete();
        Ok(())
    }

    fn cold_broadcast(
        &self,
        state: &mut AsicState,
        register: u8,
        value: u32,
        host: u32,
        deadline: Instant,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<(), String> {
        for &chain in &self.chains {
            self.cold_write(
                state,
                ColdRegisterCommand {
                    chain,
                    broadcast: true,
                    chip_address: 0,
                    register,
                    value,
                },
                host,
                deadline,
                service,
            )?;
        }
        Ok(())
    }

    fn cold_write(
        &self,
        state: &mut AsicState,
        command: ColdRegisterCommand,
        host: u32,
        deadline: Instant,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<(), String> {
        self.query_presence(deadline)?;
        self.query_host(host, deadline)?;
        if self.hardware.read(DHASH)? & RUN != 0 {
            return Err("BM1396 cold engine RUN changed".into());
        }
        state
            .cold_registers
            .as_mut()
            .ok_or("BM1396 lost cold command custody")?
            .commands
            .push(command);
        self.command_and_receive_locked(
            state,
            command.chain,
            &bm1396_write_register_frame(
                command.broadcast,
                command.chip_address,
                command.register,
                command.value,
            ),
            deadline,
            service,
        )?;
        self.query_host(host, deadline)
    }
}

fn uniform_misc(records: &[PreservedReturn]) -> Result<u32, String> {
    let mut value = None;
    for raw in records {
        let ReturnPayload::Register(record) = raw.payload() else {
            return Err("BM1396 cold Misc18 invalid record".into());
        };
        if record.register != 0x18 || value.is_some_and(|old| old != record.value) {
            return Err("BM1396 cold Misc18 population is not uniform".into());
        }
        value = Some(record.value);
    }
    value.ok_or_else(|| "BM1396 cold Misc18 empty population".into())
}

fn retain_misc(state: &mut AsicState, records: Vec<PreservedReturn>) -> Result<(), String> {
    let ids: Vec<_> = records.iter().map(PreservedReturn::sequence).collect();
    state
        .cold_registers
        .as_mut()
        .ok_or("BM1396 lost cold reply custody")?
        .records
        .extend(records);
    state.pending.retain(|raw| !ids.contains(&raw.sequence()));
    Ok(())
}
