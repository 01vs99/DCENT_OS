//! Exact model-bound operational baud switch with retained population readback.
//! 52 original callers/default wrappers: native-operational-baud-vectors-v1.
use super::*;
use dcentrald_common::bm1396_contract::{
    bm1396_baud_plan, bm1396_write_register_frame, BM1396_HIGH_BAUD_CLOCK_PRELUDE,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationalBaudCommand {
    pub chain: u8,
    pub register: u8,
    pub value: u32,
    /// Actual command-portal completion, distinct from ASIC application.
    pub completed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalBaudObservation {
    model: Model,
    baud: u32,
    old_host: u32,
    requested_host: u32,
    host_attempted: bool,
    host_readback: Option<u32>,
    records: Vec<PreservedReturn>,
    commands: Vec<OperationalBaudCommand>,
    completed_at: Option<Instant>,
}
impl OperationalBaudObservation {
    pub fn model(&self) -> Model {
        self.model
    }
    /// Source-requested baud, not an oscilloscope observation.
    pub fn baud(&self) -> u32 {
        self.baud
    }
    pub fn old_host_register(&self) -> u32 {
        self.old_host
    }
    pub fn requested_host_register(&self) -> u32 {
        self.requested_host
    }
    pub fn host_write_attempted(&self) -> bool {
        self.host_attempted
    }
    pub fn host_readback(&self) -> Option<u32> {
        self.host_readback
    }
    pub fn raw_records(&self) -> &[PreservedReturn] {
        &self.records
    }
    pub fn commands(&self) -> &[OperationalBaudCommand] {
        &self.commands
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
}

impl<H: Hardware> Transport<H> {
    pub fn operational_baud_observation(
        &self,
    ) -> Result<Option<OperationalBaudObservation>, String> {
        Ok(self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 ASIC owner busy or poisoned")?
            .operational_baud
            .clone())
    }

    /// One model-fixed transition after this owner's complete cold register,
    /// assigned population and retained passing baseline ADC observations.
    /// S17e requests6Mbaud; T17e requests3Mbaud. Readback must rediscover every
    /// assigned silicon ID and matching Misc18 at the new full host selector.
    /// Failure preserves partial progress and latches terminal; there is no
    /// speculative baud sweep or unproved rollback to an old chip setting.
    pub async fn switch_to_operational_baud(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.worker(deadline, false, move |this| {
            let mut state = this.lock(&this.asic, deadline, false)?;
            this.switch_to_operational_baud_serviced(&mut state, deadline, &mut |_, _| Ok(()))
        })
        .await
    }

    pub(super) fn switch_to_operational_baud_serviced(
        &self,
        state: &mut AsicState,
        deadline: Instant,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<(), String> {
        let old_host = self.hardware.read(0x3c)?;
        let thermal_configured = state
            .thermal
            .as_ref()
            .is_some_and(|thermal| thermal.configuration_matches_host(old_host));
        if state.operational_baud.is_some()
            || !state.publications.is_empty()
            || state
                .assignment
                .as_ref()
                .is_none_or(|observation| observation.host_baud_register() != old_host)
            || state.cold_registers.as_ref().is_none_or(|observation| {
                observation.completed_at().is_none() || observation.host_baud_register() != old_host
            })
            || state.domain_adc.as_ref().is_none_or(|observation| {
                observation.minimum_passed() != Some(true)
                    || observation.adaptive_level() != state.adc_level
                    || observation.host_baud_register() != old_host
            })
            || self.hardware.read(DHASH)? & RUN != 0
        {
            return Err("BM1396 operational baud requires same-owner cold/ADC population and unused transition".into());
        }
        if state.thermal.is_some() && !thermal_configured {
            return Err(
                "BM1396 baud refuses incomplete or different-host thermal configuration".into(),
            );
        }
        let mut fault = FaultGuard::new(&self.asic_fault, &self.terminal);
        self.baud_guard(old_host, deadline)?;
        self.query_predrain(state, deadline)?;
        let baud = match self.model {
            Model::S17e => 6_000_000,
            Model::T17e => 3_000_000,
        };
        let host_plan = bm1396_baud_plan(baud, 0, old_host).map_err(|e| e.to_string())?;
        state.operational_baud = Some(OperationalBaudObservation {
            model: self.model,
            baud,
            old_host,
            requested_host: host_plan.fpga_register_value,
            host_attempted: false,
            host_readback: None,
            records: Vec::new(),
            commands: Vec::new(),
            completed_at: None,
        });
        let mut plans = Vec::new();
        for &chain in &self.chains {
            let cold_misc = state
                .cold_registers
                .as_ref()
                .and_then(|cold| {
                    cold.commands().iter().find(|command| {
                        command.chain == chain && command.broadcast && command.register == 0x18
                    })
                })
                .ok_or("BM1396 baud missing retained cold Misc18 command")?
                .value;
            let records = self.query_locked_serviced(
                state,
                chain,
                None,
                0x18,
                old_host,
                deadline,
                &mut *service,
            )?;
            let old = baseline_misc(&records, self.model, thermal_configured, Some(cold_misc));
            retain(state, records)?;
            let plan = bm1396_baud_plan(baud, old?, old_host).map_err(|e| e.to_string())?;
            plans.push((chain, plan.misc_control_register_value));
        }
        if host_plan.high_speed_clock {
            // Source all-chain dispatcher preserves register-major order.
            for (register, value) in BM1396_HIGH_BAUD_CLOCK_PRELUDE {
                for &chain in &self.chains {
                    self.baud_write(state, chain, register, value, old_host, deadline, service)?;
                }
            }
        }
        for &(chain, value) in &plans {
            self.baud_write(state, chain, 0x18, value, old_host, deadline, service)?;
        }
        // Original50,000us monotonic delay; keep the sole FIFO owner draining.
        self.query_receive_window_serviced(state, 50, old_host, deadline, |state| {
            service(state, CommandServicePoint::IdleReceive)
        })?;
        self.baud_guard(old_host, deadline)?;
        service(state, CommandServicePoint::IdleReceive)?;
        state
            .operational_baud
            .as_mut()
            .ok_or("BM1396 lost baud custody")?
            .host_attempted = true;
        self.store(0x3c, host_plan.fpga_register_value, deadline, false)?;
        self.hardware.barrier()?;
        let actual_host = self.hardware.read(0x3c)?;
        state
            .operational_baud
            .as_mut()
            .ok_or("BM1396 lost baud custody")?
            .host_readback = Some(actual_host);
        self.baud_guard(host_plan.fpga_register_value, deadline)?;
        self.query_predrain(state, deadline)?;
        for &(chain, expected) in &plans {
            let ids = self.query_locked_serviced(
                state,
                chain,
                None,
                0,
                actual_host,
                deadline,
                &mut *service,
            )?;
            let valid = ids.iter().all(|raw| matches!(raw.payload(),ReturnPayload::Register(record) if record.value >> 16 == 0x1396));
            retain(state, ids)?;
            if !valid {
                return Err("BM1396 new-baud silicon population mismatch".into());
            }
            let records = self.query_locked_serviced(
                state,
                chain,
                None,
                0x18,
                actual_host,
                deadline,
                &mut *service,
            )?;
            let actual = baseline_misc(&records, self.model, false, None);
            retain(state, records)?;
            if actual? != expected {
                return Err("BM1396 new-baud Misc18 population mismatch".into());
            }
        }
        self.baud_guard(actual_host, deadline)?;
        service(state, CommandServicePoint::IdleReceive)?;
        state
            .operational_baud
            .as_mut()
            .ok_or("BM1396 lost baud custody")?
            .completed_at = Some(Instant::now());
        fault.complete();
        Ok(())
    }

    fn baud_guard(&self, host: u32, deadline: Instant) -> Result<(), String> {
        self.query_presence(deadline)?;
        self.query_host(host, deadline)?;
        if self.hardware.read(DHASH)? & RUN != 0 {
            return Err("BM1396 baud switch engine became active".into());
        }
        self.check(deadline, false)
    }

    fn baud_write(
        &self,
        state: &mut AsicState,
        chain: u8,
        register: u8,
        value: u32,
        host: u32,
        deadline: Instant,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<(), String> {
        self.baud_guard(host, deadline)?;
        state
            .operational_baud
            .as_mut()
            .ok_or("BM1396 lost baud custody")?
            .commands
            .push(OperationalBaudCommand {
                chain,
                register,
                value,
                completed: false,
            });
        self.command_and_receive_locked(
            state,
            chain,
            &bm1396_write_register_frame(true, 0, register, value),
            deadline,
            service,
        )?;
        state
            .operational_baud
            .as_mut()
            .ok_or("BM1396 lost baud custody")?
            .commands
            .last_mut()
            .ok_or("BM1396 missing baud command")?
            .completed = true;
        self.baud_guard(host, deadline)
    }
}

fn baseline_misc(
    records: &[PreservedReturn],
    model: Model,
    thermal_configured: bool,
    cold_misc: Option<u32>,
) -> Result<u32, String> {
    let mut values = Vec::new();
    for raw in records {
        let ReturnPayload::Register(record) = raw.payload() else {
            return Err("BM1396 baud Misc18 record type".into());
        };
        if record.register != 0x18 {
            return Err("BM1396 baud Misc18 register mismatch".into());
        }
        values.push((record.chip_address, record.value));
    }
    normalized_misc(&values, model, thermal_configured, cold_misc)
}

pub(super) fn normalized_misc(
    values: &[(u8, u32)],
    model: Model,
    thermal_configured: bool,
    cold_misc: Option<u32>,
) -> Result<u32, String> {
    let sensors = sensor_positions(model);
    let mut value = None;
    for &(chip, actual) in values {
        let is_sensor = sensors.iter().any(|sensor| sensor.wire_address() == chip);
        if let Some(cold) = cold_misc {
            let expected = if thermal_configured && is_sensor {
                (cold & !0x70) | 0x4030
            } else {
                cold
            };
            if actual != expected {
                return Err(
                    "BM1396 baud Misc18 changed from retained cold/thermal baseline".into(),
                );
            }
        } else if thermal_configured {
            return Err("BM1396 baud thermal normalization requires retained cold baseline".into());
        }
        // Original thermal-enable helper updates its shared Misc cache with
        // (old & !70)|4030 before the subsequent all-chip baud broadcast.
        // Native thermal setup changes only sensor chips, so this precise
        // heterogeneity requires this owner's completed thermal configuration.
        let normalized = if thermal_configured {
            if is_sensor && actual & 0x4070 != 0x4030 {
                return Err("BM1396 thermal sensor Misc18 enable state changed".into());
            }
            (actual & !0x4070) | 0x4030
        } else {
            actual
        };
        if value.is_some_and(|old| old != normalized) {
            return Err(
                "BM1396 baud Misc18 population is nonuniform outside admitted thermal bits".into(),
            );
        }
        value = Some(normalized);
    }
    value.ok_or_else(|| "BM1396 baud Misc18 population missing".into())
}

fn retain(state: &mut AsicState, records: Vec<PreservedReturn>) -> Result<(), String> {
    let ids: Vec<_> = records.iter().map(PreservedReturn::sequence).collect();
    state
        .operational_baud
        .as_mut()
        .ok_or("BM1396 lost baud custody")?
        .records
        .extend(records);
    state
        .pending
        .retain(|record| !ids.contains(&record.sequence()));
    Ok(())
}
