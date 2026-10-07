//! Original pre-assignment census and exact address-reset/assignment sequence.
//! R06 native-startup-population-vectors-v1 executes all16 retained source cases.
//! This component neither turns power on nor creates independent enable authority.
use super::*;
use dcentrald_common::bm1396_contract::{
    bm1396_read_register_frame, bm1396_reset_address_frame, bm1396_set_address_frame,
    BM1396_WIRE_CHIP_ID,
};

/// Complete same-owner census/assignment reply custody. Pre-assignment addresses
/// may repeat; the final assigned set must be complete and unique. It establishes
/// observed communication at the retained host selector, not reset/rail safety.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentObservation {
    issuer: Arc<()>,
    model: Model,
    chains: Vec<u8>,
    host_baud_register: u32,
    initial_records: Vec<PreservedReturn>,
    assigned_records: Vec<PreservedReturn>,
    completed_at: Instant,
}
impl AssignmentObservation {
    pub fn model(&self) -> Model {
        self.model
    }
    pub fn chains(&self) -> &[u8] {
        &self.chains
    }
    pub fn host_baud_register(&self) -> u32 {
        self.host_baud_register
    }
    pub fn initial_records(&self) -> &[PreservedReturn] {
        &self.initial_records
    }
    pub fn assigned_records(&self) -> &[PreservedReturn] {
        &self.assigned_records
    }
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
}

impl<H: Hardware> Transport<H> {
    pub fn assignment_observation(&self) -> Result<Option<AssignmentObservation>, String> {
        let state = self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 ASIC owner busy or poisoned")?;
        Ok(state.assignment.clone())
    }

    /// Establish fresh communication without changing the observed host rate,
    /// then run the exact source address sequence and verify the assigned set.
    /// Source power/reset/voltage/heartbeat ordering remains the runtime caller's
    /// separately qualified responsibility. A mismatch is terminal, with no PIC
    /// application reset, speculative baud sweep or voltage escalation retry.
    pub async fn initialize_assigned_population(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.worker(deadline, false, move |this| {
            let mut state = this.lock(&this.asic, deadline, false)?;
            if state.startup_attempted
                || state.thermal.is_some()
                || !state.publications.is_empty()
                || this.hardware.read(DHASH)? & RUN != 0
            {
                return Err("BM1396 assignment requires one unused cold startup attempt".into());
            }
            state.startup_attempted = true;
            let mut fault = FaultGuard::new(&this.asic_fault, &this.terminal);
            this.query_presence(deadline)?;
            let host = this.hardware.read(0x3c)?;
            this.query_host(host, deadline)?;
            this.query_predrain(&mut state, deadline)?;
            let mut initial = Vec::new();
            for &chain in &this.chains {
                initial.extend(this.initial_census(&mut state, chain, host, deadline)?);
            }
            this.assign_counted_population_locked(&mut state, host, initial, deadline)?;
            fault.complete();
            Ok(())
        })
        .await
    }

    pub(super) fn assign_counted_population_locked(
        &self,
        state: &mut AsicState,
        host: u32,
        initial: Vec<PreservedReturn>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.assign_counted_population_serviced(state, host, initial, deadline, &mut |_, _| Ok(()))
    }

    pub(super) fn assign_counted_population_serviced(
        &self,
        state: &mut AsicState,
        host: u32,
        initial: Vec<PreservedReturn>,
        deadline: Instant,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<(), String> {
        for &chain in &self.chains {
            for _ in 0..3 {
                self.command_and_receive_locked(
                    state,
                    chain,
                    &bm1396_reset_address_frame(),
                    deadline,
                    service,
                )?;
                self.query_receive_window_serviced(state, 30, host, deadline, |state| {
                    service(state, CommandServicePoint::IdleReceive)
                })?;
                self.query_host(host, deadline)?;
            }
            let interval = u16::from(self.model.address_interval());
            for index in 0..256 / interval {
                self.command_and_receive_locked(
                    state,
                    chain,
                    &bm1396_set_address_frame((index * interval) as u8),
                    deadline,
                    service,
                )?;
                self.query_receive_window_serviced(state, 30, host, deadline, |state| {
                    service(state, CommandServicePoint::IdleReceive)
                })?;
                self.query_host(host, deadline)?;
            }
        }
        self.query_receive_window_serviced(state, 10, host, deadline, |state| {
            service(state, CommandServicePoint::IdleReceive)
        })?;
        self.query_predrain(state, deadline)?;
        let mut assigned = Vec::new();
        for &chain in &self.chains {
            let replies =
                self.query_locked_serviced(state, chain, None, 0, host, deadline, &mut *service)?;
            if replies.iter().any(|raw| !matches!(raw.payload(), ReturnPayload::Register(record) if record.value >> 16 == u32::from(BM1396_WIRE_CHIP_ID))) {
                    return Err("BM1396 assigned register0 silicon identity mismatch".into());
                }
            assigned.extend(replies);
        }
        self.query_presence(deadline)?;
        self.query_host(host, deadline)?;
        let ids: Vec<_> = initial
            .iter()
            .chain(&assigned)
            .map(PreservedReturn::sequence)
            .collect();
        state.assignment = Some(AssignmentObservation {
            issuer: Arc::clone(&self.identity),
            model: self.model,
            chains: self.chains.clone(),
            host_baud_register: host,
            initial_records: initial,
            assigned_records: assigned,
            completed_at: Instant::now(),
        });
        state.pending.retain(|raw| !ids.contains(&raw.sequence()));
        Ok(())
    }

    pub(super) fn initial_census(
        &self,
        state: &mut AsicState,
        chain: u8,
        host: u32,
        deadline: Instant,
    ) -> Result<Vec<PreservedReturn>, String> {
        self.initial_register_population(state, chain, 0, host, deadline)
    }

    pub(super) fn initial_register_population(
        &self,
        state: &mut AsicState,
        chain: u8,
        register: u8,
        host: u32,
        deadline: Instant,
    ) -> Result<Vec<PreservedReturn>, String> {
        self.initial_register_population_serviced(
            state,
            chain,
            register,
            host,
            deadline,
            &mut |_, _| Ok(()),
        )
    }

    pub(super) fn initial_register_population_serviced(
        &self,
        state: &mut AsicState,
        chain: u8,
        register: u8,
        host: u32,
        deadline: Instant,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<Vec<PreservedReturn>, String> {
        let watermark = state.next_return;
        self.query_host(host, deadline)?;
        self.command_and_receive_locked(
            state,
            chain,
            &bm1396_read_register_frame(true, 0, register),
            deadline,
            service,
        )?;
        let expected = self.model.expected_chips_per_present_chain() as usize;
        // Original census has one300ms window followed by up to four empty
        // 300+100ms windows. Its return code remains1 on short count; we inspect
        // the actual records and never use that weak success convention.
        let mut complete = false;
        for round in 0..5 {
            self.query_receive_window_serviced(state, 300, host, deadline, |state| {
                service(state, CommandServicePoint::IdleReceive)
            })?;
            for _ in 0..4 {
                self.receive_locked(state, 128, deadline)?;
                if self.hardware.read(0x18)? & 0x1ff < 2 {
                    break;
                }
            }
            self.query_host(host, deadline)?;
            service(state, CommandServicePoint::IdleReceive)?;
            let mut records = Vec::new();
            for raw in state
                .pending
                .iter()
                .filter(|raw| raw.sequence() >= watermark)
            {
                match raw.payload() {
                    ReturnPayload::Register(record)
                        if record.chain_slot == chain
                            && record.register == register
                            && (register != 0
                                || record.value >> 16 == u32::from(BM1396_WIRE_CHIP_ID)) =>
                    {
                        records.push(raw.clone())
                    }
                    ReturnPayload::Nonce { .. } => {}
                    _ => {
                        return Err(
                            "BM1396 initial census record has wrong chain/register/identity".into(),
                        )
                    }
                }
            }
            if records.len() > expected {
                return Err("BM1396 initial census exceeds exact source count".into());
            }
            if records.len() == expected {
                if complete {
                    return Ok(records);
                }
                complete = true;
            }
            if round != 4 {
                self.query_receive_window_serviced(state, 100, host, deadline, |state| {
                    service(state, CommandServicePoint::IdleReceive)
                })?;
            }
        }
        Err("BM1396 initial census lacks exact source chip count".into())
    }
}
