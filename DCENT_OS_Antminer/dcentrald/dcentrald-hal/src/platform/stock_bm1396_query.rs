//! Correlated queries through the sole retained ASIC/FIFO owner.
//!
//! Exact signed S17e 82ca4 (T17e 83b4c) clears its software queue, sends a
//! register request, waits 10 ms and joins chain/chip/register. This owner keeps
//! pre-existing records instead of clearing them and never retries an unanswered
//! request. FPGA CRC-error/type validation stays in the original receiver codec.
use super::*;
use dcentrald_common::bm1396_work::Bm1396RegisterRecord;

const OBSERVATION_CAPACITY: usize = 64;
const DRAIN_BATCHES: usize = 32;
const REPLY_BATCHES: usize = 256;

/// Complete, same-owner register replies retained before an async waiter can
/// disappear. This records observed addresses, not proof of initial enumeration,
/// silicon identity, successful reset, or physical application of a setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterObservation {
    issuer: Arc<()>,
    sequence: u64,
    model: Model,
    host_baud_register: u32,
    records: Vec<PreservedReturn>,
    completed_at: Instant,
}
impl RegisterObservation {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn model(&self) -> Model {
        self.model
    }
    pub fn host_baud_register(&self) -> u32 {
        self.host_baud_register
    }
    pub fn host_baud_selectors(&self) -> [u8; 4] {
        self.host_baud_register
            .to_le_bytes()
            .map(|byte| byte & 0x3f)
    }
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
    pub fn raw_records(&self) -> &[PreservedReturn] {
        &self.records
    }
    pub fn registers(&self) -> impl Iterator<Item = &Bm1396RegisterRecord> {
        self.records
            .iter()
            .filter_map(|record| match record.payload() {
                ReturnPayload::Register(value) => Some(value),
                _ => None,
            })
    }
}

impl<H: Hardware> Transport<H> {
    pub fn pending_register_observations(&self) -> Result<Vec<RegisterObservation>, String> {
        let state = self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 ASIC owner busy or poisoned")?;
        Ok(state.register_observations.iter().cloned().collect())
    }

    pub fn acknowledge_register_observation(
        &self,
        observation: &RegisterObservation,
    ) -> Result<(), String> {
        let mut state = self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 ASIC owner busy or poisoned")?;
        if !Arc::ptr_eq(&observation.issuer, &self.identity)
            || state.register_observations.front() != Some(observation)
        {
            return Err(
                "BM1396 register observation acknowledgment is foreign, stale or out of order"
                    .into(),
            );
        }
        state.register_observations.pop_front();
        Ok(())
    }

    /// One addressed query. Returns only the retained observation sequence; the
    /// observation and its raw records remain here until explicit acknowledgment.
    pub async fn query_register(
        self: &Arc<Self>,
        chain: u8,
        chip: u8,
        register: u8,
        deadline: Instant,
    ) -> Result<u64, String> {
        self.chain(chain)?;
        self.query_chip(chip)?;
        self.query_register_sets(vec![(chain, Some(chip))], register, deadline)
            .await
    }

    /// A broadcast read of every selected chain at the unchanged observed host
    /// baud. Requires exactly the model's assigned addresses. This is suitable
    /// AFTER assignment; it deliberately cannot qualify an unassigned census.
    pub async fn query_assigned_population(
        self: &Arc<Self>,
        register: u8,
        deadline: Instant,
    ) -> Result<u64, String> {
        let requests = self.chains.iter().map(|&chain| (chain, None)).collect();
        self.query_register_sets(requests, register, deadline).await
    }

    fn query_chip(&self, chip: u8) -> Result<(), String> {
        let interval = self.model.address_interval();
        if chip % interval != 0
            || u16::from(chip / interval) >= self.model.expected_chips_per_present_chain()
        {
            return Err("BM1396 query address is outside exact assigned geometry".into());
        }
        Ok(())
    }

    async fn query_register_sets(
        self: &Arc<Self>,
        requests: Vec<(u8, Option<u8>)>,
        register: u8,
        deadline: Instant,
    ) -> Result<u64, String> {
        self.worker(deadline, false, move |this| {
            let mut state = this.lock(&this.asic, deadline, false)?;
            if state.register_observations.len() >= OBSERVATION_CAPACITY {
                return Err("BM1396 retained register observation capacity exhausted".into());
            }
            let mut fault = FaultGuard::new(&this.asic_fault, &this.terminal);
            this.query_presence(deadline)?;
            let host = this.hardware.read(0x3c)?;
            this.query_predrain(&mut state, deadline)?;
            let mut records = Vec::new();
            for (chain, chip) in requests {
                records
                    .extend(this.query_locked(&mut state, chain, chip, register, host, deadline)?);
            }
            this.query_presence(deadline)?;
            this.query_host(host, deadline)?;
            let sequence = state.next_observation;
            let next = sequence
                .checked_add(1)
                .ok_or("BM1396 observation sequence exhausted")?;
            // Raw custody transfers while the same ASIC guard is held. Failed
            // queries leave all partial matches in the ordinary pending queue.
            let ids: Vec<_> = records.iter().map(PreservedReturn::sequence).collect();
            state.register_observations.push_back(RegisterObservation {
                issuer: Arc::clone(&this.identity),
                sequence,
                model: this.model,
                host_baud_register: host,
                records,
                completed_at: Instant::now(),
            });
            state.next_observation = next;
            state
                .pending
                .retain(|record| !ids.contains(&record.sequence()));
            fault.complete();
            Ok(sequence)
        })
        .await
    }

    pub(super) fn query_presence(&self, deadline: Instant) -> Result<(), String> {
        let expected = self
            .chains
            .iter()
            .fold(0u32, |mask, &chain| mask | (1 << chain));
        if self.hardware.read(8)? & 0xffff != expected {
            return Err("BM1396 presence changed during register observation".into());
        }
        self.check(deadline, false)
    }

    pub(super) fn query_host(&self, host: u32, deadline: Instant) -> Result<(), String> {
        let actual = self.hardware.read(BC)?;
        self.check(deadline, false)?;
        if actual & BUSY != 0 || self.hardware.read(0x3c)? != host {
            return Err("BM1396 host baud or command portal changed during query".into());
        }
        self.check(deadline, false)
    }

    pub(super) fn query_predrain(
        &self,
        state: &mut AsicState,
        deadline: Instant,
    ) -> Result<(), String> {
        for _ in 0..DRAIN_BATCHES {
            self.receive_locked(state, 128, deadline)?;
            if self.hardware.read(0x18)? & 0x1ff < 2 {
                return self.check(deadline, false);
            }
        }
        Err("BM1396 stale FIFO predrain exhausted; no query issued".into())
    }

    /// Internal bridge/startup users must hold the sole ASIC guard and retain
    /// their final observation before retiring any returned matching records.
    pub(super) fn query_locked(
        &self,
        state: &mut AsicState,
        chain: u8,
        chip: Option<u8>,
        register: u8,
        host: u32,
        deadline: Instant,
    ) -> Result<Vec<PreservedReturn>, String> {
        self.query_locked_serviced(state, chain, chip, register, host, deadline, |_, _| Ok(()))
    }

    pub(super) fn query_locked_serviced<F>(
        &self,
        state: &mut AsicState,
        chain: u8,
        chip: Option<u8>,
        register: u8,
        host: u32,
        deadline: Instant,
        mut service: F,
    ) -> Result<Vec<PreservedReturn>, String>
    where
        F: FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    {
        self.query_host(host, deadline)?;
        let watermark = state.next_return;
        let frame = dcentrald_common::bm1396_contract::bm1396_read_register_frame(
            chip.is_none(),
            chip.unwrap_or(0),
            register,
        );
        self.command_and_receive_locked(state, chain, &frame, deadline, &mut service)?;
        // Stock's query thread waits10/300ms while its separate receiver keeps
        // draining each1ms. Preserve that complete observation window through
        // this sole owner; sleeping the FIFO worker could overflow hardware.
        self.query_receive_window_serviced(
            state,
            if chip.is_some() { 10 } else { 300 },
            host,
            deadline,
            |state| service(state, CommandServicePoint::IdleReceive),
        )?;
        let expected = chip.map_or(
            self.model.expected_chips_per_present_chain() as usize,
            |_| 1,
        );
        for _ in 0..REPLY_BATCHES {
            self.receive_locked(state, 128, deadline)?;
            self.query_host(host, deadline)?;
            service(state, CommandServicePoint::IdleReceive)?;
            let matches = self.query_matches(state, watermark, chain, chip, register)?;
            if matches.len() == expected {
                // An additional source-sized receive window catches currently
                // queued duplicates. It is not a wire transaction tag or a claim
                // that an arbitrarily late duplicate can never exist.
                self.query_receive_window_serviced(state, 10, host, deadline, |state| {
                    service(state, CommandServicePoint::IdleReceive)
                })?;
                self.receive_locked(state, 128, deadline)?;
                self.query_host(host, deadline)?;
                service(state, CommandServicePoint::IdleReceive)?;
                return self.query_matches(state, watermark, chain, chip, register);
            }
            self.delay(Duration::from_millis(1), deadline, false)?;
        }
        Err("BM1396 register reply bound exhausted; request is not retried".into())
    }

    /// Emulate the source receiver's1ms cadence throughout the caller's
    /// original observation window. Every popped record stays in AsicState.
    pub(super) fn query_receive_window(
        &self,
        state: &mut AsicState,
        milliseconds: u64,
        host: u32,
        deadline: Instant,
    ) -> Result<(), String> {
        self.query_receive_window_serviced(state, milliseconds, host, deadline, |_| Ok(()))
    }

    pub(super) fn query_receive_window_serviced<F>(
        &self,
        state: &mut AsicState,
        milliseconds: u64,
        host: u32,
        deadline: Instant,
        mut service: F,
    ) -> Result<(), String>
    where
        F: FnMut(&mut AsicState) -> Result<(), String>,
    {
        self.check(deadline, false)?;
        if Instant::now()
            .checked_add(Duration::from_millis(milliseconds))
            .is_none_or(|end| end >= deadline)
        {
            return Err("BM1396 receive window exceeds absolute deadline".into());
        }
        for _ in 0..milliseconds {
            self.receive_locked(state, 128, deadline)?;
            self.query_host(host, deadline)?;
            service(state)?;
            self.delay(Duration::from_millis(1), deadline, false)?;
        }
        self.receive_locked(state, 128, deadline)?;
        self.query_host(host, deadline)?;
        service(state)
    }

    fn query_matches(
        &self,
        state: &AsicState,
        watermark: u64,
        chain: u8,
        chip: Option<u8>,
        register: u8,
    ) -> Result<Vec<PreservedReturn>, String> {
        let mut seen = [false; 256];
        let mut matches = Vec::new();
        for raw in state
            .pending
            .iter()
            .filter(|raw| raw.sequence() >= watermark)
        {
            if let ReturnPayload::Register(value) = raw.payload() {
                if value.chain_slot != chain
                    || value.register != register
                    || chip.is_some_and(|address| value.chip_address != address)
                {
                    return Err(
                        "BM1396 fresh register reply does not match chain/address/register".into(),
                    );
                }
                self.query_chip(value.chip_address)?;
                if std::mem::replace(&mut seen[value.chip_address as usize], true) {
                    return Err("BM1396 duplicate fresh register reply".into());
                }
                matches.push(raw.clone());
            }
        }
        matches.sort_by_key(|raw| match raw.payload() {
            ReturnPayload::Register(value) => value.chip_address,
            _ => 0,
        });
        Ok(matches)
    }
}
