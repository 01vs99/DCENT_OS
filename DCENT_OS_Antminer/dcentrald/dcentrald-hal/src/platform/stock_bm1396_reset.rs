//! First exact model reset/census with retained voltage/PIC custody.
//! S17e source13a14: selected reset, 3000ms, lower rail5d78c, baud115200
//! through5ea20, PIC5426c, 1000ms, release, 200ms, exact135 census.
//! It shares these operations with T17e while keeping each observed population.
//!
//! Source: complete16958 power-census-v2, prelude19824..19830, initial5f628,
//! and lower-voltage profile35. The default zero-override lower rail is1800cV.
//! This receipt ends before high voltage/cold registers/ADC/thermal/cold300.
use super::*;
use dcentrald_common::bm1396_contract::{
    bm1396_read_register_frame, bm1396_write_register_frame, BM1396_WIRE_CHIP_ID,
};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};

#[path = "stock_bm1396_adapted.rs"]
mod adapted;
pub use adapted::{AdaptedStartupHealth, AdaptedStartupObservation, AdaptedStartupStage};

const RESET: u32 = 0x34;
const INITIAL_MISC: u32 = 0x0040_ba05;
const RETAINED_RECORDS: usize = 16_384;

#[derive(Clone, Debug)]
pub enum ConditioningResetEvent {
    Register {
        offset: u32,
        value: u32,
        completed_at: Option<Instant>,
    },
    Asic {
        chain: u8,
        register: u8,
        value: Option<u32>,
        completed_at: Option<Instant>,
    },
    Wait {
        milliseconds: u64,
        completed_milliseconds: u64,
    },
    PicEnable {
        chain: u8,
        request: Vec<u8>,
        transmitted: usize,
        response: Vec<u8>,
        framing_complete: bool,
        completed_at: Option<Instant>,
    },
}

/// Actual ordered portal/frame and complete unassigned identity-population
/// custody. No electrical reset, PLL lock or hash-work qualification is implied.
#[derive(Clone, Debug)]
pub struct ConditioningResetObservation {
    issuer: Arc<()>,
    source: SourceStartObservation,
    old_host: u32,
    requested_host: u32,
    events: Vec<ConditioningResetEvent>,
    low_voltage: Option<VoltageAttempt>,
    unsolicited: Vec<PreservedReturn>,
    census: Vec<PreservedReturn>,
    completed_chains: Vec<u8>,
    completed_at: Option<Instant>,
    failure: Option<String>,
}
impl ConditioningResetObservation {
    pub fn same_owner<H: Hardware>(&self, owner: &Arc<Transport<H>>) -> bool {
        Arc::ptr_eq(&self.issuer, &owner.identity)
    }
    pub fn source(&self) -> &SourceStartObservation {
        &self.source
    }
    pub fn old_host_register(&self) -> u32 {
        self.old_host
    }
    pub fn requested_host_register(&self) -> u32 {
        self.requested_host
    }
    pub fn events(&self) -> &[ConditioningResetEvent] {
        &self.events
    }
    pub fn low_voltage(&self) -> Option<&VoltageAttempt> {
        self.low_voltage.as_ref()
    }
    pub fn unsolicited_records(&self) -> &[PreservedReturn] {
        &self.unsolicited
    }
    pub fn census_records(&self) -> &[PreservedReturn] {
        &self.census
    }
    pub fn completed_chains(&self) -> &[u8] {
        &self.completed_chains
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
}

enum PicRequest {
    HighVoltage,
    LowVoltage,
    Enable(u8),
}
enum PicCompletion {
    HighVoltage,
    Ready,
    LowVoltage,
    Enabled(u8),
}

impl<H: Hardware> PicApplication<H> {
    pub fn conditioning_reset_observation(
        &self,
    ) -> Result<Option<ConditioningResetObservation>, String> {
        Ok(self
            .conditioning_reset
            .lock()
            .map_err(|_| "T17e reset custody poisoned")?
            .clone())
    }

    /// One unused first conditioning pass, through this exact application's
    /// voltage lease and this transport's counted worker/ASIC owner. The caller
    /// keeps independent fan, heartbeat, watchdog and source-high supervision.
    pub async fn initialize_conditioning_reset(
        self: &Arc<Self>,
        line: Arc<PowerLine<H>>,
        deadline: Instant,
    ) -> Result<ConditioningResetObservation, String> {
        let app = self.clone();
        let runtime = tokio::runtime::Handle::current();
        self.owner
            .worker(deadline, false, move |owner| {
                let mut state = owner.lock(&owner.asic, deadline, false)?;
                if !line.same_owner(&owner)
                    || state.startup_attempted
                    || state.dma_initialized
                    || state.thermal.is_some()
                    || state.assignment.is_some()
                    || state.cold_registers.is_some()
                    || state.domain_adc.is_some()
                    || state.operational_baud.is_some()
                    || !state.publications.is_empty()
                    || !state.register_observations.is_empty()
                {
                    return Err(
                        "T17e conditioning reset requires exact unused same-owner startup".into(),
                    );
                }
                line.check_active_source(&owner, deadline)?;
                let source = line
                    .source_start_observation()?
                    .ok_or("T17e reset source receipt lost")?;
                owner.factory_calibration_profile()?;
                app.require_health(deadline)?;
                let host = owner.hardware.read(0x3c)?;
                ResetTransaction::first(&app).reset_guard(&line, host, None, false, deadline)?;
                {
                    let mut retained = app
                        .conditioning_reset
                        .lock()
                        .map_err(|_| "T17e reset custody poisoned")?;
                    if retained.is_some() {
                        return Err("T17e conditioning reset attempt already spent".into());
                    }
                    *retained = Some(ConditioningResetObservation {
                        issuer: owner.identity.clone(),
                        source,
                        old_host: host,
                        requested_host: (host & 0xc0c0_c0c0) | 0x1a1a_1a1a,
                        events: Vec::new(),
                        low_voltage: None,
                        unsolicited: Vec::new(),
                        census: Vec::new(),
                        completed_chains: Vec::new(),
                        completed_at: None,
                        failure: None,
                    });
                }
                let (requests, request_rx) = mpsc::sync_channel(1);
                let (completion_tx, completed) = mpsc::sync_channel(1);
                let pic_app = app.clone();
                let pic_owner = owner.clone();
                let pic_worker = runtime.spawn(async move {
                    pic_owner
                        .worker(deadline, false, move |_| {
                            let lease = pic_app.voltage_lease(deadline)?;
                            ResetTransaction::first(&pic_app).reset_pic_loop(
                                &lease,
                                request_rx,
                                completion_tx,
                                deadline,
                            )
                        })
                        .await
                });
                let result = ResetTransaction::first(&app)
                    .reset_sequence(&mut state, &line, host, &requests, &completed, deadline);
                if result.is_err() {
                    owner.begin_terminal();
                }
                drop(requests);
                let pic_result = runtime
                    .block_on(pic_worker)
                    .map_err(|e| format!("T17e reset PIC worker join: {e}"))
                    .and_then(|r| r);
                let result = match (result, pic_result) {
                    (Ok(()), Ok(())) => owner.check(deadline, false),
                    (Err(a), Err(b)) => Err(format!("{a}; PIC worker: {b}")),
                    (Err(error), _) | (_, Err(error)) => Err(error),
                };
                let mut retained = app
                    .conditioning_reset
                    .lock()
                    .map_err(|_| "T17e reset custody poisoned")?;
                let observation = retained.as_mut().ok_or("T17e reset custody lost")?;
                if let Err(error) = result {
                    owner.begin_terminal();
                    observation.failure = Some(error.clone());
                    return Err(error);
                }
                observation.completed_at = Some(Instant::now());
                Ok(observation.clone())
            })
            .await
    }
}

// The actual first-pass caller and both counted workers keep their app alive.
// A later adapted controller can select a separate retained receipt without
// copying this validated byte/frame/reset/census sequence or replacing history.
struct ResetTransaction<'a, H: Hardware> {
    app: &'a PicApplication<H>,
    retained: &'a Mutex<Option<ConditioningResetObservation>>,
    predecessor: Option<&'a AdaptedPredecessor>,
}
impl<H: Hardware> std::ops::Deref for ResetTransaction<'_, H> {
    type Target = PicApplication<H>;
    fn deref(&self) -> &Self::Target {
        self.app
    }
}
impl<'a, H: Hardware> ResetTransaction<'a, H> {
    fn first(app: &'a PicApplication<H>) -> Self {
        Self {
            app,
            retained: &app.conditioning_reset,
            predecessor: None,
        }
    }

    fn adapted(app: &'a PicApplication<H>, predecessor: &'a AdaptedPredecessor) -> Self {
        Self {
            app,
            retained: &app.adapted_reset,
            predecessor: Some(predecessor),
        }
    }

    fn reset_pic_loop(
        &self,
        lease: &VoltageLease<'_>,
        requests: Receiver<PicRequest>,
        completed: SyncSender<PicCompletion>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.require_health(deadline)?;
        if let Some(predecessor) = self.predecessor {
            self.validate_adapted_predecessor_voltage_locked(lease, predecessor)?;
        } else {
            let state = self.state.lock().map_err(|_| "T17e PIC state poisoned")?;
            if state.next_voltage != 0
                || state.last_voltage.is_some()
                || !state.voltage_attempts.is_empty()
            {
                return Err("T17e conditioning must precede every voltage attempt".into());
            }
        }
        completed
            .send(PicCompletion::Ready)
            .map_err(|_| "T17e reset ASIC worker disconnected")?;
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
            let result = match request {
                PicRequest::HighVoltage => {
                    if self.predecessor.is_none() {
                        return Err("T17e first reset cannot issue adapted higher voltage".into());
                    }
                    let command = self.command_voltage_locked(lease, 2000, true, deadline)?;
                    self.retain_adapted_higher(command)?;
                    PicCompletion::HighVoltage
                }
                PicRequest::LowVoltage => {
                    if self.predecessor.is_some() {
                        self.command_voltage_locked(lease, 1800, true, deadline)?;
                    } else {
                        self.command_first_lower_voltage_locked(lease, deadline)?;
                    }
                    let mut state = self.state.lock().map_err(|_| "T17e PIC state poisoned")?;
                    let attempt = state
                        .voltage_attempts
                        .front()
                        .ok_or("T17e lower voltage attempt custody lost")?;
                    if attempt.completed_at().is_none()
                        || attempt.requested_centivolts() != 1800
                        || match self.predecessor {
                            Some(prior) => {
                                attempt.sequence() != prior.next_voltage
                                    || attempt.prior_command() != Some(prior.current_voltage)
                                    || attempt.initial_source_context_centivolts().is_some()
                            }
                            None => {
                                attempt.prior_command().is_some()
                                    || attempt.initial_source_context_centivolts() != Some(0)
                            }
                        }
                    {
                        return Err(
                            "T17e lower voltage differs from first default source command".into(),
                        );
                    }
                    let mut retained = self
                        .retained
                        .lock()
                        .map_err(|_| "T17e reset custody poisoned")?;
                    let observation = retained.as_mut().ok_or("T17e reset custody lost")?;
                    if observation.low_voltage.is_some() {
                        return Err("T17e lower voltage already retained".into());
                    }
                    observation.low_voltage = state.voltage_attempts.pop_front();
                    PicCompletion::LowVoltage
                }
                PicRequest::Enable(chain) => {
                    let request = bm1396_pic_rail_enable_frame();
                    let index = self.reset_event(ConditioningResetEvent::PicEnable {
                        chain,
                        request: request.to_vec(),
                        transmitted: 0,
                        response: Vec::new(),
                        framing_complete: false,
                        completed_at: None,
                    })?;
                    let _lane = self.owner.lock(&self.owner.management, deadline, false)?;
                    self.require_health(deadline)?;
                    let mut fault =
                        FaultGuard::new(&self.owner.management_fault, &self.owner.terminal);
                    let prefix = 0x0040_0000 | (u32::from(chain & 7) << 16);
                    for (sent, &byte) in request.iter().enumerate() {
                        self.owner.management_byte_locked(
                            prefix | u32::from(byte),
                            deadline,
                            false,
                        )?;
                        self.reset_update(index, |event| match event {
                            ConditioningResetEvent::PicEnable { transmitted, .. } => {
                                *transmitted = sent + 1
                            }
                            _ => unreachable!("retained PIC event type"),
                        })?;
                    }
                    self.owner
                        .delay(Duration::from_millis(500), deadline, false)?;
                    let mut bytes = Vec::with_capacity(2);
                    for _ in 0..2 {
                        let byte = self.owner.management_byte_locked(
                            prefix | 0x0200_0000,
                            deadline,
                            false,
                        )?;
                        bytes.push(byte);
                        self.reset_update(index, |event| match event {
                            ConditioningResetEvent::PicEnable { response, .. } => {
                                response.push(byte)
                            }
                            _ => unreachable!("retained PIC event type"),
                        })?;
                    }
                    // Preserve the complete consumed frame before reporting a
                    // late final-byte deadline. Its bytes are not lost on error.
                    self.reset_update(index, |event| match event {
                        ConditioningResetEvent::PicEnable {
                            framing_complete, ..
                        } => *framing_complete = true,
                        _ => unreachable!("retained PIC event type"),
                    })?;
                    fault.complete();
                    self.owner.check(deadline, false)?;
                    self.owner
                        .delay(Duration::from_millis(500), deadline, false)?;
                    if !bm1396_pic_response_accepted(&bytes, 2, 0x15) {
                        return Err("T17e reset PIC enable framing rejected".into());
                    }
                    self.require_health(deadline)?;
                    self.reset_update(index, |event| match event {
                        ConditioningResetEvent::PicEnable { completed_at, .. } => {
                            *completed_at = Some(Instant::now())
                        }
                        _ => unreachable!("retained PIC event type"),
                    })?;
                    PicCompletion::Enabled(chain)
                }
            };
            completed
                .send(result)
                .map_err(|_| "T17e reset ASIC worker disconnected")?;
        }
    }

    fn reset_guard(
        &self,
        line: &PowerLine<H>,
        host: u32,
        reset: Option<u32>,
        owned_busy: bool,
        deadline: Instant,
    ) -> Result<(), String> {
        self.require_health(deadline)?;
        line.check_active_source(&self.owner, deadline)?;
        self.owner.query_presence(deadline)?;
        if self.owner.hardware.read(DHASH)? & RUN != 0
            || self.owner.hardware.read(0x3c)? != host
            || (!owned_busy && self.owner.hardware.read(BC)? & BUSY != 0)
            || reset.is_some_and(|expected| self.owner.hardware.read(RESET).ok() != Some(expected))
        {
            return Err("T17e reset engine, host or reset word changed".into());
        }
        self.owner.check(deadline, false)
    }

    fn reset_receive(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        host: u32,
        reset: Option<u32>,
        owned_busy: bool,
        keep_query: bool,
        deadline: Instant,
    ) -> Result<(), String> {
        self.reset_guard(line, host, reset, owned_busy, deadline)?;
        self.owner.receive_locked(state, 128, deadline)?;
        if let Some(predecessor) = self.predecessor {
            self.check_adapted_pending_temperature(state, predecessor.preparation.cutoff_c())?;
            // Old automatic44 records are retained separately even inside a
            // census window; they can never satisfy its strict register0 set.
            self.retain_adapted_temperatures(state, true)?;
        }
        if !keep_query {
            let mut retained = self
                .retained
                .lock()
                .map_err(|_| "T17e reset custody poisoned")?;
            let observation = retained.as_mut().ok_or("T17e reset custody lost")?;
            if observation.unsolicited.len() + observation.census.len() + state.pending.len()
                > RETAINED_RECORDS
            {
                return Err(
                    "T17e reset raw custody capacity exhausted; pending records retained".into(),
                );
            }
            observation.unsolicited.extend(state.pending.drain(..));
        }
        self.reset_guard(line, host, reset, owned_busy, deadline)
    }

    fn reset_event(&self, event: ConditioningResetEvent) -> Result<usize, String> {
        let mut retained = self
            .retained
            .lock()
            .map_err(|_| "T17e reset custody poisoned")?;
        let events = &mut retained.as_mut().ok_or("T17e reset custody lost")?.events;
        let index = events.len();
        if index >= 128 {
            return Err("T17e reset event capacity exhausted".into());
        }
        events.push(event);
        Ok(index)
    }
    fn reset_update(
        &self,
        index: usize,
        update: impl FnOnce(&mut ConditioningResetEvent),
    ) -> Result<(), String> {
        let mut retained = self
            .retained
            .lock()
            .map_err(|_| "T17e reset custody poisoned")?;
        update(
            retained
                .as_mut()
                .and_then(|o| o.events.get_mut(index))
                .ok_or("T17e reset event custody lost")?,
        );
        Ok(())
    }

    fn reset_wait(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        host: u32,
        reset: Option<u32>,
        milliseconds: u64,
        keep_query: bool,
        deadline: Instant,
    ) -> Result<(), String> {
        let index = self.reset_event(ConditioningResetEvent::Wait {
            milliseconds,
            completed_milliseconds: 0,
        })?;
        for elapsed in 0..milliseconds {
            self.reset_receive(state, line, host, reset, false, keep_query, deadline)?;
            self.owner
                .delay(Duration::from_millis(1), deadline, false)?;
            self.reset_update(index, |event| match event {
                ConditioningResetEvent::Wait {
                    completed_milliseconds,
                    ..
                } => *completed_milliseconds = elapsed + 1,
                _ => unreachable!("retained wait event type"),
            })?;
        }
        self.reset_receive(state, line, host, reset, false, keep_query, deadline)
    }

    fn reset_store(&self, offset: u32, value: u32, deadline: Instant) -> Result<(), String> {
        let index = self.reset_event(ConditioningResetEvent::Register {
            offset,
            value,
            completed_at: None,
        })?;
        self.owner.checked_store(offset, value, deadline, false)?;
        if self.owner.hardware.read(offset)? != value {
            return Err("T17e reset register readback mismatch".into());
        }
        self.reset_update(index, |event| match event {
            ConditioningResetEvent::Register { completed_at, .. } => {
                *completed_at = Some(Instant::now())
            }
            _ => unreachable!("retained register event type"),
        })
    }

    fn reset_command(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        chain: u8,
        register: u8,
        value: Option<u32>,
        host: u32,
        reset: u32,
        keep_query: bool,
        deadline: Instant,
    ) -> Result<(), String> {
        self.reset_guard(line, host, Some(reset), false, deadline)?;
        let frame = match value {
            Some(value) => bm1396_write_register_frame(true, 0, register, value).to_vec(),
            None => bm1396_read_register_frame(true, 0, register).to_vec(),
        };
        let index = self.reset_event(ConditioningResetEvent::Asic {
            chain,
            register,
            value,
            completed_at: None,
        })?;
        self.owner
            .command_locked_serviced(chain, &frame, deadline, |point| match point {
                CommandServicePoint::BeforePublish => {
                    self.reset_guard(line, host, Some(reset), false, deadline)
                }
                CommandServicePoint::Poll => {
                    self.reset_receive(state, line, host, Some(reset), true, keep_query, deadline)
                }
                CommandServicePoint::IdleReceive => {
                    unreachable!("command does not own idle receive window")
                }
            })?;
        self.reset_guard(line, host, Some(reset), false, deadline)?;
        self.reset_update(index, |event| match event {
            ConditioningResetEvent::Asic { completed_at, .. } => {
                *completed_at = Some(Instant::now())
            }
            _ => unreachable!("retained ASIC event type"),
        })
    }

    fn reset_completion(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        host: u32,
        reset: Option<u32>,
        completed: &Receiver<PicCompletion>,
        deadline: Instant,
    ) -> Result<PicCompletion, String> {
        loop {
            self.reset_receive(state, line, host, reset, false, false, deadline)?;
            match completed.try_recv() {
                Ok(value) => return Ok(value),
                Err(TryRecvError::Disconnected) => {
                    return Err("T17e reset PIC worker ended before completion".into())
                }
                Err(TryRecvError::Empty) => {
                    self.owner
                        .delay(Duration::from_millis(1), deadline, false)?
                }
            }
        }
    }

    fn reset_sequence(
        &self,
        state: &mut AsicState,
        line: &PowerLine<H>,
        mut host: u32,
        requests: &SyncSender<PicRequest>,
        completed: &Receiver<PicCompletion>,
        deadline: Instant,
    ) -> Result<(), String> {
        if self.predecessor.is_none()
            && !matches!(
                self.reset_completion(state, line, host, None, completed, deadline)?,
                PicCompletion::Ready
            )
        {
            return Err("T17e reset first PIC completion is not lease admission".into());
        }
        // The containing-main prelude precedes the first original16958 call;
        // it is not replayed by its second reset branch.
        if self.predecessor.is_none() {
            self.reset_store(0x100, 0x8400, deadline)?;
            self.reset_store(0xf8, 0x10000, deadline)?;
        }
        let selected = self
            .owner
            .chains
            .iter()
            .fold(0u32, |mask, &chain| mask | (1 << chain));
        let mut reset = self.owner.hardware.read(RESET)? | selected;
        self.reset_store(RESET, reset, deadline)?;
        self.reset_wait(state, line, host, Some(reset), 3000, false, deadline)?;
        requests
            .send(PicRequest::LowVoltage)
            .map_err(|_| "T17e reset PIC request disconnected")?;
        if !matches!(
            self.reset_completion(state, line, host, Some(reset), completed, deadline)?,
            PicCompletion::LowVoltage
        ) {
            return Err("T17e reset lower voltage completion changed".into());
        }
        let previous_misc = if let Some(prior) = self.predecessor {
            let baud = prior
                .preparation
                .operational_baud()
                .ok_or("T17e adapted baud absent")?;
            let values: Vec<_> = baud
                .commands()
                .iter()
                .filter(|command| command.register == 0x18 && command.completed)
                .map(|command| (command.chain, command.value))
                .collect();
            let first = values.first().ok_or("T17e adapted Misc command absent")?.1;
            if values.len() != self.owner.chains.len()
                || values.iter().any(|(_, value)| *value != first)
                || self
                    .owner
                    .chains
                    .iter()
                    .any(|chain| values.iter().filter(|(slot, _)| slot == chain).count() != 1)
            {
                return Err("T17e adapted retained Misc population is not uniform".into());
            }
            first
        } else {
            INITIAL_MISC
        };
        let misc = (previous_misc & !0x0f01_1f00) | 0x1a00;
        for &chain in &self.owner.chains {
            self.reset_command(
                state,
                line,
                chain,
                0x18,
                Some(misc),
                host,
                reset,
                false,
                deadline,
            )?;
        }
        self.reset_wait(state, line, host, Some(reset), 50, false, deadline)?;
        host = (host & 0xc0c0_c0c0) | 0x1a1a_1a1a;
        self.reset_store(0x3c, host, deadline)?;
        self.reset_wait(state, line, host, Some(reset), 10, false, deadline)?;
        for &chain in &self.owner.chains {
            requests
                .send(PicRequest::Enable(chain))
                .map_err(|_| "T17e reset PIC request disconnected")?;
            if !matches!(self.reset_completion(state, line, host, Some(reset), completed, deadline)?, PicCompletion::Enabled(actual) if actual == chain)
            {
                return Err("T17e reset enabled chain completion changed".into());
            }
            self.reset_wait(state, line, host, Some(reset), 1000, false, deadline)?;
            reset &= !(1 << chain);
            self.reset_store(RESET, reset, deadline)?;
            self.reset_wait(state, line, host, Some(reset), 200, false, deadline)?;
            self.reset_command(
                state,
                line,
                chain,
                0x58,
                Some(0x0777_7777),
                host,
                reset,
                false,
                deadline,
            )?;
            let watermark = state.next_return;
            self.reset_command(state, line, chain, 0, None, host, reset, true, deadline)?;
            let mut complete = false;
            let mut accepted = false;
            for round in 0..5 {
                self.reset_wait(state, line, host, Some(reset), 300, true, deadline)?;
                let mut records = Vec::new();
                for raw in state
                    .pending
                    .iter()
                    .filter(|raw| raw.sequence() >= watermark)
                {
                    match raw.payload() {
                        ReturnPayload::Register(record)
                            if record.chain_slot == chain
                                && record.register == 0
                                && record.value >> 16 == u32::from(BM1396_WIRE_CHIP_ID) =>
                        {
                            records.push(raw.clone())
                        }
                        _ => return Err(
                            "T17e reset census wrong chain/register/identity or unexpected return"
                                .into(),
                        ),
                    }
                }
                if records.len() > usize::from(self.owner.model.expected_chips_per_present_chain()) {
                    return Err("T17e reset census exceeds exact model population".into());
                }
                if records.len() == usize::from(self.owner.model.expected_chips_per_present_chain()) {
                    if complete {
                        let ids: Vec<_> = records.iter().map(PreservedReturn::sequence).collect();
                        let mut retained = self
                            .retained
                            .lock()
                            .map_err(|_| "T17e reset custody poisoned")?;
                        let observation = retained.as_mut().ok_or("T17e reset custody lost")?;
                        if observation.unsolicited.len() + observation.census.len() + records.len()
                            > RETAINED_RECORDS
                        {
                            return Err(
                                "T17e reset complete census capacity exhausted; pending retained"
                                    .into(),
                            );
                        }
                        observation.census.extend(records);
                        observation.completed_chains.push(chain);
                        state.pending.retain(|raw| !ids.contains(&raw.sequence()));
                        accepted = true;
                        break;
                    }
                    complete = true;
                }
                if round != 4 {
                    self.reset_wait(state, line, host, Some(reset), 100, true, deadline)?;
                }
            }
            if !accepted {
                return Err("BM1396 reset lacks the exact complete model census".into());
            }
        }
        self.reset_receive(state, line, host, Some(reset), false, false, deadline)
    }
}
