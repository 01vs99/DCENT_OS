//! Draft retained BB management lifetime with serialized voltage execution.
//!
//! The original bus owners stay inside the diagnostic pair until explicit
//! caller joins and service closes. Later fixed APW observations use a private
//! handle from that same original worker. No historical DTO, replacement bus,
//! caller-supplied current, GPIO or ASIC pause token is accepted.
//! Internal execution remains staged until the full cold/runtime controller joins
//! factory, ASIC/GPIO and terminal lifetime. No production actuator is registered.
use crate::bb_apw_diagnostics::{Field, ProfileAttempt, Query};
use crate::bb_pre_power_diagnostics::{BbPrePowerDiagnosticSnapshot, BbPrePowerDiagnostics};
use crate::bb_voltage_planner::{self, History, Plan};
use crate::bb_voltage_profile::{Hw76RequestedVoltageProfile, SelectedVoltagePair};
use crate::i2c::{I2cServiceCloseReceipt, I2cServiceHandle, I2cServiceOwner};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::task::JoinHandle;

#[path = "bb_management_owner_bus0.rs"]
mod runtime_bus0;
pub(crate) use runtime_bus0::BbOwnedBus0Observation;

#[path = "bb_management_owner_execution.rs"]
mod execution;
pub(crate) use execution::BbOwnedExecutionObservation;

#[path = "bb_management_owner_heartbeat.rs"]
mod heartbeat;
pub use heartbeat::{
    BbHeartbeatCutoff, BbHeartbeatCutoffObservation, BbHeartbeatPicObservation, BbHeartbeatRound,
    BbHeartbeatSnapshot,
};

#[path = "bb_management_owner_pic_enable.rs"]
pub(crate) mod pic_enable;

#[path = "bb_management_owner_pic_initialization_exchange.rs"]
pub(crate) mod pic_initialization_exchange;

#[path = "bb_management_owner_pic_optional_bridge.rs"]
pub(crate) mod pic_optional_bridge;

#[path = "bb_management_owner_terminal.rs"]
mod terminal;
#[path = "bb_management_owner_initial_disable.rs"]
pub(crate) mod initial_disable;
pub(crate) use pic_initialization_exchange::pre_power_initial::Observation as BbInitialBridgeData;
pub use terminal::{
    BbTerminalOperation, BbTerminalPicObservation, BbTerminalStepObservation,
    BbTerminalSweepObservation, BbTerminalWorkerObservation,
};

#[derive(Clone, Debug)]
pub struct BbHeartbeatReleaseObservation {
    pub first_attempted_at: Instant,
    pub released_at: Option<Instant>,
    pub first_failure: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct BbPairedManagementData {
    pub sequence: u64,
    pub deadline: Instant,
    pub bus0: BbOwnedBus0Observation,
    pub voltage: BbOwnedVoltageObservation,
    /// Both actual callers were joined in this same cycle. This is historical
    /// diagnostic completion, not physical sample freshness or power authority.
    pub both_callers_joined_at: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct BbVoltagePreview {
    /// Decoded PSU report, not an independently measured rail voltage.
    pub reported_millivolts: u16,
    pub selected_pair: Option<SelectedVoltagePair>,
    /// Every preview starts with empty request history. Computing or returning
    /// a proposal never establishes that a voltage request was actually sent.
    pub first_step: Option<Plan>,
}

#[derive(Clone, Debug)]
pub(crate) struct BbOwnedVoltageObservation {
    pub sequence: u64,
    pub deadline: Instant,
    pub requested_profile: Hw76RequestedVoltageProfile,
    /// Caller-side timestamps only. They do not backdate physical sampling.
    pub caller_prepared_at: Option<Instant>,
    pub caller_returned_at: Option<Instant>,
    pub caller_joined_at: Option<Instant>,
    pub attempt: Option<ProfileAttempt>,
    pub failure: Option<String>,
    /// Historical numerical output from this exact joined observation only.
    /// Never an energizing, freshness, convergence or completed-off capability.
    pub preview: Option<BbVoltagePreview>,
}

#[derive(Clone, Debug)]
pub(crate) struct BbManagementSnapshot {
    pub diagnostics: BbPrePowerDiagnosticSnapshot,
    pub stopped_at: Option<Instant>,
    pub stop_reason: Option<String>,
    pub requested_profile: Hw76RequestedVoltageProfile,
    /// Bounded storage: latest attempt only. Returned snapshots can be retained
    /// by a recorder; an unjoined attempt can never be replaced by a new one.
    pub latest_voltage: Option<BbOwnedVoltageObservation>,
    pub voltage_caller_pending: bool,
    pub latest_bus0: Option<BbOwnedBus0Observation>,
    pub bus0_caller_pending: bool,
    pub last_complete_pair: Option<BbPairedManagementData>,
    pub execution_caller_pending: bool,
    pub latest_execution: Option<BbOwnedExecutionObservation>,
    pub last_complete_execution: Option<BbOwnedExecutionObservation>,
    pub committed_request_history: History,
    pub profile_generation: u64,
    pub heartbeat: Option<BbHeartbeatSnapshot>,
    pub terminal: Option<BbTerminalSweepObservation>,
    pub heartbeat_release: Option<BbHeartbeatReleaseObservation>,
}

#[derive(Clone)]
struct Handles {
    bus0: I2cServiceHandle,
    bus1: I2cServiceHandle,
}

impl Handles {
    fn fence(&self) {
        self.bus0.latch_terminal_safe_off();
        self.bus1.latch_terminal_safe_off();
    }

    fn is_stopped(&self) -> bool {
        self.bus0.terminal_safe_off_is_latched() || self.bus1.terminal_safe_off_is_latched()
    }
}

#[derive(Default)]
struct State {
    diagnostic_started: bool,
    diagnostic_joined: bool,
    initial_disable_active: bool,
    stopped_at: Option<Instant>,
    stop_reason: Option<String>,
    profile: Hw76RequestedVoltageProfile,
    sequence: u64,
    latest: Option<BbOwnedVoltageObservation>,
    selected_addresses: Vec<u8>,
    latest_bus0: Option<BbOwnedBus0Observation>,
    last_complete_pair: Option<BbPairedManagementData>,
    execution: execution::State,
    pic_enable_reserved: [bool; 3],
    pic_initialization_reserved: [[bool; 4]; 3],
    pic_optional_bridge: pic_optional_bridge::OwnerState,
}

impl State {
    fn stop(&mut self, reason: &str) {
        self.stopped_at.get_or_insert_with(Instant::now);
        self.stop_reason.get_or_insert_with(|| reason.into());
        // Previously returned previews remain historical. A pending attempt
        // has none; cleanup must never promote its eventual late result.
    }

    fn can_continue(&mut self, handles: &Handles) -> bool {
        if handles.is_stopped() || self.stopped_at.is_some() {
            handles.fence();
            self.stop("BB management observed permanent terminal fence");
            false
        } else {
            // The new initial sweep owns ordinary admission until its real join.
            !self.initial_disable_active
        }
    }
}

fn lock<'a>(state: &'a Mutex<State>, handles: &Handles) -> MutexGuard<'a, State> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poison) => {
            handles.fence();
            let mut state = poison.into_inner();
            state.stop("BB management state poisoned");
            state
        }
    }
}

fn stop(state: &Mutex<State>, handles: &Handles, reason: &str) {
    handles.fence();
    lock(state, handles).stop(reason);
}

struct PendingActivity {
    state: Arc<Mutex<State>>,
    handles: Handles,
    armed: bool,
}

impl Drop for PendingActivity {
    fn drop(&mut self) {
        if self.armed {
            stop(
                &self.state,
                &self.handles,
                "BB management pending future cancelled",
            );
        }
    }
}

pub(crate) struct BbManagementOwner {
    diagnostics: BbPrePowerDiagnostics,
    handles: Handles,
    state: Arc<Mutex<State>>,
    voltage_task: Option<JoinHandle<()>>,
    bus0_task: Option<JoinHandle<()>>,
    execution_task: Option<JoinHandle<()>>,
    initialization_callers: pic_initialization_exchange::retained_callers::RetainedCallers,
    enable_callers: pic_enable::retained_callers::RetainedCallers,
    optional_callers: pic_optional_bridge::retained_callers::RetainedCallers,
    initial_disable: initial_disable::Retained,
    initial_bridges: Option<pic_initialization_exchange::pre_power_initial::History>,
    heartbeat: Option<heartbeat::Actor>,
    heartbeat_final: Option<BbHeartbeatSnapshot>,
    terminal: Option<terminal::Sweep>,
    heartbeat_release: Option<BbHeartbeatReleaseObservation>,
}

impl BbManagementOwner {
    /// Consume the original pair once. Neither service is extracted, replaced
    /// or reopened after diagnostics; no sender is exposed by this object.
    pub(crate) fn new(bus0: I2cServiceOwner, bus1: I2cServiceOwner) -> Self {
        let handles = Handles {
            bus0: bus0.request_handle(),
            bus1: bus1.request_handle(),
        };
        Self {
            diagnostics: BbPrePowerDiagnostics::new(bus0, bus1),
            handles,
            state: Arc::new(Mutex::new(State::default())),
            voltage_task: None,
            bus0_task: None,
            execution_task: None,
            initialization_callers: Default::default(),
            enable_callers: Default::default(),
            optional_callers: Default::default(),
            initial_disable: Default::default(),
            initial_bridges: None,
            heartbeat: None,
            heartbeat_final: None,
            terminal: None,
            heartbeat_release: None,
        }
    }

    pub(crate) fn snapshot(&self) -> BbManagementSnapshot {
        let mut state = lock(&self.state, &self.handles);
        state.can_continue(&self.handles);
        BbManagementSnapshot {
            diagnostics: self.diagnostics.snapshot(),
            stopped_at: state.stopped_at,
            stop_reason: state.stop_reason.clone(),
            requested_profile: state.profile,
            latest_voltage: state.latest.clone(),
            voltage_caller_pending: self.voltage_task.is_some(),
            latest_bus0: state.latest_bus0.clone(),
            bus0_caller_pending: self.bus0_task.is_some(),
            last_complete_pair: state.last_complete_pair.clone(),
            execution_caller_pending: self.execution_task.is_some(),
            latest_execution: state.execution.latest.clone(),
            last_complete_execution: state.execution.last_complete.clone(),
            committed_request_history: state.execution.history,
            profile_generation: state.execution.profile_generation,
            heartbeat: self.heartbeat_snapshot(),
            terminal: self.terminal_snapshot(),
            heartbeat_release: self.heartbeat_release.clone(),
        }
    }

    pub(crate) fn cancel(&self) {
        stop(&self.state, &self.handles, "BB management cancelled");
        if let Some(actor) = &self.heartbeat {
            actor.stop("BB original management cancelled");
        }
        self.diagnostics.cancel();
    }

    /// Begin the one retained actor from this owner's actual joined fw89
    /// diagnostics. No caller roster, snapshot, endpoint or bus handle enters.
    pub(crate) fn start_heartbeat(
        &mut self,
        cutoff: Arc<dyn BbHeartbeatCutoff>,
    ) -> Result<(), String> {
        if self.heartbeat.is_some() || self.heartbeat_final.is_some() {
            return Err(
                "BB heartbeat actor start is one-shot; retained history cannot be replaced".into(),
            );
        }
        tokio::runtime::Handle::try_current()
            .map_err(|_| "BB heartbeat actor requires its enclosing Tokio runtime".to_string())?;
        let observed = self.diagnostics.snapshot();
        let mut state = lock(&self.state, &self.handles);
        let selected = state.selected_addresses.clone();
        let valid = state.diagnostic_joined
            && observed.stop.is_none()
            && observed.both_callers_joined_observed_at.is_some()
            && selected == observed.selected_addresses
            && !selected.is_empty()
            && selected.len() <= 3
            && selected.iter().enumerate().all(|(index, address)| {
                (0x50..=0x52).contains(address) && !selected[..index].contains(address)
            })
            && observed.historical.as_ref().is_some_and(|data| {
                let pics = &data.bus0.selected_inventory.pics;
                pics.len() == selected.len()
                    && pics.iter().zip(&selected).all(|(pic, address)| {
                        pic.factory_address == *address
                            && pic.native_slot == usize::from(address - 0x50)
                            && pic.pic_address == 0x20 + (address - 0x50)
                            && pic.call_returned_at.is_some()
                            && pic.error.is_none()
                            && pic.returned_reads.as_ref().is_some_and(|reads| {
                                crate::bb_pic_application::complete_reply(reads).ok()
                                    == pic.accepted_reply
                                    && pic.accepted_reply.is_some()
                            })
                    })
            });
        if !valid
            || self.voltage_task.is_some()
            || self.bus0_task.is_some()
            || self.execution_task.is_some()
            || !state.can_continue(&self.handles)
        {
            self.handles.fence();
            state.stop("BB heartbeat start lacks original joined selected fw89 diagnostics");
            return Err(
                "BB heartbeat start lacks original joined selected fw89 diagnostics".into(),
            );
        }
        drop(state);
        self.heartbeat = Some(heartbeat::Actor::start(
            selected,
            self.handles.clone(),
            cutoff,
        ));
        Ok(())
    }

    pub(crate) fn heartbeat_snapshot(&self) -> Option<BbHeartbeatSnapshot> {
        self.heartbeat
            .as_ref()
            .map(|actor| actor.snapshot())
            .or_else(|| self.heartbeat_final.clone())
    }

    pub(crate) fn terminal_snapshot(&self) -> Option<BbTerminalSweepObservation> {
        self.terminal.as_ref().map(terminal::Sweep::snapshot)
    }

    pub(crate) async fn wait_stable_heartbeat_until(
        &self,
        deadline: Instant,
    ) -> Result<BbHeartbeatSnapshot, String> {
        self.heartbeat
            .as_ref()
            .ok_or("BB original heartbeat actor has not started")?
            .wait_stable_until(deadline)
            .await
    }

    pub(crate) fn release_joined_heartbeat_cutoff(&mut self) -> Result<bool, String> {
        let Some(actor) = self.heartbeat.as_ref() else {
            return Ok(false);
        };
        let record = self
            .heartbeat_release
            .get_or_insert_with(|| BbHeartbeatReleaseObservation {
                first_attempted_at: Instant::now(),
                released_at: None,
                first_failure: None,
            });
        // Normal execution may still hold a private live gate into this actor.
        // Its original caller must join before callback ownership can leave.
        if self.execution_task.is_some()
            || self.bus0_task.is_some()
            || self.voltage_task.is_some()
            || self.initialization_callers.pending()
            || self.enable_callers.pending()
            || self.optional_callers.pending()
            || self.initial_disable.pending()
        {
            let reason = "BB management caller still retains heartbeat cutoff custody".to_string();
            record.first_failure.get_or_insert_with(|| reason.clone());
            return Err(reason);
        }
        let final_snapshot = actor.snapshot_for_callback_release().map_err(|reason| {
            record.first_failure.get_or_insert_with(|| reason.clone());
            reason
        })?;
        self.heartbeat_final = Some(final_snapshot);
        self.heartbeat.take();
        record.released_at = Some(Instant::now());
        Ok(true)
    }

    fn begin_terminal_once(&mut self, deadline: Instant) {
        if self.terminal.is_some() || (self.heartbeat.is_none() && self.heartbeat_final.is_none()) {
            return;
        }
        let state = lock(&self.state, &self.handles);
        let selected = if state.diagnostic_joined {
            state.selected_addresses.clone()
        } else {
            Vec::new()
        };
        drop(state);
        self.terminal = Some(terminal::Sweep::prepare(
            &selected,
            self.handles.clone(),
            deadline,
        ));
    }

    async fn launch_terminal_after_callback_entry_until(&mut self, deadline: Instant) -> bool {
        while self
            .terminal
            .as_ref()
            .is_some_and(terminal::Sweep::awaiting_launch)
        {
            // This is entry into the original operational callback, not proof
            // of a GPIO syscall, cutoff receipt, ACK or physical rail OFF.
            if self
                .heartbeat_snapshot()
                .and_then(|state| state.cutoff)
                .is_some_and(|cutoff| cutoff.started_at.is_some())
            {
                self.terminal
                    .as_mut()
                    .expect("original reserved sweep")
                    .launch_once();
                return true;
            }
            if Instant::now() >= deadline {
                self.terminal
                    .as_ref()
                    .expect("original reserved sweep")
                    .record_callback_entry_wait_expired();
                return false;
            }
            tokio::time::sleep_until(
                (Instant::now() + std::time::Duration::from_millis(5))
                    .min(deadline)
                    .into(),
            )
            .await;
        }
        true
    }

    /// A current software-policy observation only. Enclosing GPIO, voltage and
    /// mining admission still must bind it to their own original owner.
    pub(crate) fn require_stable_heartbeat(&self) -> Result<BbHeartbeatSnapshot, String> {
        self.heartbeat
            .as_ref()
            .ok_or("BB heartbeat actor has not started")?
            .require_stable()
    }

    pub(crate) fn stop_heartbeat(&self) {
        self.cancel();
    }

    pub(crate) fn merge_requested_voltage(
        &mut self,
        target: Option<f64>,
        maximum_step: Option<f64>,
    ) -> Result<(), String> {
        let mut state = lock(&self.state, &self.handles);
        if !state.can_continue(&self.handles) {
            return Err("BB management is permanently stopped".into());
        }
        if self.voltage_task.is_some() || self.bus0_task.is_some() || self.execution_task.is_some()
        {
            return Err("BB requested profile cannot change while a caller remains pending".into());
        }
        let mut proposed = state.profile;
        proposed
            .merge_request(target, maximum_step)
            .map_err(|error| {
                format!("BB requested voltage refused without changing the profile: {error:?}")
            })?;
        if proposed != state.profile {
            let generation = state
                .execution
                .profile_generation
                .checked_add(1)
                .ok_or("BB requested profile generation exhausted")?;
            state.profile = proposed;
            state.execution.profile_generation = generation;
        }
        Ok(())
    }

    pub(crate) async fn observe_pre_power_once(
        &mut self,
        selected: &[u8],
        deadline: Instant,
    ) -> BbManagementSnapshot {
        {
            let mut state = lock(&self.state, &self.handles);
            if state.diagnostic_started || !state.can_continue(&self.handles) {
                drop(state);
                self.cancel();
                return self.snapshot();
            }
            state.diagnostic_started = true;
        }
        let mut pending = PendingActivity {
            state: self.state.clone(),
            handles: self.handles.clone(),
            armed: true,
        };
        let observed = self.diagnostics.observe_once(selected, deadline).await;
        let mut state = lock(&self.state, &self.handles);
        if observed.stop.is_none()
            && observed.historical.is_some()
            && observed.both_callers_joined_observed_at.is_some()
            && Instant::now() < deadline
            && state.can_continue(&self.handles)
        {
            state.diagnostic_joined = true;
            state.selected_addresses = observed.selected_addresses.clone();
        } else {
            self.handles.fence();
            state.stop("BB management pre-power diagnostics not accepted");
        }
        pending.armed = false;
        drop(state);
        self.snapshot()
    }

    /// Read the complete existing fixed APW identity/calibration/DAC sequence
    /// through the retained worker, then join its actual caller before making
    /// a numerical preview. This deliberately does not reuse diagnostic data
    /// as a present current input. The fixed query cadence is unchanged.
    pub(crate) async fn observe_voltage_once(
        &mut self,
        deadline: Instant,
    ) -> Result<BbManagementSnapshot, String> {
        self.start_voltage(deadline)?;
        join_voltage(
            &mut self.voltage_task,
            &self.state,
            &self.handles,
            deadline,
            true,
        )
        .await;
        Ok(self.snapshot())
    }

    fn start_voltage(&mut self, deadline: Instant) -> Result<(), String> {
        let mut state = lock(&self.state, &self.handles);
        if self.execution_task.is_some()
            || self.voltage_task.is_some()
            || self.bus0_task.is_some()
            || !state.diagnostic_joined
            || Instant::now() >= deadline
            || !state.can_continue(&self.handles)
        {
            self.handles.fence();
            state.stop("BB voltage observation requires joined diagnostics, no pending caller and a new live deadline");
            return Err(state.stop_reason.clone().expect("stop recorded"));
        }
        let Some(sequence) = state.sequence.checked_add(1) else {
            self.handles.fence();
            state.stop("BB voltage observation sequence exhausted");
            return Err(state.stop_reason.clone().expect("stop recorded"));
        };
        state.sequence = sequence;
        state.latest = Some(BbOwnedVoltageObservation {
            sequence,
            deadline,
            requested_profile: state.profile,
            caller_prepared_at: None,
            caller_returned_at: None,
            caller_joined_at: None,
            attempt: None,
            failure: None,
            preview: None,
        });
        drop(state);
        let shared = self.state.clone();
        let handles = self.handles.clone();
        self.voltage_task = Some(tokio::task::spawn_blocking(move || {
            let mut state = lock(&shared, &handles);
            if !state.can_continue(&handles) || Instant::now() >= deadline {
                handles.fence();
                state.stop("BB voltage caller deadline or terminal fence before preparation");
                return;
            }
            state
                .latest
                .as_mut()
                .expect("retained current attempt")
                .caller_prepared_at = Some(Instant::now());
            drop(state);
            let attempt = handles.bus1.read_bb_apw_profile_at(deadline);
            let returned_at = Instant::now();
            let failure = attempt.failure.clone();
            let complete = attempt.caller_completed_at.is_some();
            let mut state = lock(&shared, &handles);
            let observation = state
                .latest
                .as_mut()
                .expect("attempt cannot be replaced before join");
            observation.caller_returned_at = Some(returned_at);
            observation.attempt = Some(attempt);
            observation.failure = failure.clone();
            if failure.is_some() || !complete || returned_at >= deadline {
                handles.fence();
                state.stop("BB voltage fixed caller failed, incomplete or late");
            }
            state.can_continue(&handles);
        }));
        Ok(())
    }

    /// Renew selected fw89/LM75 observations and the APW profile in parallel
    /// through the original two service workers. The selected endpoints come
    /// only from this owner's successful diagnostic attempt. No new factory
    /// scan or unselected endpoint is introduced. Both original caller joins
    /// must be observed before this deadline to retain a complete pair.
    pub(crate) async fn observe_runtime_once(
        &mut self,
        deadline: Instant,
    ) -> Result<BbManagementSnapshot, String> {
        self.start_voltage(deadline)?;
        self.bus0_task = Some(runtime_bus0::start(&self.state, &self.handles, deadline));
        let (voltage_joined, bus0_joined) = tokio::join!(
            join_voltage(
                &mut self.voltage_task,
                &self.state,
                &self.handles,
                deadline,
                true
            ),
            runtime_bus0::join_until(
                &mut self.bus0_task,
                &self.state,
                &self.handles,
                deadline,
                true
            ),
        );
        let observed_at = Instant::now();
        let mut state = lock(&self.state, &self.handles);
        if voltage_joined
            && bus0_joined
            && observed_at < deadline
            && state.can_continue(&self.handles)
        {
            let bus0 = state
                .latest_bus0
                .as_ref()
                .filter(|sample| sample.accepted_at.is_some());
            let voltage = state
                .latest
                .as_ref()
                .filter(|sample| sample.preview.is_some());
            if let (Some(bus0), Some(voltage)) = (bus0, voltage) {
                if bus0.sequence == voltage.sequence
                    && bus0.deadline == deadline
                    && voltage.deadline == deadline
                {
                    state.last_complete_pair = Some(BbPairedManagementData {
                        sequence: voltage.sequence,
                        deadline,
                        bus0: bus0.clone(),
                        voltage: voltage.clone(),
                        both_callers_joined_at: observed_at,
                    });
                } else {
                    self.handles.fence();
                    state.stop("BB paired management observations have different cycle identities");
                }
            } else {
                self.handles.fence();
                state.stop("BB paired management has no complete owned result from both callers");
            }
        } else {
            self.handles.fence();
            state.stop("BB paired management did not complete within its original deadline");
        }
        drop(state);
        Ok(self.snapshot())
    }

    /// Cleanup observes actual callers and permanently refuses new work. A
    /// later cleanup deadline never extends an observation's original deadline.
    pub(crate) async fn join_callers_until(&mut self, deadline: Instant) -> bool {
        self.cancel();
        self.begin_terminal_once(deadline);
        if !self
            .launch_terminal_after_callback_entry_until(deadline)
            .await
        {
            return false;
        }
        let (diagnostics, voltage, bus0, executed, heartbeat, terminal, initialization, enable, optional, initial_disable) = tokio::join!(
            self.diagnostics.join_callers_until(deadline),
            join_voltage(
                &mut self.voltage_task,
                &self.state,
                &self.handles,
                deadline,
                false
            ),
            runtime_bus0::join_until(
                &mut self.bus0_task,
                &self.state,
                &self.handles,
                deadline,
                false
            ),
            execution::join_until(
                &mut self.execution_task,
                &self.state,
                &self.handles,
                deadline,
                false
            ),
            heartbeat::join_until(&mut self.heartbeat, deadline),
            terminal::join_until(&mut self.terminal, deadline),
            pic_initialization_exchange::retained_callers::join_until(
                &mut self.initialization_callers,
                &self.state,
                &self.handles,
                deadline,
            ),
            pic_enable::retained_callers::join_until(
                &mut self.enable_callers,
                &self.state,
                &self.handles,
                deadline,
            ),
            pic_optional_bridge::retained_callers::join_until(
                &mut self.optional_callers,
                &self.state,
                &self.handles,
                deadline,
            ),
            initial_disable::join_until(
                &mut self.initial_disable, &self.state, &self.handles, deadline, true,
            ),
        );
        diagnostics && voltage && bus0 && executed && heartbeat && terminal && initialization && enable && optional && initial_disable
    }

    /// Synchronous teardown after caller joins, on the exact retained pair.
    /// Refusal preserves both service owners and the pending caller for retry.
    pub(crate) fn close_services_until(&mut self, deadline: Instant) -> Result<bool, String> {
        self.cancel();
        if self.heartbeat.is_some()
            || self.terminal.as_ref().is_some_and(terminal::Sweep::pending)
            || ((self.heartbeat.is_some() || self.heartbeat_final.is_some())
                && self.terminal.is_none())
            || self.voltage_task.is_some()
            || self.bus0_task.is_some()
            || self.execution_task.is_some()
            || self.initialization_callers.pending()
            || self.enable_callers.pending()
            || self.optional_callers.pending()
            || self.initial_disable.pending()
        {
            return Err(
                "BB management callers must actually join and release heartbeat callback custody before either service close".into(),
            );
        }
        Ok(self.diagnostics.close_services_until(deadline))
    }

    pub(crate) fn close_receipts(
        &self,
    ) -> (
        Option<&I2cServiceCloseReceipt>,
        Option<&I2cServiceCloseReceipt>,
    ) {
        self.diagnostics.close_receipts()
    }
}

impl Drop for BbManagementOwner {
    fn drop(&mut self) {
        self.cancel();
        // A Drop fence does not join a caller, interrupt a kernel transfer or
        // establish physical power-off. Enclosing runtime must retain cleanup.
    }
}

async fn join_voltage(
    task: &mut Option<JoinHandle<()>>,
    shared: &Arc<Mutex<State>>,
    handles: &Handles,
    deadline: Instant,
    promote: bool,
) -> bool {
    let Some(join) = task.as_mut() else {
        return true;
    };
    if Instant::now() >= deadline {
        stop(shared, handles, "BB voltage caller join deadline elapsed");
        return false;
    }
    let mut pending = PendingActivity {
        state: shared.clone(),
        handles: handles.clone(),
        armed: true,
    };
    let result = tokio::select! {
        result = join => Some(result),
        _ = tokio::time::sleep_until(deadline.into()) => None,
    };
    let Some(result) = result else {
        stop(
            shared,
            handles,
            "BB voltage caller was not joined before deadline",
        );
        return false;
    };
    *task = None;
    let observed_at = Instant::now();
    let mut state = lock(shared, handles);
    let observation = state
        .latest
        .as_mut()
        .expect("actual retained caller has its attempt");
    observation.caller_joined_at = Some(observed_at);
    let original_deadline = observation.deadline;
    if let Err(error) = result {
        observation
            .failure
            .get_or_insert_with(|| format!("BB voltage caller task failed: {error}"));
        handles.fence();
        state.stop("BB voltage caller task failed");
    } else if observed_at >= deadline || observed_at >= original_deadline {
        handles.fence();
        state.stop("BB voltage caller joined after an observation deadline");
    } else if promote && state.can_continue(handles) {
        let observation = state.latest.as_mut().expect("actual retained attempt");
        match preview(observation) {
            Ok(value) => observation.preview = Some(value),
            Err(error) => {
                observation.failure.get_or_insert(error);
                handles.fence();
                state.stop("BB voltage numerical preview refused");
            }
        }
    }
    pending.armed = false;
    true
}

fn preview(observation: &BbOwnedVoltageObservation) -> Result<BbVoltagePreview, String> {
    let attempt = observation
        .attempt
        .as_ref()
        .filter(|attempt| attempt.failure.is_none() && attempt.caller_completed_at.is_some())
        .ok_or("BB voltage preview lacks a complete owned APW observation")?;
    let millivolts = match attempt.queries.last() {
        Some(query) if query.query == Query::Dac => match &query.decoded {
            Ok(Field::Dac {
                millivolts: Some(value),
                ..
            }) => *value,
            _ => return Err("BB voltage preview has no convertible DAC report".into()),
        },
        _ => return Err("BB voltage preview lacks the final owned DAC query".into()),
    };
    let current = f64::from(millivolts) / 1000.0;
    let pair = observation
        .requested_profile
        .select_pair(current)
        .map_err(|error| format!("BB voltage preview current/profile refused: {error:?}"))?;
    let first_step = pair
        .map(|pair| {
            bb_voltage_planner::plan_step(
                current,
                pair.target,
                pair.maximum_step,
                History {
                    previous_request: None,
                    repeated_requests: 0,
                },
            )
        })
        .transpose()
        .map_err(|error| format!("BB voltage preview calculation refused: {error:?}"))?;
    Ok(BbVoltagePreview {
        reported_millivolts: millivolts,
        selected_pair: pair,
        first_step,
    })
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_management_owner_tests.rs"]
mod tests;
