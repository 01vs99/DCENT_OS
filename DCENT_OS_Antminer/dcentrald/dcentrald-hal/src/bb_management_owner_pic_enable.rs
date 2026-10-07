//! Private admission for one selected PIC enable attempt. This is a component
//! seam only: the enclosing original-owner initializer must first perform its
//! retained initial disable, bridge and rail operations before exposing enable.
//! No daemon entry or initialization-complete capability is defined here.
use super::{heartbeat::VoltageGate, lock, stop, BbManagementOwner, Handles, State};
use crate::i2c::bb_pic_enable::{OriginalService, Prepared};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Fields and constructor remain inside the original management owner. Neither
/// historical snapshots nor a caller-supplied address can construct admission.
pub(crate) struct Admission {
    state: Arc<Mutex<State>>,
    handles: Handles,
    heartbeat: VoltageGate,
    selected: Vec<u8>,
    native_slot: usize,
    factory_address: u8,
    sequence: u64,
    profile_generation: u64,
    deadline: Instant,
}

impl Admission {
    pub(crate) fn native_slot(&self) -> usize {
        self.native_slot
    }
    pub(crate) fn factory_address(&self) -> u8 {
        self.factory_address
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn refuse(&self, reason: &str) {
        stop(&self.state, &self.handles, reason);
    }
    /// Original mutable state and actor are checked after acquiring the state
    /// lock on each actual admission. The returned Instant is diagnostic data.
    pub(crate) fn observe(&self) -> Result<Instant, String> {
        let mut state = lock(&self.state, &self.handles);
        let now = Instant::now();
        if now >= self.deadline
            || !state.can_continue(&self.handles)
            || !state.diagnostic_joined
            || state.selected_addresses != self.selected
            || state.sequence != self.sequence
            || state.execution.profile_generation != self.profile_generation
            || !state.pic_enable_reserved[self.native_slot]
            || !self.selected.contains(&self.factory_address)
            || self.factory_address != 0x50 + self.native_slot as u8
        {
            self.handles.fence();
            state.stop("BB fixed enable lost its original management/slot admission");
            return Err(state.stop_reason.clone().expect("stop retained"));
        }
        let observed = self.heartbeat.observe(self.deadline)?;
        // The actor lock itself may have waited. Do not promote the earlier
        // management-lock timestamp, or a fence published during that wait.
        let now = Instant::now();
        if now >= self.deadline || !state.can_continue(&self.handles) {
            self.handles.fence();
            state.stop("BB fixed enable admission became late or terminal");
            return Err(state.stop_reason.clone().expect("stop retained"));
        }
        Ok(observed.observed_at)
    }
}

impl BbManagementOwner {
    /// Private, one-shot component preparation. The index chooses an entry in
    /// the already joined original diagnostic roster, never an I2C address.
    /// This method is intentionally not exported by BbManagementRuntime.
    fn prepare_selected_pic_enable(
        &mut self,
        selected_index: usize,
        deadline: Instant,
    ) -> Result<Prepared, String> {
        let mut state = lock(&self.state, &self.handles);
        if self.optional_callers.pending()
            || self.enable_callers.pending()
            || self.initialization_callers.pending()
            || self.execution_task.is_some()
            || self.voltage_task.is_some()
            || self.bus0_task.is_some()
            || !state.diagnostic_joined
            || Instant::now() >= deadline
            || !state.can_continue(&self.handles)
        {
            return Err("BB PIC enable requires joined idle management and a live deadline".into());
        }
        let factory_address = *state
            .selected_addresses
            .get(selected_index)
            .ok_or_else(|| {
                "BB PIC enable index is outside the original selected roster".to_string()
            })?;
        let native_slot = usize::from(
            factory_address
                .checked_sub(0x50)
                .filter(|slot| *slot < 3)
                .ok_or_else(|| "BB PIC enable original factory slot is invalid".to_string())?,
        );
        if state.pic_enable_reserved[native_slot] {
            return Err("BB PIC enable reservation is one-shot for each original slot".into());
        }
        let heartbeat = self
            .heartbeat
            .as_ref()
            .ok_or_else(|| "BB PIC enable requires original retained heartbeat actor".to_string())?
            .voltage_gate();
        heartbeat.observe(deadline)?;
        // Captured before any later blocking-caller/queue delay. This opaque
        // service object has no sender accessor and cannot be replaced later.
        let original =
            OriginalService::capture(&self.handles.bus0).map_err(|error| error.to_string())?;
        let admission = Admission {
            state: self.state.clone(),
            handles: self.handles.clone(),
            heartbeat,
            selected: state.selected_addresses.clone(),
            native_slot,
            factory_address,
            sequence: state.sequence,
            profile_generation: state.execution.profile_generation,
            deadline,
        };
        state.pic_enable_reserved[native_slot] = true;
        drop(state);
        Prepared::new(original, admission)
    }
}

#[path = "bb_management_owner_pic_enable_callers.rs"]
pub(in crate::bb_management_owner) mod retained_callers;

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_management_owner_pic_enable_tests.rs"]
mod tests;
