//! Private fixed-phase reservation on the original selected management owner.
//! A reservation alone never proves initialization order or previous caller joins.
//! Root's enclosing initializer must retain those actual attempts and one deadline.
use super::{lock, stop, BbManagementOwner, Handles, State};
use crate::i2c::bb_pic_initialization_exchange::{OriginalService, Prepared};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Closed source phases only; there is no packet, timing or arbitrary-address API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Bridge,
    StartupHeartbeat,
    PreEnableRail,
    FinalRail,
}
impl Phase {
    fn index(self) -> usize {
        match self {
            Self::Bridge => 0,
            Self::StartupHeartbeat => 1,
            Self::PreEnableRail => 2,
            Self::FinalRail => 3,
        }
    }
}

/// Fields and constructor remain inside the original management owner. Neither
/// historical snapshots nor a caller-supplied address can construct admission.
pub(crate) struct Admission {
    state: Arc<Mutex<State>>,
    handles: Handles,
    phase: Phase,
    selected: Vec<u8>,
    native_slot: usize,
    factory_address: u8,
    sequence: u64,
    profile_generation: u64,
    deadline: Instant,
}

impl Admission {
    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }
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
    /// Original mutable state and service fences are checked after acquiring the state
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
            || !state.pic_initialization_reserved[self.native_slot][self.phase.index()]
            || !self.selected.contains(&self.factory_address)
            || self.factory_address != 0x50 + self.native_slot as u8
        {
            self.handles.fence();
            state.stop(
                "BB fixed initialization exchange lost its original management/slot admission",
            );
            return Err(state.stop_reason.clone().expect("stop retained"));
        }
        // These private transport primitives do not manufacture steady-actor
        // admission. The enclosing owner must enforce actual phase order and
        // actor policy; FinalRail belongs after separately admitted enable.
        // Recheck terminal state before returning diagnostic observation time.
        let now = Instant::now();
        if now >= self.deadline || !state.can_continue(&self.handles) {
            self.handles.fence();
            state.stop("BB fixed initialization exchange admission became late or terminal");
            return Err(state.stop_reason.clone().expect("stop retained"));
        }
        Ok(now)
    }
}

impl BbManagementOwner {
    /// Private, one-shot component preparation. The index chooses an entry in
    /// the already joined original diagnostic roster, never an I2C address.
    /// This method is intentionally not exported by BbManagementRuntime.
    fn prepare_selected_pic_initialization_exchange(
        &mut self,
        selected_index: usize,
        phase: Phase,
        deadline: Instant,
    ) -> Result<Prepared, String> {
        let mut state = lock(&self.state, &self.handles);
        if self.optional_callers.pending()
            || self.initialization_callers.pending()
            || self.enable_callers.pending()
            || self.execution_task.is_some()
            || self.voltage_task.is_some()
            || self.bus0_task.is_some()
            || !state.diagnostic_joined
            || Instant::now() >= deadline
            || !state.can_continue(&self.handles)
        {
            return Err("BB PIC initialization exchange requires joined idle management and a live deadline".into());
        }
        let factory_address = *state
            .selected_addresses
            .get(selected_index)
            .ok_or_else(|| {
                "BB PIC initialization exchange index is outside the original selected roster"
                    .to_string()
            })?;
        let native_slot = usize::from(
            factory_address
                .checked_sub(0x50)
                .filter(|slot| *slot < 3)
                .ok_or_else(|| {
                    "BB PIC initialization exchange original factory slot is invalid".to_string()
                })?,
        );
        if state.pic_initialization_reserved[native_slot][phase.index()] {
            return Err(
                "BB PIC initialization exchange reservation is one-shot for each original slot"
                    .into(),
            );
        }
        // Captured before any later blocking-caller/queue delay. This opaque
        // service object has no sender accessor and cannot be replaced later.
        let original = if self.initial_bridges.as_ref().is_some_and(pre_power_initial::bridge_active) {
            if phase != Phase::Bridge {
                return Err("initial bridge prefix admits only its fixed Bridge phase".into());
            }
            let origin = self.initial_disable.following_phase_origin()
                .ok_or("original initial-disable origin absent at bridge preparation")?;
            OriginalService::capture_after_initial_disable(&self.handles.bus0, &origin)
                .map_err(|error| error.to_string())?
        } else {
            OriginalService::capture(&self.handles.bus0).map_err(|error| error.to_string())?
        };
        let admission = Admission {
            state: self.state.clone(),
            handles: self.handles.clone(),
            phase,
            selected: state.selected_addresses.clone(),
            native_slot,
            factory_address,
            sequence: state.sequence,
            profile_generation: state.execution.profile_generation,
            deadline,
        };
        state.pic_initialization_reserved[native_slot][phase.index()] = true;
        drop(state);
        Prepared::new(original, admission)
    }
}

#[path = "bb_management_owner_pre_power_initial.rs"]
pub(super) mod pre_power_initial;

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_management_owner_pic_initialization_exchange_tests.rs"]
mod tests;

#[path = "bb_management_owner_pic_initialization_callers.rs"]
pub(super) mod retained_callers;
