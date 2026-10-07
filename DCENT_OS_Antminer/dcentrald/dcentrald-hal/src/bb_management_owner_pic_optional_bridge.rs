//! Private optional-bridge reservation from this owner's joined exact factory pages.
//! Native source selection remains separate from transport, readiness and physical use.
use super::{lock, stop, BbManagementOwner, Handles, State};
use crate::i2c::bb_pic_optional_bridge::{OriginalService, Prepared};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[path = "bb_management_owner_pic_optional_callers.rs"]
pub(in crate::bb_management_owner) mod retained_callers;

#[path = "bb_management_owner_pic_optional_policy.rs"]
mod native_policy;

#[derive(Debug)]
enum Origin {
    // Absence remains refusal; the native constructor is private to this owner.
    Unadmitted,
    NativeJoined(native_policy::NativePolicy),
    #[cfg(all(test, feature = "sim-hal"))]
    SelfFixture,
}
#[derive(Debug)]
struct Policy {
    origin: Origin,
}
impl Policy {
    fn allowed(&self) -> bool {
        match &self.origin {
            Origin::Unadmitted => false,
            Origin::NativeJoined(_) => true,
            #[cfg(all(test, feature = "sim-hal"))]
            Origin::SelfFixture => true,
        }
    }
    fn native_profile_admitted(&self) -> bool {
        matches!(&self.origin, Origin::NativeJoined(_))
    }
    fn matches_owner(&self, owner: &Arc<Mutex<State>>, state: &State) -> bool {
        match &self.origin {
            Origin::Unadmitted => false,
            Origin::NativeJoined(policy) => policy.matches_owner(owner, state),
            #[cfg(all(test, feature = "sim-hal"))]
            Origin::SelfFixture => true,
        }
    }
    fn label(&self) -> &'static str {
        match &self.origin {
            Origin::Unadmitted => "native_optional_profile_unadmitted",
            Origin::NativeJoined(policy) => policy.label(),
            #[cfg(all(test, feature = "sim-hal"))]
            Origin::SelfFixture => "explicit_original_service_self_fixture_only",
        }
    }
}

/// Dedicated additive slot; existing initialization phase arrays stay unchanged.
#[derive(Default)]
pub(crate) struct OwnerState {
    policy: Option<Arc<Policy>>,
    reserved: [bool; 3],
}

impl OwnerState {
    pub(super) fn has_reservation(&self) -> bool {
        self.reserved.iter().any(|reserved| *reserved)
    }
}

pub(crate) struct Admission {
    state: Arc<Mutex<State>>,
    handles: Handles,
    policy: Arc<Policy>,
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
    pub(crate) fn native_profile_admitted(&self) -> bool {
        self.policy.native_profile_admitted()
    }
    pub(crate) fn policy_source(&self) -> &'static str {
        self.policy.label()
    }
    pub(crate) fn refuse(&self, reason: &str) {
        stop(&self.state, &self.handles, reason);
    }
    pub(crate) fn observe(&self) -> Result<Instant, String> {
        let mut state = lock(&self.state, &self.handles);
        let now = Instant::now();
        if now >= self.deadline
            || !state.can_continue(&self.handles)
            || !state.diagnostic_joined
            || state.selected_addresses != self.selected
            || state.sequence != self.sequence
            || state.execution.profile_generation != self.profile_generation
            || !state.pic_optional_bridge.reserved[self.native_slot]
            || !state
                .pic_optional_bridge
                .policy
                .as_ref()
                .is_some_and(|policy| {
                    Arc::ptr_eq(policy, &self.policy)
                        && policy.allowed()
                        && policy.matches_owner(&self.state, &state)
                })
            || !self.selected.contains(&self.factory_address)
            || self.factory_address != 0x50 + self.native_slot as u8
        {
            self.handles.fence();
            state.stop("BB optional bridge sweep lost its original owner/slot/policy admission");
            return Err(state.stop_reason.clone().expect("stop retained"));
        }
        let now = Instant::now();
        if now >= self.deadline || !state.can_continue(&self.handles) {
            self.handles.fence();
            state.stop("BB optional bridge sweep admission became late or terminal");
            return Err(state.stop_reason.clone().expect("stop retained"));
        }
        Ok(now)
    }
}

impl BbManagementOwner {
    /// Component only: root's original initializer must enforce source order,
    /// retain/join the original caller, and retain the same absolute deadline.
    /// No runtime export: the private native constructor derives only from this owner.
    fn prepare_selected_pic_optional_bridge(
        &mut self,
        selected_index: usize,
        deadline: Instant,
    ) -> Result<Prepared, String> {
        let mut state = lock(&self.state, &self.handles);
        if self.optional_callers.pending()
            || self.enable_callers.pending()
            || self.execution_task.is_some()
            || self.voltage_task.is_some()
            || self.bus0_task.is_some()
            || self.initialization_callers.pending()
            || !state.diagnostic_joined
            || Instant::now() >= deadline
            || !state.can_continue(&self.handles)
        {
            return Err(
                "BB optional bridge sweep requires joined idle management and a live deadline"
                    .into(),
            );
        }
        let policy = state
            .pic_optional_bridge
            .policy
            .as_ref()
            .filter(|policy| policy.allowed() && policy.matches_owner(&self.state, &state))
            .cloned()
            .ok_or_else(|| "BB native optional bridge profile remains unadmitted".to_string())?;
        let factory_address = *state
            .selected_addresses
            .get(selected_index)
            .ok_or_else(|| {
                "BB optional bridge index is outside original selected roster".to_string()
            })?;
        let native_slot = usize::from(
            factory_address
                .checked_sub(0x50)
                .filter(|slot| *slot < 3)
                .ok_or_else(|| "BB optional bridge original slot is invalid".to_string())?,
        );
        if state.pic_optional_bridge.reserved[native_slot] {
            return Err("BB optional bridge reservation is one-shot per original slot".into());
        }
        let original =
            OriginalService::capture(&self.handles.bus0).map_err(|error| error.to_string())?;
        let admission = Admission {
            state: self.state.clone(),
            handles: self.handles.clone(),
            policy,
            selected: state.selected_addresses.clone(),
            native_slot,
            factory_address,
            sequence: state.sequence,
            profile_generation: state.execution.profile_generation,
            deadline,
        };
        state.pic_optional_bridge.reserved[native_slot] = true;
        drop(state);
        Prepared::new(original, admission)
    }

    /// Explicit test input, never a native factory/profile result. It admits
    /// no timestamps, snapshots, ready state, packets, addresses or handles.
    #[cfg(all(test, feature = "sim-hal"))]
    fn admit_optional_bridge_self_fixture(&mut self) -> Result<(), String> {
        let mut state = lock(&self.state, &self.handles);
        if !state.diagnostic_joined
            || state.selected_addresses.is_empty()
            || !state.can_continue(&self.handles)
            || state.pic_optional_bridge.policy.is_some()
            || state.pic_optional_bridge.reserved.iter().any(|used| *used)
        {
            return Err(
                "BB optional bridge self-fixture requires original joined unused owner".into(),
            );
        }
        state.pic_optional_bridge.policy = Some(Arc::new(Policy {
            origin: Origin::SelfFixture,
        }));
        Ok(())
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_management_owner_pic_optional_bridge_tests.rs"]
mod tests;
