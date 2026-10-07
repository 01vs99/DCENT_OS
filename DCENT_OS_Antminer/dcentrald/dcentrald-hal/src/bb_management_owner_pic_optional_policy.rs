//! Exact private source policy from this owner's joined immutable factory pages.
//! Original model+0x96 is decoded source data, NEVER EEPROM raw[0x96].
//! The separate model+0x94 PIC/voltage profile is not this selector.
use super::{lock, BbManagementOwner, Origin, Policy, State};
use dcentrald_api_types::bb_factory_profile::{BbFactoryCollection, BbFactorySku};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequiredExchange {
    RequiredFourBridgeSweep,
}

/// Source metadata only. Neither this data nor a publicly decoded collection
/// can construct an Admission; only the original owner's method below can.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordSource {
    factory_address: u8,
    exact_sku: BbFactorySku,
    original_model_96: u8,
    required: RequiredExchange,
}

fn source_records(
    collection: &BbFactoryCollection,
    selected: &[u8],
) -> Result<Vec<RecordSource>, String> {
    if selected.is_empty()
        || selected.len() > 3
        || selected.iter().enumerate().any(|(index, address)| {
            !(0x50..=0x52).contains(address) || selected[..index].contains(address)
        })
        || collection.pages().len() != selected.len()
    {
        return Err("BB optional policy lacks the exact native selected collection".into());
    }
    let mut records = Vec::with_capacity(selected.len());
    for (page, address) in collection.pages().iter().zip(selected) {
        if page.address() != *address
            || page.identity().board_name != page.sku().board_name()
            || collection.pages()[0].sku() != page.sku()
        {
            return Err("BB optional policy collection/roster/exact SKU differs".into());
        }
        // Retained original decoder and collection11 establish model96=1 for
        // these exact two SKUs, including homogeneous one/two/three records.
        // No default for another SKU, broad PIC profile or source byte94 exists.
        let original_model_96 = match page.sku() {
            BbFactorySku::Bhb42601 => 1,
            BbFactorySku::Bhb42641 => 1,
        };
        records.push(RecordSource {
            factory_address: *address,
            exact_sku: page.sku(),
            original_model_96,
            required: RequiredExchange::RequiredFourBridgeSweep,
        });
    }
    Ok(records)
}

/// Immutable provenance derived internally from the original diagnostic pair.
/// Original service authority remains in Admission, never in a public DTO.
pub(super) struct NativePolicy {
    original_owner: Weak<Mutex<State>>,
    collection: BbFactoryCollection,
    selected: Vec<u8>,
    records: Vec<RecordSource>,
    sequence: u64,
    profile_generation: u64,
    diagnostic_deadline: Instant,
    diagnostic_joined_at: Instant,
    admitted_at: Instant,
}

impl std::fmt::Debug for NativePolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BbNativeOptionalSourcePolicy")
            .field("selected", &self.selected)
            .field("records", &self.records)
            .field("sequence", &self.sequence)
            .field("profile_generation", &self.profile_generation)
            .field("diagnostic_deadline", &self.diagnostic_deadline)
            .field("diagnostic_joined_at", &self.diagnostic_joined_at)
            .field("admitted_at", &self.admitted_at)
            .finish_non_exhaustive()
    }
}

impl NativePolicy {
    pub(super) fn label(&self) -> &'static str {
        match self.records[0].exact_sku {
            BbFactorySku::Bhb42601 => "original_joined_exact_bhb42601_model96_one",
            BbFactorySku::Bhb42641 => "original_joined_exact_bhb42641_model96_one",
        }
    }

    pub(super) fn matches_owner(&self, owner: &Arc<Mutex<State>>, state: &State) -> bool {
        self.original_owner
            .upgrade()
            .is_some_and(|original| Arc::ptr_eq(&original, owner))
            && state.diagnostic_joined
            && state.selected_addresses == self.selected
            && state.sequence == self.sequence
            && state.execution.profile_generation == self.profile_generation
            && source_records(&self.collection, &self.selected)
                .is_ok_and(|records| records == self.records)
    }
}

impl BbManagementOwner {
    /// Source policy only, not current readiness or full initialization. The
    /// same owner supplies every page, endpoint, firmware result and join.
    /// Call once after actual diagnostics, before their original deadline.
    /// Later sweeps keep their own original deadline and current generation;
    /// immutable source provenance is never refreshed by a replacement owner.
    pub(in crate::bb_management_owner) fn admit_native_optional_bridge_policy(
        &mut self,
    ) -> Result<(), String> {
        let observed = self.diagnostics.snapshot();
        let mut state = lock(&self.state, &self.handles);
        if !state.diagnostic_joined
            || !state.can_continue(&self.handles)
            || self.handles.bus0.bus() != 0
            || self.handles.bus1.bus() != 1
            || self.voltage_task.is_some()
            || self.bus0_task.is_some()
            || self.execution_task.is_some()
            || self.initialization_callers.pending()
            || self.enable_callers.pending()
            || self.optional_callers.pending()
            || state.pic_optional_bridge.policy.is_some()
            || state.pic_optional_bridge.reserved.iter().any(|used| *used)
            || observed.stop.is_some()
            || observed.selected_addresses != state.selected_addresses
            || observed.bus0.failure.is_some()
            || observed.bus0.stopped_at.is_some()
            || observed.bus0.inventory.failure.is_some()
            || observed.bus0.inventory.stopped_at.is_some()
        {
            return Err(
                "BB native optional policy requires this original joined idle owner".into(),
            );
        }
        let deadline = observed
            .original_deadline
            .ok_or("BB native optional policy lacks the original diagnostic deadline")?;
        let joined_at = observed
            .both_callers_joined_observed_at
            .ok_or("BB native optional policy lacks the actual paired caller join")?;
        let data = observed
            .historical
            .as_ref()
            .ok_or("BB native optional policy lacks this owner's historical factory data")?;
        let inventory = &data.bus0.selected_inventory;
        let records = source_records(&inventory.factory, &state.selected_addresses)?;
        if observed.bus0.inventory.selected_addresses != state.selected_addresses
            || observed.bus0.all_caller_tasks_joined_at.is_none()
            || observed.bus0.inventory.all_caller_tasks_joined_at.is_none()
            || observed
                .bus0
                .inventory
                .factory
                .as_ref()
                .is_none_or(|factory| {
                    factory.failure.is_some()
                        || factory.stopped_at.is_some()
                        || factory.blocking_task_joined_at.is_none()
                        || factory.selected_addresses != state.selected_addresses
                        || factory.collection.as_ref() != Some(&inventory.factory)
                        || factory.attempts.len() != inventory.factory.pages().len()
                        || !factory.attempts.iter().zip(inventory.factory.pages()).all(
                            |(attempt, page)| {
                                attempt.address == page.address()
                                    && attempt.call_returned_at.is_some()
                                    && attempt.error.is_none()
                                    && attempt.returned_page.as_deref()
                                        == Some(page.raw_page().as_slice())
                            },
                        )
                })
            || inventory.pics.len() != state.selected_addresses.len()
            || !inventory
                .pics
                .iter()
                .zip(&state.selected_addresses)
                .all(|(pic, address)| {
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
        {
            return Err(
                "BB native optional policy lacks original collection/roster/fw89 joins".into(),
            );
        }
        let collection = inventory.factory.clone();
        let selected = state.selected_addresses.clone();
        let original_owner = Arc::downgrade(&self.state);
        // Sample under the original state lock after cloning retained data,
        // at actual promotion, never
        // before lock acquisition or from a caller-provided timestamp.
        let admitted_at = Instant::now();
        if joined_at >= deadline || admitted_at >= deadline || !state.can_continue(&self.handles) {
            return Err("BB native optional policy diagnostic deadline or owner expired".into());
        }
        let policy = NativePolicy {
            original_owner,
            collection,
            selected,
            records,
            sequence: state.sequence,
            profile_generation: state.execution.profile_generation,
            diagnostic_deadline: deadline,
            diagnostic_joined_at: joined_at,
            admitted_at,
        };
        state.pic_optional_bridge.policy = Some(Arc::new(Policy {
            origin: Origin::NativeJoined(policy),
        }));
        Ok(())
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_management_owner_pic_optional_policy_source_tests.rs"]
mod source_tests;
