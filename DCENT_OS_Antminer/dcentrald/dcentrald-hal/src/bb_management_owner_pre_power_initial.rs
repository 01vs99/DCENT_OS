//! Original initial-disable -> fixed bridge prefix, with no ON or voltage phase.
//! Descends from the fixed-exchange owner, preserving private caller ownership.
use super::{lock, stop, BbManagementOwner, Handles, Phase, State};
use crate::i2c::bb_pic_initialization_exchange::Observation as ExchangeObservation;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

#[derive(Clone, Debug)]
pub(crate) struct BridgeCall {
    pub selected_index: usize,
    pub factory_address: u8,
    pub invoked_at: Instant,
    pub returned_at: Option<Instant>,
    pub failure: Option<String>,
    // Index in this owner's actual retained caller vector, reserved before
    // entering the helper. Absence of a real row is never fabricated as a join.
    caller_index: usize,
    pub original: Option<ExchangeObservation>,
    pub caller_joined_at: Option<Instant>,
    pub timely_joined_at: Option<Instant>,
    pub original_pending: Option<bool>,
}

#[derive(Clone, Debug)]
pub(crate) struct Observation {
    pub started_at: Instant,
    pub original_deadline: Instant,
    pub selected_addresses: Vec<u8>,
    pub initial_disable_joined_at: Option<Instant>,
    pub bridge_phase_started_at: Option<Instant>,
    pub returned_at: Option<Instant>,
    pub accepted_at: Option<Instant>,
    pub cancelled_at: Option<Instant>,
    pub first_failure: Option<String>,
    pub calls: Vec<BridgeCall>,
    pub original_callers_pending: bool,
    bridge_active: bool,
}
pub(in crate::bb_management_owner) type History = Arc<Mutex<Observation>>;
fn history(value: &Mutex<Observation>) -> MutexGuard<'_, Observation> {
    value.lock().unwrap_or_else(|poison| {
        let mut held = poison.into_inner();
        held.first_failure
            .get_or_insert_with(|| "initial bridge history poisoned".into());
        held
    })
}
pub(super) fn bridge_active(value: &History) -> bool {
    history(value).bridge_active
}

struct PendingPrefix {
    state: Arc<Mutex<State>>,
    handles: Handles,
    history: History,
    armed: bool,
}
impl Drop for PendingPrefix {
    fn drop(&mut self) {
        if self.armed {
            stop(
                &self.state,
                &self.handles,
                "original initial bridge prefix canceled or failed",
            );
            let mut held = history(&self.history);
            held.cancelled_at.get_or_insert_with(Instant::now);
            held.first_failure
                .get_or_insert_with(|| "original initial bridge prefix canceled or failed".into());
        }
    }
}

impl BbManagementOwner {
    pub(crate) fn initial_bridge_snapshot(&self) -> Option<Observation> {
        let retained = self.initial_bridges.as_ref()?;
        let mut value = history(retained).clone();
        let callers = self.initialization_callers.snapshots();
        for call in &mut value.calls {
            if let Some(actual) = callers.get(call.caller_index) {
                // These are actual original records, including late worker
                // completion while the asynchronous enclosing caller is gone.
                call.original = Some(actual.original.clone());
                call.caller_joined_at = actual.history.joined_at;
                call.timely_joined_at = actual.history.timely_joined_at;
                call.original_pending = Some(actual.pending);
            }
        }
        value.original_callers_pending =
            self.initial_disable.pending() || self.initialization_callers.pending();
        Some(value)
    }

    /// No caller selection/policy/frame or prior receipt enters this prefix.
    /// Each fresh normal bridge token remains bound to the sweep's final exact
    /// allocation/generation at capture; later normal phases remain separate.
    pub(crate) async fn initial_disable_and_bridges_until(
        &mut self,
        deadline: Instant,
    ) -> Result<(), String> {
        if self.initial_bridges.is_some() {
            return Err("original initial bridge prefix is one-shot".into());
        }
        let selected = {
            let mut state = lock(&self.state, &self.handles);
            if !state.diagnostic_joined
                || Instant::now() >= deadline
                || !state.can_continue(&self.handles)
            {
                return Err(
                    "initial bridge prefix requires original joined live diagnostics".into(),
                );
            }
            state.selected_addresses.clone()
        };
        let retained = Arc::new(Mutex::new(Observation {
            started_at: Instant::now(),
            original_deadline: deadline,
            selected_addresses: selected.clone(),
            initial_disable_joined_at: None,
            bridge_phase_started_at: None,
            returned_at: None,
            accepted_at: None,
            cancelled_at: None,
            first_failure: None,
            calls: Vec::new(),
            original_callers_pending: false,
            bridge_active: false,
        }));
        self.initial_bridges = Some(retained.clone());
        let mut pending = PendingPrefix {
            state: self.state.clone(),
            handles: self.handles.clone(),
            history: retained.clone(),
            armed: true,
        };
        let result: Result<(), String> = async {
            self.initial_disable_until(deadline).await?;
            // This same owner consumes the actual initial result immediately
            // before the following fixed phase, with no caller DTO/await gap.
            self.require_initial_disable_complete()?;
            {
                let original = self
                    .initial_disable_snapshot()
                    .ok_or("original initial sweep absent")?;
                if original.original.original_deadline != deadline {
                    return Err("initial prefix deadline changed".into());
                }
                let mut held = history(&retained);
                if held.first_failure.is_some() || Instant::now() >= deadline {
                    return Err("initial bridge phase became late or failed".into());
                }
                held.initial_disable_joined_at = original.history.timely_joined_at;
                held.bridge_phase_started_at = Some(Instant::now());
                held.bridge_active = true;
            }
            for (selected_index, factory_address) in selected.iter().copied().enumerate() {
                self.require_initial_disable_complete()?;
                let caller_index = self.initialization_callers.snapshots().len();
                {
                    let mut held = history(&retained);
                    held.calls.push(BridgeCall {
                        selected_index,
                        factory_address,
                        invoked_at: Instant::now(),
                        returned_at: None,
                        failure: None,
                        caller_index,
                        original: None,
                        caller_joined_at: None,
                        timely_joined_at: None,
                        original_pending: None,
                    });
                }
                // The unchanged retained caller invokes the actual preparation
                // synchronously before its first await. The narrow preparation
                // branch additionally compares the fresh token to the exact
                // original disable generation, closing the guard/capture race.
                let result = self
                    .run_retained_pic_initialization_exchange(
                        selected_index,
                        Phase::Bridge,
                        deadline,
                    )
                    .await;
                {
                    let mut held = history(&retained);
                    let call = held.calls.last_mut().expect("original invocation retained");
                    call.returned_at = Some(Instant::now());
                    call.failure = result.as_ref().err().cloned();
                }
                result?;
                // Bridge never advances generation. A foreign SafeOff after its
                // original worker/caller completion cannot become prefix success.
                self.require_initial_disable_complete()?;
            }
            self.require_initial_disable_complete()?;
            let observed = self
                .initial_bridge_snapshot()
                .ok_or("original prefix disappeared")?;
            if observed.original_callers_pending
                || observed.calls.len() != selected.len()
                || observed.calls.iter().zip(&selected).any(|(call, address)| {
                    call.factory_address != *address
                        || call.original_pending != Some(false)
                        || call.timely_joined_at.is_none()
                        || call.failure.is_some()
                        || call.original.as_ref().is_none_or(|original| {
                            original.phase != Phase::Bridge
                                || original.factory_address != *address
                                || original.original_deadline != deadline
                                || original.worker_finalized_at.is_none()
                                || original.caller_finalized_at.is_none()
                                || original.first_failure.is_some()
                        })
                })
            {
                return Err("original bridge callers and workers did not all join".into());
            }
            Ok(())
        }
        .await;
        let mut held = history(&retained);
        let final_generation_current = self
            .initial_disable
            .following_phase_origin()
            .is_some_and(|origin| origin.final_generation_current());
        let now = Instant::now();
        held.returned_at = Some(now);
        let result = result.and_then(|()| {
            if now >= deadline
                || held.first_failure.is_some()
                || self.handles.is_stopped()
                || !final_generation_current
            {
                Err("original initial bridge prefix returned late, failed or terminal".into())
            } else {
                Ok(())
            }
        });
        if result.is_ok() {
            held.accepted_at = Some(now);
            held.bridge_active = false;
        } else {
            held.first_failure
                .get_or_insert_with(|| result.as_ref().err().unwrap().clone());
        }
        drop(held);
        if result.is_err() {
            stop(
                &self.state,
                &self.handles,
                "original initial bridge prefix failed",
            );
        }
        pending.armed = false;
        result
    }
}
