//! Fixed selected fw89/LM75 observations on the parent's retained bus0 worker.
use super::{lock, stop, Handles, PendingActivity, State};
use crate::bb_pic_application;
use crate::bb_pic_lm75;
use crate::platform::bb_bus0_diagnostic::BbBridgeDiagnosticAttempt;
use crate::platform::bb_selected_inventory::BbSelectedPicAttempt;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub(crate) struct BbOwnedBus0Observation {
    pub sequence: u64,
    pub deadline: Instant,
    pub selected_addresses: Vec<u8>,
    pub pics: Vec<BbSelectedPicAttempt>,
    pub bridges: Vec<BbBridgeDiagnosticAttempt>,
    pub caller_completed_at: Option<Instant>,
    pub caller_joined_at: Option<Instant>,
    /// Whole fixed caller was joined before its original deadline. No method
    /// turns these caller times into physical temperature sampling timestamps.
    pub accepted_at: Option<Instant>,
    pub failure: Option<String>,
}

fn can_continue(state: &mut State, handles: &Handles) -> bool {
    let deadline = state
        .latest_bus0
        .as_ref()
        .expect("retained bus0 attempt")
        .deadline;
    if Instant::now() >= deadline {
        handles.fence();
        state.stop("BB runtime bus0 original deadline elapsed");
        state
            .latest_bus0
            .as_mut()
            .expect("retained bus0 attempt")
            .failure
            .get_or_insert_with(|| "BB runtime bus0 original deadline elapsed".into());
    }
    state.can_continue(handles)
}

fn fail(state: &mut State, handles: &Handles, reason: String) {
    handles.fence();
    state.stop(&reason);
    state
        .latest_bus0
        .as_mut()
        .expect("retained bus0 attempt")
        .failure
        .get_or_insert(reason);
}

pub(super) fn start(
    shared: &Arc<Mutex<State>>,
    handles: &Handles,
    deadline: Instant,
) -> JoinHandle<()> {
    let mut state = lock(shared, handles);
    let selected = state.selected_addresses.clone();
    state.latest_bus0 = Some(BbOwnedBus0Observation {
        sequence: state.sequence,
        deadline,
        selected_addresses: selected.clone(),
        pics: Vec::with_capacity(selected.len()),
        bridges: Vec::with_capacity(selected.len() * 4),
        caller_completed_at: None,
        caller_joined_at: None,
        accepted_at: None,
        failure: None,
    });
    drop(state);
    let shared = shared.clone();
    let handles = handles.clone();
    tokio::task::spawn_blocking(move || {
        // These declarations came from actual joined factory acquisition;
        // independently recheck their narrow native endpoint shape before I/O.
        let valid = !selected.is_empty()
            && selected.len() <= 3
            && selected.iter().enumerate().all(|(index, address)| {
                (0x50..=0x52).contains(address) && !selected[..index].contains(address)
            });
        if !valid || handles.bus0.bus() != 0 {
            fail(
                &mut lock(&shared, &handles),
                &handles,
                "BB runtime bus0 selected endpoint shape refused".into(),
            );
            return;
        }
        // Renew every selected application before any selected LM75 query,
        // preserving the accepted pre-power inventory's ordering policy.
        for address in &selected {
            let slot = usize::from(address - 0x50);
            let index = {
                let mut state = lock(&shared, &handles);
                if !can_continue(&mut state, &handles) {
                    return;
                }
                let sample = state.latest_bus0.as_mut().expect("retained bus0 attempt");
                let index = sample.pics.len();
                sample.pics.push(BbSelectedPicAttempt {
                    factory_address: *address,
                    native_slot: slot,
                    pic_address: bb_pic_application::native_pic_address(slot)
                        .expect("native slot checked"),
                    call_prepared_at: Instant::now(),
                    call_returned_at: None,
                    returned_reads: None,
                    accepted_reply: None,
                    error: None,
                });
                index
            };
            let returned = handles.bus0.read_bb_pic_application_at(slot, deadline);
            let mut state = lock(&shared, &handles);
            let attempt = &mut state
                .latest_bus0
                .as_mut()
                .expect("retained bus0 attempt")
                .pics[index];
            attempt.call_returned_at = Some(Instant::now());
            let parsed = match returned {
                Ok(reads) => {
                    let parsed = bb_pic_application::complete_reply(&reads)
                        .map_err(|error| error.to_string());
                    attempt.returned_reads = Some(reads);
                    parsed
                }
                Err(error) => Err(error.to_string()),
            };
            match parsed {
                Ok(reply) => attempt.accepted_reply = Some(reply),
                Err(error) => {
                    attempt.error = Some(error.clone());
                    fail(&mut state, &handles, error);
                    return;
                }
            }
            if !can_continue(&mut state, &handles) {
                return;
            }
        }
        for address in &selected {
            let slot = usize::from(address - 0x50);
            for sensor in bb_pic_lm75::SENSOR_ADDRESSES {
                let index = {
                    let mut state = lock(&shared, &handles);
                    if !can_continue(&mut state, &handles) {
                        return;
                    }
                    let sample = state.latest_bus0.as_mut().expect("retained bus0 attempt");
                    let index = sample.bridges.len();
                    sample.bridges.push(BbBridgeDiagnosticAttempt {
                        factory_address: *address,
                        native_slot: slot,
                        pic_address: bb_pic_application::native_pic_address(slot)
                            .expect("native slot checked"),
                        sensor_address: sensor,
                        call_prepared_at: Instant::now(),
                        call_returned_at: None,
                        returned_reads: None,
                        decoded: None,
                        error: None,
                    });
                    index
                };
                let returned = handles.bus0.read_bb_pic_lm75_at(slot, sensor, deadline);
                let mut state = lock(&shared, &handles);
                let attempt = &mut state
                    .latest_bus0
                    .as_mut()
                    .expect("retained bus0 attempt")
                    .bridges[index];
                attempt.call_returned_at = Some(Instant::now());
                let parsed = match returned {
                    Ok(reads) => {
                        let parsed = bb_pic_lm75::complete_reply(&reads)
                            .map_err(|error| format!("BB runtime LM75 reply refused: {error:?}"));
                        attempt.returned_reads = Some(reads);
                        parsed
                    }
                    Err(error) => Err(error.to_string()),
                };
                match parsed {
                    Ok(sample) => attempt.decoded = Some(sample),
                    Err(error) => {
                        attempt.error = Some(error.clone());
                        fail(&mut state, &handles, error);
                        return;
                    }
                }
                if !can_continue(&mut state, &handles) {
                    return;
                }
            }
        }
        let mut state = lock(&shared, &handles);
        if can_continue(&mut state, &handles) {
            state
                .latest_bus0
                .as_mut()
                .expect("retained bus0 attempt")
                .caller_completed_at = Some(Instant::now());
        }
    })
}

pub(super) async fn join_until(
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
        stop(
            shared,
            handles,
            "BB runtime bus0 caller join deadline elapsed",
        );
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
            "BB runtime bus0 caller not joined before deadline",
        );
        return false;
    };
    *task = None;
    let observed_at = Instant::now();
    let mut state = lock(shared, handles);
    state
        .latest_bus0
        .as_mut()
        .expect("retained bus0 attempt")
        .caller_joined_at = Some(observed_at);
    if let Err(error) = result {
        fail(
            &mut state,
            handles,
            format!("BB runtime bus0 caller task failed: {error}"),
        );
    } else if observed_at >= deadline {
        fail(
            &mut state,
            handles,
            "BB runtime bus0 caller joined after observation deadline".into(),
        );
    } else if promote && can_continue(&mut state, handles) {
        let sample = state.latest_bus0.as_mut().expect("retained bus0 attempt");
        if sample.failure.is_none()
            && sample.caller_completed_at.is_some()
            && sample.pics.len() == sample.selected_addresses.len()
            && sample.bridges.len() == sample.selected_addresses.len() * 4
        {
            sample.accepted_at = Some(observed_at);
        } else {
            fail(
                &mut state,
                handles,
                "BB runtime bus0 caller did not complete the whole selected observation".into(),
            );
        }
    }
    pending.armed = false;
    true
}
