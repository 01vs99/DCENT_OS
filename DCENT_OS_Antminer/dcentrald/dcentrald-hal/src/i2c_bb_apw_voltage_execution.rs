//! Internal BB controller execution candidate; not registered in production.
//!
//! Executes through one retained service using the actual absolute deadline.
//! The complete cold/runtime controller must own the selected factory tuple,
//! ASIC drain, GPIO and terminal lifetime before calling this component.
//! Existing public APW setters remain unsupported. No daemon caller is added.

use super::*;
use crate::bb_apw_diagnostics::{Field, ProfileAttempt, Query};
use crate::bb_apw_voltage_exchange::{Hw76VoltageExchange, Phase, Snapshot};
use crate::bb_voltage_planner::{self, Decision, History, Plan};
use crate::bb_voltage_profile::{Hw76RequestedVoltageProfile, SelectedVoltagePair};

#[derive(Clone, Debug)]
pub(crate) struct VoltageExecutionAttempt {
    pub deadline: Instant,
    pub caller_started_at: Instant,
    pub requested_profile: Hw76RequestedVoltageProfile,
    pub prior_history: History,
    /// This attempt's actual identity/calibration/DAC query results through
    /// the same retained service, never an injected historical profile DTO.
    pub profile: Option<ProfileAttempt>,
    pub selected_pair: Option<SelectedVoltagePair>,
    /// Proposed history only. The enclosing owner must observe the real caller
    /// join before committing any successful operation history.
    pub plan: Option<Plan>,
    pub exchange: Option<Snapshot>,
    pub failure: Option<String>,
    /// Caller completion is not its JoinHandle or a service-close receipt.
    /// With no exchange, it can mean only a numerical no-request outcome.
    pub caller_completed_at: Option<Instant>,
}

struct FenceOnFailure<'a> {
    handle: &'a I2cServiceHandle,
    armed: bool,
}

impl Drop for FenceOnFailure<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.handle.latch_terminal_safe_off();
        }
    }
}

/// Internal blocking worker caller, intended to be held in the full controller's
/// retained JoinHandle. No replacement bus, raw frame, endpoint, cadence, intent
/// or caller-supplied current is accepted. Numerical input alone is not a cold
/// hardware admission; this draft has no registered production caller.
pub(crate) fn execute(
    handle: &I2cServiceHandle,
    requested_profile: Hw76RequestedVoltageProfile,
    history: History,
    deadline: Instant,
) -> VoltageExecutionAttempt {
    let mut result = VoltageExecutionAttempt {
        deadline,
        caller_started_at: Instant::now(),
        requested_profile,
        prior_history: history,
        profile: None,
        selected_pair: None,
        plan: None,
        exchange: None,
        failure: None,
        caller_completed_at: None,
    };
    let mut guard = FenceOnFailure {
        handle,
        armed: true,
    };
    let outcome = (|| -> std::result::Result<(), String> {
        if handle.bus != 1 {
            return Err("BB voltage execution requires its retained bus-1 service".into());
        }
        live(handle, deadline)?;
        // Fixed HW76/FW17 checks precede calibration and DAC; no control frame
        // can reach a foreign device after a failed identity observation.
        result.profile = Some(handle.read_bb_apw_profile_at(deadline));
        let profile = result.profile.as_ref().expect("actual profile retained");
        if profile.failure.is_some() || profile.caller_completed_at.is_none() {
            return Err(format!(
                "BB voltage execution profile failed: {:?}",
                profile.failure
            ));
        }
        live(handle, deadline)?;
        let current = match profile.queries.last() {
            Some(query) if query.query == Query::Dac => match &query.decoded {
                Ok(Field::Dac {
                    millivolts: Some(value),
                    ..
                }) => f64::from(*value) / 1000.0,
                _ => return Err("BB voltage execution has no convertible owned DAC reply".into()),
            },
            _ => return Err("BB voltage execution lacks its final owned DAC query".into()),
        };
        result.selected_pair = requested_profile
            .select_pair(current)
            .map_err(|error| format!("BB voltage selection refused: {error:?}"))?;
        let Some(pair) = result.selected_pair else {
            return Ok(());
        };
        let plan = bb_voltage_planner::plan_step(current, pair.target, pair.maximum_step, history)
            .map_err(|error| format!("BB voltage history/plan refused: {error:?}"))?;
        result.plan = Some(plan);
        let Decision::Request(volts) = plan.decision else {
            // A source numerical no-request/tolerance branch is recorded as
            // such. It neither powers down nor starts a fabricated exchange.
            return Ok(());
        };
        let mut exchange = Hw76VoltageExchange::new(volts, Instant::now(), deadline)
            .map_err(|error| format!("BB voltage exchange preparation refused: {error:?}"))?;
        let executed = (|| -> std::result::Result<(), String> {
            for (expected_before, expected_after, intent) in [
                (
                    Phase::ReadySet,
                    Phase::SetAcknowledged,
                    I2cOperationIntent::Energize,
                ),
                (
                    Phase::SetAcknowledged,
                    Phase::Complete,
                    I2cMutationLabel::QueryPrelude.internal_intent(),
                ),
            ] {
                live(handle, deadline)?;
                if exchange.snapshot().phase != expected_before {
                    return Err("BB voltage exchange phase changed before execution".into());
                }
                let steps = exchange.prepare_next(Instant::now()).map_err(|error| {
                    format!("BB voltage fixed transaction preparation failed: {error:?}")
                })?;
                let returned = submit_fixed(handle, intent, steps, deadline)
                    .map_err(|error| error.to_string());
                // Preserve all actual returned records even if a concurrently
                // latched fence prevents this result from advancing the owner.
                let decoded = exchange.accept_reply(Instant::now(), returned);
                live(handle, deadline)?;
                if decoded
                    .map_err(|error| format!("BB voltage exchange reply failed: {error:?}"))?
                    != expected_after
                {
                    return Err("BB voltage exchange returned an unexpected phase".into());
                }
            }
            Ok(())
        })();
        if executed.is_err() {
            exchange.cancel();
        }
        result.exchange = Some(exchange.snapshot());
        executed
    })();
    match outcome.and_then(|()| live(handle, deadline)) {
        Ok(()) => {
            let completed = Instant::now();
            if completed < deadline && !handle.terminal_safe_off_is_latched() {
                result.caller_completed_at = Some(completed);
                guard.armed = false;
            } else {
                result.failure =
                    Some("BB voltage execution deadline/fence at caller completion".into());
            }
        }
        Err(error) => result.failure = Some(error),
    }
    result
}

fn live(handle: &I2cServiceHandle, deadline: Instant) -> std::result::Result<(), String> {
    if Instant::now() >= deadline || handle.terminal_safe_off_is_latched() {
        Err("BB voltage execution deadline or permanent terminal fence".into())
    } else {
        Ok(())
    }
}

fn submit_fixed(
    handle: &I2cServiceHandle,
    intent: I2cOperationIntent,
    steps: Vec<I2cTransactionStep>,
    deadline: Instant,
) -> Result<Vec<Vec<u8>>> {
    const ADDRESS: u8 = crate::bb_apw_diagnostics::ADDRESS;
    validate_transaction_message_lengths(handle.bus, ADDRESS, &steps)?;
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    let request = I2cRequest::Transaction {
        addr: ADDRESS,
        steps,
        reply_tx,
    };
    let budget = I2cRequestBudget::for_request_until(&request, deadline).ok_or_else(|| {
        HalError::I2cEndpointNotReady {
            bus: handle.bus,
            addr: ADDRESS,
            detail: "BB voltage execution deadline elapsed before fixed transaction admission"
                .into(),
        }
    })?;
    handle.submit_with_intent_budget(ADDRESS, intent, request, reply_rx, budget)
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "i2c_bb_apw_voltage_execution_tests.rs"]
mod tests;
