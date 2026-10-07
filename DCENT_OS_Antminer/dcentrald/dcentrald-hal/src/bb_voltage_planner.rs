//! Pure BB voltage-worker arithmetic from held LuxOS ELF
//! 386b88490154b1007ca15d0f529749664ec641743d7f132127ec078c196df1df.
//!
//! This planner owns no bus, GPIO, queue, timer, profile admission or actuator.
//! Its numerical output is not permission to apply an electrical command.
//! A future controller must supply its independently admitted operating tuple,
//! fresh owned readback and actual request history before using the result.
//!
//! ELF 559d1c..559d88 and 55ac88..55acd0 supply the request calculation;
//! 55bc08..55bc10 update history, and 55bc4c..55bc70 choose tolerance handling.
//! The helper at 9c0710 clears fractional bits: it truncates toward zero.
//! Both centivolt operations must remain separate, with no reassociation.

/// Source command producer 5589f0 loads literal 558dc8. This is a step,
/// not a target voltage or an admitted operating limit.
pub(crate) const SOURCE_DEFAULT_STEP_VOLTS: f64 = f64::from_bits(0x3fa9_9999_9999_999a);

/// Independently loaded source tolerance at the later history branch.
const SOURCE_TOLERANCE_VOLTS: f64 = f64::from_bits(0x3fa9_9999_9999_999a);

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct History {
    pub previous_request: Option<f64>,
    pub repeated_requests: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Decision {
    Request(f64),
    UnchangedCentivolts,
    /// Source execution has reached its history/tolerance branch. This is
    /// neither successful physical convergence nor a completed shutdown.
    HistoryTolerance {
        within_source_tolerance: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Plan {
    pub decision: Decision,
    pub history: History,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlanError {
    InvalidVoltage,
    InvalidStep,
    InvalidHistory,
    RepeatCounterOverflow,
}

fn finite_centivolt_domain(value: f64) -> bool {
    // Numerical representability only; no hardware or operating limit.
    value.is_finite() && (value * 100.0).abs() < (1_u64 << 53) as f64
}

fn centivolts(value: f64) -> f64 {
    (value * 100.0).trunc() / 100.0
}

/// Plan one source numerical step. The caller must separately admit the
/// selected source profile, voltage limits and step override.
///
/// Deliberate native refusals: nonfinite/unrepresentable numbers, negative
/// voltages, steps below one centivolt and overflowing history. The original
/// accepts zero/sub-centivolt steps and can then jump directly to the target;
/// retaining that diagnostic source behavior is not suitable admission.
pub(crate) fn plan_step(
    current: f64,
    target: f64,
    maximum_step: f64,
    history: History,
) -> Result<Plan, PlanError> {
    if !finite_centivolt_domain(current)
        || !finite_centivolt_domain(target)
        || current < 0.0
        || target < 0.0
    {
        return Err(PlanError::InvalidVoltage);
    }
    if !finite_centivolt_domain(maximum_step) || maximum_step < 0.01 {
        return Err(PlanError::InvalidStep);
    }
    if history
        .previous_request
        .is_some_and(|previous| !finite_centivolt_domain(previous) || previous < 0.0)
        || (history.previous_request.is_none() && history.repeated_requests != 0)
    {
        return Err(PlanError::InvalidHistory);
    }
    source_step(current, target, maximum_step, history)
}

// Kept private to test diagnostic original inputs (including step zero)
// against captured ARM results without granting those inputs native admission.
fn source_step(
    current: f64,
    target: f64,
    maximum_step: f64,
    mut history: History,
) -> Result<Plan, PlanError> {
    let delta = target - current;
    let bounded_delta = delta.clamp(-maximum_step, maximum_step);
    let truncated_delta = centivolts(bounded_delta);
    let candidate = if truncated_delta != 0.0 {
        centivolts(current + truncated_delta)
    } else {
        let truncated_target = centivolts(target);
        if truncated_target == centivolts(current) {
            return Ok(Plan {
                decision: Decision::UnchangedCentivolts,
                history,
            });
        }
        truncated_target
    };
    if history.previous_request != Some(candidate) {
        history.previous_request = Some(candidate);
        history.repeated_requests = 0;
    } else {
        history.repeated_requests = history
            .repeated_requests
            .checked_add(1)
            .ok_or(PlanError::RepeatCounterOverflow)?;
        let distance = (current - target).abs();
        // Original 55bc4c checks the updated count for zero. Native checked
        // increment above makes wraparound impossible, so every count here
        // is nonzero. Preserve the source threshold of greater than nine.
        if distance <= maximum_step || history.repeated_requests > 9 {
            return Ok(Plan {
                decision: Decision::HistoryTolerance {
                    within_source_tolerance: distance <= SOURCE_TOLERANCE_VOLTS,
                },
                history,
            });
        }
    }
    Ok(Plan {
        decision: Decision::Request(candidate),
        history,
    })
}

#[cfg(test)]
#[path = "bb_voltage_planner_tests.rs"]
mod tests;
