//! Pure requested-voltage profile for the held BB HW0x76 software path.
//!
//! Held ELF SHA256386b88490154b1007ca15d0f529749664ec641743d7f132127ec078c196df1df:
//! 593c48 supplies software bounds for packed PSU tag0/HW76 and model1/2/4/5;
//! 557504 merges optional requested fields; 565b50..565e50 selects the voltage
//! pair with the source default step. Native additionally refuses nonfinite
//! inputs and invalid current observations. Typed options represent only
//! absence or presence; diagnostic noncanonical serialized words have no API.
//!
//! This data object contains no current identity, observation freshness, bus,
//! GPIO, worker, timer or power capability. Its constructor does not identify
//! hardware. A future controller must establish the exact tuple and retain all
//! physical owners before using this software policy. No actuator is exposed.

/// Original helper output+0x68/+0x70 on the exact packed HW76 path.
const SOURCE_MIN_VOLTS: f64 = 11.88;
const SOURCE_MAX_VOLTS: f64 = 15.12;
/// Original helper output+0x78/+0x80. This maximum is a software bound,
/// not a recommendation to make a ten-volt electrical change.
const SOURCE_MIN_STEP_VOLTS: f64 = 0.05;
const SOURCE_MAX_STEP_VOLTS: f64 = 10.0;
/// Original 5589f0 PC-relative load from558dc8.
const SOURCE_DEFAULT_STEP_VOLTS: f64 = f64::from_bits(0x3fa9_9999_9999_999a);

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Hw76RequestedVoltageProfile {
    target: Option<f64>,
    step_override: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct SelectedVoltagePair {
    pub target: f64,
    pub maximum_step: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileError {
    InvalidTarget,
    InvalidStep,
    InvalidCurrent,
}

fn voltage_in_source_bounds(value: f64) -> bool {
    value.is_finite() && (SOURCE_MIN_VOLTS..=SOURCE_MAX_VOLTS).contains(&value)
}

impl Hw76RequestedVoltageProfile {
    /// Merge a partial request. None preserves the existing requested field;
    /// it does not reset a step override or erase a previously stored target.
    /// Validate the entire update before changing either field.
    pub(crate) fn merge_request(
        &mut self,
        target: Option<f64>,
        step_override: Option<f64>,
    ) -> Result<(), ProfileError> {
        if target.is_some_and(|value| !voltage_in_source_bounds(value)) {
            return Err(ProfileError::InvalidTarget);
        }
        if step_override.is_some_and(|value| {
            !value.is_finite() || !(SOURCE_MIN_STEP_VOLTS..=SOURCE_MAX_STEP_VOLTS).contains(&value)
        }) {
            return Err(ProfileError::InvalidStep);
        }
        if let Some(value) = target {
            self.target = Some(value);
        }
        if let Some(value) = step_override {
            self.step_override = Some(value);
        }
        Ok(())
    }

    /// Numerical selection for the source request mode used by the retained
    /// producer. Other frequency/profile modes are not represented here.
    /// None is only a lack of a new numerical voltage request, never evidence
    /// of electrical convergence, successful mining or terminal shutdown.
    pub(crate) fn select_pair(
        &self,
        current: f64,
    ) -> Result<Option<SelectedVoltagePair>, ProfileError> {
        if !voltage_in_source_bounds(current) {
            return Err(ProfileError::InvalidCurrent);
        }
        let Some(target) = self.target else {
            return Ok(None);
        };
        // Original565cd0..565cfc independently truncates both values before
        // comparing them. Preserve operation order and the original f64 bits.
        let target_centivolts = (target * 100.0).trunc() / 100.0;
        let current_centivolts = (current * 100.0).trunc() / 100.0;
        if target_centivolts == current_centivolts {
            return Ok(None);
        }
        Ok(Some(SelectedVoltagePair {
            target: target_centivolts,
            maximum_step: self.step_override.unwrap_or(SOURCE_DEFAULT_STEP_VOLTS),
        }))
    }
}

#[cfg(test)]
#[path = "bb_voltage_profile_tests.rs"]
mod tests;
