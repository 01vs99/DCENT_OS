//! Retained direct/stepped DAC commands from 394 complete original callers.
//! A received frame is command evidence; rail verification remains independent.
use super::*;
use dcentrald_common::bm1396_contract::{
    bm1396_validate_voltage_response, bm1396_voltage_dac_in_vendor_envelope,
    bm1396_voltage_request_frame, plan_bm1396_vendor_voltage_dac_ramp,
};

const CAPACITY: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoltageStepObservation {
    dac: u8,
    request: [u8; 8],
    transmitted: usize,
    response: Vec<u8>,
    framing_complete: bool,
    completed_at: Option<Instant>,
}
impl VoltageStepObservation {
    pub fn dac(&self) -> u8 {
        self.dac
    }
    pub fn request(&self) -> &[u8; 8] {
        &self.request
    }
    pub fn completed_request_bytes(&self) -> usize {
        self.transmitted
    }
    pub fn response(&self) -> &[u8] {
        &self.response
    }
    pub fn framing_complete(&self) -> bool {
        self.framing_complete
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoltageAttempt {
    issuer: Arc<()>,
    sequence: u64,
    prior: Option<CommandedVoltage>,
    initial_source_context_cv: Option<u16>,
    requested_cv: u16,
    stepped: bool,
    codes: Vec<u8>,
    steps: Vec<VoltageStepObservation>,
    completed_at: Option<Instant>,
}
impl VoltageAttempt {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn prior_command(&self) -> Option<CommandedVoltage> {
        self.prior
    }
    /// Original supply42 initializer's software value, never a measured rail
    /// or a synthetic prior completed command. Only first reset can consume it.
    pub fn initial_source_context_centivolts(&self) -> Option<u16> {
        self.initial_source_context_cv
    }
    pub fn requested_centivolts(&self) -> u16 {
        self.requested_cv
    }
    pub fn is_stepped(&self) -> bool {
        self.stepped
    }
    pub fn planned_dac_codes(&self) -> &[u8] {
        &self.codes
    }
    pub fn steps(&self) -> &[VoltageStepObservation] {
        &self.steps
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
}

impl<H: Hardware> PicApplication<H> {
    pub fn voltage_attempts(&self) -> Result<Vec<VoltageAttempt>, String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?
            .voltage_attempts
            .iter()
            .cloned()
            .collect())
    }

    pub fn acknowledge_voltage_attempt(&self, attempt: &VoltageAttempt) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?;
        if !Arc::ptr_eq(&attempt.issuer, &self.owner.identity)
            || attempt.completed_at.is_none()
            || state.voltage_attempts.front() != Some(attempt)
        {
            return Err(
                "BM1396 voltage acknowledgment requires oldest exact completed owner attempt"
                    .into(),
            );
        }
        state.voltage_attempts.pop_front();
        Ok(())
    }

    /// Exact17-code ramp from this owner's last completed command. Every frame
    /// must complete and validate; partial failures are terminal without retry.
    /// Does not synthesize an intermediate cV value or physical rail result.
    /// Runtime must perform fresh consecutive rail checks after completion.
    pub async fn command_voltage_ramp(
        self: &Arc<Self>,
        requested_cv: u16,
        deadline: Instant,
    ) -> Result<CommandedVoltage, String> {
        self.command_voltage_retained(requested_cv, true, deadline)
            .await
    }

    pub(super) async fn command_voltage_retained(
        self: &Arc<Self>,
        requested_cv: u16,
        stepped: bool,
        deadline: Instant,
    ) -> Result<CommandedVoltage, String> {
        bm1396_voltage_dac_in_vendor_envelope(requested_cv).map_err(|e| e.to_string())?;
        let app = Arc::clone(self);
        self.owner
            .worker(deadline, false, move |_owner| {
                let lease = app.voltage_lease(deadline)?;
                app.command_voltage_locked(&lease, requested_cv, stepped, deadline)
            })
            .await
    }

    /// Caller holds the logical voltage sequence through every physical frame.
    pub(super) fn command_voltage_locked(
        &self,
        lease: &VoltageLease<'_>,
        requested_cv: u16,
        stepped: bool,
        deadline: Instant,
    ) -> Result<CommandedVoltage, String> {
        self.command_voltage_policy_locked(lease, requested_cv, stepped, false, deadline)
    }

    pub(super) fn command_first_lower_voltage_locked(
        &self,
        lease: &VoltageLease<'_>,
        deadline: Instant,
    ) -> Result<CommandedVoltage, String> {
        self.require_supply_type()?;
        if self
                .conditioning_reset
                .lock()
                .map_err(|_| "T17e reset custody poisoned")?
                .is_none()
        {
            return Err("T17e initial voltage requires its admitted conditioning reset".into());
        }
        self.command_voltage_policy_locked(lease, 1800, true, true, deadline)
    }

    fn command_voltage_policy_locked(
        &self,
        lease: &VoltageLease<'_>,
        requested_cv: u16,
        stepped: bool,
        initial_source: bool,
        deadline: Instant,
    ) -> Result<CommandedVoltage, String> {
        self.require_voltage_lease(lease)?;
        let app = self;
        let owner = &self.owner;
        let dac = bm1396_voltage_dac_in_vendor_envelope(requested_cv).map_err(|e| e.to_string())?;
        app.require_health(deadline)?;
        owner.query_presence(deadline)?;
        let (sequence, codes) = {
            let mut state = app.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
            if state.voltage_attempts.len() >= CAPACITY {
                return Err("BM1396 retained voltage attempt capacity exhausted".into());
            }
            let prior = state.last_voltage;
            let codes = if initial_source {
                if state.next_voltage != 0
                    || prior.is_some()
                    || !state.voltage_attempts.is_empty()
                    || requested_cv != 1800
                {
                    return Err("T17e initial voltage software context already consumed".into());
                }
                // Original supply42 context [0,0,2000,1800,1850,1800], then
                // complete 5e394/5c804: conversion of software zero narrows to
                // DAC253; exact17-code descent ends at1800cV/DAC120. This is
                // no claim that a prior physical voltage command completed.
                vec![236, 219, 202, 185, 168, 151, 134, 120]
            } else if stepped {
                let previous =
                    prior.ok_or("BM1396 stepped voltage requires retained prior command")?;
                plan_bm1396_vendor_voltage_dac_ramp(previous.requested_cv, requested_cv)
                    .map_err(|e| e.to_string())?
            } else {
                vec![dac]
            };
            let sequence = state.next_voltage;
            state.next_voltage = sequence
                .checked_add(1)
                .ok_or("BM1396 voltage sequence exhausted")?;
            state.voltage_attempts.push_back(VoltageAttempt {
                issuer: Arc::clone(&owner.identity),
                sequence,
                prior,
                initial_source_context_cv: initial_source.then_some(0),
                requested_cv,
                stepped,
                codes: codes.clone(),
                steps: Vec::new(),
                completed_at: None,
            });
            (sequence, codes)
        };
        let mut final_response = None;
        for code in codes {
            // Keep the logical voltage sequence stable while releasing the
            // physical lane between frames for admitted PIC heartbeats.
            let _lane = owner.lock(&owner.management, deadline, false)?;
            app.require_health(deadline)?;
            owner.query_presence(deadline)?;
            final_response = Some(app.voltage_frame(sequence, code, deadline)?);
        }
        owner.query_presence(deadline)?;
        app.require_health(deadline)?;
        let response = final_response.ok_or("BM1396 empty voltage sequence")?;
        let completed_at = Instant::now();
        let result = CommandedVoltage {
            requested_cv,
            dac,
            response,
            completed_at,
        };
        let mut state = app.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
        let attempt = state
            .voltage_attempts
            .back_mut()
            .filter(|attempt| attempt.sequence == sequence)
            .ok_or("BM1396 voltage attempt custody lost")?;
        attempt.completed_at = Some(completed_at);
        state.last_voltage = Some(result);
        Ok(result)
    }

    fn voltage_step_update(
        &self,
        sequence: u64,
        update: impl FnOnce(&mut VoltageStepObservation),
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?;
        let step = state
            .voltage_attempts
            .back_mut()
            .filter(|attempt| attempt.sequence == sequence)
            .and_then(|attempt| attempt.steps.last_mut())
            .ok_or("BM1396 voltage step custody lost")?;
        update(step);
        Ok(())
    }

    fn voltage_frame(&self, sequence: u64, dac: u8, deadline: Instant) -> Result<[u8; 8], String> {
        let owner = &self.owner;
        owner.check(deadline, false)?;
        if owner.management_fault.load(Ordering::SeqCst) {
            return Err("BM1396 management portal unresolved".into());
        }
        let request = bm1396_voltage_request_frame(dac);
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "BM1396 PIC observations poisoned")?;
            let attempt = state
                .voltage_attempts
                .back_mut()
                .filter(|attempt| attempt.sequence == sequence)
                .ok_or("BM1396 voltage attempt custody lost")?;
            attempt.steps.push(VoltageStepObservation {
                dac,
                request,
                transmitted: 0,
                response: Vec::with_capacity(8),
                framing_complete: false,
                completed_at: None,
            });
        }
        let mut fault = FaultGuard::new(&owner.management_fault, &owner.terminal);
        for byte in request {
            owner.management_byte_locked(0x0520_1100 | u32::from(byte), deadline, false)?;
            self.voltage_step_update(sequence, |step| step.transmitted += 1)?;
        }
        owner.delay(Duration::from_millis(500), deadline, false)?;
        let mut response = [0; 8];
        for byte in &mut response {
            *byte = owner.management_byte_locked(0x0620_0000, deadline, false)?;
            self.voltage_step_update(sequence, |step| step.response.push(*byte))?;
        }
        fault.complete();
        self.voltage_step_update(sequence, |step| step.framing_complete = true)?;
        owner.check(deadline, false)?;
        bm1396_validate_voltage_response(&response)
            .map_err(|e| format!("BM1396 voltage response: {e:?}"))?;
        owner.check(deadline, false)?;
        self.voltage_step_update(sequence, |step| step.completed_at = Some(Instant::now()))?;
        Ok(response)
    }
}
