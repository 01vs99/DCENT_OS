//! One detached HW76 voltage set/echo/following-read protocol operation.
//!
//! Held ELF386b88490154b1007ca15d0f529749664ec641743d7f132127ec078c196df1df:
//! 5aa3b0 supplies opcode83/DAC and checked echo; 5fd130 queues the set then
//! a forced slot read, whose complete 5a6f08 callee supplies opcode03. Native
//! preserves its existing500ms transaction cadence. Source300ms/200ms delays
//! do not replace the retained native cadence. Exact byte echoes are a native
//! correlation requirement, stricter than the source numerical tolerance.
//!
//! This object has no bus handle and performs no I/O. Preparing transactions
//! and accepting caller-provided reply records cannot establish physical
//! identity, freshness, actual task completion or permission to energize.
//! The full controller must retain the same worker and independently admit
//! its cold/ASIC/GPIO lifetime before executing these fixed transactions.

use crate::bb_voltage_profile::Hw76RequestedVoltageProfile;
use crate::i2c::I2cTransactionStep;
use crate::psu_apw_uart_tunnel::{self as wire, Apw76VoltageCode};
use std::time::{Duration, Instant};

const SET_OPCODE: u8 = 0x83;
const REPLY_BYTES: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    ReadySet,
    SetPrepared,
    SetAcknowledged,
    ReadbackPrepared,
    Complete,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExchangeError {
    InvalidRequest,
    Deadline,
    Chronology,
    UnexpectedPhase,
    Transport,
    ReplyShape,
    ReplyProtocol,
    WrongOpcode,
    WrongCode,
    Cancelled,
}

#[derive(Clone, Debug)]
pub(crate) struct ReplyObservation {
    pub received_at: Instant,
    /// Actual caller-returned records, including malformed/short records.
    /// A transport error carries no invented partial worker bytes.
    pub records: Option<Vec<Vec<u8>>>,
    pub transport_error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Snapshot {
    pub created_at: Instant,
    pub requested_millivolts: u16,
    pub expected_code: [u8; 2],
    pub deadline: Instant,
    pub phase: Phase,
    pub set_prepared_at: Option<Instant>,
    pub set_reply: Option<ReplyObservation>,
    pub readback_prepared_at: Option<Instant>,
    pub readback_reply: Option<ReplyObservation>,
    pub reported_millivolts: Option<u16>,
    /// Protocol completion only, not a service/caller join or rail witness.
    /// If a later invalid call fails the object, this stays historical.
    pub protocol_completed_at: Option<Instant>,
    pub failure: Option<ExchangeError>,
}

pub(crate) struct Hw76VoltageExchange {
    state: Snapshot,
}

impl Hw76VoltageExchange {
    /// A numerical request only. The enclosing controller owns admission and
    /// the planner's proposed versus actually committed request history.
    pub(crate) fn new(
        requested_volts: f64,
        now: Instant,
        deadline: Instant,
    ) -> Result<Self, ExchangeError> {
        let mut limits = Hw76RequestedVoltageProfile::default();
        limits
            .merge_request(Some(requested_volts), None)
            .map_err(|_| ExchangeError::InvalidRequest)?;
        let requested_millivolts = (requested_volts * 1000.0).round() as u16;
        // Every accepted planner request is expressed in whole centivolts.
        // Refuse lossy narrowing instead of silently changing a command.
        if requested_millivolts % 10 != 0
            || f64::from(requested_millivolts) / 1000.0 != requested_volts
        {
            return Err(ExchangeError::InvalidRequest);
        }
        let code = Apw76VoltageCode::from_millivolts(requested_millivolts)
            .map_err(|_| ExchangeError::InvalidRequest)?;
        if now >= deadline {
            return Err(ExchangeError::Deadline);
        }
        Ok(Self {
            state: Snapshot {
                created_at: now,
                requested_millivolts,
                expected_code: code.payload(),
                deadline,
                phase: Phase::ReadySet,
                set_prepared_at: None,
                set_reply: None,
                readback_prepared_at: None,
                readback_reply: None,
                reported_millivolts: None,
                protocol_completed_at: None,
                failure: None,
            },
        })
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        self.state.clone()
    }

    fn fail<T>(&mut self, error: ExchangeError) -> Result<T, ExchangeError> {
        self.state.phase = Phase::Failed;
        let original = *self.state.failure.get_or_insert(error);
        Err(original)
    }

    pub(crate) fn cancel(&mut self) {
        let _ = self.fail::<()>(ExchangeError::Cancelled);
    }

    /// Prepare each phase once. This never means that a transfer started.
    /// Only a validated set echo enables preparation of the following query;
    /// there is no cached-value shortcut, retry or replacement deadline.
    pub(crate) fn prepare_next(
        &mut self,
        now: Instant,
    ) -> Result<Vec<I2cTransactionStep>, ExchangeError> {
        let earliest = self
            .state
            .set_reply
            .as_ref()
            .map_or(self.state.created_at, |reply| reply.received_at);
        if now < earliest {
            return self.fail(ExchangeError::Chronology);
        }
        let delay = Duration::from_millis(wire::APW_READ_DELAY_MS);
        if now
            .checked_add(delay)
            .is_none_or(|end| end >= self.state.deadline)
        {
            return self.fail(ExchangeError::Deadline);
        }
        let (opcode, parameters, next) = match self.state.phase {
            Phase::ReadySet => (
                SET_OPCODE,
                self.state.expected_code.as_slice(),
                Phase::SetPrepared,
            ),
            Phase::SetAcknowledged => (wire::OP_READ_STATUS_0X03, &[][..], Phase::ReadbackPrepared),
            _ => return self.fail(ExchangeError::UnexpectedPhase),
        };
        let frame = match wire::build_request(opcode, parameters) {
            Ok(frame) => frame,
            Err(_) => return self.fail(ExchangeError::InvalidRequest),
        };
        if next == Phase::SetPrepared {
            self.state.set_prepared_at = Some(now);
        } else {
            self.state.readback_prepared_at = Some(now);
        }
        self.state.phase = next;
        Ok(vec![
            I2cTransactionStep::Write(frame),
            I2cTransactionStep::SleepMs(wire::APW_READ_DELAY_MS),
            I2cTransactionStep::Read(REPLY_BYTES),
        ])
    }

    /// Feed one synchronous caller result. Caller/service ownership is outside
    /// this detached protocol object. Raw observations are retained before
    /// deadline/shape checks, but a late result cannot enable another phase.
    pub(crate) fn accept_reply(
        &mut self,
        now: Instant,
        returned: Result<Vec<Vec<u8>>, String>,
    ) -> Result<Phase, ExchangeError> {
        let phase = self.state.phase;
        if !matches!(phase, Phase::SetPrepared | Phase::ReadbackPrepared) {
            return self.fail(ExchangeError::UnexpectedPhase);
        }
        let prepared_at = if phase == Phase::SetPrepared {
            self.state.set_prepared_at
        } else {
            self.state.readback_prepared_at
        }
        .expect("prepared phase has its original preparation time");
        let observation = match returned {
            Ok(records) => ReplyObservation {
                received_at: now,
                records: Some(records),
                transport_error: None,
            },
            Err(error) => ReplyObservation {
                received_at: now,
                records: None,
                transport_error: Some(error),
            },
        };
        let transport_returned_records = observation.records.is_some();
        let decoded = Self::decode(
            &observation,
            if phase == Phase::SetPrepared {
                SET_OPCODE
            } else {
                wire::OP_READ_STATUS_0X03
            },
            self.state.expected_code,
        );
        if phase == Phase::SetPrepared {
            self.state.set_reply = Some(observation);
        } else {
            self.state.readback_reply = Some(observation);
        }
        if now >= self.state.deadline {
            return self.fail(ExchangeError::Deadline);
        }
        // A failed write/transfer may return immediately. Only returned
        // records are subject to the fixed reply delay; an Err must retain
        // its transport classification. Backwards timestamps remain invalid.
        if now < prepared_at
            || (transport_returned_records
                && prepared_at
                    .checked_add(Duration::from_millis(wire::APW_READ_DELAY_MS))
                    .is_none_or(|earliest| now < earliest))
        {
            return self.fail(ExchangeError::Chronology);
        }
        let code = match decoded {
            Ok(code) => code,
            Err(error) => return self.fail(error),
        };
        if phase == Phase::SetPrepared {
            self.state.phase = Phase::SetAcknowledged;
        } else {
            self.state.reported_millivolts = Some(code.reported_millivolts());
            self.state.protocol_completed_at = Some(now);
            self.state.phase = Phase::Complete;
        }
        Ok(self.state.phase)
    }

    fn decode(
        observation: &ReplyObservation,
        opcode: u8,
        expected: [u8; 2],
    ) -> Result<Apw76VoltageCode, ExchangeError> {
        let records = observation
            .records
            .as_ref()
            .ok_or(ExchangeError::Transport)?;
        if records.len() != 1 || records[0].len() != REPLY_BYTES {
            return Err(ExchangeError::ReplyShape);
        }
        let reply = wire::parse_response(&records[0]).map_err(|_| ExchangeError::ReplyProtocol)?;
        if reply.opcode_echo != opcode {
            return Err(ExchangeError::WrongOpcode);
        }
        if reply.data.as_slice() != expected {
            return Err(ExchangeError::WrongCode);
        }
        Apw76VoltageCode::from_reply(&reply.data).map_err(|_| ExchangeError::WrongCode)
    }
}

#[cfg(test)]
#[path = "bb_apw_voltage_exchange_tests.rs"]
mod tests;
