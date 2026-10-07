//! Detached fixed APW121215f diagnostic sequence for the retained BB bus-1
//! owner. No GPIO, watchdog control, voltage setter or operating authority.
//!
//! Existing native delays (500ms / calibration1200ms) and strict framing come
//! from psu_apw_uart_tunnel.rs and the held .79 replies. The optional source
//! initializer's shorter cadence is not substituted for this native policy.
//! QueryPrelude requests remain normal-lane mutations even for observations.

use crate::i2c::I2cTransactionStep;
use crate::psu_apw_uart_tunnel as wire;
use std::time::Instant;

pub(crate) const ADDRESS: u8 = wire::APW_UART_TUNNEL_I2C_ADDR;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Query {
    Hardware,
    Firmware,
    Calibration,
    Dac,
}

impl Query {
    pub(crate) fn opcode(self) -> u8 {
        match self {
            Self::Hardware => wire::OP_READ_HW_TYPE,
            Self::Firmware => wire::OP_READ_FW_VERSION,
            Self::Calibration => wire::OP_READ_CAL_BLOCK,
            Self::Dac => wire::OP_READ_STATUS_0X03,
        }
    }

    pub(crate) fn read_len(self) -> usize {
        match self {
            Self::Hardware | Self::Firmware => 8,
            Self::Calibration => 40,
            Self::Dac => 10,
        }
    }

    pub(crate) fn steps(self) -> crate::Result<Vec<I2cTransactionStep>> {
        let params: &[u8] = if self == Self::Calibration {
            &wire::CAL_BLOCK_PARAMS
        } else {
            &[]
        };
        Ok(vec![
            I2cTransactionStep::Write(wire::build_request(self.opcode(), params)?),
            I2cTransactionStep::SleepMs(if self == Self::Calibration {
                wire::APW_CAL_READ_DELAY_MS
            } else {
                wire::APW_READ_DELAY_MS
            }),
            I2cTransactionStep::Read(self.read_len()),
        ])
    }

    pub(crate) fn decode(self, reads: &[Vec<u8>]) -> Result<Field, String> {
        if reads.len() != 1 || reads[0].len() != self.read_len() {
            return Err("APW diagnostic requires its exact single reply record".into());
        }
        let reply = wire::parse_response(&reads[0]).map_err(|error| error.to_string())?;
        if reply.opcode_echo != self.opcode() {
            return Err("APW diagnostic opcode echo differs".into());
        }
        match self {
            Self::Hardware if reply.data.as_slice() == [wire::EXPECTED_HW_TYPE, 0] => {
                Ok(Field::Hardware(wire::EXPECTED_HW_TYPE))
            }
            Self::Firmware if reply.data.as_slice() == [wire::EXPECTED_FW_VERSION, 0] => {
                Ok(Field::Firmware(wire::EXPECTED_FW_VERSION))
            }
            Self::Calibration
                if reply.data.len() == 33 && reply.data[0] == wire::CAL_BLOCK_PARAMS[0] =>
            {
                let mut raw = [0; 32];
                raw.copy_from_slice(&reply.data[1..]);
                Ok(Field::Calibration(raw))
            }
            Self::Dac if reply.data.len() == 2 => {
                let raw = u16::from_le_bytes([reply.data[0], reply.data[1]]);
                let millivolts = wire::Apw76VoltageCode::from_reply(&reply.data)
                    .ok()
                    .map(wire::Apw76VoltageCode::reported_millivolts);
                Ok(Field::Dac { raw, millivolts })
            }
            _ => Err("APW diagnostic exact identity or field shape refused".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Field {
    Hardware(u8),
    Firmware(u8),
    /// Raw block bytes; all-FF does not establish a valid calibration table.
    Calibration([u8; 32]),
    /// Preserve the full reported word even when its high byte prevents the
    /// current one-byte HW76 numerical conversion. Neither value is rail truth.
    Dac {
        raw: u16,
        millivolts: Option<u16>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct QueryAttempt {
    pub query: Query,
    pub prepared_at: Instant,
    pub returned_at: Instant,
    /// Only actual returned records. An Err cannot recover the worker's
    /// unavailable internal partial or late bytes.
    pub returned_reads: Option<Vec<Vec<u8>>>,
    pub decoded: Result<Field, String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProfileAttempt {
    pub deadline: Instant,
    pub queries: Vec<QueryAttempt>,
    pub stopped_at: Option<Instant>,
    pub failure: Option<String>,
    /// Means only that this blocking caller decoded all four ordered replies
    /// before its deadline. The enclosing async owner must still observe its
    /// real caller-task join, and separately retain/close the actual service.
    pub caller_completed_at: Option<Instant>,
}

impl ProfileAttempt {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            queries: Vec::new(),
            stopped_at: None,
            failure: None,
            caller_completed_at: None,
        }
    }

    pub(crate) fn stop(&mut self, reason: impl Into<String>) {
        self.stopped_at.get_or_insert_with(Instant::now);
        self.failure.get_or_insert_with(|| reason.into());
        self.caller_completed_at = None;
    }
}

#[cfg(test)]
#[path = "bb_apw_diagnostics_tests.rs"]
mod tests;
