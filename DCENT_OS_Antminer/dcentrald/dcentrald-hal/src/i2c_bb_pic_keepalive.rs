//! Fixed native BB KeepAlive through the original bus0 service.
//!
//! Request and seven 30 ms waits come from bb_pic_heartbeat's retained complete
//! worker replays. Strict framing/opcode/payload policy is the existing daemon
//! am3_bb_validate_heartbeat_reply policy, not the source worker's discarded
//! reply values. No endpoint, frame, intent or timing escape is exposed.
use super::*;
use dcentrald_api_types::dspic_frame::{decode_framed_sum_reply_body, DspicOpcode};

#[derive(Clone, Debug)]
pub(crate) struct Attempt {
    pub native_slot: usize,
    pub pic_address: Option<u8>,
    pub deadline: Instant,
    pub caller_started_at: Instant,
    pub caller_returned_at: Option<Instant>,
    /// Exact available transaction results. On a transfer error the existing
    /// worker returns no partial read vector; this must remain None.
    pub returned_reads: Option<Vec<Vec<u8>>>,
    pub decoded_reply: Option<[u8; crate::bb_pic_heartbeat::RESPONSE_BYTES]>,
    pub transport_error: Option<String>,
    pub failure: Option<String>,
    /// Historical strict reply completion before the original deadline only.
    /// This is neither a worker join nor rolling health/power authority.
    pub accepted_at: Option<Instant>,
}

fn validate(reads: &[Vec<u8>]) -> std::result::Result<[u8; 6], String> {
    let reply =
        crate::bb_pic_heartbeat::complete_reply(reads).map_err(|error| error.to_string())?;
    let frame = decode_framed_sum_reply_body(&reply)
        .map_err(|error| format!("BB heartbeat framing refused: {error:?}"))?;
    if frame.opcode != DspicOpcode::Heartbeat || frame.payload.as_slice() != [1, 0, 0] {
        return Err("BB heartbeat requires exact existing .79 opcode/payload policy".into());
    }
    Ok(reply)
}

impl I2cServiceHandle {
    /// Internal synchronous caller for the enclosing retained heartbeat actor.
    /// The actor must fence both buses/UART and cut power on any failure, keep
    /// this caller's actual task, and join it before closing either service.
    /// A timeout does not cancel a started kernel transfer or prove drain.
    pub(crate) fn exchange_bb_pic_keepalive_at(&self, chain: usize, deadline: Instant) -> Attempt {
        let mut attempt = Attempt {
            native_slot: chain,
            pic_address: crate::bb_pic_application::native_pic_address(chain),
            deadline,
            caller_started_at: Instant::now(),
            caller_returned_at: None,
            returned_reads: None,
            decoded_reply: None,
            transport_error: None,
            failure: None,
            accepted_at: None,
        };
        let result = self.submit_bb_pic_keepalive_at(chain, deadline);
        attempt.caller_returned_at = Some(Instant::now());
        match result {
            Ok(reads) => {
                let decoded = validate(&reads);
                attempt.returned_reads = Some(reads);
                match decoded {
                    Ok(reply) => attempt.decoded_reply = Some(reply),
                    Err(error) => attempt.failure = Some(error),
                }
            }
            Err(error) => {
                let error = error.to_string();
                attempt.transport_error = Some(error.clone());
                attempt.failure = Some(error);
            }
        }
        let observed_at = Instant::now();
        if observed_at >= deadline {
            attempt.failure.get_or_insert_with(|| {
                "BB heartbeat original deadline elapsed before strict completion".into()
            });
        }
        if self.terminal_safe_off_is_latched() {
            attempt.failure.get_or_insert_with(|| {
                "BB heartbeat returned after original service terminal fence".into()
            });
        }
        if attempt.failure.is_none() {
            attempt.accepted_at = Some(observed_at);
        }
        attempt
    }

    fn submit_bb_pic_keepalive_at(&self, chain: usize, deadline: Instant) -> Result<Vec<Vec<u8>>> {
        let addr = crate::bb_pic_application::native_pic_address(chain).ok_or_else(|| {
            HalError::I2cEndpointRefused {
                bus: self.bus,
                addr: 0,
                detail: "BB heartbeat requires native slot0..2".into(),
            }
        })?;
        if self.bus != 0 {
            return Err(HalError::I2cEndpointRefused {
                bus: self.bus,
                addr,
                detail: "BB heartbeat requires the original bus-0 service".into(),
            });
        }
        let steps = crate::bb_pic_heartbeat::transaction_steps();
        validate_transaction_message_lengths(self.bus, addr, &steps)?;
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let request = I2cRequest::Transaction {
            addr,
            steps,
            reply_tx,
        };
        let budget = I2cRequestBudget::for_request_until(&request, deadline).ok_or_else(|| {
            HalError::I2cEndpointNotReady {
                bus: self.bus,
                addr,
                detail: "BB heartbeat original deadline elapsed before admission".into(),
            }
        })?;
        self.submit_with_intent_budget(
            addr,
            I2cMutationLabel::KeepAlive.internal_intent(),
            request,
            reply_rx,
            budget,
        )
    }
}

// The tests use the opt-in `platform::sim` framework, which exists only
// behind `sim-hal` (see Cargo.toml: no shipped binary enables it).
#[cfg(all(test, feature = "sim-hal"))]
#[path = "i2c_bb_pic_keepalive_tests.rs"]
mod tests;
