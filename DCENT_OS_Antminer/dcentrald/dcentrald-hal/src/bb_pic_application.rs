//! Existing native BB fw89 application query, shared with selected inventory.
//!
//! The135ms initial/four20ms inter-read waits are the existing native query
//! schedule, not the donor's different post-RESET entry schedule. This query
//! never authorizes RESET, JUMP, voltage, controller startup or physical work.

use crate::i2c::I2cTransactionStep;
use dcentrald_api_types::dspic_frame::{decode_framed_sum_reply_body, DspicOpcode};

pub const REQUEST: [u8; 6] = [0x55, 0xaa, 0x04, 0x17, 0x00, 0x1b];
pub const RESPONSE_BYTES: usize = 5;

/// The configured native inventory currently has three PIC endpoint slots.
/// This is not the original worker's wider queue-message discriminator range.
pub fn native_pic_address(chain: usize) -> Option<u8> {
    (chain < 3).then(|| 0x20 + chain as u8)
}

pub fn transaction_steps() -> Vec<I2cTransactionStep> {
    let mut steps = vec![
        I2cTransactionStep::Write(REQUEST.to_vec()),
        I2cTransactionStep::SleepMs(135),
    ];
    for index in 0..RESPONSE_BYTES {
        steps.push(I2cTransactionStep::Read(1));
        if index + 1 < RESPONSE_BYTES {
            steps.push(I2cTransactionStep::SleepMs(20));
        }
    }
    steps
}

#[derive(Debug, thiserror::Error)]
pub enum ApplicationReplyError {
    #[error("application query requires five complete one-byte reads")]
    Incomplete,
    #[error("invalid application version frame: {0}")]
    Malformed(String),
    #[error("an already-running framed fw89 application is required; controller recovery is unavailable in the mining daemon")]
    ForeignApplication,
}

/// Preserve the individual five-read shape before shared framed validation.
/// Callers retain available raw transaction results separately on refusal.
pub fn complete_reply(reads: &[Vec<u8>]) -> Result<[u8; RESPONSE_BYTES], ApplicationReplyError> {
    if reads.len() != RESPONSE_BYTES || reads.iter().any(|read| read.len() != 1) {
        return Err(ApplicationReplyError::Incomplete);
    }
    let reply = std::array::from_fn(|index| reads[index][0]);
    let frame = decode_framed_sum_reply_body(&reply)
        .map_err(|error| ApplicationReplyError::Malformed(format!("{error:?}")))?;
    if frame.opcode != DspicOpcode::GetVersion || frame.payload.as_slice() != [0x89, 0x00] {
        return Err(ApplicationReplyError::ForeignApplication);
    }
    Ok(reply)
}
