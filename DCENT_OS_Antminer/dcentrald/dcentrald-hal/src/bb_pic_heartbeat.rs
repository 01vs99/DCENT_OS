//! Exact BB PIC heartbeat transaction timing from the retained `a lab unit` source.
//!
//! Original worker4a339c..4a44e8 constructs55aa0416001a and reads six
//! individual bytes, with30ms before the first and after every read, including
//! the last. `bb-pic-heartbeat-replay-v1.json` retains18 original executions.
//! The source discards reply values. This transport plan does not relax the
//! daemon's separate strict framed reply/opcode/payload validation.

pub const REQUEST: [u8; 6] = [0x55, 0xaa, 0x04, 0x16, 0x00, 0x1a];
pub const RESPONSE_BYTES: usize = 6;
pub const BEFORE_READ_MS: u64 = 30;
pub const AFTER_EACH_READ_MS: u64 = 30;

/// Construct the fixed plan for the existing sole I2C service owner. The
/// caller labels this transaction KeepAlive; construction itself does no I/O.
pub fn transaction_steps() -> Vec<crate::i2c::I2cTransactionStep> {
    use crate::i2c::I2cTransactionStep;
    let mut steps = Vec::with_capacity(2 + RESPONSE_BYTES * 2);
    steps.push(I2cTransactionStep::Write(REQUEST.to_vec()));
    steps.push(I2cTransactionStep::SleepMs(BEFORE_READ_MS));
    for _ in 0..RESPONSE_BYTES {
        steps.push(I2cTransactionStep::Read(1));
        steps.push(I2cTransactionStep::SleepMs(AFTER_EACH_READ_MS));
    }
    steps
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("BB PIC heartbeat requires six complete one-byte reads")]
pub struct IncompleteReads;

/// Preserve individual transaction-result boundaries before semantic framing
/// validation. Flattening a short/extended read into a six-byte total is not
/// complete acquisition of the six source-requested reads.
pub fn complete_reply(reads: &[Vec<u8>]) -> Result<[u8; RESPONSE_BYTES], IncompleteReads> {
    if reads.len() != RESPONSE_BYTES || reads.iter().any(|read| read.len() != 1) {
        return Err(IncompleteReads);
    }
    Ok(std::array::from_fn(|index| reads[index][0]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_complete_request_and_seven_waits_match_fixed_service_plan() {
        use crate::i2c::I2cTransactionStep;
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("bb_pic_heartbeat_vectors.json")).unwrap();
        let rows = vectors["cases"].as_array().unwrap();
        assert_eq!(rows.len(), 18);
        let mut requests = Vec::new();
        let mut sleeps = Vec::new();
        let mut read_indices = Vec::new();
        for step in transaction_steps() {
            match step {
                I2cTransactionStep::Write(bytes) => {
                    assert!(requests.is_empty() && sleeps.is_empty() && read_indices.is_empty());
                    requests.push(
                        bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>(),
                    );
                }
                I2cTransactionStep::Read(count) => {
                    assert_eq!(count, 1);
                    assert_eq!(sleeps.len(), read_indices.len() + 1);
                    read_indices.push(read_indices.len());
                }
                I2cTransactionStep::SleepMs(ms) => {
                    assert_eq!(sleeps.len(), read_indices.len());
                    sleeps.push(ms * 1_000_000);
                }
                _ => panic!("unexpected heartbeat step"),
            }
        }
        for row in rows
            .iter()
            .filter(|row| row["failed_read_index"].is_null() && row["failed_send"] == false)
        {
            assert_eq!(requests[0], row["sends"][0]["frame"]);
            assert_eq!(serde_json::json!(sleeps), row["sleep_nanoseconds"]);
            let original_reads: Vec<_> = row["reads"]
                .as_array()
                .unwrap()
                .iter()
                .map(|read| read["index"].as_u64().unwrap() as usize)
                .collect();
            assert_eq!(read_indices, original_reads);
        }
        assert_eq!(sleeps.iter().sum::<u64>(), 210_000_000);
    }

    #[test]
    fn complete_acquisition_preserves_source_bytes_without_authenticating_them() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("bb_pic_heartbeat_vectors.json")).unwrap();
        for row in vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["failed_read_index"].is_null() && row["failed_send"] == false)
        {
            let reads: Vec<Vec<u8>> = row["reads"]
                .as_array()
                .unwrap()
                .iter()
                .map(|read| vec![read["value"].as_u64().unwrap() as u8])
                .collect();
            let reply = complete_reply(&reads).unwrap();
            let hex = reply
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(hex, row["response_hex"]);
        }
    }

    #[test]
    fn missing_extra_and_redistributed_read_results_are_refused() {
        for count in (0..=9).filter(|count| *count != RESPONSE_BYTES) {
            assert_eq!(complete_reply(&vec![vec![0]; count]), Err(IncompleteReads));
        }
        for index in 0..RESPONSE_BYTES {
            for length in [0, 2, 3] {
                let mut reads = vec![vec![0]; RESPONSE_BYTES];
                reads[index] = vec![0; length];
                assert_eq!(complete_reply(&reads), Err(IncompleteReads));
            }
            let mut redistributed = vec![vec![0]; RESPONSE_BYTES];
            redistributed[index] = vec![0, 0];
            redistributed[(index + 1) % RESPONSE_BYTES].clear();
            assert_eq!(
                redistributed.iter().map(Vec::len).sum::<usize>(),
                RESPONSE_BYTES
            );
            assert_eq!(complete_reply(&redistributed), Err(IncompleteReads));
        }
    }
}
