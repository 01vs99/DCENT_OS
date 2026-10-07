//! Pure BB PIC3A rail observations from the retained `a lab unit` LuxOS ARM source.
//!
//! `bb-pic-rail-acquisition-replay-v1.json` in the September 7 beta campaign
//! executes the original request, seven read-result folds and VFP conversion.
//! The original worker extracts bytes3/4 without checking the other five bytes.
//! This decoder preserves that limitation: an observation is neither a framed
//! response authentication nor a voltage-control admission. There is no I/O,
//! actuator command, calibration adjustment or cross-controller fallback here.

/// Original worker4a49ec..4a4a08: PIC read-voltage request, additive checksum.
pub const READ_REQUEST: [u8; 6] = [0x55, 0xaa, 0x04, 0x3a, 0x00, 0x3e];
/// Original worker4a4f84..4a65c8: one50ms wait, seven reads each followed by20ms.
pub const RESPONSE_BYTES: usize = 7;
pub const BEFORE_READ_MS: u64 = 50;
pub const AFTER_EACH_READ_MS: u64 = 20;

/// Fixed query plan for the existing sole I2C service owner. The final20ms
/// wait belongs to the original acquisition too; it is not merely an interval
/// between reads. Constructing this plan performs no I/O.
pub fn read_steps() -> Vec<crate::i2c::I2cTransactionStep> {
    use crate::i2c::I2cTransactionStep;
    let mut steps = Vec::with_capacity(2 + RESPONSE_BYTES * 2);
    steps.push(I2cTransactionStep::Write(READ_REQUEST.to_vec()));
    steps.push(I2cTransactionStep::SleepMs(BEFORE_READ_MS));
    for _ in 0..RESPONSE_BYTES {
        steps.push(I2cTransactionStep::Read(1));
        steps.push(I2cTransactionStep::SleepMs(AFTER_EACH_READ_MS));
    }
    steps
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("BB PIC rail observation requires exactly7 bytes, received {actual}")]
pub struct IncompleteReply {
    pub actual: usize,
}

/// Complete raw observation with the original uncalibrated ADC conversion.
///
/// Fields are private so raw bytes and derived values cannot disagree. No
/// assumption about an electrically valid ADC range or measured rail tolerance
/// is inferred from the source's16-bit extraction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BbPicRailObservation {
    reply: [u8; RESPONSE_BYTES],
    raw_adc: u16,
    voltage_v: f64,
}

impl BbPicRailObservation {
    pub fn from_complete_reply(reply: &[u8]) -> Result<Self, IncompleteReply> {
        let reply: [u8; RESPONSE_BYTES] = reply.try_into().map_err(|_| IncompleteReply {
            actual: reply.len(),
        })?;
        let raw_adc = u16::from_be_bytes([reply[3], reply[4]]);
        // Original loads49ef00/0c/10/24/28 and arithmetic4a6570..4a65c8:
        // preserve individual f64 operations and truncation toward zero.
        // The source has no AML `raw*0.02448-0.35` calibration offset.
        let adc_v = f64::from(raw_adc) * 3.3;
        let divided_v = adc_v * (1.0 / 1024.0);
        let rail_v = divided_v * 7.55;
        let voltage_v = (rail_v * 1000.0).trunc() / 1000.0;
        Ok(Self {
            reply,
            raw_adc,
            voltage_v,
        })
    }

    pub fn reply(&self) -> &[u8; RESPONSE_BYTES] {
        &self.reply
    }

    pub fn raw_adc(&self) -> u16 {
        self.raw_adc
    }

    pub fn voltage_v(&self) -> f64 {
        self.voltage_v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_query_plan_matches_original_request_and_all_eight_waits() {
        use crate::i2c::I2cTransactionStep;
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("bb_pic_rail_vectors.json")).unwrap();
        let steps = read_steps();
        assert_eq!(steps.len(), 16);
        let mut sleeps = Vec::new();
        let mut reads = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            match step {
                I2cTransactionStep::Write(data) => {
                    assert_eq!(index, 0);
                    let hex: String = data.iter().map(|byte| format!("{byte:02x}")).collect();
                    assert_eq!(hex, vectors["request_hex"].as_str().unwrap());
                }
                I2cTransactionStep::Read(count) => {
                    assert_eq!(*count, 1);
                    assert_eq!(index, 2 + reads.len() * 2);
                    reads.push(reads.len() as u64);
                }
                I2cTransactionStep::SleepMs(ms) => {
                    assert_eq!(index, 1 + sleeps.len() * 2);
                    sleeps.push(ms * 1_000_000);
                }
                _ => panic!("unexpected transaction step"),
            }
        }
        assert_eq!(serde_json::json!(reads), vectors["read_indices"]);
        assert_eq!(serde_json::json!(sleeps), vectors["sleep_nanoseconds"]);
    }

    #[test]
    fn original_vfp_bits_and_byte_positions_match_twenty_retained_results() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("bb_pic_rail_vectors.json")).unwrap();
        let rows = vectors["cases"].as_array().unwrap();
        assert_eq!(rows.len(), 20);
        for row in rows {
            let encoded = row["response_hex"].as_str().unwrap();
            let reply: Vec<u8> = (0..encoded.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&encoded[at..at + 2], 16).unwrap())
                .collect();
            let observed = BbPicRailObservation::from_complete_reply(&reply).unwrap();
            assert_eq!(observed.reply().as_slice(), reply);
            assert_eq!(u64::from(observed.raw_adc()), row["raw_adc_be16"]);
            // Integer goldens preserve the original VFP bits independently of
            // JSON decimal parser rounding.
            assert_eq!(observed.voltage_v().to_bits(), row["voltage_bits"]);
        }
    }

    #[test]
    fn short_empty_and_extended_replies_never_make_an_observation() {
        for size in (0..=16).filter(|size| *size != RESPONSE_BYTES) {
            assert_eq!(
                BbPicRailObservation::from_complete_reply(&vec![0; size]),
                Err(IncompleteReply { actual: size })
            );
        }
    }

    #[test]
    fn ignored_bytes_remain_available_without_claiming_checksum_authentication() {
        let reply = [0, 0xff, 0x10, 2, 0, 0xff, 0x89];
        let observation = BbPicRailObservation::from_complete_reply(&reply).unwrap();
        assert_eq!(observation.reply(), &reply);
        assert_eq!(observation.raw_adc(), 512);
        assert_eq!(observation.voltage_v(), 12.457);
    }
}
