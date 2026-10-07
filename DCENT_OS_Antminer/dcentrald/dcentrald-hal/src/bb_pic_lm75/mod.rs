//! Pure BB LM75 bridge bytes and the two retained query schedules.
//!
//! This preserves the existing native status/checksum/raw/range policy. It
//! tightens transaction acceptance to exactly seven separate one-byte reads.
//! Descriptor byte 2 is checksum-covered but has no admitted status or sensor
//! identity meaning. No sensor echo is inferred from a reply.
//!
//! A decoded value is checked data only: no acquisition time, freshness,
//! selected-chain identity, physical sensor truth or startup authority is
//! created here. The enclosing owner must retain actual available reads on
//! service failure, cancellation and late completion as well as parser refusal.

use crate::i2c::I2cTransactionStep;

pub const SENSOR_ADDRESSES: [u8; 4] = [0x48, 0x49, 0x4a, 0x4b];
pub const RESPONSE_BYTES: usize = 7;
pub const MIN_VALID_C: f32 = -20.0;
pub const MAX_VALID_C: f32 = 125.0;

/// The four source-selected bridge requests. This does not prove a sensor is
/// present or associate any subsequently received bytes with that sensor.
pub fn request(sensor_address: u8) -> Option<[u8; 8]> {
    SENSOR_ADDRESSES.contains(&sensor_address).then(|| {
        let checksum = 0x06u8
            .wrapping_add(0x3c)
            .wrapping_add(sensor_address)
            .wrapping_add(0x02);
        [0x55, 0xaa, 0x06, 0x3c, sensor_address, 0x02, 0x00, checksum]
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryCadence {
    /// Existing daemon: initial 20ms and six inter-read 20ms waits.
    ExistingRuntime,
    /// Original optional initializer: initial 20ms and 20ms after all seven
    /// reads. Its separate 50ms transition after the fourth query is outside
    /// this single-query plan and remains an enclosing caller obligation.
    OriginalStartup,
}

/// Exact byte/read/sleep description only; this does not submit an operation.
/// Callers must use the established sole service and its fixed QueryPrelude
/// classification, selected endpoint and absolute deadline.
pub fn transaction_steps(
    sensor_address: u8,
    cadence: QueryCadence,
) -> Option<Vec<I2cTransactionStep>> {
    let frame = request(sensor_address)?;
    let mut steps = vec![
        I2cTransactionStep::Write(frame.to_vec()),
        I2cTransactionStep::SleepMs(20),
    ];
    for index in 0..RESPONSE_BYTES {
        steps.push(I2cTransactionStep::Read(1));
        if index + 1 < RESPONSE_BYTES || cadence == QueryCadence::OriginalStartup {
            steps.push(I2cTransactionStep::SleepMs(20));
        }
    }
    Some(steps)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyError {
    Length { actual: usize },
    ReadShape,
    Header,
    Status { actual: u8 },
    Checksum,
    LowNibble,
    Range { signed_raw: i16 },
}

/// An immutable checked reply. Private bytes prevent construction without
/// validation; they provide no hardware admission capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    raw: [u8; RESPONSE_BYTES],
}

impl Sample {
    pub fn raw(&self) -> &[u8; RESPONSE_BYTES] {
        &self.raw
    }

    pub fn temperature_c(&self) -> f32 {
        i16::from_be_bytes([self.raw[3], self.raw[4]]) as f32 / 256.0
    }
}

/// Validate an exact raw frame. The existing daemon accepts at least seven
/// bytes; this extraction intentionally refuses surplus bytes rather than
/// silently using a prefix. No existing daemon behavior is changed by a draft.
pub fn decode_reply(reply: &[u8]) -> Result<Sample, ReplyError> {
    let raw: [u8; RESPONSE_BYTES] = reply.try_into().map_err(|_| ReplyError::Length {
        actual: reply.len(),
    })?;
    if raw[0] != 0x07 || raw[1] != 0x3c {
        return Err(ReplyError::Header);
    }
    // Captured status byte 5 dominates the superficially plausible temperature
    // words. Byte 2 remains unrestricted, including values other than one.
    if raw[5] != 0 {
        return Err(ReplyError::Status { actual: raw[5] });
    }
    // Keep the native sum over bytes 0..5. With the required zero status this
    // equals the observed device checksum, which excludes status byte 5.
    if raw[..6]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
        != raw[6]
    {
        return Err(ReplyError::Checksum);
    }
    let signed_raw = i16::from_be_bytes([raw[3], raw[4]]);
    if signed_raw & 0x000f != 0 {
        return Err(ReplyError::LowNibble);
    }
    let temperature_c = signed_raw as f32 / 256.0;
    if !(MIN_VALID_C..=MAX_VALID_C).contains(&temperature_c) {
        return Err(ReplyError::Range { signed_raw });
    }
    Ok(Sample { raw })
}

/// Require the actual seven one-byte result records; flattening first would
/// erase short, redistributed or excess reads. The caller retains `reads`.
pub fn complete_reply(reads: &[Vec<u8>]) -> Result<Sample, ReplyError> {
    if reads.len() != RESPONSE_BYTES || reads.iter().any(|read| read.len() != 1) {
        return Err(ReplyError::ReadShape);
    }
    decode_reply(&std::array::from_fn::<_, RESPONSE_BYTES, _>(|index| {
        reads[index][0]
    }))
}

/// Diagnostic ownership of already-available result bytes, including malformed
/// shapes. Moving a result here makes no service join, cancellation, freshness
/// or physical measurement claim. A future owner must also retain service
/// errors and lifecycle observations; this value cannot replace them.
#[derive(Debug)]
pub struct ReplyObservation {
    reads: Vec<Vec<u8>>,
    decoded: Result<Sample, ReplyError>,
}

impl ReplyObservation {
    pub fn from_reads(reads: Vec<Vec<u8>>) -> Self {
        let decoded = complete_reply(&reads);
        Self { reads, decoded }
    }

    pub fn reads(&self) -> &[Vec<u8>] {
        &self.reads
    }

    pub fn decoded(&self) -> Result<&Sample, &ReplyError> {
        self.decoded.as_ref()
    }
}

#[cfg(test)]
#[path = "bb_pic_lm75_tests.rs"]
mod tests;
