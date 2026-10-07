//! Bounded admission and optional capacity-derived pool hints.
//!
//! These checks establish transaction structure, not full block validity.

use std::time::{Duration, Instant};

/// An expected capacity snapshot published by the runtime after chain admission.
/// This is not measured hashrate or proof of accepted pool work. A withdrawn
/// snapshot stops hints; it does not itself authorize or stop hardware.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ActiveCapacity {
    pub hashes_per_second: f64,
}

impl ActiveCapacity {
    pub fn new(hashes_per_second: f64) -> Option<Self> {
        (hashes_per_second.is_finite() && hashes_per_second >= 0.0)
            .then_some(Self { hashes_per_second })
    }
}

/// One suggestion per interval, with hysteresis against our own last hint.
/// Pool `set_difficulty` messages never enter this policy.
#[derive(Debug, Default)]
pub(crate) struct DifficultyHints {
    last: Option<u64>,
    sent_at: Option<Instant>,
}

impl DifficultyHints {
    pub(crate) const INTERVAL: Duration = Duration::from_secs(5);

    pub(crate) fn candidate(&self, capacity: ActiveCapacity, now: Instant) -> Option<u64> {
        if !capacity.hashes_per_second.is_finite() || capacity.hashes_per_second <= 0.0 {
            return None;
        }
        // Three seconds of expected work, in difficulty-one units. Integer
        // hints retain the existing ASIC protocol contract and avoid zero.
        let value =
            (capacity.hashes_per_second * 3.0 / 4_294_967_296.0).clamp(1.0, u32::MAX as f64) as u64;
        let material = self.last.is_none_or(|last| {
            value as f64 <= last as f64 * 0.8 || value as f64 >= last as f64 * 1.5
        });
        let cooled = self
            .sent_at
            .is_none_or(|sent| now.saturating_duration_since(sent) >= Self::INTERVAL);
        (material && cooled).then_some(value)
    }

    pub(crate) fn sent(&mut self, value: u64, now: Instant) {
        self.last = Some(value);
        self.sent_at = Some(now);
    }
}

const MAX_COINBASE_BYTES: usize = 1_000_000;

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or("coinbase length overflow")?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated coinbase")?;
        self.offset = end;
        Ok(bytes)
    }

    fn compact_size(&mut self) -> Result<usize, &'static str> {
        let tag = self.take(1)?[0];
        let value = match tag {
            0..=252 => u64::from(tag),
            253 => u64::from(u16::from_le_bytes(
                self.take(2)?.try_into().map_err(|_| "compact size")?,
            )),
            254 => u64::from(u32::from_le_bytes(
                self.take(4)?.try_into().map_err(|_| "compact size")?,
            )),
            255 => u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| "compact size")?),
        };
        if (tag == 253 && value < 253)
            || (tag == 254 && value <= u16::MAX as u64)
            || (tag == 255 && value <= u32::MAX as u64)
        {
            return Err("non-canonical compact size");
        }
        usize::try_from(value).map_err(|_| "compact size overflow")
    }
}

/// Validate a non-witness coinbase serialization and ensure both extranonces
/// fall wholly inside its scriptSig. V1 hashes these bytes directly as a txid;
/// witness serialization would require a different hashing path and is refused.
/// Work and allocation are bounded by the byte budget, including output loops.
pub(crate) fn validate_coinbase(
    prefix: &[u8],
    extranonce1: &[u8],
    extranonce2_size: usize,
    suffix: &[u8],
) -> Result<(), &'static str> {
    let size = prefix
        .len()
        .checked_add(extranonce1.len())
        .and_then(|n| n.checked_add(extranonce2_size))
        .and_then(|n| n.checked_add(suffix.len()))
        .ok_or("coinbase length overflow")?;
    if size > MAX_COINBASE_BYTES || !(1..=8).contains(&extranonce2_size) {
        return Err("coinbase exceeds bounds");
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(extranonce1);
    bytes.resize(bytes.len() + extranonce2_size, 0);
    let splice_end = bytes.len();
    bytes.extend_from_slice(suffix);
    let mut cursor = Cursor {
        bytes: &bytes,
        offset: 0,
    };
    cursor.take(4)?;
    if cursor.compact_size()? != 1 {
        return Err("coinbase must have one non-witness input");
    }
    if cursor.take(32)?.iter().any(|byte| *byte != 0) || cursor.take(4)? != [0xff; 4] {
        return Err("coinbase input is not null");
    }
    let script_len = cursor.compact_size()?;
    if !(2..=100).contains(&script_len) {
        return Err("coinbase scriptSig length outside 2..100");
    }
    let script_start = cursor.offset;
    cursor.take(script_len)?;
    if prefix.len() < script_start || splice_end > cursor.offset {
        return Err("extranonce splice escapes coinbase scriptSig");
    }
    cursor.take(4)?;
    let outputs = cursor.compact_size()?;
    if outputs == 0 || outputs > bytes.len().saturating_sub(cursor.offset) / 9 {
        return Err("coinbase output count exceeds remaining bytes");
    }
    for _ in 0..outputs {
        cursor.take(8)?;
        let script_len = cursor.compact_size()?;
        cursor.take(script_len)?;
    }
    cursor.take(4)?;
    if cursor.offset != bytes.len() {
        return Err("trailing coinbase bytes");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn fixture_coinbase(extranonce_bytes: usize) -> (String, String) {
    // One input; extranonces occupy scriptSig; one zero-valued OP_TRUE output.
    (
        format!(
            "0100000001{}ffffffff{:02x}",
            "00".repeat(32),
            extranonce_bytes
        ),
        "ffffffff010000000000000000015100000000".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_admission_checks_structure_and_splice() {
        for width in 1..=8 {
            let (prefix, suffix) = fixture_coinbase(4 + width);
            assert_eq!(
                validate_coinbase(
                    &hex::decode(&prefix).unwrap(),
                    &[0; 4],
                    width,
                    &hex::decode(&suffix).unwrap()
                ),
                Ok(())
            );
        }
        assert!(validate_coinbase(&[0xaa], &[0; 4], 4, &[0xbb]).is_err());
        let (prefix, suffix) = fixture_coinbase(8);
        let prefix = hex::decode(prefix).unwrap();
        let mut suffix = hex::decode(suffix).unwrap();
        suffix.push(0);
        assert!(validate_coinbase(&prefix, &[0; 4], 4, &suffix).is_err());
        assert!(validate_coinbase(&prefix, &[0; 4], 8, &suffix).is_err());
        // Noncanonical or enormous lengths must fail before allocation/loops.
        let mut noncanonical = vec![0xff; 4];
        noncanonical.extend_from_slice(&[0xfd, 1, 0]);
        noncanonical.extend_from_slice(&suffix[5..]);
        assert!(validate_coinbase(&prefix, &[0; 4], 4, &noncanonical).is_err());
        let mut enormous = vec![0xff; 13];
        enormous.extend_from_slice(&suffix[5..]);
        assert!(validate_coinbase(&prefix, &[0; 4], 4, &enormous).is_err());
        let mut outside_script = prefix.clone();
        *outside_script.last_mut().unwrap() = 2;
        assert!(validate_coinbase(&outside_script, &[0; 4], 4, &suffix).is_err());
        // A larger ordinary payout script remains admissible with canonical
        // CompactSize encoding; the validator isn't a narrow pool template.
        let mut large_output = vec![0xff; 4];
        large_output.push(1);
        large_output.extend_from_slice(&[0; 8]);
        large_output.extend_from_slice(&[0xfd, 0xfd, 0]);
        large_output.extend_from_slice(&[0; 253]);
        large_output.extend_from_slice(&[0; 4]);
        assert_eq!(
            validate_coinbase(&prefix, &[0; 4], 4, &large_output),
            Ok(())
        );
    }

    #[test]
    fn hints_coalesce_capacity_changes_and_respect_hysteresis() {
        let now = Instant::now();
        let mut hints = DifficultyHints::default();
        let capacity = |h| ActiveCapacity::new(h).unwrap();
        let first = hints.candidate(capacity(1e12), now).unwrap();
        hints.sent(first, now);
        assert!(hints.candidate(capacity(0.5e12), now).is_none());
        assert!(hints
            .candidate(capacity(1.1e12), now + Duration::from_secs(5))
            .is_none());
        assert!(hints
            .candidate(capacity(0.5e12), now + Duration::from_secs(5))
            .is_some());
        assert!(hints
            .candidate(capacity(0.0), now + Duration::from_secs(5))
            .is_none());
        assert!(ActiveCapacity::new(f64::NAN).is_none());
    }
}
