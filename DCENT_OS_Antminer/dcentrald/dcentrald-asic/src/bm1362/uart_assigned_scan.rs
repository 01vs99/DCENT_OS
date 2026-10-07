//! Assigned-address bytes collected through the original exclusive cold UART.
//! Neither a complete window nor exact expected coverage proves population,
//! freshness, causal response to this query, ASIC idle or electrical readiness.
use super::*;
use crate::bm1362::assigned_address::{
    assess_assigned_address_scan, AssignedAddressCoverage, AssignedAddressScanReport,
    ASSIGNED_ADDRESS_RESPONSE_BYTES,
};
use std::collections::BTreeSet;

const MAX_RAW: usize = (u8::MAX as usize) * ASSIGNED_ADDRESS_RESPONSE_BYTES;
const MAX_READS: usize = 512;
const SETTLE_MS: u32 = 50;
const WINDOW_MS: u64 = 300;

#[derive(Clone, Debug)]
pub(crate) struct AssignedScanObservation {
    /// Input assumption retained in its original order, not inferred from RX.
    pub expected_addresses: Vec<u8>,
    pub window_started_at: Option<Instant>,
    pub window_deadline: Option<Instant>,
    pub window_completed_at: Option<Instant>,
    /// Actual collection return, including failure during settle or reads.
    pub collection_returned_at: Option<Instant>,
    pub raw: Vec<u8>,
    pub reads: Vec<RawReadAttempt>,
    /// Assessment of all retained bytes, including a trailing incomplete frame.
    /// Available after collection returns even if it failed or was cancelled.
    /// ExactExpectedSet here does not complete the enclosing cold attempt.
    pub report: Option<AssignedAddressScanReport>,
}

impl AssignedScanObservation {
    pub(super) fn new(expected_addresses: Vec<u8>) -> Self {
        Self {
            expected_addresses,
            window_started_at: None,
            window_deadline: None,
            window_completed_at: None,
            collection_returned_at: None,
            raw: Vec::new(),
            reads: Vec::new(),
            report: None,
        }
    }
}

pub(super) fn validate_expected(expected: &[u8]) -> Result<(), String> {
    if expected.is_empty() || expected.len() > usize::from(u8::MAX) {
        return Err("assigned scan requires 1..=255 expected addresses".into());
    }
    if expected.iter().copied().collect::<BTreeSet<_>>().len() != expected.len() {
        return Err("assigned scan expected addresses contain duplicates".into());
    }
    Ok(())
}

pub(super) fn collect(
    uart: &mut SerialUart,
    stop: &DispatchStop,
    deadline: Instant,
    output: &mut ColdControlAttempt,
) -> Result<(), String> {
    let record = output
        .assigned_scan
        .as_mut()
        .expect("validated expected addresses reserved before query write");
    let result = (|| -> Result<(), String> {
        wait(stop, deadline, SETTLE_MS, &mut output.delays)?;
        let started = Instant::now();
        let end = started + Duration::from_millis(WINDOW_MS);
        record.window_started_at = Some(started);
        record.window_deadline = Some(end);
        while Instant::now() < end {
            check(stop, deadline)?;
            if record.reads.len() == MAX_READS {
                return Err("assigned scan raw caller read bound reached".into());
            }
            // One overflow byte is retained. Never silently truncate a full
            // maximum-size response or consume the rest by flushing the UART.
            let capacity = (MAX_RAW + 1 - record.raw.len()).min(256);
            let mut bytes = vec![0; capacity];
            let attempt = uart
                .backend
                .read_raw_once_bounded(&mut bytes, deadline, &|| {
                    stop.snapshot().permanently_stopped
                });
            record.raw.extend_from_slice(&attempt.bytes);
            let complete = attempt.status.caller_completed_at.is_some()
                && attempt.status.failure.is_none()
                && attempt.status.restore_error.is_none();
            let empty = attempt.returned_count == Some(0);
            // Retain actual bytes and the exact raw return before considering
            // cancellation, deadline or flag-restoration failure.
            record.reads.push(attempt);
            if !complete {
                return Err("assigned scan raw read failed, stopped or expired".into());
            }
            if record.raw.len() > MAX_RAW {
                return Err("assigned scan raw response bound exceeded".into());
            }
            if empty {
                std::thread::sleep(
                    Duration::from_millis(1)
                        .min(end.saturating_duration_since(Instant::now()))
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
        check(stop, deadline)?;
        record.window_completed_at = Some(Instant::now());
        Ok(())
    })();
    // chunks, not chunks_exact: malformed preambles and trailing bytes remain
    // explicit strict-parser rejections; no scanning/resynchronization drops RX.
    let report = assess_assigned_address_scan(
        record.raw.chunks(ASSIGNED_ADDRESS_RESPONSE_BYTES),
        &record.expected_addresses,
    );
    let exact = report.coverage == AssignedAddressCoverage::ExactExpectedSet;
    record.report = Some(report);
    record.collection_returned_at = Some(Instant::now());
    result?;
    if !exact {
        return Err(
            "assigned scan window does not contain exactly the expected address set".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "uart_assigned_scan_tests.rs"]
mod tests;
