//! Seven authored groups; actual Cargo execution is pending root scheduling.
use super::*;
use serde_json::{json, Value};

fn framed(signed_raw: i16, descriptor: u8, status: u8) -> [u8; 7] {
    let [high, low] = signed_raw.to_be_bytes();
    let mut raw = [7, 0x3c, descriptor, high, low, status, 0];
    raw[6] = raw[..6].iter().copied().fold(0u8, u8::wrapping_add);
    raw
}

fn records(raw: &[u8]) -> Vec<Vec<u8>> {
    raw.iter().map(|byte| vec![*byte]).collect()
}

fn reason(result: Result<Sample, ReplyError>) -> &'static str {
    match result {
        Ok(_) => "Accepted",
        Err(ReplyError::Length { .. }) => "Length",
        Err(ReplyError::ReadShape) => "ReadShape",
        Err(ReplyError::Header) => "Header",
        Err(ReplyError::Status { .. }) => "Status",
        Err(ReplyError::Checksum) => "Checksum",
        Err(ReplyError::LowNibble) => "LowNibble",
        Err(ReplyError::Range { .. }) => "Range",
    }
}

#[test]
fn all_500_held_capture_lines_preserve_native_policy_and_complete_raw() {
    let corpus: Value = serde_json::from_str(include_str!("held-captures.json")).unwrap();
    let cases = corpus["records"].as_array().unwrap();
    assert_eq!(cases.len(), 500);
    let mut accepted = 0;
    for case in cases {
        let raw: Vec<u8> = case["raw"]
            .as_array()
            .unwrap()
            .iter()
            .map(|byte| u8::try_from(byte.as_u64().unwrap()).unwrap())
            .collect();
        let decoded = complete_reply(&records(&raw));
        assert_eq!(
            reason(decoded),
            case["expected"].as_str().unwrap(),
            "{case}"
        );
        if let Ok(sample) = decoded {
            accepted += 1;
            assert_eq!(sample.raw().as_slice(), raw);
            let expected_raw = case["expected_signed_raw"].as_i64().unwrap();
            assert_eq!(sample.temperature_c(), expected_raw as f32 / 256.0);
        }
    }
    assert_eq!(accepted, 295);
    // Individually addressable held examples, including a plausible but failed
    // status frame whose device checksum excludes that status byte.
    assert_eq!(
        decode_reply(&[7, 0x3c, 1, 0x26, 0x30, 0, 0x9a])
            .unwrap()
            .temperature_c(),
        38.1875
    );
    assert_eq!(
        decode_reply(&[7, 0x3c, 1, 0x29, 0x40, 0, 0xad])
            .unwrap()
            .temperature_c(),
        41.25
    );
    assert_eq!(
        decode_reply(&[7, 0x3c, 1, 0x25, 0xb0, 1, 0x19]),
        Err(ReplyError::Status { actual: 1 })
    );
}

#[test]
fn exact_original_frames_and_distinct_runtime_startup_read_sleep_plans() {
    let source: Value = serde_json::from_str(include_str!("startup-plans.json")).unwrap();
    for sensor in 0..=u8::MAX {
        let selected = (0x48..=0x4b).contains(&sensor);
        assert_eq!(request(sensor).is_some(), selected);
        assert_eq!(
            transaction_steps(sensor, QueryCadence::ExistingRuntime).is_some(),
            selected
        );
    }
    for bridge in source["bridges"].as_array().unwrap() {
        let sensor = bridge["sensor"].as_u64().unwrap() as u8;
        let startup = transaction_steps(sensor, QueryCadence::OriginalStartup).unwrap();
        let normalized: Vec<Value> = startup
            .iter()
            .map(|step| match step {
                I2cTransactionStep::Write(bytes) => json!({"write": bytes}),
                I2cTransactionStep::Read(size) => json!({"read": size}),
                I2cTransactionStep::SleepMs(ms) => json!({"sleep_ms": ms}),
                other => panic!("unexpected bridge operation: {other:?}"),
            })
            .collect();
        assert_eq!(normalized, *bridge["source_query_plan"].as_array().unwrap());
        let runtime = transaction_steps(sensor, QueryCadence::ExistingRuntime).unwrap();
        assert_eq!(runtime.len() + 1, startup.len());
        assert_eq!(runtime.as_slice(), &startup[..startup.len() - 1]);
        for (steps, expected_waits) in [(&runtime, 7), (&startup, 8)] {
            assert_eq!(
                steps
                    .iter()
                    .filter(|step| matches!(step, I2cTransactionStep::Read(1)))
                    .count(),
                7
            );
            assert_eq!(
                steps
                    .iter()
                    .filter(|step| matches!(step, I2cTransactionStep::SleepMs(20)))
                    .count(),
                expected_waits
            );
            assert!(!steps
                .iter()
                .any(|step| matches!(step, I2cTransactionStep::SleepMs(50))));
        }
        assert_eq!(
            bridge["separate_following_transition_ms"].as_u64().unwrap(),
            if sensor == 0x4b { 50 } else { 0 }
        );
    }
}

#[test]
fn exact_length_and_all_seven_read_positions_refuse_redistribution() {
    let raw = framed(0x2630, 1, 0);
    for size in 0..=16 {
        let mut bytes = raw.to_vec();
        bytes.resize(size, 0);
        assert_eq!(decode_reply(&bytes).is_ok(), size == 7, "length {size}");
    }
    for index in 0..7 {
        let mut short = records(&raw);
        short.remove(index);
        assert_eq!(complete_reply(&short), Err(ReplyError::ReadShape));
        for size in [0, 2] {
            let mut wrong = records(&raw);
            wrong[index].resize(size, 0);
            assert_eq!(complete_reply(&wrong), Err(ReplyError::ReadShape));
        }
        let next = (index + 1) % 7;
        let mut redistributed = records(&raw);
        redistributed[index].clear();
        redistributed[next].push(raw[index]);
        assert_eq!(redistributed.iter().map(Vec::len).sum::<usize>(), 7);
        assert_eq!(complete_reply(&redistributed), Err(ReplyError::ReadShape));
    }
    let mut excess = records(&raw);
    excess.push(Vec::new());
    assert_eq!(complete_reply(&excess), Err(ReplyError::ReadShape));
    assert_eq!(complete_reply(&[raw.to_vec()]), Err(ReplyError::ReadShape));
}

#[test]
fn valid_checksum_status_controls_and_unrestricted_descriptor_are_distinct() {
    for descriptor in 0..=u8::MAX {
        let raw = framed(0x2630, descriptor, 0);
        assert_eq!(decode_reply(&raw).unwrap().raw(), &raw);
    }
    for status in 1..=u8::MAX {
        // Full native checksum is valid; status is still an independent refusal.
        assert_eq!(
            decode_reply(&framed(0x2630, 1, status)),
            Err(ReplyError::Status { actual: status })
        );
        // Device-style checksum omits status; refusal must not depend on its
        // coincidental checksum disagreement with the native sum.
        let mut raw = framed(0x2630, 1, 0);
        raw[5] = status;
        assert_eq!(
            decode_reply(&raw),
            Err(ReplyError::Status { actual: status })
        );
    }
}

#[test]
fn all_signed_raw_words_apply_low_nibble_and_inclusive_native_range() {
    let mut accepted = 0;
    for word in i16::MIN..=i16::MAX {
        let raw = framed(word, 1, 0);
        let result = decode_reply(&raw);
        let aligned = word % 16 == 0;
        let inside = (-5120..=32000).contains(&word);
        assert_eq!(result.is_ok(), aligned && inside, "word {word}");
        if let Ok(sample) = result {
            accepted += 1;
            assert_eq!(sample.temperature_c(), f32::from(word / 16) / 16.0);
        } else if !aligned {
            assert_eq!(result, Err(ReplyError::LowNibble));
        } else {
            assert_eq!(result, Err(ReplyError::Range { signed_raw: word }));
        }
    }
    assert_eq!(accepted, 2321);
    assert_eq!(
        decode_reply(&framed(-5120, 1, 0)).unwrap().temperature_c(),
        -20.0
    );
    assert_eq!(
        decode_reply(&framed(32000, 1, 0)).unwrap().temperature_c(),
        125.0
    );
}

#[test]
fn checksum_header_and_opcode_controls_are_independently_rejected() {
    let original = framed(0x2630, 1, 0);
    for position in [0, 1] {
        for value in 0..=u8::MAX {
            let mut raw = original;
            raw[position] = value;
            raw[6] = raw[..6].iter().copied().fold(0, u8::wrapping_add);
            assert_eq!(decode_reply(&raw).is_ok(), value == original[position]);
        }
    }
    for offset in 1..=u8::MAX {
        let mut raw = original;
        raw[6] = raw[6].wrapping_add(offset);
        assert_eq!(decode_reply(&raw), Err(ReplyError::Checksum));
    }
}

#[test]
fn owned_observation_preserves_accepted_and_every_rejected_available_byte() {
    let raw = framed(0x2630, 1, 0);
    let mut cases = vec![records(&raw), vec![], vec![raw.to_vec()]];
    for index in 0..7 {
        let mut partial = records(&raw);
        partial[index].clear();
        cases.push(partial);
    }
    cases.push(records(&framed(0x2630, 1, 1)));
    cases.push(records(&framed(-5136, 1, 0)));
    cases.push(records(&framed(0x2631, 1, 0)));
    for reads in cases {
        let before = reads.clone();
        let outer_ptr = reads.as_ptr();
        let observation = ReplyObservation::from_reads(reads);
        assert_eq!(observation.reads(), before);
        assert_eq!(observation.reads().as_ptr(), outer_ptr);
        assert_eq!(observation.decoded().is_ok(), before == records(&raw));
        if let Ok(sample) = observation.decoded() {
            assert_eq!(sample.raw(), &raw);
        }
    }
}
