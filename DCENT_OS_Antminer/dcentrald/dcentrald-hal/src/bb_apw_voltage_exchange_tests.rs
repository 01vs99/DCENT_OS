use super::*;

#[test]
fn immediate_transport_errors_keep_their_classification_in_both_phases() {
    for read_phase in [false, true] {
        let start = Instant::now();
        let mut exchange = operation(start);
        exchange.prepare_next(start).unwrap();
        let prepared = if read_phase {
            exchange
                .accept_reply(at(start, 500), Ok(vec![vectors::ORIGINAL[0].2.to_vec()]))
                .unwrap();
            exchange.prepare_next(at(start, 500)).unwrap();
            at(start, 500)
        } else {
            start
        };
        let returned_at = prepared + Duration::from_millis(1);
        assert_eq!(
            exchange.accept_reply(returned_at, Err("immediate transfer error".into())),
            Err(ExchangeError::Transport)
        );
        let failed = exchange.snapshot();
        assert_eq!(failed.phase, Phase::Failed);
        assert_eq!(failed.failure, Some(ExchangeError::Transport));
        assert_eq!(failed.protocol_completed_at, None);
        let observed = if read_phase {
            failed.readback_reply
        } else {
            failed.set_reply
        }
        .unwrap();
        assert_eq!(observed.received_at, returned_at);
        assert_eq!(observed.records, None);
        assert_eq!(
            observed.transport_error.as_deref(),
            Some("immediate transfer error")
        );
        assert_eq!(
            exchange.prepare_next(at(start, 1100)).unwrap_err(),
            ExchangeError::Transport
        );
    }
    let start = Instant::now();
    let mut backwards = operation(start);
    backwards.prepare_next(start).unwrap();
    assert_eq!(
        backwards.accept_reply(start - Duration::from_millis(1), Err("backwards".into())),
        Err(ExchangeError::Chronology)
    );
}

#[path = "bb_apw_voltage_exchange_vectors.rs"]
mod vectors;

fn at(start: Instant, millis: u64) -> Instant {
    start + Duration::from_millis(millis)
}

fn operation(start: Instant) -> Hw76VoltageExchange {
    Hw76VoltageExchange::new(
        f64::from_bits(vectors::ORIGINAL[0].0),
        start,
        at(start, 2000),
    )
    .unwrap()
}

fn verify_steps(steps: &[I2cTransactionStep], expected: &[u8]) {
    assert_eq!(steps.len(), 3);
    match (&steps[0], &steps[1], &steps[2]) {
        (
            I2cTransactionStep::Write(frame),
            I2cTransactionStep::SleepMs(500),
            I2cTransactionStep::Read(10),
        ) => {
            assert_eq!(frame, expected);
        }
        other => panic!("unexpected fixed transaction: {other:?}"),
    }
}

#[test]
fn complete_original_set_and_forced_read_vectors() {
    assert_eq!(vectors::ORIGINAL.len(), 19);
    for (bits, set_frame, set_reply, read_frame, read_reply, reported_mv) in vectors::ORIGINAL {
        let start = Instant::now();
        let mut exchange =
            Hw76VoltageExchange::new(f64::from_bits(*bits), start, at(start, 2000)).unwrap();
        verify_steps(&exchange.prepare_next(start).unwrap(), set_frame);
        assert_eq!(exchange.snapshot().reported_millivolts, None);
        assert_eq!(
            exchange.accept_reply(at(start, 500), Ok(vec![set_reply.to_vec()])),
            Ok(Phase::SetAcknowledged)
        );
        assert_eq!(exchange.snapshot().protocol_completed_at, None);
        verify_steps(&exchange.prepare_next(at(start, 500)).unwrap(), read_frame);
        assert_eq!(
            exchange.accept_reply(at(start, 1000), Ok(vec![read_reply.to_vec()])),
            Ok(Phase::Complete)
        );
        let completed = exchange.snapshot();
        assert_eq!(completed.reported_millivolts, Some(*reported_mv));
        assert_eq!(completed.protocol_completed_at, Some(at(start, 1000)));
        assert_eq!(completed.deadline, at(start, 2000));
        assert_eq!(
            completed.set_reply.unwrap().records,
            Some(vec![set_reply.to_vec()])
        );
        assert_eq!(
            completed.readback_reply.unwrap().records,
            Some(vec![read_reply.to_vec()])
        );
        assert_eq!(completed.failure, None);
    }
}

#[test]
fn every_reply_byte_corruption_fails_without_a_later_phase() {
    let (_, _, set_reply, _, read_reply, _) = vectors::ORIGINAL[0];
    for read_phase in [false, true] {
        for offset in 0..10 {
            let start = Instant::now();
            let mut exchange = operation(start);
            exchange.prepare_next(start).unwrap();
            if read_phase {
                exchange
                    .accept_reply(at(start, 500), Ok(vec![set_reply.to_vec()]))
                    .unwrap();
                exchange.prepare_next(at(start, 500)).unwrap();
            }
            let mut damaged = if read_phase {
                read_reply.to_vec()
            } else {
                set_reply.to_vec()
            };
            damaged[offset] ^= 1;
            let reply_at = at(start, if read_phase { 1000 } else { 500 });
            assert!(exchange
                .accept_reply(reply_at, Ok(vec![damaged.clone()]))
                .is_err());
            let failed = exchange.snapshot();
            assert_eq!(failed.phase, Phase::Failed);
            assert_eq!(failed.protocol_completed_at, None);
            let actual = if read_phase {
                failed.readback_reply
            } else {
                failed.set_reply
            };
            assert_eq!(actual.unwrap().records, Some(vec![damaged]));
            assert!(exchange.prepare_next(reply_at).is_err());
            assert_eq!(exchange.snapshot().failure, failed.failure);
        }
    }
}

fn repaired_reply(opcode: u8, code: [u8; 2]) -> Vec<u8> {
    let checksum = wire::checksum(6, opcode, &code).to_le_bytes();
    vec![
        0x55,
        0xaa,
        6,
        opcode,
        code[0],
        code[1],
        checksum[0],
        checksum[1],
        0xf5,
        0xf5,
    ]
}

#[test]
fn valid_checksums_do_not_admit_wrong_opcode_code_or_high_word() {
    let start = Instant::now();
    let code = operation(start).snapshot().expected_code;
    let (_, _, set_reply, _, _, _) = vectors::ORIGINAL[0];
    for read_phase in [false, true] {
        let opcode = if read_phase { 3 } else { 0x83 };
        for (reply, error) in [
            (
                repaired_reply(opcode ^ 0x80, code),
                ExchangeError::WrongOpcode,
            ),
            (
                repaired_reply(opcode, [code[0] + 1, 0]),
                ExchangeError::WrongCode,
            ),
            (
                repaired_reply(opcode, [code[0], 1]),
                ExchangeError::WrongCode,
            ),
        ] {
            let mut exchange = operation(start);
            exchange.prepare_next(start).unwrap();
            if read_phase {
                exchange
                    .accept_reply(at(start, 500), Ok(vec![set_reply.to_vec()]))
                    .unwrap();
                exchange.prepare_next(at(start, 500)).unwrap();
            }
            assert_eq!(
                exchange.accept_reply(at(start, 1000), Ok(vec![reply.clone()])),
                Err(error)
            );
            assert!(exchange.prepare_next(at(start, 1000)).is_err());
            assert_eq!(exchange.snapshot().protocol_completed_at, None);
        }
    }
}

#[test]
fn record_shapes_and_transport_failures_preserve_available_observations() {
    let (_, _, good, _, _, _) = vectors::ORIGINAL[0];
    let mut shapes = vec![vec![], vec![good.to_vec(), good.to_vec()]];
    shapes.extend((0..10).map(|length| vec![good[..length].to_vec()]));
    let mut long = good.to_vec();
    long.push(0xf5);
    shapes.push(vec![long]);
    for records in shapes {
        let start = Instant::now();
        let mut exchange = operation(start);
        exchange.prepare_next(start).unwrap();
        assert_eq!(
            exchange.accept_reply(at(start, 500), Ok(records.clone())),
            Err(ExchangeError::ReplyShape)
        );
        assert_eq!(
            exchange.snapshot().set_reply.unwrap().records,
            Some(records)
        );
        assert_eq!(exchange.snapshot().readback_prepared_at, None);
    }
    let start = Instant::now();
    let mut exchange = operation(start);
    exchange.prepare_next(start).unwrap();
    assert_eq!(
        exchange.accept_reply(
            at(start, 500),
            Err("worker timeout; late bytes unavailable".into())
        ),
        Err(ExchangeError::Transport)
    );
    let observed = exchange.snapshot().set_reply.unwrap();
    assert_eq!(observed.records, None);
    assert_eq!(
        observed.transport_error.as_deref(),
        Some("worker timeout; late bytes unavailable")
    );
}

#[test]
fn absolute_deadline_and_cadence_apply_to_both_exchanges() {
    let (_, _, set_reply, _, read_reply, _) = vectors::ORIGINAL[0];
    let start = Instant::now();
    let volts = f64::from_bits(vectors::ORIGINAL[0].0);
    assert!(matches!(
        Hw76VoltageExchange::new(volts, start, start),
        Err(ExchangeError::Deadline)
    ));
    let mut too_short = Hw76VoltageExchange::new(volts, start, at(start, 500)).unwrap();
    assert_eq!(
        too_short.prepare_next(start).unwrap_err(),
        ExchangeError::Deadline
    );
    assert_eq!(too_short.snapshot().set_prepared_at, None);
    let mut no_second_budget = Hw76VoltageExchange::new(volts, start, at(start, 1000)).unwrap();
    no_second_budget.prepare_next(start).unwrap();
    no_second_budget
        .accept_reply(at(start, 500), Ok(vec![set_reply.to_vec()]))
        .unwrap();
    assert_eq!(
        no_second_budget.prepare_next(at(start, 500)).unwrap_err(),
        ExchangeError::Deadline
    );
    assert_eq!(no_second_budget.snapshot().readback_prepared_at, None);
    for read_phase in [false, true] {
        for millis in [499, 2000, 2500] {
            let mut exchange = operation(start);
            exchange.prepare_next(start).unwrap();
            if read_phase {
                exchange
                    .accept_reply(at(start, 500), Ok(vec![set_reply.to_vec()]))
                    .unwrap();
                exchange.prepare_next(at(start, 500)).unwrap();
            }
            let records = vec![if read_phase {
                read_reply.to_vec()
            } else {
                set_reply.to_vec()
            }];
            let result = exchange.accept_reply(at(start, millis), Ok(records.clone()));
            assert_eq!(
                result,
                Err(if millis < 2000 {
                    ExchangeError::Chronology
                } else {
                    ExchangeError::Deadline
                })
            );
            let snapshot = exchange.snapshot();
            assert_eq!(snapshot.deadline, at(start, 2000));
            assert_eq!(snapshot.protocol_completed_at, None);
            let observation = if read_phase {
                snapshot.readback_reply
            } else {
                snapshot.set_reply
            };
            assert_eq!(observation.unwrap().records, Some(records));
        }
    }
    let mut reversed = operation(start);
    assert_eq!(
        reversed
            .prepare_next(start - Duration::from_millis(1))
            .unwrap_err(),
        ExchangeError::Chronology
    );
    let mut reversed_second = operation(start);
    reversed_second.prepare_next(start).unwrap();
    reversed_second
        .accept_reply(at(start, 600), Ok(vec![set_reply.to_vec()]))
        .unwrap();
    assert_eq!(
        reversed_second.prepare_next(at(start, 599)).unwrap_err(),
        ExchangeError::Chronology
    );
}

#[test]
fn invalid_sequence_and_cancellation_cannot_restart_or_replace_replies() {
    let (_, _, set_reply, _, read_reply, _) = vectors::ORIGINAL[0];
    let start = Instant::now();
    let mut before_prepare = operation(start);
    assert_eq!(
        before_prepare.accept_reply(at(start, 500), Ok(vec![set_reply.to_vec()])),
        Err(ExchangeError::UnexpectedPhase)
    );
    assert!(before_prepare.snapshot().set_reply.is_none());
    let mut duplicate = operation(start);
    duplicate.prepare_next(start).unwrap();
    assert_eq!(
        duplicate.prepare_next(start).unwrap_err(),
        ExchangeError::UnexpectedPhase
    );
    for reached in 0..5 {
        let mut exchange = operation(start);
        if reached >= 1 {
            exchange.prepare_next(start).unwrap();
        }
        if reached >= 2 {
            exchange
                .accept_reply(at(start, 500), Ok(vec![set_reply.to_vec()]))
                .unwrap();
        }
        if reached >= 3 {
            exchange.prepare_next(at(start, 500)).unwrap();
        }
        if reached >= 4 {
            exchange
                .accept_reply(at(start, 1000), Ok(vec![read_reply.to_vec()]))
                .unwrap();
        }
        let before = exchange.snapshot();
        exchange.cancel();
        assert_eq!(
            exchange.prepare_next(at(start, 1100)).unwrap_err(),
            ExchangeError::Cancelled
        );
        assert_eq!(
            exchange.accept_reply(at(start, 1100), Ok(vec![read_reply.to_vec()])),
            Err(ExchangeError::Cancelled)
        );
        let after = exchange.snapshot();
        assert_eq!(after.phase, Phase::Failed);
        assert_eq!(after.protocol_completed_at, before.protocol_completed_at);
        assert_eq!(
            after.set_reply.map(|reply| reply.records),
            before.set_reply.map(|reply| reply.records)
        );
        assert_eq!(
            after.readback_reply.map(|reply| reply.records),
            before.readback_reply.map(|reply| reply.records)
        );
    }
}

#[test]
fn request_must_fit_exact_native_profile_centivolts_without_saturation() {
    let start = Instant::now();
    for volts in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -1.0,
        0.0,
        11.87,
        15.13,
        13.801,
        13.805,
        13.800_000_000_000_002,
    ] {
        assert!(matches!(
            Hw76VoltageExchange::new(volts, start, at(start, 2000)),
            Err(ExchangeError::InvalidRequest)
        ));
    }
    for volts in [11.88, 13.4, 15.12] {
        let exchange = Hw76VoltageExchange::new(volts, start, at(start, 2000)).unwrap();
        assert_eq!(
            f64::from(exchange.snapshot().requested_millivolts) / 1000.0,
            volts
        );
    }
}
