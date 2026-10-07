//! Actual original-factory prefix fixtures. All time and event observations
//! originate in retained workers; raw PIC reply bytes carry no ACK authority.
use super::*;

fn never_energized(value: &PrePowerRun, files: &Files, fan: &Arc<Fan>) {
    let state = value.snapshot();
    assert!(state.gpio.never_energized_consumed_at.is_none());
    assert!(state.gpio.calls.iter().all(|call| {
        !matches!(
            call.phase,
            GpioPhase::EnableAuxiliary | GpioPhase::PostPicReset
        )
    }));
    assert!(state
        .gpio
        .events
        .iter()
        .all(|event| event.action != "original-board-enable"));
    assert_eq!(files.read(59, "value"), "0");
    assert!(fan
        .writes
        .lock()
        .unwrap()
        .iter()
        .all(|pwm| *pwm <= AM3_BB_FAN_HARD_CAP_PWM));
}

fn cutoff_completed(state: &PrePowerObservation) -> Instant {
    // A returned successful original GPIO operation, not merely async method
    // entry or a callback timestamp. File fixture only, no physical OFF claim.
    state
        .gpio
        .events
        .iter()
        .find(|event| {
            event.action == "stop-cutoff" && event.error.is_none() && event.returned_at.is_some()
        })
        .expect("original immediate GPIO cutoff did not actually return")
        .returned_at
        .unwrap()
}

fn joined_cleanup(state: &PrePowerObservation) {
    let controller = state.controller.as_ref().unwrap();
    let close = controller.management_close().unwrap();
    // HAL records this after joining original callers and just before the
    // service-close task is reserved; it is not an instrumented syscall entry.
    assert!(cutoff_completed(state) <= close.started_at);
    assert!(close.started_at <= close.services_returned_at.unwrap());
    assert!(close.services_returned_at.unwrap() <= close.caller_joined_at.unwrap());
    assert!(close.caller_joined_at.unwrap() < close.deadline);
    assert!(close.both_service_receipts && close.failure.is_none());
    assert!(controller.uart_terminal());
    assert!(!controller.uart_call_pending());
    assert!(state.gpio.close_joined_at.is_some());
    assert!(state.close_failure.is_none());
}

#[tokio::test]
async fn original_factory_prefix_preserves_one_and_three_slot_order_then_closes_never_energized() {
    if !isolated_descriptor_test("initial_bridge::original_factory_prefix_preserves_one_and_three_slot_order_then_closes_never_energized") {
        return;
    }
    for selected in [&[0x50][..], &[0x52, 0x50, 0x51][..]] {
        let (mut value, files, fan, _watchdog) = captured(selected);
        let (result, fixture, _ptys, uart_calls) = open(&mut value, false, false).await;
        result.unwrap();
        value.diagnose_until(due()).await.unwrap();
        let identities = fixture.original_service_identities();
        assert!(identities.0.is_some() && identities.1.is_some());
        assert_ne!(identities.0, identities.1);
        let descriptors = pty_descriptors();
        let deadline = due();
        value
            .initial_disable_and_bridges_until(deadline)
            .await
            .unwrap();
        let prefix = value
            .controller
            .as_ref()
            .unwrap()
            .initial_bridge_observation()
            .unwrap();
        assert_eq!(prefix.selected_eeproms(), selected);
        assert_eq!(prefix.original_deadline(), deadline);
        assert!(prefix.initial_disable_joined_at().unwrap() < prefix.accepted_at().unwrap());
        assert!(prefix.accepted_at().unwrap() < deadline);
        assert_eq!(prefix.bridge_calls(), selected.len());
        assert!(!prefix.caller_or_worker_pending());
        assert!(prefix.failure().is_none());
        let events = fixture.pic_events();
        let writes: Vec<_> = events.iter().filter(|event| event.write).collect();
        let expected: Vec<_> = selected
            .iter()
            .map(|address| (address - 0x30, vec![0x55, 0xaa, 5, 0x15, 0, 0, 0x1a]))
            .chain(
                selected
                    .iter()
                    .map(|address| (address - 0x30, vec![0x55, 0xaa, 6, 0x3b, 0x48, 0, 0, 0x89])),
            )
            .collect();
        assert_eq!(
            writes
                .iter()
                .map(|event| (event.address, event.bytes.clone()))
                .collect::<Vec<_>>(),
            expected
        );
        for &address in selected {
            let raw: Vec<_> = events
                .iter()
                .filter(|event| {
                    !event.write && event.opcode == 0x3b && event.address == address - 0x30
                })
                .map(|event| event.bytes.clone())
                .collect();
            assert_eq!(raw, [vec![0], vec![0xff]]);
        }
        assert_eq!(fixture.opener_calls(), [0, 1]);
        assert_eq!(fixture.original_service_identities(), identities);
        assert_eq!(
            *uart_calls.lock().unwrap(),
            selected.iter().map(|a| a - 0x50).collect::<Vec<_>>()
        );
        assert_eq!(pty_descriptors(), descriptors);
        assert_eq!(fixture.apw_opcodes(), [2, 1, 6, 3]);
        assert!(value
            .snapshot()
            .controller
            .as_ref()
            .unwrap()
            .heartbeat()
            .is_none());
        never_energized(&value, &files, &fan);
        assert!(
            value.never.is_none(),
            "token remains in the original GPIO owner"
        );
        value.close_until(due()).await.unwrap();
        joined_cleanup(&value.snapshot());
        never_energized(&value, &files, &fan);
        assert_eq!(fixture.opener_calls(), [0, 1]);
        assert_eq!(Arc::strong_count(&fan), 1);
        let mut done = closed(value);
        let original = done.take_never_energized().unwrap();
        assert!(done.take_never_energized().is_err());
        drop(original); // Actual inert-watchdog token; no physical closeout claim.
    }
}

#[tokio::test]
async fn original_bridge_read_failure_retains_partial_reply_and_cuts_gpio_before_service_close() {
    let selected = [0x52, 0x50];
    let (mut value, files, fan, _watchdog) = captured(&selected);
    let (result, fixture, _ptys, _calls) = open(&mut value, false, false).await;
    result.unwrap();
    value.diagnose_until(due()).await.unwrap();
    fixture.fail_bridge_final_read();
    assert!(value
        .initial_disable_and_bridges_until(due())
        .await
        .is_err());
    // The actual enclosing error path has performed its own explicit cleanup.
    let prefix = value
        .controller
        .as_ref()
        .unwrap()
        .initial_bridge_observation()
        .unwrap();
    assert!(prefix.accepted_at().is_none() && prefix.failure().is_some());
    assert!(!prefix.caller_or_worker_pending());
    assert_eq!(prefix.bridge_calls(), 1);
    assert!(prefix.initial_disable_joined_at().is_some());
    let bridge: Vec<_> = fixture
        .pic_events()
        .into_iter()
        .filter(|event| event.opcode == 0x3b)
        .collect();
    assert_eq!(
        bridge.len(),
        2,
        "only the fixed write and first raw read returned"
    );
    assert!(bridge[0].write && !bridge[1].write);
    assert_eq!(bridge[0].address, 0x22);
    assert_eq!(bridge[1].bytes, [0]);
    joined_cleanup(&value.snapshot());
    never_energized(&value, &files, &fan);
    assert_eq!(fixture.opener_calls(), [0, 1]);
    assert_eq!(fixture.apw_opcodes(), [2, 1, 6, 3]);
    assert_eq!(Arc::strong_count(&fan), 1);
    let mut done = closed(value);
    let original = done.take_never_energized().unwrap();
    assert!(done.take_never_energized().is_err());
    drop(original);
}

#[tokio::test]
async fn cancelled_prefix_keeps_exact_blocked_worker_until_original_deadline_close_retry() {
    for block_bridge in [false, true] {
        let (mut value, files, fan, _watchdog) = captured(&[0x52, 0x50]);
        let (result, fixture, _ptys, _calls) = open(&mut value, false, false).await;
        result.unwrap();
        value.diagnose_until(due()).await.unwrap();
        let identities = fixture.original_service_identities();
        if block_bridge {
            fixture.block_bridge_final_read();
        } else {
            fixture.block_initial_disable_final_read();
        }
        let prefix_deadline = due();
        tokio::select! {
            _ = async {
                if block_bridge { fixture.wait_bridge_entered().await; }
                else { fixture.wait_initial_disable_entered().await; }
            } => {},
            result = value.initial_disable_and_bridges_until(prefix_deadline) =>
                panic!("original worker gate did not hold prefix: {result:?}"),
        }
        let mut value = retained(value);
        let prefix = value
            .controller
            .as_ref()
            .unwrap()
            .initial_bridge_observation()
            .unwrap();
        assert_eq!(prefix.original_deadline(), prefix_deadline);
        assert!(prefix.caller_or_worker_pending());
        assert!(prefix.accepted_at().is_none());
        assert_eq!(prefix.bridge_calls(), usize::from(block_bridge));
        let opcode = if block_bridge { 0x3b } else { 0x15 };
        let held_reads = fixture
            .pic_events()
            .into_iter()
            .filter(|event| !event.write && event.opcode == opcode && event.address == 0x22)
            .count();
        assert_eq!(
            held_reads, 1,
            "the second actual read has entered but not returned"
        );
        never_energized(&value, &files, &fan);
        assert!(value.never.is_none());
        let original_close_deadline = due();
        {
            let mut closing = Box::pin(value.close_until(original_close_deadline));
            poll_fn(|cx| match closing.as_mut().poll(cx) {
                std::task::Poll::Pending => std::task::Poll::Ready(()),
                std::task::Poll::Ready(result) => {
                    panic!("blocked original close returned: {result:?}")
                }
            })
            .await;
        }
        let mut value = retained(value);
        let during = value.snapshot();
        assert_eq!(
            during.original_close_deadline,
            Some(original_close_deadline)
        );
        assert!(during.close_calls[0].returned_at.is_none());
        let cutoff_at = cutoff_completed(&during);
        assert!(during
            .controller
            .as_ref()
            .unwrap()
            .management_close()
            .is_none());
        let pending = value
            .controller
            .as_ref()
            .unwrap()
            .initial_bridge_observation()
            .unwrap();
        assert!(pending.caller_or_worker_pending());
        assert!(pending.accepted_at().is_none());
        assert_eq!(
            fixture
                .pic_events()
                .into_iter()
                .filter(|event| { !event.write && event.opcode == opcode && event.address == 0x22 })
                .count(),
            held_reads
        );
        let release_at = Instant::now();
        assert!(cutoff_at <= release_at);
        fixture.release(); // Releases this exact original worker's retained gate.
        value.close_until(due()).await.unwrap();
        let after = value.snapshot();
        let returned_read_at = fixture
            .pic_events()
            .into_iter()
            .filter(|event| !event.write && event.opcode == opcode && event.address == 0x22)
            .nth(1)
            .unwrap()
            .at;
        assert!(release_at <= returned_read_at);
        let close = after
            .controller
            .as_ref()
            .unwrap()
            .management_close()
            .unwrap();
        assert!(returned_read_at <= close.started_at);
        assert_eq!(after.original_close_deadline, Some(original_close_deadline));
        assert_eq!(after.close_calls.len(), 2);
        assert!(after.close_calls[0].returned_at.is_none());
        assert!(after.close_calls[1].returned_at.unwrap() < original_close_deadline);
        let prefix = value
            .controller
            .as_ref()
            .unwrap()
            .initial_bridge_observation()
            .unwrap();
        assert_eq!(prefix.original_deadline(), prefix_deadline);
        assert!(!prefix.caller_or_worker_pending());
        assert!(prefix.accepted_at().is_none() && prefix.failure().is_some());
        joined_cleanup(&after);
        never_energized(&value, &files, &fan);
        assert_eq!(fixture.opener_calls(), [0, 1]);
        assert_eq!(fixture.original_service_identities(), identities);
        assert_eq!(Arc::strong_count(&fan), 1);
        let mut done = closed(value);
        let original = done.take_never_energized().unwrap();
        assert!(done.take_never_energized().is_err());
        drop(original);
    }
}
