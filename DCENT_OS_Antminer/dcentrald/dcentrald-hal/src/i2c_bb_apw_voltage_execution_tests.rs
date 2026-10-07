use super::*;

#[test]
fn immediate_failed_set_preserves_transport_error_and_stops_before_readback() {
    let backend = Backend::new(0x76, 0x17, 0x68, None, None);
    backend.fail_set_write();
    let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    let result = execute(
        &handle,
        requested(Some(13.4)),
        history(),
        Instant::now() + Duration::from_secs(10),
    );
    assert!(result.failure.as_deref().unwrap().contains("Transport"));
    assert!(result.caller_completed_at.is_none());
    let exchange = result.exchange.unwrap();
    assert_eq!(exchange.phase, Phase::Failed);
    assert_eq!(
        exchange.failure,
        Some(crate::bb_apw_voltage_exchange::ExchangeError::Transport)
    );
    let failed = exchange.set_reply.unwrap();
    assert!(failed.records.is_none());
    assert!(failed
        .transport_error
        .unwrap()
        .contains("fixture immediate set write failure"));
    assert!(exchange.readback_prepared_at.is_none() && exchange.readback_reply.is_none());
    assert_eq!(backend.opcodes(), [2, 1, 6, 3, 0x83]);
    assert!(handle.terminal_safe_off_is_latched());
    close(&mut owner);
}
use crate::i2c::spawn_owned_sim_i2c_service;
use std::time::Duration;

#[path = "i2c_bb_apw_voltage_execution_test_support.rs"]
mod support;
use support::{Backend, Event};

fn history() -> History {
    History {
        previous_request: None,
        repeated_requests: 0,
    }
}

fn requested(target: Option<f64>) -> Hw76RequestedVoltageProfile {
    let mut profile = Hw76RequestedVoltageProfile::default();
    profile.merge_request(target, None).unwrap();
    profile
}

fn close(owner: &mut I2cServiceOwner) {
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(2))
        .unwrap();
}

#[test]
fn same_actual_worker_queries_plans_sets_and_forces_readback() {
    let backend = Backend::new(0x76, 0x17, 0x68, None, None);
    let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    let deadline = Instant::now() + Duration::from_secs(12);
    let result = execute(&handle, requested(Some(13.4)), history(), deadline);
    assert!(result.failure.is_none(), "{:?}", result.failure);
    assert!(result.caller_completed_at.is_some_and(|at| at < deadline));
    assert_eq!(result.deadline, deadline);
    assert_eq!(result.prior_history, history());
    assert_eq!(result.plan.unwrap().decision, Decision::Request(13.75));
    let exchange = result.exchange.unwrap();
    assert_eq!(exchange.phase, Phase::Complete);
    assert_eq!(exchange.reported_millivolts, Some(13750));
    assert_eq!(exchange.deadline, deadline);
    assert_eq!(backend.opcodes(), [2, 1, 6, 3, 0x83, 3]);
    assert_eq!(
        exchange.set_reply.unwrap().records.unwrap()[0],
        [0x55, 0xaa, 6, 0x83, 0x6c, 0, 0xf5, 0, 0xf5, 0xf5]
    );
    assert_eq!(
        exchange.readback_reply.unwrap().records.unwrap()[0],
        [0x55, 0xaa, 6, 3, 0x6c, 0, 0x75, 0, 0xf5, 0xf5]
    );
    assert!(!handle.terminal_safe_off_is_latched());
    close(&mut owner);
}

#[test]
fn numerical_no_request_and_tolerance_do_not_create_control_transactions() {
    for (profile, prior, expected_plan) in [
        (requested(None), history(), None),
        (requested(Some(13.8)), history(), None),
        (
            requested(Some(13.4)),
            History {
                previous_request: Some(13.75),
                repeated_requests: 10,
            },
            Some(Decision::HistoryTolerance {
                within_source_tolerance: false,
            }),
        ),
    ] {
        let backend = Backend::new(0x76, 0x17, 0x68, None, None);
        let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
        let result = execute(
            &owner.request_handle(),
            profile,
            prior,
            Instant::now() + Duration::from_secs(10),
        );
        assert!(result.failure.is_none() && result.caller_completed_at.is_some());
        assert_eq!(result.plan.map(|plan| plan.decision), expected_plan);
        assert!(result.exchange.is_none());
        assert_eq!(backend.opcodes(), [2, 1, 6, 3]);
        close(&mut owner);
    }
}

#[test]
fn identity_wide_dac_and_invalid_history_refuse_before_any_set() {
    for (hw, fw, dac, prior, expected) in [
        (0x176, 0x17, 0x68, history(), vec![2]),
        (0x76, 0x117, 0x68, history(), vec![2, 1]),
        (0x76, 0x17, 0x168, history(), vec![2, 1, 6, 3]),
        (
            0x76,
            0x17,
            0x68,
            History {
                previous_request: None,
                repeated_requests: 1,
            },
            vec![2, 1, 6, 3],
        ),
    ] {
        let backend = Backend::new(hw, fw, dac, None, None);
        let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
        let handle = owner.request_handle();
        let result = execute(
            &handle,
            requested(Some(13.4)),
            prior,
            Instant::now() + Duration::from_secs(10),
        );
        assert!(result.failure.is_some() && result.caller_completed_at.is_none());
        assert!(result.profile.is_some() && result.exchange.is_none());
        assert_eq!(backend.opcodes(), expected);
        assert!(handle.terminal_safe_off_is_latched());
        let retry = execute(
            &handle,
            requested(Some(13.4)),
            history(),
            Instant::now() + Duration::from_secs(10),
        );
        assert!(retry.profile.is_none() && retry.failure.is_some());
        assert_eq!(backend.opcodes(), expected);
        close(&mut owner);
    }
}

#[test]
fn wrong_bus_expired_deadline_and_prior_fence_emit_no_bytes() {
    for mode in 0..3 {
        let backend = Backend::new(0x76, 0x17, 0x68, None, None);
        let mut owner =
            spawn_owned_sim_i2c_service(if mode == 0 { 0 } else { 1 }, backend.clone(), Vec::new())
                .unwrap();
        let handle = owner.request_handle();
        if mode == 2 {
            handle.latch_terminal_safe_off();
        }
        let now = Instant::now();
        let result = execute(
            &handle,
            requested(Some(13.4)),
            history(),
            if mode == 1 {
                now
            } else {
                now + Duration::from_secs(10)
            },
        );
        assert!(result.failure.is_some() && result.profile.is_none() && result.exchange.is_none());
        assert!(handle.terminal_safe_off_is_latched());
        assert_eq!(backend.trace(), []);
        close(&mut owner);
    }
}

#[test]
fn malformed_set_and_following_replies_retain_phases_and_fence_the_worker() {
    for fault in [(0x83, true), (0x83, false), (3, false)] {
        let backend = Backend::new(0x76, 0x17, 0x68, Some(fault), None);
        let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
        let handle = owner.request_handle();
        let result = execute(
            &handle,
            requested(Some(13.4)),
            history(),
            Instant::now() + Duration::from_secs(10),
        );
        assert!(result.failure.is_some() && result.caller_completed_at.is_none());
        let exchange = result.exchange.unwrap();
        assert_eq!(exchange.phase, Phase::Failed);
        assert!(exchange.protocol_completed_at.is_none());
        assert_eq!(
            exchange
                .set_reply
                .as_ref()
                .unwrap()
                .records
                .as_ref()
                .unwrap()[0]
                .len(),
            if fault == (0x83, false) { 9 } else { 10 }
        );
        if fault.0 == 3 {
            assert_eq!(backend.opcodes(), [2, 1, 6, 3, 0x83, 3]);
            assert_eq!(
                exchange.readback_reply.unwrap().records.unwrap()[0].len(),
                9
            );
        } else {
            assert_eq!(backend.opcodes(), [2, 1, 6, 3, 0x83]);
            assert!(exchange.readback_reply.is_none());
        }
        assert!(handle.terminal_safe_off_is_latched());
        close(&mut owner);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_fence_during_set_write_prevents_echo_and_following_read() {
    let backend = Backend::new(0x76, 0x17, 0x68, None, Some((0x83, support::Phase::Write)));
    let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    let caller_handle = handle.clone();
    let caller = std::thread::spawn(move || {
        execute(
            &caller_handle,
            requested(Some(13.4)),
            history(),
            Instant::now() + Duration::from_secs(10),
        )
    });
    backend.wait_entered().await;
    handle.latch_terminal_safe_off();
    backend.release();
    let result = caller.join().unwrap();
    assert!(result.failure.is_some() && result.caller_completed_at.is_none());
    let exchange = result.exchange.unwrap();
    assert_eq!(exchange.phase, Phase::Failed);
    assert!(exchange.set_reply.unwrap().records.is_none());
    assert!(exchange.readback_prepared_at.is_none());
    assert_eq!(backend.opcodes(), [2, 1, 6, 3, 0x83]);
    assert!(!backend
        .trace()
        .iter()
        .any(|event| matches!(event, Event::Read(0x83, _))));
    close(&mut owner);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn started_set_timeout_returns_caller_but_retains_real_service_close_custody() {
    let backend = Backend::new(0x76, 0x17, 0x68, None, Some((0x83, support::Phase::Write)));
    let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    let caller_handle = handle.clone();
    let deadline = Instant::now() + Duration::from_secs(5);
    let caller = std::thread::spawn(move || {
        execute(&caller_handle, requested(Some(13.4)), history(), deadline)
    });
    backend.wait_entered().await;
    let result = caller.join().unwrap();
    assert_eq!(result.deadline, deadline);
    assert!(result.failure.is_some() && result.caller_completed_at.is_none());
    let exchange = result.exchange.unwrap();
    assert_eq!(exchange.deadline, deadline);
    assert!(exchange.set_reply.unwrap().records.is_none());
    assert!(exchange.readback_prepared_at.is_none());
    assert!(handle.terminal_safe_off_is_latched());
    assert!(owner
        .close_and_join_until(Instant::now() + Duration::from_millis(10))
        .is_err());
    backend.release();
    close(&mut owner);
    assert_eq!(backend.opcodes(), [2, 1, 6, 3, 0x83]);
    assert!(!backend
        .trace()
        .iter()
        .any(|event| matches!(event, Event::Read(0x83, _))));
}
