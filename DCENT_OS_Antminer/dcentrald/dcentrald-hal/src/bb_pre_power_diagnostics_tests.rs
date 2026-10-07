//! Actual owned-service aggregate tests; independent inert wire fixtures only.
use super::*;
use crate::i2c::{spawn_owned_sim_i2c_service, I2cServiceHandle};
use std::time::Duration;

#[path = "bb_pre_power_apw_test_support.rs"]
mod apw;
#[path = "bb_pre_power_bus0_test_support.rs"]
mod bus0;

struct Release {
    bus0: Arc<bus0::Backend>,
    apw: Arc<apw::Backend>,
}

impl Drop for Release {
    fn drop(&mut self) {
        self.bus0.release();
        self.apw.release();
    }
}

fn owners(a: &Arc<bus0::Backend>, b: &Arc<apw::Backend>) -> (I2cServiceOwner, I2cServiceOwner) {
    (
        spawn_owned_sim_i2c_service(0, a.clone(), (0x50..=0x57).collect()).unwrap(),
        spawn_owned_sim_i2c_service(1, b.clone(), vec![]).unwrap(),
    )
}

fn pair(
    a: &Arc<bus0::Backend>,
    b: &Arc<apw::Backend>,
) -> (BbPrePowerDiagnostics, I2cServiceHandle, I2cServiceHandle) {
    let (a, b) = owners(a, b);
    let handles = (a.request_handle(), b.request_handle());
    (BbPrePowerDiagnostics::new(a, b), handles.0, handles.1)
}

async fn fences_latched(a: &I2cServiceHandle, b: &I2cServiceHandle) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !(a.terminal_safe_off_is_latched() && b.terminal_safe_off_is_latched()) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

fn close(pair: &mut BbPrePowerDiagnostics) {
    assert!(tokio::task::block_in_place(
        || pair.close_services_until(Instant::now() + Duration::from_secs(2))
    ));
    let (a, b) = pair.close_receipts();
    assert_eq!((a.unwrap().bus(), b.unwrap().bus()), (0, 1));
    assert!(a.unwrap().worker_exit_observed_at() <= Instant::now());
    assert!(b.unwrap().worker_exit_observed_at() <= Instant::now());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_actual_pair_retains_raw_histories_one_deadline_and_both_workers() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = apw::Backend::new(0x23, false, None);
    let (mut pair, h0, h1) = pair(&a, &b);
    let deadline = Instant::now() + Duration::from_secs(12);
    let snapshot = pair.observe_once(&[0x52, 0x50, 0x51], deadline).await;
    assert!(snapshot.stop.is_none(), "{snapshot:?}");
    assert_eq!(snapshot.original_deadline, Some(deadline));
    assert_eq!(snapshot.bus0.deadline, Some(deadline));
    assert_eq!(snapshot.apw.deadline, Some(deadline));
    assert!(snapshot.both_callers_joined_observed_at.is_some());
    let historical = snapshot.historical.unwrap();
    assert!(historical.both_observed_at < deadline);
    assert_eq!(historical.bus0.bridges.len(), 12);
    assert_eq!(historical.apw.profile.queries.len(), 4);
    assert_eq!(b.opcodes(), [2, 1, 6, 3]);
    assert!(spawn_owned_sim_i2c_service(0, a.clone(), vec![]).is_err());
    assert!(spawn_owned_sim_i2c_service(1, b.clone(), vec![]).is_err());
    assert!(pair.close_receipts().0.is_none() && pair.close_receipts().1.is_none());
    pair.cancel();
    assert!(h0.terminal_safe_off_is_latched() && h1.terminal_safe_off_is_latched());
    assert!(
        pair.snapshot().historical.is_some(),
        "historical data survives stop without authority"
    );
    assert_eq!(historical.apw.profile.queries.len(), 4);
    close(&mut pair);
    let (mut replacement0, mut replacement1) = owners(&a, &b);
    tokio::task::block_in_place(|| {
        replacement0
            .close_and_join_until(Instant::now() + Duration::from_secs(1))
            .unwrap();
        replacement1
            .close_and_join_until(Instant::now() + Duration::from_secs(1))
            .unwrap();
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_bus_endpoint_and_expired_declarations_fence_both_before_any_wire_work() {
    for defect in 0..5 {
        let a = bus0::Backend::new(bus0::Fault::None, None);
        let b = apw::Backend::new(0x23, false, None);
        let (owner0, owner1) = owners(&a, &b);
        let (h0, h1) = (owner0.request_handle(), owner1.request_handle());
        let mut pair = if defect == 0 {
            BbPrePowerDiagnostics::new(owner1, owner0)
        } else {
            BbPrePowerDiagnostics::new(owner0, owner1)
        };
        let selected: &[u8] = match defect {
            1 => &[],
            2 => &[0x50, 0x50],
            3 => &[0x53],
            _ => &[0x50],
        };
        let deadline = if defect == 4 {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(2)
        };
        let snapshot = pair.observe_once(selected, deadline).await;
        assert!(snapshot.stop.is_some() && snapshot.historical.is_none());
        assert!(snapshot.bus0.deadline.is_none() && snapshot.apw.deadline.is_none());
        assert!(a.trace().is_empty() && b.trace().is_empty());
        assert!(h0.terminal_safe_off_is_latched() && h1.terminal_safe_off_is_latched());
        assert!(
            pair.join_callers_until(Instant::now() + Duration::from_secs(1))
                .await
        );
        assert!(tokio::task::block_in_place(
            || pair.close_services_until(Instant::now() + Duration::from_secs(2))
        ));
        assert!(pair.close_receipts().0.is_some() && pair.close_receipts().1.is_some());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn either_failed_child_fences_the_still_blocked_other_before_waiting_for_its_join() {
    for bus0_fails in [true, false] {
        let a = bus0::Backend::new(
            if bus0_fails {
                bus0::Fault::Status
            } else {
                bus0::Fault::None
            },
            Some((0x48, 0)),
        );
        let b = apw::Backend::new(0x23, !bus0_fails, Some((2, apw::Phase::Write)));
        let _release = Release {
            bus0: a.clone(),
            apw: b.clone(),
        };
        let (mut pair, h0, h1) = pair(&a, &b);
        let deadline = Instant::now() + Duration::from_secs(12);
        let snapshot = {
            let observe = pair.observe_once(&[0x50], deadline);
            tokio::pin!(observe);
            tokio::select! { _ = a.wait_entered() => {}, _ = &mut observe => panic!("aggregate completed before both controlled caller gates") }
            tokio::select! { _ = b.wait_entered() => {}, _ = &mut observe => panic!("aggregate completed before both controlled caller gates") }
            if bus0_fails {
                a.release();
            } else {
                b.release();
            }
            tokio::select! { _ = fences_latched(&h0, &h1) => {}, _ = &mut observe => panic!("aggregate joined while sibling transfer remains blocked") }
            if bus0_fails {
                assert_eq!(b.opcodes(), [2]);
                b.release();
            } else {
                a.release();
            }
            observe.await
        };
        assert!(snapshot.stop.is_some() && snapshot.historical.is_none());
        assert!(snapshot.both_callers_joined_observed_at.is_some());
        assert!(snapshot.bus0.inventory.factory.is_some());
        assert!(!snapshot.bus0.bridges.is_empty());
        assert!(snapshot.apw.attempt.is_some());
        if bus0_fails {
            assert_eq!(snapshot.bus0.bridges.len(), 2);
            assert!(snapshot.bus0.bridges[0].decoded.is_some());
            assert!(snapshot.bus0.bridges[1].error.is_some());
        } else {
            assert_eq!(snapshot.apw.attempt.unwrap().queries.len(), 3);
            assert_eq!(snapshot.bus0.bridges.len(), 1);
        }
        close(&mut pair);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_observation_keeps_both_callers_and_failed_close_attempts_for_retry() {
    let a = bus0::Backend::new(bus0::Fault::None, Some((0x48, 0)));
    let b = apw::Backend::new(0x23, false, Some((2, apw::Phase::Write)));
    let _release = Release {
        bus0: a.clone(),
        apw: b.clone(),
    };
    let (mut pair, h0, h1) = pair(&a, &b);
    let original = Instant::now() + Duration::from_secs(12);
    {
        let observe = pair.observe_once(&[0x50], original);
        tokio::pin!(observe);
        tokio::select! { _ = a.wait_entered() => {}, _ = &mut observe => panic!("premature completion") }
        tokio::select! { _ = b.wait_entered() => {}, _ = &mut observe => panic!("premature completion") }
    }
    assert!(h0.terminal_safe_off_is_latched() && h1.terminal_safe_off_is_latched());
    assert!(pair.snapshot().stop.unwrap().reason.contains("cancelled"));
    assert!(
        !pair
            .join_callers_until(Instant::now() + Duration::from_millis(5))
            .await
    );
    assert!(!tokio::task::block_in_place(|| pair.close_services_until(
        Instant::now() + Duration::from_millis(5)
    )));
    assert_eq!(pair.snapshot().close_attempts.len(), 1);
    assert!(pair.snapshot().close_attempts[0].bus0_error.is_some());
    assert!(pair.snapshot().close_attempts[0].bus1_error.is_some());
    assert!(pair.close_receipts().0.is_none() && pair.close_receipts().1.is_none());
    a.release();
    b.release();
    assert!(
        pair.join_callers_until(Instant::now() + Duration::from_secs(2))
            .await
    );
    assert_eq!(pair.snapshot().original_deadline, Some(original));
    assert!(pair.snapshot().historical.is_none());
    close(&mut pair);
    assert_eq!(pair.snapshot().close_attempts.len(), 2);
    assert!(pair.snapshot().close_attempts[1].bus0_error.is_none());
    assert!(pair.snapshot().close_attempts[1].bus1_error.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_expiry_never_becomes_diagnostic_success_after_late_caller_cleanup() {
    let a = bus0::Backend::new(bus0::Fault::None, Some((0x48, 0)));
    let b = apw::Backend::new(0x23, false, Some((2, apw::Phase::Write)));
    let _release = Release {
        bus0: a.clone(),
        apw: b.clone(),
    };
    let (mut pair, h0, h1) = pair(&a, &b);
    let original = Instant::now() + Duration::from_secs(1);
    let snapshot = pair.observe_once(&[0x50], original).await;
    assert!(snapshot.stop.is_some() && snapshot.historical.is_none());
    assert!(h0.terminal_safe_off_is_latched() && h1.terminal_safe_off_is_latched());
    a.release();
    b.release();
    assert!(
        pair.join_callers_until(Instant::now() + Duration::from_secs(2))
            .await
    );
    assert_eq!(pair.snapshot().original_deadline, Some(original));
    assert!(pair.snapshot().historical.is_none());
    close(&mut pair);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_without_an_attempt_fences_both_services_without_claiming_close_receipts() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = apw::Backend::new(0x23, false, None);
    let (pair, h0, h1) = pair(&a, &b);
    assert!(pair.close_receipts().0.is_none() && pair.close_receipts().1.is_none());
    drop(pair);
    assert!(h0.terminal_safe_off_is_latched() && h1.terminal_safe_off_is_latched());
    assert!(a.trace().is_empty() && b.trace().is_empty());
}
