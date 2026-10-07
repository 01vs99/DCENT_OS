use super::*;
use std::sync::Condvar;
use std::time::Duration;

fn due() -> Instant {
    Instant::now() + Duration::from_secs(12)
}
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}
impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            condition: Condvar::new(),
        })
    }
    fn wait(&self) {
        self.entered.store(true, Ordering::SeqCst);
        let guard = self.released.lock().unwrap();
        let (_guard, timed) = self
            .condition
            .wait_timeout_while(guard, Duration::from_secs(4), |released| !*released)
            .unwrap();
        assert!(!timed.timed_out());
    }
    async fn entered(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test]
async fn original_diagnostics_and_runtime_then_actual_worker_and_close_caller_joins() {
    let (mut runtime, fixture) = simulated::Fixture::new(false, false);
    let initial = runtime.observe_initial_until(&[0x50], due()).await.unwrap();
    assert!(initial.diagnostic_complete() && initial.factory().is_some() && !initial.stopped());
    runtime.merge_requested_voltage(Some(13.4), None).unwrap();
    let value = runtime.observe_runtime_until(due()).await.unwrap();
    assert!(value.last_pair_sequence().is_some() && !value.stopped());
    assert_eq!(value.profile_generation(), 1);
    assert!(fixture.bus0_events() > 0);
    assert_eq!(fixture.apw_opcodes(), [2, 1, 6, 3, 2, 1, 6, 3]);
    assert!(runtime.close_until(due()).await);
    let close = runtime.close_observation().unwrap();
    assert!(
        close.both_service_receipts
            && close.services_returned_at.unwrap() <= close.caller_joined_at.unwrap()
    );
    let receipts = runtime.close_receipts();
    assert_eq!(
        (receipts.0.unwrap().bus(), receipts.1.unwrap().bus()),
        (0, 1)
    );
    assert!(runtime.snapshot().diagnostic_complete());
    assert!(runtime.close_until(due()).await);
    assert_eq!(runtime.close_observation().unwrap().attempt, 1);
}

#[tokio::test]
async fn cancellation_and_timeout_retain_same_returned_but_unjoined_close_caller() {
    let (mut runtime, _fixture) = simulated::Fixture::new(false, false);
    let gate = Gate::new();
    let _release = Release(gate.clone());
    let worker = gate.clone();
    let mut pending = Box::pin(runtime.close_with(due(), move || worker.wait()));
    tokio::select! { _ = &mut pending => panic!("caller has not returned"), _ = gate.entered() => {} }
    drop(pending);
    let before = runtime.close_observation().unwrap();
    assert!(before.both_service_receipts && before.caller_joined_at.is_none());
    assert!(runtime.close_caller_pending() && runtime.owner.is_none());
    assert_eq!(runtime.close_receipts().0.is_none(), true);
    assert!(
        !runtime
            .close_until(Instant::now() + Duration::from_millis(10))
            .await
    );
    assert_eq!(
        runtime.close_observation().unwrap().started_at,
        before.started_at
    );
    gate.release();
    assert!(runtime.close_until(due()).await);
    let after = runtime.close_observation().unwrap();
    assert_eq!(after.attempt, before.attempt);
    assert_eq!(after.services_returned_at, before.services_returned_at);
    assert!(after.caller_joined_at.is_some() && runtime.owner.is_some());
}

#[tokio::test]
async fn cancelled_diagnostic_retains_blocked_worker_and_retry_joins_that_worker() {
    let (mut runtime, fixture) = simulated::Fixture::new(true, false);
    let mut pending = Box::pin(runtime.observe_initial_until(&[0x50], due()));
    tokio::select! { _ = &mut pending => panic!("fixture blocked"), _ = fixture.wait_apw_entered() => {} }
    drop(pending);
    assert!(runtime.snapshot().stopped());
    assert!(
        !runtime
            .close_until(Instant::now() + Duration::from_millis(80))
            .await
    );
    assert!(runtime.close_receipts().1.is_none());
    fixture.release();
    assert!(runtime.close_until(due()).await);
    assert!(runtime.close_receipts().1.is_some());
    assert!(!runtime.snapshot().diagnostic_complete());
    assert_eq!(fixture.apw_opcodes(), [2]);
}

#[tokio::test]
async fn close_tail_unwind_keeps_original_manager_and_move_only_service_receipts() {
    let (mut runtime, _fixture) = simulated::Fixture::new(false, false);
    assert!(
        !runtime
            .close_with(due(), || panic!("bounded tail unwind"))
            .await
    );
    assert!(runtime.owner.is_some() && !runtime.close_caller_pending());
    let stamps = {
        let (a, b) = runtime.close_receipts();
        (
            a.unwrap().worker_exit_observed_at(),
            b.unwrap().worker_exit_observed_at(),
        )
    };
    assert!(runtime.close_observation().unwrap().failure.is_some());
    assert!(runtime.close_until(due()).await);
    let (a, b) = runtime.close_receipts();
    assert_eq!(
        stamps,
        (
            a.unwrap().worker_exit_observed_at(),
            b.unwrap().worker_exit_observed_at()
        )
    );
    assert_eq!(runtime.close_observation().unwrap().attempt, 2);
}

#[tokio::test]
async fn expired_cleanup_keeps_owner_without_starting_close_then_actual_retry_succeeds() {
    let (mut runtime, fixture) = simulated::Fixture::new(false, false);
    assert!(!runtime.close_until(Instant::now()).await);
    assert!(runtime.owner.is_some() && !runtime.close_caller_pending());
    assert!(runtime.close_observation().is_none());
    assert!(fixture.apw_opcodes().is_empty() && fixture.bus0_events() == 0);
    assert!(runtime.close_until(due()).await);
}

#[tokio::test]
async fn sender_free_external_stop_refuses_new_management_and_closes_original_pair() {
    let (mut runtime, fixture) = simulated::Fixture::new(false, false);
    let stop = runtime.stop_handle();
    stop.stop();
    assert!(runtime.snapshot().stopped());
    assert!(runtime.merge_requested_voltage(Some(13.4), None).is_err());
    assert!(runtime.observe_initial_until(&[0x50], due()).await.is_err());
    assert!(runtime.execute_voltage_until(due()).await.is_err());
    assert!(runtime.close_until(due()).await);
    assert!(fixture.apw_opcodes().is_empty() && fixture.bus0_events() == 0);
}
