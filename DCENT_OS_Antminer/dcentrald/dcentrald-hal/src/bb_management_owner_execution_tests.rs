use super::*;
use crate::i2c::spawn_owned_sim_i2c_service;
use std::time::Duration;

#[path = "bb_management_owner_execution_test_support.rs"]
mod apw;
#[path = "bb_pre_power_bus0_test_support.rs"]
mod bus0;

struct Release(Arc<apw::Backend>, Arc<bus0::Backend>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
        self.1.release();
    }
}

fn owner(a: &Arc<bus0::Backend>, b: &Arc<apw::Backend>) -> BbManagementOwner {
    BbManagementOwner::new(
        spawn_owned_sim_i2c_service(
            0,
            crate::bb_management_runtime::wire_sim::RuntimeWire::new(a.clone()),
            (0x50..=0x57).collect(),
        )
        .unwrap(),
        spawn_owned_sim_i2c_service(1, b.clone(), Vec::new()).unwrap(),
    )
}

async fn prepared(a: &Arc<bus0::Backend>, b: &Arc<apw::Backend>) -> BbManagementOwner {
    let mut owner = owner(a, b);
    let result = owner
        .observe_pre_power_once(&[0x50], Instant::now() + Duration::from_secs(12))
        .await;
    assert!(result.stopped_at.is_none(), "{result:?}");
    struct InertCutoff;
    impl crate::bb_management_runtime::BbHeartbeatCutoff for InertCutoff {
        fn cutoff(&self) -> Result<(), String> {
            Ok(())
        }
    }
    owner.start_heartbeat(Arc::new(InertCutoff)).unwrap();
    owner
        .wait_stable_heartbeat_until(Instant::now() + Duration::from_secs(18))
        .await
        .unwrap();
    owner.merge_requested_voltage(Some(13.4), None).unwrap();
    owner
}

async fn finish(owner: &mut BbManagementOwner) {
    assert!(
        owner
            .join_callers_until(Instant::now() + Duration::from_secs(3))
            .await
    );
    owner.release_joined_heartbeat_cutoff().unwrap();
    assert!(tokio::task::block_in_place(
        || owner.close_services_until(Instant::now() + Duration::from_secs(3))
    )
    .unwrap());
    assert!(owner.close_receipts().0.is_some() && owner.close_receipts().1.is_some());
}

async fn launch(owner: &mut BbManagementOwner, deadline: Instant) {
    owner.begin_execution(deadline).unwrap();
    owner.bus0_task = Some(runtime_bus0::start(&owner.state, &owner.handles, deadline));
    assert!(
        runtime_bus0::join_until(
            &mut owner.bus0_task,
            &owner.state,
            &owner.handles,
            deadline,
            true
        )
        .await
    );
    assert!(owner.start_execution_caller(deadline));
}

async fn finished(owner: &BbManagementOwner) {
    tokio::time::timeout(Duration::from_secs(6), async {
        while !owner.execution_task.as_ref().unwrap().is_finished() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_pair_serializes_two_executions_and_commits_only_actual_request_history() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = apw::Backend::new(0x76, 0x17, 0x68, None, None);
    let mut owner = prepared(&a, &b).await;
    let initial_trace = a.trace();
    let initial_history = owner.snapshot().committed_request_history;
    assert_eq!(initial_history.previous_request, None);
    let mut retained = Vec::new();
    for (sequence, expected) in [(1, 13.75), (2, 13.7)] {
        let deadline = Instant::now() + Duration::from_secs(8);
        let snapshot = owner.execute_voltage_once(deadline).await.unwrap();
        assert!(snapshot.stopped_at.is_none(), "{snapshot:?}");
        assert!(!snapshot.execution_caller_pending && !snapshot.bus0_caller_pending);
        let completed = snapshot.last_complete_execution.unwrap();
        assert_eq!(
            (completed.sequence, completed.profile_generation),
            (sequence, 1)
        );
        assert_eq!(completed.deadline, deadline);
        assert!(completed.caller_joined_at.unwrap() <= completed.accepted_at.unwrap());
        assert!(completed.accepted_at.unwrap() < deadline);
        let actual = completed.attempt.as_ref().unwrap();
        assert!(
            snapshot.latest_bus0.unwrap().caller_joined_at.unwrap() <= actual.caller_started_at
        );
        assert_eq!(actual.plan.unwrap().decision, Decision::Request(expected));
        assert_eq!(
            snapshot.committed_request_history.previous_request,
            Some(expected)
        );
        assert_eq!(snapshot.committed_request_history.repeated_requests, 0);
        assert_eq!(
            actual.prior_history.previous_request,
            if sequence == 1 { None } else { Some(13.75) }
        );
        retained.push(completed);
    }
    assert_eq!(
        retained[0]
            .attempt
            .as_ref()
            .unwrap()
            .plan
            .unwrap()
            .history
            .previous_request,
        Some(13.75)
    );
    assert_eq!(
        &b.opcodes()[4..],
        [2, 1, 6, 3, 0x83, 3, 2, 1, 6, 3, 0x83, 3]
    );
    assert!(a.trace()[initial_trace.len()..]
        .iter()
        .all(|event| !matches!(event, bus0::Event::Page(_, _))));
    let history = owner.snapshot().committed_request_history;
    let preview = owner
        .observe_voltage_once(Instant::now() + Duration::from_secs(6))
        .await
        .unwrap();
    assert_eq!(preview.committed_request_history, history);
    owner.merge_requested_voltage(Some(13.3), None).unwrap();
    assert_eq!(owner.snapshot().profile_generation, 2);
    assert_eq!(owner.snapshot().committed_request_history, history);
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_return_before_actual_join_cannot_commit_or_replace_profile() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = apw::Backend::new(0x76, 0x17, 0x68, None, None);
    let mut owner = prepared(&a, &b).await;
    let deadline = Instant::now() + Duration::from_secs(8);
    launch(&mut owner, deadline).await;
    finished(&owner).await;
    let unjoined = owner.snapshot();
    assert!(unjoined.execution_caller_pending);
    assert!(unjoined
        .latest_execution
        .as_ref()
        .unwrap()
        .attempt
        .as_ref()
        .unwrap()
        .caller_completed_at
        .is_some());
    assert!(unjoined.last_complete_execution.is_none());
    assert_eq!(unjoined.committed_request_history.previous_request, None);
    assert!(owner.merge_requested_voltage(Some(13.3), None).is_err());
    assert_eq!(
        owner.snapshot().requested_profile,
        unjoined.requested_profile
    );
    assert_eq!(owner.snapshot().profile_generation, 1);
    assert!(
        join_until(
            &mut owner.execution_task,
            &owner.state,
            &owner.handles,
            deadline,
            true
        )
        .await
    );
    assert_eq!(
        owner.snapshot().committed_request_history.previous_request,
        Some(13.75)
    );
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn numerical_equal_target_never_creates_or_commits_an_electrical_request() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = apw::Backend::new(0x76, 0x17, 0x68, None, None);
    let mut owner = prepared(&a, &b).await;
    owner.merge_requested_voltage(Some(13.8), None).unwrap();
    let result = owner
        .execute_voltage_once(Instant::now() + Duration::from_secs(8))
        .await
        .unwrap();
    assert!(result.stopped_at.is_none(), "{result:?}");
    assert!(result
        .last_complete_execution
        .unwrap()
        .attempt
        .unwrap()
        .exchange
        .is_none());
    assert_eq!(result.committed_request_history.previous_request, None);
    assert!(!b.opcodes().contains(&0x83));
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_future_retains_real_caller_and_fences_both_workers_without_history() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = apw::Backend::new(0x76, 0x17, 0x68, None, Some((0x83, apw::Phase::Write)));
    let _release = Release(b.clone(), a.clone());
    let mut owner = prepared(&a, &b).await;
    {
        let future = owner.execute_voltage_once(Instant::now() + Duration::from_secs(8));
        tokio::pin!(future);
        tokio::select! {
            _=b.wait_entered()=>{},
            result=&mut future=>panic!("execution returned before blocked transfer: {result:?}"),
        }
    }
    let cancelled = owner.snapshot();
    assert!(cancelled.stopped_at.is_some() && cancelled.execution_caller_pending);
    assert!(
        owner.handles.bus0.terminal_safe_off_is_latched()
            && owner.handles.bus1.terminal_safe_off_is_latched()
    );
    assert!(owner
        .close_services_until(Instant::now() + Duration::from_millis(20))
        .is_err());
    assert_eq!(cancelled.committed_request_history.previous_request, None);
    b.release();
    finish(&mut owner).await;
    let final_state = owner.snapshot();
    assert!(!final_state.execution_caller_pending);
    assert!(final_state.last_complete_execution.is_none());
    assert!(final_state
        .latest_execution
        .unwrap()
        .caller_joined_at
        .is_some());
    assert_eq!(b.opcodes().last(), Some(&0x83));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadline_join_keeps_service_owner_until_blocked_transfer_really_exits() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = apw::Backend::new(0x76, 0x17, 0x68, None, Some((0x83, apw::Phase::Write)));
    let _release = Release(b.clone(), a.clone());
    let mut owner = prepared(&a, &b).await;
    let deadline = Instant::now() + Duration::from_secs(6);
    {
        let future = owner.execute_voltage_once(deadline);
        tokio::pin!(future);
        tokio::select! {
            _=b.wait_entered()=>{},
            result=&mut future=>panic!("execution returned before transfer: {result:?}"),
        }
        let result = future.await.unwrap();
        assert!(result.stopped_at.is_some());
    }
    assert!(
        owner
            .join_callers_until(Instant::now() + Duration::from_secs(2))
            .await
    );
    assert!(!owner.snapshot().execution_caller_pending);
    owner.release_joined_heartbeat_cutoff().unwrap();
    assert!(!tokio::task::block_in_place(
        || owner.close_services_until(Instant::now() + Duration::from_millis(30))
    )
    .unwrap());
    assert!(owner.close_receipts().1.is_none());
    assert_eq!(
        owner.snapshot().committed_request_history.previous_request,
        None
    );
    b.release();
    finish(&mut owner).await;
    assert!(owner.snapshot().last_complete_execution.is_none());
    assert_eq!(b.opcodes().last(), Some(&0x83));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_generation_before_actual_join_refuses_an_otherwise_complete_wire_result() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = apw::Backend::new(0x76, 0x17, 0x68, None, None);
    let mut owner = prepared(&a, &b).await;
    let deadline = Instant::now() + Duration::from_secs(8);
    launch(&mut owner, deadline).await;
    finished(&owner).await;
    // Corrupt only the owner generation through this private test seam. No
    // runtime API can replace a profile while the actual caller is pending.
    lock(&owner.state, &owner.handles)
        .execution
        .profile_generation += 1;
    assert!(
        join_until(
            &mut owner.execution_task,
            &owner.state,
            &owner.handles,
            deadline,
            true
        )
        .await
    );
    let refused = owner.snapshot();
    assert!(refused.stopped_at.is_some());
    assert_eq!(refused.committed_request_history.previous_request, None);
    assert!(refused.last_complete_execution.is_none());
    assert!(refused
        .latest_execution
        .unwrap()
        .failure
        .unwrap()
        .contains("identity changed"));
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_execution_refuses_observation_and_cleanup_cannot_promote_success() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = apw::Backend::new(0x76, 0x17, 0x68, None, None);
    let mut owner = prepared(&a, &b).await;
    launch(&mut owner, Instant::now() + Duration::from_secs(8)).await;
    finished(&owner).await;
    let opcodes = b.opcodes();
    assert!(owner
        .observe_runtime_once(Instant::now() + Duration::from_secs(8))
        .await
        .is_err());
    assert!(
        owner.handles.bus0.terminal_safe_off_is_latched()
            && owner.handles.bus1.terminal_safe_off_is_latched()
    );
    assert!(owner
        .close_services_until(Instant::now() + Duration::from_millis(20))
        .is_err());
    finish(&mut owner).await;
    assert_eq!(b.opcodes(), opcodes);
    assert_eq!(
        owner.snapshot().committed_request_history.previous_request,
        None
    );
    assert!(owner.snapshot().last_complete_execution.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_set_preserves_prior_success_and_does_not_commit_the_proposed_history() {
    let a = bus0::Backend::new(bus0::Fault::None, None);
    let b = apw::Backend::new(0x76, 0x17, 0x68, None, None);
    let mut owner = prepared(&a, &b).await;
    let first = owner
        .execute_voltage_once(Instant::now() + Duration::from_secs(8))
        .await
        .unwrap();
    b.fail_set_write();
    let next = owner
        .execute_voltage_once(Instant::now() + Duration::from_secs(8))
        .await
        .unwrap();
    assert!(next.stopped_at.is_some());
    assert_eq!(
        next.committed_request_history,
        first.committed_request_history
    );
    assert_eq!(
        next.last_complete_execution.unwrap().accepted_at,
        first.last_complete_execution.unwrap().accepted_at
    );
    let latest = next.latest_execution.unwrap();
    assert!(latest.accepted_at.is_none());
    assert!(latest.failure.unwrap().contains("Transport"));
    assert_eq!(
        latest
            .attempt
            .unwrap()
            .plan
            .unwrap()
            .history
            .previous_request,
        Some(13.7)
    );
    assert_eq!(b.opcodes().last(), Some(&0x83));
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unprepared_expired_or_terminal_owner_emits_no_execution_transactions() {
    for mode in 0..3 {
        let a = bus0::Backend::new(bus0::Fault::None, None);
        let b = apw::Backend::new(0x76, 0x17, 0x68, None, None);
        let mut owner = owner(&a, &b);
        if mode == 2 {
            owner.cancel();
        }
        let deadline = if mode == 1 {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(2)
        };
        assert!(owner.execute_voltage_once(deadline).await.is_err());
        assert!(a.trace().is_empty() && b.trace().is_empty());
        assert_eq!(
            owner.snapshot().committed_request_history.previous_request,
            None
        );
        finish(&mut owner).await;
    }
}
