//! Real original worker threads and joined diagnostics; no injected actor
//! timestamps, acceptance values, readiness, roster DTOs or whole snapshots.
use super::*;
use crate::bb_management_owner::BbManagementOwner;
use crate::bb_management_runtime::BbManagementRuntime;
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use crate::HalError;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

#[path = "bb_pre_power_apw_test_support.rs"]
mod diagnostic_apw;
#[path = "bb_pre_power_bus0_test_support.rs"]
mod diagnostic_bus0;

pub(super) struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
}
impl Gate {
    fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            changed: Condvar::new(),
        }
    }
    pub(super) fn wait(&self) {
        self.entered.store(true, Ordering::SeqCst);
        let guard = self.released.lock().unwrap();
        let (guard, _) = self
            .changed
            .wait_timeout_while(guard, Duration::from_secs(10), |released| !*released)
            .unwrap();
        assert!(
            *guard,
            "fixture failed to release its original worker/callback"
        );
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

struct ReleaseGate(Arc<Gate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct Bus0 {
    diagnostic: Arc<diagnostic_bus0::Backend>,
    heartbeat: AtomicBool,
    disable: AtomicBool,
    position: AtomicUsize,
    fault: AtomicU8,
    writes: Mutex<Vec<(Instant, u8)>>,
    reads: Mutex<Vec<(Instant, u8, u8)>>,
    gate: Gate,
}
impl Bus0 {
    fn new(firmware_bad: bool) -> Arc<Self> {
        Arc::new(Self {
            diagnostic: diagnostic_bus0::Backend::new(
                if firmware_bad {
                    diagnostic_bus0::Fault::Firmware
                } else {
                    diagnostic_bus0::Fault::None
                },
                None,
            ),
            heartbeat: AtomicBool::new(false),
            disable: AtomicBool::new(false),
            position: AtomicUsize::new(0),
            fault: AtomicU8::new(0),
            writes: Mutex::new(Vec::new()),
            reads: Mutex::new(Vec::new()),
            gate: Gate::new(),
        })
    }
}
impl I2cSimBackend for Bus0 {
    fn service_identity(&self) -> Option<usize> {
        self.diagnostic.service_identity()
    }
    fn write(&self, bus: u8, address: u8, bytes: &[u8]) -> crate::Result<usize> {
        self.disable.store(false, Ordering::SeqCst);
        if bytes == crate::bb_pic_heartbeat::REQUEST {
            assert_eq!(bus, 0);
            assert!((0x20..=0x22).contains(&address));
            self.heartbeat.store(true, Ordering::SeqCst);
            self.position.store(0, Ordering::SeqCst);
            self.writes.lock().unwrap().push((Instant::now(), address));
            Ok(bytes.len())
        } else if bytes == [0x55, 0xaa, 5, 0x15, 0, 0, 0x1a] {
            assert_eq!(bus, 0);
            assert!((0x20..=0x22).contains(&address));
            self.heartbeat.store(false, Ordering::SeqCst);
            self.disable.store(true, Ordering::SeqCst);
            self.position.store(0, Ordering::SeqCst);
            Ok(bytes.len())
        } else {
            self.heartbeat.store(false, Ordering::SeqCst);
            self.diagnostic.write(bus, address, bytes)
        }
    }
    fn read(&self, bus: u8, address: u8, bytes: &mut [u8]) -> crate::Result<usize> {
        if self.disable.load(Ordering::SeqCst) {
            assert_eq!((bus, bytes.len()), (0, 1));
            bytes[0] = [0x15, 0][self.position.fetch_add(1, Ordering::SeqCst)];
            return Ok(1);
        }
        if self.fault.load(Ordering::SeqCst) == 7 && !self.heartbeat.load(Ordering::SeqCst) {
            self.gate.wait();
            bytes.fill(0);
            return Ok(bytes.len());
        }
        if !self.heartbeat.load(Ordering::SeqCst) {
            return self.diagnostic.read(bus, address, bytes);
        }
        assert_eq!((bus, bytes.len()), (0, 1));
        let index = self.position.fetch_add(1, Ordering::SeqCst);
        let fault = self.fault.load(Ordering::SeqCst);
        if (fault == 6 && index == 1) || (fault == 8 && index == 0) {
            self.gate.wait();
        }
        if fault == 5 && index == 1 {
            return Err(HalError::I2cEndpointRefused {
                bus,
                addr: address,
                detail: "authored heartbeat second-read failure".into(),
            });
        }
        let reply = match fault {
            1 => [6, 0x17, 1, 0, 0, 0x1e],
            2 => [6, 0x16, 0, 0, 0, 0x1c],
            3 => [6, 0x16, 1, 0, 0, 0x1c],
            4 => [5, 0x16, 1, 0, 0, 0x1c],
            _ => [6, 0x16, 1, 0, 0, 0x1d],
        };
        bytes[0] = reply[index];
        self.reads
            .lock()
            .unwrap()
            .push((Instant::now(), address, bytes[0]));
        Ok(1)
    }
    fn write_read(
        &self,
        bus: u8,
        address: u8,
        input: &[u8],
        output: &mut [u8],
    ) -> crate::Result<()> {
        self.diagnostic.write_read(bus, address, input, output)
    }
}

struct Cutoff {
    calls: AtomicUsize,
    mode: u8,
    gate: Gate,
}
impl Cutoff {
    fn new(mode: u8) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            mode,
            gate: Gate::new(),
        })
    }
}
impl BbHeartbeatCutoff for Cutoff {
    fn cutoff(&self) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            1 => Err("authored operational cutoff failure, physical outcome unknown".into()),
            2 => panic!("authored cutoff panic"),
            3 => {
                self.gate.wait();
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

struct Release {
    bus: Arc<Bus0>,
    cutoff: Arc<Cutoff>,
}
impl Drop for Release {
    fn drop(&mut self) {
        self.bus.gate.release();
        self.bus.diagnostic.release();
        self.cutoff.gate.release();
    }
}

fn runtime(bus: &Arc<Bus0>) -> BbManagementRuntime {
    let apw = diagnostic_apw::Backend::new(0x23, false, None);
    BbManagementRuntime::new(
        spawn_owned_sim_i2c_service(0, bus.clone(), (0x50..=0x57).collect()).unwrap(),
        spawn_owned_sim_i2c_service(1, apw, Vec::new()).unwrap(),
    )
}
fn owner(bus: &Arc<Bus0>) -> BbManagementOwner {
    let apw = diagnostic_apw::Backend::new(0x23, false, None);
    BbManagementOwner::new(
        spawn_owned_sim_i2c_service(0, bus.clone(), (0x50..=0x57).collect()).unwrap(),
        spawn_owned_sim_i2c_service(1, apw, Vec::new()).unwrap(),
    )
}
fn due() -> Instant {
    Instant::now() + Duration::from_secs(20)
}
async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(18), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
async fn diagnose(runtime: &mut BbManagementRuntime, selected: &[u8]) {
    let observed = runtime
        .observe_initial_until(selected, due())
        .await
        .unwrap();
    assert!(
        observed.diagnostic_complete() && !observed.stopped(),
        "{observed:?}"
    );
}
fn assert_joined(snapshot: &BbHeartbeatSnapshot) {
    assert!(snapshot.stopped_at.is_some() && snapshot.first_failure.is_some());
    assert!(snapshot.caller_started_at.unwrap() <= snapshot.caller_returned_at.unwrap());
    assert!(snapshot.caller_returned_at.unwrap() <= snapshot.caller_joined_at.unwrap());
    assert!(snapshot.monitor_started_at.unwrap() <= snapshot.monitor_returned_at.unwrap());
    assert!(snapshot.monitor_returned_at.unwrap() <= snapshot.monitor_joined_at.unwrap());
    let cutoff = snapshot.cutoff.as_ref().unwrap();
    assert!(cutoff.prepared_at <= cutoff.started_at.unwrap());
    assert!(cutoff.started_at.unwrap() <= cutoff.returned_at.unwrap());
    assert!(cutoff.returned_at.unwrap() <= cutoff.joined_at.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_joined_three_pic_roster_requires_five_sweeps_and_original_post_sweep_waits() {
    let bus = Bus0::new(false);
    let cutoff = Cutoff::new(0);
    let _release = Release {
        bus: bus.clone(),
        cutoff: cutoff.clone(),
    };
    let mut runtime = runtime(&bus);
    let selected = [0x52, 0x50, 0x51];
    diagnose(&mut runtime, &selected).await;
    runtime.start_heartbeat(cutoff.clone()).unwrap();
    until(|| runtime.heartbeat_snapshot().unwrap().complete_sweeps >= 1).await;
    assert!(
        runtime.require_stable_heartbeat().is_err(),
        "one sweep must not pass stability"
    );
    until(|| runtime.heartbeat_snapshot().unwrap().complete_sweeps >= 5).await;
    let ready = runtime.require_stable_heartbeat().unwrap();
    assert_eq!(ready.selected_factory_addresses, selected);
    assert!(
        ready
            .last_complete_at
            .unwrap()
            .duration_since(ready.started_at)
            >= Duration::from_millis(7150)
    );
    assert_eq!(
        ready.warmup_deadline.duration_since(ready.started_at),
        WARMUP_LIMIT
    );
    assert_eq!(cutoff.calls.load(Ordering::SeqCst), 0);
    for (index, round) in ready.retained_rounds.iter().take(5).enumerate() {
        assert_eq!(round.sequence, index as u64 + 1);
        assert_eq!(round.attempts.len(), 3);
        assert_eq!(
            round.deadline.duration_since(round.scheduled_start),
            ROUND_LIMIT
        );
        assert!(round.accepted_at.unwrap() < round.deadline);
        assert!(
            round
                .completed_at
                .unwrap()
                .duration_since(round.caller_started_at.unwrap())
                >= Duration::from_millis(630)
        );
        for (attempt, address) in round.attempts.iter().zip(selected) {
            assert_eq!(attempt.native_slot, usize::from(address - 0x50));
            assert_eq!(attempt.pic_address, Some(address - 0x30));
            assert_eq!(attempt.deadline, round.deadline);
            assert_eq!(
                attempt.returned_reads,
                Some(vec![
                    vec![6],
                    vec![0x16],
                    vec![1],
                    vec![0],
                    vec![0],
                    vec![0x1d]
                ])
            );
            assert!(attempt.failure.is_none());
        }
    }
    for pair in ready.retained_rounds.as_slices().0.windows(2) {
        assert!(
            pair[1]
                .caller_started_at
                .unwrap()
                .duration_since(pair[0].completed_at.unwrap())
                >= AFTER_SWEEP
        );
        assert_eq!(
            pair[1].scheduled_start,
            pair[0].completed_at.unwrap() + AFTER_SWEEP
        );
    }
    let before_restart = runtime.heartbeat_snapshot().unwrap();
    assert!(runtime.start_heartbeat(Cutoff::new(0)).is_err());
    assert_eq!(
        runtime.heartbeat_snapshot().unwrap().started_at,
        before_restart.started_at
    );
    runtime.stop_heartbeat();
    let deadline = Instant::now() + Duration::from_secs(3);
    assert!(runtime.close_until(deadline).await);
    let stopped = runtime.heartbeat_snapshot().unwrap();
    assert_joined(&stopped);
    assert_eq!(cutoff.calls.load(Ordering::SeqCst), 1);
    assert!(runtime.require_stable_heartbeat().is_err());
    assert!(runtime.close_receipts().0.is_some() && runtime.close_receipts().1.is_some());
    let close = runtime.close_observation().unwrap();
    assert!(close.caller_joined_at.unwrap() < deadline);
    assert!(stopped.caller_joined_at.unwrap() <= close.started_at);
    assert!(stopped.monitor_joined_at.unwrap() <= close.started_at);
    assert!(stopped.cutoff.as_ref().unwrap().joined_at.unwrap() <= close.started_at);
    assert!(runtime.start_heartbeat(Cutoff::new(0)).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_or_actual_foreign_fw_diagnostics_cannot_start_timer_or_cutoff() {
    for bad_firmware in [false, true] {
        let bus = Bus0::new(bad_firmware);
        let cutoff = Cutoff::new(0);
        let _release = Release {
            bus: bus.clone(),
            cutoff: cutoff.clone(),
        };
        let mut runtime = runtime(&bus);
        if bad_firmware {
            let observed = runtime.observe_initial_until(&[0x50], due()).await.unwrap();
            assert!(observed.stopped());
        }
        assert!(runtime.start_heartbeat(cutoff.clone()).is_err());
        assert!(runtime.heartbeat_snapshot().is_none());
        assert!(bus.writes.lock().unwrap().is_empty());
        assert_eq!(cutoff.calls.load(Ordering::SeqCst), 0);
        assert!(runtime.close_until(due()).await);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_strict_reply_failures_retain_available_raw_bytes_and_one_terminal_callback() {
    for fault in 1..=5 {
        let bus = Bus0::new(false);
        let cutoff = Cutoff::new(0);
        let _release = Release {
            bus: bus.clone(),
            cutoff: cutoff.clone(),
        };
        let mut runtime = runtime(&bus);
        diagnose(&mut runtime, &[0x50]).await;
        bus.fault.store(fault, Ordering::SeqCst);
        runtime.start_heartbeat(cutoff.clone()).unwrap();
        // The original owner is never polled to pump a heartbeat/cutoff event.
        until(|| cutoff.calls.load(Ordering::SeqCst) == 1).await;
        let failed = runtime.heartbeat_snapshot().unwrap();
        assert_eq!(failed.complete_sweeps, 0);
        assert_eq!(failed.current_round.attempts.len(), 1);
        let attempt = &failed.current_round.attempts[0];
        assert!(attempt.failure.is_some() && attempt.strict_completed_at.is_none());
        if fault == 5 {
            assert!(attempt.returned_reads.is_none() && attempt.transport_error.is_some());
        } else {
            assert_eq!(attempt.returned_reads.as_ref().unwrap().len(), 6);
        }
        let reason = failed.first_failure.clone();
        assert!(runtime.close_until(due()).await);
        let joined = runtime.heartbeat_snapshot().unwrap();
        assert_joined(&joined);
        assert_eq!(joined.first_failure, reason);
        assert_eq!(joined.complete_sweeps, 0);
        assert_eq!(cutoff.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn started_read_stall_fences_and_cuts_without_owner_pumping_then_keeps_late_unknown() {
    let bus = Bus0::new(false);
    let cutoff = Cutoff::new(0);
    let _release = Release {
        bus: bus.clone(),
        cutoff: cutoff.clone(),
    };
    let mut runtime = runtime(&bus);
    diagnose(&mut runtime, &[0x50]).await;
    bus.fault.store(6, Ordering::SeqCst);
    runtime.start_heartbeat(cutoff.clone()).unwrap();
    until(|| bus.gate.entered.load(Ordering::SeqCst)).await;
    {
        let _exclusive_controller_borrow = &mut runtime;
        until(|| cutoff.calls.load(Ordering::SeqCst) == 1).await;
        // No method on the borrowed controller drives the monitor. The later
        // ASIC integration uses this same independence; it is not tested here.
    }
    let failed = runtime.heartbeat_snapshot().unwrap();
    assert!(failed.first_failure.is_some());
    assert_eq!(failed.complete_sweeps, 0);
    // The synchronous request may have returned its timeout while the actual
    // service worker is still inside this backend read. No drain is inferred.
    assert!(
        !runtime
            .close_until(Instant::now() + Duration::from_millis(20))
            .await
    );
    assert!(runtime.close_receipts().0.is_none());
    bus.gate.release();
    assert!(runtime.close_until(due()).await);
    let final_state = runtime.heartbeat_snapshot().unwrap();
    assert_joined(&final_state);
    assert_eq!(final_state.complete_sweeps, 0);
    assert_eq!(final_state.first_failure, failed.first_failure);
    assert_eq!(final_state.current_round.attempts.len(), 1);
    assert!(final_state.current_round.attempts[0]
        .returned_reads
        .is_none());
    assert!(final_state.current_round.accepted_at.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_timer_expires_on_original_worker_without_writing_and_cannot_restart() {
    let bus = Bus0::new(false);
    let cutoff = Cutoff::new(0);
    let _release = Release {
        bus: bus.clone(),
        cutoff: cutoff.clone(),
    };
    let mut owner = owner(&bus);
    let diagnostic = owner.observe_pre_power_once(&[0x50], due()).await;
    assert!(diagnostic.diagnostics.historical.is_some() && diagnostic.stopped_at.is_none());
    bus.fault.store(7, Ordering::SeqCst);
    // Private original handle used solely to occupy the real service worker.
    // The production actor API has no handle or arbitrary-transaction escape.
    let original = owner.handles.bus0.clone();
    let occupied = std::thread::spawn(move || original.read_bytes(0x20, 1));
    until(|| bus.gate.entered.load(Ordering::SeqCst)).await;
    owner.start_heartbeat(cutoff.clone()).unwrap();
    until(|| cutoff.calls.load(Ordering::SeqCst) == 1).await;
    assert!(bus.writes.lock().unwrap().is_empty());
    assert!(
        owner.handles.bus0.terminal_safe_off_is_latched()
            && owner.handles.bus1.terminal_safe_off_is_latched()
    );
    let failed = owner.heartbeat_snapshot().unwrap();
    assert_eq!(failed.complete_sweeps, 0);
    assert!(owner.start_heartbeat(Cutoff::new(0)).is_err());
    bus.gate.release();
    let _ = occupied.join().unwrap();
    assert!(owner.join_callers_until(due()).await);
    owner.release_joined_heartbeat_cutoff().unwrap();
    assert!(owner.close_services_until(due()).unwrap());
    let closed = owner.heartbeat_snapshot().unwrap();
    assert_joined(&closed);
    assert_eq!(closed.started_at, failed.started_at);
    assert_eq!(closed.first_failure, failed.first_failure);
    assert!(closed.current_round.attempts[0].returned_reads.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_cleanup_retains_blocked_cutoff_and_both_services_until_actual_join() {
    let bus = Bus0::new(false);
    let cutoff = Cutoff::new(3);
    let _release = Release {
        bus: bus.clone(),
        cutoff: cutoff.clone(),
    };
    let mut runtime = runtime(&bus);
    diagnose(&mut runtime, &[0x50]).await;
    runtime.start_heartbeat(cutoff.clone()).unwrap();
    until(|| runtime.heartbeat_snapshot().unwrap().complete_sweeps == 1).await;
    runtime.stop_heartbeat();
    until(|| cutoff.gate.entered.load(Ordering::SeqCst)).await;
    let mut closing = Box::pin(runtime.close_until(due()));
    tokio::select! {
        _ = &mut closing => panic!("blocked retained cutoff must not be dropped by cleanup"),
        _ = tokio::time::sleep(Duration::from_millis(30)) => {},
    }
    drop(closing);
    let pending = runtime.heartbeat_snapshot().unwrap();
    assert!(pending.cutoff.as_ref().unwrap().returned_at.is_none());
    assert!(pending.cutoff.as_ref().unwrap().joined_at.is_none());
    assert!(runtime.close_receipts().0.is_none() && runtime.close_receipts().1.is_none());
    assert!(
        !runtime
            .close_until(Instant::now() + Duration::from_millis(10))
            .await
    );
    cutoff.gate.release();
    assert!(runtime.close_until(due()).await);
    assert_joined(&runtime.heartbeat_snapshot().unwrap());
    assert_eq!(cutoff.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operational_cutoff_error_or_panic_remains_error_after_join_and_no_late_readiness() {
    for mode in [1, 2] {
        let bus = Bus0::new(false);
        let cutoff = Cutoff::new(mode);
        let _release = Release {
            bus: bus.clone(),
            cutoff: cutoff.clone(),
        };
        let mut runtime = runtime(&bus);
        diagnose(&mut runtime, &[0x50]).await;
        runtime.start_heartbeat(cutoff.clone()).unwrap();
        until(|| runtime.heartbeat_snapshot().unwrap().complete_sweeps == 1).await;
        runtime.cancel();
        until(|| cutoff.calls.load(Ordering::SeqCst) == 1).await;
        assert!(runtime.close_until(due()).await);
        let snapshot = runtime.heartbeat_snapshot().unwrap();
        assert_joined(&snapshot);
        assert!(snapshot.cutoff.unwrap().result.unwrap().is_err());
        assert!(runtime.require_stable_heartbeat().is_err());
        assert_eq!(cutoff.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_post_completion_lock_delay_cannot_backdate_whole_roster_acceptance() {
    let bus = Bus0::new(false);
    let cutoff = Cutoff::new(0);
    let _release = Release {
        bus: bus.clone(),
        cutoff: cutoff.clone(),
    };
    let mut owner = owner(&bus);
    let observed = owner.observe_pre_power_once(&[0x50], due()).await;
    assert!(observed.diagnostics.historical.is_some() && observed.stopped_at.is_none());
    // Hold the real first wire read while installing the promotion pause, so
    // this fixture does not depend on winning the first 210 ms scheduling race.
    bus.fault.store(8, Ordering::SeqCst);
    owner.start_heartbeat(cutoff.clone()).unwrap();
    until(|| bus.gate.entered.load(Ordering::SeqCst)).await;
    let shared = owner.heartbeat.as_ref().unwrap().shared.clone();
    // This hook pauses the actual caller immediately before its promotion
    // lock. It accepts no timestamp, reply, roster or readiness value.
    let pause = Arc::new(Gate::new());
    let _release_pause = ReleaseGate(pause.clone());
    *shared.before_promotion.lock().unwrap() = Some(pause.clone());
    bus.gate.release();
    until(|| pause.entered.load(Ordering::SeqCst)).await;
    let holding = shared.clone();
    let lock_task = tokio::task::spawn_blocking(move || {
        let state = holding.state.lock().unwrap();
        let locked_at = Instant::now();
        let deadline = state.current_round.deadline;
        assert!(locked_at < deadline);
        assert_eq!(state.current_round.attempts.len(), 1);
        assert!(state.current_round.attempts[0].strict_completed_at.unwrap() < deadline);
        pause.release();
        // A real mutex is held across real wall time. Actor state is read only;
        // neither its original deadline nor any acceptance field is replaced.
        std::thread::sleep(
            (deadline + Duration::from_millis(30)).saturating_duration_since(Instant::now()),
        );
        let released_at = Instant::now();
        drop(state);
        (locked_at, deadline, released_at)
    });
    let (locked_at, deadline, released_at) = lock_task.await.unwrap();
    assert!(locked_at < deadline && released_at > deadline);
    drop(shared);
    until(|| cutoff.calls.load(Ordering::SeqCst) == 1).await;
    assert!(owner.join_callers_until(due()).await);
    owner.release_joined_heartbeat_cutoff().unwrap();
    assert!(owner.close_services_until(due()).unwrap());
    let result = owner.heartbeat_snapshot().unwrap();
    assert_joined(&result);
    assert_eq!(result.complete_sweeps, 0);
    assert!(result.current_round.completed_at.unwrap() < deadline);
    assert!(result.current_round.accepted_at.is_none());
    assert!(result.current_round.attempts[0].returned_reads.is_some());
    assert!(owner.require_stable_heartbeat().is_err());
}
