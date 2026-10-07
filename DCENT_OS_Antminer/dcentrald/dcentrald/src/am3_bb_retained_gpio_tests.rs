use super::*;
use dcentrald_hal::platform::{config::PlatformConfig, FanCommandReceipt};
use std::sync::Condvar;

pub(super) struct IoPause {
    pub attribute: &'static str,
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}
impl IoPause {
    fn new(attribute: &'static str) -> Arc<Self> {
        Arc::new(Self {
            attribute,
            state: Mutex::new((false, false)),
            changed: Condvar::new(),
        })
    }
    pub(super) fn after_actual_write(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).unwrap();
        }
    }
    pub(super) fn after_actual_completion(&self) {
        // Same rendezvous, reached only after the real terminal phase body and
        // its recorded successful completion. No result or clock is supplied.
        self.after_actual_write();
    }
    fn entered(&self) -> bool {
        self.state.lock().unwrap().0
    }
    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}
struct ReleasePause(Arc<IoPause>);
impl Drop for ReleasePause {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct Files {
    root: std::path::PathBuf,
}
impl Files {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let name = format!(
            "dcent-bb-retained-gpio-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        );
        let root = std::env::temp_dir().join(name);
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("export"), "").unwrap();
        let files = Self { root };
        for gpio in [49, 60, 27, 22, 59] {
            files.add(gpio);
        }
        files
    }
    fn add(&self, gpio: u32) {
        let path = self.root.join(format!("gpio{gpio}"));
        std::fs::create_dir(&path).unwrap();
        for (name, value) in [("direction", "in"), ("active_low", "0"), ("value", "0")] {
            std::fs::write(path.join(name), value).unwrap();
        }
    }
    fn attr(&self, gpio: u32, name: &str) -> std::path::PathBuf {
        self.root.join(format!("gpio{gpio}")).join(name)
    }
    fn read(&self, gpio: u32, name: &str) -> String {
        std::fs::read_to_string(self.attr(gpio, name))
            .unwrap()
            .trim()
            .to_owned()
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        // Only this test's newly created, verified private temporary tree can
        // be recursively removed. No source, real sysfs or device is touched.
        let path = self.root.canonicalize().unwrap();
        let base = std::env::temp_dir().canonicalize().unwrap();
        assert!(path.starts_with(&base) && path != base);
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("dcent-bb-retained-gpio-"));
        std::fs::remove_dir_all(path).unwrap();
    }
}
struct Fan {
    writes: Mutex<Vec<u8>>,
    fail: AtomicBool,
}
impl FanAccess for Fan {
    fn set_speed(&self, pwm: u8) {
        self.writes.lock().unwrap().push(pwm);
    }
    fn set_speed_checked(&self, pwm: u8) -> dcentrald_hal::Result<FanCommandReceipt> {
        self.set_speed(pwm);
        if self.fail.load(Ordering::SeqCst) {
            return Err(dcentrald_hal::HalError::Fan(
                "authored checked-fan failure".into(),
            ));
        }
        FanCommandReceipt::from_matching_readback(pwm, self.get_speed_pwm())
    }
    fn get_rpm(&self) -> u32 {
        1234
    }
    fn get_speed_pwm(&self) -> u8 {
        self.writes.lock().unwrap().last().copied().unwrap_or(0)
    }
}
fn platform() -> BeagleBonePlatform {
    BeagleBonePlatform::with_config(PlatformConfig::s19j_beaglebone())
}
fn fixture(ids: &[u8]) -> (RetainedGpioLifecycle, Files, Arc<Fan>, SafetyWatchdogOwner) {
    let files = Files::new();
    let cutoffs = am3_bb_prepare_board_cutoff_set_at_with_direction_readback(
        &files.root,
        59,
        true,
        |direction| {
            // Explicit ordinary-file model of existing kernel direction=low ABI.
            std::fs::write(direction.parent().unwrap().join("value"), "0")?;
            Ok("out\n".to_owned())
        },
        Am3BbRetainedReadbackMode::OrdinaryFileFixture,
    )
    .unwrap();
    let fan = Arc::new(Fan {
        writes: Mutex::new(Vec::new()),
        fail: AtomicBool::new(false),
    });
    let guard = Am3BbRunSafetyGuard {
        dspic_i2c: None,
        active_dspic_addrs: Vec::new(),
        reset_gpios: vec![49, 60, 27, 22],
        board_enable: cutoffs.runtime,
        heartbeat_board_cutoff: Some(cutoffs.heartbeat),
        panic_board_cutoff: Some(cutoffs.panic),
        fan: Some(fan.clone()),
        fan_min_pwm: 10,
        fan_max_pwm: 255,
        safe_pwm: am3_bb_quiet_safe_pwm(10, 255),
        board_cutoff_receipt_issued: false,
        teardown_done: false,
    };
    let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
    watchdog.claim_am3_bb_route_scope().unwrap();
    let never = watchdog.issue_am3_bb_never_energized().unwrap();
    let mut value = RetainedGpioLifecycle::adopt(&platform(), ids, guard, never)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    value.core.as_mut().unwrap().root = files.root.clone();
    (value, files, fan, watchdog)
}
fn due() -> Instant {
    Instant::now() + Duration::from_secs(8)
}
fn run(body: impl std::future::Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(body);
}
async fn close_pre_power(value: &mut RetainedGpioLifecycle) {
    value.stop_and_join_until(due()).await.unwrap();
    let never = value.take_never_energized_after_join().unwrap();
    let history = value.close_until(due()).await.unwrap();
    assert!(history.closed_at.is_some() && history.close_joined_at.is_some());
    assert!(value.task.is_none() && value.close_task.is_none() && value.core.is_none());
    drop(never); // This inert watchdog fixture does not claim physical closeout.
}
async fn close_after_on(value: &mut RetainedGpioLifecycle) {
    value.stop_and_join_until(due()).await.unwrap();
    assert!(value.take_never_energized_after_join().is_err());
    value
        .run_until(GpioPhase::TerminalReset, due())
        .await
        .unwrap();
    let history = value.close_until(due()).await.unwrap();
    assert!(history.closed_at.unwrap() <= history.close_joined_at.unwrap());
    assert!(history.cancel_lane_dropped_at.unwrap() >= history.close_joined_at.unwrap());
    assert!(
        value.core.is_none()
            && value.task.is_none()
            && value.close_task.is_none()
            && value.cancel_cutoff.is_none()
    );
}

#[test]
fn exact_physical_selection_preserves_order_and_rejects_invalid_sets_before_adoption() {
    for (ids, pins) in [
        (vec![2, 0], vec![27, 49]),
        (vec![3, 1], vec![22, 60]),
        (vec![0, 1, 2, 3], vec![49, 60, 27, 22]),
    ] {
        let selected = selected_resets(&platform(), &ids).unwrap();
        assert_eq!(selected.iter().map(|s| s.chain_id).collect::<Vec<_>>(), ids);
        assert_eq!(selected.iter().map(|s| s.gpio).collect::<Vec<_>>(), pins);
    }
    for ids in [&[][..], &[4], &[0, 0], &[0, 1, 2, 3, 4], &[255]] {
        assert!(selected_resets(&platform(), ids).is_err());
    }
    let wrong = BeagleBonePlatform::with_config_and_board_target(
        PlatformConfig::s19j_beaglebone(),
        "other",
        platform().board_target().clone(),
    );
    assert!(selected_resets(&wrong, &[0]).is_err());
}

#[test]
fn selected_retained_inodes_own_full_ordered_enable_reset_and_capped_cooling() {
    run(async {
        let (mut value, files, fan, _watchdog) = fixture(&[2, 0]);
        let prepared = value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        assert_eq!(prepared.retained_reset_attributes, 6);
        assert_eq!(files.read(59, "value"), "0");
        for gpio in [27, 49] {
            assert_eq!(files.read(gpio, "value"), "1");
        }
        for gpio in [60, 22] {
            assert_eq!(files.read(gpio, "direction"), "in");
        }
        let core = value.core.as_ref().unwrap();
        assert!(core.guard.reset_gpios.is_empty());
        let extra = value.cancel_cutoff.as_ref().unwrap();
        assert!(Arc::ptr_eq(
            &value.stop,
            &core.guard.board_enable.io.terminal
        ));
        assert!(Arc::ptr_eq(
            &extra.terminal,
            &core.guard.board_enable.io.terminal
        ));
        assert!(Arc::ptr_eq(
            &extra.on_writer_thread,
            &core.guard.board_enable.io.on_writer_thread
        ));
        let fds = [
            core.guard.board_enable.on_writer.as_raw_fd(),
            core.guard.board_enable.io.direction_writer.as_raw_fd(),
            core.guard
                .heartbeat_board_cutoff
                .as_ref()
                .unwrap()
                .direction_writer
                .as_raw_fd(),
            core.guard
                .panic_board_cutoff
                .as_ref()
                .unwrap()
                .direction_writer
                .as_raw_fd(),
            extra.direction_writer.as_raw_fd(),
        ];
        assert_eq!(
            fds.into_iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            5
        );
        let original = files.root.join("retained27");
        std::fs::rename(files.root.join("gpio27"), &original).unwrap();
        files.add(27);
        let deadline = due();
        value
            .run_until(GpioPhase::EnableAuxiliary, deadline)
            .await
            .unwrap();
        assert_eq!(files.read(59, "value"), "1");
        let enabled = value.snapshot();
        let on = enabled
            .events
            .iter()
            .find(|e| e.action == "original-board-enable")
            .unwrap();
        assert!(enabled.never_energized_consumed_at.unwrap() <= on.started_at);
        assert!(
            enabled.calls[1]
                .completed_at
                .unwrap()
                .duration_since(on.returned_at.unwrap())
                >= AUX_SETTLE
        );
        assert!(enabled.calls[1].promoted_at.unwrap() < deadline);
        value
            .run_until(GpioPhase::PostPicReset, due())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(original.join("value")).unwrap(),
            "0"
        );
        assert_eq!(files.read(49, "value"), "0");
        assert_eq!(files.read(27, "direction"), "in");
        let history = value.snapshot();
        let released: Vec<_> = history
            .events
            .iter()
            .filter(|e| e.action == "write" && e.attribute == "value" && e.requested == b"0")
            .map(|e| e.gpio)
            .collect();
        assert_eq!(released, [27, 49]);
        assert!(history
            .events
            .iter()
            .filter(|e| e.action == "write")
            .all(|e| e.returned_at.is_some() && e.error.is_none()));
        assert!(fan.writes.lock().unwrap().iter().all(|pwm| *pwm <= 30));
        assert!(value
            .run_until(GpioPhase::PostPicReset, due())
            .await
            .is_err());
        close_after_on(&mut value).await;
    });
}

#[test]
fn later_open_failure_retains_each_earlier_descriptor_and_never_energized_token() {
    run(async {
        let (mut value, files, _fan, _watchdog) = fixture(&[2, 0]);
        std::fs::remove_file(files.attr(49, "active_low")).unwrap();
        std::fs::create_dir(files.attr(49, "active_low")).unwrap();
        assert!(value.run_until(GpioPhase::Prepare, due()).await.is_err());
        let history = value.snapshot();
        assert_eq!(history.retained_reset_attributes, 4);
        assert!(history
            .events
            .iter()
            .any(|e| e.gpio == 49 && e.attribute == "active_low" && e.error.is_some()));
        assert!(!history
            .events
            .iter()
            .any(|e| e.action == "write" && e.attribute == "value"));
        assert!(history.calls[0].joined_at.is_some() && history.calls[0].promoted_at.is_none());
        assert!(
            history.calls[0].worker_returned_at.unwrap() <= history.calls[0].joined_at.unwrap()
        );
        assert!(history.calls[0].completed_at.is_none());
        assert!(value.core.as_ref().unwrap().resets[0].value.is_some());
        assert!(value.core.as_ref().unwrap().resets[1].direction.is_some());
        assert_eq!(files.read(59, "value"), "0");
        close_pre_power(&mut value).await;
    });
}

#[test]
fn actual_attribute_drift_and_bounded_malformed_reads_refuse_before_on_without_repair() {
    run(async {
        for (attr, bytes) in [
            ("active_low", b"0".to_vec()),
            ("direction", b"in".to_vec()),
            ("value", b"0".to_vec()),
            ("value", vec![b'1'; 64]),
            ("value", vec![0xff]),
        ] {
            let (mut value, files, _fan, _watchdog) = fixture(&[0]);
            value.run_until(GpioPhase::Prepare, due()).await.unwrap();
            std::fs::write(files.attr(49, attr), &bytes).unwrap();
            assert!(value
                .run_until(GpioPhase::EnableAuxiliary, due())
                .await
                .is_err());
            let history = value.snapshot();
            assert!(history.never_energized_consumed_at.is_none());
            assert!(!history
                .events
                .iter()
                .any(|e| e.action == "original-board-enable"));
            assert!(history.events.iter().any(|e| e.action == "read"
                && e.gpio == 49
                && e.attribute == attr
                && e.observed == bytes));
            assert_eq!(files.read(59, "value"), "0");
            close_pre_power(&mut value).await;
        }
    });
}

#[test]
fn actual_read_only_fixture_descriptor_error_preserves_failed_write_and_blocks_completion() {
    run(async {
        let (mut value, files, _fan, _watchdog) = fixture(&[0]);
        value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        // Explicit backend fault fixture: a genuinely read-only ordinary-file
        // descriptor makes the actual std::io::Write syscall fail. No fake
        // success/error receipt is passed into the production operation.
        value.core.as_mut().unwrap().resets[0].value =
            Some(File::open(files.attr(49, "value")).unwrap());
        assert!(value
            .run_until(GpioPhase::TerminalReset, due())
            .await
            .is_err());
        let history = value.snapshot();
        assert!(history.events.iter().any(|e| e.action == "write"
            && e.gpio == 49
            && e.attribute == "value"
            && e.requested == b"1"
            && e.error.is_some()
            && e.number.is_none()));
        assert!(history.calls.last().unwrap().completed_at.is_none());
        assert!(history.calls.last().unwrap().worker_returned_at.is_some());
        assert!(history.calls.last().unwrap().join_failure.is_none());
        assert!(history.calls.last().unwrap().unpromoted_exit_at.is_some());
        assert_eq!(files.read(59, "value"), "0");
        close_pre_power(&mut value).await;

        let (mut value, files, _fan, _watchdog) = fixture(&[0]);
        value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        value
            .run_until(GpioPhase::EnableAuxiliary, due())
            .await
            .unwrap();
        value
            .run_until(GpioPhase::TerminalReset, due())
            .await
            .unwrap();
        assert!(value.core.as_ref().unwrap().terminal_complete);
        assert!(value.terminal_promoted);
        assert!(value
            .run_until(
                GpioPhase::TerminalReset,
                Instant::now() - Duration::from_millis(1)
            )
            .await
            .is_err());
        assert!(!value.terminal_promoted);
        assert!(value.close_until(due()).await.is_err());
        value
            .run_until(GpioPhase::TerminalReset, due())
            .await
            .unwrap();
        assert!(value.terminal_promoted);
        // A subsequent actual backend failure invalidates prior completion.
        value.core.as_mut().unwrap().resets[0].value =
            Some(File::open(files.attr(49, "value")).unwrap());
        assert!(value
            .run_until(GpioPhase::TerminalReset, due())
            .await
            .is_err());
        assert!(!value.core.as_ref().unwrap().terminal_complete);
        assert!(value.close_until(due()).await.is_err());
        assert!(value.core.is_some() && value.close_task.is_none());
        // Explicitly restore this authored backend for real terminal cleanup;
        // production performs no reopening or silent repair on this path.
        value.core.as_mut().unwrap().resets[0].value = Some(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(files.attr(49, "value"))
                .unwrap(),
        );
        close_after_on(&mut value).await;
    });
}

#[test]
fn cancellation_after_actual_on_cuts_before_join_and_keeps_original_budget_identity() {
    run(async {
        let (mut value, files, _fan, mut watchdog) = fixture(&[0]);
        value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        let original_deadline = due();
        let mut pending = Box::pin(value.run_until(GpioPhase::EnableAuxiliary, original_deadline));
        tokio::select! {
            _=&mut pending=>panic!("actual ON must enter real3-second settle"),
            _=async{while files.read(59,"value")!="1"{tokio::time::sleep(Duration::from_millis(1)).await;}}=>{}
        }
        let (budget, _admission) = watchdog.request_teardown_budget().unwrap().into_parts();
        let view = budget.view();
        drop(pending);
        assert_eq!(files.read(59, "value"), "0");
        assert!(value.task.is_some());
        let receipt = value.cut_with_original_budget(view.clone()).unwrap();
        assert!(receipt.teardown_budget.same_view(&view));
        assert!(view.require_not_before_start(receipt.started_at).is_ok());
        assert!(value.cut_with_original_budget(view).is_err());
        value.stop_and_join_until(due()).await.unwrap();
        let history = value.snapshot();
        assert!(history.never_energized_consumed_at.is_some());
        assert_eq!(history.calls[1].deadline, original_deadline);
        assert!(history.calls[1].joined_at.is_some() && history.calls[1].promoted_at.is_none());
        assert!(history
            .events
            .iter()
            .any(|e| e.action == "cancel-cutoff" && e.error.is_none()));
        close_after_on(&mut value).await;
    });
}

#[test]
fn existing_on_readback_failure_consumes_original_boundary_and_retains_mandatory_recut() {
    run(async {
        let (mut value, files, _fan, _watchdog) = fixture(&[0]);
        value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        value
            .core
            .as_mut()
            .unwrap()
            .guard
            .board_enable
            .fail_on_readback_after_on_write = true;
        assert!(value
            .run_until(GpioPhase::EnableAuxiliary, due())
            .await
            .is_err());
        assert!(value.snapshot().never_energized_consumed_at.is_some());
        assert!(value
            .snapshot()
            .events
            .iter()
            .any(|e| e.action == "original-board-enable" && e.error.is_some()));
        assert_eq!(files.read(59, "value"), "0");
        assert_eq!(
            value.core.as_ref().unwrap().guard.board_enable.state,
            Am3BbBoardEnableState::TerminalOff
        );
        close_after_on(&mut value).await;
    });
}

#[test]
fn blocked_actual_reset_write_does_not_delay_cancel_cut_and_failed_join_retains_owner() {
    run(async {
        let (mut value, files, _fan, _watchdog) = fixture(&[0]);
        value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        value
            .run_until(GpioPhase::EnableAuxiliary, due())
            .await
            .unwrap();
        let pause = IoPause::new("value");
        let release = ReleasePause(pause.clone());
        value.core.as_mut().unwrap().resets[0].after_write = Some(pause.clone());
        let original_deadline = due();
        let mut pending = Box::pin(value.run_until(GpioPhase::PostPicReset, original_deadline));
        tokio::select! {
            _=&mut pending=>panic!("actual reset caller should be paused after its write"),
            _=async{while !pause.entered(){tokio::time::sleep(Duration::from_millis(1)).await;}}=>{}
        }
        drop(pending);
        assert_eq!(files.read(59, "value"), "0");
        assert!(!value.task.as_ref().unwrap().is_finished());
        assert!(value
            .stop_and_join_until(Instant::now() + Duration::from_millis(10))
            .await
            .is_err());
        assert!(value.task.is_some() && value.core.is_none());
        let history = value.snapshot();
        assert!(history.events.iter().any(|e| e.gpio == 49
            && e.action == "write"
            && e.attribute == "value"
            && e.observed == b"1"
            && e.returned_at.is_some()));
        assert!(history.calls.last().unwrap().completed_at.is_none());
        assert!(history.calls.last().unwrap().worker_returned_at.is_none());
        assert!(history.calls.last().unwrap().join_failure.is_some());
        assert!(history.calls.last().unwrap().unpromoted_exit_at.is_some());
        drop(release);
        value.stop_and_join_until(due()).await.unwrap();
        let history = value.snapshot();
        assert_eq!(history.calls.last().unwrap().deadline, original_deadline);
        assert!(
            history.calls.last().unwrap().joined_at.is_some()
                && history.calls.last().unwrap().promoted_at.is_none()
        );
        close_after_on(&mut value).await;
    });
}

#[test]
fn real_deadline_after_on_and_original_panic_fence_never_promote_a_normal_operation() {
    run(async {
        let (mut value, files, _fan, _watchdog) = fixture(&[0]);
        value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        let original_deadline = Instant::now() + Duration::from_millis(50);
        assert!(value
            .run_until(GpioPhase::EnableAuxiliary, original_deadline)
            .await
            .is_err());
        value.stop_and_join_until(due()).await.unwrap();
        let history = value.snapshot();
        assert!(history
            .events
            .iter()
            .any(|e| e.action == "original-board-enable" && e.error.is_none()));
        assert!(history.calls[1].completed_at.is_none() && history.calls[1].promoted_at.is_none());
        assert_eq!(history.calls[1].deadline, original_deadline);
        assert_eq!(files.read(59, "value"), "0");
        close_after_on(&mut value).await;

        let (mut value, files, _fan, _watchdog) = fixture(&[2]);
        let panic = value.take_panic_cutoff().unwrap();
        value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        panic.cut_checked().unwrap();
        assert!(value.stop.load(Ordering::SeqCst));
        assert!(value
            .run_until(GpioPhase::EnableAuxiliary, due())
            .await
            .is_err());
        assert_eq!(value.snapshot().calls.len(), 1);
        assert!(value.snapshot().never_energized_consumed_at.is_none());
        assert_eq!(files.read(59, "value"), "0");
        close_pre_power(&mut value).await;
    });
}

#[test]
fn checked_fan_failure_keeps_actual_original_pre_on_token_and_error() {
    run(async {
        let (mut value, files, fan, _watchdog) = fixture(&[3]);
        value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        fan.fail.store(true, Ordering::SeqCst);
        assert!(value
            .run_until(GpioPhase::EnableAuxiliary, due())
            .await
            .is_err());
        let history = value.snapshot();
        assert!(history.never_energized_consumed_at.is_none());
        assert!(history.events.iter().any(|e| e.action == "checked-fan"
            && e.error
                .as_deref()
                .is_some_and(|e| e.contains("authored checked-fan failure"))));
        assert!(!history
            .events
            .iter()
            .any(|e| e.action == "original-board-enable"));
        assert!(history.calls.last().unwrap().worker_returned_at.is_some());
        assert!(history.calls.last().unwrap().completed_at.is_none());
        assert_eq!(files.read(59, "value"), "0");
        close_pre_power(&mut value).await;
        assert!(fan.writes.lock().unwrap().iter().all(|pwm| *pwm <= 30));
    });
}

#[test]
fn exhausted_diagnostic_log_and_expired_admission_cannot_prevent_actual_cutoff() {
    run(async {
        let (mut value, files, _fan, mut watchdog) = fixture(&[0]);
        value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        value
            .run_until(GpioPhase::EnableAuxiliary, due())
            .await
            .unwrap();
        assert_eq!(files.read(59, "value"), "1");
        // Explicit diagnostic-capacity fixture only. Cloned history is never
        // accepted as physical I/O, completion, or teardown authority.
        {
            let mut history = lock(&value.history);
            let filler = history.events[0].clone();
            history.events.resize(MAX_EVENTS, filler);
        }
        assert!(value
            .run_until(
                GpioPhase::PostPicReset,
                Instant::now() - Duration::from_millis(1)
            )
            .await
            .is_err());
        assert_eq!(files.read(59, "value"), "0");
        let history = value.snapshot();
        assert_eq!(history.calls.len(), 2);
        assert_eq!(history.events.len(), MAX_EVENTS);
        assert_eq!(history.unlogged_cutoffs, 1);
        assert_eq!(
            history.last_cutoff.as_ref().unwrap().action,
            "admission-refused-cutoff"
        );
        assert!(history.last_cutoff.as_ref().unwrap().error.is_none());
        let (budget, _admission) = watchdog.request_teardown_budget().unwrap().into_parts();
        value.cut_with_original_budget(budget.view()).unwrap();
        assert_eq!(value.snapshot().unlogged_cutoffs, 2);
        value.stop_and_join_until(due()).await.unwrap();
        // Log exhaustion prevents checked reset completion; it cannot create
        // finalization authority. Only the original retained fallback closes
        // here, and no successful close receipt is asserted for this case.
        assert!(value
            .run_until(GpioPhase::TerminalReset, due())
            .await
            .is_err());
        assert!(value.close_until(due()).await.is_err());
        assert!(value.core.is_some() && value.task.is_none());
        drop(value);
        assert_eq!(files.read(59, "value"), "0");
    });
}

#[test]
fn actual_export_requires_later_node_materialization_and_retains_timeout_history() {
    run(async {
        for materialize in [true, false] {
            let (mut value, files, _fan, _watchdog) = fixture(&[0]);
            for attr in ["direction", "active_low", "value"] {
                std::fs::remove_file(files.attr(49, attr)).unwrap();
            }
            std::fs::remove_dir(files.root.join("gpio49")).unwrap();
            let helper = materialize.then(|| {
                // Authored ordinary-file provider publishes a complete node
                // only after observing the actual retained export write.
                let root = files.root.clone();
                std::thread::spawn(move || {
                    let staged = root.join("authored-node49");
                    std::fs::create_dir(&staged).unwrap();
                    for (attr, bytes) in [("direction", "in"), ("active_low", "0"), ("value", "0")]
                    {
                        std::fs::write(staged.join(attr), bytes).unwrap();
                    }
                    let until = Instant::now() + Duration::from_secs(2);
                    while std::fs::read(root.join("export")).unwrap() != b"49" {
                        assert!(Instant::now() < until, "actual export was not observed");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    std::fs::rename(staged, root.join("gpio49")).unwrap();
                })
            });
            let deadline = due();
            let result = value.run_until(GpioPhase::Prepare, deadline).await;
            if let Some(helper) = helper {
                helper.join().unwrap();
            }
            assert_eq!(result.is_ok(), materialize);
            let history = value.snapshot();
            assert_eq!(history.calls[0].deadline, deadline);
            assert!(
                history.calls[0].worker_returned_at.is_some()
                    && history.calls[0].joined_at.is_some()
            );
            assert_eq!(history.calls[0].promoted_at.is_some(), materialize);
            assert!(value.core.as_ref().unwrap().export.is_some());
            assert!(history.events.iter().any(|e| e.action == "write"
                && e.attribute == "export"
                && e.requested == b"49"
                && e.observed == b"49"
                && e.number == Some(2)));
            assert!(history.events.iter().any(|e| e.action == "metadata"
                && e.attribute == "directory"
                && e.number == Some(0)));
            assert_eq!(
                history.retained_reset_attributes,
                if materialize { 3 } else { 0 }
            );
            assert!(history.never_energized_consumed_at.is_none());
            assert_eq!(files.read(59, "value"), "0");
            close_pre_power(&mut value).await;
        }
    });
}

#[test]
fn consuming_finalization_preserves_original_owner_on_refusal_and_joins_its_exact_fence() {
    run(async {
        let (mut value, files, _fan, _watchdog) = fixture(&[1]);
        value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        let mut value = match value.into_finalized_owner() {
            Ok(_) => panic!("unclosed original GPIO owner cannot finalize"),
            Err(refusal) => {
                assert!(refusal.error.contains("not actually finalized"));
                assert!(refusal.owner.core.is_some());
                refusal.owner
            }
        };
        let panic_lane = value.take_panic_cutoff().unwrap();
        assert!(value.stop.load(Ordering::SeqCst));
        close_pre_power(&mut value).await;
        let finalized = match value.into_finalized_owner() {
            Ok(finalized) => finalized,
            Err(refusal) => panic!("{}", refusal.error),
        };
        assert!(finalized.shares_terminal_fence(&panic_lane));
        assert!(finalized.history().cancel_lane_dropped_at.is_some());
        assert_eq!(files.read(59, "value"), "0");
        let (foreign, _foreign_files, _foreign_fan, _foreign_watchdog) = fixture(&[1]);
        assert!(!finalized.shares_terminal_fence(
            foreign
                .core
                .as_ref()
                .unwrap()
                .guard
                .board_enable
                .cutoff_io()
        ));
        // The independent panic lane remains separately owned here. This
        // handoff cannot impersonate its finalization or aggregate safe-off.
        drop(panic_lane);
        drop(finalized);
    });
}

#[test]
fn completed_terminal_worker_without_original_caller_promotion_cannot_finalize() {
    run(async {
        let (mut value, files, _fan, _watchdog) = fixture(&[0]);
        value.run_until(GpioPhase::Prepare, due()).await.unwrap();
        value
            .run_until(GpioPhase::EnableAuxiliary, due())
            .await
            .unwrap();
        let pause = IoPause::new("after-terminal-completion");
        let release = ReleasePause(pause.clone());
        value.core.as_mut().unwrap().after_terminal_completion = Some(pause.clone());
        let original = due();
        let history_handle = value.history.clone();
        let mut pending = Box::pin(value.run_until(GpioPhase::TerminalReset, original));
        tokio::select! {
            _ = &mut pending => panic!("the actual terminal worker must pause before its return"),
            _ = async { while !pause.entered() { tokio::time::sleep(Duration::from_millis(1)).await; } } => {}
        }
        {
            let history = lock(&history_handle);
            let call = history.calls.last().unwrap();
            assert!(call.completed_at.is_some());
            assert!(
                call.worker_returned_at.is_none()
                    && call.joined_at.is_none()
                    && call.promoted_at.is_none()
            );
        }
        drop(pending);
        assert!(!value.terminal_promoted);
        assert_eq!(files.read(59, "value"), "0");
        assert!(value
            .stop_and_join_until(Instant::now() + Duration::from_millis(10))
            .await
            .is_err());
        assert!(value.task.is_some() && value.core.is_none());
        drop(release);
        value.stop_and_join_until(due()).await.unwrap();
        let history = value.snapshot();
        let call = history.calls.last().unwrap();
        assert_eq!(call.deadline, original);
        assert!(
            call.completed_at.is_some()
                && call.worker_returned_at.is_some()
                && call.joined_at.is_some()
        );
        assert!(call.promoted_at.is_none());
        assert!(value.core.as_ref().unwrap().terminal_complete);
        assert!(!value.terminal_promoted);
        assert!(value.close_until(due()).await.is_err());
        assert!(value.core.is_some() && value.close_task.is_none());
        close_after_on(&mut value).await;
    });
}
