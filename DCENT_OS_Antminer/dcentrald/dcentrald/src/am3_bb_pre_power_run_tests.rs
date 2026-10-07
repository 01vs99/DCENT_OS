use super::*;
use dcentrald_hal::bb_management_runtime::simulated::Fixture;
use dcentrald_hal::platform::beaglebone::{BeagleBoneBoardTarget, BoardTargetPlatformSection};
use dcentrald_hal::platform::{config::PlatformConfig, FanCommandReceipt};
use dcentrald_hal::serial_chain::SerialChainBackend;
use std::collections::BTreeMap;
use std::fs::File;
use std::future::{poll_fn, Future};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

fn due() -> Instant {
    Instant::now() + Duration::from_secs(12)
}

struct Files {
    root: std::path::PathBuf,
}
impl Files {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let name = format!(
            "dcent-bb-pre-power-run-{}-{}-{}",
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
            .starts_with("dcent-bb-pre-power-run-"));
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
    let mut target = BeagleBoneBoardTarget::hardcoded_v2_0_defaults();
    target.platform = Some(BoardTargetPlatformSection {
        board_target: Some("am3-bb-s19jpro".into()),
        soc: Some("am335x".into()),
        cpu: Some("cortex-a8".into()),
        io_board: Some("S19J_IO_BOARD_V2_0".into()),
        voltage_controller: Some("dspic33ep-fw89".into()),
    });
    BeagleBonePlatform::with_config_and_board_target(
        PlatformConfig::s19j_beaglebone(),
        "am3-bb-s19jpro",
        target,
    )
}
struct Pty {
    master: File,
    slave: File,
}
impl Pty {
    fn new() -> Self {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: distinct initialized outputs; optional name/termios/window
        // pointers are absent. This opens only a local host PTY fixture.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        Self {
            // SAFETY: adopt the new master descriptor exactly once.
            master: unsafe { File::from_raw_fd(master) },
            // SAFETY: adopt the distinct new slave descriptor exactly once.
            slave: unsafe { File::from_raw_fd(slave) },
        }
    }
    fn path(&self) -> String {
        format!("/proc/self/fd/{}", self.slave.as_raw_fd())
    }
}
fn pty_descriptors() -> BTreeMap<u32, std::path::PathBuf> {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let number = entry.file_name().to_str()?.parse().ok()?;
            let target = std::fs::read_link(entry.path()).ok()?;
            target.starts_with("/dev/pts").then_some((number, target))
        })
        .collect()
}

// Descriptor-leak assertions need their own process: unrelated native tests
// legitimately open and close PTYs while the default Rust harness runs in parallel.
fn isolated_descriptor_test(name: &str) -> bool {
    let exact = format!("am3_bb_mining::pre_power_run::tests::{name}");
    if std::env::var("DCENT_BB_DESCRIPTOR_TEST_CHILD").as_deref() == Ok(exact.as_str()) {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact, "--nocapture"])
        .env("DCENT_BB_DESCRIPTOR_TEST_CHILD", &exact)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{exact}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed; 0 ignored"),
        "the isolated descriptor test must execute exactly once: {exact}"
    );
    false
}
fn original_parts() -> (
    BeagleBonePlatform,
    Am3BbRunSafetyGuard,
    Am3BbNeverEnergized,
    Files,
    Arc<Fan>,
    SafetyWatchdogOwner,
) {
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
    (platform(), guard, never, files, fan, watchdog)
}

fn captured(selected: &[u8]) -> (PrePowerRun, Files, Arc<Fan>, SafetyWatchdogOwner) {
    let (platform, guard, never, files, fan, watchdog) = original_parts();
    let mut value = PrePowerRun::capture(platform, selected, guard, never, due())
        .unwrap_or_else(|refusal| panic!("{}", refusal.error));
    value
        .gpio
        .as_mut()
        .unwrap()
        .set_pre_power_fixture_root(&files.root)
        .unwrap();
    (value, files, fan, watchdog)
}
async fn open(
    value: &mut PrePowerRun,
    block_apw: bool,
    fail_second_uart: bool,
) -> (
    std::result::Result<(), String>,
    Fixture,
    Vec<Pty>,
    Arc<Mutex<Vec<u8>>>,
) {
    let (services, fixture) = Fixture::factory_services(block_apw, false);
    let ptys: Vec<_> = (0..3).map(|_| Pty::new()).collect();
    let paths: Vec<_> = ptys.iter().map(Pty::path).collect();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let result = value
        .prepare_and_open_simulated_until(due(), services, move |slot, configured| {
            assert_eq!(
                configured,
                ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS4"][slot as usize]
            );
            let mut calls = observed.lock().unwrap();
            calls.push(slot);
            if fail_second_uart && calls.len() == 2 {
                return Err(dcentrald_hal::HalError::DeviceOpen {
                    path: configured.to_owned(),
                    source: std::io::Error::other("authored second original UART open refusal"),
                });
            }
            SerialChainBackend::open_native_linux_only(slot, &paths[slot as usize], 115_200)
        })
        .await
        .map_err(|error| format!("{error:#}"));
    (result, fixture, ptys, calls)
}
fn retained(value: PrePowerRun) -> PrePowerRun {
    match value.try_into_closed() {
        Err(original) => original,
        Ok(_) => panic!("unjoined or late run became a closed original run"),
    }
}
fn closed(value: PrePowerRun) -> ClosedPrePowerRun {
    match value.try_into_closed() {
        Ok(original) => original,
        Err(_) => panic!("actual joined original run was not accepted"),
    }
}

#[tokio::test]
async fn sparse_roster_joins_original_gpio_factory_controller_and_actual_close() {
    if !isolated_descriptor_test(
        "sparse_roster_joins_original_gpio_factory_controller_and_actual_close",
    ) {
        return;
    }
    let (mut value, files, fan, _watchdog) = captured(&[0x52, 0x50]);
    assert!(value.snapshot().gpio.calls.is_empty());
    for pin in [49, 60, 27, 22] {
        assert_eq!(files.read(pin, "direction"), "in");
    }
    let (result, fixture, _ptys, calls) = open(&mut value, false, false).await;
    result.unwrap();
    assert_eq!(*calls.lock().unwrap(), [2, 0]);
    let state = value.snapshot();
    assert_eq!(state.selected_ids, [2, 0]);
    assert_eq!(
        state
            .gpio
            .selected
            .iter()
            .map(|r| r.gpio)
            .collect::<Vec<_>>(),
        [27, 49]
    );
    assert_eq!(
        state
            .factory
            .open
            .uarts_opened
            .iter()
            .map(|r| r.0)
            .collect::<Vec<_>>(),
        [2, 0]
    );
    assert_eq!(
        state.controller.as_ref().unwrap().selected_eeproms(),
        [0x52, 0x50]
    );
    for pin in [27, 49] {
        assert_eq!(files.read(pin, "value"), "1");
    }
    for pin in [60, 22] {
        assert_eq!(files.read(pin, "direction"), "in");
    }
    assert_eq!(files.read(59, "value"), "0");
    assert!(state.gpio.never_energized_consumed_at.is_none());
    assert!(value.factory.take_ready().is_err());
    let descriptors = pty_descriptors();
    value.diagnose_until(due()).await.unwrap();
    assert_eq!(pty_descriptors(), descriptors);
    assert_eq!(fixture.apw_opcodes(), [2, 1, 6, 3]);
    assert!(value.never.is_none());
    value.close_until(due()).await.unwrap();
    assert_eq!(
        Arc::strong_count(&fan),
        1,
        "original guard/fan reference remained after joined close"
    );
    let mut done = closed(value);
    assert!(done.snapshot().gpio.close_joined_at.is_some());
    let original = done.take_never_energized().unwrap();
    assert!(done.take_never_energized().is_err());
    drop(original); // Inert test watchdog; no physical or watchdog closeout claim.
}

#[test]
fn invalid_roster_returns_original_guard_platform_and_never_token() {
    if !isolated_descriptor_test("invalid_roster_returns_original_guard_platform_and_never_token") {
        return;
    }
    for selected in [&[][..], &[0x50, 0x50], &[0x53], &[0x4f]] {
        let (platform, guard, never, files, _fan, _watchdog) = original_parts();
        let terminal = Arc::clone(&guard.board_enable.io.terminal);
        let before = pty_descriptors();
        let refusal = match PrePowerRun::capture(platform, selected, guard, never, due()) {
            Err(refusal) => refusal,
            Ok(_) => panic!("invalid roster was captured"),
        };
        match refusal.custody {
            CaptureCustody::Original {
                platform,
                guard,
                never,
            } => {
                assert_eq!(platform.board_target_name(), "am3-bb-s19jpro");
                assert!(Arc::ptr_eq(&terminal, &guard.board_enable.io.terminal));
                assert_eq!(files.read(59, "value"), "0");
                drop(never);
                drop(guard);
            }
            _ => panic!("invalid roster advanced beyond original custody"),
        }
        assert_eq!(pty_descriptors(), before);
    }
}

#[tokio::test]
async fn expired_factory_capture_retains_adopted_gpio_and_original_never_token() {
    let (platform, guard, never, files, _fan, _watchdog) = original_parts();
    let refusal = match PrePowerRun::capture(
        platform,
        &[0x52],
        guard,
        never,
        Instant::now() - Duration::from_millis(1),
    ) {
        Err(refusal) => refusal,
        Ok(_) => panic!("expired factory was captured"),
    };
    match refusal.custody {
        CaptureCustody::Adopted { platform, mut gpio } => {
            assert_eq!(platform.board_target_name(), "am3-bb-s19jpro");
            assert_eq!(gpio.snapshot().selected[0].chain_id, 2);
            assert!(gpio.snapshot().calls.is_empty());
            gpio.set_pre_power_fixture_root(&files.root).unwrap();
            gpio.stop_and_join_until(due()).await.unwrap();
            let never = gpio.take_never_energized_after_join().unwrap();
            gpio.close_until(due()).await.unwrap();
            assert!(gpio.into_finalized_owner().is_ok());
            drop(never);
        }
        _ => panic!("expired factory lost its adopted owner"),
    }
}

#[tokio::test]
async fn partial_original_uart_acquisition_closes_original_services_and_descriptor() {
    if !isolated_descriptor_test(
        "partial_original_uart_acquisition_closes_original_services_and_descriptor",
    ) {
        return;
    }
    let inherited = pty_descriptors();
    let (mut value, _files, fan, _watchdog) = captured(&[0x52, 0x50]);
    let (result, _fixture, ptys, calls) = open(&mut value, false, true).await;
    assert!(result.is_err());
    assert_eq!(*calls.lock().unwrap(), [2, 0]);
    assert!(value.controller.is_none());
    assert_eq!(
        value
            .snapshot()
            .factory
            .open
            .uarts_opened
            .iter()
            .map(|r| r.0)
            .collect::<Vec<_>>(),
        [2]
    );
    value.close_until(due()).await.unwrap();
    let mut done = closed(value);
    assert_eq!(
        done.snapshot().factory.close.unwrap().service_receipts,
        [0, 1]
    );
    assert_eq!(Arc::strong_count(&fan), 1);
    let expected: Vec<_> = ptys
        .iter()
        .flat_map(|pty| [pty.master.as_raw_fd() as u32, pty.slave.as_raw_fd() as u32])
        .collect();
    assert!(pty_descriptors()
        .keys()
        .all(|fd| expected.contains(fd) || inherited.contains_key(fd)));
    drop(done.take_never_energized().unwrap());
}

#[tokio::test]
async fn cancelled_real_diagnostic_retains_original_run_until_worker_release_and_close() {
    let (mut value, _files, _fan, _watchdog) = captured(&[0x50]);
    let (result, fixture, _ptys, _calls) = open(&mut value, true, false).await;
    result.unwrap();
    tokio::select! {
        _=fixture.wait_apw_entered()=>{},
        result=value.diagnose_until(due())=>panic!("held APW diagnostic completed: {result:?}"),
    }
    let mut value = retained(value);
    assert!(value.never.is_none());
    fixture.release();
    value.close_until(due()).await.unwrap();
    assert!(closed(value).snapshot().controller.unwrap().uart_terminal());
}

#[tokio::test]
async fn late_resource_recovery_never_refreshes_original_run_close_deadline() {
    let (mut value, _files, _fan, _watchdog) = captured(&[0x50]);
    let (result, _fixture, _ptys, _calls) = open(&mut value, false, false).await;
    result.unwrap();
    let expired = Instant::now() - Duration::from_millis(1);
    assert!(value.close_until(expired).await.is_err());
    assert!(value.close_until(due()).await.is_err());
    let value = retained(value);
    let state = value.snapshot();
    assert_eq!(state.original_close_deadline, Some(expired));
    assert_eq!(state.close_calls.len(), 2);
    assert!(state
        .close_calls
        .iter()
        .all(|call| call.returned_at.is_some() && call.failure.is_some()));
    assert!(
        state.gpio.close_joined_at.is_some(),
        "actual resource recovery was skipped"
    );
    assert!(
        value.never.is_some(),
        "original token must remain in refused aggregate"
    );
}

#[tokio::test]
async fn cancelled_close_keeps_original_deadline_and_unreturned_history_then_joins() {
    let (mut value, _files, _fan, _watchdog) = captured(&[0x50]);
    let (result, fixture, _ptys, _calls) = open(&mut value, true, false).await;
    result.unwrap();
    tokio::select! {
        _=fixture.wait_apw_entered()=>{},
        result=value.diagnose_until(due())=>panic!("held APW diagnostic completed: {result:?}"),
    }
    let original = due();
    {
        let mut closing = Box::pin(value.close_until(original));
        poll_fn(|cx| match closing.as_mut().poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Ready(()),
            std::task::Poll::Ready(result) => panic!("held original close completed: {result:?}"),
        })
        .await;
    }
    let mut value = retained(value);
    assert!(value.snapshot().close_calls[0].returned_at.is_none());
    fixture.release();
    value.close_until(due()).await.unwrap();
    let done = closed(value);
    let state = done.snapshot();
    assert_eq!(state.original_close_deadline, Some(original));
    assert_eq!(state.close_calls.len(), 2);
    assert!(state.close_calls[0].returned_at.is_none());
    assert!(state.close_calls[1].returned_at.unwrap() < original);
}

#[tokio::test]
async fn failed_latest_close_cannot_borrow_a_prior_successful_close() {
    let (mut value, _files, _fan, _watchdog) = captured(&[0x50]);
    let (result, _fixture, _ptys, _calls) = open(&mut value, false, false).await;
    result.unwrap();
    let original = due();
    value.close_until(original).await.unwrap();
    assert!(value.snapshot().close_calls[0].failure.is_none());
    assert!(value
        .close_until(Instant::now() - Duration::from_millis(1))
        .await
        .is_err());
    let value = retained(value);
    let state = value.snapshot();
    assert_eq!(state.original_close_deadline, Some(original));
    assert_eq!(state.close_calls.len(), 2);
    assert!(state.close_calls[0].failure.is_none());
    assert!(state.close_calls[1].failure.is_some());
}

#[path = "am3_bb_pre_power_initial_bridge_tests.rs"]
mod initial_bridge;
