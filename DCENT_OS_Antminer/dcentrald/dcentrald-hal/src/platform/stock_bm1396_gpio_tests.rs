use super::super::tests::{owner, Event, Fake};
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::Condvar;

struct TestPin {
    hardware: Arc<Fake>,
    state: Arc<AtomicBool>,
    fail: bool,
    observe_low: bool,
}
impl Pin for TestPin {
    fn high(&self) -> Result<(), String> {
        self.hardware.events.lock().unwrap().push(Event::SourceHigh);
        if self.fail {
            return Err("injected independent pin failure".into());
        }
        self.state.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn observed_high(&self) -> Result<bool, String> {
        Ok(self.state.load(Ordering::SeqCst) && !self.observe_low)
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn line(
    hardware: Arc<Fake>,
    owner: Arc<Transport<Fake>>,
    fail: bool,
    observe_low: bool,
) -> Arc<PowerLine<Fake>> {
    PowerLine::from_test_pin(
        owner,
        Box::new(TestPin {
            hardware,
            state: Arc::new(AtomicBool::new(false)),
            fail,
            observe_low,
        }),
    )
}

#[tokio::test]
async fn independent_high_then_both_quiet_registers_have_sealed_same_owner_custody() {
    let (fake, owner) = owner(Model::S17e).await;
    let line = line(fake.clone(), owner.clone(), false, false);
    fake.events.lock().unwrap().clear();
    let (observed, quiet) = line.park_with_quiet_fans(deadline()).unwrap();
    assert!(observed.pin_high && observed.same_owner(&owner));
    assert!(observed.attempted_at() <= observed.observed_at());
    assert_eq!(quiet.percent, 30);
    assert_eq!(quiet.registers(), [(0x84, 0x000f0023), (0xa0, 0x000f0023)]);
    let events = fake.events.lock().unwrap().clone();
    assert_eq!(events[0], Event::SourceHigh);
    assert_eq!(fake.writes(), vec![(0x84, 0x000f0023), (0xa0, 0x000f0023)]);
    let (_, other) = super::super::tests::owner(Model::S17e).await;
    assert!(!observed.same_owner(&other));
    assert!(!quiet.same_owner(&other));
    assert!(owner.is_terminal());
}

#[tokio::test]
async fn failed_or_low_source_observation_never_commands_pwm() {
    for (fail, observed_low) in [(true, false), (false, true)] {
        let (fake, owner) = owner(Model::S17e).await;
        let line = line(fake.clone(), owner, fail, observed_low);
        assert!(line.park_with_quiet_fans(deadline()).is_err());
        assert!(fake.writes().is_empty());
    }
}

#[tokio::test]
async fn partial_dual_pwm_failure_has_no_combined_receipt_and_source_stays_high() {
    let (fake, owner) = owner(Model::T17e).await;
    let high = Arc::new(AtomicBool::new(false));
    let line = PowerLine::from_test_pin(
        owner,
        Box::new(TestPin {
            hardware: fake.clone(),
            state: high.clone(),
            fail: false,
            observe_low: false,
        }),
    );
    fake.fail_write.store(0xa0, Ordering::SeqCst);
    assert!(line.park_with_quiet_fans(deadline()).is_err());
    assert!(high.load(Ordering::SeqCst));
    assert_eq!(fake.writes(), vec![(0x84, 0x000f0023), (0xa0, 0x000f0023)]);
}

#[tokio::test]
async fn cutoff_does_not_wait_for_asic_management_or_fan_transaction_locks() {
    let (fake, owner) = owner(Model::S17e).await;
    let line = line(fake.clone(), owner.clone(), false, false);
    let _asic = owner.asic.lock().unwrap();
    let _management = owner.management.lock().unwrap();
    let _fans = owner.fans.lock().unwrap();
    owner.management_fault.store(true, Ordering::SeqCst);
    let observed = line.terminal_high(deadline()).await.unwrap();
    assert!(observed.pin_high);
    assert!(fake.writes().is_empty());
    assert!(owner.is_terminal());
}

#[tokio::test]
async fn quiet_and_tach_use_distinct_r06_offsets_and_preserve_zero_duplicate_ids() {
    let (fake, owner) = owner(Model::T17e).await;
    let quiet = owner.quiet_fans(deadline()).await.unwrap();
    assert_eq!(quiet.registers(), [(0x84, 0x000f0023), (0xa0, 0x000f0023)]);
    fake.write(0, 0xb025).unwrap();
    fake.write(4, 0x0305).unwrap();
    let sample = owner.sample_fan_tach(deadline()).await.unwrap();
    assert_eq!(sample.samples().len(), 8);
    for (raw, decoded) in sample.samples() {
        assert_eq!(*raw, 0x305);
        assert_eq!(decoded.fan_id, 3);
        assert_eq!(decoded.rpm, 1200);
    }
    fake.write(4, 0).unwrap();
    let zero = owner.sample_fan_tach(deadline()).await.unwrap();
    assert!(zero.samples().iter().all(|(_, reading)| reading.rpm == 0));
}

#[test]
fn exact_export_descriptor_is_write_only_and_wrong_modes_are_refused() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("bm1396-gpio-export-{}-{stamp}", std::process::id()));
    struct Remove(PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _remove = Remove(path.clone());
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o200)).unwrap();
    // This actual descriptor fixture uses the same opener and its kernel access
    // flags; it is not a physical sysfs export or a controller identity proof.
    let uid = std::fs::metadata(&path).unwrap().uid();
    let file = open_owned(&path, false, true, uid).unwrap();
    // SAFETY: F_GETFL reads the flags of this retained valid fixture descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(flags & libc::O_ACCMODE, libc::O_WRONLY);
    write(&file, b"907").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(open_owned(&path, true, true, uid).is_err());
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "bm1396-gpio-fixture-{}-{stamp}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn uid(&self) -> u32 {
        std::fs::metadata(&self.0).unwrap().uid()
    }
    fn write(&self, path: &str, bytes: &[u8]) {
        let path = self.0.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    fn link(&self, from: &str, to: &Path) {
        let from = self.0.join(from);
        std::fs::create_dir_all(from.parent().unwrap()).unwrap();
        symlink(to, from).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this newly created unique test directory is removed, never a
        // real sysfs tree, device, supplied path or prior workspace artifact.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn actual_controller_tree_and_exported_line_require_exact_ps_mio1_binding() {
    let f = Fixture::new();
    for relative in [
        "tree/#address-cells",
        "tree/#size-cells",
        "tree/amba@0/#address-cells",
        "tree/amba@0/#size-cells",
    ] {
        f.write(relative, &1u32.to_be_bytes());
    }
    f.write("tree/amba@0/ranges", &[]);
    let properties: [(&str, &[u8]); 5] = [
        ("sys/gpiochip906/base", b"906\n"),
        ("sys/gpiochip906/ngpio", b"118\n"),
        ("sys/gpiochip906/label", b"zynq_gpio\n"),
        (
            "tree/amba@0/ps7-gpio@e000a000/reg",
            &[0xe0, 0, 0xa0, 0, 0, 0, 0x10, 0],
        ),
        (
            "tree/amba@0/ps7-gpio@e000a000/compatible",
            b"xlnx,zynq-gpio-1.0\0",
        ),
    ];
    for (path, bytes) in properties {
        f.write(path, bytes);
    }
    let node = f.0.join("tree").join(GPIO_NODE);
    f.link("sys/gpiochip906/device/of_node", &node);
    f.link("sys/gpio907/device/of_node", &node);
    let sysfs = f.0.join("sys");
    let tree = f.0.join("tree");
    assert_eq!(validate_controller(&sysfs, &tree, f.uid()).unwrap(), node);
    assert!(validate_line(&sysfs.join("gpio907"), &node).is_ok());
    f.write("tree/amba@0/ranges", &[0; 12]);
    assert!(validate_controller(&sysfs, &tree, f.uid()).is_err());
    f.write("tree/amba@0/ranges", &[]);
    f.write("tree/amba@0/#address-cells", &2u32.to_be_bytes());
    assert!(validate_controller(&sysfs, &tree, f.uid()).is_err());
    f.write("tree/amba@0/#address-cells", &1u32.to_be_bytes());
    for (path, bytes) in properties {
        f.write(path, b"wrong");
        assert!(validate_controller(&sysfs, &tree, f.uid()).is_err());
        f.write(path, bytes);
    }
    std::fs::create_dir(tree.join("foreign-controller")).unwrap();
    for path in [
        "sys/gpiochip906/device/of_node",
        "sys/gpio907/device/of_node",
    ] {
        std::fs::remove_file(f.0.join(path)).unwrap();
        f.link(path, &tree.join("foreign-controller"));
        assert!(if path.contains("gpiochip") {
            validate_controller(&sysfs, &tree, f.uid()).is_err()
        } else {
            validate_line(&sysfs.join("gpio907"), &node).is_err()
        });
        std::fs::remove_file(f.0.join(path)).unwrap();
        f.link(path, &node);
    }
    let base = sysfs.join("gpiochip906/base");
    std::fs::remove_file(&base).unwrap();
    symlink(sysfs.join("gpiochip906/ngpio"), &base).unwrap();
    assert!(validate_controller(&sysfs, &tree, f.uid()).is_err());
}

#[test]
fn native_latch_or_inversion_failure_never_reaches_direction_or_value_store() {
    let f = Fixture::new();
    f.write("direction", b"in\n");
    f.write("value", b"0\n");
    f.write("active_low", b"0\n");
    f.write("page", &vec![0; 4096]);
    let page = open_owned(&f.0.join("page"), true, true, f.uid()).unwrap();
    // SAFETY: ordinary newly created test file, page-sized mapping at offset0;
    // no physical memory or device is opened by this descriptor fixture.
    let mapped = unsafe {
        libc::mmap64(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            page.as_raw_fd(),
            0,
        )
    };
    assert_ne!(mapped, libc::MAP_FAILED);
    let pin = SysfsPin {
        direction: open_owned(&f.0.join("direction"), true, true, f.uid()).unwrap(),
        value: open_owned(&f.0.join("value"), true, true, f.uid()).unwrap(),
        active_low: open_owned(&f.0.join("active_low"), true, false, f.uid()).unwrap(),
        preload: mapped as usize,
        _devmem: page,
    };
    assert!(pin.high().unwrap_err().contains("preload"));
    assert_eq!(read(&pin.direction, 8).unwrap(), b"in\n");
    assert_eq!(read(&pin.value, 8).unwrap(), b"0\n");
    // The fixture observes the real volatile store's exact pin1 mask. It does
    // not emulate hardware masked-DATA semantics or prove a physical transition.
    assert_eq!(
        &std::fs::read(f.0.join("page")).unwrap()[..4],
        &0xfffd0002u32.to_ne_bytes()
    );
    f.write("active_low", b"1\n");
    // SAFETY: first aligned word of the same retained 4096-byte fixture mapping.
    unsafe { std::ptr::write_volatile(mapped as *mut u32, 0) };
    assert!(pin.high().unwrap_err().contains("inversion"));
    // SAFETY: same retained fixture mapping, read only the first aligned word.
    assert_eq!(unsafe { std::ptr::read_volatile(mapped as *const u32) }, 0);
    assert_eq!(read(&pin.direction, 8).unwrap(), b"in\n");
    assert_eq!(read(&pin.value, 8).unwrap(), b"0\n");
    assert!(pin.observed_high().is_err());
}

#[tokio::test]
async fn private_empty_population_boot_owner_is_terminal_and_only_parks_source_and_fans() {
    let fake = Fake::new(Model::S17e, 0);
    assert!(Transport::observe(fake.clone(), Model::S17e, vec![])
        .await
        .is_err());
    let owner = Transport::parked(fake.clone()).unwrap();
    assert!(owner.is_terminal() && owner.chains().is_empty());
    assert!(PicApplication::claim(owner.clone()).is_err());
    assert!(owner
        .request_register(0, None, 0, deadline())
        .await
        .is_err());
    fake.events.lock().unwrap().clear();
    let line = line(fake.clone(), owner.clone(), false, false);
    assert!(line.park_with_quiet_fans(deadline()).unwrap().0.pin_high);
    assert_eq!(fake.writes(), [(0x84, 0x000f0023), (0xa0, 0x000f0023)]);
    assert!(!fake
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, Event::Read(8) | Event::Read(0x30))));
}

struct BlockedPin {
    entered: AtomicBool,
    high: AtomicBool,
    release: Mutex<bool>,
    condition: Condvar,
}
impl Pin for Arc<BlockedPin> {
    fn high(&self) -> Result<(), String> {
        if !self.entered.swap(true, Ordering::SeqCst) {
            let release = self.release.lock().unwrap();
            let (_released, result) = self
                .condition
                .wait_timeout_while(release, Duration::from_secs(5), |released| !*released)
                .unwrap();
            if result.timed_out() {
                return Err("fixture source worker did not release".into());
            }
        }
        self.high.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn observed_high(&self) -> Result<bool, String> {
        Ok(self.high.load(Ordering::SeqCst))
    }
}

#[tokio::test]
async fn cancelled_boot_waiter_retains_actual_cut_worker_and_both_pwm_stages_until_drain() {
    let fake = Fake::new(Model::T17e, 0);
    let owner = Transport::parked(fake.clone()).unwrap();
    let pin = Arc::new(BlockedPin {
        entered: AtomicBool::new(false),
        high: AtomicBool::new(false),
        release: Mutex::new(false),
        condition: Condvar::new(),
    });
    let line = PowerLine::from_test_pin(owner.clone(), Box::new(pin.clone()));
    let retained = Arc::downgrade(&line);
    let runner = owner.clone();
    let until = deadline();
    let job = tokio::spawn(async move {
        runner
            .worker(until, true, move |_| line.park_with_quiet_fans(until))
            .await
    });
    let limit = deadline();
    while !pin.entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < limit);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    assert!(retained.upgrade().is_some());
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    assert!(fake.writes().is_empty());
    *pin.release.lock().unwrap() = true;
    pin.condition.notify_all();
    owner.drain(deadline()).await.unwrap();
    assert!(pin.high.load(Ordering::SeqCst));
    assert_eq!(fake.writes(), [(0x84, 0x000f0023), (0xa0, 0x000f0023)]);
    assert!(retained.upgrade().is_none());
}

#[tokio::test]
async fn detached_result_cleanup_remains_counted_until_its_retained_owner_is_dropped() {
    struct State {
        entered: AtomicBool,
        return_now: AtomicBool,
        dropping: AtomicBool,
        drop_done: AtomicBool,
        release: Mutex<bool>,
        condition: Condvar,
    }
    struct ReturnedOwner(Arc<State>);
    impl Drop for ReturnedOwner {
        fn drop(&mut self) {
            self.0.dropping.store(true, Ordering::SeqCst);
            let guard = self.0.release.lock().unwrap();
            let (_released, result) = self
                .0
                .condition
                .wait_timeout_while(guard, Duration::from_secs(5), |released| !*released)
                .unwrap();
            assert!(!result.timed_out());
            self.0.drop_done.store(true, Ordering::SeqCst);
        }
    }
    let (_, owner) = owner(Model::S17e).await;
    let state = Arc::new(State {
        entered: AtomicBool::new(false),
        return_now: AtomicBool::new(false),
        dropping: AtomicBool::new(false),
        drop_done: AtomicBool::new(false),
        release: Mutex::new(false),
        condition: Condvar::new(),
    });
    let worker_state = state.clone();
    let runner = owner.clone();
    let until = deadline();
    let task = tokio::spawn(async move {
        runner
            .worker(until, false, move |_| {
                worker_state.entered.store(true, Ordering::SeqCst);
                while !worker_state.return_now.load(Ordering::SeqCst) {
                    assert!(Instant::now() < until);
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(ReturnedOwner(worker_state))
            })
            .await
    });
    while !state.entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    task.abort();
    assert!(matches!(task.await, Err(e) if e.is_cancelled()));
    state.return_now.store(true, Ordering::SeqCst);
    while !state.dropping.load(Ordering::SeqCst) {
        assert!(Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    assert!(!state.drop_done.load(Ordering::SeqCst));
    *state.release.lock().unwrap() = true;
    state.condition.notify_all();
    owner.drain(deadline()).await.unwrap();
    assert!(state.drop_done.load(Ordering::SeqCst));
}
