use super::*;

#[test]
fn export_descriptor_is_write_only_for_the_held_kernfs_permission_contract() {
    use std::os::unix::fs::PermissionsExt;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("bm1391-export-{}-{stamp}", std::process::id()));
    let created = File::create_new(&path).unwrap();
    created
        .set_permissions(std::fs::Permissions::from_mode(0o200))
        .unwrap();
    drop(created);
    let descriptor = open_descriptor(&path, false, true).unwrap();
    // Actual descriptor flags complement the original kernfs permission
    // replay: ordinary-root filesystem access alone would miss this defect.
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(flags & libc::O_ACCMODE, libc::O_WRONLY);
    write(&descriptor, b"907").unwrap();
    drop(descriptor);
    std::fs::remove_file(path).unwrap();
}

struct RegistersFixture {
    forbidden: AtomicBool,
}
impl Registers for RegistersFixture {
    fn validate_owner(&self) -> Result<(), String> {
        if self.forbidden.load(Ordering::SeqCst) {
            Err("fixture inherited owner".into())
        } else {
            Ok(())
        }
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        match offset {
            VERSION => Ok(0xc501),
            PRESENCE => Ok(7),
            _ => Err("fabric unavailable".into()),
        }
    }
    fn write(&self, _: u32, _: u32) -> Result<(), String> {
        Err("fabric unavailable".into())
    }
}
#[derive(Default)]
struct PinState {
    writes: Vec<bool>,
    high: bool,
    fail_low: bool,
    stuck_low: bool,
}
struct PinFixture(Arc<Mutex<PinState>>);
impl Pin for PinFixture {
    fn high(&self) -> Result<(), String> {
        let mut pin = self.0.lock().unwrap();
        pin.writes.push(true);
        pin.high = !pin.stuck_low;
        Ok(())
    }
    fn low(&self) -> Result<(), String> {
        let mut pin = self.0.lock().unwrap();
        pin.writes.push(false);
        pin.high = false;
        if pin.fail_low {
            Err("torn GPIO low operation".into())
        } else {
            Ok(())
        }
    }
    fn observed_high(&self) -> Result<bool, String> {
        Ok(self.0.lock().unwrap().high)
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(1)
}

#[test]
fn empty_population_source_park_is_permanently_terminal_and_cannot_enable() {
    struct Empty;
    impl Registers for Empty {
        fn read(&self, offset: u32) -> Result<u32, String> {
            match offset {
                VERSION => Ok(0xc501),
                PRESENCE => Ok(0),
                _ => Err("no ASIC transport".into()),
            }
        }
        fn write(&self, _: u32, _: u32) -> Result<(), String> {
            panic!("parked owner must not issue FPGA work")
        }
    }
    assert!(Transport::new(Arc::new(Empty), vec![]).is_err());
    assert!(Transport::new(Arc::new(Empty), vec![0]).is_err());
    let owner = Transport::new_parked(Arc::new(Empty)).unwrap();
    assert!(owner.chains.is_empty());
    assert!(owner.terminal());
    assert!(owner.selected_work_ready(deadline()).is_err());
    let pin = Arc::new(Mutex::new(PinState::default()));
    let line = PowerLine::from_test_pin(owner, Box::new(PinFixture(pin.clone())));
    assert!(line.terminal_high(deadline()).unwrap().pin_high);
    assert!(line.enable_source_line(deadline()).is_err());
    assert!(pin.lock().unwrap().writes.iter().all(|high| *high));
}

#[test]
fn boot_park_cuts_before_quiet_pwm_and_never_certifies_a_failed_stage() {
    struct State {
        events: Mutex<Vec<&'static str>>,
        defect: u8,
    }
    struct FanRegisters(Arc<State>);
    impl Registers for FanRegisters {
        fn read(&self, offset: u32) -> Result<u32, String> {
            match offset {
                VERSION => Ok(0xc501),
                0x84 => {
                    self.0.events.lock().unwrap().push("pwm_read");
                    Ok(if self.0.defect == 3 { 0 } else { 0x000f_0023 })
                }
                _ => Err("boot parking must not access work/PIC/tach".into()),
            }
        }
        fn write(&self, offset: u32, value: u32) -> Result<(), String> {
            assert_eq!((offset, value), (0x84, 0x000f_0023));
            self.0.events.lock().unwrap().push("pwm_write");
            if self.0.defect == 2 {
                Err("PWM write failed".into())
            } else {
                Ok(())
            }
        }
    }
    struct BootPin(Arc<State>);
    impl Pin for BootPin {
        fn high(&self) -> Result<(), String> {
            self.0.events.lock().unwrap().push("high");
            if self.0.defect == 1 {
                Err("GPIO cut failed".into())
            } else {
                Ok(())
            }
        }
        fn low(&self) -> Result<(), String> {
            panic!("terminal boot owner cannot energize")
        }
        fn observed_high(&self) -> Result<bool, String> {
            self.0.events.lock().unwrap().push("high_read");
            if self.0.defect == 4 {
                std::thread::sleep(Duration::from_millis(3));
            }
            Ok(true)
        }
    }
    for defect in 0..5 {
        let state = Arc::new(State {
            events: Mutex::new(Vec::new()),
            defect,
        });
        let owner = Transport::new_parked(Arc::new(FanRegisters(state.clone()))).unwrap();
        let line = PowerLine::from_test_pin(owner.clone(), Box::new(BootPin(state.clone())));
        let until = if defect == 4 {
            Instant::now() + Duration::from_millis(1)
        } else {
            deadline()
        };
        let result = line.park_with_quiet_fans(until);
        assert!(owner.terminal() && owner.chains.is_empty());
        assert!(line.enable_source_line(deadline()).is_err());
        // enable's failure repeats high as cleanup, but never writes low.
        let events = state.events.lock().unwrap().clone();
        assert_eq!(events[0], "high");
        if defect == 0 {
            let (observed, quiet) = result.unwrap();
            assert!(observed.pin_high);
            assert_eq!((quiet.percent, quiet.register_word), (30, 0x000f_0023));
            assert_eq!(&events[..4], ["high", "high_read", "pwm_write", "pwm_read"]);
        } else {
            assert!(result.is_err());
            if defect == 1 || defect == 4 {
                assert!(!events.contains(&"pwm_write"));
            }
        }
    }
}
fn fixture() -> (
    Arc<RegistersFixture>,
    Arc<Mutex<PinState>>,
    PowerLine<RegistersFixture>,
) {
    let registers = Arc::new(RegistersFixture {
        forbidden: AtomicBool::new(false),
    });
    let owner = Transport::new(registers.clone(), vec![0, 1, 2]).unwrap();
    let pin = Arc::new(Mutex::new(PinState::default()));
    (
        registers,
        pin.clone(),
        PowerLine {
            owner,
            pin: Box::new(PinFixture(pin)),
            gate: Mutex::new(()),
        },
    )
}

#[test]
fn source_high_low_high_lifecycle_survives_unresolved_management_and_retains_terminal_fence() {
    let (_, pin, line) = fixture();
    line.initial_high(deadline()).unwrap();
    line.enable_source_line(deadline()).unwrap();
    let _asic = line.owner.lane.lock().unwrap();
    let _management = line.owner.management_lane.lock().unwrap();
    line.owner.management_fault.store(true, Ordering::SeqCst);
    assert!(line.terminal_high(deadline()).unwrap().pin_high);
    assert_eq!(pin.lock().unwrap().writes, [true, false, true]);
    assert!(line.enable_source_line(deadline()).is_err());
    assert!(!pin.lock().unwrap().writes.iter().skip(2).any(|high| !high));
    assert!(line.owner.terminal());
}

#[test]
fn failed_enable_attempts_high_before_unlock_and_failed_cut_never_returns_observation() {
    let (_, pin, line) = fixture();
    line.initial_high(deadline()).unwrap();
    pin.lock().unwrap().fail_low = true;
    assert!(line
        .enable_source_line(deadline())
        .unwrap_err()
        .contains("torn GPIO low"));
    assert_eq!(pin.lock().unwrap().writes, [true, false, true]);
    assert!(line.owner.terminal());
    pin.lock().unwrap().stuck_low = true;
    assert!(line.terminal_high(deadline()).is_err());
}

#[test]
fn inherited_owner_never_touches_pin_and_final_drop_only_attempts_source_high() {
    let (registers, pin, line) = fixture();
    registers.forbidden.store(true, Ordering::SeqCst);
    assert!(line.enable_source_line(deadline()).is_err());
    assert!(line.terminal_high(deadline()).is_err());
    drop(line);
    assert!(pin.lock().unwrap().writes.is_empty());
    let (_, pin, line) = fixture();
    drop(line);
    assert_eq!(pin.lock().unwrap().writes, [true]);
}
