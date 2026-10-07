use super::super::super::power::{ClassicAmlPowerOwner, ClassicControlCut, Controls};
use super::*;

#[derive(Default)]
struct ControlState {
    events: Vec<&'static str>,
    rail: bool,
    reset_release: [bool; 3],
}
#[derive(Default)]
struct MockControls {
    state: Mutex<ControlState>,
    terminal: AtomicBool,
    fail: Mutex<Option<&'static str>>,
    stopped_fan: AtomicBool,
    psu_failed: AtomicBool,
    configure_gate: Mutex<Option<Gate>>,
    heartbeat_gate: Mutex<Option<Gate>>,
    heartbeat_delay: Mutex<Duration>,
}
impl MockControls {
    fn event(&self, event: &'static str) -> Result<()> {
        if self.terminal.load(Ordering::SeqCst) {
            return Err(error("mock controls terminal"));
        }
        self.state.lock().unwrap().events.push(event);
        if event == "configure" {
            if let Some(gate) = self.configure_gate.lock().unwrap().take() {
                let _ = gate.started.send(());
                gate.release.recv_timeout(Duration::from_secs(3)).unwrap();
                if self.terminal.load(Ordering::SeqCst) {
                    self.psu_failed.store(true, Ordering::SeqCst);
                    return Err(error(
                        "mock interrupted PSU command requires retained parser custody",
                    ));
                }
            }
        }

        if *self.fail.lock().unwrap() == Some(event) {
            if matches!(event, "discover" | "configure" | "psu-heartbeat") {
                self.psu_failed.store(true, Ordering::SeqCst);
            }
            Err(error(format!("mock {event} failure")))
        } else {
            Ok(())
        }
    }
}
impl Controls for MockControls {
    fn fence(&self) {
        self.terminal.store(true, Ordering::SeqCst);
    }
    fn discover(&self, _: Instant) -> Result<()> {
        self.event("discover")
    }
    fn configure(&self, _: f64, _: Instant) -> Result<()> {
        self.event("configure")
    }
    fn heartbeat(&self, _: Instant) -> Result<()> {
        self.event("psu-heartbeat")?;
        if let Some(gate) = self.heartbeat_gate.lock().unwrap().take() {
            let _ = gate.started.send(());
            gate.release.recv_timeout(Duration::from_secs(3)).unwrap();
        }
        std::thread::sleep(*self.heartbeat_delay.lock().unwrap());
        Ok(())
    }
    fn rail(&self, on: bool, _: Instant) -> Result<()> {
        self.event("rail")?;
        self.state.lock().unwrap().rail = on;
        Ok(())
    }
    fn resets(&self, populated: [bool; 3], release: bool, _: Instant) -> Result<()> {
        self.event("resets")?;
        self.state.lock().unwrap().reset_release = populated.map(|p| p && release);
        Ok(())
    }
    fn verify(&self, populated: [bool; 3], rail: bool, released: bool, _: Instant) -> Result<()> {
        self.event("verify")?;
        let state = self.state.lock().unwrap();
        if state.rail != rail || state.reset_release != populated.map(|p| p && released) {
            return Err(error("mock actual GPIO state mismatch"));
        }
        Ok(())
    }
    fn fans(&self, _: Instant) -> Result<Vec<(u8, u32)>> {
        self.event("fans")?;
        Ok(vec![
            (0, 2000),
            (1, 2000),
            (
                2,
                if self.stopped_fan.load(Ordering::SeqCst) {
                    0
                } else {
                    2000
                },
            ),
            (3, 2000),
        ])
    }
    fn cut(&self, _: Instant) -> ClassicControlCut {
        self.fence();
        let mut state = self.state.lock().unwrap();
        state.events.push("cut");
        state.rail = false;
        state.reset_release = [false; 3];
        ClassicControlCut {
            attempted_at: Some(Instant::now()),
            rail_observed_at: Some(Instant::now()),
            rail_off: true,
            resets_held: true,
            quiet_fans: true,
            errors: vec![],
        }
    }
    fn close(&self, _: Instant) -> Result<()> {
        self.state.lock().unwrap().events.push("close");
        if self.psu_failed.load(Ordering::SeqCst) {
            Err(error("mock unresolved PSU custody"))
        } else {
            Ok(())
        }
    }
}
async fn fixture(
    populated: [bool; 3],
) -> (Arc<ClassicAmlPicOwner>, Arc<Backend>, Arc<MockControls>) {
    let pic = Backend::new(0);
    let identity = Backend::new(1);
    let owner = ClassicAmlPicOwner::observe_with(
        Observed::new(populated),
        deadline(),
        spawn_factory(pic.clone(), identity, Arc::new(Mutex::new(vec![]))),
    )
    .await
    .unwrap();
    // Power orchestration tests start after five independently covered rounds;
    // the separate enable test below checks the actual owner-side admission.
    {
        let mut state = owner.state.lock().await;
        state.stable = 5;
        state.last_round = Some(Instant::now());
    }
    (Arc::new(owner), pic, Arc::new(MockControls::default()))
}

#[tokio::test]
async fn actual_pic_worker_and_power_orchestrator_cover_every_selected_population() {
    for mask in 1u8..8 {
        let populated = [mask & 1 != 0, mask & 2 != 0, mask & 4 != 0];
        let (pic_owner, pic, controls) = fixture(populated).await;
        let owner = ClassicAmlPowerOwner::test_with(pic_owner, controls.clone());
        let health = owner
            .start_at(13.4, 1800, Instant::now() + Duration::from_secs(20))
            .await
            .unwrap();
        let selected: Vec<u8> = (1..=3)
            .filter(|chain| mask & (1 << (chain - 1)) != 0)
            .collect();
        assert_eq!(health.temperatures.len(), selected.len() * 4);
        assert_eq!(
            health.voltages.iter().map(|v| v.chain).collect::<Vec<_>>(),
            selected
        );
        owner.require_work_health_at(deadline()).await.unwrap();
        assert_eq!(controls.state.lock().unwrap().reset_release, populated);
        let enables: Vec<_> = pic
            .trace
            .lock()
            .unwrap()
            .frames
            .iter()
            .filter(|(_, f)| f == &[0x55, 0xaa, 5, 0x15, 1, 0, 0x1b])
            .map(|(a, _)| *a - 0x1f)
            .collect();
        assert_eq!(enables, selected);
        let events = controls.state.lock().unwrap().events.clone();
        assert!(
            events.iter().position(|e| *e == "discover") < events.iter().position(|e| *e == "rail")
        );
        assert!(
            events.iter().position(|e| *e == "configure")
                < events.iter().position(|e| *e == "resets")
        );
        let close = owner.close_at(deadline()).await;
        assert!(close.software_cleanup_complete(), "{close:?}");
        assert!(!controls.state.lock().unwrap().rail);
        assert!(owner.require_work_health_at(deadline()).await.is_err());
    }
}

#[tokio::test]
async fn source_paced_three_board_refresh_returns_its_own_fresh_timestamp_to_waiting_work() {
    let (pic, _, controls) = fixture([true, true, true]).await;
    // PIC simulation uses the actual production 50/100/50ms LM75 delays and
    // 50ms application waits. Add the real PSU provider's350ms response wait.
    *controls.heartbeat_delay.lock().unwrap() = Duration::from_millis(350);
    let owner = Arc::new(ClassicAmlPowerOwner::test_with(pic, controls.clone()));
    owner
        .start_at(13.4, 1800, Instant::now() + Duration::from_secs(20))
        .await
        .unwrap();
    let (started, seen) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    *controls.heartbeat_gate.lock().unwrap() = Some(Gate {
        started,
        release: wait,
    });
    let refresh_owner = owner.clone();
    let refresh = tokio::spawn(async move {
        refresh_owner
            .health_at(Instant::now() + Duration::from_secs(5))
            .await
    });
    seen.await.unwrap();
    let work_owner = owner.clone();
    let mut work = tokio::spawn(async move {
        work_owner
            .require_work_health_at(Instant::now() + Duration::from_secs(5))
            .await
    });
    release.send(()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1100), &mut work)
            .await
            .is_err(),
        "work must await the actual complete scan rather than an arbitrary1s deadline"
    );
    let health = refresh.await.unwrap().unwrap();
    assert!(
        health.completed_at.duration_since(health.observed_from) >= Duration::from_millis(3350)
    );
    let observed = work.await.unwrap().unwrap();
    assert_eq!(observed, health.observed_from);
    assert!(observed.elapsed() < Duration::from_secs(5));
    assert!(!controls.terminal.load(Ordering::SeqCst));
    assert!(owner.close_at(deadline()).await.software_cleanup_complete());
}

#[tokio::test]
async fn each_control_failure_closes_work_and_still_attempts_all_pic_cuts() {
    for failed in [
        "fans",
        "discover",
        "rail",
        "configure",
        "resets",
        "psu-heartbeat",
    ] {
        let (pic_owner, pic, controls) = fixture([true, false, true]).await;
        *controls.fail.lock().unwrap() = Some(failed);
        let owner = ClassicAmlPowerOwner::test_with(pic_owner, controls.clone());
        assert!(
            owner
                .start_at(13.4, 1800, Instant::now() + Duration::from_secs(20))
                .await
                .is_err(),
            "{failed}"
        );
        assert!(controls.terminal.load(Ordering::SeqCst));
        assert!(owner.require_work_health_at(deadline()).await.is_err());
        let close = owner.close_at(deadline()).await;
        assert_eq!(
            close.software_cleanup_complete(),
            !matches!(failed, "discover" | "configure" | "psu-heartbeat"),
            "{failed}: {close:?}"
        );
        let cuts: Vec<_> = pic
            .trace
            .lock()
            .unwrap()
            .frames
            .iter()
            .filter(|(_, f)| f == &[0x55, 0xaa, 5, 0x15, 0, 0, 0x1a])
            .map(|(a, _)| *a)
            .collect();
        assert_eq!(cuts, [0x20, 0x22]);
        assert_eq!(controls.state.lock().unwrap().reset_release, [false; 3]);
    }
}

#[tokio::test]
async fn live_fan_failure_fences_composition_and_independent_cut_precedes_owner_release() {
    let (pic_owner, _, controls) = fixture([true, true, true]).await;
    let owner = ClassicAmlPowerOwner::test_with(pic_owner, controls.clone());
    owner
        .start_at(13.4, 1800, Instant::now() + Duration::from_secs(20))
        .await
        .unwrap();
    controls.stopped_fan.store(true, Ordering::SeqCst);
    assert!(owner.health_at(deadline()).await.is_err());
    assert!(owner.require_work_health_at(deadline()).await.is_err());
    let closed = owner.close_at(deadline()).await;
    assert!(closed.software_cleanup_complete());
    let state = controls.state.lock().unwrap();
    assert!(
        state.events.iter().position(|e| *e == "cut")
            < state.events.iter().position(|e| *e == "close")
    );
}

#[tokio::test]
async fn private_enable_refuses_missing_or_expired_rounds_before_any_enable_byte() {
    for (stable, age) in [(0, 0), (4, 0), (5, 4)] {
        let (owner, pic, _) = fixture([true, false, true]).await;
        {
            let mut state = owner.state.lock().await;
            state.stable = stable;
            state.last_round = Some(Instant::now() - Duration::from_secs(age));
        }
        let before = pic.trace.lock().unwrap().writes.len();
        assert!(owner.enable_at(deadline()).await.is_err());
        assert_eq!(pic.trace.lock().unwrap().writes.len(), before);
        owner.close_at(deadline()).await.unwrap();
    }
}

#[test]
fn queued_cut_reports_worker_attempt_time_and_not_the_earlier_request() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (pic, _, controls) = fixture([true, false, false]).await;
        let owner = Arc::new(ClassicAmlPowerOwner::test_with(pic, controls));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let blocker = tokio::task::spawn_blocking(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        entered_rx.await.unwrap();
        let requested = Instant::now();
        let closing_owner = owner.clone();
        let close = tokio::spawn(async move {
            closing_owner
                .close_at(Instant::now() + Duration::from_secs(2))
                .await
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        let report = close.await.unwrap();
        assert!(report.software_cleanup_complete(), "{report:?}");
        assert!(report.cutoff_started().unwrap() >= requested + Duration::from_millis(40));
        assert!(report.cutoff_observed_at().unwrap() >= report.cutoff_started().unwrap());
        assert!(report.same_owner(&owner));
    });
}

#[tokio::test]
async fn dropped_start_fences_running_psu_and_retains_worker_until_it_exits() {
    let (pic, _, controls) = fixture([true, false, false]).await;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    *controls.configure_gate.lock().unwrap() = Some(Gate {
        started: started_tx,
        release: release_rx,
    });
    let owner = Arc::new(ClassicAmlPowerOwner::test_with(pic, controls.clone()));
    let runner = owner.clone();
    let caller = tokio::spawn(async move {
        runner
            .start_at(13.4, 1800, Instant::now() + Duration::from_secs(20))
            .await
    });
    started_rx.await.unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(controls.terminal.load(Ordering::SeqCst));
    assert!(owner.require_work_health_at(deadline()).await.is_err());
    let close = owner
        .close_at(Instant::now() + Duration::from_millis(300))
        .await;
    assert!(!close.software_cleanup_complete());
    assert!(close
        .errors()
        .iter()
        .any(|e| e.contains("workers did not quiesce")));
    assert!(
        !controls.state.lock().unwrap().rail,
        "independent cut must not await PSU parser"
    );
    release_tx.send(()).unwrap();
    let close = owner.close_at(deadline()).await;
    assert!(
        !close.software_cleanup_complete(),
        "interrupted PSU custody cannot become healthy"
    );
}
