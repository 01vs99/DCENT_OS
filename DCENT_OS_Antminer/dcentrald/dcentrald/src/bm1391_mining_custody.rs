//! Retained queued/running blocking workers and independent health observations.
use super::*;
use crate::runtime::watchdog_feed_gate::WatchdogFeedStopSignal;
use dcentrald_hal::platform::stock_bm1391::{Registers, ThermalSensor};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{OnceLock, Weak};

/// Stop-only crash ownership. Emergency GPIO observation never mints the
/// watchdog manifest used by normal same-owner terminal closeout.
pub(super) trait CrashSource: Send + Sync + 'static {
    fn latch_terminal(&self);
    fn high(&self, deadline: Instant);
}
pub(super) struct NativeCrashSource {
    owner: Arc<NativeTransport>,
    line: Arc<PowerLine<NativeMmio>>,
}
impl CrashSource for NativeCrashSource {
    fn latch_terminal(&self) {
        self.owner.latch_terminal();
    }
    fn high(&self, deadline: Instant) {
        let _ = self.line.terminal_high(deadline);
    }
}
struct CrashControl<S: CrashSource> {
    armed: AtomicBool,
    source: S,
    feed: WatchdogFeedStopSignal,
    shutdown: CancellationToken,
}
impl<S: CrashSource> CrashControl<S> {
    fn stop(&self) {
        if !self.armed.load(Ordering::SeqCst) {
            return;
        }
        self.source.latch_terminal();
        self.feed.close_terminal_lock_free();
        self.shutdown.cancel();
        // GPIO has its own retained pin lock; no ASIC, management or watchdog
        // kick lock is needed. A stuck pin operation can only fail this attempt.
        self.source
            .high(Instant::now() + Duration::from_millis(100));
    }
}
pub(super) struct CrashGuard<S: CrashSource = NativeCrashSource>(Arc<CrashControl<S>>);
impl<S: CrashSource> CrashGuard<S> {
    /// Caller clears this only after the actual typed disarm-and-join receipt.
    pub fn disarmed(&self) {
        self.0.armed.store(false, Ordering::SeqCst);
    }
}
impl<S: CrashSource> Drop for CrashGuard<S> {
    fn drop(&mut self) {
        self.0.stop();
    }
}
static CRASH: OnceLock<Mutex<Option<Weak<CrashControl<NativeCrashSource>>>>> = OnceLock::new();
pub(super) fn install_crash_guard(
    owner: Arc<NativeTransport>,
    line: Arc<PowerLine<NativeMmio>>,
    feed: WatchdogFeedStopSignal,
    shutdown: CancellationToken,
) -> Result<CrashGuard> {
    let guard = CrashGuard(Arc::new(CrashControl {
        armed: AtomicBool::new(true),
        source: NativeCrashSource { owner, line },
        feed,
        shutdown,
    }));
    let mut registered = CRASH
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| anyhow!("BM1391 crash custody registry poisoned"))?;
    ensure!(
        registered.as_ref().and_then(Weak::upgrade).is_none(),
        "BM1391 crash custody already owned"
    );
    *registered = Some(Arc::downgrade(&guard.0));
    Ok(guard)
}
pub(super) fn panic_teardown() {
    let Some(registry) = CRASH.get() else {
        return;
    };
    let Ok(registered) = registry.try_lock() else {
        return;
    };
    let owner = registered.as_ref().and_then(Weak::upgrade);
    drop(registered);
    if let Some(owner) = owner {
        owner.stop();
    }
}

/// Recent rate uses real elapsed time and at least five seconds of independent
/// CPU-difficulty64 ticket observations. More frequent API publication reuses
/// the last complete window rather than relabeling a shorter sample as five seconds.
pub(super) struct TicketRateWindow {
    previous: Instant,
    totals: [u64; 3],
    rates: [f64; 3],
}
impl TicketRateWindow {
    pub fn new(now: Instant) -> Self {
        Self {
            previous: now,
            totals: [0; 3],
            rates: [0.0; 3],
        }
    }
    pub fn observe(&mut self, now: Instant, totals: [u64; 3]) -> Result<[f64; 3]> {
        ensure!(
            now >= self.previous,
            "BM1391 ticket observation time rewound"
        );
        ensure!(
            totals
                .iter()
                .zip(self.totals)
                .all(|(current, previous)| *current >= previous),
            "BM1391 lifetime ticket observation counter rewound"
        );
        let elapsed = now.duration_since(self.previous);
        if elapsed >= Duration::from_secs(5) {
            self.rates = std::array::from_fn(|i| {
                (totals[i] - self.totals[i]) as f64 * 64.0 * 4.294967296 / elapsed.as_secs_f64()
            });
            self.previous = now;
            self.totals = totals;
        }
        Ok(self.rates)
    }
}

pub(super) struct BlockingOwner<R: Registers = NativeMmio> {
    owner: Arc<Transport<R>>,
    queued_or_running: AtomicUsize,
    closed: AtomicBool,
}
struct CountedWorker<R: Registers>(Arc<BlockingOwner<R>>);
impl<R: Registers> Drop for CountedWorker<R> {
    fn drop(&mut self) {
        self.0.queued_or_running.fetch_sub(1, Ordering::SeqCst);
    }
}
struct AwaitingWorker<R: Registers> {
    owner: Arc<Transport<R>>,
    completed: bool,
}
impl<R: Registers> Drop for AwaitingWorker<R> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.latch_terminal();
        }
    }
}
impl<R: Registers> BlockingOwner<R> {
    pub fn new(owner: Arc<Transport<R>>) -> Arc<Self> {
        Arc::new(Self {
            owner,
            queued_or_running: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        })
    }
    pub async fn run<T: Send + 'static>(
        self: &Arc<Self>,
        deadline: Instant,
        operation: impl FnOnce(Arc<Transport<R>>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        ensure!(
            !self.closed.load(Ordering::SeqCst),
            "BM1391 blocking worker owner closed"
        );
        self.queued_or_running.fetch_add(1, Ordering::SeqCst);
        let worker = CountedWorker(self.clone());
        let mut pending = AwaitingWorker {
            owner: self.owner.clone(),
            completed: false,
        };
        let result = tokio::task::spawn_blocking(move || {
            let _worker = worker;
            ensure!(
                !_worker.0.closed.load(Ordering::SeqCst) && Instant::now() < deadline,
                "BM1391 queued worker missed original admission deadline"
            );
            let result = operation(_worker.0.owner.clone());
            if result.is_err() {
                _worker.0.owner.latch_terminal();
            }
            result
        })
        .await
        .context("BM1391 retained blocking worker panicked")?;
        if result.is_err() {
            self.owner.latch_terminal();
        }
        pending.completed = true;
        result
    }
    pub async fn drain(&self, deadline: Instant) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        while self.queued_or_running.load(Ordering::SeqCst) != 0 {
            ensure!(
                Instant::now() < deadline,
                "BM1391 retained worker drain expired"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        ensure!(
            Instant::now() < deadline,
            "BM1391 retained worker drain completed late"
        );
        Ok(())
    }
}

/// Pool metadata invalidation cannot stop already published physical work.
/// Until a source-backed resumable engine stop exists, that transition must
/// leave the mining loop and enter the route's terminal physical closeout.
#[derive(Default)]
pub(super) struct PublishedPoolWork(AtomicBool);
impl PublishedPoolWork {
    pub fn mark_published(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn require_unpublished_for_invalidation(&self) -> Result<()> {
        ensure!(
            !self.0.load(Ordering::SeqCst),
            "BM1391 pool disconnected or flushed after physical work; terminal source cut required"
        );
        Ok(())
    }
}

#[derive(Clone, Default)]
pub(super) struct Health {
    pub fans: BTreeMap<u8, u32>,
    pub admitted_fans: Vec<u8>,
    pub temperatures: Vec<BoardTemperature>,
    pub require_temperature: bool,
    thermal_sensors: Vec<ThermalSensor>,
}
impl Health {
    pub fn fans(&mut self, snapshot: FanTachSnapshot, establish: bool) -> Result<()> {
        ensure!(
            snapshot.observed_at.elapsed() < Duration::from_secs(2),
            "BM1391 fan response arrived stale"
        );
        let mut fans = BTreeMap::new();
        for sample in snapshot.samples.iter().flatten() {
            // Source4ff84/4ffb4 admits any responding ID0..7 with RPM>500.
            fans.insert(sample.fan_index, sample.stock_rpm);
        }
        if establish {
            self.admitted_fans = fans
                .iter()
                .filter(|(_, rpm)| **rpm > 500)
                .map(|(id, _)| *id)
                .collect();
            ensure!(self.admitted_fans.len() >= 2, "BM1391 needs at least two responding fan IDs above stock500RPM threshold at quiet30");
        }
        ensure!(
            !self.admitted_fans.is_empty()
                && self
                    .admitted_fans
                    .iter()
                    .all(|id| fans.get(id).is_some_and(|rpm| *rpm > 500)),
            "BM1391 an admitted fan stopped or disappeared"
        );
        self.fans = fans;
        Ok(())
    }
    pub fn bind_thermal_sensors(
        &mut self,
        sensors: Vec<ThermalSensor>,
        chains: &[u8],
    ) -> Result<()> {
        ensure!(
            self.thermal_sensors.is_empty(),
            "BM1391 thermal topology already bound"
        );
        let mut endpoints = std::collections::BTreeSet::new();
        ensure!(
            !chains.is_empty()
                && !sensors.is_empty()
                && sensors.iter().all(|sensor| chains.contains(&sensor.chain)
                    && endpoints.insert((
                        sensor.chain,
                        sensor.chip_address,
                        sensor.sensor_address
                    )))
                && chains
                    .iter()
                    .all(|chain| sensors.iter().any(|sensor| sensor.chain == *chain)),
            "BM1391 initialized thermal topology is incomplete, duplicated or foreign"
        );
        self.thermal_sensors = sensors;
        Ok(())
    }
    pub fn check_temperatures(&self, profile: Profile, chains: &[u8]) -> Result<()> {
        if !self.require_temperature {
            return Ok(());
        }
        ensure!(
            !self.thermal_sensors.is_empty()
                && self.temperatures.len() == self.thermal_sensors.len()
                && self.thermal_sensors.iter().all(|sensor| {
                    chains.contains(&sensor.chain)
                        && self
                            .temperatures
                            .iter()
                            .filter(|reading| reading.sensor == *sensor)
                            .count()
                            == 1
                })
                && chains.iter().all(|chain| self
                    .thermal_sensors
                    .iter()
                    .any(|sensor| sensor.chain == *chain)),
            "BM1391 missing selected-board thermal observation"
        );
        for reading in &self.temperatures {
            ensure!(
                reading.observed_at.elapsed() < Duration::from_secs(8),
                "BM1391 board temperature reply is stale"
            );
            ensure!(
                reading.pcb_celsius < profile.cutoff_c
                    && reading.estimated_chip_celsius < profile.cutoff_c,
                "BM1391 board temperature or stockPCB+15 estimate reached configured cutoff"
            );
        }
        Ok(())
    }
}

pub(super) fn fault(
    owner: &NativeTransport,
    fault: &watch::Sender<Option<String>>,
    error: impl std::fmt::Display,
) {
    owner.latch_terminal();
    fault.send_if_modified(|first| {
        if first.is_some() {
            false
        } else {
            *first = Some(error.to_string());
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_hal::platform::stock_bm1391::FanTachSample;
    struct RegistersFixture;
    impl Registers for RegistersFixture {
        fn read(&self, offset: u32) -> Result<u32, String> {
            Ok(match offset {
                0 => 0xc501,
                8 => 1,
                _ => 0,
            })
        }
        fn write(&self, _: u32, _: u32) -> Result<(), String> {
            panic!("custody test must perform no hardware store")
        }
    }
    struct CrashFixture {
        terminal: Arc<AtomicBool>,
        cuts: Arc<AtomicUsize>,
        feed: crate::runtime::watchdog_feed_gate::WatchdogFeedGate,
        shutdown: CancellationToken,
    }
    impl CrashSource for CrashFixture {
        fn latch_terminal(&self) {
            self.terminal.store(true, Ordering::SeqCst);
        }
        fn high(&self, until: Instant) {
            assert!(self.terminal.load(Ordering::SeqCst));
            assert!(self.shutdown.is_cancelled());
            assert_eq!(
                self.feed
                    .try_kick(|| -> Result<(), ()> { panic!("late feed after emergency") })
                    .unwrap(),
                crate::runtime::watchdog_feed_gate::WatchdogFeedOutcome::WithheldTerminal
            );
            assert!(until > Instant::now() && until <= Instant::now() + Duration::from_millis(100));
            self.cuts.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn crash_fixture() -> (
        CrashGuard<CrashFixture>,
        Arc<AtomicBool>,
        Arc<AtomicUsize>,
        crate::runtime::watchdog_feed_gate::WatchdogFeedGateOwner,
    ) {
        let feed = crate::runtime::watchdog_feed_gate::WatchdogFeedGateOwner::new();
        let terminal = Arc::new(AtomicBool::new(false));
        let cuts = Arc::new(AtomicUsize::new(0));
        let shutdown = CancellationToken::new();
        (
            CrashGuard(Arc::new(CrashControl {
                armed: AtomicBool::new(true),
                source: CrashFixture {
                    terminal: terminal.clone(),
                    cuts: cuts.clone(),
                    feed: feed.gate(),
                    shutdown: shutdown.clone(),
                },
                feed: feed.stop_signal(),
                shutdown,
            })),
            terminal,
            cuts,
            feed,
        )
    }
    #[test]
    fn crash_and_future_drop_fence_work_and_feeds_before_independent_gpio_attempt() {
        let (guard, terminal, cuts, _feed) = crash_fixture();
        guard.0.stop();
        assert!(terminal.load(Ordering::SeqCst));
        assert_eq!(cuts.load(Ordering::SeqCst), 1);
        drop(guard);
        assert_eq!(cuts.load(Ordering::SeqCst), 2);
    }
    #[tokio::test]
    async fn aborting_a_runtime_future_retains_and_runs_its_crash_drop() {
        let (guard, terminal, cuts, _feed) = crash_fixture();
        let (started, entered) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _guard = guard;
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        entered.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(terminal.load(Ordering::SeqCst));
        assert_eq!(cuts.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn only_completed_disarm_disables_the_drop_cut() {
        let (guard, terminal, cuts, _feed) = crash_fixture();
        guard.disarmed();
        drop(guard);
        assert!(!terminal.load(Ordering::SeqCst));
        assert_eq!(cuts.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn recent_ticket_rate_waits_for_real_five_second_window_and_uses_actual_elapsed_time() {
        let start = Instant::now();
        let mut window = TicketRateWindow::new(start);
        assert_eq!(
            window
                .observe(start + Duration::from_secs(2), [2, 0, 0])
                .unwrap(),
            [0.0; 3]
        );
        assert_eq!(
            window
                .observe(start + Duration::from_secs(4), [4, 0, 0])
                .unwrap(),
            [0.0; 3]
        );
        let first = window
            .observe(start + Duration::from_secs(6), [6, 3, 0])
            .unwrap();
        assert!((first[0] - 64.0 * 4.294967296).abs() < 1e-9);
        assert!((first[1] - 32.0 * 4.294967296).abs() < 1e-9);
        assert_eq!(first[2], 0.0);
        assert_eq!(
            window
                .observe(start + Duration::from_secs(8), [6, 3, 0])
                .unwrap(),
            first
        );
        assert_eq!(
            window
                .observe(start + Duration::from_secs(12), [6, 3, 0])
                .unwrap(),
            [0.0; 3]
        );
        assert!(window
            .observe(start + Duration::from_secs(13), [5, 3, 0])
            .is_err());
        assert!(window
            .observe(start + Duration::from_secs(11), [6, 3, 0])
            .is_err());
    }
    #[test]
    fn initial_pool_connect_can_wait_but_published_work_cannot_be_metadata_only_invalidated() {
        let work = PublishedPoolWork::default();
        work.require_unpublished_for_invalidation().unwrap();
        work.require_unpublished_for_invalidation().unwrap();
        work.mark_published();
        assert!(work.require_unpublished_for_invalidation().is_err());
        // Disconnect never resets this lifetime physical publication fact.
        assert!(work.require_unpublished_for_invalidation().is_err());
    }
    #[test]
    fn cancelled_queued_worker_remains_counted_until_it_is_dequeued() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap()
            .block_on(async {
                let owner = Transport::new(Arc::new(RegistersFixture), vec![0]).unwrap();
                let workers = BlockingOwner::new(owner.clone());
                let (release, hold) = std::sync::mpsc::channel();
                let (started_tx, started_rx) = tokio::sync::oneshot::channel();
                let occupying = tokio::task::spawn_blocking(move || {
                    started_tx.send(()).unwrap();
                    hold.recv().unwrap();
                });
                started_rx.await.unwrap();
                let queued = workers.clone();
                let caller = tokio::spawn(async move { queued.run(deadline(2), |_| Ok(())).await });
                while workers.queued_or_running.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
                caller.abort();
                assert!(caller.await.unwrap_err().is_cancelled());
                assert!(owner.terminal());
                assert!(workers
                    .drain(Instant::now() + Duration::from_millis(5))
                    .await
                    .is_err());
                assert_eq!(workers.queued_or_running.load(Ordering::SeqCst), 1);
                release.send(()).unwrap();
                occupying.await.unwrap();
                workers.drain(deadline(1)).await.unwrap();
                assert_eq!(workers.queued_or_running.load(Ordering::SeqCst), 0);
            });
    }
    fn fans(values: &[(u8, u8)]) -> FanTachSnapshot {
        FanTachSnapshot {
            observed_at: Instant::now(),
            samples: std::array::from_fn(|i| {
                values.get(i).map(|(id, count)| FanTachSample {
                    raw_word: u32::from(*id) << 8 | u32::from(*count),
                    fan_index: *id,
                    raw_count: *count,
                    stock_rpm: u32::from(*count) * 120,
                })
            }),
        }
    }
    #[test]
    fn quiet_fan_population_is_observed_and_dropout_checks_keep_those_ids() {
        let mut health = Health::default();
        health.fans(fans(&[(3, 6), (6, 5)]), true).unwrap();
        assert_eq!(health.admitted_fans, vec![3, 6]);
        assert!(health.fans(fans(&[(0, 7), (1, 8)]), false).is_err());
        assert!(health.fans(fans(&[(3, 4), (6, 5)]), false).is_err());
        health.fans(fans(&[(3, 6), (6, 8)]), false).unwrap();
    }
    #[test]
    fn duplicate_tach_ids_and_values_at_or_below500rpm_cannot_admit_two_fans() {
        assert!(Health::default()
            .fans(fans(&[(2, 8), (2, 9)]), true)
            .is_err());
        assert!(Health::default()
            .fans(fans(&[(2, 4), (7, 8)]), true)
            .is_err());
    }
}

#[cfg(test)]
#[path = "bm1391_mining_thermal_health_tests.rs"]
mod thermal_health_tests;
