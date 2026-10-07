//! Actual watchdog worker with a modeled descriptor, only in sim-hal unit tests.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};

#[derive(Default)]
pub(crate) struct Observation {
    kicks: AtomicUsize,
    closes: AtomicUsize,
    drops_armed: AtomicUsize,
    close_fails: AtomicBool,
}
impl Observation {
    pub(crate) fn kicks(&self) -> usize {
        self.kicks.load(Ordering::SeqCst)
    }
    pub(crate) fn closes(&self) -> usize {
        self.closes.load(Ordering::SeqCst)
    }
    pub(crate) fn drops_armed(&self) -> usize {
        self.drops_armed.load(Ordering::SeqCst)
    }
    pub(crate) fn refuse_close(&self) {
        self.close_fails.store(true, Ordering::SeqCst);
    }
}
struct Device {
    observation: Arc<Observation>,
    closed: bool,
}
impl WatchdogDevice for Device {
    fn set_timeout(&self, seconds: u32) -> std::result::Result<u32, String> {
        Ok(seconds)
    }
    fn kick(&self) -> std::result::Result<(), String> {
        self.observation.kicks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn try_close_magic(&mut self) -> std::result::Result<(), String> {
        if self.observation.close_fails.load(Ordering::SeqCst) {
            return Err("modeled watchdog refuses magic close".into());
        }
        self.observation.closes.fetch_add(1, Ordering::SeqCst);
        self.closed = true;
        Ok(())
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        if !self.closed {
            self.observation.drops_armed.fetch_add(1, Ordering::SeqCst);
        }
    }
}
pub(crate) async fn start(
    config: &WatchdogConfig,
    liveness: SafetyLiveness,
) -> Result<(SafetyWatchdogOwner, Arc<Observation>)> {
    start_with_grace(config, liveness, Duration::from_secs(900)).await
}

pub(crate) async fn start_with_grace(
    config: &WatchdogConfig,
    liveness: SafetyLiveness,
    grace: Duration,
) -> Result<(SafetyWatchdogOwner, Arc<Observation>)> {
    anyhow::ensure!(
        !grace.is_zero() && grace <= Duration::from_secs(900),
        "modeled startup grace is unbounded"
    );
    let observation = Arc::new(Observation::default());
    let device_observation = observation.clone();
    let (owner, admission) = SafetyWatchdogOwner::start_with_factory(
        config,
        grace,
        Duration::from_secs(3),
        liveness,
        Box::new(move || {
            Ok(Box::new(Device {
                observation: device_observation,
                closed: false,
            }))
        }),
    )
    .await?;
    admission.require_armed("bm1396-modeled-native-runtime")?;
    Ok((owner, observation))
}
