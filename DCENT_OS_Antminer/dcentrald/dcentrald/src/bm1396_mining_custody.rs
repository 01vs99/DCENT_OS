//! Detached native crash custody; not registered or compiled.
use crate::runtime::watchdog_feed_gate::WatchdogFeedStopSignal;
use anyhow::{anyhow, ensure, Result};
use dcentrald_hal::platform::stock_bm1396::{Hardware, PowerLine, Transport};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

struct Control<H: Hardware> {
    armed: AtomicBool,
    owner: Arc<Transport<H>>,
    line: Arc<PowerLine<H>>,
    feed: WatchdogFeedStopSignal,
    stop: CancellationToken,
}
trait CrashControl: Send + Sync {
    fn cut(&self);
    fn disarm(&self);
}
impl<H: Hardware> CrashControl for Control<H> {
    fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }
    fn cut(&self) {
        if !self.armed.load(Ordering::SeqCst) {
            return;
        }
        self.owner.begin_terminal();
        self.feed.close_terminal_lock_free();
        self.stop.cancel();
        // Actual independent source-high attempt, with no ASIC/management lock.
        // It cannot mint a typed successful watchdog-disarm receipt.
        let _ = self
            .line
            .emergency_high(Instant::now() + Duration::from_millis(100));
    }
}
pub(super) struct CrashGuard(Arc<dyn CrashControl>);
impl CrashGuard {
    pub(super) fn disarmed(&self) {
        self.0.disarm();
    }
}
impl Drop for CrashGuard {
    fn drop(&mut self) {
        self.0.cut();
    }
}
static CRASH: OnceLock<Mutex<Option<Weak<dyn CrashControl>>>> = OnceLock::new();

pub(super) fn install<H: Hardware>(
    owner: Arc<Transport<H>>,
    line: Arc<PowerLine<H>>,
    feed: WatchdogFeedStopSignal,
    stop: CancellationToken,
) -> Result<CrashGuard> {
    let guard = CrashGuard(Arc::new(Control {
        armed: AtomicBool::new(true),
        owner,
        line,
        feed,
        stop,
    }));
    let mut current = CRASH
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| anyhow!("BM1396 crash custody poisoned"))?;
    ensure!(
        current.as_ref().and_then(Weak::upgrade).is_none(),
        "BM1396 crash owner already present"
    );
    *current = Some(Arc::downgrade(&guard.0));
    Ok(guard)
}
pub(super) fn panic_teardown() {
    let Some(registry) = CRASH.get() else {
        return;
    };
    let Ok(current) = registry.try_lock() else {
        return;
    };
    let owner = current.as_ref().and_then(Weak::upgrade);
    drop(current);
    if let Some(owner) = owner {
        owner.cut();
    }
}
