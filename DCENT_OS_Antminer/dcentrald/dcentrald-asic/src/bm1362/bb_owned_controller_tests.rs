use super::*;
use crate::bm1362::uart_transport::BbOwnedController as ExportedController;
use dcentrald_hal::bb_management_runtime::simulated::Fixture;
use dcentrald_hal::platform::beaglebone::{
    BbHardwareFactory, BeagleBoneBoardTarget, BoardTargetPlatformSection,
};
use dcentrald_hal::platform::config::PlatformConfig;
use std::collections::BTreeMap;
use std::fs::File;
use std::future::{poll_fn, Future};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

fn due() -> Instant {
    Instant::now() + Duration::from_secs(12)
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
async fn opened(
    selected: &[u8],
    block_apw: bool,
    bad_factory: bool,
) -> (ExportedController, Fixture, Vec<Pty>) {
    let mut factory = BbHardwareFactory::new(platform(), selected, due())
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    let (services, fixture) = Fixture::factory_services(block_apw, bad_factory);
    let ptys: Vec<_> = (0..3).map(|_| Pty::new()).collect();
    let paths: Vec<_> = ptys.iter().map(Pty::path).collect();
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    assert!(factory
        .open_simulated_until(services, move |slot, configured| {
            assert_eq!(
                configured,
                ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS4"][slot as usize]
            );
            calls.fetch_add(1, Ordering::SeqCst);
            SerialChainBackend::open_native_linux_only(slot, &paths[slot as usize], 115_200)
        })
        .await
        .unwrap());
    let original = factory
        .take_ready()
        .unwrap_or_else(|error| panic!("{error}"));
    let before = pty_descriptors();
    let value = ExportedController::from_opened(original, 1);
    assert_eq!(
        pty_descriptors(),
        before,
        "constructor replaced/opened a PTY descriptor"
    );
    assert_eq!(count.load(Ordering::SeqCst), selected.len());
    assert_eq!(value.selected_eeproms(), selected);
    assert_eq!(
        value.original_chain_ids(),
        selected.iter().map(|v| v - 0x50).collect::<Vec<_>>()
    );
    assert!(factory.take_ready().is_err());
    drop(factory);
    (value, fixture, ptys)
}
fn retained(value: ExportedController) -> ExportedController {
    match value.try_into_closed() {
        Err(original) => original,
        Ok(_) => panic!("unjoined original owner became a closed owner"),
    }
}
fn closed(value: ExportedController) -> BbClosedController {
    match value.try_into_closed() {
        Ok(original) => original,
        Err(_) => panic!("original joined owner was not retained"),
    }
}

#[tokio::test]
async fn public_factory_transfer_retains_selected_order_and_original_pty_read() {
    let (mut value, fixture, mut ptys) = opened(&[0x52, 0x50], false, false).await;
    value.diagnose_held_until(due()).await.unwrap();
    assert!(value.snapshot().management().diagnostic_complete());
    ptys[2].master.write_all(&[0xaa, 0x55, 1, 2, 3]).unwrap();
    let mut poll = libc::pollfd {
        fd: ptys[2].slave.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized local PTY pollfd and a bounded timeout.
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 500) }, 1);
    value.observe_held_until(due()).await.unwrap();
    let state = value.snapshot();
    let UartOutput::Received(rx) = state.inner.uart.latest.unwrap().output.unwrap() else {
        panic!("actual original receive absent")
    };
    assert_eq!(rx.io[0].1.bytes, [0xaa, 0x55, 1, 2, 3]);
    assert_eq!(fixture.apw_opcodes(), [2, 1, 6, 3, 2, 1, 6, 3]);
    assert!(value.close_until(due()).await);
    let original = closed(value);
    assert_eq!(original.board_target_name(), "am3-bb-s19jpro");
    let _actual_receipts = original.management_receipts();
    assert!(original.snapshot().uart_terminal());
}

#[tokio::test]
async fn copied_observation_and_expired_close_cannot_replace_original_join() {
    let (value, _fixture, _ptys) = opened(&[0x51], false, false).await;
    let copied = value.snapshot().clone();
    let mut value = retained(value);
    assert!(!value.close_until(Instant::now()).await);
    let mut value = retained(value);
    assert!(!copied.uart_terminal());
    assert!(value.snapshot().uart_terminal());
    assert!(value.close_until(due()).await);
    let _original = closed(value);
}

#[tokio::test]
async fn cancelled_original_diagnostic_retains_blocked_worker_through_close_retry() {
    let (mut value, fixture, _ptys) = opened(&[0x50], true, false).await;
    {
        let mut call = Box::pin(value.diagnose_held_until(due()));
        tokio::select! {
            _ = fixture.wait_apw_entered() => {},
            result = &mut call => panic!("blocked original diagnostic returned: {result:?}"),
        }
    }
    assert!(value.snapshot().uart_terminal());
    assert!(
        !value
            .close_until(Instant::now() + Duration::from_millis(40))
            .await
    );
    let mut value = retained(value);
    fixture.release();
    assert!(value.close_until(due()).await);
    let _original = closed(value);
}

#[tokio::test]
async fn joined_diagnostics_without_actual_stable_actor_refuse_voltage_before_apw() {
    let (mut value, fixture, _ptys) = opened(&[0x50], false, false).await;
    value.diagnose_held_until(due()).await.unwrap();
    value.merge_requested_voltage(Some(13.4), None).unwrap();
    let before = fixture.apw_opcodes();
    assert!(value.voltage_held_until(due()).await.is_err());
    assert_eq!(fixture.apw_opcodes(), before);
    assert!(value.snapshot().uart_terminal());
    assert!(value.close_until(due()).await);
    let _original = closed(value);
}

struct Cutoff {
    stop: BbOwnedControllerStop,
    entered: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
}
impl Cutoff {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
impl BbHeartbeatCutoff for Cutoff {
    fn cutoff(&self) -> Result<(), String> {
        assert!(self.stop.0.uart.snapshot().permanently_stopped);
        self.entered.store(true, Ordering::SeqCst);
        let lock = self.released.lock().unwrap();
        let (_lock, timeout) = self
            .wake
            .wait_timeout_while(lock, Duration::from_secs(5), |v| !*v)
            .unwrap();
        assert!(
            !timeout.timed_out(),
            "bounded real cutoff callback did not release"
        );
        Ok(())
    }
}
struct Release(Arc<Cutoff>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test]
async fn independent_actor_callback_fences_original_uart_and_must_join_before_closed_transfer() {
    let (mut value, _fixture, _ptys) = opened(&[0x50], false, false).await;
    value.diagnose_held_until(due()).await.unwrap();
    let cutoff = Arc::new(Cutoff {
        stop: value.stop_handle(),
        entered: AtomicBool::new(false),
        released: Mutex::new(false),
        wake: Condvar::new(),
    });
    let _release = Release(cutoff.clone());
    value.start_heartbeat(cutoff.clone()).unwrap();
    value.cancel();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !cutoff.entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !value
            .close_until(Instant::now() + Duration::from_millis(40))
            .await
    );
    let mut value = retained(value);
    cutoff.release();
    assert!(value.close_until(due()).await);
    assert_eq!(
        Arc::strong_count(&cutoff),
        2,
        "joined HAL actor retained its GPIO callback"
    );
    let original = closed(value);
    let state = original.snapshot();
    let actor = state.heartbeat().unwrap();
    assert!(actor.caller_joined_at.is_some() && actor.monitor_joined_at.is_some());
    assert!(actor.cutoff.as_ref().unwrap().joined_at.is_some());
}

#[tokio::test]
async fn invalid_original_inventory_refuses_actor_start_and_closed_owner_requires_cleanup() {
    let (mut value, _fixture, _ptys) = opened(&[0x50], false, true).await;
    assert!(value.diagnose_held_until(due()).await.is_err());
    let cutoff = Arc::new(Cutoff {
        stop: value.stop_handle(),
        entered: AtomicBool::new(false),
        released: Mutex::new(true),
        wake: Condvar::new(),
    });
    assert!(value.start_heartbeat(cutoff.clone()).is_err());
    assert!(!cutoff.entered.load(Ordering::SeqCst));
    let mut value = retained(value);
    assert!(value.close_until(due()).await);
    let _original = closed(value);
}

#[tokio::test]
async fn cancelling_actual_stability_wait_fences_both_original_transports() {
    let (mut value, _fixture, _ptys) = opened(&[0x50], false, false).await;
    value.diagnose_held_until(due()).await.unwrap();
    let cutoff = Arc::new(Cutoff {
        stop: value.stop_handle(),
        entered: AtomicBool::new(false),
        released: Mutex::new(true),
        wake: Condvar::new(),
    });
    value.start_heartbeat(cutoff.clone()).unwrap();
    {
        let mut wait = Box::pin(value.wait_stable_heartbeat_until(due()));
        // Poll the actual production future to its first Pending; no clock,
        // completion record or stable-round observation is manufactured.
        poll_fn(|context| match wait.as_mut().poll(context) {
            std::task::Poll::Pending => std::task::Poll::Ready(()),
            std::task::Poll::Ready(result) => panic!("new actor wait did not suspend: {result:?}"),
        })
        .await;
    }
    assert!(value.snapshot().uart_terminal());
    assert!(value.snapshot().management().stopped());
    assert!(value.close_until(due()).await);
    let _original = closed(value);
    assert!(cutoff.entered.load(Ordering::SeqCst));
    assert_eq!(
        Arc::strong_count(&cutoff),
        1,
        "joined actor retained a private callback copy"
    );
}
