use super::*;
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use crate::platform::sim::{SimControllerKind, SimI2cBackend};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Condvar;
use std::time::Duration;

fn due() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn platform() -> BeagleBonePlatform {
    let mut value =
        BeagleBonePlatform::with_config(super::super::PlatformConfig::s19j_beaglebone());
    value.board_target.platform = Some(BoardTargetPlatformSection {
        board_target: Some("am3-bb-s19jpro".into()),
        soc: Some("am335x".into()),
        cpu: Some("cortex-a8".into()),
        io_board: Some("S19J_IO_BOARD_V2_0".into()),
        voltage_controller: Some("dspic33ep-fw89".into()),
    });
    value
}
fn factory(selected: &[u8], deadline: Instant) -> BbHardwareFactory {
    BbHardwareFactory::new(platform(), selected, deadline)
        .unwrap_or_else(|(_, error)| panic!("{error}"))
}
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}
impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            condition: Condvar::new(),
        })
    }
    fn wait(&self) {
        self.entered.store(true, Ordering::SeqCst);
        let guard = self.released.lock().unwrap();
        let (_guard, timed) = self
            .condition
            .wait_timeout_while(guard, Duration::from_secs(5), |released| !*released)
            .unwrap();
        assert!(!timed.timed_out(), "bounded factory fixture elapsed");
    }
    async fn entered(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct Backend {
    identity: SimI2cBackend,
    initialize: Option<Arc<Gate>>,
}
impl Backend {
    fn new(initialize: Option<Arc<Gate>>) -> Arc<Self> {
        Arc::new(Self {
            identity: SimI2cBackend::with_controller(SimControllerKind::Dspic),
            initialize,
        })
    }
}
impl I2cSimBackend for Backend {
    fn service_identity(&self) -> Option<usize> {
        self.identity.service_identity()
    }
    fn set_timeout(&self, _: u8, _: u32) -> crate::Result<()> {
        if let Some(gate) = &self.initialize {
            gate.wait();
        }
        Ok(())
    }
    fn write(&self, _: u8, _: u8, _: &[u8]) -> crate::Result<usize> {
        panic!("factory must not issue I2c writes")
    }
    fn read(&self, _: u8, _: u8, _: &mut [u8]) -> crate::Result<usize> {
        panic!("factory must not issue I2c reads")
    }
    fn write_read(&self, _: u8, _: u8, _: &[u8], _: &mut [u8]) -> crate::Result<()> {
        panic!("factory must not issue I2c write_read")
    }
}
fn bus_opener(
    a: Arc<Backend>,
    b: Arc<Backend>,
) -> impl FnMut(u8) -> std::io::Result<I2cServiceOwner> + Send + 'static {
    move |bus| {
        spawn_owned_sim_i2c_service(
            bus,
            if bus == 0 { a.clone() } else { b.clone() },
            (0x50..=0x57).collect(),
        )
    }
}
struct Pty {
    master: File,
    slave: File,
}
impl Pty {
    fn new() -> Self {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: fresh initialized output descriptors for a host-only PTY;
        // optional name/termios/window buffers are absent.
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
        // SAFETY: adopt the two distinct newly created descriptors once each.
        let master = unsafe { File::from_raw_fd(master) };
        // SAFETY: the fresh slave has not otherwise been adopted.
        let slave = unsafe { File::from_raw_fd(slave) };
        Self { master, slave }
    }
    fn path(&self) -> String {
        format!("/proc/self/fd/{}", self.slave.as_raw_fd())
    }
}
fn uart_opener(
    paths: Vec<String>,
) -> impl FnMut(u8, &str) -> crate::Result<SerialChainBackend> + Send + 'static {
    move |index, path| {
        assert_eq!(
            path,
            ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS4"][usize::from(index)]
        );
        SerialChainBackend::open_native_linux_only(index, &paths[usize::from(index)], 115_200)
    }
}
async fn reclaims(bus: u8, backend: Arc<Backend>) {
    // A new fixture claim after cleanup independently proves that the original
    // actual worker released its registry reservation. It is not a factory retry.
    let mut owner = spawn_owned_sim_i2c_service(bus, backend, vec![]).unwrap();
    assert!(
        tokio::task::spawn_blocking(move || owner.close_and_join_until(due()))
            .await
            .unwrap()
            .is_ok()
    );
}
fn closed(factory: &BbHardwareFactory, buses: &[u8]) {
    let state = factory.snapshot();
    assert!(state.stopped && !state.open_caller_pending && !state.close_caller_pending);
    let close = state.close.unwrap();
    assert!(close.failure.is_none() && close.uart_drop_returned_at.is_some());
    assert!(close.caller_returned_at.unwrap() <= close.caller_joined_at.unwrap());
    assert_eq!(close.service_receipts, buses);
}

#[tokio::test]
async fn original_platform_and_selected_order_handoff_to_live_management_and_actual_pty() {
    let mut factory = factory(&[0x52, 0x50], due());
    let a = Backend::new(None);
    let b = Backend::new(None);
    let mut ptys = [Pty::new(), Pty::new(), Pty::new()];
    assert!(factory
        .open_with(
            bus_opener(a.clone(), b.clone()),
            uart_opener(ptys.iter().map(Pty::path).collect()),
            || {}
        )
        .await
        .unwrap());
    let before = factory.snapshot();
    assert_eq!(
        before
            .open
            .uarts_opened
            .iter()
            .map(|item| item.0)
            .collect::<Vec<_>>(),
        [2, 0]
    );
    assert!(before.open.caller_returned_at.unwrap() <= before.open.caller_joined_at.unwrap());
    let original_name = factory
        .platform
        .as_ref()
        .unwrap()
        .board_target_name()
        .as_ptr();
    let parts = factory.take_ready().unwrap();
    let (platform, mut management, mut uarts, selected) = parts.into_parts();
    assert_eq!(platform.board_target_name().as_ptr(), original_name);
    assert_eq!(selected, [0x52, 0x50]);
    assert!(factory.take_ready().is_err());
    factory.cancel();
    drop(factory);
    assert!(!management.snapshot().stopped());
    let raw = uarts[0].write_raw_until(&[1, 2, 3, 4], due(), &|| false);
    assert_eq!(raw.accepted_prefix, [1, 2, 3, 4]);
    let mut wire = [0; 4];
    ptys[2].master.read_exact(&mut wire).unwrap();
    assert_eq!(wire, [1, 2, 3, 4]);
    assert!(management.close_until(due()).await);
    tokio::task::spawn_blocking(move || drop(uarts))
        .await
        .unwrap();
    reclaims(0, a).await;
    reclaims(1, b).await;
}

#[tokio::test]
async fn second_bus_creation_failure_retains_first_actual_worker_until_joined_cleanup() {
    let mut factory = factory(&[0x50], due());
    let a = Backend::new(None);
    let worker = a.clone();
    let opened = factory
        .open_with(
            move |bus| {
                if bus == 1 {
                    return Err(std::io::Error::other("bounded second bus failure"));
                }
                spawn_owned_sim_i2c_service(bus, worker.clone(), (0x50..=0x57).collect())
            },
            |_, _| panic!("no UART after bus failure"),
            || {},
        )
        .await
        .unwrap();
    assert!(!opened && factory.take_ready().is_err());
    assert!(spawn_owned_sim_i2c_service(0, a.clone(), vec![]).is_err());
    assert_eq!(factory.snapshot().open.services_spawned.len(), 1);
    assert!(factory.close_until(due()).await);
    closed(&factory, &[0]);
    reclaims(0, a).await;
}

#[tokio::test]
async fn later_uart_open_error_retains_both_services_and_first_exclusive_uart() {
    let mut factory = factory(&[0x50, 0x51], due());
    let a = Backend::new(None);
    let b = Backend::new(None);
    let pty = Pty::new();
    let path = pty.path();
    assert!(!factory
        .open_with(
            bus_opener(a.clone(), b.clone()),
            move |index, _| {
                if index == 1 {
                    return Err(crate::HalError::Platform(
                        "bounded second UART failure".into(),
                    ));
                }
                SerialChainBackend::open_native_linux_only(index, &path, 115_200)
            },
            || {}
        )
        .await
        .unwrap());
    let state = factory.snapshot();
    assert_eq!(state.open.services_spawned.len(), 2);
    assert_eq!(state.open.uarts_opened.len(), 1);
    assert!(state.open.failure.unwrap().contains("second UART failure"));
    assert!(factory.take_ready().is_err());
    assert!(factory.close_until(due()).await);
    closed(&factory, &[0, 1]);
    reclaims(0, a).await;
    reclaims(1, b).await;
}

#[tokio::test]
async fn returned_open_owners_cannot_transfer_before_actual_join_and_late_cleanup_cannot_promote() {
    let mut factory = factory(&[0x50], Instant::now() + Duration::from_millis(180));
    let a = Backend::new(None);
    let b = Backend::new(None);
    let pty = Pty::new();
    let gate = Gate::new();
    let _release = Release(gate.clone());
    let worker = gate.clone();
    let mut pending = Box::pin(factory.open_with(
        bus_opener(a.clone(), b.clone()),
        uart_opener(vec![pty.path()]),
        move || worker.wait(),
    ));
    tokio::select! {_=&mut pending=>panic!("tail is retained"),_=gate.entered()=>{}}
    drop(pending);
    let returned = factory.snapshot();
    assert!(returned.open.caller_returned_at.is_some() && returned.open.caller_joined_at.is_none());
    assert!(factory.take_ready().is_err());
    assert!(
        !factory
            .close_until(Instant::now() + Duration::from_millis(10))
            .await
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    gate.release();
    assert!(factory.close_until(due()).await);
    closed(&factory, &[0, 1]);
    assert!(factory.snapshot().open.accepted_at.is_none());
    assert!(factory.snapshot().open.failure.unwrap().contains("late"));
}

#[tokio::test]
async fn cancellation_during_second_service_open_fences_its_returned_owner_and_starts_no_uart() {
    let mut factory = factory(&[0x50], due());
    let a = Backend::new(None);
    let b = Backend::new(None);
    let mut opener = bus_opener(a.clone(), b.clone());
    let gate = Gate::new();
    let _release = Release(gate.clone());
    let worker = gate.clone();
    let mut pending = Box::pin(factory.open_with(
        move |bus| {
            let owner = opener(bus)?;
            if bus == 1 {
                worker.wait();
            }
            Ok(owner)
        },
        |_, _| panic!("cancelled factory cannot open UART"),
        || {},
    ));
    tokio::select! {_=&mut pending=>panic!("actual opener blocked"),_=gate.entered()=>{}}
    drop(pending);
    assert!(factory.snapshot().stopped);
    gate.release();
    assert!(factory.close_until(due()).await);
    closed(&factory, &[0, 1]);
    assert!(factory.snapshot().open.uarts_opened.is_empty());
    assert!(factory.snapshot().open.accepted_at.is_none());
    reclaims(0, a).await;
    reclaims(1, b).await;
}

#[tokio::test]
async fn caught_later_opener_unwind_preserves_partial_original_owners_for_close() {
    let mut factory = factory(&[0x50, 0x51], due());
    let a = Backend::new(None);
    let b = Backend::new(None);
    let pty = Pty::new();
    let path = pty.path();
    assert!(!factory
        .open_with(
            bus_opener(a.clone(), b.clone()),
            move |index, _| {
                if index == 1 {
                    panic!("bounded opener unwind");
                }
                SerialChainBackend::open_native_linux_only(index, &path, 115_200)
            },
            || {}
        )
        .await
        .unwrap());
    let state = factory.snapshot();
    assert_eq!(state.open.uarts_opened.len(), 1);
    assert!(state.open.failure.unwrap().contains("unwound"));
    assert!(factory.close_until(due()).await);
    closed(&factory, &[0, 1]);
    reclaims(0, a).await;
    reclaims(1, b).await;
}

#[tokio::test]
async fn exact_topology_and_selection_validation_preserves_original_platform_without_opening() {
    for selected in [
        vec![],
        vec![0x53],
        vec![0x50, 0x50],
        vec![0x50, 0x51, 0x52, 0x50],
    ] {
        let platform = platform();
        let ptr = platform.board_target_name().as_ptr();
        let Err((platform, _)) = BbHardwareFactory::new(platform, &selected, due()) else {
            panic!("invalid selection accepted")
        };
        assert_eq!(platform.board_target_name().as_ptr(), ptr);
    }
    let mut invalid = platform();
    invalid.board_target.gpio.board_enable = 65;
    assert!(BbHardwareFactory::new(invalid, &[0x50], due()).is_err());
    assert!(BbHardwareFactory::new(platform(), &[0x50], Instant::now()).is_err());
    let mut fallback = platform();
    fallback.board_target.platform = None;
    assert!(BbHardwareFactory::new(fallback, &[0x50], due()).is_err());
    let mut exact = platform();
    exact.board_target.platform = None;
    exact.identity_evidence = Am3BbIdentityEvidence::ExactDeviceTree;
    let mut exact = BbHardwareFactory::new(exact, &[0x50], due())
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    assert!(exact
        .platform
        .as_ref()
        .unwrap()
        .board_target
        .platform
        .is_none());
    assert!(exact.snapshot().open.started_at.is_none());
    assert!(exact.close_until(due()).await);
    closed(&exact, &[]);
    let mut wrong = platform();
    wrong.board_target.platform = None;
    wrong.identity_evidence = Am3BbIdentityEvidence::ExactDeviceTree;
    wrong.board_target.gpio.board_enable = 65;
    assert!(BbHardwareFactory::new(wrong, &[0x50], due()).is_err());
}

#[tokio::test]
async fn cancelled_and_timed_out_partial_close_retains_same_task_and_blocked_original_worker() {
    let mut factory = factory(&[0x50], due());
    let gate = Gate::new();
    let _release = Release(gate.clone());
    let a = Backend::new(None);
    let b = Backend::new(Some(gate.clone()));
    let pty = Pty::new();
    assert!(factory
        .open_with(
            bus_opener(a.clone(), b.clone()),
            uart_opener(vec![pty.path()]),
            || {}
        )
        .await
        .unwrap());
    gate.entered().await;
    let mut pending = Box::pin(factory.close_until(due()));
    tokio::select! {_=&mut pending=>panic!("original worker initializing"),_=tokio::time::sleep(Duration::from_millis(30))=>{}}
    drop(pending);
    let before = factory.snapshot();
    let close = before.close.unwrap();
    assert!(
        before.close_caller_pending
            && close.uart_drop_returned_at.is_some()
            && close.caller_returned_at.is_none()
    );
    assert!(
        !factory
            .close_until(Instant::now() + Duration::from_millis(10))
            .await
    );
    assert_eq!(
        factory.snapshot().close.unwrap().started_at,
        close.started_at
    );
    assert!(factory.take_ready().is_err());
    gate.release();
    assert!(factory.close_until(due()).await);
    closed(&factory, &[0, 1]);
    assert_eq!(
        factory.snapshot().close.unwrap().started_at,
        close.started_at
    );
    reclaims(0, a).await;
    reclaims(1, b).await;
}
