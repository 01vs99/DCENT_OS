//! One retained opening lifetime for captured BB topology and partial resources.
//! No GPIO, power, reset, bus requests or ASIC commands are issued here.
//! Service creation is not kernel-adapter readiness; original diagnostics must
//! subsequently establish usable communication through those same workers.
use super::{
    validate_supported_board_target, Am3BbIdentityEvidence, BeagleBonePlatform,
    BoardTargetPlatformSection,
};
use crate::bb_management_runtime::BbManagementRuntime;
use crate::i2c::{
    spawn_owned_i2c_service_no_register_touch_with_denylist_and_reserved_preparation,
    I2cServiceCloseReceipt, I2cServiceOwner, I2cServiceTerminalFence,
};
use crate::serial_chain::SerialChainBackend;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Instant;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub struct BbFactoryOpenObservation {
    pub deadline: Instant,
    pub started_at: Option<Instant>,
    pub services_spawned: Vec<(u8, Instant)>,
    pub uarts_opened: Vec<(u8, Instant)>,
    pub caller_returned_at: Option<Instant>,
    pub caller_joined_at: Option<Instant>,
    pub accepted_at: Option<Instant>,
    pub transferred_at: Option<Instant>,
    pub failure: Option<String>,
}
#[derive(Clone, Debug)]
pub struct BbFactoryCloseObservation {
    pub attempt: u64,
    pub deadline: Instant,
    pub started_at: Instant,
    pub uart_drop_returned_at: Option<Instant>,
    pub service_receipts: Vec<u8>,
    pub caller_returned_at: Option<Instant>,
    pub caller_joined_at: Option<Instant>,
    pub failure: Option<String>,
}
#[derive(Clone, Debug)]
pub struct BbFactoryObservation {
    pub stopped: bool,
    pub open_caller_pending: bool,
    pub close_caller_pending: bool,
    pub open: BbFactoryOpenObservation,
    pub close: Option<BbFactoryCloseObservation>,
}

#[derive(Default)]
struct Partial {
    services: [Option<I2cServiceOwner>; 2],
    receipts: [Option<I2cServiceCloseReceipt>; 2],
    uarts: Vec<SerialChainBackend>,
}
#[derive(Clone, Default)]
struct Stop {
    stopped: Arc<AtomicBool>,
    fences: Arc<Mutex<Vec<I2cServiceTerminalFence>>>,
}
impl Stop {
    fn stop(&self) {
        // Publish terminal state before waiting for the short fence registry
        // lock, so a just-returning open cannot miss cancellation publication.
        self.stopped.store(true, Ordering::SeqCst);
        for fence in self
            .fences
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .iter()
        {
            fence.latch_terminal_safe_off();
        }
    }
    fn attach(&self, fence: I2cServiceTerminalFence) {
        let mut fences = self
            .fences
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if self.stopped.load(Ordering::SeqCst) {
            fence.latch_terminal_safe_off();
        }
        fences.push(fence);
    }
    fn check(&self, deadline: Instant) -> Result<(), String> {
        if self.stopped.load(Ordering::SeqCst) || Instant::now() >= deadline {
            self.stop();
            Err("BB factory is terminal or past its original deadline".into())
        } else {
            Ok(())
        }
    }
}
struct Pending {
    stop: Stop,
    armed: bool,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if self.armed {
            self.stop.stop();
        }
    }
}

struct State {
    partial: Option<Partial>,
    open: BbFactoryOpenObservation,
    close: Option<BbFactoryCloseObservation>,
}
fn lock<'a>(state: &'a Mutex<State>, stop: &Stop) -> std::sync::MutexGuard<'a, State> {
    state.lock().unwrap_or_else(|poison| {
        stop.stop();
        poison.into_inner()
    })
}

/// The factory never exposes a partial owner. A successful one-shot handoff
/// transfers the original captured platform, both workers, and selected UARTs.
/// The caller must move these directly into its retained controller lifetime.
pub struct BbOpenedHardware {
    platform: BeagleBonePlatform,
    management: BbManagementRuntime,
    uarts: Vec<SerialChainBackend>,
    selected_eeproms: Vec<u8>,
}
impl BbOpenedHardware {
    pub fn into_parts(
        self,
    ) -> (
        BeagleBonePlatform,
        BbManagementRuntime,
        Vec<SerialChainBackend>,
        Vec<u8>,
    ) {
        (
            self.platform,
            self.management,
            self.uarts,
            self.selected_eeproms,
        )
    }
}

pub struct BbHardwareFactory {
    platform: Option<BeagleBonePlatform>,
    selected: Vec<u8>,
    uart_plan: Vec<(u8, String)>,
    deadline: Instant,
    stop: Stop,
    state: Arc<Mutex<State>>,
    open_caller: Option<JoinHandle<()>>,
    close_caller: Option<JoinHandle<()>>,
    transferred: bool,
}

/// Host-only opaque opener custody. The raw service owner remains private to
/// HAL; external fixtures cannot extract it or supply accepted observations.
#[cfg(feature = "sim-hal")]
pub struct BbSimFactoryServices {
    open: Box<dyn FnMut(u8) -> std::io::Result<I2cServiceOwner> + Send>,
}
#[cfg(feature = "sim-hal")]
impl BbSimFactoryServices {
    pub(crate) fn from_opener(
        open: impl FnMut(u8) -> std::io::Result<I2cServiceOwner> + Send + 'static,
    ) -> Self {
        Self {
            open: Box::new(open),
        }
    }
}
impl BbHardwareFactory {
    /// Pure capture/validation, no device access. Invalid selection or topology
    /// returns the same platform, preserving the daemon's original route object.
    pub fn new(
        platform: BeagleBonePlatform,
        selected: &[u8],
        deadline: Instant,
    ) -> Result<Self, (BeagleBonePlatform, String)> {
        let validation = (|| {
            let mut validation_target = platform.board_target().clone();
            // Existing BeagleBonePlatform::new permits the built-in topology
            // only after exact captured DT identity when TOML is absent. That
            // fallback has no TOML header. Normalize only this local validation
            // view from its already captured provenance, then validate every
            // actual GPIO/UART/I2c/cold field. Do not mutate/reread the platform.
            if validation_target.platform.is_none()
                && platform.identity_evidence() == Am3BbIdentityEvidence::ExactDeviceTree
            {
                validation_target.platform = Some(BoardTargetPlatformSection {
                    board_target: Some("am3-bb-s19jpro".into()),
                    soc: Some("am335x".into()),
                    cpu: Some("cortex-a8".into()),
                    io_board: Some("S19J_IO_BOARD_V2_0".into()),
                    voltage_controller: Some("dspic33ep-fw89".into()),
                });
            }
            validate_supported_board_target(platform.board_target_name(), &validation_target)
                .map_err(|error| error.to_string())?;
            if selected.is_empty()
                || selected.len() > 3
                || selected.iter().enumerate().any(|(i, address)| {
                    !(0x50..=0x52).contains(address) || selected[..i].contains(address)
                })
            {
                return Err(
                    "BB factory requires one to three unique selected EEPROMs 0x50..0x52".into(),
                );
            }
            if Instant::now() >= deadline {
                return Err("BB factory creation deadline expired".into());
            }
            Ok(())
        })();
        if let Err(error) = validation {
            return Err((platform, error));
        }
        let uart_plan = selected
            .iter()
            .map(|address| {
                let index = *address - 0x50;
                let uart = &platform.board_target().uart.chains[usize::from(index)];
                (uart.index, uart.device.clone())
            })
            .collect();
        Ok(Self {
            platform: Some(platform),
            selected: selected.to_vec(),
            uart_plan,
            deadline,
            stop: Stop::default(),
            open_caller: None,
            close_caller: None,
            transferred: false,
            state: Arc::new(Mutex::new(State {
                partial: Some(Partial::default()),
                open: BbFactoryOpenObservation {
                    deadline,
                    started_at: None,
                    services_spawned: Vec::new(),
                    uarts_opened: Vec::new(),
                    caller_returned_at: None,
                    caller_joined_at: None,
                    accepted_at: None,
                    transferred_at: None,
                    failure: None,
                },
                close: None,
            })),
        })
    }
    pub fn snapshot(&self) -> BbFactoryObservation {
        let state = lock(&self.state, &self.stop);
        BbFactoryObservation {
            stopped: self.stop.stopped.load(Ordering::SeqCst),
            open_caller_pending: self.open_caller.is_some(),
            close_caller_pending: self.close_caller.is_some(),
            open: state.open.clone(),
            close: state.close.clone(),
        }
    }
    pub fn cancel(&self) {
        if !self.transferred {
            self.stop.stop();
        }
    }

    /// Open on a retained blocking caller. The reserved I2c constructor has no
    /// direct-register recovery and protects EEPROM writes before requests.
    /// UART 115200 is the existing BB enumeration baud (am3_bb_mining enum_baud).
    pub async fn open_until(&mut self) -> Result<bool, String> {
        self.open_with(
            |bus| {
                spawn_owned_i2c_service_no_register_touch_with_denylist_and_reserved_preparation(
                    bus,
                    (0x50..=0x57).collect(),
                    || Ok(()),
                )
            },
            |index, path| SerialChainBackend::open_native_linux_only(index, path, 115_200),
            || {},
        )
        .await
    }
    // Private seams supply real simulated service owners and actual PTYs in
    // host tests. Production callers cannot supply a factory or hardware DTO.
    /// Host-only injection into the actual retained opening/join/transfer path.
    /// The returned owners and UARTs remain real services and descriptors. No
    /// readiness observation or accepted timestamp can be supplied by a fixture.
    #[cfg(feature = "sim-hal")]
    pub async fn open_simulated_until(
        &mut self,
        mut services: BbSimFactoryServices,
        open_uart: impl FnMut(u8, &str) -> crate::Result<SerialChainBackend> + Send + 'static,
    ) -> Result<bool, String> {
        self.open_with(move |bus| (services.open)(bus), open_uart, || {})
            .await
    }

    async fn open_with(
        &mut self,
        mut open_bus: impl FnMut(u8) -> std::io::Result<I2cServiceOwner> + Send + 'static,
        mut open_uart: impl FnMut(u8, &str) -> crate::Result<SerialChainBackend> + Send + 'static,
        after_record: impl FnOnce() + Send + 'static,
    ) -> Result<bool, String> {
        if self.transferred || self.close_caller.is_some() {
            return Err("BB factory transferred or closing".into());
        }
        self.stop.check(self.deadline)?;
        if self.open_caller.is_none() {
            let mut state = lock(&self.state, &self.stop);
            if state.open.started_at.is_some() {
                return Ok(state.open.accepted_at.is_some() && state.open.failure.is_none());
            }
            state.open.started_at = Some(Instant::now());
            let mut partial = state.partial.take().expect("initial empty partial owner");
            drop(state);
            let shared = self.state.clone();
            let stop = self.stop.clone();
            let deadline = self.deadline;
            let uarts = self.uart_plan.clone();
            self.open_caller = Some(tokio::task::spawn_blocking(move || {
                // Partial is outside the caught scope. Once an owner returns,
                // store it before any later opener/callback can fail or unwind.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || -> Result<(), String> {
                        for bus in [0u8, 1] {
                            stop.check(deadline)?;
                            let owner = open_bus(bus).map_err(|error| {
                                format!("BB bus{bus} service creation: {error}")
                            })?;
                            stop.attach(owner.terminal_fence());
                            partial.services[usize::from(bus)] = Some(owner);
                            lock(&shared, &stop)
                                .open
                                .services_spawned
                                .push((bus, Instant::now()));
                            stop.check(deadline)?;
                        }
                        for (index, path) in uarts {
                            stop.check(deadline)?;
                            let uart = open_uart(index, &path)
                                .map_err(|error| format!("BB chain{index} UART open: {error}"))?;
                            partial.uarts.push(uart);
                            lock(&shared, &stop)
                                .open
                                .uarts_opened
                                .push((index, Instant::now()));
                            stop.check(deadline)?;
                        }
                        Ok(())
                    },
                ))
                .unwrap_or_else(|_| Err("BB hardware factory opener unwound".into()));
                if result.is_err() {
                    stop.stop();
                }
                {
                    let mut state = lock(&shared, &stop);
                    state.partial = Some(partial);
                    state.open.caller_returned_at = Some(Instant::now());
                    state.open.failure = result.err();
                }
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(after_record)).is_err() {
                    stop.stop();
                    lock(&shared, &stop).open.failure =
                        Some("BB factory caller tail unwound".into());
                }
            }));
        }
        Ok(self.join_open_until(self.deadline, true).await)
    }
    async fn join_open_until(&mut self, deadline: Instant, promote: bool) -> bool {
        let Some(task) = self.open_caller.as_mut() else {
            return true;
        };
        if Instant::now() >= deadline {
            self.stop.stop();
            return false;
        }
        let mut pending = Pending {
            stop: self.stop.clone(),
            armed: true,
        };
        let joined = tokio::select! { result = task => Some(result), _ = tokio::time::sleep_until(deadline.into()) => None };
        let Some(joined) = joined else {
            return false;
        };
        self.open_caller = None;
        let now = Instant::now();
        let mut state = lock(&self.state, &self.stop);
        state.open.caller_joined_at = Some(now);
        if let Err(error) = joined {
            self.stop.stop();
            state.open.failure = Some(format!("BB factory open caller failed: {error}"));
        }
        if now >= self.deadline || now >= deadline {
            self.stop.stop();
            state
                .open
                .failure
                .get_or_insert_with(|| "BB factory open caller joined late".into());
        }
        if promote
            && !self.stop.stopped.load(Ordering::SeqCst)
            && state.open.failure.is_none()
            && state
                .open
                .caller_returned_at
                .is_some_and(|time| time < self.deadline)
            && state.partial.as_ref().is_some_and(|partial| {
                partial.services.iter().all(Option::is_some)
                    && partial.uarts.len() == self.uart_plan.len()
            })
        {
            state.open.accepted_at = Some(now);
        }
        pending.armed = false;
        if promote {
            state.open.accepted_at.is_some()
        } else {
            true
        }
    }
    pub fn take_ready(&mut self) -> Result<BbOpenedHardware, String> {
        // Ownership transfer does not refresh the original acquisition deadline
        // or establish sample/power readiness. Its accepted join is historical.
        if self.transferred || self.stop.stopped.load(Ordering::SeqCst) {
            return Err("BB factory already transferred or terminal".into());
        }
        let mut state = lock(&self.state, &self.stop);
        if self.transferred
            || self.open_caller.is_some()
            || self.close_caller.is_some()
            || state.close.is_some()
            || state.open.accepted_at.is_none()
            || state.open.failure.is_some()
            || !state.partial.as_ref().is_some_and(|partial| {
                partial.services.iter().all(Option::is_some)
                    && partial.uarts.len() == self.uart_plan.len()
            })
        {
            return Err("BB factory handoff requires its joined complete original owners".into());
        }
        let mut partial = state
            .partial
            .take()
            .expect("checked complete original partial owner");
        let bus0 = partial.services[0].take().expect("checked original bus0");
        let bus1 = partial.services[1].take().expect("checked original bus1");
        let hardware = BbOpenedHardware {
            platform: self.platform.take().expect("captured original platform"),
            management: BbManagementRuntime::new(bus0, bus1),
            uarts: partial.uarts,
            selected_eeproms: self.selected.clone(),
        };
        state.open.transferred_at = Some(Instant::now());
        self.transferred = true;
        self.stop
            .fences
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
        Ok(hardware)
    }

    /// Caller retains the factory outside cancellation until this joins its
    /// original opening and cleanup callers. Drop alone only fences services.
    pub async fn close_until(&mut self, deadline: Instant) -> bool {
        if self.transferred {
            return false;
        }
        self.cancel();
        let _pending = Pending {
            stop: self.stop.clone(),
            armed: true,
        };
        if !self.join_open_until(deadline, false).await {
            return false;
        }
        if self.close_caller.is_none() {
            let mut state = lock(&self.state, &self.stop);
            if state
                .close
                .as_ref()
                .is_some_and(|close| close.caller_joined_at.is_some() && close.failure.is_none())
                && state.partial.as_ref().is_some_and(|partial| {
                    partial.uarts.is_empty()
                        && partial
                            .services
                            .iter()
                            .enumerate()
                            .all(|(i, owner)| owner.is_none() || partial.receipts[i].is_some())
                })
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            let attempt = match state
                .close
                .as_ref()
                .map(|record| record.attempt)
                .unwrap_or(0)
                .checked_add(1)
            {
                Some(value) => value,
                None => return false,
            };
            let Some(mut partial) = state.partial.take() else {
                return false;
            };
            state.close = Some(BbFactoryCloseObservation {
                attempt,
                deadline,
                started_at: Instant::now(),
                uart_drop_returned_at: None,
                service_receipts: Vec::new(),
                caller_returned_at: None,
                caller_joined_at: None,
                failure: None,
            });
            drop(state);
            let shared = self.state.clone();
            let stop = self.stop.clone();
            self.close_caller = Some(tokio::task::spawn_blocking(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || -> Result<(), String> {
                        // UART ownership closes before waiting on either bus worker.
                        drop(std::mem::take(&mut partial.uarts));
                        lock(&shared, &stop)
                            .close
                            .as_mut()
                            .expect("reserved close")
                            .uart_drop_returned_at = Some(Instant::now());
                        let mut errors = Vec::new();
                        for index in 0..2 {
                            if partial.receipts[index].is_none() {
                                if let Some(owner) = partial.services[index].as_mut() {
                                    match owner.close_and_join_until(deadline) {
                                        Ok(receipt) => partial.receipts[index] = Some(receipt),
                                        Err(error) => errors.push(format!("bus{index}: {error}")),
                                    }
                                }
                            }
                        }
                        if errors.is_empty() {
                            Ok(())
                        } else {
                            Err(errors.join("; "))
                        }
                    },
                ))
                .unwrap_or_else(|_| Err("BB partial hardware close unwound".into()));
                let mut state = lock(&shared, &stop);
                let record = state.close.as_mut().expect("reserved partial close record");
                record.service_receipts = partial
                    .receipts
                    .iter()
                    .filter_map(|value| value.as_ref().map(|receipt| receipt.bus()))
                    .collect();
                record.caller_returned_at = Some(Instant::now());
                record.failure = outcome.err();
                state.partial = Some(partial);
            }));
        }
        if Instant::now() >= deadline {
            return false;
        }
        let joined = tokio::select! { result = self.close_caller.as_mut().expect("actual close caller") => Some(result), _ = tokio::time::sleep_until(deadline.into()) => None };
        let Some(joined) = joined else {
            return false;
        };
        self.close_caller = None;
        let now = Instant::now();
        let mut state = lock(&self.state, &self.stop);
        let record = state.close.as_mut().expect("actual partial close record");
        record.caller_joined_at = Some(now);
        if let Err(error) = joined {
            record.failure = Some(format!("BB partial close caller failed: {error}"));
        }
        record.failure.is_none()
            && record.caller_returned_at.is_some()
            && record.uart_drop_returned_at.is_some()
            && now < deadline
    }
}
impl Drop for BbHardwareFactory {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "beaglebone_owned_factory_tests.rs"]
mod tests;
