//! Public custody of the original factory result, with no replacement/open API.
//! The daemon retains its independent GPIO, watchdog and cooling owner. It must
//! fence and physically cut power before awaiting this controller's cleanup.
use super::*;
use dcentrald_hal::bb_management_runtime::{BbHeartbeatCutoff, BbHeartbeatSnapshot};
use dcentrald_hal::i2c::I2cServiceCloseReceipt;
use dcentrald_hal::platform::beaglebone::{BbOpenedHardware, BeagleBonePlatform};
use std::sync::Arc;

/// Terminal publication only. Cloning this fence cannot duplicate a resource.
#[derive(Clone)]
pub struct BbOwnedControllerStop(ControllerStop);
impl BbOwnedControllerStop {
    pub fn stop(&self) {
        self.0.stop();
    }
}

/// Data copied from the retained controller; never an admission or close token.
#[derive(Clone, Debug)]
pub struct BbControllerObservation {
    inner: ControllerSnapshot,
    heartbeat: Option<BbHeartbeatSnapshot>,
    selected_eeproms: Vec<u8>,
}
impl BbControllerObservation {
    pub fn management(&self) -> &BbManagementObservation {
        &self.inner.management
    }
    pub fn heartbeat(&self) -> Option<&BbHeartbeatSnapshot> {
        self.heartbeat.as_ref()
    }
    pub fn selected_eeproms(&self) -> &[u8] {
        &self.selected_eeproms
    }
    pub fn uart_terminal(&self) -> bool {
        self.inner.uart.dispatch.permanently_stopped
    }
    pub fn uart_call_pending(&self) -> bool {
        self.inner.uart.caller_pending || self.inner.uart.close_caller_pending
    }
    pub fn management_close(&self) -> Option<&BbManagementCloseObservation> {
        self.inner.management_close.as_ref()
    }
}

struct OriginalCutoff {
    stop: ControllerStop,
    gpio: Arc<dyn BbHeartbeatCutoff>,
}
impl BbHeartbeatCutoff for OriginalCutoff {
    fn cutoff(&self) -> Result<(), String> {
        // Publish the original UART and both original I2C terminal fences before
        // invoking the independent GPIO owner. Never wait for PIC I/O here.
        self.stop.stop();
        self.gpio.cutoff()
    }
}

/// A one-way factory-to-controller transfer. No raw service/UART constructor,
/// Clone, extraction, selected-roster replacement or public request DTO exists.
pub struct BbOwnedController {
    platform: BeagleBonePlatform,
    selected_eeproms: Vec<u8>,
    controller: BbController,
}
impl BbOwnedController {
    pub fn from_opened(opened: BbOpenedHardware, dispatch_interval_us: u64) -> Self {
        let (platform, management, uarts, selected_eeproms) = opened.into_parts();
        let serial = BbSerialDispatchOwner::new(uarts, dispatch_interval_us);
        Self {
            platform,
            selected_eeproms,
            controller: BbController::new(management, BbUartRuntime::new(serial)),
        }
    }
    pub async fn initial_disable_and_bridges_held_until(&mut self, deadline: Instant) -> Result<(), String> {
        self.controller.initial_disable_and_bridges_held_until(deadline).await.map(|_| ())
    }
    pub fn initial_bridge_observation(&self) -> Option<dcentrald_hal::bb_management_runtime::BbInitialBridgeObservation> {
        self.controller.management.initial_bridge_observation()
    }

    pub fn board_target_name(&self) -> &str {
        self.platform.board_target_name()
    }
    pub fn selected_eeproms(&self) -> &[u8] {
        &self.selected_eeproms
    }
    pub fn original_chain_ids(&self) -> &[u8] {
        self.controller.uart.source_chain_ids()
    }
    pub fn stop_handle(&self) -> BbOwnedControllerStop {
        BbOwnedControllerStop(self.controller.stop_handle())
    }
    pub fn cancel(&self) {
        self.controller.stop.stop();
    }
    pub fn snapshot(&self) -> BbControllerObservation {
        BbControllerObservation {
            inner: self.controller.snapshot(),
            heartbeat: self.controller.management.heartbeat_snapshot(),
            selected_eeproms: self.selected_eeproms.clone(),
        }
    }
    /// The roster comes exclusively from the consumed original factory.
    pub async fn diagnose_held_until(&mut self, deadline: Instant) -> Result<(), String> {
        self.controller
            .diagnose_held_until(&self.selected_eeproms, deadline)
            .await
            .map(|_| ())
    }
    /// The supplied callback must retain the daemon's original GPIO cutoff.
    /// The actor owns it through actual joins; callback success is not OFF proof.
    pub fn start_heartbeat(&mut self, gpio: Arc<dyn BbHeartbeatCutoff>) -> Result<(), String> {
        let uart = self.controller.uart.snapshot();
        if !uart.dispatch.held || uart.dispatch.permanently_stopped || uart.caller_pending {
            self.cancel();
            return Err("BB heartbeat requires its original joined UART hold".into());
        }
        let cutoff = Arc::new(OriginalCutoff {
            stop: self.controller.stop_handle(),
            gpio,
        });
        let result = self.controller.management.start_heartbeat(cutoff);
        if result.is_err() {
            self.cancel();
        }
        result
    }
    pub fn merge_requested_voltage(
        &mut self,
        target: Option<f64>,
        maximum_step: Option<f64>,
    ) -> Result<(), String> {
        self.controller
            .merge_requested_voltage(target, maximum_step)
    }
    /// Wait on this original actor's actual rounds; cancellation fences both
    /// original transports while all actor tasks remain with their HAL owner.
    pub async fn wait_stable_heartbeat_until(&mut self, deadline: Instant) -> Result<(), String> {
        let mut pending = Pending {
            stop: self.controller.stop_handle(),
            armed: true,
        };
        let result = self
            .controller
            .management
            .wait_stable_heartbeat_until(deadline)
            .await;
        if result.is_ok() {
            pending.armed = false;
        }
        result.map(|_| ())
    }
    pub async fn observe_held_until(&mut self, deadline: Instant) -> Result<(), String> {
        self.controller
            .observe_held_until(deadline)
            .await
            .map(|_| ())
    }
    /// The original HAL owner must also recheck its actor at actual APW entry.
    /// This facade check is only the earlier caller admission boundary.
    pub async fn voltage_held_until(&mut self, deadline: Instant) -> Result<(), String> {
        if let Err(error) = self.controller.management.require_stable_heartbeat() {
            self.cancel();
            return Err(error);
        }
        self.controller
            .voltage_held_until(deadline)
            .await
            .map(|_| ())
    }
    /// Retains the existing explicit experimental recipe. The daemon must
    /// establish its original reset, cooling and selected PIC/power ordering.
    pub async fn initialize_asics_held_until(&mut self, deadline: Instant) -> Result<(), String> {
        if let Err(error) = self.controller.management.require_stable_heartbeat() {
            self.cancel();
            return Err(error);
        }
        if self
            .controller
            .management
            .snapshot()
            .last_execution_sequence()
            .is_none()
        {
            self.cancel();
            return Err("BB ASIC startup lacks an original joined voltage execution".into());
        }
        self.controller
            .initialize_asics_held_until(StartupRecipe::Am2DerivedExperimental, deadline)
            .await
            .map(|_| ())
    }
    /// Invoke only after the independent immediate GPIO cutoff. A timeout or
    /// cancelled future keeps every original caller and resource in this value.
    pub async fn close_until(&mut self, deadline: Instant) -> bool {
        self.controller.close_until(deadline).await
    }
    /// Move the original closed owners, never assemble custody from a snapshot.
    /// Failure returns the same controller for explicit cleanup continuation.
    pub fn try_into_closed(self) -> Result<BbClosedController, Self> {
        let state = self.controller.snapshot();
        let receipts = self.controller.management.close_receipts();
        let complete = state.cleanup.as_ref().is_some_and(|record| {
            record.management_closed
                && record.uart_closed
                && record.returned_at.is_some_and(|at| at < record.deadline)
        }) && receipts.0.is_some()
            && receipts.1.is_some()
            && state.management.stopped()
            && state.uart.dispatch.permanently_stopped
            && !state.management_close_caller_pending
            && !state.uart.caller_pending
            && !state.uart.close_caller_pending
            && state.uart.close.as_ref().is_some_and(|record| {
                record.owner_drop_returned_at.is_some()
                    && record.caller_joined_at.is_some()
                    && record.failure.is_none()
            });
        if complete {
            Ok(BbClosedController { original: self })
        } else {
            Err(self)
        }
    }
}

/// Closed transport custody only. It proves neither physical power OFF nor
/// complete daemon teardown, and supplies no SafeOff/Mining/Disarm capability.
pub struct BbClosedController {
    original: BbOwnedController,
}
impl BbClosedController {
    pub fn snapshot(&self) -> BbControllerObservation {
        self.original.snapshot()
    }
    pub fn board_target_name(&self) -> &str {
        self.original.board_target_name()
    }
    pub fn management_receipts(&self) -> (&I2cServiceCloseReceipt, &I2cServiceCloseReceipt) {
        let (bus0, bus1) = self.original.controller.management.close_receipts();
        (
            bus0.expect("original bus0 receipt retained by closed controller"),
            bus1.expect("original bus1 receipt retained by closed controller"),
        )
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_owned_controller_tests.rs"]
mod tests;
