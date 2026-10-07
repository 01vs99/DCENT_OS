//! Combined original management/UART custody, before cold-boot admission.
//! Does not open GPIO, buses or UARTs, or establish ASIC/electrical quiescence.
//! The daemon must retain this owner through explicit cleanup and supply its
//! independent power cutoff. Dropping an operation future permanently fences
//! both subsystems while their actual task handles remain in this controller.
use super::*;
use dcentrald_hal::bb_management_runtime::{
    BbManagementCloseObservation, BbManagementObservation, BbManagementRuntime, BbManagementStop,
};

#[derive(Clone)]
pub(crate) struct ControllerStop {
    management: BbManagementStop,
    uart: DispatchStop,
}
impl ControllerStop {
    pub(crate) fn stop(&self) {
        self.uart.stop();
        self.management.stop();
    }
}
struct Pending {
    stop: ControllerStop,
    armed: bool,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if self.armed {
            self.stop.stop();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControllerOperation {
    DiagnoseHeld,
    InitialDisableBridgeHeld,
    ObserveHeld,
    VoltageHeld,
    ColdControl,
    InitializeAsicsHeld,
}
#[derive(Clone, Debug)]
pub(crate) struct ControllerAttempt {
    pub sequence: u64,
    pub operation: ControllerOperation,
    pub deadline: Instant,
    pub started_at: Instant,
    pub accepted_at: Option<Instant>,
    pub failure: Option<String>,
}
#[derive(Clone, Debug)]
pub(crate) struct ControllerCleanup {
    pub deadline: Instant,
    pub started_at: Instant,
    pub returned_at: Option<Instant>,
    pub management_closed: bool,
    pub uart_closed: bool,
}
#[derive(Clone, Debug)]
pub(crate) struct ControllerSnapshot {
    pub management: BbManagementObservation,
    pub management_close: Option<BbManagementCloseObservation>,
    pub management_close_caller_pending: bool,
    pub uart: UartRuntimeSnapshot,
    pub latest: Option<ControllerAttempt>,
    pub last_complete: Option<ControllerAttempt>,
    pub cleanup: Option<ControllerCleanup>,
    pub startup: Option<startup::StartupAttempt>,
}

pub(crate) struct BbController {
    management: BbManagementRuntime,
    uart: BbUartRuntime,
    stop: ControllerStop,
    sequence: u64,
    latest: Option<ControllerAttempt>,
    last_complete: Option<ControllerAttempt>,
    cleanup: Option<ControllerCleanup>,
    startup: Option<startup::StartupAttempt>,
}
impl BbController {
    pub(crate) fn new(management: BbManagementRuntime, uart: BbUartRuntime) -> Self {
        let stop = ControllerStop {
            management: management.stop_handle(),
            uart: uart.stop_handle(),
        };
        Self {
            management,
            uart,
            stop,
            sequence: 0,
            latest: None,
            last_complete: None,
            cleanup: None,
            startup: None,
        }
    }
    pub(crate) fn stop_handle(&self) -> ControllerStop {
        self.stop.clone()
    }
    pub(crate) fn snapshot(&self) -> ControllerSnapshot {
        let uart = self.uart.snapshot();
        let startup = self.startup_observation(&uart);
        ControllerSnapshot {
            management: self.management.snapshot(),
            management_close: self.management.close_observation(),
            management_close_caller_pending: self.management.close_caller_pending(),
            uart,
            startup,
            latest: self.latest.clone(),
            last_complete: self.last_complete.clone(),
            cleanup: self.cleanup.clone(),
        }
    }
    pub(crate) fn merge_requested_voltage(
        &mut self,
        target: Option<f64>,
        maximum_step: Option<f64>,
    ) -> Result<(), String> {
        if self.uart.snapshot().dispatch.permanently_stopped {
            return Err("BB controller UART terminal".into());
        }
        self.management
            .merge_requested_voltage(target, maximum_step)
    }
    fn begin(
        &mut self,
        operation: ControllerOperation,
        deadline: Instant,
    ) -> Result<Pending, String> {
        let uart = self.uart.snapshot();
        if self.management.snapshot().stopped()
            || uart.dispatch.permanently_stopped
            || self.cleanup.is_some()
            || uart.caller_pending
            || uart.close_caller_pending
            || self.management.close_caller_pending()
            || Instant::now() >= deadline
        {
            self.stop.stop();
            return Err("BB controller is terminal, pending, closing or past its deadline".into());
        }
        let sequence = self.sequence.checked_add(1).ok_or_else(|| {
            self.stop.stop();
            "BB controller sequence exhausted".to_owned()
        })?;
        self.sequence = sequence;
        self.latest = Some(ControllerAttempt {
            sequence,
            operation,
            deadline,
            started_at: Instant::now(),
            accepted_at: None,
            failure: None,
        });
        Ok(Pending {
            stop: self.stop.clone(),
            armed: true,
        })
    }
    fn finish(
        &mut self,
        mut pending: Pending,
        result: Result<(), String>,
    ) -> Result<ControllerSnapshot, String> {
        let now = Instant::now();
        let latest = self.latest.as_mut().expect("reserved controller operation");
        let result = result.and_then(|()| {
            if now >= latest.deadline
                || self.management.snapshot().stopped()
                || self.uart.snapshot().dispatch.permanently_stopped
            {
                Err("BB controller completion was late or terminal".into())
            } else {
                Ok(())
            }
        });
        match result {
            Ok(()) => {
                latest.accepted_at = Some(now);
                self.last_complete = Some(latest.clone());
                pending.armed = false;
                Ok(self.snapshot())
            }
            Err(error) => {
                latest.failure = Some(error.clone());
                self.stop.stop();
                Err(error)
            }
        }
    }
    async fn ensure_held(&mut self, deadline: Instant) -> Result<(), String> {
        if !self.uart.snapshot().dispatch.held {
            self.uart.execute(UartRequest::Hold, deadline).await?;
        }
        let state = self.uart.snapshot();
        if !state.dispatch.held || state.dispatch.permanently_stopped || state.caller_pending {
            return Err("BB controller did not join its original UART hold".into());
        }
        Ok(())
    }
    /// Software inventory only: caller must resolve actual auxiliary-power and
    /// reset/cooling ordering before using this in a physical cold-start route.
    pub(crate) async fn diagnose_held_until(
        &mut self,
        selected: &[u8],
        deadline: Instant,
    ) -> Result<ControllerSnapshot, String> {
        let pending = self.begin(ControllerOperation::DiagnoseHeld, deadline)?;
        let result = async {
            self.ensure_held(deadline).await?;
            let value = self
                .management
                .observe_initial_until(selected, deadline)
                .await?;
            if !value.diagnostic_complete() || value.factory().is_none() || value.stopped() {
                return Err(
                    "BB management inventory did not complete under its original deadline".into(),
                );
            }
            Ok(())
        }
        .await;
        self.finish(pending, result)
    }
    pub(crate) async fn initial_disable_and_bridges_held_until(
        &mut self, deadline: Instant,
    ) -> Result<ControllerSnapshot, String> {
        let pending = self.begin(ControllerOperation::InitialDisableBridgeHeld, deadline)?;
        let result = async {
            self.ensure_held(deadline).await?;
            self.management.initial_disable_and_bridges_until(deadline).await
        }.await;
        self.finish(pending, result)
    }

    pub(crate) async fn observe_held_until(
        &mut self,
        deadline: Instant,
    ) -> Result<ControllerSnapshot, String> {
        let pending = self.begin(ControllerOperation::ObserveHeld, deadline)?;
        let result = async {
            self.ensure_held(deadline).await?;
            let prior = self.management.snapshot().last_pair_sequence();
            let (management, uart) = tokio::join!(
                self.management.observe_runtime_until(deadline),
                self.uart.execute(UartRequest::Receive, deadline)
            );
            let management = management?;
            let uart = uart?;
            if management.stopped()
                || management.last_pair_sequence().is_none()
                || management.last_pair_sequence() == prior
                || uart.caller_pending
                || uart.dispatch.permanently_stopped
                || !uart.latest.as_ref().is_some_and(|record| {
                    record.promoted_at.is_some()
                        && matches!(record.output, Some(UartOutput::Received(_)))
                })
            {
                return Err("BB paired management/RX callers did not both complete".into());
            }
            Ok(())
        }
        .await;
        self.finish(pending, result)
    }
    /// Every attempt observes the held physical driver again. Queue-empty alone
    /// cannot authorize this call; unsupported line status refuses before APW
    /// execution. Successful transport drain is still not ASIC idle/rail proof.
    pub(crate) async fn voltage_held_until(
        &mut self,
        deadline: Instant,
    ) -> Result<ControllerSnapshot, String> {
        let pending = self.begin(ControllerOperation::VoltageHeld, deadline)?;
        let result = async {
            self.ensure_held(deadline).await?;
            if !self.management.snapshot().diagnostic_complete() {
                return Err("BB voltage operation lacks joined original inventory".into());
            }
            let uart = self
                .uart
                .execute(UartRequest::ObserveHeld, deadline)
                .await?;
            if uart.caller_pending
                || uart.dispatch.permanently_stopped
                || !uart.dispatch.held
                || !uart.latest.as_ref().is_some_and(|record| {
                    record.promoted_at.is_some()
                        && record.deadline == deadline
                        && matches!(record.output, Some(UartOutput::Observed(_)))
                })
            {
                return Err("BB held transmitter observation did not actually complete".into());
            }
            let prior = self.management.snapshot().last_execution_sequence();
            let value = self.management.execute_voltage_until(deadline).await?;
            if value.stopped()
                || value.last_execution_sequence().is_none()
                || value.last_execution_sequence() == prior
            {
                return Err("BB original voltage caller did not join and commit".into());
            }
            Ok(())
        }
        .await;
        self.finish(pending, result)
    }
    pub(crate) async fn cold_control_until(
        &mut self,
        chain: usize,
        control: ColdControl,
        deadline: Instant,
    ) -> Result<ControllerSnapshot, String> {
        let pending = self.begin(ControllerOperation::ColdControl, deadline)?;
        let result = async {
            self.ensure_held(deadline).await?;
            if !self.management.snapshot().diagnostic_complete() {
                return Err("BB cold control requires joined original management inventory".into());
            }
            let state = self
                .uart
                .execute(UartRequest::ColdControl { chain, control }, deadline)
                .await?;
            if state.caller_pending
                || state.dispatch.permanently_stopped
                || !state.latest.as_ref().is_some_and(|record| {
                    record.promoted_at.is_some()
                        && matches!(record.output, Some(UartOutput::Controlled(_)))
                })
            {
                return Err("BB cold control did not actually complete and join".into());
            }
            Ok(())
        }
        .await;
        self.finish(pending, result)
    }
    pub(crate) async fn close_until(&mut self, deadline: Instant) -> bool {
        self.stop.stop();
        let _pending = Pending {
            stop: self.stop.clone(),
            armed: true,
        };
        self.cleanup = Some(ControllerCleanup {
            deadline,
            started_at: Instant::now(),
            returned_at: None,
            management_closed: false,
            uart_closed: false,
        });
        // Both retained subsystems receive the same original cleanup deadline.
        // A blocked bus must not prevent starting UART cleanup (or vice versa).
        let (management, uart) = tokio::join!(
            self.management.close_until(deadline),
            self.uart.close_until(deadline)
        );
        let now = Instant::now();
        let record = self.cleanup.as_mut().expect("reserved combined cleanup");
        record.returned_at = Some(now);
        record.management_closed = management;
        record.uart_closed = uart;
        management && uart && now < deadline
    }
}
impl Drop for BbController {
    fn drop(&mut self) {
        self.stop.stop();
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_controller_tests.rs"]
mod tests;

#[path = "bb_asic_startup.rs"]
mod startup;
pub(crate) use startup::StartupRecipe;

#[path = "bb_owned_controller.rs"]
mod daemon;
pub use daemon::{
    BbClosedController, BbControllerObservation, BbOwnedController, BbOwnedControllerStop,
};
