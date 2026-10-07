//! Original platform, selected GPIOs and transport acquisition for one BB run.
//! This first state has no ON, heartbeat-start, voltage or mining entry point.
//! Its closed value retains resource custody; watchdog closeout stays separate.
use super::retained_gpio::{FinalizedGpioOwner, GpioHistory, GpioPhase, RetainedGpioLifecycle};
use super::*;
use dcentrald_asic::bm1362::uart_transport::{
    BbClosedController, BbControllerObservation, BbOwnedController, BbOwnedControllerStop,
};
use dcentrald_hal::platform::beaglebone::{BbFactoryObservation, BbHardwareFactory};

pub(super) enum CaptureCustody {
    Original {
        platform: BeagleBonePlatform,
        guard: Am3BbRunSafetyGuard,
        never: Am3BbNeverEnergized,
    },
    Adopted {
        platform: BeagleBonePlatform,
        gpio: RetainedGpioLifecycle,
    },
}
pub(super) struct CaptureRefusal {
    pub error: String,
    pub custody: CaptureCustody,
}

#[derive(Clone, Debug)]
pub(super) struct PrePowerCloseCall {
    pub caller_deadline: Instant,
    pub started_at: Instant,
    pub returned_at: Option<Instant>,
    pub failure: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct PrePowerObservation {
    pub selected_eeproms: Vec<u8>,
    pub selected_ids: Vec<u8>,
    pub factory: BbFactoryObservation,
    pub controller: Option<BbControllerObservation>,
    pub gpio: GpioHistory,
    pub original_close_deadline: Option<Instant>,
    pub close_returned_at: Option<Instant>,
    pub close_failure: Option<String>,
    pub close_calls: Vec<PrePowerCloseCall>,
}

struct PendingInitialPrefix<'a> {
    stopped: &'a mut bool,
    stop: BbOwnedControllerStop,
    armed: bool,
}
impl Drop for PendingInitialPrefix<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.stop.stop();
            *self.stopped = true;
        }
    }
}

/// Private construction joins the same captured platform and roster before
/// moving the platform once into its factory. No constructor accepts opened
/// transports, copied readiness observations or independently closed tokens.
pub(super) struct PrePowerRun {
    selected_eeproms: Vec<u8>,
    selected_ids: Vec<u8>,
    factory: BbHardwareFactory,
    controller: Option<BbOwnedController>,
    gpio: Option<RetainedGpioLifecycle>,
    never: Option<Am3BbNeverEnergized>,
    closed_controller: Option<BbClosedController>,
    finalized_gpio: Option<FinalizedGpioOwner>,
    original_close_deadline: Option<Instant>,
    close_returned_at: Option<Instant>,
    close_failure: Option<String>,
    close_calls: Vec<PrePowerCloseCall>,
    stopped: bool,
}

impl PrePowerRun {
    pub(super) fn capture(
        platform: BeagleBonePlatform,
        selected: &[u8],
        guard: Am3BbRunSafetyGuard,
        never: Am3BbNeverEnergized,
        open_deadline: Instant,
    ) -> std::result::Result<Self, CaptureRefusal> {
        // Native BB uses original physical slots 0..2 (EEPROM 0x50..0x52).
        // Selection order is kept even for a sparse roster such as [2,0].
        if selected.is_empty()
            || selected.len() > 3
            || selected.iter().enumerate().any(|(i, address)| {
                !(0x50..=0x52).contains(address) || selected[..i].contains(address)
            })
        {
            return Err(CaptureRefusal {
                error: "BB run requires one to three distinct physical EEPROMs 0x50..0x52".into(),
                custody: CaptureCustody::Original {
                    platform,
                    guard,
                    never,
                },
            });
        }
        let selected_ids: Vec<_> = selected.iter().map(|address| address - 0x50).collect();
        let gpio = match RetainedGpioLifecycle::adopt(&platform, &selected_ids, guard, never) {
            Ok(gpio) => gpio,
            Err(refusal) => {
                return Err(CaptureRefusal {
                    error: refusal.error,
                    custody: CaptureCustody::Original {
                        platform,
                        guard: refusal.guard,
                        never: refusal.never_energized,
                    },
                });
            }
        };
        let factory = match BbHardwareFactory::new(platform, selected, open_deadline) {
            Ok(factory) => factory,
            Err((platform, error)) => {
                return Err(CaptureRefusal {
                    error,
                    custody: CaptureCustody::Adopted { platform, gpio },
                });
            }
        };
        Ok(Self {
            selected_eeproms: selected.to_vec(),
            selected_ids,
            factory,
            controller: None,
            gpio: Some(gpio),
            never: None,
            closed_controller: None,
            finalized_gpio: None,
            original_close_deadline: None,
            close_returned_at: None,
            close_failure: None,
            close_calls: Vec::new(),
            stopped: false,
        })
    }

    pub(super) fn snapshot(&self) -> PrePowerObservation {
        PrePowerObservation {
            selected_eeproms: self.selected_eeproms.clone(),
            selected_ids: self.selected_ids.clone(),
            factory: self.factory.snapshot(),
            controller: self
                .controller
                .as_ref()
                .map(BbOwnedController::snapshot)
                .or_else(|| {
                    self.closed_controller
                        .as_ref()
                        .map(BbClosedController::snapshot)
                }),
            gpio: self
                .gpio
                .as_ref()
                .map(RetainedGpioLifecycle::snapshot)
                .unwrap_or_else(|| {
                    self.finalized_gpio
                        .as_ref()
                        .expect("original GPIO custody retained")
                        .history()
                        .clone()
                }),
            original_close_deadline: self.original_close_deadline,
            close_returned_at: self.close_returned_at,
            close_failure: self.close_failure.clone(),
            close_calls: self.close_calls.clone(),
        }
    }

    fn require_open_state(&self) -> Result<()> {
        anyhow::ensure!(
            !self.stopped && self.original_close_deadline.is_none(),
            "original BB run is terminal"
        );
        anyhow::ensure!(
            self.controller.is_none(),
            "original BB factory already transferred"
        );
        Ok(())
    }

    pub(super) async fn prepare_and_open_until(
        &mut self,
        gpio_deadline: Instant,
        dispatch_interval_us: u64,
    ) -> Result<()> {
        self.require_open_state()?;
        self.gpio
            .as_mut()
            .context("original GPIO owner absent")?
            .run_until(GpioPhase::Prepare, gpio_deadline)
            .await?;
        self.factory
            .open_until()
            .await
            .map_err(anyhow::Error::msg)?;
        self.transfer_joined_factory(dispatch_interval_us)
    }

    fn transfer_joined_factory(&mut self, dispatch_interval_us: u64) -> Result<()> {
        self.require_open_state()?;
        let opened = self.factory.take_ready().map_err(anyhow::Error::msg)?;
        // Store actual ownership before inspecting it. A failed check retains
        // the same original transports for explicit cleanup.
        self.controller = Some(BbOwnedController::from_opened(opened, dispatch_interval_us));
        let controller = self
            .controller
            .as_ref()
            .expect("stored original controller");
        if controller.selected_eeproms() != self.selected_eeproms
            || controller.original_chain_ids() != self.selected_ids
        {
            self.stopped = true;
            controller.cancel();
            anyhow::bail!("original BB acquisition changed its selected physical roster");
        }
        Ok(())
    }

    #[cfg(all(test, feature = "sim-hal"))]
    async fn prepare_and_open_simulated_until(
        &mut self,
        gpio_deadline: Instant,
        services: dcentrald_hal::platform::beaglebone::BbSimFactoryServices,
        uarts: impl FnMut(
                u8,
                &str,
            )
                -> dcentrald_hal::Result<dcentrald_hal::serial_chain::SerialChainBackend>
            + Send
            + 'static,
    ) -> Result<()> {
        self.require_open_state()?;
        self.gpio
            .as_mut()
            .context("original GPIO owner absent")?
            .run_until(GpioPhase::Prepare, gpio_deadline)
            .await?;
        self.factory
            .open_simulated_until(services, uarts)
            .await
            .map_err(anyhow::Error::msg)?;
        self.transfer_joined_factory(1)
    }

    pub(super) async fn diagnose_until(&mut self, deadline: Instant) -> Result<()> {
        anyhow::ensure!(!self.stopped, "original BB run is terminal");
        self.controller
            .as_mut()
            .context("original BB factory has not transferred")?
            .diagnose_held_until(deadline)
            .await
            .map_err(anyhow::Error::msg)
    }

    /// Prepared-off original GPIO state is retained throughout this prefix.
    /// No auxiliary ON, reset pulse, heartbeat, voltage or ASIC work is added.
    pub(super) async fn initial_disable_and_bridges_until(&mut self, deadline: Instant) -> Result<()> {
        anyhow::ensure!(!self.stopped && self.original_close_deadline.is_none(), "original BB run is terminal");
        anyhow::ensure!(self.gpio.is_some(), "original prepared GPIO custody absent");
        let controller = self.controller.as_mut().context("original BB factory has not transferred")?;
        let mut pending = PendingInitialPrefix { stopped: &mut self.stopped, stop: controller.stop_handle(), armed: true };
        let result = controller.initial_disable_and_bridges_held_until(deadline).await;
        if result.is_ok() { pending.armed = false; }
        drop(pending);
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                // Execute the original GPIO cutoff before transport cleanup.
                // Even an expired prefix deadline cannot skip that first cut;
                // incomplete joins stay retained for explicit cleanup retry.
                let _ = self.close_until(deadline).await;
                Err(anyhow::Error::msg(error))
            }
        }
    }

    /// Cleanup retries retain the first deadline for the acceptance verdict.
    /// A later caller deadline permits resource recovery, never renewed proof.
    pub(super) async fn close_until(&mut self, caller_deadline: Instant) -> Result<()> {
        self.stopped = true;
        let original = *self.original_close_deadline.get_or_insert(caller_deadline);
        // Clear latest completion before this actual call can suspend. A
        // cancelled retry cannot borrow the completion of its predecessor.
        self.close_returned_at = None;
        self.close_failure = None;
        let index = self.close_calls.len();
        self.close_calls.push(PrePowerCloseCall {
            caller_deadline,
            started_at: Instant::now(),
            returned_at: None,
            failure: None,
        });
        self.factory.cancel();
        if let Some(controller) = &self.controller {
            controller.cancel();
        }
        let mut result = self.close_originals_until(caller_deadline, original).await;
        let returned = Instant::now();
        self.close_returned_at = Some(returned);
        if result.is_ok() && (returned >= caller_deadline || returned >= original) {
            result = Err(anyhow::anyhow!(
                "BB close returned after its caller or original deadline"
            ));
        }
        if let Err(error) = &result {
            self.close_failure = Some(format!("{error:#}"));
        }
        self.close_calls[index].returned_at = self.close_returned_at;
        self.close_calls[index].failure = self.close_failure.clone();
        result
    }

    async fn close_originals_until(
        &mut self,
        caller_deadline: Instant,
        original: Instant,
    ) -> Result<()> {
        // This state exposes no ON boundary. Still execute the independent
        // original cutoff before awaiting any transport close. If preparation
        // was cancelled, its actual GPIO caller remains retained through join.
        let gpio_result = match self.gpio.as_mut() {
            Some(gpio) => gpio.stop_and_join_until(caller_deadline).await.map(|_| ()),
            None => Ok(()),
        };
        let transports_closed = if let Some(controller) = self.controller.as_mut() {
            controller.close_until(caller_deadline).await
        } else if self.closed_controller.is_some() {
            true
        } else {
            self.factory.close_until(caller_deadline).await
        };
        // A GPIO failure does not skip the transport cleanup attempt above.
        gpio_result?;
        if let Some(gpio) = self.gpio.as_mut() {
            if self.never.is_none() {
                self.never = Some(gpio.take_never_energized_after_join()?);
            }
            gpio.close_until(caller_deadline).await?;
        }
        anyhow::ensure!(
            transports_closed,
            "original BB transport callers have not closed"
        );
        let completed = Instant::now();
        anyhow::ensure!(
            completed < caller_deadline,
            "current BB close caller deadline expired"
        );
        anyhow::ensure!(
            completed < original,
            "original BB close deadline expired; resources may have recovered late"
        );
        Ok(())
    }

    /// Consume this same aggregate only after actual original joins. The
    /// retained never-energized token is inaccessible until this transition.
    pub(super) fn try_into_closed(mut self) -> std::result::Result<ClosedPrePowerRun, Self> {
        let timely = self.original_close_deadline.is_some_and(|deadline| {
            self.close_returned_at.is_some_and(|at| {
                at < deadline
                    && self
                        .close_calls
                        .last()
                        .is_some_and(|call| at < call.caller_deadline)
            })
        });
        if !self.stopped || !timely || self.never.is_none() || self.close_failure.is_some() {
            return Err(self);
        }
        if let Some(controller) = self.controller.take() {
            match controller.try_into_closed() {
                Ok(closed) => self.closed_controller = Some(closed),
                Err(original) => {
                    self.controller = Some(original);
                    return Err(self);
                }
            }
        }
        if let Some(gpio) = self.gpio.take() {
            match gpio.into_finalized_owner() {
                Ok(closed) => self.finalized_gpio = Some(closed),
                Err(refusal) => {
                    self.gpio = Some(refusal.owner);
                    return Err(self);
                }
            }
        }
        Ok(ClosedPrePowerRun { original: self })
    }
}

impl Drop for PrePowerRun {
    fn drop(&mut self) {
        self.factory.cancel();
        if let Some(controller) = &self.controller {
            controller.cancel();
        }
        // Retained GPIO Drop follows with the original cutoff. No detached
        // task is replaced and no Drop path manufactures joined closeout.
    }
}

pub(super) struct ClosedPrePowerRun {
    original: PrePowerRun,
}
impl ClosedPrePowerRun {
    pub(super) fn snapshot(&self) -> PrePowerObservation {
        self.original.snapshot()
    }
    pub(super) fn take_never_energized(&mut self) -> Result<Am3BbNeverEnergized> {
        self.original
            .never
            .take()
            .context("original never-energized token already transferred")
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "am3_bb_pre_power_run_tests.rs"]
mod tests;
