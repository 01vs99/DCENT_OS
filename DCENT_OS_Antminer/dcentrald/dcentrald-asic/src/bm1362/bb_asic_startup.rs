//! Ordered experimental ASIC operations through the original joined controller.
//! AM2 register defaults, BB host 3 Mbaud and BM1368-derived PLL dwell policy
//! remain distinct source scopes. This sequence does not qualify those values
//! for BB, service a physical PIC heartbeat, operate power/reset/cooling, or
//! establish response freshness, physical population, PLL lock or mining.
use super::*;
use crate::drivers::bm1362::{decode_pll_reg_to_freq, pll_ramp_sequence, BM1362_INIT_PLAN};
use dcentrald_api_types::bb_factory_profile::{BbFactoryCollection, BbFactoryPage};
use dcentrald_hal::serial_chain::NativeBbBaud;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartupRecipe {
    /// Existing selected-route software defaults; independent BB qualification
    /// and daemon GPIO/watchdog/management-timer composition remain required.
    Am2DerivedExperimental,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PllSetting {
    pub register: u32,
    pub table_mhz: u16,
    pub decoded_mhz: u16,
}
#[derive(Clone, Debug)]
pub(crate) struct ChainPlan {
    pub uart_index: usize,
    pub original_chain_id: u8,
    pub factory_page: BbFactoryPage,
    pub expected_addresses: Vec<u8>,
    pub pll_settings: Vec<PllSetting>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StartupStep {
    Control { chain: usize, control: ColdControl },
    Delay { milliseconds: u32 },
}
#[derive(Clone, Debug)]
pub(crate) struct StartupPlan {
    pub recipe: StartupRecipe,
    pub chains: Vec<ChainPlan>,
    pub steps: Vec<StartupStep>,
}
#[derive(Clone, Debug)]
pub(crate) struct StartupStepAttempt {
    pub index: usize,
    pub step: StartupStep,
    pub started_at: Instant,
    pub expected_uart_sequence: Option<u64>,
    pub uart: Option<UartCallRecord>,
    pub completed_at: Option<Instant>,
    pub failure: Option<String>,
}
#[derive(Clone, Debug)]
pub(crate) struct StartupAttempt {
    pub controller_sequence: u64,
    pub recipe: StartupRecipe,
    pub deadline: Instant,
    pub started_at: Instant,
    pub original_management: BbManagementObservation,
    pub original_chain_ids: Vec<u8>,
    pub plan: Option<StartupPlan>,
    pub steps: Vec<StartupStepAttempt>,
    /// Host operation completion only; supplies no physical startup capability.
    pub commands_completed_at: Option<Instant>,
    pub failure: Option<String>,
}

fn plan(
    recipe: StartupRecipe,
    factory: &BbFactoryCollection,
    chain_ids: &[u8],
) -> Result<StartupPlan, String> {
    let pages = factory.pages();
    if !(1..=3).contains(&pages.len()) || pages.len() != chain_ids.len() {
        return Err("BB startup requires every selected factory page and original UART".into());
    }
    let mut chains = Vec::with_capacity(pages.len());
    // Validate the entire selected set before constructing any wire operation.
    for (index, page) in pages.iter().enumerate() {
        if !(0x50..=0x52).contains(&page.address())
            || page.source_chain_index() != chain_ids[index]
            || chain_ids[..index].contains(&chain_ids[index])
            || page.sku().expected_chip_count() != 126
        {
            return Err(
                "BB startup factory order/count does not match the original UART set".into(),
            );
        }
        let frequency = page.factory_frequency_mhz();
        if !(400..=597).contains(&frequency) {
            return Err("BB startup factory frequency outside the retained PLL table".into());
        }
        let pll_settings = pll_ramp_sequence(400, frequency, 25)
            .into_iter()
            .map(|(register, table_mhz)| {
                let decoded_mhz = decode_pll_reg_to_freq(register).ok_or_else(|| {
                    "BB startup table register has no frequency decode".to_owned()
                })?;
                if decoded_mhz != table_mhz || register == 0x40a8_0265 {
                    return Err("BB startup PLL label and encoded divider disagree".into());
                }
                Ok(PllSetting {
                    register,
                    table_mhz,
                    decoded_mhz,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        if pll_settings.is_empty() {
            return Err("BB startup PLL plan is empty".into());
        }
        // Both exact held SKUs expect 126 addresses with interval two. This is
        // source-profile expectation, never a discovered number of ASICs.
        let interval = dcentrald_common::bm1397plus_addr_interval(126);
        let expected_addresses = (0..126u8).map(|chip| chip * interval).collect();
        chains.push(ChainPlan {
            uart_index: index,
            original_chain_id: chain_ids[index],
            factory_page: page.clone(),
            expected_addresses,
            pll_settings,
        });
    }
    let mut steps = Vec::new();
    for chain in &chains {
        append_chain(&mut steps, chain);
    }
    Ok(StartupPlan {
        recipe,
        chains,
        steps,
    })
}
fn delay(steps: &mut Vec<StartupStep>, milliseconds: u32) {
    steps.push(StartupStep::Delay { milliseconds });
}
fn control(steps: &mut Vec<StartupStep>, chain: usize, control: ColdControl, after_ms: u32) {
    steps.push(StartupStep::Control { chain, control });
    if after_ms != 0 {
        delay(steps, after_ms);
    }
}
fn broadcast(
    steps: &mut Vec<StartupStep>,
    chain: usize,
    register: ColdRegister,
    value: u32,
    after: u32,
) {
    control(
        steps,
        chain,
        ColdControl::Broadcast { register, value },
        after,
    );
}
fn append_chain(steps: &mut Vec<StartupStep>, chain: &ChainPlan) {
    let p = BM1362_INIT_PLAN;
    let id = chain.uart_index;
    // The v2 monotonic-history guard has already admitted this one-shot startup.
    // Observe the same original kernel tty immediately before the first query;
    // no setter/drain/flush is needed and no earlier cached open is proof.
    control(steps, id, ColdControl::ObserveEnumerationBaud, 0);
    control(steps, id, ColdControl::ResetBaseline, 0);
    for _ in 0..3 {
        broadcast(steps, id, ColdRegister::VersionMask, p.version_mask, 5);
    }
    broadcast(
        steps,
        id,
        ColdRegister::InitControl,
        p.init_control_broadcast,
        10,
    );
    control(
        steps,
        id,
        ColdControl::MiscBroadcast(p.misc_control_pre_baud),
        0,
    );
    for _ in 0..3 {
        control(steps, id, ColdControl::ChainInactive, 5);
    }
    for &address in &chain.expected_addresses {
        control(steps, id, ColdControl::SetChipAddress(address), 2);
    }
    for (index, &address) in chain.expected_addresses.iter().enumerate() {
        control(
            steps,
            id,
            ColdControl::Chip {
                address,
                register: ColdRegister::InitControl,
                value: p.init_control_per_chip,
            },
            0,
        );
        control(
            steps,
            id,
            ColdControl::MiscChip {
                address,
                value: p.misc_control_pre_baud,
            },
            0,
        );
        for value in [p.core_reg_hash_clk, p.core_reg_clk_delay, p.core_reg_family] {
            control(
                steps,
                id,
                ColdControl::Chip {
                    address,
                    register: ColdRegister::CoreControl,
                    value,
                },
                0,
            );
        }
        if (index + 1) % 16 == 0 {
            delay(steps, 20);
        }
    }
    delay(steps, 100);
    broadcast(steps, id, ColdRegister::TicketMask, 0xff, 10);
    broadcast(steps, id, ColdRegister::IoDriver, p.io_driver_normal, 10);
    broadcast(steps, id, ColdRegister::AnalogMux, p.analog_mux_value, 10);
    // No 0x2c/0x34 relay, 0x70 lab divider, PLL1 or BM1370-tail writes.
    broadcast(steps, id, ColdRegister::FastUart, p.fast_uart_value, 10);
    control(
        steps,
        id,
        ColdControl::MiscBroadcast(p.misc_control_post_fast_baud),
        0,
    );
    control(steps, id, ColdControl::HostBaud(NativeBbBaud::Mining), 500);
    control(
        steps,
        id,
        ColdControl::AssignedScan {
            expected_addresses: chain.expected_addresses.clone(),
        },
        0,
    );
    broadcast(steps, id, ColdRegister::NonceRange, 0x1381, 10);
    for pll in &chain.pll_settings {
        broadcast(steps, id, ColdRegister::Pll0, pll.register, 10);
        delay(steps, 100);
    }
    broadcast(steps, id, ColdRegister::VersionMask, p.version_mask, 10);
}

impl BbController {
    pub(super) fn startup_observation(&self, uart: &UartRuntimeSnapshot) -> Option<StartupAttempt> {
        let mut result = self.startup.clone()?;
        // A cancelled future may not copy its actual caller's returned report.
        // The retained UART still owns it. Join by exact sequence AND request,
        // retaining late/unpromoted data without manufacturing step completion.
        if let Some(step) = result.steps.last_mut() {
            if let Some(record) = uart.latest.as_ref().filter(|record| {
                step.expected_uart_sequence == Some(record.sequence)
                    && record.deadline == result.deadline
                    && request_matches(&step.step, &record.request)
            }) {
                step.uart = Some(record.clone());
            }
        }
        Some(result)
    }
    /// One-shot experimental command execution. The plan comes only from this
    /// owner's actual joined management snapshot and consumed original UARTs.
    /// Does not resume work dispatch or accept a cloned plan as admission.
    pub(crate) async fn initialize_asics_held_until(
        &mut self,
        recipe: StartupRecipe,
        deadline: Instant,
    ) -> Result<ControllerSnapshot, String> {
        let pending = self.begin(ControllerOperation::InitializeAsicsHeld, deadline)?;
        if self.startup.is_some() {
            return self.finish(pending, Err("BB startup has already been attempted".into()));
        }
        self.startup = Some(StartupAttempt {
            controller_sequence: self.sequence,
            recipe,
            deadline,
            started_at: Instant::now(),
            original_management: self.management.snapshot(),
            original_chain_ids: self.uart.source_chain_ids().to_vec(),
            plan: None,
            steps: Vec::new(),
            commands_completed_at: None,
            failure: None,
        });
        let result = self.run_startup(recipe, deadline).await;
        if let Err(error) = &result {
            self.startup.as_mut().expect("retained startup").failure = Some(error.clone());
        }
        self.finish(pending, result)
    }
    async fn run_startup(
        &mut self,
        recipe: StartupRecipe,
        deadline: Instant,
    ) -> Result<(), String> {
        let management = self.management.snapshot();
        if !management.diagnostic_complete() || management.stopped() {
            return Err("BB startup lacks original joined management inventory".into());
        }
        let factory = management
            .factory()
            .ok_or("BB startup lacks original factory pages")?;
        let plan = plan(recipe, factory, self.uart.source_chain_ids())?;
        self.startup.as_mut().expect("retained startup").plan = Some(plan.clone());
        self.ensure_held(deadline).await?;
        let uart = self.uart.snapshot();
        // Voltage drain and paired receive observations legitimately advance
        // the original caller history before ASIC initialization. A monotonic
        // reservation bit prevents a later observation/hold from concealing
        // any earlier cold command. The cold owner separately refuses prior
        // mining dispatch or unresolved mining-parser bytes before each write.
        if uart.cold_control_started
            || !uart.latest.as_ref().is_some_and(|record| {
                record.joined_at.is_some()
                    && record.promoted_at.is_some()
                    && record.failure.is_none()
            })
        {
            return Err(
                "BB startup requires joined held custody without prior cold control".into(),
            );
        }
        for (index, step) in plan.steps.into_iter().enumerate() {
            self.startup_active(deadline)?;
            let expected_uart_sequence = if matches!(step, StartupStep::Control { .. }) {
                Some(
                    self.uart
                        .snapshot()
                        .latest
                        .as_ref()
                        .map_or(0, |r| r.sequence)
                        .checked_add(1)
                        .ok_or("BB startup UART sequence exhausted")?,
                )
            } else {
                None
            };
            self.startup
                .as_mut()
                .expect("retained startup")
                .steps
                .push(StartupStepAttempt {
                    index,
                    step: step.clone(),
                    started_at: Instant::now(),
                    expected_uart_sequence,
                    uart: None,
                    completed_at: None,
                    failure: None,
                });
            let result = match step {
                StartupStep::Control { chain, control } => {
                    self.startup_control(chain, control, deadline).await
                }
                StartupStep::Delay { milliseconds } => {
                    self.startup_delay(milliseconds, deadline).await
                }
            };
            let active = result.and_then(|()| self.startup_active(deadline));
            let last = self
                .startup
                .as_mut()
                .expect("retained startup")
                .steps
                .last_mut()
                .expect("retained step");
            match active {
                Ok(()) => last.completed_at = Some(Instant::now()),
                Err(error) => {
                    last.failure = Some(error.clone());
                    return Err(error);
                }
            }
        }
        self.startup_active(deadline)?;
        self.startup
            .as_mut()
            .expect("retained startup")
            .commands_completed_at = Some(Instant::now());
        Ok(())
    }
    fn startup_active(&self, deadline: Instant) -> Result<(), String> {
        if Instant::now() >= deadline
            || self.management.snapshot().stopped()
            || self.uart.snapshot().dispatch.permanently_stopped
        {
            Err("BB startup stopped or its original deadline expired".into())
        } else {
            Ok(())
        }
    }
    async fn startup_control(
        &mut self,
        chain: usize,
        control: ColdControl,
        deadline: Instant,
    ) -> Result<(), String> {
        let result = self
            .uart
            .execute(UartRequest::ColdControl { chain, control }, deadline)
            .await;
        let state = self.uart.snapshot();
        let step = self
            .startup
            .as_mut()
            .expect("retained startup")
            .steps
            .last_mut()
            .expect("retained step");
        if let Some(record) = state.latest.as_ref().filter(|record| {
            Some(record.sequence) == step.expected_uart_sequence
                && record.deadline == deadline
                && request_matches(&step.step, &record.request)
        }) {
            step.uart = Some(record.clone());
        }
        result?;
        if state.caller_pending
            || !state.dispatch.held
            || state.dispatch.permanently_stopped
            || !step.uart.as_ref().is_some_and(|record| {
                record.joined_at.is_some()
                    && record.promoted_at.is_some()
                    && record.failure.is_none()
                    && matches!(&record.output, Some(UartOutput::Controlled(attempt))
                        if attempt.caller_completed_at.is_some() && attempt.failure.is_none())
            })
        {
            return Err("BB startup cold operation did not actually complete and join".into());
        }
        Ok(())
    }
    async fn startup_delay(&self, milliseconds: u32, deadline: Instant) -> Result<(), String> {
        let end = Instant::now() + Duration::from_millis(u64::from(milliseconds));
        loop {
            self.startup_active(deadline)?;
            let now = Instant::now();
            if now >= end {
                return Ok(());
            }
            tokio::time::sleep_until(
                (now + Duration::from_millis(1))
                    .min(end)
                    .min(deadline)
                    .into(),
            )
            .await;
        }
    }
}
fn request_matches(step: &StartupStep, request: &UartRequest) -> bool {
    matches!((step, request),
        (StartupStep::Control { chain, control }, UartRequest::ColdControl { chain: actual_chain, control: actual_control })
        if chain == actual_chain && control == actual_control)
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bb_asic_startup_tests.rs"]
mod tests;
