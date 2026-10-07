//! Actual model-specific startup coordinator under independent safety actors.
//! This returns the HAL's actual final observation, never a readiness boolean.
use crate::bm1396_admission::Bm1396DispatchAdmission;
use crate::runtime::safety_watchdog::Bm1396Actors;
use anyhow::{ensure, Context, Result};
use dcentrald_hal::platform::stock_bm1396::{
    Hardware, Model, NativePllObservation, PicApplication, PowerLine, Transport,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Private scheduling state for the independent health actor, not work
/// authority. The actor still reads actual HAL observations and owner health.
#[derive(Clone, Copy, Debug)]
pub(super) enum Phase {
    Observing,
    SourceHigh,
    SourceSettling,
    ConditioningReset,
    Conditioning,
    ConditioningPll,
    Adapted,
    FinalPll,
    Probing,
    Mining,
    Terminal,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PhaseDeadline {
    pub(super) phase: Phase,
    pub(super) until: Instant,
}

fn enter(
    phase: &watch::Sender<PhaseDeadline>,
    selected: Phase,
    until: Instant,
    actors: &Bm1396Actors,
) -> Result<()> {
    actors.require_running()?;
    ensure!(
        Instant::now() < until,
        "BM1396 startup phase deadline already expired"
    );
    phase.send_replace(PhaseDeadline {
        phase: selected,
        until,
    });
    Ok(())
}

/// Native execution budgets are policy limits, not claims about a physically
/// safe thermal-suspension duration. HAL exact source waits remain mandatory.
pub(super) async fn startup<H: Hardware>(
    owner: &Arc<Transport<H>>,
    line: &Arc<PowerLine<H>>,
    pic: &Arc<PicApplication<H>>,
    admission: &Bm1396DispatchAdmission,
    actors: &Bm1396Actors,
    phase: &watch::Sender<PhaseDeadline>,
    heartbeat_enabled: &watch::Sender<bool>,
    startup_deadline: Instant,
) -> Result<NativePllObservation> {
    ensure!(
        owner.model() == admission.model(),
        "BM1396 startup model changed"
    );
    let bounded =
        |seconds: u64| (Instant::now() + Duration::from_secs(seconds)).min(startup_deadline);
    enter(phase, Phase::Observing, bounded(100), actors)?;
    // Source high was already observed by the native opener. These are actual
    // retained read-only observations, with no recovery/jump or speculative retry.
    owner
        .acquire_factory_calibration(bounded(45))
        .await
        .map_err(anyhow::Error::msg)?;
    if owner.model() == Model::S17e {
        let records = owner.s17e_factory_records().map_err(anyhow::Error::msg)?;
        ensure!(
            records
                .iter()
                .all(|(_, record)| record.maximum_mhz() <= admission.frequency_limit_mhz()),
            "S17e actual factory frequency exceeds the configured ceiling"
        );
    }
    pic.observe_supply_type(bounded(10))
        .await
        .map_err(anyhow::Error::msg)?;
    pic.observe_versions(bounded(10))
        .await
        .map_err(anyhow::Error::msg)?;
    for _ in 0..5 {
        pic.heartbeat_round(bounded(super::health::HEARTBEAT_ROUND_BUDGET.as_secs()))
            .await
            .map_err(anyhow::Error::msg)?;
    }
    pic.check_health(bounded(1)).map_err(anyhow::Error::msg)?;
    heartbeat_enabled.send_replace(true);

    let not_before = line
        .source_enable_not_before()
        .map_err(anyhow::Error::msg)?;
    ensure!(
        not_before < startup_deadline,
        "BM1396 startup cannot contain required source-high interval"
    );
    enter(phase, Phase::SourceHigh, startup_deadline, actors)?;
    tokio::time::sleep_until(tokio::time::Instant::from_std(not_before)).await;
    actors.require_running()?;
    // New observations after the actual 61 s source-high interval; an earlier
    // tach snapshot cannot be relabeled fresh to satisfy the source-low guard.
    let quiet = owner
        .quiet_fans(bounded(2))
        .await
        .map_err(anyhow::Error::msg)?;
    let fans = owner
        .sample_fan_tach(bounded(2))
        .await
        .map_err(anyhow::Error::msg)?;
    enter(phase, Phase::SourceSettling, bounded(5), actors)?;
    line.enable_source_after_observations(pic.clone(), quiet, fans, bounded(5))
        .await
        .map_err(anyhow::Error::msg)?;

    let until = bounded(90);
    enter(phase, Phase::ConditioningReset, until, actors)?;
    pic.initialize_conditioning_reset(line.clone(), until)
        .await
        .map_err(anyhow::Error::msg)?;
    let until = bounded(150);
    enter(phase, Phase::Conditioning, until, actors)?;
    pic.initialize_conditioning_preparation(line.clone(), admission.cutoff_c(), until)
        .await
        .map_err(anyhow::Error::msg)?;
    let until = bounded(180);
    enter(phase, Phase::ConditioningPll, until, actors)?;
    pic.initialize_conditioning_pll(line.clone(), until)
        .await
        .map_err(anyhow::Error::msg)?;
    if owner.model() == Model::T17e {
        let until = bounded(150);
        enter(phase, Phase::Adapted, until, actors)?;
        pic.initialize_adapted_startup(line.clone(), until)
            .await
            .map_err(anyhow::Error::msg)?;
        let until = bounded(180);
        enter(phase, Phase::FinalPll, until, actors)?;
        pic.initialize_final_pll(line.clone(), until)
            .await
            .map_err(anyhow::Error::msg)?;
    }
    let final_observation = pic
        .native_pll_observation()
        .map_err(anyhow::Error::msg)?
        .context("BM1396 actual native PLL observation absent")?;
    ensure!(
        final_observation.same_owner(owner),
        "BM1396 final observation changed owner"
    );
    final_observation
        .completed_at()
        .context("BM1396 final PLL did not complete")?;
    ensure!(
        final_observation.failure().is_none()
            && final_observation.completed_frequency_mhz().is_some()
            && final_observation.timeout_base().is_some(),
        "BM1396 final source profile incomplete"
    );
    actors.require_running()?;
    Ok(final_observation)
}
