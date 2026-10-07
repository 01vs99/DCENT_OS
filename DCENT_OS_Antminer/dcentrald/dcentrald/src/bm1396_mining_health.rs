//! Detached fixed-roster health actors; not registered or compiled.
use super::startup::{Phase, PhaseDeadline};
use crate::runtime::safety_watchdog::{Bm1396ActorSlot, Bm1396Actors, SafetyLiveness};
use crate::runtime::watchdog_feed_gate::WatchdogFeedStopSignal;
use anyhow::{anyhow, ensure, Context, Result};
use dcentrald_hal::platform::stock_bm1396::{
    AdaptedStartupStage, FixedWorkHealth, Hardware, PicApplication, PowerLine, ThermalSnapshot,
    Transport,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

type Owner<H> = Arc<Transport<H>>;
type Pic<H> = Arc<PicApplication<H>>;
pub(super) type CurrentThermal = Arc<Mutex<Option<ThermalSnapshot>>>;
pub(super) type CurrentWorkHealth = Arc<Mutex<Option<FixedWorkHealth>>>;
// Three chains require 3*(500+500+10) ms before any I/O or scheduling cost.
// This native caller limit preserves every original HAL wait; it is not a
// promise that an arbitrarily contended management operation must complete.
pub(super) const HEARTBEAT_ROUND_BUDGET: Duration = Duration::from_secs(6);

fn current_snapshot(
    current: &CurrentThermal,
    work: &CurrentWorkHealth,
) -> Result<Option<ThermalSnapshot>> {
    let work = work
        .lock()
        .map_err(|_| anyhow!("BM1396 current work health custody poisoned"))?
        .clone();
    if let Some(work) = work {
        if let Some(actual) = work.latest_thermal().map_err(anyhow::Error::msg)? {
            return Ok(Some(actual));
        }
    }
    Ok(current
        .lock()
        .map_err(|_| anyhow!("BM1396 current thermal custody poisoned"))?
        .clone())
}

pub(super) struct FaultSignal<H: Hardware> {
    pub(super) owner: Owner<H>,
    pub(super) line: Arc<PowerLine<H>>,
    pub(super) feed: WatchdogFeedStopSignal,
    pub(super) faults: watch::Sender<Option<String>>,
}
impl<H: Hardware> Clone for FaultSignal<H> {
    fn clone(&self) -> Self {
        Self {
            owner: self.owner.clone(),
            line: self.line.clone(),
            feed: self.feed.clone(),
            faults: self.faults.clone(),
        }
    }
}
impl<H: Hardware> FaultSignal<H> {
    pub(super) fn trip(&self, error: String) {
        self.owner.begin_terminal();
        self.feed.close_terminal_lock_free();
        self.faults.send_if_modified(|first| {
            if first.is_none() {
                *first = Some(error);
                true
            } else {
                false
            }
        });
        // Independent emergency cut even if the main runtime is delayed. This
        // best-effort attempt creates no successful terminal/disarm receipt.
        let _ = self
            .line
            .emergency_high(Instant::now() + Duration::from_millis(100));
    }
}

pub(super) fn spawn_heartbeats<H: Hardware>(
    actors: &mut Bm1396Actors,
    owner: Owner<H>,
    pic: Pic<H>,
    mut enabled: watch::Receiver<bool>,
    stop: CancellationToken,
    faults: FaultSignal<H>,
) -> Result<()> {
    actors.spawn(Bm1396ActorSlot::Heartbeats, async move {
        loop {
            if *enabled.borrow() {
                break;
            }
            tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                changed = enabled.changed() => if changed.is_err() {
                    faults.trip("BM1396 heartbeat admission channel closed".into()); return;
                }
            }
        }
        loop {
            tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(1)) => (),
            }
            if let Err(error) = pic
                .heartbeat_round(Instant::now() + HEARTBEAT_ROUND_BUDGET)
                .await
            {
                faults.trip(error);
                return;
            }
        }
    })
}

fn temperature(snapshot: &ThermalSnapshot, epoch: u64, cutoff: i16, chains: &[u8]) -> Result<()> {
    ensure!(
        snapshot.epoch() == epoch && snapshot.is_fresh_at(Instant::now()),
        "BM1396 current thermal epoch is absent or stale"
    );
    ensure!(
        snapshot.samples().len() == chains.len() * 4,
        "BM1396 current thermal population is incomplete"
    );
    // The sealed HAL producer checks exact chain/address positions and epoch.
    // Keep independent cutoff checks against all actual nonzero channels.
    for sample in snapshot.samples() {
        ensure!(
            sample.epoch() == epoch && !sample.is_historical(),
            "BM1396 historical temperature cannot admit current health"
        );
        for (raw, value) in sample
            .raw_channels()
            .into_iter()
            .zip(sample.temperatures_c(snapshot.sampling_mode()))
        {
            ensure!(
                raw == 0 || value < cutoff,
                "BM1396 configured thermal cutoff reached"
            );
        }
    }
    Ok(())
}

fn phase_thermal<H: Hardware>(
    pic: &Pic<H>,
    current: &CurrentThermal,
    work: &CurrentWorkHealth,
    phase: PhaseDeadline,
    cutoff: i16,
    chains: &[u8],
    work_epoch: u64,
) -> Result<()> {
    ensure!(
        matches!(phase.phase, Phase::Mining) || Instant::now() < phase.until,
        "BM1396 native phase deadline expired"
    );
    let (snapshot, epoch, required) = match phase.phase {
        Phase::Observing | Phase::SourceHigh | Phase::SourceSettling | Phase::ConditioningReset => {
            (None, 0, false)
        }
        Phase::Conditioning => (
            pic.conditioning_preparation_latest_thermal()
                .map_err(anyhow::Error::msg)?,
            0,
            false,
        ),
        Phase::ConditioningPll => (
            pic.cold_pll_latest_thermal()
                .map_err(anyhow::Error::msg)?
                .or(pic
                    .conditioning_preparation_latest_thermal()
                    .map_err(anyhow::Error::msg)?),
            0,
            true,
        ),
        Phase::Adapted => {
            // The read-only getter copies only current fields/latest actual
            // population. The original full custody stays in its HAL owner.
            match pic.adapted_startup_health().map_err(anyhow::Error::msg)? {
                None => (
                    pic.cold_pll_latest_thermal().map_err(anyhow::Error::msg)?,
                    0,
                    true,
                ),
                Some(row) if row.stage() == AdaptedStartupStage::Admitted => (
                    pic.cold_pll_latest_thermal().map_err(anyhow::Error::msg)?,
                    0,
                    true,
                ),
                Some(row) => {
                    ensure!(
                        row.phase_deadline() == phase.until && row.epoch() == 1 && !row.failed(),
                        "BM1396 actual adapted phase binding changed"
                    );
                    let latest = row.latest_thermal().cloned();
                    // Exact ongoing requalification remains bounded by its real
                    // caller deadline. Historical samples are never relabeled.
                    (latest, 1, row.completed_at().is_some())
                }
            }
        }
        Phase::FinalPll => (
            pic.final_pll_latest_thermal()
                .map_err(anyhow::Error::msg)?
                .or(pic
                    .adapted_startup_health()
                    .map_err(anyhow::Error::msg)?
                    .and_then(|row| row.latest_thermal().cloned())),
            1,
            true,
        ),
        Phase::Probing | Phase::Mining => (current_snapshot(current, work)?, work_epoch, true),
        Phase::Terminal => return Err(anyhow!("BM1396 terminal health phase")),
    };
    if let Some(snapshot) = snapshot {
        temperature(&snapshot, epoch, cutoff, chains)?;
    } else {
        ensure!(
            !required,
            "BM1396 required current thermal population missing"
        );
    }
    Ok(())
}

pub(super) fn spawn_health<H: Hardware>(
    actors: &mut Bm1396Actors,
    owner: Owner<H>,
    pic: Pic<H>,
    phase: watch::Receiver<PhaseDeadline>,
    heartbeat_enabled: watch::Receiver<bool>,
    current: CurrentThermal,
    work: CurrentWorkHealth,
    state: watch::Sender<dcentrald_api::MinerState>,
    started: Instant,
    cutoff: i16,
    liveness: SafetyLiveness,
    stop: CancellationToken,
    faults: FaultSignal<H>,
) -> Result<()> {
    actors.spawn(Bm1396ActorSlot::Health, async move {
        loop {
            tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_millis(250)) => (),
            }
            let result: Result<()> = async {
                ensure!(!owner.is_terminal(), "BM1396 transport became terminal");
                if *heartbeat_enabled.borrow() {
                    pic.check_health(Instant::now() + Duration::from_secs(1))
                        .map_err(anyhow::Error::msg)?;
                }
                let until = Instant::now() + Duration::from_secs(1);
                let quiet = owner.quiet_fans(until).await.map_err(anyhow::Error::msg)?;
                let fans = owner
                    .sample_fan_tach(until)
                    .await
                    .map_err(anyhow::Error::msg)?;
                ensure!(
                    fans.raw_version() == owner.observed_version() && fans.samples().len() == 8,
                    "BM1396 fan source population or version changed"
                );
                let active = *phase.borrow();
                // Admission and every powered phase use the same fresh PWM30
                // population rule; stock full-PWM startup is a separate policy.
                if !matches!(active.phase, Phase::Observing | Phase::SourceHigh) {
                    fans.require_quiet_population(&quiet)
                        .map_err(anyhow::Error::msg)?;
                }
                phase_thermal(
                    &pic,
                    &current,
                    &work,
                    active,
                    cutoff,
                    owner.chains(),
                    match owner.model() {
                        dcentrald_hal::platform::stock_bm1396::Model::S17e => 0,
                        dcentrald_hal::platform::stock_bm1396::Model::T17e => 1,
                    },
                )?;
                super::telemetry::fans(&state, &quiet, &fans, started);
                if matches!(active.phase, Phase::Probing | Phase::Mining) {
                    let observed = current_snapshot(&current, &work)?;
                    if let Some(observed) = observed {
                        super::telemetry::temperatures(
                            &state,
                            &observed,
                            match owner.model() {
                                dcentrald_hal::platform::stock_bm1396::Model::S17e => 0,
                                dcentrald_hal::platform::stock_bm1396::Model::T17e => 1,
                            },
                        )?;
                    }
                }
                Ok(())
            }
            .await;
            match result {
                Ok(()) => liveness.mark_progress(),
                Err(error) => {
                    faults.trip(format!("{error:#}"));
                    return;
                }
            }
        }
    })
}

#[cfg(test)]
#[path = "bm1396_mining_health_tests.rs"]
mod tests;
