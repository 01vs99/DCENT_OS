// SPDX-License-Identifier: GPL-3.0-or-later
//! Native C43 S9SE/S9k: retained flat MMIO, framed PIC, ASIC commands,
//! independent cooling custody, pinned work codec, Stratum and checked cut.

use anyhow::{anyhow, bail, ensure, Context, Result};
use dcentrald_common::bm1393_native::{Bm1393PicCommand, Bm1393Runtime};
use dcentrald_common::s9se_nonce::S9SeFifoRecord;
use dcentrald_hal::platform::c43_bm1393::{
    transport::{C43NativeMmio, C43Registers, C43TemperatureSnapshot, C43Transport},
    C43Bm1393Adapter, C43Custody, C43PowerOffReceipt, C43TerminalBarrierReceipt,
};
use dcentrald_hal::platform::HardwareMutationGateOwner;
use dcentrald_stratum::types::{JobTemplate, StratumStatus, ValidShare};
use dcentrald_stratum::work::WorkBuilder;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::config::DcentraldConfig;
use crate::runtime::safety_watchdog::{
    C43WatchdogShutdownManifest, SafetyLiveness, SafetyWatchdogOwner, WatchdogDisarmPermit,
};
use crate::runtime::teardown_budget::{TeardownBudgetView, TeardownDisarmAuthority, TeardownStage};
#[path = "c43_bm1393_work.rs"]
mod work;
use work::Feeder;

#[derive(Debug)]
struct TerminalSafeOffError {
    source: anyhow::Error,
    _receipt: crate::runtime::safety_watchdog::WatchdogCloseoutReceipt,
}
impl std::fmt::Display for TerminalSafeOffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.source)
    }
}
impl std::error::Error for TerminalSafeOffError {}
pub(crate) fn is_terminal_safe_off(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<TerminalSafeOffError>().is_some())
}

pub(crate) struct C43SafeOffEvidence {
    budget: TeardownBudgetView,
    power: C43PowerOffReceipt,
    actors_joined: bool,
}
impl C43SafeOffEvidence {
    pub(crate) fn completed(&self) -> bool {
        self.power.completed() && self.actors_joined
    }
    pub(crate) fn same_teardown_budget(&self, authority: &TeardownDisarmAuthority) -> bool {
        self.budget.same_budget(authority)
    }
    pub(crate) fn same_owner(&self, barrier: &C43TerminalBarrierReceipt) -> bool {
        self.power.same_owner(barrier)
    }
}

struct OwnedActors {
    cancellation: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl OwnedActors {
    async fn stop(&mut self) -> bool {
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
        let mut joined = true;
        for task in &mut self.tasks {
            joined &= tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .is_ok();
        }
        joined
    }
}
impl Drop for OwnedActors {
    fn drop(&mut self) {
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[derive(Clone, Debug, Default)]
struct HealthSnapshot {
    at: Option<Instant>,
    fans: Vec<(u8, u32)>,
    temperatures: Vec<C43TemperatureSnapshot>,
    error: Option<String>,
}

struct Custody {
    transport: Arc<C43Transport<C43NativeMmio>>,
    snapshot: Arc<Mutex<HealthSnapshot>>,
    require_all_sensors: Arc<AtomicBool>,
    cancellation: CancellationToken,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    liveness: SafetyLiveness,
    pwm: u8,
    cutoff: f32,
}

fn validate_health(
    fans: &[(u8, u32)],
    temperatures: &[C43TemperatureSnapshot],
    chains: &[u8],
    require_all: bool,
    cutoff: f32,
    xadc: dcentrald_hal::xadc::XadcReadings,
) -> Result<(), String> {
    if ![0, 1]
        .iter()
        .all(|required| fans.iter().any(|(id, rpm)| id == required && *rpm > 0))
    {
        return Err("C43 both physical fan0/fan1 tach readings are required".into());
    }
    if !xadc.die_temp_c.is_finite()
        || !(0.0..85.0).contains(&xadc.die_temp_c)
        || !(0.9..=1.1).contains(&xadc.vccint_v)
        || !(1.65..=1.95).contains(&xadc.vccaux_v)
    {
        return Err("C43 fresh XADC temperature/rail limits exceeded".into());
    }
    if require_all
        && !chains.iter().all(|c| {
            temperatures
                .iter()
                .any(|t| t.chain == *c && !t.readings.is_empty())
        })
    {
        return Err("C43 not every selected board has fresh chip temperature".into());
    }
    for board in temperatures {
        if board.sampled.elapsed() > Duration::from_secs(5)
            || board.readings.is_empty()
            || board.readings.iter().any(|(_, local, remote)| {
                !local.is_finite()
                    || !remote.is_finite()
                    || *local < -20.0
                    || *remote < -20.0
                    || *local >= cutoff
                    || *remote >= cutoff
            })
        {
            return Err(format!(
                "C43 chain{} stale/invalid/over-limit temperature",
                board.chain
            ));
        }
    }
    Ok(())
}

async fn sample(
    transport: &Arc<C43Transport<C43NativeMmio>>,
    pwm: u8,
    require_all: bool,
    cutoff: f32,
) -> Result<HealthSnapshot, String> {
    let fans = transport.fan(pwm).await?;
    let xadc = tokio::task::spawn_blocking(dcentrald_hal::xadc::Xadc::read_all)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    // Cooling and SoC rails are shared faults. Check them before attempting
    // board-local retirement, so fan failure cannot be masked by exclusions.
    validate_health(&fans, &[], &[], false, cutoff, xadc)?;
    let mut temperatures = transport.temperatures().await?;
    for board in &temperatures {
        if validate_health(
            &fans,
            std::slice::from_ref(board),
            &[board.chain],
            true,
            cutoff,
            xadc,
        )
        .is_err()
        {
            let proof = transport.isolate_chain(board.chain).await?;
            if !transport.accepts_isolation(&proof) {
                return Err("C43 temperature isolation receipt does not match owner".into());
            }
        }
    }
    let active = transport.active_chains();
    if active.is_empty() {
        return Err("C43 no healthy boards remain".into());
    }
    temperatures.retain(|board| active.contains(&board.chain));
    validate_health(&fans, &temperatures, &active, require_all, cutoff, xadc)?;
    Ok(HealthSnapshot {
        at: Some(Instant::now()),
        fans,
        temperatures,
        error: None,
    })
}

impl C43Custody<C43NativeMmio> for Custody {
    async fn start(&self, transport: Arc<C43Transport<C43NativeMmio>>) -> Result<(), String> {
        if !Arc::ptr_eq(&transport, &self.transport) {
            return Err("C43 custody owner mismatch".into());
        }
        if self
            .task
            .lock()
            .map_err(|_| "C43 watcher poisoned")?
            .is_some()
        {
            return Err("C43 custody already started".into());
        }
        for &chain in transport.chains() {
            transport.reset(chain, true).await?;
            transport
                .pic(chain, Bm1393PicCommand::Enable(false))
                .await?;
        }
        // Spin the source-defined two fan channels while chips remain reset/off.
        transport.fan(self.pwm).await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let first_sample = sample(&transport, self.pwm, false, self.cutoff).await?;
        *self.snapshot.lock().map_err(|_| "C43 health poisoned")? = first_sample;
        self.liveness.mark_progress();
        let snapshot = self.snapshot.clone();
        let cancellation = self.cancellation.clone();
        let required = self.require_all_sensors.clone();
        let liveness = self.liveness.clone();
        let pwm = self.pwm;
        let cutoff = self.cutoff;
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(2));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! { _ = cancellation.cancelled() => break, _ = ticker.tick() => {} }
                let result = tokio::time::timeout(
                    Duration::from_secs(6),
                    sample(&transport, pwm, required.load(Ordering::SeqCst), cutoff),
                )
                .await;
                match result {
                    Ok(Ok(value)) => {
                        if let Ok(mut target) = snapshot.lock() {
                            *target = value;
                        } else {
                            break;
                        }
                        // Only a completed physical safety iteration feeds the
                        // independent watchdog's progress clock.
                        liveness.mark_progress();
                    }
                    failure => {
                        if let Ok(mut target) = snapshot.lock() {
                            target.error = Some(format!("C43 cooling watcher: {failure:?}"));
                        }
                        break;
                    }
                }
            }
            let cut = transport.terminal_cut().await;
            if !cut.completed() {
                tracing::error!(errors=?cut.errors(), "C43 independent watcher cutoff unproven");
            }
        });
        *self.task.lock().map_err(|_| "C43 watcher poisoned")? = Some(task);
        Ok(())
    }
    async fn check_health(&self) -> Result<(), String> {
        let snapshot = self.snapshot.lock().map_err(|_| "C43 health poisoned")?;
        if let Some(error) = &snapshot.error {
            return Err(error.clone());
        }
        if snapshot
            .at
            .is_none_or(|at| at.elapsed() > Duration::from_secs(8))
        {
            return Err("C43 independent safety sample is stale".into());
        }
        if self
            .task
            .lock()
            .map_err(|_| "C43 watcher poisoned")?
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            return Err("C43 safety watcher is absent or exited".into());
        }
        Ok(())
    }
    async fn stop(&self) -> Result<(), String> {
        if !self.transport.terminal() {
            return Err("C43 custody stop requires terminal transport".into());
        }
        self.cancellation.cancel();
        let task = self.task.lock().map_err(|_| "C43 watcher poisoned")?.take();
        if let Some(task) = task {
            task.await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
impl Drop for Custody {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
type NativeRuntime = Bm1393Runtime<C43Bm1393Adapter<C43NativeMmio, Custody>>;

pub(crate) async fn run(
    config: DcentraldConfig,
    shutdown: CancellationToken,
    state_tx: Option<watch::Sender<dcentrald_api::MinerState>>,
    admission: crate::C43RuntimeDispatchAdmission,
) -> Result<()> {
    ensure!(
        matches!(admission.board_target(), "am1-s9se" | "am1-s9k")
            && admission.identity() == dcentrald_common::AsicProtocolIdentity::Bm1393,
        "C43 exact native admission mismatch"
    );
    let software_closeout_run =
        dcentrald_common::mutation_disposition::capture_software_closeout_run(
            admission.board_target(),
        );
    ensure!(
        std::fs::read_to_string("/etc/dcentos/board_target")?.trim() == admission.board_target(),
        "C43 image identity changed"
    );
    let frequency: u16 = config
        .mining
        .frequency_mhz
        .try_into()
        .context("C43 frequency overflow")?;
    let voltage: u16 = config
        .mining
        .voltage_mv
        .try_into()
        .context("C43 voltage overflow")?;
    let pwm = config.thermal.fan_max_pwm.min(30);
    ensure!((5..=30).contains(&pwm), "C43 cooling duty invalid");
    let registers = C43NativeMmio::open().await.map_err(anyhow::Error::msg)?;
    let plug = registers
        .read(dcentrald_common::s9se_fpga::HASH_ON_PLUG.byte_offset)
        .map_err(anyhow::Error::msg)?;
    let chains: Vec<u8> = (0..16)
        .filter(|chain| dcentrald_common::s9se_fpga::hash_on_plug_populated(plug, *chain))
        .collect();
    let transport = C43Transport::new(registers, chains.clone()).map_err(anyhow::Error::msg)?;
    let liveness = SafetyLiveness::default();
    let custody = Arc::new(Custody {
        transport: transport.clone(),
        snapshot: Arc::new(Mutex::new(HealthSnapshot::default())),
        require_all_sensors: Arc::new(AtomicBool::new(false)),
        cancellation: CancellationToken::new(),
        task: Mutex::new(None),
        liveness: liveness.clone(),
        pwm,
        cutoff: f32::from(config.thermal.dangerous_temp_c.min(80)),
    });
    let adapter = C43Bm1393Adapter::new(transport.clone(), custody.clone());
    let mut runtime =
        Bm1393Runtime::new(adapter, chains, frequency, voltage).map_err(anyhow::Error::msg)?;
    let mutation_owner = HardwareMutationGateOwner::new_pending();
    let state_tx = state_tx.unwrap_or_else(|| {
        watch::channel(dcentrald_api::MinerState::empty(
            dcentrald_api::OperatingMode::Standard,
        ))
        .0
    });
    let api_shutdown = shutdown.child_token();
    let api = crate::runtime::api::spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
        config.clone(),
        dcentrald_api::RuntimeHealthMode::Native,
        None,
        Some(state_tx.subscribe()),
        mutation_owner.gate(),
        api_shutdown.clone(),
    )
    .await?;
    let mut actors = OwnedActors {
        cancellation: api_shutdown,
        tasks: vec![api.0, api.1],
    };
    let (mut watchdog, armed) = SafetyWatchdogOwner::start_before_energizing(
        &config.watchdog,
        Duration::from_secs(300),
        Duration::from_secs(2),
        liveness,
    )
    .await?;
    armed.require_armed("c43-bm1393-native")?;
    let scope = watchdog.claim_c43_route_scope()?;
    let result: Result<()> = async {
        tokio::select! { _ = shutdown.cancelled() => bail!("C43 startup cancelled"), result = runtime.start() => result? }
        custody.require_all_sensors.store(true, Ordering::SeqCst);
        let snapshot = sample(&transport, pwm, true, custody.cutoff).await.map_err(anyhow::Error::msg)?;
        *custody.snapshot.lock().map_err(|_| anyhow!("C43 health poisoned"))? = snapshot;
        watchdog.enter_mining().await?;
        // Retire startup/core-opening returns before the first pool ledger.
        transport.flush_returns().await.map_err(anyhow::Error::msg)?;
        mining_loop(&config, &shutdown, &state_tx, &custody, &mut runtime, &mut actors).await
    }.await;
    let teardown_request = watchdog.request_teardown_budget();
    let cut_started = Instant::now();
    let cut = transport.terminal_cut().await;
    let cut_finished = Instant::now();
    if !cut.completed() {
        tracing::error!(errors=?cut.errors(), "C43 terminal cut incomplete");
    }
    let runtime_stopped = runtime.shutdown().await.is_ok();
    let custody_stopped = custody.stop().await.is_ok();
    let actors_joined = actors.stop().await && runtime_stopped && custody_stopped;
    let (barrier, power) = cut.into_parts();
    let cleanup: Result<_> = async {
        let (budget, admission) = teardown_request?.into_parts();
        let view = budget.view();
        watchdog
            .observe_teardown_admission(admission, &view)
            .await
            .map_err(anyhow::Error::msg)?;
        view.require_completed_at(TeardownStage::CutoffStart, cut_started)?;
        view.require_completed_at(TeardownStage::CutoffComplete, cut_finished)?;
        let drain =
            mutation_owner.close_and_drain_until(view.deadline(TeardownStage::CleanupComplete))?;
        let commit = match mutation_owner.revoke_commit_fence().try_wait() {
            dcentrald_hal::platform::HardwareMutationCommitFenceTryWait::Fenced(receipt) => receipt,
            _ => bail!("C43 API commit owner did not quiesce"),
        };
        view.require_completed_at(TeardownStage::CleanupComplete, Instant::now())?;
        let safe_off = C43SafeOffEvidence {
            budget: view,
            power,
            actors_joined,
        };
        let authority = budget.begin_disarm_at(Instant::now())?;
        WatchdogDisarmPermit::from_c43_manifest(C43WatchdogShutdownManifest::new(
            scope, drain, commit, barrier, safe_off, authority,
        ))
    }
    .await;
    match cleanup {
        Ok(permit) => {
            let receipt = watchdog
                .disarm_and_join(permit, Duration::from_secs(2))
                .await?;
            match result {
                Ok(()) => crate::daemon::publish_orderly_software_closeout(
                    software_closeout_run,
                    &receipt,
                ),
                Err(source) => Err(anyhow::Error::new(TerminalSafeOffError {
                    source,
                    _receipt: receipt,
                })),
            }
        }
        Err(error) => {
            let _ = watchdog
                .suppress_feeds_terminally(format!("C43 shutdown incomplete: {error:#}"))
                .await;
            Err(
                crate::runtime::safety_watchdog::watchdog_reset_pending_error(
                    "c43-bm1393-native",
                    format!("{error:#}"),
                ),
            )
        }
    }
}

async fn mining_loop(
    config: &DcentraldConfig,
    shutdown: &CancellationToken,
    state: &watch::Sender<dcentrald_api::MinerState>,
    custody: &Arc<Custody>,
    runtime: &mut NativeRuntime,
    actors: &mut OwnedActors,
) -> Result<()> {
    let (job_tx, mut job_rx) = tokio::sync::mpsc::channel::<JobTemplate>(16);
    let (share_tx, share_rx) = tokio::sync::mpsc::channel::<ValidShare>(128);
    let (status_tx, mut status_rx) = tokio::sync::mpsc::channel::<StratumStatus>(128);
    let pool_config = crate::config::build_stratum_config_with_enumerated_chips(
        config,
        crate::config::stratum_donation_config(&config.donation),
        config.mining.version_rolling,
        false,
        Some(runtime.active_chains().len() as u32 * 60),
    );
    let worker = pool_config.pool1.worker.clone();
    actors.tasks.push(tokio::spawn(
        dcentrald_stratum::StratumRouter::new(pool_config).run(job_tx, share_rx, status_tx),
    ));
    let mut feeder = Feeder::new(runtime.active_chains());
    let mut builder = WorkBuilder::new();
    let mut job: Option<JobTemplate> = None;
    let mut poll = tokio::time::interval(Duration::from_millis(1));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut publish = tokio::time::interval(Duration::from_secs(2));
    publish.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let started = Instant::now();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            status = status_rx.recv() => match status {
                Some(StratumStatus::ShareAccepted { .. }) => state.send_modify(|s| s.accepted += 1),
                Some(StratumStatus::ShareRejected { .. }) => state.send_modify(|s| s.rejected += 1),
                Some(StratumStatus::DifficultyChanged(d)) => state.send_modify(|s| s.pool.difficulty = d),
                Some(StratumStatus::StateChanged(status)) => {
                    state.send_modify(|s| s.pool.status = format!("{status:?}").to_lowercase());
                    if !matches!(status, dcentrald_stratum::types::StratumState::Mining | dcentrald_stratum::types::StratumState::Donating) {
                        job = None; feeder.pause(Instant::now());
                    }
                }
                Some(status) => tracing::debug!(?status, "C43 pool status"),
                None => bail!("C43 Stratum status actor exited"),
            },
            next = job_rx.recv() => {
                let next = next.context("C43 Stratum job actor exited")?;
                feeder.invalidate();
                builder.set_version_mask(next.version_mask); job = Some(next);
            },
            _ = publish.tick() => {
                custody.check_health().await.map_err(anyhow::Error::msg)?;
                let snapshot = custody.snapshot.lock().map_err(|_| anyhow!("C43 health poisoned"))?.clone();
                let now = Instant::now();
                let mut silent = Vec::new();
                for (&chain, ledger) in &mut feeder.ledgers {
                    while ledger.recent.front().is_some_and(|at| now.duration_since(*at) > Duration::from_secs(5)) { ledger.recent.pop_front(); }
                    if job.is_some() && ledger.ticket_deadline_expired(now) { silent.push(chain); }
                }
                for chain in silent {
                    tracing::error!(chain, "C43 no CPU-verified tickets for60s: isolating chain");
                    if runtime.active_chains().contains(&chain) {
                        runtime.isolate_chain(chain).await?;
                    }
                }
                feeder.retain_active(runtime.active_chains());
                state.send_modify(|s| {
                    let elapsed = started.elapsed().as_secs_f64().max(1.0);
                    s.uptime_s = started.elapsed().as_secs();
                    s.hashrate_ghs = feeder.ledgers.values().map(|l| l.tickets as f64 * 64.0 * 4.294967296 / elapsed).sum();
                    s.hashrate_5s_ghs = feeder.ledgers.values().map(|l| l.recent.len() as f64 * 64.0 * 4.294967296 / elapsed.min(5.0)).sum();
                    s.chains = feeder.ledgers.iter().map(|(&chain, ledger)| dcentrald_api::ChainState {
                        id: chain, chips: 60, frequency_mhz: config.mining.frequency_mhz as u16,
                        voltage_mv: config.mining.voltage_mv as u16,
                        temp_c: snapshot.temperatures.iter().find(|t| t.chain == chain)
                            .map(|t| t.readings.iter().map(|(_, local, remote)| local.max(*remote)).fold(f32::NEG_INFINITY, f32::max)).unwrap_or(0.0),
                        temp_source: Some(dcentrald_api::ChainTempSource::BOARD_SENSOR.into()),
                        hashrate_ghs: ledger.tickets as f64 * 64.0 * 4.294967296 / elapsed,
                        errors: 0, status: if job.is_some() { "mining" } else { "waiting_for_pool" }.into(),
                    }).collect();
                    s.fans.pwm = custody.pwm;
                    s.fans.rpm = snapshot.fans.iter().find(|(id, _)| *id == 0).map(|(_, rpm)| *rpm).unwrap_or(0);
                    s.fans.per_fan = snapshot.fans.iter().map(|(id, rpm)| dcentrald_api::PerFanReading { id: *id, rpm: *rpm, pwm_percent: custody.pwm }).collect();
                });
            },
            _ = poll.tick() => {
                for record in runtime.poll_returns().await? {
                    if let S9SeFifoRecord::Nonce { chain, work_id, nonce3 } = record {
                        if let Some(ledger) = feeder.ledgers.get_mut(&chain) {
                            if let Some(share) = ledger.validate(chain, work_id, nonce3, &worker) {
                                share_tx.try_send(share).context("C43 share queue unavailable")?;
                            }
                        }
                    }
                }
                feeder.retain_active(runtime.active_chains());
                if let Some(template) = &job {
                    let batch = feeder.prepare(|| Ok(builder.next_work(template)?))?;
                    let accepted = runtime.submit_batch(batch).await?;
                    feeder.commit(&accepted)?;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c43_safety_requires_both_fans_all_boards_and_fresh_temperature() {
        let xadc = dcentrald_hal::xadc::XadcReadings {
            die_temp_c: 45.0,
            vccint_v: 1.0,
            vccaux_v: 1.8,
        };
        let fans = [(0, 1800), (1, 2000)];
        let mut temperatures = vec![C43TemperatureSnapshot {
            chain: 0,
            readings: vec![(120, 35.0, 47.0)],
            sampled: Instant::now(),
        }];
        assert!(validate_health(&fans, &temperatures, &[0], true, 80.0, xadc).is_ok());
        assert!(validate_health(&fans[..1], &temperatures, &[0], true, 80.0, xadc).is_err());
        assert!(validate_health(&fans, &temperatures, &[0, 1], true, 80.0, xadc).is_err());
        assert!(validate_health(&fans, &[], &[0], false, 80.0, xadc).is_ok());
        temperatures[0].readings[0].2 = 80.0;
        assert!(validate_health(&fans, &temperatures, &[0], true, 80.0, xadc).is_err());
        temperatures[0].readings[0].2 = 45.0;
        temperatures[0].sampled = Instant::now() - Duration::from_secs(6);
        assert!(validate_health(&fans, &temperatures, &[0], true, 80.0, xadc).is_err());
    }
}
