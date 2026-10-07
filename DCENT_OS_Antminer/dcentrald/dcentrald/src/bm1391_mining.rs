// SPDX-License-Identifier: GPL-3.0-or-later
//! Exact held S15/T15 native startup, retained FIFO/thermal custody and pool work.
//! No source mode fallback is attempted: physical known-header returns must
//! qualify this boot's cold raw-TW transport before normal pool dispatch.
use crate::bm1391_admission::Bm1391DispatchAdmission;
use crate::bm1391_mining_work::WorkDispatcher;
use crate::config::DcentraldConfig;
use crate::runtime::safety_watchdog::{
    Bm1391ActorSlot, Bm1391Actors, Bm1391WatchdogShutdownManifest, SafetyLiveness,
    SafetyWatchdogOwner, WatchdogDisarmPermit,
};
use crate::runtime::teardown_budget::TeardownStage;
use anyhow::{anyhow, bail, ensure, Context, Result};
use dcentrald_common::bm1391_stock_return::Bm1391StockFpgaReturn;
use dcentrald_hal::platform::stock_bm1391::{
    BoardTemperature, FanTachSnapshot, Model, NativeMmio, PicApplication, PllSetting, PowerLine,
    PreservedThermalNonce, StartupBaud, StartupObservation, ThermalApplication, Transport, Work,
};
use dcentrald_stratum::types::{JobTemplate, StratumStatus, ValidShare};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

#[path = "bm1391_mining_custody.rs"]
mod custody;
#[path = "bm1391_mining_pool.rs"]
pub(crate) mod pool;
#[path = "bm1391_mining_probe.rs"]
mod probe;
#[path = "bm1391_mining_profile.rs"]
mod profile;
use custody::{BlockingOwner, Health, PublishedPoolWork, TicketRateWindow};
use probe::Probe;
use profile::Profile;
type NativeTransport = Transport<NativeMmio>;
type Dispatcher = Arc<Mutex<WorkDispatcher<NativeMmio>>>;

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bm1391_mining_integration_tests.rs"]
mod integration_tests;

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
pub(crate) fn panic_hook_best_effort_teardown() {
    custody::panic_teardown();
}

pub(crate) fn is_terminal_safe_off(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<TerminalSafeOffError>().is_some())
}

#[derive(Default)]
struct Services {
    startup: Option<Arc<StartupObservation<NativeMmio>>>,
    thermal: Option<Arc<ThermalApplication<NativeMmio>>>,
    probe: Option<Arc<Mutex<Probe>>>,
}
fn deadline(seconds: u64) -> Instant {
    Instant::now() + Duration::from_secs(seconds)
}

/// The main dispatch owner supplies the exact model/admission, never an
/// arbitrary register mapping or caller-provided physical success receipt.
pub(crate) async fn run(
    config: DcentraldConfig,
    shutdown: CancellationToken,
    state_tx: Option<watch::Sender<dcentrald_api::MinerState>>,
    admission: Bm1391DispatchAdmission,
) -> Result<()> {
    run_in_environment(
        config,
        shutdown,
        state_tx,
        admission,
        RunEnvironment::Native,
    )
    .await
}

enum RunEnvironment {
    Native,
    #[cfg(all(test, feature = "sim-hal"))]
    Simulated {
        rig: Arc<dcentrald_hal::platform::stock_bm1391::simulation::Rig>,
        device_tree: std::path::PathBuf,
        watchdog:
            Arc<std::sync::OnceLock<Arc<crate::runtime::safety_watchdog::bm1396_sim::Observation>>>,
    },
}

// Only descriptors differ in unit simulation. PIC observations, startup actors,
// physical-work qualification, loop and typed closeout below remain shared.
async fn run_in_environment(
    config: DcentraldConfig,
    shutdown: CancellationToken,
    state_tx: Option<watch::Sender<dcentrald_api::MinerState>>,
    admission: Bm1391DispatchAdmission,
    environment: RunEnvironment,
) -> Result<()> {
    let software_closeout_run =
        dcentrald_common::mutation_disposition::capture_software_closeout_run(
            admission.board_target(),
        );
    let profile = Profile::from_config(&config, admission.model())?;
    let owner = match &environment {
        RunEnvironment::Native => NativeTransport::open_observed(profile.model).await,
        #[cfg(all(test, feature = "sim-hal"))]
        RunEnvironment::Simulated {
            rig, device_tree, ..
        } => rig.open_transport(profile.model, device_tree),
    }
    .map_err(anyhow::Error::msg)?;
    // Source high is established before PIC observation, watchdog startup or
    // any low/enable action. Native owner independently validates current boot.
    let line = match &environment {
        RunEnvironment::Native => PowerLine::open(owner.clone(), deadline(5)).await,
        #[cfg(all(test, feature = "sim-hal"))]
        RunEnvironment::Simulated { rig, .. } => rig.open_line(owner.clone(), deadline(5)),
    }
    .map_err(anyhow::Error::msg)?;
    let pic = PicApplication::observe(owner.clone(), profile.model, deadline(90))
        .await
        .map_err(anyhow::Error::msg)?;
    let blocking = BlockingOwner::new(owner.clone());
    let health = Arc::new(Mutex::new(Health::default()));
    let liveness = SafetyLiveness::default();
    let mut watchdog = match &environment {
        RunEnvironment::Native => {
            let (watchdog, armed) = SafetyWatchdogOwner::start_before_energizing(
                &config.watchdog,
                Duration::from_secs(240),
                Duration::from_secs(3),
                liveness.clone(),
            )
            .await?;
            armed.require_armed("bm1391-native")?;
            watchdog
        }
        #[cfg(all(test, feature = "sim-hal"))]
        RunEnvironment::Simulated {
            watchdog: observation,
            ..
        } => {
            let (watchdog, observed) =
                crate::runtime::safety_watchdog::bm1396_sim::start_with_grace(
                    &config.watchdog,
                    liveness.clone(),
                    Duration::from_secs(240),
                )
                .await?;
            observation
                .set(observed)
                .map_err(|_| anyhow!("modeled BM1391 watchdog already observed"))?;
            watchdog
        }
    };
    let actor_stop = CancellationToken::new();
    let crash_guard = custody::install_crash_guard(
        owner.clone(),
        line.clone(),
        watchdog.feed_stop_signal(),
        actor_stop.clone(),
    )?;
    let (route, mut actors) =
        watchdog.claim_bm1391_route_scope(owner.clone(), actor_stop.clone())?;
    let (fault_tx, mut faults) = watch::channel(None::<String>);
    let schedule = Arc::new(tokio::sync::Mutex::new(()));
    let state = state_tx.unwrap_or_else(|| {
        watch::channel(dcentrald_api::MinerState::empty(
            dcentrald_api::OperatingMode::Standard,
        ))
        .0
    });
    let pool_config = crate::config::build_stratum_config_with_enumerated_chips(
        &config,
        crate::config::stratum_donation_config(&config.donation),
        config.mining.version_rolling,
        false,
        Some(owner.selected_chains().len() as u32 * u32::from(profile.model.expected_chips())),
    );
    let dispatcher = Arc::new(Mutex::new(WorkDispatcher::new(
        owner.clone(),
        pool_config.pool1.worker.clone(),
    )));
    let mut services = Services::default();
    let mut interrupt_faults = faults.clone();
    let result: Result<()> = tokio::select! {
        biased;
        _ = shutdown.cancelled() => Err(anyhow!("BM1391 runtime cancelled")),
        _ = interrupt_faults.changed() => Err(anyhow!("BM1391 safety interruption: {}", interrupt_faults.borrow().as_deref().unwrap_or("actor channel closed"))),
        result = async {
        let api_state = dcentrald_api::build_minimal_app_state_with_hardware_mutation_gate(
            dcentrald_api::MinimalAppStateInputs {
                api_config: dcentrald_api::ApiConfig {
                    cgminer_port: config.api.cgminer_port, http_port: config.api.http_port,
                    http_bind: config.api.http_bind.clone(), websocket_enabled: config.api.websocket,
                    websocket_tickets: config.api.websocket_tickets, cgminer_bind_lan: config.api.cgminer_bind_lan,
                    cgminer_lan_writes: config.api.cgminer_lan_writes, metrics_require_auth: config.api.metrics_require_auth,
                    expose_boot_timeline: config.api.expose_boot_timeline, observer_only: false,
                },
                pool_url: config.pool.url.clone(), pool_protocol: config.pool.protocol.clone().unwrap_or_else(|| "sv1".into()),
                mode: dcentrald_api::OperatingMode::from_config_str(&config.mode.active),
                firmware_version: env!("CARGO_PKG_VERSION").into(), fan_pwm: 0,
                network_block: config.network_block.clone(), profile_path: config.autotuner.profile_path.clone(),
                control_board_label: profile.model.board_target().into(), chip_type_label: "BM1391".into(),
                external_state_rx: Some(state.subscribe()),
            }, route.api_gate());
        // Retain the two actual listener tasks; notification/helper tasks are
        // not created outside this route's fixed actor roster.
        let api = dcentrald_api::start_api_servers(api_state).await?;
        adopt_api(&mut actors, api).await?;
        let startup = startup(&owner, &line, &pic, &blocking, &health, &dispatcher, &schedule,
            &mut services, &mut actors, &actor_stop, &fault_tx, liveness, profile);
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => bail!("BM1391 startup cancelled"),
            _ = faults.changed() => bail!("BM1391 startup safety actor: {}", faults.borrow().as_deref().unwrap_or("actor channel closed")),
            result = tokio::time::timeout(Duration::from_secs(180), startup) => result.context("BM1391 absolute startup window expired")??,
        }
        watchdog.enter_mining().await?;
        let thermal = services.thermal.as_ref().context("BM1391 startup lost retained thermal owner")?.clone();
        mining_loop(&owner, &blocking, &dispatcher, &thermal, &health, &state,
            &shutdown, &mut faults, &mut actors, pool_config, profile).await
        } => result,
    };
    owner.latch_terminal();
    actors.request_stop();
    // One absolute watchdog-issued budget covers API fencing, first GPIO cut,
    // PIC/engine completion, queued-worker drain and actor shutdown.
    let teardown = watchdog.request_teardown_budget();
    let cleanup: Result<_> = async {
        let (budget, admission) = teardown?.into_parts();
        let view = budget.view();
        // API stays pending throughout this route. Still consume the route's
        // sealed fence before cutoff; if it fails, cutoff is attempted below.
        let api = route
            .close_api_until(view.deadline(TeardownStage::CutoffStart))
            .await;
        let controls = owner
            .close_terminal_controls(
                line.clone(),
                pic.clone(),
                view.deadline(TeardownStage::CutoffComplete),
                view.deadline(TeardownStage::CleanupComplete),
            )
            .await;
        let cleanup_deadline = view.deadline(TeardownStage::CleanupComplete);
        let workers = blocking.drain(cleanup_deadline).await;
        let mut custody_result = Ok(());
        if let Some(observation) = &services.startup {
            if let Err(error) = observation
                .unexpected_nonce_after_drain(cleanup_deadline)
                .await
            {
                custody_result = Err(anyhow!(error));
            }
        }
        if let Some(thermal) = &services.thermal {
            match thermal.pending_nonces_after_drain(cleanup_deadline).await {
                Ok(pending) => {
                    // Work epoch is terminal. Keep an explicit record of any
                    // nonce replies retired during shutdown; no late submits.
                    tracing::info!(
                        pending_nonces = pending.len(),
                        "BM1391 terminal thermal nonce custody drained"
                    );
                    if let Some(last) = pending.last() {
                        if let Err(error) = thermal.acknowledge_nonces_through(last.sequence) {
                            custody_result = Err(anyhow!(error));
                        }
                    }
                }
                Err(error) => custody_result = Err(anyhow!(error)),
            }
        }
        let actor_receipt = actors.close_until(cleanup_deadline).await;
        watchdog
            .observe_teardown_admission(admission, &view)
            .await
            .map_err(anyhow::Error::msg)?;
        workers?;
        if let Some(probe) = &services.probe {
            let probe = probe.lock().map_err(|_| anyhow!("BM1391 probe poisoned"))?;
            tracing::info!(
                first_header_complete = probe.complete(0),
                second_header_complete = probe.complete(1),
                unrelated_returns = probe.unrelated_returns,
                "BM1391 terminal probe custody drained"
            );
        }
        custody_result?;
        let authority = budget.begin_disarm_at(Instant::now())?;
        WatchdogDisarmPermit::from_bm1391_manifest(Bm1391WatchdogShutdownManifest::new(
            route,
            api?,
            controls.map_err(anyhow::Error::msg)?,
            actor_receipt?,
            view,
            authority,
        ))
    }
    .await;
    match cleanup {
        Ok(permit) => match watchdog
            .disarm_and_join(permit, Duration::from_secs(2))
            .await
        {
            Ok(receipt) => {
                crash_guard.disarmed();
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
                // The consuming disarm method retains/reset-closes its own
                // worker on failure; its owner cannot be reused here.
                Err(
                    crate::runtime::safety_watchdog::watchdog_reset_pending_error(
                        "bm1391-native",
                        format!("{error:#}"),
                    ),
                )
            }
        },
        Err(error) => {
            // A budget issue/fence failure must not prevent an independent
            // source-high attempt. It cannot mint a successful closeout.
            let cut_line = line.clone();
            let until = deadline(1);
            let _ = tokio::task::spawn_blocking(move || cut_line.terminal_high(until)).await;
            let _ = watchdog
                .suppress_feeds_terminally(format!("BM1391 shutdown incomplete: {error:#}"))
                .await;
            Err(
                crate::runtime::safety_watchdog::watchdog_reset_pending_error(
                    "bm1391-native",
                    format!("{error:#}"),
                ),
            )
        }
    }
}

async fn adopt_api(
    actors: &mut Bm1391Actors,
    handles: (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>),
) -> Result<()> {
    let mut rejected = Vec::new();
    for (slot, handle) in [
        (Bm1391ActorSlot::ApiServer, handles.0),
        (Bm1391ActorSlot::ApiState, handles.1),
    ] {
        if let Err(handle) = actors.adopt(slot, handle) {
            handle.abort();
            rejected.push(handle);
        }
    }
    let failed = !rejected.is_empty();
    for handle in rejected {
        let _ = handle.await;
    }
    ensure!(!failed, "BM1391 API actor adoption rejected");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn startup(
    owner: &Arc<NativeTransport>,
    line: &Arc<PowerLine<NativeMmio>>,
    pic: &Arc<PicApplication<NativeMmio>>,
    blocking: &Arc<BlockingOwner>,
    health: &Arc<Mutex<Health>>,
    dispatcher: &Dispatcher,
    schedule: &Arc<tokio::sync::Mutex<()>>,
    services: &mut Services,
    actors: &mut Bm1391Actors,
    actor_stop: &CancellationToken,
    faults: &watch::Sender<Option<String>>,
    liveness: SafetyLiveness,
    profile: Profile,
) -> Result<()> {
    owner
        .set_quiet_fans(deadline(2))
        .await
        .map_err(anyhow::Error::msg)?;
    pic.disable_for_startup(deadline(5))
        .await
        .map_err(anyhow::Error::msg)?;
    for _ in 0..5 {
        pic.heartbeat(deadline(3))
            .await
            .map_err(anyhow::Error::msg)?;
    }
    let until = deadline(20);
    loop {
        let snapshot = owner
            .fan_tach_snapshot(deadline(2))
            .await
            .map_err(anyhow::Error::msg)?;
        if health
            .lock()
            .map_err(|_| anyhow!("BM1391 health poisoned"))?
            .fans(snapshot, true)
            .is_ok()
        {
            break;
        }
        ensure!(
            Instant::now() < until,
            "BM1391 quiet startup fan admission timed out"
        );
        // Keep stable per-route heartbeat timestamps while fans start.
        pic.heartbeat(deadline(3))
            .await
            .map_err(anyhow::Error::msg)?;
    }
    spawn_heartbeats(
        actors,
        owner.clone(),
        pic.clone(),
        schedule.clone(),
        actor_stop.clone(),
        faults.clone(),
    )?;
    spawn_health(
        actors,
        owner.clone(),
        pic.clone(),
        health.clone(),
        profile,
        liveness,
        actor_stop.clone(),
        faults.clone(),
    )?;
    actors.require_started_running()?;
    let power_line = line.clone();
    let until = deadline(2);
    blocking
        .run(until, move |_| {
            power_line
                .enable_source_line(until)
                .map_err(anyhow::Error::msg)
        })
        .await?;
    // Original GPIO-on/PIC-off startup holds30 seconds before highest voltage.
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        actors.require_started_running()?;
    }
    {
        let _schedule = schedule.lock().await;
        pic.heartbeat(deadline(3))
            .await
            .map_err(anyhow::Error::msg)?;
        let voltage = pic
            .set_apw8_voltage(20.0, deadline(2))
            .await
            .map_err(anyhow::Error::msg)?;
        tracing::info!(
            commanded_volts = voltage.requested_volts,
            dac = voltage.dac_code,
            "BM1391 stock startup voltage command completed; no rail measurement"
        );
        pic.enable(deadline(10)).await.map_err(anyhow::Error::msg)?;
    }
    for level in [true, false] {
        actors.require_started_running()?;
        let until = deadline(2);
        blocking
            .run(until, move |owner| {
                for &chain in owner.selected_chains() {
                    owner
                        .set_chain_reset_level(chain, level, until)
                        .map_err(anyhow::Error::msg)?;
                }
                Ok(())
            })
            .await?;
        tokio::time::sleep(Duration::from_secs(if level { 3 } else { 1 })).await;
    }
    // Read at the unchanged observed host rate. Never sweep aliases or assume
    // an inherited/reset baud. Nonempty initial census precedes assignment.
    let mut population = Vec::new();
    for &chain in owner.selected_chains() {
        actors.require_started_running()?;
        let initial = owner
            .census(profile.model, chain, deadline(5))
            .await
            .map_err(anyhow::Error::msg)?;
        ensure!(
            !initial.replies.is_empty(),
            "BM1391 initial ASIC census was empty"
        );
        owner
            .configure_addresses(profile.model, chain, deadline(10))
            .await
            .map_err(anyhow::Error::msg)?;
        population.push(
            owner
                .census(profile.model, chain, deadline(5))
                .await
                .map_err(anyhow::Error::msg)?,
        );
    }
    let observation =
        StartupObservation::new(owner.clone(), population.clone()).map_err(anyhow::Error::msg)?;
    services.startup = Some(observation.clone());
    let baud = observation
        .observe_and_switch(StartupBaud::Operational, deadline(10))
        .await
        .map_err(anyhow::Error::msg)?;
    tracing::info!(
        host_before = baud.host_before(),
        host_after = baud.host_after(),
        replies = baud.replies().len(),
        "BM1391 full population baud transition completed"
    );
    let until = deadline(3);
    blocking
        .run(until, move |owner| {
            owner
                .prepare_cold_engine(until)
                .map_err(anyhow::Error::msg)?;
            owner
                .set_work_timeout_ticks(50_000, until)
                .map_err(anyhow::Error::msg)?;
            for &chain in owner.selected_chains() {
                owner
                    .program_pll(chain, profile.pll, until)
                    .map_err(anyhow::Error::msg)?;
            }
            Ok(())
        })
        .await?;
    let thermal = ThermalApplication::from_pic_observation(pic, &population, deadline(2))
        .map_err(anyhow::Error::msg)?;
    services.thermal = Some(thermal.clone());
    let initialized = thermal.initialize(deadline(10)).await;
    offer_pending(
        blocking,
        dispatcher,
        &thermal,
        initialized.pending_nonces,
        None,
    )
    .await?;
    let sensors = initialized.result.map_err(anyhow::Error::msg)?;
    health
        .lock()
        .map_err(|_| anyhow!("BM1391 health poisoned"))?
        .bind_thermal_sensors(sensors, owner.selected_chains())?;
    sample_thermal(
        blocking,
        dispatcher,
        &thermal,
        health,
        profile,
        owner.selected_chains(),
    )
    .await?;
    for &chain in owner.selected_chains() {
        actors.require_started_running()?;
        owner
            .initialize_cores_in_cold_engine(chain, deadline(6))
            .await
            .map_err(anyhow::Error::msg)?;
        sample_thermal(
            blocking,
            dispatcher,
            &thermal,
            health,
            profile,
            owner.selected_chains(),
        )
        .await?;
    }
    let codes = profile::ramp_codes(20.0, profile.working_volts);
    let last = codes.len() - 1;
    for (index, code) in codes.into_iter().enumerate() {
        actors.require_started_running()?;
        {
            let _schedule = schedule.lock().await;
            let requested = if index == last {
                profile.working_volts
            } else {
                profile::dac_preimage(code)
            };
            let completed = pic
                .set_apw8_voltage(requested, deadline(2))
                .await
                .map_err(anyhow::Error::msg)?;
            ensure!(
                completed.dac_code == code,
                "BM1391 source ramp DAC code did not match the completed setting"
            );
        }
        // Exact source default:500ms in addition to the setter's own settle.
        // Independent heartbeats keep running while ASIC thermal reads occur.
        tokio::time::sleep(Duration::from_millis(500)).await;
        sample_thermal(
            blocking,
            dispatcher,
            &thermal,
            health,
            profile,
            owner.selected_chains(),
        )
        .await?;
    }
    tracing::info!(
        commanded_volts = profile.working_volts,
        "BM1391 source working-voltage DAC ramp completed; no rail measurement"
    );
    let until = deadline(2);
    blocking
        .run(until, move |owner| {
            owner
                .set_work_timeout_ticks(profile.timeout_ticks, until)
                .map_err(anyhow::Error::msg)
        })
        .await?;
    let probe = Arc::new(Mutex::new(Probe::new(owner.selected_chains())));
    services.probe = Some(probe.clone());
    qualify_raw(
        owner, blocking, dispatcher, &thermal, health, profile, actors, probe,
    )
    .await?;
    actors.require_started_running()?;
    Ok(())
}

fn spawn_heartbeats(
    actors: &mut Bm1391Actors,
    owner: Arc<NativeTransport>,
    pic: Arc<PicApplication<NativeMmio>>,
    schedule: Arc<tokio::sync::Mutex<()>>,
    stop: CancellationToken,
    faults: watch::Sender<Option<String>>,
) -> Result<()> {
    actors.spawn(Bm1391ActorSlot::Heartbeats, async move {
        loop {
            tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::sleep(Duration::from_millis(100)) => () }
            // The enable sequence performs its own interleaved heartbeats.
            // Mint a fresh deadline only after that serialized policy operation.
            let _schedule = tokio::select! { _ = stop.cancelled() => break, guard = schedule.lock() => guard };
            if let Err(error) = pic.heartbeat(deadline(3)).await { custody::fault(&owner, &faults, error); break; }
        }
    })
}
fn spawn_health(
    actors: &mut Bm1391Actors,
    owner: Arc<NativeTransport>,
    pic: Arc<PicApplication<NativeMmio>>,
    health: Arc<Mutex<Health>>,
    profile: Profile,
    liveness: SafetyLiveness,
    stop: CancellationToken,
    faults: watch::Sender<Option<String>>,
) -> Result<()> {
    actors.spawn(Bm1391ActorSlot::Health, async move {
        loop {
            tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::sleep(Duration::from_millis(500)) => () }
            let result: Result<()> = async {
                pic.check_application_health(deadline(1)).map_err(anyhow::Error::msg)?;
                owner.set_quiet_fans(deadline(1)).await.map_err(anyhow::Error::msg)?;
                let fans = owner.fan_tach_snapshot(deadline(1)).await.map_err(anyhow::Error::msg)?;
                let mut current = health.lock().map_err(|_| anyhow!("BM1391 health poisoned"))?;
                current.fans(fans, false)?;
                current.check_temperatures(profile, owner.selected_chains())?;
                Ok(())
            }.await;
            match result { Ok(()) => liveness.mark_progress(), Err(error) => { custody::fault(&owner, &faults, error); break; } }
        }
    })
}

async fn offer_pending(
    blocking: &Arc<BlockingOwner>,
    dispatcher: &Dispatcher,
    thermal: &Arc<ThermalApplication<NativeMmio>>,
    pending: Vec<PreservedThermalNonce>,
    probe: Option<&Arc<Mutex<Probe>>>,
) -> Result<()> {
    let probe = probe.cloned();
    let dispatch = dispatcher.clone();
    let through = blocking
        .run(deadline(2), move |_| {
            // Qualification precedes acknowledgment inside retained custody.
            // Cancellation cannot strand a consumed pre-pool probe record.
            if let Some(probe) = probe {
                let mut probe = probe.lock().map_err(|_| anyhow!("BM1391 probe poisoned"))?;
                for nonce in &pending {
                    probe.offer(nonce.record);
                }
            }
            dispatch
                .lock()
                .map_err(|_| anyhow!("BM1391 dispatcher poisoned"))?
                .offer_preserved(&pending)
        })
        .await?;
    if let Some(sequence) = through {
        thermal
            .acknowledge_nonces_through(sequence)
            .map_err(anyhow::Error::msg)?;
    }
    Ok(())
}
async fn sample_thermal(
    blocking: &Arc<BlockingOwner>,
    dispatcher: &Dispatcher,
    thermal: &Arc<ThermalApplication<NativeMmio>>,
    health: &Arc<Mutex<Health>>,
    profile: Profile,
    chains: &[u8],
) -> Result<()> {
    sample_thermal_with_probe(blocking, dispatcher, thermal, health, profile, chains, None).await
}
#[allow(clippy::too_many_arguments)]
async fn sample_thermal_with_probe(
    blocking: &Arc<BlockingOwner>,
    dispatcher: &Dispatcher,
    thermal: &Arc<ThermalApplication<NativeMmio>>,
    health: &Arc<Mutex<Health>>,
    profile: Profile,
    chains: &[u8],
    probe: Option<&Arc<Mutex<Probe>>>,
) -> Result<()> {
    let outcome = thermal.sample(deadline(5)).await;
    offer_pending(blocking, dispatcher, thermal, outcome.pending_nonces, probe).await?;
    let temperatures = outcome.result.map_err(anyhow::Error::msg)?;
    let mut current = health
        .lock()
        .map_err(|_| anyhow!("BM1391 health poisoned"))?;
    current.temperatures = temperatures;
    current.require_temperature = true;
    current.check_temperatures(profile, chains)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn qualify_raw(
    owner: &Arc<NativeTransport>,
    blocking: &Arc<BlockingOwner>,
    dispatcher: &Dispatcher,
    thermal: &Arc<ThermalApplication<NativeMmio>>,
    health: &Arc<Mutex<Health>>,
    profile: Profile,
    actors: &Bm1391Actors,
    probe: Arc<Mutex<Probe>>,
) -> Result<()> {
    let until = deadline(2);
    blocking
        .run(until, move |owner| {
            // No pool epoch exists yet. Require an observed empty FIFO after a
            // bounded drain of earlier reset/core/test traffic before admission.
            let mut empty = false;
            for _ in 0..512 {
                if owner
                    .read_return(until)
                    .map_err(anyhow::Error::msg)?
                    .is_none()
                {
                    empty = true;
                    break;
                }
            }
            ensure!(empty, "BM1391 pre-probe return FIFO did not become empty");
            // Full original7b994/7b95c zero setting around the stock test routine.
            for &chain in owner.selected_chains() {
                owner
                    .write_register(chain, 0, true, 0x14, 0, until)
                    .map_err(anyhow::Error::msg)?;
            }
            Ok(())
        })
        .await?;
    for index in 0..2 {
        let frames = probe
            .lock()
            .map_err(|_| anyhow!("BM1391 probe poisoned"))?
            .frames(index)?;
        let until = deadline(2);
        loop {
            let ready = blocking
                .run(until, move |owner| {
                    owner.selected_work_ready(until).map_err(anyhow::Error::msg)
                })
                .await?;
            if ready {
                break;
            }
            ensure!(
                Instant::now() < until,
                "BM1391 probe work slots remained busy"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let published_probe = probe.clone();
        blocking
            .run(until, move |owner| {
                ensure!(
                    owner
                        .selected_work_ready(until)
                        .map_err(anyhow::Error::msg)?,
                    "BM1391 probe work slots unavailable"
                );
                for frame in frames {
                    owner
                        .publish_work(&frame, until)
                        .map_err(anyhow::Error::msg)?;
                }
                published_probe
                    .lock()
                    .map_err(|_| anyhow!("BM1391 probe poisoned"))?
                    .published(index);
                Ok(())
            })
            .await?;
        let until = deadline(20);
        let mut sampled = Instant::now();
        while !probe
            .lock()
            .map_err(|_| anyhow!("BM1391 probe poisoned"))?
            .complete(index)
        {
            actors.require_started_running()?;
            ensure!(Instant::now() < until, "BM1391 cold raw transport did not return both known headers on every selected chain");
            let read_deadline = deadline(1).min(until);
            let retained_probe = probe.clone();
            blocking
                .run(read_deadline, move |owner| {
                    let mut probe = retained_probe
                        .lock()
                        .map_err(|_| anyhow!("BM1391 probe poisoned"))?;
                    for _ in 0..128 {
                        match owner
                            .read_return(read_deadline)
                            .map_err(anyhow::Error::msg)?
                        {
                            None => break,
                            Some(Bm1391StockFpgaReturn::Nonce(nonce)) => probe.offer(nonce),
                            Some(Bm1391StockFpgaReturn::Register(_)) => (),
                        }
                    }
                    Ok(())
                })
                .await?;
            if sampled.elapsed() >= Duration::from_secs(1) {
                sample_thermal_with_probe(
                    blocking,
                    dispatcher,
                    thermal,
                    health,
                    profile,
                    owner.selected_chains(),
                    Some(&probe),
                )
                .await?;
                sampled = Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    let until = deadline(2);
    blocking
        .run(until, move |owner| {
            // Original initialized B82EC is3f in both releases; restore after test.
            for &chain in owner.selected_chains() {
                owner
                    .write_register(chain, 0, true, 0x14, 0x3f, until)
                    .map_err(anyhow::Error::msg)?;
            }
            Ok(())
        })
        .await?;
    let unrelated_probe_returns = probe
        .lock()
        .map_err(|_| anyhow!("BM1391 probe poisoned"))?
        .unrelated_returns;
    tracing::info!(chains=?owner.selected_chains(), unrelated_probe_returns,
        "BM1391 two known canonical headers and exact raw return IDs observed on every selected chain");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn mining_loop(
    owner: &Arc<NativeTransport>,
    blocking: &Arc<BlockingOwner>,
    dispatcher: &Dispatcher,
    thermal: &Arc<ThermalApplication<NativeMmio>>,
    health: &Arc<Mutex<Health>>,
    state: &watch::Sender<dcentrald_api::MinerState>,
    shutdown: &CancellationToken,
    faults: &mut watch::Receiver<Option<String>>,
    actors: &mut Bm1391Actors,
    pool_config: dcentrald_stratum::types::StratumConfig,
    profile: Profile,
) -> Result<()> {
    let (job_tx, mut jobs) = mpsc::channel::<JobTemplate>(16);
    let (share_tx, shares) = mpsc::channel::<ValidShare>(128);
    let (status_tx, mut statuses) = mpsc::channel::<StratumStatus>(128);
    actors.spawn(
        Bm1391ActorSlot::Stratum,
        dcentrald_stratum::StratumRouter::new(pool_config).run(job_tx, shares, status_tx),
    )?;
    let mut poll = tokio::time::interval(Duration::from_millis(5));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut temperatures = tokio::time::interval(Duration::from_secs(1));
    temperatures.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut publish = tokio::time::interval(Duration::from_secs(2));
    publish.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let started = Instant::now();
    let published_work = Arc::new(PublishedPoolWork::default());
    let mut active_job = false;
    let mut active_since = None::<Instant>;
    let mut ticket_window = TicketRateWindow::new(started);
    loop {
        actors.require_running()?;
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            _ = faults.changed() => bail!("BM1391 safety actor: {}", faults.borrow().as_deref().unwrap_or("actor channel closed")),
            event = pool::next_pool_event(&mut jobs, &mut statuses) => match event? {
            pool::PoolEvent::Job(next) => {
                if next.is_flush_only() { published_work.require_unpublished_for_invalidation()?; }
                active_job = !next.is_flush_only();
                if active_job { active_since.get_or_insert(Instant::now()); } else { active_since = None; }
                let dispatch = dispatcher.clone();
                blocking.run(deadline(1), move |_| dispatch.lock().map_err(|_| anyhow!("BM1391 dispatcher poisoned"))?.accept_job(next)).await?;
            }
            pool::PoolEvent::Status(status) => match status {
                StratumStatus::ShareAccepted { .. } => state.send_modify(|s| s.accepted += 1),
                StratumStatus::ShareRejected { .. } => state.send_modify(|s| s.rejected += 1),
                StratumStatus::DifficultyChanged(value) => state.send_modify(|s| s.pool.difficulty = value),
                StratumStatus::StateChanged(status) => {
                    state.send_modify(|s| s.pool.status = format!("{status:?}").to_lowercase());
                    if !matches!(status, dcentrald_stratum::types::StratumState::Mining | dcentrald_stratum::types::StratumState::Donating) {
                        published_work.require_unpublished_for_invalidation()?;
                        active_job = false;
                        active_since = None;
                    }
                    let dispatch = dispatcher.clone();
                    blocking.run(deadline(1), move |_| { dispatch.lock().map_err(|_| anyhow!("BM1391 dispatcher poisoned"))?.observe_pool_state(status); Ok(()) }).await?;
                }
                status => tracing::debug!(?status, "BM1391 pool status"),
            },
            },
            _ = poll.tick() => {
                let dispatch = dispatcher.clone();
                let shares = share_tx.clone();
                let published_work = published_work.clone();
                let until = deadline(1);
                blocking.run(until, move |_| {
                    let mut dispatch = dispatch.lock().map_err(|_| anyhow!("BM1391 dispatcher poisoned"))?;
                    if dispatch.flush_shares(&shares)? {
                        dispatch.drain_fifo(until)?;
                        dispatch.flush_shares(&shares)?;
                        if dispatch.dispatch_if_ready(until)? { published_work.mark_published(); }
                    }
                    Ok(())
                }).await?;
            }
            _ = temperatures.tick() => {
                sample_thermal(blocking, dispatcher, thermal, health, profile, owner.selected_chains()).await?;
            }
            _ = publish.tick() => {
                let current = health.lock().map_err(|_| anyhow!("BM1391 health poisoned"))?.clone();
                current.check_temperatures(profile, owner.selected_chains())?;
                let dispatch = dispatcher.clone();
                let tickets = blocking.run(deadline(1), move |_| Ok(dispatch.lock().map_err(|_| anyhow!("BM1391 dispatcher poisoned"))?.ticket_observations())).await?;
                let now = Instant::now();
                let elapsed = now.duration_since(started).as_secs_f64().max(1.0);
                let rates = ticket_window.observe(now, tickets.map(|ticket| ticket.total))?;
                for &chain in owner.selected_chains() {
                    let at = usize::from(chain);
                    if let Some(active_at) = active_since {
                        let progress = tickets[at].last.unwrap_or(active_at).max(active_at);
                        ensure!(now.duration_since(progress) < Duration::from_secs(60), "BM1391 selected chain has no CPU-verified difficulty64 ticket for60 seconds");
                    }
                }
                state.send_modify(|s| {
                    s.uptime_s = started.elapsed().as_secs();
                    // Estimate from deduplicated, canonical CPU-difficulty64
                    // tickets, separately from the pool's acceptance target.
                    s.hashrate_ghs = tickets.iter().map(|t| t.total as f64 * 64.0 * 4.294967296 / elapsed).sum();
                    s.hashrate_5s_ghs = rates.iter().sum();
                    s.chains = owner.selected_chains().iter().map(|chain| dcentrald_api::ChainState {
                        id: *chain, chips: profile.model.expected_chips(), frequency_mhz: profile.configured_mhz,
                        voltage_mv: (profile.working_volts * 1000.0).round() as u16,
                        temp_c: current.temperatures.iter().find(|t| t.sensor.chain == *chain).map(|t| f32::from(t.pcb_celsius)).unwrap_or(0.0),
                        temp_source: Some(dcentrald_api::ChainTempSource::BOARD_SENSOR.into()),
                        hashrate_ghs: rates[usize::from(*chain)], errors: 0, status: if active_job { "mining" } else { "waiting_for_pool" }.into(),
                    }).collect();
                    s.fans.pwm = 30;
                    s.fans.rpm = current.fans.values().copied().min().unwrap_or(0);
                    s.fans.per_fan = current.fans.iter().map(|(id, rpm)| dcentrald_api::PerFanReading { id: *id, rpm: *rpm, pwm_percent: 30 }).collect();
                });
            }
        }
    }
}
