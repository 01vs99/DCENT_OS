//! Exact S17e/T17e native runtime with retained source/work/watchdog custody.
//! Lexical child of bm1396_mining_work. Main/catalog registration and complete
//! runtime validation are tracked by the campaign's retained evidence receipts.
#[path = "bm1396_mining_custody.rs"]
mod custody;
#[path = "bm1396_mining_dispatch.rs"]
mod dispatch;
#[path = "bm1396_mining_health.rs"]
mod health;
#[path = "bm1396_mining_startup.rs"]
mod startup;
#[path = "bm1396_mining_telemetry.rs"]
mod telemetry;
use crate::bm1396_mining_work::registry::WorkRegistry;
use crate::runtime::safety_watchdog::{
    watchdog_reset_pending_error, Bm1396ActorSlot, Bm1396Actors, Bm1396WatchdogShutdownManifest,
    SafetyLiveness, SafetyWatchdogOwner, WatchdogDisarmPermit,
};
use crate::runtime::teardown_budget::TeardownStage;
use crate::{bm1396_admission::Bm1396DispatchAdmission, config::DcentraldConfig};
use anyhow::{anyhow, bail, ensure, Context, Result};
use dcentrald_hal::platform::stock_bm1396::{
    Hardware, NativeMmio, PicApplication, PowerLine, Transport,
};
use dcentrald_stratum::StratumRouter;
use startup::{Phase, PhaseDeadline};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

pub(crate) fn panic_teardown() {
    custody::panic_teardown();
}
fn deadline(seconds: u64) -> Instant {
    Instant::now() + Duration::from_secs(seconds)
}

async fn adopt_api(
    actors: &mut Bm1396Actors,
    handles: (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>),
) -> Result<()> {
    let mut rejected = Vec::new();
    for (slot, handle) in [
        (Bm1396ActorSlot::ApiServer, handles.0),
        (Bm1396ActorSlot::ApiState, handles.1),
    ] {
        if let Err(handle) = actors.adopt(slot, handle) {
            handle.abort();
            rejected.push(handle);
        }
    }
    let failed = !rejected.is_empty();
    let until = tokio::time::Instant::now() + Duration::from_secs(1);
    for handle in rejected {
        let _ = tokio::time::timeout_at(until, handle).await;
    }
    ensure!(!failed, "BM1396 API task ownership admission failed");
    Ok(())
}

pub(crate) async fn run(
    config: DcentraldConfig,
    shutdown: CancellationToken,
    state_tx: Option<watch::Sender<dcentrald_api::MinerState>>,
    admission: Bm1396DispatchAdmission,
) -> Result<()> {
    let software_closeout_run =
        dcentrald_common::mutation_disposition::capture_software_closeout_run(
            admission.board_target(),
        );
    let started = Instant::now();
    // No generic platform constructor can reach this method through a board
    // family guess: root main must consume the exact held admission first.
    let owner = Transport::<NativeMmio>::open_observed(admission.model())
        .await
        .map_err(anyhow::Error::msg)?;
    let line = PowerLine::open(owner.clone(), deadline(5))
        .await
        .map_err(anyhow::Error::msg)?;
    let pic = PicApplication::claim(owner.clone()).map_err(anyhow::Error::msg)?;
    let liveness = SafetyLiveness::default();
    let (watchdog, armed) = SafetyWatchdogOwner::start_before_energizing(
        &config.watchdog,
        Duration::from_secs(900),
        Duration::from_secs(3),
        liveness.clone(),
    )
    .await?;
    armed.require_armed("bm1396-native")?;
    run_owned(
        config,
        shutdown,
        state_tx,
        admission,
        owner,
        line,
        pic,
        watchdog,
        liveness,
        started,
        software_closeout_run,
    )
    .await
}

// The production caller above creates only the exact native transports and
// actual armed watchdog. Generic hardware permits desk execution of this same
// coordinator; it does not expose a second product dispatch entry.
async fn run_owned<H: Hardware>(
    config: DcentraldConfig,
    shutdown: CancellationToken,
    state_tx: Option<watch::Sender<dcentrald_api::MinerState>>,
    admission: Bm1396DispatchAdmission,
    owner: Arc<Transport<H>>,
    line: Arc<PowerLine<H>>,
    pic: Arc<PicApplication<H>>,
    mut watchdog: SafetyWatchdogOwner,
    liveness: SafetyLiveness,
    started: Instant,
    software_closeout_run: std::result::Result<
        dcentrald_common::mutation_disposition::SoftwareCloseoutRun,
        String,
    >,
) -> Result<()> {
    let actor_stop = CancellationToken::new();
    let crash = custody::install(
        owner.clone(),
        line.clone(),
        watchdog.feed_stop_signal(),
        actor_stop.clone(),
    )?;
    let (route, mut actors) =
        watchdog.claim_bm1396_route_scope(owner.clone(), actor_stop.clone())?;
    let (fault_tx, mut faults) = watch::channel(None::<String>);
    let fault_signal = health::FaultSignal {
        owner: owner.clone(),
        line: line.clone(),
        feed: watchdog.feed_stop_signal(),
        faults: fault_tx,
    };
    let startup_deadline = deadline(900);
    let (phase_tx, phase_rx) = watch::channel(PhaseDeadline {
        phase: Phase::Observing,
        until: startup_deadline,
    });
    let (heartbeat_tx, heartbeat_rx) = watch::channel(false);
    let current_thermal: health::CurrentThermal = Arc::new(Mutex::new(None));
    let current_work: health::CurrentWorkHealth = Arc::new(Mutex::new(None));
    let (thermal_tx, mut thermal_rx) = watch::channel(None);
    let (progress_tx, mut progress_rx) = watch::channel(dispatch::DispatchProgress::default());
    let state = state_tx.unwrap_or_else(|| {
        watch::channel(dcentrald_api::MinerState::empty(
            dcentrald_api::OperatingMode::Standard,
        ))
        .0
    });
    state.send_modify(|state| {
        state.pool.url = config.pool.url.clone();
        state.pool.worker = config.pool.worker.clone();
        state.pool.protocol = "sv1".into();
    });
    let mut retained_registry: Option<WorkRegistry<H>> = None;
    let mut interrupt_faults = faults.clone();
    let result: Result<()> = tokio::select! {
        biased;
        _=shutdown.cancelled()=>Err(anyhow!("BM1396 runtime cancelled")),
        _=interrupt_faults.changed()=>Err(anyhow!("BM1396 independent safety fault: {}",
            interrupt_faults.borrow().as_deref().unwrap_or("fault owner closed"))),
        result=async {
            let api_state=dcentrald_api::build_minimal_app_state_with_hardware_mutation_gate(
                dcentrald_api::MinimalAppStateInputs {
                    api_config:dcentrald_api::ApiConfig {
                        cgminer_port:config.api.cgminer_port,http_port:config.api.http_port,
                        http_bind:config.api.http_bind.clone(),websocket_enabled:config.api.websocket,
                        websocket_tickets:config.api.websocket_tickets,cgminer_bind_lan:config.api.cgminer_bind_lan,
                        cgminer_lan_writes:config.api.cgminer_lan_writes,metrics_require_auth:config.api.metrics_require_auth,
                        expose_boot_timeline:config.api.expose_boot_timeline,observer_only:false,
                    },
                    pool_url:config.pool.url.clone(),pool_protocol:"sv1".into(),
                    mode:dcentrald_api::OperatingMode::from_config_str(&config.mode.active),
                    firmware_version:env!("CARGO_PKG_VERSION").into(),fan_pwm:30,
                    network_block:config.network_block.clone(),profile_path:config.autotuner.profile_path.clone(),
                    control_board_label:admission.board_target().into(),chip_type_label:"BM1396".into(),
                    external_state_rx:Some(state.subscribe()),
                },route.api_gate());
            adopt_api(&mut actors,dcentrald_api::start_api_servers(api_state).await?).await?;
            health::spawn_heartbeats(&mut actors,owner.clone(),pic.clone(),heartbeat_rx.clone(),
                actor_stop.clone(),fault_signal.clone())?;
            health::spawn_health(&mut actors,owner.clone(),pic.clone(),phase_rx,heartbeat_rx,
                current_thermal.clone(),current_work.clone(),state.clone(),started,admission.cutoff_c(),liveness,actor_stop.clone(),fault_signal.clone())?;
            let pool_config=crate::config::build_stratum_config_with_enumerated_chips(
                &config,crate::config::stratum_donation_config(&config.donation),false,false,
                Some(owner.chains().len() as u32*u32::from(owner.model().expected_chips_per_present_chain())));
            retained_registry=Some(WorkRegistry::new(owner.clone(),pool_config.pool1.worker.clone())?);
            let (job_tx,mut jobs)=mpsc::channel(16);
            let (share_tx,share_rx)=mpsc::channel(128);
            let (status_tx,mut statuses)=mpsc::channel(128);
            let (pool_start, start_pool) = tokio::sync::oneshot::channel::<()>();
            let stratum_stop=actor_stop.clone();let stratum_fault=fault_signal.clone();
            actors.spawn(Bm1396ActorSlot::Stratum,async move {
                // Own the actual required actor during startup, but only begin
                // the pool session after the completed final HAL observation.
                // This prevents unread notify/status queues filling during the
                // long source-mandated reset and calibration sequence.
                tokio::select! {
                    biased;
                    _=stratum_stop.cancelled()=>return,
                    started=start_pool=>if started.is_err() {
                        stratum_fault.trip("BM1396 pool-start owner closed".into());return;
                    }
                }
                tokio::select! {
                    biased;
                    _=stratum_stop.cancelled()=>{},
                    _=StratumRouter::new(pool_config).run(job_tx,share_rx,status_tx)=>{
                        stratum_fault.trip("BM1396 required Stratum actor ended".into());
                    }
                }
            })?;
            actors.require_running()?;
            let final_receipt={
                let startup=startup::startup(&owner,&line,&pic,&admission,&actors,&phase_tx,
                    &heartbeat_tx,startup_deadline);
                tokio::pin!(startup);
                let mut roster_check=tokio::time::interval(Duration::from_millis(100));
                loop {
                    tokio::select! {
                        biased;
                        _=shutdown.cancelled()=>bail!("BM1396 startup cancelled"),
                        _=faults.changed()=>bail!("BM1396 startup safety fault: {}",faults.borrow().as_deref().unwrap_or("fault owner closed")),
                        result=&mut startup=>break result?,
                        _=roster_check.tick()=>actors.require_running()?,
                    }
                }
            };
            telemetry::final_profile(&state,owner.chains(),&final_receipt)?;
            let thermal=final_receipt.thermal_snapshots().last().cloned().context("BM1396 completed final population absent")?;
            telemetry::temperatures(&state,&thermal,final_receipt.epoch())?;
            *current_thermal.lock().map_err(|_|anyhow!("BM1396 thermal custody poisoned"))?=Some(thermal);
            watchdog.enter_bm1396_mining(&route,&actors).await?;
            pool_start.send(()).map_err(|_|anyhow!("BM1396 required pool-start actor ended"))?;
            let launch_deadline=deadline(60);
            phase_tx.send_replace(PhaseDeadline {phase:Phase::Probing,until:launch_deadline});
            let (control,mut events,work_health,inbox)=pic.fixed_work_channels();
            *current_work.lock().map_err(|_|anyhow!("BM1396 current work health custody poisoned"))?=Some(work_health);
            let registry=retained_registry.as_mut().context("BM1396 registry owner missing")?;
            let serving=pic.serve_fixed_work(line.clone(),inbox,deadline(5));
            let consuming=dispatch::dispatch(&owner,registry,&control,&mut events,&mut jobs,
                &mut statuses,&share_tx,&thermal_tx,&progress_tx,&shutdown,launch_deadline);
            tokio::pin!(serving);tokio::pin!(consuming);
            let mut actor_check=tokio::time::interval(Duration::from_millis(100));
            loop {
                tokio::select! {
                    biased;
                    _=shutdown.cancelled()=>bail!("BM1396 active work cancelled"),
                    _=faults.changed()=>bail!("BM1396 active safety fault: {}",faults.borrow().as_deref().unwrap_or("fault owner closed")),
                    result=&mut serving=>{
                        result.map_err(anyhow::Error::msg)?;
                        bail!("BM1396 required continuous ASIC worker ended");
                    }
                    result=&mut consuming=>{result?;bail!("BM1396 required work custody consumer ended");}
                    _=actor_check.tick()=>actors.require_running()?,
                    changed=thermal_rx.changed()=>{
                        changed.context("BM1396 thermal event copy owner closed")?;
                        *current_thermal.lock().map_err(|_|anyhow!("BM1396 thermal custody poisoned"))?=thermal_rx.borrow_and_update().clone();
                    }
                    changed=progress_rx.changed()=>{
                        changed.context("BM1396 work progress owner closed")?;
                        let progress=progress_rx.borrow_and_update().clone();
                        telemetry::progress(&state,&progress);
                        if progress.phase==dispatch::DispatchPhase::PoolWork {
                            phase_tx.send_replace(PhaseDeadline {phase:Phase::Mining,until:launch_deadline});
                        }
                        tracing::debug!(phase=?progress.phase,retained_jobs=progress.retained_jobs,
                            retained_returns=progress.retained_returns,job_bytes=progress.charged_job_bytes,
                            accepted=progress.accepted_shares,rejected=progress.rejected_shares,
                            "BM1396 actual runtime progress");
                    }
                }
            }
        }=>result,
    };
    // Dropping either active future cancels the counted worker's waiter. The
    // original registry and HAL receipts stay alive through actual closeout.
    owner.begin_terminal();
    actors.request_stop();
    telemetry::stopped(&state);
    phase_tx.send_replace(PhaseDeadline {
        phase: Phase::Terminal,
        until: Instant::now(),
    });
    let requested = watchdog.request_teardown_budget();
    let permit: Result<_> = async {
        let (budget, admission) = requested?.into_parts();
        let view = budget.view();
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
        let actor_receipt = actors
            .close_until(view.deadline(TeardownStage::CleanupComplete))
            .await;
        watchdog
            .observe_teardown_admission(admission, &view)
            .await
            .map_err(anyhow::Error::msg)?;
        if let Some(registry) = retained_registry.as_ref() {
            tracing::info!(
                retained_jobs = registry.lifetime_jobs(),
                retained_returns = registry.retained_returns().len(),
                job_bytes = registry.charged_bytes(),
                "BM1396 terminal registry custody retained through closeout"
            );
        }
        let authority = budget.begin_disarm_at(Instant::now())?;
        WatchdogDisarmPermit::from_bm1396_manifest(Bm1396WatchdogShutdownManifest::new(
            route,
            api?,
            controls.map_err(anyhow::Error::msg)?,
            actor_receipt?,
            view,
            authority,
        ))
    }
    .await;
    // A safety actor closes the terminal fence before it publishes its
    // observation. A concurrent worker/consumer can therefore win select with
    // a terminal-gate error. Read the retained observation after owned actor
    // closeout and preserve both errors. Cutoff and disarm ordering stay intact.
    let result = match faults.borrow().clone() {
        Some(cause) => {
            let context = format!("BM1396 independent safety observation: {cause}");
            match result {
                Ok(()) => Err(anyhow!(context)),
                Err(error) => Err(error.context(context)),
            }
        }
        None => result,
    };
    match permit {
        Ok(permit) => match watchdog
            .disarm_and_join(permit, Duration::from_secs(2))
            .await
        {
            Ok(actual_receipt) => {
                crash.disarmed();
                match result {
                    Ok(()) => crate::daemon::publish_orderly_software_closeout(
                        software_closeout_run,
                        &actual_receipt,
                    ),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(watchdog_reset_pending_error(
                "bm1396-native",
                format!("{error:#}"),
            )),
        },
        Err(error) => {
            watchdog.feed_stop_signal().close_terminal_lock_free();
            let _ = line.terminal_high(deadline(1)).await;
            let _ = watchdog
                .suppress_feeds_terminally(format!("BM1396 shutdown incomplete: {error:#}"))
                .await;
            Err(watchdog_reset_pending_error(
                "bm1396-native",
                format!("{error:#}"),
            ))
        }
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bm1396_mining_integration_tests.rs"]
mod integration_tests;
