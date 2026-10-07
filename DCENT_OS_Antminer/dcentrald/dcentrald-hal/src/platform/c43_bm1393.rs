//! Native C43 adapter joining the executable BM1393 program to retained MMIO.
//! The daemon supplies its independently watched safety custody. This adapter
//! owns one PIC heartbeat schedule and never opens a second hardware handle.

#[path = "c43_bm1393_transport.rs"]
pub mod transport;
pub use transport::{C43CutReceipt, C43PowerOffReceipt, C43TerminalBarrierReceipt};

use dcentrald_common::bm1393_native::*;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use transport::{C43Registers, C43Transport};

/// `start` binds this exact transport to a process-independent watchdog before
/// powering chips, proves fresh fan/XADC and holds the reset/PIC cut route.
/// `check_health` checks fresh per-site temperature once configured, fan tach,
/// XADC and independent watchdog liveness. `stop` requires matching checked
/// reset/PIC off receipts. Implementations have no success-default methods.
pub trait C43Custody<R: C43Registers>: Send + Sync + 'static {
    fn start(
        &self,
        transport: Arc<C43Transport<R>>,
    ) -> impl Future<Output = Result<(), String>> + Send;
    fn check_health(&self) -> impl Future<Output = Result<(), String>> + Send;
    fn stop(&self) -> impl Future<Output = Result<(), String>> + Send;
}

pub struct C43Bm1393Adapter<R: C43Registers, C: C43Custody<R>> {
    transport: Arc<C43Transport<R>>,
    custody: Arc<C>,
    heartbeat_chains: Arc<Mutex<Vec<u8>>>,
    heartbeat_error: Arc<Mutex<Option<String>>>,
    cancellation: CancellationToken,
    heartbeat_task: Option<JoinHandle<()>>,
}

impl<R: C43Registers, C: C43Custody<R>> C43Bm1393Adapter<R, C> {
    pub fn new(transport: Arc<C43Transport<R>>, custody: Arc<C>) -> Self {
        Self {
            transport,
            custody,
            heartbeat_chains: Arc::new(Mutex::new(Vec::new())),
            heartbeat_error: Arc::new(Mutex::new(None)),
            cancellation: CancellationToken::new(),
            heartbeat_task: None,
        }
    }
    pub fn transport(&self) -> &Arc<C43Transport<R>> {
        &self.transport
    }
    fn start_heartbeat_worker(&mut self) {
        if self.heartbeat_task.is_some() {
            return;
        }
        let transport = self.transport.clone();
        let selected = self.heartbeat_chains.clone();
        let failure = self.heartbeat_error.clone();
        let cancellation = self.cancellation.clone();
        self.heartbeat_task = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(3));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    _ = ticker.tick() => {}
                }
                let chains = match selected.lock() {
                    Ok(value) => value.clone(),
                    Err(_) => break,
                };
                let mut error = None;
                for chain in chains {
                    if transport.chain_is_fenced(chain) {
                        continue;
                    }
                    if let Err(detail) = transport.pic(chain, Bm1393PicCommand::Heartbeat).await {
                        match transport.isolate_chain(chain).await {
                            Ok(proof) if transport.accepts_isolation(&proof) => {
                                tracing::error!(chain, %detail, "C43 PIC heartbeat fault: chain fenced and cut");
                            }
                            _ => {
                                error = Some(format!("{detail}; C43 chain isolation unproven"));
                                break;
                            }
                        }
                    }
                }
                if transport.active_chains().is_empty() {
                    error = Some("C43 no healthy chains remain".into());
                }
                if let Some(detail) = error {
                    if let Ok(mut target) = failure.lock() {
                        *target = Some(detail);
                    }
                    break;
                }
            }
            // Cancellation and heartbeat faults both retire this generation.
            // Each retained IIC operation finishes/flushes before fixed OFF.
            transport.latch_terminal();
            for &chain in transport.chains() {
                if let Err(error) = transport.reset(chain, true).await {
                    tracing::error!(chain, %error, "C43 heartbeat exit reset unproven");
                }
                if let Err(error) = transport.pic(chain, Bm1393PicCommand::Enable(false)).await {
                    tracing::error!(chain, %error, "C43 heartbeat exit power-off unproven");
                }
            }
        }));
    }
    async fn health(&self) -> Result<(), String> {
        if self.transport.terminal() {
            return Err("C43 retained owner is terminal".into());
        }
        if let Some(error) = self
            .heartbeat_error
            .lock()
            .map_err(|_| "C43 heartbeat status poisoned")?
            .clone()
        {
            return Err(error);
        }
        if self
            .heartbeat_task
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            return Err("C43 heartbeat worker exited".into());
        }
        self.custody.check_health().await
    }
}

impl<R: C43Registers, C: C43Custody<R>> Bm1393Io for C43Bm1393Adapter<R, C> {
    async fn execute(&mut self, action: &Bm1393Action) -> Result<Bm1393Reply, String> {
        match action {
            Bm1393Action::StartCustody { chains } => {
                if chains != self.transport.chains() {
                    return Err(
                        "C43 execution population differs from retained hardware owner".into(),
                    );
                }
                self.custody.start(self.transport.clone()).await?;
            }
            Bm1393Action::ReadProtectedEeprom { chain } => {
                return self
                    .transport
                    .read_factory(*chain)
                    .await
                    .map(Bm1393Reply::Eeprom)
            }
            Bm1393Action::ChainReset { chain, asserted } => {
                self.transport.reset(*chain, *asserted).await?
            }
            Bm1393Action::Pic { chain, command } => {
                return self
                    .transport
                    .pic(*chain, *command)
                    .await
                    .map(Bm1393Reply::Bytes)
            }
            Bm1393Action::MaintainPicHeartbeat { chain } => {
                if !self.transport.chains().contains(chain) {
                    return Err("C43 heartbeat chain is not owned".into());
                }
                {
                    let mut chains = self
                        .heartbeat_chains
                        .lock()
                        .map_err(|_| "C43 heartbeat chain set poisoned")?;
                    if chains.contains(chain) {
                        return Err("C43 heartbeat already maintained".into());
                    }
                    chains.push(*chain);
                }
                self.start_heartbeat_worker();
            }
            Bm1393Action::ConfigureFabric => self.transport.configure().await?,
            Bm1393Action::SetBaud { divisor } => self.transport.set_baud(*divisor).await?,
            Bm1393Action::Asic { chain, bytes } => {
                self.transport.asic(*chain, bytes.clone()).await?
            }
            Bm1393Action::ReadChipCoverage { chain } => {
                return self
                    .transport
                    .coverage(*chain)
                    .await
                    .map(Bm1393Reply::Coverage)
            }
            Bm1393Action::ConfigureTemperature { chain, profile } => {
                self.transport
                    .configure_temperature(*chain, profile.clone())
                    .await?;
            }
            Bm1393Action::CheckHealth => self.health().await?,
            Bm1393Action::SetWorkTimeout { word } => self.transport.timeout(*word).await?,
            Bm1393Action::Work { chain, words } => self.transport.work(*chain, *words).await?,
            Bm1393Action::WorkBatch { items } => {
                return self
                    .transport
                    .try_work_batch(items.clone())
                    .await
                    .map(Bm1393Reply::Submitted);
            }
            Bm1393Action::ReadActiveChains => {
                return Ok(Bm1393Reply::ActiveChains(self.transport.active_chains()));
            }
            Bm1393Action::IsolateChain { chain } => {
                let proof = self.transport.isolate_chain(*chain).await?;
                if !self.transport.accepts_isolation(&proof) {
                    self.transport.latch_terminal();
                    return Err("C43 isolation receipt belongs to another owner".into());
                }
            }
            Bm1393Action::ReadReturns { maximum } => {
                return self
                    .transport
                    .returns(*maximum)
                    .await
                    .map(Bm1393Reply::Returns)
            }
            Bm1393Action::StopWork => self.transport.latch_terminal(),
            Bm1393Action::StopCustody => {
                self.cancellation.cancel();
                if let Some(task) = self.heartbeat_task.take() {
                    task.await
                        .map_err(|e| format!("C43 heartbeat join failed: {e}"))?;
                }
                self.custody.stop().await?;
            }
            Bm1393Action::DelayMs(ms) => {
                tokio::time::sleep(Duration::from_millis(u64::from(*ms))).await
            }
        }
        Ok(Bm1393Reply::Complete)
    }
}
impl<R: C43Registers, C: C43Custody<R>> Drop for C43Bm1393Adapter<R, C> {
    fn drop(&mut self) {
        self.transport.latch_terminal();
        self.cancellation.cancel();
    }
}
