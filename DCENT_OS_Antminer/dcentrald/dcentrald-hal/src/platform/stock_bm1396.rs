//! Retained exact signed S17e/T17e BM1396 stock FPGA owner.
//!
//! The R06 source/replay receipts establish this ABI independently of C43 and
//! BM1391. Native mapping requires the exact programmed payload, current boot,
//! and an uncached, reserved 16 MiB DMA window. Generic hardware is an injection
//! seam for transaction tests, never evidence that a physical board is admitted.

pub use dcentrald_common::bm1396_contract::Bm1396Model as Model;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

#[path = "stock_bm1396_adc.rs"]
mod adc;
#[path = "stock_bm1396_baud.rs"]
mod baud;
#[path = "stock_bm1396_closeout.rs"]
mod closeout;
#[path = "stock_bm1396_cold.rs"]
mod cold;
#[path = "stock_bm1396_factory.rs"]
mod factory;
#[path = "stock_bm1396_gpio.rs"]
mod gpio;
#[path = "stock_bm1396_management.rs"]
mod management;
#[path = "stock_bm1396_native.rs"]
mod native;
#[path = "stock_bm1396_query.rs"]
mod query;
#[path = "stock_bm1396_quiet.rs"]
mod quiet;
#[path = "stock_bm1396_receiver.rs"]
mod receiver;
#[path = "stock_bm1396_startup.rs"]
mod startup;
#[path = "stock_bm1396_thermal.rs"]
mod thermal;
#[path = "stock_bm1396_work.rs"]
mod work;
pub use adc::{DomainAdcChain, DomainAdcCommand, DomainAdcObservation};
pub use baud::{OperationalBaudCommand, OperationalBaudObservation};
pub use closeout::TerminalControlsReceipt;
pub use cold::{ColdRegisterCommand, ColdRegisterObservation};
pub use factory::{FactoryCalibrationObservation, FactoryCalibrationRecord};
pub use gpio::{
    park_source_line, ParkedSourceLine, PowerLine, PowerLineOffObservation, SourceStartObservation,
};
pub use management::{
    AdaptedStartupHealth, AdaptedStartupObservation, AdaptedStartupStage, ColdPllCommand,
    ColdPllObservation, ColdPllStage, ColdPllVoltagePlan, CommandedVoltage,
    ConditioningPreparationObservation, ConditioningPreparationStage, ConditioningResetEvent,
    ConditioningResetObservation, FinalPllObservation, NativePllObservation, FixedWorkControl, FixedWorkEvent,
    FixedWorkEvents, FixedWorkHealth, FixedWorkInbox, PicApplication, PicReply,
    RailFrameObservation, RailSample, RailSnapshot, RailVerificationCheck, RailVerificationEvent,
    RailVerificationObservation, RailVerificationWait, SupplyTypeObservation, VoltageAttempt,
    VoltageStepObservation,
};
// Explicit host-only modeled wire rig; shipping feature sets omit this.
#[cfg(feature = "sim-hal")]
#[path = "stock_bm1396_sim.rs"]
pub mod simulation;

pub use native::NativeMmio;
pub use query::RegisterObservation;
pub use quiet::{FanTachSnapshot, QuietFanSetting};
pub use receiver::{PreservedReturn, ReturnPayload};
pub use startup::AssignmentObservation;
pub use thermal::{
    sensor_positions, SensorPosition, TemperatureRecord, ThermalConfiguration, ThermalSnapshot,
};
pub use work::{JobPublication, OutstandingObservation};

pub const PHYSICAL_BASE: u32 = 0x4000_0000;
pub const DMA_BASE: u32 = 0x0f00_0000;
pub const DMA_BYTES: usize = 0x0100_0000;
pub const BITSTREAM_SHA256: &str =
    "39109da8ab92a08842141bd960d70987a47f368c9529c124540dce71c4098195";
const REGISTER_BYTES: u32 = 0x1200;
const BUSY: u32 = 0x8000_0000;
const DHASH: u32 = 0x100;
const RUN: u32 = 0x40;
const BC: u32 = 0xc0;
const RETURN_CAPACITY: usize = 4096;

/// Private callbacks execute only while the caller retains the ASIC mutex.
/// BeforePublish must not receive: a query may already have set its watermark.
#[derive(Clone, Copy)]
enum CommandServicePoint {
    BeforePublish,
    Poll,
    IdleReceive,
}

pub const fn board_target(model: Model) -> &'static str {
    match model {
        Model::S17e => "am2-s17e",
        Model::T17e => "am2-t17e",
    }
}

/// Implementations must retain their mapping for their entire lifetime and
/// enforce a single transport claim. NativeMmio is constructible only through
/// the boot-bound factory; it never exposes its mapping or file descriptors.
pub trait Hardware: Send + Sync + 'static {
    fn model(&self) -> Model;
    fn validate_owner(&self) -> Result<(), String>;
    fn claim_transport(&self) -> Result<(), String>;
    fn read(&self, offset: u32) -> Result<u32, String>;
    fn write(&self, offset: u32, value: u32) -> Result<(), String>;
    fn read_dma(&self, offset: usize, out: &mut [u8]) -> Result<(), String>;
    fn write_dma(&self, offset: usize, bytes: &[u8]) -> Result<(), String>;
    fn barrier(&self) -> Result<(), String>;
    /// Real hardware sleeps; test implementations can record logical delays.
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Default)]
struct Workers {
    count: usize,
    closed: bool,
}

struct AsicState {
    receiver: receiver::Assembler,
    pending: VecDeque<PreservedReturn>,
    next_return: u64,
    dma_initialized: bool,
    next_buffer: u8,
    publications: Vec<JobPublication>,
    register_observations: VecDeque<RegisterObservation>,
    next_observation: u64,
    thermal: Option<thermal::State>,
    // One completed conditioning epoch remains inspectable after active slots
    // are moved for the one-way adapted reset. Raw/counter custody is unchanged.
    prior_thermal: Option<thermal::State>,
    prior_assignment: Option<AssignmentObservation>,
    prior_cold_registers: Option<ColdRegisterObservation>,
    prior_domain_adc: Option<DomainAdcObservation>,
    prior_operational_baud: Option<OperationalBaudObservation>,
    thermal_epoch: u64,
    requalification_deadline: Option<Instant>,
    startup_attempted: bool,
    assignment: Option<AssignmentObservation>,
    cold_registers: Option<ColdRegisterObservation>,
    domain_adc: Option<DomainAdcObservation>,
    adc_level: dcentrald_common::bm1396_domain_voltage::Bm1396DomainVoltageAdaptiveLevel,
    operational_baud: Option<OperationalBaudObservation>,
}
impl Default for AsicState {
    fn default() -> Self {
        Self {
            receiver: receiver::Assembler::default(),
            pending: VecDeque::new(),
            next_return: 1,
            dma_initialized: false,
            next_buffer: 0,
            publications: Vec::new(),
            register_observations: VecDeque::new(),
            next_observation: 1,
            thermal: None,
            prior_thermal: None,
            prior_assignment: None,
            prior_cold_registers: None,
            prior_domain_adc: None,
            prior_operational_baud: None,
            thermal_epoch: 0,
            requalification_deadline: None,
            startup_attempted: false,
            assignment: None,
            cold_registers: None,
            domain_adc: None,
            adc_level:
                dcentrald_common::bm1396_domain_voltage::Bm1396DomainVoltageAdaptiveLevel::Baseline,
            operational_baud: None,
        }
    }
}

pub struct Transport<H: Hardware> {
    identity: Arc<()>,
    hardware: Arc<H>,
    model: Model,
    chains: Vec<u8>,
    version: u32,
    terminal: AtomicBool,
    asic_fault: AtomicBool,
    management_fault: AtomicBool,
    asic: Mutex<AsicState>,
    management: Mutex<()>,
    factory_calibration: Mutex<Option<FactoryCalibrationObservation>>,
    fans: Mutex<()>,
    workers: Mutex<Workers>,
    pic_claimed: AtomicBool,
    power_line_claimed: AtomicBool,
    terminal_controls_claimed: AtomicBool,
}

impl<H: Hardware> Transport<H> {
    /// Private empty-population source parking. It is permanently terminal and
    /// never exposed as a normal Transport by the native public park result.
    fn parked(hardware: Arc<H>) -> Result<Arc<Self>, String> {
        hardware.validate_owner()?;
        let model = hardware.model();
        let version = hardware.read(0)?;
        hardware.claim_transport()?;
        Ok(Arc::new(Self {
            identity: Arc::new(()),
            hardware,
            model,
            chains: Vec::new(),
            version,
            terminal: AtomicBool::new(true),
            asic_fault: AtomicBool::new(false),
            management_fault: AtomicBool::new(false),
            asic: Mutex::new(AsicState::default()),
            management: Mutex::new(()),
            factory_calibration: Mutex::new(None),
            fans: Mutex::new(()),
            workers: Mutex::new(Workers::default()),
            pic_claimed: AtomicBool::new(false),
            power_line_claimed: AtomicBool::new(false),
            terminal_controls_claimed: AtomicBool::new(false),
        }))
    }

    /// Injected/native hardware must already be retained. This observation does
    /// no writes; exact presence is re-read inside the asynchronous worker.
    pub async fn observe(
        hardware: Arc<H>,
        model: Model,
        chains: Vec<u8>,
    ) -> Result<Arc<Self>, String> {
        tokio::task::spawn_blocking(move || {
            hardware.validate_owner()?;
            if hardware.model() != model || chains.is_empty() || chains.len() > 8 {
                return Err("BM1396 model or selected population is invalid".into());
            }
            let mut mask = 0u32;
            let mut pic_mask = 0u8;
            for &chain in &chains {
                if chain >= 16 || mask & (1 << chain) != 0 || pic_mask & (1 << (chain & 7)) != 0 {
                    return Err(
                        "BM1396 duplicate/out-of-range chain or aliased PIC selector".into(),
                    );
                }
                mask |= 1 << chain;
                pic_mask |= 1 << (chain & 7);
            }
            if !chains.windows(2).all(|w| w[0] < w[1]) {
                return Err(
                    "BM1396 selected chains must be in exact ascending source order".into(),
                );
            }
            if hardware.read(8)? & 0xffff != mask {
                return Err("BM1396 live presence differs from selected population".into());
            }
            let version = hardware.read(0)?;
            hardware.claim_transport()?;
            Ok(Arc::new(Self {
                identity: Arc::new(()),
                hardware,
                model,
                chains,
                version,
                terminal: AtomicBool::new(false),
                asic_fault: AtomicBool::new(false),
                management_fault: AtomicBool::new(false),
                asic: Mutex::new(AsicState::default()),
                management: Mutex::new(()),
                factory_calibration: Mutex::new(None),
                fans: Mutex::new(()),
                workers: Mutex::new(Workers::default()),
                pic_claimed: AtomicBool::new(false),
                power_line_claimed: AtomicBool::new(false),
                terminal_controls_claimed: AtomicBool::new(false),
            }))
        })
        .await
        .map_err(|e| format!("BM1396 observation worker: {e}"))?
    }

    pub fn model(&self) -> Model {
        self.model
    }
    pub fn chains(&self) -> &[u8] {
        &self.chains
    }
    /// Raw observation only: original stock does not enforce fixed VERSION.
    pub fn observed_version(&self) -> u32 {
        self.version
    }
    pub fn is_terminal(&self) -> bool {
        self.terminal.load(Ordering::SeqCst)
    }
    pub fn begin_terminal(&self) {
        self.terminal.store(true, Ordering::SeqCst);
    }

    fn check(&self, deadline: Instant, terminal_allowed: bool) -> Result<(), String> {
        self.hardware.validate_owner()?;
        if Instant::now() >= deadline {
            return Err("BM1396 absolute deadline elapsed".into());
        }
        if !terminal_allowed && self.is_terminal() {
            return Err("BM1396 transport is terminal".into());
        }
        Ok(())
    }

    fn chain(&self, chain: u8) -> Result<(), String> {
        if self.chains.contains(&chain) {
            Ok(())
        } else {
            Err("BM1396 chain is outside retained population".into())
        }
    }

    fn lock<'a, T>(
        &self,
        mutex: &'a Mutex<T>,
        deadline: Instant,
        terminal_allowed: bool,
    ) -> Result<MutexGuard<'a, T>, String> {
        loop {
            self.check(deadline, terminal_allowed)?;
            match mutex.try_lock() {
                Ok(guard) => {
                    self.check(deadline, terminal_allowed)?;
                    return Ok(guard);
                }
                Err(TryLockError::WouldBlock) => self.hardware.sleep(Duration::from_millis(1)),
                Err(TryLockError::Poisoned(_)) => {
                    self.begin_terminal();
                    return Err("BM1396 transaction owner poisoned".into());
                }
            }
        }
    }

    fn delay(
        &self,
        duration: Duration,
        deadline: Instant,
        terminal_allowed: bool,
    ) -> Result<(), String> {
        self.check(deadline, terminal_allowed)?;
        if Instant::now()
            .checked_add(duration)
            .map_or(true, |end| end > deadline)
        {
            return Err("BM1396 remaining absolute budget cannot contain source delay".into());
        }
        self.hardware.sleep(duration);
        self.check(deadline, terminal_allowed)
    }

    fn store(
        &self,
        offset: u32,
        value: u32,
        deadline: Instant,
        terminal_allowed: bool,
    ) -> Result<(), String> {
        self.check(deadline, terminal_allowed)?;
        self.hardware.write(offset, value)
    }

    fn checked_store(
        &self,
        offset: u32,
        value: u32,
        deadline: Instant,
        terminal_allowed: bool,
    ) -> Result<(), String> {
        self.store(offset, value, deadline, terminal_allowed)?;
        self.hardware.barrier()?;
        let actual = self.hardware.read(offset)?;
        self.check(deadline, terminal_allowed)?;
        if actual != value {
            return Err(format!(
                "BM1396 +{offset:x} readback {actual:08x} != {value:08x}"
            ));
        }
        Ok(())
    }

    async fn worker<T, F>(
        self: &Arc<Self>,
        deadline: Instant,
        terminal_allowed: bool,
        action: F,
    ) -> Result<T, String>
    where
        T: Send + 'static,
        F: FnOnce(&Arc<Self>) -> Result<T, String> + Send + 'static,
    {
        self.check(deadline, terminal_allowed)?;
        {
            let mut state = self
                .workers
                .lock()
                .map_err(|_| "BM1396 worker registry poisoned")?;
            if state.closed {
                return Err("BM1396 worker registry is closed".into());
            }
            state.count = state
                .count
                .checked_add(1)
                .ok_or("BM1396 worker count overflow")?;
        }
        // Count and retained guard exist BEFORE scheduling. A dropped waiter
        // marks terminal but cannot drop mapping or records owned by the worker.
        let guard = WorkerGuard {
            owner: Arc::clone(self),
        };
        let mut waiter = WaiterGuard {
            owner: Arc::clone(self),
            completed: false,
        };
        let handle = tokio::task::spawn_blocking(move || {
            let result = guard
                .owner
                .check(deadline, terminal_allowed)
                .and_then(|_| action(&guard.owner));
            // A detached result can itself retain a pin whose Drop attempts
            // source high. Keep that entire result ahead of the count guard so
            // cancelled-result cleanup finishes before drain can observe zero.
            WorkerOutput { result, guard }
        });
        let WorkerOutput { result, guard } = handle
            .await
            .map_err(|e| format!("BM1396 retained worker: {e}"))?;
        waiter.completed = true;
        if result.is_err() {
            self.begin_terminal();
        }
        // No await follows acceptance: ownership now transfers synchronously
        // to this caller. An abandoned join output drops result before guard.
        drop(guard);
        result
    }

    /// Closes ALL new worker admission and waits for the actual workers. Invoke
    /// explicit terminal controls before this final seal. A timeout is not drain.
    pub async fn drain(self: &Arc<Self>, deadline: Instant) -> Result<(), String> {
        self.begin_terminal();
        self.workers
            .lock()
            .map_err(|_| "BM1396 worker registry poisoned")?
            .closed = true;
        loop {
            self.check(deadline, true)?;
            if self
                .workers
                .lock()
                .map_err(|_| "BM1396 worker registry poisoned")?
                .count
                == 0
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// One complete CRC-framed register-read request. The returned completion
    /// confirms the command portal only; replies remain in the retained FIFO.
    pub async fn request_register(
        self: &Arc<Self>,
        chain: u8,
        chip: Option<u8>,
        register: u8,
        deadline: Instant,
    ) -> Result<(), String> {
        self.chain(chain)?;
        let frame = dcentrald_common::bm1396_contract::bm1396_read_register_frame(
            chip.is_none(),
            chip.unwrap_or(0),
            register,
        );
        self.worker(deadline, false, move |this| {
            let _lane = this.lock(&this.asic, deadline, false)?;
            this.command_locked(chain, &frame, deadline)
        })
        .await
    }

    /// CRC-framed source register-write transport. A completed command is not
    /// proof that a chip applied the setting; population readback is separate.
    pub async fn write_register(
        self: &Arc<Self>,
        chain: u8,
        chip: Option<u8>,
        register: u8,
        value: u32,
        deadline: Instant,
    ) -> Result<(), String> {
        self.chain(chain)?;
        if let Some(address) = chip {
            if address % self.model.address_interval() != 0
                || u16::from(address / self.model.address_interval())
                    >= self.model.expected_chips_per_present_chain()
            {
                return Err(
                    "BM1396 register write chip address is outside exact model topology".into(),
                );
            }
        }
        let frame = dcentrald_common::bm1396_contract::bm1396_write_register_frame(
            chip.is_none(),
            chip.unwrap_or(0),
            register,
            value,
        );
        self.worker(deadline, false, move |this| {
            let _lane = this.lock(&this.asic, deadline, false)?;
            this.command_locked(chain, &frame, deadline)
        })
        .await
    }

    /// Original source BC transport, shared by all future register/setup helpers.
    fn command_locked(&self, chain: u8, frame: &[u8], deadline: Instant) -> Result<(), String> {
        self.command_locked_serviced(chain, frame, deadline, |_| Ok(()))
    }

    fn command_locked_serviced<F>(
        &self,
        chain: u8,
        frame: &[u8],
        deadline: Instant,
        mut service: F,
    ) -> Result<(), String>
    where
        F: FnMut(CommandServicePoint) -> Result<(), String>,
    {
        self.chain(chain)?;
        self.check(deadline, false)?;
        if self.asic_fault.load(Ordering::SeqCst) {
            return Err("BM1396 ASIC portal unresolved".into());
        }
        if frame.is_empty() || frame.len() > 12 {
            return Err("BM1396 invalid command length".into());
        }
        let old = self.hardware.read(BC)?;
        if old & BUSY != 0 {
            self.asic_fault.store(true, Ordering::SeqCst);
            return Err("BM1396 command portal already busy".into());
        }
        service(CommandServicePoint::BeforePublish)?;
        let mut fault = FaultGuard::new(&self.asic_fault, &self.terminal);
        let mut packed = [0u8; 12];
        packed[..frame.len()].copy_from_slice(frame);
        for (index, bytes) in packed.chunks_exact(4).enumerate() {
            let value = u32::from_be_bytes(bytes.try_into().expect("four byte chunk"));
            self.checked_store(0xc4 + index as u32 * 4, value, deadline, false)?;
        }
        let command = (old & !0x000f_0000) | 0x8080_0000 | (u32::from(chain) << 16);
        service(CommandServicePoint::BeforePublish)?;
        self.store(BC, command, deadline, false)?;
        for _ in 0..3001 {
            // This callback is reached only after this owner published BC. It
            // can drain returns while our own command is still legitimately busy.
            service(CommandServicePoint::Poll)?;
            self.check(deadline, false)?;
            if self.hardware.read(BC)? & BUSY == 0 {
                self.check(deadline, false)?;
                fault.complete();
                return Ok(());
            }
            self.delay(Duration::from_millis(1), deadline, false)?;
        }
        Err("BM1396 command completion exhausted 3001 original polls".into())
    }

    /// Startup service under the caller's existing ASIC guard. A query may
    /// already own its receive watermark, so BeforePublish never consumes FIFO.
    /// Only this command's post-publication Poll both drains and permits BUSY.
    pub(super) fn command_and_receive_locked(
        &self,
        state: &mut AsicState,
        chain: u8,
        frame: &[u8],
        deadline: Instant,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<(), String> {
        self.command_locked_serviced(chain, frame, deadline, |point| {
            if matches!(point, CommandServicePoint::Poll) {
                self.receive_locked(state, 128, deadline)?;
            }
            service(state, point)
        })?;
        service(state, CommandServicePoint::IdleReceive)
    }

    /// Commanded RUN clear, not a measured rail cut. Does not wait for a broken
    /// management portal; the single ASIC owner still serializes engine writes.
    pub async fn stop_engine(self: &Arc<Self>, deadline: Instant) -> Result<(), String> {
        self.begin_terminal();
        self.worker(deadline, true, move |this| {
            let _lane = this.lock(&this.asic, deadline, true)?;
            let old = this.hardware.read(DHASH)?;
            this.store(DHASH, old & !RUN, deadline, true)?;
            this.hardware.barrier()?;
            this.check(deadline, true)?;
            if this.hardware.read(DHASH)? & RUN != 0 {
                return Err("BM1396 RUN clear not observed".into());
            }
            this.check(deadline, true)
        })
        .await
    }
}

struct WorkerOutput<T, H: Hardware> {
    result: Result<T, String>,
    guard: WorkerGuard<H>,
}

struct WorkerGuard<H: Hardware> {
    owner: Arc<Transport<H>>,
}
impl<H: Hardware> Drop for WorkerGuard<H> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.owner.begin_terminal();
        }
        if let Ok(mut state) = self.owner.workers.lock() {
            state.count -= 1;
        } else {
            self.owner.begin_terminal();
        }
    }
}
struct WaiterGuard<H: Hardware> {
    owner: Arc<Transport<H>>,
    completed: bool,
}
impl<H: Hardware> Drop for WaiterGuard<H> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.begin_terminal();
        }
    }
}
struct FaultGuard<'a> {
    fault: &'a AtomicBool,
    terminal: &'a AtomicBool,
    complete: bool,
}
impl<'a> FaultGuard<'a> {
    fn new(fault: &'a AtomicBool, terminal: &'a AtomicBool) -> Self {
        Self {
            fault,
            terminal,
            complete: false,
        }
    }
    fn complete(&mut self) {
        self.complete = true;
    }
}
impl Drop for FaultGuard<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.fault.store(true, Ordering::SeqCst);
            self.terminal.store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
#[path = "stock_bm1396_tests.rs"]
mod tests;
