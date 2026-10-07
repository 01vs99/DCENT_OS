//! Platform trait and auto-detection.
//!
//! dcentrald supports multiple control board types through a platform trait.
//! Each platform provides its own implementation of chain access, I2C, fan
//! control, and GPIO. The initial implementation targets Zynq only.
//!
//! Platform auto-detection at startup:
//!   1. Check for UIO devices (/dev/uio0) -> Zynq
//!   2. Check for /dev/ttyO1 -> BeagleBone
//!   3. Check for STM32MP15 / ttySTM* -> Braiins BCB100
//!   Unsupported CV1835 identities refuse before hardware construction.
//!   4. Check for /dev/ttyS1 + Amlogic DTS -> Amlogic

pub mod am2_bm1398;
pub mod am2_controller;
pub mod amlogic;
pub(crate) mod bb_bus0_diagnostic;
pub(crate) mod bb_factory_acquisition;
pub(crate) mod bb_selected_inventory;
pub mod beaglebone;
pub mod beaglebone_cold_boot;
pub mod beaglebone_psu;
pub mod c43_bm1393;
pub mod config;
pub(crate) mod cv1835_retirement;
// R16 held stock fixtures and ABI inventory survive runtime retirement.
// Test-only: the evidence adapter never constructs a hardware owner.
#[cfg(test)]
mod cvitek_stock_evidence;
#[cfg(feature = "sim-hal")]
pub mod sim;
pub mod stm32mp15;
pub mod stock_bm1391;
pub mod stock_bm1396;
pub mod subtype;
pub mod zynq;

use crate::i2c::I2cBus;
use crate::{HalError, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

pub use am2_controller::{
    bind_am2_controller_endpoint_from_observation, bind_am2_hashboard_presence,
    discover_am2_controller_endpoint, discover_system_am2_controller_plan,
    observe_am2_hashboard_presence, try_discover_system_am2_controller_plan, Am2ControllerContext,
    Am2ControllerPlan, Am2HashboardPresence,
};
pub use config::VoltageControllerKind;
pub use subtype::{
    discover_system_pic16_endpoint, discover_system_voltage_controller_endpoint,
    VoltageControllerEndpoint, VoltageControllerEndpointError,
};

/// Control board type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardType {
    /// Zynq 7010 (S9, S17, S19) - FPGA UART FIFOs via UIO.
    Zynq,
    /// BeagleBone AM335x (S19j) - hardware UART /dev/ttyO1-5, no FPGA.
    BeagleBone,
    /// Amlogic A113D (S19XP, S21) - software UART /dev/ttyS1-3, no FPGA.
    Amlogic,
    /// CVITEK CV1835 (S21/T21 recent) - uart_trans kernel module.
    CVitek,
    /// STM32MP15 / Braiins BCB100 replacement board - direct UART, lab-gated.
    Stm32Mp15,
}

/// Abstract chain access interface.
///
/// For Zynq, this is implemented by FpgaChain (UIO mmap + IRQ).
/// For BeagleBone, it would be a UART serial device.
/// For Amlogic, it would be software UART or /dev/ttyS.
pub trait ChainAccess: Send + Sync {
    /// Send a command to the ASIC chain.
    fn send_command(&self, data: &[u8]) -> Result<()>;

    /// Read a response from the ASIC chain.
    fn read_response(&self, buf: &mut [u8]) -> Result<usize>;

    /// Send mining work data to the chain.
    fn send_work(&self, data: &[u8]) -> Result<()>;

    /// Read a nonce response from the chain.
    fn read_nonce(&self, buf: &mut [u8]) -> Result<usize>;

    /// Set the UART baud rate for this chain.
    fn set_baud(&self, baud: u32) -> Result<()>;

    /// Blocking wait for nonce data (IRQ or poll-based).
    fn wait_for_nonce(&self) -> Result<()>;
}

/// Checked fan-command evidence. This proves only that the platform command
/// path completed and its available PWM readback matched; it does not prove
/// airflow or physical fan rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanCommandReceipt {
    pub(crate) requested_pwm: u8,
    pub(crate) observed_pwm: u8,
}

impl FanCommandReceipt {
    /// Build command evidence after a platform implementation has read its
    /// applied PWM back. External platform crates can implement [`FanAccess`]
    /// without gaining a constructor that accepts a mismatch.
    pub fn from_matching_readback(requested_pwm: u8, observed_pwm: u8) -> Result<Self> {
        if requested_pwm != observed_pwm {
            return Err(HalError::Fan(format!(
                "fan PWM readback mismatch: requested {requested_pwm}, observed {observed_pwm}"
            )));
        }
        Ok(Self {
            requested_pwm,
            observed_pwm,
        })
    }

    pub fn requested_pwm(&self) -> u8 {
        self.requested_pwm
    }

    pub fn observed_pwm(&self) -> u8 {
        self.observed_pwm
    }
}

/// Abstract fan access interface.
pub trait FanAccess: Send + Sync {
    /// Set fan speed (PWM value, platform-specific range).
    fn set_speed(&self, pwm: u8);

    /// Set fan speed through a platform-specific fallible command path and
    /// require its available readback. The default is deliberately unavailable:
    /// calling an infallible compatibility setter and then observing an old,
    /// already-equal value cannot prove that the new write completed.
    fn set_speed_checked(&self, _pwm: u8) -> Result<FanCommandReceipt> {
        Err(HalError::Fan(
            "checked fan commands are not implemented for this platform".to_string(),
        ))
    }

    /// Get current fan RPM.
    fn get_rpm(&self) -> u32;

    /// Get current PWM value.
    fn get_speed_pwm(&self) -> u8;

    /// Get per-fan RPM readings. Returns (fan_id, rpm) pairs.
    /// Default: single-fan fallback from get_rpm().
    fn get_per_fan_rpm(&self) -> Vec<(u8, u32)> {
        vec![(0, self.get_rpm())]
    }

    /// Number of physical fan channels.
    fn fan_count(&self) -> u8 {
        1
    }

    /// Whether hardware fan tachometer readings are available.
    /// When false, RPM accessors provide no safety evidence: they may return
    /// zero for compatibility, but the thermal controller must not interpret
    /// that zero as a measured stopped fan. It must rely on temperature
    /// thresholds until fresh tach evidence becomes available.
    fn tach_available(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
enum HardwareMutationGatePhase {
    Pending = 0,
    Open = 1,
    Closed = 2,
}

#[derive(Debug)]
struct HardwareMutationGateState {
    in_flight: usize,
}

#[derive(Debug)]
struct HardwareMutationGateInner {
    /// Atomically couples admission phase and generation so terminal closure
    /// never depends on either mutex. The low two bits encode the phase.
    admission: AtomicU64,
    state: Mutex<HardwareMutationGateState>,
    /// Serializes the final hardware commit of every admitted request against
    /// terminal safe-off. Preparatory work must stay outside this fence.
    commit_fence: Mutex<()>,
}

const HARDWARE_MUTATION_PHASE_BITS: u32 = 2;
const HARDWARE_MUTATION_PHASE_MASK: u64 = (1 << HARDWARE_MUTATION_PHASE_BITS) - 1;
const HARDWARE_MUTATION_MAX_GENERATION: u64 = u64::MAX >> HARDWARE_MUTATION_PHASE_BITS;

fn encode_mutation_admission(phase: HardwareMutationGatePhase, generation: u64) -> u64 {
    (generation << HARDWARE_MUTATION_PHASE_BITS) | phase as u64
}

fn decode_mutation_admission(value: u64) -> (HardwareMutationGatePhase, u64) {
    let phase = match value & HARDWARE_MUTATION_PHASE_MASK {
        0 => HardwareMutationGatePhase::Pending,
        1 => HardwareMutationGatePhase::Open,
        2 => HardwareMutationGatePhase::Closed,
        _ => unreachable!("two-bit hardware mutation phase was invalid"),
    };
    (phase, value >> HARDWARE_MUTATION_PHASE_BITS)
}

/// Shared admission barrier for hardware mutations that can race teardown.
///
/// Every external control-plane mutator holds a lease for the full blocking
/// hardware call. Teardown closes admission and waits for all leases to drain
/// before it observes software safe-off. This makes a checked LOW readback a
/// stable ordering fact instead of a value that an in-flight API handler can
/// immediately invalidate.
#[derive(Clone, Debug)]
pub struct HardwareMutationGate {
    inner: Arc<HardwareMutationGateInner>,
}

impl HardwareMutationGate {
    pub fn new_open() -> Self {
        Self::new(HardwareMutationGatePhase::Open)
    }

    /// Construct a terminally closed gate for management surfaces that must
    /// never admit hardware mutations in this process lifetime.
    ///
    /// Closed admission is irreversible. Because no lease can have been
    /// admitted before construction, [`Self::close_and_drain`] succeeds
    /// immediately and returns the same opaque barrier evidence as a drained
    /// open gate.
    pub fn new_closed() -> Self {
        Self::new(HardwareMutationGatePhase::Closed)
    }

    fn new(phase: HardwareMutationGatePhase) -> Self {
        Self {
            inner: Arc::new(HardwareMutationGateInner {
                admission: AtomicU64::new(encode_mutation_admission(phase, 1)),
                state: Mutex::new(HardwareMutationGateState { in_flight: 0 }),
                commit_fence: Mutex::new(()),
            }),
        }
    }

    pub fn try_acquire(&self) -> Result<HardwareMutationLease> {
        let observed = self.inner.admission.load(Ordering::Acquire);
        match decode_mutation_admission(observed).0 {
            HardwareMutationGatePhase::Open => {}
            HardwareMutationGatePhase::Pending => {
                return Err(HalError::Platform(
                    "hardware mutation admission is pending mining readiness".to_string(),
                ));
            }
            HardwareMutationGatePhase::Closed => {
                return Err(HalError::Platform(
                    "hardware mutation admission is closed for teardown".to_string(),
                ));
            }
        }
        let mut state = match self.inner.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                return Err(HalError::Platform(
                    "hardware mutation admission state is busy; retry the request".to_string(),
                ))
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(HalError::Platform(
                    "hardware mutation gate mutex poisoned".to_string(),
                ))
            }
        };
        let admitted = self.inner.admission.load(Ordering::Acquire);
        let (phase, generation) = decode_mutation_admission(admitted);
        if phase != HardwareMutationGatePhase::Open || admitted != observed {
            return Err(HalError::Platform(
                "hardware mutation admission closed while acquiring a lease".to_string(),
            ));
        }
        state.in_flight = state.in_flight.saturating_add(1);
        drop(state);
        Ok(HardwareMutationLease {
            inner: Arc::clone(&self.inner),
            generation,
        })
    }

    pub fn close_and_drain(&self, timeout: Duration) -> Result<HardwareMutationBarrierReceipt> {
        let started_at = Instant::now();
        let deadline = started_at + timeout;
        self.close_and_drain_before(deadline, Some(timeout))
    }

    /// Irreversibly close admission and drain leases against an already-issued
    /// absolute deadline. Unlike the zero-duration compatibility path above,
    /// an observation at or after this deadline is never positive evidence.
    pub fn close_and_drain_until(
        &self,
        deadline: Instant,
    ) -> Result<HardwareMutationBarrierReceipt> {
        self.close_and_drain_before(deadline, None)
    }

    fn close_and_drain_before(
        &self,
        deadline: Instant,
        relative_timeout: Option<Duration>,
    ) -> Result<HardwareMutationBarrierReceipt> {
        let closed_generation = close_mutation_generation(&self.inner);
        let mut first_probe = true;
        let mut last_in_flight = None;

        loop {
            match self.inner.state.try_lock() {
                Ok(state) => {
                    let observed_at = Instant::now();
                    last_in_flight = Some(state.in_flight);
                    if state.in_flight == 0 {
                        let timely = relative_timeout.map_or(observed_at < deadline, |timeout| {
                            drain_observation_is_timely(timeout, first_probe, observed_at, deadline)
                        });
                        if timely {
                            return Ok(HardwareMutationBarrierReceipt {
                                closed_generation,
                                closed_and_drained_at: observed_at,
                            });
                        }
                        let deadline_description = relative_timeout.map_or_else(
                            || "absolute drain deadline".to_string(),
                            |timeout| format!("{} ms drain deadline", timeout.as_millis()),
                        );
                        return Err(HalError::Platform(format!(
                            "hardware mutation leases became quiescent only at or after the {deadline_description}"
                        )));
                    }
                }
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Poisoned(_)) => {
                    return Err(HalError::Platform(
                        "hardware mutation gate mutex poisoned".to_string(),
                    ))
                }
            }

            first_probe = false;
            let now = Instant::now();
            if now >= deadline {
                let detail = last_in_flight.map_or_else(
                    || "hardware mutation admission state remained busy".to_string(),
                    |count| format!("{count} in-flight hardware mutation(s) remained"),
                );
                let timeout_description = relative_timeout.map_or_else(
                    || "the absolute deadline elapsed".to_string(),
                    |timeout| format!("timed out after {} ms", timeout.as_millis()),
                );
                return Err(HalError::Platform(format!(
                    "{timeout_description} draining hardware mutations: {detail}"
                )));
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(1)),
            );
        }
    }

    /// Irreversibly close mutation admission and return move-only authority to
    /// observe the final software commit section without parking a thread.
    ///
    /// Lease drain and commit-fence quiescence are intentionally independent:
    /// a stale lease may remain in preparatory work after close, yet can no
    /// longer enter [`HardwareMutationLease::commit`]. Callers which require
    /// both facts must retain the separate drain receipt as well.
    pub fn revoke_commit_fence(&self) -> RevokedHardwareMutationCommitFence {
        let closed_generation = close_mutation_generation(&self.inner);
        RevokedHardwareMutationCommitFence {
            inner: Arc::clone(&self.inner),
            closed_generation,
        }
    }
}

fn drain_observation_is_timely(
    timeout: Duration,
    first_probe: bool,
    observed_at: Instant,
    deadline: Instant,
) -> bool {
    observed_at < deadline || (timeout.is_zero() && first_probe)
}

fn close_mutation_generation(inner: &HardwareMutationGateInner) -> u64 {
    let mut observed = inner.admission.load(Ordering::Acquire);
    loop {
        let (phase, generation) = decode_mutation_admission(observed);
        if phase == HardwareMutationGatePhase::Closed {
            return generation;
        }
        let closed_generation = generation
            .saturating_add(1)
            .min(HARDWARE_MUTATION_MAX_GENERATION);
        let closed =
            encode_mutation_admission(HardwareMutationGatePhase::Closed, closed_generation);
        match inner.admission.compare_exchange_weak(
            observed,
            closed,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return closed_generation,
            Err(current) => observed = current,
        }
    }
}

/// Sole capability that can transition a shared hardware-mutation gate from
/// pending to open. API state receives only [`HardwareMutationGate`], so it can
/// acquire leases after admission or close admission, but cannot authorize its
/// own hardware access during engine bring-up.
#[derive(Debug)]
pub struct HardwareMutationGateOwner {
    gate: HardwareMutationGate,
}

impl HardwareMutationGateOwner {
    pub fn new_pending() -> Self {
        let gate = HardwareMutationGate::new(HardwareMutationGatePhase::Pending);
        Self { gate }
    }

    pub fn gate(&self) -> HardwareMutationGate {
        self.gate.clone()
    }

    pub fn open(&self) -> Result<HardwareMutationAdmissionReceipt> {
        let observed = self.gate.inner.admission.load(Ordering::Acquire);
        let (phase, generation) = decode_mutation_admission(observed);
        match phase {
            HardwareMutationGatePhase::Pending => self
                .gate
                .inner
                .admission
                .compare_exchange(
                    observed,
                    encode_mutation_admission(HardwareMutationGatePhase::Open, generation),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map(|_| HardwareMutationAdmissionReceipt {
                    opened_at: Instant::now(),
                })
                .map_err(|current| {
                    let detail = match decode_mutation_admission(current).0 {
                        HardwareMutationGatePhase::Pending => "changed concurrently",
                        HardwareMutationGatePhase::Open => "was already opened",
                        HardwareMutationGatePhase::Closed => "is terminally closed",
                    };
                    HalError::Platform(format!("hardware mutation admission {detail}"))
                }),
            HardwareMutationGatePhase::Open => Err(HalError::Platform(
                "hardware mutation admission was already opened".to_string(),
            )),
            HardwareMutationGatePhase::Closed => Err(HalError::Platform(
                "hardware mutation admission is terminally closed".to_string(),
            )),
        }
    }

    pub fn close_and_drain(&self, timeout: Duration) -> Result<HardwareMutationBarrierReceipt> {
        self.gate.close_and_drain(timeout)
    }

    pub fn close_and_drain_until(
        &self,
        deadline: Instant,
    ) -> Result<HardwareMutationBarrierReceipt> {
        self.gate.close_and_drain_until(deadline)
    }

    pub fn revoke_commit_fence(&self) -> RevokedHardwareMutationCommitFence {
        self.gate.revoke_commit_fence()
    }
}

impl Drop for HardwareMutationGateOwner {
    fn drop(&mut self) {
        // Drop is fail-closed and non-blocking. A failed zero-time drain still
        // leaves admission terminally closed; it simply cannot mint evidence.
        let _ = self.gate.close_and_drain(Duration::ZERO);
    }
}

/// Opaque evidence that the hardware owner transitioned pending admission to
/// open exactly once.
#[derive(Debug)]
pub struct HardwareMutationAdmissionReceipt {
    opened_at: Instant,
}

impl HardwareMutationAdmissionReceipt {
    pub fn opened_at(&self) -> Instant {
        self.opened_at
    }
}

/// RAII proof that one admitted hardware mutation is still in flight.
#[derive(Debug)]
pub struct HardwareMutationLease {
    inner: Arc<HardwareMutationGateInner>,
    generation: u64,
}

impl HardwareMutationLease {
    /// Execute one final physical mutation only while this lease's exact open
    /// generation remains current.
    ///
    /// The closure is serialized against
    /// [`HardwareMutationGate::revoke_commit_fence`]. Long-running
    /// parsing, validation, queueing, or broker preparation belongs before this
    /// call; keep only the final bounded write/readback transaction inside it.
    pub fn commit<T>(&self, mutation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.ensure_current()?;
        let fence = loop {
            self.ensure_current()?;
            match self.inner.commit_fence.try_lock() {
                Ok(fence) => break fence,
                Err(TryLockError::WouldBlock) => std::thread::yield_now(),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(HalError::Platform(
                        "hardware mutation commit fence poisoned".to_string(),
                    ))
                }
            }
        };
        self.ensure_current()?;
        let result = mutation();
        drop(fence);
        result
    }

    fn ensure_current(&self) -> Result<()> {
        let (phase, generation) =
            decode_mutation_admission(self.inner.admission.load(Ordering::Acquire));
        if phase != HardwareMutationGatePhase::Open || generation != self.generation {
            return Err(HalError::Platform(format!(
                "hardware mutation lease generation {} is stale; active generation {} is {:?}",
                self.generation, generation, phase
            )));
        }
        Ok(())
    }
}

impl Drop for HardwareMutationLease {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.in_flight = state.in_flight.saturating_sub(1);
    }
}

/// Opaque evidence that mutation admission is closed and every admitted
/// control-plane mutation has completed.
#[derive(Debug)]
pub struct HardwareMutationBarrierReceipt {
    closed_generation: u64,
    closed_and_drained_at: Instant,
}

impl HardwareMutationBarrierReceipt {
    pub fn closed_generation(&self) -> u64 {
        self.closed_generation
    }

    pub fn closed_and_drained_at(&self) -> Instant {
        self.closed_and_drained_at
    }
}

/// Opaque proof that terminal admission is closed and no earlier final commit
/// can still execute after the caller begins safe-off.
#[derive(Debug)]
pub struct HardwareMutationCommitFenceReceipt {
    closed_generation: u64,
    fenced_at: Instant,
    fence_poisoned: bool,
}

impl HardwareMutationCommitFenceReceipt {
    pub fn closed_generation(&self) -> u64 {
        self.closed_generation
    }

    pub fn fenced_at(&self) -> Instant {
        self.fenced_at
    }

    /// A poisoned fence is quiescent, but the previous mutation may have
    /// unwound after a partial physical side effect. Terminal safe-off remains
    /// mandatory and diagnostics must not present this as a clean commit.
    pub fn fence_poisoned(&self) -> bool {
        self.fence_poisoned
    }
}

/// Move-only authority for one closed hardware-mutation generation.
#[derive(Debug)]
pub struct RevokedHardwareMutationCommitFence {
    inner: Arc<HardwareMutationGateInner>,
    closed_generation: u64,
}

impl RevokedHardwareMutationCommitFence {
    pub fn closed_generation(&self) -> u64 {
        self.closed_generation
    }

    /// Probe commit-section quiescence without blocking an OS thread.
    pub fn try_wait(self) -> HardwareMutationCommitFenceTryWait {
        let fence_poisoned = match self.inner.commit_fence.try_lock() {
            Ok(fence) => {
                drop(fence);
                Some(false)
            }
            Err(TryLockError::WouldBlock) => None,
            Err(TryLockError::Poisoned(error)) => {
                drop(error.into_inner());
                Some(true)
            }
        };
        match fence_poisoned {
            Some(fence_poisoned) => {
                HardwareMutationCommitFenceTryWait::Fenced(HardwareMutationCommitFenceReceipt {
                    closed_generation: self.closed_generation,
                    fenced_at: Instant::now(),
                    fence_poisoned,
                })
            }
            None => HardwareMutationCommitFenceTryWait::Pending(self),
        }
    }
}

#[derive(Debug)]
pub enum HardwareMutationCommitFenceTryWait {
    Pending(RevokedHardwareMutationCommitFence),
    Fenced(HardwareMutationCommitFenceReceipt),
}

#[cfg(test)]
mod hardware_mutation_gate_tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    struct InfallibleCompatibilityFan;

    impl FanAccess for InfallibleCompatibilityFan {
        fn set_speed(&self, _pwm: u8) {}

        fn get_rpm(&self) -> u32 {
            0
        }

        fn get_speed_pwm(&self) -> u8 {
            30
        }
    }

    #[test]
    fn default_checked_fan_path_never_mints_receipt_from_stale_equal_readback() {
        let fan = InfallibleCompatibilityFan;
        assert!(fan.set_speed_checked(30).is_err());
    }

    #[test]
    fn close_rejects_new_mutations_and_waits_for_admitted_lease() {
        let gate = HardwareMutationGate::new_open();
        let lease = gate.try_acquire().unwrap();
        let closer = gate.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            started_tx.send(()).unwrap();
            closer.close_and_drain(Duration::from_secs(1))
        });
        started_rx.recv().unwrap();

        while gate.try_acquire().is_ok() {
            thread::yield_now();
        }
        assert!(!handle.is_finished());
        drop(lease);
        assert!(handle.join().unwrap().is_ok());
        assert!(gate.try_acquire().is_err());
    }

    #[test]
    fn drain_timeout_keeps_admission_closed() {
        let gate = HardwareMutationGate::new_open();
        let lease = gate.try_acquire().unwrap();
        assert!(gate.close_and_drain(Duration::from_millis(1)).is_err());
        assert!(gate.try_acquire().is_err());
        let wrote_after_close = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let wrote_after_close_for_commit = Arc::clone(&wrote_after_close);
        assert!(lease
            .commit(|| {
                wrote_after_close_for_commit.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .is_err());
        assert!(!wrote_after_close.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn terminal_fence_orders_an_entered_commit_before_safe_off_and_rejects_later_commit() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let gate = HardwareMutationGate::new_open();
        let lease = gate.try_acquire().unwrap();
        let hardware_enabled = Arc::new(AtomicBool::new(false));
        let hardware_enabled_for_commit = Arc::clone(&hardware_enabled);
        let (commit_entered_tx, commit_entered_rx) = mpsc::channel();
        let (release_commit_tx, release_commit_rx) = mpsc::channel();
        let (try_late_commit_tx, try_late_commit_rx) = mpsc::channel();
        let (late_result_tx, late_result_rx) = mpsc::channel();
        let commit_thread = thread::spawn(move || {
            lease
                .commit(|| {
                    commit_entered_tx.send(()).unwrap();
                    release_commit_rx.recv().unwrap();
                    hardware_enabled_for_commit.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .unwrap();
            try_late_commit_rx.recv().unwrap();
            let late = lease.commit(|| {
                hardware_enabled_for_commit.store(true, Ordering::SeqCst);
                Ok(())
            });
            late_result_tx.send(late.is_err()).unwrap();
        });
        commit_entered_rx.recv().unwrap();

        let revoked = gate.revoke_commit_fence();
        while gate.try_acquire().is_ok() {
            thread::yield_now();
        }
        let mut pending = match revoked.try_wait() {
            HardwareMutationCommitFenceTryWait::Pending(pending) => pending,
            HardwareMutationCommitFenceTryWait::Fenced(_) => {
                panic!("entered final commit unexpectedly appeared quiescent")
            }
        };

        release_commit_tx.send(()).unwrap();
        let poll_deadline = Instant::now() + Duration::from_secs(1);
        let fence_receipt = loop {
            match pending.try_wait() {
                HardwareMutationCommitFenceTryWait::Fenced(receipt) => break receipt,
                HardwareMutationCommitFenceTryWait::Pending(next) => {
                    assert!(
                        Instant::now() < poll_deadline,
                        "released commit did not become quiescent within one second"
                    );
                    pending = next;
                    thread::sleep(Duration::from_millis(1));
                }
            }
        };
        assert!(fence_receipt.closed_generation() >= 2);
        assert!(fence_receipt.fenced_at() <= Instant::now());
        assert!(!fence_receipt.fence_poisoned());

        // Terminal safe-off happens only after the fence receipt.
        hardware_enabled.store(false, Ordering::SeqCst);
        try_late_commit_tx.send(()).unwrap();
        assert!(late_result_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        commit_thread.join().unwrap();
        assert!(!hardware_enabled.load(Ordering::SeqCst));
    }

    #[test]
    fn revocation_rejects_a_waiting_stale_commit_before_the_entered_commit_returns() {
        let gate = HardwareMutationGate::new_open();
        let entered_lease = gate.try_acquire().unwrap();
        let waiting_lease = gate.try_acquire().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let entered_thread = thread::spawn(move || {
            entered_lease
                .commit(|| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let (waiting_tx, waiting_rx) = mpsc::channel();
        let waiting_thread = thread::spawn(move || {
            waiting_tx.send(()).unwrap();
            waiting_lease.commit(|| Ok(())).is_err()
        });
        waiting_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let revoked = gate.revoke_commit_fence();

        assert!(
            waiting_thread
                .join()
                .expect("waiting commit thread did not panic"),
            "stale commit was not rejected after terminal revocation"
        );
        assert!(matches!(
            revoked.try_wait(),
            HardwareMutationCommitFenceTryWait::Pending(_)
        ));
        release_tx.send(()).unwrap();
        entered_thread.join().unwrap();
    }

    #[test]
    fn panicked_commit_mints_dirty_quiescence_evidence_and_rejects_late_mutation() {
        let gate = HardwareMutationGate::new_open();
        let panicking_lease = gate.try_acquire().unwrap();
        let late_lease = gate.try_acquire().unwrap();

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = panicking_lease.commit(|| -> Result<()> {
                panic!("fixture commit panicked after a possible physical side effect")
            });
        }));
        assert!(panic.is_err());

        let receipt = match gate.revoke_commit_fence().try_wait() {
            HardwareMutationCommitFenceTryWait::Fenced(receipt) => receipt,
            HardwareMutationCommitFenceTryWait::Pending(_) => {
                panic!("unwound commit retained the commit fence")
            }
        };
        assert!(receipt.fence_poisoned());
        assert!(late_lease.commit(|| Ok(())).is_err());
        drop(late_lease);
        drop(panicking_lease);
        assert!(gate.close_and_drain(Duration::ZERO).is_ok());
    }

    #[test]
    fn preparatory_lease_timeout_can_still_prove_commit_fence_quiescence() {
        let gate = HardwareMutationGate::new_open();
        let lease = gate.try_acquire().unwrap();

        assert!(gate.close_and_drain(Duration::from_millis(1)).is_err());
        let receipt = match gate.revoke_commit_fence().try_wait() {
            HardwareMutationCommitFenceTryWait::Fenced(receipt) => receipt,
            HardwareMutationCommitFenceTryWait::Pending(_) => {
                panic!("a lease outside its commit section held the commit fence")
            }
        };
        assert!(!receipt.fence_poisoned());
        assert!(lease.commit(|| Ok(())).is_err());
    }

    #[test]
    fn initially_closed_gate_rejects_leases_and_is_already_drained() {
        let gate = HardwareMutationGate::new_closed();

        assert!(gate.try_acquire().is_err());
        let receipt = gate.close_and_drain(Duration::ZERO).unwrap();
        assert_eq!(receipt.closed_generation(), 1);
        assert!(receipt.closed_and_drained_at() <= Instant::now());
        assert!(gate.try_acquire().is_err());
    }

    #[test]
    fn only_zero_timeout_allows_an_initial_quiescent_observation_at_its_deadline() {
        let deadline = Instant::now();
        assert!(drain_observation_is_timely(
            Duration::ZERO,
            true,
            deadline,
            deadline
        ));
        assert!(!drain_observation_is_timely(
            Duration::from_millis(1),
            true,
            deadline,
            deadline
        ));
        assert!(!drain_observation_is_timely(
            Duration::ZERO,
            false,
            deadline,
            deadline
        ));
    }

    #[test]
    fn absolute_mutation_drain_never_rebases_an_expired_deadline() {
        let owner = HardwareMutationGateOwner::new_pending();
        let gate = owner.gate();
        owner.open().unwrap();
        let expired = Instant::now();

        let error = owner.close_and_drain_until(expired).unwrap_err();

        assert!(error.to_string().contains("absolute drain deadline"));
        assert!(
            gate.try_acquire().is_err(),
            "expired drain must still close admission"
        );
    }

    #[test]
    fn pending_gate_can_only_be_opened_once_by_its_owner() {
        let owner = HardwareMutationGateOwner::new_pending();
        let gate = owner.gate();
        assert!(gate
            .try_acquire()
            .unwrap_err()
            .to_string()
            .contains("pending mining readiness"));

        let receipt = owner.open().unwrap();
        assert!(receipt.opened_at() <= Instant::now());
        let lease = gate.try_acquire().unwrap();
        assert!(owner.open().is_err());
        drop(lease);

        owner.close_and_drain(Duration::ZERO).unwrap();
        assert!(gate.try_acquire().is_err());
        assert!(owner.open().is_err());
    }

    #[test]
    fn dropping_pending_gate_owner_terminally_closes_api_admission() {
        let gate = {
            let owner = HardwareMutationGateOwner::new_pending();
            let gate = owner.gate();
            owner.open().unwrap();
            assert!(gate.try_acquire().is_ok());
            gate
        };

        assert!(gate.try_acquire().is_err());
    }
}

/// Abstract GPIO access interface.
pub trait GpioAccess: Send + Sync {
    /// Read hash board plug detect state.
    fn read_plug_detect(&self) -> [bool; 3];

    /// Assert or release hash board reset.
    fn set_board_reset(&self, chain: u8, assert_reset: bool);
}

/// Platform trait for multi-board support.
///
/// Each supported control board type implements this trait to provide
/// platform-specific hardware access.
pub trait Platform: Send + Sync {
    /// Get the board type.
    fn board_type(&self) -> BoardType;

    /// Get the number of hash board chains this platform supports.
    fn chain_count(&self) -> u8;

    /// Open a chain access interface for the given chain ID.
    fn open_chain(&self, chain_id: u8) -> Result<Box<dyn ChainAccess>>;

    /// Open a legacy mutation-capable I2C bus.
    ///
    /// A platform whose evidence permits discovery reads but not writes must
    /// fail closed here and expose a board-specific opaque read-only
    /// capability instead. Returning [`I2cBus`] inherently exposes raw writes,
    /// compound write-read transactions, timeout changes, and recovery.
    fn open_i2c(&self, bus: u8) -> Result<I2cBus>;

    /// Open the fan controller.
    fn open_fan(&self) -> Result<Box<dyn FanAccess>>;

    /// Open the GPIO controller.
    fn open_gpio(&self) -> Result<Box<dyn GpioAccess>>;

    /// Informational voltage-controller kind in use on this platform.
    ///
    /// The default is deliberately `NoPic`: implementations without exact
    /// hashboard identity must not silently select dsPIC wire bytes. This enum
    /// is compatibility/telemetry data, not service-construction authority.
    ///
    /// W2A.2 (2026-05-09): introduced as part of the PIC1704 wire-up.
    fn voltage_controller(&self) -> VoltageControllerKind {
        VoltageControllerKind::NoPic
    }
}

impl BoardType {
    /// Fail-closed hint for callers without a live `Platform` instance.
    /// Control-board family alone does not identify the attached hashboard or
    /// its controller protocol, so every unproven static default is `NoPic`.
    pub fn voltage_controller_default(&self) -> VoltageControllerKind {
        match self {
            // Even a CV1835 carrier can host different hashboard families.
            BoardType::CVitek => VoltageControllerKind::NoPic,
            // No carrier family alone grants a controller protocol.
            BoardType::Zynq => VoltageControllerKind::NoPic,
            BoardType::BeagleBone => VoltageControllerKind::NoPic,
            BoardType::Amlogic => VoltageControllerKind::NoPic,
            BoardType::Stm32Mp15 => VoltageControllerKind::NoPic,
        }
    }
}

/// Reads the concatenated Device-Tree `compatible` list (NUL-separated) as a
/// lossy UTF-8 string, trying the procfs node first and the sysfs node second.
///
/// Returns an empty string when neither node is readable (host tests, or a
/// platform that exposes no flattened device tree). An empty string yields no
/// SoC opinion, never a refusal — see [`classify_soc_evidence`].
fn read_soc_compatible() -> String {
    for path in [
        "/proc/device-tree/compatible",
        "/sys/firmware/devicetree/base/compatible",
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            if !bytes.is_empty() {
                // `compatible` is a NUL-separated list; flatten to spaces.
                return String::from_utf8_lossy(&bytes).replace('\0', " ");
            }
        }
    }
    String::new()
}

/// Declarative SoC-family evidence: map the `/proc/cpuinfo` `Hardware:` string
/// and the Device-Tree `compatible` list to the [`BoardType`] their silicon
/// implies.
///
/// This is **corroboration only** and is deliberately fail-closed: a SoC we
/// hold no on-disk evidence for returns `None` ("no opinion"), never a guess.
/// Every arm is backed by a real observed string — AM335x `am33xx`/`am335x`
/// (the same discriminator `detect_platform` already keys the BeagleBone
/// tiebreaker on), Amlogic A113D `amlogic`/`a113`, Xilinx `zynq`, and STM32MP15
/// `stm32mp15` (see the fixture tests). CVitek CV1835 has **no** confirmed
/// `cpuinfo`/`compatible` signature held on disk, so it is intentionally absent
/// (returns `None`) rather than invented.
///
/// This ports the one genuinely more-general thing ePIC's `bms-miner` does —
/// read `/proc/cpuinfo Hardware:` on every platform — generalising the
/// pre-existing STM32MP15-only
/// [`stm32mp15::compatible_bytes_look_like_stm32mp15`] check into one shared
/// classifier (queue rank 29 / H1 GAP-6).
pub fn classify_soc_evidence(cpuinfo: &str, compatible: &str) -> Option<BoardType> {
    let hay = format!("{cpuinfo}\n{compatible}").to_ascii_lowercase();
    // Most specific / least ambiguous strings first.
    if hay.contains("stm32mp15") {
        return Some(BoardType::Stm32Mp15);
    }
    if hay.contains("am33xx") || hay.contains("am335x") {
        return Some(BoardType::BeagleBone);
    }
    if hay.contains("amlogic") || hay.contains("a113") {
        return Some(BoardType::Amlogic);
    }
    if hay.contains("zynq") {
        return Some(BoardType::Zynq);
    }
    None
}

/// Advisory cross-check: given the [`BoardType`] chosen by hardware-signature
/// detection, return `Some(observed)` when the SoC evidence names a *different*
/// family, else `None`.
///
/// Strictly advisory. `detect_platform` only **logs** on `Some(_)` and never
/// refuses on it, so a unit whose live DTB/cpuinfo string differs from what we
/// hold on disk (classifier returns `None`) is still admitted on its
/// device-node signature. Absent evidence can never manufacture a contradiction.
pub fn soc_evidence_contradiction(
    selected: BoardType,
    cpuinfo: &str,
    compatible: &str,
) -> Option<BoardType> {
    match classify_soc_evidence(cpuinfo, compatible) {
        Some(observed) if observed != selected => Some(observed),
        _ => None,
    }
}

/// Emit a loud, non-fatal warning when the SoC evidence contradicts the
/// hardware-signature detection. Instrument, never gate — the platform the
/// hardware signatures selected is always the one returned.
fn warn_if_soc_contradicts(selected: BoardType, cpuinfo: &str, compatible: &str) {
    if let Some(observed) = soc_evidence_contradiction(selected, cpuinfo, compatible) {
        tracing::warn!(
            selected = ?selected,
            soc_evidence = ?observed,
            "platform hardware-signature detection disagrees with SoC evidence; \
             proceeding on the hardware signature (SoC evidence is advisory only)"
        );
    }
}

/// Attach the advisory SoC cross-check to a freshly detected platform, then
/// return it unchanged. Centralises the warn so every detection branch shares
/// one instrumentation point via the platform's own [`Platform::board_type`].
fn finalize_detection(
    platform: Box<dyn Platform>,
    cpuinfo: &str,
    compatible: &str,
) -> Result<Box<dyn Platform>> {
    warn_if_soc_contradicts(platform.board_type(), cpuinfo, compatible);
    Ok(platform)
}

/// Auto-detect the current platform.
///
/// Checks hardware signatures to determine which control board we're running on.
/// For Zynq boards, further distinguishes S9 (am1-s9) vs S19 (am2-s17) via UIO
/// device naming patterns — see `zynq::detect_zynq_variant()`.
///
/// After the hardware signatures select a platform, the SoC evidence
/// (`/proc/cpuinfo Hardware:` + Device-Tree `compatible`) is attached as an
/// advisory cross-check via [`finalize_detection`] — it logs a warning on a
/// family mismatch but never changes or refuses the selection.
///
/// Detection order matters when multiple signatures coexist (e.g. stock Bitmain
/// BB has both `/dev/ttyO1` AND `/sys/module/uart_trans` loaded — BB must win
/// because uart_trans is just a wrapper layered on top of the same omap-serial
/// ttyOX devices). The AM33XX CPU string is the BB tiebreaker over CVitek
/// (different SoC entirely).
pub fn detect_platform() -> Result<Box<dyn Platform>> {
    // Simulation is considered before hardware auto-detection only when at
    // least one simulation variable is explicitly present. A partial or
    // malformed request fails closed instead of falling through to a real
    // platform. `SimPlatform::from_env` also refuses every known miner
    // hardware signature, even in a binary accidentally built with sim-hal.
    #[cfg(feature = "sim-hal")]
    if sim::sim_environment_is_mentioned() {
        return Ok(Box::new(sim::SimPlatform::from_env()?));
    }

    // SoC evidence is read once up front (the procfs `Hardware:` string plus
    // the Device-Tree `compatible` list) and attached as an advisory
    // cross-check to whichever platform the hardware signatures select below.
    // It never gates detection — see `finalize_detection`/`warn_if_soc_contradicts`.
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let compatible = read_soc_compatible();
    let model = std::fs::read_to_string("/proc/device-tree/model").unwrap_or_default();
    cv1835_retirement::require_supported_controller(
        &cpuinfo,
        &compatible,
        &model,
        std::path::Path::new("/sys/module/uart_trans").exists(),
        cv1835_retirement::cv1835_child_identity(std::path::Path::new(
            "/sys/firmware/devicetree/base",
        )),
    )?;

    // 1. Zynq — UIO devices (covers both S9 and S19/am2-s17)
    if std::path::Path::new("/dev/uio0").exists() {
        return finalize_detection(Box::new(zynq::ZynqPlatform::new()?), &cpuinfo, &compatible);
    }

    // 2. BeagleBone — TI AM335x SoC + a chain-0 UART node.
    //    Stock Bitmain BB also loads uart_trans.ko (which proxies the same
    //    ttyOX devices), so check BB BEFORE the uart_trans-based CVitek path.
    //    The `/proc/cpuinfo` "AM33XX" hardware string is the authoritative
    //    SoC tiebreaker — it is present ONLY on AM335x (a real Amlogic A113D
    //    is aarch64 and never reports AM33XX), so an AM335x match cannot
    //    false-positive onto the Amlogic branch below.
    //
    //    Chain-0 UART naming differs by kernel: stock Bitmain BB exposes
    //    `/dev/ttyO1` (legacy omap-serial naming), while LuxOS / DCENT_OS on
    //    the `a lab unit`-class S19J_IO_BOARD_V2_0 unit exposes `/dev/ttyS1`
    //    (mainline omap-serial). `BeagleBonePlatform::new()` already accepts
    //    EITHER node; this detection gate must accept both too, otherwise a
    //    `a lab unit`-class LuxOS/DCENT_OS BB (ttyS1, no ttyO1) skips the BB branch
    //    and falls through to the Amlogic `/dev/ttyS1` branch — constructing
    //    the wrong (aarch64 Amlogic) HAL on an armv7 AM335x board.
    let is_am335x =
        cpuinfo.contains("AM33XX") || cpuinfo.contains("AM335x") || cpuinfo.contains("am33xx");
    if is_am335x
        && (std::path::Path::new("/dev/ttyO1").exists()
            || std::path::Path::new("/dev/ttyS1").exists())
    {
        return finalize_detection(
            Box::new(beaglebone::BeagleBonePlatform::new()?),
            &cpuinfo,
            &compatible,
        );
    }

    // 3. Braiins BCB100 / STM32MP15. The constructor is lab-gated until
    // the GPIO, fan, PSU, and PIC maps are live-verified.
    if stm32mp15::looks_like_bcb100_host() {
        return finalize_detection(
            Box::new(stm32mp15::Bcb100Platform::new()?),
            &cpuinfo,
            &compatible,
        );
    }

    // 4. Amlogic UART. Unsupported/unknown uart_trans identities were refused
    // before any constructor above; module presence alone never chooses a SoC.
    if classify_soc_evidence(&cpuinfo, &compatible) == Some(BoardType::Amlogic)
        && ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]
            .iter()
            .any(|path| std::path::Path::new(path).exists())
    {
        return finalize_detection(
            Box::new(amlogic::AmlogicPlatform::new()?),
            &cpuinfo,
            &compatible,
        );
    }

    Err(HalError::Platform(
        "unable to detect platform: no known hardware signatures found".to_string(),
    ))
}

#[cfg(test)]
mod soc_evidence_tests {
    use super::*;

    #[test]
    fn classifier_maps_every_evidenced_soc_string() {
        // AM335x (BeagleBone) — the same discriminator detect_platform keys the
        // BeagleBone tiebreaker on.
        assert_eq!(
            classify_soc_evidence("Hardware\t: Generic AM33XX (Flattened Device Tree)", ""),
            Some(BoardType::BeagleBone)
        );
        // Amlogic A113D — from the held restore-to-stock cpuinfo fixtures.
        assert_eq!(
            classify_soc_evidence("Hardware\t: Amlogic A113D", ""),
            Some(BoardType::Amlogic)
        );
        // Xilinx Zynq — from the held Zynq cpuinfo fixtures.
        assert_eq!(
            classify_soc_evidence("Hardware\t: Xilinx Zynq Platform", ""),
            Some(BoardType::Zynq)
        );
        // STM32MP15 — via the Device-Tree `compatible` list (procfs empty).
        assert_eq!(
            classify_soc_evidence("", "st,stm32mp157c-ii1 st,stm32mp157"),
            Some(BoardType::Stm32Mp15)
        );
    }

    #[test]
    fn classifier_returns_none_for_unheld_or_unknown_soc() {
        // CVitek CV1835 has no held cpuinfo/compatible signature -> no guess.
        assert_eq!(classify_soc_evidence("Hardware\t: cvitek", ""), None);
        // Empty / unreadable -> no opinion (host tests, or no flattened DT).
        assert_eq!(classify_soc_evidence("", ""), None);
        // A completely unknown SoC -> no opinion, never a wrong guess.
        assert_eq!(
            classify_soc_evidence("Hardware\t: Raspberry Pi 4", ""),
            None
        );
    }

    #[test]
    fn contradiction_never_fires_without_positive_evidence() {
        // No SoC evidence -> never contradicts, so a unit whose live DTB/cpuinfo
        // differs from what we hold on disk is never refused.
        assert_eq!(soc_evidence_contradiction(BoardType::Amlogic, "", ""), None);
        assert_eq!(soc_evidence_contradiction(BoardType::Zynq, "", ""), None);
        // Matching evidence -> no contradiction.
        assert_eq!(
            soc_evidence_contradiction(BoardType::Amlogic, "Hardware\t: Amlogic A113D", ""),
            None
        );
    }

    #[test]
    fn contradiction_flags_a_genuine_soc_mismatch() {
        // Selected Amlogic but the silicon reports Xilinx Zynq -> flagged
        // (warn-only; the selection is still returned by detect_platform).
        assert_eq!(
            soc_evidence_contradiction(BoardType::Amlogic, "Hardware\t: Xilinx Zynq Platform", ""),
            Some(BoardType::Zynq)
        );
    }
}
