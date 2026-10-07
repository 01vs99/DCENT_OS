// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) D-Central Technologies — https://d-central.tech

//! Fail-closed ownership for the Linux hardware watchdog.
//!
//! A watchdog file descriptor is a safety resource, not a background timer.
//! This module owns its worker thread, requires an observed arm admission
//! before an engine may energize hardware, and makes magic-close reachable
//! only from an admitted teardown carrying engine-issued shutdown evidence.
//! Dropping the owner, losing the command channel, missing a deadline, or
//! suppressing feeds never writes the magic-close byte.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use dcentrald_hal::watchdog::Watchdog;

mod c43;
pub(crate) use c43::C43WatchdogShutdownManifest;
mod bm1391;
pub(crate) use bm1391::{Bm1391ActorSlot, Bm1391Actors, Bm1391WatchdogShutdownManifest};
mod bm1396;
pub(crate) use bm1396::{Bm1396ActorSlot, Bm1396Actors, Bm1396WatchdogShutdownManifest};
mod classic_aml;
pub(crate) use classic_aml::{
    ClassicAmlActorSlot, ClassicAmlActors, ClassicAmlWatchdogRouteScope,
    ClassicAmlWatchdogShutdownManifest,
};

use crate::config::WatchdogConfig;
use crate::runtime::task_guard::StandardMiningActorQuiescenceReceipt;
use crate::runtime::teardown_budget::{
    issue_teardown_budget_authority, TeardownBudget, TeardownBudgetExpectation,
    TeardownBudgetIssuer, TeardownBudgetPolicy, TeardownBudgetView, TeardownDisarmAuthority,
    TeardownStage, TeardownStart,
};
use crate::runtime::thread_guard::{
    issue_thread_roster, join_thread_bounded, join_thread_until, FixedThreadSlot,
    ThreadRosterExpectation, ThreadRosterOwner, ThreadRosterQuiescenceReceipt,
    ThreadSlotDeclaration, ThreadStopOutcome, ThreadStopSummary,
};
use crate::runtime::watchdog_feed_gate::{
    WatchdogFeedGate, WatchdogFeedGateOwner, WatchdogFeedOutcome, WatchdogFeedStopSignal,
};

const WATCHDOG_ADMISSION_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const DEFAULT_WATCHDOG_STOP_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const DEFAULT_WATCHDOG_TEARDOWN_GRACE: Duration = Duration::from_secs(30);

/// The kicker period must remain non-zero even if validation was bypassed.
pub(crate) fn watchdog_interval_secs(kick_interval_s: u64) -> u64 {
    kick_interval_s.max(1)
}

pub(crate) fn watchdog_teardown_kick_allowed(deadline: Instant, now: Instant) -> bool {
    now < deadline
}

pub(crate) fn watchdog_stall_limit(
    effective_timeout_s: u64,
    kick_secs: u64,
    expected_liveness_interval: Option<Duration>,
) -> u64 {
    let kick_secs = kick_secs.max(1);
    let half_window_limit = ((effective_timeout_s / 2) / kick_secs).max(2);
    let cadence_limit = expected_liveness_interval
        .map(|interval| {
            ((interval.as_secs_f64() / kick_secs as f64).ceil() as u64).saturating_add(2)
        })
        .unwrap_or(0);
    half_window_limit.max(cadence_limit)
}

/// Pure mining-liveness decision. The caller must latch the first `false`
/// result terminally; a late counter advance must never cancel a reset that
/// safety policy has already requested.
pub(crate) fn watchdog_kick_decision(
    current: u64,
    last_live: u64,
    stalls: u64,
    stall_limit: u64,
) -> (bool, u64, u64) {
    if current == last_live {
        let stalls = stalls.saturating_add(1);
        (stalls < stall_limit, last_live, stalls)
    } else {
        (true, current, 0)
    }
}

/// Opaque safety-progress clock. Mining engines mark progress only after the
/// safety-critical loop (for example thermal sensing plus fan actuation) has
/// completed one iteration.
#[derive(Clone, Default)]
pub(crate) struct SafetyLiveness(Arc<AtomicU64>);

impl SafetyLiveness {
    pub(crate) fn mark_progress(&self) {
        self.0.fetch_add(1, Ordering::Release);
    }

    fn snapshot(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WatchdogArmReceipt {
    pub(crate) requested_timeout_s: u32,
    pub(crate) effective_timeout_s: u32,
    pub(crate) kick_interval_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WatchdogAdmission {
    Armed(WatchdogArmReceipt),
    DisabledByConfiguration,
    UnavailableBeforeOpen { reason: String },
    OpenedOrOutcomeUnknown { reason: String },
}

/// Marker preserved in the anyhow source chain whenever the descriptor may
/// have opened but arming was not positively admitted. Callers must terminate
/// into watchdog reset; they may not claim a stable management-only state.
#[derive(Debug)]
pub(crate) struct WatchdogResetPendingError {
    engine: &'static str,
    reason: String,
}

impl std::fmt::Display for WatchdogResetPendingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} watchdog descriptor was opened or is outcome-unknown; reset pending: {}",
            self.engine, self.reason
        )
    }
}

impl std::error::Error for WatchdogResetPendingError {}

pub(crate) fn is_watchdog_reset_pending(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<WatchdogResetPendingError>())
}

/// Preserve reset-pending disposition for failures that occur after an armed
/// owner exists but outside the initial admission state machine.
pub(crate) fn watchdog_reset_pending_error(
    engine: &'static str,
    reason: impl Into<String>,
) -> anyhow::Error {
    anyhow::Error::new(WatchdogResetPendingError {
        engine,
        reason: reason.into(),
    })
}

/// The only error channel from `start_before_energizing`. Construction errors
/// are restricted to validation or worker-spawn failure before the worker can
/// call the watchdog factory. Once the worker exists, every outcome is returned
/// as a `WatchdogAdmission`, preserving descriptor-open state explicitly.
#[derive(Debug)]
pub(crate) struct WatchdogPreOpenStartError(anyhow::Error);

impl std::fmt::Display for WatchdogPreOpenStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:#}", self.0)
    }
}

impl std::error::Error for WatchdogPreOpenStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl WatchdogAdmission {
    pub(crate) fn require_armed(self, engine: &'static str) -> Result<WatchdogArmReceipt> {
        match self {
            Self::Armed(receipt) => Ok(receipt),
            Self::DisabledByConfiguration => anyhow::bail!(
                "{engine} requires an armed SoC watchdog before energizing hardware; watchdog is disabled by configuration"
            ),
            Self::UnavailableBeforeOpen { reason } => anyhow::bail!(
                "{engine} requires an armed SoC watchdog before energizing hardware: {reason}"
            ),
            Self::OpenedOrOutcomeUnknown { reason } => {
                Err(anyhow::Error::new(WatchdogResetPendingError { engine, reason }))
            }
        }
    }
}

mod evidence_sealed {
    pub trait Sealed {}
}

/// Owner-issued proof that every registered hardware-mutating actor has
/// terminated. Implementations are centrally sealed receipt types, never
/// engine-provided booleans.
pub(crate) trait ActorQuiescenceEvidence: evidence_sealed::Sealed {
    fn all_hardware_actors_quiesced(&self) -> bool;
}

/// Owner-issued proof that new hardware mutations are rejected and every
/// previously admitted mutation has completed.
pub(crate) trait MutationBarrierEvidence: evidence_sealed::Sealed {
    fn hardware_mutations_closed_and_drained(&self) -> bool;
}

/// HAL-issued proof that its software safe-off command and required
/// readback completed. This is command/readback evidence, not physical rail
/// measurement.
pub(crate) trait SoftwareSafeOffEvidence: evidence_sealed::Sealed {
    fn software_safe_off_completed(&self) -> bool;
}

impl evidence_sealed::Sealed for ThreadStopSummary {}

impl ActorQuiescenceEvidence for ThreadStopSummary {
    fn all_hardware_actors_quiesced(&self) -> bool {
        !self.is_empty() && !self.any_timed_out()
    }
}

impl evidence_sealed::Sealed for dcentrald_hal::platform::HardwareMutationBarrierReceipt {}

impl MutationBarrierEvidence for dcentrald_hal::platform::HardwareMutationBarrierReceipt {
    fn hardware_mutations_closed_and_drained(&self) -> bool {
        true
    }
}

impl evidence_sealed::Sealed for dcentrald_hal::platform::HardwareMutationCommitFenceReceipt {}

impl MutationBarrierEvidence for dcentrald_hal::platform::HardwareMutationCommitFenceReceipt {
    fn hardware_mutations_closed_and_drained(&self) -> bool {
        !self.fence_poisoned()
    }
}

impl evidence_sealed::Sealed for dcentrald_hal::i2c::TerminalSafeOffTransition {}

impl MutationBarrierEvidence for dcentrald_hal::i2c::TerminalSafeOffTransition {
    fn hardware_mutations_closed_and_drained(&self) -> bool {
        self.no_controller_mutation_stage_in_flight()
    }
}

impl evidence_sealed::Sealed for dcentrald_hal::i2c::I2cServiceCloseReceipt {}

impl MutationBarrierEvidence for dcentrald_hal::i2c::I2cServiceCloseReceipt {
    fn hardware_mutations_closed_and_drained(&self) -> bool {
        self.terminal_transition()
            .no_controller_mutation_stage_in_flight()
    }
}

impl evidence_sealed::Sealed for crate::serial_mining::SerialExecutionBarrierReceipt {}

impl MutationBarrierEvidence for crate::serial_mining::SerialExecutionBarrierReceipt {
    fn hardware_mutations_closed_and_drained(&self) -> bool {
        true
    }
}

impl evidence_sealed::Sealed for crate::serial_mining::SerialExecutionDomainCloseout {}

impl MutationBarrierEvidence for crate::serial_mining::SerialExecutionDomainCloseout {
    fn hardware_mutations_closed_and_drained(&self) -> bool {
        self.is_complete()
    }
}

impl evidence_sealed::Sealed for crate::serial_mining::ApiMutationDomainCloseout {}

impl MutationBarrierEvidence for crate::serial_mining::ApiMutationDomainCloseout {
    fn hardware_mutations_closed_and_drained(&self) -> bool {
        self.is_complete()
    }
}

impl evidence_sealed::Sealed for dcentrald_hal::platform::amlogic::PsuSafeOffReceipt {}

impl SoftwareSafeOffEvidence for dcentrald_hal::platform::amlogic::PsuSafeOffReceipt {
    fn software_safe_off_completed(&self) -> bool {
        true
    }
}

impl evidence_sealed::Sealed for crate::am3_bb_mining::Am3BbSafeOffReceipt {}

impl SoftwareSafeOffEvidence for crate::am3_bb_mining::Am3BbSafeOffReceipt {
    fn software_safe_off_completed(&self) -> bool {
        true
    }
}

impl evidence_sealed::Sealed for crate::s19j_hybrid_mining::Am2TerminalSafeOffEvidence {}

impl SoftwareSafeOffEvidence for crate::s19j_hybrid_mining::Am2TerminalSafeOffEvidence {
    fn software_safe_off_completed(&self) -> bool {
        self.completed_gracefully()
    }
}

impl evidence_sealed::Sealed for crate::serial_mining::Am2SerialSafeOffReceipt {}

impl SoftwareSafeOffEvidence for crate::serial_mining::Am2SerialSafeOffReceipt {
    fn software_safe_off_completed(&self) -> bool {
        self.software_safe_off_completed()
    }
}

/// Private-construction capability required for magic-close.
pub(crate) struct WatchdogDisarmPermit {
    scope: WatchdogRunScope,
    composition: WatchdogComposition,
    teardown: WatchdogTeardownAuthority,
}

enum WatchdogTeardownAuthority {
    /// Test-only relative authority keeps generic validator-negative tests
    /// independent of the production route manifests. No production permit can
    /// bypass the watchdog-issued absolute schedule.
    #[cfg(test)]
    TestRelative,
    Absolute(TeardownDisarmAuthority),
}

/// Exact hardware composition bound to one watchdog owner before any route can
/// mint terminal Disarm authority. A valid permit must match both this tag and
/// the run's pointer identity; same-run evidence from another route is not
/// interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchdogComposition {
    ClassicAml,
    C43Native,
    Bm1391Native,
    Bm1396Native,
    NoPicSerial,
    S19kTrack1Serial,
    Am2Bm1362Serial,
    HybridAm2,
    S17Hybrid,
    Bm1398Native,
    Am3Bb,
    #[cfg(test)]
    TestOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SerialWatchdogComposition {
    NoPic,
    S19kTrack1,
    Am2Bm1362,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoPicSerialThreadSlot {
    SerialIo,
    Track1SafetySampler,
}

impl FixedThreadSlot for NoPicSerialThreadSlot {
    fn name(self) -> &'static str {
        match self {
            Self::SerialIo => "s19j-serial-io",
            Self::Track1SafetySampler => "s19k-track1-safety",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Am2SerialThreadSlot {
    ApwHeartbeat,
    DspicHeartbeat,
    SerialIo,
}

impl FixedThreadSlot for Am2SerialThreadSlot {
    fn name(self) -> &'static str {
        match self {
            Self::ApwHeartbeat => "s19j-serial-psu-hb",
            Self::DspicHeartbeat => "s19j-pic-hb",
            Self::SerialIo => "s19j-serial-io",
        }
    }
}

/// Watchdog-issued route/actor trust root consumed by the exact serial-domain
/// owner. The expectation half never leaves that owner; only the move-only
/// actor half can activate the corresponding fixed roster.
pub(crate) enum SerialWatchdogRouteAdmission {
    NoPic {
        scope: WatchdogRunScope,
        actor_owner: ThreadRosterOwner<NoPicSerialThreadSlot>,
        actor_expectation: ThreadRosterExpectation<NoPicSerialThreadSlot>,
    },
    S19kTrack1 {
        scope: WatchdogRunScope,
        actor_owner: ThreadRosterOwner<NoPicSerialThreadSlot>,
        actor_expectation: ThreadRosterExpectation<NoPicSerialThreadSlot>,
    },
    Am2Bm1362 {
        scope: WatchdogRunScope,
        actor_owner: ThreadRosterOwner<Am2SerialThreadSlot>,
        actor_expectation: ThreadRosterExpectation<Am2SerialThreadSlot>,
    },
}

impl SerialWatchdogRouteAdmission {
    pub(crate) fn into_nopic_parts(
        self,
    ) -> Result<(
        WatchdogRunScope,
        ThreadRosterOwner<NoPicSerialThreadSlot>,
        ThreadRosterExpectation<NoPicSerialThreadSlot>,
    )> {
        match self {
            Self::NoPic {
                scope,
                actor_owner,
                actor_expectation,
            } => Ok((scope, actor_owner, actor_expectation)),
            Self::S19kTrack1 { .. } => {
                anyhow::bail!("S19k Track-1 watchdog admission requires its exact consumer")
            }
            Self::Am2Bm1362 { .. } => {
                anyhow::bail!("AM2 serial watchdog admission cannot authorize NoPic actors")
            }
        }
    }

    pub(crate) fn into_s19k_track1_parts(
        self,
    ) -> Result<(
        WatchdogRunScope,
        ThreadRosterOwner<NoPicSerialThreadSlot>,
        ThreadRosterExpectation<NoPicSerialThreadSlot>,
    )> {
        match self {
            Self::S19kTrack1 {
                scope,
                actor_owner,
                actor_expectation,
            } => Ok((scope, actor_owner, actor_expectation)),
            Self::NoPic { .. } | Self::Am2Bm1362 { .. } => {
                anyhow::bail!("non-Track-1 watchdog admission cannot authorize S19k actors")
            }
        }
    }

    pub(crate) fn into_am2_parts(
        self,
    ) -> Result<(
        WatchdogRunScope,
        ThreadRosterOwner<Am2SerialThreadSlot>,
        ThreadRosterExpectation<Am2SerialThreadSlot>,
    )> {
        match self {
            Self::Am2Bm1362 {
                scope,
                actor_owner,
                actor_expectation,
            } => Ok((scope, actor_owner, actor_expectation)),
            Self::NoPic { .. } | Self::S19kTrack1 { .. } => {
                anyhow::bail!("NoPic serial watchdog admission cannot authorize AM2 actors")
            }
        }
    }
}

/// Move-only composition scope issued only when an owner binds itself to the
/// hybrid route. The raw run scope is deliberately not exposed to callers.
pub(crate) struct HybridWatchdogRouteScope {
    scope: WatchdogRunScope,
    actor_owner: Option<ThreadRosterOwner<HybridThreadSlot>>,
    actor_expectation: ThreadRosterExpectation<HybridThreadSlot>,
}

/// S17 uses one serialized hardware lifecycle, including PIC keepalive and
/// temperature reads. It has no S19j heartbeat-thread roster to manufacture.
pub(crate) struct S17WatchdogRouteScope {
    scope: WatchdogRunScope,
}

/// NBP1901 has one retained I2C fabric for its PIC, PSU and temperature
/// operations. Its shutdown evidence cannot disarm another AM2 composition.
pub(crate) struct Bm1398WatchdogRouteScope {
    scope: WatchdogRunScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HybridThreadSlot {
    PsuHeartbeat,
    PicHeartbeat,
}

impl FixedThreadSlot for HybridThreadSlot {
    fn name(self) -> &'static str {
        match self {
            Self::PsuHeartbeat => "s19j-psu-heartbeat",
            Self::PicHeartbeat => "s19j-pic-heartbeat",
        }
    }
}

impl HybridWatchdogRouteScope {
    pub(crate) fn take_actor_owner(&mut self) -> Result<ThreadRosterOwner<HybridThreadSlot>> {
        self.actor_owner
            .take()
            .context("hybrid watchdog actor owner was already consumed")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Am3BbThreadSlot {
    DspicHeartbeat,
}

impl FixedThreadSlot for Am3BbThreadSlot {
    fn name(self) -> &'static str {
        match self {
            Self::DspicHeartbeat => "am3-bb-dspic-heartbeat",
        }
    }
}

/// Move-only composition scope issued only when an owner binds itself to the
/// AM3-BB route. The raw run scope is deliberately not exposed to callers.
pub(crate) struct Am3BbWatchdogRouteScope {
    scope: WatchdogRunScope,
    actor_owner: Option<ThreadRosterOwner<Am3BbThreadSlot>>,
    actor_expectation: ThreadRosterExpectation<Am3BbThreadSlot>,
}

impl Am3BbWatchdogRouteScope {
    pub(crate) fn take_actor_owner(&mut self) -> Result<ThreadRosterOwner<Am3BbThreadSlot>> {
        self.actor_owner
            .take()
            .context("AM3-BB watchdog actor owner was already consumed")
    }
}

/// Per-run identity shared only by one watchdog owner and its exact route
/// shutdown manifest. Pointer identity avoids another numeric generation and
/// makes cross-run substitution fail closed.
#[derive(Debug, Clone)]
pub(crate) struct WatchdogRunScope(Arc<()>);

impl WatchdogRunScope {
    pub(crate) fn new() -> Self {
        Self(Arc::new(()))
    }

    pub(crate) fn same_run(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// Opaque, one-shot proof that this exact AM3-BB watchdog run has not crossed
/// the first outcome-unknown GPIO59 HIGH attempt. Only the watchdog owner can
/// construct or inspect it; the engine may solely move or destroy it.
pub(crate) struct Am3BbNeverEnergized {
    run_scope: WatchdogRunScope,
}

/// Opaque, one-shot proof that this exact AM2 BM1362 watchdog run has not
/// crossed the first outcome-unknown PWR_CONTROL assertion. Construction and
/// inspection stay beside the watchdog owner; the serial engine may only move
/// or destroy the token at its physical energization boundary.
pub(crate) struct Am2NeverEnergized {
    run_scope: WatchdogRunScope,
}

/// Opaque, one-shot proof that this exact S19k Track-1 watchdog run has not
/// claimed a hardware route or crossed the stock-process handoff boundary.
///
/// Track-1 inherits rails that stock bosminer already owns, so calling this
/// evidence "never energized" would be false.  It authorizes magic-close only
/// while the watchdog composition is still unclaimed; a route claim destroys
/// the pre-handoff condition even if no GPIO write has occurred yet.
pub(crate) struct S19kTrack1NeverHandoff {
    run_scope: WatchdogRunScope,
}

/// Move-only issuer half of the standard mining-actor trust root. The task
/// guard can consume this identity but cannot create a matching watchdog
/// expectation for itself.
pub(crate) struct StandardMiningActorIssuer(Arc<()>);

/// Watchdog-retained half of one standard mining-actor trust root.
#[derive(Clone)]
pub(crate) struct StandardMiningActorExpectation(Arc<()>);

/// Move-only issuer half of the standard daemon's non-actor closeout trust
/// root. The daemon splits this identity across its PSU-feeder, controller
/// heartbeat, and software-safe-off owners; it cannot create the watchdog's
/// matching expectation.
pub(crate) struct StandardUnitCloseoutIssuer(Arc<()>);

/// Watchdog-retained half of one standard-daemon unit-closeout trust root.
#[derive(Clone)]
pub(crate) struct StandardUnitCloseoutExpectation(Arc<()>);

impl StandardMiningActorIssuer {
    pub(crate) fn into_identity(self) -> Arc<()> {
        self.0
    }
}

impl StandardMiningActorExpectation {
    pub(crate) fn matches_identity(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.0, identity)
    }
}

impl StandardUnitCloseoutIssuer {
    pub(crate) fn into_identity(self) -> Arc<()> {
        self.0
    }
}

impl StandardUnitCloseoutExpectation {
    pub(crate) fn matches_identity(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.0, identity)
    }
}

/// Single issuance point for the standard watchdog run and its actor roster.
/// The guard receives only the move-only issuer; the expectation is moved into
/// the watchdog worker before it opens the device.
pub(crate) struct StandardWatchdogRunAdmission {
    scope: WatchdogRunScope,
    actor_issuer: StandardMiningActorIssuer,
    actor_expectation: StandardMiningActorExpectation,
    unit_closeout_issuer: StandardUnitCloseoutIssuer,
    unit_closeout_expectation: StandardUnitCloseoutExpectation,
    teardown_budget_issuer: TeardownBudgetIssuer,
    teardown_budget_expectation: TeardownBudgetExpectation,
}

impl StandardWatchdogRunAdmission {
    pub(crate) fn new() -> Self {
        Self::for_scope(WatchdogRunScope::new())
    }

    fn for_scope(scope: WatchdogRunScope) -> Self {
        let actor_identity = Arc::new(());
        let unit_closeout_identity = Arc::new(());
        let (teardown_budget_issuer, teardown_budget_expectation) =
            issue_teardown_budget_authority(scope.clone());
        Self {
            scope,
            actor_issuer: StandardMiningActorIssuer(Arc::clone(&actor_identity)),
            actor_expectation: StandardMiningActorExpectation(actor_identity),
            unit_closeout_issuer: StandardUnitCloseoutIssuer(Arc::clone(&unit_closeout_identity)),
            unit_closeout_expectation: StandardUnitCloseoutExpectation(unit_closeout_identity),
            teardown_budget_issuer,
            teardown_budget_expectation,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        WatchdogRunScope,
        StandardMiningActorIssuer,
        StandardMiningActorExpectation,
        StandardUnitCloseoutIssuer,
        StandardUnitCloseoutExpectation,
        TeardownBudgetIssuer,
        TeardownBudgetExpectation,
    ) {
        (
            self.scope,
            self.actor_issuer,
            self.actor_expectation,
            self.unit_closeout_issuer,
            self.unit_closeout_expectation,
            self.teardown_budget_issuer,
            self.teardown_budget_expectation,
        )
    }

    #[cfg(test)]
    pub(crate) fn for_scope_for_test(scope: WatchdogRunScope) -> Self {
        Self::for_scope(scope)
    }
}

fn require_mutation_barrier(
    name: &'static str,
    evidence: &dyn MutationBarrierEvidence,
) -> Result<()> {
    if !evidence.hardware_mutations_closed_and_drained() {
        anyhow::bail!("watchdog disarm requires complete {name} evidence");
    }
    Ok(())
}

fn require_actor_quiescence(
    name: &'static str,
    evidence: &dyn ActorQuiescenceEvidence,
) -> Result<()> {
    if !evidence.all_hardware_actors_quiesced() {
        anyhow::bail!("watchdog disarm requires complete {name} evidence");
    }
    Ok(())
}

fn require_software_safe_off(
    name: &'static str,
    evidence: &dyn SoftwareSafeOffEvidence,
) -> Result<()> {
    if !evidence.software_safe_off_completed() {
        anyhow::bail!("watchdog disarm requires complete {name} evidence");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ExactSerialManifestRoute {
    NoPic,
    S19kTrack1,
    Am2Bm1362,
}

fn validate_exact_serial_domain_pair(
    route: ExactSerialManifestRoute,
    serial: &crate::serial_mining::SerialExecutionDomainCloseout,
    api: &crate::serial_mining::ApiMutationDomainCloseout,
) -> Result<WatchdogRunScope> {
    let route_matches = match route {
        ExactSerialManifestRoute::NoPic => serial.is_nopic() && api.is_nopic(),
        ExactSerialManifestRoute::S19kTrack1 => serial.is_s19k_track1() && api.is_s19k_track1(),
        ExactSerialManifestRoute::Am2Bm1362 => serial.is_am2_bm1362() && api.is_am2_bm1362(),
    };
    if !route_matches {
        anyhow::bail!("watchdog manifest received another route's domain closeout");
    }
    if !serial.run_scope().same_run(api.run_scope()) {
        anyhow::bail!("serial and API closeouts belong to different watchdog runs");
    }
    Ok(serial.run_scope().clone())
}

#[cfg(test)]
pub(crate) fn validate_exact_serial_domain_pair_for_test(
    exact_am2_bm1362: bool,
    serial: &crate::serial_mining::SerialExecutionDomainCloseout,
    api: &crate::serial_mining::ApiMutationDomainCloseout,
) -> Result<()> {
    let route = if exact_am2_bm1362 {
        ExactSerialManifestRoute::Am2Bm1362
    } else {
        ExactSerialManifestRoute::NoPic
    };
    validate_exact_serial_domain_pair(route, serial, api).map(drop)
}

/// Exact move-only NoPic closeout roster. Both mutation domains are mandatory
/// opaque lifecycle closeouts: each proves either owner-issued NeverOpened or
/// owner-aggregated Closed evidence for this same watchdog run.
pub(crate) struct NoPicWatchdogShutdownManifest {
    serial_execution: crate::serial_mining::SerialExecutionDomainCloseout,
    api_mutation: crate::serial_mining::ApiMutationDomainCloseout,
    actors: ThreadRosterQuiescenceReceipt<NoPicSerialThreadSlot>,
    safe_off: crate::serial_mining::NoPicSafeOffReceipt,
    teardown: crate::serial_mining::ExactSerialTeardownReceipt,
    teardown_disarm: TeardownDisarmAuthority,
}

impl NoPicWatchdogShutdownManifest {
    pub(crate) fn new(
        serial_execution: crate::serial_mining::SerialExecutionDomainCloseout,
        api_mutation: crate::serial_mining::ApiMutationDomainCloseout,
        actors: ThreadRosterQuiescenceReceipt<NoPicSerialThreadSlot>,
        safe_off: crate::serial_mining::NoPicSafeOffReceipt,
        teardown: crate::serial_mining::ExactSerialTeardownReceipt,
        teardown_disarm: TeardownDisarmAuthority,
    ) -> Self {
        Self {
            serial_execution,
            api_mutation,
            actors,
            safe_off,
            teardown,
            teardown_disarm,
        }
    }

    fn into_validated_parts(self) -> Result<(WatchdogRunScope, TeardownDisarmAuthority)> {
        let scope = validate_exact_serial_domain_pair(
            ExactSerialManifestRoute::NoPic,
            &self.serial_execution,
            &self.api_mutation,
        )?;
        require_mutation_barrier("NoPic serial-execution domain", &self.serial_execution)?;
        require_mutation_barrier("NoPic API-mutation domain", &self.api_mutation)?;
        require_mutation_barrier(
            "NoPic terminal management-fabric barrier",
            self.safe_off.management_fabric(),
        )?;
        anyhow::ensure!(
            self.serial_execution.authorizes_nopic_actors(&self.actors),
            "NoPic serial actor receipt was not issued by this watchdog route scope"
        );
        if self.serial_execution.nopic_runtime_actors_were_admitted() {
            anyhow::ensure!(
                self.actors.joined(NoPicSerialThreadSlot::SerialIo),
                "NoPic admitted runtime requires the exact joined serial-I/O slot"
            );
            anyhow::ensure!(
                self.actors
                    .topology_not_applicable(NoPicSerialThreadSlot::Track1SafetySampler),
                "native NoPic closeout must exclude the S19k Track-1 safety sampler"
            );
        } else {
            anyhow::ensure!(
                self.actors.joined(NoPicSerialThreadSlot::SerialIo)
                    || self
                        .actors
                        .not_started_before_runtime_admission(NoPicSerialThreadSlot::SerialIo),
                "NoPic pre-runtime closeout requires joined or explicit not-reached serial-I/O evidence"
            );
            anyhow::ensure!(
                self.actors.not_started_before_runtime_admission(
                    NoPicSerialThreadSlot::Track1SafetySampler
                ) || self
                    .actors
                    .topology_not_applicable(NoPicSerialThreadSlot::Track1SafetySampler),
                "NoPic pre-runtime closeout lacks Track-1 sampler exclusion evidence"
            );
        }
        require_software_safe_off("NoPic checked power-off", self.safe_off.power())?;
        anyhow::ensure!(
            self.safe_off.same_teardown_budget(&self.teardown_disarm),
            "NoPic checked safe-off evidence belongs to another teardown budget"
        );
        anyhow::ensure!(
            self.teardown.same_teardown_budget(&self.teardown_disarm),
            "NoPic closeout evidence belongs to another teardown budget"
        );
        Ok((scope, self.teardown_disarm))
    }
}

/// Exact move-only S19k Track-1 closeout roster. Track-1 adopts already
/// energized rails and therefore has a typed physical terminal receipt. The
/// ordinary Track-1 contract is three checked reset assertions followed by the
/// fixed-polarity GPIO437 cut; install custody is the distinct checked
/// GPIO437-only contract. Neither can substitute a generic NoPic PSU receipt.
pub(crate) struct S19kTrack1WatchdogShutdownManifest {
    serial_execution: crate::serial_mining::SerialExecutionDomainCloseout,
    api_mutation: crate::serial_mining::ApiMutationDomainCloseout,
    actors: ThreadRosterQuiescenceReceipt<NoPicSerialThreadSlot>,
    safe_off: crate::serial_mining::S19kTrack1TerminalSafeOffReceipt,
    teardown: crate::serial_mining::ExactSerialTeardownReceipt,
    teardown_disarm: TeardownDisarmAuthority,
}

impl S19kTrack1WatchdogShutdownManifest {
    pub(crate) fn new(
        serial_execution: crate::serial_mining::SerialExecutionDomainCloseout,
        api_mutation: crate::serial_mining::ApiMutationDomainCloseout,
        actors: ThreadRosterQuiescenceReceipt<NoPicSerialThreadSlot>,
        safe_off: crate::serial_mining::S19kTrack1TerminalSafeOffReceipt,
        teardown: crate::serial_mining::ExactSerialTeardownReceipt,
        teardown_disarm: TeardownDisarmAuthority,
    ) -> Self {
        Self {
            serial_execution,
            api_mutation,
            actors,
            safe_off,
            teardown,
            teardown_disarm,
        }
    }

    fn into_validated_parts(self) -> Result<(WatchdogRunScope, TeardownDisarmAuthority)> {
        let scope = validate_exact_serial_domain_pair(
            ExactSerialManifestRoute::S19kTrack1,
            &self.serial_execution,
            &self.api_mutation,
        )?;
        require_mutation_barrier(
            "S19k Track-1 serial-execution domain",
            &self.serial_execution,
        )?;
        require_mutation_barrier("S19k Track-1 API-mutation domain", &self.api_mutation)?;
        if let Some(fabric) = self.safe_off.management_fabric() {
            require_mutation_barrier("S19k Track-1 terminal management-fabric barrier", fabric)?;
        }
        anyhow::ensure!(
            self.serial_execution.authorizes_nopic_actors(&self.actors),
            "S19k Track-1 actor receipt was not issued by this watchdog route scope"
        );
        if self.serial_execution.nopic_runtime_actors_were_admitted() {
            anyhow::ensure!(
                self.actors.joined(NoPicSerialThreadSlot::SerialIo),
                "S19k Track-1 closeout requires the joined serial-I/O actor"
            );
            anyhow::ensure!(
                self.actors
                    .joined(NoPicSerialThreadSlot::Track1SafetySampler),
                "S19k Track-1 closeout requires the joined thermal/tach safety sampler"
            );
            anyhow::ensure!(
                self.safe_off.management_fabric().is_some(),
                "S19k Track-1 admitted runtime requires a closed management-fabric receipt"
            );
        } else {
            anyhow::ensure!(
                self.actors.joined(NoPicSerialThreadSlot::SerialIo)
                    || self
                        .actors
                        .not_started_before_runtime_admission(NoPicSerialThreadSlot::SerialIo),
                "S19k Track-1 pre-runtime closeout lacks serial-I/O not-reached evidence"
            );
            anyhow::ensure!(
                self.actors
                    .joined(NoPicSerialThreadSlot::Track1SafetySampler)
                    || self.actors.not_started_before_runtime_admission(
                        NoPicSerialThreadSlot::Track1SafetySampler
                    ),
                "S19k Track-1 pre-runtime closeout lacks safety-sampler not-reached evidence"
            );
            anyhow::ensure!(
                self.safe_off.management_fabric().is_some()
                    || self.safe_off.management_fabric_never_opened(),
                "S19k Track-1 pre-runtime management-fabric closeout is unresolved"
            );
        }
        anyhow::ensure!(
            self.safe_off.has_exact_checked_physical_safeoff(),
            "S19k Track-1 terminal receipt lacks an exact typed checked physical SafeOff"
        );
        anyhow::ensure!(
            self.safe_off.same_teardown_budget(&self.teardown_disarm),
            "S19k Track-1 checked safe-off evidence belongs to another teardown budget"
        );
        anyhow::ensure!(
            self.teardown.same_teardown_budget(&self.teardown_disarm),
            "S19k Track-1 closeout timing belongs to another teardown budget"
        );
        Ok((scope, self.teardown_disarm))
    }
}

/// Exact move-only AM2 direct-serial closeout roster.
pub(crate) struct Am2SerialWatchdogShutdownManifest {
    serial_execution: crate::serial_mining::SerialExecutionDomainCloseout,
    api_mutation: crate::serial_mining::ApiMutationDomainCloseout,
    reset: crate::serial_mining::Am2ResetDomainCloseout,
    actors: ThreadRosterQuiescenceReceipt<Am2SerialThreadSlot>,
    safe_off: crate::serial_mining::Am2SerialSafeOffReceipt,
    teardown: crate::serial_mining::ExactSerialTeardownReceipt,
    teardown_disarm: TeardownDisarmAuthority,
}

impl Am2SerialWatchdogShutdownManifest {
    pub(crate) fn new(
        serial_execution: crate::serial_mining::SerialExecutionDomainCloseout,
        api_mutation: crate::serial_mining::ApiMutationDomainCloseout,
        reset: crate::serial_mining::Am2ResetDomainCloseout,
        actors: ThreadRosterQuiescenceReceipt<Am2SerialThreadSlot>,
        safe_off: crate::serial_mining::Am2SerialSafeOffReceipt,
        teardown: crate::serial_mining::ExactSerialTeardownReceipt,
        teardown_disarm: TeardownDisarmAuthority,
    ) -> Self {
        Self {
            serial_execution,
            api_mutation,
            reset,
            actors,
            safe_off,
            teardown,
            teardown_disarm,
        }
    }

    fn into_validated_parts(self) -> Result<(WatchdogRunScope, TeardownDisarmAuthority)> {
        let scope = validate_exact_serial_domain_pair(
            ExactSerialManifestRoute::Am2Bm1362,
            &self.serial_execution,
            &self.api_mutation,
        )?;
        require_mutation_barrier("AM2 serial-execution domain", &self.serial_execution)?;
        require_mutation_barrier("AM2 API-mutation domain", &self.api_mutation)?;
        anyhow::ensure!(
            self.reset.run_scope().same_run(&scope),
            "AM2 reset closeout belongs to another watchdog run"
        );
        anyhow::ensure!(
            !self.reset.outcome_unknown(),
            "AM2 reset MMIO outcome is unknown; watchdog Disarm is forbidden"
        );
        if self.serial_execution.serial_was_observed()
            || self.serial_execution.am2_runtime_actors_were_admitted()
        {
            anyhow::ensure!(
                self.reset.pulse_register_verified(),
                "AM2 serial observation/runtime requires reset assertion/release register verification"
            );
        } else {
            anyhow::ensure!(
                self.reset.terminal_release_register_verified()
                    || self.reset.safe_without_reset_mutation(),
                "AM2 early closeout lacks a safe reset-domain disposition"
            );
        }
        require_mutation_barrier(
            "AM2 terminal management-fabric barrier",
            self.safe_off.management_fabric(),
        )?;
        anyhow::ensure!(
            self.serial_execution.authorizes_am2_actors(&self.actors),
            "AM2 serial actor receipt was not issued by this watchdog route scope"
        );
        if self.serial_execution.am2_runtime_actors_were_admitted() {
            anyhow::ensure!(
                self.actors.joined(Am2SerialThreadSlot::SerialIo),
                "AM2 admitted runtime requires the exact joined serial-I/O slot"
            );
            anyhow::ensure!(
                self.actors.joined(Am2SerialThreadSlot::DspicHeartbeat),
                "AM2 admitted runtime requires the exact joined dsPIC-heartbeat slot"
            );
            if self.safe_off.smart_psu_present() {
                anyhow::ensure!(
                    self.actors.joined(Am2SerialThreadSlot::ApwHeartbeat),
                    "AM2 smart-APW admitted runtime requires the exact joined APW-heartbeat slot"
                );
            } else {
                anyhow::ensure!(
                    self.actors
                        .topology_not_applicable(Am2SerialThreadSlot::ApwHeartbeat),
                    "AM2 explicit APW bypass requires heartbeat non-applicability evidence"
                );
            }
        } else {
            for slot in [
                Am2SerialThreadSlot::DspicHeartbeat,
                Am2SerialThreadSlot::SerialIo,
            ] {
                anyhow::ensure!(
                    self.actors.joined(slot)
                        || self.actors.not_started_before_runtime_admission(slot),
                    "AM2 pre-runtime closeout requires joined or explicit not-reached evidence for {slot:?}"
                );
            }
            if self.safe_off.smart_psu_present() {
                anyhow::ensure!(
                    self.actors.joined(Am2SerialThreadSlot::ApwHeartbeat)
                        || self
                            .actors
                            .not_started_before_runtime_admission(
                                Am2SerialThreadSlot::ApwHeartbeat,
                            ),
                    "AM2 smart-APW pre-runtime closeout requires joined or explicit not-reached heartbeat evidence"
                );
            } else {
                anyhow::ensure!(
                    self.actors
                        .topology_not_applicable(Am2SerialThreadSlot::ApwHeartbeat),
                    "AM2 explicit APW bypass requires heartbeat non-applicability evidence"
                );
            }
        }
        require_software_safe_off("AM2 checked terminal safe-off", &self.safe_off)?;
        anyhow::ensure!(
            self.safe_off.same_teardown_budget(&self.teardown_disarm),
            "AM2 checked safe-off evidence belongs to another teardown budget"
        );
        anyhow::ensure!(
            self.teardown.same_teardown_budget(&self.teardown_disarm),
            "AM2 exact-serial closeout evidence belongs to another teardown budget"
        );
        Ok((scope, self.teardown_disarm))
    }
}

/// Exact move-only hybrid-AM2 closeout roster.
pub(crate) struct HybridWatchdogShutdownManifest {
    route_scope: HybridWatchdogRouteScope,
    api_drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
    api_final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
    actors: ThreadRosterQuiescenceReceipt<HybridThreadSlot>,
    safe_off: crate::s19j_hybrid_mining::Am2TerminalSafeOffEvidence,
    teardown: TeardownDisarmAuthority,
}

/// Exact S17 closeout. The hardware owner constructs `safe_off` only after
/// dispatch has stopped, the I2C fabric is terminal, GPIO907 was read off,
/// every PIC disable completed and the Stratum task was observed terminated.
pub(crate) struct S17WatchdogShutdownManifest {
    route_scope: S17WatchdogRouteScope,
    api_drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
    api_final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
    fabric: dcentrald_hal::i2c::TerminalSafeOffTransition,
    psu_fabric: dcentrald_hal::i2c::TerminalSafeOffTransition,
    safe_off: crate::s17_hybrid_mining::S17SafeOffEvidence,
    teardown: TeardownDisarmAuthority,
}

impl S17WatchdogShutdownManifest {
    pub(crate) fn new(
        route_scope: S17WatchdogRouteScope,
        api_drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
        api_final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
        fabric: dcentrald_hal::i2c::TerminalSafeOffTransition,
        psu_fabric: dcentrald_hal::i2c::TerminalSafeOffTransition,
        safe_off: crate::s17_hybrid_mining::S17SafeOffEvidence,
        teardown: TeardownDisarmAuthority,
    ) -> Self {
        Self {
            route_scope,
            api_drain,
            api_final_commit,
            fabric,
            psu_fabric,
            safe_off,
            teardown,
        }
    }

    fn into_validated_parts(self) -> Result<(WatchdogRunScope, TeardownDisarmAuthority)> {
        require_mutation_barrier("S17 API drain", &self.api_drain)?;
        require_mutation_barrier("S17 API final commit", &self.api_final_commit)?;
        require_mutation_barrier("S17 controller fabric", &self.fabric)?;
        require_mutation_barrier("S17 APW9 fabric", &self.psu_fabric)?;
        validate_s17_safe_off(&self.safe_off, &self.teardown)?;
        Ok((self.route_scope.scope, self.teardown))
    }
}

fn validate_s17_safe_off(
    evidence: &crate::s17_hybrid_mining::S17SafeOffEvidence,
    teardown: &TeardownDisarmAuthority,
) -> Result<()> {
    anyhow::ensure!(
        evidence.completed(),
        "S17 physical cutoff/actor closeout incomplete"
    );
    anyhow::ensure!(
        evidence.same_teardown_budget(teardown),
        "S17 cutoff evidence belongs to another watchdog teardown budget"
    );
    Ok(())
}

pub(crate) struct Bm1398WatchdogShutdownManifest {
    route_scope: Bm1398WatchdogRouteScope,
    api_drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
    api_final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
    fabric: dcentrald_hal::i2c::TerminalSafeOffTransition,
    safe_off: crate::s19_bm1398_native_mining::Bm1398SafeOffEvidence,
    teardown: TeardownDisarmAuthority,
}

impl Bm1398WatchdogShutdownManifest {
    pub(crate) fn new(
        route_scope: Bm1398WatchdogRouteScope,
        api_drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
        api_final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
        fabric: dcentrald_hal::i2c::TerminalSafeOffTransition,
        safe_off: crate::s19_bm1398_native_mining::Bm1398SafeOffEvidence,
        teardown: TeardownDisarmAuthority,
    ) -> Self {
        Self {
            route_scope,
            api_drain,
            api_final_commit,
            fabric,
            safe_off,
            teardown,
        }
    }

    fn into_validated_parts(self) -> Result<(WatchdogRunScope, TeardownDisarmAuthority)> {
        require_mutation_barrier("BM1398 API drain", &self.api_drain)?;
        require_mutation_barrier("BM1398 API final commit", &self.api_final_commit)?;
        require_mutation_barrier("BM1398 controller fabric", &self.fabric)?;
        anyhow::ensure!(
            self.safe_off.completed(),
            "BM1398 cutoff/actor closeout incomplete"
        );
        anyhow::ensure!(
            self.safe_off.same_teardown_budget(&self.teardown),
            "BM1398 cutoff evidence belongs to another watchdog teardown budget"
        );
        Ok((self.route_scope.scope, self.teardown))
    }
}

impl HybridWatchdogShutdownManifest {
    pub(crate) fn new(
        route_scope: HybridWatchdogRouteScope,
        api_drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
        api_final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
        actors: ThreadRosterQuiescenceReceipt<HybridThreadSlot>,
        safe_off: crate::s19j_hybrid_mining::Am2TerminalSafeOffEvidence,
        teardown: TeardownDisarmAuthority,
    ) -> Self {
        Self {
            route_scope,
            api_drain,
            api_final_commit,
            actors,
            safe_off,
            teardown,
        }
    }

    fn into_validated_parts(self) -> Result<(WatchdogRunScope, TeardownDisarmAuthority)> {
        require_mutation_barrier("hybrid API-drain barrier", &self.api_drain)?;
        require_mutation_barrier("hybrid API final-commit barrier", &self.api_final_commit)?;
        anyhow::ensure!(
            self.route_scope.actor_owner.is_none(),
            "hybrid watchdog actor owner was never activated"
        );
        anyhow::ensure!(
            self.actors.authorizes(&self.route_scope.actor_expectation),
            "hybrid heartbeat receipt was not issued by this watchdog route scope"
        );
        anyhow::ensure!(
            self.actors.joined(HybridThreadSlot::PicHeartbeat),
            "hybrid watchdog Disarm requires the exact joined PIC heartbeat slot"
        );
        if self.safe_off.smart_psu_present() {
            anyhow::ensure!(
                self.actors.joined(HybridThreadSlot::PsuHeartbeat),
                "hybrid smart-PSU safe-off requires the exact joined PSU heartbeat slot"
            );
        } else {
            anyhow::ensure!(
                self.actors.not_applicable(HybridThreadSlot::PsuHeartbeat),
                "hybrid no-smart-PSU safe-off requires explicit PSU-heartbeat non-applicability"
            );
        }
        require_software_safe_off("hybrid terminal safe-off", &self.safe_off)?;
        anyhow::ensure!(
            self.safe_off.same_teardown_budget(&self.teardown),
            "hybrid safe-off evidence belongs to another teardown budget"
        );
        Ok((self.route_scope.scope, self.teardown))
    }
}

/// Exact move-only AM3-BB closeout roster.
pub(crate) struct Am3BbWatchdogShutdownManifest {
    route_scope: Am3BbWatchdogRouteScope,
    api_drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
    api_final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
    controller_fabric: dcentrald_hal::i2c::TerminalSafeOffTransition,
    actors: ThreadRosterQuiescenceReceipt<Am3BbThreadSlot>,
    safe_off: crate::am3_bb_mining::Am3BbSafeOffReceipt,
    teardown: TeardownDisarmAuthority,
}

impl Am3BbWatchdogShutdownManifest {
    pub(crate) fn new(
        route_scope: Am3BbWatchdogRouteScope,
        api_drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
        api_final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
        controller_fabric: dcentrald_hal::i2c::TerminalSafeOffTransition,
        actors: ThreadRosterQuiescenceReceipt<Am3BbThreadSlot>,
        safe_off: crate::am3_bb_mining::Am3BbSafeOffReceipt,
        teardown: TeardownDisarmAuthority,
    ) -> Self {
        Self {
            route_scope,
            api_drain,
            api_final_commit,
            controller_fabric,
            actors,
            safe_off,
            teardown,
        }
    }

    fn into_validated_parts(self) -> Result<(WatchdogRunScope, TeardownDisarmAuthority)> {
        require_mutation_barrier("AM3-BB API-drain barrier", &self.api_drain)?;
        require_mutation_barrier("AM3-BB API final-commit barrier", &self.api_final_commit)?;
        require_mutation_barrier("AM3-BB controller-fabric barrier", &self.controller_fabric)?;
        anyhow::ensure!(
            self.route_scope.actor_owner.is_none(),
            "AM3-BB watchdog actor owner was never activated"
        );
        anyhow::ensure!(
            self.actors.authorizes(&self.route_scope.actor_expectation),
            "AM3-BB heartbeat receipt was not issued by this watchdog route scope"
        );
        anyhow::ensure!(
            self.actors.joined(Am3BbThreadSlot::DspicHeartbeat),
            "AM3-BB watchdog Disarm requires the exact joined dsPIC heartbeat slot"
        );
        require_software_safe_off("AM3-BB checked board safe-off", &self.safe_off)?;
        anyhow::ensure!(
            self.safe_off.same_teardown_budget(&self.teardown),
            "AM3-BB safe-off evidence belongs to another teardown budget"
        );
        Ok((self.route_scope.scope, self.teardown))
    }
}

/// Move-only standard-daemon authority for the irreversible magic-close write.
/// Cloneable lifecycle intents cannot construct or carry this capability.
pub(crate) struct StandardWatchdogDisarmPermit {
    scope: WatchdogRunScope,
    _execution: crate::asic_identity_publication::CompositionInvalidationReceipt,
    actors: StandardMiningActorQuiescenceReceipt,
    unit_closeout: crate::daemon::StandardUnitCloseoutIdentity,
    teardown: TeardownDisarmAuthority,
}

impl StandardWatchdogDisarmPermit {
    pub(crate) fn from_evidence(
        evidence: crate::daemon::StandardDaemonShutdownEvidence,
    ) -> Result<Self> {
        let (scope, execution, actors, unit_closeout, teardown) =
            evidence.into_validated_parts()?;
        Ok(Self {
            scope,
            _execution: execution,
            actors,
            unit_closeout,
            teardown,
        })
    }

    pub(crate) fn authorizes(
        &self,
        watchdog_scope: &WatchdogRunScope,
        actor_expectation: &StandardMiningActorExpectation,
        unit_closeout_expectation: &StandardUnitCloseoutExpectation,
        teardown_expectation: &TeardownBudgetExpectation,
    ) -> bool {
        self.scope.same_run(watchdog_scope)
            && self.actors.authorizes(watchdog_scope, actor_expectation)
            && self
                .unit_closeout
                .authorizes(watchdog_scope, unit_closeout_expectation)
            && self
                .teardown
                .authorizes(watchdog_scope, teardown_expectation)
    }

    pub(crate) fn deadline(&self, stage: TeardownStage) -> Instant {
        self.teardown.deadline(stage)
    }

    pub(crate) fn require_disarm_command_started_at(&self, started_at: Instant) -> Result<()> {
        self.teardown.require_disarm_command_started_at(started_at)
    }

    pub(crate) fn require_completed_at(
        &self,
        stage: TeardownStage,
        completed_at: Instant,
    ) -> Result<()> {
        self.teardown.require_completed_at(stage, completed_at)
    }
}

impl WatchdogDisarmPermit {
    pub(crate) fn from_nopic_manifest(manifest: NoPicWatchdogShutdownManifest) -> Result<Self> {
        let (scope, teardown) = manifest.into_validated_parts()?;
        Ok(Self {
            scope,
            composition: WatchdogComposition::NoPicSerial,
            teardown: WatchdogTeardownAuthority::Absolute(teardown),
        })
    }

    pub(crate) fn from_s19k_track1_manifest(
        manifest: S19kTrack1WatchdogShutdownManifest,
    ) -> Result<Self> {
        let (scope, teardown) = manifest.into_validated_parts()?;
        Ok(Self {
            scope,
            composition: WatchdogComposition::S19kTrack1Serial,
            teardown: WatchdogTeardownAuthority::Absolute(teardown),
        })
    }

    pub(crate) fn from_am2_serial_manifest(
        manifest: Am2SerialWatchdogShutdownManifest,
    ) -> Result<Self> {
        let (scope, teardown) = manifest.into_validated_parts()?;
        Ok(Self {
            scope,
            composition: WatchdogComposition::Am2Bm1362Serial,
            teardown: WatchdogTeardownAuthority::Absolute(teardown),
        })
    }

    pub(crate) fn from_hybrid_manifest(manifest: HybridWatchdogShutdownManifest) -> Result<Self> {
        let (scope, teardown) = manifest.into_validated_parts()?;
        Ok(Self {
            scope,
            composition: WatchdogComposition::HybridAm2,
            teardown: WatchdogTeardownAuthority::Absolute(teardown),
        })
    }

    pub(crate) fn from_s17_manifest(manifest: S17WatchdogShutdownManifest) -> Result<Self> {
        let (scope, teardown) = manifest.into_validated_parts()?;
        Ok(Self {
            scope,
            composition: WatchdogComposition::S17Hybrid,
            teardown: WatchdogTeardownAuthority::Absolute(teardown),
        })
    }

    pub(crate) fn from_bm1398_manifest(manifest: Bm1398WatchdogShutdownManifest) -> Result<Self> {
        let (scope, teardown) = manifest.into_validated_parts()?;
        Ok(Self {
            scope,
            composition: WatchdogComposition::Bm1398Native,
            teardown: WatchdogTeardownAuthority::Absolute(teardown),
        })
    }

    pub(crate) fn from_am3_bb_manifest(manifest: Am3BbWatchdogShutdownManifest) -> Result<Self> {
        let (scope, teardown) = manifest.into_validated_parts()?;
        Ok(Self {
            scope,
            composition: WatchdogComposition::Am3Bb,
            teardown: WatchdogTeardownAuthority::Absolute(teardown),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_evidence<M, Q, S>(
        scope: WatchdogRunScope,
        mutation_barrier: &M,
        quiescence: &Q,
        safe_off: &S,
    ) -> Result<Self>
    where
        M: MutationBarrierEvidence,
        Q: ActorQuiescenceEvidence,
        S: SoftwareSafeOffEvidence,
    {
        let mutation_barriers: [&dyn MutationBarrierEvidence; 1] = [mutation_barrier];
        Self::from_evidence_set(scope, &mutation_barriers, quiescence, safe_off)
    }

    /// Test-only generic constructor used to exercise the validator's negative
    /// cases. Production routes cannot call this type-erased surface; each must
    /// consume its fixed named manifest above.
    #[cfg(test)]
    pub(crate) fn from_evidence_set<Q, S>(
        scope: WatchdogRunScope,
        mutation_barriers: &[&dyn MutationBarrierEvidence],
        quiescence: &Q,
        safe_off: &S,
    ) -> Result<Self>
    where
        Q: ActorQuiescenceEvidence,
        S: SoftwareSafeOffEvidence,
    {
        if mutation_barriers.is_empty() {
            anyhow::bail!("watchdog disarm requires at least one mutation barrier receipt");
        }
        for (index, mutation_barrier) in mutation_barriers.iter().enumerate() {
            if !mutation_barrier.hardware_mutations_closed_and_drained() {
                anyhow::bail!("hardware mutation barrier evidence at index {index} is incomplete");
            }
        }
        if !quiescence.all_hardware_actors_quiesced() {
            anyhow::bail!("hardware actor quiescence evidence is incomplete");
        }
        if !safe_off.software_safe_off_completed() {
            anyhow::bail!("software safe-off evidence is incomplete");
        }
        Ok(Self {
            scope,
            composition: WatchdogComposition::TestOnly,
            teardown: WatchdogTeardownAuthority::TestRelative,
        })
    }
}

/// Linear capability issued only after the magic-close write succeeds and
/// watchdog worker termination is observed. Its private representation and
/// private constructor prevent sibling modules from synthesizing closeout.
#[derive(Debug)]
pub(crate) struct WatchdogCloseoutReceipt {
    _private: (),
}

impl WatchdogCloseoutReceipt {
    fn magic_close_write_completed_and_worker_exit_observed() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FeedSuppressionReason {
    BringupDeadlineExpired,
    MiningLivenessStalled,
    TeardownDeadlineExpired,
    ExternallyReportedSafetyFailure(String),
}

#[derive(Debug)]
enum WatchdogPhase {
    Bringup { deadline: Instant },
    Mining { last_live: u64, stalls: u64 },
    Teardown { deadline: Instant },
    FeedSuppressed(FeedSuppressionReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhaseReceipt {
    MiningAdmitted,
    TeardownAdmitted { admitted_at: Instant },
    FeedSuppressed,
}

enum WatchdogCommand {
    EnterMining {
        reply: oneshot::Sender<std::result::Result<PhaseReceipt, String>>,
    },
    BeginTeardown {
        deadline: Instant,
        reply: oneshot::Sender<std::result::Result<PhaseReceipt, String>>,
    },
    SuppressFeeds {
        reason: String,
        reply: oneshot::Sender<std::result::Result<PhaseReceipt, String>>,
    },
    DisarmNeverEnergized {
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
    Disarm {
        permit: WatchdogDisarmPermit,
        reply: oneshot::Sender<std::result::Result<Instant, String>>,
    },
}

trait WatchdogDevice: Send {
    fn set_timeout(&self, seconds: u32) -> std::result::Result<u32, String>;
    fn kick(&self) -> std::result::Result<(), String>;
    fn try_close_magic(&mut self) -> std::result::Result<(), String>;
}

impl WatchdogDevice for Watchdog {
    fn set_timeout(&self, seconds: u32) -> std::result::Result<u32, String> {
        #[cfg(unix)]
        {
            Watchdog::set_timeout(self, seconds).map_err(|error| error.to_string())
        }
        #[cfg(not(unix))]
        {
            Ok(seconds)
        }
    }

    fn kick(&self) -> std::result::Result<(), String> {
        Watchdog::kick(self).map_err(|error| error.to_string())
    }

    fn try_close_magic(&mut self) -> std::result::Result<(), String> {
        Watchdog::try_close_magic(self).map_err(|error| error.to_string())
    }
}

type WatchdogFactory =
    Box<dyn FnOnce() -> std::result::Result<Box<dyn WatchdogDevice>, String> + Send>;

/// Cancellation- and unwind-safe ownership for an armed watchdog device.
///
/// Before a completed magic-close byte, every ordinary Rust drop path must
/// retain the descriptor for the remainder of the process. This includes
/// configuration failures, admission receiver loss, worker panics, and future
/// maintenance that introduces an early return. The only normal close is the
/// explicit `close_after_magic_write` transition.
struct RetainedArmedWatchdog {
    device: Option<Box<dyn WatchdogDevice>>,
}

impl RetainedArmedWatchdog {
    fn new(device: Box<dyn WatchdogDevice>) -> Self {
        Self {
            device: Some(device),
        }
    }

    #[cfg(test)]
    fn empty() -> Self {
        Self { device: None }
    }

    fn as_ref(&self) -> Option<&dyn WatchdogDevice> {
        self.device.as_deref()
    }

    fn as_mut(&mut self) -> Option<&mut (dyn WatchdogDevice + 'static)> {
        self.device.as_deref_mut()
    }

    fn retain(&mut self) {
        if let Some(device) = self.device.take() {
            std::mem::forget(device);
        }
    }

    fn close_after_magic_write(&mut self) {
        drop(self.device.take());
    }
}

impl Drop for RetainedArmedWatchdog {
    fn drop(&mut self) {
        self.retain();
    }
}

/// Sole owner of one fail-closed watchdog worker.
pub(crate) struct SafetyWatchdogOwner {
    command_tx: Option<mpsc::Sender<WatchdogCommand>>,
    worker: Option<JoinHandle<()>>,
    feed_owner: WatchdogFeedGateOwner,
    teardown_admitted: bool,
    /// One-way, process-local deadline visible to the worker without waiting
    /// for command/RPC acknowledgement. Once published, potentially blocking
    /// safe-off I/O cannot leave the watchdog in unbounded Bringup/Mining feed
    /// behavior even if the actor response is delayed.
    teardown_deadline_request: Arc<OnceLock<Instant>>,
    run_scope: WatchdogRunScope,
    teardown_budget_issuer: TeardownBudgetIssuer,
    teardown_budget_expectation: TeardownBudgetExpectation,
    composition: Option<WatchdogComposition>,
    never_energized_issued: bool,
}

/// Move-only watchdog Teardown request split at the physical-cut boundary.
///
/// Issuing this synchronously publishes the local feed deadline and submits
/// the actor command. The caller can then cut power before spending any of the
/// cutoff reserve waiting for the actor acknowledgement.
pub(crate) struct WatchdogTeardownRequest {
    budget: TeardownBudget,
    admission: WatchdogTeardownAdmission,
}

impl WatchdogTeardownRequest {
    pub(crate) fn into_parts(self) -> (TeardownBudget, WatchdogTeardownAdmission) {
        (self.budget, self.admission)
    }
}

/// Opaque, one-shot actor acknowledgement owned by a published Teardown
/// request. It cannot mint or extend a budget and can be observed only once.
pub(crate) struct WatchdogTeardownAdmission {
    receipt: Option<oneshot::Receiver<std::result::Result<PhaseReceipt, String>>>,
    immediate_error: Option<String>,
}

impl WatchdogTeardownAdmission {
    fn pending(receipt: oneshot::Receiver<std::result::Result<PhaseReceipt, String>>) -> Self {
        Self {
            receipt: Some(receipt),
            immediate_error: None,
        }
    }

    fn failed(reason: String) -> Self {
        Self {
            receipt: None,
            immediate_error: Some(reason),
        }
    }
}

impl SafetyWatchdogOwner {
    fn claim_composition(&mut self, composition: WatchdogComposition) -> Result<WatchdogRunScope> {
        if let Some(existing) = self.composition {
            anyhow::bail!(
                "watchdog composition was already bound to {existing:?}; refusing competing {composition:?} authority"
            );
        }
        self.composition = Some(composition);
        Ok(self.run_scope.clone())
    }

    /// Claim the one exact direct-serial route-domain bundle associated with
    /// this watchdog run. The route is retained by the owner, so a same-run
    /// Hybrid or AM3 manifest cannot bypass the serial lifecycle closeout.
    pub(crate) fn claim_serial_route_scope(
        &mut self,
        route: SerialWatchdogComposition,
    ) -> Result<SerialWatchdogRouteAdmission> {
        match route {
            SerialWatchdogComposition::NoPic => {
                let (actor_owner, actor_expectation) = issue_thread_roster([
                    ThreadSlotDeclaration::conditional(NoPicSerialThreadSlot::SerialIo),
                    ThreadSlotDeclaration::conditional(NoPicSerialThreadSlot::Track1SafetySampler),
                ])?;
                let scope = self.claim_composition(WatchdogComposition::NoPicSerial)?;
                Ok(SerialWatchdogRouteAdmission::NoPic {
                    scope,
                    actor_owner,
                    actor_expectation,
                })
            }
            SerialWatchdogComposition::S19kTrack1 => {
                let (actor_owner, actor_expectation) = issue_thread_roster([
                    ThreadSlotDeclaration::conditional(NoPicSerialThreadSlot::SerialIo),
                    ThreadSlotDeclaration::conditional(NoPicSerialThreadSlot::Track1SafetySampler),
                ])?;
                let scope = self.claim_composition(WatchdogComposition::S19kTrack1Serial)?;
                Ok(SerialWatchdogRouteAdmission::S19kTrack1 {
                    scope,
                    actor_owner,
                    actor_expectation,
                })
            }
            SerialWatchdogComposition::Am2Bm1362 => {
                let (actor_owner, actor_expectation) = issue_thread_roster([
                    ThreadSlotDeclaration::conditional(Am2SerialThreadSlot::ApwHeartbeat),
                    ThreadSlotDeclaration::conditional(Am2SerialThreadSlot::DspicHeartbeat),
                    ThreadSlotDeclaration::conditional(Am2SerialThreadSlot::SerialIo),
                ])?;
                let scope = self.claim_composition(WatchdogComposition::Am2Bm1362Serial)?;
                Ok(SerialWatchdogRouteAdmission::Am2Bm1362 {
                    scope,
                    actor_owner,
                    actor_expectation,
                })
            }
        }
    }

    /// Exact Track-1 claim with no fallible conversion after composition is
    /// committed.  Thread-roster construction happens first; `claim_composition`
    /// is the final fallible operation and mutates only on success.  This lets
    /// callers retain `S19kTrack1NeverHandoff` for a clean magic-close on every
    /// returned error, then cross directly into the terminal signal boundary
    /// after `Ok` without another fallible ownership conversion.
    pub(crate) fn claim_s19k_track1_route_scope(
        &mut self,
    ) -> Result<(
        WatchdogRunScope,
        ThreadRosterOwner<NoPicSerialThreadSlot>,
        ThreadRosterExpectation<NoPicSerialThreadSlot>,
    )> {
        let (actor_owner, actor_expectation) = issue_thread_roster([
            ThreadSlotDeclaration::conditional(NoPicSerialThreadSlot::SerialIo),
            ThreadSlotDeclaration::conditional(NoPicSerialThreadSlot::Track1SafetySampler),
        ])?;
        let scope = self.claim_composition(WatchdogComposition::S19kTrack1Serial)?;
        Ok((scope, actor_owner, actor_expectation))
    }

    pub(crate) fn claim_hybrid_route_scope(&mut self) -> Result<HybridWatchdogRouteScope> {
        let (actor_owner, actor_expectation) = issue_thread_roster([
            ThreadSlotDeclaration::conditional(HybridThreadSlot::PsuHeartbeat),
            ThreadSlotDeclaration::required(HybridThreadSlot::PicHeartbeat),
        ])?;
        Ok(HybridWatchdogRouteScope {
            scope: self.claim_composition(WatchdogComposition::HybridAm2)?,
            actor_owner: Some(actor_owner),
            actor_expectation,
        })
    }

    pub(crate) fn claim_s17_route_scope(&mut self) -> Result<S17WatchdogRouteScope> {
        Ok(S17WatchdogRouteScope {
            scope: self.claim_composition(WatchdogComposition::S17Hybrid)?,
        })
    }

    pub(crate) fn claim_bm1398_route_scope(&mut self) -> Result<Bm1398WatchdogRouteScope> {
        Ok(Bm1398WatchdogRouteScope {
            scope: self.claim_composition(WatchdogComposition::Bm1398Native)?,
        })
    }

    pub(crate) fn claim_am3_bb_route_scope(&mut self) -> Result<Am3BbWatchdogRouteScope> {
        let (actor_owner, actor_expectation) =
            issue_thread_roster([ThreadSlotDeclaration::required(
                Am3BbThreadSlot::DspicHeartbeat,
            )])?;
        Ok(Am3BbWatchdogRouteScope {
            scope: self.claim_composition(WatchdogComposition::Am3Bb)?,
            actor_owner: Some(actor_owner),
            actor_expectation,
        })
    }

    /// Issue the sole AM2 pre-energization close capability for this exact
    /// owner/run. It is unavailable until the owner is composition-bound and
    /// cannot be re-minted after a caller consumes or loses it.
    pub(crate) fn issue_am2_never_energized(&mut self) -> Result<Am2NeverEnergized> {
        if self.composition != Some(WatchdogComposition::Am2Bm1362Serial) {
            anyhow::bail!(
                "AM2 never-energized authority requires an AM2 BM1362 serial watchdog binding"
            );
        }
        if self.never_energized_issued {
            anyhow::bail!("AM2 never-energized authority was already issued");
        }
        self.never_energized_issued = true;
        Ok(Am2NeverEnergized {
            run_scope: self.run_scope.clone(),
        })
    }

    /// Issue the sole S19k Track-1 pre-handoff close capability for this run.
    /// It is deliberately available only before any watchdog composition is
    /// claimed, so a failed watchdog-SLA check can leave stock bosminer and the
    /// inherited rail state untouched.
    pub(crate) fn issue_s19k_track1_never_handoff(&mut self) -> Result<S19kTrack1NeverHandoff> {
        if self.composition.is_some() {
            anyhow::bail!(
                "S19k Track-1 never-handoff authority requires an unclaimed watchdog route"
            );
        }
        if self.never_energized_issued {
            anyhow::bail!("S19k Track-1 never-handoff authority was already issued");
        }
        self.never_energized_issued = true;
        Ok(S19kTrack1NeverHandoff {
            run_scope: self.run_scope.clone(),
        })
    }

    /// Issue the sole AM3-BB pre-energization close capability for this exact
    /// owner/run. The token is destroyed immediately before GPIO59 HIGH becomes
    /// reachable, so later faults cannot use the bring-up close path.
    pub(crate) fn issue_am3_bb_never_energized(&mut self) -> Result<Am3BbNeverEnergized> {
        if self.composition != Some(WatchdogComposition::Am3Bb) {
            anyhow::bail!("AM3-BB never-energized authority requires an AM3-BB watchdog binding");
        }
        if self.never_energized_issued {
            anyhow::bail!("watchdog never-energized authority was already issued");
        }
        self.never_energized_issued = true;
        Ok(Am3BbNeverEnergized {
            run_scope: self.run_scope.clone(),
        })
    }

    #[cfg(test)]
    fn claim_test_route_scope(&mut self) -> Result<WatchdogRunScope> {
        self.claim_composition(WatchdogComposition::TestOnly)
    }

    /// Inert owner for unit tests that never cross the pre-hardware cancellation
    /// fence. Production admission must always use `start_before_energizing`.
    #[cfg(test)]
    pub(crate) fn inert_for_pre_hardware_test() -> Self {
        let run_scope = WatchdogRunScope::new();
        let (teardown_budget_issuer, teardown_budget_expectation) =
            issue_teardown_budget_authority(run_scope.clone());
        let feed_owner = WatchdogFeedGateOwner::new();
        let teardown_deadline_request = feed_owner.deadline_request();
        Self {
            command_tx: None,
            worker: None,
            feed_owner,
            teardown_admitted: false,
            teardown_deadline_request,
            run_scope,
            teardown_budget_issuer,
            teardown_budget_expectation,
            composition: None,
            never_energized_issued: false,
        }
    }

    pub(crate) async fn start_before_energizing(
        config: &WatchdogConfig,
        bringup_grace: Duration,
        expected_liveness_interval: Duration,
        liveness: SafetyLiveness,
    ) -> std::result::Result<(Self, WatchdogAdmission), WatchdogPreOpenStartError> {
        Self::start_with_factory(
            config,
            bringup_grace,
            expected_liveness_interval,
            liveness,
            Box::new(|| {
                Watchdog::open()
                    .map(|watchdog| Box::new(watchdog) as Box<dyn WatchdogDevice>)
                    .map_err(|error| error.to_string())
            }),
        )
        .await
    }

    async fn start_with_factory(
        config: &WatchdogConfig,
        bringup_grace: Duration,
        expected_liveness_interval: Duration,
        liveness: SafetyLiveness,
        factory: WatchdogFactory,
    ) -> std::result::Result<(Self, WatchdogAdmission), WatchdogPreOpenStartError> {
        if !config.enabled {
            let run_scope = WatchdogRunScope::new();
            let (teardown_budget_issuer, teardown_budget_expectation) =
                issue_teardown_budget_authority(run_scope.clone());
            let feed_owner = WatchdogFeedGateOwner::new();
            let teardown_deadline_request = feed_owner.deadline_request();
            return Ok((
                Self {
                    command_tx: None,
                    worker: None,
                    feed_owner,
                    teardown_admitted: false,
                    teardown_deadline_request,
                    run_scope,
                    teardown_budget_issuer,
                    teardown_budget_expectation,
                    composition: None,
                    never_energized_issued: false,
                },
                WatchdogAdmission::DisabledByConfiguration,
            ));
        }
        if bringup_grace.is_zero() {
            return Err(WatchdogPreOpenStartError(anyhow::anyhow!(
                "watchdog bring-up grace must be non-zero"
            )));
        }

        let (command_tx, command_rx) = mpsc::channel();
        let (admission_tx, admission_rx) = oneshot::channel();
        let feed_owner = WatchdogFeedGateOwner::new();
        let worker_feed_gate = feed_owner.gate();
        let teardown_deadline_request = feed_owner.deadline_request();
        let worker_teardown_deadline_request = Arc::clone(&teardown_deadline_request);
        let config = config.clone();
        let worker = std::thread::Builder::new()
            .name("soc-safety-watchdog".to_string())
            .spawn(move || {
                watchdog_worker(
                    config,
                    bringup_grace,
                    expected_liveness_interval,
                    liveness,
                    command_rx,
                    admission_tx,
                    factory,
                    worker_teardown_deadline_request,
                    worker_feed_gate,
                );
            })
            .map_err(|error| {
                WatchdogPreOpenStartError(
                    anyhow::Error::new(error)
                        .context("failed to spawn SoC safety-watchdog owner thread"),
                )
            })?;

        let run_scope = WatchdogRunScope::new();
        let (teardown_budget_issuer, teardown_budget_expectation) =
            issue_teardown_budget_authority(run_scope.clone());
        let mut owner = Self {
            command_tx: Some(command_tx),
            worker: Some(worker),
            feed_owner,
            teardown_admitted: false,
            teardown_deadline_request,
            run_scope,
            teardown_budget_issuer,
            teardown_budget_expectation,
            composition: None,
            never_energized_issued: false,
        };
        let mut admission = match tokio::time::timeout(WATCHDOG_ADMISSION_TIMEOUT, admission_rx)
            .await
        {
            Ok(Ok(admission)) => admission,
            Ok(Err(_)) => {
                owner.command_tx.take();
                let _ = owner.join_worker(DEFAULT_WATCHDOG_STOP_TIMEOUT).await;
                WatchdogAdmission::OpenedOrOutcomeUnknown {
                    reason: "SoC watchdog worker exited without an arm admission; descriptor state is outcome-unknown".to_string(),
                }
            }
            Err(_) => {
                owner.command_tx.take();
                let _ = owner.join_worker(DEFAULT_WATCHDOG_STOP_TIMEOUT).await;
                WatchdogAdmission::OpenedOrOutcomeUnknown {
                    reason: "timed out waiting for SoC watchdog arm admission; descriptor state is outcome-unknown".to_string(),
                }
            }
        };

        if !matches!(admission, WatchdogAdmission::Armed(_)) {
            owner.command_tx.take();
            if let Err(error) = owner.join_worker(DEFAULT_WATCHDOG_STOP_TIMEOUT).await {
                admission = WatchdogAdmission::OpenedOrOutcomeUnknown {
                    reason: format!(
                        "watchdog admission failed and worker termination was not cleanly observed: {error:#}"
                    ),
                };
            }
        }
        Ok((owner, admission))
    }

    pub(crate) async fn enter_mining(&mut self) -> Result<()> {
        anyhow::ensure!(
            !matches!(
                self.composition,
                Some(WatchdogComposition::NoPicSerial)
                    | Some(WatchdogComposition::Bm1396Native)
                    | Some(WatchdogComposition::ClassicAml)
                    | Some(WatchdogComposition::S19kTrack1Serial)
                    | Some(WatchdogComposition::Am2Bm1362Serial)
            ),
            "exact serial watchdog Mining admission requires typed runtime-actor authority"
        );
        self.enter_mining_inner().await
    }

    /// Issue a cloneable, stop-only crash signal. It can irreversibly suppress
    /// future feed admissions without waiting for a kernel watchdog write, but
    /// it cannot feed or disarm the device.
    pub(crate) fn feed_stop_signal(&self) -> WatchdogFeedStopSignal {
        self.feed_owner.stop_signal()
    }

    async fn enter_mining_inner(&mut self) -> Result<()> {
        let tx = self
            .command_tx
            .as_ref()
            .context("watchdog was not armed by this daemon")?;
        let (reply, receipt) = oneshot::channel();
        tx.send(WatchdogCommand::EnterMining { reply })
            .map_err(|_| {
                anyhow::anyhow!("watchdog command channel closed before Mining admission")
            })?;
        match tokio::time::timeout(WATCHDOG_ADMISSION_TIMEOUT, receipt).await {
            Ok(Ok(Ok(PhaseReceipt::MiningAdmitted))) => Ok(()),
            Ok(Ok(Ok(other))) => anyhow::bail!("unexpected watchdog phase receipt: {other:?}"),
            Ok(Ok(Err(reason))) => anyhow::bail!("watchdog refused Mining admission: {reason}"),
            Ok(Err(_)) => anyhow::bail!("watchdog worker exited before Mining admission"),
            Err(_) => anyhow::bail!("timed out waiting for watchdog Mining admission"),
        }
    }

    pub(crate) async fn enter_exact_serial_mining(
        &mut self,
        admission: crate::serial_mining::ExactSerialRuntimeAdmissionPermit,
    ) -> Result<()> {
        anyhow::ensure!(
            admission.run_scope().same_run(&self.run_scope),
            "exact serial runtime admission belongs to another watchdog run"
        );
        match self.composition {
            Some(WatchdogComposition::NoPicSerial) => anyhow::ensure!(
                admission.is_nopic(),
                "NoPic watchdog cannot enter Mining with AM2 actor admission"
            ),
            Some(WatchdogComposition::S19kTrack1Serial) => anyhow::ensure!(
                admission.is_s19k_track1(),
                "S19k Track-1 watchdog requires its distinct serial actor admission"
            ),
            Some(WatchdogComposition::Am2Bm1362Serial) => anyhow::ensure!(
                admission.is_am2_bm1362(),
                "AM2 watchdog cannot enter Mining with NoPic actor admission"
            ),
            Some(composition) => anyhow::bail!(
                "non-serial watchdog composition {composition:?} cannot consume exact serial actor admission"
            ),
            None => anyhow::bail!(
                "watchdog composition was not bound before exact serial Mining admission"
            ),
        }
        self.enter_mining_inner().await
    }

    /// Publish the immutable teardown deadline and submit the actor transition
    /// without awaiting its acknowledgement. This is deliberately synchronous:
    /// a load-bearing physical cutoff must be able to happen immediately after
    /// publication, before scheduler or actor latency consumes CutoffStart.
    pub(crate) fn request_teardown_budget(&mut self) -> Result<WatchdogTeardownRequest> {
        anyhow::ensure!(
            !self.teardown_admitted && self.teardown_deadline_request.get().is_none(),
            "watchdog teardown was already requested; refusing deadline extension"
        );
        let started_at = Instant::now();
        let budget = self
            .teardown_budget_issuer
            .issue_at(started_at, TeardownBudgetPolicy::watchdog_default())?;
        anyhow::ensure!(
            budget
                .view()
                .authorizes(&self.run_scope, &self.teardown_budget_expectation),
            "watchdog-issued teardown budget did not match its retained expectation"
        );
        let deadline = budget.deadline(TeardownStage::FeedDeadline);
        // This one publication is shared by the physical feed gate and worker.
        // It is lock-free, so a watchdog device write already blocked in the
        // kernel cannot delay the caller's load-bearing hardware cutoff.
        if let Err(reason) = self.feed_owner.publish_deadline(deadline) {
            return Ok(WatchdogTeardownRequest {
                budget,
                admission: WatchdogTeardownAdmission::failed(reason.to_string()),
            });
        }

        let admission = match self.command_tx.as_ref() {
            Some(tx) => {
                let (reply, receipt) = oneshot::channel();
                match tx.send(WatchdogCommand::BeginTeardown { deadline, reply }) {
                    Ok(()) => WatchdogTeardownAdmission::pending(receipt),
                    Err(_) => WatchdogTeardownAdmission::failed(
                        "watchdog command channel closed before Teardown admission".to_string(),
                    ),
                }
            }
            None => WatchdogTeardownAdmission::failed(
                "watchdog was not armed by this daemon".to_string(),
            ),
        };

        Ok(WatchdogTeardownRequest { budget, admission })
    }

    /// Observe the actor acknowledgement after the route's physical cutoff.
    /// Positive acknowledgement remains mandatory for Disarm authority.
    pub(crate) async fn observe_teardown_admission(
        &mut self,
        mut admission: WatchdogTeardownAdmission,
        budget: &TeardownBudgetView,
    ) -> std::result::Result<(), String> {
        let result = match admission.immediate_error.take() {
            Some(reason) => Err(reason),
            None => match admission.receipt.take() {
                Some(receipt) => {
                    let deadline = budget.deadline(TeardownStage::CutoffStart);
                    match tokio::time::timeout_at(
                        tokio::time::Instant::from_std(deadline),
                        receipt,
                    )
                    .await
                    {
                        Ok(Ok(Ok(PhaseReceipt::TeardownAdmitted { admitted_at }))) => budget
                            .require_completed_at(TeardownStage::CutoffStart, admitted_at)
                            .map_err(|error| {
                                format!(
                                    "watchdog Teardown admission was acknowledged too late: {error:#}"
                                )
                            }),
                        Ok(Ok(Ok(other))) => {
                            Err(format!("unexpected watchdog phase receipt: {other:?}"))
                        }
                        Ok(Ok(Err(reason))) => {
                            Err(format!("watchdog refused Teardown admission: {reason}"))
                        }
                        Ok(Err(_)) => {
                            Err("watchdog worker exited before Teardown admission".to_string())
                        }
                        Err(_) => Err(
                            "timed out waiting for watchdog Teardown admission before the cutoff-start deadline"
                                .to_string(),
                        ),
                    }
                }
                None => Err("watchdog Teardown admission receipt was already consumed".to_string()),
            },
        };
        if result.is_ok() {
            self.teardown_admitted = true;
        }
        result
    }

    pub(crate) async fn begin_teardown_budget(&mut self) -> Result<TeardownStart> {
        let request = self.request_teardown_budget()?;
        let (budget, admission) = request.into_parts();
        let budget_view = budget.view();
        let admission = self
            .observe_teardown_admission(admission, &budget_view)
            .await;
        Ok(TeardownStart::new(budget, admission))
    }

    pub(crate) async fn begin_teardown(&mut self, grace: Duration) -> Result<()> {
        anyhow::ensure!(
            grace == DEFAULT_WATCHDOG_TEARDOWN_GRACE,
            "legacy teardown caller requested a noncanonical grace; use the watchdog-issued absolute budget"
        );
        let (_budget, admission) = self.begin_teardown_budget().await?.into_parts();
        admission.map_err(anyhow::Error::msg)
    }

    /// Terminally suppress future watchdog feeds as soon as software can no
    /// longer prove the electrical safe state. This never grants disarm and is
    /// intentionally idempotent only at the worker phase level.
    pub(crate) async fn suppress_feeds_terminally(&mut self, reason: String) -> Result<()> {
        self.feed_owner.close_terminal();
        let tx = self
            .command_tx
            .as_ref()
            .context("watchdog was not armed by this daemon")?;
        let (reply, receipt) = oneshot::channel();
        tx.send(WatchdogCommand::SuppressFeeds { reason, reply })
            .map_err(|_| {
                anyhow::anyhow!("watchdog command channel closed before feed suppression")
            })?;
        match tokio::time::timeout(WATCHDOG_ADMISSION_TIMEOUT, receipt).await {
            Ok(Ok(Ok(PhaseReceipt::FeedSuppressed))) => Ok(()),
            Ok(Ok(Ok(other))) => anyhow::bail!("unexpected watchdog phase receipt: {other:?}"),
            Ok(Ok(Err(reason))) => anyhow::bail!("watchdog refused feed suppression: {reason}"),
            Ok(Err(_)) => anyhow::bail!("watchdog worker exited before feed suppression"),
            Err(_) => anyhow::bail!("timed out waiting for watchdog feed suppression"),
        }
    }

    pub(crate) async fn disarm_never_energized(
        mut self,
        evidence: Am2NeverEnergized,
        timeout: Duration,
    ) -> Result<WatchdogCloseoutReceipt> {
        if !evidence.run_scope.same_run(&self.run_scope) {
            anyhow::bail!("watchdog pre-energization evidence belongs to another watchdog/run");
        }
        if self.composition != Some(WatchdogComposition::Am2Bm1362Serial) {
            anyhow::bail!(
                "watchdog pre-energization evidence does not match the owner composition"
            );
        }
        self.feed_owner.close_terminal();
        let tx = self
            .command_tx
            .as_ref()
            .context("watchdog was not armed by this daemon")?;
        let (reply, receipt) = oneshot::channel();
        tx.send(WatchdogCommand::DisarmNeverEnergized { reply })
            .map_err(|_| {
                anyhow::anyhow!("watchdog command channel closed before pre-energization Disarm")
            })?;
        match tokio::time::timeout(timeout, receipt).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(reason))) => {
                anyhow::bail!("watchdog refused pre-energization Disarm: {reason}")
            }
            Ok(Err(_)) => anyhow::bail!(
                "watchdog worker exited without a pre-energization magic-close receipt"
            ),
            Err(_) => anyhow::bail!(
                "timed out after requesting pre-energization watchdog Disarm; magic-close outcome is unknown"
            ),
        }
        self.command_tx.take();
        self.join_worker(timeout).await?;
        Ok(WatchdogCloseoutReceipt::magic_close_write_completed_and_worker_exit_observed())
    }

    /// Cleanly close an armed Track-1 watchdog after an SLA refusal while the
    /// exact stock owner still owns the inherited rails.  This is intentionally
    /// distinct from terminal SafeOff: it performs no reset/GPIO mutation and
    /// is invalid after even a route claim.
    pub(crate) async fn disarm_s19k_track1_never_handoff(
        mut self,
        evidence: S19kTrack1NeverHandoff,
        timeout: Duration,
    ) -> Result<WatchdogCloseoutReceipt> {
        if !evidence.run_scope.same_run(&self.run_scope) {
            anyhow::bail!("S19k Track-1 pre-handoff evidence belongs to another watchdog/run");
        }
        if self.composition.is_some() {
            anyhow::bail!("S19k Track-1 pre-handoff disarm requires an unclaimed watchdog route");
        }
        self.feed_owner.close_terminal();
        let tx = self
            .command_tx
            .as_ref()
            .context("watchdog was not armed by this daemon")?;
        let (reply, receipt) = oneshot::channel();
        tx.send(WatchdogCommand::DisarmNeverEnergized { reply })
            .map_err(|_| {
                anyhow::anyhow!("watchdog command channel closed before S19k pre-handoff Disarm")
            })?;
        match tokio::time::timeout(timeout, receipt).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(reason))) => {
                anyhow::bail!("watchdog refused S19k pre-handoff Disarm: {reason}")
            }
            Ok(Err(_)) => anyhow::bail!(
                "watchdog worker exited without an S19k pre-handoff magic-close receipt"
            ),
            Err(_) => anyhow::bail!(
                "timed out after requesting S19k pre-handoff watchdog Disarm; magic-close outcome is unknown"
            ),
        }
        self.command_tx.take();
        self.join_worker(timeout).await?;
        Ok(WatchdogCloseoutReceipt::magic_close_write_completed_and_worker_exit_observed())
    }

    pub(crate) async fn disarm_am3_bb_never_energized(
        mut self,
        evidence: Am3BbNeverEnergized,
        timeout: Duration,
    ) -> Result<WatchdogCloseoutReceipt> {
        if !evidence.run_scope.same_run(&self.run_scope) {
            anyhow::bail!("AM3-BB pre-energization evidence belongs to another watchdog/run");
        }
        if self.composition != Some(WatchdogComposition::Am3Bb) {
            anyhow::bail!("AM3-BB pre-energization evidence does not match the owner composition");
        }
        self.feed_owner.close_terminal();
        let tx = self
            .command_tx
            .as_ref()
            .context("watchdog was not armed by this daemon")?;
        let (reply, receipt) = oneshot::channel();
        tx.send(WatchdogCommand::DisarmNeverEnergized { reply })
            .map_err(|_| {
                anyhow::anyhow!(
                    "watchdog command channel closed before AM3-BB pre-energization Disarm"
                )
            })?;
        match tokio::time::timeout(timeout, receipt).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(reason))) => {
                anyhow::bail!("watchdog refused AM3-BB pre-energization Disarm: {reason}")
            }
            Ok(Err(_)) => anyhow::bail!(
                "watchdog worker exited without an AM3-BB pre-energization magic-close receipt"
            ),
            Err(_) => anyhow::bail!(
                "timed out after requesting AM3-BB pre-energization watchdog Disarm; magic-close outcome is unknown"
            ),
        }
        self.command_tx.take();
        self.join_worker(timeout).await?;
        Ok(WatchdogCloseoutReceipt::magic_close_write_completed_and_worker_exit_observed())
    }

    pub(crate) async fn disarm_and_join(
        mut self,
        permit: WatchdogDisarmPermit,
        timeout: Duration,
    ) -> Result<WatchdogCloseoutReceipt> {
        if !permit.scope.same_run(&self.run_scope) {
            anyhow::bail!("watchdog Disarm permit belongs to another watchdog/run scope");
        }
        if self.composition != Some(permit.composition) {
            anyhow::bail!(
                "watchdog Disarm permit composition {:?} does not match owner binding {:?}",
                permit.composition,
                self.composition
            );
        }
        if !self.teardown_admitted {
            anyhow::bail!("watchdog Disarm requires an actor-observed Teardown admission");
        }
        let absolute_deadlines = match &permit.teardown {
            #[cfg(test)]
            WatchdogTeardownAuthority::TestRelative => None,
            WatchdogTeardownAuthority::Absolute(authority) => {
                anyhow::ensure!(
                    authority.authorizes(&self.run_scope, &self.teardown_budget_expectation),
                    "watchdog Disarm teardown authority belongs to another run or issuer"
                );
                let requested_deadline = self
                    .teardown_deadline_request
                    .get()
                    .copied()
                    .context("watchdog Disarm has no locally published teardown deadline")?;
                anyhow::ensure!(
                    authority.deadline(TeardownStage::FeedDeadline) == requested_deadline,
                    "watchdog Disarm teardown authority does not match the locally published feed deadline"
                );
                Some((
                    authority.deadline(TeardownStage::TerminalReceipt),
                    authority.deadline(TeardownStage::WorkerJoin),
                ))
            }
        };
        self.feed_owner.close_terminal();
        let tx = self
            .command_tx
            .as_ref()
            .context("watchdog was not armed by this daemon")?;
        match &permit.teardown {
            #[cfg(test)]
            WatchdogTeardownAuthority::TestRelative => {}
            WatchdogTeardownAuthority::Absolute(authority) => {
                // This timestamp is the synchronous command-send boundary, not
                // the earlier manifest/permit construction time. A task
                // descheduled between those operations cannot spend the Disarm
                // reserve and still authorize magic-close.
                authority
                    .require_disarm_command_started_at(Instant::now())
                    .context("watchdog Disarm command missed its absolute start deadline")?;
            }
        }
        let (reply, receipt) = oneshot::channel();
        tx.send(WatchdogCommand::Disarm { permit, reply })
            .map_err(|_| anyhow::anyhow!("watchdog command channel closed before Disarm"))?;

        let receipt_result = match absolute_deadlines {
            Some((receipt_deadline, _)) => {
                tokio::time::timeout_at(tokio::time::Instant::from_std(receipt_deadline), receipt)
                    .await
            }
            None => tokio::time::timeout(timeout, receipt).await,
        };
        let completed_at = match receipt_result {
            Ok(Ok(Ok(completed_at))) => completed_at,
            Ok(Ok(Err(reason))) => anyhow::bail!("watchdog refused or failed Disarm: {reason}"),
            Ok(Err(_)) => {
                self.command_tx.take();
                let worker_diagnostic = match absolute_deadlines {
                    Some((_, deadline)) => match self.join_worker_until(deadline).await {
                        Ok(()) => "worker exit was observed without a receipt".to_string(),
                        Err(error) => format!("worker termination diagnostic: {error:#}"),
                    },
                    None => match self.join_worker(timeout).await {
                        Ok(()) => "worker exit was observed without a receipt".to_string(),
                        Err(error) => format!("worker termination diagnostic: {error:#}"),
                    },
                };
                anyhow::bail!(
                    "watchdog worker exited without a magic-close receipt; magic-close outcome is unknown; {worker_diagnostic}"
                );
            }
            Err(_) => anyhow::bail!(
                "timed out after requesting watchdog Disarm; magic-close outcome is unknown"
            ),
        };

        if let Some((receipt_deadline, _)) = absolute_deadlines {
            anyhow::ensure!(
                completed_at < receipt_deadline,
                "watchdog magic-close completed at or after the absolute terminal-receipt deadline"
            );
        }

        self.command_tx.take();
        match absolute_deadlines {
            Some((_, join_deadline)) => self.join_worker_until(join_deadline).await?,
            None => self.join_worker(timeout).await?,
        }
        Ok(WatchdogCloseoutReceipt::magic_close_write_completed_and_worker_exit_observed())
    }

    async fn join_worker(&mut self, timeout: Duration) -> Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        match join_thread_bounded(worker, timeout).await {
            ThreadStopOutcome::Joined => Ok(()),
            ThreadStopOutcome::Panicked => anyhow::bail!("SoC watchdog worker panicked"),
            ThreadStopOutcome::TimedOut => anyhow::bail!(
                "SoC watchdog worker termination was not observed before the deadline"
            ),
        }
    }

    async fn join_worker_until(&mut self, deadline: Instant) -> Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        match join_thread_until(worker, deadline).await {
            ThreadStopOutcome::Joined => Ok(()),
            ThreadStopOutcome::Panicked => anyhow::bail!("SoC watchdog worker panicked"),
            ThreadStopOutcome::TimedOut => anyhow::bail!(
                "SoC watchdog worker termination was not observed before the absolute deadline"
            ),
        }
    }
}

impl Drop for SafetyWatchdogOwner {
    fn drop(&mut self) {
        // Sender loss is the abnormal-stop command. The worker permanently
        // retains its armed descriptor without magic close; dropping the
        // JoinHandle detaches only until that channel loss is observed and
        // never grants disarm authority.
        self.command_tx.take();
        self.worker.take();
    }
}

fn watchdog_worker(
    config: WatchdogConfig,
    bringup_grace: Duration,
    expected_liveness_interval: Duration,
    liveness: SafetyLiveness,
    command_rx: mpsc::Receiver<WatchdogCommand>,
    admission_tx: oneshot::Sender<WatchdogAdmission>,
    factory: WatchdogFactory,
    teardown_deadline_request: Arc<OnceLock<Instant>>,
    feed_gate: WatchdogFeedGate,
) {
    let watchdog = match factory() {
        Ok(watchdog) => watchdog,
        Err(reason) => {
            let _ = admission_tx.send(WatchdogAdmission::UnavailableBeforeOpen { reason });
            return;
        }
    };
    // Install fail-closed retention immediately after open. No subsequent
    // error, panic, or channel-loss path may implicitly close the armed fd.
    let mut watchdog = RetainedArmedWatchdog::new(watchdog);
    let effective_timeout_s = match watchdog
        .as_ref()
        .expect("newly retained watchdog device")
        .set_timeout(config.timeout_s)
    {
        Ok(timeout) => timeout,
        Err(reason) => {
            let _ = admission_tx.send(WatchdogAdmission::OpenedOrOutcomeUnknown {
                reason: format!("failed to configure watchdog timeout: {reason}"),
            });
            return;
        }
    };
    let kick_secs = watchdog_interval_secs(config.kick_interval_s as u64);
    if effective_timeout_s as u64 <= kick_secs {
        let _ = admission_tx.send(WatchdogAdmission::OpenedOrOutcomeUnknown {
            reason: format!(
                "kernel effective watchdog timeout {effective_timeout_s}s is not greater than kick interval {kick_secs}s"
            ),
        });
        return;
    }
    match feed_gate.try_kick(|| {
        watchdog
            .as_ref()
            .expect("configured retained watchdog device")
            .kick()
    }) {
        Ok(WatchdogFeedOutcome::Kicked) => {}
        Ok(outcome) => {
            let _ = admission_tx.send(WatchdogAdmission::OpenedOrOutcomeUnknown {
                reason: format!("initial watchdog kick was withheld by feed gate: {outcome:?}"),
            });
            return;
        }
        Err(reason) => {
            let _ = admission_tx.send(WatchdogAdmission::OpenedOrOutcomeUnknown {
                reason: format!("initial watchdog kick failed: {reason}"),
            });
            return;
        }
    }

    // Bringup time starts only after the FD is configured and the initial kick
    // has completed. Arm admission can therefore never describe an already
    // expired phase, even if device open/configuration was slow.
    let bringup_deadline = Instant::now() + bringup_grace;

    let receipt = WatchdogArmReceipt {
        requested_timeout_s: config.timeout_s,
        effective_timeout_s,
        kick_interval_s: kick_secs,
    };
    if admission_tx
        .send(WatchdogAdmission::Armed(receipt.clone()))
        .is_err()
    {
        warn!("watchdog admission owner disappeared; leaving watchdog armed");
        return;
    }
    info!(
        requested_timeout_s = receipt.requested_timeout_s,
        effective_timeout_s = receipt.effective_timeout_s,
        kick_interval_s = receipt.kick_interval_s,
        "fail-closed SoC watchdog admitted in bounded Bringup phase"
    );

    let stall_limit = watchdog_stall_limit(
        effective_timeout_s as u64,
        kick_secs,
        Some(expected_liveness_interval),
    );
    let mut phase = WatchdogPhase::Bringup {
        deadline: bringup_deadline,
    };
    let mut next_kick = Instant::now() + Duration::from_secs(kick_secs);

    loop {
        let now = Instant::now();
        latch_expired_deadline(&mut phase, now);
        latch_requested_teardown_deadline(&mut phase, &teardown_deadline_request, now);
        latch_expired_deadline(&mut phase, now);
        let next_phase_deadline = match phase {
            WatchdogPhase::Bringup { deadline } | WatchdogPhase::Teardown { deadline } => {
                Some(deadline)
            }
            WatchdogPhase::Mining { .. } | WatchdogPhase::FeedSuppressed(_) => None,
        };
        let next_event = next_phase_deadline
            .map(|deadline| deadline.min(next_kick))
            .unwrap_or(next_kick);
        let wait = next_event.saturating_duration_since(now);

        match command_rx.recv_timeout(wait) {
            Ok(command) => {
                if handle_command(command, &mut phase, &liveness, &mut watchdog, &feed_gate) {
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                feed_gate.close_terminal();
                warn!("watchdog command owner disappeared; leaving watchdog armed");
                retain_armed_watchdog_descriptor(&mut watchdog);
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                latch_expired_deadline(&mut phase, now);
                latch_requested_teardown_deadline(&mut phase, &teardown_deadline_request, now);
                latch_expired_deadline(&mut phase, now);
                if now < next_kick {
                    continue;
                }
                service_watchdog_kick_deadline(
                    &mut phase,
                    &liveness,
                    stall_limit,
                    &watchdog,
                    &feed_gate,
                );
                next_kick = now + Duration::from_secs(kick_secs);
            }
        }
    }
}

/// Apply the one-way owner-published teardown deadline independently of the
/// command reply path. The ordinary command still supplies an actor receipt;
/// this local latch only guarantees finite feed behavior if acknowledgement is
/// delayed while terminal code is entering fallible physical I/O.
fn latch_requested_teardown_deadline(
    phase: &mut WatchdogPhase,
    request: &OnceLock<Instant>,
    now: Instant,
) {
    let Some(deadline) = request.get().copied() else {
        return;
    };
    match phase {
        WatchdogPhase::Bringup { deadline: existing } if *existing <= now => {
            *phase = WatchdogPhase::FeedSuppressed(FeedSuppressionReason::BringupDeadlineExpired);
        }
        WatchdogPhase::Bringup { .. } | WatchdogPhase::Mining { .. } => {
            if deadline <= now {
                *phase =
                    WatchdogPhase::FeedSuppressed(FeedSuppressionReason::TeardownDeadlineExpired);
            } else {
                *phase = WatchdogPhase::Teardown { deadline };
            }
        }
        WatchdogPhase::Teardown { deadline: admitted } => {
            // The local request is write-once and the command carries the same
            // instant. Preserve the earliest deadline defensively.
            *admitted = (*admitted).min(deadline);
        }
        WatchdogPhase::FeedSuppressed(_) => {}
    }
}

/// Services exactly one scheduled feed deadline.
///
/// Keeping this decision separate from the blocking receiver loop makes the
/// terminal suppression invariant directly executable: once a suppression
/// receipt has been emitted, any number of later deadlines must remain inert.
fn service_watchdog_kick_deadline(
    phase: &mut WatchdogPhase,
    liveness: &SafetyLiveness,
    stall_limit: u64,
    watchdog: &RetainedArmedWatchdog,
    feed_gate: &WatchdogFeedGate,
) {
    let should_kick = match phase {
        WatchdogPhase::Bringup { .. } | WatchdogPhase::Teardown { .. } => true,
        WatchdogPhase::Mining { last_live, stalls } => {
            let current = liveness.snapshot();
            let (should_kick, new_last, new_stalls) =
                watchdog_kick_decision(current, *last_live, *stalls, stall_limit);
            *last_live = new_last;
            *stalls = new_stalls;
            if !should_kick {
                *phase =
                    WatchdogPhase::FeedSuppressed(FeedSuppressionReason::MiningLivenessStalled);
                error!(
                    stalls = new_stalls,
                    stall_limit, "watchdog safety liveness stalled; feed suppression is terminal"
                );
            }
            should_kick
        }
        WatchdogPhase::FeedSuppressed(reason) => {
            error!(?reason, "watchdog feed remains terminally suppressed");
            false
        }
    };
    if should_kick {
        if let Some(device) = watchdog.as_ref() {
            match feed_gate.try_kick(|| device.kick()) {
                Ok(WatchdogFeedOutcome::Kicked) => {}
                Ok(outcome) => {
                    warn!(
                        ?outcome,
                        "exact watchdog feed gate withheld a scheduled kick"
                    );
                }
                Err(reason) => {
                    error!(%reason, "watchdog kick failed; feed loop continues but reset may occur");
                }
            }
        }
    } else {
        feed_gate.close_terminal();
    }
}

fn latch_expired_deadline(phase: &mut WatchdogPhase, now: Instant) {
    let reason = match phase {
        WatchdogPhase::Bringup { deadline } if !watchdog_teardown_kick_allowed(*deadline, now) => {
            Some(FeedSuppressionReason::BringupDeadlineExpired)
        }
        WatchdogPhase::Teardown { deadline } if !watchdog_teardown_kick_allowed(*deadline, now) => {
            Some(FeedSuppressionReason::TeardownDeadlineExpired)
        }
        _ => None,
    };
    if let Some(reason) = reason {
        error!(
            ?reason,
            "watchdog deadline expired; feed suppression is terminal"
        );
        *phase = WatchdogPhase::FeedSuppressed(reason);
    }
}

/// Retain an armed descriptor on every abnormal worker exit. An ordinary close
/// is not a portable substitute for an intentionally omitted magic close.
fn retain_armed_watchdog_descriptor(watchdog: &mut RetainedArmedWatchdog) {
    watchdog.retain();
}

fn attempt_magic_close_retaining_on_failure(
    watchdog: &mut RetainedArmedWatchdog,
) -> std::result::Result<(), String> {
    let attempt = match watchdog.as_mut() {
        Some(device) => {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| device.try_close_magic()))
        }
        None => return Err("watchdog device was already consumed".to_string()),
    };
    match attempt {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            retain_armed_watchdog_descriptor(watchdog);
            Err(error)
        }
        Err(payload) => {
            retain_armed_watchdog_descriptor(watchdog);
            std::panic::resume_unwind(payload)
        }
    }
}

fn handle_command(
    command: WatchdogCommand,
    phase: &mut WatchdogPhase,
    liveness: &SafetyLiveness,
    watchdog: &mut RetainedArmedWatchdog,
    feed_gate: &WatchdogFeedGate,
) -> bool {
    handle_command_at(
        command,
        phase,
        liveness,
        watchdog,
        feed_gate,
        Instant::now(),
    )
}

fn handle_command_at(
    command: WatchdogCommand,
    phase: &mut WatchdogPhase,
    liveness: &SafetyLiveness,
    watchdog: &mut RetainedArmedWatchdog,
    feed_gate: &WatchdogFeedGate,
    physical_boundary: Instant,
) -> bool {
    latch_expired_deadline(phase, physical_boundary);
    match command {
        WatchdogCommand::EnterMining { reply } => {
            let result = match phase {
                WatchdogPhase::Bringup { .. } => {
                    *phase = WatchdogPhase::Mining {
                        last_live: liveness.snapshot(),
                        stalls: 0,
                    };
                    Ok(PhaseReceipt::MiningAdmitted)
                }
                WatchdogPhase::FeedSuppressed(reason) => {
                    Err(format!("feed already suppressed: {reason:?}"))
                }
                other => Err(format!("invalid phase for Mining admission: {other:?}")),
            };
            let _ = reply.send(result);
            false
        }
        WatchdogCommand::BeginTeardown { deadline, reply } => {
            let result = if deadline <= physical_boundary {
                Err("teardown deadline is not in the future".to_string())
            } else {
                match phase {
                    WatchdogPhase::Bringup { .. } | WatchdogPhase::Mining { .. } => {
                        *phase = WatchdogPhase::Teardown { deadline };
                        Ok(PhaseReceipt::TeardownAdmitted {
                            admitted_at: physical_boundary,
                        })
                    }
                    WatchdogPhase::Teardown { deadline: admitted } if *admitted == deadline => {
                        // The owner publishes this exact deadline through the
                        // local one-way latch before queueing the command. If
                        // the worker observes that latch first, the matching
                        // command is acknowledgement, not an extension.
                        Ok(PhaseReceipt::TeardownAdmitted {
                            admitted_at: physical_boundary,
                        })
                    }
                    WatchdogPhase::Teardown { .. } => {
                        Err("teardown already admitted; deadline extension refused".to_string())
                    }
                    WatchdogPhase::FeedSuppressed(reason) => {
                        Err(format!("feed already suppressed: {reason:?}"))
                    }
                }
            };
            let _ = reply.send(result);
            false
        }
        WatchdogCommand::SuppressFeeds { reason, reply } => {
            feed_gate.close_terminal();
            let result = match phase {
                WatchdogPhase::FeedSuppressed(existing) => {
                    Err(format!("feed already suppressed: {existing:?}"))
                }
                WatchdogPhase::Bringup { .. }
                | WatchdogPhase::Mining { .. }
                | WatchdogPhase::Teardown { .. } => {
                    *phase = WatchdogPhase::FeedSuppressed(
                        FeedSuppressionReason::ExternallyReportedSafetyFailure(reason),
                    );
                    Ok(PhaseReceipt::FeedSuppressed)
                }
            };
            let _ = reply.send(result);
            false
        }
        WatchdogCommand::DisarmNeverEnergized { reply } => {
            feed_gate.close_terminal();
            let result = match phase {
                WatchdogPhase::Bringup { deadline } if *deadline > physical_boundary => {
                    attempt_magic_close_retaining_on_failure(watchdog)
                }
                WatchdogPhase::FeedSuppressed(reason) => Err(format!(
                    "terminal feed suppression forbids pre-energization Disarm: {reason:?}"
                )),
                other => Err(format!(
                    "invalid phase for pre-energization Disarm: {other:?}"
                )),
            };
            if result.is_err() {
                retain_armed_watchdog_descriptor(watchdog);
            } else {
                watchdog.close_after_magic_write();
            }
            let _ = reply.send(result);
            true
        }
        WatchdogCommand::Disarm { permit, reply } => {
            feed_gate.close_terminal();
            // DisarmStart is the latest time at which the physical worker may
            // *admit* the non-cancellable kernel magic-close write. Character-
            // device completion is then reported separately and the owner must
            // still observe worker exit. A blocking write cannot be revoked
            // safely after it begins, so this is intentionally not described as
            // a completion deadline.
            let result = match phase {
                WatchdogPhase::Teardown { deadline } if *deadline > physical_boundary => {
                    let physical_started_at = physical_boundary;
                    let authority_result = match &permit.teardown {
                        #[cfg(test)]
                        WatchdogTeardownAuthority::TestRelative => Ok(()),
                        WatchdogTeardownAuthority::Absolute(authority) => {
                            if authority.deadline(TeardownStage::FeedDeadline) != *deadline {
                                Err("watchdog Disarm authority feed deadline differs from the worker phase".to_string())
                            } else {
                                authority
                                    .require_disarm_command_started_at(physical_started_at)
                                    .map_err(|error| format!(
                                        "watchdog Disarm reached the physical magic-close boundary after its absolute start deadline: {error}"
                                    ))
                            }
                        }
                    };
                    authority_result.and_then(|()| {
                        attempt_magic_close_retaining_on_failure(watchdog).map(|()| Instant::now())
                    })
                }
                WatchdogPhase::FeedSuppressed(reason) => Err(format!(
                    "terminal feed suppression forbids Disarm: {reason:?}"
                )),
                other => Err(format!("invalid phase for Disarm: {other:?}")),
            };
            if result.is_err() {
                retain_armed_watchdog_descriptor(watchdog);
            } else {
                watchdog.close_after_magic_write();
            }
            let _ = reply.send(result);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Mutex;

    #[test]
    fn watchdog_closeout_receipt_is_opaque_move_only_and_owner_minted() {
        let watchdog_source = include_str!("safety_watchdog.rs");
        let production = watchdog_source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production watchdog source");
        let declaration_start = production
            .find("#[derive(Debug)]\npub(crate) struct WatchdogCloseoutReceipt")
            .expect("opaque watchdog closeout receipt declaration");
        let declaration_end = production[declaration_start..]
            .find("\n\n#[derive(Debug, Clone, PartialEq, Eq)]\nenum FeedSuppressionReason")
            .map(|offset| declaration_start + offset)
            .expect("bounded watchdog closeout receipt declaration");
        let declaration = &production[declaration_start..declaration_end];

        assert!(declaration.contains("_private: ()"));
        assert!(declaration
            .contains("fn magic_close_write_completed_and_worker_exit_observed() -> Self"));
        assert!(!declaration.contains("pub(crate) fn"));
        assert!(!declaration.contains("Clone"));
        assert!(!declaration.contains("Copy"));
        assert!(!production.contains("Clone for WatchdogCloseoutReceipt"));
        assert!(!production.contains("Copy for WatchdogCloseoutReceipt"));

        let owner_mint = concat!(
            "WatchdogCloseoutReceipt",
            "::magic_close_write_completed_and_worker_exit_observed()"
        );
        assert_eq!(
            production.matches(owner_mint).count(),
            4,
            "AM2 never-energized, S19k never-handoff, AM3-BB never-energized, and terminal disarm are the only receipt minters"
        );

        for (name, source) in [
            ("serial", include_str!("../serial_mining.rs")),
            ("hybrid", include_str!("../s19j_hybrid_mining.rs")),
            ("AM3-BB", include_str!("../am3_bb_mining.rs")),
        ] {
            let sibling_production = source
                .split("\n#[cfg(test)]\nmod tests {")
                .next()
                .expect("production sibling source");
            assert!(
                !sibling_production.contains(concat!("WatchdogCloseoutReceipt", "::")),
                "{name} must not construct or inspect the opaque watchdog closeout receipt"
            );
            assert!(
                !sibling_production.contains(concat!("WatchdogCloseoutReceipt", " {")),
                "{name} must not construct the opaque watchdog closeout receipt"
            );
        }
    }

    #[test]
    fn production_watchdog_disarm_uses_only_move_only_exact_route_manifests() {
        for (name, source, manifest, constructor) in [
            (
                "serial",
                include_str!("../serial_mining.rs"),
                "NoPicWatchdogShutdownManifest::new(",
                "WatchdogDisarmPermit::from_nopic_manifest(",
            ),
            (
                "serial",
                include_str!("../serial_mining.rs"),
                "Am2SerialWatchdogShutdownManifest::new(",
                "WatchdogDisarmPermit::from_am2_serial_manifest(",
            ),
            (
                "hybrid",
                include_str!("../s19j_hybrid_mining.rs"),
                "HybridWatchdogShutdownManifest::new(",
                "WatchdogDisarmPermit::from_hybrid_manifest(",
            ),
            (
                "AM3-BB",
                include_str!("../am3_bb_mining.rs"),
                "Am3BbWatchdogShutdownManifest::new(",
                "WatchdogDisarmPermit::from_am3_bb_manifest(",
            ),
        ] {
            let production = source
                .split("\n#[cfg(test)]\nmod tests {")
                .next()
                .expect("production source");
            assert!(
                production.contains(manifest),
                "{name} production must construct {manifest}"
            );
            assert!(
                production.contains(constructor),
                "{name} production must consume {constructor}"
            );
            assert!(
                !production.contains("WatchdogDisarmPermit::from_evidence_set("),
                "{name} production must not construct a type-erased evidence roster"
            );
            assert!(
                !production.contains("WatchdogDisarmPermit::from_evidence("),
                "{name} production must not borrow evidence to mint reusable authority"
            );
        }

        let watchdog_source = include_str!("safety_watchdog.rs");
        assert!(watchdog_source.contains("#[cfg(test)]\n    pub(crate) fn from_evidence<M, Q, S>("));
        assert!(
            watchdog_source.contains("#[cfg(test)]\n    pub(crate) fn from_evidence_set<Q, S>(")
        );
        for manifest in [
            "NoPicWatchdogShutdownManifest",
            "Am2SerialWatchdogShutdownManifest",
            "HybridWatchdogShutdownManifest",
            "Am3BbWatchdogShutdownManifest",
        ] {
            let declaration = format!("pub(crate) struct {manifest}");
            let body = watchdog_source
                .split(&declaration)
                .nth(1)
                .unwrap_or_else(|| panic!("missing {manifest}"))
                .split(&format!("impl {manifest}"))
                .next()
                .expect("bounded manifest declaration");
            assert!(!body.contains("Clone"));
            assert!(!body.contains("Copy"));
        }
        assert!(
            watchdog_source
                .matches("self.safe_off.same_teardown_budget(&self.teardown_disarm)")
                .count()
                >= 2
        );
        assert!(watchdog_source.contains(".require_disarm_command_started_at(Instant::now())"));
        assert!(watchdog_source.contains("#[cfg(test)]\n    TestRelative"));
    }

    #[derive(Default)]
    struct FakeState {
        events: Mutex<Vec<&'static str>>,
        close_fails: AtomicBool,
        panic_on_close: AtomicBool,
        kick_fails: AtomicBool,
        set_timeout_fails: AtomicBool,
        panic_on_set_timeout: AtomicBool,
        drops_armed: AtomicUsize,
    }

    struct FakeWatchdog {
        state: Arc<FakeState>,
        closed: bool,
    }

    impl Drop for FakeWatchdog {
        fn drop(&mut self) {
            if !self.closed {
                self.state.drops_armed.fetch_add(1, Ordering::SeqCst);
                self.state.events.lock().unwrap().push("drop-armed");
            }
        }
    }

    impl WatchdogDevice for FakeWatchdog {
        fn set_timeout(&self, seconds: u32) -> std::result::Result<u32, String> {
            self.state.events.lock().unwrap().push("set-timeout");
            if self.state.panic_on_set_timeout.load(Ordering::SeqCst) {
                panic!("scripted watchdog worker panic");
            }
            if self.state.set_timeout_fails.load(Ordering::SeqCst) {
                return Err("scripted set-timeout failure".to_string());
            }
            Ok(seconds)
        }

        fn kick(&self) -> std::result::Result<(), String> {
            self.state.events.lock().unwrap().push("kick");
            if self.state.kick_fails.load(Ordering::SeqCst) {
                return Err("scripted kick failure".to_string());
            }
            Ok(())
        }

        fn try_close_magic(&mut self) -> std::result::Result<(), String> {
            self.state.events.lock().unwrap().push("magic-close");
            if self.state.panic_on_close.load(Ordering::SeqCst) {
                panic!("scripted magic-close panic");
            }
            if self.state.close_fails.load(Ordering::SeqCst) {
                return Err("scripted close failure".to_string());
            }
            self.closed = true;
            Ok(())
        }
    }

    struct CompleteActors;
    impl evidence_sealed::Sealed for CompleteActors {}
    impl ActorQuiescenceEvidence for CompleteActors {
        fn all_hardware_actors_quiesced(&self) -> bool {
            true
        }
    }
    struct CompleteMutations;
    impl evidence_sealed::Sealed for CompleteMutations {}
    impl MutationBarrierEvidence for CompleteMutations {
        fn hardware_mutations_closed_and_drained(&self) -> bool {
            true
        }
    }
    struct CompleteSafeOff;
    impl evidence_sealed::Sealed for CompleteSafeOff {}
    impl SoftwareSafeOffEvidence for CompleteSafeOff {
        fn software_safe_off_completed(&self) -> bool {
            true
        }
    }
    struct Incomplete;
    impl evidence_sealed::Sealed for Incomplete {}
    impl ActorQuiescenceEvidence for Incomplete {
        fn all_hardware_actors_quiesced(&self) -> bool {
            false
        }
    }
    impl SoftwareSafeOffEvidence for Incomplete {
        fn software_safe_off_completed(&self) -> bool {
            false
        }
    }
    impl MutationBarrierEvidence for Incomplete {
        fn hardware_mutations_closed_and_drained(&self) -> bool {
            false
        }
    }

    fn config() -> WatchdogConfig {
        WatchdogConfig {
            enabled: true,
            timeout_s: 30,
            kick_interval_s: 5,
        }
    }

    async fn fake_owner(
        state: Arc<FakeState>,
        bringup_grace: Duration,
    ) -> (SafetyWatchdogOwner, SafetyLiveness) {
        let liveness = SafetyLiveness::default();
        let factory_state = Arc::clone(&state);
        let (owner, admission) = SafetyWatchdogOwner::start_with_factory(
            &config(),
            bringup_grace,
            Duration::from_secs(2),
            liveness.clone(),
            Box::new(move || {
                Ok(Box::new(FakeWatchdog {
                    state: factory_state,
                    closed: false,
                }))
            }),
        )
        .await
        .unwrap();
        assert!(matches!(admission, WatchdogAdmission::Armed(_)));
        (owner, liveness)
    }

    #[test]
    fn s17_cutoff_evidence_requires_every_actual_outcome_and_its_own_issuer() {
        let scope = WatchdogRunScope::new();
        let (mut issuer, _) = issue_teardown_budget_authority(scope.clone());
        let (mut foreign_issuer, _) = issue_teardown_budget_authority(scope);
        let budget = issuer
            .issue_at(Instant::now(), TeardownBudgetPolicy::watchdog_default())
            .unwrap();
        let view = budget.view();
        let authority = budget.begin_disarm_at(Instant::now()).unwrap();
        let foreign = foreign_issuer
            .issue_at(Instant::now(), TeardownBudgetPolicy::watchdog_default())
            .unwrap();
        for outcomes in [
            (false, true, true, true),
            (true, false, true, true),
            (true, true, false, true),
            (true, true, true, false),
        ] {
            let evidence = crate::s17_hybrid_mining::S17SafeOffEvidence::outcomes_for_test(
                view.clone(),
                outcomes.0,
                outcomes.1,
                outcomes.2,
                outcomes.3,
            );
            assert!(validate_s17_safe_off(&evidence, &authority).is_err());
        }
        let complete = crate::s17_hybrid_mining::S17SafeOffEvidence::outcomes_for_test(
            view, true, true, true, true,
        );
        assert!(validate_s17_safe_off(&complete, &authority).is_ok());
        assert!(
            validate_s17_safe_off(&complete, &foreign.begin_disarm_at(Instant::now()).unwrap())
                .is_err(),
            "even another budget for the same nominal run must not substitute its issuer"
        );
    }

    #[test]
    fn s17_route_scope_cannot_be_claimed_as_another_composition() {
        let mut owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        owner.claim_s17_route_scope().unwrap();
        assert!(owner.claim_s17_route_scope().is_err());
        assert!(owner.claim_hybrid_route_scope().is_err());
        assert!(owner.claim_am3_bb_route_scope().is_err());
    }

    #[test]
    fn bm1398_route_scope_cannot_be_reused_or_claimed_by_another_composition() {
        let mut owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        owner.claim_bm1398_route_scope().unwrap();
        assert!(owner.claim_bm1398_route_scope().is_err());
        assert!(owner.claim_s17_route_scope().is_err());
        assert!(owner.claim_hybrid_route_scope().is_err());
        assert!(owner
            .claim_serial_route_scope(SerialWatchdogComposition::Am2Bm1362)
            .is_err());
        let mut s17 = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        s17.claim_s17_route_scope().unwrap();
        assert!(s17.claim_bm1398_route_scope().is_err());
    }

    fn test_feed_gate() -> (WatchdogFeedGateOwner, WatchdogFeedGate) {
        let owner = WatchdogFeedGateOwner::new();
        let gate = owner.gate();
        (owner, gate)
    }

    #[test]
    fn mining_stall_decision_has_no_zero_is_healthy_sentinel() {
        assert_eq!(watchdog_kick_decision(0, 0, 0, 2), (true, 0, 1));
        assert_eq!(watchdog_kick_decision(0, 0, 1, 2), (false, 0, 2));
    }

    #[test]
    fn expired_deadline_latches_and_cannot_return_to_mining() {
        let mut phase = WatchdogPhase::Bringup {
            deadline: Instant::now(),
        };
        latch_expired_deadline(&mut phase, Instant::now());
        assert!(matches!(phase, WatchdogPhase::FeedSuppressed(_)));
        let (reply, mut receipt) = oneshot::channel();
        let mut device = RetainedArmedWatchdog::empty();
        let (_feed_owner, feed_gate) = test_feed_gate();
        assert!(!handle_command(
            WatchdogCommand::EnterMining { reply },
            &mut phase,
            &SafetyLiveness::default(),
            &mut device,
            &feed_gate,
        ));
        assert!(receipt.try_recv().unwrap().is_err());
    }

    #[test]
    fn expired_teardown_rejects_late_disarm_without_magic_close() {
        let state = Arc::new(FakeState::default());
        let mut phase = WatchdogPhase::Teardown {
            deadline: Instant::now(),
        };
        let mut device = RetainedArmedWatchdog::new(Box::new(FakeWatchdog {
            state: Arc::clone(&state),
            closed: false,
        }));
        let permit = WatchdogDisarmPermit::from_evidence(
            WatchdogRunScope::new(),
            &CompleteMutations,
            &CompleteActors,
            &CompleteSafeOff,
        )
        .unwrap();
        let (reply, mut receipt) = oneshot::channel();
        let (_feed_owner, feed_gate) = test_feed_gate();
        assert!(handle_command(
            WatchdogCommand::Disarm { permit, reply },
            &mut phase,
            &SafetyLiveness::default(),
            &mut device,
            &feed_gate,
        ));
        assert!(receipt.try_recv().unwrap().is_err());
        drop(device);
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn worker_rejects_disarm_after_absolute_start_deadline_even_before_feed_deadline() {
        let state = Arc::new(FakeState::default());
        let scope = WatchdogRunScope::new();
        let (mut issuer, _) = issue_teardown_budget_authority(scope.clone());
        // Inject the physical boundary directly. Wall-clock scheduling cannot
        // consume this test's narrow DisarmStart-to-FeedDeadline reserve.
        let started_at = Instant::now();
        let budget = issuer
            .issue_at(started_at, TeardownBudgetPolicy::watchdog_default())
            .unwrap();
        let feed_deadline = budget.deadline(TeardownStage::FeedDeadline);
        let permit = WatchdogDisarmPermit {
            scope,
            composition: WatchdogComposition::TestOnly,
            teardown: WatchdogTeardownAuthority::Absolute(
                budget
                    .begin_disarm_at(started_at + Duration::from_nanos(1))
                    .unwrap(),
            ),
        };
        let mut phase = WatchdogPhase::Teardown {
            deadline: feed_deadline,
        };
        let mut device = RetainedArmedWatchdog::new(Box::new(FakeWatchdog {
            state: Arc::clone(&state),
            closed: false,
        }));
        let (reply, mut receipt) = oneshot::channel();
        let (_feed_owner, feed_gate) = test_feed_gate();

        assert!(handle_command_at(
            WatchdogCommand::Disarm { permit, reply },
            &mut phase,
            &SafetyLiveness::default(),
            &mut device,
            &feed_gate,
            started_at + Duration::from_secs(29),
        ));
        let error = receipt.try_recv().unwrap().unwrap_err();
        assert!(error.contains("physical magic-close boundary"));
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn owner_drop_and_command_loss_never_magic_close() {
        let state = Arc::new(FakeState::default());
        let (owner, _) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        drop(owner);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn admission_distinguishes_pre_open_from_post_open_failures() {
        let mut disabled = config();
        disabled.enabled = false;
        let factory_called = Arc::new(AtomicBool::new(false));
        let factory_called_worker = Arc::clone(&factory_called);
        let (_owner, admission) = SafetyWatchdogOwner::start_with_factory(
            &disabled,
            Duration::from_secs(30),
            Duration::from_secs(2),
            SafetyLiveness::default(),
            Box::new(move || {
                factory_called_worker.store(true, Ordering::SeqCst);
                Err("must not open".to_string())
            }),
        )
        .await
        .unwrap();
        assert_eq!(admission, WatchdogAdmission::DisabledByConfiguration);
        assert!(!factory_called.load(Ordering::SeqCst));
        assert!(admission.require_armed("test NoPic").is_err());

        let (_owner, admission) = SafetyWatchdogOwner::start_with_factory(
            &config(),
            Duration::from_secs(30),
            Duration::from_secs(2),
            SafetyLiveness::default(),
            Box::new(|| Err("scripted open failure".to_string())),
        )
        .await
        .unwrap();
        assert!(matches!(
            &admission,
            WatchdogAdmission::UnavailableBeforeOpen { .. }
        ));
        assert!(admission.require_armed("test NoPic").is_err());

        let state = Arc::new(FakeState::default());
        state.set_timeout_fails.store(true, Ordering::SeqCst);
        let factory_state = Arc::clone(&state);
        let (_owner, admission) = SafetyWatchdogOwner::start_with_factory(
            &config(),
            Duration::from_secs(30),
            Duration::from_secs(2),
            SafetyLiveness::default(),
            Box::new(move || {
                Ok(Box::new(FakeWatchdog {
                    state: factory_state,
                    closed: false,
                }))
            }),
        )
        .await
        .unwrap();
        assert!(matches!(
            admission,
            WatchdogAdmission::OpenedOrOutcomeUnknown { .. }
        ));
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));

        let state = Arc::new(FakeState::default());
        state.kick_fails.store(true, Ordering::SeqCst);
        let factory_state = Arc::clone(&state);
        let (_owner, admission) = SafetyWatchdogOwner::start_with_factory(
            &config(),
            Duration::from_secs(30),
            Duration::from_secs(2),
            SafetyLiveness::default(),
            Box::new(move || {
                Ok(Box::new(FakeWatchdog {
                    state: factory_state,
                    closed: false,
                }))
            }),
        )
        .await
        .unwrap();
        assert!(matches!(
            admission,
            WatchdogAdmission::OpenedOrOutcomeUnknown { .. }
        ));
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
    }

    #[test]
    fn only_opened_or_unknown_admission_carries_reset_pending_marker() {
        let before_open = WatchdogAdmission::UnavailableBeforeOpen {
            reason: "no device".to_string(),
        }
        .require_armed("test")
        .unwrap_err();
        assert!(!super::is_watchdog_reset_pending(&before_open));

        let after_open = WatchdogAdmission::OpenedOrOutcomeUnknown {
            reason: "initial kick failed".to_string(),
        }
        .require_armed("test")
        .unwrap_err();
        assert!(super::is_watchdog_reset_pending(&after_open));
    }

    #[tokio::test]
    async fn worker_panic_is_observed_without_magic_close() {
        let state = Arc::new(FakeState::default());
        state.panic_on_set_timeout.store(true, Ordering::SeqCst);
        let factory_state = Arc::clone(&state);
        let (_owner, admission) = SafetyWatchdogOwner::start_with_factory(
            &config(),
            Duration::from_secs(30),
            Duration::from_secs(2),
            SafetyLiveness::default(),
            Box::new(move || {
                Ok(Box::new(FakeWatchdog {
                    state: factory_state,
                    closed: false,
                }))
            }),
        )
        .await
        .unwrap();
        assert!(matches!(
            admission,
            WatchdogAdmission::OpenedOrOutcomeUnknown { .. }
        ));
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
    }

    #[tokio::test]
    async fn bringup_expiry_and_teardown_retry_are_terminal_or_nonextending() {
        let state = Arc::new(FakeState::default());
        let (mut expired_owner, _) =
            fake_owner(Arc::clone(&state), Duration::from_millis(20)).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(expired_owner.enter_mining().await.is_err());
        drop(expired_owner);

        let state = Arc::new(FakeState::default());
        let (mut owner, _) = fake_owner(state, Duration::from_secs(30)).await;
        owner
            .begin_teardown(DEFAULT_WATCHDOG_TEARDOWN_GRACE)
            .await
            .unwrap();
        assert!(owner.teardown_deadline_request.get().is_some());
        assert!(owner
            .begin_teardown(DEFAULT_WATCHDOG_TEARDOWN_GRACE)
            .await
            .is_err());
        drop(owner);
    }

    #[test]
    fn local_teardown_request_bounds_feeds_without_actor_acknowledgement() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(10);
        let request = OnceLock::new();
        request.set(deadline).unwrap();
        let mut phase = WatchdogPhase::Mining {
            last_live: 0,
            stalls: 0,
        };

        latch_requested_teardown_deadline(&mut phase, &request, now);
        assert!(matches!(
            phase,
            WatchdogPhase::Teardown {
                deadline: observed
            } if observed == deadline
        ));

        latch_expired_deadline(&mut phase, deadline);
        assert!(matches!(
            phase,
            WatchdogPhase::FeedSuppressed(FeedSuppressionReason::TeardownDeadlineExpired)
        ));

        let expired_request = OnceLock::new();
        expired_request.set(now).unwrap();
        let mut bringup = WatchdogPhase::Bringup {
            deadline: now + Duration::from_secs(30),
        };
        latch_requested_teardown_deadline(&mut bringup, &expired_request, now);
        assert!(matches!(
            bringup,
            WatchdogPhase::FeedSuppressed(FeedSuppressionReason::TeardownDeadlineExpired)
        ));

        let future_request = OnceLock::new();
        future_request.set(now + Duration::from_secs(30)).unwrap();
        let mut already_expired_bringup = WatchdogPhase::Bringup {
            deadline: now - Duration::from_millis(1),
        };
        latch_requested_teardown_deadline(&mut already_expired_bringup, &future_request, now);
        assert!(matches!(
            already_expired_bringup,
            WatchdogPhase::FeedSuppressed(FeedSuppressionReason::BringupDeadlineExpired)
        ));
    }

    #[tokio::test]
    async fn watchdog_teardown_request_and_actor_acknowledgement_are_separate_boundaries() {
        let state = Arc::new(FakeState::default());
        let (mut owner, liveness) = fake_owner(state, Duration::from_secs(30)).await;
        owner.enter_mining().await.unwrap();
        liveness.mark_progress();

        // This call is intentionally synchronous: returning proves local feed
        // deadline publication and actor command submission require no await.
        let request = owner.request_teardown_budget().unwrap();
        assert!(owner.teardown_deadline_request.get().is_some());
        assert!(!owner.teardown_admitted);
        let (budget, admission) = request.into_parts();
        let view = budget.view();

        owner
            .observe_teardown_admission(admission, &view)
            .await
            .unwrap();
        assert!(owner.teardown_admitted);
    }

    #[tokio::test]
    async fn watchdog_teardown_receipt_timestamp_cannot_launder_late_admission() {
        let state = Arc::new(FakeState::default());
        let (mut owner, _) = fake_owner(state, Duration::from_secs(30)).await;
        let started_at = Instant::now();
        let budget = owner
            .teardown_budget_issuer
            .issue_at(started_at, TeardownBudgetPolicy::watchdog_default())
            .unwrap();
        let view = budget.view();
        let (reply, receipt) = oneshot::channel();
        reply
            .send(Ok(PhaseReceipt::TeardownAdmitted {
                admitted_at: view.deadline(TeardownStage::CutoffStart),
            }))
            .unwrap();

        let error = owner
            .observe_teardown_admission(WatchdogTeardownAdmission::pending(receipt), &view)
            .await
            .unwrap_err();

        assert!(error.contains("acknowledged too late"));
        assert!(!owner.teardown_admitted);
    }

    #[test]
    fn watchdog_teardown_admission_wait_uses_the_original_absolute_deadline() {
        let source = include_str!("safety_watchdog.rs");
        let start = source
            .find("pub(crate) async fn observe_teardown_admission(")
            .unwrap();
        let end = source[start..]
            .find("pub(crate) async fn begin_teardown_budget(")
            .map(|offset| start + offset)
            .unwrap();
        let body = &source[start..end];

        assert!(body.contains("budget.deadline(TeardownStage::CutoffStart)"));
        assert!(body.contains("tokio::time::timeout_at("));
        assert!(!body.contains("tokio::time::timeout(timeout"));
    }

    #[test]
    fn locally_latched_deadline_accepts_only_its_matching_actor_command() {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut phase = WatchdogPhase::Teardown { deadline };
        let liveness = SafetyLiveness::default();
        let mut watchdog = RetainedArmedWatchdog::empty();
        let (_feed_owner, feed_gate) = test_feed_gate();

        let (matching_reply, matching_receipt) = oneshot::channel();
        assert!(!handle_command(
            WatchdogCommand::BeginTeardown {
                deadline,
                reply: matching_reply,
            },
            &mut phase,
            &liveness,
            &mut watchdog,
            &feed_gate,
        ));
        assert!(matches!(
            matching_receipt.blocking_recv().unwrap().unwrap(),
            PhaseReceipt::TeardownAdmitted { admitted_at } if admitted_at <= Instant::now()
        ));

        let (extension_reply, extension_receipt) = oneshot::channel();
        assert!(!handle_command(
            WatchdogCommand::BeginTeardown {
                deadline: deadline + Duration::from_secs(1),
                reply: extension_reply,
            },
            &mut phase,
            &liveness,
            &mut watchdog,
            &feed_gate,
        ));
        assert!(extension_receipt
            .blocking_recv()
            .unwrap()
            .unwrap_err()
            .contains("deadline extension refused"));
    }

    #[tokio::test]
    async fn explicit_safety_failure_suppresses_feeds_and_permanently_forbids_disarm() {
        let state = Arc::new(FakeState::default());
        let (mut owner, _) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        owner
            .suppress_feeds_terminally("GPIO OFF readback failed".to_string())
            .await
            .unwrap();
        assert!(owner
            .begin_teardown(DEFAULT_WATCHDOG_TEARDOWN_GRACE)
            .await
            .is_err());
        drop(owner);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn feed_suppression_receipt_makes_every_later_kick_deadline_inert() {
        let state = Arc::new(FakeState::default());
        let liveness = SafetyLiveness::default();
        let mut phase = WatchdogPhase::Bringup {
            deadline: Instant::now() + Duration::from_secs(30),
        };
        let mut watchdog = RetainedArmedWatchdog::new(Box::new(FakeWatchdog {
            state: Arc::clone(&state),
            closed: false,
        }));
        let (_feed_owner, feed_gate) = test_feed_gate();

        service_watchdog_kick_deadline(&mut phase, &liveness, 2, &watchdog, &feed_gate);
        let kicks_before_suppression = state
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "kick")
            .count();
        assert_eq!(kicks_before_suppression, 1, "test seam must feed first");

        let (reply, mut receipt) = oneshot::channel();
        assert!(!handle_command(
            WatchdogCommand::SuppressFeeds {
                reason: "scripted terminal safety failure".to_string(),
                reply,
            },
            &mut phase,
            &liveness,
            &mut watchdog,
            &feed_gate,
        ));
        assert_eq!(
            receipt.try_recv().unwrap().unwrap(),
            PhaseReceipt::FeedSuppressed
        );

        let kicks_after_receipt = state
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "kick")
            .count();
        for _ in 0..3 {
            service_watchdog_kick_deadline(&mut phase, &liveness, 2, &watchdog, &feed_gate);
        }
        assert_eq!(
            state
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "kick")
                .count(),
            kicks_after_receipt,
            "a positive suppression receipt must make every later feed deadline inert"
        );
    }

    #[tokio::test]
    async fn sealed_never_energized_evidence_cleanly_closes_bringup_watchdog() {
        let state = Arc::new(FakeState::default());
        let (mut owner, _) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        owner
            .claim_serial_route_scope(SerialWatchdogComposition::Am2Bm1362)
            .unwrap();
        let never_energized = owner.issue_am2_never_energized().unwrap();
        let _receipt = owner
            .disarm_never_energized(never_energized, DEFAULT_WATCHDOG_STOP_TIMEOUT)
            .await
            .unwrap();
        assert!(state.events.lock().unwrap().contains(&"magic-close"));
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn s19k_never_handoff_evidence_cleanly_closes_before_route_claim() {
        let state = Arc::new(FakeState::default());
        let (mut owner, _) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        let never_handoff = owner.issue_s19k_track1_never_handoff().unwrap();
        let _receipt = owner
            .disarm_s19k_track1_never_handoff(never_handoff, DEFAULT_WATCHDOG_STOP_TIMEOUT)
            .await
            .unwrap();
        assert!(state.events.lock().unwrap().contains(&"magic-close"));
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn s19k_never_handoff_evidence_from_another_run_is_rejected() {
        let mut old_owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let stale = old_owner.issue_s19k_track1_never_handoff().unwrap();
        drop(old_owner);

        let state = Arc::new(FakeState::default());
        let (current_owner, _) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        let error = current_owner
            .disarm_s19k_track1_never_handoff(stale, DEFAULT_WATCHDOG_STOP_TIMEOUT)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("another watchdog/run"));
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
    }

    #[tokio::test]
    async fn s19k_never_handoff_evidence_is_invalid_after_route_claim() {
        let state = Arc::new(FakeState::default());
        let (mut owner, _) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        let never_handoff = owner.issue_s19k_track1_never_handoff().unwrap();
        owner
            .claim_serial_route_scope(SerialWatchdogComposition::S19kTrack1)
            .unwrap();
        let error = owner
            .disarm_s19k_track1_never_handoff(never_handoff, DEFAULT_WATCHDOG_STOP_TIMEOUT)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unclaimed watchdog route"));
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
    }

    #[tokio::test]
    async fn never_energized_evidence_from_another_run_is_rejected() {
        let mut old_owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        old_owner
            .claim_serial_route_scope(SerialWatchdogComposition::Am2Bm1362)
            .unwrap();
        let stale = old_owner.issue_am2_never_energized().unwrap();
        drop(old_owner);

        let state = Arc::new(FakeState::default());
        let (mut current_owner, _) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        current_owner
            .claim_serial_route_scope(SerialWatchdogComposition::Am2Bm1362)
            .unwrap();

        let error = current_owner
            .disarm_never_energized(stale, DEFAULT_WATCHDOG_STOP_TIMEOUT)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("another watchdog/run"));
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
    }

    #[tokio::test]
    async fn worker_liveness_stall_is_terminal_after_late_progress() {
        let state = Arc::new(FakeState::default());
        let factory_state = Arc::clone(&state);
        let liveness = SafetyLiveness::default();
        let mut fast_config = config();
        fast_config.timeout_s = 3;
        fast_config.kick_interval_s = 1;
        let (mut owner, admission) = SafetyWatchdogOwner::start_with_factory(
            &fast_config,
            Duration::from_secs(10),
            Duration::from_millis(10),
            liveness.clone(),
            Box::new(move || {
                Ok(Box::new(FakeWatchdog {
                    state: factory_state,
                    closed: false,
                }))
            }),
        )
        .await
        .unwrap();
        assert!(matches!(admission, WatchdogAdmission::Armed(_)));
        owner.enter_mining().await.unwrap();

        // stall_limit=3 after the cadence safety margin: the first two mining
        // intervals are kicked and the third terminally suppresses. A later
        // safety-loop advance must not resume.
        tokio::time::sleep(Duration::from_millis(3300)).await;
        let kicks_before_late_progress = state
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "kick")
            .count();
        liveness.mark_progress();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let kicks_after_late_progress = state
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "kick")
            .count();
        assert_eq!(kicks_after_late_progress, kicks_before_late_progress);
        assert!(owner
            .begin_teardown(DEFAULT_WATCHDOG_TEARDOWN_GRACE)
            .await
            .is_err());
        drop(owner);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn incomplete_engine_evidence_cannot_mint_disarm_permit() {
        assert!(WatchdogDisarmPermit::from_evidence(
            WatchdogRunScope::new(),
            &Incomplete,
            &CompleteActors,
            &CompleteSafeOff,
        )
        .is_err());
        assert!(WatchdogDisarmPermit::from_evidence(
            WatchdogRunScope::new(),
            &CompleteMutations,
            &Incomplete,
            &CompleteSafeOff,
        )
        .is_err());
        assert!(WatchdogDisarmPermit::from_evidence(
            WatchdogRunScope::new(),
            &CompleteMutations,
            &CompleteActors,
            &Incomplete,
        )
        .is_err());
    }

    #[test]
    fn disarm_permit_requires_every_mutation_domain() {
        let complete: [&dyn MutationBarrierEvidence; 2] = [&CompleteMutations, &CompleteMutations];
        assert!(WatchdogDisarmPermit::from_evidence_set(
            WatchdogRunScope::new(),
            &complete,
            &CompleteActors,
            &CompleteSafeOff,
        )
        .is_ok());

        let one_incomplete: [&dyn MutationBarrierEvidence; 2] = [&CompleteMutations, &Incomplete];
        assert!(WatchdogDisarmPermit::from_evidence_set(
            WatchdogRunScope::new(),
            &one_incomplete,
            &CompleteActors,
            &CompleteSafeOff,
        )
        .is_err());
    }

    #[test]
    fn disarm_permit_rejects_an_empty_mutation_domain_set() {
        let empty: [&dyn MutationBarrierEvidence; 0] = [];
        assert!(WatchdogDisarmPermit::from_evidence_set(
            WatchdogRunScope::new(),
            &empty,
            &CompleteActors,
            &CompleteSafeOff,
        )
        .is_err());
    }

    #[tokio::test]
    async fn successful_disarm_requires_receipt_and_observed_worker_exit() {
        let state = Arc::new(FakeState::default());
        let (mut owner, liveness) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        owner.enter_mining().await.unwrap();
        liveness.mark_progress();
        owner
            .begin_teardown(DEFAULT_WATCHDOG_TEARDOWN_GRACE)
            .await
            .unwrap();
        let scope = owner.claim_test_route_scope().unwrap();
        let permit = WatchdogDisarmPermit::from_evidence(
            scope,
            &CompleteMutations,
            &CompleteActors,
            &CompleteSafeOff,
        )
        .unwrap();
        let _receipt = owner
            .disarm_and_join(permit, Duration::from_secs(1))
            .await
            .unwrap();
        let events = state.events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == "magic-close")
                .count(),
            1
        );
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn absolute_budget_disarm_uses_the_watchdog_issued_schedule() {
        let state = Arc::new(FakeState::default());
        let (mut owner, liveness) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        owner.enter_mining().await.unwrap();
        liveness.mark_progress();

        let teardown_start = owner.begin_teardown_budget().await.unwrap();
        let (budget, admission) = teardown_start.into_parts();
        admission.unwrap();
        let scope = owner.claim_test_route_scope().unwrap();
        let permit = WatchdogDisarmPermit {
            scope,
            composition: WatchdogComposition::TestOnly,
            teardown: WatchdogTeardownAuthority::Absolute(
                budget.begin_disarm_at(Instant::now()).unwrap(),
            ),
        };

        let _receipt = owner
            // The relative argument is deliberately unusable. Absolute permits
            // must derive receipt and join waits only from their schedule.
            .disarm_and_join(permit, Duration::from_nanos(1))
            .await
            .unwrap();
        assert_eq!(
            state
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "magic-close")
                .count(),
            1
        );
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn disarm_permit_from_another_watchdog_run_is_rejected() {
        let state = Arc::new(FakeState::default());
        let (mut owner, _) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        owner.enter_mining().await.unwrap();
        owner
            .begin_teardown(DEFAULT_WATCHDOG_TEARDOWN_GRACE)
            .await
            .unwrap();
        owner.claim_test_route_scope().unwrap();
        let permit = WatchdogDisarmPermit::from_evidence(
            WatchdogRunScope::new(),
            &CompleteMutations,
            &CompleteActors,
            &CompleteSafeOff,
        )
        .unwrap();

        let error = owner
            .disarm_and_join(permit, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("another watchdog/run scope"));
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
    }

    #[tokio::test]
    async fn same_run_permit_from_another_composition_is_rejected() {
        let state = Arc::new(FakeState::default());
        let (mut owner, _) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        owner.enter_mining().await.unwrap();
        owner
            .begin_teardown(DEFAULT_WATCHDOG_TEARDOWN_GRACE)
            .await
            .unwrap();
        let hybrid_scope = owner.claim_hybrid_route_scope().unwrap();
        let permit = WatchdogDisarmPermit::from_evidence(
            hybrid_scope.scope.clone(),
            &CompleteMutations,
            &CompleteActors,
            &CompleteSafeOff,
        )
        .unwrap();

        let error = owner
            .disarm_and_join(permit, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("does not match owner binding"));
        assert!(!state.events.lock().unwrap().contains(&"magic-close"));
    }

    #[test]
    fn watchdog_composition_binding_is_single_use() {
        let mut owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        assert!(owner.claim_hybrid_route_scope().is_ok());
        assert!(owner.claim_am3_bb_route_scope().is_err());
        assert!(owner
            .claim_serial_route_scope(SerialWatchdogComposition::NoPic)
            .is_err());

        let mut am2_owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        am2_owner
            .claim_serial_route_scope(SerialWatchdogComposition::Am2Bm1362)
            .unwrap();
        assert!(am2_owner.issue_am2_never_energized().is_ok());
        assert!(am2_owner.issue_am2_never_energized().is_err());

        let mut am3_owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        am3_owner.claim_am3_bb_route_scope().unwrap();
        assert!(am3_owner.issue_am3_bb_never_energized().is_ok());
        assert!(am3_owner.issue_am3_bb_never_energized().is_err());

        let mut s19k_owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        assert!(s19k_owner.issue_s19k_track1_never_handoff().is_ok());
        assert!(s19k_owner.issue_s19k_track1_never_handoff().is_err());

        let mut claimed_s19k_owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        claimed_s19k_owner
            .claim_serial_route_scope(SerialWatchdogComposition::S19kTrack1)
            .unwrap();
        assert!(claimed_s19k_owner
            .issue_s19k_track1_never_handoff()
            .is_err());
    }

    #[tokio::test]
    async fn exact_serial_compositions_reject_untyped_mining_admission() {
        for route in [
            SerialWatchdogComposition::NoPic,
            SerialWatchdogComposition::S19kTrack1,
            SerialWatchdogComposition::Am2Bm1362,
        ] {
            let mut owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
            let _admission = owner.claim_serial_route_scope(route).unwrap();
            let error = owner.enter_mining().await.unwrap_err();
            assert!(error
                .to_string()
                .contains("requires typed runtime-actor authority"));
        }
    }

    #[tokio::test]
    async fn nopic_serial_actor_roster_is_watchdog_issued_and_issuer_bound() {
        let mut owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let admission = owner
            .claim_serial_route_scope(SerialWatchdogComposition::NoPic)
            .unwrap();
        let (_scope, actor_owner, actor_expectation) = admission.into_nopic_parts().unwrap();

        let shutdown = tokio_util::sync::CancellationToken::new();
        let worker_shutdown = shutdown.clone();
        let mut actors = actor_owner.activate(shutdown);
        actors
            .resolve_conditional(
                NoPicSerialThreadSlot::Track1SafetySampler,
                false,
                "native NoPic topology excludes the S19k Track-1 sampler",
            )
            .unwrap();
        actors
            .reserve(NoPicSerialThreadSlot::SerialIo)
            .unwrap()
            .attach(std::thread::spawn(move || {
                while !worker_shutdown.is_cancelled() {
                    std::thread::yield_now();
                }
            }));
        let receipt = actors
            .stop_and_join(Duration::from_secs(1))
            .await
            .into_receipt()
            .unwrap();

        assert!(receipt.authorizes(&actor_expectation));
        assert!(receipt.joined(NoPicSerialThreadSlot::SerialIo));
        assert!(receipt.not_applicable(NoPicSerialThreadSlot::Track1SafetySampler));
        let (_foreign_owner, foreign_expectation) =
            issue_thread_roster([ThreadSlotDeclaration::required(
                NoPicSerialThreadSlot::SerialIo,
            )])
            .unwrap();
        assert!(!receipt.authorizes(&foreign_expectation));
    }

    #[tokio::test]
    async fn am2_serial_actor_roster_records_bypass_topology_and_issuer_binding() {
        let mut owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let admission = owner
            .claim_serial_route_scope(SerialWatchdogComposition::Am2Bm1362)
            .unwrap();
        let (_scope, actor_owner, actor_expectation) = admission.into_am2_parts().unwrap();

        let shutdown = tokio_util::sync::CancellationToken::new();
        let dspic_shutdown = shutdown.clone();
        let serial_shutdown = shutdown.clone();
        let mut actors = actor_owner.activate(shutdown);
        actors
            .resolve_conditional(
                Am2SerialThreadSlot::ApwHeartbeat,
                false,
                "test topology uses explicit APW bypass",
            )
            .unwrap();
        actors
            .reserve(Am2SerialThreadSlot::DspicHeartbeat)
            .unwrap()
            .attach(std::thread::spawn(move || {
                while !dspic_shutdown.is_cancelled() {
                    std::thread::yield_now();
                }
            }));
        actors
            .reserve(Am2SerialThreadSlot::SerialIo)
            .unwrap()
            .attach(std::thread::spawn(move || {
                while !serial_shutdown.is_cancelled() {
                    std::thread::yield_now();
                }
            }));
        let receipt = actors
            .stop_and_join(Duration::from_secs(1))
            .await
            .into_receipt()
            .unwrap();

        assert!(receipt.authorizes(&actor_expectation));
        assert!(receipt.not_applicable(Am2SerialThreadSlot::ApwHeartbeat));
        assert!(receipt.joined(Am2SerialThreadSlot::DspicHeartbeat));
        assert!(receipt.joined(Am2SerialThreadSlot::SerialIo));
        let (_foreign_owner, foreign_expectation) = issue_thread_roster([
            ThreadSlotDeclaration::conditional(Am2SerialThreadSlot::ApwHeartbeat),
            ThreadSlotDeclaration::required(Am2SerialThreadSlot::DspicHeartbeat),
            ThreadSlotDeclaration::required(Am2SerialThreadSlot::SerialIo),
        ])
        .unwrap();
        assert!(!receipt.authorizes(&foreign_expectation));
    }

    #[test]
    fn serial_watchdog_admission_cannot_change_composition_after_claim() {
        let mut nopic_owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let nopic = nopic_owner
            .claim_serial_route_scope(SerialWatchdogComposition::NoPic)
            .unwrap();
        assert!(nopic.into_am2_parts().is_err());

        let mut am2_owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let am2 = am2_owner
            .claim_serial_route_scope(SerialWatchdogComposition::Am2Bm1362)
            .unwrap();
        assert!(am2.into_nopic_parts().is_err());
    }

    #[tokio::test]
    async fn hybrid_actor_roster_owner_is_single_claim_and_issuer_bound() {
        let mut owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut route_scope = owner.claim_hybrid_route_scope().unwrap();
        let actor_owner = route_scope.take_actor_owner().unwrap();
        assert!(route_scope.take_actor_owner().is_err());

        let shutdown = tokio_util::sync::CancellationToken::new();
        let worker_shutdown = shutdown.clone();
        let mut actors = actor_owner.activate(shutdown);
        actors
            .resolve_conditional(
                HybridThreadSlot::PsuHeartbeat,
                false,
                "test topology has no smart PSU",
            )
            .unwrap();
        actors
            .reserve(HybridThreadSlot::PicHeartbeat)
            .unwrap()
            .attach(std::thread::spawn(move || {
                while !worker_shutdown.is_cancelled() {
                    std::thread::yield_now();
                }
            }));
        let receipt = actors
            .stop_and_join(Duration::from_secs(1))
            .await
            .into_receipt()
            .unwrap();
        assert!(receipt.authorizes(&route_scope.actor_expectation));
        assert!(receipt.not_applicable(HybridThreadSlot::PsuHeartbeat));
        assert!(receipt.joined(HybridThreadSlot::PicHeartbeat));

        let (_foreign_owner, foreign_expectation) = issue_thread_roster([
            ThreadSlotDeclaration::conditional(HybridThreadSlot::PsuHeartbeat),
            ThreadSlotDeclaration::required(HybridThreadSlot::PicHeartbeat),
        ])
        .unwrap();
        assert!(!receipt.authorizes(&foreign_expectation));
    }

    #[tokio::test]
    async fn am3_actor_roster_owner_is_single_claim_and_issuer_bound() {
        let mut owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut route_scope = owner.claim_am3_bb_route_scope().unwrap();
        let actor_owner = route_scope.take_actor_owner().unwrap();
        assert!(route_scope.take_actor_owner().is_err());

        let shutdown = tokio_util::sync::CancellationToken::new();
        let worker_shutdown = shutdown.clone();
        let mut actors = actor_owner.activate(shutdown);
        actors
            .reserve(Am3BbThreadSlot::DspicHeartbeat)
            .unwrap()
            .attach(std::thread::spawn(move || {
                while !worker_shutdown.is_cancelled() {
                    std::thread::yield_now();
                }
            }));
        let receipt = actors
            .stop_and_join(Duration::from_secs(1))
            .await
            .into_receipt()
            .unwrap();
        assert!(receipt.authorizes(&route_scope.actor_expectation));
        assert!(receipt.joined(Am3BbThreadSlot::DspicHeartbeat));

        let (_foreign_owner, foreign_expectation) =
            issue_thread_roster([ThreadSlotDeclaration::required(
                Am3BbThreadSlot::DspicHeartbeat,
            )])
            .unwrap();
        assert!(!receipt.authorizes(&foreign_expectation));
    }

    #[tokio::test]
    async fn standard_disarm_permit_uses_watchdog_issued_actor_authority() {
        use crate::runtime::task_guard::{StandardMiningActorSlot, StandardMiningTaskGuard};

        let (
            scope,
            issuer,
            expectation,
            unit_closeout_issuer,
            unit_closeout_expectation,
            mut teardown_budget_issuer,
            teardown_budget_expectation,
        ) = StandardWatchdogRunAdmission::new().into_parts();
        let same_run = scope.clone();
        let other_run = WatchdogRunScope::new();
        let mut guard = StandardMiningTaskGuard::new(
            tokio_util::sync::CancellationToken::new(),
            scope.clone(),
            issuer,
        );
        assert!(guard.spawn(StandardMiningActorSlot::WorkDispatcher, async {}));
        let actors = guard
            .stop_and_join(Duration::from_secs(1))
            .await
            .into_receipt()
            .expect("real standard actor lifecycle must close");
        let (
            _foreign_scope,
            foreign_issuer,
            foreign_expectation,
            _foreign_unit_closeout_issuer,
            foreign_unit_closeout_expectation,
            _foreign_teardown_budget_issuer,
            foreign_teardown_budget_expectation,
        ) = StandardWatchdogRunAdmission::for_scope_for_test(scope.clone()).into_parts();
        let _foreign_guard = StandardMiningTaskGuard::new(
            tokio_util::sync::CancellationToken::new(),
            scope.clone(),
            foreign_issuer,
        );
        let teardown_budget = teardown_budget_issuer
            .issue_at(Instant::now(), TeardownBudgetPolicy::watchdog_default())
            .unwrap();
        let unit_closeout =
            crate::daemon::StandardUnitCloseoutOwners::new(scope.clone(), unit_closeout_issuer)
                .complete_for_test(teardown_budget.view())
                .expect("test unit closeout authority must complete");
        let permit = StandardWatchdogDisarmPermit {
            scope,
            _execution: crate::asic_identity_publication::CompositionInvalidationReceipt::test_idle(
            ),
            actors,
            unit_closeout,
            teardown: teardown_budget.begin_disarm_at(Instant::now()).unwrap(),
        };

        assert!(permit.authorizes(
            &same_run,
            &expectation,
            &unit_closeout_expectation,
            &teardown_budget_expectation,
        ));
        assert!(!permit.authorizes(
            &other_run,
            &expectation,
            &unit_closeout_expectation,
            &teardown_budget_expectation,
        ));
        assert!(!permit.authorizes(
            &same_run,
            &foreign_expectation,
            &unit_closeout_expectation,
            &teardown_budget_expectation,
        ));
        assert!(!permit.authorizes(
            &same_run,
            &expectation,
            &foreign_unit_closeout_expectation,
            &teardown_budget_expectation,
        ));
        assert!(!permit.authorizes(
            &same_run,
            &expectation,
            &unit_closeout_expectation,
            &foreign_teardown_budget_expectation,
        ));
    }

    #[tokio::test]
    async fn magic_close_failure_never_mints_positive_closeout() {
        let state = Arc::new(FakeState::default());
        state.close_fails.store(true, Ordering::SeqCst);
        let (mut owner, _) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        owner.enter_mining().await.unwrap();
        owner
            .begin_teardown(DEFAULT_WATCHDOG_TEARDOWN_GRACE)
            .await
            .unwrap();
        let scope = owner.claim_test_route_scope().unwrap();
        let permit = WatchdogDisarmPermit::from_evidence(
            scope,
            &CompleteMutations,
            &CompleteActors,
            &CompleteSafeOff,
        )
        .unwrap();
        assert!(owner
            .disarm_and_join(permit, Duration::from_secs(1))
            .await
            .is_err());
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn magic_close_receipt_drop_reports_unknown_outcome_and_worker_panic() {
        let state = Arc::new(FakeState::default());
        state.panic_on_close.store(true, Ordering::SeqCst);
        let (mut owner, _) = fake_owner(Arc::clone(&state), Duration::from_secs(30)).await;
        owner.enter_mining().await.unwrap();
        owner
            .begin_teardown(DEFAULT_WATCHDOG_TEARDOWN_GRACE)
            .await
            .unwrap();
        let scope = owner.claim_test_route_scope().unwrap();
        let permit = WatchdogDisarmPermit::from_evidence(
            scope,
            &CompleteMutations,
            &CompleteActors,
            &CompleteSafeOff,
        )
        .unwrap();

        let error = owner
            .disarm_and_join(permit, Duration::from_secs(1))
            .await
            .expect_err("magic-close panic must not mint positive closeout")
            .to_string();
        assert!(error.contains("magic-close outcome is unknown"));
        assert!(error.contains("watchdog worker panicked"));
        assert_eq!(state.drops_armed.load(Ordering::SeqCst), 0);
    }
}

#[cfg(all(test, feature = "sim-hal"))]
#[path = "bm1396_sim_watchdog.rs"]
pub(crate) mod bm1396_sim;
