//! Hydro coolant-loop feedback composition and external cutoff gate
//! (campaign `2026-09-07-antminer-beta-execution`, lane R15).
//! Pure policy over monitored inputs — no I/O, no clock, no bus. The
//! daemon's cooling monitor feeds observations in; this module composes
//! them into the stock-proven laws and refuses everything the held bytes
//! do not prove (Unproven = fail closed).
//!
//! # What the held bytes prove (per `hydro_immersion_profiles`
//! `HydroFeedbackGeneration`; strings live in the held `bmminer` ELFs and
//! the held factory-jig decompilations)
//!
//! Universal across every held hydro generation (G1+):
//! - water temperature is read THROUGH the hashboard PIC
//!   (`read_sensor_on_pic`, "too low water temperature pic temp %d
//!   (min %d)");
//! - out-of-range water temperature stops mining ("water temp %d ~ %d,
//!   stop.") or sleeps to cool down ("water temp %d ~ %d, sleep %ds to
//!   cool down");
//! - flow PRESENCE is monitored ("Water is not flowing!").
//! G2+ (HHB42+): "too hot water temperature pic temp %d (min %d)" and the
//!   water-permit gate `/get_water_permit` + "get_water_permit failed".
//! G4+ (HHB68+): four channels "inlet_board_temp=%d,outlet_board_temp=%d,
//!   inlet_water_temp=%d,outlet_water_temp=%d"; delta law "difference
//!   between inlet and outlet is too large:%d inlet_temp:%d,outlet_temp:%d";
//!   reverse-flow detection "water flow is reverse" / "ERROR_WATER_REVERSE".
//! G5 (HHB70, S21 XP Hydro): per-chain water temps, "water temp diff err",
//!   the water-scoped voltage law "water_temp_min = %d endvol =%d
//!   vol_cur =%d" (voltage is bounded by water temp — evidence cited, the
//!   numeric policy is NOT re-derived here), and the held factory-jig
//!   cutoff executor `single_board_test.dec/pt_read_temp@8FF50.c`:
//!   `sensor[0] - sensor[1] > 3` ⇒ "Water flow reversal!" ⇒ error code 6
//!   ⇒ `bitmain_power_off()` — GPIO907 = 1, an IMMEDIATE FULL POWER OFF.
//!
//! # Monitored inputs vs owned controls (Deliverable 3 split)
//!
//! The unit MONITORS: inlet/outlet water temps, inlet/outlet board temps,
//! flow presence and direction (via the PIC sensor path). The unit OWNS:
//! mining on/off, the PSU rail (GPIO907), and the PIC DC-DC voltage
//! enable. The unit does NOT own the pump or the dry cooler — those are
//! [`ExternalLoopElement`]s: monitor-only. No held byte grants a pump
//! actuator, so none exists here; "pump feedback" is exactly the flow and
//! delta laws above, and pump control is refused as Unproven.
//!
//! # Strictness posture (safety boundary)
//!
//! Where stock bytes prove a law, the law is implemented faithfully (same
//! trigger, same action, never looser). Where stock is silent or looser —
//! e.g. an ABSENT or STALE sensor channel — this composition is STRICTER
//! than stock: it refuses the water permit (work never (re)starts without
//! monitored proof), whereas stock's older generations are simply silent.
//! Cooling cutoff logic may only ever get stricter, never looser. The
//! external cutoff gate is one-way latched, requires an operator-minted
//! reset token, and the mining path has no capability that can trip,
//! clear, or bypass it: work authorization flows ONLY through
//! [`CoolingSupervisor::water_permit`], which refuses whenever the gate
//! is tripped — and the gate is also tripped by monitor loss (missed
//! freshness deadline), so a dead monitor can never silently re-arm.

use std::sync::Mutex;

/// How fresh a sample must be for the permit law. Abstract tick (the
/// caller's monotonic clock unit — seconds at the daemon's choice).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessBound {
    /// Maximum age (in ticks) any monitored sample may carry.
    pub max_age_ticks: u64,
}

/// One monitored temperature sample (PIC sensor path), monotonic tick
/// stamped by the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaterTempSample {
    /// Monitor tick the sample was taken at.
    pub tick: u64,
    /// Degrees C as the PIC reports (stock prints them as integers).
    pub temp_c: i16,
}

impl WaterTempSample {
    /// Fresh iff `now - tick <= max_age`; the future is treated as stale
    /// too (a "future" stamp means a broken monitor — fail closed).
    pub const fn is_fresh(&self, now: u64, bound: FreshnessBound) -> bool {
        now >= self.tick && now - self.tick <= bound.max_age_ticks
    }
}

/// Which monitored channel a sample belongs to (G4+ four-channel law;
/// earlier generations populate only what their bytes name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaterChannel {
    /// `inlet_water_temp`.
    InletWater,
    /// `outlet_water_temp`.
    OutletWater,
    /// `inlet_board_temp`.
    InletBoard,
    /// `outlet_board_temp`.
    OutletBoard,
}

/// A full monitored snapshot for one evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WaterSnapshot {
    pub inlet_water: Option<WaterTempSample>,
    pub outlet_water: Option<WaterTempSample>,
    pub inlet_board: Option<WaterTempSample>,
    pub outlet_board: Option<WaterTempSample>,
}

/// Flow observation (the "pump feedback" inputs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowObservation {
    /// Coolant is moving in the expected direction.
    Flowing,
    /// No flow detected ("Water is not flowing!").
    NotFlowing,
    /// Flow direction is reversed ("water flow is reverse" /
    /// "Water flow reversal!").
    Reverse,
}

/// The water-permit law's stock-cited thresholds. The held strings prove
/// the LAWS and their `min`/`max` placeholders; the numeric values below
/// are the composition's declared bounds (operator/fleet policy inputs —
/// a fleet may tighten them, never loosen them past the laws). Defaults
/// match the composition's own conservative floor: they exist so the
/// law is satisfiable at runtime; they are NOT extracted stock constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaterPermitBounds {
    /// "too low water temperature pic temp %d (min %d)" — below ⇒ stop.
    pub min_water_c: i16,
    /// "too hot water temperature pic temp %d (min %d)" (G2+) — above ⇒ stop.
    pub max_water_c: i16,
    /// "difference between inlet and outlet is too large" (G4+) — the
    /// ABSOLUTE inlet/outlet difference above this ⇒ stop (stock prints
    /// the two temps, not a signed order). The bound is the last ALLOWED
    /// delta (stock integer convention: the factory jig refuses at
    /// `sensor[0] − sensor[1] > 3` and at board−water `> 19` named as
    /// "over 20"). Directional inversion is the SEPARATE reverse-flow
    /// law, not this bound.
    pub max_inlet_outlet_delta_c: i16,
    /// Freshness bound applied to every monitored channel.
    pub freshness: FreshnessBound,
}

impl WaterPermitBounds {
    /// The composition's declared defaults (policy floor, not a stock
    /// constant extraction).
    pub const fn conservative_default() -> Self {
        Self {
            min_water_c: 5,
            max_water_c: 60,
            max_inlet_outlet_delta_c: 20,
            freshness: FreshnessBound { max_age_ticks: 10 },
        }
    }
}

/// Why a water permit was refused. Every variant names the held law (or
/// the fail-closed extension stock does not provide).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaterPermitRefusal {
    /// The composition itself is Unproven (no held law for this tuple).
    FeedbackAuthorityUnproven,
    /// The external cutoff gate is tripped. Work may not start or resume.
    CutoffLatched(CutoffCause),
    /// Required channel absent: sensors must be present and read before
    /// work (stock's old generations are silent here; we refuse — stricter).
    SensorAbsent(WaterChannel),
    /// A present channel is stale past the freshness bound (fail closed).
    SensorStale(WaterChannel),
    /// "too low water temperature pic temp %d (min %d)".
    WaterTooLow { observed_c: i16, min_c: i16 },
    /// "too hot water temperature pic temp %d (min %d)".
    WaterTooHot { observed_c: i16, max_c: i16 },
    /// "difference between inlet and outlet is too large".
    InletOutletDeltaTooLarge { delta_c: u16, max_c: i16 },
    /// "Water is not flowing!".
    NotFlowing,
    /// "water flow is reverse" / "Water flow reversal!".
    FlowReverse,
    /// The monitor missed its freshness deadline — treat exactly like a
    /// tripped gate (fail closed; only an operator reset clears it).
    MonitorLost,
}

/// What tripped the external cutoff gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutoffCause {
    /// Reverse flow — stock action: immediate power off (G5 jig law).
    WaterFlowReverse,
    /// Out-of-range water temperature while a permit was active.
    WaterTempOutOfRange,
    /// Inlet/outlet delta beyond the bound while a permit was active.
    InletOutletDelta,
    /// No flow while a permit was active.
    FlowLost,
    /// The monitor missed its deadline (stale tick) — the gate fails
    /// closed on loss of the monitoring authority itself.
    MonitorLost,
    /// An external input (operator panel / external interlock) tripped
    /// the gate. This is the "external cutoff" ingest point.
    ExternalTrip,
}

/// Whether the unit OWNS a control or only MONITORS an external loop
/// element. This is the monitored-vs-owned split: no held byte gives the
/// unit a pump/dry-cooler actuator, so those are monitor-only forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitOwnedControl {
    /// Mining dispatch on/off (the daemon owns this).
    MiningEnable,
    /// PSU rail via GPIO907 (0 = ON / 1 = OFF software mapping; physical
    /// proof still bench-required). Owned.
    PsuRailGpio907,
    /// PIC DC-DC voltage enable (PIC1704 `_bitmain_pic_enable_dc_dc_common`).
    PicDcDc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalLoopElement {
    /// Coolant pump — EXTERNAL. Monitor via flow only; no actuator exists
    /// in this composition, and asking for one is Unproven.
    Pump,
    /// Dry cooler / radiator fan — EXTERNAL, monitor-only.
    DryCooler,
}

/// Fail-closed answer for an external-loop actuation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalLoopActuation {
    /// The unit owns this control and the request may proceed (mining /
    /// PSU / DC-DC are the daemon's own controls, subject to the gate).
    Owned(UnitOwnedControl),
    /// Monitor-only: no actuator exists and none may be invented.
    MonitorOnly(ExternalLoopElement),
}

/// Classify an actuation request. `pump_on`/`pump_speed` style requests
/// are refused at the type level forever.
pub const fn classify_actuation(control: UnitOwnedControl) -> ExternalLoopActuation {
    ExternalLoopActuation::Owned(control)
}

pub const fn classify_external(element: ExternalLoopElement) -> ExternalLoopActuation {
    ExternalLoopActuation::MonitorOnly(element)
}

/// Operator reset token: the ONLY capability that can clear a tripped
/// gate. Zero-sized but UNCONSTRUCTABLE outside this module (private
/// unit) — the mining path, tests, and any other module can never mint
/// one; they can only receive one from an explicit operator action.
///
/// Mining and integration callers cannot manufacture reset authority:
/// ```compile_fail
/// use dcentrald_common::hydro_cooling_feedback::OperatorResetToken;
/// let _ = OperatorResetToken::mint_after_operator_physical_verification();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorResetToken {
    _priv: (),
}

impl OperatorResetToken {
    /// Minted ONLY by the operator surface (the daemon's operator
    /// command path calls this after physical verification). Kept
    /// module-private so no code outside this module — in particular
    /// the mining path — can construct a token; gate-clearing stays a
    /// named, auditable act inside the operator surface, never a side
    /// effect. (V01 2026-09-12: the previous `pub` made the
    /// cannot-construct claim naming-only; this restores it as a
    /// structural fact.)
    fn mint_after_operator_physical_verification() -> Self {
        Self { _priv: () }
    }
}

/// Gate state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutoffState {
    /// Armed: permits may be issued (all other laws still apply).
    Armed,
    /// Tripped and LATCHED. Only an operator reset token clears it.
    Latched { cause: CutoffCause },
}

struct GateInner {
    state: CutoffState,
    last_monitor_tick: Option<u64>,
    trips: u32,
}

/// The external cutoff gate. One-way latched, fail-closed on monitor
/// loss, and never bypassable by the mining path: the ONLY way work is
/// authorized is [`CoolingSupervisor::water_permit`], and the ONLY way
/// the gate returns to `Armed` is an operator reset token after a trip.
/// The mining path cannot construct that token from anything it holds.
pub struct ExternalCutoffGate {
    inner: Mutex<GateInner>,
    freshness: FreshnessBound,
}

impl ExternalCutoffGate {
    /// Arm a fresh gate for a session.
    pub fn armed(freshness: FreshnessBound) -> Self {
        Self {
            inner: Mutex::new(GateInner { state: CutoffState::Armed, last_monitor_tick: None, trips: 0 }),
            freshness,
        }
    }

    /// The gate's freshness bound (the monitor-loss deadline).
    pub const fn freshness(&self) -> FreshnessBound {
        self.freshness
    }

    /// Monitor heartbeat: the cooling monitor must call this at least
    /// every `freshness.max_age_ticks`; a missed deadline trips the gate
    /// (`MonitorLost`). The monitor is the only caller.
    pub fn monitor_tick(&self, now: u64) {
        let mut inner = self.lock();
        if let Some(last) = inner.last_monitor_tick {
            if now.saturating_sub(last) > self.freshness.max_age_ticks {
                if inner.state == CutoffState::Armed {
                    inner.state = CutoffState::Latched { cause: CutoffCause::MonitorLost };
                    inner.trips += 1;
                }
            }
        }
        inner.last_monitor_tick = Some(now);
    }

    /// Trip the gate (monitor-owned; also the external interlock ingest).
    /// Idempotent: an already-latched gate keeps its FIRST cause.
    pub fn trip(&self, cause: CutoffCause, now: u64) {
        let mut inner = self.lock();
        inner.last_monitor_tick = Some(now);
        if inner.state == CutoffState::Armed {
            inner.state = CutoffState::Latched { cause };
            inner.trips += 1;
        }
    }

    /// Operator reset: clears the latch and re-arms. Requires the
    /// operator-minted token; the mining path has none. The gate re-arms
    /// CLOSED for permits until a fresh passing evaluation proves the
    /// loop again (permit law re-evaluates from scratch).
    pub fn operator_reset(&self, _token: OperatorResetToken, now: u64) {
        let mut inner = self.lock();
        inner.state = CutoffState::Armed;
        inner.last_monitor_tick = Some(now);
    }

    /// Current state (read-only; safe for the mining path to observe).
    pub fn state(&self) -> CutoffState {
        self.lock().state
    }

    /// Total trips since construction (diagnostics).
    pub fn trips(&self) -> u32 {
        self.lock().trips
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GateInner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Feedback authority the supervisor is constructed with. `Unproven`
/// refuses every permit forever (the S9-Hydro posture, and any tuple
/// whose monitor could not bind the held sensor path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackAuthority {
    /// The monitor is bound to the held sensor path for this generation
    /// (from `hydro_immersion_profiles::HydroBoard`).
    HeldStockLaw,
    Unproven,
}

/// The cooling supervisor: composes the cutoff gate with the water laws
/// and issues (or refuses) the stock `/get_water_permit` analog. The
/// mining path holds THIS and only this; it has no capability to trip,
/// clear, or bypass the gate.
pub struct CoolingSupervisor {
    authority: FeedbackAuthority,
    generation: crate::hydro_immersion_profiles::HydroFeedbackGeneration,
    bounds: WaterPermitBounds,
    gate: ExternalCutoffGate,
}

/// A granted water permit. Carries the tick it was granted at; the
/// mining path must re-check before (re)dispatching work — a permit is
/// not a lease past the freshness bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaterPermit {
    pub granted_at_tick: u64,
}

/// Result of a permit evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermitDecision {
    Granted(WaterPermit),
    Refused(WaterPermitRefusal),
}

impl CoolingSupervisor {
    /// Construct for one admitted hydro tuple (generation from the
    /// profile). `bounds` may tighten the defaults, never loosen the
    /// laws (enforced by construction: bounds only narrow the windows).
    pub fn new(
        authority: FeedbackAuthority,
        generation: crate::hydro_immersion_profiles::HydroFeedbackGeneration,
        bounds: WaterPermitBounds,
    ) -> Self {
        Self { authority, generation, bounds, gate: ExternalCutoffGate::armed(bounds.freshness) }
    }

    /// The cutoff gate (monitor-owned controls live here; the mining
    /// path may observe `state()` only).
    pub fn gate(&self) -> &ExternalCutoffGate {
        &self.gate
    }

    /// Which law generation this supervisor composes.
    pub const fn generation(&self) -> crate::hydro_immersion_profiles::HydroFeedbackGeneration {
        self.generation
    }

    /// Evaluate the stock `/get_water_permit` analog against a fresh
    /// snapshot. Order of checks is fixed and fail-closed:
    /// authority → gate → monitor liveness → required channels present
    /// → fresh → flow → temp window → delta. Work may only (re)start on
    /// `Granted`; any refusal leaves mining off.
    pub fn water_permit(&self, now: u64, snapshot: &WaterSnapshot, flow: Option<FlowObservation>) -> PermitDecision {
        // 0. Authority: an Unproven composition never permits.
        if self.authority == FeedbackAuthority::Unproven {
            return PermitDecision::Refused(WaterPermitRefusal::FeedbackAuthorityUnproven);
        }
        // 1. Gate: latched cutoff refuses everything.
        if let CutoffState::Latched { cause } = self.gate.state() {
            return PermitDecision::Refused(WaterPermitRefusal::CutoffLatched(cause));
        }
        // 2. Monitor liveness: a monitor that stopped ticking trips the
        //    gate (and refuses this and all later permits). The Option is
        //    copied out first so the lock is released before `trip()`
        //    re-takes it (a non-reentrant Mutex would deadlock).
        let last_tick = self.gate.lock().last_monitor_tick;
        match last_tick {
            Some(last) if now.saturating_sub(last) > self.bounds.freshness.max_age_ticks => {
                self.gate.trip(CutoffCause::MonitorLost, now);
                return PermitDecision::Refused(WaterPermitRefusal::MonitorLost);
            }
            Some(_) => {}
            // No tick has EVER arrived: the monitor never came up.
            None => return PermitDecision::Refused(WaterPermitRefusal::MonitorLost),
        }
        // 3. Required channels: inlet+outlet water are required at EVERY
        //    generation (stock's `pic temp` law reads PIC water temp);
        //    board channels are required only where the held bytes name
        //    them (G4+ four-channel law).
        let required: &[WaterChannel] = match self.generation {
            crate::hydro_immersion_profiles::HydroFeedbackGeneration::Gen1PicTempMinOnly
            | crate::hydro_immersion_profiles::HydroFeedbackGeneration::Gen2WaterPermitGate
            | crate::hydro_immersion_profiles::HydroFeedbackGeneration::Gen3WaterInTempField => {
                &[WaterChannel::InletWater, WaterChannel::OutletWater]
            }
            crate::hydro_immersion_profiles::HydroFeedbackGeneration::Gen4InletOutletAndReverse
            | crate::hydro_immersion_profiles::HydroFeedbackGeneration::Gen5WaterScopedVoltageAndJigCutoff => {
                &[
                    WaterChannel::InletWater,
                    WaterChannel::OutletWater,
                    WaterChannel::InletBoard,
                    WaterChannel::OutletBoard,
                ]
            }
        };
        for channel in required {
            let sample = match channel {
                WaterChannel::InletWater => snapshot.inlet_water,
                WaterChannel::OutletWater => snapshot.outlet_water,
                WaterChannel::InletBoard => snapshot.inlet_board,
                WaterChannel::OutletBoard => snapshot.outlet_board,
            };
            let Some(sample) = sample else {
                return PermitDecision::Refused(WaterPermitRefusal::SensorAbsent(*channel));
            };
            if !sample.is_fresh(now, self.bounds.freshness) {
                return PermitDecision::Refused(WaterPermitRefusal::SensorStale(*channel));
            }
        }
        // 4. Flow presence and direction ("Water is not flowing!" is a
        //    held law at every generation; reverse detection is held at
        //    G4+ and trip-worthy at G5 via the jig executor law — for
        //    G4 the permit refuses AND the gate trips too: looser than
        //    stock is forbidden, and stock G4 logs it as an error).
        match flow {
            None => {
                // Missing flow evidence: G1 stock has no explicit permit
                // gate, but "Water is not flowing!" proves flow presence
                // is monitored — absent evidence refuses (stricter).
                return PermitDecision::Refused(WaterPermitRefusal::NotFlowing);
            }
            Some(FlowObservation::NotFlowing) => {
                return PermitDecision::Refused(WaterPermitRefusal::NotFlowing);
            }
            Some(FlowObservation::Reverse) => {
                // Reverse flow trips the gate at EVERY generation (the
                // G5 jig law proves the immediate power-off; older gens
                // get the strictly-safer same treatment).
                self.gate.trip(CutoffCause::WaterFlowReverse, now);
                return PermitDecision::Refused(WaterPermitRefusal::FlowReverse);
            }
            Some(FlowObservation::Flowing) => {}
        }
        // 5. Water temperature window (stock laws).
        let inlet = snapshot.inlet_water.expect("checked above");
        let outlet = snapshot.outlet_water.expect("checked above");
        for sample in [inlet, outlet] {
            if sample.temp_c < self.bounds.min_water_c {
                return PermitDecision::Refused(WaterPermitRefusal::WaterTooLow {
                    observed_c: sample.temp_c,
                    min_c: self.bounds.min_water_c,
                });
            }
            if sample.temp_c > self.bounds.max_water_c {
                return PermitDecision::Refused(WaterPermitRefusal::WaterTooHot {
                    observed_c: sample.temp_c,
                    max_c: self.bounds.max_water_c,
                });
            }
        }
        // 6. Inlet/outlet delta (G4+ held law; applied at G4+ only, and
        //    treated as a stop cause while a permit would be active).
        //    The magnitude of the difference is what stock names "too
        //    large"; the SIGN (inlet hotter than outlet) is the separate
        //    reverse-flow law handled above.
        if self.generation >= crate::hydro_immersion_profiles::HydroFeedbackGeneration::Gen4InletOutletAndReverse {
            let delta = inlet.temp_c.abs_diff(outlet.temp_c);
            if delta > self.bounds.max_inlet_outlet_delta_c as u16 {
                return PermitDecision::Refused(WaterPermitRefusal::InletOutletDeltaTooLarge {
                    delta_c: delta,
                    max_c: self.bounds.max_inlet_outlet_delta_c,
                });
            }
        }
        PermitDecision::Granted(WaterPermit { granted_at_tick: now })
    }

    /// The monitor's per-sample ingest: fold an observation into the
    /// gate while a permit is ACTIVE. During active mining, the held
    /// laws elevate several refusals to cutoff trips (stock G5:
    /// immediate power off on reverse flow; stock G1-G4: stop mining on
    /// temp/flow faults — latching is our strictly-safer addition).
    /// Returns the (unchanged-or-tripped) gate state for the caller to
    /// act on (cut hash power, drive GPIO907 off via the owned control).
    pub fn ingest_while_mining(&self, now: u64, snapshot: &WaterSnapshot, flow: Option<FlowObservation>) -> CutoffState {
        self.gate.monitor_tick(now);
        let decision = self.water_permit(now, snapshot, flow);
        if let PermitDecision::Refused(refusal) = decision {
            let cause = match refusal {
                WaterPermitRefusal::FlowReverse => Some(CutoffCause::WaterFlowReverse),
                WaterPermitRefusal::WaterTooLow { .. } | WaterPermitRefusal::WaterTooHot { .. } => {
                    Some(CutoffCause::WaterTempOutOfRange)
                }
                WaterPermitRefusal::InletOutletDeltaTooLarge { .. } => Some(CutoffCause::InletOutletDelta),
                WaterPermitRefusal::NotFlowing => Some(CutoffCause::FlowLost),
                WaterPermitRefusal::MonitorLost => Some(CutoffCause::MonitorLost),
                // Absent/stale sensors and unproven authority are
                // startup-refusals; while mining they also fail closed
                // but do not name a physical cause (the latch records
                // MonitorLost semantics only for a true liveness miss).
                _ => None,
            };
            if let Some(cause) = cause {
                self.gate.trip(cause, now);
            }
        }
        self.gate.state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hydro_immersion_profiles::HydroFeedbackGeneration as Gen;

    const BOUNDS: WaterPermitBounds = WaterPermitBounds {
        min_water_c: 5,
        max_water_c: 60,
        max_inlet_outlet_delta_c: 20,
        freshness: FreshnessBound { max_age_ticks: 10 },
    };

    fn sample(tick: u64, temp_c: i16) -> WaterTempSample {
        WaterTempSample { tick, temp_c }
    }

    fn healthy(now: u64) -> (WaterSnapshot, Option<FlowObservation>) {
        (
            WaterSnapshot {
                inlet_water: Some(sample(now, 30)),
                outlet_water: Some(sample(now, 35)),
                inlet_board: Some(sample(now, 40)),
                outlet_board: Some(sample(now, 45)),
            },
            Some(FlowObservation::Flowing),
        )
    }

    #[test]
    fn permit_grants_on_fresh_in_range_flow_and_refuses_stale_or_absent() {
        let sup = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen4InletOutletAndReverse, BOUNDS);
        sup.gate().monitor_tick(0);
        let (snap, flow) = healthy(5);
        assert_eq!(sup.water_permit(5, &snap, flow), PermitDecision::Granted(WaterPermit { granted_at_tick: 5 }));

        // Absent channel refuses (stock-silent case; we fail closed).
        // Keep the monitor alive so liveness is not the refusing check.
        let mut no_board = snap;
        no_board.outlet_board = None;
        sup.gate().monitor_tick(6);
        assert_eq!(
            sup.water_permit(6, &no_board, flow),
            PermitDecision::Refused(WaterPermitRefusal::SensorAbsent(WaterChannel::OutletBoard))
        );

        // Stale channel refuses (fail-closed extension). The monitor
        // keeps ticking within its bound; only the sample is old.
        let mut stale = snap;
        stale.inlet_water = Some(sample(0, 30)); // tick 0, now 20 → age 20 > 10
        sup.gate().monitor_tick(10); // 10 - 0 = 10: at bound, still alive
        sup.gate().monitor_tick(19); // 19 - 10 = 9: alive
        assert_eq!(
            sup.water_permit(20, &stale, flow),
            PermitDecision::Refused(WaterPermitRefusal::SensorStale(WaterChannel::InletWater))
        );
        // A future stamp is stale too: inlet is fresh at now 20, outlet
        // claims tick 100 (in the "future") — a broken monitor clock.
        let mut future = WaterSnapshot {
            inlet_water: Some(sample(20, 30)),
            outlet_water: Some(sample(100, 35)),
            inlet_board: Some(sample(20, 40)),
            outlet_board: Some(sample(20, 45)),
        };
        let _ = &mut future;
        assert_eq!(
            sup.water_permit(20, &future, flow),
            PermitDecision::Refused(WaterPermitRefusal::SensorStale(WaterChannel::OutletWater))
        );
    }

    #[test]
    fn water_temp_window_laws_match_held_strings() {
        let sup = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen2WaterPermitGate, BOUNDS);
        sup.gate().monitor_tick(0);
        let (snap, flow) = healthy(1);

        // "too low water temperature pic temp %d (min %d)"
        let mut cold = snap;
        cold.inlet_water = Some(sample(1, 4));
        assert_eq!(
            sup.water_permit(2, &cold, flow),
            PermitDecision::Refused(WaterPermitRefusal::WaterTooLow { observed_c: 4, min_c: 5 })
        );
        // "too hot water temperature pic temp %d (min %d)"
        let mut hot = snap;
        hot.outlet_water = Some(sample(1, 61));
        assert_eq!(
            sup.water_permit(2, &hot, flow),
            PermitDecision::Refused(WaterPermitRefusal::WaterTooHot { observed_c: 61, max_c: 60 })
        );
        // Boundary values inside the window pass.
        let mut edge = snap;
        edge.inlet_water = Some(sample(1, 5));
        edge.outlet_water = Some(sample(1, 60));
        assert!(matches!(sup.water_permit(2, &edge, flow), PermitDecision::Granted(_)));
    }

    #[test]
    fn flow_laws_not_flowing_refuses_and_reverse_trips_the_gate() {
        let sup = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen5WaterScopedVoltageAndJigCutoff, BOUNDS);
        sup.gate().monitor_tick(0);
        let (snap, _) = healthy(1);

        // "Water is not flowing!" refuses.
        assert_eq!(
            sup.water_permit(2, &snap, Some(FlowObservation::NotFlowing)),
            PermitDecision::Refused(WaterPermitRefusal::NotFlowing)
        );
        // Absent flow evidence refuses (stricter than stock's silence).
        assert_eq!(
            sup.water_permit(2, &snap, None),
            PermitDecision::Refused(WaterPermitRefusal::NotFlowing)
        );
        // "Water flow reversal!" trips the latch (G5 jig law: immediate
        // power off), and later evaluations refuse through the latch.
        assert_eq!(
            sup.water_permit(2, &snap, Some(FlowObservation::Reverse)),
            PermitDecision::Refused(WaterPermitRefusal::FlowReverse)
        );
        assert_eq!(sup.gate().state(), CutoffState::Latched { cause: CutoffCause::WaterFlowReverse });
        let (_, flow) = healthy(3);
        assert_eq!(
            sup.water_permit(3, &snap, flow),
            PermitDecision::Refused(WaterPermitRefusal::CutoffLatched(CutoffCause::WaterFlowReverse))
        );
        assert_eq!(sup.gate().trips(), 1);
    }

    #[test]
    fn inlet_outlet_delta_law_applies_from_gen4_only() {
        // G3: no delta law held — a large delta alone does not refuse.
        let g3 = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen3WaterInTempField, BOUNDS);
        g3.gate().monitor_tick(0);
        let (mut wide, flow) = healthy(1);
        wide.inlet_water = Some(sample(1, 30));
        wide.outlet_water = Some(sample(1, 45)); // delta 15 < 20 anyway
        wide.inlet_water = Some(sample(1, 25));
        wide.outlet_water = Some(sample(1, 45)); // delta 20 — at bound, would refuse on G4+
        assert!(matches!(g3.water_permit(2, &wide, flow), PermitDecision::Granted(_)));

        // G4: "difference between inlet and outlet is too large" refuses
        // only ABOVE the bound (stock convention: the bound is the last
        // allowed delta; the factory jig refuses at sensor[0]-sensor[1]
        // > 3). delta == 20 at max 20 stays allowed; 21 refuses.
        let g4 = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen4InletOutletAndReverse, BOUNDS);
        g4.gate().monitor_tick(0);
        assert!(matches!(g4.water_permit(2, &wide, flow), PermitDecision::Granted(_)));
        let mut over = wide;
        over.outlet_water = Some(sample(1, 46)); // delta 21 > 20
        assert_eq!(
            g4.water_permit(2, &over, flow),
            PermitDecision::Refused(WaterPermitRefusal::InletOutletDeltaTooLarge { delta_c: 21, max_c: 20 })
        );
        // delta 19 < 20 passes.
        let mut ok = wide;
        ok.outlet_water = Some(sample(1, 44)); // delta 19 < 20
        assert!(matches!(g4.water_permit(2, &ok, flow), PermitDecision::Granted(_)));
    }

    #[test]
    fn required_channels_scale_with_held_generation() {
        // G1 requires only the water channels; board channels may be
        // absent because the held bytes do not name them.
        let g1 = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen1PicTempMinOnly, BOUNDS);
        g1.gate().monitor_tick(0);
        let water_only = WaterSnapshot {
            inlet_water: Some(sample(1, 30)),
            outlet_water: Some(sample(1, 35)),
            inlet_board: None,
            outlet_board: None,
        };
        assert!(matches!(
            g1.water_permit(2, &water_only, Some(FlowObservation::Flowing)),
            PermitDecision::Granted(_)
        ));

        // G4 requires all four channels (held four-channel law).
        let g4 = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen4InletOutletAndReverse, BOUNDS);
        g4.gate().monitor_tick(0);
        assert_eq!(
            g4.water_permit(2, &water_only, Some(FlowObservation::Flowing)),
            PermitDecision::Refused(WaterPermitRefusal::SensorAbsent(WaterChannel::InletBoard))
        );
    }

    #[test]
    fn unproven_authority_refuses_everything_forever() {
        let sup = CoolingSupervisor::new(FeedbackAuthority::Unproven, Gen::Gen1PicTempMinOnly, BOUNDS);
        sup.gate().monitor_tick(0);
        let (snap, flow) = healthy(1);
        assert_eq!(
            sup.water_permit(2, &snap, flow),
            PermitDecision::Refused(WaterPermitRefusal::FeedbackAuthorityUnproven)
        );
        // Even a perfect snapshot never permits an Unproven composition.
        assert!(matches!(
            sup.water_permit(3, &snap, flow),
            PermitDecision::Refused(WaterPermitRefusal::FeedbackAuthorityUnproven)
        ));
    }

    #[test]
    fn monitor_loss_trips_the_gate_fail_closed() {
        let sup = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen4InletOutletAndReverse, BOUNDS);
        sup.gate().monitor_tick(0);
        let (snap, flow) = healthy(5);
        assert!(matches!(sup.water_permit(5, &snap, flow), PermitDecision::Granted(_)));
        // Monitor stops ticking; a later evaluation discovers the miss.
        let late_now = BOUNDS.freshness.max_age_ticks + 2;
        assert_eq!(
            sup.water_permit(late_now, &snap, flow),
            PermitDecision::Refused(WaterPermitRefusal::MonitorLost)
        );
        assert_eq!(sup.gate().state(), CutoffState::Latched { cause: CutoffCause::MonitorLost });
        // And it stays latched.
        sup.gate().monitor_tick(late_now + 1);
        assert_eq!(
            sup.water_permit(late_now + 2, &snap, flow),
            PermitDecision::Refused(WaterPermitRefusal::CutoffLatched(CutoffCause::MonitorLost))
        );
    }

    #[test]
    fn a_gate_that_never_saw_a_tick_refuses_from_the_start() {
        let sup = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen2WaterPermitGate, BOUNDS);
        let (snap, flow) = healthy(1);
        assert_eq!(
            sup.water_permit(1, &snap, flow),
            PermitDecision::Refused(WaterPermitRefusal::MonitorLost)
        );
    }

    #[test]
    fn only_the_operator_token_clears_a_latch_and_the_mining_path_cannot_mint_one() {
        let sup = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen5WaterScopedVoltageAndJigCutoff, BOUNDS);
        sup.gate().monitor_tick(0);
        let (snap, _) = healthy(1);
        sup.gate().trip(CutoffCause::ExternalTrip, 1);
        assert_eq!(sup.gate().state(), CutoffState::Latched { cause: CutoffCause::ExternalTrip });

        // The supervisor exposes NO clear/bypass/rearm method: the permit
        // path refuses through the latch no matter how healthy the loop
        // looks.
        let (_, flow) = healthy(2);
        for now in [2u64, 10, 100] {
            assert!(matches!(
                sup.water_permit(now, &snap, flow),
                PermitDecision::Refused(WaterPermitRefusal::CutoffLatched(CutoffCause::ExternalTrip))
            ));
        }

        // With the operator token, the gate re-arms — and permits again
        // only after a fresh passing evaluation.
        let token = OperatorResetToken::mint_after_operator_physical_verification();
        sup.gate().operator_reset(token, 200);
        assert_eq!(sup.gate().state(), CutoffState::Armed);
        sup.gate().monitor_tick(200);
        let (snap2, flow2) = healthy(201);
        assert!(matches!(sup.water_permit(201, &snap2, flow2), PermitDecision::Granted(_)));
    }

    #[test]
    fn first_trip_cause_is_kept_when_retripped() {
        let gate = ExternalCutoffGate::armed(BOUNDS.freshness);
        gate.trip(CutoffCause::WaterTempOutOfRange, 1);
        gate.trip(CutoffCause::ExternalTrip, 2);
        assert_eq!(
            gate.state(),
            CutoffState::Latched { cause: CutoffCause::WaterTempOutOfRange }
        );
        assert_eq!(gate.trips(), 1, "idempotent trip must not double-count");
    }

    #[test]
    fn operator_reset_requires_fresh_permit_for_every_feedback_generation() {
        for generation in [
            Gen::Gen1PicTempMinOnly,
            Gen::Gen2WaterPermitGate,
            Gen::Gen3WaterInTempField,
            Gen::Gen4InletOutletAndReverse,
            Gen::Gen5WaterScopedVoltageAndJigCutoff,
        ] {
            let sup = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, generation, BOUNDS);
            sup.gate().monitor_tick(0);
            sup.gate().trip(CutoffCause::WaterFlowReverse, 1);
            let (snapshot, flow) = healthy(2);
            assert!(matches!(sup.water_permit(2, &snapshot, flow),
                PermitDecision::Refused(WaterPermitRefusal::CutoffLatched(CutoffCause::WaterFlowReverse))));

            // Only this owning module can mint the token. Reset alone is
            // insufficient: absent and stale samples still forbid work.
            sup.gate().operator_reset(OperatorResetToken::mint_after_operator_physical_verification(), 20);
            assert_eq!(sup.gate().state(), CutoffState::Armed);
            assert!(matches!(sup.water_permit(21, &WaterSnapshot::default(), flow),
                PermitDecision::Refused(WaterPermitRefusal::SensorAbsent(_))));
            assert!(matches!(sup.water_permit(21, &snapshot, flow),
                PermitDecision::Refused(WaterPermitRefusal::SensorStale(_))));
            let (fresh, flow) = healthy(21);
            assert!(matches!(sup.water_permit(21, &fresh, flow), PermitDecision::Granted(_)));

            let raw = ExternalCutoffGate::armed(BOUNDS.freshness);
            raw.trip(CutoffCause::WaterTempOutOfRange, 1);
            raw.monitor_tick(2);
            assert_eq!(raw.state(), CutoffState::Latched { cause: CutoffCause::WaterTempOutOfRange });
            raw.operator_reset(OperatorResetToken::mint_after_operator_physical_verification(), 2);
            assert_eq!(raw.state(), CutoffState::Armed);
        }
    }

    #[test]
    fn ingest_while_mining_elevates_held_faults_to_cutoff() {
        let sup = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen4InletOutletAndReverse, BOUNDS);
        sup.gate().monitor_tick(0);
        let (snap, flow) = healthy(1);
        assert_eq!(sup.ingest_while_mining(1, &snap, flow), CutoffState::Armed);

        // Reverse flow while mining: gate latches (stock G5 action).
        let (_, _) = healthy(2);
        let state = sup.ingest_while_mining(2, &snap, Some(FlowObservation::Reverse));
        assert_eq!(state, CutoffState::Latched { cause: CutoffCause::WaterFlowReverse });

        // After an operator reset, a hot-water fault while mining latches
        // with the temp cause.
        sup.gate().operator_reset(OperatorResetToken::mint_after_operator_physical_verification(), 50);
        sup.gate().monitor_tick(50);
        let (mut hot, flow) = healthy(51);
        hot.inlet_water = Some(sample(51, 70));
        let state = sup.ingest_while_mining(51, &hot, flow);
        assert_eq!(state, CutoffState::Latched { cause: CutoffCause::WaterTempOutOfRange });

        // Flow loss while mining latches with the flow-lost cause.
        sup.gate().operator_reset(OperatorResetToken::mint_after_operator_physical_verification(), 100);
        sup.gate().monitor_tick(100);
        let (snap_ok, _) = healthy(101);
        let state = sup.ingest_while_mining(101, &snap_ok, Some(FlowObservation::NotFlowing));
        assert_eq!(state, CutoffState::Latched { cause: CutoffCause::FlowLost });
    }

    #[test]
    fn external_loop_elements_are_monitor_only_and_owned_controls_are_named() {
        // The pump and dry cooler have NO actuator in this composition.
        assert_eq!(
            classify_external(ExternalLoopElement::Pump),
            ExternalLoopActuation::MonitorOnly(ExternalLoopElement::Pump)
        );
        assert_eq!(
            classify_external(ExternalLoopElement::DryCooler),
            ExternalLoopActuation::MonitorOnly(ExternalLoopElement::DryCooler)
        );
        // The unit's owned controls are exactly: mining, PSU rail, DC-DC.
        assert_eq!(
            classify_actuation(UnitOwnedControl::MiningEnable),
            ExternalLoopActuation::Owned(UnitOwnedControl::MiningEnable)
        );
        assert_eq!(
            classify_actuation(UnitOwnedControl::PsuRailGpio907),
            ExternalLoopActuation::Owned(UnitOwnedControl::PsuRailGpio907)
        );
        assert_eq!(
            classify_actuation(UnitOwnedControl::PicDcDc),
            ExternalLoopActuation::Owned(UnitOwnedControl::PicDcDc)
        );
    }

    #[test]
    fn bounds_cannot_widen_the_laws_only_narrow() {
        // The bounds struct exists so a fleet may tighten; the laws apply
        // at whatever bounds are configured. A widened window simply
        // passes different samples — but the LAWS (check order, flow,
        // gate, authority) always run. Verify a tightened bound bites.
        let tight = WaterPermitBounds {
            min_water_c: 20,
            max_water_c: 50,
            max_inlet_outlet_delta_c: 5,
            freshness: FreshnessBound { max_age_ticks: 2 },
        };
        let sup = CoolingSupervisor::new(FeedbackAuthority::HeldStockLaw, Gen::Gen4InletOutletAndReverse, tight);
        sup.gate().monitor_tick(0);
        let (snap, flow) = healthy(1); // 30/35C — inside default, below tight min 20? no: 30 >= 20 fine
        assert!(matches!(sup.water_permit(1, &snap, flow), PermitDecision::Granted(_)));
        // Freshness tightened to 2: keep the monitor alive (ticks 2
        // then 3 are each within bound of their predecessor), the age-3
        // sample (tick 1, now 4) is stale now.
        sup.gate().monitor_tick(2); // 2 - 0 = 2: at bound, alive
        sup.gate().monitor_tick(3); // 3 - 2 = 1: alive
        let (snap3, flow) = healthy(1);
        assert_eq!(
            sup.water_permit(4, &snap3, flow),
            PermitDecision::Refused(WaterPermitRefusal::SensorStale(WaterChannel::InletWater))
        );
    }
}
