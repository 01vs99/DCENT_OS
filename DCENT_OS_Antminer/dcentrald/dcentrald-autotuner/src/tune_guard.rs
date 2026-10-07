//! C3a (2026-09-01, Supremacy Gauntlet lane C3a): variant envelope + cut-ladder
//! guard for the autotuner — the safety substrate that makes "autotune
//! default-ON everywhere" (operator decision 2026-09-01) shippable.
//!
//! # The rule this module enforces
//!
//! **Refuse, do not tune blind.** Every tuning action (a frequency step, a
//! voltage step) is validated against the variant's declared envelope AND the
//! BoardDesc cut-ladder semantics BEFORE it is handed to the dispatcher. A
//! variant whose envelope datums are UNKNOWN or missing refuses to tune at
//! all with an explicit, surfaced `NotTunable` reason. This is the
//! fail-closed direction the operator decision requires: default-ON must
//! never become "default-tuning-without-data".
//!
//! # Envelope sources (honesty: only published datums)
//!
//! - **BM1387 + PIC16 (am1-s9)** — the desk-published S9 band:
//!   frequency `[200, 750]` MHz (the shipped `min_freq_mhz`/`max_freq_mhz`
//!   safety clamp pair in `dcentrald.toml` `[autotuner]` and the crate
//!   defaults), chain-rail voltage `[8400, 9400]` mV (floor: the documented
//!   "S9 safe range" — see `config.rs::default_min_voltage` doc and
//!   `AutoTunerConfig::min_voltage_mv`; ceiling: PIC DAC 6 = 9.40 V, the
//!   codebase's safe operating ceiling — `S9_STOCK_ELECTRICAL_ANALYSIS.md`
//!   §1.3 DAC table and `dcentrald-common/src/voltage_rail.rs`
//!   `PIC16_MIN_SAFE_DAC`/`STOCK_PIC16_INIT_MV`; DAC 0 = 9.44 V is the
//!   absolute-max overvolt stock firmware never uses). No core-rail band:
//!   the S9 voltage actuator (PIC16 DAC) writes the chain rail only.
//! - **BM1362 (am2 S19j Pro family)** — the per-SKU PVT envelope from
//!   [`dcentrald_silicon_profiles::bm1362::Bm1362HashboardSku::freq_voltage_table`]
//!   (frequency band + CORE-rail mV band), available ONLY when the daemon
//!   classified a uniform SKU for the chains (`set_chain_sku`). Without a
//!   classified SKU the variant refuses to tune
//!   ([`NotTunableReason::VariantEnvelopeUnknown`]) — the pre-C3a behavior
//!   (open gate / no clamp) is deliberately NOT preserved: an unclassified
//!   board has no envelope datums, so under a default-ON autotuner it must
//!   surface NotTunable instead of probing blind. When the (default-OFF,
//!   live-safety fence) `DCENT_AM2_VOLTAGE_AUTOTUNE` env gate is armed, the
//!   dsPIC chain-rail window `[13700, 14500]` mV
//!   ([`crate::config::AM2_DSPIC_VOLTAGE_AUTOTUNE_MIN_MV`] /
//!   [`crate::config::AM2_DSPIC_VOLTAGE_AUTOTUNE_MAX_MV`]) is additionally
//!   declared for chain-rail-axis voltage steps.
//! - **Everything else (BM1366 / BM1368 / BM1370 / BM1397 / BM1398 / …)** —
//!   no published per-variant envelope datums exist desk-side today; those
//!   variants refuse to tune with [`NotTunableReason::VariantEnvelopeUnknown`]
//!   until their B-lane BoardDesc/envelope rows land. That refusal is the
//!   product behavior, not a gap: the dashboard surfaces the reason.
//!
//! # Voltage axes (load-bearing)
//!
//! Reuses [`crate::pvt_envelope::classify_voltage_axis`]: core-rail
//! (~0.5-2.0 V, per-domain core mV) vs chain-rail (~7.5-15.0 V). A voltage
//! step is validated against the band declared for the axis the requested
//! millivolts actually fall on; a requested axis with no declared band is
//! REFUSED (`VoltAxisUndeclared`) — passing the 13.7 V chain rail where a
//! ~1340 mV core voltage is expected (or vice versa) must never silently
//! pass.
//!
//! # Cut-ladder semantics
//!
//! The guard re-validates the variant's declared
//! [`CoolingMedium`]/[`CutRung`] ladder (from `dcentrald_common::BoardDesc`)
//! at construction with [`validate_cut_ladder`]:
//!
//! - a structurally invalid ladder ⇒ NotTunable (fail-closed);
//! - a fanless medium (hydro/immersion — `CoolingClass::ExternalLoop`) must
//!   carry NO `RaiseFansToCap` rung (absent, not zero): the guard refuses
//!   such a ladder with [`NotTunableReason::FanRungOnFanlessMedium`], so a
//!   fanless variant can never reach a fan-raise actuation through the
//!   tuner's escalation inputs.
//!
//! # Frequency-step direction (why decreases are never blocked)
//!
//! A frequency step ABOVE the envelope maximum is refused regardless of
//! direction — a decrease can never exceed the maximum, so this single rule
//! refuses every dangerous raise while never blocking a heat/power-reducing
//! step-down (thermal backoff, bad-chip actuation, emergency throttle). That
//! matches the codebase-wide decrease-only actuation philosophy
//! (`bad_chip_actuation`). A nominal restore (`FreqStepKind::NominalRestore`)
//! is allowed through with a loud warning when the stock nominal sits above
//! the envelope maximum — returning to the operator's stock point is not
//! tuning, and stranding a chain at a probed frequency because the ENVELOPE
//! is narrower than stock would be the less safe outcome. The event is
//! counted in telemetry so the mismatch is visible.
//!
//! # Mutation-test contract
//!
//! The tests at the bottom of this file include "mutation pins": each
//! load-bearing guard property has a test that fails if the guard is broken
//! in exactly one way (fan rung admitted on fanless, out-of-envelope raise
//! admitted, wrong-axis voltage admitted, unknown variant tuned, …). If you
//! weaken the guard, a named test fails — keep it that way.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use dcentrald_common::cooling_medium::{
    validate_cut_ladder, CoolingMedium, CutLadderError, CutRung, CANONICAL_FORCED_AIR_LADDER,
};
use dcentrald_silicon_profiles::bm1362::Bm1362HashboardSku;

use crate::pvt_envelope::{classify_voltage_axis, pvt_envelope, VoltageAxis};

/// Envelope version tag surfaced in convergence telemetry. Bump when any
/// resolver's declared band changes so dashboard evidence can name the
/// envelope generation it was produced under.
///
/// c3a-2 (fix lane, DCENT_EE merge condition): S9 chain-rail ceiling
/// 9440 → 9400 mV (DAC 6, the codebase's safe operating ceiling — 9440 was
/// DAC 0 absolute-max overvolt).
pub const TUNE_ENVELOPE_VERSION: &str = "c3a-2";

/// The variant's declared tuning envelope.
///
/// Every field is an inclusive bound. `None` voltage bands mean the axis has
/// no published datum for this variant — voltage steps on that axis refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantTuneEnvelope {
    /// Inclusive frequency band (MHz) the variant may be tuned within.
    pub freq_min_mhz: u16,
    /// Inclusive frequency ceiling (MHz). Steps above refuse.
    pub freq_max_mhz: u16,
    /// Inclusive CORE-rail band (mV, ~500-2000) if the variant publishes one.
    pub core_volt_mv: Option<(u16, u16)>,
    /// Inclusive CHAIN-rail band (mV, ~7500-15000) if the variant publishes one.
    pub chain_volt_mv: Option<(u16, u16)>,
    /// Declared cooling medium from the variant's BoardDesc row.
    pub cooling_medium: Option<CoolingMedium>,
    /// Declared cut-ladder from the variant's BoardDesc row.
    pub cut_ladder: &'static [CutRung],
    /// Evidence label (e.g. `bm1387-pic16:documented-s9-band`,
    /// `bm1362-pvt:BHB42601`) — surfaced in telemetry so an operator can see
    /// WHICH envelope refused a step.
    pub source: &'static str,
}

/// Why a variant refuses to tune at all (never tune blind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotTunableReason {
    /// The (chip, voltage-controller) combination has no published envelope
    /// datums desk-side. Tuning is refused until the variant's BoardDesc /
    /// silicon-profile envelope row lands.
    VariantEnvelopeUnknown {
        chip_id: u16,
        voltage_control: String,
    },
    /// BM1362 chains did not resolve a uniform classified SKU, so there is no
    /// PVT table to tune against.
    Bm1362SkuUnclassified,
    /// The declared cut-ladder failed structural validation.
    CutLadderInvalid { detail: String },
    /// The declared medium has no fan actuator but the ladder carries a
    /// `RaiseFansToCap` rung — the rung must be absent, not zero.
    FanRungOnFanlessMedium { position: usize },
}

impl std::fmt::Display for NotTunableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotTunableReason::VariantEnvelopeUnknown {
                chip_id,
                voltage_control,
            } => write!(
                f,
                "variant 0x{chip_id:04X}/{voltage_control} has no published tuning-envelope \
                 datums — refusing to tune blind (NotTunable until its envelope row lands)"
            ),
            NotTunableReason::Bm1362SkuUnclassified => write!(
                f,
                "BM1362 chains did not resolve a uniform classified hashboard SKU — no PVT \
                 envelope, refusing to tune blind"
            ),
            NotTunableReason::CutLadderInvalid { detail } => {
                write!(f, "declared cut-ladder failed validation: {detail}")
            }
            NotTunableReason::FanRungOnFanlessMedium { position } => write!(
                f,
                "fanless medium carries a RaiseFansToCap rung at position {position} — the \
                 rung must be absent, not zero"
            ),
        }
    }
}

/// Why a single tuning step was refused (the tuner stays engaged; the step
/// is not executed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuneStepRefusal {
    /// The variant is NotTunable — every mutating step refuses.
    NotTunable(NotTunableReason),
    /// Frequency step above the variant's envelope ceiling.
    FreqAboveEnvelope {
        chain_id: u8,
        freq_mhz: u16,
        envelope_max_mhz: u16,
        source: &'static str,
    },
    /// Voltage step outside the declared band for its axis.
    VoltOutsideEnvelope {
        chain_id: u8,
        volt_mv: u16,
        axis: VoltageAxisRefusal,
        band: (u16, u16),
        source: &'static str,
    },
    /// Voltage step on an axis the variant declares no band for.
    VoltAxisUndeclared {
        chain_id: u8,
        volt_mv: u16,
        source: &'static str,
    },
}

/// Which voltage axis a refusal happened on (mirrors
/// [`crate::pvt_envelope::VoltageAxis`] in a serde-friendly shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoltageAxisRefusal {
    CoreRail,
    ChainRail,
}

impl VoltageAxisRefusal {
    fn from_axis(axis: VoltageAxis) -> Self {
        match axis {
            VoltageAxis::CoreRail => VoltageAxisRefusal::CoreRail,
            VoltageAxis::ChainRail => VoltageAxisRefusal::ChainRail,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            VoltageAxisRefusal::CoreRail => "core_rail",
            VoltageAxisRefusal::ChainRail => "chain_rail",
        }
    }
}

impl std::fmt::Display for TuneStepRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TuneStepRefusal::NotTunable(reason) => write!(f, "refused (NotTunable): {reason}"),
            TuneStepRefusal::FreqAboveEnvelope {
                chain_id,
                freq_mhz,
                envelope_max_mhz,
                source,
            } => write!(
                f,
                "refused frequency step chain {chain_id}: {freq_mhz} MHz above envelope \
                 ceiling {envelope_max_mhz} MHz (envelope {source})"
            ),
            TuneStepRefusal::VoltOutsideEnvelope {
                chain_id,
                volt_mv,
                axis,
                band,
                source,
            } => write!(
                f,
                "refused voltage step chain {chain_id}: {volt_mv} mV outside {} band \
                 [{}, {}] mV (envelope {source})",
                axis.as_str(),
                band.0,
                band.1
            ),
            TuneStepRefusal::VoltAxisUndeclared {
                chain_id,
                volt_mv,
                source,
            } => write!(
                f,
                "refused voltage step chain {chain_id}: {volt_mv} mV is on an axis the \
                 variant declares no band for (envelope {source})"
            ),
        }
    }
}

/// What kind of frequency step is being requested (see module docs on
/// direction semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreqStepKind {
    /// A tuner-driven step (binary-search probe, boost-back, mode target…).
    TuneStep,
    /// A restore to the variant's stock nominal frequency (allowed through
    /// with a warning when nominal sits above the envelope ceiling).
    NominalRestore,
}

/// Normalize a voltage-controller kind string the same way the capability
/// table does (`config.rs::normalize_voltage_control_kind`).
fn normalize_voltage_control(voltage_control: &str) -> String {
    match voltage_control.trim().to_ascii_lowercase().as_str() {
        "pic16" => "pic16".to_string(),
        "dspic" => "dspic".to_string(),
        "nopic" => "nopic".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Resolve the variant tuning envelope for a (chip, controller, SKU) tuple.
///
/// Pure. `am2_voltage_gate` mirrors the daemon-read
/// `DCENT_AM2_VOLTAGE_AUTOTUNE` live-safety fence (KEEP OFF by default): the
/// dsPIC chain-rail window is only declared when the operator armed it.
///
/// `Err(reason)` is the fail-closed "refuse to tune" answer for variants
/// without published datums.
pub fn resolve_variant_envelope(
    chip_id: u16,
    voltage_control: &str,
    uniform_sku: Option<Bm1362HashboardSku>,
    am2_voltage_gate: bool,
    cooling_medium: Option<CoolingMedium>,
    cut_ladder: &'static [CutRung],
) -> Result<VariantTuneEnvelope, NotTunableReason> {
    let normalized = normalize_voltage_control(voltage_control);

    // Cut-ladder structural validation applies to EVERY variant first: an
    // invalid ladder or a fan rung on a fanless medium is NotTunable before
    // any envelope is even consulted.
    validate_cut_ladder(cooling_medium, cut_ladder).map_err(|e| match e {
        CutLadderError::FanRungOnFanlessMedium { position } => {
            NotTunableReason::FanRungOnFanlessMedium { position }
        }
        other => NotTunableReason::CutLadderInvalid {
            detail: other.to_string(),
        },
    })?;

    match (chip_id, normalized.as_str()) {
        (0x1387, "pic16") => Ok(VariantTuneEnvelope {
            // Desk-published S9 band: the shipped safety-clamp pair
            // (`dcentrald.toml [autotuner] min_freq_mhz=200/max_freq_mhz=750`
            // and the crate defaults) plus the documented S9 chain-rail
            // floor 8400 mV / ceiling 9400 mV. 9400 = PIC DAC 6, the
            // codebase's safe operating ceiling
            // (
            // §1.3 DAC table: DAC 6 → 9.40 V "Init safe voltage"; DAC 0 →
            // 9.44 V is absolute-max overvolt stock never uses), mirrored by
            // `dcentrald-common/src/voltage_rail.rs:429-435`
            // (`PIC16_MIN_SAFE_DAC = 6`, `STOCK_PIC16_INIT_MV = 9400`) and by
            // tuner.rs's 0x1387 chain-voltage clamp — the two must agree.
            // (c3a-2, DCENT_EE merge condition: ceiling was 9440.)
            freq_min_mhz: 200,
            freq_max_mhz: 750,
            core_volt_mv: None,
            chain_volt_mv: Some((8_400, 9_400)),
            cooling_medium,
            cut_ladder,
            source: "bm1387-pic16:documented-s9-band",
        }),
        (0x1362, _) => {
            let Some(sku) = uniform_sku else {
                return Err(NotTunableReason::Bm1362SkuUnclassified);
            };
            let table = pvt_envelope(sku);
            if table.is_empty() {
                return Err(NotTunableReason::Bm1362SkuUnclassified);
            }
            let mut freq_min = u16::MAX;
            let mut freq_max = u16::MIN;
            let mut volt_min = u16::MAX;
            let mut volt_max = u16::MIN;
            for (f, v) in table {
                freq_min = freq_min.min(*f);
                freq_max = freq_max.max(*f);
                volt_min = volt_min.min(*v);
                volt_max = volt_max.max(*v);
            }
            Ok(VariantTuneEnvelope {
                freq_min_mhz: freq_min,
                freq_max_mhz: freq_max,
                core_volt_mv: Some((volt_min, volt_max)),
                // dsPIC chain-rail window only under the live-safety fence.
                chain_volt_mv: if am2_voltage_gate {
                    Some((
                        crate::config::AM2_DSPIC_VOLTAGE_AUTOTUNE_MIN_MV,
                        crate::config::AM2_DSPIC_VOLTAGE_AUTOTUNE_MAX_MV,
                    ))
                } else {
                    None
                },
                cooling_medium,
                cut_ladder,
                source: "bm1362-pvt",
            })
        }
        _ => Err(NotTunableReason::VariantEnvelopeUnknown {
            chip_id,
            voltage_control: normalized,
        }),
    }
}

/// The guard. Constructed with either an envelope (`Ok`) or a NotTunable
/// reason (`Err`); every mutating tuner step consults it BEFORE the step is
/// sent to the dispatcher.
///
/// Counters use interior mutability so guard checks take `&self` (the tuner
/// calls them from `&mut self` contexts with other borrows live).
/// Interior mutability note: counters must be `Sync` (the guard lives
/// inside the tuner task, whose future is `tokio::spawn`ed and therefore
/// `Send`), so they use atomics + a small `Mutex` instead of
/// `Cell`/`RefCell`.
#[derive(Debug)]
pub struct TuneGuard {
    envelope: Result<VariantTuneEnvelope, NotTunableReason>,
    refused_steps: AtomicU32,
    nominal_above_envelope_restores: AtomicU32,
    last_refusal: Mutex<Option<TuneStepRefusal>>,
    /// Description of the most recent step presented to the guard (executed
    /// or refused) — feeds the convergence telemetry's `last_step`.
    last_step: Mutex<Option<String>>,
}

impl Clone for TuneGuard {
    fn clone(&self) -> Self {
        Self {
            envelope: self.envelope.clone(),
            refused_steps: AtomicU32::new(self.refused_steps.load(Ordering::Relaxed)),
            nominal_above_envelope_restores: AtomicU32::new(
                self.nominal_above_envelope_restores.load(Ordering::Relaxed),
            ),
            last_refusal: Mutex::new(self.last_refusal.lock().unwrap_or_else(|e| e.into_inner()).clone()),
            last_step: Mutex::new(self.last_step.lock().unwrap_or_else(|e| e.into_inner()).clone()),
        }
    }
}

impl TuneGuard {
    /// Build a guard from a resolver result.
    pub fn new(envelope: Result<VariantTuneEnvelope, NotTunableReason>) -> Self {
        Self {
            envelope,
            refused_steps: AtomicU32::new(0),
            nominal_above_envelope_restores: AtomicU32::new(0),
            last_refusal: Mutex::new(None),
            last_step: Mutex::new(None),
        }
    }

    /// The envelope this guard enforces, when the variant is tunable.
    pub fn envelope(&self) -> Result<&VariantTuneEnvelope, &NotTunableReason> {
        self.envelope.as_ref()
    }

    /// True when the variant is tunable (envelope resolved + ladder valid).
    pub fn tunable(&self) -> bool {
        self.envelope.is_ok()
    }

    /// True when the variant's medium has a fan actuator the ladder may
    /// command. On a fanless variant a fan-raise actuation must be
    /// UNREACHABLE — the guard construction already refused any ladder that
    /// carries a fan rung on a fanless medium, so this accessor is the
    /// negative-space proof: the tuner can ask, and the answer is `false`.
    pub fn fan_raise_reachable(&self) -> bool {
        match self.envelope.as_ref() {
            Ok(env) => env
                .cooling_medium
                .map(|m| m.has_fan_actuator())
                // Undeclared medium keeps forced-air rules (fans stay
                // managed) — the conservative direction from
                // `cooling_medium`'s module contract.
                .unwrap_or(true),
            Err(_) => false,
        }
    }

    fn count_refusal(&self, refusal: TuneStepRefusal) -> TuneStepRefusal {
        self.refused_steps.fetch_add(1, Ordering::Relaxed);
        *self
            .last_refusal
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(refusal.clone());
        refusal
    }

    /// Record the description of a step presented to the guard (executed or
    /// refused) — the convergence telemetry's `last_step` evidence.
    pub fn record_step(&self, description: String) {
        *self.last_step.lock().unwrap_or_else(|e| e.into_inner()) = Some(description);
    }

    /// Validate a frequency step BEFORE execution.
    ///
    /// - NotTunable variant ⇒ refuse every step with the reason.
    /// - `freq_mhz` above the envelope ceiling ⇒ refuse (any direction — a
    ///   decrease can never trip this).
    /// - `FreqStepKind::NominalRestore` above the ceiling ⇒ ALLOW with a
    ///   counted warning (returning to stock is not tuning; stranding a
    ///   chain at a probed frequency would be worse).
    /// - Everything else (in-band moves, step-downs) ⇒ allow.
    pub fn check_freq_step(
        &self,
        chain_id: u8,
        freq_mhz: u16,
        kind: FreqStepKind,
    ) -> Result<(), TuneStepRefusal> {
        let Ok(env) = self.envelope.as_ref() else {
            let reason = self.envelope.as_ref().unwrap_err().clone();
            return Err(self.count_refusal(TuneStepRefusal::NotTunable(reason)));
        };
        if freq_mhz > env.freq_max_mhz {
            if kind == FreqStepKind::NominalRestore {
                self.nominal_above_envelope_restores
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            return Err(self.count_refusal(TuneStepRefusal::FreqAboveEnvelope {
                chain_id,
                freq_mhz,
                envelope_max_mhz: env.freq_max_mhz,
                source: env.source,
            }));
        }
        Ok(())
    }

    /// Validate a voltage step BEFORE execution (both directions: an
    /// under-volt risks chip drop-out, an over-volt exceeds the cap).
    ///
    /// The requested millivolts are classified onto the core/chain axis
    /// first; the band declared for THAT axis applies. No band on that axis
    /// ⇒ refuse (`VoltAxisUndeclared`).
    pub fn check_voltage_step(
        &self,
        chain_id: u8,
        volt_mv: u16,
    ) -> Result<(), TuneStepRefusal> {
        let Ok(env) = self.envelope.as_ref() else {
            let reason = self.envelope.as_ref().unwrap_err().clone();
            return Err(self.count_refusal(TuneStepRefusal::NotTunable(reason)));
        };
        let axis = classify_voltage_axis(volt_mv);
        let band = match axis {
            VoltageAxis::CoreRail => env.core_volt_mv,
            VoltageAxis::ChainRail => env.chain_volt_mv,
        };
        let Some((lo, hi)) = band else {
            return Err(self.count_refusal(TuneStepRefusal::VoltAxisUndeclared {
                chain_id,
                volt_mv,
                source: env.source,
            }));
        };
        if volt_mv < lo || volt_mv > hi {
            return Err(self.count_refusal(TuneStepRefusal::VoltOutsideEnvelope {
                chain_id,
                volt_mv,
                axis: VoltageAxisRefusal::from_axis(axis),
                band: (lo, hi),
                source: env.source,
            }));
        }
        Ok(())
    }

    /// Telemetry snapshot: refusal counters + envelope version.
    pub fn telemetry(&self) -> GuardTelemetry {
        GuardTelemetry {
            envelope_version: TUNE_ENVELOPE_VERSION.to_string(),
            tunable: self.tunable(),
            envelope_source: match self.envelope.as_ref() {
                Ok(env) => Some(env.source.to_string()),
                Err(_) => None,
            },
            refused_steps: self.refused_steps.load(Ordering::Relaxed),
            nominal_above_envelope_restores: self
                .nominal_above_envelope_restores
                .load(Ordering::Relaxed),
            last_refusal: self
                .last_refusal
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|r| r.to_string()),
            last_step: self
                .last_step
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        }
    }
}

/// Serializable telemetry snapshot for the guard (surfaced through the
/// convergence telemetry — see `telemetry.rs`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct GuardTelemetry {
    pub envelope_version: String,
    pub tunable: bool,
    pub envelope_source: Option<String>,
    pub refused_steps: u32,
    pub nominal_above_envelope_restores: u32,
    pub last_refusal: Option<String>,
    #[serde(default)]
    pub last_step: Option<String>,
}

// ===================================================================
// C3a phase 2 — first-boot safe-stock start gate
// ===================================================================

/// Snapshot of the first-boot start-gate conditions the daemon publishes on
/// a watch channel. The tuner parks in `Idle` with a visible reason until
/// every required condition holds; characterization never starts while any
/// park reason stands.
///
/// Mapping (daemon-side):
/// - `health_snapshot_ok` — mining health evidence: non-zero hashrate +
///   fresh per-chain stats (the pre-C3a readiness loop's condition).
/// - `fans_ok` — fan evidence: EVERY observable per-fan tach channel shows
///   motion (all-observable-channels-motion, mirroring the daemon P0
///   preflight rule `cooling_readiness_from_tach`; the legacy primary-tach
///   reading is a fallback only when no per-fan channels are observable),
///   OR the variant's declared medium has no fan actuator (external loop:
///   vacuously true). Fail-closed default: an air-shaped variant with no
///   fan telemetry parks. (C3a fix lane: the previous doc also carried a
///   third "fan awareness disabled by configuration + quiet-home PWM cap"
///   arm that NO production publisher implemented — struck as doc-vs-code
///   drift on a safety contract; do not re-add without implementing it as
///   an explicit, declared, fail-closed path.)
/// - `temp_in_envelope` — fresh board/die temperature sample present and
///   within plausibility bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct FirstBootGateSnapshot {
    pub health_snapshot_ok: bool,
    pub fans_ok: bool,
    pub temp_in_envelope: bool,
}

impl FirstBootGateSnapshot {
    /// All-pass snapshot (used by tests and by paths whose conditions were
    /// proven before the gate was introduced — see the daemon wiring).
    pub const fn all_pass() -> Self {
        Self {
            health_snapshot_ok: true,
            fans_ok: true,
            temp_in_envelope: true,
        }
    }

    /// True iff every required condition holds.
    pub fn passes(&self) -> bool {
        self.park_reason().is_none()
    }

    /// The first failing condition, in evaluation order (health → fans →
    /// temp → experimental ack). `None` = gate open.
    pub fn park_reason(&self) -> Option<&'static str> {
        if !self.health_snapshot_ok {
            Some("waiting for health snapshot OK (stable hashrate + fresh per-chain stats)")
        } else if !self.fans_ok {
            Some("waiting for fans OK (no fan motion evidence yet)")
        } else if !self.temp_in_envelope {
            Some("waiting for temperature in envelope (no fresh in-bounds board/die temp)")
        } else {
            None
        }
    }
}

/// Default ladder when no BoardDesc row was supplied (every registered row
/// today carries the canonical forced-air ladder; undeclared medium keeps
/// forced-air rules per `cooling_medium`'s contract).
pub fn default_variant_ladder() -> &'static [CutRung] {
    CANONICAL_FORCED_AIR_LADDER
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_common::cooling_medium::{
        canonical_cut_ladder, CoolingClass, CANONICAL_EXTERNAL_LOOP_LADDER,
    };
    use dcentrald_silicon_profiles::bm1362::Bm1362HashboardSku;

    fn s9_envelope() -> Result<VariantTuneEnvelope, NotTunableReason> {
        resolve_variant_envelope(
            0x1387,
            "pic16",
            None,
            false,
            None,
            default_variant_ladder(),
        )
    }

    fn bm1362_envelope(
        sku: Option<Bm1362HashboardSku>,
        am2_gate: bool,
    ) -> Result<VariantTuneEnvelope, NotTunableReason> {
        resolve_variant_envelope(
            0x1362,
            "dspic",
            sku,
            am2_gate,
            None,
            default_variant_ladder(),
        )
    }

    // ---- resolver honesty ----------------------------------------------

    #[test]
    fn s9_variant_resolves_documented_band() {
        let env = s9_envelope().expect("BM1387+pic16 must resolve");
        assert_eq!(env.freq_min_mhz, 200);
        assert_eq!(env.freq_max_mhz, 750);
        // c3a-2 (DCENT_EE merge condition): ceiling 9400 = DAC 6 (safe
        // operating ceiling), NOT the old 9440 = DAC 0 absolute-max overvolt.
        assert_eq!(env.chain_volt_mv, Some((8_400, 9_400)));
        assert_eq!(env.core_volt_mv, None);
        assert_eq!(env.source, "bm1387-pic16:documented-s9-band");
    }

    /// MUTATION PIN: if the resolver stops refusing unknown variants (e.g.
    /// someone adds a permissive fallback band for BM1366/BM1368), this
    /// fails. "Never tune blind" is the load-bearing property.
    #[test]
    fn unknown_variants_refuse_to_tune_not_tunable() {
        for chip in [0x1366u16, 0x1368, 0x1370, 0x1397, 0x1398, 0xABCD] {
            let err = resolve_variant_envelope(
                chip,
                "nopic",
                None,
                false,
                None,
                default_variant_ladder(),
            )
            .expect_err("variants without published envelope datums must refuse");
            assert!(
                matches!(err, NotTunableReason::VariantEnvelopeUnknown { .. }),
                "chip 0x{chip:04X}: {err:?}"
            );
            // The surfaced reason names the variant.
            assert!(err.to_string().contains(&format!("{chip:04X}")));
        }
        // Unknown controller kind is equally refused for a KNOWN chip.
        assert!(matches!(
            resolve_variant_envelope(0x1387, "pic", None, false, None, default_variant_ladder())
                .unwrap_err(),
            NotTunableReason::VariantEnvelopeUnknown { .. }
        ));
    }

    /// MUTATION PIN: BM1362 without a classified SKU must refuse
    /// (Bm1362SkuUnclassified) — the pre-C3a "open gate" behavior must not
    /// come back under a default-ON autotuner.
    #[test]
    fn bm1362_without_sku_refuses() {
        let err = bm1362_envelope(None, false).unwrap_err();
        assert_eq!(err, NotTunableReason::Bm1362SkuUnclassified);
        assert!(err.to_string().contains("SKU"));
    }

    #[test]
    fn bm1362_with_sku_derives_pvt_band() {
        let env =
            bm1362_envelope(Some(Bm1362HashboardSku::Bhb42601), false).expect("PVT envelope");
        // BHB42601 PVT: 465-545 MHz @ 1320-1380 mV core.
        assert_eq!((env.freq_min_mhz, env.freq_max_mhz), (465, 545));
        assert_eq!(env.core_volt_mv, Some((1_320, 1_380)));
        // Chain-rail axis is NOT declared with the am2 fence off (KEEP-OFF
        // live-safety fence honored).
        assert_eq!(env.chain_volt_mv, None);
    }

    #[test]
    fn bm1362_chain_rail_window_only_under_am2_fence() {
        let env =
            bm1362_envelope(Some(Bm1362HashboardSku::Bhb42601), true).expect("PVT envelope");
        assert_eq!(
            env.chain_volt_mv,
            Some((
                crate::config::AM2_DSPIC_VOLTAGE_AUTOTUNE_MIN_MV,
                crate::config::AM2_DSPIC_VOLTAGE_AUTOTUNE_MAX_MV
            ))
        );
    }

    // ---- cut-ladder / fanless semantics ---------------------------------

    /// MUTATION PIN: a fan rung on a fanless medium must make the variant
    /// NotTunable at resolution time — `RaiseFansToCap` is unreachable on
    /// fanless through the tuner's inputs.
    #[test]
    fn fanless_medium_with_fan_rung_is_not_tunable() {
        for medium in [CoolingMedium::Hydro, CoolingMedium::Immersion] {
            let err = resolve_variant_envelope(
                0x1387,
                "pic16",
                None,
                false,
                Some(medium),
                CANONICAL_FORCED_AIR_LADDER,
            )
            .unwrap_err();
            assert_eq!(
                err,
                NotTunableReason::FanRungOnFanlessMedium { position: 1 },
                "medium {medium:?}"
            );
        }
        // And the external-loop ladder is fine on a fanless medium.
        assert!(resolve_variant_envelope(
            0x1387,
            "pic16",
            None,
            false,
            Some(CoolingMedium::Hydro),
            canonical_cut_ladder(CoolingClass::ExternalLoop),
        )
        .is_ok());
    }

    #[test]
    fn structurally_invalid_ladder_is_not_tunable() {
        // Empty ladder fails validation → CutLadderInvalid.
        let err = resolve_variant_envelope(0x1387, "pic16", None, false, None, &[])
            .unwrap_err();
        assert!(matches!(err, NotTunableReason::CutLadderInvalid { .. }));
    }

    #[test]
    fn fan_raise_reachable_is_false_on_fanless() {
        let guard = TuneGuard::new(resolve_variant_envelope(
            0x1387,
            "pic16",
            None,
            false,
            Some(CoolingMedium::Immersion),
            CANONICAL_EXTERNAL_LOOP_LADDER,
        ));
        assert!(!guard.fan_raise_reachable());
        let air = TuneGuard::new(s9_envelope());
        assert!(air.fan_raise_reachable());
        // NotTunable variant: nothing is reachable.
        let refused = TuneGuard::new(Err(NotTunableReason::Bm1362SkuUnclassified));
        assert!(!refused.fan_raise_reachable());
    }

    // ---- step refusals ---------------------------------------------------

    /// MUTATION PIN: an above-envelope frequency raise must refuse. Break
    /// the ceiling check and this fails.
    #[test]
    fn freq_step_above_envelope_refuses() {
        let guard = TuneGuard::new(s9_envelope());
        assert!(guard.check_freq_step(0, 750, FreqStepKind::TuneStep).is_ok());
        let refusal = guard
            .check_freq_step(0, 751, FreqStepKind::TuneStep)
            .expect_err("751 MHz must refuse vs the 750 ceiling");
        match refusal {
            TuneStepRefusal::FreqAboveEnvelope {
                freq_mhz,
                envelope_max_mhz,
                ..
            } => {
                assert_eq!(freq_mhz, 751);
                assert_eq!(envelope_max_mhz, 750);
            }
            other => panic!("expected FreqAboveEnvelope, got {other:?}"),
        }
        // Counted once.
        assert_eq!(guard.telemetry().refused_steps, 1);
        assert!(guard.telemetry().last_refusal.unwrap().contains("751"));
    }

    #[test]
    fn freq_decreases_and_in_band_steps_pass() {
        let guard = TuneGuard::new(s9_envelope());
        for freq in [200u16, 400, 650, 749, 750] {
            assert!(guard.check_freq_step(3, freq, FreqStepKind::TuneStep).is_ok());
        }
        // Step-downs below the envelope floor are allowed (never block a
        // heat/power-reducing move) — including to 0.
        assert!(guard.check_freq_step(3, 0, FreqStepKind::TuneStep).is_ok());
    }

    #[test]
    fn nominal_restore_above_ceiling_is_allowed_and_counted() {
        let guard = TuneGuard::new(s9_envelope());
        assert!(guard
            .check_freq_step(0, 900, FreqStepKind::NominalRestore)
            .is_ok());
        assert_eq!(guard.telemetry().nominal_above_envelope_restores, 1);
        // But a TuneStep at the same frequency still refuses.
        assert!(guard
            .check_freq_step(0, 900, FreqStepKind::TuneStep)
            .is_err());
    }

    /// MUTATION PIN: out-of-band voltage must refuse on BOTH directions and
    /// on BOTH axes; wrong-axis requests must refuse via
    /// VoltAxisUndeclared.
    #[test]
    fn voltage_steps_validate_band_and_axis() {
        let guard = TuneGuard::new(s9_envelope());
        // S9 chain-rail band [8400, 9400] — 9400 = PIC DAC 6, the codebase's
        // safe operating ceiling (c3a-2, DCENT_EE merge condition: the old
        // 9440 ceiling was DAC 0 absolute-max overvolt; no published BM1387
        // preset exceeds 9.4 V, so nothing legitimate is refused at 9400).
        assert!(guard.check_voltage_step(0, 9_100).is_ok());
        assert!(guard.check_voltage_step(0, 8_400).is_ok());
        assert!(guard.check_voltage_step(0, 9_400).is_ok());
        // Over-volt refuses — including the old 9440 (DAC 0 absolute-max).
        assert!(matches!(
            guard.check_voltage_step(0, 9_401),
            Err(TuneStepRefusal::VoltOutsideEnvelope { .. })
        ));
        assert!(matches!(
            guard.check_voltage_step(0, 9_440),
            Err(TuneStepRefusal::VoltOutsideEnvelope { .. })
        ));
        // Under-volt refuses.
        assert!(matches!(
            guard.check_voltage_step(0, 8_399),
            Err(TuneStepRefusal::VoltOutsideEnvelope { .. })
        ));
        // Core-rail request (1340 mV) on an S9 (no core band declared)
        // refuses as undeclared axis — the unit-confusion trap must NOT
        // silently pass.
        assert!(matches!(
            guard.check_voltage_step(0, 1_340),
            Err(TuneStepRefusal::VoltAxisUndeclared { .. })
        ));
    }

    #[test]
    fn bm1362_voltage_axis_split() {
        let guard = TuneGuard::new(bm1362_envelope(Some(Bm1362HashboardSku::Bhb42601), true));
        // Core axis declared [1320, 1380]: in-band passes, out refuses.
        assert!(guard.check_voltage_step(1, 1_340).is_ok());
        assert!(matches!(
            guard.check_voltage_step(1, 1_500),
            Err(TuneStepRefusal::VoltOutsideEnvelope { axis, .. }) if axis == VoltageAxisRefusal::CoreRail
        ));
        // Chain axis declared [13700, 14500] under the fence.
        assert!(guard.check_voltage_step(1, 13_700).is_ok());
        assert!(matches!(
            guard.check_voltage_step(1, 14_501),
            Err(TuneStepRefusal::VoltOutsideEnvelope { axis, .. }) if axis == VoltageAxisRefusal::ChainRail
        ));
        // Without the fence the chain axis is undeclared.
        let unfenced = TuneGuard::new(bm1362_envelope(Some(Bm1362HashboardSku::Bhb42601), false));
        assert!(matches!(
            unfenced.check_voltage_step(1, 13_700),
            Err(TuneStepRefusal::VoltAxisUndeclared { .. })
        ));
    }

    /// MUTATION PIN: a NotTunable guard refuses EVERY mutating step and
    /// carries the reason.
    #[test]
    fn not_tunable_guard_refuses_every_step() {
        let guard = TuneGuard::new(Err(NotTunableReason::VariantEnvelopeUnknown {
            chip_id: 0x1366,
            voltage_control: "nopic".to_string(),
        }));
        for freq in [200u16, 400, 600, 750] {
            let refusal = guard
                .check_freq_step(0, freq, FreqStepKind::TuneStep)
                .expect_err("NotTunable guard must refuse every step");
            assert!(matches!(refusal, TuneStepRefusal::NotTunable(_)));
        }
        assert!(matches!(
            guard.check_voltage_step(0, 9_000),
            Err(TuneStepRefusal::NotTunable(_))
        ));
        assert!(!guard.telemetry().tunable);
        assert_eq!(guard.telemetry().refused_steps, 5);
    }

    #[test]
    fn telemetry_names_envelope_version_and_source() {
        let guard = TuneGuard::new(s9_envelope());
        let t = guard.telemetry();
        assert_eq!(t.envelope_version, TUNE_ENVELOPE_VERSION);
        assert_eq!(t.envelope_source.as_deref(), Some("bm1387-pic16:documented-s9-band"));
        assert!(t.tunable);
        assert_eq!(t.refused_steps, 0);
    }

    // ---- first-boot start gate -------------------------------------------

    /// MUTATION PIN: each park condition individually parks the gate (break
    /// any single condition's check and this fails).
    #[test]
    fn first_boot_gate_parks_per_condition() {
        // All-pass gate opens.
        assert!(FirstBootGateSnapshot::all_pass().passes());
        assert_eq!(FirstBootGateSnapshot::all_pass().park_reason(), None);

        // Health not OK.
        let mut g = FirstBootGateSnapshot::all_pass();
        g.health_snapshot_ok = false;
        assert!(!g.passes());
        assert!(g.park_reason().unwrap().contains("health snapshot"));

        // Fans not OK.
        let mut g = FirstBootGateSnapshot::all_pass();
        g.fans_ok = false;
        assert!(!g.passes());
        assert!(g.park_reason().unwrap().contains("fans OK"));

        // Temp not in envelope.
        let mut g = FirstBootGateSnapshot::all_pass();
        g.temp_in_envelope = false;
        assert!(!g.passes());
        assert!(g.park_reason().unwrap().contains("temperature in envelope"));

        // Default (all health facts false) parks on health first —
        // evaluation order is deterministic.
        assert!(FirstBootGateSnapshot::default()
            .park_reason()
            .unwrap()
            .contains("health snapshot"));
    }
}
