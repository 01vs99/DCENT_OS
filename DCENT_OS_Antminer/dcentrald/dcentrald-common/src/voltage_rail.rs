//! VoltageRail — power-facet interface sketch (ADR-0010).
//!
//! # Why this exists
//!
//! `ChipDriver::set_voltage(&mut PicController, …)` is the wrong long-term
//! spine: BM1362 is a no-op, BM1370 is TODO TAS5782M, PIC1704 is a third
//! protocol family, and production AM2 uses dsPIC with fw-identity-dependent
//! framing. Voltage must be a **composed facet**, not a chip-driver method.
//!
//! # Status
//!
//! Pure error/type surface + ownership admission + **host-testable adapter
//! policy** (P1-2). Live I/O controllers remain in `dcentrald-asic` (`pic`,
//! `dspic`, `pic1704`) and PSU modules in `dcentrald-hal`. Adapters must:
//! 1. resolve [`VoltageRailAdapterKind`] from BoardDesc,
//! 2. call [`admit_voltage_rail_op`] (or use [`BackendVoltageRail`]) before I/O,
//! 3. map controller errors to [`VoltageRailError`] (never bare `Ok(())` on miss).
//!
//! [`voltage_ownership_for_asic`] is the host-safe SSOT for "may ChipDriver
//! set_voltage be called for this silicon?" — BM1362/BM1368 must refuse via
//! [`chip_driver_set_voltage_admission`], never return `Ok(())`.
//!
//! Maturity:
//! - Adapter policy / PIC16 encode / fail-closed ExternalDac: **PRODUCTION pure**
//! - Live `dcentrald-asic` thin wrappers: **EXPERIMENTAL** (host-mockable via
//!   [`BackendVoltageRail`]; real I2C path still platform-gated)
//! - TAS5782M wire I/O: **NOT IMPLEMENTED** (honest [`UnsupportedExternalDacRail`])
//!
//! Do not add a fourth parallel voltage protocol without implementing (or
//! planning) this trait.

/// Exact T21 APW11A identification profile from the stock Zynq topology.
/// These are identity keys, not DAC coefficients, PMBus commands or AML wiring.
pub const T21_APW11A_VERSION_KEYS: &[u8] = &[66, 67, 106, 113, 114, 115, 117, 118, 119, 120, 193];

/// PSU identity supplied by a bench observation. Discovery never probes a bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchPsuIdentity<'a> {
    pub family: &'a str,
    pub address_7bit: u8,
    pub version: u8,
}

/// Validate the T21 stock-declared APW11A tuple. In particular, APW11 and
/// APW11A1216-1a are different profiles; matching a version alone is insufficient.
pub fn validate_t21_apw11a(identity: BenchPsuIdentity<'_>) -> Result<(), VoltageRailError> {
    let declaration = crate::t21_bm1368_profile::T21_PSU_ZYNQ_VARIANT_DECLARATION;
    if identity.family != declaration.family
        || identity.address_7bit != declaration.i2c_addr_7bit
        || !T21_APW11A_VERSION_KEYS.contains(&identity.version)
    {
        return Err(VoltageRailError::Refused {
            reason: VoltageRefuseReason::BindingMismatch,
            detail: "T21 PSU identity does not match stock APW11A at 0x10 and its version list"
                .into(),
        });
    }
    Ok(())
}

/// A discover-only row. Geometry reuses the exact existing board profiles.
/// This row supplies neither a hardware owner nor a voltage-control protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S21BenchProfile {
    board_target: &'static str,
    asic: crate::board_desc::AsicProtocolIdentity,
    chips_per_chain: u16,
    board_names: &'static [&'static str],
}

impl S21BenchProfile {
    pub fn for_board_target(target: &str) -> Result<Self, VoltageRailError> {
        use crate::bm1370_board_profiles::Bm1370BoardProfile;
        use crate::board_desc::AsicProtocolIdentity;
        use crate::t21_bm1368_profile::T21;
        let profile = match target {
            "am3-t21" => Self {
                board_target: T21.board_target,
                asic: AsicProtocolIdentity::Bm1368,
                chips_per_chain: T21.chips_per_chain,
                board_names: T21.board_names,
            },
            "am3-s21" => Self {
                board_target: "am3-s21",
                asic: AsicProtocolIdentity::Bm1368,
                chips_per_chain: 108,
                board_names: &["BHB68603", "BHB68606"],
            },
            other => {
                let p = Bm1370BoardProfile::for_board_target(other).ok_or_else(|| {
                    VoltageRailError::InvalidParameter {
                        detail: format!("unknown S21 bench board target {other:?}"),
                    }
                })?;
                Self {
                    board_target: p.board_target,
                    asic: AsicProtocolIdentity::Bm1370,
                    chips_per_chain: p.chips_per_chain,
                    board_names: p.board_names,
                }
            }
        };
        Ok(profile)
    }

    pub const fn board_target(self) -> &'static str {
        self.board_target
    }
    pub const fn asic(self) -> crate::board_desc::AsicProtocolIdentity {
        self.asic
    }
    pub const fn chips_per_chain(self) -> u16 {
        self.chips_per_chain
    }

    /// A successful population check is useful for simulation and bench review,
    /// but never substitutes for format-specific EEPROM decoding on hardware.
    pub fn validate_population(self, boards: &[(&str, u16)]) -> Result<(), VoltageRailError> {
        if boards.len() != 3
            || boards.iter().any(|(name, count)| {
                !self.board_names.contains(name) || *count == 0 || *count != self.chips_per_chain
            })
        {
            return Err(VoltageRailError::Refused {
                reason: VoltageRefuseReason::BindingMismatch,
                detail: format!(
                    "{} requires three exact board identities with {} chips each",
                    self.board_target, self.chips_per_chain
                ),
            });
        }
        Ok(())
    }

    /// Render the existing per-target polarity policy; never duplicate levels
    /// or derive them from a sibling. Missing entries also stay undriven.
    pub fn polarity_card(self) -> String {
        use crate::amlogic_gpio437::{resolve_boot_policy, BootGpio437Policy};
        let policy = match resolve_boot_policy(self.board_target) {
            Ok(BootGpio437Policy::QualifiedOff(recipe)) => format!(
                "GPIO437 raw ON={} OFF={} (software-qualified; electrical check pending)",
                recipe.on_raw(),
                recipe.off_raw()
            ),
            Ok(BootGpio437Policy::Undriven) | Err(_) => {
                "GPIO437 undriven; no qualified ON/OFF levels".into()
            }
        };
        format!(
            "{}: {policy}; discover-only performs no GPIO, PSU or fan writes",
            self.board_target
        )
    }
}

/// Result of passive PSU discovery, deliberately not a VoltageRail or an
/// electrical admission token. All observations remain caller-supplied data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S21PsuDiscovery {
    pub profile: S21BenchProfile,
    pub observed_psu: Option<(String, u8, u8)>,
    pub polarity_card: String,
    pub voltage_ceiling: &'static str,
}

pub const S21_VOLTAGE_CEILING: &str = "External DAC set_mv/enable unavailable; no APW11A voltage law or AML binding; discovery does not energize or claim SafeOff";

/// Offline bench mode: validate supplied identities and population, and return
/// a polarity card. No bus scan, fallback probe, GPIO export or rail operation.
/// T21 APW11A recognition preserves the stock Zynq declaration's scope; it
/// does not translate GPIO907 to AML GPIO437 or select a live AML PSU adapter.
pub fn discover_s21_psu(
    target: &str,
    boards: &[(&str, u16)],
    psu: Option<BenchPsuIdentity<'_>>,
) -> Result<S21PsuDiscovery, VoltageRailError> {
    let profile = S21BenchProfile::for_board_target(target)?;
    profile.validate_population(boards)?;
    if let Some(identity) = psu {
        if identity.family.is_empty() || identity.address_7bit > 0x7f {
            return Err(VoltageRailError::InvalidParameter {
                detail: "invalid observed PSU identity".into(),
            });
        }
        if target == "am3-t21" {
            validate_t21_apw11a(identity)?;
        }
    }
    Ok(S21PsuDiscovery {
        profile,
        observed_psu: psu.map(|p| (p.family.to_owned(), p.address_7bit, p.version)),
        polarity_card: profile.polarity_card(),
        voltage_ceiling: S21_VOLTAGE_CEILING,
    })
}

/// Class of refuse conditions that must fail closed on production paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoltageRefuseReason {
    /// Proven post-RESET corruption (e.g. dsPIC fw=0x86).
    DegradedFirmware,
    /// Controller not in app mode / bootloader only.
    WrongMode,
    /// Platform binding does not match probe (e.g. Pic1704 seal fail).
    BindingMismatch,
    /// Lab override required but not set.
    LabOverrideRequired,
}

/// Host-safe voltage operation error (no HAL types).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoltageRailError {
    /// Communication / I/O failure (filled by adapters with detail).
    Io { detail: String },
    /// Explicit refuse (must not retry as success).
    Refused {
        reason: VoltageRefuseReason,
        detail: String,
    },
    /// Feature not implemented for this binding (must not return Ok(())).
    Unsupported { detail: String },
    /// Invalid set-point.
    InvalidParameter { detail: String },
}

impl std::fmt::Display for VoltageRailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { detail } => write!(f, "voltage I/O: {detail}"),
            Self::Refused { reason, detail } => {
                write!(f, "voltage refused ({reason:?}): {detail}")
            }
            Self::Unsupported { detail } => write!(f, "voltage unsupported: {detail}"),
            Self::InvalidParameter { detail } => write!(f, "voltage parameter: {detail}"),
        }
    }
}

impl std::error::Error for VoltageRailError {}

/// Operations every voltage backend must eventually expose.
///
/// Implemented by adapters over PIC16 / dsPIC / PIC1704 / NoPic+PSU — not by
/// `ChipDriver`. Heartbeat is part of the rail (fail-closed on miss → cut).
pub trait VoltageRail {
    /// Commanded voltage in millivolts (protocol-specific encoding inside impl).
    fn set_mv(&mut self, mv: u16) -> Result<(), VoltageRailError>;

    /// Enable hashboard rail / voltage output.
    fn enable(&mut self) -> Result<(), VoltageRailError>;

    /// Disable rail (emergency and teardown must prefer this path).
    fn disable(&mut self) -> Result<(), VoltageRailError>;

    /// Heartbeat / kick so hardware watchdogs do not cut unexpectedly.
    fn heartbeat(&mut self) -> Result<(), VoltageRailError>;

    /// Optional measured rail mV (None if measure unsupported).
    fn measure_mv(&mut self) -> Result<Option<u16>, VoltageRailError> {
        Ok(None)
    }

    /// Firmware / identity byte when known (e.g. dsPIC GET_VERSION).
    fn firmware_identity(&self) -> Option<u8> {
        None
    }
}

/// Map a “voltage path not implemented for this chip” situation.
///
/// **Must not** be converted to `Ok(())` at call sites (historical BM1362
/// `set_voltage` no-op returned Ok — that pattern is forbidden).
pub fn unsupported_voltage_path(detail: impl Into<String>) -> VoltageRailError {
    VoltageRailError::Unsupported {
        detail: detail.into(),
    }
}

/// Map degraded-firmware refuse (e.g. dsPIC fw=0x86).
pub fn refuse_degraded_firmware(detail: impl Into<String>) -> VoltageRailError {
    VoltageRailError::Refused {
        reason: VoltageRefuseReason::DegradedFirmware,
        detail: detail.into(),
    }
}

/// Map wrong app/bootloader mode refuse.
pub fn refuse_wrong_mode(detail: impl Into<String>) -> VoltageRailError {
    VoltageRailError::Refused {
        reason: VoltageRefuseReason::WrongMode,
        detail: detail.into(),
    }
}

/// True when the error is an explicit refusal; it must not be retried as success.
pub fn is_hard_refuse(err: &VoltageRailError) -> bool {
    matches!(err, VoltageRailError::Refused { .. })
}

/// Who owns voltage mutation for a given ASIC protocol identity.
///
/// Decade backlog P1-2: voltage is a composed facet, not a `ChipDriver` method.
/// This pure map is the admission gate engines and ChipDriver impls consult
/// before attempting a PIC-parameterized `set_voltage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoltageOwnership {
    /// S9-class: PIC16 on-chip path via ChipDriver + PicController is legitimate.
    ChipDriverPic,
    /// AM2 S19j Pro class: dsPIC33EP hashboard rail — never ChipDriver.
    HashboardDspic,
    /// BM1396: an exact framed hashboard endpoint is known, but the populated
    /// controller silicon and a live-safe adapter are not. ASIC identity alone
    /// must never promote this to the generic dsPIC mutation path.
    HashboardFramedEndpointEvidenceOnly,
    /// S21 NoPic class: external DAC / PMIC (e.g. TAS5782M) — ChipDriver unsupported.
    ExternalDacNoPic,
    /// Identity not enough to choose a rail; must not mutate via ChipDriver.
    RuntimeDiscovered,
}

impl VoltageOwnership {
    /// Whether `ChipDriver::set_voltage(&mut PicController, …)` is a valid spine.
    pub const fn chip_driver_set_voltage_allowed(self) -> bool {
        matches!(self, Self::ChipDriverPic)
    }
}

/// Map ASIC protocol identity → voltage ownership (pure, host-safe).
///
/// Evidence:
/// - BM1362 production rail is `DspicController` (AM2); ChipDriver returns Err
/// - BM1368/BM1370 S21 class is TAS5782M / NoPic, not PIC set_voltage
/// - BM1387 S9 uses PicController via ChipDriver
/// - BM1397/BM1398 industrial boards use hashboard dsPIC-class rails
pub fn voltage_ownership_for_asic(
    identity: crate::board_desc::AsicProtocolIdentity,
) -> VoltageOwnership {
    use crate::board_desc::AsicProtocolIdentity;
    match identity {
        AsicProtocolIdentity::Bm1387 => VoltageOwnership::ChipDriverPic,
        AsicProtocolIdentity::Bm1396 => VoltageOwnership::HashboardFramedEndpointEvidenceOnly,
        AsicProtocolIdentity::Bm1362
        | AsicProtocolIdentity::Bm1391
        | AsicProtocolIdentity::Bm1397
        | AsicProtocolIdentity::Bm1398 => VoltageOwnership::HashboardDspic,
        // BM1366 spans PIC industrial boards and Amlogic/NoPic S19k-class
        // boards (Has_Pic:false, BHB5690x). Identity alone must not admit the
        // ChipDriver PIC path — BoardDesc must scope NoPic vs PIC before any
        // voltage owner is selected (RE-4A / S19k BETA fail-closed).
        AsicProtocolIdentity::Bm1366 | AsicProtocolIdentity::Bm1393 => {
            // S9 SE dsPIC IIC map is pinned in `s9se_gauntlet` / `bm1393.rs`.
            // Identity alone must not select ChipDriverPic or AM2 framed dsPIC.
            VoltageOwnership::RuntimeDiscovered
        }
        AsicProtocolIdentity::Bm1368 | AsicProtocolIdentity::Bm1370 => {
            VoltageOwnership::ExternalDacNoPic
        }
        AsicProtocolIdentity::RuntimeDiscovered => VoltageOwnership::RuntimeDiscovered,
    }
}

/// Fail-closed admission for `ChipDriver::set_voltage`.
///
/// Returns `Ok(())` only when ownership is [`VoltageOwnership::ChipDriverPic`].
/// Otherwise returns [`unsupported_voltage_path`] (must not be mapped to Ok).
pub fn chip_driver_set_voltage_admission(
    identity: crate::board_desc::AsicProtocolIdentity,
) -> Result<(), VoltageRailError> {
    let ownership = voltage_ownership_for_asic(identity);
    if ownership.chip_driver_set_voltage_allowed() {
        return Ok(());
    }
    Err(unsupported_voltage_path(format!(
        "ChipDriver::set_voltage refused for {identity:?}: ownership={ownership:?} \
         (route via VoltageRail / DspicController / external DAC — ADR-0010 P1-2)"
    )))
}

/// Which live VoltageRail **adapter family** BoardDesc voltage class selects.
///
/// Distinct from [`VoltageOwnership`] (ASIC-identity view of whether
/// `ChipDriver::set_voltage` is legitimate). Adapter kind is the composed
/// facet engines should construct once BoardDesc is known — pure map only;
/// I/O adapters remain in `dcentrald-asic` / `dcentrald-hal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoltageRailAdapterKind {
    /// S9-class PIC16 via ChipDriver + PicController path.
    Pic16ChipDriver,
    /// AM2 hashboard dsPIC33EP (framing depends on fw identity at runtime).
    DsPic33Ep,
    /// Exact BM1396 framed I2C 0x11 ABI. Pure codec evidence exists, but no
    /// live rail adapter is admitted yet.
    Bm1396I2c11EvidenceOnly,
    /// Only ClassicAmlPowerOwner holds this PIC/APW12 composition. Legacy
    /// generic adapters must refuse every op, including heartbeat and cut.
    ClassicAmlRetainedOwner,
    /// Only the native BM1391 PIC/APW8 owner may operate this rail.
    Bm1391RetainedOwner,
    /// PIC1704 family (protocol-sealed boards).
    Pic1704,
    /// NoPic external DAC / PMIC (e.g. TAS5782M on S21-class).
    ExternalDacNoPic,
    /// Must refine via runtime topology before mutating voltage.
    RuntimeDiscovered,
}

impl VoltageRailAdapterKind {
    /// Whether a live adapter may mutate voltage without further discovery.
    pub const fn admits_mutation(self) -> bool {
        !matches!(
            self,
            Self::Bm1396I2c11EvidenceOnly
                | Self::ClassicAmlRetainedOwner
                | Self::Bm1391RetainedOwner
                | Self::RuntimeDiscovered
        )
    }

    /// Map adapter kind → ChipDriver set_voltage ownership class.
    pub const fn as_voltage_ownership(self) -> VoltageOwnership {
        match self {
            Self::Pic16ChipDriver => VoltageOwnership::ChipDriverPic,
            Self::DsPic33Ep | Self::Pic1704 => VoltageOwnership::HashboardDspic,
            Self::Bm1396I2c11EvidenceOnly => VoltageOwnership::HashboardFramedEndpointEvidenceOnly,
            Self::ClassicAmlRetainedOwner => VoltageOwnership::RuntimeDiscovered,
            Self::Bm1391RetainedOwner => VoltageOwnership::RuntimeDiscovered,
            Self::ExternalDacNoPic => VoltageOwnership::ExternalDacNoPic,
            Self::RuntimeDiscovered => VoltageOwnership::RuntimeDiscovered,
        }
    }
}

/// BoardDesc voltage controller class → VoltageRail adapter family (pure SSOT).
///
/// Prefer this over ASIC-identity alone when a BoardDesc is available (decade
/// P1-2: composed facet from board topology, not chip marketing name).
pub fn voltage_rail_adapter_for_controller(
    class: crate::board_desc::VoltageControllerClass,
) -> VoltageRailAdapterKind {
    use crate::board_desc::VoltageControllerClass;
    match class {
        VoltageControllerClass::Pic16F1704 => VoltageRailAdapterKind::Pic16ChipDriver,
        VoltageControllerClass::DsPic33Ep => VoltageRailAdapterKind::DsPic33Ep,
        VoltageControllerClass::Bm1396FramedI2c11 => {
            VoltageRailAdapterKind::Bm1396I2c11EvidenceOnly
        }
        VoltageControllerClass::ClassicAmlApplication89 => {
            VoltageRailAdapterKind::ClassicAmlRetainedOwner
        }
        VoltageControllerClass::Bm1391Application => VoltageRailAdapterKind::Bm1391RetainedOwner,
        VoltageControllerClass::Pic1704 => VoltageRailAdapterKind::Pic1704,
        VoltageControllerClass::NoPic => VoltageRailAdapterKind::ExternalDacNoPic,
        VoltageControllerClass::RuntimeDiscovered => VoltageRailAdapterKind::RuntimeDiscovered,
    }
}

/// Prefer BoardDesc controller class when known; fall back to ASIC identity.
///
/// Returns the adapter kind engines should construct. `RuntimeDiscovered`
/// remains fail-closed for mutation until refined.
pub fn resolve_voltage_rail_adapter(
    controller: crate::board_desc::VoltageControllerClass,
    asic: crate::board_desc::AsicProtocolIdentity,
) -> VoltageRailAdapterKind {
    let from_board = voltage_rail_adapter_for_controller(controller);
    if from_board != VoltageRailAdapterKind::RuntimeDiscovered {
        return from_board;
    }
    // Board could not select — map ASIC ownership into adapter kind.
    match voltage_ownership_for_asic(asic) {
        VoltageOwnership::ChipDriverPic => VoltageRailAdapterKind::Pic16ChipDriver,
        VoltageOwnership::HashboardDspic => VoltageRailAdapterKind::DsPic33Ep,
        VoltageOwnership::HashboardFramedEndpointEvidenceOnly => {
            VoltageRailAdapterKind::Bm1396I2c11EvidenceOnly
        }
        VoltageOwnership::ExternalDacNoPic => VoltageRailAdapterKind::ExternalDacNoPic,
        VoltageOwnership::RuntimeDiscovered => VoltageRailAdapterKind::RuntimeDiscovered,
    }
}

/// Fail-closed: may this resolved adapter attempt voltage mutation?
pub fn admit_voltage_rail_mutation(
    adapter: VoltageRailAdapterKind,
) -> Result<(), VoltageRailError> {
    if adapter.admits_mutation() {
        return Ok(());
    }
    Err(unsupported_voltage_path(format!(
        "VoltageRail mutation refused: adapter={adapter:?} \
         (refine BoardDesc / topology before set_mv/enable)"
    )))
}

// ---------------------------------------------------------------------------
// Per-op adapter admission (P1-2 I/O policy — host pure)
// ---------------------------------------------------------------------------

/// VoltageRail method being admitted (for per-op policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoltageRailOp {
    SetMv,
    Enable,
    Disable,
    Heartbeat,
    Measure,
}

impl VoltageRailOp {
    /// Ops that energize or reprogram the rail (must pass full mutation policy).
    pub const fn is_energizing(self) -> bool {
        matches!(self, Self::SetMv | Self::Enable)
    }

    /// Safe-off / keepalive ops — allowed even when energizing is refused,
    /// except RuntimeDiscovered (no protocol known).
    pub const fn is_safe_or_keepalive(self) -> bool {
        matches!(self, Self::Disable | Self::Heartbeat | Self::Measure)
    }
}

/// Proven dsPIC app-mode firmware bytes that may energize.
///
/// Mirrors `dcentrald-asic::dspic::dspic_voltage_command_allowed` for the
/// host-safe adapter layer (fw=0x86 is always refused).
pub const DSPIC_PROVEN_APP_FW: &[u8] = &[0x82, 0x89, 0x8A, 0xB9, 0xFE];

/// Degraded post-RESET corruption identity (load-bearing refuse by default).
pub const DSPIC_DEGRADED_FW: u8 = 0x86;

/// Pure dsPIC firmware admission for VoltageRail energizing ops.
///
/// - `None` / unknown: refuse (no proven wire protocol)
/// - `Some(0x86)`: always refused, including legacy override requests
/// - proven app bytes: allow
/// - other observed bytes: refuse
pub fn admit_dspic_firmware_for_energize(
    firmware: Option<u8>,
    _trust_degraded: bool,
) -> Result<(), VoltageRailError> {
    match firmware {
        None => Err(refuse_wrong_mode(
            "dsPIC VoltageRail energize refused: firmware identity unknown \
             (observe GET_VERSION before set_mv/enable)",
        )),
        Some(DSPIC_DEGRADED_FW) => Err(refuse_degraded_firmware(
            "dsPIC VoltageRail energize refused for fw=0x86; no override permitted",
        )),
        Some(fw) if DSPIC_PROVEN_APP_FW.contains(&fw) => Ok(()),
        Some(fw) => Err(unsupported_voltage_path(format!(
            "dsPIC VoltageRail energize refused for unsupported firmware 0x{fw:02X}"
        ))),
    }
}

/// Per-op admission before any adapter performs I/O.
///
/// Policy:
/// - `RuntimeDiscovered`: refuse all ops (refine topology first)
/// - `ExternalDacNoPic`: energizing → honest Unsupported (TAS5782M not wired);
///   disable/heartbeat/measure still admitted so safe-off scaffolding can call
/// - `DsPic33Ep`: energizing requires [`admit_dspic_firmware_for_energize`];
///   disable always admitted (cut-hash-before-noise)
/// - `Pic16ChipDriver` / `Pic1704`: admitted when [`VoltageRailAdapterKind::admits_mutation`]
pub fn admit_voltage_rail_op(
    adapter: VoltageRailAdapterKind,
    firmware: Option<u8>,
    trust_degraded: bool,
    op: VoltageRailOp,
) -> Result<(), VoltageRailError> {
    if matches!(
        adapter,
        VoltageRailAdapterKind::ClassicAmlRetainedOwner
            | VoltageRailAdapterKind::Bm1391RetainedOwner
    ) {
        return Err(unsupported_voltage_path(
            "native application rail I/O requires its retained current-boot PIC/PSU owner",
        ));
    }
    if matches!(adapter, VoltageRailAdapterKind::RuntimeDiscovered) {
        return Err(unsupported_voltage_path(format!(
            "VoltageRail {op:?} refused: adapter=RuntimeDiscovered \
             (refine BoardDesc / topology before rail I/O)"
        )));
    }

    if matches!(adapter, VoltageRailAdapterKind::ExternalDacNoPic) && op.is_energizing() {
        return Err(unsupported_voltage_path(
            "VoltageRail ExternalDacNoPic energize not implemented: \
             TAS5782M / kernel-DAC path has no VoltageRail adapter yet \
             (do not map to Ok(()) — ADR-0010 P1-2)",
        ));
    }

    if op.is_energizing() && matches!(adapter, VoltageRailAdapterKind::DsPic33Ep) {
        admit_dspic_firmware_for_energize(firmware, trust_degraded)?;
    }

    // Disable / heartbeat / measure on admitted kinds: allow through.
    // Energizing on Pic16/Pic1704: kind already admits_mutation.
    if op.is_energizing() {
        admit_voltage_rail_mutation(adapter)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PIC16 pure encode (S9 ChipDriver path) — shared by adapters + tests
// ---------------------------------------------------------------------------

/// Live-proven PIC16F1704 DAC formula offset (volts domain).
pub const PIC16_VOLTAGE_OFFSET: f64 = 1_608.420_446;
/// Live-proven PIC16F1704 DAC formula divisor (volts domain).
pub const PIC16_VOLTAGE_DIVISOR: f64 = 170.423_497;
/// Minimum safe PIC DAC value (pic=6 ≈ 9.40 V; pic=0 is overvolt).
pub const PIC16_MIN_SAFE_DAC: u8 = 6;

/// S9 stock-FPGA bring-up init rail (safe enumeration ~9.4 V).
pub const STOCK_PIC16_INIT_MV: u16 = 9_400;
/// S9 stock-FPGA steady operating rail (~9.1 V, historical bmminer class).
pub const STOCK_PIC16_OPERATING_MV: u16 = 9_100;

/// Init DAC for stock FPGA energize (must stay equal to historical `INIT_VOLTAGE_DAC=6`).
pub fn stock_pic16_init_dac() -> u8 {
    pic16_mv_to_dac(STOCK_PIC16_INIT_MV)
}

/// Operating DAC for stock FPGA post-enum set-point (SSOT; may differ ±1 from
/// historical hardcoded `DEFAULT_VOLTAGE_DAC=57` if formula rounding drifts).
pub fn stock_pic16_operating_dac() -> u8 {
    pic16_mv_to_dac(STOCK_PIC16_OPERATING_MV)
}

// ---------------------------------------------------------------------------
// PIC1704 short-form set_mv (evidence-exhausted pure admission)
// ---------------------------------------------------------------------------

/// Short-form PIC1704 voltage feedback low register (R) — SOURCE_HAL pic1704.h.
pub const PIC1704_REG_VOLTAGE_L: u8 = 0x02;
/// Short-form PIC1704 voltage feedback high register (R).
pub const PIC1704_REG_VOLTAGE_H: u8 = 0x03;
/// Short-form PIC1704 control register (W) — DC-DC / heartbeat only.
pub const PIC1704_REG_CONTROL: u8 = 0x09;

/// Held short-form map has **no** writable mV/DAC set-point register.
///
/// Rail absolute voltage is board/PSU topology; PIC1704 gates DC-DC via
/// `REG_CONTROL`. VoltageRail `set_mv` is therefore **NOT IMPLEMENTED** with
/// evidence exhausted offline (not merely live-unvalidated).
pub const fn pic1704_short_form_has_writable_voltage_setpoint() -> bool {
    false
}

/// Pure admission for Pic1704 VoltageRail `set_mv` (host-safe, no HAL).
pub fn admit_pic1704_short_form_set_mv(mv: u16) -> Result<(), VoltageRailError> {
    debug_assert!(!pic1704_short_form_has_writable_voltage_setpoint());
    let _ = (
        PIC1704_REG_VOLTAGE_L,
        PIC1704_REG_VOLTAGE_H,
        PIC1704_REG_CONTROL,
    );
    Err(unsupported_voltage_path(format!(
        "PIC1704 short-form set_mv({mv}) refused: SOURCE_HAL map has no writable mV/DAC register \
         (REG_VOLTAGE_L/H=0x02/0x03 are read-only feedback; rail gate is REG_CONTROL DC-DC only). \
         Evidence-exhausted offline — not live-gated; do not invent a write path"
    )))
}

/// Convert millivolts → PIC16 DAC byte with safety floor.
pub fn pic16_mv_to_dac(mv: u16) -> u8 {
    let voltage_v = f64::from(mv) / 1000.0;
    let raw = (PIC16_VOLTAGE_OFFSET - (voltage_v * PIC16_VOLTAGE_DIVISOR)).round();
    let as_u8 = if raw < 0.0 {
        0u8
    } else if raw > 255.0 {
        255u8
    } else {
        raw as u8
    };
    as_u8.max(PIC16_MIN_SAFE_DAC)
}

/// Convert PIC16 DAC byte → millivolts (rounded).
pub fn pic16_dac_to_mv(dac: u8) -> u16 {
    let voltage_v = (PIC16_VOLTAGE_OFFSET - f64::from(dac)) / PIC16_VOLTAGE_DIVISOR;
    let mv = (voltage_v * 1000.0).round();
    if mv < 0.0 {
        0
    } else if mv > f64::from(u16::MAX) {
        u16::MAX
    } else {
        mv as u16
    }
}

// ---------------------------------------------------------------------------
// Host-mockable adapter wrappers
// ---------------------------------------------------------------------------

/// Pure no-op rail used only in host tests of adapter discipline.
///
/// Production code must not use this for real boards — it records commands
/// without I/O so VoltageRail call-order tests stay HAL-free. Prefer wrapping
/// with [`BackendVoltageRail`] so admission policy is exercised.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecordingVoltageRail {
    pub commands: Vec<&'static str>,
    pub last_mv: Option<u16>,
}

impl VoltageRail for RecordingVoltageRail {
    fn set_mv(&mut self, mv: u16) -> Result<(), VoltageRailError> {
        self.commands.push("set_mv");
        self.last_mv = Some(mv);
        Ok(())
    }
    fn enable(&mut self) -> Result<(), VoltageRailError> {
        self.commands.push("enable");
        Ok(())
    }
    fn disable(&mut self) -> Result<(), VoltageRailError> {
        self.commands.push("disable");
        Ok(())
    }
    fn heartbeat(&mut self) -> Result<(), VoltageRailError> {
        self.commands.push("heartbeat");
        Ok(())
    }
}

/// Honest NOT IMPLEMENTED rail for S21-class ExternalDac / TAS5782M.
///
/// Energizing returns [`VoltageRailError::Unsupported`]. Disable/heartbeat
/// succeed as no-op safe-off scaffolding (no I/O claimed).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedExternalDacRail;

impl VoltageRail for UnsupportedExternalDacRail {
    fn set_mv(&mut self, _mv: u16) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::ExternalDacNoPic,
            None,
            false,
            VoltageRailOp::SetMv,
        )
    }
    fn enable(&mut self) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::ExternalDacNoPic,
            None,
            false,
            VoltageRailOp::Enable,
        )
    }
    fn disable(&mut self) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::ExternalDacNoPic,
            None,
            false,
            VoltageRailOp::Disable,
        )?;
        Ok(())
    }
    fn heartbeat(&mut self) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::ExternalDacNoPic,
            None,
            false,
            VoltageRailOp::Heartbeat,
        )?;
        Ok(())
    }
    fn measure_mv(&mut self) -> Result<Option<u16>, VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::ExternalDacNoPic,
            None,
            false,
            VoltageRailOp::Measure,
        )?;
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// TAS5782M ExternalDac (S21 NoPic) — evidence-backed constants + EXPERIMENTAL rail
// ---------------------------------------------------------------------------

/// S21 NoPic TAS5782M I²C addresses (chain A/B/C class; Bible + platform config).
///
/// Evidence: `HARDWARE_REFERENCE.md`,
/// `platform/config.rs` S21 NoPic DTB notes (i2c-0 0x49/0x4A/0x4B).
pub const TAS5782M_I2C_ADDRS: [u8; 3] = [0x49, 0x4A, 0x4B];

/// Whether an I²C 7-bit address is a known TAS5782M voltage DAC slot.
pub const fn is_tas5782m_i2c_addr(addr: u8) -> bool {
    matches!(addr, 0x49..=0x4B)
}

/// EXPERIMENTAL TAS5782M VoltageRail — **userland write path not RE'd**.
///
/// On S21 NoPic, platform notes state voltage is **kernel DTB-managed**. This
/// type encodes known topology (addresses) and fail-closed mutation so engines
/// can construct ExternalDac adapters without inventing I2C register writes.
/// Disable is a no-op Ok (safe-off scaffolding); set/enable remain Unsupported.
///
/// Maturity: **EXPERIMENTAL** (topology) / **NOT IMPLEMENTED** (wire set_mv).
/// Safety: never GPIO-reset NoPic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tas5782mVoltageRail {
    /// I²C 7-bit address for this rail instance (must be in [`TAS5782M_I2C_ADDRS`]).
    pub i2c_addr: u8,
}

impl Tas5782mVoltageRail {
    /// Construct only for known TAS addresses; refuse unknown (fail-closed).
    pub fn try_new(i2c_addr: u8) -> Result<Self, VoltageRailError> {
        if !is_tas5782m_i2c_addr(i2c_addr) {
            return Err(unsupported_voltage_path(format!(
                "TAS5782M VoltageRail refuse: i2c_addr=0x{i2c_addr:02X} not in {{0x49,0x4A,0x4B}}"
            )));
        }
        Ok(Self { i2c_addr })
    }

    /// All known chain DAC addresses (host-safe inventory).
    pub fn known_addrs() -> &'static [u8] {
        &TAS5782M_I2C_ADDRS
    }
}

impl VoltageRail for Tas5782mVoltageRail {
    fn set_mv(&mut self, _mv: u16) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::ExternalDacNoPic,
            None,
            false,
            VoltageRailOp::SetMv,
        )?;
        Err(unsupported_voltage_path(format!(
            "TAS5782M@0x{:02X} set_mv not implemented: S21 NoPic voltage is kernel/DTB-managed; \
             userland I2C DAC write sequence not RE'd offline (do not invent registers)",
            self.i2c_addr
        )))
    }

    fn enable(&mut self) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::ExternalDacNoPic,
            None,
            false,
            VoltageRailOp::Enable,
        )?;
        Err(unsupported_voltage_path(format!(
            "TAS5782M@0x{:02X} enable not implemented: kernel-managed DAC; \
             never GPIO-reset NoPic to 'wake' the rail",
            self.i2c_addr
        )))
    }

    fn disable(&mut self) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::ExternalDacNoPic,
            None,
            false,
            VoltageRailOp::Disable,
        )?;
        // No userland mute sequence held offline — Ok no-op for safe-off scaffolding
        // (PSU cut is the production NoPic safe-off path, not TAS I2C).
        Ok(())
    }

    fn heartbeat(&mut self) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::ExternalDacNoPic,
            None,
            false,
            VoltageRailOp::Heartbeat,
        )?;
        Ok(())
    }

    fn measure_mv(&mut self) -> Result<Option<u16>, VoltageRailError> {
        admit_voltage_rail_op(
            VoltageRailAdapterKind::ExternalDacNoPic,
            None,
            false,
            VoltageRailOp::Measure,
        )?;
        Ok(None)
    }
}

/// Host-mockable VoltageRail adapter: policy gate + injected backend.
///
/// Live engines construct this with a backend that talks to PicController /
/// DspicController (see `dcentrald-asic::voltage_rail_adapters`). Host tests
/// inject [`RecordingVoltageRail`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendVoltageRail<B> {
    /// BoardDesc-resolved adapter family.
    pub kind: VoltageRailAdapterKind,
    /// Observed controller firmware byte when known (dsPIC GET_VERSION).
    pub firmware: Option<u8>,
    /// Legacy compatibility flag; cannot override the fw=0x86 refusal.
    pub trust_degraded: bool,
    /// Inner rail / controller façade.
    pub backend: B,
}

impl<B> BackendVoltageRail<B> {
    pub fn new(
        kind: VoltageRailAdapterKind,
        firmware: Option<u8>,
        trust_degraded: bool,
        backend: B,
    ) -> Self {
        Self {
            kind,
            firmware,
            trust_degraded,
            backend,
        }
    }

    /// Convenience: Pic16 / DsPic / Pic1704 mock for host tests (no fw refuse).
    pub fn host_mock(kind: VoltageRailAdapterKind, backend: B) -> Self {
        let firmware = match kind {
            VoltageRailAdapterKind::DsPic33Ep => Some(0x89),
            _ => None,
        };
        Self::new(kind, firmware, false, backend)
    }
}

impl<B: VoltageRail> VoltageRail for BackendVoltageRail<B> {
    fn set_mv(&mut self, mv: u16) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            self.kind,
            self.firmware,
            self.trust_degraded,
            VoltageRailOp::SetMv,
        )?;
        self.backend.set_mv(mv)
    }
    fn enable(&mut self) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            self.kind,
            self.firmware,
            self.trust_degraded,
            VoltageRailOp::Enable,
        )?;
        self.backend.enable()
    }
    fn disable(&mut self) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            self.kind,
            self.firmware,
            self.trust_degraded,
            VoltageRailOp::Disable,
        )?;
        self.backend.disable()
    }
    fn heartbeat(&mut self) -> Result<(), VoltageRailError> {
        admit_voltage_rail_op(
            self.kind,
            self.firmware,
            self.trust_degraded,
            VoltageRailOp::Heartbeat,
        )?;
        self.backend.heartbeat()
    }
    fn measure_mv(&mut self) -> Result<Option<u16>, VoltageRailError> {
        admit_voltage_rail_op(
            self.kind,
            self.firmware,
            self.trust_degraded,
            VoltageRailOp::Measure,
        )?;
        self.backend.measure_mv()
    }
    fn firmware_identity(&self) -> Option<u8> {
        self.firmware.or_else(|| self.backend.firmware_identity())
    }
}

/// Construct the default fail-closed / mockable rail for an adapter kind.
///
/// - `ExternalDacNoPic` → [`UnsupportedExternalDacRail`] (honest NOT IMPLEMENTED)
/// - other admitted kinds → [`BackendVoltageRail`] over [`RecordingVoltageRail`]
///   for host/unit paths only — production must replace the backend with a live
///   controller wrapper before calling set_mv on real hardware.
pub fn host_adapter_rail(
    kind: VoltageRailAdapterKind,
) -> Result<BackendVoltageRail<RecordingVoltageRail>, VoltageRailError> {
    admit_voltage_rail_mutation(kind)?;
    if matches!(kind, VoltageRailAdapterKind::ExternalDacNoPic) {
        // Caller should use UnsupportedExternalDacRail; keep mutation admitted
        // so BoardDesc NoPic rows resolve, but energize still fails at op level.
    }
    Ok(BackendVoltageRail::host_mock(
        kind,
        RecordingVoltageRail::default(),
    ))
}

/// Map a controller I/O failure string into [`VoltageRailError::Io`].
pub fn voltage_rail_io_error(detail: impl Into<String>) -> VoltageRailError {
    VoltageRailError::Io {
        detail: detail.into(),
    }
}

/// Canonical bring-up sequence on a VoltageRail: set_mv then enable.
///
/// Engines must prefer this over ad-hoc `set_voltage` + `enable_voltage`
/// pairs so admission policy and ordering stay SSOT (P1-2 engine wire).
pub fn energize_voltage_rail<R: VoltageRail + ?Sized>(
    rail: &mut R,
    mv: u16,
) -> Result<(), VoltageRailError> {
    rail.set_mv(mv)?;
    rail.enable()
}

/// Canonical safe-off: disable rail (cut-hash-before-noise first step).
pub fn safe_off_voltage_rail<R: VoltageRail + ?Sized>(
    rail: &mut R,
) -> Result<(), VoltageRailError> {
    rail.disable()
}

/// Walk rail to a floor mV then disable (clean-stop / teardown pattern).
///
/// Used by AM2 hybrid Phase-3A teardown: coast chips before disable.
pub fn walk_down_and_safe_off_voltage_rail<R: VoltageRail + ?Sized>(
    rail: &mut R,
    floor_mv: u16,
) -> Result<(), VoltageRailError> {
    // Floor set is still an energizing-class op on some controllers (DAC write);
    // use set_mv only — do not re-enable after disable.
    rail.set_mv(floor_mv)?;
    rail.disable()
}

#[cfg(test)]
mod tests {
    #[test]
    fn t21_apw11a_profile_accepts_all_stock_versions_only() {
        for version in 0..=u8::MAX {
            let identity = super::BenchPsuIdentity {
                family: "APW11A",
                address_7bit: 0x10,
                version,
            };
            assert_eq!(
                super::validate_t21_apw11a(identity).is_ok(),
                [66, 67, 106, 113, 114, 115, 117, 118, 119, 120, 193].contains(&version)
            );
        }
        for (family, address_7bit) in [
            ("APW11", 0x10),
            ("APW12", 0x10),
            ("APW11A1216-1a", 0x10),
            ("APW11A", 0x50),
        ] {
            assert!(super::validate_t21_apw11a(super::BenchPsuIdentity {
                family,
                address_7bit,
                version: 66
            })
            .is_err());
        }
    }

    #[test]
    fn s21_bench_exact_geometry_and_polarity_cards() {
        use super::S21BenchProfile;
        for (target, count) in [
            ("am3-s21", 108),
            ("am3-t21", 108),
            ("amlogic-s21plus", 55),
            ("am3-s21pro", 65),
            ("am3-s21xp", 91),
        ] {
            let p = S21BenchProfile::for_board_target(target).unwrap();
            assert_eq!(p.board_target(), target);
            assert_eq!(p.chips_per_chain(), count);
            let card = p.polarity_card();
            assert!(card.starts_with(target));
            if target == "am3-t21" || target == "amlogic-s21plus" {
                assert!(card.contains("undriven"));
                assert!(!card.contains("ON=0"));
                assert!(!card.contains("ON=1"));
            } else {
                assert!(card.contains("ON=0 OFF=1"));
            }
        }
        for target in ["S21", "am3-s21plus", "am3-t21 ", "am3-s19xp"] {
            assert!(S21BenchProfile::for_board_target(target).is_err());
        }
    }

    #[test]
    fn s21_bench_refuses_wrong_identity_zero_and_sibling_populations() {
        use super::discover_s21_psu;
        for (target, name, count, wrong_name) in [
            ("am3-t21", "BHB68701", 108, "BHB68603"),
            ("amlogic-s21plus", "A3HB70701", 55, "A3HB70601"),
        ] {
            assert!(discover_s21_psu(target, &[(name, count); 3], None).is_ok());
            for bad in [0, count - 1, count + 1, 65, 91] {
                assert!(discover_s21_psu(target, &[(name, bad); 3], None).is_err());
            }
            assert!(discover_s21_psu(target, &[(wrong_name, count); 3], None).is_err());
            assert!(discover_s21_psu(target, &[(name, count); 2], None).is_err());
            assert!(discover_s21_psu(target, &[], None).is_err());
            assert!(discover_s21_psu(
                target,
                &[(name, count), (name, count), (wrong_name, count)],
                None
            )
            .is_err());
        }
        for (family, address_7bit) in [("", 0x10), ("unknown", 0x80)] {
            assert!(discover_s21_psu(
                "amlogic-s21plus",
                &[("A3HB70701", 55); 3],
                Some(super::BenchPsuIdentity {
                    family,
                    address_7bit,
                    version: 0,
                })
            )
            .is_err());
        }
    }
    use super::*;
    use crate::board_desc::AsicProtocolIdentity;

    #[test]
    fn retained_native_application_classes_never_fall_back_to_legacy_pic_adapters() {
        for class in [
            crate::board_desc::VoltageControllerClass::ClassicAmlApplication89,
            crate::board_desc::VoltageControllerClass::Bm1391Application,
        ] {
            let adapter = resolve_voltage_rail_adapter(class, AsicProtocolIdentity::Bm1362);
            assert!(!adapter.admits_mutation());
            for operation in [
                VoltageRailOp::SetMv,
                VoltageRailOp::Enable,
                VoltageRailOp::Disable,
                VoltageRailOp::Heartbeat,
                VoltageRailOp::Measure,
            ] {
                assert!(admit_voltage_rail_op(adapter, Some(0x89), true, operation).is_err());
            }
        }
    }

    struct RefuseAll;

    impl VoltageRail for RefuseAll {
        fn set_mv(&mut self, _mv: u16) -> Result<(), VoltageRailError> {
            Err(VoltageRailError::Refused {
                reason: VoltageRefuseReason::DegradedFirmware,
                detail: "test".into(),
            })
        }
        fn enable(&mut self) -> Result<(), VoltageRailError> {
            self.set_mv(0)
        }
        fn disable(&mut self) -> Result<(), VoltageRailError> {
            Ok(())
        }
        fn heartbeat(&mut self) -> Result<(), VoltageRailError> {
            Ok(())
        }
    }

    #[test]
    fn refuse_is_not_ok() {
        let mut r = RefuseAll;
        assert!(r.set_mv(13700).is_err());
        assert!(r.enable().is_err());
        assert!(r.disable().is_ok());
    }

    #[test]
    fn unsupported_must_not_be_confused_with_success() {
        let err = VoltageRailError::Unsupported {
            detail: "TAS5782M not wired".into(),
        };
        assert!(matches!(err, VoltageRailError::Unsupported { .. }));
        // BM1362 historically returned Ok(()) while doing nothing — forbidden.
        assert_ne!(format!("{err}"), "");
    }

    #[test]
    fn helper_constructors_match_discipline() {
        let e = unsupported_voltage_path("BM1362 needs DspicController");
        assert!(!is_hard_refuse(&e));
        assert!(is_hard_refuse(&refuse_degraded_firmware("fw=0x86")));
        assert!(is_hard_refuse(&refuse_wrong_mode("bootloader")));
    }

    #[test]
    fn bm1362_chip_driver_set_voltage_is_refused() {
        // Historical bug: BM1362::set_voltage returned Ok(()) while doing nothing.
        let err = chip_driver_set_voltage_admission(AsicProtocolIdentity::Bm1362).unwrap_err();
        assert!(matches!(err, VoltageRailError::Unsupported { .. }));
        assert_eq!(
            voltage_ownership_for_asic(AsicProtocolIdentity::Bm1362),
            VoltageOwnership::HashboardDspic
        );
    }

    #[test]
    fn bm1368_and_bm1370_are_external_dac_not_chip_driver() {
        for id in [AsicProtocolIdentity::Bm1368, AsicProtocolIdentity::Bm1370] {
            assert_eq!(
                voltage_ownership_for_asic(id),
                VoltageOwnership::ExternalDacNoPic
            );
            assert!(chip_driver_set_voltage_admission(id).is_err());
        }
    }

    #[test]
    fn bm1366_identity_alone_is_runtime_discovered_not_chip_driver_pic() {
        // S19k Amlogic NoPic (Has_Pic:false) forbids inheriting BM1362/PIC
        // voltage fabrics from chip identity alone. Industrial PIC BM1366
        // must be BoardDesc-scoped (Pic16/Pic1704) before ChipDriver admits.
        assert_eq!(
            voltage_ownership_for_asic(AsicProtocolIdentity::Bm1366),
            VoltageOwnership::RuntimeDiscovered
        );
        assert!(chip_driver_set_voltage_admission(AsicProtocolIdentity::Bm1366).is_err());
        use crate::board_desc::VoltageControllerClass;
        let amlogic_nopic = resolve_voltage_rail_adapter(
            VoltageControllerClass::NoPic,
            AsicProtocolIdentity::Bm1366,
        );
        assert_eq!(amlogic_nopic, VoltageRailAdapterKind::ExternalDacNoPic);
        let industrial_pic = resolve_voltage_rail_adapter(
            VoltageControllerClass::Pic16F1704,
            AsicProtocolIdentity::Bm1366,
        );
        assert_eq!(industrial_pic, VoltageRailAdapterKind::Pic16ChipDriver);
        assert!(industrial_pic.admits_mutation());
    }
    #[test]
    fn bm1387_allows_chip_driver_pic_path() {
        assert_eq!(
            voltage_ownership_for_asic(AsicProtocolIdentity::Bm1387),
            VoltageOwnership::ChipDriverPic
        );
        assert!(chip_driver_set_voltage_admission(AsicProtocolIdentity::Bm1387).is_ok());
    }

    #[test]
    fn industrial_bm139x_with_proven_controller_identity_are_hashboard_dspic() {
        for id in [
            AsicProtocolIdentity::Bm1391,
            AsicProtocolIdentity::Bm1397,
            AsicProtocolIdentity::Bm1398,
        ] {
            assert_eq!(
                voltage_ownership_for_asic(id),
                VoltageOwnership::HashboardDspic
            );
            assert!(chip_driver_set_voltage_admission(id).is_err());
        }
    }

    #[test]
    fn bm1396_identity_only_fallback_cannot_promote_voltage_mutation() {
        use crate::board_desc::VoltageControllerClass;

        assert_eq!(
            voltage_ownership_for_asic(AsicProtocolIdentity::Bm1396),
            VoltageOwnership::HashboardFramedEndpointEvidenceOnly
        );
        assert!(chip_driver_set_voltage_admission(AsicProtocolIdentity::Bm1396).is_err());

        let fallback = resolve_voltage_rail_adapter(
            VoltageControllerClass::RuntimeDiscovered,
            AsicProtocolIdentity::Bm1396,
        );
        assert_eq!(fallback, VoltageRailAdapterKind::Bm1396I2c11EvidenceOnly);
        assert!(!fallback.admits_mutation());
        assert!(admit_voltage_rail_mutation(fallback).is_err());
    }

    #[test]
    fn recording_rail_preserves_command_order() {
        let mut rail = RecordingVoltageRail::default();
        rail.set_mv(13_700).unwrap();
        rail.enable().unwrap();
        rail.heartbeat().unwrap();
        rail.disable().unwrap();
        assert_eq!(rail.commands, ["set_mv", "enable", "heartbeat", "disable"]);
        assert_eq!(rail.last_mv, Some(13_700));
    }

    #[test]
    fn board_desc_voltage_class_agrees_with_ownership_for_beta_rows() {
        use crate::board_desc::{BoardDesc, VoltageControllerClass};
        // Public-beta am1-s9: PIC path
        assert_eq!(
            BoardDesc::am1_s9().voltage_controller,
            VoltageControllerClass::Pic16F1704
        );
        assert_eq!(
            voltage_ownership_for_asic(BoardDesc::am1_s9().asic_protocol),
            VoltageOwnership::ChipDriverPic
        );
        // Public-beta am2-s19j: dsPIC
        let am2 = BoardDesc::lookup("am2-s19j").expect("registry");
        assert_eq!(am2.voltage_controller, VoltageControllerClass::DsPic33Ep);
        assert_eq!(
            voltage_ownership_for_asic(am2.asic_protocol),
            VoltageOwnership::HashboardDspic
        );
    }

    #[test]
    fn voltage_rail_adapter_from_controller_class_is_stable() {
        use crate::board_desc::VoltageControllerClass;
        assert_eq!(
            voltage_rail_adapter_for_controller(VoltageControllerClass::Pic16F1704),
            VoltageRailAdapterKind::Pic16ChipDriver
        );
        assert_eq!(
            voltage_rail_adapter_for_controller(VoltageControllerClass::DsPic33Ep),
            VoltageRailAdapterKind::DsPic33Ep
        );
        assert_eq!(
            voltage_rail_adapter_for_controller(VoltageControllerClass::Bm1396FramedI2c11),
            VoltageRailAdapterKind::Bm1396I2c11EvidenceOnly
        );
        assert_eq!(
            voltage_rail_adapter_for_controller(VoltageControllerClass::NoPic),
            VoltageRailAdapterKind::ExternalDacNoPic
        );
        assert_eq!(
            voltage_rail_adapter_for_controller(VoltageControllerClass::RuntimeDiscovered),
            VoltageRailAdapterKind::RuntimeDiscovered
        );
        assert!(!VoltageRailAdapterKind::RuntimeDiscovered.admits_mutation());
        assert!(!VoltageRailAdapterKind::Bm1396I2c11EvidenceOnly.admits_mutation());
        assert!(VoltageRailAdapterKind::DsPic33Ep.admits_mutation());
    }

    #[test]
    fn resolve_voltage_rail_prefers_board_controller_over_asic() {
        use crate::board_desc::{AsicProtocolIdentity, VoltageControllerClass};
        // Board says NoPic even if ASIC identity might map elsewhere.
        let kind = resolve_voltage_rail_adapter(
            VoltageControllerClass::NoPic,
            AsicProtocolIdentity::Bm1362,
        );
        assert_eq!(kind, VoltageRailAdapterKind::ExternalDacNoPic);
        // Board RuntimeDiscovered → fall back to ASIC ownership map.
        let kind = resolve_voltage_rail_adapter(
            VoltageControllerClass::RuntimeDiscovered,
            AsicProtocolIdentity::Bm1362,
        );
        assert_eq!(kind, VoltageRailAdapterKind::DsPic33Ep);
        let kind = resolve_voltage_rail_adapter(
            VoltageControllerClass::RuntimeDiscovered,
            AsicProtocolIdentity::Bm1387,
        );
        assert_eq!(kind, VoltageRailAdapterKind::Pic16ChipDriver);
    }

    #[test]
    fn admit_voltage_rail_mutation_fail_closed_on_runtime_discovered() {
        assert!(admit_voltage_rail_mutation(VoltageRailAdapterKind::DsPic33Ep).is_ok());
        let err =
            admit_voltage_rail_mutation(VoltageRailAdapterKind::RuntimeDiscovered).unwrap_err();
        assert!(matches!(err, VoltageRailError::Unsupported { .. }));
    }

    #[test]
    fn beta_board_desc_resolves_production_adapters() {
        use crate::board_desc::BoardDesc;
        let s9 = BoardDesc::am1_s9();
        let kind = resolve_voltage_rail_adapter(s9.voltage_controller, s9.asic_protocol);
        assert_eq!(kind, VoltageRailAdapterKind::Pic16ChipDriver);
        assert!(admit_voltage_rail_mutation(kind).is_ok());
        let am2 = BoardDesc::lookup("am2-s19j").expect("registry");
        let kind = resolve_voltage_rail_adapter(am2.voltage_controller, am2.asic_protocol);
        assert_eq!(kind, VoltageRailAdapterKind::DsPic33Ep);
        assert_eq!(
            kind.as_voltage_ownership(),
            VoltageOwnership::HashboardDspic
        );
    }

    /// Structural pin: ChipDriver refuse sites must call the pure admission SSOT
    /// (not re-open-code Ok(()) or a free-form string only).
    #[test]
    fn chip_driver_impls_call_pure_admission_ssot() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for rel in [
            "dcentrald-asic/src/drivers/bm1362.rs",
            "dcentrald-asic/src/drivers/bm1368.rs",
            "dcentrald-asic/src/drivers/bm1370.rs",
        ] {
            let src = std::fs::read_to_string(root.join(rel))
                .unwrap_or_else(|e| panic!("read {rel}: {e}"));
            assert!(
                src.contains("chip_driver_set_voltage_admission"),
                "{rel} must call dcentrald_common::chip_driver_set_voltage_admission"
            );
            // Forbid reintroducing a bare success return on the wrong spine.
            // Ignore comment lines that document the ban ("MUST NOT return Ok(())").
            let body = src.split("fn set_voltage").nth(1).unwrap_or("");
            let bare_ok = body.lines().take(30).any(|l| {
                let t = l.trim();
                if t.starts_with("//") {
                    return false;
                }
                t == "Ok(())"
                    || t == "Ok(()) ,"
                    || t.starts_with("Ok(()) //")
                    || t.contains("return Ok(())")
            });
            assert!(
                !bare_ok,
                "{rel} set_voltage must not bare-return Ok(()) (use VoltageOwnership SSOT)"
            );
        }
    }

    #[test]
    fn pic1704_adapter_kind_admits_mutation_and_maps_from_board() {
        use crate::board_desc::VoltageControllerClass;
        assert_eq!(
            voltage_rail_adapter_for_controller(VoltageControllerClass::Pic1704),
            VoltageRailAdapterKind::Pic1704
        );
        assert!(VoltageRailAdapterKind::Pic1704.admits_mutation());
        assert_eq!(
            VoltageRailAdapterKind::Pic1704.as_voltage_ownership(),
            VoltageOwnership::HashboardDspic
        );
        // Host mock can energize-plan (Recording) even though live set_mv is unsupported.
        let mut rail = BackendVoltageRail::host_mock(
            VoltageRailAdapterKind::Pic1704,
            RecordingVoltageRail::default(),
        );
        energize_voltage_rail(&mut rail, 12_000).unwrap();
        assert_eq!(rail.backend.commands, ["set_mv", "enable"]);
    }

    #[test]
    fn admit_pic1704_short_form_set_mv_is_evidence_exhausted() {
        assert!(!pic1704_short_form_has_writable_voltage_setpoint());
        assert_eq!(PIC1704_REG_VOLTAGE_L, 0x02);
        assert_eq!(PIC1704_REG_VOLTAGE_H, 0x03);
        assert_eq!(PIC1704_REG_CONTROL, 0x09);
        let err = admit_pic1704_short_form_set_mv(13_700).unwrap_err();
        assert!(matches!(err, VoltageRailError::Unsupported { .. }));
        let msg = err.to_string();
        assert!(msg.contains("0x02") || msg.contains("read-only") || msg.contains("REG_VOLTAGE"));
        assert!(
            msg.contains("Evidence-exhausted") || msg.contains("evidence-exhausted"),
            "{msg}"
        );
    }

    /// Structural pin: asic Pic1704 protocol + adapter call pure common SSOT.
    #[test]
    fn pic1704_set_mv_evidence_exhausted_is_shipped_ssot() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let proto = std::fs::read_to_string(root.join("dcentrald-asic/src/pic1704/protocol.rs"))
            .expect("protocol");
        for needle in [
            "fn admit_short_form_set_mv",
            "fn short_form_has_writable_voltage_setpoint",
            "Pic1704RegisterAccess",
            "REG_VOLTAGE_L",
            "ReadOnly",
            "admit_pic1704_short_form_set_mv",
        ] {
            assert!(
                proto.contains(needle),
                "pic1704/protocol.rs must contain `{needle}`"
            );
        }
        let adapters =
            std::fs::read_to_string(root.join("dcentrald-asic/src/voltage_rail_adapters.rs"))
                .expect("adapters");
        assert!(
            adapters.contains("admit_short_form_set_mv"),
            "Pic1704VoltageRail set_mv must call admit_short_form_set_mv"
        );
    }

    /// Daemon thermal emergency/fan-failure/throttle/set_fan must plan via SafetyAction.
    #[test]
    fn daemon_thermal_emergency_wires_safety_action_plan() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../dcentrald/src/daemon.rs");
        let src = std::fs::read_to_string(&path).expect("daemon.rs");
        for needle in [
            "as_safety_action",
            "apply_safety_action",
            "EmergencyShutdown",
            "FanFailure",
            "plan_cut",
            "plan_fan_pwm",
        ] {
            assert!(
                src.contains(needle),
                "daemon.rs thermal path must wire `{needle}` (P1-6)"
            );
        }
        // Both emergency arms must plan SafetyAction (not only ad-hoc fan set).
        let em_idx = src
            .find("ThermalAction::EmergencyShutdown =>")
            .expect("EmergencyShutdown arm");
        let em_slice = &src[em_idx..em_idx.saturating_add(2500).min(src.len())];
        assert!(
            em_slice.contains("as_safety_action") && em_slice.contains("apply_safety_action"),
            "EmergencyShutdown arm must call as_safety_action + apply_safety_action"
        );
        let ff_idx = src
            .find("ThermalAction::FanFailure =>")
            .expect("FanFailure arm");
        let ff_slice = &src[ff_idx..ff_idx.saturating_add(2500).min(src.len())];
        assert!(
            ff_slice.contains("as_safety_action") && ff_slice.contains("apply_safety_action"),
            "FanFailure arm must call as_safety_action + apply_safety_action"
        );
        // FanOnly arms — match exact match-arm openers (not earlier pattern matches).
        let set_idx = src
            .find("ThermalAction::SetFanPwm(pwm) =>")
            .expect("SetFanPwm arm");
        let thr_idx = src
            .find("ThermalAction::ThrottleAndFan { pwm, freq_reduction_pct } =>")
            .expect("ThrottleAndFan arm");
        let em_arm_idx = src
            .find("ThermalAction::EmergencyShutdown =>")
            .expect("EmergencyShutdown match arm");
        assert!(
            set_idx < thr_idx && thr_idx < em_arm_idx,
            "expected arm order SetFanPwm < ThrottleAndFan < EmergencyShutdown"
        );
        let set_slice = &src[set_idx..thr_idx];
        assert!(
            set_slice.contains("as_safety_action") && set_slice.contains("apply_safety_action"),
            "SetFanPwm arm must call as_safety_action + apply_safety_action"
        );
        let thr_slice = &src[thr_idx..em_arm_idx];
        assert!(
            thr_slice.contains("as_safety_action") && thr_slice.contains("apply_safety_action"),
            "ThrottleAndFan arm must call as_safety_action + apply_safety_action"
        );
    }

    #[test]
    fn tas5782m_topology_and_fail_closed_userland_writes() {
        assert_eq!(TAS5782M_I2C_ADDRS, [0x49, 0x4A, 0x4B]);
        assert!(is_tas5782m_i2c_addr(0x49));
        assert!(!is_tas5782m_i2c_addr(0x20));
        assert!(Tas5782mVoltageRail::try_new(0x11).is_err());
        let mut rail = Tas5782mVoltageRail::try_new(0x49).expect("known addr");
        assert!(rail.set_mv(12_000).is_err());
        assert!(rail.enable().is_err());
        assert!(rail.disable().is_ok());
        assert!(rail.heartbeat().is_ok());
        assert_eq!(rail.measure_mv().unwrap(), None);
        // BoardDesc NoPic resolves ExternalDac adapter family.
        use crate::board_desc::VoltageControllerClass;
        assert_eq!(
            voltage_rail_adapter_for_controller(VoltageControllerClass::NoPic),
            VoltageRailAdapterKind::ExternalDacNoPic
        );
    }

    /// ChipDriver PIC path drivers must go through VoltageRail strangler helper.
    #[test]
    fn chip_driver_pic_path_uses_voltage_rail_strangler() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let adapters =
            std::fs::read_to_string(root.join("dcentrald-asic/src/voltage_rail_adapters.rs"))
                .expect("adapters");
        assert!(
            adapters.contains("fn chip_driver_set_voltage_via_pic16_rail"),
            "must export ChipDriver→Pic16 VoltageRail strangler"
        );
        for rel in [
            "dcentrald-asic/src/drivers/bm1387.rs",
            "dcentrald-asic/src/drivers/bm1366.rs",
            "dcentrald-asic/src/drivers/bm1397.rs",
            "dcentrald-asic/src/drivers/bm1398.rs",
        ] {
            let src = std::fs::read_to_string(root.join(rel))
                .unwrap_or_else(|e| panic!("read {rel}: {e}"));
            assert!(
                src.contains("chip_driver_set_voltage_via_pic16_rail"),
                "{rel} must call chip_driver_set_voltage_via_pic16_rail"
            );
            assert!(
                !src.contains("PicController::voltage_to_pic"),
                "{rel} must not encode DAC via PicController::voltage_to_pic directly"
            );
            assert!(
                !src.contains("pic.set_voltage(pic_value)"),
                "{rel} must not call pic.set_voltage with raw DAC (use VoltageRail)"
            );
        }
        // HashboardDspic identities refuse ChipDriver path even through the strangler.
        assert!(chip_driver_set_voltage_admission(AsicProtocolIdentity::Bm1397).is_err());
        assert!(chip_driver_set_voltage_admission(AsicProtocolIdentity::Bm1398).is_err());
        assert!(chip_driver_set_voltage_admission(AsicProtocolIdentity::Bm1387).is_ok());
        assert!(chip_driver_set_voltage_admission(AsicProtocolIdentity::Bm1366).is_err());
    }

    #[test]
    fn dspic_fw86_energize_refused_even_with_trust_degraded() {
        assert!(admit_dspic_firmware_for_energize(Some(0x86), false).is_err());
        assert!(admit_dspic_firmware_for_energize(Some(0x86), true).is_err());
        assert!(admit_dspic_firmware_for_energize(Some(0x89), false).is_ok());
        assert!(admit_dspic_firmware_for_energize(Some(0x82), false).is_ok());
        assert!(admit_dspic_firmware_for_energize(None, false).is_err());
        assert!(admit_dspic_firmware_for_energize(Some(0x11), false).is_err());
    }

    #[test]
    fn admit_voltage_rail_op_external_dac_blocks_energize_not_disable() {
        let kind = VoltageRailAdapterKind::ExternalDacNoPic;
        let err = admit_voltage_rail_op(kind, None, false, VoltageRailOp::SetMv).unwrap_err();
        assert!(matches!(err, VoltageRailError::Unsupported { .. }));
        assert!(admit_voltage_rail_op(kind, None, false, VoltageRailOp::Disable).is_ok());
        assert!(admit_voltage_rail_op(kind, None, false, VoltageRailOp::Heartbeat).is_ok());
    }

    #[test]
    fn backend_rail_dspic_refuses_fw86_before_backend_runs() {
        let mut rail = BackendVoltageRail::new(
            VoltageRailAdapterKind::DsPic33Ep,
            Some(0x86),
            false,
            RecordingVoltageRail::default(),
        );
        assert!(rail.set_mv(13_700).is_err());
        assert!(rail.enable().is_err());
        // Backend must not have been invoked for energizing.
        assert!(rail.backend.commands.is_empty());
        // Safe-off still reaches backend.
        rail.disable().unwrap();
        assert_eq!(rail.backend.commands, ["disable"]);
    }

    #[test]
    fn backend_rail_dspic_trust_degraded_cannot_energize() {
        let mut rail = BackendVoltageRail::new(
            VoltageRailAdapterKind::DsPic33Ep,
            Some(0x86),
            true,
            RecordingVoltageRail::default(),
        );
        assert!(rail.set_mv(13_700).is_err());
        assert!(rail.enable().is_err());
        assert!(rail.backend.commands.is_empty());
        assert_eq!(rail.backend.last_mv, None);
    }

    #[test]
    fn backend_rail_pic16_host_mock_orders_commands() {
        let mut rail = BackendVoltageRail::host_mock(
            VoltageRailAdapterKind::Pic16ChipDriver,
            RecordingVoltageRail::default(),
        );
        rail.set_mv(9_000).unwrap();
        rail.enable().unwrap();
        rail.heartbeat().unwrap();
        rail.disable().unwrap();
        assert_eq!(
            rail.backend.commands,
            ["set_mv", "enable", "heartbeat", "disable"]
        );
    }

    #[test]
    fn unsupported_external_dac_rail_is_honest() {
        let mut rail = UnsupportedExternalDacRail;
        assert!(rail.set_mv(12_000).is_err());
        assert!(rail.enable().is_err());
        assert!(rail.disable().is_ok());
        assert!(rail.heartbeat().is_ok());
        assert_eq!(rail.measure_mv().unwrap(), None);
    }

    #[test]
    fn pic16_mv_dac_roundtrip_near_9v() {
        // PIC value 75 = 9.00 V (documented live formula).
        let dac = pic16_mv_to_dac(9_000);
        assert_eq!(dac, 75);
        let mv = pic16_dac_to_mv(75);
        // Round-trip within 5 mV of the 9.00 V point.
        assert!((mv as i32 - 9_000).abs() < 5, "mv={mv}");
    }

    #[test]
    fn pic16_dac_never_below_min_safe() {
        // Requesting a very high voltage would encode a low DAC; floor at 6.
        let dac = pic16_mv_to_dac(20_000);
        assert!(dac >= PIC16_MIN_SAFE_DAC);
        assert_eq!(
            pic16_mv_to_dac(9_440).max(PIC16_MIN_SAFE_DAC),
            pic16_mv_to_dac(9_440)
        );
    }

    #[test]
    fn host_adapter_rail_from_beta_board_desc() {
        use crate::board_desc::BoardDesc;
        let s9 = BoardDesc::am1_s9();
        let kind = resolve_voltage_rail_adapter(s9.voltage_controller, s9.asic_protocol);
        let mut rail = host_adapter_rail(kind).expect("s9 adapter");
        rail.set_mv(9_000).unwrap();
        assert_eq!(rail.backend.last_mv, Some(9_000));

        let am2 = BoardDesc::lookup("am2-s19j").expect("registry");
        let kind = resolve_voltage_rail_adapter(am2.voltage_controller, am2.asic_protocol);
        let mut rail = host_adapter_rail(kind).expect("am2 adapter");
        rail.set_mv(13_700).unwrap();
        assert_eq!(rail.backend.last_mv, Some(13_700));
    }

    #[test]
    fn runtime_discovered_refuses_all_ops() {
        for op in [
            VoltageRailOp::SetMv,
            VoltageRailOp::Enable,
            VoltageRailOp::Disable,
            VoltageRailOp::Heartbeat,
            VoltageRailOp::Measure,
        ] {
            assert!(
                admit_voltage_rail_op(VoltageRailAdapterKind::RuntimeDiscovered, None, false, op)
                    .is_err(),
                "{op:?}"
            );
        }
    }

    /// Structural pin: live asic adapter module must implement VoltageRail
    /// over DspicController / PicController / Pic0x89Service and call pure admit helpers.
    #[test]
    fn asic_voltage_rail_adapters_module_exists_and_uses_policy() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../dcentrald-asic/src/voltage_rail_adapters.rs");
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        for needle in [
            "impl VoltageRail for DsPicVoltageRail",
            "impl VoltageRail for Pic16VoltageRail",
            "impl VoltageRail for Pic0x89VoltageRail",
            "impl VoltageRail for StockFpgaVoltageRail",
            "impl VoltageRail for Pic1704VoltageRail",
            "admit_voltage_rail_op",
            "UnsupportedExternalDacRail",
            "VoltageRailError",
        ] {
            assert!(
                src.contains(needle),
                "voltage_rail_adapters.rs must contain `{needle}`"
            );
        }
        let lib = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../dcentrald-asic/src/lib.rs"),
        )
        .expect("asic lib");
        assert!(
            lib.contains("pub mod voltage_rail_adapters"),
            "dcentrald-asic lib.rs must export voltage_rail_adapters"
        );
    }

    #[test]
    fn energize_voltage_rail_is_set_then_enable() {
        let mut rail = BackendVoltageRail::host_mock(
            VoltageRailAdapterKind::DsPic33Ep,
            RecordingVoltageRail::default(),
        );
        energize_voltage_rail(&mut rail, 13_700).unwrap();
        assert_eq!(rail.backend.commands, ["set_mv", "enable"]);
        assert_eq!(rail.backend.last_mv, Some(13_700));
    }

    #[test]
    fn energize_stops_before_enable_if_set_refused() {
        let mut rail = BackendVoltageRail::new(
            VoltageRailAdapterKind::DsPic33Ep,
            Some(0x86),
            false,
            RecordingVoltageRail::default(),
        );
        assert!(energize_voltage_rail(&mut rail, 13_700).is_err());
        assert!(rail.backend.commands.is_empty());
    }

    #[test]
    fn safe_off_and_walk_down_order() {
        let mut rail = BackendVoltageRail::host_mock(
            VoltageRailAdapterKind::DsPic33Ep,
            RecordingVoltageRail::default(),
        );
        safe_off_voltage_rail(&mut rail).unwrap();
        assert_eq!(rail.backend.commands, ["disable"]);
        rail.backend.commands.clear();
        walk_down_and_safe_off_voltage_rail(&mut rail, 11_500).unwrap();
        assert_eq!(rail.backend.commands, ["set_mv", "disable"]);
        assert_eq!(rail.backend.last_mv, Some(11_500));
    }

    /// Hybrid engine must construct Pic0x89VoltageRail + pure energize/safe_off
    /// at real voltage call sites (P1-2 engine wire).
    #[test]
    fn hybrid_engine_wires_pic0x89_voltage_rail() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../dcentrald/src/s19j_hybrid_mining.rs");
        let src = std::fs::read_to_string(&path).expect("hybrid source");
        for needle in [
            "Pic0x89VoltageRail",
            "energize_voltage_rail",
            "safe_off_voltage_rail",
            "apply_safety_action",
            "home_thermal_hard_stop_action",
            "home_panic_park_action",
        ] {
            assert!(
                src.contains(needle),
                "s19j_hybrid_mining.rs must wire `{needle}` (P1-2/P1-6 engine path)"
            );
        }
    }

    #[test]
    fn stock_pic16_mv_constants_match_historical_init_dac() {
        assert_eq!(STOCK_PIC16_INIT_MV, 9_400);
        assert_eq!(STOCK_PIC16_OPERATING_MV, 9_100);
        assert_eq!(stock_pic16_init_dac(), 6);
        assert_eq!(stock_pic16_init_dac(), pic16_mv_to_dac(STOCK_PIC16_INIT_MV));
        // Operating DAC is pure SSOT (historical bmminer used 57; accept ±1 LSB).
        let op = stock_pic16_operating_dac();
        assert!((op as i16 - 57).abs() <= 1, "operating dac={op}");
    }

    #[test]
    fn stock_energize_via_backend_rail_is_set_then_enable() {
        let mut rail = BackendVoltageRail::host_mock(
            VoltageRailAdapterKind::Pic16ChipDriver,
            RecordingVoltageRail::default(),
        );
        energize_voltage_rail(&mut rail, STOCK_PIC16_INIT_MV).unwrap();
        assert_eq!(rail.backend.commands, ["set_mv", "enable"]);
        assert_eq!(rail.backend.last_mv, Some(STOCK_PIC16_INIT_MV));
        rail.set_mv(STOCK_PIC16_OPERATING_MV).unwrap();
        assert_eq!(rail.backend.last_mv, Some(STOCK_PIC16_OPERATING_MV));
    }

    /// Stock + serial engines must use SafetyAction apply / VoltageRail safe_off.
    #[test]
    fn stock_and_serial_engines_wire_safety_action_and_voltage_rail() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let stock = std::fs::read_to_string(root.join("dcentrald/src/stock_mining.rs"))
            .expect("stock_mining");
        for needle in [
            "apply_safety_action",
            "PowerCutOnly",
            "PanicTeardown",
            "pic16_mv_to_dac",
            "StockFpgaVoltageRail",
            "energize_voltage_rail",
            "safe_off_voltage_rail",
            "STOCK_PIC16_INIT_MV",
            "STOCK_PIC16_OPERATING_MV",
        ] {
            assert!(
                stock.contains(needle),
                "stock_mining.rs must wire `{needle}`"
            );
        }
        // INIT DAC must be the pure PIC16 encode of 9.4 V.
        assert_eq!(pic16_mv_to_dac(9_400), 6);
        // No raw i2c.set_voltage on the energize/operating path once VoltageRail is wired.
        assert!(
            !stock.contains("i2c.set_voltage("),
            "stock_mining must not call i2c.set_voltage directly (use StockFpgaVoltageRail)"
        );
        // Panic hook + ordinary teardown must cut via VoltageRail safe_off, not raw enable_voltage(false).
        assert!(
            !stock.contains("enable_voltage(chain, false)")
                && !stock.contains("enable_voltage(chain_id, false)"),
            "stock_mining must not raw enable_voltage(..., false); use safe_off_voltage_rail"
        );

        let serial = std::fs::read_to_string(root.join("dcentrald/src/serial_mining.rs"))
            .expect("serial_mining");
        for needle in [
            "Pic0x89VoltageRail",
            "safe_off_voltage_rail",
            "apply_safety_action",
            "home_thermal_hard_stop_action",
        ] {
            assert!(
                serial.contains(needle),
                "serial_mining.rs must wire `{needle}`"
            );
        }

        let daemon = std::fs::read_to_string(root.join("dcentrald/src/daemon.rs")).expect("daemon");
        assert!(
            daemon.contains("pic16_mv_to_dac"),
            "daemon S9/PIC16 runtime path must use pic16_mv_to_dac SSOT"
        );
        // Forbid reintroducing the free-form PicController voltage_to_pic on the runtime path
        // without going through common SSOT (voltage_to_pic itself now wraps SSOT).
        assert!(
            !daemon.contains("PicController::voltage_to_pic"),
            "daemon must not call PicController::voltage_to_pic directly (use pic16_mv_to_dac)"
        );
    }
}
