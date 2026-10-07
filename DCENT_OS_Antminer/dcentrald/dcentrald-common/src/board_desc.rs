//! BoardDesc — declarative composition identity for a control-board target (ADR-0011).
//!
//! # Purpose
//!
//! New hardware support should be **data + thin backends**, not a new
//! `*_mining.rs` product. This module defines the host-safe, HAL-free shape of
//! that data so packaging, toolbox, runtime admission, and the daemon can
//! share one registry.
//!
//! # Status (2026-07-11)
//!
//! Runtime adoption is deliberately narrow. The standard daemon binds an exact
//! registry row to its immutable platform-identity snapshot and uses typed
//! [`BoardFamily`] to reject a declared/observed control-board contradiction
//! before serialized-I2C construction. Main runtime dispatch also admits exact
//! transport/work-engine pairs before constructing a mining arm. The declared
//! ASIC protocol is an admission constraint, not measured-silicon evidence:
//! mutation-capable engines must bind it to configured or observed identity.
//! Remaining fields are migration scaffolding and do not select hashboard, PSU,
//! cooling, network, or complete-miner behavior.
//!
//! # Facets (see `docs/architecture/COMPOSITION_MODEL.md`)
//!
//! `BoardDesc` names a packaged target-composition row. ASIC identity,
//! hashboard SKU, PSU, and cooling are still detected or profiled separately
//! and bound at bring-up time; a target's protocol declaration only narrows
//! what a runtime is permitted to attempt.

#![allow(dead_code)] // Scaffold: fields/enums reserved for migration consumers.

use crate::ReleaseChannel;
use crate::cooling_medium::{
    canonical_cut_ladder, validate_cut_ladder, CoolingMedium, CutLadderError, CutRung,
    CANONICAL_FORCED_AIR_LADDER,
};
use dcent_schema::hardware::{
    ArtifactKind, ArtifactMaturity, ExternalMediaMaturity, ExternalMediaMode, GenericConstruction,
    HardwareEnablementPolicy, ImplementationMaturity, InstallAuthorization, LifecycleLane,
    RecoveryMaturity, RuntimeStatus, StorageTopology, UpdateMechanism,
};

/// Thermal-supervisor **lane** identity for a registered target.
///
/// # Why this is a declared registry facet and not a string prefix
///
/// Round-15 A9 finding F-8: `dcentrald-thermal`'s
/// `SupervisorPlatform::from_board_target` classifies by
/// `m.starts_with("am1") || m.contains("s9")`, so **every** `am1-*` row —
/// including the capture-first rows Rounds 14/15 registered (`am1-s9i`,
/// `am1-s9j`, `am1-s11`, `am1-s15`, `am1-t15`, `am1-t9plus`) — silently
/// acquires the `Am1S9` classification of a live-validated S9. That is the
/// pattern the hardware-enablement constitution §1.4 forbids: *an unknown
/// board must not silently inherit another board's thermal envelope.* It grows
/// with every registered row, which is what these rounds do for a living.
///
/// # What a concrete variant means — and what it does NOT mean
///
/// A concrete variant names the thermal-supervisor **lane** whose live
/// validation would apply to this row. It is emphatically **not** an
/// energization or thermal envelope: `supervisor_default_enabled` in
/// `dcentrald-thermal` is still the sign-off gate and currently returns
/// `false` for every lane, validated flag or not.
///
/// A row earns a concrete lane **only** if `runtime_status.permits_mining_lane()`
/// — the existing single-source derivation in `dcent-schema` — is true for it.
/// A row that cannot mine cannot need a supervisor lane, so `CaptureFirst`,
/// `ManagementOnlyByPolicy` and `EvidenceRetainedNotImplemented` rows all take
/// [`Self::Unclassified`], the fail-closed value. This correspondence is
/// registry-derived (not a hand-enumerated target list — the Round-15 A8/A9
/// lesson one level up) and pinned by
/// `supervisor_class_is_never_inherited_by_a_non_executable_row`, so a newly
/// registered row cannot borrow a sibling SKU's lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupervisorClass {
    /// am1 — S9 (BM1387) Zynq lane.
    Am1S9,
    /// Exact C43 BM1393 lane; cooling custody is owned by its native runtime.
    Am1C43,
    /// Exact retained S15/T15 BM1391 runtime; no S9 cooling inheritance.
    Am1Bm1391,
    /// Exact T17e native BM1396 cooling custody; no hybrid inheritance.
    Am2Bm1396,
    /// am2 — Zynq S17/S19/S19j Pro hybrid lane (BM1398/BM1362).
    Am2Zynq,
    /// am3 — Amlogic A113D native-serial lane (NoPic).
    Am3Aml,
    /// am3 — BeagleBone Black AM335x serial lane.
    Am3Bb,
    /// **Fail-closed default.** No evidenced supervisor lane for this row.
    /// Capture-first, management-only and evidence-retained rows land here,
    /// as does any unknown `board_target` marker. Never default-on.
    Unclassified,
}

/// High-level SoC / carrier family (mirrors HAL `BoardType` names without
/// depending on `dcentrald-hal`, so Windows host tests stay clean).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoardFamily {
    /// Zynq-7000 am1/am2 class (S9, S17, S19, S19j Pro XIL).
    Zynq,
    /// TI AM335x BeagleBone class.
    BeagleBone,
    /// Amlogic A113D class.
    Amlogic,
    /// CVITEK CV183x class.
    Cvitek,
    /// STM32MP15 / BCB100 lab class.
    Stm32Mp15,
}

impl BoardFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zynq => "zynq",
            Self::BeagleBone => "beaglebone",
            Self::Amlogic => "amlogic",
            Self::Cvitek => "cvitek",
            Self::Stm32Mp15 => "stm32mp15",
        }
    }
}

/// How the daemon talks to the ASIC chain (transport facet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainTransportKind {
    /// Braiins-layout FPGA FIFO via UIO (`FpgaChain`).
    FpgaUio,
    /// AM2 hybrid: PL UART and/or FPGA work (recipe-selected).
    ZynqHybrid,
    /// Linux serial (`/dev/ttyS*` / `ttyO*`) NS16550-class.
    Serial,
    /// Stock-layout FPGA registers, including native retained `/dev/mem` C43 access.
    StockFpga,
    /// CVITEK `uart_trans` kernel helper.
    UartTrans,
    /// Management-only / no chain open.
    None,
}

impl ChainTransportKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FpgaUio => "fpga_uio",
            Self::ZynqHybrid => "zynq_hybrid",
            Self::Serial => "serial",
            Self::StockFpga => "stock_fpga",
            Self::UartTrans => "uart_trans",
            Self::None => "none",
        }
    }
}

/// Where mining work is pushed (work-engine facet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkEngineKind {
    FpgaWorkFifo,
    SerialWork,
    StockDma,
    /// API/dashboard only; hash boards not energized by this target default.
    ManagementOnly,
}

/// ASIC wire-protocol identity admitted by a composed board target.
///
/// This is the protocol family a mining engine is allowed to speak, not proof
/// that silicon was observed at runtime.  Mutation-capable constructors must
/// bind this declared identity to independently configured or discovered ASIC
/// evidence before they can open a chain.  Keeping it separate from transport
/// prevents a shared UART/FPGA carrier from accidentally authorizing a
/// different chip family's register map or work codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsicProtocolIdentity {
    Bm1387,
    /// S15 / T15 7nm silicon.
    ///
    /// The numeric mapping below is a *catalog* identity used by declarative
    /// registration and the acceptance matrix. It is deliberately NOT evidence
    /// that a chain reporting `0x1391` is trustworthy. Exact S15/T15 miners do
    /// compare register 0's high word with `0x1391`, while the sibling S11 jig
    /// provides no model-ID frame. The generic serial response parser still
    /// lacks a captured BM1391 core-count layout, so it refuses that identity
    /// rather than importing a different family's layout.
    Bm1391,
    /// S9 SE / S9k 7nm BM1393. Catalog + BoardDesc identity only.
    /// `ChipRegistry` must stay undriveable until `am1-s9se` has an
    /// executor. Stock speaks CRC5 VIL, not BM1387 HW-CRC (DCENT_OS#2).
    Bm1393,
    Bm1396,
    Bm1397,
    Bm1398,
    Bm1362,
    Bm1366,
    Bm1368,
    Bm1370,
    /// The target marker is insufficient; passive/runtime identity evidence
    /// must select the protocol before any ASIC mutation.
    RuntimeDiscovered,
}

/// Separately sourced vendor catalog identity. It may differ from, or agree
/// numerically with, the ASIC wire protocol admitted by
/// [`BoardDesc::asic_protocol`].
///
/// This is descriptive provenance only. It cannot be converted into an
/// [`AsicProtocolAdmission`] and therefore cannot authorize a chain command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsicCatalogIdentity {
    Bm1396,
}

impl AsicProtocolIdentity {
    /// Map the canonical numeric ChipID used by ASIC drivers and configuration
    /// into the protocol identity consumed by runtime admission.
    pub const fn from_chip_id(chip_id: u16) -> Option<Self> {
        match chip_id {
            0x1387 => Some(Self::Bm1387),
            0x1391 => Some(Self::Bm1391),
            0x1393 => Some(Self::Bm1393),
            0x1396 => Some(Self::Bm1396),
            0x1397 => Some(Self::Bm1397),
            0x1398 => Some(Self::Bm1398),
            0x1362 => Some(Self::Bm1362),
            0x1366 => Some(Self::Bm1366),
            0x1368 => Some(Self::Bm1368),
            0x1370 => Some(Self::Bm1370),
            _ => None,
        }
    }

    /// Reverse map for profile / nominal-hashrate lookup (P2-9 composition).
    ///
    /// [`Self::RuntimeDiscovered`] has no single ChipID — returns `None` so
    /// callers must use measured silicon identity instead of guessing.
    pub const fn to_chip_id(self) -> Option<u16> {
        match self {
            Self::Bm1387 => Some(0x1387),
            Self::Bm1391 => Some(0x1391),
            Self::Bm1393 => Some(0x1393),
            Self::Bm1396 => Some(0x1396),
            Self::Bm1397 => Some(0x1397),
            Self::Bm1398 => Some(0x1398),
            Self::Bm1362 => Some(0x1362),
            Self::Bm1366 => Some(0x1366),
            Self::Bm1368 => Some(0x1368),
            Self::Bm1370 => Some(0x1370),
            Self::RuntimeDiscovered => None,
        }
    }

    /// Parse the canonical `BMxxxx` label used by configuration and hardware
    /// identity snapshots. Unknown labels remain unknown instead of being
    /// coerced to a nearby protocol family.
    pub fn from_chip_label(label: &str) -> Option<Self> {
        match label.trim().to_ascii_uppercase().as_str() {
            "BM1387" => Some(Self::Bm1387),
            "BM1391" => Some(Self::Bm1391),
            "BM1393" => Some(Self::Bm1393),
            "BM1396" => Some(Self::Bm1396),
            "BM1397" => Some(Self::Bm1397),
            "BM1398" => Some(Self::Bm1398),
            "BM1362" => Some(Self::Bm1362),
            "BM1366" => Some(Self::Bm1366),
            "BM1368" => Some(Self::Bm1368),
            "BM1370" => Some(Self::Bm1370),
            _ => None,
        }
    }
}

/// Proof that a board composition and independent runtime identity evidence
/// agree on one exact ASIC protocol.
///
/// The field is private so mutation-capable engines cannot mint the proof from
/// an enum literal.  Proofs are created only by [`BoardDesc::admit_asic_protocol`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsicProtocolAdmission {
    identity: AsicProtocolIdentity,
}

impl AsicProtocolAdmission {
    pub const fn identity(self) -> AsicProtocolIdentity {
        self.identity
    }
}

/// Voltage-controller class (power facet; protocol details live in asic crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoltageControllerClass {
    Pic16F1704,
    DsPic33Ep,
    /// Exact S17e/T17e BM1396 framed application ABI. Physical silicon is
    /// model-specific (S17e dsPIC33EP16GS202; T17e PIC16F1704) and is recorded
    /// separately in `bm1396_pic`; a part name never selects a legacy adapter.
    Bm1396FramedI2c11,
    /// Classic AML fw89 application ABI plus the retained shared APW12 owner.
    /// This informational class cannot construct a legacy PIC voltage adapter.
    ClassicAmlApplication89,
    /// Exact BM1391 application protocol; this is not an MCU silicon claim.
    Bm1391Application,
    Pic1704,
    /// Exact operating profile controls voltage without a hashboard MCU.
    /// This does not prove that an optional factory-programming PIC is absent.
    NoPic,
    /// The control-board target alone cannot select a controller protocol.
    /// Runtime subtype/topology discovery must refine this before mutation.
    RuntimeDiscovered,
}

/// Legacy combined slot/update policy.
///
/// New authorization or update decisions MUST use [`BoardDesc::enablement`].
/// This enum remains temporarily for runtime-dispatch compatibility while
/// those call sites migrate; notably, `LabGated` is not a storage topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotPolicy {
    /// Dual-copy U-Boot env + inactive rootfs (classic Zynq DCENT sysupgrade).
    ZynqAbFwSetenv,
    /// Single eMMC/NAND slot — no A/B fallback (e.g. some CV paths).
    SingleSlot,
    /// SD-first / no trusted env map (BB empty fw_env).
    SdOnly,
    /// Lab / undocumented — refuse product install without override.
    LabGated,
}

const AM1_S9_PUBLIC_UPDATE_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::RedundantSlots,
    update_mechanism: UpdateMechanism::ZynqUbiFwSetenv,
    update_maturity: ImplementationMaturity::Experimental,
    install_authorization: InstallAuthorization::PublicBeta,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::SysupgradeBundle,
    artifact_maturity: ArtifactMaturity::Experimental,
    external_media_mode: ExternalMediaMode::BootOnly,
    external_media_maturity: ExternalMediaMaturity::BootWitnessed,
    external_media_authorization: InstallAuthorization::PublicBeta,
};

/// AM2 has a host-generated, identity-stamped SD boot artifact, but its
/// physical cold boot remains a lab witness item. Keep its removable-media
/// authority independent from the broader already-running-target update lane.
const AM2_PUBLIC_UPDATE_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::RedundantSlots,
    update_mechanism: UpdateMechanism::ZynqUbiFwSetenv,
    update_maturity: ImplementationMaturity::Experimental,
    install_authorization: InstallAuthorization::PublicBeta,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::SysupgradeBundle,
    artifact_maturity: ArtifactMaturity::Experimental,
    external_media_mode: ExternalMediaMode::BootOnly,
    external_media_maturity: ExternalMediaMaturity::ArtifactGenerated,
    external_media_authorization: InstallAuthorization::LabOnly,
};

const ZYNQ_LAB_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::RedundantSlots,
    update_mechanism: UpdateMechanism::ZynqUbiFwSetenv,
    update_maturity: ImplementationMaturity::Experimental,
    install_authorization: InstallAuthorization::LabOnly,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::SysupgradeBundle,
    artifact_maturity: ArtifactMaturity::Experimental,
    external_media_mode: ExternalMediaMode::BootOnly,
    external_media_maturity: ExternalMediaMaturity::ArtifactGenerated,
    external_media_authorization: InstallAuthorization::LabOnly,
};

/// A host-buildable Zynq package with no admitted target-side update or
/// first-install workflow. This keeps artifact evidence distinct from writer
/// authority for boards such as S17/S17 Pro.
const ZYNQ_PACKAGE_ONLY_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::RedundantSlots,
    update_mechanism: UpdateMechanism::ZynqUbiFwSetenv,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::Denied,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::SysupgradeBundle,
    artifact_maturity: ArtifactMaturity::Experimental,
    external_media_mode: ExternalMediaMode::None,
    external_media_maturity: ExternalMediaMaturity::NotImplemented,
    external_media_authorization: InstallAuthorization::Denied,
};

/// Exact S17-family cards were constructed with their current native runtime,
/// stamped geometry and complete two-partition boot chain on 2026-09-07.
/// This media facet does not grant first-install or onboard-update authority.
const S17_NATIVE_MEDIA_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    external_media_mode: ExternalMediaMode::BootOnly,
    external_media_maturity: ExternalMediaMaturity::ArtifactGenerated,
    external_media_authorization: InstallAuthorization::LabOnly,
    ..ZYNQ_PACKAGE_ONLY_ENABLEMENT
};

/// Exact C43 S9 SE/S9k cards were built and inspected with the current native
/// ARM binaries. Root/data filesystem checks, all boot payloads and both
/// Toolbox host readers passed. Physical boot remains a tester qualification.
const C43_NATIVE_MEDIA_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    external_media_mode: ExternalMediaMode::BootOnly,
    external_media_maturity: ExternalMediaMaturity::ArtifactGenerated,
    external_media_authorization: InstallAuthorization::LabOnly,
    ..ZYNQ_PACKAGE_ONLY_ENABLEMENT
};

const ZYNQ_RUNTIME_ONLY_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::RedundantSlots,
    update_mechanism: UpdateMechanism::ZynqUbiFwSetenv,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::Denied,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::None,
    artifact_maturity: ArtifactMaturity::NotImplemented,
    external_media_mode: ExternalMediaMode::None,
    external_media_maturity: ExternalMediaMaturity::NotImplemented,
    external_media_authorization: InstallAuthorization::Denied,
};

/// Both exact BM1391 cards were built from snapshot15 ARM binaries and their
/// actual boot/root filesystems passed the independent Toolbox reader. This
/// records host artifact generation only; physical boot remains unwitnessed.
/// The removable-media facet carries its own LabOnly authority. There is no
/// primary onboard package, persistent API updater or NAND installation lane.
const BM1391_NATIVE_MEDIA_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::ExternalMediaOnly,
    update_mechanism: UpdateMechanism::SdImage,
    external_media_mode: ExternalMediaMode::BootOnly,
    external_media_maturity: ExternalMediaMaturity::ArtifactGenerated,
    external_media_authorization: InstallAuthorization::LabOnly,
    ..ZYNQ_RUNTIME_ONLY_ENABLEMENT
};

/// Exact T17e FAT/ext2/ext4 cards are built from a current signed ARM runtime
/// and independently decoded by Toolbox. This is host artifact generation;
/// physical boot and quiet-profile airflow remain bench qualification.
const BM1396_NATIVE_MEDIA_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::ExternalMediaOnly,
    update_mechanism: UpdateMechanism::SdImage,
    external_media_mode: ExternalMediaMode::BootOnly,
    external_media_maturity: ExternalMediaMaturity::ArtifactGenerated,
    external_media_authorization: InstallAuthorization::LabOnly,
    ..ZYNQ_RUNTIME_ONLY_ENABLEMENT
};

/// Exact S9i/S9j removable boot artifacts are host-buildable and can be
/// written by Toolbox's guarded raw-media writer. Cold boot remains
/// unwitnessed, so this is LabOnly/Experimental and grants no NAND mutation.
const AM1_LEGACY_EXPERIMENTAL_MEDIA_ENABLEMENT: HardwareEnablementPolicy =
    HardwareEnablementPolicy {
        storage_topology: StorageTopology::RedundantSlots,
        update_mechanism: UpdateMechanism::ZynqUbiFwSetenv,
        update_maturity: ImplementationMaturity::NotImplemented,
        install_authorization: InstallAuthorization::Denied,
        recovery_maturity: RecoveryMaturity::EvidenceOnly,
        artifact_kind: ArtifactKind::None,
        artifact_maturity: ArtifactMaturity::NotImplemented,
        external_media_mode: ExternalMediaMode::BootOnly,
        external_media_maturity: ExternalMediaMaturity::ArtifactGenerated,
        external_media_authorization: InstallAuthorization::LabOnly,
    };

const AMLOGIC_LAB_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::SingleSlot,
    update_mechanism: UpdateMechanism::HostRootfsWindow,
    update_maturity: ImplementationMaturity::Experimental,
    install_authorization: InstallAuthorization::LabOnly,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::SysupgradeBundle,
    artifact_maturity: ArtifactMaturity::Experimental,
    external_media_mode: ExternalMediaMode::None,
    external_media_maturity: ExternalMediaMaturity::NotImplemented,
    external_media_authorization: InstallAuthorization::Denied,
};

const AMLOGIC_RUNTIME_ONLY_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::SingleSlot,
    update_mechanism: UpdateMechanism::HostRootfsWindow,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::Denied,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::None,
    artifact_maturity: ArtifactMaturity::NotImplemented,
    external_media_mode: ExternalMediaMode::None,
    external_media_maturity: ExternalMediaMaturity::NotImplemented,
    external_media_authorization: InstallAuthorization::Denied,
};

/// A host-buildable A113D artifact with no hardware-install authority.
///
/// Held vendor firmware binds product identity and the shared runtime ABI, but
/// does not constitute a live witness for a DCENT_OS rootfs-window install.
const AMLOGIC_PACKAGE_ONLY_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::Unknown,
    update_mechanism: UpdateMechanism::None,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::Denied,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::SysupgradeBundle,
    artifact_maturity: ArtifactMaturity::Experimental,
    external_media_mode: ExternalMediaMode::None,
    external_media_maturity: ExternalMediaMaturity::NotImplemented,
    external_media_authorization: InstallAuthorization::Denied,
};

/// S19k has a signed, dependency-bound host rootfs-window package lane. The
/// implementation remains experimental and LabOnly: actual backup/recovery
/// evidence and explicit operator authority stay outside this source policy.
const AMLOGIC_S19K_GUARDED_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::SingleSlot,
    update_mechanism: UpdateMechanism::HostRootfsWindow,
    update_maturity: ImplementationMaturity::Experimental,
    install_authorization: InstallAuthorization::LabOnly,
    recovery_maturity: RecoveryMaturity::EvidenceOnly,
    artifact_kind: ArtifactKind::SysupgradeBundle,
    artifact_maturity: ArtifactMaturity::Experimental,
    external_media_mode: ExternalMediaMode::None,
    external_media_maturity: ExternalMediaMaturity::NotImplemented,
    external_media_authorization: InstallAuthorization::Denied,
};

const BEAGLEBONE_SD_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::ExternalMediaOnly,
    update_mechanism: UpdateMechanism::SdImage,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::LabOnly,
    recovery_maturity: RecoveryMaturity::EvidenceOnly,
    artifact_kind: ArtifactKind::SdCardPayload,
    artifact_maturity: ArtifactMaturity::Experimental,
    external_media_mode: ExternalMediaMode::BootOnly,
    // Exact S19j Pro BB v1.2.6 boot.bin/uEnv/uImage/DTB artifacts are held and
    // hash-pinned. Clean-room analysis proves that this exact boot.bin patches
    // the resident RSA verifier to success before boot dispatch, and Toolbox
    // validates a target-bound fresh image manifest. Cold boot remains
    // unwitnessed, so removable-media authority is Experimental/lab-only.
    external_media_maturity: ExternalMediaMaturity::MediaWritten,
    external_media_authorization: InstallAuthorization::LabOnly,
};

const BEAGLEBONE_GENERIC_EVIDENCE_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::ExternalMediaOnly,
    update_mechanism: UpdateMechanism::SdImage,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::LabOnly,
    recovery_maturity: RecoveryMaturity::EvidenceOnly,
    artifact_kind: ArtifactKind::SdCardPayload,
    artifact_maturity: ArtifactMaturity::Experimental,
    external_media_mode: ExternalMediaMode::BootOnly,
    external_media_maturity: ExternalMediaMaturity::MediaWritten,
    // The exact S19j Pro carrier is the only admitted BB writer target.
    external_media_authorization: InstallAuthorization::Denied,
};

const CV1835_EVIDENCE_ONLY_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::SingleSlot,
    update_mechanism: UpdateMechanism::EmmcContentSelectorEvidenceOnly,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::Denied,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::None,
    artifact_maturity: ArtifactMaturity::NotImplemented,
    external_media_mode: ExternalMediaMode::None,
    external_media_maturity: ExternalMediaMaturity::NotImplemented,
    external_media_authorization: InstallAuthorization::Denied,
};

/// STM32MP15 / BCB100: every facet refuses, and `storage_topology` is
/// explicitly `Unknown` rather than borrowed from a sibling family.
///
/// The BCB100 carrier is documented as eMMC + microSD boot
/// (`dcentrald-hal/src/platform/stm32mp15.rs:5`), but no bench probe has ever
/// captured its partition map, so we may not claim `SingleSlot` (which would
/// assert we know where a writer would land) nor `ExternalMediaOnly` (which
/// would assert SD is the only surface). `UpdateMechanism::None` is the
/// matching honest value: unlike CVitek there is not even a passive boot
/// selector we have read.
const STM32MP15_UNVERIFIED_ENABLEMENT: HardwareEnablementPolicy = HardwareEnablementPolicy {
    storage_topology: StorageTopology::Unknown,
    update_mechanism: UpdateMechanism::None,
    update_maturity: ImplementationMaturity::NotImplemented,
    install_authorization: InstallAuthorization::Denied,
    recovery_maturity: RecoveryMaturity::NotImplemented,
    artifact_kind: ArtifactKind::None,
    artifact_maturity: ArtifactMaturity::NotImplemented,
    external_media_mode: ExternalMediaMode::None,
    external_media_maturity: ExternalMediaMaturity::NotImplemented,
    external_media_authorization: InstallAuthorization::Denied,
};

/// Retained CV1835 reverse-engineering evidence backing the deliberate
/// `EvidenceRetainedNotImplemented` refusal on `cv1835-s19jpro`
/// after removal of the incomplete runtime. Held ABI fixtures remain test-only.
/// Paths are relative to `DCENT_OS_Antminer/dcentrald/` and existence-checked
/// by `cv1835_retained_evidence_paths_exist_on_disk`.
const CV1835_RETAINED_EVIDENCE: &[&str] = &[
    "dcentrald-hal/src/platform/cvitek_stock_evidence.rs",
    "dcentrald-hal/src/platform/cv1835_retirement.rs",
];

/// The am1 S11 datums that remain UNCONFIRMED from held bytes (Round 15).
///
/// Unlike S15/T15, the S11's **ASIC identity itself** is unconfirmed. Its only
/// official stock image (`Antminer-S11-all-user-201908011639-sig.tar.gz`,
/// `usr/bin/compile_time` = `Antminer S11` / `V2.1.25`) is a factory
/// hashboard-test firmware whose `cgminer.sh` launches `single-board-test`,
/// and whose production `bmminer` is the S9-family `driver-btm-c5.c` build
/// (`is_S11()` and `is_S9_plus()` both `return 1`) containing **zero** BM139x
/// strings. Its jig `Config.ini` says `AsicType=1387 / AsicNum=63 /
/// CoreNum=114`, but is titled `Name=S9 HASH board`. A BM1391 `cgminer` ships
/// in one of the two payloads and is never started.
///
/// So both candidate identities are refused. Full byte-level adjudication:
/// `dcentrald-silicon-profiles/src/bm1391_stock_fw.rs`.
///
/// **Byte-traceable (why `BoardFamily::Zynq` is not a family guess):** the
/// package carries two `devicetree.dtb` files, both `xlnx,zynq-7000`, and both
/// md5-identical to device trees already in
///
/// (`42edf047` for the `7007` carrier, `2a08498e` for the `XILINX` carrier).
const AM1_S11_UNCONFIRMED_DATUMS: &[&str] = &[
    "ASIC identity (stock bmminer is BM1387-lineage; an unused BM1391 cgminer also ships)",
    "chips per chain (the only count in the image is titled 'S9 HASH board')",
    "which of the two shipped carriers (7007 / XILINX) a given unit uses",
    "control-board GPIO map",
    "chain UART transport bases",
    "cold-boot sequence",
];

/// The am1 T9+ control-board datums that remain UNCONFIRMED from held bytes.
///
/// Unlike the S15/T15 class, the T9+ *carrier* is confirmed: the held stock
/// firmware `Antminer-T9plus-awesome-3.9.tar.gz` ships a `xilinx/` payload whose
/// `devicetree.dtb` declares `compatible = "xlnx,zynq-7000"` with a `ps7-nand`
/// controller — so `BoardFamily::Zynq` is byte-traceable, not inferred. What is
/// NOT traceable is the per-chain topology and the chip identity (below).
const AM1_T9PLUS_UNCONFIRMED_DATUMS: &[&str] = &[
    // CHIP COUNT AND CHIP IDENTITY ARE NO LONGER LISTED HERE — both are settled
    // byte-exactly by Bitmain's own factory jig config (see the descriptor doc).
    // NOTE: chain topology is no longer listed here either — it is byte-stated
    // by the T9+'s own miner binary (see the descriptor doc). Only the
    // control-board facts below remain genuinely unknown.
    // Stock T9+ NAND is a THREE-partition layout
    // (`BOOT.bin-env-dts-kernel` / `angstram-rootfs` / `upgrade-rootfs`).
    // CORRECTION (device-tree census of all 36 held Antminer stock images):
    // that observation does NOT distinguish T9+ from S9 — real S9 stock mining
    // firmware declares the byte-identical 3-partition map, and the T9+ and S9
    // device trees fall in the same equivalence class. The A/B
    // `firmware1`/`firmware2` pair `ZynqAbFwSetenv` assumes is what DCENT_OS /
    // BraiinsOS *create at install*, not the Bitmain stock layout. So the slot
    // policy still cannot be copied from `am1_s9` — but because no T9+ has been
    // contacted and the GPIO map is unknown, NOT because the stock map differs.
    "NAND slot layout (stock 3-partition map is shared with stock S9)",
    "control-board GPIO map",
];

/// S9 SE Ctrl_C43 live/firmware-settled vs still capture-first.
///
/// Settled on the desk: BM1393 CRC5 VIL, FPGA AXI map, 208 cores, PWM-dead
/// `0x84`/`0x04`, 3×60 last-addr `0x78` (issue #2), C43 / XC7Z007S, 256 MiB,
/// and the exact S9 SE ramdisk's 256-MiB `fpga_mem` base `0x0F000000`.
/// Not settled: live GetAddress body, dsPIC IIC adapter vs AM2 framed warmup,
/// and an install-safe NAND slot contract.
///
/// Lane B re-verification 2026-09-01 (held bytes, fresh grep counts): the
/// controller FAMILY is settled — held S9k `cgminer` carries 26x
/// `dsPIC33EP16GS202` / 0x `PIC16F1704`, the `S9SES9KTestJig` `bmminer`
/// 18x / 0x, and neither binary contains a single `bm1391` marker (19x /
/// 23x `bm1393`). The open datum below is the LIVE adapter ABI on the C43
/// carrier, not the controller family. :24`'s old
/// "BM1391 / 63 chips / 3x PIC16F1704" row was falsified by these bytes
/// and corrected the same session.
const AM1_S9SE_UNCONFIRMED_DATUMS: &[&str] = &[
    "live GetAddress response body (firmware is 1393; #2 pasted BC word0 only)",
    "dsPIC33EP16GS202 IIC adapter ABI vs AM2 framed warmup (do not copy)",
    "NAND slot layout / first-install capsule (management-only until captured)",
];

/// S9k carrier/safety facts that the recovered BM1393 miner does not settle.
///
/// The held S9k `cgminer` is valuable exact evidence for the BM1393 codec,
/// 60-response population and address interval, but it is not authority to
/// reuse the S9 SE's C43 carrier or any S9-family power/install contract.
///
/// 2026-09-01 (Lane B): the voltage-controller FAMILY is positively resolved
/// to dsPIC33EP16GS202 from the held S9k `cgminer` itself (26x marker
/// strings, 0x `PIC16F1704`) — the third datum below is therefore the live
/// read + energize/electrical contract, no longer the family question.
const AM1_S9K_UNCONFIRMED_DATUMS: &[&str] = &[
    "exact production control-board revision and resident device tree",
    "chain carrier/UART route and reset GPIO map",
    "voltage-controller live read + energize/PSU electrical contract (family \
     positively resolved to dsPIC33EP16GS202, NOT PIC16F1704, from the held \
     S9k cgminer)",
    "cooling custody and independent power cutoff",
    "NAND slot layout / recoverable first-install transaction",
];

/// S17-family controller evidence and the Round-15 string-inventory correction.
///
/// Historical method: each `Antminer-<model>-user-OM-*-sig_*.tar.gz` → `fw.tar.gz` →
/// `uramdisk.image.gz` (64-byte uImage header + gzip + ext2) → `debugfs rdump`.
/// The following `rg -a --no-ignore` counts were confirmed over both extracted
/// roots and raw ext2 images. They are retained as a reproducible software
/// inventory, **not** as physical-part evidence:
///
/// | model  | ant_version | hashboard | jig `PIC16F1704` | jig `dsPIC33EP16GS202` |
/// |--------|-------------|-----------|------------------|------------------------|
/// | S17    | 5835        | BHB07601  | 20               | 12                     |
/// | S17Pro | 5837        | BHB07601  | 20               | 12                     |
/// | S17+   | 5968        | BHB07602  | **0**            | 1                      |
/// | S17e   | 5818        | BHB16601  | **0**            | 1                      |
/// | T17    | 5828        | (no jig)  | n/a              | n/a                    |
/// | T17+   | 5967        | BHB07702  | **0**            | 1                      |
/// | T17e   | 5820        | BHB16701  | **0**            | 1                      |
///
/// All seven `usr/bin/bmminer` binaries are per-model distinct (7 distinct
/// md5s) and every one hardcodes `/etc/config/dsPIC33EP16GS202_app.txt` while
/// containing **zero** `PIC16F1704` symbols.
///
/// Round 15 incorrectly promoted that negative string result into a silicon
/// claim. Exact model-co-bundled MCU payloads falsify the inference: the AMTC
/// `T17e Testing Files` folder pairs `SD_T17e.zip` with `T17ePIC.hex` SHA-256
/// `ea101608283f6b9175fa5e6fdf205859957a92fa4c4a623979ab2cfee85f885d`.
/// That 464-line Intel HEX image is byte-identical to `S17+PIC.hex` and
/// `T17+PIC.hex`, occupies PIC16 program range `0x0000..0x1eff`, and encodes
/// config words `0x3f94` / `0x1ffe`. The T17e maintenance schematic
/// independently labels U3 `PIC16F1704-I/SL`.
///
/// The exact sibling AMTC `S17eTesting Files` folder pairs `SD-S17e.zip` with
/// `S17ePIC.hex` SHA-256
/// `bde15c70845d6e82d1e54926ea04076f87b91282b82ca5e06172cc3c1a1af713`.
/// That 1,462-line 24-bit image is byte-identical to `S17PIC.hex` and reaches
/// the dsPIC configuration area through `0x5763`. Therefore the BM1396 physical
/// split is S17e dsPIC33EP16GS202 versus T17e PIC16F1704. The profile route
/// discriminator is independently correlated only after this proof; it is not
/// the source of part identity.
///
/// Ghidra explains why the common filename is misleading: the bundled updater
/// consumes six hexadecimal digits per 24-bit instruction into a fixed
/// `0x3700`-byte buffer and cannot consume the T17e PIC16 Intel HEX payload.
/// The recovered BM1396 framed host ABI remains common across the two physical
/// parts. Physical identity grants no voltage envelope, carrier, mutation, or
/// installation authority.
const S17_FAMILY_STOCK_CONTROLLER_EVIDENCE: &str =
    "Bitmain S17-family bmminer/jig binaries carry a common dsPIC updater filename, but \
     that string is not physical-part evidence. Exact co-bundled AMTC MCU payloads split \
     the family: S17ePIC.hex is dsPIC33EP16GS202, while T17ePIC.hex is PIC16F1704; \
     application ABI and populated silicon must be recorded independently";

/// S17-family chip identity, settled from the `AsicType` **numeric literal**
/// each model's factory jig build requires its factory `Config.ini` to declare.
/// Round 15, A8; **provenance corrected Round 16, B2** (§"What the literal
/// actually is" below) — it is a vendor build-time configuration contract, not
/// a silicon readback.
///
/// A2 (Round 15) reported that the *string* `BM1396` occurs zero times in all
/// seven official S17-family images and correctly declined to flip the identity
/// on that negative. That negative is **non-discriminating**, and this is the
/// key methodological point: the S17+ and T17+ jigs — whose BM1397 identity is
/// not in dispute — **also** contain zero occurrences of their own chip name,
/// and no `bmminer` in the corpus contains any anchored `BM13[0-9]{2}` string at
/// all. Chip identity in these binaries is carried **only** as a 16-bit numeric
/// literal, so a string sweep is structurally incapable of finding it.
///
/// The decisive artifact is the `expect` operand of
/// `"error AsicType: 0x%x, expect 0x%x"` — a build-time literal the vendor's own
/// factory test compares against the `Asic_Type` its factory config declares
/// (⚠️ **not** the chip's self-reported type; see §"What the literal actually
/// is"). Recovered by ARM
/// disassembly (`arm-linux-gnueabihf-objdump`); all vaddrs below (file offset +
/// 0x8000 for every one of these ELFs):
///
/// | model  | jig md5 (prefix) | `cmp` site | `expect` |
/// |--------|------------------|------------|----------|
/// | S17    | `0a657f6a` | `0xd9ec`  `ldr r2,[r6,#116]` / `movw r3,#0x1397` | **0x1397** |
/// | S17+   | `cb408bec` | `0x453cc` `movw r6,#0x1397` / `cmp r3,r6`        | **0x1397** |
/// | T17+   | `e2a41da1` | `0x44f98` `movw r3,#0x1397` / `cmp r2,r3`        | **0x1397** |
/// | S17e   | `5324d7ec` | `0x10ba8` `movw r2,#0x1396` / `cmp r1,r2`        | **0x1396** |
/// | T17e   | `b11a5c03` | `0x113e8` `movw r2,#0x1396` / `cmp r1,r2`        | **0x1396** |
///
/// The S17+ jig also passes the literal explicitly as the printf `expect`
/// vararg (`0x45470  movw ip,#0x1397` → `stmib sp,{r1,ip}`), as do the S17e
/// (`0x10c68  movw r3,#0x1396` → `str r3,[sp,#16]`) and T17e (`0x114a8`) jigs —
/// so the constant is calibrated by three models whose identity is settled and
/// is read the same way in the two under question.
///
/// Occurrence counts of the `movw` immediate across each whole jig partition
/// perfectly: S17 `0x1397`×3 / `0x1396`×0 · S17+ ×6/×0 · T17+ ×5/×0 · S17e
/// ×0/×10 · T17e ×0/×10. The same partition repeats independently in the seven
/// `bmminer` runtime binaries.
///
/// This establishes a vendor *catalog/configuration* identity. A later pass
/// over the exact model-specific production `bmminer` binaries independently
/// established the matching chain register identity; the byte-identical
/// `cgminer` files remain only the smaller command/API process.
///
/// # What the literal actually is (Round 16, B2 — provenance audit)
///
/// B2 re-extracted the S17e jig independently (same md5 `5324d7ec…`, so A8's
/// extraction reproduces) and read the code around `0x10ba8` rather than the
/// instruction alone. The comparison is **`check_config()` in `config.c:265`**
/// (both names are recoverable: `"check_config"` is the `%s` function-name arg
/// and `"config.c"` the file arg of that very format string).
///
/// The "actual" operand is **not** a silicon readback. The jig `readdir()`s
/// `/mnt/card/`, keeps entries matching `*Config*` **and** `*.ini*`, loads each
/// with **iniparser**, and stores the result into an array of two ~`0x9d4`-byte
/// config structs at `sp+0x140` and `sp+0xb14`. `Config:Asic_Num` lands at
/// struct `+0x10` and **`Config:Asic_Type` at struct `+0x14`** — so `sp+0xb24`
/// and `sp+0xb28` are `cfg[1].Asic_Num` and `cfg[1].Asic_Type`, exactly the two
/// slots compared against `#135` and `#0x1396`.
///
/// Every one of the ten `movw #0x1396` sites in the jig (and the ten in the
/// S17e `bmminer`) partitions into three non-silicon classes: the
/// `check_config` comparison + its two `printf` `expect` args; three
/// `fixture_header` checks against the header of the vendor pattern file
/// `/mnt/card/16601_pattern_135.bin` (proved by the sibling
/// `"Fixture header check fail, fixture_header = 0x%x"` site reading the same
/// `[r4]`); and build-time record constants that store `0x1396` next to `135`.
/// **No site reads the chain/UART.** Two of twenty sites were not fully
/// resolved; neither shows a chain read in context.
///
/// So the honest strength is: *Bitmain's own per-model factory-test build
/// requires this board's factory configuration to declare `Asic_Type` `0x1396`,
/// where the same construct declares `0x1397` on three models whose BM1397
/// identity is not in dispute.* That is a **vendor build-time declaration**,
/// strong and model-specific, but a transcription rather than a measurement.
/// The conclusion from this jig site remains deliberately narrow: vendor
/// catalog/configuration identity BM1396. The independent production-binary
/// wire evidence is recorded in [`S17E_T17E_SIGNED_USERSPACE_EVIDENCE`].
///
/// Corollary the coordinator should note: the adjacent `Asic_Num` `#135`
/// literal has **exactly the same epistemic status** as the `Asic_Type` literal
/// — same function, same config struct, adjacent instructions. A8 refused the
/// first and promoted the second on identical evidence. The refusal is the
/// correct posture; it is applied inconsistently, not wrongly.
///
/// This site alone settles only the vendor build/configuration label. It
/// authorizes no voltage envelope, chain transport, or runtime path.
const S17E_T17E_JIG_ASIC_TYPE_EVIDENCE: &str =
    "Bitmain signed S17e/T17e stock factory jigs (usr/bin/single-board-test, md5 \
     5324d7ec1701743c88afaf8533766a29 / b11a5c03935207343859f66dbba42f26): check_config() \
     (config.c:265) requires the factory Config.ini key Config:Asic_Type to equal the \
     build-time literal 0x1396 (S17e vaddr 0x10ba8, T17e vaddr 0x113e8), calibrated \
     against 0x1397 in the S17/S17+/T17+ jigs. Vendor build-time configuration contract, \
     NOT a silicon readback (Round 16 B2 provenance audit)";

/// Exact signed-stock userspace pins and their deliberately bounded meaning.
///
/// Both exact signed roots contain the same small `cgminer` command/API process
/// (`libcmd_trans_a.so.0` client), while their model-specific `bmminer` binaries
/// own `/dev/axi_fpga_dev` and `/dev/fpga_mem`. Static disassembly of those
/// exact production binaries proves the wire ChipID, command codec, and
/// per-present-chain enumeration count. It does not prove a DCENT carrier or
/// electrical safety composition.
const S17E_T17E_SIGNED_USERSPACE_EVIDENCE: &str = "Bitmain signed S17e/T17e roots: shared \
     usr/bin/cgminer size 283195 sha256 \
     68df4a7e393f467a645a4e50a3cf79fa1cf2a04b5c7f00c0576dc564a9199276; \
     S17e usr/bin/bmminer sha256 \
     819bd5ee790f3ce74f61a45546856e0cd7b37a62e7ec2263ebb83e35220c8243; \
     T17e usr/bin/bmminer sha256 \
     d0f14d843e35b15ffdf73d3523fa637ac318ade6c1a660764ceab5a48e135ffe; \
     S17e enum 0x82958 compares register-zero high16 to 0x1396 at 0x82a70 and count 135 \
     at 0x82ad4; T17e enum 0x83800 compares at 0x83918 and count 78 at 0x8397c; \
     CONFIRMED_MULTI_FIRMWARE wire identity and per-present-chain geometry";

/// This digest belongs to the 1,481,552-byte symbol-bearing corpus `cgminer`
/// copied identically under S17e/T17/T17e. Round-15 A2 identifies it as a
/// BM1391/S11-era binary. It is not present in either exact signed S17e/T17e
/// root and must never be admitted as model provenance.
const S17E_T17E_REJECTED_CGMINER_PROVENANCE_SHA256: &str =
    "9283110862c74a7546923915be3a3d639768b56bf769577a47908df704887b8b";

const S17E_T17E_SIGNED_USERSPACE_SHA256: &[&str] = &[
    "68df4a7e393f467a645a4e50a3cf79fa1cf2a04b5c7f00c0576dc564a9199276",
    "819bd5ee790f3ce74f61a45546856e0cd7b37a62e7ec2263ebb83e35220c8243",
    "d0f14d843e35b15ffdf73d3523fa637ac318ade6c1a660764ceab5a48e135ffe",
];

/// Physical qualification not established by the exact S17e/T17e source profiles.
///
/// The vendor build/configuration identity, hashboard code, and voltage-controller
/// family are NOT listed: all are byte-stated by each model's own signed image
/// (see [`S17E_T17E_JIG_ASIC_TYPE_EVIDENCE`],
/// [`S17E_T17E_SIGNED_USERSPACE_EVIDENCE`], and
/// [`S17_FAMILY_STOCK_CONTROLLER_EVIDENCE`]). The source-bound software needed
/// to energize silicon is checked independently on each native boot.
const AM2_S17E_CLASS_UNCONFIRMED_DATUMS: &[&str] = &[
    "physical per-chip core count / active-core performance validation",
    "physical FPGA carrier execution and selected operational-baud qualification",
    "physical control-board GPIO cutoff / reset / plug-detect qualification",
    "absolute/certified electrical envelope (the physical controller split and recovered framed ABI are known, but only the 1800-2100 cV vendor software clamp is statically bounded)",
    "physical quiet30 fan airflow, sensor attribution and thermal cutoff qualification",
    "install-slot / revert semantics for the byte-stated NAND partition map",
];

/// Antminer S19j-classic (BHB42701) datums that remain UNCONFIRMED from held
/// bytes (Gauntlet lane B5b, 2026-09-02).
///
/// Stock-settled and therefore NOT listed: ASIC identity (BM1362,
/// `asic_addr 0x1362`), per-chain geometry (108 = 12×9 placement grid exactly
/// populated, 36 voltage domains × 3, address interval 2, 65 big + 514 small
/// cores), PSU dialect (APW12 @ I²C `0x10`, power GPIO 907), hashboard EEPROM
/// (AT24C02D @ `0x50`), and LM75A sensor map (`0x48..=0x4b`) — all byte-stated
/// by the `BHB42701` entry of the 15-machine `config[]` topology DB inside
/// Bitmain's own S19j merge image
/// (
/// 02_Antminer_S19j_zynq7007/components/minerfs.image.gz.tree/etc/topol.conf`,
/// sha256 `61a6404b…0ffe8`, byte-identical in both zynq7007 records; see
/// `dcentrald-silicon-profiles::s19_family_stock_topol` for the transcription
/// and `PHASE_A_EVIDENCE_REPORT.md` §3.6 for the campaign adjudication).
///
/// What stays unconfirmed is everything a runtime would need beyond that
/// catalogue: no S19j-classic unit has EVER been contacted (unlike the S19j
/// Pro XIL `a lab unit`/`a lab unit` units that own the `am2-s19j` key), the stock
/// `chain_num: 4` counts connector slots rather than populated boards
/// (Phase A §1.3.5), and the stock `"PIC1704"` chain-MCU label is Bitmain's
/// name for the slot whose sibling-generation (BHB42601) populated part our
/// live probes identified as dsPIC33EP16GS202 — a label is not a
/// populated-part proof for this board.
const AM2_S19J_CLASSIC_UNCONFIRMED_DATUMS: &[&str] = &[
    "live unit: no S19j-classic has ever been contacted (chain enumeration / populated-slot count is capture-first; stock chain_num 4 is slot semantics)",
    "hashboard voltage controller live read + energize contract (stock labels the slot PIC1704 @ 0x20; sibling-generation BHB42601 live-proven dsPIC33EP16GS202 — label is not a populated-part proof)",
    "control-board GPIO map (reset / plug-detect / enable; stock topol states only PSU GPIO 907)",
    "which control-board platform a given unit carries (the merge image ships both BB and ZYNQ7007 records; this row types the zynq-class one)",
    "certified electrical envelope, fan PWM/tach mapping, and immutable independent thermal cutoff",
    "install-slot / revert semantics (no S19j-classic NAND map captured)",
];

/// BCB100 datums that no bench probe has captured.
///
/// Sourced from the HAL scaffold's own refusals, not from a family guess:
/// `stm32mp15.rs` `Bcb100Platform::open_fan` refuses fan control because the
/// PWM/tach map is not live-verified, `open_gpio` refuses GPIO control because
/// the reset/plug map is not live-verified, and the toolbox route notes the
/// exact-pilot posture holds "until a bench probe captures pic_address /
/// plug_detect_gpio / enable_gpio"
/// (`dcent-toolbox/src/dcent_toolbox/core/installer.py:2008-2011`).
///
/// 2026-08-12 evidence upgrade — these all remain UNCONFIRMED because the bar
/// here is a *bench probe*, and none has run. But several are no longer blind
/// guesses: Braiins' own `ii1-am2` device tree
///
/// supplies vendor-configured values for the chain UART mapping and the fan PWM
/// timer channels. A device tree states what the vendor's software drives, not
/// what the silicon does, so it raises confidence without discharging the probe.
/// Descriptions below record the current best value so nobody re-derives it.
const BCB100_UNCONFIRMED_DATUMS: &[&str] = &[
    "hashboard voltage controller address (pic_address)",
    "plug-detect GPIO map (net→pin known; active level schematic-derived active-HIGH via 4k7 pull-down, not measured)",
    "hashboard enable / reset GPIO map (net→pin known; reset active polarity NOT derivable from the hardware package)",
    "fan PWM period and tachometer map (PWM timer channels TIM1_CH4/TIM2_CH3 are DT-sourced; period and tach capture are not)",
    "chain UART device mapping (DT-sourced as ttySTM1..4 from Braiins' ii1-am2 aliases; not bench-captured)",
    "eMMC/microSD partition map and boot selector",
];

/// Antminer S9 Hydro datums that remain UNCONFIRMED from held bytes (R17-D,
/// 2026-09-11; campaign `2026-09-07-antminer-beta-execution`).
///
/// What the held bytes DO settle — and therefore is NOT listed: the
/// voltage-controller GENERATION and its framed wire laws. The production
/// `bmminer`
/// (
/// angstrom-rootfs/863220460/rootfs/usr/bin/bmminer`, 521,076 bytes, sha256
/// `81b89d0833cc5b368682b4ba1880b63f3b61ee992dc49f9402c9d4b0af92ac85`) is the
/// framed dsPIC33EP16GS202 "S9 plus plus" build: `is_S9_Hydro()=1` is a
/// compile-time predicate of that binary (`01 20 70 47` @0x3a3b1), the framed
/// handlers have production call chains (enable/heartbeat/disable/telemetry),
/// and the analog-voltage telemetry law is byte-exact. Transcription +
/// admission: `dcentrald-common::s9_plus_plus_pic_generation` (the R02 T9+
/// generation sibling of the bare-PIC16 S9/S9i/S9j builds). What a runtime
/// would still need is everything below — capture-first, never inferred from
/// the S9 or any sibling:
const AM1_S9_HYDRO_UNCONFIRMED_DATUMS: &[&str] = &[
    "ASIC identity string / wire ChipID (no BM1387 string occurs in the held production binary; the generation symbol names BM1387_54 and jig AsicType=1387 is corroborating only — the same jig text ships under the same 'S9 HASH board' title for the S11)",
    "chips per chain and chain population (jig AsicNum=63 corroborating only; capture-first enumeration)",
    "chain transport / carrier devicetree and reset GPIO map (no DTB analysis in R17; Zynq declared from the held S9-class angstrom rootfs class, not a DTB parse)",
    "numeric liquid-cooling minimum (the `s9_hydro_strong_liquid_cooling_min_pwm_percent` law string exists in the held binary; the value was never extracted)",
    "install / NAND slot layout (the angstrom rootfs is production-style, but no NAND layout analysis was performed)",
];

/// Antminer S19i (NBS2003) datums that remain UNCONFIRMED from held bytes
/// (R17-B, 2026-09-11).
///
/// Stock-settled and therefore NOT listed: machine identity `NBS2003`,
/// `asic_id "BM1360" @ 0x1360` (156 big + 624 small cores), FOUR chains x 80
/// chips (8x10 placement grid, 2 chips/domain, 40 domains/chain), address
/// interval 3, stock `PIC1704 @ 0x20` slot label, 4x LM75A @ iic 72..75,
/// `AT24C02D @ 0x50`, APW12-class PSU versions [66,67,113] @ i2c 0x10, GPIO
/// 907, ZYNQ7007 — all byte-stated by Bitmain's own `topol.conf` inside the
/// held signed production image
/// (
/// components/minerfs.image.gz.tree/etc/topol.conf`, 624 lines, sha256
/// `700ebd31038001f0a4b015cb84b94266816514c64a5efccca0dc5ff6ab74855f`;
/// carrier `devicetree.dtb` = `xlnx,zynq-7000` with `ps7-nand`). Transcription
/// + exact-match admission: `dcentrald-common::s19_legacy_zynq_profiles`
/// (`S19I_PROFILE`; the three-chain alias is refused by test). What a runtime
/// would still need is everything below:
const AM2_S19I_UNCONFIRMED_DATUMS: &[&str] = &[
    "live unit: no S19i has ever been contacted (populated-slot count and per-chain population are capture-first; topol.conf 4x80 is the factory declaration)",
    "BM1360 work/nonce wire codec (never traced; explicitly NOT aliased onto BM1398 or onto the am3 AML APW12 lanes)",
    "hashboard voltage controller live read + energize contract (stock labels the slot PIC1704 @ 0x20; a label is not a populated-part proof)",
    "PSU voltage command law execution (APW12 version set [66,67,113] is first-party; the command law is unproven and is not inherited from R12/R13)",
    "cooling custody: fan PWM/control mapping and immutable independent thermal cutoff",
    "install-slot / revert semantics (no S19i NAND map captured)",
];

/// Antminer S19a (BHB28611) datums that remain UNCONFIRMED from held bytes
/// (R17-C, 2026-09-11).
///
/// Stock-settled and therefore NOT listed: machine identity `BHB28611`,
/// `asic_id "BM1398S" @ 0x1398` (156 big + 623 small cores — a DISTINCT
/// silicon string from plain `BM1398`, never a plain-BM1398 row), FOUR chains
/// x 72 chips (9x8 placement grid, 8 chips/domain, 9 domains/chain), address
/// interval 3, stock `PIC1704 @ 0x20` slot label, 4x LM75A @ iic 72..75,
/// `AT24C02D @ 0x50`, APW12-class PSU versions [67,113,116,117,118] @ i2c
/// 0x10, GPIO 907, ZYNQ7007 — all byte-stated by Bitmain's own `topol.conf`
/// inside the held signed production image
/// (
/// components/minerfs.image.gz.tree/etc/topol.conf`, sha256
/// `01ef73a6f358ba0407368d660487ade792297805e29675ae13e97f71936b809d`).
/// Transcription + exact-match admission:
/// `dcentrald-common::s19_legacy_zynq_profiles` (`S19A_PROFILE`; the plain
/// `BM1398` conflation and the three-chain alias are refused by test). What a
/// runtime would still need is everything below:
const AM2_S19A_UNCONFIRMED_DATUMS: &[&str] = &[
    "live unit: no S19a has ever been contacted (populated-slot count and per-chain population are capture-first; topol.conf 4x72 is the factory declaration)",
    "BM1398S work/nonce wire codec (never traced; the `-a` suffix resolves to a distinct silicon STRING, not to the S19 Pro BM1398 row's runtime)",
    "hashboard voltage controller live read + energize contract (stock labels the slot PIC1704 @ 0x20; a label is not a populated-part proof)",
    "PSU voltage command law execution (APW12 version set [67,113,116,117,118] is first-party; the command law is unproven and is not inherited from R12/R13)",
    "cooling custody: fan PWM/control mapping and immutable independent thermal cutoff",
    "install-slot / revert semantics (no S19a NAND map captured)",
];

/// A packaged control-board composition. Release eligibility is independent
/// from storage geometry, first-install support and physical runtime identity.
/// A signed image and matching hardware are still required before dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardDesc {
    /// Canonical target id (`am2-s19j`, `am1-s9`, …).
    pub board_target: &'static str,
    /// Coarse SoC family.
    pub family: BoardFamily,
    /// Default chain transport for this target.
    pub chain_transport: ChainTransportKind,
    /// Default work engine.
    pub work_engine: WorkEngineKind,
    /// ASIC protocol expected by this complete target composition.  This is an
    /// admission constraint only; runtime evidence still has to agree.
    pub asic_protocol: AsicProtocolIdentity,
    /// Informational controller expectation, never mutation authority.
    /// Use `RuntimeDiscovered` when the control-board target is insufficient.
    pub voltage_controller: VoltageControllerClass,
    /// Install / recovery slot policy.
    pub slot_policy: SlotPolicy,
    /// Independent storage, artifact, maturity, authorization, and recovery
    /// facets. This is the authoritative install/update contract.
    pub enablement: HardwareEnablementPolicy,
    /// Publishable release channel for an implemented work engine. This is
    /// eligibility, not proof that the installed image is signed.
    pub release_channel: ReleaseChannel,
    /// Whether a first install from another OS has an implemented product
    /// route. Self-update and removable-media policies remain independent.
    pub first_install_supported: bool,
    /// Whether mining is allowed to auto-start on a fresh image (usually false).
    pub mining_default_enabled: bool,
    /// Why this target does or does not run (H7 G8). Distinguishes an
    /// architectural routing refusal (`SpecialisedLifecycle` — e.g. Amlogic,
    /// which mines via the native serial lane and deliberately refuses generic
    /// `Platform` construction) from a genuine fail-closed
    /// `EvidenceRetainedNotImplemented` (e.g. CVitek). Orthogonal to
    /// `enablement` maturity/authorization facets: classification/reporting
    /// only, never mutation authority.
    pub runtime_status: RuntimeStatus,
    /// Declared cooling medium (Round-15 A3 axis, [`crate::cooling_medium`]).
    ///
    /// `None` = **undeclared**, and that is the correct value for every row
    /// registered today, for a held-bytes reason rather than for want of
    /// effort: **cooling medium is a hashboard/chassis facet, not a
    /// control-board facet.** In the pinned VNish 1.2.7 corpus
    /// (`dcentrald-silicon-profiles/src/vnish_thermal_matrix_1_2_7.json`) the
    /// air `s21` (`BHB68603`), `s21-hydro` (`HHB68501`) and `s21-imm`
    /// (`IHB68601`) rows all declare the *same* `observed_platforms`
    /// (`aml, bb, cv, xil`) — one control board, three cooling media. So
    /// `am3-s21` covers air, hydro and immersion units alike and cannot
    /// truthfully declare any of them. The discriminator is the hashboard
    /// code prefix (`BHB`/`A3HB` air vs `HHB`/`H6HB`/`H1HB` hydro vs
    /// `IHB`/`M1HB` immersion), which lives in that registry, not here.
    ///
    /// Undeclared is fail-closed in both
    /// directions: it never earns the fan-management bypass
    /// (`fan_bypass_permitted(None) == false`) and its escalation ladder
    /// validates under forced-air rules, so fans stay managed.
    ///
    /// NEVER project `Hydro`/`Immersion` onto a row without bytes — a
    /// wrongly-fanless row would strip fan management from an air board.
    /// Equally, do not "tidy" undeclared rows to `Some(Air)`: that asserts a
    /// chassis-fan actuator the same control board does not have when it is
    /// carrying a hydro or immersion hashboard.
    pub cooling_medium: Option<CoolingMedium>,
    /// Declarative thermal escalation ladder for this target.
    ///
    /// Validated registry-wide against [`Self::cooling_medium`] by
    /// [`Self::validate_cut_ladder`] and
    /// `every_registered_row_has_a_valid_cut_ladder`. The two load-bearing
    /// properties: the terminal rung is always a power cut (fan raise is never
    /// the last resort), and a row declaring a medium with **no fan actuator**
    /// must carry NO [`CutRung::RaiseFansToCap`] rung at all — absent, not
    /// zero. "Cut hash before raising fan noise" is undefined on a board with
    /// no fan; it degenerates to "cut hash".
    pub cut_ladder: &'static [CutRung],
    /// Declared thermal-supervisor lane (Round-15 A9 finding F-8).
    ///
    /// Fail-closed: [`SupervisorClass::Unclassified`] unless this row has an
    /// executable mining lane. This exists so a newly registered `am1-*` row
    /// cannot silently inherit a live-validated S9's classification from a
    /// `board_target` string prefix.
    pub supervisor_class: SupervisorClass,
}

impl BoardDesc {
    /// Return a separately evidenced vendor catalog identity. The wire
    /// protocol may differ or may be independently proven to agree.
    ///
    /// `None` means this registry has no distinct catalog/wire split for the
    /// row; it is not evidence that every vendor label is known.
    pub fn distinct_asic_catalog_identity(&self) -> Option<AsicCatalogIdentity> {
        match self.board_target {
            // The factory configuration and exact production wire paths are
            // independent evidence sources even though both resolve to 0x1396.
            "am2-s17e" | "am2-t17e" => Some(AsicCatalogIdentity::Bm1396),
            _ => None,
        }
    }

    /// Well-known beta-tier S9 Xilinx target (am1).
    pub const fn am1_s9() -> Self {
        Self {
            board_target: "am1-s9",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am1S9,
            runtime_status: RuntimeStatus::GenericPlatform,
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::FpgaUio,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1387,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: AM1_S9_PUBLIC_UPDATE_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: true,
            mining_default_enabled: false,
        }
    }

    /// Exact compositions that use the standard BM1387/PIC16 executor.
    ///
    /// S9i/S9j production startup, heartbeat and voltage conversion are traced
    /// in the hash-bound 2019-07-31 stock image, not inferred from part-name
    /// strings. Its unused dsPIC symbols do not select an adapter. The daemon
    /// must still join this declaration with the observed chain6/7/8 fabric
    /// and live PIC/ASIC responses before acquiring execution authority.
    pub fn admits_standard_bm1387_runtime(&self) -> bool {
        matches!(self.board_target, "am1-s9" | "am1-s9i" | "am1-s9j")
            && self.family == BoardFamily::Zynq
            && self.asic_protocol == AsicProtocolIdentity::Bm1387
            && self.voltage_controller == VoltageControllerClass::Pic16F1704
            && self.chain_transport == ChainTransportKind::FpgaUio
            && self.work_engine == WorkEngineKind::FpgaWorkFifo
            && self.supervisor_class == SupervisorClass::Am1S9
            && self.runtime_status.permits_mining_lane()
    }

    /// S11 exact composition; management-only, capture-first (am1 Zynq).
    ///
    /// Registered in Round 15 so a whole held-firmware vendor model stops being
    /// invisible to every registry that walks [`Self::all_registered`] — the
    /// same reasoning as [`Self::am1_t9plus`] and [`Self::am1_s9i`]. It claims
    /// nothing the bytes do not support.
    ///
    /// **`asic_protocol: RuntimeDiscovered` is the load-bearing choice.** Both
    /// candidate identities are refused, because the official S11 image
    /// contradicts each of them in a different way — see
    /// [`AM1_S11_UNCONFIRMED_DATUMS`] and
    /// `dcentrald-silicon-profiles/src/bm1391_stock_fw.rs`. In particular this
    /// row must NOT be "tidied" to `Bm1391` to match
    /// `dcentrald-re-catalog`'s `s11` row: that row's sole cited binary
    /// (sha256
    /// `a9417924…`) is byte-identical to the official image's `bmminer` and
    /// contains no BM139x token at all.
    ///
    /// `slot_policy: LabGated` because no S11 has been contacted and the
    /// package's own `runme.sh` shows two mutually exclusive flash layouts
    /// (`7007`: raw `nandwrite` of `uramdisk.image.gz` to mtd1/mtd4; `XILINX`:
    /// UBI attach + `nandwrite` of a UBI rootfs to mtd2/mtd3). Nothing here
    /// authorizes either.
    pub const fn am1_s11() -> Self {
        Self {
            board_target: "am1-s11",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Unclassified,
            runtime_status: RuntimeStatus::CaptureFirst {
                unconfirmed: AM1_S11_UNCONFIRMED_DATUMS,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::None,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::RuntimeDiscovered,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact held 72-chip S15 native flat-FPGA/application-PIC composition.
    /// Its own runtime retains the current-boot fabric and source GPIO owner,
    /// verifies full census and known headers, and owns power/thermal teardown.
    /// Source command/pin observations do not certify physical rail voltage.
    /// A conflicting 60-chip S15 variant cannot borrow this runtime admission.
    /// Generic construction and onboard installation remain refused.
    pub const fn am1_s15() -> Self {
        Self {
            board_target: "am1-s15",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am1Bm1391,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Bm1391Native,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::StockFpga,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1391,
            voltage_controller: VoltageControllerClass::Bm1391Application,
            slot_policy: SlotPolicy::SdOnly,
            enablement: BM1391_NATIVE_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// T9+ exact composition; management-only, capture-first (am1 Zynq).
    ///
    /// We hold two independent T9+ stock firmware images
    /// (
    /// and its `SD-` sibling) plus three extracted rootfs trees under
    /// /…/t9plus/`, yet the
    /// SKU resolved to **no descriptor at all** — so a whole held-firmware
    /// vendor model was invisible to every registry that walks
    /// [`Self::all_registered`]. This row makes it visible **without** claiming
    /// anything the bytes do not support.
    ///
    /// **Byte-traceable (why `BoardFamily::Zynq` is not a family guess):** the
    /// stock tarball's inner `fw.tar.gz` carries a `xilinx/` payload
    /// (`BOOT.bin`, `uImage`, `devicetree.dtb`, `angstrom_rootfs.jffs2`), and
    /// that DTB parses to `compatible = "xlnx,zynq-7000"` with `ps7-nand` —
    /// the same carrier class as [`Self::am1_s9`].
    ///
    /// **Chip identity and chip count are SETTLED — by Bitmain's own factory
    /// jig config**, +`
    /// (`Name=T9+ HASH board`):
    ///
    /// ```text
    /// AsicType=1387      AsicNum=18      CoreNum=114     sensor_model=3 (TMP421)
    /// ```
    ///
    /// Its siblings in the same directory validate the whole BM1387 line
    /// byte-for-byte — S9 `1387`/`63`, S9+ `1387`/`84`, T9 `1387`/`57`, and
    /// (BM1385) S7 `1385`/`45`|`54` — so this is a per-model table, not a
    /// template. `asic_protocol` is therefore [`AsicProtocolIdentity::Bm1387`],
    /// and it **resolves a long-standing corpus conflict**: the BM1391 reading
    /// in `research/s9/WAVE3_STOCK_X9_L3_RECOVERY_INVENTORY.md:279` is wrong:
    /// exact S15/T15 miners compare register 0's high word with `0x1391`, while
    /// the held T9+ config and miner identify BM1387. The "3 | 63" in
    /// `research/models/:26` is an **S9 copy-across** —
    /// 63 is exactly S9's `AsicNum`.
    ///
    /// **Chain topology is also SETTLED**, by the T9+'s own miner binary
    /// +/bmminer` — which
    /// self-identifies as `Miner Type = T9+` and whose only `BM13xx` string is
    /// `BM1387` (a third independent confirmation of the chip family):
    ///
    /// | fact | value | site |
    /// |---|---|---|
    /// | chains | **9** | `bitmain_c5_prepare@383FC:133` `c5_config.chain_num = 9` |
    /// | ASICs per chain | **18** | `doTestBoard@16318:231` `cgpu.real_asic_num = 18` |
    /// | chain-index mask | `& 0xF` | `get_nonce_and_register@31CB0:72` (16 slots) |
    ///
    /// `c5_config` is assigned in exactly one function and never overridden, and
    /// `isChainEnough@2EE68` independently walks a 16-slot array requiring
    /// `count > 8`. **9 x 18 = 162 BM1387**, which reconciles the nameplate at
    /// 10.5 TH/s / 162 = 64.8 GH/s per chip — in line with S9 (71.4) and T9
    /// (67.3). `C5` also matches the catalog's "C5/Xil" carrier for T9+.
    /// (The sibling `c5_config.asic_num = 54` is most plausibly chips per *hash
    /// board* — 3 chains x 18 — which yields the same 162 total across 3 boards;
    /// that unit reading is inference, so nothing is declared from it.)
    ///
    /// **The voltage controller is NOT the S9's PIC16F1704 — the catalog is
    /// wrong about this.** `research/chips/:134` lists
    /// `PIC16F1704 | S9 / S9i / S9j / T9+ | 0x55/0x56/0x57`. The T9+'s own
    /// `bmminer` says otherwise: it contains **8** `dsPIC33EP16GS202_*`
    /// routines (`pic_heart_beat`, `enable_pic_dc_dc`, `reset_pic`,
    /// `get_pic_sw_version`, `send_data_to_pic`, `erase_pic_app_program`,
    /// `update_pic_app_program`, `jump_to_app_from_loader`) and **zero** PIC16
    /// or `1704` symbols — the single textual `1704` is
    /// `c5_config.token_type = 1704017`, an unrelated constant. The
    /// T9+-specific transport `T9_plus_write_pic_iic@2CF7C` (FPGA-mediated I²C
    /// via `axi_fpga_addr` + `set_iic`) is called **only** by those dsPIC33
    /// routines.
    ///
    /// This is exactly the trap [`Self::am1_s15`] warns about — "the S9
    /// template's `Pic16F1704` is a real controller claim and must not be copied
    /// across on family resemblance" — so `voltage_controller` stays
    /// [`VoltageControllerClass::RuntimeDiscovered`]. Promotion to a concrete
    /// dsPIC33 class is *evidence-supported* but deliberately withheld: a
    /// voltage-controller class energizes a rail, one binary read is not a live
    /// read, and this row cannot open a chain anyway.
    ///
    /// **Deliberately NOT claimed** (see [`AM1_T9PLUS_UNCONFIRMED_DATUMS`]):
    /// - `chain_transport: None` / `WorkEngineKind::ManagementOnly`. Knowing the
    ///   topology is not knowing how to drive it: the control-board GPIO map and
    ///   NAND slot layout are still unknown, and no T9+ has ever been contacted.
    ///   A chain that cannot be opened cannot be opened wrongly.
    /// - `SlotPolicy::LabGated`, **not** the S9's `ZynqAbFwSetenv` — because no
    ///   T9+ has been contacted and the control-board GPIO map is unknown. Note
    ///   the three-partition stock NAND
    ///   (`BOOT.bin-env-dts-kernel` / `angstram-rootfs` / `upgrade-rootfs`) is
    ///   **not** the discriminator it was once recorded as: stock S9 ships the
    ///   byte-identical map (see [`AM1_T9PLUS_UNCONFIRMED_DATUMS`]).
    ///   (`ZYNQ_RUNTIME_ONLY_ENABLEMENT`'s `storage_topology` is inert here —
    ///   every authorization facet refuses, so it asserts nothing about T9+.)
    ///
    /// **Correction carried by this row:** the recorded "T9+ stock default is
    /// 400 MHz, not S9's 650" claim is weaker than it reads. `400` appears only
    /// in the **SD-20Tools recovery** image's `bmminer.conf.factory`; both real
    /// T9+ mining firmwares (VNish 3.8.6 and 3.9.0) ship `"bitmain-freq" :
    /// "650"`, identical to S9. Nothing here may seed a T9+ frequency default.
    pub const fn am1_t9plus() -> Self {
        Self {
            board_target: "am1-t9plus",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Unclassified,
            runtime_status: RuntimeStatus::CaptureFirst {
                unconfirmed: AM1_T9PLUS_UNCONFIRMED_DATUMS,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::None,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1387,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// S9i exact 3x63 BM1387/PIC16 application-ABI beta composition.
    ///
    /// S9i and S9j 2019-07-31 production bmminers are byte-identical, SHA256
    /// 03e19bc31dd51330604d746ce9bf4dbb3d29b69a1461915a2c7ecb773828854a.
    /// bitmain_c5_init calls bare enable_pic_dac (55 AA 15 01), and its
    /// heartbeat thread calls bare pic_heart_beat_each_chain (55 AA 16).
    /// The production DAC law is exactly 1608.420446 - 170.423497 * volts,
    /// independently matching the existing S9 implementation. Framed dsPIC
    /// enable/heartbeat handlers have no incoming calls or pointer references.
    /// See campaign evidence/r02/stock-pic-source-manifest.json and the raw
    /// instruction captures. The factory profile and stock DTB independently
    /// bind BM1387/63/114 and the S9 carrier. Physical qualification is pending.
    /// Storage policy stays external-media-only; this does not inherit S9's
    /// public NAND update capability.
    pub const fn am1_s9i() -> Self {
        Self {
            board_target: "am1-s9i",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am1S9,
            runtime_status: RuntimeStatus::GenericPlatform,
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::FpgaUio,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1387,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::LabGated,
            enablement: AM1_LEGACY_EXPERIMENTAL_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// S9j sibling with its own exact image/experimental admission token.
    /// Its held production executable is byte-identical to S9i's; see above.
    pub const fn am1_s9j() -> Self {
        Self {
            board_target: "am1-s9j",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am1S9,
            runtime_status: RuntimeStatus::GenericPlatform,
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::FpgaUio,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1387,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::LabGated,
            enablement: AM1_LEGACY_EXPERIMENTAL_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact am1-s9se C43/BM1393 native executor. Runtime checks loaded fabric,
    /// framed PIC identity, all 60 ASICs, cooling and observed work serialization.
    /// Exact generated SD media is writable; onboard installation stays separate.
    pub const fn am1_s9se() -> Self {
        Self {
            board_target: "am1-s9se",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am1C43,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::C43Bm1393Native,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::StockFpga,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1393,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::LabGated,
            enablement: C43_NATIVE_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact am1-s9k C43/BM1393 native executor. Runtime checks loaded fabric,
    /// framed PIC identity, all 60 ASICs, cooling and observed work serialization.
    /// Exact generated SD media is writable; onboard installation stays separate.
    pub const fn am1_s9k() -> Self {
        Self {
            board_target: "am1-s9k",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am1C43,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::C43Bm1393Native,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::StockFpga,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1393,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::LabGated,
            enablement: C43_NATIVE_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// S9 Hydro — capture-first AM1 row whose PIC GENERATION is resolved
    /// (R17-D, 2026-09-11): the production miner is the framed
    /// dsPIC33EP16GS202 "S9 plus plus" build (`is_S9_Hydro()=1` compile-time
    /// predicate of the held 2019-09-20 bmminer, sha256 `81b89d08…ac85`), with
    /// production enable/heartbeat/disable/telemetry call chains and a
    /// byte-exact analog-voltage telemetry law
    /// (`55 AA 04 29 00 2D`, 9-byte reply, `V = BE16 * 3.3 * (1/4096) * 4.0`)
    /// transcribed in `dcentrald-common::s9_plus_plus_pic_generation`. The
    /// generation boundary is three-way and predicate-decided: bare-PIC16
    /// (S9, S9i, S9j) | framed dsPIC (T9+; S9 Hydro; S11 build).
    ///
    /// **Deliberately NOT claimed** (see [`AM1_S9_HYDRO_UNCONFIRMED_DATUMS`]):
    /// - `chain_transport: None` / `work_engine: ManagementOnly` — the chain
    ///   transport/reset GPIO map and population are capture-first; no S9
    ///   Hydro has ever been contacted. A chain that cannot be opened cannot
    ///   be opened wrongly.
    /// - `asic_protocol: Bm1387` is the GENERATION's first-party lineage
    ///   (predicate + `set_Voltage_S9_plus_plus_BM1387_54`), an admission
    ///   constraint only — the exact identity string / wire ChipID stays in
    ///   the unconfirmed datums and no work codec is admitted.
    /// - `voltage_controller: DsPic33Ep` names the generation-proven framed
    ///   family; the live read + energize electrical contract stays
    ///   capture-first.
    /// - `cooling_medium: None` — the held binary names a liquid-cooling law
    ///   (`s9_hydro_strong_liquid_cooling_min_pwm_percent`) but its numeric
    ///   minimum was never extracted, and cooling medium is a hashboard/
    ///   chassis facet per the registry-wide rule
    ///   (`no_registered_row_declares_a_cooling_medium_without_evidence`).
    ///   Undeclared keeps fan management enforced.
    /// - `release_channel: Denied` — no image composition exists for this
    ///   target; install/NAND layout unanalyzed.
    pub const fn am1_s9_hydro() -> Self {
        Self {
            board_target: "am1-s9-hydro",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Unclassified,
            runtime_status: RuntimeStatus::CaptureFirst {
                unconfirmed: AM1_S9_HYDRO_UNCONFIRMED_DATUMS,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::None,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1387,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::LabGated,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact held 60-chip T15 native composition. Its independent model joins
    /// address interval4, EEPROM revision selector routing and source profile;
    /// it cannot borrow the S15 population or a generic S9 transport.
    /// Onboard installation and generic construction remain refused.
    pub const fn am1_t15() -> Self {
        Self {
            board_target: "am1-t15",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am1Bm1391,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Bm1391Native,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::StockFpga,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1391,
            voltage_controller: VoltageControllerClass::Bm1391Application,
            slot_policy: SlotPolicy::SdOnly,
            enablement: BM1391_NATIVE_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// S19j Pro Xilinx target (am2): public-beta self-update, but no
    /// vendor-source first-install capsule.
    pub const fn am2_s19jpro() -> Self {
        Self {
            board_target: "am2-s19j",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Zynq,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::S19jHybrid,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::ZynqHybrid,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: AM2_PUBLIC_UPDATE_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Antminer **S19j classic** (non-Pro, hashboard `BHB42701`) — distinct
    /// evidence row, management-only, capture-first (Gauntlet lane B5b,
    /// 2026-09-02).
    ///
    /// # Identity — settled by Bitmain's own stock topology DB
    ///
    /// The S19j merge image's 15-machine `config[]` DB states
    /// `BHB42701: asic_id "BM1362" / asic_addr "0x1362" / 108 per chain
    /// (12×9) / 36 domains × 3 / interval 2 / PIC1704 @ 0x20 / APW12 @ 0x10
    /// gpio 907 / AT24C02D @ 0x50`
    /// (
    /// sha256 `61a6404b…0ffe8`). This **refutes** the roster's old
    /// "S19j = BM1398 identity-only" claim: the classic S19j is a real
    /// second-generation S19j-family BM1362 board (65+514 cores, 8 small per
    /// big core — same silicon census as the sibling S19j Pro boards in the
    /// same DB), not an S19-classic BM1398P variant. `model.rs`'s `s19j` row
    /// is corrected in the same lane.
    ///
    /// # Why a DISTINCT row, not an alias onto `am2-s19j`
    ///
    /// `am2-s19j` is the registered key of the **S19j Pro XIL** row
    /// ([`Self::am2_s19jpro`]; `BOARD_TARGET_ALIASES` maps
    /// `am2-s19jpro-zynq`/`am2-s19jpro` onto it). As with NBS1902 S19 versus
    /// NBP1901 S19 Pro, this classic S19j requires its own composition:
    /// it is a different hashboard (BHB42701 108/chain vs the Pro
    /// boards' 126/120/84-per-chain variants) on a never-contacted platform,
    /// so an alias would silently borrow the Pro row's live-proven geometry,
    /// PIC plan and dispatch. Same rule as [`Self::am1_s9i`] vs
    /// [`Self::am1_s9j`]: one row per genuinely distinct board, so a
    /// first-light on one never silently promotes the other.
    ///
    /// # Runtime-sharing adjudication — REFUSED (why this row is `Denied`)
    ///
    /// A BM1362 am2 runtime exists (the S19jHybrid lane, live-proven on the
    /// Pro XIL units `a lab unit`/`a lab unit`), but its dispatch is **exact-match on
    /// `board_target == "am2-s19j"`** and its per-slot plan binds retained
    /// pre-energize EEPROM observations from those units. Classic-j cannot
    /// share it honestly: making a 108/chain never-contacted board ride a
    /// 126/110-class runtime plan would require dispatch edits adjacent to
    /// energize paths — outside this lane's BoardDesc scope (DCENT_EE
    /// territory). Per the three-state contract, `Denied` means no
    /// configuration converts this park into dispatch; promotion requires a
    /// reviewed change-set moving the row with its own evidenced runtime.
    ///
    /// # Fail-closed facet choices (do not "tidy")
    ///
    /// - `chain_transport: None` / `work_engine: ManagementOnly` — no carrier
    ///   for THIS board has been captured (the merge ships both BB and ZYNQ
    ///   records; a target that cannot open a chain cannot open the wrong
    ///   one — same reasoning as [`Self::am1_s15`]).
    /// - `asic_protocol: Bm1362` — stock-settled identity, an admission
    ///   constraint only (never measured-silicon evidence).
    /// - `voltage_controller: RuntimeDiscovered` — the stock `PIC1704` label
    ///   is not a populated-part proof (see
    ///   [`AM2_S19J_CLASSIC_UNCONFIRMED_DATUMS`]).
    /// - `slot_policy: LabGated` — the merge image carries two mutually
    ///   exclusive control-board payloads (BB + ZYNQ7007) and no unit has
    ///   been contacted to disambiguate a storage map (same posture as
    ///   [`Self::am1_s11`]).
    /// - `enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT` — deliberately NO
    ///   install/flash facet: no artifact producer, no update mechanism, no
    ///   removable media.
    pub const fn am2_s19j_classic() -> Self {
        Self {
            board_target: "am2-s19j-classic",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Unclassified,
            runtime_status: RuntimeStatus::CaptureFirst {
                unconfirmed: AM2_S19J_CLASSIC_UNCONFIRMED_DATUMS,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::None,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// AM3 BeagleBone S19j Pro — runtime mining proven; not public-beta install.
    pub const fn am3_bb_s19jpro() -> Self {
        Self {
            board_target: "am3-bb-s19jpro",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am3Bb,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Am3BbSerial,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::BeagleBone,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::SdOnly,
            enablement: BEAGLEBONE_SD_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Generic AM3 BeagleBone image — management only without exact carrier proof.
    pub const fn am3_bb() -> Self {
        Self {
            board_target: "am3-bb",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Unclassified,
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate: "generic am3-bb image lacks exact carrier proof; am3-bb-s19jpro is the executable route",
            },
            family: BoardFamily::BeagleBone,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::SdOnly,
            enablement: BEAGLEBONE_GENERIC_EVIDENCE_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Amlogic S21 — mining evidence exists; public install lab-gated (ADR-0002).
    ///
    /// # Stock/factory reconciliation (Gauntlet B10, 2026-09-02)
    ///
    /// The asicminingsupplies S21 air record (`s21-aml-20241011`, BMU
    /// sha256 `c09a1904…`) is a **sealed** code-9 `ANDROID!` AMLCtrl image
    /// — no plaintext stock topol/levels/bmminer exists for this SKU (only
    /// the boot-header fields + the `AMLSECU!` build timestamp 2024-10-11
    /// are readable; pinned in
    /// `dcentrald-silicon-profiles::s21_family_stock_topol`). The
    /// first-party facts come from Bitmain's own factory bench instead:
    /// the AMTC/HashSource S21 jig (binary sha256 `0be42807…`, unstripped
    /// with debug_info) + its `Config.ini` (`fab1a64d…`) pin the air
    /// hashboard **BHB68603 = BM1368, 108 ASICs/board, 12 voltage domains
    /// × 9** — the factory confirmation of the Lane I geometry — plus the
    /// bench PSU-version keys `[193,113,114,116,117,118,119,120]` (key
    /// 116 a first sighting; the fleet unit's own APW121215f reports 118)
    /// and jig-only 12 Mbaud test baud (miner baud stays the live-proven
    /// 3.125 Mbaud).
    ///
    /// **Controller adjudication (evidence record — NO facet change):**
    /// the same jig carries `hal/pic/bitmain_pic_1704.c` and the full 1704
    /// flash programmer (`_bitmain_pic_{write,erase,seek}_1704`,
    /// `_update_pic_app_program_1704`, "pic jump from loader to app") —
    /// first-party proof the BHB68603 hashboard **populates a PIC1704**.
    /// The production AML stack nevertheless leaves it idle (live ftrace:
    /// zero PIC I²C traffic; voltage via kernel-DTB TAS5782M @ 0x48-0x4B
    /// + PSU PMBus/GPIO; the shipped bench config itself sets
    /// `Read_Temperature_From_Pic: false`). `VoltageControllerClass::
    /// RuntimeDiscovered` and the daemon's NoPic serial posture therefore
    /// remain correct as **control-board software facts**, not statements
    /// about hashboard silicon — a zynq-class board driving the same
    /// hashboards would face a live PIC1704 (every zynq-class S21-family
    /// stock record labels PIC1704 @ 0x20). DMM rail-polarity proof for
    /// the PSU-enable pin stays on the bench queue (item #4).
    pub const fn am3_s21() -> Self {
        Self {
            board_target: "am3-s21",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am3Aml,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1368,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_LAB_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact AML S21 Pro runtime: A3HB70601/02, 65 BM1370 per board.
    /// Held production model6f6870 -> chip profile824ce0 -> factory8c7a10
    /// selects PsuAsVoltageController, not the separate PIC test-jig path.
    /// AML registry key3 supplies GPIO437 active-low, reset454..456 and
    /// physical UART3/2/1. Native startup independently captures repeated
    /// format1 factory names and full cold/assigned ASIC coverage.
    /// Evidence: campaign r14/production-model-psu-selection.asm,
    /// donor SHA25664e120df8c8011aa5199c87ebbd30276766ec3c746d597ab67a6119cf1c3cbe1.
    pub const fn am3_s21pro() -> Self {
        Self {
            board_target: "am3-s21pro",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am3Aml,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1370,
            voltage_controller: VoltageControllerClass::NoPic,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_LAB_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact AML S21 XP air runtime: A3HB70501/02/03, 91 BM1370 per board.
    /// Production model6f9b88 -> chip profile825c94 -> factory8c7a10 selects
    /// PSU voltage control through the same explicit AML registry as Pro.
    /// Its 91-chip geometry remains distinct from Pro65, S21+55, and hydro.
    /// Fresh factory name and every selected UART's full ASIC count are
    /// required by the executor; encrypted tuning fields remain unknown.
    /// Evidence: campaign r14/production-model-psu-selection.asm.
    pub const fn am3_s21xp() -> Self {
        Self {
            board_target: "am3-s21xp",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am3Aml,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1370,
            voltage_controller: VoltageControllerClass::NoPic,
            slot_policy: SlotPolicy::LabGated,
            // Native mining is implemented; its separate persistent installer
            // route remains package-only until the exact writer is joined.
            enablement: AMLOGIC_PACKAGE_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Evidence-only AML S21+ admission target: A3HB70701/02/03, 55 BM1370
    /// per board (11 domains x 5; 3 x 55 = 165 per unit) — a DISTINCT
    /// platform from Pro65 (13x5) and XP91 (13x7) on the same silicon.
    /// Held model list
    ///
    /// 03-bosminer/model-list.json` (SHA256
    /// c79f56e2d2a3f1e593b21d8a79a5364b2997e76f09b2ee9167fac64d1bf7dfe0)
    /// settles name/geometry only. The production model->ASIC-profile->
    /// PSU-controller chain traced for Pro/XP
    /// (r14/production-model-psu-selection.asm) was NEVER traced for S21+,
    /// so this row inherits no route, no PSU profile, and no GPIO437
    /// polarity from any sibling board target. ePIC/VNish controller
    /// observations conflict and are retained as refusals
    /// (`s21_generation_admission::S21PLUS_CONTROLLER_OBSERVATIONS`;
    /// ePIC six caveats apply). Promotion requires an exact traced carrier
    /// contract plus fresh repeated format1 names and full independent
    /// 55-chip populations. (Re-materialized 2026-09-12 from the R14
    /// integration patch after board_desc.rs reformatting.)
    pub const fn amlogic_s21plus() -> Self {
        Self {
            board_target: "amlogic-s21plus",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Unclassified,
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate: "S21+ hashboard name/geometry is stock-settled \
                       (A3HB70701/02/03 BM1370 11x5=55 per board; held model \
                       list SHA256 c79f56e2d2a3f1e593b21d8a79a5364b2997e76f0\
                       9b2ee9167fac64d1bf7dfe0) but its AML registry \
                       descriptor, PSU factory chain and GPIO437 polarity \
                       were never traced: no route, PSU profile or polarity \
                       may be inherited from am3-s21/am3-s21pro/am3-s21xp",
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1370,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            // No artifact, no update path, no install: the S21+ runtime
            // layout is not traced ("exact runtime layout still to trace",
            // r14 checkpoint board table), so even the package story the
            // PACKAGE_ONLY rows carry would over-claim.
            enablement: AMLOGIC_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Amlogic T21 evidence/package target. An exact held production rootfs
    /// binds T21/AML to three direct UART routes plus GPIO/PWM observations,
    /// while PIC/PSU protocol, safe power/cooling lifecycle, live enumeration,
    /// cold-init sequencing, and persistent-write geometry remain unresolved.
    ///
    /// # Stock-contract reconciliation (Gauntlet B9, 2026-09-02)
    ///
    /// Bitmain's own `t21-merge-20240926` image (BMU sha256 `f9dcf13a…`,
    /// Phase A §3.9) now settles the HASHBOARD-side contracts for the
    /// BHB6870X family — pinned in
    /// `dcentrald-silicon-profiles::t21_stock_topol` (every datum cited):
    /// BM1368 3×108 (12 dom × 9, interval 2), PSU **APW11A** @ I²C 0x10
    /// gpio 907 (first stock sighting of the dialect; NOT APW12 and NOT the
    /// S21-hydro APW11 — the shipped TOML's old `APW12` placeholder was
    /// corrected on this evidence), per-chain voltage-MCU label PIC1704 @
    /// 0x20 with AT24C02D EEPROM @ 0x50, 4-fan layout, stock levels ladder
    /// 600/350 MHz (opaque voltage tokens 1550/1300). The same-chip
    /// S21-hydro record (also BM1368) proves chip identity does NOT
    /// determine chain topology or PSU dialect — T21 stands on its own
    /// citations.
    ///
    /// What the stock image does NOT settle, and why every facet below stays
    /// fail-closed: the merge's AML record is a **sealed** code-9 `ANDROID!`
    /// image, so every CONTROL-BOARD-side contract for this Amlogic target
    /// (its PSU-enable GPIO translation of the zynq gpio 907, storage map,
    /// and its own cold-init order) remains unproven; the PIC1704 topol
    /// label is not a populated-part proof (S19-family caveat — a sibling
    /// generation shipped dsPIC33EP16GS202 in a PIC1704-labelled slot); and
    /// no T21 unit has ever been contacted. The stock zynq cold-init
    /// sequence (topol load → per-chain EEPROM/PIC open → PSU version probe
    /// with v2-protocol fallback → open-core voltage → low-temp power-on →
    /// chain enumeration → fixed-step frequency ladder) is transcribed as
    /// string-level evidence in `t21_stock_topol` — sequence evidence, not
    /// an execution contract.
    pub const fn am3_t21() -> Self {
        Self {
            board_target: "am3-t21",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Unclassified,
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate: "T21 hashboard contracts are stock-settled (BHB6870X BM1368 3x108, \
                       APW11A@0x10, PIC1704@0x20 label; t21_stock_topol) but the AML \
                       control-board record is sealed and no unit was ever contacted: \
                       runtime, cold-init execution, storage-write and safe \
                       power/cooling contracts stay unproven",
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1368,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_PACKAGE_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Amlogic S19k Pro. The default-off native BM1366 route joins the exact
    /// NoPic lifecycle owner; live cold-init and NAND remain evidence- and
    /// operator-authority-gated.
    pub const fn am3_s19kpro() -> Self {
        Self {
            board_target: "am3-s19k",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am3Aml,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1366,
            voltage_controller: VoltageControllerClass::NoPic,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_S19K_GUARDED_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// The DISTINCT deployed S19k Pro NoPic persistent-startup identity
    /// (`am3-s19kpro`), registered 2026-09-12 (drift13 #5 adjudication, option
    /// b — R10 board join).
    ///
    /// Why this row exists: the shipped
    /// `br2_external_dcentos/board/amlogic/am3-s19kpro-nopic/` overlay stamps
    /// `/etc/dcentos/board_target` = `am3-s19kpro`, and the physical S19k Pro
    /// install session flashed exactly that target (deployed truth; the shared
    /// `S37board_setup` mutation authority admits the
    /// `am3-aml-s19kpro:am3-s19kpro` tuple). Until this row existed the marker
    /// resolved only through the `am3-s19kpro → am3-s19k` alias, which
    /// conflated two image identities on one registry key.
    ///
    /// What held bytes support (lineage only — nothing else is inherited from
    /// [`BoardDesc::am3_s19kpro`]): BM1366 silicon (skus.conf `S19kPro` row:
    /// 3x77 BM1366 NoPic; the overlay's `dcentrald.toml` pins
    /// serial_chip_type BM1366, 77 chips, ttyS1/2/3), NoPic posture
    /// (TAS5782M kernel-managed voltage; no PIC traffic), Serial transport,
    /// and the Am3Aml supervisor lane (thermal-supervisor continuity: before
    /// this row existed the marker resolved to am3-s19k's Am3Aml plan, and
    /// the deployed unit runs that plan).
    ///
    /// What stays UNCONFIRMED and fail-closed on purpose:
    /// - population/PSU/polarity facets are overlay + session datums, not
    ///   admitted contracts (APW121215f PSU model and rail GPIO 437 polarity
    ///   come from the overlay's envelope files; no independent PSU/polarity
    ///   witness was captured for this NoPic unit);
    /// - the runtime lane is NOT admitted: the typed BM1366 serial-platform
    ///   table has no `am3-s19kpro` profile, so work_engine stays
    ///   ManagementOnly and dispatch parks (identity known, mining not
    ///   enabled);
    /// - no artifact claim: the lane's builder emits
    ///   `dcentos-sysupgrade-am3-s19kpro.tar`, the exact basename already
    ///   published by the committed guarded am3-s19k lane, so
    ///   [`AMLOGIC_RUNTIME_ONLY_ENABLEMENT`] (artifact None) is the honest
    ///   posture until the Lead adjudicates the nopic lane's published
    ///   artifact identity (see evidence/r10/board-join-20260912);
    /// - install admission stays Denied and mining stays default-off.
    pub const fn am3_s19kpro_nopic() -> Self {
        Self {
            board_target: "am3-s19kpro",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            // Drift-13/R10 join, Lead fix: the registry-wide guard requires a
            // non-executable (ManagementOnlyByPolicy) row to keep its
            // thermal-supervisor lane Unclassified — borrowing the sibling
            // SKU's supervisor is exactly the inheritance this facet stops.
            supervisor_class: SupervisorClass::Unclassified,
            runtime_status: RuntimeStatus::ManagementOnlyByPolicy {
                gate: "exact S19k Pro NoPic persistent-startup identity is deployed \
                       (physical install session; S37 admits am3-aml-s19kpro:am3-s19kpro) \
                       but its native serial route is not admitted: the typed BM1366 \
                       serial-platform table carries no am3-s19kpro profile, the \
                       persistent storage writer/boot-selector contract is unadmitted, \
                       and nothing is inherited from am3-s19k beyond BM1366/NoPic lineage",
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1366,
            voltage_controller: VoltageControllerClass::NoPic,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact BHB56801/02,110 BM1366 per board; production PSU controller.
    /// Stock PIC labels do not mean this runtime uses the optional board PIC.
    pub const fn am3_s19xp() -> Self {
        Self {
            board_target: "am3-s19xp",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am3Aml,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1366,
            voltage_controller: VoltageControllerClass::NoPic,
            slot_policy: SlotPolicy::LabGated,
            // Native mining is implemented; its separate persistent installer
            // route remains package-only until the exact writer is joined.
            enablement: AMLOGIC_PACKAGE_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact BHB56804,110 BM1366 per board; measured APW17c1 production PSU.
    /// Unknown BHB56807 and PSUc2 profiles are not inherited.
    pub const fn am3_s19jxp() -> Self {
        Self {
            board_target: "am3-s19jxp",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am3Aml,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1366,
            voltage_controller: VoltageControllerClass::NoPic,
            slot_policy: SlotPolicy::LabGated,
            // Native mining is implemented; its separate persistent installer
            // route remains package-only until the exact writer is joined.
            enablement: AMLOGIC_PACKAGE_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact BHB42603/31/51 A126 native runtime. Installer and artifact
    /// assembly are separate implementation work from this physical owner.
    ///
    /// 2026-09-12 (drift13 #6a adjudication, R10 board join): promoted from
    /// `AMLOGIC_RUNTIME_ONLY_ENABLEMENT` to `AMLOGIC_PACKAGE_ONLY_ENABLEMENT`.
    /// The lane ships a real package surface: its overlay post-image execs the
    /// shared `am3-bm1362-nopic` builder (05124af24) and emits the exact
    /// model-named archive `dcentos-sysupgrade-am3-s19jproa.tar` with
    /// `PACKAGE_INSTALL_AUTHORIZED=0` / `package_only_denied` metadata, and
    /// `require-exact-build-inputs.sh` binds the exact s19jpro-a donor
    /// fw-info. The claim is artifact-evidence only: storage stays Unknown,
    /// the update mechanism stays None, and install admission stays Denied.
    pub const fn am3_s19jproa() -> Self {
        Self {
            board_target: "am3-s19jproa",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am3Aml,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::NoPic,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_PACKAGE_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact BHB42612 Plus120 production NoPic serial lifecycle. Its
    /// existing guarded rootfs-window installation remains a separate facet.
    pub const fn am3_s19jproplus() -> Self {
        Self {
            board_target: "am3-s19jproplus",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am3Aml,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::NoPic,
            slot_policy: SlotPolicy::LabGated,
            enablement: AMLOGIC_LAB_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact classic BHB42601/21/41,126 BM1362 per board, retained fw89 PIC
    /// application, protected factory bus1 and independent APW12/GPIO owner.
    /// R10 original-machine replays establish registry key3 raw1-off polarity
    /// and PIC bus0 framing; the A/Plus NoPic profile is a separate lifecycle.
    /// Physical qualification and persistent installation remain separate.
    pub const fn am3_s19jpro_aml() -> Self {
        Self {
            board_target: "am3-s19jpro-aml",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am3Aml,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::ClassicAmlNativeSerial,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Amlogic,
            chain_transport: ChainTransportKind::Serial,
            work_engine: WorkEngineKind::SerialWork,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::ClassicAmlApplication89,
            slot_policy: SlotPolicy::LabGated,
            // Drift-13 adjudication 2026-09-12: e3cf6127d regressed this row
            // to PACKAGE_ONLY without touching any package surface, while the
            // shipped overlay, committed manifest, README, and toolbox all
            // describe the guarded rootfs-window (seven-partition single-slot
            // NAND) LAB lane. LAB is the strictly conservative restoration:
            // release_channel stays Denied and LabGated stays.
            // L12 retirement (2026-09-15): no compatible persistent writer
            // (mtd5=config, mtd6=nvdata) — package-only posture.
            enablement: AMLOGIC_PACKAGE_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// CVITEK CV1835 S19j Pro identity — evidence-only, with no artifact or runtime lane.
    pub const fn cv1835_s19jpro() -> Self {
        Self {
            board_target: "cv1835-s19jpro",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Unclassified,
            runtime_status: RuntimeStatus::EvidenceRetainedNotImplemented {
                evidence: CV1835_RETAINED_EVIDENCE,
            },
            family: BoardFamily::Cvitek,
            chain_transport: ChainTransportKind::UartTrans,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::Bm1362,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::SingleSlot,
            enablement: CV1835_EVIDENCE_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// STM32MP15 / Braiins BCB100 S19-family carrier — capture-first, every
    /// facet denied.
    ///
    /// `BoardFamily::Stm32Mp15` has existed since the HAL scaffold landed
    /// (`board_desc.rs` `BoardFamily::Stm32Mp15`), and the toolbox ships a
    /// double-gated route for `board_target: "bcb100-s19jpro"`
    /// (`dcent-toolbox/src/dcent_toolbox/core/installer.py:1987-2012`), yet the
    /// registry had **no** `stm32mp15` row — so the projected install matrix
    /// had no `stm32mp15` line at all and the family was invisible rather than
    /// visibly refused. Registering the row does NOT enable anything: it turns
    /// a silent absence into a typed, CI-visible refusal.
    ///
    /// Every fail-closed choice below is deliberate and must not be "tidied":
    /// - `chain_transport: None` — the four `/dev/ttySTM*` names in
    ///   `dcentrald-hal/src/platform/stm32mp15.rs:29-40` are explicitly
    ///   *inferred*; declaring `Serial` would assert a carrier nobody captured.
    ///   Same reasoning as [`Self::am1_s15`].
    /// - `asic_protocol: RuntimeDiscovered` — BCB100 is a *replacement* control
    ///   board for the whole S19 family, so the hashboard silicon is a property
    ///   of the donor chassis, not of this carrier. A concrete family here would
    ///   be a guess, and `main.rs`'s serial route explicitly refuses a
    ///   `RuntimeDiscovered` descriptor before hardware construction.
    /// - `voltage_controller: RuntimeDiscovered` — `pic_address` is one of the
    ///   uncaptured datums; the S19-family `DsPic33Ep` must not be inherited on
    ///   family resemblance.
    /// - `enablement: STM32MP15_UNVERIFIED_ENABLEMENT` — `storage_topology`
    ///   stays `Unknown` because no partition map has been read.
    pub const fn bcb100_s19jpro() -> Self {
        Self {
            board_target: "bcb100-s19jpro",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Unclassified,
            runtime_status: RuntimeStatus::CaptureFirst {
                unconfirmed: BCB100_UNCONFIRMED_DATUMS,
            },
            family: BoardFamily::Stm32Mp15,
            chain_transport: ChainTransportKind::None,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::RuntimeDiscovered,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: STM32MP15_UNVERIFIED_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Zynq S19 NBS1902:76 BM1398 ASICs, address interval3, PIC1704.
    /// Held stock geometry is distinct from NBP1901's114/2 composition.
    /// Its native profile is planned; the target cannot borrow S19 Pro's
    /// executor, voltage ladder or factory identity decoder through an alias.
    pub const fn am2_s19() -> Self {
        Self {
            board_target: "am2-s19",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Zynq,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Am2Bm1398Native,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::FpgaUio,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1398,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Antminer **S19i** (machine `NBS2003`) — distinct evidence row,
    /// management-only, capture-first (R17-B, 2026-09-11).
    ///
    /// # Identity — settled by Bitmain's own stock topology DB
    ///
    /// The held signed S19i production image (2021-04-27) states, in its own
    /// `etc/topol.conf` (sha256 `700ebd31…855f`): `machine "NBS2003"`,
    /// `asic_id "BM1360" @ 0x1360` (156 big + 624 small cores), **four**
    /// chains x **80** chips (8x10 grid, 2 chips/domain, 40 domains/chain),
    /// address interval 3, `PIC1704 @ 0x20` slot label, 4x LM75A, `AT24C02D
    /// @ 0x50`, APW12-class PSU versions [66,67,113] @ 0x10, GPIO 907,
    /// `processor "ZYNQ7007"`. The carrier DTB is `xlnx,zynq-7000`, so
    /// `BoardFamily::Zynq` is byte-traceable, not a family guess. Exact
    /// transcription + exact-match admission:
    /// `dcentrald-common::s19_legacy_zynq_profiles::S19I_PROFILE` (keyed on
    /// exactly this board target; the three-chain sibling alias is refused by
    /// test). This row resolves the census conflict "the historical am2-s19
    /// alias cannot represent BM1360 S19 boards" by construction: the BM1360
    /// board now has its own row, so no alias path exists.
    ///
    /// # Fail-closed facet choices (do not "tidy")
    ///
    /// - `asic_protocol: RuntimeDiscovered` — BM1360 has no wire law in this
    ///   registry (the work/nonce codec was never traced), and the enum
    ///   carries no BM1360 variant; the exact identity string lives in the
    ///   profile module. Runtime identity evidence must select the protocol
    ///   before any ASIC mutation.
    /// - `voltage_controller: RuntimeDiscovered` — the stock `PIC1704` label
    ///   is not a populated-part proof (same rule as
    ///   [`Self::am2_s19j_classic`]).
    /// - `chain_transport: None` / `work_engine: ManagementOnly` — no S19i
    ///   has ever been contacted; the four-chain topol counts are the factory
    ///   declaration, not a captured population.
    /// - `slot_policy: LabGated`, `enablement:
    ///   ZYNQ_RUNTIME_ONLY_ENABLEMENT`, `release_channel: Denied` — no
    ///   image composition or NAND layout exists for this target; nothing may
    ///   be inherited from the S19 Pro NBP1901 or NBS1902 rows.
    pub const fn am2_s19i() -> Self {
        Self {
            board_target: "am2-s19i",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Unclassified,
            runtime_status: RuntimeStatus::CaptureFirst {
                unconfirmed: AM2_S19I_UNCONFIRMED_DATUMS,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::None,
            work_engine: WorkEngineKind::ManagementOnly,
            asic_protocol: AsicProtocolIdentity::RuntimeDiscovered,
            voltage_controller: VoltageControllerClass::RuntimeDiscovered,
            slot_policy: SlotPolicy::LabGated,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Unsupported,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact BHB28611 / BM1398S native runtime, 72 chips at interval 3.
    /// Held Bitmain S19a 20221206 topology and its own 40-pair levels table
    /// supply the software profile; its binary uses the BM1398 command law.
    /// The topology's four chain slots are capacity, not a populated census.
    /// The retained owner admits only observed slots 0..2 and exact decoded
    /// BHB28611 EEPROM identities, PIC89, PSU71 and controller/fabric identity.
    /// Runtime capability does not grant first install or mining by default.
    pub const fn am2_s19a() -> Self {
        Self {
            board_target: "am2-s19a",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Zynq,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Am2Bm1398Native,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::FpgaUio,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1398,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact S19+ BHB28701 native runtime: 80 BM1398 chips at interval 3,
    /// ten domains of eight, and only the 645 MHz / 1400 cV operating point.
    /// The held VNish Xilinx NAND rc5 hwscan model/default constructors and
    /// its cgminer model parser, ASIC factory and semantic power callbacks
    /// provide the exact software join. Bitmain's guide independently agrees
    /// on the 80-chip geometry. No measured electrical result is claimed.
    /// EEPROM identity, PIC89/PSU71, actual GPIO controller and loaded fabric
    /// remain runtime checks; first install and mining by default stay false.
    pub const fn am2_s19plus() -> Self {
        Self {
            board_target: "am2-s19plus",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Zynq,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Am2Bm1398Native,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::FpgaUio,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1398,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Native Zynq S19 Pro NBP1901/BM1398 lifecycle.
    ///
    /// The serial CLI entry delegates to a dedicated retained-owner FPGA
    /// executor before generic serial hardware construction. Admission binds
    /// the current factory page, independent 114-chip address coverage, PIC89,
    /// APW12 version 0x71, loaded fabric identity and observed FCLK. The PIC
    /// part is PIC16F1704 (stock topol.conf and held firmware); its framed
    /// protocol must not be selected from the older dsPIC placeholder.
    /// Source and implementation: the 2026-09-07 beta campaign R07 report.
    /// Install maturity remains independent of callable native mining.
    pub const fn am2_s19pro() -> Self {
        Self {
            board_target: "am2-s19pro",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Zynq,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Am2Bm1398Native,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::FpgaUio,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1398,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_LAB_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// S17 / S17 Pro (am2-s17p) — BM1397 hybrid runtime lane (2026-08-27).
    ///
    /// Promoted from the TD-003 management-only scaffold by the
    /// `2026-08-27-antminer17-unlock-armada` campaign (agent B1). Hashboard is
    /// **BHB07601** (48 BM1397/chain × 3 chains, 672 cores/chip); S17 and
    /// S17 Pro are binary-identical stock bmminers except build-id/timestamp,
    /// the SKU split being runtime EEPROM dispatch (A1 §V1). Voltage controller
    /// is the dsPIC33EP16GS202 **G2a framed** class at FPGA-bus `0x20|chain`
    /// (A1 §V3, A3 §2).
    ///
    /// `LifecycleLane::S17Hybrid` (added 2026-08-28, unlock-armada
    /// convergence): the interim reuse of `S19jHybrid` documented by B1 is
    /// retired — the four 17-series rows now carry their dedicated lane, one
    /// lane per engine (`--s17-hybrid` vs `--s19j-hybrid`).
    pub const fn am2_s17() -> Self {
        Self {
            board_target: "am2-s17p",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Zynq,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::S17Hybrid,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::StockFpga,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1397,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: S17_NATIVE_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// S17+ (am2-s17plus) — BM1397 hybrid runtime lane (2026-08-27).
    ///
    /// Promoted from management-only by the `2026-08-27-antminer17-unlock-armada`
    /// campaign (agent B1) after controller-ABI adjudication. Hashboard is
    /// **BHB07602** (65 BM1397/chain × 3 chains = 195). Stock-RE verdict (A1 §V1,
    /// HIGH): the S17+ class co-bundles `S17+PIC.hex`, a **PIC16F1704** image, and
    /// `bmminer` drives it through the `pic1704_*` (`init_pic_one_chain`) flow —
    /// the G2b raw S9-family frame dialect (`55 AA 10 VV` set-voltage, A3 §2).
    /// The prior `DsPic33Ep` value was an adapter placeholder from the BM1396
    /// correction era, superseded by the 17-family controller-ABI RE. Lane reuse
    /// note: see `am2_s17`.
    pub const fn am2_s17plus() -> Self {
        Self {
            board_target: "am2-s17plus",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Zynq,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::S17Hybrid,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::StockFpga,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1397,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            // 2026-08-27 armada (C1): B2 shipped the package-only board lane.
            enablement: S17_NATIVE_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// T17 (am2-t17) — BM1397 hybrid runtime lane (2026-08-27).
    ///
    /// Promoted from `RuntimeDiscovered` by the `2026-08-27-antminer17-unlock-armada`
    /// campaign (agent B1). Stock-RE verdict (A1 §V1, HIGH): T17 is S17-class —
    /// BOOT.bin variant A is byte-identical to S17's, the dsPIC33EP16GS202 flow
    /// (no `init_pic_one_chain`), per-chain pattern file `/dev/07701_pattern_30.txt`
    /// (hashboard **BHB07701**, sibling of S17's BHB07601). The earlier
    /// `RuntimeDiscovered` posture was correct only while the signed bmminer's
    /// common updater filename was the sole evidence; the pattern-file + BOOT.bin
    /// + shared-gram triangulation settles the dsPIC G2a plan. Geometry 30
    /// BM1397/chain × 3 chains = 90. Lane reuse note: see `am2_s17`.
    pub const fn am2_t17() -> Self {
        Self {
            board_target: "am2-t17",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Zynq,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::S17Hybrid,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::StockFpga,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1397,
            voltage_controller: VoltageControllerClass::DsPic33Ep,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            // 2026-08-27 armada (C1): B2 shipped the package-only board lane.
            enablement: S17_NATIVE_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// T17+ (am2-t17plus) — BM1397 hybrid runtime lane (2026-08-27).
    ///
    /// Promoted from management-only by the `2026-08-27-antminer17-unlock-armada`
    /// campaign (agent B1) after controller-ABI adjudication. Hashboard is
    /// **BHB07702** (44 BM1397/chain × 3 chains = 132 — stock
    /// `/dev/07702_pattern_44.txt`, A1 §V2). Stock-RE verdict (A1 §V1, HIGH):
    /// the T17+ class is S17+-class — `init_pic_one_chain` + `pic1704_*` flow,
    /// **PIC16F1704** (`T17+PIC.hex`), G2b raw S9-family frame dialect (A3 §2).
    /// The prior `DsPic33Ep` value was an adapter placeholder from the BM1396
    /// correction era, superseded by the 17-family controller-ABI RE. Lane reuse
    /// note: see `am2_s17`.
    pub const fn am2_t17plus() -> Self {
        Self {
            board_target: "am2-t17plus",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Zynq,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::S17Hybrid,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::StockFpga,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1397,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            // 2026-08-27 armada (C1): B2 shipped the package-only board lane.
            enablement: S17_NATIVE_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact S17e BHB16601 factory-profile native route. The distinct signed
    /// source supplies 135 per-chip factory targets, interval1, 6-Mbaud work,
    /// fixed Baseline ADC and post-ramp working voltage. Native construction
    /// still requires exact boot/fabric/GPIO identity, fresh PIC/fan/rail/thermal
    /// observations and 135 live responses per observed present chain.
    /// No T17e calibration, adapted pass, generic PIC adapter or fixed physical
    /// chain count can substitute. Removable SD publication is separate from
    /// persistent installation; physical qualification and mining remain off.
    pub const fn am2_s17e() -> Self {
        Self {
            board_target: "am2-s17e",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Bm1396,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Bm1396Native,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::StockFpga,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1396,
            voltage_controller: VoltageControllerClass::Bm1396FramedI2c11,
            slot_policy: SlotPolicy::LabGated,
            enablement: BM1396_NATIVE_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// Exact T17e BHB16701 cold-300 native route. The source-bound runtime owns
    /// FPGA/PIC startup, factory calibration, thermal populations, work and
    /// terminal/watchdog closeout. Native admission still checks this boot's
    /// exact fabric, reserved DMA, GPIO identity and all 78 responses per
    /// selected present chain. A descriptor is never a hardware observation.
    ///
    /// S17e's BHB16601/135-chip factory startup remains a separate source branch.
    /// T17e's physical PIC16F1704 uses the BM1396 framed application ABI;
    /// it cannot select the legacy S9 PIC adapter. No static chain count,
    /// installation authority or default mining is inferred from this route.
    pub const fn am2_t17e() -> Self {
        Self {
            board_target: "am2-t17e",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Bm1396,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Bm1396Native,
                generic_construction: GenericConstruction::Refused,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::StockFpga,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1396,
            voltage_controller: VoltageControllerClass::Bm1396FramedI2c11,
            slot_policy: SlotPolicy::LabGated,
            enablement: BM1396_NATIVE_MEDIA_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// TD-003 scaffolding: T19 — management-only, with no artifact producer.
    ///
    /// Gauntlet B6 first-party stock adjudication (2026-09-02, evidence-only —
    /// no facet changed): the stock T19 `topol.conf`
    ///
    /// pins **NBT1903 = BM1398P, 76 ASICs/chain** (8x10 grid, 38 domains x 2,
    /// addr interval 3 — geometry pinned as
    /// `bm1398_protocol::T19_NBT1903_BOARD_GEOMETRY`, the same physical bin
    /// family as the S19's NBS1902), controller **PIC1704 @ 0x20** (+4 LM75A),
    /// PSU **AWP12 @ 0x10 gpio 907** with `power.version [67,113,116,117,118]`,
    /// stock `levels.json` ladder 550-625 MHz at 14.00-14.40 V (centivolts;
    /// `dcentrald-silicon-profiles::s19_family_stock`). The
    /// `voltage_controller: DsPic33Ep` label carries the same
    /// carried-placeholder caveat as [`Self::am2_s19pro`] (stock says
    /// PIC16F1704); flip adjudication stays with the promotion-time DCENT_EE
    /// review. Chain population (VNish says 3x76) is a live-capture datum.
    pub const fn am2_t19() -> Self {
        Self {
            board_target: "am2-t19",
            cooling_medium: None,
            cut_ladder: CANONICAL_FORCED_AIR_LADDER,
            supervisor_class: SupervisorClass::Am2Zynq,
            runtime_status: RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Am2Bm1398Native,
                generic_construction: GenericConstruction::ManagementOnly,
            },
            family: BoardFamily::Zynq,
            chain_transport: ChainTransportKind::FpgaUio,
            work_engine: WorkEngineKind::FpgaWorkFifo,
            asic_protocol: AsicProtocolIdentity::Bm1398,
            voltage_controller: VoltageControllerClass::Pic16F1704,
            slot_policy: SlotPolicy::ZynqAbFwSetenv,
            enablement: ZYNQ_RUNTIME_ONLY_ENABLEMENT,
            release_channel: ReleaseChannel::Beta,
            first_install_supported: false,
            mining_default_enabled: false,
        }
    }

    /// First-install compatibility view. A Beta channel alone does not
    /// manufacture a storage writer or a supported source-OS transition.
    pub const fn public_beta_install(&self) -> bool {
        self.release_channel.is_publishable() && self.first_install_supported
    }

    /// Whether product install (signed public beta package) is appropriate.
    ///
    /// Channel eligibility and first-install capability are independent: an
    /// implemented engine does not supply a persistent storage writer.
    pub fn is_public_beta_install_target(board_target: &str) -> bool {
        Self::lookup(board_target)
            .map(|d| d.public_beta_install())
            .unwrap_or(false)
    }

    /// Bind the protocol declared by this target to independent runtime ASIC
    /// evidence and return a non-forgeable admission proof.
    pub fn admit_asic_protocol(
        &self,
        configured_or_observed: Option<AsicProtocolIdentity>,
        required: AsicProtocolIdentity,
    ) -> Result<AsicProtocolAdmission, String> {
        if self.asic_protocol != required {
            return Err(format!(
                "BoardDesc {} declares ASIC protocol {:?}, incompatible with engine requiring {:?}",
                self.board_target, self.asic_protocol, required
            ));
        }
        if configured_or_observed != Some(required) {
            return Err(format!(
                "BoardDesc {} requires exact {:?} runtime ASIC evidence, got {:?}",
                self.board_target, required, configured_or_observed
            ));
        }
        Ok(AsicProtocolAdmission { identity: required })
    }

    /// Validate this row's declared [`Self::cut_ladder`] against its declared
    /// [`Self::cooling_medium`].
    ///
    /// This is the per-row half of the registry-wide gate
    /// `every_registered_row_has_a_valid_cut_ladder`. It refuses, fail-closed:
    /// an empty ladder; a terminal rung that is not a power cut; a fan raise
    /// that precedes every hash-reducing rung (cut-before-noise); and — the
    /// axis-4 rule — **any** [`CutRung::RaiseFansToCap`] on a row that declares
    /// a medium with no fan actuator. On such a board the rung must be
    /// ABSENT, not zero: a no-op rung can *satisfy* the ladder while the board
    /// keeps heating.
    pub fn validate_cut_ladder(&self) -> Result<(), CutLadderError> {
        validate_cut_ladder(self.cooling_medium, self.cut_ladder)
    }

    /// The canonical ladder implied by this row's declared medium, or the
    /// forced-air ladder when the medium is undeclared (fans stay managed).
    pub fn canonical_cut_ladder(&self) -> &'static [CutRung] {
        match self.cooling_medium {
            Some(m) => canonical_cut_ladder(m.cooling_class()),
            None => CANONICAL_FORCED_AIR_LADDER,
        }
    }

    /// Registry-derived thermal-supervisor lane for a `/etc/dcentos/board_target`
    /// marker.
    ///
    /// **This is the drop-in replacement for `dcentrald-thermal`'s
    /// `SupervisorPlatform::from_board_target`** (Round-15 A9 finding F-8).
    /// The difference that matters: this resolves through the registry and the
    /// single-source alias table ([`canonical_board_target`]), so an
    /// **unregistered** marker gets [`SupervisorClass::Unclassified`] instead
    /// of inheriting a sibling SKU's lane from a `starts_with("am1")` /
    /// `contains("s9")` string prefix.
    ///
    /// Marker handling matches the classifier it replaces: leading/trailing
    /// whitespace is trimmed and comparison is ASCII-lowercase, so
    /// `"  AM1-S9\n"` resolves like `"am1-s9"`. Anything that does not resolve
    /// to a registered row fails closed.
    pub fn supervisor_class_for_target(marker: &str) -> SupervisorClass {
        let m = marker.trim().to_ascii_lowercase();
        Self::lookup(canonical_board_target(&m))
            .map(|d| d.supervisor_class)
            .unwrap_or(SupervisorClass::Unclassified)
    }

    /// Lookup a static desc by `board_target` string (trim-sensitive exact match).
    ///
    /// Returns `None` for unknown targets — callers must fail closed or use
    /// management-only defaults (ADR-0002 scaffolding rules).
    pub fn lookup(board_target: &str) -> Option<&'static BoardDesc> {
        Self::all_registered()
            .iter()
            .find(|d| d.board_target == board_target)
    }

    /// All registered descriptors (for matrix generators / tests).
    ///
    /// Grow this static list when adding targets — not a new `*_mining.rs`.
    pub fn all_registered() -> &'static [BoardDesc] {
        static REGISTRY: &[BoardDesc] = &[
            BoardDesc::am1_s9(),
            BoardDesc::am1_s9i(),
            BoardDesc::am1_s9j(),
            BoardDesc::am1_s9se(),
            BoardDesc::am1_s9k(),
            BoardDesc::am1_s9_hydro(),
            BoardDesc::am1_s11(),
            BoardDesc::am1_s15(),
            BoardDesc::am1_t15(),
            BoardDesc::am1_t9plus(),
            BoardDesc::am2_s19jpro(),
            BoardDesc::am2_s19j_classic(),
            BoardDesc::am2_s19pro(),
            BoardDesc::am2_s19(),
            BoardDesc::am2_s19i(),
            BoardDesc::am2_s19a(),
            BoardDesc::am2_s19plus(),
            BoardDesc::am2_s17(),
            BoardDesc::am2_s17plus(),
            BoardDesc::am2_t17(),
            BoardDesc::am2_t17plus(),
            BoardDesc::am2_s17e(),
            BoardDesc::am2_t17e(),
            BoardDesc::am2_t19(),
            BoardDesc::am3_bb(),
            BoardDesc::am3_bb_s19jpro(),
            BoardDesc::am3_s21(),
            BoardDesc::am3_s21pro(),
            BoardDesc::am3_s21xp(),
            BoardDesc::amlogic_s21plus(),
            BoardDesc::am3_t21(),
            BoardDesc::am3_s19kpro(),
            BoardDesc::am3_s19kpro_nopic(),
            BoardDesc::am3_s19xp(),
            BoardDesc::am3_s19jxp(),
            BoardDesc::am3_s19jproa(),
            BoardDesc::am3_s19jproplus(),
            BoardDesc::am3_s19jpro_aml(),
            BoardDesc::cv1835_s19jpro(),
            BoardDesc::bcb100_s19jpro(),
        ];
        REGISTRY
    }

    /// Whether this target is allowed to auto-route first install from a
    /// non-DCENT_OS source without lab overrides.
    pub fn product_install_allowed(&self) -> bool {
        self.public_beta_install()
            && matches!(
                self.enablement.install_authorization,
                InstallAuthorization::PublicBeta | InstallAuthorization::Production
            )
    }
}

/// Non-canonical `board_target` spellings accepted across registries — build
/// lanes, acceptance SKUs (`scripts/hw-acceptance/skus.conf`), and historical /
/// vendor names — mapped to the single registered [`BoardDesc`] key each
/// resolves to.
///
/// This is the ONE source of truth for `board_target` aliasing. Cross-registry
/// gates and consumers should canonicalize through [`canonical_board_target`]
/// rather than re-encoding the mapping inline. Before this table existed the
/// same `am2-s19jpro-zynq` → `am2-s19j` fact was re-spelled independently in
/// `platform/zynq.rs`, `platform/am2_controller.rs`, `serial_chain.rs`, and the
/// acceptance-inventory test — each a place it could silently drift.
///
/// Invariants (pinned by `board_target_aliases_resolve_and_never_shadow`):
/// every value MUST be a registered target, and every key MUST NOT itself be a
/// registered target (an alias is a non-canonical spelling, never a real key).
pub const BOARD_TARGET_ALIASES: &[(&str, &str)] = &[
    // S19j Pro Zynq (BM1362) beta tier: the canonical /etc/dcentos/board_target
    // and the `S19jPro` acceptance SKU spell it `am2-s19jpro-zynq`; the
    // registered descriptor key is `am2-s19j` ( beta tier; skus.conf).
    ("am2-s19jpro-zynq", "am2-s19j"),
    ("am2-s19jpro", "am2-s19j"),
    // S19k Pro (2026-09-12, drift13 #5 adjudication): `am3-s19kpro` used to be
    // an alias to `am3-s19k` while the release-capsule policy, lane scripts,
    // and campaign docs consistently spelled the target `am3-s19kpro`. The
    // deployed S19k Pro NoPic image stamps exactly that marker, so
    // `am3-s19kpro` is now a REGISTERED row in its own right
    // ([`BoardDesc::am3_s19kpro_nopic`]) and an alias here would shadow a real
    // key. The guarded PIC-era runtime row keeps the `am3-s19k` key.
];

/// Resolve any accepted `board_target` spelling to its registered
/// [`BoardDesc`] key via [`BOARD_TARGET_ALIASES`].
///
/// Unaliased inputs pass through unchanged: they are either already canonical
/// or genuinely unknown, and the caller still fails closed on a
/// [`BoardDesc::lookup`] miss. This never mints a target — it only rewrites a
/// known alternate spelling.
pub fn canonical_board_target(board_target: &str) -> &str {
    BOARD_TARGET_ALIASES
        .iter()
        .find(|(alias, _)| *alias == board_target)
        .map(|(_, canonical)| *canonical)
        .unwrap_or(board_target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn collect_overlay_board_targets(dir: &Path, targets: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read board overlay tree") {
            let entry = entry.expect("read board overlay entry");
            let file_type = entry.file_type().expect("read overlay entry type");
            if file_type.is_dir() {
                collect_overlay_board_targets(&entry.path(), targets);
            } else if file_type.is_file() && entry.file_name() == "board_target" {
                let target = std::fs::read_to_string(entry.path())
                    .expect("read board_target marker")
                    .trim()
                    .to_string();
                assert!(!target.is_empty(), "board_target marker must not be empty");
                targets.push(target);
            } else if file_type.is_file() && entry.file_name() == "post-build.sh" {
                let post_build =
                    std::fs::read_to_string(entry.path()).expect("read post-build identity stamps");
                for line in post_build.lines().map(str::trim) {
                    if !line.starts_with("echo \"")
                        || !line.contains("${TARGET_DIR}/etc/dcentos/board_target")
                    {
                        continue;
                    }
                    let target = line
                        .strip_prefix("echo \"")
                        .and_then(|rest| rest.split('"').next())
                        .expect("parse post-build board_target stamp");
                    assert!(
                        !target.is_empty(),
                        "post-build board target must not be empty"
                    );
                    targets.push(target.to_string());
                }
            }
        }
    }

    #[test]
    fn channels_follow_implemented_engines_and_never_start_mining() {
        let rows = BoardDesc::all_registered();
        assert_eq!(rows.iter().filter(|d| d.release_channel == ReleaseChannel::Beta).count(), 29);
        assert_eq!(rows.iter().filter(|d| d.release_channel == ReleaseChannel::Unsupported).count(), 11);
        for row in rows {
            assert_eq!(row.release_channel.is_publishable(), row.work_engine != WorkEngineKind::ManagementOnly, "{}", row.board_target);
            assert!(!row.mining_default_enabled, "{}", row.board_target);
        }
    }

    #[test]
    fn beta_targets_are_registered() {
        let s9 = BoardDesc::lookup("am1-s9").expect("am1-s9");
        assert!(s9.public_beta_install());
        assert!(!s9.mining_default_enabled);
        assert_eq!(s9.family, BoardFamily::Zynq);
        assert_eq!(s9.chain_transport, ChainTransportKind::FpgaUio);

        let j = BoardDesc::lookup("am2-s19j").expect("am2-s19j");
        assert!(!j.public_beta_install());
        assert!(!j.product_install_allowed());
        assert_eq!(
            j.enablement.install_authorization,
            InstallAuthorization::PublicBeta
        );
        assert!(j.enablement.allows_persistent_update());
        assert_eq!(j.chain_transport, ChainTransportKind::ZynqHybrid);
        assert_eq!(j.work_engine, WorkEngineKind::SerialWork);
        assert_eq!(j.asic_protocol, AsicProtocolIdentity::Bm1362);
        assert_eq!(j.voltage_controller, VoltageControllerClass::DsPic33Ep);
    }

    #[test]
    fn unknown_target_is_none() {
        assert!(BoardDesc::lookup("am2-not-a-real-sku").is_none());
        assert!(BoardDesc::lookup("").is_none());
    }

    /// H7 G8 required invariant: `EvidenceRetainedNotImplemented` implies a
    /// non-empty evidence list AND NOT `public_beta_install`.
    #[test]
    fn evidence_retained_not_implemented_requires_evidence_and_forbids_public_beta_install() {
        let mut seen = Vec::new();
        for desc in BoardDesc::all_registered() {
            if let RuntimeStatus::EvidenceRetainedNotImplemented { evidence } = desc.runtime_status
            {
                seen.push(desc.board_target);
                assert!(
                    !evidence.is_empty(),
                    "{}: EvidenceRetainedNotImplemented must carry retained evidence",
                    desc.board_target
                );
                for entry in evidence {
                    assert!(
                        !entry.trim().is_empty(),
                        "{}: blank evidence entry",
                        desc.board_target
                    );
                }
                assert!(
                    !desc.public_beta_install(),
                    "{}: a not-implemented target must never be a public-beta install target",
                    desc.board_target
                );
                assert!(
                    !desc.product_install_allowed(),
                    "{}: a not-implemented target must never allow product install",
                    desc.board_target
                );
            }
        }
        assert_eq!(
            seen,
            vec!["cv1835-s19jpro"],
            "exactly cv1835-s19jpro is EvidenceRetainedNotImplemented today; \
             grow this pin deliberately when classifying another target"
        );
    }

    /// The two unconditional constructor refusals are DIFFERENT states and
    /// must never be flattened: Amlogic ROUTES ELSEWHERE (native serial lane,
    /// `amlogic/mod.rs` `AmlogicPlatform::new` refusal), CVitek is genuinely
    /// not implemented with retained evidence (`cvitek.rs` `CViTekPlatform::new`).
    #[test]
    fn cvitek_and_amlogic_refusals_are_distinct_status_classes() {
        let cv = BoardDesc::lookup("cv1835-s19jpro").expect("cv1835-s19jpro");
        assert!(matches!(
            cv.runtime_status,
            RuntimeStatus::EvidenceRetainedNotImplemented { .. }
        ));
        assert!(!cv.runtime_status.permits_mining_lane());

        let s21 = BoardDesc::lookup("am3-s21").expect("am3-s21");
        assert_eq!(
            s21.runtime_status,
            RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::AmlogicNativeSerial,
                generic_construction: GenericConstruction::Refused,
            }
        );
        assert!(s21.runtime_status.permits_mining_lane());

        assert_ne!(cv.runtime_status, s21.runtime_status);
    }

    /// Every registered status must be structurally well-formed (fail closed
    /// on absent evidence) and must agree with the row's own work engine:
    /// a status that names a mining lane must not sit on a management-only
    /// row, and vice versa.
    #[test]
    fn every_registered_runtime_status_is_well_formed_and_agrees_with_work_engine() {
        for desc in BoardDesc::all_registered() {
            assert!(
                desc.runtime_status.is_well_formed(),
                "{}: runtime_status {:?} is not well-formed",
                desc.board_target,
                desc.runtime_status
            );
            let names_mining_lane = desc.runtime_status.permits_mining_lane();
            let management_only = matches!(desc.work_engine, WorkEngineKind::ManagementOnly);
            assert_eq!(
                names_mining_lane, !management_only,
                "{}: runtime_status {:?} disagrees with work_engine {:?}",
                desc.board_target, desc.runtime_status, desc.work_engine
            );
        }
    }

    /// The Amlogic generic-construction refusal (`AmlogicPlatform::new`) is
    /// family-wide, so every Amlogic row that names the native serial lane
    /// must declare `GenericConstruction::Refused` — never `ManagementOnly`.
    #[test]
    fn amlogic_lifecycle_rows_declare_refused_generic_construction() {
        let mut lane_rows = 0;
        for desc in BoardDesc::all_registered()
            .iter()
            .filter(|d| d.family == BoardFamily::Amlogic)
        {
            match desc.runtime_status {
                RuntimeStatus::SpecialisedLifecycle {
                    lane,
                    generic_construction,
                } => {
                    lane_rows += 1;
                    assert_eq!(
                        lane,
                        if desc.board_target == "am3-s19jpro-aml" {
                            LifecycleLane::ClassicAmlNativeSerial
                        } else {
                            LifecycleLane::AmlogicNativeSerial
                        },
                        "{}",
                        desc.board_target
                    );
                    assert_eq!(
                        generic_construction,
                        GenericConstruction::Refused,
                        "{}: Amlogic generic Platform construction is refused by design",
                        desc.board_target
                    );
                }
                RuntimeStatus::ManagementOnlyByPolicy { .. } => {}
                other => panic!(
                    "{}: unexpected Amlogic runtime_status {other:?}",
                    desc.board_target
                ),
            }
        }
        assert_eq!(
            lane_rows, 9,
            "S19k, S21/Pro/XP, XP/jXP and BM1362 classic/A/Plus use distinct native serial lanes"
        );
    }

    /// The retained CV1835 evidence must be real files, not decorative
    /// strings — fail closed on absent evidence (CONTEXT §1.4).
    #[test]
    fn cv1835_retained_evidence_paths_exist_on_disk() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("dcentrald-common lives under DCENT_OS_Antminer/dcentrald");
        let RuntimeStatus::EvidenceRetainedNotImplemented { evidence } =
            BoardDesc::cv1835_s19jpro().runtime_status
        else {
            panic!("cv1835-s19jpro must be EvidenceRetainedNotImplemented");
        };
        for rel in evidence {
            assert!(
                workspace_root.join(rel).is_file(),
                "retained CV1835 evidence path missing on disk: {rel}"
            );
        }
    }

    #[test]
    fn every_shipped_board_target_stamp_has_an_exact_descriptor() {
        let project_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("dcentrald-common lives under DCENT_OS_Antminer/dcentrald");
        let mut targets = Vec::new();
        collect_overlay_board_targets(
            &project_root.join("br2_external_dcentos/board"),
            &mut targets,
        );
        targets.sort();
        targets.dedup();
        assert!(!targets.is_empty(), "expected shipped board_target markers");
        for target in targets {
            assert!(
                BoardDesc::lookup(&target).is_some(),
                "shipped overlay board_target {target:?} is absent from BoardDesc"
            );
        }
    }

    #[test]
    fn amlogic_bm1366_board_descs_preserve_voltage_evidence_boundaries() {
        // RE-4A / S19k BETA has exact Has_Pic:false evidence. X19 XP evidence
        // does not settle PIC-versus-NoPic, so ASIC identity alone must not
        // let those package-only rows inherit the S19k controller choice.
        let s19k = BoardDesc::am3_s19kpro();
        assert_eq!(s19k.asic_protocol, AsicProtocolIdentity::Bm1366);
        assert_eq!(s19k.voltage_controller, VoltageControllerClass::NoPic);

        for desc in [BoardDesc::am3_s19xp(), BoardDesc::am3_s19jxp()] {
            assert_eq!(desc.asic_protocol, AsicProtocolIdentity::Bm1366);
            assert_eq!(
                desc.voltage_controller,
                VoltageControllerClass::NoPic,
                "{} must use the production PSU controller without board PIC traffic",
                desc.board_target
            );
            assert!(!desc.mining_default_enabled);
            assert!(!desc.public_beta_install());
        }
    }

    /// B8 (2026-09-02): the XP-pair rows are the BoardDesc carriers of the
    /// settled stock contracts (Phase A §3.8) but stay denied/capture-first —
    /// geometry evidence is NOT runtime admission, and the pair's PSU
    /// dialect split (APW12 vs APW17) forbids one shared carrier.
    #[test]
    fn xp_pair_rows_join_native_serial_with_distinct_110_chip_profiles() {
        use crate::bm1366_serial_platform::{
            bm1366_dispatch_admitted_serial_platform, bm1366_serial_platform_for,
        };
        for desc in [BoardDesc::am3_s19xp(), BoardDesc::am3_s19jxp()] {
            assert_eq!(desc.work_engine, WorkEngineKind::SerialWork);
            assert_eq!(desc.release_channel, ReleaseChannel::Beta);
            assert_eq!(desc.slot_policy, SlotPolicy::LabGated);
            assert!(!desc.mining_default_enabled);
            let profile = bm1366_dispatch_admitted_serial_platform(desc.board_target).unwrap();
            assert_eq!(profile.expected_chips_per_uart, 110);
            assert_eq!(
                desc.runtime_status,
                RuntimeStatus::SpecialisedLifecycle {
                    lane: LifecycleLane::AmlogicNativeSerial,
                    generic_construction: GenericConstruction::Refused
                }
            );
        }
        // PSU dialect split is pinned on both carriers.
        let s19xp = bm1366_serial_platform_for("am3-s19xp").unwrap();
        let s19jxp = bm1366_serial_platform_for("am3-s19jxp").unwrap();
        assert!(s19xp.stock_basis.contains("APW12"));
        assert!(!s19xp.stock_basis.contains("APW17"));
        assert!(s19jxp.stock_basis.contains("APW17"));
        assert!(!s19jxp.stock_basis.contains("APW12"));
        // And the pair stays distinct from the one admitted runtime row.
        let s19k = BoardDesc::am3_s19kpro();
        assert_eq!(s19k.work_engine, WorkEngineKind::SerialWork);
        let admitted = bm1366_dispatch_admitted_serial_platform("am3-s19k").unwrap();
        assert_eq!(admitted.expected_chips_per_uart, 77);
        assert_ne!(admitted.board_target, s19xp.board_target);
        assert_ne!(admitted.board_target, s19jxp.board_target);
    }

    #[test]
    fn s19k_overlay_post_build_and_descriptor_share_runtime_identity() {
        let descriptor = BoardDesc::lookup("am3-s19k").expect("registered S19k runtime target");
        assert_eq!(descriptor, &BoardDesc::am3_s19kpro());
        // 2026-09-12 (drift13 #5 adjudication, option b): the build-lane name
        // `am3-s19kpro` is no longer an unresolved alias — it is the DISTINCT
        // deployed NoPic persistent-startup row. The old pin
        // (`lookup("am3-s19kpro") == None`) is replaced by this exact-row pin;
        // the guarded PIC-era row above keeps the `am3-s19k` key.
        assert_eq!(
            BoardDesc::lookup("am3-s19kpro"),
            Some(&BoardDesc::am3_s19kpro_nopic()),
            "the deployed S19k Pro NoPic marker must resolve to its own exact row"
        );
        assert_ne!(
            BoardDesc::am3_s19kpro(),
            BoardDesc::am3_s19kpro_nopic(),
            "guarded PIC-era and NoPic S19k Pro rows must stay distinct rows"
        );

        let post_build =
            include_str!("../../../br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh");
        let stamps: Vec<_> = post_build
            .lines()
            .filter(|line| line.contains("${TARGET_DIR}/etc/dcentos/board_target"))
            .collect();
        assert_eq!(
            stamps.len(),
            1,
            "S19k post-build must stamp one unambiguous runtime board target"
        );
        assert!(
            stamps[0].contains(r#"echo "am3-s19k""#),
            "S19k post-build target drifted from BoardDesc: {}",
            stamps[0]
        );
        assert_eq!(descriptor.work_engine, WorkEngineKind::SerialWork);
        assert!(descriptor.runtime_status.permits_mining_lane());
        assert_eq!(
            descriptor.enablement.update_maturity,
            ImplementationMaturity::Experimental
        );
        assert_eq!(
            descriptor.enablement.install_authorization,
            InstallAuthorization::LabOnly
        );
        assert!(descriptor.enablement.allows_persistent_update());
        assert_eq!(
            descriptor.enablement.recovery_maturity,
            RecoveryMaturity::EvidenceOnly
        );
        assert!(!descriptor.enablement.allows_restore());
        assert_eq!(descriptor.supervisor_class, SupervisorClass::Am3Aml);
    }

    /// 2026-09-12 (drift13 #5 adjudication, option b — R10 board join): the
    /// deployed S19k Pro NoPic persistent-startup row must stay a distinct,
    /// fail-closed identity. Lineage facts (BM1366 / NoPic / Serial /
    /// Am3Aml) are pinned; every authority facet is pinned shut.
    #[test]
    fn am3_s19kpro_nopic_row_is_the_distinct_deployed_fail_closed_identity() {
        let desc = BoardDesc::lookup("am3-s19kpro").expect("deployed NoPic row registered");
        assert_eq!(desc, &BoardDesc::am3_s19kpro_nopic());

        // Distinctness: the guarded PIC-era row keeps am3-s19k; there is no
        // alias left to conflate the two image identities.
        assert_ne!(desc, &BoardDesc::am3_s19kpro());
        assert_eq!(
            canonical_board_target("am3-s19kpro"),
            "am3-s19kpro",
            "the deployed marker must be its own registered key, not an alias"
        );
        assert_eq!(
            BoardDesc::supervisor_class_for_target("am3-s19kpro"),
            SupervisorClass::Unclassified,
            "non-executable NoPic row keeps its thermal-supervisor lane \
             Unclassified (registry-wide inheritance guard; the deployed \
             unit's supervisor facts stay unadmitted with the serial route)"
        );

        // Held-bytes lineage only (skus.conf S19kPro row + overlay
        // dcentrald.toml: BM1366, 77 chips x3 chains, NoPic TAS5782M).
        assert_eq!(desc.family, BoardFamily::Amlogic);
        assert_eq!(desc.chain_transport, ChainTransportKind::Serial);
        assert_eq!(desc.asic_protocol, AsicProtocolIdentity::Bm1366);
        assert_eq!(desc.voltage_controller, VoltageControllerClass::NoPic);
        assert_eq!(desc.slot_policy, SlotPolicy::LabGated);

        // Fail-closed runtime posture: no admitted native serial route.
        assert_eq!(desc.work_engine, WorkEngineKind::ManagementOnly);
        assert!(!desc.runtime_status.permits_mining_lane());

        // Fail-closed authority posture: no artifact claim (the nopic
        // builder's output basename collides with the guarded lane's
        // published artifact), no persistent update, no install, no
        // public beta, no default mining.
        assert_eq!(desc.enablement.artifact_kind, ArtifactKind::None);
        assert_eq!(
            desc.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert!(!desc.enablement.allows_persistent_update());
        assert!(!desc.public_beta_install());
        assert!(!desc.product_install_allowed());
        assert_eq!(desc.release_channel, ReleaseChannel::Unsupported);
        assert!(!desc.mining_default_enabled);


    }

    #[test]
    fn generic_bb_post_build_has_a_management_only_descriptor() {
        let descriptor = BoardDesc::lookup("am3-bb").expect("registered generic BB target");
        assert_eq!(descriptor.family, BoardFamily::BeagleBone);
        assert_eq!(descriptor.work_engine, WorkEngineKind::ManagementOnly);
        assert_eq!(descriptor.asic_protocol, AsicProtocolIdentity::Bm1362);

        let post_build =
            include_str!("../../../br2_external_dcentos/board/beaglebone/am3-bb/post-build.sh");
        let stamps: Vec<_> = post_build
            .lines()
            .filter(|line| line.contains("${TARGET_DIR}/etc/dcentos/board_target"))
            .collect();
        assert_eq!(stamps.len(), 1, "generic BB must stamp one board target");
        assert!(
            stamps[0].contains(r#"echo "am3-bb""#),
            "generic BB post-build target drifted from BoardDesc: {}",
            stamps[0]
        );
    }

    #[test]
    fn shipped_serial_configs_match_descriptor_asic_identity() {
        let shipped_configs = [
            (
                "am2-s19j",
                include_str!("../../configs/dcentrald_s19jpro_am2_baked_default.toml"),
            ),
            (
                "am2-s19pro",
                include_str!("../../configs/dcentrald_s19pro_am2_baked_default.toml"),
            ),
            (
                "am2-s17p",
                include_str!("../../configs/dcentrald_s17pro_am2_baked_default.toml"),
            ),
            (
                "am3-bb",
                include_str!("../../../br2_external_dcentos/board/beaglebone/am3-bb/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-bb-s19jpro",
                include_str!("../../../br2_external_dcentos/board/beaglebone/am3-bb-s19jpro/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-s21",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-s21/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-s21pro",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-s21pro/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-s21xp",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-s21xp/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-t21",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-t21/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-s19k",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/dcentrald.toml"),
            ),
            (
                "am3-s19jpro-aml",
                include_str!("../../../br2_external_dcentos/board/amlogic/am3-s19jpro-aml/rootfs-overlay/etc/dcentrald.toml"),
            ),
        ];

        for (board_target, config) in shipped_configs {
            let descriptor =
                BoardDesc::lookup(board_target).expect("shipped config target is registered");
            let configured_protocols: Vec<_> = config
                .lines()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.starts_with('#') {
                        return None;
                    }
                    let (key, value) = line.split_once('=')?;
                    if !matches!(key.trim(), "chip" | "serial_chip_type") {
                        return None;
                    }
                    let label = value.trim().trim_matches('"');
                    Some(
                        AsicProtocolIdentity::from_chip_label(label).unwrap_or_else(|| {
                            panic!("{board_target} shipped config has unknown ASIC label {label}")
                        }),
                    )
                })
                .collect();
            assert!(
                !configured_protocols.is_empty(),
                "{board_target} shipped config has no exact ASIC identity"
            );
            assert!(
                configured_protocols
                    .iter()
                    .all(|configured| *configured == descriptor.asic_protocol),
                "{board_target} shipped config ASIC identity {:?} disagrees with descriptor {:?}",
                configured_protocols,
                descriptor.asic_protocol
            );
        }

        let acceptance_skus = include_str!("../../../scripts/hw-acceptance/skus.conf");
        assert!(
            acceptance_skus
                .lines()
                .any(|line| line.starts_with("T21|am3-t21|aarch64|BM1368|0x1368|")),
            "T21 acceptance inventory must share the descriptor ASIC identity"
        );

        // Lane I 2026-08-31 (S21 geometry resolution): the full SKU is
        // 3 chains x 108 chips = 324 (factory jig Asic_Num=108, 12 domains x 9,
        // HASH_ON_PLUG=0x7 three-slot control board; `a lab unit` recon "Chains: 3").
        // enum_expect stays 108 because the held `a lab unit` bench unit has exactly
        // ONE populated board (slot 2, ttyS2) — a unit datum, not the SKU.
        // The falsified "4x55=220" catalog claim must not return; the row note
        // must keep stating the resolved full-SKU geometry. Adjudication:
        //
        let s21_row = acceptance_skus
            .lines()
            .find(|line| line.starts_with("S21|"))
            .expect("S21 acceptance row present");
        assert!(
            s21_row.starts_with("S21|am3-s21|aarch64|BM1368|0x1368|108|"),
            "S21 acceptance row must keep the live-pinned held-unit enumeration (108)"
        );
        assert!(
            s21_row.contains("3x108"),
            "S21 acceptance note must state the resolved full-SKU geometry (3x108=324)"
        );
    }

    /// Lane J 2026-09-01 (BM1370 S21 Pro/XP geometry resolution): the stale
    /// "1x195" (S21 Pro) and "4x220+" (S21 Pro/XP) catalog framings are
    /// falsified. Two independent held sources agree first-hand on the full-SKU
    /// geometry: bosminer `model-list.json` (A3HB70601/70501 per-hashboard
    /// counts 65/91) + the ePIC jig hashboard DB (A3HB706xx/705xx `chain_num=3`).
    /// The daemon SSOT `dcentrald-silicon-profiles/src/bm1370.rs` already pins
    /// 3x65=195. Pin the acceptance rows so neither framing can return.
    /// Adjudication:
    /// .
    #[test]
    fn acceptance_inventory_s21pro_and_s21xp_state_resolved_bm1370_geometry() {
        let acceptance_skus = include_str!("../../../scripts/hw-acceptance/skus.conf");

        let s21pro_row = acceptance_skus
            .lines()
            .find(|line| line.starts_with("S21Pro|"))
            .expect("S21Pro acceptance row present");
        assert!(
            s21pro_row.starts_with("S21Pro|am3-s21pro|aarch64|BM1370|0x1370|195|"),
            "S21 Pro acceptance row must keep BM1370 and the 195-chip full-SKU total"
        );
        assert!(
            s21pro_row.contains("3x65"),
            "S21 Pro acceptance note must state the resolved 3x65=195 geometry, not 1x195"
        );
        assert!(
            !s21pro_row.contains("1x195") && !s21pro_row.contains("4x220"),
            "S21 Pro acceptance note must not reintroduce the falsified 1x195 / 4x220 framing"
        );

        let s21xp_row = acceptance_skus
            .lines()
            .find(|line| line.starts_with("S21XP|"))
            .expect("S21XP acceptance row present");
        assert!(
            s21xp_row.starts_with("S21XP|am3-s21xp|aarch64|BM1370|0x1370|273|"),
            "S21 XP acceptance row must keep BM1370 and the 273-chip full-SKU total"
        );
        assert!(
            s21xp_row.contains("3x91"),
            "S21 XP acceptance note must state the resolved 3x91 production route"
        );
    }

    #[test]
    fn acceptance_inventory_matches_registered_asic_protocols() {
        let acceptance_skus = include_str!("../../../scripts/hw-acceptance/skus.conf");
        let mut validated_rows = 0;
        for line in acceptance_skus.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split('|').collect();
            assert_eq!(fields.len(), 11, "malformed acceptance row: {line}");
            // Single source of truth for the alias mapping (was an inline
            // literal that duplicated BOARD_TARGET_ALIASES).
            let runtime_target = canonical_board_target(fields[1]);
            let descriptor = match BoardDesc::lookup(runtime_target) {
                Some(descriptor) => descriptor,
                None if fields[8] == "NOT-IMPLEMENTED" => continue,
                None => panic!(
                    "{} is {} but has no registered BoardDesc for {}",
                    fields[0], fields[8], runtime_target
                ),
            };

            let configured_protocol = AsicProtocolIdentity::from_chip_label(fields[3])
                .unwrap_or_else(|| panic!("{} has unknown ASIC label {}", fields[0], fields[3]));
            if fields[4] == "0" {
                assert_eq!(
                    fields[8], "NOT-IMPLEMENTED",
                    "{} may omit a wire ChipID only while capture-first",
                    fields[0]
                );
                match descriptor.distinct_asic_catalog_identity() {
                    Some(AsicCatalogIdentity::Bm1396) => {
                        assert_eq!(
                            configured_protocol,
                            AsicProtocolIdentity::Bm1396,
                            "{} unresolved-wire catalog identity drift",
                            fields[0]
                        );
                        assert_eq!(
                            descriptor.asic_protocol,
                            AsicProtocolIdentity::RuntimeDiscovered,
                            "{} has no wire ChipID and must not admit a protocol",
                            fields[0]
                        );
                    }
                    None => {
                        assert_eq!(
                            descriptor.asic_protocol, configured_protocol,
                            "{} vendor configuration identity disagrees with BoardDesc {}",
                            fields[0], runtime_target
                        );
                    }
                }
                validated_rows += 1;
                continue;
            }
            let chip_id_text = fields[4]
                .strip_prefix("0x")
                .unwrap_or_else(|| panic!("{} has malformed ChipID {}", fields[0], fields[4]));
            let chip_id = u16::from_str_radix(chip_id_text, 16)
                .unwrap_or_else(|_| panic!("{} has malformed ChipID {}", fields[0], fields[4]));
            let chip_protocol = AsicProtocolIdentity::from_chip_id(chip_id);
            match descriptor.distinct_asic_catalog_identity() {
                Some(AsicCatalogIdentity::Bm1396) => {
                    assert_eq!(
                        configured_protocol,
                        AsicProtocolIdentity::Bm1396,
                        "{} acceptance catalog identity drift",
                        fields[0]
                    );
                    assert_eq!(
                        chip_protocol,
                        Some(descriptor.asic_protocol),
                        "{} acceptance wire ChipID disagrees with BoardDesc {}",
                        fields[0],
                        runtime_target
                    );
                }
                None => {
                    assert_eq!(
                        chip_protocol,
                        Some(configured_protocol),
                        "{} acceptance ASIC label/ChipID mismatch",
                        fields[0]
                    );
                    assert_eq!(
                        descriptor.asic_protocol, configured_protocol,
                        "{} acceptance ASIC identity disagrees with BoardDesc {}",
                        fields[0], runtime_target
                    );
                }
            }
            validated_rows += 1;
        }
        assert_eq!(
            validated_rows, 30,
            "registered acceptance coverage changed; classify new aliases explicitly"
        );
    }

    /// `skus.conf` release labels are executable-support claims, not evidence
    /// or artifact-maturity labels. Keep them derived from the registry's
    /// runtime status so a package-only or management-only row cannot enter
    /// live acceptance merely because a tarball exists. Conversely, a real
    /// callable lane must not remain labelled NOT-IMPLEMENTED.
    #[test]
    fn acceptance_release_state_matches_executable_runtime_status() {
        let acceptance_skus = include_str!("../../../scripts/hw-acceptance/skus.conf");
        // 2026-08-27 S17 promotion TRANSITION arm REMOVED (C1 convergence,
        // `2026-08-27-antminer17-unlock-armada`): agent B2 landed the
        // EXPERIMENTAL skus.conf release_state for all four BM1397 17-series
        // targets (rows 32-36), completing the B1 handoff contract. Every row
        // is back under the exact bidirectional equality below.
        //
        // R10 classic AML now has its own source-bound native owner. All
        // first-class rows again obey the same callable-runtime equality;
        // artifact/install maturity remains an independent facet.
        let mut checked = 0;
        for line in acceptance_skus.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split('|').collect();
            assert_eq!(fields.len(), 11, "malformed acceptance row: {line}");
            let descriptor = BoardDesc::lookup(canonical_board_target(fields[1]))
                .unwrap_or_else(|| panic!("{} has no registered BoardDesc", fields[0]));
            let release_claims_callable = matches!(fields[8], "PRODUCTION" | "EXPERIMENTAL");
            assert_eq!(
                release_claims_callable,
                descriptor.runtime_status.permits_mining_lane(),
                "{} ({}) release_state={} contradicts BoardDesc runtime_status={:?}; \
                 artifact/install maturity is orthogonal to callable mining support",
                fields[0],
                fields[1],
                fields[8],
                descriptor.runtime_status
            );
            checked += 1;
        }
        assert_eq!(checked, 30, "acceptance executable-support roster changed");
    }

    // ---- rank 18: cross-registry identity graph ----------------------------
    // These pin the `BoardDesc` ↔ acceptance-SKU ↔ defconfig ↔ alias registries
    // into one resolvable graph so a new spelling or an orphan build lane fails
    // a host gate instead of relying on a human noticing. They complement the
    // already-present artifact/skus/overlay/config reconciliation tests above.

    /// `BOARD_TARGET_ALIASES` integrity: every alias resolves to a registered
    /// target, no alias shadows a real key, keys are unique, and every
    /// canonical/registered target is a fixed point of `canonical_board_target`.
    #[test]
    fn board_target_aliases_resolve_and_never_shadow() {
        let registered: std::collections::BTreeSet<&str> = BoardDesc::all_registered()
            .iter()
            .map(|d| d.board_target)
            .collect();
        let mut seen = std::collections::BTreeSet::new();
        for (alias, canonical) in BOARD_TARGET_ALIASES {
            assert!(
                seen.insert(*alias),
                "duplicate board_target alias key {alias:?}"
            );
            assert!(
                !registered.contains(alias),
                "alias {alias:?} shadows a registered BoardDesc target; an alias must be a \
                 non-canonical spelling, never a real key"
            );
            assert!(
                registered.contains(canonical),
                "alias {alias:?} resolves to {canonical:?}, which is not a registered target"
            );
            // Aliasing is a single hop: a canonical target is never itself aliased.
            assert_eq!(
                canonical_board_target(canonical),
                *canonical,
                "canonical target {canonical:?} must not itself be an alias key"
            );
        }
        for target in &registered {
            assert_eq!(
                canonical_board_target(target),
                *target,
                "registered target {target:?} must canonicalize to itself"
            );
        }
    }

    /// Every acceptance SKU (`skus.conf`) with a registered descriptor resolves
    /// through [`canonical_board_target`]. This isolates
    /// the identity-resolution contract from the ASIC-identity assertion in
    /// `acceptance_inventory_matches_registered_asic_protocols`, and exercises
    /// the shared alias table against the acceptance registry directly.
    #[test]
    fn every_acceptance_sku_board_target_canonicalizes_to_a_registered_descriptor() {
        let acceptance_skus = include_str!("../../../scripts/hw-acceptance/skus.conf");
        let mut resolved = 0;
        for line in acceptance_skus.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split('|').collect();
            assert_eq!(fields.len(), 11, "malformed acceptance row: {line}");
            let canonical = canonical_board_target(fields[1]);
            match BoardDesc::lookup(canonical) {
                Some(_) => resolved += 1,
                // An unregistered target is only tolerated for a scaffold SKU
                // that rides capture-first and refuses before transport. A
                // runnable SKU that fails to resolve is a real drift.
                None if fields[8] == "NOT-IMPLEMENTED" => continue,
                None => panic!(
                    "acceptance SKU {} ({}) board_target {:?} canonicalizes to {:?}, which is \
                     not a registered BoardDesc target",
                    fields[0], fields[8], fields[1], canonical
                ),
            }
        }
        assert_eq!(
            resolved, 30,
            "registered acceptance-SKU coverage changed; reconcile skus.conf against the registry"
        );
    }

    /// Defconfig completeness (the reverse of the forward existence check in
    /// `every_claimed_artifact_has_a_primary_build_driver_lane`): the set of
    /// shipped `dcentos_*_defconfig` files on disk is exactly the set claimed by
    /// [`PRIMARY_ARTIFACT_PRODUCERS`](crate::artifact_producer::PRIMARY_ARTIFACT_PRODUCERS).
    /// Catches an orphan defconfig (a build lane invisible to the registry) or a
    /// producer naming a defconfig that was never shipped.
    #[test]
    fn every_shipped_defconfig_is_claimed_by_a_primary_producer() {
        let configs_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("dcentrald-common lives under DCENT_OS_Antminer/dcentrald")
            .join("br2_external_dcentos/configs");
        let mut shipped: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(&configs_dir).expect("read defconfig dir") {
            let name = entry
                .expect("defconfig dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            if name.starts_with("dcentos_") && name.ends_with("_defconfig") {
                shipped.insert(name);
            }
        }
        assert!(
            !shipped.is_empty(),
            "expected shipped dcentos_*_defconfig files"
        );
        let claimed: std::collections::BTreeSet<String> =
            crate::artifact_producer::PRIMARY_ARTIFACT_PRODUCERS
                .iter()
                .map(|p| p.defconfig.to_string())
                .collect();
        // 2026-09-12 (R10 board join, drift13 #6b): the in-flight S19k Pro
        // NoPic lane ships `dcentos_am3_s19kpro_nopic_defconfig`, but its
        // builder emits `dcentos-sysupgrade-am3-s19kpro.tar` — the exact
        // basename already published by the committed guarded am3-s19k lane —
        // so the producer-table filename-uniqueness pin forbids a second
        // artifact claim until the Lead adjudicates the nopic lane's
        // published-artifact identity. The row
        // ([`BoardDesc::am3_s19kpro_nopic`]) therefore carries artifact None
        // and this defconfig stays a documented, named exception. See
        // evidence/r10/board-join-20260912/SOURCE_NOTE.md.
        const UNCLAIMED_DEPLOYED_LANE_DEFCONFIGS: [&str; 1] =
            ["dcentos_am3_s19kpro_nopic_defconfig"];
        for name in UNCLAIMED_DEPLOYED_LANE_DEFCONFIGS {
            assert!(
                shipped.remove(name),
                "exempted defconfig {name} is not shipped; shrink the exemption list"
            );
        }
        assert_eq!(
            shipped, claimed,
            "shipped dcentos_*_defconfig set drifted from the primary artifact-producer \
             inventory; every defconfig must be claimed by exactly one build lane, and every \
             claimed defconfig must be shipped"
        );
    }

    #[test]
    fn every_claimed_artifact_has_a_primary_build_driver_lane() {
        let project_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("dcentrald-common lives under DCENT_OS_Antminer/dcentrald");
        let build_driver =
            include_str!("../../../scripts/build_in_docker.sh").replace("\r\n", "\n");
        let package_validation_marker = build_driver
            .find("echo \"Package-only validation:\"")
            .expect("package-only validation marker");
        let package_validation_case_start = build_driver[..package_validation_marker]
            .rfind("case ")
            .expect("package-only validation case");
        let package_validation_case =
            &build_driver[package_validation_case_start..package_validation_marker];
        let non_s9_inventory = include_str!("../../../scripts/rebuild_all_non_s9.sh");
        for producer in crate::artifact_producer::PRIMARY_ARTIFACT_PRODUCERS {
            let runtime_target = producer.board_target;
            let build_target = producer.build_target;
            let defconfig = producer.defconfig;
            let overlay = producer.overlay;
            let package_validated = producer.package_validated;
            let tarball = producer.artifact_filename;
            // Shared carrier arms still require an exact producer token in
            // the primary dispatch, followed by the same defconfig, package
            // identity and version verification requirements below.
            let target_dispatch = build_driver
                .split_once("case \"$TARGET\" in\n")
                .expect("primary target dispatch")
                .1
                .split_once("\nesac")
                .expect("terminated primary target dispatch")
                .0;
            let arm_line = target_dispatch
                .lines()
                .find(|line| {
                    line.strip_prefix("    ")
                        .and_then(|line| line.strip_suffix(')'))
                        .is_some_and(|names| names.split('|').any(|name| name == build_target))
                })
                .unwrap_or_else(|| {
                    panic!("{runtime_target} claims an absent build target {build_target}")
                });
            let arm = format!("\n{arm_line}");
            let arm_start = build_driver.find(&arm).unwrap_or_else(|| {
                panic!(
                    "{runtime_target} claims an artifact but build target {build_target} is absent"
                )
            });
            let arm_body = &build_driver[arm_start + arm.len()..];
            let arm_end = arm_body
                .find("\n        ;;")
                .unwrap_or_else(|| panic!("unterminated build target arm {build_target}"));
            let arm_body = &arm_body[..arm_end];
            assert!(
                arm_body.contains(&format!(r#"BR_DEFCONFIG="{defconfig}""#)),
                "{build_target} does not select {defconfig}"
            );
            assert!(
                arm_body.contains(&format!(r#"BOARD_PKG_NAME="{runtime_target}""#)),
                "{build_target} does not package canonical runtime target {runtime_target}"
            );
            assert!(
                project_root
                    .join("br2_external_dcentos/configs")
                    .join(defconfig)
                    .is_file(),
                "{build_target} references missing defconfig {defconfig}"
            );
            let version_overlay =
                format!("/build/DCENT_OS_Antminer/br2_external_dcentos/{overlay}/rootfs-overlay");
            assert!(
                build_driver.matches(&version_overlay).count() >= 2,
                "{build_target} must synchronize and then verify {overlay}/rootfs-overlay"
            );
            if package_validated {
                assert!(
                    package_validation_case.contains(&format!("|{build_target}|"))
                        || package_validation_case.contains(&format!("|{build_target})"))
                        || package_validation_case.contains(&format!("    {build_target}|"))
                        || package_validation_case.contains(&format!("    {build_target})")),
                    "{build_target} artifact bypasses package-only validation"
                );
            }
            if build_target != "s9" {
                assert!(
                    non_s9_inventory.contains(&format!("\n    {build_target}\n")),
                    "{build_target} is absent from the fail-closed non-S9 inventory"
                );
                assert!(
                    non_s9_inventory.contains(&format!(r#"[{build_target}]="{tarball}""#)),
                    "{build_target} inventory mapping does not name {tarball}"
                );
            }
        }
    }

    #[test]
    fn beta_targets_prefer_ab_fw_setenv() {
        assert_eq!(BoardDesc::am1_s9().slot_policy, SlotPolicy::ZynqAbFwSetenv);
        assert_eq!(
            BoardDesc::am2_s19jpro().slot_policy,
            SlotPolicy::ZynqAbFwSetenv
        );
    }

    #[test]
    fn only_beta_flags_match_public_beta_gate_story() {
        let beta: Vec<_> = BoardDesc::all_registered()
            .iter()
            .filter(|d| d.public_beta_install())
            .map(|d| d.board_target)
            .collect();
        assert_eq!(beta, vec!["am1-s9"]);
    }

    #[test]
    fn bb_is_sd_only_not_public_beta() {
        for id in ["am3-bb", "am3-bb-s19jpro"] {
            let bb = BoardDesc::lookup(id).unwrap_or_else(|| panic!("missing {id}"));
            assert!(!bb.public_beta_install());
            assert_eq!(bb.slot_policy, SlotPolicy::SdOnly);
            assert_eq!(bb.family, BoardFamily::BeagleBone);
        }
    }

    #[test]
    fn amlogic_targets_pin_controller_class_and_stay_serial_lab_gated() {
        for (id, voltage_controller) in [
            ("am3-s21", VoltageControllerClass::RuntimeDiscovered),
            ("am3-s21pro", VoltageControllerClass::NoPic),
            ("am3-s21xp", VoltageControllerClass::NoPic),
            ("amlogic-s21plus", VoltageControllerClass::RuntimeDiscovered),
            ("am3-t21", VoltageControllerClass::RuntimeDiscovered),
            ("am3-s19k", VoltageControllerClass::NoPic),
            // 2026-09-12 (R10 board join): the deployed NoPic identity joins
            // the same BM1366/NoPic lineage pin.
            ("am3-s19kpro", VoltageControllerClass::NoPic),
            ("am3-s19xp", VoltageControllerClass::NoPic),
            ("am3-s19jxp", VoltageControllerClass::NoPic),
            ("am3-s19jproa", VoltageControllerClass::NoPic),
            ("am3-s19jproplus", VoltageControllerClass::NoPic),
            (
                "am3-s19jpro-aml",
                VoltageControllerClass::ClassicAmlApplication89,
            ),
        ] {
            let d = BoardDesc::lookup(id).unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(d.family, BoardFamily::Amlogic, "{id}");
            assert_eq!(d.chain_transport, ChainTransportKind::Serial, "{id}");
            assert_eq!(d.voltage_controller, voltage_controller, "{id}");
            assert_eq!(d.slot_policy, SlotPolicy::LabGated, "{id}");
            assert!(!d.product_install_allowed(), "{id}");
        }
    }

    /// The S21-class Amlogic targets are NOT one ASIC. `am3-s21`/`am3-t21` are
    /// BM1368; `am3-s21pro`/`am3-s21xp` are BM1370 — different silicon on the
    /// same A113D control board (queue rank 19 / H1 GAP-3); the evidence-only
    /// `amlogic-s21plus` row (R14) is BM1370 with every executable facet
    /// denied. Pin the per-target
    /// `asic_protocol` so a future edit cannot silently converge a BM1370 SKU
    /// onto the BM1368 identity — the exact "inherit an uncaptured topology"
    /// hazard. `GenericConstruction::Refused` is already pinned family-wide by
    /// `amlogic_lifecycle_rows_declare_refused_generic_construction`; this test
    /// adds the ASIC-identity axis that the runtime-discovered test above omits.
    #[test]
    fn amlogic_s21_class_asic_identity_is_pinned_per_target() {
        for (id, asic) in [
            ("am3-s21", AsicProtocolIdentity::Bm1368),
            ("am3-s21pro", AsicProtocolIdentity::Bm1370),
            ("am3-s21xp", AsicProtocolIdentity::Bm1370),
            ("amlogic-s21plus", AsicProtocolIdentity::Bm1370),
            ("am3-t21", AsicProtocolIdentity::Bm1368),
        ] {
            let d = BoardDesc::lookup(id).unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(d.asic_protocol, asic, "{id} ASIC identity must not drift");
        }
    }

    #[test]
    fn bm1362_aml_a_plus_runtime_and_classic_pic_boundary_are_distinct() {
        for target in ["am3-s19jproa", "am3-s19jproplus"] {
            let d = BoardDesc::lookup(target).unwrap();
            assert_eq!(d.asic_protocol, AsicProtocolIdentity::Bm1362);
            assert_eq!(d.voltage_controller, VoltageControllerClass::NoPic);
            assert_eq!(d.supervisor_class, SupervisorClass::Am3Aml);
            assert!(d.runtime_status.permits_mining_lane());
            assert!(!d.mining_default_enabled);
            assert!(!d.product_install_allowed());
        }
        let classic = BoardDesc::lookup("am3-s19jpro-aml").unwrap();
        assert!(classic.runtime_status.permits_mining_lane());
        assert_eq!(classic.work_engine, WorkEngineKind::SerialWork);
        assert_eq!(
            classic.voltage_controller,
            VoltageControllerClass::ClassicAmlApplication89
        );
        assert_eq!(
            classic.runtime_status,
            RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::ClassicAmlNativeSerial,
                generic_construction: GenericConstruction::Refused,
            }
        );
        assert!(!classic.product_install_allowed());
    }

    #[test]
    fn unimplemented_runtime_targets_are_management_only() {
        // The four BM1397 17-series targets (am2-s17p/am2-s17plus/am2-t17/
        // am2-t17plus) were PROMOTED to the S17 hybrid SerialWork lane on
        // 2026-08-27 (`2026-08-27-antminer17-unlock-armada`, agent B1) and are
        // therefore deliberately absent here; their lane is pinned by
        // `s17_family_never_inherits_legacy_s9_pic16_adapter_from_part_name`.
        // The 2026-09-12 F02 batch adds four more management-only rows
        // (R17's am1-s9-hydro/am2-s19i capture-first rows and the
        // R14 evidence-only amlogic-s21plus row); they belong exactly here.
        // R10 board join: am3-s19kpro is the deployed NoPic persistent-startup
        // identity whose native serial route is deliberately not admitted.
        for id in [
            "am3-bb",
            "cv1835-s19jpro",
            "bcb100-s19jpro",
            "am1-s9-hydro",
            "am2-s19i",
            "am3-s19kpro",
            "amlogic-s21plus",
        ] {
            let descriptor = BoardDesc::lookup(id).unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(
                descriptor.work_engine,
                WorkEngineKind::ManagementOnly,
                "{id} must be rejected before a hardware-owning runtime is constructed"
            );
        }
    }

    /// Mirror of `install_matrix::tests::cv1835_has_no_artifact_or_install_lane`
    /// for the STM32MP15 / BCB100 family (queue rank 12, H6 G-4).
    ///
    /// It asserts against the *projected* install-matrix row rather than the
    /// descriptor, exactly like its CVitek sibling, because the projection is
    /// what docs, CI, and the Toolbox actually consume. Before this row
    /// existed, `install_matrix()` had no `stm32mp15` line at all, so the
    /// family was silently absent instead of visibly refused.
    #[test]
    fn stm32mp15_has_no_artifact_or_install_lane() {
        let row = crate::install_matrix()
            .into_iter()
            .find(|row| row.board_target == "bcb100-s19jpro")
            .expect("STM32MP15 / BCB100 row");
        assert_eq!(row.family, BoardFamily::Stm32Mp15);
        // Unknown, NOT borrowed from a sibling family: no partition map read.
        assert_eq!(row.enablement.storage_topology, StorageTopology::Unknown);
        assert_eq!(row.enablement.update_mechanism, UpdateMechanism::None);
        assert_eq!(
            row.enablement.update_maturity,
            ImplementationMaturity::NotImplemented
        );
        assert_eq!(
            row.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert_eq!(
            row.enablement.recovery_maturity,
            RecoveryMaturity::NotImplemented
        );
        assert_eq!(row.enablement.artifact_kind, ArtifactKind::None);
        assert_eq!(
            row.enablement.artifact_maturity,
            ArtifactMaturity::NotImplemented
        );
        assert!(!row.public_beta_install);
        assert!(!row.persistent_update_allowed);
        assert!(!row.product_install_allowed);
        assert!(!row.ab_sysupgrade);
        assert!(!row.mining_default_enabled);
    }

    /// The all-`Denied` row must genuinely deny, not merely be labelled denied.
    ///
    /// Registering a descriptor is the *only* way a runtime dispatch can get
    /// past `main.rs`'s "no BoardDesc is registered" refusal, so this pins the
    /// three independent facets that keep the next gate closed:
    /// `ManagementOnly` (hard refusal in `runtime_dispatch_admission`),
    /// `RuntimeDiscovered` ASIC protocol (the serial route refuses it, and
    /// `admit_asic_protocol` can never mint a proof for it), and a `None`
    /// transport (no concrete carrier is asserted). Relaxing any one of these
    /// on evidence other than a bench capture re-opens a lane.
    #[test]
    fn bcb100_all_denied_row_cannot_admit_any_mining_lane() {
        let d = BoardDesc::lookup("bcb100-s19jpro").expect("bcb100-s19jpro");
        assert_eq!(d.family, BoardFamily::Stm32Mp15);
        assert_eq!(d.work_engine, WorkEngineKind::ManagementOnly);
        assert_eq!(d.chain_transport, ChainTransportKind::None);
        assert_eq!(d.asic_protocol, AsicProtocolIdentity::RuntimeDiscovered);
        assert_eq!(
            d.voltage_controller,
            VoltageControllerClass::RuntimeDiscovered
        );
        assert_eq!(d.slot_policy, SlotPolicy::LabGated);
        assert!(!d.enablement.allows_persistent_update());
        assert!(!d.enablement.allows_restore());
        assert!(!d.product_install_allowed());
        assert!(!BoardDesc::is_public_beta_install_target("bcb100-s19jpro"));
        assert!(!d.runtime_status.permits_mining_lane());
        assert!(d.runtime_status.is_well_formed());
        assert!(matches!(
            d.runtime_status,
            RuntimeStatus::CaptureFirst { .. }
        ));

        // No concrete ASIC family can ever be admitted from this row: the
        // declared protocol is RuntimeDiscovered, so the declared/required
        // comparison fails before the runtime-evidence comparison is reached.
        for required in [
            AsicProtocolIdentity::Bm1362,
            AsicProtocolIdentity::Bm1366,
            AsicProtocolIdentity::Bm1368,
            AsicProtocolIdentity::Bm1370,
            AsicProtocolIdentity::Bm1398,
        ] {
            assert!(
                d.admit_asic_protocol(Some(required), required).is_err(),
                "bcb100-s19jpro must not admit {required:?}"
            );
        }
    }

    #[test]
    fn cvitek_is_single_slot_and_requires_runtime_controller_discovery() {
        let d = BoardDesc::lookup("cv1835-s19jpro").expect("cv");
        assert_eq!(d.family, BoardFamily::Cvitek);
        assert_eq!(d.slot_policy, SlotPolicy::SingleSlot);
        assert_eq!(d.enablement.storage_topology, StorageTopology::SingleSlot);
        assert_eq!(
            d.enablement.update_mechanism,
            UpdateMechanism::EmmcContentSelectorEvidenceOnly
        );
        assert_eq!(
            d.enablement.update_maturity,
            ImplementationMaturity::NotImplemented
        );
        assert_eq!(
            d.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert_eq!(d.enablement.artifact_kind, ArtifactKind::None);
        assert_eq!(
            d.enablement.artifact_maturity,
            ArtifactMaturity::NotImplemented
        );
        assert_eq!(
            d.enablement.recovery_maturity,
            RecoveryMaturity::NotImplemented
        );
        assert!(!d.enablement.allows_persistent_update());
        assert!(!d.enablement.allows_restore());
        assert_eq!(
            d.voltage_controller,
            VoltageControllerClass::RuntimeDiscovered
        );
        assert_eq!(d.chain_transport, ChainTransportKind::UartTrans);
        assert_eq!(d.work_engine, WorkEngineKind::ManagementOnly);
    }

    #[test]
    fn s19_nbs1902_is_distinct_from_executable_s19pro_nbp1901() {
        let s19 = BoardDesc::lookup("am2-s19").unwrap();
        let pro = BoardDesc::lookup("am2-s19pro").unwrap();
        assert_eq!(canonical_board_target("am2-s19"), "am2-s19");
        assert_eq!(s19.asic_protocol, AsicProtocolIdentity::Bm1398);
        assert_eq!(s19.voltage_controller, VoltageControllerClass::Pic16F1704);
        assert_eq!(s19.work_engine, WorkEngineKind::FpgaWorkFifo);
        assert!(matches!(
            s19.runtime_status,
            RuntimeStatus::SpecialisedLifecycle { lane: LifecycleLane::Am2Bm1398Native, .. }
        ));
        assert!(matches!(
            pro.runtime_status,
            RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Am2Bm1398Native,
                ..
            }
        ));
        assert_ne!(s19.board_target, pro.board_target);
    }

    #[test]
    fn registry_has_no_duplicate_targets() {
        let ids: Vec<_> = BoardDesc::all_registered()
            .iter()
            .map(|d| d.board_target)
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            ids.len(),
            sorted.len(),
            "duplicate board_target in registry"
        );
    }

    #[test]
    fn asic_protocol_chip_id_roundtrip_for_known_families() {
        for id in [
            0x1387u16, 0x1391, 0x1393, 0x1396, 0x1397, 0x1398, 0x1362, 0x1366, 0x1368, 0x1370,
        ] {
            let identity = AsicProtocolIdentity::from_chip_id(id).expect("known id");
            assert_eq!(identity.to_chip_id(), Some(id));
        }
        assert_eq!(AsicProtocolIdentity::RuntimeDiscovered.to_chip_id(), None);
        // Public-beta board rows expose a profile-usable ChipID.
        assert_eq!(BoardDesc::am1_s9().asic_protocol.to_chip_id(), Some(0x1387));
        assert_eq!(
            BoardDesc::am2_s19jpro().asic_protocol.to_chip_id(),
            Some(0x1362)
        );
    }

    #[test]
    fn registry_artifact_contracts_are_consistent() {
        for board in BoardDesc::all_registered() {
            assert!(
                board.enablement.artifact_contract_is_consistent(),
                "{} has contradictory artifact kind/maturity",
                board.board_target
            );
        }
    }

    /// S19j-classic (BHB42701): the stock-settled BM1362 identity is admitted
    /// as a *constraint*, while every executable facet stays fail-closed and
    /// the row cannot be confused with the S19j Pro that owns `am2-s19j`.
    #[test]
    fn s19j_classic_is_a_distinct_denied_bm1362_row() {
        let classic = BoardDesc::lookup("am2-s19j-classic").expect("am2-s19j-classic registered");
        assert_eq!(classic.asic_protocol, AsicProtocolIdentity::Bm1362);
        assert_eq!(classic.family, BoardFamily::Zynq);
        assert_eq!(classic.chain_transport, ChainTransportKind::None);
        assert_eq!(classic.work_engine, WorkEngineKind::ManagementOnly);
        assert_eq!(
            classic.voltage_controller,
            VoltageControllerClass::RuntimeDiscovered
        );
        assert_eq!(classic.release_channel, ReleaseChannel::Unsupported);
        assert!(!classic.release_channel.is_publishable());
        assert!(!classic.public_beta_install());
        assert!(!classic.mining_default_enabled);
        assert_eq!(classic.supervisor_class, SupervisorClass::Unclassified);
        // No install/flash facet: runtime-only enablement refuses everything.
        assert_eq!(
            classic.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert_eq!(classic.enablement.artifact_kind, ArtifactKind::None);
        // The declared BM1362 protocol still binds runtime identity when a
        // future evidenced runtime arrives — and refuses any other family.
        assert!(classic
            .admit_asic_protocol(
                Some(AsicProtocolIdentity::Bm1362),
                AsicProtocolIdentity::Bm1362
            )
            .is_ok());
        assert!(classic
            .admit_asic_protocol(
                Some(AsicProtocolIdentity::Bm1362),
                AsicProtocolIdentity::Bm1398
            )
            .is_err());
        // Distinct from the S19j Pro row that owns the `am2-s19j` key: a
        // first-light on one must never silently promote the other.
        let pro = BoardDesc::lookup("am2-s19j").expect("am2-s19j (S19j Pro XIL) registered");
        assert_ne!(classic.board_target, pro.board_target);
        assert_ne!(classic.runtime_status, pro.runtime_status);
        assert_ne!(classic.chain_transport, pro.chain_transport);
        assert_ne!(classic.enablement, pro.enablement);
        // Not reachable through the alias table either (an alias would borrow
        // the Pro row's live-proven plan; the classic has none).
        assert_eq!(
            canonical_board_target("am2-s19j-classic"),
            "am2-s19j-classic"
        );
    }

    /// R17-D (2026-09-11): the S9 Hydro row registers the framed-dsPIC
    /// "S9 plus plus" GENERATION (proven from held bytes) while every
    /// runtime facet stays capture-first. The row key must equal the one
    /// string the generation module's admission gate accepts.
    #[test]
    fn am1_s9_hydro_is_a_generation_proven_capture_first_row() {
        use crate::s9_plus_plus_pic_generation::{admit_generation_board, S9_HYDRO_BOARD_TARGET};
        let hydro = BoardDesc::lookup("am1-s9-hydro").expect("am1-s9-hydro registered");
        // The row key is exactly the string the R17 generation module admits.
        assert_eq!(hydro.board_target, S9_HYDRO_BOARD_TARGET);
        assert_eq!(admit_generation_board(hydro.board_target), Ok(()));
        // Generation-proven facets: BM1387-lineage protocol constraint and
        // the framed dsPIC controller family.
        assert_eq!(hydro.asic_protocol, AsicProtocolIdentity::Bm1387);
        assert_eq!(hydro.voltage_controller, VoltageControllerClass::DsPic33Ep);
        assert_eq!(hydro.family, BoardFamily::Zynq);
        // Capture-first facets stay fail-closed.
        assert_eq!(hydro.chain_transport, ChainTransportKind::None);
        assert_eq!(hydro.work_engine, WorkEngineKind::ManagementOnly);
        assert_eq!(hydro.supervisor_class, SupervisorClass::Unclassified);
        assert_eq!(hydro.release_channel, ReleaseChannel::Unsupported);
        assert!(!hydro.release_channel.is_publishable());
        assert!(!hydro.public_beta_install());
        assert!(!hydro.mining_default_enabled);
        assert_eq!(
            hydro.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert_eq!(hydro.enablement.artifact_kind, ArtifactKind::None);
        assert_eq!(hydro.cooling_medium, None);
        let RuntimeStatus::CaptureFirst { unconfirmed } = hydro.runtime_status else {
            panic!(
                "S9 Hydro must stay CaptureFirst, got {:?}",
                hydro.runtime_status
            );
        };
        let joined = unconfirmed.join(" | ").to_lowercase();
        assert!(joined.contains("chipid"), "datums: {joined}");
        assert!(joined.contains("population"), "datums: {joined}");
        assert!(joined.contains("cooling"), "datums: {joined}");
        assert!(joined.contains("nand"), "datums: {joined}");
        // Distinct from the bare-PIC16 S9 row: a different PIC generation is
        // a different row, never an alias.
        assert_eq!(canonical_board_target("am1-s9-hydro"), "am1-s9-hydro");
        let s9 = BoardDesc::lookup("am1-s9").unwrap();
        assert_ne!(hydro.voltage_controller, s9.voltage_controller);
        assert_ne!(hydro.runtime_status, s9.runtime_status);
        assert_ne!(hydro.release_channel, s9.release_channel);
    }

    /// The legacy tables retain their original four-slot software declarations.
    /// S19i remains refused. S19a has an exact native owner with its own
    /// geometry and observed slot census; neither target aliases a sibling.
    #[test]
    fn am2_s19i_remains_refused_while_s19a_has_a_distinct_native_owner() {
        use crate::s19_legacy_zynq_profiles::admit_legacy_s19;
        // The registry rows key exactly the tuples the R17 profile module
        // admits: first-party machine identity, four chains, factory
        // per-chain population. (Both exact tuples are pinned in that
        // module's own tests; here we pin the join with the registry.)
        assert!(admit_legacy_s19("am2-s19i", "NBS2003", 4, 80).is_ok());
        assert!(admit_legacy_s19("am2-s19a", "BHB28611", 4, 72).is_ok());
        for target in ["am2-s19i"] {
            let row =
                BoardDesc::lookup(target).unwrap_or_else(|| panic!("{target} registered"));
            assert_eq!(row.family, BoardFamily::Zynq);
            assert_eq!(row.chain_transport, ChainTransportKind::None);
            assert_eq!(row.work_engine, WorkEngineKind::ManagementOnly);
            assert_eq!(
                row.asic_protocol,
                AsicProtocolIdentity::RuntimeDiscovered
            );
            assert_eq!(
                row.voltage_controller,
                VoltageControllerClass::RuntimeDiscovered
            );
            assert_eq!(row.supervisor_class, SupervisorClass::Unclassified);
            assert_eq!(row.release_channel, ReleaseChannel::Unsupported);
            assert!(!row.release_channel.is_publishable());
            assert!(!row.public_beta_install());
            assert!(!row.mining_default_enabled);
            assert_eq!(
                row.enablement.install_authorization,
                InstallAuthorization::Denied
            );
            assert_eq!(row.enablement.artifact_kind, ArtifactKind::None);
            assert_eq!(row.cooling_medium, None);
            let RuntimeStatus::CaptureFirst { unconfirmed } = row.runtime_status else {
                panic!(
                    "{target} must stay CaptureFirst, got {:?}",
                    row.runtime_status
                );
            };
            let joined = unconfirmed.join(" | ").to_lowercase();
            assert!(joined.contains("capture-first"), "{target} datums: {joined}");
            assert!(joined.contains("wire codec"), "{target} datums: {joined}");
            assert!(
                joined.contains("voltage command law"),
                "{target} datums: {joined}"
            );
            // No runtime identity is minted: the declared protocol refuses
            // every concrete family until runtime evidence selects one — in
            // particular the BM1398 family (plain-BM1398/S19 Pro conflation
            // is exactly what the R17 adjudication refuses).
            for family in [
                AsicProtocolIdentity::Bm1398,
                AsicProtocolIdentity::Bm1387,
                AsicProtocolIdentity::Bm1362,
            ] {
                assert!(
                    row.admit_asic_protocol(None, family).is_err(),
                    "{target} must not admit {family:?}"
                );
            }
        }
        // The two rows are distinct platforms from each other and from the
        // three-chain S19 (NBS1902) / S19 Pro (NBP1901) rows — the four-chain
        // alias is refused by the profile module and impossible here by
        // construction (distinct keys).
        let s19i = BoardDesc::lookup("am2-s19i").unwrap();
        let s19a = BoardDesc::lookup("am2-s19a").unwrap();
        assert_ne!(s19i.board_target, s19a.board_target);
        assert_ne!(s19i.runtime_status, s19a.runtime_status);
        for sibling in ["am2-s19", "am2-s19pro"] {
            let sib = BoardDesc::lookup(sibling).unwrap();
            assert_ne!(s19i.board_target, sib.board_target);
            assert_ne!(s19a.board_target, sib.board_target);
        }
        assert_eq!(canonical_board_target("am2-s19i"), "am2-s19i");
        assert_eq!(canonical_board_target("am2-s19a"), "am2-s19a");
    }

    /// Re-materialized R14 integration patch (2026-09-12): the evidence-only
    /// S21+ row stays a fail-closed management carrier: exact silicon/
    /// geometry, zero runtime authority, and explicit non-inheritance from
    /// the Pro/XP native rows it is most often confused with.
    #[test]
    fn amlogic_s21plus_is_an_evidence_only_management_row_never_a_pro_or_xp_alias() {
        let plus = BoardDesc::lookup("amlogic-s21plus")
            .expect("amlogic-s21plus registered");
        assert_eq!(plus.asic_protocol, AsicProtocolIdentity::Bm1370);
        assert_eq!(plus.family, BoardFamily::Amlogic);
        assert_eq!(plus.chain_transport, ChainTransportKind::Serial);
        assert_eq!(plus.work_engine, WorkEngineKind::ManagementOnly);
        assert_eq!(
            plus.voltage_controller,
            VoltageControllerClass::RuntimeDiscovered
        );
        assert_eq!(plus.release_channel, ReleaseChannel::Unsupported);
        assert!(!plus.release_channel.is_publishable());
        assert!(!plus.public_beta_install());
        assert!(!plus.mining_default_enabled);
        assert_eq!(plus.supervisor_class, SupervisorClass::Unclassified);
        assert_eq!(
            plus.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert_eq!(plus.enablement.artifact_kind, ArtifactKind::None);
        assert_eq!(plus.cooling_medium, None);
        match &plus.runtime_status {
            RuntimeStatus::ManagementOnlyByPolicy { gate } => {
                assert!(gate.contains("11x5=55"), "gate: {gate}");
                assert!(gate.contains("never traced"), "gate: {gate}");
                assert!(gate.contains("inherited"), "gate: {gate}");
            }
            other => panic!("S21+ must stay ManagementOnlyByPolicy, got {other:?}"),
        }
        // Distinct rows on the same silicon: the board target is the
        // identity, never the chip family.
        assert_ne!(plus.board_target, BoardDesc::am3_s21pro().board_target);
        assert_ne!(plus.board_target, BoardDesc::am3_s21xp().board_target);
        assert_eq!(canonical_board_target("amlogic-s21plus"), "amlogic-s21plus");
    }

    /// F02 batch 2026-09-12: the two NEW acceptance rows added with this
    /// registration (S9 Hydro, S21 Plus) must stay capture-first scaffolds:
    /// NOT-IMPLEMENTED release state, enum_expect 0, and notes carrying the
    /// held evidence hashes. The BM1360 S19i / BM1398S S19a tuples are
    /// deliberately NOT rows in that file — the acceptance schema's chip
    /// vocabulary has no BM1360/BM1398S identity and inventing a nearby label
    /// would conflate exactly the silicon strings the R17 adjudication
    /// resolved (see the F02 batch SOURCE_NOTE).
    #[test]
    fn acceptance_s9hydro_and_s21plus_rows_are_not_implemented_scaffolds() {
        let acceptance_skus = include_str!("../../../scripts/hw-acceptance/skus.conf");
        let hydro = acceptance_skus
            .lines()
            .find(|line| line.starts_with("S9Hydro|"))
            .expect("S9Hydro acceptance row present");
        assert!(
            hydro.starts_with(
                "S9Hydro|am1-s9-hydro|armv7|BM1387|0|0|zynq|nand-ab|NOT-IMPLEMENTED|"
            ),
            "S9 Hydro acceptance row must stay a capture-first scaffold: {hydro}"
        );
        assert!(
            hydro.contains("81b89d08"),
            "S9 Hydro note must cite the held bmminer SHA-256: {hydro}"
        );
        let plus = acceptance_skus
            .lines()
            .find(|line| line.starts_with("S21Plus|"))
            .expect("S21Plus acceptance row present");
        assert!(
            plus.starts_with(
                "S21Plus|amlogic-s21plus|aarch64|BM1370|0x1370|0|amlogic|single-image|NOT-IMPLEMENTED|"
            ),
            "S21 Plus acceptance row must stay a capture-first scaffold: {plus}"
        );
        assert!(
            plus.contains("11x5=55"),
            "S21 Plus note must state the 11x5=55 per-board geometry: {plus}"
        );
        assert!(
            plus.contains("c79f56e2"),
            "S21 Plus note must cite the held model-list SHA-256: {plus}"
        );
    }

    /// T21 (Gauntlet B9, 2026-09-02): the stock `t21-merge-20240926` image
    /// settles the hashboard-side contracts (BM1368 3x108, APW11A PSU,
    /// PIC1704@0x20 label — `dcentrald-silicon-profiles::t21_stock_topol`),
    /// and this row admits that identity as a *constraint only*: every
    /// executable facet stays fail-closed because the AML control-board
    /// record is sealed and no T21 unit has ever been contacted. The row
    /// must also stay distinct from the live-proven S21 row that shares
    /// the BM1368 chip (same chip, different hashboard family — the
    /// S21-hydro stock cross-check pins the divergence).
    #[test]
    fn am3_t21_is_a_stock_pinned_denied_management_only_bm1368_row() {
        let t21 = BoardDesc::lookup("am3-t21").expect("am3-t21 registered");
        assert_eq!(t21.asic_protocol, AsicProtocolIdentity::Bm1368);
        assert_eq!(t21.family, BoardFamily::Amlogic);
        assert_eq!(t21.chain_transport, ChainTransportKind::Serial);
        assert_eq!(t21.work_engine, WorkEngineKind::ManagementOnly);
        // The stock PIC1704 label is NOT a populated-part proof and the AML
        // control board is sealed: the concrete controller stays
        // runtime-discovered (B5b/S19-family precedent).
        assert_eq!(
            t21.voltage_controller,
            VoltageControllerClass::RuntimeDiscovered
        );
        assert_eq!(t21.release_channel, ReleaseChannel::Unsupported);
        assert!(!t21.release_channel.is_publishable());
        assert!(!t21.public_beta_install());
        assert!(!t21.mining_default_enabled);
        assert_eq!(t21.supervisor_class, SupervisorClass::Unclassified);
        // Package-only enablement: a host-buildable artifact with no
        // hardware-install authority.
        assert_eq!(
            t21.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        // The gate text must name BOTH halves of the B9 reconciliation —
        // the stock-settled hashboard contracts AND the sealed-AML/never-
        // contacted residuals — so neither the old "all contracts absent"
        // framing nor an over-claim can silently return.
        match &t21.runtime_status {
            RuntimeStatus::ManagementOnlyByPolicy { gate } => {
                assert!(gate.contains("stock-settled"), "gate: {gate}");
                assert!(gate.contains("3x108"), "gate: {gate}");
                assert!(gate.contains("APW11A"), "gate: {gate}");
                assert!(gate.contains("sealed"), "gate: {gate}");
                assert!(gate.contains("ever contacted"), "gate: {gate}");
            }
            other => {
                panic!("am3-t21 runtime status must stay ManagementOnlyByPolicy, got {other:?}")
            }
        }
        // The declared BM1368 protocol binds runtime identity when a future
        // evidenced runtime arrives — and refuses every other family
        // (a BM1370 or BM1362 chain must never ride this row).
        assert!(t21
            .admit_asic_protocol(
                Some(AsicProtocolIdentity::Bm1368),
                AsicProtocolIdentity::Bm1368
            )
            .is_ok());
        for wrong in [
            AsicProtocolIdentity::Bm1370,
            AsicProtocolIdentity::Bm1362,
            AsicProtocolIdentity::Bm1366,
        ] {
            assert!(
                t21.admit_asic_protocol(Some(AsicProtocolIdentity::Bm1368), wrong)
                    .is_err(),
                "am3-t21 must refuse {wrong:?}"
            );
        }
        // Distinct from the live-proven S21 row sharing the chip: same
        // BM1368, different hashboard family, wildly different admission
        // (the S21 row carries a live-proven serial-work runtime; T21 has
        // none — release_channel is Denied on both, so the WORK ENGINE
        // and runtime-status facets carry the distinction).
        let s21 = BoardDesc::lookup("am3-s21").expect("am3-s21 registered");
        assert_ne!(t21.board_target, s21.board_target);
        assert_ne!(t21.work_engine, s21.work_engine);
        assert_ne!(t21.runtime_status, s21.runtime_status);
        // No alias maps onto this row (the stock image's own platform names
        // — BHB68701/03/05 — are hashboard codes, not board targets).
        assert_eq!(canonical_board_target("am3-t21"), "am3-t21");
    }

    /// The actual production Pro/XP factories select a PSU voltage controller.
    /// Their native lifecycle remains distinct from independent install approval.
    #[test]
    fn s21_air_family_rows_bind_native_profiles_and_independent_install_facets() {
        let s21 = BoardDesc::lookup("am3-s21").expect("am3-s21 registered");
        assert_eq!(s21.asic_protocol, AsicProtocolIdentity::Bm1368);
        assert_eq!(s21.work_engine, WorkEngineKind::SerialWork);
        assert_eq!(s21.supervisor_class, SupervisorClass::Am3Aml);
        assert_eq!(s21.release_channel, ReleaseChannel::Beta);
        for target in ["am3-s21pro", "am3-s21xp"] {
            let desc = BoardDesc::lookup(target).expect("exact BM1370 target registered");
            assert_eq!(desc.asic_protocol, AsicProtocolIdentity::Bm1370);
            assert_eq!(desc.voltage_controller, VoltageControllerClass::NoPic);
            assert_eq!(desc.work_engine, WorkEngineKind::SerialWork);
            assert_eq!(desc.supervisor_class, SupervisorClass::Am3Aml);
            assert_eq!(
                desc.runtime_status,
                RuntimeStatus::SpecialisedLifecycle {
                    lane: LifecycleLane::AmlogicNativeSerial,
                    generic_construction: GenericConstruction::Refused,
                }
            );
            assert_eq!(desc.release_channel, ReleaseChannel::Beta);
            assert_eq!(
                desc.enablement.install_authorization,
                if target == "am3-s21pro" {
                    InstallAuthorization::LabOnly
                } else {
                    InstallAuthorization::Denied
                }
            );
            assert_eq!(
                desc.enablement.allows_persistent_update(),
                target == "am3-s21pro"
            );
            assert!(!desc.product_install_allowed());
            assert_eq!(canonical_board_target(target), target);
            assert_ne!(desc.board_target, s21.board_target);
        }
        assert_ne!(
            BoardDesc::am3_s21pro().board_target,
            BoardDesc::am3_s21xp().board_target
        );
    }

    #[test]
    fn protocol_admission_requires_declared_and_runtime_identity_to_match() {
        let s19j = BoardDesc::am2_s19jpro();
        let proof = s19j
            .admit_asic_protocol(
                Some(AsicProtocolIdentity::Bm1362),
                AsicProtocolIdentity::Bm1362,
            )
            .expect("exact BM1362 composition should admit");
        assert_eq!(proof.identity(), AsicProtocolIdentity::Bm1362);
        assert!(s19j
            .admit_asic_protocol(None, AsicProtocolIdentity::Bm1362)
            .is_err());

        let s19pro = BoardDesc::am2_s19pro();
        assert_eq!(s19pro.asic_protocol, AsicProtocolIdentity::Bm1398);
        assert_eq!(s19pro.work_engine, WorkEngineKind::FpgaWorkFifo);
        assert!(s19pro
            .admit_asic_protocol(
                Some(AsicProtocolIdentity::Bm1398),
                AsicProtocolIdentity::Bm1362,
            )
            .is_err());
    }

    #[test]
    fn protocol_identity_parsers_refuse_unknown_or_ambiguous_labels() {
        assert_eq!(
            AsicProtocolIdentity::from_chip_id(0x1398),
            Some(AsicProtocolIdentity::Bm1398)
        );
        assert_eq!(
            AsicProtocolIdentity::from_chip_id(0x1396),
            Some(AsicProtocolIdentity::Bm1396)
        );
        assert_eq!(
            AsicProtocolIdentity::from_chip_label("BM1396"),
            Some(AsicProtocolIdentity::Bm1396)
        );
        assert_eq!(
            AsicProtocolIdentity::from_chip_label(" bm1362 "),
            Some(AsicProtocolIdentity::Bm1362)
        );
        assert_eq!(AsicProtocolIdentity::from_chip_id(0x1390), None);
        assert_eq!(AsicProtocolIdentity::from_chip_label("BM13XX"), None);
    }

    /// The T9+ row exists and is registered — a held-firmware SKU that used to
    /// resolve to nothing at all.
    #[test]
    fn am1_t9plus_is_registered_and_capture_first() {
        let t9 = BoardDesc::lookup("am1-t9plus").expect("am1-t9plus must be registered");
        assert_eq!(t9.family, BoardFamily::Zynq, "T9+ carrier is DTB-confirmed");
        match t9.runtime_status {
            RuntimeStatus::CaptureFirst { unconfirmed } => assert!(
                !unconfirmed.is_empty(),
                "capture-first must name what is unconfirmed"
            ),
            other => panic!("T9+ must stay capture-first, got {other:?}"),
        }
    }

    /// Fail-closed contract. Every one of these is a field the S9 template
    /// declares concretely; copying any of them across on am1 family
    /// resemblance is exactly the error this row exists to prevent.
    ///
    /// Mutation-checked: flipping `asic_protocol` to `Bm1387`, `slot_policy`
    /// to `ZynqAbFwSetenv`, `chain_transport` to the S9 transport, or
    /// `voltage_controller` to `Pic16F1704` each fails this test.
    #[test]
    fn am1_t9plus_never_inherits_s9_hardware_claims() {
        let t9 = BoardDesc::lookup("am1-t9plus").expect("am1-t9plus");
        let s9 = BoardDesc::lookup("am1-s9").expect("am1-s9");

        // Chip identity IS settled -- Bitmain's own jig config
        // `amtc-testing/s9/Config.ini-T9+` declares `AsicType=1387`. It happens
        // to match S9's, but it is declared from T9+'s OWN config row, never
        // borrowed: the same directory gives S9+ 84 and T9 57 from identical
        // `AsicType=1387` rows, proving the table is per-model, not a template.
        assert_eq!(
            t9.asic_protocol,
            AsicProtocolIdentity::Bm1387,
            "Config.ini-T9+ declares AsicType=1387"
        );

        // Stock T9+ NAND is 3-partition, not the A/B pair ZynqAbFwSetenv assumes.
        assert_eq!(t9.slot_policy, SlotPolicy::LabGated);
        assert_ne!(
            t9.slot_policy, s9.slot_policy,
            "T9+ stock NAND layout is not the S9 A/B pair"
        );

        // Chips-per-chain is unconfirmed => a chain that cannot be opened
        // cannot be opened wrongly.
        assert_eq!(t9.chain_transport, ChainTransportKind::None);
        assert_eq!(t9.work_engine, WorkEngineKind::ManagementOnly);
        assert_eq!(
            t9.voltage_controller,
            VoltageControllerClass::RuntimeDiscovered,
            "the S9 Pic16F1704 is a real controller claim and must not cross over"
        );
        // Guard the specific WRONG answer, not just "not S9's". The catalog
        // (:134) lists PIC16F1704 for T9+, but the T9+
        // bmminer has 8 dsPIC33EP16GS202 routines and ZERO PIC16 symbols. If
        // anyone "corrects" this row from that catalog row, this fails.
        assert_ne!(
            t9.voltage_controller,
            VoltageControllerClass::Pic16F1704,
            "T9+ bmminer drives dsPIC33EP16GS202, not PIC16F1704 — the catalog row is wrong"
        );

        // Nothing about this row may authorize an install or start mining.
        assert!(!t9.public_beta_install());
        assert!(!t9.mining_default_enabled);
        assert_eq!(
            t9.enablement.install_authorization,
            InstallAuthorization::Denied
        );
    }

    /// The unconfirmed-datum list is the row's honesty ledger; it must keep
    /// naming the three specific gaps the held bytes actually leave open.
    #[test]
    fn am1_t9plus_unconfirmed_datums_name_the_real_gaps() {
        let joined = AM1_T9PLUS_UNCONFIRMED_DATUMS.join(" | ").to_lowercase();
        // Chain topology left the list once `bmminer` byte-stated it
        // (chain_num = 9, real_asic_num = 18). Only control-board facts remain.
        assert!(
            !joined.contains("hash-board count"),
            "chain topology is settled by T9+ bmminer; stop listing it as unknown: {joined}"
        );
        assert!(
            joined.contains("nand"),
            "slot-layout gap must stay named: {joined}"
        );
        assert!(
            joined.contains("gpio"),
            "GPIO-map gap must stay named: {joined}"
        );
        // Settled facts must NOT be re-listed as unknown -- that would make the
        // ledger lie in the safe direction and hide real progress.
        assert!(
            !joined.contains("chips per chain"),
            "chips-per-chain is settled by Config.ini-T9+ (AsicNum=18): {joined}"
        );
        assert!(
            !joined.contains("bm1391"),
            "chip identity is settled by Config.ini-T9+ (AsicType=1387): {joined}"
        );
    }

    /// Round 15 (A1): `am1-s11` is registered, resolvable, authorizes nothing,
    /// and — the load-bearing part — **refuses to name an ASIC family**.
    ///
    /// Evidence: Bitmain's own signed `Antminer-S11-all-user-201908011639-sig`.
    /// Its production `bmminer` (byte-identical to the held
    /// `bitmain-antminer-binaries/S11/bmminer`, sha256 `a9417924…`) is the
    /// S9-family `driver-btm-c5.c` build with `is_S11()` and `is_S9_plus()`
    /// both `return 1` and **zero** BM139x strings; a BM1391 `cgminer` also
    /// ships in one of the two payloads and is never started. Both candidates
    /// are therefore refused. Full adjudication:
    /// `dcentrald-silicon-profiles/src/bm1391_stock_fw.rs`.
    ///
    /// Mutation-checked 2026-08-07: setting `asic_protocol` to `Bm1391` (to
    /// match `dcentrald-re-catalog`'s `s11` row) or to `Bm1387` (to match the
    /// jig `Config.ini`) each fails this test; so does flipping
    /// `public_beta_install`, `mining_default_enabled`, `chain_transport`,
    /// `work_engine`, or `voltage_controller`.
    #[test]
    fn am1_s11_is_registered_and_refuses_to_name_its_silicon() {
        let d =
            BoardDesc::lookup("am1-s11").expect("am1-s11 must resolve to a registered descriptor");

        // Byte-traceable: two `xlnx,zynq-7000` DTBs in the one package.
        assert_eq!(d.family, BoardFamily::Zynq);

        // THE guard. Neither candidate identity may be adopted.
        assert_eq!(
            d.asic_protocol,
            AsicProtocolIdentity::RuntimeDiscovered,
            "the S11's own stock image contradicts BOTH candidates — \
             its bmminer is BM1387-lineage with zero BM139x strings, and its \
             BM1391 cgminer is never started. Do not settle this from a registry."
        );
        assert_ne!(d.asic_protocol, AsicProtocolIdentity::Bm1391);
        assert_ne!(d.asic_protocol, AsicProtocolIdentity::Bm1387);

        // The rail controller is likewise unnamed: the image ships
        // `dsPIC33EP16GS202_app.txt`, but that is a jig asset, not a claim
        // about the S11 product hashboard (the `am1-s9i` discipline).
        assert_eq!(
            d.voltage_controller,
            VoltageControllerClass::RuntimeDiscovered
        );

        // Nothing here may install, mine, or open a chain.
        assert!(
            !d.public_beta_install(),
            "am1-s11 must not be install-eligible"
        );
        assert!(!d.mining_default_enabled, "am1-s11 must not auto-mine");
        assert_eq!(
            d.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert_eq!(d.chain_transport, ChainTransportKind::None);
        assert_eq!(d.work_engine, WorkEngineKind::ManagementOnly);
        assert_eq!(d.slot_policy, SlotPolicy::LabGated);

        // It is its own row, not an alias of the BM1391 S15/T15 class — those
        // ARE settled as BM1391 and must not drag S11 along with them.
        assert_ne!(d.board_target, BoardDesc::am1_s15().board_target);
        assert_ne!(
            d.asic_protocol,
            BoardDesc::am1_s15().asic_protocol,
            "S15 is BM1391 by its own stock firmware; S11 is not settled"
        );

        // The unconfirmed-datum list must keep naming the identity gap, so the
        // refusal is legible to `dcent-accept.sh` and not just to this test.
        let RuntimeStatus::CaptureFirst { unconfirmed } = d.runtime_status else {
            panic!("am1-s11 must be CaptureFirst");
        };
        let joined = unconfirmed.join(" | ").to_ascii_lowercase();
        assert!(
            joined.contains("asic identity"),
            "the S11 identity gap must stay named: {joined}"
        );
        assert!(
            joined.contains("chips per chain"),
            "the S11 chip count is not settled either: {joined}"
        );
    }

    #[test]
    fn c43_bm1393_rows_admit_only_their_native_runtime() {
        for target in ["am1-s9se", "am1-s9k"] {
            let d = BoardDesc::lookup(target).unwrap();
            assert_eq!(d.family, BoardFamily::Zynq);
            assert_eq!(d.asic_protocol, AsicProtocolIdentity::Bm1393);
            assert_eq!(d.chain_transport, ChainTransportKind::StockFpga);
            assert_eq!(d.work_engine, WorkEngineKind::FpgaWorkFifo);
            assert_eq!(d.supervisor_class, SupervisorClass::Am1C43);
            assert_eq!(
                d.runtime_status,
                RuntimeStatus::SpecialisedLifecycle {
                    lane: LifecycleLane::C43Bm1393Native,
                    generic_construction: GenericConstruction::Refused,
                }
            );
            assert!(!d.admits_standard_bm1387_runtime());
            assert!(!d.public_beta_install());
            assert!(!d.mining_default_enabled);
            assert!(d.enablement.allows_external_media_write());
            assert_eq!(
                d.enablement.external_media_mode,
                ExternalMediaMode::BootOnly
            );
            assert_eq!(
                d.enablement.external_media_maturity,
                ExternalMediaMaturity::ArtifactGenerated
            );
            assert_eq!(
                d.enablement.external_media_authorization,
                InstallAuthorization::LabOnly
            );
            assert!(!d.enablement.allows_persistent_update());
            assert_eq!(
                d.enablement.install_authorization,
                InstallAuthorization::Denied
            );
            assert!(d
                .admit_asic_protocol(
                    Some(AsicProtocolIdentity::Bm1387),
                    AsicProtocolIdentity::Bm1393
                )
                .is_err());
        }
    }

    /// Exact production ABI composition permits native beta runtime while
    /// keeping persistent installation and initial energization separate.
    #[test]
    fn am1_s9i_and_s9j_admit_native_bm1387_external_media_beta() {
        for target in ["am1-s9i", "am1-s9j"] {
            let d = BoardDesc::lookup(target)
                .unwrap_or_else(|| panic!("{target} must resolve to a registered descriptor"));

            // Byte-traceable from the held recovery images.
            assert_eq!(d.family, BoardFamily::Zynq);
            assert_eq!(d.asic_protocol, AsicProtocolIdentity::Bm1387);

            assert!(d.admits_standard_bm1387_runtime());
            assert_eq!(d.release_channel, ReleaseChannel::Beta);
            // No persistent install promotion or automatic first-boot mining.
            assert!(
                !d.public_beta_install(),
                "{target} must not be install-eligible"
            );
            assert!(!d.mining_default_enabled, "{target} must not auto-mine");
            assert_eq!(
                d.enablement.install_authorization,
                InstallAuthorization::Denied,
                "{target} install must be denied"
            );
            assert!(
                d.enablement.allows_external_media_write(),
                "{target} exact Experimental boot image must remain writable to removable media"
            );
            assert_eq!(
                d.enablement.external_media_authorization,
                InstallAuthorization::LabOnly
            );

            assert_eq!(d.chain_transport, ChainTransportKind::FpgaUio);
            assert_eq!(d.work_engine, WorkEngineKind::FpgaWorkFifo);
            assert_eq!(d.voltage_controller, VoltageControllerClass::Pic16F1704);
        }
    }

    /// A physical PIC16F1704 identity must not select the legacy S9 adapter ABI
    /// *without an application-ABI adjudication*.
    ///
    /// The physical family and application ABI are separate contracts.
    /// `VoltageControllerClass` is an adapter/ABI selector, so no non-S9 row may
    /// inherit the S9 `Pic16F1704` adapter solely from a part number.
    ///
    /// Mutation-checked 2026-08-07; **REBASED 2026-08-27** by the
    /// `2026-08-27-antminer17-unlock-armada` campaign (agent B1): the 17-family
    /// stock-RE (A1 §V1 HIGH + A3 §2) adjudicated the S17+/T17+ application ABI
    /// as the G2b raw S9-family frame dialect (`55 AA 10 VV` set-voltage etc.),
    /// so `am2-s17plus`/`am2-t17plus` now deliberately carry `Pic16F1704` on RE
    /// evidence, and all four BM1397 rows are promoted to the S17 hybrid
    /// SerialWork lane. The part-name-without-evidence guard below still applies
    /// in full to the BM1396 rows (`am2-s17e`/`am2-t17e`), which stay
    /// `Bm1396FramedI2c11` with distinct native startup profiles, and to T17, which is pinned to
    /// the RE-adjudicated dsPIC G2a plan.
    #[test]
    fn s17_family_never_inherits_legacy_s9_pic16_adapter_from_part_name() {
        // REGISTRY-DERIVED, not hand-enumerated (Round-15 A8 coverage gap):
        // the original four-target list let `am2-s17e` / `am2-t17e` register
        // later and silently escape this voltage-controller safety assertion.
        //
        // Round-15 A9 REFUTED the first fix and this is the repair. Two defects
        // it found, both preserved here as the reason for the current shape:
        //
        //  (a) A bare `am2-s17*` / `am2-t17*` prefix filter is not
        //      registry-derived, it is hand-enumerated *prefixes*. This exact
        //      family already carries a live alternate spelling in-tree —
        //      `x17-s17e-dspic-planned` / `x17-t17e-pic16-planned`
        //      (`scripts/hw-acceptance/skus.conf`, `dcentrald/src/model.rs`) —
        //      so a future row named `x17-…`, the naming its own siblings use,
        //      would escape silently. The filter therefore keys on the DECLARED
        //      FACET (S17-family silicon on Zynq), with the target prefixes kept
        //      only as an additional, not exclusive, admission path.
        //
        //  (b) A `>= 4` floor against a 6-row family is theatre in precisely
        //      the direction A8 complained about: two rows could be dropped or
        //      renamed out of coverage and the assertion would still pass. The
        //      floor is replaced by an EXACT-SET assertion, so adding, removing
        //      or renaming an S17-family row forces a deliberate edit here.
        const EXPECTED_S17_FAMILY: &[&str] = &[
            "am2-s17e",
            "am2-s17p",
            "am2-s17plus",
            "am2-t17",
            "am2-t17e",
            "am2-t17plus",
        ];
        let family: Vec<&BoardDesc> = BoardDesc::all_registered()
            .iter()
            .filter(|d| {
                // Declared facet first: S17-generation silicon on a Zynq carrier.
                let by_facet = matches!(
                    d.asic_protocol,
                    AsicProtocolIdentity::Bm1396 | AsicProtocolIdentity::Bm1397
                ) && d.family == BoardFamily::Zynq;
                // Naming is a fallback admission path, never the sole one, and
                // deliberately covers the live `x17-` spelling as well.
                let t = d.board_target;
                let by_name = t.starts_with("am2-s17")
                    || t.starts_with("am2-t17")
                    || t.starts_with("x17-s17")
                    || t.starts_with("x17-t17");
                by_facet || by_name
            })
            .collect();
        let mut found: Vec<&str> = family.iter().map(|d| d.board_target).collect();
        found.sort_unstable();
        assert_eq!(
            found, EXPECTED_S17_FAMILY,
            "the S17/T17-family roster changed. This is an EXACT set on purpose: a new \
             or renamed row must be added here deliberately so it cannot slip out of the \
             adapter guards below. Update EXPECTED_S17_FAMILY in the same change."
        );

        // BM1396 rows keep the original guard in full: their application ABI is
        // the framed BM1396 contract (Bm1396FramedI2c11), proven for their
        // physical silicon, independently of each exact work route.
        for d in &family {
            let target = d.board_target;
            if matches!(d.asic_protocol, AsicProtocolIdentity::Bm1397) {
                continue;
            }
            assert_ne!(
                d.voltage_controller,
                VoltageControllerClass::Pic16F1704,
                "{target}: {S17_FAMILY_STOCK_CONTROLLER_EVIDENCE}"
            );
            assert_eq!(
                d.work_engine,
                WorkEngineKind::FpgaWorkFifo,
                "{target}: exact BM1396 work route must not inherit the BM1397 lane"
            );
        }

        // The four BM1397 rows are pinned to the 2026-08-27 RE-adjudicated
        // controller plan (A1 §V1: s17p/t17 = dsPIC G2a framed; s17plus/t17plus
        // = PIC16 G2b raw) and to the promoted S17 hybrid work lane. None of
        // them may authorize an install or start mining.
        for (target, controller) in [
            ("am2-s17p", VoltageControllerClass::DsPic33Ep),
            ("am2-t17", VoltageControllerClass::DsPic33Ep),
            ("am2-s17plus", VoltageControllerClass::Pic16F1704),
            ("am2-t17plus", VoltageControllerClass::Pic16F1704),
        ] {
            let d = BoardDesc::lookup(target).unwrap();
            assert_eq!(
                d.voltage_controller, controller,
                "{target}: controller plan drifted from the 2026-08-27 stock-RE adjudication"
            );
            assert_eq!(
                d.work_engine,
                WorkEngineKind::FpgaWorkFifo,
                "{target}: S17 native UIO work engine drifted"
            );
            assert!(
                !d.public_beta_install(),
                "{target} must not be install-eligible"
            );
            assert!(!d.mining_default_enabled, "{target} must not auto-mine");
        }

        // Negative control for the promotion: the BM1396 siblings did NOT get
        // swept into the runtime lane.
        for target in ["am2-s17e", "am2-t17e"] {
            assert_ne!(
                BoardDesc::lookup(target).unwrap().work_engine,
                WorkEngineKind::SerialWork,
                "{target}: BM1396 native row must not inherit the BM1397 lane"
            );
        }
    }

    /// The BM1396/BM1397 reversal must not creep back into the original
    /// S17/S17+/T17/T17+ rows. All four are `Bm1397` (operator decision 2026-08-03, commit
    /// `1de772e96`), and Round 15 found **zero** `BM1396` occurrences anywhere
    /// in any of the seven signed S17-family stock images — checked twice, once
    /// per extracted rootfs and once over each raw ext2 ramdisk.
    ///
    /// S17e/T17e are tested separately below because later exact signed
    /// production binaries settle their BM1396 wire identity without changing
    /// the original four BM1397 rows.
    ///
    /// Mutation-checked 2026-08-07: flipping any of the four to `Bm1396` fails.
    #[test]
    fn s17_family_asic_protocol_is_bm1397_not_bm1396() {
        for target in ["am2-s17p", "am2-s17plus", "am2-t17", "am2-t17plus"] {
            let d = BoardDesc::lookup(target).unwrap();
            assert_eq!(
                d.asic_protocol,
                AsicProtocolIdentity::Bm1397,
                "{target}: S17+/T17+ are BM1397 (operator-confirmed 2026-08-03); the reversal \
                 seeded by the PR-056 disambiguation doc must not return"
            );
        }
    }

    /// S17e/T17e bind exact BM1396 catalog and wire identity while retaining a
    /// separate exact native startup profiles and observed carrier/work lanes.
    ///
    /// The catalog value comes from the model-specific factory `Config.ini`
    /// check. Independent exact production `bmminer` paths compare
    /// register-zero responses to `0x1396`. The T17e native lifecycle adds
    /// independent carrier admission; wire identity alone grants none.
    #[test]
    fn s17e_t17e_bind_exact_bm1396_wire_identity_and_distinct_runtime_routes() {
        for target in ["am2-s17e", "am2-t17e"] {
            let d = BoardDesc::lookup(target)
                .unwrap_or_else(|| panic!("{target} must resolve to a registered descriptor"));
            let model = crate::bm1396_contract::Bm1396Model::from_board_target(target)
                .expect("exact BM1396 model route");

            assert_eq!(d.family, BoardFamily::Zynq);
            assert_eq!(
                d.asic_protocol,
                AsicProtocolIdentity::Bm1396,
                "{target}: exact signed production binary proves wire 0x1396"
            );
            assert_eq!(
                d.distinct_asic_catalog_identity(),
                Some(AsicCatalogIdentity::Bm1396),
                "{target}: {S17E_T17E_JIG_ASIC_TYPE_EVIDENCE}"
            );
            let (expected_count, interval, last_address) = match target {
                "am2-s17e" => (135, 1, 134),
                "am2-t17e" => (78, 3, 231),
                _ => unreachable!(),
            };
            assert_eq!(model.expected_chips_per_present_chain(), expected_count);
            assert_eq!(model.address_interval(), interval);
            assert_eq!(
                model.hardware_address(expected_count - 1),
                Some(last_address)
            );
            assert!(
                d.admit_asic_protocol(
                    Some(AsicProtocolIdentity::Bm1396),
                    AsicProtocolIdentity::Bm1396
                )
                .is_ok(),
                "{target}: exact 0x1396 observation must bind the protocol identity"
            );
            assert!(
                d.admit_asic_protocol(
                    Some(AsicProtocolIdentity::Bm1397),
                    AsicProtocolIdentity::Bm1396
                )
                .is_err(),
                "{target}: the rejected 0x1397 claim must remain fail-closed"
            );

            // Exact binaries prove the framed ABI. Independent model-bundled
            // payloads prove the physical part. Keep those axes distinct so
            // T17e's PIC16F1704 cannot select the legacy S9 PIC adapter.
            assert_eq!(
                d.voltage_controller,
                VoltageControllerClass::Bm1396FramedI2c11,
                "{target}: exact BM1396 voltage endpoint must remain distinct"
            );
            let expected_part = match model {
                crate::bm1396_contract::Bm1396Model::S17e => {
                    crate::bm1396_pic::Bm1396PicPhysicalPart::Dspic33Ep16Gs202
                }
                crate::bm1396_contract::Bm1396Model::T17e => {
                    crate::bm1396_pic::Bm1396PicPhysicalPart::Pic16F1704
                }
            };
            assert_eq!(
                crate::bm1396_pic::bm1396_pic_physical_part_for_model(model),
                expected_part,
                "{target}: physical-part evidence drifted"
            );

            assert_eq!(d.chain_transport, ChainTransportKind::StockFpga);
            assert_eq!(d.work_engine, WorkEngineKind::FpgaWorkFifo);
            assert_eq!(d.supervisor_class, SupervisorClass::Am2Bm1396);
            assert_eq!(d.release_channel, ReleaseChannel::Beta);
            assert_eq!(d.runtime_status, RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Bm1396Native,
                generic_construction: GenericConstruction::Refused,
            });
            assert_eq!(d.slot_policy, SlotPolicy::LabGated);
            assert!(
                !d.public_beta_install(),
                "{target} must not be install-eligible"
            );
            assert!(!d.mining_default_enabled, "{target} must not auto-mine");
            assert_eq!(
                d.enablement.install_authorization,
                InstallAuthorization::Denied,
                "{target} install must be denied"
            );
        }
    }

    #[test]
    fn t17e_native_media_preserves_no_nand_and_no_physical_boot_claim() {
        let desc = BoardDesc::am2_t17e();
        assert_eq!(
            desc.enablement.storage_topology,
            StorageTopology::ExternalMediaOnly
        );
        assert_eq!(desc.enablement.update_mechanism, UpdateMechanism::SdImage);
        assert_eq!(
            desc.enablement.external_media_mode,
            ExternalMediaMode::BootOnly
        );
        assert_eq!(
            desc.enablement.external_media_maturity,
            ExternalMediaMaturity::ArtifactGenerated
        );
        assert!(desc.enablement.allows_external_media_write());
        assert!(!desc.enablement.allows_persistent_update());
        assert!(!desc.enablement.allows_restore());
        assert!(!desc.enablement.external_media_maturity.has_boot_witness());
        assert!(!desc.first_install_supported);
        assert!(!desc.mining_default_enabled);
        let s17e = BoardDesc::am2_s17e();
        assert_eq!(s17e.enablement, desc.enablement);
        assert_ne!(s17e.board_target, desc.board_target);
        assert!(!s17e.first_install_supported && !s17e.mining_default_enabled);
    }

    /// Regression for the provenance error corrected during the S17e/T17e
    /// control-board audit. The rejected digest is a byte-identical, misfiled
    /// BM1391/S11-era corpus binary and is absent from both exact signed roots.
    #[test]
    fn s17e_t17e_reject_misfiled_cgminer_as_signed_model_provenance() {
        assert_eq!(
            S17E_T17E_REJECTED_CGMINER_PROVENANCE_SHA256,
            "9283110862c74a7546923915be3a3d639768b56bf769577a47908df704887b8b"
        );
        assert!(
            !S17E_T17E_SIGNED_USERSPACE_SHA256
                .contains(&S17E_T17E_REJECTED_CGMINER_PROVENANCE_SHA256),
            "the misfiled corpus binary must never enter the exact signed-root allowlist"
        );
        assert!(
            S17E_T17E_SIGNED_USERSPACE_EVIDENCE
                .contains("68df4a7e393f467a645a4e50a3cf79fa1cf2a04b5c7f00c0576dc564a9199276"),
            "the actual byte-identical signed-root cgminer pin must remain explicit"
        );
        assert!(
            S17E_T17E_SIGNED_USERSPACE_EVIDENCE.contains("CONFIRMED_MULTI_FIRMWARE"),
            "the exact production wire result must remain confidence-labelled"
        );
    }

    /// Negative pin for facts the exact production enumeration did not settle.
    ///
    /// The S17e and T17e jigs sit next to their `AsicType` check with an
    /// `Asic_Num` comparison (`cmp r2,#135` at S17e vaddr `0x10d04`;
    /// `cmp r2,#78` at T17e vaddr `0x11544`). Those operands were *observed*,
    /// not adjudicated — the S17-family jigs read their geometry from
    /// `/mnt/card/Config.ini`, so those sites alone were not chips-per-chain
    /// proof. The later exact production enumeration independently enforces
    /// 135/78 responses. Core count, physical chain count, carrier, and voltage
    /// remain outside that evidence.
    ///
    /// Round 16 (B2) **confirmed the premise byte-exactly**: both immediates are
    /// compared against iniparser-parsed keys of the same config struct
    /// (`Config:Asic_Num` at `+0x10`, `Config:Asic_Type` at `+0x14`) inside one
    /// `check_config()` call. That remains catalog evidence only and is not
    /// mistaken for the independent runtime-enumeration proof.
    #[test]
    fn s17e_t17e_refuse_core_carrier_and_safety_facts_they_did_not_settle() {
        let joined = AM2_S17E_CLASS_UNCONFIRMED_DATUMS.join(" | ").to_lowercase();
        for needle in [
            "core count",
            "carrier",
            "gpio",
            "electrical envelope",
            "thermal",
            "install-slot",
        ] {
            assert!(
                joined.contains(needle),
                "the S17e/T17e honesty ledger must keep naming {needle:?}: {joined}"
            );
        }
        // The ledger must NOT re-list what the signed images DO settle,
        // or the row understates its own evidence.
        for settled in [
            "asictype",
            "chip identity",
            "hashboard code",
            "chips-per-chain",
        ] {
            assert!(
                !joined.contains(settled),
                "{settled:?} is byte-stated by the model's own signed image — \
                 do not list it as unconfirmed: {joined}"
            );
        }
        // Native software admission does not assert physical qualification.
        assert!(BoardDesc::am2_s17e().runtime_status.permits_mining_lane());
        assert!(BoardDesc::am2_t17e().runtime_status.permits_mining_lane());
        assert!(!BoardDesc::am2_t17e().public_beta_install());
    }

    /// S17e and T17e must stay separate rows. Their held evidence agrees on the
    /// vendor configuration identity but differs on hashboard (BHB16601 vs BHB16701) and on
    /// the jig's `Asic_Num` operand (135 vs 78), so promoting one must never
    /// silently promote the other.
    #[test]
    fn s17e_and_t17e_are_distinct_rows_not_aliases() {
        let s = BoardDesc::am2_s17e();
        let t = BoardDesc::am2_t17e();
        assert_ne!(s.board_target, t.board_target);
        assert_eq!(
            BoardDesc::all_registered()
                .iter()
                .filter(|d| d.board_target == "am2-s17e" || d.board_target == "am2-t17e")
                .count(),
            2,
            "both SKUs must be registered independently"
        );
    }

    /// S9i and S9j must stay separate rows so promoting one cannot silently
    /// promote the other, even though their held evidence is near-identical.
    #[test]
    fn am1_s9i_and_s9j_are_distinct_rows_not_aliases() {
        let i = BoardDesc::am1_s9i();
        let j = BoardDesc::am1_s9j();
        assert_ne!(i.board_target, j.board_target);
        assert_eq!(
            BoardDesc::all_registered()
                .iter()
                .filter(|d| d.board_target == "am1-s9i" || d.board_target == "am1-s9j")
                .count(),
            2,
            "both SKUs must be registered independently"
        );
    }

    /// A target name alone cannot substitute another ASIC, transport, or PIC
    /// into the established S9 executor.
    #[test]
    fn standard_bm1387_composition_rejects_changed_execution_facets() {
        for target in ["am1-s9", "am1-s9i", "am1-s9j"] {
            let desc = BoardDesc::lookup(target).unwrap();
            assert!(desc.admits_standard_bm1387_runtime());
            let mut wrong = desc.clone();
            wrong.voltage_controller = VoltageControllerClass::RuntimeDiscovered;
            assert!(!wrong.admits_standard_bm1387_runtime());
            wrong = desc.clone();
            wrong.asic_protocol = AsicProtocolIdentity::Bm1393;
            assert!(!wrong.admits_standard_bm1387_runtime());
            wrong = desc.clone();
            wrong.chain_transport = ChainTransportKind::None;
            assert!(!wrong.admits_standard_bm1387_runtime());
            wrong = desc.clone();
            wrong.work_engine = WorkEngineKind::ManagementOnly;
            assert!(!wrong.admits_standard_bm1387_runtime());
            wrong = desc.clone();
            wrong.board_target = "am1-s9-prototype";
            assert!(!wrong.admits_standard_bm1387_runtime());
        }
        for desc in [
            BoardDesc::am1_s9se(),
            BoardDesc::am1_s9k(),
            BoardDesc::am1_t9plus(),
        ] {
            assert!(!desc.admits_standard_bm1387_runtime());
        }
    }

    // -----------------------------------------------------------------------
    // Round-16 B5 — cooling-medium axis: registry-wide cut-ladder validation
    // (closes Round-15 A9 finding F-9: the axis had zero registry consumers)
    // -----------------------------------------------------------------------

    /// **The registry-wide gate.** Every registered row's declared escalation
    /// ladder must validate against its declared cooling medium.
    ///
    /// This is what makes the axis load-bearing rather than an unconsumed API:
    /// a future row that declares a fanless medium while keeping a fan-raise
    /// rung fails HERE, in the registry, not in a unit test of the validator.
    #[test]
    fn every_registered_row_has_a_valid_cut_ladder() {
        for d in BoardDesc::all_registered() {
            d.validate_cut_ladder().unwrap_or_else(|e| {
                panic!(
                    "{} declares an invalid escalation ladder for medium {:?}: {e}\n\
                     ladder = {:?}\n\
                     A board with no fan actuator must carry NO RaiseFansToCap rung \
                     (absent, not zero) and must terminate in a power cut.",
                    d.board_target, d.cooling_medium, d.cut_ladder
                )
            });
        }
    }

    /// The terminal rung is a power cut on EVERY row, regardless of medium —
    /// "raise fans harder" is never the last resort, and neither is a bare
    /// throttle.
    #[test]
    fn every_registered_row_terminates_its_ladder_in_a_power_cut() {
        for d in BoardDesc::all_registered() {
            let terminal = *d
                .cut_ladder
                .last()
                .unwrap_or_else(|| panic!("{} declares an empty cut ladder", d.board_target));
            assert!(
                terminal.is_power_cut(),
                "{} terminates its ladder in {terminal:?}, which is not a power cut",
                d.board_target
            );
        }
    }

    /// **Evidence posture, pinned.** No registered row declares a cooling
    /// medium today, and that is a measured conclusion, not an omission.
    ///
    /// Cooling medium is a **hashboard/chassis** facet, not a control-board
    /// facet. Measured untruncated against the pinned VNish 1.2.7 corpus
    /// (`vnish_thermal_matrix_1_2_7.json`, 77 rows): the 25 fan-curve-less
    /// rows are exactly the rows with `cooling_modes == ["immersion"]`, and
    /// exactly the rows whose `auto_target_c` and `manual_fan_pct` are both
    /// null — two independent routes to the same 25. Critically, the air
    /// `s21` (`BHB68603`), `s21-hydro` (`HHB68501`) and `s21-imm`
    /// (`IHB68601`) rows all declare the SAME `observed_platforms`
    /// (`aml, bb, cv, xil`). One control board, three media — so no
    /// `board_target` can truthfully declare one.
    ///
    /// If a future row genuinely evidences a medium (e.g. a hydro-only
    /// carrier), change this test deliberately in the same commit that adds
    /// the citation — and `every_registered_row_has_a_valid_cut_ladder` will
    /// then force its ladder to drop the fan rung.
    #[test]
    fn no_registered_row_declares_a_cooling_medium_without_evidence() {
        let declared: Vec<(&str, CoolingMedium)> = BoardDesc::all_registered()
            .iter()
            .filter_map(|d| d.cooling_medium.map(|m| (d.board_target, m)))
            .collect();
        assert!(
            declared.is_empty(),
            "a row declared a cooling medium; cooling medium is a hashboard facet \
             (air/hydro/immersion S21 variants share one control board), so this needs \
             a per-row held-bytes citation and a deliberate edit here: {declared:?}"
        );
        // …and undeclared must never be "tidied" into a fanless certification.
        for d in BoardDesc::all_registered() {
            assert!(
                !crate::cooling_medium::fan_bypass_permitted(d.cooling_medium),
                "{} would bypass fan management — undeclared must never earn the bypass",
                d.board_target
            );
        }
    }

    /// **The direction that matters (Round-16 B5 mission item d).** A row that
    /// declares a medium with no fan actuator but keeps a fan-raise rung is
    /// REFUSED by the same validator the registry gate runs.
    ///
    /// Built by mutating a real registered row rather than a hand-built
    /// fixture, so it exercises the exact shape the registry ships.
    #[test]
    fn a_fanless_declaration_with_a_fan_raise_rung_is_refused() {
        let air_row = BoardDesc::lookup("am1-s9").expect("am1-s9 is registered");
        assert!(
            air_row.cut_ladder.iter().any(|r| r.is_fan_raise()),
            "precondition: the baseline row must actually carry a fan-raise rung, \
             otherwise this test is vacuous"
        );
        for medium in [CoolingMedium::Hydro, CoolingMedium::Immersion] {
            let mut fanless: BoardDesc = (*air_row).clone();
            fanless.cooling_medium = Some(medium);
            let err = fanless.validate_cut_ladder().expect_err(
                "a fanless medium keeping a fan-raise rung must be refused, not accepted",
            );
            assert!(
                matches!(err, CutLadderError::FanRungOnFanlessMedium { .. }),
                "medium {medium:?} got {err:?}, expected FanRungOnFanlessMedium"
            );
            // The fix is to DROP the rung, not zero it: the canonical
            // external-loop ladder validates.
            let external_loop = fanless.canonical_cut_ladder();
            fanless.cut_ladder = external_loop;
            assert!(
                !fanless.cut_ladder.iter().any(|r| r.is_fan_raise()),
                "the external-loop ladder must be fan-rung ABSENT, not zero"
            );
            fanless
                .validate_cut_ladder()
                .expect("the canonical external-loop ladder must validate");
        }
    }

    // -----------------------------------------------------------------------
    // Round-16 B5 — supervisor lane (closes Round-15 A9 finding F-8)
    // -----------------------------------------------------------------------

    /// **F-8, closed.** A row without an executable mining lane must NOT carry
    /// a concrete supervisor lane — it must be `Unclassified`.
    ///
    /// This is the registry-derived guard that `dcentrald-thermal`'s
    /// `SupervisorPlatform::from_board_target` string-prefix classifier cannot
    /// provide: there, `am1-s11` / `am1-s15` / `am1-t15` / `am1-s9i` /
    /// `am1-s9j` / `am1-t9plus` all classify as `Am1S9` purely because their
    /// target starts with `am1`, inheriting a live-validated S9's lane. The
    /// derivation here is `runtime_status.permits_mining_lane()`, so a NEWLY
    /// registered row is covered the moment it is registered — no
    /// hand-enumerated target list to silently exclude it.
    #[test]
    fn supervisor_class_is_never_inherited_by_a_non_executable_row() {
        for d in BoardDesc::all_registered() {
            if d.runtime_status.permits_mining_lane() {
                continue;
            }
            assert_eq!(
                d.supervisor_class,
                SupervisorClass::Unclassified,
                "{} has no executable mining lane ({:?}) yet declares supervisor lane {:?}. \
                 A row that cannot mine must not borrow a sibling SKU's thermal-supervisor \
                 lane — that is exactly the am1-* prefix inheritance this facet exists to stop.",
                d.board_target,
                d.runtime_status,
                d.supervisor_class
            );
        }
    }

    /// The converse: a row that CAN mine must name its lane, never fall into
    /// the fail-closed bucket by accident, and the executable roster is an
    /// EXACT set so adding/renaming a row forces a deliberate edit here
    /// (Round-15 A9 F-7's lesson: a `>=` floor is theatre).
    #[test]
    fn executable_rows_declare_an_exact_supervisor_lane_roster() {
        const EXPECTED: &[(&str, SupervisorClass)] = &[
            ("am1-s15", SupervisorClass::Am1Bm1391),
            ("am1-s9", SupervisorClass::Am1S9),
            ("am1-s9i", SupervisorClass::Am1S9),
            ("am1-s9j", SupervisorClass::Am1S9),
            ("am1-s9k", SupervisorClass::Am1C43),
            ("am1-s9se", SupervisorClass::Am1C43),
            ("am1-t15", SupervisorClass::Am1Bm1391),
            // 2026-08-27 S17 hybrid promotion (`2026-08-27-antminer17-unlock-armada`,
            // agent B1): the four BM1397 17-series rows join the executable
            // roster on the same am2 Zynq thermal-supervisor lane as the S19j
            // hybrid (ZynqVariant::S17 fan/PSU/GPIO907 plan).
            ("am2-s17e", SupervisorClass::Am2Bm1396),
            ("am2-s17p", SupervisorClass::Am2Zynq),
            ("am2-s17plus", SupervisorClass::Am2Zynq),
            ("am2-s19", SupervisorClass::Am2Zynq),
            ("am2-s19a", SupervisorClass::Am2Zynq),
            ("am2-s19j", SupervisorClass::Am2Zynq),
            ("am2-s19plus", SupervisorClass::Am2Zynq),
            ("am2-s19pro", SupervisorClass::Am2Zynq),
            ("am2-t17", SupervisorClass::Am2Zynq),
            ("am2-t17e", SupervisorClass::Am2Bm1396),
            ("am2-t17plus", SupervisorClass::Am2Zynq),
            ("am2-t19", SupervisorClass::Am2Zynq),
            ("am3-bb-s19jpro", SupervisorClass::Am3Bb),
            ("am3-s19jpro-aml", SupervisorClass::Am3Aml),
            ("am3-s19jproa", SupervisorClass::Am3Aml),
            ("am3-s19jproplus", SupervisorClass::Am3Aml),
            ("am3-s19jxp", SupervisorClass::Am3Aml),
            ("am3-s19k", SupervisorClass::Am3Aml),
            ("am3-s19xp", SupervisorClass::Am3Aml),
            ("am3-s21", SupervisorClass::Am3Aml),
            ("am3-s21pro", SupervisorClass::Am3Aml),
            ("am3-s21xp", SupervisorClass::Am3Aml),
        ];
        let mut found: Vec<(&str, SupervisorClass)> = BoardDesc::all_registered()
            .iter()
            .filter(|d| d.runtime_status.permits_mining_lane())
            .map(|d| (d.board_target, d.supervisor_class))
            .collect();
        found.sort_unstable_by_key(|(t, _)| *t);
        assert_eq!(
            found, EXPECTED,
            "the executable-lane roster changed. This is an EXACT set on purpose: a new, \
             renamed or newly-promoted row must be added here deliberately so it cannot \
             acquire — or silently lose — a thermal-supervisor lane."
        );
        for (_, class) in found {
            assert_ne!(
                class,
                SupervisorClass::Unclassified,
                "an executable row must name its supervisor lane explicitly"
            );
        }
    }

    /// The `am1-*` rows Rounds 14/15 registered must NOT inherit `Am1S9`.
    ///
    /// Named explicitly (in addition to the registry-derived guard above)
    /// because this is the exact scenario A9 reported: an S15 guide stating 60
    /// twice but implying 72 once while the held S15 cgminer requires 72 BM1391
    /// register-zero responses, a T15 whose stock cgminer requires 60 responses
    /// but whose physical count remains independently unproved, and a row that
    /// refuses to name its silicon at all, inheriting an S9's BM1387 geometry
    /// classification.
    #[test]
    fn newly_registered_am1_rows_do_not_inherit_the_s9_supervisor_lane() {
        for target in ["am1-s11", "am1-t9plus", "am1-s9-hydro"] {
            let d = BoardDesc::lookup(target).unwrap_or_else(|| panic!("{target} is registered"));
            assert_eq!(
                d.supervisor_class,
                SupervisorClass::Unclassified,
                "{target} must not inherit another SKU's supervisor lane"
            );
            assert_eq!(
                BoardDesc::supervisor_class_for_target(target),
                SupervisorClass::Unclassified,
                "{target} must resolve fail-closed through the registry resolver too"
            );
        }
        for target in ["am1-s15", "am1-t15"] {
            let desc = BoardDesc::lookup(target).unwrap();
            assert_eq!(desc.supervisor_class, SupervisorClass::Am1Bm1391);
            assert_eq!(
                BoardDesc::supervisor_class_for_target(target),
                SupervisorClass::Am1Bm1391
            );
            assert_eq!(
                desc.voltage_controller,
                VoltageControllerClass::Bm1391Application
            );
            assert_eq!(
                desc.runtime_status,
                RuntimeStatus::SpecialisedLifecycle {
                    lane: LifecycleLane::Bm1391Native,
                    generic_construction: GenericConstruction::Refused,
                }
            );
            assert_eq!(
                desc.enablement.install_authorization,
                InstallAuthorization::Denied
            );
            assert_eq!(
                desc.enablement.storage_topology,
                StorageTopology::ExternalMediaOnly
            );
            assert_eq!(
                desc.enablement.external_media_mode,
                ExternalMediaMode::BootOnly
            );
            assert_eq!(
                desc.enablement.external_media_maturity,
                ExternalMediaMaturity::ArtifactGenerated
            );
            assert_eq!(
                desc.enablement.external_media_authorization,
                InstallAuthorization::LabOnly
            );
            assert!(desc.enablement.allows_external_media_write());
            assert!(!desc.enablement.allows_persistent_update());
            assert!(!desc.enablement.allows_restore());
            assert!(!desc.enablement.external_media_maturity.has_boot_witness());
        }
        // The original S9 row retains its established supervisor lane.
        assert_eq!(
            BoardDesc::supervisor_class_for_target("am1-s9"),
            SupervisorClass::Am1S9
        );
    }

    /// The registry resolver fails closed on markers the string-prefix
    /// classifier would happily classify, and resolves aliases + whitespace.
    #[test]
    fn supervisor_class_for_target_fails_closed_on_unregistered_markers() {
        // Each of these is classified as a concrete platform by
        // `SupervisorPlatform::from_board_target`'s prefix/contains rules but
        // is NOT a registered row, so it must fail closed here.
        for marker in [
            "am1-s9-prototype",
            "am1-whatever",
            "zynq-bm3-am2",
            "xil",
            "amlogic-a113d",
            "beaglebone",
            "S9",
            "",
            "something-else",
        ] {
            assert_eq!(
                BoardDesc::supervisor_class_for_target(marker),
                SupervisorClass::Unclassified,
                "unregistered marker {marker:?} must fail closed"
            );
        }
        // Aliases resolve through the single-source table…
        assert_eq!(
            BoardDesc::supervisor_class_for_target("am2-s19jpro-zynq"),
            SupervisorClass::Am2Zynq
        );
        for target in ["am2-s19", "am2-t19", "am2-s19a", "am2-s19plus"] {
            assert_eq!(
                BoardDesc::supervisor_class_for_target(target),
                SupervisorClass::Am2Zynq,
                "{target} has its own factory-bound BM1398 native supervisor"
            );
        }
        for target in ["am2-s19i", "am2-s19-plus", "am2-s19a-prototype"] {
            assert_eq!(
                BoardDesc::supervisor_class_for_target(target),
                SupervisorClass::Unclassified,
                "{target} cannot inherit a sibling's supervisor"
            );
        }
        // …and whitespace/case are normalized exactly like the classifier it
        // replaces.
        assert_eq!(
            BoardDesc::supervisor_class_for_target("  AM1-S9\n"),
            SupervisorClass::Am1S9
        );
    }
}
