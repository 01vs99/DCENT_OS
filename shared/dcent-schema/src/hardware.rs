use serde::{Deserialize, Serialize};

/// Version of the cross-firmware hardware-enablement policy contract.
///
/// This contract separates physical topology from implementation maturity and
/// operator authorization.  A single-slot device is not thereby installable,
/// and an experimental artifact is not thereby a persistent update.
/// Version 2 adds explicit absent-artifact wire values (`none` and
/// `not_implemented`). Version 3 separates public first-install eligibility
/// from the broader install authorization used by an already-running target's
/// persistent-update API. Version 4 adds an independent external-media facet,
/// so an SD boot image can no longer inherit sysupgrade/NAND authority merely
/// because both capabilities belong to the same board target. Strict older
/// consumers must reject rather than silently reinterpret any schema change.
pub const HARDWARE_ENABLEMENT_SCHEMA_VERSION: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageTopology {
    #[serde(rename = "redundant_slots")]
    RedundantSlots,
    #[serde(rename = "single_slot")]
    SingleSlot,
    #[serde(rename = "external_media_only")]
    ExternalMediaOnly,
    #[serde(rename = "unknown")]
    Unknown,
}

impl StorageTopology {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RedundantSlots => "redundant_slots",
            Self::SingleSlot => "single_slot",
            Self::ExternalMediaOnly => "external_media_only",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UpdateMechanism {
    #[serde(rename = "zynq_ubi_fw_setenv")]
    ZynqUbiFwSetenv,
    #[serde(rename = "host_rootfs_window")]
    HostRootfsWindow,
    /// Passive boot evidence exists, but no persistent selector writer does.
    #[serde(rename = "emmc_content_selector_evidence_only")]
    EmmcContentSelectorEvidenceOnly,
    #[serde(rename = "sd_image")]
    SdImage,
    #[serde(rename = "none")]
    None,
}

impl UpdateMechanism {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZynqUbiFwSetenv => "zynq_ubi_fw_setenv",
            Self::HostRootfsWindow => "host_rootfs_window",
            Self::EmmcContentSelectorEvidenceOnly => "emmc_content_selector_evidence_only",
            Self::SdImage => "sd_image",
            Self::None => "none",
        }
    }

    /// Whether this mechanism implements the persistent sysupgrade contract.
    ///
    /// Evidence-only selectors and external-media image creation are useful
    /// capabilities, but neither is authority to mutate an installed rootfs.
    pub const fn supports_sysupgrade(self) -> bool {
        matches!(self, Self::ZynqUbiFwSetenv | Self::HostRootfsWindow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImplementationMaturity {
    #[serde(rename = "not_implemented")]
    NotImplemented,
    #[serde(rename = "experimental")]
    Experimental,
    #[serde(rename = "production")]
    Production,
}

impl ImplementationMaturity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotImplemented => "not_implemented",
            Self::Experimental => "experimental",
            Self::Production => "production",
        }
    }

    pub const fn is_implemented(self) -> bool {
        !matches!(self, Self::NotImplemented)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstallAuthorization {
    #[serde(rename = "denied")]
    Denied,
    #[serde(rename = "lab_only")]
    LabOnly,
    #[serde(rename = "public_beta")]
    PublicBeta,
    #[serde(rename = "production")]
    Production,
}

impl InstallAuthorization {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::LabOnly => "lab_only",
            Self::PublicBeta => "public_beta",
            Self::Production => "production",
        }
    }

    pub const fn allows_any_install(self) -> bool {
        !matches!(self, Self::Denied)
    }
}

/// What an external removable-medium artifact does for this target.
///
/// This is deliberately orthogonal to [`UpdateMechanism`]. A board may have a
/// working A/B sysupgrade lane and only an experimental SD *boot* image; the
/// former must never authorize the latter to write NAND.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExternalMediaMode {
    #[serde(rename = "none")]
    None,
    /// Boot the supplied operating system while leaving onboard storage
    /// untouched. Removing the medium restores the prior boot source.
    #[serde(rename = "boot_only")]
    BootOnly,
    /// Boot removable media whose declared purpose includes installing to
    /// onboard storage. No current Antminer row earns this mode yet.
    #[serde(rename = "installer")]
    Installer,
    /// Vendor/DCENT recovery media, not a normal product install artifact.
    #[serde(rename = "recovery")]
    Recovery,
}

impl ExternalMediaMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BootOnly => "boot_only",
            Self::Installer => "installer",
            Self::Recovery => "recovery",
        }
    }

    pub const fn is_implemented(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Evidence/proof rung reached by an external-media lane.
///
/// These values distinguish host-side construction from physical-media and
/// cold-boot evidence. Hardware validation advances maturity; it does not
/// prevent an artifact generator from existing at `artifact_generated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExternalMediaMaturity {
    #[serde(rename = "not_implemented")]
    NotImplemented,
    #[serde(rename = "artifact_generated")]
    ArtifactGenerated,
    #[serde(rename = "media_written")]
    MediaWritten,
    #[serde(rename = "boot_witnessed")]
    BootWitnessed,
    #[serde(rename = "production")]
    Production,
}

impl ExternalMediaMaturity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotImplemented => "not_implemented",
            Self::ArtifactGenerated => "artifact_generated",
            Self::MediaWritten => "media_written",
            Self::BootWitnessed => "boot_witnessed",
            Self::Production => "production",
        }
    }

    pub const fn is_implemented(self) -> bool {
        !matches!(self, Self::NotImplemented)
    }

    pub const fn has_boot_witness(self) -> bool {
        matches!(self, Self::BootWitnessed | Self::Production)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoveryMaturity {
    #[serde(rename = "not_implemented")]
    NotImplemented,
    #[serde(rename = "evidence_only")]
    EvidenceOnly,
    #[serde(rename = "verified")]
    Verified,
}

impl RecoveryMaturity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotImplemented => "not_implemented",
            Self::EvidenceOnly => "evidence_only",
            Self::Verified => "verified",
        }
    }

    pub const fn allows_restore(self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// No artifact producer or supported artifact lane exists for this target.
    #[serde(rename = "none")]
    None,
    #[serde(rename = "sysupgrade")]
    SysupgradeBundle,
    #[serde(rename = "offline_analysis")]
    OfflineAnalysisBundle,
    #[serde(rename = "sdcard_payload")]
    SdCardPayload,
    #[serde(rename = "runtime_bundle")]
    RuntimeBundle,
    #[serde(rename = "recovery_image")]
    RecoveryImage,
    #[serde(rename = "rootfs_reference")]
    RootfsReference,
}

impl ArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SysupgradeBundle => "sysupgrade",
            Self::OfflineAnalysisBundle => "offline_analysis",
            Self::SdCardPayload => "sdcard_payload",
            Self::RuntimeBundle => "runtime_bundle",
            Self::RecoveryImage => "recovery_image",
            Self::RootfsReference => "rootfs_reference",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "sysupgrade" => Some(Self::SysupgradeBundle),
            "offline_analysis" => Some(Self::OfflineAnalysisBundle),
            "sdcard_payload" => Some(Self::SdCardPayload),
            "runtime_bundle" => Some(Self::RuntimeBundle),
            "recovery_image" => Some(Self::RecoveryImage),
            "rootfs_reference" => Some(Self::RootfsReference),
            _ => None,
        }
    }

    pub const fn is_persistent_update(self) -> bool {
        matches!(self, Self::SysupgradeBundle)
    }

    pub const fn is_implemented(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactMaturity {
    /// Artifact production is not implemented for this target.
    #[serde(rename = "not_implemented")]
    NotImplemented,
    #[serde(rename = "experimental")]
    Experimental,
    #[serde(rename = "production")]
    Production,
}

impl ArtifactMaturity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotImplemented => "not_implemented",
            Self::Experimental => "experimental",
            Self::Production => "production",
        }
    }

    pub const fn is_implemented(self) -> bool {
        !matches!(self, Self::NotImplemented)
    }
}

/// Named specialised mining lifecycle (routing lane).
///
/// A lane names *how* a target mines when it does not run through the generic
/// `Platform` trait. It is a routing fact, not a maturity tier: a target can be
/// `Experimental` on the maturity axis while being correctly routed here.
/// Consumed by [`RuntimeStatus::SpecialisedLifecycle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LifecycleLane {
    /// Exact S15/T15 flat FPGA BM1391 lifecycle and retained application PIC.
    #[serde(rename = "bm1391_native")]
    Bm1391Native,
    /// Exact T17e BM1396 FPGA/PIC native lifecycle with retained safety owners.
    #[serde(rename = "bm1396_native")]
    Bm1396Native,
    /// Native C43 flat FPGA FIFO and retained framed-PIC lifecycle (BM1393).
    #[serde(rename = "c43_bm1393_native")]
    C43Bm1393Native,
    /// Native Amlogic serial-mining lifecycle with retained bus-1 power/thermal
    /// ownership (the NoPic management fabric). Generic `Platform` construction
    /// is deliberately refused on this carrier.
    #[serde(rename = "amlogic_native_serial")]
    AmlogicNativeSerial,
    /// Classic AML BHB42601/21/41: retained fw89 PIC, shared APW12 rail,
    /// all selected UARTs and independent GPIO cutoff. Never NoPic custody.
    #[serde(rename = "classic_aml_native_serial")]
    ClassicAmlNativeSerial,
    /// Exact AM2/Zynq BM1362 direct-serial lifecycle.
    #[serde(rename = "am2_bm1362_serial")]
    Am2Bm1362Serial,
    /// Native AM2 BM1398 FPGA command/work FIFO lifecycle, selected by the
    /// serial entry point before generic hardware construction.
    #[serde(rename = "am2_bm1398_native")]
    Am2Bm1398Native,
    /// AM3 BeagleBone serial lifecycle (`--am3-bb-mining`).
    #[serde(rename = "am3_bb_serial")]
    Am3BbSerial,
    /// AM2 S19j hybrid lifecycle (`--s19j-hybrid`).
    #[serde(rename = "s19j_hybrid")]
    S19jHybrid,
    /// AM2 S17-family (BM1397) hybrid lifecycle (`--s17-hybrid`).
    ///
    /// Added 2026-08-28 (unlock-armada convergence): the four promoted
    /// 17-series targets previously reused `S19jHybrid` because the enum
    /// lived outside that campaign's crate lane; the dedicated variant
    /// restores one-lane-per-engine routing honesty. No consumer matches
    /// exhaustively on this enum outside its own `as_str`/serde impls.
    #[serde(rename = "s17_hybrid")]
    S17Hybrid,
}

impl LifecycleLane {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bm1391Native => "bm1391_native",
            Self::Bm1396Native => "bm1396_native",
            Self::C43Bm1393Native => "c43_bm1393_native",
            Self::AmlogicNativeSerial => "amlogic_native_serial",
            Self::ClassicAmlNativeSerial => "classic_aml_native_serial",
            Self::Am2Bm1362Serial => "am2_bm1362_serial",
            Self::Am2Bm1398Native => "am2_bm1398_native",
            Self::Am3BbSerial => "am3_bb_serial",
            Self::S19jHybrid => "s19j_hybrid",
            Self::S17Hybrid => "s17_hybrid",
        }
    }
}

/// What generic `Platform` construction does on a specialised-lifecycle target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GenericConstruction {
    /// Generic construction returns `Err` by design (Amlogic: the board
    /// requires the native serial-mining lifecycle with retained power/thermal
    /// ownership, so generic `Platform` construction is refused).
    #[serde(rename = "refused")]
    Refused,
    /// Generic construction succeeds but owns management surfaces only; mining
    /// requires the named lane (Zynq hybrid, BeagleBone serial).
    #[serde(rename = "management_only")]
    ManagementOnly,
}

impl GenericConstruction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::ManagementOnly => "management_only",
        }
    }
}

/// Why a registered board target does or does not run — first-class, not an
/// error string.
///
/// Two platform constructors return `Err` unconditionally today for
/// structurally different reasons, and a status model that flattens them lies:
///
/// - Amlogic (`dcentrald-hal/src/platform/amlogic/mod.rs`,
///   `AmlogicPlatform::new`) is an **architectural routing refusal** — the
///   board mines via the native serial lifecycle; generic construction is
///   refused. Amlogic routes elsewhere; it is not broken.
/// - CVitek (`dcentrald-hal/src/platform/cvitek.rs`, `CViTekPlatform::new`) is
///   a **genuine not-implemented fail-closed** — reverse-engineered register
///   evidence is retained, but no runtime mutation lane is admitted.
///
/// Collapsing both to "unsupported" would either falsely condemn Amlogic or
/// falsely promise CVitek. This axis is orthogonal to maturity and install
/// authorization.
///
/// Deliberately `Serialize`-only: statuses are declared in code next to the
/// registry row they describe and are never parsed from data. Accepting a
/// deserialized status would let external input inject a "this target runs"
/// claim, so the absence of `Deserialize` is the fail-closed choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "status")]
pub enum RuntimeStatus {
    /// Runs through the generic `Platform` trait.
    #[serde(rename = "generic_platform")]
    GenericPlatform,
    /// Runs, but ONLY through a named specialised lifecycle. This is a routing
    /// fact, not a capability gap.
    #[serde(rename = "specialised_lifecycle")]
    SpecialisedLifecycle {
        lane: LifecycleLane,
        generic_construction: GenericConstruction,
    },
    /// Evidence is retained; no runtime mutation lane is admitted. Not a bug,
    /// not a routing detail — an explicit product decision. The `evidence`
    /// list must be non-empty (enforced by [`Self::is_well_formed`] and by the
    /// registry test) and such a row must never be a public-beta install
    /// target.
    #[serde(rename = "evidence_retained_not_implemented")]
    EvidenceRetainedNotImplemented { evidence: &'static [&'static str] },
    /// Management-only by policy, even though a lane could exist. `gate` names
    /// the policy or missing admission that keeps mining off.
    #[serde(rename = "management_only_by_policy")]
    ManagementOnlyByPolicy { gate: &'static str },
    /// No control-board datums captured yet; capture-first. `unconfirmed`
    /// names the datums that must be captured before any lane can exist.
    #[serde(rename = "capture_first")]
    CaptureFirst {
        unconfirmed: &'static [&'static str],
    },
}

impl RuntimeStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::GenericPlatform => "generic_platform",
            Self::SpecialisedLifecycle { .. } => "specialised_lifecycle",
            Self::EvidenceRetainedNotImplemented { .. } => "evidence_retained_not_implemented",
            Self::ManagementOnlyByPolicy { .. } => "management_only_by_policy",
            Self::CaptureFirst { .. } => "capture_first",
        }
    }

    /// Whether this status names an admissible mining lane at all.
    ///
    /// `SpecialisedLifecycle` counts: routing elsewhere is not a capability
    /// gap. The three refusal statuses do not.
    pub const fn permits_mining_lane(&self) -> bool {
        matches!(
            self,
            Self::GenericPlatform | Self::SpecialisedLifecycle { .. }
        )
    }

    /// Fail-closed structural validity: every explanatory payload must be
    /// non-empty and contain no blank entries. A refusal that cannot say why
    /// it refuses is not well-formed.
    pub fn is_well_formed(&self) -> bool {
        fn all_non_blank(entries: &[&str]) -> bool {
            !entries.is_empty() && entries.iter().all(|entry| !entry.trim().is_empty())
        }
        match self {
            Self::GenericPlatform | Self::SpecialisedLifecycle { .. } => true,
            Self::EvidenceRetainedNotImplemented { evidence } => all_non_blank(evidence),
            Self::ManagementOnlyByPolicy { gate } => !gate.trim().is_empty(),
            Self::CaptureFirst { unconfirmed } => all_non_blank(unconfirmed),
        }
    }
}

/// Independent enablement facets for one packaged board target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HardwareEnablementPolicy {
    pub storage_topology: StorageTopology,
    pub update_mechanism: UpdateMechanism,
    pub update_maturity: ImplementationMaturity,
    pub install_authorization: InstallAuthorization,
    pub recovery_maturity: RecoveryMaturity,
    pub artifact_kind: ArtifactKind,
    pub artifact_maturity: ArtifactMaturity,
    /// Removable-media behavior, proof rung, and writer authorization are
    /// independent of the primary sysupgrade/runtime artifact above.
    pub external_media_mode: ExternalMediaMode,
    pub external_media_maturity: ExternalMediaMaturity,
    pub external_media_authorization: InstallAuthorization,
}

impl HardwareEnablementPolicy {
    /// Whether kind and maturity agree on the existence of an artifact lane.
    pub const fn artifact_contract_is_consistent(self) -> bool {
        self.artifact_kind.is_implemented() == self.artifact_maturity.is_implemented()
    }

    /// Whether the removable-media mode, maturity, and authorization form a
    /// coherent fail-closed contract. Artifact generation may exist while
    /// writes remain denied, but an absent lane may never carry authority.
    pub const fn external_media_contract_is_consistent(self) -> bool {
        let exists = self.external_media_mode.is_implemented();
        let implemented = self.external_media_maturity.is_implemented();
        exists == implemented
            && (exists
                || matches!(
                    self.external_media_authorization,
                    InstallAuthorization::Denied
                ))
    }

    /// Whether a caller may write the declared image to removable media.
    /// This grants no onboard-storage mutation, even for `Installer` mode;
    /// target-side installation requires its own route-specific admission.
    pub const fn allows_external_media_write(self) -> bool {
        self.external_media_contract_is_consistent()
            && self.external_media_maturity.is_implemented()
            && self.external_media_authorization.allows_any_install()
    }

    /// Whether a persistent-update API is representable for this target.
    pub const fn allows_persistent_update(self) -> bool {
        self.update_maturity.is_implemented()
            && self.install_authorization.allows_any_install()
            && self.artifact_kind.is_persistent_update()
            && self.update_mechanism.supports_sysupgrade()
    }

    /// Whether a destructive restore route is representable for this target.
    pub const fn allows_restore(self) -> bool {
        self.recovery_maturity.allows_restore()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_pinned() {
        assert_eq!(HARDWARE_ENABLEMENT_SCHEMA_VERSION, 4);
    }

    #[test]
    fn absent_artifact_cannot_become_an_update_from_single_slot_topology() {
        let policy = HardwareEnablementPolicy {
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

        assert!(!policy.allows_persistent_update());
        assert!(!policy.allows_restore());
        assert!(policy.artifact_contract_is_consistent());
        assert_eq!(policy.storage_topology, StorageTopology::SingleSlot);
    }

    #[test]
    fn persistent_update_requires_an_actual_sysupgrade_writer() {
        let baseline = HardwareEnablementPolicy {
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

        assert!(baseline.allows_persistent_update());
        for update_mechanism in [
            UpdateMechanism::None,
            UpdateMechanism::EmmcContentSelectorEvidenceOnly,
            UpdateMechanism::SdImage,
        ] {
            assert!(
                !HardwareEnablementPolicy {
                    update_mechanism,
                    ..baseline
                }
                .allows_persistent_update(),
                "{update_mechanism:?} must not authorize sysupgrade"
            );
        }
    }

    #[test]
    fn artifact_kind_wire_values_match_current_manifests() {
        for (wire, expected) in [
            ("none", ArtifactKind::None),
            ("sysupgrade", ArtifactKind::SysupgradeBundle),
            ("offline_analysis", ArtifactKind::OfflineAnalysisBundle),
            ("sdcard_payload", ArtifactKind::SdCardPayload),
        ] {
            assert_eq!(ArtifactKind::parse(wire), Some(expected));
            assert_eq!(expected.as_str(), wire);
            assert_eq!(
                serde_json::to_string(&expected).unwrap(),
                format!("\"{wire}\"")
            );
        }
        assert_eq!(ArtifactKind::parse("firmware-ish"), None);
    }

    #[test]
    fn runtime_status_distinguishes_routing_refusal_from_not_implemented() {
        let amlogic_shaped = RuntimeStatus::SpecialisedLifecycle {
            lane: LifecycleLane::AmlogicNativeSerial,
            generic_construction: GenericConstruction::Refused,
        };
        let cvitek_shaped = RuntimeStatus::EvidenceRetainedNotImplemented {
            evidence: &["dcentrald-hal/src/platform/cvitek.rs"],
        };
        assert_ne!(amlogic_shaped, cvitek_shaped);
        // Routing elsewhere still names a mining lane; retained-evidence
        // not-implemented does not.
        assert!(amlogic_shaped.permits_mining_lane());
        assert!(!cvitek_shaped.permits_mining_lane());
        assert_eq!(amlogic_shaped.as_str(), "specialised_lifecycle");
        assert_eq!(cvitek_shaped.as_str(), "evidence_retained_not_implemented");
    }

    #[test]
    fn runtime_status_fails_closed_on_absent_or_blank_evidence() {
        assert!(!RuntimeStatus::EvidenceRetainedNotImplemented { evidence: &[] }.is_well_formed());
        assert!(
            !RuntimeStatus::EvidenceRetainedNotImplemented { evidence: &["  "] }.is_well_formed()
        );
        assert!(!RuntimeStatus::ManagementOnlyByPolicy { gate: "" }.is_well_formed());
        assert!(!RuntimeStatus::CaptureFirst { unconfirmed: &[] }.is_well_formed());
        assert!(RuntimeStatus::EvidenceRetainedNotImplemented {
            evidence: &["dcentrald-hal/src/platform/cvitek.rs"]
        }
        .is_well_formed());
        assert!(RuntimeStatus::GenericPlatform.is_well_formed());
    }

    #[test]
    fn runtime_status_serializes_with_stable_wire_labels() {
        let value = serde_json::to_value(RuntimeStatus::SpecialisedLifecycle {
            lane: LifecycleLane::AmlogicNativeSerial,
            generic_construction: GenericConstruction::Refused,
        })
        .unwrap();
        assert_eq!(value["status"], "specialised_lifecycle");
        assert_eq!(value["lane"], "amlogic_native_serial");
        assert_eq!(value["generic_construction"], "refused");

        let value = serde_json::to_value(RuntimeStatus::EvidenceRetainedNotImplemented {
            evidence: &["dcentrald-hal/src/platform/cvitek.rs"],
        })
        .unwrap();
        assert_eq!(value["status"], "evidence_retained_not_implemented");
        assert_eq!(value["evidence"][0], "dcentrald-hal/src/platform/cvitek.rs");
    }

    #[test]
    fn artifact_kind_and_maturity_cannot_disagree() {
        let policy = HardwareEnablementPolicy {
            storage_topology: StorageTopology::Unknown,
            update_mechanism: UpdateMechanism::None,
            update_maturity: ImplementationMaturity::NotImplemented,
            install_authorization: InstallAuthorization::Denied,
            recovery_maturity: RecoveryMaturity::NotImplemented,
            artifact_kind: ArtifactKind::None,
            artifact_maturity: ArtifactMaturity::Experimental,
            external_media_mode: ExternalMediaMode::None,
            external_media_maturity: ExternalMediaMaturity::NotImplemented,
            external_media_authorization: InstallAuthorization::Denied,
        };
        assert!(!policy.artifact_contract_is_consistent());
    }

    #[test]
    fn external_media_does_not_inherit_persistent_update_authority() {
        let policy = HardwareEnablementPolicy {
            storage_topology: StorageTopology::RedundantSlots,
            update_mechanism: UpdateMechanism::ZynqUbiFwSetenv,
            update_maturity: ImplementationMaturity::Experimental,
            install_authorization: InstallAuthorization::PublicBeta,
            recovery_maturity: RecoveryMaturity::NotImplemented,
            artifact_kind: ArtifactKind::SysupgradeBundle,
            artifact_maturity: ArtifactMaturity::Experimental,
            external_media_mode: ExternalMediaMode::BootOnly,
            external_media_maturity: ExternalMediaMaturity::ArtifactGenerated,
            external_media_authorization: InstallAuthorization::Denied,
        };

        assert!(policy.allows_persistent_update());
        assert!(policy.external_media_contract_is_consistent());
        assert!(!policy.allows_external_media_write());
    }

    #[test]
    fn absent_external_media_cannot_carry_writer_authority() {
        let policy = HardwareEnablementPolicy {
            storage_topology: StorageTopology::Unknown,
            update_mechanism: UpdateMechanism::None,
            update_maturity: ImplementationMaturity::NotImplemented,
            install_authorization: InstallAuthorization::Denied,
            recovery_maturity: RecoveryMaturity::NotImplemented,
            artifact_kind: ArtifactKind::None,
            artifact_maturity: ArtifactMaturity::NotImplemented,
            external_media_mode: ExternalMediaMode::None,
            external_media_maturity: ExternalMediaMaturity::NotImplemented,
            external_media_authorization: InstallAuthorization::LabOnly,
        };

        assert!(!policy.external_media_contract_is_consistent());
        assert!(!policy.allows_external_media_write());
    }
}
