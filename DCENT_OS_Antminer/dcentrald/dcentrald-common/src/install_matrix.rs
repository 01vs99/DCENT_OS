//! Install / packaging matrix derived from [`BoardDesc`] (ADR-0011).
//!
//! Pure host-safe view for toolbox, Docker target tables, docs, and CI.
//! Does **not** replace live install scripts yet — generators should consume
//! this so stringly-typed board lists stop diverging.

use crate::board_desc::{
    BoardDesc, BoardFamily, ChainTransportKind, VoltageControllerClass, WorkEngineKind,
};
use dcent_schema::hardware::{
    HardwareEnablementPolicy, UpdateMechanism, HARDWARE_ENABLEMENT_SCHEMA_VERSION,
};

/// One row of the install/product matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallMatrixRow {
    pub board_target: &'static str,
    pub family: BoardFamily,
    pub chain_transport: ChainTransportKind,
    pub work_engine: WorkEngineKind,
    pub voltage_controller: VoltageControllerClass,
    pub enablement: HardwareEnablementPolicy,
    /// Signed public-beta package is appropriate for first install from a
    /// non-DCENT_OS source.
    pub public_beta_install: bool,
    /// Fresh image may auto-enable mining (almost always false).
    pub mining_default_enabled: bool,
    /// Product install without lab override is allowed.
    pub product_install_allowed: bool,
    /// A/B sysupgrade with fw_setenv is the declared update mechanism.
    pub ab_sysupgrade: bool,
    /// The complete typed policy admits a persistent update API.
    pub persistent_update_allowed: bool,
    /// The independent removable-media facet admits writing an image to a
    /// card. This never implies onboard-storage mutation authority.
    pub external_media_write_allowed: bool,
}

impl From<&BoardDesc> for InstallMatrixRow {
    fn from(d: &BoardDesc) -> Self {
        Self {
            board_target: d.board_target,
            family: d.family,
            chain_transport: d.chain_transport,
            work_engine: d.work_engine,
            voltage_controller: d.voltage_controller,
            enablement: d.enablement,
            public_beta_install: d.public_beta_install(),
            mining_default_enabled: d.mining_default_enabled,
            product_install_allowed: d.product_install_allowed(),
            ab_sysupgrade: matches!(
                d.enablement.update_mechanism,
                UpdateMechanism::ZynqUbiFwSetenv
            ),
            persistent_update_allowed: d.enablement.allows_persistent_update(),
            external_media_write_allowed: d.enablement.allows_external_media_write(),
        }
    }
}

/// Full matrix for every registered [`BoardDesc`].
pub fn install_matrix() -> Vec<InstallMatrixRow> {
    BoardDesc::all_registered()
        .iter()
        .map(InstallMatrixRow::from)
        .collect()
}

/// Board targets allowed for public-beta product install packages.
pub fn public_beta_board_targets() -> Vec<&'static str> {
    install_matrix()
        .into_iter()
        .filter(|r| r.public_beta_install)
        .map(|r| r.board_target)
        .collect()
}

/// Board targets that use Zynq A/B + fw_setenv update rail.
pub fn ab_sysupgrade_board_targets() -> Vec<&'static str> {
    install_matrix()
        .into_iter()
        .filter(|r| r.ab_sysupgrade)
        .map(|r| r.board_target)
        .collect()
}

/// Stable TSV for docs/CI (no external deps).
///
/// The TSV is a derived human-readable view. Machine consumers must use the
/// versioned JSON export so schema drift fails closed.
pub fn install_matrix_tsv() -> String {
    let mut out = String::from(
        "board_target\tfamily\tstorage_topology\tupdate_mechanism\tupdate_maturity\tinstall_authorization\trecovery_maturity\tartifact_kind\tartifact_maturity\texternal_media_mode\texternal_media_maturity\texternal_media_authorization\texternal_media_write_allowed\tpublic_beta_install\tpersistent_update_allowed\ttransport\n",
    );
    for row in install_matrix() {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            row.board_target,
            row.family.as_str(),
            row.enablement.storage_topology.as_str(),
            row.enablement.update_mechanism.as_str(),
            row.enablement.update_maturity.as_str(),
            row.enablement.install_authorization.as_str(),
            row.enablement.recovery_maturity.as_str(),
            row.enablement.artifact_kind.as_str(),
            row.enablement.artifact_maturity.as_str(),
            row.enablement.external_media_mode.as_str(),
            row.enablement.external_media_maturity.as_str(),
            row.enablement.external_media_authorization.as_str(),
            row.external_media_write_allowed as u8,
            row.public_beta_install as u8,
            row.persistent_update_allowed as u8,
            row.chain_transport.as_str(),
        ));
    }
    out
}

/// Canonical versioned machine-readable export for non-Rust consumers.
///
/// Values come exclusively from typed enums; there are no inferred defaults.
pub fn install_matrix_json() -> String {
    let rows = install_matrix();
    let mut out = format!(
        "{{\n  \"schema\": {},\n  \"targets\": [\n",
        HARDWARE_ENABLEMENT_SCHEMA_VERSION
    );
    for (index, row) in rows.iter().enumerate() {
        if index != 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!(
            concat!(
                "    {{\"board_target\":\"{}\",\"family\":\"{}\",",
                "\"storage_topology\":\"{}\",\"update_mechanism\":\"{}\",",
                "\"update_maturity\":\"{}\",\"install_authorization\":\"{}\",",
                "\"recovery_maturity\":\"{}\",\"artifact_kind\":\"{}\",",
                "\"artifact_maturity\":\"{}\",\"external_media_mode\":\"{}\",",
                "\"external_media_maturity\":\"{}\",",
                "\"external_media_authorization\":\"{}\",",
                "\"external_media_write_allowed\":{},\"public_beta_install\":{},",
                "\"persistent_update_allowed\":{},\"transport\":\"{}\"}}"
            ),
            row.board_target,
            row.family.as_str(),
            row.enablement.storage_topology.as_str(),
            row.enablement.update_mechanism.as_str(),
            row.enablement.update_maturity.as_str(),
            row.enablement.install_authorization.as_str(),
            row.enablement.recovery_maturity.as_str(),
            row.enablement.artifact_kind.as_str(),
            row.enablement.artifact_maturity.as_str(),
            row.enablement.external_media_mode.as_str(),
            row.enablement.external_media_maturity.as_str(),
            row.enablement.external_media_authorization.as_str(),
            row.external_media_write_allowed,
            row.public_beta_install,
            row.persistent_update_allowed,
            row.chain_transport.as_str(),
        ));
    }
    out.push_str("\n  ]\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcent_schema::hardware::{
        ArtifactKind, ArtifactMaturity, ExternalMediaMaturity, ExternalMediaMode,
        ImplementationMaturity, InstallAuthorization, RecoveryMaturity, StorageTopology,
    };

    #[test]
    fn public_beta_first_install_is_s9_only() {
        assert_eq!(public_beta_board_targets(), vec!["am1-s9"]);
    }

    #[test]
    fn c43_native_cards_allow_external_media_without_onboard_writer_authority() {
        for target in ["am1-s9se", "am1-s9k"] {
            let row = install_matrix()
                .into_iter()
                .find(|row| row.board_target == target)
                .expect("C43 matrix row");
            assert!(!row.public_beta_install);
            assert!(!row.mining_default_enabled);
            assert!(!row.product_install_allowed);
            assert!(!row.persistent_update_allowed);
            assert!(row.external_media_write_allowed);
            assert_eq!(
                row.enablement.install_authorization,
                InstallAuthorization::Denied
            );
            assert_eq!(
                row.enablement.external_media_authorization,
                InstallAuthorization::LabOnly
            );
            assert_eq!(
                row.enablement.external_media_maturity,
                ExternalMediaMaturity::ArtifactGenerated
            );
            assert_eq!(
                row.enablement.external_media_mode,
                ExternalMediaMode::BootOnly
            );
            assert_eq!(row.chain_transport, ChainTransportKind::StockFpga);
        }
    }

    #[test]
    fn every_public_beta_row_is_ab_sysupgrade() {
        for row in install_matrix()
            .into_iter()
            .filter(|r| r.public_beta_install)
        {
            assert!(
                row.ab_sysupgrade,
                "{} public beta must use A/B fw_setenv",
                row.board_target
            );
            assert!(!row.mining_default_enabled);
            assert!(row.product_install_allowed);
        }
    }

    #[test]
    fn amlogic_rows_are_never_public_install_targets() {
        for row in install_matrix()
            .into_iter()
            .filter(|r| r.family == BoardFamily::Amlogic)
        {
            assert!(!row.public_beta_install, "{}", row.board_target);
            assert!(
                matches!(
                    row.enablement.install_authorization,
                    InstallAuthorization::LabOnly | InstallAuthorization::Denied
                ),
                "{} must remain lab-only or denied",
                row.board_target
            );
            if matches!(
                row.board_target,
                // The Unknown-storage rows: native runtime shipped/implemented,
                // but no persistent install geometry is admitted. 2026-09-12
                // (drift13 #6a / R10 board join): am3-s19jproa joins with the
                // PACKAGE_ONLY promotion — its shipped package surface
                // (shared am3-bm1362-nopic builder, package_only_denied)
                // claims no storage writer.
                "am3-s19xp" | "am3-s19jxp" | "am3-s21xp" | "am3-t21" | "am3-s19jproa"
                // L12 retirement (2026-09-15): Classic has no compatible
                // persistent writer (mtd5=config, mtd6=nvdata) — Unknown
                // topology, no storage writer claimed.
                | "am3-s19jpro-aml"
            ) {
                assert_eq!(row.enablement.storage_topology, StorageTopology::Unknown);
                assert_eq!(row.enablement.update_mechanism, UpdateMechanism::None);
            } else {
                assert_eq!(
                    row.enablement.storage_topology,
                    StorageTopology::SingleSlot,
                    "{}",
                    row.board_target
                );
            }
            assert_eq!(row.chain_transport, ChainTransportKind::Serial);
        }
    }

    #[test]
    fn cv1835_has_no_artifact_or_install_lane() {
        let row = install_matrix()
            .into_iter()
            .find(|row| row.board_target == "cv1835-s19jpro")
            .expect("CV1835 row");
        assert_eq!(row.enablement.storage_topology, StorageTopology::SingleSlot);
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
        assert!(!row.persistent_update_allowed);
        assert!(!row.product_install_allowed);
    }

    #[test]
    fn am2_public_update_does_not_authorize_vendor_source_first_install() {
        let row = install_matrix()
            .into_iter()
            .find(|row| row.board_target == "am2-s19j")
            .expect("registered AM2 S19j row");
        assert_eq!(
            row.enablement.install_authorization,
            InstallAuthorization::PublicBeta
        );
        assert!(row.persistent_update_allowed);
        assert!(!row.public_beta_install);
        assert!(!row.product_install_allowed);
        assert_eq!(
            row.enablement.external_media_mode,
            ExternalMediaMode::BootOnly
        );
        assert_eq!(
            row.enablement.external_media_maturity,
            ExternalMediaMaturity::ArtifactGenerated
        );
        assert_eq!(
            row.enablement.external_media_authorization,
            InstallAuthorization::LabOnly
        );
        assert!(row.external_media_write_allowed);
    }

    #[test]
    fn s17_native_card_grants_media_without_onboard_update_authority() {
        let row = install_matrix()
            .into_iter()
            .find(|row| row.board_target == "am2-s17p")
            .expect("registered AM2 S17 row");
        assert_eq!(
            row.enablement.update_maturity,
            ImplementationMaturity::NotImplemented
        );
        assert_eq!(
            row.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert_eq!(row.enablement.artifact_kind, ArtifactKind::SysupgradeBundle);
        assert_eq!(
            row.enablement.artifact_maturity,
            ArtifactMaturity::Experimental
        );
        assert_eq!(
            row.enablement.external_media_mode,
            ExternalMediaMode::BootOnly
        );
        assert_eq!(
            row.enablement.external_media_maturity,
            ExternalMediaMaturity::ArtifactGenerated
        );
        assert_eq!(
            row.enablement.external_media_authorization,
            InstallAuthorization::LabOnly
        );
        assert!(!row.persistent_update_allowed);
        assert!(row.external_media_write_allowed);
        assert!(!row.product_install_allowed);
        assert!(!row.public_beta_install);
    }

    #[test]
    fn external_media_facets_distinguish_s9_am2_and_beaglebone_proof() {
        let rows = install_matrix();
        let s9 = rows
            .iter()
            .find(|row| row.board_target == "am1-s9")
            .unwrap();
        assert_eq!(
            s9.enablement.external_media_mode,
            ExternalMediaMode::BootOnly
        );
        assert_eq!(
            s9.enablement.external_media_maturity,
            ExternalMediaMaturity::BootWitnessed
        );
        assert_eq!(
            s9.enablement.external_media_authorization,
            InstallAuthorization::PublicBeta
        );
        assert!(s9.external_media_write_allowed);

        let bb = rows
            .iter()
            .find(|row| row.board_target == "am3-bb-s19jpro")
            .unwrap();
        assert_eq!(
            bb.enablement.external_media_mode,
            ExternalMediaMode::BootOnly
        );
        assert_eq!(
            bb.enablement.external_media_maturity,
            ExternalMediaMaturity::MediaWritten
        );
        assert_eq!(
            bb.enablement.external_media_authorization,
            InstallAuthorization::LabOnly
        );
        assert!(bb.external_media_write_allowed);

        let aml = rows
            .iter()
            .find(|row| row.board_target == "am3-s21")
            .unwrap();
        assert_eq!(aml.enablement.external_media_mode, ExternalMediaMode::None);
        assert!(!aml.external_media_write_allowed);
    }

    #[test]
    fn metadata_only_targets_have_no_artifact_or_install_lane() {
        // 2026-08-27 armada (C1): am2-s17plus/am2-t17/am2-t17plus left this
        // set when B2 shipped their package-only board lanes (defconfig +
        // sysupgrade tar + package_only_denied contract); am2-t19 stays
        // metadata-only.
        for target in ["am2-t19"] {
            let row = install_matrix()
                .into_iter()
                .find(|row| row.board_target == target)
                .unwrap_or_else(|| panic!("missing metadata-only target {target}"));
            assert_eq!(
                row.enablement.update_maturity,
                ImplementationMaturity::NotImplemented,
                "{target}"
            );
            assert_eq!(
                row.enablement.install_authorization,
                InstallAuthorization::Denied,
                "{target}"
            );
            assert_eq!(row.enablement.artifact_kind, ArtifactKind::None, "{target}");
            assert_eq!(
                row.enablement.artifact_maturity,
                ArtifactMaturity::NotImplemented,
                "{target}"
            );
            assert!(!row.persistent_update_allowed, "{target}");
            assert!(!row.product_install_allowed, "{target}");
        }
    }

    #[test]
    fn exact_a113d_s19jproplus_package_has_guarded_lab_install_authority() {
        for target in ["am3-s19jproplus"] {
            let row = install_matrix()
                .into_iter()
                .find(|row| row.board_target == target)
                .unwrap_or_else(|| panic!("missing guarded Amlogic target {target}"));
            assert_eq!(
                row.enablement.update_maturity,
                ImplementationMaturity::Experimental,
                "{target}"
            );
            assert_eq!(
                row.enablement.install_authorization,
                InstallAuthorization::LabOnly,
                "{target}"
            );
            assert_eq!(
                row.enablement.artifact_kind,
                ArtifactKind::SysupgradeBundle,
                "{target}"
            );
            assert_eq!(
                row.enablement.artifact_maturity,
                ArtifactMaturity::Experimental,
                "{target}"
            );
            assert!(row.persistent_update_allowed, "{target}");
            assert!(!row.product_install_allowed, "{target}");
        }
    }

    #[test]
    fn x19_aml_packages_grant_no_persistent_writer_authority() {
        for target in ["am3-s19xp", "am3-s19jxp"] {
            let row = install_matrix()
                .into_iter()
                .find(|row| row.board_target == target)
                .unwrap_or_else(|| panic!("missing X19 AML target {target}"));
            assert_eq!(
                row.enablement.update_maturity,
                ImplementationMaturity::NotImplemented,
                "{target}"
            );
            assert_eq!(
                row.enablement.install_authorization,
                InstallAuthorization::Denied,
                "{target}"
            );
            assert_eq!(
                row.enablement.artifact_kind,
                ArtifactKind::SysupgradeBundle,
                "{target}"
            );
            assert_eq!(
                row.enablement.artifact_maturity,
                ArtifactMaturity::Experimental,
                "{target}"
            );
            assert!(!row.persistent_update_allowed, "{target}");
            assert!(!row.product_install_allowed, "{target}");
        }
    }

    #[test]
    fn t21_package_evidence_grants_no_persistent_writer_authority() {
        let row = install_matrix()
            .into_iter()
            .find(|row| row.board_target == "am3-t21")
            .expect("missing T21 package-evidence target");
        assert_eq!(
            row.enablement.update_maturity,
            ImplementationMaturity::NotImplemented
        );
        assert_eq!(
            row.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert_eq!(row.enablement.storage_topology, StorageTopology::Unknown);
        assert_eq!(row.enablement.update_mechanism, UpdateMechanism::None);
        assert_eq!(row.enablement.artifact_kind, ArtifactKind::SysupgradeBundle);
        assert_eq!(
            row.enablement.artifact_maturity,
            ArtifactMaturity::Experimental
        );
        assert!(!row.persistent_update_allowed);
        assert!(!row.product_install_allowed);
    }

    #[test]
    fn tsv_contains_header_and_beta_targets() {
        let tsv = install_matrix_tsv();
        assert!(tsv.starts_with("board_target\t"));
        assert!(tsv.contains("am1-s9\t"));
        assert!(tsv.contains("am2-s19j\t"));
        assert!(tsv.contains("am3-s21\t"));
    }

    #[test]
    fn matrix_len_matches_registry() {
        assert_eq!(install_matrix().len(), BoardDesc::all_registered().len());
    }

    #[test]
    fn tsv_row_count_matches_registry_plus_header() {
        let tsv = install_matrix_tsv();
        let lines: Vec<_> = tsv.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), BoardDesc::all_registered().len() + 1);
        assert!(tsv.contains('\t'), "TSV must use tab separators");
    }

    #[test]
    fn json_is_versioned_and_contains_typed_cv_policy() {
        let json = install_matrix_json();
        assert!(json.starts_with("{\n  \"schema\": 4,"));
        assert!(json.contains("\"board_target\":\"cv1835-s19jpro\""));
        assert!(json.contains("\"artifact_kind\":\"none\""));
        assert!(json.contains("\"artifact_maturity\":\"not_implemented\""));
        assert!(json.contains("\"update_maturity\":\"not_implemented\""));
        assert!(json.contains("\"install_authorization\":\"denied\""));
        assert!(json.contains("\"external_media_mode\":\"none\""));
    }

    /// Drift pin: committed `docs/architecture/install_matrix.tsv` must match
    /// `install_matrix_tsv()`. Regenerate with
    /// `scripts/export_install_matrix.ps1` after BoardDesc changes.
    #[test]
    fn committed_install_matrix_tsv_matches_generator() {
        // Crate root is dcentrald-common/; docs live under DCENT_OS_Antminer/docs/.
        // src/ -> .. = crate, ../.. = dcentrald/, ../../.. = dcentos/
        let committed = include_str!("../../../docs/architecture/install_matrix.tsv");
        let generated = install_matrix_tsv();
        let norm = |s: &str| {
            s.replace("\r\n", "\n")
                .trim_end()
                .lines()
                .map(str::trim_end)
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(
            norm(committed),
            norm(&generated),
            "install_matrix.tsv drifted from BoardDesc registry — re-run scripts/export_install_matrix.ps1"
        );
    }

    #[test]
    fn committed_install_matrix_json_matches_generator() {
        let committed = include_str!("../../../docs/architecture/hardware_enablement_matrix.json");
        assert_eq!(
            committed.replace("\r\n", "\n"),
            install_matrix_json(),
            "hardware_enablement_matrix.json drifted from BoardDesc registry"
        );
    }
}
