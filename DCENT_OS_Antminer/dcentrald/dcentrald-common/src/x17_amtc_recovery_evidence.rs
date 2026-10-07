//! Exact offline X17 AMTC recovery-script and T17e archive observations.
//!
//! The parent/member facts below describe held recovery media only. In
//! particular, the exact T17e central directory contains no `runme.sh`; its
//! boot payloads therefore cannot inherit the S17+/T17+/S17e shell-writer
//! behavior. No media writer, archive extractor, flash operation, boot,
//! install, rollback, or recovery authority is exposed here.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X17RecoveryArtifactPin {
    pub association: &'static str,
    pub artifact_id: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

pub const X17_RECOVERY_PARENTS: [X17RecoveryArtifactPin; 4] = [
    X17RecoveryArtifactPin {
        association: "S17+ recovery",
        artifact_id: "S17+ SD-card ZIP",
        size: 32_189_053,
        sha256: "af5f4e80050debdfba5eaf78c0b93a2ddac39f4ba3dd257102b188614cbbbdfd",
    },
    X17RecoveryArtifactPin {
        association: "T17+ recovery",
        artifact_id: "SD_T17+.zip",
        size: 46_958_987,
        sha256: "1d933dff55d751a6e5cbdb4d572079456e9a6c3aca9fafc8f6cb531c822ee6f7",
    },
    X17RecoveryArtifactPin {
        association: "S17e recovery",
        artifact_id: "SD-S17e.zip",
        size: 48_844_056,
        sha256: "74b8b553e39b487a382cb7f1a6def12ba06630bfb6923640650db953fe9f2bbc",
    },
    X17RecoveryArtifactPin {
        association: "T17e recovery",
        artifact_id: "SD_T17e.zip",
        size: 48_748_519,
        sha256: "5eca68d32fbe724b43a2e66ba9d7d8102efa3f41dee67442c2bbc2d95eb8f238",
    },
];

pub const X17_RECOVERY_SCRIPT_MEMBERS: [X17RecoveryArtifactPin; 2] = [
    X17RecoveryArtifactPin {
        association: "S17+/T17+ base recovery writer member",
        artifact_id: "base_runme",
        size: 1_061,
        sha256: "b8aeed73da5e2bec12704cc9a5eb7653ca661a42a102752ebfdc71db14e6fda7",
    },
    X17RecoveryArtifactPin {
        association: "S17e anti-downgrade recovery writer member",
        artifact_id: "antidowngrade_runme",
        size: 1_571,
        sha256: "755088b87278c328798b9180266ae1128dece8ca863cd621c1dc5fedaa010c59",
    },
];

pub const T17E_RECOVERY_CENTRAL_DIRECTORY_ENTRIES: [&str; 11] = [
    "SD_T17e/",
    "SD_T17e/BOOT.bin",
    "SD_T17e/devicetree.dtb",
    "SD_T17e/.DS_Store",
    "SD_T17e/bin/",
    "SD_T17e/bin/BOOT.bin",
    "SD_T17e/bin/devicetree.dtb",
    "SD_T17e/bin/uImage",
    "SD_T17e/bin/uramdisk.image.gz",
    "SD_T17e/uImage",
    "SD_T17e/uramdisk.image.gz",
];

pub const T17E_RECOVERY_CENTRAL_DIRECTORY_SIZES: [u64; 11] = [
    0, 2_751_032, 7_650, 8_196, 0, 2_735_664, 7_650, 4_006_832, 12_991_279, 4_006_832, 27_125_535,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X17RecoveryWriterObservation {
    pub ordered_targets: [&'static str; 5],
    pub rootfs_md5_only: bool,
    pub boot_components_authenticated: bool,
    pub command_exit_status_checked: bool,
    pub rollback_implemented: bool,
    pub t17e_parent_exact_bytes_verified: bool,
    pub t17e_central_directory_verified: bool,
    pub t17e_runme_member_absence_verified: bool,
    pub t17e_boot_execution_semantics_verified: bool,
}

pub const X17_RECOVERY_WRITER_OBSERVATION: X17RecoveryWriterObservation =
    X17RecoveryWriterObservation {
        ordered_targets: [
            "mtd0:BOOT@0",
            "mtd0:DTB@0x1a00000",
            "mtd0:uImage@0x2000000",
            "mtd1:rootfs@0",
            "optional mtd4:rootfs-backup@0",
        ],
        rootfs_md5_only: true,
        boot_components_authenticated: false,
        command_exit_status_checked: false,
        rollback_implemented: false,
        t17e_parent_exact_bytes_verified: true,
        t17e_central_directory_verified: true,
        t17e_runme_member_absence_verified: true,
        t17e_boot_execution_semantics_verified: false,
    };

pub const X17_RECOVERY_UNRESOLVED: [&str; 6] = [
    "exact deployed controller and NAND identity for every X17 model",
    "authenticated boot-component provenance and target compatibility",
    "T17e boot-media entry and execution semantics without runme.sh",
    "checked write/readback, atomicity, rollback, and power-loss recovery",
    "independent watchdog and known-safe electrical state throughout recovery",
    "authorized live boot, health, mining, and stock-recovery acceptance",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X17RecoveryAuthority {
    EvidenceOnly,
}

impl X17RecoveryAuthority {
    pub const fn permits_path_or_archive_open(self) -> bool {
        false
    }

    pub const fn permits_media_or_flash_write(self) -> bool {
        false
    }

    pub const fn permits_install_or_recovery(self) -> bool {
        false
    }

    pub const fn permits_boot_or_reboot(self) -> bool {
        false
    }

    pub const fn permits_hardware_or_network_contact(self) -> bool {
        false
    }
}

pub const X17_RECOVERY_AUTHORITY: X17RecoveryAuthority = X17RecoveryAuthority::EvidenceOnly;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_desc::{
        AsicProtocolIdentity, BoardDesc, ChainTransportKind, VoltageControllerClass, WorkEngineKind,
    };
    use dcent_schema::hardware::{
        GenericConstruction, InstallAuthorization, LifecycleLane, RuntimeStatus,
    };

    #[test]
    fn four_parent_and_two_script_pins_are_exact_and_distinct() {
        assert_eq!(X17_RECOVERY_PARENTS.len(), 4);
        assert_eq!(X17_RECOVERY_SCRIPT_MEMBERS.len(), 2);
        assert_eq!(X17_RECOVERY_PARENTS[3].size, 48_748_519);
        assert_ne!(
            X17_RECOVERY_PARENTS[2].sha256,
            X17_RECOVERY_PARENTS[3].sha256
        );
        assert_eq!(X17_RECOVERY_SCRIPT_MEMBERS[0].size, 1_061);
        assert_eq!(X17_RECOVERY_SCRIPT_MEMBERS[1].size, 1_571);
    }

    #[test]
    fn exact_t17e_inventory_has_boot_payloads_but_no_script() {
        assert_eq!(T17E_RECOVERY_CENTRAL_DIRECTORY_ENTRIES.len(), 11);
        assert_eq!(T17E_RECOVERY_CENTRAL_DIRECTORY_SIZES.len(), 11);
        assert_eq!(T17E_RECOVERY_CENTRAL_DIRECTORY_SIZES[1], 2_751_032);
        assert_eq!(T17E_RECOVERY_CENTRAL_DIRECTORY_SIZES[5], 2_735_664);
        assert!(T17E_RECOVERY_CENTRAL_DIRECTORY_ENTRIES
            .iter()
            .all(|name| !name.ends_with("/bin/runme.sh")));
        assert!(X17_RECOVERY_WRITER_OBSERVATION.t17e_runme_member_absence_verified);
        assert!(!X17_RECOVERY_WRITER_OBSERVATION.t17e_boot_execution_semantics_verified);
    }

    #[test]
    fn observed_script_writer_is_non_atomic_and_non_authorizing() {
        assert!(X17_RECOVERY_WRITER_OBSERVATION.rootfs_md5_only);
        assert!(!X17_RECOVERY_WRITER_OBSERVATION.boot_components_authenticated);
        assert!(!X17_RECOVERY_WRITER_OBSERVATION.command_exit_status_checked);
        assert!(!X17_RECOVERY_WRITER_OBSERVATION.rollback_implemented);
        assert_eq!(X17_RECOVERY_UNRESOLVED.len(), 6);
    }

    #[test]
    fn evidence_only_authority_keeps_every_action_class_closed() {
        assert!(!X17_RECOVERY_AUTHORITY.permits_path_or_archive_open());
        assert!(!X17_RECOVERY_AUTHORITY.permits_media_or_flash_write());
        assert!(!X17_RECOVERY_AUTHORITY.permits_install_or_recovery());
        assert!(!X17_RECOVERY_AUTHORITY.permits_boot_or_reboot());
        assert!(!X17_RECOVERY_AUTHORITY.permits_hardware_or_network_contact());
    }

    #[test]
    fn s17e_t17e_owned_native_descriptors_keep_generic_and_install_denied() {
        // Both exact native owners retain stock fabric custody. Recovery-jig
        // evidence supplies neither generic construction nor install authority.
        let s17e = BoardDesc::lookup("am2-s17e").expect("registered BM1396 target");
        assert_eq!(s17e.asic_protocol, AsicProtocolIdentity::Bm1396);
        assert_eq!(s17e.chain_transport, ChainTransportKind::StockFpga);
        assert_eq!(s17e.work_engine, WorkEngineKind::FpgaWorkFifo);
        assert_eq!(
            s17e.voltage_controller,
            VoltageControllerClass::Bm1396FramedI2c11
        );
        assert!(matches!(
            s17e.runtime_status,
            RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Bm1396Native,
                generic_construction: GenericConstruction::Refused
            }
        ));
        assert_eq!(
            s17e.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert!(!s17e.public_beta_install());
        assert!(!s17e.mining_default_enabled);
        assert!(s17e.admit_protocol_transport_and_work_engine().is_err());

        // am2-t17e landed its exact native cold-300 BM1396 runtime
        // (SpecialisedLifecycle over the retained stock fabric). The
        // fail-closed law that must survive: install stays Denied, and the
        // generic BM1396 protocol admit still refuses an active transport
        // (BM1396 is pure-only; the native runtime owns its exact custody).
        let t17e = BoardDesc::lookup("am2-t17e").expect("registered BM1396 target");
        assert_eq!(t17e.asic_protocol, AsicProtocolIdentity::Bm1396);
        assert_eq!(t17e.chain_transport, ChainTransportKind::StockFpga);
        assert_eq!(t17e.work_engine, WorkEngineKind::FpgaWorkFifo);
        assert_eq!(
            t17e.voltage_controller,
            VoltageControllerClass::Bm1396FramedI2c11
        );
        assert!(matches!(
            t17e.runtime_status,
            RuntimeStatus::SpecialisedLifecycle {
                lane: LifecycleLane::Bm1396Native,
                generic_construction: GenericConstruction::Refused
            }
        ));
        assert_eq!(
            t17e.enablement.install_authorization,
            InstallAuthorization::Denied
        );
        assert!(!t17e.public_beta_install());
        assert!(!t17e.mining_default_enabled);
        assert!(
            t17e.admit_protocol_transport_and_work_engine().is_err(),
            "am2-t17e generic admit must stay refused"
        );
    }
}
