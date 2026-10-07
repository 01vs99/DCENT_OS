//! Exact offline S19 XP / S19j XP Amlogic production-route observations.
//!
//! Ten hash-pinned files bind two Awesome 1.2.6 AML NAND root filesystems to
//! their model identities. Independent `hwscan` and `cgminer` ARM32 mapper
//! receipts agree on `/dev/ttyS3`, `/dev/ttyS2`, `/dev/ttyS1` for both models.
//! These facts grant no path, device, UART, GPIO, power, mining, installation,
//! or recovery authority.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X19AmlArtifactPin {
    pub model: &'static str,
    pub artifact_id: &'static str,
    pub rootfs_path: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

pub const X19_AML_ARTIFACTS: [X19AmlArtifactPin; 10] = [
    X19AmlArtifactPin {
        model: "s19xp",
        artifact_id: "vnish-s19xp-1.2.6-hwscan",
        rootfs_path: "usr/bin/hwscan",
        size: 4_001_996,
        sha256: "dcd1e869dd96150775e09f7a5181e53844b7140dd75e9679e0d03aff0ee0da6f",
    },
    X19AmlArtifactPin {
        model: "s19xp",
        artifact_id: "vnish-s19xp-1.2.6-cgminer",
        rootfs_path: "usr/bin/cgminer",
        size: 5_400_552,
        sha256: "6f90b49d4047f9e329140ae5bc0918129aa36be1de8262fb6aeeb7ea69f489e1",
    },
    X19AmlArtifactPin {
        model: "s19xp",
        artifact_id: "vnish-s19xp-1.2.6-fw-info",
        rootfs_path: "etc/fw-info",
        size: 270,
        sha256: "644c9cc6d24b6a915e98d699a2b40f7f673f1c1623eb17de474aacbf50b115ed",
    },
    X19AmlArtifactPin {
        model: "s19xp",
        artifact_id: "vnish-s19xp-1.2.6-s12hwscan",
        rootfs_path: "etc/init.d/S12hwscan",
        size: 493,
        sha256: "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8",
    },
    X19AmlArtifactPin {
        model: "s19xp",
        artifact_id: "vnish-s19xp-1.2.6-s11board",
        rootfs_path: "etc/init.d/S11board",
        size: 2_928,
        sha256: "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4",
    },
    X19AmlArtifactPin {
        model: "s19j-xp",
        artifact_id: "vnish-s19jxp-1.2.6-hwscan",
        rootfs_path: "usr/bin/hwscan",
        size: 3_993_804,
        sha256: "425e99950e9f8539caa209f88b472090c400d27dbe6555124e8e69537ab96909",
    },
    X19AmlArtifactPin {
        model: "s19j-xp",
        artifact_id: "vnish-s19jxp-1.2.6-cgminer",
        rootfs_path: "usr/bin/cgminer",
        size: 5_363_624,
        sha256: "49f0784c7fd181250ac5ff4dfbea1ecb866d56e63f8da48c3b38004757d51059",
    },
    X19AmlArtifactPin {
        model: "s19j-xp",
        artifact_id: "vnish-s19jxp-1.2.6-fw-info",
        rootfs_path: "etc/fw-info",
        size: 273,
        sha256: "2a430a185a224bc719ff9afacc5e8d017f965afa15e7bc22ce82dbfcad2edaf5",
    },
    X19AmlArtifactPin {
        model: "s19j-xp",
        artifact_id: "vnish-s19jxp-1.2.6-s12hwscan",
        rootfs_path: "etc/init.d/S12hwscan",
        size: 493,
        sha256: "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8",
    },
    X19AmlArtifactPin {
        model: "s19j-xp",
        artifact_id: "vnish-s19jxp-1.2.6-s11board",
        rootfs_path: "etc/init.d/S11board",
        size: 2_928,
        sha256: "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X19AmlFirmwareIdentity {
    pub miner: &'static str,
    pub model: &'static str,
    pub platform: &'static str,
    pub install_type: &'static str,
    pub hwscan_command: &'static str,
}

pub const X19_AML_FIRMWARE_IDENTITIES: [X19AmlFirmwareIdentity; 2] = [
    X19AmlFirmwareIdentity {
        miner: "Antminer S19 XP",
        model: "s19xp",
        platform: "aml",
        install_type: "nand",
        hwscan_command: "hwscan --platform aml --gen-model-info s19xp --gen-def-conf s19xp",
    },
    X19AmlFirmwareIdentity {
        miner: "Antminer S19j XP",
        model: "s19j-xp",
        platform: "aml",
        install_type: "nand",
        hwscan_command: "hwscan --platform aml --gen-model-info s19j-xp --gen-def-conf s19j-xp",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X19AmlMapperReceipt {
    pub model: &'static str,
    pub artifact_id: &'static str,
    pub virtual_address: u32,
    pub file_offset: u32,
    pub size: u32,
    pub sha256: &'static str,
    pub mapper_table_virtual_address: u32,
    pub mapper_table_file_offset: u32,
    pub vtable_pointer_virtual_address: u32,
    pub vtable_pointer_file_offset: u32,
}

pub const X19_AML_ROUTE_MAPPERS: [X19AmlMapperReceipt; 4] = [
    X19AmlMapperReceipt {
        model: "s19xp",
        artifact_id: "vnish-s19xp-1.2.6-hwscan",
        virtual_address: 0x000f_acf8,
        file_offset: 0x000e_acf8,
        size: 0x28,
        sha256: "9e4d2cf8a118a561d7ea540823d9bf72d67e445a1301a4c75d27c9bd9c5066ac",
        mapper_table_virtual_address: 0x003d_c558,
        mapper_table_file_offset: 0x003b_c558,
        vtable_pointer_virtual_address: 0x003d_e6c0,
        vtable_pointer_file_offset: 0x003b_e6c0,
    },
    X19AmlMapperReceipt {
        model: "s19xp",
        artifact_id: "vnish-s19xp-1.2.6-cgminer",
        virtual_address: 0x0010_aeac,
        file_offset: 0x000f_aeac,
        size: 0x28,
        sha256: "8c351233f54143a9adfea921761b9bc29b1d11107c96fda4ca4d7cbac9998468",
        mapper_table_virtual_address: 0x0051_5450,
        mapper_table_file_offset: 0x004f_5450,
        vtable_pointer_virtual_address: 0x0051_8238,
        vtable_pointer_file_offset: 0x004f_8238,
    },
    X19AmlMapperReceipt {
        model: "s19j-xp",
        artifact_id: "vnish-s19jxp-1.2.6-hwscan",
        virtual_address: 0x000f_acf8,
        file_offset: 0x000e_acf8,
        size: 0x28,
        sha256: "8fefcfc1b22b57ba292dfc13c2529fb5b81ed8ec13c8077e0ee7f3ca79fee718",
        mapper_table_virtual_address: 0x003d_a558,
        mapper_table_file_offset: 0x003b_a558,
        vtable_pointer_virtual_address: 0x003d_c6c0,
        vtable_pointer_file_offset: 0x003b_c6c0,
    },
    X19AmlMapperReceipt {
        model: "s19j-xp",
        artifact_id: "vnish-s19jxp-1.2.6-cgminer",
        virtual_address: 0x0010_7e8c,
        file_offset: 0x000f_7e8c,
        size: 0x28,
        sha256: "e4807988de8605506d9daadc5fcb438cc063efe63465602efce1a42ab8b865e1",
        mapper_table_virtual_address: 0x0050_c450,
        mapper_table_file_offset: 0x004e_c450,
        vtable_pointer_virtual_address: 0x0050_f230,
        vtable_pointer_file_offset: 0x004e_f230,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X19AmlChainRoute {
    pub zero_based_chain_index: u8,
    pub uart_device: &'static str,
    pub plug_gpio: u16,
    pub reset_gpio: u16,
    pub reset_active_low: bool,
}

pub const X19_AML_CHAIN_ROUTES: [X19AmlChainRoute; 3] = [
    X19AmlChainRoute {
        zero_based_chain_index: 0,
        uart_device: "/dev/ttyS3",
        plug_gpio: 439,
        reset_gpio: 454,
        reset_active_low: true,
    },
    X19AmlChainRoute {
        zero_based_chain_index: 1,
        uart_device: "/dev/ttyS2",
        plug_gpio: 440,
        reset_gpio: 455,
        reset_active_low: true,
    },
    X19AmlChainRoute {
        zero_based_chain_index: 2,
        uart_device: "/dev/ttyS1",
        plug_gpio: 441,
        reset_gpio: 456,
        reset_active_low: true,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X19AmlBoardObservation {
    pub recovery_input_gpio: u16,
    pub ip_report_input_gpio: u16,
    pub power_enable_gpio: u16,
    pub power_enable_startup_value: u8,
    pub plug_input_gpios: [u16; 3],
    pub reset_output_gpios: [u16; 3],
    pub reset_active_low: bool,
    pub led_output_gpios: [u16; 2],
    pub script_has_errexit: bool,
    pub setup_failures_are_fatal: bool,
    pub output_readback_verified: bool,
    pub stop_teardown_present: bool,
}

pub const X19_AML_BOARD_IO: X19AmlBoardObservation = X19AmlBoardObservation {
    recovery_input_gpio: 446,
    ip_report_input_gpio: 445,
    power_enable_gpio: 437,
    power_enable_startup_value: 1,
    plug_input_gpios: [439, 440, 441],
    reset_output_gpios: [454, 455, 456],
    reset_active_low: true,
    led_output_gpios: [453, 438],
    script_has_errexit: false,
    setup_failures_are_fatal: false,
    output_readback_verified: false,
    stop_teardown_present: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X19AmlFanObservation {
    pub front_tach_input_gpios: [u16; 2],
    pub rear_tach_input_gpios: [u16; 2],
    pub tach_edge: &'static str,
    pub pwm_channels: [u8; 2],
    pub pwm_period_ns: u32,
    pub startup_duty_cycle_ns: u32,
    pub startup_enabled: bool,
    pub tach_readback_verified: bool,
    pub airflow_verified: bool,
}

pub const X19_AML_FANS: X19AmlFanObservation = X19AmlFanObservation {
    front_tach_input_gpios: [447, 448],
    rear_tach_input_gpios: [449, 450],
    tach_edge: "falling",
    pwm_channels: [0, 1],
    pwm_period_ns: 100_000,
    startup_duty_cycle_ns: 100_000,
    startup_enabled: true,
    tach_readback_verified: false,
    airflow_verified: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X19AmlPsuObservation {
    pub power_enable_gpio: u16,
    pub startup_value: u8,
    pub software_i2c_gpios: [u16; 2],
    pub interface_label: &'static str,
    pub low_and_high_write_functions_observed: bool,
    pub pic_or_nopic_selection_verified: bool,
    pub psu_protocol_identified: bool,
    pub safe_off_value_verified: bool,
    pub safe_energization_order_verified: bool,
}

pub const X19_AML_PSU: X19AmlPsuObservation = X19AmlPsuObservation {
    power_enable_gpio: 437,
    startup_value: 1,
    software_i2c_gpios: [477, 476],
    interface_label: "i2c:psu-bus",
    low_and_high_write_functions_observed: true,
    pic_or_nopic_selection_verified: false,
    psu_protocol_identified: false,
    safe_off_value_verified: false,
    safe_energization_order_verified: false,
};

pub const X19_AML_UNRESOLVED: [&str; 6] = [
    "exact deployed hashboard identity for both model compositions",
    "PIC or NoPic selection, PSU protocol, voltage units, limits, polarity, safe-off, and ordering",
    "controller revision, exclusive ownership, cold initialization, and failure unwind",
    "live enumeration, work/nonce ownership, and authenticated accepted share",
    "fan/tach/airflow/thermal attribution and watchdog custody",
    "persistent write window, readback, boot selection, rollback, and recovery",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X19AmlProductionRouteAuthority {
    EvidenceOnly,
}

impl X19AmlProductionRouteAuthority {
    pub const fn permits_path_or_device_open(self) -> bool {
        false
    }

    pub const fn permits_uart_or_gpio_io(self) -> bool {
        false
    }

    pub const fn permits_pic_or_psu_io(self) -> bool {
        false
    }

    pub const fn permits_power_or_mining(self) -> bool {
        false
    }

    pub const fn permits_install_or_recovery(self) -> bool {
        false
    }
}

pub const X19_AML_AUTHORITY: X19AmlProductionRouteAuthority =
    X19AmlProductionRouteAuthority::EvidenceOnly;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_producer::{primary_artifact_producer, ArtifactInstallContract};
    use crate::board_desc::{
        AsicProtocolIdentity, BoardDesc, BoardFamily, ChainTransportKind, WorkEngineKind,
    };
    use dcent_schema::hardware::{
        GenericConstruction, InstallAuthorization, LifecycleLane, RuntimeStatus,
    };

    #[test]
    fn exact_ten_artifact_and_two_identity_pins_are_stable() {
        assert_eq!(X19_AML_ARTIFACTS.len(), 10);
        assert_eq!(X19_AML_ARTIFACTS[0].size, 4_001_996);
        assert_eq!(X19_AML_ARTIFACTS[5].size, 3_993_804);
        assert_eq!(
            X19_AML_ARTIFACTS[6].sha256,
            "49f0784c7fd181250ac5ff4dfbea1ecb866d56e63f8da48c3b38004757d51059"
        );
        assert_eq!(
            X19_AML_FIRMWARE_IDENTITIES.map(|identity| identity.model),
            ["s19xp", "s19j-xp"]
        );
        assert!(X19_AML_FIRMWARE_IDENTITIES
            .iter()
            .all(|identity| identity.platform == "aml" && identity.install_type == "nand"));
    }

    #[test]
    fn four_mapper_receipts_agree_without_collapsing_model_identity() {
        assert_eq!(X19_AML_ROUTE_MAPPERS.len(), 4);
        assert_eq!(X19_AML_ROUTE_MAPPERS[0].file_offset, 0x000e_acf8);
        assert_eq!(X19_AML_ROUTE_MAPPERS[1].file_offset, 0x000f_aeac);
        assert_eq!(X19_AML_ROUTE_MAPPERS[2].file_offset, 0x000e_acf8);
        assert_eq!(X19_AML_ROUTE_MAPPERS[3].file_offset, 0x000f_7e8c);
        assert_ne!(
            X19_AML_ROUTE_MAPPERS[0].sha256,
            X19_AML_ROUTE_MAPPERS[2].sha256
        );
        assert_eq!(
            X19_AML_CHAIN_ROUTES.map(|route| route.uart_device),
            ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"]
        );
    }

    #[test]
    fn shared_init_observations_preserve_missing_safety_proof() {
        assert_eq!(X19_AML_BOARD_IO.plug_input_gpios, [439, 440, 441]);
        assert_eq!(X19_AML_BOARD_IO.reset_output_gpios, [454, 455, 456]);
        assert!(X19_AML_BOARD_IO.reset_active_low);
        assert!(!X19_AML_BOARD_IO.setup_failures_are_fatal);
        assert!(!X19_AML_BOARD_IO.output_readback_verified);
        assert!(!X19_AML_BOARD_IO.stop_teardown_present);
        assert_eq!(X19_AML_FANS.front_tach_input_gpios, [447, 448]);
        assert_eq!(X19_AML_FANS.rear_tach_input_gpios, [449, 450]);
        assert!(!X19_AML_FANS.tach_readback_verified);
        assert!(!X19_AML_FANS.airflow_verified);
        assert!(!X19_AML_PSU.pic_or_nopic_selection_verified);
        assert!(!X19_AML_PSU.safe_off_value_verified);
        assert!(!X19_AML_PSU.safe_energization_order_verified);
    }

    #[test]
    fn evidence_only_authority_keeps_every_action_class_closed() {
        assert!(!X19_AML_AUTHORITY.permits_path_or_device_open());
        assert!(!X19_AML_AUTHORITY.permits_uart_or_gpio_io());
        assert!(!X19_AML_AUTHORITY.permits_pic_or_psu_io());
        assert!(!X19_AML_AUTHORITY.permits_power_or_mining());
        assert!(!X19_AML_AUTHORITY.permits_install_or_recovery());
        assert_eq!(X19_AML_UNRESOLVED.len(), 6);
    }

    #[test]
    fn registered_compositions_remain_management_only_and_package_only() {
        // 2026-09 refresh: the XP pair landed its exact native serial route
        // (SpecialisedLifecycle over AmlogicNativeSerial), so the rows are no
        // longer ManagementOnlyByPolicy. What must not move: the package
        // story stays package-only-denied — producer contract, package
        // validation, Denied install authorization, no public beta, and no
        // mining auto-start.
        for target in ["am3-s19xp", "am3-s19jxp"] {
            let board = BoardDesc::lookup(target).expect("registered X19 AML board");
            assert_eq!(board.family, BoardFamily::Amlogic);
            assert_eq!(board.chain_transport, ChainTransportKind::Serial);
            assert_eq!(board.work_engine, WorkEngineKind::SerialWork);
            assert_eq!(board.asic_protocol, AsicProtocolIdentity::Bm1366);
            assert!(matches!(
                board.runtime_status,
                RuntimeStatus::SpecialisedLifecycle {
                    lane: LifecycleLane::AmlogicNativeSerial,
                    generic_construction: GenericConstruction::Refused
                }
            ));
            assert_eq!(
                board.enablement.install_authorization,
                InstallAuthorization::Denied
            );
            assert!(!board.public_beta_install());
            assert!(!board.mining_default_enabled);

            let producer = primary_artifact_producer(target).expect("registered artifact producer");
            assert!(producer.package_validated);
            assert_eq!(
                producer.install_contract,
                ArtifactInstallContract::PackageOnlyDenied
            );
        }
    }
}
