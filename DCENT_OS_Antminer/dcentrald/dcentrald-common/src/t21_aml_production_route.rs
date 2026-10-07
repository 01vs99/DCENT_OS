//! Exact, offline-only T21 Amlogic production-route evidence.
//!
//! Five hash-pinned files from the held VNish/Awesome 1.2.6 NAND rootfs
//! associate `model=t21` with `platform=aml`. Two independent ARM32
//! executables map chain indices 0/1/2 to `/dev/ttyS3`, `/dev/ttyS2`, and
//! `/dev/ttyS1`; the init script records the associated GPIO/PWM setup.
//!
//! Everything in this module is passive data. It cannot open a path or
//! device, touch UART/GPIO/I2C/PWM, select a PIC/PSU protocol, energize a
//! rail, start mining, install firmware, or execute recovery.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21AmlArtifactPin {
    pub artifact_id: &'static str,
    pub rootfs_path: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

pub const T21_AML_ARTIFACTS: [T21AmlArtifactPin; 5] = [
    T21AmlArtifactPin {
        artifact_id: "vnish-t21-1.2.6-hwscan",
        rootfs_path: "usr/bin/hwscan",
        size: 4_001_996,
        sha256: "dcd1e869dd96150775e09f7a5181e53844b7140dd75e9679e0d03aff0ee0da6f",
    },
    T21AmlArtifactPin {
        artifact_id: "vnish-t21-1.2.6-cgminer",
        rootfs_path: "usr/bin/cgminer",
        size: 5_384_168,
        sha256: "da66295ab17273d7e6a8805958c9e47ee364e57a55c38528e801240a5e7c0735",
    },
    T21AmlArtifactPin {
        artifact_id: "vnish-t21-1.2.6-fw-info",
        rootfs_path: "etc/fw-info",
        size: 265,
        sha256: "60638646b5fc4807498d10240bbce8461ca9f5aa7b343d25089217186474e7db",
    },
    T21AmlArtifactPin {
        artifact_id: "vnish-t21-1.2.6-s12hwscan",
        rootfs_path: "etc/init.d/S12hwscan",
        size: 493,
        sha256: "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8",
    },
    T21AmlArtifactPin {
        artifact_id: "vnish-t21-1.2.6-s11board",
        rootfs_path: "etc/init.d/S11board",
        size: 2_928,
        sha256: "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21AmlFirmwareIdentity {
    pub firmware_name: &'static str,
    pub firmware_version: &'static str,
    pub miner: &'static str,
    pub model: &'static str,
    pub platform: &'static str,
    pub install_type: &'static str,
    pub hwscan_command: &'static str,
}

pub const T21_AML_FIRMWARE_IDENTITY: T21AmlFirmwareIdentity = T21AmlFirmwareIdentity {
    firmware_name: "Awesome",
    firmware_version: "1.2.6",
    miner: "Antminer T21",
    model: "t21",
    platform: "aml",
    install_type: "nand",
    hwscan_command: "hwscan --platform aml --gen-model-info t21 --gen-def-conf t21",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21AmlFunctionReceipt {
    pub artifact_id: &'static str,
    pub name: &'static str,
    pub virtual_address: u32,
    pub file_offset: u32,
    pub size: u32,
    pub sha256: &'static str,
    pub mapper_table_virtual_address: u32,
    pub mapper_table_file_offset: u32,
    pub vtable_pointer_virtual_address: u32,
    pub vtable_pointer_file_offset: u32,
}

pub const T21_AML_ROUTE_MAPPERS: [T21AmlFunctionReceipt; 2] = [
    T21AmlFunctionReceipt {
        artifact_id: "vnish-t21-1.2.6-hwscan",
        name: "AML chain UART mapper",
        virtual_address: 0x000f_acf8,
        file_offset: 0x000e_acf8,
        size: 0x28,
        sha256: "9e4d2cf8a118a561d7ea540823d9bf72d67e445a1301a4c75d27c9bd9c5066ac",
        mapper_table_virtual_address: 0x003d_c558,
        mapper_table_file_offset: 0x003b_c558,
        vtable_pointer_virtual_address: 0x003d_e6c0,
        vtable_pointer_file_offset: 0x003b_e6c0,
    },
    T21AmlFunctionReceipt {
        artifact_id: "vnish-t21-1.2.6-cgminer",
        name: "AML chain UART mapper",
        virtual_address: 0x0010_7e34,
        file_offset: 0x000f_7e34,
        size: 0x28,
        sha256: "2898396347770a76c65f6f32a55c804b776d360ab1443e2e9bf712b907e80af5",
        mapper_table_virtual_address: 0x0051_1450,
        mapper_table_file_offset: 0x004f_1450,
        vtable_pointer_virtual_address: 0x0051_4238,
        vtable_pointer_file_offset: 0x004f_4238,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21AmlChainRoute {
    pub zero_based_chain_index: u8,
    pub uart_device: &'static str,
    pub plug_gpio: u16,
    pub reset_gpio: u16,
    pub reset_active_low: bool,
}

pub const T21_AML_CHAIN_ROUTES: [T21AmlChainRoute; 3] = [
    T21AmlChainRoute {
        zero_based_chain_index: 0,
        uart_device: "/dev/ttyS3",
        plug_gpio: 439,
        reset_gpio: 454,
        reset_active_low: true,
    },
    T21AmlChainRoute {
        zero_based_chain_index: 1,
        uart_device: "/dev/ttyS2",
        plug_gpio: 440,
        reset_gpio: 455,
        reset_active_low: true,
    },
    T21AmlChainRoute {
        zero_based_chain_index: 2,
        uart_device: "/dev/ttyS1",
        plug_gpio: 441,
        reset_gpio: 456,
        reset_active_low: true,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21AmlBoardIoObservation {
    pub recovery_input_gpio: u16,
    pub ip_report_input_gpio: u16,
    pub power_enable_gpio: u16,
    pub power_enable_startup_value: u8,
    pub plug_input_gpios: [u16; 3],
    pub plug_pull_down_requested: bool,
    pub reset_output_gpios: [u16; 3],
    pub reset_active_low: bool,
    pub green_led_output_gpio: u16,
    pub red_led_output_gpio: u16,
    pub script_has_errexit: bool,
    pub setup_failures_are_fatal: bool,
    pub output_readback_verified: bool,
    pub stop_teardown_present: bool,
}

pub const T21_AML_BOARD_IO: T21AmlBoardIoObservation = T21AmlBoardIoObservation {
    recovery_input_gpio: 446,
    ip_report_input_gpio: 445,
    power_enable_gpio: 437,
    power_enable_startup_value: 1,
    plug_input_gpios: [439, 440, 441],
    plug_pull_down_requested: true,
    reset_output_gpios: [454, 455, 456],
    reset_active_low: true,
    green_led_output_gpio: 453,
    red_led_output_gpio: 438,
    script_has_errexit: false,
    setup_failures_are_fatal: false,
    output_readback_verified: false,
    stop_teardown_present: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21AmlFanObservation {
    pub front_tach_input_gpios: [u16; 2],
    pub rear_tach_input_gpios: [u16; 2],
    pub tach_edge: &'static str,
    pub pwm_chip: u8,
    pub rear_pwm_channel: u8,
    pub front_pwm_channel: u8,
    pub pwm_period_ns: u32,
    pub startup_duty_cycle_ns: u32,
    pub startup_enabled: bool,
    pub tach_readback_verified: bool,
    pub airflow_verified: bool,
    pub setup_failures_are_fatal: bool,
}

pub const T21_AML_FANS: T21AmlFanObservation = T21AmlFanObservation {
    front_tach_input_gpios: [447, 448],
    rear_tach_input_gpios: [449, 450],
    tach_edge: "falling",
    pwm_chip: 0,
    rear_pwm_channel: 0,
    front_pwm_channel: 1,
    pwm_period_ns: 100_000,
    startup_duty_cycle_ns: 100_000,
    startup_enabled: true,
    tach_readback_verified: false,
    airflow_verified: false,
    setup_failures_are_fatal: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21AmlPsuObservation {
    pub scope: &'static str,
    pub power_enable_gpio: u16,
    pub startup_value: u8,
    pub software_i2c_gpios: [u16; 2],
    pub interface_label: &'static str,
    pub low_and_high_write_functions_observed: bool,
    pub psu_family_identified: bool,
    pub protocol_identified: bool,
    pub safe_off_value_verified: bool,
    pub safe_energization_order_verified: bool,
}

pub const T21_AML_PSU: T21AmlPsuObservation = T21AmlPsuObservation {
    scope: "board-global code and init-script observation only",
    power_enable_gpio: 437,
    startup_value: 1,
    software_i2c_gpios: [477, 476],
    interface_label: "i2c:psu-bus",
    low_and_high_write_functions_observed: true,
    psu_family_identified: false,
    protocol_identified: false,
    safe_off_value_verified: false,
    safe_energization_order_verified: false,
};

pub const T21_AML_UNRESOLVED: [&str; 6] = [
    "PIC implementation, address, command effects, and production selection",
    "PSU family, wire protocol, limits, retry behavior, safe-off value, and safe ordering",
    "exact T21 EEPROM page or live miner-model/hw-info result",
    "controller revision and carrier electrical validation",
    "cold initialization, failure unwind, fan/tach/airflow proof, and live chain enumeration",
    "persistent install, recovery offsets, readback, boot, and rollback behavior",
];

/// The only authority class available from this evidence module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T21AmlProductionRouteAuthority {
    EvidenceOnly,
}

impl T21AmlProductionRouteAuthority {
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

pub const T21_AML_AUTHORITY: T21AmlProductionRouteAuthority =
    T21AmlProductionRouteAuthority::EvidenceOnly;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_producer::{primary_artifact_producer, ArtifactInstallContract};
    use crate::board_desc::{
        AsicProtocolIdentity, BoardDesc, BoardFamily, ChainTransportKind, VoltageControllerClass,
        WorkEngineKind,
    };
    use dcent_schema::hardware::RuntimeStatus;

    #[test]
    fn exact_artifact_and_identity_pins_are_stable() {
        assert_eq!(T21_AML_ARTIFACTS.len(), 5);
        assert_eq!(T21_AML_ARTIFACTS[0].size, 4_001_996);
        assert_eq!(
            T21_AML_ARTIFACTS[0].sha256,
            "dcd1e869dd96150775e09f7a5181e53844b7140dd75e9679e0d03aff0ee0da6f"
        );
        assert_eq!(T21_AML_ARTIFACTS[4].rootfs_path, "etc/init.d/S11board");
        assert_eq!(T21_AML_FIRMWARE_IDENTITY.model, "t21");
        assert_eq!(T21_AML_FIRMWARE_IDENTITY.platform, "aml");
        assert_eq!(T21_AML_FIRMWARE_IDENTITY.install_type, "nand");
    }

    #[test]
    fn independent_mapper_receipts_agree_on_the_direct_uart_route() {
        assert_eq!(T21_AML_ROUTE_MAPPERS.len(), 2);
        assert_eq!(T21_AML_ROUTE_MAPPERS[0].virtual_address, 0x000f_acf8);
        assert_eq!(T21_AML_ROUTE_MAPPERS[0].file_offset, 0x000e_acf8);
        assert_eq!(T21_AML_ROUTE_MAPPERS[1].virtual_address, 0x0010_7e34);
        assert_eq!(T21_AML_ROUTE_MAPPERS[1].file_offset, 0x000f_7e34);
        assert_eq!(
            T21_AML_CHAIN_ROUTES.map(|route| route.uart_device),
            ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"]
        );
        assert!(T21_AML_CHAIN_ROUTES
            .iter()
            .all(|route| route.reset_active_low));
    }

    #[test]
    fn init_observations_preserve_missing_safety_proof() {
        assert_eq!(T21_AML_BOARD_IO.plug_input_gpios, [439, 440, 441]);
        assert_eq!(T21_AML_BOARD_IO.reset_output_gpios, [454, 455, 456]);
        assert!(!T21_AML_BOARD_IO.setup_failures_are_fatal);
        assert!(!T21_AML_BOARD_IO.output_readback_verified);
        assert!(!T21_AML_BOARD_IO.stop_teardown_present);
        assert_eq!(T21_AML_FANS.front_tach_input_gpios, [447, 448]);
        assert_eq!(T21_AML_FANS.rear_tach_input_gpios, [449, 450]);
        assert_eq!(T21_AML_FANS.pwm_period_ns, 100_000);
        assert_eq!(T21_AML_FANS.startup_duty_cycle_ns, 100_000);
        assert!(!T21_AML_FANS.tach_readback_verified);
        assert!(!T21_AML_FANS.airflow_verified);
        assert!(!T21_AML_PSU.safe_off_value_verified);
        assert!(!T21_AML_PSU.safe_energization_order_verified);
    }

    #[test]
    fn evidence_only_authority_keeps_every_action_class_closed() {
        assert!(!T21_AML_AUTHORITY.permits_path_or_device_open());
        assert!(!T21_AML_AUTHORITY.permits_uart_or_gpio_io());
        assert!(!T21_AML_AUTHORITY.permits_pic_or_psu_io());
        assert!(!T21_AML_AUTHORITY.permits_power_or_mining());
        assert!(!T21_AML_AUTHORITY.permits_install_or_recovery());
        assert_eq!(T21_AML_UNRESOLVED.len(), 6);
    }

    #[test]
    fn board_and_artifact_contracts_remain_management_only_and_denied() {
        let board = BoardDesc::lookup("am3-t21").expect("registered T21 board");
        assert_eq!(board.family, BoardFamily::Amlogic);
        assert_eq!(board.chain_transport, ChainTransportKind::Serial);
        assert_eq!(board.work_engine, WorkEngineKind::ManagementOnly);
        assert_eq!(board.asic_protocol, AsicProtocolIdentity::Bm1368);
        assert_eq!(
            board.voltage_controller,
            VoltageControllerClass::RuntimeDiscovered
        );
        assert!(matches!(
            board.runtime_status,
            RuntimeStatus::ManagementOnlyByPolicy { .. }
        ));
        assert!(!board.public_beta_install());
        assert!(!board.mining_default_enabled);

        let producer =
            primary_artifact_producer("am3-t21").expect("registered T21 artifact producer");
        assert!(producer.package_validated);
        assert_eq!(
            producer.install_contract,
            ArtifactInstallContract::PackageOnlyDenied
        );
    }
}
