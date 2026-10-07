//! Exact offline AMTC factory-profile observations for S17 and T17+.
//!
//! The sibling Python exact-byte inspector validates the held ZIP members and
//! their factory binaries. This module carries the resulting typed facts into
//! the shared no-I/O crate. Factory settings are not production defaults:
//! raw voltage units, carrier ownership, electrical limits, cooling safety,
//! runtime identity, installation, and recovery all remain unproved.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X17AmtcArtifactPin {
    pub artifact_id: &'static str,
    pub member_path: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

pub const X17_AMTC_FACTORY_ARTIFACTS: [X17AmtcArtifactPin; 4] = [
    X17AmtcArtifactPin {
        artifact_id: "s17_config",
        member_path: "S17 testing ZIP::0/Config.ini",
        size: 2_019,
        sha256: "1cf8e105ab9fae0f047538b0894c86e2335436ad90ab8043b1a87821fc192ae4",
    },
    X17AmtcArtifactPin {
        artifact_id: "s17_factory_jig",
        member_path: "S17 testing ZIP::0/single-board-test",
        size: 583_696,
        sha256: "89695fc1287897c63b7c3404944e19e3b21396dbed7768e2d75d4a432b7c0b41",
    },
    X17AmtcArtifactPin {
        artifact_id: "t17plus_config",
        member_path: "T17+TestJig.zip::T17+/Config.ini",
        size: 1_990,
        sha256: "18c716f074badb97801679474f189adbfb991c3fa2bd24d69a2ca059075cdb20",
    },
    X17AmtcArtifactPin {
        artifact_id: "t17plus_factory_jig",
        member_path: "T17+TestJig.zip::T17+/single-board-test",
        size: 516_132,
        sha256: "8c01ce2c7ab18e489e72340daa4feb971342d72dc79aaa358680c71434befb28",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X17AmtcArchivePin {
    pub association: &'static str,
    pub filename: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

pub const X17_AMTC_FACTORY_ARCHIVES: [X17AmtcArchivePin; 2] = [
    X17AmtcArchivePin {
        association: "S17 factory",
        filename: "S17 testing ZIP",
        size: 30_206_409,
        sha256: "88c64db57c77e5fced012c946e144ba45f7bded536ef8e13413cbf12c4d61b8e",
    },
    X17AmtcArchivePin {
        association: "T17+ factory",
        filename: "T17+TestJig.zip",
        size: 29_089_700,
        sha256: "201ae4a91ae72bce91d69d8006d0564a2dc377f93c14b48b844bf9d77f3c477b",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X17AmtcFactoryBaudObservation {
    /// S17 `baudrate=` uses the Bitmain enum/divider vocabulary.
    ConfigEnum { raw: u32, resolved_bps: u32 },
    /// T17+ stores a literal bits-per-second value.
    LiteralBps(u32),
}

impl X17AmtcFactoryBaudObservation {
    pub const fn resolved_bps(self) -> u32 {
        match self {
            Self::ConfigEnum { resolved_bps, .. } => resolved_bps,
            Self::LiteralBps(value) => value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X17AmtcFactoryProfile {
    pub model_label: &'static str,
    pub hashboard: &'static str,
    pub asic_type_text: &'static str,
    pub asic_count: u8,
    pub config_artifact_id: &'static str,
    pub factory_binary_artifact_id: &'static str,
    pub frequency_steps_mhz: [u16; 9],
    pub open_core_gap: Option<u32>,
    pub timeout_percent: u8,
    pub baud: X17AmtcFactoryBaudObservation,
    pub open_core_voltage_raw: u16,
    pub voltage_steps_raw: [u16; 9],
    pub sensor_label: &'static str,
    pub sensor_model: u8,
    pub temp_sensor_indices: [Option<u8>; 4],
    pub fan_setting: u8,
    pub fan_scale_max: u8,
    pub core_clock_delay: u8,
}

pub const X17_AMTC_FACTORY_PROFILES: [X17AmtcFactoryProfile; 2] = [
    X17AmtcFactoryProfile {
        model_label: "S17",
        hashboard: "BHB07601",
        asic_type_text: "1397",
        asic_count: 48,
        config_artifact_id: "s17_config",
        factory_binary_artifact_id: "s17_factory_jig",
        frequency_steps_mhz: [450, 0, 0, 0, 0, 0, 0, 0, 0],
        open_core_gap: Some(20_000),
        timeout_percent: 10,
        baud: X17AmtcFactoryBaudObservation::ConfigEnum {
            raw: 3,
            resolved_bps: 6_000_000,
        },
        open_core_voltage_raw: 2_000,
        voltage_steps_raw: [1_900, 0, 0, 0, 0, 0, 0, 0, 0],
        sensor_label: "TMP451 (sensor_model=1 comment)",
        sensor_model: 1,
        temp_sensor_indices: [Some(9), Some(12), Some(40), Some(37)],
        fan_setting: 10,
        fan_scale_max: 10,
        core_clock_delay: 0x34,
    },
    X17AmtcFactoryProfile {
        model_label: "T17+",
        hashboard: "BHB07702",
        asic_type_text: "1397",
        asic_count: 44,
        config_artifact_id: "t17plus_config",
        factory_binary_artifact_id: "t17plus_factory_jig",
        frequency_steps_mhz: [700, 680, 630, 630, 700, 680, 600, 550, 0],
        open_core_gap: None,
        timeout_percent: 90,
        baud: X17AmtcFactoryBaudObservation::LiteralBps(6_000_000),
        open_core_voltage_raw: 1_850,
        voltage_steps_raw: [1_750, 1_770, 1_750, 1_780, 1_730, 1_750, 1_800, 1_830, 0],
        sensor_label: "NCT218 (Sensor_Model=1 comment)",
        sensor_model: 1,
        temp_sensor_indices: [None, None, None, None],
        fan_setting: 100,
        fan_scale_max: 100,
        core_clock_delay: 0x34,
    },
];

pub fn x17_amtc_factory_profile(model_label: &str) -> Option<&'static X17AmtcFactoryProfile> {
    X17_AMTC_FACTORY_PROFILES
        .iter()
        .find(|profile| profile.model_label == model_label)
}

pub const X17_AMTC_FACTORY_UNRESOLVED: [&str; 7] = [
    "factory raw-voltage units and electrically safe envelope",
    "production frequency, timeout, OpenCoreGap, voltage, fan, and sensor profile",
    "same-unit controller revision, physical MCU identity, and application ABI",
    "exclusive FPGA/PIC/carrier ownership and verified rail-off",
    "model-bound thermal, tach, cooling, and watchdog composition",
    "live enumeration, work/nonce ownership, and authenticated accepted share",
    "atomic install, readback, boot, rollback, and recovery",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X17AmtcFactoryAuthority {
    EvidenceOnly,
}

impl X17AmtcFactoryAuthority {
    pub const fn permits_factory_execution(self) -> bool {
        false
    }

    pub const fn permits_runtime_or_power(self) -> bool {
        false
    }

    pub const fn permits_voltage_or_cooling_control(self) -> bool {
        false
    }

    pub const fn permits_install_or_recovery(self) -> bool {
        false
    }

    pub const fn permits_production_defaults(self) -> bool {
        false
    }
}

pub const X17_AMTC_FACTORY_AUTHORITY: X17AmtcFactoryAuthority =
    X17AmtcFactoryAuthority::EvidenceOnly;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_desc::{
        AsicProtocolIdentity, BoardDesc, BoardFamily, ChainTransportKind, WorkEngineKind,
    };
    use dcent_schema::hardware::RuntimeStatus;

    #[test]
    fn exact_archive_and_member_pins_are_stable() {
        assert_eq!(X17_AMTC_FACTORY_ARCHIVES[0].size, 30_206_409);
        assert_eq!(
            X17_AMTC_FACTORY_ARCHIVES[1].sha256,
            "201ae4a91ae72bce91d69d8006d0564a2dc377f93c14b48b844bf9d77f3c477b"
        );
        assert_eq!(X17_AMTC_FACTORY_ARTIFACTS.len(), 4);
        assert_eq!(X17_AMTC_FACTORY_ARTIFACTS[0].size, 2_019);
        assert_eq!(X17_AMTC_FACTORY_ARTIFACTS[3].size, 516_132);
    }

    #[test]
    fn s17_factory_profile_is_exact_and_factory_scoped() {
        let profile = x17_amtc_factory_profile("S17").expect("held S17 factory profile");
        assert_eq!(profile.hashboard, "BHB07601");
        assert_eq!(profile.asic_count, 48);
        assert_eq!(profile.frequency_steps_mhz, [450, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(profile.open_core_gap, Some(20_000));
        assert_eq!(profile.timeout_percent, 10);
        assert_eq!(
            profile.baud,
            X17AmtcFactoryBaudObservation::ConfigEnum {
                raw: 3,
                resolved_bps: 6_000_000
            }
        );
        assert_eq!(profile.open_core_voltage_raw, 2_000);
        assert_eq!(
            profile.temp_sensor_indices,
            [Some(9), Some(12), Some(40), Some(37)]
        );
        assert_eq!((profile.fan_setting, profile.fan_scale_max), (10, 10));
    }

    #[test]
    fn t17plus_factory_profile_keeps_distinct_grammar_and_values() {
        let profile = x17_amtc_factory_profile("T17+").expect("held T17+ factory profile");
        assert_eq!(profile.hashboard, "BHB07702");
        assert_eq!(profile.asic_count, 44);
        assert_eq!(
            profile.frequency_steps_mhz,
            [700, 680, 630, 630, 700, 680, 600, 550, 0]
        );
        assert_eq!(profile.open_core_gap, None);
        assert_eq!(profile.timeout_percent, 90);
        assert_eq!(
            profile.baud,
            X17AmtcFactoryBaudObservation::LiteralBps(6_000_000)
        );
        assert_eq!(profile.open_core_voltage_raw, 1_850);
        assert_eq!(profile.voltage_steps_raw[7], 1_830);
        assert_eq!(profile.temp_sensor_indices, [None, None, None, None]);
        assert_eq!((profile.fan_setting, profile.fan_scale_max), (100, 100));
        assert!(x17_amtc_factory_profile("S17Pro").is_none());
    }

    #[test]
    fn factory_evidence_never_mints_action_or_production_authority() {
        assert!(!X17_AMTC_FACTORY_AUTHORITY.permits_factory_execution());
        assert!(!X17_AMTC_FACTORY_AUTHORITY.permits_runtime_or_power());
        assert!(!X17_AMTC_FACTORY_AUTHORITY.permits_voltage_or_cooling_control());
        assert!(!X17_AMTC_FACTORY_AUTHORITY.permits_install_or_recovery());
        assert!(!X17_AMTC_FACTORY_AUTHORITY.permits_production_defaults());
        assert_eq!(X17_AMTC_FACTORY_UNRESOLVED.len(), 7);
    }

    #[test]
    fn registered_s17_and_t17plus_compositions_use_owned_stock_fabric() {
        // Factory evidence still grants no authority. The current exact
        // S17 lifecycle owns stock FPGA work framing and controller custody.
        for target in ["am2-s17p", "am2-t17plus"] {
            let board = BoardDesc::lookup(target).expect("registered X17 board");
            assert_eq!(board.family, BoardFamily::Zynq);
            assert_eq!(board.chain_transport, ChainTransportKind::StockFpga);
            assert_eq!(board.work_engine, WorkEngineKind::FpgaWorkFifo);
            assert_eq!(board.asic_protocol, AsicProtocolIdentity::Bm1397);
            assert!(board.runtime_status.permits_mining_lane());
            assert!(!board.public_beta_install());
            assert!(!board.mining_default_enabled);
        }
    }
}
