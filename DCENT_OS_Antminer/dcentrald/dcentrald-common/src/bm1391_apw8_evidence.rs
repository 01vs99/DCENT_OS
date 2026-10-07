//! Exact offline S15/T15 APW8-adjacent software and guide observations.
//!
//! Six hash-pinned artifacts bind two December-2019 stock miners to the same
//! FPGA general-I2C command tuple and retain separate maintenance-guide facts.
//! They do not join GPIO907 to APW8 `PWR_EN`, authenticate the package
//! publisher, establish a wire checksum, prove safe voltage limits, or grant
//! any path, device, I/O, power, mining, install, factory, or live authority.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391Apw8ArtifactPin {
    pub artifact_id: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

const fn artifact(
    artifact_id: &'static str,
    size: u64,
    sha256: &'static str,
) -> Bm1391Apw8ArtifactPin {
    Bm1391Apw8ArtifactPin {
        artifact_id,
        size,
        sha256,
    }
}

pub const BM1391_APW8_ARTIFACTS: [Bm1391Apw8ArtifactPin; 6] = [
    artifact(
        "bitmain-s15-20191213-signed-envelope",
        24_962_829,
        "68a1ba8f3597b6775c2d226482e72bcc8095358020cd3bb2c07a8eec886f5e71",
    ),
    artifact(
        "bitmain-s15-20191213-cgminer",
        691_180,
        "3cf4302b87d5c5588f3c6cbfb2eb3e46dc7545da4d62f715651e84e0dde119c8",
    ),
    artifact(
        "bitmain-t15-20191213-signed-envelope",
        23_696_441,
        "7bd2c1105267be53545ffe5a87e75a6049524caab34cb4af8f14700e79eff7b4",
    ),
    artifact(
        "bitmain-t15-20191213-cgminer",
        691_180,
        "fdeaf71ab1d8e1613e9dd0353621cd07c349179d450999d51e31e0df308cdf01",
    ),
    artifact(
        "bitmain-s15-maintenance-guide-20190702",
        3_800_577,
        "4496807c14291da95bdc4ba399097f8a3d5f1c15d0cab882dcd57c10e5e2ab27",
    ),
    artifact(
        "bitmain-apw8-maintenance-guide",
        1_853_200,
        "a8694c6eff734784c91c71a6e6d7ceff0cf25b8e98494d8d535cc8ecfdd43214",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391Apw8FunctionReceipt {
    pub model: &'static str,
    pub name: &'static str,
    pub analysis_address: u32,
    pub file_offset: u32,
    pub size: u32,
    pub sha256: &'static str,
}

const fn function(
    model: &'static str,
    name: &'static str,
    analysis_address: u32,
    file_offset: u32,
    size: u32,
    sha256: &'static str,
) -> Bm1391Apw8FunctionReceipt {
    Bm1391Apw8FunctionReceipt {
        model,
        name,
        analysis_address,
        file_offset,
        size,
        sha256,
    }
}

pub const BM1391_APW8_FUNCTIONS: [Bm1391Apw8FunctionReceipt; 16] = [
    function(
        "S15",
        "gpio907 software power_on",
        0x79f50,
        0x71f50,
        0x60,
        "47d5ba70d8a5f600350ebd9472434a54bd4911642f06b1831b3f22a9343da696",
    ),
    function(
        "S15",
        "gpio907 software power_off",
        0x7a06c,
        0x7206c,
        0x60,
        "976a0626aa0d7d42eb9f78cb6ca8f39b0c4b6ca27ec8eda101254781dc9adcab",
    ),
    function(
        "S15",
        "FPGA I2C power-byte wrapper",
        0x7a3b0,
        0x723b0,
        0x60,
        "92dfb3b5924d7152cafe324df3d0f4f71a085c9f8882ccf952a1b7068a767413",
    ),
    function(
        "S15",
        "set_iic_power_by_voltage",
        0x7a57c,
        0x7257c,
        0x158,
        "0a4fed13ff070e85cf52320a4c7d79ef5d032635a74b4f6e71d6b4aa32e80a35",
    ),
    function(
        "S15",
        "power conversion constants",
        0x7a6a0,
        0x726a0,
        0x18,
        "a0769edabc069045cbf692ce0837a338945abaa17ba5189baf886fbd063eed15",
    ),
    function(
        "S15",
        "PIC heartbeat",
        0x7e304,
        0x76304,
        0x80,
        "3207a7d461340074e03efd4634ff4e0b024eaf43f6b36336a4d3a08d0bb48fe1",
    ),
    function(
        "S15",
        "FPGA general-I2C command helper",
        0x86aec,
        0x7eaec,
        0x64,
        "d73a0d1ec0a679930e1d0e1c62fe0598d9e2e9efa43158d208cbd186063ea745",
    ),
    function(
        "S15",
        "GPIO907 strings",
        0xa8910,
        0xa0910,
        0xd8,
        "3b7752b05ec8284cb6063821c67c0913e031b3b6d790ce13ab84c7c37e32b1f0",
    ),
    function(
        "T15",
        "gpio907 software power_on",
        0x79f18,
        0x71f18,
        0x60,
        "0ba5907dc32ebcb26809368c3cdca2ff77c695e46e88960c92ebe4d3b5389064",
    ),
    function(
        "T15",
        "gpio907 software power_off",
        0x7a034,
        0x72034,
        0x60,
        "731707267315867742dcffb5bca414c150819b55a79ca6affec5f564a12f14f4",
    ),
    function(
        "T15",
        "FPGA I2C power-byte wrapper",
        0x7a378,
        0x72378,
        0x60,
        "5f24b0031997a7135ad6406849941fad6c5e9be8ae8f36300c8f7ae18ca96232",
    ),
    function(
        "T15",
        "set_iic_power_by_voltage",
        0x7a544,
        0x72544,
        0x158,
        "08112e3d69521000b585fcd046e9855418d75ec363bd785d0f5a9bf648a3e677",
    ),
    function(
        "T15",
        "power conversion constants",
        0x7a668,
        0x72668,
        0x18,
        "a0769edabc069045cbf692ce0837a338945abaa17ba5189baf886fbd063eed15",
    ),
    function(
        "T15",
        "PIC heartbeat",
        0x7e2cc,
        0x762cc,
        0x80,
        "c04fbffbd985d29a978e9330ba9a71cb9be822d47bd93515f02dbd220b0ce8ba",
    ),
    function(
        "T15",
        "FPGA general-I2C command helper",
        0x86a0c,
        0x7ea0c,
        0x64,
        "fee34622fdfcbc2b7e6d9c1b266f1833257a528a60691b583bbef6a75680851e",
    ),
    function(
        "T15",
        "GPIO907 strings",
        0xa8830,
        0xa0830,
        0xd8,
        "3b7752b05ec8284cb6063821c67c0913e031b3b6d790ce13ab84c7c37e32b1f0",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1391Apw8SoftwareObservation {
    pub fpga_register_offset: u8,
    pub i2c_device_address: u8,
    pub fpga_bus_selector: u8,
    pub read_direction: bool,
    pub register_prefix_enabled: bool,
    pub register_address: u8,
    pub payload_bytes: u8,
    pub packed_command_base_without_payload: u32,
    pub poll_iterations: u16,
    pub poll_interval_us: u32,
    pub wrapper_pre_delay_us: u32,
    pub caller_post_delay_us: u32,
    pub raw_byte_bounds: [u16; 2],
    pub conversion_slope: f64,
    pub conversion_intercept: f64,
    pub conversion_units_verified: bool,
    pub helper_result_consumed: bool,
    pub write_readback_observed: bool,
    pub userspace_checksum_bytes_observed: u8,
    pub wire_checksum_rule_verified: bool,
    pub software_power_on_level: u8,
    pub software_power_off_level: u8,
    pub gpio907_physical_binding_verified: bool,
}

pub const BM1391_APW8_SOFTWARE: Bm1391Apw8SoftwareObservation = Bm1391Apw8SoftwareObservation {
    fpga_register_offset: 0x30,
    i2c_device_address: 0x10,
    fpga_bus_selector: 1,
    read_direction: false,
    register_prefix_enabled: true,
    register_address: 0x02,
    payload_bytes: 1,
    packed_command_base_without_payload: 0x0520_0200,
    poll_iterations: 101,
    poll_interval_us: 5_000,
    wrapper_pre_delay_us: 100_000,
    caller_post_delay_us: 300_000,
    raw_byte_bounds: [0, 255],
    conversion_slope: 59.931_506_85,
    conversion_intercept: 1215.894_44,
    conversion_units_verified: false,
    helper_result_consumed: false,
    write_readback_observed: false,
    userspace_checksum_bytes_observed: 0,
    wire_checksum_rule_verified: false,
    software_power_on_level: 0,
    software_power_off_level: 1,
    gpio907_physical_binding_verified: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1391Apw8HeartbeatObservation {
    pub frame: [u8; 6],
    pub expected_reply: [u8; 2],
    pub attempts: u8,
    pub caller_period_seconds: u8,
    pub failure_action: &'static str,
    pub electrical_safe_off_verified: bool,
}

pub const BM1391_APW8_HEARTBEAT: Bm1391Apw8HeartbeatObservation = Bm1391Apw8HeartbeatObservation {
    frame: [0x55, 0xaa, 0x04, 0x16, 0x00, 0x1a],
    expected_reply: [0x16, 0x01],
    attempts: 3,
    caller_period_seconds: 10,
    failure_action: "retry/log only",
    electrical_safe_off_verified: false,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1391Apw8GuideObservation {
    pub document_version: &'static str,
    pub named_products: [&'static str; 2],
    pub named_psu: &'static str,
    pub adjustable_output_range_v: [f64; 2],
    pub adjustable_output_max_a: f64,
    pub fixed_output_v: f64,
    pub fixed_output_max_a: f64,
    pub documented_values_are_runtime_safe_limits: bool,
    pub control_signals: [&'static str; 3],
    pub en_documented_effective_level: u8,
    pub guide_en_polarity_bound_to_gpio907: bool,
    pub controller_label: &'static str,
    pub controller_revision: &'static str,
    pub j11_signals: [&'static str; 3],
    pub linux_gpio_printed_for_pwr_en: bool,
    pub topology_pages_1_and_3: &'static str,
    pub topology_page_10: &'static str,
    pub topology_internally_consistent: bool,
    pub exact_release_controller_binding_verified: bool,
}

pub const BM1391_APW8_GUIDE: Bm1391Apw8GuideObservation = Bm1391Apw8GuideObservation {
    document_version: "2019.07.02",
    named_products: ["S15", "T15"],
    named_psu: "APW8",
    adjustable_output_range_v: [16.32, 20.04],
    adjustable_output_max_a: 95.0,
    fixed_output_v: 12.0,
    fixed_output_max_a: 5.0,
    documented_values_are_runtime_safe_limits: false,
    control_signals: ["SDA", "SCL", "EN"],
    en_documented_effective_level: 0,
    guide_en_polarity_bound_to_gpio907: false,
    controller_label: "Ctrl_C43",
    controller_revision: "V1.2011",
    j11_signals: ["PWR_I2C_SDA", "PWR_I2C_SCL", "PWR_EN"],
    linux_gpio_printed_for_pwr_en: false,
    topology_pages_1_and_3: "12 voltage domains; 5 chips/domain; 60 chips",
    topology_page_10: "6 chips in each domain",
    topology_internally_consistent: false,
    exact_release_controller_binding_verified: false,
};

pub const BM1391_APW8_UNRESOLVED: [&str; 7] = [
    "exact resident NAND DTB at 0x01a00000 for each controller",
    "net-level GPIO907 to J11 PWR_EN correlation and polarity",
    "electrical capture of device 0x10 register 0x02 transaction",
    "wire checksum or integrity behavior below the FPGA command register",
    "APW8 revision and exact release/controller association",
    "T15 board revision and independent physical topology",
    "safe operational voltage limits and fail-safe de-energization proof",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391Apw8Authority {
    EvidenceOnly,
}

impl Bm1391Apw8Authority {
    pub const fn permits_path_or_device_open(self) -> bool {
        false
    }

    pub const fn permits_i2c_or_gpio_io(self) -> bool {
        false
    }

    pub const fn permits_power_or_voltage_change(self) -> bool {
        false
    }

    pub const fn permits_pic_or_mining_io(self) -> bool {
        false
    }

    pub const fn permits_install_factory_or_live_probe(self) -> bool {
        false
    }
}

pub const BM1391_APW8_AUTHORITY: Bm1391Apw8Authority = Bm1391Apw8Authority::EvidenceOnly;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_desc::{
        AsicProtocolIdentity, BoardDesc, ChainTransportKind, VoltageControllerClass, WorkEngineKind,
    };
    use dcent_schema::hardware::{GenericConstruction, LifecycleLane, RuntimeStatus};

    #[test]
    fn six_artifact_and_sixteen_function_pins_are_exact() {
        assert_eq!(BM1391_APW8_ARTIFACTS.len(), 6);
        assert_eq!(BM1391_APW8_FUNCTIONS.len(), 16);
        assert_eq!(BM1391_APW8_ARTIFACTS[0].size, 24_962_829);
        assert_eq!(BM1391_APW8_ARTIFACTS[5].size, 1_853_200);
        assert_eq!(
            BM1391_APW8_FUNCTIONS
                .iter()
                .filter(|receipt| receipt.model == "S15")
                .count(),
            8
        );
        assert_eq!(
            BM1391_APW8_FUNCTIONS
                .iter()
                .filter(|receipt| receipt.model == "T15")
                .count(),
            8
        );
    }

    #[test]
    fn software_tuple_retains_unknown_units_and_integrity() {
        assert_eq!(BM1391_APW8_SOFTWARE.fpga_register_offset, 0x30);
        assert_eq!(BM1391_APW8_SOFTWARE.i2c_device_address, 0x10);
        assert_eq!(BM1391_APW8_SOFTWARE.register_address, 0x02);
        assert_eq!(
            BM1391_APW8_SOFTWARE.packed_command_base_without_payload,
            0x0520_0200
        );
        assert!(!BM1391_APW8_SOFTWARE.conversion_units_verified);
        assert!(!BM1391_APW8_SOFTWARE.helper_result_consumed);
        assert!(!BM1391_APW8_SOFTWARE.write_readback_observed);
        assert!(!BM1391_APW8_SOFTWARE.wire_checksum_rule_verified);
        assert!(!BM1391_APW8_SOFTWARE.gpio907_physical_binding_verified);
    }

    #[test]
    fn guide_and_heartbeat_do_not_form_a_safe_power_join() {
        assert_eq!(BM1391_APW8_GUIDE.named_products, ["S15", "T15"]);
        assert_eq!(BM1391_APW8_GUIDE.named_psu, "APW8");
        assert_eq!(BM1391_APW8_GUIDE.adjustable_output_range_v, [16.32, 20.04]);
        assert_eq!(BM1391_APW8_GUIDE.en_documented_effective_level, 0);
        assert!(!BM1391_APW8_GUIDE.guide_en_polarity_bound_to_gpio907);
        assert!(!BM1391_APW8_GUIDE.topology_internally_consistent);
        assert!(!BM1391_APW8_GUIDE.exact_release_controller_binding_verified);
        assert_eq!(BM1391_APW8_HEARTBEAT.attempts, 3);
        assert_eq!(BM1391_APW8_HEARTBEAT.failure_action, "retry/log only");
        assert!(!BM1391_APW8_HEARTBEAT.electrical_safe_off_verified);
    }

    #[test]
    fn evidence_only_authority_keeps_every_action_class_closed() {
        assert!(!BM1391_APW8_AUTHORITY.permits_path_or_device_open());
        assert!(!BM1391_APW8_AUTHORITY.permits_i2c_or_gpio_io());
        assert!(!BM1391_APW8_AUTHORITY.permits_power_or_voltage_change());
        assert!(!BM1391_APW8_AUTHORITY.permits_pic_or_mining_io());
        assert!(!BM1391_APW8_AUTHORITY.permits_install_factory_or_live_probe());
        assert_eq!(BM1391_APW8_UNRESOLVED.len(), 7);
    }

    #[test]
    fn registered_s15_t15_compositions_remain_capture_first_and_closed() {
        // 2026-09 refresh: both rows carry their exact held native BM1391
        // runtime (stock-FPGA fabric + application-PIC custody) as a
        // SpecialisedLifecycle lane, but the composition stays closed:
        // BM1391 is pure-only (no active protocol admit), install stays
        // Denied with Ring-2 opt-in dispatch only, and mining never
        // auto-starts. A conflicting 60/72-chip variant cannot borrow this
        // admission.
        for target in ["am1-s15", "am1-t15"] {
            let board = BoardDesc::lookup(target).expect("registered BM1391 board");
            assert_eq!(board.chain_transport, ChainTransportKind::StockFpga);
            assert_eq!(board.work_engine, WorkEngineKind::FpgaWorkFifo);
            assert_eq!(board.asic_protocol, AsicProtocolIdentity::Bm1391);
            assert_eq!(
                board.voltage_controller,
                VoltageControllerClass::Bm1391Application
            );
            assert!(matches!(
                board.runtime_status,
                RuntimeStatus::SpecialisedLifecycle {
                    lane: LifecycleLane::Bm1391Native,
                    generic_construction: GenericConstruction::Refused
                }
            ));
            assert!(board.release_channel.is_publishable());
            assert!(!board.public_beta_install());
            assert!(!board.mining_default_enabled);
            assert_eq!(
                board.enablement.install_authorization,
                dcent_schema::hardware::InstallAuthorization::Denied
            );
            // The generic protocol+transport+work admit must still refuse:
            // BM1391 is pure-only and the stock-FPGA fabric takes no
            // FpgaWorkFifo work admit.
            assert!(
                board.admit_protocol_transport_and_work_engine().is_err(),
                "{target} must refuse the generic mining admit"
            );
        }
    }
}
