//! Exact offline S21 XP air AML route and topology evidence.
//!
//! Three independent production-software observations agree on the direct
//! UART route, but they do not establish a safe executable platform. In
//! particular, the exact route contradicts the shared S21 `ttyS4` third-lane
//! assumption, production PIC selection remains unresolved, and an independent
//! topology artifact declares PIC1704 rather than proving the current NoPic
//! inheritance. This module exposes observations only and grants no I/O,
//! power, runtime, installation, factory, or live-validation authority.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S21XpArtifactPin {
    pub artifact_id: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

/// Ten unique exact artifacts. `S11board` is consumed by both Python evidence
/// inspectors but appears once here because its byte identity is identical.
pub const S21XP_AML_ARTIFACTS: [S21XpArtifactPin; 10] = [
    S21XpArtifactPin {
        artifact_id: "bosminer-model-list",
        size: 16_854,
        sha256: "c79f56e2d2a3f1e593b21d8a79a5364b2997e76f09b2ee9167fac64d1bf7dfe0",
    },
    S21XpArtifactPin {
        artifact_id: "bosminer-unpacked",
        size: 23_963_080,
        sha256: "5a49dcbe2e2d9f4fb047eca856e71440bd73fc020a817e808b5af3b45a7c8707",
    },
    S21XpArtifactPin {
        artifact_id: "vnish-s21xp-air-devicetree",
        size: 20_945,
        sha256: "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257",
    },
    S21XpArtifactPin {
        artifact_id: "vnish-s21xp-air-s11board",
        size: 2_928,
        sha256: "bbc25a2137fd35ff97d6aa545992d21e4d7d35303fe5650b1b226fdd94b249c4",
    },
    S21XpArtifactPin {
        artifact_id: "bitmain-s21xp-single-board-test",
        size: 4_073_320,
        sha256: "4b4e08d1f206836749b71b2a01822a66127fbf7d9904d0ba91427e28fd4f3f61",
    },
    S21XpArtifactPin {
        artifact_id: "epic-v1.22.0-hashboard-topology",
        size: 72_339,
        sha256: "fec8360ac48ae46938c41037daf93907ac556b84432e07111a237b6bd9b5cbfa",
    },
    S21XpArtifactPin {
        artifact_id: "vnish-s21xp-1.2.7-hwscan",
        size: 4_574_504,
        sha256: "9cfd4593fab33a58442fed55ff5c6205b6b07283a56677926b03b8ea1166a396",
    },
    S21XpArtifactPin {
        artifact_id: "vnish-s21xp-1.2.7-cgminer",
        size: 5_798_548,
        sha256: "d71f268b8ec18f29f45a9cb20b34ed3976e2011d1ca6268c61cd2f8a7ac39e3b",
    },
    S21XpArtifactPin {
        artifact_id: "vnish-s21xp-1.2.7-fw-info",
        size: 295,
        sha256: "899e9bde7780b0ec53406d01c7f08e4bf947617259d543aea820116a3abae531",
    },
    S21XpArtifactPin {
        artifact_id: "vnish-s21xp-1.2.7-s12hwscan",
        size: 493,
        sha256: "445b70b3e15687c1e9aef738d9bc8c4a9cf475765937109b136d32c2dd978db8",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S21XpRouteReceipt {
    pub source: &'static str,
    pub source_index_base: u8,
    pub devices_in_source_order: [&'static str; 3],
}

pub const S21XP_ROUTE_RECEIPTS: [S21XpRouteReceipt; 3] = [
    S21XpRouteReceipt {
        source: "VNish 1.2.7 hwscan AML vtable mapper",
        source_index_base: 0,
        devices_in_source_order: ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"],
    },
    S21XpRouteReceipt {
        source: "VNish 1.2.7 cgminer AML vtable mapper",
        source_index_base: 0,
        devices_in_source_order: ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"],
    },
    S21XpRouteReceipt {
        source: "Bosminer am3-aml hashchain tty formatter",
        source_index_base: 1,
        devices_in_source_order: ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"],
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S21XpProductionChain {
    pub zero_based_chain: u8,
    pub uart_device: &'static str,
    pub plug_gpio: u32,
    pub reset_gpio: u32,
    pub reset_active_low: bool,
}

pub const S21XP_PRODUCTION_CHAINS: [S21XpProductionChain; 3] = [
    S21XpProductionChain {
        zero_based_chain: 0,
        uart_device: "/dev/ttyS3",
        plug_gpio: 439,
        reset_gpio: 454,
        reset_active_low: true,
    },
    S21XpProductionChain {
        zero_based_chain: 1,
        uart_device: "/dev/ttyS2",
        plug_gpio: 440,
        reset_gpio: 455,
        reset_active_low: true,
    },
    S21XpProductionChain {
        zero_based_chain: 2,
        uart_device: "/dev/ttyS1",
        plug_gpio: 441,
        reset_gpio: 456,
        reset_active_low: true,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S21XpHashboardObservation {
    pub sku: &'static str,
    pub asic: &'static str,
    pub chains_per_unit: u8,
    pub chips_per_chain: u16,
    pub domains_per_chain: u8,
    pub chips_per_domain: u8,
    pub vendor_declared_pic: &'static str,
    pub runtime_pic_identity_verified: bool,
}

pub const S21XP_HASHBOARD: S21XpHashboardObservation = S21XpHashboardObservation {
    sku: "A3HB70501",
    asic: "BM1370",
    chains_per_unit: 3,
    chips_per_chain: 91,
    domains_per_chain: 13,
    chips_per_domain: 7,
    vendor_declared_pic: "PIC1704",
    runtime_pic_identity_verified: false,
};

pub const S21XP_PRODUCTION_IDENTITY: (&str, &str, &str, &str) =
    ("Vnish", "1.2.7", "s21xp", "aml/nand");
pub const S21XP_POWER_ENABLE_GPIO: u32 = 437;
pub const S21XP_SOFTWARE_I2C_GPIOS: (u32, u32) = (477, 476);
pub const S21XP_FAN_TACH_GPIOS: [u32; 4] = [447, 448, 449, 450];
pub const S21XP_FAN_PWM_CHANNELS: [u8; 2] = [0, 1];

pub const S21XP_UNRESOLVED: [&str; 7] = [
    "PIC presence, implementation, address, wire protocol, and production selection",
    "PSU family, protocol, retry behavior, limits, acknowledgement, and readback",
    "safe energization, failure unwind, watchdog custody, and electrical rail-off",
    "live carrier revision and exact deployed hashboard identity",
    "checked cooling, sensor attribution, airflow, and thermal cutoff",
    "generation-safe work/nonce ownership and authenticated accepted shares",
    "DCENT install, boot-health, rollback, and stock-recovery acceptance",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S21XpEvidenceAuthority {
    EvidenceOnly,
}

impl S21XpEvidenceAuthority {
    pub const fn permits_path_or_device_open(self) -> bool {
        false
    }

    pub const fn permits_uart_gpio_pic_or_psu(self) -> bool {
        false
    }

    pub const fn permits_power_or_mining(self) -> bool {
        false
    }

    pub const fn permits_install_or_factory(self) -> bool {
        false
    }

    pub const fn permits_runtime_or_live_validation(self) -> bool {
        false
    }
}

pub const S21XP_EVIDENCE_AUTHORITY: S21XpEvidenceAuthority = S21XpEvidenceAuthority::EvidenceOnly;

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
    fn ten_unique_artifacts_and_three_independent_routes_are_exact() {
        assert_eq!(S21XP_AML_ARTIFACTS.len(), 10);
        assert_eq!(S21XP_ROUTE_RECEIPTS.len(), 3);
        for receipt in S21XP_ROUTE_RECEIPTS {
            assert_eq!(
                receipt.devices_in_source_order,
                ["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"]
            );
        }
        assert_eq!(S21XP_ROUTE_RECEIPTS[0].source_index_base, 0);
        assert_eq!(S21XP_ROUTE_RECEIPTS[2].source_index_base, 1);
    }

    #[test]
    fn production_route_and_gpio_observations_do_not_collapse_indexing() {
        assert_eq!(S21XP_PRODUCTION_CHAINS[0].uart_device, "/dev/ttyS3");
        assert_eq!(S21XP_PRODUCTION_CHAINS[2].uart_device, "/dev/ttyS1");
        assert_eq!(S21XP_PRODUCTION_CHAINS[0].plug_gpio, 439);
        assert_eq!(S21XP_PRODUCTION_CHAINS[2].reset_gpio, 456);
        assert!(S21XP_PRODUCTION_CHAINS
            .iter()
            .all(|chain| chain.reset_active_low));
        assert_eq!(S21XP_POWER_ENABLE_GPIO, 437);
        assert_eq!(S21XP_SOFTWARE_I2C_GPIOS, (477, 476));
    }

    #[test]
    fn hashboard_geometry_does_not_prove_pic_or_safe_power_composition() {
        assert_eq!(S21XP_HASHBOARD.asic, "BM1370");
        assert_eq!(S21XP_HASHBOARD.chains_per_unit, 3);
        assert_eq!(S21XP_HASHBOARD.chips_per_chain, 91);
        assert_eq!(S21XP_HASHBOARD.vendor_declared_pic, "PIC1704");
        assert!(!S21XP_HASHBOARD.runtime_pic_identity_verified);
        assert_eq!(S21XP_UNRESOLVED.len(), 7);
    }

    #[test]
    fn every_action_class_remains_closed() {
        assert!(!S21XP_EVIDENCE_AUTHORITY.permits_path_or_device_open());
        assert!(!S21XP_EVIDENCE_AUTHORITY.permits_uart_gpio_pic_or_psu());
        assert!(!S21XP_EVIDENCE_AUTHORITY.permits_power_or_mining());
        assert!(!S21XP_EVIDENCE_AUTHORITY.permits_install_or_factory());
        assert!(!S21XP_EVIDENCE_AUTHORITY.permits_runtime_or_live_validation());
    }

    #[test]
    fn board_and_acceptance_rows_refuse_the_unproved_shared_s21_inheritance() {
        // 2026-09 refresh: the XP row now carries its own traced native route
        // (exact key3 -> PsuAsVoltageController production chain, distinct
        // 91-chip geometry). Nothing is inherited from am3-s21/pro: the pins
        // below hold the row to its XP-specific facts and keep every install
        // posture denied.
        let board = BoardDesc::lookup("am3-s21xp").expect("registered S21 XP target");
        assert_eq!(board.asic_protocol, AsicProtocolIdentity::Bm1370);
        assert_eq!(board.chain_transport, ChainTransportKind::Serial);
        assert_eq!(board.work_engine, WorkEngineKind::SerialWork);
        assert_eq!(board.voltage_controller, VoltageControllerClass::NoPic);
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

        let acceptance = include_str!("../../../scripts/hw-acceptance/skus.conf");
        let line = acceptance
            .lines()
            .find(|line| line.starts_with("S21XP|"))
            .expect("S21XP acceptance row");
        // Acceptance truth: the exact native profile is EXPERIMENTAL with
        // physical qualification pending — implemented, never public.
        assert!(line.contains("|EXPERIMENTAL|"));
        assert!(line.contains("am3-s21xp"));
        assert!(line.contains("3x91 BM1370"));
        assert!(line.contains("ttyS3/2/1"));
        assert!(line.contains("physical qualification pending"));
    }
}
