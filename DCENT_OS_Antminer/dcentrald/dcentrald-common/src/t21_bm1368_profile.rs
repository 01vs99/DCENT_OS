//! Exact, evidence-scoped T21 (am3-t21, BM1368) profile: controller, PSU and
//! geometry pinned ONLY to held T21 bytes (campaign
//! `2026-09-07-antminer-beta-execution`, lane R13 deliverable 2).
//!
//! Evidence discipline: every proven constant below cites a held T21 file by
//! path + SHA-256 (+ the declaring JSON key). Anything the held bytes do not
//! prove is [`T21Unproven`] or an explicit unresolved item — it is NEVER
//! inherited from the S21 sibling, the BM1370 bins, or any other board
//! target, and this profile mints no runtime or electrical authority.
//!
//! Held-byte sources:
//! - FIRST-PARTY stock Bitmain T21 merge release 20240926
//!   (
//!   source `.bmu` SHA-256
//!   `f9dcf13af16399585449c0d17e0ecdc6db93936e85137479d9aa9efdc4909905`).
//!   Its ZYNQ7007-processor member unpacked a minerfs carrying one topology
//!   file per hashboard SKU; all three declare the SAME geometry, controller
//!   and PSU record and differ only in the board name:
//!   `etc/topol_BHB6870{1,3,5}.conf` under
//!   `00_Antminer_T21_zynq7007_BHB6870X/components/minerfs.image.gz.tree/`.
//! - The stock T21 **Amlogic control-board** member
//!   (`02_Antminer_T21_AMLCtrl_BHB6870X/components/unknown_09`, 15,124,992
//!   bytes) is an opaque BMU layer with NO unpacked rootfs, so first-party
//!   stock proves NO AML-carrier PSU/controller contract for T21. AML-carrier
//!   wiring comes only from the held VNish/Awesome 1.2.6 T21 AML rootfs
//!   (`t21_aml_production_route`), whose PSU family it does not identify.
//! - Route evidence (slot0/1/2 = ttyS3/ttyS2/ttyS1, plug 439/440/441, reset
//!   454/455/456 active-low): two independent ARM32 mappers in that held
//!   VNish rootfs (`t21_aml_production_route::T21_AML_ROUTE_MAPPERS`).
//!
//! What the bytes prove vs. what they do not:
//! - PROVEN (stock topol, hashboard-side): BHB68701/03/05 are 3-chain boards
//!   of 12 domains x 9 = 108 BM1368 chips, address interval 2; per-chain
//!   PIC1704 declared at 7-bit 0x20; per-chain AT24C02D EEPROM declared at
//!   0x50; four LM75A sensors at 0x48..0x4b; per-chip 80 big cores x 16
//!   small cores with 1276 declared small cores; four fans (2 in / 2 out).
//! - DECLARED on the ZYNQ7007 control-board variant only: PSU family
//!   APW11A, 7-bit address 0x10, power GPIO 907. The AML-carrier PSU stays
//!   Unproven (no stock AML record; VNish identifies no PSU family).
//! - UNPROVEN everywhere: GPIO437 electrical polarity (the stock init
//!   script's startup write is the same script class the S21 control-flow
//!   proof CORRECTED, so a startup value proves nothing); PSU wire protocol,
//!   limits, safe-off value and ordering; PIC command effects; cold-init
//!   sequencing; any measured rail. T21 therefore has NO callable runtime
//!   and stays management-only (`am3-t21` catalog row, enum 0, NOT-
//!   IMPLEMENTED); enumeration authority remains 0 until a live unit proves
//!   population.
//!
//! Note on core counts: the T21 stock topol declares
//! `asic_small_core_num: 1276` where the S21 factory JIG counts 1280 cores
//! (80 x 16) for the BM1368 (`bm1368::cores_per_chip`, live-share-proven).
//! These are different held artifacts making different declarations; the
//! driver keeps 1280, and this profile records 1276 as the T21 stock
//! declaration without promoting either to the other's artifact.

use crate::t21_aml_production_route::T21_AML_AUTHORITY;

/// BM1368 chip ID declared by every stock T21 topol (`asic_id "BM1368"`,
/// `asic_addr "0x1368"`); same silicon family as the S21 driver constant.
pub const T21_CHIP_ID: u16 = 0x1368;

/// T21 chains per unit (`chain_num`).
pub const T21_CHAINS_PER_UNIT: u8 = 3;

/// One held stock T21 topology file, byte-pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21StockTopolPin {
    pub machine: &'static str,
    pub rootfs_path: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

/// The three held stock T21 topologies (identical content except the board
/// name; byte-verified 2026-09-11 from the unpacked merge tree).
pub const T21_STOCK_TOPOL_PINS: [T21StockTopolPin; 3] = [
    T21StockTopolPin {
        machine: "BHB68701",
        rootfs_path: "00_Antminer_T21_zynq7007_BHB6870X/components/minerfs.image.gz.tree/etc/topol_BHB68701.conf",
        size: 4_168,
        sha256: "4d2b37890f4cad2e15fdae557e7cdfb864f7ee7d8e69526902f4f71088286a3d",
    },
    T21StockTopolPin {
        machine: "BHB68703",
        rootfs_path: "00_Antminer_T21_zynq7007_BHB6870X/components/minerfs.image.gz.tree/etc/topol_BHB68703.conf",
        size: 4_169,
        sha256: "056a9bd58ac9974c3551b4c7e83f6f3e414237ab6774cfe7d882564480dde12f",
    },
    T21StockTopolPin {
        machine: "BHB68705",
        rootfs_path: "00_Antminer_T21_zynq7007_BHB6870X/components/minerfs.image.gz.tree/etc/topol_BHB68705.conf",
        size: 4_169,
        sha256: "608a15db9ccea4f75c83b3e47665a7d42aa17d0c2ec16890b0d8db127a2165a3",
    },
];

/// Exact evidence-scoped T21 board profile. Hashboard-side facts are
/// verified stock declarations; carrier-side facts are scoped to the record
/// that proves them; nothing is inherited from another board target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21Bm1368Profile {
    /// Campaign board target string.
    pub board_target: &'static str,
    /// Exact factory hashboard names that may select this profile.
    pub board_names: &'static [&'static str],
    /// `chain_num`
    pub chains: u8,
    /// `chain_domain_num` (also `chain_row`)
    pub domains_per_board: u8,
    /// `domain_asic_num` (also `chain_column`)
    pub chips_per_domain: u8,
    /// `chain_asic_num`: 12 x 9 = 108. An off-by-one observation refuses.
    pub chips_per_chain: u16,
    /// `asic_addr_interval`
    pub address_interval: u8,
    /// `asic_core_num`
    pub big_cores_per_chip: u16,
    /// `core_small_core_num`
    pub small_cores_per_big_core: u16,
    /// `asic_small_core_num` — the stock T21 declaration (1276, distinct
    /// from the S21 jig's 1280; see module doc; no driver change).
    pub declared_small_cores_total: u16,
    /// `fan` array length: 4 (ids 0/1 right-in, 2/3 left-out).
    pub fans: u8,
}

/// The exact T21 profile selected by BHB68701/03/05.
pub const T21: T21Bm1368Profile = T21Bm1368Profile {
    board_target: "am3-t21",
    board_names: &["BHB68701", "BHB68703", "BHB68705"],
    chains: T21_CHAINS_PER_UNIT,
    domains_per_board: 12,
    chips_per_domain: 9,
    chips_per_chain: 108,
    address_interval: 2,
    big_cores_per_chip: 80,
    small_cores_per_big_core: 16,
    declared_small_cores_total: 1276,
    fans: 4,
};

impl T21Bm1368Profile {
    /// Domain-times-chip consistency for the pinned geometry (12 x 9 = 108).
    pub const fn domains_times_chips(&self) -> u16 {
        self.domains_per_board as u16 * self.chips_per_domain as u16
    }

    /// Exact full-unit ASIC count at the geometry: 3 x 108 = 324.
    pub const fn chips_per_unit(&self) -> u16 {
        self.chips_per_chain * (self.chains as u16)
    }

    /// Exact profile for a decoded factory board name, else `None`.
    /// The S21 BHB686xx names, the BM1370 A3HB names and every other family
    /// refuse here; identity is name-scoped, never count-scoped.
    pub fn for_board_name(name: &str) -> Option<Self> {
        if T21.board_names.contains(&name) {
            Some(T21)
        } else {
            None
        }
    }
}

/// Per-chain hashboard controller, as DECLARED by the stock topol
/// (`chain.pic`): PIC1704 at 7-bit address 32 (0x20) with four LM75A sensors
/// at 72..75 (0x48..0x4b) hanging off the same per-chain PIC record.
///
/// This is a factory declaration, NOT a verified physical identity or a
/// command protocol: no T21 PIC command effect, firmware state or production
/// selection is proven, so no PIC transaction may be derived from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21DeclaredChainController {
    pub controller: &'static str,
    pub i2c_addr_7bit: u8,
    pub sensor_addrs_7bit: [u8; 4],
}

/// The stock-declared per-chain controller record (identical in all three
/// topol files).
pub const T21_DECLARED_CHAIN_CONTROLLER: T21DeclaredChainController = T21DeclaredChainController {
    controller: "PIC1704",
    i2c_addr_7bit: 0x20,
    sensor_addrs_7bit: [72, 73, 74, 75],
};

/// Per-chain EEPROM as DECLARED by the stock topol (`chain.eeprom`):
/// AT24C02D at 7-bit 80 (0x50). The workspace EEPROM write-protect rule
/// (0x50..=0x57 denylist at the HAL) applies unchanged; a declaration is
/// never write authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21DeclaredChainEeprom {
    pub eeprom: &'static str,
    pub i2c_addr_7bit: u8,
}

/// The stock-declared per-chain EEPROM record.
pub const T21_DECLARED_CHAIN_EEPROM: T21DeclaredChainEeprom = T21DeclaredChainEeprom {
    eeprom: "AT24C02D",
    i2c_addr_7bit: 0x50,
};

/// Carrier scope of a T21 PSU record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T21PsuCarrierScope {
    /// Declared by the ZYNQ7007-processor control-board variant of the
    /// stock T21 merge firmware (`topol*.conf` `power` object).
    ZynqVariantTopolDeclaration,
    /// The stock T21 AML control-board member is an opaque BMU layer and
    /// the held VNish T21 AML rootfs identifies no PSU family: nothing is
    /// proven about PSU wiring or protocol on the AML carrier.
    AmlCarrierUnproven,
}

/// PSU record exactly as the held bytes state it. This is a DECLARATION
/// with a carrier scope — not a wire protocol, not a voltage law, not
/// polarity, and never a command authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21PsuDeclaration {
    /// `power.type`
    pub family: &'static str,
    /// `power.i2c_addr` (decimal 16 = 7-bit 0x10)
    pub i2c_addr_7bit: u8,
    /// `power.gpio` (907 on the Zynq-variant record)
    pub power_gpio: u16,
    /// `power.version` array length (11 accepted firmware versions [66, 67,
    /// 106, 113, 114, 115, 117, 118, 119, 120, 193]).
    pub declared_version_count: usize,
    pub scope: T21PsuCarrierScope,
}

/// The stock-declared T21 PSU record, scoped to the carrier that declares
/// it. The AML carrier (the only T21 carrier DCENT images target) stays
/// [`T21PsuCarrierScope::AmlCarrierUnproven`].
pub const T21_PSU_ZYNQ_VARIANT_DECLARATION: T21PsuDeclaration = T21PsuDeclaration {
    family: "APW11A",
    i2c_addr_7bit: 0x10,
    power_gpio: 907,
    declared_version_count: 11,
    scope: T21PsuCarrierScope::ZynqVariantTopolDeclaration,
};

/// T21 GPIO437 (and every other electrical) polarity evidence state.
/// T21 has NO production control-flow proof of enable/disable levels: the
/// stock init script's startup GPIO write is the same script class the S21
/// production proof CORRECTED, so a startup value proves nothing and no
/// sibling's mapping is ever inherited. Everything electrical on T21 that
/// the held bytes do not prove lands in [`T21Unproven::Unproven`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T21Unproven {
    Unproven,
}

/// The single polarity state T21 evidence supports today.
pub const T21_POWER_POLARITY: T21Unproven = T21Unproven::Unproven;

/// The only runtime authority the T21 evidence supports: read-only evidence
/// (`t21_aml_production_route::T21_AML_AUTHORITY`). Every action class it
/// names stays closed; this profile adds no authority of its own.
pub const T21_RUNTIME_AUTHORITY: crate::t21_aml_production_route::T21AmlProductionRouteAuthority =
    T21_AML_AUTHORITY;

// ---------------------------------------------------------------------------
// Population admission (planning only): 108 exact per populated chain.
// ---------------------------------------------------------------------------

/// One chain's fresh full GetAddress observation (planning input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21ChainPopulation {
    /// Physical chain slot 0..3 (AM3 UART slot, ttyS3=0 / ttyS2=1 / ttyS1=2).
    pub chain: u8,
    /// Freshly observed unassigned-zero address-window population.
    pub observed_chips: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T21PopulationAdmissionError {
    EmptyUnit,
    ChainOutOfRange,
    DuplicateChain,
    PopulationMismatch {
        chain: u8,
        observed: u16,
        expected: u16,
    },
}

/// An admitted (planned) T21 unit. Admission is a PLANNING act only: it
/// grants no UART open, no power, no PIC/PSU I/O and no mining, because the
/// T21 runtime authority stays evidence-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedT21Unit {
    pub profile: T21Bm1368Profile,
    pub populated_chains: [u8; 3],
    pub populated_count: usize,
}

/// Admit a fresh unit population against the exact T21 geometry. Physical
/// subsets are admissible — identity never requires all three slots — but
/// EVERY populated chain must report the exact 108-chip count.
pub fn admit_t21_unit_population(
    profile: T21Bm1368Profile,
    populations: &[T21ChainPopulation],
) -> Result<AdmittedT21Unit, T21PopulationAdmissionError> {
    if populations.is_empty() {
        return Err(T21PopulationAdmissionError::EmptyUnit);
    }
    let mut populated_chains = [0u8; 3];
    let mut populated_count = 0usize;
    for population in populations {
        if population.chain >= T21_CHAINS_PER_UNIT {
            return Err(T21PopulationAdmissionError::ChainOutOfRange);
        }
        if populated_chains[..populated_count]
            .iter()
            .any(|prior| *prior == population.chain)
        {
            return Err(T21PopulationAdmissionError::DuplicateChain);
        }
        if population.observed_chips != profile.chips_per_chain {
            return Err(T21PopulationAdmissionError::PopulationMismatch {
                chain: population.chain,
                observed: population.observed_chips,
                expected: profile.chips_per_chain,
            });
        }
        populated_chains[populated_count] = population.chain;
        populated_count += 1;
    }
    Ok(AdmittedT21Unit {
        profile,
        populated_chains,
        populated_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stock_topol_pins_are_exact_and_geometry_is_identical_across_skus() {
        assert_eq!(T21_STOCK_TOPOL_PINS.len(), 3);
        assert_eq!(
            T21_STOCK_TOPOL_PINS[0].sha256,
            "4d2b37890f4cad2e15fdae557e7cdfb864f7ee7d8e69526902f4f71088286a3d"
        );
        assert_eq!(
            T21_STOCK_TOPOL_PINS[1].sha256,
            "056a9bd58ac9974c3551b4c7e83f6f3e414237ab6774cfe7d882564480dde12f"
        );
        assert_eq!(
            T21_STOCK_TOPOL_PINS[2].sha256,
            "608a15db9ccea4f75c83b3e47665a7d42aa17d0c2ec16890b0d8db127a2165a3"
        );
        for pin in &T21_STOCK_TOPOL_PINS {
            assert!(pin
                .rootfs_path
                .ends_with(&format!("topol_{}.conf", pin.machine)));
        }
        // Profile facts every topol declares identically.
        assert_eq!(T21.board_target, "am3-t21");
        assert_eq!(T21.board_names, &["BHB68701", "BHB68703", "BHB68705"]);
        assert_eq!(T21.chains, 3);
        assert_eq!(T21.domains_per_board, 12);
        assert_eq!(T21.chips_per_domain, 9);
        assert_eq!(T21.domains_times_chips(), 108);
        assert_eq!(T21.chips_per_chain, 108);
        assert_eq!(T21.chips_per_unit(), 324);
        assert_eq!(T21.address_interval, 2);
        assert_eq!(T21.big_cores_per_chip, 80);
        assert_eq!(T21.small_cores_per_big_core, 16);
        assert_eq!(T21.declared_small_cores_total, 1276);
        assert_eq!(T21.fans, 4);
        assert_eq!(T21_CHIP_ID, 0x1368);
        assert_eq!(T21_CHAINS_PER_UNIT, 3);
    }

    #[test]
    fn controller_psu_and_eeprom_declarations_cite_the_stock_records() {
        assert_eq!(T21_DECLARED_CHAIN_CONTROLLER.controller, "PIC1704");
        assert_eq!(T21_DECLARED_CHAIN_CONTROLLER.i2c_addr_7bit, 0x20);
        assert_eq!(
            T21_DECLARED_CHAIN_CONTROLLER.sensor_addrs_7bit,
            [72, 73, 74, 75]
        );
        assert_eq!(T21_DECLARED_CHAIN_EEPROM.eeprom, "AT24C02D");
        assert_eq!(T21_DECLARED_CHAIN_EEPROM.i2c_addr_7bit, 0x50);
        // PSU record is scoped to the carrier that declares it.
        assert_eq!(T21_PSU_ZYNQ_VARIANT_DECLARATION.family, "APW11A");
        assert_eq!(T21_PSU_ZYNQ_VARIANT_DECLARATION.i2c_addr_7bit, 0x10);
        assert_eq!(T21_PSU_ZYNQ_VARIANT_DECLARATION.power_gpio, 907);
        assert_eq!(T21_PSU_ZYNQ_VARIANT_DECLARATION.declared_version_count, 11);
        assert_eq!(
            T21_PSU_ZYNQ_VARIANT_DECLARATION.scope,
            T21PsuCarrierScope::ZynqVariantTopolDeclaration
        );
        // The AML carrier — the only T21 carrier DCENT images target — has
        // NO proven PSU record at all.
        assert_eq!(
            T21PsuCarrierScope::AmlCarrierUnproven,
            T21PsuCarrierScope::AmlCarrierUnproven
        );
    }

    #[test]
    fn polarity_stays_unproven_and_never_inherits_a_sibling_mapping() {
        // The ONLY polarity state T21 evidence supports.
        assert_eq!(T21_POWER_POLARITY, T21Unproven::Unproven);
        // There is no enable-level, safe-off-level or voltage-law accessor
        // on this profile at all: absence is the fail-closed contract.
    }

    #[test]
    fn name_scoping_refuses_every_sibling_board() {
        assert_eq!(T21Bm1368Profile::for_board_name("BHB68701"), Some(T21));
        assert_eq!(T21Bm1368Profile::for_board_name("BHB68703"), Some(T21));
        assert_eq!(T21Bm1368Profile::for_board_name("BHB68705"), Some(T21));
        // Identity is name-scoped: the S21 boards carry the same 108 count
        // and still refuse, as does every other family name.
        for name in [
            "BHB68603",
            "BHB68606", // exact S21
            "A3HB70501",
            "A3HB70601",
            "A3HB70701", // BM1370 bins
            "BHB56903",  // S19k
            "BHB68702",
            "BHB68709", // adjacent non-factory names
        ] {
            assert_eq!(
                T21Bm1368Profile::for_board_name(name),
                None,
                "{name} must not select the T21 profile"
            );
        }
    }

    #[test]
    fn population_admission_is_exact_and_refuses_wrong_duplicate_empty() {
        let full: Vec<T21ChainPopulation> = (0..3)
            .map(|chain| T21ChainPopulation {
                chain,
                observed_chips: 108,
            })
            .collect();
        admit_t21_unit_population(T21, &full).expect("exact full unit");

        // Off-by-one refuses on every chain slot, both directions.
        for drifted in [107u16, 109] {
            for chain in 0..3u8 {
                assert_eq!(
                    admit_t21_unit_population(
                        T21,
                        &[T21ChainPopulation {
                            chain,
                            observed_chips: drifted,
                        }]
                    ),
                    Err(T21PopulationAdmissionError::PopulationMismatch {
                        chain,
                        observed: drifted,
                        expected: 108,
                    })
                );
            }
        }
        // Empty, duplicate and out-of-range refuse.
        assert_eq!(
            admit_t21_unit_population(T21, &[]),
            Err(T21PopulationAdmissionError::EmptyUnit)
        );
        let dup = [
            T21ChainPopulation {
                chain: 0,
                observed_chips: 108,
            },
            T21ChainPopulation {
                chain: 0,
                observed_chips: 108,
            },
        ];
        assert_eq!(
            admit_t21_unit_population(T21, &dup),
            Err(T21PopulationAdmissionError::DuplicateChain)
        );
        assert_eq!(
            admit_t21_unit_population(
                T21,
                &[T21ChainPopulation {
                    chain: 3,
                    observed_chips: 108,
                }]
            ),
            Err(T21PopulationAdmissionError::ChainOutOfRange)
        );
    }

    #[test]
    fn runtime_authority_stays_evidence_only() {
        // The profile adds no authority: the composed T21 authority remains
        // the held VNish evidence-only grant, which closes every action.
        assert!(!T21_RUNTIME_AUTHORITY.permits_path_or_device_open());
        assert!(!T21_RUNTIME_AUTHORITY.permits_uart_or_gpio_io());
        assert!(!T21_RUNTIME_AUTHORITY.permits_pic_or_psu_io());
        assert!(!T21_RUNTIME_AUTHORITY.permits_power_or_mining());
        assert!(!T21_RUNTIME_AUTHORITY.permits_install_or_recovery());
        // A planned unit is still not a runtime: admission grants planning.
        let planned = admit_t21_unit_population(
            T21,
            &[T21ChainPopulation {
                chain: 1,
                observed_chips: 108,
            }],
        )
        .expect("planning admission");
        assert_eq!(planned.populated_count, 1);
        assert!(!T21_RUNTIME_AUTHORITY.permits_power_or_mining());
    }
}
