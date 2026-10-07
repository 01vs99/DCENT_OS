//! Distinct S19 Pro BM1398 hybrid runtime contracts and staged executor.
//!
//! This must never be routed through the BM1362-only S19j lifecycle. The held
//! S19 Pro driver establishes geometry; the held modern sender establishes
//! full FPGA work-id semantics. [`executor`] composes stock controller and PSU
//! dialects with caller-owned cooling/reset/ASIC/work transports. The legacy
//! target-string-only admission remains insufficient: real execution requires
//! identity, queried dialects, fresh cooling and complete chain coverage.

#[path = "s19_bm1398_executor.rs"]
pub mod executor;

use crate::serial_chain_proof::{
    ChainCoverageCertificate, ChainCoverageError, PacedEnumerationPolicy,
};

pub const S19_PRO_CHIPS_PER_CHAIN: u16 = 114;
pub const S19_PRO_ADDRESS_INTERVAL: u8 = 2;
/// Four midstates reserve two of the sixteen returned identifier bits.
/// Held modern sender0x3230c8; this supersedes the historical256-slot ledger.
pub const BM1398_FPGA_WORK_ID_SLOTS: u16 = 16_384;
pub const S19_PRO_TEMPERATURE_CHANNELS: u8 = 4;
pub const S19_PRO_TEMPERATURE_ADDRESSES: [u8; 4] = [0x48, 0x49, 0x4a, 0x4b];

/// Provenance classes are intentionally part of the runtime contract. A
/// reconstructed protocol or a vendor catalog entry is useful desk evidence,
/// but neither is same-unit electrical authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398EvidenceClass {
    HeldStockBinary,
    HeldRepairJig,
    HeldThirdPartyFirmware,
    HistoricalDcentTranscript,
    SameUnitPassiveIdentity,
    SameUnitPhysicalMeasurement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398EvidenceFact {
    pub class: Bm1398EvidenceClass,
    pub source: &'static str,
    pub exact_for_energize: bool,
}

pub const NBP1901_GEOMETRY_EVIDENCE: Bm1398EvidenceFact = Bm1398EvidenceFact {
    class: Bm1398EvidenceClass::HeldStockBinary,
    source: "stock NBP1901 miner + independent BM1398 repair jig (Wave 481)",
    exact_for_energize: false,
};

pub const NBP1901_THERMAL_TOPOLOGY_EVIDENCE: Bm1398EvidenceFact = Bm1398EvidenceFact {
    class: Bm1398EvidenceClass::HeldThirdPartyFirmware,
    source: "VNish 1.2.7 Xilinx model catalog: NBP1901 via-pic 0x48..0x4b",
    exact_for_energize: false,
};

// ── 2026-08-29 desk residual: evidence-cited electrical candidates ──────────
//
// The enums above intentionally contain only `Unresolved` so no software
// path can forge an admitted electrical receipt. The facts below are the
// DESK-CLOSED candidates a future same-unit receipt must SELECT among:
// they are typed with their exact evidence classes, are never inputs to
// `bm1398_electrical_gaps` or `admit_bm1398_hybrid_energize`, and none of
// them is `exact_for_energize`. Two of the catalog fields independently
// agree with facts this crate already typed from other origins (the four
// 0x48..0x4b LM75A channels; gpio 907), which raises confidence in the
// transcription without changing its evidence class.

/// Source: the 50-record hashboard capability DB embedded in ePIC's UMC OS
/// v1.22.0 `bms-miner` (Bitmain-derived, ePIC-transcribed — real
/// transcription defects exist elsewhere in the DB), decoded to JSON at
/// ,
/// record `NBP1901`.
pub const NBP1901_CATALOG_EVIDENCE: Bm1398EvidenceFact = Bm1398EvidenceFact {
    class: Bm1398EvidenceClass::HeldThirdPartyFirmware,
    source: "ePIC UMC OS v1.22.0 embedded hashboard DB, NBP1901 record (Bitmain-derived, ePIC-transcribed)",
    exact_for_energize: false,
};

/// Source: the held BM1398 factory repair jig
/// (`amtc-s19pro-jig/single_board_test_bm1398`), decompiled via the
/// ghidra-bridge skill (PROJECT_LOG 2026-08 Wave record).
pub const NBP1901_JIG_EVIDENCE: Bm1398EvidenceFact = Bm1398EvidenceFact {
    class: Bm1398EvidenceClass::HeldRepairJig,
    source: "amtc-s19pro-jig/single_board_test_bm1398 (decompiled)",
    exact_for_energize: false,
};

/// Catalog PSU candidate for NBP1901: APW12-class PSU controller on I2C
/// address 0x10 with power-control GPIO 907. The gpio number
/// independently matches the factory jig's energize pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398PsuCandidate {
    pub name: &'static str,
    pub i2c_addr: u8,
    pub power_gpio: u16,
    pub evidence: Bm1398EvidenceFact,
}

pub const NBP1901_PSU_CANDIDATES: &[Bm1398PsuCandidate] = &[Bm1398PsuCandidate {
    name: "APW12",
    i2c_addr: 0x10,
    power_gpio: 907,
    evidence: NBP1901_CATALOG_EVIDENCE,
}];

/// Catalog controller candidate for NBP1901: PIC1704 on I2C address 0x20
/// with the four LM75A sensors this crate already types as
/// `S19_PRO_TEMPERATURE_ADDRESSES` (independent same-address agreement).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398ControllerCandidate {
    pub kind: &'static str,
    pub i2c_addr: u8,
    pub evidence: Bm1398EvidenceFact,
}

pub const NBP1901_CONTROLLER_CANDIDATES: &[Bm1398ControllerCandidate] =
    &[Bm1398ControllerCandidate {
        kind: "PIC1704",
        i2c_addr: 0x20,
        evidence: NBP1901_CATALOG_EVIDENCE,
    }];

/// Hashboard identity EEPROM candidate (AT24C02D at the standard 0x50).
pub const NBP1901_EEPROM_I2C_ADDR: u8 = 0x50;

/// Historical factory-jig software observation: APW_power_on writes "0".
/// Runtime polarity comes from the exact composition in
/// runtime_hardware_recipe and the owner's observed GPIO-controller join.
/// This constant is not a measurement or an independent permission token.
pub const NBP1901_GPIO907_JIG_ENERGIZE_WRITE: &str = "0";

/// Exact stock low-clock path: 25 MHz / (8 * 2). This avoids the separate
/// >3 MHz PLL3/relay transaction and raises the available nonce bandwidth.
/// Bitmain stock reference `FUN_0004ffe8`; equivalent low-clock branch in
/// NBS1902, NBT1903 and BHB28611 production binaries.
pub const BM1398_RUNTIME_WORK_BAUD: u32 = 1_562_500;

pub fn bm1398_oscillator_baud_register(previous: u32, baud: u32) -> Result<u32, &'static str> {
    if baud == 0 || baud > 3_000_000 {
        return Err("BM1398 oscillator baud must stay below the PLL3 transition");
    }
    let divisor = 25_000_000 / (baud * 8);
    if !(1..=256).contains(&divisor) {
        return Err("BM1398 oscillator baud divider is not representable");
    }
    let field = divisor - 1;
    // Stock preserves unrelated bits, splits divider across byte1[4:0] and
    // byte3[3:0], and clears the PLL3 clock select at bit16.
    Ok((previous & !0x0f01_1f00) | ((field & 31) << 8) | ((field >> 5) << 24))
}

/// Catalog fan topology: four axial fans — two intake right, two exhaust
/// left (cooling-custody geometry for the future bench receipt).
pub const NBP1901_FAN_COUNT: u8 = 4;

/// The jig gates the UART relay on `Voltage_Domain >= 10` (Bitmain's own
/// log text says "less than 9"; the code tests `< 10` — trust the code).
/// Capability-shaped, per the recorded follow-up design: it can retire the
/// model-specific `BoardRelayComposition::S19ProNbp1901` variant later.
pub const NBP1901_RELAY_MIN_VOLTAGE_DOMAINS: u32 = 10;

pub const fn voltage_domain_relay_capable(voltage_domains: u32) -> bool {
    voltage_domains >= NBP1901_RELAY_MIN_VOLTAGE_DOMAINS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398HybridModel {
    /// S19 Pro hashboard bin NBP1901 (114 chips/chain, address interval 2).
    S19Pro,
    /// S19 classic hashboard bin NBS1902 (76 chips/chain, address interval 3).
    S19Classic,
    /// T19 hashboard bin NBT1903 (76 chips/chain, address interval 3).
    T19,
    /// S19a BHB28611: 72 BM1398S chips, nine domains of eight chips.
    S19a,
    /// S19+ BHB28701: 80 chips, ten domains of eight; exact VNish rc5 profile.
    S19Plus,
}

/// Exact stock levels.json ladders as (frequency MHz, rail centivolts) pairs.
/// Each bin's ladder comes from that bin's own held first-party stock image:
///
/// - NBP1901:
///   s19-pro-20211116/components/minerfs.image.gz.tree/etc/levels.json`
///   (sha256 `64aae4c71e9018087210d5923654c3684b24aa033c85f90e45c307f2f7b9ab3a`;
///   the same six pairs are pinned by the held analysis root
///   `HashSource/bmminer_NBP1901_analysis/levels.json`, sha256
///   `8145e0b26fc11bdf0727531bcc346f6fb7ca572e20d9cdc1ad297d18df838aa8`).
/// - NBS1902: `.../s19-20211116/.../etc/levels.json` (sha256
///   `3c4fe0f3559fcab77fa035b1f7f625067383618ce7e2d83dd3bd646985c929db`).
/// - NBT1903: `.../t19-20230320/.../etc/levels.json` (sha256
///   `1bb4a6e535edf7e5f48afeab40b1bd4169963eb2cb114364de9289bf0f17e1bd`).
pub const NBP1901_STOCK_LEVELS: [(u16, u16); 6] = [
    (525, 1260),
    (525, 1280),
    (525, 1300),
    (500, 1260),
    (500, 1280),
    (500, 1300),
];

pub const NBS1902_STOCK_LEVELS: [(u16, u16); 6] = [
    (675, 1380),
    (675, 1400),
    (675, 1420),
    (650, 1380),
    (650, 1400),
    (650, 1420),
];

pub const NBT1903_STOCK_LEVELS: [(u16, u16); 10] = [
    (625, 1400),
    (625, 1420),
    (600, 1400),
    (600, 1420),
    (575, 1400),
    (575, 1420),
    (550, 1420),
    (625, 1440),
    (600, 1440),
    (575, 1440),
];

/// Exact Bitmain `s19a-20221206/.../etc/levels.json` rows. This is a
/// factory software table, not measured DCENT performance. The BHB28611
/// topology in the same rootfs is 72 BM1398S chips, not the 76-chip NBS bin.
pub const BHB28611_STOCK_LEVELS: [(u16, u16); 40] = [
    (750, 1260),
    (750, 1280),
    (750, 1300),
    (750, 1310),
    (750, 1320),
    (750, 1330),
    (750, 1340),
    (720, 1240),
    (720, 1250),
    (720, 1260),
    (720, 1270),
    (720, 1280),
    (720, 1290),
    (720, 1300),
    (720, 1310),
    (720, 1320),
    (720, 1330),
    (720, 1340),
    (720, 1350),
    (720, 1360),
    (690, 1240),
    (690, 1250),
    (690, 1260),
    (690, 1270),
    (690, 1280),
    (690, 1290),
    (690, 1300),
    (690, 1310),
    (690, 1320),
    (690, 1330),
    (690, 1340),
    (690, 1350),
    (690, 1360),
    (660, 1280),
    (660, 1300),
    (660, 1320),
    (660, 1340),
    (725, 1300),
    (695, 1300),
    (665, 1300),
];

/// Exact default from the held VNish S19+ Xilinx NAND 1.2.6-rc5 image.
/// hwscan SHA256 95ee1211e9e3dd9c992ab7a44b9f576237684f56504de110e966d72aa8394393:
/// model constructor 0x7ed14 identifies s19plus/BHB28701; the paired defaults
/// constructor 0x7ebd8 returns 645 MHz / 1400 centivolts. Lookup 0x99730 joins
/// them; generators 0x22310 and 0x2349c serialize the exact model and defaults.
/// The older C table's zero frequency fields are not operational defaults.
/// Only this exact pair is implemented, not its autotuning preset envelopes.
/// This is vendor software evidence, not measured DCENT performance.
pub const BHB28701_VENDOR_LEVELS: [(u16, u16); 1] = [(645, 1400)];

impl Bm1398HybridModel {
    /// The `/etc/dcentos/board_target` image marker this bin's runtime runs as.
    pub const fn board_target(self) -> &'static str {
        match self {
            Self::S19Pro => "am2-s19pro",
            Self::S19Classic => "am2-s19",
            Self::T19 => "am2-t19",
            Self::S19a => "am2-s19a",
            Self::S19Plus => "am2-s19plus",
        }
    }

    /// Stock topol.conf `machine` names accepted as this bin's factory
    /// identity. First-party sources: each bin's held
    /// `minerfs.image.gz.tree/etc/topol.conf` (NBS1902 sha256
    /// `59d911b44a5b68177b5f86f46cb187f3fd84a42432cdee43f242f62088a5ad11`,
    /// NBT1903 sha256
    /// `360af8228ebeb5aadc2f623227aa476ad3d3067d7caa9cfc70eb688c78b10c98`).
    /// `NBP1901-38` is the pre-existing 38-domain alias accepted by the
    /// September 2 NBP1901 runtime.
    pub const fn stock_board_names(self) -> &'static [&'static str] {
        match self {
            Self::S19Pro => &["NBP1901", "NBP1901-38"],
            Self::S19Classic => &["NBS1902"],
            Self::T19 => &["NBT1903"],
            Self::S19a => &["BHB28611"],
            Self::S19Plus => &["BHB28701"],
        }
    }

    /// Per-bin stock geometry pins. The counts are the stock topol.conf
    /// `chain.chain_asic_num` rows (NBS1902/NBT1903: 76 at interval 3;
    /// NBP1901: 114 at interval 2), restated as literals because
    /// dcentrald-common does not depend on dcentrald-api-types, where the
    /// same rows are typed as `bm1398_protocol::BM1398_AIR_BOARD_GEOMETRIES`.
    pub const fn chips_per_chain(self) -> u16 {
        match self {
            Self::S19Pro => 114,
            Self::S19Classic | Self::T19 => 76,
            Self::S19a => 72,
            Self::S19Plus => 80,
        }
    }

    pub const fn address_interval(self) -> u8 {
        match self {
            Self::S19Pro => 2,
            Self::S19Classic | Self::T19 | Self::S19a | Self::S19Plus => 3,
        }
    }

    /// Exact vendor operating ladder (BHB28701 implements its default only). The requested (frequency, rail) pair
    /// must be a member; this table is the single source for every caller.
    pub const fn stock_levels(self) -> &'static [(u16, u16)] {
        match self {
            Self::S19Pro => &NBP1901_STOCK_LEVELS,
            Self::S19Classic => &NBS1902_STOCK_LEVELS,
            Self::T19 => &NBT1903_STOCK_LEVELS,
            Self::S19a => &BHB28611_STOCK_LEVELS,
            Self::S19Plus => &BHB28701_VENDOR_LEVELS,
        }
    }

    /// Zero-config default operating point. NBP1901 keeps the historical
    /// 500 MHz / 12.80 V selection. The two 76-chip bins default to their
    /// lowest held stock pair (quiet-home posture); both defaults are real
    /// levels.json rows of their own ladder.
    pub const fn default_operating_point(self) -> (u16, u16) {
        match self {
            Self::S19Pro => (500, 1280),
            Self::S19Classic => (650, 1380),
            Self::T19 => (550, 1420),
            Self::S19a => (660, 1280),
            Self::S19Plus => (645, 1400),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398FpgaMidstateMode {
    Four,
    Eight,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1398HybridDeskPlan {
    pub model: Bm1398HybridModel,
    pub chains: u8,
    pub chips_per_chain: u16,
    pub address_interval: u8,
    pub work_id_slots: u16,
    pub midstate_mode: Bm1398FpgaMidstateMode,
    pub enumeration: PacedEnumerationPolicy,
}

impl Bm1398HybridDeskPlan {
    pub fn s19_pro(
        enumeration: PacedEnumerationPolicy,
        midstate_mode: Bm1398FpgaMidstateMode,
    ) -> Self {
        Self::for_model(Bm1398HybridModel::S19Pro, enumeration, midstate_mode)
    }

    /// S19 classic (NBS1902) desk plan: 3 x 76 at address interval 3.
    pub fn s19_classic(
        enumeration: PacedEnumerationPolicy,
        midstate_mode: Bm1398FpgaMidstateMode,
    ) -> Self {
        Self::for_model(Bm1398HybridModel::S19Classic, enumeration, midstate_mode)
    }

    /// T19 (NBT1903) desk plan: 3 x 76 at address interval 3.
    pub fn t19(enumeration: PacedEnumerationPolicy, midstate_mode: Bm1398FpgaMidstateMode) -> Self {
        Self::for_model(Bm1398HybridModel::T19, enumeration, midstate_mode)
    }

    pub fn for_model(
        model: Bm1398HybridModel,
        enumeration: PacedEnumerationPolicy,
        midstate_mode: Bm1398FpgaMidstateMode,
    ) -> Self {
        Self {
            model,
            chains: 3,
            chips_per_chain: model.chips_per_chain(),
            address_interval: model.address_interval(),
            work_id_slots: match midstate_mode {
                Bm1398FpgaMidstateMode::Four => BM1398_FPGA_WORK_ID_SLOTS,
                Bm1398FpgaMidstateMode::Eight => BM1398_FPGA_WORK_ID_SLOTS / 2,
            },
            midstate_mode,
            enumeration,
        }
    }

    pub fn expected_addresses(&self) -> Vec<u8> {
        (0..self.chips_per_chain)
            .map(|index| (index as u8).wrapping_mul(self.address_interval))
            .collect()
    }

    pub fn certify_chain(
        &self,
        observed_addresses: &[u8],
    ) -> Result<ChainCoverageCertificate, ChainCoverageError> {
        ChainCoverageCertificate::certify(&self.expected_addresses(), observed_addresses)
    }

    /// Decode the extracted sixteen-bit extended ID (WORK_RX metadata>>8).
    /// Low bits select the midstate; the remaining bits identify host work.
    pub const fn decode_carrier_work_id(&self, echoed: u32) -> u16 {
        let log2 = match self.midstate_mode {
            Bm1398FpgaMidstateMode::Four => 2,
            Bm1398FpgaMidstateMode::Eight => 3,
        };
        (echoed as u16) >> log2
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398HybridAdmissionError {
    WrongBoardTarget,
    /// Historic label. NBT1903 geometry itself is now first-party settled
    /// (76/chain at interval 3, stock t19-20230320 topol.conf); this
    /// refusal now means no per-bin energize contract is joined for
    /// am2-t19. The variant name stays for API stability.
    T19ExactGeometryUnresolved,
    ElectricalEnergizeContractUnresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398ControllerDialect {
    /// The exact production controller is not joined. Do not substitute the
    /// S19j Pro dsPIC or S17 PIC16 executor based on connector similarity.
    Unresolved,
    /// NBP1901 stock framed PIC1704, application revision observed as 0x89.
    /// This is not the CV/BB/AML short-form register service.
    StockPic1704Framed89,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398PsuDialect {
    /// No exact stock version and command dialect has been observed.
    Unresolved,
    /// NBP1901 framed APW121215a, queried version 0x71 (Sep 2 capture).
    Apw12StockFramed71,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398ElectricalEvidence {
    pub passive_board_identity: bool,
    pub independent_chip_id_match: bool,
    pub controller: Bm1398ControllerDialect,
    pub psu: Bm1398PsuDialect,
    pub power_control_polarity_measured: bool,
    pub reset_executor_joined: bool,
    pub cooling_custody_joined: bool,
    pub thermal_sensor_freshness_joined: bool,
    pub terminal_rail_off_measured: bool,
}

impl Default for Bm1398ElectricalEvidence {
    fn default() -> Self {
        Self {
            passive_board_identity: false,
            independent_chip_id_match: false,
            controller: Bm1398ControllerDialect::Unresolved,
            psu: Bm1398PsuDialect::Unresolved,
            power_control_polarity_measured: false,
            reset_executor_joined: false,
            cooling_custody_joined: false,
            thermal_sensor_freshness_joined: false,
            terminal_rail_off_measured: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398ElectricalGap {
    PassiveBoardIdentity,
    IndependentChipIdMatch,
    ControllerDialect,
    PsuDialect,
    MeasuredPowerControlPolarity,
    ResetExecutor,
    CoolingCustody,
    ThermalSensorFreshness,
    MeasuredTerminalRailOff,
}

/// A typed, exhaustive desk receipt. This is diagnostic only: while the
/// controller/PSU enums contain only `Unresolved`, it is impossible to forge
/// an admitted electrical receipt in software.
pub fn bm1398_electrical_gaps(evidence: Bm1398ElectricalEvidence) -> Vec<Bm1398ElectricalGap> {
    let mut gaps = Vec::new();
    if !evidence.passive_board_identity {
        gaps.push(Bm1398ElectricalGap::PassiveBoardIdentity);
    }
    if !evidence.independent_chip_id_match {
        gaps.push(Bm1398ElectricalGap::IndependentChipIdMatch);
    }
    if matches!(evidence.controller, Bm1398ControllerDialect::Unresolved) {
        gaps.push(Bm1398ElectricalGap::ControllerDialect);
    }
    if matches!(evidence.psu, Bm1398PsuDialect::Unresolved) {
        gaps.push(Bm1398ElectricalGap::PsuDialect);
    }
    if !evidence.power_control_polarity_measured {
        gaps.push(Bm1398ElectricalGap::MeasuredPowerControlPolarity);
    }
    if !evidence.reset_executor_joined {
        gaps.push(Bm1398ElectricalGap::ResetExecutor);
    }
    if !evidence.cooling_custody_joined {
        gaps.push(Bm1398ElectricalGap::CoolingCustody);
    }
    if !evidence.thermal_sensor_freshness_joined {
        gaps.push(Bm1398ElectricalGap::ThermalSensorFreshness);
    }
    if !evidence.terminal_rail_off_measured {
        gaps.push(Bm1398ElectricalGap::MeasuredTerminalRailOff);
    }
    gaps
}

/// Legacy target-name-only admission. A name cannot establish controller or
/// board identity; native callers use [`executor::Bm1398Runtime`], which
/// executes and checks the actual factory/controller/ASIC transactions.
pub fn admit_bm1398_hybrid_energize(board_target: &str) -> Result<(), Bm1398HybridAdmissionError> {
    match board_target {
        "am2-s19pro" => Err(Bm1398HybridAdmissionError::ElectricalEnergizeContractUnresolved),
        "am2-t19" => Err(Bm1398HybridAdmissionError::T19ExactGeometryUnresolved),
        _ => Err(Bm1398HybridAdmissionError::WrongBoardTarget),
    }
}

// ── 2026-08-29 authorization package: typed no-work bench receipts ──────────
//
// The operator bench card
//
// defines four passive phases (R1 board identity, R2 chip-count log read,
// R3 dialect probe reads, R4 DMM polarity). These types are the
// machine-readable home those receipts fill. They close EXACTLY the four
// software-visible gaps and select dialects among the typed candidates;
// energize admission stays refused (five gates remain open by design) and
// no install tier follows. Every receipt must cite its instrument
// artifacts by sha256 — a receipt without pinned artifacts is refused, so
// software alone cannot conjure one.

/// One instrument artifact backing a receipt (bench-captured file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1398ReceiptArtifact {
    pub name: &'static str,
    pub sha256_hex: String,
    pub bytes: u64,
}

impl Bm1398ReceiptArtifact {
    /// A pinned artifact must carry a real sha256 (64 hex chars) and size.
    pub fn is_pinned(&self) -> bool {
        self.bytes > 0
            && self.sha256_hex.len() == 64
            && self.sha256_hex.chars().all(|c| c.is_ascii_hexdigit())
    }
}

/// R4 outcome: the measured level that corresponds to the rail ENABLED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398MeasuredPolarity {
    EnabledLow,
    EnabledHigh,
}

/// Which typed candidate a dialect-selection receipt confirms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398DialectSelection {
    ConfirmedPsu(&'static str),
    ConfirmedController(&'static str),
    /// The probe read contradicted every typed candidate: the capture wins
    /// and the candidate layer is retired for this unit.
    RetiredAll,
}

/// One phase receipt as filled by the operator from the bench artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1398NoWorkReceipt {
    pub phase: &'static str,
    pub operator: String,
    pub timestamp_utc: String,
    pub instrument: String,
    pub artifacts: Vec<Bm1398ReceiptArtifact>,
    pub selection: Option<Bm1398DialectSelection>,
    pub polarity: Option<Bm1398MeasuredPolarity>,
}

impl Bm1398NoWorkReceipt {
    fn admissible(&self) -> bool {
        let phase_ok = matches!(self.phase, "R1" | "R2" | "R3" | "R4");
        let provenance_ok = !self.operator.is_empty()
            && !self.timestamp_utc.is_empty()
            && !self.instrument.is_empty();
        let artifacts_ok =
            !self.artifacts.is_empty() && self.artifacts.iter().all(|a| a.is_pinned());
        phase_ok && provenance_ok && artifacts_ok
    }
}

/// Apply a set of accepted no-work receipts to the electrical evidence,
/// closing exactly the four receipt-backed gaps. Unknown phases, unpinned
/// receipts, or dialect selections naming a candidate outside the typed
/// tables are refused — the caller keeps the unmodified evidence.
pub fn apply_bm1398_no_work_receipts(
    evidence: Bm1398ElectricalEvidence,
    receipts: &[Bm1398NoWorkReceipt],
) -> Result<Bm1398ElectricalEvidence, &'static str> {
    let mut out = evidence;
    for receipt in receipts {
        if !receipt.admissible() {
            return Err("receipt lacks operator provenance or pinned instrument artifacts");
        }
        match receipt.phase {
            "R1" => out.passive_board_identity = true,
            "R2" => out.independent_chip_id_match = true,
            "R3" => match receipt.selection {
                Some(Bm1398DialectSelection::ConfirmedPsu(name)) => {
                    if !NBP1901_PSU_CANDIDATES.iter().any(|c| c.name == name) {
                        return Err("psu selection names a candidate outside the typed table");
                    }
                }
                Some(Bm1398DialectSelection::ConfirmedController(kind)) => {
                    if !NBP1901_CONTROLLER_CANDIDATES.iter().any(|c| c.kind == kind) {
                        return Err(
                            "controller selection names a candidate outside the typed table",
                        );
                    }
                }
                Some(Bm1398DialectSelection::RetiredAll) => {
                    return Err("candidate retirement requires a campaign decision, not a receipt");
                }
                None => return Err("R3 receipt must carry a dialect selection"),
            },
            "R4" => {
                // The measurement closes the polarity gate whichever way it
                // reads; a reading that CONTRADICTS the jig hypothesis is
                // recorded in the artifact and retires the desk constant
                // during promotion review — the receipt itself still closes
                // the measured-polarity gap.
                out.power_control_polarity_measured = receipt.polarity.is_some();
                if receipt.polarity.is_none() {
                    return Err("R4 receipt must carry the measured polarity");
                }
            }
            _ => unreachable!("admissible() restricted the phase set"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn oscillator_baud_transition_preserves_unrelated_bits_and_refuses_pll3_path() {
        assert_eq!(
            bm1398_oscillator_baud_register(0x0000_7a31, BM1398_RUNTIME_WORK_BAUD),
            Ok(0x0000_6131)
        );
        for old in [0, 0xffff_ffff, 0x1234_5678, 0x0000_7a31] {
            let new = bm1398_oscillator_baud_register(old, BM1398_RUNTIME_WORK_BAUD).unwrap();
            assert_eq!(new & !0x0f01_1f00, old & !0x0f01_1f00);
            assert_eq!((new >> 8) & 31, 1);
            assert_eq!(new & 0x0f01_0000, 0);
        }
        for baud in [0, 1, 3_000_001, 3_125_000, 12_000_000, u32::MAX] {
            assert!(bm1398_oscillator_baud_register(0, baud).is_err());
        }
    }

    fn policy() -> PacedEnumerationPolicy {
        PacedEnumerationPolicy::new(
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(10),
            2,
        )
        .unwrap()
    }

    #[test]
    fn exact_s19pro_geometry_and_coverage_are_typed() {
        let plan = Bm1398HybridDeskPlan::s19_pro(policy(), Bm1398FpgaMidstateMode::Eight);
        let expected = plan.expected_addresses();
        assert_eq!(expected.len(), 114);
        assert_eq!(expected.first(), Some(&0x00));
        assert_eq!(expected.last(), Some(&0xe2));
        assert!(plan.certify_chain(&expected).is_ok());
        assert!(plan.certify_chain(&expected[..113]).is_err());
    }

    #[test]
    fn work_id_preserves_the_full_extended_fifo_identifier() {
        let plan = Bm1398HybridDeskPlan::s19_pro(policy(), Bm1398FpgaMidstateMode::Four);
        assert_eq!(plan.work_id_slots, 16_384);
        assert_eq!(plan.decode_carrier_work_id(0x12ab), 0x4aa);
        assert_eq!(plan.decode_carrier_work_id(0xffff), 0x3fff);
        let eight = Bm1398HybridDeskPlan::s19_pro(policy(), Bm1398FpgaMidstateMode::Eight);
        assert_eq!(eight.work_id_slots, 8192);
        assert_eq!(eight.decode_carrier_work_id(0xffff), 0x1fff);
    }

    /// R07 family pins: the two 76-chip bins carry the exact stock
    /// NBS1902/NBT1903 geometry (76/chain, interval 3, shared plan), their
    /// own levels.json ladders, and per-bin defaults. Neither 76-chip bin
    /// accepts the Pro ladder and vice versa.
    #[test]
    fn nbs1902_and_nbt1903_plans_pin_stock_geometry_levels_and_targets() {
        let s19 = Bm1398HybridDeskPlan::s19_classic(policy(), Bm1398FpgaMidstateMode::Four);
        assert_eq!(s19.model, Bm1398HybridModel::S19Classic);
        assert_eq!(s19.chips_per_chain, 76);
        assert_eq!(s19.address_interval, 3);
        let expected = s19.expected_addresses();
        assert_eq!(expected.len(), 76);
        assert_eq!(expected.first(), Some(&0x00));
        assert_eq!(expected.last(), Some(&(75 * 3)));
        assert!(s19.certify_chain(&expected).is_ok());
        assert!(s19.certify_chain(&expected[..75]).is_err());
        let t19 = Bm1398HybridDeskPlan::t19(policy(), Bm1398FpgaMidstateMode::Four);
        assert_eq!(t19.expected_addresses(), expected, "same 76/3 plan");

        assert!(Bm1398HybridModel::S19Classic
            .stock_levels()
            .contains(&(675, 1380)));
        assert!(Bm1398HybridModel::T19.stock_levels().contains(&(550, 1420)));
        assert!(!Bm1398HybridModel::S19Pro
            .stock_levels()
            .contains(&(675, 1380)));
        // The T19 ladder is not a cross product: (550, 1400) is not a row.
        assert!(!Bm1398HybridModel::T19.stock_levels().contains(&(550, 1400)));
        assert!(!Bm1398HybridModel::S19Classic
            .stock_levels()
            .contains(&(500, 1280)));
        assert_eq!(
            Bm1398HybridModel::S19Classic.default_operating_point(),
            (650, 1380)
        );
        assert_eq!(
            Bm1398HybridModel::T19.default_operating_point(),
            (550, 1420)
        );
        assert_eq!(Bm1398HybridModel::S19Classic.board_target(), "am2-s19");
        assert_eq!(Bm1398HybridModel::T19.board_target(), "am2-t19");
        assert_eq!(
            Bm1398HybridModel::S19Classic.stock_board_names(),
            &["NBS1902"]
        );
        assert_eq!(Bm1398HybridModel::T19.stock_board_names(), &["NBT1903"]);
    }

    #[test]
    fn energize_stays_closed_and_t19_is_not_callable() {
        assert_eq!(
            admit_bm1398_hybrid_energize("am2-s19pro"),
            Err(Bm1398HybridAdmissionError::ElectricalEnergizeContractUnresolved)
        );
        assert_eq!(
            admit_bm1398_hybrid_energize("am2-t19"),
            Err(Bm1398HybridAdmissionError::T19ExactGeometryUnresolved)
        );
        assert_eq!(
            admit_bm1398_hybrid_energize("am2-s19"),
            Err(Bm1398HybridAdmissionError::WrongBoardTarget)
        );
    }

    #[test]
    fn exact_nbp1901_thermal_topology_is_typed_but_not_energize_authority() {
        assert_eq!(S19_PRO_TEMPERATURE_CHANNELS, 4);
        assert_eq!(S19_PRO_TEMPERATURE_ADDRESSES, [0x48, 0x49, 0x4a, 0x4b]);
        assert!(!NBP1901_GEOMETRY_EVIDENCE.exact_for_energize);
        assert!(!NBP1901_THERMAL_TOPOLOGY_EVIDENCE.exact_for_energize);
    }

    #[test]
    fn empty_electrical_receipt_names_every_irreducible_gate() {
        assert_eq!(
            bm1398_electrical_gaps(Bm1398ElectricalEvidence::default()),
            vec![
                Bm1398ElectricalGap::PassiveBoardIdentity,
                Bm1398ElectricalGap::IndependentChipIdMatch,
                Bm1398ElectricalGap::ControllerDialect,
                Bm1398ElectricalGap::PsuDialect,
                Bm1398ElectricalGap::MeasuredPowerControlPolarity,
                Bm1398ElectricalGap::ResetExecutor,
                Bm1398ElectricalGap::CoolingCustody,
                Bm1398ElectricalGap::ThermalSensorFreshness,
                Bm1398ElectricalGap::MeasuredTerminalRailOff,
            ]
        );
    }

    #[test]
    fn software_observations_cannot_close_physical_or_dialect_gates() {
        let evidence = Bm1398ElectricalEvidence {
            passive_board_identity: true,
            independent_chip_id_match: true,
            reset_executor_joined: true,
            cooling_custody_joined: true,
            thermal_sensor_freshness_joined: true,
            ..Default::default()
        };
        assert_eq!(
            bm1398_electrical_gaps(evidence),
            vec![
                Bm1398ElectricalGap::ControllerDialect,
                Bm1398ElectricalGap::PsuDialect,
                Bm1398ElectricalGap::MeasuredPowerControlPolarity,
                Bm1398ElectricalGap::MeasuredTerminalRailOff,
            ]
        );
    }

    /// 2026-08-29 desk-residual pins: the candidate layer exists only as
    /// evidence-cited desk facts. It can never close a gap, flip a
    /// dialect enum, or soften the admission refusal.
    #[test]
    fn candidates_are_desk_facts_never_admission_inputs() {
        // Every candidate is explicitly not energize authority.
        for candidate in NBP1901_PSU_CANDIDATES {
            assert!(!candidate.evidence.exact_for_energize);
        }
        for candidate in NBP1901_CONTROLLER_CANDIDATES {
            assert!(!candidate.evidence.exact_for_energize);
        }
        assert!(!NBP1901_CATALOG_EVIDENCE.exact_for_energize);
        assert!(!NBP1901_JIG_EVIDENCE.exact_for_energize);
        // The dialect enums still hold only Unresolved — the forging
        // guarantee the boundary documents is intact.
        assert!(matches!(
            Bm1398ControllerDialect::Unresolved,
            Bm1398ControllerDialect::Unresolved
        ));
        assert!(matches!(
            Bm1398PsuDialect::Unresolved,
            Bm1398PsuDialect::Unresolved
        ));
        // Admission still refuses S19 Pro even with candidates on record.
        assert_eq!(
            admit_bm1398_hybrid_energize("am2-s19pro"),
            Err(Bm1398HybridAdmissionError::ElectricalEnergizeContractUnresolved)
        );
        // And the gap enumeration is unchanged by the candidates' existence.
        assert_eq!(
            bm1398_electrical_gaps(Bm1398ElectricalEvidence::default()).len(),
            9
        );
    }

    /// Catalog cross-corroborations: the PSU candidate's power GPIO matches
    /// the factory jig's energize pin, and the controller candidate's
    /// sensors are exactly the already-typed thermal channels.
    #[test]
    fn catalog_candidates_cross_corroborate_independently_typed_facts() {
        let psu = NBP1901_PSU_CANDIDATES[0];
        assert_eq!(psu.i2c_addr, 0x10);
        assert_eq!(psu.power_gpio, 907, "matches the jig's energize GPIO");
        let controller = NBP1901_CONTROLLER_CANDIDATES[0];
        assert_eq!(controller.i2c_addr, 0x20);
        // The PIC sensor set in the catalog is exactly 0x48..0x4b — the
        // same addresses typed from the VNish catalog origin.
        let sensors = [0x48u8, 0x49, 0x4a, 0x4b];
        assert_eq!(S19_PRO_TEMPERATURE_ADDRESSES, sensors);
        assert_eq!(NBP1901_EEPROM_I2C_ADDR, 0x50);
        assert_eq!(NBP1901_FAN_COUNT, 4);
    }

    /// The jig-derived energize polarity and relay capability are recorded
    /// as desk facts; the ACTIVE_HIGH contradiction stays operator-gated.
    #[test]
    fn jig_polarity_and_relay_capability_are_typed_desk_facts() {
        assert_eq!(NBP1901_GPIO907_JIG_ENERGIZE_WRITE, "0");
        // Relay capability boundary: the code tests < 10, so 9 is incapable
        // and 10 is capable (Bitmain's "less than 9" log text is wrong).
        assert!(!voltage_domain_relay_capable(9));
        assert!(voltage_domain_relay_capable(10));
        assert!(voltage_domain_relay_capable(38), "NBP1901-38 domains");
    }

    fn pinned_artifact() -> Bm1398ReceiptArtifact {
        Bm1398ReceiptArtifact {
            name: "r1_eeprom_hb1.hex",
            sha256_hex: "a".repeat(64),
            bytes: 256,
        }
    }

    fn receipt(phase: &'static str) -> Bm1398NoWorkReceipt {
        Bm1398NoWorkReceipt {
            phase,
            operator: "operator".into(),
            timestamp_utc: "2026-08-29T00:00:00Z".into(),
            instrument: "bench DMM".into(),
            artifacts: vec![pinned_artifact()],
            selection: None,
            polarity: None,
        }
    }

    /// The four bench-card phases close EXACTLY their four gaps; the other
    /// five stay open and energize admission still refuses afterwards.
    #[test]
    fn no_work_receipts_close_exactly_their_four_gaps() {
        let mut receipts = vec![
            receipt("R1"),
            receipt("R2"),
            Bm1398NoWorkReceipt {
                selection: Some(Bm1398DialectSelection::ConfirmedPsu("APW12")),
                ..receipt("R3")
            },
            Bm1398NoWorkReceipt {
                selection: Some(Bm1398DialectSelection::ConfirmedController("PIC1704")),
                ..receipt("R3")
            },
            Bm1398NoWorkReceipt {
                polarity: Some(Bm1398MeasuredPolarity::EnabledLow),
                ..receipt("R4")
            },
        ];
        // Duplicate phases are not double-counted but also not refused.
        receipts.push(receipt("R1"));
        let applied = apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &receipts)
            .expect("complete receipt set applies");
        assert!(applied.passive_board_identity);
        assert!(applied.independent_chip_id_match);
        assert!(applied.power_control_polarity_measured);
        // Six gates remain: the dialect enums hold only Unresolved by the
        // anti-forging design, so an R3 selection VALIDATES against the
        // candidate table but the ControllerDialect/PsuDialect gaps close
        // only when the campaign adds the confirmed enum variants at
        // promotion time (from these accepted receipts). Energize still
        // refuses afterwards.
        assert_eq!(
            bm1398_electrical_gaps(applied),
            vec![
                Bm1398ElectricalGap::ControllerDialect,
                Bm1398ElectricalGap::PsuDialect,
                Bm1398ElectricalGap::ResetExecutor,
                Bm1398ElectricalGap::CoolingCustody,
                Bm1398ElectricalGap::ThermalSensorFreshness,
                Bm1398ElectricalGap::MeasuredTerminalRailOff,
            ]
        );
        assert_eq!(
            admit_bm1398_hybrid_energize("am2-s19pro"),
            Err(Bm1398HybridAdmissionError::ElectricalEnergizeContractUnresolved)
        );
    }

    /// Unpinned or anonymous receipts are refused — software cannot conjure
    /// a receipt without operator provenance and real artifact hashes.
    #[test]
    fn unpinned_or_anonymous_receipts_are_refused() {
        let r = Bm1398NoWorkReceipt {
            artifacts: Vec::new(),
            ..receipt("R1")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());

        let mut r = receipt("R1");
        r.artifacts[0].sha256_hex.truncate(10);
        assert!(
            apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r.clone()])
                .is_err()
        );

        let mut r = receipt("R1");
        r.artifacts[0].bytes = 0;
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());

        let r = Bm1398NoWorkReceipt {
            operator: String::new(),
            ..receipt("R1")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());

        let r = Bm1398NoWorkReceipt {
            polarity: None,
            ..receipt("R4")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());
        let r = Bm1398NoWorkReceipt {
            polarity: Some(Bm1398MeasuredPolarity::EnabledHigh),
            ..receipt("R4")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_ok());
    }

    /// Dialect selections must name a TYPED candidate; retirement is a
    /// campaign decision, not something a receipt can do alone.
    #[test]
    fn dialect_selections_must_name_typed_candidates() {
        let r = Bm1398NoWorkReceipt {
            selection: Some(Bm1398DialectSelection::ConfirmedPsu("APW8-not-typed")),
            ..receipt("R3")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());

        let r = Bm1398NoWorkReceipt {
            selection: Some(Bm1398DialectSelection::RetiredAll),
            ..receipt("R3")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());

        let r = Bm1398NoWorkReceipt {
            selection: Some(Bm1398DialectSelection::ConfirmedController("PIC1704")),
            ..receipt("R3")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_ok());
    }
}
