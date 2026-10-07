//! Exact hydro / immersion board-PSU-cooling runtime profiles (campaign
//! `2026-09-07-antminer-beta-execution`, lane R15).
//! Pure and no-I/O: this module enumerates, admits, scopes and refuses; it
//! never opens a UART, drives GPIO907, talks I2C, or grants electrical
//! authority. Doctrine mirrors `bm1368_s21_board_profiles` (lane R13) and
//! `bm1370_board_profiles` (lane R14): exact per-board tuples, refuse
//! wrong / duplicate / empty, Unproven stays Unproven, EvidenceOnly
//! authority wherever held evidence is absent.
//!
//! # Tuple inventory (Deliverable 1) — what the held stock bytes prove
//!
//! Every tuple below is cited to a HELD stock `topol.conf` (per-machine
//! factory topology, decrypted and extracted inside the held Bitmain update
//! images under ) plus the
//! held stock `bmminer` ELF of the same image. All eight held hydro images
//! share one byte-identical Zynq-7000 control-board devicetree (SHA-256
//! `47e56969ce80ae9b1374aea555bf49d3c47637c6207ee33d70a20e7f214e45c0`,
//! 8014 bytes, `xlnx,zynq-7000`): the hydro control board is a ZYNQ7007
//! processor on EVERY held generation (S19 Hydro 2022 → S21 XP Hydro
//! 2024-10). Universal per-machine constants held by every `topol.conf`:
//! PSU control at I²C address 16 (0x10) with PSU-enable GPIO **907**, the
//! hashboard PIC is a **PIC1704** at I²C address 32 (0x20), and the
//! hashboard EEPROM is an **AT24C02D** at I²C address 80 (0x50) — inside
//! the HAL's 0x50..=0x57 write-protect denylist (corruption-prevention
//! guarantee 1, root ).
//!
//! | Generation | Held image (`…asicminingsupplies/<dir>`) | Boards (topol.conf `machine`) | ASIC (id, cores, interval) | Chains | PIC sensors (exact I²C addrs) | PSU (`type`, target W) |
//! |---|---|---|---|---|---|---|
//! | HHB28 | `s19-hydro-20221217` | HHB28601 | BM1398P (0x1398, 156 cores, interval 2) | 4 x 104 (52 dom x 2) = 416 | 2x LM75A @0x48 right/bottom, @0x49 right/top | "AWP11" (stock's own spelling) 0x10/GPIO907 |
//! | HHB28 | `t19-hydro-20221212` | HHB28602 | BM1398P (same) | 4 x 104 | same 2x LM75A | "AWP11" |
//! | HHB42 | `s19pro-hydro-20240202`, `s19pro-plus-hydro-20230308` | HHB42601 (5600 W), HHB42602 (5600 W), HHB42631 (5600 W) | BM1362 (0x1362, 65 cores, interval 1) | 4 x 180 (60 dom x 3) = 720 | LM75A @0x4A left/bottom, @0x48 right/bottom, @0x49 right/top, TMP451 @0x4C left/top | "AWP11" |
//! | HHB42 | (same two images) | HHB42701, HHB42711, TH401 (no power_target) | BM1362 (same) | 4 x 180 | same 4 sensors | "AWP8" — a DIFFERENT PSU family |
//! | HHB56 | `s19-xp-hydro-20240924` (zynq7007 image), `s19e-xp-hydro-20240624`, `t19-pro-hydro-20240417` | HHB56601 (5400 W), HHB56611, HHB56701 (4700 W), HHB56603, HHB56613, HHB56702 (5400 W), H6HB56702, H1HB56703 | BM1366 (0x1366, 112 cores, interval 1) | 3 x 204 (17 dom x 12) = 612 | 4x LM75A @0x4A, @0x48, @0x49, @0x4B | APW11 0x10/GPIO907 |
//! | HHB68 | `s21-hydro-20240519` | HHB68601, HHB68602 (jt 16.80), HHB68501, HHB68502, HHB68503, HHB68504 (jt 16.00) | BM1368 (0x1368, 80 cores, interval 1) | 3 x 216 (18 dom x 12) = 648 | 4x LM75A @0x4A, @0x48, @0x49, @0x4B | APW11 |
//! | HHB68 | (same image) | HHB68701 (jt 19.00) | BM1368 | 3 x 180 = 540 | same 4x LM75A | APW11 |
//! | HHB70 | `s21-xp-hydro-20241011` | H6HB70601, H6HB70602, H6HB70501, H1HB70601 | BM1370 (0x1370, 128 cores, interval 1) | 3 x 160 (20 dom x 8) = 480 | 4x LM75A | APW11 |
//!
//! # Unproven / absent (never inferred from a sibling row)
//!
//! - **S9 Hydro (2019)**: held bytes prove the miner *config* only —
//!   `s9-hydro-xilinx-20190920` rootfs `etc/config/Config.ini`
//!   (SHA-256 `cfd88790ea1b6714474d39eb410b2af99b1f254cb3401601e79f5a47110f880b`:
//!   `AsicType=1387`, `AsicNum=63`, `CoreNum=114`, PIC voltage path
//!   `Pic_VOLTAGE=1`, `IICPic=1`, `DAC=1`) and `etc/bmminer.conf.factory`
//!   (`bitmain-freq 550`, `bitmain-voltage 0706`, `bitmain-low-vol 1`).
//!   No miner ELF and no hydro water-law strings are held for this model,
//!   and it carries no `topol.conf`; its water feedback is **Unproven**
//!   (`S9_Hydro_CONFIG_ONLY` below) and it has no runtime profile here.
//! - **Immersion-only boards** (VNish-transcribed `IHB68601` S21 Imm,
//!   `M1HB70601/02` S21 XP Imm, `H1HB68601` U3S19XP+H, `H1HB70602`
//!   U3S21EXPH …): VNish-transcribed model JSON rows only
//!   (`desk_vnish_firmware_experimental` provenance), **no held stock
//!   bytes**. The U3 exception: held factory-jig decompilations for
//!   `U3S21EXPH` and `S21xp-hydro` single-board-test binaries exist
//!, which prove the
//!   cutoff LAW (`pt_read_temp`, see `hydro_cooling_feedback`) but NOT a
//!   shipping tuple (no chains/ASIC/PSU row). They stay absent here.
//! - **No per-board chip-geometry for immersion kits, no fan geometry, no
//!   pump control law**: the pump/dry-cooler is an EXTERNAL loop element;
//!   no held byte grants the unit a pump actuator.
//! - The VNish matrix claims per-hydro-board chip counts (e.g. HHB68501
//!   3x216) that AGREE with the held topol.conf for every board it names,
//!   but VNish rows are transcription-only (ePIC-caveat class); the held
//!   topol.conf is the authority cited here, never the JSON.
//!
//! # Install / registration posture
//!
//! Hydro rows are EXCLUDED from beta kits (agent_tasks R15): this module
//! exposes runtime profiles only — no install route, no enablement-matrix
//! row, no board registration claim. Promotion of any tuple to installable
//! is a deliberate, evidence-backed F02/B01 decision outside this lane.

use crate::cooling_medium::CoolingMedium;

/// PIC1704 hashboard controller I²C address (7-bit), decimal 32, held by
/// every hydro `topol.conf` (`"pic": {"type": "PIC1704", "i2c_addr": 32}`)
/// — S19 Hydro 2022 through S21 XP Hydro 2024-10.
pub const HYDRO_PIC1704_I2C_ADDR: u8 = 32;

/// Hydro hashboard EEPROM: AT24C02D at I²C 0x50 (`"eeprom": {"type":
/// "AT24C02D", "i2c_addr": 80}`), inside the HAL 0x50..=0x57 write
/// denylist. Reads only; writes are HAL-refused.
pub const HYDRO_EEPROM_I2C_ADDR: u8 = 80;

/// PSU control I²C address (decimal 16 = 0x10) held by every hydro
/// `topol.conf` power block.
pub const HYDRO_PSU_I2C_ADDR: u8 = 16;

/// PSU-enable GPIO number held by every hydro `topol.conf` power block and
/// by the factory `bitmain_power_off` executor (`single_board_test.dec/
/// bitmain_power_off@1C54D0` writes GPIO907 = 1 to power OFF, i.e. the
/// software mapping on this control board is 0 = ON, 1 = OFF — the same
/// mapping the 17-series lane pins for GPIO907). This is production
/// software-mapping evidence, not a DMM rail measurement; physical SafeOff
/// proof remains a bench requirement.
pub const HYDRO_PSU_ENABLE_GPIO: u32 = 907;

/// Zynq-7000 control board (`"processor": {"type": "ZYNQ7007"}` in every
/// held hydro topol.conf; byte-identical `xlnx,zynq-7000` devicetree across
/// all eight held images).
pub const HYDRO_CONTROL_PROCESSOR: &str = "ZYNQ7007";

/// The coolant-loop cooling medium every profile here declares. Declared
/// from the held per-model evidence (immersion-only VNish rows + hydro
/// `bitmain-fan-ctrl: false` factory confs + absent fan hardware in the
/// hydro topol present only as stock's 4-slot air template), never
/// inferred from a board name alone.
pub const HYDRO_COOLING_MEDIUM: CoolingMedium = CoolingMedium::Hydro;

/// Which stock PSU firmware family a hydro tuple's power block names.
/// The exact `type` string is carried verbatim — two held generations
/// spell it "AWP11" (stock's own typo for APW11) and one group of HHB42
/// boards names "AWP8"; neither is normalized, corrected, or inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HydroPsuFamily {
    /// Held `type` string "APW11" (HHB56/HHB68/HHB70 topol.conf power
    /// blocks, I²C 0x10, GPIO907).
    Apw11,
    /// Held `type` string "AWP11" — stock's own spelling in the HHB28 and
    /// HHB42 topol.conf power blocks (same address pair 0x10/GPIO907).
    /// Carried verbatim; never rewritten to Apw11.
    Apw11StockSpellingAwp11,
    /// Held `type` string "AWP8" — the HHB42 boards HHB42701 / HHB42711 /
    /// TH401 (s19pro-hydro + s19pro-plus-hydro topol.conf), which also
    /// carry NO `power_target`/`jt_target` rows. A distinct PSU family
    /// from APW11; never merged with it.
    Apw8StockSpellingAwp8,
}

impl HydroPsuFamily {
    /// The exact stock JSON `type` string these held bytes carry.
    pub const fn stock_type_string(self) -> &'static str {
        match self {
            HydroPsuFamily::Apw11 => "APW11",
            HydroPsuFamily::Apw11StockSpellingAwp11 => "AWP11",
            HydroPsuFamily::Apw8StockSpellingAwp8 => "AWP8",
        }
    }
}

/// Which held water-feedback law set a generation's bmminer bytes prove.
/// Cited strings live in the listed held ELF (`usr/bin/bmminer` of the
/// same image). The generations are ordered; a profile carries exactly
/// the law set its own bytes prove — laws are NEVER back-ported forward
/// or assumed backward (a G1 board gets no permit-API law, an S9 Hydro
/// gets no water law at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HydroFeedbackGeneration {
    /// HHB28 (S19/T19 Hydro 2022-12 bmminer, SHA-256 `8f584fa9…6697ce` /
    /// `73bc8c8b…445de2d`): "too low water temperature pic temp %d (min
    /// %d)", "inlet_temperature" API field, "water temp %d ~ %d, stop.",
    /// "Water is not flowing!", "water temp %d ~ %d, sleep %ds to cool
    /// down", "Water temperature is too low!". NO too-hot string, NO
    /// water-permit API, NO reverse-flow detection is held for this
    /// generation.
    Gen1PicTempMinOnly,
    /// HHB42 (S19 Pro / Pro+ Hydro 2023-2024 bmminer, `78adc24b…011696` /
    /// `235d5c7e…f61ff1`): adds "too hot water temperature pic temp %d
    /// (min %d)" and the water-permit gate `/get_water_permit` +
    /// "get_water_permit failed" + "Water temperature is too high!".
    /// Also "Water is not flowing!".
    Gen2WaterPermitGate,
    /// HHB56 (S19 XP / S19e XP / T19 Pro Hydro 2024 bmminer, `c62d0dda…419135` /
    /// `6d7cfffd…a4b18` / `fcce4aa6…0b871b`): Gen2 + "water_in_temp" API
    /// field. Same core law set.
    Gen3WaterInTempField,
    /// HHB68 (S21 Hydro 2024-05 bmminer, `d07fa2e8…9ede4141`): adds the
    /// four-channel law "inlet_board_temp=%d,outlet_board_temp=%d,
    /// inlet_water_temp=%d,outlet_water_temp=%d", the delta law
    /// "difference between inlet and outlet is too large:%d
    /// inlet_temp:%d,outlet_temp:%d", board-temp stats
    /// "inlet_board_temp_max:%d, inlet_board_temp_min:%d, …", and
    /// reverse-flow detection "water flow is reverse, please swap the
    /// water pipes at the inlet and outlet" / "water flow is reverse" /
    /// "ERROR_WATER_REVERSE".
    Gen4InletOutletAndReverse,
    /// HHB70 (S21 XP Hydro 2024-10 bmminer, `aa642f76…2ddfda1`): Gen4 +
    /// per-chain water temps "inlet_water_temp:%d, outlet_water_temp:%d,
    /// chain : 0x%0x", "water temp diff err", the water-scoped voltage
    /// law "water_temp_min = %d endvol =%d vol_cur =%d" and the
    /// `/inlet_temp` API. PLUS the held factory-jig cutoff executor:
    /// `single_board_test.dec/pt_read_temp@8FF50` — sensor[0] minus
    /// sensor[1] > 3 °C ⇒ "Water flow reversal!" ⇒ err code 6 ⇒
    /// `bitmain_power_off()` (GPIO907 = 1) immediately.
    Gen5WaterScopedVoltageAndJigCutoff,
}

/// One exact LM75A/TMP451 sensor slot on the PIC sensor path, with the
/// exact stock JSON I²C address and its physical x/y placement from
/// `topol.conf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HydroPicSensor {
    /// Stock JSON sensor index (topol.conf `pic.sensor[].index`).
    pub index: u8,
    /// Exact stock type string ("LM75A" / "TMP451").
    pub stock_type: &'static str,
    /// I²C address as held in the topol.conf (decimal: 72=0x48, 73=0x49,
    /// 74=0x4A, 75=0x4B, 76=0x4C).
    pub i2c_addr: u8,
    /// Stock x placement ("left" / "right").
    pub x: &'static str,
    /// Stock y placement ("bottom" / "top").
    pub y: &'static str,
}

/// ASIC silicon identity + per-chain geometry a held topol.conf proves for
/// one hydro board. A nonce/observation against a different identity
/// refuses at admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HydroAsicProfile {
    /// Exact stock asic_id string.
    pub stock_id: &'static str,
    /// ASIC wire identity address (e.g. 0x1362) from topol.conf
    /// `asic_addr`.
    pub chip_id: u16,
    /// Stock `asic_core_num`.
    pub cores_per_chip: u16,
    /// Stock post-assignment chip address interval.
    pub address_interval: u8,
}

/// One exact hydro board profile (one held topol.conf `machine` entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HydroBoard {
    /// Exact stock `machine` string (e.g. "HHB56601"). This is the ONLY
    /// selector; a near-miss name never selects a profile.
    pub board_name: &'static str,
    /// The held image that carries this entry (short dir name under
    /// ).
    pub held_image: &'static str,
    pub asic: HydroAsicProfile,
    /// Stock `chain.chain_num` — hashboards per full unit.
    pub chains_per_unit: u8,
    /// Stock `chain.chain_asic_num` — exact ASIC count per populated chain.
    pub chips_per_chain: u16,
    /// Stock `chain.chain_domain_num`.
    pub domains_per_chain: u16,
    /// Stock `chain.domain_asic_num`.
    pub chips_per_domain: u8,
    /// PSU family this machine's power block names.
    pub psu: HydroPsuFamily,
    /// Stock `power_target` in W, when the machine entry carries one
    /// (AWP8 HHB42 entries carry none and stay `None` — never defaulted).
    pub power_target_w: Option<u16>,
    /// Which water-feedback law set the same image's bmminer proves.
    pub feedback_generation: HydroFeedbackGeneration,
    /// The PIC sensor path exactly as held (2, 3, or 4 sensors; counts and
    /// addresses are name-scoped per generation and never inherited).
    pub pic_sensors: &'static [HydroPicSensor],
}

/// The two-sensor HHB28 PIC path (LM75A right/bottom, right/top).
const PIC_SENSORS_HHB28: &[HydroPicSensor] = &[
    HydroPicSensor { index: 0, stock_type: "LM75A", i2c_addr: 72, x: "right", y: "bottom" },
    HydroPicSensor { index: 1, stock_type: "LM75A", i2c_addr: 73, x: "right", y: "top" },
];

/// The four-sensor HHB42 PIC path (3x LM75A + TMP451).
const PIC_SENSORS_HHB42: &[HydroPicSensor] = &[
    HydroPicSensor { index: 0, stock_type: "LM75A", i2c_addr: 74, x: "left", y: "bottom" },
    HydroPicSensor { index: 1, stock_type: "LM75A", i2c_addr: 72, x: "right", y: "bottom" },
    HydroPicSensor { index: 2, stock_type: "LM75A", i2c_addr: 73, x: "right", y: "top" },
    HydroPicSensor { index: 3, stock_type: "TMP451", i2c_addr: 76, x: "left", y: "top" },
];

/// The four-sensor HHB56/HHB68/HHB70 PIC path (4x LM75A).
const PIC_SENSORS_HHB56_68_70: &[HydroPicSensor] = &[
    HydroPicSensor { index: 0, stock_type: "LM75A", i2c_addr: 74, x: "left", y: "bottom" },
    HydroPicSensor { index: 1, stock_type: "LM75A", i2c_addr: 72, x: "right", y: "bottom" },
    HydroPicSensor { index: 2, stock_type: "LM75A", i2c_addr: 73, x: "right", y: "top" },
    HydroPicSensor { index: 3, stock_type: "LM75A", i2c_addr: 75, x: "left", y: "top" },
];

const BM1398P: HydroAsicProfile = HydroAsicProfile {
    stock_id: "BM1398P",
    chip_id: 0x1398,
    cores_per_chip: 156,
    address_interval: 2,
};
const BM1362: HydroAsicProfile = HydroAsicProfile {
    stock_id: "BM1362",
    chip_id: 0x1362,
    cores_per_chip: 65,
    address_interval: 1,
};
const BM1366: HydroAsicProfile = HydroAsicProfile {
    stock_id: "BM1366",
    chip_id: 0x1366,
    cores_per_chip: 112,
    address_interval: 1,
};
const BM1368: HydroAsicProfile = HydroAsicProfile {
    stock_id: "BM1368",
    chip_id: 0x1368,
    cores_per_chip: 80,
    address_interval: 1,
};
const BM1370: HydroAsicProfile = HydroAsicProfile {
    stock_id: "BM1370",
    chip_id: 0x1370,
    cores_per_chip: 128,
    address_interval: 1,
};

/// Every hydro machine entry held across the eight topol.conf files, in
/// generation order. This is the COMPLETE inventory — a name not in this
/// table has NO held hydro tuple and selects nothing.
pub const HYDRO_BOARDS: &[HydroBoard] = &[
    // ---- HHB28: s19-hydro-20221217 / t19-hydro-20221212 (one machine
    // entry per file; single-object topol.conf shape) ----
    HydroBoard {
        board_name: "HHB28601",
        held_image: "s19-hydro-20221217",
        asic: BM1398P,
        chains_per_unit: 4,
        chips_per_chain: 104,
        domains_per_chain: 52,
        chips_per_domain: 2,
        psu: HydroPsuFamily::Apw11StockSpellingAwp11,
        power_target_w: None,
        feedback_generation: HydroFeedbackGeneration::Gen1PicTempMinOnly,
        pic_sensors: PIC_SENSORS_HHB28,
    },
    HydroBoard {
        board_name: "HHB28602",
        held_image: "t19-hydro-20221212",
        asic: BM1398P,
        chains_per_unit: 4,
        chips_per_chain: 104,
        domains_per_chain: 52,
        chips_per_domain: 2,
        psu: HydroPsuFamily::Apw11StockSpellingAwp11,
        power_target_w: None,
        feedback_generation: HydroFeedbackGeneration::Gen1PicTempMinOnly,
        pic_sensors: PIC_SENSORS_HHB28,
    },
    // ---- HHB42: s19pro-hydro-20240202 / s19pro-plus-hydro-20230308
    // (six machine entries per file, identical tuples) ----
    HydroBoard {
        board_name: "HHB42601",
        held_image: "s19pro-hydro-20240202",
        asic: BM1362,
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        psu: HydroPsuFamily::Apw11StockSpellingAwp11,
        power_target_w: Some(5600),
        feedback_generation: HydroFeedbackGeneration::Gen2WaterPermitGate,
        pic_sensors: PIC_SENSORS_HHB42,
    },
    HydroBoard {
        board_name: "HHB42602",
        held_image: "s19pro-hydro-20240202",
        asic: BM1362,
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        psu: HydroPsuFamily::Apw11StockSpellingAwp11,
        power_target_w: Some(5600),
        feedback_generation: HydroFeedbackGeneration::Gen2WaterPermitGate,
        pic_sensors: PIC_SENSORS_HHB42,
    },
    HydroBoard {
        board_name: "HHB42631",
        held_image: "s19pro-hydro-20240202",
        asic: BM1362,
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        psu: HydroPsuFamily::Apw11StockSpellingAwp11,
        power_target_w: Some(5600),
        feedback_generation: HydroFeedbackGeneration::Gen2WaterPermitGate,
        pic_sensors: PIC_SENSORS_HHB42,
    },
    HydroBoard {
        board_name: "HHB42701",
        held_image: "s19pro-hydro-20240202",
        asic: BM1362,
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        psu: HydroPsuFamily::Apw8StockSpellingAwp8,
        power_target_w: None,
        feedback_generation: HydroFeedbackGeneration::Gen2WaterPermitGate,
        pic_sensors: PIC_SENSORS_HHB42,
    },
    HydroBoard {
        board_name: "HHB42711",
        held_image: "s19pro-hydro-20240202",
        asic: BM1362,
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        psu: HydroPsuFamily::Apw8StockSpellingAwp8,
        power_target_w: None,
        feedback_generation: HydroFeedbackGeneration::Gen2WaterPermitGate,
        pic_sensors: PIC_SENSORS_HHB42,
    },
    HydroBoard {
        board_name: "TH401",
        held_image: "s19pro-hydro-20240202",
        asic: BM1362,
        chains_per_unit: 4,
        chips_per_chain: 180,
        domains_per_chain: 60,
        chips_per_domain: 3,
        psu: HydroPsuFamily::Apw8StockSpellingAwp8,
        power_target_w: None,
        feedback_generation: HydroFeedbackGeneration::Gen2WaterPermitGate,
        pic_sensors: PIC_SENSORS_HHB42,
    },
    // ---- HHB56: s19-xp-hydro-20240924 (zynq7007) / s19e-xp-hydro-20240624
    // / t19-pro-hydro-20240417 ----
    HydroBoard {
        board_name: "HHB56601",
        held_image: "s19-xp-hydro-20240924",
        asic: BM1366,
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen3WaterInTempField,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "HHB56611",
        held_image: "s19-xp-hydro-20240924",
        asic: BM1366,
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen3WaterInTempField,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "HHB56701",
        held_image: "s19-xp-hydro-20240924",
        asic: BM1366,
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(4700),
        feedback_generation: HydroFeedbackGeneration::Gen3WaterInTempField,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "HHB56603",
        held_image: "s19-xp-hydro-20240924",
        asic: BM1366,
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen3WaterInTempField,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "HHB56613",
        held_image: "s19-xp-hydro-20240924",
        asic: BM1366,
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen3WaterInTempField,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "HHB56702",
        held_image: "s19-xp-hydro-20240924",
        asic: BM1366,
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen3WaterInTempField,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "H6HB56702",
        held_image: "s19-xp-hydro-20240924",
        asic: BM1366,
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen3WaterInTempField,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "H1HB56703",
        held_image: "s19-xp-hydro-20240924",
        asic: BM1366,
        chains_per_unit: 3,
        chips_per_chain: 204,
        domains_per_chain: 17,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen3WaterInTempField,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    // ---- HHB68: s21-hydro-20240519 ----
    HydroBoard {
        board_name: "HHB68601",
        held_image: "s21-hydro-20240519",
        asic: BM1368,
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen4InletOutletAndReverse,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "HHB68602",
        held_image: "s21-hydro-20240519",
        asic: BM1368,
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen4InletOutletAndReverse,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "HHB68501",
        held_image: "s21-hydro-20240519",
        asic: BM1368,
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen4InletOutletAndReverse,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "HHB68502",
        held_image: "s21-hydro-20240519",
        asic: BM1368,
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen4InletOutletAndReverse,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "HHB68503",
        held_image: "s21-hydro-20240519",
        asic: BM1368,
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen4InletOutletAndReverse,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "HHB68504",
        held_image: "s21-hydro-20240519",
        asic: BM1368,
        chains_per_unit: 3,
        chips_per_chain: 216,
        domains_per_chain: 18,
        chips_per_domain: 12,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen4InletOutletAndReverse,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "HHB68701",
        held_image: "s21-hydro-20240519",
        asic: BM1368,
        chains_per_unit: 3,
        chips_per_chain: 180,
        domains_per_chain: 18,
        // Stock carries `domain_asic_num: 10` for this machine (18 x 10 =
        // 180 — stock is internally consistent here; the 12-chip domain
        // rows belong to the 216-chip HHB68 boards).
        chips_per_domain: 10,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen4InletOutletAndReverse,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    // ---- HHB70: s21-xp-hydro-20241011 ----
    HydroBoard {
        board_name: "H6HB70601",
        held_image: "s21-xp-hydro-20241011",
        asic: BM1370,
        chains_per_unit: 3,
        chips_per_chain: 160,
        domains_per_chain: 20,
        chips_per_domain: 8,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen5WaterScopedVoltageAndJigCutoff,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "H6HB70602",
        held_image: "s21-xp-hydro-20241011",
        asic: BM1370,
        chains_per_unit: 3,
        chips_per_chain: 160,
        domains_per_chain: 20,
        chips_per_domain: 8,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen5WaterScopedVoltageAndJigCutoff,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "H6HB70501",
        held_image: "s21-xp-hydro-20241011",
        asic: BM1370,
        chains_per_unit: 3,
        chips_per_chain: 160,
        domains_per_chain: 20,
        chips_per_domain: 8,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen5WaterScopedVoltageAndJigCutoff,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
    HydroBoard {
        board_name: "H1HB70601",
        held_image: "s21-xp-hydro-20241011",
        asic: BM1370,
        chains_per_unit: 3,
        chips_per_chain: 160,
        domains_per_chain: 20,
        chips_per_domain: 8,
        psu: HydroPsuFamily::Apw11,
        power_target_w: Some(5400),
        feedback_generation: HydroFeedbackGeneration::Gen5WaterScopedVoltageAndJigCutoff,
        pic_sensors: PIC_SENSORS_HHB56_68_70,
    },
];

/// Why a hydro tuple lookup / admission refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HydroProfileError {
    /// The board name is not in the held inventory (or empty). Nothing is
    /// inferred from a near-miss or from a marketing name.
    UnknownBoardName,
    /// The same physical chain was reported twice.
    DuplicateChain,
    /// Chain index outside the profile's `chains_per_unit`.
    ChainOutOfRange,
    /// No populated chain was observed.
    EmptyUnit,
    /// A populated chain's observed population is not the exact held
    /// per-chain count.
    PopulationMismatch {
        chain: u8,
        observed: u16,
        expected: u16,
    },
    /// The controller evidence does not match the held ZYNQ7007 law.
    ControllerMismatch,
    /// The presented PSU evidence does not match the held power block.
    PsuMismatch,
    /// The presented cooling-medium declaration is not the hydro external
    /// loop (an air declaration can never admit a hydro runtime profile).
    CoolingMediumMismatch,
}

impl core::fmt::Display for HydroProfileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HydroProfileError::UnknownBoardName => write!(f, "board name has no held hydro tuple"),
            HydroProfileError::DuplicateChain => write!(f, "duplicate chain in admission"),
            HydroProfileError::ChainOutOfRange => write!(f, "chain index out of range"),
            HydroProfileError::EmptyUnit => write!(f, "no populated chain"),
            HydroProfileError::PopulationMismatch { chain, observed, expected } => write!(
                f,
                "chain {chain} population {observed} != held exact {expected}"
            ),
            HydroProfileError::ControllerMismatch => {
                write!(f, "controller evidence is not the held ZYNQ7007 hydro control board")
            }
            HydroProfileError::PsuMismatch => write!(
                f,
                "PSU evidence does not match the held topol.conf power block"
            ),
            HydroProfileError::CoolingMediumMismatch => {
                write!(f, "declared cooling medium is not the hydro external loop")
            }
        }
    }
}

impl std::error::Error for HydroProfileError {}

/// The S9 Hydro posture: held config bytes only, no water law, no runtime
/// tuple. Enumerated so the inventory is explicit about what is NOT
/// implementable (the lane refusal is a typed value, not a silence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9HydroConfigOnly {
    /// `etc/config/Config.ini` `AsicType=1387`.
    pub config_asic_type: u16,
    /// `AsicNum=63` (factory test config; not a runtime population claim).
    pub config_asic_num: u16,
    /// `CoreNum=114`.
    pub config_core_num: u16,
}

/// The held S9 Hydro 2019 config-only tuple (`s9-hydro-xilinx-20190920`
/// rootfs `etc/config/Config.ini`). No miner ELF, no topol.conf, no water
/// strings are held for this model — therefore NO runtime profile exists
/// and feedback authority is Unproven.
pub const S9_HYDRO_CONFIG_ONLY: S9HydroConfigOnly = S9HydroConfigOnly {
    config_asic_type: 1387,
    config_asic_num: 63,
    config_core_num: 114,
};

/// Exact profile for a decoded board (`machine`) name; `None` otherwise.
/// Air-cooled board families (BHB42/56/68xxx, A3HB…), the immersion-only
/// VNish names without held bytes (IHB68601, M1HB70601/02, H1HB68601,
/// H1HB70602), and near-miss hydro names all refuse here.
pub fn hydro_board_for_name(name: &str) -> Option<&'static HydroBoard> {
    HYDRO_BOARDS.iter().find(|board| board.board_name == name)
}

impl HydroBoard {
    /// Domain-times-chip consistency: `domains_per_chain * chips_per_domain
    /// == chips_per_chain` for every held entry (compile-checked by test).
    pub const fn domains_times_chips(&self) -> u16 {
        self.domains_per_chain * self.chips_per_domain as u16
    }

    /// Exact full-unit ASIC count: chains x chips-per-chain.
    pub const fn chips_per_unit(&self) -> u32 {
        self.chips_per_chain as u32 * self.chains_per_unit as u32
    }

    /// Post-assignment address plan for one chain at the held interval.
    pub fn address_plan(&self) -> Vec<u8> {
        (0..self.chips_per_chain)
            .map(|position| (position as u16 * self.asic.address_interval as u16) as u8)
            .collect()
    }

    /// Chip position for a decoded chip address, iff inside the held
    /// interval plan; `None` otherwise (never fabricated).
    pub fn chip_position(&self, decoded_chip_address: u8) -> Option<usize> {
        let interval = self.asic.address_interval as u8;
        if decoded_chip_address % interval == 0 {
            let position = (decoded_chip_address / interval) as usize;
            if position < self.chips_per_chain as usize {
                return Some(position);
            }
        }
        None
    }

    /// The PSU control addresses every held hydro power block shares.
    pub const fn psu_i2c_addr(&self) -> u8 {
        HYDRO_PSU_I2C_ADDR
    }

    pub const fn psu_enable_gpio(&self) -> u32 {
        HYDRO_PSU_ENABLE_GPIO
    }

    pub const fn pic_i2c_addr(&self) -> u8 {
        HYDRO_PIC1704_I2C_ADDR
    }

    pub const fn eeprom_i2c_addr(&self) -> u8 {
        HYDRO_EEPROM_I2C_ADDR
    }

    /// Hydro rows are excluded from beta kits (agent_tasks R15): runtime
    /// profiles only, no install / registration claim. Always `false` —
    /// promotion is a deliberate F02/B01 decision, never a default.
    pub const fn install_kit_eligible(&self) -> bool {
        false
    }
}

/// One chain's fresh full population observation for admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HydroChainPopulation {
    /// Physical chain slot `0..chains_per_unit`.
    pub chain: u8,
    /// Freshly observed unassigned-zero address-window population.
    pub observed_chips: u16,
}

/// An admitted hydro unit: exact per-chain populations against one held
/// profile. Physical subsets (fewer populated chains than the full unit)
/// are admissible — identity never requires every slot — but EVERY
/// populated chain must report the exact held count; wrong / duplicate /
/// empty refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedHydroUnit {
    pub board: &'static HydroBoard,
    /// Populated chain slots, in admission order.
    pub populated_chains: Vec<u8>,
}

/// Admit a fresh unit population against one exact held hydro profile.
pub fn admit_hydro_unit_population(
    board: &'static HydroBoard,
    populations: &[HydroChainPopulation],
) -> Result<AdmittedHydroUnit, HydroProfileError> {
    if populations.is_empty() {
        return Err(HydroProfileError::EmptyUnit);
    }
    let mut populated_chains = Vec::with_capacity(usize::from(board.chains_per_unit));
    for population in populations {
        if population.chain >= board.chains_per_unit {
            return Err(HydroProfileError::ChainOutOfRange);
        }
        if populated_chains.contains(&population.chain) {
            return Err(HydroProfileError::DuplicateChain);
        }
        if population.observed_chips != board.chips_per_chain {
            return Err(HydroProfileError::PopulationMismatch {
                chain: population.chain,
                observed: population.observed_chips,
                expected: board.chips_per_chain,
            });
        }
        populated_chains.push(population.chain);
    }
    Ok(AdmittedHydroUnit { board, populated_chains })
}

/// Stricter full-unit manifest: exactly all `chains_per_unit` chains, each
/// at the exact held count.
pub fn admit_hydro_full_unit_population(
    board: &'static HydroBoard,
    populations: &[HydroChainPopulation],
) -> Result<AdmittedHydroUnit, HydroProfileError> {
    let unit = admit_hydro_unit_population(board, populations)?;
    if unit.populated_chains.len() != usize::from(board.chains_per_unit) {
        return Err(HydroProfileError::EmptyUnit);
    }
    Ok(unit)
}

// ---------------------------------------------------------------------------
// Transport + startup scope (Deliverable 2): evidence-scoped admission that
// every exact transport fact is HELD before a hydro runtime may plan
// anything. Pure: this composes evidence *declarations*; it performs no I/O
// and grants no electrical authority. A real runtime consumes the admission
// as a precondition, exactly as the R13/R14 profiles do.
// ---------------------------------------------------------------------------

/// Controller evidence declaration (what the runtime independently
/// resolved before asking for admission).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HydroControllerEvidence {
    /// Held law: byte-identical `xlnx,zynq-7000` devicetree + topol.conf
    /// `"processor": {"type": "ZYNQ7007"}` on every held generation.
    Zynq7007,
    /// Anything else (AML, CV183x, unknown) — the held hydro bytes prove
    /// nothing about those controllers. (The S19 XP Hydro CVCtrl variant
    /// IS held as a CVITEK/Sophon CV183x merge record, but its full
    /// rootfs is not held, so no transport profile exists for it.)
    OtherOrUnproven,
}

/// PSU evidence declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HydroPsuEvidence {
    /// The PSU version/identity observed at the held power I²C address
    /// matches the profile's held family.
    MatchesHeldFamily(HydroPsuFamily),
    /// Nothing held was observed (or the family disagrees).
    Unproven,
}

/// Cooling declaration (must be the declared external loop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HydroCoolingDeclaration {
    /// Explicitly declared hydro external loop.
    Hydro,
    /// Explicitly declared immersion. The held transport tuples are hydro
    /// boards; an immersion declaration names a board family with NO held
    /// stock bytes, so it cannot select a transport tuple — it refuses at
    /// name resolution already. Carried for explicit refusal messaging.
    Immersion,
    /// Undeclared / air. Never admits.
    UndeclaredOrAir,
}

/// Feedback authority declaration (joins `hydro_cooling_feedback`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HydroFeedbackAuthority {
    /// The cooling monitor is bound to the sensor path the held bytes pin
    /// for this generation and passes the composed permit law.
    HeldStockLaw,
    /// Monitor absent, sensor path unverified, or law generation
    /// unproven. Fail closed: no startup, no work.
    Unproven,
}

/// What a refused startup admission found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HydroStartupRefusal {
    ProfileUnknown,
    PopulationAdmission(HydroProfileError),
    ControllerMismatch,
    PsuUnproven,
    CoolingNotDeclaredHydro,
    FeedbackAuthorityUnproven,
}

/// The exact transport facts admission locks in for a hydro session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydroTransportFacts {
    pub board: &'static HydroBoard,
    pub control_processor: &'static str,
    pub psu_i2c_addr: u8,
    pub psu_enable_gpio: u32,
    pub pic_i2c_addr: u8,
    pub eeprom_i2c_addr: u8,
    pub address_interval: u8,
    pub address_plan: Vec<u8>,
    pub feedback_generation: HydroFeedbackGeneration,
}

/// Compose the exact transport + startup admission for one hydro tuple.
/// Every input must be held-evidence-backed; any Unproven input refuses
/// BEFORE any work is planned (fail closed, stricter than stock where
/// stock is silent). The returned facts are the ONLY transport scope a
/// hydro runtime may use; there is no default and no air-profile
/// inheritance.
pub fn admit_hydro_transport_and_startup(
    board_name: &str,
    populations: &[HydroChainPopulation],
    controller: HydroControllerEvidence,
    psu: HydroPsuEvidence,
    cooling: HydroCoolingDeclaration,
    feedback: HydroFeedbackAuthority,
) -> Result<HydroTransportFacts, HydroStartupRefusal> {
    let board = hydro_board_for_name(board_name).ok_or(HydroStartupRefusal::ProfileUnknown)?;
    admit_hydro_unit_population(board, populations)
        .map_err(HydroStartupRefusal::PopulationAdmission)?;
    if controller != HydroControllerEvidence::Zynq7007 {
        return Err(HydroStartupRefusal::ControllerMismatch);
    }
    if psu != HydroPsuEvidence::MatchesHeldFamily(board.psu) {
        return Err(HydroStartupRefusal::PsuUnproven);
    }
    if cooling != HydroCoolingDeclaration::Hydro {
        return Err(HydroStartupRefusal::CoolingNotDeclaredHydro);
    }
    if feedback != HydroFeedbackAuthority::HeldStockLaw {
        return Err(HydroStartupRefusal::FeedbackAuthorityUnproven);
    }
    Ok(HydroTransportFacts {
        board,
        control_processor: HYDRO_CONTROL_PROCESSOR,
        psu_i2c_addr: board.psu_i2c_addr(),
        psu_enable_gpio: board.psu_enable_gpio(),
        pic_i2c_addr: board.pic_i2c_addr(),
        eeprom_i2c_addr: board.eeprom_i2c_addr(),
        address_interval: board.asic.address_interval,
        address_plan: board.address_plan(),
        feedback_generation: board.feedback_generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_is_complete_and_consistent_per_held_topol_conf() {
        // 27 machine entries across the eight held topol.conf files:
        // 2 (HHB28) + 6 (HHB42) + 8 (HHB56) + 7 (HHB68) + 4 (HHB70).
        assert_eq!(HYDRO_BOARDS.len(), 27);
        // Every entry is internally consistent with its held JSON.
        for board in HYDRO_BOARDS {
            assert_eq!(
                board.domains_times_chips(),
                board.chips_per_chain,
                "{}: domains x chips must equal held chain_asic_num",
                board.board_name
            );
            assert_eq!(board.psu_i2c_addr(), 16);
            assert_eq!(board.psu_enable_gpio(), 907);
            assert_eq!(board.pic_i2c_addr(), 32);
            assert_eq!(board.eeprom_i2c_addr(), 80);
            assert!(!board.install_kit_eligible());
        }
        // Name lookups are exact and unique. Identity is asserted by value:
        // HYDRO_BOARDS is a const, so each mention is a fresh inlined array
        // and cross-site pointer equality would be meaningless.
        for board in HYDRO_BOARDS {
            assert_eq!(
                hydro_board_for_name(board.board_name).unwrap().board_name,
                board.board_name,
                "{} lookup must return itself",
                board.board_name
            );
        }
        // Generation ordering by held image is exact.
        let by_name = |n: &str| hydro_board_for_name(n).unwrap();
        assert_eq!(by_name("HHB28601").feedback_generation, HydroFeedbackGeneration::Gen1PicTempMinOnly);
        assert_eq!(by_name("HHB28602").feedback_generation, HydroFeedbackGeneration::Gen1PicTempMinOnly);
        assert_eq!(by_name("HHB42602").feedback_generation, HydroFeedbackGeneration::Gen2WaterPermitGate);
        assert_eq!(by_name("HHB56702").feedback_generation, HydroFeedbackGeneration::Gen3WaterInTempField);
        assert_eq!(by_name("HHB68501").feedback_generation, HydroFeedbackGeneration::Gen4InletOutletAndReverse);
        assert_eq!(by_name("H6HB70501").feedback_generation, HydroFeedbackGeneration::Gen5WaterScopedVoltageAndJigCutoff);
    }

    #[test]
    fn exact_asic_psu_and_geometry_pins_per_generation() {
        let by_name = |n: &str| hydro_board_for_name(n).unwrap();

        // HHB28: BM1398P, interval 2, 4x104, AWP11 (stock spelling), 2 PIC sensors.
        let s19_hydro = by_name("HHB28601");
        assert_eq!(s19_hydro.asic, BM1398P);
        assert_eq!(s19_hydro.chains_per_unit, 4);
        assert_eq!(s19_hydro.chips_per_chain, 104);
        assert_eq!(s19_hydro.chips_per_unit(), 416);
        assert_eq!(s19_hydro.psu, HydroPsuFamily::Apw11StockSpellingAwp11);
        assert_eq!(s19_hydro.psu.stock_type_string(), "AWP11");
        assert_eq!(s19_hydro.power_target_w, None);
        assert_eq!(s19_hydro.pic_sensors.len(), 2);
        assert_eq!(s19_hydro.pic_sensors[0].i2c_addr, 72);
        assert_eq!(s19_hydro.pic_sensors[1].i2c_addr, 73);
        // T19 Hydro is the sibling machine entry in its own held image.
        let t19_hydro = by_name("HHB28602");
        assert_eq!(t19_hydro.asic, BM1398P);
        assert_eq!(t19_hydro.held_image, "t19-hydro-20221212");

        // HHB42: BM1362, interval 1, 4x180, AWP11 (3 boards) vs AWP8
        // (HHB42701/HHB42711/TH401 — no power_target), 4 PIC sensors
        // incl. TMP451 @0x4C.
        let pro = by_name("HHB42602");
        assert_eq!(pro.asic, BM1362);
        assert_eq!(pro.chains_per_unit, 4);
        assert_eq!(pro.chips_per_chain, 180);
        assert_eq!(pro.chips_per_unit(), 720);
        assert_eq!(pro.psu, HydroPsuFamily::Apw11StockSpellingAwp11);
        assert_eq!(pro.power_target_w, Some(5600));
        assert_eq!(pro.pic_sensors.len(), 4);
        assert_eq!(pro.pic_sensors[3].stock_type, "TMP451");
        assert_eq!(pro.pic_sensors[3].i2c_addr, 76);
        for awp8_name in ["HHB42701", "HHB42711", "TH401"] {
            let board = by_name(awp8_name);
            assert_eq!(board.psu, HydroPsuFamily::Apw8StockSpellingAwp8);
            assert_eq!(board.power_target_w, None, "{awp8_name} carries no power_target");
        }

        // HHB56: BM1366, 3x204, APW11, HHB56701 is the 4700 W bin.
        let xp = by_name("HHB56601");
        assert_eq!(xp.asic, BM1366);
        assert_eq!(xp.chains_per_unit, 3);
        assert_eq!(xp.chips_per_chain, 204);
        assert_eq!(xp.chips_per_unit(), 612);
        assert_eq!(xp.psu, HydroPsuFamily::Apw11);
        assert_eq!(xp.psu.stock_type_string(), "APW11");
        assert_eq!(by_name("HHB56701").power_target_w, Some(4700));
        assert_eq!(by_name("H1HB56703").power_target_w, Some(5400));

        // HHB68: BM1368, 3x216 except HHB68701 at 3x180.
        let s21 = by_name("HHB68501");
        assert_eq!(s21.asic, BM1368);
        assert_eq!(s21.chips_per_chain, 216);
        assert_eq!(s21.chips_per_unit(), 648);
        let xp_plus = by_name("HHB68701");
        assert_eq!(xp_plus.chips_per_chain, 180);
        assert_eq!(xp_plus.chips_per_unit(), 540);
        for name in ["HHB68501", "HHB68502", "HHB68503", "HHB68504"] {
            assert_eq!(by_name(name).chips_per_chain, 216, "{name}");
        }

        // HHB70: BM1370, 3x160, 20 domains x 8.
        let s21_xp = by_name("H6HB70501");
        assert_eq!(s21_xp.asic, BM1370);
        assert_eq!(s21_xp.chains_per_unit, 3);
        assert_eq!(s21_xp.chips_per_chain, 160);
        assert_eq!(s21_xp.domains_per_chain, 20);
        assert_eq!(s21_xp.chips_per_domain, 8);
        assert_eq!(s21_xp.chips_per_unit(), 480);
    }

    #[test]
    fn unknown_near_miss_and_other_family_names_refuse() {
        // Near-miss hydro names.
        for name in [
            "HHB28603", "HHB42603", "HHB56602", "HHB68505", "HHB68603", "HHB68702",
            "H6HB70502", "H1HB70602", "TH402", "hhb56601", "HHB5660", "",
        ] {
            assert!(
                hydro_board_for_name(name).is_none(),
                "{name:?} must not select a hydro profile"
            );
        }
        // Air-cooled board families never select a hydro tuple.
        for name in ["BHB42601", "BHB56902", "BHB68606", "BHB68703", "A3HB70501"] {
            assert!(hydro_board_for_name(name).is_none(), "{name:?} is an air board");
        }
        // Immersion-only VNish names without held stock bytes refuse.
        for name in ["IHB68601", "M1HB70601", "M1HB70602", "H1HB68601", "H1HB70602"] {
            assert!(
                hydro_board_for_name(name).is_none(),
                "{name:?} has no held stock bytes"
            );
        }
    }

    #[test]
    fn address_plans_follow_held_interval_and_chip_credit_never_fabricates() {
        // Interval 2 (BM1398P HHB28): 0, 2, .., 206.
        let s19_hydro = hydro_board_for_name("HHB28601").unwrap();
        let plan = s19_hydro.address_plan();
        assert_eq!(plan.len(), 104);
        assert_eq!(plan[0], 0);
        assert_eq!(plan[1], 2);
        assert_eq!(plan[103], 206);
        assert_eq!(s19_hydro.chip_position(0), Some(0));
        assert_eq!(s19_hydro.chip_position(206), Some(103));
        assert_eq!(s19_hydro.chip_position(1), None);
        assert_eq!(s19_hydro.chip_position(208), None);

        // Interval 1 (BM1366 HHB56): 0..=203.
        let xp = hydro_board_for_name("HHB56601").unwrap();
        let plan = xp.address_plan();
        assert_eq!(plan.len(), 204);
        assert_eq!(plan[203], 203);
        assert_eq!(xp.chip_position(203), Some(203));
        assert_eq!(xp.chip_position(204), None);
    }

    #[test]
    fn population_admission_refuses_wrong_duplicate_empty_and_subset_is_allowed() {
        let board = hydro_board_for_name("HHB56601").unwrap();
        let full: Vec<HydroChainPopulation> = (0..3)
            .map(|chain| HydroChainPopulation { chain, observed_chips: 204 })
            .collect();
        admit_hydro_full_unit_population(board, &full).expect("exact full unit");

        // Off-by-one refuses on every slot, both directions.
        for drifted in [203u16, 205] {
            assert_eq!(
                admit_hydro_unit_population(
                    board,
                    &[HydroChainPopulation { chain: 1, observed_chips: drifted }]
                ),
                Err(HydroProfileError::PopulationMismatch {
                    chain: 1,
                    observed: drifted,
                    expected: 204,
                })
            );
        }
        // Duplicate / out-of-range / empty refuse.
        assert_eq!(
            admit_hydro_unit_population(
                board,
                &[
                    HydroChainPopulation { chain: 0, observed_chips: 204 },
                    HydroChainPopulation { chain: 0, observed_chips: 204 },
                ]
            ),
            Err(HydroProfileError::DuplicateChain)
        );
        assert_eq!(
            admit_hydro_unit_population(
                board,
                &[HydroChainPopulation { chain: 3, observed_chips: 204 }]
            ),
            Err(HydroProfileError::ChainOutOfRange)
        );
        assert_eq!(
            admit_hydro_unit_population(board, &[]),
            Err(HydroProfileError::EmptyUnit)
        );
        // Full-unit manifest refuses a missing chain.
        let two: Vec<HydroChainPopulation> = full.iter().take(2).copied().collect();
        assert_eq!(
            admit_hydro_full_unit_population(board, &two),
            Err(HydroProfileError::EmptyUnit)
        );
        // Subset (two populated chains) stays admissible outside the
        // full-unit manifest.
        admit_hydro_unit_population(board, &two).expect("physical subset");
    }

    #[test]
    fn transport_startup_admission_is_exact_and_fail_closed() {
        let pops = vec![HydroChainPopulation { chain: 1, observed_chips: 216 }];

        // The exact held-evidence composition admits and locks the facts.
        let facts = admit_hydro_transport_and_startup(
            "HHB68501",
            &pops,
            HydroControllerEvidence::Zynq7007,
            HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw11),
            HydroCoolingDeclaration::Hydro,
            HydroFeedbackAuthority::HeldStockLaw,
        )
        .expect("held-evidence composition");
        assert_eq!(facts.control_processor, "ZYNQ7007");
        assert_eq!(facts.psu_i2c_addr, 0x10);
        assert_eq!(facts.psu_enable_gpio, 907);
        assert_eq!(facts.pic_i2c_addr, 0x20);
        assert_eq!(facts.eeprom_i2c_addr, 0x50);
        assert_eq!(facts.address_interval, 1);
        assert_eq!(facts.address_plan.len(), 216);
        assert_eq!(
            facts.feedback_generation,
            HydroFeedbackGeneration::Gen4InletOutletAndReverse
        );
        assert_eq!(facts.board.held_image, "s21-hydro-20240519");

        // Unknown board refuses first.
        assert_eq!(
            admit_hydro_transport_and_startup(
                "BHB68606",
                &pops,
                HydroControllerEvidence::Zynq7007,
                HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw11),
                HydroCoolingDeclaration::Hydro,
                HydroFeedbackAuthority::HeldStockLaw,
            ),
            Err(HydroStartupRefusal::ProfileUnknown)
        );
        // Bad population refuses.
        assert!(matches!(
            admit_hydro_transport_and_startup(
                "HHB68501",
                &[HydroChainPopulation { chain: 1, observed_chips: 215 }],
                HydroControllerEvidence::Zynq7007,
                HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw11),
                HydroCoolingDeclaration::Hydro,
                HydroFeedbackAuthority::HeldStockLaw,
            ),
            Err(HydroStartupRefusal::PopulationAdmission(
                HydroProfileError::PopulationMismatch { .. }
            ))
        ));
        // Non-Zynq controller evidence refuses (no AML/CV hydro transport
        // tuple is held).
        assert_eq!(
            admit_hydro_transport_and_startup(
                "HHB68501",
                &pops,
                HydroControllerEvidence::OtherOrUnproven,
                HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw11),
                HydroCoolingDeclaration::Hydro,
                HydroFeedbackAuthority::HeldStockLaw,
            ),
            Err(HydroStartupRefusal::ControllerMismatch)
        );
        // PSU evidence unproven OR wrong family refuses (never inferred).
        assert_eq!(
            admit_hydro_transport_and_startup(
                "HHB68501",
                &pops,
                HydroControllerEvidence::Zynq7007,
                HydroPsuEvidence::Unproven,
                HydroCoolingDeclaration::Hydro,
                HydroFeedbackAuthority::HeldStockLaw,
            ),
            Err(HydroStartupRefusal::PsuUnproven)
        );
        assert_eq!(
            admit_hydro_transport_and_startup(
                "HHB68501",
                &pops,
                HydroControllerEvidence::Zynq7007,
                HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw8StockSpellingAwp8),
                HydroCoolingDeclaration::Hydro,
                HydroFeedbackAuthority::HeldStockLaw,
            ),
            Err(HydroStartupRefusal::PsuUnproven)
        );
        // Cooling must be the DECLARED hydro loop — air and undeclared
        // refuse, and an air inheritance is impossible.
        for cooling in [HydroCoolingDeclaration::UndeclaredOrAir, HydroCoolingDeclaration::Immersion] {
            assert_eq!(
                admit_hydro_transport_and_startup(
                    "HHB68501",
                    &pops,
                    HydroControllerEvidence::Zynq7007,
                    HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw11),
                    cooling,
                    HydroFeedbackAuthority::HeldStockLaw,
                ),
                Err(HydroStartupRefusal::CoolingNotDeclaredHydro)
            );
        }
        // Unproven feedback authority refuses (fail closed).
        assert_eq!(
            admit_hydro_transport_and_startup(
                "HHB68501",
                &pops,
                HydroControllerEvidence::Zynq7007,
                HydroPsuEvidence::MatchesHeldFamily(HydroPsuFamily::Apw11),
                HydroCoolingDeclaration::Hydro,
                HydroFeedbackAuthority::Unproven,
            ),
            Err(HydroStartupRefusal::FeedbackAuthorityUnproven)
        );
    }

    #[test]
    fn psu_family_strings_are_carried_verbatim_never_normalized() {
        assert_eq!(HydroPsuFamily::Apw11.stock_type_string(), "APW11");
        assert_eq!(HydroPsuFamily::Apw11StockSpellingAwp11.stock_type_string(), "AWP11");
        assert_eq!(HydroPsuFamily::Apw8StockSpellingAwp8.stock_type_string(), "AWP8");
        // The stock typo is a distinct value from the corrected name.
        assert_ne!(
            HydroPsuFamily::Apw11,
            HydroPsuFamily::Apw11StockSpellingAwp11
        );
    }

    #[test]
    fn s9_hydro_is_config_only_and_feedback_unproven() {
        assert_eq!(S9_HYDRO_CONFIG_ONLY.config_asic_type, 1387);
        assert_eq!(S9_HYDRO_CONFIG_ONLY.config_asic_num, 63);
        assert_eq!(S9_HYDRO_CONFIG_ONLY.config_core_num, 114);
        // No runtime tuple: the 2019 S9 Hydro has no topol.conf profile.
        assert!(hydro_board_for_name("S9 Hydro").is_none());
        assert!(hydro_board_for_name("HB28600").is_none());
    }

    #[test]
    fn hydro_profiles_declare_the_external_loop_medium() {
        // Every profile here is the hydro medium (external loop, no fan
        // actuator) — the declaration feeding cooling_medium's ladder law.
        assert_eq!(HYDRO_COOLING_MEDIUM, CoolingMedium::Hydro);
        assert!(!HYDRO_COOLING_MEDIUM.has_fan_actuator());
        assert_eq!(
            HYDRO_COOLING_MEDIUM.cooling_class(),
            crate::cooling_medium::CoolingClass::ExternalLoop
        );
    }
}
