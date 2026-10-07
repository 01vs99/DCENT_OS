//! Board configuration and model detection for DCENT_axe hardware variants.
//!
//! Supports both BitAxe and Nerd-family boards. Each board has different ASIC
//! chips, pin mappings, voltage ranges, power IC configurations, and peripherals.
//! This module centralizes all board-specific parameters so the rest of the HAL
//! can be board-agnostic.
//!
//! Pin families are selected at compile time via Cargo features:
//! - `pins-bitaxe`: I2C SDA=47, SCL=48; UART TX=17, RX=18 (all BitAxe boards)
//! - `pins-nerd`:   I2C SDA=18, SCL=17; UART TX=43, RX=44 (Nerd-family / TTGO T-Display S3)
//! - `pins-hammer-bc`: I2C SDA=44, SCL=43; UART selected per Hammer BC SKU
//! - `pins-hammer-dc`: I2C SDA=44, SCL=43; UART selected per Hammer DC SKU

// Compile-time safety: exactly one pin family must be selected
#[cfg(any(
    all(feature = "pins-bitaxe", feature = "pins-nerd"),
    all(feature = "pins-bitaxe", feature = "pins-hammer-bc"),
    all(feature = "pins-bitaxe", feature = "pins-hammer-dc"),
    all(feature = "pins-nerd", feature = "pins-hammer-bc"),
    all(feature = "pins-nerd", feature = "pins-hammer-dc"),
    all(feature = "pins-hammer-bc", feature = "pins-hammer-dc"),
))]
compile_error!(
    "Pin families are mutually exclusive — select exactly one of pins-bitaxe, \
     pins-nerd, pins-hammer-bc, or pins-hammer-dc"
);

#[cfg(not(any(
    feature = "pins-bitaxe",
    feature = "pins-nerd",
    feature = "pins-hammer-bc",
    feature = "pins-hammer-dc",
)))]
compile_error!("No board selected — use --features bitaxe-gamma (or nerdnos, nerdaxe, etc)");

#[cfg(all(feature = "display-ssd1306", feature = "display-none"))]
compile_error!("Display families are mutually exclusive — select one display feature");

use crate::ntc_convert::NtcChannel;
use crate::tmp451_convert::Calibration as Tmp451Calibration;
use dcentaxe_asic::common::PowAlgorithm;
use log::{info, warn};
use serde::{Deserialize, Serialize};

/// Supported board models across BitAxe and Nerd families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitAxeModel {
    // ── BitAxe family ──
    /// BitAxe Max — BM1397 (S17-era chip), single ASIC
    Max,
    /// BitAxe Ultra — BM1366 (S19XP-era chip), single ASIC
    Ultra,
    /// BitAxe Hex Ultra — 6x BM1366
    HexUltra,
    /// BitAxe Supra — BM1368 (S21-era chip), single ASIC
    Supra,
    /// BitAxe Hex Supra — 6x BM1368
    HexSupra,
    /// BitAxe Gamma — BM1370 (S21 Pro chip), single ASIC
    Gamma,
    /// BitAxe Gamma Duo — 2x BM1370XP, 5V input
    GammaDuo,
    /// BitAxe Gamma Turbo — 2x BM1370, 12V input
    GammaTurbo,
    /// BitAxe Touch — single BM1370 + separate ESP32-S3 LVGL accessory
    /// over BAP (UART_NUM_2). Same mining board as Gamma; differs only in
    /// the populated BAP header + preinstalled Touch-aware self-test path.
    Touch,
    /// BitAxe Turbo Touch — GT-801 mining board (2× BM1370) + the same
    /// LVGL accessory over BAP. Electrically identical to GammaTurbo; the
    /// variant exists so the dashboard, `board_target`, and self-test flow
    /// know to advertise Touch-aware behaviour.
    GtTouch,

    // ── Nerd family ──
    /// NerdNOS — BM1397, headless, USB-C 5V ~8W, fixed voltage, no fan
    NerdNOS,
    /// NerdAxe — **BM1366**, T-Display S3, **DS4432U + TPS40305**, EMC2101,
    /// INA260. Single ASIC.
    ///
    /// ⚠ Its enable GPIO is **INVERTED**. Upstream `nerdaxe.cpp` defines
    /// `PWR_EN_PIN = GPIO_NUM_10` and comments it "// inverted" twice:
    /// `initBoard` drives **1** to leave the rail off, `setVoltage(0.0)` drives
    /// **1**, and only a real setpoint drives **0**. This board is therefore
    /// ACTIVE-LOW, unlike every other Nerd board, whose `TPS53647_EN_PIN` on the
    /// same GPIO10 is active-HIGH. See [`BitAxeModel::buck_enable_wiring`] — the
    /// polarity reaches the panic hook, so getting it backwards would energize
    /// the rail on a firmware panic instead of cutting it.
    ///
    /// This row was previously described as BM1370 + TPS546 borrowing BitAxe
    /// profile "601"; that is [`Self::NerdAxeGamma`], not this board.
    NerdAxe,
    /// NerdAxe-γ — BM1370, T-Display S3, **TPS546 PMBus**, EMC2101 external
    /// diode. Single ASIC.
    ///
    /// Derives from `NerdAxe` upstream but overrides `initBoard`, `setVoltage`
    /// and `getTemperature`, so it shares almost no hardware with its parent:
    /// different ASIC, different regulator, and **no enable GPIO at all** — the
    /// rail is commanded entirely over PMBus. `initBoard` configures only
    /// `BM1370_RST_PIN`; `PWR_EN_PIN` is never selected, never made an output,
    /// and never driven.
    ///
    /// Electrically this is the BitAxe Gamma "601" shape (EMC2101 external diode
    /// at ideality `0x24` / beta `0x00`, TPS546 rail), which is exactly why the
    /// old mislabelled `NerdAxe` row borrowed "601" and looked plausible.
    ///
    /// Upstream sets `m_deviceModel = "NerdAxeGamma"` but leaves
    /// `m_miningAgent = "NerdAxe"`, so an inbound mining-agent string CANNOT
    /// distinguish the two boards. Identity has to come from the device model.
    NerdAxeGamma,
    /// NerdQaxe+ — 4x BM1368, TTGO T-Display S3, TPS53647 2-phase
    NerdQaxePlus,
    /// NerdQaxe++ — 4x BM1370, TTGO T-Display S3, TPS53647 3-phase
    NerdQaxePP,
    /// NerdOCTAXE+ — 8x BM1368, TPS53647 3-phase, ~5 TH/s at ~100 W.
    ///
    /// An 8-ASIC single-UART daisy chain (address interval `256/8 = 32`).
    /// Upstream describes it as "a 8-Asic version of the NerdQAxe+" and its
    /// board class literally inherits `NerdQaxePlus`, so it shares the BM1368
    /// driver and the 12 V input envelope but NOT the phase/current limits.
    NerdOctaxePlus,
    /// NerdOCTAXE-γ — 8x BM1370, multi-phase, hardware-revision dependent VRM.
    ///
    /// ⚠ This board ships with **two different power stages** under one name:
    /// rev ≤3.3 carries a 4-phase TPS53647 (180 A, ~250 W) and rev 3.4 carries a
    /// 6-phase TPS53667 (240 A, ~300 W). Upstream selects between them at
    /// runtime by reading a strap on GPIO3 and then raises the frequency and
    /// voltage tables for the 6-phase part. Our row therefore declares only the
    /// **conservative 4-phase envelope**; the part is identified from its device
    /// code at bring-up and a mismatch is refused rather than assumed.
    NerdOctaxeGamma,
    /// NerdQX — 4x BM1370, 3-phase TPS53647, ~240 W. The high-frequency member
    /// of the NerdQAxe++ line: 777 MHz default against the '++'s 600, and a
    /// 1250 MHz / 1375 mV ceiling reached only when the board proves itself.
    ///
    /// 🔴 UPSTREAM SETS AN OVER-CURRENT TRIP THAT CANNOT ASSERT. Its own
    /// obfuscated `decode_m_ifault(3)` yields **142 A against a 90 A `imax`** —
    /// and `imax` is the current-sense FULL SCALE (`MFR_SPECIFIC_10`) that the
    /// comparator measures against, so a 142 A threshold is armed on paper and
    /// inert in silicon. Every other Nerd board sits within ±5 A of its `imax`.
    /// We declare 85 A and [`tps5364x_convert::check_iout_fault_limit`] refuses
    /// the upstream value outright.
    ///
    /// ⚠ Its TMP451 mux IS its identity check: upstream probes the mux on
    /// GPIO2/GPIO3 at 0x4C and, when absent, concludes "not a QX" and clamps to
    /// 1150 mV / 495 MHz. Our row declares the CLAMPED envelope for exactly that
    /// reason — the high ceiling is a reward for a positive probe, never an
    /// assumption.
    NerdQX,
    /// NerdHaxe-γ — 6x BM1370, 4-phase TPS53647 (120 A), ~250 W. Inherits the
    /// NerdQAxe++ frequency/voltage tables unchanged; only the chip count, phase
    /// count and power envelope differ.
    NerdHaxeGamma,
    /// NerdEKO — 12x BM1370, 6-phase **TPS53667** (240 A), ~350 W.
    ///
    /// The largest board in the registry by chip count, and the first to need a
    /// TPS53667 by declaration rather than by runtime revision detection: the
    /// NerdOCTAXE-γ may carry either part, but NerdEKO's board class constructs
    /// one explicitly (`m_tps = new TPS53667()`). Both parts answer at 0x71 and
    /// are told apart only by device code, so the row still declares the family
    /// and `Tps5364x::identify` does the discriminating.
    ///
    /// 12 chips in one UART daisy chain: address interval `256/12 = 21`,
    /// addresses 0..231. It is the board that raises
    /// `LARGEST_SUPPORTED_ASIC_COUNT` from 9 to 12.
    NerdEko,

    // ── Q-series (OSMU third-party, FXL6408 port-expander topology) ──
    /// Q1370 — 4x BM1370, 4-phase TPS53647 (123 A), ~150 W.
    ///
    /// 🔑 THE FIRST BOARD WHOSE POWER SEQUENCING IS NOT ON ESP GPIOs. ASIC
    /// reset, VREG enable and LDO enable all run through an **FXL6408 I2C port
    /// expander at 0x43** (pins 0, 1, 2), with the TMP451 mux selects on
    /// expander pins 3/4 and the CAN slave-detect strap on pin 5. A board whose
    /// safety-critical enables live behind an I2C transaction has a failure mode
    /// a GPIO does not: a bus error means the enable never moved and the caller
    /// must be told, never assume.
    Q1370,
    /// Q1373 — 4x BM1373 on the Q1370 board, ~180 W. Same FXL6408 topology and
    /// the same 123 A / 4-phase rail; what changes is the ASIC and therefore the
    /// whole envelope — 350 MHz / 1010 mV defaults against the Q1370's
    /// 600 MHz / 1150 mV, and a 900-1200 mV window instead of 1050-1400.
    ///
    /// Real BM1373 silicon reports chip id **0x1372**, not 0x1373 (proven in
    /// `BM1373_DOSSIER.md`); [`Self::expected_chip_id`] reports the silicon
    /// truth. Upstream also gives this board a TMP451 calibration of its own
    /// (`scale 1.06`, `offset -25.4`) — carried in `tmp451_convert::Calibration`
    /// as `Q1373`, never as a default.
    Q1373,

    // ── DCENT_axe family (D-Central BM1397 SKUs) ──
    /// DCENT_axe BM1397 — single BM1397 (S17-era chip), EMC2101 fan, TPS546D24A
    /// PMBus VRM (EN wired to GPIO10, ACTIVE-HIGH). There is NO DS4432U and NO
    /// INA260 on this board — verified from the dcent-axe-BM1397 schematic
    /// netlist (PREFAB_DESIGN_REVIEW_2026-07-08 R-10).
    /// D-Central's own BitAxe-Max-class single-chip board.
    DcentAxeBm1397,
    /// DCENT_axe Quad BM1397 — 4x BM1397 single UART daisy chain, EMC2302
    /// dual fan, TPS546. Same driver as the single, scaled to 4 chips.
    DcentAxeQuadBm1397,
    /// DCENT_axe Hex BM1397 — 6x BM1397 single UART daisy chain, EMC2302
    /// dual fan, TPS546, 3 series voltage domains (Hex-class topology).
    DcentAxeHexBm1397,

    // ── Hammer BC0x family (Volc/Hammer ODM, SHA-256; EXPERIMENTAL) ──
    // Registered from the 2026-07-27 Hammer RE wave
    //.
    // ⚠ IDENTITY + ENVELOPE REGISTRATION ONLY: no Hammer peripheral driver
    // (VRM address, TMP75@0x49/0x4D temp, fan path) is shipped yet, so the
    // rows below declare fan/temp/power = None and the fail-closed board
    // validation refuses mining on these models until real drivers land.
    // BC08 is deliberately NOT registered — see docs/HAMMER_BC0X_BOARDS_REPORT.md.
    /// Hammer BC01 — 1x BM1370, Wi-Fi only, USB-PD (HUSB238A) input.
    /// ASIC UART TX GPIO18 / RX GPIO17 (verified from disassembly — the
    /// OPPOSITE of BC04; pinout does not track the family).
    HammerBc01,
    /// Hammer BC01 Pro — 1x BM1373 (silicon reports chip id 0x1372), ~4 TH at
    /// 45 W. ⚠ LOWER CONFIDENCE: no firmware image held; numbers come from the
    /// vendor web-UI model table only. 1.15 V hard cap, 500 MHz vendor ceiling.
    HammerBc01Pro,
    /// Hammer BC02 — 2x BM1370 in ONE series voltage domain (rail = 2 x
    /// per-chip). ⚠ No BC02 firmware image held; series topology is the
    /// family rule (matrix §2.2) — flagged for verification before any
    /// regulator driver is enabled.
    HammerBc02,
    /// Hammer BC04 (vendor codebase `thor`) — 4x BM1370 in ONE series voltage
    /// domain: the TPS546-class regulator output is the WHOLE-STACK voltage
    /// (vendor NVS default 4800 mV = 4 x 1200 mV per chip, clamp 4000-5000).
    /// ASIC UART TX GPIO17 / RX GPIO18, reset GPIO1 (verified). GPIO15 is a
    /// shared board-power + LCD-power net — never drive it casually.
    HammerBc04,

    // ── Hammer DC0x family (Volc/Hammer ODM, **SCRYPT**; EXPERIMENTAL) ──
    // Registered from the 2026-07-27 Hammer RE wave
    // ( §7 and
    // MSBT0501_PROTOCOL.md). These are the first non-SHA-256 boards in the
    // registry: `pow_algorithm = Scrypt1024`, ASIC `MSBT0501`.
    //
    // 🔴 FOUR DISCRETE PROFILES, NEVER A PARAMETERISED FAMILY. DC02 and
    // DC04/DC06 share the SoC package and the display block and then diverge
    // violently: FIVE GPIOs (1, 2, 3, 10, 11) carry DIFFERENT FUNCTIONS on
    // DC02 vs DC04, every one an output-vs-output or output-into-driven-net
    // collision. DC02's ASIC RESET (GPIO 3) is DC04's 16 MHz SPI SCLK; DC02's
    // TPS546 PGOOD (GPIO 10) is DC04's SPI CS; DC02's fan tach (GPIO 1) is
    // DC04's ASIC RESET. A mis-selected profile is a hardware-damage path.
    //
    // 🔴 SERIES-STACKED RAIL: `rail = 0.635 V x chip_count`, proven three
    // independent ways (DC02 1270/2, DC04 2540/4, DC06 3810/6). Every voltage
    // field below is PER-ASIC and the rail is always DERIVED via
    // `voltage_domains`. DC08 is deliberately NOT registered — no image is
    // held and its per-model fields (UART polarity, reset/PGOOD GPIO, fan
    // count vs board count) are unproven.
    /// Hammer DC02 — 2x MSBT0501 in series (rail = 2 x 0.635 V = 1.27 V),
    /// 150 MH/s Scrypt. TMP75 identity strap **0x48 on bus 0**, and DC02 is
    /// the ONLY DC model with **no strap auto-rotation** — it cannot
    /// self-correct into the right identity, which is exactly why our identity
    /// gate must REFUSE on mismatch rather than guess.
    /// ASIC UART **TX 18 / RX 17** (opposite of DC04/DC06), RESET GPIO 3,
    /// PGOOD GPIO 10, TPS546 @0x24 on **I2C bus 1** (SDA 11 / SCL 12), fan is
    /// SoC LEDC PWM 2 / PCNT tach 1, no Ethernet.
    HammerDc02,
    /// Hammer DC04 — 4x MSBT0501 in series (rail = 4 x 0.635 V = 2.54 V),
    /// 300 MH/s Scrypt. TMP75 strap **0x4C**. ASIC UART **TX 17 / RX 18**,
    /// RESET GPIO 1, PGOOD GPIO 11, TPS546 @0x24 on I2C bus 0, EMC2302 @0x2E
    /// dual fan, W5500 SPI Ethernet.
    HammerDc04,
    /// Hammer DC06 — 6x MSBT0501 in series (rail = 6 x 0.635 V = 3.81 V),
    /// 450 MH/s Scrypt. Byte-identical firmware to DC04; the ONLY differences
    /// are the TMP75 strap (**0x4F**), the chip count and the voltage row.
    HammerDc06,

    // ── Lucky Miner LVxx family (BM1366; EXPERIMENTAL, no live hardware) ──
    // Registered from the 2026-07-27 Lucky Miner enablement wave
    // (recon R1/R2).
    // Evidence source: mrbonkerz/ESP-Miner-LVXX fork,
    // main/device_config.h:112-114 (LV06/LV07/LV08 family rows) and
    // :140-146 (board_version rows "300"/"301"/"302" + anonymous "300A"/
    // "301A"/"302A"). All three are 12 V-input, BM1366, electrically
    // Bitaxe-Ultra/Hex-derivative boards with 100% stock BitAxe pinout
    // (ASIC UART TX17/RX18, RST_N GPIO1 active-low, I2C SDA47/SCL48,
    // SSD1306 OLED @ 0x3C) — they reuse the `pins-bitaxe` family.
    //
    // ⚠ TOPOLOGY (SPEC §1.1, THE load-bearing Lucky fact): every LVxx model
    // has ONE parallel ~1.2 V core voltage domain — the chips sit in
    // PARALLEL, explicitly NOT series-stacked like the Hex family. LVXX
    // HEAD commit `48b77a8` DELETED a live 3.6 V / 0.125-scale LV08 case
    // and folded LV08 into the shared 1.2 V / 0.25-scale case (the deleted
    // block survives only as a comment in the fork's vcore.c:82-97).
    // NEVER resurrect it; `voltage_domains` for every Lucky model is 1.
    //
    // Shared peripherals (device_config.h rows): EMC2302 fan controller
    // @ 0x2F (2 channels), 2x TMP1075 temp sensors @ 0x4A/0x4B,
    // temp_offset +5 °C, TPS546 PMBus VRM.
    /// Lucky Miner LV06 — 1x BM1366, 12 V input, one parallel ~1.2 V core
    /// domain, single TPS546 @ 0x24, ~40 W max. Vendor board_version "300"
    /// (anonymous variant "300A"); LVXX NVS devicemodel "lv06".
    LuckyLv06,
    /// Lucky Miner LV07 — 2x BM1366 in PARALLEL on one ~1.2 V domain
    /// (NOT series), 12 V input, single TPS546 @ 0x24, ~40 W max. Vendor
    /// board_version "301" ("301A"); LVXX NVS devicemodel "lv07".
    LuckyLv07,
    /// Lucky Miner LV08 — **9x BM1366 in PARALLEL on ONE ~1.2 V domain**
    /// (NOT series — see the family block comment above), 12 V input,
    /// **THREE paralleled TPS546 regulators @ 0x24 / 0x7F / 0x14**
    /// (`TPS546_LV08` bitfield in the fork; the 3-address array is
    /// fork-only and unreachable from any NVS custom-board key), ~140 W
    /// max. Vendor board_version "302" ("302A") — a DIRECT string
    /// collision with the genuine BitAxe Hex Ultra "302", which is why
    /// inbound identity must go through [`resolve_identity`] instead of a
    /// bare `BoardVersionProfile::find`. LVXX NVS devicemodel "lv08";
    /// stock Lucky factory firmware lies as boardversion "402" /
    /// devicemodel "supra" with minermodel "LV08".
    LuckyLv08,

    // ── BitForge (CERN-OHL-S open hardware; EXPERIMENTAL, no live hardware) ──
    /// BitForge Nano — **2x BM1370 in PARALLEL on one 1.2 V domain**, ESP32-S3,
    /// TPS546A24 PMBus rail, INA260, and **two EMC2101s behind a PCA9544A I2C
    /// bus multiplexer** at 0x70 on channels **2 and 3**.
    ///
    /// The first board in the registry that needs a *bus* multiplexer: the
    /// EMC2101's address is hard-wired, so neither sensor is reachable without
    /// selecting a channel first. See
    /// [`pca9544_convert`](crate::pca9544_convert), which binds select and
    /// confirm together so a failed select cannot return the other ASIC's die
    /// temperature under this ASIC's name.
    ///
    /// Uniquely well-evidenced for a third-party board: we hold BOTH the vendor
    /// firmware (whose only device model is
    /// `BITFORGE_NANO`) and the CERN-OHL-S schematic
    ///. The mux address, the channel
    /// assignment and the parallel topology are each confirmed by both.
    ///
    /// ⚠ TOPOLOGY: the two dies are in PARALLEL on one rail (README: "connected
    /// in parallel"; one `TPS546_CONFIG_NANO` with `VOUT_COMMAND 1.2`), so
    /// `voltage_domains` must stay **1**. `power.rs` derives the rail as
    /// per-ASIC mV x domains — a 2 here would command 2.4 V onto parallel
    /// BM1370 dies. Same hazard class as Lucky LV08 and Hammer DC06.
    ///
    /// ⚠ We deliberately do NOT inherit upstream's voltage defaults. See
    /// `BoardConfig::for_model` for the 1400 mV / `VOUT_MAX 2.0` finding.
    BitForgeNano,
    /// BitAxe Naja — bitaxeorg's dual **BM1373** (S23-generation) prototype.
    ///
    /// Evidence is schematic-only:  (KiCad,
    /// CERN-OHL-S). bitaxeorg ships **no firmware** for this board, so there is
    /// no vendor NVS `boardversion`, no vendor voltage default, and no vendor
    /// pin map to inherit — every value in this board's rows is either read off
    /// the netlist or taken from the BM1373 envelope we already ship for
    /// [`Self::Q1373`]. Upstream's own README calls it "an untested prototype".
    ///
    /// The board is labelled "BM1340", which is a silkscreen name, not a part
    /// number: the `BM1340_mode1` symbol is a byte-for-byte clone of
    /// `BM1370_mode1` (same 32 pins in the same order, and its default `Value`
    /// property is *still* the string `"BM1370_mode1"`), the real upstream
    /// driver is `class BM1373 : public BM1370`, and the silicon answers
    /// **`0x1372`** on the wire. Full adjudication:
    /// .
    ///
    /// TOPOLOGY (from `bitaxeNaja.kicad_pcb`, pad level): both A1 and A2 put
    /// their `VDD` exposed pad (34 pads each) on `/Vcore` and their `VSS` (29
    /// pads) on `GND`, and L1/L2 both land on `/Vcore`. The two dies are in
    /// **PARALLEL** across one 2-phase rail, so `voltage_domains` must stay
    /// **1** — `power.rs` derives the rail as per-ASIC mV x domains, and a 2
    /// here would command double onto parallel dies (the Lucky LV08 / Hammer
    /// DC06 hazard class). The `VDD1/2/3_0`/`_1` pins shared between the chips
    /// are inter-chip decoupling taps; the harvest dossier reads those pin
    /// *names* as series-capable, which they are — but this board does not wire
    /// them that way, and the netlist outranks the pin-name inference.
    ///
    /// ⚠ The Vcore rail is **not firmware-gatable**. `EN_UVLO` carries only a
    /// fixed 12 V divider (R4 6.04k / R5 649) and the two TPS546 EN pins; the
    /// 3V3 module's EN is likewise a hard divider (R17/R18). `PWR_EN` (GPIO10)
    /// is a **dangling net** — the ESP32 pad is the only thing on it. The rail
    /// comes up whenever 12 V is present, so [`Self::buck_enable_wiring`] is
    /// `NotAGpio` and the panic hook has no actuator here.
    ///
    /// ⚠ The EMC2103's own hardware thermal trip is **inert**: `TRIP_SET` has
    /// its programming resistor (R35), but `SYS_SHDN` (pad 7) and `ALERT`
    /// (pad 6) are both unconnected. Nothing in hardware acts on an over-temp.
    /// Thermal protection on this board is 100% firmware, which is why the row
    /// declares `Emc2103` and therefore inherits mandatory fan-tach proof.
    BitaxeNaja,
}

/// An I2C **bus** multiplexer standing between the controller and a board's
/// thermal sensor.
///
/// Declared by [`BitAxeModel::thermal_i2c_mux`]. Boards whose temperature
/// sensor sits on a flat bus return `None` and pay nothing; a board that
/// returns `Some` cannot read a temperature at all until the channel is
/// selected, which is why this is a board capability rather than a driver
/// detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThermalI2cMux {
    /// 7-bit address of the multiplexer itself.
    pub addr: u8,
    /// Downstream channel carrying the sensor the firmware reads.
    pub channel: u8,
}

/// One TMP451 remote-diode sensor, and which ASICs its channels read.
///
/// A board may carry more than one sharing a single pair of select lines — see
/// [`Tmp451DiodeMux`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tmp451Sensor {
    /// 7-bit I2C address this sensor answers at.
    pub addr: u8,
    /// ASIC index that this sensor's mux channel 0 reads.
    pub first_asic: u8,
    /// How many channels carry a real ASIC diode.
    ///
    /// Not always 4. The part always has 4 selectable inputs, but a board may
    /// route fewer — the sibling TMP1075 path already has this exact shape,
    /// where a 4-ASIC Nerd board fits only 3 ASIC sensors because the fourth
    /// strap is the VR. Counting unrouted channels as ASICs would invent die
    /// readings out of an open circuit.
    pub channels: u8,
}

/// How a board drives the TMP451's 2-bit analog channel select.
///
/// The distinction is not cosmetic: a GPIO write cannot fail, an I2C expander
/// write can. A caller that treats the two the same will believe a channel was
/// selected when the bus NAK'd, and then attribute one ASIC's temperature to
/// another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tmp451SelectLines {
    /// Two ESP GPIOs drive A0/A1 directly.
    Gpio { a0: i32, a1: i32 },
    /// A0/A1 are pins on an I2C port expander at `addr`.
    Expander { addr: u8, a0: u8, a1: u8 },
}

/// The 2-bit **analog** mux that fans one TMP451 across up to four ASIC diodes.
///
/// Declared by [`BitAxeModel::tmp451_diode_mux`]. Distinct from
/// [`ThermalI2cMux`], which multiplexes the I2C **bus**: this one switches which
/// diode the sensor's single remote input is connected to, so the sensor stays
/// reachable at all times and it is the *reading* that becomes wrong — silently,
/// and attributed to the wrong chip — if the select lines are not driven.
///
/// # Why this is a declaration and not a `TempSensorKind`
///
/// The mux is fitted only to newer board revisions (NerdOCTAXE-γ rev 3.4). A row
/// that declared `TempSensorKind::Tmp451` would claim guaranteed thermal trust
/// that an older unit of the same model cannot honour, so the sensor is **probed
/// as an enrichment** and the row keeps declaring the TMP1075 it always has.
/// `no_shipping_row_declares_the_tmp451_variant_yet` pins that.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tmp451DiodeMux {
    /// Sensors sharing this one pair of select lines, in ASIC-index order.
    pub sensors: &'static [Tmp451Sensor],
    /// The shared channel-select wiring.
    pub select: Tmp451SelectLines,
    /// `true` when a set channel bit drives its select line HIGH.
    pub active_high: bool,
    /// Per-board linear correction for the raw remote-diode reading.
    ///
    /// Carried here, per board, because applying one board's correction to
    /// another under-reports die temperature by tens of degrees — see
    /// [`tmp451_convert::Calibration`](crate::tmp451_convert::Calibration).
    pub calibration: Tmp451Calibration,
}

/// How a board's buck-enable is wired, for the models that pin it by identity
/// rather than inheriting the stock BitAxe power-controller default.
///
/// Returned by [`BitAxeModel::buck_enable_wiring`] and projected onto
/// `BoardConfig` by `normalize_power_pins`. See that method for why the
/// polarity is safety-critical (it reaches the panic hook).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuckEnableWiring {
    /// No ESP GPIO drives this board's buck enable — it is on an I2C expander,
    /// commanded over PMBus, or simply unverified. `buck_enable_pin` becomes
    /// the `-1` sentinel and the GPIO binder constructs a reset+LED controller
    /// with no buck pin, so `enable_buck` returns `Err` in BOTH directions.
    ///
    /// That `Err` is a TOPOLOGY report, not an actuation failure, and it must be
    /// read through [`RailBringup`] — never as a bare error. It used to be read
    /// as a failure at `main.rs`'s one un-`ok()`d call site, which set
    /// `mining_permitted = false`; since `mining_permitted` only ever ratchets
    /// false, every board here booted, identified, served the dashboard and
    /// could never mine. That is fixed: `main.rs` now dispatches on
    /// `rail_bringup()`, so a [`RailBringup::RegulatorOnly`] board skips the
    /// GPIO step and lets `PowerManager` raise the rail, while a
    /// [`RailBringup::NoActuator`] board is still refused — for the real reason
    /// this time, which is that nothing in firmware can bring its rail down.
    ///
    /// Returning this variant therefore no longer decides whether a board can
    /// mine; `has_voltage_control()` does. Keep it accurate about the WIRING and
    /// let `RailBringup` draw the safety conclusion.
    NotAGpio,
    /// An ESP GPIO drives the buck enable. `active_low` means asserting the
    /// rail drives the pin LOW, so cutting it drives HIGH.
    Gpio { pin: i32, active_low: bool },
    /// The buck enable is a pin on an I²C port expander, not an ESP GPIO.
    ///
    /// `buck_enable_pin` still normalizes to the `-1` sentinel — the ESP GPIO
    /// binder must claim nothing, and `PANIC_BUCK_GPIO` must stay disarmed —
    /// but unlike [`Self::NotAGpio`] this board DOES have an enable, and it can
    /// be both raised and cut. The two are not interchangeable, and
    /// [`RailBringup`] is what tells them apart: reading this as "no actuator"
    /// is what kept the Q-series refused while its enable sat one I²C write
    /// away.
    ///
    /// ACTIVE-HIGH, like every expander enable in the corpus.
    Expander { addr: u8, pin: u8 },
}

/// A pin on an I²C port expander: which part, and which of its 8 pins.
///
/// Serde-derived because it lands in `BoardConfig`, which is serialized to the
/// dashboard — so a board's rail actuator is visible in the API rather than
/// implied by an absent pin number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpanderPin {
    /// I²C address of the expander.
    pub addr: u8,
    /// Pin index, 0..=7.
    pub pin: u8,
}

/// Where a board's **ASIC LDO** enable lives, if it has one.
///
/// # This is a second rail, not a second name for the buck
///
/// The multi-phase Nerd line runs its BM137x dies from two supplies: the
/// TPS5364x core rail, and a bank of LDOs that the ESP enables separately. Both
/// must be up before the chain will answer on the UART, and upstream's
/// `NerdQaxePlus::initAsics` orders them explicitly — LDO first, a 100 ms
/// settle, THEN the buck is configured and commanded:
///
/// ```text
/// setVoltage(0.0)   // VREG_disable
/// LDO_disable()
/// setAsicReset(0)   // hold the chain in reset
/// delay 250 ms
/// LDO_enable()      // <-- the step this type exists for
/// delay 100 ms
/// m_tps->init(...)  // our PowerManager::new
/// setVoltage(...)   // VREG_enable + VOUT_COMMAND
/// delay 500 ms
/// setAsicReset(1)   // release
/// ```
///
/// A board whose LDO never comes up has a perfectly configured core rail and a
/// silent chain, which reads as an enumeration fault rather than a missing
/// supply. That is precisely the state this firmware shipped in: `GPIO13` was
/// unreferenced in the entire tree — no pin map, no binder arm, no board row —
/// so the nine boards whose VRM was wired up still had no IO rail.
///
/// # Why model-keyed
///
/// Same reason as [`BuckEnableWiring`]: an NVS hardware override can rewrite
/// `power_controller` at runtime, so deriving "has an LDO" from
/// `PowerControllerKind::Tps5364x` would let a mistaken override drive GPIO13
/// on a board where that pin is something else. The discriminator here is
/// upstream's class hierarchy — every board that inherits `NerdQaxePlus`
/// inherits its `LDO_EN_PIN` — which is a fact about the hardware family, not
/// about a field a user can edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdoEnable {
    /// A discrete ESP GPIO drives the LDO enable, ACTIVE-HIGH.
    ///
    /// Every implementation in the corpus is active-high — upstream's
    /// `LDO_enable()` writes 1 and `LDO_disable()` writes 0, on both the GPIO
    /// and the port-expander board — so there is no polarity to carry and none
    /// to get wrong.
    Gpio { pin: i32 },
    /// The LDO enable is a pin on an I²C port expander (Q-series, pin 2).
    ///
    /// Same rail, same ordering, different transport — and that is the point.
    /// The bring-up step asks for "this board's LDO enable", not "GPIO13", so
    /// adding a second transport added no second sequence.
    Expander { addr: u8, pin: u8 },
}

/// When the enable GPIO may be asserted, relative to configuring the regulator.
///
/// This is not a style preference — it decides whether the rail can come up at
/// an *unconfigured* voltage during bring-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RailEnableOrder {
    /// Assert the enable GPIO first, then configure the regulator. Safe only
    /// because `Tps546::new`'s first write is `OPERATION_OFF`, and the TPS546's
    /// `ON_OFF_CONFIG = 0x1B` has the CMD bit SET — so the stage stays off while
    /// limits are programmed, even with EN already high.
    GpioBeforeRegulator,
    /// Configure the regulator first, then assert the enable GPIO.
    ///
    /// Required for the TPS5364x family, and the reason is exactly the property
    /// that makes it uncuttable over I2C: its `ON_OFF_CONFIG = 0b0001_0111` has
    /// the CMD bit CLEAR, so `OPERATION_OFF` does nothing and only the EN pin
    /// gates the output. Assert EN first and the stage energizes at whatever
    /// `VOUT` the part's NVM holds — through `RESTORE_DEFAULT_ALL`, before
    /// `VOUT_COMMAND` is ever written. Upstream's own order is
    /// `TPS53647::init()` then `VREG_enable()`, for the same reason.
    RegulatorBeforeGpio,
}

/// What can actually bring a board's ASIC rail up — and, more importantly, cut
/// it again.
///
/// Derived, never stored, from the buck-enable projection plus
/// [`BitAxeModel::has_voltage_control`]. It exists because "no enable GPIO" and
/// "no way to command the rail at all" are very different situations that the
/// `-1` sentinel alone cannot tell apart, and the difference decides whether a
/// board is safe to energize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RailBringup {
    /// A discrete ESP GPIO asserts the enable. This is the only variant whose
    /// rail the panic hook (XPSAFE-1) can cut, because the hook drives a pin
    /// number and nothing else.
    EnableGpio,
    /// No discrete enable exists; the rail is commanded over PMBus by
    /// `PowerManager` — `set_voltage` sends VOUT_COMMAND + OPERATION_ON to
    /// raise it, `disable` sends OPERATION_OFF to cut it. Every normal-path
    /// safety cut therefore works.
    ///
    /// The panic path is weaker but no longer absent: XPSAFE-5 arms the hook
    /// with a bounded `OPERATION_OFF` write (`main.rs`
    /// `arm_panic_pmbus_rail_cut`), armed only on boards of this class. A GPIO
    /// cut is a lock-free register write that cannot fail; a PMBus cut needs the
    /// I2C peripheral and can time out. Best-effort-but-bounded — more than
    /// nothing, less than [`Self::EnableGpio`]. Boards here are EXPERIMENTAL for
    /// that reason, not because their rail is uncontrolled.
    RegulatorOnly,
    /// The enable is a pin on an I²C port expander (Q-series, FXL6408 pin 1).
    ///
    /// A real actuator in BOTH directions — the panic hook cuts it with one
    /// bounded write of `0x00` to `OUTPUT_STATE`, which drops ASIC reset, VREG
    /// and LDO together and needs no knowledge of the driver's shadow
    /// registers. Strictly stronger than [`Self::RegulatorOnly`] on a part
    /// whose `OPERATION` is inert, and weaker than [`Self::EnableGpio`] only in
    /// that I²C can time out where a register write cannot.
    ///
    /// These boards were classified `RegulatorOnly` and refused, because the
    /// classifier could see the absent GPIO but not the present expander.
    ExpanderGpio { addr: u8, pin: u8 },
    /// Neither a discrete enable nor commandable voltage. Nothing in firmware
    /// can raise or lower this rail; it is whatever the hardware makes it.
    /// A board here must not be treated as merely "missing a pin".
    NoActuator,
}

impl BitAxeModel {
    pub fn canonical_key(&self) -> &'static str {
        match self {
            Self::Max => "max",
            Self::Ultra => "ultra",
            Self::HexUltra => "hexultra",
            Self::Supra => "supra",
            Self::HexSupra => "suprahex",
            Self::Gamma => "gamma",
            Self::GammaDuo => "gammaduo",
            Self::GammaTurbo => "gammaturbo",
            Self::Touch => "touch",
            Self::GtTouch => "gt_touch",
            Self::NerdNOS => "nerdnos",
            Self::NerdAxe => "nerdaxe",
            Self::NerdAxeGamma => "nerdaxegamma",
            Self::NerdQaxePlus => "nerdqaxeplus",
            Self::NerdQaxePP => "nerdqaxepp",
            Self::NerdOctaxePlus => "nerdoctaxeplus",
            Self::NerdOctaxeGamma => "nerdoctaxegamma",
            Self::NerdQX => "nerdqx",
            Self::NerdHaxeGamma => "nerdhaxegamma",
            Self::NerdEko => "nerdeko",
            Self::Q1370 => "q1370",
            Self::Q1373 => "q1373",
            Self::DcentAxeBm1397 => "dcentaxe_bm1397",
            Self::DcentAxeQuadBm1397 => "dcentaxe_quad_bm1397",
            Self::DcentAxeHexBm1397 => "dcentaxe_hex_bm1397",
            Self::HammerBc01 => "hammer_bc01",
            Self::HammerBc01Pro => "hammer_bc01_pro",
            Self::HammerBc02 => "hammer_bc02",
            Self::HammerBc04 => "hammer_bc04",
            Self::HammerDc02 => "hammer_dc02",
            Self::HammerDc04 => "hammer_dc04",
            Self::HammerDc06 => "hammer_dc06",
            // Lucky LVxx: matches the LVXX fork's own NVS `devicemodel`
            // strings (config-lv0x.cvs) — this string is also the
            // device_model baked into the OTA schema-2 signature.
            Self::LuckyLv06 => "lv06",
            Self::LuckyLv07 => "lv07",
            Self::LuckyLv08 => "lv08",
            Self::BitForgeNano => "bitforgenano",
            Self::BitaxeNaja => "bitaxenaja",
        }
    }

    pub fn from_device_model(model: &str) -> Option<Self> {
        match model.trim().to_ascii_lowercase().as_str() {
            "max" => Some(Self::Max),
            "ultra" => Some(Self::Ultra),
            "hex" | "hexultra" | "hex_ultra" | "ultrahex" => Some(Self::HexUltra),
            "supra" => Some(Self::Supra),
            "hexsupra" | "hex_supra" | "suprahex" | "supra_hex" => Some(Self::HexSupra),
            "gamma" => Some(Self::Gamma),
            "gammaduo" => Some(Self::GammaDuo),
            "gammaturbo" | "gt" => Some(Self::GammaTurbo),
            "touch" | "bitaxe_touch" | "bitaxetouch" => Some(Self::Touch),
            "gt_touch" | "gttouch" | "turbotouch" | "turbo_touch" => Some(Self::GtTouch),
            "nerdnos" => Some(Self::NerdNOS),
            // Order matters against the bare "nerdaxe" arm below only because
            // these are exact-match arms; upstream's device model is
            // "NerdAxeGamma" while its MINING AGENT is plain "NerdAxe", so a
            // client that reports the agent string lands on the parent board.
            // That is the safe direction (BM1366/DS4432U is fail-closed against
            // BM1370 silicon), but it means agent strings cannot identify a γ.
            "nerdaxegamma" | "nerdaxe_gamma" | "nerdaxe-gamma" | "nerdaxeg" => {
                Some(Self::NerdAxeGamma)
            }
            "nerdaxe" => Some(Self::NerdAxe),
            "nerdqaxe+" | "nerdqaxeplus" | "nerdqaxe_plus" => Some(Self::NerdQaxePlus),
            "nerdqaxe++" | "nerdqaxepp" | "nerdqaxe_pp" => Some(Self::NerdQaxePP),
            // Upstream reports these as "NerdOCTAXE+" and "NerdOCTAXE-γ"; the
            // non-ASCII gamma is accepted alongside ASCII spellings so a device
            // that announces its vendor string still resolves.
            "nerdoctaxe+" | "nerdoctaxeplus" | "nerdoctaxe_plus" => Some(Self::NerdOctaxePlus),
            "nerdoctaxe-γ" | "nerdoctaxegamma" | "nerdoctaxe_gamma" | "nerdoctaxe-gamma" => {
                Some(Self::NerdOctaxeGamma)
            }
            // "NerdQX", "NerdHaxe-γ", "NerdEKO", "Q1370" and "Q1373" ARE the
            // vendor's own `m_deviceModel` strings — these boards set no
            // distinct `m_version`, so the model string is the ONLY identity
            // they announce. The non-ASCII gamma is accepted alongside the
            // ASCII spellings for the same reason as the OCTAXE row above.
            "nerdqx" | "nerd_qx" | "nerd qx" => Some(Self::NerdQX),
            "nerdhaxe-γ" | "nerdhaxegamma" | "nerdhaxe_gamma" | "nerdhaxe-gamma" => {
                Some(Self::NerdHaxeGamma)
            }
            "nerdeko" | "nerd_eko" | "nerd eko" => Some(Self::NerdEko),
            "q1370" | "q_1370" => Some(Self::Q1370),
            "q1373" | "q_1373" => Some(Self::Q1373),
            // Canonical key, compact aliases, and the lowercased marketing name
            // ("DCENT_axe BM1397" -> "dcent_axe bm1397").
            "dcentaxe_bm1397" | "dcentaxebm1397" | "dcent_axe_bm1397" | "dcentaxe bm1397"
            | "dcent_axe bm1397" => Some(Self::DcentAxeBm1397),
            "dcentaxe_quad_bm1397"
            | "dcentaxequadbm1397"
            | "dcent_axe_quad_bm1397"
            | "quad_bm1397"
            | "dcentaxe quad bm1397"
            | "dcent_axe quad bm1397" => Some(Self::DcentAxeQuadBm1397),
            "dcentaxe_hex_bm1397"
            | "dcentaxehexbm1397"
            | "dcent_axe_hex_bm1397"
            | "hex_bm1397"
            | "dcentaxe hex bm1397"
            | "dcent_axe hex bm1397" => Some(Self::DcentAxeHexBm1397),
            // Hammer BC0x: canonical keys + the vendor's own model spellings.
            // Hammer stock firmware is ESP-Miner-derived and stores a
            // `devicemodel` NVS string ("BC01"-style, exact casing pending RE
            // capture); accepting the lowercased vendor names lets a DCENT_OS
            // image flashed over stock Hammer auto-identify via the
            // DeviceModelDefault ladder rung even before the vendor
            // boardversion strings are captured.
            "hammer_bc01" | "hammerbc01" | "hammer bc01" | "bc01" => Some(Self::HammerBc01),
            "hammer_bc01_pro" | "hammerbc01pro" | "hammer bc01 pro" | "bc01pro" | "bc01-pro"
            | "bc01_pro" => Some(Self::HammerBc01Pro),
            "hammer_bc02" | "hammerbc02" | "hammer bc02" | "bc02" => Some(Self::HammerBc02),
            "hammer_bc04" | "hammerbc04" | "hammer bc04" | "bc04" => Some(Self::HammerBc04),
            // Hammer DC0x (Scrypt). "DC02"/"DC04"/"DC06" ARE the vendor's own
            // NVS `devicemodel` spellings (the strings its firmware compares
            // against the TMP75 strap), lowercased here like every other alias.
            "hammer_dc02" | "hammerdc02" | "hammer dc02" | "dc02" => Some(Self::HammerDc02),
            "hammer_dc04" | "hammerdc04" | "hammer dc04" | "dc04" => Some(Self::HammerDc04),
            "hammer_dc06" | "hammerdc06" | "hammer dc06" | "dc06" => Some(Self::HammerDc06),
            // Lucky Miner LVxx: the canonical key "lv0x" IS the vendor's own
            // NVS `devicemodel` spelling (LVXX fork config-lv0x.cvs) and also
            // the lowercased marketing name ("LV06" → "lv06"), so a DCENT_OS
            // image flashed over an unlocked LVXX unit auto-identifies via
            // the DeviceModelDefault ladder rung. Additional human aliases
            // cover underscore/space/board-target spellings.
            "lv06" | "lucky_lv06" | "luckylv06" | "lucky lv06" | "lucky-lv06" => {
                Some(Self::LuckyLv06)
            }
            "lv07" | "lucky_lv07" | "luckylv07" | "lucky lv07" | "lucky-lv07" => {
                Some(Self::LuckyLv07)
            }
            "lv08" | "lucky_lv08" | "luckylv08" | "lucky lv08" | "lucky-lv08" => {
                Some(Self::LuckyLv08)
            }
            // BitForge Nano. The vendor firmware carries no `devicemodel`
            // string at all (its only identity is the `BITFORGE_NANO` enum and
            // a "BitForge-" BLE name prefix), so these are our canonical key
            // plus the human/board-target spellings.
            "bitforgenano" | "bitforge_nano" | "bitforge nano" | "bitforge-nano" | "nano" => {
                Some(Self::BitForgeNano)
            }
            // BitAxe Naja. bitaxeorg ships no firmware for this prototype, so
            // there is no vendor `devicemodel` string either — these are our
            // canonical key plus the human/board-target spellings. "naja" is
            // unambiguous ("nano" is already taken by the BitForge above).
            "bitaxenaja" | "bitaxe_naja" | "bitaxe naja" | "bitaxe-naja" | "naja" => {
                Some(Self::BitaxeNaja)
            }
            _ => None,
        }
    }

    pub fn board_target(&self) -> &'static str {
        match self {
            Self::Max => "bitaxe-max",
            Self::Ultra => "bitaxe-ultra",
            Self::HexUltra => "bitaxe-hex-ultra",
            Self::Supra => "bitaxe-supra",
            Self::HexSupra => "bitaxe-hex-supra",
            Self::Gamma => "bitaxe-gamma",
            Self::GammaDuo => "bitaxe-gamma-duo",
            Self::GammaTurbo => "bitaxe-gt",
            // Touch variants reuse the underlying mining board targets but
            // flip on the BAP accessory driver via the `bap` Cargo feature.
            Self::Touch => "bitaxe-touch",
            Self::GtTouch => "bitaxe-gt-touch",
            Self::NerdNOS => "nerdnos",
            Self::NerdAxe => "nerdaxe",
            Self::NerdAxeGamma => "nerdaxe-gamma",
            Self::NerdOctaxePlus => "nerdoctaxe-plus",
            Self::NerdOctaxeGamma => "nerdoctaxe-gamma",
            Self::NerdQaxePlus => "nerdqaxe-plus",
            Self::NerdQaxePP => "nerdqaxe-pp",
            Self::NerdQX => "nerdqx",
            Self::NerdHaxeGamma => "nerdhaxe-gamma",
            Self::NerdEko => "nerdeko",
            Self::Q1370 => "q1370",
            Self::Q1373 => "q1373",
            Self::DcentAxeBm1397 => "dcent-axe-bm1397",
            Self::DcentAxeQuadBm1397 => "dcent-axe-quad-bm1397",
            Self::DcentAxeHexBm1397 => "dcent-axe-hex-bm1397",
            Self::HammerBc01 => "hammer-bc01",
            Self::HammerBc01Pro => "hammer-bc01-pro",
            Self::HammerBc02 => "hammer-bc02",
            Self::HammerBc04 => "hammer-bc04",
            Self::HammerDc02 => "hammer-dc02",
            Self::HammerDc04 => "hammer-dc04",
            Self::HammerDc06 => "hammer-dc06",
            Self::LuckyLv06 => "lucky-lv06",
            Self::LuckyLv07 => "lucky-lv07",
            Self::LuckyLv08 => "lucky-lv08",
            Self::BitForgeNano => "bitforge-nano",
            Self::BitaxeNaja => "bitaxe-naja",
        }
    }

    /// Number of ASIC chips on this board variant.
    pub fn asic_count(&self) -> u8 {
        match self {
            // NerdHaxe-γ is 6 chips but is NOT `is_hex()`: Hex means the BitAxe
            // 6x/3-series-domain topology. NerdHaxe-γ is six BM1370 in PARALLEL
            // on one multi-phase rail. Routing it through the Hex preset would
            // command triple the intended voltage onto parallel dies.
            Self::HexUltra | Self::HexSupra | Self::DcentAxeHexBm1397 | Self::NerdHaxeGamma => 6,
            Self::GammaDuo
            | Self::GammaTurbo
            | Self::GtTouch
            | Self::HammerBc02
            | Self::HammerDc02
            | Self::LuckyLv07 => 2,
            Self::NerdQaxePlus
            | Self::NerdQaxePP
            | Self::NerdQX
            | Self::Q1370
            | Self::Q1373
            | Self::DcentAxeQuadBm1397
            | Self::HammerBc04
            | Self::HammerDc04 => 4,
            // NerdEKO: TWELVE BM1370 in one UART daisy chain — the largest
            // board in the registry. Address interval `256/12 = 21`, addresses
            // 0..231. This is what raises `LARGEST_SUPPORTED_ASIC_COUNT` from
            // 9 to 12; `MAX_CHIPS` (16) still covers it with headroom.
            Self::NerdEko => 12,
            // DC06 is 6 chips but is NOT `is_hex()`: Hex means the BitAxe
            // 6x/3-domain 12 V topology. DC06 is 6 chips in SIX series
            // domains at 0.635 V each. Routing it through the Hex TPS546
            // preset would command a 3-domain rail onto a 6-chip stack.
            Self::HammerDc06 => 6,
            // Lucky LV08: NINE BM1366 in a single UART daisy chain — the
            // first board past the 6-chip Hex ceiling (address interval
            // 256/9 = 28, addresses 0..224; verified safe in SPEC §5).
            Self::LuckyLv08 => 9,
            // BitForge Nano: 2 BM1370 in one UART daisy chain
            // (`BITFORGE_NANO_ASIC_COUNT 2`, forge-os `asic.h:8`). Must be
            // explicit — the `_ => 1` arm below is fail-open, and reporting one
            // chip would halve every derived hashrate and power figure.
            Self::BitForgeNano => 2,
            // BitAxe Naja: 2 BM1373 in one UART daisy chain. Read off the
            // netlist rather than a vendor constant — A1's CO/RI/CLKO/BO/NRSTO
            // drive A2's CI/RO/CLKI/BI/NRSTI, and A2's outbound side
            // terminates. Explicit for the same reason as the BitForge above:
            // the `_ => 1` arm is fail-open.
            Self::BitaxeNaja => 2,
            // NerdOCTAXE+/γ: EIGHT ASICs in a single UART daisy chain
            // (interval 256/8 = 32, addresses 0..224 — an exact divisor, so
            // unlike LV08 there is no remainder to reason about). These MUST
            // be explicit: the `_ => 1` arm below is fail-open, and an OCTAXE
            // silently reporting one chip would under-enumerate the chain and
            // mis-scale every hashrate and power figure derived from it.
            Self::NerdOctaxePlus | Self::NerdOctaxeGamma => 8,
            _ => 1,
        }
    }

    /// Human-readable name for logging and UI.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Max => "BitAxe Max",
            Self::Ultra => "BitAxe Ultra",
            Self::HexUltra => "BitAxe Hex Ultra",
            Self::Supra => "BitAxe Supra",
            Self::HexSupra => "BitAxe Hex Supra",
            Self::Gamma => "BitAxe Gamma",
            Self::GammaDuo => "BitAxe Gamma Duo",
            Self::GammaTurbo => "BitAxe Gamma Turbo",
            Self::Touch => "BitAxe Touch",
            Self::GtTouch => "BitAxe Turbo Touch",
            Self::NerdNOS => "NerdNOS",
            Self::NerdAxe => "NerdAxe",
            Self::NerdAxeGamma => "NerdAxe-Gamma",
            Self::NerdQaxePlus => "NerdQaxe+",
            Self::NerdQaxePP => "NerdQaxe++",
            Self::NerdOctaxePlus => "NerdOCTAXE+",
            Self::NerdOctaxeGamma => "NerdOCTAXE-Gamma",
            Self::NerdQX => "NerdQX",
            Self::NerdHaxeGamma => "NerdHaxe-Gamma",
            Self::NerdEko => "NerdEKO",
            Self::Q1370 => "Q1370",
            Self::Q1373 => "Q1373",
            Self::DcentAxeBm1397 => "DCENT_axe BM1397",
            Self::DcentAxeQuadBm1397 => "DCENT_axe Quad BM1397",
            Self::DcentAxeHexBm1397 => "DCENT_axe Hex BM1397",
            Self::HammerBc01 => "Hammer BC01",
            Self::HammerBc01Pro => "Hammer BC01 Pro",
            Self::HammerBc02 => "Hammer BC02",
            Self::HammerBc04 => "Hammer BC04",
            Self::HammerDc02 => "Hammer DC02",
            Self::HammerDc04 => "Hammer DC04",
            Self::HammerDc06 => "Hammer DC06",
            Self::LuckyLv06 => "Lucky Miner LV06",
            Self::LuckyLv07 => "Lucky Miner LV07",
            Self::LuckyLv08 => "Lucky Miner LV08",
            Self::BitForgeNano => "BitForge Nano",
            Self::BitaxeNaja => "BitAxe Naja",
        }
    }

    /// The stock-AxeOS device-model name to report over the stock HTTP API and
    /// the cgminer TCP protocol.
    ///
    /// Third-party tooling (AxeOS clients, swarm dashboards, cgminer-protocol
    /// monitors) recognises a fixed set of stock BitAxe names. Boards that are
    /// not stock BitAxes report either their own marketing name, where tooling
    /// benefits from telling them apart, or the closest stock model for the ASIC
    /// actually fitted, where it does not.
    ///
    /// ⚠ THIS FUNCTION EXISTS BECAUSE ITS PREDECESSOR DID NOT. Two byte-identical
    /// copies of this map lived in `dcentaxe/src/api.rs` and
    /// `dcentaxe/src/cgminer_tcp.rs`, each an exhaustive `match` on
    /// [`BitAxeModel`]. Commit `13e44591` added two variants, verified
    /// `dcentaxe-hal`, and shipped a HEAD that did not compile for any Nerd
    /// target — because the two copies it had to update were in a crate it never
    /// built. Registering a board must not require finding every exhaustive
    /// match scattered across the binary. Keep this the ONLY such map, and let
    /// the compiler point at this one place.
    ///
    /// `board_version` is checked first: some versions are shared by boards that
    /// report a different stock name than their [`BitAxeModel`] would give.
    pub fn stock_model_name(&self, board_version: &str) -> &'static str {
        match board_version {
            "302" | "303" => return "Hex",
            "650" => return "GammaDuo",
            "701" | "702" => return "SupraHex",
            "801" => return "GammaTurbo",
            _ => {}
        }
        match self {
            Self::Max => "Max",
            Self::Ultra => "Ultra",
            Self::Supra => "Supra",
            Self::Gamma => "Gamma",
            Self::GammaDuo => "GammaDuo",
            Self::GammaTurbo => "GammaTurbo",
            Self::HexUltra => "Hex",
            Self::HexSupra => "SupraHex",
            Self::NerdNOS => "Max",
            // BM1366 => Ultra, by the same "closest stock model for the ASIC
            // actually fitted" rule the rest of this map follows (BM1397 =>
            // Max, BM1368 => Supra, BM1370 => Gamma). This read "Gamma" while
            // the row claimed BM1370; correcting the silicon corrects this too.
            Self::NerdAxe => "Ultra",
            Self::NerdAxeGamma => "Gamma",
            Self::NerdQaxePlus => "Supra",
            Self::NerdQaxePP => "Gamma",
            // The Nerd multi-ASIC line follows one convention: report the
            // closest stock model for the ASIC actually fitted (BM1368 =>
            // Supra, BM1370 => Gamma) so stock-protocol clients identify them.
            Self::NerdOctaxePlus => "Supra",
            Self::NerdOctaxeGamma => "Gamma",
            Self::NerdQX => "Gamma",
            Self::NerdHaxeGamma => "Gamma",
            Self::NerdEko => "Gamma",
            // Q-series: BM1370 maps to Gamma by the same rule. Q1373 is BM1373
            // silicon, which has no stock BitAxe equivalent at all — Gamma is
            // the nearest generation, and the honest model name is carried
            // separately by `name()`.
            Self::Q1370 | Self::Q1373 => "Gamma",
            // BM1370 => Gamma, by the same "closest stock model for the ASIC
            // actually fitted" rule. The honest name is carried by `name()`.
            Self::BitForgeNano => "Gamma",
            // BM1373, so the same rule as Q1373 above: no stock BitAxe carries
            // this silicon, and Gamma is the nearest generation.
            Self::BitaxeNaja => "Gamma",
            // Surface Touch variants with their own marketing names so the
            // dashboard / swarm / cgminer stock protocol identify them correctly.
            Self::Touch => "Touch",
            Self::GtTouch => "GtTouch",
            // DCENT_axe BM1397 SKUs.
            Self::DcentAxeBm1397 => "DCENT_axe BM1397",
            Self::DcentAxeQuadBm1397 => "DCENT_axe Quad BM1397",
            Self::DcentAxeHexBm1397 => "DCENT_axe Hex BM1397",
            // Hammer BC0x / DC0x (EXPERIMENTAL) — vendor model names for
            // third-party tool compatibility.
            Self::HammerBc01 => "HammerBC01",
            Self::HammerBc01Pro => "HammerBC01Pro",
            Self::HammerBc02 => "HammerBC02",
            Self::HammerBc04 => "HammerBC04",
            Self::HammerDc02 => "HammerDC02",
            Self::HammerDc04 => "HammerDC04",
            Self::HammerDc06 => "HammerDC06",
            // Lucky Miner LVxx (EXPERIMENTAL) — vendor model names for
            // third-party tooling compatibility.
            Self::LuckyLv06 => "LV06",
            Self::LuckyLv07 => "LV07",
            Self::LuckyLv08 => "LV08",
        }
    }

    /// Honest release-support status for operator-facing surfaces.
    ///
    /// This is deliberately coarse and conservative. Unknown board versions are
    /// handled by config-level recognition helpers and surface as `unknown`.
    pub fn support_status(&self) -> &'static str {
        match self {
            Self::Gamma | Self::Max | Self::Ultra | Self::Supra => "supported",
            Self::HexUltra
            | Self::HexSupra
            | Self::GammaDuo
            | Self::GammaTurbo
            | Self::Touch
            | Self::GtTouch
            | Self::NerdNOS
            | Self::NerdAxe
            | Self::NerdAxeGamma
            | Self::NerdQaxePlus
            | Self::NerdQaxePP
            // NerdOCTAXE+/γ: no live hardware on any bench, and the γ ships two
            // different power stages under one name. Experimental until a
            // witnessed run exists on each revision.
            | Self::NerdOctaxePlus
            | Self::NerdOctaxeGamma
            // The rest of the Nerd multi-ASIC line and the Q-series: no live
            // hardware, and NerdQX in particular carries an upstream
            // over-current trip we deliberately refuse rather than reproduce.
            | Self::NerdQX
            | Self::NerdHaxeGamma
            | Self::NerdEko
            | Self::Q1370
            | Self::Q1373
            | Self::DcentAxeBm1397
            | Self::DcentAxeQuadBm1397
            | Self::DcentAxeHexBm1397
            | Self::HammerBc01
            | Self::HammerBc01Pro
            | Self::HammerBc02
            | Self::HammerBc04
            | Self::HammerDc02
            | Self::HammerDc04
            | Self::HammerDc06
            // Lucky LVxx: no live hardware on any bench — experimental until
            // a witnessed soak exists (SPEC §8 honesty posture).
            | Self::LuckyLv06
            | Self::LuckyLv07
            | Self::LuckyLv08
            // BitForge Nano: open hardware with vendor firmware AND schematic
            // held, but no unit on any bench. Experimental until a witnessed
            // run exists.
            | Self::BitForgeNano
            // BitAxe Naja: schematic only — no vendor firmware exists at all,
            // and upstream itself calls the board an untested prototype. This
            // is the weakest evidence position of any registered board.
            | Self::BitaxeNaja => "experimental",
        }
    }

    /// Returns true if this is a Hex (6-ASIC series-chain) variant.
    ///
    /// ⚠ Do NOT add the Lucky LVxx models here (SPEC §1.1). `is_hex()` means
    /// "6-ASIC SERIES chain with 3 voltage domains on 12 V" and drives the
    /// Hex TPS546 preset + a hardcoded "3 voltage domains" log string. Lucky
    /// chips are PARALLEL on ONE ~1.2 V domain — routing LV08 through the
    /// Hex path would command a multiple of 1.2 V onto nine parallel dies.
    pub fn is_hex(&self) -> bool {
        matches!(
            self,
            Self::HexUltra | Self::HexSupra | Self::DcentAxeHexBm1397
        )
    }

    /// Returns true if this is a Nerd-family board.
    pub fn is_nerd(&self) -> bool {
        matches!(
            self,
            Self::NerdNOS
                | Self::NerdAxe
                | Self::NerdAxeGamma
                | Self::NerdQaxePlus
                | Self::NerdQaxePP
                | Self::NerdOctaxePlus
                | Self::NerdOctaxeGamma
                | Self::NerdQX
                | Self::NerdHaxeGamma
                | Self::NerdEko
        )
    }

    /// Returns true if this is a Q-series board (Q1370 / Q1373).
    ///
    /// The Q-series shares the Nerd multi-ASIC software stack — same TPS53647
    /// rail, same TMP1075 thermal topology, same BM1370-family driver — but is
    /// NOT Nerd-branded, and differs in one load-bearing way: its ASIC reset,
    /// VREG enable and LDO enable are driven through an FXL6408 I2C port
    /// expander at 0x43 instead of ESP GPIOs. See [`fxl6408_convert`].
    pub fn is_q_series(&self) -> bool {
        matches!(self, Self::Q1370 | Self::Q1373)
    }

    /// Returns true if this board's core rail is a TPS53647/TPS53667
    /// multi-phase VRM rather than the TPS546 used by BitAxe-class boards.
    ///
    /// These are all single-voltage-domain boards with their ASICs in
    /// **parallel** — deliberately NOT `is_hex()`, whose 3-domain series preset
    /// would command a multiple of the intended voltage onto parallel dies.
    ///
    /// Nerd-branded members only; the Q-series carries the same part and is
    /// covered by [`Self::has_multiphase_vrm`]. Callers that mean "this board's
    /// rail is a TPS5364x" want that one — this narrower predicate exists
    /// because `test_runtime_hardware_ownership.py` pins HAL function names
    /// exactly, so it is added to rather than renamed.
    pub fn is_multiphase_nerd(&self) -> bool {
        matches!(
            self,
            Self::NerdQaxePlus
                | Self::NerdQaxePP
                | Self::NerdOctaxePlus
                | Self::NerdOctaxeGamma
                | Self::NerdQX
                | Self::NerdHaxeGamma
                | Self::NerdEko
        )
    }

    /// Returns true if this board's core rail is a TPS53647/TPS53667, whoever
    /// built the board.
    ///
    /// This is the predicate to reach for when the question is about the
    /// **hardware** — which regulator answers at 0x71, which thermal topology
    /// the TMP1075s follow — rather than about the brand on the silkscreen.
    pub fn has_multiphase_vrm(&self) -> bool {
        self.is_multiphase_nerd() || self.is_q_series()
    }

    /// Returns true if this is a D-Central DCENT_axe family board.
    ///
    /// Used by `normalize_power_pins` to give the family its own deterministic
    /// power path: the TPS546D24A EN pin is wired to **GPIO10, ACTIVE-HIGH** on
    /// these boards (verified from the dcent-axe-BM1397 schematic netlist,
    /// PREFAB_DESIGN_REVIEW_2026-07-08 R-10) — NOT the stock-BitAxe GPIO46 the
    /// generic Tps546 arm picks (unconnected here), and NOT active-low.
    pub fn is_dcent_axe(&self) -> bool {
        matches!(
            self,
            Self::DcentAxeBm1397 | Self::DcentAxeQuadBm1397 | Self::DcentAxeHexBm1397
        )
    }

    /// The buck-enable wiring this MODEL pins, or `None` when the model does
    /// not pin one and `normalize_power_pins` should derive it from the
    /// power-controller kind (stock BitAxe: DS4432U => GPIO10 active-low,
    /// TPS546 => GPIO46 active-high).
    ///
    /// **Why model-keyed rather than derived.** An NVS hardware override can
    /// rewrite `power_controller` at runtime. If these boards fell through to
    /// the derived path, a mistaken override would silently re-route them: the
    /// TPS546 branch picks GPIO46 (unconnected, or worse, a panel data line)
    /// and the DS4432U branch makes GPIO10 active-LOW — turning fail-closed
    /// "power OFF" into driving the VRM rail ON. Pinning by model makes that
    /// unreachable.
    ///
    /// **Why this is a table and not an if-chain.** `buck_enable_active_low`
    /// is stored into `PANIC_BUCK_ACTIVE_LOW` and read by the panic hook, which
    /// drives `safety::buck_off_level(active_low)` to cut the rail before the
    /// runtime aborts. A wrong polarity here does not merely fail to cut power
    /// — it ENERGIZES the rail at the moment thermal supervision dies. The
    /// old chain grouped every Nerd board under one `is_nerd()` arm and so
    /// asserted active-HIGH for [`Self::NerdAxe`], whose GPIO10 is inverted.
    /// One row per real topology, with the evidence on the row.
    /// Where this model's ASIC LDO enable lives, or `None` if it has no
    /// separate LDO rail. See [`LdoEnable`] for why this is load-bearing.
    ///
    /// One row per real topology, with the evidence on the row — the same
    /// discipline as [`Self::buck_enable_wiring`], and for a related reason: a
    /// wrong pin here does not fail quietly, it drives an uncharacterized net
    /// high during power-up.
    pub fn asic_ldo_enable(&self) -> Option<LdoEnable> {
        match self {
            // The multi-phase Nerd line. `LDO_EN_PIN` is `#define`d exactly
            // once upstream — `nerdqaxeplus.cpp:8`, `GPIO_NUM_13` — and every
            // board below is a subclass of `NerdQaxePlus` that inherits its
            // `LDO_enable()`/`LDO_disable()` unchanged. `initBoard` configures
            // it as an output driven LOW; `initAsics` raises it before the TPS
            // init; `shutdown` drops it 500 ms after the core rail.
            //
            // GPIO13 is claimed by nothing else in this firmware: it appears in
            // no `pins-*` map, no `lora_pins` row, no `st7789_pins` row, and no
            // other board field. That was verified before binding it, because a
            // runtime `match` arm in the GPIO binder compiles into EVERY image
            // regardless of board — see the `bitforge-nano` + `lora` note there.
            Self::NerdQaxePlus
            | Self::NerdQaxePP
            | Self::NerdOctaxePlus
            | Self::NerdOctaxeGamma
            | Self::NerdQX
            | Self::NerdHaxeGamma
            | Self::NerdEko => Some(LdoEnable::Gpio { pin: 13 }),
            // Q-series: same LDO in the same place in the sequence, reached
            // over I2C instead. `Q1370B::LDO_enable()` writes expander pin 2.
            // Declaring it as `Gpio { pin: 13 }` would drive an ESP pin this
            // board does not use for that.
            m if m.is_q_series() => Some(LdoEnable::Expander {
                addr: crate::fxl6408_convert::ADDR,
                pin: crate::fxl6408_convert::q_series::LDO_ENABLE,
            }),
            // Deliberately NOT the rest of `is_nerd()`. NerdNOS, NerdAxe and
            // NerdAxe-gamma are separate upstream classes with their own
            // `initBoard`, and none of them defines or calls an LDO enable —
            // a repo-wide grep for `LDO_EN_PIN`/`LDO_enable`/`LDO_disable`
            // returns only `nerdqaxeplus.cpp` and `q1370.cpp`. Grouping them
            // under one `is_nerd()` arm would drive GPIO13 on three boards that
            // have no LDO there.
            //
            // The Q-series DOES have one, on expander pin 2 rather than an ESP
            // GPIO, and is handled once the FXL6408 transport ships. Returning
            // `None` here keeps it off a pin it does not own; those two boards
            // are refused before the rail for an unrelated reason anyway.
            _ => None,
        }
    }

    pub fn buck_enable_wiring(&self) -> Option<BuckEnableWiring> {
        // DCENT_axe (PREFAB_DESIGN_REVIEW_2026-07-08 R-10): TPS546D24A EN on
        // GPIO10 ACTIVE-HIGH, verified from the dcent-axe-BM1397 schematic
        // netlist. GPIO46 is UNCONNECTED on these boards.
        if self.is_dcent_axe() {
            return Some(BuckEnableWiring::Gpio {
                pin: 10,
                active_low: false,
            });
        }
        // Hammer BC0x AND DC0x: bind no discrete buck-enable GPIO. The
        // regulator-EN wiring is unverified (DC0x commands its TPS546 over
        // PMBus), GPIO15 is the shared board/LCD-power net that must not be
        // touched without bench characterization, and GPIO46 is byte-verified
        // ST7789 panel data D5 — NOT an unconnected safe dummy. Driving 46
        // push-pull at boot was a live panel-contention defect in every
        // published Hammer image.
        //
        // NOTE this deliberately does NOT speak for `asic_reset_pin`: DC02's
        // ASIC RESET is GPIO 3 while DC04/DC06's is GPIO 1, and that per-MODEL
        // truth is set in `for_model`. Flattening it would be exactly the "one
        // parameterised family profile" the RE forbids — on a DC02 it would
        // leave the real reset unasserted during vcore bring-up while driving
        // the fan tach line instead.
        if self.is_hammer() {
            return Some(BuckEnableWiring::NotAGpio);
        }
        // Lucky LVxx: 100% stock BitAxe power wiring (R1) — TPS546 EN on
        // GPIO46, ACTIVE-HIGH. These are 12 V boards; the DS4432U GPIO10
        // active-low path would invert fail-closed "power OFF" into rail-ON.
        if self.is_lucky() {
            return Some(BuckEnableWiring::Gpio {
                pin: 46,
                active_low: false,
            });
        }
        // Q1370 / Q1373: the enable is NOT an ESP GPIO at all. VREG_ENABLE is
        // pin 1 of the FXL6408 expander at 0x43 (LDO_ENABLE pin 2, ASIC reset
        // pin 0) — see [`crate::fxl6408_convert`]. Binding GPIO46 here, which
        // is what the derived TPS546 path would have done, would drive an
        // uncharacterized net.
        //
        // This used to return `NotAGpio`, which was true about the GPIO and
        // wrong about the board: it collapsed "the enable is elsewhere" into
        // "there is no enable", and the classifier then refused the board for
        // having no way to cut its rail. It has one — `Q1370B::VREG_enable()`
        // writes expander pin 1 — and the panic hook can reach it with the same
        // bounded I2C write it already performs for the fan. `buck_enable_pin`
        // still normalizes to -1, so the ESP GPIO binder claims nothing and
        // `PANIC_BUCK_GPIO` stays disarmed; the expander is carried separately.
        if self.is_q_series() {
            return Some(BuckEnableWiring::Expander {
                addr: crate::fxl6408_convert::ADDR,
                pin: crate::fxl6408_convert::q_series::VREG_ENABLE,
            });
        }
        match self {
            // NerdAxe: `PWR_EN_PIN = GPIO_NUM_10`, ACTIVE-LOW. Upstream
            // `nerdaxe.cpp` comments it "// inverted" twice — `initBoard` and
            // `setVoltage(0.0)` drive 1 to keep the rail OFF, and only a real
            // setpoint drives 0. This is the one Nerd board whose GPIO10 is
            // inverted relative to the TPS53647 line's `TPS53647_EN_PIN`.
            Self::NerdAxe => Some(BuckEnableWiring::Gpio {
                pin: 10,
                active_low: true,
            }),
            // NerdAxe-γ: no enable GPIO exists. Its `initBoard` overrides the
            // parent's and configures only `BM1370_RST_PIN`; the rail is
            // commanded entirely over TPS546 PMBus. GPIO10 is never selected,
            // never made an output and never driven, so claiming it would put
            // an unconfigured pin in the panic hook's hands.
            Self::NerdAxeGamma => Some(BuckEnableWiring::NotAGpio),
            // BitForge Nano: no enable GPIO exists. `GPIO_ASIC_ENABLE` is
            // #defined in THREE files (`vcore.c:11`, `power.c:8`,
            // `self_test.c:52`) and never driven — a repo-wide search for
            // `gpio_set_level`/`gpio_set_direction`/`gpio_config` returns only
            // the two status LEDs and `GPIO_ASIC_RESET`. The rail is TPS546A24
            // PMBus only, so there is no polarity to guess. Good, because this
            // is the field that reaches the panic hook.
            Self::BitForgeNano => Some(BuckEnableWiring::NotAGpio),
            // BitAxe Naja: no enable GPIO exists, and this one is not merely
            // undriven — it is unwired. `EN_UVLO` carries a fixed 12 V divider
            // (R4 6.04k / R5 649) plus C17 and the two TPS546 EN pins, and
            // NOTHING else; `PWR_EN` (GPIO10) is a dangling net whose only
            // member is the ESP32 pad. Verified from `bitaxeNaja.kicad_pcb`.
            // There is no polarity to guess because there is no pin to drive.
            Self::BitaxeNaja => Some(BuckEnableWiring::NotAGpio),
            // NerdNOS and the TPS53647/TPS53667 multi-phase Nerd line: GPIO10
            // ACTIVE-HIGH. Upstream `nerdqaxeplus.cpp` drives
            // `TPS53647_EN_PIN` to 0 at init and to 1 in `VREG_enable()`;
            // NerdNOS's fixed TPSM863257RDX EN is likewise active-high.
            m if m.is_nerd() => Some(BuckEnableWiring::Gpio {
                pin: 10,
                active_low: false,
            }),
            _ => None,
        }
    }

    /// The I2C bus multiplexer this board's thermal sensor sits behind, if any.
    ///
    /// `None` — the overwhelming majority — means the sensor is on a flat bus
    /// and is reachable directly. `Some` means a channel MUST be selected and
    /// verified before any sensor transaction; see
    /// [`pca9544_convert`](crate::pca9544_convert).
    ///
    /// Declared here rather than branched on at the call site so the next muxed
    /// board is one row, not another `if model == ...`.
    pub fn thermal_i2c_mux(&self) -> Option<ThermalI2cMux> {
        match self {
            // BitForge Nano: two EMC2101s at the part's one hard-wired address,
            // behind a PCA9544A at 0x70. Firmware selects channels 2 and 3; the
            // schematic's live downstream nets are SC2/SD2 (FAN_1_*) and
            // SC3/SD3 (FAN_2_*), confirming the same assignment independently.
            //
            // We declare channel 2 — ASIC 0's controller. Upstream drives BOTH
            // controllers at the SAME duty (`Thermal_setFanSpeedPercent` sets
            // one value on each) and reads the tach from channel 2 only, so one
            // controller at one duty is faithful to the vendor rather than a
            // simplification. The second EMC2101 is unconsumed; promoting to
            // independent per-ASIC fan control is a follow-up.
            Self::BitForgeNano => Some(ThermalI2cMux {
                addr: 0x70,
                channel: 2,
            }),
            _ => None,
        }
    }

    /// NTC thermistors this board reads through ESP32 ADC inputs.
    ///
    /// Empty for every board that carries none, which is all of them but one
    /// today. Declared as a table so the next board with thermistors is a row
    /// rather than another call-site branch — the same shape as
    /// [`Self::thermal_i2c_mux`].
    ///
    /// These are a **board proxy**, not a die reading. The thermistor sits on
    /// the PCB beside the ASIC, so it reads cooler than the junction, and a
    /// consumer must classify it with `board_temp` rather than with
    /// `chip_temp`. Counting it as a die reading would let it satisfy the
    /// THERMAL-BLIND fail-closed check and mask the loss of every real die
    /// sensor.
    pub fn ntc_thermal_channels(&self) -> &'static [NtcChannel] {
        match self {
            // BitForge Nano: TH1/TH2, NTCG103JF103FT1 (TDK 10 k, 0402), each
            // from GND to a node pulled to 3V3 by R68/R73 (10 k). Those nodes
            // land on ESP32 pads 5 and 4 = GPIO5 (ADC1_CH4) and GPIO4
            // (ADC1_CH3) — read from `BitForgeNano.kicad_pcb`, and the vendor
            // firmware's own mapping agrees exactly
            // (`V_TEMP_10K_A1 -> ADC_CHANNEL_4`, `_A2 -> ADC_CHANNEL_3`).
            //
            // `offset_c: 11` is upstream's `return temperature_celsius + 11U`
            // (`adc.c:246`) — an undocumented board calibration with no
            // derivation given. It is carried HERE, as declared board data,
            // rather than inside `ntc_convert`'s physics, so that it is
            // attributable and cannot leak onto a board that never measured it.
            //
            // Upstream reads both of these exactly ONCE, inside `Thermal_init`,
            // into a local whose only other use is a `#ifdef
            // DEBUG_THERMALMONITORING` log — so with debug off, which is the
            // default, the value is dead. There is no runtime thermistor path
            // upstream at all. Ours is a capability the vendor's own firmware
            // does not have, and it matters on this board specifically because
            // every OTHER thermal source here sits behind the PCA9544A.
            Self::BitForgeNano => &[
                NtcChannel {
                    adc1_channel: 4,
                    gpio: 5,
                    offset_c: 11,
                    asic_index: 0,
                },
                NtcChannel {
                    adc1_channel: 3,
                    gpio: 4,
                    offset_c: 11,
                    asic_index: 1,
                },
            ],
            _ => &[],
        }
    }

    /// The TMP451 analog diode mux this board fits, if any.
    ///
    /// `None` for every board without one. `Some` describes hardware that may
    /// or may not be populated on a given unit — see [`Tmp451DiodeMux`] for why
    /// this is an enrichment to probe rather than a declared sensor.
    ///
    /// A table so the next muxed board is a row, not another call-site branch —
    /// the same shape as [`Self::thermal_i2c_mux`] and
    /// [`Self::ntc_thermal_channels`].
    ///
    /// # Two upstream defects this table deliberately does not reproduce
    ///
    /// 1. `Tmp451MuxExp`'s constructor takes `mux_active_high` and **never
    ///    assigns it**; the member has no in-class initializer either, so
    ///    `if (!m_mux_active_high)` reads an indeterminate value. Garbage
    ///    reading false inverts both select lines, which maps channel `k` onto
    ///    ASIC `3-k` — ASIC0 and ASIC3 swap. Only the expander variant is
    ///    affected (the GPIO one initializes correctly), so it hits exactly the
    ///    Q-series rows below. We declare the polarity the caller *intended*.
    /// 2. On the Q-series the select lines are configured as expander outputs
    ///    BEFORE `Fxl6408::init()` runs, and that init issues a software reset
    ///    which clears the direction register. Nothing re-asserts it, so the two
    ///    select pins can be left as inputs — floating, with the mux channel
    ///    undefined. This is why the Q-series rows are declared but NOT wired:
    ///    a reading you cannot attribute to a known ASIC is worse than none.
    pub fn tmp451_diode_mux(&self) -> Option<Tmp451DiodeMux> {
        match self {
            // NerdOCTAXE-γ: TWO sensors, 8 ASICs, ONE shared pair of select
            // lines (GPIO2 = A0, GPIO12 = A1) — so a single select drives both
            // analog paths and each address is then read at that channel.
            // `asic = mux * 4 + ch`, stated explicitly upstream.
            // Polarity comes from the defaulted 4th ctor arg, and that class
            // does initialize the member.
            Self::NerdOctaxeGamma => Some(Tmp451DiodeMux {
                sensors: &[
                    Tmp451Sensor {
                        addr: 0x4C,
                        first_asic: 0,
                        channels: 4,
                    },
                    Tmp451Sensor {
                        addr: 0x4E,
                        first_asic: 4,
                        channels: 4,
                    },
                ],
                select: Tmp451SelectLines::Gpio { a0: 2, a1: 12 },
                active_high: true,
                calibration: Tmp451Calibration::NERD_BM1370,
            }),
            // NerdQX: one sensor, 4 ASICs, channel i -> ASIC i. Polarity is
            // passed explicitly. A0 = GPIO2, A1 = **GPIO3**.
            //
            // Wired on `--features nerdqx` (`temp-tmp451`): `main.rs` binds
            // GPIO2/GPIO3 and the Hammer DC02 gpio3 arm is cfg-gated out of
            // that image. The static row stays clamped; a positive mux
            // bring-up calls [`BoardConfig::apply_nerdqx_tmp451_identity`].
            Self::NerdQX => Some(Tmp451DiodeMux {
                sensors: &[Tmp451Sensor {
                    addr: 0x4C,
                    first_asic: 0,
                    channels: 4,
                }],
                select: Tmp451SelectLines::Gpio { a0: 2, a1: 3 },
                active_high: true,
                calibration: Tmp451Calibration::NERD_BM1370,
            }),
            // Q-series: select lines are FXL6408 expander pins 3/4 at 0x43, not
            // ESP GPIOs. Declared for the record and blocked by defect 2 above.
            // Q1373 is the one board upstream gives its own calibration.
            Self::Q1370 | Self::Q1373 => Some(Tmp451DiodeMux {
                sensors: &[Tmp451Sensor {
                    addr: 0x4C,
                    first_asic: 0,
                    channels: 4,
                }],
                select: Tmp451SelectLines::Expander {
                    addr: 0x43,
                    a0: 3,
                    a1: 4,
                },
                active_high: true,
                calibration: if matches!(self, Self::Q1373) {
                    Tmp451Calibration::Q1373
                } else {
                    Tmp451Calibration::NERD_BM1370
                },
            }),
            _ => None,
        }
    }

    /// Returns true if this is a Hammer BC0x family board.
    ///
    /// Used by `normalize_power_pins` to give the family a deterministic power
    /// path regardless of NVS hardware overrides (same rationale as the
    /// DCENT_axe arm): Hammer regulator EN wiring is UNVERIFIED, so a
    /// misdirected Ds4432u override must never flip GPIO10 to active-low
    /// semantics on these boards.
    pub fn is_hammer(&self) -> bool {
        self.is_hammer_bc() || self.is_hammer_dc()
    }

    /// Hammer **BC0x** (SHA-256, BM1370/BM1373) subset.
    pub fn is_hammer_bc(&self) -> bool {
        matches!(
            self,
            Self::HammerBc01 | Self::HammerBc01Pro | Self::HammerBc02 | Self::HammerBc04
        )
    }

    /// Hammer **DC0x** (Scrypt, MSBT0501) subset.
    ///
    /// ⚠ This predicate exists for family-wide SAFETY decisions only (power-pin
    /// normalisation, capability honesty). It must NEVER be used to select
    /// pins, voltages, reset choreography or peripheral addresses: DC02 and
    /// DC04/DC06 have FIVE output-vs-output GPIO collisions between them
    /// (DC0X_BOARD_RESIDUALS.md §5.4), so those are per-MODEL decisions in
    /// `BoardConfig::for_model`. "Four discrete profiles, no parameterised
    /// family profile" is the standing implementation gate.
    pub fn is_hammer_dc(&self) -> bool {
        matches!(self, Self::HammerDc02 | Self::HammerDc04 | Self::HammerDc06)
    }

    /// Proof-of-work algorithm this board's ASIC computes.
    ///
    /// The Hammer DC0x line is the only Scrypt family in the registry. This is
    /// the single source the board ROW's `pow_algorithm` field is pinned
    /// against, so a row and its model can never disagree.
    pub fn pow_algorithm(&self) -> PowAlgorithm {
        if self.is_hammer_dc() {
            PowAlgorithm::Scrypt1024
        } else {
            PowAlgorithm::Sha256d
        }
    }

    /// Returns true if this is a Lucky Miner LVxx family board.
    ///
    /// Used by `normalize_power_pins` (deterministic stock GPIO46 active-HIGH
    /// EN path regardless of NVS hardware overrides), by the multi-regulator
    /// power path (LV08's three paralleled TPS546 @ 0x24/0x7F/0x14 — the
    /// spec-reserved 0x7F probe must never run on non-Lucky boards), and by
    /// [`resolve_identity`] tests. Deliberately NOT folded into `is_hex()` —
    /// Lucky is one PARALLEL ~1.2 V domain, not a series stack (SPEC §1.1).
    pub fn is_lucky(&self) -> bool {
        matches!(self, Self::LuckyLv06 | Self::LuckyLv07 | Self::LuckyLv08)
    }

    /// Returns true if this board has a multi-ASIC UART daisy chain.
    pub fn is_multi_asic(&self) -> bool {
        self.asic_count() > 1
    }

    /// Whether this board has I2C-programmable voltage control.
    ///
    /// Hammer BC0x: the boards DO have a PMBus-class regulator (BC04's TPS546
    /// output is the whole-stack rail), but its I2C address is not yet
    /// RE-confirmed and no DCENT_OS driver path exists for it — claiming
    /// voltage control here would surface a lying capability descriptor
    /// (`writes_enabled` in capabilities.rs). Flip per-model once the
    /// regulator address + EN wiring are verified.
    pub fn has_voltage_control(&self) -> bool {
        !matches!(self, Self::NerdNOS) && !self.is_hammer()
    }

    /// Operating envelope for a board whose core rail is a TPS53647/TPS53667.
    ///
    /// Declarative hardware description, not per-board code: `PowerManager`
    /// detects the part from its device code and then asks this table for the
    /// envelope. `None` means "this model does not carry a TPS5364x", which is
    /// also the correct answer for a model/part pair that does not exist.
    ///
    /// **Variant-aware on purpose.** The NerdOCTAXE-γ ships BOTH parts across
    /// hardware revisions — a TPS53647 at 4 phases up to rev3.3, a TPS53667 at 6
    /// from rev3.4. Upstream picks between them by reading `VR_DETECT_PIN`
    /// (GPIO3); we take the part's own device code instead, so the same image
    /// serves both revisions with no strap to trust and no pin to claim.
    ///
    /// Every value is the upstream board constructor's, EXCEPT where upstream
    /// sets `ifault` above `imax`. `imax` is the current-sense FULL SCALE, so a
    /// threshold above it is a protection that can never assert — armed on
    /// paper, inert in silicon. `check_iout_fault_limit` refuses those, and the
    /// three affected rows are clamped to `imax` here rather than carried:
    ///
    /// | Model | upstream `ifault` | ours | source |
    /// |---|---|---|---|
    /// | NerdQAxe++ | 95 (`imax + 5`) | 90 | `nerdqaxeplus2.cpp:20` |
    /// | NerdQX | 142 (`decode_m_ifault(3)`) | 90 | `nerdqx.cpp:38` |
    /// | Q1370 / Q1373 | 160 | 123 | `q1370.cpp:21` |
    ///
    /// That is a deliberate divergence from vendor firmware in the safe
    /// direction: it makes the over-current trip real. A board that genuinely
    /// wants the higher threshold must raise `imax` to match, because it is the
    /// sense scale that has to be able to see the current.
    pub fn tps5364x_envelope(
        &self,
        variant: crate::tps5364x_convert::Variant,
    ) -> Option<crate::tps5364x_convert::Tps5364xConfig> {
        use crate::tps5364x_convert::Variant;
        let (num_phases, imax_a, ifault_a) = match (self, variant) {
            // 4x BM1368, 2-phase. nerdqaxeplus.cpp:45-47 (imax = phases * 30).
            (Self::NerdQaxePlus, Variant::Tps53647) => (2u8, 60u16, 55.0f32),
            // 4x BM1370, 3-phase. nerdqaxeplus2.cpp:20-22 — upstream ifault 95.
            (Self::NerdQaxePP, Variant::Tps53647) => (3, 90, 90.0),
            // 8x BM1368, 3-phase. nerdoctaxeplus.cpp:10-12.
            (Self::NerdOctaxePlus, Variant::Tps53647) => (3, 90, 85.0),
            // 8x BM1370. Two revisions, two parts, two envelopes.
            (Self::NerdOctaxeGamma, Variant::Tps53647) => (4, 180, 160.0),
            (Self::NerdOctaxeGamma, Variant::Tps53667) => (6, 240, 235.0),
            // 4x BM1370, 3-phase. nerdqx.cpp:38-40 — upstream ifault 142.
            (Self::NerdQX, Variant::Tps53647) => (3, 90, 90.0),
            // 6x BM1370, 4-phase. nerdhaxegamma.cpp:12-14.
            (Self::NerdHaxeGamma, Variant::Tps53647) => (4, 120, 105.0),
            // 12x BM1370, 6-phase '667. nerdeko.cpp:14-16.
            (Self::NerdEko, Variant::Tps53667) => (6, 240, 235.0),
            // 4x BM1370 / BM1373, 4-phase. q1370.cpp:21-23 — upstream ifault 160.
            (Self::Q1370 | Self::Q1373, Variant::Tps53647) => (4, 123, 123.0),
            _ => return None,
        };
        Some(crate::tps5364x_convert::Tps5364xConfig {
            num_phases,
            imax_a,
            ifault_a,
            // Upstream writes MFR_SPECIFIC_13 = 0x89 on every board, which keeps
            // every phase switching. Shedding is never enabled by the vendor and
            // is not enabled here.
            phase_shedding: false,
            // TPS53667 only (ignored by the '647 path). TPS53667.cpp:89-90:
            // ~300 W input warn, ~336 W input fault at 12 V.
            iin_oc_warn_a: 25.0,
            iin_oc_fault_a: 28.0,
        })
    }

    /// Whether this board has a fan controller.
    pub fn has_fan(&self) -> bool {
        !matches!(self, Self::NerdNOS)
    }

    /// Whether this board has a hardware display (OLED or LCD).
    pub fn has_display(&self) -> bool {
        self.display_kind().has_hardware()
    }

    pub fn display_kind(&self) -> DisplayKind {
        match self {
            Self::NerdNOS => DisplayKind::None,
            // Hammer boards carry a vendor ST7789 LCD (BC04/thor drives a
            // 320x170 panel), but DCENT_OS ships no ST7789 driver — declaring
            // Ssd1306 would be a false hardware claim. Headless until an
            // ST7789 driver exists.
            Self::HammerBc01
            | Self::HammerBc01Pro
            | Self::HammerBc02
            | Self::HammerBc04
            // DC0x carries the SAME ST7789 i80 320x170 panel (byte-verified
            // across five vendor images: DC 7, WR 8, CS 6, D0-7 = 39,40,41,
            // 42,45,46,47,48). Still headless here — no ST7789 driver ships.
            | Self::HammerDc02
            | Self::HammerDc04
            | Self::HammerDc06 => DisplayKind::None,
            Self::NerdAxe
            | Self::NerdAxeGamma
            | Self::NerdQaxePlus
            | Self::NerdQaxePP
            // Both OCTAXE variants drive the same Lilygo T-Display S3 the rest
            // of the Nerd multi-ASIC line uses.
            | Self::NerdOctaxePlus
            | Self::NerdOctaxeGamma
            // NerdQX / NerdHaxe-γ / NerdEKO and the Q-series all inherit the
            // NerdQAxe+ board class, which drives the same T-Display S3.
            // (NerdQX additionally sets `m_flipScreen`; that is a panel
            // orientation detail, not a different display part.)
            | Self::NerdQX
            | Self::NerdHaxeGamma
            | Self::NerdEko
            | Self::Q1370
            | Self::Q1373 => DisplayKind::TDisplayS3,
            Self::Touch | Self::GtTouch => DisplayKind::BapTouch,
            Self::Max
            | Self::Ultra
            | Self::HexUltra
            | Self::Supra
            | Self::HexSupra
            | Self::Gamma
            | Self::GammaDuo
            | Self::GammaTurbo
            | Self::DcentAxeBm1397
            | Self::DcentAxeQuadBm1397
            | Self::DcentAxeHexBm1397
            // Lucky LVxx carries the stock BitAxe SSD1306 OLED @ 0x3C
            // (100% stock pin map — R1 hardware evidence).
            | Self::LuckyLv06
            | Self::LuckyLv07
            | Self::LuckyLv08 => DisplayKind::Ssd1306,
            // BitForge Nano is headless: the README lists two status LEDs and
            // no panel, and the vendor firmware drives only `BLINK_GPIO_1/2`.
            Self::BitForgeNano => DisplayKind::None,
            // BitAxe Naja is headless: the only ESP32 headers on the netlist
            // are J2 (JTAG: GPIO39-42) and J3 (an I2C breakout). No panel.
            Self::BitaxeNaja => DisplayKind::None,
        }
    }

    /// ASIC chip ID expected during detection (read from register 0x00).
    pub fn expected_chip_id(&self) -> u16 {
        match self {
            Self::Max
            | Self::NerdNOS
            | Self::DcentAxeBm1397
            | Self::DcentAxeQuadBm1397
            | Self::DcentAxeHexBm1397 => 0x1397,
            // Lucky LVxx is BM1366 across the whole family (LVXX fork
            // device_config.h:112-114; all six config-lv0x.cvs say BM1366).
            // NerdAxe is BM1366 (upstream `nerdaxe.cpp`: `m_asicModel =
            // "BM1366"`, `m_asics = new BM1366()`), NOT BM1370. It was
            // previously declared 0x1370, which fails chip detection on real
            // hardware — fail-closed, but it meant the board could never mine.
            Self::Ultra
            | Self::HexUltra
            | Self::NerdAxe
            | Self::LuckyLv06
            | Self::LuckyLv07
            | Self::LuckyLv08 => 0x1366,
            // NerdOCTAXE+ inherits the NerdQAxe+ board class upstream, so it is
            // BM1368 across all 8 positions.
            Self::Supra | Self::HexSupra | Self::NerdQaxePlus | Self::NerdOctaxePlus => 0x1368,
            // MSBT0501 has NO 16-bit chip-ID register: enumeration is a
            // broadcast READ of reg 0x10 whose responders are COUNTED, not
            // identity-checked (MSBT0501_PROTOCOL.md §6). 0 is an honest
            // "no chip-ID contract", not a placeholder to compare against.
            Self::HammerDc02 | Self::HammerDc04 | Self::HammerDc06 => 0x0000,
            Self::Gamma
            | Self::GammaDuo
            | Self::GammaTurbo
            | Self::NerdAxeGamma
            | Self::NerdQaxePP
            | Self::NerdOctaxeGamma
            | Self::NerdQX
            | Self::NerdHaxeGamma
            | Self::NerdEko
            | Self::Q1370
            | Self::Touch
            | Self::GtTouch
            | Self::HammerBc01
            | Self::HammerBc02
            | Self::HammerBc04
            // BitForge Nano: `ASIC_BM1370` is the only ASIC in forge-os's enum,
            // and the README/schematic both say BM1370.
            | Self::BitForgeNano => 0x1370,
            // PROVEN (BM1373_DOSSIER.md): real BM1373 silicon reports 0x1372,
            // not the 0x1373 part number. The BM1373 driver's accept logic
            // admits both; this metadata reports the silicon truth. Q1373 is
            // the same silicon on the Q1370 board.
            // BitAxe Naja carries the same silicon: board-labelled "BM1340",
            // community-named BM1373, answers 0x1372 on the wire.
            Self::HammerBc01Pro | Self::Q1373 | Self::BitaxeNaja => 0x1372,
        }
    }

    /// Whether this variant ships the BAP accessory header populated + the
    /// stock Touch / Turbo Touch LVGL board attached. Firmware uses this to
    /// decide whether to start the BAP UART server and to adjust self-test
    /// flow (auto-reboot after pass because no reset button is reachable).
    pub fn has_bap(&self) -> bool {
        matches!(
            self,
            Self::Touch
                | Self::GtTouch
                // Every DCENT_axe board ships the BAP accessory header populated.
                | Self::DcentAxeBm1397
                | Self::DcentAxeQuadBm1397
                | Self::DcentAxeHexBm1397
        )
    }

    /// Status-LED hardware kind (M-7, FULL_PREFAB_REVIEW_2026-07-11).
    ///
    /// `Sk6812` ONLY for the DCENT_axe BM1397 single board, whose 2026-07-11
    /// netlist confirms D1 = SK6812MINI-E on GPIO4. Quad/Hex stay `PlainGpio`
    /// until their own netlists exist (no speculative claims). NOTE: this is
    /// honest metadata, not a shipped driver — see [`StatusLedKind`] and
    /// `docs/STATUS_LED_SK6812_GAP.md`.
    pub fn status_led_kind(&self) -> StatusLedKind {
        match self {
            Self::DcentAxeBm1397 => StatusLedKind::Sk6812,
            _ => StatusLedKind::PlainGpio,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerControllerKind {
    None,
    Tps546,
    Ds4432u,
    /// TPS53647 / TPS53667 multi-phase PMBus VRM (Nerd multi-ASIC boards).
    ///
    /// Which of the two parts is fitted is resolved at runtime from the device
    /// code — see `tps5364x_convert::Variant::from_device_code`. The board row
    /// declares only that the rail is multi-phase, never which member, because
    /// the NerdOCTAXE-γ ships both across hardware revisions.
    ///
    /// Unlike [`Self::Tps546`], this kind does NOT by itself satisfy
    /// `has_trusted_thermal_source_configured`: the TPS546 path earns thermal
    /// trust from a characterized on-die sensor reading, and no Nerd board
    /// carrying a TPS5364x has had that reading validated against real hardware.
    /// Those boards must declare a real `temp_sensor` to become mining-capable.
    Tps5364x,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FanControllerKind {
    None,
    Emc2101,
    Emc2103,
    Emc2302,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TempSensorKind {
    None,
    Emc2101,
    Tmp1075,
    Emc2103,
    /// TMP451 / ADT7461-family remote-diode sensor, optionally behind a 2-bit
    /// analog mux fanning one sensor across four ASIC diodes.
    ///
    /// For a board whose ONLY thermal source is a TMP451. The Nerd multi-ASIC
    /// boards are NOT this: they all carry TMP1075s and declare
    /// [`Self::Tmp1075`], with the TMP451 mux — present only on the newer
    /// revisions — probed at runtime as a per-ASIC enrichment. Declaring a
    /// sensor that only some revisions fit would claim thermal trust an older
    /// board cannot honour.
    Tmp451,
}

/// Source-level capability ceiling for a power, fan, or temperature kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentKindCapabilityState {
    /// A driver exists, but the exact board revision and safe runtime
    /// composition are admitted by the board profile/runtime path, not by the
    /// enum identity.
    SourceDriverModelScoped,
    /// A driver exists only as optional per-revision enrichment; no shipping
    /// row may treat the component as universally populated.
    SourceDriverRevisionOptional,
    /// Typed absence/fallback identity.
    NoComponentFallback,
}

/// Exact, non-authorizing source capability record for one component kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentKindCapability {
    pub component_kind: &'static str,
    pub state: ComponentKindCapabilityState,
    pub implementation: &'static str,
    pub exact_board_revision_verified: bool,
    pub catalog_runtime_authorized: bool,
    pub catalog_mutation_authorized: bool,
    pub catalog_thermal_trust_authorized: bool,
}

/// Exhaustive capability ceiling for [`PowerControllerKind`].
pub const POWER_CONTROLLER_KIND_CAPABILITIES: &[ComponentKindCapability] = &[
    ComponentKindCapability {
        component_kind: "None",
        state: ComponentKindCapabilityState::NoComponentFallback,
        implementation: "typed absence",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
    ComponentKindCapability {
        component_kind: "Tps546",
        state: ComponentKindCapabilityState::SourceDriverModelScoped,
        implementation: "power::Tps546",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
    ComponentKindCapability {
        component_kind: "Ds4432u",
        state: ComponentKindCapabilityState::SourceDriverModelScoped,
        implementation: "power::Ds4432u",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
    ComponentKindCapability {
        component_kind: "Tps5364x",
        state: ComponentKindCapabilityState::SourceDriverModelScoped,
        implementation: "power::Tps5364x",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
];

/// Exhaustive capability ceiling for [`FanControllerKind`].
pub const FAN_CONTROLLER_KIND_CAPABILITIES: &[ComponentKindCapability] = &[
    ComponentKindCapability {
        component_kind: "None",
        state: ComponentKindCapabilityState::NoComponentFallback,
        implementation: "typed absence",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
    ComponentKindCapability {
        component_kind: "Emc2101",
        state: ComponentKindCapabilityState::SourceDriverModelScoped,
        implementation: "fan::Emc2101",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
    ComponentKindCapability {
        component_kind: "Emc2103",
        state: ComponentKindCapabilityState::SourceDriverModelScoped,
        implementation: "fan::Emc2103",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
    ComponentKindCapability {
        component_kind: "Emc2302",
        state: ComponentKindCapabilityState::SourceDriverModelScoped,
        implementation: "fan::Emc2302",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
];

/// Exhaustive capability ceiling for [`TempSensorKind`].
pub const TEMP_SENSOR_KIND_CAPABILITIES: &[ComponentKindCapability] = &[
    ComponentKindCapability {
        component_kind: "None",
        state: ComponentKindCapabilityState::NoComponentFallback,
        implementation: "typed absence",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
    ComponentKindCapability {
        component_kind: "Emc2101",
        state: ComponentKindCapabilityState::SourceDriverModelScoped,
        implementation: "temp::Emc2101",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
    ComponentKindCapability {
        component_kind: "Tmp1075",
        state: ComponentKindCapabilityState::SourceDriverModelScoped,
        implementation: "temp::Tmp1075",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
    ComponentKindCapability {
        component_kind: "Emc2103",
        state: ComponentKindCapabilityState::SourceDriverModelScoped,
        implementation: "temp::Emc2103",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
    ComponentKindCapability {
        component_kind: "Tmp451",
        state: ComponentKindCapabilityState::SourceDriverRevisionOptional,
        implementation: "tmp451_convert plus runtime mux enrichment",
        exact_board_revision_verified: false,
        catalog_runtime_authorized: false,
        catalog_mutation_authorized: false,
        catalog_thermal_trust_authorized: false,
    },
];

#[cfg(test)]
mod component_kind_capability_tests {
    use super::*;

    fn assert_non_authorizing(rows: &[ComponentKindCapability], expected_len: usize) {
        assert_eq!(rows.len(), expected_len);
        let kinds: std::collections::BTreeSet<&str> =
            rows.iter().map(|row| row.component_kind).collect();
        assert_eq!(kinds.len(), rows.len());
        for row in rows {
            assert!(!row.exact_board_revision_verified);
            assert!(!row.catalog_runtime_authorized);
            assert!(!row.catalog_mutation_authorized);
            assert!(!row.catalog_thermal_trust_authorized);
        }
    }

    #[test]
    fn component_kind_capability_tables_are_exhaustive_and_non_authorizing() {
        assert_non_authorizing(POWER_CONTROLLER_KIND_CAPABILITIES, 4);
        assert_non_authorizing(FAN_CONTROLLER_KIND_CAPABILITIES, 4);
        assert_non_authorizing(TEMP_SENSOR_KIND_CAPABILITIES, 5);

        let tmp451 = TEMP_SENSOR_KIND_CAPABILITIES
            .iter()
            .find(|row| row.component_kind == "Tmp451")
            .unwrap();
        assert_eq!(
            tmp451.state,
            ComponentKindCapabilityState::SourceDriverRevisionOptional
        );
        for rows in [
            POWER_CONTROLLER_KIND_CAPABILITIES,
            FAN_CONTROLLER_KIND_CAPABILITIES,
            TEMP_SENSOR_KIND_CAPABILITIES,
        ] {
            assert_eq!(
                rows.iter()
                    .find(|row| row.component_kind == "None")
                    .unwrap()
                    .state,
                ComponentKindCapabilityState::NoComponentFallback
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisplayKind {
    None,
    Ssd1306,
    TDisplayS3,
    BapTouch,
}

impl DisplayKind {
    pub fn has_hardware(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessoryMode {
    None,
    BapTouch,
    W5500Lan,
}

/// Status-LED hardware kind (M-7, FULL_PREFAB_REVIEW_2026-07-11).
///
/// Most boards wire a plain push-pull LED to the status-LED GPIO. The
/// DCENT_axe BM1397 single board instead places an SK6812MINI-E addressable
/// one-wire LED (D1) on GPIO4 — driving it push-pull (today's `GpioController`
/// path) never lights it, because SK6812 needs the RMT-timed one-wire
/// protocol. This enum is HONEST METADATA ONLY: the RMT driver is NOT shipped
/// (it is esp-idf/xtensa-only and cannot be host-verified — see
/// `docs/STATUS_LED_SK6812_GAP.md`), and `main.rs` still drives GPIO4
/// push-pull on every board (electrically harmless on an SK6812 DIN pin; the
/// LED simply stays dark).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatusLedKind {
    /// Plain push-pull GPIO LED (every stock BitAxe / Nerd board).
    PlainGpio,
    /// SK6812MINI-E addressable one-wire LED — needs an RMT driver the
    /// firmware does not ship yet (documented gap, LED stays dark).
    Sk6812,
}

/// Retained proof level for a board-version row.
///
/// This is intentionally separate from [`BitAxeModel::support_status`]:
/// `supported` means the firmware supports the board class, while this field
/// records the strongest retained evidence artifact. Do not infer soak proof
/// from a support label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiveProof {
    None,
    Host,
    FocusedRun,
    SustainedSoak,
}

impl LiveProof {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Host => "host",
            Self::FocusedRun => "focused-run",
            Self::SustainedSoak => "sustained-soak",
        }
    }
}

/// Explicit hardware overrides migrated from ESP-Miner custom-board NVS keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardHardwareConfig {
    pub plug_sense: bool,
    pub asic_enable: bool,
    pub fan_controller: FanControllerKind,
    pub temp_sensor: TempSensorKind,
    pub power_controller: PowerControllerKind,
    pub has_ina260: bool,
    pub emc_internal_temp: bool,
    pub emc_ideality_factor: u8,
    pub emc_beta_compensation: u8,
    pub temp_offset_c: i8,
    pub power_consumption_target_w: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardVersionProfile {
    pub board_version: &'static str,
    pub device_model: &'static str,
    pub asic_model: &'static str,
    pub model: BitAxeModel,
    pub live_proof: LiveProof,
    pub fan_controller: FanControllerKind,
    pub temp_sensor: TempSensorKind,
    pub power_controller: PowerControllerKind,
    pub has_ina260: bool,
    pub emc_internal_temp: bool,
    pub emc_ideality_factor: u8,
    pub emc_beta_compensation: u8,
    pub temp_offset_c: i8,
    pub power_consumption_target_w: u16,
    /// Pass-5 audit: per ESP-Miner PR #1616 (`33d7210`), some boards have
    /// the EMC2103 internal/external temp readings physically swapped on
    /// the silicon. Currently true only for v801 GT. Consumers should swap
    /// `chip_temp` and `board_temp` when this is set, regardless of which
    /// fan/temp controller they're using.
    pub temp_flip: bool,
    /// Proof-of-work algorithm the board's ASIC mines (P1 Scrypt seam,
    /// docs/SCRYPT_STACK_DESIGN.md §4.5). Every existing row is `Sha256d`
    /// (pinned by `every_profile_row_is_sha256d_in_p1`); `Scrypt1024` rows
    /// arrive with the Hammer DC0x lane (P3) once the vendor NVS
    /// `boardversion` strings are RE-captured. The Scrypt stack is
    /// fail-closed until P2, so a Scrypt row cannot mine even if added.
    pub pow_algorithm: PowAlgorithm,
}

impl BoardVersionProfile {
    pub const ALL: [BoardVersionProfile; 57] = [
        Self {
            board_version: "2.2",
            device_model: "max",
            asic_model: "BM1397",
            model: BitAxeModel::Max,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "102",
            device_model: "max",
            asic_model: "BM1397",
            model: BitAxeModel::Max,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "0.11",
            device_model: "ultra",
            asic_model: "BM1366",
            model: BitAxeModel::Ultra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            emc_internal_temp: true,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "201",
            device_model: "ultra",
            asic_model: "BM1366",
            model: BitAxeModel::Ultra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            emc_internal_temp: true,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "202",
            device_model: "ultra",
            asic_model: "BM1366",
            model: BitAxeModel::Ultra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            emc_internal_temp: true,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "203",
            device_model: "ultra",
            asic_model: "BM1366",
            model: BitAxeModel::Ultra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            emc_internal_temp: true,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "204",
            device_model: "ultra",
            asic_model: "BM1366",
            model: BitAxeModel::Ultra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            emc_internal_temp: true,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "205",
            device_model: "ultra",
            asic_model: "BM1366",
            model: BitAxeModel::Ultra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            emc_internal_temp: true,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "207",
            device_model: "ultra",
            asic_model: "BM1366",
            model: BitAxeModel::Ultra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "302",
            device_model: "hex",
            asic_model: "BM1366",
            model: BitAxeModel::HexUltra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 10,
            power_consumption_target_w: 40,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "303",
            device_model: "hex",
            asic_model: "BM1366",
            model: BitAxeModel::HexUltra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 10,
            power_consumption_target_w: 40,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "400",
            device_model: "supra",
            asic_model: "BM1368",
            model: BitAxeModel::Supra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            emc_internal_temp: true,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "401",
            device_model: "supra",
            asic_model: "BM1368",
            model: BitAxeModel::Supra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            emc_internal_temp: true,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "402",
            device_model: "supra",
            asic_model: "BM1368",
            model: BitAxeModel::Supra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 8,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "403",
            device_model: "supra",
            asic_model: "BM1368",
            model: BitAxeModel::Supra,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 8,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "600",
            device_model: "gamma",
            asic_model: "BM1370",
            model: BitAxeModel::Gamma,
            live_proof: LiveProof::FocusedRun,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x24,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 19,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "601",
            device_model: "gamma",
            asic_model: "BM1370",
            model: BitAxeModel::Gamma,
            live_proof: LiveProof::FocusedRun,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x24,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 19,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "602",
            device_model: "gamma",
            asic_model: "BM1370",
            model: BitAxeModel::Gamma,
            live_proof: LiveProof::FocusedRun,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x24,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 22,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            // Gamma 603 — BM1370, hardware config identical to 602 (EMC2101 +
            // TPS546, ideality 0x24, 22 W target). Added for board-version parity
            // with ESP-Miner master `device_config.h`, which added 603 after our
            // vendored clone snapshot. Lets DCENT_OS auto-identify a 603 Gamma
            // flashed from stock AxeOS instead of falling back to the default.
            board_version: "603",
            device_model: "gamma",
            asic_model: "BM1370",
            model: BitAxeModel::Gamma,
            live_proof: LiveProof::FocusedRun,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x24,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 22,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "650",
            device_model: "gammaduo",
            asic_model: "BM1370",
            model: BitAxeModel::GammaDuo,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x24,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 35,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "701",
            device_model: "suprahex",
            asic_model: "BM1368",
            model: BitAxeModel::HexSupra,
            live_proof: LiveProof::FocusedRun,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 10,
            power_consumption_target_w: 90,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "702",
            device_model: "suprahex",
            asic_model: "BM1368",
            model: BitAxeModel::HexSupra,
            live_proof: LiveProof::FocusedRun,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 10,
            power_consumption_target_w: 90,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "801",
            device_model: "gammaturbo",
            asic_model: "BM1370",
            model: BitAxeModel::GammaTurbo,
            live_proof: LiveProof::FocusedRun,
            fan_controller: FanControllerKind::Emc2103,
            temp_sensor: TempSensorKind::Emc2103,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x24,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 36,
            temp_flip: true,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // ── DCENT_axe BM1397 family (D-Central) ──
        // Single 1x — EMC2101 fan/temp like the BitAxe Max, but the power path
        // is a TPS546D24A PMBus VRM at 0x24 (EN on GPIO10, ACTIVE-HIGH) with NO
        // DS4432U and NO INA260 — verified from the dcent-axe-BM1397 schematic
        // netlist (PREFAB_DESIGN_REVIEW_2026-07-08 R-10). The old Ds4432u +
        // has_ina260 row made `normalize_power_pins` treat GPIO10 as active-LOW,
        // which inverted fail-closed "power OFF" into driving the VRM rail ON.
        //
        // LEGACY ALIAS — the canonical board_version is `9010` (see the 9###
        // registry rows below; BOARD_VERSION_REGISTRY.md §5 migration
        // 900→9010 / 910→9040 / 920→9060). These 3-digit rows are kept so any
        // NVS blob written before the migration still resolves; no fabricated
        // board reports them (Phase 0), and `default_for_model` now points at
        // the canonical 9### rows.
        Self {
            board_version: "900",
            device_model: "dcentaxe_bm1397",
            asic_model: "BM1397",
            model: BitAxeModel::DcentAxeBm1397,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // Quad 4x — single UART daisy chain, EMC2302 dual fan + TPS546 (Hex-class
        // power/fan/temp pairing) with a single parallel voltage domain.
        Self {
            board_version: "910",
            device_model: "dcentaxe_quad_bm1397",
            asic_model: "BM1397",
            model: BitAxeModel::DcentAxeQuadBm1397,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 10,
            power_consumption_target_w: 48,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // Hex 6x — single UART daisy chain, EMC2302 dual fan + TPS546, 3 series
        // voltage domains (mirrors the Hex Ultra / Hex Supra topology).
        Self {
            board_version: "920",
            device_model: "dcentaxe_hex_bm1397",
            asic_model: "BM1397",
            model: BitAxeModel::DcentAxeHexBm1397,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 10,
            power_consumption_target_w: 72,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // ── DCENT_axe `9###` registry rows (CANONICAL — BOARD_VERSION_REGISTRY.md §5) ──
        // Wired live 2026-07-11 (operator-authorized, FULL_PREFAB_REVIEW_2026-07-11
        // H-3): the dcent-axe-BM1397 hardware self-describes `board_version=9010`
        // in its board_config.json, so provisioning must resolve it here instead
        // of falling back to the model default / "custom board" lab bypass.
        // Encoding is `9 C F R` (9=DCENT_axe namespace, C=0 BM1397, F=ASIC count,
        // R=rev 0). Electrical profiles are byte-identical to the legacy
        // 900/910/920 rows above (same boards, renumbered — clean Phase-0 rename).
        // Keep these rows byte-parallel with the toolbox mirror
        // `dcent-toolbox/.../core/board_catalog.py` `ESP_BOARD_VERSION_PROFILES`.
        //
        // 9010 — DCENT_axe BM1397 Single (canonical for legacy 900).
        Self {
            board_version: "9010",
            device_model: "dcentaxe_bm1397",
            asic_model: "BM1397",
            model: BitAxeModel::DcentAxeBm1397,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 12,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // 9040 — DCENT_axe Quad BM1397 (canonical for legacy 910).
        Self {
            board_version: "9040",
            device_model: "dcentaxe_quad_bm1397",
            asic_model: "BM1397",
            model: BitAxeModel::DcentAxeQuadBm1397,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 10,
            power_consumption_target_w: 48,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // 9060 — DCENT_axe Hex BM1397 (canonical for legacy 920).
        Self {
            board_version: "9060",
            device_model: "dcentaxe_hex_bm1397",
            asic_model: "BM1397",
            model: BitAxeModel::DcentAxeHexBm1397,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 10,
            power_consumption_target_w: 72,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // ── Hammer BC0x rows (EXPERIMENTAL — Hammer RE wave 2026-07-27) ──
        // CANONICAL board_version strings are the 4-digit `3XXX` third-party
        // namespace (operator-approved, Lucky-enablement SPEC §2.2 — 3-digit
        // `1xx`-`8xx` stays OSMU/BitAxe-owned, so 4-digit `3001`/`3011`/
        // `3002`/`3004` cannot collide with any upstream numeric row). The
        // original DCENT-minted `hammer-*` strings are kept below as ALIAS
        // rows because DCENT_OS itself may have written one into a bench
        // unit's NVS. The vendor firmware is ESP-Miner-derived and stores its
        // own NVS `boardversion` values, which the RE lane has NOT yet
        // captured; when captured, add the vendor strings as additional rows
        // (the way ESP-Miner's 600-603 values were) — do not repurpose these.
        //
        // fan/temp/power = None is deliberate and HONEST: no Hammer peripheral
        // is drivable yet (BC01 fan is SoC LEDC PWM — not our shipping path;
        // temp is a TMP75 at 0x49/0x4D — no driver at those addresses; the
        // regulator I2C address is unconfirmed on every BC0x). Consequence:
        // `BoardConfig::validate()` fails "mining-capable board requires a
        // trusted temperature source", so mining is REFUSED fail-closed while
        // the board still boots, identifies, and serves the dashboard.
        Self {
            board_version: "3001",
            device_model: "hammer_bc01",
            asic_model: "BM1370",
            model: BitAxeModel::HammerBc01,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::None,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 25,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // BC01 Pro — ⚠ no firmware image held; vendor web-UI numbers only.
        Self {
            board_version: "3011",
            device_model: "hammer_bc01_pro",
            asic_model: "BM1373",
            model: BitAxeModel::HammerBc01Pro,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::None,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 45,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // BC02 — ⚠ no firmware image held; series topology per family rule.
        Self {
            board_version: "3002",
            device_model: "hammer_bc02",
            asic_model: "BM1370",
            model: BitAxeModel::HammerBc02,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::None,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 50,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // BC04 (`thor`) — best-evidenced Hammer board (full driver RE'd).
        Self {
            board_version: "3004",
            device_model: "hammer_bc04",
            asic_model: "BM1370",
            model: BitAxeModel::HammerBc04,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::None,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 100,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // ── Hammer legacy-string ALIAS rows (`hammer-*` → canonical 3XXX) ──
        // These strings were DCENT-invented before the 3XXX renumber; nothing
        // vendor-side ever carried them, but DCENT_OS itself may have written
        // one into a bench unit's NVS, so they stay resolvable byte-identical
        // to the canonical rows (same pattern as the DCENT_axe 900→9010
        // migration). Pinned by `legacy_hammer_aliases_resolve_identically`.
        Self {
            board_version: "hammer-bc01",
            device_model: "hammer_bc01",
            asic_model: "BM1370",
            model: BitAxeModel::HammerBc01,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::None,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 25,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "hammer-bc01-pro",
            device_model: "hammer_bc01_pro",
            asic_model: "BM1373",
            model: BitAxeModel::HammerBc01Pro,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::None,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 45,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "hammer-bc02",
            device_model: "hammer_bc02",
            asic_model: "BM1370",
            model: BitAxeModel::HammerBc02,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::None,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 50,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "hammer-bc04",
            device_model: "hammer_bc04",
            asic_model: "BM1370",
            model: BitAxeModel::HammerBc04,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::None,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 100,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // ── Hammer DC0x rows (EXPERIMENTAL — Scrypt, enablement wave 2026-07-27) ──
        // CANONICAL board_version strings continue the operator-approved 4-digit
        // `3XXX` Hammer namespace with a `31XX` sub-range for the DC (Scrypt)
        // line: 3102 / 3104 / 3106. No legacy alias rows exist — unlike BC0x,
        // no DCENT-minted DC string was ever written to a bench unit's NVS.
        // Vendor NVS `boardversion` values are NOT yet captured; when they are,
        // add them as ADDITIONAL rows, never repurpose these.
        //
        // 🔴 THESE ARE THE FIRST NON-SHA-256 ROWS IN THE REGISTRY:
        // `pow_algorithm: Scrypt1024`, `asic_model: "MSBT0501"`.
        //
        // 🔴 fan/temp/power capabilities are HONEST, not aspirational:
        //   * temp_sensor = None on every row — the identity/board sensor is a
        //     TMP75 (DC02 @0x48, DC04 @0x4C, DC06 @0x4F) and DCENT_OS ships NO
        //     TMP75 driver. It is also only a BOARD-proxy sensor, never a die
        //     temperature (R7 die-blindness), so it could not be trusted as the
        //     sole thermal source even once a driver exists.
        //   * power_controller = None on every row — the part IS a TPS546 @0x24,
        //     but DC02 puts it on I2C **bus 1** (SDA 11 / SCL 12) which this HAL
        //     has no concept of, DC02 uses ULINEAR16 encoding + the SHORT init
        //     path while DC04/DC06 use LINEAR11 + the LONG path, and the VIN
        //     thresholds are UNKNOWN. Declaring Tps546 would ALSO satisfy
        //     `has_trusted_thermal_source_configured()` and thereby PERMIT
        //     mining — the opposite of what the evidence supports.
        //   * fan_controller: DC04/DC06 genuinely drive an **EMC2302 @0x2E**
        //     whose register map (duty 0x30/0x40, tach 0x3E/0x3F AND 0x4E/0x4F,
        //     RPM = 3932160/count) matches the shipped `emc2302.rs` exactly, so
        //     that is declared truthfully. DC02's fan is SoC LEDC PWM 2 + PCNT
        //     tach 1 — not our shipping fan path — so it stays None.
        //
        // Net effect: `BoardConfig::validate()` returns
        // "mining-capable board requires a trusted temperature source" on all
        // three, so mining is REFUSED FAIL-CLOSED while the board still boots,
        // identifies and serves the dashboard. That is the intended outcome:
        // a board that boots and refuses to mine is fine; a board that mines at
        // a wrong voltage is not.
        Self {
            board_version: "3102",
            device_model: "hammer_dc02",
            asic_model: "MSBT0501",
            model: BitAxeModel::HammerDc02,
            live_proof: LiveProof::None,
            fan_controller: FanControllerKind::None,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 50,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Scrypt1024,
        },
        Self {
            board_version: "3104",
            device_model: "hammer_dc04",
            asic_model: "MSBT0501",
            model: BitAxeModel::HammerDc04,
            live_proof: LiveProof::None,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 100,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Scrypt1024,
        },
        Self {
            board_version: "3106",
            device_model: "hammer_dc06",
            asic_model: "MSBT0501",
            model: BitAxeModel::HammerDc06,
            live_proof: LiveProof::None,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 100,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Scrypt1024,
        },
        // ── Lucky Miner LVxx rows (EXPERIMENTAL — enablement wave 2026-07-27) ──
        // CANONICAL board_version strings are the operator-approved 4-digit
        // `2XXX` third-party namespace (SPEC §2.1): 2006/2007/2008. The
        // vendor's literal "300"/"301"/"302" strings CANNOT be adopted —
        // "302" collides head-on with the genuine BitAxe Hex Ultra row above
        // (a linear first-match `find` would resolve a 9-chip LV08 as a
        // 6-chip 3-series-domain Hex: a safety event). Inbound vendor
        // identities are handled by [`resolve_identity`] instead.
        //
        // live_proof is deliberately `None` (SPEC §8): no Lucky hardware is
        // on any bench; nothing here may be described as live-proven.
        // Peripherals map to already-shipped drivers: EMC2302 @0x2F,
        // 2x TMP1075 @0x4A/0x4B (temp_offset +5), TPS546 PMBus VRM.
        // NOTE (SPEC §7 ordering): because these rows declare Tmp1075 +
        // Tps546 they PASS BoardConfig::validate() — the rows must only land
        // together with the §3/§4/§5/§6 safety work in the same commit.
        Self {
            board_version: "2006",
            device_model: "lv06",
            asic_model: "BM1366",
            model: BitAxeModel::LuckyLv06,
            live_proof: LiveProof::None,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 40,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "2007",
            device_model: "lv07",
            asic_model: "BM1366",
            model: BitAxeModel::LuckyLv07,
            live_proof: LiveProof::None,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 40,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // LV08: 9x BM1366, three paralleled TPS546 @ 0x24/0x7F/0x14, 140 W.
        Self {
            board_version: "2008",
            device_model: "lv08",
            asic_model: "BM1366",
            model: BitAxeModel::LuckyLv08,
            live_proof: LiveProof::None,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 140,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // ── Nerd multi-ASIC + Q-series rows (EXPERIMENTAL — 2026-07-28) ──
        //
        // CANONICAL board_version strings are the `4XXX` third-party namespace,
        // allocated here on the same principle as Hammer's `3XXX` and Lucky's
        // `2XXX`: these boards announce NO distinct board_version of their own.
        // Upstream's whole Nerd multi-ASIC line inherits `m_version = 501` from
        // NerdQaxePlus (502 on a rev7 NerdQAxe++), so the only identity they
        // publish is the `m_deviceModel` string — which is exactly what
        // `from_device_model` matches on. `40NN` = Nerd-branded, `43NN` =
        // Q-series (NN from the ASIC part number).
        //
        // The NerdQAxe+/++/OCTAXE rows USED to borrow BitAxe profiles
        // ("402"/"601") as a starting shape. That wart is gone: `4006`-`4009`
        // below are their canonical rows (IMPLEMENTATION_QUEUE rank 41).
        //
        // live_proof is `Host` — the same level as the Hammer BC0x rows and for
        // the same reason. No Nerd or Q-series hardware is on any bench, so
        // nothing here is live-proven; what DOES exist is host-level evidence,
        // because the host gate exercises these rows and the TPS5364x /
        // TMP1075 / FXL6408 math their envelopes depend on. Promotion past
        // `Host` requires a real retained run artifact, never a row edit.
        // temp_offset_c carries the upstream die-vs-board correction, which is
        // ADDED (`main.rs`: `t + temp_offset_c`) and therefore over-reports —
        // the safe direction for a cutoff.
        Self {
            board_version: "4001",
            device_model: "NerdQX",
            asic_model: "BM1370",
            model: BitAxeModel::NerdQX,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps5364x,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            // NerdQaxePlus2::getTemperature adds 10 °C: the TMP1075 reads the
            // board, not the die, and the die is hotter.
            temp_offset_c: 10,
            power_consumption_target_w: 240,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "4002",
            device_model: "NerdHaxe-Gamma",
            asic_model: "BM1370",
            model: BitAxeModel::NerdHaxeGamma,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps5364x,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 10,
            power_consumption_target_w: 250,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // NerdEKO: 12x BM1370 on a SIX-phase TPS53667. The regulator family is
        // the same declaration as every other row here — both parts answer at
        // 0x71 and `Tps5364x::identify` reads the device code before any write.
        Self {
            board_version: "4003",
            device_model: "NerdEKO",
            asic_model: "BM1370",
            model: BitAxeModel::NerdEko,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps5364x,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 10,
            power_consumption_target_w: 350,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // ── The four boards that used to BORROW a BitAxe row (rank 41) ──
        //
        // `NerdQAxe+`/`++` and the OCTAXE pair resolved through BitAxe "402"
        // (Supra) and "601" (Gamma) as a "starting shape", with `for_model`
        // overriding the three fields that were obviously wrong (fan → EMC2302,
        // VRM → TPS5364x, temp → TMP1075). Everything the override did NOT
        // reach was inherited silently, and three of those inherited values
        // were WRONG in the unsafe or dishonest direction:
        //
        //   * `live_proof` — "601" carries `FocusedRun`, a real BitAxe **Gamma**
        //     bench result. `support_status()` says these boards have no live
        //     hardware on any bench. The rows now say `Host`, the same level
        //     and the same reason as their `4001`-`4003` siblings above.
        //   * `power_consumption_target_w` — 8 W / 19 W inherited, against
        //     upstream `m_maxPin` values of 70 / 100 / 130 / 250 W.
        //   * `temp_offset_c` — 0 inherited on all four, but the two boards
        //     that derive from `NerdQaxePlus2` add +10 °C. Under-reporting a
        //     die temperature is the UNSAFE direction.
        //
        // Values are read from the vendor's own firmware for these exact
        // boards,
        // NOT from the BitAxe rows they replace. The class hierarchy is what
        // decides `temp_offset_c`, so it is stated per row.
        //
        // `emc_ideality_factor` / `emc_beta_compensation` are INERT on all four
        // and are not a claim about this hardware: no EMC2101 is fitted. That
        // part appears in the upstream tree ONLY under
        // `main/boards/drivers/nerdaxe/`, i.e. on the two single-ASIC boards.
        // The values carried are the same inert pair the `4001`-`4003` sibling
        // rows carry, so the family stays uniform; they are only ever written
        // on an EMC2101/EMC2103 temperature path, which these boards do not
        // have. Likewise `has_ina260: false` is EVIDENCE, not a default —
        // INA260 also appears only under `drivers/nerdaxe/`.
        //
        // NOTE the deliberate absence: frequency, voltage, the voltage window,
        // `voltage_domains` and `power_offset_w` are NOT profile fields. They
        // live in `BoardConfig::for_model` and were already sourced from these
        // same constructors. This migration does not move one of them.
        Self {
            // NerdQAxe+ — `nerdqaxeplus.cpp:27-56`. 4x BM1368, 2-phase
            // TPS53647, 12 V in.
            board_version: "4006",
            device_model: "NerdQAxe+",
            // `m_asicModel = "BM1368"` (:31). Same string the borrowed "402"
            // happened to carry — correct there by coincidence, sourced here.
            asic_model: "BM1368",
            model: BitAxeModel::NerdQaxePlus,
            live_proof: LiveProof::Host,
            // `#include "EMC2302.h"` (:17), `EMC2302_init` (:114),
            // `m_numFans = 2` (:49).
            fan_controller: FanControllerKind::Emc2302,
            // `#include "TMP1075.h"` (:18), `TMP1075_read_temperature` (:296).
            temp_sensor: TempSensorKind::Tmp1075,
            // TPS53647, `m_numPhases = 2` (:45), `m_imax = 60` (:46).
            power_controller: PowerControllerKind::Tps5364x,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            // ZERO, and this is the load-bearing difference from `4007`/`4009`:
            // `NerdQaxePlus::getTemperature` (:305-311) returns the TMP1075
            // reading unmodified. The +10 °C correction belongs to the
            // `NerdQaxePlus2` subclass, and this board is the BASE class.
            temp_offset_c: 0,
            // `m_maxPin = 70.0` (:53). The borrowed "402" said 8.
            power_consumption_target_w: 70,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            // NerdQAxe++ — `nerdqaxeplus2.cpp:16-41`. 4x BM1370, 3-phase
            // TPS53647, 12 V in.
            //
            // ⚠ A rev7 NerdQAxe++ is a DIFFERENT board: `m_version = 502`
            // (:64), TPS546 driven as two SERIES domains, `m_maxPin = 120`
            // (:66). Upstream detects it with an I2C probe (`probeRev7Buck`).
            // This row is the non-rev7 board only, and a rev7 unit must not be
            // energized from it — rev7 detection is separately BLOCKED
            // (queue section 0, H8 G-9).
            board_version: "4007",
            device_model: "NerdQAxe++",
            asic_model: "BM1370", // `m_asicModel` (:18)
            model: BitAxeModel::NerdQaxePP,
            // Was `FocusedRun`, inherited from the BitAxe Gamma row "601".
            // That was a Gamma bench result wearing this board's name.
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            // `m_numPhases = 3` (:20), `m_imax = 90` (:21).
            power_controller: PowerControllerKind::Tps5364x,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            // `NerdQaxePlus2::getTemperature` (:199-206) adds 10 °C, because
            // the TMP1075 reads the board and the die is hotter. The offset is
            // ADDED by `main.rs` (`t + temp_offset_c`) and therefore
            // over-reports — the safe direction for a cutoff. The borrowed
            // "601" carried 0, i.e. it under-reported this board by 10 °C.
            temp_offset_c: 10,
            // `m_maxPin = 100.0` (:38). The borrowed "601" said 19.
            power_consumption_target_w: 100,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            // NerdOCTAXE+ — `nerdoctaxeplus.cpp:6-21`. 8x BM1368, 3-phase
            // TPS53647. `NerdOctaxePlus : public NerdQaxePlus`
            // (`nerdoctaxeplus.h:5`), so it inherits the BASE thermal path.
            board_version: "4008",
            device_model: "NerdOCTAXE+",
            // Inherited from `NerdQaxePlus()`; the subclass constructor does
            // not reassign `m_asicModel`.
            asic_model: "BM1368",
            model: BitAxeModel::NerdOctaxePlus,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            // `m_numPhases = 3` (:10), `m_imax = 90` (:11).
            power_controller: PowerControllerKind::Tps5364x,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            // Zero for the same reason as `4006`: this class derives from
            // `NerdQaxePlus`, NOT `NerdQaxePlus2`, and adds no offset of its
            // own. Do not "make the OCTAXE pair consistent" by copying the
            // γ's 10 — the pair genuinely differs, one class apart.
            temp_offset_c: 0,
            // `m_maxPin = 130.0` (:18). The borrowed "402" said 8.
            power_consumption_target_w: 130,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            // NerdOCTAXE-γ — `nerdoctaxegamma.cpp:19-86`. 8x BM1370.
            // `NerdOctaxeGamma : public NerdQaxePlus2`
            // (`nerdoctaxegamma.h:15`).
            //
            // ⚠ TWO power stages ship under this ONE name. The constructor
            // branches: rev 3.4 is a 6-phase TPS53667 (`m_imax = 240` :59,
            // `m_maxPin = 300.0` :61, and upstream raises defaults to 700 MHz /
            // 1210 mV :75-76); rev <=3.3 is a 4-phase TPS53647 (`m_imax = 180`
            // :83, `m_maxPin = 250.0` :85). This row declares the CONSERVATIVE
            // 4-phase envelope, matching `BoardConfig::for_model`. The 6-phase
            // numbers are only valid once the TPS53667 has been positively
            // identified by its device code at bring-up.
            board_version: "4009",
            // ASCII, following `4002` ("NerdHaxe-Gamma") rather than upstream's
            // literal "NerdOCTAXE-γ".
            device_model: "NerdOCTAXE-Gamma",
            asic_model: "BM1370", // `m_asicModel` (:21)
            model: BitAxeModel::NerdOctaxeGamma,
            // Was `FocusedRun`, inherited from "601" — same laundering as
            // `4007`. Both revisions of this board are unbenched.
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            // TMP1075 only. Newer revisions additionally carry two TMP451s
            // behind an analog mux for true per-die temps, but that is probed
            // at runtime as an enrichment and is deliberately NOT declared
            // here — a declared sensor is a promise EVERY revision must keep.
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps5364x,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            // +10 °C: derives `NerdQaxePlus2`, so it inherits that class's
            // `getTemperature` override. The borrowed "601" carried 0.
            temp_offset_c: 10,
            // `m_maxPin = 250.0` (:85) — the 4-phase branch. NOT the 300 W the
            // rev-3.4 branch sets. The borrowed "601" said 19.
            power_consumption_target_w: 250,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // NerdNOS — the fifth rank-41 board, and the one whose borrow was doing
        // the most damage. It resolved to BitAxe Max row "102", which asserted
        // an EMC2101 fan controller, an EMC2101 temperature sensor, a DS4432U
        // voltage DAC and an INA260 on a board that has NONE of those four.
        //
        // ⚠ EVIDENCE GRADE: SECONDARY, SINGLE-SOURCE. This is the weakest
        // evidence position of ANY row in this table — weaker than BitAxe Naja,
        // which at least has a held KiCad project. The sole source is
        //
        // (authored 2026-03-23), which SAYS it read the `benjamin-wilson/
        // NerdNOS` KiCad schematics (`NerdNOS.kicad_sch` / `bm1397.kicad_sch` /
        // `T_Display_S3.kicad_sch` / `power.kicad_sch`) — but WE DO NOT HOLD
        // THOSE FILES. They exist in this tree only as filenames inside that
        // document. There is no NerdNOS firmware either: the upstream Nerd
        // firmware we do hold has twelve board classes and none of them is a
        // NerdNOS. Do not upgrade this row's `live_proof`, and do not describe
        // any value here as schematic-verified.
        //
        // ⚠ THE NAME IS CONTESTED.
        // fork/01-ECOSYSTEM-DOSSIER.md:277-280`, the DOMINANT "NerdNOS" is a
        // headless ESP32-S3 SOFTWARE miner with no ASIC at all (KH/s); a
        // separate BM1397 ASIC stick is ALSO marketed as "TheNerdNOS" by third
        // parties. This row describes the latter. That ambiguity is a second,
        // independent reason the row must stay fail-closed.
        //
        // What the document DOES state, and what this row is built from, is its
        // "Key Difference from BitAxe Max" section (:117-122) — a point-by-point
        // falsification of the row this board was borrowing:
        //
        //   * "No TPS546 buck regulator (uses TPSM863257RDX instead)"
        //   * "No DS4432U DAC (voltage is fixed, not I2C-programmable?)"
        //   * "No INA260 power monitor mentioned"
        //   * "No EMC2101 fan controller (no fan on NerdNOS — passive/USB
        //     powered)", restated at :154 "NerdNOS has no fan"
        //
        // Read those quotes exactly as written. Two are HEDGED by their own
        // author — "not I2C-programmable?" carries the question mark, and "No
        // INA260 ... mentioned" is absence-of-evidence, not evidence-of-absence.
        // Every field below is `None`/false anyway, which is the fail-closed
        // reading of a hedge; a later editor must not read the hedge the other
        // way and promote a part into this row.
        //
        // ⚠ The same document contradicts itself once: its pin table at :44-52
        // is headed "NerdNOS / NerdAxe" and merges the two boards, so its
        // "Fan PWM | TBD | Via EMC2101 on I2C" line describes the NerdAxe. Two
        // explicit prose statements (:121, :154) say this board has no fan; one
        // merged table cell says TBD. The prose wins, and `for_model` already
        // agrees by setting fan_pwm_pin/fan_tach_pin to -1.
        //
        // ⚠ THIS ROW MAKES THE BOARD REFUSE TO MINE, and that is the point.
        // `temp_sensor: None` + `power_controller: None` means
        // `has_trusted_thermal_source_configured()` is false and `validate()`
        // returns "mining-capable board requires a trusted temperature source"
        // — the identical fail-closed posture the Hammer rows carry, for the
        // identical reason: the board's only thermal source is a 10 kOhm NTC on
        // the BM1397's TEMP_P/TEMP_N pins (:115) and no NTC transport ships
        // (`ntc_convert` is declared and unwired, see the BitForge notes).
        //
        // It is NOT a regression. This board could not mine BEFORE either — the
        // borrowed "102" is in `plug_sense()`, while `buck_enable_wiring()`
        // forces `plug_sense_pin` to -1 for every `is_nerd()` model, so main.rs
        // took its `_ => false` arm and blocked mining with
        // "Power input not detected by plug-sense gate". The board was refused
        // for a reason that was not true. Now it is refused for one that is.
        //
        // ⚠ THREE CLAIMS ELSEWHERE IN OUR SOURCE THAT NO HELD EVIDENCE
        // SUPPORTS. All three are OUTSIDE this row, and all three are left
        // alone deliberately — this row's job was identity, and "correcting" an
        // electrical value from a single secondary document would repeat the
        // exact mistake it exists to undo. Recorded so the next reader does not
        // mistake any of them for something that was checked:
        //   1. `BoardConfig::for_model` fixes this board at 1200 mV. The
        //      document reads the TPSM863257RDX feedback divider (R12 = 40.2k,
        //      R13 = 30k) as **1.4 V** to the BM1397 core (:105-107). Raising a
        //      rail on one secondary source is the unsafe direction, so this is
        //      reported, not changed.
        //   2. `BoardConfig::for_model` defaults this board to 400 MHz. That
        //      number appears NOWHERE in the corpus — not in this document, and
        //      it is not the BitAxe Max default either (425 MHz / 1400 mV). It
        //      is unattributed.
        //   3. `buck_enable_wiring()` gives every `is_nerd()` model GPIO10
        //      ACTIVE-HIGH, and its comment asserts "NerdNOS's fixed
        //      TPSM863257RDX EN is likewise active-high". The document says
        //      GPIO10 "polarity TBD" (:84) — a TBD that was silently upgraded
        //      to a polarity. That value is stored into `PANIC_BUCK_ACTIVE_LOW`
        //      and read by the panic hook, which is exactly the field the
        //      NerdAxe correction was about. Getting it backwards drives the
        //      rail ON at the moment thermal supervision stops.
        Self {
            board_version: "4010",
            device_model: "NerdNOS",
            // 1x BM1397 (:10, :99, :109). Note the residual doubt recorded in
            // DCENT_OS_ESP/ is about the FIRMWARE lineage (the
            // `WantClue/NerdMiner_v2` `nerdnos` branch does not implement
            // BM1397 control); the HARDWARE claim is carried by the KiCad
            // schematics above, which are a different and better source.
            asic_model: "BM1397",
            model: BitAxeModel::NerdNOS,
            live_proof: LiveProof::Host,
            // No fan exists. `for_model` already sets fan_pwm_pin/fan_tach_pin
            // to -1; the borrowed row was declaring a fan CONTROLLER anyway.
            fan_controller: FanControllerKind::None,
            // NTC thermistor only, and no NTC transport ships. Declaring a
            // sensor is a promise; this board cannot keep one yet.
            temp_sensor: TempSensorKind::None,
            // Fixed-output TPSM863257RDX power module. There is nothing to
            // command: no PMBus part, no current DAC. `has_voltage_control()`
            // already returns false for this model, so the two now agree.
            power_controller: PowerControllerKind::None,
            has_ina260: false,
            // No EMC2101 is fitted, so these three are inert. 0x00 is the
            // "do not write" sentinel `main.rs` honours (it gates BOTH the
            // ideality and the beta write) — the same choice row `4004` makes,
            // and the correct one for a board with no such part at all. The
            // borrowed "102" carried 0x12, a real BitAxe Max calibration.
            emc_internal_temp: false,
            emc_ideality_factor: 0x00,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            // "~8W (USB-C)" (:10). The borrowed "102" said 12 — a BitAxe Max
            // figure for a USB-powered board with no fan.
            power_consumption_target_w: 8,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // Q-series: same rail and thermal topology as the Nerd line, but ASIC
        // reset / VREG enable / LDO enable are behind an FXL6408 I2C port
        // expander at 0x43 (see `fxl6408_convert`). Q1370B::getTemperature
        // applies a smaller +3 °C correction than the Nerd boards' +10.
        Self {
            board_version: "4370",
            device_model: "Q1370",
            asic_model: "BM1370",
            model: BitAxeModel::Q1370,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps5364x,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 3,
            power_consumption_target_w: 150,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "4373",
            device_model: "Q1373",
            asic_model: "BM1373",
            model: BitAxeModel::Q1373,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2302,
            temp_sensor: TempSensorKind::Tmp1075,
            power_controller: PowerControllerKind::Tps5364x,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 3,
            power_consumption_target_w: 180,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // ── NerdAxe single-ASIC pair ──
        //
        // These two used to be ONE row (`NerdAxe`) that borrowed BitAxe profile
        // "601" and described neither board: it claimed BM1370 + TPS546 (the γ)
        // under the name NerdAxe (BM1366 + DS4432U), at a 525 MHz default that
        // is neither board's number.
        //
        // They get `4XXX` rows for the same reason the multi-ASIC line does:
        // upstream's `m_version` values (204 for NerdAxe, 200 for the γ) sit
        // inside the BitAxe Ultra namespace, and "204" is ALREADY a real BitAxe
        // Ultra profile in this table. Publishing the vendor number would
        // collide two different boards onto one row.
        Self {
            board_version: "4004",
            device_model: "NerdAxe",
            asic_model: "BM1366",
            model: BitAxeModel::NerdAxe,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            // DS4432U current-DAC steering a TPS40305 — the stock BitAxe
            // Ultra/Max power stage, NOT the TPS546 the old row claimed.
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            // `EMC2101_get_internal_temp() + 5` — this board reads the
            // controller's own die, not an external diode, so the external
            // diode ideality/beta are never configured upstream. 0 ideality is
            // the "do not write" sentinel `main.rs` honours (it gates BOTH the
            // ideality and beta writes), which keeps us byte-faithful.
            emc_internal_temp: true,
            emc_ideality_factor: 0x00,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            // Upstream `m_maxPin = 15.0`.
            power_consumption_target_w: 15,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        Self {
            board_version: "4005",
            device_model: "NerdAxeGamma",
            asic_model: "BM1370",
            model: BitAxeModel::NerdAxeGamma,
            live_proof: LiveProof::Host,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: false,
            // EMC2101 EXTERNAL diode (real ASIC junction), so no offset:
            // `EMC2101_set_ideality_factor(EMC2101_IDEALITY_1_0319)` = 0x24 and
            // `EMC2101_set_beta_compensation(EMC2101_BETA_11)` = 0x00, both
            // byte-verified in `main/boards/drivers/nerdaxe/EMC2101.h`. The
            // internal+5 path exists upstream only before `m_isInitialized`.
            emc_internal_temp: false,
            emc_ideality_factor: 0x24,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            // Upstream `m_maxPin = 25.0`.
            power_consumption_target_w: 25,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // BitForge Nano — a new vendor, so it opens its own century in the
        // `4XXX` D-Central space (Nerd holds 400x, the Q-series 43xx). The
        // vendor publishes no board-version string at all: forge-os identifies
        // the board by a compile-time `BITFORGE_NANO` enum, so there is no
        // number to collide with and none to inherit.
        Self {
            board_version: "4100",
            device_model: "BitForgeNano",
            asic_model: "BM1370",
            model: BitAxeModel::BitForgeNano,
            live_proof: LiveProof::Host,
            // TWO EMC2101s, one per ASIC, reachable only through the PCA9544A
            // at 0x70 on channels 2/3. `FanControllerKind`/`TempSensorKind` are
            // one kind per board, which is faithful here: upstream's
            // `Thermal_setFanSpeedPercent` selects channel 2, sets a duty, then
            // selects channel 3 and sets the SAME duty. Declaring one Emc2101
            // at one duty matches the vendor exactly. The hardware supports
            // independent per-ASIC fans (`FAN_1_*`/`FAN_2_*` in the schematic);
            // promoting to that is a follow-up, not a claim made here.
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            // TPS546A24, 12 V -> 1.2 V over PMBus (`TPS546_CONFIG_NANO`,
            // forge-os `vcore.c:15`).
            power_controller: PowerControllerKind::Tps546,
            // INA260 monitors total board V/I (README; forge-os `power.c`).
            has_ina260: true,
            // EMC2101 EXTERNAL diode: `Thermal_getAsicChipTemp` returns
            // `EMC2101_getExternalTemp()` (`ThermalMonitoring.c:103`), so each
            // controller reads its own ASIC's junction and there is no offset.
            emc_internal_temp: false,
            // `EMC2101_setIdealityFactor(EMC2101_IDEALITY_1_0566)` = 0x37
            // (`EMC2101.h:80`). NOT the 0x24 / `1_0319` the BitAxe Gamma and
            // NerdAxe-γ use — this is a board-specific diode calibration and
            // must not be inherited from the Gamma shape it otherwise
            // resembles.
            emc_ideality_factor: 0x37,
            // `EMC2101_setBetaCompensation(EMC2101_BETA_11)` = 0x00
            // (`EMC2101.h:8`).
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            // `BITFORGE_NANO_MAX_POWER 60` (forge-os `power.c:15`). The README
            // separately recommends a >=70 W supply, i.e. headroom over this.
            power_consumption_target_w: 60,
            temp_flip: false,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
        // BitAxe Naja — allocated in the `4XXX` D-Central space for the same
        // reason as the BitForge above, but note the reason is *stronger* here:
        // bitaxeorg DOES own a board-version namespace (2.2, 0.11, 1xx-8xx),
        // and this prototype has no number in it because no firmware ships. A
        // number invented inside their range could collide with a real future
        // bitaxeorg string, so we stay out of it entirely.
        Self {
            board_version: "4200",
            device_model: "BitaxeNaja",
            // Board silkscreen says "BM1340". That is not a part number — see
            // `BitAxeModel::BitaxeNaja`. We record the silicon we actually
            // drive, which is the same one `Q1373` above declares.
            asic_model: "BM1373",
            model: BitAxeModel::BitaxeNaja,
            live_proof: LiveProof::Host,
            // ONE EMC2103-2 (U13) carrying BOTH ASIC diodes natively — this
            // board needs no mux, unlike the BitForge above: the EMC2103-2 has
            // two external channels, and DP1/DN1 + DP2/DN2 are each wired to
            // one ASIC. Fan PWM/tach are generated by the EMC2103 and run
            // straight to J7; the ESP32 has no fan pin at all.
            fan_controller: FanControllerKind::Emc2103,
            temp_sensor: TempSensorKind::Emc2103,
            // TWO TPS546D24A (U1 + U4) stacked as a 2-phase rail: they share
            // VSHARE, SYNC and the BCX_CLK/BCX_DAT stacking link, and L1/L2
            // both land on `/Vcore`. U1 is the PMBus master (SDA_VR/SCL_VR/
            // ALRT_VR/PGOOD); U4's PMBus pins are strapped to AGND2, which is
            // the documented stacked-secondary configuration. One rail, one
            // PMBus address to command.
            power_controller: PowerControllerKind::Tps546,
            // No INA260 on the board. The only current-sense part in the repo
            // (NCS21671, `Supply.kicad_sch`) is on an ORPHAN sheet — the root
            // schematic instantiates ASIC/ESP32/Power/fan only, and no
            // NCS21671 footprint is placed on the PCB. Board power comes from
            // the TPS546's own PMBus telemetry.
            has_ina260: false,
            // EMC2103 EXTERNAL diodes (real ASIC junctions), so no offset.
            emc_internal_temp: false,
            // `EMC2101_IDEALITY_1_0566` = 0x37. Sourced, not inherited: the
            // vendor's own BM1373 board sets `set_temp_cal(1.06f, ...)`
            // (`ESP-Miner-NerdQAxePlus/main/boards/q1373.cpp`), i.e. a measured
            // BM1373 diode ideality of 1.06. 0x37 is the nearest tabulated
            // value BELOW that (0x38 = 1.0579 is numerically closer but sits
            // above it) — assuming a lower ideality than the truth reports
            // temperature slightly HIGH, which is the fail-safe direction on a
            // board whose only over-temp response is firmware.
            emc_ideality_factor: 0x37,
            emc_beta_compensation: 0x00,
            // Deliberately NOT the vendor's -25.4 C. `q1373.cpp` applies that
            // offset to a TMP451 on a different board with different diode
            // routing; carrying it here would bias every reading 25 C LOW on a
            // board with no hardware thermal trip. 0 reports hot, which is the
            // safe error.
            temp_offset_c: 0,
            // Q1373 is `m_maxPin = 180.0` for FOUR of these dies; Naja carries
            // two, so half. Not a measurement — no Naja has ever run.
            power_consumption_target_w: 90,
            // Same crossing as the GT: the chip-1 diode is on External2.
            // R34 ties A1's TEMP1_P to DP2, and R29 ties A2's TEMP2_P to DP1.
            temp_flip: true,
            pow_algorithm: PowAlgorithm::Sha256d,
        },
    ];

    pub fn all() -> &'static [BoardVersionProfile] {
        &Self::ALL
    }

    pub fn plug_sense(&self) -> bool {
        matches!(
            self.board_version,
            "2.2" | "102" | "0.11" | "201" | "202" | "203" | "204" | "205" | "400" | "401"
        )
    }

    pub fn asic_enable(&self) -> bool {
        matches!(
            self.board_version,
            "2.2" | "102" | "0.11" | "201" | "202" | "203" | "205" | "400" | "401"
        )
    }

    /// Row-declared fail-closed tach-proof capability (Lucky enablement wave,
    /// closing the R2 §13.4 gap: `requires_fan_tach()` was `is_hex() ||
    /// Emc2103`, so a 140 W nine-die LV08 got NO mandatory fan proof while the
    /// 40 W Hex Ultra did).
    ///
    /// This is a per-row CAPABILITY declaration (same architecture as
    /// [`plug_sense`](Self::plug_sense) / [`asic_enable`](Self::asic_enable)),
    /// consumed ADDITIVELY by [`BoardConfig::requires_fan_tach`] — it can only
    /// ADD boards to the mandatory-tach set, never remove the inherent
    /// Hex/EMC2103 requirements, and it deliberately does not touch the
    /// XPSAFE-7 operator opt-in `fan_tach_present` (which keeps its
    /// "operator-asserted" meaning).
    ///
    /// Declared rows:
    /// - `2008` (Lucky LV08): 140 W, nine parallel BM1366 dies on one rail,
    ///   dual-channel EMC2302 — the highest-dissipation ESP board in the
    ///   registry; a stalled fan here is the exact failure XPSAFE exists for.
    /// - `2007` (Lucky LV07): 40 W two-die board in the same power class as
    ///   the Hex Ultra (40 W), which already requires proof; the LVXX family
    ///   ships the dual-channel EMC2302 with tach wiring as stock, no live
    ///   unit has ever been bench-proven, and Experimental tier defaults to
    ///   the fail-closed posture (worst case is a safe mining refusal).
    /// - `2006` (Lucky LV06) is deliberately NOT declared: single die whose
    ///   real dissipation is Ultra/Gamma-class (the 40 W row value is the
    ///   family PSU rating, not measured single-chip draw); no shipping
    ///   single-chip board requires tach proof today, and the XPSAFE-7
    ///   operator opt-in remains available.
    ///
    /// The exact required set is pinned by
    /// `mandatory_tach_set_is_exactly_the_declared_boards` — extend that test
    /// consciously when declaring a new row here.
    pub fn fan_tach_required(&self) -> bool {
        matches!(self.board_version, "2007" | "2008")
    }

    /// Read-only board-identity strap address for registered Hammer DC rows.
    ///
    /// The TMP75-compatible device is used only as an address strap. It is not
    /// a trusted thermal source and deliberately does not change
    /// [`TempSensorKind`]. Keeping this as row-owned capability metadata means
    /// a custom NVS hardware override cannot forge or reroute identity.
    pub fn identity_strap_addr(&self) -> Option<u8> {
        match self.board_version {
            "3102" => Some(0x48),
            "3104" => Some(0x4C),
            "3106" => Some(0x4F),
            _ => None,
        }
    }

    pub fn display_kind(&self) -> DisplayKind {
        self.model.display_kind()
    }

    pub fn find(board_version: &str) -> Option<&'static Self> {
        let normalized = board_version.trim();
        Self::ALL
            .iter()
            .find(|profile| profile.board_version == normalized)
    }

    pub fn default_for_model(model: BitAxeModel) -> &'static Self {
        match model {
            BitAxeModel::Max => Self::find("102").unwrap(),
            BitAxeModel::Ultra => Self::find("207").unwrap(),
            BitAxeModel::HexUltra => Self::find("302").unwrap(),
            BitAxeModel::Supra => Self::find("402").unwrap(),
            BitAxeModel::HexSupra => Self::find("701").unwrap(),
            BitAxeModel::Gamma => Self::find("601").unwrap(),
            BitAxeModel::GammaDuo => Self::find("650").unwrap(),
            BitAxeModel::GammaTurbo => Self::find("801").unwrap(),
            // Touch variants reuse the underlying mining board profile;
            // BAP is a purely orthogonal accessory.
            BitAxeModel::Touch => Self::find("601").unwrap(),
            BitAxeModel::GtTouch => Self::find("801").unwrap(),
            // Canonical `4010` (queue rank 41). Was "102", the BitAxe Max row,
            // which asserted an EMC2101, a DS4432U and an INA260 this board
            // does not carry — see the row for the schematic citation.
            BitAxeModel::NerdNOS => Self::find("4010").unwrap(),
            // Canonical rows of their own — the "601" this used to borrow
            // described the γ's TPS546 stage, on a BM1366 DS4432U board.
            BitAxeModel::NerdAxe => Self::find("4004").unwrap(),
            BitAxeModel::NerdAxeGamma => Self::find("4005").unwrap(),
            // Canonical `4XXX` rows (queue rank 41). These four used to borrow
            // the BitAxe row that matched their ASIC (402 = BM1368-class,
            // 601 = BM1370-class) "purely as a starting shape", which also
            // handed them a BitAxe Gamma `live_proof`, an 8/19 W power target
            // and a 0 °C die-temp offset. They are NOT the BitAxe boards those
            // profiles name and no longer resolve to them.
            BitAxeModel::NerdQaxePlus => Self::find("4006").unwrap(),
            BitAxeModel::NerdQaxePP => Self::find("4007").unwrap(),
            BitAxeModel::NerdOctaxePlus => Self::find("4008").unwrap(),
            BitAxeModel::NerdOctaxeGamma => Self::find("4009").unwrap(),
            // Canonical `4XXX` rows of their own — unlike the borrowed
            // "402"/"601" above, these rows describe the actual board.
            BitAxeModel::NerdQX => Self::find("4001").unwrap(),
            BitAxeModel::NerdHaxeGamma => Self::find("4002").unwrap(),
            BitAxeModel::NerdEko => Self::find("4003").unwrap(),
            BitAxeModel::Q1370 => Self::find("4370").unwrap(),
            BitAxeModel::Q1373 => Self::find("4373").unwrap(),
            // Canonical `9###` registry rows (BOARD_VERSION_REGISTRY.md §5
            // migration 900→9010 / 910→9040 / 920→9060). The legacy 3-digit
            // rows stay resolvable via `find` for pre-migration NVS blobs.
            BitAxeModel::DcentAxeBm1397 => Self::find("9010").unwrap(),
            BitAxeModel::DcentAxeQuadBm1397 => Self::find("9040").unwrap(),
            BitAxeModel::DcentAxeHexBm1397 => Self::find("9060").unwrap(),
            // Hammer BC0x canonical 3XXX rows (the legacy `hammer-*` strings
            // stay resolvable via `find` as byte-identical alias rows).
            BitAxeModel::HammerBc01 => Self::find("3001").unwrap(),
            BitAxeModel::HammerBc01Pro => Self::find("3011").unwrap(),
            BitAxeModel::HammerBc02 => Self::find("3002").unwrap(),
            BitAxeModel::HammerBc04 => Self::find("3004").unwrap(),
            BitAxeModel::HammerDc02 => Self::find("3102").unwrap(),
            BitAxeModel::HammerDc04 => Self::find("3104").unwrap(),
            BitAxeModel::HammerDc06 => Self::find("3106").unwrap(),
            // Lucky LVxx canonical 2XXX rows (SPEC §2.1). The vendor's own
            // "300"/"301"/"302" strings resolve via `resolve_identity`, not
            // via these defaults.
            BitAxeModel::LuckyLv06 => Self::find("2006").unwrap(),
            BitAxeModel::LuckyLv07 => Self::find("2007").unwrap(),
            BitAxeModel::LuckyLv08 => Self::find("2008").unwrap(),
            BitAxeModel::BitForgeNano => Self::find("4100").unwrap(),
            BitAxeModel::BitaxeNaja => Self::find("4200").unwrap(),
        }
    }

    pub fn infer(board_version: &str, device_model: &str, asic_model: &str) -> &'static Self {
        if let Some(profile) = Self::find(board_version) {
            return profile;
        }

        let model_hint = device_model.trim().to_ascii_lowercase();
        let asic_hint = asic_model.trim().to_ascii_uppercase();

        match model_hint.as_str() {
            "2.2" | "max" => Self::find("102").unwrap(),
            "0.11" | "ultra" => {
                if asic_hint == "BM1366" {
                    Self::find("201").unwrap()
                } else {
                    Self::find("207").unwrap()
                }
            }
            "hex" | "hexultra" | "ultrahex" => Self::find("302").unwrap(),
            "supra" => {
                if asic_hint == "BM1368" {
                    Self::find("402").unwrap()
                } else {
                    Self::find("400").unwrap()
                }
            }
            "suprahex" => Self::find("701").unwrap(),
            "gamma" => Self::find("601").unwrap(),
            "gammaduo" => Self::find("650").unwrap(),
            "gammaturbo" | "gt" => Self::find("801").unwrap(),
            _ => {
                warn!(
                    "Unknown board version '{}' (device_model='{}', asic_model='{}'), using model default",
                    board_version, device_model, asic_model
                );
                if let Some(model) = BitAxeModel::from_device_model(device_model) {
                    return Self::default_for_model(model);
                }
                match asic_hint.as_str() {
                    "BM1397" => Self::find("102").unwrap(),
                    "BM1368" => Self::find("402").unwrap(),
                    "BM1370" => Self::find("601").unwrap(),
                    _ => Self::find("201").unwrap(),
                }
            }
        }
    }
}

/// Verdict of the fail-closed inbound identity resolution
/// ([`resolve_identity`], Lucky-enablement SPEC §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityVerdict {
    /// The identity tuple resolves unambiguously to exactly one profile row.
    Resolved(BoardVersionProfile),
    /// The tuple matches a known Lucky-vs-BitAxe collision pattern and CANNOT
    /// be resolved from NVS strings alone. When `probe_lv08` is set the caller
    /// may disambiguate by probing PMBus addresses `0x7F` and `0x14`
    /// (read-only): BOTH answering is the LV08 three-regulator signature,
    /// NEITHER answering means genuine BitAxe (SPEC §3 step 4). If the probe
    /// is unavailable or inconclusive the caller MUST refuse to energize
    /// (boot, identify, serve the dashboard — but no mining; SPEC §3 step 5,
    /// matching the Hammer fail-closed precedent).
    Ambiguous {
        reason: &'static str,
        probe_lv08: bool,
    },
    /// No rung of the ladder recognized the tuple.
    Unknown,
}

/// Fail-closed inbound identity disambiguation (Lucky-enablement SPEC §3).
///
/// **A Lucky Miner does not announce itself honestly.** Two distinct NVS
/// identities exist in the field:
///
/// | unit state | `boardversion` | `devicemodel` | `minermodel` |
/// |---|---|---|---|
/// | stock Lucky factory FW  | `402`          | `supra` | `LV08` |
/// | unlocked (mrbonkerz LVXX) | `302` / `302A` | `lv08`  | absent |
///
/// Resolving on `board_version` alone would identify a stock LV08 as a BitAxe
/// Supra (wrong chip/count) and an unlocked LV08 as a Hex Ultra — whose
/// 3-series-domain path drives a multiple of 1.2 V onto nine PARALLEL dies.
/// This resolver therefore takes the whole `(boardversion, devicemodel,
/// minermodel)` tuple and applies the SPEC §3 precedence EXACTLY:
///
/// 1. `miner_model` present and Lucky-recognized (`LV06`/`LV07`/`LV08`,
///    case-insensitive) ⇒ Lucky, authoritative (the vendor's own key and the
///    most reliable signal).
/// 2. `device_model` ∈ {`lv06`,`lv07`,`lv08`} ⇒ Lucky.
///    (SPEC §1.2 corollary rung: the A-suffixed vendor boardversions
///    `300A`/`301A`/`302A` are minted ONLY by the LVXX fork — genuine BitAxe
///    never writes them — so they resolve directly to the Lucky rows; the
///    `A` means anonymous `mining.subscribe` only, handled by the caller's
///    `anonymous_subscribe` config flag, never as separate board rows.)
/// 3. `board_version` ∈ {`302`,`303`} with `device_model` NOT hex, **or**
///    `402` with a `miner_model` present (a genuine BitAxe never writes
///    `minermodel` at all) ⇒ [`IdentityVerdict::Ambiguous`] with
///    `probe_lv08: true`.
/// 4. (caller) on Ambiguous: probe PMBus `0x7F` + `0x14` — both answer ⇒
///    LV08; neither ⇒ genuine BitAxe.
/// 5. (caller) still ambiguous ⇒ REFUSE TO ENERGIZE (fail-closed).
///
/// Non-collision tuples fall through to the normal ladder
/// (`find(board_version)`, then `from_device_model` → model default).
///
/// Pure string logic — no I2C, no NVS, fully host-testable. The caller
/// (`nvs_config.rs` wiring) owns the probe and the fail-closed refusal.
pub fn resolve_identity(
    board_version: &str,
    device_model: &str,
    miner_model: &str,
) -> IdentityVerdict {
    fn lucky_row(key: &str) -> Option<&'static BoardVersionProfile> {
        match key {
            "lv06" => BoardVersionProfile::find("2006"),
            "lv07" => BoardVersionProfile::find("2007"),
            "lv08" => BoardVersionProfile::find("2008"),
            _ => None,
        }
    }

    let bv = board_version.trim();
    let dm = device_model.trim().to_ascii_lowercase();
    let mm = miner_model.trim().to_ascii_lowercase();

    // Step 1: minermodel — the Lucky vendor's own NVS key; authoritative.
    if !mm.is_empty() {
        if let Some(profile) = lucky_row(mm.as_str()) {
            return IdentityVerdict::Resolved(*profile);
        }
    }

    // Step 2: devicemodel ∈ {lv06, lv07, lv08}.
    if let Some(profile) = lucky_row(dm.as_str()) {
        return IdentityVerdict::Resolved(*profile);
    }

    // SPEC §1.2 rung: A-suffixed vendor boardversions are LVXX-fork-only
    // spellings (2b71114 "anoymous version") — unambiguously Lucky.
    match bv.to_ascii_lowercase().as_str() {
        "300a" => return IdentityVerdict::Resolved(*BoardVersionProfile::find("2006").unwrap()),
        "301a" => return IdentityVerdict::Resolved(*BoardVersionProfile::find("2007").unwrap()),
        "302a" => return IdentityVerdict::Resolved(*BoardVersionProfile::find("2008").unwrap()),
        _ => {}
    }

    // Step 3: the two collision patterns — AMBIGUOUS, caller must probe.
    // "devicemodel NOT hex": any spelling that resolves to the genuine Hex
    // Ultra ("hex"/"hexultra"/…) counts as hex-consistent; an unlocked LVXX
    // unit always writes "lv08" (already resolved in step 2) and a stock
    // Lucky writes "supra", so this direction stays fail-closed.
    let dm_is_hex = matches!(
        BitAxeModel::from_device_model(&dm),
        Some(BitAxeModel::HexUltra)
    );
    if (bv == "302" || bv == "303") && !dm_is_hex {
        return IdentityVerdict::Ambiguous {
            reason: "boardversion 302/303 without a hex devicemodel: genuine BitAxe Hex Ultra \
                     and unlocked Lucky LV08 share this boardversion",
            probe_lv08: true,
        };
    }
    if bv == "402" && !mm.is_empty() {
        return IdentityVerdict::Ambiguous {
            reason: "boardversion 402 with a minermodel present: genuine BitAxe Supra never \
                     writes minermodel — stock Lucky factory firmware does",
            probe_lv08: true,
        };
    }

    // Non-collision fallthrough: the normal resolution ladder.
    if let Some(profile) = BoardVersionProfile::find(bv) {
        return IdentityVerdict::Resolved(*profile);
    }
    if let Some(model) = BitAxeModel::from_device_model(&dm) {
        return IdentityVerdict::Resolved(*BoardVersionProfile::default_for_model(model));
    }
    IdentityVerdict::Unknown
}

/// Complete board configuration — pins, voltages, and power parameters.
///
/// All GPIO pin numbers are configurable to support different board revisions.
/// Voltage limits are enforced by the power management layer as a safety measure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardConfig {
    /// Board model identifier
    pub model: BitAxeModel,
    /// Runtime board version from NVS / AxeOS config.
    pub board_version: String,
    /// Runtime device model from NVS / AxeOS config.
    pub device_model: String,
    /// Runtime ASIC model from NVS / AxeOS config.
    pub asic_model: String,
    /// Number of ASICs on the board
    pub asic_count: u8,
    /// Runtime fan controller selection.
    pub fan_controller: FanControllerKind,
    /// Runtime temperature sensor selection.
    pub temp_sensor: TempSensorKind,
    /// Runtime power controller selection.
    pub power_controller: PowerControllerKind,
    /// True when the board exposes an INA260 power monitor.
    pub has_ina260: bool,
    /// Board display hardware kind. This is separate from the compiled display driver.
    pub display_kind: DisplayKind,
    /// True when EMC internal temperature should be trusted.
    pub emc_internal_temp: bool,
    /// EMC diode ideality factor to apply when supported.
    pub emc_ideality_factor: u8,
    /// EMC beta compensation to apply when supported.
    pub emc_beta_compensation: u8,
    /// Temperature offset from ESP-Miner board tables.
    pub temp_offset_c: i8,
    /// Power target from ESP-Miner board tables.
    pub power_consumption_target_w: u16,
    /// Whether barrel-jack plug sensing should gate board power-up.
    pub plug_sense: bool,
    /// Stock ESP-Miner ASIC-enable flag for this board.
    pub asic_enable: bool,

    // --- GPIO pin assignments ---
    /// UART TX pin (ESP32 -> ASIC RX)
    pub uart_tx_pin: i32,
    /// UART RX pin (ASIC TX -> ESP32)
    pub uart_rx_pin: i32,
    /// I2C SDA pin (shared bus for power ICs, temp sensors)
    pub i2c_sda_pin: i32,
    /// I2C SCL pin
    pub i2c_scl_pin: i32,
    /// Barrel-jack plug-sense input pin, -1 if unused.
    pub plug_sense_pin: i32,
    /// Fan PWM output pin (LEDC channel), -1 if no fan
    pub fan_pwm_pin: i32,
    /// Fan tachometer input pin (pulse counting), -1 if no fan
    pub fan_tach_pin: i32,
    /// Status LED pin
    pub led_pin: i32,
    /// ASIC chain reset pin (active low — pull low to reset, high for normal operation)
    pub asic_reset_pin: i32,
    /// Buck converter enable pin (controls TPS546 power stage), -1 if not applicable
    pub buck_enable_pin: i32,
    /// Buck enable is active-low (true for Max/Ultra with DS4432U, false for Gamma with TPS546)
    pub buck_enable_active_low: bool,
    /// ASIC LDO enable pin, `-1` if this board has no separate LDO rail.
    ///
    /// This is a SECOND rail, not a second name for the buck enable. See
    /// [`LdoEnable`] for why it is load-bearing on the multi-phase Nerd line.
    /// Normalized from [`BitAxeModel::asic_ldo_enable`] by
    /// [`BoardConfig::normalize_power_pins`], never set directly by a row.
    pub ldo_enable_pin: i32,
    /// The core-rail enable when it lives on an I²C port expander rather than
    /// an ESP GPIO, `None` otherwise. See [`BuckEnableWiring::Expander`].
    ///
    /// Separate from `buck_enable_pin` (which stays `-1` here) because the two
    /// answer different questions: that field is what the GPIO binder and the
    /// panic hook's `PANIC_BUCK_GPIO` may claim, this one is whether an
    /// actuator exists at all. [`BoardConfig::rail_bringup`] recombines them.
    pub expander_rail_enable: Option<ExpanderPin>,

    // --- Frequency defaults ---
    /// Default ASIC hash frequency in MHz
    pub default_frequency: f32,

    // --- Voltage safety limits ---
    /// Default core voltage in millivolts
    pub default_voltage_mv: u16,
    /// Maximum safe core voltage in millivolts — NEVER exceed this
    pub max_voltage_mv: u16,
    /// Minimum operating core voltage in millivolts
    pub min_voltage_mv: u16,

    // --- Power IC configuration ---
    /// Number of voltage domains (1 for single ASIC, 3 for Hex with series chain)
    pub voltage_domains: u16,
    /// Power offset in watts for board-level power not measured by regulator
    pub power_offset_w: f32,
    /// Pass-5 audit: per ESP-Miner PR #1616, some EMC2103 boards (currently
    /// only v801 GT) have the internal/external sensor mapping physically
    /// swapped. Consumers should swap chip_temp / board_temp reads when set.
    pub temp_flip: bool,
    /// XPSAFE-7: operator-asserted "this single-fan board HAS a tachometer wire
    /// connected." Default `false` (matches every shipping board and the prior
    /// behavior). When an operator who knows their fan is wired sets this, the
    /// boot tach proof and the runtime "tach must be >0 while fan is driven"
    /// rule that Hex/GT boards already enforce become fail-closed for this
    /// board too (consumed by the `main.rs` boot/runtime gates — see
    /// [`tach_proof_required`](Self::tach_proof_required)). Genuinely tachless
    /// boards leave it `false` and keep the existing `fan1_ever_seen` heuristic
    /// + the 90/95/105 C thermal ladder as the backstop.
    pub fan_tach_present: bool,
    /// Row-declared mandatory tach proof, copied from
    /// [`BoardVersionProfile::fan_tach_required`] (currently the Lucky
    /// LV07/LV08 rows). ADDITIVE input to
    /// [`requires_fan_tach`](Self::requires_fan_tach) — it widens the
    /// mandatory-tach set beyond the inherent Hex/EMC2103 predicate without
    /// changing any previously-shipping board's verdict. Distinct from the
    /// XPSAFE-7 operator opt-in `fan_tach_present`: this one is BOARD truth
    /// from the profile row, is not NVS-overridable (deliberately not copied
    /// by `apply_hardware_config`, like `temp_flip`), and `#[serde(default)]`
    /// keeps any previously-serialized BoardConfig blob deserializable.
    #[serde(default)]
    pub fan_tach_required: bool,
    /// Registered Hammer DC TMP75 address strap. Identity-only: this does not
    /// claim a temperature driver or trusted thermal source. Copied from the
    /// profile row and deliberately absent from `apply_hardware_config`.
    #[serde(default)]
    pub identity_strap_addr: Option<u8>,
    /// XPSAFE-8: which of a dual-fan controller's headers the operator declares
    /// PHYSICALLY POPULATED. Default [`FanPopulation::Both`], which is the
    /// reference build for every dual-fan row and reproduces the prior
    /// behavior byte for byte.
    ///
    /// This does NOT relax [`requires_fan_tach`](Self::requires_fan_tach) — a
    /// Hex still MUST prove a tachometer. It changes only WHICH fans the proof
    /// is demanded from, so a board running one fan fails closed on the fan it
    /// actually has instead of failing closed forever on a header that was
    /// never populated. Consumed by the `main.rs` boot and runtime gates via
    /// [`declared_fan_tach_missing`](Self::declared_fan_tach_missing).
    ///
    /// `#[serde(default)]` keeps every previously-serialized blob deserializing
    /// as `Both`.
    #[serde(default)]
    pub fans_populated: FanPopulation,
}

/// Which headers of a dual-fan controller are physically populated.
///
/// XPSAFE-8. There is deliberately no `None` variant: a board in
/// [`BoardConfig::requires_fan_tach`] must always prove at least one
/// tachometer, so "no fans fitted" is unrepresentable here rather than merely
/// rejected at runtime. Single-fan controllers (EMC2101) ignore this — they
/// have one header and go through [`BoardConfig::tach_proof_required`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FanPopulation {
    /// Both headers fitted. The reference build, and the default.
    #[default]
    Both,
    /// Only header 1 (EMC2302 FAN1) is fitted.
    Fan1Only,
    /// Only header 2 (EMC2302 FAN2) is fitted.
    Fan2Only,
}

impl FanPopulation {
    /// Is header 1 declared fitted?
    pub fn fan1(&self) -> bool {
        matches!(self, Self::Both | Self::Fan1Only)
    }

    /// Is header 2 declared fitted?
    pub fn fan2(&self) -> bool {
        matches!(self, Self::Both | Self::Fan2Only)
    }

    /// How many headers are declared fitted. Never zero.
    pub fn count(&self) -> u8 {
        self.fan1() as u8 + self.fan2() as u8
    }
}

/// I2C SDA pin — compile-time selected by pin family feature.
#[inline]
pub const fn i2c_sda_gpio() -> i32 {
    #[cfg(feature = "pins-bitaxe")]
    {
        47
    }
    #[cfg(feature = "pins-nerd")]
    {
        18
    } // TTGO T-Display S3: GPIO18 = I2C SDA
    #[cfg(any(feature = "pins-hammer-bc", feature = "pins-hammer-dc"))]
    {
        44
    }
}

/// I2C SCL pin — compile-time selected by pin family feature.
#[inline]
pub const fn i2c_scl_gpio() -> i32 {
    #[cfg(feature = "pins-bitaxe")]
    {
        48
    }
    #[cfg(feature = "pins-nerd")]
    {
        17
    } // TTGO T-Display S3: GPIO17 = I2C SCL
    #[cfg(any(feature = "pins-hammer-bc", feature = "pins-hammer-dc"))]
    {
        43
    }
}

/// UART TX pin — compile-time selected by pin family feature.
#[inline]
pub const fn uart_tx_gpio() -> i32 {
    #[cfg(feature = "pins-bitaxe")]
    {
        17
    }
    #[cfg(feature = "pins-nerd")]
    {
        43
    } // TTGO T-Display S3: GPIO43 = UART TX
      // Hammer UART polarity varies by SKU; all Hammer model arms overwrite
      // this common default, and main.rs binds the concrete SKU at compile time.
    #[cfg(any(feature = "pins-hammer-bc", feature = "pins-hammer-dc"))]
    {
        17
    }
}

/// UART RX pin — compile-time selected by pin family feature.
#[inline]
pub const fn uart_rx_gpio() -> i32 {
    #[cfg(feature = "pins-bitaxe")]
    {
        18
    }
    #[cfg(feature = "pins-nerd")]
    {
        44
    } // TTGO T-Display S3: GPIO44 = UART RX
      // See uart_tx_gpio(): this is only the common default.
    #[cfg(any(feature = "pins-hammer-bc", feature = "pins-hammer-dc"))]
    {
        18
    }
}

impl BoardConfig {
    /// Create the default configuration for a given board model.
    ///
    /// Pin assignments are based on the open-source schematics for each board.
    /// These can be overridden after construction for custom boards.
    pub fn for_model(model: BitAxeModel) -> Self {
        Self::for_profile_with_model(BoardVersionProfile::default_for_model(model), model)
    }

    /// NerdQX identity probe. Upstream treats the TMP451 mux answering on
    /// GPIO2/GPIO3 at 0x4C as "this is a QX" and only then keeps the nominal
    /// 777 MHz / 1200 mV envelope. The static row stays clamped; call this
    /// with `mux_answered = true` only after a successful mux bring-up.
    pub fn apply_nerdqx_tmp451_identity(&mut self, mux_answered: bool) {
        if self.model != BitAxeModel::NerdQX || !mux_answered {
            return;
        }
        self.default_frequency = 777.0;
        self.default_voltage_mv = 1200;
        self.max_voltage_mv = 1200;
    }

    pub fn for_profile(profile: &BoardVersionProfile) -> Self {
        Self::for_profile_with_model(profile, profile.model)
    }

    pub fn for_profile_with_model(profile: &BoardVersionProfile, model: BitAxeModel) -> Self {
        let sda = i2c_sda_gpio();
        let scl = i2c_scl_gpio();

        // Common pin assignments (UART TX/RX are the same across all boards)
        let common = BoardConfig {
            model,
            board_version: profile.board_version.to_string(),
            device_model: model.canonical_key().to_string(),
            asic_model: profile.asic_model.to_string(),
            asic_count: model.asic_count(),
            fan_controller: profile.fan_controller,
            temp_sensor: profile.temp_sensor,
            power_controller: profile.power_controller,
            has_ina260: profile.has_ina260,
            display_kind: if profile.model == model {
                profile.display_kind()
            } else {
                model.display_kind()
            },
            emc_internal_temp: profile.emc_internal_temp,
            emc_ideality_factor: profile.emc_ideality_factor,
            emc_beta_compensation: profile.emc_beta_compensation,
            temp_offset_c: profile.temp_offset_c,
            power_consumption_target_w: profile.power_consumption_target_w,
            temp_flip: profile.temp_flip,
            // XPSAFE-7: default-OFF — no shipping board asserts a wired tach, so
            // every board keeps its prior boot/runtime fan-proof behavior until
            // an operator opts in via config.
            fan_tach_present: false,
            // Row-declared mandatory tach proof (Lucky LV07/LV08) — additive
            // to the inherent Hex/EMC2103 requirement, see requires_fan_tach.
            fan_tach_required: profile.fan_tach_required(),
            identity_strap_addr: profile.identity_strap_addr(),
            // XPSAFE-8: every row's reference build populates both headers, so
            // the default reproduces the prior gate exactly. An operator running
            // one fan declares it through config (`fans_populated`).
            fans_populated: FanPopulation::Both,
            plug_sense: profile.plug_sense(),
            asic_enable: profile.asic_enable(),
            uart_tx_pin: uart_tx_gpio(),
            uart_rx_pin: uart_rx_gpio(),
            i2c_sda_pin: sda,
            i2c_scl_pin: scl,
            plug_sense_pin: -1,
            fan_pwm_pin: 11,
            fan_tach_pin: 14,
            led_pin: 4,
            asic_reset_pin: 1,
            buck_enable_pin: 46,
            buck_enable_active_low: false,
            ldo_enable_pin: -1,
            expander_rail_enable: None,
            default_frequency: 0.0,
            default_voltage_mv: 0,
            max_voltage_mv: 0,
            min_voltage_mv: 0,
            voltage_domains: 1,
            power_offset_w: 2.0,
        };

        if model.is_hex() {
            info!("Hex board: 6-ASIC single UART daisy chain, 3 voltage domains, 12V input");
        }

        let mut board = match model {
            // ── BitAxe family ──
            BitAxeModel::Max => BoardConfig {
                default_frequency: 425.0,
                default_voltage_mv: 1400,
                max_voltage_mv: 1550,
                min_voltage_mv: 1000,
                voltage_domains: 1,
                power_offset_w: 5.0, // ESP-Miner: FAMILY_MAX.power_offset = 5
                ..common
            },
            BitAxeModel::Ultra => BoardConfig {
                default_frequency: 485.0,
                default_voltage_mv: 1200,
                max_voltage_mv: 1400,
                min_voltage_mv: 1000,
                voltage_domains: 1,
                power_offset_w: 5.0, // ESP-Miner: FAMILY_ULTRA.power_offset = 5
                ..common
            },
            BitAxeModel::HexUltra => BoardConfig {
                default_frequency: 485.0,
                default_voltage_mv: 1200,
                max_voltage_mv: 1350,
                min_voltage_mv: 850,
                voltage_domains: 3,
                power_offset_w: 12.0, // ESP-Miner: FAMILY_HEX.power_offset = 12
                ..common
            },
            BitAxeModel::Supra => BoardConfig {
                default_frequency: 490.0,
                default_voltage_mv: 1166,
                max_voltage_mv: 1400,
                min_voltage_mv: 1000,
                voltage_domains: 1,
                power_offset_w: 5.0, // ESP-Miner: FAMILY_SUPRA.power_offset = 5
                ..common
            },
            BitAxeModel::HexSupra => BoardConfig {
                default_frequency: 490.0,
                default_voltage_mv: 1166,
                max_voltage_mv: 1350,
                min_voltage_mv: 850,
                voltage_domains: 3,
                power_offset_w: 25.0, // ESP-Miner: FAMILY_SUPRA_HEX.power_offset = 25
                ..common
            },
            BitAxeModel::Gamma => BoardConfig {
                default_frequency: 525.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1350,
                min_voltage_mv: 1000,
                voltage_domains: 1,
                power_offset_w: 5.0, // ESP-Miner: FAMILY_GAMMA.power_offset = 5
                ..common
            },
            BitAxeModel::GammaDuo => BoardConfig {
                asic_count: 2,
                default_frequency: 400.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1350,
                min_voltage_mv: 1000,
                voltage_domains: 1,
                power_offset_w: 5.0,
                ..common
            },
            BitAxeModel::GammaTurbo => BoardConfig {
                asic_count: 2,
                default_frequency: 525.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1350,
                min_voltage_mv: 1000,
                voltage_domains: 1,
                power_offset_w: 10.0,
                ..common
            },
            // Touch variants are electrically identical to their mining-board
            // base — the only difference is the LVGL accessory hanging off BAP.
            BitAxeModel::Touch => BoardConfig {
                asic_count: 1,
                default_frequency: 525.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1350,
                min_voltage_mv: 1000,
                voltage_domains: 1,
                power_offset_w: 5.0, // Same as Gamma (Touch = Gamma + BAP)
                ..common
            },
            BitAxeModel::GtTouch => BoardConfig {
                asic_count: 2,
                default_frequency: 525.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1350,
                min_voltage_mv: 1000,
                voltage_domains: 1,
                power_offset_w: 10.0,
                ..common
            },

            // ── Nerd family ──
            BitAxeModel::NerdNOS => BoardConfig {
                // NerdNOS: BM1397, USB-C ~8W, fixed TPSM863257RDX, no fan, headless
                // GPIO10 = regulator EN pin — active HIGH to enable power
                fan_pwm_pin: -1, // No fan
                fan_tach_pin: -1,
                default_frequency: 400.0,
                default_voltage_mv: 1200, // Fixed — not adjustable
                max_voltage_mv: 1200,
                min_voltage_mv: 1200,
                voltage_domains: 1,
                power_offset_w: 1.0,
                ..common
            },
            BitAxeModel::NerdAxe => BoardConfig {
                // NerdAxe: 1x BM1366, T-Display S3, DS4432U + TPS40305, EMC2101
                // (internal die + 5 °C), INA260. Envelope is upstream's
                // `nerdaxe.cpp` verbatim: 485 MHz / 1200 mV default, and the
                // 1100..=1300 mV window from `m_asicVoltages`.
                //
                // The old row read 525 MHz / 1150 mV over a 1000..=1350 window,
                // which is neither this board nor the γ.
                default_frequency: 485.0,
                default_voltage_mv: 1200,
                max_voltage_mv: 1300,
                min_voltage_mv: 1100,
                voltage_domains: 1,
                power_offset_w: 2.0,
                ..common
            },
            BitAxeModel::NerdAxeGamma => BoardConfig {
                // NerdAxe-γ: 1x BM1370, T-Display S3, TPS546 PMBus (no enable
                // GPIO), EMC2101 external diode. 515 MHz / 1150 mV default over
                // the 1120..=1200 mV window from `m_asicVoltages`.
                //
                // `power_offset_w` is upstream's `GAMMA_POWER_OFFSET 5`, added
                // in `getPin()` as `(vout * iout) + 5` to account for what the
                // TPS546 cannot see.
                default_frequency: 515.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1200,
                min_voltage_mv: 1120,
                voltage_domains: 1,
                power_offset_w: 5.0,
                ..common
            },
            // ── Nerd multi-ASIC boards (TPS53647/TPS53667 multi-phase rail) ──
            //
            // Values reconciled against the upstream board constructors in
            // ESP-Miner-NerdQAxePlus/main/boards/*.cpp. All four are ONE voltage
            // domain with their ASICs in PARALLEL — `voltage_domains` must stay
            // 1. `power.rs` derives the rail as per-ASIC mV × domains, so a 2
            // here would command double onto parallel dies (the Lucky LV08
            // hazard restated).
            //
            // `power_controller: Tps5364x` is deliberately NOT a thermal-trust
            // grant (see PowerControllerKind::Tps5364x). Combined with
            // These rows declare `temp_sensor: Tmp1075`. Every one of these
            // boards derives from upstream's NerdQaxePlus, whose thermal path is
            // a set of TMP1075s strapped at 0x48..=0x4B — NOT the TPS546 the
            // BitAxe-class boards use, and NOT nothing. `temp::Tmp1075` now
            // addresses them by index (`tmp1075_convert`), so the declaration is
            // backed by a driver rather than being an aspiration.
            //
            // ⚠ Device 1 (0x49) is the VOLTAGE-REGULATOR sensor, not an ASIC
            // sensor: a four-ASIC board exposes THREE ASIC sensors (devices 0,
            // 2, 3). `tmp1075_convert::nerd_asic_device_index` encodes the skip
            // so a regulator reading is never published as a die temperature.
            //
            // The NerdOCTAXE-γ additionally carries two TMP451s behind a shared
            // 2-bit analog mux (0x4C/0x4E) giving true per-ASIC diode temps, but
            // ONLY on newer revisions — so it is probed at runtime as an
            // enrichment and is deliberately NOT what the row declares. A
            // declared sensor is a promise every revision must keep.
            //
            // Declaring a sensor is a CONFIGURATION claim, not proof: `main.rs`
            // still refuses to mine when the part does not answer at boot
            // (`mining_permitted = false`). Config trust opens the gate; the
            // runtime probe is what walks through it.
            //
            // `fan_controller` is overridden for the same reason the VRM was:
            // these rows borrow a BitAxe profile ("402"/"601") that declares a
            // single-fan EMC2101, while upstream's NerdQaxePlus base class
            // includes EMC2302.h and sets `m_numFans = 2`. Left inherited, the
            // row would name a part that is not fitted and report a two-fan
            // board as one-fan.
            BitAxeModel::NerdQaxePlus => BoardConfig {
                // NerdQaxe+: 4x BM1368, 2-phase TPS53647, 12 V in, ~70 W.
                // Upstream: m_defaultAsicFrequency 490, m_asicVoltageMillis
                // 1250, m_absMinAsicVoltageMillis 1050, m_absMax 1400.
                asic_count: 4,
                default_frequency: 490.0,
                default_voltage_mv: 1250,
                max_voltage_mv: 1400,
                // 1050, not 1000: the upstream floor. The previous 1000 was
                // BELOW what the vendor characterizes — the unsafe direction.
                min_voltage_mv: 1050,
                voltage_domains: 1,
                fan_controller: FanControllerKind::Emc2302,
                power_controller: PowerControllerKind::Tps5364x,
                temp_sensor: TempSensorKind::Tmp1075,
                power_offset_w: 5.0,
                ..common
            },
            BitAxeModel::NerdQaxePP => BoardConfig {
                // NerdQaxe++: 4x BM1370, 3-phase TPS53647, 12 V in, ~100 W.
                // Upstream m_defaultAsicFrequency is 600 and m_absMax voltage
                // 1400. NOTE: a rev7 NerdQAxe++ replaces the TPS53647 with a
                // TPS546 driven as TWO series voltage domains (~2.3 V rail).
                // That revision is detected by an I2C probe upstream
                // (probeRev7Buck) and is NOT represented by this row — a rev7
                // unit must not be energized from here.
                asic_count: 4,
                default_frequency: 600.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1400,
                min_voltage_mv: 1050,
                voltage_domains: 1,
                fan_controller: FanControllerKind::Emc2302,
                power_controller: PowerControllerKind::Tps5364x,
                temp_sensor: TempSensorKind::Tmp1075,
                power_offset_w: 8.0,
                ..common
            },
            BitAxeModel::NerdOctaxePlus => BoardConfig {
                // NerdOCTAXE+: 8x BM1368, 3-phase TPS53647 (imax 90 A), 12 V
                // in, ~130 W ceiling. Upstream README documents ~5 TH/s at
                // ~100 W. Inherits the NerdQAxe+ frequency/voltage tables.
                asic_count: 8,
                default_frequency: 490.0,
                default_voltage_mv: 1250,
                max_voltage_mv: 1400,
                min_voltage_mv: 1050,
                voltage_domains: 1,
                fan_controller: FanControllerKind::Emc2302,
                power_controller: PowerControllerKind::Tps5364x,
                temp_sensor: TempSensorKind::Tmp1075,
                power_offset_w: 10.0,
                ..common
            },
            BitAxeModel::NerdOctaxeGamma => BoardConfig {
                // NerdOCTAXE-γ: 8x BM1370. TWO power stages ship under this one
                // name — rev ≤3.3 is a 4-phase TPS53647 (180 A, ~250 W) and
                // rev 3.4 is a 6-phase TPS53667 (240 A, ~300 W, and upstream
                // raises defaults to 700 MHz / 1210 mV for it).
                //
                // This row declares the CONSERVATIVE 4-phase envelope on
                // purpose: the higher tables are only valid once the TPS53667
                // has been positively identified by its device code at
                // bring-up. Applying 6-phase defaults to a 4-phase board would
                // exceed its current capability.
                asic_count: 8,
                default_frequency: 600.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1400,
                min_voltage_mv: 1050,
                voltage_domains: 1,
                fan_controller: FanControllerKind::Emc2302,
                power_controller: PowerControllerKind::Tps5364x,
                temp_sensor: TempSensorKind::Tmp1075,
                power_offset_w: 12.0,
                ..common
            },
            BitAxeModel::NerdQX => BoardConfig {
                // NerdQX: 4x BM1370, 3-phase TPS53647 (imax 90 A), 12 V in,
                // 240 W ceiling. The high-frequency member of the line —
                // upstream defaults to 777 MHz / 1200 mV, not the '++'s
                // 600 / 1150.
                //
                // ⚠ THE CEILING HERE IS THE *CLAMPED* ONE, ON PURPOSE.
                // Upstream computes absMax 1250 MHz / 1375 mV, but only keeps
                // them if its TMP451 mux answers on GPIO2/GPIO3 at 0x4C; when
                // the probe fails it logs "assuming non-QX board" and drops to
                // 1150 mV / 495 MHz. The mux IS the identity check. Declaring
                // the high ceiling in a static row would hand a mis-identified
                // board 1375 mV — so the row declares what an unproven board is
                // allowed, and raising it is a runtime reward for a positive
                // probe, tracked as the follow-up that wires TMP451 into
                // `main.rs`.
                //
                // So the defaults are upstream's CLAMPED outcome, not its
                // nominal 777 MHz / 1200 mV: on a failed probe upstream lowers
                // absMax and then re-runs `loadSettings()`, which pulls the
                // stored setpoint down to the new ceiling. Under-clocking an
                // unproven board is safe; over-volting a mis-identified one is
                // not. `min_voltage_mv` is the vendor's own eco point (1085),
                // tighter than the 1050 family floor.
                asic_count: 4,
                default_frequency: 495.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1150,
                min_voltage_mv: 1085,
                voltage_domains: 1,
                fan_controller: FanControllerKind::Emc2302,
                power_controller: PowerControllerKind::Tps5364x,
                temp_sensor: TempSensorKind::Tmp1075,
                power_offset_w: 8.0,
                ..common
            },
            BitAxeModel::NerdHaxeGamma => BoardConfig {
                // NerdHaxe-γ: 6x BM1370, 4-phase TPS53647 (imax 120 A, ifault
                // 105 A), 12 V in, 250 W ceiling. Inherits the NerdQAxe++
                // frequency/voltage tables unchanged.
                asic_count: 6,
                default_frequency: 600.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1400,
                min_voltage_mv: 1050,
                voltage_domains: 1,
                fan_controller: FanControllerKind::Emc2302,
                power_controller: PowerControllerKind::Tps5364x,
                temp_sensor: TempSensorKind::Tmp1075,
                power_offset_w: 10.0,
                ..common
            },
            BitAxeModel::NerdEko => BoardConfig {
                // NerdEKO: 12x BM1370 on a 6-phase TPS53667 (imax 240 A,
                // ifault 235 A), 12 V in, 350 W ceiling. Same NerdQAxe++
                // tables; what scales is the chip count and the rail.
                asic_count: 12,
                default_frequency: 600.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1400,
                min_voltage_mv: 1050,
                voltage_domains: 1,
                fan_controller: FanControllerKind::Emc2302,
                power_controller: PowerControllerKind::Tps5364x,
                temp_sensor: TempSensorKind::Tmp1075,
                power_offset_w: 15.0,
                ..common
            },

            // ── Q-series (FXL6408 port-expander topology) ──
            BitAxeModel::Q1370 => BoardConfig {
                // Q1370: 4x BM1370, 4-phase TPS53647 (imax 123 A), 12 V in,
                // 150 W ceiling. Same envelope as the NerdQAxe++ but a wider
                // 1200 MHz absolute frequency ceiling.
                asic_count: 4,
                default_frequency: 600.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1400,
                min_voltage_mv: 1050,
                voltage_domains: 1,
                fan_controller: FanControllerKind::Emc2302,
                power_controller: PowerControllerKind::Tps5364x,
                temp_sensor: TempSensorKind::Tmp1075,
                power_offset_w: 8.0,
                ..common
            },
            BitAxeModel::Q1373 => BoardConfig {
                // Q1373: the Q1370 board with BM1373 silicon, 180 W ceiling.
                // The ASIC changes the WHOLE envelope, and every field here is
                // lower than the Q1370's — 350 MHz against 600, 1010 mV against
                // 1150, and a 900-1200 mV window instead of 1050-1400.
                // Inheriting the Q1370 row would command a BM1370 voltage onto
                // BM1373 dies.
                asic_count: 4,
                default_frequency: 350.0,
                default_voltage_mv: 1010,
                max_voltage_mv: 1200,
                min_voltage_mv: 900,
                voltage_domains: 1,
                fan_controller: FanControllerKind::Emc2302,
                power_controller: PowerControllerKind::Tps5364x,
                temp_sensor: TempSensorKind::Tmp1075,
                power_offset_w: 8.0,
                ..common
            },

            // ── DCENT_axe family (BM1397) ──
            // fan_pwm_pin honesty (FULL_PREFAB_REVIEW_2026-07-11 LOW): the
            // DCENT_axe boards have NO ESP-driven fan-PWM line — the I2C fan
            // controller (EMC2101 single / EMC2302 Quad+Hex) generates PWM
            // itself, and GPIO11 is unconnected on the BM1397 netlist. The
            // inherited `fan_pwm_pin: 11` was fictional; -1 = "no ESP PWM pin".
            // The tach wire IS routed (GPIO14 / FAN_TACH net), so fan_tach_pin
            // stays; `fan_tach_present` remains default-false opt-in (XPSAFE-7).
            // Single 1x: same chip envelope as the BitAxe Max BM1397.
            BitAxeModel::DcentAxeBm1397 => BoardConfig {
                fan_pwm_pin: -1, // EMC2101 generates PWM; GPIO11 unconnected
                default_frequency: 425.0,
                default_voltage_mv: 1400,
                max_voltage_mv: 1550,
                min_voltage_mv: 1000,
                voltage_domains: 1,
                power_offset_w: 5.0,
                ..common
            },
            // Quad 4x: single UART daisy chain, one parallel voltage domain.
            BitAxeModel::DcentAxeQuadBm1397 => BoardConfig {
                fan_pwm_pin: -1, // EMC2302 generates PWM; no ESP PWM line
                asic_count: 4,
                default_frequency: 425.0,
                default_voltage_mv: 1400,
                max_voltage_mv: 1550,
                min_voltage_mv: 1000,
                voltage_domains: 1,
                power_offset_w: 10.0,
                ..common
            },
            // Hex 6x: single UART daisy chain, 3 series voltage domains (Hex-class).
            BitAxeModel::DcentAxeHexBm1397 => BoardConfig {
                fan_pwm_pin: -1, // EMC2302 generates PWM; no ESP PWM line
                asic_count: 6,
                default_frequency: 425.0,
                default_voltage_mv: 1400,
                max_voltage_mv: 1550,
                min_voltage_mv: 1000,
                voltage_domains: 3,
                power_offset_w: 12.0,
                ..common
            },

            // ── Hammer BC0x family (EXPERIMENTAL — identity + envelope only) ──
            //
            // ⚠ SERIES-STACKED VOLTAGE DOMAIN (HAMMER_HARDWARE_MATRIX.md §2.2,
            // the single most safety-critical Hammer fact): the regulator
            // output is the WHOLE-STACK voltage and
            //     rail = per_chip_voltage x voltage_domains.
            // Every `default/max/min_voltage_mv` below is the PER-ASIC value;
            // the rail is always DERIVED (exactly how the TPS546 driver's
            // `set_voltage_mv` multiplies by `voltage_domains`, power.rs:906).
            // Encoding BC04's vendor NVS stack value (4800 mV) directly as
            // `default_voltage_mv` would (a) be refused by the HALPWR-3
            // 1600 mV per-ASIC driver ceiling (fail-closed, good) and (b) if
            // that ceiling were ever mis-lifted, command ~4x the intended die
            // voltage. Per-chip x domains is the only safe expression.
            //
            // Vendor default frequency (750 MHz, fw range 300-800) is
            // deliberately NOT adopted: our BM1370 driver envelope is proven
            // at 525 MHz default / 650 MHz max, and Experimental tier prefers
            // conservative envelopes.
            //
            // UART/I2C pin ints below are the vendor-RE'd Hammer values and
            // intentionally DIFFER from the compile-time `pins-bitaxe` family
            // the SKU features select; mining is refused on these models
            // (no trusted thermal source), so the compile-time binding gap is
            // dormant — resolve it with a `pins-hammer-*` family before any
            // mining bring-up. asic_reset GPIO1 is verified for BC04 only.
            BitAxeModel::HammerBc01 => BoardConfig {
                uart_tx_pin: 18, // verified: OPPOSITE of BC04 — do not share a pin constant
                uart_rx_pin: 17,
                i2c_sda_pin: 44, // Hammer/Volc family I2C bus0 (SDA44/SCL43)
                i2c_scl_pin: 43,
                fan_pwm_pin: -1, // vendor fan is SoC LEDC PWM — not our shipping fan path
                fan_tach_pin: -1, // tach wiring unverified on BC01
                default_frequency: 525.0,
                default_voltage_mv: 1200, // per-chip; vendor NVS default 1200 mV
                max_voltage_mv: 1300,     // vendor web-UI max 1.30 V
                min_voltage_mv: 1000,
                voltage_domains: 1,
                ..common
            },
            // BC01 Pro — ⚠ LOWER CONFIDENCE (no firmware image held; vendor
            // web-UI table only). BM1373 driver is a fail-closed scaffold, so
            // this model cannot mine regardless. 1.15 V is a HARD cap.
            BitAxeModel::HammerBc01Pro => BoardConfig {
                uart_tx_pin: 18, // BC01-board-family inference — UNVERIFIED
                uart_rx_pin: 17,
                i2c_sda_pin: 44,
                i2c_scl_pin: 43,
                fan_pwm_pin: -1,
                fan_tach_pin: -1,
                default_frequency: 400.0, // conservative, under the 500 MHz vendor ceiling
                default_voltage_mv: 1000, // per-chip; vendor default 1000 mV
                max_voltage_mv: 1150,     // vendor 1.15 V cap — never raise without bench proof
                min_voltage_mv: 1000,
                voltage_domains: 1,
                ..common
            },
            // BC02 — ⚠ LOWER CONFIDENCE (no firmware image held). 2 chips in
            // ONE series domain per the family stack rule; note the recorded
            // units contradiction (vendor table lists per-chip-scale 1225 mV /
            // 1.30 V max for BC02 while listing stack-scale values for BC04) —
            // MUST be resolved before any regulator driver is enabled here.
            BitAxeModel::HammerBc02 => BoardConfig {
                asic_count: 2,
                uart_tx_pin: 18, // BC01-lineage inference — UNVERIFIED
                uart_rx_pin: 17,
                i2c_sda_pin: 44,
                i2c_scl_pin: 43,
                fan_pwm_pin: -1,
                fan_tach_pin: -1,
                default_frequency: 525.0,
                default_voltage_mv: 1225, // per-chip; derived rail 2.45 V
                max_voltage_mv: 1300,
                min_voltage_mv: 1000,
                voltage_domains: 2,
                ..common
            },
            // BC04 (`thor`) — best-evidenced: UART TX17/RX18 + reset GPIO1
            // verified from disassembly; vendor NVS stack default 4800 mV
            // (= 1200 mV/chip x 4), clamp 4000-5000 (= 1000-1250 mV/chip).
            // GPIO15 is a shared board-power + LCD-power net — never add it
            // to any pin field here without accounting for both consumers.
            BitAxeModel::HammerBc04 => BoardConfig {
                asic_count: 4,
                uart_tx_pin: 17, // verified (matches pins-bitaxe values)
                uart_rx_pin: 18,
                i2c_sda_pin: 44,
                i2c_scl_pin: 43,
                fan_pwm_pin: -1, // vendor fan path unknown — no false pin claim
                fan_tach_pin: -1,
                default_frequency: 525.0,
                default_voltage_mv: 1200, // per-chip; derived rail 4.80 V = vendor 4800 mV
                max_voltage_mv: 1250,     // per-chip; derived rail cap 5.00 V = vendor clamp top
                min_voltage_mv: 1000, // per-chip; derived rail floor 4.00 V = vendor clamp bottom
                voltage_domains: 4,
                ..common
            },

            // ── Hammer DC0x family (EXPERIMENTAL — Scrypt; MSBT0501) ──
            //
            // 🔴 FOUR DISCRETE PROFILES. NEVER A PARAMETERISED FAMILY PROFILE.
            // DC02 and DC04/DC06 share only I2C0 (SDA 44 / SCL 43), the display
            // block and the buttons. Everything else collides
            // (DC0X_BOARD_RESIDUALS.md §5.4 — every one output-vs-output or
            // output-into-driven-net):
            //   GPIO 1   DC02 fan TACH input      | DC04 ASIC RESET (push-pull)
            //   GPIO 2   DC02 fan PWM (LEDC out)  | DC04 W5500 SPI MISO (driven)
            //   GPIO 3   DC02 ASIC RESET (out)    | DC04 W5500 SPI SCLK @16 MHz
            //   GPIO 10  DC02 TPS546 PGOOD (in)   | DC04 W5500 SPI CS (out)
            //   GPIO 11  DC02 I2C1 SDA (the VRM's | DC04 TPS546 PGOOD (in)
            //            ONLY control path)       |
            //   GPIO 17/18  UART RX/TX            | UART TX/RX  (swapped)
            // Applying the DC04 profile to a DC02 clocks the ASIC reset line at
            // 16 MHz, fabricates a "power good", and destroys the only path to
            // command vcore OFF. Applying DC02's to a DC04 drives 8 kHz PWM into
            // the W5500's MISO driver. Hence: identity must be PROBE-VALIDATED
            // and REFUSE on mismatch — we deliberately do NOT imitate the
            // vendor's auto-rotate-and-reboot, and DC02 has no strap rotation at
            // all so it could never self-correct anyway.
            //
            // 🔴 SERIES-STACKED RAIL: rail = 0.635 V x chip_count, proven three
            // independent ways (DC02 1270/2 = DC04 2540/4 = DC06 3810/6 = 635).
            // Every voltage field here is PER-ASIC; `voltage_domains` = chip
            // count and the TPS546 driver derives the rail
            // (`per_asic_mv * voltage_domains`, power.rs). The per-chip window
            // is IDENTICAL across all three models (500 / 635 / 750 mV) —
            // which is exactly why it must never be stored as a rail constant:
            // one shared "1.27 V" applied to a DC06 would be 0.21 V/chip, and
            // one shared "3.81 V" applied to a DC02 would be 1.9 V/chip.
            //
            // Frequency: 2300 MHz is the vendor STOCK default (0x8FC), adopted
            // as BOTH default and ceiling — zero overclock headroom. The vendor
            // firmware clamp is 700-2600 MHz and its web UI shows 2400; neither
            // is bench-proven and the RE explicitly calls both unsafe-wide.
            //
            // Pin ints below are the vendor-RE'd values and intentionally
            // DIFFER from the compile-time `pins-bitaxe` family the SKU
            // features select. Mining is refused on these models (no trusted
            // thermal source), so the compile-time binding gap is dormant —
            // a `pins-hammer-dc*` family is a PREREQUISITE for any bring-up.
            BitAxeModel::HammerDc02 => BoardConfig {
                asic_count: 2,
                // ⚠ TX 18 / RX 17 — the OPPOSITE of DC04/DC06. Never share a
                // UART pin constant across the DC lane.
                uart_tx_pin: 18,
                uart_rx_pin: 17,
                // I2C bus 0. NOTE: the TPS546 is on DC02's SECOND bus
                // (SDA 11 / SCL 12) which this HAL cannot express — one more
                // reason `power_controller` is None on the row.
                i2c_sda_pin: 44,
                i2c_scl_pin: 43,
                // Vendor fan is SoC LEDC PWM GPIO 2 + PCNT tach GPIO 1. Both
                // are recorded in the docs but NOT claimed as pins here: GPIO 1
                // and GPIO 2 are DC04's RESET and SPI MISO, and a wrong-profile
                // drive of either is a damage path. -1 = "no ESP fan pin".
                fan_pwm_pin: -1,
                fan_tach_pin: -1,
                // ASIC RESET is GPIO 3 on DC02 (GPIO 1 on DC04) — see
                // `normalize_power_pins` for why this is set per MODEL.
                asic_reset_pin: 3,
                default_frequency: 2300.0,
                default_voltage_mv: 635, // PER-ASIC; derived rail 2 x 635 = 1.27 V
                max_voltage_mv: 750,     // PER-ASIC; derived rail cap 1.50 V
                min_voltage_mv: 500,     // PER-ASIC; derived rail floor 1.00 V
                voltage_domains: 2,
                power_offset_w: 8.0,
                ..common
            },
            BitAxeModel::HammerDc04 => BoardConfig {
                asic_count: 4,
                uart_tx_pin: 17,
                uart_rx_pin: 18,
                i2c_sda_pin: 44,
                i2c_scl_pin: 43,
                // EMC2302 @0x2E generates the PWM; no ESP PWM/tach line.
                fan_pwm_pin: -1,
                fan_tach_pin: -1,
                asic_reset_pin: 1,
                default_frequency: 2300.0,
                default_voltage_mv: 635, // PER-ASIC; derived rail 4 x 635 = 2.54 V
                max_voltage_mv: 750,     // PER-ASIC; derived rail cap 3.00 V
                min_voltage_mv: 500,     // PER-ASIC; derived rail floor 2.00 V
                voltage_domains: 4,
                power_offset_w: 12.0,
                ..common
            },
            // DC06 runs the byte-identical DC04 firmware; the only functional
            // differences are the TMP75 strap (0x4F), the chip count and the
            // voltage ROW — which, expressed per-ASIC, is the SAME row.
            BitAxeModel::HammerDc06 => BoardConfig {
                asic_count: 6,
                uart_tx_pin: 17,
                uart_rx_pin: 18,
                i2c_sda_pin: 44,
                i2c_scl_pin: 43,
                fan_pwm_pin: -1,
                fan_tach_pin: -1,
                asic_reset_pin: 1,
                default_frequency: 2300.0,
                default_voltage_mv: 635, // PER-ASIC; derived rail 6 x 635 = 3.81 V
                max_voltage_mv: 750,     // PER-ASIC; derived rail cap 4.50 V
                min_voltage_mv: 500,     // PER-ASIC; derived rail floor 3.00 V
                voltage_domains: 6,
                power_offset_w: 12.0,
                ..common
            },

            // ── Lucky Miner LVxx family (BM1366; EXPERIMENTAL) ──
            // Pin map is 100% stock BitAxe (R1): the `common` block already
            // carries UART TX17/RX18 (pins-bitaxe), I2C 47/48, reset GPIO1,
            // buck-EN GPIO46 active-high — no overrides needed. Envelope from
            // the LVXX fork: 485 MHz default, 1200 mV default, voltage
            // options 1100..1300 mV; family power offset 18 W (LVXX
            // power.c:24-37).
            BitAxeModel::LuckyLv06 => BoardConfig {
                default_frequency: 485.0,
                default_voltage_mv: 1200,
                max_voltage_mv: 1300,
                min_voltage_mv: 1000,
                // SAFETY (SPEC §1.1): Lucky chips are PARALLEL on ONE ~1.2 V
                // domain. voltage_domains MUST stay 1 — any value >1 here
                // makes power.rs:906 command a multiple of 1.2 V onto the
                // parallel dies. Do NOT "harmonize" this with Hex/Hammer.
                voltage_domains: 1,
                power_offset_w: 18.0,
                ..common
            },
            BitAxeModel::LuckyLv07 => BoardConfig {
                asic_count: 2,
                default_frequency: 485.0,
                default_voltage_mv: 1200,
                max_voltage_mv: 1300,
                min_voltage_mv: 1000,
                // SAFETY (SPEC §1.1): 2 chips in PARALLEL on ONE ~1.2 V
                // domain — NOT series like Hammer BC02. voltage_domains MUST
                // stay 1; >1 drives a multiple of 1.2 V onto parallel dies.
                voltage_domains: 1,
                power_offset_w: 18.0,
                ..common
            },
            // LV08: 9x BM1366, three paralleled TPS546 @ 0x24/0x7F/0x14
            // (each set to the SAME ~1.2 V — a parallel regulator set, not a
            // GT-style current-sharing phase stack).
            BitAxeModel::LuckyLv08 => BoardConfig {
                asic_count: 9,
                default_frequency: 485.0,
                default_voltage_mv: 1200,
                max_voltage_mv: 1300,
                min_voltage_mv: 1000,
                // SAFETY (SPEC §1.1): NINE chips in PARALLEL on ONE ~1.2 V
                // domain. The LVXX fork's own HEAD (48b77a8) deleted its
                // 3.6 V/0.125-scale LV08 case for exactly this reason.
                // voltage_domains MUST stay 1 — any value >1 on this row
                // drives a multiple of 1.2 V onto nine parallel dies. A
                // future "consistency" refactor must NOT raise it.
                voltage_domains: 1,
                power_offset_w: 18.0,
                ..common
            },

            // ── BitForge ──
            BitAxeModel::BitForgeNano => BoardConfig {
                // 2x BM1370 in PARALLEL on one TPS546A24 1.2 V rail — the same
                // shape as the BitAxe Gamma Duo (2x BM1370, one domain), so it
                // takes the same BM1370 family envelope rather than inventing
                // one.
                asic_count: 2,
                //
                // ⚠ THREE PINS THAT MUST NOT BE INHERITED FROM `common`.
                //
                // The stock BitAxe map is wrong on this board for all three,
                // and each was verified twice — against `BitForgeNano.kicad_pcb`
                // and against forge-os:
                //
                // * `led_pin` 4 -> **9**. GPIO4 is `/TMP_10K_A2`, the ASIC-2
                //   NTC divider node (see `ntc_thermal_channels`). Driving it as
                //   an LED output would fight R73's 10 k pull-up, destroy that
                //   thermistor reading, and sink current through the divider
                //   forever. The real LEDs are GPIO9 (`/ESP32/LED1`) and GPIO12
                //   (`/ESP32/LED2`); forge-os agrees exactly — `self_test.c:49`
                //   `BLINK_GPIO_1 9`, `:50` `BLINK_GPIO_2 12`. We carry one LED,
                //   so it is LED1.
                // * `fan_tach_pin` 14 -> **-1**. GPIO14 is `/ESP32/INA_ALRT`,
                //   the INA260's alert output. Sampling it as a tachometer would
                //   read alert edges as fan pulses — a stopped fan could look
                //   like a spinning one to the `fan1_ever_seen` heuristic, which
                //   is the exact direction that must never fail open.
                // * `fan_pwm_pin` 11 -> **-1**. GPIO11 is **unconnected** on
                //   this board. Both fans are driven by the EMC2101s over I2C
                //   (`Thermal_setFanSpeedPercent`), and tach is read from the
                //   EMC2101's own registers 0x46/0x47 — forge-os contains no
                //   LEDC setup and no GPIO tach at all. Same honesty rule the
                //   DCENT_axe rows already apply.
                led_pin: 9,
                fan_pwm_pin: -1,
                fan_tach_pin: -1,
                default_frequency: 400.0,
                default_voltage_mv: 1150,
                max_voltage_mv: 1350,
                min_voltage_mv: 1000,
                // SAFETY: the two dies are in PARALLEL (README: "connected in
                // parallel"; ONE `TPS546_CONFIG_NANO` with `VOUT_COMMAND 1.2`).
                // `power.rs` derives the rail as per-ASIC mV x domains, so a 2
                // here would command 2.4 V onto parallel BM1370 dies. Same
                // hazard class as Lucky LV08 above and Hammer DC06. A future
                // "the board has two ASICs so it must have two domains"
                // refactor must NOT raise it.
                voltage_domains: 1,
                //
                // ⚠ WHY THIS ENVELOPE IS OURS AND NOT THE VENDOR'S
                //
                // forge-os `Kconfig.projbuild` defaults `ASIC_VOLTAGE` to
                // **1400** mV with help text reading "1200 for BM1366 or 1400
                // for BM1397 is typical" — unmigrated stock-ESP-Miner values
                // carried onto a board with no BM1397 on it. They are not
                // inert: `system.c:179` and `self_test.c:221` both call
                // `VCORE_set_voltage(nvs_config_get_u16(NVS_CONFIG_ASIC_VOLTAGE,
                // CONFIG_ASIC_VOLTAGE) / 1000.0, ...)`, and on a fresh flash
                // there is no NVS value, so a factory-fresh unit commands
                // 1.400 V onto two parallel BM1370 dies. There is no
                // `sdkconfig.defaults` override.
                //
                // Nothing downstream catches it: `VCORE_set_voltage`
                // (`vcore.c:44`) has no clamp and passes the float straight to
                // `TPS546_set_vout`, and the only backstop is
                // `TPS546_INIT_VOUT_MAX = 2` — a **2.0 V** ceiling configured on
                // a 1.2 V rail, which admits 1.4 V without complaint and would
                // admit considerably worse.
                //
                // `max_voltage_mv: 1350` plus `tps546_guard`'s ceiling logic is
                // the clamp upstream does not have. This is the same
                // refuse-don't-copy call as the NerdQX over-current trip and
                // the Lucky LV08 domain multiply: a vendor shipping a
                // protection value that cannot protect.
                //
                // (`ASIC_FREQUENCY` defaults to 250 MHz, likewise labelled
                // BM1397. Wrong direction, so not a safety issue, but it
                // confirms neither constant was revisited for this board.)
                power_offset_w: 5.0,
                ..common
            },
            BitAxeModel::BitaxeNaja => BoardConfig {
                // 2x BM1373 in PARALLEL on one 2-phase TPS546D24A rail.
                asic_count: 2,
                //
                // ⚠ THIS ENVELOPE IS BM1373's, NOT THE GAMMA TURBO's.
                //
                // Naja is structurally a Gamma Turbo — 2 dies, one domain,
                // EMC2103 with the diodes crossed the same way — and copying
                // the GT row (525 MHz / 1150 mV / 1350 max) is the obvious
                // mistake. It is the exact mistake the `Q1373` arm above exists
                // to warn about: "Inheriting the Q1370 row would command a
                // BM1370 voltage onto BM1373 dies."
                //
                // These numbers are the vendor's own for this silicon, read
                // from `ESP-Miner-NerdQAxePlus/main/boards/q1373.cpp`:
                //   m_defaultAsicFrequency     = 350
                //   m_defaultAsicVoltageMillis = 1010
                //   m_absMinAsicVoltageMillis  = 900
                //   m_absMaxAsicVoltageMillis  = 1200
                // Identical to what our own `Q1373` row already ships, which is
                // the point: the ASIC sets the envelope, the board does not.
                default_frequency: 350.0,
                default_voltage_mv: 1010,
                max_voltage_mv: 1200,
                min_voltage_mv: 900,
                // SAFETY: PARALLEL, proven at pad level — A1 and A2 both put
                // their VDD exposed pad on `/Vcore` and their VSS on GND, and
                // L1/L2 both land on `/Vcore` (`bitaxeNaja.kicad_pcb`). A 2
                // here would command double onto parallel BM1373 dies. The
                // shared `VDD1/2/3` pins between the chips are decoupling taps
                // and must not be read as a series stack.
                voltage_domains: 1,
                //
                // ⚠ THE RAIL CANNOT BE CUT BY FIRMWARE. `EN_UVLO` is a fixed
                // 12 V divider and `PWR_EN` is a dangling net, so Vcore is live
                // whenever the barrel is. The EMC2103's `SYS_SHDN` and `ALERT`
                // pins are both unconnected, so the hardware thermal trip is
                // inert too. Every over-temp response on this board is
                // firmware: command VOUT down over PMBus, and spin the fan.
                // That is why the row declares `Emc2103` and so inherits
                // mandatory fan-tach proof, and why the envelope above is the
                // conservative BM1373 one rather than anything tuned.
                power_offset_w: 10.0,
                ..common
            },
        };

        board.normalize_power_pins();
        board
    }

    fn normalize_power_pins(&mut self) {
        // The ASIC LDO enable is a property of the board FAMILY, not of the
        // (NVS-overridable) `power_controller` field — see `LdoEnable`. Cleared
        // first so a re-normalize after a hardware override can only ever
        // REMOVE a stale pin, never leave one behind.
        self.ldo_enable_pin = match self.model.asic_ldo_enable() {
            Some(LdoEnable::Gpio { pin }) => pin,
            // An expander LDO is NOT an ESP pin. Leaving the sentinel keeps it
            // out of the GPIO binder's match key, which is correct: there is no
            // ESP peripheral to bind. `asic_ldo_enable()` stays the single
            // source of truth for which transport raises it.
            Some(LdoEnable::Expander { .. }) | None => -1,
        };
        // Likewise the expander rail enable: normalized here so `rail_bringup()`
        // reads settled state, matching how it treats `buck_enable_pin`.
        // Cleared first so a re-normalize after an NVS hardware override can
        // only ever REMOVE a stale actuator, never leave one behind.
        self.expander_rail_enable = match self.model.buck_enable_wiring() {
            Some(BuckEnableWiring::Expander { addr, pin }) => Some(ExpanderPin { addr, pin }),
            _ => None,
        };
        // Models that pin their own buck-enable wiring do so as DATA
        // (`BitAxeModel::buck_enable_wiring`), not as another arm here. All of
        // them also disable plug-sense.
        if let Some(wiring) = self.model.buck_enable_wiring() {
            match wiring {
                BuckEnableWiring::NotAGpio => {
                    self.buck_enable_pin = -1;
                    self.buck_enable_active_low = false;
                }
                BuckEnableWiring::Gpio { pin, active_low } => {
                    self.buck_enable_pin = pin;
                    self.buck_enable_active_low = active_low;
                }
                // The enable exists, but not as an ESP pin. Same sentinel as
                // `NotAGpio` on purpose — the GPIO binder and the panic hook's
                // `PANIC_BUCK_GPIO` must both see "nothing to drive here" —
                // with the actuator itself carried in `expander_rail_enable`
                // above. `rail_bringup()` is what recombines them.
                BuckEnableWiring::Expander { .. } => {
                    self.buck_enable_pin = -1;
                    self.buck_enable_active_low = false;
                }
            }
            self.plug_sense_pin = -1;
        } else if self.power_controller == PowerControllerKind::Ds4432u {
            self.buck_enable_pin = 10;
            self.buck_enable_active_low = true;
            self.plug_sense_pin = if self.plug_sense { 12 } else { -1 };
        } else {
            self.buck_enable_pin = 46;
            self.buck_enable_active_low = false;
            self.plug_sense_pin = if self.plug_sense { 12 } else { -1 };
        }
    }

    pub fn apply_hardware_config(&mut self, hw: &BoardHardwareConfig) {
        self.plug_sense = hw.plug_sense;
        self.asic_enable = hw.asic_enable;
        self.fan_controller = hw.fan_controller;
        self.temp_sensor = hw.temp_sensor;
        self.power_controller = hw.power_controller;
        self.has_ina260 = hw.has_ina260;
        self.emc_internal_temp = hw.emc_internal_temp;
        self.emc_ideality_factor = hw.emc_ideality_factor;
        self.emc_beta_compensation = hw.emc_beta_compensation;
        self.temp_offset_c = hw.temp_offset_c;
        self.power_consumption_target_w = hw.power_consumption_target_w;
        self.normalize_power_pins();
    }

    pub fn mining_capable(&self) -> bool {
        self.asic_count > 0 && self.default_frequency > 0.0
    }

    pub fn has_trusted_thermal_source_configured(&self) -> bool {
        self.temp_sensor != TempSensorKind::None
            || self.power_controller == PowerControllerKind::Tps546
    }

    /// When `main.rs` may assert this board's enable GPIO. See
    /// [`RailEnableOrder`].
    ///
    /// Derived from the declared regulator, not from a per-model list, so a new
    /// board carrying a TPS5364x inherits the correct ordering with no new code.
    pub fn rail_enable_order(&self) -> RailEnableOrder {
        match self.power_controller {
            PowerControllerKind::Tps5364x => RailEnableOrder::RegulatorBeforeGpio,
            _ => RailEnableOrder::GpioBeforeRegulator,
        }
    }

    /// How this board's ASIC rail can be raised and cut. See [`RailBringup`].
    ///
    /// Derived from the already-normalized `buck_enable_pin` rather than from
    /// `BitAxeModel::buck_enable_wiring` directly, so it reflects what the GPIO
    /// binder and the panic hook will actually see — a row that pins its wiring
    /// and a row that inherits the stock default are classified the same way.
    pub fn rail_bringup(&self) -> RailBringup {
        if self.buck_enable_pin >= 0 {
            RailBringup::EnableGpio
        } else if let Some(e) = self.expander_rail_enable {
            // Checked BEFORE `has_voltage_control()`. A Q-series board answers
            // yes to both, and the expander is the stronger actuator: its
            // TPS5364x ignores `OPERATION`, so the regulator cannot cut its own
            // output while the expander pin can. Ordering these the other way
            // round would classify a cuttable board as `RegulatorOnly` and then
            // refuse it at the capability check — which is exactly the state
            // these two boards were stuck in.
            RailBringup::ExpanderGpio {
                addr: e.addr,
                pin: e.pin,
            }
        } else if self.model.has_voltage_control() {
            RailBringup::RegulatorOnly
        } else {
            RailBringup::NoActuator
        }
    }

    pub fn has_display(&self) -> bool {
        self.display_kind.has_hardware()
    }

    /// Boards that MUST prove a working tachometer before/while mining.
    ///
    /// Three ADDITIVE rungs (each can only widen the set):
    /// 1. `is_hex()` — the inherent BitAxe Hex 6-chip/3-domain requirement
    ///    (unchanged since XPSAFE).
    /// 2. runtime `fan_controller == Emc2103` — GT-class boards, including
    ///    via NVS hardware override (unchanged).
    /// 3. `fan_tach_required` — row-declared capability from
    ///    [`BoardVersionProfile::fan_tach_required`] (Lucky LV07/LV08: a
    ///    140 W nine-die board must never mine on an unproven fan). Closes
    ///    the R2 §13.4 gap without smuggling Lucky into `is_hex()`.
    ///
    /// The exact resulting set over all profile rows is pinned by
    /// `mandatory_tach_set_is_exactly_the_declared_boards` — a refactor that
    /// widens or narrows it must consciously edit that test.
    pub fn requires_fan_tach(&self) -> bool {
        self.model.is_hex()
            || self.fan_controller == FanControllerKind::Emc2103
            || self.fan_tach_required
    }

    /// XPSAFE-7: opt a single-fan EMC2101 board into fail-closed tach proof.
    ///
    /// For an operator who knows their fan's tach wire is connected. Setting
    /// this makes [`tach_proof_required`](Self::tach_proof_required) true so the
    /// `main.rs` boot gate proves RPM>0 at startup and the runtime loop treats a
    /// stalled fan as a fault — the same fail-closed posture Hex/GT boards
    /// already get — instead of the lenient `fan1_ever_seen` heuristic that lets
    /// a fan which NEVER spins masquerade as a tachless board.
    pub fn set_fan_tach_present(&mut self, present: bool) {
        self.fan_tach_present = present;
    }

    /// XPSAFE-7: the capability the `main.rs` fan-proof gates should consume.
    ///
    /// True when this board must prove a working tachometer — either because the
    /// hardware inherently requires it ([`requires_fan_tach`](Self::requires_fan_tach):
    /// Hex / EMC2103-GT), OR because the operator asserted a wired tach via
    /// [`set_fan_tach_present`](Self::set_fan_tach_present) (`fan_tach_present`).
    ///
    /// WF-F note: `main.rs` should gate the EMC2101 single-fan boot RPM assert
    /// and the runtime "tach must be >0 while fan>0" rule on THIS method, not on
    /// `requires_fan_tach()` alone, so an opted-in single-fan board fails closed.
    /// When this is false the board legitimately has no tach proof — surface
    /// "no fan proof (heuristic only); thermal ladder is the backstop" in
    /// telemetry / self-test so the operator knows.
    pub fn tach_proof_required(&self) -> bool {
        self.requires_fan_tach() || self.fan_tach_present
    }

    /// XPSAFE-8: declare which dual-fan headers are physically populated.
    ///
    /// Does not relax [`requires_fan_tach`](Self::requires_fan_tach); it only
    /// scopes WHICH fans the mandatory proof is demanded from.
    pub fn set_fans_populated(&mut self, populated: FanPopulation) {
        self.fans_populated = populated;
    }

    /// XPSAFE-8: is a fan the operator declared PRESENT failing to report tach?
    ///
    /// This is the predicate the `main.rs` dual-fan boot gate and runtime
    /// stall kill must consume instead of a bare `rpm1 == 0 || rpm2 == 0`.
    /// With the default [`FanPopulation::Both`] it is exactly that expression,
    /// so no shipping board's verdict changes. With one header declared, an
    /// unpopulated header's permanent 0 RPM stops being read as a dead fan,
    /// while the populated fan keeps the full fail-closed posture: it must
    /// prove RPM at boot and a later stall still trips the kill.
    pub fn declared_fan_tach_missing(&self, rpm1: u32, rpm2: u32) -> bool {
        (self.fans_populated.fan1() && rpm1 == 0) || (self.fans_populated.fan2() && rpm2 == 0)
    }

    /// XPSAFE-8: have all declared-present fans proven tach? Boot retry exit.
    pub fn declared_fan_tach_proven(&self, rpm1: u32, rpm2: u32) -> bool {
        !self.declared_fan_tach_missing(rpm1, rpm2)
    }

    /// XPSAFE-8: the RPM to treat as this board's primary fan reading.
    ///
    /// Header 1 when it is populated, otherwise header 2. Without this a
    /// `Fan2Only` board would feed a hardcoded 0 into the stall kill and the
    /// primary telemetry field while its real fan spins.
    pub fn primary_tach_rpm(&self, rpm1: u32, rpm2: u32) -> u32 {
        if self.fans_populated.fan1() {
            rpm1
        } else {
            rpm2
        }
    }

    pub fn accessory_mode(&self) -> AccessoryMode {
        if self.model.has_bap() {
            AccessoryMode::BapTouch
        } else {
            AccessoryMode::None
        }
    }

    pub fn validate_accessory_mode(&self, requested: AccessoryMode) -> Result<(), &'static str> {
        match (self.accessory_mode(), requested) {
            (AccessoryMode::BapTouch, AccessoryMode::W5500Lan)
            | (AccessoryMode::W5500Lan, AccessoryMode::BapTouch) => Err(
                "BAP Touch and W5500 LAN accessory modes share pins and cannot be enabled together",
            ),
            _ => Ok(()),
        }
    }

    /// Validate that the configuration is internally consistent.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.min_voltage_mv > self.max_voltage_mv {
            return Err("min_voltage_mv must be <= max_voltage_mv");
        }
        if self.default_voltage_mv < self.min_voltage_mv
            || self.default_voltage_mv > self.max_voltage_mv
        {
            return Err("default_voltage_mv must be within [min, max] range");
        }
        if self.asic_count == 0 {
            return Err("asic_count must be at least 1");
        }
        if self.voltage_domains == 0 {
            return Err("voltage_domains must be at least 1");
        }
        if self.mining_capable() && !self.has_trusted_thermal_source_configured() {
            return Err("mining-capable board requires a trusted temperature source");
        }
        Ok(())
    }
}

#[cfg(test)]
mod xpsafe7_fan_tach_capability {
    use super::*;

    // ── XPSAFE-7: default-OFF — no shipping board profile flips the new flag ──
    #[test]
    fn fan_tach_present_defaults_false_for_all_profiles() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            assert!(
                !cfg.fan_tach_present,
                "{} ({:?}) must default fan_tach_present=false (opt-in only)",
                profile.board_version, profile.model
            );
        }
    }

    // ── The EXACT mandatory-tach set over every profile row. ──
    // This is the refactor guard: any change that widens OR narrows the set
    // of boards requiring fan-tach proof (a safety-posture change either way)
    // must consciously edit this list. History: is_hex()||Emc2103 covered the
    // first seven; the Lucky enablement wave added 2007/2008 via the
    // row-declared `fan_tach_required` capability (R2 §13.4 — a 140 W
    // nine-die LV08 with no mandatory fan proof was the gap). Every other
    // previously-shipping board keeps its exact prior verdict.
    #[test]
    fn mandatory_tach_set_is_exactly_the_declared_boards() {
        // In BoardVersionProfile::ALL array order. Sources:
        // is_hex(): 302/303 (Hex Ultra), 701/702 (Hex Supra), 920/9060
        // (DCENT_axe Hex); EMC2103: 801 (GT); row capability: 2007/2008
        // (Lucky LV07/LV08).
        // "4200" (BitAxe Naja) joins via the EMC2103 rung, and SHOULD: two
        // dies, and the EMC2103's own SYS_SHDN/ALERT pins are unconnected on
        // that board, so a stalled fan has no hardware backstop at all.
        let expected: &[&str] = &[
            "302", "303", "701", "702", "801", "920", "9060", "2007", "2008", "4200",
        ];
        let mut actual: Vec<&str> = Vec::new();
        for profile in BoardVersionProfile::ALL.iter() {
            let cfg = BoardConfig::for_profile(profile);
            if cfg.requires_fan_tach() {
                actual.push(profile.board_version);
            }
        }
        assert_eq!(
            actual, expected,
            "the set of boards requiring mandatory fan-tach proof changed — \
             this is a safety-posture change in BOTH directions; edit this \
             list only with explicit intent"
        );
        // And the row capability itself is declared on exactly 2007/2008.
        for profile in BoardVersionProfile::ALL.iter() {
            assert_eq!(
                profile.fan_tach_required(),
                matches!(profile.board_version, "2007" | "2008"),
                "board {}: row-declared fan_tach_required drifted",
                profile.board_version
            );
        }
    }

    // ── XPSAFE-7: tach_proof_required matches requires_fan_tach when not opted-in ─
    // Default-preserving: with the flag off, the new capability is exactly the
    // old hardware-required predicate, so existing Hex/GT behavior is unchanged
    // and single-fan EMC2101 boards still get the heuristic (no proof required).
    #[test]
    fn tach_proof_required_equals_requires_fan_tach_by_default() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            assert_eq!(
                cfg.tach_proof_required(),
                cfg.requires_fan_tach(),
                "{} ({:?}): with fan_tach_present=false the capability must equal \
                 the hardware-required predicate",
                profile.board_version,
                profile.model
            );
        }
    }

    // ── XPSAFE-8: the default fan population reproduces the OLD gate exactly ──
    // The prior boot/runtime predicate was a bare `rpm1 == 0 || rpm2 == 0`.
    // With the default `Both`, `declared_fan_tach_missing` must equal it for
    // every row and every RPM combination, so this change is provably
    // behavior-preserving for every shipping board.
    #[test]
    fn default_fan_population_equals_the_old_both_fans_predicate() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            assert_eq!(
                cfg.fans_populated,
                FanPopulation::Both,
                "{}: every row must default to both headers populated",
                profile.board_version
            );
            for (rpm1, rpm2) in [(0, 0), (0, 1500), (1500, 0), (1500, 1500)] {
                assert_eq!(
                    cfg.declared_fan_tach_missing(rpm1, rpm2),
                    rpm1 == 0 || rpm2 == 0,
                    "{}: default population must reproduce the old predicate at \
                     fan1={rpm1} fan2={rpm2}",
                    profile.board_version
                );
            }
        }
    }

    // ── XPSAFE-8: declaring one header keeps the fan you HAVE fail-closed ──
    // The whole point of the change: an unpopulated header's permanent 0 RPM
    // stops blocking, but the populated fan must still prove tach and a later
    // stall must still trip. If this test can pass with a stalled declared fan,
    // the gate has been gutted rather than scoped.
    #[test]
    fn single_fan_declaration_scopes_the_gate_without_disarming_it() {
        // Board 702 (Hex Supra) is in the mandatory-tach set.
        let mut cfg = BoardConfig::for_profile(
            BoardVersionProfile::find("702").expect("702 is a registered row"),
        );
        assert!(
            cfg.requires_fan_tach(),
            "declaring a fan population must NOT remove the Hex tach requirement"
        );

        cfg.set_fans_populated(FanPopulation::Fan2Only);
        assert!(cfg.requires_fan_tach(), "still mandatory-tach after declaring");
        assert_eq!(cfg.fans_populated.count(), 1);

        // The empty header reading 0 forever no longer blocks...
        assert!(!cfg.declared_fan_tach_missing(0, 1650));
        assert!(cfg.declared_fan_tach_proven(0, 1650));
        // ...but the fan that IS fitted must prove tach, and a stall trips.
        assert!(cfg.declared_fan_tach_missing(0, 0));
        assert!(cfg.declared_fan_tach_missing(1650, 0));
        // Primary telemetry/stall RPM follows the populated header.
        assert_eq!(cfg.primary_tach_rpm(0, 1650), 1650);

        // Mirror case: only header 1 fitted.
        cfg.set_fans_populated(FanPopulation::Fan1Only);
        assert!(!cfg.declared_fan_tach_missing(1650, 0));
        assert!(cfg.declared_fan_tach_missing(0, 1650));
        assert_eq!(cfg.primary_tach_rpm(1650, 0), 1650);
    }

    // ── XPSAFE-8: "no fans" must be unrepresentable, not merely refused ──
    #[test]
    fn every_fan_population_declares_at_least_one_header() {
        for p in [
            FanPopulation::Both,
            FanPopulation::Fan1Only,
            FanPopulation::Fan2Only,
        ] {
            assert!(
                p.count() >= 1,
                "{p:?}: a declaration that populates no header would disarm the \
                 mandatory-tach gate entirely"
            );
            assert!(p.fan1() || p.fan2());
            // A gate that demands nothing can never report a missing fan.
            assert!(
                p.fan1() || p.fan2(),
                "{p:?}: at least one header must be proof-bearing"
            );
        }
        // All-zero RPM must block under EVERY declaration.
        let mut cfg = BoardConfig::for_model(BitAxeModel::HexSupra);
        for p in [
            FanPopulation::Both,
            FanPopulation::Fan1Only,
            FanPopulation::Fan2Only,
        ] {
            cfg.set_fans_populated(p);
            assert!(
                cfg.declared_fan_tach_missing(0, 0),
                "{p:?}: zero tach on every header must always fail closed"
            );
        }
    }

    // ── XPSAFE-8: Hex / EMC2103 boards already require proof regardless of flag ──
    #[test]
    fn hex_and_emc2103_always_require_proof() {
        // A Hex board (inherently requires tach) keeps proof required even with
        // the opt-in flag left off.
        let hex = BoardConfig::for_model(BitAxeModel::HexUltra);
        assert!(hex.requires_fan_tach());
        assert!(hex.tach_proof_required());

        // An EMC2103 (GT-class) board requires proof via fan_controller too.
        let gt = BoardConfig::for_model(BitAxeModel::GammaTurbo);
        if gt.fan_controller == FanControllerKind::Emc2103 {
            assert!(gt.requires_fan_tach());
            assert!(gt.tach_proof_required());
        }
    }

    // ── XPSAFE-7: opting a single-fan EMC2101 board in makes proof required ──
    #[test]
    fn opt_in_single_fan_board_becomes_fail_closed() {
        // A standard single-ASIC EMC2101 board: no inherent tach requirement.
        let mut cfg = BoardConfig::for_model(BitAxeModel::Ultra);
        assert_eq!(cfg.fan_controller, FanControllerKind::Emc2101);
        assert!(
            !cfg.requires_fan_tach(),
            "single-fan EMC2101 board must not inherently require tach"
        );
        assert!(
            !cfg.tach_proof_required(),
            "before opt-in, an EMC2101 single-fan board relies on the heuristic"
        );

        // Operator asserts the tach wire is connected.
        cfg.set_fan_tach_present(true);
        assert!(cfg.fan_tach_present);
        assert!(
            cfg.tach_proof_required(),
            "after opt-in, the board must require fail-closed tach proof"
        );
        // requires_fan_tach() (pure hardware predicate) is unchanged by the flag.
        assert!(
            !cfg.requires_fan_tach(),
            "opt-in must NOT rewrite the hardware-required predicate"
        );

        // Toggling back off restores the heuristic posture.
        cfg.set_fan_tach_present(false);
        assert!(!cfg.tach_proof_required());
    }
}

#[cfg(test)]
mod public_bitaxe_install_targets {
    use super::*;

    const PUBLIC_TARGETS: [(BitAxeModel, &str, &str, u8, u16); 6] = [
        (BitAxeModel::Max, "bitaxe-max", "max", 1, 0x1397),
        (BitAxeModel::Ultra, "bitaxe-ultra", "ultra", 1, 0x1366),
        (BitAxeModel::Supra, "bitaxe-supra", "supra", 1, 0x1368),
        (BitAxeModel::Gamma, "bitaxe-gamma", "gamma", 1, 0x1370),
        (
            BitAxeModel::HexUltra,
            "bitaxe-hex-ultra",
            "hexultra",
            6,
            0x1366,
        ),
        (
            BitAxeModel::HexSupra,
            "bitaxe-hex-supra",
            "suprahex",
            6,
            0x1368,
        ),
    ];

    #[test]
    fn requested_public_install_targets_keep_canonical_identity() {
        for (model, board_target, device_model, asic_count, chip_id) in PUBLIC_TARGETS {
            assert_eq!(model.board_target(), board_target);
            assert_eq!(model.canonical_key(), device_model);
            assert_eq!(BitAxeModel::from_device_model(device_model), Some(model));
            assert_eq!(model.asic_count(), asic_count);
            assert_eq!(model.expected_chip_id(), chip_id);

            let board = BoardConfig::for_model(model);
            assert_eq!(board.model, model);
            assert_eq!(
                board.device_model, device_model,
                "{board_target} BoardConfig device_model must be canonical"
            );
            assert_eq!(board.asic_count, asic_count);
            assert!(board.validate().is_ok(), "{board_target} must validate");
            assert!(
                board.mining_capable(),
                "{board_target} must be mining-capable"
            );
        }
    }
}

#[cfg(test)]
mod dcent_axe_bm1397_variants {
    use super::*;

    // Canonical `9###` registry versions (BOARD_VERSION_REGISTRY.md §5); the
    // legacy 3-digit aliases are pinned separately below.
    const DCENT_AXE_BM1397: [(BitAxeModel, &str, u8, &str); 3] = [
        (BitAxeModel::DcentAxeBm1397, "dcentaxe_bm1397", 1, "9010"),
        (
            BitAxeModel::DcentAxeQuadBm1397,
            "dcentaxe_quad_bm1397",
            4,
            "9040",
        ),
        (
            BitAxeModel::DcentAxeHexBm1397,
            "dcentaxe_hex_bm1397",
            6,
            "9060",
        ),
    ];

    // ── Legacy 900/910/920 aliases stay resolvable and byte-identical to the
    // canonical 9### rows (same board, Phase-0 rename — a pre-migration NVS
    // blob must keep resolving to the exact same hardware profile). ──
    #[test]
    fn legacy_900_family_aliases_resolve_identically_to_canonical_rows() {
        for (legacy, canonical) in [("900", "9010"), ("910", "9040"), ("920", "9060")] {
            let l = BoardVersionProfile::find(legacy)
                .unwrap_or_else(|| panic!("legacy row {legacy} must stay resolvable"));
            let c = BoardVersionProfile::find(canonical)
                .unwrap_or_else(|| panic!("canonical row {canonical} must exist"));
            assert_eq!(l.model, c.model, "{legacy}/{canonical}: model");
            assert_eq!(
                l.device_model, c.device_model,
                "{legacy}/{canonical}: device_model"
            );
            assert_eq!(l.asic_model, c.asic_model, "{legacy}/{canonical}: asic");
            assert_eq!(
                l.fan_controller, c.fan_controller,
                "{legacy}/{canonical}: fan"
            );
            assert_eq!(l.temp_sensor, c.temp_sensor, "{legacy}/{canonical}: temp");
            assert_eq!(
                l.power_controller, c.power_controller,
                "{legacy}/{canonical}: power"
            );
            assert_eq!(l.has_ina260, c.has_ina260, "{legacy}/{canonical}: ina260");
            assert_eq!(
                l.emc_internal_temp, c.emc_internal_temp,
                "{legacy}/{canonical}: emc_internal_temp"
            );
            assert_eq!(
                l.emc_ideality_factor, c.emc_ideality_factor,
                "{legacy}/{canonical}: ideality"
            );
            assert_eq!(
                l.temp_offset_c, c.temp_offset_c,
                "{legacy}/{canonical}: offset"
            );
            assert_eq!(
                l.power_consumption_target_w, c.power_consumption_target_w,
                "{legacy}/{canonical}: power target"
            );
            assert_eq!(l.temp_flip, c.temp_flip, "{legacy}/{canonical}: temp_flip");
            assert_eq!(l.live_proof, c.live_proof, "{legacy}/{canonical}: proof");
        }
        // The model default is the CANONICAL row, not the legacy alias.
        assert_eq!(
            BoardVersionProfile::default_for_model(BitAxeModel::DcentAxeBm1397).board_version,
            "9010"
        );
        assert_eq!(
            BoardVersionProfile::default_for_model(BitAxeModel::DcentAxeQuadBm1397).board_version,
            "9040"
        );
        assert_eq!(
            BoardVersionProfile::default_for_model(BitAxeModel::DcentAxeHexBm1397).board_version,
            "9060"
        );
    }

    // ── fan_pwm_pin honesty (FULL_PREFAB_REVIEW_2026-07-11 LOW): DCENT_axe has
    // no ESP-driven fan-PWM line (I2C fan controller generates PWM; GPIO11 is
    // unconnected on the BM1397 netlist). Other boards keep their stock pin. ──
    #[test]
    fn dcentaxe_fan_pwm_pin_is_honest_minus_one() {
        for (model, _key, _count, _ver) in DCENT_AXE_BM1397 {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(
                cfg.fan_pwm_pin, -1,
                "{model:?}: fan PWM is generated by the I2C fan controller, \
                 not an ESP GPIO — the pin claim must be -1"
            );
            // The tach input IS wired (FAN_TACH net / GPIO14) — unchanged.
            assert_eq!(cfg.fan_tach_pin, 14, "{model:?}: tach pin unchanged");
        }
        // No collateral change to any other family's arm.
        assert_eq!(BoardConfig::for_model(BitAxeModel::Max).fan_pwm_pin, 11);
        assert_eq!(BoardConfig::for_model(BitAxeModel::Gamma).fan_pwm_pin, 11);
        assert_eq!(
            BoardConfig::for_model(BitAxeModel::HexUltra).fan_pwm_pin,
            11
        );
        assert_eq!(BoardConfig::for_model(BitAxeModel::NerdNOS).fan_pwm_pin, -1);
    }

    // ── M-7 (FULL_PREFAB_REVIEW_2026-07-11): status-LED kind metadata. Only
    // the netlist-confirmed BM1397 single carries the SK6812; everything else
    // (including Quad/Hex, whose netlists don't exist yet) stays PlainGpio. ──
    #[test]
    fn status_led_kind_is_sk6812_only_for_the_netlist_confirmed_single() {
        assert_eq!(
            BitAxeModel::DcentAxeBm1397.status_led_kind(),
            StatusLedKind::Sk6812
        );
        for model in [
            BitAxeModel::Max,
            BitAxeModel::Ultra,
            BitAxeModel::Supra,
            BitAxeModel::Gamma,
            BitAxeModel::GammaTurbo,
            BitAxeModel::NerdNOS,
            BitAxeModel::DcentAxeQuadBm1397,
            BitAxeModel::DcentAxeHexBm1397,
        ] {
            assert_eq!(
                model.status_led_kind(),
                StatusLedKind::PlainGpio,
                "{model:?}: must stay PlainGpio (no speculative SK6812 claim)"
            );
        }
    }

    // ── The three DCENT_axe SKUs resolve from their canonical device-model key ──
    #[test]
    fn from_device_model_resolves_the_three_skus() {
        for (model, key, _count, _ver) in DCENT_AXE_BM1397 {
            assert_eq!(
                BitAxeModel::from_device_model(key),
                Some(model),
                "device_model '{key}' must resolve to {model:?}"
            );
            // canonical_key round-trips back to the same model.
            assert_eq!(
                BitAxeModel::from_device_model(model.canonical_key()),
                Some(model),
                "canonical_key '{}' must round-trip to {model:?}",
                model.canonical_key()
            );
        }
        // A couple of human/marketing aliases also resolve.
        assert_eq!(
            BitAxeModel::from_device_model("quad_bm1397"),
            Some(BitAxeModel::DcentAxeQuadBm1397)
        );
        assert_eq!(
            BitAxeModel::from_device_model("DCENT_axe Hex BM1397"),
            Some(BitAxeModel::DcentAxeHexBm1397)
        );
    }

    // ── All three drive the BM1397 chip id (detection register 0x00) ──
    #[test]
    fn expected_chip_id_is_bm1397() {
        for (model, _key, _count, _ver) in DCENT_AXE_BM1397 {
            assert_eq!(
                model.expected_chip_id(),
                0x1397,
                "{model:?} must expect chip id 0x1397"
            );
        }
    }

    // ── BAP is populated on every DCENT_axe board ──
    #[test]
    fn has_bap_is_true_for_all_three() {
        for (model, _key, _count, _ver) in DCENT_AXE_BM1397 {
            assert!(model.has_bap(), "{model:?} must report has_bap()==true");
            // Accessory mode follows has_bap and validates against itself.
            let cfg = BoardConfig::for_model(model);
            assert_eq!(cfg.accessory_mode(), AccessoryMode::BapTouch);
            assert!(cfg.validate_accessory_mode(cfg.accessory_mode()).is_ok());
        }
    }

    // ── Chip counts: 1 / 4 / 6 ──
    #[test]
    fn asic_counts_are_one_four_six() {
        for (model, _key, count, _ver) in DCENT_AXE_BM1397 {
            assert_eq!(model.asic_count(), count, "{model:?} chip count");
            assert_eq!(BoardConfig::for_model(model).asic_count, count);
        }
    }

    // ── Each SKU has a profile row that resolves and builds a valid board ──
    #[test]
    fn profiles_resolve_and_build_valid_boards() {
        for (model, key, count, ver) in DCENT_AXE_BM1397 {
            let profile = BoardVersionProfile::find(ver)
                .unwrap_or_else(|| panic!("profile {ver} for {model:?} must exist"));
            assert_eq!(profile.model, model);
            assert_eq!(profile.asic_model, "BM1397");
            assert_eq!(profile.device_model, key);
            assert_eq!(BoardVersionProfile::default_for_model(model).model, model);

            let board = BoardConfig::for_model(model);
            assert_eq!(board.model, model);
            assert_eq!(board.asic_count, count);
            assert!(
                board.validate().is_ok(),
                "{model:?} board config must validate: {:?}",
                board.validate()
            );
            assert!(board.mining_capable(), "{model:?} must be mining-capable");
        }
    }

    // ── ESP-Miner board-version parity (bitaxeorg/ESP-Miner main/device_config.h) ──
    // Every board_version ESP-Miner recognizes MUST resolve here to the correct
    // family + ASIC, so DCENT_OS can be flashed onto ANY existing Bitaxe and
    // auto-identify it by its stored board_version instead of falling back to a
    // default (a wrong family = wrong sensors / power target = a safety risk).
    // When ESP-Miner adds a new board_version, this test flags the gap — that is
    // how the 603 (Gamma) gap was caught during the ESP-Miner cross-check.
    const ESP_MINER_DEVICE_CONFIG_H: &str =
        include_str!("../../");
    const ESP_MINER_FIXTURE_MANIFEST: &str =
        include_str!("../../");

    #[derive(Clone, Copy, Debug)]
    struct UpstreamBoardVersion<'a> {
        version: &'a str,
        model: BitAxeModel,
        asic: &'static str,
    }

    fn c_initializer_field<'a>(row: &'a str, field: &str) -> Option<&'a str> {
        let marker = format!(".{field} = ");
        let value = row.split_once(&marker)?.1;
        let raw = value
            .split(|c| c == ',' || c == '}')
            .next()
            .map(str::trim)?;
        if let Some(quoted) = raw.strip_prefix('"') {
            Some(match quoted.strip_suffix('"') {
                Some(unquoted) => unquoted,
                None => quoted,
            })
        } else {
            Some(raw)
        }
    }

    fn upstream_family_to_model_and_asic(family: &str) -> (BitAxeModel, &'static str) {
        match family {
            "FAMILY_MAX" => (BitAxeModel::Max, "BM1397"),
            "FAMILY_ULTRA" => (BitAxeModel::Ultra, "BM1366"),
            "FAMILY_HEX" => (BitAxeModel::HexUltra, "BM1366"),
            "FAMILY_SUPRA" => (BitAxeModel::Supra, "BM1368"),
            "FAMILY_GAMMA" => (BitAxeModel::Gamma, "BM1370"),
            "FAMILY_GAMMA_DUO" => (BitAxeModel::GammaDuo, "BM1370"),
            "FAMILY_SUPRA_HEX" => (BitAxeModel::HexSupra, "BM1368"),
            "FAMILY_GAMMA_TURBO" => (BitAxeModel::GammaTurbo, "BM1370"),
            other => panic!("unknown ESP-Miner family constant in fixture: {other}"),
        }
    }

    fn parse_esp_miner_default_configs(header: &str) -> Vec<UpstreamBoardVersion<'_>> {
        header
            .lines()
            .filter_map(|line| {
                let row = line.trim();
                if !row.starts_with("{ .board_version = ") {
                    return None;
                }
                let version = c_initializer_field(row, "board_version")
                    .unwrap_or_else(|| panic!("missing board_version field in {row}"));
                let family = c_initializer_field(row, "family")
                    .unwrap_or_else(|| panic!("missing family field in {row}"));
                let (model, asic) = upstream_family_to_model_and_asic(family);
                Some(UpstreamBoardVersion {
                    version,
                    model,
                    asic,
                })
            })
            .collect()
    }

    fn expected_default_board_version_for_model(model: BitAxeModel) -> &'static str {
        match model {
            BitAxeModel::Max => "102",
            BitAxeModel::Ultra => "207",
            BitAxeModel::HexUltra => "302",
            BitAxeModel::Supra => "402",
            BitAxeModel::HexSupra => "701",
            BitAxeModel::Gamma => "601",
            BitAxeModel::GammaDuo => "650",
            BitAxeModel::GammaTurbo => "801",
            BitAxeModel::Touch => "601",
            BitAxeModel::GtTouch => "801",
            BitAxeModel::NerdNOS => "4010",
            BitAxeModel::NerdAxe => "4004",
            BitAxeModel::NerdAxeGamma => "4005",
            // Canonical `4XXX` rows (queue rank 41). These four used to answer
            // "402"/"601" — the ASIC-matched BitAxe row, borrowed as a shape.
            BitAxeModel::NerdQaxePlus => "4006",
            BitAxeModel::NerdQaxePP => "4007",
            BitAxeModel::NerdOctaxePlus => "4008",
            BitAxeModel::NerdOctaxeGamma => "4009",
            BitAxeModel::NerdQX => "4001",
            BitAxeModel::NerdHaxeGamma => "4002",
            BitAxeModel::NerdEko => "4003",
            BitAxeModel::Q1370 => "4370",
            BitAxeModel::Q1373 => "4373",
            BitAxeModel::DcentAxeBm1397 => "9010",
            BitAxeModel::DcentAxeQuadBm1397 => "9040",
            BitAxeModel::DcentAxeHexBm1397 => "9060",
            // Hammer canonical 3XXX rows (renumbered from the provisional
            // `hammer-*` strings, which stay resolvable as alias rows).
            BitAxeModel::HammerBc01 => "3001",
            BitAxeModel::HammerBc01Pro => "3011",
            BitAxeModel::HammerBc02 => "3002",
            BitAxeModel::HammerBc04 => "3004",
            BitAxeModel::HammerDc02 => "3102",
            BitAxeModel::HammerDc04 => "3104",
            BitAxeModel::HammerDc06 => "3106",
            // Lucky canonical 2XXX rows (SPEC §2.1).
            BitAxeModel::LuckyLv06 => "2006",
            BitAxeModel::LuckyLv07 => "2007",
            BitAxeModel::LuckyLv08 => "2008",
            BitAxeModel::BitForgeNano => "4100",
            BitAxeModel::BitaxeNaja => "4200",
        }
    }

    #[test]
    fn every_model_has_explicit_default_board_version() {
        const MODELS: &[BitAxeModel] = &[
            BitAxeModel::Max,
            BitAxeModel::Ultra,
            BitAxeModel::HexUltra,
            BitAxeModel::Supra,
            BitAxeModel::HexSupra,
            BitAxeModel::Gamma,
            BitAxeModel::GammaDuo,
            BitAxeModel::GammaTurbo,
            BitAxeModel::Touch,
            BitAxeModel::GtTouch,
            BitAxeModel::NerdNOS,
            BitAxeModel::NerdAxe,
            BitAxeModel::NerdQaxePlus,
            BitAxeModel::NerdQaxePP,
            BitAxeModel::DcentAxeBm1397,
            BitAxeModel::DcentAxeQuadBm1397,
            BitAxeModel::DcentAxeHexBm1397,
            BitAxeModel::HammerBc01,
            BitAxeModel::HammerBc01Pro,
            BitAxeModel::HammerBc02,
            BitAxeModel::HammerBc04,
            BitAxeModel::HammerDc02,
            BitAxeModel::HammerDc04,
            BitAxeModel::HammerDc06,
            BitAxeModel::LuckyLv06,
            BitAxeModel::LuckyLv07,
            BitAxeModel::LuckyLv08,
        ];

        for &model in MODELS {
            let expected = expected_default_board_version_for_model(model);
            let profile = BoardVersionProfile::default_for_model(model);
            assert_eq!(
                profile.board_version, expected,
                "{model:?} default board_version"
            );
            assert!(
                BoardVersionProfile::find(expected).is_some(),
                "{model:?} default board_version {expected} must resolve"
            );

            let board = BoardConfig::for_model(model);
            assert_eq!(board.model, model, "{model:?} default board model");
            assert_eq!(
                board.board_version, expected,
                "{model:?} default BoardConfig board_version"
            );
        }
    }

    #[test]
    fn nerd_family_defaults_preserve_model_specific_display_and_power_metadata() {
        // NerdAxe is a BM1366 DS4432U board on its own canonical row. It used
        // to assert `"601"` + `Tps546`, which described the γ.
        let nerdaxe = BoardConfig::for_model(BitAxeModel::NerdAxe);
        assert_eq!(nerdaxe.board_version, "4004");
        assert_eq!(nerdaxe.power_controller, PowerControllerKind::Ds4432u);
        assert_eq!(nerdaxe.asic_model, "BM1366");
        assert_eq!(nerdaxe.display_kind, DisplayKind::TDisplayS3);
        assert!(nerdaxe.has_display());

        let nerdaxe_gamma = BoardConfig::for_model(BitAxeModel::NerdAxeGamma);
        assert_eq!(nerdaxe_gamma.board_version, "4005");
        assert_eq!(nerdaxe_gamma.power_controller, PowerControllerKind::Tps546);
        assert_eq!(nerdaxe_gamma.asic_model, "BM1370");
        assert_eq!(nerdaxe_gamma.display_kind, DisplayKind::TDisplayS3);

        // Canonical `4006` (queue rank 41). This used to assert `"402"` — the
        // BitAxe Supra row, borrowed as a shape, which also handed this board
        // an 8 W power target and a BitAxe `live_proof`.
        let qaxe_plus = BoardConfig::for_model(BitAxeModel::NerdQaxePlus);
        assert_eq!(qaxe_plus.board_version, "4006");
        assert_eq!(qaxe_plus.asic_model, "BM1368");
        // The original assertion here pinned `Tps546` to express "must not
        // inherit the DS4432U Supra 400 profile". That intent is preserved and
        // now stated directly; the concrete value changed because these boards
        // genuinely carry a multi-phase TPS53647, not a TPS546.
        assert_ne!(
            qaxe_plus.power_controller,
            PowerControllerKind::Ds4432u,
            "NerdQaxe+ must not inherit the DS4432U Supra 400 profile"
        );
        assert_eq!(
            qaxe_plus.power_controller,
            PowerControllerKind::Tps5364x,
            "NerdQaxe+ carries a 2-phase TPS53647 (upstream nerdqaxeplus.cpp)"
        );
        assert_eq!(qaxe_plus.display_kind, DisplayKind::TDisplayS3);
        assert!(qaxe_plus.has_display());

        // Canonical `4007` — was `"601"`, the BitAxe Gamma row.
        let qaxe_pp = BoardConfig::for_model(BitAxeModel::NerdQaxePP);
        assert_eq!(qaxe_pp.board_version, "4007");
        assert_ne!(qaxe_pp.power_controller, PowerControllerKind::Ds4432u);
        assert_eq!(qaxe_pp.power_controller, PowerControllerKind::Tps5364x);
        assert_eq!(qaxe_pp.display_kind, DisplayKind::TDisplayS3);
        assert!(qaxe_pp.has_display());

        // The OCTAXE pair, likewise canonical. Their board_versions must be
        // DISTINCT from the QAxe pair's: the two OCTAXEs are separate boards
        // and, before rank 41, all four resolved onto only two rows.
        let octaxe_plus = BoardConfig::for_model(BitAxeModel::NerdOctaxePlus);
        assert_eq!(octaxe_plus.board_version, "4008");
        assert_eq!(octaxe_plus.asic_model, "BM1368");
        assert_eq!(octaxe_plus.power_controller, PowerControllerKind::Tps5364x);

        let octaxe_gamma = BoardConfig::for_model(BitAxeModel::NerdOctaxeGamma);
        assert_eq!(octaxe_gamma.board_version, "4009");
        assert_eq!(octaxe_gamma.asic_model, "BM1370");
        assert_eq!(octaxe_gamma.power_controller, PowerControllerKind::Tps5364x);

        let nerdnos = BoardConfig::for_model(BitAxeModel::NerdNOS);
        assert_eq!(nerdnos.display_kind, DisplayKind::None);
        assert!(!nerdnos.has_display());
    }

    // ── Nerd multi-ASIC boards: rail topology + fail-closed posture ───────────

    /// Every board carrying a TPS53647/TPS53667 multi-phase rail, Nerd-branded
    /// or not. The Q-series is included deliberately: it shares the rail, the
    /// TMP1075 topology and the single-domain parallel-ASIC arrangement, so
    /// every invariant these tests assert applies to it identically.
    const MULTIPHASE_NERD: &[BitAxeModel] = &[
        BitAxeModel::NerdQaxePlus,
        BitAxeModel::NerdQaxePP,
        BitAxeModel::NerdOctaxePlus,
        BitAxeModel::NerdOctaxeGamma,
        BitAxeModel::NerdQX,
        BitAxeModel::NerdHaxeGamma,
        BitAxeModel::NerdEko,
        BitAxeModel::Q1370,
        BitAxeModel::Q1373,
    ];

    #[test]
    fn multiphase_nerd_boards_are_single_voltage_domain() {
        // The Lucky LV08 hazard restated: these boards run their ASICs in
        // PARALLEL on one rail. `power.rs` derives the rail as per-ASIC mV ×
        // domains, so any value above 1 here multiplies the commanded voltage
        // onto parallel dies.
        for &model in MULTIPHASE_NERD {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(
                cfg.voltage_domains, 1,
                "{model:?} must be ONE voltage domain (ASICs in parallel)"
            );
        }
    }

    #[test]
    fn multiphase_nerd_boards_are_never_routed_through_the_hex_preset() {
        // is_hex() means "6 ASICs, 3 series domains, 12 V" and drives a TPS546
        // preset that would command a 3-domain rail. None of these qualify.
        for &model in MULTIPHASE_NERD {
            assert!(!model.is_hex(), "{model:?} must not be is_hex()");
            assert!(
                model.has_multiphase_vrm(),
                "{model:?} must carry a multi-phase VRM"
            );
            // Brand and hardware are separate questions. `is_nerd` answers the
            // first, `has_multiphase_vrm` the second — the Q-series is the
            // board that makes the difference visible, and any caller reaching
            // for `is_nerd` to mean "TPS5364x rail" would silently skip it.
            assert_eq!(
                model.is_nerd(),
                !model.is_q_series(),
                "{model:?}: every multi-phase board here is either Nerd-branded \
                 or Q-series, never both and never neither"
            );
            assert_eq!(
                model.is_multiphase_nerd(),
                model.is_nerd(),
                "{model:?}: is_multiphase_nerd is the Nerd-only subset"
            );
        }
    }

    #[test]
    fn the_nerdqx_envelope_is_the_clamped_one_not_the_nominal_one() {
        // NerdQX's TMP451 mux IS its identity check upstream: probe fails =>
        // "assuming non-QX board" => absMax drops to 495 MHz / 1150 mV and
        // loadSettings pulls the setpoint down with it. The static row must
        // declare the CLAMPED ceiling. Nominal 777 MHz / 1200 mV is a runtime
        // reward for a positive mux bring-up, never a row default.
        let cfg = BoardConfig::for_model(BitAxeModel::NerdQX);
        assert_eq!(cfg.default_frequency, 495.0);
        assert_eq!(cfg.default_voltage_mv, 1150);
        assert_eq!(cfg.max_voltage_mv, 1150);
        assert!(
            cfg.default_voltage_mv <= cfg.max_voltage_mv,
            "a default above the ceiling is a setpoint that cannot be applied"
        );
        assert!(cfg.min_voltage_mv <= cfg.default_voltage_mv);
    }

    #[test]
    fn nerdqx_nominal_envelope_is_reachable_only_behind_a_positive_probe() {
        let mut cfg = BoardConfig::for_model(BitAxeModel::NerdQX);
        cfg.apply_nerdqx_tmp451_identity(false);
        assert_eq!(cfg.default_frequency, 495.0);
        assert_eq!(cfg.default_voltage_mv, 1150);
        cfg.apply_nerdqx_tmp451_identity(true);
        assert_eq!(cfg.default_frequency, 777.0);
        assert_eq!(cfg.default_voltage_mv, 1200);
        assert_eq!(cfg.max_voltage_mv, 1200);
        assert!(cfg.min_voltage_mv <= cfg.default_voltage_mv);
        assert!(cfg.default_voltage_mv <= cfg.max_voltage_mv);

        let mut plus = BoardConfig::for_model(BitAxeModel::NerdQaxePlus);
        let before = plus.default_frequency;
        plus.apply_nerdqx_tmp451_identity(true);
        assert_eq!(plus.default_frequency, before, "non-QX rows must not move");
    }

    #[test]
    fn original_qaxe_quad_bm1366_is_stm32_not_an_esp_row() {
        // : original QAxe is a
        // Quad-BM1366 on STM32L072 (USB DFU), not ESP32-S3. Registering it as
        // a BitAxeModel would bind NerdQAxe+/ESP pins onto STM32 hardware.
        // Identity-only named gap until a native STM32 runtime exists.
        assert!(
            BitAxeModel::from_device_model("qaxe").is_none(),
            "bare 'qaxe' must not silently become an ESP mining row"
        );
        assert!(
            BitAxeModel::from_device_model("nerdqaxe").is_none(),
            "bare 'nerdqaxe' is the STM32-era name; ESP rows are nerdqaxe+ / ++"
        );
        let nerdaxe = BoardConfig::for_model(BitAxeModel::NerdAxe);
        assert_eq!(
            nerdaxe.asic_count, 1,
            "NerdAxe is 1x BM1366, not the quad QAxe"
        );
        let plus = BoardConfig::for_model(BitAxeModel::NerdQaxePlus);
        assert_eq!(plus.asic_count, 4);
        assert_eq!(plus.model, BitAxeModel::NerdQaxePlus);
    }

    #[test]
    fn every_multiphase_row_declares_a_default_inside_its_own_window() {
        // Cheap, and it catches the class of mistake the NerdQX row nearly
        // shipped: a default voltage copied from the vendor's nominal figure
        // while the ceiling was copied from the vendor's clamped one.
        for &model in MULTIPHASE_NERD {
            let cfg = BoardConfig::for_model(model);
            assert!(
                cfg.min_voltage_mv <= cfg.default_voltage_mv
                    && cfg.default_voltage_mv <= cfg.max_voltage_mv,
                "{model:?}: default {} mV outside [{}, {}]",
                cfg.default_voltage_mv,
                cfg.min_voltage_mv,
                cfg.max_voltage_mv
            );
        }
    }

    #[test]
    fn the_q1373_envelope_is_not_the_q1370_envelope() {
        // Same board, different silicon. Every voltage and frequency field is
        // lower on the BM1373 part; inheriting the Q1370 row would command a
        // BM1370 setpoint onto BM1373 dies.
        let q1370 = BoardConfig::for_model(BitAxeModel::Q1370);
        let q1373 = BoardConfig::for_model(BitAxeModel::Q1373);
        assert!(q1373.default_frequency < q1370.default_frequency);
        assert!(q1373.default_voltage_mv < q1370.default_voltage_mv);
        assert!(q1373.max_voltage_mv < q1370.max_voltage_mv);
        assert!(q1373.min_voltage_mv < q1370.min_voltage_mv);
        // ... while the board itself is unchanged: same chip count, same rail.
        assert_eq!(q1373.asic_count, q1370.asic_count);
        assert_eq!(q1373.power_controller, q1370.power_controller);
        assert_eq!(q1373.voltage_domains, q1370.voltage_domains);
        // And the silicon reports 0x1372, not the 0x1373 part number.
        assert_eq!(BitAxeModel::Q1373.expected_chip_id(), 0x1372);
        assert_eq!(BitAxeModel::Q1370.expected_chip_id(), 0x1370);
    }

    #[test]
    fn nerdeko_is_the_largest_board_and_fits_the_per_chip_telemetry_array() {
        // Twelve chips in one daisy chain. `dcentaxe-mining`'s per-chip arrays
        // are a fixed MAX_CHIPS capacity, so a board that outgrew them would
        // silently truncate telemetry (or, before the clamps, panic).
        let eko = BoardConfig::for_model(BitAxeModel::NerdEko);
        assert_eq!(eko.asic_count, 12);
        for &model in MULTIPHASE_NERD {
            assert!(
                BoardConfig::for_model(model).asic_count <= eko.asic_count,
                "{model:?} is larger than the board we call the largest"
            );
        }
        // The address interval the BM1370 driver computes for a 12-chip chain:
        // 256/12 = 21 (integer), so the last chip sits at 11 * 21 = 231 and the
        // chain stays inside the 8-bit address space.
        let interval = 256u16 / eko.asic_count as u16;
        assert_eq!(interval, 21);
        assert!((eko.asic_count as u16 - 1) * interval <= 255);
    }

    #[test]
    fn the_stock_model_name_map_is_total_and_lives_in_one_place() {
        // The map `api.rs` and `cgminer_tcp.rs` used to each hold a copy of.
        // Every model must produce a non-empty name, and the board_version
        // overrides must still win over the model map.
        for profile in BoardVersionProfile::ALL {
            let name = profile.model.stock_model_name(profile.board_version);
            assert!(
                !name.is_empty(),
                "{:?} produced an empty stock model name",
                profile.model
            );
        }
        assert_eq!(BitAxeModel::HexUltra.stock_model_name("302"), "Hex");
        assert_eq!(
            BitAxeModel::GammaTurbo.stock_model_name("801"),
            "GammaTurbo"
        );
        // Override beats the model map: a Lucky LV08 masquerading as the
        // colliding "302" still reports what that version means to stock tools.
        assert_eq!(BitAxeModel::LuckyLv08.stock_model_name("302"), "Hex");
        assert_eq!(BitAxeModel::LuckyLv08.stock_model_name("2008"), "LV08");
        // The new boards report the closest stock model for their ASIC.
        assert_eq!(BitAxeModel::NerdEko.stock_model_name("4003"), "Gamma");
        assert_eq!(BitAxeModel::Q1373.stock_model_name("4373"), "Gamma");
    }

    #[test]
    fn multiphase_nerd_boards_refuse_mining_until_a_thermal_source_exists() {
        // REVISITED DELIBERATELY. This test previously asserted these boards
        // could NOT mine, because we shipped no thermal driver for them. A
        // TMP1075 path now exists (`temp::Tmp1075::new_nerd_asic` over
        // `tmp1075_convert`'s 0x48+n addressing), so the gate legitimately
        // opens and the assertions invert.
        //
        // What must NOT change is WHY it opens: the trust comes from a declared
        // sensor backed by a driver, never from the regulator. The final
        // assertion pins that a TPS5364x on its own still buys nothing.
        for &model in MULTIPHASE_NERD {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(
                cfg.power_controller,
                PowerControllerKind::Tps5364x,
                "{model:?} carries a multi-phase VRM"
            );
            assert_eq!(
                cfg.temp_sensor,
                TempSensorKind::Tmp1075,
                "{model:?} derives from upstream's NerdQaxePlus TMP1075 path"
            );
            assert!(
                cfg.has_trusted_thermal_source_configured(),
                "{model:?} now has a driver-backed thermal source"
            );
            assert!(
                cfg.validate().is_ok(),
                "{model:?} must validate once a real thermal source is declared"
            );

            // The load-bearing half: strip the sensor and the board must fall
            // straight back to fail-closed. If this ever passes, the VRM has
            // started granting thermal trust again.
            let mut blind = cfg.clone();
            blind.temp_sensor = TempSensorKind::None;
            assert!(
                !blind.has_trusted_thermal_source_configured(),
                "{model:?}: a TPS5364x must never grant thermal trust by itself"
            );
            assert!(
                blind.validate().is_err(),
                "{model:?}: a thermally blind multi-phase board must not mine"
            );
        }
    }

    #[test]
    fn nerd_asic_sensors_never_resolve_to_the_voltage_regulator_device() {
        // Cross-module: the board rows declare TMP1075, and the addressing that
        // backs that declaration must never hand out the 0x49 VR device as an
        // ASIC sensor. A regulator reading published as a die temperature would
        // under-report the hottest thing on the board.
        use crate::tmp1075_convert::{
            nerd_asic_device_index, nerd_role, nerd_vr_address, SensorRole, NERD_ASIC_SENSOR_COUNT,
        };

        assert_eq!(nerd_vr_address(), 0x49);
        for logical in 0..NERD_ASIC_SENSOR_COUNT {
            let device = nerd_asic_device_index(logical).unwrap();
            assert_eq!(
                nerd_role(device),
                Ok(SensorRole::Asic),
                "logical ASIC sensor {logical} resolved to a non-ASIC device"
            );
        }
    }

    #[test]
    fn multiphase_nerd_boards_declare_the_dual_fan_controller_they_carry() {
        // Upstream's NerdQaxePlus — the base class all four derive from —
        // includes EMC2302.h and sets `m_numFans = 2`. These rows borrow a
        // BitAxe profile ("402"/"601") whose fan controller is a SINGLE-fan
        // EMC2101, so without an explicit override the row describes a part
        // that is not fitted and reports a two-fan board as one-fan. Same
        // defect class as the VRM, one field over.
        for &model in MULTIPHASE_NERD {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(
                cfg.fan_controller,
                FanControllerKind::Emc2302,
                "{model:?} carries a dual-fan EMC2302"
            );
        }
        // The single-ASIC NerdAxe genuinely does carry an EMC2101
        // (`nerdaxe.cpp` includes `drivers/nerdaxe/EMC2101.h`) — the override
        // must not have spread to it.
        assert_eq!(
            BoardConfig::for_model(BitAxeModel::NerdAxe).fan_controller,
            FanControllerKind::Emc2101,
            "NerdAxe is a genuine EMC2101 board"
        );
    }

    #[test]
    fn a_four_asic_nerd_board_has_fewer_asic_sensors_than_asics() {
        // Not a defect — upstream fits three ASIC sensors on a four-ASIC board
        // because the fourth strap is the VR. Recorded so nobody "fixes" the
        // count by reaching for device 1.
        use crate::tmp1075_convert::NERD_ASIC_SENSOR_COUNT;

        let cfg = BoardConfig::for_model(BitAxeModel::NerdQaxePlus);
        assert_eq!(cfg.asic_count, 4);
        assert_eq!(NERD_ASIC_SENSOR_COUNT, 3);
        assert!((NERD_ASIC_SENSOR_COUNT as u8) < cfg.asic_count);
    }

    #[test]
    fn no_shipping_row_declares_the_tmp451_variant_yet() {
        // Honesty pin. The TMP451 driver ships and is host-tested, but the mux
        // it sits behind is present only on newer NerdOCTAXE-γ revisions, so no
        // row may declare it as guaranteed thermal trust. When a board whose
        // ONLY sensor is a TMP451 lands (upstream's NerdQX), this test is the
        // deliberate place to revisit — not a rule to delete quietly.
        for profile in BoardVersionProfile::ALL {
            assert_ne!(
                profile.temp_sensor,
                TempSensorKind::Tmp451,
                "profile {} ({:?}) declares Tmp451, which no shipping revision guarantees",
                profile.board_version,
                profile.model
            );
            assert_ne!(
                BoardConfig::for_profile(&profile).temp_sensor,
                TempSensorKind::Tmp451,
                "row for {:?} declares Tmp451, which no shipping revision guarantees",
                profile.model
            );
        }
    }

    #[test]
    fn octaxe_boards_declare_eight_asics() {
        // Guards the `_ => 1` fail-open arm in the chip-count match: an OCTAXE
        // reporting one chip would under-enumerate the daisy chain.
        for model in [BitAxeModel::NerdOctaxePlus, BitAxeModel::NerdOctaxeGamma] {
            assert_eq!(model.asic_count(), 8, "{model:?} is an 8-ASIC chain");
            assert_eq!(BoardConfig::for_model(model).asic_count, 8);
        }
    }

    #[test]
    fn octaxe_address_interval_divides_evenly() {
        // 256/8 = 32 exactly, so addresses land on 0..=224 with no remainder —
        // unlike LV08's 256/9 = 28 (which leaves a gap that had to be reasoned
        // about). This pins the arithmetic rather than assuming it.
        let chips = BoardConfig::for_model(BitAxeModel::NerdOctaxePlus).asic_count as u16;
        assert_eq!(256 % chips, 0, "8 divides 256 exactly");
        assert_eq!(256 / chips, 32);
        assert_eq!((chips - 1) * (256 / chips), 224, "last chip address");
    }

    #[test]
    fn octaxe_plus_is_bm1368_and_gamma_is_bm1370() {
        assert_eq!(BitAxeModel::NerdOctaxePlus.expected_chip_id(), 0x1368);
        assert_eq!(BitAxeModel::NerdOctaxeGamma.expected_chip_id(), 0x1370);
    }

    #[test]
    fn every_model_declares_the_buck_enable_polarity_its_vendor_source_shows() {
        // THE test this file was missing. `buck_enable_active_low` is stored
        // into `PANIC_BUCK_ACTIVE_LOW` and read by the panic hook, which drives
        // `safety::buck_off_level(active_low)` to cut the rail as the runtime
        // aborts. Declaring active-HIGH on an active-LOW board does not merely
        // fail to cut power — it drives the enable to its ASSERTED level at the
        // exact moment thermal supervision stops running.
        //
        // `safety::buck_off_level_cuts_rail` cannot catch that: it tests the
        // function, not the row that feeds it. Nothing compared a row against
        // its vendor source until now, which is how NerdAxe carried the
        // inverted polarity of the whole `is_nerd()` family.
        //
        // Every entry below is the byte-level truth from the vendor board
        // source named beside it. -1 means "no ESP GPIO drives the enable".
        use BitAxeModel as M;
        const EXPECTED: &[(BitAxeModel, i32, bool, &str)] = &[
            // nerdaxe.cpp: PWR_EN_PIN = GPIO_NUM_10, commented "// inverted"
            // twice. initBoard and setVoltage(0.0) drive 1 (OFF); only a real
            // setpoint drives 0.
            (M::NerdAxe, 10, true, "nerdaxe.cpp"),
            // nerdaxegamma.cpp: initBoard overrides the parent and configures
            // ONLY BM1370_RST_PIN. No enable GPIO exists; TPS546 PMBus only.
            (M::NerdAxeGamma, -1, false, "nerdaxegamma.cpp"),
            // nerdqaxeplus.cpp: TPS53647_EN_PIN = GPIO_NUM_10, driven 0 at init
            // and 1 in VREG_enable(). Active-HIGH. Inherited by the whole
            // multi-ASIC line.
            (M::NerdQaxePlus, 10, false, "nerdqaxeplus.cpp"),
            (M::NerdQaxePP, 10, false, "nerdqaxeplus.cpp (inherited)"),
            (M::NerdOctaxePlus, 10, false, "nerdqaxeplus.cpp (inherited)"),
            (
                M::NerdOctaxeGamma,
                10,
                false,
                "nerdqaxeplus.cpp (inherited)",
            ),
            (M::NerdQX, 10, false, "nerdqaxeplus.cpp (inherited)"),
            (M::NerdHaxeGamma, 10, false, "nerdqaxeplus.cpp (inherited)"),
            (M::NerdEko, 10, false, "nerdqaxeplus.cpp (inherited)"),
            // NerdNOS: fixed TPSM863257RDX, EN on GPIO10 active-HIGH.
            (M::NerdNOS, 10, false, "NerdNOS fixed regulator"),
            // q1370.cpp / q1373.cpp: VREG_enable() goes through the FXL6408
            // expander at 0x43 pin 1 — not an ESP GPIO at all.
            (M::Q1370, -1, false, "q1370.cpp FXL6408"),
            (M::Q1373, -1, false, "q1373.cpp FXL6408 (inherited)"),
            // Hammer BC0x/DC0x: EN unverified, and GPIO46 is ST7789 panel D5.
            (
                M::HammerBc01,
                -1,
                false,
                "Hammer: EN unverified, 46 is panel D5",
            ),
            (
                M::HammerDc06,
                -1,
                false,
                "Hammer: EN unverified, 46 is panel D5",
            ),
            // DCENT_axe: TPS546D24A EN on GPIO10 ACTIVE-HIGH (schematic
            // netlist, PREFAB_DESIGN_REVIEW_2026-07-08 R-10).
            (M::DcentAxeBm1397, 10, false, "dcent-axe schematic netlist"),
            (
                M::DcentAxeQuadBm1397,
                10,
                false,
                "dcent-axe schematic netlist (same stage)",
            ),
            (
                M::DcentAxeHexBm1397,
                10,
                false,
                "dcent-axe schematic netlist (same stage)",
            ),
            // Lucky LVxx: stock BitAxe R1 wiring, TPS546 EN on GPIO46.
            (M::LuckyLv06, 46, false, "Lucky = stock BitAxe R1 wiring"),
            (M::LuckyLv07, 46, false, "Lucky = stock BitAxe R1 wiring"),
            (M::LuckyLv08, 46, false, "Lucky = stock BitAxe R1 wiring"),
            // The rest of the Hammer line, same reason as BC01/DC06 above: EN
            // unverified and GPIO46 is ST7789 panel D5 on these boards.
            (
                M::HammerBc01Pro,
                -1,
                false,
                "Hammer: EN unverified, 46 is panel D5",
            ),
            (
                M::HammerBc02,
                -1,
                false,
                "Hammer: EN unverified, 46 is panel D5",
            ),
            (
                M::HammerBc04,
                -1,
                false,
                "Hammer: EN unverified, 46 is panel D5",
            ),
            (
                M::HammerDc02,
                -1,
                false,
                "Hammer: EN unverified, 46 is panel D5",
            ),
            (
                M::HammerDc04,
                -1,
                false,
                "Hammer: EN unverified, 46 is panel D5",
            ),
            // Stock BitAxe, derived from the power-controller kind rather than
            // model-pinned. Both of these default to TPS546 profiles — Ultra's
            // default is "207" (the R7 TPS546 revision), NOT the DS4432U "205"
            // — so both land on GPIO46 active-high. The DS4432U branch is
            // exercised by `the_ds4432u_branch_is_still_gpio10_active_low`.
            (
                M::Ultra,
                46,
                false,
                "stock BitAxe Ultra R7 profile 207 = TPS546",
            ),
            (M::Gamma, 46, false, "stock BitAxe TPS546"),
            // BitForge Nano: GPIO_ASIC_ENABLE is #defined in three forge-os
            // files and never driven — a repo-wide search for gpio_set_level /
            // gpio_set_direction / gpio_config finds only the two status LEDs
            // and GPIO_ASIC_RESET. TPS546A24 PMBus only.
            (
                M::BitForgeNano,
                -1,
                false,
                "forge-os: GPIO_ASIC_ENABLE defined but never driven",
            ),
            // BitAxe Naja: stronger than "never driven" — never WIRED. EN_UVLO
            // carries only a fixed 12 V divider and the two TPS546 EN pins, and
            // PWR_EN (GPIO10) is a dangling net whose sole member is the ESP32
            // pad. No firmware-reachable rail cut exists on this board.
            (
                M::BitaxeNaja,
                -1,
                false,
                "bitaxeNaja.kicad_pcb: EN_UVLO is a fixed divider, PWR_EN dangles",
            ),
        ];

        // A fixed list cannot notice a NEW model. Every model that pins its own
        // wiring must appear above with its vendor citation, or this table
        // silently stops covering the panic-hook field for exactly the boards
        // that opted out of the derived default. (Wave 14 added the table;
        // Wave 15 added a model it did not cover, which is how this assertion
        // came to exist.)
        // Sourced from the profile table rather than a second hand-kept model
        // list: every model must own a profile row (pinned by
        // `expected_default_board_version_for_model`), so a newly registered
        // board cannot avoid appearing here.
        for profile in BoardVersionProfile::ALL {
            let model = profile.model;
            if model.buck_enable_wiring().is_some() {
                assert!(
                    EXPECTED.iter().any(|&(m, ..)| m == model),
                    "{model:?} pins its own buck_enable_wiring but is not in EXPECTED — \
                     add it with the vendor source that justifies its polarity"
                );
            }
        }

        for &(model, pin, active_low, source) in EXPECTED {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(
                cfg.buck_enable_pin, pin,
                "{model:?} buck_enable_pin ({source})"
            );
            assert_eq!(
                cfg.buck_enable_active_low, active_low,
                "{model:?} buck_enable_active_low ({source}) — this value reaches \
                 the panic hook; inverting it energizes the rail on a panic"
            );
        }
    }

    #[test]
    fn the_ds4432u_branch_is_still_gpio10_active_low() {
        // The derived branch NerdAxe's real power stage matches. Pinned
        // separately because no stock model DEFAULTS to a DS4432U profile any
        // more (Ultra's default moved to the R7 TPS546 row "207"), so the table
        // above cannot reach this branch.
        let mut cfg = BoardConfig::for_model(BitAxeModel::Ultra);
        cfg.apply_hardware_config(&BoardHardwareConfig {
            plug_sense: false,
            asic_enable: false,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: true,
            emc_internal_temp: true,
            emc_ideality_factor: 0x12,
            emc_beta_compensation: 0x00,
            temp_offset_c: 5,
            power_consumption_target_w: 12,
        });
        assert_eq!(cfg.buck_enable_pin, 10);
        assert!(
            cfg.buck_enable_active_low,
            "stock DS4432U boards drive EN low to assert"
        );
    }

    #[test]
    fn an_nvs_override_cannot_reroute_either_nerdaxe_board() {
        // Same protection the DCENT_axe / Hammer / Lucky arms already carried,
        // now proven for the pair this wave corrected. A mistaken override
        // claiming a TPS546 must not move NerdAxe onto GPIO46, and one claiming
        // a DS4432U must not invent an enable output on the γ, which has none.
        for (model, want_pin, want_low, claimed) in [
            (BitAxeModel::NerdAxe, 10, true, PowerControllerKind::Tps546),
            (
                BitAxeModel::NerdAxeGamma,
                -1,
                false,
                PowerControllerKind::Ds4432u,
            ),
        ] {
            let mut cfg = BoardConfig::for_model(model);
            cfg.apply_hardware_config(&BoardHardwareConfig {
                plug_sense: true,
                asic_enable: false,
                fan_controller: FanControllerKind::Emc2101,
                temp_sensor: TempSensorKind::Emc2101,
                power_controller: claimed,
                has_ina260: false,
                emc_internal_temp: false,
                emc_ideality_factor: 0x12,
                emc_beta_compensation: 0x00,
                temp_offset_c: 0,
                power_consumption_target_w: 20,
            });
            assert_eq!(
                cfg.buck_enable_pin, want_pin,
                "{model:?} pin after {claimed:?} override"
            );
            assert_eq!(
                cfg.buck_enable_active_low, want_low,
                "{model:?} polarity after {claimed:?} override"
            );
            assert_eq!(
                cfg.plug_sense_pin, -1,
                "{model:?}: model-pinned boards never enable plug-sense"
            );
        }
    }

    #[test]
    fn the_two_nerdaxe_boards_do_not_share_a_power_topology() {
        // They share a name, a display and an upstream class hierarchy, and
        // nothing else that matters here. This is the pairing that made one
        // mislabelled row look plausible for as long as it did.
        let axe = BoardConfig::for_model(BitAxeModel::NerdAxe);
        let gamma = BoardConfig::for_model(BitAxeModel::NerdAxeGamma);

        assert_ne!(axe.asic_model, gamma.asic_model);
        assert_ne!(axe.power_controller, gamma.power_controller);
        assert_ne!(axe.buck_enable_pin, gamma.buck_enable_pin);
        assert_ne!(axe.default_frequency, gamma.default_frequency);

        // The γ reads a real external diode; the parent reads the EMC2101's own
        // die and corrects it upward by 5 °C.
        assert!(
            axe.emc_internal_temp,
            "NerdAxe: EMC2101_get_internal_temp()"
        );
        assert_eq!(axe.temp_offset_c, 5);
        assert!(
            !gamma.emc_internal_temp,
            "NerdAxe-γ: EMC2101_get_external_temp()"
        );
        assert_eq!(gamma.temp_offset_c, 0);

        // Upstream's m_miningAgent is "NerdAxe" for BOTH boards, so only the
        // device model can tell them apart.
        assert_eq!(
            BitAxeModel::from_device_model("nerdaxe"),
            Some(BitAxeModel::NerdAxe)
        );
        assert_eq!(
            BitAxeModel::from_device_model("NerdAxeGamma"),
            Some(BitAxeModel::NerdAxeGamma)
        );
    }

    #[test]
    fn nerd_voltage_floor_is_not_below_the_vendor_characterized_minimum() {
        // A floor below what the vendor characterizes lets the autotuner walk
        // these boards under-volt — the unsafe direction, and what the previous
        // 1000 mV rows allowed.
        //
        // The floor belongs to the ASIC, not to the board. Upstream's
        // NerdQaxePlus sets m_absMinAsicVoltageMillis = 1050 and every BM1370
        // board in this family inherits it; the Q1373 overrides it to 900 for
        // BM1373 silicon, which is a genuinely different part with a genuinely
        // lower window. Asserting one number across both would either reject a
        // correct Q1373 row or license an under-volted BM1370 one.
        for &model in MULTIPHASE_NERD {
            let cfg = BoardConfig::for_model(model);
            let vendor_floor = match model.expected_chip_id() {
                // BM1373 (silicon reports 0x1372): upstream Q1373B sets 900.
                0x1372 => 900,
                _ => 1050,
            };
            assert!(
                cfg.min_voltage_mv >= vendor_floor,
                "{model:?} floor {} mV is below the upstream {vendor_floor} mV minimum",
                cfg.min_voltage_mv
            );
        }
    }

    #[test]
    fn multiphase_nerd_rails_stay_inside_the_part_voltage_window() {
        // Cross-check the board rows against the driver that will actually
        // command them: every row's [min, default, max] must encode on a
        // TPS53647 once multiplied out by its domain count. This is the test
        // that would catch a future row flipping voltage_domains to 2.
        use crate::tps5364x_convert::{rail_voltage_v_for_domains, vout_command, Variant};
        for &model in MULTIPHASE_NERD {
            let cfg = BoardConfig::for_model(model);
            for mv in [
                cfg.min_voltage_mv,
                cfg.default_voltage_mv,
                cfg.max_voltage_mv,
            ] {
                let rail = rail_voltage_v_for_domains(mv, cfg.voltage_domains);
                assert!(
                    vout_command(Variant::Tps53647, rail).is_ok(),
                    "{model:?}: {mv} mV over {} domain(s) = {rail} V is not commandable",
                    cfg.voltage_domains
                );
            }
        }
    }

    #[test]
    fn esp_miner_fixture_manifest_records_last_sync_without_network_fetch() {
        let manifest = ESP_MINER_FIXTURE_MANIFEST;
        for required in [
            "\"schema\": \"dcentos-esp.upstream-fixture.v1\"",
            "\"source_repository\": \"https://github.com/bitaxeorg/ESP-Miner\"",
            "\"source_file\": \"main/device_config.h\"",
            "\"local_file\": \"device_config.h\"",
            "\"upstream_commit\": \"b4c3dcbb9ed36c2a0eb9ae7d57a4132e8c52c14b\"",
            "\"upstream_commit_date\": \"2026-07-03\"",
            "\"last_synced_on\": \"2026-07-04\"",
            "\"network_ci_policy\": \"no_network_fetch_in_ci\"",
        ] {
            assert!(
                manifest.contains(required),
                "fixture manifest missing required marker: {required}"
            );
        }
    }

    #[test]
    fn board_version_profiles_pin_display_metadata() {
        let expected = &[
            ("2.2", DisplayKind::Ssd1306),
            ("102", DisplayKind::Ssd1306),
            ("0.11", DisplayKind::Ssd1306),
            ("201", DisplayKind::Ssd1306),
            ("202", DisplayKind::Ssd1306),
            ("203", DisplayKind::Ssd1306),
            ("204", DisplayKind::Ssd1306),
            ("205", DisplayKind::Ssd1306),
            ("207", DisplayKind::Ssd1306),
            ("302", DisplayKind::Ssd1306),
            ("303", DisplayKind::Ssd1306),
            ("400", DisplayKind::Ssd1306),
            ("401", DisplayKind::Ssd1306),
            ("402", DisplayKind::Ssd1306),
            ("403", DisplayKind::Ssd1306),
            ("600", DisplayKind::Ssd1306),
            ("601", DisplayKind::Ssd1306),
            ("602", DisplayKind::Ssd1306),
            ("603", DisplayKind::Ssd1306),
            ("650", DisplayKind::Ssd1306),
            ("701", DisplayKind::Ssd1306),
            ("702", DisplayKind::Ssd1306),
            ("801", DisplayKind::Ssd1306),
            ("900", DisplayKind::Ssd1306),
            ("910", DisplayKind::Ssd1306),
            ("920", DisplayKind::Ssd1306),
            ("9010", DisplayKind::Ssd1306),
            ("9040", DisplayKind::Ssd1306),
            ("9060", DisplayKind::Ssd1306),
            // Hammer BC0x: vendor ST7789 LCD is NOT driven by DCENT_OS —
            // headless metadata until an ST7789 driver ships. Canonical 3XXX
            // rows + the legacy `hammer-*` alias rows.
            ("3001", DisplayKind::None),
            ("3011", DisplayKind::None),
            ("3002", DisplayKind::None),
            ("3004", DisplayKind::None),
            ("hammer-bc01", DisplayKind::None),
            ("hammer-bc01-pro", DisplayKind::None),
            ("hammer-bc02", DisplayKind::None),
            ("hammer-bc04", DisplayKind::None),
            // Hammer DC0x (Scrypt): same vendor ST7789 panel, same answer.
            ("3102", DisplayKind::None),
            ("3104", DisplayKind::None),
            ("3106", DisplayKind::None),
            // Lucky LVxx: stock BitAxe SSD1306 OLED @ 0x3C.
            ("2006", DisplayKind::Ssd1306),
            ("2007", DisplayKind::Ssd1306),
            ("2008", DisplayKind::Ssd1306),
            // Nerd multi-ASIC + Q-series: all inherit the NerdQAxe+ board class
            // and its Lilygo T-Display S3.
            ("4001", DisplayKind::TDisplayS3),
            ("4002", DisplayKind::TDisplayS3),
            ("4003", DisplayKind::TDisplayS3),
            // Canonical rows for the four boards that used to borrow "402" /
            // "601" (queue rank 41). Same T-Display S3 as the rest of the
            // line — and note the borrowed BitAxe rows declared `Ssd1306`,
            // which `display_kind()` never actually honoured because it
            // resolves through the MODEL, not the row.
            ("4006", DisplayKind::TDisplayS3),
            ("4007", DisplayKind::TDisplayS3),
            ("4008", DisplayKind::TDisplayS3),
            ("4009", DisplayKind::TDisplayS3),
            // NerdNOS is the one Nerd board that is HEADLESS — it is a hat on a
            // T-Display S3's headers, not a board with its own panel. The
            // BitAxe Max row "102" it used to borrow declared `Ssd1306`.
            ("4010", DisplayKind::None),
            ("4370", DisplayKind::TDisplayS3),
            ("4373", DisplayKind::TDisplayS3),
            // NerdAxe / NerdAxe-γ: same T-Display S3 (`m_flipScreen = true`
            // on both — an orientation detail, not a different panel).
            ("4004", DisplayKind::TDisplayS3),
            ("4005", DisplayKind::TDisplayS3),
            // BitForge Nano: headless. Two status LEDs, no panel.
            ("4100", DisplayKind::None),
            // BitAxe Naja: headless. J2 is JTAG, J3 is an I2C breakout.
            ("4200", DisplayKind::None),
        ];

        assert_eq!(expected.len(), BoardVersionProfile::ALL.len());
        for (version, display_kind) in expected {
            let profile = BoardVersionProfile::find(version)
                .unwrap_or_else(|| panic!("missing board_version {version}"));
            assert_eq!(
                profile.display_kind(),
                *display_kind,
                "board {version}: display metadata"
            );
            assert_eq!(
                BoardConfig::for_profile(profile).display_kind,
                *display_kind,
                "board {version}: BoardConfig display metadata"
            );
        }
    }

    #[test]
    fn esp_miner_board_version_parity() {
        let esp_miner = parse_esp_miner_default_configs(ESP_MINER_DEVICE_CONFIG_H);
        assert!(
            esp_miner.len() >= 23,
            "fixture parser missed upstream default_configs rows"
        );
        assert!(
            esp_miner.iter().any(|entry| entry.version == "603"),
            "fixture must include upstream Gamma board_version 603"
        );
        for expected in esp_miner {
            let ver = expected.version;
            let model = &expected.model;
            let asic = &expected.asic;
            let p = BoardVersionProfile::find(ver).unwrap_or_else(|| {
                panic!(
                    "ESP-Miner board_version {ver} does not resolve — parity gap vs device_config.h"
                )
            });
            assert_eq!(p.model, *model, "board {ver}: family mismatch");
            assert_eq!(p.asic_model, *asic, "board {ver}: ASIC mismatch");
        }
    }

    // ── P3 (supersedes the P1 pin `every_profile_row_is_sha256d_in_p1`) ────
    //
    // P1 pinned EVERY row to `Sha256d` so a Scrypt row could only appear by a
    // deliberate act. That act is the Hammer DC0x lane, so the pin is now the
    // stronger invariant it was standing in for: a row's `pow_algorithm` must
    // equal its MODEL's algorithm. A row and a model can therefore never
    // disagree, and every non-DC0x row is still provably `Sha256d` — a stray
    // edit flipping, say, the Gamma row to Scrypt still fails here.
    #[test]
    fn every_row_pow_algorithm_matches_its_model() {
        for row in BoardVersionProfile::ALL.iter() {
            assert_eq!(
                row.pow_algorithm,
                row.model.pow_algorithm(),
                "board_version {}: row algorithm disagrees with its model ({:?})",
                row.board_version,
                row.model
            );
            if !row.model.is_hammer_dc() {
                assert_eq!(
                    row.pow_algorithm,
                    PowAlgorithm::Sha256d,
                    "board_version {} must stay Sha256d — only the Hammer DC0x \
                     (MSBT0501) lane may introduce a Scrypt row",
                    row.board_version
                );
                assert_ne!(
                    row.asic_model, "MSBT0501",
                    "board_version {} claims the Scrypt ASIC on a SHA-256 row",
                    row.board_version
                );
            } else {
                assert_eq!(row.pow_algorithm, PowAlgorithm::Scrypt1024);
                assert_eq!(row.asic_model, "MSBT0501");
            }
        }
        // Exactly the three registered DC0x rows are Scrypt.
        let scrypt_rows: Vec<&str> = BoardVersionProfile::ALL
            .iter()
            .filter(|r| r.pow_algorithm == PowAlgorithm::Scrypt1024)
            .map(|r| r.board_version)
            .collect();
        assert_eq!(scrypt_rows, vec!["3102", "3104", "3106"]);
    }

    // ── Fan IC: EMC2101 (single) vs EMC2302 (Quad/Hex dual-fan) ──
    #[test]
    fn board_version_deep_parity_pins_power_and_support_attributes() {
        #[derive(Clone, Copy)]
        struct Expected {
            ver: &'static str,
            model: BitAxeModel,
            asic: &'static str,
            fan: FanControllerKind,
            temp: TempSensorKind,
            power: PowerControllerKind,
            has_ina260: bool,
            temp_flip: bool,
            temp_offset_c: i8,
            power_target_w: u16,
            live_proof: LiveProof,
            support: &'static str,
        }

        let expected: &[Expected] = &[
            Expected {
                ver: "2.2",
                model: BitAxeModel::Max,
                asic: "BM1397",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Ds4432u,
                has_ina260: true,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "102",
                model: BitAxeModel::Max,
                asic: "BM1397",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Ds4432u,
                has_ina260: true,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "0.11",
                model: BitAxeModel::Ultra,
                asic: "BM1366",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Ds4432u,
                has_ina260: true,
                temp_flip: false,
                temp_offset_c: 5,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "201",
                model: BitAxeModel::Ultra,
                asic: "BM1366",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Ds4432u,
                has_ina260: true,
                temp_flip: false,
                temp_offset_c: 5,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "202",
                model: BitAxeModel::Ultra,
                asic: "BM1366",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Ds4432u,
                has_ina260: true,
                temp_flip: false,
                temp_offset_c: 5,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "203",
                model: BitAxeModel::Ultra,
                asic: "BM1366",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Ds4432u,
                has_ina260: true,
                temp_flip: false,
                temp_offset_c: 5,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "204",
                model: BitAxeModel::Ultra,
                asic: "BM1366",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Ds4432u,
                has_ina260: true,
                temp_flip: false,
                temp_offset_c: 5,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "205",
                model: BitAxeModel::Ultra,
                asic: "BM1366",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Ds4432u,
                has_ina260: true,
                temp_flip: false,
                temp_offset_c: 5,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "207",
                model: BitAxeModel::Ultra,
                asic: "BM1366",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "302",
                model: BitAxeModel::HexUltra,
                asic: "BM1366",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 10,
                power_target_w: 40,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "303",
                model: BitAxeModel::HexUltra,
                asic: "BM1366",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 10,
                power_target_w: 40,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "400",
                model: BitAxeModel::Supra,
                asic: "BM1368",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Ds4432u,
                has_ina260: true,
                temp_flip: false,
                temp_offset_c: 5,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "401",
                model: BitAxeModel::Supra,
                asic: "BM1368",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Ds4432u,
                has_ina260: true,
                temp_flip: false,
                temp_offset_c: 5,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "402",
                model: BitAxeModel::Supra,
                asic: "BM1368",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 8,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "403",
                model: BitAxeModel::Supra,
                asic: "BM1368",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 8,
                live_proof: LiveProof::Host,
                support: "supported",
            },
            Expected {
                ver: "600",
                model: BitAxeModel::Gamma,
                asic: "BM1370",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 19,
                live_proof: LiveProof::FocusedRun,
                support: "supported",
            },
            Expected {
                ver: "601",
                model: BitAxeModel::Gamma,
                asic: "BM1370",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 19,
                live_proof: LiveProof::FocusedRun,
                support: "supported",
            },
            Expected {
                ver: "602",
                model: BitAxeModel::Gamma,
                asic: "BM1370",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 22,
                live_proof: LiveProof::FocusedRun,
                support: "supported",
            },
            Expected {
                ver: "603",
                model: BitAxeModel::Gamma,
                asic: "BM1370",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 22,
                live_proof: LiveProof::FocusedRun,
                support: "supported",
            },
            Expected {
                ver: "650",
                model: BitAxeModel::GammaDuo,
                asic: "BM1370",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 35,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "701",
                model: BitAxeModel::HexSupra,
                asic: "BM1368",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 10,
                power_target_w: 90,
                live_proof: LiveProof::FocusedRun,
                support: "experimental",
            },
            Expected {
                ver: "702",
                model: BitAxeModel::HexSupra,
                asic: "BM1368",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 10,
                power_target_w: 90,
                live_proof: LiveProof::FocusedRun,
                support: "experimental",
            },
            Expected {
                ver: "801",
                model: BitAxeModel::GammaTurbo,
                asic: "BM1370",
                fan: FanControllerKind::Emc2103,
                temp: TempSensorKind::Emc2103,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: true,
                temp_offset_c: 0,
                power_target_w: 36,
                live_proof: LiveProof::FocusedRun,
                support: "experimental",
            },
            Expected {
                ver: "900",
                model: BitAxeModel::DcentAxeBm1397,
                asic: "BM1397",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                // R-10: TPS546D24A VRM, no DS4432U / no INA260 on the real board.
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "910",
                model: BitAxeModel::DcentAxeQuadBm1397,
                asic: "BM1397",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 10,
                power_target_w: 48,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "920",
                model: BitAxeModel::DcentAxeHexBm1397,
                asic: "BM1397",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 10,
                power_target_w: 72,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            // Canonical `9###` registry rows — byte-identical to 900/910/920.
            Expected {
                ver: "9010",
                model: BitAxeModel::DcentAxeBm1397,
                asic: "BM1397",
                fan: FanControllerKind::Emc2101,
                temp: TempSensorKind::Emc2101,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 12,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "9040",
                model: BitAxeModel::DcentAxeQuadBm1397,
                asic: "BM1397",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 10,
                power_target_w: 48,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "9060",
                model: BitAxeModel::DcentAxeHexBm1397,
                asic: "BM1397",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 10,
                power_target_w: 72,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            // ── Hammer BC0x provisional rows: fan/temp/power = None is the
            // honest no-driver truth and is what keeps mining fail-closed
            // refused on these models (see hammer_bc0x_boards tests). ──
            Expected {
                ver: "hammer-bc01",
                model: BitAxeModel::HammerBc01,
                asic: "BM1370",
                fan: FanControllerKind::None,
                temp: TempSensorKind::None,
                power: PowerControllerKind::None,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 25,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "hammer-bc01-pro",
                model: BitAxeModel::HammerBc01Pro,
                asic: "BM1373",
                fan: FanControllerKind::None,
                temp: TempSensorKind::None,
                power: PowerControllerKind::None,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 45,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "hammer-bc02",
                model: BitAxeModel::HammerBc02,
                asic: "BM1370",
                fan: FanControllerKind::None,
                temp: TempSensorKind::None,
                power: PowerControllerKind::None,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 50,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "hammer-bc04",
                model: BitAxeModel::HammerBc04,
                asic: "BM1370",
                fan: FanControllerKind::None,
                temp: TempSensorKind::None,
                power: PowerControllerKind::None,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 100,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            // Canonical Hammer 3XXX rows — byte-identical to the `hammer-*`
            // alias rows above (renumber, not a behavior change).
            Expected {
                ver: "3001",
                model: BitAxeModel::HammerBc01,
                asic: "BM1370",
                fan: FanControllerKind::None,
                temp: TempSensorKind::None,
                power: PowerControllerKind::None,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 25,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "3011",
                model: BitAxeModel::HammerBc01Pro,
                asic: "BM1373",
                fan: FanControllerKind::None,
                temp: TempSensorKind::None,
                power: PowerControllerKind::None,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 45,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "3002",
                model: BitAxeModel::HammerBc02,
                asic: "BM1370",
                fan: FanControllerKind::None,
                temp: TempSensorKind::None,
                power: PowerControllerKind::None,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 50,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "3004",
                model: BitAxeModel::HammerBc04,
                asic: "BM1370",
                fan: FanControllerKind::None,
                temp: TempSensorKind::None,
                power: PowerControllerKind::None,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 100,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            // Lucky LVxx rows: shipped drivers (EMC2302 + TMP1075 + TPS546),
            // temp offset +5, LiveProof::None (SPEC §8 — no bench hardware).
            Expected {
                ver: "2006",
                model: BitAxeModel::LuckyLv06,
                asic: "BM1366",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 5,
                power_target_w: 40,
                live_proof: LiveProof::None,
                support: "experimental",
            },
            Expected {
                ver: "2007",
                model: BitAxeModel::LuckyLv07,
                asic: "BM1366",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 5,
                power_target_w: 40,
                live_proof: LiveProof::None,
                support: "experimental",
            },
            Expected {
                ver: "2008",
                model: BitAxeModel::LuckyLv08,
                asic: "BM1366",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps546,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 5,
                power_target_w: 140,
                live_proof: LiveProof::None,
                support: "experimental",
            },
            // ── Queue rank 41: the four canonical Nerd multi-ASIC rows ──
            //
            // Pinned HERE, in the deep-parity table, because that is what makes
            // them different from the borrow they replace: every value below is
            // sourced from
            // boards/*.cpp`, and this table is what fails if one is quietly
            // edited toward the BitAxe row it came from.
            //
            // The three columns that were WRONG under the borrow are
            // `live_proof`, `power_target_w` and `temp_offset_c` — compare
            // "402" (Host / 8 W / 0) and "601" (FocusedRun / 19 W / 0) above.
            Expected {
                ver: "4006",
                model: BitAxeModel::NerdQaxePlus,
                asic: "BM1368",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps5364x,
                has_ina260: false,
                temp_flip: false,
                // Base class: `NerdQaxePlus::getTemperature` applies NO offset.
                temp_offset_c: 0,
                power_target_w: 70, // `m_maxPin = 70.0`
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "4007",
                model: BitAxeModel::NerdQaxePP,
                asic: "BM1370",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps5364x,
                has_ina260: false,
                temp_flip: false,
                // `NerdQaxePlus2::getTemperature` adds 10 C.
                temp_offset_c: 10,
                power_target_w: 100, // `m_maxPin = 100.0` (non-rev7)
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "4008",
                model: BitAxeModel::NerdOctaxePlus,
                asic: "BM1368",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps5364x,
                has_ina260: false,
                temp_flip: false,
                // Derives NerdQaxePlus, NOT NerdQaxePlus2 — hence 0, not 10.
                temp_offset_c: 0,
                power_target_w: 130, // `m_maxPin = 130.0`
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "4009",
                model: BitAxeModel::NerdOctaxeGamma,
                asic: "BM1370",
                fan: FanControllerKind::Emc2302,
                temp: TempSensorKind::Tmp1075,
                power: PowerControllerKind::Tps5364x,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 10, // derives NerdQaxePlus2
                // The CONSERVATIVE 4-phase (rev <=3.3) envelope. A rev-3.4
                // board is 300 W, and declaring that here would apply a
                // 6-phase ceiling to a 4-phase board.
                power_target_w: 250,
                live_proof: LiveProof::Host,
                support: "experimental",
            },
            Expected {
                ver: "4010",
                model: BitAxeModel::NerdNOS,
                asic: "BM1397",
                // All four `None`s are EVIDENCE, and each one contradicts the
                // BitAxe Max row "102" this board used to borrow. See the row
                // for the schematic citation. Flipping any of them back to a
                // real part re-asserts hardware this board does not have — and
                // `temp` in particular is what keeps `validate()` fail-closed.
                fan: FanControllerKind::None,
                temp: TempSensorKind::None,
                power: PowerControllerKind::None,
                has_ina260: false,
                temp_flip: false,
                temp_offset_c: 0,
                power_target_w: 8, // "~8W (USB-C)"; "102" said 12
                live_proof: LiveProof::Host,
                support: "experimental",
            },
        ];

        for expected in expected {
            let p = BoardVersionProfile::find(expected.ver)
                .unwrap_or_else(|| panic!("missing board_version {}", expected.ver));
            assert_eq!(p.model, expected.model, "board {}: model", expected.ver);
            assert_eq!(p.asic_model, expected.asic, "board {}: ASIC", expected.ver);
            assert_eq!(
                p.fan_controller, expected.fan,
                "board {}: fan",
                expected.ver
            );
            assert_eq!(p.temp_sensor, expected.temp, "board {}: temp", expected.ver);
            assert_eq!(
                p.power_controller, expected.power,
                "board {}: power",
                expected.ver
            );
            assert_eq!(
                p.has_ina260, expected.has_ina260,
                "board {}: INA260",
                expected.ver
            );
            assert_eq!(
                p.temp_flip, expected.temp_flip,
                "board {}: temp_flip",
                expected.ver
            );
            assert_eq!(
                p.temp_offset_c, expected.temp_offset_c,
                "board {}: temp offset",
                expected.ver
            );
            assert_eq!(
                p.power_consumption_target_w, expected.power_target_w,
                "board {}: power target",
                expected.ver
            );
            assert_eq!(
                p.live_proof, expected.live_proof,
                "board {}: live proof",
                expected.ver
            );
            assert_eq!(
                p.model.support_status(),
                expected.support,
                "board {}: support",
                expected.ver
            );
        }
    }

    #[test]
    fn live_proof_is_explicit_and_support_status_does_not_imply_soak() {
        for profile in BoardVersionProfile::ALL {
            if profile.model.is_lucky() || profile.model.is_hammer_dc() {
                // Same honesty posture for the Hammer DC0x (Scrypt) rows: no
                // DC0x hardware is on any bench and the LT0051 driver refuses
                // to init, so there is no artifact of ANY kind to point at —
                // not even a host-level one, because nothing host-side has
                // ever driven this chip. Promotion requires a real retained
                // artifact, never a row edit.
                // SPEC §8 honesty posture: no Lucky Miner hardware is on any
                // bench, so the rows must say exactly LiveProof::None —
                // promoting them to Host/FocusedRun requires a real retained
                // artifact, never a row edit.
                assert_eq!(
                    profile.live_proof,
                    LiveProof::None,
                    "Lucky board {} must stay LiveProof::None until a real \
                     retained proof artifact exists (SPEC §8)",
                    profile.board_version
                );
                continue;
            }
            assert_ne!(
                profile.live_proof,
                LiveProof::None,
                "board {} must carry an explicit retained proof level",
                profile.board_version
            );
            if profile.model.support_status() == "supported" {
                assert_ne!(
                    profile.live_proof,
                    LiveProof::SustainedSoak,
                    "board {} must not imply sustained soak from support_status alone",
                    profile.board_version
                );
            }
        }
    }

    #[test]
    fn ds4432u_profiles_stay_hardware_gated_for_live_promotion() {
        for profile in BoardVersionProfile::ALL {
            if profile.power_controller == PowerControllerKind::Ds4432u {
                assert_eq!(
                    profile.live_proof,
                    LiveProof::Host,
                    "board {} uses DS4432U and must stay host-proof only until the ignored meter-log bench gate passes",
                    profile.board_version
                );
            }
        }
    }

    // ── R-10 (PREFAB_DESIGN_REVIEW_2026-07-08): DCENT_axe resolved power path ──
    // The dcent-axe-BM1397 schematic netlist wires the TPS546D24A EN pin to
    // GPIO10, ACTIVE-HIGH; there is no DS4432U and no INA260 on the board. The
    // old profile (Ds4432u + has_ina260) resolved GPIO10 as active-LOW, so the
    // fail-closed "power OFF" drive turned the VRM rail ON, and the generic
    // Tps546 arm would have picked GPIO46 (unconnected). Pin the fully-resolved
    // power path for every DCENT_axe SKU so neither regression can come back.
    #[test]
    fn dcentaxe_power_path_resolves_tps546_gpio10_active_high() {
        for model in [
            BitAxeModel::DcentAxeBm1397,
            BitAxeModel::DcentAxeQuadBm1397,
            BitAxeModel::DcentAxeHexBm1397,
        ] {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(
                cfg.power_controller,
                PowerControllerKind::Tps546,
                "{model:?}: power controller must be the TPS546 PMBus VRM"
            );
            assert!(
                !cfg.has_ina260,
                "{model:?}: no INA260 is populated on DCENT_axe boards"
            );
            assert_eq!(
                cfg.buck_enable_pin, 10,
                "{model:?}: TPS546 EN is wired to GPIO10 (GPIO46 is unconnected)"
            );
            assert!(
                !cfg.buck_enable_active_low,
                "{model:?}: EN is ACTIVE-HIGH — an active-low resolution inverts \
                 fail-closed power-off into driving the VRM rail ON"
            );
            // The fail-closed OFF level for this polarity must actually cut the
            // rail: active-high ⇒ OFF == drive LOW (gpio_set_level 0).
            assert_eq!(
                crate::safety::buck_off_level(cfg.buck_enable_active_low),
                0,
                "{model:?}: fail-closed OFF must drive the EN pin LOW"
            );
        }
        // The board-version rows themselves must agree with the resolved config
        // (legacy 3-digit aliases AND the canonical 9### registry rows).
        for ver in ["900", "910", "920", "9010", "9040", "9060"] {
            let p = BoardVersionProfile::find(ver).unwrap();
            assert_eq!(
                p.power_controller,
                PowerControllerKind::Tps546,
                "board {ver}: profile row must declare Tps546"
            );
            assert!(
                !p.has_ina260,
                "board {ver}: profile row must not claim INA260"
            );
        }
    }

    #[test]
    fn fan_controllers_match_topology() {
        assert_eq!(
            BoardConfig::for_model(BitAxeModel::DcentAxeBm1397).fan_controller,
            FanControllerKind::Emc2101
        );
        assert_eq!(
            BoardConfig::for_model(BitAxeModel::DcentAxeQuadBm1397).fan_controller,
            FanControllerKind::Emc2302
        );
        assert_eq!(
            BoardConfig::for_model(BitAxeModel::DcentAxeHexBm1397).fan_controller,
            FanControllerKind::Emc2302
        );
        // Lucky LVxx: every model (1/2/9 chips) ships the EMC2302 @ 0x2F —
        // the whole family shares the Hex-style dual-channel fan controller
        // (LVXX device_config.h rows).
        for model in [
            BitAxeModel::LuckyLv06,
            BitAxeModel::LuckyLv07,
            BitAxeModel::LuckyLv08,
        ] {
            assert_eq!(
                BoardConfig::for_model(model).fan_controller,
                FanControllerKind::Emc2302,
                "{model:?}: Lucky boards carry an EMC2302"
            );
        }
    }
}

#[cfg(test)]
mod hammer_bc0x_boards {
    use super::*;

    // (model, canonical key, board_target, canonical 3XXX board_version,
    //  chips, series voltage domains, per-chip default mV, per-chip max mV,
    //  expected chip id)
    const HAMMER: [(BitAxeModel, &str, &str, &str, u8, u16, u16, u16, u16); 4] = [
        (
            BitAxeModel::HammerBc01,
            "hammer_bc01",
            "hammer-bc01",
            "3001",
            1,
            1,
            1200,
            1300,
            0x1370,
        ),
        (
            BitAxeModel::HammerBc01Pro,
            "hammer_bc01_pro",
            "hammer-bc01-pro",
            "3011",
            1,
            1,
            1000,
            1150,
            0x1372,
        ),
        (
            BitAxeModel::HammerBc02,
            "hammer_bc02",
            "hammer-bc02",
            "3002",
            2,
            2,
            1225,
            1300,
            0x1370,
        ),
        (
            BitAxeModel::HammerBc04,
            "hammer_bc04",
            "hammer-bc04",
            "3004",
            4,
            4,
            1200,
            1250,
            0x1370,
        ),
    ];

    // ── 3XXX renumber (Lucky-enablement SPEC §2.2): the old DCENT-minted
    // `hammer-*` strings stay resolvable as ALIAS rows byte-identical to the
    // canonical 3XXX rows, because DCENT_OS itself may have written one into
    // a bench unit's NVS. Same pattern as the DCENT_axe 900→9010 migration. ──
    #[test]
    fn legacy_hammer_aliases_resolve_identically_to_canonical_rows() {
        for (legacy, canonical) in [
            ("hammer-bc01", "3001"),
            ("hammer-bc01-pro", "3011"),
            ("hammer-bc02", "3002"),
            ("hammer-bc04", "3004"),
        ] {
            let l = BoardVersionProfile::find(legacy)
                .unwrap_or_else(|| panic!("legacy row {legacy} must stay resolvable"));
            let c = BoardVersionProfile::find(canonical)
                .unwrap_or_else(|| panic!("canonical row {canonical} must exist"));
            assert_eq!(l.model, c.model, "{legacy}/{canonical}: model");
            assert_eq!(
                l.device_model, c.device_model,
                "{legacy}/{canonical}: device_model"
            );
            assert_eq!(l.asic_model, c.asic_model, "{legacy}/{canonical}: asic");
            assert_eq!(
                l.fan_controller, c.fan_controller,
                "{legacy}/{canonical}: fan"
            );
            assert_eq!(l.temp_sensor, c.temp_sensor, "{legacy}/{canonical}: temp");
            assert_eq!(
                l.power_controller, c.power_controller,
                "{legacy}/{canonical}: power"
            );
            assert_eq!(l.has_ina260, c.has_ina260, "{legacy}/{canonical}: ina260");
            assert_eq!(
                l.temp_offset_c, c.temp_offset_c,
                "{legacy}/{canonical}: offset"
            );
            assert_eq!(
                l.power_consumption_target_w, c.power_consumption_target_w,
                "{legacy}/{canonical}: power target"
            );
            assert_eq!(l.temp_flip, c.temp_flip, "{legacy}/{canonical}: temp_flip");
            assert_eq!(l.live_proof, c.live_proof, "{legacy}/{canonical}: proof");
            // Aliases must keep the mining-refused fail-closed posture too.
            assert_eq!(l.fan_controller, FanControllerKind::None);
            assert_eq!(l.temp_sensor, TempSensorKind::None);
            assert_eq!(l.power_controller, PowerControllerKind::None);
        }
        // The model default is the CANONICAL 3XXX row, not the legacy alias.
        assert_eq!(
            BoardVersionProfile::default_for_model(BitAxeModel::HammerBc01).board_version,
            "3001"
        );
        assert_eq!(
            BoardVersionProfile::default_for_model(BitAxeModel::HammerBc01Pro).board_version,
            "3011"
        );
        assert_eq!(
            BoardVersionProfile::default_for_model(BitAxeModel::HammerBc02).board_version,
            "3002"
        );
        assert_eq!(
            BoardVersionProfile::default_for_model(BitAxeModel::HammerBc04).board_version,
            "3004"
        );
        // A legacy alias still refuses mining fail-closed when built.
        let cfg = BoardConfig::for_profile(BoardVersionProfile::find("hammer-bc04").unwrap());
        assert_eq!(
            cfg.validate(),
            Err("mining-capable board requires a trusted temperature source"),
            "legacy hammer alias rows must stay mining-refused"
        );
    }

    #[test]
    fn hammer_models_register_with_experimental_identity() {
        for (model, key, target, ver, chips, _domains, _def, _max, chip_id) in HAMMER {
            assert_eq!(model.canonical_key(), key);
            assert_eq!(model.board_target(), target);
            assert_eq!(BitAxeModel::from_device_model(key), Some(model));
            assert_eq!(model.support_status(), "experimental", "{model:?}");
            assert_eq!(model.asic_count(), chips, "{model:?}");
            assert_eq!(model.expected_chip_id(), chip_id, "{model:?}");
            assert!(model.is_hammer());
            assert!(!model.is_hex() && !model.is_nerd() && !model.is_dcent_axe());

            let profile = BoardVersionProfile::find(ver)
                .unwrap_or_else(|| panic!("profile {ver} for {model:?} must exist"));
            assert_eq!(profile.model, model);
            assert_eq!(
                BoardVersionProfile::default_for_model(model).board_version,
                ver
            );
        }
        // Vendor devicemodel spellings resolve too (over-flash auto-identify).
        assert_eq!(
            BitAxeModel::from_device_model("BC04"),
            Some(BitAxeModel::HammerBc04)
        );
        assert_eq!(
            BitAxeModel::from_device_model("BC01-Pro"),
            Some(BitAxeModel::HammerBc01Pro)
        );
    }

    // ── THE stacked-voltage safety pin (HAMMER_HARDWARE_MATRIX.md §2.2). ──
    // Every Hammer profile expresses PER-ASIC millivolts and derives the rail
    // as per_chip x voltage_domains. BC04's vendor stack values (default
    // 4800 mV, clamp 4000-5000) must reconstruct EXACTLY from the per-chip
    // encoding — and the per-chip values must sit under the HALPWR-3 1600 mV
    // per-ASIC driver ceiling, which is applied BEFORE the domain multiply
    // (power.rs `set_voltage_mv`), so a legitimate 4.8 V stack passes while a
    // stack-millivolt value smuggled in as per-chip is refused.
    #[test]
    fn hammer_profiles_express_per_chip_voltage_and_derive_the_stack() {
        for (model, _key, _target, _ver, chips, domains, def_mv, max_mv, _id) in HAMMER {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(cfg.asic_count, chips, "{model:?}");
            assert_eq!(cfg.voltage_domains, domains, "{model:?}: series count");
            assert_eq!(
                cfg.default_voltage_mv, def_mv,
                "{model:?}: per-chip default"
            );
            assert_eq!(cfg.max_voltage_mv, max_mv, "{model:?}: per-chip max");
            assert!(
                cfg.max_voltage_mv < crate::safety::DRIVER_VOLTAGE_CEILING_MV,
                "{model:?}: per-chip max must stay under the HALPWR-3 driver ceiling"
            );
            // Series stack rule: every chip is its own domain on Hammer.
            assert_eq!(
                cfg.voltage_domains, cfg.asic_count as u16,
                "{model:?}: Hammer stacks one chip per series domain"
            );
        }

        // BC04 vendor NVS values reconstruct exactly from per-chip x domains.
        let bc04 = BoardConfig::for_model(BitAxeModel::HammerBc04);
        let stack_default = bc04.default_voltage_mv as u32 * bc04.voltage_domains as u32;
        let stack_max = bc04.max_voltage_mv as u32 * bc04.voltage_domains as u32;
        let stack_min = bc04.min_voltage_mv as u32 * bc04.voltage_domains as u32;
        assert_eq!(stack_default, 4800, "vendor NVS default 4800 mV stack");
        assert_eq!(stack_max, 5000, "vendor clamp top 5000 mV stack");
        assert_eq!(stack_min, 4000, "vendor clamp bottom 4000 mV stack");
        // The stack value itself would be REFUSED as a per-chip request —
        // proves the fail-closed direction if units were ever confused.
        assert!(
            !crate::safety::voltage_within_driver_ceiling(
                4800,
                crate::safety::DRIVER_VOLTAGE_CEILING_MV
            ),
            "a stack-millivolt value smuggled in as per-chip must be refused by HALPWR-3"
        );
    }

    // ── Fail-closed: no Hammer peripheral driver exists, so the boards must
    // refuse mining (no trusted temperature source) while still registering,
    // booting and identifying. TMP75 vs TMP1075 can be classified from a
    // Device ID read (`tmp1075_convert::classify_ti_temp_part`) but Hammer
    // has no live 0x0F capture, and `RailBringup::NoActuator` still cannot
    // cut the rail. Do not invert this test until both a verified decode
    // AND a rail-cut path exist for the exact SKU. ──
    #[test]
    fn hammer_boards_refuse_mining_until_drivers_exist() {
        for (model, _key, _target, ver, _chips, _domains, _def, _max, _id) in HAMMER {
            let profile = BoardVersionProfile::find(ver).unwrap();
            assert_eq!(profile.fan_controller, FanControllerKind::None, "{model:?}");
            assert_eq!(profile.temp_sensor, TempSensorKind::None, "{model:?}");
            assert_eq!(
                profile.power_controller,
                PowerControllerKind::None,
                "{model:?}"
            );

            let cfg = BoardConfig::for_model(model);
            assert!(cfg.mining_capable(), "{model:?}: envelope is recorded");
            assert!(
                !cfg.has_trusted_thermal_source_configured(),
                "{model:?}: no thermal source may be claimed without a driver"
            );
            assert_eq!(
                cfg.validate(),
                Err("mining-capable board requires a trusted temperature source"),
                "{model:?}: board validation must refuse mining fail-closed"
            );
            assert!(
                !model.has_voltage_control(),
                "{model:?}: no voltage-control capability may be advertised"
            );
        }
    }

    // ── Boot safety: Hammer must not bind a guessed buck-enable output. The
    // main.rs GPIO binder accepts the -1 sentinel by constructing only reset
    // and LED outputs. Pin this on the MODEL so an NVS override cannot borrow
    // GPIO10 or panel D5 (GPIO46). ──
    #[test]
    fn hammer_power_pins_resolve_to_the_no_buck_tuple() {
        for (model, _key, _target, _ver, _chips, _domains, _def, _max, _id) in HAMMER {
            let mut cfg = BoardConfig::for_model(model);
            let expected_reset = if model == BitAxeModel::HammerDc02 {
                3
            } else {
                1
            };
            assert_eq!(cfg.asic_reset_pin, expected_reset, "{model:?}");
            assert_eq!(cfg.led_pin, 4, "{model:?}");
            assert_eq!(cfg.buck_enable_pin, -1, "{model:?}");
            assert!(!cfg.buck_enable_active_low, "{model:?}");
            assert_eq!(cfg.plug_sense_pin, -1, "{model:?}");

            // A hostile/mistaken NVS hardware override claiming a DS4432U must
            // NOT re-route the family onto GPIO10 active-LOW or GPIO46.
            cfg.apply_hardware_config(&BoardHardwareConfig {
                plug_sense: false,
                asic_enable: false,
                fan_controller: FanControllerKind::None,
                temp_sensor: TempSensorKind::None,
                power_controller: PowerControllerKind::Ds4432u,
                has_ina260: true,
                emc_internal_temp: false,
                emc_ideality_factor: 0x12,
                emc_beta_compensation: 0x00,
                temp_offset_c: 0,
                power_consumption_target_w: 25,
            });
            assert_eq!(
                cfg.buck_enable_pin, -1,
                "{model:?}: override must not invent a buck-enable output"
            );
            assert!(
                !cfg.buck_enable_active_low,
                "{model:?}: override must not invert EN polarity"
            );
        }
    }

    // ── Vendor-RE'd pin truth stays recorded (and the BC01/BC04 UART swap is
    // never collapsed into one shared constant). ──
    #[test]
    fn hammer_uart_pins_record_the_vendor_swap() {
        let bc01 = BoardConfig::for_model(BitAxeModel::HammerBc01);
        assert_eq!(
            (bc01.uart_tx_pin, bc01.uart_rx_pin),
            (18, 17),
            "BC01: TX18/RX17"
        );
        let bc04 = BoardConfig::for_model(BitAxeModel::HammerBc04);
        assert_eq!(
            (bc04.uart_tx_pin, bc04.uart_rx_pin),
            (17, 18),
            "BC04: TX17/RX18"
        );
        // Hammer I2C bus0 is SDA44/SCL43 — NOT the Bitaxe 47/48.
        for model in [BitAxeModel::HammerBc01, BitAxeModel::HammerBc04] {
            let cfg = BoardConfig::for_model(model);
            assert_eq!((cfg.i2c_sda_pin, cfg.i2c_scl_pin), (44, 43), "{model:?}");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Hammer DC0x (Scrypt / MSBT0501) — P3b board registration
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod hammer_dc0x_boards {
    use super::*;

    /// (model, canonical key, board_target, board_version, chips, per-chip mV,
    ///  TMP75 identity strap, ASIC UART TX, RX, ASIC RESET GPIO)
    const DC0X: [(BitAxeModel, &str, &str, &str, u8, u16, u8, i32, i32, i32); 3] = [
        (
            BitAxeModel::HammerDc02,
            "hammer_dc02",
            "hammer-dc02",
            "3102",
            2,
            635,
            0x48,
            18,
            17,
            3,
        ),
        (
            BitAxeModel::HammerDc04,
            "hammer_dc04",
            "hammer-dc04",
            "3104",
            4,
            635,
            0x4C,
            17,
            18,
            1,
        ),
        (
            BitAxeModel::HammerDc06,
            "hammer_dc06",
            "hammer-dc06",
            "3106",
            6,
            635,
            0x4F,
            17,
            18,
            1,
        ),
    ];

    #[test]
    fn dc0x_models_register_with_experimental_scrypt_identity() {
        for (model, key, target, ver, chips, _mv, strap, _tx, _rx, _rst) in DC0X {
            assert_eq!(model.canonical_key(), key);
            assert_eq!(model.board_target(), target);
            assert_eq!(model.asic_count(), chips);
            assert_eq!(model.support_status(), "experimental");
            assert_eq!(model.pow_algorithm(), PowAlgorithm::Scrypt1024);
            assert!(model.is_hammer() && model.is_hammer_dc());
            assert!(!model.is_hammer_bc(), "DC0x is not the SHA-256 BC subset");
            // DC06 is 6 chips but must NEVER be `is_hex()`: Hex means the
            // BitAxe 6x/3-domain 12 V topology and drives a different TPS546
            // preset. DC06 is 6 chips in SIX domains at 0.635 V each.
            assert!(!model.is_hex(), "{model:?} must not be treated as Hex");
            assert!(!model.is_lucky() && !model.is_dcent_axe());
            let profile = BoardVersionProfile::default_for_model(model);
            assert_eq!(profile.board_version, ver);
            assert_eq!(profile.asic_model, "MSBT0501");
            assert_eq!(profile.model, model);
            assert_eq!(
                profile.identity_strap_addr(),
                Some(strap),
                "{model:?}: row-owned identity strap"
            );
            assert_eq!(
                BoardConfig::for_model(model).identity_strap_addr,
                Some(strap),
                "{model:?}: strap must copy into runtime board config"
            );
            // No live proof of ANY kind exists for this chip.
            assert_eq!(profile.live_proof, LiveProof::None);
        }
        // Vendor `devicemodel` spellings resolve (the strings the vendor
        // firmware itself compares against the TMP75 strap).
        assert_eq!(
            BitAxeModel::from_device_model("DC06"),
            Some(BitAxeModel::HammerDc06)
        );
        assert_eq!(
            BitAxeModel::from_device_model("hammer_dc02"),
            Some(BitAxeModel::HammerDc02)
        );
    }

    #[test]
    fn dc0x_identity_strap_is_not_hardware_overridable() {
        let mut cfg = BoardConfig::for_model(BitAxeModel::HammerDc04);
        assert_eq!(cfg.identity_strap_addr, Some(0x4C));
        cfg.apply_hardware_config(&BoardHardwareConfig {
            plug_sense: true,
            asic_enable: true,
            fan_controller: FanControllerKind::None,
            temp_sensor: TempSensorKind::None,
            power_controller: PowerControllerKind::Tps546,
            has_ina260: true,
            emc_internal_temp: true,
            emc_ideality_factor: 0x24,
            emc_beta_compensation: 0,
            temp_offset_c: 9,
            power_consumption_target_w: 1,
        });
        assert_eq!(
            cfg.identity_strap_addr,
            Some(0x4C),
            "custom hardware metadata must not forge the registered strap"
        );
    }

    // ── 🔴 THE SAFETY-CRITICAL ONE: series-stacked rail derivation ──────────
    #[test]
    fn dc0x_stores_per_asic_voltage_only_and_derives_the_series_rail() {
        // rail = 0.635 V x chip_count, proven three independent ways in the RE
        // (DC02 1270/2, DC04 2540/4, DC06 3810/6). The profile stores ONLY the
        // per-ASIC value; `voltage_domains` carries the multiplier.
        let expected = [
            (BitAxeModel::HammerDc02, 1270u32, 1000u32, 1500u32),
            (BitAxeModel::HammerDc04, 2540, 2000, 3000),
            (BitAxeModel::HammerDc06, 3810, 3000, 4500),
        ];
        for (model, rail, rail_min, rail_max) in expected {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(cfg.default_voltage_mv, 635, "{model:?}: PER-ASIC mV");
            assert_eq!(
                cfg.voltage_domains as u8, cfg.asic_count,
                "{model:?}: every DC0x chip is its own series domain"
            );
            let d = cfg.voltage_domains as u32;
            assert_eq!(
                cfg.default_voltage_mv as u32 * d,
                rail,
                "{model:?}: derived rail must equal the vendor's commanded rail"
            );
            // The per-chip window is IDENTICAL across all three models — which
            // is precisely why it must never be stored as a rail constant.
            assert_eq!(
                (cfg.min_voltage_mv, cfg.max_voltage_mv),
                (500, 750),
                "{model:?}"
            );
            assert_eq!(cfg.min_voltage_mv as u32 * d, rail_min, "{model:?}");
            assert_eq!(cfg.max_voltage_mv as u32 * d, rail_max, "{model:?}");
            // HALPWR-3: the 1600 mV driver ceiling applies to the PER-ASIC
            // value BEFORE the domain multiply.
            assert!(
                crate::safety::voltage_within_driver_ceiling(
                    cfg.max_voltage_mv,
                    crate::safety::DRIVER_VOLTAGE_CEILING_MV
                ),
                "{model:?}: per-chip max must clear the HALPWR-3 ceiling"
            );
        }
        // The hazard this encoding removes: a DC06 RAIL value (3810 mV)
        // mistakenly written as a per-ASIC value would be a 6x over-volt. It
        // can only enter through the per-ASIC field — where HALPWR-3 refuses
        // it fail-closed. Same for DC04's 2540.
        for rail_value in [1270u16, 2540, 3810] {
            if rail_value > crate::safety::DRIVER_VOLTAGE_CEILING_MV {
                assert!(
                    !crate::safety::voltage_within_driver_ceiling(
                        rail_value,
                        crate::safety::DRIVER_VOLTAGE_CEILING_MV
                    ),
                    "a rail value ({rail_value} mV) smuggled in as per-ASIC must be REFUSED"
                );
            }
        }
        assert!(crate::safety::voltage_within_driver_ceiling(
            635,
            crate::safety::DRIVER_VOLTAGE_CEILING_MV
        ));
    }

    // ── 🔴 FOUR DISCRETE PROFILES: the five cross-model GPIO collisions ─────
    #[test]
    fn dc02_and_dc04_never_share_a_colliding_pin_value() {
        let dc02 = BoardConfig::for_model(BitAxeModel::HammerDc02);
        let dc04 = BoardConfig::for_model(BitAxeModel::HammerDc04);
        let dc06 = BoardConfig::for_model(BitAxeModel::HammerDc06);

        // UART is SWAPPED between DC02 and DC04/DC06 (collapsing it puts two
        // TX drivers back-to-back on both wires).
        assert_eq!((dc02.uart_tx_pin, dc02.uart_rx_pin), (18, 17), "DC02");
        assert_eq!((dc04.uart_tx_pin, dc04.uart_rx_pin), (17, 18), "DC04");
        assert_eq!((dc06.uart_tx_pin, dc06.uart_rx_pin), (17, 18), "DC06");
        assert_ne!(
            (dc02.uart_tx_pin, dc02.uart_rx_pin),
            (dc04.uart_tx_pin, dc04.uart_rx_pin),
            "the DC02/DC04 UART swap must never collapse into one constant"
        );

        // ASIC RESET: GPIO 3 on DC02, GPIO 1 on DC04/DC06. Collapsing this
        // would either clock DC02's reset line from DC04's 16 MHz SPI SCLK, or
        // drive DC04's push-pull reset into DC02's fan TACH driver while
        // leaving DC02's real reset unasserted during vcore bring-up.
        assert_eq!(dc02.asic_reset_pin, 3, "DC02 ASIC RESET");
        assert_eq!(dc04.asic_reset_pin, 1, "DC04 ASIC RESET");
        assert_eq!(dc06.asic_reset_pin, 1, "DC06 ASIC RESET");
        assert_ne!(dc02.asic_reset_pin, dc04.asic_reset_pin);

        // The five colliding GPIOs are 1, 2, 3, 10, 11. We claim NO fan pins on
        // any DC0x model (DC02's vendor fan uses GPIO 2 PWM / GPIO 1 tach —
        // both DC04 nets), which removes four of the five outright.
        for (name, cfg) in [("DC02", &dc02), ("DC04", &dc04), ("DC06", &dc06)] {
            assert_eq!(cfg.fan_pwm_pin, -1, "{name}: no ESP fan PWM pin claimed");
            assert_eq!(cfg.fan_tach_pin, -1, "{name}: no ESP fan tach pin claimed");
            assert_eq!(cfg.plug_sense_pin, -1, "{name}");
            // GPIO 10 (DC02 PGOOD / DC04 SPI CS) and GPIO 11 (DC02 I2C1 SDA —
            // the ONLY path to command vcore off — / DC04 PGOOD) must never be
            // driven as the buck-enable line.
            assert_ne!(cfg.buck_enable_pin, 10, "{name}: GPIO10 collides");
            assert_ne!(cfg.buck_enable_pin, 11, "{name}: GPIO11 collides");
            assert_eq!(cfg.buck_enable_pin, -1, "{name}: no verified buck GPIO");
            assert!(!cfg.buck_enable_active_low, "{name}");
            // I2C0 is the ONE genuinely shared bus (SDA 44 / SCL 43).
            assert_eq!((cfg.i2c_sda_pin, cfg.i2c_scl_pin), (44, 43), "{name}");
        }
    }

    // ── Every profile's GPIO tuple must be bindable by main.rs ─────────────
    #[test]
    fn board_gpio_tuple_is_bindable_for_every_model() {
        // `main.rs` matches
        // (asic_reset_pin, buck_enable_pin, led_pin, ldo_enable_pin) against a
        // CLOSED set and panics otherwise — and panic = abort = boot loop.
        // Recording DC02's real GPIO 3 reset is only safe because the binder
        // accepts (3,-1,4,-1); this test keeps the two in sync for every row.
        // (1,-1,9,-1) is the BitForge Nano: LED on GPIO9 because GPIO4 is its
        // ASIC-2 thermistor divider node, and no discrete buck-enable.
        //
        // `ldo_enable_pin` joined this key in the SAME change that introduced
        // it, deliberately. Had it stayed out, a board declaring an LDO would
        // match the existing (1,10,4) arm, bind no LDO pin, and boot with a
        // configured core rail feeding dies whose IO supply never came up —
        // silent, and indistinguishable from an enumeration fault.
        const SUPPORTED: [(i32, i32, i32, i32); 6] = [
            (1, 10, 4, 13),
            (1, 10, 4, -1),
            (1, 46, 4, -1),
            (1, -1, 4, -1),
            (3, -1, 4, -1),
            (1, -1, 9, -1),
        ];
        for row in BoardVersionProfile::ALL.iter() {
            let cfg = BoardConfig::for_model(row.model);
            let tuple = (
                cfg.asic_reset_pin,
                cfg.buck_enable_pin,
                cfg.led_pin,
                cfg.ldo_enable_pin,
            );
            assert!(
                SUPPORTED.contains(&tuple),
                "{:?} ({}) yields GPIO tuple {tuple:?}, which main.rs cannot bind \
                 — it would panic at boot (panic=abort => boot loop). Add the arm \
                 to main.rs in the SAME change, or fix the profile.",
                row.model,
                row.board_version
            );
        }
    }

    // ── Honest capabilities: these boards refuse to mine ────────────────────
    #[test]
    fn dc0x_boards_refuse_mining_until_drivers_exist() {
        for (model, _k, _t, _v, _c, _mv, _s, _tx, _rx, _r) in DC0X {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(
                cfg.temp_sensor,
                TempSensorKind::None,
                "{model:?}: no TMP75 driver exists, and a board-proxy sensor \
                 could not be a trusted die source even if one did"
            );
            assert_eq!(
                cfg.power_controller,
                PowerControllerKind::None,
                "{model:?}: DC02's TPS546 sits on an I2C bus this HAL cannot \
                 express, and DC02 vs DC04 use different PMBus encodings and \
                 init paths. Declaring Tps546 would ALSO permit mining."
            );
            assert!(!cfg.has_ina260);
            assert!(
                !cfg.has_trusted_thermal_source_configured(),
                "{model:?}: must have NO trusted thermal source"
            );
            assert_eq!(
                cfg.validate(),
                Err("mining-capable board requires a trusted temperature source"),
                "{model:?}: mining must be REFUSED fail-closed"
            );
            assert!(
                !model.has_voltage_control(),
                "{model:?}: no regulator driver path => the capability \
                 descriptor must not claim writes"
            );
            // Display: the vendor ST7789 exists but we ship no driver.
            assert_eq!(cfg.display_kind, DisplayKind::None);
        }

        // DC04/DC06 DO get an honest fan-controller declaration: the part is a
        // 2-fan EMC230x @0x2E whose register map (duty 0x30/0x40, tach
        // 0x3E/0x3F AND 0x4E/0x4F) matches the shipped driver exactly.
        assert_eq!(
            BoardConfig::for_model(BitAxeModel::HammerDc04).fan_controller,
            FanControllerKind::Emc2302
        );
        assert_eq!(
            BoardConfig::for_model(BitAxeModel::HammerDc06).fan_controller,
            FanControllerKind::Emc2302
        );
        assert_eq!(
            BoardConfig::for_model(BitAxeModel::HammerDc02).fan_controller,
            FanControllerKind::None,
            "DC02's fan is SoC LEDC PWM — declaring an EMC2302 would be a lie"
        );
    }

    // ── Frequency envelope: vendor STOCK only, zero headroom ───────────────
    #[test]
    fn dc0x_frequency_envelope_is_the_vendor_stock_default_with_no_headroom() {
        for (model, _k, _t, _v, _c, _mv, _s, _tx, _rx, _r) in DC0X {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(
                cfg.default_frequency, 2300.0,
                "{model:?}: the vendor STOCK default (0x8FC) — NOT the 2600 MHz \
                 firmware clamp and NOT the web UI's 2400 policy number"
            );
        }
    }

    #[test]
    fn dc0x_profiles_are_consistent_apart_from_the_deliberate_thermal_refusal() {
        // Everything else about the row must be internally consistent, so the
        // single validate() failure is unambiguously the thermal refusal and
        // not a masked second defect.
        for (model, _k, _t, _v, _c, _mv, _s, _tx, _rx, _r) in DC0X {
            let cfg = BoardConfig::for_model(model);
            assert!(cfg.min_voltage_mv <= cfg.max_voltage_mv, "{model:?}");
            assert!(
                cfg.default_voltage_mv >= cfg.min_voltage_mv
                    && cfg.default_voltage_mv <= cfg.max_voltage_mv,
                "{model:?}"
            );
            assert!(cfg.asic_count > 0 && cfg.voltage_domains > 0, "{model:?}");
            assert!(cfg.mining_capable(), "{model:?}: the board IS mining-class");
        }
    }
}

#[cfg(test)]
mod lucky_lvxx_boards {
    use super::*;

    // (model, canonical key / device_model, board_target, canonical 2XXX
    //  board_version, chips)
    const LUCKY: [(BitAxeModel, &str, &str, &str, u8); 3] = [
        (BitAxeModel::LuckyLv06, "lv06", "lucky-lv06", "2006", 1),
        (BitAxeModel::LuckyLv07, "lv07", "lucky-lv07", "2007", 2),
        (BitAxeModel::LuckyLv08, "lv08", "lucky-lv08", "2008", 9),
    ];

    #[test]
    fn lucky_models_register_with_experimental_identity() {
        for (model, key, target, ver, chips) in LUCKY {
            assert_eq!(model.canonical_key(), key);
            assert_eq!(model.board_target(), target);
            assert_eq!(BitAxeModel::from_device_model(key), Some(model));
            // canonical_key round-trips through from_device_model.
            assert_eq!(
                BitAxeModel::from_device_model(model.canonical_key()),
                Some(model)
            );
            assert_eq!(model.support_status(), "experimental", "{model:?}");
            assert_eq!(model.asic_count(), chips, "{model:?}");
            assert_eq!(model.expected_chip_id(), 0x1366, "{model:?}: BM1366");
            assert!(model.is_lucky(), "{model:?}");
            assert!(
                !model.is_hex() && !model.is_nerd() && !model.is_hammer() && !model.is_dcent_axe(),
                "{model:?}: Lucky is its own family"
            );
            assert!(!model.has_bap(), "{model:?}: no BAP header");
            assert_eq!(model.display_kind(), DisplayKind::Ssd1306, "{model:?}");

            let profile = BoardVersionProfile::find(ver)
                .unwrap_or_else(|| panic!("profile {ver} for {model:?} must exist"));
            assert_eq!(profile.model, model);
            assert_eq!(profile.device_model, key);
            assert_eq!(profile.asic_model, "BM1366");
            assert_eq!(
                BoardVersionProfile::default_for_model(model).board_version,
                ver
            );
        }
        // Vendor / human alias spellings resolve too.
        assert_eq!(
            BitAxeModel::from_device_model("LV06"),
            Some(BitAxeModel::LuckyLv06)
        );
        assert_eq!(
            BitAxeModel::from_device_model("lucky_lv07"),
            Some(BitAxeModel::LuckyLv07)
        );
        assert_eq!(
            BitAxeModel::from_device_model("luckylv08"),
            Some(BitAxeModel::LuckyLv08)
        );
        assert_eq!(
            BitAxeModel::from_device_model("lucky lv08"),
            Some(BitAxeModel::LuckyLv08)
        );
        assert_eq!(
            BitAxeModel::from_device_model("lucky-lv06"),
            Some(BitAxeModel::LuckyLv06)
        );
    }

    // ── THE Lucky safety invariant (SPEC §1.1): ONE PARALLEL voltage domain.
    // The chips sit in parallel at ~1.2 V — NOT series-stacked like Hex or
    // Hammer. `power.rs:906` computes rail = per_asic_v x voltage_domains, so
    // ANY value >1 on a Lucky row drives a multiple of 1.2 V onto up to nine
    // parallel dies. This test pins the 1 so no "consistency" refactor
    // (e.g. copying the Hammer chips==domains rule) can quietly raise it. ──
    #[test]
    fn lucky_voltage_domains_pinned_to_one_parallel_domain() {
        for (model, _key, _target, _ver, chips) in LUCKY {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(
                cfg.voltage_domains, 1,
                "{model:?}: Lucky chips are PARALLEL on ONE ~1.2 V domain — \
                 voltage_domains MUST stay 1 (SPEC §1.1; the LVXX fork's own \
                 HEAD deleted its 3.6 V LV08 case)"
            );
            // Derived rail == per-chip voltage (multiplier is 1).
            assert_eq!(
                cfg.default_voltage_mv as u32 * cfg.voltage_domains as u32,
                cfg.default_voltage_mv as u32,
                "{model:?}: rail must equal the per-chip voltage"
            );
            // The Hammer series rule (domains == chips) must NOT leak in.
            if chips > 1 {
                assert_ne!(
                    cfg.voltage_domains, cfg.asic_count as u16,
                    "{model:?}: Lucky is NOT one-chip-per-series-domain"
                );
            }
            // And Lucky is not Hex: it must never take the 3-domain Hex path.
            assert!(!model.is_hex(), "{model:?} must NOT be is_hex()");
        }
    }

    // ── Mandatory tach proof (closes the R2 §13.4 gap): LV08 is a 140 W
    // nine-die board and LV07 a 40 W Hex-Ultra-class two-die board — both
    // must prove their fans turn, via the ROW CAPABILITY rung
    // (`fan_tach_required`), NOT via is_hex() (which would drag in the
    // 3-domain series path). LV06 (single die, Ultra/Gamma-class real
    // dissipation) deliberately stays on the heuristic + XPSAFE-7 opt-in
    // posture like every other shipping single-chip board. ──
    #[test]
    fn lucky_lv07_lv08_require_tach_proof_via_capability_not_is_hex() {
        for (model, required) in [
            (BitAxeModel::LuckyLv06, false),
            (BitAxeModel::LuckyLv07, true),
            (BitAxeModel::LuckyLv08, true),
        ] {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(
                cfg.requires_fan_tach(),
                required,
                "{model:?}: mandatory tach proof expectation"
            );
            assert_eq!(
                cfg.tach_proof_required(),
                required,
                "{model:?}: boot/runtime gate capability must agree"
            );
            // The requirement must come from the row capability, never from
            // is_hex() or an EMC2103 claim.
            assert!(!model.is_hex(), "{model:?}");
            assert_ne!(cfg.fan_controller, FanControllerKind::Emc2103, "{model:?}");
            assert_eq!(
                cfg.fan_tach_required, required,
                "{model:?}: row capability field is the only source"
            );
        }
        // Profile-row source of truth agrees.
        assert!(!BoardVersionProfile::find("2006")
            .unwrap()
            .fan_tach_required());
        assert!(BoardVersionProfile::find("2007")
            .unwrap()
            .fan_tach_required());
        assert!(BoardVersionProfile::find("2008")
            .unwrap()
            .fan_tach_required());
    }

    // ── Envelope + validation. NOTE (SPEC §7): unlike Hammer, Lucky declares
    // real shipped drivers (Emc2302/Tmp1075/Tps546), so validate() PASSES and
    // mining is permitted — which is why the §3 disambiguation, §4
    // multi-regulator, §5 chip scaling and §6 fail-closed enum work must land
    // in the same commit as these rows. ──
    #[test]
    fn lucky_boards_validate_and_carry_the_vendor_envelope() {
        for (model, _key, _target, ver, chips) in LUCKY {
            let cfg = BoardConfig::for_model(model);
            // `ver` was destructured but unused here. Spend it on the binding
            // that actually matters: the envelope asserted below is only this
            // board's if the model still resolves to this board's profile row.
            assert_eq!(
                BoardVersionProfile::default_for_model(model).board_version,
                ver,
                "{model:?}: default profile row"
            );
            assert_eq!(cfg.asic_count, chips, "{model:?}");
            assert_eq!(cfg.default_frequency, 485.0, "{model:?}: vendor 485 MHz");
            assert_eq!(cfg.default_voltage_mv, 1200, "{model:?}: vendor 1200 mV");
            assert_eq!(cfg.max_voltage_mv, 1300, "{model:?}: vendor option cap");
            assert_eq!(cfg.min_voltage_mv, 1000, "{model:?}");
            assert_eq!(cfg.power_offset_w, 18.0, "{model:?}: LVXX family offset");
            assert_eq!(cfg.temp_offset_c, 5, "{model:?}: TMP1075 offset +5");
            assert!(
                cfg.max_voltage_mv < crate::safety::DRIVER_VOLTAGE_CEILING_MV,
                "{model:?}: per-chip max under the HALPWR-3 ceiling"
            );
            // Stock BitAxe pin map (R1: 100% stock — pins-bitaxe family).
            assert_eq!(
                (cfg.uart_tx_pin, cfg.uart_rx_pin),
                (uart_tx_gpio(), uart_rx_gpio()),
                "{model:?}: stock BitAxe UART pins"
            );
            assert_eq!(
                (cfg.i2c_sda_pin, cfg.i2c_scl_pin),
                (i2c_sda_gpio(), i2c_scl_gpio()),
                "{model:?}: stock BitAxe I2C pins"
            );
            assert_eq!(cfg.asic_reset_pin, 1, "{model:?}: RST_N GPIO1");

            assert!(
                cfg.validate().is_ok(),
                "{model:?} must validate: {:?}",
                cfg.validate()
            );
            assert!(cfg.mining_capable(), "{model:?}");
            assert!(
                cfg.has_trusted_thermal_source_configured(),
                "{model:?}: TMP1075 + TPS546 are shipped drivers"
            );
            assert!(
                model.has_voltage_control(),
                "{model:?}: TPS546 addresses \
                 are RE-confirmed (0x24; LV08 adds 0x7F/0x14)"
            );
        }
    }

    // ── Power-pin determinism: stock GPIO46 ACTIVE-HIGH, keyed on the model
    // so a mistaken NVS Ds4432u override can never flip GPIO10 active-low
    // semantics onto a 12 V Lucky board. ──
    #[test]
    fn lucky_power_pins_resolve_stock_gpio46_and_resist_overrides() {
        for (model, _key, _target, _ver, _chips) in LUCKY {
            let mut cfg = BoardConfig::for_model(model);
            assert_eq!(cfg.buck_enable_pin, 46, "{model:?}");
            assert!(!cfg.buck_enable_active_low, "{model:?}");
            assert_eq!(cfg.plug_sense_pin, -1, "{model:?}");
            // Fail-closed OFF must drive the EN pin LOW (active-high).
            assert_eq!(crate::safety::buck_off_level(cfg.buck_enable_active_low), 0);

            cfg.apply_hardware_config(&BoardHardwareConfig {
                plug_sense: false,
                asic_enable: false,
                fan_controller: FanControllerKind::Emc2302,
                temp_sensor: TempSensorKind::Tmp1075,
                power_controller: PowerControllerKind::Ds4432u,
                has_ina260: true,
                emc_internal_temp: false,
                emc_ideality_factor: 0x12,
                emc_beta_compensation: 0x00,
                temp_offset_c: 5,
                power_consumption_target_w: 40,
            });
            assert_eq!(
                cfg.buck_enable_pin, 46,
                "{model:?}: override must not move the EN pin to GPIO10"
            );
            assert!(
                !cfg.buck_enable_active_low,
                "{model:?}: override must not invert EN polarity"
            );
        }
    }

    // ── SPEC §3 disambiguation table. A Lucky Miner does not announce itself
    // honestly: stock factory FW lies as a Supra ("402"/"supra" + minermodel
    // "LV08"); the unlocked LVXX fork lies as a Hex Ultra ("302"/"lv08").
    // The tuple resolver must sort every row of this table correctly. ──
    #[test]
    fn resolve_identity_disambiguation_table() {
        use IdentityVerdict::*;

        fn resolved_version(v: IdentityVerdict) -> &'static str {
            match v {
                Resolved(p) => p.board_version,
                other => panic!("expected Resolved, got {other:?}"),
            }
        }

        // Stock LV08 (factory FW): minermodel is authoritative (step 1).
        assert_eq!(
            resolved_version(resolve_identity("402", "supra", "LV08")),
            "2008"
        );
        // ...case-insensitive.
        assert_eq!(
            resolved_version(resolve_identity("402", "supra", "lv08")),
            "2008"
        );

        // Unlocked LV08 (mrbonkerz LVXX): devicemodel rung (step 2).
        assert_eq!(
            resolved_version(resolve_identity("302", "lv08", "")),
            "2008"
        );
        assert_eq!(
            resolved_version(resolve_identity("300", "lv06", "")),
            "2006"
        );
        assert_eq!(
            resolved_version(resolve_identity("301", "lv07", "")),
            "2007"
        );

        // minermodel outranks devicemodel (step 1 before step 2).
        assert_eq!(
            resolved_version(resolve_identity("302", "hex", "LV06")),
            "2006"
        );

        // Genuine Hex Ultra: boardversion 302 WITH devicemodel hex — resolves
        // to the real Hex row, never ambiguous.
        assert_eq!(resolved_version(resolve_identity("302", "hex", "")), "302");
        assert_eq!(
            match resolve_identity("302", "hex", "") {
                Resolved(p) => p.model,
                other => panic!("expected Resolved, got {other:?}"),
            },
            BitAxeModel::HexUltra
        );

        // Genuine Supra: 402 with NO minermodel — a genuine BitAxe never
        // writes that key.
        assert_eq!(
            resolved_version(resolve_identity("402", "supra", "")),
            "402"
        );

        // A-suffix vendor spellings are LVXX-only ⇒ unambiguous Lucky
        // (SPEC §1.2 — the caller maps the anonymity to a config flag).
        assert_eq!(resolved_version(resolve_identity("302A", "", "")), "2008");
        assert_eq!(resolved_version(resolve_identity("300A", "", "")), "2006");
        assert_eq!(resolved_version(resolve_identity("301A", "", "")), "2007");

        // Canonical Lucky rows resolve directly.
        assert_eq!(resolved_version(resolve_identity("2008", "", "")), "2008");

        // AMBIGUOUS: 302/303 without a hex devicemodel ⇒ caller must probe
        // PMBus 0x7F/0x14 (three-regulator LV08 signature) or refuse.
        for bv in ["302", "303"] {
            match resolve_identity(bv, "", "") {
                Ambiguous { probe_lv08, .. } => {
                    assert!(probe_lv08, "{bv}: must request the LV08 probe")
                }
                other => panic!("{bv} with empty devicemodel must be Ambiguous, got {other:?}"),
            }
        }
        // AMBIGUOUS: 402 with a present-but-unrecognized minermodel.
        match resolve_identity("402", "supra", "LV99") {
            Ambiguous { probe_lv08, .. } => assert!(probe_lv08),
            other => panic!("402+minermodel must be Ambiguous, got {other:?}"),
        }

        // Unknown tuple stays Unknown (caller falls back / refuses).
        assert_eq!(resolve_identity("", "", ""), Unknown);
        assert_eq!(resolve_identity("999x", "", ""), Unknown);
    }
}

#[cfg(test)]
mod bitforge_nano {
    use super::*;

    /// The row's own facts, each against the source that establishes it.
    #[test]
    fn the_row_matches_the_vendor_firmware_and_the_schematic() {
        let p = BoardVersionProfile::find("4100").expect("4100 registered");
        assert_eq!(p.model, BitAxeModel::BitForgeNano);
        // forge-os `asic.h`: ASIC_BM1370 is the only ASIC in its enum.
        assert_eq!(p.asic_model, "BM1370");
        assert_eq!(BitAxeModel::BitForgeNano.expected_chip_id(), 0x1370);
        // `BITFORGE_NANO_ASIC_COUNT 2`.
        assert_eq!(BitAxeModel::BitForgeNano.asic_count(), 2);
        // TPS546A24 over PMBus (`TPS546_CONFIG_NANO`), INA260 for board V/I.
        assert_eq!(p.power_controller, PowerControllerKind::Tps546);
        assert!(p.has_ina260);
        // Two EMC2101s; `Thermal_getAsicChipTemp` returns
        // `EMC2101_getExternalTemp()`, so the EXTERNAL diode with no offset.
        assert_eq!(p.fan_controller, FanControllerKind::Emc2101);
        assert_eq!(p.temp_sensor, TempSensorKind::Emc2101);
        assert!(!p.emc_internal_temp);
        assert_eq!(p.temp_offset_c, 0);
        // `EMC2101_IDEALITY_1_0566` = 0x37 — NOT the 0x24 the Gamma-shaped
        // boards use. A board-specific diode calibration; inheriting the Gamma
        // value would mis-read every die temperature on this board.
        assert_eq!(p.emc_ideality_factor, 0x37);
        assert_eq!(p.emc_beta_compensation, 0x00);
        // `BITFORGE_NANO_MAX_POWER 60`.
        assert_eq!(p.power_consumption_target_w, 60);
        // No unit on any bench.
        assert_eq!(p.live_proof, LiveProof::Host);
        assert_eq!(BitAxeModel::BitForgeNano.support_status(), "experimental");
    }

    /// SAFETY: two dies in PARALLEL on one rail. `power.rs` derives the rail as
    /// per-ASIC mV x domains, so a 2 here would command 2.4 V onto BM1370s.
    #[test]
    fn the_two_dies_are_one_voltage_domain_not_two() {
        let cfg = BoardConfig::for_model(BitAxeModel::BitForgeNano);
        assert_eq!(cfg.asic_count, 2);
        assert_eq!(
            cfg.voltage_domains, 1,
            "BitForge Nano's BM1370s are in PARALLEL (README, and one \
             TPS546_CONFIG_NANO with VOUT_COMMAND 1.2) — raising this drives a \
             multiple of the core voltage onto parallel dies"
        );
    }

    /// SAFETY: refuse the vendor's own default rather than inherit it.
    ///
    /// forge-os defaults `CONFIG_ASIC_VOLTAGE` to 1400 mV (help text citing
    /// BM1397, on a board with no BM1397), applied on a fresh flash because no
    /// NVS value exists. `VCORE_set_voltage` has no clamp and the only backstop
    /// is `TPS546_INIT_VOUT_MAX = 2` — a 2.0 V ceiling on a 1.2 V rail.
    #[test]
    fn the_envelope_refuses_the_vendor_kconfig_default() {
        let cfg = BoardConfig::for_model(BitAxeModel::BitForgeNano);
        const VENDOR_KCONFIG_DEFAULT_MV: u16 = 1400;
        const VENDOR_TPS546_VOUT_MAX_MV: u16 = 2000;
        assert!(
            cfg.max_voltage_mv < VENDOR_KCONFIG_DEFAULT_MV,
            "our ceiling ({} mV) must refuse the vendor's 1400 mV default",
            cfg.max_voltage_mv
        );
        assert!(cfg.max_voltage_mv < VENDOR_TPS546_VOUT_MAX_MV);
        assert!(cfg.default_voltage_mv <= cfg.max_voltage_mv);
        assert!(cfg.default_voltage_mv >= cfg.min_voltage_mv);
        assert!(cfg.validate().is_ok());
    }

    /// SAFETY: `CONFIG_GPIO_PLUG_SENSE` defaults to 12 on this board, but
    /// forge-os also defines `BLINK_GPIO_2` as 12 and drives it push-pull as a
    /// status LED. Binding 12 as a sense INPUT would fight an output.
    #[test]
    fn plug_sense_is_refused_because_gpio12_is_a_status_led_here() {
        let cfg = BoardConfig::for_model(BitAxeModel::BitForgeNano);
        assert_eq!(
            cfg.plug_sense_pin, -1,
            "GPIO12 is BLINK_GPIO_2 on this board, driven as an output"
        );
        // And the rail is PMBus-only, so nothing reaches the panic hook.
        assert_eq!(cfg.buck_enable_pin, -1);
        assert!(!cfg.buck_enable_active_low);
    }

    /// The board declares a temperature sensor, so it must also be able to
    /// reach it: on this board that means the PCA9544A channel select.
    #[test]
    fn the_declared_thermal_source_is_reachable_through_the_mux() {
        let cfg = BoardConfig::for_model(BitAxeModel::BitForgeNano);
        assert!(cfg.mining_capable());
        assert!(cfg.has_trusted_thermal_source_configured());
        // Both EMC2101s live behind the mux; the schematic's live downstream
        // nets are SC2/SD2 and SC3/SD3.
        use crate::pca9544_convert as mux;
        let declared = BitAxeModel::BitForgeNano
            .thermal_i2c_mux()
            .expect("BitForge Nano's sensor is behind a bus mux");
        assert_eq!(declared.addr, 0x70, "A0/A1/A2 are all grounded");
        assert_eq!(declared.channel, 2, "ASIC 0's EMC2101 is on SC2/SD2");
        // The declaration must be something the driver will actually accept —
        // a row naming channel 4, or an address outside the part's block, would
        // be refused at runtime and leave the board with no temperature.
        assert!(mux::is_plausible_address(declared.addr));
        assert!(mux::control_byte_for_channel(declared.channel).is_ok());
        assert!(mux::control_byte_for_channel(3).is_ok());
    }

    /// The capability must stay opt-in: every other board reads its sensor off
    /// a flat bus, and claiming a mux where there is none would insert a
    /// failing channel select into a working thermal path.
    #[test]
    fn no_other_registered_board_declares_a_bus_mux() {
        for profile in BoardVersionProfile::ALL {
            let model = profile.model;
            let declared = model.thermal_i2c_mux();
            if model == BitAxeModel::BitForgeNano {
                assert!(declared.is_some(), "{model:?} must declare its mux");
            } else {
                assert!(
                    declared.is_none(),
                    "{model:?} unexpectedly declares a thermal I2C mux — every \
                     other board reads its sensor directly"
                );
            }
            // Whatever a board declares, the driver must accept it.
            if let Some(m) = declared {
                assert!(crate::pca9544_convert::is_plausible_address(m.addr));
                assert!(crate::pca9544_convert::control_byte_for_channel(m.channel).is_ok());
            }
        }
    }

    #[test]
    fn identity_resolves_from_every_spelling_we_publish() {
        for key in [
            "bitforgenano",
            "bitforge_nano",
            "bitforge nano",
            "bitforge-nano",
        ] {
            assert_eq!(
                BitAxeModel::from_device_model(key),
                Some(BitAxeModel::BitForgeNano),
                "{key} must resolve"
            );
        }
        assert_eq!(BitAxeModel::BitForgeNano.canonical_key(), "bitforgenano");
        assert_eq!(BitAxeModel::BitForgeNano.board_target(), "bitforge-nano");
        assert_eq!(
            BoardVersionProfile::default_for_model(BitAxeModel::BitForgeNano).board_version,
            "4100"
        );
    }

    /// Three pins that must NOT be inherited from the stock BitAxe map.
    ///
    /// Each is wrong on this board in a different way, and each is confirmed
    /// twice — `BitForgeNano.kicad_pcb` and forge-os.
    #[test]
    fn the_stock_bitaxe_pin_map_is_wrong_on_this_board_in_three_places() {
        let cfg = BoardConfig::for_model(BitAxeModel::BitForgeNano);
        let stock = BoardConfig::for_model(BitAxeModel::Gamma);

        // GPIO4 is `/TMP_10K_A2`, the ASIC-2 NTC divider node. Driving it as an
        // LED output fights R73's 10 k pull-up and destroys that reading.
        // forge-os `self_test.c:49`: BLINK_GPIO_1 = 9.
        assert_eq!(
            stock.led_pin, 4,
            "the stock map is the thing being corrected"
        );
        assert_eq!(
            cfg.led_pin, 9,
            "GPIO4 on this board is a thermistor divider, not an LED"
        );

        // GPIO14 is `/ESP32/INA_ALRT`. Sampling an alert output as a tachometer
        // could read alert edges as fan pulses — a stopped fan masquerading as
        // a spinning one, which is the fail-OPEN direction.
        assert_eq!(cfg.fan_tach_pin, -1, "GPIO14 is the INA260 alert line");

        // GPIO11 is unconnected. Both fans are EMC2101-driven over I2C, and
        // tach comes from the EMC2101's own 0x46/0x47 registers — forge-os has
        // no LEDC setup and no GPIO tach anywhere.
        assert_eq!(cfg.fan_pwm_pin, -1, "GPIO11 is unconnected on this board");

        // The LED pin must never collide with a declared thermistor input.
        for ch in BitAxeModel::BitForgeNano.ntc_thermal_channels() {
            assert_ne!(
                cfg.led_pin, ch.gpio as i32,
                "led_pin collides with NTC channel on GPIO{}",
                ch.gpio
            );
        }
    }

    /// The board's two NTC channels, against the netlist and the vendor map.
    #[test]
    fn the_two_thermistors_are_declared_from_the_netlist() {
        let chans = BitAxeModel::BitForgeNano.ntc_thermal_channels();
        assert_eq!(chans.len(), 2, "TH1 and TH2 are both placed on the PCB");

        // TH1 -> /TMP_10K_A1 -> ESP32 pad 5 = GPIO5 = ADC1_CH4.
        // forge-os agrees: V_TEMP_10K_A1 -> ADC_CHANNEL_4.
        assert_eq!((chans[0].gpio, chans[0].adc1_channel), (5, 4));
        assert_eq!(chans[0].asic_index, 0);
        // TH2 -> /TMP_10K_A2 -> ESP32 pad 4 = GPIO4 = ADC1_CH3.
        assert_eq!((chans[1].gpio, chans[1].adc1_channel), (4, 3));
        assert_eq!(chans[1].asic_index, 1);

        // Distinct inputs — a copy-paste pointing both at one channel would
        // report one die twice and silently lose the other.
        assert_ne!(chans[0].adc1_channel, chans[1].adc1_channel);
        assert_ne!(chans[0].gpio, chans[1].gpio);

        // forge-os `adc.c:246`: `return temperature_celsius + 11U`. Carried as
        // board data, not baked into the physics.
        assert!(chans.iter().all(|c| c.offset_c == 11));
    }

    /// No other board declares thermistors, and the capability is NOT yet wired
    /// to a live consumer.
    ///
    /// The second half is the honest part. `ntc_convert` and this table are
    /// complete and host-tested, but the esp-idf ADC transport does not ship
    /// yet, so nothing reads these channels at runtime. That is recorded here
    /// rather than left implicit, because a board capability that reads as "this
    /// board has a thermal source" while nothing consumes it is exactly the
    /// overclaim the PCA9544A wave refused. Whoever wires the transport must
    /// consciously edit this test.
    #[test]
    fn thermistors_are_declared_by_one_board_and_not_yet_wired() {
        for profile in BoardVersionProfile::ALL.iter() {
            let declared = profile.model.ntc_thermal_channels();
            if profile.model == BitAxeModel::BitForgeNano {
                assert_eq!(declared.len(), 2, "{:?}", profile.model);
            } else {
                assert!(
                    declared.is_empty(),
                    "{:?} ({}) declares NTC channels — add its netlist citation \
                     and extend this test deliberately",
                    profile.model,
                    profile.board_version
                );
            }
        }

        // The declaration must not be mistaken for a live sensor: the board's
        // TempSensorKind is still the EMC2101 behind the mux, and NOTHING in
        // this crate converts these channels at runtime yet.
        let p = BoardVersionProfile::find("4100").unwrap();
        assert_eq!(
            p.temp_sensor,
            TempSensorKind::Emc2101,
            "the NTC is an ADDITIONAL proxy source, not this board's declared sensor"
        );
    }
}

/// The TMP451 analog diode-mux declarations.
///
/// These pin the *attribution* of a die temperature to an ASIC. A mux fault
/// does not make a board go blind — it makes it read the WRONG CHIP and report
/// the number with full confidence, which is the more dangerous failure.
#[cfg(test)]
mod tmp451_diode_mux_declaration {
    use super::*;

    /// Which models declare a mux. Ordered so the diff is readable when one
    /// moves; the per-model wiring is asserted below.
    const MUXED: [BitAxeModel; 4] = [
        BitAxeModel::NerdOctaxeGamma,
        BitAxeModel::NerdQX,
        BitAxeModel::Q1370,
        BitAxeModel::Q1373,
    ];

    #[test]
    fn only_the_four_known_boards_declare_a_diode_mux() {
        for profile in BoardVersionProfile::ALL.iter() {
            let declared = profile.model.tmp451_diode_mux().is_some();
            assert_eq!(
                declared,
                MUXED.contains(&profile.model),
                "{:?}: diode-mux declaration disagrees with the known set. A new \
                 muxed board must be added to MUXED *and* have its channel map \
                 asserted below — an undeclared mux silently misattributes \
                 every die reading it produces.",
                profile.model
            );
        }
    }

    /// The whole point of the declaration: channel -> ASIC must be a bijection.
    ///
    /// A gap invents a chip with no sensor; an overlap reports one die's
    /// temperature for two chips, so a genuinely hot ASIC can be masked by a
    /// cool neighbour that shares its (mis)mapped channel.
    #[test]
    fn every_asic_is_covered_by_exactly_one_mux_channel() {
        for model in MUXED {
            let mux = model.tmp451_diode_mux().expect("in MUXED");
            let asic_count = BoardConfig::for_model(model).asic_count;

            let mut covered = vec![0u32; asic_count as usize];
            for sensor in mux.sensors {
                for ch in 0..sensor.channels {
                    let asic = sensor.first_asic + ch;
                    assert!(
                        (asic as u8) < asic_count,
                        "{model:?}: sensor 0x{:02X} channel {ch} maps to ASIC \
                         {asic}, past the board's {asic_count} chips",
                        sensor.addr
                    );
                    covered[asic as usize] += 1;
                }
            }
            for (asic, hits) in covered.iter().enumerate() {
                assert_eq!(
                    *hits, 1,
                    "{model:?}: ASIC {asic} is read by {hits} mux channels, \
                     want exactly 1 (0 = a chip with no die sensor; >1 = two \
                     chips sharing one reading, so one can hide the other)"
                );
            }
        }
    }

    /// Two sensors sharing one pair of select lines must be at DIFFERENT
    /// addresses, or "select channel 2, read both" reads the same die twice and
    /// the board believes it covered 8 chips having measured 4.
    #[test]
    fn sensors_sharing_select_lines_have_distinct_addresses() {
        for model in MUXED {
            let mux = model.tmp451_diode_mux().expect("in MUXED");
            for (i, a) in mux.sensors.iter().enumerate() {
                assert!(
                    crate::tmp451_convert::is_plausible_address(a.addr),
                    "{model:?}: 0x{:02X} is not a valid TMP451 address",
                    a.addr
                );
                assert!(a.channels >= 1, "{model:?}: a sensor with no channels");
                assert!(
                    a.channels <= crate::tmp451_convert::MAX_MUX_CHANNEL + 1,
                    "{model:?}: {} channels, the part selects at most {}",
                    a.channels,
                    crate::tmp451_convert::MAX_MUX_CHANNEL + 1
                );
                for b in mux.sensors.iter().skip(i + 1) {
                    assert_ne!(
                        a.addr, b.addr,
                        "{model:?}: two sensors both at 0x{:02X} behind one \
                         select pair — the second read returns the first die",
                        a.addr
                    );
                }
            }
        }
    }

    /// A0 and A1 must be two distinct, real lines. Collapsing them would make
    /// channels 1 and 2 unreachable and silently alias 0 and 3.
    #[test]
    fn select_lines_are_distinct_and_real() {
        for model in MUXED {
            let mux = model.tmp451_diode_mux().expect("in MUXED");
            match mux.select {
                Tmp451SelectLines::Gpio { a0, a1 } => {
                    assert!(a0 >= 0 && a1 >= 0, "{model:?}: -1 is the unwired sentinel");
                    assert_ne!(a0, a1, "{model:?}: A0 and A1 collapsed onto one GPIO");
                }
                Tmp451SelectLines::Expander { addr, a0, a1 } => {
                    assert_ne!(a0, a1, "{model:?}: A0 and A1 collapsed onto one pin");
                    assert_eq!(addr, 0x43, "{model:?}: FXL6408 address");
                }
            }
        }
    }

    /// Per-board calibration, never a shared default.
    ///
    /// Upstream's correction is ~27 °C DOWNWARD at operating temperature. On a
    /// board that does not need it that under-reports the die by tens of
    /// degrees — the exact direction that cooks a chip. So each row must carry
    /// a calibration that VALIDATES, and Q1373's distinct constants must not
    /// collapse into its Q1370 sibling's.
    #[test]
    fn calibration_is_declared_per_board_and_validates() {
        for model in MUXED {
            let mux = model.tmp451_diode_mux().expect("in MUXED");
            assert!(
                mux.calibration.validate().is_ok(),
                "{model:?}: declared calibration is out of bounds"
            );
        }
        let q1370 = BitAxeModel::Q1370.tmp451_diode_mux().unwrap().calibration;
        let q1373 = BitAxeModel::Q1373.tmp451_diode_mux().unwrap().calibration;
        assert_ne!(
            q1370, q1373,
            "Q1373 is the ONE board upstream gives its own TMP451 calibration \
             (1.06 / -25.4); collapsing it into the Q1370 default misreads its \
             BM1373 dies"
        );
    }

    /// The mux is an enrichment, so a muxed board still declares the sensor it
    /// actually always has. Complements
    /// `no_shipping_row_declares_the_tmp451_variant_yet` from the other side:
    /// that one forbids the claim globally, this one shows the muxed boards in
    /// particular keep a real fallback sensor.
    #[test]
    fn a_muxed_board_still_declares_its_own_always_present_sensor() {
        for model in MUXED {
            let cfg = BoardConfig::for_model(model);
            assert_ne!(
                cfg.temp_sensor,
                TempSensorKind::Tmp451,
                "{model:?}: the mux is fitted only to newer revisions, so it can \
                 never be the declared sensor"
            );
            assert_ne!(
                cfg.temp_sensor,
                TempSensorKind::None,
                "{model:?}: declares a diode mux but no guaranteed sensor — if \
                 the mux turns out to be unpopulated the board would have no \
                 thermal source at all"
            );
        }
    }
}

/// The ASIC LDO bank — the second supply the multi-phase Nerd line needs.
#[cfg(test)]
mod asic_ldo_enable {
    use super::*;

    /// The exact set of boards that carry an LDO enable, and the pin.
    ///
    /// Pinned as a list rather than derived, because the failure mode of
    /// getting this wrong is asymmetric. A board wrongly INCLUDED drives GPIO13
    /// on hardware where that pin is something else; a board wrongly EXCLUDED
    /// boots with a configured core rail and a chain that never answers. Both
    /// are silent, so neither can be caught by "it compiles".
    #[test]
    fn only_the_multi_phase_nerd_line_declares_an_ldo() {
        // Upstream defines an LDO enable in exactly two files, and they use two
        // different transports: `nerdqaxeplus.cpp` drives GPIO13, `q1370.cpp`
        // writes expander pin 2. Both are the same rail at the same point in
        // the sequence — which is why `LdoEnable` carries the transport rather
        // than the bring-up branching on the board.
        let on_gpio13 = [
            BitAxeModel::NerdQaxePlus,
            BitAxeModel::NerdQaxePP,
            BitAxeModel::NerdOctaxePlus,
            BitAxeModel::NerdOctaxeGamma,
            BitAxeModel::NerdQX,
            BitAxeModel::NerdHaxeGamma,
            BitAxeModel::NerdEko,
        ];
        for profile in BoardVersionProfile::ALL {
            let model = BoardConfig::for_profile(&profile).model;
            let declared = model.asic_ldo_enable();
            if on_gpio13.contains(&model) {
                assert_eq!(
                    declared,
                    Some(LdoEnable::Gpio { pin: 13 }),
                    "{model:?} inherits NerdQaxePlus::LDO_EN_PIN (GPIO13) upstream and must \
                     declare it — without the LDO its dies have no IO rail and the chain \
                     stays silent on a perfectly configured core rail"
                );
            } else if model.is_q_series() {
                assert_eq!(
                    declared,
                    Some(LdoEnable::Expander {
                        addr: crate::fxl6408_convert::ADDR,
                        pin: crate::fxl6408_convert::q_series::LDO_ENABLE,
                    }),
                    "{model:?}: Q1370B::LDO_enable() writes expander pin 2 at 0x43, not an \
                     ESP GPIO. Declaring GPIO13 here would drive a pin this board does not \
                     use for that."
                );
            } else {
                assert_eq!(
                    declared, None,
                    "{model:?} must NOT declare an LDO: a repo-wide grep for LDO_EN_PIN / \
                     LDO_enable / LDO_disable upstream returns only nerdqaxeplus.cpp and \
                     q1370.cpp, so claiming one here drives an uncharacterized net high"
                );
            }
        }
    }

    /// NerdNOS, NerdAxe and NerdAxe-gamma are `is_nerd()` and have NO LDO.
    ///
    /// Stated separately because `is_nerd()` is the obvious predicate to reach
    /// for, and it is wrong here by exactly these three boards. The equivalent
    /// over-grouping in `buck_enable_wiring` asserted active-HIGH for NerdAxe,
    /// whose GPIO10 is inverted.
    #[test]
    fn the_single_asic_nerd_boards_are_not_swept_in_by_is_nerd() {
        for model in [
            BitAxeModel::NerdNOS,
            BitAxeModel::NerdAxe,
            BitAxeModel::NerdAxeGamma,
        ] {
            assert!(
                model.is_nerd(),
                "{model:?} must still be is_nerd() — this test is about is_nerd() being the \
                 WRONG discriminator, so it is vacuous if the predicate changes"
            );
            assert_eq!(
                model.asic_ldo_enable(),
                None,
                "{model:?} is a separate upstream class with its own initBoard and no LDO"
            );
        }
    }

    /// The declaration reaches the normalized config the GPIO binder reads.
    ///
    /// `asic_ldo_enable()` is a fact about the model; `ldo_enable_pin` is what
    /// the binder matches on. A declaration that never normalizes is a
    /// capability with no consumer — the failure this codebase has now hit
    /// three times (`RailBringup`, `tps5364x_convert`, `tps5364x`).
    #[test]
    fn the_declaration_normalizes_into_the_pin_the_binder_matches_on() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            let expected = match cfg.model.asic_ldo_enable() {
                Some(LdoEnable::Gpio { pin }) => pin,
                // An expander LDO must NOT surface as an ESP pin — there is no
                // peripheral to bind, and a number here would enter the GPIO
                // binder's match key and send the board to `pins => panic!`.
                Some(LdoEnable::Expander { .. }) | None => -1,
            };
            assert_eq!(
                cfg.ldo_enable_pin,
                expected,
                "{:?} (board version {}): declared LDO {:?} but normalized to pin {}",
                cfg.model,
                profile.board_version,
                cfg.model.asic_ldo_enable(),
                cfg.ldo_enable_pin
            );
        }
    }

    /// GPIO13 collides with nothing else this board would bind.
    ///
    /// The GPIO binder is a `match` on RUNTIME values, so every arm compiles
    /// into every image and a pin bound in one arm is moved in all of them.
    /// That is how a `led_pin: 9` row broke `--features lora` on every board
    /// for two days. This checks the same class of collision within the config.
    #[test]
    fn no_board_uses_gpio13_for_anything_else() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            let model = cfg.model;
            for (name, pin) in [
                ("uart_tx", cfg.uart_tx_pin),
                ("uart_rx", cfg.uart_rx_pin),
                ("i2c_sda", cfg.i2c_sda_pin),
                ("i2c_scl", cfg.i2c_scl_pin),
                ("plug_sense", cfg.plug_sense_pin),
                ("fan_pwm", cfg.fan_pwm_pin),
                ("fan_tach", cfg.fan_tach_pin),
                ("led", cfg.led_pin),
                ("asic_reset", cfg.asic_reset_pin),
                ("buck_enable", cfg.buck_enable_pin),
            ] {
                assert_ne!(
                    pin, 13,
                    "{model:?}: {name} is GPIO13, which is the ASIC LDO enable — binding \
                     both would move the same peripheral twice"
                );
            }
        }
    }

    /// Every board that carries an LDO also carries the rail it feeds.
    ///
    /// An LDO with no core rail beneath it is a half-powered chain. Both
    /// supplies come from the same upstream class, so a row that acquires one
    /// without the other is a transcription error, not a topology.
    #[test]
    fn an_ldo_board_always_has_a_tps5364x_core_rail() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            let model = cfg.model;
            if model.asic_ldo_enable().is_none() {
                continue;
            }
            assert_eq!(
                cfg.power_controller,
                PowerControllerKind::Tps5364x,
                "{model:?} declares an ASIC LDO but not the TPS5364x core rail it sits on"
            );
            // The core rail must have an actuator too — by whichever transport.
            // An LDO up with no way to raise (or cut) the core rail beneath it
            // is a half-powered chain, and the LDO cannot hash on its own.
            assert!(
                cfg.buck_enable_pin >= 0 || cfg.expander_rail_enable.is_some(),
                "{model:?} declares an ASIC LDO but has no core-rail enable at all — \
                 neither an ESP GPIO nor an expander pin"
            );
            // And the two rails must live on the same transport. A board whose
            // LDO is an expander pin while its core enable is an ESP GPIO (or
            // vice versa) is a transcription error: upstream drives both from
            // the same place on every board in the corpus.
            match cfg.model.asic_ldo_enable() {
                Some(LdoEnable::Gpio { .. }) => assert!(
                    cfg.buck_enable_pin >= 0 && cfg.expander_rail_enable.is_none(),
                    "{model:?}: GPIO LDO but the core rail is not on a GPIO"
                ),
                Some(LdoEnable::Expander { addr, .. }) => {
                    let rail = cfg
                        .expander_rail_enable
                        .expect("expander LDO implies an expander core rail");
                    assert_eq!(
                        rail.addr, addr,
                        "{model:?}: LDO and core rail are on DIFFERENT expanders"
                    );
                }
                None => unreachable!("filtered above"),
            }
        }
    }
}

/// The Q-series rail: an actuator that is neither a GPIO nor the regulator.
#[cfg(test)]
mod expander_rail {
    use super::*;

    /// Both Q-series boards classify `ExpanderGpio`, carrying the real address.
    ///
    /// The bug this replaces was not a missing pin — it was a classifier that
    /// could see the absent GPIO and not the present expander, folded the two
    /// into `RegulatorOnly`, and then correctly refused the board because its
    /// TPS5364x cannot cut its own output. Every step was sound; the input was
    /// incomplete.
    #[test]
    fn the_q_series_rail_is_an_expander_pin_not_an_absent_actuator() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            if !cfg.model.is_q_series() {
                continue;
            }
            assert_eq!(
                cfg.rail_bringup(),
                RailBringup::ExpanderGpio {
                    addr: crate::fxl6408_convert::ADDR,
                    pin: crate::fxl6408_convert::q_series::VREG_ENABLE,
                },
                "{:?}: Q1370B::VREG_enable() writes expander pin 1 at 0x43",
                cfg.model
            );
            assert_eq!(
                cfg.buck_enable_pin, -1,
                "{:?}: the ESP GPIO binder must still claim nothing, and \
                 PANIC_BUCK_GPIO must stay disarmed",
                cfg.model
            );
        }
    }

    /// An expander board keeps the GPIO tuple it already had.
    ///
    /// `ldo_enable_pin` stays `-1` because an expander LDO is not an ESP pin.
    /// If it leaked a number, the tuple would leave `SUPPORTED` and the board
    /// would reach `pins => panic!` — `panic = abort` — a boot loop. This is
    /// the reason `asic_ldo_enable()` carries a transport instead of a bare pin.
    #[test]
    fn an_expander_board_does_not_enter_the_gpio_binder() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            if cfg.expander_rail_enable.is_none() {
                continue;
            }
            assert_eq!(
                (
                    cfg.asic_reset_pin,
                    cfg.buck_enable_pin,
                    cfg.led_pin,
                    cfg.ldo_enable_pin
                ),
                (1, -1, 4, -1),
                "{:?}: an expander board must keep an EXISTING binder tuple",
                cfg.model
            );
        }
    }

    /// Only the Q-series has an expander rail, and it is the only 0x43 claim.
    ///
    /// Pinned so a future row cannot acquire an expander actuator by inheriting
    /// `..common` — the same bulk-inheritance trap that once shipped three
    /// wrong pins by verifying only the panic-hook field.
    #[test]
    fn no_other_board_claims_an_expander_rail() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            match cfg.expander_rail_enable {
                Some(e) => {
                    assert!(
                        cfg.model.is_q_series(),
                        "{:?} claims an expander rail but is not Q-series",
                        cfg.model
                    );
                    assert_eq!(e.addr, crate::fxl6408_convert::ADDR);
                    assert!(e.pin <= crate::fxl6408_convert::MAX_PIN);
                }
                None => assert!(
                    !cfg.model.is_q_series(),
                    "{:?} is Q-series but declares no expander rail",
                    cfg.model
                ),
            }
        }
    }

    /// The Q-series inherits the TPS5364x enable ORDER with no new code.
    ///
    /// `rail_enable_order()` keys on the declared regulator, not on a board
    /// list, so these boards get `RegulatorBeforeGpio` for free — and they need
    /// it for the same reason the Nerd line does: EN asserted before
    /// `VOUT_COMMAND` energizes the stage at whatever the part's NVM holds.
    #[test]
    fn the_expander_enable_is_deferred_like_every_other_tps5364x_rail() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            if !cfg.model.is_q_series() {
                continue;
            }
            assert_eq!(
                cfg.rail_enable_order(),
                RailEnableOrder::RegulatorBeforeGpio,
                "{:?}: an expander EN is still an EN — it must be asserted after \
                 the regulator is configured",
                cfg.model
            );
        }
    }
}

/// How each board's ASIC rail can be raised and cut — and which boards
/// currently cannot be energized at all.
///
/// Kept as its own module because this cuts across every family: the
/// affected set spans Hammer, Q-series, Nerd and BitAxe-class boards.
#[cfg(test)]
mod rail_bringup_classification {
    use super::*;

    /// The boards with no discrete enable GPIO. NOT the boards that cannot mine.
    ///
    /// Every model listed here declares [`BuckEnableWiring::NotAGpio`], which
    /// normalizes `buck_enable_pin` to `-1`, which makes the GPIO binder build a
    /// controller with `buck_enable: None`, which makes `enable_buck` return
    /// `Err` in both directions. What that `Err` MEANS is the whole point of
    /// [`RailBringup`], and `main.rs` now dispatches on the classification
    /// instead of on the bare error:
    ///
    /// - `RegulatorOnly` (NerdAxe-gamma, BitForge Nano, BitAxe Naja) skips the
    ///   GPIO step entirely; `PowerManager::set_voltage` raises the rail with
    ///   VOUT_COMMAND + OPERATION_ON and `disable` cuts it. These boards MINE.
    /// - `ExpanderGpio` (Q1370, Q1373) has an enable that is neither an ESP
    ///   GPIO nor the regulator: FXL6408 pin 1 at 0x43. These were classified
    ///   `RegulatorOnly` and then refused, because their TPS5364x ignores
    ///   `OPERATION` and so cannot cut its own output — a correct refusal drawn
    ///   from an incomplete picture, since the expander can do both. They mine
    ///   once the transport ships, and the panic hook cuts them with one
    ///   bounded write of 0x00 to OUTPUT_STATE (reset + VREG + LDO all low).
    /// - `NoActuator` (the seven Hammer SKUs) is still refused, now for the
    ///   accurate reason: nothing in firmware can bring that rail DOWN. They are
    ///   independently refused anyway by
    ///   `hammer_boards_refuse_mining_until_drivers_exist` (`temp_sensor: None`
    ///   makes `validate()` fail), so the rail block is belt-and-braces there.
    ///
    /// The trade-off that once justified deferring this — "letting these boards
    /// energize buys mining at the cost of a panic-time rail cut" — turned out
    /// not to be a trade at all. The panic hook already performs bounded raw
    /// I2C writes for fan cooling, so XPSAFE-5 gives a `RegulatorOnly` board a
    /// bounded `OPERATION_OFF` by the same mechanism. Weaker than a GPIO cut
    /// (I2C can time out; a register write cannot), which is why these boards
    /// are EXPERIMENTAL — but no longer absent.
    ///
    /// If a board LEAVES this list it must be because its wiring changed, never
    /// because the assertion became inconvenient.
    #[test]
    fn rail_bringup_boards_without_a_discrete_enable_gpio() {
        let mut blocked: Vec<BitAxeModel> = Vec::new();
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            if cfg.rail_bringup() != RailBringup::EnableGpio && !blocked.contains(&cfg.model) {
                blocked.push(cfg.model);
            }
        }

        // Every Hammer SKU, both Q-series boards, NerdAxe-gamma, the BitForge
        // Nano and the BitAxe Naja. Sorted by family, not by enum order, so a
        // new registration lands somewhere obvious.
        for expected in [
            BitAxeModel::HammerBc01,
            BitAxeModel::HammerBc01Pro,
            BitAxeModel::HammerBc02,
            BitAxeModel::HammerBc04,
            BitAxeModel::HammerDc02,
            BitAxeModel::HammerDc04,
            BitAxeModel::HammerDc06,
            BitAxeModel::Q1370,
            BitAxeModel::Q1373,
            BitAxeModel::NerdAxeGamma,
            BitAxeModel::BitForgeNano,
            BitAxeModel::BitaxeNaja,
        ] {
            assert!(
                blocked.contains(&expected),
                "{expected:?} was expected to have no enable GPIO; if its rail is now \
                 commandable, update this list and the `NotAGpio` doc together"
            );
        }
    }

    /// The classification must agree with the pin the panic hook would drive.
    ///
    /// `EnableGpio` promises the hook a real pin; the other two promise it the
    /// `-1` sentinel, which is what keeps the hook a no-op instead of driving
    /// whatever number happened to be inherited onto an unrelated net. XPSAFE-5
    /// adds a SECOND hook actuator for `RegulatorOnly` boards, but it is armed
    /// from a probed I2C address, never from this pin — so this invariant is
    /// unchanged by it.
    #[test]
    fn rail_bringup_agrees_with_the_pin_the_panic_hook_would_drive() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            match cfg.rail_bringup() {
                RailBringup::EnableGpio => assert!(
                    cfg.buck_enable_pin >= 0,
                    "{:?} classified EnableGpio without a pin for the hook to drive",
                    cfg.model
                ),
                // Every other variant MUST carry the -1 sentinel, because that
                // is what makes the hook a no-op instead of driving whatever
                // number happened to be inherited onto an unrelated net.
                //
                // `ExpanderGpio` is included deliberately: it HAS an actuator,
                // but not one the GPIO cut can reach. Its panic path is the
                // separate expander arm, driven from a declared I2C address —
                // so exposing an ESP pin here would be a wrong write, not a
                // stronger cut.
                RailBringup::ExpanderGpio { .. }
                | RailBringup::RegulatorOnly
                | RailBringup::NoActuator => assert_eq!(
                    cfg.buck_enable_pin, -1,
                    "{:?} has no usable ESP enable pin yet exposes one to the panic hook",
                    cfg.model
                ),
            }
        }
    }

    /// The sharpest case: no enable pin AND no commandable voltage.
    #[test]
    fn hammer_boards_have_no_rail_actuator_at_all() {
        // `has_voltage_control()` excludes the whole Hammer line, so these
        // boards are not merely missing a GPIO — there is nothing in firmware
        // that can raise or lower their rail. That distinction is exactly why
        // `RailBringup` has three variants and not two: treating a Hammer like
        // a BitForge would claim a PMBus cut path that does not exist here.
        for model in [
            BitAxeModel::HammerBc01,
            BitAxeModel::HammerBc02,
            BitAxeModel::HammerBc04,
            BitAxeModel::HammerDc02,
            BitAxeModel::HammerDc04,
            BitAxeModel::HammerDc06,
        ] {
            let cfg = BoardConfig::for_model(model);
            assert_eq!(
                cfg.rail_bringup(),
                RailBringup::NoActuator,
                "{model:?} must classify as NoActuator"
            );
        }

        // And the contrast that makes the variant meaningful: same missing
        // pin, but a TPS546 that CAN be commanded.
        assert_eq!(
            BoardConfig::for_model(BitAxeModel::BitForgeNano).rail_bringup(),
            RailBringup::RegulatorOnly
        );
        assert_eq!(
            BoardConfig::for_model(BitAxeModel::BitaxeNaja).rail_bringup(),
            RailBringup::RegulatorOnly
        );

        // A stock BitAxe is the control: it really does have an enable GPIO.
        assert_eq!(
            BoardConfig::for_model(BitAxeModel::Gamma).rail_bringup(),
            RailBringup::EnableGpio
        );
    }

    /// The three boards that the `rail_bringup()` dispatch actually unblocks.
    ///
    /// Each was already fully registered, `validate()`-clean and CI-checked, and
    /// blocked by nothing except `enable_buck`'s absent-pin `Err` being read as
    /// a failure. This pins every property `main.rs` relies on to let them mine,
    /// so a row edit that quietly removes one re-breaks the board LOUDLY here
    /// instead of silently at boot on hardware nobody has.
    #[test]
    fn boards_unblocked_by_the_rail_bringup_dispatch_can_actually_be_energized() {
        for model in [
            BitAxeModel::NerdAxeGamma,
            BitAxeModel::BitForgeNano,
            BitAxeModel::BitaxeNaja,
        ] {
            let cfg = BoardConfig::for_model(model);
            // No enable GPIO — this is why they were blocked.
            assert_eq!(cfg.buck_enable_pin, -1, "{model:?}");
            // ...but the rail IS commandable, which is why blocking was wrong.
            assert_eq!(
                cfg.rail_bringup(),
                RailBringup::RegulatorOnly,
                "{model:?} must be RegulatorOnly: NoActuator is still refused, and \
                 EnableGpio would send main.rs to drive a pin that does not exist"
            );
            // `main.rs` refuses a RegulatorOnly board whose probed regulator is
            // not a TPS546, because a DS4432U cannot cut a rail over I2C and
            // there is no buck GPIO to fall back on. The row must declare the
            // part that check expects to find.
            assert_eq!(
                cfg.power_controller,
                PowerControllerKind::Tps546,
                "{model:?}: only a TPS546 can both raise and cut this rail"
            );
            // And nothing else may be blocking them, or the claim is hollow.
            assert_eq!(cfg.validate(), Ok(()), "{model:?}");
            assert!(
                cfg.has_trusted_thermal_source_configured(),
                "{model:?}: energizing without a trusted die source is not an upgrade"
            );
        }
    }

    /// Every board declaring a TPS5364x must have a characterized envelope.
    ///
    /// `PowerManager` refuses to configure the power stage when this returns
    /// `None`, so a row that declares the part without an envelope is a board
    /// that cannot mine. Guessing a phase count or a current-sense full scale on
    /// a 100-300 W stage is the one thing that must not happen, so the gap has
    /// to fail here, in CI, and not on a bench nobody has.
    #[test]
    fn every_tps5364x_board_has_a_characterized_envelope() {
        use crate::tps5364x_convert::Variant;
        let mut checked = 0;
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            if cfg.power_controller != PowerControllerKind::Tps5364x {
                continue;
            }
            let envelope = [Variant::Tps53647, Variant::Tps53667]
                .into_iter()
                .filter_map(|v| cfg.model.tps5364x_envelope(v))
                .next();
            assert!(
                envelope.is_some(),
                "{:?} declares a TPS5364x but has no envelope for either part — \
                 PowerManager will refuse to configure it and the board cannot mine",
                cfg.model
            );
            checked += 1;
        }
        assert!(checked > 0, "no TPS5364x rows found — the search is broken");
    }

    /// Every envelope must survive the pure core's own validators.
    ///
    /// This is the test that catches the upstream `ifault > imax` rows: an
    /// over-current threshold above the current-sense full scale is a protection
    /// that can never assert, and `check_iout_fault_limit` refuses it. Copying
    /// the vendor number would ship a trip that is armed on paper and inert in
    /// silicon.
    #[test]
    fn every_tps5364x_envelope_passes_the_pure_validators() {
        use crate::tps5364x_convert::{self as conv, Variant};
        for model in [
            BitAxeModel::NerdQaxePlus,
            BitAxeModel::NerdQaxePP,
            BitAxeModel::NerdOctaxePlus,
            BitAxeModel::NerdOctaxeGamma,
            BitAxeModel::NerdQX,
            BitAxeModel::NerdHaxeGamma,
            BitAxeModel::NerdEko,
            BitAxeModel::Q1370,
            BitAxeModel::Q1373,
        ] {
            for variant in [Variant::Tps53647, Variant::Tps53667] {
                let Some(env) = model.tps5364x_envelope(variant) else {
                    continue;
                };
                assert!(
                    conv::phase_register(variant, env.num_phases).is_ok(),
                    "{model:?}/{variant:?}: {} phases exceeds what the part supports",
                    env.num_phases
                );
                assert!(
                    conv::imax_register(env.imax_a).is_ok(),
                    "{model:?}/{variant:?}: imax {} A does not fit MFR_SPECIFIC_10",
                    env.imax_a
                );
                assert!(
                    conv::check_iout_fault_limit(env.imax_a, env.ifault_a).is_ok(),
                    "{model:?}/{variant:?}: ifault {} A exceeds the {} A sense full \
                     scale — that trip can never assert",
                    env.ifault_a,
                    env.imax_a
                );
                assert!(
                    !env.phase_shedding,
                    "{model:?}: upstream never enables phase shedding"
                );
            }
        }
    }

    /// A TPS5364x must never be energized before it has been configured.
    ///
    /// Its `ON_OFF_CONFIG` leaves the OPERATION command inert, so EN alone gates
    /// the stage: assert EN first and the rail comes up at whatever `VOUT` the
    /// part's NVM holds. Every board carrying one must declare the deferred
    /// order, and no board carrying anything else may — deferring on a TPS546
    /// would delay a rail that is already held off by `OPERATION_OFF`, for no
    /// benefit and one more ordering to reason about.
    #[test]
    fn only_tps5364x_boards_defer_their_enable_gpio() {
        let mut deferred = 0;
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            let expected = if cfg.power_controller == PowerControllerKind::Tps5364x {
                deferred += 1;
                RailEnableOrder::RegulatorBeforeGpio
            } else {
                RailEnableOrder::GpioBeforeRegulator
            };
            assert_eq!(
                cfg.rail_enable_order(),
                expected,
                "{:?} ({:?}) has the wrong rail-enable order",
                cfg.model,
                cfg.power_controller
            );
        }
        assert!(
            deferred > 0,
            "no TPS5364x rows found — the search is broken"
        );
    }

    /// The OCTAXE-γ is the reason the envelope is variant-aware.
    #[test]
    fn octaxe_gamma_has_a_distinct_envelope_per_part() {
        use crate::tps5364x_convert::Variant;
        let older = BitAxeModel::NerdOctaxeGamma
            .tps5364x_envelope(Variant::Tps53647)
            .expect("rev<=3.3 carries a TPS53647");
        let newer = BitAxeModel::NerdOctaxeGamma
            .tps5364x_envelope(Variant::Tps53667)
            .expect("rev3.4 carries a TPS53667");
        assert_eq!((older.num_phases, older.imax_a), (4, 180));
        assert_eq!((newer.num_phases, newer.imax_a), (6, 240));
        // The 6-phase profile must be REFUSED on the 4-phase part rather than
        // half-applied — that is the whole point of detecting before configuring.
        assert!(
            crate::tps5364x_convert::phase_register(Variant::Tps53647, newer.num_phases).is_err(),
            "a 6-phase profile must not be accepted by a TPS53647"
        );
    }

    /// A rail that cannot be commanded OFF must never be commanded ON.
    ///
    /// This is the invariant the `NoActuator` arm enforces in `main.rs`, stated
    /// where it can be host-tested: the variant is reachable only when the board
    /// has neither an enable pin nor voltage control, so there is no sequence of
    /// firmware actions that lowers the rail.
    #[test]
    fn no_actuator_means_no_way_down_so_mining_stays_refused() {
        for profile in BoardVersionProfile::ALL {
            let cfg = BoardConfig::for_profile(&profile);
            if cfg.rail_bringup() != RailBringup::NoActuator {
                continue;
            }
            assert_eq!(cfg.buck_enable_pin, -1, "{:?}", cfg.model);
            assert!(
                !cfg.model.has_voltage_control(),
                "{:?}: classified NoActuator while its voltage IS commandable — \
                 it should be RegulatorOnly and allowed to mine",
                cfg.model
            );
            assert_eq!(
                cfg.validate(),
                Err("mining-capable board requires a trusted temperature source"),
                "{:?}: every NoActuator board must ALSO be refused independently \
                 of the rail path, so the refusal does not rest on one check",
                cfg.model
            );
        }
    }
}

/// BitAxe Naja — bitaxeorg's dual-BM1373 prototype (board row "4200").
///
/// Schematic-only evidence, so these tests pin the facts read off
///  and the BM1373
/// envelope taken from the vendor's own Q1373 board file. There is no vendor
/// firmware for this board to check against.
#[cfg(test)]
mod bitaxe_naja {
    use super::*;

    #[test]
    fn the_row_records_the_silicon_we_drive_not_the_silkscreen() {
        let p = BoardVersionProfile::find("4200").expect("4200 registered");
        assert_eq!(p.model, BitAxeModel::BitaxeNaja);
        // The board says "BM1340". That is a silkscreen name: the symbol is a
        // byte-for-byte clone of BM1370_mode1 whose default Value property is
        // still literally "BM1370_mode1", and the real driver is
        // `class BM1373 : public BM1370`.
        assert_eq!(p.asic_model, "BM1373");
        // And the silicon answers 0x1372 on the wire — not 0x1373, not 0x1340.
        assert_eq!(BitAxeModel::BitaxeNaja.expected_chip_id(), 0x1372);
        // Same silicon as the Q1373 board we already ship.
        assert_eq!(
            BitAxeModel::BitaxeNaja.expected_chip_id(),
            BitAxeModel::Q1373.expected_chip_id()
        );
        assert_eq!(BitAxeModel::BitaxeNaja.asic_count(), 2);
        assert_eq!(BitAxeModel::BitaxeNaja.support_status(), "experimental");
    }

    /// The safety-critical one. Both dies hang across the same rail.
    #[test]
    fn the_two_dies_are_one_voltage_domain_not_two() {
        let cfg = BoardConfig::for_model(BitAxeModel::BitaxeNaja);
        assert_eq!(cfg.asic_count, 2);
        // A1 pad 31 (VDD, 34 pads) and A2 pad 31 are BOTH on /Vcore; both VSS
        // pads are on GND; L1 and L2 both land on /Vcore. Parallel, one domain.
        // A 2 here would command double onto parallel BM1373 dies.
        assert_eq!(
            cfg.voltage_domains, 1,
            "Naja's dies are in PARALLEL — raising this commands double onto them"
        );
    }

    /// The envelope must come from the ASIC, not from the board it resembles.
    #[test]
    fn the_envelope_is_bm1373s_and_not_the_gamma_turbos() {
        let naja = BoardConfig::for_model(BitAxeModel::BitaxeNaja);
        // Vendor numbers for this silicon (q1373.cpp).
        assert_eq!(naja.default_frequency, 350.0);
        assert_eq!(naja.default_voltage_mv, 1010);
        assert_eq!(naja.min_voltage_mv, 900);
        assert_eq!(naja.max_voltage_mv, 1200);

        // Naja is structurally a Gamma Turbo: 2 dies, one domain, EMC2103 with
        // the diodes crossed the same way. Copying that row is the obvious
        // mistake, and it is the one the Q1373 arm warns about. Every voltage
        // bound must be strictly below the GT's.
        let gt = BoardConfig::for_model(BitAxeModel::GammaTurbo);
        assert_eq!(gt.asic_count, naja.asic_count);
        assert_eq!(gt.voltage_domains, naja.voltage_domains);
        assert!(
            naja.default_voltage_mv < gt.default_voltage_mv
                && naja.max_voltage_mv < gt.max_voltage_mv
                && naja.min_voltage_mv < gt.min_voltage_mv,
            "Naja inherited a BM1370 envelope: {naja:?} vs GT {gt:?}"
        );

        // The ASIC sets the envelope, so it must agree with our other BM1373
        // board rather than with any BM1370 board.
        let q = BoardConfig::for_model(BitAxeModel::Q1373);
        assert_eq!(naja.default_frequency, q.default_frequency);
        assert_eq!(naja.default_voltage_mv, q.default_voltage_mv);
        assert_eq!(naja.min_voltage_mv, q.min_voltage_mv);
        assert_eq!(naja.max_voltage_mv, q.max_voltage_mv);
    }

    /// One EMC2103-2 reaches both dies natively — no mux, unlike the BitForge.
    #[test]
    fn both_dies_are_read_through_one_unmuxed_emc2103() {
        let p = BoardVersionProfile::find("4200").unwrap();
        assert_eq!(p.fan_controller, FanControllerKind::Emc2103);
        assert_eq!(p.temp_sensor, TempSensorKind::Emc2103);
        // The EMC2103-2 has two external channels, so the fixed-address
        // collision that forced a PCA9544A onto the BitForge does not exist
        // here. Declaring a mux would be a fabricated hardware claim.
        assert_eq!(BitAxeModel::BitaxeNaja.thermal_i2c_mux(), None);
        // External diodes, not the internal die.
        assert!(!p.emc_internal_temp);
        // R34 ties A1's TEMP1_P to DP2 and R29 ties A2's TEMP2_P to DP1, so
        // chip 1 sits on External2 — the same crossing the GT declares.
        assert!(
            p.temp_flip,
            "A1 is on DP2/External2; without the flip we report A2's junction as A1's"
        );
    }

    /// Ideality is sourced from the vendor's BM1373 calibration, and rounded
    /// in the direction that reports hot rather than cold.
    #[test]
    fn the_diode_calibration_errs_toward_reporting_hot() {
        let p = BoardVersionProfile::find("4200").unwrap();
        // q1373.cpp: set_temp_cal(1.06f, ...) — measured BM1373 ideality.
        // 0x37 = 1.0566 is the nearest tabulated value BELOW 1.06. Assuming a
        // lower ideality than the truth reports temperature slightly HIGH.
        assert_eq!(p.emc_ideality_factor, 0x37);
        assert_eq!(p.emc_beta_compensation, 0x00);
        // The vendor's -25.4 C offset belongs to a TMP451 on a different board
        // with different diode routing. Carrying it here would bias every
        // reading 25 C LOW on a board with no hardware thermal trip.
        assert_eq!(p.temp_offset_c, 0);
    }

    /// Firmware cannot cut this rail, so the panic hook must not think it can.
    #[test]
    fn no_enable_gpio_is_claimed_because_none_is_wired() {
        assert_eq!(
            BitAxeModel::BitaxeNaja.buck_enable_wiring(),
            Some(BuckEnableWiring::NotAGpio)
        );
        let cfg = BoardConfig::for_model(BitAxeModel::BitaxeNaja);
        // The -1 sentinel makes any enable request fail closed rather than
        // driving GPIO10, which on this board goes nowhere at all.
        assert_eq!(cfg.buck_enable_pin, -1);
        // This is the field that reaches the panic hook; a stray `true` here
        // would have it drive a rail-energizing level on some other board's
        // pin number.
        assert!(!cfg.buck_enable_active_low);
        // EN_UVLO is a fixed 12 V divider, so the rail is live whenever the
        // barrel is — plug-sense would be a fiction.
        assert!(!cfg.plug_sense);
    }

    /// With no hardware over-temp response, the fan must be proven.
    #[test]
    fn a_board_with_an_inert_hardware_trip_must_prove_its_fan() {
        let cfg = BoardConfig::for_profile(BoardVersionProfile::find("4200").unwrap());
        // The EMC2103's SYS_SHDN (pad 7) and ALERT (pad 6) are both
        // unconnected on this board, so nothing in hardware acts on an
        // over-temp. The EMC2103 rung of `requires_fan_tach` covers it.
        assert!(
            cfg.requires_fan_tach(),
            "Naja has no hardware thermal backstop; mining on an unproven fan is unsafe"
        );
        assert!(cfg.tach_proof_required());
    }

    #[test]
    fn identity_resolves_from_every_spelling_we_publish() {
        for key in [
            "bitaxenaja",
            "bitaxe_naja",
            "bitaxe naja",
            "bitaxe-naja",
            "naja",
        ] {
            assert_eq!(
                BitAxeModel::from_device_model(key),
                Some(BitAxeModel::BitaxeNaja),
                "{key} must resolve"
            );
        }
        // "nano" belongs to the BitForge and must not have been stolen.
        assert_eq!(
            BitAxeModel::from_device_model("nano"),
            Some(BitAxeModel::BitForgeNano)
        );
        assert_eq!(BitAxeModel::BitaxeNaja.canonical_key(), "bitaxenaja");
        assert_eq!(BitAxeModel::BitaxeNaja.board_target(), "bitaxe-naja");
        assert_eq!(
            BoardVersionProfile::default_for_model(BitAxeModel::BitaxeNaja).board_version,
            "4200"
        );
    }
}
/// `BoardVersionProfile::ALL` completeness -- IMPLEMENTATION_QUEUE rank 2.
///
/// `ALL` is the registry every consumer resolves a board through, but nothing
/// asserted that the registry COVERS the `BitAxeModel` enum. Seven variants have
/// no row of their own and borrow another board's row via
/// [`BoardVersionProfile::default_for_model`]; the existing per-family tests all
/// loop over hardcoded tuple arrays of the models they already know about, so a
/// new variant added with neither a row nor a deliberate borrow was invisible.
///
/// The borrow set is BASELINED, not forgiven: these tests pass today and fail
/// the moment an eighth borrower appears, or a listed borrower quietly gains its
/// own row without the list shrinking.
#[cfg(test)]
mod board_version_profile_completeness {
    use super::*;

    /// Every `BitAxeModel` variant, in declaration order.
    ///
    /// This crate has no derive-based enum iterator, so this array IS the
    /// enumeration -- and it cannot fall behind the enum, because
    /// [`model_slot`] matches exhaustively: adding a variant to `BitAxeModel`
    /// fails to COMPILE until it is added here too.
    const ALL_BITAXE_MODELS: [BitAxeModel; 37] = [
        BitAxeModel::Max,
        BitAxeModel::Ultra,
        BitAxeModel::HexUltra,
        BitAxeModel::Supra,
        BitAxeModel::HexSupra,
        BitAxeModel::Gamma,
        BitAxeModel::GammaDuo,
        BitAxeModel::GammaTurbo,
        BitAxeModel::Touch,
        BitAxeModel::GtTouch,
        BitAxeModel::NerdNOS,
        BitAxeModel::NerdAxe,
        BitAxeModel::NerdAxeGamma,
        BitAxeModel::NerdQaxePlus,
        BitAxeModel::NerdQaxePP,
        BitAxeModel::NerdOctaxePlus,
        BitAxeModel::NerdOctaxeGamma,
        BitAxeModel::NerdQX,
        BitAxeModel::NerdHaxeGamma,
        BitAxeModel::NerdEko,
        BitAxeModel::Q1370,
        BitAxeModel::Q1373,
        BitAxeModel::DcentAxeBm1397,
        BitAxeModel::DcentAxeQuadBm1397,
        BitAxeModel::DcentAxeHexBm1397,
        BitAxeModel::HammerBc01,
        BitAxeModel::HammerBc01Pro,
        BitAxeModel::HammerBc02,
        BitAxeModel::HammerBc04,
        BitAxeModel::HammerDc02,
        BitAxeModel::HammerDc04,
        BitAxeModel::HammerDc06,
        BitAxeModel::LuckyLv06,
        BitAxeModel::LuckyLv07,
        BitAxeModel::LuckyLv08,
        BitAxeModel::BitForgeNano,
        BitAxeModel::BitaxeNaja,
    ];

    /// Exhaustive by construction. Its only job is to make `ALL_BITAXE_MODELS`
    /// impossible to leave incomplete -- do not replace the match with a
    /// wildcard arm, that removes the entire guarantee.
    fn model_slot(model: BitAxeModel) -> usize {
        match model {
            BitAxeModel::Max => 0,
            BitAxeModel::Ultra => 1,
            BitAxeModel::HexUltra => 2,
            BitAxeModel::Supra => 3,
            BitAxeModel::HexSupra => 4,
            BitAxeModel::Gamma => 5,
            BitAxeModel::GammaDuo => 6,
            BitAxeModel::GammaTurbo => 7,
            BitAxeModel::Touch => 8,
            BitAxeModel::GtTouch => 9,
            BitAxeModel::NerdNOS => 10,
            BitAxeModel::NerdAxe => 11,
            BitAxeModel::NerdAxeGamma => 12,
            BitAxeModel::NerdQaxePlus => 13,
            BitAxeModel::NerdQaxePP => 14,
            BitAxeModel::NerdOctaxePlus => 15,
            BitAxeModel::NerdOctaxeGamma => 16,
            BitAxeModel::NerdQX => 17,
            BitAxeModel::NerdHaxeGamma => 18,
            BitAxeModel::NerdEko => 19,
            BitAxeModel::Q1370 => 20,
            BitAxeModel::Q1373 => 21,
            BitAxeModel::DcentAxeBm1397 => 22,
            BitAxeModel::DcentAxeQuadBm1397 => 23,
            BitAxeModel::DcentAxeHexBm1397 => 24,
            BitAxeModel::HammerBc01 => 25,
            BitAxeModel::HammerBc01Pro => 26,
            BitAxeModel::HammerBc02 => 27,
            BitAxeModel::HammerBc04 => 28,
            BitAxeModel::HammerDc02 => 29,
            BitAxeModel::HammerDc04 => 30,
            BitAxeModel::HammerDc06 => 31,
            BitAxeModel::LuckyLv06 => 32,
            BitAxeModel::LuckyLv07 => 33,
            BitAxeModel::LuckyLv08 => 34,
            BitAxeModel::BitForgeNano => 35,
            BitAxeModel::BitaxeNaja => 36,
        }
    }

    /// Models that deliberately have NO `BoardVersionProfile::ALL` row and
    /// borrow another board's row through `default_for_model`.
    ///
    /// `(model, borrowed board_version, why it borrows / what removes it)`.
    ///
    /// Two kinds live here and they are not the same thing:
    ///
    /// * `Touch` / `GtTouch` are PERMANENT by design. They are the same mining
    ///   board plus an orthogonal BAP/LVGL accessory, so borrowing the mining
    ///   board's electrical profile is correct, not a shortcut.
    /// * A GAP entry is a physically different board wearing a BitAxe row as a
    ///   "starting shape" that `for_model` then overrides field by field.
    ///   Canonical `4XXX` rows for them are IMPLEMENTATION_QUEUE rank 41.
    ///
    /// **Rank 41 closed the GAP class entirely.** All five Nerd borrowers now
    /// own canonical rows — `NerdQaxePlus` `4006`, `NerdQaxePP` `4007`,
    /// `NerdOctaxePlus` `4008`, `NerdOctaxeGamma` `4009`, `NerdNOS` `4010` —
    /// each sourced from held primary evidence for that board rather than from
    /// the BitAxe row it used to wear.
    ///
    /// What remains is ONLY the permanent class. **A new GAP entry here is
    /// therefore a regression**, not routine bookkeeping: it means a board was
    /// registered without its own identity. Prefer a row; if you genuinely
    /// cannot source one, say so here in the same detail the closed entries
    /// were, and never invent electrical values to make a row look complete.
    ///
    /// Adding an entry here to silence a failure, without writing both the
    /// reason and what removes it, defeats the point of the test.
    const BORROWED_PROFILE_ALLOWLIST: [(BitAxeModel, &str, &str); 2] = [
        (
            BitAxeModel::Touch,
            "601",
            "PERMANENT: Gamma mining board + orthogonal BAP/LVGL accessory",
        ),
        (
            BitAxeModel::GtTouch,
            "801",
            "PERMANENT: GT-801 mining board + orthogonal BAP/LVGL accessory",
        ),
    ];

    fn models_with_own_row() -> Vec<BitAxeModel> {
        let mut owners: Vec<BitAxeModel> = Vec::new();
        for profile in BoardVersionProfile::ALL {
            if !owners.contains(&profile.model) {
                owners.push(profile.model);
            }
        }
        owners
    }

    fn is_allowlisted_borrower(model: BitAxeModel) -> bool {
        BORROWED_PROFILE_ALLOWLIST
            .iter()
            .any(|(listed, _, _)| *listed == model)
    }

    /// The enumeration cannot silently fall behind the enum.
    #[test]
    fn all_bitaxe_models_is_the_complete_enum_in_declaration_order() {
        for (index, model) in ALL_BITAXE_MODELS.iter().enumerate() {
            assert_eq!(
                model_slot(*model),
                index,
                "{model:?} is duplicated or out of order in ALL_BITAXE_MODELS"
            );
        }
    }

    /// THE GATE. Every variant is either registered or a documented borrower.
    #[test]
    fn every_bitaxe_model_has_a_profile_row_or_an_allowlisted_borrow() {
        let owners = models_with_own_row();
        let mut unaccounted: Vec<BitAxeModel> = Vec::new();
        for model in ALL_BITAXE_MODELS {
            if !owners.contains(&model) && !is_allowlisted_borrower(model) {
                unaccounted.push(model);
            }
        }
        assert!(
            unaccounted.is_empty(),
            "{} BitAxeModel variant(s) have neither a BoardVersionProfile::ALL \
             row nor an entry in BORROWED_PROFILE_ALLOWLIST: {unaccounted:?}. Add \
             a row (preferred), or add an allowlist entry stating WHY it borrows \
             and WHAT removes it.",
            unaccounted.len()
        );
    }

    /// The counts are in the test NAME so they show up in plain CI test output,
    /// where a `println!` from a passing test is swallowed.
    #[test]
    fn exactly_2_of_37_models_borrow_a_row_and_35_own_one() {
        let owners = models_with_own_row();
        println!(
            "BOARD_PROFILE_COVERAGE models={} own_row={} borrowed={} rows={}",
            ALL_BITAXE_MODELS.len(),
            owners.len(),
            BORROWED_PROFILE_ALLOWLIST.len(),
            BoardVersionProfile::ALL.len()
        );
        // Rename this test when the numbers move. That friction is deliberate:
        // it forces the count into the diff instead of letting it drift.
        //
        // 7 -> 2 and 30 -> 35 is queue rank 41: all five Nerd borrowers gained
        // canonical rows `4006`-`4010`. The two that remain are the PERMANENT
        // Touch variants, so the GAP class is now EMPTY and this number should
        // not grow again.
        assert_eq!(ALL_BITAXE_MODELS.len(), 37, "BitAxeModel variants");
        assert_eq!(
            owners.len(),
            35,
            "models owning a BoardVersionProfile::ALL row"
        );
        assert_eq!(BORROWED_PROFILE_ALLOWLIST.len(), 2, "allowlisted borrowers");
        assert_eq!(
            owners.len() + BORROWED_PROFILE_ALLOWLIST.len(),
            ALL_BITAXE_MODELS.len(),
            "every model is accounted for exactly once"
        );
    }

    /// The baseline must SHRINK, never rot. A borrower that has since gained
    /// its own row is a stale allowlist entry, and leaving it in would let the
    /// next genuinely-missing model hide behind it.
    #[test]
    fn no_allowlisted_borrower_has_quietly_gained_its_own_row() {
        let owners = models_with_own_row();
        for (model, borrowed, reason) in BORROWED_PROFILE_ALLOWLIST {
            assert!(
                !owners.contains(&model),
                "{model:?} now HAS its own BoardVersionProfile::ALL row -- delete \
                 its BORROWED_PROFILE_ALLOWLIST entry (borrowed {borrowed}, \
                 recorded reason: {reason})"
            );
        }
    }

    /// Every borrow is real: the row it names exists, `default_for_model`
    /// actually returns it, and the borrowed row belongs to a DIFFERENT model
    /// (a self-borrow would mean the entry belongs in neither list).
    #[test]
    fn every_allowlisted_borrow_resolves_to_the_row_it_claims() {
        for (model, borrowed, _) in BORROWED_PROFILE_ALLOWLIST {
            let profile = BoardVersionProfile::find(borrowed).unwrap_or_else(|| {
                panic!("{model:?} borrows board_version {borrowed}, which does not exist")
            });
            assert_ne!(
                profile.model, model,
                "{model:?} is listed as borrowing {borrowed}, but that row is its own"
            );
            assert_eq!(
                BoardVersionProfile::default_for_model(model).board_version,
                borrowed,
                "{model:?} default_for_model disagrees with the allowlist"
            );
        }
    }

    /// Reverse direction: no row may name a model outside the enumeration.
    /// Cheap today, but it is what keeps `models_with_own_row` trustworthy.
    #[test]
    fn every_profile_row_names_an_enumerated_model() {
        for profile in BoardVersionProfile::ALL {
            assert!(
                ALL_BITAXE_MODELS.contains(&profile.model),
                "board_version {} names {:?}, absent from ALL_BITAXE_MODELS",
                profile.board_version,
                profile.model
            );
        }
    }

    /// A model that owns a row must have `default_for_model` point at one of
    /// ITS OWN rows -- otherwise it is a borrower wearing a row it never uses,
    /// which is exactly the shape the Nerd `4XXX` migration was fixing.
    #[test]
    fn every_owning_model_defaults_to_one_of_its_own_rows() {
        for model in ALL_BITAXE_MODELS {
            if is_allowlisted_borrower(model) {
                continue;
            }
            let default = BoardVersionProfile::default_for_model(model);
            assert_eq!(
                default.model, model,
                "{model:?} owns rows but defaults to board_version {} which \
                 belongs to {:?}",
                default.board_version, default.model
            );
        }
    }
}
